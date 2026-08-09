use std::{
    fs::File,
    io::Write,
    process,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use aws_config::SdkConfig;
use aws_sdk_s3::{
    Client,
    config::{Builder, Region, retry::RetryConfig, timeout::TimeoutConfig},
    error::{ProvideErrorMetadata, SdkError},
    operation::{
        RequestId, RequestIdExt,
        get_object::GetObjectError,
        put_object::{PutObjectError, PutObjectOutput},
    },
    primitives::ByteStream,
    types::{LifecycleRule, LifecycleRuleFilter},
};
use ravel::{
    domain::campaign::{ArtifactRef, Authority, Event, EventContent, EventRef, Head},
    storage::{
        artifacts::MAX_ARTIFACT_BYTES,
        s3::{AttemptHistory, GetOutcome, MutationOutcome, S3Store},
    },
    sync::{event, head},
};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const LIVE_FLAG: &str = "RAVEL_LIVE_S3";
const BUCKET_ENV: &str = "RAVEL_LIVE_S3_BUCKET";
const REGION_ENV: &str = "RAVEL_LIVE_S3_REGION";
const EXPECTED_BUCKET: &str = "ravel-e02-4c038b2f";
const EXPECTED_REGION: &str = "us-east-1";
const MAX_PREFIX_BYTES: usize = 64;
// Mirrors the stored-event and canonical-head decode limits in the library.
const MAX_EVENT_BYTES: usize = 256 * 1024;
const MAX_HEAD_BYTES: usize = 4 * 1024;
const RACE_ROUNDS: usize = 4;
const RACE_CONTENDERS: usize = 16;
const RACE_BODY_BYTES: usize = 16 * 1024;
const OPERATION_TIMEOUT: Duration = Duration::from_secs(30);
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Serialize)]
struct Evidence {
    run_id: String,
    prefix: String,
    bucket: &'static str,
    region: &'static str,
    epoch_nanos: u128,
    keys: Option<ChainKeys>,
    operations: Vec<OperationRecord>,
    repository_outcomes: Vec<RepositoryRecord>,
    race_rounds: usize,
    lifecycle: Option<LifecycleEvidence>,
    result: String,
}

#[derive(Clone, Serialize)]
struct ChainKeys {
    artifact: String,
    event_1: String,
    event_2: String,
    head: String,
}

#[derive(Serialize)]
struct OperationRecord {
    step: String,
    client: &'static str,
    key: String,
    condition: Option<&'static str>,
    supplied_etag: Option<String>,
    classification: String,
    status: Option<u16>,
    error_code: Option<String>,
    request_id: Option<String>,
    extended_request_id: Option<String>,
    response_etag: Option<String>,
}

#[derive(Serialize)]
struct RepositoryRecord {
    step: &'static str,
    classification: &'static str,
}

#[derive(Clone, Default, Serialize)]
struct FilterProjection {
    prefix: Option<String>,
    tag: Option<TagProjection>,
    object_size_greater_than: Option<i64>,
    object_size_less_than: Option<i64>,
    and: Option<AndProjection>,
}

#[derive(Clone, Serialize)]
struct TagProjection {
    key: String,
    value: String,
}

#[derive(Clone, Default, Serialize)]
struct AndProjection {
    prefix: Option<String>,
    tags: Vec<TagProjection>,
    object_size_greater_than: Option<i64>,
    object_size_less_than: Option<i64>,
}

#[derive(Clone, Serialize)]
struct RuleProjection {
    id: Option<String>,
    status: String,
    legacy_prefix: Option<String>,
    filter: Option<FilterProjection>,
    expiration: Option<Value>,
    noncurrent_version_expiration: Option<Value>,
    transitions: Vec<Value>,
    noncurrent_version_transitions: Vec<Value>,
    abort_incomplete_multipart_upload: Option<Value>,
}

#[derive(Serialize)]
struct LifecycleReport {
    rule_id: Option<String>,
    object_key: String,
    object_size: u64,
    selector_matches: bool,
    supported: bool,
    safe: bool,
    reason: String,
}

#[derive(Serialize)]
struct LifecycleEvidence {
    classification: String,
    safe: bool,
    request_id: Option<String>,
    extended_request_id: Option<String>,
    transition_default_minimum_object_size: Option<String>,
    rules: Vec<RuleProjection>,
    report: Vec<LifecycleReport>,
}

#[derive(Clone, Copy)]
struct ObjectFacts<'a> {
    key: &'a str,
    size: u64,
}

struct SelectorDecision {
    matches: bool,
    supported: bool,
    reason: &'static str,
}

fn live_enabled() -> Result<bool, &'static str> {
    let flag = std::env::var(LIVE_FLAG).ok();
    let bucket = std::env::var(BUCKET_ENV).ok();
    let region = std::env::var(REGION_ENV).ok();
    if flag.as_deref() != Some("1") || bucket.is_none() || region.is_none() {
        return Ok(false);
    }
    if bucket.as_deref() != Some(EXPECTED_BUCKET) {
        return Err("unexpected live S3 bucket");
    }
    if region.as_deref() != Some(EXPECTED_REGION) {
        return Err("unexpected live S3 region");
    }
    Ok(true)
}

fn physical(prefix: &str, logical: &str) -> String {
    format!("{prefix}/{logical}")
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn success_record(
    step: &str,
    key: &str,
    condition: &'static str,
    supplied_etag: Option<&str>,
    output: &PutObjectOutput,
) -> OperationRecord {
    OperationRecord {
        step: step.to_owned(),
        client: "direct-sdk",
        key: key.to_owned(),
        condition: Some(condition),
        supplied_etag: supplied_etag.map(str::to_owned),
        classification: "success".into(),
        status: None,
        error_code: None,
        request_id: output.request_id().map(str::to_owned),
        extended_request_id: output.extended_request_id().map(str::to_owned),
        response_etag: output.e_tag().map(str::to_owned),
    }
}

fn service_error_record<E>(
    step: &str,
    key: &str,
    condition: Option<&'static str>,
    supplied_etag: Option<&str>,
    error: &SdkError<E>,
) -> OperationRecord
where
    E: ProvideErrorMetadata + RequestId + RequestIdExt,
{
    match error {
        SdkError::ServiceError(service) => OperationRecord {
            step: step.to_owned(),
            client: "direct-sdk",
            key: key.to_owned(),
            condition,
            supplied_etag: supplied_etag.map(str::to_owned),
            classification: "service-error".into(),
            status: Some(service.raw().status().as_u16()),
            error_code: service.err().code().map(str::to_owned),
            request_id: service.err().request_id().map(str::to_owned),
            extended_request_id: service.err().extended_request_id().map(str::to_owned),
            response_etag: None,
        },
        _ => OperationRecord {
            step: step.to_owned(),
            client: "direct-sdk",
            key: key.to_owned(),
            condition,
            supplied_etag: supplied_etag.map(str::to_owned),
            classification: "transport-error".into(),
            status: None,
            error_code: None,
            request_id: None,
            extended_request_id: None,
            response_etag: None,
        },
    }
}

async fn conditional_put(
    client: &Client,
    bucket: &str,
    key: &str,
    bytes: Vec<u8>,
    etag: Option<&str>,
) -> Result<PutObjectOutput, SdkError<PutObjectError>> {
    let request = client
        .put_object()
        .bucket(bucket)
        .key(key)
        .body(ByteStream::from(bytes));
    match etag {
        Some(etag) => request.if_match(etag).send().await,
        None => request.if_none_match("*").send().await,
    }
}

fn direct_client(sdk_config: &SdkConfig) -> Client {
    let timeout = TimeoutConfig::builder()
        .operation_timeout(OPERATION_TIMEOUT)
        .operation_attempt_timeout(ATTEMPT_TIMEOUT)
        .build();
    Client::from_conf(
        Builder::from(sdk_config)
            .region(Region::new(EXPECTED_REGION))
            .retry_config(RetryConfig::disabled())
            .timeout_config(timeout)
            .behavior_version_latest()
            .build(),
    )
}

async fn create_object(
    client: &Client,
    bucket: &str,
    key: &str,
    bytes: &[u8],
    step: &str,
    evidence: &mut Evidence,
) -> Result<String, &'static str> {
    match conditional_put(client, bucket, key, bytes.to_vec(), None).await {
        Ok(output) => {
            let etag = output
                .e_tag()
                .ok_or("create response missing ETag")?
                .to_owned();
            evidence
                .operations
                .push(success_record(step, key, "If-None-Match:*", None, &output));
            Ok(etag)
        }
        Err(error) => {
            evidence.operations.push(service_error_record(
                step,
                key,
                Some("If-None-Match:*"),
                None,
                &error,
            ));
            Err("conditional create failed")
        }
    }
}

async fn replace_object(
    client: &Client,
    bucket: &str,
    key: &str,
    bytes: &[u8],
    etag: &str,
    step: &str,
    evidence: &mut Evidence,
) -> Result<String, &'static str> {
    match conditional_put(client, bucket, key, bytes.to_vec(), Some(etag)).await {
        Ok(output) => {
            let next = output
                .e_tag()
                .ok_or("replace response missing ETag")?
                .to_owned();
            evidence
                .operations
                .push(success_record(step, key, "If-Match", Some(etag), &output));
            Ok(next)
        }
        Err(error) => {
            evidence.operations.push(service_error_record(
                step,
                key,
                Some("If-Match"),
                Some(etag),
                &error,
            ));
            Err("conditional replacement failed")
        }
    }
}

fn expect_live_412(
    result: Result<PutObjectOutput, SdkError<PutObjectError>>,
    step: &str,
    key: &str,
    condition: &'static str,
    supplied_etag: Option<&str>,
    evidence: &mut Evidence,
) -> Result<(), &'static str> {
    match result {
        Err(error) => {
            let record = service_error_record(step, key, Some(condition), supplied_etag, &error);
            let valid = record.status == Some(412);
            evidence.operations.push(record);
            if valid {
                Ok(())
            } else {
                Err("expected live 412")
            }
        }
        Ok(output) => {
            evidence
                .operations
                .push(success_record(step, key, condition, supplied_etag, &output));
            Err("conditional request unexpectedly succeeded")
        }
    }
}

fn repository_record(step: &'static str, outcome: &MutationOutcome) -> RepositoryRecord {
    let classification = match outcome {
        MutationOutcome::Committed { .. } => "committed",
        MutationOutcome::NotFound => "not-found",
        MutationOutcome::Conflict => "conflict",
        MutationOutcome::PreconditionFailed => "precondition-failed",
        MutationOutcome::AmbiguousConflict => "ambiguous-conflict",
        MutationOutcome::Unknown => "unknown",
        MutationOutcome::ProvenNotSent => "proven-not-sent",
        MutationOutcome::TooLarge => "too-large",
    };
    RepositoryRecord {
        step,
        classification,
    }
}

fn expect_repository_412(
    step: &'static str,
    outcome: MutationOutcome,
    evidence: &mut Evidence,
) -> Result<(), &'static str> {
    evidence
        .repository_outcomes
        .push(repository_record(step, &outcome));
    if outcome == MutationOutcome::PreconditionFailed {
        Ok(())
    } else {
        Err(step)
    }
}

fn tag_projection(tag: &aws_sdk_s3::types::Tag) -> TagProjection {
    TagProjection {
        key: tag.key().to_owned(),
        value: tag.value().to_owned(),
    }
}

fn filter_projection(filter: &LifecycleRuleFilter) -> FilterProjection {
    FilterProjection {
        prefix: filter.prefix().map(str::to_owned),
        tag: filter.tag().map(tag_projection),
        object_size_greater_than: filter.object_size_greater_than(),
        object_size_less_than: filter.object_size_less_than(),
        and: filter.and().map(|and| AndProjection {
            prefix: and.prefix().map(str::to_owned),
            tags: and.tags().iter().map(tag_projection).collect(),
            object_size_greater_than: and.object_size_greater_than(),
            object_size_less_than: and.object_size_less_than(),
        }),
    }
}

#[allow(deprecated)]
fn project_rule(rule: &LifecycleRule) -> RuleProjection {
    RuleProjection {
        id: rule.id().map(str::to_owned),
        status: rule.status().as_str().to_owned(),
        legacy_prefix: rule.prefix().map(str::to_owned),
        filter: rule.filter().map(filter_projection),
        expiration: rule.expiration().map(|expiration| {
            json!({
                "date": expiration.date().map(|date| format!("{date:?}")),
                "days": expiration.days(),
                "expired_object_delete_marker": expiration.expired_object_delete_marker(),
            })
        }),
        noncurrent_version_expiration: rule.noncurrent_version_expiration().map(|expiration| {
            json!({
                "noncurrent_days": expiration.noncurrent_days(),
                "newer_noncurrent_versions": expiration.newer_noncurrent_versions(),
            })
        }),
        transitions: rule
            .transitions()
            .iter()
            .map(|transition| {
                json!({
                    "date": transition.date().map(|date| format!("{date:?}")),
                    "days": transition.days(),
                    "storage_class": transition.storage_class().map(|value| value.as_str()),
                })
            })
            .collect(),
        noncurrent_version_transitions: rule
            .noncurrent_version_transitions()
            .iter()
            .map(|transition| {
                json!({
                    "noncurrent_days": transition.noncurrent_days(),
                    "newer_noncurrent_versions": transition.newer_noncurrent_versions(),
                    "storage_class": transition.storage_class().map(|value| value.as_str()),
                })
            })
            .collect(),
        abort_incomplete_multipart_upload: rule
            .abort_incomplete_multipart_upload()
            .map(|abort| json!({ "days_after_initiation": abort.days_after_initiation() })),
    }
}

fn size_matches(size: u64, greater_than: Option<i64>, less_than: Option<i64>) -> Option<bool> {
    let size = i64::try_from(size).ok()?;
    Some(
        greater_than.is_none_or(|minimum| size > minimum)
            && less_than.is_none_or(|maximum| size < maximum),
    )
}

fn selector_matches(rule: &RuleProjection, object: ObjectFacts<'_>) -> SelectorDecision {
    if rule.legacy_prefix.is_some() && rule.filter.is_some() {
        return SelectorDecision {
            matches: true,
            supported: false,
            reason: "legacy-prefix-with-filter",
        };
    }
    let Some(filter) = &rule.filter else {
        return SelectorDecision {
            matches: rule
                .legacy_prefix
                .as_deref()
                .is_none_or(|prefix| object.key.starts_with(prefix)),
            supported: true,
            reason: if rule.legacy_prefix.is_some() {
                "legacy-prefix"
            } else {
                "global"
            },
        };
    };

    let populated = usize::from(filter.prefix.is_some())
        + usize::from(filter.tag.is_some())
        + usize::from(filter.object_size_greater_than.is_some())
        + usize::from(filter.object_size_less_than.is_some())
        + usize::from(filter.and.is_some());
    if populated > 1 {
        return SelectorDecision {
            matches: true,
            supported: false,
            reason: "ambiguous-filter",
        };
    }
    if populated == 0 {
        return SelectorDecision {
            matches: true,
            supported: true,
            reason: "empty-filter",
        };
    }
    if let Some(prefix) = &filter.prefix {
        return SelectorDecision {
            matches: object.key.starts_with(prefix),
            supported: true,
            reason: "prefix",
        };
    }
    if filter.tag.is_some() {
        return SelectorDecision {
            matches: false,
            supported: true,
            reason: "untagged-object",
        };
    }
    if let Some(and) = &filter.and {
        if !and.tags.is_empty() {
            return SelectorDecision {
                matches: false,
                supported: true,
                reason: "and-tag-on-untagged-object",
            };
        }
        let Some(size_match) = size_matches(
            object.size,
            and.object_size_greater_than,
            and.object_size_less_than,
        ) else {
            return SelectorDecision {
                matches: true,
                supported: false,
                reason: "unsupported-object-size",
            };
        };
        return SelectorDecision {
            matches: and
                .prefix
                .as_deref()
                .is_none_or(|prefix| object.key.starts_with(prefix))
                && size_match,
            supported: true,
            reason: "and",
        };
    }
    let Some(matches) = size_matches(
        object.size,
        filter.object_size_greater_than,
        filter.object_size_less_than,
    ) else {
        return SelectorDecision {
            matches: true,
            supported: false,
            reason: "unsupported-object-size",
        };
    };
    SelectorDecision {
        matches,
        supported: true,
        reason: "object-size",
    }
}

fn lifecycle_report(rules: &[RuleProjection], objects: &[ObjectFacts<'_>]) -> Vec<LifecycleReport> {
    let mut report = Vec::with_capacity(rules.len() * objects.len());
    for rule in rules {
        for object in objects {
            let selector = selector_matches(rule, *object);
            let enabled = match rule.status.as_str() {
                "Enabled" => Some(true),
                "Disabled" => Some(false),
                _ => None,
            };
            let has_expiration =
                rule.expiration.is_some() || rule.noncurrent_version_expiration.is_some();
            let safe = enabled == Some(false)
                || (enabled == Some(true)
                    && selector.supported
                    && (!selector.matches || !has_expiration));
            let reason = if enabled == Some(false) {
                "disabled"
            } else if enabled.is_none() {
                "unknown-status"
            } else if !selector.supported || !selector.matches {
                selector.reason
            } else if has_expiration {
                "matching-expiration"
            } else {
                "no-expiration"
            };
            report.push(LifecycleReport {
                rule_id: rule.id.clone(),
                object_key: object.key.to_owned(),
                object_size: object.size,
                selector_matches: selector.matches,
                supported: selector.supported,
                safe,
                reason: reason.into(),
            });
        }
    }
    report
}

async fn inspect_lifecycle(
    client: &Client,
    bucket: &str,
    objects: &[ObjectFacts<'_>],
    evidence: &mut Evidence,
) -> Result<LifecycleEvidence, &'static str> {
    match client
        .get_bucket_lifecycle_configuration()
        .bucket(bucket)
        .send()
        .await
    {
        Ok(output) => {
            let rules: Vec<_> = output.rules().iter().map(project_rule).collect();
            let report = lifecycle_report(&rules, objects);
            let safe = report.iter().all(|entry| entry.safe);
            Ok(LifecycleEvidence {
                classification: "configuration".into(),
                safe,
                request_id: output.request_id().map(str::to_owned),
                extended_request_id: output.extended_request_id().map(str::to_owned),
                transition_default_minimum_object_size: output
                    .transition_default_minimum_object_size()
                    .map(|value| value.as_str().to_owned()),
                rules,
                report,
            })
        }
        Err(SdkError::ServiceError(service))
            if service.raw().status().as_u16() == 404
                && service.err().code() == Some("NoSuchLifecycleConfiguration") =>
        {
            Ok(LifecycleEvidence {
                classification: "no-lifecycle-configuration".into(),
                safe: true,
                request_id: service.err().request_id().map(str::to_owned),
                extended_request_id: service.err().extended_request_id().map(str::to_owned),
                transition_default_minimum_object_size: None,
                rules: Vec::new(),
                report: Vec::new(),
            })
        }
        Err(error) => {
            evidence.operations.push(service_error_record(
                "lifecycle-read",
                bucket,
                None,
                None,
                &error,
            ));
            Err("lifecycle read failed")
        }
    }
}

async fn get_found_bytes(
    store: &S3Store,
    key: &str,
    limit: usize,
    step: &'static str,
    evidence: &mut Evidence,
) -> Result<Vec<u8>, &'static str> {
    match store.get_object(key, limit).await {
        Ok(GetOutcome::Found { bytes, .. }) => {
            evidence.repository_outcomes.push(RepositoryRecord {
                step,
                classification: "found",
            });
            Ok(bytes)
        }
        Ok(GetOutcome::NotFound) => {
            evidence.repository_outcomes.push(RepositoryRecord {
                step,
                classification: "not-found",
            });
            Err(step)
        }
        Err(_) => {
            evidence.repository_outcomes.push(RepositoryRecord {
                step,
                classification: "read-error",
            });
            Err(step)
        }
    }
}

async fn race_for_409(
    sdk_config: &SdkConfig,
    bucket: &str,
    prefix: &str,
    evidence: &mut Evidence,
) -> Result<(), &'static str> {
    let clients: Vec<Client> = (0..RACE_CONTENDERS)
        .map(|_| direct_client(sdk_config))
        .collect();
    for round in 0..RACE_ROUNDS {
        let key = physical(prefix, &format!("race/{round}"));
        let tasks: Vec<_> = (0..RACE_CONTENDERS)
            .map(|contender| {
                let client = clients[contender].clone();
                let bucket = bucket.to_owned();
                let key = key.clone();
                tokio::spawn(async move {
                    let mut body = vec![contender as u8; RACE_BODY_BYTES];
                    body.extend_from_slice(format!("contender-{contender}").as_bytes());
                    conditional_put(&client, &bucket, &key, body, None).await
                })
            })
            .collect();
        let mut results = Vec::with_capacity(RACE_CONTENDERS);
        for task in tasks {
            results.push(task.await.map_err(|_| "race task panicked")?);
        }
        evidence.race_rounds = round + 1;
        let mut success = false;
        let mut found_409 = false;
        for (contender, result) in results.into_iter().enumerate() {
            let step = format!("race-{round}-{contender}");
            match result {
                Ok(output) => {
                    success = true;
                    evidence.operations.push(success_record(
                        &step,
                        &key,
                        "If-None-Match:*",
                        None,
                        &output,
                    ));
                }
                Err(error) => {
                    let record =
                        service_error_record(&step, &key, Some("If-None-Match:*"), None, &error);
                    found_409 |= record.status == Some(409)
                        && record.error_code.as_deref() == Some("ConditionalRequestConflict");
                    evidence.operations.push(record);
                }
            }
        }
        if found_409 {
            return Ok(());
        }
        if !success {
            return Err("race key had no successful writer");
        }
    }
    Err("bounded race did not observe live 409")
}

async fn run_scenario(prefix: &str, evidence: &mut Evidence) -> Result<(), &'static str> {
    let sdk_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(Region::new(EXPECTED_REGION))
        .load()
        .await;
    let direct = direct_client(&sdk_config);
    let store = S3Store::new(
        EXPECTED_BUCKET,
        Region::new(EXPECTED_REGION),
        Builder::from(&sdk_config),
    );

    let head_key = physical(prefix, "head.json");
    match direct
        .get_object()
        .bucket(EXPECTED_BUCKET)
        .key(&head_key)
        .send()
        .await
    {
        Err(error @ SdkError::ServiceError(_)) => {
            let record = service_error_record("direct-missing-head", &head_key, None, None, &error);
            let modeled = match &error {
                SdkError::ServiceError(service) => {
                    matches!(service.err(), GetObjectError::NoSuchKey(_))
                }
                _ => false,
            };
            let valid = modeled && record.status == Some(404);
            evidence.operations.push(record);
            if !valid {
                return Err("missing head did not return modeled 404");
            }
        }
        Err(error) => {
            evidence.operations.push(service_error_record(
                "direct-missing-head",
                &head_key,
                None,
                None,
                &error,
            ));
            return Err("missing head direct read failed");
        }
        Ok(_) => return Err("live prefix collision"),
    }
    match store.get_object(&head_key, MAX_HEAD_BYTES).await {
        Ok(GetOutcome::NotFound) => evidence.repository_outcomes.push(RepositoryRecord {
            step: "repository-missing-head",
            classification: "not-found",
        }),
        _ => return Err("repository missing head was not typed NotFound"),
    }

    let artifact_bytes = b"ravel-e02-live-artifact".to_vec();
    let artifact_digest = sha256(&artifact_bytes);
    let artifact_ref = ArtifactRef::new(
        artifact_digest.clone(),
        artifact_bytes.len() as u64,
        "application/octet-stream".into(),
        "live-preflight-attempt".into(),
        (evidence.epoch_nanos / 1_000_000) as u64,
        Some("retain".into()),
    )
    .map_err(|_| "artifact reference construction failed")?;
    let event_1 = Event::new(
        "live-event-1".into(),
        1,
        None,
        7,
        EventContent::CampaignCreated,
    )
    .map_err(|_| "event 1 construction failed")?;
    let encoded_1 = event::encode(&event_1).map_err(|_| "event 1 encoding failed")?;
    let reference_1 = EventRef::new(1, encoded_1.digest().to_owned(), encoded_1.key().to_owned())
        .map_err(|_| "event 1 reference construction failed")?;
    let event_2 = Event::new(
        "live-event-2".into(),
        2,
        Some(reference_1.clone()),
        7,
        EventContent::ArtifactPublished(artifact_ref),
    )
    .map_err(|_| "event 2 construction failed")?;
    let encoded_2 = event::encode(&event_2).map_err(|_| "event 2 encoding failed")?;
    let reference_2 = EventRef::new(2, encoded_2.digest().to_owned(), encoded_2.key().to_owned())
        .map_err(|_| "event 2 reference construction failed")?;
    let genesis_head = Head::new(
        Authority::unowned(),
        reference_1.clone(),
        "live-head-genesis".into(),
    )
    .map_err(|_| "genesis head construction failed")?;
    let successor_head = Head::new(
        Authority::unowned(),
        reference_2.clone(),
        "live-head-successor".into(),
    )
    .map_err(|_| "successor head construction failed")?;
    let genesis_head_bytes =
        head::encode(&genesis_head).map_err(|_| "genesis head encoding failed")?;
    let successor_head_bytes =
        head::encode(&successor_head).map_err(|_| "successor head encoding failed")?;

    // Canonical event references stay unprefixed; only physical S3 keys use the run prefix.
    let keys = ChainKeys {
        artifact: physical(prefix, &format!("artifacts/sha256/{artifact_digest}")),
        event_1: physical(prefix, encoded_1.key()),
        event_2: physical(prefix, encoded_2.key()),
        head: head_key.clone(),
    };
    evidence.keys = Some(keys.clone());

    create_object(
        &direct,
        EXPECTED_BUCKET,
        &keys.artifact,
        &artifact_bytes,
        "create-artifact",
        evidence,
    )
    .await?;
    let event_1_direct_etag = create_object(
        &direct,
        EXPECTED_BUCKET,
        &keys.event_1,
        encoded_1.stored_bytes(),
        "create-event-1",
        evidence,
    )
    .await?;
    create_object(
        &direct,
        EXPECTED_BUCKET,
        &keys.event_2,
        encoded_2.stored_bytes(),
        "create-event-2",
        evidence,
    )
    .await?;
    let genesis_direct_etag = create_object(
        &direct,
        EXPECTED_BUCKET,
        &keys.head,
        &genesis_head_bytes,
        "create-genesis-head",
        evidence,
    )
    .await?;

    let stale_repository_etag = match store.get_object(&keys.head, MAX_HEAD_BYTES).await {
        Ok(GetOutcome::Found { etag, .. }) => etag,
        _ => return Err("repository genesis head read failed"),
    };
    let wrong_repository_etag = match store.get_object(&keys.event_1, MAX_EVENT_BYTES).await {
        Ok(GetOutcome::Found { etag, .. }) => etag,
        _ => return Err("repository event ETag read failed"),
    };
    let current_direct_etag = replace_object(
        &direct,
        EXPECTED_BUCKET,
        &keys.head,
        &successor_head_bytes,
        &genesis_direct_etag,
        "replace-head",
        evidence,
    )
    .await?;
    if event_1_direct_etag == current_direct_etag {
        return Err("wrong ETag unexpectedly equals current head ETag");
    }

    let direct_duplicate = conditional_put(
        &direct,
        EXPECTED_BUCKET,
        &keys.event_1,
        encoded_1.stored_bytes().to_vec(),
        None,
    )
    .await;
    expect_live_412(
        direct_duplicate,
        "duplicate-create-412",
        &keys.event_1,
        "If-None-Match:*",
        None,
        evidence,
    )?;
    let mut history = AttemptHistory::default();
    let duplicate = store
        .put_if_absent(
            &keys.event_1,
            encoded_1.stored_bytes().to_vec(),
            &mut history,
        )
        .await;
    expect_repository_412("repository-duplicate-create", duplicate, evidence)?;

    let direct_stale = conditional_put(
        &direct,
        EXPECTED_BUCKET,
        &keys.head,
        successor_head_bytes.clone(),
        Some(&genesis_direct_etag),
    )
    .await;
    expect_live_412(
        direct_stale,
        "stale-if-match-412",
        &keys.head,
        "If-Match",
        Some(&genesis_direct_etag),
        evidence,
    )?;
    let mut history = AttemptHistory::default();
    let stale = store
        .put_if_match(
            &keys.head,
            successor_head_bytes.clone(),
            &stale_repository_etag,
            &mut history,
        )
        .await;
    expect_repository_412("repository-stale-if-match", stale, evidence)?;

    let direct_wrong = conditional_put(
        &direct,
        EXPECTED_BUCKET,
        &keys.head,
        successor_head_bytes.clone(),
        Some(&event_1_direct_etag),
    )
    .await;
    expect_live_412(
        direct_wrong,
        "wrong-if-match-412",
        &keys.head,
        "If-Match",
        Some(&event_1_direct_etag),
        evidence,
    )?;
    let mut history = AttemptHistory::default();
    let wrong = store
        .put_if_match(
            &keys.head,
            successor_head_bytes.clone(),
            &wrong_repository_etag,
            &mut history,
        )
        .await;
    expect_repository_412("repository-wrong-if-match", wrong, evidence)?;

    let final_head_bytes = get_found_bytes(
        &store,
        &keys.head,
        MAX_HEAD_BYTES,
        "validate-head",
        evidence,
    )
    .await?;
    let final_head = head::decode(&final_head_bytes).map_err(|_| "final head decode failed")?;
    if final_head != successor_head {
        return Err("final head does not match successor");
    }
    let stored_event_2 = get_found_bytes(
        &store,
        &keys.event_2,
        MAX_EVENT_BYTES,
        "validate-event-2",
        evidence,
    )
    .await?;
    let decoded_event_2 =
        event::decode(&stored_event_2, encoded_2.key()).map_err(|_| "event 2 validation failed")?;
    if decoded_event_2 != event_2 || decoded_event_2.parent() != Some(&reference_1) {
        return Err("event 2 chain linkage failed");
    }
    let stored_event_1 = get_found_bytes(
        &store,
        &keys.event_1,
        MAX_EVENT_BYTES,
        "validate-event-1",
        evidence,
    )
    .await?;
    if event::decode(&stored_event_1, encoded_1.key()).map_err(|_| "event 1 validation failed")?
        != event_1
    {
        return Err("event 1 mismatch");
    }
    let stored_artifact = get_found_bytes(
        &store,
        &keys.artifact,
        MAX_ARTIFACT_BYTES,
        "validate-artifact",
        evidence,
    )
    .await?;
    if stored_artifact.len() != artifact_bytes.len() || sha256(&stored_artifact) != artifact_digest
    {
        return Err("artifact validation failed");
    }

    let objects = [
        ObjectFacts {
            key: &keys.head,
            size: final_head_bytes.len() as u64,
        },
        ObjectFacts {
            key: &keys.event_1,
            size: stored_event_1.len() as u64,
        },
        ObjectFacts {
            key: &keys.event_2,
            size: stored_event_2.len() as u64,
        },
        ObjectFacts {
            key: &keys.artifact,
            size: stored_artifact.len() as u64,
        },
    ];
    let lifecycle = inspect_lifecycle(&direct, EXPECTED_BUCKET, &objects, evidence).await?;
    let safe = lifecycle.safe;
    evidence.lifecycle = Some(lifecycle);
    if !safe {
        return Err("lifecycle rule can expire retained objects");
    }

    race_for_409(&sdk_config, EXPECTED_BUCKET, prefix, evidence).await?;
    Ok(())
}

fn write_evidence(evidence: &Evidence) -> Result<String, &'static str> {
    let path = format!("pilot/e02/live-preflight-{}.json", evidence.run_id);
    let mut bytes =
        serde_json::to_vec_pretty(evidence).map_err(|_| "evidence serialization failed")?;
    bytes.push(b'\n');
    let mut file = File::create_new(&path).map_err(|_| "evidence file creation failed")?;
    file.write_all(&bytes)
        .map_err(|_| "evidence file write failed")?;
    Ok(path)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn live_s3_preflight() {
    match live_enabled() {
        Ok(true) => {}
        Ok(false) => {
            println!("live S3 preflight skipped: set RAVEL_LIVE_S3=1, bucket, and region");
            return;
        }
        Err(message) => panic!("{message}"),
    }
    let epoch_nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is after the Unix epoch")
        .as_nanos();
    let run_id = format!("{epoch_nanos}-{}", process::id());
    let prefix = format!("e02-preflight/{run_id}");
    assert!(
        prefix.len() <= MAX_PREFIX_BYTES,
        "live prefix exceeds fixed bound"
    );
    println!("live S3 preflight prefix: {prefix}");

    let mut evidence = Evidence {
        run_id,
        prefix: prefix.clone(),
        bucket: EXPECTED_BUCKET,
        region: EXPECTED_REGION,
        epoch_nanos,
        keys: None,
        operations: Vec::new(),
        repository_outcomes: Vec::new(),
        race_rounds: 0,
        lifecycle: None,
        result: "running".into(),
    };
    let outcome = run_scenario(&prefix, &mut evidence).await;
    evidence.result = match outcome {
        Ok(()) => "passed".into(),
        Err(step) => format!("failed:{step}"),
    };
    let path = write_evidence(&evidence).expect("live evidence must be retained");
    println!("live S3 preflight evidence: {path}");
    if let Err(step) = outcome {
        panic!("live S3 preflight failed at {step}; see {path}");
    }
}

fn test_rule(
    status: &str,
    filter: Option<FilterProjection>,
    legacy: Option<&str>,
) -> RuleProjection {
    RuleProjection {
        id: Some(status.into()),
        status: status.into(),
        legacy_prefix: legacy.map(str::to_owned),
        filter,
        expiration: Some(json!({ "days": 1 })),
        noncurrent_version_expiration: None,
        transitions: Vec::new(),
        noncurrent_version_transitions: Vec::new(),
        abort_incomplete_multipart_upload: None,
    }
}

#[test]
fn lifecycle_rule_evaluator_covers_all_selector_forms_and_overlaps() {
    let object = ObjectFacts {
        key: "e02-preflight/run/head.json",
        size: 100,
    };
    let cases = [
        ("global", test_rule("Enabled", None, None), true, true),
        (
            "empty-filter",
            test_rule("Enabled", Some(FilterProjection::default()), None),
            true,
            true,
        ),
        (
            "legacy-prefix",
            test_rule("Enabled", None, Some("e02-preflight/")),
            true,
            true,
        ),
        (
            "prefix",
            test_rule(
                "Enabled",
                Some(FilterProjection {
                    prefix: Some("other/".into()),
                    ..Default::default()
                }),
                None,
            ),
            false,
            true,
        ),
        (
            "tag",
            test_rule(
                "Enabled",
                Some(FilterProjection {
                    tag: Some(TagProjection {
                        key: "expire".into(),
                        value: "yes".into(),
                    }),
                    ..Default::default()
                }),
                None,
            ),
            false,
            true,
        ),
        (
            "size-strict",
            test_rule(
                "Enabled",
                Some(FilterProjection {
                    object_size_greater_than: Some(100),
                    ..Default::default()
                }),
                None,
            ),
            false,
            true,
        ),
        (
            "and",
            test_rule(
                "Enabled",
                Some(FilterProjection {
                    and: Some(AndProjection {
                        prefix: Some("e02-preflight/".into()),
                        object_size_less_than: Some(101),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                None,
            ),
            true,
            true,
        ),
        ("disabled", test_rule("Disabled", None, None), true, true),
        ("unknown", test_rule("Future", None, None), true, true),
    ];

    for (name, rule, expected_match, expected_supported) in cases {
        let decision = selector_matches(&rule, object);
        assert_eq!(decision.matches, expected_match, "{name}");
        assert_eq!(decision.supported, expected_supported, "{name}");
    }

    let overlapping = [
        test_rule("Enabled", None, Some("other/")),
        test_rule("Enabled", None, Some("e02-preflight/")),
        test_rule("Future", None, None),
    ];
    let report = lifecycle_report(&overlapping, &[object]);
    assert_eq!(report.len(), 3);
    assert!(report[0].safe);
    assert!(!report[1].safe);
    assert!(!report[2].safe);
    assert_eq!(report[2].reason, "unknown-status");
}

#[test]
fn evaluator_fails_closed_on_noncurrent_and_unsupported_shapes() {
    let object = ObjectFacts {
        key: "e02-preflight/run/head.json",
        size: 100,
    };

    let mut noncurrent = test_rule("Enabled", None, None);
    noncurrent.expiration = None;
    noncurrent.noncurrent_version_expiration = Some(json!({ "noncurrent_days": 1 }));
    assert!(!lifecycle_report(&[noncurrent], &[object])[0].safe);

    let legacy_and_filter = test_rule(
        "Enabled",
        Some(FilterProjection {
            prefix: Some("other/".into()),
            ..Default::default()
        }),
        Some("other/"),
    );
    let decision = selector_matches(&legacy_and_filter, object);
    assert!(!decision.supported);
    assert!(!lifecycle_report(&[legacy_and_filter], &[object])[0].safe);

    let ambiguous = test_rule(
        "Enabled",
        Some(FilterProjection {
            prefix: Some("other/".into()),
            object_size_less_than: Some(1),
            ..Default::default()
        }),
        None,
    );
    let decision = selector_matches(&ambiguous, object);
    assert!(!decision.supported);
    assert!(decision.matches);
    assert!(!lifecycle_report(&[ambiguous], &[object])[0].safe);

    let and_with_tag = test_rule(
        "Enabled",
        Some(FilterProjection {
            and: Some(AndProjection {
                prefix: Some("e02-preflight/".into()),
                tags: vec![TagProjection {
                    key: "expire".into(),
                    value: "yes".into(),
                }],
                ..Default::default()
            }),
            ..Default::default()
        }),
        None,
    );
    assert!(!selector_matches(&and_with_tag, object).matches);

    let anchored_prefix = test_rule(
        "Enabled",
        Some(FilterProjection {
            prefix: Some("e02-preflight/".into()),
            ..Default::default()
        }),
        None,
    );
    let embedded = ObjectFacts {
        key: "x/e02-preflight/run/head.json",
        size: 100,
    };
    assert!(!selector_matches(&anchored_prefix, embedded).matches);
}

#[test]
fn projects_sdk_lifecycle_rule_fields() {
    let tag = aws_sdk_s3::types::Tag::builder()
        .key("expire")
        .value("yes")
        .build()
        .expect("test tag is complete");
    let and = aws_sdk_s3::types::LifecycleRuleAndOperator::builder()
        .prefix("e02-preflight/")
        .tags(tag)
        .object_size_greater_than(10)
        .object_size_less_than(1_000)
        .build();
    let filter = LifecycleRuleFilter::builder().and(and).build();
    let rule = LifecycleRule::builder()
        .id("projected-rule")
        .status(aws_sdk_s3::types::ExpirationStatus::Enabled)
        .filter(filter)
        .noncurrent_version_expiration(
            aws_sdk_s3::types::NoncurrentVersionExpiration::builder()
                .noncurrent_days(7)
                .newer_noncurrent_versions(2)
                .build(),
        )
        .build()
        .expect("test lifecycle rule is complete");

    let projection = project_rule(&rule);
    assert_eq!(projection.id.as_deref(), Some("projected-rule"));
    assert_eq!(projection.status, "Enabled");
    let filter = projection.filter.expect("filter is projected");
    let and = filter.and.expect("and is projected");
    assert_eq!(and.prefix.as_deref(), Some("e02-preflight/"));
    assert_eq!(and.tags[0].key, "expire");
    assert_eq!(and.tags[0].value, "yes");
    assert_eq!(and.object_size_greater_than, Some(10));
    assert_eq!(and.object_size_less_than, Some(1_000));
    assert!(projection.noncurrent_version_expiration.is_some());
}
