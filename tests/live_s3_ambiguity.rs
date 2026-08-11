use std::{
    collections::VecDeque,
    error::Error,
    fmt,
    fs::File,
    io::{BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    process::{self, Child, Command, Stdio},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use aws_config::SdkConfig;
use aws_sdk_s3::{
    config::{
        Builder, ConfigBag, Credentials, Intercept, Region, RuntimeComponents,
        interceptors::{
            BeforeDeserializationInterceptorContextRef, BeforeTransmitInterceptorContextRef,
        },
    },
    primitives::SdkBody,
};
use aws_smithy_runtime::client::http::test_util::{ReplayEvent, StaticReplayClient};
use ravel::{
    distributed::{
        claims::{self, ClaimAcquireOutcome},
        identity::{ActorId, InstanceId},
        presence::WorkspaceId,
    },
    domain::{
        campaign::{Authority, Event, EventContent, EventRef},
        work::{WorkId, WorkRef},
    },
    storage::{
        artifacts,
        s3::{AttemptHistory, GetOutcome, MutationOutcome, S3Store},
    },
    sync::{event, head},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const MAX_CLAIM_BYTES: usize = 4 * 1024;
const LIVE_FLAG: &str = "RAVEL_LIVE_S3";
const BUCKET_ENV: &str = "RAVEL_LIVE_S3_BUCKET";
const REGION_ENV: &str = "RAVEL_LIVE_S3_REGION";
const EXPECTED_BUCKET: &str = "ravel-e02-4c038b2f";
const EXPECTED_REGION: &str = "us-east-1";
const HEAD_KEY: &str = "head.json";
const MAX_PREFIX_BYTES: usize = 64;
const MAX_EVENT_BYTES: usize = 256 * 1024;
const OPERATION_DEADLINE: Duration = Duration::from_secs(45);
const SCENARIO_DEADLINE: Duration = Duration::from_secs(120);
const WORKER_READY_DEADLINE: Duration = Duration::from_secs(60);
const WORKER_JOIN_DEADLINE: Duration = Duration::from_secs(120);
const BARRIER_IO_TIMEOUT: Duration = Duration::from_secs(15);
const WORKER_MARKER: &str = "RAVEL_WORKER_RESULT=";
const WORKER_LAUNCH_ENV: &str = "RAVEL_WORKER_LAUNCH";

type HookError = Box<dyn Error + Send + Sync + 'static>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Condition {
    None,
    Create,
    Match,
}

impl Condition {
    fn label(self) -> Option<&'static str> {
        match self {
            Self::None => None,
            Self::Create => Some("If-None-Match:*"),
            Self::Match => Some("If-Match"),
        }
    }

    fn matches(self, if_none_match: Option<&str>, if_match: Option<&str>) -> bool {
        match self {
            Self::None => if_none_match.is_none() && if_match.is_none(),
            Self::Create => if_none_match == Some("*") && if_match.is_none(),
            Self::Match => if_match.is_some() && if_none_match.is_none(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ResponseMode {
    Drop,
    Observe,
}

#[derive(Debug)]
struct ResponseAction {
    step: &'static str,
    key: String,
    condition: Condition,
    mode: ResponseMode,
}

impl ResponseAction {
    fn drop(step: &'static str, key: &str, condition: Condition) -> Self {
        Self {
            step,
            key: key.to_owned(),
            condition,
            mode: ResponseMode::Drop,
        }
    }

    fn observe(step: &'static str, key: &str, condition: Condition) -> Self {
        Self {
            step,
            key: key.to_owned(),
            condition,
            mode: ResponseMode::Observe,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
struct ResponseRecord {
    step: &'static str,
    client: &'static str,
    key: String,
    condition: Option<&'static str>,
    supplied_etag: Option<String>,
    classification: &'static str,
    status: u16,
    error_code: Option<String>,
    request_id: Option<String>,
    extended_request_id: Option<String>,
    response_etag: Option<String>,
}

#[derive(Debug)]
struct RequestMeta {
    key: String,
    if_none_match: Option<String>,
    if_match: Option<String>,
}

#[derive(Debug)]
struct InterceptorState {
    actions: VecDeque<ResponseAction>,
    pending: Option<RequestMeta>,
    records: Vec<ResponseRecord>,
    failure: Option<&'static str>,
    /// First `If-Match` token this plan observed on the wire.
    ///
    /// Each conditional replacement in one plan must present the identical
    /// token, which is what proves the code under test reuses the ETag it
    /// originally observed instead of a freshly read one.
    pinned_etag: Option<String>,
}

#[derive(Clone, Debug)]
struct ResponseInterceptor {
    state: Arc<Mutex<InterceptorState>>,
}

impl ResponseInterceptor {
    fn new(actions: impl IntoIterator<Item = ResponseAction>) -> Self {
        Self {
            state: Arc::new(Mutex::new(InterceptorState {
                actions: actions.into_iter().collect(),
                pending: None,
                records: Vec::new(),
                failure: None,
                pinned_etag: None,
            })),
        }
    }

    fn records(&self) -> Vec<ResponseRecord> {
        self.state
            .lock()
            .expect("interceptor state is not poisoned")
            .records
            .clone()
    }

    fn finish(&self) -> Result<Vec<ResponseRecord>, &'static str> {
        let state = self
            .state
            .lock()
            .expect("interceptor state is not poisoned");
        if let Some(failure) = state.failure {
            return Err(failure);
        }
        if !state.actions.is_empty() || state.pending.is_some() {
            return Err("interceptor response plan was not exhausted");
        }
        Ok(state.records.clone())
    }
}

#[derive(Debug)]
struct ConnectionReset;

impl fmt::Display for ConnectionReset {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("injected post-send connection reset")
    }
}

impl Error for ConnectionReset {}

impl Intercept for ResponseInterceptor {
    fn name(&self) -> &'static str {
        "RavelLiveResponseInterceptor"
    }

    fn read_before_transmit(
        &self,
        context: &BeforeTransmitInterceptorContextRef<'_>,
        _runtime_components: &RuntimeComponents,
        _cfg: &mut ConfigBag,
    ) -> Result<(), HookError> {
        let mut state = self
            .state
            .lock()
            .expect("interceptor state is not poisoned");
        if state.actions.is_empty() {
            return Ok(());
        }
        let request = context.request();
        let uri = request
            .uri()
            .parse::<http::Uri>()
            .map_err(HookError::from)?;
        state.pending = Some(RequestMeta {
            key: uri.path().trim_start_matches('/').to_owned(),
            if_none_match: request.headers().get("if-none-match").map(str::to_owned),
            if_match: request.headers().get("if-match").map(str::to_owned),
        });
        Ok(())
    }

    fn read_before_deserialization(
        &self,
        context: &BeforeDeserializationInterceptorContextRef<'_>,
        _runtime_components: &RuntimeComponents,
        _cfg: &mut ConfigBag,
    ) -> Result<(), HookError> {
        let mut state = self
            .state
            .lock()
            .expect("interceptor state is not poisoned");
        let Some(action) = state.actions.pop_front() else {
            return Ok(());
        };
        let Some(request) = state.pending.take() else {
            state.failure = Some("interceptor response had no matching request");
            return Err(Box::new(ConnectionReset));
        };
        if request.key != action.key
            || !action.condition.matches(
                request.if_none_match.as_deref(),
                request.if_match.as_deref(),
            )
        {
            state.failure = Some("interceptor request did not match the response plan");
            return Err(Box::new(ConnectionReset));
        }
        if action.condition == Condition::Match {
            let supplied = request
                .if_match
                .clone()
                .expect("a matched If-Match condition carries a token");
            match &state.pinned_etag {
                Some(pinned) if *pinned != supplied => {
                    state.failure = Some("conditional replacement did not reuse the observed ETag");
                    return Err(Box::new(ConnectionReset));
                }
                Some(_) => {}
                None => state.pinned_etag = Some(supplied),
            }
        }

        let response = context.response();
        state.records.push(ResponseRecord {
            step: action.step,
            client: "production-interceptor",
            condition: action.condition.label(),
            supplied_etag: request.if_match.clone(),
            key: request.key,
            classification: match action.mode {
                ResponseMode::Drop => "dropped-response",
                ResponseMode::Observe => "observed-response",
            },
            status: response.status().as_u16(),
            error_code: None,
            request_id: response
                .headers()
                .get("x-amz-request-id")
                .map(str::to_owned),
            extended_request_id: response.headers().get("x-amz-id-2").map(str::to_owned),
            response_etag: response.headers().get("etag").map(str::to_owned),
        });
        match action.mode {
            ResponseMode::Drop => Err(Box::new(ConnectionReset)),
            ResponseMode::Observe => Ok(()),
        }
    }
}

fn live_enabled() -> Result<bool, &'static str> {
    let flag = std::env::var(LIVE_FLAG).ok();
    let bucket = std::env::var(BUCKET_ENV).ok();
    let region = std::env::var(REGION_ENV).ok();
    if flag.as_deref() != Some("1") {
        return Ok(false);
    }
    // An explicit opt-in with incomplete configuration is a misconfigured job,
    // not an absent one: skipping would let it report green without probing S3.
    if bucket.is_none() {
        return Err("live S3 opt-in is missing the bucket variable");
    }
    if region.is_none() {
        return Err("live S3 opt-in is missing the region variable");
    }
    if bucket.as_deref() != Some(EXPECTED_BUCKET) {
        return Err("unexpected live S3 bucket");
    }
    if region.as_deref() != Some(EXPECTED_REGION) {
        return Err("unexpected live S3 region");
    }
    Ok(true)
}

fn clean_store(config: &SdkConfig) -> S3Store {
    S3Store::new(
        EXPECTED_BUCKET,
        Region::new(EXPECTED_REGION),
        Builder::from(config),
    )
}

fn fault_store(config: &SdkConfig, interceptor: ResponseInterceptor) -> S3Store {
    S3Store::new(
        EXPECTED_BUCKET,
        Region::new(EXPECTED_REGION),
        Builder::from(config).interceptor(interceptor),
    )
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

async fn get_event(store: &S3Store, key: &str) -> Result<(Vec<u8>, Event), &'static str> {
    match store
        .get_object(key, MAX_EVENT_BYTES)
        .await
        .map_err(|_| "event read failed")?
    {
        GetOutcome::Found { bytes, .. } => {
            let decoded = event::decode(&bytes, key).map_err(|_| "event decode failed")?;
            Ok((bytes, decoded))
        }
        GetOutcome::NotFound => Err("event is missing"),
    }
}

/// A validator that checks only `tail` cannot detect a missing or malformed
/// ancestor below it.
async fn validate_retained_chain(store: &S3Store, tail: &EventRef) -> Result<u64, &'static str> {
    let mut expected = tail.clone();
    let mut hops = 0_u64;
    loop {
        let (bytes, event) = get_event(store, expected.key()).await?;
        if sha256(&bytes) != expected.digest() || event.sequence() != expected.sequence() {
            return Err("chain-hop-identity");
        }
        hops += 1;
        match event.parent() {
            Some(parent) => {
                if parent.sequence() + 1 != event.sequence() {
                    return Err("chain-hop-sequence");
                }
                expected = parent.clone();
            }
            None => {
                if event.sequence() != 1 {
                    return Err("chain-root-sequence");
                }
                return Ok(hops);
            }
        }
    }
}

#[derive(Serialize)]
struct Evidence {
    run_id: String,
    prefix: String,
    bucket: &'static str,
    region: &'static str,
    injected_responses: Vec<ResponseRecord>,
    scenario_a: Option<ScenarioRecord>,
    scenario_b: Option<ScenarioRecord>,
    workers: Vec<WorkerResult>,
    winner_event_key: Option<String>,
    loser_event_key: Option<String>,
    winner_artifact_key: Option<String>,
    loser_artifact_key: Option<String>,
    inherited_parent_key: Option<String>,
    inherited_chain_length: Option<u64>,
    final_validation: Option<&'static str>,
    claim_key: Option<String>,
    claim_winner: Option<u8>,
    result: String,
}

#[derive(Serialize)]
struct ScenarioRecord {
    initial_outcome: &'static str,
    resend_outcome: Option<&'static str>,
    prior_send_evidence: bool,
    head_operation_id: String,
    event_operation_id: String,
    event_key: String,
}

struct PreparedTransition {
    transition: head::HeadTransition,
    event: Event,
    condition: Condition,
}

async fn prepare_transition(
    store: &S3Store,
    identity: &str,
) -> Result<PreparedTransition, &'static str> {
    let observed = head::read(store).await.map_err(|_| "prepare-head-read")?;
    let (parent, sequence, event_parent, authority, condition) = match observed {
        Some(observed) => {
            let sequence = observed
                .head()
                .tail()
                .sequence()
                .checked_add(1)
                .ok_or("prepare-sequence")?;
            let event_parent = Some(observed.head().tail().clone());
            let authority = observed.head().authority().clone();
            (
                head::HeadParent::Existing(Box::new(observed)),
                sequence,
                event_parent,
                authority,
                Condition::Match,
            )
        }
        None => (
            head::HeadParent::Genesis,
            1,
            None,
            Authority::unowned(),
            Condition::Create,
        ),
    };
    let event = Event::new(
        format!("{identity}-event"),
        sequence,
        event_parent,
        sequence,
        EventContent::WorkflowStarted,
    )
    .map_err(|_| "prepare-event")?;
    let publication = event::publish(store, &event, None)
        .await
        .map_err(|_| "prepare-event-publication")?;
    let candidate = ravel::domain::campaign::Head::new(
        authority,
        publication.event_ref().clone(),
        format!("{identity}-head"),
    )
    .map_err(|_| "prepare-candidate-head")?;
    let transition = head::HeadTransition::new(parent, candidate, &event, &publication)
        .map_err(|_| "prepare-transition")?;
    Ok(PreparedTransition {
        transition,
        event,
        condition,
    })
}

async fn validate_transition_state(
    store: &S3Store,
    expected_head_bytes: &[u8],
    expected_event_bytes: &[u8],
    event: &Event,
) -> Result<(), &'static str> {
    let observed = head::read(store)
        .await
        .map_err(|_| "validation-head-read")?
        .ok_or("validation-head-missing")?;
    if observed.canonical_bytes() != expected_head_bytes {
        return Err("validation-head-bytes");
    }
    let (event_bytes, decoded) = get_event(store, observed.head().tail().key()).await?;
    if event_bytes != expected_event_bytes || decoded != *event {
        return Err("validation-event-identity");
    }
    Ok(())
}

async fn scenario_a(
    config: &SdkConfig,
    clean: &S3Store,
    identity: &str,
    evidence: &mut Evidence,
) -> Result<(), &'static str> {
    let prepared = prepare_transition(clean, identity).await?;
    let head_bytes = prepared.transition.canonical_head_bytes().to_vec();
    let event_bytes = prepared.transition.canonical_event_bytes().to_vec();
    let event_key = prepared.transition.candidate().tail().key().to_owned();
    let head_operation_id = prepared.transition.candidate().operation_id().to_owned();
    let event_operation_id = prepared.event.operation_id().to_owned();
    let interceptor = ResponseInterceptor::new([ResponseAction::drop(
        "scenario-a-head-put",
        HEAD_KEY,
        prepared.condition,
    )]);
    let fault = fault_store(config, interceptor.clone());
    let mut history = AttemptHistory::default();
    let outcome = head::commit(&fault, prepared.transition, &mut history).await;
    if !matches!(outcome, head::HeadCommitOutcome::Committed) {
        return Err("scenario-a-outcome");
    }
    evidence.injected_responses.extend(interceptor.records());
    let records = interceptor.finish()?;
    if records.len() != 1
        || !(200..300).contains(&records[0].status)
        || records[0].request_id.is_none()
    {
        return Err("scenario-a-injected-response");
    }
    validate_transition_state(clean, &head_bytes, &event_bytes, &prepared.event).await?;
    evidence.scenario_a = Some(ScenarioRecord {
        initial_outcome: "committed",
        resend_outcome: None,
        prior_send_evidence: history.may_have_been_sent(),
        head_operation_id,
        event_operation_id,
        event_key,
    });
    Ok(())
}

async fn scenario_b(
    config: &SdkConfig,
    clean: &S3Store,
    identity: &str,
    evidence: &mut Evidence,
) -> Result<(), &'static str> {
    let prepared = prepare_transition(clean, identity).await?;
    let head_bytes = prepared.transition.canonical_head_bytes().to_vec();
    let event_bytes = prepared.transition.canonical_event_bytes().to_vec();
    let event_key = prepared.transition.candidate().tail().key().to_owned();
    let head_operation_id = prepared.transition.candidate().operation_id().to_owned();
    let event_operation_id = prepared.event.operation_id().to_owned();
    let interceptor = ResponseInterceptor::new([
        ResponseAction::drop("scenario-b-head-put", HEAD_KEY, prepared.condition),
        ResponseAction::drop("scenario-b-head-read", HEAD_KEY, Condition::None),
        ResponseAction::observe("scenario-b-identical-resend", HEAD_KEY, prepared.condition),
    ]);
    let fault = fault_store(config, interceptor.clone());
    let mut history = AttemptHistory::default();
    let first = head::commit(&fault, prepared.transition, &mut history).await;
    let transition = match first {
        head::HeadCommitOutcome::Unresolved(transition) => transition,
        _ => return Err("scenario-b-first-outcome"),
    };
    if transition.canonical_head_bytes() != head_bytes
        || transition.canonical_event_bytes() != event_bytes
        || transition.candidate().operation_id() != head_operation_id
    {
        return Err("scenario-b-transition-changed");
    }
    // The resend must carry the first attempt's possible-send evidence. Without
    // it the 412 below would be classified as an ordinary stale precondition,
    // and the same reread branch would still commit — so HTTP status alone
    // cannot tell the two apart.
    if !history.may_have_been_sent() {
        return Err("scenario-b-missing-prior-send-evidence");
    }
    let second = head::commit(&fault, transition, &mut history).await;
    if !matches!(second, head::HeadCommitOutcome::Committed) {
        return Err("scenario-b-resend-outcome");
    }
    evidence.injected_responses.extend(interceptor.records());
    let records = interceptor.finish()?;
    if records.len() != 3
        || !(200..300).contains(&records[0].status)
        || !(200..300).contains(&records[1].status)
        || records[2].status != 412
        || records.iter().any(|record| record.request_id.is_none())
    {
        return Err("scenario-b-injected-responses");
    }
    validate_transition_state(clean, &head_bytes, &event_bytes, &prepared.event).await?;
    evidence.scenario_b = Some(ScenarioRecord {
        initial_outcome: "unresolved",
        resend_outcome: Some("committed-after-412"),
        prior_send_evidence: true,
        head_operation_id,
        event_operation_id,
        event_key,
    });
    Ok(())
}

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum WorkerMode {
    Head,
    Claim,
}

#[derive(Deserialize, Serialize)]
struct WorkerParams {
    mode: WorkerMode,
    run_id: String,
    worker_id: u8,
    parent_head_bytes: Vec<u8>,
    parent_sequence: u64,
    parent_tail_digest: String,
    parent_tail_key: String,
    barrier_address: String,
    creation_time_unix_ms: u64,
    claim_key: Option<String>,
}

#[derive(Clone, Deserialize, Serialize)]
struct WorkerResult {
    classification: String,
    worker_id: u8,
    event_operation_id: String,
    event_key: String,
    head_operation_id: String,
    artifact_digest: String,
    artifact_key: String,
    claim_operation_id: Option<String>,
}

impl WorkerResult {
    fn failed(worker_id: u8, step: &'static str) -> Self {
        Self {
            classification: format!("failed:{step}"),
            worker_id,
            event_operation_id: String::new(),
            event_key: String::new(),
            head_operation_id: String::new(),
            artifact_digest: String::new(),
            artifact_key: String::new(),
            claim_operation_id: None,
        }
    }
}

async fn load_sdk_config() -> Result<SdkConfig, &'static str> {
    tokio::time::timeout(
        OPERATION_DEADLINE,
        aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(Region::new(EXPECTED_REGION))
            .load(),
    )
    .await
    .map_err(|_| "configuration-load-timeout")
}

async fn worker_scenario(params: &WorkerParams) -> Result<WorkerResult, &'static str> {
    if !live_enabled()? {
        return Err("worker-live-gate");
    }
    let config = load_sdk_config().await?;
    match params.mode {
        WorkerMode::Head => head_worker_scenario(params, &config).await,
        WorkerMode::Claim => claim_worker_scenario(params, &config).await,
    }
}

async fn head_worker_scenario(
    params: &WorkerParams,
    config: &SdkConfig,
) -> Result<WorkerResult, &'static str> {
    let store = clean_store(config);
    let observed = head::read(&store)
        .await
        .map_err(|_| "worker-head-read")?
        .ok_or("worker-head-missing")?;
    if observed.canonical_bytes() != params.parent_head_bytes
        || observed.head().tail().sequence() != params.parent_sequence
        || observed.head().tail().digest() != params.parent_tail_digest
        || observed.head().tail().key() != params.parent_tail_key
    {
        return Err("worker-parent-changed");
    }
    let authority = observed.head().authority().clone();
    let parent_ref = observed.head().tail().clone();

    let artifact_bytes = format!("{}-artifact-{}", params.run_id, params.worker_id).into_bytes();
    let artifact = artifacts::publish(
        &store,
        artifact_bytes,
        "application/octet-stream".into(),
        format!("{}-producer-{}", params.run_id, params.worker_id),
        params.creation_time_unix_ms,
        Some("live-ambiguity".into()),
    )
    .await
    .map_err(|_| "worker-artifact-publication")?;

    wait_for_release(params)?;

    let event_operation_id = format!("{}-event-{}", params.run_id, params.worker_id);
    // append gives the head the tail's operation identity, so one append is
    // recorded under one id in both the head and the retained event.
    let head_operation_id = event_operation_id.clone();
    let event = Event::new(
        event_operation_id.clone(),
        params
            .parent_sequence
            .checked_add(1)
            .ok_or("worker-sequence")?,
        Some(parent_ref),
        params.parent_sequence + 1,
        EventContent::ArtifactPublished(artifact.artifact_ref().clone()),
    )
    .map_err(|_| "worker-event")?;
    let encoded = event::encode(&event).map_err(|_| "worker-event-encode")?;
    let event_key = encoded.key().to_owned();
    let artifact_digest = artifact.artifact_ref().digest().to_owned();
    let artifact_key = format!("artifacts/sha256/{artifact_digest}");
    let mut history = AttemptHistory::default();
    let mut outcome = tokio::time::timeout(
        OPERATION_DEADLINE,
        head::append(
            &store,
            head::HeadParent::Existing(Box::new(observed)),
            authority,
            &event,
            Some(&artifact),
            &mut history,
        ),
    )
    .await
    .map_err(|_| "worker-append-timeout")?
    .map_err(|_| "worker-append")?;
    for _ in 1..3 {
        outcome = match outcome {
            head::HeadCommitOutcome::RetryIdentically(transition) => tokio::time::timeout(
                OPERATION_DEADLINE,
                head::commit(&store, transition, &mut history),
            )
            .await
            .map_err(|_| "worker-commit-timeout")?,
            terminal => terminal,
        };
        if !matches!(outcome, head::HeadCommitOutcome::RetryIdentically(_)) {
            break;
        }
    }
    let classification = match outcome {
        head::HeadCommitOutcome::Committed => "committed",
        head::HeadCommitOutcome::ProvenNotCommitted => "proven-not-committed",
        head::HeadCommitOutcome::CommittedSuperseded => "committed-superseded",
        head::HeadCommitOutcome::RetryIdentically(_) => "retry-exhausted",
        head::HeadCommitOutcome::Unresolved(_) => "unresolved",
    };
    Ok(WorkerResult {
        classification: classification.to_owned(),
        worker_id: params.worker_id,
        event_operation_id,
        event_key,
        head_operation_id,
        artifact_digest,
        artifact_key,
        claim_operation_id: None,
    })
}

async fn claim_worker_scenario(
    params: &WorkerParams,
    config: &SdkConfig,
) -> Result<WorkerResult, &'static str> {
    params.claim_key.as_deref().ok_or("worker-claim-key")?;
    let work = WorkRef::new(
        WorkId::new("live-race-work".into()).map_err(|_| "worker-claim-work")?,
        4,
    );
    let workspace =
        WorkspaceId::new(params.run_id.clone()).map_err(|_| "worker-claim-workspace")?;
    let actor = ActorId::new(format!("claim-actor-{}", params.worker_id))
        .map_err(|_| "worker-claim-actor")?;
    let instance = InstanceId::new(format!("claim-instance-{}", params.worker_id))
        .map_err(|_| "worker-claim-instance")?;
    let attempt = claims::prepare_acquisition(
        &work,
        &workspace,
        "live-race",
        &actor,
        &instance,
        params.creation_time_unix_ms + 60_000,
    )
    .map_err(|_| "worker-claim-prepare")?;
    let operation_id = attempt.claim().operation_id().to_owned();
    wait_for_release(params)?;
    let store = clean_store(config);
    let mut history = AttemptHistory::default();
    let mut outcome = tokio::time::timeout(
        OPERATION_DEADLINE,
        claims::acquire(&store, attempt, &mut history),
    )
    .await
    .map_err(|_| "worker-claim-timeout")?;
    // Mirror the head worker: a fresh 409 with an absent reread is a valid S3
    // race that asks for an identical retry, not a worker failure.
    for _ in 1..3 {
        outcome = match outcome {
            ClaimAcquireOutcome::RetryIdentically(attempt) => tokio::time::timeout(
                OPERATION_DEADLINE,
                claims::acquire(&store, attempt, &mut history),
            )
            .await
            .map_err(|_| "worker-claim-timeout")?,
            terminal => terminal,
        };
        if !matches!(outcome, ClaimAcquireOutcome::RetryIdentically(_)) {
            break;
        }
    }
    let classification = match outcome {
        ClaimAcquireOutcome::Acquired(authority) => {
            // The granted authority must name the work revision and derived key
            // this worker attempted, not merely any surviving record.
            if authority.claim().operation_id() != operation_id
                || !authority.authorizes(&work, &workspace, "live-race")
                || authority.claim().owner_actor().as_str() != actor.as_str()
            {
                return Err("worker-claim-authority");
            }
            "claim-committed"
        }
        ClaimAcquireOutcome::Collision => "claim-collision",
        ClaimAcquireOutcome::RetryIdentically(_) | ClaimAcquireOutcome::Unresolved(_) => {
            return Err("worker-claim-outcome");
        }
    };
    Ok(WorkerResult {
        classification: classification.into(),
        worker_id: params.worker_id,
        event_operation_id: String::new(),
        event_key: String::new(),
        head_operation_id: String::new(),
        artifact_digest: String::new(),
        artifact_key: String::new(),
        claim_operation_id: Some(operation_id),
    })
}

fn wait_for_release(params: &WorkerParams) -> Result<(), &'static str> {
    let address = params
        .barrier_address
        .parse::<SocketAddr>()
        .map_err(|_| "worker-barrier-address")?;
    let mut barrier = TcpStream::connect_timeout(&address, BARRIER_IO_TIMEOUT)
        .map_err(|_| "worker-barrier-connect")?;
    barrier
        .set_read_timeout(Some(WORKER_READY_DEADLINE))
        .map_err(|_| "worker-barrier-timeout")?;
    barrier
        .set_write_timeout(Some(BARRIER_IO_TIMEOUT))
        .map_err(|_| "worker-barrier-timeout")?;
    barrier
        .write_all(&[params.worker_id])
        .map_err(|_| "worker-barrier-ready")?;
    let mut release = [0_u8; 1];
    barrier
        .read_exact(&mut release)
        .map_err(|_| "worker-barrier-release")?;
    if release[0] != b'G' {
        return Err("worker-barrier-token");
    }
    Ok(())
}

fn worker_params(
    run_id: &str,
    worker_id: u8,
    observed: &head::ObservedHead,
    barrier_address: SocketAddr,
    creation_time_unix_ms: u64,
) -> WorkerParams {
    WorkerParams {
        mode: WorkerMode::Head,
        run_id: run_id.to_owned(),
        worker_id,
        parent_head_bytes: observed.canonical_bytes().to_vec(),
        parent_sequence: observed.head().tail().sequence(),
        parent_tail_digest: observed.head().tail().digest().to_owned(),
        parent_tail_key: observed.head().tail().key().to_owned(),
        barrier_address: barrier_address.to_string(),
        creation_time_unix_ms,
        claim_key: None,
    }
}

fn claim_worker_params(
    run_id: &str,
    worker_id: u8,
    claim_key: &str,
    barrier_address: SocketAddr,
    creation_time_unix_ms: u64,
) -> WorkerParams {
    WorkerParams {
        mode: WorkerMode::Claim,
        run_id: run_id.to_owned(),
        worker_id,
        parent_head_bytes: Vec::new(),
        parent_sequence: 0,
        parent_tail_digest: String::new(),
        parent_tail_key: String::new(),
        barrier_address: barrier_address.to_string(),
        creation_time_unix_ms,
        claim_key: Some(claim_key.to_owned()),
    }
}

fn spawn_worker(params: &WorkerParams) -> Result<Child, &'static str> {
    let executable = std::env::current_exe().map_err(|_| "worker-executable")?;
    let mut child = Command::new(executable)
        .args([
            "--exact",
            "live_s3_race_worker",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(WORKER_LAUNCH_ENV, "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "worker-spawn")?;
    let mut send_params = || -> Result<(), &'static str> {
        let line = serde_json::to_string(params).map_err(|_| "worker-params-serialize")?;
        let mut stdin = child.stdin.take().ok_or("worker-stdin")?;
        stdin
            .write_all(line.as_bytes())
            .and_then(|()| stdin.write_all(b"\n"))
            .map_err(|_| "worker-params-write")
    };
    if let Err(step) = send_params() {
        stop_worker(&mut child);
        return Err(step);
    }
    Ok(child)
}

fn release_workers(listener: &TcpListener) -> Result<(), &'static str> {
    listener
        .set_nonblocking(true)
        .map_err(|_| "barrier-nonblocking")?;
    let deadline = Instant::now() + WORKER_READY_DEADLINE;
    let mut streams: [Option<TcpStream>; 2] = [None, None];
    while streams.iter().any(Option::is_none) {
        if Instant::now() >= deadline {
            return Err("worker-ready-timeout");
        }
        match listener.accept() {
            Ok((mut stream, _)) => {
                stream
                    .set_read_timeout(Some(BARRIER_IO_TIMEOUT))
                    .map_err(|_| "barrier-read-timeout")?;
                stream
                    .set_write_timeout(Some(BARRIER_IO_TIMEOUT))
                    .map_err(|_| "barrier-write-timeout")?;
                let mut id = [0_u8; 1];
                stream
                    .read_exact(&mut id)
                    .map_err(|_| "barrier-ready-read")?;
                let slot = streams.get_mut(id[0] as usize).ok_or("barrier-worker-id")?;
                if slot.is_some() {
                    return Err("barrier-duplicate-worker");
                }
                *slot = Some(stream);
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(_) => return Err("barrier-accept"),
        }
    }
    for stream in streams.iter_mut().flatten() {
        stream.write_all(b"G").map_err(|_| "barrier-release")?;
    }
    Ok(())
}

fn stop_worker(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

fn wait_worker(
    mut child: Child,
    deadline: Instant,
    expected_worker_id: u8,
) -> Result<WorkerResult, &'static str> {
    let status = loop {
        if Instant::now() >= deadline {
            stop_worker(&mut child);
            return Err("worker-join-timeout");
        }
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => thread::sleep(Duration::from_millis(20)),
            Err(_) => {
                stop_worker(&mut child);
                return Err("worker-join");
            }
        }
    };
    let mut stdout = String::new();
    child
        .stdout
        .take()
        .ok_or("worker-stdout")?
        .read_to_string(&mut stdout)
        .map_err(|_| "worker-stdout-read")?;
    // Libtest's --nocapture interleaves the "test <name> ..." header with the
    // worker's own stdout, so the marker can appear mid-line.
    let line = stdout
        .lines()
        .find_map(|line| line.split_once(WORKER_MARKER).map(|(_, rest)| rest))
        .ok_or("worker-result-missing")?;
    let result: WorkerResult = serde_json::from_str(line).map_err(|_| "worker-result-invalid")?;
    if result.worker_id != expected_worker_id {
        return Err("worker-result-identity");
    }
    if !status.success() || result.classification.starts_with("failed:") {
        return Err("worker-failed");
    }
    Ok(result)
}

async fn validate_worker_objects(
    store: &S3Store,
    common_parent: &EventRef,
    worker: &WorkerResult,
    run_id: &str,
) -> Result<Event, &'static str> {
    let (_, event) = get_event(store, &worker.event_key).await?;
    if event.operation_id() != worker.event_operation_id
        || event.parent() != Some(common_parent)
        || event.sequence() != common_parent.sequence() + 1
    {
        return Err("worker-event-identity");
    }
    let artifact = match event.content() {
        EventContent::ArtifactPublished(reference) => reference,
        _ => return Err("worker-event-content"),
    };
    if artifact.digest() != worker.artifact_digest
        || worker.artifact_key != format!("artifacts/sha256/{}", worker.artifact_digest)
    {
        return Err("worker-artifact-reference");
    }
    let bytes = match store
        .get_object(&worker.artifact_key, artifacts::MAX_ARTIFACT_BYTES)
        .await
        .map_err(|_| "worker-artifact-read")?
    {
        GetOutcome::Found { bytes, .. } => bytes,
        GetOutcome::NotFound => return Err("worker-artifact-missing"),
    };
    let expected_bytes = format!("{run_id}-artifact-{}", worker.worker_id).into_bytes();
    if bytes != expected_bytes
        || artifact.size() != bytes.len() as u64
        || sha256(&bytes) != worker.artifact_digest
    {
        return Err("worker-artifact-bytes");
    }
    Ok(event)
}

fn race_pair(
    listener: &TcpListener,
    params: &[WorkerParams; 2],
    evidence: &mut Evidence,
) -> Result<[WorkerResult; 2], &'static str> {
    let mut first_child = spawn_worker(&params[0])?;
    let mut second_child = match spawn_worker(&params[1]) {
        Ok(child) => child,
        Err(error) => {
            stop_worker(&mut first_child);
            return Err(error);
        }
    };
    if let Err(error) = release_workers(listener) {
        stop_worker(&mut first_child);
        stop_worker(&mut second_child);
        return Err(error);
    }
    let deadline = Instant::now() + WORKER_JOIN_DEADLINE;
    let first_result = match wait_worker(first_child, deadline, params[0].worker_id) {
        Ok(result) => result,
        Err(error) => {
            stop_worker(&mut second_child);
            return Err(error);
        }
    };
    let results = [
        first_result,
        wait_worker(second_child, deadline, params[1].worker_id)?,
    ];
    evidence.workers.extend(results.iter().cloned());
    Ok(results)
}

async fn two_process_race(
    config: &SdkConfig,
    run_id: &str,
    creation_time_unix_ms: u64,
    evidence: &mut Evidence,
) -> Result<(), &'static str> {
    let store = clean_store(config);
    let observed = head::read(&store)
        .await
        .map_err(|_| "race-parent-read")?
        .ok_or("race-parent-missing")?;
    let common_parent = observed.head().tail().clone();
    let inherited_bytes = observed.canonical_bytes().to_vec();
    // The chain below the pre-race parent is inherited from whatever already
    // existed at head.json, so it is validated before the race rather than
    // assumed sound.
    let inherited_hops = validate_retained_chain(&store, &common_parent).await?;
    evidence.inherited_parent_key = Some(common_parent.key().to_owned());
    evidence.inherited_chain_length = Some(inherited_hops);
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|_| "barrier-bind")?;
    let address = listener.local_addr().map_err(|_| "barrier-address")?;
    let params = [
        worker_params(run_id, 0, &observed, address, creation_time_unix_ms),
        worker_params(run_id, 1, &observed, address, creation_time_unix_ms),
    ];
    let results = race_pair(&listener, &params, evidence)?;
    let committed: Vec<_> = results
        .iter()
        .filter(|result| result.classification == "committed")
        .collect();
    let not_committed: Vec<_> = results
        .iter()
        .filter(|result| result.classification == "proven-not-committed")
        .collect();
    if committed.len() != 1 || not_committed.len() != 1 {
        return Err("race-worker-outcomes");
    }
    let winner = committed[0];
    let loser = not_committed[0];
    let winner_event = validate_worker_objects(&store, &common_parent, winner, run_id).await?;
    validate_worker_objects(&store, &common_parent, loser, run_id).await?;
    let final_head = head::read(&store)
        .await
        .map_err(|_| "race-final-head-read")?
        .ok_or("race-final-head-missing")?;
    if final_head.head().operation_id() != winner.head_operation_id
        || final_head.head().tail().key() != winner.event_key
        || winner_event.operation_id() != winner.event_operation_id
    {
        return Err("race-final-authority");
    }
    // A third writer replacing `head.json` after the pre-race read would make the
    // two local workers race against an unobserved head, so
    // `winner_event.parent()` must equal `common_parent`.
    let final_parent = winner_event.parent().ok_or("race-final-parent-missing")?;
    if *final_parent != common_parent {
        return Err("race-foreign-head-writer");
    }
    let final_hops = validate_retained_chain(&store, final_head.head().tail()).await?;
    if final_hops != inherited_hops + 1 || inherited_bytes == final_head.canonical_bytes() {
        return Err("race-final-chain");
    }
    evidence.winner_event_key = Some(winner.event_key.clone());
    evidence.loser_event_key = Some(loser.event_key.clone());
    evidence.winner_artifact_key = Some(winner.artifact_key.clone());
    evidence.loser_artifact_key = Some(loser.artifact_key.clone());
    evidence.final_validation = Some("passed");
    Ok(())
}

async fn two_process_claim_race(
    config: &SdkConfig,
    run_id: &str,
    creation_time_unix_ms: u64,
    evidence: &mut Evidence,
) -> Result<(), &'static str> {
    let key = format!("workspace/{run_id}/campaigns/live-race/work/live-race-work/claim.json");
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|_| "claim-barrier-bind")?;
    let address = listener.local_addr().map_err(|_| "claim-barrier-address")?;
    let params = [
        claim_worker_params(run_id, 0, &key, address, creation_time_unix_ms),
        claim_worker_params(run_id, 1, &key, address, creation_time_unix_ms),
    ];
    let results = race_pair(&listener, &params, evidence)?;
    let committed: Vec<_> = results
        .iter()
        .filter(|result| result.classification == "claim-committed")
        .collect();
    let collisions: Vec<_> = results
        .iter()
        .filter(|result| result.classification == "claim-collision")
        .collect();
    if committed.len() != 1 || collisions.len() != 1 {
        return Err("claim-race-worker-outcomes");
    }
    let winner = committed[0];
    let stored = match clean_store(config)
        .get_object(&key, MAX_CLAIM_BYTES)
        .await
        .map_err(|_| "claim-race-read")?
    {
        GetOutcome::Found { bytes, .. } => bytes,
        GetOutcome::NotFound => return Err("claim-race-missing"),
    };
    let claim = claims::decode(&stored).map_err(|_| "claim-race-decode")?;
    if claim.operation_id()
        != winner
            .claim_operation_id
            .as_deref()
            .ok_or("claim-race-operation")?
        || claim.owner_actor().as_str() != format!("claim-actor-{}", winner.worker_id)
        || claim.owner_instance().as_str() != format!("claim-instance-{}", winner.worker_id)
        || claim.fence() != 1
        || claim.work_revision() != 4
    {
        return Err("claim-race-authority");
    }
    evidence.claim_key = Some(key);
    evidence.claim_winner = Some(winner.worker_id);
    Ok(())
}

#[tokio::test]
async fn dropped_response_is_unknown_through_the_production_store() {
    let interceptor = ResponseInterceptor::new([ResponseAction::drop(
        "unit-drop",
        HEAD_KEY,
        Condition::Create,
    )]);
    let replay = StaticReplayClient::new(vec![ReplayEvent::new(
        http::Request::new(SdkBody::empty()),
        http::Response::builder()
            .status(200)
            .header("x-amz-request-id", "unit-request")
            .header("etag", "\"unit-etag\"")
            .body(SdkBody::empty())
            .expect("valid test response"),
    )]);
    let builder = aws_sdk_s3::Config::builder()
        .credentials_provider(Credentials::for_tests())
        .endpoint_url("https://s3.test.invalid")
        .http_client(replay)
        .interceptor(interceptor.clone());
    let store = S3Store::new("test-bucket", Region::new("us-east-1"), builder);
    let mut history = AttemptHistory::default();

    assert!(matches!(
        store
            .put_if_absent(HEAD_KEY, b"head".to_vec(), &mut history)
            .await,
        MutationOutcome::Unknown
    ));
    let records = interceptor.finish().expect("response plan completes");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].status, 200);
    assert_eq!(records[0].request_id.as_deref(), Some("unit-request"));
}

async fn run_live(
    run_id: &str,
    creation_time_unix_ms: u64,
    evidence: &mut Evidence,
) -> Result<(), &'static str> {
    let config = load_sdk_config().await?;
    let clean = clean_store(&config);
    tokio::time::timeout(
        SCENARIO_DEADLINE,
        scenario_a(
            &config,
            &clean,
            &format!("{run_id}-dropped-success"),
            evidence,
        ),
    )
    .await
    .map_err(|_| "scenario-a-timeout")??;
    tokio::time::timeout(
        SCENARIO_DEADLINE,
        scenario_b(
            &config,
            &clean,
            &format!("{run_id}-missing-evidence"),
            evidence,
        ),
    )
    .await
    .map_err(|_| "scenario-b-timeout")??;
    two_process_race(&config, run_id, creation_time_unix_ms, evidence).await?;
    two_process_claim_race(&config, run_id, creation_time_unix_ms, evidence).await?;
    Ok(())
}

fn write_evidence(evidence: &Evidence) -> Result<String, &'static str> {
    let path = format!("pilot/e02/live-s3-ambiguity-{}.json", evidence.run_id);
    let mut bytes = serde_json::to_vec_pretty(evidence).map_err(|_| "evidence-serialization")?;
    bytes.push(b'\n');
    let mut file = File::create_new(&path).map_err(|_| "evidence-create")?;
    file.write_all(&bytes).map_err(|_| "evidence-write")?;
    Ok(path)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn live_s3_ambiguity() {
    match live_enabled() {
        Ok(true) => {}
        Ok(false) => {
            println!("live S3 ambiguity skipped: set RAVEL_LIVE_S3=1, bucket, and region");
            return;
        }
        Err(step) => panic!("{step}"),
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time follows Unix epoch");
    let run_id = format!("{}-{}", now.as_nanos(), process::id());
    let prefix = format!("e02-ambiguity/{run_id}");
    assert!(
        prefix.len() <= MAX_PREFIX_BYTES,
        "run prefix exceeds fixed bound"
    );
    println!("live S3 ambiguity prefix: {prefix}");
    let mut evidence = Evidence {
        run_id: run_id.clone(),
        prefix,
        bucket: EXPECTED_BUCKET,
        region: EXPECTED_REGION,
        injected_responses: Vec::new(),
        scenario_a: None,
        scenario_b: None,
        workers: Vec::new(),
        winner_event_key: None,
        loser_event_key: None,
        winner_artifact_key: None,
        loser_artifact_key: None,
        inherited_parent_key: None,
        inherited_chain_length: None,
        final_validation: None,
        claim_key: None,
        claim_winner: None,
        result: "running".into(),
    };
    let result = run_live(&run_id, now.as_millis() as u64, &mut evidence).await;
    evidence.result = match result {
        Ok(()) => "passed".into(),
        Err(step) => format!("failed:{step}"),
    };
    if let Err(step) = result {
        println!("live S3 ambiguity step: {step}");
    }
    let evidence_path = write_evidence(&evidence).expect("evidence file is writable");
    println!("live S3 ambiguity evidence: {evidence_path}");
    if let Err(step) = result {
        panic!("live S3 ambiguity failed at {step}; see {evidence_path}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn live_s3_race_worker() {
    // Only the parent process supplies `WorkerParams` on stdin.
    if std::env::var(WORKER_LAUNCH_ENV).as_deref() != Ok("1") {
        println!("live S3 race worker skipped: launched outside spawn_worker");
        return;
    }
    let mut line = String::new();
    let parsed = BufReader::new(std::io::stdin())
        .read_line(&mut line)
        .ok()
        .and_then(|_| serde_json::from_str::<WorkerParams>(&line).ok());
    let result = match parsed {
        Some(params) => match worker_scenario(&params).await {
            Ok(result) => result,
            Err(step) => WorkerResult::failed(params.worker_id, step),
        },
        None => WorkerResult::failed(u8::MAX, "worker-params"),
    };
    let failed = result.classification.starts_with("failed:");
    println!(
        "{WORKER_MARKER}{}",
        serde_json::to_string(&result).expect("worker result serializes")
    );
    assert!(!failed, "worker failed");
}
