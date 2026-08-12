//! Read-only controller intake for sealed work submissions.
//!
//! Intake first proves that the disposable projection matches a fresh campaign
//! head. The reconstruction reads claims without mutating claim or campaign
//! history and does not consult presence. Declared artifact sizes above the
//! 10 MiB publication cap are ineligible.

use std::{error::Error, fmt};

use crate::{
    db::worker::DbHandle,
    distributed::{
        claims::{self, ClaimReadError, ClaimState},
        presence::WorkspaceId,
    },
    domain::{
        attempt::{self, MAX_SUBMISSION_BYTES, Submission},
        work::WorkRef,
    },
    storage::{
        artifacts::{MAX_ARTIFACT_BYTES, artifact_key},
        s3::{GetError, GetOutcome, S3Store, VerificationOutcome},
    },
    sync::replay::{self, NotReadyReason, Readiness},
};

/// Submission identity accepted from matching durable claim and result evidence.
///
/// The stable operation ID is the deduplication key consumed by the fenced
/// controller path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SealedSubmissionFact(Submission);

impl SealedSubmissionFact {
    #[allow(dead_code)]
    pub(crate) fn operation_id(&self) -> &str {
        self.0.operation_id()
    }
}

/// Data-free failure category for controller intake.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum IntakeError {
    NotReady(NotReadyReason),
    InvalidInput,
    Storage,
}

impl fmt::Display for IntakeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::NotReady(_) => "controller intake is not ready",
            Self::InvalidInput => "controller intake input is invalid",
            Self::Storage => "controller intake storage failed",
        })
    }
}

impl Error for IntakeError {}

/// Returns validated sealed-submission facts only after replay reaches a fresh
/// head observation.
///
/// The read-only path evaluates work in input order and issues no PUT, DELETE,
/// head/event commit, claim mutation, or presence request.
///
/// # Errors
///
/// Returns [`IntakeError::NotReady`] when replay cannot establish readiness,
/// [`IntakeError::InvalidInput`] for invalid key context, and
/// [`IntakeError::Storage`] for claim, submission, or artifact transport failure.
#[allow(dead_code)]
pub(crate) async fn intake(
    store: &S3Store,
    handle: &DbHandle,
    workspace: &WorkspaceId,
    campaign_id: &str,
    work: &[WorkRef],
) -> Result<Vec<SealedSubmissionFact>, IntakeError> {
    if let Readiness::NotReady(reason) = replay::refresh(store, handle).await {
        return Err(IntakeError::NotReady(reason));
    }

    let mut facts = Vec::new();
    for work in work {
        if let Some(fact) = evaluate_work(store, workspace, campaign_id, work).await? {
            facts.push(fact);
        }
    }
    Ok(facts)
}

async fn evaluate_work(
    store: &S3Store,
    workspace: &WorkspaceId,
    campaign_id: &str,
    work: &WorkRef,
) -> Result<Option<SealedSubmissionFact>, IntakeError> {
    let observed = match claims::observe(store, workspace, campaign_id, work.id()).await {
        Ok(Some(observed)) => observed,
        Ok(None) => return Ok(None),
        Err(ClaimReadError::Invalid(error)) => {
            let _ = error;
            return Ok(None);
        }
        Err(ClaimReadError::InvalidInput) => return Err(IntakeError::InvalidInput),
        Err(ClaimReadError::Storage(error)) => {
            let _ = error;
            return Err(IntakeError::Storage);
        }
    };
    let claim = observed.claim();
    if claim.work_id() != work.id() || claim.work_revision() != work.revision() {
        return Ok(None);
    }
    let ClaimState::Sealed { result_ref } = claim.state() else {
        return Ok(None);
    };
    if result_ref.size() > MAX_ARTIFACT_BYTES as u64 {
        return Ok(None);
    }

    let key = match attempt::submission_key(
        workspace.as_str(),
        campaign_id,
        result_ref.producer_attempt(),
    ) {
        Ok(key) => key,
        Err(_) => return Ok(None),
    };
    let bytes = match store.get_object(&key, MAX_SUBMISSION_BYTES).await {
        Ok(GetOutcome::Found { bytes, .. }) => bytes,
        Ok(GetOutcome::NotFound) | Err(GetError::TooLarge) => return Ok(None),
        Err(GetError::MissingETag | GetError::Transport) => return Err(IntakeError::Storage),
    };
    let submission = match attempt::decode(&bytes) {
        Ok(submission) => submission,
        Err(_) => return Ok(None),
    };
    let expected = match Submission::new(
        claim.work_id().clone(),
        claim.work_revision(),
        claim.owner_actor().clone(),
        claim.owner_instance().clone(),
        claim.fence(),
        claim.operation_id().to_owned(),
        result_ref.clone(),
    ) {
        Ok(expected) => expected,
        Err(_) => return Ok(None),
    };
    if submission != expected {
        return Ok(None);
    }

    match store
        .verify_object(
            &artifact_key(result_ref.digest()),
            result_ref.digest(),
            result_ref.size(),
        )
        .await
    {
        VerificationOutcome::Matched => Ok(Some(SealedSubmissionFact(submission))),
        VerificationOutcome::NotFound | VerificationOutcome::Mismatch => Ok(None),
        VerificationOutcome::Transport => Err(IntakeError::Storage),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::{Path, PathBuf},
        process,
    };

    use aws_sdk_s3::primitives::SdkBody;

    use super::*;
    use crate::{
        distributed::{
            claims::{self, Claim, ClaimState},
            identity::{ActorId, InstanceId},
        },
        domain::{
            attempt,
            campaign::{ArtifactRef, Authority, EventRef, Head},
            work::WorkId,
        },
        storage::s3::test_support::{replay_store, response},
        sync::{head, replay},
    };

    const CHILD_DIGEST: &str = "5454daad2e7a3c4ac66d017f75296647c7b3ebddc4e8d2b19d7cde066239d34c";
    const RESULT_DIGEST: &str = "f6a214f7a5fcda0c2cee9660b7fc29f5649e3c68aad48e20e950137c98913a68";
    const GENESIS_BYTES: &[u8] = include_bytes!(
        "../../tests/fixtures/v1/0000000000000001-d10251de219fe17099d74f8f14729b1cbb33bdd73f919d6fb907ef32d5a51648.cbor.zst"
    );
    const CHILD_BYTES: &[u8] = include_bytes!(
        "../../tests/fixtures/v1/0000000000000002-5454daad2e7a3c4ac66d017f75296647c7b3ebddc4e8d2b19d7cde066239d34c.cbor.zst"
    );
    const ETAG: &str = "\"intake-etag\"";

    fn path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!("ravel-intake-{}-{label}.sqlite3", process::id()))
    }

    fn clean(path: &Path) {
        let mut journal = path.as_os_str().to_owned();
        journal.push("-journal");
        let _ = fs::remove_file(PathBuf::from(journal));
        let _ = fs::remove_file(path);
    }

    fn reference(sequence: u64, digest: &str) -> EventRef {
        EventRef::from_digest(sequence, digest.to_owned()).unwrap()
    }

    fn child_ref() -> EventRef {
        reference(2, CHILD_DIGEST)
    }

    fn head_response() -> http::Response<SdkBody> {
        let value = Head::new(Authority::unowned(), child_ref(), "head-operation".into()).unwrap();
        response(200, &[("etag", ETAG)], head::encode(&value).unwrap())
    }

    fn found(bytes: impl Into<SdkBody>) -> http::Response<SdkBody> {
        response(200, &[("etag", ETAG)], bytes)
    }

    fn workspace() -> WorkspaceId {
        WorkspaceId::new("workspace-1".into()).unwrap()
    }

    fn work(id: &str, revision: u64) -> WorkRef {
        WorkRef::new(WorkId::new(id.into()).unwrap(), revision)
    }

    fn result_ref(producer: &str, size: u64) -> ArtifactRef {
        ArtifactRef::new(
            RESULT_DIGEST.into(),
            size,
            "application/json".into(),
            producer.into(),
            1,
            None,
        )
        .unwrap()
    }

    fn claim(id: &str, revision: u64, state: ClaimState) -> Claim {
        Claim::new(
            WorkId::new(id.into()).unwrap(),
            revision,
            ActorId::new("rust-worker".into()).unwrap(),
            InstanceId::new("instance-a".into()).unwrap(),
            9,
            "op-claim-001".into(),
            state,
        )
        .unwrap()
    }

    fn sealed_claim(id: &str, revision: u64, result_ref: ArtifactRef) -> Claim {
        claim(id, revision, ClaimState::Sealed { result_ref })
    }

    fn submission(claim: &Claim, result_ref: ArtifactRef) -> Submission {
        Submission::new(
            claim.work_id().clone(),
            claim.work_revision(),
            claim.owner_actor().clone(),
            claim.owner_instance().clone(),
            claim.fence(),
            claim.operation_id().to_owned(),
            result_ref,
        )
        .unwrap()
    }

    async fn evaluate(
        work: &WorkRef,
        mut responses: Vec<http::Response<SdkBody>>,
    ) -> Result<Option<SealedSubmissionFact>, IntakeError> {
        let expected = responses.len();
        // Sentinel: the replay client records a request only while a queued
        // response remains, so an injected extra request becomes countable.
        responses.push(response(500, &[], SdkBody::empty()));
        let (store, client) = replay_store(responses);
        let outcome = evaluate_work(&store, &workspace(), "campaign-1", work).await;
        assert_eq!(client.actual_requests().count(), expected);
        for request in client.actual_requests() {
            assert_eq!(request.method(), http::Method::GET);
        }
        outcome
    }

    #[tokio::test]
    async fn fresh_reconstruction_returns_only_repeatable_sealed_facts() {
        let database = path("fresh-reconstruction");
        clean(&database);
        let result_ref = result_ref("attempt-17", 6);
        let active = claim(
            "active-work",
            1,
            ClaimState::Active {
                lease_until: u64::MAX,
            },
        );
        let sealed = sealed_claim("sealed-work", 4, result_ref.clone());
        let submission = submission(&sealed, result_ref);

        let mut responses = vec![head_response(), found(CHILD_BYTES), found(GENESIS_BYTES)];
        for _ in 0..2 {
            responses.extend([
                head_response(),
                found(claims::encode(&active).unwrap()),
                found(claims::encode(&sealed).unwrap()),
                found(attempt::encode(&submission).unwrap()),
                found(b"result".to_vec()),
            ]);
        }
        let (store, client) = replay_store(responses);
        let handle = replay::startup(&store, &database)
            .await
            .unwrap()
            .into_handle();
        let requested = [work("active-work", 1), work("sealed-work", 4)];

        let first = intake(&store, &handle, &workspace(), "campaign-1", &requested)
            .await
            .unwrap();
        let second = intake(&store, &handle, &workspace(), "campaign-1", &requested)
            .await
            .unwrap();

        assert_eq!(first, second);
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].operation_id(), "op-claim-001");
        assert_eq!(client.actual_requests().count(), 13);
        for request in client.actual_requests() {
            assert_eq!(request.method(), http::Method::GET);
            assert!(
                !request
                    .uri()
                    .parse::<http::Uri>()
                    .unwrap()
                    .path()
                    .contains("/presence/")
            );
        }

        drop(handle);
        clean(&database);
    }

    #[tokio::test]
    async fn absent_active_and_stale_claims_produce_no_fact() {
        assert_eq!(
            evaluate(
                &work("work-17", 4),
                vec![response(404, &[], SdkBody::empty())]
            )
            .await,
            Ok(None)
        );
        assert_eq!(
            evaluate(&work("work-17", 4), vec![found(b"not-json".to_vec())]).await,
            Ok(None)
        );
        let active = claim("work-17", 4, ClaimState::Active { lease_until: 10 });
        assert_eq!(
            evaluate(
                &work("work-17", 4),
                vec![found(claims::encode(&active).unwrap())]
            )
            .await,
            Ok(None)
        );
        let result = result_ref("attempt-17", 6);
        for stale in [
            sealed_claim("other-work", 4, result.clone()),
            sealed_claim("work-17", 3, result.clone()),
        ] {
            assert_eq!(
                evaluate(
                    &work("work-17", 4),
                    vec![found(claims::encode(&stale).unwrap())]
                )
                .await,
                Ok(None)
            );
        }
    }

    #[tokio::test]
    async fn missing_oversized_and_malformed_submissions_produce_no_fact() {
        let result = result_ref("attempt-17", 6);
        let claim = sealed_claim("work-17", 4, result);
        let claim_bytes = claims::encode(&claim).unwrap();
        for evidence in [
            response(404, &[], SdkBody::empty()),
            found(vec![b'x'; MAX_SUBMISSION_BYTES + 1]),
            found(b"not-json".to_vec()),
        ] {
            assert_eq!(
                evaluate(
                    &work("work-17", 4),
                    vec![found(claim_bytes.clone()), evidence],
                )
                .await,
                Ok(None)
            );
        }
    }

    #[tokio::test]
    async fn every_cross_object_mismatch_produces_no_fact() {
        let result = result_ref("attempt-17", 6);
        let claim = sealed_claim("work-17", 4, result.clone());
        let claim_bytes = claims::encode(&claim).unwrap();
        let variants = [
            submission(
                &sealed_claim("work-17", 4, result_ref("other-attempt", 6)),
                result_ref("other-attempt", 6),
            ),
            Submission::new(
                WorkId::new("other-work".into()).unwrap(),
                claim.work_revision(),
                claim.owner_actor().clone(),
                claim.owner_instance().clone(),
                claim.fence(),
                claim.operation_id().to_owned(),
                result.clone(),
            )
            .unwrap(),
            Submission::new(
                claim.work_id().clone(),
                5,
                claim.owner_actor().clone(),
                claim.owner_instance().clone(),
                claim.fence(),
                claim.operation_id().to_owned(),
                result.clone(),
            )
            .unwrap(),
            Submission::new(
                claim.work_id().clone(),
                claim.work_revision(),
                ActorId::new("other-actor".into()).unwrap(),
                claim.owner_instance().clone(),
                claim.fence(),
                claim.operation_id().to_owned(),
                result.clone(),
            )
            .unwrap(),
            Submission::new(
                claim.work_id().clone(),
                claim.work_revision(),
                claim.owner_actor().clone(),
                InstanceId::new("other-instance".into()).unwrap(),
                claim.fence(),
                claim.operation_id().to_owned(),
                result.clone(),
            )
            .unwrap(),
            Submission::new(
                claim.work_id().clone(),
                claim.work_revision(),
                claim.owner_actor().clone(),
                claim.owner_instance().clone(),
                8,
                claim.operation_id().to_owned(),
                result.clone(),
            )
            .unwrap(),
            Submission::new(
                claim.work_id().clone(),
                claim.work_revision(),
                claim.owner_actor().clone(),
                claim.owner_instance().clone(),
                claim.fence(),
                "other-operation".into(),
                result.clone(),
            )
            .unwrap(),
            submission(
                &sealed_claim("work-17", 4, result_ref("attempt-17", 5)),
                result_ref("attempt-17", 5),
            ),
            submission(
                &claim,
                ArtifactRef::new(
                    CHILD_DIGEST.into(),
                    6,
                    "application/json".into(),
                    "attempt-17".into(),
                    1,
                    None,
                )
                .unwrap(),
            ),
            submission(
                &claim,
                ArtifactRef::new(
                    RESULT_DIGEST.into(),
                    6,
                    "text/plain".into(),
                    "attempt-17".into(),
                    1,
                    None,
                )
                .unwrap(),
            ),
            submission(
                &claim,
                ArtifactRef::new(
                    RESULT_DIGEST.into(),
                    6,
                    "application/json".into(),
                    "attempt-17".into(),
                    2,
                    None,
                )
                .unwrap(),
            ),
            submission(
                &claim,
                ArtifactRef::new(
                    RESULT_DIGEST.into(),
                    6,
                    "application/json".into(),
                    "attempt-17".into(),
                    1,
                    Some("standard".into()),
                )
                .unwrap(),
            ),
        ];
        for mismatched in variants {
            assert_eq!(
                evaluate(
                    &work("work-17", 4),
                    vec![
                        found(claim_bytes.clone()),
                        found(attempt::encode(&mismatched).unwrap()),
                    ],
                )
                .await,
                Ok(None)
            );
        }
    }

    #[tokio::test]
    async fn artifact_bounds_and_verification_fail_closed() {
        let invalid_key = result_ref("bad/attempt", 6);
        let invalid_key_claim = sealed_claim("work-17", 4, invalid_key);
        assert_eq!(
            evaluate(
                &work("work-17", 4),
                vec![found(claims::encode(&invalid_key_claim).unwrap())],
            )
            .await,
            Ok(None)
        );

        let oversized = result_ref("attempt-17", MAX_ARTIFACT_BYTES as u64 + 1);
        let oversized_claim = sealed_claim("work-17", 4, oversized);
        assert_eq!(
            evaluate(
                &work("work-17", 4),
                vec![found(claims::encode(&oversized_claim).unwrap())],
            )
            .await,
            Ok(None)
        );

        let at_cap = result_ref("attempt-17", MAX_ARTIFACT_BYTES as u64);
        let at_cap_claim = sealed_claim("work-17", 4, at_cap);
        assert_eq!(
            evaluate(
                &work("work-17", 4),
                vec![
                    found(claims::encode(&at_cap_claim).unwrap()),
                    response(404, &[], SdkBody::empty()),
                ],
            )
            .await,
            Ok(None)
        );

        let result = result_ref("attempt-17", 6);
        let claim = sealed_claim("work-17", 4, result.clone());
        let record = submission(&claim, result);
        let claim_bytes = claims::encode(&claim).unwrap();
        let submission_bytes = attempt::encode(&record).unwrap();
        for artifact in [
            response(404, &[], SdkBody::empty()),
            found(b"wrong!".to_vec()),
            found(b"short".to_vec()),
        ] {
            assert_eq!(
                evaluate(
                    &work("work-17", 4),
                    vec![
                        found(claim_bytes.clone()),
                        found(submission_bytes.clone()),
                        artifact,
                    ],
                )
                .await,
                Ok(None)
            );
        }
    }

    #[tokio::test]
    async fn readiness_failure_precedes_claim_reads() {
        let database = path("not-ready");
        clean(&database);
        let handle = DbHandle::spawn(database.clone()).await.unwrap();
        let (store, client) = replay_store(vec![response(404, &[], SdkBody::empty())]);
        assert!(matches!(
            intake(
                &store,
                &handle,
                &workspace(),
                "campaign-1",
                &[work("work-17", 4)],
            )
            .await,
            Err(IntakeError::NotReady(_))
        ));
        assert_eq!(client.actual_requests().count(), 1);
        let request = client.actual_requests().next().unwrap();
        assert_eq!(
            request.uri().parse::<http::Uri>().unwrap().path(),
            "/head.json"
        );
        drop(handle);
        clean(&database);
    }

    #[tokio::test]
    async fn invalid_key_context_is_an_input_error() {
        let (store, _) = replay_store(Vec::new());
        assert_eq!(
            evaluate_work(&store, &workspace(), "bad/campaign", &work("work-17", 4),).await,
            Err(IntakeError::InvalidInput)
        );
    }

    #[tokio::test]
    async fn storage_error_discards_prior_facts() {
        let database = path("partial-results");
        clean(&database);
        let (startup_store, _) = replay_store(vec![
            head_response(),
            found(CHILD_BYTES),
            found(GENESIS_BYTES),
        ]);
        let handle = replay::startup(&startup_store, &database)
            .await
            .unwrap()
            .into_handle();

        let result = result_ref("attempt-17", 6);
        let sealed = sealed_claim("sealed-work", 4, result.clone());
        let record = submission(&sealed, result);
        let (store, _) = replay_store(vec![
            head_response(),
            found(claims::encode(&sealed).unwrap()),
            found(attempt::encode(&record).unwrap()),
            found(b"result".to_vec()),
            response(500, &[], SdkBody::empty()),
        ]);
        assert_eq!(
            intake(
                &store,
                &handle,
                &workspace(),
                "campaign-1",
                &[work("sealed-work", 4), work("failed-work", 1)],
            )
            .await,
            Err(IntakeError::Storage)
        );

        // The same evidence without the failing work yields the fact, so the
        // discarded-facts assertion above cannot rot into a no-fact fixture.
        let (retry_store, _) = replay_store(vec![
            head_response(),
            found(claims::encode(&sealed).unwrap()),
            found(attempt::encode(&record).unwrap()),
            found(b"result".to_vec()),
        ]);
        let facts = intake(
            &retry_store,
            &handle,
            &workspace(),
            "campaign-1",
            &[work("sealed-work", 4)],
        )
        .await
        .unwrap();
        assert_eq!(facts.len(), 1);

        drop(handle);
        clean(&database);
    }

    #[tokio::test]
    async fn transport_failures_are_errors_not_absence() {
        assert_eq!(
            evaluate(
                &work("work-17", 4),
                vec![response(500, &[], SdkBody::empty())]
            )
            .await,
            Err(IntakeError::Storage)
        );

        let result = result_ref("attempt-17", 6);
        let claim = sealed_claim("work-17", 4, result.clone());
        let claim_bytes = claims::encode(&claim).unwrap();
        assert_eq!(
            evaluate(
                &work("work-17", 4),
                vec![
                    found(claim_bytes.clone()),
                    response(500, &[], SdkBody::empty())
                ],
            )
            .await,
            Err(IntakeError::Storage)
        );

        let record = submission(&claim, result);
        assert_eq!(
            evaluate(
                &work("work-17", 4),
                vec![
                    found(claim_bytes.clone()),
                    response(200, &[], attempt::encode(&record).unwrap()),
                ],
            )
            .await,
            Err(IntakeError::Storage)
        );

        assert_eq!(
            evaluate(
                &work("work-17", 4),
                vec![
                    found(claim_bytes),
                    found(attempt::encode(&record).unwrap()),
                    response(500, &[], SdkBody::empty()),
                ],
            )
            .await,
            Err(IntakeError::Storage)
        );
    }

    #[test]
    fn errors_are_data_free() {
        let errors = [
            IntakeError::NotReady(NotReadyReason::Behind),
            IntakeError::InvalidInput,
            IntakeError::Storage,
        ];
        for error in errors {
            let message = error.to_string();
            for sensitive in [
                "workspace-1",
                "campaign-1",
                "work-17",
                "test-bucket",
                "AccessDenied",
                "response body",
                "credential",
            ] {
                assert!(!message.contains(sensitive));
            }
        }
    }
}
