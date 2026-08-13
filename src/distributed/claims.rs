//! Scoped work claims and the controller's sealed-submission intake.
//!
//! A claim object lives at its scope's claim key and holds exactly one state: an active lease
//! or one terminal seal naming immutable result bytes. Workers publish immutable submission
//! records and seal their own claim; the controller only reads.
//!
//! Intake never lists a prefix: it reads the deterministic claim key for work the projection
//! already knows. A sealed claim yields a fact only when the claim, its submission record, and
//! the caller's expected identity agree exactly on scope, plan, work revision, owner, fence,
//! and operation, and when the submission bytes hash to the sealed digest and size. An active
//! lease, a stale revision, a regressed fence, missing evidence, or any mismatch yields no
//! fact, and repeated intake of one sealed claim yields the same fact.
//!
//! Both records carry a `record` kind, because submission records live in the global
//! content-addressed artifact space where any published bytes are addressable.
//!
//! Intake proves the submission record, not the result bytes it names: a consumer verifies
//! those against the result digest before using them.
//! commentlint: allow(JUDGE)

use std::{
    future::Future,
    num::{NonZeroU64, NonZeroUsize},
    pin::Pin,
    task::Poll,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{
    distributed::identity::{ActorId, InstanceId},
    domain::{
        artifact::ArtifactRef,
        validation::{ValidationError, validate_key_segment},
        work::WorkRef,
    },
    scope::{Digest, ScopeClaimIdentity, ScopeIdentity, scope_claim_key},
    storage::{
        artifacts,
        s3::{GetError, GetOutcome, S3Store},
    },
    sync::WireError,
};

/// Bound on one claim object and one submission record.
pub const MAX_CLAIM_BYTES: usize = 4 * 1024;

const CLAIM_RECORD: &str = "scope_claim";
const SUBMISSION_RECORD: &str = "sealed_submission";

/// Active lease or the single terminal seal of one claim generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ScopeClaimState {
    Active {
        lease_until: NonZeroU64,
    },
    /// Terminal seal naming the immutable submission record that carries the result binding.
    Sealed {
        submission: ArtifactRef,
    },
}

/// Durable claim record for one exact work revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScopeClaim {
    identity: ScopeClaimIdentity,
    owner_actor: ActorId,
    owner_instance: InstanceId,
    operation_id: String,
    state: ScopeClaimState,
}

impl ScopeClaim {
    /// # Errors
    ///
    /// Returns [`ValidationError`] when `operation_id` is not one key segment.
    pub fn new(
        identity: ScopeClaimIdentity,
        owner_actor: ActorId,
        owner_instance: InstanceId,
        operation_id: String,
        state: ScopeClaimState,
    ) -> Result<Self, ValidationError> {
        validate_key_segment(&operation_id)?;
        Ok(Self {
            identity,
            owner_actor,
            owner_instance,
            operation_id,
            state,
        })
    }

    pub fn identity(&self) -> &ScopeClaimIdentity {
        &self.identity
    }

    pub fn state(&self) -> &ScopeClaimState {
        &self.state
    }
}

/// Immutable record a worker publishes beside its result bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SealedSubmission {
    identity: ScopeClaimIdentity,
    owner_actor: ActorId,
    owner_instance: InstanceId,
    operation_id: String,
    result: ArtifactRef,
}

impl SealedSubmission {
    /// # Errors
    ///
    /// Returns [`ValidationError`] when `operation_id` is not one key segment.
    pub fn new(
        identity: ScopeClaimIdentity,
        owner_actor: ActorId,
        owner_instance: InstanceId,
        operation_id: String,
        result: ArtifactRef,
    ) -> Result<Self, ValidationError> {
        validate_key_segment(&operation_id)?;
        Ok(Self {
            identity,
            owner_actor,
            owner_instance,
            operation_id,
            result,
        })
    }
}

/// Identity the controller requires of one claim before it will accept a seal.
///
/// `minimum_fence` is the highest fence already recorded for this revision; a seal below it
/// belongs to a superseded generation.
pub struct ExpectedClaim {
    scope: ScopeIdentity,
    plan_digest: Digest,
    work: WorkRef,
    minimum_fence: Option<NonZeroU64>,
}

impl ExpectedClaim {
    pub fn new(
        scope: ScopeIdentity,
        plan_digest: Digest,
        work: WorkRef,
        minimum_fence: Option<NonZeroU64>,
    ) -> Self {
        Self {
            scope,
            plan_digest,
            work,
            minimum_fence,
        }
    }
}

/// Validated sealed submission, keyed by its stable operation identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SealedSubmissionFact {
    operation_id: String,
    work: WorkRef,
    claim_fence: NonZeroU64,
    submission: ArtifactRef,
    result: ArtifactRef,
}

impl SealedSubmissionFact {
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    pub fn work(&self) -> &WorkRef {
        &self.work
    }

    pub fn claim_fence(&self) -> NonZeroU64 {
        self.claim_fence
    }

    /// Immutable submission record the claim sealed against.
    pub fn submission(&self) -> &ArtifactRef {
        &self.submission
    }

    /// Result the submission record binds to this claim generation.
    pub fn result(&self) -> &ArtifactRef {
        &self.result
    }
}

/// Reason one claim produced no sealed fact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClaimRejection {
    /// No claim object exists for the requested revision.
    Absent,
    /// The claim holds an active lease, which is not completion.
    NotSealed,
    /// The seal belongs to a superseded fence.
    StaleFence,
    /// The claim names another plan lineage than the caller's projection.
    IdentityMismatch,
    /// The referenced submission record is missing.
    MissingEvidence,
    /// The submission record disagrees with the claim it seals.
    EvidenceMismatch,
    /// The stored bytes are not a decodable record for this key, which no retry changes.
    Malformed,
}

/// Outcome of reading and validating one claim.
#[must_use]
pub enum SubmissionIntake {
    Sealed(Box<SealedSubmissionFact>),
    Rejected(ClaimRejection),
    /// Storage did not answer, so this claim's durable state stays unknown.
    Unavailable,
}

impl SubmissionIntake {
    /// Reports whether durable state answered for this claim.
    ///
    /// An active lease is not an answer: the effect it fences may still be running, so it stays
    /// for the next controller.
    pub fn is_resolved(&self) -> bool {
        match self {
            Self::Sealed(_) => true,
            Self::Rejected(rejection) => *rejection != ClaimRejection::NotSealed,
            Self::Unavailable => false,
        }
    }
}

/// Reads one claim key and validates any seal on it.
pub async fn intake(store: &S3Store, expected: &ExpectedClaim) -> SubmissionIntake {
    let key = scope_claim_key(&expected.scope, &expected.work);
    let claim = match read_object(store, &key).await {
        Ok(Some(bytes)) => match decode_claim(&bytes, &key, &expected.scope, &expected.work) {
            Ok(claim) => claim,
            Err(_) => return SubmissionIntake::Rejected(ClaimRejection::Malformed),
        },
        Ok(None) => return SubmissionIntake::Rejected(ClaimRejection::Absent),
        Err(rejection) => return rejection,
    };
    let ScopeClaimState::Sealed {
        submission: evidence,
    } = claim.state()
    else {
        return SubmissionIntake::Rejected(ClaimRejection::NotSealed);
    };
    if claim.identity().plan_digest() != &expected.plan_digest {
        return SubmissionIntake::Rejected(ClaimRejection::IdentityMismatch);
    }
    if expected
        .minimum_fence
        .is_some_and(|floor| claim.identity().claim_fence() < floor)
    {
        return SubmissionIntake::Rejected(ClaimRejection::StaleFence);
    }
    let evidence_key = artifacts::artifact_key(evidence.digest());
    let bytes = match read_object(store, &evidence_key).await {
        Ok(Some(bytes)) => bytes,
        Ok(None) => return SubmissionIntake::Rejected(ClaimRejection::MissingEvidence),
        Err(rejection) => return rejection,
    };
    if u64::try_from(bytes.len()) != Ok(evidence.size())
        || format!("{:x}", Sha256::digest(&bytes)) != evidence.digest()
    {
        return SubmissionIntake::Rejected(ClaimRejection::EvidenceMismatch);
    }
    let submission = match decode_submission(&bytes, &expected.scope, &expected.work) {
        Ok(submission) => submission,
        Err(_) => return SubmissionIntake::Rejected(ClaimRejection::EvidenceMismatch),
    };
    if submission.identity != *claim.identity()
        || submission.owner_actor != claim.owner_actor
        || submission.owner_instance != claim.owner_instance
        || submission.operation_id != claim.operation_id
    {
        return SubmissionIntake::Rejected(ClaimRejection::EvidenceMismatch);
    }
    SubmissionIntake::Sealed(Box::new(SealedSubmissionFact {
        operation_id: claim.operation_id.clone(),
        work: claim.identity().work().clone(),
        claim_fence: claim.identity().claim_fence(),
        submission: evidence.clone(),
        result: submission.result,
    }))
}

/// Runs intake for every expected claim with at most `concurrency` reads in flight.
pub async fn intake_all(
    store: &S3Store,
    expected: &[ExpectedClaim],
    concurrency: NonZeroUsize,
) -> Vec<SubmissionIntake> {
    bounded_map(expected.len(), concurrency, |index| {
        intake(store, &expected[index])
    })
    .await
}

/// Runs `run` for every index below `count`, keeping at most `concurrency` futures alive.
///
/// The in-flight set is a single capped `Vec` polled by one task, so no work escapes the
/// caller: dropping this future cancels every started item.
pub(crate) async fn bounded_map<R, F, Fut>(
    count: usize,
    concurrency: NonZeroUsize,
    run: F,
) -> Vec<R>
where
    F: Fn(usize) -> Fut,
    Fut: Future<Output = R>,
{
    let capacity = concurrency.get();
    let mut finished: Vec<Option<R>> = Vec::with_capacity(count);
    finished.resize_with(count, || None);
    let mut started = 0;
    let mut in_flight: Vec<(usize, Pin<Box<Fut>>)> = Vec::with_capacity(capacity);
    loop {
        while in_flight.len() < capacity && started < count {
            in_flight.push((started, Box::pin(run(started))));
            started += 1;
        }
        if in_flight.is_empty() {
            break;
        }
        let (slot, outcome) = std::future::poll_fn(|context| {
            for (slot, (_, pending)) in in_flight.iter_mut().enumerate() {
                if let Poll::Ready(outcome) = pending.as_mut().poll(context) {
                    return Poll::Ready((slot, outcome));
                }
            }
            Poll::Pending
        })
        .await;
        let (index, _) = in_flight.swap_remove(slot);
        finished[index] = Some(outcome);
    }
    finished
        .into_iter()
        .map(|slot| slot.expect("every index below count completes"))
        .collect()
}

/// An oversized object is a permanent rejection: no retry shrinks stored bytes.
async fn read_object(store: &S3Store, key: &str) -> Result<Option<Vec<u8>>, SubmissionIntake> {
    match store.get_object(key, MAX_CLAIM_BYTES).await {
        Ok(GetOutcome::Found { bytes, .. }) => Ok(Some(bytes)),
        Ok(GetOutcome::NotFound) => Ok(None),
        Err(GetError::TooLarge) => Err(SubmissionIntake::Rejected(ClaimRejection::Malformed)),
        Err(_) => Err(SubmissionIntake::Unavailable),
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireArtifactRef {
    digest: String,
    size: u64,
    media_type: String,
    producer_attempt: String,
    creation_time_unix_ms: u64,
    retention_class: Option<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, tag = "state", rename_all = "snake_case")]
enum WireClaimState {
    Active { lease_until: u64 },
    Sealed { submission: WireArtifactRef },
}

/// Claim objects and submission records share this shape, so `record` keeps one from being
/// decoded as the other: submission records live in the global content-addressed artifact
/// space, where any published bytes are addressable.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireScopeClaim {
    record: String,
    campaign_id: String,
    scope_id: String,
    plan_digest: String,
    work_id: String,
    work_revision: u64,
    claim_fence: u64,
    owner_actor: String,
    owner_instance: String,
    operation_id: String,
    state: WireClaimState,
}

/// Encodes compact declaration-order JSON with every nullable field present.
///
/// # Errors
///
/// Returns [`WireError`] for serialization or size-limit failures.
pub fn encode_claim(claim: &ScopeClaim) -> Result<Vec<u8>, WireError> {
    bounded_json(&wire_record(
        CLAIM_RECORD,
        &claim.identity,
        &claim.owner_actor,
        &claim.owner_instance,
        &claim.operation_id,
        match &claim.state {
            ScopeClaimState::Active { lease_until } => WireClaimState::Active {
                lease_until: lease_until.get(),
            },
            ScopeClaimState::Sealed { submission } => WireClaimState::Sealed {
                submission: wire_artifact(submission),
            },
        },
    ))
}

/// Encodes one immutable submission record.
///
/// # Errors
///
/// Returns [`WireError`] for serialization or size-limit failures.
pub fn encode_submission(submission: &SealedSubmission) -> Result<Vec<u8>, WireError> {
    bounded_json(&wire_record(
        SUBMISSION_RECORD,
        &submission.identity,
        &submission.owner_actor,
        &submission.owner_instance,
        &submission.operation_id,
        WireClaimState::Sealed {
            submission: wire_artifact(&submission.result),
        },
    ))
}

fn wire_record(
    record: &str,
    identity: &ScopeClaimIdentity,
    owner_actor: &ActorId,
    owner_instance: &InstanceId,
    operation_id: &str,
    state: WireClaimState,
) -> WireScopeClaim {
    WireScopeClaim {
        record: record.to_owned(),
        campaign_id: identity.scope().campaign_id().as_str().to_owned(),
        scope_id: identity.scope().scope_id().as_str().to_owned(),
        plan_digest: identity.plan_digest().as_str().to_owned(),
        work_id: identity.work().id().as_str().to_owned(),
        work_revision: identity.work().revision(),
        claim_fence: identity.claim_fence().get(),
        owner_actor: owner_actor.as_str().to_owned(),
        owner_instance: owner_instance.as_str().to_owned(),
        operation_id: operation_id.to_owned(),
        state,
    }
}

/// Decodes claim bytes only when they belong to `expected_key` and name `expected_work`.
///
/// # Errors
///
/// Returns [`WireError`] for malformed, noncanonical, oversized, or mismatched input.
pub fn decode_claim(
    bytes: &[u8],
    expected_key: &str,
    expected_scope: &ScopeIdentity,
    expected_work: &WorkRef,
) -> Result<ScopeClaim, WireError> {
    let (wire, identity) = decode_bound(bytes, CLAIM_RECORD, expected_scope, expected_work)?;
    if scope_claim_key(expected_scope, expected_work) != expected_key {
        return Err(WireError::ReferenceMismatch);
    }
    let state = match wire.state {
        WireClaimState::Active { lease_until } => ScopeClaimState::Active {
            lease_until: NonZeroU64::new(lease_until).ok_or(WireError::InvalidValue)?,
        },
        WireClaimState::Sealed { submission } => ScopeClaimState::Sealed {
            submission: domain_artifact(submission)?,
        },
    };
    ScopeClaim::new(
        identity,
        ActorId::new(wire.owner_actor).map_err(|_| WireError::InvalidValue)?,
        InstanceId::new(wire.owner_instance).map_err(|_| WireError::InvalidValue)?,
        wire.operation_id,
        state,
    )
    .map_err(|_| WireError::InvalidValue)
}

/// Decodes submission bytes that must name `expected_scope` and `expected_work`.
///
/// # Errors
///
/// Returns [`WireError`] for malformed, noncanonical, oversized, mismatched, or non-terminal
/// input.
pub fn decode_submission(
    bytes: &[u8],
    expected_scope: &ScopeIdentity,
    expected_work: &WorkRef,
) -> Result<SealedSubmission, WireError> {
    let (wire, identity) = decode_bound(bytes, SUBMISSION_RECORD, expected_scope, expected_work)?;
    let WireClaimState::Sealed { submission: result } = wire.state else {
        return Err(WireError::InvalidValue);
    };
    SealedSubmission::new(
        identity,
        ActorId::new(wire.owner_actor).map_err(|_| WireError::InvalidValue)?,
        InstanceId::new(wire.owner_instance).map_err(|_| WireError::InvalidValue)?,
        wire.operation_id,
        domain_artifact(result)?,
    )
    .map_err(|_| WireError::InvalidValue)
}

fn decode_bound(
    bytes: &[u8],
    expected_record: &str,
    expected_scope: &ScopeIdentity,
    expected_work: &WorkRef,
) -> Result<(WireScopeClaim, ScopeClaimIdentity), WireError> {
    if bytes.is_empty() || bytes.len() > MAX_CLAIM_BYTES {
        return Err(WireError::LimitExceeded);
    }
    let wire: WireScopeClaim =
        serde_json::from_slice(bytes).map_err(|_| WireError::InvalidEncoding)?;
    if serde_json::to_vec(&wire).map_err(|_| WireError::InvalidEncoding)? != bytes {
        return Err(WireError::NonCanonical);
    }
    if wire.record != expected_record
        || wire.campaign_id != expected_scope.campaign_id().as_str()
        || wire.scope_id != expected_scope.scope_id().as_str()
        || wire.work_id != expected_work.id().as_str()
        || wire.work_revision != expected_work.revision()
    {
        return Err(WireError::InvalidValue);
    }
    let identity = ScopeClaimIdentity::new(
        expected_scope.clone(),
        Digest::new(wire.plan_digest.clone()).map_err(|_| WireError::InvalidValue)?,
        expected_work.clone(),
        wire.claim_fence,
    )
    .map_err(|_| WireError::InvalidValue)?;
    Ok((wire, identity))
}

fn bounded_json<T: Serialize>(value: &T) -> Result<Vec<u8>, WireError> {
    let bytes = serde_json::to_vec(value).map_err(|_| WireError::InvalidEncoding)?;
    if bytes.len() > MAX_CLAIM_BYTES {
        return Err(WireError::LimitExceeded);
    }
    Ok(bytes)
}

fn wire_artifact(result: &ArtifactRef) -> WireArtifactRef {
    WireArtifactRef {
        digest: result.digest().to_owned(),
        size: result.size(),
        media_type: result.media_type().to_owned(),
        producer_attempt: result.producer_attempt().to_owned(),
        creation_time_unix_ms: result.creation_time_unix_ms(),
        retention_class: result.retention_class().map(str::to_owned),
    }
}

fn domain_artifact(wire: WireArtifactRef) -> Result<ArtifactRef, WireError> {
    ArtifactRef::new(
        wire.digest,
        wire.size,
        wire.media_type,
        wire.producer_attempt,
        wire.creation_time_unix_ms,
        wire.retention_class,
    )
    .map_err(|_| WireError::InvalidValue)
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::{Duration, Instant},
    };

    use aws_sdk_s3::primitives::SdkBody;

    use crate::{
        distributed::identity::WorkspaceId,
        domain::work::WorkId,
        scope::{CampaignId, ScopeIdentity},
        storage::s3::test_support::{replay_store, response},
    };

    use super::*;

    const PLAN_DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn scope() -> ScopeIdentity {
        ScopeIdentity::root(
            WorkspaceId::new("workspace-a".into()).unwrap(),
            CampaignId::new("campaign-a".into()).unwrap(),
        )
        .unwrap()
    }

    fn work(revision: u64) -> WorkRef {
        WorkRef::new(WorkId::new("work-17".into()).unwrap(), revision)
    }

    fn identity(revision: u64, fence: u64) -> ScopeClaimIdentity {
        ScopeClaimIdentity::new(
            scope(),
            Digest::new(PLAN_DIGEST.into()).unwrap(),
            work(revision),
            fence,
        )
        .unwrap()
    }

    fn actor() -> ActorId {
        ActorId::new("actor-a".into()).unwrap()
    }

    fn instance() -> InstanceId {
        InstanceId::new("instance-a".into()).unwrap()
    }

    fn result_ref(digest: &str, size: u64) -> ArtifactRef {
        ArtifactRef::new(
            digest.to_owned(),
            size,
            "application/json".into(),
            "attempt-1".into(),
            1_700_000_000_000,
            None,
        )
        .unwrap()
    }

    /// Builds a claim whose seal names the submission bytes it is paired with.
    fn sealed_pair(revision: u64, fence: u64, operation: &str) -> (Vec<u8>, Vec<u8>, ArtifactRef) {
        let payload = result_ref(&"b".repeat(64), 11);
        let submission = SealedSubmission::new(
            identity(revision, fence),
            actor(),
            instance(),
            operation.into(),
            payload,
        )
        .unwrap();
        let submission_bytes = encode_submission(&submission).unwrap();
        let evidence = result_ref(
            &format!("{:x}", Sha256::digest(&submission_bytes)),
            submission_bytes.len() as u64,
        );
        let claim = ScopeClaim::new(
            identity(revision, fence),
            actor(),
            instance(),
            operation.into(),
            ScopeClaimState::Sealed {
                submission: evidence.clone(),
            },
        )
        .unwrap();
        (encode_claim(&claim).unwrap(), submission_bytes, evidence)
    }

    fn active_claim(revision: u64, fence: u64) -> Vec<u8> {
        let claim = ScopeClaim::new(
            identity(revision, fence),
            actor(),
            instance(),
            "operation-active".into(),
            ScopeClaimState::Active {
                lease_until: NonZeroU64::new(31_000).unwrap(),
            },
        )
        .unwrap();
        encode_claim(&claim).unwrap()
    }

    fn found(bytes: Vec<u8>) -> http::Response<SdkBody> {
        response(200, &[("etag", "\"object\"")], bytes)
    }

    fn expected(revision: u64, minimum_fence: Option<u64>) -> ExpectedClaim {
        ExpectedClaim::new(
            scope(),
            Digest::new(PLAN_DIGEST.into()).unwrap(),
            work(revision),
            minimum_fence.map(|fence| NonZeroU64::new(fence).unwrap()),
        )
    }

    #[tokio::test]
    async fn a_sealed_claim_and_its_evidence_yield_one_stable_fact() {
        let (claim_bytes, submission_bytes, evidence) = sealed_pair(1, 4, "operation-seal");
        let (store, client) = replay_store(vec![
            found(claim_bytes.clone()),
            found(submission_bytes.clone()),
            found(claim_bytes),
            found(submission_bytes),
        ]);

        let SubmissionIntake::Sealed(fact) = intake(&store, &expected(1, Some(4))).await else {
            panic!("expected a sealed fact");
        };
        assert_eq!(fact.operation_id(), "operation-seal");
        assert_eq!(fact.work(), &work(1));
        assert_eq!(fact.claim_fence().get(), 4);
        assert_eq!(fact.submission(), &evidence);
        assert_eq!(fact.result().digest(), "b".repeat(64));

        // Intake reads deterministic keys, never a prefix listing.
        let requests = client.actual_requests().collect::<Vec<_>>();
        let claim_path = requests[0].uri().parse::<http::Uri>().unwrap();
        assert!(claim_path.path().ends_with("/claims/work-17/1"));
        assert!(
            requests[1]
                .uri()
                .parse::<http::Uri>()
                .unwrap()
                .path()
                .contains("/artifacts/sha256/")
        );
        assert_eq!(requests[0].method(), "GET");

        // Repeated intake of the same sealed claim yields an identical fact.
        let SubmissionIntake::Sealed(again) = intake(&store, &expected(1, Some(4))).await else {
            panic!("expected the same sealed fact");
        };
        assert_eq!(again, fact);
    }

    #[tokio::test]
    async fn every_binding_mismatch_yields_no_fact() {
        // An active lease is not completion.
        let (store, _) = replay_store(vec![found(active_claim(1, 4))]);
        assert!(matches!(
            intake(&store, &expected(1, None)).await,
            SubmissionIntake::Rejected(ClaimRejection::NotSealed)
        ));

        // A seal below the recorded fence belongs to a superseded generation.
        let (claim_bytes, _, _) = sealed_pair(1, 3, "operation-stale");
        let (store, client) = replay_store(vec![found(claim_bytes)]);
        assert!(matches!(
            intake(&store, &expected(1, Some(4))).await,
            SubmissionIntake::Rejected(ClaimRejection::StaleFence)
        ));
        assert_eq!(client.actual_requests().count(), 1);

        // A claim for another revision cannot answer for this key.
        let (claim_bytes, _, _) = sealed_pair(2, 4, "operation-revision");
        let (store, _) = replay_store(vec![found(claim_bytes)]);
        assert!(matches!(
            intake(&store, &expected(1, None)).await,
            SubmissionIntake::Rejected(ClaimRejection::Malformed)
        ));

        // A claim naming another plan lineage is not current.
        let other_plan = ScopeClaim::new(
            ScopeClaimIdentity::new(scope(), Digest::new("c".repeat(64)).unwrap(), work(1), 4)
                .unwrap(),
            actor(),
            instance(),
            "operation-plan".into(),
            ScopeClaimState::Sealed {
                submission: result_ref(&"d".repeat(64), 10),
            },
        )
        .unwrap();
        let (store, _) = replay_store(vec![found(encode_claim(&other_plan).unwrap())]);
        assert!(matches!(
            intake(&store, &expected(1, None)).await,
            SubmissionIntake::Rejected(ClaimRejection::IdentityMismatch)
        ));

        // Missing evidence yields no fact.
        let (claim_bytes, _, _) = sealed_pair(1, 4, "operation-missing");
        let (store, _) = replay_store(vec![
            found(claim_bytes),
            response(404, &[], SdkBody::empty()),
        ]);
        assert!(matches!(
            intake(&store, &expected(1, None)).await,
            SubmissionIntake::Rejected(ClaimRejection::MissingEvidence)
        ));

        // Evidence bytes that do not hash to the sealed digest are refused.
        let (claim_bytes, submission_bytes, _) = sealed_pair(1, 4, "operation-digest");
        let mut tampered = submission_bytes;
        tampered.pop();
        let (store, _) = replay_store(vec![found(claim_bytes), found(tampered)]);
        assert!(matches!(
            intake(&store, &expected(1, None)).await,
            SubmissionIntake::Rejected(ClaimRejection::EvidenceMismatch)
        ));

        // Evidence that hashes correctly but names another owner, fence, or size is refused.
        for (label, submission) in [
            (
                "actor",
                SealedSubmission::new(
                    identity(1, 4),
                    ActorId::new("actor-b".into()).unwrap(),
                    instance(),
                    "operation-bind".into(),
                    result_ref(&"b".repeat(64), 11),
                )
                .unwrap(),
            ),
            (
                "instance",
                SealedSubmission::new(
                    identity(1, 4),
                    actor(),
                    InstanceId::new("instance-b".into()).unwrap(),
                    "operation-bind".into(),
                    result_ref(&"b".repeat(64), 11),
                )
                .unwrap(),
            ),
            (
                "fence",
                SealedSubmission::new(
                    identity(1, 9),
                    actor(),
                    instance(),
                    "operation-bind".into(),
                    result_ref(&"b".repeat(64), 11),
                )
                .unwrap(),
            ),
        ] {
            let submission_bytes = encode_submission(&submission).unwrap();
            let evidence = result_ref(
                &format!("{:x}", Sha256::digest(&submission_bytes)),
                submission_bytes.len() as u64,
            );
            let claim = ScopeClaim::new(
                identity(1, 4),
                actor(),
                instance(),
                "operation-bind".into(),
                ScopeClaimState::Sealed {
                    submission: evidence,
                },
            )
            .unwrap();
            let (store, _) = replay_store(vec![
                found(encode_claim(&claim).unwrap()),
                found(submission_bytes),
            ]);
            assert!(
                matches!(
                    intake(&store, &expected(1, None)).await,
                    SubmissionIntake::Rejected(ClaimRejection::EvidenceMismatch)
                ),
                "{label} mismatch must yield no fact"
            );
        }

        // Evidence whose declared size disagrees with its bytes is refused before hashing.
        let (_, submission_bytes, evidence) = sealed_pair(1, 4, "operation-size");
        let claim = ScopeClaim::new(
            identity(1, 4),
            actor(),
            instance(),
            "operation-size".into(),
            ScopeClaimState::Sealed {
                submission: result_ref(evidence.digest(), evidence.size() + 1),
            },
        )
        .unwrap();
        let (store, _) = replay_store(vec![
            found(encode_claim(&claim).unwrap()),
            found(submission_bytes),
        ]);
        assert!(matches!(
            intake(&store, &expected(1, None)).await,
            SubmissionIntake::Rejected(ClaimRejection::EvidenceMismatch)
        ));

        // A claim object republished as evidence is not a submission record.
        let (claim_bytes, _, _) = sealed_pair(1, 4, "operation-crossaxis");
        let self_named = ScopeClaim::new(
            identity(1, 4),
            actor(),
            instance(),
            "operation-crossaxis".into(),
            ScopeClaimState::Sealed {
                submission: result_ref(
                    &format!("{:x}", Sha256::digest(&claim_bytes)),
                    claim_bytes.len() as u64,
                ),
            },
        )
        .unwrap();
        let (store, _) = replay_store(vec![
            found(encode_claim(&self_named).unwrap()),
            found(claim_bytes),
        ]);
        assert!(matches!(
            intake(&store, &expected(1, None)).await,
            SubmissionIntake::Rejected(ClaimRejection::EvidenceMismatch)
        ));

        // Evidence that hashes correctly but names another operation is refused.
        let (_, other_bytes, other_evidence) = sealed_pair(1, 4, "operation-other");
        let crossed = ScopeClaim::new(
            identity(1, 4),
            actor(),
            instance(),
            "operation-claim".into(),
            ScopeClaimState::Sealed {
                submission: other_evidence,
            },
        )
        .unwrap();
        let (store, _) = replay_store(vec![
            found(encode_claim(&crossed).unwrap()),
            found(other_bytes),
        ]);
        assert!(matches!(
            intake(&store, &expected(1, None)).await,
            SubmissionIntake::Rejected(ClaimRejection::EvidenceMismatch)
        ));
        // An absent claim is an absence, not a failure.
        let (store, _) = replay_store(vec![response(404, &[], SdkBody::empty())]);
        assert!(matches!(
            intake(&store, &expected(1, None)).await,
            SubmissionIntake::Rejected(ClaimRejection::Absent)
        ));

        // An oversized object is permanent, not a retry.
        let (store, _) = replay_store(vec![found(vec![b'x'; MAX_CLAIM_BYTES + 1])]);
        assert!(matches!(
            intake(&store, &expected(1, None)).await,
            SubmissionIntake::Rejected(ClaimRejection::Malformed)
        ));

        // A storage failure stays unresolved rather than becoming an absence.
        let (store, _) = replay_store(vec![response(500, &[], SdkBody::empty())]);
        assert!(matches!(
            intake(&store, &expected(1, None)).await,
            SubmissionIntake::Unavailable
        ));
    }

    #[test]
    fn claim_bytes_round_trip_and_reject_noncanonical_input() {
        let (claim_bytes, submission_bytes, _) = sealed_pair(1, 4, "operation-wire");
        let key = scope_claim_key(&scope(), &work(1));
        let claim = decode_claim(&claim_bytes, &key, &scope(), &work(1)).unwrap();
        assert_eq!(encode_claim(&claim).unwrap(), claim_bytes);
        let submission = decode_submission(&submission_bytes, &scope(), &work(1)).unwrap();
        assert_eq!(encode_submission(&submission).unwrap(), submission_bytes);

        // Padded bytes decode but are not canonical.
        let mut padded = claim_bytes.clone();
        padded.insert(1, b' ');
        assert_eq!(
            decode_claim(&padded, &key, &scope(), &work(1)),
            Err(WireError::NonCanonical)
        );
        // An unrelated key cannot claim these bytes.
        assert_eq!(
            decode_claim(&claim_bytes, "workspace/other/head", &scope(), &work(1)),
            Err(WireError::ReferenceMismatch)
        );
        // Oversized and empty inputs fail closed.
        assert_eq!(
            decode_claim(&[], &key, &scope(), &work(1)),
            Err(WireError::LimitExceeded)
        );
        assert_eq!(
            decode_claim(&vec![b'{'; MAX_CLAIM_BYTES + 1], &key, &scope(), &work(1)),
            Err(WireError::LimitExceeded)
        );
        // An active record is not a submission.
        assert_eq!(
            decode_submission(&active_claim(1, 4), &scope(), &work(1)),
            Err(WireError::InvalidValue)
        );
    }

    /// A 32-item fixture: every item is admitted, the cap is never exceeded, and the run is
    /// concurrent rather than sequential.
    #[tokio::test(flavor = "current_thread")]
    async fn bounded_reads_never_exceed_the_configured_cap() {
        const ITEMS: usize = 32;
        let cap = NonZeroUsize::new(8).unwrap();
        let live = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let started = Instant::now();

        let latencies = bounded_map(ITEMS, cap, |index| {
            let live = Arc::clone(&live);
            let peak = Arc::clone(&peak);
            async move {
                let entered = Instant::now();
                let now = live.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(now, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(20)).await;
                live.fetch_sub(1, Ordering::SeqCst);
                (index, entered.elapsed())
            }
        })
        .await;
        let elapsed = started.elapsed();

        assert_eq!(latencies.len(), ITEMS);
        assert_eq!(
            latencies
                .iter()
                .map(|(index, _)| *index)
                .collect::<Vec<_>>(),
            (0..ITEMS).collect::<Vec<_>>()
        );
        assert!(
            latencies
                .iter()
                .all(|(_, latency)| *latency >= Duration::from_millis(20))
        );
        assert_eq!(live.load(Ordering::SeqCst), 0);
        let observed_peak = peak.load(Ordering::SeqCst);
        assert!(
            observed_peak <= cap.get(),
            "peak {observed_peak} exceeds cap"
        );
        assert!(
            observed_peak > 1,
            "peak {observed_peak} shows no concurrency"
        );
        // Four rounds of 8 at 20 ms each: concurrent, and not one 640 ms sequential run.
        assert!(elapsed >= Duration::from_millis(80), "elapsed {elapsed:?}");
        assert!(elapsed < Duration::from_millis(500), "elapsed {elapsed:?}");
    }
}
