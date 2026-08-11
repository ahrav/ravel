//! The v1 claim encoding is frozen.
//!
//! Claim bytes are compact UTF-8 JSON with no whitespace or trailing newline.
//! Field order is part of v1's canonical encoding: `version`, `work_id`,
//! `work_revision`, `owner_actor`, `owner_instance`, `fence`, `operation_id`,
//! then `state`. The state is internally tagged on the `state` key with exactly
//! `active` and `sealed`; a sealed state carries the shared artifact wire shape.
//! Records are capped at 4 KiB, and the decoder compares input bytes with the
//! production re-encoding before domain conversion.
//!
//! `work_revision` zero is valid. `fence` and `Active.lease_until` must be
//! nonzero; decode performs no clock comparison, so lease policy stays with the
//! claim-transition operations.

use std::{error::Error, fmt};

use serde::{Deserialize, Serialize};

use crate::{
    distributed::{
        identity::{ActorId, InstanceId},
        presence::WorkspaceId,
    },
    domain::{
        campaign::{ArtifactRef, ValidationError, validate_identity},
        work::{WorkId, WorkRef},
    },
    storage::s3::{AttemptHistory, ETag, GetOutcome, MutationOutcome, S3Store},
    sync::{WIRE_VERSION, WireError, event::WireArtifactRef},
};

const MAX_CLAIM_BYTES: usize = 4 * 1024;

/// Active lease or terminal immutable result reference.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClaimState {
    /// `lease_until` is a unix-millisecond expiry. Construction and decode
    /// validate only that it is nonzero; no clock comparison happens here.
    Active {
        lease_until: u64,
    },
    Sealed {
        result_ref: ArtifactRef,
    },
}

/// Validated claim record.
///
/// Authority over the work item additionally requires the coupled object
/// version in [`ClaimAuthority`]; a decoded record alone proves nothing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Claim {
    work_id: WorkId,
    work_revision: u64,
    owner_actor: ActorId,
    owner_instance: InstanceId,
    fence: u64,
    operation_id: String,
    state: ClaimState,
}

impl Claim {
    /// Constructs a claim after validating its fence, operation, and active expiry.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError`] for a zero fence, invalid operation identity, or zero
    /// active lease expiry.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        work_id: WorkId,
        work_revision: u64,
        owner_actor: ActorId,
        owner_instance: InstanceId,
        fence: u64,
        operation_id: String,
        state: ClaimState,
    ) -> Result<Self, ValidationError> {
        if fence == 0 {
            return Err(ValidationError::InvalidFence);
        }
        validate_identity(&operation_id)?;
        if matches!(state, ClaimState::Active { lease_until: 0 }) {
            return Err(ValidationError::InvalidExpiry);
        }
        Ok(Self {
            work_id,
            work_revision,
            owner_actor,
            owner_instance,
            fence,
            operation_id,
            state,
        })
    }

    pub fn work_id(&self) -> &WorkId {
        &self.work_id
    }

    pub fn work_revision(&self) -> u64 {
        self.work_revision
    }

    pub fn owner_actor(&self) -> &ActorId {
        &self.owner_actor
    }

    pub fn owner_instance(&self) -> &InstanceId {
        &self.owner_instance
    }

    pub fn fence(&self) -> u64 {
        self.fence
    }

    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    pub fn state(&self) -> &ClaimState {
        &self.state
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireClaim {
    version: u64,
    work_id: String,
    work_revision: u64,
    owner_actor: String,
    owner_instance: String,
    fence: u64,
    operation_id: String,
    state: WireClaimState,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, tag = "state", rename_all = "snake_case")]
enum WireClaimState {
    Active { lease_until: u64 },
    Sealed { result_ref: WireArtifactRef },
}

/// Couples a validated claim to the opaque ETag observed either on the
/// mutation that wrote it or on an exact same-key reread of the attempted
/// canonical bytes. Only this module constructs it; it implements neither
/// `Clone` nor `Debug`, so the proof cannot be copied or logged.
pub struct ClaimAuthority {
    claim: Claim,
    key: String,
    // Held for the lease renewal/seal CAS path that consumes this authority.
    #[allow(dead_code)]
    etag: ETag,
}

impl ClaimAuthority {
    pub fn claim(&self) -> &Claim {
        &self.claim
    }

    /// Claim keys are namespaced by workspace and campaign. A decoded `Claim`
    /// carries neither namespace, so the caller supplies both and the stored key
    /// has to match them.
    #[must_use]
    pub fn authorizes(&self, work: &WorkRef, workspace: &WorkspaceId, campaign_id: &str) -> bool {
        let Ok(expected) = claim_key(workspace, campaign_id, work.id()) else {
            return false;
        };
        self.key == expected
            && self.claim.work_id() == work.id()
            && self.claim.work_revision() == work.revision()
    }
}

pub struct ClaimAttempt {
    claim: Claim,
    key: String,
    canonical_bytes: Vec<u8>,
}

impl ClaimAttempt {
    pub fn claim(&self) -> &Claim {
        &self.claim
    }
}

#[must_use]
pub enum ClaimAcquireOutcome {
    Acquired(ClaimAuthority),
    Collision,
    RetryIdentically(ClaimAttempt),
    Unresolved(ClaimAttempt),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClaimPrepareError {
    InvalidInput,
    Entropy,
    Encoding,
}

impl fmt::Display for ClaimPrepareError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidInput => "invalid claim input",
            Self::Entropy => "claim operation identity generation failed",
            Self::Encoding => "claim encoding failed",
        })
    }
}

impl Error for ClaimPrepareError {}

pub fn prepare_acquisition(
    work: &WorkRef,
    workspace: &WorkspaceId,
    campaign_id: &str,
    owner_actor: &ActorId,
    owner_instance: &InstanceId,
    lease_until: u64,
) -> Result<ClaimAttempt, ClaimPrepareError> {
    let key = claim_key(workspace, campaign_id, work.id())
        .map_err(|_| ClaimPrepareError::InvalidInput)?;
    let operation_id = InstanceId::generate()
        .map_err(|_| ClaimPrepareError::Entropy)?
        .as_str()
        .to_owned();
    let claim = Claim::new(
        work.id().clone(),
        work.revision(),
        owner_actor.clone(),
        owner_instance.clone(),
        1,
        operation_id,
        ClaimState::Active { lease_until },
    )
    .map_err(|_| ClaimPrepareError::InvalidInput)?;
    let canonical_bytes = encode(&claim).map_err(|_| ClaimPrepareError::Encoding)?;
    Ok(ClaimAttempt {
        claim,
        key,
        canonical_bytes,
    })
}

// Key layout is duplicated in tests/live_s3_ambiguity.rs and
// tests/live_s3_preflight.rs; keep those literals in sync.
fn claim_key(
    workspace: &WorkspaceId,
    campaign_id: &str,
    work_id: &WorkId,
) -> Result<String, ValidationError> {
    validate_identity(campaign_id)?;
    if workspace.as_str().contains('/')
        || campaign_id.contains('/')
        || work_id.as_str().contains('/')
    {
        return Err(ValidationError::InvalidKey);
    }
    Ok(format!(
        "workspace/{}/campaigns/{campaign_id}/work/{}/claim.json",
        workspace.as_str(),
        work_id.as_str()
    ))
}

/// Safe retries of a returned attempt must reuse the same [`ClaimAttempt`]
/// and caller-owned [`AttemptHistory`]: identical key, canonical bytes,
/// operation ID, and `If-None-Match: *` precondition. Acquisition itself
/// performs no internal write retry.
pub async fn acquire(
    store: &S3Store,
    attempt: ClaimAttempt,
    history: &mut AttemptHistory,
) -> ClaimAcquireOutcome {
    let outcome = store
        .put_if_absent(&attempt.key, attempt.canonical_bytes.clone(), history)
        .await;
    match outcome {
        MutationOutcome::Committed { etag: Some(etag) } => {
            ClaimAcquireOutcome::Acquired(ClaimAuthority {
                claim: attempt.claim,
                key: attempt.key,
                etag,
            })
        }
        MutationOutcome::Committed { etag: None }
        | MutationOutcome::AmbiguousConflict
        | MutationOutcome::Unknown => resolve(store, attempt).await,
        // A fresh 412 proves an object already existed when the precondition was
        // evaluated, and this attempt's random operation ID cannot have produced
        // it, so it is a final collision. A fresh 409 is a concurrent-upload
        // conflict that S3 documents as retryable, not proof an existing claim
        // won; the same-key reread decides between authority, collision, and an
        // identical retry.
        MutationOutcome::PreconditionFailed => ClaimAcquireOutcome::Collision,
        MutationOutcome::Conflict => resolve(store, attempt).await,
        MutationOutcome::ProvenNotSent => ClaimAcquireOutcome::RetryIdentically(attempt),
        MutationOutcome::NotFound | MutationOutcome::TooLarge => {
            ClaimAcquireOutcome::Unresolved(attempt)
        }
    }
}

/// Byte equality against the reread proves this attempt committed: the
/// canonical bytes embed a 128-bit random operation ID, so no other claimant
/// can produce them.
async fn resolve(store: &S3Store, attempt: ClaimAttempt) -> ClaimAcquireOutcome {
    match store.get_object(&attempt.key, MAX_CLAIM_BYTES).await {
        Ok(GetOutcome::Found { bytes, etag }) if bytes == attempt.canonical_bytes => {
            ClaimAcquireOutcome::Acquired(ClaimAuthority {
                claim: attempt.claim,
                key: attempt.key,
                etag,
            })
        }
        Ok(GetOutcome::Found { .. }) => ClaimAcquireOutcome::Collision,
        // Absence proves the PUT had not landed at read time: retained claim
        // keys admit no delete path or lifecycle expiration and S3 reads are
        // strongly consistent after write. A write still in flight is safe to
        // resend because the reused AttemptHistory turns its 409/412 into
        // AmbiguousConflict and the same-key byte comparison recovers
        // authority.
        Ok(GetOutcome::NotFound) => ClaimAcquireOutcome::RetryIdentically(attempt),
        Err(_) => ClaimAcquireOutcome::Unresolved(attempt),
    }
}

/// Produces compact canonical JSON in the frozen claim field order.
///
/// # Errors
///
/// Returns [`WireError::LimitExceeded`] when output exceeds 4 KiB. Bounded field
/// lengths keep real output under 1.5 KiB, so the limit is defensive.
pub fn encode(claim: &Claim) -> Result<Vec<u8>, WireError> {
    let bytes =
        serde_json::to_vec(&WireClaim::from(claim)).map_err(|_| WireError::InvalidEncoding)?;
    if bytes.len() > MAX_CLAIM_BYTES {
        return Err(WireError::LimitExceeded);
    }
    Ok(bytes)
}

/// Decodes only exact canonical v1 claim bytes.
///
/// # Errors
///
/// Returns [`WireError`] for empty or oversized input, malformed or alternate JSON,
/// unknown versions, or invalid domain values.
pub fn decode(bytes: &[u8]) -> Result<Claim, WireError> {
    if bytes.is_empty() || bytes.len() > MAX_CLAIM_BYTES {
        return Err(WireError::LimitExceeded);
    }
    let wire: WireClaim = serde_json::from_slice(bytes).map_err(|_| WireError::InvalidEncoding)?;
    let canonical = serde_json::to_vec(&wire).map_err(|_| WireError::InvalidEncoding)?;
    if canonical != bytes {
        return Err(WireError::NonCanonical);
    }
    wire.try_into()
}

impl From<&Claim> for WireClaim {
    fn from(claim: &Claim) -> Self {
        Self {
            version: WIRE_VERSION,
            work_id: claim.work_id().as_str().to_owned(),
            work_revision: claim.work_revision(),
            owner_actor: claim.owner_actor().as_str().to_owned(),
            owner_instance: claim.owner_instance().as_str().to_owned(),
            fence: claim.fence(),
            operation_id: claim.operation_id().to_owned(),
            state: WireClaimState::from(claim.state()),
        }
    }
}

impl From<&ClaimState> for WireClaimState {
    fn from(state: &ClaimState) -> Self {
        match state {
            ClaimState::Active { lease_until } => Self::Active {
                lease_until: *lease_until,
            },
            ClaimState::Sealed { result_ref } => Self::Sealed {
                result_ref: WireArtifactRef::from(result_ref),
            },
        }
    }
}

impl TryFrom<WireClaim> for Claim {
    type Error = WireError;

    fn try_from(wire: WireClaim) -> Result<Self, Self::Error> {
        if wire.version != WIRE_VERSION {
            return Err(WireError::InvalidValue);
        }
        let state = match wire.state {
            WireClaimState::Active { lease_until } => ClaimState::Active { lease_until },
            WireClaimState::Sealed { result_ref } => ClaimState::Sealed {
                result_ref: result_ref.try_into()?,
            },
        };
        Claim::new(
            WorkId::new(wire.work_id).map_err(|_| WireError::InvalidValue)?,
            wire.work_revision,
            ActorId::new(wire.owner_actor).map_err(|_| WireError::InvalidValue)?,
            InstanceId::new(wire.owner_instance).map_err(|_| WireError::InvalidValue)?,
            wire.fence,
            wire.operation_id,
            state,
        )
        .map_err(|_| WireError::InvalidValue)
    }
}

#[cfg(test)]
mod tests {
    use aws_sdk_s3::primitives::SdkBody;

    use crate::storage::s3::test_support::{replay_store, response};

    use super::*;

    const TEST_ETAG: &str = "\"claim-token\"";

    fn artifact() -> ArtifactRef {
        ArtifactRef::new(
            "0".repeat(64),
            42,
            "application/json".into(),
            "attempt-17".into(),
            1_749_999_999_000,
            None,
        )
        .unwrap()
    }

    fn claim(state: ClaimState) -> Claim {
        Claim::new(
            WorkId::new("work-17".into()).unwrap(),
            4,
            ActorId::new("rust-worker".into()).unwrap(),
            InstanceId::new("instance-a".into()).unwrap(),
            9,
            "op-claim-001".into(),
            state,
        )
        .unwrap()
    }

    #[test]
    fn active_and_sealed_claims_round_trip_with_all_bindings() {
        for expected in [
            claim(ClaimState::Active {
                lease_until: 1_750_000_000_000,
            }),
            claim(ClaimState::Sealed {
                result_ref: artifact(),
            }),
        ] {
            let decoded = decode(&encode(&expected).unwrap()).unwrap();
            assert_eq!(decoded, expected);
            assert_eq!(decoded.work_id().as_str(), "work-17");
            assert_eq!(decoded.work_revision(), 4);
            assert_eq!(decoded.owner_actor().as_str(), "rust-worker");
            assert_eq!(decoded.owner_instance().as_str(), "instance-a");
            assert_eq!(decoded.fence(), 9);
            assert_eq!(decoded.operation_id(), "op-claim-001");
        }
    }

    #[test]
    fn constructor_accepts_revision_zero_but_rejects_invalid_authority_fields() {
        let active = ClaimState::Active { lease_until: 1 };
        assert!(
            Claim::new(
                WorkId::new("work".into()).unwrap(),
                0,
                ActorId::new("actor".into()).unwrap(),
                InstanceId::new("instance".into()).unwrap(),
                1,
                "op".into(),
                active.clone(),
            )
            .is_ok()
        );
        assert!(
            Claim::new(
                WorkId::new("work".into()).unwrap(),
                0,
                ActorId::new("actor".into()).unwrap(),
                InstanceId::new("instance".into()).unwrap(),
                0,
                "op".into(),
                active.clone(),
            )
            .is_err()
        );
        assert!(
            Claim::new(
                WorkId::new("work".into()).unwrap(),
                0,
                ActorId::new("actor".into()).unwrap(),
                InstanceId::new("instance".into()).unwrap(),
                1,
                String::new(),
                active,
            )
            .is_err()
        );
        assert!(
            Claim::new(
                WorkId::new("work".into()).unwrap(),
                0,
                ActorId::new("actor".into()).unwrap(),
                InstanceId::new("instance".into()).unwrap(),
                1,
                "op".into(),
                ClaimState::Active { lease_until: 0 },
            )
            .is_err()
        );
    }

    #[test]
    fn illegal_state_result_combinations_fail_decode() {
        let active_with_result = format!(
            "{{\"version\":1,\"work_id\":\"work\",\"work_revision\":0,\"owner_actor\":\"actor\",\"owner_instance\":\"instance\",\"fence\":1,\"operation_id\":\"op\",\"state\":{{\"state\":\"active\",\"lease_until\":1,\"result_ref\":{{\"digest\":\"{}\"}}}}}}",
            "0".repeat(64)
        );
        let sealed_without_result = b"{\"version\":1,\"work_id\":\"work\",\"work_revision\":0,\"owner_actor\":\"actor\",\"owner_instance\":\"instance\",\"fence\":1,\"operation_id\":\"op\",\"state\":{\"state\":\"sealed\"}}";
        assert_eq!(
            decode(active_with_result.as_bytes()),
            Err(WireError::InvalidEncoding)
        );
        assert_eq!(
            decode(sealed_without_result),
            Err(WireError::InvalidEncoding)
        );
    }

    #[test]
    fn decode_rejects_invalid_domain_values() {
        let canonical = encode(&claim(ClaimState::Active { lease_until: 1 })).unwrap();
        let text = String::from_utf8(canonical).unwrap();
        let zero_fence = text.replacen("\"fence\":9", "\"fence\":0", 1);
        assert_eq!(decode(zero_fence.as_bytes()), Err(WireError::InvalidValue));
        let zero_lease = text.replacen("\"lease_until\":1", "\"lease_until\":0", 1);
        assert_eq!(decode(zero_lease.as_bytes()), Err(WireError::InvalidValue));
        let empty_operation = text.replacen(
            "\"operation_id\":\"op-claim-001\"",
            "\"operation_id\":\"\"",
            1,
        );
        assert_eq!(
            decode(empty_operation.as_bytes()),
            Err(WireError::InvalidValue)
        );
    }

    #[test]
    fn rejects_unknown_field_version_and_alternate_bytes() {
        let canonical = encode(&claim(ClaimState::Active { lease_until: 1 })).unwrap();
        let text = String::from_utf8(canonical).unwrap();
        let unknown_field = text.replacen("{", "{\"extra\":1,", 1);
        assert_eq!(
            decode(unknown_field.as_bytes()),
            Err(WireError::InvalidEncoding)
        );
        let unknown_version = text.replacen("\"version\":1", "\"version\":2", 1);
        assert_eq!(
            decode(unknown_version.as_bytes()),
            Err(WireError::InvalidValue)
        );
        let reordered = text.replacen(
            "\"version\":1,\"work_id\":\"work-17\"",
            "\"work_id\":\"work-17\",\"version\":1",
            1,
        );
        assert_eq!(decode(reordered.as_bytes()), Err(WireError::NonCanonical));
        let trailing = format!("{text} ");
        assert_eq!(decode(trailing.as_bytes()), Err(WireError::NonCanonical));
    }

    #[test]
    fn rejects_empty_and_oversized_bytes() {
        assert_eq!(decode(b""), Err(WireError::LimitExceeded));
        assert_eq!(
            decode(&vec![b'x'; MAX_CLAIM_BYTES + 1]),
            Err(WireError::LimitExceeded)
        );
    }

    fn work(id: &str, revision: u64) -> WorkRef {
        WorkRef::new(WorkId::new(id.into()).unwrap(), revision)
    }

    fn workspace(id: &str) -> WorkspaceId {
        WorkspaceId::new(id.into()).unwrap()
    }

    fn attempt() -> ClaimAttempt {
        prepare_acquisition(
            &work("work-17", 4),
            &workspace("workspace-1"),
            "campaign-1",
            &ActorId::new("actor-a".into()).unwrap(),
            &InstanceId::new("instance-a".into()).unwrap(),
            1_750_000_000_000,
        )
        .unwrap()
    }

    async fn etag(value: &str) -> ETag {
        let (store, _) = replay_store(vec![response(
            200,
            &[("content-length", "0"), ("etag", value)],
            SdkBody::empty(),
        )]);
        match store.get_object("etag", 0).await.unwrap() {
            GetOutcome::Found { etag, .. } => etag,
            GetOutcome::NotFound => panic!("test ETag is missing"),
        }
    }

    #[test]
    fn preparation_freezes_key_claim_and_operation() {
        let attempt = attempt();
        assert_eq!(
            attempt.key,
            "workspace/workspace-1/campaigns/campaign-1/work/work-17/claim.json"
        );
        assert_eq!(attempt.canonical_bytes, encode(&attempt.claim).unwrap());
        assert_eq!(attempt.claim.work_id().as_str(), "work-17");
        assert_eq!(attempt.claim.work_revision(), 4);
        assert_eq!(attempt.claim.owner_actor().as_str(), "actor-a");
        assert_eq!(attempt.claim.owner_instance().as_str(), "instance-a");
        assert_eq!(attempt.claim.fence(), 1);
        assert_eq!(attempt.claim.operation_id().len(), 32);
        assert!(
            attempt
                .claim
                .operation_id()
                .bytes()
                .all(|byte| { byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte) })
        );
        assert!(matches!(
            attempt.claim.state(),
            ClaimState::Active {
                lease_until: 1_750_000_000_000
            }
        ));
    }

    #[test]
    fn key_segments_cannot_change_the_claim_prefix() {
        // Workspace and work identities reject the delimiter at construction, so an
        // ambiguous key cannot be built from them in the first place.
        assert!(WorkspaceId::new("bad/workspace".into()).is_err());
        assert!(WorkId::new("bad/work".into()).is_err());

        // A campaign id arrives as a plain string, so claim_key validates it.
        assert_eq!(
            claim_key(
                &workspace("workspace"),
                "bad/campaign",
                &WorkId::new("work".into()).unwrap()
            ),
            Err(ValidationError::InvalidKey)
        );
        assert_eq!(
            claim_key(
                &workspace("workspace"),
                "",
                &WorkId::new("work".into()).unwrap()
            ),
            Err(ValidationError::InvalidIdentity)
        );
        assert!(matches!(
            prepare_acquisition(
                &work("work", 0),
                &workspace("workspace"),
                "campaign",
                &ActorId::new("actor".into()).unwrap(),
                &InstanceId::new("instance".into()).unwrap(),
                0,
            ),
            Err(ClaimPrepareError::InvalidInput)
        ));
    }

    #[tokio::test]
    async fn successful_create_returns_authority_from_the_response_etag() {
        let attempt = attempt();
        let expected_bytes = attempt.canonical_bytes.clone();
        let expected_key = attempt.key.clone();
        let (store, client) = replay_store(vec![response(
            200,
            &[("etag", TEST_ETAG)],
            SdkBody::empty(),
        )]);
        let mut history = AttemptHistory::default();

        let authority = match acquire(&store, attempt, &mut history).await {
            ClaimAcquireOutcome::Acquired(authority) => authority,
            _ => panic!("successful create must return authority"),
        };
        assert!(authority.etag == etag(TEST_ETAG).await);
        assert!(authority.authorizes(&work("work-17", 4), &workspace("workspace-1"), "campaign-1"));
        assert_eq!(client.actual_requests().count(), 1);
        let request = client.actual_requests().next().unwrap();
        assert_eq!(request.headers().get("if-none-match"), Some("*"));
        assert!(request.headers().get("if-match").is_none());
        assert_eq!(request.body().bytes(), Some(expected_bytes.as_slice()));
        assert_eq!(
            request.uri().parse::<http::Uri>().unwrap().path(),
            format!("/{expected_key}")
        );
    }

    #[tokio::test]
    async fn successful_create_without_etag_requires_an_exact_reread() {
        let attempt = attempt();
        let bytes = attempt.canonical_bytes.clone();
        let (store, client) = replay_store(vec![
            response(200, &[], SdkBody::empty()),
            response(200, &[("etag", TEST_ETAG)], bytes),
        ]);
        let mut history = AttemptHistory::default();

        let authority = match acquire(&store, attempt, &mut history).await {
            ClaimAcquireOutcome::Acquired(authority) => authority,
            _ => panic!("exact reread must return authority"),
        };
        assert!(authority.etag == etag(TEST_ETAG).await);
        assert_eq!(client.actual_requests().count(), 2);
    }

    #[tokio::test]
    async fn a_fresh_precondition_failure_is_a_collision_without_a_reread() {
        let (store, client) = replay_store(vec![response(412, &[], SdkBody::empty())]);
        let mut history = AttemptHistory::default();
        assert!(matches!(
            acquire(&store, attempt(), &mut history).await,
            ClaimAcquireOutcome::Collision
        ));
        assert_eq!(client.actual_requests().count(), 1);
    }

    #[tokio::test]
    async fn a_fresh_conflict_resolves_from_same_key_bytes() {
        // (reread outcome, expected result): our bytes -> authority, other
        // bytes -> collision, absent -> identical retry of the same attempt.
        for case in ["ours", "other", "absent"] {
            let attempt = attempt();
            let mut bytes = attempt.canonical_bytes.clone();
            if case == "other" {
                bytes[0] ^= 1;
            }
            let reread = if case == "absent" {
                response(404, &[], SdkBody::empty())
            } else {
                response(200, &[("etag", TEST_ETAG)], bytes)
            };
            let (store, client) = replay_store(vec![response(409, &[], SdkBody::empty()), reread]);
            let mut history = AttemptHistory::default();
            let outcome = acquire(&store, attempt, &mut history).await;
            match case {
                "ours" => assert!(matches!(outcome, ClaimAcquireOutcome::Acquired(_))),
                "other" => assert!(matches!(outcome, ClaimAcquireOutcome::Collision)),
                _ => assert!(matches!(outcome, ClaimAcquireOutcome::RetryIdentically(_))),
            }
            assert_eq!(client.actual_requests().count(), 2, "case {case}");
        }
    }

    #[tokio::test]
    async fn unknown_state_resolves_only_from_same_key_bytes() {
        for exact in [true, false] {
            let attempt = attempt();
            let mut bytes = attempt.canonical_bytes.clone();
            if !exact {
                bytes[0] ^= 1;
            }
            let (store, client) = replay_store(vec![
                response(500, &[], SdkBody::empty()),
                response(200, &[("etag", TEST_ETAG)], bytes),
            ]);
            let mut history = AttemptHistory::default();
            let outcome = acquire(&store, attempt, &mut history).await;
            if exact {
                assert!(matches!(outcome, ClaimAcquireOutcome::Acquired(_)));
            } else {
                assert!(matches!(outcome, ClaimAcquireOutcome::Collision));
            }
            assert_eq!(client.actual_requests().count(), 2);
        }
    }

    #[tokio::test]
    async fn ambiguous_conflict_resolves_from_same_key_bytes() {
        let attempt = attempt();
        let bytes = attempt.canonical_bytes.clone();
        let key = attempt.key.clone();
        let (store, client) = replay_store(vec![
            response(500, &[], SdkBody::empty()),
            response(412, &[], SdkBody::empty()),
            response(200, &[("etag", TEST_ETAG)], bytes),
        ]);
        let mut history = AttemptHistory::default();
        // The taint has to come from this claim's own key: one history covers one
        // object, so tainting through another key would be the misuse the store asserts against.
        assert!(matches!(
            store.put_if_absent(&key, Vec::new(), &mut history).await,
            MutationOutcome::Unknown
        ));
        assert!(matches!(
            acquire(&store, attempt, &mut history).await,
            ClaimAcquireOutcome::Acquired(_)
        ));
        assert_eq!(client.actual_requests().count(), 3);
    }

    #[tokio::test]
    async fn failed_or_tokenless_rereads_remain_unresolved() {
        for response_plan in [
            vec![
                response(500, &[], SdkBody::empty()),
                response(500, &[], SdkBody::empty()),
            ],
            vec![
                response(500, &[], SdkBody::empty()),
                response(200, &[], b"bytes".to_vec()),
            ],
        ] {
            let (store, _) = replay_store(response_plan);
            let mut history = AttemptHistory::default();
            assert!(matches!(
                acquire(&store, attempt(), &mut history).await,
                ClaimAcquireOutcome::Unresolved(_)
            ));
        }
    }

    #[tokio::test]
    async fn absent_reread_preserves_an_identical_retry() {
        let attempt = attempt();
        let key = attempt.key.clone();
        let bytes = attempt.canonical_bytes.clone();
        let operation_id = attempt.claim.operation_id().to_owned();
        let (store, client) = replay_store(vec![
            response(500, &[], SdkBody::empty()),
            response(404, &[], SdkBody::empty()),
            response(200, &[("etag", TEST_ETAG)], SdkBody::empty()),
        ]);
        let mut history = AttemptHistory::default();

        let retry = match acquire(&store, attempt, &mut history).await {
            ClaimAcquireOutcome::RetryIdentically(attempt) => attempt,
            _ => panic!("absence after ambiguity permits one identical retry"),
        };
        assert_eq!(retry.key, key);
        assert_eq!(retry.canonical_bytes, bytes);
        assert_eq!(retry.claim.operation_id(), operation_id);
        assert!(matches!(
            acquire(&store, retry, &mut history).await,
            ClaimAcquireOutcome::Acquired(_)
        ));
        assert_eq!(client.actual_requests().count(), 3);
        for index in [0, 2] {
            let request = client.actual_requests().nth(index).unwrap();
            assert_eq!(request.headers().get("if-none-match"), Some("*"));
            assert_eq!(request.body().bytes(), Some(bytes.as_slice()));
            assert_eq!(
                request.uri().parse::<http::Uri>().unwrap().path(),
                format!("/{key}")
            );
        }
    }

    #[tokio::test]
    async fn storage_not_found_returns_no_authority_without_a_read() {
        let (store, client) = replay_store(vec![response(404, &[], SdkBody::empty())]);
        let mut history = AttemptHistory::default();
        assert!(matches!(
            acquire(&store, attempt(), &mut history).await,
            ClaimAcquireOutcome::Unresolved(_)
        ));
        assert_eq!(client.actual_requests().count(), 1);
    }

    #[tokio::test]
    async fn authority_matches_work_identity_revision_and_namespace() {
        let authority = ClaimAuthority {
            claim: claim(ClaimState::Active { lease_until: 1 }),
            key: claim_key(
                &workspace("workspace-1"),
                "campaign-1",
                work("work-17", 4).id(),
            )
            .unwrap(),
            etag: etag(TEST_ETAG).await,
        };
        assert!(authority.authorizes(&work("work-17", 4), &workspace("workspace-1"), "campaign-1"));
        assert!(!authority.authorizes(
            &work("other-work", 4),
            &workspace("workspace-1"),
            "campaign-1"
        ));
        assert!(!authority.authorizes(
            &work("work-17", 5),
            &workspace("workspace-1"),
            "campaign-1"
        ));
        assert!(!authority.authorizes(
            &work("work-17", 4),
            &workspace("workspace-2"),
            "campaign-1"
        ));
        assert!(!authority.authorizes(
            &work("work-17", 4),
            &workspace("workspace-1"),
            "campaign-2"
        ));
    }
}
