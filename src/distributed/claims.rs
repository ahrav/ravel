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
use sha2::{Digest, Sha256};

use crate::{
    distributed::{
        identity::{ActorId, InstanceId},
        presence::WorkspaceId,
    },
    domain::{
        attempt::{Submission, encode as encode_submission, submission_key},
        campaign::{ArtifactRef, ValidationError, validate_identity},
        work::{WorkId, WorkRef},
    },
    storage::{
        artifacts::PublishedArtifact,
        s3::{AttemptHistory, ETag, GetError, GetOutcome, MutationOutcome, S3Store},
    },
    sync::{WIRE_VERSION, WireError, event::WireArtifactRef},
};

const MAX_CLAIM_BYTES: usize = 4 * 1024;
const CLAIM_LEASE_MS: u64 = 15 * 60 * 1000;
/// Minimum lease left before a send: a create that S3 commits after the
/// embedded expiry grants authority over an immediately reclaimable record.
// ponytail: fixed margin, not a bound on S3 commit delay; shrink the race
// window rather than eliminate it. Reprepare-on-retry would remove it fully.
const CLAIM_SEND_MARGIN_MS: u64 = 30 * 1000;
#[allow(dead_code)]
const CLAIM_RENEWAL_CADENCE_MS: u64 = 5 * 60 * 1000;

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

/// Claim authority binds a validated claim to its exact object key and the
/// opaque ETag observed either on the mutation that wrote it or on an exact
/// same-key reread of the attempted canonical bytes. Only this module
/// constructs it; it implements neither `Clone` nor `Debug`, so the proof
/// cannot be copied or logged.
pub struct ClaimAuthority {
    claim: Claim,
    key: String,
    // Held for the lease renewal/seal CAS path that consumes this authority.
    #[allow(dead_code)]
    etag: ETag,
    /// Namespace of the store that minted this authority. The ETag is an
    /// opaque per-store token, so authority proves nothing about a key in any
    /// other store even when the tokens happen to collide.
    namespace: String,
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
    /// The attempt's frozen lease has already expired, so sending it could
    /// create a claim another worker may immediately reclaim; prepare a fresh
    /// attempt instead of retrying this one.
    Ineligible,
    RetryIdentically(ClaimAttempt),
    Unresolved(ClaimAttempt),
}

/// `ObservedClaim` prevents pairing a decoded claim with an unrelated object
/// key or ETag.
#[allow(dead_code)]
pub(crate) struct ObservedClaim {
    claim: Claim,
    key: String,
    etag: ETag,
    /// Namespace of the store this claim was read from.
    namespace: String,
}

#[derive(Debug)]
#[allow(dead_code)]
pub(crate) enum ClaimReadError {
    InvalidInput,
    Storage(GetError),
    Invalid(WireError),
}

impl fmt::Display for ClaimReadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidInput => "claim key is invalid",
            Self::Storage(_) => "claim read failed",
            Self::Invalid(_) => "claim encoding is invalid",
        })
    }
}

impl Error for ClaimReadError {}

/// `ClaimMutation` binds stable candidate bytes to the exact key and expected
/// ETag for replacement.
#[allow(dead_code)]
pub(crate) struct ClaimMutation {
    claim: Claim,
    key: String,
    canonical_bytes: Vec<u8>,
    etag: ETag,
    /// Namespace of the store whose read minted `etag`.
    namespace: String,
    /// Expiry of the claim this mutation renews, when it renews one.
    observed_expiry: Option<u64>,
    /// Verified `work.revision()` that made this mutation eligible.
    prepared_revision: u64,
}

#[allow(dead_code)]
impl ClaimMutation {
    /// A frozen mutation stays safe to resend only while the facts that made it
    /// eligible still hold: the same work generation, for a renewal an observed
    /// lease that has not expired, and a candidate lease still at least the
    /// send margin in the future — a delayed resend must not install a claim
    /// that expires before or immediately after S3 commits it.
    #[must_use]
    fn still_eligible(&self, work: &WorkRef, now: u64) -> bool {
        let candidate_current = match self.claim.state() {
            ClaimState::Active { lease_until } => {
                now.saturating_add(CLAIM_SEND_MARGIN_MS) < *lease_until
            }
            ClaimState::Sealed { .. } => true,
        };
        self.claim.work_id() == work.id()
            && self.prepared_revision == work.revision()
            && candidate_current
            && self.observed_expiry.is_none_or(|expiry| now < expiry)
    }
}

#[must_use]
#[allow(dead_code)]
pub(crate) enum ClaimMutationOutcome {
    Applied(ClaimAuthority),
    /// The write committed but no usable ETag was recovered, so the claim is
    /// durable while this caller holds no authority. Re-observe before any
    /// further mutation; the frozen mutation must not be resent because its
    /// pre-write ETag no longer matches the object it just replaced.
    AppliedUnverified,
    /// The facts that made the mutation eligible no longer hold, so it must be
    /// prepared again from a fresh observation rather than resent.
    Ineligible,
    Lost,
    RetryIdentically(ClaimMutation),
    Unresolved(ClaimMutation),
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) enum SubmitError {
    InvalidInput,
    Encoding,
    Publication,
}

impl fmt::Display for SubmitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidInput => "invalid submission input",
            Self::Encoding => "submission encoding failed",
            Self::Publication => "submission publication failed",
        })
    }
}

impl Error for SubmitError {}

#[allow(dead_code)]
pub(crate) struct SubmitFailure {
    authority: ClaimAuthority,
    error: SubmitError,
}

#[allow(dead_code)]
impl SubmitFailure {
    pub(crate) fn error(&self) -> SubmitError {
        self.error
    }

    pub(crate) fn into_authority(self) -> ClaimAuthority {
        self.authority
    }
}

pub fn prepare_acquisition(
    work: &WorkRef,
    workspace: &WorkspaceId,
    campaign_id: &str,
    owner_actor: &ActorId,
    owner_instance: &InstanceId,
    now: u64,
) -> Result<ClaimAttempt, ClaimPrepareError> {
    let key = claim_key(workspace, campaign_id, work.id())
        .map_err(|_| ClaimPrepareError::InvalidInput)?;
    let lease_until = now
        .checked_add(CLAIM_LEASE_MS)
        .ok_or(ClaimPrepareError::InvalidInput)?;
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

/// Reads a claim and keeps its key and ETag coupled to the decoded record.
///
/// # Errors
///
/// Returns [`ClaimReadError::InvalidInput`] for an invalid key,
/// [`ClaimReadError::Storage`] for storage failures, and
/// [`ClaimReadError::Invalid`] for invalid claim bytes.
#[allow(dead_code)]
pub(crate) async fn observe(
    store: &S3Store,
    workspace: &WorkspaceId,
    campaign_id: &str,
    work_id: &WorkId,
) -> Result<Option<ObservedClaim>, ClaimReadError> {
    let key =
        claim_key(workspace, campaign_id, work_id).map_err(|_| ClaimReadError::InvalidInput)?;
    let outcome = store
        .get_object(&key, MAX_CLAIM_BYTES)
        .await
        .map_err(|error| match error {
            GetError::TooLarge => ClaimReadError::Invalid(WireError::LimitExceeded),
            other => ClaimReadError::Storage(other),
        })?;
    match outcome {
        GetOutcome::NotFound => Ok(None),
        GetOutcome::Found { bytes, etag } => {
            let claim = decode(&bytes).map_err(ClaimReadError::Invalid)?;
            Ok(Some(ObservedClaim {
                claim,
                key,
                etag,
                namespace: store.namespace().to_owned(),
            }))
        }
    }
}

/// Rejection of a renewal that attempted no mutation.
///
/// `ClaimAuthority` is neither `Clone` nor `Debug`, so when the authority still
/// holds — a renewal that would not extend the lease, or a candidate that could
/// not be built — the rejection hands the unspent authority back. When the
/// rejection itself proves the authority no longer holds (expired lease, sealed
/// claim, or stale work/owner/fence identity), the authority is consumed so a
/// caller cannot keep using a fence the claim no longer backs.
#[allow(dead_code)]
#[must_use]
pub(crate) struct RenewalRejected {
    pub(crate) authority: Option<ClaimAuthority>,
    pub(crate) error: ClaimPrepareError,
}

#[allow(dead_code)]
pub(crate) fn prepare_renewal(
    authority: ClaimAuthority,
    work: &WorkRef,
    actor: &ActorId,
    instance: &InstanceId,
    expected_fence: u64,
    now: u64,
) -> Result<ClaimMutation, Box<RenewalRejected>> {
    // A rejection that disproves the authority consumes it; one that leaves the
    // authority intact hands it back.
    let forfeit = || {
        Err(Box::new(RenewalRejected {
            authority: None,
            error: ClaimPrepareError::InvalidInput,
        }))
    };
    let retain = |authority| {
        Err(Box::new(RenewalRejected {
            authority: Some(authority),
            error: ClaimPrepareError::InvalidInput,
        }))
    };
    let lease_until = match authority.claim.state() {
        ClaimState::Active { lease_until } => *lease_until,
        ClaimState::Sealed { .. } => return forfeit(),
    };
    if authority.claim.work_id() != work.id()
        || authority.claim.work_revision() != work.revision()
        || authority.claim.owner_actor() != actor
        || authority.claim.owner_instance() != instance
        || authority.claim.fence() != expected_fence
        || now >= lease_until
    {
        return forfeit();
    }
    let Some(renewed_until) = now
        .checked_add(CLAIM_LEASE_MS)
        .filter(|candidate| *candidate > lease_until)
    else {
        return retain(authority);
    };

    // The renewed claim is built from copies so that a failure here can still hand
    // the authority back. The non-`Clone` ETag moves only once nothing can fail.
    let renewed = Claim::new(
        authority.claim.work_id().clone(),
        authority.claim.work_revision(),
        authority.claim.owner_actor().clone(),
        authority.claim.owner_instance().clone(),
        authority.claim.fence(),
        authority.claim.operation_id().to_owned(),
        ClaimState::Active {
            lease_until: renewed_until,
        },
    );
    let Ok(renewed) = renewed else {
        return retain(authority);
    };
    let Ok(canonical_bytes) = encode(&renewed) else {
        return Err(Box::new(RenewalRejected {
            authority: Some(authority),
            error: ClaimPrepareError::Encoding,
        }));
    };
    let ClaimAuthority {
        key,
        etag,
        namespace,
        ..
    } = authority;
    Ok(ClaimMutation {
        claim: renewed,
        key,
        canonical_bytes,
        namespace,
        etag,
        observed_expiry: Some(lease_until),
        prepared_revision: work.revision(),
    })
}

impl fmt::Debug for RenewalRejected {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RenewalRejected")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

#[allow(dead_code)]
pub(crate) fn prepare_reclamation(
    observed: ObservedClaim,
    work: &WorkRef,
    replacement_actor: &ActorId,
    replacement_instance: &InstanceId,
    now: u64,
) -> Result<ClaimMutation, ClaimPrepareError> {
    if observed.claim.work_id() != work.id()
        // A claim written for a newer revision must not be rolled back to this
        // caller's older one.
        || observed.claim.work_revision() > work.revision()
        || !matches!(
            observed.claim.state(),
            ClaimState::Active { lease_until } if now >= *lease_until
        )
    {
        return Err(ClaimPrepareError::InvalidInput);
    }
    prepare_replacement(observed, work, replacement_actor, replacement_instance, now)
}

#[allow(dead_code)]
pub(crate) fn prepare_supersession(
    observed: ObservedClaim,
    work: &WorkRef,
    replacement_actor: &ActorId,
    replacement_instance: &InstanceId,
    now: u64,
) -> Result<ClaimMutation, ClaimPrepareError> {
    if observed.claim.work_id() != work.id()
        // Supersession only moves forward: an equal revision has nothing to
        // supersede, and a greater one would regain authority over a claim already
        // sealed for a newer generation.
        || observed.claim.work_revision() >= work.revision()
        || !matches!(observed.claim.state(), ClaimState::Sealed { .. })
    {
        return Err(ClaimPrepareError::InvalidInput);
    }
    prepare_replacement(observed, work, replacement_actor, replacement_instance, now)
}

fn prepare_replacement(
    observed: ObservedClaim,
    work: &WorkRef,
    replacement_actor: &ActorId,
    replacement_instance: &InstanceId,
    now: u64,
) -> Result<ClaimMutation, ClaimPrepareError> {
    let fence = observed
        .claim
        .fence()
        .checked_add(1)
        .ok_or(ClaimPrepareError::InvalidInput)?;
    let lease_until = now
        .checked_add(CLAIM_LEASE_MS)
        .ok_or(ClaimPrepareError::InvalidInput)?;
    let operation_id = InstanceId::generate()
        .map_err(|_| ClaimPrepareError::Entropy)?
        .as_str()
        .to_owned();
    let claim = Claim::new(
        work.id().clone(),
        work.revision(),
        replacement_actor.clone(),
        replacement_instance.clone(),
        fence,
        operation_id,
        ClaimState::Active { lease_until },
    )
    .map_err(|_| ClaimPrepareError::InvalidInput)?;
    let canonical_bytes = encode(&claim).map_err(|_| ClaimPrepareError::Encoding)?;
    Ok(ClaimMutation {
        claim,
        key: observed.key,
        canonical_bytes,
        etag: observed.etag,
        namespace: observed.namespace,
        // Replacement eligibility is an expired lease or an older sealed revision,
        // neither of which a later clock reading can invalidate; the candidate
        // lease check in `still_eligible` bounds how long the frozen mutation
        // itself stays sendable.
        observed_expiry: None,
        prepared_revision: work.revision(),
    })
}

/// The work generation and claim namespace one submission is scoped to.
#[allow(dead_code)]
pub(crate) struct ClaimScope<'a> {
    pub(crate) work: &'a WorkRef,
    pub(crate) workspace: &'a WorkspaceId,
    pub(crate) campaign_id: &'a str,
}

/// Publishes immutable evidence before consuming authority in one terminal CAS.
///
/// Sealing deliberately has no lease-time check: renewal needs a clock to
/// calculate an extension, while completion versus reclamation is decided by
/// the authority-bound key and ETag.
#[allow(dead_code)]
pub(crate) async fn submit(
    store: &S3Store,
    authority: ClaimAuthority,
    scope: ClaimScope<'_>,
    published: &PublishedArtifact,
    now: u64,
    history: &mut AttemptHistory,
) -> Result<ClaimMutationOutcome, SubmitFailure> {
    let ClaimScope {
        work,
        workspace,
        campaign_id,
    } = scope;
    if !matches!(authority.claim.state(), ClaimState::Active { .. }) {
        return Err(SubmitFailure {
            authority,
            error: SubmitError::InvalidInput,
        });
    }
    // The full scope must match before any I/O: `authorizes` binds the caller's
    // work id and revision to this authority's key, so a mismatched ClaimScope
    // is rejected here instead of publishing a submission that apply_mutation
    // would later refuse as ineligible.
    if !authority.authorizes(work, workspace, campaign_id) {
        return Err(SubmitFailure {
            authority,
            error: SubmitError::InvalidInput,
        });
    }
    // The artifact was proven durable only in the namespace that minted it; a
    // claim in this store must not seal a result that store never verified.
    if published.namespace() != store.namespace() {
        return Err(SubmitFailure {
            authority,
            error: SubmitError::InvalidInput,
        });
    }
    // The authority's ETag is likewise an opaque token from the store that
    // minted it; sending it as If-Match in another store could seal a claim
    // this store never issued authority for.
    if authority.namespace != store.namespace() {
        return Err(SubmitFailure {
            authority,
            error: SubmitError::InvalidInput,
        });
    }
    let result_ref = published.artifact_ref().clone();
    let submission = match Submission::new(
        authority.claim.work_id().clone(),
        authority.claim.work_revision(),
        authority.claim.owner_actor().clone(),
        authority.claim.owner_instance().clone(),
        authority.claim.fence(),
        authority.claim.operation_id().to_owned(),
        result_ref.clone(),
    ) {
        Ok(submission) => submission,
        Err(_) => {
            return Err(SubmitFailure {
                authority,
                error: SubmitError::InvalidInput,
            });
        }
    };
    let submission_key =
        match submission_key(workspace.as_str(), campaign_id, submission.attempt_id()) {
            Ok(key) => key,
            Err(_) => {
                return Err(SubmitFailure {
                    authority,
                    error: SubmitError::InvalidInput,
                });
            }
        };
    let submission_bytes = match encode_submission(&submission) {
        Ok(bytes) => bytes,
        Err(_) => {
            return Err(SubmitFailure {
                authority,
                error: SubmitError::Encoding,
            });
        }
    };
    let sealed = match Claim::new(
        authority.claim.work_id().clone(),
        authority.claim.work_revision(),
        authority.claim.owner_actor().clone(),
        authority.claim.owner_instance().clone(),
        authority.claim.fence(),
        authority.claim.operation_id().to_owned(),
        ClaimState::Sealed { result_ref },
    ) {
        Ok(claim) => claim,
        Err(_) => {
            return Err(SubmitFailure {
                authority,
                error: SubmitError::InvalidInput,
            });
        }
    };
    let canonical_bytes = match encode(&sealed) {
        Ok(bytes) => bytes,
        Err(_) => {
            return Err(SubmitFailure {
                authority,
                error: SubmitError::Encoding,
            });
        }
    };
    let digest = format!("{:x}", Sha256::digest(&submission_bytes));
    if store
        .publish_immutable(&submission_key, submission_bytes, &digest)
        .await
        .is_err()
    {
        return Err(SubmitFailure {
            authority,
            error: SubmitError::Publication,
        });
    }
    let prepared_revision = authority.claim.work_revision();
    let ClaimAuthority {
        key,
        etag,
        namespace,
        ..
    } = authority;
    Ok(apply_mutation(
        store,
        ClaimMutation {
            claim: sealed,
            key,
            canonical_bytes,
            etag,
            namespace,
            // A seal carries no expiry: the bound ETag CAS already excludes a
            // reclaimer, so a lapsed lease alone must not discard completed work.
            observed_expiry: None,
            prepared_revision,
        },
        work,
        now,
        history,
    )
    .await)
}

/// Safe retries of a returned attempt must reuse the same [`ClaimAttempt`]
/// and caller-owned [`AttemptHistory`]: identical key, canonical bytes,
/// operation ID, and `If-None-Match: *` precondition. Acquisition itself
/// performs no internal write retry.
///
/// `now` gates every send, including retries of a returned attempt: an attempt
/// within [`CLAIM_SEND_MARGIN_MS`] of its frozen `lease_until` is
/// [`ClaimAcquireOutcome::Ineligible`] and must be prepared again, so a create
/// that lands after the embedded expiry is not sent in the first place.
pub async fn acquire(
    store: &S3Store,
    attempt: ClaimAttempt,
    now: u64,
    history: &mut AttemptHistory,
) -> ClaimAcquireOutcome {
    let ClaimState::Active { lease_until } = attempt.claim.state() else {
        return ClaimAcquireOutcome::Ineligible;
    };
    if now.saturating_add(CLAIM_SEND_MARGIN_MS) >= *lease_until {
        return ClaimAcquireOutcome::Ineligible;
    }
    let outcome = store
        .put_if_absent(&attempt.key, attempt.canonical_bytes.clone(), history)
        .await;
    match outcome {
        MutationOutcome::Committed { etag: Some(etag) } => {
            ClaimAcquireOutcome::Acquired(ClaimAuthority {
                claim: attempt.claim,
                key: attempt.key,
                etag,
                namespace: store.namespace().to_owned(),
            })
        }
        MutationOutcome::Committed { etag: None }
        | MutationOutcome::AmbiguousConflict
        | MutationOutcome::Unknown => resolve_acquisition(store, attempt).await,
        // A fresh 412 proves an object already existed when the precondition was
        // evaluated, and this attempt's random operation ID cannot have produced
        // it, so it is a final collision. A fresh 409 is a concurrent-upload
        // conflict that S3 documents as retryable, not proof an existing claim
        // won; the same-key reread decides between authority, collision, and an
        // identical retry.
        MutationOutcome::PreconditionFailed => ClaimAcquireOutcome::Collision,
        MutationOutcome::Conflict => resolve_acquisition(store, attempt).await,
        MutationOutcome::ProvenNotSent => ClaimAcquireOutcome::RetryIdentically(attempt),
        MutationOutcome::NotFound | MutationOutcome::TooLarge => {
            ClaimAcquireOutcome::Unresolved(attempt)
        }
    }
}

/// Safe retries of a returned mutation must preserve its key, bytes, ETag, and
/// caller-owned [`AttemptHistory`]. This function performs no internal retry.
#[allow(dead_code)]
pub(crate) async fn apply_mutation(
    store: &S3Store,
    mutation: ClaimMutation,
    work: &WorkRef,
    now: u64,
    history: &mut AttemptHistory,
) -> ClaimMutationOutcome {
    if !mutation.still_eligible(work, now) {
        return ClaimMutationOutcome::Ineligible;
    }
    // The mutation's ETag was observed in one store; a CAS in any other store
    // compares against an unrelated token and could replace a claim that was
    // never read there.
    if mutation.namespace != store.namespace() {
        return ClaimMutationOutcome::Ineligible;
    }
    let outcome = store
        .put_if_match(
            &mutation.key,
            mutation.canonical_bytes.clone(),
            &mutation.etag,
            history,
        )
        .await;
    match outcome {
        MutationOutcome::Committed { etag: Some(etag) } => {
            ClaimMutationOutcome::Applied(ClaimAuthority {
                claim: mutation.claim,
                key: mutation.key,
                etag,
                namespace: store.namespace().to_owned(),
            })
        }
        // A committed write without an ETag is durable; only the fresh token is
        // missing. The pre-write ETag can no longer match, so a failed reread
        // must not hand the mutation back for an identical retry that would
        // misread its own commit as Lost.
        MutationOutcome::Committed { etag: None } => {
            match read_candidate(store, &mutation.key, &mutation.canonical_bytes).await {
                CandidateRead::Matching(etag) => ClaimMutationOutcome::Applied(ClaimAuthority {
                    claim: mutation.claim,
                    key: mutation.key,
                    etag,
                    namespace: store.namespace().to_owned(),
                }),
                CandidateRead::Different(_) => ClaimMutationOutcome::Lost,
                CandidateRead::Missing | CandidateRead::Failed => {
                    ClaimMutationOutcome::AppliedUnverified
                }
            }
        }
        MutationOutcome::AmbiguousConflict | MutationOutcome::Unknown => {
            resolve_mutation(store, mutation).await
        }
        MutationOutcome::PreconditionFailed => ClaimMutationOutcome::Lost,
        MutationOutcome::Conflict => ClaimMutationOutcome::RetryIdentically(mutation),
        MutationOutcome::ProvenNotSent => ClaimMutationOutcome::RetryIdentically(mutation),
        MutationOutcome::NotFound | MutationOutcome::TooLarge => {
            ClaimMutationOutcome::Unresolved(mutation)
        }
    }
}

/// Byte equality against the reread proves the attempted operation committed:
/// creation and replacement candidates embed a fresh 128-bit random operation
/// ID, and renewal and sealed candidates preserve their owner and operation ID
/// while any competing reclaimer mints a new one, so no other claimant can
/// produce the expected bytes.
enum CandidateRead {
    Matching(ETag),
    Different(ETag),
    Missing,
    Failed,
}

async fn read_candidate(store: &S3Store, key: &str, expected: &[u8]) -> CandidateRead {
    match store.get_object(key, MAX_CLAIM_BYTES).await {
        Ok(GetOutcome::Found { bytes, etag }) if bytes == expected => CandidateRead::Matching(etag),
        Ok(GetOutcome::Found { etag, .. }) => CandidateRead::Different(etag),
        Ok(GetOutcome::NotFound) => CandidateRead::Missing,
        Err(_) => CandidateRead::Failed,
    }
}

async fn resolve_acquisition(store: &S3Store, attempt: ClaimAttempt) -> ClaimAcquireOutcome {
    match read_candidate(store, &attempt.key, &attempt.canonical_bytes).await {
        CandidateRead::Matching(etag) => ClaimAcquireOutcome::Acquired(ClaimAuthority {
            claim: attempt.claim,
            key: attempt.key,
            etag,
            namespace: store.namespace().to_owned(),
        }),
        CandidateRead::Different(_) => ClaimAcquireOutcome::Collision,
        // Absence proves the PUT had not landed at read time: retained claim
        // keys admit no delete path or lifecycle expiration and S3 reads are
        // strongly consistent after write. A write still in flight is safe to
        // resend because the reused AttemptHistory turns its 409/412 into
        // AmbiguousConflict and the same-key byte comparison recovers
        // authority.
        CandidateRead::Missing => ClaimAcquireOutcome::RetryIdentically(attempt),
        CandidateRead::Failed => ClaimAcquireOutcome::Unresolved(attempt),
    }
}

async fn resolve_mutation(store: &S3Store, mutation: ClaimMutation) -> ClaimMutationOutcome {
    match read_candidate(store, &mutation.key, &mutation.canonical_bytes).await {
        CandidateRead::Matching(etag) => ClaimMutationOutcome::Applied(ClaimAuthority {
            claim: mutation.claim,
            key: mutation.key,
            etag,
            namespace: store.namespace().to_owned(),
        }),
        // An unchanged ETag means nothing else has taken the claim, and a possibly
        // dispatched PUT stays able to land.
        CandidateRead::Different(etag) if etag == mutation.etag => {
            ClaimMutationOutcome::Unresolved(mutation)
        }
        CandidateRead::Different(_) => ClaimMutationOutcome::Lost,
        CandidateRead::Missing | CandidateRead::Failed => {
            ClaimMutationOutcome::Unresolved(mutation)
        }
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

    use crate::storage::{
        artifacts,
        s3::test_support::{replay_store, response},
    };

    use super::*;

    const TEST_ETAG: &str = "\"claim-token\"";
    const NEW_ETAG: &str = "\"claim-token-2\"";
    const TEST_KEY: &str = "workspace/workspace-1/campaigns/campaign-1/work/work-17/claim.json";
    /// Deliberately unlike any live store namespace so a test that forgets to
    /// rebind authority to its store fails instead of passing by accident.
    const TEST_NAMESPACE: &str = "test-claim-namespace";

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
            1_749_999_100_000,
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

    async fn authority(claim: Claim) -> ClaimAuthority {
        ClaimAuthority {
            claim,
            key: TEST_KEY.into(),
            etag: etag(TEST_ETAG).await,
            namespace: TEST_NAMESPACE.into(),
        }
    }

    impl ClaimAuthority {
        fn attributed_to(mut self, namespace: &str) -> Self {
            self.namespace = namespace.to_owned();
            self
        }
    }

    impl ClaimMutation {
        fn attributed_to(mut self, namespace: &str) -> Self {
            self.namespace = namespace.to_owned();
            self
        }
    }

    async fn observed(claim: Claim) -> ObservedClaim {
        ObservedClaim {
            claim,
            key: TEST_KEY.into(),
            etag: etag(TEST_ETAG).await,
            namespace: TEST_NAMESPACE.into(),
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
                "bad/campaign",
                &ActorId::new("actor".into()).unwrap(),
                &InstanceId::new("instance".into()).unwrap(),
                100,
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

        let authority = match acquire(&store, attempt, 1_749_999_100_000, &mut history).await {
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

        let authority = match acquire(&store, attempt, 1_749_999_100_000, &mut history).await {
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
            acquire(&store, attempt(), 1_749_999_100_000, &mut history).await,
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
            let outcome = acquire(&store, attempt, 1_749_999_100_000, &mut history).await;
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
            let outcome = acquire(&store, attempt, 1_749_999_100_000, &mut history).await;
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
            acquire(&store, attempt, 1_749_999_100_000, &mut history).await,
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
                acquire(&store, attempt(), 1_749_999_100_000, &mut history).await,
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

        let retry = match acquire(&store, attempt, 1_749_999_100_000, &mut history).await {
            ClaimAcquireOutcome::RetryIdentically(attempt) => attempt,
            _ => panic!("absence after ambiguity permits one identical retry"),
        };
        assert_eq!(retry.key, key);
        assert_eq!(retry.canonical_bytes, bytes);
        assert_eq!(retry.claim.operation_id(), operation_id);
        assert!(matches!(
            acquire(&store, retry, 1_749_999_100_000, &mut history).await,
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
            acquire(&store, attempt(), 1_749_999_100_000, &mut history).await,
            ClaimAcquireOutcome::Unresolved(_)
        ));
        assert_eq!(client.actual_requests().count(), 1);
    }

    #[test]
    fn acquisition_uses_the_fixed_lease_and_rejects_timestamp_overflow() {
        assert_eq!(CLAIM_LEASE_MS, 900_000);
        assert_eq!(CLAIM_RENEWAL_CADENCE_MS, 300_000);
        let attempt = prepare_acquisition(
            &work("work-17", 4),
            &workspace("workspace-1"),
            "campaign-1",
            &ActorId::new("actor-a".into()).unwrap(),
            &InstanceId::new("instance-a".into()).unwrap(),
            100,
        )
        .unwrap();
        assert!(matches!(
            attempt.claim.state(),
            ClaimState::Active {
                lease_until: 900_100
            }
        ));
        assert!(matches!(
            prepare_acquisition(
                &work("work-17", 4),
                &workspace("workspace-1"),
                "campaign-1",
                &ActorId::new("actor-a".into()).unwrap(),
                &InstanceId::new("instance-a".into()).unwrap(),
                u64::MAX,
            ),
            Err(ClaimPrepareError::InvalidInput)
        ));
    }

    #[tokio::test]
    async fn renewal_preserves_generation_and_uses_bound_key_and_etag() {
        let original = claim(ClaimState::Active {
            lease_until: 1_000_000,
        });
        let original_operation = original.operation_id().to_owned();
        let mutation = prepare_renewal(
            authority(original).await,
            &work("work-17", 4),
            &ActorId::new("rust-worker".into()).unwrap(),
            &InstanceId::new("instance-a".into()).unwrap(),
            9,
            200_000,
        )
        .unwrap();
        assert_eq!(mutation.key, TEST_KEY);
        assert_eq!(mutation.claim.fence(), 9);
        assert_eq!(mutation.claim.operation_id(), original_operation);
        assert_eq!(mutation.claim.owner_actor().as_str(), "rust-worker");
        assert_eq!(mutation.claim.owner_instance().as_str(), "instance-a");
        assert!(matches!(
            mutation.claim.state(),
            ClaimState::Active {
                lease_until: 1_100_000
            }
        ));
        let expected_bytes = mutation.canonical_bytes.clone();
        let (store, client) =
            replay_store(vec![response(200, &[("etag", NEW_ETAG)], SdkBody::empty())]);
        let mut history = AttemptHistory::default();
        let refreshed = match apply_mutation(
            &store,
            mutation.attributed_to(store.namespace()),
            &work("work-17", 4),
            200_000,
            &mut history,
        )
        .await
        {
            ClaimMutationOutcome::Applied(authority) => authority,
            _ => panic!("committed renewal must return refreshed authority"),
        };
        assert_eq!(refreshed.key, TEST_KEY);
        assert!(refreshed.etag == etag(NEW_ETAG).await);
        assert!(matches!(
            refreshed.claim.state(),
            ClaimState::Active {
                lease_until: 1_100_000
            }
        ));
        let request = client.actual_requests().next().unwrap();
        assert_eq!(request.headers().get("if-match"), Some(TEST_ETAG));
        assert!(request.headers().get("if-none-match").is_none());
        assert_eq!(request.body().bytes(), Some(expected_bytes.as_slice()));
        assert_eq!(
            request.uri().parse::<http::Uri>().unwrap().path(),
            format!("/{TEST_KEY}")
        );
    }

    #[tokio::test]
    async fn renewal_preparation_rejects_every_stale_or_invalid_boundary() {
        let actor = ActorId::new("rust-worker".into()).unwrap();
        let instance = InstanceId::new("instance-a".into()).unwrap();
        let valid = || {
            claim(ClaimState::Active {
                lease_until: 1_000_000,
            })
        };

        assert!(matches!(
            prepare_renewal(
                authority(valid()).await,
                &work("other-work", 4),
                &actor,
                &instance,
                9,
                200_000,
            ),
            Err(rejection)
                if rejection.error == ClaimPrepareError::InvalidInput
                    && rejection.authority.is_none()
        ));
        assert!(matches!(
            prepare_renewal(
                authority(valid()).await,
                &work("work-17", 5),
                &actor,
                &instance,
                9,
                200_000,
            ),
            Err(rejection)
                if rejection.error == ClaimPrepareError::InvalidInput
                    && rejection.authority.is_none()
        ));
        assert!(matches!(
            prepare_renewal(
                authority(valid()).await,
                &work("work-17", 4),
                &ActorId::new("other-actor".into()).unwrap(),
                &instance,
                9,
                200_000,
            ),
            Err(rejection)
                if rejection.error == ClaimPrepareError::InvalidInput
                    && rejection.authority.is_none()
        ));
        assert!(matches!(
            prepare_renewal(
                authority(valid()).await,
                &work("work-17", 4),
                &actor,
                &InstanceId::new("other-instance".into()).unwrap(),
                9,
                200_000,
            ),
            Err(rejection)
                if rejection.error == ClaimPrepareError::InvalidInput
                    && rejection.authority.is_none()
        ));
        assert!(matches!(
            prepare_renewal(
                authority(valid()).await,
                &work("work-17", 4),
                &actor,
                &instance,
                8,
                200_000,
            ),
            Err(rejection)
                if rejection.error == ClaimPrepareError::InvalidInput
                    && rejection.authority.is_none()
        ));
        assert!(matches!(
            prepare_renewal(
                authority(claim(ClaimState::Sealed {
                    result_ref: artifact(),
                }))
                .await,
                &work("work-17", 4),
                &actor,
                &instance,
                9,
                200_000,
            ),
            Err(rejection)
                if rejection.error == ClaimPrepareError::InvalidInput
                    && rejection.authority.is_none()
        ));
        for now in [1_000_000, 1_000_001] {
            assert!(matches!(
                prepare_renewal(
                    authority(valid()).await,
                    &work("work-17", 4),
                    &actor,
                    &instance,
                    9,
                    now,
                ),
                Err(rejection)
                    if rejection.error == ClaimPrepareError::InvalidInput
                        && rejection.authority.is_none()
            ));
        }
        assert!(matches!(
            prepare_renewal(
                authority(claim(ClaimState::Active {
                    lease_until: 900_100,
                }))
                .await,
                &work("work-17", 4),
                &actor,
                &instance,
                9,
                100,
            ),
            Err(rejection)
                if rejection.error == ClaimPrepareError::InvalidInput
                    && rejection.authority.is_some()
        ));
        assert!(matches!(
            prepare_renewal(
                authority(claim(ClaimState::Active {
                    lease_until: u64::MAX,
                }))
                .await,
                &work("work-17", 4),
                &actor,
                &instance,
                9,
                u64::MAX - 1,
            ),
            Err(rejection)
                if rejection.error == ClaimPrepareError::InvalidInput
                    && rejection.authority.is_some()
        ));
    }

    #[tokio::test]
    async fn renewal_separates_a_stale_precondition_from_a_fresh_conflict() {
        for (status, expect_lost) in [(412, true), (409, false)] {
            let mutation = prepare_renewal(
                authority(claim(ClaimState::Active {
                    lease_until: 1_000_000,
                }))
                .await,
                &work("work-17", 4),
                &ActorId::new("rust-worker".into()).unwrap(),
                &InstanceId::new("instance-a".into()).unwrap(),
                9,
                200_000,
            )
            .unwrap();
            let (store, client) = replay_store(vec![response(status, &[], SdkBody::empty())]);
            let mut history = AttemptHistory::default();
            let outcome = apply_mutation(
                &store,
                mutation.attributed_to(store.namespace()),
                &work("work-17", 4),
                200_000,
                &mut history,
            )
            .await;
            if expect_lost {
                assert!(
                    matches!(outcome, ClaimMutationOutcome::Lost),
                    "status {status}"
                );
            } else {
                assert!(
                    matches!(outcome, ClaimMutationOutcome::RetryIdentically(_)),
                    "status {status}"
                );
            }
            assert_eq!(client.actual_requests().count(), 1);
        }
    }

    #[tokio::test]
    async fn renewal_storage_not_found_remains_unresolved() {
        let mutation = prepare_renewal(
            authority(claim(ClaimState::Active {
                lease_until: 1_000_000,
            }))
            .await,
            &work("work-17", 4),
            &ActorId::new("rust-worker".into()).unwrap(),
            &InstanceId::new("instance-a".into()).unwrap(),
            9,
            200_000,
        )
        .unwrap();
        let (store, client) = replay_store(vec![response(404, &[], SdkBody::empty())]);
        let mut history = AttemptHistory::default();
        assert!(matches!(
            apply_mutation(
                &store,
                mutation.attributed_to(store.namespace()),
                &work("work-17", 4),
                200_000,
                &mut history
            )
            .await,
            ClaimMutationOutcome::Unresolved(_)
        ));
        assert_eq!(client.actual_requests().count(), 1);
    }

    #[tokio::test]
    async fn renewal_ambiguity_requires_exact_durable_bytes() {
        for initial_status in [200, 500] {
            let mutation = prepare_renewal(
                authority(claim(ClaimState::Active {
                    lease_until: 1_000_000,
                }))
                .await,
                &work("work-17", 4),
                &ActorId::new("rust-worker".into()).unwrap(),
                &InstanceId::new("instance-a".into()).unwrap(),
                9,
                200_000,
            )
            .unwrap();
            let bytes = mutation.canonical_bytes.clone();
            let (store, _) = replay_store(vec![
                response(initial_status, &[], SdkBody::empty()),
                response(200, &[("etag", NEW_ETAG)], bytes),
            ]);
            let mut history = AttemptHistory::default();
            let authority = match apply_mutation(
                &store,
                mutation.attributed_to(store.namespace()),
                &work("work-17", 4),
                200_000,
                &mut history,
            )
            .await
            {
                ClaimMutationOutcome::Applied(authority) => authority,
                _ => panic!("exact reread must prove renewal"),
            };
            assert!(authority.etag == etag(NEW_ETAG).await);
            assert!(matches!(
                authority.claim.state(),
                ClaimState::Active {
                    lease_until: 1_100_000
                }
            ));
        }

        let mutation = prepare_renewal(
            authority(claim(ClaimState::Active {
                lease_until: 1_000_000,
            }))
            .await,
            &work("work-17", 4),
            &ActorId::new("rust-worker".into()).unwrap(),
            &InstanceId::new("instance-a".into()).unwrap(),
            9,
            200_000,
        )
        .unwrap();
        let mut different = mutation.canonical_bytes.clone();
        different[0] ^= 1;
        let (store, _) = replay_store(vec![
            response(500, &[], SdkBody::empty()),
            response(200, &[("etag", NEW_ETAG)], different),
        ]);
        let mut history = AttemptHistory::default();
        assert!(matches!(
            apply_mutation(
                &store,
                mutation.attributed_to(store.namespace()),
                &work("work-17", 4),
                200_000,
                &mut history
            )
            .await,
            ClaimMutationOutcome::Lost
        ));
    }

    #[tokio::test]
    async fn missing_or_failed_renewal_reread_is_unresolved() {
        for reread in [
            response(404, &[], SdkBody::empty()),
            response(500, &[], SdkBody::empty()),
        ] {
            let mutation = prepare_renewal(
                authority(claim(ClaimState::Active {
                    lease_until: 1_000_000,
                }))
                .await,
                &work("work-17", 4),
                &ActorId::new("rust-worker".into()).unwrap(),
                &InstanceId::new("instance-a".into()).unwrap(),
                9,
                200_000,
            )
            .unwrap();
            let (store, _) = replay_store(vec![response(500, &[], SdkBody::empty()), reread]);
            let mut history = AttemptHistory::default();
            assert!(matches!(
                apply_mutation(
                    &store,
                    mutation.attributed_to(store.namespace()),
                    &work("work-17", 4),
                    200_000,
                    &mut history
                )
                .await,
                ClaimMutationOutcome::Unresolved(_)
            ));
        }
    }

    #[tokio::test]
    async fn expired_claim_reclamation_advances_fence_and_rebinds_owner() {
        let original = claim(ClaimState::Active {
            lease_until: 1_000_000,
        });
        let original_operation = original.operation_id().to_owned();
        let mutation = prepare_reclamation(
            observed(original).await,
            &work("work-17", 5),
            &ActorId::new("replacement".into()).unwrap(),
            &InstanceId::new("replacement-instance".into()).unwrap(),
            1_000_000,
        )
        .unwrap();
        assert_eq!(mutation.claim.work_revision(), 5);
        assert_eq!(mutation.claim.owner_actor().as_str(), "replacement");
        assert_eq!(
            mutation.claim.owner_instance().as_str(),
            "replacement-instance"
        );
        assert_eq!(mutation.claim.fence(), 10);
        assert_ne!(mutation.claim.operation_id(), original_operation);
        assert_eq!(mutation.key, TEST_KEY);
        assert!(matches!(
            mutation.claim.state(),
            ClaimState::Active {
                lease_until: 1_900_000
            }
        ));
    }

    #[tokio::test]
    async fn reclamation_rejects_ineligible_and_overflowing_claims() {
        let actor = ActorId::new("replacement".into()).unwrap();
        let instance = InstanceId::new("replacement-instance".into()).unwrap();
        assert!(matches!(
            prepare_reclamation(
                observed(claim(ClaimState::Active {
                    lease_until: 1_000_001,
                }))
                .await,
                &work("work-17", 4),
                &actor,
                &instance,
                1_000_000,
            ),
            Err(ClaimPrepareError::InvalidInput)
        ));
        assert!(matches!(
            prepare_reclamation(
                observed(claim(ClaimState::Sealed {
                    result_ref: artifact(),
                }))
                .await,
                &work("work-17", 4),
                &actor,
                &instance,
                1_000_000,
            ),
            Err(ClaimPrepareError::InvalidInput)
        ));
        let max_fence = Claim::new(
            WorkId::new("work-17".into()).unwrap(),
            4,
            ActorId::new("rust-worker".into()).unwrap(),
            InstanceId::new("instance-a".into()).unwrap(),
            u64::MAX,
            "op-max".into(),
            ClaimState::Active { lease_until: 1 },
        )
        .unwrap();
        assert!(matches!(
            prepare_reclamation(
                observed(max_fence).await,
                &work("work-17", 4),
                &actor,
                &instance,
                1,
            ),
            Err(ClaimPrepareError::InvalidInput)
        ));
        assert!(matches!(
            prepare_reclamation(
                observed(claim(ClaimState::Active { lease_until: 1 })).await,
                &work("work-17", 4),
                &actor,
                &instance,
                u64::MAX,
            ),
            Err(ClaimPrepareError::InvalidInput)
        ));
    }

    #[tokio::test]
    async fn one_of_two_reclaimers_from_one_etag_wins() {
        let actor = ActorId::new("replacement".into()).unwrap();
        let first = prepare_reclamation(
            observed(claim(ClaimState::Active { lease_until: 1 })).await,
            &work("work-17", 4),
            &actor,
            &InstanceId::new("replacement-a".into()).unwrap(),
            1,
        )
        .unwrap();
        let second = prepare_reclamation(
            observed(claim(ClaimState::Active { lease_until: 1 })).await,
            &work("work-17", 4),
            &actor,
            &InstanceId::new("replacement-b".into()).unwrap(),
            1,
        )
        .unwrap();
        let (store, client) = replay_store(vec![
            response(200, &[("etag", NEW_ETAG)], SdkBody::empty()),
            response(412, &[], SdkBody::empty()),
        ]);
        let mut first_history = AttemptHistory::default();
        let mut second_history = AttemptHistory::default();
        let outcomes = [
            apply_mutation(
                &store,
                first.attributed_to(store.namespace()),
                &work("work-17", 4),
                1,
                &mut first_history,
            )
            .await,
            apply_mutation(
                &store,
                second.attributed_to(store.namespace()),
                &work("work-17", 4),
                1,
                &mut second_history,
            )
            .await,
        ];
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, ClaimMutationOutcome::Applied(_)))
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, ClaimMutationOutcome::Lost))
                .count(),
            1
        );
        for request in client.actual_requests() {
            assert_eq!(request.headers().get("if-match").unwrap(), TEST_ETAG);
            assert_eq!(
                request.uri().parse::<http::Uri>().unwrap().path(),
                format!("/{TEST_KEY}")
            );
        }
        assert_eq!(client.actual_requests().count(), 2);
    }

    #[tokio::test]
    async fn stale_sealed_claim_can_be_superseded_but_current_terminal_cannot() {
        let actor = ActorId::new("replacement".into()).unwrap();
        let instance = InstanceId::new("replacement-instance".into()).unwrap();
        let mutation = prepare_supersession(
            observed(claim(ClaimState::Sealed {
                result_ref: artifact(),
            }))
            .await,
            &work("work-17", 5),
            &actor,
            &instance,
            2_000_000,
        )
        .unwrap();
        assert_eq!(mutation.claim.work_revision(), 5);
        assert_eq!(mutation.claim.fence(), 10);
        assert_eq!(mutation.key, TEST_KEY);
        assert!(matches!(
            mutation.claim.state(),
            ClaimState::Active {
                lease_until: 2_900_000
            }
        ));
        assert!(matches!(
            prepare_supersession(
                observed(claim(ClaimState::Sealed {
                    result_ref: artifact(),
                }))
                .await,
                &work("work-17", 4),
                &actor,
                &instance,
                2_000_000,
            ),
            Err(ClaimPrepareError::InvalidInput)
        ));
        assert!(matches!(
            prepare_supersession(
                observed(claim(ClaimState::Active { lease_until: 1 })).await,
                &work("work-17", 5),
                &actor,
                &instance,
                2_000_000,
            ),
            Err(ClaimPrepareError::InvalidInput)
        ));
        assert!(matches!(
            prepare_supersession(
                observed(claim(ClaimState::Sealed {
                    result_ref: artifact(),
                }))
                .await,
                &work("other-work", 5),
                &actor,
                &instance,
                2_000_000,
            ),
            Err(ClaimPrepareError::InvalidInput)
        ));
    }

    #[tokio::test]
    async fn replacements_never_roll_a_claim_revision_backward() {
        let actor = ActorId::new("replacement".into()).unwrap();
        let instance = InstanceId::new("replacement-instance".into()).unwrap();
        let newer = |state: ClaimState| {
            Claim::new(
                WorkId::new("work-17".into()).unwrap(),
                5,
                ActorId::new("rust-worker".into()).unwrap(),
                InstanceId::new("instance-a".into()).unwrap(),
                9,
                "op-claim-005".into(),
                state,
            )
            .unwrap()
        };

        assert!(matches!(
            prepare_reclamation(
                observed(newer(ClaimState::Active { lease_until: 1 })).await,
                &work("work-17", 4),
                &actor,
                &instance,
                2_000_000,
            ),
            Err(ClaimPrepareError::InvalidInput)
        ));
        assert!(matches!(
            prepare_supersession(
                observed(newer(ClaimState::Sealed {
                    result_ref: artifact(),
                }))
                .await,
                &work("work-17", 4),
                &actor,
                &instance,
                2_000_000,
            ),
            Err(ClaimPrepareError::InvalidInput)
        ));
        assert!(
            prepare_supersession(
                observed(claim(ClaimState::Sealed {
                    result_ref: artifact(),
                }))
                .await,
                &work("work-17", 5),
                &actor,
                &instance,
                2_000_000,
            )
            .is_ok()
        );
    }

    #[tokio::test]
    async fn an_early_renewal_returns_the_unspent_authority() {
        let outcome = prepare_renewal(
            authority(claim(ClaimState::Active {
                lease_until: 10_000_000,
            }))
            .await,
            &work("work-17", 4),
            &ActorId::new("rust-worker".into()).unwrap(),
            &InstanceId::new("instance-a".into()).unwrap(),
            9,
            200_000,
        );
        let Err(rejection) = outcome else {
            panic!("a lease already past the proposed one is not renewable");
        };
        assert_eq!(rejection.error, ClaimPrepareError::InvalidInput);
        // The returned authority is intact and still authorizes the same claim.
        let authority = rejection.authority.expect("early renewal keeps authority");
        assert!(authority.authorizes(&work("work-17", 4), &workspace("workspace-1"), "campaign-1"));
    }

    #[tokio::test]
    async fn an_expired_attempt_is_ineligible_without_a_send() {
        let (store, client) = replay_store(Vec::new());
        let mut history = AttemptHistory::default();
        // attempt() freezes lease_until = prepare-time now + CLAIM_LEASE_MS; the
        // send margin makes the attempt ineligible before the lease itself lapses.
        let now = 1_749_999_100_000 + CLAIM_LEASE_MS - CLAIM_SEND_MARGIN_MS;
        assert!(matches!(
            acquire(&store, attempt(), now, &mut history).await,
            ClaimAcquireOutcome::Ineligible
        ));
        assert_eq!(client.actual_requests().count(), 0);
    }

    #[tokio::test]
    async fn a_tokenless_committed_mutation_never_retries_its_stale_etag() {
        for reread_found in [true, false] {
            let mutation = prepare_reclamation(
                observed(claim(ClaimState::Active {
                    lease_until: 1_000_000,
                }))
                .await,
                &work("work-17", 4),
                &ActorId::new("reclaimer".into()).unwrap(),
                &InstanceId::new("instance-b".into()).unwrap(),
                1_500_000,
            )
            .unwrap();
            let expected_bytes = mutation.canonical_bytes.clone();
            let reread = if reread_found {
                response(200, &[("etag", NEW_ETAG)], expected_bytes)
            } else {
                response(500, &[], SdkBody::empty())
            };
            // A 200 PUT response without an ETag header is a committed write
            // whose fresh token was not returned.
            let (store, _) = replay_store(vec![response(200, &[], SdkBody::empty()), reread]);
            let mut history = AttemptHistory::default();
            let outcome = apply_mutation(
                &store,
                mutation.attributed_to(store.namespace()),
                &work("work-17", 4),
                1_500_000,
                &mut history,
            )
            .await;
            if reread_found {
                assert!(matches!(outcome, ClaimMutationOutcome::Applied(_)));
            } else {
                assert!(matches!(outcome, ClaimMutationOutcome::AppliedUnverified));
            }
        }
    }

    #[tokio::test]
    async fn a_replacement_with_an_expired_candidate_lease_is_ineligible() {
        let observed = observed(claim(ClaimState::Active {
            lease_until: 1_000_000,
        }))
        .await;
        let mutation = prepare_reclamation(
            observed,
            &work("work-17", 4),
            &ActorId::new("reclaimer".into()).unwrap(),
            &InstanceId::new("instance-b".into()).unwrap(),
            1_500_000,
        )
        .unwrap();
        let (store, client) = replay_store(Vec::new());
        let mut history = AttemptHistory::default();
        assert!(matches!(
            apply_mutation(
                &store,
                mutation.attributed_to(store.namespace()),
                &work("work-17", 4),
                1_500_000 + CLAIM_LEASE_MS,
                &mut history,
            )
            .await,
            ClaimMutationOutcome::Ineligible
        ));
        assert_eq!(client.actual_requests().count(), 0);
    }

    #[tokio::test]
    async fn a_frozen_mutation_is_ineligible_once_its_preconditions_lapse() {
        async fn renewal() -> ClaimMutation {
            prepare_renewal(
                authority(claim(ClaimState::Active {
                    lease_until: 1_000_000,
                }))
                .await,
                &work("work-17", 4),
                &ActorId::new("rust-worker".into()).unwrap(),
                &InstanceId::new("instance-a".into()).unwrap(),
                9,
                200_000,
            )
            .expect("renewal prepares")
        }

        // The observed lease has expired by the time the retry is attempted.
        let (store, client) =
            replay_store(vec![response(200, &[("etag", NEW_ETAG)], SdkBody::empty())]);
        let mut history = AttemptHistory::default();
        assert!(matches!(
            apply_mutation(
                &store,
                renewal().await,
                &work("work-17", 4),
                1_000_000,
                &mut history
            )
            .await,
            ClaimMutationOutcome::Ineligible
        ));

        // The work generation advanced past the revision the mutation froze.
        let mut history = AttemptHistory::default();
        assert!(matches!(
            apply_mutation(
                &store,
                renewal().await,
                &work("work-17", 5),
                200_000,
                &mut history
            )
            .await,
            ClaimMutationOutcome::Ineligible
        ));
        assert_eq!(client.actual_requests().count(), 0);
    }

    #[tokio::test]
    async fn an_unchanged_object_keeps_an_ambiguous_mutation_unresolved() {
        let mutation = prepare_renewal(
            authority(claim(ClaimState::Active {
                lease_until: 1_000_000,
            }))
            .await,
            &work("work-17", 4),
            &ActorId::new("rust-worker".into()).unwrap(),
            &InstanceId::new("instance-a".into()).unwrap(),
            9,
            200_000,
        )
        .unwrap();
        let pre_mutation = encode(&claim(ClaimState::Active {
            lease_until: 1_000_000,
        }))
        .unwrap();
        let (store, client) = replay_store(vec![
            response(500, &[], SdkBody::empty()),
            response(200, &[("etag", TEST_ETAG)], pre_mutation),
        ]);
        let mut history = AttemptHistory::default();

        assert!(matches!(
            apply_mutation(
                &store,
                mutation.attributed_to(store.namespace()),
                &work("work-17", 4),
                200_000,
                &mut history
            )
            .await,
            ClaimMutationOutcome::Unresolved(_)
        ));
        assert_eq!(client.actual_requests().count(), 2);
    }

    #[tokio::test]
    async fn observation_couples_claim_key_and_etag_and_fails_closed() {
        let expected = claim(ClaimState::Active { lease_until: 1 });
        let bytes = encode(&expected).unwrap();
        let (store, _) = replay_store(vec![response(200, &[("etag", TEST_ETAG)], bytes)]);
        let found = observe(
            &store,
            &workspace("workspace-1"),
            "campaign-1",
            &WorkId::new("work-17".into()).unwrap(),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(found.claim, expected);
        assert_eq!(found.key, TEST_KEY);
        assert!(found.etag == etag(TEST_ETAG).await);

        let (store, _) = replay_store(vec![response(404, &[], SdkBody::empty())]);
        assert!(
            observe(
                &store,
                &workspace("workspace-1"),
                "campaign-1",
                &WorkId::new("work-17".into()).unwrap(),
            )
            .await
            .unwrap()
            .is_none()
        );

        let (store, _) = replay_store(vec![response(
            200,
            &[("etag", TEST_ETAG)],
            b"not-json".to_vec(),
        )]);
        assert!(matches!(
            observe(
                &store,
                &workspace("workspace-1"),
                "campaign-1",
                &WorkId::new("work-17".into()).unwrap(),
            )
            .await,
            Err(ClaimReadError::Invalid(WireError::InvalidEncoding))
        ));

        let oversized = (MAX_CLAIM_BYTES + 1).to_string();
        let (store, _) = replay_store(vec![response(
            200,
            &[("content-length", oversized.as_str()), ("etag", TEST_ETAG)],
            SdkBody::empty(),
        )]);
        assert!(matches!(
            observe(
                &store,
                &workspace("workspace-1"),
                "campaign-1",
                &WorkId::new("work-17".into()).unwrap(),
            )
            .await,
            Err(ClaimReadError::Invalid(WireError::LimitExceeded))
        ));
    }

    async fn published_result() -> PublishedArtifact {
        let (store, _) = replay_store(vec![response(200, &[], SdkBody::empty())]);
        artifacts::publish(
            &store,
            b"result".to_vec(),
            "application/json".into(),
            "attempt-17".into(),
            1_750_000_000_000,
            None,
        )
        .await
        .unwrap()
    }

    fn sealed(result_ref: ArtifactRef) -> Claim {
        claim(ClaimState::Sealed { result_ref })
    }

    fn submit_outcome(result: Result<ClaimMutationOutcome, SubmitFailure>) -> ClaimMutationOutcome {
        match result {
            Ok(outcome) => outcome,
            Err(failure) => panic!("submit failed: {}", failure.error()),
        }
    }

    #[tokio::test]
    async fn submit_publishes_bound_record_then_seals_on_authority_etag() {
        let published = published_result().await;
        let expected_result = published.artifact_ref().clone();
        // lease_until 1 is long expired: sealing consults no clock, only the
        // bound ETag CAS.
        let authority = authority(claim(ClaimState::Active { lease_until: 1 })).await;
        let (store, client) = replay_store(vec![
            response(200, &[], SdkBody::empty()),
            response(200, &[("etag", NEW_ETAG)], SdkBody::empty()),
        ]);
        let published = published.attributed_to(store.namespace());
        let mut history = AttemptHistory::default();
        let applied = match submit_outcome(
            submit(
                &store,
                authority.attributed_to(store.namespace()),
                ClaimScope {
                    work: &work("work-17", 4),
                    workspace: &workspace("workspace-1"),
                    campaign_id: "campaign-1",
                },
                &published,
                200_000,
                &mut history,
            )
            .await,
        ) {
            ClaimMutationOutcome::Applied(authority) => authority,
            _ => panic!("current ETag must seal"),
        };
        assert_eq!(applied.claim.work_revision(), 4);
        assert_eq!(applied.claim.owner_actor().as_str(), "rust-worker");
        assert_eq!(applied.claim.owner_instance().as_str(), "instance-a");
        assert_eq!(applied.claim.fence(), 9);
        assert_eq!(applied.claim.operation_id(), "op-claim-001");
        assert_eq!(
            applied.claim.state(),
            &ClaimState::Sealed {
                result_ref: expected_result.clone(),
            }
        );

        assert_eq!(client.actual_requests().count(), 2);
        let publication = client.actual_requests().next().unwrap();
        assert_eq!(publication.headers().get("if-none-match"), Some("*"));
        assert_eq!(
            publication.uri().parse::<http::Uri>().unwrap().path(),
            "/workspace/workspace-1/campaigns/campaign-1/submissions/attempt-17.json"
        );
        let record = crate::domain::attempt::decode(publication.body().bytes().unwrap()).unwrap();
        assert_eq!(record.attempt_id(), "attempt-17");
        assert_eq!(record.work_id().as_str(), "work-17");
        assert_eq!(record.work_revision(), 4);
        assert_eq!(record.owner_actor().as_str(), "rust-worker");
        assert_eq!(record.owner_instance().as_str(), "instance-a");
        assert_eq!(record.fence(), 9);
        assert_eq!(record.operation_id(), "op-claim-001");
        assert_eq!(record.result_ref(), &expected_result);

        let terminal = client.actual_requests().nth(1).unwrap();
        assert_eq!(terminal.headers().get("if-match"), Some(TEST_ETAG));
        assert!(terminal.headers().get("if-none-match").is_none());
        assert_eq!(
            terminal.uri().parse::<http::Uri>().unwrap().path(),
            format!("/{TEST_KEY}")
        );
        assert_eq!(
            decode(terminal.body().bytes().unwrap()).unwrap(),
            applied.claim
        );
    }

    #[tokio::test]
    async fn submit_rejects_terminal_or_mismatched_context_before_io() {
        let published = published_result().await;
        for (authority, workspace_id, campaign_id) in [
            (
                authority(sealed(published.artifact_ref().clone())).await,
                "workspace-1",
                "campaign-1",
            ),
            (
                authority(claim(ClaimState::Active { lease_until: 1 })).await,
                "other-workspace",
                "campaign-1",
            ),
            (
                authority(claim(ClaimState::Active { lease_until: 1 })).await,
                "workspace-1",
                "other-campaign",
            ),
        ] {
            let (store, client) = replay_store(Vec::new());
            let mut history = AttemptHistory::default();
            let failure = match submit(
                &store,
                authority,
                ClaimScope {
                    work: &work("work-17", 4),
                    workspace: &workspace(workspace_id),
                    campaign_id,
                },
                &published,
                200_000,
                &mut history,
            )
            .await
            {
                Err(failure) => failure,
                Ok(_) => panic!("invalid authority context must fail"),
            };
            assert_eq!(failure.error(), SubmitError::InvalidInput);
            let authority = failure.into_authority();
            assert_eq!(authority.claim.work_id().as_str(), "work-17");
            assert_eq!(client.actual_requests().count(), 0);
        }
    }

    #[tokio::test]
    async fn a_foreign_namespace_artifact_is_rejected_before_io() {
        // published_result() minted its witness against a different store, so
        // its namespace cannot match the submit store's.
        let published = published_result().await;
        let authority = authority(claim(ClaimState::Active { lease_until: 1 })).await;
        let (store, client) = replay_store(Vec::new());
        let mut history = AttemptHistory::default();
        let failure = match submit(
            &store,
            authority.attributed_to(store.namespace()),
            ClaimScope {
                work: &work("work-17", 4),
                workspace: &workspace("workspace-1"),
                campaign_id: "campaign-1",
            },
            &published,
            200_000,
            &mut history,
        )
        .await
        {
            Err(failure) => failure,
            Ok(_) => panic!("a foreign-namespace artifact must not seal a claim"),
        };
        assert_eq!(failure.error(), SubmitError::InvalidInput);
        let _ = failure.into_authority();
        assert_eq!(client.actual_requests().count(), 0);
    }

    #[tokio::test]
    async fn a_foreign_namespace_authority_is_rejected_before_io() {
        // authority() is bound to TEST_NAMESPACE, not this store's namespace.
        let authority = authority(claim(ClaimState::Active { lease_until: 1 })).await;
        let (store, client) = replay_store(Vec::new());
        let published = published_result().await.attributed_to(store.namespace());
        let mut history = AttemptHistory::default();
        let failure = match submit(
            &store,
            authority,
            ClaimScope {
                work: &work("work-17", 4),
                workspace: &workspace("workspace-1"),
                campaign_id: "campaign-1",
            },
            &published,
            200_000,
            &mut history,
        )
        .await
        {
            Err(failure) => failure,
            Ok(_) => panic!("a foreign-namespace authority must not seal a claim"),
        };
        assert_eq!(failure.error(), SubmitError::InvalidInput);
        let _ = failure.into_authority();
        assert_eq!(client.actual_requests().count(), 0);
    }

    #[tokio::test]
    async fn a_foreign_namespace_mutation_is_ineligible_without_a_send() {
        let mutation = prepare_reclamation(
            observed(claim(ClaimState::Active { lease_until: 1 })).await,
            &work("work-17", 4),
            &ActorId::new("reclaimer".into()).unwrap(),
            &InstanceId::new("instance-b".into()).unwrap(),
            200_000,
        )
        .unwrap();
        let (store, client) = replay_store(Vec::new());
        let mut history = AttemptHistory::default();
        // observed() is bound to TEST_NAMESPACE, not this store's namespace.
        assert!(matches!(
            apply_mutation(&store, mutation, &work("work-17", 4), 200_000, &mut history).await,
            ClaimMutationOutcome::Ineligible
        ));
        assert_eq!(client.actual_requests().count(), 0);
    }

    #[tokio::test]
    async fn a_mismatched_work_revision_is_rejected_before_io() {
        let authority = authority(claim(ClaimState::Active { lease_until: 1 })).await;
        let (store, client) = replay_store(Vec::new());
        let published = published_result().await.attributed_to(store.namespace());
        let mut history = AttemptHistory::default();
        let failure = match submit(
            &store,
            authority.attributed_to(store.namespace()),
            ClaimScope {
                work: &work("work-17", 5),
                workspace: &workspace("workspace-1"),
                campaign_id: "campaign-1",
            },
            &published,
            200_000,
            &mut history,
        )
        .await
        {
            Err(failure) => failure,
            Ok(_) => panic!("a mismatched work revision must fail before any I/O"),
        };
        assert_eq!(failure.error(), SubmitError::InvalidInput);
        let _ = failure.into_authority();
        assert_eq!(client.actual_requests().count(), 0);
    }

    #[tokio::test]
    async fn publication_failure_returns_usable_authority() {
        let published = published_result().await;
        let authority = authority(claim(ClaimState::Active { lease_until: 1 })).await;
        let (store, client) = replay_store(vec![response(404, &[], SdkBody::empty())]);
        let published = published.attributed_to(store.namespace());
        let mut history = AttemptHistory::default();
        let failure = match submit(
            &store,
            authority.attributed_to(store.namespace()),
            ClaimScope {
                work: &work("work-17", 4),
                workspace: &workspace("workspace-1"),
                campaign_id: "campaign-1",
            },
            &published,
            200_000,
            &mut history,
        )
        .await
        {
            Err(failure) => failure,
            Ok(_) => panic!("failed evidence publication must not seal"),
        };
        assert_eq!(failure.error(), SubmitError::Publication);
        assert!(failure.into_authority().authorizes(
            &work("work-17", 4),
            &workspace("workspace-1"),
            "campaign-1"
        ));
        assert_eq!(client.actual_requests().count(), 1);
    }

    #[tokio::test]
    async fn completion_and_reclamation_from_one_etag_have_one_winner() {
        let published = published_result().await;
        let original = claim(ClaimState::Active { lease_until: 1 });
        let reclaim = prepare_reclamation(
            observed(original.clone()).await,
            &work("work-17", 5),
            &ActorId::new("replacement".into()).unwrap(),
            &InstanceId::new("replacement-instance".into()).unwrap(),
            1,
        )
        .unwrap();
        let (store, _) = replay_store(vec![
            response(200, &[], SdkBody::empty()),
            response(200, &[("etag", NEW_ETAG)], SdkBody::empty()),
            response(412, &[], SdkBody::empty()),
        ]);
        let published = published.attributed_to(store.namespace());
        let mut seal_history = AttemptHistory::default();
        let mut reclaim_history = AttemptHistory::default();
        let outcomes = [
            submit_outcome(
                submit(
                    &store,
                    authority(original).await.attributed_to(store.namespace()),
                    ClaimScope {
                        work: &work("work-17", 4),
                        workspace: &workspace("workspace-1"),
                        campaign_id: "campaign-1",
                    },
                    &published,
                    200_000,
                    &mut seal_history,
                )
                .await,
            ),
            apply_mutation(
                &store,
                reclaim.attributed_to(store.namespace()),
                &work("work-17", 5),
                200_000,
                &mut reclaim_history,
            )
            .await,
        ];
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, ClaimMutationOutcome::Applied(_)))
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, ClaimMutationOutcome::Lost))
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn reclaimed_generation_leaves_stale_evidence_but_rejects_seal() {
        let published = published_result().await;
        let stale_result = published.artifact_ref().clone();
        let original = claim(ClaimState::Active { lease_until: 1 });
        let reclaim = prepare_reclamation(
            observed(original.clone()).await,
            &work("work-17", 5),
            &ActorId::new("replacement".into()).unwrap(),
            &InstanceId::new("replacement-instance".into()).unwrap(),
            1,
        )
        .unwrap();
        let (store, client) = replay_store(vec![
            response(200, &[("etag", NEW_ETAG)], SdkBody::empty()),
            response(200, &[], SdkBody::empty()),
            response(412, &[], SdkBody::empty()),
        ]);
        let published = published.attributed_to(store.namespace());
        let mut reclaim_history = AttemptHistory::default();
        assert!(matches!(
            apply_mutation(
                &store,
                reclaim.attributed_to(store.namespace()),
                &work("work-17", 5),
                200_000,
                &mut reclaim_history,
            )
            .await,
            ClaimMutationOutcome::Applied(_)
        ));
        let mut seal_history = AttemptHistory::default();
        assert!(matches!(
            submit_outcome(
                submit(
                    &store,
                    authority(original).await.attributed_to(store.namespace()),
                    ClaimScope {
                        work: &work("work-17", 4),
                        workspace: &workspace("workspace-1"),
                        campaign_id: "campaign-1",
                    },
                    &published,
                    200_000,
                    &mut seal_history,
                )
                .await,
            ),
            ClaimMutationOutcome::Lost
        ));
        assert_eq!(client.actual_requests().count(), 3);
        let current = decode(
            client
                .actual_requests()
                .next()
                .unwrap()
                .body()
                .bytes()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(current.work_revision(), 5);
        assert_eq!(current.fence(), 10);
        assert!(matches!(current.state(), ClaimState::Active { .. }));
        let stale_candidate = decode(
            client
                .actual_requests()
                .nth(2)
                .unwrap()
                .body()
                .bytes()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            stale_candidate.state(),
            &ClaimState::Sealed {
                result_ref: stale_result,
            }
        );
        assert_eq!(
            client
                .actual_requests()
                .nth(1)
                .unwrap()
                .uri()
                .parse::<http::Uri>()
                .unwrap()
                .path(),
            "/workspace/workspace-1/campaigns/campaign-1/submissions/attempt-17.json"
        );
    }

    #[tokio::test]
    async fn publication_digest_covers_the_submission_bytes() {
        let published = published_result().await;
        let expected_submission = crate::domain::attempt::encode(
            &crate::domain::attempt::Submission::new(
                WorkId::new("work-17".into()).unwrap(),
                4,
                ActorId::new("rust-worker".into()).unwrap(),
                InstanceId::new("instance-a".into()).unwrap(),
                9,
                "op-claim-001".into(),
                published.artifact_ref().clone(),
            )
            .unwrap(),
        )
        .unwrap();
        let (store, client) = replay_store(vec![
            response(409, &[], SdkBody::empty()),
            response(200, &[("etag", TEST_ETAG)], expected_submission),
            response(200, &[("etag", NEW_ETAG)], SdkBody::empty()),
        ]);
        let published = published.attributed_to(store.namespace());
        let mut history = AttemptHistory::default();
        let outcome = submit_outcome(
            submit(
                &store,
                authority(claim(ClaimState::Active { lease_until: 1 }))
                    .await
                    .attributed_to(store.namespace()),
                ClaimScope {
                    work: &work("work-17", 4),
                    workspace: &workspace("workspace-1"),
                    campaign_id: "campaign-1",
                },
                &published,
                200_000,
                &mut history,
            )
            .await,
        );
        assert!(matches!(outcome, ClaimMutationOutcome::Applied(_)));
        assert_eq!(client.actual_requests().count(), 3);
    }

    #[tokio::test]
    async fn submit_threads_the_caller_owned_history() {
        let published = published_result().await;
        let expected = sealed(published.artifact_ref().clone());
        let (store, client) = replay_store(vec![
            response(500, &[], SdkBody::empty()),
            response(200, &[], SdkBody::empty()),
            response(412, &[], SdkBody::empty()),
            response(200, &[("etag", NEW_ETAG)], encode(&expected).unwrap()),
        ]);
        let published = published.attributed_to(store.namespace());
        let mut history = AttemptHistory::default();
        // One history covers one object, so the taint comes from the claim's own key.
        let claim_key = claim_key(
            &workspace("workspace-1"),
            "campaign-1",
            work("work-17", 4).id(),
        )
        .expect("valid claim key");
        assert!(matches!(
            store
                .put_if_absent(&claim_key, Vec::new(), &mut history)
                .await,
            MutationOutcome::Unknown
        ));
        let outcome = submit_outcome(
            submit(
                &store,
                authority(claim(ClaimState::Active { lease_until: 1 }))
                    .await
                    .attributed_to(store.namespace()),
                ClaimScope {
                    work: &work("work-17", 4),
                    workspace: &workspace("workspace-1"),
                    campaign_id: "campaign-1",
                },
                &published,
                200_000,
                &mut history,
            )
            .await,
        );
        assert!(matches!(outcome, ClaimMutationOutcome::Applied(_)));
        assert_eq!(client.actual_requests().count(), 4);
    }

    #[tokio::test]
    async fn ambiguous_terminal_cas_requires_exact_same_key_bytes() {
        for case in ["exact", "different", "missing", "failed"] {
            let published = published_result().await;
            let expected = sealed(published.artifact_ref().clone());
            let reread = match case {
                "exact" => response(200, &[("etag", NEW_ETAG)], encode(&expected).unwrap()),
                "different" => response(
                    200,
                    &[("etag", NEW_ETAG)],
                    encode(&claim(ClaimState::Active { lease_until: 1 })).unwrap(),
                ),
                "missing" => response(404, &[], SdkBody::empty()),
                "failed" => response(500, &[], SdkBody::empty()),
                _ => unreachable!(),
            };
            let (store, client) = replay_store(vec![
                response(200, &[], SdkBody::empty()),
                response(500, &[], SdkBody::empty()),
                reread,
            ]);
            let published = published.attributed_to(store.namespace());
            let mut history = AttemptHistory::default();
            let outcome = submit_outcome(
                submit(
                    &store,
                    authority(claim(ClaimState::Active { lease_until: 1 }))
                        .await
                        .attributed_to(store.namespace()),
                    ClaimScope {
                        work: &work("work-17", 4),
                        workspace: &workspace("workspace-1"),
                        campaign_id: "campaign-1",
                    },
                    &published,
                    200_000,
                    &mut history,
                )
                .await,
            );
            match case {
                "exact" => assert!(matches!(outcome, ClaimMutationOutcome::Applied(_))),
                "different" => assert!(matches!(outcome, ClaimMutationOutcome::Lost)),
                "missing" | "failed" => {
                    assert!(matches!(outcome, ClaimMutationOutcome::Unresolved(_)))
                }
                _ => unreachable!(),
            }
            assert_eq!(client.actual_requests().count(), 3);
        }
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
            namespace: TEST_NAMESPACE.into(),
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
