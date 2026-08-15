//! Scoped effect grants: bounded authority for one external operation.
//!
//! A grant is an immutable JSON object at its claim generation's grant key, published
//! create-if-absent and activated by the existing `grant_fence` projection marker. The object
//! alone grants nothing: intake accepts a grant only while the projection still reports its
//! exact work revision resumable, so claim reclamation, terminal evidence, or expiry revokes it
//! without a revocation record.
//!
//! A grant authorizes execution only. No path here inserts work rows or writes terminal
//! evidence; those writers stay reachable only from plan admission and sealed-claim intake.
//! commentlint: allow(JUDGE)

use std::num::NonZeroU64;

use serde::{Deserialize, Serialize};

use crate::{
    db::{projections::ApplyError, worker::DbHandle},
    distributed::scope_controller::ControllerAuthority,
    domain::{
        proposal::MAX_STORED_INTEGER,
        validation::{ValidationError, validate_key_segment},
        work::WorkRef,
    },
    scope::{Digest, ScopeClaimIdentity, ScopeIdentity, scope_grant_key},
    storage::s3::{AttemptHistory, GetError, GetOutcome, PublicationError, S3Store},
    sync::WireError,
};

/// Bound on one grant object.
pub const MAX_GRANT_BYTES: usize = 4 * 1024;

const GRANT_RECORD: &str = "effect_grant";

/// Bounded authority for one external operation under one claim generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectGrant {
    identity: ScopeClaimIdentity,
    action: String,
    resource_scope: String,
    limit_units: NonZeroU64,
    deadline_unix_ms: NonZeroU64,
    operation_id: String,
}

impl EffectGrant {
    /// # Errors
    ///
    /// Returns [`ValidationError`] when `action`, `resource_scope`, or `operation_id` is not one
    /// key segment, or when `limit_units` or `deadline_unix_ms` is outside `1..=MAX_STORED_INTEGER`.
    pub fn new(
        identity: ScopeClaimIdentity,
        action: String,
        resource_scope: String,
        limit_units: u64,
        deadline_unix_ms: u64,
        operation_id: String,
    ) -> Result<Self, ValidationError> {
        validate_key_segment(&action)?;
        validate_key_segment(&resource_scope)?;
        validate_key_segment(&operation_id)?;
        let bounded = |value: u64| {
            NonZeroU64::new(value)
                .filter(|value| value.get() <= MAX_STORED_INTEGER)
                .ok_or(ValidationError::InvalidExpiry)
        };
        Ok(Self {
            identity,
            action,
            resource_scope,
            limit_units: bounded(limit_units)?,
            deadline_unix_ms: bounded(deadline_unix_ms)?,
            operation_id,
        })
    }

    pub fn identity(&self) -> &ScopeClaimIdentity {
        &self.identity
    }

    pub fn action(&self) -> &str {
        &self.action
    }

    pub fn resource_scope(&self) -> &str {
        &self.resource_scope
    }

    pub fn limit_units(&self) -> NonZeroU64 {
        self.limit_units
    }

    pub fn deadline_unix_ms(&self) -> NonZeroU64 {
        self.deadline_unix_ms
    }

    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }
}

/// What a caller requires of a grant before acting under it.
///
/// `max_units` and `max_deadline_unix_ms` cap what the request asked for, so a wider grant fails
/// closed instead of widening the operation.
pub struct ExpectedGrant {
    pub identity: ScopeClaimIdentity,
    pub action: String,
    pub resource_scope: String,
    pub max_units: NonZeroU64,
    pub max_deadline_unix_ms: NonZeroU64,
}

/// Data-free category for one refused grant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GrantRejection {
    /// No object exists at the claim generation's grant key.
    Absent,
    /// The grant names a lower claim fence than the caller's.
    StaleFence,
    /// Scope, plan, revision, action, or resource binding disagrees.
    IdentityMismatch,
    Expired,
    WiderThanRequested,
    /// The projection no longer reports the revision resumable under this generation.
    Revoked,
    Malformed,
}

/// Outcome of reading one grant back for use.
#[must_use]
pub enum GrantIntake {
    Accepted(Box<EffectGrant>),
    Rejected(GrantRejection),
    /// Storage or projection transport failed; retry may succeed.
    Unavailable,
}

/// Data-free category for one refused issuance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IssueError {
    /// The authority is stopped, from another scope, or holds no or another active plan.
    NotAuthorized,
    /// The grant is already expired at issuance time.
    Expired,
    /// Publication could not be proven; retry the identical grant.
    Unresolved,
    /// The projection refused the recording; the grant object stays inert.
    Refused,
}

/// Publishes one grant and activates it in the projection.
///
/// The immutable object is published before the `grant_fence` marker, so a crash between the two
/// leaves an inert object and the identical retry is safe: publication verifies the same bytes
/// and the recording is same-fence idempotent.
///
/// # Errors
///
/// Returns [`IssueError::NotAuthorized`] when `authority` is stopped or does not hold this
/// grant's scope and plan, [`IssueError::Expired`] when the deadline is not ahead of `now_ms`,
/// [`IssueError::Unresolved`] for unproven publication, and [`IssueError::Refused`] when the
/// projection rejects the binding.
pub async fn issue(
    store: &S3Store,
    database: &DbHandle,
    authority: &ControllerAuthority,
    grant: &EffectGrant,
    history: &mut AttemptHistory,
    now_ms: u64,
) -> Result<(), IssueError> {
    let head = authority.head();
    if authority.must_stop(now_ms)
        || head.scope() != grant.identity.scope()
        || head.active_plan_digest() != Some(grant.identity.plan_digest())
    {
        return Err(IssueError::NotAuthorized);
    }
    if grant.deadline_unix_ms.get() <= now_ms {
        return Err(IssueError::Expired);
    }
    let bytes = encode_grant(grant).map_err(|_| IssueError::Refused)?;
    let key = scope_grant_key(
        grant.identity.scope(),
        grant.identity.work(),
        grant.identity.claim_fence(),
    );
    let digest = format!("{:x}", <sha2::Sha256 as sha2::Digest>::digest(&bytes));
    // `operation_id` is inside the canonical bytes, so byte identity at the key is identity of
    // the operation: an ambiguous write reconciles by read-back before any retry.
    store
        .publish_with_history(&key, bytes, &digest, history)
        .await
        .map_err(|error| match error {
            PublicationError::NotSent | PublicationError::Unresolved => IssueError::Unresolved,
            _ => IssueError::Refused,
        })?;
    database
        .record_grant(
            grant.identity.scope(),
            grant.identity.work().clone(),
            grant.identity.claim_fence(),
            grant.identity.plan_digest().clone(),
            authority.scope_epoch(),
            grant.deadline_unix_ms,
            now_ms,
        )
        .await
        .map_err(|error| match error {
            ApplyError::Full | ApplyError::Stopping | ApplyError::DatabaseOperationFailed => {
                IssueError::Unresolved
            }
            ApplyError::Conflict => IssueError::Refused,
        })
}

/// Reads one grant back and decides it against `expected` at `now_ms`.
///
/// Absence, malformed bytes, and every binding disagreement are permanent rejections; only
/// transport failure is retryable.
pub async fn intake(
    store: &S3Store,
    database: &DbHandle,
    expected: &ExpectedGrant,
    scope_epoch: NonZeroU64,
    now_ms: u64,
) -> GrantIntake {
    let key = scope_grant_key(
        expected.identity.scope(),
        expected.identity.work(),
        expected.identity.claim_fence(),
    );
    let bytes = match store.get_object(&key, MAX_GRANT_BYTES).await {
        Ok(GetOutcome::Found { bytes, .. }) => bytes,
        Ok(GetOutcome::NotFound) => return GrantIntake::Rejected(GrantRejection::Absent),
        Err(GetError::TooLarge) => return GrantIntake::Rejected(GrantRejection::Malformed),
        Err(_) => return GrantIntake::Unavailable,
    };
    let grant = match decode_grant(
        &bytes,
        &key,
        expected.identity.scope(),
        expected.identity.work(),
    ) {
        Ok(grant) => grant,
        Err(_) => return GrantIntake::Rejected(GrantRejection::Malformed),
    };
    if grant.identity.claim_fence() < expected.identity.claim_fence() {
        return GrantIntake::Rejected(GrantRejection::StaleFence);
    }
    if grant.identity != expected.identity
        || grant.action != expected.action
        || grant.resource_scope != expected.resource_scope
    {
        return GrantIntake::Rejected(GrantRejection::IdentityMismatch);
    }
    if grant.deadline_unix_ms.get() <= now_ms {
        return GrantIntake::Rejected(GrantRejection::Expired);
    }
    if grant.limit_units > expected.max_units
        || grant.deadline_unix_ms > expected.max_deadline_unix_ms
    {
        return GrantIntake::Rejected(GrantRejection::WiderThanRequested);
    }
    // The object alone is not authority: the projection must still resume this exact revision.
    match database
        .resumable_work(expected.identity.scope(), scope_epoch, now_ms)
        .await
    {
        Ok(resumable) if resumable.contains(expected.identity.work()) => {
            GrantIntake::Accepted(Box::new(grant))
        }
        Ok(_) => GrantIntake::Rejected(GrantRejection::Revoked),
        Err(_) => GrantIntake::Unavailable,
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireEffectGrant {
    record: String,
    campaign_id: String,
    scope_id: String,
    plan_digest: String,
    work_id: String,
    work_revision: u64,
    claim_fence: u64,
    action: String,
    resource_scope: String,
    limit_units: u64,
    deadline_unix_ms: u64,
    operation_id: String,
}

/// Encodes compact declaration-order JSON.
///
/// # Errors
///
/// Returns [`WireError`] for serialization or size-limit failures.
pub fn encode_grant(grant: &EffectGrant) -> Result<Vec<u8>, WireError> {
    let bytes = serde_json::to_vec(&WireEffectGrant {
        record: GRANT_RECORD.to_owned(),
        campaign_id: grant.identity.scope().campaign_id().as_str().to_owned(),
        scope_id: grant.identity.scope().scope_id().as_str().to_owned(),
        plan_digest: grant.identity.plan_digest().as_str().to_owned(),
        work_id: grant.identity.work().id().as_str().to_owned(),
        work_revision: grant.identity.work().revision(),
        claim_fence: grant.identity.claim_fence().get(),
        action: grant.action.clone(),
        resource_scope: grant.resource_scope.clone(),
        limit_units: grant.limit_units.get(),
        deadline_unix_ms: grant.deadline_unix_ms.get(),
        operation_id: grant.operation_id.clone(),
    })
    .map_err(|_| WireError::InvalidEncoding)?;
    if bytes.len() > MAX_GRANT_BYTES {
        return Err(WireError::LimitExceeded);
    }
    Ok(bytes)
}

/// Decodes grant bytes only when they belong to `expected_key` and name `expected_work`.
///
/// # Errors
///
/// Returns [`WireError`] for malformed, noncanonical, oversized, or mismatched input.
pub fn decode_grant(
    bytes: &[u8],
    expected_key: &str,
    expected_scope: &ScopeIdentity,
    expected_work: &WorkRef,
) -> Result<EffectGrant, WireError> {
    if bytes.is_empty() || bytes.len() > MAX_GRANT_BYTES {
        return Err(WireError::LimitExceeded);
    }
    let wire: WireEffectGrant =
        serde_json::from_slice(bytes).map_err(|_| WireError::InvalidEncoding)?;
    if serde_json::to_vec(&wire).map_err(|_| WireError::InvalidEncoding)? != bytes {
        return Err(WireError::NonCanonical);
    }
    if wire.record != GRANT_RECORD
        || wire.campaign_id != expected_scope.campaign_id().as_str()
        || wire.scope_id != expected_scope.scope_id().as_str()
        || wire.work_id != expected_work.id().as_str()
        || wire.work_revision != expected_work.revision()
    {
        return Err(WireError::InvalidValue);
    }
    let identity = ScopeClaimIdentity::new(
        expected_scope.clone(),
        Digest::new(wire.plan_digest).map_err(|_| WireError::InvalidValue)?,
        expected_work.clone(),
        wire.claim_fence,
    )
    .map_err(|_| WireError::InvalidValue)?;
    if scope_grant_key(expected_scope, expected_work, identity.claim_fence()) != expected_key {
        return Err(WireError::ReferenceMismatch);
    }
    EffectGrant::new(
        identity,
        wire.action,
        wire.resource_scope,
        wire.limit_units,
        wire.deadline_unix_ms,
        wire.operation_id,
    )
    .map_err(|_| WireError::InvalidValue)
}
