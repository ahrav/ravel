//! Scoped effect grants: bounded authority for one external operation.
//!
//! A grant is an immutable JSON object at its claim generation's grant key, published
//! create-if-absent and activated by the existing `grant_fence` projection marker. The object
//! alone grants nothing: intake accepts a grant only while the projection still continues its
//! exact work revision under its exact claim fence, so claim reclamation, terminal evidence,
//! or expiry revokes it without a revocation record.
//!
//! A grant authorizes execution only. No path here inserts work rows or writes terminal
//! evidence.
//! commentlint: allow(JUDGE)

use std::{num::NonZeroU64, time::Duration};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{
    db::{
        projections::{
            ApplyError, GrantActivation, GrantActivationProbe, ScopeProjectionEvent,
            ScopeProjectionPayload,
        },
        worker::DbHandle,
    },
    dispatch::AttemptHistory,
    distributed::scope_controller::{self, ControllerAuthority, GrantAppend, STOP_MARGIN_MS},
    domain::{
        validation::{ValidationError, bounded_stored, validate_key_segment},
        work::WorkRef,
    },
    scope::{Digest, GrantActivatedPayload, ScopeClaimIdentity, ScopeIdentity, scope_grant_key},
    storage::s3::{GetError, GetOutcome, PublicationError, S3Store},
    sync::WireError,
};

/// Bound on one grant object.
pub const MAX_GRANT_BYTES: usize = 4 * 1024;

const GRANT_RECORD: &str = "effect_grant";
/// The action a grant must name to authorize a model invocation.
///
/// A `&str` rather than an enum because the comparison is an equality against the grant's own
/// free-form action, which [`EffectGrant::new`] validates as one key segment.
pub const GRANT_ACTION_MODEL_INVOKE: &str = "model_invoke";

/// Bounded authority for one external operation under one claim generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectGrant {
    identity: ScopeClaimIdentity,
    action: String,
    resource_scope: String,
    attempt: NonZeroU64,
    limit_units: NonZeroU64,
    deadline_unix_ms: NonZeroU64,
    operation_id: String,
}

impl EffectGrant {
    /// # Errors
    ///
    /// Returns [`ValidationError`] when `action`, `resource_scope`, or `operation_id` is not one
    /// key segment, or when a numeric binding falls outside the stored-integer range.
    /// commentlint: allow(JUDGE)
    pub fn new(
        identity: ScopeClaimIdentity,
        action: String,
        resource_scope: String,
        attempt: u64,
        limit_units: u64,
        deadline_unix_ms: u64,
        operation_id: String,
    ) -> Result<Self, ValidationError> {
        validate_key_segment(&action)?;
        validate_key_segment(&resource_scope)?;
        validate_key_segment(&operation_id)?;
        let bounded = |value: u64| bounded_stored(value).ok_or(ValidationError::OutOfRange);
        bounded(identity.work().revision())?;
        bounded(identity.claim_fence().get())?;
        Ok(Self {
            identity,
            action,
            resource_scope,
            attempt: bounded(attempt)?,
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

    pub fn attempt(&self) -> NonZeroU64 {
        self.attempt
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
/// `max_units` and `max_deadline_unix_ms` reject a grant that exceeds the request's limits.
pub struct ExpectedGrant {
    identity: ScopeClaimIdentity,
    action: String,
    resource_scope: String,
    attempt: NonZeroU64,
    max_units: NonZeroU64,
    max_deadline_unix_ms: NonZeroU64,
    operation_id: String,
}

impl ExpectedGrant {
    /// # Errors
    ///
    /// Returns [`ValidationError`] when a field of the expectation itself fails
    /// [`EffectGrant::new`]'s segment or range rules; `identity` is taken as given.
    /// commentlint: allow(JUDGE)
    pub fn new(
        identity: ScopeClaimIdentity,
        action: String,
        resource_scope: String,
        attempt: u64,
        max_units: u64,
        max_deadline_unix_ms: u64,
        operation_id: String,
    ) -> Result<Self, ValidationError> {
        validate_key_segment(&action)?;
        validate_key_segment(&resource_scope)?;
        validate_key_segment(&operation_id)?;
        let bounded = |value: u64| bounded_stored(value).ok_or(ValidationError::OutOfRange);
        Ok(Self {
            identity,
            action,
            resource_scope,
            attempt: bounded(attempt)?,
            max_units: bounded(max_units)?,
            max_deadline_unix_ms: bounded(max_deadline_unix_ms)?,
            operation_id,
        })
    }
}

/// Data-free category for one refused grant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GrantRejection {
    /// No object exists at the claim generation's grant key.
    Absent,
    /// The projection continues the work under a newer claim generation than the caller's.
    StaleFence,
    /// `IdentityMismatch` covers a grant whose binding differs from the expected binding.
    IdentityMismatch,
    Expired,
    WiderThanRequested,
    /// The projection does not continue, or no longer continues, the caller's claim generation.
    Revoked,
    /// The caller's authority is stopped or the projection outran its epoch; nothing it decides
    /// under that authority stands.
    StaleAuthority,
    Malformed,
}

/// Proof that a claim and a grant were both checked against durable state.
///
/// Only [`intake`] constructs this, the way only `publish` constructs
/// [`crate::storage::artifacts::PublishedArtifact`]: the fields are private to this module, so
/// rustc refuses construction from every other module in the crate, including the transports
/// that require one. That is the whole guarantee and its whole extent — this module and its
/// children can still build one, and the crate boundary contributes nothing because every
/// caller is in-crate.
///
/// It carries the lease's stop instant as well as the grant, because either can run out first
/// and nothing at issuance bounds the grant's deadline by the lease: issuance refuses only a
/// grant already expired, while the authority that proved current ownership stops within
/// [`STOP_MARGIN_MS`] of its own term. A call bounded only by the grant could outlive the lease,
/// and a successor that legitimately took the claim could be dispatching at the same time.
#[must_use]
pub struct EffectAuthority {
    grant: EffectGrant,
    /// Instant past which the proving authority must stop, derived from its lease term.
    authority_stop_unix_ms: u64,
}

impl EffectAuthority {
    /// Decides this authority against the request it would authorize, returning how long the
    /// call may run.
    ///
    /// The bound is the shorter of the grant's deadline and the proving lease's stop instant.
    /// Both are retested here rather than trusted from intake, because intake decided at its own
    /// `now_ms` and either term can elapse before a call is dispatched.
    ///
    /// The request is the argument rather than an action and a scope, because the only source
    /// for those would be the caller handing the authority its own values back.
    ///
    /// # Errors
    ///
    /// Returns [`GrantRejection::IdentityMismatch`] when the grant does not name a model
    /// invocation of this request's profile and operation, [`GrantRejection::Expired`] for a
    /// grant past its deadline, and [`GrantRejection::StaleAuthority`] when the proving lease
    /// has stopped.
    pub fn authorizes_model(
        &self,
        request: &crate::provider::InvocationRequest,
        now_ms: u64,
    ) -> Result<Duration, GrantRejection> {
        // The operation identity is what makes this authority specific to one call. Without it
        // a grant issued for one operation would authorize any request against the same
        // profile, so the same operation could be paid for twice under one grant with nothing
        // able to tell the second dispatch from the first. `intake` pins the grant's own
        // operation id against the caller's expectation; this pins it against the request
        // actually being sent.
        //
        // `limit_units` is deliberately not compared against the output-token cap. The grant's
        // units have no denomination anywhere in this crate, so treating them as tokens would
        // invent a contract rather than enforce one.
        if self.grant.action != GRANT_ACTION_MODEL_INVOKE
            || self.grant.resource_scope != request.profile().configuration_digest()
            || self.grant.operation_id != request.operation_id()
        {
            return Err(GrantRejection::IdentityMismatch);
        }
        if self.authority_stop_unix_ms <= now_ms {
            return Err(GrantRejection::StaleAuthority);
        }
        let deadline = self.grant.deadline_unix_ms.get();
        if deadline <= now_ms {
            return Err(GrantRejection::Expired);
        }
        Ok(Duration::from_millis(
            deadline.min(self.authority_stop_unix_ms) - now_ms,
        ))
    }
}

/// Mints an [`EffectAuthority`] without an object store or a projection.
///
/// The fields are private to this module, so a test elsewhere cannot assemble one. This is the
/// only mint path outside [`intake`].
#[cfg(test)]
pub(crate) mod test_support {
    use super::{Digest, EffectAuthority, EffectGrant, ScopeClaimIdentity, ScopeIdentity, WorkRef};
    use crate::{distributed::identity::WorkspaceId, domain::work::WorkId, scope::CampaignId};

    /// An authority for `action` over `resource_scope`, under `operation_id`.
    ///
    /// `resource_scope` is a profile's configuration digest and `operation_id` is the request's,
    /// because those are what the effect boundary compares against. `action` is a parameter so a
    /// refusal case can name an action the boundary does not accept without rebuilding a grant
    /// field by field.
    pub(crate) fn model_authority(
        action: String,
        resource_scope: String,
        operation_id: String,
        deadline_unix_ms: u64,
        authority_stop_unix_ms: u64,
    ) -> EffectAuthority {
        let identity = ScopeClaimIdentity::new(
            ScopeIdentity::root(
                WorkspaceId::new("workspace-a".into()).unwrap(),
                CampaignId::new("campaign-a".into()).unwrap(),
            )
            .unwrap(),
            Digest::new("11".repeat(32)).unwrap(),
            WorkRef::new(WorkId::new("work-a".into()).unwrap(), 1),
            2,
        )
        .unwrap();
        EffectAuthority {
            grant: EffectGrant::new(
                identity,
                action,
                resource_scope,
                1,
                1_000,
                deadline_unix_ms,
                operation_id,
            )
            .unwrap(),
            authority_stop_unix_ms,
        }
    }
}

/// Outcome of reading one grant back for use.
#[must_use]
pub enum GrantIntake {
    Accepted(Box<EffectAuthority>),
    Rejected(GrantRejection),
    /// Storage or projection transport failed; retry may succeed.
    Unavailable,
}

/// Data-free category for one refused issuance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IssueError {
    /// The authority must stop, is from another scope, or holds no or another active plan.
    NotAuthorized,
    /// The grant is already expired at issuance time.
    Expired,
    /// The local projection lags the authority's observed head; refresh, then retry.
    ProjectionBehind,
    /// The outcome is unproven; the identical retry is safe.
    Unresolved,
    /// A rival object occupies this claim generation's key, or the projection refused the
    /// binding; any published object stays inert until its binding is current again.
    Refused,
}

/// Outcome of one issuance attempt under consumed authority.
#[must_use]
pub enum IssueOutcome {
    /// The activation event committed and folded; the authority observed the committed head.
    Issued(ControllerAuthority),
    /// Refused before any event was appended; a published object stays inert and the authority
    /// remains usable.
    Refused {
        error: IssueError,
        authority: ControllerAuthority,
    },
    /// The event committed durably but the synchronous fold is not proven committed under the
    /// observed head: the projection may lag it, be past it, or the response was lost. The
    /// caller refreshes the projection, and the catch-up precondition blocks further issuance
    /// until then.
    CommittedProjectionBehind(ControllerAuthority),
    /// The authority was consumed without a proven issuance; the caller reacquires, refreshes,
    /// and retries, and the operation-id probe keeps the retry from appending a duplicate.
    Spent(IssueError),
}

/// Publishes one grant, appends its durable activation event, and folds it locally.
///
/// The flow is: catch-up check, activation probe, guards dry-run, immutable object publish, event
/// append under the consumed authority, then a synchronous local apply of the same committed
/// event. A validation refusal appends nothing and leaves any published object inert. A crash
/// between publish and append leaves an inert object at a burned fence key; the identical retry
/// reconciles the create-if-absent publish on identical bytes, and its probe reports the
/// activation before any guard whose state moves between attempts.
pub async fn issue(
    store: &S3Store,
    database: &DbHandle,
    authority: ControllerAuthority,
    grant: &EffectGrant,
    histories: [&mut AttemptHistory; 3],
    now_ms: u64,
) -> IssueOutcome {
    let [object_history, event_history, head_history] = histories;
    let refused = |error, authority| IssueOutcome::Refused { error, authority };
    if authority.must_stop(now_ms)
        || authority.namespace() != store.namespace()
        || authority.head().scope() != grant.identity.scope()
        || authority.head().active_plan_digest() != Some(grant.identity.plan_digest())
    {
        return refused(IssueError::NotAuthorized, authority);
    }
    if grant.deadline_unix_ms.get() <= now_ms {
        return refused(IssueError::Expired, authority);
    }
    // Every step shares one deadline `STOP_MARGIN_MS` short of term expiry, and the accounting
    // starts here so a queued projection read cannot spend term the later steps still assume.
    // `elapsed_ms` advances `now_ms` by time spent since `started`.
    let started = tokio::time::Instant::now();
    let deadline = started
        + Duration::from_millis(
            authority
                .remaining_term_ms(now_ms)
                .saturating_sub(STOP_MARGIN_MS),
        );
    // The probe and the dry-run read the local projection, which may lag the durable log after
    // a crash between append and apply; issuing over that lag would re-append a committed
    // operation, so a projection behind the observed head refuses until the caller refreshes.
    match tokio::time::timeout_at(deadline, database.scope_matches_head(authority.head())).await {
        Err(_) => return refused(IssueError::Unresolved, authority),
        Ok(Ok(true)) => {}
        Ok(Ok(false)) => return refused(IssueError::ProjectionBehind, authority),
        Ok(Err(_)) => return refused(IssueError::Unresolved, authority),
    }
    let scope = grant.identity.scope().clone();
    let activation = |digest: Digest| GrantActivation {
        scope_epoch: authority.scope_epoch(),
        attempt: grant.attempt,
        units: grant.limit_units,
        deadline_unix_ms: grant.deadline_unix_ms,
        digest,
    };
    let bytes = match encode_grant(grant) {
        Ok(bytes) => bytes,
        Err(_) => return refused(IssueError::Refused, authority),
    };
    let key = scope_grant_key(&scope, grant.identity.work(), grant.identity.claim_fence());
    let digest = format!("{:x}", Sha256::digest(&bytes));
    let Ok(grant_digest) = Digest::new(digest.clone()) else {
        return refused(IssueError::Refused, authority);
    };
    // The probe runs before the dry-run because an activation this grant already committed is a
    // fact, while the lease and budget the dry-run reads can move between attempts.
    match tokio::time::timeout_at(
        deadline,
        database.grant_activation_probe(&scope, grant.operation_id(), &grant_digest),
    )
    .await
    {
        Err(_) => return refused(IssueError::Unresolved, authority),
        Ok(Ok(GrantActivationProbe::Activated)) => return IssueOutcome::Issued(authority),
        Ok(Ok(GrantActivationProbe::ForeignOperation)) => {
            return refused(IssueError::Refused, authority);
        }
        Ok(Ok(GrantActivationProbe::Absent)) => {}
        Ok(Err(_)) => return refused(IssueError::Unresolved, authority),
    }
    // Guards run before the object exists, so a refused issuance publishes nothing.
    match tokio::time::timeout_at(
        deadline,
        database.grant_admissible(
            &grant.identity,
            activation(grant_digest.clone()),
            now_ms.saturating_add(elapsed_ms(started)),
        ),
    )
    .await
    {
        Err(_) => return refused(IssueError::Unresolved, authority),
        Ok(Ok(())) => {}
        Ok(Err(ApplyError::Conflict)) => return refused(IssueError::Refused, authority),
        Ok(Err(_)) => return refused(IssueError::Unresolved, authority),
    }
    // `operation_id` is inside the canonical bytes, so byte identity at the key is identity of
    // the operation: an ambiguous write reconciles by read-back before any retry.
    match tokio::time::timeout_at(
        deadline,
        store.publish_with_history(&key, bytes, &digest, object_history),
    )
    .await
    {
        Err(_) => return refused(IssueError::Unresolved, authority),
        Ok(Ok(())) => {}
        Ok(Err(
            PublicationError::NotSent
            | PublicationError::Unresolved
            | PublicationError::StorageNotFound,
        )) => return refused(IssueError::Unresolved, authority),
        Ok(Err(_)) => return refused(IssueError::Refused, authority),
    }
    let payload = match GrantActivatedPayload::new(
        grant.identity.work().id().clone(),
        grant.identity.work().revision(),
        grant.identity.claim_fence().get(),
        grant_digest,
        grant.attempt.get(),
        grant.limit_units.get(),
        grant.deadline_unix_ms.get(),
    ) {
        Ok(payload) => payload,
        Err(_) => return refused(IssueError::Refused, authority),
    };
    let append = match tokio::time::timeout_at(
        deadline,
        scope_controller::append_grant_activated(
            store,
            authority,
            &payload,
            grant.operation_id(),
            event_history,
            head_history,
            now_ms.saturating_add(elapsed_ms(started)),
        ),
    )
    .await
    {
        Err(_) => return IssueOutcome::Spent(IssueError::Unresolved),
        Ok(append) => append,
    };
    let (authority, envelope, reference) = match append {
        GrantAppend::Committed {
            authority,
            envelope,
            reference,
        } => (*authority, envelope, reference),
        GrantAppend::Stopped | GrantAppend::Superseded => {
            return IssueOutcome::Spent(IssueError::NotAuthorized);
        }
        GrantAppend::Unresolved => return IssueOutcome::Spent(IssueError::Unresolved),
    };
    // The fold, cursor advance, and post-append head verification commit together. A head
    // mismatch reports CommittedProjectionBehind for the durably committed grant; the next
    // refresh folds it. A bare grant UPDATE could fold the event twice.
    let scope_epoch = envelope.writer_epoch().get();
    let Ok(mutation) = ScopeProjectionEvent::new(
        scope,
        envelope,
        reference,
        ScopeProjectionPayload::GrantActivated { payload },
        scope_epoch,
    ) else {
        return IssueOutcome::CommittedProjectionBehind(authority);
    };
    match tokio::time::timeout_at(
        deadline,
        database.apply_suffix(vec![mutation], authority.head()),
    )
    .await
    {
        Ok(Ok(())) => IssueOutcome::Issued(authority),
        Ok(Err(_)) | Err(_) => IssueOutcome::CommittedProjectionBehind(authority),
    }
}

/// Returns `u64::MAX` when elapsed milliseconds exceed `u64::MAX`.
fn elapsed_ms(started: tokio::time::Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// Reads one grant back and decides it against `expected` at `now_ms`.
///
/// Absence, malformed bytes, and every binding disagreement are permanent rejections.
/// [`GrantRejection::Revoked`] also covers a grant not yet activated by [`issue`], so a caller
/// may retry after activation; transport failure is retryable as [`GrantIntake::Unavailable`].
///
/// `authority` caps which admissions count as current: a stopped authority is refused before
/// any read, and a projection ahead of its epoch rejects rather than answering emptily.
pub async fn intake(
    store: &S3Store,
    database: &DbHandle,
    expected: &ExpectedGrant,
    authority: &ControllerAuthority,
    now_ms: u64,
) -> GrantIntake {
    // An authority acquired against another object store cannot authorize this one.
    if authority.must_stop(now_ms) || authority.namespace() != store.namespace() {
        return GrantIntake::Rejected(GrantRejection::StaleAuthority);
    }
    let started = tokio::time::Instant::now();
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
    if grant.identity != expected.identity
        || grant.action != expected.action
        || grant.resource_scope != expected.resource_scope
        || grant.attempt != expected.attempt
        || grant.operation_id != expected.operation_id
    {
        return GrantIntake::Rejected(GrantRejection::IdentityMismatch);
    }
    // `elapsed_ms(started)` advances each deadline check past preceding awaits.
    if grant.deadline_unix_ms.get() <= now_ms.saturating_add(elapsed_ms(started)) {
        return GrantIntake::Rejected(GrantRejection::Expired);
    }
    if grant.limit_units > expected.max_units
        || grant.deadline_unix_ms > expected.max_deadline_unix_ms
    {
        return GrantIntake::Rejected(GrantRejection::WiderThanRequested);
    }
    // A grant object alone is not authority: the continuable-work record authorizes only the grant
    // whose SHA-256 digest it stores.
    match database
        .continuable_work(
            expected.identity.scope(),
            authority,
            now_ms.saturating_add(elapsed_ms(started)),
        )
        .await
    {
        Ok(continuable) => {
            let accepted_at_ms = now_ms.saturating_add(elapsed_ms(started));
            // The queued query answered against the timestamp it was given; the term can have
            // crossed its stop margin while it waited.
            if authority.must_stop(accepted_at_ms) {
                return GrantIntake::Rejected(GrantRejection::StaleAuthority);
            }
            if grant.deadline_unix_ms.get() <= accepted_at_ms {
                return GrantIntake::Rejected(GrantRejection::Expired);
            }
            match continuable
                .iter()
                .find(|row| row.work() == expected.identity.work())
            {
                // The query filtered leases against the time it was given, so the row's own lease
                // is retested against the clock after it returned.
                Some(row) if row.claim_lease_until().get() <= accepted_at_ms => {
                    GrantIntake::Rejected(GrantRejection::Revoked)
                }
                Some(row) if row.claim_fence() == expected.identity.claim_fence() => {
                    if row.grant_digest().as_str() == format!("{:x}", Sha256::digest(&bytes)) {
                        GrantIntake::Accepted(Box::new(EffectAuthority {
                            grant,
                            authority_stop_unix_ms: authority
                                .lease_until()
                                .get()
                                .saturating_sub(STOP_MARGIN_MS),
                        }))
                    } else {
                        GrantIntake::Rejected(GrantRejection::IdentityMismatch)
                    }
                }
                Some(row) if row.claim_fence() > expected.identity.claim_fence() => {
                    GrantIntake::Rejected(GrantRejection::StaleFence)
                }
                _ => GrantIntake::Rejected(GrantRejection::Revoked),
            }
        }
        Err(ApplyError::StaleAuthority) => GrantIntake::Rejected(GrantRejection::StaleAuthority),
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
    attempt: u64,
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
        attempt: grant.attempt.get(),
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
pub(crate) fn decode_grant(
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
        wire.attempt,
        wire.limit_units,
        wire.deadline_unix_ms,
        wire.operation_id,
    )
    .map_err(|_| WireError::InvalidValue)
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU64;

    use crate::domain::validation::MAX_STORED_INTEGER;

    use aws_sdk_s3::primitives::SdkBody;

    use crate::{
        distributed::{
            identity::{InstanceId, WorkspaceId},
            scope_controller::{AcquireOutcome, acquire},
        },
        domain::work::WorkId,
        scope::{
            AdmittedCampaignConfig, CampaignId, RootGenesis, ScopeAuthority, ScopeHead,
            encode_head, root_genesis,
        },
        storage::s3::test_support::{replay_store, response},
        sync::WireError,
    };

    use super::*;

    const NOW_MS: u64 = 1_700_000_000_000;

    fn genesis() -> RootGenesis {
        root_genesis(
            &AdmittedCampaignConfig::new(
                WorkspaceId::new("workspace-a".into()).unwrap(),
                CampaignId::new("campaign-a".into()).unwrap(),
                b"admitted".to_vec(),
            )
            .unwrap(),
        )
        .unwrap()
    }

    fn seed_objective() -> Digest {
        Digest::new("11".repeat(32)).unwrap()
    }

    fn seed_proposal() -> crate::domain::proposal::PlanProposal {
        use crate::domain::proposal::{PlanProposal, ProposalBasis, TargetBounds, WorkSpec};
        PlanProposal::new(
            genesis().identity().scope_id().clone(),
            seed_objective(),
            None,
            vec![ProposalBasis::Observation {
                event: crate::scope::ScopeEventRef::new(1, seed_objective()).unwrap(),
            }],
            vec![WorkSpec::new(
                WorkId::new("work-17".into()).unwrap(),
                Vec::new(),
                TargetBounds::new(3, NOW_MS + 600_000).unwrap(),
            )],
            100,
        )
    }

    /// `plan` returns the digest [`seed_proposal`] admits under.
    fn plan() -> Digest {
        use crate::domain::proposal::{ObservationFact, ProposalFacts, validate_proposal};
        let scope = genesis().identity().clone();
        let objective = seed_objective();
        let facts = [ObservationFact::new(
            scope.scope_id().clone(),
            crate::scope::ScopeEventRef::new(1, objective.clone()).unwrap(),
            crate::scope::ROOT_GENESIS_PAYLOAD_TYPE.to_owned(),
        )];
        validate_proposal(
            &seed_proposal(),
            &ProposalFacts::new(&scope, &objective, None, 1, &facts),
        )
        .unwrap()
        .plan_digest()
        .clone()
    }

    fn identity(fence: u64) -> ScopeClaimIdentity {
        ScopeClaimIdentity::new(
            genesis().identity().clone(),
            plan(),
            WorkRef::new(WorkId::new("work-17".into()).unwrap(), 1),
            fence,
        )
        .unwrap()
    }

    fn fixture(fence: u64, units: u64, deadline: u64) -> EffectGrant {
        EffectGrant::new(
            identity(fence),
            "git-push".into(),
            "repo-a".into(),
            1,
            units,
            deadline,
            "grant-op-1".into(),
        )
        .unwrap()
    }

    fn expected(fence: u64, max_units: u64, max_deadline: u64) -> ExpectedGrant {
        ExpectedGrant::new(
            identity(fence),
            "git-push".into(),
            "repo-a".into(),
            1,
            max_units,
            max_deadline,
            "grant-op-1".into(),
        )
        .unwrap()
    }

    /// The returned store retains replay responses after `acquire` consumes its head read and
    /// conditional write.
    async fn authority_with_plan(
        plan: Option<Digest>,
        then: Vec<http::Response<SdkBody>>,
    ) -> (
        crate::distributed::scope_controller::ControllerAuthority,
        S3Store,
        aws_smithy_runtime::client::http::test_util::StaticReplayClient,
    ) {
        let genesis = genesis();
        let head = ScopeHead::new(
            genesis.identity().clone(),
            ScopeAuthority::Unowned,
            1,
            genesis.event_ref().clone(),
            plan,
            "op-authority".into(),
        )
        .unwrap();
        authority_from_head(head, then, NOW_MS).await
    }

    async fn seeded_authority(
        then: Vec<http::Response<SdkBody>>,
        now_ms: u64,
    ) -> (
        crate::distributed::scope_controller::ControllerAuthority,
        S3Store,
        aws_smithy_runtime::client::http::test_util::StaticReplayClient,
    ) {
        let head = ScopeHead::new(
            genesis().identity().clone(),
            ScopeAuthority::Unowned,
            1,
            crate::scope::ScopeEventRef::new(2, Digest::new("22".repeat(32)).unwrap()).unwrap(),
            Some(plan()),
            "admit-plan".into(),
        )
        .unwrap();
        authority_from_head(head, then, now_ms).await
    }

    async fn authority_from_head(
        head: ScopeHead,
        then: Vec<http::Response<SdkBody>>,
        now_ms: u64,
    ) -> (
        crate::distributed::scope_controller::ControllerAuthority,
        S3Store,
        aws_smithy_runtime::client::http::test_util::StaticReplayClient,
    ) {
        let mut responses = vec![
            response(200, &[("etag", "\"head\"")], encode_head(&head).unwrap()),
            response(200, &[("etag", "\"next\"")], SdkBody::empty()),
        ];
        responses.extend(then);
        let (store, client) = replay_store(responses);
        let outcome = acquire(
            &store,
            genesis().identity(),
            &InstanceId::new("instance-a".into()).unwrap(),
            now_ms,
        )
        .await
        .unwrap();
        let AcquireOutcome::Acquired(authority) = outcome else {
            panic!("expected acquisition");
        };
        (authority, store, client)
    }

    fn histories() -> [AttemptHistory; 3] {
        [
            AttemptHistory::default(),
            AttemptHistory::default(),
            AttemptHistory::default(),
        ]
    }

    async fn database(label: &str) -> (std::path::PathBuf, DbHandle) {
        let path = std::env::temp_dir().join(format!(
            "ravel-grants-{}-{label}.sqlite3",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        (path.clone(), DbHandle::spawn(path).await.unwrap())
    }

    async fn seeded_database_at_epoch(
        label: &str,
        scope_epoch: u64,
    ) -> (std::path::PathBuf, DbHandle) {
        use crate::db::projections::{self, ScopeProjectionEvent, ScopeProjectionPayload};
        use crate::scope::{EventEnvelope, ScopeEventRef};
        let path = std::env::temp_dir().join(format!(
            "ravel-grants-{}-{label}.sqlite3",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let scope = genesis().identity().clone();
        let target = WorkRef::new(WorkId::new("work-17".into()).unwrap(), 1);
        {
            let mut connection = projections::create(&path).unwrap();
            let digest = seed_objective();
            let envelope = EventEnvelope::new(
                scope.scope_id().clone(),
                1,
                None,
                1,
                format!("root-genesis:{}", scope.scope_id().as_str()),
                "root_genesis".into(),
            )
            .unwrap();
            let event = ScopeProjectionEvent::new(
                scope.clone(),
                envelope,
                ScopeEventRef::new(1, digest.clone()).unwrap(),
                ScopeProjectionPayload::RootGenesis {
                    objective_digest: digest,
                },
                scope_epoch,
            )
            .unwrap();
            projections::apply_scope_event(&mut connection, &event).unwrap();

            let admission = ScopeProjectionEvent::new(
                scope.clone(),
                EventEnvelope::new(
                    scope.scope_id().clone(),
                    2,
                    Some(ScopeEventRef::new(1, seed_objective()).unwrap()),
                    1,
                    "admit-plan".into(),
                    crate::scope::PLAN_ADMITTED_PAYLOAD_TYPE.into(),
                )
                .unwrap(),
                ScopeEventRef::new(2, Digest::new("22".repeat(32)).unwrap()).unwrap(),
                ScopeProjectionPayload::PlanAdmitted {
                    plan_digest: plan(),
                    proposal: Box::new(seed_proposal()),
                },
                scope_epoch,
            )
            .unwrap();
            projections::apply_scope_event(&mut connection, &admission).unwrap();
            projections::record_claim(
                &connection,
                &scope,
                &target,
                NonZeroU64::new(2).unwrap(),
                NonZeroU64::new(NOW_MS + 30_000).unwrap(),
                NOW_MS,
            )
            .unwrap();
        }
        (path.clone(), DbHandle::open_existing(path).await.unwrap())
    }

    #[test]
    fn grant_bytes_round_trip_and_reject_every_corruption() {
        let grant = fixture(2, 5, NOW_MS + 60_000);
        let bytes = encode_grant(&grant).unwrap();
        let scope = genesis().identity().clone();
        let work = WorkRef::new(WorkId::new("work-17".into()).unwrap(), 1);
        let key = scope_grant_key(&scope, &work, NonZeroU64::new(2).unwrap());

        assert_eq!(decode_grant(&bytes, &key, &scope, &work).unwrap(), grant);
        assert_eq!(
            decode_grant(&[], &key, &scope, &work),
            Err(WireError::LimitExceeded)
        );
        assert_eq!(
            decode_grant(&vec![b'x'; MAX_GRANT_BYTES + 1], &key, &scope, &work),
            Err(WireError::LimitExceeded)
        );
        assert_eq!(
            decode_grant(b"not-json", &key, &scope, &work),
            Err(WireError::InvalidEncoding)
        );
        // An unknown field is not part of the record.
        let mut extra = bytes.clone();
        extra.truncate(extra.len() - 1);
        extra.extend_from_slice(b",\"extra\":1}");
        assert_eq!(
            decode_grant(&extra, &key, &scope, &work),
            Err(WireError::InvalidEncoding)
        );
        // Padded bytes decode but are not canonical.
        let mut padded = bytes.clone();
        padded.push(b' ');
        assert_eq!(
            decode_grant(&padded, &key, &scope, &work),
            Err(WireError::NonCanonical)
        );
        // The record must live at exactly its claim generation's key.
        let wrong_key = scope_grant_key(&scope, &work, NonZeroU64::new(9).unwrap());
        assert_eq!(
            decode_grant(&bytes, &wrong_key, &scope, &work),
            Err(WireError::ReferenceMismatch)
        );
        let other_work = WorkRef::new(WorkId::new("work-99".into()).unwrap(), 1);
        assert_eq!(
            decode_grant(&bytes, &key, &scope, &other_work),
            Err(WireError::InvalidValue)
        );
        for (units, deadline) in [(0, 1), (1, 0)] {
            assert!(
                EffectGrant::new(
                    identity(2),
                    "a".into(),
                    "r".into(),
                    1,
                    units,
                    deadline,
                    "op".into()
                )
                .is_err()
            );
        }
    }

    #[tokio::test]
    async fn intake_decides_every_rejection_before_granting_authority() {
        let (db_path, handle) = database("intake").await;
        let grant_bytes = |grant: &EffectGrant| encode_grant(grant).unwrap();
        let found = |bytes: Vec<u8>| response(200, &[("etag", "\"grant\"")], bytes);
        // Each intake consumes one GET from the store used to acquire its authority.
        let (authority, store, _) = authority_with_plan(
            Some(plan()),
            vec![
                response(404, &[], SdkBody::empty()),
                found(grant_bytes(&fixture(2, 5, NOW_MS + 60_000))),
                found(grant_bytes(&fixture(2, 6, NOW_MS + 60_000))),
                found(grant_bytes(&fixture(2, 5, NOW_MS + 90_000))),
                found(grant_bytes(&fixture(2, 5, NOW_MS + 60_000))),
                found(grant_bytes(&fixture(2, 5, NOW_MS + 60_000))),
                found(grant_bytes(&fixture(2, 5, NOW_MS + 60_000))),
                found(grant_bytes(&fixture(2, 5, NOW_MS + 60_000))),
                found(grant_bytes(&fixture(2, 5, NOW_MS + 60_000))),
                response(500, &[], SdkBody::empty()),
            ],
        )
        .await;
        let epoch = &authority;

        // Absent object.
        assert!(matches!(
            intake(
                &store,
                &handle,
                &expected(2, 5, NOW_MS + 60_000),
                epoch,
                NOW_MS
            )
            .await,
            GrantIntake::Rejected(GrantRejection::Absent)
        ));
        // A key naming a fence the object does not carry cannot decode.
        assert!(matches!(
            intake(
                &store,
                &handle,
                &expected(3, 5, NOW_MS + 60_000),
                epoch,
                NOW_MS
            )
            .await,
            GrantIntake::Rejected(GrantRejection::Malformed)
        ));
        // Expired, judged under an authority whose own term covers the late clock.
        let late_head = ScopeHead::new(
            genesis().identity().clone(),
            ScopeAuthority::Unowned,
            1,
            genesis().event_ref().clone(),
            Some(plan()),
            "op-authority".into(),
        )
        .unwrap();
        let (late, late_store, _) = authority_from_head(
            late_head,
            vec![found(grant_bytes(&fixture(2, 5, NOW_MS + 60_000)))],
            NOW_MS + 60_000,
        )
        .await;
        assert!(matches!(
            intake(
                &late_store,
                &handle,
                &expected(2, 5, NOW_MS + 60_000),
                &late,
                NOW_MS + 60_000
            )
            .await,
            GrantIntake::Rejected(GrantRejection::Expired)
        ));
        // Wider than requested, on units and on deadline.
        assert!(matches!(
            intake(
                &store,
                &handle,
                &expected(2, 5, NOW_MS + 60_000),
                epoch,
                NOW_MS
            )
            .await,
            GrantIntake::Rejected(GrantRejection::WiderThanRequested)
        ));
        assert!(matches!(
            intake(
                &store,
                &handle,
                &expected(2, 5, NOW_MS + 60_000),
                epoch,
                NOW_MS
            )
            .await,
            GrantIntake::Rejected(GrantRejection::WiderThanRequested)
        ));
        // A plan the caller does not expect is an identity disagreement.
        let other_plan = ExpectedGrant::new(
            ScopeClaimIdentity::new(
                genesis().identity().clone(),
                Digest::new("cd".repeat(32)).unwrap(),
                WorkRef::new(WorkId::new("work-17".into()).unwrap(), 1),
                2,
            )
            .unwrap(),
            "git-push".into(),
            "repo-a".into(),
            1,
            5,
            NOW_MS + 60_000,
            "grant-op-1".into(),
        )
        .unwrap();
        assert!(matches!(
            intake(&store, &handle, &other_plan, epoch, NOW_MS).await,
            GrantIntake::Rejected(GrantRejection::IdentityMismatch)
        ));
        // Action mismatch is an identity disagreement.
        let other_action = ExpectedGrant::new(
            identity(2),
            "git-fetch".into(),
            "repo-a".into(),
            1,
            5,
            NOW_MS + 60_000,
            "grant-op-1".into(),
        )
        .unwrap();
        assert!(matches!(
            intake(&store, &handle, &other_action, epoch, NOW_MS).await,
            GrantIntake::Rejected(GrantRejection::IdentityMismatch)
        ));
        // A grant minted for another attempt cannot stand in for this one.
        let other_attempt = ExpectedGrant::new(
            identity(2),
            "git-push".into(),
            "repo-a".into(),
            2,
            5,
            NOW_MS + 60_000,
            "grant-op-1".into(),
        )
        .unwrap();
        assert!(matches!(
            intake(&store, &handle, &other_attempt, epoch, NOW_MS).await,
            GrantIntake::Rejected(GrantRejection::IdentityMismatch)
        ));
        // A grant minted for another operation cannot stand in for this one.
        let other_operation = ExpectedGrant::new(
            identity(2),
            "git-push".into(),
            "repo-a".into(),
            1,
            5,
            NOW_MS + 60_000,
            "grant-op-2".into(),
        )
        .unwrap();
        assert!(matches!(
            intake(&store, &handle, &other_operation, epoch, NOW_MS).await,
            GrantIntake::Rejected(GrantRejection::IdentityMismatch)
        ));
        // Valid bytes, but the projection continues nothing: the object alone is not authority.
        assert!(matches!(
            intake(
                &store,
                &handle,
                &expected(2, 5, NOW_MS + 60_000),
                epoch,
                NOW_MS
            )
            .await,
            GrantIntake::Rejected(GrantRejection::Revoked)
        ));
        // Transport failure stays retryable.
        assert!(matches!(
            intake(
                &store,
                &handle,
                &expected(2, 5, NOW_MS + 60_000),
                epoch,
                NOW_MS
            )
            .await,
            GrantIntake::Unavailable
        ));

        handle.drain().await.unwrap();
        drop(handle);
        let _ = std::fs::remove_file(db_path);
    }

    async fn issue_once(
        store: &S3Store,
        handle: &DbHandle,
        authority: ControllerAuthority,
        grant: &EffectGrant,
        now_ms: u64,
    ) -> IssueOutcome {
        let [mut object, mut event, mut head] = histories();
        issue(
            store,
            handle,
            authority,
            grant,
            [&mut object, &mut event, &mut head],
            now_ms,
        )
        .await
    }

    fn refusal(outcome: IssueOutcome) -> (IssueError, ControllerAuthority) {
        match outcome {
            IssueOutcome::Refused { error, authority } => (error, authority),
            _ => panic!("expected a refusal"),
        }
    }

    fn issued(outcome: IssueOutcome) -> ControllerAuthority {
        match outcome {
            IssueOutcome::Issued(authority) => authority,
            _ => panic!("expected an issuance"),
        }
    }

    #[tokio::test]
    async fn issuance_requires_live_authority_over_the_admitted_plan() {
        let (db_path, handle) = database("issue").await;
        let grant = fixture(2, 5, NOW_MS + 60_000);

        // No active plan on the head.
        let (authority, store, client) = authority_with_plan(None, vec![]).await;
        assert_eq!(
            refusal(issue_once(&store, &handle, authority, &grant, NOW_MS).await).0,
            IssueError::NotAuthorized
        );
        assert_eq!(client.actual_requests().count(), 2);
        // Another plan is active.
        let (authority, store, _) =
            authority_with_plan(Some(Digest::new("cd".repeat(32)).unwrap()), vec![]).await;
        assert_eq!(
            refusal(issue_once(&store, &handle, authority, &grant, NOW_MS).await).0,
            IssueError::NotAuthorized
        );
        // Ownership proved in one store proves nothing in another.
        let (authority, _, _) = authority_with_plan(Some(plan()), vec![]).await;
        let (foreign_store, foreign_client) = replay_store(vec![]);
        assert_eq!(
            refusal(issue_once(&foreign_store, &handle, authority, &grant, NOW_MS).await).0,
            IssueError::NotAuthorized
        );
        assert_eq!(foreign_client.actual_requests().count(), 0);
        // The right plan and a live lease, but the grant deadline has already passed.
        let (authority, store, _) = authority_with_plan(Some(plan()), vec![]).await;
        let short = fixture(2, 5, NOW_MS + 10_000);
        assert_eq!(
            refusal(issue_once(&store, &handle, authority, &short, NOW_MS + 10_000).await).0,
            IssueError::Expired
        );
        // An empty projection lags the observed head, so issuance waits for a refresh instead
        // of probing state that cannot answer for the durable log.
        let (authority, store, client) = authority_with_plan(Some(plan()), vec![]).await;
        assert_eq!(
            refusal(issue_once(&store, &handle, authority, &grant, NOW_MS).await).0,
            IssueError::ProjectionBehind
        );
        assert_eq!(client.actual_requests().count(), 2);

        handle.drain().await.unwrap();
        drop(handle);
        let _ = std::fs::remove_file(db_path);
    }

    #[test]
    fn grant_bounds_reject_values_beyond_stored_range() {
        let max = MAX_STORED_INTEGER;
        let work_ref = |revision| WorkRef::new(WorkId::new("work-17".into()).unwrap(), revision);
        let claim = |revision, fence| {
            ScopeClaimIdentity::new(
                genesis().identity().clone(),
                plan(),
                work_ref(revision),
                fence,
            )
            .unwrap()
        };
        let grant = |identity, units, deadline| {
            EffectGrant::new(
                identity,
                "git-push".into(),
                "repo-a".into(),
                1,
                units,
                deadline,
                "grant-op-1".into(),
            )
        };

        assert!(grant(claim(max, max), max, max).is_ok());
        assert_eq!(
            grant(claim(max + 1, 2), 5, max),
            Err(ValidationError::OutOfRange)
        );
        assert_eq!(
            grant(claim(1, max + 1), 5, max),
            Err(ValidationError::OutOfRange)
        );
        assert_eq!(
            grant(claim(1, 2), max + 1, max),
            Err(ValidationError::OutOfRange)
        );
        assert_eq!(
            grant(claim(1, 2), 5, max + 1),
            Err(ValidationError::OutOfRange)
        );
    }

    #[tokio::test]
    async fn issuance_reconciles_ambiguity_by_operation_identity() {
        use crate::scope::{decode_head, scope_head_key};

        let grant = fixture(2, 5, NOW_MS + 60_000);
        let bytes = encode_grant(&grant).unwrap();

        // A plain create publishes the object, appends the event, and folds it locally.
        let (db_path, handle) = seeded_database_at_epoch("issue-ok", 1).await;
        let (authority, store, client) = seeded_authority(
            vec![
                response(200, &[], SdkBody::empty()),
                response(200, &[], SdkBody::empty()),
                response(200, &[("etag", "\"appended\"")], SdkBody::empty()),
                response(200, &[("etag", "\"renewed\"")], SdkBody::empty()),
            ],
            NOW_MS,
        )
        .await;
        let authority = issued(issue_once(&store, &handle, authority, &grant, NOW_MS).await);
        assert_eq!(client.actual_requests().count(), 5);
        assert_eq!(authority.head().tail().sequence(), 3);
        // The retry probe recognizes the committed activation before any object-store request.
        let authority = issued(issue_once(&store, &handle, authority, &grant, NOW_MS).await);
        assert_eq!(client.actual_requests().count(), 5);
        // The refreshed authority still renews: its retained observation is the committed head.
        let outcome = crate::distributed::scope_controller::renew(&store, authority, NOW_MS + 100)
            .await
            .unwrap();
        let crate::distributed::scope_controller::RenewOutcome::Renewed(renewed) = outcome else {
            panic!("expected renewal");
        };
        assert_eq!(renewed.scope_epoch().get(), 3);
        let requests = client.actual_requests().collect::<Vec<_>>();
        assert_eq!(
            requests[5].headers().get("if-match").unwrap(),
            "\"appended\""
        );
        let renewed_head = decode_head(
            requests[5].body().bytes().unwrap(),
            &scope_head_key(genesis().identity()),
            genesis().identity(),
        )
        .unwrap();
        assert_eq!(renewed_head.tail().sequence(), 3);
        handle.drain().await.unwrap();
        drop(handle);
        let _ = std::fs::remove_file(db_path);

        // A conflicting create whose read-back returns the identical bytes reconciles, then
        // appends and folds as usual.
        let (db_path, handle) = seeded_database_at_epoch("issue-reconcile", 1).await;
        let (authority, store, client) = seeded_authority(
            vec![
                response(412, &[], SdkBody::empty()),
                response(200, &[("etag", "\"grant\"")], bytes.clone()),
                response(200, &[], SdkBody::empty()),
                response(200, &[("etag", "\"appended\"")], SdkBody::empty()),
            ],
            NOW_MS,
        )
        .await;
        let _ = issued(issue_once(&store, &handle, authority, &grant, NOW_MS).await);
        assert_eq!(client.actual_requests().count(), 6);
        handle.drain().await.unwrap();
        drop(handle);
        let _ = std::fs::remove_file(db_path);

        // A rival operation's bytes at the key cause refusal without a resend and without an
        // event append.
        let rival = EffectGrant::new(
            identity(2),
            "git-push".into(),
            "repo-a".into(),
            1,
            5,
            NOW_MS + 60_000,
            "grant-op-2".into(),
        )
        .unwrap();
        let (db_path, handle) = seeded_database_at_epoch("issue-rival", 1).await;
        let (authority, store, client) = seeded_authority(
            vec![
                response(412, &[], SdkBody::empty()),
                response(200, &[("etag", "\"grant\"")], encode_grant(&rival).unwrap()),
            ],
            NOW_MS,
        )
        .await;
        assert_eq!(
            refusal(issue_once(&store, &handle, authority, &grant, NOW_MS).await).0,
            IssueError::Refused
        );
        assert_eq!(client.actual_requests().count(), 4);

        // An authority past its lease safety margin must stop issuing.
        let (authority, store, client) = authority_with_plan(Some(plan()), vec![]).await;
        assert_eq!(
            refusal(
                issue_once(
                    &store,
                    &handle,
                    authority,
                    &fixture(2, 5, NOW_MS + 120_000),
                    NOW_MS + 60_000
                )
                .await
            )
            .0,
            IssueError::NotAuthorized
        );
        assert_eq!(client.actual_requests().count(), 2);

        // A grant naming another scope is not this authority's to issue.
        let other = root_genesis(
            &AdmittedCampaignConfig::new(
                WorkspaceId::new("workspace-a".into()).unwrap(),
                CampaignId::new("campaign-b".into()).unwrap(),
                b"admitted".to_vec(),
            )
            .unwrap(),
        )
        .unwrap();
        let foreign = EffectGrant::new(
            ScopeClaimIdentity::new(
                other.identity().clone(),
                plan(),
                WorkRef::new(WorkId::new("work-17".into()).unwrap(), 1),
                2,
            )
            .unwrap(),
            "git-push".into(),
            "repo-a".into(),
            1,
            5,
            NOW_MS + 60_000,
            "grant-op-1".into(),
        )
        .unwrap();
        let (authority, store, client) = authority_with_plan(Some(plan()), vec![]).await;
        assert_eq!(
            refusal(issue_once(&store, &handle, authority, &foreign, NOW_MS).await).0,
            IssueError::NotAuthorized
        );
        assert_eq!(client.actual_requests().count(), 2);

        handle.drain().await.unwrap();
        drop(handle);
        let _ = std::fs::remove_file(db_path);
    }

    #[tokio::test]
    async fn refused_guards_append_no_event_and_keep_the_authority_usable() {
        let (db_path, handle) = seeded_database_at_epoch("issue-guards", 1).await;
        // Only the follow-up issuance's three writes are scripted, so a dry-run refusal that
        // touched storage would fail this test on request accounting.
        let (authority, store, client) = seeded_authority(
            vec![
                response(200, &[], SdkBody::empty()),
                response(200, &[], SdkBody::empty()),
                response(200, &[("etag", "\"appended\"")], SdkBody::empty()),
            ],
            NOW_MS,
        )
        .await;
        // The projection claims fence 2; a fence-9 issuance fails the dry-run.
        let (error, authority) = refusal(
            issue_once(
                &store,
                &handle,
                authority,
                &fixture(9, 5, NOW_MS + 60_000),
                NOW_MS,
            )
            .await,
        );
        assert_eq!(error, IssueError::Refused);
        assert_eq!(client.actual_requests().count(), 2);
        assert_eq!(authority.head().tail().sequence(), 2);
        // The returned authority is still live and issues the admissible grant.
        let authority = issued(
            issue_once(
                &store,
                &handle,
                authority,
                &fixture(2, 5, NOW_MS + 60_000),
                NOW_MS,
            )
            .await,
        );
        assert_eq!(client.actual_requests().count(), 5);
        assert_eq!(authority.head().tail().sequence(), 3);

        handle.drain().await.unwrap();
        drop(handle);
        let _ = std::fs::remove_file(db_path);
    }

    #[tokio::test]
    async fn stale_or_superseded_authority_is_a_consistency_error_not_an_empty_result() {
        let grant = fixture(2, 5, NOW_MS + 60_000);
        let found = |bytes: Vec<u8>| response(200, &[("etag", "\"grant\"")], bytes);

        // The projection was written at epoch 5; an epoch-2 authority is superseded evidence.
        let (db_path, handle) = seeded_database_at_epoch("epoch-ahead", 5).await;
        let (authority, store, client) =
            authority_with_plan(Some(plan()), vec![found(encode_grant(&grant).unwrap())]).await;
        assert_eq!(
            handle
                .continuable_work(genesis().identity(), &authority, NOW_MS)
                .await,
            Err(ApplyError::StaleAuthority)
        );
        assert!(matches!(
            intake(
                &store,
                &handle,
                &expected(2, 5, NOW_MS + 60_000),
                &authority,
                NOW_MS
            )
            .await,
            GrantIntake::Rejected(GrantRejection::StaleAuthority)
        ));

        // A stopped authority is refused before any read, whatever its epoch says.
        let requests_before_stop = client.actual_requests().count();
        assert!(matches!(
            intake(
                &store,
                &handle,
                &expected(2, 5, NOW_MS + 60_000),
                &authority,
                NOW_MS + 30_000
            )
            .await,
            GrantIntake::Rejected(GrantRejection::StaleAuthority)
        ));
        assert_eq!(client.actual_requests().count(), requests_before_stop);
        assert_eq!(
            handle
                .continuable_work(genesis().identity(), &authority, NOW_MS + 30_000)
                .await,
            Err(ApplyError::StaleAuthority)
        );

        handle.drain().await.unwrap();
        drop(handle);
        let _ = std::fs::remove_file(db_path);
    }

    /// The projection sits at epoch 1, behind the epoch-2 authority, so the epoch-lag arm
    /// cannot fire and only the stopped-term check can produce these refusals.
    #[tokio::test]
    async fn a_stopped_authority_is_refused_when_its_epoch_is_current() {
        let (db_path, handle) = seeded_database_at_epoch("stopped-current", 1).await;
        let (authority, store, client) = authority_with_plan(Some(plan()), vec![]).await;
        let stopped_at = NOW_MS + 30_000;
        assert!(authority.must_stop(stopped_at));
        assert_eq!(
            handle
                .continuable_work(genesis().identity(), &authority, stopped_at)
                .await,
            Err(ApplyError::StaleAuthority)
        );
        let requests_before = client.actual_requests().count();
        assert!(matches!(
            intake(
                &store,
                &handle,
                &expected(2, 5, NOW_MS + 60_000),
                &authority,
                stopped_at
            )
            .await,
            GrantIntake::Rejected(GrantRejection::StaleAuthority)
        ));
        assert_eq!(client.actual_requests().count(), requests_before);

        handle.drain().await.unwrap();
        drop(handle);
        let _ = std::fs::remove_file(db_path);
    }

    #[tokio::test]
    async fn intake_tracks_the_projected_claim_generation() {
        let (db_path, handle) = seeded_database_at_epoch("intake-gen", 1).await;
        let grant = fixture(2, 5, NOW_MS + 60_000);
        let bytes = encode_grant(&grant).unwrap();
        let found = |bytes: Vec<u8>| response(200, &[("etag", "\"grant\"")], bytes);
        let rival = EffectGrant::new(
            identity(2),
            "git-push".into(),
            "repo-a".into(),
            2,
            5,
            NOW_MS + 60_000,
            "grant-op-1".into(),
        )
        .unwrap();
        // Each intake consumes one GET from the store used to acquire its authority.
        let (reader, store, _) = authority_with_plan(
            Some(plan()),
            vec![
                found(bytes.clone()),
                found(bytes.clone()),
                found(encode_grant(&rival).unwrap()),
            ],
        )
        .await;

        // Published but not yet recorded: the projection continues nothing.
        assert!(matches!(
            intake(
                &store,
                &handle,
                &expected(2, 5, NOW_MS + 60_000),
                &reader,
                NOW_MS
            )
            .await,
            GrantIntake::Rejected(GrantRejection::Revoked)
        ));

        // Issuance activates the grant, and intake accepts it.
        let (issuer, publish, _) = seeded_authority(
            vec![
                response(200, &[], SdkBody::empty()),
                response(200, &[], SdkBody::empty()),
                response(200, &[("etag", "\"appended\"")], SdkBody::empty()),
            ],
            NOW_MS,
        )
        .await;
        let _ = issued(issue_once(&publish, &handle, issuer, &grant, NOW_MS).await);
        let accepted = intake(
            &store,
            &handle,
            &expected(2, 5, NOW_MS + 60_000),
            &reader,
            NOW_MS,
        )
        .await;
        let GrantIntake::Accepted(accepted) = accepted else {
            panic!("expected acceptance");
        };
        // Reading the private fields is what this test is for: every other test hands them
        // literals, so without this the stop instant could be minted as `u64::MAX` unnoticed.
        assert_eq!(accepted.grant, grant);
        assert_eq!(
            accepted.authority_stop_unix_ms,
            reader.lease_until().get() - STOP_MARGIN_MS
        );

        // A grant with matching bindings must equal the projection's recorded grant.
        assert!(matches!(
            intake(
                &store,
                &handle,
                &expected(2, 5, NOW_MS + 60_000),
                &reader,
                NOW_MS
            )
            .await,
            GrantIntake::Rejected(GrantRejection::IdentityMismatch)
        ));

        // A reclaim at fence 3 supersedes the fence-2 caller once its lease has lapsed.
        let target = WorkRef::new(WorkId::new("work-17".into()).unwrap(), 1);
        handle
            .record_claim(
                genesis().identity(),
                target.clone(),
                NonZeroU64::new(3).unwrap(),
                NonZeroU64::new(NOW_MS + 90_000).unwrap(),
                NOW_MS + 30_000,
            )
            .await
            .unwrap();
        let fence_three = EffectGrant::new(
            identity(3),
            "git-push".into(),
            "repo-a".into(),
            2,
            5,
            NOW_MS + 50_000,
            "grant-op-1".into(),
        )
        .unwrap();
        let projected_epoch = NonZeroU64::new(2).unwrap();
        handle
            .record_grant(
                &identity(3),
                GrantActivation {
                    scope_epoch: projected_epoch,
                    attempt: fence_three.attempt(),
                    units: fence_three.limit_units(),
                    deadline_unix_ms: fence_three.deadline_unix_ms(),
                    digest: Digest::new(format!(
                        "{:x}",
                        Sha256::digest(encode_grant(&fence_three).unwrap())
                    ))
                    .unwrap(),
                },
                NOW_MS + 30_000,
            )
            .await
            .unwrap();
        // The reader acquired at NOW_MS is stopped by now, so a later term reads the row.
        let late_head = ScopeHead::new(
            genesis().identity().clone(),
            ScopeAuthority::Unowned,
            2,
            genesis().event_ref().clone(),
            Some(plan()),
            "op-authority".into(),
        )
        .unwrap();
        let (late_reader, late_store, _) =
            authority_from_head(late_head, vec![found(bytes)], NOW_MS + 30_000).await;
        assert!(matches!(
            intake(
                &late_store,
                &handle,
                &expected(2, 5, NOW_MS + 60_000),
                &late_reader,
                NOW_MS + 30_001
            )
            .await,
            GrantIntake::Rejected(GrantRejection::StaleFence)
        ));

        handle.drain().await.unwrap();
        drop(handle);
        let _ = std::fs::remove_file(db_path);
    }
}
