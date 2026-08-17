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
    distributed::{
        identity::InstanceId,
        scope_controller::{self, ControllerAuthority, GrantAppend, STOP_MARGIN_MS},
    },
    domain::{
        validation::{ValidationError, bounded_stored, validate_key_segment},
        work::WorkRef,
    },
    invocation::{GateDecision, GateDecisionRecord, InvocationBinding},
    scope::{
        Digest, GrantActivatedPayload, ScopeClaimIdentity, ScopeIdentity, scope_gate_decision_key,
        scope_grant_key,
    },
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

/// Data-free category for one refused grant, or for a gate decision that was not recorded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GrantRejection {
    /// No object exists at the claim generation's grant key.
    Absent,
    /// The projection continues the work under a newer claim generation than the caller's.
    StaleFence,
    /// `IdentityMismatch` covers a grant whose binding differs from the expected binding.
    IdentityMismatch,
    /// Authority was minted under another instance's lease.
    ///
    /// This proves only a lease-holder mismatch; it says nothing about claim ownership.
    SubjectMismatch,
    Expired,
    /// The grant authorizes more than the caller asked for, refused at intake so an over-wide
    /// grant cannot be taken up at all.
    WiderThanRequested,
    /// The grant authorizes fewer output tokens than the request would draw.
    ///
    /// The opposite direction from [`Self::WiderThanRequested`], and refused at a different
    /// boundary: intake bounds the grant from above by what the caller expected, while an effect
    /// bounds the request from above by what the grant authorized. A request that could draw
    /// past its reservation is refused rather than truncated, because a truncated completion is
    /// a different answer than the one the work asked for.
    NarrowerThanRequest,
    /// The projection does not continue, or no longer continues, the caller's claim generation.
    Revoked,
    /// The caller's authority is stopped, the projection outran its epoch, or the authority was
    /// minted against a different object store; nothing it decides under that authority stands.
    StaleAuthority,
    Malformed,
    /// The gate could not prove its decision durable. Retry may succeed.
    Unrecorded,
}

impl GrantRejection {
    /// Stable, data-free gate-decision value.
    ///
    /// [`Self::Unrecorded`] is the one value a durable record cannot carry.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Absent => "absent",
            Self::StaleFence => "stale_fence",
            Self::IdentityMismatch => "identity_mismatch",
            Self::SubjectMismatch => "subject_mismatch",
            Self::Expired => "expired",
            Self::WiderThanRequested => "wider_than_requested",
            Self::NarrowerThanRequest => "narrower_than_request",
            Self::Revoked => "revoked",
            Self::StaleAuthority => "stale_authority",
            Self::Malformed => "malformed",
            Self::Unrecorded => "unrecorded",
        }
    }
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
/// It carries a stop instant as well as the grant, because either can run out first and
/// nothing at issuance bounds the grant's deadline by a lease: issuance refuses only a
/// grant already expired. The stop instant is the shorter of the two leases that prove
/// current ownership — the controller's term and the work claim's lease — each less
/// [`STOP_MARGIN_MS`], because they expire independently: the controller renews its own
/// term while a claim lease is not renewed by anything in this crate, and an unexpired
/// claim survives controller takeover. A call bounded only by the grant, or by only one
/// of the leases, could outlive the other one, and a successor that legitimately took the
/// claim could be dispatching at the same time.
///
/// `subject` is the lease holder proved by [`intake`]. Claim ownership remains assumed rather
/// than proven because admitted work carries no owner identity. `namespace` pins that proof to
/// the exact constructed object store from which it was obtained, not merely its endpoint.
/// Neither field is exposed to callers.
#[must_use]
pub struct EffectAuthority {
    grant: EffectGrant,
    subject: InstanceId,
    namespace: String,
    /// Instant past which the proving authority must stop: the shorter of the controller
    /// lease and the work-claim lease, less [`STOP_MARGIN_MS`].
    authority_stop_unix_ms: u64,
}

impl EffectAuthority {
    /// Verifies, decides, and durably records one model gate before any provider effect.
    ///
    /// `expected_subject` is the caller's independently held process identity. A namespace
    /// mismatch is refused without a record: a record written to the wrong store records nothing
    /// about this dispatch. Every other gate decision, a subject mismatch included, is recorded
    /// before it is returned. The record holds that decision, not the post-write bound correction:
    /// an `allowed` record can still return `Expired` or `StaleAuthority` when its write consumed
    /// the remaining window.
    ///
    /// A second effect entry must route its decision through [`Self::record_decision`] before its
    /// effect. Module privacy prevents outside callers from reaching [`Self::decide_model`], but
    /// cannot stop a sibling decision function here from skipping the record.
    ///
    /// # Errors
    ///
    /// Returns [`GrantRejection::SubjectMismatch`] for authority minted under another instance,
    /// [`GrantRejection::IdentityMismatch`] for an action, resource, or operation mismatch,
    /// [`GrantRejection::NarrowerThanRequest`] when the request exceeds the grant's units,
    /// [`GrantRejection::Expired`] when the grant deadline is the tighter elapsed clock,
    /// [`GrantRejection::StaleAuthority`] for a store mismatch or tighter elapsed authority stop,
    /// and [`GrantRejection::Unrecorded`] when building or persisting the record failed or elapsed.
    pub async fn authorize_model(
        &self,
        store: &S3Store,
        expected_subject: &InstanceId,
        request: &crate::provider::InvocationRequest,
        now_ms: u64,
    ) -> Result<Duration, GrantRejection> {
        if self.namespace != store.namespace() {
            return Err(GrantRejection::StaleAuthority);
        }
        // The comparand is the caller's own process identity. No accessor exposes `subject`, so
        // callers cannot turn this into self-verification.
        let decision = if self.subject != *expected_subject {
            Err(GrantRejection::SubjectMismatch)
        } else {
            self.decide_model(request, now_ms)
        };
        let request_digest =
            Digest::new(request.request_digest()).map_err(|_| GrantRejection::Unrecorded)?;
        let started = tokio::time::Instant::now();
        let (recorded, record_deadline) = match decision {
            // An allowed write is bounded by the authority window it is buying.
            Ok(authorized_for) => (GateDecision::Allowed, started + authorized_for),
            // A refused write buys no dispatch, so bound only caller delay by the existing margin.
            Err(reason) => (
                GateDecision::Refused(reason),
                started + Duration::from_millis(STOP_MARGIN_MS),
            ),
        };
        tokio::time::timeout_at(
            record_deadline,
            self.record_decision(store, request_digest, recorded),
        )
        .await
        .map_err(|_| GrantRejection::Unrecorded)??;
        // A refusal returns its category only after the record is durable; an allowed call is
        // then re-bounded by what that write cost.
        decision?;

        self.remaining_window(now_ms.saturating_add(elapsed_ms(started)))
    }

    fn decide_model(
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
        if self.grant.action != GRANT_ACTION_MODEL_INVOKE
            || self.grant.resource_scope != request.profile().configuration_digest()
            || self.grant.operation_id != request.operation_id()
        {
            return Err(GrantRejection::IdentityMismatch);
        }
        // One unit is one authorized output token: `limit_units` is what the reservation drew at
        // activation, and `max_output_tokens` is what this call may draw against it. One-sided on
        // purpose — a grant authorizing more than this call needs is fine, and bounding a grant
        // from above is intake's job against the caller's own expectation.
        //
        // This bounds one call against its own reservation. It does not make the scope's
        // `reserved_budget_units` a spend bound: that budget is checked against authorized units
        // at issuance, and nothing anywhere debits what a call actually reported.
        if u64::from(request.max_output_tokens().get()) > self.grant.limit_units.get() {
            return Err(GrantRejection::NarrowerThanRequest);
        }
        self.remaining_window(now_ms)
    }

    /// Returns `min(grant deadline, authority stop) - now_ms`, retested because either clock can
    /// elapse after intake. The tighter clock names a refusal when both have elapsed.
    fn remaining_window(&self, now_ms: u64) -> Result<Duration, GrantRejection> {
        let deadline = self.grant.deadline_unix_ms.get();
        let (cutoff, rejection) = if self.authority_stop_unix_ms <= deadline {
            (self.authority_stop_unix_ms, GrantRejection::StaleAuthority)
        } else {
            (deadline, GrantRejection::Expired)
        };
        cutoff
            .checked_sub(now_ms)
            .filter(|remaining| *remaining > 0)
            .map(Duration::from_millis)
            .ok_or(rejection)
    }

    /// Publishes one immutable, secret-free decision record before its effect can occur.
    ///
    /// Grant fields plus an effect-specific request digest make this seam reusable by sibling
    /// effect entries. Every failure becomes [`GrantRejection::Unrecorded`].
    async fn record_decision(
        &self,
        store: &S3Store,
        request_digest: Digest,
        decision: GateDecision,
    ) -> Result<(), GrantRejection> {
        let grant_digest = Digest::new(format!(
            "{:x}",
            Sha256::digest(encode_grant(&self.grant).map_err(|_| GrantRejection::Unrecorded)?)
        ))
        .map_err(|_| GrantRejection::Unrecorded)?;
        let identity = self.grant.identity();
        let binding = InvocationBinding::new(
            identity.scope().scope_id().clone(),
            identity.plan_digest().clone(),
            identity.work().id().clone(),
            identity.work().revision(),
            identity.claim_fence().get(),
            grant_digest,
            self.grant.attempt().get(),
        )
        .map_err(|_| GrantRejection::Unrecorded)?;
        let record = GateDecisionRecord::new(
            binding,
            self.grant.action().to_owned(),
            self.grant.resource_scope().to_owned(),
            self.grant.operation_id().to_owned(),
            request_digest,
            decision,
        )
        .map_err(|_| GrantRejection::Unrecorded)?;
        let (bytes, digest) = record
            .stored_bytes()
            .map_err(|_| GrantRejection::Unrecorded)?;
        let key = scope_gate_decision_key(
            identity.scope(),
            identity.work(),
            identity.claim_fence(),
            self.grant.attempt(),
            &digest,
        );
        // Effect-gate taxonomy entry (4) excludes this create-only, content-verified decision
        // write; routing the record through another gate would recurse.
        store
            .publish_immutable(&key, bytes, &digest)
            .await
            .map_err(|_| GrantRejection::Unrecorded)
    }
}

/// Mints an [`EffectAuthority`] without an object store or a projection.
///
/// The fields are private to this module, so a test elsewhere cannot assemble one. This is the
/// only mint path outside [`intake`].
#[cfg(test)]
pub(crate) mod test_support {
    use super::{
        Digest, EffectAuthority, EffectGrant, InstanceId, ScopeClaimIdentity, ScopeIdentity,
        WorkRef,
    };
    use crate::{
        distributed::identity::WorkspaceId,
        domain::work::WorkId,
        invocation::{GateDecisionRecord, decode_gate_decision},
        scope::CampaignId,
    };

    /// Test-only provenance grouped to keep [`model_authority`] within the parameter limit.
    pub(crate) struct ModelAuthorityContext {
        pub(crate) subject: InstanceId,
        pub(crate) namespace: String,
    }

    /// An authority for `action` over `resource_scope`, under `operation_id`, authorizing
    /// `limit_units` output tokens.
    ///
    /// Every value the effect boundary compares against is a parameter, so a refusal case can
    /// vary exactly one of them: the resource scope is a profile's configuration digest, the
    /// operation id is the request's, and `limit_units` is the output-token budget a request's
    /// cap is checked against. `action`, subject, and namespace are parameters too, so a case can
    /// vary any compared value without rebuilding a grant field by field.
    pub(crate) fn model_authority(
        action: String,
        resource_scope: String,
        operation_id: String,
        limit_units: u64,
        deadline_unix_ms: u64,
        authority_stop_unix_ms: u64,
        context: ModelAuthorityContext,
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
                limit_units,
                deadline_unix_ms,
                operation_id,
            )
            .unwrap(),
            subject: context.subject,
            namespace: context.namespace,
            authority_stop_unix_ms,
        }
    }

    pub(crate) fn decision_key(uri: &str) -> &str {
        uri.split_once(".invalid/")
            .map(|(_, key)| key)
            .expect("test endpoint path")
            .split('?')
            .next()
            .expect("object key")
    }

    pub(crate) fn decode_model_record(uri: &str, bytes: &[u8]) -> GateDecisionRecord {
        let key = decision_key(uri);
        let digest = key.rsplit('/').next().expect("digest suffix");
        let scope = ScopeIdentity::root(
            WorkspaceId::new("workspace-a".into()).unwrap(),
            CampaignId::new("campaign-a".into()).unwrap(),
        )
        .unwrap();
        let work = WorkRef::new(WorkId::new("work-a".into()).unwrap(), 1);
        decode_gate_decision(bytes, key, &scope, &work, digest).unwrap()
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
                        // The controller lease and the work-claim lease expire independently:
                        // the controller renews its own term, while nothing renews a claim
                        // lease, and a claim survives controller takeover. Whichever ends
                        // first is when a successor can legitimately be dispatching, so the
                        // stop instant takes the shorter of the two.
                        GrantIntake::Accepted(Box::new(EffectAuthority {
                            grant,
                            subject: authority.instance().clone(),
                            namespace: store.namespace().to_owned(),
                            authority_stop_unix_ms: authority
                                .lease_until()
                                .get()
                                .min(row.claim_lease_until().get())
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
    use std::{
        num::{NonZeroU32, NonZeroU64},
        sync::{
            Arc, Mutex,
            atomic::{AtomicBool, Ordering},
        },
    };

    use crate::domain::validation::MAX_STORED_INTEGER;

    use aws_sdk_bedrockruntime::config::{Credentials, HttpClient, Region};
    use aws_sdk_s3::primitives::SdkBody;
    use aws_smithy_runtime::client::http::test_util::{
        NeverClient, ReplayEvent, StaticReplayClient,
    };

    use crate::{
        distributed::{
            identity::{InstanceId, WorkspaceId},
            scope_controller::{AcquireOutcome, acquire},
        },
        domain::work::WorkId,
        invocation::GateDecision,
        provider::{BedrockTransport, InvocationRequest, ModelProfile, ModelProvider},
        scope::{
            AdmittedCampaignConfig, CampaignId, RootGenesis, ScopeAuthority, ScopeHead,
            encode_head, root_genesis,
        },
        storage::s3::test_support::{replay_store, response, test_builder},
        sync::WireError,
    };

    use super::{
        test_support::{decision_key, decode_model_record},
        *,
    };

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

    fn model_request() -> InvocationRequest {
        InvocationRequest::new(
            ModelProfile::new(
                ModelProvider::Bedrock,
                "anthropic.claude-fixture-v1:0".into(),
                "profile-a".into(),
                NonZeroU32::new(4_096).unwrap(),
                None,
                None,
                Vec::new(),
            )
            .unwrap(),
            "secret system text".into(),
            "secret fixture prompt".into(),
            NonZeroU32::new(512).unwrap(),
            "invoke-op-1".into(),
        )
        .unwrap()
    }

    fn model_authority_for(
        namespace: &str,
        subject: &str,
        deadline_unix_ms: u64,
        authority_stop_unix_ms: u64,
    ) -> EffectAuthority {
        let request = model_request();
        test_support::model_authority(
            GRANT_ACTION_MODEL_INVOKE.to_owned(),
            request.profile().configuration_digest(),
            request.operation_id().to_owned(),
            u64::from(request.max_output_tokens().get()),
            deadline_unix_ms,
            authority_stop_unix_ms,
            test_support::ModelAuthorityContext {
                subject: InstanceId::new(subject.into()).unwrap(),
                namespace: namespace.to_owned(),
            },
        )
    }

    fn bedrock_transport(
        store: Arc<S3Store>,
        instance: &str,
        client: impl HttpClient + 'static,
    ) -> BedrockTransport {
        BedrockTransport::new(
            Region::new("us-east-1"),
            aws_sdk_bedrockruntime::Config::builder()
                .credentials_provider(Credentials::for_tests())
                .endpoint_url("https://bedrock.test.invalid")
                .http_client(client),
            store,
            InstanceId::new(instance.into()).unwrap(),
        )
    }

    fn bedrock_replay(
        store: Arc<S3Store>,
        responses: Vec<http::Response<SdkBody>>,
    ) -> (BedrockTransport, StaticReplayClient) {
        let client = StaticReplayClient::new(
            responses
                .into_iter()
                .map(|response| ReplayEvent::new(http::Request::new(SdkBody::empty()), response))
                .collect(),
        );
        (
            bedrock_transport(store, "instance-a", client.clone()),
            client,
        )
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

    /// A grant may authorize more output tokens than a call will draw. Without this check, the
    /// one-sided comparison could become equality and reject every over-provisioned reservation.
    #[test]
    fn a_grant_wider_than_the_request_still_authorizes_it() {
        let request = model_request();
        let authority = test_support::model_authority(
            GRANT_ACTION_MODEL_INVOKE.to_owned(),
            request.profile().configuration_digest(),
            request.operation_id().to_owned(),
            u64::from(request.max_output_tokens().get()) + 1,
            NOW_MS + 60_000,
            NOW_MS + 25_000,
            test_support::ModelAuthorityContext {
                subject: InstanceId::new("instance-a".into()).unwrap(),
                namespace: "namespace-a".into(),
            },
        );
        assert!(authority.decide_model(&request, NOW_MS).is_ok());
    }

    #[tokio::test]
    async fn a_refused_dispatch_records_its_reason_before_returning_it() {
        let (store, decision_client) = replay_store(vec![response(200, &[], SdkBody::empty())]);
        let store = Arc::new(store);
        let (transport, bedrock_client) = bedrock_replay(
            Arc::clone(&store),
            vec![response(200, &[], SdkBody::empty())],
        );
        let authority =
            model_authority_for(store.namespace(), "instance-a", NOW_MS, NOW_MS + 25_000);
        let grant_digest = Digest::new(format!(
            "{:x}",
            Sha256::digest(encode_grant(&authority.grant).unwrap())
        ))
        .unwrap();
        let request = model_request();
        let identity = authority.grant.identity();
        let expected = GateDecisionRecord::new(
            InvocationBinding::new(
                identity.scope().scope_id().clone(),
                identity.plan_digest().clone(),
                identity.work().id().clone(),
                identity.work().revision(),
                identity.claim_fence().get(),
                grant_digest,
                authority.grant.attempt().get(),
            )
            .unwrap(),
            authority.grant.action().to_owned(),
            authority.grant.resource_scope().to_owned(),
            authority.grant.operation_id().to_owned(),
            Digest::new(request.request_digest()).unwrap(),
            GateDecision::Refused(GrantRejection::Expired),
        )
        .unwrap();
        let mut history = AttemptHistory::default();

        assert_eq!(
            transport
                .invoke(authority, &request, &mut history, NOW_MS)
                .await,
            Err(GrantRejection::Expired)
        );
        assert!(!history.may_have_been_sent());
        assert_eq!(bedrock_client.actual_requests().count(), 0);
        let sent = decision_client
            .actual_requests()
            .next()
            .expect("decision PUT");
        assert_eq!(
            decode_model_record(sent.uri(), sent.body().bytes().expect("in-memory decision")),
            expected
        );
    }

    #[tokio::test]
    async fn an_unwritable_decision_refuses_the_dispatch() {
        let (store, decision_client) = replay_store(vec![
            response(500, &[], SdkBody::empty()),
            response(500, &[], SdkBody::empty()),
        ]);
        let store = Arc::new(store);
        let (transport, bedrock_client) = bedrock_replay(
            Arc::clone(&store),
            vec![response(200, &[], SdkBody::empty())],
        );
        let authority = model_authority_for(
            store.namespace(),
            "instance-a",
            NOW_MS + 60_000,
            NOW_MS + 25_000,
        );
        let mut history = AttemptHistory::default();

        assert_eq!(
            transport
                .invoke(authority, &model_request(), &mut history, NOW_MS)
                .await,
            Err(GrantRejection::Unrecorded)
        );
        assert_eq!(decision_client.actual_requests().count(), 2);
        assert_eq!(bedrock_client.actual_requests().count(), 0);
        assert!(!history.may_have_been_sent());
    }

    #[tokio::test]
    async fn a_refused_decision_record_carries_no_request_text() {
        let (store, decision_client) = replay_store(vec![response(200, &[], SdkBody::empty())]);
        let authority =
            model_authority_for(store.namespace(), "instance-a", NOW_MS, NOW_MS + 25_000);

        assert_eq!(
            authority
                .authorize_model(
                    &store,
                    &InstanceId::new("instance-a".into()).unwrap(),
                    &model_request(),
                    NOW_MS,
                )
                .await,
            Err(GrantRejection::Expired)
        );
        let sent = decision_client
            .actual_requests()
            .next()
            .expect("decision PUT");
        let stored = sent.body().bytes().expect("in-memory decision");
        assert!(
            !stored
                .windows(b"secret fixture prompt".len())
                .any(|bytes| { bytes == b"secret fixture prompt" })
        );
        assert!(
            !stored
                .windows(b"secret system text".len())
                .any(|bytes| { bytes == b"secret system text" })
        );
    }

    #[tokio::test]
    async fn an_identical_refusal_reconciles_at_one_key() {
        let (first_store, first_client) = replay_store(vec![response(200, &[], SdkBody::empty())]);
        let first = model_authority_for(
            first_store.namespace(),
            "instance-a",
            NOW_MS,
            NOW_MS + 25_000,
        );
        assert_eq!(
            first
                .authorize_model(
                    &first_store,
                    &InstanceId::new("instance-a".into()).unwrap(),
                    &model_request(),
                    NOW_MS,
                )
                .await,
            Err(GrantRejection::Expired)
        );
        let first_request = first_client.actual_requests().next().expect("first PUT");
        let bytes = first_request
            .body()
            .bytes()
            .expect("in-memory decision")
            .to_vec();
        let first_uri = first_request.uri().to_owned();

        let (store, client) = replay_store(vec![
            response(409, &[], SdkBody::empty()),
            response(200, &[], bytes),
        ]);
        let authority =
            model_authority_for(store.namespace(), "instance-a", NOW_MS, NOW_MS + 25_000);
        assert_eq!(
            authority
                .authorize_model(
                    &store,
                    &InstanceId::new("instance-a".into()).unwrap(),
                    &model_request(),
                    NOW_MS,
                )
                .await,
            Err(GrantRejection::Expired)
        );
        let requests = client.actual_requests().collect::<Vec<_>>();
        assert_eq!(requests.len(), 2);
        assert_eq!(decision_key(requests[0].uri()), decision_key(&first_uri));
        assert_eq!(decision_key(requests[1].uri()), decision_key(&first_uri));
    }

    #[tokio::test]
    async fn a_namespace_mismatch_refuses_before_recording() {
        let (store, decision_client) = replay_store(vec![response(200, &[], SdkBody::empty())]);
        let (foreign, _) = replay_store(Vec::new());
        let store = Arc::new(store);
        let (transport, bedrock_client) = bedrock_replay(
            Arc::clone(&store),
            vec![response(200, &[], SdkBody::empty())],
        );
        let authority = model_authority_for(
            foreign.namespace(),
            "instance-a",
            NOW_MS + 60_000,
            NOW_MS + 25_000,
        );
        let mut history = AttemptHistory::default();

        assert_eq!(
            transport
                .invoke(authority, &model_request(), &mut history, NOW_MS)
                .await,
            Err(GrantRejection::StaleAuthority)
        );
        assert_eq!(decision_client.actual_requests().count(), 0);
        assert_eq!(bedrock_client.actual_requests().count(), 0);
        assert!(!history.may_have_been_sent());
    }

    #[tokio::test]
    async fn an_allowed_dispatch_records_before_it_sends() {
        let (store, decision_client) = replay_store(vec![response(200, &[], SdkBody::empty())]);
        let store = Arc::new(store);
        let observed_send = Arc::new(AtomicBool::new(false));
        let observed = Arc::clone(&observed_send);
        let decisions = decision_client.clone();
        let bedrock_client = aws_smithy_http_client::test_util::infallible_client_fn(move |_| {
            assert_eq!(decisions.actual_requests().count(), 1);
            observed.store(true, Ordering::SeqCst);
            response(
                200,
                &[("content-type", "application/json")],
                r#"{"output":{"message":{"role":"assistant","content":[{"text":"answer"}]}},"stopReason":"end_turn","usage":{"inputTokens":1,"outputTokens":1,"totalTokens":2}}"#,
            )
        });
        let transport = bedrock_transport(Arc::clone(&store), "instance-a", bedrock_client);
        let authority = model_authority_for(
            store.namespace(),
            "instance-a",
            NOW_MS + 60_000,
            NOW_MS + 25_000,
        );
        let mut history = AttemptHistory::default();

        assert!(
            transport
                .invoke(authority, &model_request(), &mut history, NOW_MS)
                .await
                .is_ok()
        );
        assert!(observed_send.load(Ordering::SeqCst));
        let sent = decision_client
            .actual_requests()
            .next()
            .expect("decision PUT");
        let record =
            decode_model_record(sent.uri(), sent.body().bytes().expect("in-memory decision"));
        assert_eq!(record.decision().as_str(), "allowed");
    }

    #[tokio::test]
    async fn an_allowed_record_can_precede_a_charged_window_refusal() {
        // This connector does not yield, so Tokio polls its successful response before noticing
        // the timeout deadline. The post-write charge must still stop dispatch.
        let captured = Arc::new(Mutex::new(None));
        let observed = Arc::clone(&captured);
        let client = aws_smithy_http_client::test_util::infallible_client_fn(move |request| {
            std::thread::sleep(Duration::from_millis(1_200));
            *observed.lock().unwrap() = Some((
                request.uri().to_string(),
                request.body().bytes().unwrap().to_vec(),
            ));
            response(200, &[], SdkBody::empty())
        });
        let store = S3Store::new(
            "test-bucket",
            aws_sdk_s3::config::Region::new("us-east-1"),
            test_builder(client),
        );
        let authority = model_authority_for(
            store.namespace(),
            "instance-a",
            NOW_MS + 60_000,
            NOW_MS + 1_000,
        );

        assert_eq!(
            authority
                .authorize_model(
                    &store,
                    &InstanceId::new("instance-a".into()).unwrap(),
                    &model_request(),
                    NOW_MS,
                )
                .await,
            Err(GrantRejection::StaleAuthority)
        );
        let (uri, bytes) = captured.lock().unwrap().take().expect("decision PUT");
        assert_eq!(
            decode_model_record(&uri, &bytes).decision(),
            GateDecision::Allowed
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_refused_decision_write_has_a_bounded_record_budget() {
        let never_store = NeverClient::new();
        let store = S3Store::new(
            "test-bucket",
            aws_sdk_s3::config::Region::new("us-east-1"),
            test_builder(never_store.clone()),
        );
        let authority =
            model_authority_for(store.namespace(), "instance-a", NOW_MS, NOW_MS + 25_000);

        let started = tokio::time::Instant::now();
        assert_eq!(
            authority
                .authorize_model(
                    &store,
                    &InstanceId::new("instance-a".into()).unwrap(),
                    &model_request(),
                    NOW_MS,
                )
                .await,
            Err(GrantRejection::Unrecorded)
        );
        assert_eq!(started.elapsed(), Duration::from_millis(STOP_MARGIN_MS));
        assert_eq!(never_store.num_calls(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn an_elapsed_decision_write_refuses_the_dispatch() {
        let never_store = NeverClient::new();
        let store = Arc::new(S3Store::new(
            "test-bucket",
            aws_sdk_s3::config::Region::new("us-east-1"),
            test_builder(never_store.clone()),
        ));
        let (transport, bedrock_client) = bedrock_replay(
            Arc::clone(&store),
            vec![response(200, &[], SdkBody::empty())],
        );
        let authority = model_authority_for(
            store.namespace(),
            "instance-a",
            NOW_MS + 60_000,
            NOW_MS + 3_000,
        );
        let mut history = AttemptHistory::default();

        let started = tokio::time::Instant::now();
        assert_eq!(
            transport
                .invoke(authority, &model_request(), &mut history, NOW_MS)
                .await,
            Err(GrantRejection::Unrecorded)
        );
        assert_eq!(started.elapsed(), Duration::from_millis(3_000));
        assert_eq!(never_store.num_calls(), 1);
        assert_eq!(bedrock_client.actual_requests().count(), 0);
        assert!(!history.may_have_been_sent());
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
            vec![found(bytes.clone()), found(encode_grant(&rival).unwrap())],
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
        // Acquired later than the seeding, so this reader's term outlives the claim lease
        // and the two clocks in the minted stop instant are distinguishable.
        let later_head = ScopeHead::new(
            genesis().identity().clone(),
            ScopeAuthority::Unowned,
            1,
            genesis().event_ref().clone(),
            Some(plan()),
            "op-authority".into(),
        )
        .unwrap();
        let (later_reader, later_store, _) =
            authority_from_head(later_head, vec![found(bytes.clone())], NOW_MS + 10_000).await;
        let accepted = intake(
            &later_store,
            &handle,
            &expected(2, 5, NOW_MS + 60_000),
            &later_reader,
            NOW_MS + 10_000,
        )
        .await;
        let GrantIntake::Accepted(accepted) = accepted else {
            panic!("expected acceptance");
        };
        // Reading private fields is this test's purpose: every other test hands them literals,
        // so a stop minted as `u64::MAX`, or provenance minted from something other than the
        // proving authority and its store, would otherwise pass unnoticed.
        assert_eq!(accepted.grant, grant);
        assert_eq!(accepted.subject, *later_reader.instance());
        assert_eq!(accepted.namespace, later_store.namespace());
        // The claim lease (seeded at NOW_MS + 30_000) ends before this reader's term, so it
        // is the clock that must set the stop instant; a stop minted from the controller
        // lease alone would end STOP_MARGIN_MS short of that later term instead.
        assert!(later_reader.lease_until().get() > NOW_MS + 30_000);
        assert_eq!(
            accepted.authority_stop_unix_ms,
            NOW_MS + 30_000 - STOP_MARGIN_MS
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
