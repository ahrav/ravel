//! Scoped effect grants: bounded authority for one external operation.
//!
//! A grant is an immutable JSON object at its claim generation's grant key, published
//! create-if-absent and activated by the existing `grant_fence` projection marker. The object
//! alone grants nothing: intake accepts a grant only while the projection still resumes its
//! exact work revision under its exact claim fence, so claim reclamation, terminal evidence,
//! or expiry revokes it without a revocation record.
//!
//! A grant authorizes execution only. No path here inserts work rows or writes terminal
//! evidence.
//! commentlint: allow(JUDGE)

use std::num::NonZeroU64;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

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
    /// key segment, or when a numeric binding falls outside the stored-integer range.
    /// commentlint: allow(JUDGE)
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
                .ok_or(ValidationError::OutOfRange)
        };
        bounded(identity.work().revision())?;
        bounded(identity.claim_fence().get())?;
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
    identity: ScopeClaimIdentity,
    action: String,
    resource_scope: String,
    max_units: NonZeroU64,
    max_deadline_unix_ms: NonZeroU64,
}

impl ExpectedGrant {
    /// # Errors
    ///
    /// Returns [`ValidationError`] for a value [`EffectGrant::new`] would also reject, so an
    /// expectation cannot name a value no grant can carry.
    /// commentlint: allow(JUDGE)
    pub fn new(
        identity: ScopeClaimIdentity,
        action: String,
        resource_scope: String,
        max_units: u64,
        max_deadline_unix_ms: u64,
    ) -> Result<Self, ValidationError> {
        validate_key_segment(&action)?;
        validate_key_segment(&resource_scope)?;
        let bounded = |value: u64| {
            NonZeroU64::new(value)
                .filter(|value| value.get() <= MAX_STORED_INTEGER)
                .ok_or(ValidationError::OutOfRange)
        };
        Ok(Self {
            identity,
            action,
            resource_scope,
            max_units: bounded(max_units)?,
            max_deadline_unix_ms: bounded(max_deadline_unix_ms)?,
        })
    }
}

/// Data-free category for one refused grant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GrantRejection {
    /// No object exists at the claim generation's grant key.
    Absent,
    /// The projection resumes the work under a newer claim generation than the caller's.
    StaleFence,
    /// Plan, action, or resource binding disagrees with the caller's expectation.
    IdentityMismatch,
    Expired,
    WiderThanRequested,
    /// The projection does not resume, or no longer resumes, the caller's claim generation.
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
    /// The authority must stop, is from another scope, or holds no or another active plan.
    NotAuthorized,
    /// The grant is already expired at issuance time.
    Expired,
    /// The outcome is unproven; the identical retry is safe.
    Unresolved,
    /// No identical retry can succeed: a rival object occupies this claim generation's key, or
    /// the projection refused the binding and any published object stays inert.
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
/// Returns [`IssueError::NotAuthorized`] when `authority` must stop or does not hold this
/// grant's scope and plan, [`IssueError::Expired`] when the deadline is not ahead of `now_ms`,
/// [`IssueError::Unresolved`] when publication or recording is unproven, and
/// [`IssueError::Refused`] when a rival object holds the key or the projection rejects the
/// binding.
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
    let digest = format!("{:x}", Sha256::digest(&bytes));
    // `operation_id` is inside the canonical bytes, so byte identity at the key is identity of
    // the operation: an ambiguous write reconciles by read-back before any retry.
    store
        .publish_with_history(&key, bytes, &digest, history)
        .await
        .map_err(|error| match error {
            PublicationError::NotSent
            | PublicationError::Unresolved
            | PublicationError::StorageNotFound => IssueError::Unresolved,
            _ => IssueError::Refused,
        })?;
    database
        .record_grant(
            &grant.identity,
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
/// Absence, malformed bytes, and every binding disagreement are permanent rejections.
/// [`GrantRejection::Revoked`] also covers a grant not yet activated by [`issue`], so a caller
/// may retry after activation; transport failure is retryable as [`GrantIntake::Unavailable`].
///
/// `scope_epoch` caps which admissions count as current and must come from the same observed
/// head as `expected`; a newer epoch can only widen the resumable set, never narrow a refusal.
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
    // A grant object alone is not authority.
    match database
        .resumable_work(expected.identity.scope(), scope_epoch, now_ms)
        .await
    {
        Ok(resumable) => {
            match resumable
                .iter()
                .find(|row| row.work() == expected.identity.work())
            {
                Some(row) if row.claim_fence() == expected.identity.claim_fence() => {
                    GrantIntake::Accepted(Box::new(grant))
                }
                Some(row) if row.claim_fence() > expected.identity.claim_fence() => {
                    GrantIntake::Rejected(GrantRejection::StaleFence)
                }
                _ => GrantIntake::Rejected(GrantRejection::Revoked),
            }
        }
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

#[cfg(test)]
mod tests {
    use std::num::NonZeroU64;

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

    fn plan() -> Digest {
        Digest::new("ab".repeat(32)).unwrap()
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
            max_units,
            max_deadline,
        )
        .unwrap()
    }

    /// A head whose plan is active, observed and acquired through one replay store.
    async fn authority_with_plan(
        plan: Option<Digest>,
    ) -> crate::distributed::scope_controller::ControllerAuthority {
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
        let (store, _) = replay_store(vec![
            response(200, &[("etag", "\"head\"")], encode_head(&head).unwrap()),
            response(200, &[("etag", "\"next\"")], SdkBody::empty()),
        ]);
        let outcome = acquire(
            &store,
            genesis.identity(),
            &InstanceId::new("instance-a".into()).unwrap(),
            NOW_MS,
        )
        .await
        .unwrap();
        let AcquireOutcome::Acquired(authority) = outcome else {
            panic!("expected acquisition");
        };
        authority
    }

    async fn database(label: &str) -> (std::path::PathBuf, DbHandle) {
        let path = std::env::temp_dir().join(format!(
            "ravel-grants-{}-{label}.sqlite3",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        (path.clone(), DbHandle::spawn(path).await.unwrap())
    }

    /// Seeds a projection directly so `issue` and `intake` can run end to end.
    async fn seeded_database(label: &str) -> (std::path::PathBuf, DbHandle) {
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
            let digest = Digest::new("11".repeat(32)).unwrap();
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
                1,
            )
            .unwrap();
            projections::apply_scope_event(&mut connection, &event).unwrap();
            connection
                .execute(
                    "UPDATE scopes SET active_plan_digest = ?1, reserved_budget_units = 0 \
                     WHERE scope_id = ?2",
                    rusqlite::params![plan().as_str(), scope.scope_id().as_str()],
                )
                .unwrap();
            projections::admit_work(
                &mut connection,
                &scope,
                &target,
                &[],
                NonZeroU64::new(1).unwrap(),
            )
            .unwrap();
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
        let epoch = NonZeroU64::new(1).unwrap();
        let grant_bytes = |grant: &EffectGrant| encode_grant(grant).unwrap();
        let found = |bytes: Vec<u8>| response(200, &[("etag", "\"grant\"")], bytes);

        // Absent object.
        let (store, _) = replay_store(vec![response(404, &[], SdkBody::empty())]);
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
        let (store, _) = replay_store(vec![found(grant_bytes(&fixture(2, 5, NOW_MS + 60_000)))]);
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
        // Expired.
        let (store, _) = replay_store(vec![found(grant_bytes(&fixture(2, 5, NOW_MS + 60_000)))]);
        assert!(matches!(
            intake(
                &store,
                &handle,
                &expected(2, 5, NOW_MS + 60_000),
                epoch,
                NOW_MS + 60_000
            )
            .await,
            GrantIntake::Rejected(GrantRejection::Expired)
        ));
        // Wider than requested, on units and on deadline.
        let (store, _) = replay_store(vec![found(grant_bytes(&fixture(2, 6, NOW_MS + 60_000)))]);
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
        let (store, _) = replay_store(vec![found(grant_bytes(&fixture(2, 5, NOW_MS + 90_000)))]);
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
        // Action mismatch is an identity disagreement.
        let (store, _) = replay_store(vec![found(grant_bytes(&fixture(2, 5, NOW_MS + 60_000)))]);
        let other_action = ExpectedGrant::new(
            identity(2),
            "git-fetch".into(),
            "repo-a".into(),
            5,
            NOW_MS + 60_000,
        )
        .unwrap();
        assert!(matches!(
            intake(&store, &handle, &other_action, epoch, NOW_MS).await,
            GrantIntake::Rejected(GrantRejection::IdentityMismatch)
        ));
        // Valid bytes, but the projection resumes nothing: the object alone is not authority.
        let (store, _) = replay_store(vec![found(grant_bytes(&fixture(2, 5, NOW_MS + 60_000)))]);
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
        let (store, _) = replay_store(vec![response(500, &[], SdkBody::empty())]);
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

    #[tokio::test]
    async fn issuance_requires_live_authority_over_the_admitted_plan() {
        let (db_path, handle) = database("issue").await;
        let grant = fixture(2, 5, NOW_MS + 60_000);
        let (store, _) = replay_store(vec![]);

        // No active plan on the head.
        let authority = authority_with_plan(None).await;
        assert_eq!(
            issue(
                &store,
                &handle,
                &authority,
                &grant,
                &mut AttemptHistory::default(),
                NOW_MS
            )
            .await,
            Err(IssueError::NotAuthorized)
        );
        // Another plan is active.
        let authority = authority_with_plan(Some(Digest::new("cd".repeat(32)).unwrap())).await;
        assert_eq!(
            issue(
                &store,
                &handle,
                &authority,
                &grant,
                &mut AttemptHistory::default(),
                NOW_MS
            )
            .await,
            Err(IssueError::NotAuthorized)
        );
        // The right plan and a live lease, but the grant deadline has already passed.
        let authority = authority_with_plan(Some(plan())).await;
        let short = fixture(2, 5, NOW_MS + 10_000);
        assert_eq!(
            issue(
                &store,
                &handle,
                &authority,
                &short,
                &mut AttemptHistory::default(),
                NOW_MS + 10_000
            )
            .await,
            Err(IssueError::Expired)
        );
        // Publication succeeds but the projection knows no such claim: the object stays inert.
        let authority = authority_with_plan(Some(plan())).await;
        let (store, client) = replay_store(vec![response(200, &[], SdkBody::empty())]);
        assert_eq!(
            issue(
                &store,
                &handle,
                &authority,
                &grant,
                &mut AttemptHistory::default(),
                NOW_MS
            )
            .await,
            Err(IssueError::Refused)
        );
        assert_eq!(client.actual_requests().count(), 1);

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
        let (db_path, handle) = seeded_database("issue-ok").await;
        let grant = fixture(2, 5, NOW_MS + 60_000);
        let bytes = encode_grant(&grant).unwrap();

        // A plain create publishes once and records.
        let authority = authority_with_plan(Some(plan())).await;
        let (store, client) = replay_store(vec![response(200, &[], SdkBody::empty())]);
        assert_eq!(
            issue(
                &store,
                &handle,
                &authority,
                &grant,
                &mut AttemptHistory::default(),
                NOW_MS
            )
            .await,
            Ok(())
        );
        assert_eq!(client.actual_requests().count(), 1);

        // A conflicting create whose read-back returns the identical bytes reconciles.
        let authority = authority_with_plan(Some(plan())).await;
        let (store, client) = replay_store(vec![
            response(412, &[], SdkBody::empty()),
            response(200, &[("etag", "\"grant\"")], bytes.clone()),
        ]);
        assert_eq!(
            issue(
                &store,
                &handle,
                &authority,
                &grant,
                &mut AttemptHistory::default(),
                NOW_MS
            )
            .await,
            Ok(())
        );
        assert_eq!(client.actual_requests().count(), 2);

        // A rival operation's bytes at the key cause refusal without a resend.
        let rival = EffectGrant::new(
            identity(2),
            "git-push".into(),
            "repo-a".into(),
            5,
            NOW_MS + 60_000,
            "grant-op-2".into(),
        )
        .unwrap();
        let authority = authority_with_plan(Some(plan())).await;
        let (store, client) = replay_store(vec![
            response(412, &[], SdkBody::empty()),
            response(200, &[("etag", "\"grant\"")], encode_grant(&rival).unwrap()),
        ]);
        assert_eq!(
            issue(
                &store,
                &handle,
                &authority,
                &grant,
                &mut AttemptHistory::default(),
                NOW_MS
            )
            .await,
            Err(IssueError::Refused)
        );
        assert_eq!(client.actual_requests().count(), 2);

        // An authority past its lease safety margin must stop issuing.
        let authority = authority_with_plan(Some(plan())).await;
        let (store, client) = replay_store(vec![]);
        assert_eq!(
            issue(
                &store,
                &handle,
                &authority,
                &fixture(2, 5, NOW_MS + 120_000),
                &mut AttemptHistory::default(),
                NOW_MS + 60_000
            )
            .await,
            Err(IssueError::NotAuthorized)
        );
        assert_eq!(client.actual_requests().count(), 0);

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
            5,
            NOW_MS + 60_000,
            "grant-op-1".into(),
        )
        .unwrap();
        let authority = authority_with_plan(Some(plan())).await;
        assert_eq!(
            issue(
                &store,
                &handle,
                &authority,
                &foreign,
                &mut AttemptHistory::default(),
                NOW_MS
            )
            .await,
            Err(IssueError::NotAuthorized)
        );
        assert_eq!(client.actual_requests().count(), 0);

        handle.drain().await.unwrap();
        drop(handle);
        let _ = std::fs::remove_file(db_path);
    }

    #[tokio::test]
    async fn intake_tracks_the_projected_claim_generation() {
        let (db_path, handle) = seeded_database("intake-gen").await;
        let grant = fixture(2, 5, NOW_MS + 60_000);
        let bytes = encode_grant(&grant).unwrap();
        let epoch = NonZeroU64::new(1).unwrap();
        let found = |bytes: Vec<u8>| response(200, &[("etag", "\"grant\"")], bytes);

        // Published but not yet recorded: the projection resumes nothing.
        let (store, _) = replay_store(vec![found(bytes.clone())]);
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

        // Recording activates the grant, and intake accepts it.
        let authority = authority_with_plan(Some(plan())).await;
        let (publish, _) = replay_store(vec![response(200, &[], SdkBody::empty())]);
        issue(
            &publish,
            &handle,
            &authority,
            &grant,
            &mut AttemptHistory::default(),
            NOW_MS,
        )
        .await
        .unwrap();
        let (store, _) = replay_store(vec![found(bytes.clone())]);
        let accepted = intake(
            &store,
            &handle,
            &expected(2, 5, NOW_MS + 60_000),
            epoch,
            NOW_MS,
        )
        .await;
        let GrantIntake::Accepted(accepted) = accepted else {
            panic!("expected acceptance");
        };
        assert_eq!(*accepted, grant);

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
        handle
            .record_grant(
                &identity(3),
                epoch,
                NonZeroU64::new(NOW_MS + 50_000).unwrap(),
                NOW_MS + 30_000,
            )
            .await
            .unwrap();
        let (store, _) = replay_store(vec![found(bytes)]);
        assert!(matches!(
            intake(
                &store,
                &handle,
                &expected(2, 5, NOW_MS + 60_000),
                epoch,
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
