//! Scope replay separates asynchronous object reads from blocking SQLite transactions.
//!
//! Ready output carries the observed head whose tail matches the committed local row.
//! Remote validation completes before the first projection write.
//! A writer epoch may lag the head epoch but never exceeds it or its own child's.
//! Replay limits are 4,096 unseen events and 64 MiB of stored event and plan bytes.

use std::{collections::HashSet, error::Error, fmt, path::Path};

use ciborium::Value;

use crate::{
    db::{
        projections::{
            ApplyError, ApplyOutcome, ScopeProjectionEvent, ScopeProjectionPayload, ValidateError,
        },
        worker::{DbHandle, OpenExistingError},
    },
    distributed::claims::{MAX_CLAIM_BYTES, ScopeClaimState, decode_claim},
    domain::proposal::{MAX_PLAN_STORED_BYTES, PlanProposal, decode_plan},
    scope::{
        Digest, GRANT_ACTIVATED_PAYLOAD_TYPE, PLAN_ADMITTED_PAYLOAD_TYPE, ScopeEventRef,
        ScopeIdentity, grant_activated_from_decoded, plan_admitted_from_decoded, plan_key,
        root_event_from_decoded, scope_claim_key,
    },
    storage::s3::{GetError, GetOutcome, S3Store},
};

use super::{
    WireError,
    event::{ScopeEventReadError, payload_registered, read_opaque, root_domain_valid},
    head::{self, ObservedScopeHead, ScopeHeadReadError},
};

const LIMITS: Limits = Limits {
    events: MAX_SCOPE_REPLAY_EVENTS,
    bytes: 64 * 1024 * 1024,
};

/// Unseen events one refresh may replay. A rebuild starts at cursor 0, so a committed head above
/// this bound is unreachable from genesis; [`crate::sync::head`] refuses to append past it.
pub(crate) const MAX_SCOPE_REPLAY_EVENTS: u64 = 4_096;

#[derive(Clone, Copy)]
struct Limits {
    events: u64,
    bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScopeReplayError {
    ScopeMissing,
    HeadStorage,
    HeadInvalid(WireError),
    EventMissing,
    EventStorage,
    EventInvalid(WireError),
    UnsupportedPayload,
    ClaimStorage,
    ClaimInvalid(WireError),
    HistoryConflict,
    CursorAhead,
    TailMismatch,
    Overflow,
    Apply(ApplyError),
    DatabaseUnavailable,
}

impl fmt::Display for ScopeReplayError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ScopeMissing => "scope head is missing",
            Self::HeadStorage => "scope head read failed",
            Self::HeadInvalid(_) => "scope head is invalid",
            Self::EventMissing => "scope event is missing",
            Self::EventStorage => "scope event read failed",
            Self::EventInvalid(_) => "scope event is invalid",
            Self::UnsupportedPayload => "scope event payload is unsupported",
            Self::ClaimStorage => "scope claim read failed",
            Self::ClaimInvalid(_) => "scope claim is invalid",
            Self::HistoryConflict => "scope history conflicts with the local projection",
            Self::CursorAhead => "scope cursor is ahead of the observed head",
            Self::TailMismatch => "scope cursor differs from the observed head",
            Self::Overflow => "scope replay exceeds its bound",
            Self::Apply(_) => "scope event application failed",
            Self::DatabaseUnavailable => "scope database is unavailable",
        })
    }
}

impl Error for ScopeReplayError {}

pub enum ScopeReadiness {
    Ready {
        local_cursor: (u64, Digest),
        observed_head: Box<ObservedScopeHead>,
    },
    NotReady(ScopeReplayError),
}

pub(crate) struct PreparedSuffix {
    observed: ObservedScopeHead,
    events: Vec<Prepared>,
}

struct Prepared {
    decoded: crate::scope::DecodedScopeEvent<Value>,
    /// Present exactly for `plan_admitted` events: the decoded event and the verified plan object
    /// replay re-admits from.
    plan: Option<(crate::scope::PlanAdmittedEvent, PlanProposal)>,
}

/// Replays the unseen suffix through the projection-owning worker.
///
/// Remote reads and validation complete before the first projection write; the worker
/// applies one event per transaction and advances that scope's cursor atomically.
pub async fn refresh(store: &S3Store, handle: &DbHandle, scope: &ScopeIdentity) -> ScopeReadiness {
    let cursor = match handle.scope_cursor(scope).await {
        Ok(cursor) => cursor,
        Err(error) => return ScopeReadiness::NotReady(ScopeReplayError::Apply(error)),
    };
    // The durable flag, not the starting cursor, gates the claim reader: a crash or storage
    // failure part-way through a rebuild leaves the cursor advanced but the flag down, and
    // gating on a blank cursor would skip the remaining restore forever.
    match prepare_suffix(store, scope, cursor).await {
        Ok(prepared) => match apply_suffix(handle, scope, prepared).await {
            Ok((local_cursor, observed_head)) => {
                match handle.claims_restored(scope).await {
                    Ok(true) => {}
                    Ok(false) => {
                        if let Err(error) = restore_claims(store, handle, scope).await {
                            return ScopeReadiness::NotReady(error);
                        }
                    }
                    Err(error) => {
                        return ScopeReadiness::NotReady(ScopeReplayError::Apply(error));
                    }
                }
                ScopeReadiness::Ready {
                    local_cursor,
                    observed_head: Box::new(observed_head),
                }
            }
            Err(error) => ScopeReadiness::NotReady(error),
        },
        Err(error) => ScopeReadiness::NotReady(error),
    }
}

/// Restores claim columns from the claim object at each admitted row's deterministic key.
///
/// An absent object restores nothing.
/// A `Sealed` claim is skipped because terminal evidence has no representation in the projection.
/// A claim naming a plan other than the row's admitting plan is skipped: the key carries no plan
/// segment, so the object's own binding is the only evidence of which plan it attests.
async fn restore_claims(
    store: &S3Store,
    handle: &DbHandle,
    scope: &ScopeIdentity,
) -> Result<(), ScopeReplayError> {
    let works = handle
        .admitted_work_refs(scope)
        .await
        .map_err(ScopeReplayError::Apply)?;
    for (work, plan_digest) in works {
        let key = scope_claim_key(scope, &work);
        let bytes = match store.get_object(&key, MAX_CLAIM_BYTES).await {
            Ok(GetOutcome::Found { bytes, .. }) => bytes,
            Ok(GetOutcome::NotFound) => continue,
            Err(GetError::TooLarge) => {
                return Err(ScopeReplayError::ClaimInvalid(WireError::LimitExceeded));
            }
            Err(_) => return Err(ScopeReplayError::ClaimStorage),
        };
        let claim =
            decode_claim(&bytes, &key, scope, &work).map_err(ScopeReplayError::ClaimInvalid)?;
        if claim.identity().plan_digest() != &plan_digest {
            continue;
        }
        match claim.state() {
            ScopeClaimState::Active { lease_until } => {
                // A fresh row records under the fence-free arm, so the takeover clock is never
                // consulted; zero keeps that explicit. A partially restored retry can meet a row
                // whose recorded state the object has since superseded; that rejection is a skip
                // here, because the projection then lags the object only in the fail-closed
                // direction and the next production claim record converges it.
                match handle
                    .record_claim(scope, work, claim.identity().claim_fence(), *lease_until, 0)
                    .await
                {
                    Ok(()) | Err(ApplyError::Conflict) => {}
                    Err(error) => return Err(ScopeReplayError::Apply(error)),
                }
            }
            ScopeClaimState::Sealed { .. } => {}
        }
    }
    // Each restored row commits in its own worker transaction, so this final flag-set is the
    // restore's commit point: a crash anywhere earlier leaves the flag down and the next
    // refresh re-runs the reader, which RECORD_CLAIM_SQL's fresh-row and monotonic arms make
    // idempotent. A restore over zero admitted rows still commits here; admission clears the flag
    // again for the rows it inserts.
    handle
        .mark_claims_restored(scope)
        .await
        .map_err(ScopeReplayError::Apply)
}

/// Replaces the file after deterministic local format or history validation failures.
/// A foreign application id is a refusal, not a rebuild: it can belong to unrelated
/// local data. Database-operation failures leave the existing file intact.
///
/// # Errors
///
/// Returns [`ScopeReplayError::DatabaseUnavailable`] for `:memory:` or `file:` URIs,
/// file I/O failures, and SQLite operation failures.
pub async fn open_projection(path: &Path) -> Result<DbHandle, ScopeReplayError> {
    if is_sqlite_uri(path) {
        return Err(ScopeReplayError::DatabaseUnavailable);
    }
    if !path
        .try_exists()
        .map_err(|_| ScopeReplayError::DatabaseUnavailable)?
    {
        return DbHandle::spawn(path.to_path_buf())
            .await
            .map_err(|_| ScopeReplayError::DatabaseUnavailable);
    }
    match DbHandle::open_existing(path.to_path_buf()).await {
        Ok(handle) => Ok(handle),
        Err(OpenExistingError::Validation(
            ValidateError::IntegrityCheckFailed
            | ValidateError::InvalidSchema
            | ValidateError::InvalidHistory,
        )) => rebuild_projection(path).await,
        Err(OpenExistingError::DatabaseOperationFailed | OpenExistingError::Validation(_)) => {
            Err(ScopeReplayError::DatabaseUnavailable)
        }
    }
}

async fn rebuild_projection(path: &Path) -> Result<DbHandle, ScopeReplayError> {
    for suffix in ["-journal", "-wal", "-shm"] {
        let mut sidecar = path.as_os_str().to_owned();
        sidecar.push(suffix);
        remove_if_exists(Path::new(&sidecar))?;
    }
    remove_if_exists(path)?;
    DbHandle::spawn(path.to_path_buf())
        .await
        .map_err(|_| ScopeReplayError::DatabaseUnavailable)
}

fn remove_if_exists(path: &Path) -> Result<(), ScopeReplayError> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(ScopeReplayError::DatabaseUnavailable),
    }
}

/// Reads and validates the complete unseen suffix without touching SQLite.
pub(crate) async fn prepare_suffix(
    store: &S3Store,
    scope: &ScopeIdentity,
    cursor: (u64, Option<Digest>),
) -> Result<PreparedSuffix, ScopeReplayError> {
    prepare_suffix_with_limits(store, scope, cursor, LIMITS).await
}

async fn prepare_suffix_with_limits(
    store: &S3Store,
    scope: &ScopeIdentity,
    cursor: (u64, Option<Digest>),
    limits: Limits,
) -> Result<PreparedSuffix, ScopeReplayError> {
    let observed = match head::read(store, scope).await {
        Ok(Some(head)) => head,
        Ok(None) => return Err(ScopeReplayError::ScopeMissing),
        Err(ScopeHeadReadError::Storage(_)) => return Err(ScopeReplayError::HeadStorage),
        Err(ScopeHeadReadError::Invalid(error)) => {
            return Err(ScopeReplayError::HeadInvalid(error));
        }
    };
    let events = prepare_chain(
        store,
        scope,
        cursor,
        observed.head().tail().clone(),
        observed.head().scope_epoch().get(),
        observed.head().operation_id(),
        limits,
    )
    .await?;
    Ok(PreparedSuffix { observed, events })
}

/// Converts the prepared suffix, then applies its events through the worker.
pub(crate) async fn apply_suffix(
    handle: &DbHandle,
    scope: &ScopeIdentity,
    mut prepared: PreparedSuffix,
) -> Result<((u64, Digest), ObservedScopeHead), ScopeReplayError> {
    for event in &prepared.events {
        if handle
            .scope_conflicting_operation(
                scope,
                event.decoded.envelope().operation_id(),
                event.decoded.event_ref(),
            )
            .await
            .map_err(ScopeReplayError::Apply)?
        {
            return Err(ScopeReplayError::HistoryConflict);
        }
    }
    prepared.events.reverse();
    let scope_epoch = prepared.observed.head().scope_epoch().get();
    let mutations = prepared
        .events
        .into_iter()
        .map(|prepared| {
            let reference = prepared.decoded.event_ref().clone();
            let (envelope, payload) = typed_payload(prepared, scope)?;
            ScopeProjectionEvent::new(scope.clone(), envelope, reference, payload, scope_epoch)
                .map_err(|_| ScopeReplayError::HistoryConflict)
        })
        .collect::<Result<Vec<_>, _>>()?;

    for mutation in mutations {
        match handle.apply(mutation).await {
            Ok(ApplyOutcome::Applied | ApplyOutcome::AlreadyApplied) => {}
            Err(error) => return Err(ScopeReplayError::Apply(error)),
        }
    }
    if !handle
        .scope_matches_head(prepared.observed.head())
        .await
        .map_err(ScopeReplayError::Apply)?
    {
        return Err(ScopeReplayError::HistoryConflict);
    }
    let local_cursor = (
        prepared.observed.head().tail().sequence(),
        prepared.observed.head().tail().digest().clone(),
    );
    Ok((local_cursor, prepared.observed))
}

/// Converts one prepared event into the typed content its apply writes.
fn typed_payload(
    prepared: Prepared,
    scope: &ScopeIdentity,
) -> Result<(crate::scope::EventEnvelope, ScopeProjectionPayload), ScopeReplayError> {
    match prepared.decoded.envelope().payload_type() {
        PLAN_ADMITTED_PAYLOAD_TYPE => {
            let (event, proposal) = prepared.plan.ok_or(ScopeReplayError::HistoryConflict)?;
            Ok((
                event.envelope().clone(),
                ScopeProjectionPayload::PlanAdmitted {
                    plan_digest: event.payload().plan_digest().clone(),
                    proposal: Box::new(proposal),
                },
            ))
        }
        crate::scope::ROOT_GENESIS_PAYLOAD_TYPE => {
            let event = root_event_from_decoded(prepared.decoded, scope)
                .map_err(ScopeReplayError::EventInvalid)?;
            Ok((
                event.envelope().clone(),
                ScopeProjectionPayload::RootGenesis {
                    objective_digest: event.payload().config_digest().clone(),
                },
            ))
        }
        GRANT_ACTIVATED_PAYLOAD_TYPE => {
            let event = grant_activated_from_decoded(prepared.decoded)
                .map_err(ScopeReplayError::EventInvalid)?;
            Ok((
                event.envelope().clone(),
                ScopeProjectionPayload::GrantActivated {
                    payload: event.payload().clone(),
                },
            ))
        }
        #[cfg(test)]
        crate::scope::TEST_SUCCESSOR_PAYLOAD_TYPE => Ok((
            prepared.decoded.envelope().clone(),
            ScopeProjectionPayload::TestSuccessor,
        )),
        // `prepare_chain` already refused unregistered payloads; a new registered type must be
        // routed here explicitly rather than absorbed by a catch-all.
        _ => Err(ScopeReplayError::UnsupportedPayload),
    }
}

async fn prepare_chain(
    store: &S3Store,
    scope: &ScopeIdentity,
    cursor: (u64, Option<Digest>),
    tail: ScopeEventRef,
    scope_epoch: u64,
    head_operation: &str,
    limits: Limits,
) -> Result<Vec<Prepared>, ScopeReplayError> {
    if tail.sequence() < cursor.0 {
        return Err(ScopeReplayError::CursorAhead);
    }
    if tail.sequence() == cursor.0 {
        return if cursor.1.as_ref() == Some(tail.digest()) {
            Ok(Vec::new())
        } else {
            Err(ScopeReplayError::TailMismatch)
        };
    }
    let unseen = tail.sequence() - cursor.0;
    if unseen > limits.events {
        return Err(ScopeReplayError::Overflow);
    }

    let mut current = tail;
    let mut total_bytes = 0;
    let mut operations = HashSet::new();
    // The walk runs newest to oldest, so each event's writer epoch bounds its parent's.
    let mut highest_epoch = scope_epoch;
    let mut prepared = Vec::with_capacity(unseen as usize);
    for hop in 0..unseen {
        let (decoded, bytes) = match read_opaque(store, scope, &current).await {
            Ok(Some(event)) => event,
            Ok(None) => return Err(ScopeReplayError::EventMissing),
            Err(ScopeEventReadError::Invalid(error)) => {
                return Err(ScopeReplayError::EventInvalid(error));
            }
            Err(ScopeEventReadError::Storage(_)) => return Err(ScopeReplayError::EventStorage),
        };
        total_bytes = checked_total(total_bytes, bytes.len(), limits.bytes)?;
        if decoded.event_ref() != &current
            || decoded.envelope().writer_epoch().get() > scope_epoch
            || decoded.envelope().writer_epoch().get() > highest_epoch
            || !operations.insert(decoded.envelope().operation_id().to_owned())
            || (hop == 0 && decoded.envelope().operation_id() != head_operation)
        {
            return Err(ScopeReplayError::HistoryConflict);
        }
        highest_epoch = decoded.envelope().writer_epoch().get();
        if !payload_registered(decoded.envelope()) {
            return Err(ScopeReplayError::UnsupportedPayload);
        }
        if !root_domain_valid(decoded.envelope()) {
            return Err(ScopeReplayError::EventInvalid(WireError::InvalidValue));
        }
        let final_hop = hop + 1 == unseen;
        if final_hop {
            let boundary = if cursor.0 == 0 {
                decoded.envelope().sequence() == 1 && decoded.envelope().parent_event().is_none()
            } else {
                decoded.envelope().parent_event().is_some_and(|parent| {
                    parent.sequence() == cursor.0 && cursor.1.as_ref() == Some(parent.digest())
                })
            };
            if !boundary {
                return Err(ScopeReplayError::HistoryConflict);
            }
        } else {
            current = decoded
                .envelope()
                .parent_event()
                .cloned()
                .ok_or(ScopeReplayError::HistoryConflict)?;
        }
        let plan = if decoded.envelope().payload_type() == PLAN_ADMITTED_PAYLOAD_TYPE {
            let event = plan_admitted_from_decoded(decoded.clone())
                .map_err(ScopeReplayError::EventInvalid)?;
            let key = plan_key(
                scope.workspace_id(),
                scope.campaign_id(),
                event.payload().plan_digest(),
            );
            // Plan objects draw on the same byte budget as the events that cite them.
            let bytes = match store
                .get_object(&key, MAX_PLAN_STORED_BYTES)
                .await
                .map_err(|error| match error {
                    GetError::TooLarge => ScopeReplayError::EventInvalid(WireError::LimitExceeded),
                    _ => ScopeReplayError::EventStorage,
                })? {
                GetOutcome::Found { bytes, .. } => bytes,
                GetOutcome::NotFound => return Err(ScopeReplayError::EventMissing),
            };
            total_bytes = checked_total(total_bytes, bytes.len(), limits.bytes)?;
            let proposal = decode_plan(&bytes, event.payload().plan_digest())
                .map_err(|_| ScopeReplayError::EventInvalid(WireError::InvalidValue))?;
            Some((event, proposal))
        } else {
            None
        };
        prepared.push(Prepared { decoded, plan });
    }
    Ok(prepared)
}

fn checked_total(total: usize, next: usize, limit: usize) -> Result<usize, ScopeReplayError> {
    let total = total.checked_add(next).ok_or(ScopeReplayError::Overflow)?;
    if total > limit {
        Err(ScopeReplayError::Overflow)
    } else {
        Ok(total)
    }
}

/// `is_sqlite_uri` compares encoded bytes so non-UTF-8 paths can match `b"file:"`.
fn is_sqlite_uri(path: &Path) -> bool {
    let bytes = path.as_os_str().as_encoded_bytes();
    bytes == b":memory:" || bytes.starts_with(b"file:")
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::ffi::OsStringExt,
        path::PathBuf,
        process,
        time::{Duration, Instant},
    };

    use aws_sdk_s3::primitives::SdkBody;
    use ciborium::Value;

    use crate::{
        db::{projections, worker::DbHandle},
        distributed::identity::{InstanceId, WorkspaceId},
        scope::{
            AdmittedCampaignConfig, CampaignId, Digest, EventEnvelope, ROOT_GENESIS_PAYLOAD_TYPE,
            ScopeAuthority, ScopeEventRef, ScopeHead, TEST_SUCCESSOR_PAYLOAD_TYPE, encode_head,
            encode_scope_event, root_genesis,
        },
        storage::s3::test_support::{replay_store, response},
    };

    use super::*;

    fn path(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "ravel-scope-replay-{}-{label}.sqlite3",
            process::id()
        ));
        let _ = fs::remove_file(&path);
        path
    }

    fn genesis() -> crate::scope::RootGenesis {
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

    fn root_mutation(genesis: &crate::scope::RootGenesis) -> ScopeProjectionEvent {
        let root = crate::scope::decode_root_event(
            genesis.event_bytes(),
            genesis.event_key(),
            genesis.identity(),
        )
        .unwrap();
        ScopeProjectionEvent::new(
            genesis.identity().clone(),
            root.envelope().clone(),
            genesis.event_ref().clone(),
            ScopeProjectionPayload::RootGenesis {
                objective_digest: root.payload().config_digest().clone(),
            },
            1,
        )
        .unwrap()
    }

    /// Runs one statement over a short-lived connection while the worker is idle.
    fn side_execute(path: &Path, sql: &str, params: &[&dyn rusqlite::ToSql]) {
        rusqlite::Connection::open(path)
            .unwrap()
            .execute(sql, rusqlite::params_from_iter(params.iter().copied()))
            .unwrap();
    }

    /// Reads projection rows over a short-lived connection while the worker is idle.
    fn row_counts(path: &Path) -> (i64, i64) {
        rusqlite::Connection::open(path)
            .unwrap()
            .query_row(
                "SELECT (SELECT COUNT(*) FROM scopes), \
                 (SELECT COUNT(*) FROM applied_scope_events)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap()
    }

    fn head_response(bytes: Vec<u8>) -> http::Response<SdkBody> {
        response(200, &[("etag", "\"head\"")], bytes)
    }

    fn event_response(bytes: Vec<u8>) -> http::Response<SdkBody> {
        response(200, &[("etag", "\"event\"")], bytes)
    }

    #[tokio::test]
    async fn replay_is_idempotent_and_returns_the_observed_head_witness() {
        let genesis = genesis();
        let path = path("idempotent");
        let handle = DbHandle::spawn(path.clone()).await.unwrap();
        let (store, client) = replay_store(vec![
            head_response(genesis.head_bytes().to_vec()),
            event_response(genesis.event_bytes().to_vec()),
        ]);
        match refresh(&store, &handle, genesis.identity()).await {
            ScopeReadiness::Ready {
                local_cursor,
                observed_head,
            } => {
                assert_eq!(local_cursor.0, 1);
                assert_eq!(local_cursor.1, *genesis.event_ref().digest());
                assert_eq!(observed_head.canonical_bytes(), genesis.head_bytes());
            }
            ScopeReadiness::NotReady(_) => panic!("genesis must replay"),
        }
        assert_eq!(
            handle.scope_cursor(genesis.identity()).await.unwrap(),
            (1, Some(genesis.event_ref().digest().clone()))
        );
        assert_eq!(client.actual_requests().count(), 2);
        let before = row_counts(&path);
        let (store, client) = replay_store(vec![head_response(genesis.head_bytes().to_vec())]);
        assert!(matches!(
            refresh(&store, &handle, genesis.identity()).await,
            ScopeReadiness::Ready { .. }
        ));
        assert_eq!(client.actual_requests().count(), 1);
        assert_eq!(row_counts(&path), before);
        drop(handle);
        fs::remove_file(path).unwrap();
    }

    /// Two `refresh` calls sharing cloned handles can both read one stale cursor and prepare
    /// the same suffix. The second must still report ready once the first commits it.
    #[tokio::test]
    async fn a_suffix_another_caller_already_committed_replays_ready() {
        let genesis = genesis();
        let path = path("concurrent-suffix");
        let handle = DbHandle::spawn(path.clone()).await.unwrap();
        let other = handle.clone();
        let cursor = handle.scope_cursor(genesis.identity()).await.unwrap();
        assert_eq!(cursor, (0, None));

        let mut prepared = Vec::with_capacity(2);
        for _ in 0..2 {
            let (store, _) = replay_store(vec![
                head_response(genesis.head_bytes().to_vec()),
                event_response(genesis.event_bytes().to_vec()),
            ]);
            prepared.push(
                prepare_suffix(&store, genesis.identity(), cursor.clone())
                    .await
                    .unwrap(),
            );
        }
        let second = prepared.pop().unwrap();
        let first = prepared.pop().unwrap();

        let (first_cursor, _) = apply_suffix(&handle, genesis.identity(), first)
            .await
            .unwrap();
        let rows = row_counts(&path);
        let (second_cursor, _) = apply_suffix(&other, genesis.identity(), second)
            .await
            .expect("a suffix the first caller committed is not a history conflict");

        assert_eq!(second_cursor, first_cursor);
        assert_eq!(row_counts(&path), rows);
        drop((handle, other));
        fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn invalid_suffix_and_event_count_limit_apply_nothing() {
        let genesis = genesis();
        let path = path("invalid");
        let handle = DbHandle::spawn(path.clone()).await.unwrap();
        let (store, _) = replay_store(vec![
            head_response(genesis.head_bytes().to_vec()),
            event_response(b"not-zstd".to_vec()),
        ]);
        assert!(matches!(
            refresh(&store, &handle, genesis.identity()).await,
            ScopeReadiness::NotReady(ScopeReplayError::EventInvalid(_))
        ));
        assert_eq!(
            handle.scope_cursor(genesis.identity()).await.unwrap(),
            (0, None)
        );

        let successor_envelope = EventEnvelope::new(
            genesis.identity().scope_id().clone(),
            2,
            Some(genesis.event_ref().clone()),
            1,
            "successor".into(),
            "artifact".into(),
        )
        .unwrap();
        let successor = encode_scope_event(&successor_envelope, &Value::Null).unwrap();
        let successor_head = ScopeHead::new(
            genesis.identity().clone(),
            ScopeAuthority::Unowned,
            1,
            successor.event_ref().clone(),
            None,
            "successor".into(),
        )
        .unwrap();
        let (store, client) = replay_store(vec![
            head_response(encode_head(&successor_head).unwrap()),
            event_response(successor.stored_bytes().to_vec()),
        ]);
        assert!(matches!(
            refresh(&store, &handle, genesis.identity()).await,
            ScopeReadiness::NotReady(ScopeReplayError::UnsupportedPayload)
        ));
        assert_eq!(client.actual_requests().count(), 2);
        assert_eq!(
            handle.scope_cursor(genesis.identity()).await.unwrap(),
            (0, None)
        );

        let invalid_root_envelope = EventEnvelope::new(
            genesis.identity().scope_id().clone(),
            2,
            Some(genesis.event_ref().clone()),
            1,
            "invalid-root-payload".into(),
            ROOT_GENESIS_PAYLOAD_TYPE.into(),
        )
        .unwrap();
        let invalid_root = encode_scope_event(&invalid_root_envelope, &Value::Null).unwrap();
        let invalid_root_head = ScopeHead::new(
            genesis.identity().clone(),
            ScopeAuthority::Unowned,
            1,
            invalid_root.event_ref().clone(),
            None,
            "invalid-root-payload".into(),
        )
        .unwrap();
        let (store, client) = replay_store(vec![
            head_response(encode_head(&invalid_root_head).unwrap()),
            event_response(invalid_root.stored_bytes().to_vec()),
        ]);
        assert!(matches!(
            refresh(&store, &handle, genesis.identity()).await,
            ScopeReadiness::NotReady(ScopeReplayError::EventInvalid(WireError::InvalidValue))
        ));
        assert_eq!(client.actual_requests().count(), 2);
        assert_eq!(
            handle.scope_cursor(genesis.identity()).await.unwrap(),
            (0, None)
        );

        let mismatched_head = ScopeHead::new(
            genesis.identity().clone(),
            ScopeAuthority::Unowned,
            1,
            genesis.event_ref().clone(),
            None,
            "mismatched-operation".into(),
        )
        .unwrap();
        let (store, client) = replay_store(vec![
            head_response(encode_head(&mismatched_head).unwrap()),
            event_response(genesis.event_bytes().to_vec()),
        ]);
        assert!(matches!(
            refresh(&store, &handle, genesis.identity()).await,
            ScopeReadiness::NotReady(ScopeReplayError::HistoryConflict)
        ));
        assert_eq!(client.actual_requests().count(), 2);
        assert_eq!(
            handle.scope_cursor(genesis.identity()).await.unwrap(),
            (0, None)
        );

        let tail = ScopeEventRef::new(4_097, Digest::new("f".repeat(64)).unwrap()).unwrap();
        let head = ScopeHead::new(
            genesis.identity().clone(),
            ScopeAuthority::Unowned,
            1,
            tail,
            None,
            "far-head".into(),
        )
        .unwrap();
        let (store, client) = replay_store(vec![head_response(encode_head(&head).unwrap())]);
        assert!(matches!(
            refresh(&store, &handle, genesis.identity()).await,
            ScopeReadiness::NotReady(ScopeReplayError::Overflow)
        ));
        assert_eq!(client.actual_requests().count(), 1);
        assert_eq!(
            handle.scope_cursor(genesis.identity()).await.unwrap(),
            (0, None)
        );

        // A head claiming an active plan is decodable now, but a suffix that contains no
        // admission event cannot substantiate it, so the mismatch surfaces after apply:
        // genesis lands, the head comparison fails, and readiness is refused.
        let unsubstantiated_plan_head = ScopeHead::new(
            genesis.identity().clone(),
            ScopeAuthority::Unowned,
            1,
            genesis.event_ref().clone(),
            Some(Digest::new("a".repeat(64)).unwrap()),
            format!("root-genesis:{}", genesis.identity().scope_id().as_str()),
        )
        .unwrap();
        let (store, client) = replay_store(vec![
            head_response(encode_head(&unsubstantiated_plan_head).unwrap()),
            event_response(genesis.event_bytes().to_vec()),
        ]);
        assert!(matches!(
            refresh(&store, &handle, genesis.identity()).await,
            ScopeReadiness::NotReady(ScopeReplayError::HistoryConflict)
        ));
        assert_eq!(client.actual_requests().count(), 2);
        assert_eq!(handle.scope_cursor(genesis.identity()).await.unwrap().0, 1);
        drop(handle);
        fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn cursor_conflicts_fail_closed_and_invalid_projection_rebuilds() {
        let genesis = genesis();
        let path = path("cursor-conflicts");
        let handle = DbHandle::spawn(path.clone()).await.unwrap();
        handle.apply(root_mutation(&genesis)).await.unwrap();
        side_execute(
            &path,
            "UPDATE scopes SET tail_event_digest = ?1 WHERE scope_id = ?2",
            &[&"f".repeat(64), &genesis.identity().scope_id().as_str()],
        );
        let (store, _) = replay_store(vec![head_response(genesis.head_bytes().to_vec())]);
        assert!(matches!(
            refresh(&store, &handle, genesis.identity()).await,
            ScopeReadiness::NotReady(ScopeReplayError::TailMismatch)
        ));

        side_execute(
            &path,
            "UPDATE scopes SET sequence = 2 WHERE scope_id = ?1",
            &[&genesis.identity().scope_id().as_str()],
        );
        let (store, _) = replay_store(vec![head_response(genesis.head_bytes().to_vec())]);
        assert!(matches!(
            refresh(&store, &handle, genesis.identity()).await,
            ScopeReadiness::NotReady(ScopeReplayError::CursorAhead)
        ));
        drop(handle);

        // A foreign application id is unrelated local data, so the file survives.
        let foreign = rusqlite::Connection::open(&path).unwrap();
        foreign
            .pragma_update(None, "application_id", 0x1234)
            .unwrap();
        drop(foreign);
        assert!(matches!(
            open_projection(&path).await,
            Err(ScopeReplayError::DatabaseUnavailable)
        ));
        assert_eq!(
            rusqlite::Connection::open(&path)
                .unwrap()
                .pragma_query_value(None, "application_id", |row| row.get::<_, i32>(0))
                .unwrap(),
            0x1234
        );

        fs::write(&path, b"not-a-database".repeat(512)).unwrap();
        let sidecars = [
            PathBuf::from(format!("{}-journal", path.display())),
            PathBuf::from(format!("{}-wal", path.display())),
            PathBuf::from(format!("{}-shm", path.display())),
        ];
        for sidecar in &sidecars {
            fs::write(sidecar, b"stale").unwrap();
        }
        let rebuilt = open_projection(&path).await.unwrap();
        // A rebuilt projection is empty and carries the neutral application id.
        assert_eq!(
            rebuilt.scope_cursor(genesis.identity()).await.unwrap(),
            (0, None)
        );
        assert!(sidecars.iter().all(|sidecar| !sidecar.exists()));
        drop(rebuilt);
        assert_eq!(
            rusqlite::Connection::open(&path)
                .unwrap()
                .pragma_query_value(None, "application_id", |row| row.get::<_, i32>(0))
                .unwrap(),
            0x5241_564c
        );
        fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn database_failure_keeps_a_valid_committed_prefix_not_ready() {
        let genesis = genesis();
        let path = path("committed-prefix");
        let handle = DbHandle::spawn(path.clone()).await.unwrap();
        rusqlite::Connection::open(&path)
            .unwrap()
            .execute_batch(
                "CREATE TRIGGER fail_second_event BEFORE INSERT ON applied_scope_events \
                 WHEN NEW.sequence = 2 BEGIN SELECT RAISE(ABORT, 'injected'); END;",
            )
            .unwrap();
        let successor_envelope = EventEnvelope::new(
            genesis.identity().scope_id().clone(),
            2,
            Some(genesis.event_ref().clone()),
            1,
            "successor".into(),
            TEST_SUCCESSOR_PAYLOAD_TYPE.into(),
        )
        .unwrap();
        let successor = encode_scope_event(&successor_envelope, &Value::Null).unwrap();
        let successor_head = ScopeHead::new(
            genesis.identity().clone(),
            ScopeAuthority::Unowned,
            1,
            successor.event_ref().clone(),
            None,
            "successor".into(),
        )
        .unwrap();
        let (store, _) = replay_store(vec![
            head_response(encode_head(&successor_head).unwrap()),
            event_response(successor.stored_bytes().to_vec()),
            event_response(genesis.event_bytes().to_vec()),
        ]);
        assert!(matches!(
            refresh(&store, &handle, genesis.identity()).await,
            ScopeReadiness::NotReady(ScopeReplayError::Apply(ApplyError::DatabaseOperationFailed))
        ));
        assert_eq!(
            handle.scope_cursor(genesis.identity()).await.unwrap(),
            (1, Some(genesis.event_ref().digest().clone()))
        );
        drop(handle);
        rusqlite::Connection::open(&path)
            .unwrap()
            .execute_batch("DROP TRIGGER fail_second_event")
            .unwrap();
        // The committed prefix is still a valid projection after the injected failure.
        drop(projections::open_existing(&path).unwrap());
        fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn byte_limit_is_inclusive_and_errors_do_not_echo_inputs() {
        assert_eq!(
            checked_total(64 * 1024 * 1024 - 1, 1, LIMITS.bytes),
            Ok(LIMITS.bytes)
        );
        assert_eq!(
            checked_total(LIMITS.bytes, 1, LIMITS.bytes),
            Err(ScopeReplayError::Overflow)
        );
        assert!(
            !ScopeReplayError::EventStorage
                .to_string()
                .contains("malicious/internal/key")
        );
        assert!(open_projection(Path::new(":memory:")).await.is_err());
        assert!(
            open_projection(Path::new("file:scope.sqlite3"))
                .await
                .is_err()
        );
        let non_utf8 = std::ffi::OsString::from_vec(b"file:scope.sqlite3?mode=memory\xff".to_vec());
        assert!(is_sqlite_uri(Path::new(&non_utf8)));
        assert!(open_projection(Path::new(&non_utf8)).await.is_err());
    }

    /// Builds one canonical chain of `LIMITS.events` events: root genesis at sequence 1 and
    /// test-only successors above it.
    #[cfg(target_os = "linux")]
    fn benchmark_chain(
        genesis: &crate::scope::RootGenesis,
    ) -> (Vec<Vec<u8>>, Vec<crate::scope::ScopeEventRef>) {
        let mut bytes = Vec::with_capacity(LIMITS.events as usize);
        let mut references = Vec::with_capacity(LIMITS.events as usize);
        bytes.push(genesis.event_bytes().to_vec());
        references.push(genesis.event_ref().clone());
        for sequence in 2..=LIMITS.events {
            let parent = references[(sequence - 2) as usize].clone();
            let envelope = EventEnvelope::new(
                genesis.identity().scope_id().clone(),
                sequence,
                Some(parent),
                1,
                format!("benchmark-operation-{sequence}"),
                TEST_SUCCESSOR_PAYLOAD_TYPE.into(),
            )
            .unwrap();
            let encoded = encode_scope_event(&envelope, &Value::Null).unwrap();
            bytes.push(encoded.stored_bytes().to_vec());
            references.push(encoded.event_ref().clone());
        }
        (bytes, references)
    }

    #[cfg(target_os = "linux")]
    async fn benchmark_sample(
        genesis: &crate::scope::RootGenesis,
        size: usize,
        sample: &str,
        bytes: &[Vec<u8>],
        references: &[crate::scope::ScopeEventRef],
    ) -> Duration {
        let path = PathBuf::from(format!(
            "/dev/shm/ravel-scope-replay-growth-{}-{size}-{sample}.sqlite3",
            process::id()
        ));
        let _ = fs::remove_file(&path);
        let head = ScopeHead::new(
            genesis.identity().clone(),
            ScopeAuthority::Unowned,
            1,
            references[size - 1].clone(),
            None,
            format!("benchmark-operation-{size}"),
        )
        .unwrap();
        let mut responses = Vec::with_capacity(size + 1);
        responses.push(head_response(encode_head(&head).unwrap()));
        responses.extend(
            (0..size)
                .rev()
                .map(|index| event_response(bytes[index].clone())),
        );
        let (store, _) = replay_store(responses);
        let handle = DbHandle::spawn(path.clone()).await.unwrap();

        let started = Instant::now();
        let readiness = refresh(&store, &handle, genesis.identity()).await;
        let elapsed = started.elapsed();
        match readiness {
            ScopeReadiness::Ready { local_cursor, .. } => {
                assert_eq!(local_cursor.0, size as u64);
                assert_eq!(local_cursor.1, *references[size - 1].digest());
            }
            ScopeReadiness::NotReady(error) => panic!("benchmark replay failed: {error}"),
        }

        drop(handle);
        let _ = fs::remove_file(&path);
        elapsed
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "55s growth gate: cargo test -- --ignored"]
    async fn replay_growth_stays_subquadratic() {
        const SIZES: [usize; 5] = [256, 512, 1_024, 2_048, 4_096];
        assert_eq!(SIZES.last().copied(), Some(LIMITS.events as usize));
        // Tmpfs keeps fixed filesystem latency from hiding history-dependent growth. Minimums
        // reduce one-sided scheduler noise. Quadratic work approaches 4x per doubling and 256x
        // end-to-end; the gates leave margin around the expected 2x and 16x linear growth.
        let probe = PathBuf::from(format!(
            "/dev/shm/ravel-scope-replay-growth-probe-{}",
            process::id()
        ));
        if fs::write(&probe, b"probe").is_err() {
            eprintln!("skipping replay growth gate: /dev/shm is unavailable or unwritable");
            return;
        }
        let _ = fs::remove_file(probe);

        let genesis = genesis();
        let (bytes, references) = benchmark_chain(&genesis);
        let _ = benchmark_sample(&genesis, 256, "warmup", &bytes, &references).await;
        let mut minimums = Vec::with_capacity(SIZES.len());
        for size in SIZES {
            let mut samples = Vec::with_capacity(3);
            for sample in 0..3 {
                samples.push(
                    benchmark_sample(
                        &genesis,
                        size,
                        &format!("sample-{sample}"),
                        &bytes,
                        &references,
                    )
                    .await,
                );
            }
            minimums.push(samples.into_iter().min().unwrap());
        }
        let minimum_millis: Vec<u128> = minimums.iter().map(Duration::as_millis).collect();
        assert!(
            minimums
                .windows(2)
                .all(|pair| pair[1].as_nanos() < pair[0].as_nanos() * 3),
            "replay growth exceeded 3x: sizes={SIZES:?} minimum-ms={minimum_millis:?}"
        );
        assert!(
            minimums.last().unwrap().as_nanos() < minimums.first().unwrap().as_nanos() * 32,
            "replay endpoint growth exceeded 32x: sizes={SIZES:?} minimum-ms={minimum_millis:?}"
        );
    }

    /// A controller that acquires and renews authority advances the scope epoch without
    /// publishing an event, so the genesis writer epoch legitimately lags the head epoch.
    #[tokio::test]
    async fn a_head_at_a_higher_epoch_replays_a_lagging_writer_epoch() {
        let genesis = genesis();
        let path = path("epoch-lag");
        let handle = DbHandle::spawn(path.clone()).await.unwrap();
        let owned = ScopeHead::new(
            genesis.identity().clone(),
            ScopeAuthority::owned(InstanceId::new("instance-a".into()).unwrap(), 31_000).unwrap(),
            3,
            genesis.event_ref().clone(),
            None,
            genesis.head().operation_id().to_owned(),
        )
        .unwrap();
        let (store, _) = replay_store(vec![
            head_response(encode_head(&owned).unwrap()),
            event_response(genesis.event_bytes().to_vec()),
        ]);
        assert!(matches!(
            refresh(&store, &handle, genesis.identity()).await,
            ScopeReadiness::Ready { .. }
        ));
        assert_eq!(
            handle.scope_cursor(genesis.identity()).await.unwrap(),
            (1, Some(genesis.event_ref().digest().clone()))
        );

        // A relinquished head at the same epoch keeps the projection ready.
        let relinquished = ScopeHead::new(
            genesis.identity().clone(),
            ScopeAuthority::Unowned,
            4,
            genesis.event_ref().clone(),
            None,
            genesis.head().operation_id().to_owned(),
        )
        .unwrap();
        let (store, _) = replay_store(vec![head_response(encode_head(&relinquished).unwrap())]);
        assert!(matches!(
            refresh(&store, &handle, genesis.identity()).await,
            ScopeReadiness::Ready { .. }
        ));

        // A head below the projected epoch is stale evidence.
        let (store, _) = replay_store(vec![head_response(genesis.head_bytes().to_vec())]);
        assert!(matches!(
            refresh(&store, &handle, genesis.identity()).await,
            ScopeReadiness::NotReady(ScopeReplayError::HistoryConflict)
        ));

        drop(handle);
        fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn an_event_above_the_head_epoch_fails_closed() {
        let genesis = genesis();
        let path = path("epoch-ahead");
        let handle = DbHandle::spawn(path.clone()).await.unwrap();
        let envelope = EventEnvelope::new(
            genesis.identity().scope_id().clone(),
            2,
            Some(genesis.event_ref().clone()),
            5,
            "ahead-op".into(),
            TEST_SUCCESSOR_PAYLOAD_TYPE.into(),
        )
        .unwrap();
        let encoded = encode_scope_event(&envelope, &Value::Null).unwrap();
        let head = ScopeHead::new(
            genesis.identity().clone(),
            ScopeAuthority::owned(InstanceId::new("instance-a".into()).unwrap(), 31_000).unwrap(),
            4,
            encoded.event_ref().clone(),
            None,
            "ahead-op".into(),
        )
        .unwrap();
        let (store, _) = replay_store(vec![
            head_response(encode_head(&head).unwrap()),
            event_response(encoded.stored_bytes().to_vec()),
        ]);
        assert!(matches!(
            refresh(&store, &handle, genesis.identity()).await,
            ScopeReadiness::NotReady(ScopeReplayError::HistoryConflict)
        ));
        assert_eq!(
            handle.scope_cursor(genesis.identity()).await.unwrap(),
            (0, None)
        );
        drop(handle);
        fs::remove_file(path).unwrap();
    }

    /// The chain is walked newest to oldest, so a parent whose writer epoch exceeds its child's
    /// is a superseded writer spliced under a newer event.
    #[tokio::test]
    async fn a_parent_above_its_child_writer_epoch_fails_closed() {
        let genesis = genesis();
        let path = path("epoch-inversion");
        let handle = DbHandle::spawn(path.clone()).await.unwrap();
        let first = EventEnvelope::new(
            genesis.identity().scope_id().clone(),
            1,
            None,
            3,
            "inverted-root".into(),
            TEST_SUCCESSOR_PAYLOAD_TYPE.into(),
        )
        .unwrap();
        let first_encoded = encode_scope_event(&first, &Value::Null).unwrap();
        let second = EventEnvelope::new(
            genesis.identity().scope_id().clone(),
            2,
            Some(first_encoded.event_ref().clone()),
            2,
            "inverted-child".into(),
            TEST_SUCCESSOR_PAYLOAD_TYPE.into(),
        )
        .unwrap();
        let second_encoded = encode_scope_event(&second, &Value::Null).unwrap();
        let head = ScopeHead::new(
            genesis.identity().clone(),
            ScopeAuthority::owned(InstanceId::new("instance-a".into()).unwrap(), 31_000).unwrap(),
            3,
            second_encoded.event_ref().clone(),
            None,
            "inverted-child".into(),
        )
        .unwrap();
        let (store, _) = replay_store(vec![
            head_response(encode_head(&head).unwrap()),
            event_response(second_encoded.stored_bytes().to_vec()),
            event_response(first_encoded.stored_bytes().to_vec()),
        ]);
        assert!(matches!(
            refresh(&store, &handle, genesis.identity()).await,
            ScopeReadiness::NotReady(ScopeReplayError::HistoryConflict)
        ));
        assert_eq!(
            handle.scope_cursor(genesis.identity()).await.unwrap(),
            (0, None)
        );
        drop(handle);
        fs::remove_file(path).unwrap();
    }

    /// A deleted projection is rebuilt from durable history alone: genesis, the admission event,
    /// and the plan object reproduce the same plan, work, dependencies, bounds, and reservation.
    #[tokio::test]
    async fn replay_reconstructs_an_admitted_plan_from_durable_history() {
        use crate::domain::proposal::{
            PlanProposal, ProposalBasis, ProposalFacts, TargetBounds, WorkSpec, validate_proposal,
        };
        use crate::domain::work::WorkId;
        use crate::scope::{PlanAdmittedEvent, PlanAdmittedPayload, encode_plan_admitted_event};

        let genesis = genesis();
        let scope = genesis.identity().clone();
        let objective = genesis.config_digest().clone();
        let proposal = PlanProposal::new(
            scope.scope_id().clone(),
            objective.clone(),
            None,
            vec![ProposalBasis::Observation {
                event: genesis.event_ref().clone(),
            }],
            vec![
                WorkSpec::new(
                    WorkId::new("work-a".into()).unwrap(),
                    Vec::new(),
                    TargetBounds::new(2, 60_000).unwrap(),
                ),
                WorkSpec::new(
                    WorkId::new("work-b".into()).unwrap(),
                    vec![WorkId::new("work-a".into()).unwrap()],
                    TargetBounds::new(2, 60_000).unwrap(),
                ),
            ],
            11,
        );
        let facts = [crate::domain::proposal::ObservationFact::new(
            scope.scope_id().clone(),
            genesis.event_ref().clone(),
            ROOT_GENESIS_PAYLOAD_TYPE.to_owned(),
        )];
        let admissible = validate_proposal(
            &proposal,
            &ProposalFacts::new(&scope, &objective, None, 1, &facts),
        )
        .unwrap();
        let event = PlanAdmittedEvent::new(
            EventEnvelope::new(
                scope.scope_id().clone(),
                2,
                Some(genesis.event_ref().clone()),
                1,
                "admit-plan-1".into(),
                crate::scope::PLAN_ADMITTED_PAYLOAD_TYPE.to_owned(),
            )
            .unwrap(),
            PlanAdmittedPayload::new(admissible.plan_digest().clone()),
        )
        .unwrap();
        let encoded = encode_plan_admitted_event(&event).unwrap();
        let head = ScopeHead::new(
            scope.clone(),
            ScopeAuthority::Unowned,
            1,
            encoded.event_ref().clone(),
            Some(admissible.plan_digest().clone()),
            "admit-plan-1".into(),
        )
        .unwrap();

        let responses = || {
            vec![
                head_response(encode_head(&head).unwrap()),
                event_response(encoded.stored_bytes().to_vec()),
                response(
                    200,
                    &[("etag", "\"plan\"")],
                    admissible.stored_bytes().to_vec(),
                ),
                event_response(genesis.event_bytes().to_vec()),
                response(404, &[], Vec::new()),
                response(404, &[], Vec::new()),
            ]
        };
        // Comparing complete rows detects incorrect revisions, plan digests, attempt limits, and
        // deadlines even when row counts match.
        let admitted_rows = |path: &Path| {
            let connection = rusqlite::Connection::open(path).unwrap();
            let scope_row = connection
                .query_row(
                    "SELECT (SELECT active_plan_digest FROM scopes), \
                     (SELECT reserved_budget_units FROM scopes), \
                     (SELECT objective_digest FROM scopes)",
                    [],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, String>(2)?,
                        ))
                    },
                )
                .unwrap();
            let work_rows = connection
                .prepare(
                    "SELECT work_id, work_revision, plan_digest, max_attempts, deadline_unix_ms \
                     FROM admitted_work ORDER BY work_id",
                )
                .unwrap()
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                    ))
                })
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            let edges = connection
                .prepare(
                    "SELECT work_id, depends_on_work_id, depends_on_work_revision \
                     FROM work_dependencies ORDER BY work_id",
                )
                .unwrap()
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                })
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            (scope_row, work_rows, edges)
        };

        let path = path("replay-admission");
        let handle = DbHandle::spawn(path.clone()).await.unwrap();
        let (store, _) = replay_store(responses());
        assert!(matches!(
            refresh(&store, &handle, &scope).await,
            ScopeReadiness::Ready { .. }
        ));
        drop(handle);
        let first = admitted_rows(&path);
        assert_eq!(
            first,
            (
                (
                    admissible.plan_digest().as_str().to_owned(),
                    11,
                    objective.as_str().to_owned(),
                ),
                vec![
                    (
                        "work-a".to_owned(),
                        1,
                        admissible.plan_digest().as_str().to_owned(),
                        2,
                        60_000,
                    ),
                    (
                        "work-b".to_owned(),
                        1,
                        admissible.plan_digest().as_str().to_owned(),
                        2,
                        60_000,
                    ),
                ],
                vec![("work-b".to_owned(), "work-a".to_owned(), 1)],
            )
        );

        // Delete the file and replay the identical durable history: the rebuilt projection is
        // byte-for-byte the same admission state.
        fs::remove_file(&path).unwrap();
        let handle = DbHandle::spawn(path.clone()).await.unwrap();
        let (store, _) = replay_store(responses());
        assert!(matches!(
            refresh(&store, &handle, &scope).await,
            ScopeReadiness::Ready { .. }
        ));
        drop(handle);
        assert_eq!(admitted_rows(&path), first);

        // Reject a head whose plan digest differs from its admission event's plan digest.
        let disagreeing = ScopeHead::new(
            scope.clone(),
            ScopeAuthority::Unowned,
            1,
            encoded.event_ref().clone(),
            Some(Digest::new("a".repeat(64)).unwrap()),
            "admit-plan-1".into(),
        )
        .unwrap();
        fs::remove_file(&path).unwrap();
        let handle = DbHandle::spawn(path.clone()).await.unwrap();
        let (store, _) = replay_store(vec![
            head_response(encode_head(&disagreeing).unwrap()),
            event_response(encoded.stored_bytes().to_vec()),
            response(
                200,
                &[("etag", "\"plan\"")],
                admissible.stored_bytes().to_vec(),
            ),
            event_response(genesis.event_bytes().to_vec()),
        ]);
        assert!(matches!(
            refresh(&store, &handle, &scope).await,
            ScopeReadiness::NotReady(ScopeReplayError::HistoryConflict)
        ));
        drop(handle);
        // The projection holds the event's admission, not the head's claim.
        assert_eq!(admitted_rows(&path), first);
        fs::remove_file(&path).unwrap();
    }
    /// Shared fixture for the grant round-trip tests: a validated two-work proposal, its
    /// admission event at sequence 2, and the unowned head that activates it.
    struct AdmittedFixture {
        scope: ScopeIdentity,
        plan_digest: Digest,
        admissible_bytes: Vec<u8>,
        admission_bytes: Vec<u8>,
        head_bytes: Vec<u8>,
    }

    fn admitted_fixture(genesis: &crate::scope::RootGenesis, now_ms: u64) -> AdmittedFixture {
        use crate::domain::proposal::{
            ObservationFact, PlanProposal, ProposalBasis, ProposalFacts, TargetBounds, WorkSpec,
            validate_proposal,
        };
        use crate::domain::work::WorkId;
        use crate::scope::{PlanAdmittedEvent, PlanAdmittedPayload, encode_plan_admitted_event};

        let scope = genesis.identity().clone();
        let objective = genesis.config_digest().clone();
        let proposal = PlanProposal::new(
            scope.scope_id().clone(),
            objective.clone(),
            None,
            vec![ProposalBasis::Observation {
                event: genesis.event_ref().clone(),
            }],
            vec![
                WorkSpec::new(
                    WorkId::new("work-a".into()).unwrap(),
                    Vec::new(),
                    TargetBounds::new(3, now_ms + 600_000).unwrap(),
                ),
                WorkSpec::new(
                    WorkId::new("work-b".into()).unwrap(),
                    Vec::new(),
                    TargetBounds::new(3, now_ms + 600_000).unwrap(),
                ),
            ],
            100,
        );
        let facts = [ObservationFact::new(
            scope.scope_id().clone(),
            genesis.event_ref().clone(),
            ROOT_GENESIS_PAYLOAD_TYPE.to_owned(),
        )];
        let admissible = validate_proposal(
            &proposal,
            &ProposalFacts::new(&scope, &objective, None, 1, &facts),
        )
        .unwrap();
        let event = PlanAdmittedEvent::new(
            EventEnvelope::new(
                scope.scope_id().clone(),
                2,
                Some(genesis.event_ref().clone()),
                1,
                "admit-plan-1".into(),
                crate::scope::PLAN_ADMITTED_PAYLOAD_TYPE.to_owned(),
            )
            .unwrap(),
            PlanAdmittedPayload::new(admissible.plan_digest().clone()),
        )
        .unwrap();
        let encoded = encode_plan_admitted_event(&event).unwrap();
        let head = ScopeHead::new(
            scope.clone(),
            ScopeAuthority::Unowned,
            1,
            encoded.event_ref().clone(),
            Some(admissible.plan_digest().clone()),
            "admit-plan-1".into(),
        )
        .unwrap();
        AdmittedFixture {
            scope,
            plan_digest: admissible.plan_digest().clone(),
            admissible_bytes: admissible.stored_bytes().to_vec(),
            admission_bytes: encoded.stored_bytes().to_vec(),
            head_bytes: encode_head(&head).unwrap(),
        }
    }

    fn claim_object(
        fixture: &AdmittedFixture,
        work: &crate::domain::work::WorkRef,
        fence: u64,
        state: crate::distributed::claims::ScopeClaimState,
        operation: &str,
    ) -> Vec<u8> {
        claim_object_for_plan(fixture, &fixture.plan_digest, work, fence, state, operation)
    }

    fn claim_object_for_plan(
        fixture: &AdmittedFixture,
        plan_digest: &Digest,
        work: &crate::domain::work::WorkRef,
        fence: u64,
        state: crate::distributed::claims::ScopeClaimState,
        operation: &str,
    ) -> Vec<u8> {
        use crate::distributed::claims::{ScopeClaim, encode_claim};
        use crate::distributed::identity::ActorId;
        encode_claim(
            &ScopeClaim::new(
                crate::scope::ScopeClaimIdentity::new(
                    fixture.scope.clone(),
                    plan_digest.clone(),
                    work.clone(),
                    fence,
                )
                .unwrap(),
                ActorId::new("actor-a".into()).unwrap(),
                InstanceId::new("worker-a".into()).unwrap(),
                operation.to_owned(),
                state,
            )
            .unwrap(),
        )
        .unwrap()
    }

    async fn issue_ok(
        store: &S3Store,
        handle: &DbHandle,
        authority: crate::distributed::scope_controller::ControllerAuthority,
        grant: &crate::distributed::grants::EffectGrant,
        now_ms: u64,
    ) -> crate::distributed::scope_controller::ControllerAuthority {
        use crate::storage::s3::AttemptHistory;
        let [mut object, mut event, mut head] = [
            AttemptHistory::default(),
            AttemptHistory::default(),
            AttemptHistory::default(),
        ];
        match crate::distributed::grants::issue(
            store,
            handle,
            authority,
            grant,
            [&mut object, &mut event, &mut head],
            now_ms,
        )
        .await
        {
            crate::distributed::grants::IssueOutcome::Issued(refreshed) => refreshed,
            _ => panic!("expected issuance"),
        }
    }

    /// The scheduling-relevant columns of one admitted row.
    /// `admitted_scope_epoch` is authority provenance, not scheduling state: a rebuild replays
    /// under the current head epoch, so that one column may legitimately differ.
    #[derive(Debug, Eq, PartialEq)]
    struct SchedulingRow {
        work_id: String,
        work_revision: i64,
        plan_digest: String,
        max_attempts: i64,
        deadline_unix_ms: i64,
        claim_fence: Option<i64>,
        claim_lease_until: Option<i64>,
        grant_fence: Option<i64>,
        grant_digest: Option<String>,
        granted_attempt: Option<i64>,
        granted_units: Option<i64>,
        grant_deadline_unix_ms: Option<i64>,
        terminal_result_digest: Option<String>,
    }

    fn scheduling_rows(path: &Path) -> Vec<SchedulingRow> {
        rusqlite::Connection::open(path)
            .unwrap()
            .prepare(
                "SELECT work_id, work_revision, plan_digest, max_attempts, deadline_unix_ms, \
                 claim_fence, claim_lease_until, grant_fence, grant_digest, granted_attempt, \
                 granted_units, grant_deadline_unix_ms, terminal_result_digest \
                 FROM admitted_work ORDER BY work_id",
            )
            .unwrap()
            .query_map([], |row| {
                Ok(SchedulingRow {
                    work_id: row.get(0)?,
                    work_revision: row.get(1)?,
                    plan_digest: row.get(2)?,
                    max_attempts: row.get(3)?,
                    deadline_unix_ms: row.get(4)?,
                    claim_fence: row.get(5)?,
                    claim_lease_until: row.get(6)?,
                    grant_fence: row.get(7)?,
                    grant_digest: row.get(8)?,
                    granted_attempt: row.get(9)?,
                    granted_units: row.get(10)?,
                    grant_deadline_unix_ms: row.get(11)?,
                    terminal_result_digest: row.get(12)?,
                })
            })
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    }

    /// I4: production writers populate the projection, the file is deleted, and a rebuild from
    /// durable history alone reproduces the scheduling-relevant columns, including the
    /// `granted_units` running total across two fences and the retained-stale-grant row.
    #[tokio::test]
    async fn rebuild_reproduces_grants_and_claims_from_durable_facts() {
        use crate::distributed::claims::ScopeClaimState;
        use crate::distributed::grants::EffectGrant;
        use crate::distributed::scope_controller::{AcquireOutcome, RenewOutcome, acquire, renew};
        use crate::domain::work::{WorkId, WorkRef};

        const NOW: u64 = 1_700_000_000_000;
        let genesis = genesis();
        let fixture = admitted_fixture(&genesis, NOW);
        let scope = fixture.scope.clone();
        let work_a = WorkRef::new(WorkId::new("work-a".into()).unwrap(), 1);
        let work_b = WorkRef::new(WorkId::new("work-b".into()).unwrap(), 1);
        let grant = |work: &WorkRef,
                     fence: u64,
                     attempt: u64,
                     units: u64,
                     deadline: u64,
                     operation: &str| {
            EffectGrant::new(
                crate::scope::ScopeClaimIdentity::new(
                    scope.clone(),
                    fixture.plan_digest.clone(),
                    work.clone(),
                    fence,
                )
                .unwrap(),
                "git-push".into(),
                "repo-a".into(),
                attempt,
                units,
                deadline,
                operation.into(),
            )
            .unwrap()
        };
        // Populate the live projection through the production writers.
        let live_path = path("round-trip-live");
        let handle = DbHandle::spawn(live_path.clone()).await.unwrap();
        let (store, _) = replay_store(vec![
            head_response(fixture.head_bytes.clone()),
            event_response(fixture.admission_bytes.clone()),
            response(
                200,
                &[("etag", "\"plan\"")],
                fixture.admissible_bytes.clone(),
            ),
            event_response(genesis.event_bytes().to_vec()),
            response(404, &[], Vec::new()),
            response(404, &[], Vec::new()),
        ]);
        assert!(matches!(
            refresh(&store, &handle, &scope).await,
            ScopeReadiness::Ready { .. }
        ));
        let fence = |value: u64| std::num::NonZeroU64::new(value).unwrap();
        handle
            .record_claim(&scope, work_a.clone(), fence(2), fence(NOW + 10_000), NOW)
            .await
            .unwrap();
        handle
            .record_claim(&scope, work_b.clone(), fence(2), fence(NOW + 10_000), NOW)
            .await
            .unwrap();

        // One store carries the authority: acquisition, three issuances, and one renewal.
        let (authority_store, client) = replay_store(vec![
            response(200, &[("etag", "\"h0\"")], fixture.head_bytes.clone()),
            response(200, &[("etag", "\"h1\"")], Vec::new()),
            response(200, &[], Vec::new()),
            response(200, &[], Vec::new()),
            response(200, &[("etag", "\"h2\"")], Vec::new()),
            response(200, &[], Vec::new()),
            response(200, &[], Vec::new()),
            response(200, &[("etag", "\"h3\"")], Vec::new()),
            response(200, &[], Vec::new()),
            response(200, &[], Vec::new()),
            response(200, &[("etag", "\"h4\"")], Vec::new()),
            response(200, &[("etag", "\"h5\"")], Vec::new()),
        ]);
        let outcome = acquire(
            &authority_store,
            &scope,
            &InstanceId::new("instance-a".into()).unwrap(),
            NOW,
        )
        .await
        .unwrap();
        let AcquireOutcome::Acquired(mut authority) = outcome else {
            panic!("expected acquisition");
        };
        for (grant, now_ms) in [
            (grant(&work_a, 2, 1, 7, NOW + 20_000, "grant-a-f2"), NOW),
            (grant(&work_b, 2, 1, 5, NOW + 20_000, "grant-b-f2"), NOW),
        ] {
            authority = issue_ok(&authority_store, &handle, authority, &grant, now_ms).await;
        }
        // The fence-2 leases lapse, both works reclaim at fence 3, and only work-a draws again:
        // work-b keeps its fence-2 grant columns beside the fence-3 claim.
        handle
            .record_claim(
                &scope,
                work_a.clone(),
                fence(3),
                fence(NOW + 29_000),
                NOW + 15_000,
            )
            .await
            .unwrap();
        handle
            .record_claim(
                &scope,
                work_b.clone(),
                fence(3),
                fence(NOW + 29_000),
                NOW + 15_000,
            )
            .await
            .unwrap();
        authority = issue_ok(
            &authority_store,
            &handle,
            authority,
            &grant(&work_a, 3, 2, 9, NOW + 25_000, "grant-a-f3"),
            NOW + 16_000,
        )
        .await;
        // T-f: the returned authority renews against the committed head it observed.
        let outcome = renew(&authority_store, authority, NOW + 16_500)
            .await
            .unwrap();
        let RenewOutcome::Renewed(renewed) = outcome else {
            panic!("expected renewal");
        };
        assert_eq!(renewed.scope_epoch().get(), 3);
        let requests = client.actual_requests().collect::<Vec<_>>();
        assert_eq!(requests.len(), 12);
        assert_eq!(requests[11].headers().get("if-match").unwrap(), "\"h4\"");
        let renewed_head = crate::scope::decode_head(
            requests[11].body().bytes().unwrap(),
            &crate::scope::scope_head_key(&scope),
            &scope,
        )
        .unwrap();
        assert_eq!(renewed_head.tail().sequence(), 5);

        handle.drain().await.unwrap();
        drop(handle);
        let live = scheduling_rows(&live_path);
        assert_eq!(live.len(), 2);
        // work-a drew at fences 2 and 3: the running total is both draws.
        assert_eq!(live[0].claim_fence, Some(3));
        assert_eq!(live[0].grant_fence, Some(3));
        assert_eq!(live[0].granted_attempt, Some(2));
        assert_eq!(live[0].granted_units, Some(16));
        // work-b reclaimed to fence 3 without a new grant: the fence-2 grant columns remain.
        assert_eq!(live[1].claim_fence, Some(3));
        assert_eq!(live[1].grant_fence, Some(2));
        assert_eq!(live[1].granted_units, Some(5));

        // Rebuild from durable facts alone: the captured head, events, plan, and claim objects.
        let final_head = requests[10].body().bytes().unwrap().to_vec();
        let event_bytes = |index: usize| requests[index].body().bytes().unwrap().to_vec();
        let rebuild_path = path("round-trip-rebuild");
        let rebuilt = DbHandle::spawn(rebuild_path.clone()).await.unwrap();
        let (store, rebuild_client) = replay_store(vec![
            head_response(final_head.clone()),
            event_response(event_bytes(9)),
            event_response(event_bytes(6)),
            event_response(event_bytes(3)),
            event_response(fixture.admission_bytes.clone()),
            response(
                200,
                &[("etag", "\"plan\"")],
                fixture.admissible_bytes.clone(),
            ),
            event_response(genesis.event_bytes().to_vec()),
            response(
                200,
                &[("etag", "\"claim-a\"")],
                claim_object(
                    &fixture,
                    &work_a,
                    3,
                    ScopeClaimState::Active {
                        lease_until: fence(NOW + 29_000),
                    },
                    "claim-a-3",
                ),
            ),
            response(
                200,
                &[("etag", "\"claim-b\"")],
                claim_object(
                    &fixture,
                    &work_b,
                    3,
                    ScopeClaimState::Active {
                        lease_until: fence(NOW + 29_000),
                    },
                    "claim-b-3",
                ),
            ),
        ]);
        assert!(matches!(
            refresh(&store, &rebuilt, &scope).await,
            ScopeReadiness::Ready { .. }
        ));
        // D1: rebuild folds grant facts from events and never addresses a grant object.
        assert!(
            rebuild_client
                .actual_requests()
                .all(|request| !request.uri().contains("/grants/"))
        );
        // The completed restore is durable, so a routine refresh reads the head and no claim
        // objects.
        let (routine_store, routine_client) = replay_store(vec![head_response(final_head)]);
        assert!(matches!(
            refresh(&routine_store, &rebuilt, &scope).await,
            ScopeReadiness::Ready { .. }
        ));
        assert_eq!(routine_client.actual_requests().count(), 1);
        assert!(
            routine_client
                .actual_requests()
                .all(|request| !request.uri().contains("/claims/"))
        );
        rebuilt.drain().await.unwrap();
        drop(rebuilt);
        assert_eq!(scheduling_rows(&rebuild_path), live);

        fs::remove_file(live_path).unwrap();
        fs::remove_file(rebuild_path).unwrap();
    }

    /// I6: a grant object with no committed activation event stays inert through a rebuild, and
    /// a sealed claim restores nothing.
    #[tokio::test]
    async fn a_published_but_uncommitted_grant_stays_inert_through_rebuild() {
        use crate::distributed::claims::ScopeClaimState;
        use crate::domain::artifact::ArtifactRef;
        use crate::domain::work::{WorkId, WorkRef};

        const NOW: u64 = 1_700_000_000_000;
        let genesis = genesis();
        let fixture = admitted_fixture(&genesis, NOW);
        let scope = fixture.scope.clone();
        let work_a = WorkRef::new(WorkId::new("work-a".into()).unwrap(), 1);
        let work_b = WorkRef::new(WorkId::new("work-b".into()).unwrap(), 1);
        let fence = |value: u64| std::num::NonZeroU64::new(value).unwrap();

        let db_path = path("inert-grant");
        let handle = DbHandle::spawn(db_path.clone()).await.unwrap();
        // The trailing response simulates the publish-succeeded/append-failed window: a grant
        // object sits at its fence key, and the rebuild must never request it.
        let (store, client) = replay_store(vec![
            head_response(fixture.head_bytes.clone()),
            event_response(fixture.admission_bytes.clone()),
            response(
                200,
                &[("etag", "\"plan\"")],
                fixture.admissible_bytes.clone(),
            ),
            event_response(genesis.event_bytes().to_vec()),
            response(
                200,
                &[("etag", "\"claim-a\"")],
                claim_object(
                    &fixture,
                    &work_a,
                    2,
                    ScopeClaimState::Active {
                        lease_until: fence(NOW + 10_000),
                    },
                    "claim-a-2",
                ),
            ),
            response(
                200,
                &[("etag", "\"claim-b\"")],
                claim_object(
                    &fixture,
                    &work_b,
                    2,
                    ScopeClaimState::Sealed {
                        submission: ArtifactRef::new(
                            "ab".repeat(32),
                            64,
                            "application/json".into(),
                            "attempt-1".into(),
                            NOW,
                            None,
                        )
                        .unwrap(),
                    },
                    "claim-b-2",
                ),
            ),
            response(200, &[("etag", "\"planted-grant\"")], b"planted".to_vec()),
        ]);
        assert!(matches!(
            refresh(&store, &handle, &scope).await,
            ScopeReadiness::Ready { .. }
        ));
        assert_eq!(client.actual_requests().count(), 6);
        assert!(
            client
                .actual_requests()
                .all(|request| !request.uri().contains("/grants/"))
        );
        handle.drain().await.unwrap();
        drop(handle);
        let rows = scheduling_rows(&db_path);
        assert_eq!(rows.len(), 2);
        // work-a: the active claim restores, and no grant column is populated.
        assert_eq!(rows[0].claim_fence, Some(2));
        assert_eq!(rows[0].claim_lease_until, Some((NOW + 10_000) as i64));
        assert_eq!(rows[0].grant_fence, None);
        assert_eq!(rows[0].grant_digest, None);
        // work-b: a sealed claim restores nothing at all.
        assert_eq!(rows[1].claim_fence, None);
        assert_eq!(rows[1].claim_lease_until, None);
        assert_eq!(rows[1].grant_fence, None);
        assert_eq!(rows[1].terminal_result_digest, None);
        fs::remove_file(db_path).unwrap();
    }

    /// A retry meets a row a partial restore already populated whose claim object has since
    /// advanced to a higher fence: the stale row is kept fail-closed and the restore completes
    /// instead of wedging on the rejection.
    #[tokio::test]
    async fn a_restore_retry_skips_a_row_whose_claim_object_advanced() {
        use crate::distributed::claims::ScopeClaimState;
        use crate::domain::work::{WorkId, WorkRef};

        const NOW: u64 = 1_700_000_000_000;
        let genesis = genesis();
        let fixture = admitted_fixture(&genesis, NOW);
        let scope = fixture.scope.clone();
        let work_a = WorkRef::new(WorkId::new("work-a".into()).unwrap(), 1);
        let fence = |value: u64| std::num::NonZeroU64::new(value).unwrap();

        let db_path = path("restore-retry-skip");
        let handle = DbHandle::spawn(db_path.clone()).await.unwrap();
        let (store, client) = replay_store(vec![
            // First refresh: replay admits both works, work-a's claim restores at fence 2,
            // then work-b's claim GET returns 500, so claims_restored remains false.
            head_response(fixture.head_bytes.clone()),
            event_response(fixture.admission_bytes.clone()),
            response(
                200,
                &[("etag", "\"plan\"")],
                fixture.admissible_bytes.clone(),
            ),
            event_response(genesis.event_bytes().to_vec()),
            response(
                200,
                &[("etag", "\"claim-a\"")],
                claim_object(
                    &fixture,
                    &work_a,
                    2,
                    ScopeClaimState::Active {
                        lease_until: fence(NOW + 10_000),
                    },
                    "claim-a-2",
                ),
            ),
            response(500, &[], Vec::new()),
            // Retry: work-a's claim object has fence 3 while its restored row has fence 2 and
            // a live lease, and work-b's claim never existed.
            head_response(fixture.head_bytes.clone()),
            response(
                200,
                &[("etag", "\"claim-a-3\"")],
                claim_object(
                    &fixture,
                    &work_a,
                    3,
                    ScopeClaimState::Active {
                        lease_until: fence(NOW + 20_000),
                    },
                    "claim-a-3",
                ),
            ),
            response(404, &[], Vec::new()),
        ]);

        assert!(matches!(
            refresh(&store, &handle, &scope).await,
            ScopeReadiness::NotReady { .. }
        ));
        assert!(!handle.claims_restored(&scope).await.unwrap());
        assert!(matches!(
            refresh(&store, &handle, &scope).await,
            ScopeReadiness::Ready { .. }
        ));
        assert!(handle.claims_restored(&scope).await.unwrap());
        assert_eq!(client.actual_requests().count(), 9);

        handle.drain().await.unwrap();
        drop(handle);
        let rows = scheduling_rows(&db_path);
        // The skipped row retains the fence and lease recorded by the partial restore.
        assert_eq!(rows[0].claim_fence, Some(2));
        assert_eq!(rows[0].claim_lease_until, Some((NOW + 10_000) as i64));
        fs::remove_file(db_path).unwrap();
    }

    /// A claim object naming a plan other than the row's admitting plan restores nothing, and the
    /// restore still completes.
    #[tokio::test]
    async fn a_claim_naming_another_plan_restores_nothing() {
        use crate::distributed::claims::ScopeClaimState;
        use crate::domain::work::{WorkId, WorkRef};

        const NOW: u64 = 1_700_000_000_000;
        let genesis = genesis();
        let fixture = admitted_fixture(&genesis, NOW);
        let scope = fixture.scope.clone();
        let work_a = WorkRef::new(WorkId::new("work-a".into()).unwrap(), 1);
        let foreign_plan = Digest::new("f".repeat(64)).unwrap();
        let fence = |value: u64| std::num::NonZeroU64::new(value).unwrap();

        let db_path = path("foreign-plan-claim");
        let handle = DbHandle::spawn(db_path.clone()).await.unwrap();
        let (store, client) = replay_store(vec![
            head_response(fixture.head_bytes.clone()),
            event_response(fixture.admission_bytes.clone()),
            response(
                200,
                &[("etag", "\"plan\"")],
                fixture.admissible_bytes.clone(),
            ),
            event_response(genesis.event_bytes().to_vec()),
            response(
                200,
                &[("etag", "\"claim-a\"")],
                claim_object_for_plan(
                    &fixture,
                    &foreign_plan,
                    &work_a,
                    2,
                    ScopeClaimState::Active {
                        lease_until: fence(NOW + 10_000),
                    },
                    "claim-a-2",
                ),
            ),
            response(404, &[], Vec::new()),
        ]);

        assert!(matches!(
            refresh(&store, &handle, &scope).await,
            ScopeReadiness::Ready { .. }
        ));
        assert_eq!(client.actual_requests().count(), 6);
        assert!(handle.claims_restored(&scope).await.unwrap());

        handle.drain().await.unwrap();
        drop(handle);
        let rows = scheduling_rows(&db_path);
        assert_eq!(rows[0].claim_fence, None);
        assert_eq!(rows[0].claim_lease_until, None);
        fs::remove_file(db_path).unwrap();
    }
}
