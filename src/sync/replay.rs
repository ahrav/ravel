//! Scope replay separates asynchronous object reads from blocking SQLite transactions.
//!
//! Ready output carries the observed head whose tail matches the committed local row.
//! Remote validation completes before the first projection write.
//! Replay limits are 4,096 unseen events and 64 MiB of stored event bytes.

use std::{collections::HashSet, error::Error, fmt, path::Path};

use ciborium::Value;

use crate::{
    db::{
        projections::{ApplyError, ApplyOutcome, ScopeProjectionEvent},
        worker::{DbHandle, OpenExistingError},
    },
    scope::{Digest, ScopeAuthority, ScopeEventRef, ScopeIdentity, root_event_from_decoded},
    storage::s3::S3Store,
};

use super::{
    WireError,
    event::{ScopeEventReadError, payload_registered, read_opaque},
    head::{self, ObservedScopeHead, ScopeHeadReadError},
};

const LIMITS: Limits = Limits {
    events: 4_096,
    bytes: 64 * 1024 * 1024,
};

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
    match prepare_suffix(store, scope, cursor).await {
        Ok(prepared) => match apply_suffix(handle, scope, prepared).await {
            Ok((local_cursor, observed_head)) => ScopeReadiness::Ready {
                local_cursor,
                observed_head: Box::new(observed_head),
            },
            Err(error) => ScopeReadiness::NotReady(error),
        },
        Err(error) => ScopeReadiness::NotReady(error),
    }
}

/// Replaces the file after deterministic local format or history validation failures.
/// Database-operation failures leave the existing file intact.
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
        Err(OpenExistingError::DatabaseOperationFailed) => {
            Err(ScopeReplayError::DatabaseUnavailable)
        }
        Err(OpenExistingError::Validation(_)) => rebuild_projection(path).await,
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
    if !matches!(observed.head().authority(), ScopeAuthority::Unowned)
        || observed.head().scope_epoch().get() != 1
        || observed.head().active_plan_digest().is_some()
    {
        return Err(ScopeReplayError::HeadInvalid(WireError::InvalidValue));
    }
    let events = prepare_chain(
        store,
        scope,
        cursor,
        observed.head().tail().clone(),
        observed.head().scope_epoch().get(),
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
            .scope_contains_operation(scope, event.decoded.envelope().operation_id())
            .await
            .map_err(ScopeReplayError::Apply)?
        {
            return Err(ScopeReplayError::HistoryConflict);
        }
    }
    prepared.events.reverse();
    let head = prepared.observed.head();
    let active_plan = head.active_plan_digest().cloned();
    let scope_epoch = head.scope_epoch().get();
    let mutations = prepared
        .events
        .into_iter()
        .map(|prepared| {
            let reference = prepared.decoded.event_ref().clone();
            #[cfg(test)]
            let envelope = if prepared.decoded.envelope().payload_type()
                == crate::scope::TEST_SUCCESSOR_PAYLOAD_TYPE
            {
                prepared.decoded.envelope().clone()
            } else {
                root_event_from_decoded(prepared.decoded, scope)
                    .map_err(ScopeReplayError::EventInvalid)?
                    .envelope()
                    .clone()
            };
            #[cfg(not(test))]
            let envelope = root_event_from_decoded(prepared.decoded, scope)
                .map_err(ScopeReplayError::EventInvalid)?
                .envelope()
                .clone();
            ScopeProjectionEvent::new(
                scope.clone(),
                envelope,
                reference,
                active_plan.clone(),
                scope_epoch,
            )
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

async fn prepare_chain(
    store: &S3Store,
    scope: &ScopeIdentity,
    cursor: (u64, Option<Digest>),
    tail: ScopeEventRef,
    scope_epoch: u64,
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
            || decoded.envelope().writer_epoch().get() != scope_epoch
            || !operations.insert(decoded.envelope().operation_id().to_owned())
        {
            return Err(ScopeReplayError::HistoryConflict);
        }
        if !payload_registered(decoded.envelope()) {
            return Err(ScopeReplayError::UnsupportedPayload);
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
        prepared.push(Prepared { decoded });
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

fn is_sqlite_uri(path: &Path) -> bool {
    let Some(text) = path.to_str() else {
        return false;
    };
    text == ":memory:" || text.starts_with("file:")
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
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
            None,
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
            event_response(genesis.event_bytes().to_vec()),
        ]);
        assert!(matches!(
            refresh(&store, &handle, genesis.identity()).await,
            ScopeReadiness::NotReady(ScopeReplayError::EventInvalid(_))
        ));
        assert_eq!(client.actual_requests().count(), 3);
        assert_eq!(
            handle.scope_cursor(genesis.identity()).await.unwrap(),
            (0, None)
        );

        let invalid_heads = [
            ScopeHead::new(
                genesis.identity().clone(),
                ScopeAuthority::owned(InstanceId::new("instance-a".into()).unwrap(), 1).unwrap(),
                1,
                genesis.event_ref().clone(),
                None,
                "invalid-owned-head".into(),
            )
            .unwrap(),
            ScopeHead::new(
                genesis.identity().clone(),
                ScopeAuthority::Unowned,
                2,
                genesis.event_ref().clone(),
                None,
                "invalid-epoch-head".into(),
            )
            .unwrap(),
            ScopeHead::new(
                genesis.identity().clone(),
                ScopeAuthority::Unowned,
                1,
                genesis.event_ref().clone(),
                Some(Digest::new("a".repeat(64)).unwrap()),
                "invalid-plan-head".into(),
            )
            .unwrap(),
        ];
        for head in invalid_heads {
            let (store, client) = replay_store(vec![head_response(encode_head(&head).unwrap())]);
            assert!(matches!(
                refresh(&store, &handle, genesis.identity()).await,
                ScopeReadiness::NotReady(ScopeReplayError::HeadInvalid(WireError::InvalidValue))
            ));
            assert_eq!(client.actual_requests().count(), 1);
            assert_eq!(
                handle.scope_cursor(genesis.identity()).await.unwrap(),
                (0, None)
            );
        }

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

        let corrupt = rusqlite::Connection::open(&path).unwrap();
        corrupt.pragma_update(None, "application_id", 0).unwrap();
        drop(corrupt);
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
            format!("benchmark-head-{size}"),
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
}
