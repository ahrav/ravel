//! Scope replay separates asynchronous object reads from blocking SQLite transactions.
//!
//! Ready output carries the observed head whose tail matches the committed local row.
//! Remote validation completes before the first projection write. The whole suffix and observed-
//! head comparison apply in one transaction; any failure rolls back the suffix and leaves the
//! cursor unchanged. A writer epoch may lag the head epoch but never exceeds it or its own child's.
//! Replay limits are 4,096 unseen events and 64 MiB of stored event and plan bytes.

use std::{
    collections::{HashMap, HashSet},
    error::Error,
    fmt,
    path::Path,
};

use ciborium::Value;

use crate::{
    db::{
        projections::{ApplyError, ScopeProjectionEvent, ScopeProjectionPayload, ValidateError},
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
    accelerator::{self, RetainedEvent, StoredEvent},
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
    /// True when the pack rung supplied the whole suffix; republishing it adds nothing.
    from_packs: bool,
}

struct Prepared {
    decoded: crate::scope::DecodedScopeEvent<Value>,
    /// Exact stored compressed bytes, retained for opportunistic pack publication.
    bytes: Vec<u8>,
    /// Present exactly for `plan_admitted` events: the decoded event and the verified plan object
    /// replay re-admits from.
    plan: Option<(crate::scope::PlanAdmittedEvent, PlanProposal)>,
}

/// Replays the unseen suffix through the projection-owning worker.
///
/// Remote reads and validation complete before the first projection write; the worker applies
/// the whole suffix and the observed-head comparison in one transaction, so any failure inside
/// that transaction rolls back the entire suffix and leaves the cursor unchanged. The claim
/// restore that follows the commit reads remote objects and can still refuse readiness.
pub async fn refresh(store: &S3Store, handle: &DbHandle, scope: &ScopeIdentity) -> ScopeReadiness {
    let cursor = match handle.scope_cursor(scope).await {
        Ok(cursor) => cursor,
        Err(error) => return ScopeReadiness::NotReady(ScopeReplayError::Apply(error)),
    };
    // The durable flag, not the starting cursor, gates the claim reader: a crash or storage
    // failure part-way through a rebuild leaves the cursor advanced but the flag down, and
    // gating on a blank cursor would skip the remaining restore forever.
    match prepare_suffix(store, scope, cursor).await {
        Ok(prepared) => {
            match apply_suffix(handle, scope, prepared).await {
                Ok((local_cursor, observed_head, retained)) => {
                    // Publication is a best-effort hint: any failure inside it leaves the
                    // just-committed replay result untouched.
                    if let Some(retained) = retained {
                        accelerator::publish_packs_after_replay(store, scope, &retained).await;
                    }
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
            }
        }
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

/// Opens the scope projection at `path`, installing a certified checkpoint when the
/// projection is missing or rebuildable.
///
/// A valid existing projection opens normally and is never replaced merely because a
/// checkpoint exists. A missing or rebuildable projection first tries the checkpoint
/// rung: prove a certified snapshot and its packed suffix against the pinned head, then
/// install it with one atomic rename. Any checkpoint failure creates or rebuilds the
/// empty projection as before; a later refresh replays through packs, LIST, then the
/// serial walk from genesis. A foreign application id is a refusal, not a rebuild: it
/// can belong to unrelated local data. Database-operation failures leave the existing
/// file intact.
///
/// # Errors
///
/// Returns [`ScopeReplayError::DatabaseUnavailable`] for `:memory:` or `file:` URIs,
/// file I/O failures, and SQLite operation failures.
pub async fn open_projection(
    store: &S3Store,
    scope: &ScopeIdentity,
    path: &Path,
) -> Result<DbHandle, ScopeReplayError> {
    if is_sqlite_uri(path) {
        return Err(ScopeReplayError::DatabaseUnavailable);
    }
    let exists = path
        .try_exists()
        .map_err(|_| ScopeReplayError::DatabaseUnavailable)?;
    if exists {
        match DbHandle::open_existing(path.to_path_buf()).await {
            Ok(handle) => return Ok(handle),
            Err(OpenExistingError::Validation(
                ValidateError::IntegrityCheckFailed
                | ValidateError::InvalidSchema
                | ValidateError::InvalidHistory,
            )) => {}
            Err(OpenExistingError::DatabaseOperationFailed | OpenExistingError::Validation(_)) => {
                return Err(ScopeReplayError::DatabaseUnavailable);
            }
        }
        // The invalid file is removed before the checkpoint rung so its stale sidecars
        // can never bleed into an installed snapshot.
        rebuild_files(path)?;
    }
    if let Some(handle) = install_checkpoint(store, scope, path).await {
        return Ok(handle);
    }
    DbHandle::spawn(path.to_path_buf())
        .await
        .map_err(|_| ScopeReplayError::DatabaseUnavailable)
}

/// Installs the newest provable certified checkpoint at `destination`.
///
/// `None` is a rung miss: the empty projection is created as before and later refreshes
/// replay from genesis. Every accelerator object consulted here is a hint; the pinned
/// head and the exact `events/` ancestry are the only authority the install trusts.
async fn install_checkpoint(
    store: &S3Store,
    scope: &ScopeIdentity,
    destination: &Path,
) -> Option<DbHandle> {
    let observed = head::read(store, scope).await.ok().flatten()?;
    let accelerator::CurrentCatalog::Present(catalog, _) =
        accelerator::read_current_catalog(store, scope).await
    else {
        return None;
    };
    for certificate_ref in catalog.checkpoints().iter().rev() {
        if certificate_ref.sequence() > observed.head().tail().sequence() {
            continue;
        }
        if let Some(handle) = install_candidate(
            store,
            scope,
            destination,
            &observed,
            &catalog,
            certificate_ref,
        )
        .await
        {
            return Some(handle);
        }
    }
    None
}

/// Proves one checkpoint candidate against the pinned head, then installs its snapshot.
///
/// Proof precedes download: the certificate's covered cursor must reach the pinned tail
/// through packed events and the common chain validator before the snapshot GET is
/// issued at its certified byte length and checked against its certified digest. The
/// rename from the staged sibling path to `destination` is the commit point: before it
/// the previous destination is untouched; after it the snapshot is independently valid
/// at its covered cursor, so interruption before the suffix applies still leaves a valid
/// replayable projection. `None` lets the caller try the next candidate.
async fn install_candidate(
    store: &S3Store,
    scope: &ScopeIdentity,
    destination: &Path,
    observed: &ObservedScopeHead,
    catalog: &accelerator::ReplayCatalog,
    certificate_ref: &ScopeEventRef,
) -> Option<DbHandle> {
    // The certificate is read at its exact event key; its typed conversion requires the
    // envelope parent and the payload's covered cursor to agree.
    let (decoded, _) = read_opaque(store, scope, certificate_ref).await.ok()??;
    let certificate = crate::scope::projection_checkpoint_from_decoded(decoded).ok()?;
    let covered = (
        certificate.payload().covered_sequence(),
        Some(certificate.payload().covered_tail_digest().clone()),
    );
    // `precheck` bounds the covered-to-tail interval before any pack fetch.
    precheck(&covered, observed.head().tail(), LIMITS).ok()?;

    let stored = accelerator::packed_events_from_catalog(
        store,
        scope,
        catalog,
        certificate.envelope().sequence(),
        observed.head().tail().sequence(),
    )
    .await?;
    let events = prepare_chain(
        store,
        scope,
        covered.clone(),
        observed.head().tail().clone(),
        observed.head().scope_epoch().get(),
        observed.head().operation_id(),
        LIMITS,
        ChainEvents::prefetched(stored),
    )
    .await
    .ok()?;

    let length = usize::try_from(certificate.payload().snapshot_length()).ok()?;
    let key = accelerator::scope_checkpoint_key(
        scope,
        certificate.payload().covered_sequence(),
        certificate.payload().snapshot_digest(),
    );
    let bytes = match store.get_object(&key, length).await {
        Ok(GetOutcome::Found { bytes, .. }) => bytes,
        Ok(GetOutcome::NotFound) | Err(_) => return None,
    };
    if bytes.len() != length
        || crate::scope::sha256(&bytes) != certificate.payload().snapshot_digest().as_str()
    {
        return None;
    }

    let mut staging = destination.as_os_str().to_owned();
    // The process-local counter differentiates staging paths for overlapping installs.
    static STAGING_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    staging.push(format!(
        ".checkpoint-{}-{}",
        std::process::id(),
        STAGING_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let staging = std::path::PathBuf::from(staging);
    let installed = {
        let scope = scope.clone();
        let destination = destination.to_path_buf();
        crate::db::worker::run_blocking(move || {
            if rebuild_files(&staging).is_err() {
                return false;
            }
            let installed = std::fs::write(&staging, &bytes).is_ok()
                && staged_snapshot_valid(&staging, &scope, &certificate)
                && std::fs::rename(&staging, &destination).is_ok();
            if !installed {
                let _ = rebuild_files(&staging);
            }
            installed
        })
        .await
        .unwrap_or(false)
    };
    if !installed {
        return None;
    }
    let handle = DbHandle::open_existing(destination.to_path_buf())
        .await
        .ok()?;
    let prepared = PreparedSuffix {
        observed: ObservedScopeHead::proven(
            observed.head().clone(),
            observed.canonical_bytes().to_vec(),
            observed.etag().clone(),
            observed.namespace().to_owned(),
        ),
        events,
        from_packs: true,
    };
    // The suffix was proven above; a failure here leaves the snapshot's covered cursor
    // in place and the next refresh replays the same suffix.
    let _ = apply_suffix(&handle, scope, prepared).await;
    Some(handle)
}

/// Validates the staged snapshot file: full open-time projection validation plus the
/// certified scope, covered cursor, and active-plan bindings.
fn staged_snapshot_valid(
    staging: &Path,
    scope: &ScopeIdentity,
    certificate: &crate::scope::ProjectionCheckpointEvent,
) -> bool {
    let covered = (
        certificate.payload().covered_sequence(),
        Some(certificate.payload().covered_tail_digest().clone()),
    );
    let Ok(connection) = crate::db::projections::open_existing(staging) else {
        return false;
    };
    let Ok(cursor) = crate::db::projections::scope_cursor(&connection, scope) else {
        return false;
    };
    let Ok(active_plan) = crate::db::projections::scope_active_plan(&connection, scope) else {
        return false;
    };
    cursor == covered && active_plan.as_ref() == certificate.payload().covered_active_plan_digest()
}

fn rebuild_files(path: &Path) -> Result<(), ScopeReplayError> {
    for suffix in ["-journal", "-wal", "-shm"] {
        let mut sidecar = path.as_os_str().to_owned();
        sidecar.push(suffix);
        remove_if_exists(Path::new(&sidecar))?;
    }
    remove_if_exists(path)
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
    let tail = observed.head().tail().clone();
    let scope_epoch = observed.head().scope_epoch().get();
    let head_operation = observed.head().operation_id().to_owned();
    let unseen = precheck(&cursor, &tail, limits)?;
    if unseen == 0 {
        return Ok(PreparedSuffix {
            observed,
            events: Vec::new(),
            from_packs: false,
        });
    }
    // The accelerator ladder: packed events, then LIST-assisted reads, then the serial
    // walk. Every rung feeds the same chain validator; an accelerator failure of any kind
    // falls through without changing the projection, and only the final serial rung
    // surfaces errors.
    let mut events = None;
    let mut from_packs = false;
    if let Some(stored) =
        accelerator::packed_events(store, scope, cursor.0 + 1, tail.sequence()).await
    {
        events = prepare_chain(
            store,
            scope,
            cursor.clone(),
            tail.clone(),
            scope_epoch,
            &head_operation,
            limits,
            ChainEvents::prefetched(stored),
        )
        .await
        .ok();
        from_packs = events.is_some();
    }
    if events.is_none()
        && let Some(stored) = listed_events(store, scope, cursor.0, &tail).await
    {
        events = prepare_chain(
            store,
            scope,
            cursor.clone(),
            tail.clone(),
            scope_epoch,
            &head_operation,
            limits,
            ChainEvents::prefetched(stored),
        )
        .await
        .ok();
    }
    let events = match events {
        Some(events) => events,
        None => {
            prepare_chain(
                store,
                scope,
                cursor,
                tail,
                scope_epoch,
                &head_operation,
                limits,
                ChainEvents::Serial,
            )
            .await?
        }
    };
    Ok(PreparedSuffix {
        observed,
        events,
        from_packs,
    })
}

/// Cursor, tail, and limit checks that run once, ahead of the accelerator ladder.
///
/// Returns the unseen event count; zero means the suffix is empty.
fn precheck(
    cursor: &(u64, Option<Digest>),
    tail: &ScopeEventRef,
    limits: Limits,
) -> Result<u64, ScopeReplayError> {
    if tail.sequence() < cursor.0 {
        return Err(ScopeReplayError::CursorAhead);
    }
    if tail.sequence() == cursor.0 {
        return if cursor.1.as_ref() == Some(tail.digest()) {
            Ok(0)
        } else {
            Err(ScopeReplayError::TailMismatch)
        };
    }
    let unseen = tail.sequence() - cursor.0;
    if unseen > limits.events {
        return Err(ScopeReplayError::Overflow);
    }
    Ok(unseen)
}

/// LIST-assisted candidate discovery for the unseen range `(cursor, tail]`.
///
/// LIST is a hint, never a snapshot: candidates below the cursor or beyond the pinned
/// tail are ignored, and any in-range gap, duplicate sequence, malformed key, missing
/// object, or invalid event returns `None` so the caller falls through.
async fn listed_events(
    store: &S3Store,
    scope: &ScopeIdentity,
    cursor_sequence: u64,
    tail: &ScopeEventRef,
) -> Option<Vec<StoredEvent>> {
    let unseen = tail.sequence().checked_sub(cursor_sequence)?;
    let prefix = accelerator::scope_events_prefix(scope);
    // Keys embed zero-padded 16-digit sequences, so lexicographic listing order is
    // numeric. `.` sorts after `-`, so this boundary skips every key at the cursor
    // sequence and none above it.
    let start_after = (cursor_sequence > 0).then(|| format!("{prefix}{cursor_sequence:016}."));
    // `MAX_SCOPE_REPLAY_EVENTS` covers the lifetime sequence ceiling, so keys beyond the
    // pinned tail are ignored rather than causing failure.
    let keys = store
        .list_keys(
            &prefix,
            start_after.as_deref(),
            MAX_SCOPE_REPLAY_EVENTS as usize,
        )
        .await
        .ok()?;
    let mut references: Vec<ScopeEventRef> = Vec::with_capacity(unseen as usize);
    let mut next = cursor_sequence + 1;
    for key in &keys {
        if next == tail.sequence() + 1 {
            break;
        }
        let reference = parse_event_key(key, &prefix)?;
        if reference.sequence() > tail.sequence() {
            // Beyond the pinned tail is not part of this replay; later keys only sort higher.
            break;
        }
        if reference.sequence() != next {
            // A duplicate sequence is an orphaned rival; a skipped one is a gap.
            return None;
        }
        next += 1;
        references.push(reference);
    }
    if next != tail.sequence() + 1 {
        return None;
    }
    accelerator::fetch_events(store, scope, &references).await
}

/// Parses `{sequence:016}-{digest}.cbor.zst` after `prefix`; any deviation is a miss.
fn parse_event_key(key: &str, prefix: &str) -> Option<ScopeEventRef> {
    let name = key.strip_prefix(prefix)?;
    let name = name.strip_suffix(".cbor.zst")?;
    let (sequence, digest) = name.split_at_checked(16)?;
    let digest = digest.strip_prefix('-')?;
    if !sequence.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let sequence: u64 = sequence.parse().ok()?;
    ScopeEventRef::new(sequence, Digest::new(digest.to_owned()).ok()?).ok()
}

/// Converts the prepared suffix, then applies its events through the worker.
///
/// The returned retained events are the verified suffix in chain order, kept for
/// opportunistic pack publication after the commit; `None` when the suffix came from
/// packs and republishing it would add nothing.
pub(crate) async fn apply_suffix(
    handle: &DbHandle,
    scope: &ScopeIdentity,
    mut prepared: PreparedSuffix,
) -> Result<((u64, Digest), ObservedScopeHead, Option<Vec<RetainedEvent>>), ScopeReplayError> {
    prepared.events.reverse();
    let scope_epoch = prepared.observed.head().scope_epoch().get();
    let mut retained = (!prepared.from_packs).then(|| Vec::with_capacity(prepared.events.len()));
    let mutations = prepared
        .events
        .into_iter()
        .map(|mut prepared| {
            let reference = prepared.decoded.event_ref().clone();
            if let Some(retained) = retained.as_mut() {
                retained.push(RetainedEvent {
                    reference: reference.clone(),
                    parent: prepared.decoded.envelope().parent_event().cloned(),
                    payload_type: prepared.decoded.envelope().payload_type().to_owned(),
                    bytes: std::mem::take(&mut prepared.bytes),
                });
            }
            let (envelope, payload) = typed_payload(prepared, scope)?;
            ScopeProjectionEvent::new(scope.clone(), envelope, reference, payload, scope_epoch)
                .map_err(|_| ScopeReplayError::HistoryConflict)
        })
        .collect::<Result<Vec<_>, _>>()?;

    match handle
        .apply_suffix(mutations, prepared.observed.head())
        .await
    {
        Ok(()) => {}
        Err(ApplyError::Conflict) => return Err(ScopeReplayError::HistoryConflict),
        Err(error) => return Err(ScopeReplayError::Apply(error)),
    }
    let local_cursor = (
        prepared.observed.head().tail().sequence(),
        prepared.observed.head().tail().digest().clone(),
    );
    Ok((local_cursor, prepared.observed, retained))
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
        crate::scope::PROJECTION_CHECKPOINT_PAYLOAD_TYPE => {
            let event = crate::scope::projection_checkpoint_from_decoded(prepared.decoded)
                .map_err(ScopeReplayError::EventInvalid)?;
            Ok((
                event.envelope().clone(),
                ScopeProjectionPayload::CheckpointPublished,
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

/// Where the chain validator draws each event from.
///
/// `Serial` reads newest-to-oldest through [`read_opaque`], preserving the final rung's
/// behavior and error classification. `Prefetched` consumes accelerator-supplied events
/// already re-verified against their synthesized keys; the validator still enforces every
/// source-independent check on them.
enum ChainEvents {
    Serial,
    Prefetched(HashMap<u64, StoredEvent>),
}

impl ChainEvents {
    fn prefetched(events: Vec<StoredEvent>) -> Self {
        Self::Prefetched(
            events
                .into_iter()
                .map(|event| (event.decoded.event_ref().sequence(), event))
                .collect(),
        )
    }
}

/// Source-independent chain validation and plan loading shared by every replay rung.
///
/// Enforces the exact tail named by the pinned head, newest-to-oldest parent continuity,
/// the writer-epoch bounds, unique operation IDs, the head operation at hop zero, the
/// exact cursor or genesis boundary, and the event and byte limits. Plan objects load
/// serially and draw on the same byte budget regardless of the event source.
#[expect(
    clippy::too_many_arguments,
    reason = "one internal call shape per rung"
)]
async fn prepare_chain(
    store: &S3Store,
    scope: &ScopeIdentity,
    cursor: (u64, Option<Digest>),
    tail: ScopeEventRef,
    scope_epoch: u64,
    head_operation: &str,
    limits: Limits,
    mut source: ChainEvents,
) -> Result<Vec<Prepared>, ScopeReplayError> {
    let unseen = precheck(&cursor, &tail, limits)?;

    let mut current = tail;
    let mut total_bytes = 0;
    let mut operations = HashSet::new();
    // The walk runs newest to oldest, so each event's writer epoch bounds its parent's.
    let mut highest_epoch = scope_epoch;
    let mut prepared = Vec::with_capacity(unseen as usize);
    for hop in 0..unseen {
        let (decoded, bytes) = match &mut source {
            ChainEvents::Serial => match read_opaque(store, scope, &current).await {
                Ok(Some(event)) => event,
                Ok(None) => return Err(ScopeReplayError::EventMissing),
                Err(ScopeEventReadError::Invalid(error)) => {
                    return Err(ScopeReplayError::EventInvalid(error));
                }
                Err(ScopeEventReadError::Storage(_)) => return Err(ScopeReplayError::EventStorage),
            },
            ChainEvents::Prefetched(events) => {
                let stored = events
                    .remove(&current.sequence())
                    .ok_or(ScopeReplayError::EventMissing)?;
                (stored.decoded, stored.bytes)
            }
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
        prepared.push(Prepared {
            decoded,
            bytes,
            plan,
        });
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
            AdmittedCampaignConfig, CampaignId, Digest, EventEnvelope,
            PROJECTION_CHECKPOINT_PAYLOAD_TYPE, ProjectionCheckpointEvent,
            ProjectionCheckpointPayload, ROOT_GENESIS_PAYLOAD_TYPE, ScopeAuthority, ScopeEventRef,
            ScopeHead, TEST_SUCCESSOR_PAYLOAD_TYPE, encode_head,
            encode_projection_checkpoint_event, encode_scope_event, root_genesis, sha256,
        },
        storage::s3::test_support::{keyed_store, list_response, replay_store, response},
        sync::accelerator::{PackEntry, build_pack, encode_catalog, encode_pointer},
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

    /// Dumps every table's rows (sorted) so two projections compare by content, not by
    /// row counts.
    fn projection_content(path: &Path) -> Vec<String> {
        let connection = rusqlite::Connection::open(path).unwrap();
        let tables: Vec<String> = connection
            .prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let mut dump = Vec::new();
        for table in tables {
            let mut statement = connection
                .prepare(&format!("SELECT * FROM \"{table}\""))
                .unwrap();
            let columns = statement.column_count();
            let mut rows: Vec<String> = statement
                .query_map([], |row| {
                    let cells: Vec<String> = (0..columns)
                        .map(|index| {
                            format!("{:?}", row.get::<_, rusqlite::types::Value>(index).unwrap())
                        })
                        .collect();
                    Ok(cells.join("|"))
                })
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            rows.sort();
            dump.extend(rows.into_iter().map(|row| format!("{table}: {row}")));
        }
        dump
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

    /// Returns 404 for an accelerator pointer read or LIST probe.
    fn accel_miss() -> http::Response<SdkBody> {
        response(404, &[], SdkBody::empty())
    }

    #[tokio::test]
    async fn replay_is_idempotent_and_returns_the_observed_head_witness() {
        let genesis = genesis();
        let path = path("idempotent");
        let handle = DbHandle::spawn(path.clone()).await.unwrap();
        let (store, client) = replay_store(vec![
            head_response(genesis.head_bytes().to_vec()),
            accel_miss(),
            accel_miss(),
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
        assert_eq!(client.actual_requests().count(), 4);
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
                accel_miss(),
                accel_miss(),
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

        let (first_cursor, _, _) = apply_suffix(&handle, genesis.identity(), first)
            .await
            .unwrap();
        let rows = row_counts(&path);
        let (second_cursor, _, _) = apply_suffix(&other, genesis.identity(), second)
            .await
            .expect("a suffix the first caller committed is not a history conflict");

        assert_eq!(second_cursor, first_cursor);
        assert_eq!(row_counts(&path), rows);

        let successor_envelope = EventEnvelope::new(
            genesis.identity().scope_id().clone(),
            2,
            Some(genesis.event_ref().clone()),
            1,
            "mixed-overlap".into(),
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
            "mixed-overlap".into(),
        )
        .unwrap();
        let (store, _) = replay_store(vec![
            head_response(encode_head(&successor_head).unwrap()),
            accel_miss(),
            accel_miss(),
            event_response(successor.stored_bytes().to_vec()),
            event_response(genesis.event_bytes().to_vec()),
        ]);
        let prepared = prepare_suffix(&store, genesis.identity(), (0, None))
            .await
            .unwrap();
        let (mixed_cursor, _, _) = apply_suffix(&other, genesis.identity(), prepared)
            .await
            .expect("an already-applied prefix continues into the unseen suffix");

        assert_eq!(mixed_cursor, (2, successor.event_ref().digest().clone()));
        assert_eq!(
            handle.scope_cursor(genesis.identity()).await.unwrap(),
            (2, Some(successor.event_ref().digest().clone()))
        );
        assert_eq!(row_counts(&path), (1, 2));
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
            accel_miss(),
            accel_miss(),
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
            accel_miss(),
            accel_miss(),
            event_response(successor.stored_bytes().to_vec()),
        ]);
        assert!(matches!(
            refresh(&store, &handle, genesis.identity()).await,
            ScopeReadiness::NotReady(ScopeReplayError::UnsupportedPayload)
        ));
        assert_eq!(client.actual_requests().count(), 4);
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
            accel_miss(),
            accel_miss(),
            event_response(invalid_root.stored_bytes().to_vec()),
        ]);
        assert!(matches!(
            refresh(&store, &handle, genesis.identity()).await,
            ScopeReadiness::NotReady(ScopeReplayError::EventInvalid(WireError::InvalidValue))
        ));
        assert_eq!(client.actual_requests().count(), 4);
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
            accel_miss(),
            accel_miss(),
            event_response(genesis.event_bytes().to_vec()),
        ]);
        assert!(matches!(
            refresh(&store, &handle, genesis.identity()).await,
            ScopeReadiness::NotReady(ScopeReplayError::HistoryConflict)
        ));
        assert_eq!(client.actual_requests().count(), 4);
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
        // admission event cannot substantiate it. The in-transaction head mismatch rolls back
        // the whole suffix and refuses readiness.
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
            accel_miss(),
            accel_miss(),
            event_response(genesis.event_bytes().to_vec()),
        ]);
        assert!(matches!(
            refresh(&store, &handle, genesis.identity()).await,
            ScopeReadiness::NotReady(ScopeReplayError::HistoryConflict)
        ));
        assert_eq!(client.actual_requests().count(), 4);
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

        // A foreign application id is unrelated local data, so the file survives.
        let foreign = rusqlite::Connection::open(&path).unwrap();
        foreign
            .pragma_update(None, "application_id", 0x1234)
            .unwrap();
        drop(foreign);
        let (offline, _) = replay_store(vec![]);
        assert!(matches!(
            open_projection(&offline, genesis.identity(), &path).await,
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
        let (offline, _) = replay_store(vec![]);
        let rebuilt = open_projection(&offline, genesis.identity(), &path)
            .await
            .unwrap();
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
    async fn a_database_failure_rolls_back_the_entire_suffix() {
        let genesis = genesis();
        let path = path("suffix-rollback");
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
            accel_miss(),
            accel_miss(),
            event_response(successor.stored_bytes().to_vec()),
            event_response(genesis.event_bytes().to_vec()),
        ]);
        assert!(matches!(
            refresh(&store, &handle, genesis.identity()).await,
            ScopeReadiness::NotReady(ScopeReplayError::Apply(ApplyError::DatabaseOperationFailed))
        ));
        assert_eq!(
            handle.scope_cursor(genesis.identity()).await.unwrap(),
            (0, None)
        );
        drop(handle);
        rusqlite::Connection::open(&path)
            .unwrap()
            .execute_batch("DROP TRIGGER fail_second_event")
            .unwrap();
        drop(projections::open_existing(&path).unwrap());

        let (offline, _) = replay_store(vec![]);
        let recovered = open_projection(&offline, genesis.identity(), &path)
            .await
            .unwrap();
        let (store, _) = replay_store(vec![
            head_response(encode_head(&successor_head).unwrap()),
            accel_miss(),
            accel_miss(),
            event_response(successor.stored_bytes().to_vec()),
            event_response(genesis.event_bytes().to_vec()),
        ]);
        assert!(matches!(
            refresh(&store, &recovered, genesis.identity()).await,
            ScopeReadiness::Ready { .. }
        ));
        assert_eq!(
            recovered.scope_cursor(genesis.identity()).await.unwrap(),
            (2, Some(successor.event_ref().digest().clone()))
        );
        drop(recovered);
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
        let genesis = genesis();
        let (offline, _) = replay_store(vec![]);
        assert!(
            open_projection(&offline, genesis.identity(), Path::new(":memory:"))
                .await
                .is_err()
        );
        assert!(
            open_projection(
                &offline,
                genesis.identity(),
                Path::new("file:scope.sqlite3")
            )
            .await
            .is_err()
        );
        let non_utf8 = std::ffi::OsString::from_vec(b"file:scope.sqlite3?mode=memory\xff".to_vec());
        assert!(is_sqlite_uri(Path::new(&non_utf8)));
        assert!(
            open_projection(&offline, genesis.identity(), Path::new(&non_utf8))
                .await
                .is_err()
        );
    }

    /// Builds one canonical chain of `LIMITS.events` events: root genesis at sequence 1 and
    /// test-only successors above it.
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

    #[tokio::test]
    #[ignore = "9s full-limit gate: cargo test -- --ignored"]
    async fn a_full_limit_suffix_commits_in_one_transaction() {
        let genesis = genesis();
        let path = path("full-limit-suffix");
        let (bytes, references) = benchmark_chain(&genesis);
        let last = LIMITS.events as usize - 1;
        let head = ScopeHead::new(
            genesis.identity().clone(),
            ScopeAuthority::Unowned,
            1,
            references[last].clone(),
            None,
            format!("benchmark-operation-{}", LIMITS.events),
        )
        .unwrap();
        let mut responses = Vec::with_capacity(bytes.len() + 1);
        responses.push(head_response(encode_head(&head).unwrap()));
        responses.push(accel_miss());
        responses.push(accel_miss());
        responses.extend(bytes.into_iter().rev().map(event_response));
        let (store, _) = replay_store(responses);
        let handle = DbHandle::spawn(path.clone()).await.unwrap();

        match refresh(&store, &handle, genesis.identity()).await {
            ScopeReadiness::Ready { local_cursor, .. } => {
                assert_eq!(
                    local_cursor,
                    (LIMITS.events, references[last].digest().clone())
                );
            }
            ScopeReadiness::NotReady(error) => panic!("full suffix replay failed: {error}"),
        }
        assert_eq!(
            handle.scope_cursor(genesis.identity()).await.unwrap(),
            (LIMITS.events, Some(references[last].digest().clone()))
        );
        let diagnostics = handle.diagnostics().await.unwrap();
        assert_eq!(diagnostics.suffix_count, 1);
        assert_eq!(diagnostics.apply_count, LIMITS.events as usize);
        drop(handle);
        fs::remove_file(path).unwrap();
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
        let mut responses = Vec::with_capacity(size + 3);
        responses.push(head_response(encode_head(&head).unwrap()));
        responses.push(accel_miss());
        responses.push(accel_miss());
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
            accel_miss(),
            accel_miss(),
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
            accel_miss(),
            accel_miss(),
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
            accel_miss(),
            accel_miss(),
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
                accel_miss(),
                accel_miss(),
                event_response(encoded.stored_bytes().to_vec()),
                response(
                    200,
                    &[("etag", "\"plan\"")],
                    admissible.stored_bytes().to_vec(),
                ),
                event_response(genesis.event_bytes().to_vec()),
                accel_miss(),
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
            accel_miss(),
            accel_miss(),
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
        // Atomic suffix application leaves the fresh projection empty on head mismatch.
        assert_eq!(handle.scope_cursor(&scope).await.unwrap(), (0, None));
        assert_eq!(row_counts(&path), (0, 0));
        drop(handle);
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
            accel_miss(),
            accel_miss(),
            event_response(fixture.admission_bytes.clone()),
            response(
                200,
                &[("etag", "\"plan\"")],
                fixture.admissible_bytes.clone(),
            ),
            event_response(genesis.event_bytes().to_vec()),
            accel_miss(),
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
            accel_miss(),
            accel_miss(),
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
            accel_miss(),
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
            accel_miss(),
            accel_miss(),
            event_response(fixture.admission_bytes.clone()),
            response(
                200,
                &[("etag", "\"plan\"")],
                fixture.admissible_bytes.clone(),
            ),
            event_response(genesis.event_bytes().to_vec()),
            accel_miss(),
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
        assert_eq!(client.actual_requests().count(), 9);
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
            accel_miss(),
            accel_miss(),
            event_response(fixture.admission_bytes.clone()),
            response(
                200,
                &[("etag", "\"plan\"")],
                fixture.admissible_bytes.clone(),
            ),
            event_response(genesis.event_bytes().to_vec()),
            accel_miss(),
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
        assert_eq!(client.actual_requests().count(), 12);

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
            accel_miss(),
            accel_miss(),
            event_response(fixture.admission_bytes.clone()),
            response(
                200,
                &[("etag", "\"plan\"")],
                fixture.admissible_bytes.clone(),
            ),
            event_response(genesis.event_bytes().to_vec()),
            accel_miss(),
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
        assert_eq!(client.actual_requests().count(), 9);
        assert!(handle.claims_restored(&scope).await.unwrap());

        handle.drain().await.unwrap();
        drop(handle);
        let rows = scheduling_rows(&db_path);
        assert_eq!(rows[0].claim_fence, None);
        assert_eq!(rows[0].claim_lease_until, None);
        fs::remove_file(db_path).unwrap();
    }

    /// Builds a canonical chain of `count` events: genesis plus test successors, beside the
    /// unowned head naming the final event.
    fn accel_chain(
        genesis: &crate::scope::RootGenesis,
        count: usize,
    ) -> (Vec<(ScopeEventRef, Vec<u8>)>, ScopeHead) {
        accel_chain_with(genesis, count, "accel-op")
    }

    fn accel_chain_with(
        genesis: &crate::scope::RootGenesis,
        count: usize,
        operation_prefix: &str,
    ) -> (Vec<(ScopeEventRef, Vec<u8>)>, ScopeHead) {
        let mut events = Vec::with_capacity(count);
        events.push((genesis.event_ref().clone(), genesis.event_bytes().to_vec()));
        for sequence in 2..=count as u64 {
            let parent = events[(sequence - 2) as usize].0.clone();
            let envelope = EventEnvelope::new(
                genesis.identity().scope_id().clone(),
                sequence,
                Some(parent),
                1,
                format!("{operation_prefix}-{sequence}"),
                TEST_SUCCESSOR_PAYLOAD_TYPE.into(),
            )
            .unwrap();
            let encoded = encode_scope_event(&envelope, &Value::Null).unwrap();
            events.push((encoded.event_ref().clone(), encoded.stored_bytes().to_vec()));
        }
        let operation = if count == 1 {
            genesis.head().operation_id().to_owned()
        } else {
            format!("{operation_prefix}-{count}")
        };
        let head = ScopeHead::new(
            genesis.identity().clone(),
            ScopeAuthority::Unowned,
            1,
            events[count - 1].0.clone(),
            None,
            operation,
        )
        .unwrap();
        (events, head)
    }

    fn event_keys(scope: &ScopeIdentity, events: &[(ScopeEventRef, Vec<u8>)]) -> Vec<String> {
        events
            .iter()
            .map(|(reference, _)| crate::scope::scope_event_key(scope, reference))
            .collect()
    }

    /// Builds a keyed route serving `head` plus the listed events, with a 404 pointer
    /// and 500 for anything else, so concurrent fetch order cannot skew the script.
    fn accel_route(
        scope: &ScopeIdentity,
        head: &ScopeHead,
        events: &[(ScopeEventRef, Vec<u8>)],
        listed: Vec<String>,
    ) -> impl Fn(&str) -> http::Response<SdkBody> + Send + Sync + 'static {
        let head_bytes = encode_head(head).unwrap();
        let events: Vec<(String, Vec<u8>)> = events
            .iter()
            .map(|(reference, bytes)| {
                (
                    format!("/{}", crate::scope::scope_event_key(scope, reference)),
                    bytes.clone(),
                )
            })
            .collect();
        move |uri: &str| {
            let path = uri.split('?').next().unwrap();
            if uri.contains("list-type=2") {
                let refs: Vec<&str> = listed.iter().map(String::as_str).collect();
                return list_response(&refs, false, None);
            }
            if path.ends_with("/head") {
                return head_response(head_bytes.clone());
            }
            if path.ends_with("/replay-index/current") {
                return accel_miss();
            }
            if let Some((_, bytes)) = events.iter().find(|(key, _)| path == key) {
                return event_response(bytes.clone());
            }
            response(500, &[], SdkBody::empty())
        }
    }

    /// The unseen-event limit is inclusive: a suffix exactly at the limit passes the
    /// precheck and one past it overflows.
    #[test]
    fn precheck_accepts_an_unseen_span_exactly_at_the_event_limit() {
        let digest = Digest::new("a".repeat(64)).unwrap();
        let limits = Limits {
            events: 3,
            bytes: 64,
        };
        let tail = ScopeEventRef::new(3, digest.clone()).unwrap();
        assert_eq!(precheck(&(0, None), &tail, limits), Ok(3));
        let tail = ScopeEventRef::new(4, digest).unwrap();
        assert_eq!(
            precheck(&(0, None), &tail, limits),
            Err(ScopeReplayError::Overflow)
        );
    }

    /// The LIST rung replays exactly what the serial walk replays, at the same cursor.
    #[tokio::test]
    async fn list_replay_is_equivalent_to_the_serial_walk() {
        let genesis = genesis();
        let scope = genesis.identity().clone();
        let (events, head) = accel_chain(&genesis, 2);
        let keys = event_keys(&scope, &events);

        let serial_path = path("list-equivalence-serial");
        let serial = DbHandle::spawn(serial_path.clone()).await.unwrap();
        let (store, _) = replay_store(vec![
            head_response(encode_head(&head).unwrap()),
            accel_miss(),
            accel_miss(),
            event_response(events[1].1.clone()),
            event_response(events[0].1.clone()),
        ]);
        assert!(matches!(
            refresh(&store, &serial, &scope).await,
            ScopeReadiness::Ready { .. }
        ));
        let serial_cursor = serial.scope_cursor(&scope).await.unwrap();
        drop(serial);

        let listed_path = path("list-equivalence-listed");
        let listed = DbHandle::spawn(listed_path.clone()).await.unwrap();
        let (store, requests) = keyed_store(accel_route(&scope, &head, &events, keys.clone()));
        match refresh(&store, &listed, &scope).await {
            ScopeReadiness::Ready { local_cursor, .. } => {
                assert_eq!(local_cursor.0, 2);
                assert_eq!(local_cursor.1, *events[1].0.digest());
            }
            ScopeReadiness::NotReady(error) => panic!("LIST replay failed: {error}"),
        }
        assert_eq!(listed.scope_cursor(&scope).await.unwrap(), serial_cursor);
        assert_eq!(
            projection_content(&listed_path),
            projection_content(&serial_path)
        );
        // Head, pointer miss, LIST, one bounded GET per candidate, and the failed pack
        // publication PUT; the keyed route records every request, so a surplus request
        // would raise the count.
        let recorded = requests.lock().unwrap().clone();
        assert_eq!(recorded.len(), 7);
        assert!(recorded[0].contains("/head"));
        assert!(recorded[1].contains("/replay-index/current"));
        assert!(recorded[2].contains("list-type=2"));
        // A cursor-0 replay lists from the start of the prefix: no start-after key.
        assert!(!recorded[2].contains("start-after"));
        let mut candidate_gets = vec![recorded[3].clone(), recorded[4].clone()];
        candidate_gets.sort();
        let candidate = |index: usize| {
            format!(
                "GET /{}?x-id=GetObject",
                crate::scope::scope_event_key(&scope, &events[index].0)
            )
        };
        assert_eq!(candidate_gets, vec![candidate(0), candidate(1)]);
        // The failed pack PUT and its ambiguity probe end publication.
        assert!(recorded[5].starts_with("PUT ") && recorded[5].contains("/replay-packs/"));
        assert!(recorded[6].starts_with("GET ") && recorded[6].contains("/replay-packs/"));
        drop(listed);
        fs::remove_file(serial_path).unwrap();
        fs::remove_file(listed_path).unwrap();
    }

    /// A batched suffix produces the same cursor and projection content through the serial
    /// walk, LIST, and packs.
    #[tokio::test]
    async fn a_batched_suffix_replays_identically_through_every_rung() {
        let genesis = genesis();
        let scope = genesis.identity().clone();
        let (events, head) = accel_chain(&genesis, 4);
        let keys = event_keys(&scope, &events);

        let serial_path = path("batched-suffix-serial");
        let serial = DbHandle::spawn(serial_path.clone()).await.unwrap();
        let (store, _) = replay_store(vec![
            head_response(encode_head(&head).unwrap()),
            accel_miss(),
            accel_miss(),
            event_response(events[3].1.clone()),
            event_response(events[2].1.clone()),
            event_response(events[1].1.clone()),
            event_response(events[0].1.clone()),
        ]);
        assert!(matches!(
            refresh(&store, &serial, &scope).await,
            ScopeReadiness::Ready { .. }
        ));
        let serial_cursor = serial.scope_cursor(&scope).await.unwrap();
        assert_eq!(serial_cursor, (4, Some(events[3].0.digest().clone())));
        drop(serial);

        let listed_path = path("batched-suffix-listed");
        let listed = DbHandle::spawn(listed_path.clone()).await.unwrap();
        let (store, _) = keyed_store(accel_route(&scope, &head, &events, keys));
        assert!(matches!(
            refresh(&store, &listed, &scope).await,
            ScopeReadiness::Ready { .. }
        ));
        assert_eq!(listed.scope_cursor(&scope).await.unwrap(), serial_cursor);
        drop(listed);

        let slices: Vec<&[u8]> = events.iter().map(|(_, bytes)| bytes.as_slice()).collect();
        let pack = build_pack(&scope, None, 1, &slices).unwrap();
        let entry = PackEntry::new(1, 4, pack.digest().clone()).unwrap();
        let (catalog_bytes, catalog_digest) = encode_catalog(&scope, &[entry], &[]).unwrap();
        let pointer_bytes = encode_pointer(&scope, &catalog_digest).unwrap();
        let packed_path = path("batched-suffix-packed");
        let packed = DbHandle::spawn(packed_path.clone()).await.unwrap();
        let (store, _) = replay_store(vec![
            head_response(encode_head(&head).unwrap()),
            response(200, &[("etag", "\"pointer\"")], pointer_bytes),
            response(200, &[("etag", "\"catalog\"")], catalog_bytes),
            response(200, &[("etag", "\"pack\"")], pack.bytes().to_vec()),
        ]);
        assert!(matches!(
            refresh(&store, &packed, &scope).await,
            ScopeReadiness::Ready { .. }
        ));
        assert_eq!(packed.scope_cursor(&scope).await.unwrap(), serial_cursor);
        drop(packed);

        assert_eq!(
            projection_content(&listed_path),
            projection_content(&serial_path)
        );
        assert_eq!(
            projection_content(&packed_path),
            projection_content(&serial_path)
        );
        for path in [serial_path, listed_path, packed_path] {
            fs::remove_file(path).unwrap();
        }
    }

    /// Anomalous listings fall back to the serial walk without changing the outcome, and a
    /// candidate beyond the pinned tail is ignored rather than treated as an anomaly.
    #[tokio::test]
    async fn list_anomalies_fall_back_and_beyond_tail_candidates_are_ignored() {
        let genesis = genesis();
        let scope = genesis.identity().clone();
        let (events, head) = accel_chain(&genesis, 4);
        let keys = event_keys(&scope, &events);
        let prefix = crate::sync::accelerator::scope_events_prefix(&scope);
        let orphan_key = format!("{prefix}0000000000000002-{}.cbor.zst", "e".repeat(64));

        // Each anomaly is detected while scanning keys, before any candidate fetch.
        let listings = [
            // An in-range gap: sequence 2 is missing from the listing.
            vec![keys[0].clone(), keys[2].clone(), keys[3].clone()],
            // An in-range orphan: a rival object at an expected sequence.
            vec![
                keys[0].clone(),
                orphan_key.clone(),
                keys[1].clone(),
                keys[2].clone(),
            ],
            // A malformed key inside the range.
            vec![
                keys[0].clone(),
                format!("{prefix}not-an-event"),
                keys[2].clone(),
            ],
        ];
        for listing in listings {
            let key_refs: Vec<&str> = listing.iter().map(String::as_str).collect();
            let path = path("list-fallback");
            let handle = DbHandle::spawn(path.clone()).await.unwrap();
            let (store, _) = replay_store(vec![
                head_response(encode_head(&head).unwrap()),
                accel_miss(),
                list_response(&key_refs, false, None),
                event_response(events[3].1.clone()),
                event_response(events[2].1.clone()),
                event_response(events[1].1.clone()),
                event_response(events[0].1.clone()),
            ]);
            assert!(matches!(
                refresh(&store, &handle, &scope).await,
                ScopeReadiness::Ready { .. }
            ));
            assert_eq!(handle.scope_cursor(&scope).await.unwrap().0, 4);
            drop(handle);
            fs::remove_file(path).unwrap();
        }

        // A listed-but-missing object forces the serial fallback.
        let (short_events, short_head) = accel_chain(&genesis, 2);
        let short_keys = event_keys(&scope, &short_events);
        let short_refs: Vec<&str> = short_keys.iter().map(String::as_str).collect();
        let path_missing = path("list-missing-object");
        let handle = DbHandle::spawn(path_missing.clone()).await.unwrap();
        let (store, _) = replay_store(vec![
            head_response(encode_head(&short_head).unwrap()),
            accel_miss(),
            list_response(&short_refs, false, None),
            event_response(short_events[0].1.clone()),
            response(404, &[], Vec::new()),
            event_response(short_events[1].1.clone()),
            event_response(short_events[0].1.clone()),
        ]);
        assert!(matches!(
            refresh(&store, &handle, &scope).await,
            ScopeReadiness::Ready { .. }
        ));
        drop(handle);
        fs::remove_file(path_missing).unwrap();

        // A listed candidate answered with foreign event bytes fails its synthesized-key
        // check and forces the serial fallback.
        let invalid_path = path("list-invalid-event");
        let handle = DbHandle::spawn(invalid_path.clone()).await.unwrap();
        let (store, _) = replay_store(vec![
            head_response(encode_head(&short_head).unwrap()),
            accel_miss(),
            list_response(&short_refs, false, None),
            event_response(short_events[1].1.clone()),
            event_response(short_events[1].1.clone()),
            event_response(short_events[1].1.clone()),
            event_response(short_events[0].1.clone()),
        ]);
        assert!(matches!(
            refresh(&store, &handle, &scope).await,
            ScopeReadiness::Ready { .. }
        ));
        drop(handle);
        fs::remove_file(invalid_path).unwrap();

        // Candidates beyond the pinned tail are ignored: the head pins sequence 2 while the
        // listing also names sequence 3.
        let beyond_path = path("list-beyond-tail");
        let handle = DbHandle::spawn(beyond_path.clone()).await.unwrap();
        let (store, requests) = keyed_store(accel_route(
            &scope,
            &short_head,
            &events[..2],
            keys[..3].to_vec(),
        ));
        assert!(matches!(
            refresh(&store, &handle, &scope).await,
            ScopeReadiness::Ready { .. }
        ));
        assert_eq!(handle.scope_cursor(&scope).await.unwrap().0, 2);
        // Head, pointer miss, LIST, two candidate GETs, and the failed publication PUT
        // plus its ambiguity probe: the beyond-tail candidate is never fetched.
        let recorded = requests.lock().unwrap().clone();
        assert_eq!(recorded.len(), 7);
        assert!(recorded.iter().all(|line| !line.contains(&format!(
            "/{}",
            crate::scope::scope_event_key(&scope, &events[2].0)
        ))));
        drop(handle);
        fs::remove_file(beyond_path).unwrap();
    }

    /// The pack rung replays exactly what the serial walk replays and re-verifies every
    /// embedded event; corrupt, wrong-scope, range-mismatch, and tail-mismatch packs fall
    /// through.
    #[tokio::test]
    async fn packed_replay_is_equivalent_and_bad_packs_fall_back() {
        let genesis = genesis();
        let scope = genesis.identity().clone();
        let (events, head) = accel_chain(&genesis, 3);
        let slices: Vec<&[u8]> = events.iter().map(|(_, bytes)| bytes.as_slice()).collect();
        let pack = build_pack(&scope, None, 1, &slices).unwrap();
        let entry = PackEntry::new(1, 3, pack.digest().clone()).unwrap();
        let (catalog_bytes, catalog_digest) = encode_catalog(&scope, &[entry], &[]).unwrap();
        let pointer_bytes = encode_pointer(&scope, &catalog_digest).unwrap();

        let serial_path = path("pack-equivalence-serial");
        let serial = DbHandle::spawn(serial_path.clone()).await.unwrap();
        let (store, _) = replay_store(vec![
            head_response(encode_head(&head).unwrap()),
            accel_miss(),
            accel_miss(),
            event_response(events[2].1.clone()),
            event_response(events[1].1.clone()),
            event_response(events[0].1.clone()),
        ]);
        assert!(matches!(
            refresh(&store, &serial, &scope).await,
            ScopeReadiness::Ready { .. }
        ));
        let serial_cursor = serial.scope_cursor(&scope).await.unwrap();
        drop(serial);

        let packed_path = path("pack-equivalence-packed");
        let packed = DbHandle::spawn(packed_path.clone()).await.unwrap();
        let (store, client) = replay_store(vec![
            head_response(encode_head(&head).unwrap()),
            response(200, &[("etag", "\"pointer\"")], pointer_bytes.clone()),
            response(200, &[("etag", "\"catalog\"")], catalog_bytes.clone()),
            response(200, &[("etag", "\"pack\"")], pack.bytes().to_vec()),
            response(500, &[], SdkBody::empty()),
            response(500, &[], SdkBody::empty()),
        ]);
        assert!(matches!(
            refresh(&store, &packed, &scope).await,
            ScopeReadiness::Ready { .. }
        ));
        assert_eq!(packed.scope_cursor(&scope).await.unwrap(), serial_cursor);
        assert_eq!(
            projection_content(&packed_path),
            projection_content(&serial_path)
        );
        // Head, pointer, catalog, and one pack: no per-event GET and no republication.
        // The surplus scripted failures would record any extra request.
        assert_eq!(client.actual_requests().count(), 4);
        drop(packed);
        fs::remove_file(packed_path).unwrap();

        // A corrupt pack, a wrong-scope pack, a pack that mismatches its catalog range, and
        // a pack whose final event misses the pinned tail all fall through to the serial
        // walk without changing the outcome.
        let foreign_config = AdmittedCampaignConfig::new(
            WorkspaceId::new("workspace-b".into()).unwrap(),
            CampaignId::new("campaign-b".into()).unwrap(),
            b"admitted".to_vec(),
        )
        .unwrap();
        let foreign_genesis = crate::scope::root_genesis(&foreign_config).unwrap();
        let (foreign_events, _) = accel_chain(&foreign_genesis, 3);
        let foreign_slices: Vec<&[u8]> = foreign_events
            .iter()
            .map(|(_, bytes)| bytes.as_slice())
            .collect();
        let foreign_pack =
            build_pack(foreign_genesis.identity(), None, 1, &foreign_slices).unwrap();
        let short_slices: Vec<&[u8]> = slices[..2].to_vec();
        let short_pack = build_pack(&scope, None, 1, &short_slices).unwrap();
        let (alternate_events, _) = accel_chain_with(&genesis, 3, "rival-op");
        let alternate_slices: Vec<&[u8]> = alternate_events
            .iter()
            .map(|(_, bytes)| bytes.as_slice())
            .collect();
        let alternate_pack = build_pack(&scope, None, 1, &alternate_slices).unwrap();
        let mut corrupt = pack.bytes().to_vec();
        corrupt[20] ^= 0xff;
        let bad_packs = [
            (pack.digest().clone(), corrupt),
            (foreign_pack.digest().clone(), foreign_pack.bytes().to_vec()),
            (short_pack.digest().clone(), short_pack.bytes().to_vec()),
            (
                alternate_pack.digest().clone(),
                alternate_pack.bytes().to_vec(),
            ),
        ];
        for (digest, bytes) in bad_packs {
            let entry = PackEntry::new(1, 3, digest).unwrap();
            let (bad_catalog, bad_digest) = encode_catalog(&scope, &[entry], &[]).unwrap();
            let bad_pointer = encode_pointer(&scope, &bad_digest).unwrap();
            let fallback_path = path("pack-fallback");
            let handle = DbHandle::spawn(fallback_path.clone()).await.unwrap();
            let (store, _) = replay_store(vec![
                head_response(encode_head(&head).unwrap()),
                response(200, &[("etag", "\"pointer\"")], bad_pointer),
                response(200, &[("etag", "\"catalog\"")], bad_catalog),
                response(200, &[("etag", "\"pack\"")], bytes),
                accel_miss(),
                event_response(events[2].1.clone()),
                event_response(events[1].1.clone()),
                event_response(events[0].1.clone()),
            ]);
            assert!(matches!(
                refresh(&store, &handle, &scope).await,
                ScopeReadiness::Ready { .. }
            ));
            assert_eq!(handle.scope_cursor(&scope).await.unwrap(), serial_cursor);
            drop(handle);
            fs::remove_file(fallback_path).unwrap();
        }
        fs::remove_file(serial_path).unwrap();
    }

    /// For an N-event history served through packs, event-data GETs drop from N to
    /// `ceil(N / 256)`; the fixed head/pointer/catalog requests are asserted separately.
    #[tokio::test]
    async fn packed_replay_reduces_event_data_requests_to_pack_count() {
        const EVENTS: usize = 300;
        let genesis = genesis();
        let scope = genesis.identity().clone();
        let (events, head) = accel_chain(&genesis, EVENTS);
        let mut entries = Vec::new();
        let mut packs = Vec::new();
        for group in (0..EVENTS).collect::<Vec<_>>().chunks(256) {
            let start = group[0];
            let end = group[group.len() - 1];
            let parent = (start > 0).then(|| events[start - 1].0.clone());
            let slices: Vec<&[u8]> = events[start..=end]
                .iter()
                .map(|(_, bytes)| bytes.as_slice())
                .collect();
            let pack = build_pack(&scope, parent.as_ref(), start as u64 + 1, &slices).unwrap();
            entries.push(
                PackEntry::new(start as u64 + 1, end as u64 + 1, pack.digest().clone()).unwrap(),
            );
            packs.push(pack);
        }
        assert_eq!(packs.len(), EVENTS.div_ceil(256));
        let (catalog_bytes, catalog_digest) = encode_catalog(&scope, &entries, &[]).unwrap();
        let pointer_bytes = encode_pointer(&scope, &catalog_digest).unwrap();

        let path = path("pack-request-count");
        let handle = DbHandle::spawn(path.clone()).await.unwrap();
        let mut responses = vec![
            head_response(encode_head(&head).unwrap()),
            response(200, &[("etag", "\"pointer\"")], pointer_bytes),
            response(200, &[("etag", "\"catalog\"")], catalog_bytes),
        ];
        responses.extend(
            packs
                .iter()
                .map(|pack| response(200, &[("etag", "\"pack\"")], pack.bytes().to_vec())),
        );
        let (store, client) = replay_store(responses);
        assert!(matches!(
            refresh(&store, &handle, &scope).await,
            ScopeReadiness::Ready { .. }
        ));
        assert_eq!(handle.scope_cursor(&scope).await.unwrap().0, EVENTS as u64);
        let requests: Vec<String> = client
            .actual_requests()
            .map(|request| {
                request
                    .uri()
                    .parse::<http::Uri>()
                    .unwrap()
                    .path()
                    .to_owned()
            })
            .collect();
        let event_gets = requests
            .iter()
            .filter(|path| path.contains("/events/"))
            .count();
        let pack_gets = requests
            .iter()
            .filter(|path| path.contains("/replay-packs/"))
            .count();
        assert_eq!(event_gets, 0);
        assert_eq!(pack_gets, EVENTS.div_ceil(256));
        assert_eq!(requests.len(), 1 + 2 + pack_gets);
        drop(handle);
        fs::remove_file(path).unwrap();
    }

    /// A LIST-served replay publishes packs, and a second cold projection then replays
    /// through them: the acceptance path from serial cost to `ceil(N / 256)` GETs.
    #[tokio::test]
    async fn a_replay_publishes_packs_that_serve_the_next_cold_projection() {
        let genesis = genesis();
        let scope = genesis.identity().clone();
        let (events, head) = accel_chain(&genesis, 2);
        let keys = event_keys(&scope, &events);
        let key_refs: Vec<&str> = keys.iter().map(String::as_str).collect();
        let slices: Vec<&[u8]> = events.iter().map(|(_, bytes)| bytes.as_slice()).collect();
        let expected_pack = build_pack(&scope, None, 1, &slices).unwrap();
        let entry = PackEntry::new(1, 2, expected_pack.digest().clone()).unwrap();
        let (catalog_bytes, catalog_digest) = encode_catalog(&scope, &[entry], &[]).unwrap();
        let pointer_bytes = encode_pointer(&scope, &catalog_digest).unwrap();

        let first_path = path("publish-first");
        let first = DbHandle::spawn(first_path.clone()).await.unwrap();
        let (store, client) = replay_store(vec![
            head_response(encode_head(&head).unwrap()),
            accel_miss(),
            list_response(&key_refs, false, None),
            event_response(events[0].1.clone()),
            event_response(events[1].1.clone()),
            // Publication: pack PUT, pointer probe, catalog PUT, pointer create.
            response(200, &[], SdkBody::empty()),
            response(404, &[], SdkBody::empty()),
            response(200, &[], SdkBody::empty()),
            response(200, &[], SdkBody::empty()),
        ]);
        assert!(matches!(
            refresh(&store, &first, &scope).await,
            ScopeReadiness::Ready { .. }
        ));
        let requests: Vec<_> = client.actual_requests().collect();
        assert_eq!(requests.len(), 9);
        assert_eq!(requests[5].body().bytes(), Some(expected_pack.bytes()));
        assert_eq!(requests[7].body().bytes(), Some(catalog_bytes.as_slice()));
        assert_eq!(requests[8].body().bytes(), Some(pointer_bytes.as_slice()));
        drop(first);
        fs::remove_file(first_path).unwrap();

        let second_path = path("publish-second");
        let second = DbHandle::spawn(second_path.clone()).await.unwrap();
        let (store, client) = replay_store(vec![
            head_response(encode_head(&head).unwrap()),
            response(200, &[("etag", "\"pointer\"")], pointer_bytes),
            response(200, &[("etag", "\"catalog\"")], catalog_bytes),
            response(200, &[("etag", "\"pack\"")], expected_pack.bytes().to_vec()),
        ]);
        assert!(matches!(
            refresh(&store, &second, &scope).await,
            ScopeReadiness::Ready { .. }
        ));
        assert_eq!(second.scope_cursor(&scope).await.unwrap().0, 2);
        assert_eq!(client.actual_requests().count(), 4);
        drop(second);
        fs::remove_file(second_path).unwrap();
    }

    /// Shared checkpoint fixture: a live projection at genesis, its sanitized snapshot,
    /// the certificate at sequence 2, one successor at sequence 3, and the accelerator
    /// objects proving them.
    struct CheckpointFixture {
        scope: ScopeIdentity,
        head: ScopeHead,
        snapshot: Vec<u8>,
        certificate_bytes: Vec<u8>,
        successor_bytes: Vec<u8>,
        successor_ref: ScopeEventRef,
        pack: crate::sync::accelerator::EncodedPack,
        catalog_bytes: Vec<u8>,
        pointer_bytes: Vec<u8>,
    }

    async fn checkpoint_fixture(
        genesis: &crate::scope::RootGenesis,
        label: &str,
    ) -> CheckpointFixture {
        let scope = genesis.identity().clone();
        let live_path = path(&format!("checkpoint-fixture-live-{label}"));
        let snap_path = path(&format!("checkpoint-fixture-snap-{label}"));
        let _ = fs::remove_file(&snap_path);
        let live = DbHandle::spawn(live_path.clone()).await.unwrap();
        live.apply(root_mutation(genesis)).await.unwrap();
        live.snapshot_to(genesis.head(), snap_path.clone())
            .await
            .unwrap();
        drop(live);
        let snapshot = fs::read(&snap_path).unwrap();
        fs::remove_file(&live_path).unwrap();
        fs::remove_file(&snap_path).unwrap();
        let snapshot_digest = Digest::new(sha256(&snapshot)).unwrap();

        let payload = ProjectionCheckpointPayload::new(
            snapshot_digest,
            snapshot.len() as u64,
            1,
            genesis.event_ref().digest().clone(),
            None,
        )
        .unwrap();
        let certificate = ProjectionCheckpointEvent::new(
            EventEnvelope::new(
                scope.scope_id().clone(),
                2,
                Some(genesis.event_ref().clone()),
                1,
                "checkpoint-op-1".into(),
                PROJECTION_CHECKPOINT_PAYLOAD_TYPE.to_owned(),
            )
            .unwrap(),
            payload,
        )
        .unwrap();
        let certificate_encoded = encode_projection_checkpoint_event(&certificate).unwrap();
        let successor_envelope = EventEnvelope::new(
            scope.scope_id().clone(),
            3,
            Some(certificate_encoded.event_ref().clone()),
            1,
            "post-checkpoint-op".into(),
            TEST_SUCCESSOR_PAYLOAD_TYPE.into(),
        )
        .unwrap();
        let successor = encode_scope_event(&successor_envelope, &Value::Null).unwrap();
        let head = ScopeHead::new(
            scope.clone(),
            ScopeAuthority::Unowned,
            1,
            successor.event_ref().clone(),
            None,
            "post-checkpoint-op".into(),
        )
        .unwrap();
        let pack = build_pack(
            &scope,
            Some(genesis.event_ref()),
            2,
            &[certificate_encoded.stored_bytes(), successor.stored_bytes()],
        )
        .unwrap();
        let entry = PackEntry::new(2, 3, pack.digest().clone()).unwrap();
        let (catalog_bytes, catalog_digest) = encode_catalog(
            &scope,
            &[entry],
            std::slice::from_ref(certificate_encoded.event_ref()),
        )
        .unwrap();
        let pointer_bytes = encode_pointer(&scope, &catalog_digest).unwrap();
        CheckpointFixture {
            scope,
            head,
            snapshot,
            certificate_bytes: certificate_encoded.stored_bytes().to_vec(),
            successor_bytes: successor.stored_bytes().to_vec(),
            successor_ref: successor.event_ref().clone(),
            pack,
            catalog_bytes,
            pointer_bytes,
        }
    }

    /// A cold start through a certified checkpoint reaches the same projection and cursor
    /// as the serial walk from genesis, with one snapshot GET plus `ceil(suffix / 256)`
    /// pack GETs beside the fixed head/pointer/catalog/certificate requests.
    #[tokio::test]
    async fn a_cold_start_installs_a_certified_checkpoint_and_matches_the_serial_walk() {
        let genesis = genesis();
        let fixture = checkpoint_fixture(&genesis, "cold-start").await;
        let scope = fixture.scope.clone();

        // The serial baseline replays the same chain from genesis.
        let serial_path = path("checkpoint-serial-baseline");
        let serial = DbHandle::spawn(serial_path.clone()).await.unwrap();
        let (store, _) = replay_store(vec![
            head_response(encode_head(&fixture.head).unwrap()),
            accel_miss(),
            accel_miss(),
            event_response(fixture.successor_bytes.clone()),
            event_response(fixture.certificate_bytes.clone()),
            event_response(genesis.event_bytes().to_vec()),
        ]);
        assert!(matches!(
            refresh(&store, &serial, &scope).await,
            ScopeReadiness::Ready { .. }
        ));
        let serial_cursor = serial.scope_cursor(&scope).await.unwrap();
        drop(serial);

        let cold_path = path("checkpoint-cold-install");
        let _ = fs::remove_file(&cold_path);
        let (store, client) = replay_store(vec![
            head_response(encode_head(&fixture.head).unwrap()),
            response(
                200,
                &[("etag", "\"pointer\"")],
                fixture.pointer_bytes.clone(),
            ),
            response(
                200,
                &[("etag", "\"catalog\"")],
                fixture.catalog_bytes.clone(),
            ),
            event_response(fixture.certificate_bytes.clone()),
            response(200, &[("etag", "\"pack\"")], fixture.pack.bytes().to_vec()),
            response(200, &[("etag", "\"snapshot\"")], fixture.snapshot.clone()),
        ]);
        let handle = open_projection(&store, &scope, &cold_path).await.unwrap();
        assert_eq!(handle.scope_cursor(&scope).await.unwrap(), serial_cursor);
        assert_eq!(
            handle.scope_cursor(&scope).await.unwrap(),
            (3, Some(fixture.successor_ref.digest().clone()))
        );
        assert_eq!(row_counts(&cold_path), row_counts(&serial_path));
        let requests: Vec<String> = client
            .actual_requests()
            .map(|request| {
                request
                    .uri()
                    .parse::<http::Uri>()
                    .unwrap()
                    .path()
                    .to_owned()
            })
            .collect();
        assert_eq!(requests.len(), 6);
        assert_eq!(
            requests
                .iter()
                .filter(|path| path.contains("/checkpoints/"))
                .count(),
            1
        );
        assert_eq!(
            requests
                .iter()
                .filter(|path| path.contains("/replay-packs/"))
                .count(),
            1
        );
        // The one event GET is the certificate read at its exact key.
        assert_eq!(
            requests
                .iter()
                .filter(|path| path.contains("/events/"))
                .count(),
            1
        );

        // A valid existing projection opens normally with no store request at all.
        drop(handle);
        let (offline, offline_client) = replay_store(vec![]);
        let reopened = open_projection(&offline, &scope, &cold_path).await.unwrap();
        assert_eq!(reopened.scope_cursor(&scope).await.unwrap(), serial_cursor);
        assert_eq!(offline_client.actual_requests().count(), 0);
        drop(reopened);
        fs::remove_file(serial_path).unwrap();
        fs::remove_file(cold_path).unwrap();
    }

    /// Builds the six-response script certifying `snapshot` at covered sequence 1
    /// through a certificate at sequence 2 under `operation`.
    fn certified_responses(
        genesis: &crate::scope::RootGenesis,
        snapshot: Vec<u8>,
        active_plan: Option<Digest>,
        operation: &str,
    ) -> Vec<http::Response<SdkBody>> {
        let scope = genesis.identity().clone();
        let payload = ProjectionCheckpointPayload::new(
            Digest::new(sha256(&snapshot)).unwrap(),
            snapshot.len() as u64,
            1,
            genesis.event_ref().digest().clone(),
            active_plan.clone(),
        )
        .unwrap();
        let certificate = ProjectionCheckpointEvent::new(
            EventEnvelope::new(
                scope.scope_id().clone(),
                2,
                Some(genesis.event_ref().clone()),
                1,
                operation.into(),
                PROJECTION_CHECKPOINT_PAYLOAD_TYPE.to_owned(),
            )
            .unwrap(),
            payload,
        )
        .unwrap();
        let encoded = encode_projection_checkpoint_event(&certificate).unwrap();
        let head = ScopeHead::new(
            scope.clone(),
            ScopeAuthority::Unowned,
            1,
            encoded.event_ref().clone(),
            active_plan,
            operation.into(),
        )
        .unwrap();
        let pack = build_pack(
            &scope,
            Some(genesis.event_ref()),
            2,
            &[encoded.stored_bytes()],
        )
        .unwrap();
        let entry = PackEntry::new(2, 2, pack.digest().clone()).unwrap();
        let (catalog, digest) =
            encode_catalog(&scope, &[entry], std::slice::from_ref(encoded.event_ref())).unwrap();
        let pointer = encode_pointer(&scope, &digest).unwrap();
        vec![
            head_response(encode_head(&head).unwrap()),
            response(200, &[("etag", "\"pointer\"")], pointer),
            response(200, &[("etag", "\"catalog\"")], catalog),
            event_response(encoded.stored_bytes().to_vec()),
            response(200, &[("etag", "\"pack\"")], pack.bytes().to_vec()),
            response(200, &[("etag", "\"snapshot\"")], snapshot),
        ]
    }

    /// Uncertified, wrong-digest, invalid-SQLite, wrong-plan, wrong-scope, and
    /// wrong-cursor checkpoints all fall through to the empty projection.
    #[tokio::test]
    async fn bad_checkpoints_fall_through_to_an_empty_projection() {
        let genesis = genesis();
        let fixture = checkpoint_fixture(&genesis, "fallback").await;
        let scope = fixture.scope.clone();

        // Uncertified: the catalog names packs but no checkpoint certificate.
        let entry = PackEntry::new(2, 3, fixture.pack.digest().clone()).unwrap();
        let (bare_catalog, bare_digest) = encode_catalog(&scope, &[entry], &[]).unwrap();
        let bare_pointer = encode_pointer(&scope, &bare_digest).unwrap();
        let uncertified = vec![
            head_response(encode_head(&fixture.head).unwrap()),
            response(200, &[("etag", "\"pointer\"")], bare_pointer),
            response(200, &[("etag", "\"catalog\"")], bare_catalog),
        ];

        // Wrong digest: the snapshot object does not hash to the certified digest.
        let mut corrupt_snapshot = fixture.snapshot.clone();
        let last = corrupt_snapshot.len() - 1;
        corrupt_snapshot[last] ^= 0xff;
        let wrong_digest = vec![
            head_response(encode_head(&fixture.head).unwrap()),
            response(
                200,
                &[("etag", "\"pointer\"")],
                fixture.pointer_bytes.clone(),
            ),
            response(
                200,
                &[("etag", "\"catalog\"")],
                fixture.catalog_bytes.clone(),
            ),
            event_response(fixture.certificate_bytes.clone()),
            response(200, &[("etag", "\"pack\"")], fixture.pack.bytes().to_vec()),
            response(200, &[("etag", "\"snapshot\"")], corrupt_snapshot),
        ];

        // Invalid SQLite: the certified length and digest match arbitrary junk.
        let junk = certified_responses(
            &genesis,
            b"not-a-sqlite-database".repeat(64),
            None,
            "junk-checkpoint-op",
        );

        // Wrong plan: the certificate claims an active plan the snapshot does not hold.
        let wrong_plan = certified_responses(
            &genesis,
            fixture.snapshot.clone(),
            Some(Digest::new("a".repeat(64)).unwrap()),
            "planned-checkpoint-op",
        );

        // Wrong scope: the snapshot is a valid projection of a foreign scope, so the
        // certified scope binding refuses it before installation.
        let foreign_genesis = root_genesis(
            &AdmittedCampaignConfig::new(
                WorkspaceId::new("workspace-b".into()).unwrap(),
                CampaignId::new("campaign-b".into()).unwrap(),
                b"admitted".to_vec(),
            )
            .unwrap(),
        )
        .unwrap();
        let foreign_live = path("checkpoint-foreign-live");
        let foreign_snap = path("checkpoint-foreign-snap");
        let _ = fs::remove_file(&foreign_snap);
        let live = DbHandle::spawn(foreign_live.clone()).await.unwrap();
        live.apply(root_mutation(&foreign_genesis)).await.unwrap();
        live.snapshot_to(foreign_genesis.head(), foreign_snap.clone())
            .await
            .unwrap();
        drop(live);
        let foreign_snapshot = fs::read(&foreign_snap).unwrap();
        fs::remove_file(&foreign_live).unwrap();
        fs::remove_file(&foreign_snap).unwrap();
        let wrong_scope =
            certified_responses(&genesis, foreign_snapshot, None, "foreign-checkpoint-op");

        // Wrong cursor: the snapshot is a valid projection of this scope, two events
        // deep, while the certificate covers cursor 1.
        let two_envelope = EventEnvelope::new(
            scope.scope_id().clone(),
            2,
            Some(genesis.event_ref().clone()),
            1,
            "two-op".into(),
            TEST_SUCCESSOR_PAYLOAD_TYPE.into(),
        )
        .unwrap();
        let two_encoded = encode_scope_event(&two_envelope, &Value::Null).unwrap();
        let two_head = ScopeHead::new(
            scope.clone(),
            ScopeAuthority::Unowned,
            1,
            two_encoded.event_ref().clone(),
            None,
            "two-op".into(),
        )
        .unwrap();
        let two_live = path("checkpoint-two-live");
        let two_snap = path("checkpoint-two-snap");
        let _ = fs::remove_file(&two_snap);
        let live = DbHandle::spawn(two_live.clone()).await.unwrap();
        live.apply(root_mutation(&genesis)).await.unwrap();
        live.apply(
            ScopeProjectionEvent::new(
                scope.clone(),
                two_envelope,
                two_encoded.event_ref().clone(),
                ScopeProjectionPayload::TestSuccessor,
                1,
            )
            .unwrap(),
        )
        .await
        .unwrap();
        live.snapshot_to(&two_head, two_snap.clone()).await.unwrap();
        drop(live);
        let two_snapshot = fs::read(&two_snap).unwrap();
        fs::remove_file(&two_live).unwrap();
        fs::remove_file(&two_snap).unwrap();
        let wrong_cursor = certified_responses(&genesis, two_snapshot, None, "wrong-cursor-op");

        for responses in [
            uncertified,
            wrong_digest,
            junk,
            wrong_plan,
            wrong_scope,
            wrong_cursor,
        ] {
            let cold_path = path("checkpoint-fallback");
            let _ = fs::remove_file(&cold_path);
            let (store, _) = replay_store(responses);
            let handle = open_projection(&store, &scope, &cold_path).await.unwrap();
            assert_eq!(handle.scope_cursor(&scope).await.unwrap(), (0, None));
            assert_eq!(
                row_counts(&cold_path),
                (0, 0),
                "a refused checkpoint must leave a fresh empty projection"
            );
            let leaked = fs::read_dir(cold_path.parent().unwrap())
                .unwrap()
                .filter(|entry| {
                    entry
                        .as_ref()
                        .unwrap()
                        .file_name()
                        .to_str()
                        .unwrap()
                        .starts_with(&format!(
                            "{}.checkpoint-",
                            cold_path.file_name().unwrap().to_str().unwrap()
                        ))
                })
                .count();
            assert_eq!(leaked, 0, "a refused install must remove its staging file");
            drop(handle);
            fs::remove_file(cold_path).unwrap();
        }
    }

    /// A snapshot whose bytes match the certified length but not the certified digest
    /// falls through without installation.
    #[tokio::test]
    async fn a_snapshot_matching_length_but_not_digest_falls_through() {
        let genesis = genesis();
        let fixture = checkpoint_fixture(&genesis, "digest-split").await;
        let scope = fixture.scope.clone();
        // The certificate names the exact snapshot length with a digest of other bytes.
        let payload = ProjectionCheckpointPayload::new(
            Digest::new(sha256(b"different-bytes")).unwrap(),
            fixture.snapshot.len() as u64,
            1,
            genesis.event_ref().digest().clone(),
            None,
        )
        .unwrap();
        let certificate = ProjectionCheckpointEvent::new(
            EventEnvelope::new(
                scope.scope_id().clone(),
                2,
                Some(genesis.event_ref().clone()),
                1,
                "digest-split-op".into(),
                PROJECTION_CHECKPOINT_PAYLOAD_TYPE.to_owned(),
            )
            .unwrap(),
            payload,
        )
        .unwrap();
        let encoded = encode_projection_checkpoint_event(&certificate).unwrap();
        let head = ScopeHead::new(
            scope.clone(),
            ScopeAuthority::Unowned,
            1,
            encoded.event_ref().clone(),
            None,
            "digest-split-op".into(),
        )
        .unwrap();
        let pack = build_pack(
            &scope,
            Some(genesis.event_ref()),
            2,
            &[encoded.stored_bytes()],
        )
        .unwrap();
        let entry = PackEntry::new(2, 2, pack.digest().clone()).unwrap();
        let (catalog, digest) =
            encode_catalog(&scope, &[entry], std::slice::from_ref(encoded.event_ref())).unwrap();
        let pointer = encode_pointer(&scope, &digest).unwrap();
        let cold_path = path("checkpoint-digest-split");
        let (store, _) = replay_store(vec![
            head_response(encode_head(&head).unwrap()),
            response(200, &[("etag", "\"pointer\"")], pointer),
            response(200, &[("etag", "\"catalog\"")], catalog),
            event_response(encoded.stored_bytes().to_vec()),
            response(200, &[("etag", "\"pack\"")], pack.bytes().to_vec()),
            response(200, &[("etag", "\"snapshot\"")], fixture.snapshot.clone()),
        ]);
        let handle = open_projection(&store, &scope, &cold_path).await.unwrap();
        assert_eq!(handle.scope_cursor(&scope).await.unwrap(), (0, None));
        drop(handle);
        fs::remove_file(cold_path).unwrap();
    }

    /// Candidates are attempted newest first; a failing newer candidate falls to an
    /// older one, and a candidate beyond the pinned tail is skipped without a read.
    #[tokio::test]
    async fn checkpoint_candidates_try_newest_first_and_fall_to_older_ones() {
        let genesis = genesis();
        let scope = genesis.identity().clone();

        let live_path = path("candidates-live");
        let snap_path = path("candidates-snap");
        let _ = fs::remove_file(&snap_path);
        let live = DbHandle::spawn(live_path.clone()).await.unwrap();
        live.apply(root_mutation(&genesis)).await.unwrap();
        live.snapshot_to(genesis.head(), snap_path.clone())
            .await
            .unwrap();
        drop(live);
        let old_snapshot = fs::read(&snap_path).unwrap();
        fs::remove_file(&live_path).unwrap();
        fs::remove_file(&snap_path).unwrap();

        let old_payload = ProjectionCheckpointPayload::new(
            Digest::new(sha256(&old_snapshot)).unwrap(),
            old_snapshot.len() as u64,
            1,
            genesis.event_ref().digest().clone(),
            None,
        )
        .unwrap();
        let old_certificate = ProjectionCheckpointEvent::new(
            EventEnvelope::new(
                scope.scope_id().clone(),
                2,
                Some(genesis.event_ref().clone()),
                1,
                "old-cert-op".into(),
                PROJECTION_CHECKPOINT_PAYLOAD_TYPE.to_owned(),
            )
            .unwrap(),
            old_payload,
        )
        .unwrap();
        let old_encoded = encode_projection_checkpoint_event(&old_certificate).unwrap();
        let mid_envelope = EventEnvelope::new(
            scope.scope_id().clone(),
            3,
            Some(old_encoded.event_ref().clone()),
            1,
            "mid-op".into(),
            TEST_SUCCESSOR_PAYLOAD_TYPE.into(),
        )
        .unwrap();
        let mid = encode_scope_event(&mid_envelope, &Value::Null).unwrap();
        // The newer certificate is fully certified but its snapshot object is missing.
        let new_payload = ProjectionCheckpointPayload::new(
            Digest::new(sha256(b"missing-snapshot")).unwrap(),
            1_024,
            3,
            mid.event_ref().digest().clone(),
            None,
        )
        .unwrap();
        let new_certificate = ProjectionCheckpointEvent::new(
            EventEnvelope::new(
                scope.scope_id().clone(),
                4,
                Some(mid.event_ref().clone()),
                1,
                "new-cert-op".into(),
                PROJECTION_CHECKPOINT_PAYLOAD_TYPE.to_owned(),
            )
            .unwrap(),
            new_payload,
        )
        .unwrap();
        let new_encoded = encode_projection_checkpoint_event(&new_certificate).unwrap();
        let head = ScopeHead::new(
            scope.clone(),
            ScopeAuthority::Unowned,
            1,
            new_encoded.event_ref().clone(),
            None,
            "new-cert-op".into(),
        )
        .unwrap();
        let pack = build_pack(
            &scope,
            Some(genesis.event_ref()),
            2,
            &[
                old_encoded.stored_bytes(),
                mid.stored_bytes(),
                new_encoded.stored_bytes(),
            ],
        )
        .unwrap();
        let entry = PackEntry::new(2, 4, pack.digest().clone()).unwrap();
        let beyond = ScopeEventRef::new(99, Digest::new("9".repeat(64)).unwrap()).unwrap();
        let (catalog_bytes, catalog_digest) = encode_catalog(
            &scope,
            &[entry],
            &[
                old_encoded.event_ref().clone(),
                new_encoded.event_ref().clone(),
                beyond,
            ],
        )
        .unwrap();
        let pointer_bytes = encode_pointer(&scope, &catalog_digest).unwrap();

        let cold_path = path("candidates-cold");
        let _ = fs::remove_file(&cold_path);
        let (store, client) = replay_store(vec![
            head_response(encode_head(&head).unwrap()),
            response(200, &[("etag", "\"pointer\"")], pointer_bytes),
            response(200, &[("etag", "\"catalog\"")], catalog_bytes),
            event_response(new_encoded.stored_bytes().to_vec()),
            response(200, &[("etag", "\"pack\"")], pack.bytes().to_vec()),
            response(404, &[], SdkBody::empty()),
            event_response(old_encoded.stored_bytes().to_vec()),
            response(200, &[("etag", "\"pack\"")], pack.bytes().to_vec()),
            response(200, &[("etag", "\"snapshot\"")], old_snapshot),
        ]);
        let handle = open_projection(&store, &scope, &cold_path).await.unwrap();
        assert_eq!(
            handle.scope_cursor(&scope).await.unwrap(),
            (4, Some(new_encoded.event_ref().digest().clone()))
        );
        let requests: Vec<String> = client
            .actual_requests()
            .map(|request| {
                request
                    .uri()
                    .parse::<http::Uri>()
                    .unwrap()
                    .path()
                    .to_owned()
            })
            .collect();
        assert_eq!(requests.len(), 9);
        // Newest first: the sequence-4 certificate and its snapshot are attempted
        // before the sequence-2 certificate.
        assert!(requests[3].contains("/events/0000000000000004-"));
        assert!(requests[5].contains("/checkpoints/0000000000000003-"));
        assert!(requests[6].contains("/events/0000000000000002-"));
        assert!(requests[8].contains("/checkpoints/0000000000000001-"));
        // The beyond-tail candidate is never read.
        assert!(
            requests
                .iter()
                .all(|path| !path.contains("0000000000000099"))
        );
        drop(handle);
        fs::remove_file(cold_path).unwrap();
    }

    /// A warm refresh lists strictly after the cursor sequence: the boundary key ends
    /// with `.`, which sorts between the cursor key and every later sequence.
    #[tokio::test]
    async fn a_warm_list_refresh_starts_after_the_cursor_boundary() {
        let genesis = genesis();
        let scope = genesis.identity().clone();
        let (events, head) = accel_chain(&genesis, 3);
        let keys = event_keys(&scope, &events);
        let db_path = path("list-warm-cursor");
        let handle = DbHandle::spawn(db_path.clone()).await.unwrap();
        let (store, _) = replay_store(vec![
            head_response(genesis.head_bytes().to_vec()),
            accel_miss(),
            accel_miss(),
            event_response(events[0].1.clone()),
        ]);
        assert!(matches!(
            refresh(&store, &handle, &scope).await,
            ScopeReadiness::Ready { .. }
        ));
        assert_eq!(handle.scope_cursor(&scope).await.unwrap().0, 1);

        let (store, requests) =
            keyed_store(accel_route(&scope, &head, &events[1..], keys[1..].to_vec()));
        assert!(matches!(
            refresh(&store, &handle, &scope).await,
            ScopeReadiness::Ready { .. }
        ));
        assert_eq!(handle.scope_cursor(&scope).await.unwrap().0, 3);
        let recorded = requests.lock().unwrap().clone();
        assert_eq!(recorded.len(), 7);
        assert!(recorded[2].contains("list-type=2"));
        assert!(
            recorded[2].contains("start-after=") && recorded[2].contains("0000000000000001."),
            "the listing must start after every key at the cursor sequence: {}",
            recorded[2]
        );
        drop(handle);
        fs::remove_file(db_path).unwrap();
    }

    /// A checkpointed cold start over a suffix wider than one pack performs one
    /// snapshot GET plus `ceil(suffix / 256)` pack GETs.
    #[tokio::test]
    async fn a_checkpoint_cold_start_reads_the_suffix_in_pack_sized_requests() {
        const COUNT: usize = 302;
        let genesis = genesis();
        let scope = genesis.identity().clone();

        let live_path = path("ratio-live");
        let snap_path = path("ratio-snap");
        let _ = fs::remove_file(&snap_path);
        let live = DbHandle::spawn(live_path.clone()).await.unwrap();
        live.apply(root_mutation(&genesis)).await.unwrap();
        live.snapshot_to(genesis.head(), snap_path.clone())
            .await
            .unwrap();
        drop(live);
        let snapshot = fs::read(&snap_path).unwrap();
        fs::remove_file(&live_path).unwrap();
        fs::remove_file(&snap_path).unwrap();

        let payload = ProjectionCheckpointPayload::new(
            Digest::new(sha256(&snapshot)).unwrap(),
            snapshot.len() as u64,
            1,
            genesis.event_ref().digest().clone(),
            None,
        )
        .unwrap();
        let certificate = ProjectionCheckpointEvent::new(
            EventEnvelope::new(
                scope.scope_id().clone(),
                2,
                Some(genesis.event_ref().clone()),
                1,
                "ratio-cert-op".into(),
                PROJECTION_CHECKPOINT_PAYLOAD_TYPE.to_owned(),
            )
            .unwrap(),
            payload,
        )
        .unwrap();
        let cert_encoded = encode_projection_checkpoint_event(&certificate).unwrap();
        let mut suffix: Vec<(ScopeEventRef, Vec<u8>)> = vec![(
            cert_encoded.event_ref().clone(),
            cert_encoded.stored_bytes().to_vec(),
        )];
        for sequence in 3..=COUNT as u64 {
            let parent = suffix.last().unwrap().0.clone();
            let envelope = EventEnvelope::new(
                scope.scope_id().clone(),
                sequence,
                Some(parent),
                1,
                format!("ratio-op-{sequence}"),
                TEST_SUCCESSOR_PAYLOAD_TYPE.into(),
            )
            .unwrap();
            let encoded = encode_scope_event(&envelope, &Value::Null).unwrap();
            suffix.push((encoded.event_ref().clone(), encoded.stored_bytes().to_vec()));
        }
        let head = ScopeHead::new(
            scope.clone(),
            ScopeAuthority::Unowned,
            1,
            suffix.last().unwrap().0.clone(),
            None,
            format!("ratio-op-{COUNT}"),
        )
        .unwrap();
        let mut entries = Vec::new();
        let mut packs = Vec::new();
        let mut parent = genesis.event_ref().clone();
        let mut start = 2_u64;
        for group in suffix.chunks(256) {
            let slices: Vec<&[u8]> = group.iter().map(|(_, bytes)| bytes.as_slice()).collect();
            let pack = build_pack(&scope, Some(&parent), start, &slices).unwrap();
            entries.push(
                PackEntry::new(start, start + group.len() as u64 - 1, pack.digest().clone())
                    .unwrap(),
            );
            parent = group.last().unwrap().0.clone();
            start += group.len() as u64;
            packs.push(pack);
        }
        let suffix_len = COUNT - 1;
        assert_eq!(packs.len(), suffix_len.div_ceil(256));
        let (catalog_bytes, catalog_digest) = encode_catalog(
            &scope,
            &entries,
            std::slice::from_ref(cert_encoded.event_ref()),
        )
        .unwrap();
        let pointer_bytes = encode_pointer(&scope, &catalog_digest).unwrap();

        let cold_path = path("ratio-cold");
        let _ = fs::remove_file(&cold_path);
        let mut responses = vec![
            head_response(encode_head(&head).unwrap()),
            response(200, &[("etag", "\"pointer\"")], pointer_bytes),
            response(200, &[("etag", "\"catalog\"")], catalog_bytes),
            event_response(cert_encoded.stored_bytes().to_vec()),
        ];
        responses.extend(
            packs
                .iter()
                .map(|pack| response(200, &[("etag", "\"pack\"")], pack.bytes().to_vec())),
        );
        responses.push(response(200, &[("etag", "\"snapshot\"")], snapshot));
        let (store, client) = replay_store(responses);
        let handle = open_projection(&store, &scope, &cold_path).await.unwrap();
        assert_eq!(handle.scope_cursor(&scope).await.unwrap().0, COUNT as u64);
        let requests: Vec<String> = client
            .actual_requests()
            .map(|request| {
                request
                    .uri()
                    .parse::<http::Uri>()
                    .unwrap()
                    .path()
                    .to_owned()
            })
            .collect();
        let count_of = |segment: &str| {
            requests
                .iter()
                .filter(|path| path.contains(segment))
                .count()
        };
        assert_eq!(count_of("/checkpoints/"), 1);
        assert_eq!(count_of("/replay-packs/"), suffix_len.div_ceil(256));
        assert_eq!(count_of("/events/"), 1);
        assert_eq!(requests.len(), 3 + 1 + suffix_len.div_ceil(256) + 1);
        drop(handle);
        fs::remove_file(cold_path).unwrap();
    }

    /// A checkpoint cold start over a plan-, work-, and grant-bearing history matches
    /// the serial walk row for row.
    #[tokio::test]
    async fn a_checkpoint_cold_start_reproduces_plan_and_grant_state() {
        use crate::domain::work::WorkId;
        use crate::scope::{GrantActivatedEvent, GrantActivatedPayload};

        const NOW: u64 = 1_700_000_000_000;
        let genesis = genesis();
        let fixture = admitted_fixture(&genesis, NOW);
        let scope = fixture.scope.clone();
        let plan = fixture.plan_digest.clone();
        let admission_ref =
            ScopeEventRef::new(2, Digest::new(sha256(&fixture.admission_bytes)).unwrap()).unwrap();
        let grant_event = GrantActivatedEvent::new(
            EventEnvelope::new(
                scope.scope_id().clone(),
                3,
                Some(admission_ref.clone()),
                1,
                "grant-op-3".into(),
                GRANT_ACTIVATED_PAYLOAD_TYPE.to_owned(),
            )
            .unwrap(),
            GrantActivatedPayload::new(
                WorkId::new("work-a".into()).unwrap(),
                1,
                2,
                Digest::new("d".repeat(64)).unwrap(),
                1,
                5,
                NOW + 20_000,
            )
            .unwrap(),
        )
        .unwrap();
        let grant_encoded = crate::scope::encode_grant_activated_event(&grant_event).unwrap();
        let head3 = ScopeHead::new(
            scope.clone(),
            ScopeAuthority::Unowned,
            1,
            grant_encoded.event_ref().clone(),
            Some(plan.clone()),
            "grant-op-3".into(),
        )
        .unwrap();

        // The live projection replays the grant-bearing chain and is snapshotted.
        let live_path = path("grant-checkpoint-live");
        let snap_path = path("grant-checkpoint-snap");
        let _ = fs::remove_file(&snap_path);
        let live = DbHandle::spawn(live_path.clone()).await.unwrap();
        let (store, _) = replay_store(vec![
            head_response(encode_head(&head3).unwrap()),
            accel_miss(),
            accel_miss(),
            event_response(grant_encoded.stored_bytes().to_vec()),
            event_response(fixture.admission_bytes.clone()),
            response(
                200,
                &[("etag", "\"plan\"")],
                fixture.admissible_bytes.clone(),
            ),
            event_response(genesis.event_bytes().to_vec()),
            response(500, &[], SdkBody::empty()),
            response(500, &[], SdkBody::empty()),
            response(404, &[], SdkBody::empty()),
            response(404, &[], SdkBody::empty()),
        ]);
        assert!(matches!(
            refresh(&store, &live, &scope).await,
            ScopeReadiness::Ready { .. }
        ));
        live.snapshot_to(&head3, snap_path.clone()).await.unwrap();
        drop(live);
        let snapshot = fs::read(&snap_path).unwrap();
        fs::remove_file(&live_path).unwrap();
        fs::remove_file(&snap_path).unwrap();

        let payload = ProjectionCheckpointPayload::new(
            Digest::new(sha256(&snapshot)).unwrap(),
            snapshot.len() as u64,
            3,
            grant_encoded.event_ref().digest().clone(),
            Some(plan.clone()),
        )
        .unwrap();
        let certificate = ProjectionCheckpointEvent::new(
            EventEnvelope::new(
                scope.scope_id().clone(),
                4,
                Some(grant_encoded.event_ref().clone()),
                1,
                "grant-cert-op".into(),
                PROJECTION_CHECKPOINT_PAYLOAD_TYPE.to_owned(),
            )
            .unwrap(),
            payload,
        )
        .unwrap();
        let cert_encoded = encode_projection_checkpoint_event(&certificate).unwrap();
        let head4 = ScopeHead::new(
            scope.clone(),
            ScopeAuthority::Unowned,
            1,
            cert_encoded.event_ref().clone(),
            Some(plan.clone()),
            "grant-cert-op".into(),
        )
        .unwrap();
        let pack = build_pack(
            &scope,
            Some(grant_encoded.event_ref()),
            4,
            &[cert_encoded.stored_bytes()],
        )
        .unwrap();
        let entry = PackEntry::new(4, 4, pack.digest().clone()).unwrap();
        let (catalog_bytes, catalog_digest) = encode_catalog(
            &scope,
            &[entry],
            std::slice::from_ref(cert_encoded.event_ref()),
        )
        .unwrap();
        let pointer_bytes = encode_pointer(&scope, &catalog_digest).unwrap();

        // The serial baseline replays the whole chain from genesis.
        let serial_path = path("grant-checkpoint-serial");
        let serial = DbHandle::spawn(serial_path.clone()).await.unwrap();
        let (store, _) = replay_store(vec![
            head_response(encode_head(&head4).unwrap()),
            accel_miss(),
            accel_miss(),
            event_response(cert_encoded.stored_bytes().to_vec()),
            event_response(grant_encoded.stored_bytes().to_vec()),
            event_response(fixture.admission_bytes.clone()),
            response(
                200,
                &[("etag", "\"plan\"")],
                fixture.admissible_bytes.clone(),
            ),
            event_response(genesis.event_bytes().to_vec()),
            response(500, &[], SdkBody::empty()),
            response(500, &[], SdkBody::empty()),
            response(404, &[], SdkBody::empty()),
            response(404, &[], SdkBody::empty()),
        ]);
        assert!(matches!(
            refresh(&store, &serial, &scope).await,
            ScopeReadiness::Ready { .. }
        ));
        let serial_cursor = serial.scope_cursor(&scope).await.unwrap();
        serial.drain().await.unwrap();
        drop(serial);

        // The cold start installs the snapshot, applies the packed suffix, and restores
        // claims on its first refresh.
        let cold_path = path("grant-checkpoint-cold");
        let _ = fs::remove_file(&cold_path);
        let (store, _) = replay_store(vec![
            head_response(encode_head(&head4).unwrap()),
            response(200, &[("etag", "\"pointer\"")], pointer_bytes),
            response(200, &[("etag", "\"catalog\"")], catalog_bytes),
            event_response(cert_encoded.stored_bytes().to_vec()),
            response(200, &[("etag", "\"pack\"")], pack.bytes().to_vec()),
            response(200, &[("etag", "\"snapshot\"")], snapshot),
        ]);
        let cold = open_projection(&store, &scope, &cold_path).await.unwrap();
        let (store, _) = replay_store(vec![
            head_response(encode_head(&head4).unwrap()),
            response(404, &[], SdkBody::empty()),
            response(404, &[], SdkBody::empty()),
        ]);
        assert!(matches!(
            refresh(&store, &cold, &scope).await,
            ScopeReadiness::Ready { .. }
        ));
        assert_eq!(cold.scope_cursor(&scope).await.unwrap(), serial_cursor);
        cold.drain().await.unwrap();
        drop(cold);

        // The fixture genuinely carries plan, work, and grant state.
        let rows = scheduling_rows(&cold_path);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].granted_units, Some(5));
        assert_eq!(rows[0].plan_digest, plan.as_str());
        assert_eq!(
            projection_content(&cold_path),
            projection_content(&serial_path)
        );
        fs::remove_file(serial_path).unwrap();
        fs::remove_file(cold_path).unwrap();
    }

    /// Interruption immediately before the rename leaves the destination untouched;
    /// interruption immediately after it leaves an independently valid projection at the
    /// covered cursor that the next refresh completes.
    #[tokio::test]
    async fn an_interrupted_installation_leaves_a_usable_destination() {
        let genesis = genesis();
        let fixture = checkpoint_fixture(&genesis, "interrupted").await;
        let scope = fixture.scope.clone();
        let destination = path("checkpoint-interrupted");
        let _ = fs::remove_file(&destination);

        let mut staging = destination.as_os_str().to_owned();
        staging.push(".checkpoint-9999999-0");
        let staging = PathBuf::from(staging);
        fs::write(&staging, b"stale-staging").unwrap();
        let staging_siblings = || {
            let name = destination
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .to_owned();
            let mut siblings: Vec<String> = fs::read_dir(destination.parent().unwrap())
                .unwrap()
                .filter_map(|entry| {
                    let entry = entry.unwrap().file_name().to_str().unwrap().to_owned();
                    entry
                        .starts_with(&format!("{name}.checkpoint-"))
                        .then_some(entry)
                })
                .collect();
            siblings.sort();
            siblings
        };
        assert!(!destination.exists());
        let (store, _) = replay_store(vec![
            head_response(encode_head(&fixture.head).unwrap()),
            response(
                200,
                &[("etag", "\"pointer\"")],
                fixture.pointer_bytes.clone(),
            ),
            response(
                200,
                &[("etag", "\"catalog\"")],
                fixture.catalog_bytes.clone(),
            ),
            event_response(fixture.certificate_bytes.clone()),
            response(200, &[("etag", "\"pack\"")], fixture.pack.bytes().to_vec()),
            response(200, &[("etag", "\"snapshot\"")], fixture.snapshot.clone()),
        ]);
        let handle = open_projection(&store, &scope, &destination).await.unwrap();
        assert_eq!(handle.scope_cursor(&scope).await.unwrap().0, 3);
        assert_eq!(
            staging_siblings(),
            vec![staging.file_name().unwrap().to_str().unwrap().to_owned()],
            "the retried install must leave no staging sibling of its own"
        );
        fs::remove_file(&staging).unwrap();
        drop(handle);
        fs::remove_file(&destination).unwrap();

        // After the rename: the destination holds the validated snapshot at its covered
        // cursor. It opens as a valid existing projection and refresh replays the
        // suffix.
        fs::write(&destination, &fixture.snapshot).unwrap();
        let (offline, _) = replay_store(vec![]);
        let handle = open_projection(&offline, &scope, &destination)
            .await
            .unwrap();
        assert_eq!(
            handle.scope_cursor(&scope).await.unwrap(),
            (1, Some(genesis.event_ref().digest().clone()))
        );
        let (store, _) = replay_store(vec![
            head_response(encode_head(&fixture.head).unwrap()),
            response(
                200,
                &[("etag", "\"pointer\"")],
                fixture.pointer_bytes.clone(),
            ),
            response(
                200,
                &[("etag", "\"catalog\"")],
                fixture.catalog_bytes.clone(),
            ),
            response(200, &[("etag", "\"pack\"")], fixture.pack.bytes().to_vec()),
        ]);
        assert!(matches!(
            refresh(&store, &handle, &scope).await,
            ScopeReadiness::Ready { .. }
        ));
        assert_eq!(
            handle.scope_cursor(&scope).await.unwrap(),
            (3, Some(fixture.successor_ref.digest().clone()))
        );
        drop(handle);
        fs::remove_file(destination).unwrap();
    }
}
