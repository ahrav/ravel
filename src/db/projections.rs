//! The projection file is disposable: one neutral application id rejects unrelated files,
//! and a file that fails validation is rebuilt from durable history rather than migrated.
//! It persists plan-stable histories at any controller epoch: a scope row's `scope_epoch`
//! advances monotonically and may lead its applied events, because authority transitions
//! advance the epoch without publishing an event.
//!
//! Work readiness is derived by query from admitted work, dependencies, revision, claim
//! state, and terminal evidence; it is never stored as a flag. A reopened file keeps its work
//! rows; a rebuilt file recovers them by re-applying the admission event, whose payload names
//! the plan object replay re-fetches. Claim leases and readiness clocks are Unix-epoch
//! milliseconds on one shared base.
//! commentlint: allow(JUDGE)
//!
//! The epoch ordering rule lives in `sync::head`.

use std::{error::Error, fmt, num::NonZeroU64, path::Path};

use rusqlite::{OpenFlags, OptionalExtension, params};

use crate::{
    domain::{
        proposal::{
            INITIAL_WORK_REVISION, MAX_STORED_INTEGER, ObservationFact, PlanProposal,
            ProposalFacts, TargetBounds, validate_proposal,
        },
        validation::ValidationError,
        work::{WorkId, WorkRef},
    },
    scope::{
        Digest, EventEnvelope, ScopeEventRef, ScopeHead, ScopeIdentity, payload_type_registered,
    },
};

// "RAVL": rejects an unrelated SQLite file without naming a protocol era.
const APPLICATION_ID: i32 = 0x5241_564c;
const TABLES: [&str; 4] = [
    "admitted_work",
    "applied_scope_events",
    "scopes",
    "work_dependencies",
];

const SCOPE_SELECT_SQL: &str = "SELECT campaign_id, sequence, tail_event_digest, \
     active_plan_digest, scope_epoch FROM scopes WHERE scope_id = ?1";
const SCOPE_HEAD_MATCH_SQL: &str = "SELECT scope.campaign_id, scope.sequence, \
     scope.tail_event_digest, scope.active_plan_digest, scope.scope_epoch, event.operation_id \
     FROM scopes AS scope \
     JOIN applied_scope_events AS event \
       ON event.scope_id = scope.scope_id AND event.sequence = scope.sequence \
     WHERE scope.scope_id = ?1";
const EVENT_AT_SEQUENCE_SQL: &str =
    "SELECT digest FROM applied_scope_events WHERE scope_id = ?1 AND sequence = ?2";
const OPERATION_CONFLICT_SQL: &str = "SELECT EXISTS(SELECT 1 FROM applied_scope_events \
     WHERE scope_id = ?1 AND operation_id = ?2 AND (sequence <> ?3 OR digest <> ?4))";
const DUPLICATE_EXISTS_SQL: &str = "SELECT EXISTS(SELECT 1 FROM applied_scope_events \
     WHERE scope_id = ?1 AND (digest = ?2 OR operation_id = ?3))";
const SCOPE_UPDATE_SQL: &str = "UPDATE scopes SET sequence = ?1, tail_event_digest = ?2, \
     scope_epoch = ?3 WHERE scope_id = ?4";
const TAIL_WRITER_EPOCH_SQL: &str = "SELECT writer_epoch FROM applied_scope_events \
     WHERE scope_id = ?1 AND sequence = ?2";
const ADMIT_WORK_SQL: &str = "INSERT INTO admitted_work \
     (scope_id, work_id, work_revision, admitted_scope_epoch, max_attempts, deadline_unix_ms, \
      claim_fence, claim_lease_until, grant_fence, terminal_result_digest) \
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, NULL, NULL, NULL) \
     ON CONFLICT DO UPDATE SET admitted_scope_epoch = ?4 \
     WHERE admitted_scope_epoch <= ?4";
const ADMITTED_REVISION_EXISTS_SQL: &str = "SELECT EXISTS(SELECT 1 FROM admitted_work \
     WHERE scope_id = ?1 AND work_id = ?2 AND work_revision = ?3)";
const PROJECTED_SCOPE_EPOCH_SQL: &str = "SELECT scope_epoch FROM scopes WHERE scope_id = ?1";
const OBJECTIVE_SQL: &str = "SELECT objective_digest FROM scopes WHERE scope_id = ?1";
const OBSERVATION_FACT_SQL: &str =
    "SELECT digest, payload_type FROM applied_scope_events WHERE scope_id = ?1 AND sequence = ?2";
/// Only admission sets the pair, and only from no plan: rowcount 0 is a second plan.
const ADMIT_PLAN_SQL: &str = "UPDATE scopes \
     SET active_plan_digest = ?2, reserved_budget_units = ?3 \
     WHERE scope_id = ?1 AND active_plan_digest IS NULL";
/// A grant is bound to the exact claim fence it was issued for, so a reclaimed work revision
/// cannot resume under a grant minted for the fence it superseded.
const RECORD_GRANT_SQL: &str = "UPDATE admitted_work SET grant_fence = ?4 \
     WHERE scope_id = ?1 AND work_id = ?2 AND work_revision = ?3 \
       AND terminal_result_digest IS NULL AND claim_fence = ?4";
/// Restart resumes a revision only while every binding is still current: the admitting epoch is
/// not ahead of the controller's, the revision is the highest admitted, carries no terminal
/// evidence, its deadline is still ahead of `?3`, the claim lease is live, and a grant is bound
/// to that exact claim fence.
const RESUMABLE_WORK_SQL: &str = "SELECT work_id, work_revision FROM admitted_work AS resumable \
     WHERE resumable.scope_id = ?1 \
       AND resumable.deadline_unix_ms > ?3 \
       AND resumable.terminal_result_digest IS NULL \
       AND resumable.admitted_scope_epoch <= ?2 \
       AND resumable.claim_lease_until > ?3 \
       AND resumable.grant_fence = resumable.claim_fence \
       AND resumable.work_revision = (SELECT MAX(latest.work_revision) \
             FROM admitted_work AS latest \
             WHERE latest.scope_id = resumable.scope_id \
               AND latest.work_id = resumable.work_id) \
     ORDER BY work_id";
const WORK_DEPENDENCIES_SQL: &str = "SELECT depends_on_work_id FROM work_dependencies \
     WHERE scope_id = ?1 AND work_id = ?2 AND work_revision = ?3 \
     ORDER BY depends_on_work_id";
const ADMIT_DEPENDENCY_SQL: &str = "INSERT INTO work_dependencies \
     (scope_id, work_id, work_revision, depends_on_work_id) VALUES (?1, ?2, ?3, ?4)";
/// A recorded fence never regresses. A higher `?4` replaces `claim_fence` only when
/// `claim_lease_until <= ?6`; an equal `?4` only extends its own lease.
const RECORD_CLAIM_SQL: &str = "UPDATE admitted_work \
     SET claim_fence = ?4, claim_lease_until = ?5 \
     WHERE scope_id = ?1 AND work_id = ?2 AND work_revision = ?3 \
       AND terminal_result_digest IS NULL \
       AND (claim_fence IS NULL \
            OR (claim_fence < ?4 AND claim_lease_until <= ?6) \
            OR (claim_fence = ?4 AND claim_lease_until <= ?5))";
/// Terminal evidence names the exact claim it came from, so a submission from a superseded
/// claim cannot mark work terminal.
#[cfg(test)]
const RECORD_TERMINAL_SQL: &str = "UPDATE admitted_work SET terminal_result_digest = ?5 \
     WHERE scope_id = ?1 AND work_id = ?2 AND work_revision = ?3 \
       AND claim_fence = ?4 \
       AND (terminal_result_digest IS NULL OR terminal_result_digest = ?5)";

/// Readiness is a query, not a stored flag: an admitted revision is ready when it is the
/// highest admitted revision of its work id, has a deadline still ahead of `?2`, carries no
/// terminal evidence, holds no claim whose lease is still live at `?2`, and every dependency's
/// own highest admitted revision carries terminal evidence. Expiry gates scheduling only; claim
/// and grant mutations stay deadline-free.
const READY_WORK_SQL: &str = "SELECT work_id, work_revision FROM admitted_work AS ready \
     WHERE ready.scope_id = ?1 \
       AND ready.deadline_unix_ms > ?2 \
       AND ready.terminal_result_digest IS NULL \
       AND (ready.claim_lease_until IS NULL OR ready.claim_lease_until <= ?2) \
       AND ready.work_revision = (SELECT MAX(newer.work_revision) FROM admitted_work AS newer \
             WHERE newer.scope_id = ready.scope_id AND newer.work_id = ready.work_id) \
       AND NOT EXISTS (SELECT 1 FROM work_dependencies AS dependency \
             WHERE dependency.scope_id = ready.scope_id \
               AND dependency.work_id = ready.work_id \
               AND dependency.work_revision = ready.work_revision \
               AND NOT EXISTS (SELECT 1 FROM admitted_work AS resolved \
                     WHERE resolved.scope_id = dependency.scope_id \
                       AND resolved.work_id = dependency.depends_on_work_id \
                       AND resolved.terminal_result_digest IS NOT NULL \
                       AND resolved.work_revision = (SELECT MAX(latest.work_revision) \
                             FROM admitted_work AS latest \
                             WHERE latest.scope_id = resolved.scope_id \
                               AND latest.work_id = resolved.work_id))) \
     ORDER BY work_id";

const SCHEMA: &str = "
CREATE TABLE scopes (
    scope_id TEXT PRIMARY KEY NOT NULL,
    campaign_id TEXT NOT NULL,
    parent_scope_id TEXT,
    delegation_digest TEXT,
    sequence INTEGER NOT NULL,
    tail_event_digest TEXT NOT NULL,
    active_plan_digest TEXT,
    scope_epoch INTEGER NOT NULL,
    objective_digest TEXT NOT NULL,
    reserved_budget_units INTEGER,
    CHECK (length(scope_id) = 64 AND length(CAST(scope_id AS BLOB)) = 64
        AND scope_id NOT GLOB '*[^0-9a-f]*'),
    CHECK (length(CAST(campaign_id AS BLOB)) BETWEEN 1 AND 128
        AND instr(CAST(campaign_id AS BLOB), CAST('/' AS BLOB)) = 0),
    CHECK (parent_scope_id IS NULL),
    CHECK (delegation_digest IS NULL),
    CHECK (sequence BETWEEN 1 AND 9999999999999999),
    CHECK (length(tail_event_digest) = 64
        AND length(CAST(tail_event_digest AS BLOB)) = 64
        AND tail_event_digest NOT GLOB '*[^0-9a-f]*'),
    CHECK (active_plan_digest IS NULL OR (length(active_plan_digest) = 64
        AND length(CAST(active_plan_digest AS BLOB)) = 64
        AND active_plan_digest NOT GLOB '*[^0-9a-f]*')),
    CHECK (scope_epoch BETWEEN 1 AND 9999999999999999),
    CHECK (length(objective_digest) = 64
        AND length(CAST(objective_digest AS BLOB)) = 64
        AND objective_digest NOT GLOB '*[^0-9a-f]*'),
    -- The plan and its reservation are one fact: a half-written pair is unrepresentable.
    CHECK ((active_plan_digest IS NULL AND reserved_budget_units IS NULL)
        OR (active_plan_digest IS NOT NULL AND reserved_budget_units IS NOT NULL
            AND reserved_budget_units BETWEEN 0 AND 9999999999999999))
) STRICT, WITHOUT ROWID;

CREATE TABLE applied_scope_events (
    scope_id TEXT NOT NULL,
    sequence INTEGER NOT NULL,
    digest TEXT NOT NULL,
    parent_digest TEXT,
    operation_id TEXT NOT NULL,
    writer_epoch INTEGER NOT NULL,
    payload_type TEXT NOT NULL,
    PRIMARY KEY (scope_id, sequence),
    UNIQUE (scope_id, digest),
    UNIQUE (scope_id, operation_id),
    FOREIGN KEY (scope_id) REFERENCES scopes(scope_id) ON DELETE CASCADE,
    CHECK (sequence BETWEEN 1 AND 9999999999999999),
    CHECK (length(digest) = 64 AND length(CAST(digest AS BLOB)) = 64
        AND digest NOT GLOB '*[^0-9a-f]*'),
    CHECK ((sequence = 1 AND parent_digest IS NULL) OR (
        sequence > 1 AND parent_digest IS NOT NULL
        AND length(parent_digest) = 64
        AND length(CAST(parent_digest AS BLOB)) = 64
        AND parent_digest NOT GLOB '*[^0-9a-f]*')),
    CHECK (length(CAST(operation_id AS BLOB)) BETWEEN 1 AND 128
        AND instr(CAST(operation_id AS BLOB), CAST('/' AS BLOB)) = 0),
    CHECK (writer_epoch > 0),
    CHECK (length(CAST(payload_type AS BLOB)) BETWEEN 1 AND 128
        AND instr(CAST(payload_type AS BLOB), CAST('/' AS BLOB)) = 0),
    CHECK ((sequence = 1 AND payload_type = 'root_genesis'
            AND operation_id = 'root-genesis:' || scope_id)
        OR (sequence > 1 AND payload_type <> 'root_genesis'))
) STRICT, WITHOUT ROWID;

CREATE TABLE admitted_work (
    scope_id TEXT NOT NULL,
    work_id TEXT NOT NULL,
    work_revision INTEGER NOT NULL,
    admitted_scope_epoch INTEGER NOT NULL,
    max_attempts INTEGER NOT NULL,
    deadline_unix_ms INTEGER NOT NULL,
    claim_fence INTEGER,
    claim_lease_until INTEGER,
    grant_fence INTEGER,
    terminal_result_digest TEXT,
    PRIMARY KEY (scope_id, work_id, work_revision),
    FOREIGN KEY (scope_id) REFERENCES scopes(scope_id) ON DELETE CASCADE,
    CHECK (length(CAST(work_id AS BLOB)) BETWEEN 1 AND 128
        AND instr(CAST(work_id AS BLOB), CAST('/' AS BLOB)) = 0),
    CHECK (work_revision BETWEEN 0 AND 9999999999999999),
    CHECK (admitted_scope_epoch BETWEEN 1 AND 9999999999999999),
    CHECK (max_attempts BETWEEN 1 AND 9999999999999999),
    CHECK (deadline_unix_ms BETWEEN 1 AND 9999999999999999),
    -- A CHECK passes when its expression evaluates to NULL, so each branch names the columns
    -- it requires: without the explicit IS NOT NULL tests, a half-populated claim evaluates to
    -- NULL and is accepted.
    CHECK ((claim_fence IS NULL AND claim_lease_until IS NULL)
        OR (claim_fence IS NOT NULL AND claim_lease_until IS NOT NULL
            AND claim_fence BETWEEN 1 AND 9999999999999999
            AND claim_lease_until BETWEEN 1 AND 9999999999999999)),
    CHECK (grant_fence IS NULL OR grant_fence BETWEEN 1 AND 9999999999999999),
    -- `record_terminal` only writes a digest under a matching claim fence, so terminal evidence
    -- without a recorded claim is not a row this code can produce.
    CHECK (terminal_result_digest IS NULL OR (claim_fence IS NOT NULL
        AND length(terminal_result_digest) = 64
        AND length(CAST(terminal_result_digest AS BLOB)) = 64
        AND terminal_result_digest NOT GLOB '*[^0-9a-f]*'))
) STRICT, WITHOUT ROWID;

CREATE TABLE work_dependencies (
    scope_id TEXT NOT NULL,
    work_id TEXT NOT NULL,
    work_revision INTEGER NOT NULL,
    depends_on_work_id TEXT NOT NULL,
    PRIMARY KEY (scope_id, work_id, work_revision, depends_on_work_id),
    FOREIGN KEY (scope_id, work_id, work_revision)
        REFERENCES admitted_work(scope_id, work_id, work_revision) ON DELETE CASCADE,
    CHECK (length(CAST(depends_on_work_id AS BLOB)) BETWEEN 1 AND 128
        AND instr(CAST(depends_on_work_id AS BLOB), CAST('/' AS BLOB)) = 0),
    CHECK (depends_on_work_id <> work_id)
) STRICT, WITHOUT ROWID;
";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SchemaError {
    DatabaseOperationFailed,
    IntegrityCheckFailed,
}

impl fmt::Display for SchemaError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::DatabaseOperationFailed => "scope database operation failed",
            Self::IntegrityCheckFailed => "scope database integrity check failed",
        })
    }
}

impl Error for SchemaError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ValidateError {
    DatabaseOperationFailed,
    WrongApplicationId,
    IntegrityCheckFailed,
    InvalidSchema,
    InvalidHistory,
}

impl fmt::Display for ValidateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::DatabaseOperationFailed => "scope database operation failed",
            Self::WrongApplicationId => "scope database application id does not match",
            Self::IntegrityCheckFailed => "scope database integrity check failed",
            Self::InvalidSchema => "scope database schema is invalid",
            Self::InvalidHistory => "scope database history is invalid",
        })
    }
}

impl Error for ValidateError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ApplyOutcome {
    Applied,
    AlreadyApplied,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApplyError {
    Conflict,
    /// Emitted by [`crate::db::worker::DbHandle`] when its queue has no admission slot.
    Full,
    /// Emitted by [`crate::db::worker::DbHandle`] when its receiver is disconnected.
    Stopping,
    DatabaseOperationFailed,
}

impl fmt::Display for ApplyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Conflict => "scope event conflicts with local projection state",
            Self::Full => "scope database command queue is full",
            Self::Stopping => "scope database worker is stopping",
            Self::DatabaseOperationFailed => "scope database operation failed",
        })
    }
}

impl Error for ApplyError {}

impl From<rusqlite::Error> for ApplyError {
    fn from(_: rusqlite::Error) -> Self {
        Self::DatabaseOperationFailed
    }
}

/// Typed content one applied event writes, resolved before any SQLite call.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ScopeProjectionPayload {
    RootGenesis {
        objective_digest: Digest,
    },
    /// Carries the decoded proposal so a rebuilt projection recovers its work rows from bytes the
    /// event address already proves.
    PlanAdmitted {
        plan_digest: Digest,
        proposal: Box<PlanProposal>,
    },
    #[cfg(test)]
    TestSuccessor,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ScopeProjectionEvent {
    scope: ScopeIdentity,
    envelope: EventEnvelope,
    reference: ScopeEventRef,
    payload: ScopeProjectionPayload,
    scope_epoch: u64,
}

impl ScopeProjectionEvent {
    pub(crate) fn new(
        scope: ScopeIdentity,
        envelope: EventEnvelope,
        reference: ScopeEventRef,
        payload: ScopeProjectionPayload,
        scope_epoch: u64,
    ) -> Result<Self, ValidationError> {
        // Authority transitions advance the epoch without publishing an event, so an event's
        // writer epoch may lag the head epoch. An event above that epoch is not projectable.
        if envelope.scope_id() != scope.scope_id()
            || envelope.sequence() != reference.sequence()
            || envelope.writer_epoch().get() > scope_epoch
            || scope_epoch > MAX_STORED_INTEGER
        {
            return Err(ValidationError::InvalidIdentity);
        }
        // Genesis carries the objective; nothing else may occupy sequence 1.
        let genesis_payload = matches!(payload, ScopeProjectionPayload::RootGenesis { .. });
        if genesis_payload != (envelope.sequence() == 1) {
            return Err(ValidationError::InvalidIdentity);
        }
        Ok(Self {
            scope,
            envelope,
            reference,
            payload,
            scope_epoch,
        })
    }
}

pub(crate) fn create(path: impl AsRef<Path>) -> Result<rusqlite::Connection, SchemaError> {
    let connection = initialize(path.as_ref()).map_err(|_| SchemaError::DatabaseOperationFailed)?;
    let integrity: String = connection
        .query_row("PRAGMA quick_check", [], |row| row.get(0))
        .map_err(|_| SchemaError::DatabaseOperationFailed)?;
    if integrity != "ok" {
        return Err(SchemaError::IntegrityCheckFailed);
    }
    Ok(connection)
}

pub(crate) fn open_existing(path: impl AsRef<Path>) -> Result<rusqlite::Connection, ValidateError> {
    let connection = rusqlite::Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|_| ValidateError::DatabaseOperationFailed)?;
    connection
        .pragma_update(None, "foreign_keys", true)
        .map_err(|_| ValidateError::DatabaseOperationFailed)?;
    validate(&connection)?;
    // Run `set_rollback_journal` after `validate` so journal-mode failures do not mask
    // validation failures.
    set_rollback_journal(&connection).map_err(|_| ValidateError::DatabaseOperationFailed)?;
    Ok(connection)
}

pub(crate) fn scope_cursor(
    connection: &rusqlite::Connection,
    scope: &ScopeIdentity,
) -> Result<(u64, Option<Digest>), ApplyError> {
    let stored: Option<(String, i64, String)> = connection
        .query_row(SCOPE_SELECT_SQL, [scope.scope_id().as_str()], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })
        .optional()?;
    match stored {
        None => Ok((0, None)),
        Some((campaign_id, sequence, digest)) => {
            if campaign_id != scope.campaign_id().as_str() {
                // A root scope id derives from its campaign id, so this row belongs to no
                // reachable scope.
                connection.execute(
                    "DELETE FROM scopes WHERE scope_id = ?1",
                    [scope.scope_id().as_str()],
                )?;
                return Ok((0, None));
            }
            Ok((
                u64::try_from(sequence).map_err(|_| ApplyError::DatabaseOperationFailed)?,
                Some(Digest::new(digest).map_err(|_| ApplyError::Conflict)?),
            ))
        }
    }
}

pub(crate) fn scope_conflicting_operation(
    connection: &rusqlite::Connection,
    scope: &ScopeIdentity,
    operation_id: &str,
    reference: &ScopeEventRef,
) -> Result<bool, ApplyError> {
    let sequence =
        i64::try_from(reference.sequence()).map_err(|_| ApplyError::DatabaseOperationFailed)?;
    connection
        .query_row(
            OPERATION_CONFLICT_SQL,
            params![
                scope.scope_id().as_str(),
                operation_id,
                sequence,
                reference.digest().as_str()
            ],
            |row| row.get(0),
        )
        .map_err(Into::into)
}

pub(crate) fn scope_matches_head(
    connection: &rusqlite::Connection,
    head: &ScopeHead,
) -> Result<bool, ApplyError> {
    let stored: Option<(String, i64, String, Option<String>, i64, String)> = connection
        .query_row(
            SCOPE_HEAD_MATCH_SQL,
            [head.scope().scope_id().as_str()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .optional()?;
    Ok(
        stored.is_some_and(|(campaign, sequence, tail, plan, epoch, operation)| {
            campaign == head.scope().campaign_id().as_str()
                && u64::try_from(sequence).ok() == Some(head.tail().sequence())
                && tail == head.tail().digest().as_str()
                && plan.as_deref() == head.active_plan_digest().map(Digest::as_str)
                // The projected epoch may lag an eventless authority transition, but a head
                // below the projected epoch is stale evidence.
                && u64::try_from(epoch).is_ok_and(|epoch| epoch <= head.scope_epoch().get())
                && operation == head.operation_id()
        }),
    )
}

/// Re-admitting a revision is idempotent only when its canonical dependency set is unchanged.
/// Dependency edges name work ids, so a dependency may be admitted after the revision that
/// requires it. The scope's own projected row must already exist.
///
/// # Errors
///
/// Returns [`ApplyError::Conflict`] when a dependency names the revision's own work id or an
/// existing revision has a different dependency set. Returns
/// [`ApplyError::DatabaseOperationFailed`] when the scope has no projected row or SQLite fails.
#[cfg(test)]
pub(crate) fn admit_work(
    connection: &mut rusqlite::Connection,
    scope: &ScopeIdentity,
    work: &WorkRef,
    dependencies: &[WorkId],
    scope_epoch: NonZeroU64,
) -> Result<(), ApplyError> {
    let bounds = TargetBounds::new(1, MAX_STORED_INTEGER)
        .map_err(|_| ApplyError::DatabaseOperationFailed)?;
    let transaction = connection.transaction()?;
    insert_work_row(&transaction, scope, work, dependencies, scope_epoch, bounds)?;
    transaction.commit()?;
    Ok(())
}

/// Writes one admitted revision and its edges inside the caller's transaction.
fn insert_work_row(
    transaction: &rusqlite::Transaction<'_>,
    scope: &ScopeIdentity,
    work: &WorkRef,
    dependencies: &[WorkId],
    scope_epoch: NonZeroU64,
    bounds: TargetBounds,
) -> Result<(), ApplyError> {
    if dependencies
        .iter()
        .any(|dependency| dependency == work.id())
    {
        return Err(ApplyError::Conflict);
    }
    let mut dependencies = dependencies.iter().map(WorkId::as_str).collect::<Vec<_>>();
    dependencies.sort_unstable();
    dependencies.dedup();

    let revision = stored_u64(work.revision())?;
    let readmission = transaction.query_row(
        ADMITTED_REVISION_EXISTS_SQL,
        params![scope.scope_id().as_str(), work.id().as_str(), revision],
        |row| row.get::<_, bool>(0),
    )?;
    // The projected epoch only advances, so an admission below it was produced under superseded
    // authority.
    let projected_epoch: i64 = transaction.query_row(
        PROJECTED_SCOPE_EPOCH_SQL,
        [scope.scope_id().as_str()],
        |row| row.get(0),
    )?;
    if !u64::try_from(projected_epoch).is_ok_and(|epoch| epoch <= scope_epoch.get()) {
        return Err(ApplyError::Conflict);
    }
    // A superseded epoch cannot update the row, so it must not rewrite the edges readiness is
    // derived from either.
    if transaction.execute(
        ADMIT_WORK_SQL,
        params![
            scope.scope_id().as_str(),
            work.id().as_str(),
            revision,
            stored_u64(scope_epoch.get())?,
            stored_u64(bounds.max_attempts().get())?,
            stored_u64(bounds.deadline_unix_ms().get())?
        ],
    )? == 0
    {
        return Err(ApplyError::Conflict);
    }
    if readmission {
        let mut statement = transaction.prepare(WORK_DEPENDENCIES_SQL)?;
        let stored = statement
            .query_map(
                params![scope.scope_id().as_str(), work.id().as_str(), revision],
                |row| row.get::<_, String>(0),
            )?
            .collect::<Result<Vec<_>, _>>()?;
        if stored != dependencies {
            return Err(ApplyError::Conflict);
        }
    } else {
        for dependency in dependencies {
            transaction.execute(
                ADMIT_DEPENDENCY_SQL,
                params![
                    scope.scope_id().as_str(),
                    work.id().as_str(),
                    revision,
                    dependency
                ],
            )?;
        }
    }
    Ok(())
}

/// Validates and records one first plan admission inside the caller's transaction.
///
/// The snapshot the gate sees and the rows it writes commit together, which is what makes the
/// admission deterministic: same durable history, same verdict.
fn admit_plan(
    transaction: &rusqlite::Transaction<'_>,
    event: &ScopeProjectionEvent,
    plan_digest: &Digest,
    proposal: &PlanProposal,
) -> Result<(), ApplyError> {
    let scope_id = event.scope.scope_id().as_str();
    let objective: String = transaction.query_row(OBJECTIVE_SQL, [scope_id], |row| row.get(0))?;
    let objective = Digest::new(objective).map_err(|_| ApplyError::DatabaseOperationFailed)?;
    let tail_sequence = event.envelope.sequence() - 1;
    let mut observations = Vec::new();
    for basis in proposal.bases() {
        let crate::domain::proposal::ProposalBasis::Observation { event: cited } = basis else {
            continue;
        };
        let fact: Option<(String, String)> = transaction
            .query_row(
                OBSERVATION_FACT_SQL,
                params![scope_id, stored_u64(cited.sequence())?],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        // A citation with no projected row is refused here, not deferred to the gate, so the
        // gate's MissingBasis rule and this resolution cannot drift apart silently.
        let Some((digest, payload_type)) = fact else {
            return Err(ApplyError::Conflict);
        };
        let digest = Digest::new(digest).map_err(|_| ApplyError::DatabaseOperationFailed)?;
        let reference = ScopeEventRef::new(cited.sequence(), digest)
            .map_err(|_| ApplyError::DatabaseOperationFailed)?;
        observations.push(ObservationFact::new(
            event.scope.scope_id().clone(),
            reference,
            payload_type,
        ));
    }
    // The gate rules on the same snapshot the writes land on; any rejection is a conflict here.
    let admissible = validate_proposal(
        proposal,
        // First admission only: the gate sees no active plan, and ADMIT_PLAN_SQL's rowcount is
        // the durable refusal of a second plan. The supersession bead owns widening this.
        &ProposalFacts::new(&event.scope, &objective, None, tail_sequence, &observations),
    )
    .map_err(|_| ApplyError::Conflict)?;
    if admissible.plan_digest() != plan_digest {
        return Err(ApplyError::Conflict);
    }

    for spec in proposal.work_specs() {
        insert_work_row(
            transaction,
            &event.scope,
            &WorkRef::new(spec.work_id().clone(), INITIAL_WORK_REVISION),
            spec.dependencies(),
            NonZeroU64::new(event.scope_epoch).ok_or(ApplyError::DatabaseOperationFailed)?,
            spec.bounds(),
        )?;
    }
    let updated = transaction.execute(
        ADMIT_PLAN_SQL,
        params![
            scope_id,
            plan_digest.as_str(),
            stored_u64(proposal.reserved_budget_units())?,
        ],
    )?;
    if updated != 1 {
        return Err(ApplyError::Conflict);
    }
    Ok(())
}

/// `now_ms` is the clock a higher fence takes over an expired lease against, on the same base as
/// [`ready_work`].
///
/// # Errors
///
/// Returns [`ApplyError::Conflict`] when the revision is unknown, already carries terminal
/// evidence, would regress its fence, or holds a claim whose lease is still live at `now_ms`, and
/// [`ApplyError::DatabaseOperationFailed`] when SQLite fails or a value exceeds the
/// stored-integer bound.
pub(crate) fn record_claim(
    connection: &rusqlite::Connection,
    scope: &ScopeIdentity,
    work: &WorkRef,
    claim_fence: NonZeroU64,
    lease_until: NonZeroU64,
    now_ms: u64,
) -> Result<(), ApplyError> {
    let updated = connection.execute(
        RECORD_CLAIM_SQL,
        params![
            scope.scope_id().as_str(),
            work.id().as_str(),
            stored_u64(work.revision())?,
            stored_u64(claim_fence.get())?,
            stored_u64(lease_until.get())?,
            stored_u64(now_ms)?,
        ],
    )?;
    if updated == 1 {
        Ok(())
    } else {
        Err(ApplyError::Conflict)
    }
}

/// Records terminal evidence produced under the revision's current claim fence.
///
/// # Errors
///
/// Returns [`ApplyError::Conflict`] when the revision is unknown, has no claim, holds a different
/// claim fence, or already carries different terminal evidence. Returns
/// [`ApplyError::DatabaseOperationFailed`] when SQLite fails or a value exceeds the
/// stored-integer bound.
#[cfg(test)]
pub(crate) fn record_terminal(
    connection: &rusqlite::Connection,
    scope: &ScopeIdentity,
    work: &WorkRef,
    claim_fence: NonZeroU64,
    result: &Digest,
) -> Result<(), ApplyError> {
    let updated = connection.execute(
        RECORD_TERMINAL_SQL,
        params![
            scope.scope_id().as_str(),
            work.id().as_str(),
            stored_u64(work.revision())?,
            stored_u64(claim_fence.get())?,
            result.as_str(),
        ],
    )?;
    if updated == 1 {
        Ok(())
    } else {
        Err(ApplyError::Conflict)
    }
}

/// # Errors
///
/// Returns [`ApplyError::Conflict`] when the revision is unknown, already terminal, or holds a
/// claim at another fence, and [`ApplyError::DatabaseOperationFailed`] when SQLite fails.
pub(crate) fn record_grant(
    connection: &rusqlite::Connection,
    scope: &ScopeIdentity,
    work: &WorkRef,
    claim_fence: NonZeroU64,
) -> Result<(), ApplyError> {
    let updated = connection.execute(
        RECORD_GRANT_SQL,
        params![
            scope.scope_id().as_str(),
            work.id().as_str(),
            stored_u64(work.revision())?,
            stored_u64(claim_fence.get())?,
        ],
    )?;
    if updated == 1 {
        Ok(())
    } else {
        Err(ApplyError::Conflict)
    }
}

/// Lists the revisions a restart may resume at `scope_epoch` and `now_ms`.
///
/// # Errors
///
/// Returns [`ApplyError::DatabaseOperationFailed`] when SQLite fails or a stored row cannot be
/// converted back into a validated work reference.
pub(crate) fn resumable_work(
    connection: &rusqlite::Connection,
    scope: &ScopeIdentity,
    scope_epoch: NonZeroU64,
    now_ms: u64,
) -> Result<Vec<WorkRef>, ApplyError> {
    let mut statement = connection.prepare(RESUMABLE_WORK_SQL)?;
    let rows = statement
        .query_map(
            params![
                scope.scope_id().as_str(),
                stored_u64(scope_epoch.get())?,
                stored_u64(now_ms)?
            ],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
        )?
        .collect::<Result<Vec<_>, _>>()?;
    work_refs(rows)
}

/// Derives one scope's ready set from admitted work, dependencies, revision, claim state,
/// and terminal evidence as of `now_ms`.
///
/// The same rows and `now_ms` always produce the same ordered set, so a restart cannot
/// release a revision that is claimed or already terminal.
///
/// # Errors
///
/// Returns [`ApplyError::DatabaseOperationFailed`] when SQLite fails or a stored row cannot be
/// converted back into a validated work reference.
pub(crate) fn ready_work(
    connection: &rusqlite::Connection,
    scope: &ScopeIdentity,
    now_ms: u64,
) -> Result<Vec<WorkRef>, ApplyError> {
    let mut statement = connection.prepare(READY_WORK_SQL)?;
    let rows = statement
        .query_map(
            params![scope.scope_id().as_str(), stored_u64(now_ms)?],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
        )?
        .collect::<Result<Vec<_>, _>>()?;
    work_refs(rows)
}

fn work_refs(rows: Vec<(String, i64)>) -> Result<Vec<WorkRef>, ApplyError> {
    rows.into_iter()
        .map(|(work_id, revision)| {
            Ok(WorkRef::new(
                WorkId::new(work_id).map_err(|_| ApplyError::DatabaseOperationFailed)?,
                u64::try_from(revision).map_err(|_| ApplyError::DatabaseOperationFailed)?,
            ))
        })
        .collect()
}

fn stored_u64(value: u64) -> Result<i64, ApplyError> {
    i64::try_from(value).map_err(|_| ApplyError::DatabaseOperationFailed)
}

pub(crate) fn apply_scope_event(
    connection: &mut rusqlite::Connection,
    event: &ScopeProjectionEvent,
) -> Result<ApplyOutcome, ApplyError> {
    let transaction = connection.transaction()?;
    let scope_id = event.scope.scope_id().as_str();
    let sequence = event.envelope.sequence();
    let stored_sequence =
        i64::try_from(sequence).map_err(|_| ApplyError::DatabaseOperationFailed)?;
    let historical: Option<String> = transaction
        .query_row(
            EVENT_AT_SEQUENCE_SQL,
            params![scope_id, stored_sequence],
            |row| row.get(0),
        )
        .optional()?;
    let current: Option<(String, i64, String, Option<String>, i64)> = transaction
        .query_row(SCOPE_SELECT_SQL, [scope_id], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        })
        .optional()?;

    if let Some((_, cursor, tail, _, _)) = &current {
        let recorded_tail: Option<String> = transaction
            .query_row(EVENT_AT_SEQUENCE_SQL, params![scope_id, cursor], |row| {
                row.get(0)
            })
            .optional()?;
        if recorded_tail.as_deref() != Some(tail) {
            return Err(ApplyError::Conflict);
        }
    } else if historical.is_some() {
        return Err(ApplyError::Conflict);
    }
    if let Some(digest) = historical {
        if digest != event.reference.digest().as_str() {
            return Err(ApplyError::Conflict);
        }
        // A same-digest event with different admission content is unrepresentable: the event
        // digest covers the payload, and the event and its rows commit in one transaction.
        return Ok(ApplyOutcome::AlreadyApplied);
    }

    let parent_digest = event
        .envelope
        .parent_event()
        .map(|parent| parent.digest().as_str());
    match current {
        None => {
            let ScopeProjectionPayload::RootGenesis { objective_digest } = &event.payload else {
                return Err(ApplyError::Conflict);
            };
            // The payload/sequence biconditional in `ScopeProjectionEvent::new` proves this is
            // sequence 1, and the envelope proved genesis carries no parent.
            if parent_digest.is_some() {
                return Err(ApplyError::Conflict);
            }
            transaction.execute(
                "INSERT INTO scopes (scope_id, campaign_id, parent_scope_id, delegation_digest, \
                 sequence, tail_event_digest, active_plan_digest, scope_epoch, objective_digest, \
                 reserved_budget_units) \
                 VALUES (?1, ?2, NULL, NULL, ?3, ?4, NULL, ?5, ?6, NULL)",
                params![
                    scope_id,
                    event.scope.campaign_id().as_str(),
                    stored_sequence,
                    event.reference.digest().as_str(),
                    stored_u64(event.scope_epoch)?,
                    objective_digest.as_str(),
                ],
            )?;
        }
        Some((campaign_id, cursor, tail, _active_plan, scope_epoch)) => {
            // The projected epoch only advances: a mutation carrying an older epoch than the
            // projected row was produced under superseded authority.
            if campaign_id != event.scope.campaign_id().as_str()
                || cursor.checked_add(1) != Some(stored_sequence)
                || parent_digest != Some(tail.as_str())
                || !u64::try_from(scope_epoch).is_ok_and(|epoch| epoch <= event.scope_epoch)
            {
                return Err(ApplyError::Conflict);
            }
            // The applied tail's writer epoch bounds this event's, which keeps the chain
            // non-decreasing across replay batches, not only within one batch.
            let tail_writer_epoch: i64 =
                transaction.query_row(TAIL_WRITER_EPOCH_SQL, params![scope_id, cursor], |row| {
                    row.get(0)
                })?;
            if !u64::try_from(tail_writer_epoch)
                .is_ok_and(|epoch| epoch <= event.envelope.writer_epoch().get())
            {
                return Err(ApplyError::Conflict);
            }
            let updated = transaction.execute(
                SCOPE_UPDATE_SQL,
                params![
                    stored_sequence,
                    event.reference.digest().as_str(),
                    stored_u64(event.scope_epoch)?,
                    scope_id,
                ],
            )?;
            if updated != 1 {
                return Err(ApplyError::DatabaseOperationFailed);
            }
        }
    }

    if let ScopeProjectionPayload::PlanAdmitted {
        plan_digest,
        proposal,
    } = &event.payload
    {
        admit_plan(&transaction, event, plan_digest, proposal)?;
    }

    let duplicate: bool = transaction.query_row(
        DUPLICATE_EXISTS_SQL,
        params![
            scope_id,
            event.reference.digest().as_str(),
            event.envelope.operation_id()
        ],
        |row| row.get(0),
    )?;
    if duplicate {
        return Err(ApplyError::Conflict);
    }
    transaction.execute(
        "INSERT INTO applied_scope_events \
         (scope_id, sequence, digest, parent_digest, operation_id, writer_epoch, payload_type) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            scope_id,
            stored_sequence,
            event.reference.digest().as_str(),
            parent_digest,
            event.envelope.operation_id(),
            i64::try_from(event.envelope.writer_epoch().get())
                .map_err(|_| ApplyError::DatabaseOperationFailed)?,
            event.envelope.payload_type(),
        ],
    )?;
    transaction.commit()?;
    Ok(ApplyOutcome::Applied)
}

fn initialize(path: &Path) -> rusqlite::Result<rusqlite::Connection> {
    let mut connection = rusqlite::Connection::open(path)?;
    if connection.query_row("SELECT count(*) FROM sqlite_schema", [], |row| {
        row.get::<_, i64>(0)
    })? != 0
    {
        return Err(rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_CONSTRAINT),
            Some("database is not empty".into()),
        ));
    }
    set_rollback_journal(&connection)?;
    connection.pragma_update(None, "foreign_keys", true)?;
    let transaction = connection.transaction()?;
    let existing: i64 =
        transaction.query_row("SELECT count(*) FROM sqlite_schema", [], |row| row.get(0))?;
    if existing != 0 {
        return Err(rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_CONSTRAINT),
            Some("database is not empty".into()),
        ));
    }
    transaction.execute_batch(SCHEMA)?;
    transaction.pragma_update(None, "application_id", APPLICATION_ID)?;
    transaction.commit()?;
    Ok(connection)
}

fn validate(connection: &rusqlite::Connection) -> Result<(), ValidateError> {
    let application_id: i32 = connection
        .pragma_query_value(None, "application_id", |row| row.get(0))
        .map_err(local_format_error)?;
    if application_id != APPLICATION_ID && !is_blank(connection) {
        return Err(ValidateError::WrongApplicationId);
    }
    let integrity: String = connection
        .query_row("PRAGMA quick_check", [], |row| row.get(0))
        .map_err(local_format_error)?;
    if integrity != "ok" {
        return Err(ValidateError::IntegrityCheckFailed);
    }
    // `PRAGMA foreign_key_check` errors on a malformed foreign key, so the schema comparison
    // runs first and classifies such a file as `InvalidSchema`.
    validate_schema(connection)?;
    let foreign_key_failure = {
        let mut statement = connection
            .prepare("PRAGMA foreign_key_check")
            .map_err(|_| ValidateError::DatabaseOperationFailed)?;
        statement
            .query([])
            .map_err(|_| ValidateError::DatabaseOperationFailed)?
            .next()
            .map_err(|_| ValidateError::DatabaseOperationFailed)?
            .is_some()
    };
    if foreign_key_failure {
        return Err(ValidateError::InvalidHistory);
    }
    validate_history(connection)
}

fn local_format_error(error: rusqlite::Error) -> ValidateError {
    match error.sqlite_error_code() {
        Some(
            rusqlite::ErrorCode::SystemIoFailure
            | rusqlite::ErrorCode::DatabaseBusy
            | rusqlite::ErrorCode::DatabaseLocked
            | rusqlite::ErrorCode::CannotOpen
            | rusqlite::ErrorCode::PermissionDenied
            | rusqlite::ErrorCode::ReadOnly
            | rusqlite::ErrorCode::DiskFull
            | rusqlite::ErrorCode::OutOfMemory
            | rusqlite::ErrorCode::OperationInterrupted
            | rusqlite::ErrorCode::FileLockingProtocolFailed,
        ) => ValidateError::DatabaseOperationFailed,
        _ => ValidateError::IntegrityCheckFailed,
    }
}

/// `GLOB`, not `LIKE`: `_` is a single-character wildcard in `LIKE`, so a file whose only
/// user table is named `sqliteXfoo` reads as blank under `LIKE 'sqlite_%'`.
fn is_blank(connection: &rusqlite::Connection) -> bool {
    connection
        .query_row(
            "SELECT COUNT(*) = 0 FROM sqlite_schema WHERE name NOT GLOB 'sqlite_*'",
            [],
            |row| row.get(0),
        )
        .unwrap_or(false)
}

/// Invalid UTF-8 passes the byte-oriented CHECKs and then fails the read that converts the
/// column to a Rust `String`, so it is rejected here as invalid history.
fn validate_text(connection: &rusqlite::Connection) -> Result<(), ValidateError> {
    let mut statement = connection
        .prepare(
            "SELECT CAST(scope_id AS BLOB) FROM scopes \
             UNION ALL SELECT CAST(campaign_id AS BLOB) FROM scopes \
             UNION ALL SELECT CAST(tail_event_digest AS BLOB) FROM scopes \
             UNION ALL SELECT CAST(objective_digest AS BLOB) FROM scopes \
             UNION ALL SELECT CAST(active_plan_digest AS BLOB) FROM scopes \
               WHERE active_plan_digest IS NOT NULL \
             UNION ALL SELECT CAST(scope_id AS BLOB) FROM applied_scope_events \
             UNION ALL SELECT CAST(digest AS BLOB) FROM applied_scope_events \
             UNION ALL SELECT CAST(parent_digest AS BLOB) FROM applied_scope_events \
               WHERE parent_digest IS NOT NULL \
             UNION ALL SELECT CAST(operation_id AS BLOB) FROM applied_scope_events \
             UNION ALL SELECT CAST(payload_type AS BLOB) FROM applied_scope_events \
             UNION ALL SELECT CAST(work_id AS BLOB) FROM admitted_work \
             UNION ALL SELECT CAST(terminal_result_digest AS BLOB) FROM admitted_work \
               WHERE terminal_result_digest IS NOT NULL \
             UNION ALL SELECT CAST(work_id AS BLOB) FROM work_dependencies \
             UNION ALL SELECT CAST(depends_on_work_id AS BLOB) FROM work_dependencies",
        )
        .map_err(|_| ValidateError::DatabaseOperationFailed)?;
    let mut rows = statement
        .query([])
        .map_err(|_| ValidateError::DatabaseOperationFailed)?;
    while let Some(row) = rows
        .next()
        .map_err(|_| ValidateError::DatabaseOperationFailed)?
    {
        let bytes: Vec<u8> = row
            .get(0)
            .map_err(|_| ValidateError::DatabaseOperationFailed)?;
        if std::str::from_utf8(&bytes).is_err() {
            return Err(ValidateError::InvalidHistory);
        }
    }
    Ok(())
}

/// Journal mode persists in the file, so every open sets `journal_mode` to `DELETE`.
fn set_rollback_journal(connection: &rusqlite::Connection) -> rusqlite::Result<()> {
    let mode: String =
        connection.pragma_update_and_check(None, "journal_mode", "DELETE", |row| row.get(0))?;
    if !mode.eq_ignore_ascii_case("delete") {
        return Err(rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_CONSTRAINT),
            Some(format!("journal mode is {mode}, not delete")),
        ));
    }
    Ok(())
}

fn validate_schema(connection: &rusqlite::Connection) -> Result<(), ValidateError> {
    let mut definitions = connection
        .prepare("SELECT name, sql, type FROM sqlite_schema WHERE sql IS NOT NULL")
        .map_err(|_| ValidateError::DatabaseOperationFailed)?
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .map_err(|_| ValidateError::DatabaseOperationFailed)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ValidateError::DatabaseOperationFailed)?;
    definitions.retain(|(name, _, _)| !name.starts_with("sqlite_"));
    if definitions.len() != TABLES.len() || definitions.iter().any(|(_, _, kind)| kind != "table") {
        return Err(ValidateError::InvalidSchema);
    }
    for (name, sql, _) in definitions {
        let expected = expected_definition(&name).ok_or(ValidateError::InvalidSchema)?;
        if normalized(&sql) != normalized(expected) {
            return Err(ValidateError::InvalidSchema);
        }
    }
    Ok(())
}

fn validate_history(connection: &rusqlite::Connection) -> Result<(), ValidateError> {
    validate_text(connection)?;
    let orphans: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM applied_scope_events AS event \
             LEFT JOIN scopes AS scope ON scope.scope_id = event.scope_id \
             WHERE scope.scope_id IS NULL",
            [],
            |row| row.get(0),
        )
        .map_err(|_| ValidateError::DatabaseOperationFailed)?;
    let broken_parents: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM applied_scope_events AS event \
             LEFT JOIN applied_scope_events AS parent \
               ON parent.scope_id = event.scope_id AND parent.sequence = event.sequence - 1 \
             WHERE (event.sequence = 1 AND event.parent_digest IS NOT NULL) \
                OR (event.sequence > 1 AND (parent.digest IS NULL OR parent.digest != event.parent_digest)) \
                OR (event.sequence > 1 AND parent.writer_epoch > event.writer_epoch)",
            [],
            |row| row.get(0),
        )
        .map_err(|_| ValidateError::DatabaseOperationFailed)?;
    let broken_cursors: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM scopes AS scope WHERE \
             (SELECT COUNT(*) FROM applied_scope_events AS event WHERE event.scope_id = scope.scope_id) != scope.sequence \
             OR (SELECT MIN(sequence) FROM applied_scope_events AS event WHERE event.scope_id = scope.scope_id) != 1 \
             OR (SELECT MAX(sequence) FROM applied_scope_events AS event WHERE event.scope_id = scope.scope_id) != scope.sequence \
             OR (SELECT digest FROM applied_scope_events AS event \
                 WHERE event.scope_id = scope.scope_id AND event.sequence = scope.sequence) != scope.tail_event_digest \
             OR EXISTS(SELECT 1 FROM applied_scope_events AS event WHERE event.scope_id = scope.scope_id \
                 AND event.writer_epoch > scope.scope_epoch)",
            [],
            |row| row.get(0),
        )
        .map_err(|_| ValidateError::DatabaseOperationFailed)?;
    let unregistered = {
        let mut statement = connection
            .prepare("SELECT DISTINCT payload_type FROM applied_scope_events")
            .map_err(|_| ValidateError::DatabaseOperationFailed)?;
        let mut rows = statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|_| ValidateError::DatabaseOperationFailed)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| ValidateError::DatabaseOperationFailed)?;
        rows.retain(|payload_type| !payload_type_registered(payload_type));
        !rows.is_empty()
    };
    if orphans != 0 || broken_parents != 0 || broken_cursors != 0 || unregistered {
        return Err(ValidateError::InvalidHistory);
    }
    Ok(())
}

fn expected_definition(table: &str) -> Option<&'static str> {
    SCHEMA.split(';').map(str::trim).find(|statement| {
        statement
            .strip_prefix("CREATE TABLE ")
            .is_some_and(|rest| rest.starts_with(table) && rest[table.len()..].starts_with(" ("))
    })
}

fn normalized(sql: &str) -> String {
    sql.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf, process};

    use crate::{
        distributed::identity::WorkspaceId,
        scope::{CampaignId, EventEnvelope, ScopeEventRef, ScopeIdentity},
    };

    use super::*;

    const DIGEST_1: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const DIGEST_2: &str = "123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0";
    const DIGEST_3: &str = "23456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01";

    fn path(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "ravel-scope-projection-{}-{label}.sqlite3",
            process::id()
        ));
        let _ = fs::remove_file(&path);
        path
    }

    fn scope(workspace: &str, campaign: &str) -> ScopeIdentity {
        ScopeIdentity::root(
            WorkspaceId::new(workspace.into()).unwrap(),
            CampaignId::new(campaign.into()).unwrap(),
        )
        .unwrap()
    }

    fn mutation(
        scope: &ScopeIdentity,
        sequence: u64,
        digest: &str,
        parent: Option<&str>,
    ) -> ScopeProjectionEvent {
        mutation_with_operation(scope, sequence, digest, parent, &operation(scope, sequence))
    }

    fn operation(scope: &ScopeIdentity, sequence: u64) -> String {
        if sequence == 1 {
            format!("root-genesis:{}", scope.scope_id().as_str())
        } else {
            format!("operation-{sequence}")
        }
    }

    fn mutation_with_operation(
        scope: &ScopeIdentity,
        sequence: u64,
        digest: &str,
        parent: Option<&str>,
        operation_id: &str,
    ) -> ScopeProjectionEvent {
        let parent = parent.map(|digest| {
            ScopeEventRef::new(sequence - 1, Digest::new(digest.into()).unwrap()).unwrap()
        });
        let envelope = EventEnvelope::new(
            scope.scope_id().clone(),
            sequence,
            parent,
            1,
            operation_id.into(),
            if sequence == 1 {
                crate::scope::ROOT_GENESIS_PAYLOAD_TYPE
            } else {
                crate::scope::TEST_SUCCESSOR_PAYLOAD_TYPE
            }
            .into(),
        )
        .unwrap();
        ScopeProjectionEvent::new(
            scope.clone(),
            envelope,
            ScopeEventRef::new(sequence, Digest::new(digest.into()).unwrap()).unwrap(),
            if sequence == 1 {
                ScopeProjectionPayload::RootGenesis {
                    objective_digest: Digest::new("0".repeat(64)).unwrap(),
                }
            } else {
                ScopeProjectionPayload::TestSuccessor
            },
            1,
        )
        .unwrap()
    }

    #[derive(Debug, Eq, PartialEq)]
    struct Snapshot {
        scopes: Vec<(String, i64, String)>,
        events: Vec<(String, i64, String)>,
    }

    fn snapshot(connection: &rusqlite::Connection) -> Snapshot {
        let scopes = connection
            .prepare("SELECT scope_id, sequence, tail_event_digest FROM scopes ORDER BY scope_id")
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let events = connection
            .prepare("SELECT scope_id, sequence, digest FROM applied_scope_events ORDER BY scope_id, sequence")
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        Snapshot { scopes, events }
    }

    #[test]
    fn creates_the_projection_schema_and_rejects_an_unrelated_file() {
        let db_path = path("schema");
        let connection = create(&db_path).unwrap();
        assert_eq!(
            connection
                .pragma_query_value(None, "application_id", |row| row.get::<_, i32>(0))
                .unwrap(),
            APPLICATION_ID
        );
        assert_eq!(
            snapshot(&connection),
            Snapshot {
                scopes: vec![],
                events: vec![]
            }
        );
        drop(connection);
        drop(open_existing(&db_path).unwrap());
        fs::remove_file(db_path).unwrap();

        // An unrelated SQLite file carries a different application id.
        let unrelated = path("unrelated");
        let foreign = rusqlite::Connection::open(&unrelated).unwrap();
        foreign
            .pragma_update(None, "application_id", 0x1234)
            .unwrap();
        foreign
            .execute_batch("CREATE TABLE other (id INTEGER PRIMARY KEY) STRICT")
            .unwrap();
        drop(foreign);
        assert_eq!(
            open_existing(&unrelated).unwrap_err(),
            ValidateError::WrongApplicationId
        );
        fs::remove_file(unrelated).unwrap();

        // `sqliteXfoo` is a user table that matches `LIKE 'sqlite_%'`.
        let wildcard = path("wildcard-internal-name");
        let foreign = rusqlite::Connection::open(&wildcard).unwrap();
        foreign
            .pragma_update(None, "application_id", 0x1234)
            .unwrap();
        foreign
            .execute_batch("CREATE TABLE sqliteXfoo (id INTEGER PRIMARY KEY) STRICT")
            .unwrap();
        drop(foreign);
        assert_eq!(
            open_existing(&wildcard).unwrap_err(),
            ValidateError::WrongApplicationId
        );
        fs::remove_file(wildcard).unwrap();

        let blank = path("blank");
        let empty = rusqlite::Connection::open(&blank).unwrap();
        empty.pragma_update(None, "application_id", 0x1234).unwrap();
        drop(empty);
        assert_eq!(
            open_existing(&blank).unwrap_err(),
            ValidateError::InvalidSchema
        );
        fs::remove_file(blank).unwrap();

        let garbage = path("garbage");
        fs::write(&garbage, b"not-a-database".repeat(512)).unwrap();
        assert_eq!(
            open_existing(&garbage).unwrap_err(),
            ValidateError::IntegrityCheckFailed
        );
        fs::remove_file(garbage).unwrap();

        // A foreign application_id remains WrongApplicationId when bytes 100..4096 are corrupted.
        let unreadable = path("unreadable");
        drop(create(&unreadable).unwrap());
        let foreign = rusqlite::Connection::open(&unreadable).unwrap();
        foreign
            .pragma_update(None, "application_id", 0x1234)
            .unwrap();
        drop(foreign);
        let mut bytes = fs::read(&unreadable).unwrap();
        bytes[100..4096].fill(0xff);
        fs::write(&unreadable, &bytes).unwrap();
        assert_eq!(
            open_existing(&unreadable).unwrap_err(),
            ValidateError::WrongApplicationId
        );
        fs::remove_file(unreadable).unwrap();
    }

    #[test]
    fn a_root_row_requires_the_derived_operation_id() {
        let path = path("root-operation");
        let mut connection = create(&path).unwrap();
        let scope = scope("workspace-a", "campaign-a");
        assert_eq!(
            apply_scope_event(
                &mut connection,
                &mutation_with_operation(&scope, 1, DIGEST_1, None, "bogus-root-op")
            ),
            Err(ApplyError::DatabaseOperationFailed)
        );
        assert_eq!(scope_cursor(&connection, &scope).unwrap(), (0, None));
        drop(connection);
        fs::remove_file(path).unwrap();
    }

    fn query_plan(
        connection: &rusqlite::Connection,
        sql: &str,
        parameters: &[&dyn rusqlite::ToSql],
    ) -> Vec<String> {
        let mut statement = connection
            .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
            .unwrap();
        statement
            .query_map(
                rusqlite::params_from_iter(parameters.iter().copied()),
                |row| row.get(3),
            )
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    }

    #[test]
    fn apply_lookup_statements_avoid_table_scans() {
        let db_path = path("query-plans");
        let connection = create(&db_path).unwrap();
        let scope_id = DIGEST_1;
        let sequence = 1_i64;
        let digest = DIGEST_2;
        let operation = "operation-1";
        let work_id = "work-17";
        let revision = 3_i64;
        let plans = [
            query_plan(&connection, SCOPE_SELECT_SQL, &[&scope_id]),
            query_plan(&connection, SCOPE_HEAD_MATCH_SQL, &[&scope_id]),
            query_plan(&connection, EVENT_AT_SEQUENCE_SQL, &[&scope_id, &sequence]),
            query_plan(
                &connection,
                OPERATION_CONFLICT_SQL,
                &[&scope_id, &operation, &sequence, &digest],
            ),
            query_plan(
                &connection,
                DUPLICATE_EXISTS_SQL,
                &[&scope_id, &digest, &operation],
            ),
            query_plan(
                &connection,
                SCOPE_UPDATE_SQL,
                &[&sequence, &digest, &sequence, &scope_id],
            ),
            query_plan(
                &connection,
                WORK_DEPENDENCIES_SQL,
                &[&scope_id, &work_id, &revision],
            ),
            query_plan(
                &connection,
                RECORD_CLAIM_SQL,
                &[
                    &scope_id, &work_id, &revision, &sequence, &sequence, &sequence,
                ],
            ),
            query_plan(
                &connection,
                RECORD_TERMINAL_SQL,
                &[&scope_id, &work_id, &revision, &sequence, &digest],
            ),
            query_plan(&connection, READY_WORK_SQL, &[&scope_id, &sequence]),
            query_plan(
                &connection,
                RECORD_GRANT_SQL,
                &[&scope_id, &work_id, &revision, &sequence],
            ),
            query_plan(
                &connection,
                RESUMABLE_WORK_SQL,
                &[&scope_id, &sequence, &sequence],
            ),
        ];
        assert!(plans.iter().all(|details| !details.is_empty()));
        for detail in plans
            .iter()
            .flatten()
            .filter(|detail| detail.starts_with("SCAN"))
        {
            // A constant-row scan touches no projection table; it is the only accepted
            // SCAN plan from the bundled SQLite engine used by this test.
            assert_eq!(detail, "SCAN CONSTANT ROW");
        }

        drop(connection);
        fs::remove_file(db_path).unwrap();
    }

    #[test]
    fn a_projected_identity_rejects_a_slash_hidden_after_a_nul() {
        let path = path("nul-smuggled");
        let connection = create(&path).unwrap();
        // SQLite text matching stops at an embedded NUL, so the bound is byte-wise.
        assert!(
            connection
                .execute(
                    "INSERT INTO scopes (scope_id, campaign_id, parent_scope_id, \
                     delegation_digest, sequence, tail_event_digest, active_plan_digest, \
                     scope_epoch) \
                     VALUES (?1, 'campaign-a' || char(0) || '/other', NULL, NULL, 1, ?2, NULL, 1)",
                    params![DIGEST_1, DIGEST_2],
                )
                .is_err()
        );
        drop(connection);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn applies_idempotently_and_rejects_gaps_without_mutation() {
        let path = path("apply");
        let mut connection = create(&path).unwrap();
        let multibyte = scope("workspace-a", "campagne-café");
        let scope = scope("workspace-a", "campaign-a");
        let genesis = mutation(&scope, 1, DIGEST_1, None);
        assert_eq!(
            apply_scope_event(&mut connection, &genesis),
            Ok(ApplyOutcome::Applied)
        );
        let after_genesis = snapshot(&connection);
        assert_eq!(
            apply_scope_event(&mut connection, &genesis),
            Ok(ApplyOutcome::AlreadyApplied)
        );
        assert_eq!(snapshot(&connection), after_genesis);
        let gap = mutation(&scope, 3, DIGEST_3, Some(DIGEST_2));
        assert_eq!(
            apply_scope_event(&mut connection, &gap),
            Err(ApplyError::Conflict)
        );
        assert_eq!(snapshot(&connection), after_genesis);
        let successor = mutation(&scope, 2, DIGEST_2, Some(DIGEST_1));
        assert_eq!(
            apply_scope_event(&mut connection, &successor),
            Ok(ApplyOutcome::Applied)
        );
        assert_eq!(scope_cursor(&connection, &scope).unwrap().0, 2);
        assert!(
            scope_matches_head(
                &connection,
                &ScopeHead::new(
                    scope.clone(),
                    crate::scope::ScopeAuthority::Unowned,
                    1,
                    successor.reference.clone(),
                    None,
                    successor.envelope.operation_id().into(),
                )
                .unwrap()
            )
            .unwrap()
        );
        assert!(
            !scope_matches_head(
                &connection,
                &ScopeHead::new(
                    scope.clone(),
                    crate::scope::ScopeAuthority::Unowned,
                    1,
                    successor.reference.clone(),
                    None,
                    "other-operation".into(),
                )
                .unwrap()
            )
            .unwrap()
        );

        // A campaign id is bounded by bytes, so a multibyte identity projects.
        assert_eq!(
            apply_scope_event(&mut connection, &mutation(&multibyte, 1, DIGEST_3, None)),
            Ok(ApplyOutcome::Applied)
        );
        assert_eq!(scope_cursor(&connection, &multibyte).unwrap().0, 1);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn sqlite_failure_rolls_back_and_scopes_are_isolated() {
        let path = path("rollback");
        let mut connection = create(&path).unwrap();
        let first = scope("workspace-a", "campaign-a");
        let second = scope("workspace-b", "campaign-b");
        assert_eq!(
            apply_scope_event(&mut connection, &mutation(&first, 1, DIGEST_1, None)),
            Ok(ApplyOutcome::Applied)
        );
        assert_eq!(
            apply_scope_event(&mut connection, &mutation(&second, 1, DIGEST_2, None)),
            Ok(ApplyOutcome::Applied)
        );
        let before = snapshot(&connection);
        connection
            .execute_batch(
                "CREATE TRIGGER fail_scope_cursor BEFORE UPDATE ON scopes \
                 BEGIN SELECT RAISE(ABORT, 'injected'); END;",
            )
            .unwrap();
        assert_eq!(
            apply_scope_event(
                &mut connection,
                &mutation(&first, 2, DIGEST_3, Some(DIGEST_1))
            ),
            Err(ApplyError::DatabaseOperationFailed)
        );
        assert_eq!(snapshot(&connection), before);
        connection
            .execute_batch("DROP TRIGGER fail_scope_cursor")
            .unwrap();

        let after_update_conflict =
            mutation_with_operation(&first, 2, DIGEST_3, Some(DIGEST_1), &operation(&first, 1));
        assert_eq!(
            apply_scope_event(&mut connection, &after_update_conflict),
            Err(ApplyError::Conflict)
        );
        assert_eq!(snapshot(&connection), before);
        assert_eq!(scope_cursor(&connection, &second).unwrap().0, 1);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn validation_rejects_orphaned_history() {
        let path = path("orphan");
        drop(create(&path).unwrap());
        let connection = rusqlite::Connection::open(&path).unwrap();
        connection
            .pragma_update(None, "foreign_keys", false)
            .unwrap();
        connection
            .execute(
                "INSERT INTO applied_scope_events \
                 (scope_id, sequence, digest, parent_digest, operation_id, writer_epoch, payload_type) \
                 VALUES (?1, 1, ?2, NULL, 'root-genesis:' || ?1, 1, 'root_genesis')",
                params![DIGEST_1, DIGEST_2],
            )
            .unwrap();
        drop(connection);
        assert_eq!(
            open_existing(&path).unwrap_err(),
            ValidateError::InvalidHistory
        );
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn a_malformed_foreign_key_is_an_invalid_schema_not_an_operation_failure() {
        let path = path("foreign-key-mismatch");
        let foreign = rusqlite::Connection::open(&path).unwrap();
        foreign
            .pragma_update(None, "application_id", APPLICATION_ID)
            .unwrap();
        // `PRAGMA foreign_key_check` errors on this schema instead of reporting rows.
        foreign
            .execute_batch(
                "CREATE TABLE scopes (scope_id TEXT PRIMARY KEY NOT NULL) STRICT; \
                 CREATE TABLE applied_scope_events (scope_id TEXT NOT NULL, \
                   FOREIGN KEY (scope_id) REFERENCES scopes(absent_column)) STRICT;",
            )
            .unwrap();
        drop(foreign);
        assert_eq!(
            open_existing(&path).unwrap_err(),
            ValidateError::InvalidSchema
        );
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn a_cursor_row_for_another_campaign_is_dropped_rather_than_conflicting() {
        let path = path("campaign-mismatch");
        let mut connection = create(&path).unwrap();
        let scope = scope("workspace-a", "campaign-a");
        apply_scope_event(&mut connection, &mutation(&scope, 1, DIGEST_1, None)).unwrap();
        connection
            .execute("UPDATE scopes SET campaign_id = 'campaign-b'", [])
            .unwrap();

        assert_eq!(scope_cursor(&connection, &scope).unwrap(), (0, None));
        assert_eq!(
            snapshot(&connection),
            Snapshot {
                scopes: vec![],
                events: vec![]
            }
        );
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn validation_rejects_invalid_utf8_in_projected_text() {
        let path = path("invalid-utf8");
        let mut connection = create(&path).unwrap();
        let scope = scope("workspace-a", "campaign-a");
        apply_scope_event(&mut connection, &mutation(&scope, 1, DIGEST_1, None)).unwrap();
        drop(connection);
        drop(open_existing(&path).unwrap());

        // Byte length and the '/' test both pass for 0xff, and STRICT stores it as TEXT.
        let corrupted = rusqlite::Connection::open(&path).unwrap();
        corrupted
            .execute("UPDATE scopes SET campaign_id = CAST(x'ff' AS TEXT)", [])
            .unwrap();
        drop(corrupted);
        assert_eq!(
            open_existing(&path).unwrap_err(),
            ValidateError::InvalidHistory
        );
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn opening_an_existing_projection_restores_the_rollback_journal() {
        let path = path("journal-mode");
        drop(create(&path).unwrap());
        let switched = rusqlite::Connection::open(&path).unwrap();
        assert_eq!(
            switched
                .pragma_update_and_check(None, "journal_mode", "WAL", |row| row.get::<_, String>(0))
                .unwrap(),
            "wal"
        );
        drop(switched);

        let connection = open_existing(&path).unwrap();
        assert_eq!(
            connection
                .pragma_query_value(None, "journal_mode", |row| row.get::<_, String>(0))
                .unwrap(),
            "delete"
        );
        drop(connection);
        let mut sidecar = path.as_os_str().to_owned();
        sidecar.push("-wal");
        assert!(!PathBuf::from(sidecar).exists());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn validation_rejects_an_unregistered_projected_payload() {
        let path = path("unregistered-payload");
        let mut connection = create(&path).unwrap();
        let scope = scope("workspace-a", "campaign-a");
        apply_scope_event(&mut connection, &mutation(&scope, 1, DIGEST_1, None)).unwrap();
        apply_scope_event(
            &mut connection,
            &mutation(&scope, 2, DIGEST_2, Some(DIGEST_1)),
        )
        .unwrap();
        drop(connection);
        drop(open_existing(&path).unwrap());

        let mutated = rusqlite::Connection::open(&path).unwrap();
        mutated
            .execute(
                "UPDATE applied_scope_events SET payload_type = 'artifact' WHERE sequence = 2",
                [],
            )
            .unwrap();
        drop(mutated);
        assert_eq!(
            open_existing(&path).unwrap_err(),
            ValidateError::InvalidHistory
        );
        fs::remove_file(path).unwrap();
    }

    fn mutation_at_epoch(
        scope: &ScopeIdentity,
        sequence: u64,
        digest: &str,
        parent: Option<&str>,
        writer_epoch: u64,
        scope_epoch: u64,
    ) -> ScopeProjectionEvent {
        let parent = parent.map(|digest| {
            ScopeEventRef::new(sequence - 1, Digest::new(digest.into()).unwrap()).unwrap()
        });
        let envelope = EventEnvelope::new(
            scope.scope_id().clone(),
            sequence,
            parent,
            writer_epoch,
            operation(scope, sequence),
            crate::scope::TEST_SUCCESSOR_PAYLOAD_TYPE.into(),
        )
        .unwrap();
        ScopeProjectionEvent::new(
            scope.clone(),
            envelope,
            ScopeEventRef::new(sequence, Digest::new(digest.into()).unwrap()).unwrap(),
            ScopeProjectionPayload::TestSuccessor,
            scope_epoch,
        )
        .unwrap()
    }

    fn projected_epoch(connection: &rusqlite::Connection, scope: &ScopeIdentity) -> i64 {
        connection
            .query_row(
                "SELECT scope_epoch FROM scopes WHERE scope_id = ?1",
                [scope.scope_id().as_str()],
                |row| row.get(0),
            )
            .unwrap()
    }

    fn stored_claim(
        connection: &rusqlite::Connection,
        scope: &ScopeIdentity,
        work: &WorkRef,
    ) -> (Option<i64>, Option<i64>) {
        connection
            .query_row(
                "SELECT claim_fence, claim_lease_until FROM admitted_work \
                 WHERE scope_id = ?1 AND work_id = ?2 AND work_revision = ?3",
                params![
                    scope.scope_id().as_str(),
                    work.id().as_str(),
                    work.revision() as i64
                ],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap()
    }

    fn stored_terminal(
        connection: &rusqlite::Connection,
        scope: &ScopeIdentity,
        work: &WorkRef,
    ) -> Option<String> {
        connection
            .query_row(
                "SELECT terminal_result_digest FROM admitted_work \
                 WHERE scope_id = ?1 AND work_id = ?2 AND work_revision = ?3",
                params![
                    scope.scope_id().as_str(),
                    work.id().as_str(),
                    work.revision() as i64
                ],
                |row| row.get(0),
            )
            .unwrap()
    }

    fn epoch(value: u64) -> NonZeroU64 {
        NonZeroU64::new(value).unwrap()
    }

    fn work(id: &str, revision: u64) -> WorkRef {
        WorkRef::new(WorkId::new(id.into()).unwrap(), revision)
    }

    fn ready(connection: &rusqlite::Connection, scope: &ScopeIdentity, now_ms: u64) -> Vec<String> {
        ready_work(connection, scope, now_ms)
            .unwrap()
            .into_iter()
            .map(|work| format!("{}@{}", work.id().as_str(), work.revision()))
            .collect()
    }

    fn admitted_scope(label: &str) -> (PathBuf, rusqlite::Connection, ScopeIdentity) {
        let db_path = path(label);
        let mut connection = create(&db_path).unwrap();
        let scope = scope("workspace-a", "campaign-a");
        apply_scope_event(&mut connection, &mutation(&scope, 1, DIGEST_1, None)).unwrap();
        (db_path, connection, scope)
    }

    #[test]
    fn readiness_follows_dependencies_revisions_claims_and_terminal_evidence() {
        let (db_path, mut connection, scope) = admitted_scope("ready-work");
        let first = WorkId::new("work-a".into()).unwrap();

        admit_work(&mut connection, &scope, &work("work-a", 1), &[], epoch(1)).unwrap();
        admit_work(
            &mut connection,
            &scope,
            &work("work-b", 1),
            std::slice::from_ref(&first),
            epoch(1),
        )
        .unwrap();
        // An unsatisfied dependency withholds the dependent revision.
        assert_eq!(ready(&connection, &scope, 1_000), vec!["work-a@1"]);

        // Re-admission is idempotent.
        admit_work(&mut connection, &scope, &work("work-a", 1), &[], epoch(1)).unwrap();
        assert_eq!(ready(&connection, &scope, 1_000), vec!["work-a@1"]);

        let result = Digest::new(DIGEST_2.into()).unwrap();
        let fence = NonZeroU64::new(1).unwrap();
        let lease = NonZeroU64::new(31_000).unwrap();
        record_claim(&connection, &scope, &work("work-a", 1), fence, lease, 1_000).unwrap();
        record_terminal(&connection, &scope, &work("work-a", 1), fence, &result).unwrap();
        assert_eq!(ready(&connection, &scope, 1_000), vec!["work-b@1"]);

        record_claim(&connection, &scope, &work("work-b", 1), fence, lease, 1_000).unwrap();
        // A live claim withholds the revision; an expired one makes it reclaimable.
        assert!(ready(&connection, &scope, 1_000).is_empty());
        assert_eq!(ready(&connection, &scope, 31_000), vec!["work-b@1"]);

        // A higher admitted revision supersedes its predecessor and its claim.
        admit_work(
            &mut connection,
            &scope,
            &work("work-b", 2),
            &[first],
            epoch(1),
        )
        .unwrap();
        assert_eq!(ready(&connection, &scope, 1_000), vec!["work-b@2"]);

        // Terminal evidence from the current claim removes the revision from the ready set.
        record_claim(&connection, &scope, &work("work-b", 2), fence, lease, 1_000).unwrap();
        record_terminal(&connection, &scope, &work("work-b", 2), fence, &result).unwrap();
        assert!(ready(&connection, &scope, 1_000).is_empty());

        // Work that was never admitted is never ready.
        assert_eq!(
            record_claim(&connection, &scope, &work("work-c", 1), fence, lease, 1_000),
            Err(ApplyError::Conflict)
        );

        drop(connection);
        fs::remove_file(db_path).unwrap();
    }

    #[test]
    fn a_reopened_projection_rebuilds_the_same_ready_set() {
        let (db_path, mut connection, scope) = admitted_scope("ready-restart");
        let blocker = WorkId::new("work-a".into()).unwrap();
        admit_work(&mut connection, &scope, &work("work-a", 1), &[], epoch(1)).unwrap();
        admit_work(
            &mut connection,
            &scope,
            &work("work-b", 1),
            &[blocker],
            epoch(1),
        )
        .unwrap();
        admit_work(&mut connection, &scope, &work("work-c", 1), &[], epoch(1)).unwrap();
        record_claim(
            &connection,
            &scope,
            &work("work-c", 1),
            NonZeroU64::new(4).unwrap(),
            NonZeroU64::new(31_000).unwrap(),
            1_000,
        )
        .unwrap();
        let before = ready(&connection, &scope, 1_000);
        assert_eq!(before, vec!["work-a@1"]);
        drop(connection);

        let reopened = open_existing(&db_path).unwrap();
        assert_eq!(ready(&reopened, &scope, 1_000), before);
        // Past the recorded lease the claimed revision is reclaimable exactly once, and the
        // restart cannot hand it out under a regressed fence or a shortened lease.
        assert_eq!(
            ready(&reopened, &scope, 31_000),
            vec!["work-a@1", "work-c@1"]
        );
        assert_eq!(
            record_claim(
                &reopened,
                &scope,
                &work("work-c", 1),
                NonZeroU64::new(3).unwrap(),
                NonZeroU64::new(61_000).unwrap(),
                31_000
            ),
            Err(ApplyError::Conflict)
        );
        assert_eq!(
            stored_claim(&reopened, &scope, &work("work-c", 1)),
            (Some(4), Some(31_000))
        );

        drop(reopened);
        fs::remove_file(db_path).unwrap();
    }

    #[test]
    fn a_dependency_is_resolved_only_at_its_highest_admitted_revision() {
        let (db_path, mut connection, scope) = admitted_scope("dependency-supersession");
        let blocker = WorkId::new("work-a".into()).unwrap();
        let result = Digest::new(DIGEST_2.into()).unwrap();
        admit_work(&mut connection, &scope, &work("work-a", 1), &[], epoch(1)).unwrap();
        admit_work(
            &mut connection,
            &scope,
            &work("work-b", 1),
            std::slice::from_ref(&blocker),
            epoch(1),
        )
        .unwrap();
        let fence = NonZeroU64::new(1).unwrap();
        let lease = NonZeroU64::new(31_000).unwrap();
        record_claim(&connection, &scope, &work("work-a", 1), fence, lease, 1_000).unwrap();
        record_terminal(&connection, &scope, &work("work-a", 1), fence, &result).unwrap();
        assert_eq!(ready(&connection, &scope, 1_000), vec!["work-b@1"]);

        // A newer open revision of the dependency withdraws the terminal evidence.
        admit_work(&mut connection, &scope, &work("work-a", 2), &[], epoch(1)).unwrap();
        assert_eq!(ready(&connection, &scope, 1_000), vec!["work-a@2"]);

        record_claim(&connection, &scope, &work("work-a", 2), fence, lease, 1_000).unwrap();
        record_terminal(&connection, &scope, &work("work-a", 2), fence, &result).unwrap();
        assert_eq!(ready(&connection, &scope, 1_000), vec!["work-b@1"]);

        drop(connection);
        fs::remove_file(db_path).unwrap();
    }

    #[test]
    fn the_schema_rejects_a_half_recorded_claim_and_unclaimed_terminal_evidence() {
        let (db_path, mut connection, scope) = admitted_scope("claim-column-checks");
        let target = work("work-a", 1);
        admit_work(&mut connection, &scope, &target, &[], epoch(1)).unwrap();
        let tamper = |fence: Option<i64>, lease: Option<i64>, digest: Option<&str>| {
            connection.execute(
                "UPDATE admitted_work SET claim_fence = ?4, claim_lease_until = ?5, \
                 terminal_result_digest = ?6 \
                 WHERE scope_id = ?1 AND work_id = ?2 AND work_revision = ?3",
                params![
                    scope.scope_id().as_str(),
                    target.id().as_str(),
                    target.revision() as i64,
                    fence,
                    lease,
                    digest
                ],
            )
        };

        assert!(tamper(Some(1), None, None).is_err());
        assert!(tamper(None, Some(31_000), None).is_err());
        assert!(tamper(None, None, Some(DIGEST_2)).is_err());
        tamper(Some(1), Some(31_000), Some(DIGEST_2)).unwrap();

        drop(connection);
        fs::remove_file(db_path).unwrap();
    }

    #[test]
    fn claim_and_terminal_records_never_regress() {
        let (db_path, mut connection, scope) = admitted_scope("record-guards");
        let target = work("work-a", 1);
        admit_work(&mut connection, &scope, &target, &[], epoch(1)).unwrap();
        let high = NonZeroU64::new(4).unwrap();
        let low = NonZeroU64::new(3).unwrap();
        let lease = NonZeroU64::new(31_000).unwrap();
        let short_lease = NonZeroU64::new(2_000).unwrap();
        let first = Digest::new(DIGEST_2.into()).unwrap();
        let second = Digest::new(DIGEST_3.into()).unwrap();

        // Unclaimed work cannot be completed. A higher fence reclaims an expired low-fence claim.
        assert_eq!(
            record_terminal(&connection, &scope, &target, low, &first),
            Err(ApplyError::Conflict)
        );
        record_claim(&connection, &scope, &target, low, short_lease, 1_000).unwrap();
        assert_eq!(
            ready(&connection, &scope, short_lease.get()),
            vec!["work-a@1"]
        );
        // A higher fence waits for the recorded lease instead of displacing a live claimant.
        assert_eq!(
            record_claim(&connection, &scope, &target, high, lease, 1_999),
            Err(ApplyError::Conflict)
        );
        assert_eq!(
            stored_claim(&connection, &scope, &target),
            (Some(3), Some(2_000))
        );
        record_claim(&connection, &scope, &target, high, lease, 2_000).unwrap();

        // A lower fence, and an equal fence that would shorten the live lease, are refused.
        assert_eq!(
            record_claim(&connection, &scope, &target, low, lease, 31_000),
            Err(ApplyError::Conflict)
        );
        assert_eq!(
            record_claim(&connection, &scope, &target, high, short_lease, 31_000),
            Err(ApplyError::Conflict)
        );
        assert_eq!(
            stored_claim(&connection, &scope, &target),
            (Some(4), Some(31_000))
        );
        // An equal fence may extend its own lease.
        record_claim(
            &connection,
            &scope,
            &target,
            high,
            NonZeroU64::new(41_000).unwrap(),
            31_000,
        )
        .unwrap();
        assert_eq!(
            stored_claim(&connection, &scope, &target),
            (Some(4), Some(41_000))
        );

        // Evidence from the superseded low-fence claim cannot mark work terminal.
        assert_eq!(
            record_terminal(&connection, &scope, &target, low, &first),
            Err(ApplyError::Conflict)
        );
        assert_eq!(stored_terminal(&connection, &scope, &target), None);
        record_terminal(&connection, &scope, &target, high, &first).unwrap();
        // Repeating the same evidence is idempotent; different evidence conflicts.
        record_terminal(&connection, &scope, &target, high, &first).unwrap();
        assert_eq!(
            record_terminal(&connection, &scope, &target, high, &second),
            Err(ApplyError::Conflict)
        );
        assert_eq!(
            stored_terminal(&connection, &scope, &target).as_deref(),
            Some(DIGEST_2)
        );
        // A claim cannot be recorded against terminal work.
        assert_eq!(
            record_claim(
                &connection,
                &scope,
                &target,
                NonZeroU64::new(9).unwrap(),
                lease,
                41_000
            ),
            Err(ApplyError::Conflict)
        );

        drop(connection);
        fs::remove_file(db_path).unwrap();
    }

    #[test]
    fn re_admission_requires_the_same_dependency_set_and_rejects_a_self_edge() {
        let (db_path, mut connection, scope) = admitted_scope("dependency-immutability");
        let first = WorkId::new("work-a".into()).unwrap();
        let second = WorkId::new("work-c".into()).unwrap();
        admit_work(
            &mut connection,
            &scope,
            &work("work-b", 1),
            &[first.clone(), second.clone()],
            epoch(1),
        )
        .unwrap();
        assert!(ready(&connection, &scope, 1_000).is_empty());

        // Ordering and duplicates do not change canonical set identity.
        admit_work(
            &mut connection,
            &scope,
            &work("work-b", 1),
            &[second.clone(), first.clone(), second.clone()],
            epoch(1),
        )
        .unwrap();
        assert_eq!(
            admit_work(
                &mut connection,
                &scope,
                &work("work-b", 1),
                std::slice::from_ref(&first),
                epoch(1),
            ),
            Err(ApplyError::Conflict)
        );

        // Conflicting re-admission retains both original edges atomically.
        let fence = NonZeroU64::new(1).unwrap();
        let lease = NonZeroU64::new(31_000).unwrap();
        let result = Digest::new(DIGEST_2.into()).unwrap();
        admit_work(&mut connection, &scope, &work("work-a", 1), &[], epoch(1)).unwrap();
        record_claim(&connection, &scope, &work("work-a", 1), fence, lease, 1_000).unwrap();
        record_terminal(&connection, &scope, &work("work-a", 1), fence, &result).unwrap();
        assert!(ready(&connection, &scope, 1_000).is_empty());
        admit_work(&mut connection, &scope, &work("work-c", 1), &[], epoch(1)).unwrap();
        record_claim(&connection, &scope, &work("work-c", 1), fence, lease, 1_000).unwrap();
        record_terminal(&connection, &scope, &work("work-c", 1), fence, &result).unwrap();
        assert_eq!(ready(&connection, &scope, 1_000), vec!["work-b@1"]);

        // A newer admitting epoch does not license a changed dependency set.
        assert_eq!(
            admit_work(
                &mut connection,
                &scope,
                &work("work-b", 1),
                std::slice::from_ref(&first),
                epoch(9),
            ),
            Err(ApplyError::Conflict)
        );
        admit_work(
            &mut connection,
            &scope,
            &work("work-b", 1),
            &[first.clone(), second.clone()],
            epoch(9),
        )
        .unwrap();

        assert_eq!(
            admit_work(
                &mut connection,
                &scope,
                &work("work-b", 2),
                &[WorkId::new("work-b".into()).unwrap()],
                epoch(1),
            ),
            Err(ApplyError::Conflict)
        );
        assert_eq!(ready(&connection, &scope, 1_000), vec!["work-b@1"]);

        drop(connection);
        fs::remove_file(db_path).unwrap();
    }

    #[test]
    fn an_event_below_the_projected_epoch_or_tail_writer_epoch_is_refused() {
        let db_path = path("epoch-regression");
        let mut connection = create(&db_path).unwrap();
        let scope = scope("workspace-a", "campaign-a");
        apply_scope_event(&mut connection, &mutation(&scope, 1, DIGEST_1, None)).unwrap();
        apply_scope_event(
            &mut connection,
            &mutation_at_epoch(&scope, 2, DIGEST_2, Some(DIGEST_1), 5, 5),
        )
        .unwrap();
        assert_eq!(projected_epoch(&connection, &scope), 5);

        // A head epoch below the projected epoch is superseded authority.
        assert_eq!(
            apply_scope_event(
                &mut connection,
                &mutation_at_epoch(&scope, 3, DIGEST_3, Some(DIGEST_2), 4, 4)
            ),
            Err(ApplyError::Conflict)
        );
        // A writer epoch below the applied tail's writer epoch cannot extend the chain.
        assert_eq!(
            apply_scope_event(
                &mut connection,
                &mutation_at_epoch(&scope, 3, DIGEST_3, Some(DIGEST_2), 4, 6)
            ),
            Err(ApplyError::Conflict)
        );
        assert_eq!(scope_cursor(&connection, &scope).unwrap().0, 2);
        assert_eq!(projected_epoch(&connection, &scope), 5);

        // The same suffix at the projected epoch applies.
        apply_scope_event(
            &mut connection,
            &mutation_at_epoch(&scope, 3, DIGEST_3, Some(DIGEST_2), 5, 6),
        )
        .unwrap();
        assert_eq!(projected_epoch(&connection, &scope), 6);

        drop(connection);
        fs::remove_file(db_path).unwrap();
    }

    fn resumable(
        connection: &rusqlite::Connection,
        scope: &ScopeIdentity,
        scope_epoch: u64,
        now_ms: u64,
    ) -> Vec<String> {
        resumable_work(connection, scope, epoch(scope_epoch), now_ms)
            .unwrap()
            .into_iter()
            .map(|work| format!("{}@{}", work.id().as_str(), work.revision()))
            .collect()
    }

    #[test]
    fn a_restart_resumes_only_current_epoch_revision_claim_and_grant() {
        let (db_path, mut connection, scope) = admitted_scope("resumable-work");
        let target = work("work-a", 1);
        let fence = NonZeroU64::new(2).unwrap();
        let lease = NonZeroU64::new(31_000).unwrap();
        admit_work(&mut connection, &scope, &target, &[], epoch(3)).unwrap();

        // A claim without a grant cannot resume: no effect authority is current.
        record_claim(&connection, &scope, &target, fence, lease, 1_000).unwrap();
        assert!(resumable(&connection, &scope, 3, 1_000).is_empty());

        record_grant(&connection, &scope, &target, fence).unwrap();
        assert_eq!(resumable(&connection, &scope, 3, 1_000), vec!["work-a@1"]);

        // An expired claim lease is not current.
        assert!(resumable(&connection, &scope, 31_000, 31_000).is_empty());

        // A reclaim at a higher fence, once the recorded lease has expired, leaves the old grant
        // behind.
        let higher = NonZeroU64::new(3).unwrap();
        record_claim(&connection, &scope, &target, higher, lease, 31_000).unwrap();
        assert!(resumable(&connection, &scope, 3, 1_000).is_empty());
        record_grant(&connection, &scope, &target, higher).unwrap();
        assert_eq!(resumable(&connection, &scope, 3, 1_000), vec!["work-a@1"]);

        // Work admitted under a newer epoch than this controller holds is not resumable.
        let ahead = work("work-b", 1);
        admit_work(&mut connection, &scope, &ahead, &[], epoch(5)).unwrap();
        record_claim(&connection, &scope, &ahead, fence, lease, 1_000).unwrap();
        record_grant(&connection, &scope, &ahead, fence).unwrap();
        assert_eq!(resumable(&connection, &scope, 3, 1_000), vec!["work-a@1"]);
        assert_eq!(
            resumable(&connection, &scope, 5, 1_000),
            vec!["work-a@1", "work-b@1"]
        );

        // A superseding revision withdraws its predecessor, grant and all.
        admit_work(&mut connection, &scope, &work("work-a", 2), &[], epoch(3)).unwrap();
        assert_eq!(resumable(&connection, &scope, 5, 1_000), vec!["work-b@1"]);

        // Terminal evidence ends resumption.
        record_terminal(
            &connection,
            &scope,
            &ahead,
            fence,
            &Digest::new(DIGEST_2.into()).unwrap(),
        )
        .unwrap();
        assert!(resumable(&connection, &scope, 5, 1_000).is_empty());

        drop(connection);
        fs::remove_file(db_path).unwrap();
    }

    #[test]
    fn a_grant_binds_to_one_claim_fence() {
        let (db_path, mut connection, scope) = admitted_scope("grant-binding");
        let target = work("work-a", 1);
        let fence = NonZeroU64::new(2).unwrap();
        let lease = NonZeroU64::new(31_000).unwrap();

        // No claim yet, so there is no fence to bind to.
        admit_work(&mut connection, &scope, &target, &[], epoch(1)).unwrap();
        assert_eq!(
            record_grant(&connection, &scope, &target, fence),
            Err(ApplyError::Conflict)
        );

        record_claim(&connection, &scope, &target, fence, lease, 1_000).unwrap();
        assert_eq!(
            record_grant(&connection, &scope, &target, NonZeroU64::new(9).unwrap()),
            Err(ApplyError::Conflict)
        );
        record_grant(&connection, &scope, &target, fence).unwrap();

        // Terminal work takes no further grant.
        record_terminal(
            &connection,
            &scope,
            &target,
            fence,
            &Digest::new(DIGEST_2.into()).unwrap(),
        )
        .unwrap();
        assert_eq!(
            record_grant(&connection, &scope, &target, fence),
            Err(ApplyError::Conflict)
        );

        // Re-admission at a newer epoch keeps the row; a superseded epoch is refused outright.
        admit_work(&mut connection, &scope, &target, &[], epoch(4)).unwrap();
        assert_eq!(
            admit_work(&mut connection, &scope, &target, &[], epoch(2)),
            Err(ApplyError::Conflict)
        );

        drop(connection);
        fs::remove_file(db_path).unwrap();
    }

    #[test]
    fn work_offered_below_the_projected_scope_epoch_never_becomes_ready() {
        let (db_path, mut connection, scope) = admitted_scope("admission-epoch-floor");
        apply_scope_event(
            &mut connection,
            &mutation_at_epoch(&scope, 2, DIGEST_2, Some(DIGEST_1), 5, 5),
        )
        .unwrap();
        assert_eq!(projected_epoch(&connection, &scope), 5);

        // A first revision has no prior row to compare against, so the projected epoch is the
        // only floor that refuses it.
        assert_eq!(
            admit_work(&mut connection, &scope, &work("work-a", 1), &[], epoch(3)),
            Err(ApplyError::Conflict)
        );
        assert!(ready(&connection, &scope, 1_000).is_empty());

        admit_work(&mut connection, &scope, &work("work-a", 1), &[], epoch(5)).unwrap();
        assert_eq!(ready(&connection, &scope, 1_000), vec!["work-a@1"]);

        drop(connection);
        fs::remove_file(db_path).unwrap();
    }

    fn plan_bounds(deadline_unix_ms: u64) -> TargetBounds {
        TargetBounds::new(3, deadline_unix_ms).unwrap()
    }

    fn plan_proposal(
        scope: &ScopeIdentity,
        objective: &Digest,
        deadline_unix_ms: u64,
    ) -> PlanProposal {
        let spec = |id: &str, deps: &[&str]| {
            crate::domain::proposal::WorkSpec::new(
                WorkId::new(id.into()).unwrap(),
                deps.iter()
                    .map(|dep| WorkId::new((*dep).into()).unwrap())
                    .collect(),
                plan_bounds(deadline_unix_ms),
            )
        };
        PlanProposal::new(
            scope.scope_id().clone(),
            objective.clone(),
            None,
            vec![crate::domain::proposal::ProposalBasis::Observation {
                event: ScopeEventRef::new(1, Digest::new(DIGEST_1.into()).unwrap()).unwrap(),
            }],
            vec![spec("work-a", &[]), spec("work-b", &["work-a"])],
            7,
        )
    }

    fn admission_event(
        scope: &ScopeIdentity,
        proposal: &PlanProposal,
        operation: &str,
    ) -> (ScopeProjectionEvent, Digest) {
        let objective = proposal.objective_digest().clone();
        let facts = [ObservationFact::new(
            scope.scope_id().clone(),
            ScopeEventRef::new(1, Digest::new(DIGEST_1.into()).unwrap()).unwrap(),
            crate::scope::ROOT_GENESIS_PAYLOAD_TYPE.to_owned(),
        )];
        let admissible = validate_proposal(
            proposal,
            &ProposalFacts::new(scope, &objective, None, 1, &facts),
        )
        .unwrap();
        let plan_digest = admissible.plan_digest().clone();
        let envelope = EventEnvelope::new(
            scope.scope_id().clone(),
            2,
            Some(ScopeEventRef::new(1, Digest::new(DIGEST_1.into()).unwrap()).unwrap()),
            1,
            operation.into(),
            crate::scope::PLAN_ADMITTED_PAYLOAD_TYPE.into(),
        )
        .unwrap();
        let event = ScopeProjectionEvent::new(
            scope.clone(),
            envelope,
            ScopeEventRef::new(2, Digest::new(DIGEST_2.into()).unwrap()).unwrap(),
            ScopeProjectionPayload::PlanAdmitted {
                plan_digest: plan_digest.clone(),
                proposal: Box::new(proposal.clone()),
            },
            1,
        )
        .unwrap();
        (event, plan_digest)
    }

    /// The genesis helper `mutation()` seeds `objective_digest` with all zeros, so admission
    /// tests build their proposals against that objective.
    fn zero_objective() -> Digest {
        Digest::new("0".repeat(64)).unwrap()
    }

    #[test]
    fn plan_admission_records_everything_atomically_and_gates_readiness() {
        let (db_path, mut connection, scope) = admitted_scope("plan-admission");
        let objective = zero_objective();
        let proposal = plan_proposal(&scope, &objective, 10_000);
        let (event, plan_digest) = admission_event(&scope, &proposal, "admit-plan-1");

        assert_eq!(
            apply_scope_event(&mut connection, &event),
            Ok(ApplyOutcome::Applied)
        );
        let (active, reserved): (Option<String>, Option<i64>) = connection
            .query_row(
                "SELECT active_plan_digest, reserved_budget_units FROM scopes WHERE scope_id = ?1",
                [scope.scope_id().as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(active.as_deref(), Some(plan_digest.as_str()));
        assert_eq!(reserved, Some(7));
        let (rows, edges, bounded): (i64, i64, i64) = connection
            .query_row(
                "SELECT (SELECT COUNT(*) FROM admitted_work), \
                 (SELECT COUNT(*) FROM work_dependencies), \
                 (SELECT COUNT(*) FROM admitted_work WHERE max_attempts = 3 \
                    AND deadline_unix_ms = 10000)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!((rows, edges, bounded), (2, 1, 2));

        // Only the dependency-free revision is ready, and only until its deadline passes.
        assert_eq!(ready(&connection, &scope, 1), ["work-a@1"]);
        assert_eq!(ready(&connection, &scope, 10_000), Vec::<String>::new());

        // A claimed, granted revision resumes only until its deadline, though its lease is live.
        record_claim(
            &connection,
            &scope,
            &work("work-a", 1),
            epoch(1),
            epoch(20_000),
            1,
        )
        .unwrap();
        record_grant(&connection, &scope, &work("work-a", 1), epoch(1)).unwrap();
        assert_eq!(
            resumable_work(&connection, &scope, epoch(1), 1).unwrap(),
            [work("work-a", 1)]
        );
        assert_eq!(
            resumable_work(&connection, &scope, epoch(1), 10_000).unwrap(),
            []
        );

        // Repeating the identical admission reports success and changes nothing.
        assert_eq!(
            apply_scope_event(&mut connection, &event),
            Ok(ApplyOutcome::AlreadyApplied)
        );

        drop(connection);
        fs::remove_file(db_path).unwrap();
    }

    #[test]
    fn plan_admission_fails_closed_and_writes_nothing_on_rejection() {
        let (db_path, mut connection, scope) = admitted_scope("plan-admission-reject");
        // The proposal cites an objective the scope does not hold, so the gate refuses it.
        let foreign = plan_proposal(&scope, &Digest::new("9".repeat(64)).unwrap(), 10_000);
        let (event, _) = admission_event(&scope, &foreign, "admit-plan-bad");

        assert_eq!(
            apply_scope_event(&mut connection, &event),
            Err(ApplyError::Conflict)
        );
        let (rows, active, events): (i64, Option<String>, i64) = connection
            .query_row(
                "SELECT (SELECT COUNT(*) FROM admitted_work), \
                 (SELECT active_plan_digest FROM scopes), \
                 (SELECT COUNT(*) FROM applied_scope_events)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!((rows, active, events), (0, None, 1));

        drop(connection);
        fs::remove_file(db_path).unwrap();
    }

    #[test]
    fn a_second_plan_and_a_mismatched_address_are_refused() {
        let (db_path, mut connection, scope) = admitted_scope("plan-admission-second");
        let objective = zero_objective();
        let first = plan_proposal(&scope, &objective, 10_000);
        let (event, _) = admission_event(&scope, &first, "admit-plan-1");
        apply_scope_event(&mut connection, &event).unwrap();

        // A correctly addressed second plan passes every byte check and reaches the durable
        // refusal: the scope already holds an active plan, so the guarded UPDATE matches no row.
        // Its work rows are written before that refusal, so this also proves rollback.
        let mut second = plan_proposal(&scope, &objective, 20_000);
        second = PlanProposal::new(
            second.scope_id().clone(),
            objective.clone(),
            None,
            second.bases().to_vec(),
            [
                second.work_specs().to_vec(),
                vec![crate::domain::proposal::WorkSpec::new(
                    WorkId::new("work-z".into()).unwrap(),
                    Vec::new(),
                    plan_bounds(20_000),
                )],
            ]
            .concat(),
            second.reserved_budget_units(),
        );
        let second_facts = [ObservationFact::new(
            scope.scope_id().clone(),
            ScopeEventRef::new(1, Digest::new(DIGEST_1.into()).unwrap()).unwrap(),
            crate::scope::ROOT_GENESIS_PAYLOAD_TYPE.to_owned(),
        )];
        let second_digest = validate_proposal(
            &second,
            &ProposalFacts::new(&scope, &objective, None, 2, &second_facts),
        )
        .unwrap()
        .plan_digest()
        .clone();
        let envelope = EventEnvelope::new(
            scope.scope_id().clone(),
            3,
            Some(ScopeEventRef::new(2, Digest::new(DIGEST_2.into()).unwrap()).unwrap()),
            1,
            "admit-plan-2".into(),
            crate::scope::PLAN_ADMITTED_PAYLOAD_TYPE.into(),
        )
        .unwrap();
        let second_event = ScopeProjectionEvent::new(
            scope.clone(),
            envelope,
            ScopeEventRef::new(3, Digest::new(DIGEST_3.into()).unwrap()).unwrap(),
            ScopeProjectionPayload::PlanAdmitted {
                plan_digest: second_digest,
                proposal: Box::new(second),
            },
            1,
        )
        .unwrap();
        assert_eq!(
            apply_scope_event(&mut connection, &second_event),
            Err(ApplyError::Conflict)
        );
        // Rollback left no trace of the refused plan: its new work row is absent, the event
        // count is unchanged, and the active plan is still the first admission.
        let (work_z, events, active): (i64, i64, Option<String>) = connection
            .query_row(
                "SELECT (SELECT COUNT(*) FROM admitted_work WHERE work_id = 'work-z'), \
                 (SELECT COUNT(*) FROM applied_scope_events), \
                 (SELECT active_plan_digest FROM scopes)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(work_z, 0);
        assert_eq!(events, 2);
        assert!(active.is_some());

        // Same operation identity with different event bytes is a conflict, not a replay: the
        // historical row at sequence 2 holds another digest.
        let conflicting = ScopeProjectionEvent::new(
            scope.clone(),
            EventEnvelope::new(
                scope.scope_id().clone(),
                2,
                Some(ScopeEventRef::new(1, Digest::new(DIGEST_1.into()).unwrap()).unwrap()),
                1,
                "admit-plan-1".into(),
                crate::scope::PLAN_ADMITTED_PAYLOAD_TYPE.into(),
            )
            .unwrap(),
            ScopeEventRef::new(2, Digest::new(DIGEST_3.into()).unwrap()).unwrap(),
            ScopeProjectionPayload::PlanAdmitted {
                plan_digest: Digest::new("8".repeat(64)).unwrap(),
                proposal: Box::new(plan_proposal(&scope, &objective, 30_000)),
            },
            1,
        )
        .unwrap();
        assert_eq!(
            apply_scope_event(&mut connection, &conflicting),
            Err(ApplyError::Conflict)
        );

        drop(connection);
        fs::remove_file(db_path).unwrap();
    }
}
