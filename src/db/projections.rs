//! The projection file is disposable: one neutral application id rejects unrelated files,
//! and a file that fails validation is rebuilt from durable history rather than migrated.
//! It persists plan-stable histories at any controller epoch: a scope row's `scope_epoch`
//! advances monotonically and may lead its applied events, because authority transitions
//! advance the epoch without publishing an event.
//!
//! Scheduling authority is derived by query, never stored as a flag: `claimable_work` names the
//! revisions a worker may claim, `continuable_work` the ones an existing claim and grant may
//! continue.
//! `claimable_work` derives from admitted work, its admitting plan, dependencies, claim state,
//! and terminal evidence. `continuable_work` derives from the claim and grant bindings on the
//! active plan's rows. A reopened file keeps its work rows; a rebuilt file recovers
//! them by re-applying the admission event, whose payload names the plan object replay
//! re-fetches. Claim leases and scheduling clocks are Unix-epoch milliseconds on one shared
//! base.
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
        Digest, EventEnvelope, GrantActivatedPayload, ScopeClaimIdentity, ScopeEventRef, ScopeHead,
        ScopeIdentity, payload_type_registered,
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
/// `issue()`'s pre-append probe: an operation id already applied means this issuance committed
/// on an earlier attempt, so the retry must not append a duplicate event.
const OPERATION_RECORDED_SQL: &str = "SELECT EXISTS(SELECT 1 FROM applied_scope_events \
     WHERE scope_id = ?1 AND operation_id = ?2)";
const DUPLICATE_EXISTS_SQL: &str = "SELECT EXISTS(SELECT 1 FROM applied_scope_events \
     WHERE scope_id = ?1 AND (digest = ?2 OR operation_id = ?3))";
const SCOPE_UPDATE_SQL: &str = "UPDATE scopes SET sequence = ?1, tail_event_digest = ?2, \
     scope_epoch = ?3 WHERE scope_id = ?4";
const TAIL_WRITER_EPOCH_SQL: &str = "SELECT writer_epoch FROM applied_scope_events \
     WHERE scope_id = ?1 AND sequence = ?2";
/// The admitting plan is written once and only read back: re-admission requires `?4` to equal the
/// stored binding, so a revision cannot be re-bound to another plan and rowcount 0 is that
/// refusal. Inside `DO UPDATE ... WHERE`, a bare column names the existing row and only
/// `excluded.` names the incoming one.
///
/// The conflict target is explicit because the table carries two unique constraints and only the
/// primary key is an upsert here: a `(scope_id, work_id, plan_digest)` collision is a second
/// revision of one work id under one plan, which must fail rather than silently update.
const ADMIT_WORK_SQL: &str = "INSERT INTO admitted_work \
     (scope_id, work_id, work_revision, plan_digest, admitted_scope_epoch, max_attempts, \
      deadline_unix_ms, claim_fence, claim_lease_until, grant_fence, terminal_result_digest) \
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL, NULL, NULL, NULL) \
     ON CONFLICT (scope_id, work_id, work_revision) DO UPDATE SET admitted_scope_epoch = ?5 \
     WHERE admitted_scope_epoch <= ?5 AND plan_digest = ?4";
const ADMITTED_REVISION_EXISTS_SQL: &str = "SELECT EXISTS(SELECT 1 FROM admitted_work \
     WHERE scope_id = ?1 AND work_id = ?2 AND work_revision = ?3)";
/// Enumerates the rows a rebuild's claim reader must consult; replayed admissions are the only
/// source of work identity, so no object listing exists anywhere in the read path.
const ADMITTED_WORK_REFS_SQL: &str = "SELECT work_id, work_revision FROM admitted_work \
     WHERE scope_id = ?1 ORDER BY work_id, work_revision";
const PROJECTED_SCOPE_EPOCH_SQL: &str = "SELECT scope_epoch FROM scopes WHERE scope_id = ?1";
const CLAIMS_RESTORED_SQL: &str = "SELECT claims_restored FROM scopes WHERE scope_id = ?1";
const MARK_CLAIMS_RESTORED_SQL: &str = "UPDATE scopes SET claims_restored = 1 WHERE scope_id = ?1";
const OBJECTIVE_SQL: &str = "SELECT objective_digest FROM scopes WHERE scope_id = ?1";
const OBSERVATION_FACT_SQL: &str =
    "SELECT digest, payload_type FROM applied_scope_events WHERE scope_id = ?1 AND sequence = ?2";
/// Only admission sets the pair, and only from no plan: rowcount 0 is a second plan.
const ADMIT_PLAN_SQL: &str = "UPDATE scopes \
     SET active_plan_digest = ?2, reserved_budget_units = ?3 \
     WHERE scope_id = ?1 AND active_plan_digest IS NULL";
/// A grant is bound to the exact claim fence it was issued for, so a reclaimed work revision
/// cannot continue under a grant minted for the fence it superseded. Admissibility also requires
/// the issuing authority's plan to match the scope row, its epoch to be no older than the
/// projected one, a live claim lease at `?7`, and a grant deadline no later than the admitted
/// work deadline. The projected epoch may lag an eventless authority transition, hence `<=`.
///
/// `?6 > ?7` refuses a grant whose own deadline has already passed, so an expired object cannot
/// be activated and cannot charge units for authority nobody can use.
///
/// Attempts are consumed, not merely labelled: `granted_attempt` records the last attempt this
/// revision drew, a new fence must name a strictly higher one, and `?9 <= max_attempts` caps the
/// series. The identical object at the same fence repeats its attempt and draws nothing; a
/// different object at an already-granted fence is refused.
///
/// `granted_units` accumulates every grant this revision has drawn, so successive fences add up
/// instead of replacing one another, and the running total plus every sibling revision's must
/// stay within `reserved_budget_units`.
///
/// This SELECT is `issue()`'s dry-run: the same predicates the guarded grant UPDATE used to
/// enforce, evaluated before the activation event is appended. After the event commits, the
/// fold applies its facts unconditionally.
const GRANT_ADMISSIBLE_SQL: &str = "SELECT EXISTS(SELECT 1 FROM admitted_work \
     WHERE scope_id = ?1 AND work_id = ?2 AND work_revision = ?3 \
       AND terminal_result_digest IS NULL AND claim_fence = ?4 \
       AND claim_lease_until > ?7 \
       AND deadline_unix_ms >= ?6 \
       AND ?6 > ?7 \
       AND ?9 <= max_attempts \
       AND (grant_fence IS NULL \
            OR (grant_fence < ?4 AND ?9 > granted_attempt) \
            OR (grant_fence = ?4 AND grant_digest = ?11 AND ?9 = granted_attempt)) \
       AND (CASE WHEN grant_fence = ?4 AND grant_digest = ?11 \
              THEN COALESCE(granted_units, 0) \
              ELSE COALESCE(granted_units, 0) + ?10 END) \
           + (SELECT COALESCE(SUM(sibling.granted_units), 0) FROM admitted_work AS sibling \
                WHERE sibling.scope_id = ?1 \
                  AND NOT (sibling.work_id = ?2 AND sibling.work_revision = ?3)) \
           <= (SELECT reserved_budget_units FROM scopes WHERE scope_id = ?1) \
       AND EXISTS(SELECT 1 FROM scopes WHERE scope_id = ?1 \
             AND active_plan_digest = ?5 AND scope_epoch <= ?8))";
/// The fold applies one committed `grant_activated` event as fact: issuance-time guards ran
/// before the event was appended, so no arm here re-checks lease liveness, fences, attempts, or
/// budget. The applied-events cursor already refuses a replayed sequence, so the accumulation
/// cannot run twice for one event.
const FOLD_GRANT_SQL: &str = "UPDATE admitted_work \
     SET grant_fence = ?4, grant_digest = ?5, granted_attempt = ?6, \
         grant_deadline_unix_ms = ?7, \
         granted_units = COALESCE(granted_units, 0) + ?8 \
     WHERE scope_id = ?1 AND work_id = ?2 AND work_revision = ?3";
/// The re-record probe keeps the test-only `record_grant` faithful to the event path: an
/// identical object at an already-granted fence is the probe-skipped duplicate, which draws
/// nothing instead of folding again.
#[cfg(test)]
const GRANT_RERECORD_SQL: &str = "SELECT EXISTS(SELECT 1 FROM admitted_work \
     WHERE scope_id = ?1 AND work_id = ?2 AND work_revision = ?3 \
       AND grant_fence = ?4 AND grant_digest = ?5)";
/// A restart continues a revision only while every binding is still current: the admitting epoch
/// is not ahead of the controller's `?2`, the revision carries no terminal evidence, its deadline
/// is still ahead of `?3`, its claim lease is live at `?3`, a grant is bound to that exact claim
/// fence, the grant's recorded deadline is still ahead of `?3`, and the scope's
/// `active_plan_digest` is the plan that admitted it. `active_plan_digest IS NULL` matches no
/// row, so a scope holding no plan continues nothing.
///
/// No arm compares revisions: `UNIQUE (scope_id, work_id, plan_digest)` makes a second revision of
/// one work id under one plan unrepresentable, so at most one revision of a work id can match.
const CONTINUABLE_WORK_SQL: &str = "SELECT work_id, work_revision, claim_fence, grant_digest, \
     claim_lease_until \
     FROM admitted_work AS continuable \
     WHERE continuable.scope_id = ?1 \
       AND continuable.deadline_unix_ms > ?3 \
       AND continuable.terminal_result_digest IS NULL \
       AND continuable.admitted_scope_epoch <= ?2 \
       AND continuable.claim_lease_until > ?3 \
       AND continuable.grant_fence = continuable.claim_fence \
       AND continuable.grant_deadline_unix_ms > ?3 \
       AND continuable.plan_digest = (SELECT active_plan_digest FROM scopes \
             WHERE scope_id = ?1) \
     ORDER BY work_id";
const WORK_DEPENDENCIES_SQL: &str = "SELECT depends_on_work_id, depends_on_work_revision \
     FROM work_dependencies \
     WHERE scope_id = ?1 AND work_id = ?2 AND work_revision = ?3 \
     ORDER BY depends_on_work_id";
const ADMIT_DEPENDENCY_SQL: &str = "INSERT INTO work_dependencies \
     (scope_id, work_id, work_revision, depends_on_work_id, depends_on_work_revision) \
     VALUES (?1, ?2, ?3, ?4, ?5)";
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

/// A revision is claimable while its deadline is still ahead of `?2`, it carries no terminal
/// evidence, it holds no claim whose lease is still live at `?2`, the scope's `active_plan_digest`
/// is the plan that admitted it, and every dependency it declares carries terminal evidence on the
/// exact revision the edge bound at admission. The bound revision is a primary-key probe, so
/// terminal evidence on any other revision of that work id — or on a row a dangling edge names
/// that was never admitted — satisfies nothing.
///
/// No arm compares sibling revisions of the claimable row: `UNIQUE (scope_id, work_id,
/// plan_digest)` makes a second revision of one work id under one plan unrepresentable, and a
/// revision any other plan admitted fails the active-plan arm.
///
/// Expiry gates scheduling only: `RECORD_CLAIM_SQL` and `RECORD_TERMINAL_SQL` name no deadline, so
/// work claimed before its deadline can still be closed after it.
const CLAIMABLE_WORK_SQL: &str = "SELECT work_id, work_revision FROM admitted_work AS claimable \
     WHERE claimable.scope_id = ?1 \
       AND claimable.deadline_unix_ms > ?2 \
       AND claimable.terminal_result_digest IS NULL \
       AND (claimable.claim_lease_until IS NULL OR claimable.claim_lease_until <= ?2) \
       AND claimable.plan_digest = (SELECT active_plan_digest FROM scopes WHERE scope_id = ?1) \
       AND NOT EXISTS (SELECT 1 FROM work_dependencies AS dependency \
             WHERE dependency.scope_id = claimable.scope_id \
               AND dependency.work_id = claimable.work_id \
               AND dependency.work_revision = claimable.work_revision \
               AND NOT EXISTS (SELECT 1 FROM admitted_work AS resolved \
                     WHERE resolved.scope_id = dependency.scope_id \
                       AND resolved.work_id = dependency.depends_on_work_id \
                       AND resolved.work_revision = dependency.depends_on_work_revision \
                       AND resolved.terminal_result_digest IS NOT NULL)) \
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
    -- Claim columns live only in worker-published objects, so a rebuilt projection must read
    -- them back. The flag stays 0 until one refresh completes that restore, and a crash or
    -- storage failure mid-restore leaves it 0 so the next refresh retries the reader.
    claims_restored INTEGER NOT NULL,
    CHECK (claims_restored IN (0, 1)),
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
    plan_digest TEXT NOT NULL,
    admitted_scope_epoch INTEGER NOT NULL,
    max_attempts INTEGER NOT NULL,
    deadline_unix_ms INTEGER NOT NULL,
    claim_fence INTEGER,
    claim_lease_until INTEGER,
    grant_fence INTEGER,
    grant_digest TEXT,
    granted_attempt INTEGER,
    granted_units INTEGER,
    grant_deadline_unix_ms INTEGER,
    terminal_result_digest TEXT,
    PRIMARY KEY (scope_id, work_id, work_revision),
    -- Scheduling asks which revision of a work id the active plan admitted, and this constraint
    -- is what makes that a lookup instead of a comparison: one plan admits one revision per work
    -- id, so two revisions of a work id can never be schedulable together.
    UNIQUE (scope_id, work_id, plan_digest),
    FOREIGN KEY (scope_id) REFERENCES scopes(scope_id) ON DELETE CASCADE,
    CHECK (length(CAST(work_id AS BLOB)) BETWEEN 1 AND 128
        AND instr(CAST(work_id AS BLOB), CAST('/' AS BLOB)) = 0),
    CHECK (work_revision BETWEEN 0 AND 9999999999999999),
    CHECK (length(plan_digest) = 64
        AND length(CAST(plan_digest AS BLOB)) = 64
        AND plan_digest NOT GLOB '*[^0-9a-f]*'),
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
    -- `granted_units` is the running total this revision has drawn from the plan reservation,
    -- `granted_attempt` is the last attempt it drew, `grant_digest` names the object the latest
    -- fence activated, and `grant_deadline_unix_ms` is that object's own deadline, so the five
    -- grant columns are present or absent together.
    CHECK ((grant_fence IS NULL AND grant_digest IS NULL AND granted_units IS NULL
            AND granted_attempt IS NULL AND grant_deadline_unix_ms IS NULL)
        OR (grant_fence IS NOT NULL AND grant_digest IS NOT NULL AND granted_units IS NOT NULL
            AND granted_attempt IS NOT NULL AND grant_deadline_unix_ms IS NOT NULL
            AND grant_fence BETWEEN 1 AND 9999999999999999
            AND granted_attempt BETWEEN 1 AND 9999999999999999
            AND granted_units BETWEEN 1 AND 9999999999999999
            AND grant_deadline_unix_ms BETWEEN 1 AND 9999999999999999
            AND length(grant_digest) = 64
            AND length(CAST(grant_digest AS BLOB)) = 64
            AND grant_digest NOT GLOB '*[^0-9a-f]*')),
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
    depends_on_work_revision INTEGER NOT NULL,
    PRIMARY KEY (scope_id, work_id, work_revision, depends_on_work_id),
    FOREIGN KEY (scope_id, work_id, work_revision)
        REFERENCES admitted_work(scope_id, work_id, work_revision) ON DELETE CASCADE,
    CHECK (length(CAST(depends_on_work_id AS BLOB)) BETWEEN 1 AND 128
        AND instr(CAST(depends_on_work_id AS BLOB), CAST('/' AS BLOB)) = 0),
    CHECK (depends_on_work_revision BETWEEN 0 AND 9999999999999999),
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
    /// The supplied controller authority is stopped or the projection already advanced past its
    /// epoch; either way it authorizes nothing, and the caller reacquires instead of retrying.
    StaleAuthority,
    DatabaseOperationFailed,
}

impl fmt::Display for ApplyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Conflict => "scope event conflicts with local projection state",
            Self::Full => "scope database command queue is full",
            Self::Stopping => "scope database worker is stopping",
            Self::StaleAuthority => "controller authority is stopped or superseded",
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
    /// Carries every grant fact the fold writes, so the projection needs no grant-object read.
    GrantActivated {
        payload: GrantActivatedPayload,
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

/// Re-admitting a revision is idempotent only when its canonical dependency set — the sorted,
/// deduplicated `(work id, revision)` pairs — is unchanged. Dependency edges name work ids that
/// may be admitted after the revision that requires them. The scope's own projected row must
/// already exist.
///
/// # Errors
///
/// Returns [`ApplyError::Conflict`] when a dependency names the revision's own work id, two
/// dependencies bind one work id to different revisions, an existing revision has a different
/// dependency set or another admitting plan, or `plan_digest` already admitted a different
/// revision of this work id. Returns [`ApplyError::DatabaseOperationFailed`] when the scope has
/// no projected row or SQLite fails.
#[cfg(test)]
pub(crate) fn admit_work(
    connection: &mut rusqlite::Connection,
    scope: &ScopeIdentity,
    work: &WorkRef,
    dependencies: &[WorkRef],
    plan_digest: &Digest,
    scope_epoch: NonZeroU64,
) -> Result<(), ApplyError> {
    let bounds = TargetBounds::new(3, MAX_STORED_INTEGER)
        .map_err(|_| ApplyError::DatabaseOperationFailed)?;
    let transaction = connection.transaction()?;
    insert_work_row(
        &transaction,
        scope,
        work,
        dependencies,
        plan_digest,
        scope_epoch,
        bounds,
    )?;
    transaction.commit()?;
    Ok(())
}

/// The only violation `ADMIT_WORK_SQL` can reach is `UNIQUE (scope_id, work_id, plan_digest)`:
/// `Digest`, `WorkId`, `TargetBounds`, and `stored_u64` pre-validate every CHECK on the inserted
/// columns, and a missing scope row fails `PROJECTED_SCOPE_EPOCH_SQL` first. A second revision of
/// one work id under one plan is a projection conflict, not a failure of the database, and the
/// blanket `From<rusqlite::Error>` would report `DatabaseOperationFailed` and hide it.
fn constraint_conflict(error: rusqlite::Error) -> ApplyError {
    if error.sqlite_error_code() == Some(rusqlite::ErrorCode::ConstraintViolation) {
        ApplyError::Conflict
    } else {
        ApplyError::DatabaseOperationFailed
    }
}

/// Writes one admitted revision and its edges inside the caller's transaction. Each edge stores
/// the exact revision it binds, so dependency resolution never re-derives it at query time.
fn insert_work_row(
    transaction: &rusqlite::Transaction<'_>,
    scope: &ScopeIdentity,
    work: &WorkRef,
    dependencies: &[WorkRef],
    plan_digest: &Digest,
    scope_epoch: NonZeroU64,
    bounds: TargetBounds,
) -> Result<(), ApplyError> {
    if dependencies
        .iter()
        .any(|dependency| dependency.id() == work.id())
    {
        return Err(ApplyError::Conflict);
    }
    let mut dependencies = dependencies
        .iter()
        .map(|dependency| Ok((dependency.id().as_str(), stored_u64(dependency.revision())?)))
        .collect::<Result<Vec<_>, ApplyError>>()?;
    dependencies.sort_unstable();
    dependencies.dedup();
    // Two edges binding one work id to different revisions would be two answers to one question,
    // and letting the PK refuse them would surface as `DatabaseOperationFailed`.
    if dependencies.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(ApplyError::Conflict);
    }

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
    // A superseded epoch cannot update the row, so it must not rewrite edges that scheduling uses.
    if transaction
        .execute(
            ADMIT_WORK_SQL,
            params![
                scope.scope_id().as_str(),
                work.id().as_str(),
                revision,
                plan_digest.as_str(),
                stored_u64(scope_epoch.get())?,
                stored_u64(bounds.max_attempts().get())?,
                stored_u64(bounds.deadline_unix_ms().get())?
            ],
        )
        .map_err(constraint_conflict)?
        == 0
    {
        return Err(ApplyError::Conflict);
    }
    if readmission {
        let mut statement = transaction.prepare(WORK_DEPENDENCIES_SQL)?;
        let stored = statement
            .query_map(
                params![scope.scope_id().as_str(), work.id().as_str(), revision],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
            )?
            .collect::<Result<Vec<_>, _>>()?;
        if !stored
            .iter()
            .map(|(id, revision)| (id.as_str(), *revision))
            .eq(dependencies.iter().copied())
        {
            return Err(ApplyError::Conflict);
        }
    } else {
        for (dependency_id, dependency_revision) in dependencies {
            transaction.execute(
                ADMIT_DEPENDENCY_SQL,
                params![
                    scope.scope_id().as_str(),
                    work.id().as_str(),
                    revision,
                    dependency_id,
                    dependency_revision
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
        // Every spec in the proposal is admitted at `INITIAL_WORK_REVISION` and the proposal
        // gate refuses a dependency naming a work id outside it, so the revision this plan
        // admits for each dependency is known here, at edge-writing time.
        let dependencies = spec
            .dependencies()
            .iter()
            .map(|dependency| WorkRef::new(dependency.clone(), INITIAL_WORK_REVISION))
            .collect::<Vec<_>>();
        insert_work_row(
            transaction,
            &event.scope,
            &WorkRef::new(spec.work_id().clone(), INITIAL_WORK_REVISION),
            &dependencies,
            plan_digest,
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
/// [`claimable_work`].
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

/// `GrantActivation` records grant bounds and object identity beyond its claim identity.
pub(crate) struct GrantActivation {
    pub(crate) scope_epoch: NonZeroU64,
    pub(crate) attempt: NonZeroU64,
    pub(crate) units: NonZeroU64,
    pub(crate) deadline_unix_ms: NonZeroU64,
    pub(crate) digest: Digest,
}

/// Evaluates the issuance guards without writing anything: the projection changes only when the
/// committed activation event folds.
///
/// # Errors
///
/// Returns [`ApplyError::Conflict`] when the revision is unknown, terminal, claimed at another
/// fence or with an expired lease, when the grant deadline has passed or exceeds the admitted
/// deadline, when the attempt is above the admitted `max_attempts` or does not exceed the last
/// attempt this revision drew, when the units would take the scope past its reserved budget, when
/// another object already holds this fence, or when the scope's active plan is not the identity's
/// or the projected epoch is ahead of `scope_epoch`; and
/// [`ApplyError::DatabaseOperationFailed`] when SQLite fails.
pub(crate) fn grant_admissible(
    connection: &rusqlite::Connection,
    identity: &ScopeClaimIdentity,
    activation: &GrantActivation,
    now_ms: u64,
) -> Result<(), ApplyError> {
    let admissible: bool = connection.query_row(
        GRANT_ADMISSIBLE_SQL,
        params![
            identity.scope().scope_id().as_str(),
            identity.work().id().as_str(),
            stored_u64(identity.work().revision())?,
            stored_u64(identity.claim_fence().get())?,
            identity.plan_digest().as_str(),
            stored_u64(activation.deadline_unix_ms.get())?,
            stored_u64(now_ms)?,
            stored_u64(activation.scope_epoch.get())?,
            stored_u64(activation.attempt.get())?,
            stored_u64(activation.units.get())?,
            activation.digest.as_str(),
        ],
        |row| row.get(0),
    )?;
    if admissible {
        Ok(())
    } else {
        Err(ApplyError::Conflict)
    }
}

/// Test-only guarded recording; production activation goes dry-run, event append, then fold.
///
/// # Errors
///
/// Returns exactly [`grant_admissible`]'s errors; a passing re-record of the identical object at
/// the same fence draws nothing.
#[cfg(test)]
pub(crate) fn record_grant(
    connection: &rusqlite::Connection,
    identity: &ScopeClaimIdentity,
    activation: &GrantActivation,
    now_ms: u64,
) -> Result<(), ApplyError> {
    grant_admissible(connection, identity, activation, now_ms)?;
    let rerecord: bool = connection.query_row(
        GRANT_RERECORD_SQL,
        params![
            identity.scope().scope_id().as_str(),
            identity.work().id().as_str(),
            stored_u64(identity.work().revision())?,
            stored_u64(identity.claim_fence().get())?,
            activation.digest.as_str(),
        ],
        |row| row.get(0),
    )?;
    if rerecord {
        return Ok(());
    }
    let updated = connection.execute(
        FOLD_GRANT_SQL,
        params![
            identity.scope().scope_id().as_str(),
            identity.work().id().as_str(),
            stored_u64(identity.work().revision())?,
            stored_u64(identity.claim_fence().get())?,
            activation.digest.as_str(),
            stored_u64(activation.attempt.get())?,
            stored_u64(activation.deadline_unix_ms.get())?,
            stored_u64(activation.units.get())?,
        ],
    )?;
    if updated == 1 {
        Ok(())
    } else {
        Err(ApplyError::Conflict)
    }
}

/// The claim fence and grant digest travel with the work reference because a continuation must
/// prove it holds the exact grant the row recorded, not merely some grant for that work.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContinuableWork {
    work: WorkRef,
    claim_fence: NonZeroU64,
    grant_digest: Digest,
    claim_lease_until: NonZeroU64,
}

impl ContinuableWork {
    pub fn work(&self) -> &WorkRef {
        &self.work
    }

    pub fn claim_fence(&self) -> NonZeroU64 {
        self.claim_fence
    }

    /// `grant_digest` identifies the grant whose `grant_activated` fold landed at
    /// [`Self::claim_fence`].
    pub fn grant_digest(&self) -> &Digest {
        &self.grant_digest
    }

    /// The row's recorded lease, so a caller can retest it against a clock read after this query
    /// returned.
    pub fn claim_lease_until(&self) -> NonZeroU64 {
        self.claim_lease_until
    }
}

/// Lists the revisions an existing claim and grant may continue at `scope_epoch` and `now_ms`.
///
/// # Errors
///
/// Returns [`ApplyError::StaleAuthority`] when the projected scope epoch is ahead of
/// `scope_epoch`, which proves the supplied authority superseded rather than the set empty, and
/// [`ApplyError::DatabaseOperationFailed`] when SQLite fails or a stored row cannot be
/// converted back into a validated work reference.
pub(crate) fn continuable_work(
    connection: &rusqlite::Connection,
    scope: &ScopeIdentity,
    scope_epoch: NonZeroU64,
    now_ms: u64,
) -> Result<Vec<ContinuableWork>, ApplyError> {
    let projected: Option<i64> = connection
        .query_row(
            PROJECTED_SCOPE_EPOCH_SQL,
            [scope.scope_id().as_str()],
            |row| row.get(0),
        )
        .optional()?;
    // A projection ahead of the caller's epoch was written under newer authority; answering
    // with rows (or none) would let a superseded controller mistake supersession for idleness.
    if let Some(projected) = projected
        && !u64::try_from(projected).is_ok_and(|epoch| epoch <= scope_epoch.get())
    {
        return Err(ApplyError::StaleAuthority);
    }
    let mut statement = connection.prepare(CONTINUABLE_WORK_SQL)?;
    let rows = statement
        .query_map(
            params![
                scope.scope_id().as_str(),
                stored_u64(scope_epoch.get())?,
                stored_u64(now_ms)?
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )?
        .collect::<Result<Vec<_>, _>>()?;
    rows.into_iter()
        .map(
            |(work_id, revision, claim_fence, grant_digest, claim_lease_until)| {
                let bounded = |value: i64| {
                    u64::try_from(value)
                        .ok()
                        .and_then(NonZeroU64::new)
                        .ok_or(ApplyError::DatabaseOperationFailed)
                };
                Ok(ContinuableWork {
                    work: WorkRef::new(
                        WorkId::new(work_id).map_err(|_| ApplyError::DatabaseOperationFailed)?,
                        u64::try_from(revision).map_err(|_| ApplyError::DatabaseOperationFailed)?,
                    ),
                    claim_fence: bounded(claim_fence)?,
                    grant_digest: Digest::new(grant_digest)
                        .map_err(|_| ApplyError::DatabaseOperationFailed)?,
                    claim_lease_until: bounded(claim_lease_until)?,
                })
            },
        )
        .collect()
}

/// Claimability considers the admitting plan, dependencies, claim state, and terminal evidence at
/// `now_ms`.
///
/// The same rows and `now_ms` always produce the same ordered set, so a restart cannot
/// release a revision that is claimed or already terminal.
///
/// # Errors
///
/// Returns [`ApplyError::DatabaseOperationFailed`] when SQLite fails or a stored row cannot be
/// converted back into a validated work reference.
pub(crate) fn claimable_work(
    connection: &rusqlite::Connection,
    scope: &ScopeIdentity,
    now_ms: u64,
) -> Result<Vec<WorkRef>, ApplyError> {
    let mut statement = connection.prepare(CLAIMABLE_WORK_SQL)?;
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

/// Lists every admitted `(work, revision)` row of one scope.
///
/// # Errors
///
/// Returns [`ApplyError::DatabaseOperationFailed`] when SQLite fails or a stored row cannot be
/// converted back into a validated work reference.
pub(crate) fn admitted_work_refs(
    connection: &rusqlite::Connection,
    scope: &ScopeIdentity,
) -> Result<Vec<WorkRef>, ApplyError> {
    let mut statement = connection.prepare(ADMITTED_WORK_REFS_SQL)?;
    let rows = statement
        .query_map([scope.scope_id().as_str()], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    work_refs(rows)
}

/// Reports whether one scope already applied an event under `operation_id`.
///
/// # Errors
///
/// Returns [`ApplyError::DatabaseOperationFailed`] when SQLite fails.
pub(crate) fn scope_operation_recorded(
    connection: &rusqlite::Connection,
    scope: &ScopeIdentity,
    operation_id: &str,
) -> Result<bool, ApplyError> {
    connection
        .query_row(
            OPERATION_RECORDED_SQL,
            params![scope.scope_id().as_str(), operation_id],
            |row| row.get(0),
        )
        .map_err(Into::into)
}

fn stored_u64(value: u64) -> Result<i64, ApplyError> {
    i64::try_from(value).map_err(|_| ApplyError::DatabaseOperationFailed)
}

/// # Errors
///
/// Returns [`ApplyError::DatabaseOperationFailed`] when the scope row is missing or SQLite
/// fails.
pub(crate) fn claims_restored(
    connection: &rusqlite::Connection,
    scope: &ScopeIdentity,
) -> Result<bool, ApplyError> {
    connection
        .query_row(CLAIMS_RESTORED_SQL, [scope.scope_id().as_str()], |row| {
            row.get(0)
        })
        .map_err(Into::into)
}

/// # Errors
///
/// Returns [`ApplyError::Conflict`] when the scope row is missing and
/// [`ApplyError::DatabaseOperationFailed`] when SQLite fails.
pub(crate) fn mark_claims_restored(
    connection: &rusqlite::Connection,
    scope: &ScopeIdentity,
) -> Result<(), ApplyError> {
    let updated = connection.execute(MARK_CLAIMS_RESTORED_SQL, [scope.scope_id().as_str()])?;
    if updated == 1 {
        Ok(())
    } else {
        Err(ApplyError::Conflict)
    }
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
                 reserved_budget_units, claims_restored) \
                 VALUES (?1, ?2, NULL, NULL, ?3, ?4, NULL, ?5, ?6, NULL, 0)",
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

    // A committed activation event is fact (I2): rowcount 0 means the history names a revision
    // no admission produced, which a well-formed chain cannot do.
    if let ScopeProjectionPayload::GrantActivated { payload } = &event.payload {
        let updated = transaction.execute(
            FOLD_GRANT_SQL,
            params![
                scope_id,
                payload.work().id().as_str(),
                stored_u64(payload.work().revision())?,
                stored_u64(payload.claim_fence().get())?,
                payload.grant_digest().as_str(),
                stored_u64(payload.attempt().get())?,
                stored_u64(payload.deadline_unix_ms().get())?,
                stored_u64(payload.units().get())?,
            ],
        )?;
        if updated != 1 {
            return Err(ApplyError::Conflict);
        }
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

/// Covers every projected TEXT column a read decodes as a Rust `String`, minus the columns a
/// CHECK pins `IS NULL` and the FK-derived `scope_id`s, which SQLite's `foreign_key_check`
/// matches against an already validated `scopes.scope_id`.
const VALIDATE_TEXT_SQL: &str = "SELECT CAST(scope_id AS BLOB) FROM scopes \
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
     UNION ALL SELECT CAST(plan_digest AS BLOB) FROM admitted_work \
     UNION ALL SELECT CAST(grant_digest AS BLOB) FROM admitted_work \
       WHERE grant_digest IS NOT NULL \
     UNION ALL SELECT CAST(terminal_result_digest AS BLOB) FROM admitted_work \
       WHERE terminal_result_digest IS NOT NULL \
     UNION ALL SELECT CAST(work_id AS BLOB) FROM work_dependencies \
     UNION ALL SELECT CAST(depends_on_work_id AS BLOB) FROM work_dependencies";

/// Invalid UTF-8 passes the byte-oriented CHECKs and then fails the read that converts the
/// column to a Rust `String`, so it is rejected here as invalid history.
fn validate_text(connection: &rusqlite::Connection) -> Result<(), ValidateError> {
    let mut statement = connection
        .prepare(VALIDATE_TEXT_SQL)
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
    let broken_admissions: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM scopes AS scope \
             WHERE (scope.active_plan_digest IS NOT NULL) != EXISTS(SELECT 1 \
                 FROM applied_scope_events AS event \
                 WHERE event.scope_id = scope.scope_id AND event.payload_type = ?1)",
            [crate::scope::PLAN_ADMITTED_PAYLOAD_TYPE],
            |row| row.get(0),
        )
        .map_err(|_| ValidateError::DatabaseOperationFailed)?;
    if orphans != 0
        || broken_parents != 0
        || broken_cursors != 0
        || unregistered
        || broken_admissions != 0
    {
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
    /// A row bound to any plan other than the scope's active one is excluded from scheduling, so
    /// one constant serves as both the seeded active plan and the admitting plan.
    const ADMITTING_PLAN_DIGEST: &str = DIGEST_2;

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
            query_plan(&connection, CLAIMABLE_WORK_SQL, &[&scope_id, &sequence]),
            query_plan(
                &connection,
                GRANT_ADMISSIBLE_SQL,
                &[
                    &scope_id, &work_id, &revision, &sequence, &digest, &sequence, &sequence,
                    &sequence, &sequence, &sequence, &digest,
                ],
            ),
            query_plan(
                &connection,
                FOLD_GRANT_SQL,
                &[
                    &scope_id, &work_id, &revision, &sequence, &digest, &sequence, &sequence,
                    &sequence,
                ],
            ),
            query_plan(
                &connection,
                GRANT_RERECORD_SQL,
                &[&scope_id, &work_id, &revision, &sequence, &digest],
            ),
            query_plan(&connection, ADMITTED_WORK_REFS_SQL, &[&scope_id]),
            query_plan(&connection, CLAIMS_RESTORED_SQL, &[&scope_id]),
            query_plan(&connection, MARK_CLAIMS_RESTORED_SQL, &[&scope_id]),
            query_plan(
                &connection,
                OPERATION_RECORDED_SQL,
                &[&scope_id, &operation],
            ),
            query_plan(
                &connection,
                CONTINUABLE_WORK_SQL,
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

    /// A new TEXT column needs a matching UNION arm in `VALIDATE_TEXT_SQL`, or it escapes UTF-8
    /// validation; this test fails otherwise.
    #[test]
    fn validate_text_covers_every_projected_text_column() {
        const PINNED_NULL_OR_FK_DERIVED: [(&str, &str); 4] = [
            ("scopes", "parent_scope_id"),
            ("scopes", "delegation_digest"),
            ("admitted_work", "scope_id"),
            ("work_dependencies", "scope_id"),
        ];
        let path = path("validate-text-coverage");
        let connection = create(&path).unwrap();
        for table in TABLES {
            let columns: Vec<String> = connection
                .prepare("SELECT name FROM pragma_table_info(?1) WHERE type = 'TEXT'")
                .unwrap()
                .query_map([table], |row| row.get(0))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap();
            assert!(!columns.is_empty(), "{table} reported no TEXT columns");
            for column in columns {
                if PINNED_NULL_OR_FK_DERIVED.contains(&(table, column.as_str())) {
                    continue;
                }
                assert!(
                    VALIDATE_TEXT_SQL.contains(&format!("CAST({column} AS BLOB) FROM {table}")),
                    "{table}.{column} is not validated by VALIDATE_TEXT_SQL"
                );
            }
        }
        drop(connection);
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

    fn stored_plan_digest(
        connection: &rusqlite::Connection,
        scope: &ScopeIdentity,
        work: &WorkRef,
    ) -> String {
        connection
            .query_row(
                "SELECT plan_digest FROM admitted_work \
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

    /// `ADMIT_PLAN_SQL` still refuses a second plan, so a test that needs the superseded state
    /// writes the pointer directly, as the repo already does for states production cannot produce.
    fn supersede_plan(connection: &rusqlite::Connection, scope: &ScopeIdentity, digest: &str) {
        connection
            .execute(
                "UPDATE scopes SET active_plan_digest = ?1 WHERE scope_id = ?2",
                params![digest, scope.scope_id().as_str()],
            )
            .unwrap();
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

    fn plan(digest: &str) -> Digest {
        Digest::new(digest.into()).unwrap()
    }

    /// Admits test work under `ADMITTING_PLAN_DIGEST`, matching `seed_active_plan`.
    fn admit(
        connection: &mut rusqlite::Connection,
        scope: &ScopeIdentity,
        work: &WorkRef,
        dependencies: &[WorkRef],
        scope_epoch: NonZeroU64,
    ) -> Result<(), ApplyError> {
        admit_work(
            connection,
            scope,
            work,
            dependencies,
            &plan(ADMITTING_PLAN_DIGEST),
            scope_epoch,
        )
    }

    fn claimable(
        connection: &rusqlite::Connection,
        scope: &ScopeIdentity,
        now_ms: u64,
    ) -> Vec<String> {
        claimable_work(connection, scope, now_ms)
            .unwrap()
            .into_iter()
            .map(|work| format!("{}@{}", work.id().as_str(), work.revision()))
            .collect()
    }

    fn genesis_scope(label: &str) -> (PathBuf, rusqlite::Connection, ScopeIdentity) {
        let db_path = path(label);
        let mut connection = create(&db_path).unwrap();
        let scope = scope("workspace-a", "campaign-a");
        apply_scope_event(&mut connection, &mutation(&scope, 1, DIGEST_1, None)).unwrap();
        (db_path, connection, scope)
    }

    /// `admitted_scope` seeds an active plan without an admission event, so databases it creates
    /// fail `open_existing`'s `validate_history`. A test that reopens a database uses
    /// `genesis_scope` and admits a real plan.
    fn admitted_scope(label: &str) -> (PathBuf, rusqlite::Connection, ScopeIdentity) {
        let (db_path, connection, scope) = genesis_scope(label);
        seed_active_plan(&connection, &scope, 1);
        (db_path, connection, scope)
    }

    #[test]
    fn a_grant_activation_for_an_unadmitted_revision_applies_nothing() {
        let (db_path, mut connection, scope) = admitted_scope("grant-fold-unadmitted");
        admit(&mut connection, &scope, &work("work-a", 1), &[], epoch(1)).unwrap();

        // Revision 2 of work-a was never admitted, so the fold updates zero rows.
        let payload = GrantActivatedPayload::new(
            work("work-a", 2),
            2,
            Digest::new(DIGEST_3.into()).unwrap(),
            1,
            5,
            60_000,
        )
        .unwrap();
        let envelope = EventEnvelope::new(
            scope.scope_id().clone(),
            2,
            Some(ScopeEventRef::new(1, Digest::new(DIGEST_1.into()).unwrap()).unwrap()),
            1,
            "grant-op-2".into(),
            crate::scope::GRANT_ACTIVATED_PAYLOAD_TYPE.into(),
        )
        .unwrap();
        let event = ScopeProjectionEvent::new(
            scope.clone(),
            envelope,
            ScopeEventRef::new(2, Digest::new(DIGEST_2.into()).unwrap()).unwrap(),
            ScopeProjectionPayload::GrantActivated { payload },
            1,
        )
        .unwrap();

        assert_eq!(
            apply_scope_event(&mut connection, &event),
            Err(ApplyError::Conflict)
        );
        // The fold and the cursor advance share one transaction, so the refused event leaves
        // no trace: the cursor still names genesis and no event row exists at sequence 2.
        assert_eq!(scope_cursor(&connection, &scope).unwrap().0, 1);
        let recorded: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM applied_scope_events \
                 WHERE scope_id = ?1 AND sequence = 2)",
                [scope.scope_id().as_str()],
                |row| row.get(0),
            )
            .unwrap();
        assert!(!recorded);

        drop(connection);
        fs::remove_file(db_path).unwrap();
    }

    #[test]
    fn a_grant_activation_event_folds_exactly_once() {
        let (db_path, mut connection, scope) = admitted_scope("grant-fold-once");
        admit(&mut connection, &scope, &work("work-a", 1), &[], epoch(1)).unwrap();

        let grant_event = |sequence: u64,
                           parent: &str,
                           digest: &str,
                           target: WorkRef,
                           fence: u64,
                           attempt: u64,
                           units: u64| {
            let payload = GrantActivatedPayload::new(
                target,
                fence,
                Digest::new(DIGEST_3.into()).unwrap(),
                attempt,
                units,
                60_000,
            )
            .unwrap();
            let envelope = EventEnvelope::new(
                scope.scope_id().clone(),
                sequence,
                Some(
                    ScopeEventRef::new(sequence - 1, Digest::new(parent.into()).unwrap()).unwrap(),
                ),
                1,
                format!("grant-op-{sequence}"),
                crate::scope::GRANT_ACTIVATED_PAYLOAD_TYPE.into(),
            )
            .unwrap();
            ScopeProjectionEvent::new(
                scope.clone(),
                envelope,
                ScopeEventRef::new(sequence, Digest::new(digest.into()).unwrap()).unwrap(),
                ScopeProjectionPayload::GrantActivated { payload },
                1,
            )
            .unwrap()
        };
        let grant_columns = |connection: &rusqlite::Connection| {
            connection
                .query_row(
                    "SELECT grant_fence, grant_digest, granted_attempt, granted_units, \
                     grant_deadline_unix_ms FROM admitted_work \
                     WHERE scope_id = ?1 AND work_id = 'work-a' AND work_revision = 1",
                    [scope.scope_id().as_str()],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, i64>(2)?,
                            row.get::<_, i64>(3)?,
                            row.get::<_, i64>(4)?,
                        ))
                    },
                )
                .unwrap()
        };

        // The fold is a fact application: no claim exists, and it lands anyway.
        let first = grant_event(2, DIGEST_1, DIGEST_2, work("work-a", 1), 2, 1, 5);
        assert_eq!(
            apply_scope_event(&mut connection, &first),
            Ok(ApplyOutcome::Applied)
        );
        let after = grant_columns(&connection);
        assert_eq!(after, (2, DIGEST_3.to_owned(), 1, 5, 60_000));

        // A replayed sequence is recognised, so the running total cannot double-accumulate.
        assert_eq!(
            apply_scope_event(&mut connection, &first),
            Ok(ApplyOutcome::AlreadyApplied)
        );
        assert_eq!(grant_columns(&connection), after);

        // A later fence accumulates units instead of replacing them.
        let second = grant_event(3, DIGEST_2, DIGEST_3, work("work-a", 1), 3, 2, 7);
        assert_eq!(
            apply_scope_event(&mut connection, &second),
            Ok(ApplyOutcome::Applied)
        );
        assert_eq!(
            grant_columns(&connection),
            (3, DIGEST_3.to_owned(), 2, 12, 60_000)
        );

        // An event naming an unadmitted revision is a conflict, and nothing commits.
        let missing = grant_event(4, DIGEST_3, DIGEST_1, work("work-x", 1), 4, 3, 1);
        assert_eq!(
            apply_scope_event(&mut connection, &missing),
            Err(ApplyError::Conflict)
        );
        assert_eq!(scope_cursor(&connection, &scope).unwrap().0, 3);

        drop(connection);
        fs::remove_file(db_path).unwrap();
    }

    #[test]
    fn claimability_follows_dependencies_claims_and_terminal_evidence() {
        let (db_path, mut connection, scope) = admitted_scope("claimable-work");

        admit(&mut connection, &scope, &work("work-a", 1), &[], epoch(1)).unwrap();
        admit(
            &mut connection,
            &scope,
            &work("work-b", 1),
            &[work("work-a", 1)],
            epoch(1),
        )
        .unwrap();
        // An unsatisfied dependency withholds the dependent revision.
        assert_eq!(claimable(&connection, &scope, 1_000), vec!["work-a@1"]);

        // Re-admission is idempotent.
        admit(&mut connection, &scope, &work("work-a", 1), &[], epoch(1)).unwrap();
        assert_eq!(claimable(&connection, &scope, 1_000), vec!["work-a@1"]);

        let result = Digest::new(DIGEST_2.into()).unwrap();
        let fence = NonZeroU64::new(1).unwrap();
        let lease = NonZeroU64::new(31_000).unwrap();
        record_claim(&connection, &scope, &work("work-a", 1), fence, lease, 1_000).unwrap();
        record_terminal(&connection, &scope, &work("work-a", 1), fence, &result).unwrap();
        assert_eq!(claimable(&connection, &scope, 1_000), vec!["work-b@1"]);

        record_claim(&connection, &scope, &work("work-b", 1), fence, lease, 1_000).unwrap();
        // A live claim withholds the revision; an expired one makes it reclaimable.
        assert!(claimable(&connection, &scope, 1_000).is_empty());
        assert_eq!(claimable(&connection, &scope, 31_000), vec!["work-b@1"]);

        // Terminal evidence prevents reclamation after lease expiry.
        record_terminal(&connection, &scope, &work("work-b", 1), fence, &result).unwrap();
        assert!(claimable(&connection, &scope, 31_000).is_empty());

        // Claims for unadmitted work return `ApplyError::Conflict`.
        assert_eq!(
            record_claim(&connection, &scope, &work("work-c", 1), fence, lease, 1_000),
            Err(ApplyError::Conflict)
        );

        drop(connection);
        fs::remove_file(db_path).unwrap();
    }

    #[test]
    fn a_reopened_projection_rebuilds_the_same_claimable_set() {
        let (db_path, mut connection, scope) = genesis_scope("claimable-restart");
        // Reopening validates the file, and `validate_history` pairs `active_plan_digest` with an
        // applied plan-admitted event, so this fixture admits a real plan rather than seeding the
        // pointer. That proposal already carries `work-a` and `work-b` depending on it.
        let proposal = plan_proposal(&scope, &zero_objective(), MAX_STORED_INTEGER);
        let (event, plan_digest) = admission_event(&scope, &proposal, "admit-plan-1");
        apply_scope_event(&mut connection, &event).unwrap();
        admit_work(
            &mut connection,
            &scope,
            &work("work-c", 1),
            &[],
            &plan_digest,
            epoch(1),
        )
        .unwrap();
        record_claim(
            &connection,
            &scope,
            &work("work-c", 1),
            NonZeroU64::new(4).unwrap(),
            NonZeroU64::new(31_000).unwrap(),
            1_000,
        )
        .unwrap();
        let before = claimable(&connection, &scope, 1_000);
        assert_eq!(before, vec!["work-a@1"]);
        drop(connection);

        let reopened = open_existing(&db_path).unwrap();
        assert_eq!(claimable(&reopened, &scope, 1_000), before);
        // Past the recorded lease the claimed revision is reclaimable exactly once, and the
        // restart cannot hand it out under a regressed fence or a shortened lease.
        assert_eq!(
            claimable(&reopened, &scope, 31_000),
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
    fn a_dependency_is_resolved_only_at_the_revision_the_active_plan_admitted() {
        let (db_path, mut connection, scope) = admitted_scope("dependency-supersession");
        let result = Digest::new(DIGEST_2.into()).unwrap();
        let fence = NonZeroU64::new(1).unwrap();
        let lease = NonZeroU64::new(31_000).unwrap();
        admit(&mut connection, &scope, &work("work-a", 1), &[], epoch(1)).unwrap();
        admit(
            &mut connection,
            &scope,
            &work("work-b", 1),
            &[work("work-a", 1)],
            epoch(1),
        )
        .unwrap();
        record_claim(&connection, &scope, &work("work-a", 1), fence, lease, 1_000).unwrap();
        record_terminal(&connection, &scope, &work("work-a", 1), fence, &result).unwrap();
        assert_eq!(claimable(&connection, &scope, 1_000), vec!["work-b@1"]);

        // A second plan admits its own revision of both work ids, binding `work-b@2`'s edge to
        // the revision it admits.
        supersede_plan(&connection, &scope, DIGEST_3);
        admit_work(
            &mut connection,
            &scope,
            &work("work-a", 2),
            &[],
            &plan(DIGEST_3),
            epoch(1),
        )
        .unwrap();
        admit_work(
            &mut connection,
            &scope,
            &work("work-b", 2),
            &[work("work-a", 2)],
            &plan(DIGEST_3),
            epoch(1),
        )
        .unwrap();

        // `work-a@1` still carries terminal evidence, but the superseded plan admitted it, so it
        // does not resolve the edge `work-b@2` declares.
        assert_eq!(claimable(&connection, &scope, 1_000), vec!["work-a@2"]);

        // The same evidence on the row the active plan admitted does resolve it.
        record_claim(&connection, &scope, &work("work-a", 2), fence, lease, 1_000).unwrap();
        record_terminal(&connection, &scope, &work("work-a", 2), fence, &result).unwrap();
        assert_eq!(claimable(&connection, &scope, 1_000), vec!["work-b@2"]);

        drop(connection);
        fs::remove_file(db_path).unwrap();
    }

    /// A terminal result for `work-a@5` does not satisfy `work-b@1`'s dependency on `work-a@1`.
    #[test]
    fn a_dependency_edge_is_satisfied_only_at_its_bound_revision() {
        let (db_path, mut connection, scope) = admitted_scope("dependency-bound-revision");
        let fence = NonZeroU64::new(1).unwrap();
        let lease = NonZeroU64::new(31_000).unwrap();
        let result = Digest::new(DIGEST_2.into()).unwrap();
        admit(&mut connection, &scope, &work("work-a", 1), &[], epoch(1)).unwrap();
        admit(
            &mut connection,
            &scope,
            &work("work-b", 1),
            &[work("work-a", 1)],
            epoch(1),
        )
        .unwrap();

        // The direct insert creates a terminal `work-a@5` row under another plan.
        connection
            .execute(
                "INSERT INTO admitted_work \
                 (scope_id, work_id, work_revision, plan_digest, admitted_scope_epoch, \
                  max_attempts, deadline_unix_ms, claim_fence, claim_lease_until, \
                  terminal_result_digest) \
                 VALUES (?1, 'work-a', 5, ?2, 1, 3, 9999999999999999, 1, 31000, ?3)",
                params![scope.scope_id().as_str(), DIGEST_3, DIGEST_1],
            )
            .unwrap();
        // A dangling edge fails closed: `(work-x, 1)` was never admitted, and the terminal
        // `work-x@7` row under `ADMITTING_PLAN_DIGEST` does not stand in for it.
        admit(
            &mut connection,
            &scope,
            &work("work-c", 1),
            &[work("work-x", 1)],
            epoch(1),
        )
        .unwrap();
        connection
            .execute(
                "INSERT INTO admitted_work \
                 (scope_id, work_id, work_revision, plan_digest, admitted_scope_epoch, \
                  max_attempts, deadline_unix_ms, claim_fence, claim_lease_until, \
                  terminal_result_digest) \
                 VALUES (?1, 'work-x', 7, ?2, 1, 3, 9999999999999999, 1, 31000, ?3)",
                params![scope.scope_id().as_str(), ADMITTING_PLAN_DIGEST, DIGEST_1],
            )
            .unwrap();
        assert_eq!(claimable(&connection, &scope, 1_000), vec!["work-a@1"]);

        // Terminal evidence on the exact bound revision is what satisfies the edge.
        record_claim(&connection, &scope, &work("work-a", 1), fence, lease, 1_000).unwrap();
        record_terminal(&connection, &scope, &work("work-a", 1), fence, &result).unwrap();
        assert_eq!(claimable(&connection, &scope, 1_000), vec!["work-b@1"]);

        drop(connection);
        fs::remove_file(db_path).unwrap();
    }

    #[test]
    fn plan_supersession_withdraws_scheduling_and_keeps_the_superseded_row() {
        let (db_path, mut connection, scope) = admitted_scope("plan-supersession");
        let superseded = work("work-a", 1);
        let current = work("work-a", 2);
        let fence = NonZeroU64::new(2).unwrap();
        let lease = NonZeroU64::new(31_000).unwrap();
        admit(&mut connection, &scope, &superseded, &[], epoch(1)).unwrap();
        record_claim(&connection, &scope, &superseded, fence, lease, 1_000).unwrap();
        grant_at(&connection, &scope, &superseded, fence, 1, 1).unwrap();
        assert_eq!(
            continuable(&connection, &scope, 1, 1_000),
            vec!["work-a@1#2"]
        );

        // Recording terminal evidence for `closed` leaves `superseded`'s plan binding as its only
        // continuability arm.
        let closed = work("work-b", 1);
        let result = Digest::new(DIGEST_1.into()).unwrap();
        admit(&mut connection, &scope, &closed, &[], epoch(1)).unwrap();
        record_claim(&connection, &scope, &closed, fence, lease, 1_000).unwrap();
        record_terminal(&connection, &scope, &closed, fence, &result).unwrap();

        supersede_plan(&connection, &scope, DIGEST_3);
        admit_work(
            &mut connection,
            &scope,
            &current,
            &[],
            &plan(DIGEST_3),
            epoch(1),
        )
        .unwrap();

        // Only the revision the active plan admitted schedules. Past the superseded row's lease
        // the plan binding is the only arm still withholding it.
        assert_eq!(claimable(&connection, &scope, 31_000), vec!["work-a@2"]);
        assert!(continuable(&connection, &scope, 1, 1_000).is_empty());

        // Supersession withdraws scheduling and rewrites no recorded evidence.
        assert_eq!(
            stored_claim(&connection, &scope, &superseded),
            (Some(2), Some(31_000))
        );
        assert_eq!(granted_units(&connection, &superseded), Some(1));
        assert_eq!(
            stored_plan_digest(&connection, &scope, &superseded),
            ADMITTING_PLAN_DIGEST
        );
        assert_eq!(
            stored_terminal(&connection, &scope, &closed),
            Some(DIGEST_1.to_owned())
        );

        // A claim and grant on the active-plan row do continue.
        record_claim(&connection, &scope, &current, fence, lease, 1_000).unwrap();
        record_grant(
            &connection,
            &ScopeClaimIdentity::new(scope.clone(), plan(DIGEST_3), current.clone(), fence.get())
                .unwrap(),
            &GrantActivation {
                scope_epoch: epoch(1),
                attempt: NonZeroU64::new(1).unwrap(),
                units: NonZeroU64::new(1).unwrap(),
                deadline_unix_ms: NonZeroU64::new(MAX_STORED_INTEGER).unwrap(),
                digest: grant_digest(fence.get(), 1),
            },
            1_000,
        )
        .unwrap();
        assert_eq!(
            continuable(&connection, &scope, 1, 1_000),
            vec!["work-a@2#2"]
        );

        drop(connection);
        fs::remove_file(db_path).unwrap();
    }

    #[test]
    fn a_scope_with_no_active_plan_schedules_nothing() {
        let (db_path, mut connection, scope) = admitted_scope("no-active-plan");
        let target = work("work-a", 1);
        let fence = NonZeroU64::new(2).unwrap();
        admit(&mut connection, &scope, &target, &[], epoch(1)).unwrap();
        record_claim(
            &connection,
            &scope,
            &target,
            fence,
            NonZeroU64::new(31_000).unwrap(),
            1_000,
        )
        .unwrap();
        grant_at(&connection, &scope, &target, fence, 1, 1).unwrap();
        assert_eq!(claimable(&connection, &scope, 31_000), vec!["work-a@1"]);
        assert_eq!(
            continuable(&connection, &scope, 1, 1_000),
            vec!["work-a@1#2"]
        );

        connection
            .execute(
                "UPDATE scopes SET active_plan_digest = NULL, reserved_budget_units = NULL \
                 WHERE scope_id = ?1",
                [scope.scope_id().as_str()],
            )
            .unwrap();

        // Past the recorded lease nothing but the plan binding withholds the row.
        assert!(claimable(&connection, &scope, 31_000).is_empty());
        assert!(continuable(&connection, &scope, 1, 1_000).is_empty());

        drop(connection);
        fs::remove_file(db_path).unwrap();
    }

    #[test]
    fn re_admission_under_another_plan_conflicts_and_keeps_the_stored_binding() {
        let (db_path, mut connection, scope) = admitted_scope("plan-rebinding");
        let target = work("work-a", 1);
        admit(&mut connection, &scope, &target, &[], epoch(1)).unwrap();
        assert_eq!(
            admit_work(
                &mut connection,
                &scope,
                &target,
                &[],
                &plan(DIGEST_3),
                epoch(1)
            ),
            Err(ApplyError::Conflict)
        );
        assert_eq!(
            stored_plan_digest(&connection, &scope, &target),
            ADMITTING_PLAN_DIGEST
        );

        // Re-admission naming the plan that admitted it stays idempotent.
        admit(&mut connection, &scope, &target, &[], epoch(1)).unwrap();
        assert_eq!(claimable(&connection, &scope, 1_000), vec!["work-a@1"]);

        drop(connection);
        fs::remove_file(db_path).unwrap();
    }

    #[test]
    fn one_plan_admits_one_revision_of_a_work_id() {
        let (db_path, mut connection, scope) = admitted_scope("one-revision-per-plan");
        let admitting_epoch = |connection: &rusqlite::Connection| -> i64 {
            connection
                .query_row(
                    "SELECT admitted_scope_epoch FROM admitted_work WHERE work_revision = 1",
                    [],
                    |row| row.get(0),
                )
                .unwrap()
        };
        admit(&mut connection, &scope, &work("work-a", 1), &[], epoch(1)).unwrap();
        // The refused revision names a higher epoch, so an upsert that resolved this collision
        // instead of raising it would leave its trace on the first row.
        assert_eq!(
            admit(&mut connection, &scope, &work("work-a", 2), &[], epoch(2)),
            Err(ApplyError::Conflict)
        );

        // The refused revision wrote no row, so it added no second schedulable revision.
        assert_eq!(claimable(&connection, &scope, 1_000), vec!["work-a@1"]);
        assert_eq!(admitting_epoch(&connection), 1);

        drop(connection);
        fs::remove_file(db_path).unwrap();
    }

    /// Scheduling reads the plan binding, so an absent or malformed one must be unrepresentable
    /// rather than merely unschedulable.
    /// Every byte outside `0-9a-f` fails the hex CHECK, so invalid UTF-8 cannot enter the column.
    #[test]
    fn the_schema_rejects_a_missing_or_non_hex_plan_digest() {
        let (db_path, connection, scope) = genesis_scope("plan-digest-column-checks");
        let insert = |digest: Option<&str>| {
            connection.execute(
                "INSERT INTO admitted_work \
                 (scope_id, work_id, work_revision, plan_digest, admitted_scope_epoch, \
                  max_attempts, deadline_unix_ms) \
                 VALUES (?1, 'work-a', 1, ?2, 1, 3, 9999999999999999)",
                params![scope.scope_id().as_str(), digest],
            )
        };
        let non_hex = "z".repeat(64);

        // A CHECK passes when it evaluates to NULL, so a NULL binding would escape the hex test
        // too if `NOT NULL` did not refuse it first.
        for digest in [None, Some(non_hex.as_str())] {
            assert_eq!(
                insert(digest).unwrap_err().sqlite_error_code(),
                Some(rusqlite::ErrorCode::ConstraintViolation)
            );
        }
        insert(Some(ADMITTING_PLAN_DIGEST)).unwrap();

        drop(connection);
        fs::remove_file(db_path).unwrap();
    }

    #[test]
    fn the_schema_rejects_a_half_recorded_claim_grant_or_unclaimed_terminal_evidence() {
        let (db_path, mut connection, scope) = admitted_scope("claim-column-checks");
        let target = work("work-a", 1);
        admit(&mut connection, &scope, &target, &[], epoch(1)).unwrap();
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

        // The five grant columns are present or absent together, so a recorded grant cannot
        // lose its deadline and a deadline cannot exist without its grant.
        let grant = |rest: Option<i64>, deadline: Option<i64>| {
            connection.execute(
                "UPDATE admitted_work SET grant_fence = ?4, grant_digest = ?5, \
                 granted_attempt = ?4, granted_units = ?4, grant_deadline_unix_ms = ?6 \
                 WHERE scope_id = ?1 AND work_id = ?2 AND work_revision = ?3",
                params![
                    scope.scope_id().as_str(),
                    target.id().as_str(),
                    target.revision() as i64,
                    rest,
                    rest.map(|_| DIGEST_3),
                    deadline
                ],
            )
        };
        for (rest, deadline) in [(Some(1), None), (None, Some(10_000))] {
            assert_eq!(
                grant(rest, deadline).unwrap_err().sqlite_error_code(),
                Some(rusqlite::ErrorCode::ConstraintViolation)
            );
        }
        grant(Some(1), Some(10_000)).unwrap();

        drop(connection);
        fs::remove_file(db_path).unwrap();
    }

    #[test]
    fn claim_and_terminal_records_never_regress() {
        let (db_path, mut connection, scope) = admitted_scope("record-guards");
        let target = work("work-a", 1);
        admit(&mut connection, &scope, &target, &[], epoch(1)).unwrap();
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
            claimable(&connection, &scope, short_lease.get()),
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
        let first = work("work-a", 1);
        let second = work("work-c", 1);
        admit(
            &mut connection,
            &scope,
            &work("work-b", 1),
            &[first.clone(), second.clone()],
            epoch(1),
        )
        .unwrap();
        assert!(claimable(&connection, &scope, 1_000).is_empty());

        // Ordering and duplicates do not change canonical set identity.
        admit(
            &mut connection,
            &scope,
            &work("work-b", 1),
            &[second.clone(), first.clone(), second.clone()],
            epoch(1),
        )
        .unwrap();
        assert_eq!(
            admit(
                &mut connection,
                &scope,
                &work("work-b", 1),
                std::slice::from_ref(&first),
                epoch(1),
            ),
            Err(ApplyError::Conflict)
        );
        // The canonical set is pairs: the same work ids bound at another revision are a
        // different set, not a reordering.
        assert_eq!(
            admit(
                &mut connection,
                &scope,
                &work("work-b", 1),
                &[work("work-a", 2), second.clone()],
                epoch(1),
            ),
            Err(ApplyError::Conflict)
        );

        // Conflicting re-admission retains both original edges atomically.
        let fence = NonZeroU64::new(1).unwrap();
        let lease = NonZeroU64::new(31_000).unwrap();
        let result = Digest::new(DIGEST_2.into()).unwrap();
        admit(&mut connection, &scope, &work("work-a", 1), &[], epoch(1)).unwrap();
        record_claim(&connection, &scope, &work("work-a", 1), fence, lease, 1_000).unwrap();
        record_terminal(&connection, &scope, &work("work-a", 1), fence, &result).unwrap();
        assert!(claimable(&connection, &scope, 1_000).is_empty());
        admit(&mut connection, &scope, &work("work-c", 1), &[], epoch(1)).unwrap();
        record_claim(&connection, &scope, &work("work-c", 1), fence, lease, 1_000).unwrap();
        record_terminal(&connection, &scope, &work("work-c", 1), fence, &result).unwrap();
        assert_eq!(claimable(&connection, &scope, 1_000), vec!["work-b@1"]);

        // A newer admitting epoch does not license a changed dependency set.
        assert_eq!(
            admit(
                &mut connection,
                &scope,
                &work("work-b", 1),
                std::slice::from_ref(&first),
                epoch(9),
            ),
            Err(ApplyError::Conflict)
        );
        admit(
            &mut connection,
            &scope,
            &work("work-b", 1),
            &[first.clone(), second.clone()],
            epoch(9),
        )
        .unwrap();

        assert_eq!(
            admit(
                &mut connection,
                &scope,
                &work("work-b", 2),
                &[work("work-b", 1)],
                epoch(1),
            ),
            Err(ApplyError::Conflict)
        );
        // A single admission cannot bind one work id to two revisions.
        // `work-d` has no prior admission; only the duplicate `work-a` pair can conflict.
        assert_eq!(
            admit(
                &mut connection,
                &scope,
                &work("work-d", 1),
                &[work("work-a", 1), work("work-a", 2)],
                epoch(1),
            ),
            Err(ApplyError::Conflict)
        );
        assert_eq!(claimable(&connection, &scope, 1_000), vec!["work-b@1"]);

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

    fn continuable(
        connection: &rusqlite::Connection,
        scope: &ScopeIdentity,
        scope_epoch: u64,
        now_ms: u64,
    ) -> Vec<String> {
        continuable_work(connection, scope, epoch(scope_epoch), now_ms)
            .unwrap()
            .into_iter()
            .map(|row| {
                format!(
                    "{}@{}#{}",
                    row.work().id().as_str(),
                    row.work().revision(),
                    row.claim_fence()
                )
            })
            .collect()
    }

    /// Seeds an active plan directly so grant tests exercise the plan/epoch bindings without a
    /// full admission fixture.
    fn seed_active_plan(connection: &rusqlite::Connection, scope: &ScopeIdentity, epoch: u64) {
        connection
            .execute(
                "UPDATE scopes SET active_plan_digest = ?1, reserved_budget_units = 100, \
                 scope_epoch = ?2 WHERE scope_id = ?3",
                params![
                    ADMITTING_PLAN_DIGEST,
                    epoch as i64,
                    scope.scope_id().as_str()
                ],
            )
            .unwrap();
    }

    /// Fixtures derive the grant digest from `fence` and `units` so different fence-unit pairs
    /// produce different digests.
    fn grant_digest(fence: u64, units: u64) -> Digest {
        Digest::new(format!("{fence:032x}{units:032x}")).unwrap()
    }

    fn granted_units(connection: &rusqlite::Connection, work: &WorkRef) -> Option<i64> {
        connection
            .query_row(
                "SELECT granted_units FROM admitted_work \
                 WHERE work_id = ?1 AND work_revision = ?2",
                params![work.id().as_str(), work.revision() as i64],
                |row| row.get(0),
            )
            .unwrap()
    }

    fn grant_at(
        connection: &rusqlite::Connection,
        scope: &ScopeIdentity,
        work: &WorkRef,
        fence: NonZeroU64,
        scope_epoch: u64,
        attempt: u64,
    ) -> Result<(), ApplyError> {
        let deadline = NonZeroU64::new(MAX_STORED_INTEGER).unwrap();
        grant_bounded(
            connection,
            scope,
            work,
            fence,
            scope_epoch,
            deadline,
            attempt,
            1,
        )
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "one call shape for every SQL binding"
    )]
    fn grant_bounded(
        connection: &rusqlite::Connection,
        scope: &ScopeIdentity,
        work: &WorkRef,
        fence: NonZeroU64,
        scope_epoch: u64,
        deadline: NonZeroU64,
        attempt: u64,
        units: u64,
    ) -> Result<(), ApplyError> {
        let identity = ScopeClaimIdentity::new(
            scope.clone(),
            plan(ADMITTING_PLAN_DIGEST),
            work.clone(),
            fence.get(),
        )
        .unwrap();
        record_grant(
            connection,
            &identity,
            &GrantActivation {
                scope_epoch: epoch(scope_epoch),
                attempt: NonZeroU64::new(attempt).unwrap(),
                units: NonZeroU64::new(units).unwrap(),
                deadline_unix_ms: deadline,
                digest: grant_digest(fence.get(), units),
            },
            1_000,
        )
    }

    #[test]
    fn a_restart_continues_only_a_current_epoch_claim_and_grant() {
        let (db_path, mut connection, scope) = admitted_scope("continuable-work");
        seed_active_plan(&connection, &scope, 3);
        let target = work("work-a", 1);
        let fence = NonZeroU64::new(2).unwrap();
        let lease = NonZeroU64::new(31_000).unwrap();
        admit(&mut connection, &scope, &target, &[], epoch(3)).unwrap();

        // A claim without a grant cannot continue: no effect authority is current.
        record_claim(&connection, &scope, &target, fence, lease, 1_000).unwrap();
        assert!(continuable(&connection, &scope, 3, 1_000).is_empty());

        grant_at(&connection, &scope, &target, fence, 3, 1).unwrap();
        assert_eq!(
            continuable(&connection, &scope, 3, 1_000),
            vec!["work-a@1#2"]
        );

        // An expired claim lease is not current.
        assert!(continuable(&connection, &scope, 31_000, 31_000).is_empty());

        // A reclaim at a higher fence, once the recorded lease has expired, leaves the old grant
        // behind, and its grant draws the next attempt.
        let higher = NonZeroU64::new(3).unwrap();
        record_claim(&connection, &scope, &target, higher, lease, 31_000).unwrap();
        assert!(continuable(&connection, &scope, 3, 1_000).is_empty());
        assert_eq!(
            grant_at(&connection, &scope, &target, higher, 3, 1),
            Err(ApplyError::Conflict)
        );
        grant_at(&connection, &scope, &target, higher, 3, 2).unwrap();
        assert_eq!(
            continuable(&connection, &scope, 3, 1_000),
            vec!["work-a@1#3"]
        );

        // Work admitted under a newer epoch than this controller holds is not continuable.
        let ahead = work("work-b", 1);
        admit(&mut connection, &scope, &ahead, &[], epoch(5)).unwrap();
        record_claim(&connection, &scope, &ahead, fence, lease, 1_000).unwrap();
        grant_at(&connection, &scope, &ahead, fence, 3, 1).unwrap();
        assert_eq!(
            continuable(&connection, &scope, 3, 1_000),
            vec!["work-a@1#3"]
        );
        assert_eq!(
            continuable(&connection, &scope, 5, 1_000),
            vec!["work-a@1#3", "work-b@1#2"]
        );

        // Terminal evidence ends continuation for the revision that carries it.
        record_terminal(
            &connection,
            &scope,
            &ahead,
            fence,
            &Digest::new(DIGEST_2.into()).unwrap(),
        )
        .unwrap();
        assert_eq!(
            continuable(&connection, &scope, 5, 1_000),
            vec!["work-a@1#3"]
        );

        drop(connection);
        fs::remove_file(db_path).unwrap();
    }

    /// The recorded lease and the admitted work deadline are both far past the grant deadline,
    /// so the grant-deadline arm alone decides both sides of the boundary.
    #[test]
    fn an_expired_grant_deadline_ends_continuation_at_exactly_the_deadline() {
        let (db_path, mut connection, scope) = admitted_scope("grant-deadline-boundary");
        let target = work("work-a", 1);
        let fence = NonZeroU64::new(2).unwrap();
        admit(&mut connection, &scope, &target, &[], epoch(1)).unwrap();
        record_claim(
            &connection,
            &scope,
            &target,
            fence,
            NonZeroU64::new(31_000).unwrap(),
            1_000,
        )
        .unwrap();
        let deadline = NonZeroU64::new(10_000).unwrap();
        grant_bounded(&connection, &scope, &target, fence, 1, deadline, 1, 1).unwrap();

        // The stored row fact is the activation's own deadline.
        let stored: i64 = connection
            .query_row(
                "SELECT grant_deadline_unix_ms FROM admitted_work \
                 WHERE scope_id = ?1 AND work_id = ?2 AND work_revision = ?3",
                params![
                    scope.scope_id().as_str(),
                    target.id().as_str(),
                    target.revision() as i64
                ],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(stored, 10_000);

        assert_eq!(
            continuable(&connection, &scope, 1, 9_999),
            vec!["work-a@1#2"]
        );
        assert!(continuable(&connection, &scope, 1, 10_000).is_empty());

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
        admit(&mut connection, &scope, &target, &[], epoch(1)).unwrap();
        assert_eq!(
            grant_at(&connection, &scope, &target, fence, 1, 1),
            Err(ApplyError::Conflict)
        );

        record_claim(&connection, &scope, &target, fence, lease, 1_000).unwrap();
        assert_eq!(
            grant_at(
                &connection,
                &scope,
                &target,
                NonZeroU64::new(9).unwrap(),
                1,
                1
            ),
            Err(ApplyError::Conflict)
        );
        grant_at(&connection, &scope, &target, fence, 1, 1).unwrap();

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
            grant_at(&connection, &scope, &target, fence, 1, 2),
            Err(ApplyError::Conflict)
        );

        // Re-admission at a newer epoch keeps the row; a superseded epoch is refused outright.
        admit(&mut connection, &scope, &target, &[], epoch(4)).unwrap();
        assert_eq!(
            admit(&mut connection, &scope, &target, &[], epoch(2)),
            Err(ApplyError::Conflict)
        );

        drop(connection);
        fs::remove_file(db_path).unwrap();
    }

    #[test]
    fn a_sibling_draw_counts_against_the_scope_reservation() {
        let (db_path, mut connection, scope) = admitted_scope("grant-sibling-budget");
        seed_active_plan(&connection, &scope, 3);
        let sibling = work("work-a", 1);
        let target = work("work-b", 1);
        let fence = NonZeroU64::new(2).unwrap();
        let lease = NonZeroU64::new(31_000).unwrap();
        let deadline = NonZeroU64::new(MAX_STORED_INTEGER).unwrap();
        admit(&mut connection, &scope, &sibling, &[], epoch(3)).unwrap();
        admit(&mut connection, &scope, &target, &[], epoch(3)).unwrap();
        record_claim(&connection, &scope, &sibling, fence, lease, 1_000).unwrap();
        record_claim(&connection, &scope, &target, fence, lease, 1_000).unwrap();

        // The reservation is scope-wide, not per revision: after the sibling draws 60 of the
        // 100 reserved units, a 41-unit grant that is fine in isolation must be refused.
        grant_bounded(&connection, &scope, &sibling, fence, 3, deadline, 1, 60).unwrap();
        assert_eq!(
            grant_bounded(&connection, &scope, &target, fence, 3, deadline, 1, 41),
            Err(ApplyError::Conflict)
        );
        // The refusal draws nothing from either revision.
        assert_eq!(granted_units(&connection, &sibling), Some(60));
        assert_eq!(granted_units(&connection, &target), None);
        // The remaining 40 units are still drawable.
        grant_bounded(&connection, &scope, &target, fence, 3, deadline, 1, 40).unwrap();
        assert_eq!(granted_units(&connection, &sibling), Some(60));
        assert_eq!(granted_units(&connection, &target), Some(40));

        drop(connection);
        fs::remove_file(db_path).unwrap();
    }

    #[test]
    fn grant_recording_refuses_every_stale_binding() {
        let (db_path, mut connection, scope) = admitted_scope("grant-refusals");
        seed_active_plan(&connection, &scope, 3);
        let target = work("work-a", 1);
        let fence = NonZeroU64::new(2).unwrap();
        let lease = NonZeroU64::new(31_000).unwrap();
        admit(&mut connection, &scope, &target, &[], epoch(3)).unwrap();
        record_claim(&connection, &scope, &target, fence, lease, 1_000).unwrap();
        let identity = |digest: &str| {
            ScopeClaimIdentity::new(
                scope.clone(),
                Digest::new(digest.into()).unwrap(),
                target.clone(),
                fence.get(),
            )
            .unwrap()
        };
        let deadline = NonZeroU64::new(MAX_STORED_INTEGER).unwrap();
        let activation =
            |scope_epoch: u64, attempt: u64, units: u64, deadline: NonZeroU64| GrantActivation {
                scope_epoch: epoch(scope_epoch),
                attempt: NonZeroU64::new(attempt).unwrap(),
                units: NonZeroU64::new(units).unwrap(),
                deadline_unix_ms: deadline,
                digest: grant_digest(fence.get(), units),
            };

        // A lease that ends at `now_ms` is already expired.
        assert_eq!(
            record_grant(
                &connection,
                &identity(DIGEST_2),
                &activation(3, 1, 1, deadline),
                31_000
            ),
            Err(ApplyError::Conflict)
        );
        // A plan the scope does not hold.
        assert_eq!(
            record_grant(
                &connection,
                &identity(DIGEST_1),
                &activation(3, 1, 1, deadline),
                1_000
            ),
            Err(ApplyError::Conflict)
        );
        // An authority epoch behind the projection is superseded.
        assert_eq!(
            record_grant(
                &connection,
                &identity(DIGEST_2),
                &activation(2, 1, 1, deadline),
                1_000
            ),
            Err(ApplyError::Conflict)
        );
        // A grant deadline beyond the admitted work deadline.
        assert_eq!(
            record_grant(
                &connection,
                &identity(DIGEST_2),
                &activation(3, 1, 1, NonZeroU64::new(MAX_STORED_INTEGER + 1).unwrap()),
                1_000
            ),
            Err(ApplyError::Conflict)
        );
        // The active plan permits three attempts; attempt 4 conflicts.
        assert_eq!(
            record_grant(
                &connection,
                &identity(DIGEST_2),
                &activation(3, 4, 1, deadline),
                1_000
            ),
            Err(ApplyError::Conflict)
        );
        // A grant deadline at `now_ms` has already passed.
        assert_eq!(
            record_grant(
                &connection,
                &identity(DIGEST_2),
                &activation(3, 1, 1, NonZeroU64::new(1_000).unwrap()),
                1_000
            ),
            Err(ApplyError::Conflict)
        );
        // The plan reserved 100 units; 101 conflicts.
        assert_eq!(
            record_grant(
                &connection,
                &identity(DIGEST_2),
                &activation(3, 1, 101, deadline),
                1_000
            ),
            Err(ApplyError::Conflict)
        );

        // An authority epoch ahead of the projection records; re-recording the identical object
        // at the same fence draws no additional units.
        record_grant(
            &connection,
            &identity(DIGEST_2),
            &activation(4, 1, 60, deadline),
            1_000,
        )
        .unwrap();
        record_grant(
            &connection,
            &identity(DIGEST_2),
            &activation(4, 1, 60, deadline),
            1_000,
        )
        .unwrap();
        assert_eq!(granted_units(&connection, &target), Some(60));

        // A different `GrantActivation` at an already-granted fence conflicts; granted units
        // remain 60.
        let rival = GrantActivation {
            digest: Digest::new(DIGEST_3.into()).unwrap(),
            ..activation(4, 1, 60, deadline)
        };
        assert_eq!(
            record_grant(&connection, &identity(DIGEST_2), &rival, 1_000),
            Err(ApplyError::Conflict)
        );
        assert_eq!(granted_units(&connection, &target), Some(60));

        // A reclaim must draw the next attempt, and 40 units remain of the reservation.
        let higher = NonZeroU64::new(3).unwrap();
        record_claim(&connection, &scope, &target, higher, lease, 31_000).unwrap();
        assert_eq!(
            grant_bounded(&connection, &scope, &target, higher, 4, deadline, 1, 40),
            Err(ApplyError::Conflict)
        );
        assert_eq!(
            grant_bounded(&connection, &scope, &target, higher, 4, deadline, 2, 41),
            Err(ApplyError::Conflict)
        );
        grant_bounded(&connection, &scope, &target, higher, 4, deadline, 2, 40).unwrap();
        assert_eq!(granted_units(&connection, &target), Some(100));

        // Three attempts are admitted, so a third fence must name attempt 3.
        let third = NonZeroU64::new(4).unwrap();
        record_claim(&connection, &scope, &target, third, lease, 31_000).unwrap();
        assert_eq!(
            grant_bounded(&connection, &scope, &target, third, 4, deadline, 2, 1),
            Err(ApplyError::Conflict)
        );

        // record_grant created no work row and wrote no terminal result.
        let (rows, terminal): (i64, i64) = connection
            .query_row(
                "SELECT (SELECT COUNT(*) FROM admitted_work), \
                 (SELECT COUNT(*) FROM admitted_work \
                    WHERE terminal_result_digest IS NOT NULL)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!((rows, terminal), (1, 0));

        drop(connection);
        fs::remove_file(db_path).unwrap();
    }

    #[test]
    fn work_offered_below_the_projected_scope_epoch_never_becomes_claimable() {
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
            admit(&mut connection, &scope, &work("work-a", 1), &[], epoch(3)),
            Err(ApplyError::Conflict)
        );
        assert!(claimable(&connection, &scope, 1_000).is_empty());

        admit(&mut connection, &scope, &work("work-a", 1), &[], epoch(5)).unwrap();
        assert_eq!(claimable(&connection, &scope, 1_000), vec!["work-a@1"]);

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
        admission_event_at_head_epoch(scope, proposal, operation, 1)
    }

    /// The event's writer epoch is 1; `head_epoch` may be higher.
    fn admission_event_at_head_epoch(
        scope: &ScopeIdentity,
        proposal: &PlanProposal,
        operation: &str,
        head_epoch: u64,
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
            head_epoch,
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
    fn plan_admission_records_everything_atomically_and_gates_scheduling() {
        let (db_path, mut connection, scope) = genesis_scope("plan-admission");
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

        // Only the dependency-free revision is claimable, and only until its deadline passes.
        assert_eq!(claimable(&connection, &scope, 1), ["work-a@1"]);
        assert_eq!(claimable(&connection, &scope, 10_000), Vec::<String>::new());
        // The admission event writes the plan digest scheduling reads.
        assert_eq!(
            stored_plan_digest(&connection, &scope, &work("work-a", 1)),
            plan_digest.as_str()
        );

        // A claimed, granted revision continues only until its deadline, though its lease is live.
        record_claim(
            &connection,
            &scope,
            &work("work-a", 1),
            epoch(1),
            epoch(20_000),
            1,
        )
        .unwrap();
        record_grant(
            &connection,
            &ScopeClaimIdentity::new(scope.clone(), plan_digest.clone(), work("work-a", 1), 1)
                .unwrap(),
            &GrantActivation {
                scope_epoch: epoch(1),
                attempt: NonZeroU64::new(1).unwrap(),
                units: NonZeroU64::new(7).unwrap(),
                deadline_unix_ms: NonZeroU64::new(9_000).unwrap(),
                digest: grant_digest(1, 7),
            },
            1,
        )
        .unwrap();
        let rows = continuable_work(&connection, &scope, epoch(1), 1).unwrap();
        assert_eq!(
            rows.iter()
                .map(|row| (
                    row.work().clone(),
                    row.claim_fence().get(),
                    row.claim_lease_until().get()
                ))
                .collect::<Vec<_>>(),
            [(work("work-a", 1), 1, 20_000)]
        );
        assert_eq!(
            continuable_work(&connection, &scope, epoch(1), 10_000).unwrap(),
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

    /// `admitted_scope_epoch` records the projected head epoch, not the event's writer epoch.
    #[test]
    fn admission_at_a_head_above_its_writer_epoch_records_the_projected_epoch() {
        let (db_path, mut connection, scope) = genesis_scope("plan-admission-epoch-lag");
        let proposal = plan_proposal(&scope, &zero_objective(), 10_000);
        let (event, plan_digest) =
            admission_event_at_head_epoch(&scope, &proposal, "admit-plan-lag", 3);

        assert_eq!(
            apply_scope_event(&mut connection, &event),
            Ok(ApplyOutcome::Applied)
        );
        assert_eq!(projected_epoch(&connection, &scope), 3);
        let admitted: Vec<(String, i64)> = connection
            .prepare("SELECT work_id, admitted_scope_epoch FROM admitted_work ORDER BY work_id")
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(
            admitted,
            [("work-a".to_owned(), 3), ("work-b".to_owned(), 3)]
        );

        // At the head that admitted it, the work is still claimable and continuable.
        assert_eq!(claimable(&connection, &scope, 1), ["work-a@1"]);
        record_claim(
            &connection,
            &scope,
            &work("work-a", 1),
            epoch(1),
            epoch(20_000),
            1,
        )
        .unwrap();
        record_grant(
            &connection,
            &ScopeClaimIdentity::new(scope.clone(), plan_digest.clone(), work("work-a", 1), 1)
                .unwrap(),
            &GrantActivation {
                scope_epoch: epoch(3),
                attempt: NonZeroU64::new(1).unwrap(),
                units: NonZeroU64::new(7).unwrap(),
                deadline_unix_ms: NonZeroU64::new(9_000).unwrap(),
                digest: grant_digest(1, 7),
            },
            1,
        )
        .unwrap();
        assert_eq!(continuable(&connection, &scope, 3, 1), ["work-a@1#1"]);

        drop(connection);
        fs::remove_file(db_path).unwrap();
    }

    #[test]
    fn validation_rejects_a_plan_pointer_without_its_admission_event() {
        let (db_path, mut connection, scope) = genesis_scope("plan-pointer-tamper");
        let proposal = plan_proposal(&scope, &zero_objective(), 10_000);
        let (event, _) = admission_event(&scope, &proposal, "admit-plan-1");
        apply_scope_event(&mut connection, &event).unwrap();
        drop(connection);
        drop(open_existing(&db_path).unwrap());

        let tampered = rusqlite::Connection::open(&db_path).unwrap();
        tampered
            .execute(
                "UPDATE scopes SET active_plan_digest = NULL, reserved_budget_units = NULL",
                [],
            )
            .unwrap();
        drop(tampered);
        assert_eq!(
            open_existing(&db_path).unwrap_err(),
            ValidateError::InvalidHistory
        );
        fs::remove_file(db_path).unwrap();
    }

    #[test]
    fn plan_admission_fails_closed_and_writes_nothing_on_rejection() {
        let (db_path, mut connection, scope) = genesis_scope("plan-admission-reject");
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
        let (db_path, mut connection, scope) = genesis_scope("plan-admission-second");
        let objective = zero_objective();
        let first = plan_proposal(&scope, &objective, 10_000);
        let (event, _) = admission_event(&scope, &first, "admit-plan-1");
        apply_scope_event(&mut connection, &event).unwrap();

        // A correctly addressed second plan passes every byte check and reaches the durable
        // refusal: the scope already holds an active plan, so the guarded UPDATE matches no row.
        // Its work rows are written before that refusal, so this also proves rollback. They name
        // work ids the first plan did not, because re-admitting a first-plan row under a second
        // plan digest is refused earlier, by the plan binding on that row.
        let mut second = plan_proposal(&scope, &objective, 20_000);
        second = PlanProposal::new(
            second.scope_id().clone(),
            objective.clone(),
            None,
            second.bases().to_vec(),
            ["work-y", "work-z"]
                .into_iter()
                .map(|id| {
                    crate::domain::proposal::WorkSpec::new(
                        WorkId::new(id.into()).unwrap(),
                        Vec::new(),
                        plan_bounds(20_000),
                    )
                })
                .collect(),
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
