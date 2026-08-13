//! The projection file is disposable: one neutral application id rejects unrelated files,
//! and a file that fails validation is rebuilt from durable history rather than migrated.
//! It persists only unowned epoch-1, plan-stable histories, so the first epoch or plan
//! transition must relax this schema.

use std::{error::Error, fmt, path::Path};

use rusqlite::{OpenFlags, OptionalExtension, params};

use crate::{
    domain::validation::ValidationError,
    scope::{
        Digest, EventEnvelope, ScopeEventRef, ScopeHead, ScopeIdentity, payload_type_registered,
    },
};

// "RAVL": rejects an unrelated SQLite file without naming a protocol era.
const APPLICATION_ID: i32 = 0x5241_564c;
const TABLES: [&str; 2] = ["applied_scope_events", "scopes"];

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
    CHECK (length(scope_id) = 64 AND length(CAST(scope_id AS BLOB)) = 64
        AND scope_id NOT GLOB '*[^0-9a-f]*'),
    CHECK (length(CAST(campaign_id AS BLOB)) BETWEEN 1 AND 128
        AND campaign_id NOT LIKE '%/%'),
    CHECK (parent_scope_id IS NULL),
    CHECK (delegation_digest IS NULL),
    CHECK (sequence BETWEEN 1 AND 9999999999999999),
    CHECK (length(tail_event_digest) = 64
        AND length(CAST(tail_event_digest AS BLOB)) = 64
        AND tail_event_digest NOT GLOB '*[^0-9a-f]*'),
    CHECK (active_plan_digest IS NULL),
    CHECK (scope_epoch = 1)
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
        AND operation_id NOT LIKE '%/%'),
    CHECK (writer_epoch > 0),
    CHECK (length(CAST(payload_type AS BLOB)) BETWEEN 1 AND 128
        AND payload_type NOT LIKE '%/%'),
    CHECK ((sequence = 1 AND payload_type = 'root_genesis'
            AND operation_id = 'root-genesis:' || scope_id)
        OR (sequence > 1 AND payload_type <> 'root_genesis'))
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
    DatabaseOperationFailed,
}

impl fmt::Display for ApplyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Conflict => "scope event conflicts with local projection state",
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ScopeProjectionEvent {
    scope: ScopeIdentity,
    envelope: EventEnvelope,
    reference: ScopeEventRef,
    active_plan_digest: Option<Digest>,
    scope_epoch: u64,
}

impl ScopeProjectionEvent {
    pub(crate) fn new(
        scope: ScopeIdentity,
        envelope: EventEnvelope,
        reference: ScopeEventRef,
        active_plan_digest: Option<Digest>,
        scope_epoch: u64,
    ) -> Result<Self, ValidationError> {
        if envelope.scope_id() != scope.scope_id()
            || envelope.sequence() != reference.sequence()
            || envelope.writer_epoch().get() != scope_epoch
            || scope_epoch != 1
            || active_plan_digest.is_some()
        {
            return Err(ValidationError::InvalidIdentity);
        }
        Ok(Self {
            scope,
            envelope,
            reference,
            active_plan_digest,
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
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_URI,
    )
    .map_err(|_| ValidateError::DatabaseOperationFailed)?;
    connection
        .pragma_update(None, "foreign_keys", true)
        .map_err(|_| ValidateError::DatabaseOperationFailed)?;
    validate(&connection)?;
    Ok(connection)
}

pub(crate) fn scope_cursor(
    connection: &rusqlite::Connection,
    scope: &ScopeIdentity,
) -> Result<(u64, Option<Digest>), ApplyError> {
    let stored: Option<(String, i64, String)> = connection
        .query_row(
            "SELECT campaign_id, sequence, tail_event_digest FROM scopes WHERE scope_id = ?1",
            [scope.scope_id().as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    match stored {
        None => Ok((0, None)),
        Some((campaign_id, sequence, digest)) => {
            if campaign_id != scope.campaign_id().as_str() {
                return Err(ApplyError::Conflict);
            }
            Ok((
                u64::try_from(sequence).map_err(|_| ApplyError::DatabaseOperationFailed)?,
                Some(Digest::new(digest).map_err(|_| ApplyError::Conflict)?),
            ))
        }
    }
}

pub(crate) fn scope_contains_operation(
    connection: &rusqlite::Connection,
    scope: &ScopeIdentity,
    operation_id: &str,
) -> Result<bool, ApplyError> {
    connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM applied_scope_events \
             WHERE scope_id = ?1 AND operation_id = ?2)",
            params![scope.scope_id().as_str(), operation_id],
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
            "SELECT scope.campaign_id, scope.sequence, scope.tail_event_digest, \
             scope.active_plan_digest, scope.scope_epoch, event.operation_id \
             FROM scopes AS scope \
             JOIN applied_scope_events AS event \
               ON event.scope_id = scope.scope_id AND event.sequence = scope.sequence \
             WHERE scope.scope_id = ?1",
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
                && u64::try_from(epoch).ok() == Some(head.scope_epoch().get())
                && operation == head.operation_id()
        }),
    )
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
            "SELECT digest FROM applied_scope_events WHERE scope_id = ?1 AND sequence = ?2",
            params![scope_id, stored_sequence],
            |row| row.get(0),
        )
        .optional()?;
    let current: Option<(String, i64, String, Option<String>, i64)> = transaction
        .query_row(
            "SELECT campaign_id, sequence, tail_event_digest, active_plan_digest, scope_epoch \
             FROM scopes WHERE scope_id = ?1",
            [scope_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .optional()?;

    if let Some((_, cursor, tail, _, _)) = &current {
        let recorded_tail: Option<String> = transaction
            .query_row(
                "SELECT digest FROM applied_scope_events WHERE scope_id = ?1 AND sequence = ?2",
                params![scope_id, cursor],
                |row| row.get(0),
            )
            .optional()?;
        if recorded_tail.as_deref() != Some(tail) {
            return Err(ApplyError::Conflict);
        }
    } else if historical.is_some() {
        return Err(ApplyError::Conflict);
    }
    if let Some(digest) = historical {
        return if digest == event.reference.digest().as_str() {
            Ok(ApplyOutcome::AlreadyApplied)
        } else {
            Err(ApplyError::Conflict)
        };
    }

    let parent_digest = event
        .envelope
        .parent_event()
        .map(|parent| parent.digest().as_str());
    match current {
        None => {
            if sequence != 1 || parent_digest.is_some() {
                return Err(ApplyError::Conflict);
            }
            transaction.execute(
                "INSERT INTO scopes (scope_id, campaign_id, parent_scope_id, delegation_digest, \
                 sequence, tail_event_digest, active_plan_digest, scope_epoch) \
                 VALUES (?1, ?2, NULL, NULL, ?3, ?4, ?5, ?6)",
                params![
                    scope_id,
                    event.scope.campaign_id().as_str(),
                    stored_sequence,
                    event.reference.digest().as_str(),
                    event.active_plan_digest.as_ref().map(Digest::as_str),
                    i64::try_from(event.scope_epoch)
                        .map_err(|_| ApplyError::DatabaseOperationFailed)?,
                ],
            )?;
        }
        Some((campaign_id, cursor, tail, active_plan, scope_epoch)) => {
            if campaign_id != event.scope.campaign_id().as_str()
                || cursor.checked_add(1) != Some(stored_sequence)
                || parent_digest != Some(tail.as_str())
                || active_plan.as_deref() != event.active_plan_digest.as_ref().map(Digest::as_str)
                || u64::try_from(scope_epoch).ok() != Some(event.scope_epoch)
            {
                return Err(ApplyError::Conflict);
            }
            let updated = transaction.execute(
                "UPDATE scopes SET sequence = ?1, tail_event_digest = ?2 WHERE scope_id = ?3",
                params![stored_sequence, event.reference.digest().as_str(), scope_id],
            )?;
            if updated != 1 {
                return Err(ApplyError::DatabaseOperationFailed);
            }
        }
    }

    let duplicate: bool = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM applied_scope_events \
         WHERE scope_id = ?1 AND (digest = ?2 OR operation_id = ?3))",
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
    connection.pragma_update_and_check(None, "journal_mode", "DELETE", |row| {
        row.get::<_, String>(0)
    })?;
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
    validate_schema(connection)?;
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

fn is_blank(connection: &rusqlite::Connection) -> bool {
    connection
        .query_row(
            "SELECT COUNT(*) = 0 FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
            [],
            |row| row.get(0),
        )
        .unwrap_or(false)
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
                OR (event.sequence > 1 AND (parent.digest IS NULL OR parent.digest != event.parent_digest))",
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
                 AND event.writer_epoch != scope.scope_epoch)",
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
            None,
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
}
