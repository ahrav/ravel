//! Fixed schema for a disposable local SQLite projection.
//!
//! S3 is the durable authority. Schema version 2 comprises seven logical tables without
//! migration history, and the `RVL1` application id identifies this database format.
//! `sync_cursor` holds one row, in one of two shapes: the genesis pairing of sequence 0 with a
//! null digest, or a durable sequence paired with 64 lowercase hexadecimal digest characters.
//! One database projects one campaign chain, so workflows need no campaign identity column.

use std::{error::Error, fmt, path::Path};

use rusqlite::OpenFlags;

const APPLICATION_ID: i32 = 0x5256_4c31; // "RVL1"
const SCHEMA_VERSION: i32 = 2;

const PROJECTION_TABLES: [&str; 7] = [
    "applied_events",
    "campaigns",
    "dependencies",
    "objectives",
    "sync_cursor",
    "work_items",
    "workflows",
];

const SCHEMA: &str = "
CREATE TABLE applied_events (
    sequence INTEGER PRIMARY KEY,
    digest TEXT NOT NULL UNIQUE
) STRICT, WITHOUT ROWID;

CREATE TABLE sync_cursor (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    sequence INTEGER NOT NULL,
    tail_digest TEXT,
    CHECK (
        (sequence = 0 AND tail_digest IS NULL)
        OR (
            sequence BETWEEN 1 AND 9999999999999999
            AND tail_digest IS NOT NULL
            AND length(tail_digest) = 64
            AND length(CAST(tail_digest AS BLOB)) = 64
            AND tail_digest NOT GLOB '*[^0-9a-f]*'
        )
    )
) STRICT;

CREATE TRIGGER sync_cursor_is_singleton
BEFORE DELETE ON sync_cursor
BEGIN
    SELECT RAISE(ABORT, 'sync_cursor holds exactly one row');
END;

CREATE TABLE campaigns (
    campaign_id TEXT PRIMARY KEY NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('active', 'completed'))
) STRICT;

CREATE TABLE objectives (
    objective_id TEXT PRIMARY KEY NOT NULL
) STRICT;

CREATE TABLE workflows (
    workflow_id TEXT PRIMARY KEY NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('active', 'completed'))
) STRICT;

CREATE TABLE work_items (
    work_id TEXT PRIMARY KEY NOT NULL,
    workflow_id TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('ready', 'done', 'cancelled')),
    budget_remaining INTEGER NOT NULL CHECK (budget_remaining >= 0),
    required_capabilities TEXT NOT NULL
) STRICT;

CREATE TABLE dependencies (
    work_id TEXT NOT NULL,
    depends_on_work_id TEXT NOT NULL,
    PRIMARY KEY (work_id, depends_on_work_id)
) STRICT;
";

/// Failure while creating or checking the projection schema.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SchemaError {
    /// Opening, initializing, or integrity-checking the database failed.
    DatabaseOperationFailed,
    /// The database did not report a successful integrity check.
    IntegrityCheckFailed,
}

impl fmt::Display for SchemaError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::DatabaseOperationFailed => "database operation failed",
            Self::IntegrityCheckFailed => "database integrity check failed",
        })
    }
}

impl Error for SchemaError {}

/// `ValidateError` reports failures while validating an existing disposable projection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ValidateError {
    DatabaseOperationFailed,
    WrongApplicationId,
    WrongSchemaVersion,
    IntegrityCheckFailed,
    InvalidHistory,
}

impl fmt::Display for ValidateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::DatabaseOperationFailed => "database operation failed",
            Self::WrongApplicationId => "database application id does not match",
            Self::WrongSchemaVersion => "database schema version does not match",
            Self::IntegrityCheckFailed => "database integrity check failed",
            Self::InvalidHistory => "database history is invalid",
        })
    }
}

impl Error for ValidateError {}

/// Creates the fixed projection schema at `path` and verifies its integrity.
///
/// Creation requires a path that does not already hold this schema; this function neither
/// validates nor rebuilds an existing projection. SQLite honors its reserved filenames,
/// `:memory:` and `file:` URIs among them, rather than rejecting them. Creation sets
/// `journal_mode=DELETE` on a database it accepts; busy handling and connection ownership stay
/// with the caller.
///
/// # Errors
///
/// Returns [`SchemaError::DatabaseOperationFailed`] when SQLite cannot open the database,
/// initialize it, or run the integrity check, including when the file already holds any
/// objects at all rather than only when these table names collide.
/// Returns [`SchemaError::IntegrityCheckFailed`] when `PRAGMA quick_check` does not return `ok`.
pub fn create(path: impl AsRef<Path>) -> Result<rusqlite::Connection, SchemaError> {
    let connection = initialize(path.as_ref()).map_err(|_| SchemaError::DatabaseOperationFailed)?;
    let integrity: String = connection
        .query_row("PRAGMA quick_check", [], |row| row.get(0))
        .map_err(|_| SchemaError::DatabaseOperationFailed)?;
    if integrity != "ok" {
        return Err(SchemaError::IntegrityCheckFailed);
    }

    Ok(connection)
}

/// Opens an existing projection only when its format, integrity, and event history agree.
///
/// The schema has no foreign keys, so validation has no foreign-key check.
///
/// # Errors
///
/// Returns [`ValidateError`] for an unreadable database, a format mismatch, a failed
/// `quick_check`, or cursor and applied-event history that do not form one contiguous prefix.
pub(crate) fn open_existing(path: impl AsRef<Path>) -> Result<rusqlite::Connection, ValidateError> {
    let connection = rusqlite::Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_URI,
    )
    .map_err(|_| ValidateError::DatabaseOperationFailed)?;

    // A truncated or non-SQLite file opens successfully and then fails these
    // pragmas with SQLITE_NOTADB or a corruption code rather than a mismatched id,
    // which is a local format failure the caller repairs by rebuilding.
    let application_id: i32 = connection
        .pragma_query_value(None, "application_id", |row| row.get(0))
        .map_err(local_format_error)?;
    if application_id != APPLICATION_ID {
        return Err(ValidateError::WrongApplicationId);
    }
    let schema_version: i32 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(local_format_error)?;
    if schema_version != SCHEMA_VERSION {
        return Err(ValidateError::WrongSchemaVersion);
    }
    let integrity: String = connection
        .query_row("PRAGMA quick_check", [], |row| row.get(0))
        .map_err(local_format_error)?;
    if integrity != "ok" {
        return Err(ValidateError::IntegrityCheckFailed);
    }

    let cursor = {
        let mut statement = connection
            .prepare("SELECT id, sequence, tail_digest FROM sync_cursor")
            .map_err(local_format_error)?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Option<String>>(2)?,
                ))
            })
            .map_err(local_format_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(local_format_error)?;
        match rows.as_slice() {
            [cursor] => cursor.clone(),
            _ => return Err(ValidateError::InvalidHistory),
        }
    };
    let (id, stored_sequence, tail_digest) = cursor;
    let sequence = u64::try_from(stored_sequence).map_err(|_| ValidateError::InvalidHistory)?;
    if id != 1 || !valid_cursor(sequence, tail_digest.as_deref()) {
        return Err(ValidateError::InvalidHistory);
    }

    let (count, minimum, maximum): (i64, Option<i64>, Option<i64>) = connection
        .query_row(
            "SELECT COUNT(*), MIN(sequence), MAX(sequence) FROM applied_events",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(local_format_error)?;
    // Every retained digest is checked, not only the cursor's tail: a malformed
    // row below the tail cannot have come from the immutable event chain.
    let malformed: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM applied_events \
             WHERE typeof(digest) != 'text' \
                OR length(digest) != 64 \
                OR length(CAST(digest AS BLOB)) != 64 \
                OR digest GLOB '*[^0-9a-f]*'",
            [],
            |row| row.get(0),
        )
        .map_err(local_format_error)?;
    if malformed != 0 {
        return Err(ValidateError::InvalidHistory);
    }
    if sequence == 0 {
        if count != 0 || minimum.is_some() || maximum.is_some() {
            return Err(ValidateError::InvalidHistory);
        }
    } else {
        let expected = i64::try_from(sequence).map_err(|_| ValidateError::InvalidHistory)?;
        if count != expected || minimum != Some(1) || maximum != Some(expected) {
            return Err(ValidateError::InvalidHistory);
        }
        let applied_tail: String = connection
            .query_row(
                "SELECT digest FROM applied_events WHERE sequence = ?1",
                [expected],
                |row| row.get(0),
            )
            .map_err(local_format_error)?;
        if tail_digest.as_deref() != Some(applied_tail.as_str()) {
            return Err(ValidateError::InvalidHistory);
        }
    }

    // A valid cursor and history do not imply the rest of the projection survived.
    // Names alone do not either: a table present with different columns or dropped
    // constraints would serve reads that cannot come from the event chain.
    let mut definitions = {
        let mut stored = connection
            .prepare("SELECT name, sql, type FROM sqlite_schema WHERE sql IS NOT NULL")
            .map_err(local_format_error)?;
        stored
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .map_err(local_format_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(local_format_error)?
    };
    definitions.retain(|(name, _, _)| !name.starts_with("sqlite_"));
    let (tables, others): (Vec<_>, Vec<_>) = definitions
        .into_iter()
        .partition(|(_, _, kind)| kind == "table");
    if tables.len() != PROJECTION_TABLES.len() {
        return Err(ValidateError::InvalidHistory);
    }
    for (name, sql, _) in &tables {
        let expected = expected_definition(name).ok_or(ValidateError::InvalidHistory)?;
        if normalized(sql) != normalized(expected) {
            return Err(ValidateError::InvalidHistory);
        }
    }
    // The fixed schema declares exactly one non-table object: the cursor-singleton
    // trigger. Any other trigger, view, or index is a schema this projection never
    // creates and could alter reads or abort applies.
    match others.as_slice() {
        [(_, sql, kind)]
            if kind == "trigger" && normalized(sql) == normalized(expected_trigger()) => {}
        _ => return Err(ValidateError::InvalidHistory),
    }

    Ok(connection)
}

/// Recovers the one `CREATE TRIGGER` statement this schema declares.
fn expected_trigger() -> &'static str {
    let start = SCHEMA
        .find("CREATE TRIGGER")
        .expect("schema declares the cursor-singleton trigger");
    let length = SCHEMA[start..]
        .find("END")
        .expect("trigger body terminates")
        + "END".len();
    &SCHEMA[start..start + length]
}

/// Recovers the `CREATE TABLE` statement this schema declares for `table`.
fn expected_definition(table: &str) -> Option<&'static str> {
    SCHEMA.split(';').map(str::trim).find(|statement| {
        statement
            .strip_prefix("CREATE TABLE ")
            .is_some_and(|rest| rest.starts_with(table) && rest[table.len()..].starts_with(" ("))
    })
}

/// Collapses the whitespace SQLite preserves verbatim in `sqlite_schema.sql`.
fn normalized(sql: &str) -> String {
    sql.split_whitespace().collect::<Vec<_>>().join(" ")
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
        _ => ValidateError::InvalidHistory,
    }
}

fn valid_cursor(sequence: u64, digest: Option<&str>) -> bool {
    match (sequence, digest) {
        (0, None) => true,
        (1..=9_999_999_999_999_999, Some(digest)) => {
            digest.len() == 64
                && digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        }
        _ => false,
    }
}

/// Creates the schema, versions, and genesis cursor as one committed transaction.
fn initialize(path: &Path) -> rusqlite::Result<rusqlite::Connection> {
    let mut connection = rusqlite::Connection::open(path)?;
    // Leaving WAL rewrites the database header and no rollback undoes it, so refuse a database
    // that already holds objects before reconfiguring its journal mode. The in-transaction check
    // below still closes the concurrent-writer window.
    if connection.query_row("SELECT count(*) FROM sqlite_schema", [], |row| {
        row.get::<_, i64>(0)
    })? != 0
    {
        return Err(rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_CONSTRAINT),
            Some("database is not empty".into()),
        ));
    }
    // Configure rollback journaling before any schema write so the first commit
    // never runs in a non-DELETE compile-time default mode (e.g. a WAL default),
    // which could leave sidecar files behind on an early crash.
    connection.pragma_update_and_check(None, "journal_mode", "DELETE", |row| {
        row.get::<_, String>(0)
    })?;
    let transaction = connection.transaction()?;
    // Stamping RVL1 onto a database that already holds unrelated objects would
    // produce a mixed file that passes quick_check while not being this schema.
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
    transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    transaction.execute(
        "INSERT INTO sync_cursor (id, sequence, tail_digest) VALUES (1, 0, NULL)",
        [],
    )?;
    transaction.commit()?;
    Ok(connection)
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf, process};

    use rusqlite::{ErrorCode, params};

    use super::*;

    const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const OTHER_DIGEST: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

    fn test_path(label: &str) -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("ravel-schema-{}-{label}.sqlite3", process::id()));
        let _ = fs::remove_file(&path);
        path
    }

    fn cursor_rows(connection: &rusqlite::Connection) -> Vec<(i64, i64, Option<String>)> {
        connection
            .prepare("SELECT id, sequence, tail_digest FROM sync_cursor")
            .unwrap()
            .query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Option<String>>(2)?,
                ))
            })
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    }

    fn assert_constraint(result: Result<usize, rusqlite::Error>) {
        let error = result.unwrap_err();
        let rusqlite::Error::SqliteFailure(error, _) = error else {
            panic!("expected SQLite failure, got {error:?}");
        };
        assert_eq!(error.code, ErrorCode::ConstraintViolation);
    }

    #[test]
    fn creates_expected_schema_and_genesis_cursor() {
        let path = test_path("creation");
        let connection = create(&path).unwrap();

        assert_eq!(
            connection
                .pragma_query_value(None, "application_id", |row| row.get::<_, i32>(0))
                .unwrap(),
            APPLICATION_ID
        );
        assert_eq!(
            connection
                .pragma_query_value(None, "user_version", |row| row.get::<_, i32>(0))
                .unwrap(),
            SCHEMA_VERSION
        );

        assert_eq!(cursor_rows(&connection), [(1, 0, None)]);

        assert_eq!(
            connection
                .query_row::<String, _, _>("PRAGMA quick_check", [], |row| row.get(0))
                .unwrap(),
            "ok"
        );

        let mut tables = connection
            .prepare(
                "SELECT name FROM sqlite_schema \
                 WHERE type IN ('table', 'view') AND name NOT LIKE 'sqlite_%'",
            )
            .unwrap()
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        tables.sort();
        assert_eq!(
            tables,
            [
                "applied_events",
                "campaigns",
                "dependencies",
                "objectives",
                "sync_cursor",
                "work_items",
                "workflows",
            ]
        );

        let columns = |table: &str| {
            connection
                .prepare(&format!("PRAGMA table_info({table})"))
                .unwrap()
                .query_map([], |row| row.get::<_, String>(1))
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap()
        };
        assert_eq!(columns("applied_events"), ["sequence", "digest"]);
        assert_eq!(columns("campaigns"), ["campaign_id", "state"]);
        assert_eq!(columns("workflows"), ["workflow_id", "state"]);
        assert_eq!(
            columns("work_items"),
            [
                "work_id",
                "workflow_id",
                "state",
                "budget_remaining",
                "required_capabilities",
            ]
        );

        drop(connection);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn rejects_invalid_cursor_rows() {
        let path = test_path("cursor-constraints");
        let connection = create(&path).unwrap();

        assert_constraint(connection.execute(
            "INSERT INTO sync_cursor (id, sequence, tail_digest) VALUES (2, 0, NULL)",
            [],
        ));
        assert_constraint(connection.execute(
            "UPDATE sync_cursor SET sequence = 1, tail_digest = NULL WHERE id = 1",
            [],
        ));
        assert_constraint(connection.execute(
            "UPDATE sync_cursor SET sequence = 0, tail_digest = ?1 WHERE id = 1",
            [DIGEST],
        ));
        assert_constraint(connection.execute(
            "UPDATE sync_cursor SET sequence = 1, tail_digest = ?1 WHERE id = 1",
            [&DIGEST[..63]],
        ));
        assert_constraint(connection.execute(
            "UPDATE sync_cursor SET sequence = 1, tail_digest = ?1 WHERE id = 1",
            [&DIGEST.to_uppercase()],
        ));
        for out_of_range in [-1_i64, 10_000_000_000_000_000] {
            assert_constraint(connection.execute(
                "UPDATE sync_cursor SET sequence = ?1, tail_digest = ?2 WHERE id = 1",
                params![out_of_range, DIGEST],
            ));
        }
        assert_eq!(cursor_rows(&connection), [(1, 0, None)]);

        // An accepted sequence-1 advance proves the CHECK retains its non-genesis branch.
        assert_eq!(
            connection
                .execute(
                    "UPDATE sync_cursor SET sequence = 1, tail_digest = ?1 WHERE id = 1",
                    [DIGEST],
                )
                .unwrap(),
            1
        );
        assert_eq!(cursor_rows(&connection), [(1, 1, Some(DIGEST.to_owned()))]);

        // STRICT rejects a REAL `sequence` and a BLOB `tail_digest` that pass the
        // CHECK constraints.
        assert_constraint(connection.execute(
            "UPDATE sync_cursor SET sequence = 1.5, tail_digest = ?1 WHERE id = 1",
            [DIGEST],
        ));
        assert_constraint(connection.execute(
            "UPDATE sync_cursor SET sequence = 1, tail_digest = ?1 WHERE id = 1",
            [DIGEST.as_bytes()],
        ));
        assert_eq!(cursor_rows(&connection), [(1, 1, Some(DIGEST.to_owned()))]);

        drop(connection);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn refuses_a_database_that_already_holds_objects() {
        let path = test_path("non-empty");
        let foreign = rusqlite::Connection::open(&path).unwrap();
        foreign
            .pragma_update_and_check(None, "journal_mode", "WAL", |row| row.get::<_, String>(0))
            .unwrap();
        foreign
            .execute("CREATE TABLE unrelated (id INTEGER PRIMARY KEY)", [])
            .unwrap();
        drop(foreign);

        assert_eq!(
            create(&path).err(),
            Some(SchemaError::DatabaseOperationFailed)
        );

        let inspect = rusqlite::Connection::open(&path).unwrap();
        // Journal mode lives in the database header, so a refused create that reconfigured it
        // would leave this unrelated database permanently converted out of WAL.
        assert_eq!(
            inspect
                .pragma_query_value(None, "journal_mode", |row| row.get::<_, String>(0))
                .unwrap(),
            "wal"
        );
        assert_eq!(
            inspect
                .pragma_query_value(None, "application_id", |row| row.get::<_, i32>(0))
                .unwrap(),
            0
        );
        assert_eq!(
            inspect
                .query_row::<i64, _, _>(
                    "SELECT count(*) FROM sqlite_schema WHERE name = 'sync_cursor'",
                    [],
                    |row| row.get(0)
                )
                .unwrap(),
            0
        );

        drop(inspect);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn the_cursor_row_cannot_be_deleted() {
        let path = test_path("cursor-singleton");
        let connection = create(&path).unwrap();

        let error = connection
            .execute("DELETE FROM sync_cursor WHERE id = 1", [])
            .unwrap_err();
        assert!(
            matches!(error, rusqlite::Error::SqliteFailure(_, Some(ref m)) if m.contains("exactly one row")),
            "unexpected error: {error:?}"
        );
        assert_eq!(cursor_rows(&connection), [(1, 0, None)]);

        drop(connection);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn a_cursor_digest_hiding_bytes_after_a_nul_is_rejected() {
        let path = test_path("cursor-nul-digest");
        let connection = create(&path).unwrap();

        // length() and GLOB both stop at the NUL, so only the byte length sees the rest.
        let smuggled = format!("{DIGEST}\0trailing");
        assert_constraint(connection.execute(
            "UPDATE sync_cursor SET sequence = 1, tail_digest = ?1 WHERE id = 1",
            [&smuggled],
        ));
        assert_eq!(cursor_rows(&connection), [(1, 0, None)]);

        drop(connection);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn rejects_duplicate_identities_and_edges() {
        let path = test_path("identity-constraints");
        let connection = create(&path).unwrap();

        for (insert, insert_null) in [
            (
                "INSERT INTO campaigns (campaign_id, state) VALUES ('id', 'active')",
                "INSERT INTO campaigns (campaign_id, state) VALUES (NULL, 'active')",
            ),
            (
                "INSERT INTO objectives (objective_id) VALUES ('id')",
                "INSERT INTO objectives (objective_id) VALUES (NULL)",
            ),
            (
                "INSERT INTO workflows (workflow_id, state) VALUES ('id', 'active')",
                "INSERT INTO workflows (workflow_id, state) VALUES (NULL, 'active')",
            ),
            (
                "INSERT INTO work_items \
                 (work_id, workflow_id, state, budget_remaining, required_capabilities) \
                 VALUES ('id', 'workflow', 'ready', 1, '')",
                "INSERT INTO work_items \
                 (work_id, workflow_id, state, budget_remaining, required_capabilities) \
                 VALUES (NULL, 'workflow', 'ready', 1, '')",
            ),
        ] {
            connection.execute(insert, []).unwrap();
            assert_constraint(connection.execute(insert, []));
            // STRICT makes PRIMARY KEY columns implicitly NOT NULL, so the explicit clause
            // is belt-and-braces should STRICT ever be dropped.
            assert_constraint(connection.execute(insert_null, []));
        }
        for invalid in [
            "INSERT INTO campaigns (campaign_id, state) VALUES ('bad-campaign', 'paused')",
            "INSERT INTO workflows (workflow_id, state) VALUES ('bad-workflow', 'paused')",
            "INSERT INTO work_items \
             (work_id, workflow_id, state, budget_remaining, required_capabilities) \
             VALUES ('bad-state', 'workflow', 'blocked', 1, '')",
            "INSERT INTO work_items \
             (work_id, workflow_id, state, budget_remaining, required_capabilities) \
             VALUES ('bad-budget', 'workflow', 'ready', -1, '')",
        ] {
            assert_constraint(connection.execute(invalid, []));
        }

        connection
            .execute(
                "INSERT INTO applied_events (sequence, digest) VALUES (?1, ?2)",
                params![1, DIGEST],
            )
            .unwrap();
        assert_constraint(connection.execute(
            "INSERT INTO applied_events (sequence, digest) VALUES (?1, ?2)",
            params![1, OTHER_DIGEST],
        ));
        assert_constraint(connection.execute(
            "INSERT INTO applied_events (sequence, digest) VALUES (?1, ?2)",
            params![2, DIGEST],
        ));
        assert_constraint(connection.execute(
            "INSERT INTO applied_events (sequence, digest) VALUES (2, NULL)",
            [],
        ));
        // WITHOUT ROWID stops `sequence` from aliasing the rowid, so a missing or
        // NULL sequence is rejected instead of being auto-generated.
        assert_constraint(connection.execute(
            "INSERT INTO applied_events (digest) VALUES (?1)",
            [OTHER_DIGEST],
        ));
        assert_constraint(connection.execute(
            "INSERT INTO applied_events (sequence, digest) VALUES (NULL, ?1)",
            [OTHER_DIGEST],
        ));
        // STRICT rejects storage classes outside the declared column types.
        assert_constraint(connection.execute(
            "INSERT INTO applied_events (sequence, digest) VALUES (2.5, ?1)",
            [OTHER_DIGEST],
        ));

        connection
            .execute(
                "INSERT INTO dependencies (work_id, depends_on_work_id) VALUES ('work', 'dependency')",
                [],
            )
            .unwrap();
        assert_constraint(connection.execute(
            "INSERT INTO dependencies (work_id, depends_on_work_id) VALUES ('work', 'dependency')",
            [],
        ));
        // STRICT makes both PRIMARY KEY columns implicitly NOT NULL, so these rows are
        // rejected before the UNIQUE index compares them; the explicit clauses are
        // belt-and-braces should STRICT ever be dropped.
        for null_edge in [
            "INSERT INTO dependencies (work_id, depends_on_work_id) VALUES (NULL, 'dependency')",
            "INSERT INTO dependencies (work_id, depends_on_work_id) VALUES ('work', NULL)",
        ] {
            assert_constraint(connection.execute(null_edge, []));
        }

        assert_eq!(
            connection
                .query_row("SELECT count(*) FROM applied_events", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
            1
        );
        assert_eq!(
            connection
                .query_row("SELECT count(*) FROM dependencies", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
            1
        );

        drop(connection);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn opens_fresh_existing_projection() {
        let path = test_path("open-existing");
        drop(create(&path).unwrap());
        let connection = open_existing(&path).unwrap();
        assert_eq!(cursor_rows(&connection), [(1, 0, None)]);
        drop(connection);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn rejects_existing_format_and_integrity_mismatches() {
        for (label, pragma, value, expected) in [
            (
                "wrong-application",
                "application_id",
                0,
                ValidateError::WrongApplicationId,
            ),
            (
                "wrong-version",
                "user_version",
                99,
                ValidateError::WrongSchemaVersion,
            ),
        ] {
            let path = test_path(label);
            let connection = create(&path).unwrap();
            connection.pragma_update(None, pragma, value).unwrap();
            drop(connection);
            assert_eq!(open_existing(&path).unwrap_err(), expected);
            fs::remove_file(path).unwrap();
        }

        let path = test_path("quick-check");
        let connection = create(&path).unwrap();
        connection
            .pragma_update(None, "ignore_check_constraints", true)
            .unwrap();
        connection
            .execute("UPDATE sync_cursor SET id = 2 WHERE id = 1", [])
            .unwrap();
        connection
            .pragma_update(None, "ignore_check_constraints", false)
            .unwrap();
        drop(connection);
        assert_eq!(
            open_existing(&path).unwrap_err(),
            ValidateError::IntegrityCheckFailed
        );
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn rejects_missing_gapped_and_mismatched_history() {
        let path = test_path("missing-cursor");
        let connection = create(&path).unwrap();
        // The singleton trigger guards production deletes; bypass and restore it so
        // the only deviation this case validates is the missing cursor row.
        connection
            .execute("DROP TRIGGER sync_cursor_is_singleton", [])
            .unwrap();
        connection.execute("DELETE FROM sync_cursor", []).unwrap();
        connection.execute(expected_trigger(), []).unwrap();
        drop(connection);
        assert_eq!(
            open_existing(&path).unwrap_err(),
            ValidateError::InvalidHistory
        );
        fs::remove_file(path).unwrap();

        let path = test_path("gapped-history");
        let connection = create(&path).unwrap();
        connection
            .execute(
                "INSERT INTO applied_events (sequence, digest) VALUES (2, ?1)",
                [DIGEST],
            )
            .unwrap();
        connection
            .execute(
                "UPDATE sync_cursor SET sequence = 2, tail_digest = ?1 WHERE id = 1",
                [DIGEST],
            )
            .unwrap();
        drop(connection);
        assert_eq!(
            open_existing(&path).unwrap_err(),
            ValidateError::InvalidHistory
        );
        fs::remove_file(path).unwrap();

        let path = test_path("tail-mismatch");
        let connection = create(&path).unwrap();
        connection
            .execute(
                "INSERT INTO applied_events (sequence, digest) VALUES (1, ?1)",
                [DIGEST],
            )
            .unwrap();
        connection
            .execute(
                "UPDATE sync_cursor SET sequence = 1, tail_digest = ?1 WHERE id = 1",
                [OTHER_DIGEST],
            )
            .unwrap();
        drop(connection);
        assert_eq!(
            open_existing(&path).unwrap_err(),
            ValidateError::InvalidHistory
        );
        fs::remove_file(path).unwrap();

        let path = test_path("zero-sequence-history");
        let connection = create(&path).unwrap();
        connection
            .execute(
                "INSERT INTO applied_events (sequence, digest) VALUES (0, ?1), (2, ?2)",
                params![OTHER_DIGEST, DIGEST],
            )
            .unwrap();
        connection
            .execute(
                "UPDATE sync_cursor SET sequence = 2, tail_digest = ?1 WHERE id = 1",
                [DIGEST],
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
    fn rejects_a_malformed_digest_below_the_cursor_tail() {
        let path = test_path("malformed-interior-digest");
        let connection = create(&path).unwrap();
        connection
            .execute(
                "INSERT INTO applied_events (sequence, digest) VALUES (1, ?1), (2, ?2)",
                params![DIGEST.to_uppercase(), OTHER_DIGEST],
            )
            .unwrap();
        connection
            .execute(
                "UPDATE sync_cursor SET sequence = 2, tail_digest = ?1 WHERE id = 1",
                [OTHER_DIGEST],
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
    fn a_missing_projection_table_is_rebuildable_rather_than_unavailable() {
        for table in ["applied_events", "campaigns", "workflows", "dependencies"] {
            let path = test_path(&format!("dropped-{table}"));
            let connection = create(&path).unwrap();
            connection
                .execute(&format!("DROP TABLE {table}"), [])
                .unwrap();
            drop(connection);

            assert_eq!(
                open_existing(&path).unwrap_err(),
                ValidateError::InvalidHistory,
                "dropped {table}"
            );
            fs::remove_file(path).unwrap();
        }
    }

    #[test]
    fn a_table_with_the_right_name_and_wrong_shape_is_rebuildable() {
        let path = test_path("reshaped-table");
        let connection = create(&path).unwrap();
        connection.execute("DROP TABLE campaigns", []).unwrap();
        connection
            .execute("CREATE TABLE campaigns (id TEXT)", [])
            .unwrap();
        drop(connection);

        assert_eq!(
            open_existing(&path).unwrap_err(),
            ValidateError::InvalidHistory
        );
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn an_unexpected_schema_object_is_rebuildable() {
        let path = test_path("extra-trigger");
        let connection = create(&path).unwrap();
        connection
            .execute(
                "CREATE TRIGGER extra BEFORE UPDATE ON sync_cursor BEGIN \
                 SELECT RAISE(ABORT, 'no'); END",
                [],
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
    fn a_digest_hiding_bytes_after_a_nul_is_rejected() {
        let path = test_path("nul-digest");
        let connection = create(&path).unwrap();
        // length() and GLOB both stop at the NUL, so only a byte-length check sees
        // the trailing bytes.
        let smuggled = format!("{DIGEST}\0trailing");
        connection
            .execute(
                "INSERT INTO applied_events (sequence, digest) VALUES (1, ?1), (2, ?2)",
                params![smuggled, OTHER_DIGEST],
            )
            .unwrap();
        connection
            .execute(
                "UPDATE sync_cursor SET sequence = 2, tail_digest = ?1 WHERE id = 1",
                [OTHER_DIGEST],
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
    fn a_corrupt_database_header_is_rebuildable_rather_than_unavailable() {
        let path = test_path("corrupt-header");
        fs::write(&path, b"this is not a sqlite database at all, just bytes").unwrap();

        assert_eq!(
            open_existing(&path).unwrap_err(),
            ValidateError::InvalidHistory
        );
        fs::remove_file(path).unwrap();
    }
}
