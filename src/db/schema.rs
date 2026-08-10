//! Fixed schema for a disposable local SQLite projection.
//!
//! S3 is the durable authority. Schema version 1 comprises seven logical tables without
//! migration history, and the `RVL1` application id identifies this database format.
//! `sync_cursor` holds one row, in one of two shapes: the genesis pairing of sequence 0 with a
//! null digest, or a durable sequence paired with 64 lowercase hexadecimal digest characters.

use std::{error::Error, fmt, path::Path};

const APPLICATION_ID: i32 = 0x5256_4c31; // "RVL1"
const SCHEMA_VERSION: i32 = 1;

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
            AND tail_digest NOT GLOB '*[^0-9a-f]*'
        )
    )
) STRICT;

CREATE TABLE campaigns (
    campaign_id TEXT PRIMARY KEY NOT NULL
) STRICT;

CREATE TABLE objectives (
    objective_id TEXT PRIMARY KEY NOT NULL
) STRICT;

CREATE TABLE workflows (
    workflow_id TEXT PRIMARY KEY NOT NULL
) STRICT;

CREATE TABLE work_items (
    work_id TEXT PRIMARY KEY NOT NULL
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

/// Creates the fixed projection schema at `path` and verifies its integrity.
///
/// Creation requires a path that does not already hold this schema; this function neither
/// validates nor rebuilds an existing projection. SQLite honors its reserved filenames,
/// `:memory:` and `file:` URIs among them, rather than rejecting them. Journal mode, busy
/// handling, and connection ownership stay with the caller.
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

/// Creates the schema, versions, and genesis cursor as one committed transaction.
fn initialize(path: &Path) -> rusqlite::Result<rusqlite::Connection> {
    let mut connection = rusqlite::Connection::open(path)?;
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

        let columns = connection
            .prepare("PRAGMA table_info(applied_events)")
            .unwrap()
            .query_map([], |row| row.get::<_, String>(1))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(columns, ["sequence", "digest"]);

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
            .execute("CREATE TABLE unrelated (id INTEGER PRIMARY KEY)", [])
            .unwrap();
        drop(foreign);

        assert_eq!(
            create(&path).err(),
            Some(SchemaError::DatabaseOperationFailed)
        );

        let inspect = rusqlite::Connection::open(&path).unwrap();
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
    fn rejects_duplicate_identities_and_edges() {
        let path = test_path("identity-constraints");
        let connection = create(&path).unwrap();

        for (insert, insert_null) in [
            (
                "INSERT INTO campaigns (campaign_id) VALUES ('id')",
                "INSERT INTO campaigns (campaign_id) VALUES (NULL)",
            ),
            (
                "INSERT INTO objectives (objective_id) VALUES ('id')",
                "INSERT INTO objectives (objective_id) VALUES (NULL)",
            ),
            (
                "INSERT INTO workflows (workflow_id) VALUES ('id')",
                "INSERT INTO workflows (workflow_id) VALUES (NULL)",
            ),
            (
                "INSERT INTO work_items (work_id) VALUES ('id')",
                "INSERT INTO work_items (work_id) VALUES (NULL)",
            ),
        ] {
            connection.execute(insert, []).unwrap();
            assert_constraint(connection.execute(insert, []));
            // NOT NULL is load-bearing: a non-INTEGER PRIMARY KEY otherwise accepts NULL.
            assert_constraint(connection.execute(insert_null, []));
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
        // A composite primary key is a UNIQUE index, where NULL never compares equal, so
        // repeated NULL edges would be accepted without the column NOT NULL clauses.
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
}
