//! A dedicated blocking thread owns one SQLite connection and serializes mutations.
//!
//! Async callers transfer owned mutations and await owned results. SQLite values and guards
//! remain on the worker thread. The connection runs in rollback-journal `delete` mode, which
//! keeps the projection a single file with no write-ahead-log sidecars. The worker either
//! creates a fresh projection or opens an existing file after validating it, and it answers
//! cursor reads.

use std::{
    error::Error,
    fmt,
    path::PathBuf,
    sync::mpsc::{self, Receiver, Sender},
    thread,
};

use tokio::sync::oneshot;

use crate::{
    db::{
        projections::{self, ApplyError, ApplyOutcome},
        schema::{self, SchemaError, ValidateError},
    },
    sync::event::SchedulingMutation,
};

enum Command {
    Apply {
        mutation: SchedulingMutation,
        respond: oneshot::Sender<Result<ApplyOutcome, ApplyError>>,
    },
    Cursor {
        respond: oneshot::Sender<Result<(u64, Option<String>), ApplyError>>,
    },
    ListReadyWork {
        campaign_id: String,
        capabilities: Vec<String>,
        limit: usize,
        after: Option<(String, String)>,
        respond: oneshot::Sender<Result<Vec<(String, String)>, ApplyError>>,
    },
    #[cfg(test)]
    Diagnostics {
        respond: oneshot::Sender<Result<Diagnostics, ApplyError>>,
    },
}

#[cfg(test)]
pub(crate) struct Diagnostics {
    pub(crate) worker_thread: thread::ThreadId,
    pub(crate) apply_thread: Option<thread::ThreadId>,
    pub(crate) journal_mode: String,
    pub(crate) apply_count: usize,
}

#[derive(Clone, Copy)]
enum OpenMode {
    Create,
    Existing,
}

#[derive(Debug)]
enum StartError {
    Create(SchemaError),
    Existing(ValidateError),
    DatabaseOperationFailed,
}

/// `OpenExistingError` separates validation failures from database-operation failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OpenExistingError {
    Validation(ValidateError),
    DatabaseOperationFailed,
}

impl fmt::Display for OpenExistingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Validation(_) => "database validation failed",
            Self::DatabaseOperationFailed => "database operation failed",
        })
    }
}

impl Error for OpenExistingError {}

/// Provides async access to the connection-owning SQLite thread.
///
/// Clones share one worker thread and one connection.
#[derive(Clone)]
pub struct DbHandle {
    commands: Sender<Command>,
}

impl DbHandle {
    /// Starts a blocking SQLite owner and creates a projection database at `path`.
    ///
    /// Creation requires a path that does not already hold this projection. The worker
    /// configures and verifies exact `delete` journal mode before this function returns.
    /// Dropping the returned future stops the worker; a database file it already created
    /// remains on disk.
    ///
    /// # Errors
    ///
    /// Forwards [`SchemaError`] from schema creation, returns
    /// [`SchemaError::DatabaseOperationFailed`] when the journal mode cannot be configured or
    /// verified, and returns the same variant when the worker exits before reporting startup.
    pub async fn spawn(path: PathBuf) -> Result<Self, SchemaError> {
        match Self::start(path, OpenMode::Create).await {
            Ok(handle) => Ok(handle),
            Err(StartError::Create(error)) => Err(error),
            Err(StartError::Existing(_) | StartError::DatabaseOperationFailed) => {
                Err(SchemaError::DatabaseOperationFailed)
            }
        }
    }

    /// Opens a validated existing projection on a blocking SQLite owner.
    ///
    /// Database read failures during validation produce
    /// [`OpenExistingError::DatabaseOperationFailed`].
    pub(crate) async fn open_existing(path: PathBuf) -> Result<Self, OpenExistingError> {
        match Self::start(path, OpenMode::Existing).await {
            Ok(handle) => Ok(handle),
            Err(StartError::Existing(ValidateError::DatabaseOperationFailed)) => {
                Err(OpenExistingError::DatabaseOperationFailed)
            }
            Err(StartError::Existing(error)) => Err(OpenExistingError::Validation(error)),
            Err(StartError::Create(_) | StartError::DatabaseOperationFailed) => {
                Err(OpenExistingError::DatabaseOperationFailed)
            }
        }
    }

    async fn start(path: PathBuf, mode: OpenMode) -> Result<Self, StartError> {
        let (commands, receiver) = mpsc::channel();
        let (startup_send, startup_receive) = oneshot::channel();
        thread::Builder::new()
            .name("ravel-sqlite".into())
            .spawn(move || run(path, mode, receiver, startup_send))
            .map_err(|_| StartError::DatabaseOperationFailed)?;

        match startup_receive.await {
            Ok(Ok(())) => Ok(Self { commands }),
            Ok(Err(error)) => Err(error),
            Err(_) => Err(StartError::DatabaseOperationFailed),
        }
    }

    /// Applies one owned scheduling mutation on the SQLite owner thread.
    ///
    /// Dropping the returned future does not revoke a command that was already sent;
    /// the mutation still applies, and only the response is discarded.
    ///
    /// # Errors
    ///
    /// Returns errors from [`projections::apply`], or [`ApplyError::DatabaseOperationFailed`]
    /// when the command or response channel disconnects.
    pub async fn apply(&self, mutation: SchedulingMutation) -> Result<ApplyOutcome, ApplyError> {
        let (respond, receive) = oneshot::channel();
        self.commands
            .send(Command::Apply { mutation, respond })
            .map_err(|_| ApplyError::DatabaseOperationFailed)?;
        receive
            .await
            .map_err(|_| ApplyError::DatabaseOperationFailed)?
    }

    /// Reads the singleton synchronization cursor on the SQLite owner thread.
    ///
    /// # Errors
    ///
    /// Returns [`ApplyError::DatabaseOperationFailed`] when the query fails or the command or
    /// response channel disconnects.
    pub(crate) async fn cursor(&self) -> Result<(u64, Option<String>), ApplyError> {
        let (respond, receive) = oneshot::channel();
        self.commands
            .send(Command::Cursor { respond })
            .map_err(|_| ApplyError::DatabaseOperationFailed)?;
        receive
            .await
            .map_err(|_| ApplyError::DatabaseOperationFailed)?
    }

    /// Queries ready work on the SQLite owner thread.
    ///
    /// # Errors
    ///
    /// Returns [`ApplyError::DatabaseOperationFailed`] when command delivery, response receipt, or
    /// the SQLite query fails.
    pub async fn list_ready_work(
        &self,
        campaign_id: String,
        capabilities: Vec<String>,
        limit: usize,
        after: Option<(String, String)>,
    ) -> Result<Vec<(String, String)>, ApplyError> {
        let (respond, receive) = oneshot::channel();
        self.commands
            .send(Command::ListReadyWork {
                campaign_id,
                capabilities,
                limit,
                after,
                respond,
            })
            .map_err(|_| ApplyError::DatabaseOperationFailed)?;
        receive
            .await
            .map_err(|_| ApplyError::DatabaseOperationFailed)?
    }

    #[cfg(test)]
    pub(crate) async fn diagnostics(&self) -> Result<Diagnostics, ApplyError> {
        let (respond, receive) = oneshot::channel();
        self.commands
            .send(Command::Diagnostics { respond })
            .map_err(|_| ApplyError::DatabaseOperationFailed)?;
        receive
            .await
            .map_err(|_| ApplyError::DatabaseOperationFailed)?
    }
}

fn run(
    path: PathBuf,
    mode: OpenMode,
    commands: Receiver<Command>,
    startup: oneshot::Sender<Result<(), StartError>>,
) {
    let mut connection = match configured_connection(path, mode) {
        Ok(connection) => connection,
        Err(error) => {
            let _ = startup.send(Err(error));
            return;
        }
    };
    if startup.send(Ok(())).is_err() {
        return;
    }

    #[cfg(test)]
    let mut last_apply_thread: Option<thread::ThreadId> = None;
    #[cfg(test)]
    let mut apply_count = 0;
    while let Ok(command) = commands.recv() {
        match command {
            Command::Apply { mutation, respond } => {
                #[cfg(test)]
                {
                    last_apply_thread = Some(thread::current().id());
                    apply_count += 1;
                }
                let outcome = projections::apply(&mut connection, &mutation);
                #[cfg(test)]
                crate::sync::replay::test_crash::reach("after-commit");
                let _ = respond.send(outcome);
            }
            Command::Cursor { respond } => {
                let _ = respond.send(read_cursor(&connection));
            }
            Command::ListReadyWork {
                campaign_id,
                capabilities,
                limit,
                after,
                respond,
            } => {
                let _ = respond.send(projections::list_ready_work(
                    &connection,
                    &campaign_id,
                    &capabilities,
                    limit,
                    after,
                ));
            }
            #[cfg(test)]
            Command::Diagnostics { respond } => {
                let diagnostics = connection
                    .pragma_query_value(None, "journal_mode", |row| row.get::<_, String>(0))
                    .map(|journal_mode| Diagnostics {
                        worker_thread: thread::current().id(),
                        apply_thread: last_apply_thread,
                        journal_mode,
                        apply_count,
                    })
                    .map_err(ApplyError::from);
                let _ = respond.send(diagnostics);
            }
        }
    }
}

fn configured_connection(
    path: PathBuf,
    open_mode: OpenMode,
) -> Result<rusqlite::Connection, StartError> {
    let connection = match open_mode {
        OpenMode::Create => schema::create(path).map_err(StartError::Create)?,
        OpenMode::Existing => schema::open_existing(path).map_err(StartError::Existing)?,
    };
    let mode = connection
        .pragma_update_and_check(None, "journal_mode", "DELETE", |row| {
            row.get::<_, String>(0)
        })
        .map_err(|_| StartError::DatabaseOperationFailed)?;
    if mode != "delete" {
        return Err(StartError::DatabaseOperationFailed);
    }
    Ok(connection)
}

fn read_cursor(connection: &rusqlite::Connection) -> Result<(u64, Option<String>), ApplyError> {
    let (stored_sequence, digest): (i64, Option<String>) = connection.query_row(
        "SELECT sequence, tail_digest FROM sync_cursor WHERE id = 1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let sequence =
        u64::try_from(stored_sequence).map_err(|_| ApplyError::DatabaseOperationFailed)?;
    Ok((sequence, digest))
}

#[cfg(test)]
mod tests {
    use std::{fs, process};

    use crate::{
        domain::campaign::{Event, EventContent, EventRef},
        sync::event::{encode, scheduling_mutation},
    };

    use super::*;

    fn path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!("ravel-worker-{}-{label}.sqlite3", process::id()))
    }

    #[tokio::test]
    async fn owns_one_delete_journal_connection_on_a_blocking_thread() {
        let path = path("owner");
        let _ = fs::remove_file(&path);
        let event = Event::new(
            "operation-1".into(),
            1,
            None,
            1,
            EventContent::CampaignCreated,
        )
        .unwrap();
        let encoded = encode(&event).unwrap();
        let reference = EventRef::new(
            event.sequence(),
            encoded.digest().to_owned(),
            encoded.key().to_owned(),
        )
        .unwrap();
        let mutation = scheduling_mutation(reference, &event).unwrap();
        let handle = DbHandle::spawn(path.clone()).await.unwrap();
        assert_eq!(handle.cursor().await.unwrap(), (0, None));
        let caller_thread = thread::current().id();
        let diagnostics = handle.diagnostics().await.unwrap();
        assert_ne!(diagnostics.worker_thread, caller_thread);
        assert_eq!(diagnostics.apply_thread, None);
        assert_eq!(diagnostics.journal_mode, "delete");
        assert_eq!(diagnostics.apply_count, 0);

        let other = handle.clone();
        let (first, second) = tokio::join!(handle.apply(mutation.clone()), other.apply(mutation));
        assert!(matches!(
            (first, second),
            (Ok(ApplyOutcome::Applied), Ok(ApplyOutcome::AlreadyApplied))
                | (Ok(ApplyOutcome::AlreadyApplied), Ok(ApplyOutcome::Applied))
        ));
        assert_eq!(
            handle.cursor().await.unwrap(),
            (1, Some(encoded.digest().to_owned()))
        );
        assert!(
            handle
                .list_ready_work("0000000000000001".into(), Vec::new(), 10, None)
                .await
                .unwrap()
                .is_empty()
        );

        let diagnostics_after = handle.diagnostics().await.unwrap();
        assert_eq!(diagnostics_after.worker_thread, diagnostics.worker_thread);
        assert_eq!(
            diagnostics_after.apply_thread,
            Some(diagnostics.worker_thread)
        );
        assert_eq!(diagnostics_after.journal_mode, "delete");
        assert_eq!(diagnostics_after.apply_count, 2);

        assert_eq!(
            DbHandle::spawn(path.clone()).await.err(),
            Some(SchemaError::DatabaseOperationFailed)
        );

        drop(handle);
        drop(other);
        fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn queries_ready_work_through_the_owner() {
        let path = path("ready-work");
        let _ = fs::remove_file(&path);
        let connection = schema::create(&path).unwrap();
        connection
            .execute_batch(
                "INSERT INTO campaigns (campaign_id, state) VALUES ('campaign', 'active');
                 INSERT INTO workflows (workflow_id, state) VALUES ('workflow', 'active');
                 INSERT INTO work_items
                     (work_id, workflow_id, state, budget_remaining, required_capabilities)
                 VALUES ('work', 'workflow', 'ready', 1, 'rust');",
            )
            .unwrap();
        drop(connection);
        let handle = DbHandle::open_existing(path.clone()).await.unwrap();

        assert_eq!(
            handle
                .list_ready_work("campaign".into(), vec!["rust".into()], 10, None)
                .await
                .unwrap(),
            [("workflow".to_owned(), "work".to_owned())]
        );

        drop(handle);
        fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn opens_valid_existing_projection_and_rejects_invalid_version() {
        let valid_path = path("existing-valid");
        let _ = fs::remove_file(&valid_path);
        drop(schema::create(&valid_path).unwrap());
        let handle = DbHandle::open_existing(valid_path.clone()).await.unwrap();
        assert_eq!(handle.cursor().await.unwrap(), (0, None));
        assert_eq!(handle.diagnostics().await.unwrap().journal_mode, "delete");
        drop(handle);
        fs::remove_file(valid_path).unwrap();

        let invalid_path = path("existing-invalid");
        let _ = fs::remove_file(&invalid_path);
        let connection = schema::create(&invalid_path).unwrap();
        connection.pragma_update(None, "user_version", 99).unwrap();
        drop(connection);
        assert_eq!(
            DbHandle::open_existing(invalid_path.clone()).await.err(),
            Some(OpenExistingError::Validation(
                ValidateError::WrongSchemaVersion
            ))
        );
        fs::remove_file(invalid_path).unwrap();
    }
}
