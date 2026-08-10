//! A dedicated blocking thread owns one SQLite connection and serializes mutations.
//!
//! Async callers transfer owned mutations and await owned results. SQLite values and guards
//! remain on the worker thread. The connection runs in rollback-journal `delete` mode, which
//! keeps the projection a single file with no write-ahead-log sidecars.

use std::{
    path::PathBuf,
    sync::mpsc::{self, Receiver, Sender},
    thread,
};

use tokio::sync::oneshot;

use crate::{
    db::{
        projections::{self, ApplyError, ApplyOutcome},
        schema::{self, SchemaError},
    },
    sync::event::SchedulingMutation,
};

enum Command {
    Apply {
        mutation: SchedulingMutation,
        respond: oneshot::Sender<Result<ApplyOutcome, ApplyError>>,
    },
    #[cfg(test)]
    Diagnostics {
        respond: oneshot::Sender<(
            thread::ThreadId,
            Option<thread::ThreadId>,
            Result<String, ApplyError>,
        )>,
    },
}

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
        let (commands, receiver) = mpsc::channel();
        let (startup_send, startup_receive) = oneshot::channel();
        let _worker = thread::spawn(move || run(path, receiver, startup_send));

        match startup_receive.await {
            Ok(Ok(())) => Ok(Self { commands }),
            Ok(Err(error)) => Err(error),
            Err(_) => Err(SchemaError::DatabaseOperationFailed),
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

    #[cfg(test)]
    async fn diagnostics(
        &self,
    ) -> Result<(thread::ThreadId, Option<thread::ThreadId>, String), ApplyError> {
        let (respond, receive) = oneshot::channel();
        self.commands
            .send(Command::Diagnostics { respond })
            .map_err(|_| ApplyError::DatabaseOperationFailed)?;
        let (thread_id, apply_thread, mode) = receive
            .await
            .map_err(|_| ApplyError::DatabaseOperationFailed)?;
        Ok((thread_id, apply_thread, mode?))
    }
}

fn run(
    path: PathBuf,
    commands: Receiver<Command>,
    startup: oneshot::Sender<Result<(), SchemaError>>,
) {
    let mut connection = match configured_connection(path) {
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
    while let Ok(command) = commands.recv() {
        match command {
            Command::Apply { mutation, respond } => {
                #[cfg(test)]
                {
                    last_apply_thread = Some(thread::current().id());
                }
                let _ = respond.send(projections::apply(&mut connection, &mutation));
            }
            #[cfg(test)]
            Command::Diagnostics { respond } => {
                let mode = connection
                    .pragma_query_value(None, "journal_mode", |row| row.get::<_, String>(0))
                    .map_err(ApplyError::from);
                let _ = respond.send((thread::current().id(), last_apply_thread, mode));
            }
        }
    }
}

fn configured_connection(path: PathBuf) -> Result<rusqlite::Connection, SchemaError> {
    let connection = schema::create(path)?;
    let mode = connection
        .pragma_update_and_check(None, "journal_mode", "DELETE", |row| {
            row.get::<_, String>(0)
        })
        .map_err(|_| SchemaError::DatabaseOperationFailed)?;
    if mode != "delete" {
        return Err(SchemaError::DatabaseOperationFailed);
    }
    Ok(connection)
}

#[cfg(test)]
mod tests {
    use std::{fs, process};

    use crate::{
        domain::campaign::{Event, EventContent, EventRef},
        sync::event::{encode, scheduling_mutation},
    };

    use super::*;

    #[tokio::test]
    async fn owns_one_delete_journal_connection_on_a_blocking_thread() {
        let path = std::env::temp_dir().join(format!("ravel-worker-{}.sqlite3", process::id()));
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
        let caller_thread = thread::current().id();
        let (worker_thread, applied_on, journal_mode) = handle.diagnostics().await.unwrap();
        assert_ne!(worker_thread, caller_thread);
        assert_eq!(applied_on, None);
        assert_eq!(journal_mode, "delete");

        let other = handle.clone();
        let (first, second) = tokio::join!(handle.apply(mutation.clone()), other.apply(mutation));
        assert!(matches!(
            (first, second),
            (Ok(ApplyOutcome::Applied), Ok(ApplyOutcome::AlreadyApplied))
                | (Ok(ApplyOutcome::AlreadyApplied), Ok(ApplyOutcome::Applied))
        ));

        let (worker_thread_after, applied_on_after, journal_mode_after) =
            handle.diagnostics().await.unwrap();
        assert_eq!(worker_thread_after, worker_thread);
        assert_eq!(applied_on_after, Some(worker_thread));
        assert_eq!(journal_mode_after, "delete");

        assert_eq!(
            DbHandle::spawn(path.clone()).await.err(),
            Some(SchemaError::DatabaseOperationFailed)
        );

        drop(handle);
        drop(other);
        fs::remove_file(path).unwrap();
    }
}
