//! A dedicated blocking thread owns one SQLite connection and serializes mutations.
//!
//! Reads and writes share one queue bounded at 64. Admission fails with full or stopping
//! instead of blocking. Accepted commands remain owned by the detached worker if callers drop
//! response futures. SQLite values and guards remain on the worker thread. The connection runs in
//! rollback-journal `delete` mode, which keeps the projection a single file with no
//! write-ahead-log sidecars. The worker creates a fresh projection or opens an existing file
//! after validating it.

use std::{
    error::Error,
    fmt,
    num::NonZeroU64,
    path::PathBuf,
    sync::mpsc::{self, Receiver, SyncSender},
    thread,
};

use tokio::sync::oneshot;

use crate::{
    db::projections::{
        self, ApplyError, ApplyOutcome, GrantActivation, ResumableWork, SchemaError,
        ScopeProjectionEvent, ValidateError,
    },
    domain::work::WorkRef,
    scope::{Digest, ScopeClaimIdentity, ScopeEventRef, ScopeHead, ScopeIdentity},
};

#[cfg(test)]
use crate::{db::projections::ScopeProjectionPayload, domain::work::WorkId};

const COMMAND_QUEUE_CAPACITY: usize = 64;

fn command_channel() -> (SyncSender<Command>, Receiver<Command>) {
    mpsc::sync_channel(COMMAND_QUEUE_CAPACITY)
}

enum Command {
    Apply {
        mutation: Box<ScopeProjectionEvent>,
        respond: oneshot::Sender<Result<ApplyOutcome, ApplyError>>,
    },
    Cursor {
        scope: Box<ScopeIdentity>,
        respond: oneshot::Sender<Result<(u64, Option<Digest>), ApplyError>>,
    },
    ConflictingOperation {
        scope: Box<ScopeIdentity>,
        operation_id: String,
        reference: ScopeEventRef,
        respond: oneshot::Sender<Result<bool, ApplyError>>,
    },
    MatchesHead {
        head: Box<ScopeHead>,
        respond: oneshot::Sender<Result<bool, ApplyError>>,
    },
    /// Work creation has no production command: admission through an applied plan event is the
    /// only writer of `admitted_work`.
    #[cfg(test)]
    AdmitWork {
        scope: Box<ScopeIdentity>,
        work: WorkRef,
        dependencies: Vec<WorkId>,
        scope_epoch: NonZeroU64,
        respond: oneshot::Sender<Result<(), ApplyError>>,
    },
    RecordGrant {
        identity: Box<ScopeClaimIdentity>,
        activation: Box<GrantActivation>,
        now_ms: u64,
        respond: oneshot::Sender<Result<(), ApplyError>>,
    },
    ResumableWork {
        scope: Box<ScopeIdentity>,
        scope_epoch: NonZeroU64,
        now_ms: u64,
        respond: oneshot::Sender<Result<Vec<ResumableWork>, ApplyError>>,
    },
    Drain {
        respond: oneshot::Sender<Result<(), ApplyError>>,
    },
    RecordClaim {
        scope: Box<ScopeIdentity>,
        work: WorkRef,
        claim_fence: NonZeroU64,
        lease_until: NonZeroU64,
        now_ms: u64,
        respond: oneshot::Sender<Result<(), ApplyError>>,
    },
    /// Terminal evidence has no production command until trusted sealed-claim intake lands.
    #[cfg(test)]
    RecordTerminal {
        scope: Box<ScopeIdentity>,
        work: WorkRef,
        claim_fence: NonZeroU64,
        result: Digest,
        respond: oneshot::Sender<Result<(), ApplyError>>,
    },
    ReadyWork {
        scope: Box<ScopeIdentity>,
        now_ms: u64,
        respond: oneshot::Sender<Result<Vec<WorkRef>, ApplyError>>,
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
    commands: SyncSender<Command>,
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
    /// verified, when the OS refuses to spawn the worker thread, and when the worker exits
    /// before reporting startup.
    pub(crate) async fn spawn(path: PathBuf) -> Result<Self, SchemaError> {
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
        let (commands, receiver) = command_channel();
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

    fn enqueue<T>(
        &self,
        command: impl FnOnce(oneshot::Sender<Result<T, ApplyError>>) -> Command,
    ) -> Result<oneshot::Receiver<Result<T, ApplyError>>, ApplyError> {
        let (respond, receive) = oneshot::channel();
        match self.commands.try_send(command(respond)) {
            Ok(()) => Ok(receive),
            Err(mpsc::TrySendError::Full(_)) => Err(ApplyError::Full),
            Err(mpsc::TrySendError::Disconnected(_)) => Err(ApplyError::Stopping),
        }
    }

    // The live, unpolled receiver keeps admission full; dropping it yields Stopping.
    #[cfg(test)]
    fn stalled() -> (Self, Receiver<Command>) {
        let (commands, receiver) = command_channel();
        (Self { commands }, receiver)
    }

    /// Applies one owned projection mutation on the SQLite owner thread.
    ///
    /// Dropping the returned future does not revoke a command that was already accepted;
    /// the mutation still applies, and only the response is discarded. A lost response does
    /// not indicate whether the accepted mutation committed.
    ///
    /// # Errors
    ///
    /// Returns [`ApplyError::Full`] when admission is saturated,
    /// [`ApplyError::Stopping`] when the worker is disconnected, errors from
    /// [`projections::apply_scope_event`], or [`ApplyError::DatabaseOperationFailed`] when an
    /// accepted command loses its response.
    pub(crate) async fn apply(
        &self,
        mutation: ScopeProjectionEvent,
    ) -> Result<ApplyOutcome, ApplyError> {
        self.enqueue(|respond| Command::Apply {
            mutation: Box::new(mutation),
            respond,
        })?
        .await
        .map_err(|_| ApplyError::DatabaseOperationFailed)?
    }

    /// Reads one scope's projection cursor on the SQLite owner thread.
    ///
    /// # Errors
    ///
    /// Returns [`ApplyError::Full`] when admission is saturated,
    /// [`ApplyError::Stopping`] when the worker is disconnected, or
    /// [`ApplyError::DatabaseOperationFailed`] when the query or accepted response fails.
    pub(crate) async fn scope_cursor(
        &self,
        scope: &ScopeIdentity,
    ) -> Result<(u64, Option<Digest>), ApplyError> {
        let scope = Box::new(scope.clone());
        self.enqueue(|respond| Command::Cursor { scope, respond })?
            .await
            .map_err(|_| ApplyError::DatabaseOperationFailed)?
    }

    /// Reports whether one scope recorded `operation_id` for an event other than `reference`.
    ///
    /// # Errors
    ///
    /// Returns [`ApplyError::Full`], [`ApplyError::Stopping`], or
    /// [`ApplyError::DatabaseOperationFailed`].
    pub(crate) async fn scope_conflicting_operation(
        &self,
        scope: &ScopeIdentity,
        operation_id: &str,
        reference: &ScopeEventRef,
    ) -> Result<bool, ApplyError> {
        let scope = Box::new(scope.clone());
        let operation_id = operation_id.to_owned();
        let reference = reference.clone();
        self.enqueue(|respond| Command::ConflictingOperation {
            scope,
            operation_id,
            reference,
            respond,
        })?
        .await
        .map_err(|_| ApplyError::DatabaseOperationFailed)?
    }

    /// Reports whether the committed projection row equals `head`.
    ///
    /// # Errors
    ///
    /// Returns [`ApplyError::Full`], [`ApplyError::Stopping`], or
    /// [`ApplyError::DatabaseOperationFailed`].
    pub(crate) async fn scope_matches_head(&self, head: &ScopeHead) -> Result<bool, ApplyError> {
        let head = Box::new(head.clone());
        self.enqueue(|respond| Command::MatchesHead { head, respond })?
            .await
            .map_err(|_| ApplyError::DatabaseOperationFailed)?
    }

    #[cfg(test)]
    pub(crate) async fn diagnostics(&self) -> Result<Diagnostics, ApplyError> {
        self.enqueue(|respond| Command::Diagnostics { respond })?
            .await
            .map_err(|_| ApplyError::DatabaseOperationFailed)?
    }

    /// Test-only direct admission; production work rows exist only through an applied plan event.
    ///
    /// # Errors
    ///
    /// Returns [`ApplyError::Conflict`] for a changed dependency set or self-dependency,
    /// [`ApplyError::Full`], [`ApplyError::Stopping`], or
    /// [`ApplyError::DatabaseOperationFailed`].
    #[cfg(test)]
    pub(crate) async fn admit_work(
        &self,
        scope: &ScopeIdentity,
        work: WorkRef,
        dependencies: Vec<WorkId>,
        scope_epoch: NonZeroU64,
    ) -> Result<(), ApplyError> {
        let scope = Box::new(scope.clone());
        self.enqueue(|respond| Command::AdmitWork {
            scope,
            work,
            dependencies,
            scope_epoch,
            respond,
        })?
        .await
        .map_err(|_| ApplyError::DatabaseOperationFailed)?
    }

    /// `record_grant` records a grant only when `identity`'s claim fence, plan, scope epoch,
    /// live lease, and admitted deadline are current, and `activation` stays inside the admitted
    /// attempt bound and the plan's reserved budget.
    ///
    /// # Errors
    ///
    /// Returns [`ApplyError::Conflict`] when any of those bindings fails, [`ApplyError::Full`],
    /// [`ApplyError::Stopping`], or [`ApplyError::DatabaseOperationFailed`].
    pub(crate) async fn record_grant(
        &self,
        identity: &ScopeClaimIdentity,
        activation: GrantActivation,
        now_ms: u64,
    ) -> Result<(), ApplyError> {
        let identity = Box::new(identity.clone());
        let activation = Box::new(activation);
        self.enqueue(|respond| Command::RecordGrant {
            identity,
            activation,
            now_ms,
            respond,
        })?
        .await
        .map_err(|_| ApplyError::DatabaseOperationFailed)?
    }

    /// Lists the revisions a restart may resume under `scope_epoch` at `now_ms`.
    ///
    /// # Errors
    ///
    /// Returns [`ApplyError::Full`], [`ApplyError::Stopping`], or
    /// [`ApplyError::DatabaseOperationFailed`].
    pub async fn resumable_work(
        &self,
        scope: &ScopeIdentity,
        scope_epoch: NonZeroU64,
        now_ms: u64,
    ) -> Result<Vec<ResumableWork>, ApplyError> {
        let scope = Box::new(scope.clone());
        self.enqueue(|respond| Command::ResumableWork {
            scope,
            scope_epoch,
            now_ms,
            respond,
        })?
        .await
        .map_err(|_| ApplyError::DatabaseOperationFailed)?
    }

    /// Resolves once every command accepted before this call has been applied.
    ///
    /// Commands are served in admission order on one thread, so this reply proves the queue
    /// ahead of it drained; it does not stop later admissions.
    ///
    /// # Errors
    ///
    /// Returns [`ApplyError::Full`], [`ApplyError::Stopping`], or
    /// [`ApplyError::DatabaseOperationFailed`].
    pub async fn drain(&self) -> Result<(), ApplyError> {
        self.enqueue(|respond| Command::Drain { respond })?
            .await
            .map_err(|_| ApplyError::DatabaseOperationFailed)?
    }

    /// # Errors
    ///
    /// Returns [`ApplyError::Conflict`] for an unknown, terminal, or fence-regressing
    /// revision, [`ApplyError::Full`], [`ApplyError::Stopping`], or
    /// [`ApplyError::DatabaseOperationFailed`].
    pub async fn record_claim(
        &self,
        scope: &ScopeIdentity,
        work: WorkRef,
        claim_fence: NonZeroU64,
        lease_until: NonZeroU64,
        now_ms: u64,
    ) -> Result<(), ApplyError> {
        let scope = Box::new(scope.clone());
        self.enqueue(|respond| Command::RecordClaim {
            scope,
            work,
            claim_fence,
            lease_until,
            now_ms,
            respond,
        })?
        .await
        .map_err(|_| ApplyError::DatabaseOperationFailed)?
    }

    /// Test-only terminal evidence; no production completion path exists until trusted
    /// sealed-claim intake lands.
    ///
    /// # Errors
    ///
    /// Returns [`ApplyError::Conflict`] for an unknown or unclaimed revision, a stale claim
    /// fence, or conflicting evidence, [`ApplyError::Full`], [`ApplyError::Stopping`], or
    /// [`ApplyError::DatabaseOperationFailed`].
    #[cfg(test)]
    pub(crate) async fn record_terminal(
        &self,
        scope: &ScopeIdentity,
        work: WorkRef,
        claim_fence: NonZeroU64,
        result: Digest,
    ) -> Result<(), ApplyError> {
        let scope = Box::new(scope.clone());
        self.enqueue(|respond| Command::RecordTerminal {
            scope,
            work,
            claim_fence,
            result,
            respond,
        })?
        .await
        .map_err(|_| ApplyError::DatabaseOperationFailed)?
    }

    /// Readiness is derived per call; it is never stored.
    ///
    /// # Errors
    ///
    /// Returns [`ApplyError::Full`], [`ApplyError::Stopping`], or
    /// [`ApplyError::DatabaseOperationFailed`].
    pub async fn ready_work(
        &self,
        scope: &ScopeIdentity,
        now_ms: u64,
    ) -> Result<Vec<WorkRef>, ApplyError> {
        let scope = Box::new(scope.clone());
        self.enqueue(|respond| Command::ReadyWork {
            scope,
            now_ms,
            respond,
        })?
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
                let outcome = projections::apply_scope_event(&mut connection, &mutation);
                let _ = respond.send(outcome);
            }
            Command::Cursor { scope, respond } => {
                let _ = respond.send(projections::scope_cursor(&connection, &scope));
            }
            Command::ConflictingOperation {
                scope,
                operation_id,
                reference,
                respond,
            } => {
                let _ = respond.send(projections::scope_conflicting_operation(
                    &connection,
                    &scope,
                    &operation_id,
                    &reference,
                ));
            }
            Command::MatchesHead { head, respond } => {
                let _ = respond.send(projections::scope_matches_head(&connection, &head));
            }
            #[cfg(test)]
            Command::AdmitWork {
                scope,
                work,
                dependencies,
                scope_epoch,
                respond,
            } => {
                let _ = respond.send(projections::admit_work(
                    &mut connection,
                    &scope,
                    &work,
                    &dependencies,
                    scope_epoch,
                ));
            }
            Command::RecordGrant {
                identity,
                activation,
                now_ms,
                respond,
            } => {
                let _ = respond.send(projections::record_grant(
                    &connection,
                    &identity,
                    &activation,
                    now_ms,
                ));
            }
            Command::ResumableWork {
                scope,
                scope_epoch,
                now_ms,
                respond,
            } => {
                let _ = respond.send(projections::resumable_work(
                    &connection,
                    &scope,
                    scope_epoch,
                    now_ms,
                ));
            }
            Command::Drain { respond } => {
                let _ = respond.send(Ok(()));
            }
            Command::RecordClaim {
                scope,
                work,
                claim_fence,
                lease_until,
                now_ms,
                respond,
            } => {
                let _ = respond.send(projections::record_claim(
                    &connection,
                    &scope,
                    &work,
                    claim_fence,
                    lease_until,
                    now_ms,
                ));
            }
            #[cfg(test)]
            Command::RecordTerminal {
                scope,
                work,
                claim_fence,
                result,
                respond,
            } => {
                let _ = respond.send(projections::record_terminal(
                    &connection,
                    &scope,
                    &work,
                    claim_fence,
                    &result,
                ));
            }
            Command::ReadyWork {
                scope,
                now_ms,
                respond,
            } => {
                let _ = respond.send(projections::ready_work(&connection, &scope, now_ms));
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
        OpenMode::Create => projections::create(path).map_err(StartError::Create)?,
        OpenMode::Existing => projections::open_existing(path).map_err(StartError::Existing)?,
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

#[cfg(test)]
mod tests {
    use std::{
        fs,
        process::{self, Command as ProcessCommand, Stdio},
        time::{Duration, Instant},
    };

    use crate::{
        distributed::identity::WorkspaceId,
        scope::{AdmittedCampaignConfig, CampaignId, RootGenesis, root_genesis},
    };

    use super::*;

    fn path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!("ravel-worker-{}-{label}.sqlite3", process::id()))
    }

    fn genesis() -> RootGenesis {
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

    fn test_mutation() -> ScopeProjectionEvent {
        let genesis = genesis();
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

    #[tokio::test]
    async fn bounded_queue_reports_full_then_stopping_for_every_command() {
        let genesis = genesis();
        let (handle, receiver) = DbHandle::stalled();
        let mut pending = Vec::with_capacity(COMMAND_QUEUE_CAPACITY);
        for _ in 0..COMMAND_QUEUE_CAPACITY {
            pending.push(
                handle
                    .enqueue(|respond| Command::Cursor {
                        scope: Box::new(genesis.identity().clone()),
                        respond,
                    })
                    .unwrap(),
            );
        }

        assert_eq!(handle.apply(test_mutation()).await, Err(ApplyError::Full));
        assert_eq!(
            handle.scope_cursor(genesis.identity()).await,
            Err(ApplyError::Full)
        );
        assert_eq!(
            handle
                .scope_conflicting_operation(genesis.identity(), "operation", genesis.event_ref())
                .await,
            Err(ApplyError::Full)
        );
        assert_eq!(
            handle.scope_matches_head(genesis.head()).await,
            Err(ApplyError::Full)
        );
        assert_eq!(handle.diagnostics().await.err(), Some(ApplyError::Full));
        assert_eq!(
            work_commands(&handle, &genesis).await,
            [Err(ApplyError::Full); 7]
        );

        drop(receiver.recv().unwrap());
        drop(
            handle
                .enqueue(|respond| Command::Cursor {
                    scope: Box::new(genesis.identity().clone()),
                    respond,
                })
                .expect("admission recovers after one slot drains"),
        );

        drop(receiver);
        assert_eq!(
            handle.apply(test_mutation()).await,
            Err(ApplyError::Stopping)
        );
        assert_eq!(
            handle.scope_cursor(genesis.identity()).await,
            Err(ApplyError::Stopping)
        );
        assert_eq!(
            handle
                .scope_conflicting_operation(genesis.identity(), "operation", genesis.event_ref())
                .await,
            Err(ApplyError::Stopping)
        );
        assert_eq!(
            handle.scope_matches_head(genesis.head()).await,
            Err(ApplyError::Stopping)
        );
        assert_eq!(handle.diagnostics().await.err(), Some(ApplyError::Stopping));
        assert_eq!(
            work_commands(&handle, &genesis).await,
            [Err(ApplyError::Stopping); 7]
        );
        drop(pending);
    }

    /// Admission for every work command, mapped to `()` so one array compares them all.
    async fn work_commands(
        handle: &DbHandle,
        genesis: &crate::scope::RootGenesis,
    ) -> [Result<(), ApplyError>; 7] {
        let scope = genesis.identity();
        let work = WorkRef::new(WorkId::new("work-17".into()).unwrap(), 1);
        let fence = NonZeroU64::new(1).unwrap();
        [
            handle
                .admit_work(scope, work.clone(), Vec::new(), fence)
                .await,
            handle
                .record_claim(scope, work.clone(), fence, fence, 1)
                .await,
            handle
                .record_terminal(scope, work.clone(), fence, genesis.config_digest().clone())
                .await,
            handle
                .record_grant(
                    &ScopeClaimIdentity::new(
                        scope.clone(),
                        genesis.config_digest().clone(),
                        work.clone(),
                        fence.get(),
                    )
                    .unwrap(),
                    GrantActivation {
                        scope_epoch: fence,
                        attempt: fence,
                        units: fence,
                        deadline_unix_ms: fence,
                        digest: genesis.config_digest().clone(),
                    },
                    1,
                )
                .await,
            handle.ready_work(scope, 1).await.map(|_| ()),
            handle.resumable_work(scope, fence, 1).await.map(|_| ()),
            handle.drain().await,
        ]
    }

    #[cfg(target_os = "linux")]
    fn vm_hwm_kib() -> u64 {
        fs::read_to_string("/proc/self/status")
            .unwrap()
            .lines()
            .find_map(|line| line.strip_prefix("VmHWM:"))
            .and_then(|value| value.split_whitespace().next())
            .and_then(|value| value.parse().ok())
            .expect("VmHWM is present in /proc/self/status")
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "launched in isolation by stalled_writer_memory_is_bounded"]
    async fn stalled_writer_memory_child() {
        let genesis = genesis();
        let (handle, receiver) = DbHandle::stalled();
        let mut pending = Vec::with_capacity(COMMAND_QUEUE_CAPACITY);
        for _ in 0..COMMAND_QUEUE_CAPACITY {
            pending.push(
                handle
                    .enqueue(|respond| Command::Cursor {
                        scope: Box::new(genesis.identity().clone()),
                        respond,
                    })
                    .unwrap(),
            );
        }
        assert_eq!(handle.apply(test_mutation()).await, Err(ApplyError::Full));

        let mutation = test_mutation();
        let mut rejected = 0_u64;
        let mut samples = Vec::with_capacity(10);
        // VmHWM is process-wide, so the parent isolates this child. The first sample follows
        // 10,000 attempts to exclude allocator and runtime warm-up.
        for attempt in 1..=100_000_u64 {
            assert_eq!(handle.apply(mutation.clone()).await, Err(ApplyError::Full));
            rejected += 1;
            if attempt % 10_000 == 0 {
                samples.push(vm_hwm_kib());
            }
        }
        assert_eq!(rejected, 100_000);
        let delta = samples.last().unwrap().saturating_sub(samples[0]);
        println!("VmHWM-kib={samples:?}; delta-kib={delta}; rejected={rejected}");
        assert!(delta <= 8 * 1024, "VmHWM grew by {delta} KiB: {samples:?}");

        drop(receiver);
        drop(pending);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn stalled_writer_memory_is_bounded() {
        let stdout_path = path("rss-stdout");
        let stderr_path = path("rss-stderr");
        let _ = fs::remove_file(&stdout_path);
        let _ = fs::remove_file(&stderr_path);
        let mut child = ProcessCommand::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "db::worker::tests::stalled_writer_memory_child",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .stdout(Stdio::from(fs::File::create(&stdout_path).unwrap()))
            .stderr(Stdio::from(fs::File::create(&stderr_path).unwrap()))
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(60);
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) => {}
                Err(error) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("failed to poll stalled-writer RSS child: {error}");
                }
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("stalled-writer RSS child exceeded 60 seconds");
            }
            thread::sleep(Duration::from_millis(25));
        };
        let stdout = fs::read_to_string(&stdout_path).unwrap();
        let stderr = fs::read_to_string(&stderr_path).unwrap();
        let _ = fs::remove_file(stdout_path);
        let _ = fs::remove_file(stderr_path);
        assert!(status.success(), "child failed: {stdout}\n{stderr}");
        let samples = stdout
            .lines()
            .find(|line| line.contains("VmHWM-kib="))
            .expect("child reports RSS samples");
        println!("{samples}");
    }

    #[tokio::test]
    async fn owns_one_delete_journal_connection_on_a_blocking_thread() {
        let path = path("owner");
        let _ = fs::remove_file(&path);
        let genesis = genesis();
        let mutation = test_mutation();
        let handle = DbHandle::spawn(path.clone()).await.unwrap();
        assert_eq!(
            handle.scope_cursor(genesis.identity()).await.unwrap(),
            (0, None)
        );
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
            handle.scope_cursor(genesis.identity()).await.unwrap(),
            (1, Some(genesis.event_ref().digest().clone()))
        );
        assert!(
            !handle
                .scope_conflicting_operation(
                    genesis.identity(),
                    genesis.head().operation_id(),
                    genesis.event_ref()
                )
                .await
                .unwrap()
        );
        let reused = ScopeEventRef::new(2, genesis.event_ref().digest().clone()).unwrap();
        assert!(
            handle
                .scope_conflicting_operation(
                    genesis.identity(),
                    genesis.head().operation_id(),
                    &reused
                )
                .await
                .unwrap()
        );
        assert!(handle.scope_matches_head(genesis.head()).await.unwrap());

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
    async fn opens_a_valid_existing_projection_and_rejects_a_foreign_file() {
        let valid_path = path("existing-valid");
        let _ = fs::remove_file(&valid_path);
        drop(projections::create(&valid_path).unwrap());
        let handle = DbHandle::open_existing(valid_path.clone()).await.unwrap();
        assert_eq!(
            handle.scope_cursor(genesis().identity()).await.unwrap(),
            (0, None)
        );
        assert_eq!(handle.diagnostics().await.unwrap().journal_mode, "delete");
        drop(handle);
        fs::remove_file(valid_path).unwrap();

        let foreign_path = path("existing-foreign");
        let _ = fs::remove_file(&foreign_path);
        let connection = projections::create(&foreign_path).unwrap();
        connection
            .pragma_update(None, "application_id", 0x1234)
            .unwrap();
        drop(connection);
        assert_eq!(
            DbHandle::open_existing(foreign_path.clone()).await.err(),
            Some(OpenExistingError::Validation(
                ValidateError::WrongApplicationId
            ))
        );
        fs::remove_file(foreign_path).unwrap();
    }
}
