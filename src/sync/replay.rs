//! Reconstructs the disposable projection from the exact S3 head ancestry.
//!
//! Replay follows parent references, verifies and converts the complete unseen chain, then sends
//! mutations to the SQLite owner in ascending sequence. Local validation failure, whether wrong
//! format, failed integrity check, or invalid local history, replaces the database; a remote
//! history conflict never does.

use std::{
    error::Error,
    ffi::OsString,
    fmt, io,
    path::{Path, PathBuf},
};

use crate::{
    db::{
        projections::{ApplyError, ApplyOutcome},
        worker::{DbHandle, OpenExistingError},
    },
    domain::campaign::{EventRef, Head},
    storage::s3::{GetError, GetOutcome, S3Store},
    sync::{
        WireError,
        event::{self, ConversionError, SchedulingMutation},
        head::{self, HeadReadError, ObservedHead},
    },
};

// The count cap is checked before any event GET and the byte cap sums compressed stored bytes
// after each GET, with a total exactly at the cap accepted. Each object stays separately bounded
// by the 256 KiB event read limit.
const LIMITS: Limits = Limits {
    events: 4_096,
    bytes: 64 * 1024 * 1024,
};

#[derive(Clone, Copy)]
struct Limits {
    events: u64,
    bytes: usize,
}

/// Identifies which replay stage failed, without retaining object data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayError {
    /// No campaign head exists at the store.
    CampaignMissing,
    /// The head object could not be read.
    HeadStorage,
    /// The head bytes failed wire validation.
    HeadInvalid(WireError),
    /// A referenced event object is absent.
    EventMissing,
    /// An event object could not be read.
    EventStorage,
    /// An event's bytes failed wire validation.
    EventInvalid(WireError),
    /// A verified event has no legal scheduling projection.
    Conversion(ConversionError),
    HistoryConflict,
    /// The local cursor is ahead of the observed head.
    CursorAhead,
    /// The local cursor and observed head have the same sequence but different digests.
    TailMismatch,
    /// The unseen chain exceeds the preparation count or byte cap.
    Overflow,
    /// The SQLite apply transaction rejected a prepared mutation.
    Apply(ApplyError),
    /// The local database could not be inspected, removed, started, or read.
    DatabaseUnavailable,
}

impl fmt::Display for ReplayError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::CampaignMissing => "campaign head is missing",
            Self::HeadStorage => "campaign head read failed",
            Self::HeadInvalid(_) => "campaign head is invalid",
            Self::EventMissing => "event object is missing",
            Self::EventStorage => "event object read failed",
            Self::EventInvalid(_) => "event object is invalid",
            Self::Conversion(_) => "event has no valid scheduling projection",
            Self::HistoryConflict => "remote history conflicts with the local projection",
            Self::CursorAhead => "local cursor is ahead of the campaign head",
            Self::TailMismatch => "local cursor digest differs from the campaign head",
            Self::Overflow => "unseen event preparation exceeds its bound",
            Self::Apply(_) => "event application failed",
            Self::DatabaseUnavailable => "local database is unavailable",
        })
    }
}

impl Error for ReplayError {}

/// A projection synchronized against one specific observed head.
///
/// The head and cursor are the ones this replay attempt read and reached, so a
/// readiness check compares against that attempt's boundary. Rereading head and
/// cursor after `startup` instead would let a remote head advance in between and
/// make a synchronized projection look not-ready.
pub struct ReplayedProjection {
    handle: DbHandle,
    head: ObservedHead,
    cursor: (u64, Option<String>),
}

impl ReplayedProjection {
    pub fn handle(&self) -> &DbHandle {
        &self.handle
    }

    pub fn into_handle(self) -> DbHandle {
        self.handle
    }

    pub fn head(&self) -> &ObservedHead {
        &self.head
    }

    pub fn cursor(&self) -> (u64, Option<&str>) {
        (self.cursor.0, self.cursor.1.as_deref())
    }
}

/// Ephemeral outcome of one refresh attempt.
pub enum Readiness {
    /// Replay succeeded and the local cursor equals the observed head tail.
    ///
    /// Carries the full [`ObservedHead`] witness so a caller publishing the next
    /// event keeps the ETag coupled to the head this readiness was verified
    /// against, rather than rereading the head and losing that binding.
    Ready {
        local_cursor: (u64, String),
        observed_head: Box<ObservedHead>,
    },
    /// Replay or the final cursor comparison failed.
    NotReady(NotReadyReason),
}

/// Data-free reason one refresh attempt did not establish readiness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NotReadyReason {
    /// Replay failed before its cursor comparison.
    Replay(ReplayError),
    /// The post-replay cursor remains behind the observed head.
    Behind,
    /// The local cursor is ahead of the observed head, before or after replay.
    Ahead,
    /// The local cursor digest differs from the observed head tail, before or after replay.
    TailMismatch,
}

struct ReplaySuccess {
    observed_head: ObservedHead,
    local_cursor: (u64, Option<String>),
}

/// Replays one fresh head observation and reports ephemeral readiness.
pub async fn refresh(store: &S3Store, handle: &DbHandle) -> Readiness {
    match replay_with_limits(store, handle, LIMITS).await {
        Ok(success) => match compare_cursor(success.observed_head.head(), success.local_cursor) {
            Ok(local_cursor) => Readiness::Ready {
                local_cursor,
                observed_head: Box::new(success.observed_head),
            },
            Err(reason) => Readiness::NotReady(reason),
        },
        // Prepare reports these cursor mismatches before the final comparison runs;
        // surface them as the dedicated readiness reasons rather than nested replay
        // errors so callers can tell a cursor mismatch from replay/storage failure.
        Err(ReplayError::CursorAhead) => Readiness::NotReady(NotReadyReason::Ahead),
        Err(ReplayError::TailMismatch) => Readiness::NotReady(NotReadyReason::TailMismatch),
        Err(error) => Readiness::NotReady(NotReadyReason::Replay(error)),
    }
}

fn compare_cursor(
    observed_head: &Head,
    local_cursor: (u64, Option<String>),
) -> Result<(u64, String), NotReadyReason> {
    let tail = observed_head.tail().clone();
    match local_cursor.0.cmp(&tail.sequence()) {
        std::cmp::Ordering::Less => Err(NotReadyReason::Behind),
        std::cmp::Ordering::Greater => Err(NotReadyReason::Ahead),
        std::cmp::Ordering::Equal => match local_cursor.1 {
            Some(digest) if digest == tail.digest() => Ok((tail.sequence(), digest)),
            _ => Err(NotReadyReason::TailMismatch),
        },
    }
}

/// Opens or creates the disposable projection and replays the fresh observed ancestry.
///
/// Local validation failure removes the rollback journal, then the database, before creating a
/// replacement. Remote history and replay errors return without replacing a valid local database.
/// A failed replacement replay returns an error and leaves the replacement file on disk;
/// the invalid prior database is never restored.
///
/// # Errors
///
/// Returns [`ReplayError::DatabaseUnavailable`] when the path cannot be inspected, the worker
/// cannot start, an existing file fails outside validation, or `db_path` is a SQLite URI or
/// reserved filename. Every other variant reports the replay stage that failed.
pub async fn startup(store: &S3Store, db_path: &Path) -> Result<ReplayedProjection, ReplayError> {
    // Existence drives the create-or-validate decision, and `try_exists` compares a
    // literal path. SQLite would resolve `file:` URIs and `:memory:` to something
    // else, so a URI-backed projection would look absent on every startup.
    if is_sqlite_uri(db_path) {
        return Err(ReplayError::DatabaseUnavailable);
    }
    if !db_path
        .try_exists()
        .map_err(|_| ReplayError::DatabaseUnavailable)?
    {
        let handle = DbHandle::spawn(db_path.to_path_buf())
            .await
            .map_err(|_| ReplayError::DatabaseUnavailable)?;
        let success = replay_with_limits(store, &handle, LIMITS).await?;
        return Ok(ReplayedProjection {
            handle,
            head: success.observed_head,
            cursor: success.local_cursor,
        });
    }

    match DbHandle::open_existing(db_path.to_path_buf()).await {
        Ok(handle) => {
            let success = replay_with_limits(store, &handle, LIMITS).await?;
            Ok(ReplayedProjection {
                handle,
                head: success.observed_head,
                cursor: success.local_cursor,
            })
        }
        Err(OpenExistingError::DatabaseOperationFailed) => Err(ReplayError::DatabaseUnavailable),
        Err(OpenExistingError::Validation(_)) => replace_and_replay(store, db_path).await,
    }
}

async fn replace_and_replay(
    store: &S3Store,
    db_path: &Path,
) -> Result<ReplayedProjection, ReplayError> {
    remove_if_present(&journal_path(db_path))?;
    remove_if_present(db_path)?;
    let handle = DbHandle::spawn(db_path.to_path_buf())
        .await
        .map_err(|_| ReplayError::DatabaseUnavailable)?;
    let success = replay_with_limits(store, &handle, LIMITS).await?;
    Ok(ReplayedProjection {
        handle,
        head: success.observed_head,
        cursor: success.local_cursor,
    })
}

fn remove_if_present(path: &Path) -> Result<(), ReplayError> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(ReplayError::DatabaseUnavailable),
    }
}

fn is_sqlite_uri(path: &Path) -> bool {
    let Some(text) = path.to_str() else {
        return false;
    };
    text == ":memory:" || text.starts_with("file:")
}

fn journal_path(path: &Path) -> PathBuf {
    let mut journal = OsString::from(path.as_os_str());
    journal.push("-journal");
    journal.into()
}

async fn replay_with_limits(
    store: &S3Store,
    handle: &DbHandle,
    limits: Limits,
) -> Result<ReplaySuccess, ReplayError> {
    let observed = match head::read(store).await {
        Ok(Some(observed)) => observed,
        Ok(None) => return Err(ReplayError::CampaignMissing),
        Err(HeadReadError::Storage(_)) => return Err(ReplayError::HeadStorage),
        Err(HeadReadError::Invalid(error)) => return Err(ReplayError::HeadInvalid(error)),
    };
    let cursor = handle
        .cursor()
        .await
        .map_err(|_| ReplayError::DatabaseUnavailable)?;
    let mut prepared = prepare(store, cursor, observed.head().tail().clone(), limits).await?;
    prepared.reverse();
    for mutation in prepared {
        #[cfg(test)]
        test_crash::reach("before-apply");
        match handle.apply(mutation).await {
            Ok(ApplyOutcome::Applied | ApplyOutcome::AlreadyApplied) => {}
            Err(error) => return Err(ReplayError::Apply(error)),
        }
    }
    let local_cursor = handle
        .cursor()
        .await
        .map_err(|_| ReplayError::DatabaseUnavailable)?;
    Ok(ReplaySuccess {
        observed_head: observed,
        local_cursor,
    })
}

async fn prepare(
    store: &S3Store,
    cursor: (u64, Option<String>),
    tail: EventRef,
    limits: Limits,
) -> Result<Vec<SchedulingMutation>, ReplayError> {
    let (cursor_sequence, cursor_digest) = cursor;
    if tail.sequence() < cursor_sequence {
        return Err(ReplayError::CursorAhead);
    }
    if tail.sequence() == cursor_sequence {
        return if cursor_digest.as_deref() == Some(tail.digest()) {
            Ok(Vec::new())
        } else {
            Err(ReplayError::TailMismatch)
        };
    }

    let unseen = tail.sequence() - cursor_sequence;
    if unseen > limits.events {
        return Err(ReplayError::Overflow);
    }

    let mut current = tail;
    let mut total_bytes = 0_usize;
    let mut prepared = Vec::with_capacity(unseen as usize);
    for hop in 0..unseen {
        let bytes = match store
            .get_object(current.key(), event::MAX_COMPRESSED_BYTES)
            .await
        {
            Ok(GetOutcome::Found { bytes, .. }) => bytes,
            Ok(GetOutcome::NotFound) => return Err(ReplayError::EventMissing),
            Err(GetError::TooLarge) => {
                return Err(ReplayError::EventInvalid(WireError::LimitExceeded));
            }
            Err(GetError::MissingETag | GetError::Transport) => {
                return Err(ReplayError::EventStorage);
            }
        };
        total_bytes = total_bytes
            .checked_add(bytes.len())
            .ok_or(ReplayError::Overflow)?;
        if total_bytes > limits.bytes {
            return Err(ReplayError::Overflow);
        }
        let decoded = event::decode(&bytes, current.key()).map_err(ReplayError::EventInvalid)?;
        let mutation = event::scheduling_mutation(current.clone(), &decoded)
            .map_err(ReplayError::Conversion)?;
        let final_hop = hop + 1 == unseen;
        if final_hop {
            let boundary_matches = if cursor_sequence == 0 {
                decoded.sequence() == 1 && decoded.parent().is_none()
            } else {
                decoded.parent().is_some_and(|parent| {
                    parent.sequence() == cursor_sequence
                        && cursor_digest.as_deref() == Some(parent.digest())
                })
            };
            if !boundary_matches {
                return Err(ReplayError::HistoryConflict);
            }
        } else {
            current = decoded
                .parent()
                .cloned()
                .ok_or(ReplayError::HistoryConflict)?;
        }
        prepared.push(mutation);
    }
    Ok(prepared)
}

#[cfg(test)]
pub(crate) mod test_crash {
    use std::{io::Write, path::PathBuf, sync::OnceLock, thread};

    static CONFIG: OnceLock<(String, PathBuf)> = OnceLock::new();

    pub(crate) fn install(site: String, control: PathBuf) -> Result<(), ()> {
        CONFIG.set((site, control)).map_err(|_| ())
    }

    pub(crate) fn reach(site: &str) {
        let Some((selected, control)) = CONFIG.get() else {
            return;
        };
        if selected != site {
            return;
        }

        let mut file = std::fs::File::create(control).expect("create crash control file");
        write!(file, "REACHED:{site}").expect("write crash control marker");
        file.flush().expect("flush crash control marker");
        loop {
            thread::park();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        io::{BufRead, Write},
        os::unix::process::ExitStatusExt,
        process::{self, Command, Stdio},
        thread,
        time::{Duration, Instant},
    };

    use aws_sdk_s3::primitives::SdkBody;
    use serde::{Deserialize, Serialize};
    use sha2::{Digest, Sha256};

    use crate::{
        db::{
            projections::{self, FAIL_CURSOR_TRIGGER, tests::snapshot},
            schema,
            worker::DbHandle,
        },
        domain::campaign::{ArtifactRef, Authority, Event, EventContent, Head},
        storage::s3::test_support::{replay_store, response},
        sync::{event, head},
    };

    use super::*;

    const GENESIS_DIGEST: &str = "d10251de219fe17099d74f8f14729b1cbb33bdd73f919d6fb907ef32d5a51648";
    const CHILD_DIGEST: &str = "5454daad2e7a3c4ac66d017f75296647c7b3ebddc4e8d2b19d7cde066239d34c";
    const GENESIS_BYTES: &[u8] = include_bytes!(
        "../../tests/fixtures/v1/0000000000000001-d10251de219fe17099d74f8f14729b1cbb33bdd73f919d6fb907ef32d5a51648.cbor.zst"
    );
    const CHILD_BYTES: &[u8] = include_bytes!(
        "../../tests/fixtures/v1/0000000000000002-5454daad2e7a3c4ac66d017f75296647c7b3ebddc4e8d2b19d7cde066239d34c.cbor.zst"
    );

    fn path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!("ravel-replay-{}-{label}.sqlite3", process::id()))
    }

    fn clean(path: &Path) {
        let _ = fs::remove_file(journal_path(path));
        let _ = fs::remove_file(path);
    }

    fn reference(sequence: u64, digest: &str) -> EventRef {
        EventRef::from_digest(sequence, digest.to_owned()).unwrap()
    }

    fn genesis_ref() -> EventRef {
        reference(1, GENESIS_DIGEST)
    }

    fn child_ref() -> EventRef {
        reference(2, CHILD_DIGEST)
    }

    fn head_value(tail: EventRef) -> Head {
        Head::new(Authority::unowned(), tail, "head-operation".into()).unwrap()
    }

    fn head_response(tail: EventRef) -> http::Response<SdkBody> {
        response(
            200,
            &[("etag", "\"head-etag\"")],
            head::encode(&head_value(tail)).unwrap(),
        )
    }

    fn event_response(bytes: impl Into<SdkBody>) -> http::Response<SdkBody> {
        response(200, &[("etag", "\"event-etag\"")], bytes)
    }

    fn fixture_mutation(bytes: &[u8], reference: EventRef) -> SchedulingMutation {
        let decoded = event::decode(bytes, reference.key()).unwrap();
        event::scheduling_mutation(reference, &decoded).unwrap()
    }

    async fn apply_count(handle: &DbHandle) -> usize {
        handle.diagnostics().await.unwrap().apply_count
    }

    fn assert_gets(
        client: &aws_smithy_runtime::client::http::test_util::StaticReplayClient,
        paths: &[&str],
    ) {
        assert_eq!(client.actual_requests().count(), paths.len());
        for (request, path) in client.actual_requests().zip(paths) {
            assert_eq!(request.method(), http::Method::GET);
            let uri = request.uri().parse::<http::Uri>().unwrap();
            assert_eq!(uri.path(), format!("/{path}"));
        }
    }

    fn encoded_reference(event: &Event) -> (event::EncodedEvent, EventRef) {
        let encoded = event::encode(event).unwrap();
        let reference =
            EventRef::from_digest(event.sequence(), encoded.digest().to_owned()).unwrap();
        (encoded, reference)
    }

    #[derive(Deserialize, Serialize)]
    struct CrashParams {
        database: PathBuf,
        control: PathBuf,
        witness: PathBuf,
        site: String,
    }

    #[derive(Debug, Eq, PartialEq)]
    struct NarrowState {
        campaigns: i64,
        workflows: i64,
        applied_events: i64,
    }

    fn crash_params(site: &str) -> CrashParams {
        let database = path(&format!("crash-{site}"));
        CrashParams {
            control: database.with_extension("control"),
            witness: database.with_extension("witness"),
            database,
            site: site.to_owned(),
        }
    }

    fn clean_crash(params: &CrashParams) {
        clean(&params.database);
        let _ = fs::remove_file(&params.control);
        let _ = fs::remove_file(&params.witness);
    }

    fn stage_genesis(database: &Path) -> Result<(), &'static str> {
        clean(database);
        let mut connection = schema::create(database).map_err(|_| "create staging database")?;
        projections::apply(
            &mut connection,
            &fixture_mutation(GENESIS_BYTES, genesis_ref()),
        )
        .map_err(|_| "stage genesis")?;
        Ok(())
    }

    fn narrow_state(database: &Path) -> Result<NarrowState, &'static str> {
        let connection = rusqlite::Connection::open_with_flags(
            database,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .map_err(|_| "open database for counts")?;
        let count = |table: &str| {
            connection
                .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                    row.get::<_, i64>(0)
                })
                .map_err(|_| "read database counts")
        };
        Ok(NarrowState {
            campaigns: count("campaigns")?,
            workflows: count("workflows")?,
            applied_events: count("applied_events")?,
        })
    }

    fn expected_ready() -> Readiness {
        Readiness::Ready {
            local_cursor: (2, CHILD_DIGEST.to_owned()),
            observed_head: head_value(child_ref()),
        }
    }

    fn supervise_crash_child(params: &CrashParams) -> Result<(), &'static str> {
        let mut child = Command::new(std::env::current_exe().map_err(|_| "find test binary")?)
            .args([
                "--exact",
                "sync::replay::tests::crash_boundary_child",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| "spawn crash child")?;

        let result = (|| {
            let mut stdin = child.stdin.take().ok_or("open crash child stdin")?;
            serde_json::to_writer(&mut stdin, params).map_err(|_| "write crash child params")?;
            stdin
                .write_all(b"\n")
                .map_err(|_| "terminate crash child params")?;
            stdin.flush().map_err(|_| "flush crash child params")?;

            let expected = format!("REACHED:{}", params.site);
            let deadline = Instant::now() + Duration::from_secs(30);
            loop {
                match fs::read_to_string(&params.control) {
                    Ok(marker) if marker == expected => break,
                    Ok(marker) if expected.starts_with(&marker) => {}
                    Ok(_) => return Err("unexpected crash control marker"),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(_) => return Err("read crash control marker"),
                }
                if child.try_wait().map_err(|_| "poll crash child")?.is_some() {
                    return Err("crash child exited before cut");
                }
                if Instant::now() >= deadline {
                    return Err("crash child cut timeout");
                }
                thread::sleep(Duration::from_millis(25));
            }

            if params.witness.exists() {
                return Err("success preceded crash cut");
            }
            thread::sleep(Duration::from_millis(25));
            if child
                .try_wait()
                .map_err(|_| "poll blocked crash child")?
                .is_some()
            {
                return Err("crash child did not remain blocked");
            }
            child.kill().map_err(|_| "kill crash child")?;
            let status = child.wait().map_err(|_| "reap crash child")?;
            if status.signal() != Some(9) {
                return Err("crash child was not killed by signal 9");
            }
            if params.witness.exists() {
                return Err("success witness appeared before reap");
            }
            Ok(())
        })();

        if result.is_err() {
            if child.try_wait().ok().flatten().is_none() {
                let _ = child.kill();
            }
            let _ = child.wait();
        }
        result
    }

    #[tokio::test]
    #[ignore]
    async fn crash_boundary_child() {
        let mut input = String::new();
        std::io::stdin()
            .lock()
            .read_line(&mut input)
            .expect("read crash child params");
        let params: CrashParams = serde_json::from_str(&input).expect("decode crash child params");
        assert!(matches!(
            params.site.as_str(),
            "before-apply" | "before-commit" | "after-commit"
        ));
        test_crash::install(params.site, params.control).expect("install crash cut");

        let handle = DbHandle::open_existing(params.database)
            .await
            .expect("open crash database");
        let (store, _) = replay_store(vec![
            head_response(child_ref()),
            event_response(CHILD_BYTES),
        ]);
        match refresh(&store, &handle).await {
            Readiness::Ready { .. } => {
                fs::write(params.witness, b"SUCCESS").expect("write crash success witness")
            }
            Readiness::NotReady(_) => panic!("crash child refresh was not ready"),
        }
    }

    struct CrashCleanup {
        baseline: PathBuf,
        cases: Vec<CrashParams>,
    }

    impl Drop for CrashCleanup {
        fn drop(&mut self) {
            clean(&self.baseline);
            for params in &self.cases {
                clean_crash(params);
            }
        }
    }

    async fn run_crash_boundary_matrix(cleanup: &CrashCleanup) -> Result<(), &'static str> {
        let baseline = DbHandle::spawn(cleanup.baseline.clone())
            .await
            .map_err(|_| "start baseline worker")?;
        let (store, _) = replay_store(vec![
            head_response(child_ref()),
            event_response(CHILD_BYTES),
            event_response(GENESIS_BYTES),
        ]);
        if refresh(&store, &baseline).await != expected_ready() {
            return Err("build uninterrupted baseline");
        }
        if baseline
            .cursor()
            .await
            .map_err(|_| "read baseline cursor")?
            != (2, Some(CHILD_DIGEST.to_owned()))
        {
            return Err("baseline cursor mismatch");
        }
        if narrow_state(&cleanup.baseline)?
            != (NarrowState {
                campaigns: 1,
                workflows: 1,
                applied_events: 2,
            })
        {
            return Err("baseline state mismatch");
        }

        let mut final_recovered = None;
        for params in &cleanup.cases {
            stage_genesis(&params.database)?;
            supervise_crash_child(params)?;
            // The worker runs in delete journal mode, so a hot rollback journal survives
            // only the before-commit cut: before-apply wrote nothing, and commit removes
            // the journal.
            if journal_path(&params.database).exists() != (params.site == "before-commit") {
                return Err("crash journal state mismatch");
            }

            let handle = DbHandle::open_existing(params.database.clone())
                .await
                .map_err(|_| "open database after crash")?;
            let committed = params.site == "after-commit";
            let expected_cursor = if committed {
                (2, Some(CHILD_DIGEST.to_owned()))
            } else {
                (1, Some(GENESIS_DIGEST.to_owned()))
            };
            if handle.cursor().await.map_err(|_| "read crash cursor")? != expected_cursor {
                return Err("pre-recovery cursor mismatch");
            }
            let expected_state = NarrowState {
                campaigns: 1,
                workflows: i64::from(committed),
                applied_events: if committed { 2 } else { 1 },
            };
            if narrow_state(&params.database)? != expected_state {
                return Err("pre-recovery state mismatch");
            }

            let responses = if committed {
                vec![head_response(child_ref())]
            } else {
                vec![head_response(child_ref()), event_response(CHILD_BYTES)]
            };
            let (store, _) = replay_store(responses);
            if refresh(&store, &handle).await != expected_ready() {
                return Err("crash recovery was not ready");
            }
            if handle.cursor().await.map_err(|_| "read recovered cursor")?
                != (2, Some(CHILD_DIGEST.to_owned()))
            {
                return Err("recovered cursor mismatch");
            }
            let diagnostics = handle
                .diagnostics()
                .await
                .map_err(|_| "read recovery diagnostics")?;
            if diagnostics.apply_count != usize::from(!committed) {
                return Err("recovery apply count mismatch");
            }
            if narrow_state(&params.database)?
                != (NarrowState {
                    campaigns: 1,
                    workflows: 1,
                    applied_events: 2,
                })
            {
                return Err("recovered state mismatch");
            }

            if committed {
                final_recovered = Some(handle);
            } else {
                drop(handle);
                clean_crash(params);
            }
        }

        let final_recovered = final_recovered.ok_or("missing final recovered handle")?;
        let baseline_ready = baseline
            .list_ready_work("0000000000000001".into(), Vec::new(), 10, None)
            .await
            .map_err(|_| "query baseline ready work")?;
        let recovered_ready = final_recovered
            .list_ready_work("0000000000000001".into(), Vec::new(), 10, None)
            .await
            .map_err(|_| "query recovered ready work")?;
        if baseline_ready != recovered_ready {
            return Err("ready-work recovery mismatch");
        }
        // The v1 projection never writes work items, so the comparison is over empty
        // results; the canonical snapshot carries the row-level equivalence evidence.
        if !baseline_ready.is_empty() {
            return Err("unexpected baseline ready work");
        }

        drop(baseline);
        drop(final_recovered);
        let baseline_connection =
            schema::open_existing(&cleanup.baseline).map_err(|_| "validate baseline")?;
        let final_connection = schema::open_existing(&cleanup.cases[2].database)
            .map_err(|_| "validate recovered database")?;
        if snapshot(&baseline_connection) != snapshot(&final_connection) {
            return Err("canonical recovery mismatch");
        }
        Ok(())
    }

    #[tokio::test]
    async fn crash_boundaries_recover_without_skip_or_duplicate() {
        let cleanup = CrashCleanup {
            baseline: path("crash-baseline"),
            cases: ["before-apply", "before-commit", "after-commit"]
                .into_iter()
                .map(crash_params)
                .collect(),
        };
        clean(&cleanup.baseline);
        for params in &cleanup.cases {
            clean_crash(params);
        }

        assert_eq!(run_crash_boundary_matrix(&cleanup).await, Ok(()));
    }

    #[tokio::test]
    async fn injected_write_failure_stays_not_ready_until_clean_replay() {
        let database = path("injected-readiness");
        clean(&database);
        stage_genesis(&database).unwrap();
        let connection = rusqlite::Connection::open(&database).unwrap();
        connection.execute_batch(FAIL_CURSOR_TRIGGER).unwrap();
        drop(connection);

        let handle = DbHandle::open_existing(database.clone()).await.unwrap();
        let mut responses = Vec::new();
        for _ in 0..3 {
            responses.push(head_response(child_ref()));
            responses.push(event_response(CHILD_BYTES));
        }
        let (store, _) = replay_store(responses);
        let expected_failure = Readiness::NotReady(NotReadyReason::Replay(ReplayError::Apply(
            ApplyError::DatabaseOperationFailed,
        )));
        assert_eq!(refresh(&store, &handle).await, expected_failure);
        assert_eq!(refresh(&store, &handle).await, expected_failure);
        assert_eq!(
            handle.cursor().await.unwrap(),
            (1, Some(GENESIS_DIGEST.to_owned()))
        );
        assert_eq!(apply_count(&handle).await, 2);
        drop(handle);

        let connection = rusqlite::Connection::open(&database).unwrap();
        assert_eq!(
            narrow_state(&database).unwrap(),
            NarrowState {
                campaigns: 1,
                workflows: 0,
                applied_events: 1,
            }
        );
        connection
            .execute_batch("DROP TRIGGER fail_cursor_update")
            .unwrap();
        drop(connection);

        let handle = DbHandle::open_existing(database.clone()).await.unwrap();
        assert_eq!(refresh(&store, &handle).await, expected_ready());
        assert_eq!(apply_count(&handle).await, 1);
        assert_eq!(
            narrow_state(&database).unwrap(),
            NarrowState {
                campaigns: 1,
                workflows: 1,
                applied_events: 2,
            }
        );

        drop(handle);
        clean(&database);
    }

    #[tokio::test]
    async fn fresh_replay_follows_only_the_exact_parent_chain() {
        let path = path("fresh");
        clean(&path);
        let (store, client) = replay_store(vec![
            head_response(child_ref()),
            event_response(CHILD_BYTES),
            event_response(GENESIS_BYTES),
        ]);

        let replayed = startup(&store, &path).await.unwrap();
        assert_eq!(replayed.cursor(), (2, Some(CHILD_DIGEST)));
        assert_eq!(replayed.head().head().tail(), &child_ref());
        let handle = replayed.into_handle();
        assert_eq!(
            handle.cursor().await.unwrap(),
            (2, Some(CHILD_DIGEST.into()))
        );
        assert_eq!(apply_count(&handle).await, 2);
        assert_gets(
            &client,
            &["head.json", child_ref().key(), genesis_ref().key()],
        );

        drop(handle);
        clean(&path);
    }

    #[tokio::test]
    async fn incremental_replay_stops_at_the_exact_local_boundary() {
        let path = path("incremental");
        clean(&path);
        let handle = DbHandle::spawn(path.clone()).await.unwrap();
        handle
            .apply(fixture_mutation(GENESIS_BYTES, genesis_ref()))
            .await
            .unwrap();
        let (store, client) = replay_store(vec![
            head_response(child_ref()),
            event_response(CHILD_BYTES),
        ]);

        replay_with_limits(&store, &handle, LIMITS).await.unwrap();
        assert_eq!(
            handle.cursor().await.unwrap(),
            (2, Some(CHILD_DIGEST.into()))
        );
        assert_eq!(apply_count(&handle).await, 2);
        assert_gets(&client, &["head.json", child_ref().key()]);

        let (store, client) = replay_store(vec![head_response(genesis_ref())]);
        assert_eq!(
            replay_with_limits(&store, &handle, LIMITS).await.err(),
            Some(ReplayError::CursorAhead)
        );
        assert_eq!(apply_count(&handle).await, 2);
        assert_gets(&client, &["head.json"]);

        // A head at the cursor sequence with a different digest is a tail mismatch.
        let (store, client) = replay_store(vec![head_response(reference(2, GENESIS_DIGEST))]);
        assert_eq!(
            replay_with_limits(&store, &handle, LIMITS).await.err(),
            Some(ReplayError::TailMismatch)
        );
        assert_eq!(apply_count(&handle).await, 2);
        assert_gets(&client, &["head.json"]);

        // A head equal to the cursor in sequence and digest replays as a no-op with no event GET.
        let (store, client) = replay_store(vec![head_response(child_ref())]);
        replay_with_limits(&store, &handle, LIMITS).await.unwrap();
        assert_eq!(apply_count(&handle).await, 2);
        assert_gets(&client, &["head.json"]);

        drop(handle);
        clean(&path);
    }

    #[tokio::test]
    async fn remote_fork_neither_applies_nor_rebuilds_valid_local_state() {
        let path = path("fork");
        clean(&path);
        let handle = DbHandle::spawn(path.clone()).await.unwrap();
        handle
            .apply(fixture_mutation(GENESIS_BYTES, genesis_ref()))
            .await
            .unwrap();
        let alternate_genesis = Event::new(
            "alternate-genesis".into(),
            1,
            None,
            8,
            EventContent::CampaignCreated,
        )
        .unwrap();
        let (_, alternate_genesis_ref) = encoded_reference(&alternate_genesis);
        let alternate_child = Event::new(
            "alternate-child".into(),
            2,
            Some(alternate_genesis_ref),
            9,
            EventContent::WorkflowStarted,
        )
        .unwrap();
        let (alternate_bytes, alternate_ref) = encoded_reference(&alternate_child);
        let (store, client) = replay_store(vec![
            head_response(alternate_ref.clone()),
            event_response(alternate_bytes.stored_bytes().to_vec()),
        ]);

        assert_eq!(
            replay_with_limits(&store, &handle, LIMITS).await.err(),
            Some(ReplayError::HistoryConflict)
        );
        assert_eq!(apply_count(&handle).await, 1);
        assert_eq!(
            handle.cursor().await.unwrap(),
            (1, Some(GENESIS_DIGEST.into()))
        );
        assert_gets(&client, &["head.json", alternate_ref.key()]);
        drop(handle);

        let (store, _) = replay_store(vec![
            head_response(alternate_ref),
            event_response(alternate_bytes.stored_bytes().to_vec()),
        ]);
        assert_eq!(
            startup(&store, &path).await.err(),
            Some(ReplayError::HistoryConflict)
        );
        let connection = schema::open_existing(&path).unwrap();
        assert_eq!(
            connection
                .query_row("SELECT count(*) FROM campaigns", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            1
        );
        drop(connection);
        clean(&path);
    }

    #[tokio::test]
    async fn chain_failures_send_no_apply_commands() {
        let cases = {
            let mut cbor = zstd::bulk::decompress(GENESIS_BYTES, 1024 * 1024).unwrap();
            let version = cbor
                .windows(7)
                .position(|window| window == b"version")
                .unwrap()
                + 7;
            assert_eq!(cbor[version], 1);
            cbor[version] = 2;
            let unknown_version = zstd::bulk::compress(&cbor, 3).unwrap();
            let unknown_digest = format!("{:x}", Sha256::digest(&unknown_version));
            let unknown_ref = reference(1, &unknown_digest);

            let artifact = ArtifactRef::new(
                "0".repeat(64),
                4,
                "application/octet-stream".into(),
                "attempt".into(),
                1,
                None,
            )
            .unwrap();
            let artifact_event = Event::new(
                "artifact-operation".into(),
                1,
                None,
                1,
                EventContent::ArtifactPublished(artifact),
            )
            .unwrap();
            let (artifact_bytes, artifact_ref) = encoded_reference(&artifact_event);

            vec![
                (
                    "missing-link",
                    vec![
                        head_response(child_ref()),
                        event_response(CHILD_BYTES),
                        response(404, &[], SdkBody::empty()),
                    ],
                    ReplayError::EventMissing,
                ),
                (
                    "malformed",
                    vec![
                        head_response(genesis_ref()),
                        event_response(b"bad".as_slice()),
                    ],
                    ReplayError::EventInvalid(WireError::InvalidEncoding),
                ),
                (
                    "unknown-version",
                    vec![head_response(unknown_ref), event_response(unknown_version)],
                    ReplayError::EventInvalid(WireError::InvalidValue),
                ),
                (
                    "digest-mismatch",
                    vec![head_response(genesis_ref()), event_response(CHILD_BYTES)],
                    ReplayError::EventInvalid(WireError::ReferenceMismatch),
                ),
                (
                    "unsupported-conversion",
                    vec![
                        head_response(artifact_ref),
                        event_response(artifact_bytes.stored_bytes().to_vec()),
                    ],
                    ReplayError::Conversion(ConversionError::UnsupportedContent),
                ),
            ]
        };

        for (label, responses, expected) in cases {
            let path = path(label);
            clean(&path);
            let handle = DbHandle::spawn(path.clone()).await.unwrap();
            let (store, _) = replay_store(responses);
            assert_eq!(
                replay_with_limits(&store, &handle, LIMITS).await.err(),
                Some(expected)
            );
            assert_eq!(apply_count(&handle).await, 0);
            assert_eq!(handle.cursor().await.unwrap(), (0, None));
            drop(handle);
            clean(&path);
        }
    }

    #[test]
    fn sqlite_uri_paths_are_rejected_rather_than_treated_as_absent() {
        for text in [":memory:", "file:/var/lib/ravel/projection.sqlite?mode=rwc"] {
            assert!(is_sqlite_uri(Path::new(text)), "{text}");
        }
        assert!(!is_sqlite_uri(Path::new(
            "/var/lib/ravel/projection.sqlite"
        )));
    }

    #[tokio::test]
    async fn preparation_limits_precede_any_apply() {
        let path = path("limits");
        clean(&path);
        let handle = DbHandle::spawn(path.clone()).await.unwrap();
        let (store, client) = replay_store(vec![head_response(child_ref())]);
        assert_eq!(
            replay_with_limits(
                &store,
                &handle,
                Limits {
                    events: 1,
                    bytes: usize::MAX,
                },
            )
            .await
            .err(),
            Some(ReplayError::Overflow)
        );
        assert_gets(&client, &["head.json"]);

        let (store, client) = replay_store(vec![
            head_response(genesis_ref()),
            event_response(GENESIS_BYTES),
        ]);
        assert_eq!(
            replay_with_limits(
                &store,
                &handle,
                Limits {
                    events: 1,
                    bytes: GENESIS_BYTES.len() - 1,
                },
            )
            .await
            .err(),
            Some(ReplayError::Overflow)
        );
        assert_gets(&client, &["head.json", genesis_ref().key()]);
        assert_eq!(apply_count(&handle).await, 0);

        // A prepared-byte total exactly at the cap succeeds.
        let (store, _) = replay_store(vec![
            head_response(genesis_ref()),
            event_response(GENESIS_BYTES),
        ]);
        replay_with_limits(
            &store,
            &handle,
            Limits {
                events: 1,
                bytes: GENESIS_BYTES.len(),
            },
        )
        .await
        .unwrap();
        assert_eq!(apply_count(&handle).await, 1);

        drop(handle);
        clean(&path);
    }

    fn not_ready_reason(readiness: Readiness) -> NotReadyReason {
        match readiness {
            Readiness::NotReady(reason) => reason,
            Readiness::Ready { .. } => panic!("expected not ready"),
        }
    }

    fn assert_ready(readiness: Readiness, cursor: (u64, &str), expected_head: &Head) {
        match readiness {
            Readiness::Ready {
                local_cursor,
                observed_head,
            } => {
                assert_eq!(local_cursor, (cursor.0, cursor.1.to_owned()));
                assert_eq!(observed_head.head(), expected_head);
            }
            Readiness::NotReady(reason) => panic!("expected ready, got {reason:?}"),
        }
    }

    #[test]
    fn cursor_comparison_outcomes_are_typed() {
        let observed_head = head_value(child_ref());
        for (local_cursor, expected) in [
            ((1, Some(GENESIS_DIGEST.to_owned())), NotReadyReason::Behind),
            ((3, Some("3".repeat(64))), NotReadyReason::Ahead),
            (
                (2, Some(GENESIS_DIGEST.to_owned())),
                NotReadyReason::TailMismatch,
            ),
        ] {
            assert_eq!(compare_cursor(&observed_head, local_cursor), Err(expected));
        }
        assert_eq!(
            compare_cursor(&observed_head, (2, Some(CHILD_DIGEST.to_owned()))),
            Ok((2, CHILD_DIGEST.to_owned()))
        );
    }

    #[tokio::test]
    async fn refresh_is_ready_only_for_its_successful_head_observation() {
        let path = path("refresh");
        clean(&path);
        let handle = DbHandle::spawn(path.clone()).await.unwrap();
        let expected_head = head_value(child_ref());
        let (store, _) = replay_store(vec![
            head_response(child_ref()),
            event_response(CHILD_BYTES),
            event_response(GENESIS_BYTES),
        ]);
        assert_ready(
            refresh(&store, &handle).await,
            (2, CHILD_DIGEST),
            &expected_head,
        );

        let (store, _) = replay_store(vec![response(404, &[], SdkBody::empty())]);
        assert_eq!(
            not_ready_reason(refresh(&store, &handle).await),
            NotReadyReason::Replay(ReplayError::CampaignMissing)
        );

        drop(handle);
        clean(&path);
    }

    #[tokio::test]
    async fn advanced_head_is_not_ready_until_ancestry_is_available() {
        let path = path("advanced-head");
        clean(&path);
        let handle = DbHandle::spawn(path.clone()).await.unwrap();
        handle
            .apply(fixture_mutation(GENESIS_BYTES, genesis_ref()))
            .await
            .unwrap();

        let (store, _) = replay_store(vec![
            head_response(child_ref()),
            response(404, &[], SdkBody::empty()),
        ]);
        assert_eq!(
            not_ready_reason(refresh(&store, &handle).await),
            NotReadyReason::Replay(ReplayError::EventMissing)
        );

        let expected_head = head_value(child_ref());
        let (store, _) = replay_store(vec![
            head_response(child_ref()),
            event_response(CHILD_BYTES),
        ]);
        assert_ready(
            refresh(&store, &handle).await,
            (2, CHILD_DIGEST),
            &expected_head,
        );

        drop(handle);
        clean(&path);
    }

    #[tokio::test]
    async fn a_cursor_ahead_of_the_head_reads_as_ahead_not_a_replay_error() {
        let path = path("ahead-cursor");
        clean(&path);
        let handle = DbHandle::spawn(path.clone()).await.unwrap();
        handle
            .apply(fixture_mutation(GENESIS_BYTES, genesis_ref()))
            .await
            .unwrap();
        handle
            .apply(fixture_mutation(CHILD_BYTES, child_ref()))
            .await
            .unwrap();

        let (store, _) = replay_store(vec![head_response(genesis_ref())]);
        assert_eq!(
            not_ready_reason(refresh(&store, &handle).await),
            NotReadyReason::Ahead
        );

        drop(handle);
        clean(&path);
    }

    #[tokio::test]
    async fn refresh_keeps_wire_version_and_digest_failures_distinct() {
        let mut cbor = zstd::bulk::decompress(GENESIS_BYTES, 1024 * 1024).unwrap();
        let version = cbor
            .windows(7)
            .position(|window| window == b"version")
            .unwrap()
            + 7;
        assert_eq!(cbor[version], 1);
        cbor[version] = 2;
        let unknown_version = zstd::bulk::compress(&cbor, 3).unwrap();
        let unknown_digest = format!("{:x}", Sha256::digest(&unknown_version));
        let cases = [
            (
                "refresh-version",
                head_response(reference(1, &unknown_digest)),
                event_response(unknown_version),
                WireError::InvalidValue,
            ),
            (
                "refresh-digest",
                head_response(genesis_ref()),
                event_response(CHILD_BYTES),
                WireError::ReferenceMismatch,
            ),
        ];

        for (label, head, event, expected) in cases {
            let path = path(label);
            clean(&path);
            let handle = DbHandle::spawn(path.clone()).await.unwrap();
            let (store, _) = replay_store(vec![head, event]);
            assert_eq!(
                not_ready_reason(refresh(&store, &handle).await),
                NotReadyReason::Replay(ReplayError::EventInvalid(expected))
            );
            drop(handle);
            clean(&path);
        }
    }

    #[tokio::test]
    async fn fresh_and_incremental_replay_have_equivalent_query_state() {
        let fresh_path = path("equivalence-fresh");
        let incremental_path = path("equivalence-incremental");
        clean(&fresh_path);
        clean(&incremental_path);

        let (fresh_store, _) = replay_store(vec![
            head_response(child_ref()),
            event_response(CHILD_BYTES),
            event_response(GENESIS_BYTES),
        ]);
        let fresh = startup(&fresh_store, &fresh_path)
            .await
            .unwrap()
            .into_handle();

        let incremental = DbHandle::spawn(incremental_path.clone()).await.unwrap();
        incremental
            .apply(fixture_mutation(GENESIS_BYTES, genesis_ref()))
            .await
            .unwrap();
        let (incremental_store, _) = replay_store(vec![
            head_response(child_ref()),
            event_response(CHILD_BYTES),
        ]);
        assert!(matches!(
            refresh(&incremental_store, &incremental).await,
            Readiness::Ready { .. }
        ));

        let capabilities = vec!["rust".to_owned()];
        let fresh_ready = fresh
            .list_ready_work("0000000000000001".into(), capabilities.clone(), 10, None)
            .await
            .unwrap();
        let incremental_ready = incremental
            .list_ready_work("0000000000000001".into(), capabilities, 10, None)
            .await
            .unwrap();
        assert!(fresh_ready.is_empty());
        assert_eq!(fresh_ready, incremental_ready);
        let fresh_connection = schema::open_existing(&fresh_path).unwrap();
        let incremental_connection = schema::open_existing(&incremental_path).unwrap();
        assert_eq!(
            snapshot(&fresh_connection),
            snapshot(&incremental_connection)
        );

        drop(fresh_connection);
        drop(incremental_connection);
        drop(fresh);
        drop(incremental);
        clean(&fresh_path);
        clean(&incremental_path);
    }

    #[tokio::test]
    async fn missing_head_leaves_a_valid_genesis_projection() {
        let path = path("missing-head");
        clean(&path);
        let (store, _) = replay_store(vec![response(404, &[], SdkBody::empty())]);
        assert_eq!(
            startup(&store, &path).await.err(),
            Some(ReplayError::CampaignMissing)
        );
        let connection = schema::open_existing(&path).unwrap();
        assert_eq!(
            connection
                .query_row("SELECT sequence FROM sync_cursor WHERE id = 1", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
            0
        );
        drop(connection);
        clean(&path);
    }

    #[tokio::test]
    async fn invalid_local_projection_is_replaced_and_replayed() {
        let path = path("replace-success");
        clean(&path);
        let connection = schema::create(&path).unwrap();
        connection
            .execute(
                "INSERT INTO campaigns (campaign_id, state) VALUES ('old', 'active')",
                [],
            )
            .unwrap();
        connection.pragma_update(None, "user_version", 1).unwrap();
        drop(connection);
        fs::write(journal_path(&path), b"stale").unwrap();
        let (store, _) = replay_store(vec![
            head_response(child_ref()),
            event_response(CHILD_BYTES),
            event_response(GENESIS_BYTES),
        ]);

        let handle = startup(&store, &path).await.unwrap().into_handle();
        assert_eq!(
            handle.cursor().await.unwrap(),
            (2, Some(CHILD_DIGEST.into()))
        );
        assert!(!journal_path(&path).exists());
        drop(handle);
        let connection = schema::open_existing(&path).unwrap();
        assert_eq!(
            connection
                .query_row(
                    "SELECT count(*) FROM campaigns WHERE campaign_id = 'old'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
        drop(connection);
        clean(&path);
    }

    #[tokio::test]
    async fn failed_replacement_never_restores_invalid_local_data() {
        let path = path("replace-failure");
        clean(&path);
        let connection = schema::create(&path).unwrap();
        connection
            .execute(
                "INSERT INTO campaigns (campaign_id, state) VALUES ('old', 'active')",
                [],
            )
            .unwrap();
        connection.pragma_update(None, "user_version", 99).unwrap();
        drop(connection);
        let (store, _) = replay_store(vec![
            head_response(child_ref()),
            response(404, &[], SdkBody::empty()),
        ]);

        assert_eq!(
            startup(&store, &path).await.err(),
            Some(ReplayError::EventMissing)
        );
        let connection = schema::open_existing(&path).unwrap();
        assert_eq!(
            connection
                .query_row(
                    "SELECT count(*) FROM campaigns WHERE campaign_id = 'old'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
        drop(connection);
        clean(&path);
    }
}
