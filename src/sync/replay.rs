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
    domain::campaign::EventRef,
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
    /// The remote history disagrees with the local cursor or applied events.
    HistoryConflict,
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
        let (head, cursor) = replay_with_limits(store, &handle, LIMITS).await?;
        return Ok(ReplayedProjection {
            handle,
            head,
            cursor,
        });
    }

    match DbHandle::open_existing(db_path.to_path_buf()).await {
        Ok(handle) => {
            let (head, cursor) = replay_with_limits(store, &handle, LIMITS).await?;
            Ok(ReplayedProjection {
                handle,
                head,
                cursor,
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
    let (head, cursor) = replay_with_limits(store, &handle, LIMITS).await?;
    Ok(ReplayedProjection {
        handle,
        head,
        cursor,
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
) -> Result<(ObservedHead, (u64, Option<String>)), ReplayError> {
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
        match handle.apply(mutation).await {
            Ok(ApplyOutcome::Applied | ApplyOutcome::AlreadyApplied) => {}
            Err(error) => return Err(ReplayError::Apply(error)),
        }
    }
    let cursor = handle
        .cursor()
        .await
        .map_err(|_| ReplayError::DatabaseUnavailable)?;
    Ok((observed, cursor))
}

async fn prepare(
    store: &S3Store,
    cursor: (u64, Option<String>),
    tail: EventRef,
    limits: Limits,
) -> Result<Vec<SchedulingMutation>, ReplayError> {
    let (cursor_sequence, cursor_digest) = cursor;
    if tail.sequence() < cursor_sequence {
        return Err(ReplayError::HistoryConflict);
    }
    if tail.sequence() == cursor_sequence {
        return if cursor_digest.as_deref() == Some(tail.digest()) {
            Ok(Vec::new())
        } else {
            Err(ReplayError::HistoryConflict)
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
mod tests {
    use std::{fs, process};

    use aws_sdk_s3::primitives::SdkBody;
    use sha2::{Digest, Sha256};

    use crate::{
        db::{schema, worker::DbHandle},
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

    fn head_response(tail: EventRef) -> http::Response<SdkBody> {
        let value = Head::new(Authority::unowned(), tail, "head-operation".into()).unwrap();
        response(
            200,
            &[("etag", "\"head-etag\"")],
            head::encode(&value).unwrap(),
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
            Some(ReplayError::HistoryConflict)
        );
        assert_eq!(apply_count(&handle).await, 2);
        assert_gets(&client, &["head.json"]);

        // A head at the cursor sequence with a different digest is a history conflict.
        let (store, client) = replay_store(vec![head_response(reference(2, GENESIS_DIGEST))]);
        assert_eq!(
            replay_with_limits(&store, &handle, LIMITS).await.err(),
            Some(ReplayError::HistoryConflict)
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
            .execute("INSERT INTO campaigns (campaign_id) VALUES ('old')", [])
            .unwrap();
        connection.pragma_update(None, "user_version", 2).unwrap();
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
            .execute("INSERT INTO campaigns (campaign_id) VALUES ('old')", [])
            .unwrap();
        connection.pragma_update(None, "user_version", 2).unwrap();
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
