//! Shared replay-accelerator objects: packs, catalogs, the current pointer, and
//! checkpoint snapshots.
//!
//! Replay climbs a fail-closed ladder: a cold open may install a certified checkpoint
//! plus its packed suffix, and a refresh tries packed events, then LIST-assisted reads,
//! then the serial event walk. Every object here is a hint. `head` and the exact
//! `events/` ancestry remain the only commitment authority: a missing, stale, malformed,
//! corrupt, or conflicting accelerator object makes a reader fall through to a slower
//! rung without changing any projection.
//!
//! Three canonical-CBOR formats — a pack of at most 256 events and an 8 MiB event
//! section, a catalog of sorted non-overlapping pack rows plus checkpoint-certificate
//! references, and the current pointer naming one catalog digest — reject unknown fields
//! and require exact re-encoding; a raw SQLite snapshot is certified separately by a
//! `projection_checkpoint_published` event. Packs embed the exact stored `.cbor.zst`
//! event bytes, never re-encodings, so each embedded event re-hashes to its stored
//! reference, synthesizes its exact event key, and passes the canonical event decoder
//! unchanged: a pack cannot smuggle bytes that differ from `events/`.
//!
//! Packs, catalogs, and snapshots are content-addressed and publish create-only
//! (`If-None-Match: *`), so duplicate publication is idempotent. `replay-index/current`
//! is the one mutable object: created with `put_if_absent`, CAS-replaced with
//! `put_if_match` on its GET ETag. Publication is best effort because read-side
//! validation is the correctness boundary: a publisher that fails, races, or loses the
//! pointer CAS leaves at worst a stale pointer or orphaned immutable objects, never a
//! wrong replay.

use std::{error::Error, fmt, io::Cursor, num::NonZeroUsize, path::Path};

use ciborium::{de::from_reader_with_recursion_limit, ser::into_writer};
use serde::{Deserialize, Serialize};

use crate::{
    db::{projections::ApplyError, worker::DbHandle},
    dispatch::AttemptHistory,
    distributed::claims::bounded_map,
    scope::{
        DecodedScopeEvent, Digest, MAX_COMPRESSED_BYTES, ProjectionCheckpointPayload,
        ScopeEventRef, ScopeIdentity, decode_scope_event, scope_event_key, sha256,
    },
    storage::s3::{ETag, GetOutcome, MutationOutcome, S3Store},
    sync::WireError,
};

use super::head::{self, ScopeAppendError, ScopeHeadCommitOutcome, ScopeHeadParent};

/// Most events one pack may embed.
pub const MAX_PACK_EVENTS: usize = 256;
/// Largest concatenated event-byte section one pack may embed.
pub const MAX_PACK_EVENT_BYTES: usize = 8 * 1024 * 1024;
/// Largest checkpoint snapshot one certificate may name.
pub const MAX_SNAPSHOT_BYTES: usize = 64 * 1024 * 1024;
/// Read cap for one pack object: the event section plus bounded framing.
const MAX_PACK_OBJECT_BYTES: usize = MAX_PACK_EVENT_BYTES + 64 * 1024;
const MAX_POINTER_BYTES: usize = 4 * 1024;
const MAX_CATALOG_BYTES: usize = 1024 * 1024;
/// Caps lifetime catalog rows (one appended batch per advancing refresh), not sequences; a catalog at the cap refuses new rows while replay stays correct. commentlint: allow(JUDGE)
const MAX_CATALOG_ROWS: usize = crate::sync::replay::MAX_SCOPE_REPLAY_EVENTS as usize;
/// Accumulated bytes one accelerator read may fetch; matches the replay byte budget. commentlint: allow(JUDGE)
const MAX_FETCH_BYTES: usize = 64 * 1024 * 1024;
/// Packs one replay may publish.
///
/// Publication is awaited on the readiness path, so the batch is bounded rather than sized to
/// the replay: a full-limit replay would otherwise issue sixteen sequential object writes
/// before its scope could report ready.
const MAX_PUBLISHED_PACKS_PER_REPLAY: usize = 4;
const CBOR_RECURSION_LIMIT: usize = 16;
const FORMAT_VERSION: u64 = 1;
/// Fixed remote-read concurrency, matching the repository's bounded-read policy.
pub(crate) const CONCURRENT_FETCHES: NonZeroUsize = NonZeroUsize::new(4).unwrap();

/// One decoded event beside the exact compressed bytes it was stored as.
pub(crate) struct StoredEvent {
    pub(crate) decoded: DecodedScopeEvent<ciborium::Value>,
    pub(crate) bytes: Vec<u8>,
}

fn scope_prefix(scope: &ScopeIdentity) -> String {
    format!(
        "workspace/{}/campaigns/{}/scopes/{}",
        scope.workspace_id().as_str(),
        scope.campaign_id().as_str(),
        scope.scope_id().as_str()
    )
}

/// Builds the prefix every stored event key of `scope` shares.
pub fn scope_events_prefix(scope: &ScopeIdentity) -> String {
    format!("{}/events/", scope_prefix(scope))
}

/// Builds the content-addressed key of one replay pack.
pub fn replay_pack_key(scope: &ScopeIdentity, start: u64, end: u64, digest: &Digest) -> String {
    format!(
        "{}/replay-packs/{start:016}-{end:016}-{}",
        scope_prefix(scope),
        digest.as_str()
    )
}

/// Builds the content-addressed key of one replay catalog.
pub fn replay_catalog_key(scope: &ScopeIdentity, digest: &Digest) -> String {
    format!("{}/replay-index/{}", scope_prefix(scope), digest.as_str())
}

/// Builds the single mutable pointer key naming the current catalog.
pub fn replay_pointer_key(scope: &ScopeIdentity) -> String {
    format!("{}/replay-index/current", scope_prefix(scope))
}

/// Builds the key of one immutable checkpoint snapshot.
pub fn scope_checkpoint_key(
    scope: &ScopeIdentity,
    covered_sequence: u64,
    snapshot_digest: &Digest,
) -> String {
    format!(
        "{}/checkpoints/{covered_sequence:016}-{}",
        scope_prefix(scope),
        snapshot_digest.as_str()
    )
}

/// Concatenated event bytes encoded as one CBOR byte string.
struct EventSection(Vec<u8>);

impl Serialize for EventSection {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for EventSection {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl serde::de::Visitor<'_> for Visitor {
            type Value = EventSection;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a byte string")
            }

            fn visit_bytes<E: serde::de::Error>(self, bytes: &[u8]) -> Result<Self::Value, E> {
                Ok(EventSection(bytes.to_vec()))
            }

            fn visit_byte_buf<E: serde::de::Error>(self, bytes: Vec<u8>) -> Result<Self::Value, E> {
                Ok(EventSection(bytes))
            }
        }
        deserializer.deserialize_byte_buf(Visitor)
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireEventRef {
    sequence: u64,
    digest: String,
}

impl WireEventRef {
    fn from_ref(reference: &ScopeEventRef) -> Self {
        Self {
            sequence: reference.sequence(),
            digest: reference.digest().as_str().to_owned(),
        }
    }

    fn into_ref(self) -> Result<ScopeEventRef, WireError> {
        ScopeEventRef::new(
            self.sequence,
            Digest::new(self.digest).map_err(|_| WireError::InvalidValue)?,
        )
        .map_err(|_| WireError::InvalidValue)
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WirePack {
    version: u64,
    scope_id: String,
    start_sequence: u64,
    end_sequence: u64,
    parent_event: Option<WireEventRef>,
    final_event: WireEventRef,
    event_count: u64,
    offsets: Vec<u64>,
    events: EventSection,
    events_digest: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireCatalogEntry {
    start: u64,
    end: u64,
    pack_digest: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireCatalog {
    version: u64,
    scope_id: String,
    packs: Vec<WireCatalogEntry>,
    checkpoints: Vec<WireEventRef>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WirePointer {
    version: u64,
    scope_id: String,
    catalog_digest: String,
}

/// Canonical pack bytes beside the digest and range that address them.
#[derive(Debug, Eq, PartialEq)]
pub struct EncodedPack {
    bytes: Vec<u8>,
    digest: Digest,
    start: u64,
    end: u64,
}

impl EncodedPack {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    pub fn start(&self) -> u64 {
        self.start
    }

    pub fn end(&self) -> u64 {
        self.end
    }

    pub fn key(&self, scope: &ScopeIdentity) -> String {
        replay_pack_key(scope, self.start, self.end, &self.digest)
    }
}

/// One validated decoded pack; embedded events remain untrusted until re-decoded.
#[derive(Debug, Eq, PartialEq)]
pub struct ReplayPack {
    start: u64,
    end: u64,
    parent_event: Option<ScopeEventRef>,
    final_event: ScopeEventRef,
    offsets: Vec<usize>,
    events: Vec<u8>,
}

impl ReplayPack {
    pub fn start(&self) -> u64 {
        self.start
    }

    pub fn end(&self) -> u64 {
        self.end
    }

    pub fn parent_event(&self) -> Option<&ScopeEventRef> {
        self.parent_event.as_ref()
    }

    pub fn final_event(&self) -> &ScopeEventRef {
        &self.final_event
    }

    pub fn event_count(&self) -> usize {
        self.offsets.len() - 1
    }

    /// Returns the exact stored bytes of the embedded event at `index`.
    ///
    /// # Panics
    ///
    /// Panics when `index` is at or above [`ReplayPack::event_count`].
    pub fn event_bytes(&self, index: usize) -> &[u8] {
        &self.events[self.offsets[index]..self.offsets[index + 1]]
    }
}

/// Builds one canonical pack from exact stored event bytes in chain order.
///
/// `parent` is the reference immediately before the first event and must be absent exactly
/// at genesis. Sequences are `start`, `start + 1`, and so on; digests are recomputed from
/// the supplied bytes, so a caller cannot claim a digest the bytes do not carry.
///
/// # Errors
///
/// Returns [`WireError::InvalidValue`] for an empty set, more than 256 events, a
/// parent/start mismatch, or an unrepresentable sequence, [`WireError::LimitExceeded`]
/// above the 8 MiB event-section cap, and encoding failures verbatim.
pub fn build_pack(
    scope: &ScopeIdentity,
    parent: Option<&ScopeEventRef>,
    start: u64,
    events: &[&[u8]],
) -> Result<EncodedPack, WireError> {
    if events.is_empty() || events.len() > MAX_PACK_EVENTS {
        return Err(WireError::InvalidValue);
    }
    match parent {
        None if start == 1 => {}
        Some(parent) if parent.sequence().checked_add(1) == Some(start) => {}
        _ => return Err(WireError::InvalidValue),
    }
    let end = start
        .checked_add(events.len() as u64 - 1)
        .ok_or(WireError::InvalidValue)?;
    let mut offsets = Vec::with_capacity(events.len() + 1);
    let mut section = Vec::new();
    offsets.push(0_u64);
    for bytes in events {
        if bytes.is_empty() {
            return Err(WireError::InvalidValue);
        }
        section.extend_from_slice(bytes);
        if section.len() > MAX_PACK_EVENT_BYTES {
            return Err(WireError::LimitExceeded);
        }
        offsets.push(section.len() as u64);
    }
    let final_digest =
        Digest::new(sha256(events[events.len() - 1])).map_err(|_| WireError::InvalidValue)?;
    let final_event = ScopeEventRef::new(end, final_digest).map_err(|_| WireError::InvalidValue)?;
    let wire = WirePack {
        version: FORMAT_VERSION,
        scope_id: scope.scope_id().as_str().to_owned(),
        start_sequence: start,
        end_sequence: end,
        parent_event: parent.map(WireEventRef::from_ref),
        final_event: WireEventRef::from_ref(&final_event),
        event_count: events.len() as u64,
        offsets,
        events_digest: sha256(&section),
        events: EventSection(section),
    };
    let bytes = encode_cbor(&wire)?;
    let digest = Digest::new(sha256(&bytes)).map_err(|_| WireError::InvalidValue)?;
    Ok(EncodedPack {
        bytes,
        digest,
        start,
        end,
    })
}

/// Decodes one pack after recomputing its object digest.
///
/// # Errors
///
/// Returns [`WireError::ReferenceMismatch`] when the bytes do not hash to
/// `expected_digest`, and framing, canonicality, scope, range, offset, checksum, or limit
/// failures as their [`WireError`] categories.
pub fn decode_pack(
    bytes: &[u8],
    expected_digest: &Digest,
    expected_scope: &ScopeIdentity,
) -> Result<ReplayPack, WireError> {
    if bytes.is_empty() || bytes.len() > MAX_PACK_OBJECT_BYTES {
        return Err(WireError::LimitExceeded);
    }
    if sha256(bytes) != expected_digest.as_str() {
        return Err(WireError::ReferenceMismatch);
    }
    let wire: WirePack = decode_cbor(bytes)?;
    if wire.version != FORMAT_VERSION
        || wire.scope_id != expected_scope.scope_id().as_str()
        || wire.start_sequence == 0
        || wire.end_sequence < wire.start_sequence
    {
        return Err(WireError::InvalidValue);
    }
    let count = wire.end_sequence - wire.start_sequence + 1;
    if count > MAX_PACK_EVENTS as u64 || wire.event_count != count {
        return Err(WireError::InvalidValue);
    }
    let count = count as usize;
    if wire.offsets.len() != count + 1 || wire.offsets[0] != 0 {
        return Err(WireError::InvalidValue);
    }
    let section = wire.events.0;
    if section.len() > MAX_PACK_EVENT_BYTES {
        return Err(WireError::LimitExceeded);
    }
    let mut offsets = Vec::with_capacity(count + 1);
    for offset in &wire.offsets {
        let offset = usize::try_from(*offset).map_err(|_| WireError::InvalidValue)?;
        if offsets.last().is_some_and(|prev| offset <= *prev) || offset > section.len() {
            return Err(WireError::InvalidValue);
        }
        offsets.push(offset);
    }
    if offsets[count] != section.len() {
        return Err(WireError::InvalidValue);
    }
    if wire.events_digest != sha256(&section) {
        return Err(WireError::InvalidValue);
    }
    let parent_event = match (wire.parent_event, wire.start_sequence) {
        (None, 1) => None,
        (Some(parent), start) if start > 1 => {
            let parent = parent.into_ref()?;
            if parent.sequence() + 1 != start {
                return Err(WireError::InvalidValue);
            }
            Some(parent)
        }
        _ => return Err(WireError::InvalidValue),
    };
    let final_event = wire.final_event.into_ref()?;
    if final_event.sequence() != wire.end_sequence
        || final_event.digest().as_str() != sha256(&section[offsets[count - 1]..])
    {
        return Err(WireError::InvalidValue);
    }
    Ok(ReplayPack {
        start: wire.start_sequence,
        end: wire.end_sequence,
        parent_event,
        final_event,
        offsets,
        events: section,
    })
}

/// One catalog row naming a pack by its covered range and object digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackEntry {
    start: u64,
    end: u64,
    digest: Digest,
}

impl PackEntry {
    /// # Errors
    ///
    /// Returns [`WireError::InvalidValue`] when `start == 0`, `end < start`, or the range
    /// is wider than [`MAX_PACK_EVENTS`].
    pub fn new(start: u64, end: u64, digest: Digest) -> Result<Self, WireError> {
        if start == 0 || end < start || end - start + 1 > MAX_PACK_EVENTS as u64 {
            return Err(WireError::InvalidValue);
        }
        Ok(Self { start, end, digest })
    }

    pub fn start(&self) -> u64 {
        self.start
    }

    pub fn end(&self) -> u64 {
        self.end
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    fn overlaps(&self, other: &Self) -> bool {
        self.start <= other.end && other.start <= self.end
    }

    /// Whether this row's range contains all of `other`'s.
    fn covers(&self, other: &Self) -> bool {
        self.start <= other.start && other.end <= self.end
    }
}

/// One validated catalog: sorted non-overlapping pack rows plus checkpoint certificates.
#[derive(Debug, Eq, PartialEq)]
pub struct ReplayCatalog {
    entries: Vec<PackEntry>,
    checkpoints: Vec<ScopeEventRef>,
}

impl ReplayCatalog {
    pub fn entries(&self) -> &[PackEntry] {
        &self.entries
    }

    /// Checkpoint certificate references in ascending sequence order.
    pub fn checkpoints(&self) -> &[ScopeEventRef] {
        &self.checkpoints
    }
}

fn rows_valid(entries: &[PackEntry], checkpoints: &[ScopeEventRef]) -> bool {
    entries.len() <= MAX_CATALOG_ROWS
        && checkpoints.len() <= MAX_CATALOG_ROWS
        && entries.windows(2).all(|pair| pair[0].end < pair[1].start)
        && checkpoints
            .windows(2)
            .all(|pair| pair[0].sequence() < pair[1].sequence())
}

/// Encodes one canonical catalog, returning its bytes and content digest.
///
/// # Errors
///
/// Returns [`WireError::InvalidValue`] for unsorted or overlapping rows,
/// [`WireError::LimitExceeded`] when the encoding exceeds `MAX_CATALOG_BYTES`, and
/// encoding failures verbatim.
pub fn encode_catalog(
    scope: &ScopeIdentity,
    entries: &[PackEntry],
    checkpoints: &[ScopeEventRef],
) -> Result<(Vec<u8>, Digest), WireError> {
    if !rows_valid(entries, checkpoints) {
        return Err(WireError::InvalidValue);
    }
    let wire = WireCatalog {
        version: FORMAT_VERSION,
        scope_id: scope.scope_id().as_str().to_owned(),
        packs: entries
            .iter()
            .map(|entry| WireCatalogEntry {
                start: entry.start,
                end: entry.end,
                pack_digest: entry.digest.as_str().to_owned(),
            })
            .collect(),
        checkpoints: checkpoints.iter().map(WireEventRef::from_ref).collect(),
    };
    let bytes = encode_cbor(&wire)?;
    if bytes.len() > MAX_CATALOG_BYTES {
        return Err(WireError::LimitExceeded);
    }
    let digest = Digest::new(sha256(&bytes)).map_err(|_| WireError::InvalidValue)?;
    Ok((bytes, digest))
}

/// Decodes one catalog after recomputing its content digest.
///
/// # Errors
///
/// Returns [`WireError::ReferenceMismatch`] when the bytes do not hash to
/// `expected_digest`, and framing, canonicality, scope, ordering, or limit failures as
/// their [`WireError`] categories.
pub fn decode_catalog(
    bytes: &[u8],
    expected_digest: &Digest,
    expected_scope: &ScopeIdentity,
) -> Result<ReplayCatalog, WireError> {
    if bytes.is_empty() || bytes.len() > MAX_CATALOG_BYTES {
        return Err(WireError::LimitExceeded);
    }
    if sha256(bytes) != expected_digest.as_str() {
        return Err(WireError::ReferenceMismatch);
    }
    let wire: WireCatalog = decode_cbor(bytes)?;
    if wire.version != FORMAT_VERSION || wire.scope_id != expected_scope.scope_id().as_str() {
        return Err(WireError::InvalidValue);
    }
    let entries = wire
        .packs
        .into_iter()
        .map(|entry| {
            PackEntry::new(
                entry.start,
                entry.end,
                Digest::new(entry.pack_digest).map_err(|_| WireError::InvalidValue)?,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let checkpoints = wire
        .checkpoints
        .into_iter()
        .map(WireEventRef::into_ref)
        .collect::<Result<Vec<_>, _>>()?;
    if !rows_valid(&entries, &checkpoints) {
        return Err(WireError::InvalidValue);
    }
    Ok(ReplayCatalog {
        entries,
        checkpoints,
    })
}

/// Encodes the canonical current pointer naming `catalog_digest`.
///
/// # Errors
///
/// Returns encoding failures verbatim.
pub fn encode_pointer(
    scope: &ScopeIdentity,
    catalog_digest: &Digest,
) -> Result<Vec<u8>, WireError> {
    encode_cbor(&WirePointer {
        version: FORMAT_VERSION,
        scope_id: scope.scope_id().as_str().to_owned(),
        catalog_digest: catalog_digest.as_str().to_owned(),
    })
}

/// Decodes the current pointer, returning the catalog digest it names.
///
/// # Errors
///
/// Returns framing, canonicality, scope, or limit failures as their [`WireError`]
/// categories.
pub fn decode_pointer(bytes: &[u8], expected_scope: &ScopeIdentity) -> Result<Digest, WireError> {
    if bytes.is_empty() || bytes.len() > MAX_POINTER_BYTES {
        return Err(WireError::LimitExceeded);
    }
    let wire: WirePointer = decode_cbor(bytes)?;
    if wire.version != FORMAT_VERSION || wire.scope_id != expected_scope.scope_id().as_str() {
        return Err(WireError::InvalidValue);
    }
    Digest::new(wire.catalog_digest).map_err(|_| WireError::InvalidValue)
}

fn encode_cbor<T: Serialize>(value: &T) -> Result<Vec<u8>, WireError> {
    let mut bytes = Vec::new();
    into_writer(value, &mut bytes).map_err(|_| WireError::InvalidEncoding)?;
    Ok(bytes)
}

fn decode_cbor<T: Serialize + serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, WireError> {
    let mut reader = Cursor::new(bytes);
    let value: T = from_reader_with_recursion_limit(&mut reader, CBOR_RECURSION_LIMIT)
        .map_err(|_| WireError::InvalidEncoding)?;
    if reader.position() != bytes.len() as u64 {
        return Err(WireError::NonCanonical);
    }
    if encode_cbor(&value)? != bytes {
        return Err(WireError::NonCanonical);
    }
    Ok(value)
}

/// Reads and validates the current pointer and the catalog it names.
///
/// [`CurrentCatalog::Present`] carries the pointer's ETag for CAS replacement by a
/// publisher; readers treat every other state as an accelerator miss.
pub(crate) async fn read_current_catalog(store: &S3Store, scope: &ScopeIdentity) -> CurrentCatalog {
    let (bytes, etag) = match store
        .get_object(&replay_pointer_key(scope), MAX_POINTER_BYTES)
        .await
    {
        Ok(GetOutcome::Found { bytes, etag }) => (bytes, etag),
        Ok(GetOutcome::NotFound) => return CurrentCatalog::Absent,
        Err(_) => return CurrentCatalog::Unusable,
    };
    let Ok(catalog_digest) = decode_pointer(&bytes, scope) else {
        return CurrentCatalog::Unusable;
    };
    let catalog_bytes = match store
        .get_object(
            &replay_catalog_key(scope, &catalog_digest),
            MAX_CATALOG_BYTES,
        )
        .await
    {
        Ok(GetOutcome::Found { bytes, .. }) => bytes,
        Ok(GetOutcome::NotFound) | Err(_) => return CurrentCatalog::Unusable,
    };
    match decode_catalog(&catalog_bytes, &catalog_digest, scope) {
        Ok(catalog) => CurrentCatalog::Present(catalog, etag),
        Err(_) => CurrentCatalog::Unusable,
    }
}

pub(crate) enum CurrentCatalog {
    /// No pointer object exists.
    Absent,
    /// The pointer or the catalog it names is unreadable, malformed, or wrong-scope.
    Unusable,
    Present(ReplayCatalog, ETag),
}

/// Chooses contiguous catalog rows whose union covers `first..=last`.
fn coverage(catalog: &ReplayCatalog, first: u64, last: u64) -> Option<Vec<&PackEntry>> {
    let mut chosen: Vec<&PackEntry> = Vec::new();
    let mut next = first;
    for entry in catalog.entries() {
        if chosen.is_empty() {
            if entry.end < first {
                continue;
            }
            if entry.start > first {
                return None;
            }
        } else if entry.start != next {
            return None;
        }
        chosen.push(entry);
        if entry.end >= last {
            return Some(chosen);
        }
        next = entry.end + 1;
    }
    None
}

/// Reads packed events covering `first..=last` through the validated catalog.
///
/// Every embedded event is re-hashed, assigned its synthesized event key, and passed
/// through the canonical event decoder. Events below `first` or above `last` inside a
/// covering pack are ignored. `None` is an accelerator miss.
pub(crate) async fn packed_events(
    store: &S3Store,
    scope: &ScopeIdentity,
    first: u64,
    last: u64,
) -> Option<Vec<StoredEvent>> {
    let CurrentCatalog::Present(catalog, _) = read_current_catalog(store, scope).await else {
        return None;
    };
    packed_events_from_catalog(store, scope, &catalog, first, last).await
}

/// Reads packed events through an already validated `catalog`, sparing a reread of the
/// pointer when the caller holds one.
///
/// The range guards run before any request: `first == 0`, an inverted interval, or a
/// span wider than one replay (4,096 events) is a miss. The 64 MiB pack budget is
/// enforced while fetching, so a lying catalog cannot buffer unbounded bytes.
pub(crate) async fn packed_events_from_catalog(
    store: &S3Store,
    scope: &ScopeIdentity,
    catalog: &ReplayCatalog,
    first: u64,
    last: u64,
) -> Option<Vec<StoredEvent>> {
    if first == 0 || last < first || last - first + 1 > crate::sync::replay::MAX_SCOPE_REPLAY_EVENTS
    {
        return None;
    }
    let chosen = coverage(catalog, first, last)?;
    let mut packs = Vec::with_capacity(chosen.len());
    let mut total_bytes = 0_usize;
    for window in chosen.chunks(CONCURRENT_FETCHES.get()) {
        let fetched = bounded_map(window.len(), CONCURRENT_FETCHES, |index| {
            let entry = window[index];
            async move {
                let key = replay_pack_key(scope, entry.start(), entry.end(), entry.digest());
                match store.get_object(&key, MAX_PACK_OBJECT_BYTES).await {
                    Ok(GetOutcome::Found { bytes, .. }) => Some(bytes),
                    Ok(GetOutcome::NotFound) | Err(_) => None,
                }
            }
        })
        .await;
        for bytes in fetched {
            let bytes = bytes?;
            total_bytes = total_bytes.checked_add(bytes.len())?;
            if total_bytes > MAX_FETCH_BYTES {
                return None;
            }
            packs.push(bytes);
        }
    }
    let mut events = Vec::new();
    let mut expected = first;
    for (entry, bytes) in chosen.iter().zip(packs) {
        let pack = decode_pack(&bytes, entry.digest(), scope).ok()?;
        if pack.start() != entry.start() || pack.end() != entry.end() {
            return None;
        }
        for index in 0..pack.event_count() {
            let sequence = pack.start() + index as u64;
            if sequence < expected || sequence > last {
                continue;
            }
            events.push(verify_embedded(scope, sequence, pack.event_bytes(index))?);
            expected = sequence + 1;
        }
    }
    (expected == last + 1).then_some(events)
}

/// Re-hashes one embedded slice and decodes it against its synthesized event key.
fn verify_embedded(scope: &ScopeIdentity, sequence: u64, bytes: &[u8]) -> Option<StoredEvent> {
    let digest = Digest::new(sha256(bytes)).ok()?;
    let reference = ScopeEventRef::new(sequence, digest).ok()?;
    let key = scope_event_key(scope, &reference);
    let decoded = decode_scope_event(bytes, &key, scope, None).ok()?;
    Some(StoredEvent {
        decoded,
        bytes: bytes.to_vec(),
    })
}

/// Fetches the events named by `references` with bounded concurrency.
///
/// Each object is decoded against the exact key its reference synthesizes. `None` is an
/// accelerator miss: a missing, oversized, undecodable, or over-budget object.
pub(crate) async fn fetch_events(
    store: &S3Store,
    scope: &ScopeIdentity,
    references: &[ScopeEventRef],
) -> Option<Vec<StoredEvent>> {
    let mut events = Vec::with_capacity(references.len());
    let mut total_bytes = 0_usize;
    for window in references.chunks(CONCURRENT_FETCHES.get()) {
        let fetched = bounded_map(window.len(), CONCURRENT_FETCHES, |index| {
            let reference = &window[index];
            async move {
                let key = scope_event_key(scope, reference);
                let bytes = match store.get_object(&key, MAX_COMPRESSED_BYTES).await {
                    Ok(GetOutcome::Found { bytes, .. }) => bytes,
                    Ok(GetOutcome::NotFound) | Err(_) => return None,
                };
                let decoded = decode_scope_event(&bytes, &key, scope, None).ok()?;
                Some(StoredEvent { decoded, bytes })
            }
        })
        .await;
        for stored in fetched {
            let stored = stored?;
            total_bytes = total_bytes.checked_add(stored.bytes.len())?;
            if total_bytes > MAX_FETCH_BYTES {
                return None;
            }
            events.push(stored);
        }
    }
    Some(events)
}

/// One verified event retained from a successful replay for opportunistic packing.
pub(crate) struct RetainedEvent {
    pub(crate) reference: ScopeEventRef,
    pub(crate) parent: Option<ScopeEventRef>,
    pub(crate) payload_type: String,
    pub(crate) bytes: Vec<u8>,
}

/// Best-effort pack, catalog, and pointer publication after one successful replay.
///
/// `events` are the verified suffix in chain order. Any storage failure, malformed
/// existing accelerator state, or pointer CAS loss stops publication silently: the replay
/// that produced these events already succeeded and its result must not change.
///
/// At most [`MAX_PUBLISHED_PACKS_PER_REPLAY`] packs are written per call, chosen from the
/// lowest sequences the current catalog does not already cover, so repeated replays extend
/// coverage instead of re-offering one fixed prefix. A caller awaits this before it can report
/// readiness, and a full-limit replay segments into sixteen packs whose PUTs each carry the
/// store's operation timeout, so an unbounded batch lets slow or write-denied storage hold a
/// correctly rebuilt scope unready. Sequences past the bound stay unpacked until a later replay
/// publishes them, which costs event reads, never correctness.
pub(crate) async fn publish_packs_after_replay(
    store: &S3Store,
    scope: &ScopeIdentity,
    events: &[RetainedEvent],
) {
    if events.is_empty() {
        return;
    }
    let Some(packs) = segment_packs(scope, events) else {
        return;
    };
    let existing = match read_current_catalog(store, scope).await {
        CurrentCatalog::Absent => None,
        CurrentCatalog::Unusable => return,
        CurrentCatalog::Present(catalog, etag) => Some((catalog, etag)),
    };
    let (mut entries, mut checkpoints) = match &existing {
        Some((catalog, _)) => (catalog.entries().to_vec(), catalog.checkpoints().to_vec()),
        None => (Vec::new(), Vec::new()),
    };
    // The catalog is read before the bound is applied, so the batch is the first
    // `MAX_PUBLISHED_PACKS_PER_REPLAY` packs this catalog does not already have. Bounding the
    // segmentation instead would pin every replay to the same low prefix: a partial catalog
    // fails to cover the requested suffix, the next replay reads events again and segments the
    // same packs, the merge finds nothing new, and coverage would never pass the bound.
    let mut pending = Vec::with_capacity(MAX_PUBLISHED_PACKS_PER_REPLAY);
    for pack in &packs {
        let Ok(entry) = PackEntry::new(pack.start(), pack.end(), pack.digest().clone()) else {
            return;
        };
        if entries.iter().any(|existing| existing.covers(&entry)) {
            continue;
        }
        // A partial overlap cannot be resolved without re-segmenting the publication.
        if entries
            .iter()
            .any(|existing| existing.overlaps(&entry) && !entry.covers(existing))
        {
            continue;
        }
        pending.push((pack, entry));
        if pending.len() == MAX_PUBLISHED_PACKS_PER_REPLAY {
            break;
        }
    }
    for (pack, _) in &pending {
        if store
            .publish_immutable(
                &pack.key(scope),
                pack.bytes().to_vec(),
                pack.digest().as_str(),
            )
            .await
            .is_err()
        {
            return;
        }
    }
    let mut changed = false;
    for (_, entry) in pending {
        // An overlap here is a wider pack over rows it fully contains — a replay from an
        // earlier cursor than the one that built them — so the narrower rows are replaced.
        // Dropping it instead would leave the sequences past the old row's end uncovered until
        // some node happened to replay from exactly that boundary.
        entries.retain(|existing| !entry.covers(existing));
        entries.push(entry);
        changed = true;
    }
    entries.sort_by_key(PackEntry::start);
    for event in events {
        if event.payload_type == crate::scope::PROJECTION_CHECKPOINT_PAYLOAD_TYPE
            && !checkpoints.contains(&event.reference)
        {
            checkpoints.push(event.reference.clone());
            changed = true;
        }
    }
    checkpoints.sort_by_key(ScopeEventRef::sequence);
    if !changed {
        return;
    }
    let Ok((catalog_bytes, catalog_digest)) = encode_catalog(scope, &entries, &checkpoints) else {
        return;
    };
    if store
        .publish_immutable(
            &replay_catalog_key(scope, &catalog_digest),
            catalog_bytes,
            catalog_digest.as_str(),
        )
        .await
        .is_err()
    {
        return;
    }
    let Ok(pointer_bytes) = encode_pointer(scope, &catalog_digest) else {
        return;
    };
    let mut history = AttemptHistory::default();
    let key = replay_pointer_key(scope);
    // A CAS loser stops here by falling out of scope: replay already succeeded, and the
    // winning pointer names a catalog some other publisher validated.
    let _outcome: MutationOutcome = match existing {
        None => store.put_if_absent(&key, pointer_bytes, &mut history).await,
        Some((_, etag)) => {
            store
                .put_if_match(&key, pointer_bytes, &etag, &mut history)
                .await
        }
    };
}

/// Data-free failure category for explicit checkpoint publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CheckpointPublishError {
    /// The parent is genesis or otherwise unusable as a fenced boundary.
    InvalidInput,
    /// The live projection does not match the supplied covered head.
    ProjectionMismatch,
    /// The snapshot copy, sanitize, bound, or validation step failed.
    SnapshotFailed,
    /// The immutable snapshot object could not be published.
    SnapshotStorage,
    /// The certificate event or head append failed.
    Append(ScopeAppendError),
}

impl fmt::Display for CheckpointPublishError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidInput => "checkpoint input is invalid",
            Self::ProjectionMismatch => "projection does not match the covered head",
            Self::SnapshotFailed => "checkpoint snapshot failed",
            Self::SnapshotStorage => "checkpoint snapshot publication failed",
            Self::Append(_) => "checkpoint certificate append failed",
        })
    }
}

impl Error for CheckpointPublishError {}

/// Explicitly publishes one certified checkpoint from a caller holding a fresh fenced
/// parent.
///
/// The projection is copied through the worker with `VACUUM INTO` at `staging` (an
/// absent path the caller owns), sanitized, validated, hashed, and published immutably;
/// the certificate event then appends through the ordinary event and head-CAS path,
/// preserving the parent head's active plan. If the head CAS loses, the snapshot and
/// event may remain immutable orphans; they grant no authority.
///
/// # Errors
///
/// Returns a [`CheckpointPublishError`] category; no step mutates any existing object,
/// so every failure leaves replay exactly as it was.
pub async fn publish_checkpoint(
    store: &S3Store,
    handle: &DbHandle,
    parent: ScopeHeadParent,
    staging: &Path,
    operation_id: &str,
    histories: [&mut AttemptHistory; 3],
) -> Result<ScopeHeadCommitOutcome, CheckpointPublishError> {
    let [snapshot_history, event_history, head_history] = histories;
    let ScopeHeadParent::Existing(observed) = &parent else {
        return Err(CheckpointPublishError::InvalidInput);
    };
    // An occupied staging path is a caller input error, not a projection mismatch.
    if staging.try_exists().unwrap_or(true) {
        return Err(CheckpointPublishError::InvalidInput);
    }
    let scope = observed.head().scope().clone();
    let covered = observed.head().tail().clone();
    let covered_plan = observed.head().active_plan_digest().cloned();
    handle
        .snapshot_to(observed.head(), staging.to_path_buf())
        .await
        .map_err(|error| match error {
            ApplyError::Conflict => CheckpointPublishError::ProjectionMismatch,
            _ => CheckpointPublishError::SnapshotFailed,
        })?;
    let staged = {
        let staging = staging.to_path_buf();
        crate::db::worker::run_blocking(move || {
            let bytes = std::fs::read(&staging).ok()?;
            if bytes.is_empty() || bytes.len() > MAX_SNAPSHOT_BYTES {
                return None;
            }
            let digest = Digest::new(sha256(&bytes)).ok()?;
            Some((bytes, digest))
        })
        .await
        .flatten()
    };
    let Some((bytes, digest)) = staged else {
        let _ = std::fs::remove_file(staging);
        return Err(CheckpointPublishError::SnapshotFailed);
    };
    let length = bytes.len();
    let key = scope_checkpoint_key(&scope, covered.sequence(), &digest);
    if store
        .publish_with_history(&key, bytes, digest.as_str(), snapshot_history)
        .await
        .is_err()
    {
        let _ = std::fs::remove_file(staging);
        return Err(CheckpointPublishError::SnapshotStorage);
    }
    let payload = match ProjectionCheckpointPayload::new(
        digest,
        length as u64,
        covered.sequence(),
        covered.digest().clone(),
        covered_plan,
    ) {
        Ok(payload) => payload,
        Err(_) => {
            let _ = std::fs::remove_file(staging);
            return Err(CheckpointPublishError::InvalidInput);
        }
    };
    match head::append_checkpoint(
        store,
        parent,
        &scope,
        &payload,
        operation_id,
        event_history,
        head_history,
    )
    .await
    {
        Ok(outcome) => Ok(outcome),
        Err(error) => {
            let _ = std::fs::remove_file(staging);
            Err(CheckpointPublishError::Append(error))
        }
    }
}

/// Segments retained events into pack builds honoring the flush limits.
fn segment_packs(scope: &ScopeIdentity, events: &[RetainedEvent]) -> Option<Vec<EncodedPack>> {
    let mut packs = Vec::new();
    let mut group: Vec<&RetainedEvent> = Vec::new();
    let mut group_bytes = 0_usize;
    let mut flush = |group: &mut Vec<&RetainedEvent>| -> Option<()> {
        let first = group.first()?;
        let slices: Vec<&[u8]> = group.iter().map(|event| event.bytes.as_slice()).collect();
        let pack = build_pack(
            scope,
            first.parent.as_ref(),
            first.reference.sequence(),
            &slices,
        )
        .ok()?;
        packs.push(pack);
        group.clear();
        Some(())
    };
    for event in events {
        // Flush before adding an event that would exceed 8 MiB, or once 256 events are held.
        if !group.is_empty()
            && (group.len() == MAX_PACK_EVENTS
                || group_bytes + event.bytes.len() > MAX_PACK_EVENT_BYTES)
        {
            flush(&mut group)?;
            group_bytes = 0;
        }
        group_bytes += event.bytes.len();
        group.push(event);
    }
    if !group.is_empty() {
        flush(&mut group)?;
    }
    Some(packs)
}

#[cfg(test)]
mod tests {
    use aws_sdk_s3::primitives::SdkBody;
    use ciborium::Value;

    use crate::{
        distributed::identity::WorkspaceId,
        scope::{
            AdmittedCampaignConfig, CampaignId, EventEnvelope, TEST_SUCCESSOR_PAYLOAD_TYPE,
            encode_scope_event, root_genesis,
        },
        storage::s3::test_support::{keyed_store, replay_store, response},
    };

    use super::*;

    fn genesis() -> crate::scope::RootGenesis {
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

    /// Builds a canonical chain of `count` events: genesis plus test successors.
    fn chain(genesis: &crate::scope::RootGenesis, count: usize) -> Vec<(ScopeEventRef, Vec<u8>)> {
        let mut events = Vec::with_capacity(count);
        events.push((genesis.event_ref().clone(), genesis.event_bytes().to_vec()));
        for sequence in 2..=count as u64 {
            let parent = events[(sequence - 2) as usize].0.clone();
            let envelope = EventEnvelope::new(
                genesis.identity().scope_id().clone(),
                sequence,
                Some(parent),
                1,
                format!("chain-op-{sequence}"),
                TEST_SUCCESSOR_PAYLOAD_TYPE.into(),
            )
            .unwrap();
            let encoded = encode_scope_event(&envelope, &Value::Null).unwrap();
            events.push((encoded.event_ref().clone(), encoded.stored_bytes().to_vec()));
        }
        events
    }

    fn pack_of(
        genesis: &crate::scope::RootGenesis,
        events: &[(ScopeEventRef, Vec<u8>)],
        start: usize,
        end: usize,
    ) -> EncodedPack {
        let parent = (start > 0).then(|| events[start - 1].0.clone());
        let slices: Vec<&[u8]> = events[start..=end]
            .iter()
            .map(|(_, bytes)| bytes.as_slice())
            .collect();
        build_pack(
            genesis.identity(),
            parent.as_ref(),
            start as u64 + 1,
            &slices,
        )
        .unwrap()
    }

    #[test]
    fn packs_round_trip_exact_event_bytes_and_reject_corruption() {
        let genesis = genesis();
        let events = chain(&genesis, 3);
        let pack = pack_of(&genesis, &events, 0, 2);
        assert_eq!(pack.start(), 1);
        assert_eq!(pack.end(), 3);
        assert!(pack.key(genesis.identity()).ends_with(&format!(
            "/replay-packs/0000000000000001-0000000000000003-{}",
            pack.digest().as_str()
        )));

        let decoded = decode_pack(pack.bytes(), pack.digest(), genesis.identity()).unwrap();
        assert_eq!(decoded.event_count(), 3);
        for (index, (reference, bytes)) in events.iter().enumerate() {
            assert_eq!(decoded.event_bytes(index), bytes.as_slice());
            assert_eq!(
                verify_embedded(genesis.identity(), reference.sequence(), bytes.as_slice())
                    .unwrap()
                    .decoded
                    .event_ref(),
                reference
            );
        }
        assert_eq!(decoded.parent_event(), None);
        assert_eq!(decoded.final_event(), &events[2].0);

        // The object digest is recomputed, so one flipped byte is a reference mismatch.
        let mut corrupt = pack.bytes().to_vec();
        corrupt[10] ^= 1;
        assert_eq!(
            decode_pack(&corrupt, pack.digest(), genesis.identity()),
            Err(WireError::ReferenceMismatch)
        );
        let corrupt_digest = Digest::new(sha256(&corrupt)).unwrap();
        assert!(decode_pack(&corrupt, &corrupt_digest, genesis.identity()).is_err());

        // Wrong-scope packs are refused before any embedded event is trusted.
        let foreign = ScopeIdentity::root(
            WorkspaceId::new("workspace-b".into()).unwrap(),
            CampaignId::new("campaign-b".into()).unwrap(),
        )
        .unwrap();
        assert_eq!(
            decode_pack(pack.bytes(), pack.digest(), &foreign),
            Err(WireError::InvalidValue)
        );

        assert_eq!(
            decode_pack(&[], pack.digest(), genesis.identity()),
            Err(WireError::LimitExceeded)
        );
    }

    /// The size caps are part of the durable format contract: objects stored under one
    /// build must keep decoding under the next, so the exact values are pinned rather
    /// than re-derived from their expressions.
    #[test]
    fn size_caps_are_pinned_to_the_durable_format_contract() {
        assert_eq!(MAX_PACK_EVENT_BYTES, 8_388_608);
        assert_eq!(MAX_SNAPSHOT_BYTES, 67_108_864);
        assert_eq!(MAX_PACK_OBJECT_BYTES, 8_454_144);
        assert_eq!(MAX_POINTER_BYTES, 4_096);
        assert_eq!(MAX_CATALOG_BYTES, 1_048_576);
        assert_eq!(MAX_FETCH_BYTES, 67_108_864);
    }

    /// A wrong-type event section names the expected shape in its decode error.
    #[test]
    fn event_section_decoding_names_the_expected_shape() {
        let mut bytes = Vec::new();
        into_writer(&Value::Array(Vec::new()), &mut bytes).unwrap();
        let error = match ciborium::from_reader::<EventSection, _>(bytes.as_slice()) {
            Err(error) => error,
            Ok(_) => panic!("an array must not decode as an event section"),
        };
        assert!(error.to_string().contains("a byte string"), "{error}");
    }

    #[test]
    fn a_pack_above_genesis_exposes_its_exact_parent_reference() {
        let genesis = genesis();
        let events = chain(&genesis, 3);
        let pack = pack_of(&genesis, &events, 1, 2);
        let decoded = decode_pack(pack.bytes(), pack.digest(), genesis.identity()).unwrap();
        assert_eq!(decoded.parent_event(), Some(&events[0].0));
        assert_eq!((decoded.start(), decoded.end()), (2, 3));
    }

    #[test]
    fn pack_build_enforces_parent_binding_count_and_section_limits() {
        let genesis = genesis();
        let events = chain(&genesis, 2);
        // Genesis start refuses a parent; later starts require one.
        assert!(
            build_pack(
                genesis.identity(),
                Some(&events[0].0),
                1,
                &[events[0].1.as_slice()],
            )
            .is_err()
        );
        assert!(build_pack(genesis.identity(), None, 2, &[events[1].1.as_slice()]).is_err());
        assert!(build_pack(genesis.identity(), None, 1, &[]).is_err());

        let big = vec![0_u8; MAX_PACK_EVENT_BYTES / 2 + 1];
        assert_eq!(
            build_pack(
                genesis.identity(),
                None,
                1,
                &[big.as_slice(), big.as_slice()],
            ),
            Err(WireError::LimitExceeded)
        );

        let tiny = [1_u8];
        let slices: Vec<&[u8]> = (0..MAX_PACK_EVENTS + 1).map(|_| tiny.as_slice()).collect();
        assert_eq!(
            build_pack(genesis.identity(), None, 1, &slices),
            Err(WireError::InvalidValue)
        );
    }

    /// A section at exactly the byte cap is accepted by both sides of the codec, and
    /// one byte past it is refused by the decoder.
    #[test]
    fn the_event_section_cap_is_inclusive_on_both_sides_of_the_codec() {
        let genesis = genesis();
        let big = vec![7_u8; MAX_PACK_EVENT_BYTES];
        let pack = build_pack(genesis.identity(), None, 1, &[big.as_slice()]).unwrap();
        let decoded = decode_pack(pack.bytes(), pack.digest(), genesis.identity()).unwrap();
        assert_eq!(decoded.event_count(), 1);
        assert_eq!(decoded.event_bytes(0), big.as_slice());

        // One byte past the cap only exists in a hand-built object; the decoder still
        // refuses it before hashing the section.
        let section = vec![7_u8; MAX_PACK_EVENT_BYTES + 1];
        let wire = WirePack {
            version: FORMAT_VERSION,
            scope_id: genesis.identity().scope_id().as_str().to_owned(),
            start_sequence: 1,
            end_sequence: 1,
            parent_event: None,
            final_event: WireEventRef {
                sequence: 1,
                digest: sha256(&section),
            },
            event_count: 1,
            offsets: vec![0, section.len() as u64],
            events_digest: sha256(&section),
            events: EventSection(section),
        };
        let bytes = encode_cbor(&wire).unwrap();
        let digest = Digest::new(sha256(&bytes)).unwrap();
        assert_eq!(
            decode_pack(&bytes, &digest, genesis.identity()),
            Err(WireError::LimitExceeded)
        );
    }

    /// An object at exactly the read cap reaches decoding; one byte past it does not.
    #[test]
    fn the_pack_object_cap_is_inclusive() {
        let genesis = genesis();
        let at_cap = vec![7_u8; MAX_PACK_OBJECT_BYTES];
        let digest = Digest::new(sha256(&at_cap)).unwrap();
        assert_eq!(
            decode_pack(&at_cap, &digest, genesis.identity()),
            Err(WireError::InvalidEncoding)
        );
        let over = vec![7_u8; MAX_PACK_OBJECT_BYTES + 1];
        let digest = Digest::new(sha256(&over)).unwrap();
        assert_eq!(
            decode_pack(&over, &digest, genesis.identity()),
            Err(WireError::LimitExceeded)
        );
    }

    /// Each range and binding validation rejects on its own, with every other field of
    /// the crafted object left consistent.
    #[test]
    fn each_pack_range_and_binding_check_rejects_independently() {
        let genesis = genesis();
        let scope = genesis.identity();
        let events = chain(&genesis, 2);
        let pack = pack_of(&genesis, &events, 0, 1);
        let assert_rejected = |wire: &WirePack| {
            let bytes = encode_cbor(wire).unwrap();
            let digest = Digest::new(sha256(&bytes)).unwrap();
            assert_eq!(
                decode_pack(&bytes, &digest, scope),
                Err(WireError::InvalidValue)
            );
        };

        // An inverted range alone is refused.
        let section = vec![1_u8];
        assert_rejected(&WirePack {
            version: FORMAT_VERSION,
            scope_id: scope.scope_id().as_str().to_owned(),
            start_sequence: 2,
            end_sequence: 1,
            parent_event: Some(WireEventRef {
                sequence: 1,
                digest: "a".repeat(64),
            }),
            final_event: WireEventRef {
                sequence: 1,
                digest: sha256(&section),
            },
            event_count: 1,
            offsets: vec![0, 1],
            events_digest: sha256(&section),
            events: EventSection(section),
        });

        // A count field disagreeing with the range alone is refused.
        let mut wire: WirePack = decode_cbor(pack.bytes()).unwrap();
        wire.event_count = 3;
        assert_rejected(&wire);

        // A nonzero first offset alone is refused.
        let mut wire: WirePack = decode_cbor(pack.bytes()).unwrap();
        wire.offsets[0] = 1;
        assert_rejected(&wire);

        // A final-event digest disagreeing with the last event alone is refused.
        let mut wire: WirePack = decode_cbor(pack.bytes()).unwrap();
        wire.final_event.digest = sha256(b"other");
        assert_rejected(&wire);
    }

    #[test]
    fn pack_decoding_rejects_unknown_fields_and_broken_framing() {
        let genesis = genesis();
        let events = chain(&genesis, 2);
        let pack = pack_of(&genesis, &events, 0, 1);
        let mut value: Value = ciborium::from_reader(pack.bytes()).unwrap();
        let Value::Map(entries) = &mut value else {
            panic!("expected map");
        };
        entries.push((Value::Text("extra".into()), Value::Null));
        let mut extended = Vec::new();
        into_writer(&value, &mut extended).unwrap();
        let digest = Digest::new(sha256(&extended)).unwrap();
        assert_eq!(
            decode_pack(&extended, &digest, genesis.identity()),
            Err(WireError::InvalidEncoding)
        );

        // A tampered offset table breaks the strict monotonicity requirement.
        let mut value: Value = ciborium::from_reader(pack.bytes()).unwrap();
        let Value::Map(entries) = &mut value else {
            panic!("expected map");
        };
        for (key, field) in entries.iter_mut() {
            if key == &Value::Text("offsets".into()) {
                let Value::Array(offsets) = field else {
                    panic!("expected array");
                };
                offsets.swap(0, 1);
            }
        }
        let mut tampered = Vec::new();
        into_writer(&value, &mut tampered).unwrap();
        let digest = Digest::new(sha256(&tampered)).unwrap();
        assert_eq!(
            decode_pack(&tampered, &digest, genesis.identity()),
            Err(WireError::InvalidValue)
        );
    }

    #[test]
    fn catalogs_and_pointers_round_trip_and_reject_disorder() {
        let genesis = genesis();
        let scope = genesis.identity();
        let digest = |seed: &str| Digest::new(sha256(seed.as_bytes())).unwrap();
        let entries = vec![
            PackEntry::new(1, 256, digest("pack-a")).unwrap(),
            PackEntry::new(257, 300, digest("pack-b")).unwrap(),
        ];
        let checkpoints = vec![ScopeEventRef::new(200, digest("certificate")).unwrap()];
        let (bytes, catalog_digest) = encode_catalog(scope, &entries, &checkpoints).unwrap();
        let decoded = decode_catalog(&bytes, &catalog_digest, scope).unwrap();
        assert_eq!(decoded.entries(), entries.as_slice());
        assert_eq!(decoded.checkpoints(), checkpoints.as_slice());

        // Overlapping and unsorted rows are refused on both sides of the codec.
        let overlapping = vec![
            PackEntry::new(1, 256, digest("pack-a")).unwrap(),
            PackEntry::new(200, 300, digest("pack-b")).unwrap(),
        ];
        assert_eq!(
            encode_catalog(scope, &overlapping, &[]),
            Err(WireError::InvalidValue)
        );
        let unsorted = vec![entries[1].clone(), entries[0].clone()];
        assert_eq!(
            encode_catalog(scope, &unsorted, &[]),
            Err(WireError::InvalidValue)
        );
        assert_eq!(
            decode_catalog(&bytes, &digest("wrong"), scope),
            Err(WireError::ReferenceMismatch)
        );

        let pointer = encode_pointer(scope, &catalog_digest).unwrap();
        assert_eq!(decode_pointer(&pointer, scope).unwrap(), catalog_digest);
        let foreign = ScopeIdentity::root(
            WorkspaceId::new("workspace-b".into()).unwrap(),
            CampaignId::new("campaign-b".into()).unwrap(),
        )
        .unwrap();
        assert_eq!(
            decode_pointer(&pointer, &foreign),
            Err(WireError::InvalidValue)
        );
        assert_eq!(decode_pointer(&[], scope), Err(WireError::LimitExceeded));

        // A row wider than one pack can hold is refused at construction.
        assert_eq!(
            PackEntry::new(1, MAX_PACK_EVENTS as u64 + 1, digest("wide")),
            Err(WireError::InvalidValue)
        );
        assert!(PackEntry::new(1, MAX_PACK_EVENTS as u64, digest("widest")).is_ok());
    }

    /// Rows sharing one boundary sequence overlap in both directions.
    #[test]
    fn pack_rows_sharing_one_boundary_sequence_overlap() {
        let digest = |seed: &str| Digest::new(sha256(seed.as_bytes())).unwrap();
        let a = PackEntry::new(1, 4, digest("a")).unwrap();
        let b = PackEntry::new(4, 6, digest("b")).unwrap();
        let c = PackEntry::new(5, 6, digest("c")).unwrap();
        assert!(a.overlaps(&b));
        assert!(b.overlaps(&a));
        assert!(!a.overlaps(&c));
        assert!(!c.overlaps(&a));
    }

    /// Catalog ordering is strict: rows touching at one sequence and checkpoints
    /// repeating one sequence are both refused.
    #[test]
    fn catalog_rows_touching_at_one_sequence_are_refused() {
        let genesis = genesis();
        let scope = genesis.identity();
        let digest = |seed: &str| Digest::new(sha256(seed.as_bytes())).unwrap();
        let touching = vec![
            PackEntry::new(1, 4, digest("a")).unwrap(),
            PackEntry::new(4, 6, digest("b")).unwrap(),
        ];
        assert_eq!(
            encode_catalog(scope, &touching, &[]),
            Err(WireError::InvalidValue)
        );
        let duplicate = vec![
            ScopeEventRef::new(200, digest("x")).unwrap(),
            ScopeEventRef::new(200, digest("y")).unwrap(),
        ];
        assert_eq!(
            encode_catalog(scope, &[], &duplicate),
            Err(WireError::InvalidValue)
        );
    }

    /// Catalog and pointer byte caps admit exactly-at-cap objects into decoding and
    /// refuse one byte past, and an empty object is a limit failure, not a hash one.
    #[test]
    fn catalog_and_pointer_byte_caps_are_inclusive() {
        let genesis = genesis();
        let scope = genesis.identity();
        let empty_digest = Digest::new(sha256(&[])).unwrap();
        assert_eq!(
            decode_catalog(&[], &empty_digest, scope),
            Err(WireError::LimitExceeded)
        );
        let at_cap = vec![7_u8; MAX_CATALOG_BYTES];
        let digest = Digest::new(sha256(&at_cap)).unwrap();
        assert_eq!(
            decode_catalog(&at_cap, &digest, scope),
            Err(WireError::InvalidEncoding)
        );
        let over = vec![7_u8; MAX_CATALOG_BYTES + 1];
        let digest = Digest::new(sha256(&over)).unwrap();
        assert_eq!(
            decode_catalog(&over, &digest, scope),
            Err(WireError::LimitExceeded)
        );

        let at_cap = vec![7_u8; MAX_POINTER_BYTES];
        assert_eq!(
            decode_pointer(&at_cap, scope),
            Err(WireError::InvalidEncoding)
        );
        let over = vec![7_u8; MAX_POINTER_BYTES + 1];
        assert_eq!(decode_pointer(&over, scope), Err(WireError::LimitExceeded));
    }

    #[test]
    fn a_catalog_at_the_row_cap_encodes_and_decodes_under_the_byte_cap() {
        let genesis = genesis();
        let scope = genesis.identity();
        let digest = |seed: usize| Digest::new(sha256(&seed.to_le_bytes())).unwrap();
        let entries: Vec<PackEntry> = (0..MAX_CATALOG_ROWS)
            .map(|index| {
                let start = index as u64 * 2 + 1;
                PackEntry::new(start, start + 1, digest(index)).unwrap()
            })
            .collect();
        let checkpoints: Vec<ScopeEventRef> = (0..MAX_CATALOG_ROWS)
            .map(|index| ScopeEventRef::new(index as u64 + 1, digest(index)).unwrap())
            .collect();
        let (bytes, catalog_digest) = encode_catalog(scope, &entries, &checkpoints).unwrap();
        assert!(bytes.len() <= MAX_CATALOG_BYTES);
        let decoded = decode_catalog(&bytes, &catalog_digest, scope).unwrap();
        assert_eq!(decoded.entries().len(), MAX_CATALOG_ROWS);
        assert_eq!(decoded.checkpoints().len(), MAX_CATALOG_ROWS);

        let mut over = entries.clone();
        let start = MAX_CATALOG_ROWS as u64 * 2 + 1;
        over.push(PackEntry::new(start, start + 1, digest(MAX_CATALOG_ROWS)).unwrap());
        assert_eq!(
            encode_catalog(scope, &over, &checkpoints),
            Err(WireError::InvalidValue)
        );

        // Worst-case row width: 16-digit sequences at the representable ceiling still
        // encode under the byte cap, so the encoder's byte guard is pure defense in
        // depth and can never fire for row-valid input.
        let base = 9_999_999_999_999_999_u64 - 2 * MAX_CATALOG_ROWS as u64;
        let wide: Vec<PackEntry> = (0..MAX_CATALOG_ROWS)
            .map(|index| {
                let start = base + index as u64 * 2;
                PackEntry::new(start, start + 1, digest(index)).unwrap()
            })
            .collect();
        let tall: Vec<ScopeEventRef> = (0..MAX_CATALOG_ROWS)
            .map(|index| ScopeEventRef::new(base + index as u64, digest(index)).unwrap())
            .collect();
        let (bytes, _) = encode_catalog(scope, &wide, &tall).unwrap();
        assert!(bytes.len() <= MAX_CATALOG_BYTES);
    }

    #[test]
    fn coverage_requires_contiguous_rows_reaching_the_whole_interval() {
        let genesis = genesis();
        let scope = genesis.identity();
        let digest = |seed: &str| Digest::new(sha256(seed.as_bytes())).unwrap();
        let entries = vec![
            PackEntry::new(1, 4, digest("a")).unwrap(),
            PackEntry::new(5, 8, digest("b")).unwrap(),
            PackEntry::new(11, 12, digest("c")).unwrap(),
        ];
        let (bytes, catalog_digest) = encode_catalog(scope, &entries, &[]).unwrap();
        let catalog = decode_catalog(&bytes, &catalog_digest, scope).unwrap();

        let ranges = |first, last| {
            coverage(&catalog, first, last)
                .map(|chosen| chosen.iter().map(|entry| entry.start()).collect::<Vec<_>>())
        };
        assert_eq!(ranges(1, 8), Some(vec![1, 5]));
        // A superset row still covers a smaller interval.
        assert_eq!(ranges(3, 6), Some(vec![1, 5]));
        assert_eq!(ranges(5, 5), Some(vec![5]));
        // The 9..=10 hole makes anything crossing or starting inside it a miss.
        assert_eq!(ranges(3, 12), None);
        assert_eq!(ranges(9, 12), None);
        assert_eq!(ranges(13, 14), None);
    }

    #[tokio::test]
    async fn packed_events_verifies_every_embedded_event_against_its_synthesized_key() {
        let genesis = genesis();
        let scope = genesis.identity();
        let events = chain(&genesis, 4);
        let first_pack = pack_of(&genesis, &events, 0, 1);
        let second_pack = pack_of(&genesis, &events, 2, 3);
        let entries = vec![
            PackEntry::new(1, 2, first_pack.digest().clone()).unwrap(),
            PackEntry::new(3, 4, second_pack.digest().clone()).unwrap(),
        ];
        let (catalog_bytes, catalog_digest) = encode_catalog(scope, &entries, &[]).unwrap();
        let pointer = encode_pointer(scope, &catalog_digest).unwrap();
        let (store, _) = replay_store(vec![
            response(200, &[("etag", "\"pointer\"")], pointer.clone()),
            response(200, &[("etag", "\"catalog\"")], catalog_bytes.clone()),
            response(200, &[("etag", "\"p1\"")], first_pack.bytes().to_vec()),
            response(200, &[("etag", "\"p2\"")], second_pack.bytes().to_vec()),
        ]);
        let stored = packed_events(&store, scope, 2, 4).await.unwrap();
        assert_eq!(stored.len(), 3);
        for (stored, (reference, bytes)) in stored.iter().zip(&events[1..]) {
            assert_eq!(stored.decoded.event_ref(), reference);
            assert_eq!(&stored.bytes, bytes);
        }

        // A pack whose bytes do not match its catalog digest is a miss, not an error.
        let (store, _) = replay_store(vec![
            response(200, &[("etag", "\"pointer\"")], pointer.clone()),
            response(200, &[("etag", "\"catalog\"")], catalog_bytes.clone()),
            response(200, &[("etag", "\"p1\"")], b"corrupt".to_vec()),
            response(200, &[("etag", "\"p2\"")], second_pack.bytes().to_vec()),
        ]);
        assert!(packed_events(&store, scope, 2, 4).await.is_none());

        // A missing pointer or catalog is a miss.
        let (store, _) = replay_store(vec![response(404, &[], SdkBody::empty())]);
        assert!(packed_events(&store, scope, 2, 4).await.is_none());
        let (store, _) = replay_store(vec![
            response(200, &[("etag", "\"pointer\"")], pointer),
            response(404, &[], SdkBody::empty()),
        ]);
        assert!(packed_events(&store, scope, 2, 4).await.is_none());
    }

    #[tokio::test]
    async fn packed_reads_truncate_above_last_and_refuse_over_budget_fetches() {
        let genesis = genesis();
        let scope = genesis.identity();
        let events = chain(&genesis, 4);
        let pack = pack_of(&genesis, &events, 0, 3);
        let entries = vec![PackEntry::new(1, 4, pack.digest().clone()).unwrap()];
        let (catalog_bytes, catalog_digest) = encode_catalog(scope, &entries, &[]).unwrap();
        let pointer = encode_pointer(scope, &catalog_digest).unwrap();
        // Events above `last` inside the covering pack are skipped, not returned.
        let (store, _) = replay_store(vec![
            response(200, &[("etag", "\"pointer\"")], pointer),
            response(200, &[("etag", "\"catalog\"")], catalog_bytes),
            response(200, &[("etag", "\"pack\"")], pack.bytes().to_vec()),
        ]);
        let stored = packed_events(&store, scope, 2, 3).await.unwrap();
        assert_eq!(stored.len(), 2);
        assert_eq!(stored[0].decoded.event_ref(), &events[1].0);
        assert_eq!(stored[1].decoded.event_ref(), &events[2].0);

        // Nine full-width rows answered with pack-object-sized bodies cross the 64 MiB
        // budget inside the second concurrency window: the read is a miss, not an
        // error, and the third window is never requested.
        let digest = |seed: usize| Digest::new(sha256(&seed.to_le_bytes())).unwrap();
        let wide: Vec<PackEntry> = (0..9_u64)
            .map(|index| {
                let start = index * MAX_PACK_EVENTS as u64 + 1;
                PackEntry::new(
                    start,
                    start + MAX_PACK_EVENTS as u64 - 1,
                    digest(index as usize),
                )
                .unwrap()
            })
            .collect();
        let (catalog_bytes, catalog_digest) = encode_catalog(scope, &wide, &[]).unwrap();
        let pointer = encode_pointer(scope, &catalog_digest).unwrap();
        let mut responses = vec![
            response(200, &[("etag", "\"pointer\"")], pointer),
            response(200, &[("etag", "\"catalog\"")], catalog_bytes),
        ];
        responses.extend((0..8).map(|_| {
            response(
                200,
                &[("etag", "\"pack\"")],
                vec![0_u8; MAX_PACK_OBJECT_BYTES],
            )
        }));
        let (store, client) = replay_store(responses);
        assert!(
            packed_events(&store, scope, 1, 9 * MAX_PACK_EVENTS as u64)
                .await
                .is_none()
        );
        assert_eq!(client.actual_requests().count(), 10);

        // An interval wider than one replay is refused before any request.
        let (store, client) = replay_store(vec![]);
        assert!(
            packed_events_from_catalog(
                &store,
                scope,
                &ReplayCatalog {
                    entries: Vec::new(),
                    checkpoints: Vec::new(),
                },
                2,
                2 + crate::sync::replay::MAX_SCOPE_REPLAY_EVENTS,
            )
            .await
            .is_none()
        );
        assert_eq!(client.actual_requests().count(), 0);
    }

    /// A span of exactly `MAX_SCOPE_REPLAY_EVENTS` is served, and every wider or
    /// degenerate interval is refused before any request, even when the catalog
    /// covers it.
    #[tokio::test]
    async fn packed_reads_accept_a_full_replay_span_and_refuse_wider_intervals() {
        let genesis = genesis();
        let scope = genesis.identity();
        let max = crate::sync::replay::MAX_SCOPE_REPLAY_EVENTS as usize;
        // One extra pack past the span cap keeps coverage satisfiable for the
        // wider-interval probes below.
        let events = chain(&genesis, max + MAX_PACK_EVENTS);
        let packs: Vec<EncodedPack> = (0..events.len() / MAX_PACK_EVENTS)
            .map(|index| {
                pack_of(
                    &genesis,
                    &events,
                    index * MAX_PACK_EVENTS,
                    (index + 1) * MAX_PACK_EVENTS - 1,
                )
            })
            .collect();
        let entries: Vec<PackEntry> = packs
            .iter()
            .map(|pack| PackEntry::new(pack.start(), pack.end(), pack.digest().clone()).unwrap())
            .collect();
        let (catalog_bytes, catalog_digest) = encode_catalog(scope, &entries, &[]).unwrap();
        let catalog = decode_catalog(&catalog_bytes, &catalog_digest, scope).unwrap();

        let bodies: Vec<(String, Vec<u8>)> = packs
            .iter()
            .map(|pack| (format!("/{}", pack.key(scope)), pack.bytes().to_vec()))
            .collect();
        let (store, _) = keyed_store(move |uri| {
            let path = uri.split('?').next().unwrap();
            match bodies.iter().find(|(key, _)| path == key) {
                Some((_, bytes)) => response(200, &[("etag", "\"pack\"")], bytes.clone()),
                None => response(404, &[], SdkBody::empty()),
            }
        });
        let stored = packed_events_from_catalog(&store, scope, &catalog, 1, max as u64)
            .await
            .unwrap();
        assert_eq!(stored.len(), max);
        assert_eq!(stored[max - 1].decoded.event_ref(), &events[max - 1].0);

        let (store, client) = replay_store(vec![
            response(500, &[], SdkBody::empty()),
            response(500, &[], SdkBody::empty()),
            response(500, &[], SdkBody::empty()),
            response(500, &[], SdkBody::empty()),
        ]);
        assert!(
            packed_events_from_catalog(&store, scope, &catalog, 1, max as u64 + 1)
                .await
                .is_none()
        );
        assert!(
            packed_events_from_catalog(&store, scope, &catalog, 5, 3)
                .await
                .is_none()
        );
        assert!(
            packed_events_from_catalog(&store, scope, &catalog, 0, u64::MAX)
                .await
                .is_none()
        );
        assert_eq!(client.actual_requests().count(), 0);
    }

    /// A decodable pack whose range disagrees with its catalog row is a miss even when
    /// the row's digest names the object exactly.
    #[tokio::test]
    async fn a_pack_whose_range_disagrees_with_its_catalog_row_is_a_miss() {
        let genesis = genesis();
        let scope = genesis.identity();
        let events = chain(&genesis, 3);
        let pack = pack_of(&genesis, &events, 0, 2);
        // The row narrows the covered range to 2..=3 while naming the same object.
        let entry = PackEntry::new(2, 3, pack.digest().clone()).unwrap();
        let (catalog_bytes, catalog_digest) =
            encode_catalog(scope, std::slice::from_ref(&entry), &[]).unwrap();
        let catalog = decode_catalog(&catalog_bytes, &catalog_digest, scope).unwrap();
        let (store, _) = replay_store(vec![response(
            200,
            &[("etag", "\"pack\"")],
            pack.bytes().to_vec(),
        )]);
        assert!(
            packed_events_from_catalog(&store, scope, &catalog, 2, 3)
                .await
                .is_none()
        );
    }

    /// Eight 8 MiB bodies land exactly on the 64 MiB pack-fetch budget, so the ninth
    /// row is still requested before its garbage body fails decoding.
    #[tokio::test]
    async fn the_packed_fetch_budget_is_inclusive_at_exactly_the_cap() {
        let genesis = genesis();
        let scope = genesis.identity();
        let digest = |seed: usize| Digest::new(sha256(&seed.to_le_bytes())).unwrap();
        let wide: Vec<PackEntry> = (0..9_u64)
            .map(|index| {
                let start = index * MAX_PACK_EVENTS as u64 + 1;
                PackEntry::new(
                    start,
                    start + MAX_PACK_EVENTS as u64 - 1,
                    digest(index as usize),
                )
                .unwrap()
            })
            .collect();
        let (catalog_bytes, catalog_digest) = encode_catalog(scope, &wide, &[]).unwrap();
        let catalog = decode_catalog(&catalog_bytes, &catalog_digest, scope).unwrap();
        let responses: Vec<_> = (0..9)
            .map(|_| {
                response(
                    200,
                    &[("etag", "\"pack\"")],
                    vec![0_u8; MAX_PACK_EVENT_BYTES],
                )
            })
            .collect();
        let (store, client) = replay_store(responses);
        assert!(
            packed_events_from_catalog(&store, scope, &catalog, 1, 9 * MAX_PACK_EVENTS as u64)
                .await
                .is_none()
        );
        assert_eq!(client.actual_requests().count(), 9);
    }

    /// Builds one decodable event whose stored bytes are exactly `MAX_COMPRESSED_BYTES`,
    /// by sizing an incompressible payload until the compressed frame lands on the cap.
    fn event_of_exact_stored_size(
        scope: &ScopeIdentity,
        sequence: u64,
    ) -> (ScopeEventRef, Vec<u8>) {
        let parent = ScopeEventRef::new(
            sequence - 1,
            Digest::new(sha256(&sequence.to_le_bytes())).unwrap(),
        )
        .unwrap();
        let encode = |length: usize, seed: u64| {
            let mut state = seed.wrapping_mul(2 * sequence + 1) | 1;
            let payload: Vec<u8> = (0..length)
                .map(|_| {
                    state = state
                        .wrapping_mul(6_364_136_223_846_793_005)
                        .wrapping_add(1_442_695_040_888_963_407);
                    (state >> 33) as u8
                })
                .collect();
            let envelope = EventEnvelope::new(
                scope.scope_id().clone(),
                sequence,
                Some(parent.clone()),
                1,
                format!("sized-op-{sequence:04}"),
                TEST_SUCCESSOR_PAYLOAD_TYPE.into(),
            )
            .unwrap();
            crate::scope::encode_scope_event(&envelope, &Value::Bytes(payload)).unwrap()
        };
        for seed in 1..64_u64 {
            let probe = encode(MAX_COMPRESSED_BYTES - 1_024, seed);
            let base =
                MAX_COMPRESSED_BYTES - 1_024 + (MAX_COMPRESSED_BYTES - probe.stored_bytes().len());
            for length in base.saturating_sub(4)..=base + 4 {
                let encoded = encode(length, seed);
                if encoded.stored_bytes().len() == MAX_COMPRESSED_BYTES {
                    return (encoded.event_ref().clone(), encoded.stored_bytes().to_vec());
                }
            }
        }
        panic!("no exact-size event for sequence {sequence}");
    }

    /// 256 events of exactly `MAX_COMPRESSED_BYTES` land exactly on the 64 MiB event
    /// fetch budget and are all served.
    #[tokio::test]
    async fn the_event_fetch_budget_is_inclusive_at_exactly_the_cap() {
        let genesis = genesis();
        let scope = genesis.identity().clone();
        assert_eq!(256 * MAX_COMPRESSED_BYTES, MAX_FETCH_BYTES);
        let events: Vec<(ScopeEventRef, Vec<u8>)> = (2..258_u64)
            .map(|sequence| event_of_exact_stored_size(&scope, sequence))
            .collect();
        let references: Vec<ScopeEventRef> = events
            .iter()
            .map(|(reference, _)| reference.clone())
            .collect();
        let bodies: Vec<(String, Vec<u8>)> = events
            .iter()
            .map(|(reference, bytes)| {
                (
                    format!("/{}", scope_event_key(&scope, reference)),
                    bytes.clone(),
                )
            })
            .collect();
        let (store, _) = keyed_store(move |uri| {
            let path = uri.split('?').next().unwrap();
            match bodies.iter().find(|(key, _)| path == key) {
                Some((_, bytes)) => response(200, &[("etag", "\"event\"")], bytes.clone()),
                None => response(404, &[], SdkBody::empty()),
            }
        });
        let stored = fetch_events(&store, &scope, &references).await.unwrap();
        assert_eq!(stored.len(), 256);
        let total: usize = stored.iter().map(|event| event.bytes.len()).sum();
        assert_eq!(total, MAX_FETCH_BYTES);
    }

    #[test]
    fn segmentation_flushes_at_the_event_count_and_byte_boundaries() {
        let genesis = genesis();
        let events = chain(&genesis, MAX_PACK_EVENTS + 1);
        let retained: Vec<RetainedEvent> = events
            .iter()
            .enumerate()
            .map(|(index, (reference, bytes))| RetainedEvent {
                reference: reference.clone(),
                parent: (index > 0).then(|| events[index - 1].0.clone()),
                payload_type: TEST_SUCCESSOR_PAYLOAD_TYPE.into(),
                bytes: bytes.clone(),
            })
            .collect();
        let packs = segment_packs(genesis.identity(), &retained).unwrap();
        assert_eq!(packs.len(), 2);
        assert_eq!(
            (packs[0].start(), packs[0].end()),
            (1, MAX_PACK_EVENTS as u64)
        );
        assert_eq!(
            (packs[1].start(), packs[1].end()),
            (MAX_PACK_EVENTS as u64 + 1, MAX_PACK_EVENTS as u64 + 1)
        );

        // Byte-bounded flush: three third-of-the-cap events split two-and-one.
        let third = MAX_PACK_EVENT_BYTES / 3 + 1;
        let digest = |seed: u8| Digest::new(sha256(&[seed])).unwrap();
        let fat: Vec<RetainedEvent> = (0..3_u64)
            .map(|index| RetainedEvent {
                reference: ScopeEventRef::new(index + 1, digest(index as u8)).unwrap(),
                parent: index
                    .checked_sub(1)
                    .map(|parent| ScopeEventRef::new(parent + 1, digest(parent as u8)).unwrap()),
                payload_type: TEST_SUCCESSOR_PAYLOAD_TYPE.into(),
                bytes: vec![index as u8; third],
            })
            .collect();
        let packs = segment_packs(genesis.identity(), &fat).unwrap();
        assert_eq!(packs.len(), 2);
        assert_eq!((packs[0].start(), packs[0].end()), (1, 2));
        assert_eq!((packs[1].start(), packs[1].end()), (3, 3));

        // Two half-cap events land exactly on the byte cap and stay in one pack: the
        // flush boundary is exclusive at the cap.
        let half = MAX_PACK_EVENT_BYTES / 2;
        let exact: Vec<RetainedEvent> = (0..2_u64)
            .map(|index| RetainedEvent {
                reference: ScopeEventRef::new(index + 1, digest(index as u8)).unwrap(),
                parent: index
                    .checked_sub(1)
                    .map(|parent| ScopeEventRef::new(parent + 1, digest(parent as u8)).unwrap()),
                payload_type: TEST_SUCCESSOR_PAYLOAD_TYPE.into(),
                bytes: vec![index as u8; half],
            })
            .collect();
        let packs = segment_packs(genesis.identity(), &exact).unwrap();
        assert_eq!(packs.len(), 1);
        assert_eq!((packs[0].start(), packs[0].end()), (1, 2));
    }

    #[test]
    fn new_error_displays_are_static_and_data_free() {
        for (error, text) in [
            (
                CheckpointPublishError::InvalidInput,
                "checkpoint input is invalid",
            ),
            (
                CheckpointPublishError::ProjectionMismatch,
                "projection does not match the covered head",
            ),
            (
                CheckpointPublishError::SnapshotFailed,
                "checkpoint snapshot failed",
            ),
            (
                CheckpointPublishError::SnapshotStorage,
                "checkpoint snapshot publication failed",
            ),
            (
                CheckpointPublishError::Append(ScopeAppendError::InvalidInput),
                "checkpoint certificate append failed",
            ),
        ] {
            assert_eq!(error.to_string(), text);
        }
        // The wrapper's display is identical for different inner variants, so no inner
        // error text can ever reach a caller through it.
        assert_eq!(
            CheckpointPublishError::Append(ScopeAppendError::InvalidInput).to_string(),
            CheckpointPublishError::Append(ScopeAppendError::Publication(
                crate::sync::event::ScopeEventPublicationError::UnsupportedPayload
            ))
            .to_string()
        );
    }

    /// Publication skips the packs a catalog already covers before applying its own bound, so
    /// repeated replays extend coverage instead of re-offering one fixed prefix.
    #[tokio::test]
    async fn publication_advances_past_already_catalogued_packs() {
        let genesis = genesis();
        let scope = genesis.identity();
        // One event past four full packs, so the batch bound and the covered prefix cannot both
        // fit: applying the bound before the skip would stop one pack short, every later replay
        // would re-offer the same prefix, and coverage would never reach the tail.
        let events = chain(&genesis, MAX_PACK_EVENTS * 4 + 1);
        let retained: Vec<RetainedEvent> = events
            .iter()
            .enumerate()
            .map(|(index, (reference, bytes))| RetainedEvent {
                reference: reference.clone(),
                parent: (index > 0).then(|| events[index - 1].0.clone()),
                payload_type: TEST_SUCCESSOR_PAYLOAD_TYPE.into(),
                bytes: bytes.clone(),
            })
            .collect();
        let packs = segment_packs(scope, &retained).unwrap();
        assert_eq!(packs.len(), MAX_PUBLISHED_PACKS_PER_REPLAY + 1);
        let tail = packs.last().unwrap().end();

        // The catalog already holds the first pack.
        let covered =
            PackEntry::new(packs[0].start(), packs[0].end(), packs[0].digest().clone()).unwrap();
        let (catalog_bytes, catalog_digest) =
            encode_catalog(scope, std::slice::from_ref(&covered), &[]).unwrap();
        let pointer_bytes = encode_pointer(scope, &catalog_digest).unwrap();

        let mut script = vec![
            response(200, &[("etag", "\"pointer\"")], pointer_bytes),
            response(200, &[("etag", "\"catalog\"")], catalog_bytes),
        ];
        // One PUT per published pack, then the catalog and pointer writes.
        for _ in 0..MAX_PUBLISHED_PACKS_PER_REPLAY + 2 {
            script.push(response(200, &[], SdkBody::empty()));
        }
        script.push(response(500, &[], SdkBody::empty()));
        let (store, client) = replay_store(script);
        publish_packs_after_replay(&store, scope, &retained).await;

        let requests: Vec<_> = client.actual_requests().collect();
        assert_eq!(requests.len(), MAX_PUBLISHED_PACKS_PER_REPLAY + 4);
        let published = requests
            .iter()
            .filter(|request| request.uri().contains("/replay-packs/"))
            .count();
        assert_eq!(published, MAX_PUBLISHED_PACKS_PER_REPLAY);
        // The catalog write is the second-to-last request; its rows must reach the tail.
        let written = requests[requests.len() - 2].body().bytes().unwrap();
        let digest = Digest::new(sha256(written)).unwrap();
        let catalog = decode_catalog(written, &digest, scope).unwrap();
        assert_eq!(catalog.entries().last().unwrap().end(), tail);
        assert!(coverage(&catalog, 1, tail).is_some());
    }

    #[tokio::test]
    async fn checkpoint_publication_snapshots_then_appends_through_the_head_cas() {
        use crate::sync::head::read;

        let genesis = genesis();
        let scope = genesis.identity().clone();
        let db_path = std::env::temp_dir().join(format!(
            "ravel-accel-checkpoint-{}-live.sqlite3",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&db_path);
        let staging = std::env::temp_dir().join(format!(
            "ravel-accel-checkpoint-{}-staging.sqlite3",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&staging);
        let handle = DbHandle::spawn(db_path.clone()).await.unwrap();
        let root = crate::scope::decode_root_event(
            genesis.event_bytes(),
            genesis.event_key(),
            genesis.identity(),
        )
        .unwrap();
        let mutation = crate::db::projections::ScopeProjectionEvent::new(
            scope.clone(),
            root.envelope().clone(),
            genesis.event_ref().clone(),
            crate::db::projections::ScopeProjectionPayload::RootGenesis {
                objective_digest: root.payload().config_digest().clone(),
            },
            1,
        )
        .unwrap();
        handle
            .apply_suffix(vec![mutation], genesis.head())
            .await
            .unwrap();

        // A genesis parent is refused before any snapshot work.
        let mut histories = [
            AttemptHistory::default(),
            AttemptHistory::default(),
            AttemptHistory::default(),
        ];
        let [a, b, c] = &mut histories;
        let (store, client) = replay_store(vec![]);
        assert_eq!(
            publish_checkpoint(
                &store,
                &handle,
                ScopeHeadParent::Genesis,
                &staging,
                "checkpoint-op-1",
                [a, b, c],
            )
            .await
            .err(),
            Some(CheckpointPublishError::InvalidInput)
        );
        assert_eq!(client.actual_requests().count(), 0);

        let mut histories = [
            AttemptHistory::default(),
            AttemptHistory::default(),
            AttemptHistory::default(),
        ];
        let [a, b, c] = &mut histories;
        let (store, client) = replay_store(vec![
            response(
                200,
                &[("etag", "\"parent\"")],
                genesis.head_bytes().to_vec(),
            ),
            response(200, &[], SdkBody::empty()),
            response(200, &[], SdkBody::empty()),
            response(200, &[("etag", "\"committed\"")], SdkBody::empty()),
        ]);
        let observed = read(&store, &scope).await.unwrap().unwrap();
        let outcome = publish_checkpoint(
            &store,
            &handle,
            ScopeHeadParent::existing(Box::new(observed)),
            &staging,
            "checkpoint-op-1",
            [a, b, c],
        )
        .await
        .unwrap();
        assert!(matches!(outcome, ScopeHeadCommitOutcome::Committed(_)));
        let requests: Vec<_> = client.actual_requests().collect();
        assert_eq!(requests.len(), 4);
        let path_of = |index: usize| {
            requests[index]
                .uri()
                .parse::<http::Uri>()
                .unwrap()
                .path()
                .to_owned()
        };
        let snapshot_bytes = std::fs::read(&staging).unwrap();
        let snapshot_digest = sha256(&snapshot_bytes);
        assert_eq!(
            path_of(1),
            format!(
                "/{}",
                scope_checkpoint_key(&scope, 1, &Digest::new(snapshot_digest.clone()).unwrap())
            )
        );
        assert_eq!(requests[1].headers().get("if-none-match"), Some("*"));
        assert_eq!(requests[1].body().bytes(), Some(snapshot_bytes.as_slice()));
        assert!(path_of(2).contains("/events/0000000000000002-"));
        assert_eq!(requests[2].headers().get("if-none-match"), Some("*"));
        assert!(path_of(3).ends_with("/head"));
        assert_eq!(requests[3].headers().get("if-match"), Some("\"parent\""));

        // The published certificate replays as a registered event: cursor advances,
        // nothing else changes.
        let event_bytes = requests[2].body().bytes().unwrap().to_vec();
        let reference = ScopeEventRef::new(2, Digest::new(sha256(&event_bytes)).unwrap()).unwrap();
        let certificate = crate::scope::decode_projection_checkpoint_event(
            &event_bytes,
            &scope_event_key(&scope, &reference),
            &scope,
        )
        .unwrap();
        assert_eq!(certificate.payload().covered_sequence(), 1);
        assert_eq!(
            certificate.payload().snapshot_length(),
            snapshot_bytes.len() as u64
        );
        let head_bytes = requests[3].body().bytes().unwrap().to_vec();
        let (fold_store, _) = replay_store(vec![
            response(200, &[("etag", "\"head\"")], head_bytes),
            response(404, &[], SdkBody::empty()),
            response(404, &[], SdkBody::empty()),
            response(200, &[("etag", "\"event\"")], event_bytes),
        ]);
        assert!(matches!(
            crate::sync::replay::refresh(&fold_store, &handle, &scope).await,
            crate::sync::replay::ScopeReadiness::Ready { .. }
        ));
        assert_eq!(
            handle.scope_cursor(&scope).await.unwrap(),
            (2, Some(reference.digest().clone()))
        );

        drop(handle);
        let _ = std::fs::remove_file(db_path);
        let _ = std::fs::remove_file(staging);
    }

    #[tokio::test]
    async fn a_projection_behind_the_covered_head_is_a_projection_mismatch() {
        use crate::sync::head::read;

        let genesis = genesis();
        let scope = genesis.identity().clone();
        let db_path = std::env::temp_dir().join(format!(
            "ravel-accel-checkpoint-{}-mismatch.sqlite3",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&db_path);
        let staging = std::env::temp_dir().join(format!(
            "ravel-accel-checkpoint-{}-mismatch-staging.sqlite3",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&staging);
        // The projection is empty, so it cannot match the observed genesis head.
        let handle = DbHandle::spawn(db_path.clone()).await.unwrap();
        let (store, client) = replay_store(vec![response(
            200,
            &[("etag", "\"parent\"")],
            genesis.head_bytes().to_vec(),
        )]);
        let observed = read(&store, &scope).await.unwrap().unwrap();
        let mut histories = [
            AttemptHistory::default(),
            AttemptHistory::default(),
            AttemptHistory::default(),
        ];
        let [a, b, c] = &mut histories;
        assert_eq!(
            publish_checkpoint(
                &store,
                &handle,
                ScopeHeadParent::existing(Box::new(observed)),
                &staging,
                "checkpoint-op-mismatch",
                [a, b, c],
            )
            .await
            .err(),
            Some(CheckpointPublishError::ProjectionMismatch)
        );
        assert_eq!(client.actual_requests().count(), 1);
        drop(handle);
        let _ = std::fs::remove_file(db_path);
        let _ = std::fs::remove_file(&staging);
    }

    #[tokio::test]
    async fn publication_creates_the_pointer_then_merges_and_survives_cas_loss() {
        use crate::scope::PROJECTION_CHECKPOINT_PAYLOAD_TYPE;

        let genesis = genesis();
        let scope = genesis.identity();
        let events = chain(&genesis, 2);
        // The second retained event must be recorded as a catalog checkpoint
        // certificate.
        let retained: Vec<RetainedEvent> = events
            .iter()
            .enumerate()
            .map(|(index, (reference, bytes))| RetainedEvent {
                reference: reference.clone(),
                parent: (index > 0).then(|| events[index - 1].0.clone()),
                payload_type: if index == 1 {
                    PROJECTION_CHECKPOINT_PAYLOAD_TYPE.into()
                } else {
                    TEST_SUCCESSOR_PAYLOAD_TYPE.into()
                },
                bytes: bytes.clone(),
            })
            .collect();
        let cert_ref = events[1].0.clone();
        let pack = pack_of(&genesis, &events, 0, 1);
        let entry = PackEntry::new(1, 2, pack.digest().clone()).unwrap();
        let (catalog_bytes, catalog_digest) = encode_catalog(
            scope,
            std::slice::from_ref(&entry),
            std::slice::from_ref(&cert_ref),
        )
        .unwrap();
        let pointer_bytes = encode_pointer(scope, &catalog_digest).unwrap();

        // The catalog is read first, so the pack write is chosen against what the catalog
        // already covers. An absent pointer is created with a create-only PUT. Two surplus
        // scripted failures make any request beyond the expected four visible in the count.
        let (store, client) = replay_store(vec![
            response(404, &[], SdkBody::empty()),
            response(200, &[], SdkBody::empty()),
            response(200, &[], SdkBody::empty()),
            response(200, &[], SdkBody::empty()),
            response(500, &[], SdkBody::empty()),
            response(500, &[], SdkBody::empty()),
        ]);
        publish_packs_after_replay(&store, scope, &retained).await;
        let requests: Vec<_> = client.actual_requests().collect();
        assert_eq!(requests.len(), 4);
        let path = |index: usize| {
            requests[index]
                .uri()
                .parse::<http::Uri>()
                .unwrap()
                .path()
                .to_owned()
        };
        assert!(path(0).ends_with("/replay-index/current"));
        assert!(path(1).contains("/replay-packs/"));
        assert_eq!(requests[1].headers().get("if-none-match"), Some("*"));
        assert_eq!(requests[1].body().bytes(), Some(pack.bytes()));
        assert!(path(2).ends_with(&format!("/replay-index/{}", catalog_digest.as_str())));
        assert_eq!(requests[2].headers().get("if-none-match"), Some("*"));
        assert_eq!(requests[2].body().bytes(), Some(catalog_bytes.as_slice()));
        assert!(path(3).ends_with("/replay-index/current"));
        assert_eq!(requests[3].headers().get("if-none-match"), Some("*"));
        assert_eq!(requests[3].body().bytes(), Some(pointer_bytes.as_slice()));

        // A rerun finds the catalog already covering this pack, so it writes no object at all:
        // reading the catalog first is what turns a redundant republish into two reads.
        let (store, client) = replay_store(vec![
            response(200, &[("etag", "\"pointer\"")], pointer_bytes.clone()),
            response(200, &[("etag", "\"catalog\"")], catalog_bytes.clone()),
            response(500, &[], SdkBody::empty()),
            response(500, &[], SdkBody::empty()),
        ]);
        publish_packs_after_replay(&store, scope, &retained).await;
        assert_eq!(client.actual_requests().count(), 2);

        // A pointer CAS loss is silent: publication simply stops. The merged catalog
        // must keep the existing disjoint row and carry the certificate reference.
        let disjoint = PackEntry::new(100, 101, pack.digest().clone()).unwrap();
        let (other_catalog, other_digest) =
            encode_catalog(scope, std::slice::from_ref(&disjoint), &[]).unwrap();
        let other_pointer = encode_pointer(scope, &other_digest).unwrap();
        let (merged_bytes, _) = encode_catalog(
            scope,
            &[entry.clone(), disjoint.clone()],
            std::slice::from_ref(&cert_ref),
        )
        .unwrap();
        let (store, client) = replay_store(vec![
            response(200, &[("etag", "\"pointer\"")], other_pointer),
            response(200, &[("etag", "\"catalog\"")], other_catalog),
            response(412, &[], SdkBody::empty()),
            response(200, &[], pack.bytes().to_vec()),
            response(200, &[], SdkBody::empty()),
            response(412, &[], SdkBody::empty()),
            response(500, &[], SdkBody::empty()),
            response(500, &[], SdkBody::empty()),
        ]);
        publish_packs_after_replay(&store, scope, &retained).await;
        let requests: Vec<_> = client.actual_requests().collect();
        assert_eq!(requests.len(), 6);
        assert_eq!(requests[4].headers().get("if-none-match"), Some("*"));
        assert_eq!(requests[4].body().bytes(), Some(merged_bytes.as_slice()));
        assert_eq!(requests[5].headers().get("if-match"), Some("\"pointer\""));

        // A narrower row the new pack fully covers is replaced, not a reason to drop the
        // pack: a replay from an earlier cursor builds a wider pack over the same prefix,
        // and keeping the old row would leave every sequence past its end uncovered.
        let narrow = PackEntry::new(1, 1, Digest::new(sha256(b"narrow")).unwrap()).unwrap();
        let (narrow_catalog, narrow_digest) =
            encode_catalog(scope, std::slice::from_ref(&narrow), &[]).unwrap();
        let narrow_pointer = encode_pointer(scope, &narrow_digest).unwrap();
        let (widened_bytes, _) = encode_catalog(
            scope,
            std::slice::from_ref(&entry),
            std::slice::from_ref(&cert_ref),
        )
        .unwrap();
        let (store, client) = replay_store(vec![
            response(200, &[("etag", "\"pointer\"")], narrow_pointer),
            response(200, &[("etag", "\"catalog\"")], narrow_catalog),
            response(412, &[], SdkBody::empty()),
            response(200, &[], pack.bytes().to_vec()),
            response(200, &[], SdkBody::empty()),
            response(200, &[], SdkBody::empty()),
            response(500, &[], SdkBody::empty()),
            response(500, &[], SdkBody::empty()),
        ]);
        publish_packs_after_replay(&store, scope, &retained).await;
        let requests: Vec<_> = client.actual_requests().collect();
        assert_eq!(requests.len(), 6);
        assert_eq!(requests[4].body().bytes(), Some(widened_bytes.as_slice()));
    }
}
