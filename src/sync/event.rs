//! The v1 event encoding is frozen.
//!
//! CBOR is a definite-length map whose declaration-order text keys are
//! `version`, `operation_id`, `sequence`, `parent`, `writer_fence`, and
//! `content`. Integers use ciborium's shortest representation. `parent` is
//! either null or a declaration-order map of `sequence`, `digest`, and `key`.
//! Content is one of the text values `campaign_created` or `workflow_started`.
//!
//! The CBOR is compressed by zstd's bulk encoder at level 3: one standard
//! frame with content size, no checksum, and no dictionary. SHA-256 covers
//! these compressed stored bytes. Keys are
//! `{sequence:016}-{lowercase_sha256}.cbor.zst`. Decoding caps stored bytes at
//! 256 KiB, decompressed CBOR at 1 MiB, and CBOR recursion at 16, then requires
//! exact CBOR re-encoding and exact zstd recompression before domain conversion.
//!
//! Key values exclude object-store prefixes. The `zstd-sys 2.0.16+zstd.1.5.7`
//! lockfile pin is byte-affecting.

use std::{fmt::Write as _, io::Cursor};

use ciborium::{de::from_reader_with_recursion_limit, ser::into_writer};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::domain::campaign::{Event, EventContent, EventRef};

use super::{WIRE_VERSION, WireError};

const MAX_COMPRESSED_BYTES: usize = 256 * 1024;
const MAX_DECOMPRESSED_BYTES: usize = 1024 * 1024;
const CBOR_RECURSION_LIMIT: usize = 16;
const ZSTD_LEVEL: i32 = 3;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncodedEvent {
    stored_bytes: Vec<u8>,
    reference: EventRef,
}

impl EncodedEvent {
    pub fn stored_bytes(&self) -> &[u8] {
        &self.stored_bytes
    }

    pub fn digest(&self) -> &str {
        self.reference.digest()
    }

    pub fn key(&self) -> &str {
        self.reference.key()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireEvent {
    version: u64,
    operation_id: String,
    sequence: u64,
    parent: Option<WireEventRef>,
    writer_fence: u64,
    content: WireContent,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireEventRef {
    sequence: u64,
    digest: String,
    key: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum WireContent {
    CampaignCreated,
    WorkflowStarted,
}

pub fn encode(event: &Event) -> Result<EncodedEvent, WireError> {
    let wire = WireEvent::from(event);
    let cbor = encode_cbor(&wire)?;
    let stored_bytes = compress(&cbor)?;
    let reference = EventRef::from_digest(event.sequence(), digest(&stored_bytes))
        .map_err(|_| WireError::InvalidValue)?;
    Ok(EncodedEvent {
        stored_bytes,
        reference,
    })
}

pub fn decode(stored_bytes: &[u8], expected_key: &str) -> Result<Event, WireError> {
    if stored_bytes.is_empty() || stored_bytes.len() > MAX_COMPRESSED_BYTES {
        return Err(WireError::LimitExceeded);
    }
    match zstd::zstd_safe::get_frame_content_size(stored_bytes)
        .map_err(|_| WireError::InvalidEncoding)?
    {
        None => return Err(WireError::NonCanonical),
        Some(0) => return Err(WireError::LimitExceeded),
        Some(size) if size > MAX_DECOMPRESSED_BYTES as u64 => {
            return Err(WireError::LimitExceeded);
        }
        Some(_) => {}
    }
    let cbor = zstd::bulk::decompress(stored_bytes, MAX_DECOMPRESSED_BYTES)
        .map_err(|_| WireError::InvalidEncoding)?;

    let mut reader = Cursor::new(cbor.as_slice());
    let wire: WireEvent = from_reader_with_recursion_limit(&mut reader, CBOR_RECURSION_LIMIT)
        .map_err(|_| WireError::InvalidEncoding)?;
    if wire.version != WIRE_VERSION {
        return Err(WireError::InvalidValue);
    }
    if reader.position() != cbor.len() as u64 {
        return Err(WireError::NonCanonical);
    }
    let canonical = encode_cbor(&wire)?;
    if canonical != cbor {
        return Err(WireError::NonCanonical);
    }
    if compress(&canonical)? != stored_bytes {
        return Err(WireError::NonCanonical);
    }

    let computed = EventRef::from_digest(wire.sequence, digest(stored_bytes))
        .map_err(|_| WireError::InvalidValue)?;
    if computed.key() != expected_key {
        return Err(WireError::ReferenceMismatch);
    }
    wire.try_into()
}

impl From<&Event> for WireEvent {
    fn from(event: &Event) -> Self {
        Self {
            version: WIRE_VERSION,
            operation_id: event.operation_id().to_owned(),
            sequence: event.sequence(),
            parent: event.parent().map(WireEventRef::from),
            writer_fence: event.writer_fence(),
            content: event.content().into(),
        }
    }
}

impl From<&EventRef> for WireEventRef {
    fn from(event_ref: &EventRef) -> Self {
        Self {
            sequence: event_ref.sequence(),
            digest: event_ref.digest().to_owned(),
            key: event_ref.key().to_owned(),
        }
    }
}

impl From<EventContent> for WireContent {
    fn from(content: EventContent) -> Self {
        match content {
            EventContent::CampaignCreated => Self::CampaignCreated,
            EventContent::WorkflowStarted => Self::WorkflowStarted,
        }
    }
}

impl TryFrom<WireEvent> for Event {
    type Error = WireError;

    fn try_from(wire: WireEvent) -> Result<Self, Self::Error> {
        let parent = wire.parent.map(EventRef::try_from).transpose()?;
        Event::new(
            wire.operation_id,
            wire.sequence,
            parent,
            wire.writer_fence,
            wire.content.into(),
        )
        .map_err(|_| WireError::InvalidValue)
    }
}

impl TryFrom<WireEventRef> for EventRef {
    type Error = WireError;

    fn try_from(wire: WireEventRef) -> Result<Self, Self::Error> {
        Self::new(wire.sequence, wire.digest, wire.key).map_err(|_| WireError::InvalidValue)
    }
}

impl From<WireContent> for EventContent {
    fn from(content: WireContent) -> Self {
        match content {
            WireContent::CampaignCreated => Self::CampaignCreated,
            WireContent::WorkflowStarted => Self::WorkflowStarted,
        }
    }
}

fn encode_cbor(wire: &WireEvent) -> Result<Vec<u8>, WireError> {
    let mut cbor = Vec::new();
    into_writer(wire, &mut cbor).map_err(|_| WireError::InvalidEncoding)?;
    Ok(cbor)
}

fn compress(cbor: &[u8]) -> Result<Vec<u8>, WireError> {
    zstd::bulk::compress(cbor, ZSTD_LEVEL).map_err(|_| WireError::InvalidEncoding)
}

fn digest(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

#[cfg(test)]
mod tests {
    use ciborium::Value;

    use super::*;

    fn valid_wire() -> WireEvent {
        WireEvent {
            version: WIRE_VERSION,
            operation_id: "op".into(),
            sequence: 1,
            parent: None,
            writer_fence: 7,
            content: WireContent::CampaignCreated,
        }
    }

    fn stored(wire: &WireEvent) -> Vec<u8> {
        compress(&encode_cbor(wire).unwrap()).unwrap()
    }

    fn key(stored: &[u8], sequence: u64) -> String {
        format!("{sequence:016}-{}.cbor.zst", digest(stored))
    }

    fn decode_cbor(cbor: &[u8], sequence: u64) -> Result<Event, WireError> {
        let stored = compress(cbor).unwrap();
        decode(&stored, &key(&stored, sequence))
    }

    fn mutate_value(mutator: impl FnOnce(&mut Vec<(Value, Value)>)) -> Vec<u8> {
        let cbor = encode_cbor(&valid_wire()).unwrap();
        let mut value: Value = ciborium::from_reader(cbor.as_slice()).unwrap();
        let Value::Map(entries) = &mut value else {
            panic!("event wire value should be a map");
        };
        mutator(entries);
        let mut output = Vec::new();
        into_writer(&value, &mut output).unwrap();
        output
    }

    fn incompressible_bytes(len: usize) -> Vec<u8> {
        let mut state = 0x4d59_5df4_d0f3_3173_u64;
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state as u8
            })
            .collect()
    }

    fn nested_arrays(depth: usize) -> Vec<u8> {
        let mut bytes = vec![0x81; depth];
        bytes.push(0xf6);
        bytes
    }

    #[test]
    fn production_cbor_uses_frozen_map_and_scalar_forms() {
        let cbor = encode_cbor(&valid_wire()).unwrap();
        assert!(cbor.starts_with(b"\xa6\x67version\x01\x6coperation_id"));
        assert!(cbor.ends_with(b"\x67content\x70campaign_created"));
    }

    #[test]
    fn rejects_noncanonical_zstd_framing() {
        let cbor = encode_cbor(&valid_wire()).unwrap();
        let alternate_level = zstd::bulk::compress(&cbor, 1).unwrap();
        assert_ne!(alternate_level, compress(&cbor).unwrap());
        assert_eq!(
            decode(&alternate_level, &key(&alternate_level, 1)),
            Err(WireError::NonCanonical)
        );

        let no_content_size = zstd::stream::encode_all(cbor.as_slice(), ZSTD_LEVEL).unwrap();
        assert!(matches!(
            zstd::zstd_safe::get_frame_content_size(&no_content_size),
            Ok(None)
        ));
        assert_eq!(
            decode(&no_content_size, &key(&no_content_size, 1)),
            Err(WireError::NonCanonical)
        );
    }

    #[test]
    fn rejects_unknown_version_and_invalid_references() {
        let mut wire = valid_wire();
        wire.version = 2;
        let bytes = stored(&wire);
        assert_eq!(
            decode(&bytes, &key(&bytes, 1)),
            Err(WireError::InvalidValue)
        );

        let digest = "0".repeat(64);
        wire.version = WIRE_VERSION;
        wire.sequence = 2;
        wire.parent = Some(WireEventRef {
            sequence: 1,
            digest: "G".repeat(64),
            key: "bad".into(),
        });
        let bytes = stored(&wire);
        assert_eq!(
            decode(&bytes, &key(&bytes, 2)),
            Err(WireError::InvalidValue)
        );

        wire.parent = Some(WireEventRef {
            sequence: 1,
            digest: digest.clone(),
            key: "bad".into(),
        });
        let bytes = stored(&wire);
        assert_eq!(
            decode(&bytes, &key(&bytes, 2)),
            Err(WireError::InvalidValue)
        );

        wire.sequence = 3;
        wire.parent = Some(WireEventRef {
            sequence: 1,
            key: format!("{:016}-{digest}.cbor.zst", 1),
            digest,
        });
        let bytes = stored(&wire);
        assert_eq!(
            decode(&bytes, &key(&bytes, 3)),
            Err(WireError::InvalidValue)
        );
    }

    #[test]
    fn rejects_malformed_and_noncanonical_cbor() {
        let bytes = stored(&valid_wire());
        assert!(decode(&bytes[..bytes.len() - 1], "irrelevant").is_err());
        assert_eq!(
            decode(&[1, 2, 3], "irrelevant"),
            Err(WireError::InvalidEncoding)
        );
        let mut corrupted = bytes;
        let middle = corrupted.len() / 2;
        corrupted[middle] ^= 1;
        assert!(decode(&corrupted, "irrelevant").is_err());

        let mut non_shortest = encode_cbor(&valid_wire()).unwrap();
        assert_eq!(non_shortest[9], 1);
        non_shortest.splice(9..10, [0x18, 0x01]);
        assert_eq!(decode_cbor(&non_shortest, 1), Err(WireError::NonCanonical));

        let mut indefinite_map = encode_cbor(&valid_wire()).unwrap();
        indefinite_map[0] = 0xbf;
        indefinite_map.push(0xff);
        assert_eq!(
            decode_cbor(&indefinite_map, 1),
            Err(WireError::NonCanonical)
        );

        let mut trailing = encode_cbor(&valid_wire()).unwrap();
        trailing.push(0);
        assert_eq!(decode_cbor(&trailing, 1), Err(WireError::NonCanonical));
    }

    #[test]
    fn rejects_unknown_missing_duplicate_and_invalid_wire_fields() {
        let unknown = mutate_value(|entries| {
            entries.push((Value::Text("extra".into()), Value::Null));
        });
        assert_eq!(decode_cbor(&unknown, 1), Err(WireError::InvalidEncoding));

        let missing = mutate_value(|entries| {
            entries.retain(|(key, _)| key != &Value::Text("content".into()));
        });
        assert_eq!(decode_cbor(&missing, 1), Err(WireError::InvalidEncoding));

        let duplicate = mutate_value(|entries| entries.push(entries[0].clone()));
        assert_eq!(decode_cbor(&duplicate, 1), Err(WireError::InvalidEncoding));

        let float_version = mutate_value(|entries| entries[0].1 = Value::Float(1.0));
        assert_eq!(
            decode_cbor(&float_version, 1),
            Err(WireError::InvalidEncoding)
        );

        let unknown_content = mutate_value(|entries| {
            let (_, content) = entries
                .iter_mut()
                .find(|(key, _)| key == &Value::Text("content".into()))
                .unwrap();
            *content = Value::Text("future".into());
        });
        assert_eq!(
            decode_cbor(&unknown_content, 1),
            Err(WireError::InvalidEncoding)
        );

        let canonical = encode_cbor(&valid_wire()).unwrap();
        let operation_id = canonical
            .windows(3)
            .position(|window| window == b"\x62op")
            .unwrap();
        let mut indefinite_text = canonical;
        indefinite_text.splice(
            operation_id..operation_id + 3,
            [0x7f, 0x62, b'o', b'p', 0xff],
        );
        assert_eq!(
            decode_cbor(&indefinite_text, 1),
            Err(WireError::NonCanonical)
        );
    }

    #[test]
    fn rejects_all_event_size_limits() {
        assert_eq!(decode(&[], "irrelevant"), Err(WireError::LimitExceeded));

        let payload = incompressible_bytes(320 * 1024);
        let oversized_frame = compress(&payload).unwrap();
        assert!(oversized_frame.len() > MAX_COMPRESSED_BYTES);
        assert_eq!(
            decode(&oversized_frame, "irrelevant"),
            Err(WireError::LimitExceeded)
        );

        let expanded = compress(&vec![0; MAX_DECOMPRESSED_BYTES + 1]).unwrap();
        assert_eq!(
            decode(&expanded, "irrelevant"),
            Err(WireError::LimitExceeded)
        );

        let empty_payload = compress(&[]).unwrap();
        assert_eq!(
            decode(&empty_payload, "irrelevant"),
            Err(WireError::LimitExceeded)
        );

        let mut wire = valid_wire();
        wire.operation_id = "x".repeat(129);
        let bytes = stored(&wire);
        assert_eq!(
            decode(&bytes, &key(&bytes, 1)),
            Err(WireError::InvalidValue)
        );
    }

    #[test]
    fn enforces_cbor_recursion_limit_at_the_codec_boundary() {
        // WireEvent has no recursive field; serde rejects nested values before this
        // codec limit matters. This boundary pair pins the decoder setting itself.
        assert!(
            from_reader_with_recursion_limit::<Value, _>(
                nested_arrays(CBOR_RECURSION_LIMIT).as_slice(),
                CBOR_RECURSION_LIMIT
            )
            .is_ok()
        );
        assert!(
            from_reader_with_recursion_limit::<Value, _>(
                nested_arrays(CBOR_RECURSION_LIMIT + 1).as_slice(),
                CBOR_RECURSION_LIMIT
            )
            .is_err()
        );
    }
}
