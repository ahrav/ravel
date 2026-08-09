//! The v1 event encoding is frozen.
//!
//! CBOR is a definite-length map whose declaration-order text keys are
//! `version`, `operation_id`, `sequence`, `parent`, `writer_fence`, and
//! `content`. Integers use ciborium's shortest representation. `parent` is
//! either null or a declaration-order map of `sequence`, `digest`, and `key`.
//! Content is a text value for `campaign_created` and `workflow_started`, or an
//! externally tagged `artifact_published` reference map.
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
//!
//! Event publication requires a matching artifact witness before object-store I/O.

use std::io::Cursor;

use ciborium::{de::from_reader_with_recursion_limit, ser::into_writer};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    domain::campaign::{ArtifactRef, Event, EventContent, EventRef},
    storage::{
        artifacts::PublishedArtifact,
        s3::{PublicationError, S3Store},
    },
};

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

/// Proof that immutable event bytes are present at their canonical key.
#[derive(Debug)]
pub struct ResolvedEventPublication(EventRef);

impl ResolvedEventPublication {
    pub fn event_ref(&self) -> &EventRef {
        &self.0
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

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum WireContent {
    CampaignCreated,
    WorkflowStarted,
    ArtifactPublished(WireArtifactRef),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireArtifactRef {
    digest: String,
    size: u64,
    media_type: String,
    producer_attempt: String,
    creation_time_unix_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    retention_class: Option<String>,
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

pub async fn publish(
    store: &S3Store,
    event: &Event,
    artifact: Option<&PublishedArtifact>,
) -> Result<ResolvedEventPublication, PublicationError> {
    match (event.content(), artifact) {
        (EventContent::ArtifactPublished(reference), Some(published))
            if reference == published.artifact_ref() => {}
        (EventContent::CampaignCreated | EventContent::WorkflowStarted, None) => {}
        _ => return Err(PublicationError::InvalidInput),
    }

    let encoded = encode(event).map_err(|error| match error {
        WireError::LimitExceeded => PublicationError::TooLarge,
        WireError::InvalidEncoding
        | WireError::NonCanonical
        | WireError::InvalidValue
        | WireError::ReferenceMismatch => PublicationError::InvalidInput,
    })?;
    store
        .publish_immutable(
            encoded.key(),
            encoded.stored_bytes().to_vec(),
            encoded.digest(),
        )
        .await?;
    Ok(ResolvedEventPublication(encoded.reference))
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

impl From<&EventContent> for WireContent {
    fn from(content: &EventContent) -> Self {
        match content {
            EventContent::CampaignCreated => Self::CampaignCreated,
            EventContent::WorkflowStarted => Self::WorkflowStarted,
            EventContent::ArtifactPublished(reference) => {
                Self::ArtifactPublished(WireArtifactRef::from(reference))
            }
        }
    }
}

impl From<&ArtifactRef> for WireArtifactRef {
    fn from(reference: &ArtifactRef) -> Self {
        Self {
            digest: reference.digest().to_owned(),
            size: reference.size(),
            media_type: reference.media_type().to_owned(),
            producer_attempt: reference.producer_attempt().to_owned(),
            creation_time_unix_ms: reference.creation_time_unix_ms(),
            retention_class: reference.retention_class().map(str::to_owned),
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
            wire.content.try_into()?,
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

impl TryFrom<WireContent> for EventContent {
    type Error = WireError;

    fn try_from(content: WireContent) -> Result<Self, Self::Error> {
        match content {
            WireContent::CampaignCreated => Ok(Self::CampaignCreated),
            WireContent::WorkflowStarted => Ok(Self::WorkflowStarted),
            WireContent::ArtifactPublished(reference) => Ok(Self::ArtifactPublished(
                ArtifactRef::new(
                    reference.digest,
                    reference.size,
                    reference.media_type,
                    reference.producer_attempt,
                    reference.creation_time_unix_ms,
                    reference.retention_class,
                )
                .map_err(|_| WireError::InvalidValue)?,
            )),
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
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use aws_sdk_s3::{config::Region, primitives::SdkBody};
    use aws_smithy_runtime::client::http::test_util::NeverClient;
    use ciborium::Value;

    use crate::storage::{
        artifacts,
        s3::test_support::{replay_store, response, test_builder},
    };

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

        let digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let prefix = b"\xa6\x67version\x01\x6coperation_id\x62op\x68sequence\x01\x66parent\xf6\x6cwriter_fence\x07\x67content\xa1\x72artifact_published";
        let fields = b"\x66digest\x78\x40";
        let suffix = b"\x64size\x04\x6amedia_type\x78\x18application/octet-stream\x70producer_attempt\x67attempt\x75creation_time_unix_ms\x18\x7b";

        let mut wire = valid_wire();
        wire.content = WireContent::ArtifactPublished(WireArtifactRef {
            digest: digest.into(),
            size: 4,
            media_type: "application/octet-stream".into(),
            producer_attempt: "attempt".into(),
            creation_time_unix_ms: 123,
            retention_class: None,
        });
        let expected = [
            prefix.as_slice(),
            b"\xa5".as_slice(),
            fields.as_slice(),
            digest.as_bytes(),
            suffix.as_slice(),
        ]
        .concat();
        assert_eq!(encode_cbor(&wire).unwrap(), expected);

        let WireContent::ArtifactPublished(reference) = &mut wire.content else {
            unreachable!();
        };
        reference.retention_class = Some("pilot".into());
        let expected = [
            prefix.as_slice(),
            b"\xa6".as_slice(),
            fields.as_slice(),
            digest.as_bytes(),
            suffix.as_slice(),
            b"\x6fretention_class\x65pilot".as_slice(),
        ]
        .concat();
        assert_eq!(encode_cbor(&wire).unwrap(), expected);
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
    fn artifact_content_round_trips_canonically() {
        for retention_class in [None, Some("pilot".to_owned())] {
            let artifact = ArtifactRef::new(
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
                4,
                "application/octet-stream".into(),
                "attempt".into(),
                123,
                retention_class,
            )
            .unwrap();
            let event = Event::new(
                "artifact-op".into(),
                1,
                None,
                7,
                EventContent::ArtifactPublished(artifact),
            )
            .unwrap();
            let encoded = encode(&event).unwrap();
            let decoded = decode(encoded.stored_bytes(), encoded.key()).unwrap();
            assert_eq!(decoded, event);
            assert_eq!(encode(&decoded).unwrap(), encoded);
        }
    }

    #[tokio::test]
    async fn artifact_event_requires_a_matching_publication() {
        let store = S3Store::new(
            "test-bucket",
            Region::new("us-east-1"),
            test_builder(NeverClient::new()),
        );
        let reference = ArtifactRef::new(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
            4,
            "application/octet-stream".into(),
            "attempt".into(),
            1,
            None,
        )
        .unwrap();
        let event = Event::new(
            "event-op".into(),
            1,
            None,
            1,
            EventContent::ArtifactPublished(reference),
        )
        .unwrap();
        assert!(matches!(
            publish(&store, &event, None).await,
            Err(PublicationError::InvalidInput)
        ));
    }

    #[tokio::test]
    async fn matching_artifact_allows_event_publication_at_the_encoded_key() {
        let artifact_bytes = b"artifact".to_vec();
        let (store, client) = replay_store(vec![
            response(200, &[], SdkBody::empty()),
            response(200, &[], SdkBody::empty()),
        ]);
        let artifact = artifacts::publish(
            &store,
            artifact_bytes,
            "application/octet-stream".into(),
            "attempt".into(),
            1,
            None,
        )
        .await
        .unwrap();
        let mismatched = Event::new(
            "event-op".into(),
            1,
            None,
            1,
            EventContent::ArtifactPublished(
                ArtifactRef::new(
                    artifact.artifact_ref().digest().to_owned(),
                    artifact.artifact_ref().size(),
                    artifact.artifact_ref().media_type().to_owned(),
                    "another-attempt".into(),
                    1,
                    None,
                )
                .unwrap(),
            ),
        )
        .unwrap();
        assert!(matches!(
            publish(&store, &mismatched, Some(&artifact)).await,
            Err(PublicationError::InvalidInput)
        ));
        let unit_event =
            Event::new("unit-op".into(), 1, None, 1, EventContent::CampaignCreated).unwrap();
        assert!(matches!(
            publish(&store, &unit_event, Some(&artifact)).await,
            Err(PublicationError::InvalidInput)
        ));
        assert_eq!(client.actual_requests().count(), 1);

        let event = Event::new(
            "event-op".into(),
            1,
            None,
            1,
            EventContent::ArtifactPublished(artifact.artifact_ref().clone()),
        )
        .unwrap();
        let encoded = encode(&event).unwrap();
        let resolved = publish(&store, &event, Some(&artifact)).await.unwrap();
        assert_eq!(resolved.event_ref(), &encoded.reference);
        let uri = client
            .actual_requests()
            .nth(1)
            .expect("event PUT")
            .uri()
            .parse::<http::Uri>()
            .expect("valid request URI");
        assert_eq!(uri.path(), format!("/{}", encoded.key()));
    }

    #[tokio::test]
    async fn unresolved_storage_does_not_create_an_event_publication() {
        let (store, _) = replay_store(vec![
            response(500, &[], SdkBody::empty()),
            response(500, &[], SdkBody::empty()),
        ]);
        let event =
            Event::new("event-op".into(), 1, None, 1, EventContent::CampaignCreated).unwrap();
        assert!(matches!(
            publish(&store, &event, None).await,
            Err(PublicationError::Unresolved)
        ));
    }

    #[test]
    fn enforces_cbor_recursion_limit_at_the_codec_boundary() {
        // WireEvent has no recursive field; serde rejects nested values before this
        // codec limit matters. This boundary pair pins the decoder setting itself.
        assert_eq!(CBOR_RECURSION_LIMIT, 16);
        assert!(
            from_reader_with_recursion_limit::<Value, _>(
                nested_arrays(16).as_slice(),
                CBOR_RECURSION_LIMIT
            )
            .is_ok()
        );
        assert!(
            from_reader_with_recursion_limit::<Value, _>(
                nested_arrays(17).as_slice(),
                CBOR_RECURSION_LIMIT
            )
            .is_err()
        );
    }
}
