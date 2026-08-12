//! Validated domain values for the durable event chain and authority-bearing head.
//!
//! Constructors are the semantic boundary between permissive wire decoders and
//! protocol state. Event sequences occupy `1..=9_999_999_999_999_999`, which keeps
//! the decimal sequence component of every event key at exactly 16 digits. Sequence
//! 1 has no parent; every subsequent event names the immediately preceding sequence.
//! Digests are 64 lowercase hexadecimal bytes, and durable identities are nonempty
//! UTF-8 strings of at most 128 bytes.
//!
//! `ArtifactRef` validates durable metadata but accepts any `u64` size.

use std::{error::Error, fmt};

const MAX_SEQUENCE: u64 = 9_999_999_999_999_999;
const MAX_IDENTITY_BYTES: usize = 128;

/// Sequence, digest, and derived key for one immutable event object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventRef {
    sequence: u64,
    digest: String,
    key: String,
}

impl EventRef {
    /// Validates the sequence and digest, then requires `key` to equal the derived key.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError`] for a sequence outside the durable range or a digest
    /// that is not 64-byte lowercase hexadecimal text. A key that does not match the
    /// sequence and digest also fails validation.
    pub fn new(sequence: u64, digest: String, key: String) -> Result<Self, ValidationError> {
        let event_ref = Self::from_digest(sequence, digest)?;
        if key != event_ref.key {
            return Err(ValidationError::InvalidKey);
        }
        Ok(event_ref)
    }

    pub(crate) fn from_digest(sequence: u64, digest: String) -> Result<Self, ValidationError> {
        validate_sequence(sequence)?;
        if !is_digest(&digest) {
            return Err(ValidationError::InvalidDigest);
        }
        Ok(Self {
            sequence,
            key: event_key(sequence, &digest),
            digest,
        })
    }

    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }

    pub fn key(&self) -> &str {
        &self.key
    }
}

/// Closed set of payloads encoded by the frozen event format.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EventContent {
    CampaignCreated,
    WorkflowStarted,
    ArtifactPublished(ArtifactRef),
}

/// Durable metadata stored inside an event; the artifact object contains only bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactRef {
    digest: String,
    size: u64,
    media_type: String,
    producer_attempt: String,
    creation_time_unix_ms: u64,
    retention_class: Option<String>,
}

impl ArtifactRef {
    /// Validates the digest and bounded textual metadata without applying a blob-size cap.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError`] for a malformed digest, empty identity, or identity
    /// longer than 128 UTF-8 bytes.
    pub fn new(
        digest: String,
        size: u64,
        media_type: String,
        producer_attempt: String,
        creation_time_unix_ms: u64,
        retention_class: Option<String>,
    ) -> Result<Self, ValidationError> {
        if !is_digest(&digest) {
            return Err(ValidationError::InvalidDigest);
        }
        validate_identity(&media_type)?;
        validate_identity(&producer_attempt)?;
        if let Some(value) = &retention_class {
            validate_identity(value)?;
        }
        Ok(Self {
            digest,
            size,
            media_type,
            producer_attempt,
            creation_time_unix_ms,
            retention_class,
        })
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    pub fn media_type(&self) -> &str {
        &self.media_type
    }

    pub fn producer_attempt(&self) -> &str {
        &self.producer_attempt
    }

    pub fn creation_time_unix_ms(&self) -> u64 {
        self.creation_time_unix_ms
    }

    pub fn retention_class(&self) -> Option<&str> {
        self.retention_class.as_deref()
    }
}

/// Immutable operation record linked to the immediately preceding event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Event {
    operation_id: String,
    sequence: u64,
    parent: Option<EventRef>,
    writer_fence: u64,
    content: EventContent,
}

impl Event {
    /// Enforces the genesis-or-immediate-parent sequence relationship.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError`] for an invalid operation identity, sequence outside
    /// the durable range, or parent inconsistent with the sequence.
    pub fn new(
        operation_id: String,
        sequence: u64,
        parent: Option<EventRef>,
        writer_fence: u64,
        content: EventContent,
    ) -> Result<Self, ValidationError> {
        validate_identity(&operation_id)?;
        validate_sequence(sequence)?;
        match (sequence, &parent) {
            (1, None) => {}
            (1, Some(_)) | (_, None) => return Err(ValidationError::InvalidParent),
            (sequence, Some(parent)) if parent.sequence() == sequence - 1 => {}
            (_, Some(_)) => return Err(ValidationError::InvalidParent),
        }
        Ok(Self {
            operation_id,
            sequence,
            parent,
            writer_fence,
            content,
        })
    }

    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn parent(&self) -> Option<&EventRef> {
        self.parent.as_ref()
    }

    pub fn writer_fence(&self) -> u64 {
        self.writer_fence
    }

    pub fn content(&self) -> &EventContent {
        &self.content
    }
}

/// Controller authority carried by the canonical head.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Authority {
    state: AuthorityState,
}

/// Explicit absence or ownership of controller authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthorityState {
    Unowned,
    Owned {
        owner: String,
        instance: String,
        lease_until: u64,
        controller_fence: u64,
    },
}

impl Authority {
    pub fn unowned() -> Self {
        Self {
            state: AuthorityState::Unowned,
        }
    }

    /// Creates owned authority after validating the owner and instance identities.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError`] when either identity is empty or exceeds 128 bytes.
    pub fn owned(
        owner: String,
        instance: String,
        lease_until: u64,
        controller_fence: u64,
    ) -> Result<Self, ValidationError> {
        validate_identity(&owner)?;
        validate_identity(&instance)?;
        Ok(Self {
            state: AuthorityState::Owned {
                owner,
                instance,
                lease_until,
                controller_fence,
            },
        })
    }

    pub fn state(&self) -> &AuthorityState {
        &self.state
    }
}

/// Canonical publication authority and its authoritative event tail.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Head {
    authority: Authority,
    tail: EventRef,
    operation_id: String,
}

impl Head {
    /// Associates an authority state and event tail with one head-mutation identity.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError`] when the operation identity is empty or exceeds
    /// 128 bytes.
    pub fn new(
        authority: Authority,
        tail: EventRef,
        operation_id: String,
    ) -> Result<Self, ValidationError> {
        validate_identity(&operation_id)?;
        Ok(Self {
            authority,
            tail,
            operation_id,
        })
    }

    pub fn authority(&self) -> &Authority {
        &self.authority
    }

    pub fn tail(&self) -> &EventRef {
        &self.tail
    }

    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }
}

/// Static category for a rejected durable domain value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValidationError {
    InvalidSequence,
    InvalidDigest,
    InvalidKey,
    InvalidIdentity,
    InvalidParent,
    InvalidFence,
    InvalidExpiry,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidSequence => "invalid event sequence",
            Self::InvalidDigest => "invalid event digest",
            Self::InvalidKey => "invalid event key",
            Self::InvalidIdentity => "invalid durable identity",
            Self::InvalidParent => "invalid event parent",
            Self::InvalidFence => "invalid fence",
            Self::InvalidExpiry => "invalid expiry",
        })
    }
}

impl Error for ValidationError {}

pub(crate) fn validate_sequence(sequence: u64) -> Result<(), ValidationError> {
    if (1..=MAX_SEQUENCE).contains(&sequence) {
        Ok(())
    } else {
        Err(ValidationError::InvalidSequence)
    }
}

pub(crate) fn validate_identity(value: &str) -> Result<(), ValidationError> {
    if value.is_empty() || value.len() > MAX_IDENTITY_BYTES {
        Err(ValidationError::InvalidIdentity)
    } else {
        Ok(())
    }
}

/// A `/` inside a key segment makes distinct identity tuples derive one key: an
/// actor `a/b` with instance `c` and an actor `a` with instance `b/c` both land on
/// `.../a/b/c.json`.
///
/// # Errors
///
/// Returns [`ValidationError::InvalidIdentity`] when `value` is empty, exceeds
/// 128 UTF-8 bytes, or contains `/`.
pub(crate) fn validate_key_segment(value: &str) -> Result<(), ValidationError> {
    validate_identity(value)?;
    if value.contains('/') {
        return Err(ValidationError::InvalidIdentity);
    }
    Ok(())
}

pub(crate) fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn event_key(sequence: u64, digest: &str) -> String {
    format!("{sequence:016}-{digest}.cbor.zst")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest() -> String {
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into()
    }

    fn event_ref(sequence: u64) -> EventRef {
        let digest = digest();
        EventRef::new(sequence, digest.clone(), event_key(sequence, &digest)).unwrap()
    }

    #[test]
    fn validates_reference_parts() {
        assert_eq!(
            EventRef::new(0, digest(), String::new()),
            Err(ValidationError::InvalidSequence)
        );
        assert_eq!(
            EventRef::new(MAX_SEQUENCE + 1, digest(), String::new()),
            Err(ValidationError::InvalidSequence)
        );
        assert_eq!(
            EventRef::new(1, "A".repeat(64), String::new()),
            Err(ValidationError::InvalidDigest)
        );
        assert_eq!(
            EventRef::new(1, digest(), "wrong".into()),
            Err(ValidationError::InvalidKey)
        );
    }

    #[test]
    fn validates_event_parent_relationship() {
        assert_eq!(
            Event::new(
                "op".into(),
                1,
                Some(event_ref(1)),
                1,
                EventContent::CampaignCreated,
            ),
            Err(ValidationError::InvalidParent)
        );
        assert_eq!(
            Event::new(
                "op".into(),
                2,
                Some(event_ref(2)),
                1,
                EventContent::WorkflowStarted,
            ),
            Err(ValidationError::InvalidParent)
        );
    }

    #[test]
    fn validates_identity_limits() {
        assert_eq!(
            Authority::owned(String::new(), "instance".into(), 1, 1),
            Err(ValidationError::InvalidIdentity)
        );
        assert_eq!(
            Event::new("x".repeat(129), 1, None, 1, EventContent::CampaignCreated,),
            Err(ValidationError::InvalidIdentity)
        );
        assert!(Authority::owned("x".repeat(MAX_IDENTITY_BYTES), "i".into(), 1, 1).is_ok());
    }

    #[test]
    fn accepts_maximum_sequence() {
        assert!(EventRef::from_digest(MAX_SEQUENCE, digest()).is_ok());
    }

    #[test]
    fn validates_artifact_reference_fields_without_a_publication_cap() {
        assert!(
            ArtifactRef::new(
                digest(),
                u64::MAX,
                "application/octet-stream".into(),
                "attempt".into(),
                1,
                None
            )
            .is_ok()
        );
        assert_eq!(
            ArtifactRef::new(digest(), 0, String::new(), "attempt".into(), 1, None),
            Err(ValidationError::InvalidIdentity)
        );
        assert_eq!(
            ArtifactRef::new(digest(), 0, "type".into(), String::new(), 1, None),
            Err(ValidationError::InvalidIdentity)
        );
        assert_eq!(
            ArtifactRef::new(
                digest(),
                0,
                "type".into(),
                "attempt".into(),
                1,
                Some(String::new())
            ),
            Err(ValidationError::InvalidIdentity)
        );
        for (media_type, producer_attempt, retention_class) in [
            ("x".repeat(129), "attempt".into(), None),
            ("type".into(), "x".repeat(129), None),
            ("type".into(), "attempt".into(), Some("x".repeat(129))),
        ] {
            assert_eq!(
                ArtifactRef::new(
                    digest(),
                    0,
                    media_type,
                    producer_attempt,
                    1,
                    retention_class,
                ),
                Err(ValidationError::InvalidIdentity)
            );
        }
    }
}
