//! Durable artifact metadata; the artifact object itself contains only bytes.
//!
//! `ArtifactRef` validates durable metadata but accepts any `u64` size, so a publication
//! cap belongs at the publishing boundary rather than here.

use crate::domain::validation::{ValidationError, is_digest, validate_identity};

/// Durable metadata stored beside an artifact blob.
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

#[cfg(test)]
mod tests {
    use super::*;

    fn digest() -> String {
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into()
    }

    #[test]
    fn validates_metadata_fields_without_a_publication_cap() {
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
            ArtifactRef::new(
                "not-a-digest".into(),
                0,
                "type".into(),
                "attempt".into(),
                1,
                None
            ),
            Err(ValidationError::InvalidDigest)
        );
        for (media_type, producer_attempt, retention_class) in [
            (String::new(), "attempt".to_owned(), None),
            ("type".to_owned(), String::new(), None),
            ("type".to_owned(), "attempt".to_owned(), Some(String::new())),
            ("x".repeat(129), "attempt".to_owned(), None),
            ("type".to_owned(), "x".repeat(129), None),
            (
                "type".to_owned(),
                "attempt".to_owned(),
                Some("x".repeat(129)),
            ),
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
