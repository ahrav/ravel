//! Shared boundary checks between permissive wire decoders and protocol state.
//!
//! Event sequences occupy `1..=9_999_999_999_999_999`, which keeps the decimal sequence
//! component of every event key at exactly 16 digits. Digests are 64 lowercase
//! hexadecimal bytes, and durable identities are nonempty UTF-8 strings of at most
//! 128 bytes.

use std::{error::Error, fmt};

const MAX_SEQUENCE: u64 = 9_999_999_999_999_999;
const MAX_IDENTITY_BYTES: usize = 128;

/// Static category for a rejected durable domain value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValidationError {
    InvalidSequence,
    InvalidDigest,
    InvalidIdentity,
    InvalidParent,
    InvalidFence,
    InvalidExpiry,
    OutOfRange,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidSequence => "invalid event sequence",
            Self::InvalidDigest => "invalid event digest",
            Self::InvalidIdentity => "invalid durable identity",
            Self::InvalidParent => "invalid event parent",
            Self::InvalidFence => "invalid fence",
            Self::InvalidExpiry => "invalid expiry",
            Self::OutOfRange => "value out of stored range",
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

/// A `/` inside a key segment makes distinct identity tuples derive one key: a workspace
/// `a/b` with campaign `c` and a workspace `a` with campaign `b/c` both land on
/// `workspace/a/b/campaigns/c/...` variants of the same path.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sequence_bounds_are_inclusive() {
        assert_eq!(
            validate_sequence(0),
            Err(ValidationError::InvalidSequence),
            "zero is outside the durable range"
        );
        assert!(validate_sequence(1).is_ok());
        assert!(validate_sequence(MAX_SEQUENCE).is_ok());
        assert_eq!(
            validate_sequence(MAX_SEQUENCE + 1),
            Err(ValidationError::InvalidSequence)
        );
    }

    #[test]
    fn identity_bounds_and_key_delimiter_are_enforced() {
        assert!(validate_identity("").is_err());
        assert!(validate_identity(&"x".repeat(MAX_IDENTITY_BYTES)).is_ok());
        assert!(validate_identity(&"x".repeat(MAX_IDENTITY_BYTES + 1)).is_err());
        // A key segment additionally rejects the path delimiter.
        assert!(validate_key_segment("a").is_ok());
        for value in ["a/b", "/leading", "trailing/", "/"] {
            assert!(validate_key_segment(value).is_err(), "segment {value:?}");
        }
    }

    #[test]
    fn digests_are_exactly_lowercase_hexadecimal_sha256() {
        assert!(is_digest(&"0".repeat(64)));
        assert!(is_digest(&"abcdef0123456789".repeat(4)));
        assert!(!is_digest(&"A".repeat(64)));
        assert!(!is_digest(&"g".repeat(64)));
        assert!(!is_digest(&"0".repeat(63)));
        assert!(!is_digest(&"0".repeat(65)));
    }
}
