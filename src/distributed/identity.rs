//! Validated actor and process-incarnation identities.

use crate::domain::campaign::{ValidationError, validate_identity};

/// Identity of a logical claimant, stable across process restarts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActorId(String);

impl ActorId {
    /// Validates an actor identity.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError`] when `value` is empty or exceeds 128 UTF-8 bytes.
    pub fn new(value: String) -> Result<Self, ValidationError> {
        validate_identity(&value)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Identity of one process incarnation.
///
/// [`Self::generate`] produces a fresh value once per process start;
/// [`Self::new`] accepts an already-decoded value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstanceId(String);

impl InstanceId {
    /// Validates a process-instance identity.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError`] when `value` is empty or exceeds 128 UTF-8 bytes.
    pub fn new(value: String) -> Result<Self, ValidationError> {
        validate_identity(&value)?;
        Ok(Self(value))
    }

    /// Generates a 128-bit identity from operating-system randomness, formatted
    /// as 32 lowercase hexadecimal characters.
    ///
    /// # Errors
    ///
    /// Returns [`getrandom::Error`] when the operating system cannot provide random bytes.
    pub fn generate() -> Result<Self, getrandom::Error> {
        let mut bytes = [0_u8; 16];
        getrandom::fill(&mut bytes)?;
        Ok(Self(format!("{:032x}", u128::from_be_bytes(bytes))))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::{ActorId, InstanceId};

    #[test]
    fn identities_enforce_shared_boundaries() {
        for value in [String::new(), "x".repeat(129)] {
            assert!(ActorId::new(value.clone()).is_err());
            assert!(InstanceId::new(value).is_err());
        }
        assert!(ActorId::new("x".repeat(128)).is_ok());
        assert!(InstanceId::new("x".repeat(128)).is_ok());
    }

    #[test]
    fn generated_instances_are_distinct() {
        assert_ne!(
            InstanceId::generate().unwrap(),
            InstanceId::generate().unwrap()
        );
    }

    #[test]
    fn generated_instances_are_fixed_lowercase_hex() {
        let instance = InstanceId::generate().unwrap();
        assert_eq!(instance.as_str().len(), 32);
        assert!(
            instance
                .as_str()
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );
    }
}
