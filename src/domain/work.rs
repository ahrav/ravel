//! Validated work identity and revision references.

use crate::domain::validation::{ValidationError, validate_key_segment};

/// Validated identity of one work item.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkId(String);

impl WorkId {
    /// Validates a work identity.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError`] when `value` is empty, exceeds 128 UTF-8 bytes,
    /// or contains `/`.
    pub fn new(value: String) -> Result<Self, ValidationError> {
        validate_key_segment(&value)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Shape-validated work identity paired with a caller-supplied revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkRef {
    id: WorkId,
    revision: u64,
}

impl WorkRef {
    pub fn new(id: WorkId, revision: u64) -> Self {
        Self { id, revision }
    }

    pub fn id(&self) -> &WorkId {
        &self.id
    }

    pub fn revision(&self) -> u64 {
        self.revision
    }
}

#[cfg(test)]
mod tests {
    use super::{WorkId, WorkRef};

    #[test]
    fn work_id_enforces_shared_boundaries() {
        assert!(WorkId::new(String::new()).is_err());
        assert!(WorkId::new("x".repeat(129)).is_err());
        assert!(WorkId::new("x".repeat(128)).is_ok());
    }

    #[test]
    fn work_ref_preserves_identity_and_revision() {
        let work = WorkRef::new(WorkId::new("work-17".into()).unwrap(), 0);
        assert_eq!(work.id().as_str(), "work-17");
        assert_eq!(work.revision(), 0);
    }
}
