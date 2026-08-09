use std::{error::Error, fmt};

const MAX_SEQUENCE: u64 = 9_999_999_999_999_999;
const MAX_IDENTITY_BYTES: usize = 128;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventRef {
    sequence: u64,
    digest: String,
    key: String,
}

impl EventRef {
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventContent {
    CampaignCreated,
    WorkflowStarted,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Event {
    operation_id: String,
    sequence: u64,
    parent: Option<EventRef>,
    writer_fence: u64,
    content: EventContent,
}

impl Event {
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

    pub fn content(&self) -> EventContent {
        self.content
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Authority {
    state: AuthorityState,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum AuthorityState {
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

    pub(crate) fn state(&self) -> &AuthorityState {
        &self.state
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Head {
    authority: Authority,
    tail: EventRef,
    operation_id: String,
}

impl Head {
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValidationError {
    InvalidSequence,
    InvalidDigest,
    InvalidKey,
    InvalidIdentity,
    InvalidParent,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidSequence => "invalid event sequence",
            Self::InvalidDigest => "invalid event digest",
            Self::InvalidKey => "invalid event key",
            Self::InvalidIdentity => "invalid durable identity",
            Self::InvalidParent => "invalid event parent",
        })
    }
}

impl Error for ValidationError {}

fn validate_sequence(sequence: u64) -> Result<(), ValidationError> {
    if (1..=MAX_SEQUENCE).contains(&sequence) {
        Ok(())
    } else {
        Err(ValidationError::InvalidSequence)
    }
}

fn validate_identity(value: &str) -> Result<(), ValidationError> {
    if value.is_empty() || value.len() > MAX_IDENTITY_BYTES {
        Err(ValidationError::InvalidIdentity)
    } else {
        Ok(())
    }
}

fn is_digest(value: &str) -> bool {
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
    }
}
