//! Canonical advisory presence records and freshness classification.

use serde::{Deserialize, Serialize};

use crate::{
    distributed::identity::{ActorId, InstanceId},
    domain::campaign::{ValidationError, validate_identity},
    sync::{WIRE_VERSION, WireError},
};

const MAX_PRESENCE_BYTES: usize = 4 * 1024;

/// Validated workspace identity used to construct a presence key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkspaceId(String);

impl WorkspaceId {
    /// Validates a workspace identity.
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

/// Advisory record of one process: actor, instance, static capabilities, and
/// one expiry. Presence carries no ownership, load, assignment, or claim state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Presence {
    actor: ActorId,
    instance: InstanceId,
    capabilities: Vec<String>,
    expires_at_unix_ms: u64,
}

impl Presence {
    /// Validates capabilities and requires a nonzero expiry.
    ///
    /// An empty capability list is accepted, and the list is stored verbatim
    /// without sorting or deduplication.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError`] when a capability is empty or exceeds 128 UTF-8 bytes,
    /// or when `expires_at_unix_ms` is zero.
    pub fn new(
        actor: ActorId,
        instance: InstanceId,
        capabilities: Vec<String>,
        expires_at_unix_ms: u64,
    ) -> Result<Self, ValidationError> {
        for capability in &capabilities {
            validate_identity(capability)?;
        }
        if expires_at_unix_ms == 0 {
            return Err(ValidationError::InvalidExpiry);
        }
        Ok(Self {
            actor,
            instance,
            capabilities,
            expires_at_unix_ms,
        })
    }

    pub fn actor(&self) -> &ActorId {
        &self.actor
    }

    pub fn instance(&self) -> &InstanceId {
        &self.instance
    }

    pub fn capabilities(&self) -> &[String] {
        &self.capabilities
    }

    pub fn expires_at_unix_ms(&self) -> u64 {
        self.expires_at_unix_ms
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WirePresence {
    version: u64,
    actor: String,
    instance: String,
    capabilities: Vec<String>,
    expires_at_unix_ms: u64,
}

/// Builds the object key `workspace/{workspace}/presence/{actor}/{instance}.json`.
///
/// Identities are validated for length only, not path-sanitized; any writer must
/// constrain them before the key reaches object storage.
pub fn presence_key(workspace: &WorkspaceId, actor: &ActorId, instance: &InstanceId) -> String {
    format!(
        "workspace/{}/presence/{}/{}.json",
        workspace.as_str(),
        actor.as_str(),
        instance.as_str()
    )
}

/// Produces compact canonical JSON in the frozen presence field order.
///
/// # Errors
///
/// Returns [`WireError`] when serialization fails or output exceeds 4 KiB.
pub fn encode(presence: &Presence) -> Result<Vec<u8>, WireError> {
    let bytes = serde_json::to_vec(&WirePresence::from(presence))
        .map_err(|_| WireError::InvalidEncoding)?;
    if bytes.len() > MAX_PRESENCE_BYTES {
        return Err(WireError::LimitExceeded);
    }
    Ok(bytes)
}

/// Decodes only exact canonical v1 presence bytes.
///
/// # Errors
///
/// Returns [`WireError`] for empty or oversized input, malformed or alternate JSON,
/// unknown versions, or invalid domain values.
pub fn decode(bytes: &[u8]) -> Result<Presence, WireError> {
    if bytes.is_empty() || bytes.len() > MAX_PRESENCE_BYTES {
        return Err(WireError::LimitExceeded);
    }
    let wire: WirePresence =
        serde_json::from_slice(bytes).map_err(|_| WireError::InvalidEncoding)?;
    let canonical = serde_json::to_vec(&wire).map_err(|_| WireError::InvalidEncoding)?;
    if canonical != bytes {
        return Err(WireError::NonCanonical);
    }
    wire.try_into()
}

/// Returns the presence only when `bytes` are canonical v1, valid, and
/// `now_unix_ms < expires_at_unix_ms`.
///
/// Missing, oversized, malformed, noncanonical, unknown-version, invalid, and
/// expired input all classify as `None`; decode errors are swallowed, so a
/// caller cannot distinguish absent from corrupt. The classifier reads nothing
/// but its arguments and never touches claim state.
pub fn classify(bytes: Option<&[u8]>, now_unix_ms: u64) -> Option<Presence> {
    let presence = decode(bytes?).ok()?;
    (now_unix_ms < presence.expires_at_unix_ms()).then_some(presence)
}

impl From<&Presence> for WirePresence {
    fn from(presence: &Presence) -> Self {
        Self {
            version: WIRE_VERSION,
            actor: presence.actor().as_str().to_owned(),
            instance: presence.instance().as_str().to_owned(),
            capabilities: presence.capabilities().to_vec(),
            expires_at_unix_ms: presence.expires_at_unix_ms(),
        }
    }
}

impl TryFrom<WirePresence> for Presence {
    type Error = WireError;

    fn try_from(wire: WirePresence) -> Result<Self, Self::Error> {
        if wire.version != WIRE_VERSION {
            return Err(WireError::InvalidValue);
        }
        Self::new(
            ActorId::new(wire.actor).map_err(|_| WireError::InvalidValue)?,
            InstanceId::new(wire.instance).map_err(|_| WireError::InvalidValue)?,
            wire.capabilities,
            wire.expires_at_unix_ms,
        )
        .map_err(|_| WireError::InvalidValue)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn presence(expiry: u64) -> Presence {
        Presence::new(
            ActorId::new("rust-worker".into()).unwrap(),
            InstanceId::new("instance-a".into()).unwrap(),
            vec!["rust".into(), "linux-x86_64".into()],
            expiry,
        )
        .unwrap()
    }

    #[test]
    fn workspace_and_presence_values_are_validated() {
        assert!(WorkspaceId::new(String::new()).is_err());
        assert!(WorkspaceId::new("x".repeat(129)).is_err());
        assert!(WorkspaceId::new("x".repeat(128)).is_ok());
        assert!(
            Presence::new(
                ActorId::new("actor".into()).unwrap(),
                InstanceId::new("instance".into()).unwrap(),
                vec![String::new()],
                1,
            )
            .is_err()
        );
        assert!(
            Presence::new(
                ActorId::new("actor".into()).unwrap(),
                InstanceId::new("instance".into()).unwrap(),
                Vec::new(),
                1,
            )
            .is_ok()
        );
        assert!(
            Presence::new(
                ActorId::new("actor".into()).unwrap(),
                InstanceId::new("instance".into()).unwrap(),
                Vec::new(),
                0,
            )
            .is_err()
        );
    }

    #[test]
    fn key_uses_workspace_actor_and_instance() {
        assert_eq!(
            presence_key(
                &WorkspaceId::new("workspace-a".into()).unwrap(),
                &ActorId::new("rust-worker".into()).unwrap(),
                &InstanceId::new("instance-a".into()).unwrap(),
            ),
            "workspace/workspace-a/presence/rust-worker/instance-a.json"
        );
    }

    #[test]
    fn canonical_presence_round_trips() {
        let expected = presence(1_750_000_000_000);
        let decoded = decode(&encode(&expected).unwrap()).unwrap();
        assert_eq!(decoded, expected);
        assert_eq!(decoded.actor().as_str(), "rust-worker");
        assert_eq!(decoded.instance().as_str(), "instance-a");
        assert_eq!(decoded.capabilities(), ["rust", "linux-x86_64"]);
        assert_eq!(decoded.expires_at_unix_ms(), 1_750_000_000_000);
    }

    #[test]
    fn schema_and_alternate_encodings_fail_closed() {
        let canonical = String::from_utf8(encode(&presence(10)).unwrap()).unwrap();
        let unknown_field = canonical.replacen("{", "{\"owner\":\"nobody\",", 1);
        assert_eq!(
            decode(unknown_field.as_bytes()),
            Err(WireError::InvalidEncoding)
        );
        let unknown_version = canonical.replacen("\"version\":1", "\"version\":2", 1);
        assert_eq!(
            decode(unknown_version.as_bytes()),
            Err(WireError::InvalidValue)
        );
        let reordered = canonical.replacen(
            "\"version\":1,\"actor\":\"rust-worker\"",
            "\"actor\":\"rust-worker\",\"version\":1",
            1,
        );
        assert_eq!(decode(reordered.as_bytes()), Err(WireError::NonCanonical));
        assert_eq!(decode(b"not-json"), Err(WireError::InvalidEncoding));
        let zero_expiry =
            canonical.replacen("\"expires_at_unix_ms\":10", "\"expires_at_unix_ms\":0", 1);
        assert_eq!(decode(zero_expiry.as_bytes()), Err(WireError::InvalidValue));
        let empty_capability = canonical.replacen("\"rust\"", "\"\"", 1);
        assert_eq!(
            decode(empty_capability.as_bytes()),
            Err(WireError::InvalidValue)
        );
    }

    #[test]
    fn classifier_treats_every_unusable_record_as_absent() {
        assert_eq!(classify(None, 9), None);
        assert_eq!(classify(Some(b"not-json"), 9), None);

        let canonical = String::from_utf8(encode(&presence(10)).unwrap()).unwrap();
        let unknown_version = canonical.replacen("\"version\":1", "\"version\":2", 1);
        assert_eq!(classify(Some(unknown_version.as_bytes()), 9), None);

        let zero_expiry =
            canonical.replacen("\"expires_at_unix_ms\":10", "\"expires_at_unix_ms\":0", 1);
        assert_eq!(classify(Some(zero_expiry.as_bytes()), 0), None);
        assert_eq!(classify(Some(canonical.as_bytes()), 10), None);
        assert_eq!(classify(Some(canonical.as_bytes()), 11), None);
        assert_eq!(classify(Some(canonical.as_bytes()), 9), Some(presence(10)));
    }

    #[test]
    fn size_limits_apply_to_decode_and_encode() {
        assert_eq!(decode(b""), Err(WireError::LimitExceeded));
        assert_eq!(
            decode(&vec![b'x'; MAX_PRESENCE_BYTES + 1]),
            Err(WireError::LimitExceeded)
        );
        let oversized = Presence::new(
            ActorId::new("actor".into()).unwrap(),
            InstanceId::new("instance".into()).unwrap(),
            vec!["capability".into(); 500],
            1,
        )
        .unwrap();
        assert_eq!(encode(&oversized), Err(WireError::LimitExceeded));
    }
}
