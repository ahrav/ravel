//! Canonical submission records bind immutable result identity to one claim generation.
//!
//! The attempt ID is the artifact's validated `producer_attempt` and names the
//! immutable submission key, so it must be unique per campaign: reusing one
//! attempt ID for different submission bytes fails closed at publication with
//! an integrity mismatch.

use serde::{Deserialize, Serialize};

use crate::{
    distributed::identity::{ActorId, InstanceId},
    domain::{
        campaign::{ArtifactRef, ValidationError, validate_identity},
        work::WorkId,
    },
    sync::{WIRE_VERSION, WireError, event::WireArtifactRef},
};

pub(crate) const MAX_SUBMISSION_BYTES: usize = 4 * 1024;

/// Immutable submission identity for one claimed work generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Submission {
    attempt_id: String,
    work_id: WorkId,
    work_revision: u64,
    owner_actor: ActorId,
    owner_instance: InstanceId,
    fence: u64,
    operation_id: String,
    result_ref: ArtifactRef,
}

impl Submission {
    /// Constructs a submission whose attempt identity comes from its result reference.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError`] for a zero fence or invalid operation identity.
    pub(crate) fn new(
        work_id: WorkId,
        work_revision: u64,
        owner_actor: ActorId,
        owner_instance: InstanceId,
        fence: u64,
        operation_id: String,
        result_ref: ArtifactRef,
    ) -> Result<Self, ValidationError> {
        if fence == 0 {
            return Err(ValidationError::InvalidFence);
        }
        validate_identity(&operation_id)?;
        Ok(Self {
            attempt_id: result_ref.producer_attempt().to_owned(),
            work_id,
            work_revision,
            owner_actor,
            owner_instance,
            fence,
            operation_id,
            result_ref,
        })
    }

    pub fn attempt_id(&self) -> &str {
        &self.attempt_id
    }

    pub fn work_id(&self) -> &WorkId {
        &self.work_id
    }

    pub fn work_revision(&self) -> u64 {
        self.work_revision
    }

    pub fn owner_actor(&self) -> &ActorId {
        &self.owner_actor
    }

    pub fn owner_instance(&self) -> &InstanceId {
        &self.owner_instance
    }

    pub fn fence(&self) -> u64 {
        self.fence
    }

    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    pub fn result_ref(&self) -> &ArtifactRef {
        &self.result_ref
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireSubmission {
    version: u64,
    attempt_id: String,
    work_id: String,
    work_revision: u64,
    owner_actor: String,
    owner_instance: String,
    fence: u64,
    operation_id: String,
    result_ref: WireArtifactRef,
}

/// Produces compact canonical JSON in submission field order.
///
/// # Errors
///
/// Returns [`WireError::LimitExceeded`] when output exceeds 4 KiB.
pub fn encode(submission: &Submission) -> Result<Vec<u8>, WireError> {
    let bytes = serde_json::to_vec(&WireSubmission::from(submission))
        .map_err(|_| WireError::InvalidEncoding)?;
    if bytes.len() > MAX_SUBMISSION_BYTES {
        return Err(WireError::LimitExceeded);
    }
    Ok(bytes)
}

/// Decodes only exact canonical v1 submission bytes.
///
/// # Errors
///
/// Returns [`WireError`] for empty or oversized input, malformed or alternate JSON,
/// unknown versions, mismatched attempt identity, or invalid domain values.
pub fn decode(bytes: &[u8]) -> Result<Submission, WireError> {
    if bytes.is_empty() || bytes.len() > MAX_SUBMISSION_BYTES {
        return Err(WireError::LimitExceeded);
    }
    let wire: WireSubmission =
        serde_json::from_slice(bytes).map_err(|_| WireError::InvalidEncoding)?;
    let canonical = serde_json::to_vec(&wire).map_err(|_| WireError::InvalidEncoding)?;
    if canonical != bytes {
        return Err(WireError::NonCanonical);
    }
    wire.try_into()
}

// Key layout is duplicated in tests/live_s3_preflight.rs; keep those literals
// in sync.
pub(crate) fn submission_key(
    workspace_id: &str,
    campaign_id: &str,
    attempt_id: &str,
) -> Result<String, ValidationError> {
    for component in [workspace_id, campaign_id, attempt_id] {
        validate_identity(component)?;
        if component.contains('/') {
            return Err(ValidationError::InvalidKey);
        }
    }
    Ok(format!(
        "workspace/{workspace_id}/campaigns/{campaign_id}/submissions/{attempt_id}.json"
    ))
}

impl From<&Submission> for WireSubmission {
    fn from(submission: &Submission) -> Self {
        Self {
            version: WIRE_VERSION,
            attempt_id: submission.attempt_id().to_owned(),
            work_id: submission.work_id().as_str().to_owned(),
            work_revision: submission.work_revision(),
            owner_actor: submission.owner_actor().as_str().to_owned(),
            owner_instance: submission.owner_instance().as_str().to_owned(),
            fence: submission.fence(),
            operation_id: submission.operation_id().to_owned(),
            result_ref: WireArtifactRef::from(submission.result_ref()),
        }
    }
}

impl TryFrom<WireSubmission> for Submission {
    type Error = WireError;

    fn try_from(wire: WireSubmission) -> Result<Self, Self::Error> {
        if wire.version != WIRE_VERSION {
            return Err(WireError::InvalidValue);
        }
        let result_ref: ArtifactRef = wire.result_ref.try_into()?;
        if wire.attempt_id != result_ref.producer_attempt() {
            return Err(WireError::InvalidValue);
        }
        Self::new(
            WorkId::new(wire.work_id).map_err(|_| WireError::InvalidValue)?,
            wire.work_revision,
            ActorId::new(wire.owner_actor).map_err(|_| WireError::InvalidValue)?,
            InstanceId::new(wire.owner_instance).map_err(|_| WireError::InvalidValue)?,
            wire.fence,
            wire.operation_id,
            result_ref,
        )
        .map_err(|_| WireError::InvalidValue)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn artifact() -> ArtifactRef {
        ArtifactRef::new(
            "0".repeat(64),
            42,
            "application/json".into(),
            "attempt-17".into(),
            1_750_000_000_000,
            None,
        )
        .unwrap()
    }

    fn submission() -> Submission {
        Submission::new(
            WorkId::new("work-17".into()).unwrap(),
            4,
            ActorId::new("rust-worker".into()).unwrap(),
            InstanceId::new("instance-a".into()).unwrap(),
            9,
            "op-claim-001".into(),
            artifact(),
        )
        .unwrap()
    }

    #[test]
    fn canonical_round_trip_pins_field_order() {
        let submission = submission();
        let bytes = encode(&submission).unwrap();
        assert_eq!(decode(&bytes), Ok(submission));
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.starts_with(
            "{\"version\":1,\"attempt_id\":\"attempt-17\",\"work_id\":\"work-17\",\"work_revision\":4,\"owner_actor\":\"rust-worker\",\"owner_instance\":\"instance-a\",\"fence\":9,\"operation_id\":\"op-claim-001\",\"result_ref\":"
        ));
    }

    #[test]
    fn schema_and_alternate_encodings_fail_closed() {
        let canonical = String::from_utf8(encode(&submission()).unwrap()).unwrap();
        let unknown = canonical.replacen("{", "{\"extra\":1,", 1);
        assert_eq!(decode(unknown.as_bytes()), Err(WireError::InvalidEncoding));
        let reordered = canonical.replacen(
            "\"version\":1,\"attempt_id\":\"attempt-17\"",
            "\"attempt_id\":\"attempt-17\",\"version\":1",
            1,
        );
        assert_eq!(decode(reordered.as_bytes()), Err(WireError::NonCanonical));
        let unknown_version = canonical.replacen("\"version\":1", "\"version\":2", 1);
        assert_eq!(
            decode(unknown_version.as_bytes()),
            Err(WireError::InvalidValue)
        );
    }

    #[test]
    fn size_and_attempt_binding_fail_closed() {
        assert_eq!(decode(&[]), Err(WireError::LimitExceeded));
        assert_eq!(
            decode(&vec![b'x'; MAX_SUBMISSION_BYTES + 1]),
            Err(WireError::LimitExceeded)
        );
        let canonical = String::from_utf8(encode(&submission()).unwrap()).unwrap();
        let mismatch = canonical.replacen(
            "\"attempt_id\":\"attempt-17\"",
            "\"attempt_id\":\"attempt-18\"",
            1,
        );
        assert_eq!(decode(mismatch.as_bytes()), Err(WireError::InvalidValue));
        let zero_fence = canonical.replacen("\"fence\":9", "\"fence\":0", 1);
        assert_eq!(decode(zero_fence.as_bytes()), Err(WireError::InvalidValue));
        let empty_operation = canonical.replacen(
            "\"operation_id\":\"op-claim-001\"",
            "\"operation_id\":\"\"",
            1,
        );
        assert_eq!(
            decode(empty_operation.as_bytes()),
            Err(WireError::InvalidValue)
        );
    }

    #[test]
    fn submission_key_is_exact_and_rejects_path_components() {
        assert_eq!(
            submission_key("workspace-1", "campaign-1", "attempt-17").unwrap(),
            "workspace/workspace-1/campaigns/campaign-1/submissions/attempt-17.json"
        );
        for components in [
            ("bad/workspace", "campaign", "attempt"),
            ("workspace", "bad/campaign", "attempt"),
            ("workspace", "campaign", "bad/attempt"),
        ] {
            assert_eq!(
                submission_key(components.0, components.1, components.2),
                Err(ValidationError::InvalidKey)
            );
        }
        let oversized = "x".repeat(129);
        for components in [
            ("", "campaign", "attempt"),
            ("workspace", oversized.as_str(), "attempt"),
        ] {
            assert_eq!(
                submission_key(components.0, components.1, components.2),
                Err(ValidationError::InvalidIdentity)
            );
        }
    }
}
