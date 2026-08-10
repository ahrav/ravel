//! The v1 claim encoding is frozen.
//!
//! Claim bytes are compact UTF-8 JSON with no whitespace or trailing newline.
//! Field order is part of v1's canonical encoding: `version`, `work_id`,
//! `work_revision`, `owner_actor`, `owner_instance`, `fence`, `operation_id`,
//! then `state`. The state is internally tagged on the `state` key with exactly
//! `active` and `sealed`; a sealed state carries the shared artifact wire shape.
//! Records are capped at 4 KiB, and the decoder compares input bytes with the
//! production re-encoding before domain conversion.
//!
//! `work_revision` zero is valid. `fence` and `Active.lease_until` must be
//! nonzero; decode performs no clock comparison, so lease policy stays with the
//! claim-transition operations.

use serde::{Deserialize, Serialize};

use crate::{
    distributed::identity::{ActorId, InstanceId},
    domain::campaign::{ArtifactRef, ValidationError, validate_identity, validate_key_segment},
    storage::s3::ETag,
    sync::{WIRE_VERSION, WireError, event::WireArtifactRef},
};

const MAX_CLAIM_BYTES: usize = 4 * 1024;

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

/// Active lease or terminal immutable result reference.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClaimState {
    /// `lease_until` is a unix-millisecond expiry. Construction and decode
    /// validate only that it is nonzero; no clock comparison happens here.
    Active {
        lease_until: u64,
    },
    Sealed {
        result_ref: ArtifactRef,
    },
}

/// Validated claim record.
///
/// Authority over the work item additionally requires the coupled object
/// version in [`ClaimAuthority`]; a decoded record alone proves nothing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Claim {
    work_id: WorkId,
    work_revision: u64,
    owner_actor: ActorId,
    owner_instance: InstanceId,
    fence: u64,
    operation_id: String,
    state: ClaimState,
}

impl Claim {
    /// Constructs a claim after validating its fence, operation, and active expiry.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError`] for a zero fence, invalid operation identity, or zero
    /// active lease expiry.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        work_id: WorkId,
        work_revision: u64,
        owner_actor: ActorId,
        owner_instance: InstanceId,
        fence: u64,
        operation_id: String,
        state: ClaimState,
    ) -> Result<Self, ValidationError> {
        if fence == 0 {
            return Err(ValidationError::InvalidFence);
        }
        validate_identity(&operation_id)?;
        if matches!(state, ClaimState::Active { lease_until: 0 }) {
            return Err(ValidationError::InvalidExpiry);
        }
        Ok(Self {
            work_id,
            work_revision,
            owner_actor,
            owner_instance,
            fence,
            operation_id,
            state,
        })
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

    pub fn state(&self) -> &ClaimState {
        &self.state
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireClaim {
    version: u64,
    work_id: String,
    work_revision: u64,
    owner_actor: String,
    owner_instance: String,
    fence: u64,
    operation_id: String,
    state: WireClaimState,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, tag = "state", rename_all = "snake_case")]
enum WireClaimState {
    Active { lease_until: u64 },
    Sealed { result_ref: WireArtifactRef },
}

/// Couples a validated claim to the opaque ETag observed on the mutation that
/// wrote it. Only successful claim mutations inside this module construct it;
/// it implements neither `Clone` nor `Debug`, so the proof cannot be copied or
/// logged.
#[allow(dead_code)]
pub(crate) struct ClaimAuthority {
    claim: Claim,
    etag: ETag,
}

/// Produces compact canonical JSON in the frozen claim field order.
///
/// # Errors
///
/// Returns [`WireError::LimitExceeded`] when output exceeds 4 KiB. Bounded field
/// lengths keep real output under 1.5 KiB, so the limit is defensive.
pub fn encode(claim: &Claim) -> Result<Vec<u8>, WireError> {
    let bytes =
        serde_json::to_vec(&WireClaim::from(claim)).map_err(|_| WireError::InvalidEncoding)?;
    if bytes.len() > MAX_CLAIM_BYTES {
        return Err(WireError::LimitExceeded);
    }
    Ok(bytes)
}

/// Decodes only exact canonical v1 claim bytes.
///
/// # Errors
///
/// Returns [`WireError`] for empty or oversized input, malformed or alternate JSON,
/// unknown versions, or invalid domain values.
pub fn decode(bytes: &[u8]) -> Result<Claim, WireError> {
    if bytes.is_empty() || bytes.len() > MAX_CLAIM_BYTES {
        return Err(WireError::LimitExceeded);
    }
    let wire: WireClaim = serde_json::from_slice(bytes).map_err(|_| WireError::InvalidEncoding)?;
    let canonical = serde_json::to_vec(&wire).map_err(|_| WireError::InvalidEncoding)?;
    if canonical != bytes {
        return Err(WireError::NonCanonical);
    }
    wire.try_into()
}

impl From<&Claim> for WireClaim {
    fn from(claim: &Claim) -> Self {
        Self {
            version: WIRE_VERSION,
            work_id: claim.work_id().as_str().to_owned(),
            work_revision: claim.work_revision(),
            owner_actor: claim.owner_actor().as_str().to_owned(),
            owner_instance: claim.owner_instance().as_str().to_owned(),
            fence: claim.fence(),
            operation_id: claim.operation_id().to_owned(),
            state: WireClaimState::from(claim.state()),
        }
    }
}

impl From<&ClaimState> for WireClaimState {
    fn from(state: &ClaimState) -> Self {
        match state {
            ClaimState::Active { lease_until } => Self::Active {
                lease_until: *lease_until,
            },
            ClaimState::Sealed { result_ref } => Self::Sealed {
                result_ref: WireArtifactRef::from(result_ref),
            },
        }
    }
}

impl TryFrom<WireClaim> for Claim {
    type Error = WireError;

    fn try_from(wire: WireClaim) -> Result<Self, Self::Error> {
        if wire.version != WIRE_VERSION {
            return Err(WireError::InvalidValue);
        }
        let state = match wire.state {
            WireClaimState::Active { lease_until } => ClaimState::Active { lease_until },
            WireClaimState::Sealed { result_ref } => ClaimState::Sealed {
                result_ref: result_ref.try_into()?,
            },
        };
        Claim::new(
            WorkId::new(wire.work_id).map_err(|_| WireError::InvalidValue)?,
            wire.work_revision,
            ActorId::new(wire.owner_actor).map_err(|_| WireError::InvalidValue)?,
            InstanceId::new(wire.owner_instance).map_err(|_| WireError::InvalidValue)?,
            wire.fence,
            wire.operation_id,
            state,
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
            1_749_999_999_000,
            None,
        )
        .unwrap()
    }

    fn claim(state: ClaimState) -> Claim {
        Claim::new(
            WorkId::new("work-17".into()).unwrap(),
            4,
            ActorId::new("rust-worker".into()).unwrap(),
            InstanceId::new("instance-a".into()).unwrap(),
            9,
            "op-claim-001".into(),
            state,
        )
        .unwrap()
    }

    #[test]
    fn work_id_enforces_shared_boundaries() {
        assert!(WorkId::new(String::new()).is_err());
        assert!(WorkId::new("x".repeat(129)).is_err());
        assert!(WorkId::new("x".repeat(128)).is_ok());
    }

    #[test]
    fn active_and_sealed_claims_round_trip_with_all_bindings() {
        for expected in [
            claim(ClaimState::Active {
                lease_until: 1_750_000_000_000,
            }),
            claim(ClaimState::Sealed {
                result_ref: artifact(),
            }),
        ] {
            let decoded = decode(&encode(&expected).unwrap()).unwrap();
            assert_eq!(decoded, expected);
            assert_eq!(decoded.work_id().as_str(), "work-17");
            assert_eq!(decoded.work_revision(), 4);
            assert_eq!(decoded.owner_actor().as_str(), "rust-worker");
            assert_eq!(decoded.owner_instance().as_str(), "instance-a");
            assert_eq!(decoded.fence(), 9);
            assert_eq!(decoded.operation_id(), "op-claim-001");
        }
    }

    #[test]
    fn constructor_accepts_revision_zero_but_rejects_invalid_authority_fields() {
        let active = ClaimState::Active { lease_until: 1 };
        assert!(
            Claim::new(
                WorkId::new("work".into()).unwrap(),
                0,
                ActorId::new("actor".into()).unwrap(),
                InstanceId::new("instance".into()).unwrap(),
                1,
                "op".into(),
                active.clone(),
            )
            .is_ok()
        );
        assert!(
            Claim::new(
                WorkId::new("work".into()).unwrap(),
                0,
                ActorId::new("actor".into()).unwrap(),
                InstanceId::new("instance".into()).unwrap(),
                0,
                "op".into(),
                active.clone(),
            )
            .is_err()
        );
        assert!(
            Claim::new(
                WorkId::new("work".into()).unwrap(),
                0,
                ActorId::new("actor".into()).unwrap(),
                InstanceId::new("instance".into()).unwrap(),
                1,
                String::new(),
                active,
            )
            .is_err()
        );
        assert!(
            Claim::new(
                WorkId::new("work".into()).unwrap(),
                0,
                ActorId::new("actor".into()).unwrap(),
                InstanceId::new("instance".into()).unwrap(),
                1,
                "op".into(),
                ClaimState::Active { lease_until: 0 },
            )
            .is_err()
        );
    }

    #[test]
    fn illegal_state_result_combinations_fail_decode() {
        let active_with_result = format!(
            "{{\"version\":1,\"work_id\":\"work\",\"work_revision\":0,\"owner_actor\":\"actor\",\"owner_instance\":\"instance\",\"fence\":1,\"operation_id\":\"op\",\"state\":{{\"state\":\"active\",\"lease_until\":1,\"result_ref\":{{\"digest\":\"{}\"}}}}}}",
            "0".repeat(64)
        );
        let sealed_without_result = b"{\"version\":1,\"work_id\":\"work\",\"work_revision\":0,\"owner_actor\":\"actor\",\"owner_instance\":\"instance\",\"fence\":1,\"operation_id\":\"op\",\"state\":{\"state\":\"sealed\"}}";
        assert_eq!(
            decode(active_with_result.as_bytes()),
            Err(WireError::InvalidEncoding)
        );
        assert_eq!(
            decode(sealed_without_result),
            Err(WireError::InvalidEncoding)
        );
    }

    #[test]
    fn decode_rejects_invalid_domain_values() {
        let canonical = encode(&claim(ClaimState::Active { lease_until: 1 })).unwrap();
        let text = String::from_utf8(canonical).unwrap();
        let zero_fence = text.replacen("\"fence\":9", "\"fence\":0", 1);
        assert_eq!(decode(zero_fence.as_bytes()), Err(WireError::InvalidValue));
        let zero_lease = text.replacen("\"lease_until\":1", "\"lease_until\":0", 1);
        assert_eq!(decode(zero_lease.as_bytes()), Err(WireError::InvalidValue));
        let empty_operation = text.replacen(
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
    fn rejects_unknown_field_version_and_alternate_bytes() {
        let canonical = encode(&claim(ClaimState::Active { lease_until: 1 })).unwrap();
        let text = String::from_utf8(canonical).unwrap();
        let unknown_field = text.replacen("{", "{\"extra\":1,", 1);
        assert_eq!(
            decode(unknown_field.as_bytes()),
            Err(WireError::InvalidEncoding)
        );
        let unknown_version = text.replacen("\"version\":1", "\"version\":2", 1);
        assert_eq!(
            decode(unknown_version.as_bytes()),
            Err(WireError::InvalidValue)
        );
        let reordered = text.replacen(
            "\"version\":1,\"work_id\":\"work-17\"",
            "\"work_id\":\"work-17\",\"version\":1",
            1,
        );
        assert_eq!(decode(reordered.as_bytes()), Err(WireError::NonCanonical));
        let trailing = format!("{text} ");
        assert_eq!(decode(trailing.as_bytes()), Err(WireError::NonCanonical));
    }

    #[test]
    fn rejects_empty_and_oversized_bytes() {
        assert_eq!(decode(b""), Err(WireError::LimitExceeded));
        assert_eq!(
            decode(&vec![b'x'; MAX_CLAIM_BYTES + 1]),
            Err(WireError::LimitExceeded)
        );
    }
}
