//! Root-only scope identities, keys, and canonical wire records.
//!
//! Root-genesis payloads encode null parent-scope and delegation fields and reject
//! non-null values. Events use a standard zstd level-3 frame with declared content size
//! and require exact CBOR and zstd re-encoding. Decoder limits are 256 KiB stored, 1 MiB
//! decompressed, CBOR recursion 16, and 4 KiB for heads. The
//! `zstd-sys 2.0.16+zstd.1.5.7` lockfile pin is byte-affecting.

use std::{io::Cursor, num::NonZeroU64};

use ciborium::{de::from_reader_with_recursion_limit, ser::into_writer};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest as _, Sha256};

use crate::{
    distributed::identity::{InstanceId, WorkspaceId},
    domain::{
        validation::{ValidationError, is_digest, validate_key_segment, validate_sequence},
        work::WorkRef,
    },
    sync::WireError,
};

pub(crate) const ROOT_GENESIS_PAYLOAD_TYPE: &str = "root_genesis";
#[cfg(test)]
pub(crate) const TEST_SUCCESSOR_PAYLOAD_TYPE: &str = "test_successor";
const ROOT_SCOPE_DOMAIN: &[u8] = b"ravel.scope.root\0";
const MAX_CONFIG_BYTES: usize = 1024 * 1024;
pub(crate) const MAX_COMPRESSED_BYTES: usize = 256 * 1024;
const MAX_DECOMPRESSED_BYTES: usize = 1024 * 1024;
pub(crate) const MAX_HEAD_BYTES: usize = 4 * 1024;
const CBOR_RECURSION_LIMIT: usize = 16;
const ZSTD_LEVEL: i32 = 3;

/// Validated campaign key segment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CampaignId(String);

impl CampaignId {
    /// Validates a campaign identity used in durable object keys.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError`] when `value` is empty, exceeds 128 bytes, or
    /// contains `/`.
    pub fn new(value: String) -> Result<Self, ValidationError> {
        validate_key_segment(&value)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Deterministically derived root-scope identity: 64 lowercase hexadecimal bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScopeId(String);

impl ScopeId {
    /// Validates the fixed textual scope-ID representation.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError::InvalidIdentity`] unless `value` is exactly one
    /// lowercase hexadecimal SHA-256 digest.
    pub fn new(value: String) -> Result<Self, ValidationError> {
        if !is_digest(&value) {
            return Err(ValidationError::InvalidIdentity);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Validated lowercase hexadecimal SHA-256 digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Digest(String);

impl Digest {
    /// Validates the fixed textual digest representation.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError::InvalidDigest`] unless `value` is exactly 64
    /// lowercase hexadecimal bytes.
    pub fn new(value: String) -> Result<Self, ValidationError> {
        if !is_digest(&value) {
            return Err(ValidationError::InvalidDigest);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Root-only scope identity with explicit absent parent and delegation slots.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScopeIdentity {
    workspace_id: WorkspaceId,
    campaign_id: CampaignId,
    scope_id: ScopeId,
    parent_scope_id: Option<ScopeId>,
    delegation_digest: Option<Digest>,
}

impl ScopeIdentity {
    /// Derives the admitted root scope from validated workspace and campaign IDs.
    ///
    /// # Errors
    ///
    /// Returns [`WireError`] if deterministic scope-ID serialization fails.
    pub fn root(workspace_id: WorkspaceId, campaign_id: CampaignId) -> Result<Self, WireError> {
        let scope_id = root_scope_id(&workspace_id, &campaign_id)?;
        Ok(Self {
            workspace_id,
            campaign_id,
            scope_id,
            parent_scope_id: None,
            delegation_digest: None,
        })
    }

    pub fn workspace_id(&self) -> &WorkspaceId {
        &self.workspace_id
    }

    pub fn campaign_id(&self) -> &CampaignId {
        &self.campaign_id
    }

    pub fn scope_id(&self) -> &ScopeId {
        &self.scope_id
    }

    pub fn parent_scope_id(&self) -> Option<&ScopeId> {
        self.parent_scope_id.as_ref()
    }

    pub fn delegation_digest(&self) -> Option<&Digest> {
        self.delegation_digest.as_ref()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScopeClaimIdentity {
    scope: ScopeIdentity,
    plan_digest: Digest,
    work: WorkRef,
    claim_fence: NonZeroU64,
}

impl ScopeClaimIdentity {
    /// Creates a scoped claim identity with a nonzero claim fence.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError::InvalidFence`] when `claim_fence` is zero.
    pub fn new(
        scope: ScopeIdentity,
        plan_digest: Digest,
        work: WorkRef,
        claim_fence: u64,
    ) -> Result<Self, ValidationError> {
        let claim_fence = NonZeroU64::new(claim_fence).ok_or(ValidationError::InvalidFence)?;
        Ok(Self {
            scope,
            plan_digest,
            work,
            claim_fence,
        })
    }

    pub fn scope(&self) -> &ScopeIdentity {
        &self.scope
    }

    pub fn plan_digest(&self) -> &Digest {
        &self.plan_digest
    }

    pub fn work(&self) -> &WorkRef {
        &self.work
    }

    pub fn claim_fence(&self) -> NonZeroU64 {
        self.claim_fence
    }
}

/// Sequence and stored-byte digest of one event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScopeEventRef {
    sequence: u64,
    digest: Digest,
}

impl ScopeEventRef {
    /// Creates a scope-local event reference.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError`] when `sequence` is outside the 16-digit durable
    /// range.
    pub fn new(sequence: u64, digest: Digest) -> Result<Self, ValidationError> {
        validate_sequence(sequence)?;
        Ok(Self { sequence, digest })
    }

    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }
}

/// Exact six-field event envelope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventEnvelope {
    scope_id: ScopeId,
    sequence: u64,
    parent_event: Option<ScopeEventRef>,
    writer_epoch: NonZeroU64,
    operation_id: String,
    payload_type: String,
}

impl EventEnvelope {
    /// Creates an envelope after validating its local chain relationship.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError`] for an invalid sequence, parent, writer epoch,
    /// operation identity, or payload-type identity.
    pub fn new(
        scope_id: ScopeId,
        sequence: u64,
        parent_event: Option<ScopeEventRef>,
        writer_epoch: u64,
        operation_id: String,
        payload_type: String,
    ) -> Result<Self, ValidationError> {
        validate_sequence(sequence)?;
        match (sequence, &parent_event) {
            (1, None) => {}
            (1, Some(_)) | (_, None) => return Err(ValidationError::InvalidParent),
            (sequence, Some(parent)) if parent.sequence() == sequence - 1 => {}
            (_, Some(_)) => return Err(ValidationError::InvalidParent),
        }
        let writer_epoch = NonZeroU64::new(writer_epoch).ok_or(ValidationError::InvalidFence)?;
        validate_key_segment(&operation_id)?;
        validate_key_segment(&payload_type)?;
        Ok(Self {
            scope_id,
            sequence,
            parent_event,
            writer_epoch,
            operation_id,
            payload_type,
        })
    }

    pub fn scope_id(&self) -> &ScopeId {
        &self.scope_id
    }

    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn parent_event(&self) -> Option<&ScopeEventRef> {
        self.parent_event.as_ref()
    }

    pub fn writer_epoch(&self) -> NonZeroU64 {
        self.writer_epoch
    }

    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    pub fn payload_type(&self) -> &str {
        &self.payload_type
    }
}

/// Root genesis payload; root-only identity nulls remain explicit in the wire form.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RootGenesisPayload {
    campaign_id: CampaignId,
    config_digest: Digest,
}

impl RootGenesisPayload {
    pub fn campaign_id(&self) -> &CampaignId {
        &self.campaign_id
    }

    pub fn config_digest(&self) -> &Digest {
        &self.config_digest
    }
}

/// Validated root-genesis event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RootEvent {
    envelope: EventEnvelope,
    payload: RootGenesisPayload,
}

impl RootEvent {
    pub fn envelope(&self) -> &EventEnvelope {
        &self.envelope
    }

    pub fn payload(&self) -> &RootGenesisPayload {
        &self.payload
    }
}

/// Controller authority encoded in one `ScopeHead`.
///
/// `lease_until` is a Unix-epoch millisecond expiry. Construction and decoding require
/// `lease_until` to be nonzero.
/// Lease acquisition, renewal, expiry, takeover, and epoch advancement remain outside this codec.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ScopeAuthority {
    Unowned,
    Owned {
        instance: InstanceId,
        lease_until: NonZeroU64,
    },
}

impl ScopeAuthority {
    /// Creates owned authority with a nonzero lease expiry.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError::InvalidExpiry`] when `lease_until` is zero.
    pub fn owned(instance: InstanceId, lease_until: u64) -> Result<Self, ValidationError> {
        let lease_until = NonZeroU64::new(lease_until).ok_or(ValidationError::InvalidExpiry)?;
        Ok(Self::Owned {
            instance,
            lease_until,
        })
    }
}

/// Authoritative root scope head.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScopeHead {
    scope: ScopeIdentity,
    authority: ScopeAuthority,
    scope_epoch: NonZeroU64,
    tail: ScopeEventRef,
    active_plan_digest: Option<Digest>,
    operation_id: String,
}

impl ScopeHead {
    /// Constructs a scope head from validated identities and one nonzero scope epoch.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError`] when `scope_epoch` is zero or `operation_id` is
    /// invalid.
    pub fn new(
        scope: ScopeIdentity,
        authority: ScopeAuthority,
        scope_epoch: u64,
        tail: ScopeEventRef,
        active_plan_digest: Option<Digest>,
        operation_id: String,
    ) -> Result<Self, ValidationError> {
        let scope_epoch = NonZeroU64::new(scope_epoch).ok_or(ValidationError::InvalidFence)?;
        validate_key_segment(&operation_id)?;
        Ok(Self {
            scope,
            authority,
            scope_epoch,
            tail,
            active_plan_digest,
            operation_id,
        })
    }

    pub fn scope(&self) -> &ScopeIdentity {
        &self.scope
    }

    pub fn authority(&self) -> &ScopeAuthority {
        &self.authority
    }

    pub fn scope_epoch(&self) -> NonZeroU64 {
        self.scope_epoch
    }

    pub fn tail(&self) -> &ScopeEventRef {
        &self.tail
    }

    pub fn active_plan_digest(&self) -> Option<&Digest> {
        self.active_plan_digest.as_ref()
    }

    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }
}

/// Validated input boundary for deterministic root genesis.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmittedCampaignConfig {
    workspace_id: WorkspaceId,
    campaign_id: CampaignId,
    canonical_bytes: Vec<u8>,
}

impl AdmittedCampaignConfig {
    /// Accepts nonempty caller-canonical bytes up to 1 MiB.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::InvalidValue`] for empty bytes and
    /// [`WireError::LimitExceeded`] above 1 MiB.
    pub fn new(
        workspace_id: WorkspaceId,
        campaign_id: CampaignId,
        canonical_bytes: Vec<u8>,
    ) -> Result<Self, WireError> {
        if canonical_bytes.is_empty() {
            return Err(WireError::InvalidValue);
        }
        if canonical_bytes.len() > MAX_CONFIG_BYTES {
            return Err(WireError::LimitExceeded);
        }
        Ok(Self {
            workspace_id,
            campaign_id,
            canonical_bytes,
        })
    }

    pub fn workspace_id(&self) -> &WorkspaceId {
        &self.workspace_id
    }

    pub fn campaign_id(&self) -> &CampaignId {
        &self.campaign_id
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }
}

/// Canonical compressed event bytes and their stored-byte digest reference.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncodedScopeEvent {
    stored_bytes: Vec<u8>,
    reference: ScopeEventRef,
}

impl EncodedScopeEvent {
    pub fn stored_bytes(&self) -> &[u8] {
        &self.stored_bytes
    }

    pub fn event_ref(&self) -> &ScopeEventRef {
        &self.reference
    }
}

/// Pure deterministic root-genesis result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RootGenesis {
    identity: ScopeIdentity,
    config_digest: Digest,
    event: EncodedScopeEvent,
    event_key: String,
    head: ScopeHead,
    head_bytes: Vec<u8>,
    head_key: String,
}

impl RootGenesis {
    pub fn identity(&self) -> &ScopeIdentity {
        &self.identity
    }

    pub fn config_digest(&self) -> &Digest {
        &self.config_digest
    }

    pub fn event_bytes(&self) -> &[u8] {
        self.event.stored_bytes()
    }

    pub fn event_ref(&self) -> &ScopeEventRef {
        self.event.event_ref()
    }

    pub fn event_key(&self) -> &str {
        &self.event_key
    }

    pub fn head(&self) -> &ScopeHead {
        &self.head
    }

    pub fn head_bytes(&self) -> &[u8] {
        &self.head_bytes
    }

    pub fn head_key(&self) -> &str {
        &self.head_key
    }
}

/// Builds `workspace/{workspace}/campaigns/{campaign}/scopes/{scope}/head`.
pub fn scope_head_key(scope: &ScopeIdentity) -> String {
    format!(
        "workspace/{}/campaigns/{}/scopes/{}/head",
        scope.workspace_id().as_str(),
        scope.campaign_id().as_str(),
        scope.scope_id().as_str()
    )
}

/// Builds the full key for one compressed event object.
pub fn scope_event_key(scope: &ScopeIdentity, event: &ScopeEventRef) -> String {
    format!(
        "workspace/{}/campaigns/{}/scopes/{}/events/{:016}-{}.cbor.zst",
        scope.workspace_id().as_str(),
        scope.campaign_id().as_str(),
        scope.scope_id().as_str(),
        event.sequence(),
        event.digest().as_str()
    )
}

/// Builds the full root-scoped work-claim key.
pub fn scope_claim_key(claim: &ScopeClaimIdentity) -> String {
    format!(
        "workspace/{}/campaigns/{}/scopes/{}/claims/{}/{}",
        claim.scope().workspace_id().as_str(),
        claim.scope().campaign_id().as_str(),
        claim.scope().scope_id().as_str(),
        claim.work().id().as_str(),
        claim.work().revision()
    )
}

/// Builds the full campaign plan key.
pub fn plan_key(workspace: &WorkspaceId, campaign: &CampaignId, digest: &Digest) -> String {
    format!(
        "workspace/{}/campaigns/{}/plans/{}",
        workspace.as_str(),
        campaign.as_str(),
        digest.as_str()
    )
}

/// Builds the full campaign artifact key.
pub fn artifact_key(workspace: &WorkspaceId, campaign: &CampaignId, digest: &Digest) -> String {
    format!(
        "workspace/{}/campaigns/{}/artifacts/{}",
        workspace.as_str(),
        campaign.as_str(),
        digest.as_str()
    )
}

#[derive(Serialize)]
struct RootScopeSeed<'a> {
    workspace_id: &'a str,
    campaign_id: &'a str,
}

/// Derives a root scope ID from workspace and campaign identity only.
///
/// The hash input is `ravel.scope.root\0` followed by declaration-order CBOR
/// containing `workspace_id` then `campaign_id`.
///
/// # Errors
///
/// Returns [`WireError::InvalidEncoding`] if CBOR serialization fails.
pub fn root_scope_id(workspace: &WorkspaceId, campaign: &CampaignId) -> Result<ScopeId, WireError> {
    let seed = RootScopeSeed {
        workspace_id: workspace.as_str(),
        campaign_id: campaign.as_str(),
    };
    let mut cbor = Vec::new();
    into_writer(&seed, &mut cbor).map_err(|_| WireError::InvalidEncoding)?;
    let mut hasher = Sha256::new();
    hasher.update(ROOT_SCOPE_DOMAIN);
    hasher.update(&cbor);
    ScopeId::new(format!("{:x}", hasher.finalize())).map_err(|_| WireError::InvalidValue)
}

/// Deterministically creates root event bytes and the initial unowned `ScopeHead`.
///
/// # Errors
///
/// Returns [`WireError`] only if canonical serialization, compression, or an internal
/// derived value fails validation.
pub fn root_genesis(config: &AdmittedCampaignConfig) -> Result<RootGenesis, WireError> {
    let identity =
        ScopeIdentity::root(config.workspace_id().clone(), config.campaign_id().clone())?;
    let config_digest =
        Digest::new(sha256(config.canonical_bytes())).map_err(|_| WireError::InvalidValue)?;
    let operation_id = format!("root-genesis:{}", identity.scope_id().as_str());
    let event = RootEvent {
        envelope: EventEnvelope::new(
            identity.scope_id().clone(),
            1,
            None,
            1,
            operation_id.clone(),
            ROOT_GENESIS_PAYLOAD_TYPE.to_owned(),
        )
        .map_err(|_| WireError::InvalidValue)?,
        payload: RootGenesisPayload {
            campaign_id: config.campaign_id().clone(),
            config_digest: config_digest.clone(),
        },
    };
    let event = encode_root_event(&event)?;
    let event_key = scope_event_key(&identity, event.event_ref());
    let head = ScopeHead::new(
        identity.clone(),
        ScopeAuthority::Unowned,
        1,
        event.event_ref().clone(),
        None,
        operation_id,
    )
    .map_err(|_| WireError::InvalidValue)?;
    let head_bytes = encode_head(&head)?;
    let head_key = scope_head_key(&identity);
    Ok(RootGenesis {
        identity,
        config_digest,
        event,
        event_key,
        head,
        head_bytes,
        head_key,
    })
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireScopeEvent<P> {
    envelope: WireEventEnvelope,
    payload: P,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireEventEnvelope {
    scope_id: String,
    sequence: u64,
    parent_event: Option<WireEventRef>,
    writer_epoch: u64,
    operation_id: String,
    payload_type: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireEventRef {
    sequence: u64,
    digest: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireRootGenesisPayload {
    campaign_id: String,
    parent_scope_id: Option<String>,
    delegation_digest: Option<String>,
    config_digest: String,
}

/// Canonically decoded scoped event before payload-specific domain conversion.
///
/// `P` must serialize back to the exact payload bytes it decoded from. Opaque
/// [`ciborium::Value`] traversal preserves map order and tags; typed conversion remains
/// the final gate before projection.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct DecodedScopeEvent<P> {
    envelope: EventEnvelope,
    reference: ScopeEventRef,
    payload: P,
}

impl<P> DecodedScopeEvent<P> {
    pub(crate) fn envelope(&self) -> &EventEnvelope {
        &self.envelope
    }

    pub(crate) fn event_ref(&self) -> &ScopeEventRef {
        &self.reference
    }
}

/// Encodes a validated envelope and serializable payload using the canonical framing.
///
/// # Errors
///
/// Returns [`WireError`] when serialization or compression fails or either size limit
/// would be exceeded.
pub(crate) fn encode_scope_event<P: Serialize>(
    envelope: &EventEnvelope,
    payload: &P,
) -> Result<EncodedScopeEvent, WireError> {
    let wire = WireScopeEvent {
        envelope: WireEventEnvelope::from(envelope),
        payload,
    };
    let cbor = encode_event_cbor(&wire)?;
    if cbor.len() > MAX_DECOMPRESSED_BYTES {
        return Err(WireError::LimitExceeded);
    }
    let stored_bytes = compress(&cbor)?;
    if stored_bytes.len() > MAX_COMPRESSED_BYTES {
        return Err(WireError::LimitExceeded);
    }
    let reference = ScopeEventRef::new(
        envelope.sequence(),
        Digest::new(sha256(&stored_bytes)).map_err(|_| WireError::InvalidValue)?,
    )
    .map_err(|_| WireError::InvalidValue)?;
    Ok(EncodedScopeEvent {
        stored_bytes,
        reference,
    })
}

/// Decodes the canonical framing and validates scope, reference, and envelope.
///
/// `P` must deserialize and serialize to byte-identical payload CBOR.
///
/// # Errors
///
/// Returns [`WireError`] for invalid framing, an unregistered payload type, noncanonical
/// bytes, identities, scope binding, digest, or key.
pub(crate) fn decode_scope_event<P>(
    stored_bytes: &[u8],
    expected_key: &str,
    expected_scope: &ScopeIdentity,
    expected_payload: Option<&str>,
) -> Result<DecodedScopeEvent<P>, WireError>
where
    P: Serialize + DeserializeOwned,
{
    decode_scope_event_inner(
        stored_bytes,
        expected_key,
        expected_scope,
        expected_payload,
        true,
    )
}

fn decode_scope_event_inner<P>(
    stored_bytes: &[u8],
    expected_key: &str,
    expected_scope: &ScopeIdentity,
    expected_payload: Option<&str>,
    validate_key: bool,
) -> Result<DecodedScopeEvent<P>, WireError>
where
    P: Serialize + DeserializeOwned,
{
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
    let wire: WireScopeEvent<P> =
        from_reader_with_recursion_limit(&mut reader, CBOR_RECURSION_LIMIT)
            .map_err(|_| WireError::InvalidEncoding)?;
    if expected_payload.is_some_and(|payload_type| wire.envelope.payload_type != payload_type) {
        return Err(WireError::InvalidValue);
    }
    if reader.position() != cbor.len() as u64 {
        return Err(WireError::NonCanonical);
    }
    let canonical = encode_event_cbor(&wire)?;
    if canonical != cbor || compress(&canonical)? != stored_bytes {
        return Err(WireError::NonCanonical);
    }

    let parent_event = wire
        .envelope
        .parent_event
        .map(|parent| {
            let digest = Digest::new(parent.digest).map_err(|_| WireError::InvalidValue)?;
            ScopeEventRef::new(parent.sequence, digest).map_err(|_| WireError::InvalidValue)
        })
        .transpose()?;
    let scope_id = ScopeId::new(wire.envelope.scope_id).map_err(|_| WireError::InvalidValue)?;
    if &scope_id != expected_scope.scope_id() {
        return Err(WireError::InvalidValue);
    }
    let envelope = EventEnvelope::new(
        scope_id,
        wire.envelope.sequence,
        parent_event,
        wire.envelope.writer_epoch,
        wire.envelope.operation_id,
        wire.envelope.payload_type,
    )
    .map_err(|_| WireError::InvalidValue)?;
    let reference = ScopeEventRef::new(
        envelope.sequence(),
        Digest::new(sha256(stored_bytes)).map_err(|_| WireError::InvalidValue)?,
    )
    .map_err(|_| WireError::InvalidValue)?;
    if validate_key && scope_event_key(expected_scope, &reference) != expected_key {
        return Err(WireError::ReferenceMismatch);
    }
    Ok(DecodedScopeEvent {
        envelope,
        reference,
        payload: wire.payload,
    })
}

/// Encodes one validated root-genesis event as exact CBOR and zstd level-3 bytes.
///
/// # Errors
///
/// Returns [`WireError`] for serialization, compression, or size-limit failures.
pub fn encode_root_event(event: &RootEvent) -> Result<EncodedScopeEvent, WireError> {
    encode_scope_event(
        event.envelope(),
        &WireRootGenesisPayload {
            campaign_id: event.payload().campaign_id().as_str().to_owned(),
            parent_scope_id: None,
            delegation_digest: None,
            config_digest: event.payload().config_digest().as_str().to_owned(),
        },
    )
}

/// Decodes only the exact root-genesis event for `expected_scope` at `expected_key`.
///
/// # Errors
///
/// Returns [`WireError`] for framing and size failures, malformed or noncanonical bytes,
/// an unregistered payload type, non-root or invalid identities, wrong-scope bytes, or a
/// key mismatch. The payload type is rejected before canonicality checks.
pub fn decode_root_event(
    stored_bytes: &[u8],
    expected_key: &str,
    expected_scope: &ScopeIdentity,
) -> Result<RootEvent, WireError> {
    // Root domain validation precedes key comparison so malformed root payloads cannot be reported as reference mismatches.
    let decoded = decode_scope_event_inner::<ciborium::Value>(
        stored_bytes,
        expected_key,
        expected_scope,
        Some(ROOT_GENESIS_PAYLOAD_TYPE),
        false,
    )?;
    let reference = decoded.reference.clone();
    let event = root_event_from_decoded(decoded, expected_scope)?;
    if scope_event_key(expected_scope, &reference) != expected_key {
        return Err(WireError::ReferenceMismatch);
    }
    Ok(event)
}

pub(crate) fn payload_type_registered(payload_type: &str) -> bool {
    if payload_type == ROOT_GENESIS_PAYLOAD_TYPE {
        return true;
    }
    #[cfg(test)]
    {
        payload_type == TEST_SUCCESSOR_PAYLOAD_TYPE
    }
    #[cfg(not(test))]
    {
        false
    }
}

pub(crate) fn root_event_from_decoded(
    decoded: DecodedScopeEvent<ciborium::Value>,
    expected_scope: &ScopeIdentity,
) -> Result<RootEvent, WireError> {
    if decoded.envelope.payload_type() != ROOT_GENESIS_PAYLOAD_TYPE {
        return Err(WireError::InvalidValue);
    }
    let mut original = Vec::new();
    into_writer(&decoded.payload, &mut original).map_err(|_| WireError::InvalidEncoding)?;
    let payload: WireRootGenesisPayload = decoded
        .payload
        .deserialized()
        .map_err(|_| WireError::InvalidEncoding)?;
    let mut canonical = Vec::new();
    into_writer(&payload, &mut canonical).map_err(|_| WireError::InvalidEncoding)?;
    if original != canonical {
        return Err(WireError::NonCanonical);
    }
    root_event_from_wire(
        WireScopeEvent {
            envelope: WireEventEnvelope::from(&decoded.envelope),
            payload,
        },
        expected_scope,
    )
}

impl From<&EventEnvelope> for WireEventEnvelope {
    fn from(envelope: &EventEnvelope) -> Self {
        Self {
            scope_id: envelope.scope_id().as_str().to_owned(),
            sequence: envelope.sequence(),
            parent_event: envelope.parent_event().map(|parent| WireEventRef {
                sequence: parent.sequence(),
                digest: parent.digest().as_str().to_owned(),
            }),
            writer_epoch: envelope.writer_epoch().get(),
            operation_id: envelope.operation_id().to_owned(),
            payload_type: envelope.payload_type().to_owned(),
        }
    }
}

fn root_event_from_wire(
    wire: WireScopeEvent<WireRootGenesisPayload>,
    expected_scope: &ScopeIdentity,
) -> Result<RootEvent, WireError> {
    if wire.envelope.sequence != 1
        || wire.envelope.parent_event.is_some()
        || wire.envelope.writer_epoch != 1
        || wire.payload.parent_scope_id.is_some()
        || wire.payload.delegation_digest.is_some()
    {
        return Err(WireError::InvalidValue);
    }
    let campaign_id =
        CampaignId::new(wire.payload.campaign_id).map_err(|_| WireError::InvalidValue)?;
    let scope_id = ScopeId::new(wire.envelope.scope_id).map_err(|_| WireError::InvalidValue)?;
    if &campaign_id != expected_scope.campaign_id() || &scope_id != expected_scope.scope_id() {
        return Err(WireError::InvalidValue);
    }
    let expected_operation = format!("root-genesis:{}", scope_id.as_str());
    if wire.envelope.operation_id != expected_operation {
        return Err(WireError::InvalidValue);
    }
    let config_digest =
        Digest::new(wire.payload.config_digest).map_err(|_| WireError::InvalidValue)?;
    let envelope = EventEnvelope::new(
        scope_id,
        wire.envelope.sequence,
        None,
        wire.envelope.writer_epoch,
        wire.envelope.operation_id,
        wire.envelope.payload_type,
    )
    .map_err(|_| WireError::InvalidValue)?;
    Ok(RootEvent {
        envelope,
        payload: RootGenesisPayload {
            campaign_id,
            config_digest,
        },
    })
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireScopeHead {
    campaign_id: String,
    scope_id: String,
    controller_instance_id: Option<String>,
    scope_epoch: u64,
    lease_until: Option<u64>,
    sequence: u64,
    tail_event_digest: String,
    active_plan_digest: Option<String>,
    operation_id: String,
}

/// Encodes compact declaration-order JSON with explicit nullable fields.
///
/// # Errors
///
/// Returns [`WireError`] for serialization or size-limit failures.
pub fn encode_head(head: &ScopeHead) -> Result<Vec<u8>, WireError> {
    let (controller_instance_id, lease_until) = match head.authority() {
        ScopeAuthority::Unowned => (None, None),
        ScopeAuthority::Owned {
            instance,
            lease_until,
        } => (Some(instance.as_str().to_owned()), Some(lease_until.get())),
    };
    let bytes = serde_json::to_vec(&WireScopeHead {
        campaign_id: head.scope().campaign_id().as_str().to_owned(),
        scope_id: head.scope().scope_id().as_str().to_owned(),
        controller_instance_id,
        scope_epoch: head.scope_epoch().get(),
        lease_until,
        sequence: head.tail().sequence(),
        tail_event_digest: head.tail().digest().as_str().to_owned(),
        active_plan_digest: head
            .active_plan_digest()
            .map(|digest| digest.as_str().to_owned()),
        operation_id: head.operation_id().to_owned(),
    })
    .map_err(|_| WireError::InvalidEncoding)?;
    if bytes.len() > MAX_HEAD_BYTES {
        return Err(WireError::LimitExceeded);
    }
    Ok(bytes)
}

/// Decodes canonical head bytes only when `expected_key` and `expected_scope` match.
/// The returned head clones verified `expected_scope` instead of reconstructing identity
/// from untrusted head bytes.
///
/// # Errors
///
/// Returns [`WireError`] for malformed, noncanonical, oversized, invalid-authority,
/// invalid-tail, or mismatched-key input.
pub fn decode_head(
    bytes: &[u8],
    expected_key: &str,
    expected_scope: &ScopeIdentity,
) -> Result<ScopeHead, WireError> {
    if bytes.is_empty() || bytes.len() > MAX_HEAD_BYTES {
        return Err(WireError::LimitExceeded);
    }
    let wire: WireScopeHead =
        serde_json::from_slice(bytes).map_err(|_| WireError::InvalidEncoding)?;
    let canonical = serde_json::to_vec(&wire).map_err(|_| WireError::InvalidEncoding)?;
    if canonical != bytes {
        return Err(WireError::NonCanonical);
    }
    if wire.campaign_id != expected_scope.campaign_id().as_str()
        || wire.scope_id != expected_scope.scope_id().as_str()
    {
        return Err(WireError::InvalidValue);
    }
    if scope_head_key(expected_scope) != expected_key {
        return Err(WireError::ReferenceMismatch);
    }

    let authority = match (wire.controller_instance_id, wire.lease_until) {
        (None, None) => ScopeAuthority::Unowned,
        (Some(instance), Some(lease_until)) => ScopeAuthority::owned(
            InstanceId::new(instance).map_err(|_| WireError::InvalidValue)?,
            lease_until,
        )
        .map_err(|_| WireError::InvalidValue)?,
        _ => return Err(WireError::InvalidValue),
    };
    let tail = ScopeEventRef::new(
        wire.sequence,
        Digest::new(wire.tail_event_digest).map_err(|_| WireError::InvalidValue)?,
    )
    .map_err(|_| WireError::InvalidValue)?;
    let active_plan_digest = wire
        .active_plan_digest
        .map(Digest::new)
        .transpose()
        .map_err(|_| WireError::InvalidValue)?;
    ScopeHead::new(
        expected_scope.clone(),
        authority,
        wire.scope_epoch,
        tail,
        active_plan_digest,
        wire.operation_id,
    )
    .map_err(|_| WireError::InvalidValue)
}

fn encode_event_cbor<P: Serialize>(wire: &WireScopeEvent<P>) -> Result<Vec<u8>, WireError> {
    let mut cbor = Vec::new();
    into_writer(wire, &mut cbor).map_err(|_| WireError::InvalidEncoding)?;
    Ok(cbor)
}

fn compress(cbor: &[u8]) -> Result<Vec<u8>, WireError> {
    zstd::bulk::compress(cbor, ZSTD_LEVEL).map_err(|_| WireError::InvalidEncoding)
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod codec_tests {
    use ciborium::Value;

    use crate::distributed::identity::WorkspaceId;

    use super::*;

    fn fixture() -> RootGenesis {
        root_genesis(
            &AdmittedCampaignConfig::new(
                WorkspaceId::new("workspace-a".into()).unwrap(),
                CampaignId::new("campaign-a".into()).unwrap(),
                b"admitted".to_vec(),
            )
            .unwrap(),
        )
        .unwrap()
    }

    fn map(value: &mut Value) -> &mut Vec<(Value, Value)> {
        match value {
            Value::Map(entries) => entries,
            _ => panic!("expected map"),
        }
    }

    fn reordered(genesis: &RootGenesis, field: &str) -> Vec<u8> {
        let cbor = zstd::bulk::decompress(genesis.event_bytes(), MAX_DECOMPRESSED_BYTES).unwrap();
        let mut value: Value = ciborium::from_reader(cbor.as_slice()).unwrap();
        let root = map(&mut value);
        let nested = root
            .iter_mut()
            .find_map(|(key, value)| (key == &Value::Text(field.into())).then_some(value))
            .unwrap();
        map(nested).swap(0, 1);
        let mut changed = Vec::new();
        into_writer(&value, &mut changed).unwrap();
        compress(&changed).unwrap()
    }

    #[test]
    fn typed_root_decoder_rejects_permuted_envelope_and_payload_keys() {
        let genesis = fixture();
        for bytes in [
            reordered(&genesis, "envelope"),
            reordered(&genesis, "payload"),
        ] {
            assert_eq!(
                decode_root_event(&bytes, genesis.event_key(), genesis.identity()),
                Err(WireError::NonCanonical)
            );
        }
    }

    #[test]
    fn opaque_codec_round_trips_fixture_bytes_exactly() {
        let genesis = fixture();
        let decoded = decode_scope_event::<Value>(
            genesis.event_bytes(),
            genesis.event_key(),
            genesis.identity(),
            None,
        )
        .unwrap();
        assert_eq!(
            encode_scope_event(decoded.envelope(), &decoded.payload)
                .unwrap()
                .stored_bytes(),
            genesis.event_bytes()
        );
    }
}
