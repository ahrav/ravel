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
        artifact::ArtifactRef,
        validation::{
            ValidationError, bounded_stored, is_digest, validate_key_segment, validate_sequence,
        },
        work::{WorkId, WorkRef},
    },
    sync::WireError,
};

pub(crate) const ROOT_GENESIS_PAYLOAD_TYPE: &str = "root_genesis";
pub(crate) const PLAN_ADMITTED_PAYLOAD_TYPE: &str = "plan_admitted";
pub(crate) const GRANT_ACTIVATED_PAYLOAD_TYPE: &str = "grant_activated";
/// The one payload type through which an immutable artifact enters authoritative history.
///
/// Named `artifact_reference` rather than `artifact` because `artifact` is the unregistered
/// payload type two negative tests use to prove an unknown type never reaches storage.
pub(crate) const ARTIFACT_REFERENCE_PAYLOAD_TYPE: &str = "artifact_reference";
pub(crate) const PROJECTION_CHECKPOINT_PAYLOAD_TYPE: &str = "projection_checkpoint_published";
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
    /// Crate-private because the work reference in a claim identity is only ever a row the
    /// projection read: [`WorkRef`] has no public constructor. Both production call sites are
    /// decoders, which pair that row-backed reference with a plan digest and a fence taken from the
    /// record's own bytes. The row readers on [`crate::db::worker::DbHandle`] do hand out a
    /// `WorkRef`, so the restriction is on who may pair one, not on who may hold one.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError::InvalidFence`] when `claim_fence` is zero.
    pub(crate) fn new(
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

/// Payload of the event that admits one plan revision.
///
/// It names only the address; the plan bytes live under [`plan_key`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlanAdmittedPayload {
    plan_digest: Digest,
}

impl PlanAdmittedPayload {
    pub fn new(plan_digest: Digest) -> Self {
        Self { plan_digest }
    }

    pub fn plan_digest(&self) -> &Digest {
        &self.plan_digest
    }
}

/// One validated plan-admission event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlanAdmittedEvent {
    envelope: EventEnvelope,
    payload: PlanAdmittedPayload,
}

impl PlanAdmittedEvent {
    /// # Errors
    ///
    /// Returns [`WireError::InvalidValue`] unless the envelope carries the `plan_admitted` payload
    /// type at a sequence above genesis.
    pub fn new(envelope: EventEnvelope, payload: PlanAdmittedPayload) -> Result<Self, WireError> {
        if envelope.payload_type() != PLAN_ADMITTED_PAYLOAD_TYPE || envelope.sequence() < 2 {
            return Err(WireError::InvalidValue);
        }
        Ok(Self { envelope, payload })
    }

    pub fn envelope(&self) -> &EventEnvelope {
        &self.envelope
    }

    pub fn payload(&self) -> &PlanAdmittedPayload {
        &self.payload
    }
}

/// Payload of the event that activates one issued grant.
///
/// It carries every fact the projection's grant columns store, so a rebuild folds the event
/// without reading the grant object back.
///
/// The work identity and its revision are held separately rather than as a [`WorkRef`]: this
/// payload is reachable by decoding untrusted bytes, and a `WorkRef` asserts that some admission
/// produced the revision it names. The fold resolves these two fields against the
/// `admitted_work` row and refuses a revision no admission produced.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrantActivatedPayload {
    work_id: WorkId,
    work_revision: NonZeroU64,
    claim_fence: NonZeroU64,
    grant_digest: Digest,
    attempt: NonZeroU64,
    units: NonZeroU64,
    deadline_unix_ms: NonZeroU64,
}

impl GrantActivatedPayload {
    /// # Errors
    ///
    /// Returns [`ValidationError::OutOfRange`] when the revision, fence, attempt, units, or
    /// deadline is zero or exceeds the stored-integer range.
    pub fn new(
        work_id: WorkId,
        work_revision: u64,
        claim_fence: u64,
        grant_digest: Digest,
        attempt: u64,
        units: u64,
        deadline_unix_ms: u64,
    ) -> Result<Self, ValidationError> {
        let bounded = |value: u64| bounded_stored(value).ok_or(ValidationError::OutOfRange);
        Ok(Self {
            work_id,
            work_revision: bounded(work_revision)?,
            claim_fence: bounded(claim_fence)?,
            grant_digest,
            attempt: bounded(attempt)?,
            units: bounded(units)?,
            deadline_unix_ms: bounded(deadline_unix_ms)?,
        })
    }

    pub fn work_id(&self) -> &WorkId {
        &self.work_id
    }

    pub fn work_revision(&self) -> NonZeroU64 {
        self.work_revision
    }

    pub fn claim_fence(&self) -> NonZeroU64 {
        self.claim_fence
    }

    pub fn grant_digest(&self) -> &Digest {
        &self.grant_digest
    }

    pub fn attempt(&self) -> NonZeroU64 {
        self.attempt
    }

    pub fn units(&self) -> NonZeroU64 {
        self.units
    }

    pub fn deadline_unix_ms(&self) -> NonZeroU64 {
        self.deadline_unix_ms
    }
}

/// One validated grant-activation event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrantActivatedEvent {
    envelope: EventEnvelope,
    payload: GrantActivatedPayload,
}

impl GrantActivatedEvent {
    /// # Errors
    ///
    /// Returns [`WireError::InvalidValue`] unless the envelope carries the `grant_activated`
    /// payload type at a sequence above genesis.
    pub fn new(envelope: EventEnvelope, payload: GrantActivatedPayload) -> Result<Self, WireError> {
        if envelope.payload_type() != GRANT_ACTIVATED_PAYLOAD_TYPE || envelope.sequence() < 2 {
            return Err(WireError::InvalidValue);
        }
        Ok(Self { envelope, payload })
    }

    pub fn envelope(&self) -> &EventEnvelope {
        &self.envelope
    }

    pub fn payload(&self) -> &GrantActivatedPayload {
        &self.payload
    }
}

/// What one artifact-reference event says the referenced blob is.
///
/// A closed enum, and an unrecognized wire string is refused rather than carried: a record
/// kind this crate cannot interpret must not reach history under the one payload type every
/// later artifact-bearing task extends. Extending means adding a variant here and nothing
/// else, because the wire struct's field set is frozen once its bytes ship.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArtifactKind {
    /// The immutable starting manifest of one model invocation.
    InvocationManifest,
    /// The terminal trace of one model invocation.
    InvocationTrace,
}

impl ArtifactKind {
    /// The media type a blob of this kind must carry.
    ///
    /// The kind and the media type are two records of the same fact, one in the event and one
    /// in the blob's metadata. They are pinned to each other here so a reader that trusts
    /// either one is trusting the same claim; a vendor type rather than a generic CBOR type
    /// because a reader that decodes a trace as a manifest gets a decode error, not a
    /// mismatch it can report.
    pub fn media_type(self) -> &'static str {
        match self {
            Self::InvocationManifest => "application/vnd.ravel.invocation-manifest+cbor",
            Self::InvocationTrace => "application/vnd.ravel.invocation-trace+cbor",
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvocationManifest => "invocation_manifest",
            Self::InvocationTrace => "invocation_trace",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "invocation_manifest" => Some(Self::InvocationManifest),
            "invocation_trace" => Some(Self::InvocationTrace),
            _ => None,
        }
    }
}

/// Payload of the event that admits one published artifact into authoritative history.
///
/// The reference names the attempt that produced the blob: the work revision an admission
/// released, the grant that authorized the external effect, and the attempt that drew it.
/// The claim fence is deliberately absent — the grant the digest names is itself fenced, so
/// carrying the fence again would record the same fact twice in bytes that cannot change.
///
/// Anything more the record must bind lives in the published artifact body, not here: this
/// payload rides in an event bounded at 256 KiB
/// compressed, while a prompt or completion is bounded at 1 MiB on its own. The one exception
/// is a trace's manifest address, because replay must prove the pairing after retention may
/// have deleted the blob whose body carries it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactReferencePayload {
    kind: ArtifactKind,
    artifact: ArtifactRef,
    work_id: WorkId,
    work_revision: NonZeroU64,
    grant_digest: Digest,
    attempt: NonZeroU64,
    manifest_digest: Option<Digest>,
}

impl ArtifactReferencePayload {
    /// Builds a reference from values that may have come from untrusted bytes.
    ///
    /// Crate-private and deliberately witness-free: the decode path has only bytes, so no
    /// constructor here can prove the blob exists. That proof is the append boundary's job,
    /// which takes a [`crate::storage::artifacts::PublishedArtifact`] and checks its
    /// namespace. `ArtifactRef::new` is public over plain values, so a payload constructor
    /// could not make an unwitnessed reference unrepresentable even if it tried.
    ///
    /// `manifest_digest` is the address of the manifest a trace terminates, present exactly
    /// when `kind` is a trace: a manifest starts an invocation and has no predecessor to name.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError::OutOfRange`] when the revision, attempt, artifact size, or
    /// creation time is zero or exceeds the stored-integer range. `ArtifactRef` accepts any
    /// size by design, so this is where an artifact entering durable history is bounded.
    /// Returns [`ValidationError::InvalidIdentity`] when the artifact's media type is not the
    /// one `kind` pins, its producer-attempt string names an attempt other than `attempt`, or
    /// the manifest address is present or absent against the kind's rule: each pair is two
    /// records of one fact, and both paths into history — the append boundary and the replay
    /// decoder — route through here, so neither can admit a contradiction.
    pub(crate) fn new(
        kind: ArtifactKind,
        artifact: ArtifactRef,
        work_id: WorkId,
        work_revision: u64,
        grant_digest: Digest,
        attempt: u64,
        manifest_digest: Option<Digest>,
    ) -> Result<Self, ValidationError> {
        let bounded = |value: u64| bounded_stored(value).ok_or(ValidationError::OutOfRange);
        bounded(artifact.size())?;
        bounded(artifact.creation_time_unix_ms())?;
        let work_revision = bounded(work_revision)?;
        let attempt_bound = bounded(attempt)?;
        if artifact.media_type() != kind.media_type()
            || artifact.producer_attempt() != format!("attempt-{attempt}")
            || (kind == ArtifactKind::InvocationTrace) != manifest_digest.is_some()
        {
            return Err(ValidationError::InvalidIdentity);
        }
        Ok(Self {
            kind,
            artifact,
            work_id,
            work_revision,
            grant_digest,
            attempt: attempt_bound,
            manifest_digest,
        })
    }

    pub fn kind(&self) -> ArtifactKind {
        self.kind
    }

    pub fn artifact(&self) -> &ArtifactRef {
        &self.artifact
    }

    pub fn work_id(&self) -> &WorkId {
        &self.work_id
    }

    pub fn work_revision(&self) -> NonZeroU64 {
        self.work_revision
    }

    /// The grant that authorized the effect this artifact records.
    pub fn grant_digest(&self) -> &Digest {
        &self.grant_digest
    }

    pub fn attempt(&self) -> NonZeroU64 {
        self.attempt
    }

    /// The manifest a trace terminates; `None` exactly when this reference is a manifest.
    pub fn manifest_digest(&self) -> Option<&Digest> {
        self.manifest_digest.as_ref()
    }
}

/// One validated artifact-reference event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactReferenceEvent {
    envelope: EventEnvelope,
    payload: ArtifactReferencePayload,
}

impl ArtifactReferenceEvent {
    /// # Errors
    ///
    /// Returns [`WireError::InvalidValue`] unless the envelope carries the
    /// `artifact_reference` payload type at a sequence above genesis.
    pub fn new(
        envelope: EventEnvelope,
        payload: ArtifactReferencePayload,
    ) -> Result<Self, WireError> {
        if envelope.payload_type() != ARTIFACT_REFERENCE_PAYLOAD_TYPE || envelope.sequence() < 2 {
            return Err(WireError::InvalidValue);
        }
        Ok(Self { envelope, payload })
    }

    pub fn envelope(&self) -> &EventEnvelope {
        &self.envelope
    }

    pub fn payload(&self) -> &ArtifactReferencePayload {
        &self.payload
    }
}

/// Payload of the event that certifies one published projection snapshot.
///
/// The snapshot key is derived from the covered sequence and snapshot digest; no key
/// string is stored. Certification grants no authority: replay must still prove the
/// certificate and its suffix against the pinned head before trusting the snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectionCheckpointPayload {
    snapshot_digest: Digest,
    snapshot_length: u64,
    covered_sequence: u64,
    covered_tail_digest: Digest,
    covered_active_plan_digest: Option<Digest>,
}

impl ProjectionCheckpointPayload {
    /// # Errors
    ///
    /// Returns [`WireError::InvalidValue`] for a zero or over-bound snapshot length or an
    /// invalid covered sequence.
    pub fn new(
        snapshot_digest: Digest,
        snapshot_length: u64,
        covered_sequence: u64,
        covered_tail_digest: Digest,
        covered_active_plan_digest: Option<Digest>,
    ) -> Result<Self, WireError> {
        if snapshot_length == 0
            || snapshot_length > crate::sync::accelerator::MAX_SNAPSHOT_BYTES as u64
        {
            return Err(WireError::InvalidValue);
        }
        validate_sequence(covered_sequence).map_err(|_| WireError::InvalidValue)?;
        Ok(Self {
            snapshot_digest,
            snapshot_length,
            covered_sequence,
            covered_tail_digest,
            covered_active_plan_digest,
        })
    }

    pub fn snapshot_digest(&self) -> &Digest {
        &self.snapshot_digest
    }

    pub fn snapshot_length(&self) -> u64 {
        self.snapshot_length
    }

    pub fn covered_sequence(&self) -> u64 {
        self.covered_sequence
    }

    pub fn covered_tail_digest(&self) -> &Digest {
        &self.covered_tail_digest
    }

    pub fn covered_active_plan_digest(&self) -> Option<&Digest> {
        self.covered_active_plan_digest.as_ref()
    }
}

/// One validated checkpoint-certificate event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectionCheckpointEvent {
    envelope: EventEnvelope,
    payload: ProjectionCheckpointPayload,
}

impl ProjectionCheckpointEvent {
    /// # Errors
    ///
    /// Returns [`WireError::InvalidValue`] unless the envelope carries the checkpoint
    /// payload type above genesis and its parent equals the payload's covered cursor.
    pub fn new(
        envelope: EventEnvelope,
        payload: ProjectionCheckpointPayload,
    ) -> Result<Self, WireError> {
        if envelope.payload_type() != PROJECTION_CHECKPOINT_PAYLOAD_TYPE || envelope.sequence() < 2
        {
            return Err(WireError::InvalidValue);
        }
        let parent_matches = envelope.parent_event().is_some_and(|parent| {
            parent.sequence() == payload.covered_sequence()
                && parent.digest() == payload.covered_tail_digest()
        });
        if !parent_matches {
            return Err(WireError::InvalidValue);
        }
        Ok(Self { envelope, payload })
    }

    pub fn envelope(&self) -> &EventEnvelope {
        &self.envelope
    }

    pub fn payload(&self) -> &ProjectionCheckpointPayload {
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

/// Builds the full claim key, which locates a claim by scope and work revision only.
///
/// Plan lineage and claim fence are bindings inside the record, not part of its location, so a
/// reader that has not yet seen the record can still address it.
pub(crate) fn scope_claim_key(scope: &ScopeIdentity, work: &WorkRef) -> String {
    format!(
        "workspace/{}/campaigns/{}/scopes/{}/claims/{}/{}",
        scope.workspace_id().as_str(),
        scope.campaign_id().as_str(),
        scope.scope_id().as_str(),
        work.id().as_str(),
        work.revision()
    )
}

/// Builds the full key of one claim generation's effect grant.
///
/// Unlike [`scope_claim_key`], the fence is part of the location: create-only publication then
/// yields one immutable object per claim generation, and a reader must already know its fence
/// to address a grant.
pub(crate) fn scope_grant_key(
    scope: &ScopeIdentity,
    work: &WorkRef,
    claim_fence: NonZeroU64,
) -> String {
    format!(
        "workspace/{}/campaigns/{}/scopes/{}/grants/{}/{}/{}",
        scope.workspace_id().as_str(),
        scope.campaign_id().as_str(),
        scope.scope_id().as_str(),
        work.id().as_str(),
        work.revision(),
        claim_fence
    )
}

/// The key places the digest after the attempt so `list_keys` can enumerate attempt keys without a decision address.
pub(crate) fn scope_gate_decision_key(
    scope: &ScopeIdentity,
    work: &WorkRef,
    claim_fence: NonZeroU64,
    attempt: NonZeroU64,
    decision_digest: &str,
) -> String {
    format!(
        "workspace/{}/campaigns/{}/scopes/{}/gate-decisions/{}/{}/{}/{}/{}",
        scope.workspace_id().as_str(),
        scope.campaign_id().as_str(),
        scope.scope_id().as_str(),
        work.id().as_str(),
        work.revision(),
        claim_fence,
        attempt,
        decision_digest
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
struct WirePlanAdmittedPayload {
    plan_digest: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireGrantActivatedPayload {
    work_id: String,
    work_revision: u64,
    claim_fence: u64,
    grant_digest: String,
    attempt: u64,
    units: u64,
    deadline_unix_ms: u64,
}

/// Frozen field set and declaration order of one artifact-reference payload.
///
/// CBOR writes these keys in declaration order, so both the order and the set are part of
/// this record's address. A later artifact-bearing task extends [`ArtifactKind`], never this
/// struct: adding a field here would move the bytes of every artifact reference already
/// published.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireArtifactReferencePayload {
    kind: String,
    digest: String,
    size: u64,
    media_type: String,
    producer_attempt: String,
    creation_time_unix_ms: u64,
    retention_class: Option<String>,
    work_id: String,
    work_revision: u64,
    grant_digest: String,
    attempt: u64,
    /// The manifest a trace terminates, present exactly for traces: replay proves the pairing
    /// from event bytes because retention may delete the blob whose body also carries it.
    manifest_digest: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireProjectionCheckpointPayload {
    version: u64,
    snapshot_digest: String,
    snapshot_length: u64,
    covered_sequence: u64,
    covered_tail_digest: String,
    covered_active_plan_digest: Option<String>,
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
/// Returns [`WireError`] for invalid framing, a payload type other than `expected_payload`,
/// noncanonical bytes, identities, scope binding, digest, or key.
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

/// Encodes one validated plan-admission event.
///
/// # Errors
///
/// Returns [`WireError`] for serialization, compression, or size-limit failures.
pub fn encode_plan_admitted_event(
    event: &PlanAdmittedEvent,
) -> Result<EncodedScopeEvent, WireError> {
    encode_scope_event(
        event.envelope(),
        &WirePlanAdmittedPayload {
            plan_digest: event.payload().plan_digest().as_str().to_owned(),
        },
    )
}

/// Encodes one validated grant-activation event.
///
/// # Errors
///
/// Returns [`WireError`] for serialization, compression, or size-limit failures.
pub fn encode_grant_activated_event(
    event: &GrantActivatedEvent,
) -> Result<EncodedScopeEvent, WireError> {
    encode_scope_event(
        event.envelope(),
        &WireGrantActivatedPayload {
            work_id: event.payload().work_id().as_str().to_owned(),
            work_revision: event.payload().work_revision().get(),
            claim_fence: event.payload().claim_fence().get(),
            grant_digest: event.payload().grant_digest().as_str().to_owned(),
            attempt: event.payload().attempt().get(),
            units: event.payload().units().get(),
            deadline_unix_ms: event.payload().deadline_unix_ms().get(),
        },
    )
}

/// Encodes one validated checkpoint-certificate event.
///
/// # Errors
///
/// Returns [`WireError`] for serialization, compression, or size-limit failures.
pub fn encode_projection_checkpoint_event(
    event: &ProjectionCheckpointEvent,
) -> Result<EncodedScopeEvent, WireError> {
    encode_scope_event(
        event.envelope(),
        &WireProjectionCheckpointPayload {
            version: 1,
            snapshot_digest: event.payload().snapshot_digest().as_str().to_owned(),
            snapshot_length: event.payload().snapshot_length(),
            covered_sequence: event.payload().covered_sequence(),
            covered_tail_digest: event.payload().covered_tail_digest().as_str().to_owned(),
            covered_active_plan_digest: event
                .payload()
                .covered_active_plan_digest()
                .map(|digest| digest.as_str().to_owned()),
        },
    )
}

/// Converts one opaque decoded event into a checkpoint-certificate event.
///
/// # Errors
///
/// Returns [`WireError`] for a payload type other than the checkpoint type, noncanonical
/// payload bytes, an unsupported version, or an invalid binding.
pub(crate) fn projection_checkpoint_from_decoded(
    decoded: DecodedScopeEvent<ciborium::Value>,
) -> Result<ProjectionCheckpointEvent, WireError> {
    if decoded.envelope.payload_type() != PROJECTION_CHECKPOINT_PAYLOAD_TYPE {
        return Err(WireError::InvalidValue);
    }
    let mut original = Vec::new();
    into_writer(&decoded.payload, &mut original).map_err(|_| WireError::InvalidEncoding)?;
    let payload: WireProjectionCheckpointPayload = decoded
        .payload
        .deserialized()
        .map_err(|_| WireError::InvalidEncoding)?;
    let mut canonical = Vec::new();
    into_writer(&payload, &mut canonical).map_err(|_| WireError::InvalidEncoding)?;
    if original != canonical {
        return Err(WireError::NonCanonical);
    }
    if payload.version != 1 {
        return Err(WireError::InvalidValue);
    }
    let payload = ProjectionCheckpointPayload::new(
        Digest::new(payload.snapshot_digest).map_err(|_| WireError::InvalidValue)?,
        payload.snapshot_length,
        payload.covered_sequence,
        Digest::new(payload.covered_tail_digest).map_err(|_| WireError::InvalidValue)?,
        payload
            .covered_active_plan_digest
            .map(Digest::new)
            .transpose()
            .map_err(|_| WireError::InvalidValue)?,
    )?;
    ProjectionCheckpointEvent::new(decoded.envelope, payload)
}

/// Decodes only the exact checkpoint-certificate event for `expected_scope` at
/// `expected_key`.
///
/// # Errors
///
/// Returns [`WireError`] for framing, size, canonicality, identity, or key failures.
pub fn decode_projection_checkpoint_event(
    stored_bytes: &[u8],
    expected_key: &str,
    expected_scope: &ScopeIdentity,
) -> Result<ProjectionCheckpointEvent, WireError> {
    let decoded = decode_scope_event::<ciborium::Value>(
        stored_bytes,
        expected_key,
        expected_scope,
        Some(PROJECTION_CHECKPOINT_PAYLOAD_TYPE),
    )?;
    projection_checkpoint_from_decoded(decoded)
}

/// Converts one opaque decoded event into a grant-activation event.
///
/// # Errors
///
/// Returns [`WireError`] for a payload type other than `grant_activated`, noncanonical payload
/// bytes, or an out-of-range binding.
pub(crate) fn grant_activated_from_decoded(
    decoded: DecodedScopeEvent<ciborium::Value>,
) -> Result<GrantActivatedEvent, WireError> {
    if decoded.envelope.payload_type() != GRANT_ACTIVATED_PAYLOAD_TYPE {
        return Err(WireError::InvalidValue);
    }
    let mut original = Vec::new();
    into_writer(&decoded.payload, &mut original).map_err(|_| WireError::InvalidEncoding)?;
    let payload: WireGrantActivatedPayload = decoded
        .payload
        .deserialized()
        .map_err(|_| WireError::InvalidEncoding)?;
    let mut canonical = Vec::new();
    into_writer(&payload, &mut canonical).map_err(|_| WireError::InvalidEncoding)?;
    if original != canonical {
        return Err(WireError::NonCanonical);
    }
    let payload = GrantActivatedPayload::new(
        WorkId::new(payload.work_id).map_err(|_| WireError::InvalidValue)?,
        payload.work_revision,
        payload.claim_fence,
        Digest::new(payload.grant_digest).map_err(|_| WireError::InvalidValue)?,
        payload.attempt,
        payload.units,
        payload.deadline_unix_ms,
    )
    .map_err(|_| WireError::InvalidValue)?;
    GrantActivatedEvent::new(decoded.envelope, payload)
}

/// Decodes only the exact grant-activation event for `expected_scope` at `expected_key`.
///
/// # Errors
///
/// Returns [`WireError`] for framing, size, canonicality, identity, or key failures.
pub fn decode_grant_activated_event(
    stored_bytes: &[u8],
    expected_key: &str,
    expected_scope: &ScopeIdentity,
) -> Result<GrantActivatedEvent, WireError> {
    let decoded = decode_scope_event::<ciborium::Value>(
        stored_bytes,
        expected_key,
        expected_scope,
        Some(GRANT_ACTIVATED_PAYLOAD_TYPE),
    )?;
    grant_activated_from_decoded(decoded)
}

/// Encodes one validated artifact-reference event.
///
/// # Errors
///
/// Returns [`WireError`] for serialization, compression, or size-limit failures.
pub fn encode_artifact_reference_event(
    event: &ArtifactReferenceEvent,
) -> Result<EncodedScopeEvent, WireError> {
    let payload = event.payload();
    let artifact = payload.artifact();
    encode_scope_event(
        event.envelope(),
        &WireArtifactReferencePayload {
            kind: payload.kind().as_str().to_owned(),
            digest: artifact.digest().to_owned(),
            size: artifact.size(),
            media_type: artifact.media_type().to_owned(),
            producer_attempt: artifact.producer_attempt().to_owned(),
            creation_time_unix_ms: artifact.creation_time_unix_ms(),
            retention_class: artifact.retention_class().map(str::to_owned),
            work_id: payload.work_id().as_str().to_owned(),
            work_revision: payload.work_revision().get(),
            grant_digest: payload.grant_digest().as_str().to_owned(),
            attempt: payload.attempt().get(),
            manifest_digest: payload
                .manifest_digest()
                .map(|digest| digest.as_str().to_owned()),
        },
    )
}

/// Converts one opaque decoded event into an artifact-reference event.
///
/// # Errors
///
/// Returns [`WireError`] for a payload type other than `artifact_reference`, noncanonical
/// payload bytes, a record kind this crate does not model, or an out-of-range binding.
pub(crate) fn artifact_reference_from_decoded(
    decoded: DecodedScopeEvent<ciborium::Value>,
) -> Result<ArtifactReferenceEvent, WireError> {
    if decoded.envelope.payload_type() != ARTIFACT_REFERENCE_PAYLOAD_TYPE {
        return Err(WireError::InvalidValue);
    }
    let mut original = Vec::new();
    into_writer(&decoded.payload, &mut original).map_err(|_| WireError::InvalidEncoding)?;
    let payload: WireArtifactReferencePayload = decoded
        .payload
        .deserialized()
        .map_err(|_| WireError::InvalidEncoding)?;
    let mut canonical = Vec::new();
    into_writer(&payload, &mut canonical).map_err(|_| WireError::InvalidEncoding)?;
    if original != canonical {
        return Err(WireError::NonCanonical);
    }
    let kind = ArtifactKind::parse(&payload.kind).ok_or(WireError::InvalidValue)?;
    let artifact = ArtifactRef::new(
        payload.digest,
        payload.size,
        payload.media_type,
        payload.producer_attempt,
        payload.creation_time_unix_ms,
        payload.retention_class,
    )
    .map_err(|_| WireError::InvalidValue)?;
    let payload = ArtifactReferencePayload::new(
        kind,
        artifact,
        WorkId::new(payload.work_id).map_err(|_| WireError::InvalidValue)?,
        payload.work_revision,
        Digest::new(payload.grant_digest).map_err(|_| WireError::InvalidValue)?,
        payload.attempt,
        payload
            .manifest_digest
            .map(Digest::new)
            .transpose()
            .map_err(|_| WireError::InvalidValue)?,
    )
    .map_err(|_| WireError::InvalidValue)?;
    ArtifactReferenceEvent::new(decoded.envelope, payload)
}

/// Decodes only the exact artifact-reference event for `expected_scope` at `expected_key`.
///
/// # Errors
///
/// Returns [`WireError`] for framing, size, canonicality, identity, or key failures.
pub fn decode_artifact_reference_event(
    stored_bytes: &[u8],
    expected_key: &str,
    expected_scope: &ScopeIdentity,
) -> Result<ArtifactReferenceEvent, WireError> {
    let decoded = decode_scope_event::<ciborium::Value>(
        stored_bytes,
        expected_key,
        expected_scope,
        Some(ARTIFACT_REFERENCE_PAYLOAD_TYPE),
    )?;
    artifact_reference_from_decoded(decoded)
}

/// Converts one opaque decoded event into a plan-admission event.
///
/// # Errors
///
/// Returns [`WireError`] for a payload type other than `plan_admitted`, noncanonical payload
/// bytes, or an invalid digest.
pub(crate) fn plan_admitted_from_decoded(
    decoded: DecodedScopeEvent<ciborium::Value>,
) -> Result<PlanAdmittedEvent, WireError> {
    if decoded.envelope.payload_type() != PLAN_ADMITTED_PAYLOAD_TYPE {
        return Err(WireError::InvalidValue);
    }
    let mut original = Vec::new();
    into_writer(&decoded.payload, &mut original).map_err(|_| WireError::InvalidEncoding)?;
    let payload: WirePlanAdmittedPayload = decoded
        .payload
        .deserialized()
        .map_err(|_| WireError::InvalidEncoding)?;
    let mut canonical = Vec::new();
    into_writer(&payload, &mut canonical).map_err(|_| WireError::InvalidEncoding)?;
    if original != canonical {
        return Err(WireError::NonCanonical);
    }
    let plan_digest = Digest::new(payload.plan_digest).map_err(|_| WireError::InvalidValue)?;
    PlanAdmittedEvent::new(decoded.envelope, PlanAdmittedPayload { plan_digest })
}

/// Decodes only the exact plan-admission event for `expected_scope` at `expected_key`.
///
/// # Errors
///
/// Returns [`WireError`] for framing, size, canonicality, identity, or key failures.
pub fn decode_plan_admitted_event(
    stored_bytes: &[u8],
    expected_key: &str,
    expected_scope: &ScopeIdentity,
) -> Result<PlanAdmittedEvent, WireError> {
    let decoded = decode_scope_event::<ciborium::Value>(
        stored_bytes,
        expected_key,
        expected_scope,
        Some(PLAN_ADMITTED_PAYLOAD_TYPE),
    )?;
    plan_admitted_from_decoded(decoded)
}

/// Decodes only the exact root-genesis event for `expected_scope` at `expected_key`.
///
/// # Errors
///
/// Returns [`WireError`] for framing and size failures, malformed or noncanonical bytes,
/// a payload type other than root-genesis, non-root or invalid identities, wrong-scope bytes,
/// or a key mismatch. The decoder rejects the payload type before canonicality checks.
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
    if payload_type == ROOT_GENESIS_PAYLOAD_TYPE
        || payload_type == PLAN_ADMITTED_PAYLOAD_TYPE
        || payload_type == GRANT_ACTIVATED_PAYLOAD_TYPE
        || payload_type == ARTIFACT_REFERENCE_PAYLOAD_TYPE
        || payload_type == PROJECTION_CHECKPOINT_PAYLOAD_TYPE
    {
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

pub(crate) fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod codec_tests {
    use ciborium::Value;

    use crate::domain::validation::MAX_STORED_INTEGER;

    use crate::distributed::identity::WorkspaceId;

    use super::*;

    /// Stored-byte address of the artifact-reference event
    /// `artifact_reference_events_round_trip_and_pin_their_address` builds. The preimage is the
    /// compressed CBOR, so both the `ciborium` and `zstd-sys` lockfile pins are byte-affecting
    /// for this value, as is any change to the wire struct's field set or declaration order.
    const ARTIFACT_REFERENCE_EVENT_DIGEST: &str =
        "96f6bc7d738e56fe818440dea8bf4fd76f9d04329dc57bd5a1b5dd238187920f";

    /// Stored-byte address of the activation event
    /// `grant_activated_events_round_trip_and_reject_corruption` builds. The preimage is the
    /// compressed CBOR, so both the `ciborium` and `zstd-sys` lockfile pins are byte-affecting for
    /// this value.
    const ACTIVATION_EVENT_DIGEST: &str =
        "9a00fbfcbea187b4e842f2168ebca6fe2bd60518f7e2ada79e7b330fa06a8fd4";

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

    fn repacked(
        stored: &[u8],
        scope: &ScopeIdentity,
        mutate: impl FnOnce(&mut Value),
    ) -> (Vec<u8>, String) {
        let cbor = zstd::bulk::decompress(stored, MAX_DECOMPRESSED_BYTES).unwrap();
        let mut value: Value = ciborium::from_reader(cbor.as_slice()).unwrap();
        let payload = map(&mut value)
            .iter_mut()
            .find_map(|(key, value)| (key == &Value::Text("payload".into())).then_some(value))
            .unwrap();
        mutate(payload);
        let mut rewritten = Vec::new();
        into_writer(&value, &mut rewritten).unwrap();
        let rewritten = compress(&rewritten).unwrap();
        let reference = ScopeEventRef::new(2, Digest::new(sha256(&rewritten)).unwrap()).unwrap();
        (rewritten.clone(), scope_event_key(scope, &reference))
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

    #[test]
    fn grant_activated_events_round_trip_and_reject_corruption() {
        use crate::domain::work::WorkId;

        let genesis = fixture();
        let payload = GrantActivatedPayload::new(
            WorkId::new("work-17".into()).unwrap(),
            1,
            2,
            Digest::new("ab".repeat(32)).unwrap(),
            1,
            5,
            1_700_000_060_000,
        )
        .unwrap();
        let event = GrantActivatedEvent::new(
            EventEnvelope::new(
                genesis.identity().scope_id().clone(),
                2,
                Some(genesis.event_ref().clone()),
                1,
                "grant-op-1".into(),
                GRANT_ACTIVATED_PAYLOAD_TYPE.to_owned(),
            )
            .unwrap(),
            payload.clone(),
        )
        .unwrap();

        let encoded = encode_grant_activated_event(&event).unwrap();
        let key = scope_event_key(genesis.identity(), encoded.event_ref());
        // `encode_grant_activated_event` and `grant_activated_from_decoded` map `work_id` and
        // `work_revision` field by field, so an edit applied to both leaves the round-trip
        // assertion below green while changing the address and key of every stored activation
        // event. Only a fixed digest catches that.
        assert_eq!(
            encoded.event_ref().digest().as_str(),
            ACTIVATION_EVENT_DIGEST
        );
        assert_eq!(
            decode_grant_activated_event(encoded.stored_bytes(), &key, genesis.identity()).unwrap(),
            event
        );
        // Genesis bytes are a registered event, but not this payload type.
        assert_eq!(
            decode_grant_activated_event(
                genesis.event_bytes(),
                genesis.event_key(),
                genesis.identity()
            ),
            Err(WireError::InvalidValue)
        );
        // An activation cannot occupy the genesis sequence.
        assert_eq!(
            GrantActivatedEvent::new(
                EventEnvelope::new(
                    genesis.identity().scope_id().clone(),
                    1,
                    None,
                    1,
                    "grant-op-1".into(),
                    GRANT_ACTIVATED_PAYLOAD_TYPE.to_owned(),
                )
                .unwrap(),
                payload.clone(),
            ),
            Err(WireError::InvalidValue)
        );

        // Rewriting the payload and re-keying the result is the only way to reach the decoder's own
        // rejections: the encoder cannot produce these bytes, and a stale key would be refused for
        // its address before its payload was interpreted.

        // Unknown payload fields are rejected.
        let (extended, extended_key) =
            repacked(encoded.stored_bytes(), genesis.identity(), |payload| {
                map(payload).push((Value::Text("extra".into()), Value::Integer(1.into())));
            });
        assert!(
            decode_grant_activated_event(&extended, &extended_key, genesis.identity()).is_err()
        );

        // The decoder is where an activation naming unvalidated work has to fail: nothing between
        // these bytes and the fold reconstructs the identity or re-checks the revision.
        for (field, to) in [
            ("work_id", Value::Text(String::new())),
            ("work_id", Value::Text("work/17".into())),
            ("work_id", Value::Text("w".repeat(129))),
            ("work_revision", Value::Integer(0.into())),
            (
                "work_revision",
                Value::Integer((MAX_STORED_INTEGER + 1).into()),
            ),
        ] {
            let (bytes, bad_key) =
                repacked(encoded.stored_bytes(), genesis.identity(), |payload| {
                    let slot = map(payload)
                        .iter_mut()
                        .find_map(|(key, value)| {
                            (key == &Value::Text(field.to_owned())).then_some(value)
                        })
                        .unwrap();
                    *slot = to.clone();
                });
            assert_eq!(
                decode_grant_activated_event(&bytes, &bad_key, genesis.identity()),
                Err(WireError::InvalidValue),
                "{field} = {to:?}"
            );
        }

        // Every integer binding is bounded by the stored-integer range and must be nonzero.
        let work_id = || WorkId::new("work-17".into()).unwrap();
        let digest = || Digest::new("ab".repeat(32)).unwrap();
        let max = MAX_STORED_INTEGER;
        assert!(GrantActivatedPayload::new(work_id(), max, max, digest(), max, max, max).is_ok());
        for (revision, fence, attempt, units, deadline) in [
            (0, 1, 1, 1, 1),
            (1, 0, 1, 1, 1),
            (1, 1, 0, 1, 1),
            (1, 1, 1, 0, 1),
            (1, 1, 1, 1, 0),
            (max + 1, 1, 1, 1, 1),
            (1, max + 1, 1, 1, 1),
            (1, 1, max + 1, 1, 1),
            (1, 1, 1, max + 1, 1),
            (1, 1, 1, 1, max + 1),
        ] {
            assert_eq!(
                GrantActivatedPayload::new(
                    work_id(),
                    revision,
                    fence,
                    digest(),
                    attempt,
                    units,
                    deadline
                ),
                Err(crate::domain::validation::ValidationError::OutOfRange)
            );
        }
    }

    /// Pairwise-distinct values for every field a transposition could reach: six same-typed
    /// strings and four same-typed integers, any two of which the wire layout could swap. A
    /// swapped pair would otherwise round-trip and pass canonicality unnoticed.
    fn artifact_reference() -> ArtifactReferencePayload {
        use crate::domain::work::WorkId;

        ArtifactReferencePayload::new(
            ArtifactKind::InvocationTrace,
            crate::domain::artifact::ArtifactRef::new(
                "cd".repeat(32),
                4_096,
                "application/vnd.ravel.invocation-trace+cbor".into(),
                "attempt-7".into(),
                1_700_000_123_456,
                Some("pilot".into()),
            )
            .unwrap(),
            WorkId::new("work-a".into()).unwrap(),
            3,
            Digest::new("ab".repeat(32)).unwrap(),
            7,
            Some(Digest::new("ef".repeat(32)).unwrap()),
        )
        .unwrap()
    }

    fn artifact_event(genesis: &RootGenesis) -> ArtifactReferenceEvent {
        ArtifactReferenceEvent::new(
            EventEnvelope::new(
                genesis.identity().scope_id().clone(),
                2,
                Some(genesis.event_ref().clone()),
                1,
                "artifact-op-1".into(),
                ARTIFACT_REFERENCE_PAYLOAD_TYPE.to_owned(),
            )
            .unwrap(),
            artifact_reference(),
        )
        .unwrap()
    }

    #[test]
    fn artifact_reference_events_round_trip_and_pin_their_address() {
        let genesis = fixture();
        let event = artifact_event(&genesis);

        let encoded = encode_artifact_reference_event(&event).unwrap();
        // Pins the compressed stored bytes. Both the field set and the declaration order of
        // `WireArtifactReferencePayload` are part of this address, so a reordered or extended
        // wire struct moves every artifact reference already published.
        assert_eq!(
            encoded.event_ref().digest().as_str(),
            ARTIFACT_REFERENCE_EVENT_DIGEST
        );
        let key = scope_event_key(genesis.identity(), encoded.event_ref());
        assert_eq!(
            decode_artifact_reference_event(encoded.stored_bytes(), &key, genesis.identity())
                .unwrap(),
            event
        );

        // Every field survives the round trip in its own position, which is what makes the
        // transposable pairs above worth distinct values.
        let payload = event.payload();
        assert_eq!(payload.kind(), ArtifactKind::InvocationTrace);
        assert_eq!(payload.artifact().digest(), "cd".repeat(32));
        assert_eq!(payload.artifact().size(), 4_096);
        assert_eq!(
            payload.artifact().media_type(),
            "application/vnd.ravel.invocation-trace+cbor"
        );
        assert_eq!(payload.artifact().producer_attempt(), "attempt-7");
        assert_eq!(
            payload.artifact().creation_time_unix_ms(),
            1_700_000_123_456
        );
        assert_eq!(payload.artifact().retention_class(), Some("pilot"));
        assert_eq!(payload.work_id().as_str(), "work-a");
        assert_eq!(payload.work_revision().get(), 3);
        assert_eq!(payload.grant_digest().as_str(), "ab".repeat(32));
        assert_eq!(payload.attempt().get(), 7);
        assert_eq!(
            payload.manifest_digest().map(Digest::as_str),
            Some("ef".repeat(32)).as_deref()
        );

        // Genesis bytes are a registered event, but not this payload type.
        assert_eq!(
            decode_artifact_reference_event(
                genesis.event_bytes(),
                genesis.event_key(),
                genesis.identity()
            ),
            Err(WireError::InvalidValue)
        );
        // An artifact reference cannot occupy the genesis sequence.
        assert_eq!(
            ArtifactReferenceEvent::new(
                EventEnvelope::new(
                    genesis.identity().scope_id().clone(),
                    1,
                    None,
                    1,
                    "artifact-op-1".into(),
                    ARTIFACT_REFERENCE_PAYLOAD_TYPE.to_owned(),
                )
                .unwrap(),
                artifact_reference(),
            ),
            Err(WireError::InvalidValue)
        );
    }

    /// A record kind this crate does not model is refused rather than carried. The kind is the
    /// one axis a later artifact-bearing task extends, so an unknown string reaching history
    /// would be a record no reader can interpret under a payload type they all share.
    #[test]
    fn an_unmodelled_record_kind_is_refused_by_the_decoder() {
        let genesis = fixture();
        let encoded = encode_artifact_reference_event(&artifact_event(&genesis)).unwrap();

        for kind in [
            Value::Text(String::new()),
            Value::Text("invocation_manifest_v2".into()),
            Value::Text("candidate_bundle".into()),
        ] {
            let (bytes, key) = repacked(encoded.stored_bytes(), genesis.identity(), |payload| {
                let slot = map(payload)
                    .iter_mut()
                    .find_map(|(key, value)| (key == &Value::Text("kind".into())).then_some(value))
                    .unwrap();
                *slot = kind.clone();
            });
            assert_eq!(
                decode_artifact_reference_event(&bytes, &key, genesis.identity()),
                Err(WireError::InvalidValue),
                "{kind:?}"
            );
        }
    }

    /// The kind/media-type and attempt/producer pins hold on the decode path, not just at the
    /// append boundary: canonical stored bytes whose two records of one fact disagree are
    /// refused on replay exactly as publication would have refused them.
    #[test]
    fn a_stored_reference_whose_pinned_fields_disagree_is_refused_by_the_decoder() {
        let genesis = fixture();
        let encoded = encode_artifact_reference_event(&artifact_event(&genesis)).unwrap();

        // The fixture is a trace at attempt 7, so each mutation contradicts exactly one pin.
        for (label, field, value) in [
            (
                "the other kind's media type",
                "media_type",
                Value::Text("application/vnd.ravel.invocation-manifest+cbor".into()),
            ),
            (
                "a producer string naming another attempt",
                "producer_attempt",
                Value::Text("attempt-8".into()),
            ),
            (
                "a trace with no manifest address",
                "manifest_digest",
                Value::Null,
            ),
        ] {
            let (bytes, key) = repacked(encoded.stored_bytes(), genesis.identity(), |payload| {
                let slot = map(payload)
                    .iter_mut()
                    .find_map(|(key, target)| (key == &Value::Text(field.into())).then_some(target))
                    .unwrap();
                *slot = value.clone();
            });
            assert_eq!(
                decode_artifact_reference_event(&bytes, &key, genesis.identity()),
                Err(WireError::InvalidValue),
                "{label}"
            );
        }
    }

    /// Every integer an artifact reference carries is bounded where the reference is built,
    /// including the two `ArtifactRef` accepts unbounded by design.
    #[test]
    fn artifact_reference_integer_bindings_are_bounded_and_nonzero() {
        use crate::domain::work::WorkId;

        let max = MAX_STORED_INTEGER;
        let build = |size: u64, creation: u64, revision: u64, attempt: u64| {
            let kind = ArtifactKind::InvocationManifest;
            ArtifactReferencePayload::new(
                kind,
                crate::domain::artifact::ArtifactRef::new(
                    "cd".repeat(32),
                    size,
                    kind.media_type().into(),
                    format!("attempt-{attempt}"),
                    creation,
                    None,
                )
                .unwrap(),
                WorkId::new("work-a".into()).unwrap(),
                revision,
                Digest::new("ab".repeat(32)).unwrap(),
                attempt,
                None,
            )
        };

        assert!(build(max, max, max, max).is_ok());
        for (size, creation, revision, attempt) in [
            (0, 1, 1, 1),
            (1, 0, 1, 1),
            (1, 1, 0, 1),
            (1, 1, 1, 0),
            (max + 1, 1, 1, 1),
            (1, max + 1, 1, 1),
            (1, 1, max + 1, 1),
            (1, 1, 1, max + 1),
        ] {
            assert_eq!(
                build(size, creation, revision, attempt),
                Err(ValidationError::OutOfRange),
                "{size} {creation} {revision} {attempt}"
            );
        }
    }

    /// `WorkRef` construction is crate-private, so the claim and grant key axes can only be
    /// exercised from inside the crate. The scope address itself is pinned by
    /// `root_genesis_fixture_is_deterministic_and_canonical`, so this derives it from the fixture
    /// rather than repeating the literal.
    #[test]
    fn claim_and_grant_keys_cover_the_exact_identity_axis() {
        use crate::domain::work::{WorkId, WorkRef};

        let scope = fixture().identity().clone();
        let digest = Digest::new("0".repeat(64)).unwrap();
        let claim = ScopeClaimIdentity::new(
            scope.clone(),
            digest.clone(),
            WorkRef::new(WorkId::new("work-17".into()).unwrap(), 4),
            9,
        )
        .unwrap();
        let prefix = format!(
            "workspace/workspace-a/campaigns/campaign-a/scopes/{}",
            scope.scope_id().as_str()
        );

        assert_eq!(
            scope_claim_key(claim.scope(), claim.work()),
            format!("{prefix}/claims/work-17/4")
        );
        // The fence is part of the grant location and not of the claim location.
        assert_eq!(
            scope_grant_key(claim.scope(), claim.work(), claim.claim_fence()),
            format!("{prefix}/grants/work-17/4/9")
        );
        assert_eq!(
            scope_gate_decision_key(
                claim.scope(),
                claim.work(),
                claim.claim_fence(),
                NonZeroU64::new(3).unwrap(),
                digest.as_str(),
            ),
            format!("{prefix}/gate-decisions/work-17/4/9/3/{}", digest.as_str())
        );
        assert_eq!(claim.plan_digest(), &digest);
        assert_eq!(claim.claim_fence().get(), 9);
        assert_eq!(
            ScopeClaimIdentity::new(scope, digest, claim.work().clone(), 0),
            Err(ValidationError::InvalidFence)
        );
    }

    #[test]
    fn projection_checkpoint_events_round_trip_and_reject_broken_bindings() {
        let genesis = fixture();
        let snapshot_digest = Digest::new("ab".repeat(32)).unwrap();
        let payload = ProjectionCheckpointPayload::new(
            snapshot_digest.clone(),
            8_192,
            1,
            genesis.event_ref().digest().clone(),
            None,
        )
        .unwrap();
        let event = ProjectionCheckpointEvent::new(
            EventEnvelope::new(
                genesis.identity().scope_id().clone(),
                2,
                Some(genesis.event_ref().clone()),
                1,
                "checkpoint-op-1".into(),
                PROJECTION_CHECKPOINT_PAYLOAD_TYPE.to_owned(),
            )
            .unwrap(),
            payload.clone(),
        )
        .unwrap();

        let encoded = encode_projection_checkpoint_event(&event).unwrap();
        let key = scope_event_key(genesis.identity(), encoded.event_ref());
        assert_eq!(
            decode_projection_checkpoint_event(encoded.stored_bytes(), &key, genesis.identity())
                .unwrap(),
            event
        );
        // Genesis bytes are a registered event, but not this payload type.
        assert_eq!(
            decode_projection_checkpoint_event(
                genesis.event_bytes(),
                genesis.event_key(),
                genesis.identity()
            ),
            Err(WireError::InvalidValue)
        );

        // The envelope parent must equal the payload's covered cursor.
        let disagreeing = ProjectionCheckpointPayload::new(
            snapshot_digest.clone(),
            8_192,
            1,
            Digest::new("0".repeat(64)).unwrap(),
            None,
        )
        .unwrap();
        assert_eq!(
            ProjectionCheckpointEvent::new(
                EventEnvelope::new(
                    genesis.identity().scope_id().clone(),
                    2,
                    Some(genesis.event_ref().clone()),
                    1,
                    "checkpoint-op-1".into(),
                    PROJECTION_CHECKPOINT_PAYLOAD_TYPE.to_owned(),
                )
                .unwrap(),
                disagreeing,
            ),
            Err(WireError::InvalidValue)
        );

        // A zero or over-bound snapshot length never encodes.
        assert_eq!(
            ProjectionCheckpointPayload::new(
                snapshot_digest.clone(),
                0,
                1,
                genesis.event_ref().digest().clone(),
                None,
            ),
            Err(WireError::InvalidValue)
        );
        assert_eq!(
            ProjectionCheckpointPayload::new(
                snapshot_digest.clone(),
                crate::sync::accelerator::MAX_SNAPSHOT_BYTES as u64 + 1,
                1,
                genesis.event_ref().digest().clone(),
                None,
            ),
            Err(WireError::InvalidValue)
        );
        // The bound itself is accepted.
        assert!(
            ProjectionCheckpointPayload::new(
                snapshot_digest.clone(),
                crate::sync::accelerator::MAX_SNAPSHOT_BYTES as u64,
                1,
                genesis.event_ref().digest().clone(),
                None,
            )
            .is_ok()
        );

        // A future payload version fails closed.
        let cbor = zstd::bulk::decompress(encoded.stored_bytes(), MAX_DECOMPRESSED_BYTES).unwrap();
        let mut value: Value = ciborium::from_reader(cbor.as_slice()).unwrap();
        let root = map(&mut value);
        let nested = root
            .iter_mut()
            .find_map(|(key, value)| (key == &Value::Text("payload".into())).then_some(value))
            .unwrap();
        for (key, field) in map(nested).iter_mut() {
            if key == &Value::Text("version".into()) {
                *field = Value::Integer(2.into());
            }
        }
        let mut versioned = Vec::new();
        into_writer(&value, &mut versioned).unwrap();
        let versioned = compress(&versioned).unwrap();
        let versioned_ref =
            ScopeEventRef::new(2, Digest::new(sha256(&versioned)).unwrap()).unwrap();
        let versioned_key = scope_event_key(genesis.identity(), &versioned_ref);
        assert_eq!(
            decode_projection_checkpoint_event(&versioned, &versioned_key, genesis.identity()),
            Err(WireError::InvalidValue)
        );
    }

    #[test]
    fn plan_admitted_events_round_trip_and_reject_foreign_payloads() {
        let genesis = fixture();
        let plan_digest = Digest::new("ab".repeat(32)).unwrap();
        let event = PlanAdmittedEvent::new(
            EventEnvelope::new(
                genesis.identity().scope_id().clone(),
                2,
                Some(genesis.event_ref().clone()),
                1,
                "admit-plan-1".into(),
                PLAN_ADMITTED_PAYLOAD_TYPE.to_owned(),
            )
            .unwrap(),
            PlanAdmittedPayload::new(plan_digest.clone()),
        )
        .unwrap();

        let encoded = encode_plan_admitted_event(&event).unwrap();
        let key = scope_event_key(genesis.identity(), encoded.event_ref());
        assert_eq!(
            decode_plan_admitted_event(encoded.stored_bytes(), &key, genesis.identity()).unwrap(),
            event
        );
        // Genesis bytes are a registered event, but not this payload type.
        assert_eq!(
            decode_plan_admitted_event(
                genesis.event_bytes(),
                genesis.event_key(),
                genesis.identity()
            ),
            Err(WireError::InvalidValue)
        );
        // An admission cannot occupy the genesis sequence.
        assert_eq!(
            PlanAdmittedEvent::new(
                EventEnvelope::new(
                    genesis.identity().scope_id().clone(),
                    1,
                    None,
                    1,
                    "admit-plan-1".into(),
                    PLAN_ADMITTED_PAYLOAD_TYPE.to_owned(),
                )
                .unwrap(),
                PlanAdmittedPayload::new(plan_digest),
            ),
            Err(WireError::InvalidValue)
        );
    }
}
