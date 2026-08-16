//! Root-only scoped head transitions and retained-chain reconciliation.
//!
//! Epoch ordering rule (`docs/mvp-outline.md` §7.2): a head's `scope_epoch` is at least the
//! projected scope epoch, which is at least any applied event's `writer_epoch`, and a
//! `writer_epoch` never decreases from an event to its child. An authority transition raises the
//! epoch without publishing an event, so events lag the head; an event append leaves the epoch
//! alone and commits under it. Append time enforces the equality here; replay enforces the event
//! bounds in `sync::replay::prepare_chain`; apply and open enforce the projected bounds in
//! `db::projections`.
//! commentlint: allow(JUDGE)
//!
//! Only a plan-admission event changes a head's active plan digest.
//! Retained walks stop at 4,096 events or 64 MiB of stored event bytes.

use std::{collections::HashSet, error::Error, fmt, num::NonZeroU64};

use crate::{
    dispatch::AttemptHistory,
    domain::proposal::{AdmissibleProposal, MAX_PLAN_STORED_BYTES, decode_plan},
    invocation::{InvocationBinding, decode_manifest, decode_trace},
    scope::{
        ARTIFACT_REFERENCE_PAYLOAD_TYPE, ArtifactKind, ArtifactReferenceEvent,
        ArtifactReferencePayload, Digest, EncodedScopeEvent, EventEnvelope,
        GRANT_ACTIVATED_PAYLOAD_TYPE, GrantActivatedEvent, GrantActivatedPayload, MAX_HEAD_BYTES,
        PLAN_ADMITTED_PAYLOAD_TYPE, PROJECTION_CHECKPOINT_PAYLOAD_TYPE, PlanAdmittedEvent,
        ProjectionCheckpointEvent, ProjectionCheckpointPayload, ScopeAuthority, ScopeEventRef,
        ScopeHead, ScopeIdentity, decode_head, decode_plan_admitted_event,
        encode_artifact_reference_event, encode_grant_activated_event, encode_head,
        encode_plan_admitted_event, encode_projection_checkpoint_event, plan_key, scope_event_key,
        scope_head_key,
    },
    storage::{
        artifacts::PublishedArtifact,
        s3::{ETag, GetError, GetOutcome, MutationOutcome, PublicationError, S3Store},
    },
};

use super::{
    WireError,
    accelerator::{self, StoredEvent},
    event::{
        ResolvedScopeEventPublication, ScopeEventPublicationError, payload_registered,
        publish_encoded, publish_root, read_opaque, root_domain_valid, root_payload_valid,
        validate_registered,
    },
};

const MAX_RECONCILE_HOPS: u64 = 4_096;
const MAX_RECONCILE_BYTES: usize = 64 * 1024 * 1024;

/// Canonical head bytes, ETag, and store namespace observed by [`read`].
/// Existing-parent commits require this namespace to match the target store.
pub struct ObservedScopeHead {
    head: ScopeHead,
    bytes: Vec<u8>,
    etag: ETag,
    namespace: String,
}

impl ObservedScopeHead {
    pub(crate) fn proven(head: ScopeHead, bytes: Vec<u8>, etag: ETag, namespace: String) -> Self {
        Self {
            head,
            bytes,
            etag,
            namespace,
        }
    }

    pub fn head(&self) -> &ScopeHead {
        &self.head
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) fn etag(&self) -> &ETag {
        &self.etag
    }

    pub(crate) fn namespace(&self) -> &str {
        &self.namespace
    }
}

#[derive(Debug)]
pub enum ScopeHeadReadError {
    Storage(GetError),
    Invalid(WireError),
}

impl fmt::Display for ScopeHeadReadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Storage(_) => "scope head read failed",
            Self::Invalid(_) => "scope head encoding is invalid",
        })
    }
}

impl Error for ScopeHeadReadError {}

/// Boundary authorized for one head transition.
pub enum ScopeHeadParent {
    /// Create the first head with no observed predecessor.
    Genesis,
    /// Replace exactly this observed head by ETag.
    Existing(FencedParent),
}

impl ScopeHeadParent {
    pub(crate) fn existing(observed: Box<ObservedScopeHead>) -> Self {
        Self::Existing(FencedParent(observed))
    }
}

/// Observed head that a fenced controller authorized as a transition boundary.
///
/// Outside this crate the only source is `ControllerAuthority::into_parent`, so a caller holding
/// no authority cannot replace an existing head. Inside the crate `ScopeHeadParent::existing`
/// accepts any observed head and its callers must supply a fenced one.
pub struct FencedParent(Box<ObservedScopeHead>);

impl std::ops::Deref for FencedParent {
    type Target = ObservedScopeHead;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Validated event/head unit consumed by [`commit`].
pub struct ScopeHeadTransition {
    parent: ScopeHeadParent,
    candidate: ScopeHead,
    head_bytes: Vec<u8>,
    event: ResolvedScopeEventPublication,
}

impl ScopeHeadTransition {
    /// Binds one canonical event publication to its candidate head and parent boundary.
    ///
    /// A successor candidate carries the observed controller, lease, and epoch unchanged, a new
    /// operation ID, the observed tail as its event parent, and the next sequence; its event's
    /// `writer_epoch` equals that epoch, and its active plan follows the one transition rule: a
    /// `plan_admitted` event moves it from none to the payload's digest, everything else keeps it.
    /// Genesis is instead unowned at epoch 1, sequence 1, with no event parent and no active plan.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::InvalidValue`] when any of those bindings fails, when the event's
    /// sequence is above [`crate::sync::replay::MAX_SCOPE_REPLAY_EVENTS`], or another
    /// [`WireError`] when the candidate head cannot be canonically encoded.
    pub fn new(
        parent: ScopeHeadParent,
        candidate: ScopeHead,
        event: ResolvedScopeEventPublication,
    ) -> Result<Self, WireError> {
        Self::new_batch(parent, candidate, vec![event])
    }

    /// Binds an ordered batch of canonical event publications to one candidate head.
    ///
    /// The batch commits atomically at the single head CAS: the candidate carries the final
    /// event's reference and operation identity, so the existing commit, resolution, and
    /// reconciliation mechanics treat the whole batch as one transition identified by its final
    /// event. Only that final publication is stored; the earlier members are chain-proven here
    /// and reachable from it through their parent references.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::InvalidValue`] when the batch-internal chain or any candidate
    /// binding fails, plan payload decode errors verbatim, or another [`WireError`] when the
    /// candidate head cannot be canonically encoded.
    fn new_batch(
        parent: ScopeHeadParent,
        candidate: ScopeHead,
        events: Vec<ResolvedScopeEventPublication>,
    ) -> Result<Self, WireError> {
        let active_plan = {
            let views: Vec<BatchEventView<'_>> =
                events.iter().map(BatchEventView::of_publication).collect();
            // Re-proven after publication because `new` is public API and must be sound on its
            // own, even for a caller that skipped `append_batch`'s preflight.
            validate_batch_chain(&parent, &views)?
        };
        // All members must be witnessed in one store namespace: `commit` compares only the stored final publication against its target store, so agreement across the batch is proven here. commentlint: allow(JUDGE)
        if let Some(last) = events.last()
            && events
                .iter()
                .any(|event| event.namespace() != last.namespace())
        {
            return Err(WireError::InvalidValue);
        }
        // The fallback is unreachable: validate_batch_chain rejects an empty batch.
        let event = events
            .into_iter()
            .next_back()
            .ok_or(WireError::InvalidValue)?;
        let envelope = event.envelope();
        if candidate.scope() != event.scope()
            || candidate.tail() != event.event_ref()
            || candidate.operation_id() != envelope.operation_id()
            || envelope.scope_id() != candidate.scope().scope_id()
            || envelope.writer_epoch() != candidate.scope_epoch()
            || candidate.active_plan_digest() != active_plan.as_ref()
        {
            return Err(WireError::InvalidValue);
        }
        match &parent {
            ScopeHeadParent::Genesis => {
                if !matches!(candidate.authority(), ScopeAuthority::Unowned)
                    || candidate.scope_epoch().get() != 1
                {
                    return Err(WireError::InvalidValue);
                }
            }
            ScopeHeadParent::Existing(observed) => {
                if candidate.scope() != observed.head.scope()
                    || candidate.authority() != observed.head.authority()
                    || candidate.scope_epoch() != observed.head.scope_epoch()
                {
                    return Err(WireError::InvalidValue);
                }
            }
        }
        let head_bytes = encode_head(&candidate)?;
        Ok(Self {
            parent,
            candidate,
            head_bytes,
            event,
        })
    }

    #[cfg(test)]
    pub(crate) fn attributed_to(mut self, namespace: &str) -> Self {
        self.event = self.event.attributed_to(namespace);
        if let ScopeHeadParent::Existing(observed) = &mut self.parent {
            observed.0.namespace = namespace.to_owned();
        }
        self
    }
}

#[must_use]
/// Result of conditional head publication and retained-chain reconciliation.
pub enum ScopeHeadCommitOutcome {
    /// Candidate is the authoritative head. Carries the committed observation when the write
    /// (or its resolution read) yielded an ETag, so a caller can chain the next conditional
    /// write without rereading.
    Committed(Option<Box<ObservedScopeHead>>),
    /// Candidate is proven in the retained ancestry below a newer head.
    CommittedSuperseded,
    /// The traversal reaches the original parent or genesis boundary without finding
    /// the candidate operation.
    ProvenNotCommitted,
    /// Retry the returned transition; its parent may contain a refreshed ETag.
    RetryIdentically(ScopeHeadTransition),
    /// No safe commit or retry conclusion was proven; do not retry blindly.
    Unresolved(ScopeHeadTransition),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScopeAppendError {
    Publication(ScopeEventPublicationError),
    InvalidInput,
}

impl fmt::Display for ScopeAppendError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Publication(_) => "scope event publication failed",
            Self::InvalidInput => "scope head transition is invalid",
        })
    }
}

impl Error for ScopeAppendError {}

/// One batch member's envelope, reference, and canonical bytes, viewed uniformly whether the
/// event awaits publication or is already resolved, so the pre-PUT preflight and the transition
/// constructor cannot drift apart in what they accept.
struct BatchEventView<'a> {
    envelope: &'a EventEnvelope,
    reference: &'a ScopeEventRef,
    bytes: &'a [u8],
}

impl<'a> BatchEventView<'a> {
    fn of_publication(event: &'a ResolvedScopeEventPublication) -> Self {
        Self {
            envelope: event.envelope(),
            reference: event.event_ref(),
            bytes: event.canonical_bytes(),
        }
    }

    fn of_encoded(pair: &'a (EventEnvelope, EncodedScopeEvent)) -> Self {
        Self {
            envelope: &pair.0,
            reference: pair.1.event_ref(),
            bytes: pair.1.stored_bytes(),
        }
    }
}

/// The batch-internal chain rules, shared by the pre-publication preflight and the transition
/// constructor so a doomed batch is refused before any byte is published and re-proven after.
///
/// An existing parent requires one contiguous chain rooted at the observed tail: every member
/// in the parent's scope at the parent's epoch, gapless sequences within the replay ceiling,
/// each `parent_event` naming its predecessor, operation IDs pairwise distinct and distinct
/// from the parent head's (so the final operation cannot be confused with the unchanged parent
/// during lost-CAS resolution), and the active plan folded left-to-right through the one
/// transition rule. Genesis stays a one-event transition: the first head names exactly one
/// root event, so a wider batch has no parent boundary to chain from.
///
/// `validate_batch_chain` checks operation-ID distinctness within the batch and against the
/// parent head only; replay and projection apply refuse collisions with older retained
/// operations.
///
/// Returns the active-plan digest the candidate head must carry.
///
/// # Errors
///
/// Returns [`WireError::InvalidValue`] for an empty batch or any violated rule, and plan
/// payload decode errors verbatim.
fn validate_batch_chain(
    parent: &ScopeHeadParent,
    events: &[BatchEventView<'_>],
) -> Result<Option<Digest>, WireError> {
    // Reject empty batches because an Existing parent would otherwise return its active-plan
    // digest untouched below.
    let Some(first) = events.first() else {
        return Err(WireError::InvalidValue);
    };
    let observed = match parent {
        ScopeHeadParent::Genesis => {
            if events.len() != 1
                || first.envelope.sequence() != 1
                || first.envelope.parent_event().is_some()
            {
                return Err(WireError::InvalidValue);
            }
            return Ok(None);
        }
        ScopeHeadParent::Existing(observed) => observed,
    };
    let head = observed.head();
    let mut expected_sequence = head
        .tail()
        .sequence()
        .checked_add(1)
        .ok_or(WireError::InvalidValue)?;
    let mut expected_parent = head.tail();
    let mut operations: HashSet<&str> = HashSet::with_capacity(events.len());
    let mut active_plan = head.active_plan_digest().cloned();
    for event in events {
        if event.envelope.sequence() != expected_sequence
            || event.envelope.parent_event() != Some(expected_parent)
            || event.envelope.sequence() > crate::sync::replay::MAX_SCOPE_REPLAY_EVENTS
            || event.envelope.scope_id() != head.scope().scope_id()
            || event.envelope.writer_epoch() != head.scope_epoch()
            || event.envelope.operation_id() == head.operation_id()
        {
            return Err(WireError::InvalidValue);
        }
        if !operations.insert(event.envelope.operation_id()) {
            return Err(WireError::InvalidValue);
        }
        active_plan = next_active_plan_digest(active_plan, head.scope(), event)?;
        expected_sequence = event
            .envelope
            .sequence()
            .checked_add(1)
            .ok_or(WireError::InvalidValue)?;
        expected_parent = event.reference;
    }
    Ok(active_plan)
}

/// The one rule for how an event may move a head's active plan.
///
/// A `plan_admitted` event moves it from none to exactly the digest its own payload names; every
/// other event preserves it. The payload is re-decoded from the published bytes, so the head
/// cannot disagree with the event that authorized it, and a second admission is refused because
/// the digest is already occupied.
///
/// # Errors
///
/// Returns [`WireError::InvalidValue`] for any other movement, and decode errors verbatim.
fn next_active_plan_digest(
    current: Option<Digest>,
    scope: &ScopeIdentity,
    event: &BatchEventView<'_>,
) -> Result<Option<Digest>, WireError> {
    if event.envelope.payload_type() != PLAN_ADMITTED_PAYLOAD_TYPE {
        return Ok(current);
    }
    if current.is_some() {
        return Err(WireError::InvalidValue);
    }
    let key = scope_event_key(scope, event.reference);
    let admitted = decode_plan_admitted_event(event.bytes, &key, scope)?;
    Ok(Some(admitted.payload().plan_digest().clone()))
}

/// Publishes the plan object and its admission event, then commits the head that activates it.
///
/// The plan object is published first: an event that names an address must never win the head
/// race while that address is unreadable. Objects a failed attempt leaves behind are immutable
/// and reusable.
///
/// # Errors
///
/// Returns [`ScopeAppendError::InvalidInput`] for a genesis parent, a parent that already has an
/// active plan, a cross-scope proposal, an unrepresentable operation identity or sequence, or an
/// invalid transition, and publication errors verbatim.
pub async fn append_plan_admitted(
    store: &S3Store,
    parent: ScopeHeadParent,
    scope: &ScopeIdentity,
    admissible: &AdmissibleProposal,
    operation_id: &str,
    histories: [&mut AttemptHistory; 3],
) -> Result<ScopeHeadCommitOutcome, ScopeAppendError> {
    let [plan_history, event_history, head_history] = histories;
    let ScopeHeadParent::Existing(observed) = &parent else {
        // Admission always succeeds a genesis head, so there is a parent to fence against.
        return Err(ScopeAppendError::InvalidInput);
    };
    // Same pre-publication trick as `append_root`: refuse a doomed attempt before it writes
    // immutable objects. `ScopeHeadTransition::new` re-proves the plan rule after publication.
    if admissible.scope_id() != scope.scope_id() || observed.head().active_plan_digest().is_some() {
        return Err(ScopeAppendError::InvalidInput);
    }
    // Every envelope binding is derived from the fenced parent, so a caller cannot contradict it.
    let sequence = next_sequence(observed)?;
    let event = PlanAdmittedEvent::new(
        EventEnvelope::new(
            scope.scope_id().clone(),
            sequence,
            Some(observed.head().tail().clone()),
            observed.head().scope_epoch().get(),
            operation_id.to_owned(),
            PLAN_ADMITTED_PAYLOAD_TYPE.to_owned(),
        )
        .map_err(|_| ScopeAppendError::InvalidInput)?,
        crate::scope::PlanAdmittedPayload::new(admissible.plan_digest().clone()),
    )
    .map_err(|_| ScopeAppendError::InvalidInput)?;
    let event = &event;
    let (authority, scope_epoch) = (
        observed.head().authority().clone(),
        observed.head().scope_epoch().get(),
    );
    let plan_digest = admissible.plan_digest().clone();
    let plan_key = plan_key(scope.workspace_id(), scope.campaign_id(), &plan_digest);
    store
        .publish_with_history(
            &plan_key,
            admissible.stored_bytes().to_vec(),
            plan_digest.as_str(),
            plan_history,
        )
        .await
        .map_err(|error| {
            ScopeAppendError::Publication(ScopeEventPublicationError::Storage(error))
        })?;
    let encoded = encode_plan_admitted_event(event)
        .map_err(ScopeEventPublicationError::Invalid)
        .map_err(ScopeAppendError::Publication)?;
    let publication = publish_encoded(store, scope, event.envelope(), encoded, event_history)
        .await
        .map_err(ScopeAppendError::Publication)?;
    let candidate = ScopeHead::new(
        scope.clone(),
        authority,
        scope_epoch,
        publication.event_ref().clone(),
        Some(plan_digest),
        event.envelope().operation_id().to_owned(),
    )
    .map_err(|_| ScopeAppendError::InvalidInput)?;
    let transition = ScopeHeadTransition::new(parent, candidate, publication)
        .map_err(|_| ScopeAppendError::InvalidInput)?;
    Ok(commit(store, transition, head_history).await)
}

/// Bindings of one published scope event, returned beside the commit outcome so the appender
/// can fold the same event into its local projection without reading it back.
pub(crate) struct ScopeEventAppend {
    pub(crate) outcome: ScopeHeadCommitOutcome,
    pub(crate) envelope: EventEnvelope,
    pub(crate) reference: crate::scope::ScopeEventRef,
}

/// Binds one envelope to the head it succeeds.
///
/// Every binding is read out of the fenced parent rather than taken as an argument, so a caller
/// cannot hand over a scope, sequence, or epoch that contradicts the head it is appending to.
///
/// # Errors
///
/// Returns [`ScopeAppendError::InvalidInput`] for a genesis parent, an unrepresentable operation
/// identity, or a sequence past what one refresh replays.
fn succeeding_envelope(
    parent: &ScopeHeadParent,
    operation_id: &str,
    payload_type: &str,
) -> Result<EventEnvelope, ScopeAppendError> {
    let ScopeHeadParent::Existing(observed) = parent else {
        // A successor always fences against an owned head, so there is a parent to bind to.
        return Err(ScopeAppendError::InvalidInput);
    };
    EventEnvelope::new(
        observed.head().scope().scope_id().clone(),
        next_sequence(observed)?,
        Some(observed.head().tail().clone()),
        observed.head().scope_epoch().get(),
        operation_id.to_owned(),
        payload_type.to_owned(),
    )
    .map_err(|_| ScopeAppendError::InvalidInput)
}

/// Publishes one event that succeeds a fenced parent and commits the head that appends it.
///
/// The candidate head keeps the parent's authority, epoch, and active plan, moving only the tail
/// and operation identity. That invariant lives here rather than at each append so a new event
/// type cannot quietly move a column the parent owns. `append_plan_admitted` is the one append
/// that does not route through this, because admission is exactly the case where the candidate's
/// active plan is *not* the parent's.
///
/// # Errors
///
/// Returns [`ScopeAppendError::InvalidInput`] for a genesis parent or an invalid head or
/// transition, and publication errors verbatim.
async fn publish_succeeding_event(
    store: &S3Store,
    parent: ScopeHeadParent,
    envelope: &EventEnvelope,
    encoded: EncodedScopeEvent,
    event_history: &mut AttemptHistory,
    head_history: &mut AttemptHistory,
) -> Result<ScopeEventAppend, ScopeAppendError> {
    let ScopeHeadParent::Existing(observed) = &parent else {
        return Err(ScopeAppendError::InvalidInput);
    };
    let scope = observed.head().scope().clone();
    let authority = observed.head().authority().clone();
    let scope_epoch = observed.head().scope_epoch().get();
    let active_plan = observed.head().active_plan_digest().cloned();
    let publication = publish_encoded(store, &scope, envelope, encoded, event_history)
        .await
        .map_err(ScopeAppendError::Publication)?;
    let candidate = ScopeHead::new(
        scope,
        authority,
        scope_epoch,
        publication.event_ref().clone(),
        active_plan,
        envelope.operation_id().to_owned(),
    )
    .map_err(|_| ScopeAppendError::InvalidInput)?;
    let reference = publication.event_ref().clone();
    let transition = ScopeHeadTransition::new(parent, candidate, publication)
        .map_err(|_| ScopeAppendError::InvalidInput)?;
    Ok(ScopeEventAppend {
        outcome: commit(store, transition, head_history).await,
        envelope: envelope.clone(),
        reference,
    })
}

/// Publishes the grant-activation event and commits the head that appends it.
///
/// The grant object itself is already published by the issuer; this appends only the durable
/// activation fact. Each activation permanently spends one of the 4,096 lifetime replay events;
/// replay's `Overflow` bound is the check.
///
/// # Errors
///
/// Returns [`ScopeAppendError::InvalidInput`] for a genesis parent, an unrepresentable sequence,
/// an invalid envelope or payload binding, or an invalid transition, and publication errors
/// verbatim.
pub(crate) async fn append_grant_activated(
    store: &S3Store,
    parent: ScopeHeadParent,
    payload: &GrantActivatedPayload,
    operation_id: &str,
    event_history: &mut AttemptHistory,
    head_history: &mut AttemptHistory,
) -> Result<ScopeEventAppend, ScopeAppendError> {
    let event = GrantActivatedEvent::new(
        succeeding_envelope(&parent, operation_id, GRANT_ACTIVATED_PAYLOAD_TYPE)?,
        payload.clone(),
    )
    .map_err(|_| ScopeAppendError::InvalidInput)?;
    let encoded = encode_grant_activated_event(&event)
        .map_err(ScopeEventPublicationError::Invalid)
        .map_err(ScopeAppendError::Publication)?;
    publish_succeeding_event(
        store,
        parent,
        event.envelope(),
        encoded,
        event_history,
        head_history,
    )
    .await
}

/// What one artifact-reference append admits.
///
/// The witness is the proof `publish` returned, the binding is the same value the manifest
/// and trace bodies carry, and `record_bytes` are the exact bytes the witness proves were
/// published — handed over again so the append can decode them as the declared kind instead
/// of trusting the caller's word that they are one.
pub(crate) struct ArtifactAdmission<'a> {
    pub(crate) kind: ArtifactKind,
    pub(crate) witness: &'a PublishedArtifact,
    pub(crate) binding: &'a InvocationBinding,
    pub(crate) record_bytes: &'a [u8],
    pub(crate) operation_id: &'a str,
}

/// Publishes the artifact-reference event and commits the head that admits one artifact.
///
/// This is the only place a reference is minted, and it is where the witness gate lives: the
/// caller must hand over the [`PublishedArtifact`] that `publish` returned, and its namespace
/// must be the store this append writes to. A digest key is identical in every bucket, so a
/// witness from one store proves nothing about another, and without that check a reference
/// could name bytes this scope's store has never held.
///
/// The event's attribution is read out of `binding`, the same value the manifest and trace
/// bodies carry, so an event and the record it admits cannot disagree about which attempt
/// produced the blob.
///
/// # Errors
///
/// Returns [`ScopeAppendError::InvalidInput`] for a witness whose namespace, media type, or
/// producer attempt disagrees with what the event would claim, record bytes that are not the
/// witnessed blob or do not decode as the declared kind, a record whose binding is not the one
/// being admitted, a binding whose scope or plan is not the fenced parent's, an operation id
/// the envelope or the head refuses, a missing parent head, an out-of-range binding, or a
/// sequence past what one refresh replays, and [`ScopeAppendError::Publication`] when event
/// bytes cannot be published.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "only tests call this; `expect` (not `allow`) flags this attribute for \
                  removal if a non-test caller is added"
    )
)]
pub(crate) async fn append_artifact_reference(
    store: &S3Store,
    parent: ScopeHeadParent,
    admission: ArtifactAdmission<'_>,
    event_history: &mut AttemptHistory,
    head_history: &mut AttemptHistory,
) -> Result<ScopeEventAppend, ScopeAppendError> {
    let ArtifactAdmission {
        kind,
        witness,
        binding,
        record_bytes,
        operation_id,
    } = admission;
    if witness.namespace() != store.namespace()
        || witness.artifact_ref().media_type() != kind.media_type()
        || witness.artifact_ref().producer_attempt() != binding.producer_attempt()
    {
        // The payload restates the blob's kind and attempt in event bytes that can never be
        // rewritten, so a witness that disagrees with either would make the two records of the
        // same fact permanently contradict each other with no way to tell which is right.
        return Err(ScopeAppendError::InvalidInput);
    }
    let ScopeHeadParent::Existing(observed) = &parent else {
        // An artifact is drawn under an admitted plan, so there is always history to fence
        // against; a genesis parent means the caller is admitting into the wrong scope.
        return Err(ScopeAppendError::InvalidInput);
    };
    if binding.scope_id() != observed.head().scope().scope_id()
        || Some(binding.plan_digest()) != observed.head().active_plan_digest()
    {
        // The payload drops the binding's scope and plan because the envelope and the admitted
        // work row already carry them — which is exactly why they must be proved here: an event
        // published under this head inherits this head's scope, so a binding minted for another
        // scope or plan would be silently re-attributed rather than refused.
        return Err(ScopeAppendError::InvalidInput);
    }
    // The witness proves bytes exist at the digest; only decoding proves they are the record
    // kind the event declares. The digest check pins `record_bytes` to the witnessed blob, and
    // the binding comparison pins the record's own attribution to the one being admitted, so a
    // blob whose immutable body names another scope, plan, work, grant, or attempt is refused
    // before the head CAS.
    let recorded_binding = match kind {
        ArtifactKind::InvocationManifest => {
            decode_manifest(record_bytes, witness.artifact_ref().digest())
                .map_err(|_| ScopeAppendError::InvalidInput)?
                .binding()
                .clone()
        }
        ArtifactKind::InvocationTrace => {
            decode_trace(record_bytes, witness.artifact_ref().digest())
                .map_err(|_| ScopeAppendError::InvalidInput)?
                .binding()
                .clone()
        }
    };
    if &recorded_binding != binding {
        return Err(ScopeAppendError::InvalidInput);
    }
    let payload = ArtifactReferencePayload::new(
        kind,
        witness.artifact_ref().clone(),
        binding.work_id().clone(),
        binding.work_revision().get(),
        binding.grant_digest().clone(),
        binding.attempt().get(),
    )
    .map_err(|_| ScopeAppendError::InvalidInput)?;
    let event = ArtifactReferenceEvent::new(
        succeeding_envelope(&parent, operation_id, ARTIFACT_REFERENCE_PAYLOAD_TYPE)?,
        payload,
    )
    .map_err(|_| ScopeAppendError::InvalidInput)?;
    let encoded = encode_artifact_reference_event(&event)
        .map_err(ScopeEventPublicationError::Invalid)
        .map_err(ScopeAppendError::Publication)?;
    publish_succeeding_event(
        store,
        parent,
        event.envelope(),
        encoded,
        event_history,
        head_history,
    )
    .await
}

/// Publishes the checkpoint-certificate event and commits the head that appends it.
///
/// The snapshot object must already be published: a certificate that names an unreadable
/// address must never win the head race. The candidate head keeps the parent's authority,
/// epoch, and active plan, moving only the tail and operation identity.
///
/// # Errors
///
/// Returns [`ScopeAppendError::InvalidInput`] for a genesis parent, a payload whose
/// covered cursor or active plan disagrees with the fenced parent, an unrepresentable
/// sequence, or an invalid binding, and publication errors verbatim.
pub(crate) async fn append_checkpoint(
    store: &S3Store,
    parent: ScopeHeadParent,
    scope: &ScopeIdentity,
    payload: &ProjectionCheckpointPayload,
    operation_id: &str,
    event_history: &mut AttemptHistory,
    head_history: &mut AttemptHistory,
) -> Result<ScopeHeadCommitOutcome, ScopeAppendError> {
    let ScopeHeadParent::Existing(observed) = &parent else {
        return Err(ScopeAppendError::InvalidInput);
    };
    if payload.covered_sequence() != observed.head().tail().sequence()
        || payload.covered_tail_digest() != observed.head().tail().digest()
        || payload.covered_active_plan_digest() != observed.head().active_plan_digest()
    {
        return Err(ScopeAppendError::InvalidInput);
    }
    let sequence = next_sequence(observed)?;
    let event = ProjectionCheckpointEvent::new(
        EventEnvelope::new(
            scope.scope_id().clone(),
            sequence,
            Some(observed.head().tail().clone()),
            observed.head().scope_epoch().get(),
            operation_id.to_owned(),
            PROJECTION_CHECKPOINT_PAYLOAD_TYPE.to_owned(),
        )
        .map_err(|_| ScopeAppendError::InvalidInput)?,
        payload.clone(),
    )
    .map_err(|_| ScopeAppendError::InvalidInput)?;
    let (authority, scope_epoch) = (
        observed.head().authority().clone(),
        observed.head().scope_epoch().get(),
    );
    let active_plan = observed.head().active_plan_digest().cloned();
    let encoded = encode_projection_checkpoint_event(&event)
        .map_err(ScopeEventPublicationError::Invalid)
        .map_err(ScopeAppendError::Publication)?;
    let publication = publish_encoded(store, scope, event.envelope(), encoded, event_history)
        .await
        .map_err(ScopeAppendError::Publication)?;
    let candidate = ScopeHead::new(
        scope.clone(),
        authority,
        scope_epoch,
        publication.event_ref().clone(),
        active_plan,
        operation_id.to_owned(),
    )
    .map_err(|_| ScopeAppendError::InvalidInput)?;
    let transition = ScopeHeadTransition::new(parent, candidate, publication)
        .map_err(|_| ScopeAppendError::InvalidInput)?;
    Ok(commit(store, transition, head_history).await)
}

/// Publishes an ordered batch of encoded events, then commits the head that appends them all.
///
/// The batch is atomic at the head: every event object is published create-only before the
/// single conditional CAS, so a reader that observes the committed head reaches all of the
/// batch through one contiguous chain, and a failed or losing CAS leaves at worst inert
/// immutable orphans. The whole batch-internal chain is proven before any request, so a
/// chain-invalid batch sends nothing; plan-object proofs — the only pre-publication reads —
/// run only after that proof; and the first publication failure stops the batch before the
/// CAS. The candidate head carries the final event's operation identity, so
/// lost-CAS resolution and reconciliation identify the batch exactly as a single append.
///
/// Events are published sequentially, one create-only PUT at a time. The caller owns
/// batch-size policy: the only enforced bound is the replay ceiling on the final sequence,
/// so a large batch serializes that many PUTs with no intermediate progress signal.
///
/// # Errors
///
/// Returns [`ScopeAppendError::InvalidInput`] for a genesis parent (genesis stays a one-event
/// transition through [`append_root`]), an empty batch, any batch-internal chain violation, a
/// projection-checkpoint member, a grant-activation member, a plan admission whose named plan
/// object is missing, over-limit, fails its digest check, or names a foreign scope, or an
/// invalid transition; a transport failure reading the plan object and publication errors
/// surface verbatim as [`ScopeAppendError::Publication`].
pub async fn append_batch(
    store: &S3Store,
    parent: ScopeHeadParent,
    scope: &ScopeIdentity,
    events: Vec<(EventEnvelope, EncodedScopeEvent)>,
    head_history: &mut AttemptHistory,
) -> Result<ScopeHeadCommitOutcome, ScopeAppendError> {
    let ScopeHeadParent::Existing(observed) = &parent else {
        return Err(ScopeAppendError::InvalidInput);
    };
    // Same pre-publication discipline as the single-event appends, widened to the whole batch:
    // every member must decode consistently and the chain must hold before any object exists.
    // publish_encoded re-validates each member at its own PUT; this pass exists so member N's
    // failure cannot follow members 1..N-1 into the bucket. commentlint: allow(JUDGE)
    for (envelope, encoded) in &events {
        let key = scope_event_key(scope, encoded.event_ref());
        validate_registered(scope, envelope, encoded, &key)
            .map_err(ScopeAppendError::Publication)?;
        // A checkpoint certificate presumes its covered snapshot object is already published — the checkpoint pipeline publishes the snapshot before calling `append_checkpoint` — and a batch caller holds no snapshot bytes, so checkpoint members are refused before any request. commentlint: allow(JUDGE)
        if envelope.payload_type() == PROJECTION_CHECKPOINT_PAYLOAD_TYPE {
            return Err(ScopeAppendError::InvalidInput);
        }
        // A grant activation is replayable only if the projection's admitted-work row folds it
        // (matching work revision, claim fence, and attempt) — mutable projection state that
        // `grants::issue` proves against its fenced projection before appending. No durable
        // object witnesses that proof, so this preflight cannot re-derive it; an unfoldable
        // activation that won the head CAS would poison every replay with
        // `ApplyError::Conflict`. Grant members are therefore refused before any request:
        // activations route through the issuance pipeline. commentlint: allow(JUDGE)
        if envelope.payload_type() == GRANT_ACTIVATED_PAYLOAD_TYPE {
            return Err(ScopeAppendError::InvalidInput);
        }
    }
    let active_plan = {
        let views: Vec<BatchEventView<'_>> =
            events.iter().map(BatchEventView::of_encoded).collect();
        validate_batch_chain(&parent, &views).map_err(|_| ScopeAppendError::InvalidInput)?
    };
    // A plan-admission member must name a readable plan object before the first event PUT: an event that names an address must never win the head race while that address is unreadable (`append_plan_admitted`'s ordering rule). The proof is the same bounded, digest-checked read replay performs. commentlint: allow(JUDGE)
    for (envelope, encoded) in &events {
        if envelope.payload_type() != PLAN_ADMITTED_PAYLOAD_TYPE {
            continue;
        }
        let key = scope_event_key(scope, encoded.event_ref());
        let admitted = decode_plan_admitted_event(encoded.stored_bytes(), &key, scope)
            .map_err(|_| ScopeAppendError::InvalidInput)?;
        let digest = admitted.payload().plan_digest();
        let key = plan_key(scope.workspace_id(), scope.campaign_id(), digest);
        let bytes = match store.get_object(&key, MAX_PLAN_STORED_BYTES).await {
            Ok(GetOutcome::Found { bytes, .. }) => bytes,
            // A missing or over-limit object can never satisfy the admission that names it.
            Ok(GetOutcome::NotFound) | Err(GetError::TooLarge) => {
                return Err(ScopeAppendError::InvalidInput);
            }
            // A transport or response anomaly proves nothing about the batch: it surfaces as
            // the retryable storage failure it is, so a valid batch stays distinguishable from
            // malformed input during an outage. `Unresolved` is the storage layer's word for
            // "the attempt proved nothing".
            Err(GetError::Transport | GetError::MissingETag) => {
                return Err(ScopeAppendError::Publication(
                    ScopeEventPublicationError::Storage(PublicationError::Unresolved),
                ));
            }
        };
        // `plan_key` is workspace+campaign scoped, so a readable, digest-matching plan object can
        // still belong to a sibling scope; mirror `append_plan_admitted`'s cross-scope refusal.
        // Scope is the one admissibility axis the stored bytes leave unbound here: every object
        // at `plan_key` passed `validate_proposal` at issuance, its bases name immutable applied
        // history, and the batch fold re-proves the none-to-Some active-plan rule.
        let proposal = decode_plan(&bytes, digest).map_err(|_| ScopeAppendError::InvalidInput)?;
        if proposal.scope_id() != scope.scope_id() {
            return Err(ScopeAppendError::InvalidInput);
        }
    }
    let (authority, scope_epoch) = (
        observed.head().authority().clone(),
        observed.head().scope_epoch().get(),
    );
    let mut publications = Vec::with_capacity(events.len());
    for (envelope, encoded) in events {
        // Each publication is its own logical dispatch: sharing one history across keys would
        // leak the first object's send uncertainty into the rest.
        let publication = publish_encoded(
            store,
            scope,
            &envelope,
            encoded,
            &mut AttemptHistory::default(),
        )
        .await
        .map_err(ScopeAppendError::Publication)?;
        publications.push(publication);
    }
    // The fallback is unreachable: validate_batch_chain rejects an empty batch.
    let last = publications.last().ok_or(ScopeAppendError::InvalidInput)?;
    let candidate = ScopeHead::new(
        scope.clone(),
        authority,
        scope_epoch,
        last.event_ref().clone(),
        active_plan,
        last.envelope().operation_id().to_owned(),
    )
    .map_err(|_| ScopeAppendError::InvalidInput)?;
    let transition = ScopeHeadTransition::new_batch(parent, candidate, publications)
        .map_err(|_| ScopeAppendError::InvalidInput)?;
    Ok(commit(store, transition, head_history).await)
}

/// The append path validates the next sequence before publishing event bytes, so a scope cannot
/// commit a head past what one refresh replays.
fn next_sequence(observed: &ObservedScopeHead) -> Result<u64, ScopeAppendError> {
    let sequence = observed
        .head()
        .tail()
        .sequence()
        .checked_add(1)
        .ok_or(ScopeAppendError::InvalidInput)?;
    if sequence > crate::sync::replay::MAX_SCOPE_REPLAY_EVENTS {
        return Err(ScopeAppendError::InvalidInput);
    }
    Ok(sequence)
}

/// Publishes immutable event bytes before validating or mutating the head.
///
/// The event's `writer_epoch` must equal the parent head's `scope_epoch`, which is 1 at genesis;
/// a mismatch returns [`ScopeAppendError::InvalidInput`] before any bytes are published. Every
/// remaining binding check runs after publication, so a failure there can leave an unreferenced
/// immutable event.
///
/// # Errors
///
/// Storage ambiguity is preserved as a publication error; transition validation can
/// fail after immutable bytes already exist.
pub async fn append_root(
    store: &S3Store,
    parent: ScopeHeadParent,
    scope: &ScopeIdentity,
    event: &crate::scope::RootEvent,
    event_history: &mut AttemptHistory,
    head_history: &mut AttemptHistory,
) -> Result<ScopeHeadCommitOutcome, ScopeAppendError> {
    let (authority, scope_epoch) = match &parent {
        ScopeHeadParent::Genesis => (ScopeAuthority::Unowned, 1),
        ScopeHeadParent::Existing(observed) => (
            observed.head().authority().clone(),
            observed.head().scope_epoch().get(),
        ),
    };
    // The pre-publication epoch check prevents a mismatched writer epoch from leaving an unreferenced immutable event behind.
    if event.envelope().writer_epoch().get() != scope_epoch {
        return Err(ScopeAppendError::InvalidInput);
    }
    let publication = publish_root(store, scope, event, event_history)
        .await
        .map_err(ScopeAppendError::Publication)?;
    let candidate = ScopeHead::new(
        scope.clone(),
        authority,
        scope_epoch,
        publication.event_ref().clone(),
        None,
        event.envelope().operation_id().to_owned(),
    )
    .map_err(|_| ScopeAppendError::InvalidInput)?;
    let transition = ScopeHeadTransition::new(parent, candidate, publication)
        .map_err(|_| ScopeAppendError::InvalidInput)?;
    Ok(commit(store, transition, head_history).await)
}

/// Reads and validates one scoped head while retaining its ETag and store namespace.
///
/// # Errors
///
/// Returns [`ScopeHeadReadError`] for storage, size-limit, or canonical decoding failures.
pub async fn read(
    store: &S3Store,
    scope: &ScopeIdentity,
) -> Result<Option<ObservedScopeHead>, ScopeHeadReadError> {
    let key = scope_head_key(scope);
    let outcome = store
        .get_object(&key, MAX_HEAD_BYTES)
        .await
        .map_err(|error| match error {
            GetError::TooLarge => ScopeHeadReadError::Invalid(WireError::LimitExceeded),
            other => ScopeHeadReadError::Storage(other),
        })?;
    match outcome {
        GetOutcome::NotFound => Ok(None),
        GetOutcome::Found { bytes, etag } => {
            let head = decode_head(&bytes, &key, scope).map_err(ScopeHeadReadError::Invalid)?;
            Ok(Some(ObservedScopeHead {
                head,
                bytes,
                etag,
                namespace: store.namespace().to_owned(),
            }))
        }
    }
}

/// Conditionally publishes a validated transition and reconciles ambiguous outcomes.
///
/// Event and observed-parent witnesses must come from `store`'s namespace. Namespace
/// mismatch returns [`ScopeHeadCommitOutcome::Unresolved`] without dispatching a write.
pub async fn commit(
    store: &S3Store,
    transition: ScopeHeadTransition,
    history: &mut AttemptHistory,
) -> ScopeHeadCommitOutcome {
    if transition.event.namespace() != store.namespace() {
        return ScopeHeadCommitOutcome::Unresolved(transition);
    }
    if let ScopeHeadParent::Existing(observed) = &transition.parent
        && observed.namespace != store.namespace()
    {
        return ScopeHeadCommitOutcome::Unresolved(transition);
    }
    let key = scope_head_key(transition.candidate.scope());
    let outcome = match &transition.parent {
        ScopeHeadParent::Genesis => {
            store
                .put_if_absent(&key, transition.head_bytes.clone(), history)
                .await
        }
        ScopeHeadParent::Existing(observed) => {
            store
                .put_if_match(&key, transition.head_bytes.clone(), &observed.etag, history)
                .await
        }
    };
    match outcome {
        MutationOutcome::Committed { etag } => {
            // The witness lets the committer chain its next conditional write; a response
            // without a token commits with no witness and the caller rereads if it needs one.
            let observed = etag.map(|etag| {
                Box::new(ObservedScopeHead::proven(
                    transition.candidate,
                    transition.head_bytes,
                    etag,
                    store.namespace().to_owned(),
                ))
            });
            ScopeHeadCommitOutcome::Committed(observed)
        }
        MutationOutcome::ProvenNotSent => ScopeHeadCommitOutcome::RetryIdentically(transition),
        MutationOutcome::Conflict
        | MutationOutcome::PreconditionFailed
        | MutationOutcome::AmbiguousConflict
        | MutationOutcome::Unknown => resolve(store, transition).await,
        MutationOutcome::NotFound | MutationOutcome::TooLarge => {
            ScopeHeadCommitOutcome::Unresolved(transition)
        }
    }
}

async fn resolve(store: &S3Store, mut transition: ScopeHeadTransition) -> ScopeHeadCommitOutcome {
    let current = match read(store, transition.candidate.scope()).await {
        Ok(Some(current)) => current,
        Ok(None) => {
            return match transition.parent {
                ScopeHeadParent::Genesis => ScopeHeadCommitOutcome::RetryIdentically(transition),
                ScopeHeadParent::Existing(_) => ScopeHeadCommitOutcome::Unresolved(transition),
            };
        }
        Err(_) => return ScopeHeadCommitOutcome::Unresolved(transition),
    };

    if current.head.operation_id() == transition.candidate.operation_id() {
        if current.head.tail() != transition.candidate.tail()
            || current.head.active_plan_digest() != transition.candidate.active_plan_digest()
            || current.head.scope_epoch() < transition.candidate.scope_epoch()
        {
            return ScopeHeadCommitOutcome::Unresolved(transition);
        }
        return match read_opaque(
            store,
            transition.candidate.scope(),
            transition.candidate.tail(),
        )
        .await
        {
            Ok(Some((decoded, bytes)))
                if bytes == transition.event.canonical_bytes()
                    && decoded.envelope() == transition.event.envelope() =>
            {
                ScopeHeadCommitOutcome::Committed(Some(Box::new(current)))
            }
            _ => ScopeHeadCommitOutcome::Unresolved(transition),
        };
    }

    let parent_is_current = match &transition.parent {
        ScopeHeadParent::Genesis => false,
        ScopeHeadParent::Existing(parent) => parent.bytes == current.bytes,
    };
    if parent_is_current {
        transition.parent = ScopeHeadParent::existing(Box::new(current));
        return ScopeHeadCommitOutcome::RetryIdentically(transition);
    }
    if let ScopeHeadParent::Existing(parent) = &transition.parent
        && current.head.operation_id() == parent.head.operation_id()
    {
        return ScopeHeadCommitOutcome::Unresolved(transition);
    }

    reconcile(store, transition, current).await
}

async fn reconcile(
    store: &S3Store,
    transition: ScopeHeadTransition,
    current: ObservedScopeHead,
) -> ScopeHeadCommitOutcome {
    let boundary = match &transition.parent {
        ScopeHeadParent::Genesis => None,
        ScopeHeadParent::Existing(parent) => {
            Some((parent.head.tail().clone(), parent.head.scope_epoch()))
        }
    };
    let tail = current.head.tail().clone();
    let hops = match &boundary {
        Some((boundary, _)) if tail.sequence() > boundary.sequence() => {
            tail.sequence() - boundary.sequence()
        }
        Some(_) => return ScopeHeadCommitOutcome::Unresolved(transition),
        None => tail.sequence(),
    };
    if hops > MAX_RECONCILE_HOPS {
        return ScopeHeadCommitOutcome::Unresolved(transition);
    }

    // Packs are hints: only a positive proof is accepted from them, and every other
    // outcome re-runs the serial walk, whose evidence and verdicts stay authoritative.
    let first = boundary
        .as_ref()
        .map_or(1, |(boundary, _)| boundary.sequence().saturating_add(1));
    if let Some(events) =
        accelerator::packed_events(store, transition.candidate.scope(), first, tail.sequence())
            .await
    {
        let checker = ReconcileChecker::new(&transition, &current, boundary.clone());
        match packed_verdict(checker, tail.clone(), hops, events) {
            Some(ReconcileVerdict::CommittedSuperseded) => {
                return ScopeHeadCommitOutcome::CommittedSuperseded;
            }
            Some(ReconcileVerdict::ProvenNotCommitted) => {
                return ScopeHeadCommitOutcome::ProvenNotCommitted;
            }
            Some(ReconcileVerdict::Unresolved) | None => {}
        }
    }

    let mut checker = ReconcileChecker::new(&transition, &current, boundary);
    let mut current_ref = tail;
    for hop in 0..hops {
        let (decoded, bytes) =
            match read_opaque(store, transition.candidate.scope(), &current_ref).await {
                Ok(Some(event)) => event,
                Ok(None) | Err(_) => return ScopeHeadCommitOutcome::Unresolved(transition),
            };
        match checker.check(hop, &current_ref, &decoded, &bytes) {
            ReconcileStep::Continue(parent) => current_ref = parent,
            ReconcileStep::Concluded(ReconcileVerdict::CommittedSuperseded) => {
                return ScopeHeadCommitOutcome::CommittedSuperseded;
            }
            ReconcileStep::Concluded(ReconcileVerdict::ProvenNotCommitted) => {
                return ScopeHeadCommitOutcome::ProvenNotCommitted;
            }
            ReconcileStep::Concluded(ReconcileVerdict::Unresolved) => {
                return ScopeHeadCommitOutcome::Unresolved(transition);
            }
        }
    }
    ScopeHeadCommitOutcome::Unresolved(transition)
}

/// A missing sequence, a rival object at an expected sequence, or a walk that ends short of the boundary returns `None`; the serial walk then decides from authoritative reads. commentlint: allow(JUDGE)
fn packed_verdict(
    mut checker: ReconcileChecker,
    tail: crate::scope::ScopeEventRef,
    hops: u64,
    events: Vec<StoredEvent>,
) -> Option<ReconcileVerdict> {
    let mut by_sequence: std::collections::HashMap<u64, StoredEvent> = events
        .into_iter()
        .map(|event| (event.decoded.event_ref().sequence(), event))
        .collect();
    let mut current_ref = tail;
    for hop in 0..hops {
        let stored = by_sequence.remove(&current_ref.sequence())?;
        if stored.decoded.event_ref() != &current_ref {
            return None;
        }
        match checker.check(hop, &current_ref, &stored.decoded, &stored.bytes) {
            ReconcileStep::Continue(parent) => current_ref = parent,
            ReconcileStep::Concluded(verdict) => return Some(verdict),
        }
    }
    None
}

enum ReconcileVerdict {
    CommittedSuperseded,
    ProvenNotCommitted,
    Unresolved,
}

enum ReconcileStep {
    Continue(crate::scope::ScopeEventRef),
    Concluded(ReconcileVerdict),
}

/// Per-event reconciliation verdict logic shared by pack-provided and serially read
/// events: candidate byte and envelope comparison, registered and root payload checks,
/// the current-head operation check, epoch ordering, the original-parent or genesis
/// boundary, and the hop and byte limits.
struct ReconcileChecker {
    scope: ScopeIdentity,
    candidate_tail: crate::scope::ScopeEventRef,
    candidate_operation: String,
    candidate_bytes: Vec<u8>,
    candidate_envelope: EventEnvelope,
    current_operation: String,
    current_scope_epoch: NonZeroU64,
    boundary: Option<(crate::scope::ScopeEventRef, NonZeroU64)>,
    seen: HashSet<String>,
    total_bytes: usize,
    found: bool,
    child_writer_epoch: Option<NonZeroU64>,
}

impl ReconcileChecker {
    fn new(
        transition: &ScopeHeadTransition,
        current: &ObservedScopeHead,
        boundary: Option<(crate::scope::ScopeEventRef, NonZeroU64)>,
    ) -> Self {
        Self {
            scope: transition.candidate.scope().clone(),
            candidate_tail: transition.candidate.tail().clone(),
            candidate_operation: transition.candidate.operation_id().to_owned(),
            candidate_bytes: transition.event.canonical_bytes().to_vec(),
            candidate_envelope: transition.event.envelope().clone(),
            current_operation: current.head.operation_id().to_owned(),
            current_scope_epoch: current.head.scope_epoch(),
            boundary,
            seen: HashSet::new(),
            total_bytes: 0,
            found: false,
            child_writer_epoch: None,
        }
    }

    fn check(
        &mut self,
        hop: u64,
        current_ref: &crate::scope::ScopeEventRef,
        decoded: &crate::scope::DecodedScopeEvent<ciborium::Value>,
        bytes: &[u8],
    ) -> ReconcileStep {
        let unresolved = ReconcileStep::Concluded(ReconcileVerdict::Unresolved);
        if !self.seen.insert(current_ref.digest().as_str().to_owned()) {
            return unresolved;
        }
        self.total_bytes = match self.total_bytes.checked_add(bytes.len()) {
            Some(total) if total <= MAX_RECONCILE_BYTES => total,
            _ => return unresolved,
        };
        if !payload_registered(decoded.envelope())
            || !root_domain_valid(decoded.envelope())
            || !root_payload_valid(decoded, &self.scope)
        {
            return unresolved;
        }
        if hop == 0 && decoded.envelope().operation_id() != self.current_operation {
            return unresolved;
        }
        let writer_epoch = decoded.envelope().writer_epoch();
        if writer_epoch > self.current_scope_epoch
            || self
                .child_writer_epoch
                .is_some_and(|child| writer_epoch > child)
        {
            return unresolved;
        }
        self.child_writer_epoch = Some(writer_epoch);
        if decoded.envelope().operation_id() == self.candidate_operation {
            if current_ref != &self.candidate_tail
                || bytes != self.candidate_bytes
                || decoded.envelope() != &self.candidate_envelope
            {
                return unresolved;
            }
            self.found = true;
        } else if current_ref == &self.candidate_tail {
            return unresolved;
        }
        let reached = match &self.boundary {
            Some((boundary, _)) => decoded.envelope().parent_event() == Some(boundary),
            None => {
                decoded.envelope().sequence() == 1 && decoded.envelope().parent_event().is_none()
            }
        };
        if reached {
            if let Some((_, boundary_epoch)) = &self.boundary
                && writer_epoch < *boundary_epoch
            {
                return unresolved;
            }
            return ReconcileStep::Concluded(if self.found {
                ReconcileVerdict::CommittedSuperseded
            } else {
                ReconcileVerdict::ProvenNotCommitted
            });
        }
        let Some(parent) = decoded.envelope().parent_event() else {
            return unresolved;
        };
        ReconcileStep::Continue(parent.clone())
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use aws_sdk_s3::{config::Region, primitives::SdkBody};
    use aws_smithy_runtime::client::http::test_util::NeverClient;
    use ciborium::Value;

    use crate::{
        distributed::identity::{InstanceId, WorkspaceId},
        scope::{
            AdmittedCampaignConfig, CampaignId, Digest, EventEnvelope, ScopeEventRef,
            TEST_SUCCESSOR_PAYLOAD_TYPE, encode_scope_event, root_genesis,
        },
        storage::s3::{
            S3Store,
            test_support::{replay_store, response, test_builder},
        },
        sync::event::publish_encoded,
    };

    use super::*;

    fn genesis() -> crate::scope::RootGenesis {
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

    fn never_store(bucket: &'static str) -> S3Store {
        S3Store::new(
            bucket,
            Region::new("us-east-1"),
            test_builder(NeverClient::new()),
        )
    }

    /// One real manifest for `binding`, since the append decodes what it admits.
    fn invocation_manifest(binding: &InvocationBinding) -> crate::invocation::InvocationManifest {
        use crate::provider::{InvocationRequest, ModelProfile, ModelProvider};

        let profile = ModelProfile::new(
            ModelProvider::Bedrock,
            "anthropic.claude-fixture-v1:0".into(),
            "profile-a".into(),
            std::num::NonZeroU32::new(4096).unwrap(),
            Some(250),
            None,
            Vec::new(),
        )
        .unwrap();
        let request = InvocationRequest::new(
            profile,
            "system".into(),
            "prompt".into(),
            std::num::NonZeroU32::new(512).unwrap(),
            "invoke-op-1".into(),
        )
        .unwrap();
        crate::invocation::InvocationManifest::new(binding.clone(), &request, 1_700_000_060_000)
            .unwrap()
    }

    /// A head one artifact append can fence against: the genesis tail with `plan` active.
    fn plan_bearing_head(genesis: &crate::scope::RootGenesis, plan: &Digest) -> ScopeHead {
        ScopeHead::new(
            genesis.identity().clone(),
            genesis.head().authority().clone(),
            genesis.head().scope_epoch().get(),
            genesis.event_ref().clone(),
            Some(plan.clone()),
            genesis.head().operation_id().to_owned(),
        )
        .unwrap()
    }

    /// The whole admitting path, from a witness to a committed head.
    ///
    /// Every other assertion about this path is a refusal, and a refusal is reached before the
    /// payload is built: without this test the payload could name any field of the binding and
    /// nothing would notice. The binding therefore uses a distinct revision, fence and attempt,
    /// so reading the wrong one is a different number rather than the same one.
    #[tokio::test]
    async fn an_admitted_artifact_carries_the_binding_it_was_drawn_under() {
        use crate::{
            domain::work::WorkId,
            invocation::InvocationBinding,
            scope::{ArtifactKind, ScopeId, decode_artifact_reference_event, scope_event_key},
            storage::artifacts::publish,
        };

        let genesis = genesis();
        let plan = Digest::new("11".repeat(32)).unwrap();
        let (store, client) = replay_store(vec![
            response(200, &[], SdkBody::empty()),
            response(
                200,
                &[("etag", "\"parent\"")],
                encode_head(&plan_bearing_head(&genesis, &plan)).unwrap(),
            ),
            response(200, &[], SdkBody::empty()),
            response(200, &[], SdkBody::empty()),
        ]);

        let grant_digest = Digest::new("ab".repeat(32)).unwrap();
        let binding = InvocationBinding::new(
            ScopeId::new(genesis.identity().scope_id().as_str().to_owned()).unwrap(),
            plan.clone(),
            WorkId::new("work-a".into()).unwrap(),
            7,
            3,
            grant_digest.clone(),
            2,
        )
        .unwrap();
        let (body, _) = invocation_manifest(&binding).stored_bytes().unwrap();
        let witness = publish(
            &store,
            body.clone(),
            ArtifactKind::InvocationManifest.media_type().to_owned(),
            binding.producer_attempt(),
            1_700_000_123_456,
            None,
        )
        .await
        .unwrap();
        let parent = ScopeHeadParent::existing(Box::new(
            read(&store, genesis.identity()).await.unwrap().unwrap(),
        ));

        let append = append_artifact_reference(
            &store,
            parent,
            ArtifactAdmission {
                kind: ArtifactKind::InvocationManifest,
                witness: &witness,
                binding: &binding,
                record_bytes: &body,
                operation_id: "artifact-op-1",
            },
            &mut AttemptHistory::default(),
            &mut AttemptHistory::default(),
        )
        .await
        .unwrap();
        assert!(matches!(
            append.outcome,
            ScopeHeadCommitOutcome::Committed(_)
        ));

        // The envelope succeeds the fenced parent under the same authority epoch.
        assert_eq!(append.envelope.sequence(), 2);
        assert_eq!(append.envelope.parent_event(), Some(genesis.event_ref()));
        assert_eq!(append.envelope.writer_epoch(), genesis.head().scope_epoch());
        assert_eq!(append.envelope.operation_id(), "artifact-op-1");

        // The bytes that were written decode to the payload the binding names, field by field.
        let requests = client.actual_requests().collect::<Vec<_>>();
        assert_eq!(requests.len(), 4);
        let event_bytes = requests[2].body().bytes().unwrap().to_vec();
        let event = decode_artifact_reference_event(
            &event_bytes,
            &scope_event_key(genesis.identity(), &append.reference),
            genesis.identity(),
        )
        .unwrap();
        let payload = event.payload();
        assert_eq!(payload.kind(), ArtifactKind::InvocationManifest);
        assert_eq!(payload.work_id(), binding.work_id());
        assert_eq!(payload.work_revision(), binding.work_revision());
        assert_eq!(payload.attempt(), binding.attempt());
        assert_eq!(payload.grant_digest(), &grant_digest);
        assert_eq!(payload.artifact(), witness.artifact_ref());
        assert_eq!(payload.artifact().size(), body.len() as u64);

        // The blob went to its digest key before the event that names it.
        let artifact_uri = requests[0].uri().parse::<http::Uri>().unwrap();
        assert!(
            artifact_uri
                .path()
                .ends_with(witness.artifact_ref().digest())
        );
    }

    /// A witness that describes something other than what the event would claim.
    ///
    /// The three axes are one guard because they share a consequence. A witness proves bytes
    /// exist only in the namespace it was minted against, and a namespace is one constructed
    /// store rather than a bucket name. The kind and the attempt are each recorded twice — once
    /// in the blob's metadata and once in event bytes that can never be rewritten — so a
    /// witness disagreeing with either leaves two permanent records of one fact contradicting
    /// each other with no way to tell which is right.
    ///
    /// Each case differs from the committing case by exactly one field and gets a store that
    /// would carry the append through, so the request count is what proves the refusal: an
    /// accepted witness goes on to write the event and the head. Only the namespace case uses a
    /// second store, because every constructed store has its own namespace by design — which is
    /// also why the other two must publish against the store they are admitted into, or the
    /// namespace check would refuse them first and prove nothing about kind or attempt.
    #[tokio::test]
    async fn an_artifact_witness_that_disagrees_with_the_event_is_refused_before_any_dispatch() {
        use crate::{
            domain::work::WorkId,
            invocation::InvocationBinding,
            scope::{ArtifactKind, ScopeId},
            storage::artifacts::publish,
        };

        let genesis = genesis();
        let plan = Digest::new("11".repeat(32)).unwrap();
        let binding = InvocationBinding::new(
            ScopeId::new(genesis.identity().scope_id().as_str().to_owned()).unwrap(),
            plan.clone(),
            WorkId::new("work-a".into()).unwrap(),
            7,
            3,
            Digest::new("ab".repeat(32)).unwrap(),
            2,
        )
        .unwrap();
        let kind = ArtifactKind::InvocationManifest;
        let (body, _) = invocation_manifest(&binding).stored_bytes().unwrap();

        for (case, elsewhere, media_type, producer_attempt) in [
            (
                "another namespace",
                true,
                kind.media_type(),
                binding.producer_attempt(),
            ),
            (
                "the other kind's media type",
                false,
                ArtifactKind::InvocationTrace.media_type(),
                binding.producer_attempt(),
            ),
            (
                "another attempt",
                false,
                kind.media_type(),
                "attempt-1".to_owned(),
            ),
        ] {
            // Enough responses to commit, so nothing but the mismatch can end the append.
            let (target, client) = replay_store(vec![
                response(
                    200,
                    &[("etag", "\"parent\"")],
                    encode_head(&plan_bearing_head(&genesis, &plan)).unwrap(),
                ),
                response(200, &[], SdkBody::empty()),
                response(200, &[], SdkBody::empty()),
                response(200, &[], SdkBody::empty()),
            ]);
            let parent = ScopeHeadParent::existing(Box::new(
                read(&target, genesis.identity()).await.unwrap().unwrap(),
            ));
            let (other, _) = replay_store(vec![response(200, &[], SdkBody::empty())]);
            let witness = publish(
                if elsewhere { &other } else { &target },
                body.clone(),
                media_type.to_owned(),
                producer_attempt,
                1_700_000_123_456,
                None,
            )
            .await
            .unwrap();

            let refused = append_artifact_reference(
                &target,
                parent,
                ArtifactAdmission {
                    kind,
                    witness: &witness,
                    binding: &binding,
                    record_bytes: &body,
                    operation_id: "artifact-op-2",
                },
                &mut AttemptHistory::default(),
                &mut AttemptHistory::default(),
            )
            .await;
            assert!(
                matches!(refused, Err(ScopeAppendError::InvalidInput)),
                "{case}"
            );
            // The parent read and the blob, and nothing after: neither the event nor the head
            // was written. The namespace case published its blob to the other store.
            assert_eq!(
                client.actual_requests().count(),
                if elsewhere { 1 } else { 2 },
                "{case}"
            );
        }
    }

    /// A binding or record that contradicts what the fenced parent or the blob itself says.
    ///
    /// The witness gate cannot see any of these: each case's witness agrees with the event on
    /// namespace, media type, and producer attempt, so what refuses it is the parent comparison
    /// or the record decode. Every case gets a store that would carry the append through, so
    /// the request count proves the refusal happened before any event or head write.
    #[tokio::test]
    async fn a_binding_or_record_the_parent_or_blob_contradicts_is_refused() {
        use crate::{
            domain::work::WorkId,
            invocation::InvocationBinding,
            scope::{ArtifactKind, ScopeId},
            storage::artifacts::publish,
        };

        let genesis = genesis();
        let plan = Digest::new("11".repeat(32)).unwrap();
        let kind = ArtifactKind::InvocationManifest;
        let binding = |scope: String, plan: &Digest, work: &str| {
            InvocationBinding::new(
                ScopeId::new(scope).unwrap(),
                plan.clone(),
                WorkId::new(work.into()).unwrap(),
                7,
                3,
                Digest::new("ab".repeat(32)).unwrap(),
                2,
            )
            .unwrap()
        };
        let admitted = binding(
            genesis.identity().scope_id().as_str().to_owned(),
            &plan,
            "work-a",
        );
        let manifest_bytes =
            |of: &InvocationBinding| invocation_manifest(of).stored_bytes().unwrap().0;

        let foreign_scope = binding("f".repeat(64), &plan, "work-a");
        let foreign_plan = binding(
            genesis.identity().scope_id().as_str().to_owned(),
            &Digest::new("22".repeat(32)).unwrap(),
            "work-a",
        );
        let other_work = binding(
            genesis.identity().scope_id().as_str().to_owned(),
            &plan,
            "work-b",
        );
        for (case, binding, body) in [
            // The event would publish under the parent's scope, silently re-attributing it.
            (
                "a binding for another scope",
                &foreign_scope,
                manifest_bytes(&foreign_scope),
            ),
            // The plan the binding ran under is not the plan this head holds active.
            (
                "a binding for another plan",
                &foreign_plan,
                manifest_bytes(&foreign_plan),
            ),
            // Bytes the witness proves exist but that decode as no manifest at all.
            (
                "a blob that is not the declared kind",
                &admitted,
                b"a manifest body".to_vec(),
            ),
            // A well-formed manifest whose own body names a different binding.
            (
                "a record naming another binding",
                &admitted,
                manifest_bytes(&other_work),
            ),
        ] {
            let (target, client) = replay_store(vec![
                response(
                    200,
                    &[("etag", "\"parent\"")],
                    encode_head(&plan_bearing_head(&genesis, &plan)).unwrap(),
                ),
                response(200, &[], SdkBody::empty()),
                response(200, &[], SdkBody::empty()),
                response(200, &[], SdkBody::empty()),
            ]);
            let parent = ScopeHeadParent::existing(Box::new(
                read(&target, genesis.identity()).await.unwrap().unwrap(),
            ));
            let witness = publish(
                &target,
                body.clone(),
                kind.media_type().to_owned(),
                binding.producer_attempt(),
                1_700_000_123_456,
                None,
            )
            .await
            .unwrap();

            let refused = append_artifact_reference(
                &target,
                parent,
                ArtifactAdmission {
                    kind,
                    witness: &witness,
                    binding,
                    record_bytes: &body,
                    operation_id: "artifact-op-2",
                },
                &mut AttemptHistory::default(),
                &mut AttemptHistory::default(),
            )
            .await;
            assert!(
                matches!(refused, Err(ScopeAppendError::InvalidInput)),
                "{case}"
            );
            // The parent read and the blob, and nothing after: neither the event nor the head
            // was written.
            assert_eq!(client.actual_requests().count(), 2, "{case}");
        }
    }

    async fn observed(head: &ScopeHead) -> ObservedScopeHead {
        let (store, _) = replay_store(vec![response(
            200,
            &[("etag", "\"parent\"")],
            encode_head(head).unwrap(),
        )]);
        read(&store, head.scope()).await.unwrap().unwrap()
    }

    async fn published(
        scope: &ScopeIdentity,
        envelope: &EventEnvelope,
        encoded: crate::scope::EncodedScopeEvent,
    ) -> ResolvedScopeEventPublication {
        let (store, _) = replay_store(vec![response(200, &[], SdkBody::empty())]);
        publish_encoded(
            &store,
            scope,
            envelope,
            encoded,
            &mut AttemptHistory::default(),
        )
        .await
        .unwrap()
    }

    /// Uses one store because batch publications must share a namespace: every constructed
    /// store mints a fresh one, and per-event stores would trip the constructor's
    /// namespace-agreement check before the rule a test actually targets.
    async fn published_batch(
        scope: &ScopeIdentity,
        pairs: Vec<(EventEnvelope, crate::scope::EncodedScopeEvent)>,
    ) -> Vec<ResolvedScopeEventPublication> {
        let responses = pairs
            .iter()
            .map(|_| response(200, &[], SdkBody::empty()))
            .collect();
        let (store, _) = replay_store(responses);
        let mut publications = Vec::with_capacity(pairs.len());
        for (envelope, encoded) in pairs {
            publications.push(
                publish_encoded(
                    &store,
                    scope,
                    &envelope,
                    encoded,
                    &mut AttemptHistory::default(),
                )
                .await
                .unwrap(),
            );
        }
        publications
    }

    fn successor(
        scope: &ScopeIdentity,
        parent: &ScopeEventRef,
        sequence: u64,
        operation: &str,
    ) -> (EventEnvelope, crate::scope::EncodedScopeEvent) {
        successor_at(scope, parent, sequence, operation, 1)
    }

    fn successor_at(
        scope: &ScopeIdentity,
        parent: &ScopeEventRef,
        sequence: u64,
        operation: &str,
        writer_epoch: u64,
    ) -> (EventEnvelope, crate::scope::EncodedScopeEvent) {
        let envelope = EventEnvelope::new(
            scope.scope_id().clone(),
            sequence,
            Some(parent.clone()),
            writer_epoch,
            operation.into(),
            TEST_SUCCESSOR_PAYLOAD_TYPE.into(),
        )
        .unwrap();
        let encoded = encode_scope_event(&envelope, &Value::Null).unwrap();
        (envelope, encoded)
    }

    fn owned_parent(genesis: &crate::scope::RootGenesis, owner: &str, epoch: u64) -> ScopeHead {
        ScopeHead::new(
            genesis.identity().clone(),
            ScopeAuthority::owned(InstanceId::new(owner.into()).unwrap(), 1_700_000_030_000)
                .unwrap(),
            epoch,
            genesis.event_ref().clone(),
            None,
            genesis.head().operation_id().to_owned(),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn append_root_publishes_event_before_creating_head() {
        let genesis = genesis();
        let root = crate::scope::decode_root_event(
            genesis.event_bytes(),
            genesis.event_key(),
            genesis.identity(),
        )
        .unwrap();
        let (store, client) = replay_store(vec![
            response(200, &[], SdkBody::empty()),
            response(200, &[], SdkBody::empty()),
        ]);
        assert!(matches!(
            append_root(
                &store,
                ScopeHeadParent::Genesis,
                genesis.identity(),
                &root,
                &mut AttemptHistory::default(),
                &mut AttemptHistory::default(),
            )
            .await
            .unwrap(),
            ScopeHeadCommitOutcome::Committed(_)
        ));
        let requests = client.actual_requests().collect::<Vec<_>>();
        assert_eq!(requests.len(), 2);
        let event_uri = requests[0].uri().parse::<http::Uri>().unwrap();
        let head_uri = requests[1].uri().parse::<http::Uri>().unwrap();
        assert!(event_uri.path().contains("/events/"));
        assert!(head_uri.path().ends_with("/head"));
        assert_eq!(requests[0].headers().get("if-none-match").unwrap(), "*");
        assert_eq!(requests[1].headers().get("if-none-match").unwrap(), "*");
    }

    #[tokio::test]
    async fn successor_uses_observed_etag_and_parent_refresh_allows_identical_retry() {
        let genesis = genesis();
        let parent = genesis.head().clone();
        let (envelope, encoded) =
            successor(genesis.identity(), genesis.event_ref(), 2, "successor-op");
        let event_ref = encoded.event_ref().clone();
        let publication = published(genesis.identity(), &envelope, encoded).await;
        let candidate = ScopeHead::new(
            genesis.identity().clone(),
            ScopeAuthority::Unowned,
            1,
            event_ref,
            None,
            "successor-op".into(),
        )
        .unwrap();
        let transition = ScopeHeadTransition::new(
            ScopeHeadParent::existing(Box::new(observed(&parent).await)),
            candidate,
            publication,
        )
        .unwrap();
        let (store, client) = replay_store(vec![response(200, &[], SdkBody::empty())]);
        assert!(matches!(
            commit(
                &store,
                transition.attributed_to(store.namespace()),
                &mut AttemptHistory::default()
            )
            .await,
            ScopeHeadCommitOutcome::Committed(_)
        ));
        assert_eq!(
            client
                .actual_requests()
                .next()
                .unwrap()
                .headers()
                .get("if-match")
                .unwrap(),
            "\"parent\""
        );

        let (envelope, encoded) = successor(genesis.identity(), genesis.event_ref(), 2, "retry-op");
        let event_ref = encoded.event_ref().clone();
        let publication = published(genesis.identity(), &envelope, encoded).await;
        let candidate = ScopeHead::new(
            genesis.identity().clone(),
            ScopeAuthority::Unowned,
            1,
            event_ref,
            None,
            "retry-op".into(),
        )
        .unwrap();
        let transition = ScopeHeadTransition::new(
            ScopeHeadParent::existing(Box::new(observed(&parent).await)),
            candidate,
            publication,
        )
        .unwrap();
        let (store, _) = replay_store(vec![
            response(412, &[], SdkBody::empty()),
            response(200, &[("etag", "\"fresh\"")], encode_head(&parent).unwrap()),
        ]);
        assert!(matches!(
            commit(
                &store,
                transition.attributed_to(store.namespace()),
                &mut AttemptHistory::default()
            )
            .await,
            ScopeHeadCommitOutcome::RetryIdentically(_)
        ));
    }

    #[tokio::test]
    async fn cross_namespace_witnesses_never_dispatch_head_mutations() {
        let genesis = genesis();
        let root = crate::scope::decode_root_event(
            genesis.event_bytes(),
            genesis.event_key(),
            genesis.identity(),
        )
        .unwrap();
        let publication = published(
            genesis.identity(),
            root.envelope(),
            crate::scope::encode_root_event(&root).unwrap(),
        )
        .await;
        let transition = ScopeHeadTransition::new(
            ScopeHeadParent::Genesis,
            genesis.head().clone(),
            publication,
        )
        .unwrap();
        let foreign = never_store("foreign-event-bucket");
        assert!(matches!(
            tokio::time::timeout(
                Duration::from_millis(20),
                commit(&foreign, transition, &mut AttemptHistory::default())
            )
            .await
            .unwrap(),
            ScopeHeadCommitOutcome::Unresolved(_)
        ));

        let (envelope, encoded) = successor(
            genesis.identity(),
            genesis.event_ref(),
            2,
            "foreign-parent-op",
        );
        let event_ref = encoded.event_ref().clone();
        let foreign = never_store("foreign-parent-bucket");
        let publication = published(genesis.identity(), &envelope, encoded)
            .await
            .attributed_to(foreign.namespace());
        let candidate = ScopeHead::new(
            genesis.identity().clone(),
            ScopeAuthority::Unowned,
            1,
            event_ref,
            None,
            "foreign-parent-op".into(),
        )
        .unwrap();
        let transition = ScopeHeadTransition::new(
            ScopeHeadParent::existing(Box::new(observed(genesis.head()).await)),
            candidate,
            publication,
        )
        .unwrap();
        assert!(matches!(
            tokio::time::timeout(
                Duration::from_millis(20),
                commit(&foreign, transition, &mut AttemptHistory::default())
            )
            .await
            .unwrap(),
            ScopeHeadCommitOutcome::Unresolved(_)
        ));
    }

    #[tokio::test]
    async fn unknown_outcome_requires_exact_candidate_head_and_event() {
        let genesis = genesis();
        for exact_event in [true, false] {
            let (envelope, encoded) =
                successor(genesis.identity(), genesis.event_ref(), 2, "lost-op");
            let event_ref = encoded.event_ref().clone();
            let event_bytes = encoded.stored_bytes().to_vec();
            let publication = published(genesis.identity(), &envelope, encoded).await;
            let candidate = ScopeHead::new(
                genesis.identity().clone(),
                ScopeAuthority::Unowned,
                1,
                event_ref,
                None,
                "lost-op".into(),
            )
            .unwrap();
            let candidate_bytes = encode_head(&candidate).unwrap();
            let transition = ScopeHeadTransition::new(
                ScopeHeadParent::existing(Box::new(observed(genesis.head()).await)),
                candidate,
                publication,
            )
            .unwrap();
            let tail_bytes = if exact_event {
                event_bytes
            } else {
                b"not-a-canonical-event".to_vec()
            };
            let (store, _) = replay_store(vec![
                response(500, &[], SdkBody::empty()),
                response(200, &[("etag", "\"candidate\"")], candidate_bytes),
                response(200, &[("etag", "\"event\"")], tail_bytes),
            ]);
            let outcome = commit(
                &store,
                transition.attributed_to(store.namespace()),
                &mut AttemptHistory::default(),
            )
            .await;
            assert_eq!(
                matches!(outcome, ScopeHeadCommitOutcome::Committed(_)),
                exact_event
            );
            assert_eq!(
                matches!(outcome, ScopeHeadCommitOutcome::Unresolved(_)),
                !exact_event
            );
        }

        let (envelope, encoded) = successor(
            genesis.identity(),
            genesis.event_ref(),
            2,
            "changed-head-op",
        );
        let publication = published(genesis.identity(), &envelope, encoded).await;
        let candidate = ScopeHead::new(
            genesis.identity().clone(),
            ScopeAuthority::Unowned,
            1,
            publication.event_ref().clone(),
            None,
            "changed-head-op".into(),
        )
        .unwrap();
        let transition = ScopeHeadTransition::new(
            ScopeHeadParent::existing(Box::new(observed(genesis.head()).await)),
            candidate,
            publication,
        )
        .unwrap();
        let changed = ScopeHead::new(
            genesis.identity().clone(),
            ScopeAuthority::Unowned,
            1,
            genesis.event_ref().clone(),
            None,
            "changed-head-op".into(),
        )
        .unwrap();
        let (store, _) = replay_store(vec![
            response(500, &[], SdkBody::empty()),
            response(
                200,
                &[("etag", "\"changed\"")],
                encode_head(&changed).unwrap(),
            ),
        ]);
        assert!(matches!(
            commit(
                &store,
                transition.attributed_to(store.namespace()),
                &mut AttemptHistory::default(),
            )
            .await,
            ScopeHeadCommitOutcome::Unresolved(_)
        ));
    }

    #[tokio::test]
    async fn an_authority_only_head_change_still_proves_an_ambiguous_append() {
        let genesis = genesis();
        let parent = ScopeHead::new(
            genesis.identity().clone(),
            ScopeAuthority::Unowned,
            3,
            genesis.event_ref().clone(),
            None,
            genesis.head().operation_id().to_owned(),
        )
        .unwrap();
        for (current_epoch, matching_tail, matching_plan, exact_event, committed) in [
            (4, true, true, true, true),
            (2, true, true, true, false),
            (4, false, true, true, false),
            (4, true, false, true, false),
            (4, true, true, false, false),
        ] {
            let (envelope, encoded) =
                successor_at(genesis.identity(), genesis.event_ref(), 2, "renewed-op", 3);
            let event_ref = encoded.event_ref().clone();
            let event_bytes = encoded.stored_bytes().to_vec();
            let publication = published(genesis.identity(), &envelope, encoded).await;
            let candidate = ScopeHead::new(
                genesis.identity().clone(),
                ScopeAuthority::Unowned,
                3,
                event_ref.clone(),
                None,
                "renewed-op".into(),
            )
            .unwrap();
            let transition = ScopeHeadTransition::new(
                ScopeHeadParent::existing(Box::new(observed(&parent).await)),
                candidate,
                publication,
            )
            .unwrap();
            let current_tail = if matching_tail {
                event_ref
            } else {
                genesis.event_ref().clone()
            };
            let current_plan = if matching_plan {
                None
            } else {
                Some(genesis.config_digest().clone())
            };
            let current = ScopeHead::new(
                genesis.identity().clone(),
                ScopeAuthority::owned(
                    InstanceId::new("controller-a".into()).unwrap(),
                    1_700_000_030_000,
                )
                .unwrap(),
                current_epoch,
                current_tail,
                current_plan,
                "renewed-op".into(),
            )
            .unwrap();
            let mut responses = vec![
                response(500, &[], SdkBody::empty()),
                response(
                    200,
                    &[("etag", "\"renewed\"")],
                    encode_head(&current).unwrap(),
                ),
            ];
            if current_epoch >= 3 && matching_tail && matching_plan {
                responses.push(response(
                    200,
                    &[("etag", "\"event\"")],
                    if exact_event {
                        event_bytes
                    } else {
                        b"not-a-canonical-event".to_vec()
                    },
                ));
            }
            let (store, _) = replay_store(responses);
            let outcome = commit(
                &store,
                transition.attributed_to(store.namespace()),
                &mut AttemptHistory::default(),
            )
            .await;
            assert_eq!(
                matches!(outcome, ScopeHeadCommitOutcome::Committed(_)),
                committed
            );
            assert_eq!(
                matches!(outcome, ScopeHeadCommitOutcome::Unresolved(_)),
                !committed
            );
        }
    }

    #[tokio::test]
    async fn transition_validation_rejects_invalid_bindings() {
        let genesis = genesis();
        let (envelope, encoded) = successor(genesis.identity(), genesis.event_ref(), 2, "valid-op");
        let publication = published(genesis.identity(), &envelope, encoded).await;
        let bad_tail = ScopeHead::new(
            genesis.identity().clone(),
            ScopeAuthority::Unowned,
            1,
            genesis.event_ref().clone(),
            None,
            "valid-op".into(),
        )
        .unwrap();
        assert!(
            ScopeHeadTransition::new(
                ScopeHeadParent::existing(Box::new(observed(genesis.head()).await)),
                bad_tail,
                publication,
            )
            .is_err()
        );

        let (envelope, encoded) = successor(genesis.identity(), genesis.event_ref(), 2, "event-op");
        let publication = published(genesis.identity(), &envelope, encoded).await;
        let wrong_operation = ScopeHead::new(
            genesis.identity().clone(),
            ScopeAuthority::Unowned,
            1,
            publication.event_ref().clone(),
            None,
            "head-op".into(),
        )
        .unwrap();
        assert!(
            ScopeHeadTransition::new(
                ScopeHeadParent::existing(Box::new(observed(genesis.head()).await)),
                wrong_operation,
                publication,
            )
            .is_err()
        );

        let wrong_parent = ScopeEventRef::new(1, Digest::new("c".repeat(64)).unwrap()).unwrap();
        let (envelope, encoded) = successor(genesis.identity(), &wrong_parent, 2, "parent-op");
        let publication = published(genesis.identity(), &envelope, encoded).await;
        let candidate = ScopeHead::new(
            genesis.identity().clone(),
            ScopeAuthority::Unowned,
            1,
            publication.event_ref().clone(),
            None,
            "parent-op".into(),
        )
        .unwrap();
        assert!(
            ScopeHeadTransition::new(
                ScopeHeadParent::existing(Box::new(observed(genesis.head()).await)),
                candidate,
                publication,
            )
            .is_err()
        );

        let other_scope = ScopeIdentity::root(
            WorkspaceId::new("workspace-b".into()).unwrap(),
            CampaignId::new("campaign-b".into()).unwrap(),
        )
        .unwrap();
        let other_parent = ScopeEventRef::new(1, Digest::new("b".repeat(64)).unwrap()).unwrap();
        let (other_envelope, other_encoded) = successor(&other_scope, &other_parent, 2, "scope-op");
        let publication = published(&other_scope, &other_envelope, other_encoded).await;
        let candidate = ScopeHead::new(
            genesis.identity().clone(),
            ScopeAuthority::Unowned,
            1,
            publication.event_ref().clone(),
            None,
            "scope-op".into(),
        )
        .unwrap();
        assert!(
            ScopeHeadTransition::new(
                ScopeHeadParent::existing(Box::new(observed(genesis.head()).await)),
                candidate,
                publication,
            )
            .is_err()
        );

        let (envelope, encoded) = successor(genesis.identity(), genesis.event_ref(), 2, "valid-op");
        let publication = published(genesis.identity(), &envelope, encoded).await;
        let bad_authority = ScopeHead::new(
            genesis.identity().clone(),
            ScopeAuthority::owned(InstanceId::new("controller-a".into()).unwrap(), 1).unwrap(),
            1,
            publication.event_ref().clone(),
            None,
            "valid-op".into(),
        )
        .unwrap();
        assert!(
            ScopeHeadTransition::new(
                ScopeHeadParent::existing(Box::new(observed(genesis.head()).await)),
                bad_authority,
                publication,
            )
            .is_err()
        );

        let (envelope, encoded) = successor(genesis.identity(), genesis.event_ref(), 2, "valid-op");
        let publication = published(genesis.identity(), &envelope, encoded).await;
        let bad_epoch = ScopeHead::new(
            genesis.identity().clone(),
            ScopeAuthority::Unowned,
            2,
            publication.event_ref().clone(),
            None,
            "valid-op".into(),
        )
        .unwrap();
        assert!(
            ScopeHeadTransition::new(
                ScopeHeadParent::existing(Box::new(observed(genesis.head()).await)),
                bad_epoch,
                publication,
            )
            .is_err()
        );

        let epoch_envelope = EventEnvelope::new(
            genesis.identity().scope_id().clone(),
            2,
            Some(genesis.event_ref().clone()),
            2,
            "writer-epoch-op".into(),
            TEST_SUCCESSOR_PAYLOAD_TYPE.into(),
        )
        .unwrap();
        let epoch_encoded = encode_scope_event(&epoch_envelope, &Value::Null).unwrap();
        let epoch_publication = published(genesis.identity(), &epoch_envelope, epoch_encoded).await;
        let epoch_candidate = ScopeHead::new(
            genesis.identity().clone(),
            ScopeAuthority::Unowned,
            1,
            epoch_publication.event_ref().clone(),
            None,
            "writer-epoch-op".into(),
        )
        .unwrap();
        assert!(
            ScopeHeadTransition::new(
                ScopeHeadParent::existing(Box::new(observed(genesis.head()).await)),
                epoch_candidate,
                epoch_publication,
            )
            .is_err()
        );

        let root = crate::scope::decode_root_event(
            genesis.event_bytes(),
            genesis.event_key(),
            genesis.identity(),
        )
        .unwrap();
        let root_publication = published(
            genesis.identity(),
            root.envelope(),
            crate::scope::encode_root_event(&root).unwrap(),
        )
        .await;
        let planned_genesis = ScopeHead::new(
            genesis.identity().clone(),
            ScopeAuthority::Unowned,
            1,
            genesis.event_ref().clone(),
            Some(Digest::new("e".repeat(64)).unwrap()),
            root.envelope().operation_id().into(),
        )
        .unwrap();
        assert!(
            ScopeHeadTransition::new(ScopeHeadParent::Genesis, planned_genesis, root_publication,)
                .is_err()
        );

        let (reused_envelope, reused_encoded) = successor(
            genesis.identity(),
            genesis.event_ref(),
            2,
            genesis.head().operation_id(),
        );
        let reused_publication =
            published(genesis.identity(), &reused_envelope, reused_encoded).await;
        let reused_head = ScopeHead::new(
            genesis.identity().clone(),
            ScopeAuthority::Unowned,
            1,
            reused_publication.event_ref().clone(),
            None,
            genesis.head().operation_id().into(),
        )
        .unwrap();
        assert!(
            ScopeHeadTransition::new(
                ScopeHeadParent::existing(Box::new(observed(genesis.head()).await)),
                reused_head,
                reused_publication,
            )
            .is_err()
        );

        let (envelope, encoded) = successor(genesis.identity(), genesis.event_ref(), 2, "plan-op");
        let publication = published(genesis.identity(), &envelope, encoded).await;
        let bad_plan = ScopeHead::new(
            genesis.identity().clone(),
            ScopeAuthority::Unowned,
            1,
            publication.event_ref().clone(),
            Some(Digest::new("a".repeat(64)).unwrap()),
            "plan-op".into(),
        )
        .unwrap();
        assert!(
            ScopeHeadTransition::new(
                ScopeHeadParent::existing(Box::new(observed(genesis.head()).await)),
                bad_plan,
                publication,
            )
            .is_err()
        );

        let owned_parent = ScopeHead::new(
            genesis.identity().clone(),
            ScopeAuthority::owned(InstanceId::new("controller-a".into()).unwrap(), 1).unwrap(),
            1,
            genesis.event_ref().clone(),
            None,
            genesis.head().operation_id().into(),
        )
        .unwrap();
        let (envelope, encoded) = successor(
            genesis.identity(),
            genesis.event_ref(),
            2,
            "owned-parent-op",
        );
        let publication = published(genesis.identity(), &envelope, encoded).await;
        let candidate = ScopeHead::new(
            genesis.identity().clone(),
            ScopeAuthority::Unowned,
            1,
            publication.event_ref().clone(),
            None,
            "owned-parent-op".into(),
        )
        .unwrap();
        assert!(
            ScopeHeadTransition::new(
                ScopeHeadParent::existing(Box::new(observed(&owned_parent).await)),
                candidate,
                publication,
            )
            .is_err()
        );

        let (envelope, encoded) = successor(
            genesis.identity(),
            genesis.event_ref(),
            2,
            "genesis-invalid",
        );
        let publication = published(genesis.identity(), &envelope, encoded).await;
        let candidate = ScopeHead::new(
            genesis.identity().clone(),
            ScopeAuthority::Unowned,
            1,
            publication.event_ref().clone(),
            None,
            "genesis-invalid".into(),
        )
        .unwrap();
        assert!(
            ScopeHeadTransition::new(ScopeHeadParent::Genesis, candidate, publication,).is_err()
        );
    }

    #[tokio::test]
    async fn retained_chain_proves_candidate_commit_or_noncommit() {
        let genesis = genesis();
        let parent = genesis.head().clone();
        let (candidate_envelope, candidate_encoded) =
            successor(genesis.identity(), genesis.event_ref(), 2, "candidate-op");
        let candidate_ref = candidate_encoded.event_ref().clone();
        let candidate_bytes = candidate_encoded.stored_bytes().to_vec();
        let publication =
            published(genesis.identity(), &candidate_envelope, candidate_encoded).await;
        let candidate_head = ScopeHead::new(
            genesis.identity().clone(),
            ScopeAuthority::Unowned,
            1,
            candidate_ref.clone(),
            None,
            "candidate-op".into(),
        )
        .unwrap();
        let transition = ScopeHeadTransition::new(
            ScopeHeadParent::existing(Box::new(observed(&parent).await)),
            candidate_head,
            publication,
        )
        .unwrap();
        let (later_envelope, later_encoded) =
            successor(genesis.identity(), &candidate_ref, 3, "later-op");
        let later_head = ScopeHead::new(
            genesis.identity().clone(),
            ScopeAuthority::Unowned,
            1,
            later_encoded.event_ref().clone(),
            None,
            "later-op".into(),
        )
        .unwrap();
        let (store, _) = replay_store(vec![
            response(500, &[], SdkBody::empty()),
            response(
                200,
                &[("etag", "\"current\"")],
                encode_head(&later_head).unwrap(),
            ),
            response(404, &[], SdkBody::empty()),
            response(
                200,
                &[("etag", "\"e3\"")],
                later_encoded.stored_bytes().to_vec(),
            ),
            response(200, &[("etag", "\"e2\"")], candidate_bytes),
        ]);
        let _ = later_envelope;
        assert!(matches!(
            commit(
                &store,
                transition.attributed_to(store.namespace()),
                &mut AttemptHistory::default()
            )
            .await,
            ScopeHeadCommitOutcome::CommittedSuperseded
        ));

        let (other_envelope, other_encoded) =
            successor(genesis.identity(), genesis.event_ref(), 2, "other-op");
        let other_head = ScopeHead::new(
            genesis.identity().clone(),
            ScopeAuthority::Unowned,
            1,
            other_encoded.event_ref().clone(),
            None,
            "other-op".into(),
        )
        .unwrap();
        let (candidate_envelope, candidate_encoded) =
            successor(genesis.identity(), genesis.event_ref(), 2, "absent-op");
        let publication =
            published(genesis.identity(), &candidate_envelope, candidate_encoded).await;
        let candidate_head = ScopeHead::new(
            genesis.identity().clone(),
            ScopeAuthority::Unowned,
            1,
            publication.event_ref().clone(),
            None,
            "absent-op".into(),
        )
        .unwrap();
        let transition = ScopeHeadTransition::new(
            ScopeHeadParent::existing(Box::new(observed(&parent).await)),
            candidate_head,
            publication,
        )
        .unwrap();
        let (store, _) = replay_store(vec![
            response(500, &[], SdkBody::empty()),
            response(
                200,
                &[("etag", "\"current\"")],
                encode_head(&other_head).unwrap(),
            ),
            response(404, &[], SdkBody::empty()),
            response(
                200,
                &[("etag", "\"e2\"")],
                other_encoded.stored_bytes().to_vec(),
            ),
        ]);
        let _ = other_envelope;
        assert!(matches!(
            commit(
                &store,
                transition.attributed_to(store.namespace()),
                &mut AttemptHistory::default()
            )
            .await,
            ScopeHeadCommitOutcome::ProvenNotCommitted
        ));
    }

    /// Pack-backed reconciliation reaches the same verdicts as the serial walk, with no
    /// per-event GET at all.
    #[tokio::test]
    async fn packed_reconciliation_proves_the_same_verdicts_without_event_reads() {
        use crate::sync::accelerator::{PackEntry, build_pack, encode_catalog, encode_pointer};

        let genesis = genesis();
        let scope = genesis.identity().clone();
        let parent = genesis.head().clone();

        // Superseded: the candidate committed at sequence 2 and a later event tops it.
        let (candidate_envelope, candidate_encoded) =
            successor(&scope, genesis.event_ref(), 2, "candidate-op");
        let candidate_ref = candidate_encoded.event_ref().clone();
        let candidate_bytes = candidate_encoded.stored_bytes().to_vec();
        let (_, later_encoded) = successor(&scope, &candidate_ref, 3, "later-op");
        let later_head = ScopeHead::new(
            scope.clone(),
            ScopeAuthority::Unowned,
            1,
            later_encoded.event_ref().clone(),
            None,
            "later-op".into(),
        )
        .unwrap();
        let pack = build_pack(
            &scope,
            Some(genesis.event_ref()),
            2,
            &[&candidate_bytes, later_encoded.stored_bytes()],
        )
        .unwrap();
        let entry = PackEntry::new(2, 3, pack.digest().clone()).unwrap();
        let (catalog_bytes, catalog_digest) = encode_catalog(&scope, &[entry], &[]).unwrap();
        let pointer_bytes = encode_pointer(&scope, &catalog_digest).unwrap();
        let publication = published(&scope, &candidate_envelope, candidate_encoded).await;
        let candidate_head = ScopeHead::new(
            scope.clone(),
            ScopeAuthority::Unowned,
            1,
            candidate_ref.clone(),
            None,
            "candidate-op".into(),
        )
        .unwrap();
        let transition = ScopeHeadTransition::new(
            ScopeHeadParent::existing(Box::new(observed(&parent).await)),
            candidate_head,
            publication,
        )
        .unwrap();
        let (store, client) = replay_store(vec![
            response(500, &[], SdkBody::empty()),
            response(
                200,
                &[("etag", "\"current\"")],
                encode_head(&later_head).unwrap(),
            ),
            response(200, &[("etag", "\"pointer\"")], pointer_bytes),
            response(200, &[("etag", "\"catalog\"")], catalog_bytes),
            response(200, &[("etag", "\"pack\"")], pack.bytes().to_vec()),
        ]);
        assert!(matches!(
            commit(
                &store,
                transition.attributed_to(store.namespace()),
                &mut AttemptHistory::default()
            )
            .await,
            ScopeHeadCommitOutcome::CommittedSuperseded
        ));
        let requests: Vec<_> = client.actual_requests().collect();
        assert_eq!(requests.len(), 5);
        assert!(requests.iter().all(|request| {
            !request
                .uri()
                .parse::<http::Uri>()
                .unwrap()
                .path()
                .contains("/events/")
        }));

        // Not committed: a rival occupies sequence 2 and the pack proves the whole chain.
        let (_, other_encoded) = successor(&scope, genesis.event_ref(), 2, "other-op");
        let other_head = ScopeHead::new(
            scope.clone(),
            ScopeAuthority::Unowned,
            1,
            other_encoded.event_ref().clone(),
            None,
            "other-op".into(),
        )
        .unwrap();
        let other_pack = build_pack(
            &scope,
            Some(genesis.event_ref()),
            2,
            &[other_encoded.stored_bytes()],
        )
        .unwrap();
        let entry = PackEntry::new(2, 2, other_pack.digest().clone()).unwrap();
        let (catalog_bytes, catalog_digest) = encode_catalog(&scope, &[entry], &[]).unwrap();
        let pointer_bytes = encode_pointer(&scope, &catalog_digest).unwrap();
        let (absent_envelope, absent_encoded) =
            successor(&scope, genesis.event_ref(), 2, "absent-op");
        let publication = published(&scope, &absent_envelope, absent_encoded).await;
        let candidate_head = ScopeHead::new(
            scope.clone(),
            ScopeAuthority::Unowned,
            1,
            publication.event_ref().clone(),
            None,
            "absent-op".into(),
        )
        .unwrap();
        let transition = ScopeHeadTransition::new(
            ScopeHeadParent::existing(Box::new(observed(&parent).await)),
            candidate_head,
            publication,
        )
        .unwrap();
        let (store, client) = replay_store(vec![
            response(500, &[], SdkBody::empty()),
            response(
                200,
                &[("etag", "\"current\"")],
                encode_head(&other_head).unwrap(),
            ),
            response(200, &[("etag", "\"pointer\"")], pointer_bytes),
            response(200, &[("etag", "\"catalog\"")], catalog_bytes),
            response(200, &[("etag", "\"pack\"")], other_pack.bytes().to_vec()),
        ]);
        assert!(matches!(
            commit(
                &store,
                transition.attributed_to(store.namespace()),
                &mut AttemptHistory::default()
            )
            .await,
            ScopeHeadCommitOutcome::ProvenNotCommitted
        ));
        assert_eq!(client.actual_requests().count(), 5);
    }

    /// A pack holding a rival object at an expected sequence cannot feed the packed
    /// walk; the serial walk decides from authoritative event reads.
    #[tokio::test]
    async fn a_pack_rival_at_an_expected_sequence_falls_through_to_the_serial_walk() {
        use crate::sync::accelerator::{PackEntry, build_pack, encode_catalog, encode_pointer};

        let genesis = genesis();
        let scope = genesis.identity().clone();
        let parent = genesis.head().clone();
        let (candidate_envelope, candidate_encoded) =
            successor(&scope, genesis.event_ref(), 2, "candidate-op");
        let candidate_ref = candidate_encoded.event_ref().clone();
        let candidate_bytes = candidate_encoded.stored_bytes().to_vec();
        let (_, later_encoded) = successor(&scope, &candidate_ref, 3, "later-op");
        let later_head = ScopeHead::new(
            scope.clone(),
            ScopeAuthority::Unowned,
            1,
            later_encoded.event_ref().clone(),
            None,
            "later-op".into(),
        )
        .unwrap();
        // The pack names the covering range but holds a rival at sequence 3.
        let (_, rival_encoded) = successor(&scope, &candidate_ref, 3, "rival-op");
        let rival_pack = build_pack(
            &scope,
            Some(genesis.event_ref()),
            2,
            &[&candidate_bytes, rival_encoded.stored_bytes()],
        )
        .unwrap();
        let entry = PackEntry::new(2, 3, rival_pack.digest().clone()).unwrap();
        let (catalog_bytes, catalog_digest) = encode_catalog(&scope, &[entry], &[]).unwrap();
        let pointer_bytes = encode_pointer(&scope, &catalog_digest).unwrap();
        let publication = published(&scope, &candidate_envelope, candidate_encoded).await;
        let candidate_head = ScopeHead::new(
            scope.clone(),
            ScopeAuthority::Unowned,
            1,
            candidate_ref.clone(),
            None,
            "candidate-op".into(),
        )
        .unwrap();
        let transition = ScopeHeadTransition::new(
            ScopeHeadParent::existing(Box::new(observed(&parent).await)),
            candidate_head,
            publication,
        )
        .unwrap();
        let (store, client) = replay_store(vec![
            response(500, &[], SdkBody::empty()),
            response(
                200,
                &[("etag", "\"current\"")],
                encode_head(&later_head).unwrap(),
            ),
            response(200, &[("etag", "\"pointer\"")], pointer_bytes),
            response(200, &[("etag", "\"catalog\"")], catalog_bytes),
            response(200, &[("etag", "\"pack\"")], rival_pack.bytes().to_vec()),
            response(
                200,
                &[("etag", "\"e3\"")],
                later_encoded.stored_bytes().to_vec(),
            ),
            response(200, &[("etag", "\"e2\"")], candidate_bytes),
        ]);
        assert!(matches!(
            commit(
                &store,
                transition.attributed_to(store.namespace()),
                &mut AttemptHistory::default()
            )
            .await,
            ScopeHeadCommitOutcome::CommittedSuperseded
        ));
        let requests: Vec<_> = client.actual_requests().collect();
        assert_eq!(requests.len(), 7);
        let event_gets = requests
            .iter()
            .filter(|request| {
                request
                    .uri()
                    .parse::<http::Uri>()
                    .unwrap()
                    .path()
                    .contains("/events/")
            })
            .count();
        assert_eq!(
            event_gets, 2,
            "the serial walk must decide from event reads"
        );
    }

    /// Reconciliation from a genesis parent proves a positive verdict through packs at
    /// the genesis boundary with no per-event read.
    #[tokio::test]
    async fn packed_reconciliation_reaches_the_genesis_boundary() {
        use crate::sync::accelerator::{PackEntry, build_pack, encode_catalog, encode_pointer};

        let genesis = genesis();
        let scope = genesis.identity().clone();
        let absent_envelope = EventEnvelope::new(
            scope.scope_id().clone(),
            1,
            None,
            1,
            "absent-root-op".into(),
            TEST_SUCCESSOR_PAYLOAD_TYPE.into(),
        )
        .unwrap();
        let absent_encoded = encode_scope_event(&absent_envelope, &Value::Null).unwrap();
        let publication = published(&scope, &absent_envelope, absent_encoded).await;
        let candidate_head = ScopeHead::new(
            scope.clone(),
            ScopeAuthority::Unowned,
            1,
            publication.event_ref().clone(),
            None,
            "absent-root-op".into(),
        )
        .unwrap();
        let transition =
            ScopeHeadTransition::new(ScopeHeadParent::Genesis, candidate_head, publication)
                .unwrap();
        let pack = build_pack(&scope, None, 1, &[genesis.event_bytes()]).unwrap();
        let entry = PackEntry::new(1, 1, pack.digest().clone()).unwrap();
        let (catalog_bytes, catalog_digest) = encode_catalog(&scope, &[entry], &[]).unwrap();
        let pointer_bytes = encode_pointer(&scope, &catalog_digest).unwrap();
        let (store, client) = replay_store(vec![
            response(500, &[], SdkBody::empty()),
            response(
                200,
                &[("etag", "\"current\"")],
                genesis.head_bytes().to_vec(),
            ),
            response(200, &[("etag", "\"pointer\"")], pointer_bytes),
            response(200, &[("etag", "\"catalog\"")], catalog_bytes),
            response(200, &[("etag", "\"pack\"")], pack.bytes().to_vec()),
        ]);
        assert!(matches!(
            commit(
                &store,
                transition.attributed_to(store.namespace()),
                &mut AttemptHistory::default()
            )
            .await,
            ScopeHeadCommitOutcome::ProvenNotCommitted
        ));
        let requests: Vec<_> = client.actual_requests().collect();
        assert_eq!(requests.len(), 5);
        assert!(requests.iter().all(|request| {
            !request
                .uri()
                .parse::<http::Uri>()
                .unwrap()
                .path()
                .contains("/events/")
        }));
    }

    /// The committed head keeps the fenced parent's active plan and the certificate
    /// payload carries the same binding.
    #[tokio::test]
    async fn append_checkpoint_preserves_the_parent_heads_active_plan() {
        use crate::scope::{
            ProjectionCheckpointPayload, decode_head, decode_projection_checkpoint_event,
            scope_event_key, scope_head_key, sha256,
        };

        let genesis = genesis();
        let scope = genesis.identity().clone();
        let plan = Digest::new("a".repeat(64)).unwrap();
        let parent = ScopeHead::new(
            scope.clone(),
            ScopeAuthority::Unowned,
            1,
            genesis.event_ref().clone(),
            Some(plan.clone()),
            genesis.head().operation_id().to_owned(),
        )
        .unwrap();
        let payload = ProjectionCheckpointPayload::new(
            Digest::new("b".repeat(64)).unwrap(),
            1_024,
            1,
            genesis.event_ref().digest().clone(),
            Some(plan.clone()),
        )
        .unwrap();
        let (store, client) = replay_store(vec![
            response(
                200,
                &[("etag", "\"parent\"")],
                encode_head(&parent).unwrap(),
            ),
            response(200, &[], SdkBody::empty()),
            response(200, &[("etag", "\"committed\"")], SdkBody::empty()),
        ]);
        let observed_parent = read(&store, &scope).await.unwrap().unwrap();
        let outcome = append_checkpoint(
            &store,
            ScopeHeadParent::existing(Box::new(observed_parent)),
            &scope,
            &payload,
            "checkpoint-plan-op",
            &mut AttemptHistory::default(),
            &mut AttemptHistory::default(),
        )
        .await
        .unwrap();
        assert!(matches!(outcome, ScopeHeadCommitOutcome::Committed(_)));
        let requests: Vec<_> = client.actual_requests().collect();
        assert_eq!(requests.len(), 3);
        let event_bytes = requests[1].body().bytes().unwrap().to_vec();
        let reference = ScopeEventRef::new(2, Digest::new(sha256(&event_bytes)).unwrap()).unwrap();
        let certificate = decode_projection_checkpoint_event(
            &event_bytes,
            &scope_event_key(&scope, &reference),
            &scope,
        )
        .unwrap();
        assert_eq!(
            certificate.payload().covered_active_plan_digest(),
            Some(&plan)
        );
        let committed = decode_head(
            requests[2].body().bytes().unwrap(),
            &scope_head_key(&scope),
            &scope,
        )
        .unwrap();
        assert_eq!(committed.active_plan_digest(), Some(&plan));
        assert_eq!(requests[2].headers().get("if-match"), Some("\"parent\""));

        // A payload that drops the parent's plan is refused before any publication.
        let unplanned = ProjectionCheckpointPayload::new(
            Digest::new("b".repeat(64)).unwrap(),
            1_024,
            1,
            genesis.event_ref().digest().clone(),
            None,
        )
        .unwrap();
        let (store, client) = replay_store(vec![]);
        assert!(matches!(
            append_checkpoint(
                &store,
                ScopeHeadParent::existing(Box::new(observed(&parent).await)),
                &scope,
                &unplanned,
                "checkpoint-plan-op-2",
                &mut AttemptHistory::default(),
                &mut AttemptHistory::default(),
            )
            .await,
            Err(ScopeAppendError::InvalidInput)
        ));
        assert_eq!(client.actual_requests().count(), 0);

        // A mismatched covered sequence is rejected before publication even when the
        // covered digest and plan both match.
        let ahead = ProjectionCheckpointPayload::new(
            Digest::new("b".repeat(64)).unwrap(),
            1_024,
            2,
            genesis.event_ref().digest().clone(),
            Some(plan),
        )
        .unwrap();
        let (store, client) = replay_store(vec![]);
        assert!(matches!(
            append_checkpoint(
                &store,
                ScopeHeadParent::existing(Box::new(observed(&parent).await)),
                &scope,
                &ahead,
                "checkpoint-plan-op-3",
                &mut AttemptHistory::default(),
                &mut AttemptHistory::default(),
            )
            .await,
            Err(ScopeAppendError::InvalidInput)
        ));
        assert_eq!(client.actual_requests().count(), 0);
    }

    /// Reconciliation returns `Unresolved` before any accelerator or event read when
    /// the current tail has not advanced past the parent boundary.
    #[tokio::test]
    async fn reconciliation_requires_the_current_tail_past_the_parent_boundary() {
        let genesis = genesis();
        let scope = genesis.identity().clone();
        let parent = genesis.head().clone();
        let (candidate_envelope, candidate_encoded) =
            successor(&scope, genesis.event_ref(), 2, "candidate-op");
        let candidate_ref = candidate_encoded.event_ref().clone();
        let publication = published(&scope, &candidate_envelope, candidate_encoded).await;
        let candidate_head = ScopeHead::new(
            scope.clone(),
            ScopeAuthority::Unowned,
            1,
            candidate_ref,
            None,
            "candidate-op".into(),
        )
        .unwrap();
        let transition = ScopeHeadTransition::new(
            ScopeHeadParent::existing(Box::new(observed(&parent).await)),
            candidate_head,
            publication,
        )
        .unwrap();
        // A rival current head sits at the same sequence as the parent boundary.
        let rival_tail = ScopeEventRef::new(1, Digest::new("c".repeat(64)).unwrap()).unwrap();
        let rival_head = ScopeHead::new(
            scope.clone(),
            ScopeAuthority::Unowned,
            1,
            rival_tail,
            None,
            "rival-op".into(),
        )
        .unwrap();
        // Surplus scripted failures make any request beyond the expected two visible.
        let (store, client) = replay_store(vec![
            response(500, &[], SdkBody::empty()),
            response(
                200,
                &[("etag", "\"current\"")],
                encode_head(&rival_head).unwrap(),
            ),
            response(500, &[], SdkBody::empty()),
            response(500, &[], SdkBody::empty()),
        ]);
        assert!(matches!(
            commit(
                &store,
                transition.attributed_to(store.namespace()),
                &mut AttemptHistory::default()
            )
            .await,
            ScopeHeadCommitOutcome::Unresolved(_)
        ));
        assert_eq!(client.actual_requests().count(), 2);
    }

    /// Reconciliation across a deep suffix counts hops as the exact tail-to-boundary
    /// distance; miscounting either trips the hop cap or stops before the boundary.
    #[tokio::test]
    async fn reconciliation_walks_the_exact_boundary_distance_at_high_sequences() {
        let genesis = genesis();
        let scope = genesis.identity().clone();
        let boundary_ref = ScopeEventRef::new(4_090, Digest::new("d".repeat(64)).unwrap()).unwrap();
        let parent = ScopeHead::new(
            scope.clone(),
            ScopeAuthority::Unowned,
            1,
            boundary_ref.clone(),
            None,
            "parent-op".into(),
        )
        .unwrap();
        // The candidate at 4091 lost the race to a rival chain reaching 4095.
        let (candidate_envelope, candidate_encoded) =
            successor(&scope, &boundary_ref, 4_091, "absent-op");
        let publication = published(&scope, &candidate_envelope, candidate_encoded).await;
        let candidate_head = ScopeHead::new(
            scope.clone(),
            ScopeAuthority::Unowned,
            1,
            publication.event_ref().clone(),
            None,
            "absent-op".into(),
        )
        .unwrap();
        let transition = ScopeHeadTransition::new(
            ScopeHeadParent::existing(Box::new(observed(&parent).await)),
            candidate_head,
            publication,
        )
        .unwrap();
        let mut rivals = Vec::new();
        let mut parent_ref = boundary_ref;
        for sequence in 4_091..=4_095_u64 {
            let (_, encoded) = successor(
                &scope,
                &parent_ref,
                sequence,
                &format!("rival-op-{sequence}"),
            );
            parent_ref = encoded.event_ref().clone();
            rivals.push(encoded);
        }
        let current_head = ScopeHead::new(
            scope.clone(),
            ScopeAuthority::Unowned,
            1,
            parent_ref,
            None,
            "rival-op-4095".into(),
        )
        .unwrap();
        let mut responses = vec![
            response(500, &[], SdkBody::empty()),
            response(
                200,
                &[("etag", "\"current\"")],
                encode_head(&current_head).unwrap(),
            ),
            response(404, &[], SdkBody::empty()),
        ];
        responses.extend(rivals.iter().rev().map(|encoded| {
            response(
                200,
                &[("etag", "\"event\"")],
                encoded.stored_bytes().to_vec(),
            )
        }));
        let (store, client) = replay_store(responses);
        assert!(matches!(
            commit(
                &store,
                transition.attributed_to(store.namespace()),
                &mut AttemptHistory::default()
            )
            .await,
            ScopeHeadCommitOutcome::ProvenNotCommitted
        ));
        // CAS failure, head reread, pointer miss, and one GET per hop back to the
        // boundary.
        assert_eq!(client.actual_requests().count(), 8);
    }

    /// The per-walk checks conclude unresolved on their own: the byte budget, an
    /// unregistered payload, and a displaced candidate reference each end the walk
    /// even when every later check would pass.
    #[tokio::test]
    async fn each_reconcile_walk_check_concludes_unresolved_independently() {
        use crate::scope::{decode_scope_event, encode_scope_event, scope_event_key};

        let genesis = genesis();
        let scope = genesis.identity().clone();
        let parent = genesis.head().clone();
        let (candidate_envelope, candidate_encoded) =
            successor(&scope, genesis.event_ref(), 2, "candidate-op");
        let candidate_ref = candidate_encoded.event_ref().clone();
        let candidate_bytes = candidate_encoded.stored_bytes().to_vec();
        let (_, later_encoded) = successor(&scope, &candidate_ref, 3, "later-op");
        let later_ref = later_encoded.event_ref().clone();
        let later_head = ScopeHead::new(
            scope.clone(),
            ScopeAuthority::Unowned,
            1,
            later_ref.clone(),
            None,
            "later-op".into(),
        )
        .unwrap();
        let publication = published(&scope, &candidate_envelope, candidate_encoded).await;
        let candidate_head = ScopeHead::new(
            scope.clone(),
            ScopeAuthority::Unowned,
            1,
            candidate_ref.clone(),
            None,
            "candidate-op".into(),
        )
        .unwrap();
        let transition = ScopeHeadTransition::new(
            ScopeHeadParent::existing(Box::new(observed(&parent).await)),
            candidate_head,
            publication,
        )
        .unwrap();
        let current = observed(&later_head).await;
        let boundary = Some((genesis.event_ref().clone(), NonZeroU64::new(1).unwrap()));

        // Cumulative bytes past the budget conclude unresolved ahead of every later
        // check.
        let decoded_later: crate::scope::DecodedScopeEvent<ciborium::Value> = decode_scope_event(
            later_encoded.stored_bytes(),
            &scope_event_key(&scope, &later_ref),
            &scope,
            None,
        )
        .unwrap();
        let mut checker = ReconcileChecker::new(&transition, &current, boundary.clone());
        let oversized = vec![0_u8; MAX_RECONCILE_BYTES + 1];
        assert!(matches!(
            checker.check(0, &later_ref, &decoded_later, &oversized),
            ReconcileStep::Concluded(ReconcileVerdict::Unresolved)
        ));

        // An unregistered payload type alone concludes unresolved.
        let bogus_envelope = EventEnvelope::new(
            scope.scope_id().clone(),
            3,
            Some(candidate_ref.clone()),
            1,
            "later-op".into(),
            "unregistered_payload".into(),
        )
        .unwrap();
        let bogus = encode_scope_event(&bogus_envelope, &Value::Null).unwrap();
        let bogus_ref = bogus.event_ref().clone();
        let decoded_bogus: crate::scope::DecodedScopeEvent<ciborium::Value> = decode_scope_event(
            bogus.stored_bytes(),
            &scope_event_key(&scope, &bogus_ref),
            &scope,
            None,
        )
        .unwrap();
        let mut checker = ReconcileChecker::new(&transition, &current, boundary.clone());
        assert!(matches!(
            checker.check(0, &bogus_ref, &decoded_bogus, bogus.stored_bytes()),
            ReconcileStep::Concluded(ReconcileVerdict::Unresolved)
        ));

        // A candidate-operation event whose reference does not name the candidate
        // tail concludes unresolved even when its bytes and envelope both match.
        let displaced = ScopeEventRef::new(9, candidate_ref.digest().clone()).unwrap();
        let decoded_candidate: crate::scope::DecodedScopeEvent<ciborium::Value> =
            decode_scope_event(
                &candidate_bytes,
                &scope_event_key(&scope, &candidate_ref),
                &scope,
                None,
            )
            .unwrap();
        let mut checker = ReconcileChecker::new(&transition, &current, boundary.clone());
        assert!(matches!(
            checker.check(1, &displaced, &decoded_candidate, &candidate_bytes),
            ReconcileStep::Concluded(ReconcileVerdict::Unresolved)
        ));

        // A candidate-operation event whose bytes alone disagree concludes unresolved
        // even when its reference and envelope both match.
        let mut checker = ReconcileChecker::new(&transition, &current, boundary);
        assert!(matches!(
            checker.check(1, &candidate_ref, &decoded_candidate, b"tampered"),
            ReconcileStep::Concluded(ReconcileVerdict::Unresolved)
        ));
    }

    #[tokio::test]
    async fn reconciliation_refuses_a_chain_that_breaks_the_epoch_ordering_rule() {
        let genesis = genesis();
        // An event whose writer epoch exceeds the current head's scope epoch.
        let (candidate_envelope, candidate_encoded) =
            successor(genesis.identity(), genesis.event_ref(), 2, "candidate-op");
        let candidate_ref = candidate_encoded.event_ref().clone();
        let candidate_bytes = candidate_encoded.stored_bytes().to_vec();
        let publication =
            published(genesis.identity(), &candidate_envelope, candidate_encoded).await;
        let candidate_head = ScopeHead::new(
            genesis.identity().clone(),
            ScopeAuthority::Unowned,
            1,
            candidate_ref.clone(),
            None,
            "candidate-op".into(),
        )
        .unwrap();
        let transition = ScopeHeadTransition::new(
            ScopeHeadParent::existing(Box::new(observed(genesis.head()).await)),
            candidate_head,
            publication,
        )
        .unwrap();
        let (_, above_encoded) = successor_at(genesis.identity(), &candidate_ref, 3, "later-op", 3);
        let above_head = ScopeHead::new(
            genesis.identity().clone(),
            ScopeAuthority::Unowned,
            1,
            above_encoded.event_ref().clone(),
            None,
            "later-op".into(),
        )
        .unwrap();
        let (store, _) = replay_store(vec![
            response(500, &[], SdkBody::empty()),
            response(
                200,
                &[("etag", "\"current\"")],
                encode_head(&above_head).unwrap(),
            ),
            response(404, &[], SdkBody::empty()),
            response(
                200,
                &[("etag", "\"e3\"")],
                above_encoded.stored_bytes().to_vec(),
            ),
            response(200, &[("etag", "\"e2\"")], candidate_bytes),
        ]);
        assert!(matches!(
            commit(
                &store,
                transition.attributed_to(store.namespace()),
                &mut AttemptHistory::default()
            )
            .await,
            ScopeHeadCommitOutcome::Unresolved(_)
        ));

        // A writer epoch that decreases from an event to its child.
        let parent = ScopeHead::new(
            genesis.identity().clone(),
            ScopeAuthority::Unowned,
            2,
            genesis.event_ref().clone(),
            None,
            genesis.head().operation_id().to_owned(),
        )
        .unwrap();
        let (candidate_envelope, candidate_encoded) = successor_at(
            genesis.identity(),
            genesis.event_ref(),
            2,
            "candidate-op",
            2,
        );
        let candidate_ref = candidate_encoded.event_ref().clone();
        let candidate_bytes = candidate_encoded.stored_bytes().to_vec();
        let publication =
            published(genesis.identity(), &candidate_envelope, candidate_encoded).await;
        let candidate_head = ScopeHead::new(
            genesis.identity().clone(),
            ScopeAuthority::Unowned,
            2,
            candidate_ref.clone(),
            None,
            "candidate-op".into(),
        )
        .unwrap();
        let transition = ScopeHeadTransition::new(
            ScopeHeadParent::existing(Box::new(observed(&parent).await)),
            candidate_head,
            publication,
        )
        .unwrap();
        let (_, regressed_encoded) =
            successor_at(genesis.identity(), &candidate_ref, 3, "later-op", 1);
        let regressed_head = ScopeHead::new(
            genesis.identity().clone(),
            ScopeAuthority::Unowned,
            2,
            regressed_encoded.event_ref().clone(),
            None,
            "later-op".into(),
        )
        .unwrap();
        let (store, _) = replay_store(vec![
            response(500, &[], SdkBody::empty()),
            response(
                200,
                &[("etag", "\"current\"")],
                encode_head(&regressed_head).unwrap(),
            ),
            response(404, &[], SdkBody::empty()),
            response(
                200,
                &[("etag", "\"e3\"")],
                regressed_encoded.stored_bytes().to_vec(),
            ),
            response(200, &[("etag", "\"e2\"")], candidate_bytes),
        ]);
        assert!(matches!(
            commit(
                &store,
                transition.attributed_to(store.namespace()),
                &mut AttemptHistory::default()
            )
            .await,
            ScopeHeadCommitOutcome::Unresolved(_)
        ));

        let (candidate_envelope, candidate_encoded) = successor_at(
            genesis.identity(),
            genesis.event_ref(),
            2,
            "candidate-op",
            2,
        );
        let publication =
            published(genesis.identity(), &candidate_envelope, candidate_encoded).await;
        let candidate_head = ScopeHead::new(
            genesis.identity().clone(),
            ScopeAuthority::Unowned,
            2,
            publication.event_ref().clone(),
            None,
            "candidate-op".into(),
        )
        .unwrap();
        let transition = ScopeHeadTransition::new(
            ScopeHeadParent::existing(Box::new(observed(&parent).await)),
            candidate_head,
            publication,
        )
        .unwrap();
        let (_, stale_encoded) =
            successor_at(genesis.identity(), genesis.event_ref(), 2, "other-op", 1);
        let stale_head = ScopeHead::new(
            genesis.identity().clone(),
            ScopeAuthority::Unowned,
            2,
            stale_encoded.event_ref().clone(),
            None,
            "other-op".into(),
        )
        .unwrap();
        let (store, _) = replay_store(vec![
            response(500, &[], SdkBody::empty()),
            response(
                200,
                &[("etag", "\"current\"")],
                encode_head(&stale_head).unwrap(),
            ),
            response(404, &[], SdkBody::empty()),
            response(
                200,
                &[("etag", "\"e2\"")],
                stale_encoded.stored_bytes().to_vec(),
            ),
        ]);
        assert!(matches!(
            commit(
                &store,
                transition.attributed_to(store.namespace()),
                &mut AttemptHistory::default()
            )
            .await,
            ScopeHeadCommitOutcome::Unresolved(_)
        ));
    }

    #[tokio::test]
    async fn reconciliation_refuses_an_unsupported_current_head() {
        let genesis = genesis();
        let parent = genesis.head().clone();
        let (_, other_encoded) = successor(genesis.identity(), genesis.event_ref(), 2, "other-op");
        let owned_current = ScopeHead::new(
            genesis.identity().clone(),
            ScopeAuthority::owned(InstanceId::new("controller-a".into()).unwrap(), 1).unwrap(),
            1,
            other_encoded.event_ref().clone(),
            None,
            "other-op".into(),
        )
        .unwrap();
        let (candidate_envelope, candidate_encoded) =
            successor(genesis.identity(), genesis.event_ref(), 2, "absent-op");
        let publication =
            published(genesis.identity(), &candidate_envelope, candidate_encoded).await;
        let candidate_head = ScopeHead::new(
            genesis.identity().clone(),
            ScopeAuthority::Unowned,
            1,
            publication.event_ref().clone(),
            None,
            "absent-op".into(),
        )
        .unwrap();
        let transition = ScopeHeadTransition::new(
            ScopeHeadParent::existing(Box::new(observed(&parent).await)),
            candidate_head,
            publication,
        )
        .unwrap();
        let (store, client) = replay_store(vec![
            response(500, &[], SdkBody::empty()),
            response(
                200,
                &[("etag", "\"current\"")],
                encode_head(&owned_current).unwrap(),
            ),
        ]);
        assert!(matches!(
            commit(
                &store,
                transition.attributed_to(store.namespace()),
                &mut AttemptHistory::default()
            )
            .await,
            ScopeHeadCommitOutcome::Unresolved(_)
        ));
        // The retained walk never starts, so no event read follows the head read.
        assert_eq!(client.actual_requests().count(), 2);
    }

    #[tokio::test]
    async fn reconciliation_refuses_a_current_head_that_mismatches_its_tail() {
        let genesis = genesis();
        let parent = genesis.head().clone();
        let (_, other_encoded) = successor(genesis.identity(), genesis.event_ref(), 2, "other-op");
        let mismatched = ScopeHead::new(
            genesis.identity().clone(),
            ScopeAuthority::Unowned,
            1,
            other_encoded.event_ref().clone(),
            None,
            "mismatched-op".into(),
        )
        .unwrap();
        let (candidate_envelope, candidate_encoded) =
            successor(genesis.identity(), genesis.event_ref(), 2, "absent-op");
        let publication =
            published(genesis.identity(), &candidate_envelope, candidate_encoded).await;
        let candidate_head = ScopeHead::new(
            genesis.identity().clone(),
            ScopeAuthority::Unowned,
            1,
            publication.event_ref().clone(),
            None,
            "absent-op".into(),
        )
        .unwrap();
        let transition = ScopeHeadTransition::new(
            ScopeHeadParent::existing(Box::new(observed(&parent).await)),
            candidate_head,
            publication,
        )
        .unwrap();
        let (store, client) = replay_store(vec![
            response(500, &[], SdkBody::empty()),
            response(
                200,
                &[("etag", "\"current\"")],
                encode_head(&mismatched).unwrap(),
            ),
            response(404, &[], SdkBody::empty()),
            response(
                200,
                &[("etag", "\"e2\"")],
                other_encoded.stored_bytes().to_vec(),
            ),
        ]);
        assert!(matches!(
            commit(
                &store,
                transition.attributed_to(store.namespace()),
                &mut AttemptHistory::default()
            )
            .await,
            ScopeHeadCommitOutcome::Unresolved(_)
        ));
        assert_eq!(client.actual_requests().count(), 4);
    }

    #[tokio::test]
    async fn reconciliation_refuses_an_invalid_retained_root_payload() {
        let genesis = genesis();
        let root = crate::scope::decode_root_event(
            genesis.event_bytes(),
            genesis.event_key(),
            genesis.identity(),
        )
        .unwrap();
        let fake_envelope = EventEnvelope::new(
            genesis.identity().scope_id().clone(),
            1,
            None,
            1,
            "fake-root-op".into(),
            crate::scope::ROOT_GENESIS_PAYLOAD_TYPE.into(),
        )
        .unwrap();
        let fake = encode_scope_event(&fake_envelope, &Value::Null).unwrap();
        let fake_head = ScopeHead::new(
            genesis.identity().clone(),
            ScopeAuthority::Unowned,
            1,
            fake.event_ref().clone(),
            None,
            "fake-root-op".into(),
        )
        .unwrap();
        let (store, client) = replay_store(vec![
            response(200, &[], SdkBody::empty()),
            response(500, &[], SdkBody::empty()),
            response(
                200,
                &[("etag", "\"current\"")],
                encode_head(&fake_head).unwrap(),
            ),
            response(404, &[], SdkBody::empty()),
            response(200, &[("etag", "\"e1\"")], fake.stored_bytes().to_vec()),
        ]);
        assert!(matches!(
            append_root(
                &store,
                ScopeHeadParent::Genesis,
                genesis.identity(),
                &root,
                &mut AttemptHistory::default(),
                &mut AttemptHistory::default(),
            )
            .await
            .unwrap(),
            ScopeHeadCommitOutcome::Unresolved(_)
        ));
        assert_eq!(client.actual_requests().count(), 5);
    }

    #[tokio::test]
    async fn an_owned_successor_carries_the_observed_authority_and_epoch() {
        let genesis = genesis();
        let parent = owned_parent(&genesis, "instance-a", 4);
        let (envelope, encoded) =
            successor_at(genesis.identity(), genesis.event_ref(), 2, "owned-op", 4);
        let event_ref = encoded.event_ref().clone();
        let publication = published(genesis.identity(), &envelope, encoded).await;
        let candidate = ScopeHead::new(
            genesis.identity().clone(),
            parent.authority().clone(),
            4,
            event_ref,
            None,
            "owned-op".into(),
        )
        .unwrap();
        let transition = ScopeHeadTransition::new(
            ScopeHeadParent::existing(Box::new(observed(&parent).await)),
            candidate,
            publication,
        )
        .unwrap();
        let (store, _) = replay_store(vec![response(200, &[], SdkBody::empty())]);
        assert!(matches!(
            commit(
                &store,
                transition.attributed_to(store.namespace()),
                &mut AttemptHistory::default()
            )
            .await,
            ScopeHeadCommitOutcome::Committed(_)
        ));
    }

    #[tokio::test]
    async fn a_candidate_that_moves_ownership_or_epoch_is_refused() {
        let genesis = genesis();
        let successor_owner = InstanceId::new("instance-b".into()).unwrap();
        let parent = owned_parent(&genesis, "instance-a", 4);
        let refused = [
            // A different controller.
            (
                ScopeAuthority::owned(successor_owner, 1_700_000_030_000).unwrap(),
                4,
                4,
            ),
            // An advanced epoch.
            (parent.authority().clone(), 5, 5),
            // A stale writer epoch under the observed epoch.
            (parent.authority().clone(), 4, 3),
            // A relinquished head.
            (ScopeAuthority::Unowned, 4, 4),
        ];
        for (index, (authority, epoch, writer_epoch)) in refused.into_iter().enumerate() {
            let operation = format!("refused-op-{index}");
            let (envelope, encoded) = successor_at(
                genesis.identity(),
                genesis.event_ref(),
                2,
                &operation,
                writer_epoch,
            );
            let event_ref = encoded.event_ref().clone();
            let publication = published(genesis.identity(), &envelope, encoded).await;
            let candidate = ScopeHead::new(
                genesis.identity().clone(),
                authority,
                epoch,
                event_ref,
                None,
                operation,
            )
            .unwrap();
            assert!(
                ScopeHeadTransition::new(
                    ScopeHeadParent::existing(Box::new(observed(&parent).await)),
                    candidate,
                    publication,
                )
                .is_err()
            );
        }
    }

    #[tokio::test]
    async fn a_stale_controller_commit_does_not_replace_a_higher_epoch_head() {
        let genesis = genesis();
        let winner = InstanceId::new("instance-b".into()).unwrap();
        let parent = owned_parent(&genesis, "instance-a", 4);
        let superseding = ScopeHead::new(
            genesis.identity().clone(),
            ScopeAuthority::owned(winner, 1_700_000_060_000).unwrap(),
            5,
            genesis.event_ref().clone(),
            None,
            genesis.head().operation_id().to_owned(),
        )
        .unwrap();
        let (envelope, encoded) =
            successor_at(genesis.identity(), genesis.event_ref(), 2, "stale-op", 4);
        let event_ref = encoded.event_ref().clone();
        let publication = published(genesis.identity(), &envelope, encoded).await;
        let candidate = ScopeHead::new(
            genesis.identity().clone(),
            parent.authority().clone(),
            4,
            event_ref,
            None,
            "stale-op".into(),
        )
        .unwrap();
        let transition = ScopeHeadTransition::new(
            ScopeHeadParent::existing(Box::new(observed(&parent).await)),
            candidate,
            publication,
        )
        .unwrap();
        let (store, client) = replay_store(vec![
            response(412, &[], SdkBody::empty()),
            response(
                200,
                &[("etag", "\"superseding\"")],
                encode_head(&superseding).unwrap(),
            ),
        ]);
        assert!(matches!(
            commit(
                &store,
                transition.attributed_to(store.namespace()),
                &mut AttemptHistory::default()
            )
            .await,
            ScopeHeadCommitOutcome::Unresolved(_)
        ));
        assert_eq!(client.actual_requests().count(), 2);
    }

    #[tokio::test]
    async fn append_root_refuses_a_mismatched_writer_epoch_before_publishing() {
        let genesis = genesis();
        let root = crate::scope::decode_root_event(
            genesis.event_bytes(),
            genesis.event_key(),
            genesis.identity(),
        )
        .unwrap();
        let parent = owned_parent(&genesis, "instance-a", 4);

        // The genesis event carries writer epoch 1, so an epoch-4 parent refuses it before
        // publishing any immutable bytes.
        let (store, client) = replay_store(vec![response(
            200,
            &[("etag", "\"parent\"")],
            encode_head(&parent).unwrap(),
        )]);
        let observed_parent = read(&store, genesis.identity()).await.unwrap().unwrap();
        assert!(matches!(
            append_root(
                &store,
                ScopeHeadParent::existing(Box::new(observed_parent)),
                genesis.identity(),
                &root,
                &mut AttemptHistory::default(),
                &mut AttemptHistory::default(),
            )
            .await,
            Err(ScopeAppendError::InvalidInput)
        ));
        assert!(
            client
                .actual_requests()
                .all(|request| request.method() == "GET")
        );

        // Reverting the parent-derived epoch would let this attempt publish immutable bytes
        // before its refusal, so the dispatch record above is the guard.
    }

    /// The relaxed head support lets an owned current head enter retained reconciliation, which
    /// the earlier operation-identity shortcut never reached.
    #[tokio::test]
    async fn an_owned_superseding_head_reconciles_the_retained_chain() {
        let genesis = genesis();
        let winner = InstanceId::new("instance-b".into()).unwrap();
        let parent = owned_parent(&genesis, "instance-a", 4);
        let (envelope, encoded) =
            successor_at(genesis.identity(), genesis.event_ref(), 2, "stale-op", 4);
        let event_ref = encoded.event_ref().clone();
        let publication = published(genesis.identity(), &envelope, encoded).await;
        let candidate = ScopeHead::new(
            genesis.identity().clone(),
            parent.authority().clone(),
            4,
            event_ref,
            None,
            "stale-op".into(),
        )
        .unwrap();
        let (winning_envelope, winning_encoded) =
            successor_at(genesis.identity(), genesis.event_ref(), 2, "winning-op", 5);
        let superseding = ScopeHead::new(
            genesis.identity().clone(),
            ScopeAuthority::owned(winner, 1_700_000_060_000).unwrap(),
            5,
            winning_encoded.event_ref().clone(),
            None,
            "winning-op".into(),
        )
        .unwrap();
        let transition = ScopeHeadTransition::new(
            ScopeHeadParent::existing(Box::new(observed(&parent).await)),
            candidate,
            publication,
        )
        .unwrap();
        let (store, client) = replay_store(vec![
            response(412, &[], SdkBody::empty()),
            response(
                200,
                &[("etag", "\"superseding\"")],
                encode_head(&superseding).unwrap(),
            ),
            response(404, &[], SdkBody::empty()),
            response(
                200,
                &[("etag", "\"winning-event\"")],
                winning_encoded.stored_bytes().to_vec(),
            ),
        ]);
        assert!(matches!(
            commit(
                &store,
                transition.attributed_to(store.namespace()),
                &mut AttemptHistory::default()
            )
            .await,
            ScopeHeadCommitOutcome::ProvenNotCommitted
        ));
        assert_eq!(client.actual_requests().count(), 4);
        assert_eq!(winning_envelope.writer_epoch().get(), 5);
    }

    fn admissible_plan(
        genesis: &crate::scope::RootGenesis,
    ) -> (AdmissibleProposal, PlanAdmittedEvent) {
        use crate::domain::proposal::{
            ObservationFact, PlanProposal, ProposalBasis, ProposalFacts, TargetBounds, WorkSpec,
            validate_proposal,
        };
        use crate::domain::work::WorkId;

        let scope = genesis.identity().clone();
        let objective = genesis.config_digest().clone();
        let proposal = PlanProposal::new(
            scope.scope_id().clone(),
            objective.clone(),
            None,
            vec![ProposalBasis::Observation {
                event: genesis.event_ref().clone(),
            }],
            vec![WorkSpec::new(
                WorkId::new("work-a".into()).unwrap(),
                Vec::new(),
                TargetBounds::new(1, 60_000).unwrap(),
            )],
            0,
        );
        let facts = [ObservationFact::new(
            scope.scope_id().clone(),
            genesis.event_ref().clone(),
            crate::scope::ROOT_GENESIS_PAYLOAD_TYPE.to_owned(),
        )];
        let admissible = validate_proposal(
            &proposal,
            &ProposalFacts::new(&scope, &objective, None, 1, &facts),
        )
        .unwrap();
        let event = PlanAdmittedEvent::new(
            EventEnvelope::new(
                scope.scope_id().clone(),
                2,
                Some(genesis.event_ref().clone()),
                1,
                "admit-plan-1".into(),
                PLAN_ADMITTED_PAYLOAD_TYPE.to_owned(),
            )
            .unwrap(),
            crate::scope::PlanAdmittedPayload::new(admissible.plan_digest().clone()),
        )
        .unwrap();
        (admissible, event)
    }

    #[tokio::test]
    async fn append_plan_admitted_publishes_plan_then_event_then_head() {
        let genesis = genesis();
        let (admissible, _) = admissible_plan(&genesis);
        // The parent witness must come from the same store the commit targets: a witness from
        // another constructed store is refused by design.
        let (store, client) = replay_store(vec![
            response(
                200,
                &[("etag", "\"parent\"")],
                encode_head(genesis.head()).unwrap(),
            ),
            response(200, &[], SdkBody::empty()),
            response(200, &[], SdkBody::empty()),
            response(200, &[], SdkBody::empty()),
        ]);
        let parent = ScopeHeadParent::existing(Box::new(
            read(&store, genesis.identity()).await.unwrap().unwrap(),
        ));

        assert!(matches!(
            append_plan_admitted(
                &store,
                parent,
                genesis.identity(),
                &admissible,
                "admit-plan-1",
                [
                    &mut AttemptHistory::default(),
                    &mut AttemptHistory::default(),
                    &mut AttemptHistory::default(),
                ],
            )
            .await
            .unwrap(),
            ScopeHeadCommitOutcome::Committed(_)
        ));
        let requests = client.actual_requests().collect::<Vec<_>>();
        assert_eq!(requests.len(), 4);
        let plan_uri = requests[1].uri().parse::<http::Uri>().unwrap();
        let event_uri = requests[2].uri().parse::<http::Uri>().unwrap();
        let head_uri = requests[3].uri().parse::<http::Uri>().unwrap();
        assert!(plan_uri.path().contains("/plans/"));
        assert!(plan_uri.path().ends_with(admissible.plan_digest().as_str()));
        assert!(event_uri.path().contains("/events/"));
        assert!(head_uri.path().ends_with("/head"));
        // The head replaces exactly the fenced parent; the objects are create-if-absent.
        assert_eq!(requests[1].headers().get("if-none-match").unwrap(), "*");
        assert_eq!(requests[2].headers().get("if-none-match").unwrap(), "*");
        assert_eq!(requests[3].headers().get("if-match").unwrap(), "\"parent\"");
    }

    #[tokio::test]
    async fn append_plan_admitted_refuses_doomed_attempts_before_any_write() {
        let genesis = genesis();
        let (admissible, _) = admissible_plan(&genesis);
        let store = never_store("bucket-a");

        // A parent that already holds an active plan cannot admit again.
        let occupied = ScopeHead::new(
            genesis.identity().clone(),
            ScopeAuthority::Unowned,
            1,
            genesis.event_ref().clone(),
            Some(Digest::new("a".repeat(64)).unwrap()),
            "already-admitted".into(),
        )
        .unwrap();
        let mut plan = AttemptHistory::default();
        let mut evt = AttemptHistory::default();
        let mut head = AttemptHistory::default();
        assert!(matches!(
            append_plan_admitted(
                &store,
                ScopeHeadParent::existing(Box::new(observed(&occupied).await)),
                genesis.identity(),
                &admissible,
                "admit-plan-1",
                [&mut plan, &mut evt, &mut head],
            )
            .await,
            Err(ScopeAppendError::InvalidInput)
        ));

        // Genesis is not a fenced parent for admission.
        let mut plan = AttemptHistory::default();
        let mut evt = AttemptHistory::default();
        let mut head = AttemptHistory::default();
        assert!(matches!(
            append_plan_admitted(
                &store,
                ScopeHeadParent::Genesis,
                genesis.identity(),
                &admissible,
                "admit-plan-1",
                [&mut plan, &mut evt, &mut head],
            )
            .await,
            Err(ScopeAppendError::InvalidInput)
        ));
    }

    /// The transition rule itself binds the candidate head to the payload's address, so a head
    /// that names any other plan is refused even when every pre-check upstream is bypassed.
    #[tokio::test]
    async fn a_transition_head_must_name_exactly_the_admitted_plan() {
        let genesis = genesis();
        let (admissible, event) = admissible_plan(&genesis);
        let encoded = encode_plan_admitted_event(&event).unwrap();
        let event_ref = encoded.event_ref().clone();
        let publication = published(genesis.identity(), event.envelope(), encoded).await;
        let head_with = |plan: Option<Digest>| {
            ScopeHead::new(
                genesis.identity().clone(),
                ScopeAuthority::Unowned,
                1,
                event_ref.clone(),
                plan,
                "admit-plan-1".into(),
            )
            .unwrap()
        };

        // The exact payload address commits; a foreign address and no address are refused.
        assert!(
            ScopeHeadTransition::new(
                ScopeHeadParent::existing(Box::new(observed(genesis.head()).await)),
                head_with(Some(admissible.plan_digest().clone())),
                publication.clone(),
            )
            .is_ok()
        );
        for wrong in [Some(Digest::new("c".repeat(64)).unwrap()), None] {
            assert!(matches!(
                ScopeHeadTransition::new(
                    ScopeHeadParent::existing(Box::new(observed(genesis.head()).await)),
                    head_with(wrong),
                    publication.clone(),
                ),
                Err(WireError::InvalidValue)
            ));
        }
        // An occupied parent refuses the admission at the same rule.
        let occupied = ScopeHead::new(
            genesis.identity().clone(),
            ScopeAuthority::Unowned,
            1,
            genesis.event_ref().clone(),
            Some(Digest::new("a".repeat(64)).unwrap()),
            "already-admitted".into(),
        )
        .unwrap();
        assert!(matches!(
            ScopeHeadTransition::new(
                ScopeHeadParent::existing(Box::new(observed(&occupied).await)),
                head_with(Some(admissible.plan_digest().clone())),
                publication,
            ),
            Err(WireError::InvalidValue)
        ));
    }

    #[tokio::test]
    async fn a_successor_past_the_replay_ceiling_is_refused() {
        use crate::sync::replay::MAX_SCOPE_REPLAY_EVENTS;

        let genesis = genesis();
        let parent_at = |sequence: u64| {
            ScopeHead::new(
                genesis.identity().clone(),
                ScopeAuthority::Unowned,
                1,
                ScopeEventRef::new(sequence, Digest::new("d".repeat(64)).unwrap()).unwrap(),
                None,
                "parent-op".into(),
            )
            .unwrap()
        };
        let at_ceiling = parent_at(MAX_SCOPE_REPLAY_EVENTS - 1);
        let over_ceiling = parent_at(MAX_SCOPE_REPLAY_EVENTS);

        assert_eq!(
            next_sequence(&observed(&at_ceiling).await),
            Ok(MAX_SCOPE_REPLAY_EVENTS)
        );
        assert_eq!(
            next_sequence(&observed(&over_ceiling).await),
            Err(ScopeAppendError::InvalidInput)
        );

        for (parent, sequence, accepted) in [
            (&at_ceiling, MAX_SCOPE_REPLAY_EVENTS, true),
            (&over_ceiling, MAX_SCOPE_REPLAY_EVENTS + 1, false),
        ] {
            let operation = format!("ceiling-op-{sequence}");
            let (envelope, encoded) =
                successor(genesis.identity(), parent.tail(), sequence, &operation);
            let publication = published(genesis.identity(), &envelope, encoded).await;
            let candidate = ScopeHead::new(
                genesis.identity().clone(),
                ScopeAuthority::Unowned,
                1,
                publication.event_ref().clone(),
                None,
                operation,
            )
            .unwrap();
            let transition = ScopeHeadTransition::new(
                ScopeHeadParent::existing(Box::new(observed(parent).await)),
                candidate,
                publication,
            );
            assert_eq!(transition.is_ok(), accepted);
            if !accepted {
                assert!(matches!(transition, Err(WireError::InvalidValue)));
            }
        }
    }

    fn successor_batch(
        scope: &ScopeIdentity,
        parent: &ScopeEventRef,
        first_sequence: u64,
        operations: &[&str],
    ) -> Vec<(EventEnvelope, crate::scope::EncodedScopeEvent)> {
        let mut parent_ref = parent.clone();
        let mut batch = Vec::with_capacity(operations.len());
        for (index, operation) in operations.iter().enumerate() {
            let (envelope, encoded) =
                successor(scope, &parent_ref, first_sequence + index as u64, operation);
            parent_ref = encoded.event_ref().clone();
            batch.push((envelope, encoded));
        }
        batch
    }

    fn plan_admitted_pair(
        scope: &ScopeIdentity,
        parent: &ScopeEventRef,
        sequence: u64,
        operation: &str,
        plan: Digest,
    ) -> (EventEnvelope, crate::scope::EncodedScopeEvent) {
        let event = PlanAdmittedEvent::new(
            EventEnvelope::new(
                scope.scope_id().clone(),
                sequence,
                Some(parent.clone()),
                1,
                operation.to_owned(),
                PLAN_ADMITTED_PAYLOAD_TYPE.to_owned(),
            )
            .unwrap(),
            crate::scope::PlanAdmittedPayload::new(plan),
        )
        .unwrap();
        let encoded = encode_plan_admitted_event(&event).unwrap();
        (event.envelope().clone(), encoded)
    }

    /// Every batch-internal chain violation is refused before the first S3 request, so a
    /// doomed batch never publishes an immutable object.
    #[tokio::test]
    async fn batch_preflight_refuses_chain_violations_before_any_request() {
        use crate::sync::replay::MAX_SCOPE_REPLAY_EVENTS;

        let genesis = genesis();
        let scope = genesis.identity().clone();
        let tail = genesis.event_ref().clone();

        // A member past its slot whose own envelope still chains to a self-consistent parent.
        // `EventEnvelope::new` makes a true gap that names its real predecessor
        // unconstructible, so a constructible gap carries a phantom parent and trips the
        // sequence rule first, with the parent-reference rule behind it. commentlint: allow(JUDGE)
        let gap = {
            let (env2, enc2) = successor(&scope, &tail, 2, "gap-op-2");
            let phantom = ScopeEventRef::new(3, Digest::new("a".repeat(64)).unwrap()).unwrap();
            let (env4, enc4) = successor(&scope, &phantom, 4, "gap-op-4");
            vec![(env2, enc2), (env4, enc4)]
        };
        // A contiguous sequence whose second member names a rival predecessor digest.
        let wrong_parent = {
            let (env2, enc2) = successor(&scope, &tail, 2, "wrong-parent-2");
            let rival = ScopeEventRef::new(2, Digest::new("b".repeat(64)).unwrap()).unwrap();
            let (env3, enc3) = successor(&scope, &rival, 3, "wrong-parent-3");
            vec![(env2, enc2), (env3, enc3)]
        };
        let mixed_epoch = {
            let (env2, enc2) = successor(&scope, &tail, 2, "mixed-epoch-2");
            let parent2 = enc2.event_ref().clone();
            let (env3, enc3) = successor_at(&scope, &parent2, 3, "mixed-epoch-3", 2);
            vec![(env2, enc2), (env3, enc3)]
        };
        let duplicate_operation = successor_batch(&scope, &tail, 2, &["dup-op", "dup-op"]);
        let parent_operation = successor_batch(&scope, &tail, 2, &[genesis.head().operation_id()]);
        let double_admission = {
            let (env2, enc2) = plan_admitted_pair(
                &scope,
                &tail,
                2,
                "admit-op-1",
                Digest::new("c".repeat(64)).unwrap(),
            );
            let parent2 = enc2.event_ref().clone();
            let (env3, enc3) = plan_admitted_pair(
                &scope,
                &parent2,
                3,
                "admit-op-2",
                Digest::new("d".repeat(64)).unwrap(),
            );
            vec![(env2, enc2), (env3, enc3)]
        };

        // Chain-valid against the foreign parent, but every member names this scope.
        let foreign = root_genesis(
            &AdmittedCampaignConfig::new(
                WorkspaceId::new("workspace-a".into()).unwrap(),
                CampaignId::new("campaign-b".into()).unwrap(),
                b"admitted".to_vec(),
            )
            .unwrap(),
        )
        .unwrap();
        let cross_scope = successor_batch(&scope, foreign.event_ref(), 2, &["cross-scope-op"]);
        let checkpoint_member = {
            let payload = ProjectionCheckpointPayload::new(
                Digest::new("b".repeat(64)).unwrap(),
                1_024,
                1,
                genesis.event_ref().digest().clone(),
                None,
            )
            .unwrap();
            let event = ProjectionCheckpointEvent::new(
                EventEnvelope::new(
                    scope.scope_id().clone(),
                    2,
                    Some(tail.clone()),
                    1,
                    "checkpoint-member-op".into(),
                    PROJECTION_CHECKPOINT_PAYLOAD_TYPE.to_owned(),
                )
                .unwrap(),
                payload,
            )
            .unwrap();
            let encoded = encode_projection_checkpoint_event(&event).unwrap();
            vec![(event.envelope().clone(), encoded)]
        };
        let boundary = ScopeEventRef::new(
            MAX_SCOPE_REPLAY_EVENTS - 1,
            Digest::new("d".repeat(64)).unwrap(),
        )
        .unwrap();
        let high_parent = ScopeHead::new(
            scope.clone(),
            ScopeAuthority::Unowned,
            1,
            boundary.clone(),
            None,
            "parent-op".into(),
        )
        .unwrap();
        // The ceiling breach sits on a non-first member, so the bound is proven inside the
        // walk, not only at the seed.
        let over = successor_batch(
            &scope,
            &boundary,
            MAX_SCOPE_REPLAY_EVENTS,
            &["ceiling-op-1", "ceiling-op-2"],
        );

        let cases = vec![
            ("a sequence gap", genesis.head().clone(), gap),
            (
                "a wrong parent reference",
                genesis.head().clone(),
                wrong_parent,
            ),
            ("a mixed writer epoch", genesis.head().clone(), mixed_epoch),
            (
                "a duplicate operation id",
                genesis.head().clone(),
                duplicate_operation,
            ),
            (
                "an operation id equal to the parent's",
                genesis.head().clone(),
                parent_operation,
            ),
            (
                "a second plan admission",
                genesis.head().clone(),
                double_admission,
            ),
            ("an empty batch", genesis.head().clone(), Vec::new()),
            (
                "a final sequence past the replay ceiling",
                high_parent,
                over,
            ),
            (
                "a member outside the parent head's scope",
                foreign.head().clone(),
                cross_scope,
            ),
            (
                "a projection-checkpoint member",
                genesis.head().clone(),
                checkpoint_member,
            ),
        ];
        for (label, parent, batch) in cases {
            let (store, client) = replay_store(vec![]);
            assert!(
                matches!(
                    append_batch(
                        &store,
                        ScopeHeadParent::existing(Box::new(observed(&parent).await)),
                        &scope,
                        batch,
                        &mut AttemptHistory::default(),
                    )
                    .await,
                    Err(ScopeAppendError::InvalidInput)
                ),
                "{label} must be refused"
            );
            assert_eq!(
                client.actual_requests().count(),
                0,
                "{label} must send nothing"
            );
        }

        // `append_batch` refuses any genesis parent outright: the first head is created only
        // through `append_root`. The constructor-level one-event genesis rule is proven
        // separately by `a_multi_event_genesis_batch_is_refused`.
        let genesis_batch = successor_batch(&scope, &tail, 2, &["genesis-batch-op"]);
        let (store, client) = replay_store(vec![]);
        assert!(matches!(
            append_batch(
                &store,
                ScopeHeadParent::Genesis,
                &scope,
                genesis_batch,
                &mut AttemptHistory::default(),
            )
            .await,
            Err(ScopeAppendError::InvalidInput)
        ));
        assert_eq!(client.actual_requests().count(), 0);
    }

    /// The preflight's per-member validation refuses a payload-invalid member before any
    /// object is published, so members ahead of it never reach the bucket. The error class is
    /// pinned: an unregistered member surfaces as a publication error, not `InvalidInput`.
    #[tokio::test]
    async fn batch_preflight_refuses_an_invalid_member_payload_before_any_request() {
        let genesis = genesis();
        let scope = genesis.identity().clone();
        let (env2, enc2) = successor(&scope, genesis.event_ref(), 2, "payload-op-2");
        let unregistered = {
            let envelope = EventEnvelope::new(
                scope.scope_id().clone(),
                3,
                Some(enc2.event_ref().clone()),
                1,
                "payload-op-3".into(),
                "artifact".into(),
            )
            .unwrap();
            let encoded = encode_scope_event(&envelope, &Value::Null).unwrap();
            (envelope, encoded)
        };
        let (env4, enc4) = successor(&scope, unregistered.1.event_ref(), 4, "payload-op-4");
        let (store, client) = replay_store(vec![]);
        assert!(matches!(
            append_batch(
                &store,
                ScopeHeadParent::existing(Box::new(observed(genesis.head()).await)),
                &scope,
                vec![(env2, enc2), unregistered, (env4, enc4)],
                &mut AttemptHistory::default(),
            )
            .await,
            Err(ScopeAppendError::Publication(
                ScopeEventPublicationError::UnsupportedPayload
            ))
        ));
        assert_eq!(client.actual_requests().count(), 0);
    }

    /// The first publication failure stops the batch before the head CAS, so a partially
    /// published batch can never become authoritative.
    #[tokio::test]
    async fn a_mid_batch_publication_failure_stops_before_the_head_cas() {
        let genesis = genesis();
        let scope = genesis.identity().clone();
        let batch = successor_batch(
            &scope,
            genesis.event_ref(),
            2,
            &["stop-op-2", "stop-op-3", "stop-op-4"],
        );
        let (store, client) = replay_store(vec![
            response(
                200,
                &[("etag", "\"parent\"")],
                encode_head(genesis.head()).unwrap(),
            ),
            response(200, &[], SdkBody::empty()),
            response(404, &[], SdkBody::empty()),
        ]);
        let parent = read(&store, &scope).await.unwrap().unwrap();
        assert!(matches!(
            append_batch(
                &store,
                ScopeHeadParent::existing(Box::new(parent)),
                &scope,
                batch,
                &mut AttemptHistory::default(),
            )
            .await,
            Err(ScopeAppendError::Publication(
                ScopeEventPublicationError::Storage(_)
            ))
        ));
        let requests: Vec<_> = client.actual_requests().collect();
        assert_eq!(
            requests.len(),
            3,
            "parent read + first event PUT + terminally failed second PUT"
        );
        assert!(
            requests
                .iter()
                .all(|request| request.headers().get("if-match").is_none()),
            "the head CAS must never dispatch after a publication failure"
        );
    }

    /// A batched plan admission is folded left-to-right: the digest a middle member admits
    /// survives the trailing plain member and lands on the committed head's wire form.
    #[tokio::test]
    async fn a_batched_plan_admission_carries_its_digest_onto_the_committed_head() {
        let genesis = genesis();
        let scope = genesis.identity().clone();
        let (admissible, _) = admissible_plan(&genesis);
        let plan = admissible.plan_digest().clone();
        let (env2, enc2) = successor(&scope, genesis.event_ref(), 2, "fold-op-2");
        let (env3, enc3) =
            plan_admitted_pair(&scope, enc2.event_ref(), 3, "fold-op-3", plan.clone());
        let (env4, enc4) = successor(&scope, enc3.event_ref(), 4, "fold-op-4");
        let tail_ref = enc4.event_ref().clone();
        let batch = vec![(env2, enc2), (env3, enc3), (env4, enc4)];
        let (store, client) = replay_store(vec![
            response(
                200,
                &[("etag", "\"parent\"")],
                encode_head(genesis.head()).unwrap(),
            ),
            response(
                200,
                &[("etag", "\"plan\"")],
                admissible.stored_bytes().to_vec(),
            ),
            response(200, &[], SdkBody::empty()),
            response(200, &[], SdkBody::empty()),
            response(200, &[], SdkBody::empty()),
            response(200, &[("etag", "\"committed\"")], SdkBody::empty()),
        ]);
        let parent = read(&store, &scope).await.unwrap().unwrap();
        let outcome = append_batch(
            &store,
            ScopeHeadParent::existing(Box::new(parent)),
            &scope,
            batch,
            &mut AttemptHistory::default(),
        )
        .await
        .unwrap();
        let ScopeHeadCommitOutcome::Committed(Some(committed)) = outcome else {
            panic!("the admitting batch must commit with a witness");
        };
        assert_eq!(committed.head().active_plan_digest(), Some(&plan));
        let requests: Vec<_> = client.actual_requests().collect();
        assert_eq!(
            requests.len(),
            6,
            "parent read + plan read + 3 event PUTs + head CAS"
        );
        let plan_uri = requests[1].uri().parse::<http::Uri>().unwrap();
        assert!(plan_uri.path().contains("/plans/"));
        let committed_head = decode_head(
            requests[5].body().bytes().unwrap(),
            &scope_head_key(&scope),
            &scope,
        )
        .unwrap();
        assert_eq!(committed_head.active_plan_digest(), Some(&plan));
        assert_eq!(committed_head.tail(), &tail_ref);
    }

    /// A candidate head that drops the batch's folded admission is refused at the constructor,
    /// so the fold is authoritative for the candidate's plan digest.
    #[tokio::test]
    async fn a_candidate_dropping_the_batched_admission_is_refused() {
        let genesis = genesis();
        let scope = genesis.identity().clone();
        let (admissible, _) = admissible_plan(&genesis);
        let (env2, enc2) = successor(&scope, genesis.event_ref(), 2, "drop-op-2");
        let (env3, enc3) = plan_admitted_pair(
            &scope,
            enc2.event_ref(),
            3,
            "drop-op-3",
            admissible.plan_digest().clone(),
        );
        let (env4, enc4) = successor(&scope, enc3.event_ref(), 4, "drop-op-4");
        let tail_ref = enc4.event_ref().clone();
        let publications =
            published_batch(&scope, vec![(env2, enc2), (env3, enc3), (env4, enc4)]).await;
        let candidate = ScopeHead::new(
            scope.clone(),
            ScopeAuthority::Unowned,
            1,
            tail_ref,
            None,
            "drop-op-4".into(),
        )
        .unwrap();
        assert!(matches!(
            ScopeHeadTransition::new_batch(
                ScopeHeadParent::existing(Box::new(observed(genesis.head()).await)),
                candidate,
                publications,
            ),
            Err(WireError::InvalidValue)
        ));
    }

    /// A batched admission must name a readable, digest-matching plan object before the first
    /// event PUT: an event that names an address must never win the head race while that
    /// address is unreadable.
    #[tokio::test]
    async fn a_batch_plan_admission_requires_a_readable_plan_object() {
        let genesis = genesis();
        let scope = genesis.identity().clone();
        let plan = Digest::new("c".repeat(64)).unwrap();
        let build = |prefix: &str| {
            let (env2, enc2) = successor(&scope, genesis.event_ref(), 2, &format!("{prefix}-2"));
            let (env3, enc3) = plan_admitted_pair(
                &scope,
                enc2.event_ref(),
                3,
                &format!("{prefix}-3"),
                plan.clone(),
            );
            vec![(env2, enc2), (env3, enc3)]
        };

        // Missing object, and readable bytes that do not decode to the named digest.
        let plan_responses = [
            response(404, &[], SdkBody::empty()),
            response(200, &[("etag", "\"plan\"")], b"not-a-plan".to_vec()),
        ];
        for (batch, plan_response) in [build("unread-op"), build("mismatch-op")]
            .into_iter()
            .zip(plan_responses)
        {
            let (store, client) = replay_store(vec![
                response(
                    200,
                    &[("etag", "\"parent\"")],
                    encode_head(genesis.head()).unwrap(),
                ),
                plan_response,
            ]);
            let parent = read(&store, &scope).await.unwrap().unwrap();
            assert!(matches!(
                append_batch(
                    &store,
                    ScopeHeadParent::existing(Box::new(parent)),
                    &scope,
                    batch,
                    &mut AttemptHistory::default(),
                )
                .await,
                Err(ScopeAppendError::InvalidInput)
            ));
            let requests: Vec<_> = client.actual_requests().collect();
            assert_eq!(requests.len(), 2, "parent read + failed plan read");
            assert!(
                requests
                    .iter()
                    .all(|request| request.headers().get("if-none-match").is_none()),
                "no event PUT may precede the plan-object proof"
            );
        }
    }

    /// A readable, digest-matching plan object can still belong to a foreign scope:
    /// `decode_plan` proves bytes-to-digest binding, not scope, and `plan_key` is not scoped by
    /// `scope_id`. The preflight mirrors `append_plan_admitted`'s cross-scope refusal, and no
    /// event PUT may precede it.
    #[tokio::test]
    async fn a_batch_plan_admission_naming_a_foreign_scopes_plan_is_refused() {
        let genesis = genesis();
        let scope = genesis.identity().clone();
        let foreign = root_genesis(
            &AdmittedCampaignConfig::new(
                WorkspaceId::new("workspace-b".into()).unwrap(),
                CampaignId::new("campaign-b".into()).unwrap(),
                b"admitted".to_vec(),
            )
            .unwrap(),
        )
        .unwrap();
        let (foreign_admissible, _) = admissible_plan(&foreign);
        let plan = foreign_admissible.plan_digest().clone();
        let (env2, enc2) = successor(&scope, genesis.event_ref(), 2, "foreign-plan-op-2");
        let (env3, enc3) =
            plan_admitted_pair(&scope, enc2.event_ref(), 3, "foreign-plan-op-3", plan);
        let (store, client) = replay_store(vec![
            response(
                200,
                &[("etag", "\"parent\"")],
                encode_head(genesis.head()).unwrap(),
            ),
            response(
                200,
                &[("etag", "\"plan\"")],
                foreign_admissible.stored_bytes().to_vec(),
            ),
        ]);
        let parent = read(&store, &scope).await.unwrap().unwrap();
        assert!(matches!(
            append_batch(
                &store,
                ScopeHeadParent::existing(Box::new(parent)),
                &scope,
                vec![(env2, enc2), (env3, enc3)],
                &mut AttemptHistory::default(),
            )
            .await,
            Err(ScopeAppendError::InvalidInput)
        ));
        let requests: Vec<_> = client.actual_requests().collect();
        assert_eq!(requests.len(), 2, "parent read + plan read");
        assert!(
            requests
                .iter()
                .all(|request| request.headers().get("if-none-match").is_none()),
            "no event PUT may precede the cross-scope refusal"
        );
    }

    /// A transient failure reading the companion plan proves nothing about the batch, so it
    /// surfaces as a retryable storage error rather than `InvalidInput`: a valid batch must
    /// stay distinguishable from malformed input during an outage.
    #[tokio::test]
    async fn a_batch_plan_preflight_surfaces_transport_failures_as_storage_errors() {
        let genesis = genesis();
        let scope = genesis.identity().clone();
        let plan = Digest::new("c".repeat(64)).unwrap();
        let (env2, enc2) = successor(&scope, genesis.event_ref(), 2, "transport-op-2");
        let (env3, enc3) = plan_admitted_pair(&scope, enc2.event_ref(), 3, "transport-op-3", plan);
        let (store, client) = replay_store(vec![
            response(
                200,
                &[("etag", "\"parent\"")],
                encode_head(genesis.head()).unwrap(),
            ),
            response(500, &[], SdkBody::empty()),
        ]);
        let parent = read(&store, &scope).await.unwrap().unwrap();
        assert!(matches!(
            append_batch(
                &store,
                ScopeHeadParent::existing(Box::new(parent)),
                &scope,
                vec![(env2, enc2), (env3, enc3)],
                &mut AttemptHistory::default(),
            )
            .await,
            Err(ScopeAppendError::Publication(
                ScopeEventPublicationError::Storage(_)
            ))
        ));
        assert_eq!(
            client.actual_requests().count(),
            2,
            "parent read + failed plan read; no event PUT follows a transport failure"
        );
    }

    /// A grant activation folds only against projection state — admitted work with a matching
    /// revision, claim fence, and attempt — that `grants::issue` proves before appending. No
    /// durable object witnesses that proof, so batch preflight refuses grant members before any
    /// request rather than let an unfoldable activation win the head CAS and poison replay.
    #[tokio::test]
    async fn a_batch_grant_activation_member_is_refused_before_any_request() {
        let genesis = genesis();
        let scope = genesis.identity().clone();
        let (env2, enc2) = successor(&scope, genesis.event_ref(), 2, "grant-batch-op-2");
        let (env3, enc3) = {
            let payload = GrantActivatedPayload::new(
                crate::domain::work::WorkId::new("work-a".into()).unwrap(),
                1,
                1,
                Digest::new("d".repeat(64)).unwrap(),
                1,
                1,
                60_000,
            )
            .unwrap();
            let event = GrantActivatedEvent::new(
                EventEnvelope::new(
                    scope.scope_id().clone(),
                    3,
                    Some(enc2.event_ref().clone()),
                    1,
                    "grant-batch-op-3".into(),
                    GRANT_ACTIVATED_PAYLOAD_TYPE.to_owned(),
                )
                .unwrap(),
                payload,
            )
            .unwrap();
            let encoded = encode_grant_activated_event(&event).unwrap();
            (event.envelope().clone(), encoded)
        };
        let (store, client) = replay_store(vec![response(
            200,
            &[("etag", "\"parent\"")],
            encode_head(genesis.head()).unwrap(),
        )]);
        let parent = read(&store, &scope).await.unwrap().unwrap();
        assert!(matches!(
            append_batch(
                &store,
                ScopeHeadParent::existing(Box::new(parent)),
                &scope,
                vec![(env2, enc2), (env3, enc3)],
                &mut AttemptHistory::default(),
            )
            .await,
            Err(ScopeAppendError::InvalidInput)
        ));
        assert_eq!(
            client.actual_requests().count(),
            1,
            "parent read only; the grant member is refused before any batch request"
        );
    }

    /// Genesis stays a one-event transition at the constructor too, so no caller can widen the
    /// protocol's first head into a batch.
    #[tokio::test]
    async fn a_multi_event_genesis_batch_is_refused() {
        let genesis = genesis();
        let scope = genesis.identity().clone();
        let root =
            crate::scope::decode_root_event(genesis.event_bytes(), genesis.event_key(), &scope)
                .unwrap();
        let root_pair = (
            root.envelope().clone(),
            crate::scope::encode_root_event(&root).unwrap(),
        );
        let (env2, enc2) = successor(&scope, genesis.event_ref(), 2, "genesis-batch-2");
        let tail = enc2.event_ref().clone();
        let publications = published_batch(&scope, vec![root_pair, (env2, enc2)]).await;
        let candidate = ScopeHead::new(
            scope.clone(),
            ScopeAuthority::Unowned,
            1,
            tail,
            None,
            "genesis-batch-2".into(),
        )
        .unwrap();
        assert!(matches!(
            ScopeHeadTransition::new_batch(ScopeHeadParent::Genesis, candidate, publications),
            Err(WireError::InvalidValue)
        ));
    }

    /// Publications witnessed by different stores cannot share one head commit: `commit`
    /// compares only the stored final publication against its target store, so the
    /// constructor is where cross-namespace assembly must be refused.
    #[tokio::test]
    async fn a_batch_spanning_store_namespaces_is_refused() {
        let genesis = genesis();
        let scope = genesis.identity().clone();
        let (env2, enc2) = successor(&scope, genesis.event_ref(), 2, "ns-op-2");
        let (env3, enc3) = successor(&scope, enc2.event_ref(), 3, "ns-op-3");
        let tail = enc3.event_ref().clone();
        // Per-event stores: each mints its own namespace.
        let publication2 = published(&scope, &env2, enc2).await;
        let publication3 = published(&scope, &env3, enc3).await;
        let candidate = ScopeHead::new(
            scope.clone(),
            ScopeAuthority::Unowned,
            1,
            tail,
            None,
            "ns-op-3".into(),
        )
        .unwrap();
        assert!(matches!(
            ScopeHeadTransition::new_batch(
                ScopeHeadParent::existing(Box::new(observed(genesis.head()).await)),
                candidate,
                vec![publication2, publication3],
            ),
            Err(WireError::InvalidValue)
        ));
    }

    /// A committed batch is B create-only event publications in order and exactly one
    /// conditional head CAS, advancing the head by B to the final member.
    #[tokio::test]
    async fn a_committed_batch_advances_the_head_once_past_every_member() {
        let genesis = genesis();
        let scope = genesis.identity().clone();
        let batch = successor_batch(
            &scope,
            genesis.event_ref(),
            2,
            &["batch-op-2", "batch-op-3", "batch-op-4"],
        );
        let keys: Vec<String> = batch
            .iter()
            .map(|(_, encoded)| scope_event_key(&scope, encoded.event_ref()))
            .collect();
        let bodies: Vec<Vec<u8>> = batch
            .iter()
            .map(|(_, encoded)| encoded.stored_bytes().to_vec())
            .collect();
        let last_ref = batch.last().unwrap().1.event_ref().clone();
        let (store, client) = replay_store(vec![
            response(
                200,
                &[("etag", "\"parent\"")],
                encode_head(genesis.head()).unwrap(),
            ),
            response(200, &[], SdkBody::empty()),
            response(200, &[], SdkBody::empty()),
            response(200, &[], SdkBody::empty()),
            response(200, &[("etag", "\"committed\"")], SdkBody::empty()),
        ]);
        let parent = read(&store, &scope).await.unwrap().unwrap();
        let outcome = append_batch(
            &store,
            ScopeHeadParent::existing(Box::new(parent)),
            &scope,
            batch,
            &mut AttemptHistory::default(),
        )
        .await
        .unwrap();
        let ScopeHeadCommitOutcome::Committed(Some(committed)) = outcome else {
            panic!("the batch must commit with a witness");
        };
        assert_eq!(committed.head().tail(), &last_ref);
        assert_eq!(committed.head().tail().sequence(), 4);
        assert_eq!(committed.head().operation_id(), "batch-op-4");
        let requests: Vec<_> = client.actual_requests().collect();
        assert_eq!(requests.len(), 5);
        for (request, (key, bytes)) in requests[1..4].iter().zip(keys.iter().zip(&bodies)) {
            let uri = request.uri().parse::<http::Uri>().unwrap();
            assert_eq!(uri.path(), format!("/{key}"));
            assert_eq!(request.headers().get("if-none-match").unwrap(), "*");
            // The body is a separate argument from the key, so publication order is pinned
            // by content, not just by address.
            assert_eq!(request.body().bytes().unwrap(), bytes.as_slice());
        }
        let head_uri = requests[4].uri().parse::<http::Uri>().unwrap();
        assert!(head_uri.path().ends_with("/head"));
        assert_eq!(requests[4].headers().get("if-match").unwrap(), "\"parent\"");
        let committed_head = decode_head(
            requests[4].body().bytes().unwrap(),
            &scope_head_key(&scope),
            &scope,
        )
        .unwrap();
        assert_eq!(committed_head.tail(), &last_ref);
    }

    /// Two overlapping batches race one parent. The store's conditional CAS adjudicates the
    /// race itself; this pins the loser's behavior — a 412 must never surface as `Committed`
    /// — and proves authoritative replay reaches exactly the winning batch's cursor.
    #[tokio::test]
    async fn a_losing_batch_cas_never_reports_committed_and_replay_reaches_the_winner() {
        let genesis = genesis();
        let scope = genesis.identity().clone();
        let winner_batch = successor_batch(
            &scope,
            genesis.event_ref(),
            2,
            &["win-op-2", "win-op-3", "win-op-4"],
        );
        let winner_events: Vec<(ScopeEventRef, Vec<u8>)> = winner_batch
            .iter()
            .map(|(_, encoded)| (encoded.event_ref().clone(), encoded.stored_bytes().to_vec()))
            .collect();
        let winner_head = ScopeHead::new(
            scope.clone(),
            ScopeAuthority::Unowned,
            1,
            winner_events[2].0.clone(),
            None,
            "win-op-4".into(),
        )
        .unwrap();
        let (store, _) = replay_store(vec![
            response(
                200,
                &[("etag", "\"parent\"")],
                encode_head(genesis.head()).unwrap(),
            ),
            response(200, &[], SdkBody::empty()),
            response(200, &[], SdkBody::empty()),
            response(200, &[], SdkBody::empty()),
            response(200, &[("etag", "\"won\"")], SdkBody::empty()),
        ]);
        let parent = read(&store, &scope).await.unwrap().unwrap();
        assert!(matches!(
            append_batch(
                &store,
                ScopeHeadParent::existing(Box::new(parent)),
                &scope,
                winner_batch,
                &mut AttemptHistory::default(),
            )
            .await
            .unwrap(),
            ScopeHeadCommitOutcome::Committed(_)
        ));

        // The loser publishes its members, loses the CAS, and the retained walk proves its
        // final operation absent between the winner's tail and the shared parent boundary.
        let loser_batch =
            successor_batch(&scope, genesis.event_ref(), 2, &["lose-op-2", "lose-op-3"]);
        let mut responses = lost_cas_prelude(encode_head(genesis.head()).unwrap(), 412);
        responses.extend([
            response(
                200,
                &[("etag", "\"winner\"")],
                encode_head(&winner_head).unwrap(),
            ),
            response(404, &[], SdkBody::empty()),
        ]);
        responses.extend(
            winner_events
                .iter()
                .rev()
                .map(|(_, bytes)| response(200, &[("etag", "\"event\"")], bytes.clone())),
        );
        let (store, client) = replay_store(responses);
        let parent = read(&store, &scope).await.unwrap().unwrap();
        assert!(matches!(
            append_batch(
                &store,
                ScopeHeadParent::existing(Box::new(parent)),
                &scope,
                loser_batch,
                &mut AttemptHistory::default(),
            )
            .await
            .unwrap(),
            ScopeHeadCommitOutcome::ProvenNotCommitted
        ));
        assert_eq!(
            client.actual_requests().count(),
            9,
            "parent read + 2 event PUTs + lost CAS + head reread + pointer miss + 3 winner reads"
        );

        // Authoritative replay of the winning head folds the whole batch at its cursor.
        let path = std::env::temp_dir().join(format!(
            "ravel-head-batch-race-{}.sqlite3",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let handle = crate::db::worker::DbHandle::spawn(path.clone())
            .await
            .unwrap();
        let mut responses = vec![
            response(
                200,
                &[("etag", "\"winner\"")],
                encode_head(&winner_head).unwrap(),
            ),
            response(404, &[], SdkBody::empty()),
            response(404, &[], SdkBody::empty()),
        ];
        responses.extend(
            winner_events
                .iter()
                .rev()
                .map(|(_, bytes)| response(200, &[("etag", "\"event\"")], bytes.clone())),
        );
        responses.push(response(
            200,
            &[("etag", "\"event\"")],
            genesis.event_bytes().to_vec(),
        ));
        let (store, _) = replay_store(responses);
        match crate::sync::replay::refresh(&store, &handle, &scope).await {
            crate::sync::replay::ScopeReadiness::Ready { local_cursor, .. } => {
                assert_eq!(local_cursor.0, 4);
                assert_eq!(local_cursor.1, *winner_events[2].0.digest());
            }
            crate::sync::replay::ScopeReadiness::NotReady(error) => {
                panic!("replay must reach the winning head: {error}")
            }
        }
        drop(handle);
        let _ = std::fs::remove_file(&path);
    }

    /// The fixed opening of a lost-CAS scenario: parent read, both event PUTs, and the CAS
    /// failure that hides the outcome. Scenario tails stay inline because their response
    /// order is the reconciliation walk under test.
    fn lost_cas_prelude(parent_bytes: Vec<u8>, failure: u16) -> Vec<http::Response<SdkBody>> {
        vec![
            response(200, &[("etag", "\"parent\"")], parent_bytes),
            response(200, &[], SdkBody::empty()),
            response(200, &[], SdkBody::empty()),
            response(failure, &[], SdkBody::empty()),
        ]
    }

    /// A lost batch CAS response reconciles by the batch's final operation identity: the exact
    /// candidate proves committed, a longer winning batch containing the complete candidate
    /// batch proves superseded, and a rival chain reaching the shared boundary without the
    /// final operation proves not committed.
    #[tokio::test]
    async fn a_lost_batch_cas_reconciles_by_the_final_operation_identity() {
        let genesis = genesis();
        let scope = genesis.identity().clone();

        // Committed: the current head is exactly the candidate and its tail bytes match.
        let batch = successor_batch(&scope, genesis.event_ref(), 2, &["lost-op-2", "lost-op-3"]);
        let tail_ref = batch[1].1.event_ref().clone();
        let tail_bytes = batch[1].1.stored_bytes().to_vec();
        let candidate = ScopeHead::new(
            scope.clone(),
            ScopeAuthority::Unowned,
            1,
            tail_ref,
            None,
            "lost-op-3".into(),
        )
        .unwrap();
        let mut responses = lost_cas_prelude(encode_head(genesis.head()).unwrap(), 500);
        responses.extend([
            response(
                200,
                &[("etag", "\"candidate\"")],
                encode_head(&candidate).unwrap(),
            ),
            response(200, &[("etag", "\"event\"")], tail_bytes),
        ]);
        let (store, client) = replay_store(responses);
        let parent = read(&store, &scope).await.unwrap().unwrap();
        let outcome = append_batch(
            &store,
            ScopeHeadParent::existing(Box::new(parent)),
            &scope,
            batch,
            &mut AttemptHistory::default(),
        )
        .await
        .unwrap();
        let ScopeHeadCommitOutcome::Committed(Some(witness)) = outcome else {
            panic!("the lost CAS must resolve to a committed head witness");
        };
        assert_eq!(witness.head().tail(), candidate.tail());
        assert_eq!(witness.head().operation_id(), "lost-op-3");
        assert_eq!(
            client.actual_requests().count(),
            6,
            "parent read + 2 event PUTs + lost CAS + head reread + tail readback"
        );

        // CommittedSuperseded: a longer winning batch carries our two members plus one more.
        let ours = successor_batch(
            &scope,
            genesis.event_ref(),
            2,
            &["super-op-2", "super-op-3"],
        );
        let our_events: Vec<(ScopeEventRef, Vec<u8>)> = ours
            .iter()
            .map(|(_, encoded)| (encoded.event_ref().clone(), encoded.stored_bytes().to_vec()))
            .collect();
        let (_, extension) = successor(&scope, &our_events[1].0, 4, "super-op-4");
        let longer_head = ScopeHead::new(
            scope.clone(),
            ScopeAuthority::Unowned,
            1,
            extension.event_ref().clone(),
            None,
            "super-op-4".into(),
        )
        .unwrap();
        let mut responses = lost_cas_prelude(encode_head(genesis.head()).unwrap(), 500);
        responses.extend([
            response(
                200,
                &[("etag", "\"longer\"")],
                encode_head(&longer_head).unwrap(),
            ),
            response(404, &[], SdkBody::empty()),
            response(
                200,
                &[("etag", "\"e4\"")],
                extension.stored_bytes().to_vec(),
            ),
            response(200, &[("etag", "\"e3\"")], our_events[1].1.clone()),
            response(200, &[("etag", "\"e2\"")], our_events[0].1.clone()),
        ]);
        let (store, client) = replay_store(responses);
        let parent = read(&store, &scope).await.unwrap().unwrap();
        assert!(matches!(
            append_batch(
                &store,
                ScopeHeadParent::existing(Box::new(parent)),
                &scope,
                ours,
                &mut AttemptHistory::default(),
            )
            .await
            .unwrap(),
            ScopeHeadCommitOutcome::CommittedSuperseded
        ));
        assert_eq!(
            client.actual_requests().count(),
            9,
            "parent read + 2 event PUTs + lost CAS + head reread + pointer miss + 3 chain reads"
        );

        // ProvenNotCommitted: a rival chain fills the boundary range without our final
        // operation.
        let mine = successor_batch(&scope, genesis.event_ref(), 2, &["mine-op-2", "mine-op-3"]);
        let rivals = successor_batch(
            &scope,
            genesis.event_ref(),
            2,
            &["rival-op-2", "rival-op-3"],
        );
        let rival_head = ScopeHead::new(
            scope.clone(),
            ScopeAuthority::Unowned,
            1,
            rivals[1].1.event_ref().clone(),
            None,
            "rival-op-3".into(),
        )
        .unwrap();
        let mut responses = lost_cas_prelude(encode_head(genesis.head()).unwrap(), 412);
        responses.extend([
            response(
                200,
                &[("etag", "\"rival\"")],
                encode_head(&rival_head).unwrap(),
            ),
            response(404, &[], SdkBody::empty()),
            response(
                200,
                &[("etag", "\"r3\"")],
                rivals[1].1.stored_bytes().to_vec(),
            ),
            response(
                200,
                &[("etag", "\"r2\"")],
                rivals[0].1.stored_bytes().to_vec(),
            ),
        ]);
        let (store, client) = replay_store(responses);
        let parent = read(&store, &scope).await.unwrap().unwrap();
        assert!(matches!(
            append_batch(
                &store,
                ScopeHeadParent::existing(Box::new(parent)),
                &scope,
                mine,
                &mut AttemptHistory::default(),
            )
            .await
            .unwrap(),
            ScopeHeadCommitOutcome::ProvenNotCommitted
        ));
        assert_eq!(
            client.actual_requests().count(),
            8,
            "parent read + 2 event PUTs + lost CAS + head reread + pointer miss + 2 rival reads"
        );
    }
}
