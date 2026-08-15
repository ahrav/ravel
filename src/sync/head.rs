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
    domain::proposal::AdmissibleProposal,
    scope::{
        EventEnvelope, MAX_HEAD_BYTES, PLAN_ADMITTED_PAYLOAD_TYPE, PlanAdmittedEvent,
        ScopeAuthority, ScopeHead, ScopeIdentity, decode_head, decode_plan_admitted_event,
        encode_head, encode_plan_admitted_event, plan_key, scope_event_key, scope_head_key,
    },
    storage::s3::{AttemptHistory, ETag, GetError, GetOutcome, MutationOutcome, S3Store},
};

use super::{
    WireError,
    event::{
        ResolvedScopeEventPublication, ScopeEventPublicationError, payload_registered,
        publish_encoded, publish_root, read_opaque, root_domain_valid, root_payload_valid,
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
    /// Returns [`WireError::InvalidValue`] when any of those bindings fails, or another
    /// [`WireError`] when the candidate head cannot be canonically encoded.
    pub fn new(
        parent: ScopeHeadParent,
        candidate: ScopeHead,
        event: ResolvedScopeEventPublication,
    ) -> Result<Self, WireError> {
        let envelope = event.envelope();
        if candidate.scope() != event.scope()
            || candidate.tail() != event.event_ref()
            || candidate.operation_id() != envelope.operation_id()
            || envelope.scope_id() != candidate.scope().scope_id()
            || envelope.writer_epoch() != candidate.scope_epoch()
        {
            return Err(WireError::InvalidValue);
        }
        match &parent {
            ScopeHeadParent::Genesis => {
                if envelope.sequence() != 1
                    || envelope.parent_event().is_some()
                    || candidate.active_plan_digest().is_some()
                    || !matches!(candidate.authority(), ScopeAuthority::Unowned)
                    || candidate.scope_epoch().get() != 1
                {
                    return Err(WireError::InvalidValue);
                }
            }
            ScopeHeadParent::Existing(observed) => {
                let expected = observed
                    .head
                    .tail()
                    .sequence()
                    .checked_add(1)
                    .ok_or(WireError::InvalidValue)?;
                if candidate.scope() != observed.head.scope()
                    || candidate.authority() != observed.head.authority()
                    || candidate.scope_epoch() != observed.head.scope_epoch()
                    || envelope.sequence() != expected
                    || envelope.parent_event() != Some(observed.head.tail())
                    || candidate.operation_id() == observed.head.operation_id()
                {
                    return Err(WireError::InvalidValue);
                }
                validate_active_plan_transition(observed.head(), &candidate, &event)?;
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
    /// Candidate is the authoritative head.
    Committed,
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

/// The one rule for how an event may move a head's active plan.
///
/// A `plan_admitted` event moves it from none to exactly the digest its own payload names; every
/// other event preserves it. The payload is re-decoded from the published bytes, so the head
/// cannot disagree with the event that authorized it.
///
/// # Errors
///
/// Returns [`WireError::InvalidValue`] for any other movement, and decode errors verbatim.
fn validate_active_plan_transition(
    observed: &ScopeHead,
    candidate: &ScopeHead,
    event: &ResolvedScopeEventPublication,
) -> Result<(), WireError> {
    if event.envelope().payload_type() != PLAN_ADMITTED_PAYLOAD_TYPE {
        return if candidate.active_plan_digest() == observed.active_plan_digest() {
            Ok(())
        } else {
            Err(WireError::InvalidValue)
        };
    }
    let key = scope_event_key(candidate.scope(), event.event_ref());
    let admitted = decode_plan_admitted_event(event.canonical_bytes(), &key, candidate.scope())?;
    if observed.active_plan_digest().is_some()
        || candidate.active_plan_digest() != Some(admitted.payload().plan_digest())
    {
        return Err(WireError::InvalidValue);
    }
    Ok(())
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
    let sequence = observed
        .head()
        .tail()
        .sequence()
        .checked_add(1)
        .ok_or(ScopeAppendError::InvalidInput)?;
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
        MutationOutcome::Committed { .. } => ScopeHeadCommitOutcome::Committed,
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
                ScopeHeadCommitOutcome::Committed
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
    let mut current_ref = current.head.tail().clone();
    let hops = match &boundary {
        Some((boundary, _)) if current_ref.sequence() > boundary.sequence() => {
            current_ref.sequence() - boundary.sequence()
        }
        Some(_) => return ScopeHeadCommitOutcome::Unresolved(transition),
        None => current_ref.sequence(),
    };
    if hops > MAX_RECONCILE_HOPS {
        return ScopeHeadCommitOutcome::Unresolved(transition);
    }
    let mut seen = HashSet::new();
    let mut total_bytes = 0usize;
    let mut found = false;
    let mut child_writer_epoch: Option<NonZeroU64> = None;
    for hop in 0..hops {
        if !seen.insert(current_ref.digest().as_str().to_owned()) {
            return ScopeHeadCommitOutcome::Unresolved(transition);
        }
        let (decoded, bytes) =
            match read_opaque(store, transition.candidate.scope(), &current_ref).await {
                Ok(Some(event)) => event,
                Ok(None) | Err(_) => return ScopeHeadCommitOutcome::Unresolved(transition),
            };
        total_bytes = match total_bytes.checked_add(bytes.len()) {
            Some(total) if total <= MAX_RECONCILE_BYTES => total,
            _ => return ScopeHeadCommitOutcome::Unresolved(transition),
        };
        if !payload_registered(decoded.envelope())
            || !root_domain_valid(decoded.envelope())
            || !root_payload_valid(&decoded, transition.candidate.scope())
        {
            return ScopeHeadCommitOutcome::Unresolved(transition);
        }
        if hop == 0 && decoded.envelope().operation_id() != current.head.operation_id() {
            return ScopeHeadCommitOutcome::Unresolved(transition);
        }
        let writer_epoch = decoded.envelope().writer_epoch();
        if writer_epoch > current.head.scope_epoch()
            || child_writer_epoch.is_some_and(|child| writer_epoch > child)
        {
            return ScopeHeadCommitOutcome::Unresolved(transition);
        }
        child_writer_epoch = Some(writer_epoch);
        if decoded.envelope().operation_id() == transition.candidate.operation_id() {
            if current_ref != *transition.candidate.tail()
                || bytes != transition.event.canonical_bytes()
                || decoded.envelope() != transition.event.envelope()
            {
                return ScopeHeadCommitOutcome::Unresolved(transition);
            }
            found = true;
        } else if current_ref == *transition.candidate.tail() {
            return ScopeHeadCommitOutcome::Unresolved(transition);
        }
        let reached = match &boundary {
            Some((boundary, _)) => decoded.envelope().parent_event() == Some(boundary),
            None => {
                decoded.envelope().sequence() == 1 && decoded.envelope().parent_event().is_none()
            }
        };
        if reached {
            if let Some((_, boundary_epoch)) = &boundary
                && writer_epoch < *boundary_epoch
            {
                return ScopeHeadCommitOutcome::Unresolved(transition);
            }
            return if found {
                ScopeHeadCommitOutcome::CommittedSuperseded
            } else {
                ScopeHeadCommitOutcome::ProvenNotCommitted
            };
        }
        let Some(parent) = decoded.envelope().parent_event() else {
            return ScopeHeadCommitOutcome::Unresolved(transition);
        };
        current_ref = parent.clone();
    }
    ScopeHeadCommitOutcome::Unresolved(transition)
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
            ScopeHeadCommitOutcome::Committed
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
            ScopeHeadCommitOutcome::Committed
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
                matches!(outcome, ScopeHeadCommitOutcome::Committed),
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
                matches!(outcome, ScopeHeadCommitOutcome::Committed),
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
        assert_eq!(client.actual_requests().count(), 3);
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
        assert_eq!(client.actual_requests().count(), 4);
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
            ScopeHeadCommitOutcome::Committed
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
        assert_eq!(client.actual_requests().count(), 3);
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
            ScopeHeadCommitOutcome::Committed
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
}
