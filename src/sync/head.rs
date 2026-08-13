//! Root-only scoped head transitions and retained-chain reconciliation.
//!
//! Accepts only unowned epoch-1 transitions with an unchanged active plan digest.
//! Retained walks stop at 4,096 events or 64 MiB of stored event bytes.

use std::{collections::HashSet, error::Error, fmt};

use crate::{
    scope::{
        MAX_HEAD_BYTES, ScopeAuthority, ScopeHead, ScopeIdentity, decode_head, encode_head,
        scope_head_key,
    },
    storage::s3::{AttemptHistory, ETag, GetError, GetOutcome, MutationOutcome, S3Store},
};

use super::{
    WireError,
    event::{
        ResolvedScopeEventPublication, ScopeEventPublicationError, payload_registered,
        publish_root, read_opaque, root_domain_valid, root_payload_valid,
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
    pub fn head(&self) -> &ScopeHead {
        &self.head
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.bytes
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
    Existing(Box<ObservedScopeHead>),
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
    /// Root transitions remain unowned at epoch 1. Genesis requires sequence 1, no
    /// parent, and no active plan. Successors require the exact observed tail, a new
    /// operation ID, and an unchanged active plan.
    ///
    /// # Errors
    ///
    /// Returns [`WireError`] when any binding or canonical encoding check fails.
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
            || !matches!(candidate.authority(), ScopeAuthority::Unowned)
            || candidate.scope_epoch().get() != 1
            || envelope.writer_epoch().get() != 1
        {
            return Err(WireError::InvalidValue);
        }
        match &parent {
            ScopeHeadParent::Genesis => {
                if envelope.sequence() != 1
                    || envelope.parent_event().is_some()
                    || candidate.active_plan_digest().is_some()
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
                    || !matches!(observed.head.authority(), ScopeAuthority::Unowned)
                    || observed.head.scope_epoch().get() != 1
                    || envelope.sequence() != expected
                    || envelope.parent_event() != Some(observed.head.tail())
                    || candidate.operation_id() == observed.head.operation_id()
                    || candidate.active_plan_digest() != observed.head.active_plan_digest()
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
            observed.namespace = namespace.to_owned();
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

/// Publishes immutable event bytes before validating or mutating the head.
///
/// A later head-validation failure can leave an unreferenced immutable event.
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
    let publication = publish_root(store, scope, event, event_history)
        .await
        .map_err(ScopeAppendError::Publication)?;
    let candidate = ScopeHead::new(
        scope.clone(),
        ScopeAuthority::Unowned,
        1,
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
        if current.bytes != transition.head_bytes {
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
        transition.parent = ScopeHeadParent::Existing(Box::new(current));
        return ScopeHeadCommitOutcome::RetryIdentically(transition);
    }
    if let ScopeHeadParent::Existing(parent) = &transition.parent
        && current.head.operation_id() == parent.head.operation_id()
    {
        return ScopeHeadCommitOutcome::Unresolved(transition);
    }

    reconcile(store, transition, current).await
}

pub(crate) fn root_head_supported(head: &ScopeHead) -> bool {
    matches!(head.authority(), ScopeAuthority::Unowned)
        && head.scope_epoch().get() == 1
        && head.active_plan_digest().is_none()
}

async fn reconcile(
    store: &S3Store,
    transition: ScopeHeadTransition,
    current: ObservedScopeHead,
) -> ScopeHeadCommitOutcome {
    if !root_head_supported(&current.head) {
        return ScopeHeadCommitOutcome::Unresolved(transition);
    }
    let boundary = match &transition.parent {
        ScopeHeadParent::Genesis => None,
        ScopeHeadParent::Existing(parent) => Some(parent.head.tail().clone()),
    };
    let mut current_ref = current.head.tail().clone();
    let hops = match &boundary {
        Some(boundary) if current_ref.sequence() > boundary.sequence() => {
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
            Some(boundary) => decoded.envelope().parent_event() == Some(boundary),
            None => {
                decoded.envelope().sequence() == 1 && decoded.envelope().parent_event().is_none()
            }
        };
        if reached {
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
        let envelope = EventEnvelope::new(
            scope.scope_id().clone(),
            sequence,
            Some(parent.clone()),
            1,
            operation.into(),
            TEST_SUCCESSOR_PAYLOAD_TYPE.into(),
        )
        .unwrap();
        let encoded = encode_scope_event(&envelope, &Value::Null).unwrap();
        (envelope, encoded)
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
            ScopeHeadParent::Existing(Box::new(observed(&parent).await)),
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
            ScopeHeadParent::Existing(Box::new(observed(&parent).await)),
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
            ScopeHeadParent::Existing(Box::new(observed(genesis.head()).await)),
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
                ScopeHeadParent::Existing(Box::new(observed(genesis.head()).await)),
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
            ScopeHeadParent::Existing(Box::new(observed(genesis.head()).await)),
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
                ScopeHeadParent::Existing(Box::new(observed(genesis.head()).await)),
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
                ScopeHeadParent::Existing(Box::new(observed(genesis.head()).await)),
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
                ScopeHeadParent::Existing(Box::new(observed(genesis.head()).await)),
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
                ScopeHeadParent::Existing(Box::new(observed(genesis.head()).await)),
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
                ScopeHeadParent::Existing(Box::new(observed(genesis.head()).await)),
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
                ScopeHeadParent::Existing(Box::new(observed(genesis.head()).await)),
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
                ScopeHeadParent::Existing(Box::new(observed(genesis.head()).await)),
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
                ScopeHeadParent::Existing(Box::new(observed(genesis.head()).await)),
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
                ScopeHeadParent::Existing(Box::new(observed(genesis.head()).await)),
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
                ScopeHeadParent::Existing(Box::new(observed(&owned_parent).await)),
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
            ScopeHeadParent::Existing(Box::new(observed(&parent).await)),
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
            ScopeHeadParent::Existing(Box::new(observed(&parent).await)),
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
            ScopeHeadParent::Existing(Box::new(observed(&parent).await)),
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
            ScopeHeadParent::Existing(Box::new(observed(&parent).await)),
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
}
