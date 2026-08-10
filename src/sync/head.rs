//! The v1 head encoding is frozen.
//!
//! Head bytes are compact UTF-8 JSON with no whitespace or trailing newline.
//! Field order is part of v1's canonical encoding: `version`, `authority`,
//! `tail`, then `operation_id`. Authority is `{"state":"unowned"}` or an
//! owned map with `owner`, `instance`, `lease_until`, and `controller_fence`.
//! Tail contains `sequence`, `digest`, then `key`. The decoder compares input
//! bytes with the production re-encoding before domain conversion; this rejects
//! extra fields on internally tagged unowned unit variants.
//!
//! Head transitions retain canonical bytes. commentlint: allow(JUDGE)
//! Conditional mutation and resolution preserve observed ETags. commentlint: allow(JUDGE)
//! Retained-chain reconciliation handles advanced heads. commentlint: allow(JUDGE)
//! Authority ordering is enforced in `authority_permits`. commentlint: allow(JUDGE)

use std::{error::Error, fmt};

use serde::{Deserialize, Serialize};

use crate::{
    domain::campaign::{Authority, AuthorityState, Event, EventRef, Head},
    storage::{
        artifacts::PublishedArtifact,
        s3::{
            AttemptHistory, ETag, GetError, GetOutcome, MutationOutcome, PublicationError, S3Store,
        },
    },
};

use super::{
    WIRE_VERSION, WireError,
    event::{self, ResolvedEventPublication},
};

const HEAD_KEY: &str = "head.json";
const MAX_HEAD_BYTES: usize = 4 * 1024;

pub struct ObservedHead {
    head: Head,
    bytes: Vec<u8>,
    etag: ETag,
    /// Namespace this head was read from.
    namespace: String,
}

impl ObservedHead {
    pub fn head(&self) -> &Head {
        &self.head
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[derive(Debug)]
pub enum HeadReadError {
    Storage(GetError),
    Invalid(WireError),
}

impl fmt::Display for HeadReadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Storage(_) => "head read failed",
            Self::Invalid(_) => "head encoding is invalid",
        })
    }
}

impl Error for HeadReadError {}

pub enum HeadParent {
    Genesis,
    Existing(Box<ObservedHead>),
}

pub struct HeadTransition {
    parent: HeadParent,
    candidate: Head,
    head_bytes: Vec<u8>,
    event_bytes: Vec<u8>,
    /// Namespace the tail event was published into.
    event_namespace: String,
}

impl HeadTransition {
    pub fn new(
        parent: HeadParent,
        candidate: Head,
        tail: &Event,
        publication: &ResolvedEventPublication,
    ) -> Result<Self, WireError> {
        let encoded = event::encode(tail)?;
        let published = publication.event_ref();
        if candidate.tail() != published
            || tail.sequence() != candidate.tail().sequence()
            || encoded.key() != published.key()
            || encoded.digest() != published.digest()
        {
            return Err(WireError::InvalidValue);
        }

        match &parent {
            HeadParent::Genesis => {
                if tail.sequence() != 1
                    || tail.parent().is_some()
                    || !matches!(candidate.authority().state(), AuthorityState::Unowned)
                {
                    return Err(WireError::InvalidValue);
                }
            }
            HeadParent::Existing(observed) => {
                let expected_sequence = observed
                    .head
                    .tail()
                    .sequence()
                    .checked_add(1)
                    .ok_or(WireError::InvalidValue)?;
                if candidate.operation_id() == observed.head.operation_id()
                    || tail.sequence() != expected_sequence
                    || tail.parent() != Some(observed.head.tail())
                    || !authority_permits(&observed.head, &candidate)
                    || !tail_fence_matches(tail, &candidate)
                {
                    return Err(WireError::InvalidValue);
                }
            }
        }

        let head_bytes = encode(&candidate)?;
        if head_bytes.len() > MAX_HEAD_BYTES {
            return Err(WireError::LimitExceeded);
        }
        Ok(Self {
            parent,
            candidate,
            head_bytes,
            event_bytes: encoded.stored_bytes().to_vec(),
            event_namespace: publication.namespace().to_owned(),
        })
    }

    pub fn parent(&self) -> &HeadParent {
        &self.parent
    }

    pub fn candidate(&self) -> &Head {
        &self.candidate
    }

    pub fn canonical_head_bytes(&self) -> &[u8] {
        &self.head_bytes
    }

    pub fn canonical_event_bytes(&self) -> &[u8] {
        &self.event_bytes
    }

    /// Re-labels the namespace this transition's tail was published into.
    ///
    /// Fixtures publish a tail through a throwaway store and then commit through
    /// the store under test, so they restate which store holds the tail rather
    /// than owning both response queues.
    #[cfg(test)]
    pub(crate) fn attributed_to(mut self, namespace: &str) -> Self {
        self = self.with_tail_attributed_to(namespace);
        if let HeadParent::Existing(observed) = &mut self.parent {
            observed.namespace = namespace.to_owned();
        }
        self
    }

    /// Re-labels only the tail's namespace, leaving the observed parent naming the
    /// store it was read from.
    #[cfg(test)]
    pub(crate) fn with_tail_attributed_to(mut self, namespace: &str) -> Self {
        self.event_namespace = namespace.to_owned();
        self
    }
}

#[must_use]
pub enum HeadCommitOutcome {
    Committed,
    /// Candidate event is authoritative, including under a different current head operation.
    CommittedSuperseded,
    ProvenNotCommitted,
    RetryIdentically(HeadTransition),
    Unresolved(HeadTransition),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AppendError {
    Publication(PublicationError),
    InvalidInput,
}

impl fmt::Display for AppendError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Publication(_) => "event publication failed",
            Self::InvalidInput => "invalid append input",
        })
    }
}

impl Error for AppendError {}

pub async fn append(
    store: &S3Store,
    parent: HeadParent,
    authority: Authority,
    tail: &Event,
    artifact: Option<&PublishedArtifact>,
    history: &mut AttemptHistory,
) -> Result<HeadCommitOutcome, AppendError> {
    let publication = event::publish(store, tail, artifact)
        .await
        .map_err(AppendError::Publication)?;
    // One append is one commit identity. Reconciliation walks retained events and
    // searches the operation id, so a head recording a different id than its tail
    // would be reconciled under two identities for the same logical append.
    let candidate = Head::new(
        authority,
        publication.event_ref().clone(),
        tail.operation_id().to_owned(),
    )
    .map_err(|_| AppendError::InvalidInput)?;
    let transition = HeadTransition::new(parent, candidate, tail, &publication)
        .map_err(|_| AppendError::InvalidInput)?;
    Ok(commit(store, transition, history).await)
}

pub async fn read(store: &S3Store) -> Result<Option<ObservedHead>, HeadReadError> {
    let outcome =
        store
            .get_object(HEAD_KEY, MAX_HEAD_BYTES)
            .await
            .map_err(|error| match error {
                GetError::TooLarge => HeadReadError::Invalid(WireError::LimitExceeded),
                other => HeadReadError::Storage(other),
            })?;
    match outcome {
        GetOutcome::NotFound => Ok(None),
        GetOutcome::Found { bytes, etag } => {
            let head = decode(&bytes).map_err(HeadReadError::Invalid)?;
            Ok(Some(ObservedHead {
                head,
                bytes,
                etag,
                namespace: store.namespace().to_owned(),
            }))
        }
    }
}

/// Each retry of a returned transition uses the same [`AttemptHistory`].
pub async fn commit(
    store: &S3Store,
    transition: HeadTransition,
    history: &mut AttemptHistory,
) -> HeadCommitOutcome {
    // A head is authoritative over the tail it references, so that tail has to live
    // in the store this head is committed through. Committing across namespaces
    // would publish a head whose event object cannot be read back.
    if transition.event_namespace != store.namespace() {
        return HeadCommitOutcome::Unresolved(transition);
    }
    // The observed parent's ETag becomes this store's `If-Match` token, so an
    // observation from elsewhere could compare-and-swap a head that was never read
    // in this namespace if the two happen to share an opaque token.
    if let HeadParent::Existing(observed) = &transition.parent
        && observed.namespace != store.namespace()
    {
        return HeadCommitOutcome::Unresolved(transition);
    }
    let outcome = match &transition.parent {
        HeadParent::Genesis => {
            store
                .put_if_absent(HEAD_KEY, transition.head_bytes.clone(), history)
                .await
        }
        HeadParent::Existing(observed) => {
            store
                .put_if_match(
                    HEAD_KEY,
                    transition.head_bytes.clone(),
                    &observed.etag,
                    history,
                )
                .await
        }
    };
    match outcome {
        MutationOutcome::Committed { .. } => HeadCommitOutcome::Committed,
        MutationOutcome::ProvenNotSent => HeadCommitOutcome::RetryIdentically(transition),
        MutationOutcome::Conflict
        | MutationOutcome::PreconditionFailed
        | MutationOutcome::AmbiguousConflict
        | MutationOutcome::Unknown => resolve(store, transition).await,
        MutationOutcome::NotFound | MutationOutcome::TooLarge => {
            HeadCommitOutcome::Unresolved(transition)
        }
    }
}

async fn resolve(store: &S3Store, mut transition: HeadTransition) -> HeadCommitOutcome {
    let current = match read(store).await {
        Ok(Some(current)) => current,
        Ok(None) => {
            return match transition.parent {
                HeadParent::Genesis => HeadCommitOutcome::RetryIdentically(transition),
                HeadParent::Existing(_) => HeadCommitOutcome::Unresolved(transition),
            };
        }
        Err(_) => return HeadCommitOutcome::Unresolved(transition),
    };

    if current.head.operation_id() == transition.candidate.operation_id() {
        if current.bytes != transition.head_bytes {
            return HeadCommitOutcome::Unresolved(transition);
        }
        let tail_key = transition.candidate.tail().key();
        let tail = store
            .get_object(tail_key, transition.event_bytes.len())
            .await;
        return match tail {
            Ok(GetOutcome::Found { bytes, .. })
                if bytes == transition.event_bytes && event::decode(&bytes, tail_key).is_ok() =>
            {
                HeadCommitOutcome::Committed
            }
            Ok(GetOutcome::Found { .. }) | Ok(GetOutcome::NotFound) | Err(_) => {
                HeadCommitOutcome::Unresolved(transition)
            }
        };
    }

    let parent_is_current = match &transition.parent {
        HeadParent::Genesis => false,
        HeadParent::Existing(parent) => parent.bytes == current.bytes,
    };
    if parent_is_current {
        transition.parent = HeadParent::Existing(Box::new(current));
        return HeadCommitOutcome::RetryIdentically(transition);
    }

    // A current head that reuses the observed parent's operation identity while
    // carrying different bytes means one operation id names two distinct heads.
    // Reconciliation has no way to pick between them, so it is not consulted.
    if let HeadParent::Existing(parent) = &transition.parent
        && current.head.operation_id() == parent.head.operation_id()
    {
        return HeadCommitOutcome::Unresolved(transition);
    }

    crate::recovery::reconcile::reconcile(store, transition, current).await
}

/// An owned head claims that its controller published the tail, so the tail's
/// `writer_fence` has to equal the candidate's `controller_fence`. Without the
/// equality a stale-fence event can be published first and then presented under a
/// higher-fence head, leaving authoritative history attributed to an old fence.
fn tail_fence_matches(tail: &Event, candidate: &Head) -> bool {
    match candidate.authority().state() {
        AuthorityState::Owned {
            controller_fence, ..
        } => tail.writer_fence() == *controller_fence,
        AuthorityState::Unowned => true,
    }
}

/// An unowned successor to an owned head would let any holder of the current
/// ETag strip the controller fence through the ordinary `If-Match` CAS, so the
/// non-regression check rejects it rather than falling through.
fn authority_permits(parent: &Head, candidate: &Head) -> bool {
    match (parent.authority().state(), candidate.authority().state()) {
        (
            AuthorityState::Owned {
                controller_fence: parent_fence,
                ..
            },
            AuthorityState::Owned {
                controller_fence: candidate_fence,
                ..
            },
        ) => candidate_fence >= parent_fence,
        (AuthorityState::Owned { .. }, AuthorityState::Unowned) => false,
        _ => true,
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireHead {
    version: u64,
    authority: WireAuthority,
    tail: WireEventRef,
    operation_id: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, tag = "state", rename_all = "snake_case")]
enum WireAuthority {
    Unowned,
    Owned {
        owner: String,
        instance: String,
        lease_until: u64,
        controller_fence: u64,
    },
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireEventRef {
    sequence: u64,
    digest: String,
    key: String,
}

pub fn encode(head: &Head) -> Result<Vec<u8>, WireError> {
    serde_json::to_vec(&WireHead::from(head)).map_err(|_| WireError::InvalidEncoding)
}

pub fn decode(bytes: &[u8]) -> Result<Head, WireError> {
    if bytes.is_empty() || bytes.len() > MAX_HEAD_BYTES {
        return Err(WireError::LimitExceeded);
    }
    let wire: WireHead = serde_json::from_slice(bytes).map_err(|_| WireError::InvalidEncoding)?;
    let canonical = serde_json::to_vec(&wire).map_err(|_| WireError::InvalidEncoding)?;
    if canonical != bytes {
        return Err(WireError::NonCanonical);
    }
    wire.try_into()
}

impl From<&Head> for WireHead {
    fn from(head: &Head) -> Self {
        Self {
            version: WIRE_VERSION,
            authority: WireAuthority::from(head.authority()),
            tail: WireEventRef::from(head.tail()),
            operation_id: head.operation_id().to_owned(),
        }
    }
}

impl From<&Authority> for WireAuthority {
    fn from(authority: &Authority) -> Self {
        match authority.state() {
            AuthorityState::Unowned => Self::Unowned,
            AuthorityState::Owned {
                owner,
                instance,
                lease_until,
                controller_fence,
            } => Self::Owned {
                owner: owner.clone(),
                instance: instance.clone(),
                lease_until: *lease_until,
                controller_fence: *controller_fence,
            },
        }
    }
}

impl From<&EventRef> for WireEventRef {
    fn from(event_ref: &EventRef) -> Self {
        Self {
            sequence: event_ref.sequence(),
            digest: event_ref.digest().to_owned(),
            key: event_ref.key().to_owned(),
        }
    }
}

impl TryFrom<WireHead> for Head {
    type Error = WireError;

    fn try_from(wire: WireHead) -> Result<Self, Self::Error> {
        if wire.version != WIRE_VERSION {
            return Err(WireError::InvalidValue);
        }
        let authority = Authority::try_from(wire.authority)?;
        let tail = EventRef::new(wire.tail.sequence, wire.tail.digest, wire.tail.key)
            .map_err(|_| WireError::InvalidValue)?;
        Head::new(authority, tail, wire.operation_id).map_err(|_| WireError::InvalidValue)
    }
}

impl TryFrom<WireAuthority> for Authority {
    type Error = WireError;

    fn try_from(authority: WireAuthority) -> Result<Self, Self::Error> {
        match authority {
            WireAuthority::Unowned => Ok(Self::unowned()),
            WireAuthority::Owned {
                owner,
                instance,
                lease_until,
                controller_fence,
            } => Self::owned(owner, instance, lease_until, controller_fence)
                .map_err(|_| WireError::InvalidValue),
        }
    }
}

#[cfg(test)]
mod tests {
    use aws_sdk_s3::{config::Region, primitives::SdkBody};
    use aws_smithy_runtime::client::http::test_util::NeverClient;

    use crate::{
        domain::campaign::{ArtifactRef, EventContent},
        storage::s3::test_support::{replay_store, response, test_builder},
    };

    use super::*;

    const OWNED_HEAD: &[u8] = include_bytes!("../../tests/fixtures/v1/head-owned.json");
    const OLD_ETAG: &str = "\"opaque-old\"";
    const FRESH_ETAG: &str = "\"opaque-fresh\"";

    fn event_reference(event: &Event) -> EventRef {
        let encoded = event::encode(event).expect("event encodes");
        EventRef::from_digest(event.sequence(), encoded.digest().to_owned())
            .expect("encoded event reference is valid")
    }

    fn genesis_event() -> Event {
        Event::new(
            "event-op-1".into(),
            1,
            None,
            7,
            EventContent::CampaignCreated,
        )
        .expect("valid genesis event")
    }

    fn parent_head(authority: Authority, operation_id: &str) -> Head {
        Head::new(
            authority,
            event_reference(&genesis_event()),
            operation_id.into(),
        )
        .expect("valid parent head")
    }

    async fn publish_event(event: &Event) -> ResolvedEventPublication {
        let (store, _) = replay_store(vec![response(200, &[], SdkBody::empty())]);
        event::publish(&store, event, None)
            .await
            .expect("event publication resolves")
    }

    async fn genesis_transition(authority: Authority, operation_id: &str) -> HeadTransition {
        let tail = genesis_event();
        let publication = publish_event(&tail).await;
        let candidate = Head::new(
            authority,
            publication.event_ref().clone(),
            operation_id.into(),
        )
        .expect("valid candidate head");
        HeadTransition::new(HeadParent::Genesis, candidate, &tail, &publication)
            .expect("valid genesis transition")
    }

    async fn read_observed(head: &Head, etag: &str) -> ObservedHead {
        let (store, _) = replay_store(vec![response(
            200,
            &[("etag", etag)],
            encode(head).expect("head encodes"),
        )]);
        read(&store)
            .await
            .expect("head read succeeds")
            .expect("head exists")
    }

    fn rejects_transition(
        parent: HeadParent,
        candidate: Head,
        tail: &Event,
        publication: &ResolvedEventPublication,
    ) {
        assert_eq!(
            HeadTransition::new(parent, candidate, tail, publication).err(),
            Some(WireError::InvalidValue)
        );
    }

    async fn successor_transition(
        parent: ObservedHead,
        authority: Authority,
        operation_id: &str,
    ) -> HeadTransition {
        let parent_ref = parent.head().tail().clone();
        let tail = Event::new(
            "event-op-2".into(),
            parent_ref.sequence() + 1,
            Some(parent_ref),
            8,
            EventContent::WorkflowStarted,
        )
        .expect("valid successor event");
        let publication = publish_event(&tail).await;
        let candidate = Head::new(
            authority,
            publication.event_ref().clone(),
            operation_id.into(),
        )
        .expect("valid candidate head");
        HeadTransition::new(
            HeadParent::Existing(Box::new(parent)),
            candidate,
            &tail,
            &publication,
        )
        .expect("valid successor transition")
    }

    fn request_path(
        client: &aws_smithy_runtime::client::http::test_util::StaticReplayClient,
        index: usize,
    ) -> String {
        client
            .actual_requests()
            .nth(index)
            .expect("request")
            .uri()
            .parse::<http::Uri>()
            .expect("valid request URI")
            .path()
            .to_owned()
    }

    fn sentinel_response() -> http::Response<SdkBody> {
        response(500, &[], SdkBody::empty())
    }

    fn digest() -> String {
        "0".repeat(64)
    }

    fn key() -> String {
        format!("{:016}-{}.cbor.zst", 1, digest())
    }

    fn valid_wire() -> WireHead {
        WireHead {
            version: WIRE_VERSION,
            authority: WireAuthority::Unowned,
            tail: WireEventRef {
                sequence: 1,
                digest: digest(),
                key: key(),
            },
            operation_id: "op".into(),
        }
    }

    fn bytes(wire: &WireHead) -> Vec<u8> {
        serde_json::to_vec(wire).unwrap()
    }

    #[test]
    fn production_json_uses_frozen_field_order() {
        assert_eq!(
            String::from_utf8(bytes(&valid_wire())).unwrap(),
            format!(
                "{{\"version\":1,\"authority\":{{\"state\":\"unowned\"}},\"tail\":{{\"sequence\":1,\"digest\":\"{}\",\"key\":\"{}\"}},\"operation_id\":\"op\"}}",
                digest(),
                key()
            )
        );
    }

    #[test]
    fn rejects_unknown_version_and_invalid_values() {
        let mut wire = valid_wire();
        wire.version = 2;
        assert_eq!(decode(&bytes(&wire)), Err(WireError::InvalidValue));

        wire.version = WIRE_VERSION;
        wire.tail.key = "bad".into();
        assert_eq!(decode(&bytes(&wire)), Err(WireError::InvalidValue));

        wire.tail.key = key();
        wire.operation_id = "x".repeat(129);
        assert_eq!(decode(&bytes(&wire)), Err(WireError::InvalidValue));

        wire.operation_id = "op".into();
        wire.authority = WireAuthority::Owned {
            owner: "x".repeat(129),
            instance: "instance".into(),
            lease_until: 1,
            controller_fence: 1,
        };
        assert_eq!(decode(&bytes(&wire)), Err(WireError::InvalidValue));
    }

    #[test]
    fn rejects_noncanonical_and_unrecognized_json() {
        let canonical = String::from_utf8(bytes(&valid_wire())).unwrap();
        assert_eq!(
            decode(format!("{canonical}\n").as_bytes()),
            Err(WireError::NonCanonical)
        );
        assert_eq!(
            decode(canonical.replace("\"version\":1,", "").as_bytes()),
            Err(WireError::InvalidEncoding)
        );
        assert_eq!(
            decode(
                canonical
                    .replace("{\"version\":1", "{\"version\":1,\"version\":1")
                    .as_bytes()
            ),
            Err(WireError::InvalidEncoding)
        );
        assert_eq!(
            decode(canonical.replace("\"unowned\"", "\"future\"").as_bytes()),
            Err(WireError::InvalidEncoding)
        );

        let root_extra = canonical.strip_suffix('}').unwrap().to_owned() + ",\"extra\":null}";
        assert_eq!(
            decode(root_extra.as_bytes()),
            Err(WireError::InvalidEncoding)
        );
        let authority_extra = canonical.replace(
            "{\"state\":\"unowned\"}",
            "{\"state\":\"unowned\",\"owner\":\"x\"}",
        );
        assert_eq!(
            decode(authority_extra.as_bytes()),
            Err(WireError::NonCanonical)
        );
        let tail_extra = canonical.replace("\"tail\":{", "\"tail\":{\"extra\":null,");
        assert_eq!(
            decode(tail_extra.as_bytes()),
            Err(WireError::InvalidEncoding)
        );

        let reordered = canonical.replacen("{\"version\":1,\"authority\":", "{\"authority\":", 1);
        let reordered = reordered.replacen("},\"tail\":", "},\"version\":1,\"tail\":", 1);
        assert_eq!(decode(reordered.as_bytes()), Err(WireError::NonCanonical));
    }

    #[test]
    fn rejects_alternate_scalar_representations() {
        let canonical = String::from_utf8(bytes(&valid_wire())).unwrap();
        assert_eq!(
            decode(
                canonical
                    .replace("\"version\":1", "\"version\":1.0")
                    .as_bytes()
            ),
            Err(WireError::InvalidEncoding)
        );
        assert_eq!(
            decode(
                canonical
                    .replace("\"version\":1", "\"version\":1e0")
                    .as_bytes()
            ),
            Err(WireError::InvalidEncoding)
        );
        assert_eq!(
            decode(
                canonical
                    .replace("\"operation_id\":\"op\"", "\"operation_id\":\"\\u006fp\"")
                    .as_bytes()
            ),
            Err(WireError::NonCanonical)
        );
        assert_eq!(
            decode(canonical.replace(&digest(), &"A".repeat(64)).as_bytes()),
            Err(WireError::InvalidValue)
        );

        let owned = String::from_utf8(OWNED_HEAD.to_vec()).unwrap();
        assert_eq!(
            decode(
                owned
                    .replace("\"lease_until\":1750000000000", "\"lease_until\":-1")
                    .as_bytes()
            ),
            Err(WireError::InvalidEncoding)
        );
    }

    #[test]
    fn bounds_head_input_before_parsing() {
        assert!(OWNED_HEAD.len() < MAX_HEAD_BYTES);
        assert!(decode(OWNED_HEAD).is_ok());
        assert_eq!(decode(&[]), Err(WireError::LimitExceeded));
        assert_eq!(
            decode(&vec![b' '; MAX_HEAD_BYTES + 1]),
            Err(WireError::LimitExceeded)
        );
    }

    #[tokio::test]
    async fn read_preserves_not_found_and_rejects_invalid_heads() {
        let (store, _) = replay_store(vec![response(404, &[], SdkBody::empty())]);
        assert!(read(&store).await.expect("read succeeds").is_none());

        let (store, _) = replay_store(vec![response(
            200,
            &[("etag", OLD_ETAG)],
            b"not-json".to_vec(),
        )]);
        assert!(matches!(
            read(&store).await,
            Err(HeadReadError::Invalid(WireError::InvalidEncoding))
        ));

        let (store, _) = replay_store(vec![response(
            200,
            &[("content-length", "4097"), ("etag", OLD_ETAG)],
            SdkBody::empty(),
        )]);
        assert!(matches!(
            read(&store).await,
            Err(HeadReadError::Invalid(WireError::LimitExceeded))
        ));
        assert_eq!(
            HeadReadError::Invalid(WireError::InvalidEncoding).to_string(),
            "head encoding is invalid"
        );
        assert_eq!(
            HeadReadError::Storage(GetError::Transport).to_string(),
            "head read failed"
        );
    }

    #[tokio::test]
    async fn a_tail_published_elsewhere_never_becomes_authoritative() {
        let tail = genesis_event();
        // The tail is published into the default test bucket...
        let (publishing_store, publishing_client) =
            replay_store(vec![response(200, &[], SdkBody::empty())]);
        let publication = event::publish(&publishing_store, &tail, None)
            .await
            .expect("event publication resolves");
        let candidate = Head::new(
            Authority::unowned(),
            publication.event_ref().clone(),
            "head-op-1".into(),
        )
        .expect("valid head");
        let transition = HeadTransition::new(HeadParent::Genesis, candidate, &tail, &publication)
            .expect("valid transition");
        assert_eq!(publishing_client.actual_requests().count(), 1);

        // ...so committing the head through another bucket must not proceed. A
        // NeverClient would hang if the refusal did not precede dispatch.
        let foreign_store = S3Store::new(
            "other-bucket",
            Region::new("us-east-1"),
            test_builder(NeverClient::new()),
        );
        assert_ne!(foreign_store.namespace(), publishing_store.namespace());
        let mut history = AttemptHistory::default();

        assert!(matches!(
            commit(&foreign_store, transition, &mut history).await,
            HeadCommitOutcome::Unresolved(_)
        ));
    }

    #[tokio::test]
    async fn a_parent_observed_elsewhere_never_authorizes_a_replacement() {
        let parent = parent_head(Authority::unowned(), "parent-op");
        // The parent is observed in one store...
        let observed = read_observed(&parent, OLD_ETAG).await;
        let transition = successor_transition(observed, Authority::unowned(), "head-op-2").await;

        // ...so its ETag must not become another store's If-Match token. A
        // NeverClient would hang if the refusal did not precede dispatch.
        let foreign_store = S3Store::new(
            "other-bucket",
            Region::new("us-east-1"),
            test_builder(NeverClient::new()),
        );
        // Only the tail is restated, so the observed parent still names the store it
        // was read from and the replacement is refused on that ground.
        let transition = transition.with_tail_attributed_to(foreign_store.namespace());
        let mut history = AttemptHistory::default();

        assert!(matches!(
            commit(&foreign_store, transition, &mut history).await,
            HeadCommitOutcome::Unresolved(_)
        ));
    }

    #[tokio::test]
    async fn genesis_commit_uses_create_only_with_exact_bytes() {
        let transition = genesis_transition(Authority::unowned(), "head-op-1").await;
        let expected = transition.canonical_head_bytes().to_vec();
        let (store, client) = replay_store(vec![response(200, &[], SdkBody::empty())]);
        let transition = transition.attributed_to(store.namespace());
        let mut history = AttemptHistory::default();

        assert!(matches!(
            commit(&store, transition, &mut history).await,
            HeadCommitOutcome::Committed
        ));
        assert_eq!(client.actual_requests().count(), 1);
        assert_eq!(request_path(&client, 0), "/head.json");
        let request = client.actual_requests().next().expect("head PUT");
        assert_eq!(request.headers().get("if-none-match"), Some("*"));
        assert!(request.headers().get("if-match").is_none());
        assert_eq!(request.body().bytes(), Some(expected.as_slice()));
    }

    #[tokio::test]
    async fn validated_read_couples_exact_etag_to_replacement() {
        let parent = parent_head(Authority::unowned(), "head-op-1");
        let parent_bytes = encode(&parent).expect("head encodes");
        let (store, client) = replay_store(vec![
            response(200, &[("etag", OLD_ETAG)], parent_bytes),
            response(200, &[], SdkBody::empty()),
        ]);
        let observed = read(&store)
            .await
            .expect("read succeeds")
            .expect("parent exists");
        let transition = successor_transition(observed, Authority::unowned(), "head-op-2").await;
        let transition = transition.attributed_to(store.namespace());
        let expected = transition.canonical_head_bytes().to_vec();
        let mut history = AttemptHistory::default();

        assert!(matches!(
            commit(&store, transition, &mut history).await,
            HeadCommitOutcome::Committed
        ));
        assert_eq!(client.actual_requests().count(), 2);
        assert_eq!(request_path(&client, 0), "/head.json");
        assert_eq!(request_path(&client, 1), "/head.json");
        let request = client.actual_requests().nth(1).expect("replacement PUT");
        assert_eq!(request.headers().get("if-match"), Some(OLD_ETAG));
        assert!(request.headers().get("if-none-match").is_none());
        assert_eq!(request.body().bytes(), Some(expected.as_slice()));
    }

    #[tokio::test]
    async fn transition_constructor_rejects_invalid_boundaries_and_lower_fence() {
        let predecessor = EventRef::from_digest(1, "0".repeat(64)).expect("valid predecessor");
        let sequence_two = Event::new(
            "event-op-2".into(),
            2,
            Some(predecessor),
            8,
            EventContent::WorkflowStarted,
        )
        .expect("valid event");
        let publication = publish_event(&sequence_two).await;
        let candidate = Head::new(
            Authority::unowned(),
            publication.event_ref().clone(),
            "head-op-2".into(),
        )
        .expect("valid head");
        rejects_transition(HeadParent::Genesis, candidate, &sequence_two, &publication);

        let genesis = genesis_event();
        let publication = publish_event(&genesis).await;
        let owned_genesis = Head::new(
            Authority::owned("owner".into(), "instance".into(), 1, 1).expect("valid authority"),
            publication.event_ref().clone(),
            "head-op-1".into(),
        )
        .expect("valid head");
        rejects_transition(HeadParent::Genesis, owned_genesis, &genesis, &publication);

        let genesis = genesis_event();
        let publication = publish_event(&genesis).await;
        let different =
            EventRef::from_digest(1, "f".repeat(64)).expect("valid alternate reference");
        let candidate =
            Head::new(Authority::unowned(), different, "head-op-1".into()).expect("valid head");
        rejects_transition(HeadParent::Genesis, candidate, &genesis, &publication);

        let different_tail = Event::new(
            "different-event-operation".into(),
            1,
            None,
            7,
            EventContent::CampaignCreated,
        )
        .expect("valid alternate event");
        let candidate = Head::new(
            Authority::unowned(),
            publication.event_ref().clone(),
            "head-op-1".into(),
        )
        .expect("valid head");
        rejects_transition(
            HeadParent::Genesis,
            candidate,
            &different_tail,
            &publication,
        );

        let parent = parent_head(Authority::unowned(), "parent-op");
        let observed = read_observed(&parent, OLD_ETAG).await;
        let sequence_two_ref = EventRef::from_digest(2, "1".repeat(64)).expect("valid predecessor");
        let sequence_three = Event::new(
            "event-op-3".into(),
            3,
            Some(sequence_two_ref),
            9,
            EventContent::WorkflowStarted,
        )
        .expect("valid event");
        let publication = publish_event(&sequence_three).await;
        let candidate = Head::new(
            Authority::unowned(),
            publication.event_ref().clone(),
            "head-op-3".into(),
        )
        .expect("valid head");
        rejects_transition(
            HeadParent::Existing(Box::new(observed)),
            candidate,
            &sequence_three,
            &publication,
        );

        let parent = parent_head(Authority::unowned(), "parent-op");
        let observed = read_observed(&parent, OLD_ETAG).await;
        let wrong_parent =
            EventRef::from_digest(1, "2".repeat(64)).expect("valid alternate parent");
        let tail = Event::new(
            "event-op-2".into(),
            2,
            Some(wrong_parent),
            8,
            EventContent::WorkflowStarted,
        )
        .expect("valid event");
        let publication = publish_event(&tail).await;
        let candidate = Head::new(
            Authority::unowned(),
            publication.event_ref().clone(),
            "head-op-2".into(),
        )
        .expect("valid head");
        rejects_transition(
            HeadParent::Existing(Box::new(observed)),
            candidate,
            &tail,
            &publication,
        );

        let parent = parent_head(
            Authority::owned("owner".into(), "instance".into(), 1, 2).expect("valid authority"),
            "parent-op",
        );
        let observed = read_observed(&parent, OLD_ETAG).await;
        let parent_ref = parent.tail().clone();
        let tail = Event::new(
            "event-op-2".into(),
            2,
            Some(parent_ref.clone()),
            2,
            EventContent::WorkflowStarted,
        )
        .expect("valid event");
        let publication = publish_event(&tail).await;
        let lower = Head::new(
            Authority::owned("owner".into(), "instance".into(), 2, 1).expect("valid authority"),
            publication.event_ref().clone(),
            "head-op-2".into(),
        )
        .expect("valid head");
        rejects_transition(
            HeadParent::Existing(Box::new(observed)),
            lower,
            &tail,
            &publication,
        );

        // A tail published at an older writer fence cannot be adopted by a
        // higher-fence owned head.
        let observed = read_observed(&parent, OLD_ETAG).await;
        let stale_tail = Event::new(
            "event-op-stale".into(),
            2,
            Some(parent_ref.clone()),
            1,
            EventContent::WorkflowStarted,
        )
        .expect("valid event");
        let stale_publication = publish_event(&stale_tail).await;
        let higher = Head::new(
            Authority::owned("owner".into(), "instance".into(), 2, 2).expect("valid authority"),
            stale_publication.event_ref().clone(),
            "head-op-stale".into(),
        )
        .expect("valid head");
        rejects_transition(
            HeadParent::Existing(Box::new(observed)),
            higher,
            &stale_tail,
            &stale_publication,
        );

        let observed = read_observed(&parent, OLD_ETAG).await;
        let unfenced = Head::new(
            Authority::unowned(),
            publication.event_ref().clone(),
            "head-op-2".into(),
        )
        .expect("valid head");
        rejects_transition(
            HeadParent::Existing(Box::new(observed)),
            unfenced,
            &tail,
            &publication,
        );

        let observed = read_observed(&parent, OLD_ETAG).await;
        let reused_operation = Head::new(
            Authority::owned("owner".into(), "instance".into(), 2, 2).expect("valid authority"),
            publication.event_ref().clone(),
            parent.operation_id().to_owned(),
        )
        .expect("valid head");
        rejects_transition(
            HeadParent::Existing(Box::new(observed)),
            reused_operation,
            &tail,
            &publication,
        );

        let observed = read_observed(&parent, OLD_ETAG).await;
        let equal = Head::new(
            Authority::owned("owner".into(), "instance".into(), 2, 2).expect("valid authority"),
            publication.event_ref().clone(),
            "head-op-2".into(),
        )
        .expect("valid head");
        assert!(
            HeadTransition::new(
                HeadParent::Existing(Box::new(observed)),
                equal,
                &tail,
                &publication
            )
            .is_ok()
        );
    }

    #[tokio::test]
    async fn lost_create_success_requires_exact_head_and_tail() {
        let transition = genesis_transition(Authority::unowned(), "head-op-1").await;
        let head_bytes = transition.canonical_head_bytes().to_vec();
        let event_bytes = transition.canonical_event_bytes().to_vec();
        let tail_key = transition.candidate().tail().key().to_owned();
        let (store, client) = replay_store(vec![
            response(500, &[], SdkBody::empty()),
            response(200, &[("etag", OLD_ETAG)], head_bytes),
            response(200, &[("etag", "\"tail\"")], event_bytes),
        ]);
        let transition = transition.attributed_to(store.namespace());
        let mut history = AttemptHistory::default();

        assert!(matches!(
            commit(&store, transition, &mut history).await,
            HeadCommitOutcome::Committed
        ));
        assert_eq!(client.actual_requests().count(), 3);
        assert_eq!(request_path(&client, 0), "/head.json");
        assert_eq!(request_path(&client, 1), "/head.json");
        assert_eq!(request_path(&client, 2), format!("/{tail_key}"));
    }

    #[tokio::test]
    async fn unknown_create_then_conflict_resolves_from_head_and_tail() {
        for conflict in [409, 412] {
            let transition = genesis_transition(Authority::unowned(), "head-op-1").await;
            let head_bytes = transition.canonical_head_bytes().to_vec();
            let event_bytes = transition.canonical_event_bytes().to_vec();
            let tail_key = transition.candidate().tail().key().to_owned();
            let (store, client) = replay_store(vec![
                response(500, &[], SdkBody::empty()),
                response(404, &[], SdkBody::empty()),
                response(conflict, &[], SdkBody::empty()),
                response(200, &[("etag", OLD_ETAG)], head_bytes.clone()),
                response(200, &[("etag", "\"tail\"")], event_bytes),
            ]);
            let transition = transition.attributed_to(store.namespace());
            let mut history = AttemptHistory::default();

            let transition = match commit(&store, transition, &mut history).await {
                HeadCommitOutcome::RetryIdentically(transition) => transition,
                _ => panic!("missing head permits identical retry"),
            };
            assert!(matches!(
                commit(&store, transition, &mut history).await,
                HeadCommitOutcome::Committed
            ));
            assert_eq!(client.actual_requests().count(), 5);
            assert_eq!(request_path(&client, 0), "/head.json");
            assert_eq!(request_path(&client, 1), "/head.json");
            assert_eq!(request_path(&client, 2), "/head.json");
            assert_eq!(request_path(&client, 3), "/head.json");
            assert_eq!(request_path(&client, 4), format!("/{tail_key}"));
            for index in [0, 2] {
                let request = client.actual_requests().nth(index).expect("head PUT");
                assert_eq!(request.headers().get("if-none-match"), Some("*"));
                assert_eq!(request.body().bytes(), Some(head_bytes.as_slice()));
            }
        }
    }

    #[tokio::test]
    async fn same_operation_with_changed_head_is_unresolved() {
        let transition = genesis_transition(Authority::unowned(), "head-op-1").await;
        let event_bytes = transition.canonical_event_bytes().to_vec();
        let different = Head::new(
            Authority::owned("owner".into(), "instance".into(), 1, 1).expect("valid authority"),
            transition.candidate().tail().clone(),
            transition.candidate().operation_id().to_owned(),
        )
        .expect("valid conflicting head");
        let (store, client) = replay_store(vec![
            response(500, &[], SdkBody::empty()),
            response(
                200,
                &[("etag", OLD_ETAG)],
                encode(&different).expect("head encodes"),
            ),
            response(200, &[("etag", "\"tail\"")], event_bytes),
        ]);
        let transition = transition.attributed_to(store.namespace());
        let mut history = AttemptHistory::default();

        assert!(matches!(
            commit(&store, transition, &mut history).await,
            HeadCommitOutcome::Unresolved(_)
        ));
        assert_eq!(client.actual_requests().count(), 2);
    }

    #[tokio::test]
    async fn missing_malformed_or_mismatched_tail_is_unresolved() {
        for tail_case in 0..3 {
            let transition = genesis_transition(Authority::unowned(), "head-op-1").await;
            let head_bytes = transition.canonical_head_bytes().to_vec();
            let tail_key = transition.candidate().tail().key().to_owned();
            let tail_response = match tail_case {
                0 => response(404, &[], SdkBody::empty()),
                1 => response(200, &[("etag", "\"tail\"")], b"bad".to_vec()),
                _ => {
                    let mut bytes = transition.canonical_event_bytes().to_vec();
                    bytes[0] ^= 1;
                    response(200, &[("etag", "\"tail\"")], bytes)
                }
            };
            let (store, client) = replay_store(vec![
                response(500, &[], SdkBody::empty()),
                response(200, &[("etag", OLD_ETAG)], head_bytes),
                tail_response,
            ]);
            let transition = transition.attributed_to(store.namespace());
            let mut history = AttemptHistory::default();

            assert!(matches!(
                commit(&store, transition, &mut history).await,
                HeadCommitOutcome::Unresolved(_)
            ));
            assert_eq!(client.actual_requests().count(), 3);
            assert_eq!(request_path(&client, 0), "/head.json");
            assert_eq!(request_path(&client, 1), "/head.json");
            assert_eq!(request_path(&client, 2), format!("/{tail_key}"));
        }
    }

    #[tokio::test]
    async fn current_parent_refreshes_etag_for_identical_replacement_retry() {
        for initial_status in [500, 412] {
            let parent = parent_head(Authority::unowned(), "parent-op");
            let parent_bytes = encode(&parent).expect("head encodes");
            let original = read_observed(&parent, OLD_ETAG).await;
            let transition =
                successor_transition(original, Authority::unowned(), "head-op-2").await;
            let candidate_bytes = transition.canonical_head_bytes().to_vec();
            let (store, client) = replay_store(vec![
                response(initial_status, &[], SdkBody::empty()),
                response(200, &[("etag", FRESH_ETAG)], parent_bytes),
                response(200, &[], SdkBody::empty()),
            ]);
            let transition = transition.attributed_to(store.namespace());
            let mut history = AttemptHistory::default();

            let transition = match commit(&store, transition, &mut history).await {
                HeadCommitOutcome::RetryIdentically(transition) => transition,
                _ => panic!("current parent permits identical retry"),
            };
            assert!(matches!(
                commit(&store, transition, &mut history).await,
                HeadCommitOutcome::Committed
            ));
            assert_eq!(client.actual_requests().count(), 3);
            let first = client.actual_requests().next().expect("first PUT");
            let retried = client.actual_requests().nth(2).expect("retried PUT");
            assert_eq!(first.headers().get("if-match"), Some(OLD_ETAG));
            assert_eq!(retried.headers().get("if-match"), Some(FRESH_ETAG));
            assert!(first.headers().get("if-none-match").is_none());
            assert!(retried.headers().get("if-none-match").is_none());
            assert_eq!(first.body().bytes(), Some(candidate_bytes.as_slice()));
            assert_eq!(retried.body().bytes(), Some(candidate_bytes.as_slice()));
        }
    }

    #[tokio::test]
    async fn different_current_head_without_complete_chain_is_unresolved() {
        let parent = parent_head(Authority::unowned(), "parent-op");
        let original = read_observed(&parent, OLD_ETAG).await;
        let transition = successor_transition(original, Authority::unowned(), "head-op-2").await;
        let tail_key = transition.candidate().tail().key().to_owned();
        let current = Head::new(
            Authority::unowned(),
            transition.candidate().tail().clone(),
            "other-operation".into(),
        )
        .expect("valid current head");
        let current_bytes = encode(&current).expect("head encodes");
        let (store, client) = replay_store(vec![
            response(500, &[], SdkBody::empty()),
            response(200, &[("etag", FRESH_ETAG)], current_bytes),
            response(404, &[], SdkBody::empty()),
            sentinel_response(),
        ]);
        let transition = transition.attributed_to(store.namespace());
        let mut history = AttemptHistory::default();

        assert!(matches!(
            commit(&store, transition, &mut history).await,
            HeadCommitOutcome::Unresolved(_)
        ));
        assert_eq!(client.actual_requests().count(), 3);
        assert_eq!(request_path(&client, 0), "/head.json");
        assert_eq!(request_path(&client, 1), "/head.json");
        assert_eq!(request_path(&client, 2), format!("/{tail_key}"));
    }

    #[tokio::test]
    async fn reused_parent_operation_is_unresolved_without_reconciliation() {
        let parent = parent_head(Authority::unowned(), "parent-op");
        let original = read_observed(&parent, OLD_ETAG).await;
        let transition = successor_transition(original, Authority::unowned(), "head-op-2").await;
        let current = Head::new(
            Authority::owned("owner".into(), "instance".into(), 1, 1).expect("valid authority"),
            transition.candidate().tail().clone(),
            parent.operation_id().to_owned(),
        )
        .expect("valid current head");
        let (store, client) = replay_store(vec![
            response(500, &[], SdkBody::empty()),
            response(
                200,
                &[("etag", FRESH_ETAG)],
                encode(&current).expect("head encodes"),
            ),
            sentinel_response(),
        ]);
        let transition = transition.attributed_to(store.namespace());
        let mut history = AttemptHistory::default();

        assert!(matches!(
            commit(&store, transition, &mut history).await,
            HeadCommitOutcome::Unresolved(_)
        ));
        // One operation id naming two head byte-strings is rejected before any
        // chain read, so no event object is fetched.
        assert_eq!(client.actual_requests().count(), 2);
        assert_eq!(request_path(&client, 0), "/head.json");
        assert_eq!(request_path(&client, 1), "/head.json");
    }

    #[tokio::test]
    async fn existing_parent_never_guesses_absence() {
        let parent = parent_head(Authority::unowned(), "parent-op");
        let original = read_observed(&parent, OLD_ETAG).await;
        let transition = successor_transition(original, Authority::unowned(), "head-op-2").await;
        let (store, client) = replay_store(vec![
            response(500, &[], SdkBody::empty()),
            response(404, &[], SdkBody::empty()),
            sentinel_response(),
        ]);
        let transition = transition.attributed_to(store.namespace());
        let mut history = AttemptHistory::default();

        assert!(matches!(
            commit(&store, transition, &mut history).await,
            HeadCommitOutcome::Unresolved(_)
        ));
        assert_eq!(client.actual_requests().count(), 2);
        assert_eq!(request_path(&client, 0), "/head.json");
        assert_eq!(request_path(&client, 1), "/head.json");
    }

    #[tokio::test]
    async fn storage_not_found_is_unresolved_without_a_read() {
        let transition = genesis_transition(Authority::unowned(), "head-op-1").await;
        let (store, client) = replay_store(vec![
            response(404, &[], SdkBody::empty()),
            response(404, &[], SdkBody::empty()),
        ]);
        let transition = transition.attributed_to(store.namespace());
        let mut history = AttemptHistory::default();

        assert!(matches!(
            commit(&store, transition, &mut history).await,
            HeadCommitOutcome::Unresolved(_)
        ));
        assert_eq!(client.actual_requests().count(), 1);
        assert_eq!(request_path(&client, 0), "/head.json");
    }

    #[tokio::test]
    async fn genesis_with_another_head_and_missing_chain_is_unresolved() {
        let transition = genesis_transition(Authority::unowned(), "head-op-1").await;
        let tail_key = transition.candidate().tail().key().to_owned();
        let current = Head::new(
            Authority::unowned(),
            transition.candidate().tail().clone(),
            "other-operation".into(),
        )
        .expect("valid current head");
        let (store, client) = replay_store(vec![
            response(500, &[], SdkBody::empty()),
            response(
                200,
                &[("etag", FRESH_ETAG)],
                encode(&current).expect("head encodes"),
            ),
            response(404, &[], SdkBody::empty()),
            sentinel_response(),
        ]);
        let transition = transition.attributed_to(store.namespace());
        let mut history = AttemptHistory::default();

        assert!(matches!(
            commit(&store, transition, &mut history).await,
            HeadCommitOutcome::Unresolved(_)
        ));
        assert_eq!(client.actual_requests().count(), 3);
        assert_eq!(request_path(&client, 0), "/head.json");
        assert_eq!(request_path(&client, 1), "/head.json");
        assert_eq!(request_path(&client, 2), format!("/{tail_key}"));
    }

    #[tokio::test]
    async fn head_read_failure_is_unresolved() {
        let transition = genesis_transition(Authority::unowned(), "head-op-1").await;
        let (store, client) = replay_store(vec![
            response(500, &[], SdkBody::empty()),
            response(500, &[], SdkBody::empty()),
        ]);
        let transition = transition.attributed_to(store.namespace());
        let mut history = AttemptHistory::default();

        assert!(matches!(
            commit(&store, transition, &mut history).await,
            HeadCommitOutcome::Unresolved(_)
        ));
        assert_eq!(client.actual_requests().count(), 2);
    }

    #[tokio::test]
    async fn advanced_head_resolves_through_the_complete_retained_chain() {
        let parent = parent_head(Authority::unowned(), "parent-head-operation");
        let observed = read_observed(&parent, OLD_ETAG).await;
        let transition =
            successor_transition(observed, Authority::unowned(), "candidate-head-operation").await;
        let candidate_key = transition.candidate().tail().key().to_owned();
        let candidate_event = event::decode(
            transition.canonical_event_bytes(),
            transition.candidate().tail().key(),
        )
        .expect("candidate event decodes");
        let later_event = Event::new(
            "later-event-operation".into(),
            candidate_event.sequence() + 1,
            Some(transition.candidate().tail().clone()),
            candidate_event.writer_fence() + 1,
            EventContent::WorkflowStarted,
        )
        .expect("later event is valid");
        let later_bytes = event::encode(&later_event).expect("later event encodes");
        let current_head = Head::new(
            Authority::unowned(),
            EventRef::from_digest(later_event.sequence(), later_bytes.digest().to_owned())
                .expect("later reference is valid"),
            "current-head-operation".into(),
        )
        .expect("current head is valid");
        let (store, client) = replay_store(vec![
            response(500, &[], SdkBody::empty()),
            response(
                200,
                &[("etag", FRESH_ETAG)],
                encode(&current_head).expect("current head encodes"),
            ),
            response(
                200,
                &[("etag", "\"later-event\"")],
                later_bytes.stored_bytes(),
            ),
            response(
                200,
                &[("etag", "\"candidate-event\"")],
                transition.canonical_event_bytes(),
            ),
        ]);
        let mut history = AttemptHistory::default();

        assert!(matches!(
            commit(&store, transition, &mut history).await,
            HeadCommitOutcome::CommittedSuperseded
        ));
        assert_eq!(client.actual_requests().count(), 4);
        assert_eq!(request_path(&client, 0), "/head.json");
        assert_eq!(request_path(&client, 1), "/head.json");
        assert_eq!(request_path(&client, 2), format!("/{}", later_bytes.key()));
        assert_eq!(request_path(&client, 3), format!("/{candidate_key}"));
    }

    #[tokio::test]
    async fn append_publishes_event_before_head_and_blocks_failed_publication() {
        let event = genesis_event();
        let event_key = event::encode(&event)
            .expect("event encodes")
            .key()
            .to_owned();
        let (store, client) = replay_store(vec![
            response(200, &[], SdkBody::empty()),
            response(200, &[], SdkBody::empty()),
        ]);
        let mut history = AttemptHistory::default();

        assert!(matches!(
            append(
                &store,
                HeadParent::Genesis,
                Authority::unowned(),
                &event,
                None,
                &mut history,
            )
            .await,
            Ok(HeadCommitOutcome::Committed)
        ));
        assert_eq!(client.actual_requests().count(), 2);
        assert_eq!(request_path(&client, 0), format!("/{event_key}"));
        assert_eq!(request_path(&client, 1), "/head.json");
        assert_eq!(
            client.actual_requests().next().expect("event PUT").method(),
            http::Method::PUT
        );
        assert_eq!(
            client.actual_requests().nth(1).expect("head PUT").method(),
            http::Method::PUT
        );

        let artifact = ArtifactRef::new(
            "0".repeat(64),
            1,
            "application/octet-stream".into(),
            "producer-attempt".into(),
            1,
            None,
        )
        .expect("artifact reference is valid");
        let event = Event::new(
            "artifact-event-operation".into(),
            1,
            None,
            1,
            EventContent::ArtifactPublished(artifact),
        )
        .expect("artifact event is valid");
        let (store, client) = replay_store(vec![sentinel_response()]);
        let mut history = AttemptHistory::default();
        let error = match append(
            &store,
            HeadParent::Genesis,
            Authority::unowned(),
            &event,
            None,
            &mut history,
        )
        .await
        {
            Err(error) => error,
            Ok(_) => panic!("missing artifact witness must fail publication"),
        };
        assert_eq!(
            error,
            AppendError::Publication(PublicationError::InvalidInput)
        );
        assert_eq!(error.to_string(), "event publication failed");
        assert_eq!(client.actual_requests().count(), 0);

        let event = genesis_event();
        let event_key = event::encode(&event)
            .expect("event encodes")
            .key()
            .to_owned();
        let (store, client) = replay_store(vec![
            response(500, &[], SdkBody::empty()),
            response(500, &[], SdkBody::empty()),
        ]);
        let mut history = AttemptHistory::default();
        assert!(matches!(
            append(
                &store,
                HeadParent::Genesis,
                Authority::unowned(),
                &event,
                None,
                &mut history,
            )
            .await,
            Err(AppendError::Publication(PublicationError::Unresolved))
        ));
        assert_eq!(client.actual_requests().count(), 2);
        assert_eq!(request_path(&client, 0), format!("/{event_key}"));
        assert_eq!(request_path(&client, 1), format!("/{event_key}"));
    }

    #[tokio::test]
    async fn append_gives_the_head_the_tail_operation_identity() {
        let event = genesis_event();
        let event_key = event::encode(&event)
            .expect("event encodes")
            .key()
            .to_owned();
        let (store, client) = replay_store(vec![
            response(200, &[], SdkBody::empty()),
            response(200, &[], SdkBody::empty()),
            sentinel_response(),
        ]);
        let mut history = AttemptHistory::default();

        assert!(matches!(
            append(
                &store,
                HeadParent::Genesis,
                Authority::unowned(),
                &event,
                None,
                &mut history,
            )
            .await,
            Ok(HeadCommitOutcome::Committed)
        ));
        assert_eq!(client.actual_requests().count(), 2);
        assert_eq!(request_path(&client, 0), format!("/{event_key}"));
        assert_eq!(request_path(&client, 1), "/head.json");

        // The committed head records the tail's operation id, so retained-chain
        // reconciliation searching that id finds this append.
        let committed = decode(
            client
                .actual_requests()
                .nth(1)
                .expect("head PUT")
                .body()
                .bytes()
                .expect("head bytes"),
        )
        .expect("head decodes");
        assert_eq!(committed.operation_id(), event.operation_id());
    }
}
