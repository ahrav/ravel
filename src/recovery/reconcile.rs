//! Exact-boundary reconciliation for ambiguous append-time head mutations.

use std::collections::HashSet;

use crate::{
    storage::s3::{GetOutcome, S3Store},
    sync::{
        event::{self, MAX_COMPRESSED_BYTES},
        head::{HeadCommitOutcome, HeadParent, HeadTransition, ObservedHead},
    },
};

pub(crate) async fn reconcile(
    store: &S3Store,
    transition: HeadTransition,
    current: ObservedHead,
) -> HeadCommitOutcome {
    let expected = match event::decode(
        transition.canonical_event_bytes(),
        transition.candidate().tail().key(),
    ) {
        Ok(event) => event,
        Err(_) => return HeadCommitOutcome::Unresolved(transition),
    };
    let boundary = match transition.parent() {
        HeadParent::Genesis => None,
        HeadParent::Existing(parent) => Some(parent.head().tail().clone()),
    };
    let mut current_ref = current.head().tail().clone();
    let hop_count = match &boundary {
        Some(boundary) if current_ref.sequence() > boundary.sequence() => {
            current_ref.sequence() - boundary.sequence()
        }
        Some(_) => return HeadCommitOutcome::Unresolved(transition),
        None => current_ref.sequence(),
    };
    let mut seen_digests = HashSet::new();
    let mut found = false;

    for _ in 0..hop_count {
        // `Event::new` makes repeated digests unreachable under sequence descent; this set is a corruption backstop. commentlint: allow(JUDGE)
        if !seen_digests.insert(current_ref.digest().to_owned()) {
            return HeadCommitOutcome::Unresolved(transition);
        }
        let bytes = match store
            .get_object(current_ref.key(), MAX_COMPRESSED_BYTES)
            .await
        {
            Ok(GetOutcome::Found { bytes, .. }) => bytes,
            Ok(GetOutcome::NotFound) | Err(_) => {
                return HeadCommitOutcome::Unresolved(transition);
            }
        };
        let decoded = match event::decode(&bytes, current_ref.key()) {
            Ok(event) => event,
            Err(_) => return HeadCommitOutcome::Unresolved(transition),
        };

        if decoded.operation_id() == expected.operation_id() {
            if current_ref != *transition.candidate().tail()
                || bytes != transition.canonical_event_bytes()
                || decoded != expected
            {
                return HeadCommitOutcome::Unresolved(transition);
            }
            found = true;
        } else if current_ref == *transition.candidate().tail() {
            // `event::decode` binds bytes to this key; exact comparison is a collision backstop. commentlint: allow(JUDGE)
            return HeadCommitOutcome::Unresolved(transition);
        }

        let reached_boundary = match &boundary {
            Some(boundary) => decoded.parent() == Some(boundary),
            None => decoded.sequence() == 1 && decoded.parent().is_none(),
        };
        if reached_boundary {
            return if found {
                HeadCommitOutcome::CommittedSuperseded
            } else {
                HeadCommitOutcome::ProvenNotCommitted
            };
        }

        let Some(parent) = decoded.parent() else {
            return HeadCommitOutcome::Unresolved(transition);
        };
        if parent.sequence().checked_add(1) != Some(decoded.sequence()) {
            return HeadCommitOutcome::Unresolved(transition);
        }
        current_ref = parent.clone();
    }

    HeadCommitOutcome::Unresolved(transition)
}

#[cfg(test)]
mod tests {
    use aws_sdk_s3::primitives::SdkBody;

    use crate::{
        domain::campaign::{Authority, Event, EventContent, EventRef, Head},
        storage::s3::test_support::{replay_store, response},
        sync::{
            event,
            head::{self, HeadCommitOutcome, HeadParent, HeadTransition, ObservedHead},
        },
    };

    use super::*;

    const GENESIS_KEY: &str = "0000000000000001-d10251de219fe17099d74f8f14729b1cbb33bdd73f919d6fb907ef32d5a51648.cbor.zst";
    const CHILD_KEY: &str = "0000000000000002-5454daad2e7a3c4ac66d017f75296647c7b3ebddc4e8d2b19d7cde066239d34c.cbor.zst";
    const GENESIS_BYTES: &[u8] = include_bytes!(
        "../../tests/fixtures/v1/0000000000000001-d10251de219fe17099d74f8f14729b1cbb33bdd73f919d6fb907ef32d5a51648.cbor.zst"
    );
    const CHILD_BYTES: &[u8] = include_bytes!(
        "../../tests/fixtures/v1/0000000000000002-5454daad2e7a3c4ac66d017f75296647c7b3ebddc4e8d2b19d7cde066239d34c.cbor.zst"
    );

    fn fixture_event(bytes: &[u8], key: &str) -> Event {
        event::decode(bytes, key).expect("fixture event decodes")
    }

    fn event_ref(event: &Event) -> EventRef {
        let encoded = event::encode(event).expect("event encodes");
        EventRef::from_digest(event.sequence(), encoded.digest().to_owned())
            .expect("event reference is valid")
    }

    fn child(parent: &Event, operation_id: &str, content: EventContent) -> Event {
        Event::new(
            operation_id.into(),
            parent.sequence() + 1,
            Some(event_ref(parent)),
            parent.writer_fence() + 1,
            content,
        )
        .expect("child event is valid")
    }

    async fn published(event: &Event) -> event::ResolvedEventPublication {
        let (store, _) = replay_store(vec![response(200, &[], SdkBody::empty())]);
        event::publish(&store, event, None)
            .await
            .expect("event publication resolves")
    }

    async fn observed(tail: EventRef, operation_id: &str) -> ObservedHead {
        let head =
            Head::new(Authority::unowned(), tail, operation_id.into()).expect("head is valid");
        let (store, _) = replay_store(vec![response(
            200,
            &[("etag", "\"head-etag\"")],
            head::encode(&head).expect("head encodes"),
        )]);
        head::read(&store)
            .await
            .expect("head read succeeds")
            .expect("head exists")
    }

    async fn existing_transition(parent: &Event, candidate: &Event) -> HeadTransition {
        let publication = published(candidate).await;
        let parent = observed(event_ref(parent), "parent-head-operation").await;
        let candidate_head = Head::new(
            Authority::unowned(),
            publication.event_ref().clone(),
            "candidate-head-operation".into(),
        )
        .expect("candidate head is valid");
        HeadTransition::new(
            HeadParent::Existing(Box::new(parent)),
            candidate_head,
            candidate,
            &publication,
        )
        .expect("transition is valid")
    }

    async fn genesis_transition(candidate: &Event) -> HeadTransition {
        let publication = published(candidate).await;
        let candidate_head = Head::new(
            Authority::unowned(),
            publication.event_ref().clone(),
            "candidate-head-operation".into(),
        )
        .expect("candidate head is valid");
        HeadTransition::new(HeadParent::Genesis, candidate_head, candidate, &publication)
            .expect("transition is valid")
    }

    fn sentinel() -> http::Response<SdkBody> {
        response(500, &[], SdkBody::empty())
    }

    fn assert_gets(
        client: &aws_smithy_runtime::client::http::test_util::StaticReplayClient,
        keys: &[&str],
    ) {
        assert_eq!(client.actual_requests().count(), keys.len());
        for (request, key) in client.actual_requests().zip(keys) {
            assert_eq!(request.method(), http::Method::GET);
            let uri = request.uri().parse::<http::Uri>().expect("valid URI");
            assert_eq!(uri.path(), format!("/{key}"));
        }
    }

    #[tokio::test]
    async fn fixture_candidate_in_complete_child_chain_is_committed_superseded() {
        let genesis = fixture_event(GENESIS_BYTES, GENESIS_KEY);
        let candidate = fixture_event(CHILD_BYTES, CHILD_KEY);
        let transition = existing_transition(&genesis, &candidate).await;
        let current_event = child(
            &candidate,
            "later-event-operation",
            EventContent::WorkflowStarted,
        );
        let current_bytes = event::encode(&current_event).expect("event encodes");
        let current = observed(event_ref(&current_event), "current-head-operation").await;
        let (store, client) = replay_store(vec![
            response(
                200,
                &[("etag", "\"event-3\"")],
                current_bytes.stored_bytes(),
            ),
            response(200, &[("etag", "\"event-2\"")], CHILD_BYTES),
            sentinel(),
        ]);

        assert!(matches!(
            reconcile(&store, transition, current).await,
            HeadCommitOutcome::CommittedSuperseded
        ));
        assert_gets(&client, &[current_bytes.key(), CHILD_KEY]);
    }

    #[tokio::test]
    async fn complete_competing_chain_proves_candidate_not_committed() {
        let genesis = fixture_event(GENESIS_BYTES, GENESIS_KEY);
        let candidate = fixture_event(CHILD_BYTES, CHILD_KEY);
        let transition = existing_transition(&genesis, &candidate).await;
        let competitor = child(
            &genesis,
            "competing-event-operation",
            EventContent::CampaignCreated,
        );
        let competitor_bytes = event::encode(&competitor).expect("event encodes");
        let current = observed(event_ref(&competitor), "current-head-operation").await;
        let (store, client) = replay_store(vec![
            response(
                200,
                &[("etag", "\"competitor\"")],
                competitor_bytes.stored_bytes(),
            ),
            sentinel(),
        ]);

        assert!(matches!(
            reconcile(&store, transition, current).await,
            HeadCommitOutcome::ProvenNotCommitted
        ));
        assert_gets(&client, &[competitor_bytes.key()]);
    }

    #[tokio::test]
    async fn genesis_boundary_distinguishes_found_and_absent_candidates() {
        let candidate = fixture_event(GENESIS_BYTES, GENESIS_KEY);
        let transition = genesis_transition(&candidate).await;
        let current = observed(event_ref(&candidate), "other-head-operation").await;
        let (store, client) = replay_store(vec![
            response(200, &[("etag", "\"genesis\"")], GENESIS_BYTES),
            sentinel(),
        ]);
        assert!(matches!(
            reconcile(&store, transition, current).await,
            HeadCommitOutcome::CommittedSuperseded
        ));
        assert_gets(&client, &[GENESIS_KEY]);

        let transition = genesis_transition(&candidate).await;
        let competitor = Event::new(
            "other-genesis-operation".into(),
            1,
            None,
            9,
            EventContent::CampaignCreated,
        )
        .expect("competitor is valid");
        let competitor_bytes = event::encode(&competitor).expect("event encodes");
        let current = observed(event_ref(&competitor), "other-head-operation").await;
        let (store, client) = replay_store(vec![
            response(
                200,
                &[("etag", "\"competitor\"")],
                competitor_bytes.stored_bytes(),
            ),
            sentinel(),
        ]);
        assert!(matches!(
            reconcile(&store, transition, current).await,
            HeadCommitOutcome::ProvenNotCommitted
        ));
        assert_gets(&client, &[competitor_bytes.key()]);
    }

    #[tokio::test]
    async fn gaps_transport_and_invalid_objects_are_unresolved() {
        let candidate = fixture_event(GENESIS_BYTES, GENESIS_KEY);
        for response_case in [0, 1, 2, 3, 4] {
            let transition = genesis_transition(&candidate).await;
            let current = observed(event_ref(&candidate), "other-head-operation").await;
            let object_response = match response_case {
                0 => response(404, &[], SdkBody::empty()),
                1 => response(500, &[], SdkBody::empty()),
                2 => response(200, &[], GENESIS_BYTES),
                3 => response(
                    200,
                    &[("content-length", "262145"), ("etag", "\"oversized\"")],
                    SdkBody::empty(),
                ),
                _ => response(200, &[("etag", "\"corrupt\"")], b"bad".to_vec()),
            };
            let (store, client) = replay_store(vec![object_response, sentinel()]);
            assert!(matches!(
                reconcile(&store, transition, current).await,
                HeadCommitOutcome::Unresolved(_)
            ));
            assert_gets(&client, &[GENESIS_KEY]);
        }
    }

    #[tokio::test]
    async fn chain_must_reach_the_exact_original_boundary() {
        let genesis = fixture_event(GENESIS_BYTES, GENESIS_KEY);
        let candidate = fixture_event(CHILD_BYTES, CHILD_KEY);
        let transition = existing_transition(&genesis, &candidate).await;

        let alternate_genesis = Event::new(
            "alternate-genesis-operation".into(),
            1,
            None,
            10,
            EventContent::CampaignCreated,
        )
        .expect("alternate genesis is valid");
        let wrong_parent = child(
            &alternate_genesis,
            "wrong-parent-operation",
            EventContent::WorkflowStarted,
        );
        let current_event = child(
            &wrong_parent,
            "current-event-operation",
            EventContent::WorkflowStarted,
        );
        let wrong_parent_bytes = event::encode(&wrong_parent).expect("event encodes");
        let current_bytes = event::encode(&current_event).expect("event encodes");
        let current = observed(event_ref(&current_event), "current-head-operation").await;
        let (store, client) = replay_store(vec![
            response(
                200,
                &[("etag", "\"current\"")],
                current_bytes.stored_bytes(),
            ),
            response(
                200,
                &[("etag", "\"wrong-parent\"")],
                wrong_parent_bytes.stored_bytes(),
            ),
            sentinel(),
        ]);

        assert!(matches!(
            reconcile(&store, transition, current).await,
            HeadCommitOutcome::Unresolved(_)
        ));
        assert_gets(&client, &[current_bytes.key(), wrong_parent_bytes.key()]);
    }

    #[tokio::test]
    async fn conflicting_duplicate_operation_is_unresolved() {
        let candidate = fixture_event(GENESIS_BYTES, GENESIS_KEY);
        let transition = genesis_transition(&candidate).await;
        let conflicting = Event::new(
            candidate.operation_id().into(),
            1,
            None,
            candidate.writer_fence() + 1,
            EventContent::CampaignCreated,
        )
        .expect("conflicting event is valid");
        let conflicting_bytes = event::encode(&conflicting).expect("event encodes");
        let current = observed(event_ref(&conflicting), "other-head-operation").await;
        let (store, client) = replay_store(vec![
            response(
                200,
                &[("etag", "\"conflict\"")],
                conflicting_bytes.stored_bytes(),
            ),
            sentinel(),
        ]);

        assert!(matches!(
            reconcile(&store, transition, current).await,
            HeadCommitOutcome::Unresolved(_)
        ));
        assert_gets(&client, &[conflicting_bytes.key()]);
    }

    #[tokio::test]
    async fn existing_boundary_requires_strict_advance() {
        let genesis = fixture_event(GENESIS_BYTES, GENESIS_KEY);
        let candidate = fixture_event(CHILD_BYTES, CHILD_KEY);

        let transition = existing_transition(&genesis, &candidate).await;
        let current = observed(event_ref(&genesis), "changed-head-operation").await;
        let (store, client) = replay_store(vec![sentinel()]);
        assert!(matches!(
            reconcile(&store, transition, current).await,
            HeadCommitOutcome::Unresolved(_)
        ));
        assert_gets(&client, &[]);

        let parent = candidate;
        let successor = child(
            &parent,
            "candidate-event-operation",
            EventContent::WorkflowStarted,
        );
        let transition = existing_transition(&parent, &successor).await;
        let current = observed(event_ref(&genesis), "regressed-head-operation").await;
        let (store, client) = replay_store(vec![sentinel()]);
        assert!(matches!(
            reconcile(&store, transition, current).await,
            HeadCommitOutcome::Unresolved(_)
        ));
        assert_gets(&client, &[]);
    }
}
