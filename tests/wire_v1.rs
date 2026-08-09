use ravel::{
    distributed::{
        claims::{self, ClaimState},
        presence,
    },
    domain::campaign::{Authority, Event, EventContent, EventRef, Head},
    sync::{WireError, event, head},
};
use sha2::{Digest, Sha256};

const GENESIS_DIGEST: &str = "d10251de219fe17099d74f8f14729b1cbb33bdd73f919d6fb907ef32d5a51648";
const GENESIS_KEY: &str =
    "0000000000000001-d10251de219fe17099d74f8f14729b1cbb33bdd73f919d6fb907ef32d5a51648.cbor.zst";
const CHILD_DIGEST: &str = "5454daad2e7a3c4ac66d017f75296647c7b3ebddc4e8d2b19d7cde066239d34c";
const CHILD_KEY: &str =
    "0000000000000002-5454daad2e7a3c4ac66d017f75296647c7b3ebddc4e8d2b19d7cde066239d34c.cbor.zst";
const GENESIS_BYTES: &[u8] = include_bytes!(
    "fixtures/v1/0000000000000001-d10251de219fe17099d74f8f14729b1cbb33bdd73f919d6fb907ef32d5a51648.cbor.zst"
);
const CHILD_BYTES: &[u8] = include_bytes!(
    "fixtures/v1/0000000000000002-5454daad2e7a3c4ac66d017f75296647c7b3ebddc4e8d2b19d7cde066239d34c.cbor.zst"
);
const HEAD_UNOWNED_BYTES: &[u8] = include_bytes!("fixtures/v1/head-unowned.json");
const HEAD_OWNED_BYTES: &[u8] = include_bytes!("fixtures/v1/head-owned.json");
const CLAIM_ACTIVE_BYTES: &[u8] = include_bytes!("fixtures/v1/claim-active.json");
const CLAIM_SEALED_BYTES: &[u8] = include_bytes!("fixtures/v1/claim-sealed.json");
const PRESENCE_BYTES: &[u8] = include_bytes!("fixtures/v1/presence.json");

fn event_ref(sequence: u64, digest: &str, key: &str) -> EventRef {
    EventRef::new(sequence, digest.into(), key.into()).unwrap()
}

fn genesis() -> Event {
    Event::new(
        "op-genesis-001".into(),
        1,
        None,
        7,
        EventContent::CampaignCreated,
    )
    .unwrap()
}

fn child() -> Event {
    Event::new(
        "op-workflow-001".into(),
        2,
        Some(event_ref(1, GENESIS_DIGEST, GENESIS_KEY)),
        7,
        EventContent::WorkflowStarted,
    )
    .unwrap()
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[test]
fn literal_event_chain_decodes_and_reencodes_exactly() {
    assert_eq!(sha256(GENESIS_BYTES), GENESIS_DIGEST);
    assert_eq!(sha256(CHILD_BYTES), CHILD_DIGEST);

    let decoded_genesis = event::decode(GENESIS_BYTES, GENESIS_KEY).unwrap();
    let decoded_child = event::decode(CHILD_BYTES, CHILD_KEY).unwrap();
    assert_eq!(decoded_genesis, genesis());
    assert_eq!(decoded_child, child());
    assert_eq!(
        decoded_child.parent(),
        Some(&event_ref(1, GENESIS_DIGEST, GENESIS_KEY))
    );

    let encoded_genesis = event::encode(&decoded_genesis).unwrap();
    let encoded_child = event::encode(&decoded_child).unwrap();
    assert_eq!(encoded_genesis.stored_bytes(), GENESIS_BYTES);
    assert_eq!(encoded_genesis.digest(), GENESIS_DIGEST);
    assert_eq!(encoded_genesis.key(), GENESIS_KEY);
    assert_eq!(encoded_child.stored_bytes(), CHILD_BYTES);
    assert_eq!(encoded_child.digest(), CHILD_DIGEST);
    assert_eq!(encoded_child.key(), CHILD_KEY);
    assert_eq!(
        event::decode(GENESIS_BYTES, CHILD_KEY),
        Err(WireError::ReferenceMismatch)
    );
}

#[test]
fn literal_event_chain_converts_to_owned_scheduling_mutations() {
    let decoded_genesis = event::decode(GENESIS_BYTES, GENESIS_KEY).unwrap();
    let decoded_child = event::decode(CHILD_BYTES, CHILD_KEY).unwrap();
    let genesis_reference = event_ref(1, GENESIS_DIGEST, GENESIS_KEY);
    let child_reference = event_ref(2, CHILD_DIGEST, CHILD_KEY);

    let genesis_mutation =
        event::scheduling_mutation(genesis_reference.clone(), &decoded_genesis).unwrap();
    assert_eq!(genesis_mutation.reference(), &genesis_reference);
    assert_eq!(genesis_mutation.parent(), None);
    assert_eq!(
        genesis_mutation.effect(),
        &event::SchedulingEffect::CampaignCreated {
            campaign_id: "0000000000000001".into(),
        }
    );

    let child_mutation =
        event::scheduling_mutation(child_reference.clone(), &decoded_child).unwrap();
    assert_eq!(child_mutation.reference(), &child_reference);
    assert_eq!(
        child_mutation.parent(),
        Some(&event_ref(1, GENESIS_DIGEST, GENESIS_KEY))
    );
    assert_eq!(
        child_mutation.effect(),
        &event::SchedulingEffect::WorkflowStarted {
            workflow_id: "0000000000000002".into(),
        }
    );
}

#[test]
fn event_encoding_is_deterministic() {
    let first = event::encode(&genesis()).unwrap();
    let second = event::encode(&genesis()).unwrap();
    assert_eq!(first, second);
}

#[test]
fn literal_heads_decode_and_reencode_exactly() {
    let expected_unowned = Head::new(
        Authority::unowned(),
        event_ref(1, GENESIS_DIGEST, GENESIS_KEY),
        "op-head-genesis-001".into(),
    )
    .unwrap();
    let expected_owned = Head::new(
        Authority::owned(
            "controller-a".into(),
            "instance-01".into(),
            1_750_000_000_000,
            7,
        )
        .unwrap(),
        event_ref(2, CHILD_DIGEST, CHILD_KEY),
        "op-head-owned-001".into(),
    )
    .unwrap();

    let unowned = head::decode(HEAD_UNOWNED_BYTES).unwrap();
    let owned = head::decode(HEAD_OWNED_BYTES).unwrap();
    assert_eq!(unowned, expected_unowned);
    assert_eq!(owned, expected_owned);
    assert_eq!(head::encode(&unowned).unwrap(), HEAD_UNOWNED_BYTES);
    assert_eq!(head::encode(&owned).unwrap(), HEAD_OWNED_BYTES);
}

#[test]
fn literal_claims_decode_and_reencode_exactly() {
    let active = claims::decode(CLAIM_ACTIVE_BYTES).unwrap();
    assert_eq!(active.work_id().as_str(), "work-17");
    assert_eq!(active.work_revision(), 4);
    assert_eq!(active.owner_actor().as_str(), "rust-worker");
    assert_eq!(active.owner_instance().as_str(), "instance-a");
    assert_eq!(active.fence(), 9);
    assert_eq!(active.operation_id(), "op-claim-001");
    assert_eq!(
        active.state(),
        &ClaimState::Active {
            lease_until: 1_750_000_000_000
        }
    );
    assert_eq!(claims::encode(&active).unwrap(), CLAIM_ACTIVE_BYTES);

    let sealed = claims::decode(CLAIM_SEALED_BYTES).unwrap();
    assert_eq!(sealed.work_id().as_str(), "work-17");
    assert_eq!(sealed.work_revision(), 4);
    assert_eq!(sealed.owner_actor().as_str(), "rust-worker");
    assert_eq!(sealed.owner_instance().as_str(), "instance-a");
    assert_eq!(sealed.fence(), 9);
    assert_eq!(sealed.operation_id(), "op-claim-001");
    let ClaimState::Sealed { result_ref } = sealed.state() else {
        panic!("sealed fixture decoded as active")
    };
    assert_eq!(result_ref.digest(), "0".repeat(64));
    assert_eq!(result_ref.size(), 42);
    assert_eq!(result_ref.media_type(), "application/json");
    assert_eq!(result_ref.producer_attempt(), "attempt-17");
    assert_eq!(result_ref.creation_time_unix_ms(), 1_749_999_999_000);
    assert_eq!(result_ref.retention_class(), None);
    assert_eq!(claims::encode(&sealed).unwrap(), CLAIM_SEALED_BYTES);
}

#[test]
fn literal_presence_decodes_and_reencodes_exactly() {
    let decoded = presence::decode(PRESENCE_BYTES).unwrap();
    assert_eq!(decoded.actor().as_str(), "rust-worker");
    assert_eq!(decoded.instance().as_str(), "instance-a");
    assert_eq!(decoded.capabilities(), ["rust", "linux-x86_64"]);
    assert_eq!(decoded.expires_at_unix_ms(), 1_750_000_000_000);
    assert_eq!(presence::encode(&decoded).unwrap(), PRESENCE_BYTES);
}

#[test]
fn claim_and_presence_fixtures_fail_closed_when_mutated() {
    let active = String::from_utf8(CLAIM_ACTIVE_BYTES.to_vec()).unwrap();
    let unknown_claim_version = active.replacen("\"version\":1", "\"version\":2", 1);
    assert_eq!(
        claims::decode(unknown_claim_version.as_bytes()),
        Err(WireError::InvalidValue)
    );
    let malformed_claim = active.replacen("{", "{\"unexpected\":true,", 1);
    assert_eq!(
        claims::decode(malformed_claim.as_bytes()),
        Err(WireError::InvalidEncoding)
    );

    let record = String::from_utf8(PRESENCE_BYTES.to_vec()).unwrap();
    let unknown_presence_version = record.replacen("\"version\":1", "\"version\":2", 1);
    assert_eq!(
        presence::decode(unknown_presence_version.as_bytes()),
        Err(WireError::InvalidValue)
    );
    let invalid_expiry = record.replacen(
        "\"expires_at_unix_ms\":1750000000000",
        "\"expires_at_unix_ms\":0",
        1,
    );
    assert_eq!(
        presence::decode(invalid_expiry.as_bytes()),
        Err(WireError::InvalidValue)
    );
}
