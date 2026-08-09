use ravel::{
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
