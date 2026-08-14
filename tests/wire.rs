use ciborium::Value;
use ravel::{
    distributed::identity::{InstanceId, WorkspaceId},
    domain::{
        validation::ValidationError,
        work::{WorkId, WorkRef},
    },
    scope::{
        AdmittedCampaignConfig, CampaignId, Digest, EventEnvelope, ScopeAuthority,
        ScopeClaimIdentity, ScopeEventRef, ScopeHead, ScopeId, ScopeIdentity, artifact_key,
        decode_head, decode_root_event, encode_head, encode_root_event, plan_key, root_genesis,
        root_scope_id, scope_claim_key, scope_event_key, scope_head_key,
    },
    sync::WireError,
};
use sha2::{Digest as _, Sha256};

const SCOPE_ID: &str = "0eb5db70036c5eec302d8bb83aae83e6394514453da922747159e92bce51034b";
const EVENT_DIGEST: &str = "0e180b9203c97f2961404817cef51750a24c0fe2e17e0e63e432ad46c9c12969";
const EVENT_BASENAME: &str =
    "0000000000000001-0e180b9203c97f2961404817cef51750a24c0fe2e17e0e63e432ad46c9c12969.cbor.zst";
const EVENT_BYTES: &[u8] = include_bytes!(
    "fixtures/wire/0000000000000001-0e180b9203c97f2961404817cef51750a24c0fe2e17e0e63e432ad46c9c12969.cbor.zst"
);
const HEAD_BYTES: &[u8] = include_bytes!("fixtures/wire/root-head.json");
const CONFIG_BYTES: &[u8] = br#"{"budget":7,"campaign":"campaign-a"}"#;

const ENVELOPE_FIELDS: [&str; 6] = [
    "scope_id",
    "sequence",
    "parent_event",
    "writer_epoch",
    "operation_id",
    "payload_type",
];

const PAYLOAD_FIELDS: [&str; 4] = [
    "campaign_id",
    "parent_scope_id",
    "delegation_digest",
    "config_digest",
];

fn workspace() -> WorkspaceId {
    WorkspaceId::new("workspace-a".into()).unwrap()
}

fn campaign() -> CampaignId {
    CampaignId::new("campaign-a".into()).unwrap()
}

fn config(bytes: &[u8]) -> AdmittedCampaignConfig {
    AdmittedCampaignConfig::new(workspace(), campaign(), bytes.to_vec()).unwrap()
}

fn config_for(workspace: &str, campaign: &str) -> AdmittedCampaignConfig {
    AdmittedCampaignConfig::new(
        WorkspaceId::new(workspace.into()).unwrap(),
        CampaignId::new(campaign.into()).unwrap(),
        CONFIG_BYTES.to_vec(),
    )
    .unwrap()
}

fn scope() -> ScopeIdentity {
    ScopeIdentity::root(workspace(), campaign()).unwrap()
}

fn full_head_key() -> String {
    format!("workspace/workspace-a/campaigns/campaign-a/scopes/{SCOPE_ID}/head")
}

fn full_event_key() -> String {
    format!("workspace/workspace-a/campaigns/campaign-a/scopes/{SCOPE_ID}/events/{EVENT_BASENAME}")
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn map_mut(value: &mut Value) -> &mut Vec<(Value, Value)> {
    let Value::Map(entries) = value else {
        panic!("expected CBOR map");
    };
    entries
}

fn field_mut<'a>(entries: &'a mut [(Value, Value)], name: &str) -> &'a mut Value {
    entries
        .iter_mut()
        .find_map(|(key, value)| (key == &Value::Text(name.into())).then_some(value))
        .unwrap_or_else(|| panic!("missing CBOR field {name}"))
}

fn keys(entries: &[(Value, Value)]) -> Vec<String> {
    entries
        .iter()
        .map(|(key, _)| match key {
            Value::Text(text) => text.clone(),
            other => panic!("expected text key, found {other:?}"),
        })
        .collect()
}

fn event_cbor() -> Vec<u8> {
    zstd::bulk::decompress(EVENT_BYTES, 1024 * 1024).unwrap()
}

fn mutate_event(mutator: impl FnOnce(&mut Vec<(Value, Value)>)) -> Vec<u8> {
    let mut value: Value = ciborium::from_reader(event_cbor().as_slice()).unwrap();
    mutator(map_mut(&mut value));
    let mut changed = Vec::new();
    ciborium::into_writer(&value, &mut changed).unwrap();
    zstd::bulk::compress(&changed, 3).unwrap()
}

#[test]
fn root_genesis_fixture_is_deterministic_and_canonical() {
    let first = root_genesis(&config(CONFIG_BYTES)).unwrap();
    let second = root_genesis(&config(CONFIG_BYTES)).unwrap();

    assert_eq!(first, second);
    assert_eq!(first.identity().workspace_id(), &workspace());
    assert_eq!(first.identity().campaign_id(), &campaign());
    assert_eq!(first.identity().scope_id().as_str(), SCOPE_ID);
    assert_eq!(first.identity().parent_scope_id(), None);
    assert_eq!(first.identity().delegation_digest(), None);
    assert_eq!(first.event_ref().digest().as_str(), EVENT_DIGEST);
    assert_eq!(first.event_bytes(), EVENT_BYTES);
    assert_eq!(first.head_bytes(), HEAD_BYTES);
    assert_eq!(sha256(EVENT_BYTES), EVENT_DIGEST);
    assert_eq!(first.event_key(), full_event_key());
    assert_eq!(first.head_key(), full_head_key());

    let decoded_event = decode_root_event(EVENT_BYTES, &full_event_key(), &scope()).unwrap();
    assert_eq!(decoded_event.envelope().sequence(), 1);
    assert_eq!(decoded_event.envelope().parent_event(), None);
    assert_eq!(decoded_event.envelope().writer_epoch().get(), 1);
    assert_eq!(
        decoded_event.envelope().operation_id(),
        format!("root-genesis:{SCOPE_ID}")
    );
    assert_eq!(decoded_event.envelope().payload_type(), "root_genesis");
    assert_eq!(decoded_event.payload().campaign_id(), &campaign());
    assert_eq!(
        encode_root_event(&decoded_event).unwrap().stored_bytes(),
        EVENT_BYTES
    );

    let decoded_head = decode_head(HEAD_BYTES, &full_head_key(), &scope()).unwrap();
    assert_eq!(&decoded_head, first.head());
    assert_eq!(encode_head(&decoded_head).unwrap(), HEAD_BYTES);
    assert!(matches!(decoded_head.authority(), ScopeAuthority::Unowned));
    assert_eq!(decoded_head.scope_epoch().get(), 1);
    assert_eq!(decoded_head.active_plan_digest(), None);

    let head_text = std::str::from_utf8(HEAD_BYTES).unwrap();
    assert!(head_text.contains("\"controller_instance_id\":null"));
    assert!(head_text.contains("\"lease_until\":null"));
    assert!(head_text.contains("\"active_plan_digest\":null"));
    assert!(!head_text.contains("version"));

    let mut value: Value = ciborium::from_reader(event_cbor().as_slice()).unwrap();
    let root = map_mut(&mut value);
    assert_eq!(keys(root), ["envelope", "payload"]);
    let envelope = map_mut(field_mut(root, "envelope"));
    assert_eq!(keys(envelope), ENVELOPE_FIELDS);
    let payload = map_mut(field_mut(root, "payload"));
    assert_eq!(keys(payload), PAYLOAD_FIELDS);
    assert_eq!(field_mut(payload, "parent_scope_id"), &Value::Null);
    assert_eq!(field_mut(payload, "delegation_digest"), &Value::Null);
}

#[test]
fn config_bytes_change_payload_but_not_root_scope_identity() {
    let first = root_genesis(&config(CONFIG_BYTES)).unwrap();
    let changed = root_genesis(&config(br#"{"budget":8,"campaign":"campaign-a"}"#)).unwrap();

    assert_eq!(first.identity().scope_id(), changed.identity().scope_id());
    assert_ne!(first.config_digest(), changed.config_digest());
    assert_ne!(first.event_bytes(), changed.event_bytes());
    assert_ne!(first.event_key(), changed.event_key());
    assert_ne!(first.head_bytes(), changed.head_bytes());

    let other_workspace = WorkspaceId::new("workspace-b".into()).unwrap();
    assert_ne!(
        root_scope_id(&workspace(), &campaign()).unwrap(),
        root_scope_id(&other_workspace, &campaign()).unwrap()
    );
    assert_ne!(
        root_scope_id(&workspace(), &campaign()).unwrap(),
        root_scope_id(&workspace(), &CampaignId::new("campaign-b".into()).unwrap()).unwrap()
    );
}

#[test]
fn scope_keys_cover_the_exact_identity_axis() {
    let scope = scope();
    let digest = Digest::new("0".repeat(64)).unwrap();
    let claim = ScopeClaimIdentity::new(
        scope.clone(),
        digest.clone(),
        WorkRef::new(WorkId::new("work-17".into()).unwrap(), 4),
        9,
    )
    .unwrap();
    let event = ScopeEventRef::new(2, digest.clone()).unwrap();

    assert_eq!(scope_head_key(&scope), full_head_key());
    assert_eq!(
        scope_event_key(&scope, &event),
        format!(
            "workspace/workspace-a/campaigns/campaign-a/scopes/{SCOPE_ID}/events/0000000000000002-{}.cbor.zst",
            digest.as_str()
        )
    );
    assert_eq!(
        scope_claim_key(claim.scope(), claim.work()),
        format!("workspace/workspace-a/campaigns/campaign-a/scopes/{SCOPE_ID}/claims/work-17/4")
    );
    assert_eq!(claim.plan_digest(), &digest);
    assert_eq!(claim.claim_fence().get(), 9);
    assert_eq!(
        plan_key(&workspace(), &campaign(), &digest),
        format!(
            "workspace/workspace-a/campaigns/campaign-a/plans/{}",
            digest.as_str()
        )
    );
    assert_eq!(
        artifact_key(&workspace(), &campaign(), &digest),
        format!(
            "workspace/workspace-a/campaigns/campaign-a/artifacts/{}",
            digest.as_str()
        )
    );
    assert_eq!(
        ScopeClaimIdentity::new(scope, digest, claim.work().clone(), 0),
        Err(ValidationError::InvalidFence)
    );
}

#[test]
fn identity_and_numeric_boundaries_fail_closed() {
    assert!(CampaignId::new(String::new()).is_err());
    assert!(CampaignId::new("a/b".into()).is_err());
    assert!(ScopeId::new("A".repeat(64)).is_err());
    assert!(ScopeId::new("0".repeat(63)).is_err());
    assert!(Digest::new("g".repeat(64)).is_err());
    assert_eq!(
        AdmittedCampaignConfig::new(workspace(), campaign(), Vec::new()),
        Err(WireError::InvalidValue)
    );
    assert!(AdmittedCampaignConfig::new(workspace(), campaign(), vec![0; 1024 * 1024]).is_ok());
    assert_eq!(
        AdmittedCampaignConfig::new(workspace(), campaign(), vec![0; 1024 * 1024 + 1]),
        Err(WireError::LimitExceeded)
    );
    let digest = Digest::new("0".repeat(64)).unwrap();
    assert_eq!(
        ScopeEventRef::new(0, digest.clone()),
        Err(ValidationError::InvalidSequence)
    );
    assert!(ScopeEventRef::new(9_999_999_999_999_999, digest.clone()).is_ok());
    assert_eq!(
        ScopeEventRef::new(10_000_000_000_000_000, digest),
        Err(ValidationError::InvalidSequence)
    );
    assert_eq!(
        EventEnvelope::new(
            ScopeId::new(SCOPE_ID.into()).unwrap(),
            1,
            None,
            0,
            "op".into(),
            "payload".into(),
        ),
        Err(ValidationError::InvalidFence)
    );
    assert_eq!(
        ScopeAuthority::owned(InstanceId::new("instance".into()).unwrap(), 0),
        Err(ValidationError::InvalidExpiry)
    );
    assert_eq!(
        ScopeHead::new(
            scope(),
            ScopeAuthority::Unowned,
            0,
            ScopeEventRef::new(1, Digest::new("0".repeat(64)).unwrap()).unwrap(),
            None,
            "op".into(),
        ),
        Err(ValidationError::InvalidFence)
    );
}

#[test]
fn non_root_values_and_invalid_identities_fail_before_key_use() {
    for bytes in [
        mutate_event(|root| {
            let envelope = map_mut(field_mut(root, "envelope"));
            *field_mut(envelope, "payload_type") = Value::Text("future".into());
        }),
        mutate_event(|root| {
            let payload = map_mut(field_mut(root, "payload"));
            *field_mut(payload, "parent_scope_id") = Value::Text(SCOPE_ID.into());
        }),
        mutate_event(|root| {
            let payload = map_mut(field_mut(root, "payload"));
            *field_mut(payload, "delegation_digest") = Value::Text("0".repeat(64));
        }),
        mutate_event(|root| {
            let envelope = map_mut(field_mut(root, "envelope"));
            *field_mut(envelope, "scope_id") = Value::Text("A".repeat(64));
        }),
        mutate_event(|root| {
            let envelope = map_mut(field_mut(root, "envelope"));
            *field_mut(envelope, "sequence") = Value::Integer(0.into());
        }),
        mutate_event(|root| {
            let envelope = map_mut(field_mut(root, "envelope"));
            *field_mut(envelope, "writer_epoch") = Value::Integer(0.into());
        }),
        mutate_event(|root| {
            let envelope = map_mut(field_mut(root, "envelope"));
            *field_mut(envelope, "writer_epoch") = Value::Integer(2.into());
        }),
        mutate_event(|root| {
            let envelope = map_mut(field_mut(root, "envelope"));
            *field_mut(envelope, "operation_id") = Value::Text("wrong-op".into());
        }),
        mutate_event(|root| {
            let envelope = map_mut(field_mut(root, "envelope"));
            *field_mut(envelope, "parent_event") = Value::Map(vec![
                (Value::Text("sequence".into()), Value::Integer(1.into())),
                (Value::Text("digest".into()), Value::Text("a".repeat(64))),
            ]);
        }),
        mutate_event(|root| {
            let payload = map_mut(field_mut(root, "payload"));
            *field_mut(payload, "campaign_id") = Value::Text("campaign/a".into());
        }),
        mutate_event(|root| {
            let payload = map_mut(field_mut(root, "payload"));
            *field_mut(payload, "config_digest") = Value::Text("invalid".into());
        }),
    ] {
        assert_eq!(
            decode_root_event(&bytes, "deliberately-wrong-key", &scope()),
            Err(WireError::InvalidValue)
        );
    }
}

#[test]
fn unknown_fields_fail_closed_on_events_and_heads() {
    for bytes in [
        mutate_event(|root| {
            root.push((Value::Text("extra".into()), Value::Null));
        }),
        mutate_event(|root| {
            let envelope = map_mut(field_mut(root, "envelope"));
            envelope.push((Value::Text("extra_envelope".into()), Value::Null));
        }),
        mutate_event(|root| {
            let envelope = map_mut(field_mut(root, "envelope"));
            envelope.push((Value::Text("writer_fence".into()), Value::Integer(1.into())));
        }),
        mutate_event(|root| {
            let payload = map_mut(field_mut(root, "payload"));
            payload.push((Value::Text("retention_class".into()), Value::Null));
        }),
    ] {
        assert_eq!(
            decode_root_event(&bytes, &full_event_key(), &scope()),
            Err(WireError::InvalidEncoding)
        );
    }

    let canonical = std::str::from_utf8(HEAD_BYTES).unwrap();
    for injected in [
        r#"{"owner":"nobody","#,
        r#"{"controller_fence":1,"#,
        r#"{"authority":null,"#,
    ] {
        assert_eq!(
            decode_head(
                canonical.replacen('{', injected, 1).as_bytes(),
                &full_head_key(),
                &scope()
            ),
            Err(WireError::InvalidEncoding)
        );
    }
}

#[test]
fn event_canonicality_fails_closed_and_payload_type_is_checked_first() {
    let cbor = event_cbor();
    let alternate_level = zstd::bulk::compress(&cbor, 1).unwrap();
    assert_ne!(alternate_level, EVENT_BYTES);
    assert_eq!(
        decode_root_event(&alternate_level, "wrong", &scope()),
        Err(WireError::NonCanonical)
    );

    let no_content_size = zstd::stream::encode_all(cbor.as_slice(), 3).unwrap();
    assert!(matches!(
        zstd::zstd_safe::get_frame_content_size(&no_content_size),
        Ok(None)
    ));
    assert_eq!(
        decode_root_event(&no_content_size, "wrong", &scope()),
        Err(WireError::NonCanonical)
    );

    let oversized_content = zstd::bulk::compress(&vec![0; 2 * 1024 * 1024], 3).unwrap();
    assert_eq!(
        decode_root_event(&oversized_content, "wrong", &scope()),
        Err(WireError::LimitExceeded)
    );

    let mut indefinite_map = cbor.clone();
    assert_eq!(indefinite_map[0], 0xa2);
    indefinite_map[0] = 0xbf;
    indefinite_map.push(0xff);
    let indefinite_map = zstd::bulk::compress(&indefinite_map, 3).unwrap();
    assert_eq!(
        decode_root_event(&indefinite_map, "wrong", &scope()),
        Err(WireError::NonCanonical)
    );

    let mut trailing = cbor;
    trailing.push(0);
    let trailing = zstd::bulk::compress(&trailing, 3).unwrap();
    assert_eq!(
        decode_root_event(&trailing, "wrong", &scope()),
        Err(WireError::NonCanonical)
    );

    let unregistered = mutate_event(|root| {
        let envelope = map_mut(field_mut(root, "envelope"));
        *field_mut(envelope, "payload_type") = Value::Text("future".into());
    });
    let mut unregistered_cbor = zstd::bulk::decompress(&unregistered, 1024 * 1024).unwrap();
    unregistered_cbor.push(0);
    let unregistered_noncanonical = zstd::bulk::compress(&unregistered_cbor, 3).unwrap();
    assert_eq!(
        decode_root_event(&unregistered_noncanonical, "wrong", &scope()),
        Err(WireError::InvalidValue)
    );
}

#[test]
fn event_envelope_enforces_parent_linkage() {
    let scope_id = scope().scope_id().clone();
    let digest = Digest::new("0".repeat(64)).unwrap();
    let first = ScopeEventRef::new(1, digest.clone()).unwrap();
    let second = ScopeEventRef::new(2, digest).unwrap();
    let make = |sequence, parent| {
        EventEnvelope::new(
            scope_id.clone(),
            sequence,
            parent,
            1,
            "op".into(),
            "payload".into(),
        )
    };

    assert_eq!(
        make(1, Some(first.clone())),
        Err(ValidationError::InvalidParent)
    );
    assert_eq!(make(2, None), Err(ValidationError::InvalidParent));
    assert_eq!(make(2, Some(second)), Err(ValidationError::InvalidParent));
    assert!(make(2, Some(first)).is_ok());
}

#[test]
fn foreign_scope_records_cannot_substitute_for_expected_scope() {
    for foreign in [
        root_genesis(&config_for("workspace-a", "campaign-b")).unwrap(),
        root_genesis(&config_for("workspace-b", "campaign-a")).unwrap(),
    ] {
        assert_eq!(
            decode_root_event(foreign.event_bytes(), foreign.event_key(), &scope()),
            Err(WireError::InvalidValue)
        );
        assert_eq!(
            decode_head(foreign.head_bytes(), foreign.head_key(), &scope()),
            Err(WireError::InvalidValue)
        );
    }
    assert_eq!(
        decode_head(HEAD_BYTES, "wrong", &scope()),
        Err(WireError::ReferenceMismatch)
    );
}

#[test]
fn head_authority_pairs_and_canonical_form_fail_closed() {
    let canonical = std::str::from_utf8(HEAD_BYTES).unwrap();
    for altered in [
        canonical.replacen("\"lease_until\":null", "\"lease_until\":1", 1),
        canonical.replacen(
            "\"controller_instance_id\":null",
            "\"controller_instance_id\":\"instance-a\"",
            1,
        ),
        canonical.replacen("\"scope_epoch\":1", "\"scope_epoch\":0", 1),
    ] {
        assert_eq!(
            decode_head(altered.as_bytes(), &full_head_key(), &scope()),
            Err(WireError::InvalidValue)
        );
    }
    assert_eq!(
        decode_head(
            format!("{canonical}\n").as_bytes(),
            &full_head_key(),
            &scope()
        ),
        Err(WireError::NonCanonical)
    );
    assert_eq!(
        decode_head(
            HEAD_BYTES,
            &full_head_key(),
            &ScopeIdentity::root(WorkspaceId::new("other".into()).unwrap(), campaign()).unwrap()
        ),
        Err(WireError::InvalidValue)
    );

    let fixture = root_genesis(&config(CONFIG_BYTES)).unwrap();
    let owned = ScopeHead::new(
        scope(),
        ScopeAuthority::owned(InstanceId::new("instance-a".into()).unwrap(), 99).unwrap(),
        2,
        fixture.event_ref().clone(),
        Some(Digest::new("0".repeat(64)).unwrap()),
        "owned-head".into(),
    )
    .unwrap();
    let bytes = encode_head(&owned).unwrap();
    assert_eq!(
        decode_head(&bytes, &full_head_key(), &scope()).unwrap(),
        owned
    );
}

#[test]
fn unrelated_and_obsolete_shaped_bytes_fail_as_malformed_input() {
    let obsolete_head = br#"{"authority":{"state":"unowned"},"tail":{"sequence":1,"digest":"a"},"operation_id":"op"}"#;
    assert_eq!(
        decode_head(obsolete_head, &full_head_key(), &scope()),
        Err(WireError::InvalidEncoding)
    );

    let mut obsolete_event_cbor = Vec::new();
    ciborium::into_writer(
        &Value::Map(vec![
            (
                Value::Text("operation_id".into()),
                Value::Text("operation-1".into()),
            ),
            (Value::Text("sequence".into()), Value::Integer(1.into())),
            (Value::Text("parent".into()), Value::Null),
            (Value::Text("writer_fence".into()), Value::Integer(1.into())),
            (
                Value::Text("content".into()),
                Value::Text("campaign_created".into()),
            ),
        ]),
        &mut obsolete_event_cbor,
    )
    .unwrap();
    let obsolete_event = zstd::bulk::compress(&obsolete_event_cbor, 3).unwrap();
    assert_eq!(
        decode_root_event(&obsolete_event, &full_event_key(), &scope()),
        Err(WireError::InvalidEncoding)
    );

    for unrelated in [b"not-json".as_slice(), b"\x00\x01\x02".as_slice()] {
        assert_eq!(
            decode_head(unrelated, &full_head_key(), &scope()),
            Err(WireError::InvalidEncoding)
        );
        assert_eq!(
            decode_root_event(unrelated, &full_event_key(), &scope()),
            Err(WireError::InvalidEncoding)
        );
    }
}

#[test]
fn size_and_reference_boundaries_fail_closed() {
    assert_eq!(
        decode_root_event(&[], "wrong", &scope()),
        Err(WireError::LimitExceeded)
    );
    assert_eq!(
        decode_root_event(&vec![0; 256 * 1024 + 1], "wrong", &scope()),
        Err(WireError::LimitExceeded)
    );
    assert_eq!(
        decode_head(&[], "wrong", &scope()),
        Err(WireError::LimitExceeded)
    );
    assert_eq!(
        decode_head(&vec![b' '; 4 * 1024 + 1], "wrong", &scope()),
        Err(WireError::LimitExceeded)
    );
    assert_eq!(
        decode_root_event(EVENT_BYTES, "wrong", &scope()),
        Err(WireError::ReferenceMismatch)
    );
}
