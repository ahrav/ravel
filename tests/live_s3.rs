//! Live Amazon S3 proofs for the canonical root scope protocol.
//!
//! The suite is inert unless `RAVEL_LIVE_S3=1` names the expected bucket and region, so
//! an ordinary `cargo test` run never reaches the network. An explicit opt-in with
//! incomplete or unexpected configuration fails instead of reporting green without
//! probing S3.
//!
//! Each run derives its campaign identity from the process id and clock. No protocol path
//! deletes objects, so the suite leaves its objects behind.

use std::{
    process,
    time::{SystemTime, UNIX_EPOCH},
};

use aws_config::SdkConfig;
use aws_sdk_s3::{
    config::{Builder, Region},
    primitives::ByteStream,
};
use ravel::{
    dispatch::AttemptHistory,
    distributed::{
        identity::{InstanceId, WorkspaceId},
        scope_controller::{
            AcquireOutcome, ReleaseOutcome, RenewOutcome, STOP_MARGIN_MS, acquire, release, renew,
        },
    },
    scope::{
        AdmittedCampaignConfig, CampaignId, RootGenesis, ScopeAuthority, ScopeIdentity,
        decode_head, decode_root_event, encode_head, root_genesis, scope_event_key, scope_head_key,
    },
    storage::s3::{GetOutcome, MutationOutcome, S3Store},
    sync::{
        event::publish_root,
        head::{
            ObservedScopeHead, ScopeAppendError, ScopeHeadCommitOutcome, ScopeHeadParent,
            append_root, read,
        },
    },
};

const LIVE_FLAG: &str = "RAVEL_LIVE_S3";
const BUCKET_ENV: &str = "RAVEL_LIVE_S3_BUCKET";
const REGION_ENV: &str = "RAVEL_LIVE_S3_REGION";
const EXPECTED_BUCKET: &str = "ravel-e02-4c038b2f";
const EXPECTED_REGION: &str = "us-east-1";

// The library keeps these decode caps private, so the suite restates them.
const MAX_EVENT_BYTES: usize = 256 * 1024;
const MAX_HEAD_BYTES: usize = 4 * 1024;

const CONFIG_BYTES: &[u8] = br#"{"budget":7,"campaign":"live"}"#;

fn live_enabled() -> Result<bool, &'static str> {
    let flag = std::env::var(LIVE_FLAG).ok();
    let bucket = std::env::var(BUCKET_ENV).ok();
    let region = std::env::var(REGION_ENV).ok();
    if flag.as_deref() != Some("1") {
        return Ok(false);
    }
    if bucket.is_none() {
        return Err("live S3 opt-in is missing the bucket variable");
    }
    if region.is_none() {
        return Err("live S3 opt-in is missing the region variable");
    }
    if bucket.as_deref() != Some(EXPECTED_BUCKET) {
        return Err("unexpected live S3 bucket");
    }
    if region.as_deref() != Some(EXPECTED_REGION) {
        return Err("unexpected live S3 region");
    }
    Ok(true)
}

/// Returns `false` when the suite must not touch the network.
fn ready() -> bool {
    match live_enabled() {
        Ok(false) => {
            println!("live S3 suite skipped: set RAVEL_LIVE_S3=1, bucket, and region");
            false
        }
        Err(reason) => panic!("{reason}"),
        Ok(true) => true,
    }
}

fn store(config: &SdkConfig) -> S3Store {
    S3Store::new(
        EXPECTED_BUCKET,
        Region::new(EXPECTED_REGION),
        Builder::from(config),
    )
}

/// The root scope ID hashes workspace and campaign identity, so a per-run campaign makes
/// the whole scope prefix unique to this run.
fn run_campaign() -> CampaignId {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is after the Unix epoch")
        .as_nanos();
    CampaignId::new(format!("live-{}-{nanos}", process::id())).expect("run campaign id is valid")
}

fn genesis_for(campaign: CampaignId) -> RootGenesis {
    root_genesis(
        &AdmittedCampaignConfig::new(
            WorkspaceId::new("live-workspace".into()).expect("workspace id is valid"),
            campaign,
            CONFIG_BYTES.to_vec(),
        )
        .expect("admitted configuration is within bounds"),
    )
    .expect("root genesis is deterministic")
}

async fn observed(store: &S3Store, scope: &ScopeIdentity) -> ObservedScopeHead {
    read(store, scope)
        .await
        .expect("head read succeeds")
        .expect("head exists")
}

#[tokio::test]
async fn canonical_root_genesis_publishes_and_reads_back_exactly() {
    if !ready() {
        return;
    }
    let config = aws_config::load_from_env().await;
    let store = store(&config);
    let genesis = genesis_for(run_campaign());
    let scope = genesis.identity();

    // The same admitted configuration derives the same bytes and keys, so a repeated
    // derivation addresses the same objects.
    let repeat = genesis_for(scope.campaign_id().clone());
    assert_eq!(repeat.event_bytes(), genesis.event_bytes());
    assert_eq!(repeat.head_bytes(), genesis.head_bytes());
    assert_eq!(repeat.event_key(), genesis.event_key());

    let root = decode_root_event(genesis.event_bytes(), genesis.event_key(), scope)
        .expect("canonical fixture decodes");
    assert!(matches!(
        append_root(
            &store,
            ScopeHeadParent::Genesis,
            scope,
            &root,
            &mut AttemptHistory::default(),
            &mut AttemptHistory::default(),
        )
        .await
        .expect("root append succeeds"),
        ScopeHeadCommitOutcome::Committed(_)
    ));

    let stored_event = match store
        .get_object(genesis.event_key(), MAX_EVENT_BYTES)
        .await
        .expect("event read succeeds")
    {
        GetOutcome::Found { bytes, .. } => bytes,
        GetOutcome::NotFound => panic!("published event is missing"),
    };
    assert_eq!(stored_event, genesis.event_bytes());
    assert!(
        decode_root_event(&stored_event, genesis.event_key(), scope).is_ok(),
        "stored event decodes at its own key"
    );
    assert!(
        decode_root_event(&stored_event, "wrong-key", scope).is_err(),
        "an event must not validate against a foreign key"
    );

    let stored_head = match store
        .get_object(genesis.head_key(), MAX_HEAD_BYTES)
        .await
        .expect("head read succeeds")
    {
        GetOutcome::Found { bytes, .. } => bytes,
        GetOutcome::NotFound => panic!("published head is missing"),
    };
    assert_eq!(stored_head, genesis.head_bytes());
    let head = decode_head(&stored_head, genesis.head_key(), scope).expect("stored head decodes");
    assert_eq!(&head, genesis.head());
    assert!(matches!(head.authority(), ScopeAuthority::Unowned));
    assert_eq!(head.scope_epoch().get(), 1);
    assert_eq!(encode_head(&head).expect("head re-encodes"), stored_head);

    // Byte-identical immutable publication is not an error.
    publish_root(&store, scope, &root, &mut AttemptHistory::default())
        .await
        .expect("republishing identical bytes is not an error");

    assert!(
        store.get_object(genesis.head_key(), 1).await.is_err(),
        "a head larger than the read cap must fail closed"
    );
}

#[tokio::test]
async fn head_create_cas_and_transition_validation_hold_against_the_live_bucket() {
    if !ready() {
        return;
    }
    let config = aws_config::load_from_env().await;
    let store = store(&config);
    let genesis = genesis_for(run_campaign());
    let scope = genesis.identity();
    let root = decode_root_event(genesis.event_bytes(), genesis.event_key(), scope)
        .expect("canonical fixture decodes");

    assert!(matches!(
        append_root(
            &store,
            ScopeHeadParent::Genesis,
            scope,
            &root,
            &mut AttemptHistory::default(),
            &mut AttemptHistory::default(),
        )
        .await
        .expect("first root append succeeds"),
        ScopeHeadCommitOutcome::Committed(_)
    ));

    // A byte-identical genesis retry resolves against the retained chain instead of
    // overwriting the committed head.
    assert!(
        matches!(
            append_root(
                &store,
                ScopeHeadParent::Genesis,
                scope,
                &root,
                &mut AttemptHistory::default(),
                &mut AttemptHistory::default(),
            )
            .await
            .expect("repeated root append resolves"),
            ScopeHeadCommitOutcome::Committed(_)
        ),
        "a byte-identical genesis retry must resolve as committed"
    );

    // Create-if-absent against the live head key now fails its precondition.
    assert!(
        matches!(
            store
                .put_if_absent(
                    &scope_head_key(scope),
                    genesis.head_bytes().to_vec(),
                    &mut AttemptHistory::default(),
                )
                .await,
            MutationOutcome::Conflict | MutationOutcome::PreconditionFailed
        ),
        "create-if-absent must fail once the head exists"
    );

    assert_eq!(
        scope_event_key(scope, genesis.event_ref()),
        genesis.event_key()
    );

    // Transition binding negatives are proven by unit tests; a read alone cannot mint the
    // fenced boundary those cases would need.

    // The head still holds exactly the canonical genesis bytes after every rejection.
    let final_head = observed(&store, scope).await;
    assert_eq!(final_head.canonical_bytes(), genesis.head_bytes());
    assert_eq!(final_head.head().tail(), genesis.event_ref());
}

#[tokio::test]
async fn root_controller_lifecycle_fences_a_stale_owner() {
    if !ready() {
        return;
    }
    let config = aws_config::load_from_env().await;
    let store = store(&config);
    let genesis = genesis_for(run_campaign());
    let scope = genesis.identity();
    let root = decode_root_event(genesis.event_bytes(), genesis.event_key(), scope)
        .expect("canonical fixture decodes");
    assert!(matches!(
        append_root(
            &store,
            ScopeHeadParent::Genesis,
            scope,
            &root,
            &mut AttemptHistory::default(),
            &mut AttemptHistory::default(),
        )
        .await
        .expect("root append succeeds"),
        ScopeHeadCommitOutcome::Committed(_)
    ));

    let now_ms = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock is after the Unix epoch")
            .as_millis(),
    )
    .expect("current Unix time fits u64 milliseconds");
    let old = InstanceId::new("live-old-controller".into()).expect("instance id is valid");
    let new = InstanceId::new("live-new-controller".into()).expect("instance id is valid");
    let AcquireOutcome::Acquired(old_authority) = acquire(&store, scope, &old, now_ms)
        .await
        .expect("initial acquisition succeeds")
    else {
        panic!("expected initial acquisition");
    };
    let RenewOutcome::Renewed(old_authority) = renew(&store, old_authority, now_ms + 10_000)
        .await
        .expect("renewal succeeds")
    else {
        panic!("expected renewal");
    };
    let takeover_at = old_authority.lease_until().get();
    let AcquireOutcome::Acquired(new_authority) = acquire(&store, scope, &new, takeover_at)
        .await
        .expect("takeover succeeds")
    else {
        panic!("expected takeover");
    };

    // Old holder's lagging clock still considers its term usable, but its retained ETag is fenced.
    let stale_now = takeover_at - STOP_MARGIN_MS - 1;
    assert!(matches!(
        renew(&store, old_authority, stale_now)
            .await
            .expect("stale renewal resolves"),
        RenewOutcome::Lost
    ));
    assert!(matches!(
        release(&store, new_authority.stop())
            .await
            .expect("release succeeds"),
        ReleaseOutcome::Released
    ));
    let final_head = observed(&store, scope).await;
    assert!(matches!(
        final_head.head().authority(),
        ScopeAuthority::Unowned
    ));
}

#[tokio::test]
async fn bounded_reads_reject_oversized_objects() {
    if !ready() {
        return;
    }
    let config = aws_config::load_from_env().await;
    let store = store(&config);
    let campaign = run_campaign();
    let key = format!(
        "workspace/live-workspace/campaigns/{}/oversized",
        campaign.as_str()
    );

    let client = aws_sdk_s3::Client::from_conf(
        Builder::from(&config)
            .region(Region::new(EXPECTED_REGION))
            .build(),
    );
    let body = vec![b'x'; MAX_EVENT_BYTES + 1];
    client
        .put_object()
        .bucket(EXPECTED_BUCKET)
        .key(&key)
        .if_none_match("*")
        .body(ByteStream::from(body.clone()))
        .send()
        .await
        .expect("oversized fixture upload succeeds");

    assert!(
        store.get_object(&key, MAX_EVENT_BYTES).await.is_err(),
        "an object above the read cap must fail closed"
    );
    match store
        .get_object(&key, body.len())
        .await
        .expect("a cap at the exact size succeeds")
    {
        GetOutcome::Found { bytes, .. } => assert_eq!(bytes.len(), body.len()),
        GetOutcome::NotFound => panic!("uploaded object is missing"),
    }
}

#[tokio::test]
async fn append_reports_publication_errors_with_exact_dispatch_evidence() {
    if !ready() {
        return;
    }
    let config = aws_config::load_from_env().await;
    let campaign = run_campaign();
    let unwritable = S3Store::new(
        format!("ravel-live-absent-{}", campaign.as_str()),
        Region::new(EXPECTED_REGION),
        Builder::from(&config),
    );
    let genesis = genesis_for(campaign);
    let scope = genesis.identity();
    let root = decode_root_event(genesis.event_bytes(), genesis.event_key(), scope)
        .expect("canonical fixture decodes");

    let mut event_history = AttemptHistory::default();
    let outcome = append_root(
        &unwritable,
        ScopeHeadParent::Genesis,
        scope,
        &root,
        &mut event_history,
        &mut AttemptHistory::default(),
    )
    .await;
    assert!(
        matches!(outcome, Err(ScopeAppendError::Publication(_))),
        "an unwritable bucket must surface a publication error"
    );
    assert!(
        !event_history.may_have_been_sent(),
        "an absent bucket answers with a proven 404, which must not claim a possible send"
    );
}
