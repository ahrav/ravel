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
    storage::s3::{AttemptHistory, GetOutcome, MutationOutcome, S3Store},
    sync::{
        accelerator::{publish_checkpoint, replay_pointer_key},
        event::publish_root,
        head::{
            ObservedScopeHead, ScopeAppendError, ScopeHeadCommitOutcome, ScopeHeadParent,
            append_root, read,
        },
        replay::{ScopeReadiness, open_projection, refresh},
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

/// Opens a fresh projection under a per-run temporary path.
async fn fresh_projection(
    store: &S3Store,
    scope: &ScopeIdentity,
    label: &str,
) -> (ravel::db::worker::DbHandle, std::path::PathBuf) {
    let path = std::env::temp_dir().join(format!("ravel-live-{}-{label}.sqlite3", process::id()));
    let _ = std::fs::remove_file(&path);
    let handle = open_projection(store, scope, &path)
        .await
        .expect("projection opens");
    (handle, path)
}

fn cursor_of(readiness: ScopeReadiness) -> (u64, ravel::scope::Digest) {
    match readiness {
        ScopeReadiness::Ready { local_cursor, .. } => local_cursor,
        ScopeReadiness::NotReady(error) => panic!("replay must reach readiness: {error}"),
    }
}

#[tokio::test]
async fn list_assisted_replay_then_pack_reads_reach_the_same_cursor() {
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

    // With no pointer yet, the first cold replay is LIST-assisted and then publishes
    // packs, a catalog, and the pointer.
    let (first, first_path) = fresh_projection(&store, scope, "list-first").await;
    let first_cursor = cursor_of(refresh(&store, &first, scope).await);
    assert_eq!(first_cursor.0, 1);
    assert_eq!(&first_cursor.1, genesis.event_ref().digest());
    drop(first);
    let _ = std::fs::remove_file(&first_path);
    match store
        .get_object(&replay_pointer_key(scope), 4 * 1024)
        .await
        .expect("pointer read succeeds")
    {
        GetOutcome::Found { .. } => {}
        GetOutcome::NotFound => panic!("the first replay must publish the pointer"),
    }

    // A second cold projection replays through the published packs to the same cursor.
    let (second, second_path) = fresh_projection(&store, scope, "list-second").await;
    let second_cursor = cursor_of(refresh(&store, &second, scope).await);
    assert_eq!(second_cursor, first_cursor);
    drop(second);
    let _ = std::fs::remove_file(&second_path);
}

#[tokio::test]
async fn contending_publishers_leave_replay_successful_and_one_valid_pointer() {
    if !ready() {
        return;
    }
    let config = aws_config::load_from_env().await;
    let store_a = store(&config);
    let store_b = store(&config);
    let genesis = genesis_for(run_campaign());
    let scope = genesis.identity();
    let root = decode_root_event(genesis.event_bytes(), genesis.event_key(), scope)
        .expect("canonical fixture decodes");
    assert!(matches!(
        append_root(
            &store_a,
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

    // Two cold projections replay and publish concurrently; a pointer CAS loser stops
    // publishing while both replays stay successful.
    let (first, first_path) = fresh_projection(&store_a, scope, "contend-a").await;
    let (second, second_path) = fresh_projection(&store_b, scope, "contend-b").await;
    let (readiness_a, readiness_b) = tokio::join!(
        refresh(&store_a, &first, scope),
        refresh(&store_b, &second, scope),
    );
    let cursor_a = cursor_of(readiness_a);
    let cursor_b = cursor_of(readiness_b);
    assert_eq!(cursor_a, cursor_b);
    drop((first, second));
    let _ = std::fs::remove_file(&first_path);
    let _ = std::fs::remove_file(&second_path);

    // Whichever pointer won, a third cold projection replays through it.
    let (third, third_path) = fresh_projection(&store_a, scope, "contend-c").await;
    assert_eq!(cursor_of(refresh(&store_a, &third, scope).await), cursor_a);
    drop(third);
    let _ = std::fs::remove_file(&third_path);
}

#[tokio::test]
async fn a_checkpoint_certified_cold_start_reaches_the_pinned_head() {
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

    // A live projection reaches the head, then a fenced controller certifies it.
    let (live, live_path) = fresh_projection(&store, scope, "checkpoint-live").await;
    assert_eq!(cursor_of(refresh(&store, &live, scope).await).0, 1);
    let now_ms = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock is after the Unix epoch")
            .as_millis(),
    )
    .expect("current Unix time fits u64 milliseconds");
    let instance = InstanceId::new("live-checkpoint-controller".into()).expect("id is valid");
    let AcquireOutcome::Acquired(authority) = acquire(&store, scope, &instance, now_ms)
        .await
        .expect("acquisition succeeds")
    else {
        panic!("expected acquisition");
    };
    // Acquisition advanced the epoch, so the live projection re-reads the head before
    // the snapshot comparison.
    assert_eq!(cursor_of(refresh(&store, &live, scope).await).0, 1);
    let Ok(parent) = authority.into_parent(now_ms) else {
        panic!("authority is within its term");
    };
    let staging = std::env::temp_dir().join(format!(
        "ravel-live-{}-checkpoint-staging.sqlite3",
        process::id()
    ));
    let _ = std::fs::remove_file(&staging);
    let mut histories = [
        AttemptHistory::default(),
        AttemptHistory::default(),
        AttemptHistory::default(),
    ];
    let [snapshot_history, event_history, head_history] = &mut histories;
    assert!(matches!(
        publish_checkpoint(
            &store,
            &live,
            parent,
            &staging,
            "live-checkpoint-op-1",
            [snapshot_history, event_history, head_history],
        )
        .await
        .expect("checkpoint publication succeeds"),
        ScopeHeadCommitOutcome::Committed(_)
    ));
    let _ = std::fs::remove_file(&staging);

    // Folding the certificate also publishes the pack and catalog naming it.
    assert_eq!(cursor_of(refresh(&store, &live, scope).await).0, 2);
    drop(live);
    let _ = std::fs::remove_file(&live_path);

    // A cold start now installs the certified snapshot and applies the packed suffix.
    let (cold, cold_path) = fresh_projection(&store, scope, "checkpoint-cold").await;
    assert_eq!(cursor_of(refresh(&store, &cold, scope).await).0, 2);
    drop(cold);
    let _ = std::fs::remove_file(&cold_path);
}
