//! Root-scope controller authority over one `ScopeHead`.
//!
//! Lease duration is 30 s, renewal cadence 10 s, and stop margin 5 s, so two renewal
//! attempts precede the margin and one lost renewal response does not cost authority.
//! Fencing is the correctness mechanism and the lease is liveness only: acquisition, renewal,
//! and relinquishment each advance the monotonic `scope_epoch`, and each transition
//! conditionally replaces the exact observed head. The `scope_epoch` is separate from every
//! work `claim_fence`.
//!
//! A transition that stays unresolved never extends the pinned lease deadline; one that
//! resolves to a proven commit adopts the term the committed head carries. Takeover requires a
//! freshly read head whose lease has already expired.
//!
//! Every millisecond value here is a Unix-epoch reading from one clock base shared with
//! `db::projections` claim leases. One appended event consumes the authority value, so a
//! controller that keeps deciding reacquires from a freshly read head.
//! commentlint: allow(JUDGE)

use std::num::NonZeroU64;

use crate::{
    distributed::identity::InstanceId,
    scope::{ScopeAuthority, ScopeHead, ScopeIdentity, encode_head, scope_head_key},
    storage::s3::{AttemptHistory, MutationOutcome, S3Store},
    sync::head::{self as head, ObservedScopeHead, ScopeHeadParent, ScopeHeadReadError},
};

/// Lease term granted by one acquisition or renewal, in milliseconds.
pub const LEASE_DURATION_MS: u64 = 30_000;
/// Interval between renewal attempts, in milliseconds.
pub const RENEWAL_INTERVAL_MS: u64 = 10_000;
/// Remaining lease below which the holder stops issuing authoritative mutations.
pub const STOP_MARGIN_MS: u64 = 5_000;

/// Proven root-controller authority for one scope.
///
/// The value is not clonable and not constructible outside this module, so a raw instance,
/// epoch, or lease value cannot stand in for proof of ownership. Its lease deadline is the
/// positively known term carried by the head that proved it.
///
/// Ownership proof assumes the instance ID belongs to one live incarnation, as
/// [`InstanceId::generate`] produces; a reused persisted ID would let a successor process adopt
/// its predecessor's term.
pub struct ControllerAuthority {
    observed: Box<ObservedScopeHead>,
    instance: InstanceId,
    lease_until: NonZeroU64,
}

impl ControllerAuthority {
    pub fn head(&self) -> &ScopeHead {
        self.observed.head()
    }

    pub fn scope_epoch(&self) -> NonZeroU64 {
        self.observed.head().scope_epoch()
    }

    pub fn lease_until(&self) -> NonZeroU64 {
        self.lease_until
    }

    /// A mutation against any store other than this one proves nothing about ownership there.
    pub(crate) fn namespace(&self) -> &str {
        self.observed.namespace()
    }

    /// Milliseconds of positively known term left at `now_ms`.
    pub(crate) fn remaining_term_ms(&self, now_ms: u64) -> u64 {
        self.remaining_ms(now_ms)
    }

    /// Reports whether less than [`STOP_MARGIN_MS`] of the positively known term remains.
    pub fn must_stop(&self, now_ms: u64) -> bool {
        self.remaining_ms(now_ms) < STOP_MARGIN_MS
    }

    /// Reports whether [`RENEWAL_INTERVAL_MS`] has elapsed since the term was granted.
    pub fn renewal_due(&self, now_ms: u64) -> bool {
        self.remaining_ms(now_ms) <= LEASE_DURATION_MS - RENEWAL_INTERVAL_MS
    }

    fn remaining_ms(&self, now_ms: u64) -> u64 {
        self.lease_until.get().saturating_sub(now_ms)
    }

    /// Converts proven authority into the parent boundary for one fenced head transition.
    ///
    /// The transition inherits this head's controller, lease, and epoch, so a superseded
    /// controller's boundary fails its conditional write.
    ///
    /// # Errors
    ///
    /// Returns [`StoppedAuthority`] once [`Self::must_stop`] holds, before any write is
    /// prepared.
    pub fn into_parent(self, now_ms: u64) -> Result<ScopeHeadParent, StoppedAuthority> {
        if self.must_stop(now_ms) {
            return Err(self.stop());
        }
        Ok(ScopeHeadParent::existing(self.observed))
    }

    /// Drops the authority value that authorizes new mutations.
    pub fn stop(self) -> StoppedAuthority {
        StoppedAuthority {
            observed: self.observed,
        }
    }
}

/// Authority that has stopped issuing mutations and may still be relinquished.
///
/// Producing this value consumes the [`ControllerAuthority`], so ownership cannot be
/// relinquished while any mutation remains authorized.
pub struct StoppedAuthority {
    observed: Box<ObservedScopeHead>,
}

/// Data-free failure category for one authority transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorityError {
    /// No head exists for the scope, so there is nothing to acquire.
    ScopeMissing,
    /// The head read failed in transport; a later attempt may succeed.
    ScopeStorage,
    /// The head is undecodable or names another owner after a proven write. Retrying cannot
    /// change either.
    HeadInvalid,
    /// A caller supplied a witness from another store, or a term, epoch, or encoded head that
    /// cannot be represented.
    InvalidInput,
}

/// Result of one acquisition attempt.
#[must_use]
pub enum AcquireOutcome {
    Acquired(ControllerAuthority),
    /// A live lease belongs to another instance; takeover waits for observed expiry.
    Held,
    /// Another instance advanced the epoch first.
    Superseded,
    /// No safe conclusion was proven; the caller may reread and retry.
    Unresolved,
}

/// Result of one renewal attempt.
#[must_use]
pub enum RenewOutcome {
    Renewed(ControllerAuthority),
    /// The pinned deadline is unchanged. Reusing the same `now_ms` keeps the candidate bytes
    /// identical, which is what lets a lost response be recognised; the holder stops when
    /// `must_stop` holds against the real clock.
    Unresolved(ControllerAuthority),
    /// The scope is owned at a higher epoch or by another instance.
    Lost,
    /// The term reached its stop margin; a replacement term requires a freshly read head.
    Stopped(StoppedAuthority),
}

/// Result of relinquishing ownership.
#[must_use]
pub enum ReleaseOutcome {
    Released,
    /// The head already moved on; ownership is no longer this instance's to relinquish.
    Superseded,
    Unresolved,
}

/// Acquires or resumes authority from a freshly read head.
///
/// A live lease held by another instance is refused. An unowned head, an expired lease, and
/// this instance's own head all advance the epoch and pin a new term at
/// `now_ms + LEASE_DURATION_MS`.
///
/// # Errors
///
/// Returns [`AuthorityError`] when the head is missing, unreadable, unsupported, or when the
/// new term or epoch cannot be represented.
pub async fn acquire(
    store: &S3Store,
    scope: &ScopeIdentity,
    instance: &InstanceId,
    now_ms: u64,
) -> Result<AcquireOutcome, AuthorityError> {
    let observed = read_supported(store, scope).await?;
    if let ScopeAuthority::Owned {
        instance: owner,
        lease_until,
    } = observed.head().authority()
        && owner != instance
        && lease_until.get() > now_ms
    {
        return Ok(AcquireOutcome::Held);
    }
    let candidate = next_head(
        observed.head(),
        ScopeAuthority::owned(instance.clone(), lease_deadline(now_ms)?)
            .map_err(|_| AuthorityError::InvalidInput)?,
    )?;
    Ok(
        match transition(store, &observed, candidate, Some(instance)).await? {
            Transition::Proven(observed) => {
                AcquireOutcome::Acquired(proven_authority(observed, instance.clone())?)
            }
            Transition::Superseded => AcquireOutcome::Superseded,
            Transition::Unresolved => AcquireOutcome::Unresolved,
        },
    )
}

/// Renews authority through the retained head observation.
///
/// Past the stop margin the holder keeps no renewable authority: the frozen policy allows
/// reacquisition only from a freshly read head.
///
/// # Errors
///
/// Returns [`AuthorityError`] when the reread head is unreadable or unsupported, or when the
/// new term or epoch cannot be represented.
pub async fn renew(
    store: &S3Store,
    authority: ControllerAuthority,
    now_ms: u64,
) -> Result<RenewOutcome, AuthorityError> {
    if authority.must_stop(now_ms) {
        return Ok(RenewOutcome::Stopped(authority.stop()));
    }
    let candidate = next_head(
        authority.head(),
        ScopeAuthority::owned(authority.instance.clone(), lease_deadline(now_ms)?)
            .map_err(|_| AuthorityError::InvalidInput)?,
    )?;
    Ok(
        match transition(
            store,
            &authority.observed,
            candidate,
            Some(&authority.instance),
        )
        .await?
        {
            Transition::Proven(observed) => {
                RenewOutcome::Renewed(proven_authority(observed, authority.instance)?)
            }
            Transition::Superseded => RenewOutcome::Lost,
            Transition::Unresolved => RenewOutcome::Unresolved(authority),
        },
    )
}

/// Relinquishes ownership so a replacement need not wait for lease expiry.
///
/// # Errors
///
/// Returns [`AuthorityError`] when the reread head is unreadable or unsupported, or when the
/// next epoch cannot be represented.
pub async fn release(
    store: &S3Store,
    stopped: StoppedAuthority,
) -> Result<ReleaseOutcome, AuthorityError> {
    let candidate = next_head(stopped.observed.head(), ScopeAuthority::Unowned)?;
    Ok(
        match transition(store, &stopped.observed, candidate, None).await? {
            Transition::Proven(_) => ReleaseOutcome::Released,
            Transition::Superseded => ReleaseOutcome::Superseded,
            Transition::Unresolved => ReleaseOutcome::Unresolved,
        },
    )
}

enum Transition {
    Proven(Box<ObservedScopeHead>),
    Superseded,
    Unresolved,
}

async fn transition(
    store: &S3Store,
    observed: &ObservedScopeHead,
    candidate: ScopeHead,
    owner: Option<&InstanceId>,
) -> Result<Transition, AuthorityError> {
    if observed.namespace() != store.namespace() {
        return Err(AuthorityError::InvalidInput);
    }
    let bytes = encode_head(&candidate).map_err(|_| AuthorityError::HeadInvalid)?;
    let key = scope_head_key(candidate.scope());
    let mut history = AttemptHistory::default();
    let outcome = store
        .put_if_match(&key, bytes.clone(), observed.etag(), &mut history)
        .await;
    match outcome {
        MutationOutcome::Committed { etag: Some(etag) } => Ok(Transition::Proven(Box::new(
            ObservedScopeHead::proven(candidate, bytes, etag, store.namespace().to_owned()),
        ))),
        // A committed response without a token still needs the reread that mints the ETag for
        // the next conditional write, so it resolves rather than concluding here.
        MutationOutcome::Committed { etag: None }
        | MutationOutcome::Conflict
        | MutationOutcome::PreconditionFailed
        | MutationOutcome::AmbiguousConflict
        | MutationOutcome::Unknown => resolve(store, &candidate, &bytes, owner).await,
        MutationOutcome::ProvenNotSent | MutationOutcome::NotFound => Ok(Transition::Unresolved),
        MutationOutcome::TooLarge => Err(AuthorityError::InvalidInput),
    }
}

/// Only the holder of the parent head's ETag can replace it, so a head that carries this
/// candidate's epoch and this caller's instance was written by this caller's own attempt, whose
/// committed term the head now carries. Byte equality proves the same for a relinquished head,
/// which names no instance.
async fn resolve(
    store: &S3Store,
    candidate: &ScopeHead,
    bytes: &[u8],
    owner: Option<&InstanceId>,
) -> Result<Transition, AuthorityError> {
    let current = read_supported(store, candidate.scope()).await?;
    if current.canonical_bytes() == bytes {
        return Ok(Transition::Proven(Box::new(current)));
    }
    if let (Some(owner), ScopeAuthority::Owned { instance, .. }) =
        (owner, current.head().authority())
        && instance == owner
        && current.head().scope_epoch() == candidate.scope_epoch()
    {
        return Ok(Transition::Proven(Box::new(current)));
    }
    if current.head().scope_epoch() >= candidate.scope_epoch() {
        return Ok(Transition::Superseded);
    }
    Ok(Transition::Unresolved)
}

async fn read_supported(
    store: &S3Store,
    scope: &ScopeIdentity,
) -> Result<ObservedScopeHead, AuthorityError> {
    match head::read(store, scope).await {
        Ok(Some(observed)) => Ok(observed),
        Ok(None) => Err(AuthorityError::ScopeMissing),
        Err(ScopeHeadReadError::Storage(_)) => Err(AuthorityError::ScopeStorage),
        Err(ScopeHeadReadError::Invalid(_)) => Err(AuthorityError::HeadInvalid),
    }
}

fn next_head(observed: &ScopeHead, authority: ScopeAuthority) -> Result<ScopeHead, AuthorityError> {
    let epoch = observed
        .scope_epoch()
        .get()
        .checked_add(1)
        .ok_or(AuthorityError::InvalidInput)?;
    ScopeHead::new(
        observed.scope().clone(),
        authority,
        epoch,
        observed.tail().clone(),
        observed.active_plan_digest().cloned(),
        observed.operation_id().to_owned(),
    )
    .map_err(|_| AuthorityError::InvalidInput)
}

fn lease_deadline(now_ms: u64) -> Result<u64, AuthorityError> {
    now_ms
        .checked_add(LEASE_DURATION_MS)
        .ok_or(AuthorityError::InvalidInput)
}

fn proven_authority(
    observed: Box<ObservedScopeHead>,
    instance: InstanceId,
) -> Result<ControllerAuthority, AuthorityError> {
    let ScopeAuthority::Owned {
        instance: owner,
        lease_until,
    } = observed.head().authority()
    else {
        return Err(AuthorityError::HeadInvalid);
    };
    if owner != &instance {
        return Err(AuthorityError::HeadInvalid);
    }
    let lease_until = *lease_until;
    Ok(ControllerAuthority {
        observed,
        instance,
        lease_until,
    })
}

#[cfg(test)]
mod tests {
    use aws_sdk_s3::primitives::SdkBody;
    use aws_smithy_runtime::client::http::test_util::StaticReplayClient;

    use crate::{
        distributed::identity::WorkspaceId,
        domain::work::{WorkId, WorkRef},
        scope::{
            AdmittedCampaignConfig, CampaignId, Digest, RootGenesis, ScopeClaimIdentity,
            decode_head, encode_head, root_genesis,
        },
        storage::s3::test_support::{replay_store, response},
    };

    use super::*;

    const NOW_MS: u64 = 1_700_000_000_000;

    fn genesis() -> RootGenesis {
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

    fn instance(label: &str) -> InstanceId {
        InstanceId::new(label.into()).unwrap()
    }

    fn head_response(bytes: Vec<u8>, etag: &str) -> http::Response<SdkBody> {
        response(200, &[("etag", etag)], bytes)
    }

    fn write_response(etag: &str) -> http::Response<SdkBody> {
        response(200, &[("etag", etag)], SdkBody::empty())
    }

    fn owned_head(genesis: &RootGenesis, owner: &str, lease_until: u64, epoch: u64) -> ScopeHead {
        ScopeHead::new(
            genesis.identity().clone(),
            ScopeAuthority::owned(instance(owner), lease_until).unwrap(),
            epoch,
            genesis.event_ref().clone(),
            None,
            genesis.head().operation_id().to_owned(),
        )
        .unwrap()
    }

    fn written_head(client: &StaticReplayClient, index: usize, genesis: &RootGenesis) -> ScopeHead {
        let requests = client.actual_requests().collect::<Vec<_>>();
        let bytes = requests[index].body().bytes().unwrap().to_vec();
        decode_head(
            &bytes,
            &crate::scope::scope_head_key(genesis.identity()),
            genesis.identity(),
        )
        .unwrap()
    }

    fn if_match(client: &StaticReplayClient, index: usize) -> String {
        client
            .actual_requests()
            .nth(index)
            .unwrap()
            .headers()
            .get("if-match")
            .unwrap()
            .to_owned()
    }

    async fn acquired(store: &S3Store, genesis: &RootGenesis, owner: &str) -> ControllerAuthority {
        let outcome = acquire(store, genesis.identity(), &instance(owner), NOW_MS)
            .await
            .unwrap();
        let AcquireOutcome::Acquired(authority) = outcome else {
            panic!("expected acquisition");
        };
        authority
    }

    #[tokio::test]
    async fn acquisition_pins_the_frozen_term_and_advances_the_epoch() {
        assert_eq!(LEASE_DURATION_MS, 30_000);
        assert_eq!(RENEWAL_INTERVAL_MS, 10_000);
        assert_eq!(STOP_MARGIN_MS, 5_000);

        let genesis = genesis();
        let (store, client) = replay_store(vec![
            head_response(genesis.head_bytes().to_vec(), "\"genesis\""),
            write_response("\"owned\""),
        ]);
        let authority = acquired(&store, &genesis, "instance-a").await;

        assert_eq!(authority.scope_epoch().get(), 2);
        assert_eq!(authority.lease_until().get(), NOW_MS + LEASE_DURATION_MS);
        let committed = written_head(&client, 1, &genesis);
        assert_eq!(
            committed.authority(),
            &ScopeAuthority::owned(instance("instance-a"), NOW_MS + LEASE_DURATION_MS).unwrap()
        );
        assert_eq!(committed.tail(), genesis.event_ref());
        assert_eq!(committed.operation_id(), genesis.head().operation_id());
        assert_eq!(if_match(&client, 1), "\"genesis\"");

        assert!(!authority.renewal_due(NOW_MS));
        assert!(authority.renewal_due(NOW_MS + RENEWAL_INTERVAL_MS));
        assert!(!authority.must_stop(NOW_MS + 2 * RENEWAL_INTERVAL_MS));
        assert!(!authority.must_stop(NOW_MS + LEASE_DURATION_MS - STOP_MARGIN_MS));
        assert!(authority.must_stop(NOW_MS + LEASE_DURATION_MS - STOP_MARGIN_MS + 1));

        // A work claim fence is a separate identity axis: it lives on the claim identity and
        // never appears in a head.
        let claim = ScopeClaimIdentity::new(
            genesis.identity().clone(),
            Digest::new("b".repeat(64)).unwrap(),
            WorkRef::new(WorkId::new("work-17".into()).unwrap(), 3),
            1,
        )
        .unwrap();
        assert_eq!(claim.claim_fence().get(), 1);
        let committed_bytes = encode_head(&committed).unwrap();
        assert!(
            !std::str::from_utf8(&committed_bytes)
                .unwrap()
                .contains("claim_fence")
        );
    }

    #[tokio::test]
    async fn renewal_advances_the_epoch_and_extends_the_term() {
        let genesis = genesis();
        let (store, client) = replay_store(vec![
            head_response(genesis.head_bytes().to_vec(), "\"genesis\""),
            write_response("\"owned\""),
            write_response("\"renewed\""),
        ]);
        let authority = acquired(&store, &genesis, "instance-a").await;
        let outcome = renew(&store, authority, NOW_MS + RENEWAL_INTERVAL_MS)
            .await
            .unwrap();
        let RenewOutcome::Renewed(renewed) = outcome else {
            panic!("expected renewal");
        };
        assert_eq!(renewed.scope_epoch().get(), 3);
        assert_eq!(
            renewed.lease_until().get(),
            NOW_MS + RENEWAL_INTERVAL_MS + LEASE_DURATION_MS
        );
        assert_eq!(if_match(&client, 2), "\"owned\"");
        assert_eq!(written_head(&client, 2, &genesis).scope_epoch().get(), 3);
    }

    #[tokio::test]
    async fn an_ambiguous_renewal_does_not_extend_the_pinned_term() {
        let genesis = genesis();
        let retained = owned_head(&genesis, "instance-a", NOW_MS + LEASE_DURATION_MS, 2);
        let (store, _) = replay_store(vec![
            head_response(genesis.head_bytes().to_vec(), "\"genesis\""),
            write_response("\"owned\""),
            response(500, &[], SdkBody::empty()),
            head_response(encode_head(&retained).unwrap(), "\"unchanged\""),
        ]);
        let authority = acquired(&store, &genesis, "instance-a").await;
        let outcome = renew(&store, authority, NOW_MS + RENEWAL_INTERVAL_MS)
            .await
            .unwrap();
        let RenewOutcome::Unresolved(retained_authority) = outcome else {
            panic!("expected an unresolved renewal");
        };
        assert_eq!(retained_authority.scope_epoch().get(), 2);
        assert_eq!(
            retained_authority.lease_until().get(),
            NOW_MS + LEASE_DURATION_MS
        );
    }

    #[tokio::test]
    async fn a_live_lease_is_not_taken_over_and_an_expired_one_is() {
        let genesis = genesis();
        let live = owned_head(&genesis, "instance-b", NOW_MS + 1, 5);
        let (store, client) =
            replay_store(vec![head_response(encode_head(&live).unwrap(), "\"live\"")]);
        assert!(matches!(
            acquire(&store, genesis.identity(), &instance("instance-a"), NOW_MS)
                .await
                .unwrap(),
            AcquireOutcome::Held
        ));
        assert_eq!(client.actual_requests().count(), 1);

        let expired = owned_head(&genesis, "instance-b", NOW_MS, 5);
        let (store, _) = replay_store(vec![
            head_response(encode_head(&expired).unwrap(), "\"expired\""),
            write_response("\"taken\""),
        ]);
        let authority = acquired(&store, &genesis, "instance-a").await;
        assert_eq!(authority.scope_epoch().get(), 6);
    }

    #[tokio::test]
    async fn a_superseded_controller_loses_its_authority_instead_of_renewing() {
        let genesis = genesis();
        let superseding = owned_head(&genesis, "instance-b", NOW_MS + LEASE_DURATION_MS, 4);
        let (store, client) = replay_store(vec![
            head_response(genesis.head_bytes().to_vec(), "\"genesis\""),
            write_response("\"owned\""),
            response(412, &[], SdkBody::empty()),
            head_response(encode_head(&superseding).unwrap(), "\"superseded\""),
        ]);
        let authority = acquired(&store, &genesis, "instance-a").await;
        assert!(matches!(
            renew(&store, authority, NOW_MS + RENEWAL_INTERVAL_MS)
                .await
                .unwrap(),
            RenewOutcome::Lost
        ));
        // The losing renewal attempted exactly one conditional write, from its own retained
        // token, and did not write again after reading the superseding head.
        assert_eq!(client.actual_requests().count(), 4);
        assert_eq!(if_match(&client, 2), "\"owned\"");
    }

    #[tokio::test]
    async fn authority_stops_issuing_mutations_before_it_is_relinquished() {
        let genesis = genesis();
        let (store, client) = replay_store(vec![
            head_response(genesis.head_bytes().to_vec(), "\"genesis\""),
            write_response("\"owned\""),
            write_response("\"released\""),
        ]);
        let authority = acquired(&store, &genesis, "instance-a").await;
        let past_margin = NOW_MS + LEASE_DURATION_MS - STOP_MARGIN_MS + 1;
        let Err(stopped) = authority.into_parent(past_margin) else {
            panic!("expected the stop margin to withhold the boundary");
        };
        assert_eq!(client.actual_requests().count(), 2);

        assert!(matches!(
            release(&store, stopped).await.unwrap(),
            ReleaseOutcome::Released
        ));
        let relinquished = written_head(&client, 2, &genesis);
        assert_eq!(relinquished.authority(), &ScopeAuthority::Unowned);
        assert_eq!(relinquished.scope_epoch().get(), 3);
        assert_eq!(if_match(&client, 2), "\"owned\"");
    }

    #[tokio::test]
    async fn a_holder_resumes_its_own_live_lease_at_a_higher_epoch() {
        let genesis = genesis();
        let own = owned_head(&genesis, "instance-a", NOW_MS + LEASE_DURATION_MS, 7);
        let (store, client) = replay_store(vec![
            head_response(encode_head(&own).unwrap(), "\"own\""),
            write_response("\"resumed\""),
        ]);
        let authority = acquired(&store, &genesis, "instance-a").await;
        assert_eq!(authority.scope_epoch().get(), 8);
        assert_eq!(if_match(&client, 1), "\"own\"");
    }

    #[tokio::test]
    async fn an_acquisition_that_loses_the_race_reports_supersession() {
        let genesis = genesis();
        let winner = owned_head(&genesis, "instance-b", NOW_MS + LEASE_DURATION_MS, 2);
        let (store, _) = replay_store(vec![
            head_response(genesis.head_bytes().to_vec(), "\"genesis\""),
            response(412, &[], SdkBody::empty()),
            head_response(encode_head(&winner).unwrap(), "\"winner\""),
        ]);
        assert!(matches!(
            acquire(&store, genesis.identity(), &instance("instance-a"), NOW_MS)
                .await
                .unwrap(),
            AcquireOutcome::Superseded
        ));
    }

    /// A renewal whose response was lost is retried at a later clock reading, so its candidate
    /// bytes differ from the committed head. Owner and epoch still prove the earlier attempt
    /// committed, and the reissued term is the one the head actually carries.
    #[tokio::test]
    async fn a_retried_renewal_recovers_its_own_committed_term() {
        let genesis = genesis();
        let committed = owned_head(
            &genesis,
            "instance-a",
            NOW_MS + RENEWAL_INTERVAL_MS + LEASE_DURATION_MS,
            3,
        );
        let (store, _) = replay_store(vec![
            head_response(genesis.head_bytes().to_vec(), "\"genesis\""),
            write_response("\"owned\""),
            response(500, &[], SdkBody::empty()),
            head_response(encode_head(&committed).unwrap(), "\"renewed\""),
        ]);
        let authority = acquired(&store, &genesis, "instance-a").await;
        let outcome = renew(&store, authority, NOW_MS + RENEWAL_INTERVAL_MS + 1)
            .await
            .unwrap();
        let RenewOutcome::Renewed(renewed) = outcome else {
            panic!("expected the committed renewal to be recovered");
        };
        assert_eq!(renewed.scope_epoch().get(), 3);
        assert_eq!(
            renewed.lease_until().get(),
            NOW_MS + RENEWAL_INTERVAL_MS + LEASE_DURATION_MS
        );
    }

    #[tokio::test]
    async fn renewal_past_the_stop_margin_yields_stopped_authority_without_a_write() {
        let genesis = genesis();
        let (store, client) = replay_store(vec![
            head_response(genesis.head_bytes().to_vec(), "\"genesis\""),
            write_response("\"owned\""),
        ]);
        let authority = acquired(&store, &genesis, "instance-a").await;
        let past_margin = NOW_MS + LEASE_DURATION_MS - STOP_MARGIN_MS + 1;
        assert!(matches!(
            renew(&store, authority, past_margin).await.unwrap(),
            RenewOutcome::Stopped(_)
        ));
        assert_eq!(client.actual_requests().count(), 2);
    }
}
