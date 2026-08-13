//! Bounded node intake and the ordered shutdown of one node's owned work.
//!
//! Every intake point is a fixed-capacity queue whose overflow is an outcome, never a wait:
//! a full queue refuses admission and a stopped queue says so. Shutdown runs one fixed order —
//! stop admission, reconcile outcomes that storage left unknown, kill and reap descendant
//! processes, drain accepted durable writes, then exit — and returns the phases it completed,
//! so a caller can prove nothing ran after admission stopped.
//!
//! Shutdown owns its descendants and its queue by value, so no admitted work and no child
//! process outlives the call.

use std::{collections::VecDeque, num::NonZeroUsize, process::Child};

use crate::{
    db::{projections::ApplyError, worker::DbHandle},
    distributed::claims::{ExpectedClaim, intake_all},
    storage::s3::S3Store,
};

/// Reads that shutdown reconciliation may have in flight at once.
pub const RECONCILE_CONCURRENCY: NonZeroUsize = NonZeroUsize::new(4).unwrap();

/// Outcome of offering one item to a bounded queue.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[must_use]
pub enum Admission {
    Accepted,
    /// The queue is at capacity; the caller keeps the item and sheds or retries.
    Overloaded,
    /// Admission stopped, so the item will never be served.
    Stopped,
}

/// Fixed-capacity intake queue that refuses instead of growing or blocking.
pub struct IntakeQueue<T> {
    capacity: NonZeroUsize,
    admitting: bool,
    queued: VecDeque<T>,
}

impl<T> IntakeQueue<T> {
    pub fn new(capacity: NonZeroUsize) -> Self {
        Self {
            capacity,
            admitting: true,
            queued: VecDeque::with_capacity(capacity.get()),
        }
    }

    pub fn admit(&mut self, item: T) -> Admission {
        if !self.admitting {
            return Admission::Stopped;
        }
        if self.queued.len() >= self.capacity.get() {
            return Admission::Overloaded;
        }
        self.queued.push_back(item);
        Admission::Accepted
    }

    pub fn take(&mut self) -> Option<T> {
        self.queued.pop_front()
    }

    pub fn len(&self) -> usize {
        self.queued.len()
    }

    pub fn is_empty(&self) -> bool {
        self.queued.is_empty()
    }

    pub fn capacity(&self) -> NonZeroUsize {
        self.capacity
    }

    pub fn is_admitting(&self) -> bool {
        self.admitting
    }

    pub fn stop_admission(&mut self) {
        self.admitting = false;
    }
}

/// Why a node is shutting down.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShutdownReason {
    Cancelled,
    TimedOut,
    Crashed,
    Requested,
}

/// Shutdown steps, in the order they must occur.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShutdownPhase {
    AdmissionStopped,
    OutcomesReconciled,
    DescendantsReaped,
    DurableWritesDrained,
    Exited,
}

/// What one shutdown completed.
#[derive(Debug, Eq, PartialEq)]
pub struct ShutdownRecord {
    reason: ShutdownReason,
    phases: Vec<ShutdownPhase>,
    shed: usize,
    resolved: usize,
    unresolved: usize,
    reaped: usize,
    drain: Option<Result<(), ApplyError>>,
}

impl ShutdownRecord {
    pub fn reason(&self) -> ShutdownReason {
        self.reason
    }

    pub fn phases(&self) -> &[ShutdownPhase] {
        &self.phases
    }

    /// Items dropped from the queue because admission stopped before they were served.
    pub fn shed(&self) -> usize {
        self.shed
    }

    /// Effects whose durable outcome reconciliation established.
    pub fn resolved(&self) -> usize {
        self.resolved
    }

    /// Effects still unknown after reconciliation; the next controller must resolve them.
    pub fn unresolved(&self) -> usize {
        self.unresolved
    }

    pub fn reaped(&self) -> usize {
        self.reaped
    }

    pub fn drain(&self) -> Option<&Result<(), ApplyError>> {
        self.drain.as_ref()
    }
}

/// One node's owned work, consumed by [`shutdown`].
///
/// `descendants` are the node's own child processes, killed and reaped one at a time with a
/// blocking wait after the signal. A child that forked further is contained by its runner's
/// process group, not here.
/// commentlint: allow(JUDGE)
pub struct OwnedWork<'a, T> {
    pub intake: IntakeQueue<T>,
    pub unknown_outcomes: Vec<ExpectedClaim>,
    pub reconcile_concurrency: NonZeroUsize,
    pub descendants: Vec<Child>,
    pub database: Option<&'a DbHandle>,
}

impl<T> OwnedWork<'_, T> {
    pub fn new(intake: IntakeQueue<T>) -> Self {
        Self {
            intake,
            unknown_outcomes: Vec::new(),
            reconcile_concurrency: RECONCILE_CONCURRENCY,
            descendants: Vec::new(),
            database: None,
        }
    }
}

/// Each phase yields the token the next phase consumes, so the order is a compile-time
/// property of the sequence rather than a claim the record makes about itself.
struct Stopped {
    shed: usize,
}

struct Reconciled {
    shed: usize,
    resolved: usize,
    unresolved: usize,
}

struct Reaped {
    shed: usize,
    resolved: usize,
    unresolved: usize,
    reaped: usize,
}

struct Drained {
    shed: usize,
    resolved: usize,
    unresolved: usize,
    reaped: usize,
    drain: Option<Result<(), ApplyError>>,
}

/// Runs the shutdown order and returns its record beside the stopped queue.
///
/// The returned queue proves admission stopped: it refuses every later item. Reconciliation
/// classifies each unknown outcome by rereading its durable claim; only an unavailable read or
/// a live lease leaves an effect for the next controller. Reaping blocks briefly on each child
/// so none outlives this call, and the drain barrier is retried until the durable worker
/// accepts it.
pub async fn shutdown<T>(
    store: &S3Store,
    reason: ShutdownReason,
    owned: OwnedWork<'_, T>,
) -> (ShutdownRecord, IntakeQueue<T>) {
    let OwnedWork {
        mut intake,
        unknown_outcomes,
        reconcile_concurrency,
        descendants,
        database,
    } = owned;
    let mut phases = Vec::with_capacity(5);

    let stopped = stop_admission(&mut intake, &mut phases);
    let reconciled = reconcile(
        stopped,
        store,
        &unknown_outcomes,
        reconcile_concurrency,
        &mut phases,
    )
    .await;
    let reaped = reap(reconciled, descendants, &mut phases);
    let drained = drain(reaped, database, &mut phases).await;

    phases.push(ShutdownPhase::Exited);
    let record = ShutdownRecord {
        reason,
        phases,
        shed: drained.shed,
        resolved: drained.resolved,
        unresolved: drained.unresolved,
        reaped: drained.reaped,
        drain: drained.drain,
    };
    (record, intake)
}

fn stop_admission<T>(intake: &mut IntakeQueue<T>, phases: &mut Vec<ShutdownPhase>) -> Stopped {
    intake.stop_admission();
    let shed = intake.len();
    while intake.take().is_some() {}
    phases.push(ShutdownPhase::AdmissionStopped);
    Stopped { shed }
}

async fn reconcile(
    stopped: Stopped,
    store: &S3Store,
    unknown_outcomes: &[ExpectedClaim],
    concurrency: NonZeroUsize,
    phases: &mut Vec<ShutdownPhase>,
) -> Reconciled {
    let classified = intake_all(store, unknown_outcomes, concurrency).await;
    let unresolved = classified
        .iter()
        .filter(|outcome| !outcome.is_resolved())
        .count();
    phases.push(ShutdownPhase::OutcomesReconciled);
    Reconciled {
        shed: stopped.shed,
        resolved: classified.len() - unresolved,
        unresolved,
    }
}

fn reap(
    reconciled: Reconciled,
    mut descendants: Vec<Child>,
    phases: &mut Vec<ShutdownPhase>,
) -> Reaped {
    let mut reaped = 0;
    for descendant in &mut descendants {
        let _ = descendant.kill();
        if descendant.wait().is_ok() {
            reaped += 1;
        }
    }
    phases.push(ShutdownPhase::DescendantsReaped);
    Reaped {
        shed: reconciled.shed,
        resolved: reconciled.resolved,
        unresolved: reconciled.unresolved,
        reaped,
    }
}

async fn drain(
    reaped: Reaped,
    database: Option<&DbHandle>,
    phases: &mut Vec<ShutdownPhase>,
) -> Drained {
    let drain = match database {
        None => None,
        Some(database) => {
            let mut outcome = database.drain().await;
            // A saturated queue is the case shutdown exists for, so a refused barrier is
            // retried instead of being reported as a completed drain.
            while outcome == Err(ApplyError::Full) {
                yield_once().await;
                outcome = database.drain().await;
            }
            if outcome.is_ok() {
                phases.push(ShutdownPhase::DurableWritesDrained);
            }
            Some(outcome)
        }
    };
    Drained {
        shed: reaped.shed,
        resolved: reaped.resolved,
        unresolved: reaped.unresolved,
        reaped: reaped.reaped,
        drain,
    }
}

/// Yields once so the durable worker can advance before the barrier is offered again.
async fn yield_once() {
    let mut yielded = false;
    std::future::poll_fn(move |context| {
        if yielded {
            std::task::Poll::Ready(())
        } else {
            yielded = true;
            context.waker().wake_by_ref();
            std::task::Poll::Pending
        }
    })
    .await;
}

#[cfg(test)]
mod tests {
    use std::{
        num::NonZeroU64,
        process::{Command, Stdio},
        time::Duration,
    };

    use aws_sdk_s3::primitives::SdkBody;

    use crate::{
        distributed::{
            claims::{ScopeClaim, ScopeClaimState, encode_claim},
            identity::{ActorId, InstanceId, WorkspaceId},
        },
        domain::work::{WorkId, WorkRef},
        scope::{CampaignId, Digest, ScopeClaimIdentity, ScopeIdentity},
        storage::s3::test_support::{replay_store, response},
    };

    use super::*;

    fn scope() -> ScopeIdentity {
        ScopeIdentity::root(
            WorkspaceId::new("workspace-a".into()).unwrap(),
            CampaignId::new("campaign-a".into()).unwrap(),
        )
        .unwrap()
    }

    fn expected(work_id: &str) -> ExpectedClaim {
        ExpectedClaim::new(
            scope(),
            Digest::new("a".repeat(64)).unwrap(),
            WorkRef::new(WorkId::new(work_id.into()).unwrap(), 1),
            None,
        )
    }

    fn capacity(value: usize) -> NonZeroUsize {
        NonZeroUsize::new(value).unwrap()
    }

    /// Work rows are foreign-keyed to their scope row, so genesis is applied first.
    async fn seed_scope(database: &DbHandle) {
        let genesis = crate::scope::root_genesis(
            &crate::scope::AdmittedCampaignConfig::new(
                WorkspaceId::new("workspace-a".into()).unwrap(),
                CampaignId::new("campaign-a".into()).unwrap(),
                b"admitted".to_vec(),
            )
            .unwrap(),
        )
        .unwrap();
        let root = crate::scope::decode_root_event(
            genesis.event_bytes(),
            genesis.event_key(),
            genesis.identity(),
        )
        .unwrap();
        let mutation = crate::db::projections::ScopeProjectionEvent::new(
            genesis.identity().clone(),
            root.envelope().clone(),
            genesis.event_ref().clone(),
            None,
            1,
        )
        .unwrap();
        database.apply(mutation).await.unwrap();
    }

    #[test]
    fn a_full_queue_refuses_admission_and_a_stopped_queue_says_so() {
        let mut queue = IntakeQueue::new(capacity(2));
        assert_eq!(queue.admit("first"), Admission::Accepted);
        assert_eq!(queue.admit("second"), Admission::Accepted);
        // Capacity is fixed: overload is an outcome, not a wait or a resize.
        assert_eq!(queue.admit("third"), Admission::Overloaded);
        assert_eq!(queue.len(), 2);
        assert_eq!(queue.capacity(), capacity(2));

        assert_eq!(queue.take(), Some("first"));
        assert_eq!(queue.admit("third"), Admission::Accepted);

        queue.stop_admission();
        assert_eq!(queue.admit("fourth"), Admission::Stopped);
        assert!(!queue.is_admitting());
        assert_eq!(queue.len(), 2);
    }

    #[tokio::test]
    async fn shutdown_stops_admission_reconciles_reaps_drains_then_exits() {
        let path = std::env::temp_dir().join(format!(
            "ravel-lifecycle-{}-shutdown.sqlite3",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let database = DbHandle::spawn(path.clone()).await.unwrap();
        let child = Command::new("sleep")
            .arg("120")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let child_id = child.id();

        // One claim reads back a decodable absence, one leaves storage unknown.
        let (store, client) = replay_store(vec![
            response(404, &[], SdkBody::empty()),
            response(500, &[], SdkBody::empty()),
        ]);
        let mut queue = IntakeQueue::new(capacity(4));
        assert_eq!(queue.admit("unserved"), Admission::Accepted);
        let owned = OwnedWork {
            unknown_outcomes: vec![expected("work-a"), expected("work-b")],
            descendants: vec![child],
            database: Some(&database),
            ..OwnedWork::new(queue)
        };

        let (record, stopped) = shutdown(&store, ShutdownReason::Cancelled, owned).await;

        assert_eq!(
            record.phases(),
            [
                ShutdownPhase::AdmissionStopped,
                ShutdownPhase::OutcomesReconciled,
                ShutdownPhase::DescendantsReaped,
                ShutdownPhase::DurableWritesDrained,
                ShutdownPhase::Exited,
            ]
        );
        assert_eq!(record.reason(), ShutdownReason::Cancelled);
        assert_eq!(record.shed(), 1);
        assert_eq!(record.resolved(), 1);
        assert_eq!(record.unresolved(), 1);
        assert_eq!(record.reaped(), 1);
        assert_eq!(record.drain(), Some(&Ok(())));
        assert_eq!(client.actual_requests().count(), 2);

        // The returned queue is the evidence that admission stopped and shed its items.
        let mut stopped = stopped;
        assert_eq!(stopped.admit("late"), Admission::Stopped);
        assert!(stopped.is_empty());

        // The descendant is gone before shutdown returned, so nothing outlives the node.
        let alive = Command::new("kill")
            .arg("-0")
            .arg(child_id.to_string())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(!alive.success());

        drop(database);
        tokio::time::sleep(Duration::from_millis(50)).await;
        let _ = std::fs::remove_file(&path);
    }

    /// An active lease is not an answer: the effect it fences may still be running, so shutdown
    /// hands it to the next controller instead of counting it resolved.
    #[tokio::test]
    async fn a_live_lease_stays_unresolved_through_shutdown() {
        let claim = ScopeClaim::new(
            ScopeClaimIdentity::new(
                scope(),
                Digest::new("a".repeat(64)).unwrap(),
                WorkRef::new(WorkId::new("work-a".into()).unwrap(), 1),
                2,
            )
            .unwrap(),
            ActorId::new("actor-a".into()).unwrap(),
            InstanceId::new("instance-a".into()).unwrap(),
            "operation-live".into(),
            ScopeClaimState::Active {
                lease_until: NonZeroU64::new(31_000).unwrap(),
            },
        )
        .unwrap();
        let (store, _) = replay_store(vec![response(
            200,
            &[("etag", "\"claim\"")],
            encode_claim(&claim).unwrap(),
        )]);
        let owned = OwnedWork {
            unknown_outcomes: vec![expected("work-a")],
            ..OwnedWork::new(IntakeQueue::<&str>::new(capacity(1)))
        };
        let (record, _) = shutdown(&store, ShutdownReason::TimedOut, owned).await;
        assert_eq!(record.unresolved(), 1);
        assert_eq!(record.resolved(), 0);
    }

    /// A saturated durable queue is exactly the case shutdown exists for: the barrier is retried
    /// until it is accepted, so the phase is never reported for an unapplied write.
    #[tokio::test]
    async fn a_saturated_durable_queue_still_drains_before_exit() {
        let path = std::env::temp_dir().join(format!(
            "ravel-lifecycle-{}-saturated.sqlite3",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let database = DbHandle::spawn(path.clone()).await.unwrap();
        let scope = scope();
        let work = WorkRef::new(WorkId::new("work-a".into()).unwrap(), 1);
        let epoch = NonZeroU64::new(1).unwrap();
        seed_scope(&database).await;

        // Accept writes without collecting their responses, then prove the barrier applied them.
        for index in 0..8 {
            let work = WorkRef::new(WorkId::new(format!("work-{index}")).unwrap(), 1);
            let mut pending = Box::pin(database.admit_work(&scope, work, Vec::new(), epoch));
            let waker = std::task::Waker::noop();
            let mut context = std::task::Context::from_waker(waker);
            assert!(std::future::Future::poll(pending.as_mut(), &mut context).is_pending());
            drop(pending);
        }

        let (store, _) = replay_store(vec![]);
        let owned = OwnedWork {
            database: Some(&database),
            ..OwnedWork::new(IntakeQueue::<&str>::new(capacity(1)))
        };
        let (record, _) = shutdown(&store, ShutdownReason::Requested, owned).await;
        assert_eq!(record.drain(), Some(&Ok(())));
        assert!(
            record
                .phases()
                .contains(&ShutdownPhase::DurableWritesDrained)
        );

        // An independent connection sees every accepted write, so the drain was a barrier.
        let admitted: i64 = rusqlite::Connection::open(&path)
            .unwrap()
            .query_row("SELECT COUNT(*) FROM admitted_work", [], |row| row.get(0))
            .unwrap();
        assert_eq!(admitted, 8);
        assert!(work.revision() == 1);

        drop(database);
        tokio::time::sleep(Duration::from_millis(50)).await;
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn a_crash_shutdown_without_a_database_still_reports_its_order() {
        let (store, _) = replay_store(vec![]);
        let owned: OwnedWork<'_, &str> = OwnedWork::new(IntakeQueue::new(capacity(1)));
        let (record, _) = shutdown(&store, ShutdownReason::Crashed, owned).await;
        assert_eq!(
            record.phases(),
            [
                ShutdownPhase::AdmissionStopped,
                ShutdownPhase::OutcomesReconciled,
                ShutdownPhase::DescendantsReaped,
                ShutdownPhase::Exited,
            ]
        );
        assert_eq!(record.drain(), None);
        assert_eq!(record.reason(), ShutdownReason::Crashed);
    }
}
