//! A SQLite transaction applies scheduling mutations to projection tables.
//!
//! The transaction validates local history and parent continuity, applies one projection row,
//! records the event identity, and advances the singleton synchronization cursor.

use std::{collections::BTreeSet, error::Error, fmt};

use rusqlite::{OptionalExtension, params};

use crate::sync::event::{SchedulingEffect, SchedulingMutation};

const MAX_READY_WORK: usize = 1_024;

#[cfg(test)]
/// Installs the `fail_cursor_update` trigger; removal drops that exact name.
pub(crate) const FAIL_CURSOR_TRIGGER: &str = "CREATE TRIGGER fail_cursor_update BEFORE UPDATE ON sync_cursor \
     BEGIN SELECT RAISE(ABORT, 'injected'); END;";

/// Distinguishes a committed mutation from an exact historical replay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApplyOutcome {
    /// The transaction committed the mutation's row effect, event identity, and cursor advance.
    Applied,
    /// The exact (sequence, digest) pair is already recorded; nothing was written.
    AlreadyApplied,
}

/// Distinguishes projection conflicts from database failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApplyError {
    /// The mutation disagrees with recorded history, the cursor, or projection state.
    Conflict,
    /// SQLite failed, or a sequence overflowed its stored or domain representation.
    DatabaseOperationFailed,
}

impl fmt::Display for ApplyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Conflict => "mutation conflicts with local projection state",
            Self::DatabaseOperationFailed => "database operation failed",
        })
    }
}

impl Error for ApplyError {}

impl From<rusqlite::Error> for ApplyError {
    fn from(_: rusqlite::Error) -> Self {
        Self::DatabaseOperationFailed
    }
}

/// Applies one scheduling mutation in a single SQLite transaction.
///
/// An exact historical event returns [`ApplyOutcome::AlreadyApplied`] without writes. A new event
/// must immediately follow the cursor and name its current tail.
///
/// # Errors
///
/// Returns [`ApplyError::Conflict`] when the mutation disagrees with local history, the cursor,
/// or projection state: a sequence gap, a parent that does not name the cursor tail, a parent
/// carried at the genesis cursor, a digest recorded at another sequence, or a
/// [`SchedulingEffect::WorkflowStarted`] effect while no campaign row exists.
/// Returns [`ApplyError::DatabaseOperationFailed`] when SQLite cannot complete an operation
/// or a sequence cannot be converted between its domain and stored representations.
pub fn apply(
    connection: &mut rusqlite::Connection,
    mutation: &SchedulingMutation,
) -> Result<ApplyOutcome, ApplyError> {
    let transaction = connection.transaction()?;
    let (stored_cursor_sequence, cursor_digest): (i64, Option<String>) = transaction.query_row(
        "SELECT sequence, tail_digest FROM sync_cursor WHERE id = 1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let cursor_sequence =
        u64::try_from(stored_cursor_sequence).map_err(|_| ApplyError::DatabaseOperationFailed)?;
    let sequence = mutation.reference().sequence();
    let stored_sequence =
        i64::try_from(sequence).map_err(|_| ApplyError::DatabaseOperationFailed)?;

    let historical_digest: Option<String> = transaction
        .query_row(
            "SELECT digest FROM applied_events WHERE sequence = ?1",
            [stored_sequence],
            |row| row.get(0),
        )
        .optional()?;
    if sequence <= cursor_sequence {
        return if historical_digest.as_deref() == Some(mutation.reference().digest()) {
            Ok(ApplyOutcome::AlreadyApplied)
        } else {
            Err(ApplyError::Conflict)
        };
    }
    if historical_digest.is_some() || cursor_sequence.checked_add(1) != Some(sequence) {
        return Err(ApplyError::Conflict);
    }

    let parent_matches = match (cursor_sequence, cursor_digest.as_deref(), mutation.parent()) {
        (0, None, None) => true,
        (cursor_sequence, Some(cursor_digest), Some(parent)) => {
            parent.sequence() == cursor_sequence && parent.digest() == cursor_digest
        }
        _ => false,
    };
    if !parent_matches {
        return Err(ApplyError::Conflict);
    }

    let digest_exists: bool = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM applied_events WHERE digest = ?1)",
        [mutation.reference().digest()],
        |row| row.get(0),
    )?;
    if digest_exists {
        return Err(ApplyError::Conflict);
    }

    match mutation.effect() {
        SchedulingEffect::CampaignCreated { campaign_id } => {
            transaction.execute(
                "INSERT INTO campaigns (campaign_id, state) VALUES (?1, 'active')",
                [campaign_id],
            )?;
        }
        SchedulingEffect::WorkflowStarted { workflow_id } => {
            let campaign_exists: bool =
                transaction.query_row("SELECT EXISTS(SELECT 1 FROM campaigns)", [], |row| {
                    row.get(0)
                })?;
            if !campaign_exists {
                return Err(ApplyError::Conflict);
            }
            transaction.execute(
                "INSERT INTO workflows (workflow_id, state) VALUES (?1, 'active')",
                [workflow_id],
            )?;
        }
    }

    transaction.execute(
        "INSERT INTO applied_events (sequence, digest) VALUES (?1, ?2)",
        params![stored_sequence, mutation.reference().digest()],
    )?;
    let updated = transaction.execute(
        "UPDATE sync_cursor SET sequence = ?1, tail_digest = ?2 WHERE id = 1",
        params![stored_sequence, mutation.reference().digest()],
    )?;
    if updated != 1 {
        return Err(ApplyError::DatabaseOperationFailed);
    }
    #[cfg(test)]
    crate::sync::replay::test_crash::reach("before-commit");
    transaction.commit()?;
    Ok(ApplyOutcome::Applied)
}

/// Returns ready work in stable workflow/work order, rotated strictly after `after`.
///
/// Required capabilities are space-separated tokens; empty text requires no capability.
///
/// # Errors
///
/// Returns [`ApplyError::DatabaseOperationFailed`] when SQLite cannot complete the query.
pub(crate) fn list_ready_work(
    connection: &rusqlite::Connection,
    campaign_id: &str,
    local_capabilities: &[String],
    limit: usize,
    after: Option<(String, String)>,
) -> Result<Vec<(String, String)>, ApplyError> {
    let limit = limit.min(MAX_READY_WORK);
    if limit == 0 {
        return Ok(Vec::new());
    }

    let capabilities: BTreeSet<&str> = local_capabilities.iter().map(String::as_str).collect();
    let mut statement = connection.prepare(
        "SELECT work.workflow_id, work.work_id, work.required_capabilities \
         FROM work_items AS work \
         JOIN workflows AS workflow ON workflow.workflow_id = work.workflow_id \
         WHERE EXISTS (\
             SELECT 1 FROM campaigns \
             WHERE campaign_id = ?1 AND state = 'active'\
         ) \
         AND workflow.state = 'active' \
         AND work.state = 'ready' \
         AND work.budget_remaining > 0 \
         AND NOT EXISTS (\
             SELECT 1 FROM dependencies AS dependency \
             LEFT JOIN work_items AS prerequisite \
                 ON prerequisite.work_id = dependency.depends_on_work_id \
             WHERE dependency.work_id = work.work_id \
             AND (prerequisite.work_id IS NULL OR prerequisite.state != 'done')\
         ) \
         ORDER BY work.workflow_id, work.work_id",
    )?;
    let mut rows = statement.query([campaign_id])?;
    let mut ready: Vec<(String, String)> = Vec::new();
    while let Some(row) = rows.next()? {
        let required: String = row.get(2)?;
        if required
            .split_whitespace()
            .all(|token| capabilities.contains(token))
        {
            ready.push((row.get(0)?, row.get(1)?));
        }
    }

    if let Some(after) = after {
        // SQLite's default BINARY collation orders TEXT the same way String's Ord does, which
        // partition_point requires.
        let start = ready.partition_point(|key| key <= &after);
        ready.rotate_left(start);
    }
    ready.truncate(limit);
    Ok(ready)
}

#[cfg(test)]
pub(crate) mod tests {
    use std::{fs, path::PathBuf, process};

    use crate::{
        db::schema,
        domain::campaign::{Event, EventContent, EventRef},
        sync::event::scheduling_mutation_unchecked,
    };

    use super::*;

    const DIGEST_1: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const DIGEST_2: &str = "123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0";
    const DIGEST_3: &str = "23456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01";

    #[derive(Debug, Eq, PartialEq)]
    pub(crate) struct Snapshot {
        applied_events: Vec<(i64, String)>,
        sync_cursor: Vec<(i64, i64, Option<String>)>,
        campaigns: Vec<(String, String)>,
        objectives: Vec<String>,
        workflows: Vec<(String, String)>,
        work_items: Vec<(String, String, String, i64, String)>,
        dependencies: Vec<(String, String)>,
    }

    fn test_path(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "ravel-projections-{}-{label}.sqlite3",
            process::id()
        ));
        let _ = fs::remove_file(&path);
        path
    }

    fn mutation(
        sequence: u64,
        digest: &str,
        parent_digest: Option<&str>,
        content: EventContent,
    ) -> SchedulingMutation {
        let parent = parent_digest
            .map(|digest| EventRef::from_digest(sequence - 1, digest.to_owned()).unwrap());
        let event = Event::new(
            format!("operation-{sequence}"),
            sequence,
            parent,
            1,
            content,
        )
        .unwrap();
        scheduling_mutation_unchecked(
            EventRef::from_digest(sequence, digest.to_owned()).unwrap(),
            &event,
        )
        .unwrap()
    }

    fn string_rows(connection: &rusqlite::Connection, query: &str) -> Vec<String> {
        let mut statement = connection.prepare(query).unwrap();
        let rows = statement
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>();
        rows.unwrap()
    }

    pub(crate) fn snapshot(connection: &rusqlite::Connection) -> Snapshot {
        let applied_events = connection
            .prepare("SELECT sequence, digest FROM applied_events ORDER BY sequence, digest")
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let sync_cursor = connection
            .prepare("SELECT id, sequence, tail_digest FROM sync_cursor ORDER BY id")
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let dependencies = connection
            .prepare(
                "SELECT work_id, depends_on_work_id FROM dependencies \
                 ORDER BY work_id, depends_on_work_id",
            )
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        Snapshot {
            applied_events,
            sync_cursor,
            campaigns: connection
                .prepare("SELECT campaign_id, state FROM campaigns ORDER BY campaign_id")
                .unwrap()
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap(),
            objectives: string_rows(
                connection,
                "SELECT objective_id FROM objectives ORDER BY objective_id",
            ),
            workflows: connection
                .prepare("SELECT workflow_id, state FROM workflows ORDER BY workflow_id")
                .unwrap()
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap(),
            work_items: connection
                .prepare(
                    "SELECT work_id, workflow_id, state, budget_remaining, \
                         required_capabilities FROM work_items ORDER BY work_id",
                )
                .unwrap()
                .query_map([], |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                })
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap(),
            dependencies,
        }
    }

    #[test]
    fn applies_genesis_and_workflow_to_projection_and_cursor() {
        let path = test_path("success");
        let mut connection = schema::create(&path).unwrap();
        let genesis = mutation(1, DIGEST_1, None, EventContent::CampaignCreated);
        let workflow = mutation(2, DIGEST_2, Some(DIGEST_1), EventContent::WorkflowStarted);

        assert_eq!(apply(&mut connection, &genesis), Ok(ApplyOutcome::Applied));
        assert_eq!(apply(&mut connection, &workflow), Ok(ApplyOutcome::Applied));
        assert_eq!(
            snapshot(&connection),
            Snapshot {
                applied_events: vec![(1, DIGEST_1.into()), (2, DIGEST_2.into())],
                sync_cursor: vec![(1, 2, Some(DIGEST_2.into()))],
                campaigns: vec![("0000000000000001".into(), "active".into())],
                objectives: vec![],
                workflows: vec![("0000000000000002".into(), "active".into())],
                work_items: vec![],
                dependencies: vec![],
            }
        );

        drop(connection);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn exact_replay_is_a_noop_before_and_after_later_events() {
        let path = test_path("idempotency");
        let mut connection = schema::create(&path).unwrap();
        let genesis = mutation(1, DIGEST_1, None, EventContent::CampaignCreated);
        let workflow = mutation(2, DIGEST_2, Some(DIGEST_1), EventContent::WorkflowStarted);

        assert_eq!(apply(&mut connection, &genesis), Ok(ApplyOutcome::Applied));
        let before_immediate_replay = snapshot(&connection);
        assert_eq!(
            apply(&mut connection, &genesis),
            Ok(ApplyOutcome::AlreadyApplied)
        );
        assert_eq!(snapshot(&connection), before_immediate_replay);

        assert_eq!(apply(&mut connection, &workflow), Ok(ApplyOutcome::Applied));
        let before_historical_replay = snapshot(&connection);
        assert_eq!(
            apply(&mut connection, &genesis),
            Ok(ApplyOutcome::AlreadyApplied)
        );
        assert_eq!(snapshot(&connection), before_historical_replay);

        drop(connection);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn rejects_sequence_gap_without_mutation() {
        let path = test_path("gap");
        let mut connection = schema::create(&path).unwrap();
        let workflow = mutation(2, DIGEST_2, Some(DIGEST_1), EventContent::WorkflowStarted);
        let before = snapshot(&connection);

        assert_eq!(apply(&mut connection, &workflow), Err(ApplyError::Conflict));
        assert_eq!(snapshot(&connection), before);

        drop(connection);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn rejects_wrong_parent_without_mutation() {
        let path = test_path("wrong-parent");
        let mut connection = schema::create(&path).unwrap();
        let genesis = mutation(1, DIGEST_1, None, EventContent::CampaignCreated);
        assert_eq!(apply(&mut connection, &genesis), Ok(ApplyOutcome::Applied));
        let workflow = mutation(2, DIGEST_2, Some(DIGEST_3), EventContent::WorkflowStarted);
        let before = snapshot(&connection);

        assert_eq!(apply(&mut connection, &workflow), Err(ApplyError::Conflict));
        assert_eq!(snapshot(&connection), before);

        drop(connection);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn rejects_same_sequence_with_another_digest_without_mutation() {
        let path = test_path("sequence-conflict");
        let mut connection = schema::create(&path).unwrap();
        let genesis = mutation(1, DIGEST_1, None, EventContent::CampaignCreated);
        assert_eq!(apply(&mut connection, &genesis), Ok(ApplyOutcome::Applied));
        let conflicting = mutation(1, DIGEST_2, None, EventContent::CampaignCreated);
        let before = snapshot(&connection);

        assert_eq!(
            apply(&mut connection, &conflicting),
            Err(ApplyError::Conflict)
        );
        assert_eq!(snapshot(&connection), before);

        drop(connection);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn rejects_digest_reused_at_another_sequence_without_mutation() {
        let path = test_path("digest-conflict");
        let mut connection = schema::create(&path).unwrap();
        let genesis = mutation(1, DIGEST_1, None, EventContent::CampaignCreated);
        assert_eq!(apply(&mut connection, &genesis), Ok(ApplyOutcome::Applied));
        let workflow = mutation(2, DIGEST_1, Some(DIGEST_1), EventContent::WorkflowStarted);
        let before = snapshot(&connection);

        assert_eq!(apply(&mut connection, &workflow), Err(ApplyError::Conflict));
        assert_eq!(snapshot(&connection), before);

        drop(connection);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn rejects_sequence_ahead_of_cursor_holding_another_digest() {
        let path = test_path("ahead-of-cursor");
        let mut connection = schema::create(&path).unwrap();
        let genesis = mutation(1, DIGEST_1, None, EventContent::CampaignCreated);
        assert_eq!(apply(&mut connection, &genesis), Ok(ApplyOutcome::Applied));
        connection
            .execute(
                "INSERT INTO applied_events (sequence, digest) VALUES (2, ?1)",
                [DIGEST_3],
            )
            .unwrap();
        let workflow = mutation(2, DIGEST_2, Some(DIGEST_1), EventContent::WorkflowStarted);
        let before = snapshot(&connection);

        assert_eq!(apply(&mut connection, &workflow), Err(ApplyError::Conflict));
        assert_eq!(snapshot(&connection), before);

        drop(connection);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn rejects_missing_historical_row_without_mutation() {
        let path = test_path("missing-history");
        let mut connection = schema::create(&path).unwrap();
        let genesis = mutation(1, DIGEST_1, None, EventContent::CampaignCreated);
        assert_eq!(apply(&mut connection, &genesis), Ok(ApplyOutcome::Applied));
        connection
            .execute("DELETE FROM applied_events WHERE sequence = 1", [])
            .unwrap();
        let before = snapshot(&connection);

        assert_eq!(apply(&mut connection, &genesis), Err(ApplyError::Conflict));
        assert_eq!(snapshot(&connection), before);

        drop(connection);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn rejects_workflow_when_no_campaign_row_exists() {
        let path = test_path("missing-campaign");
        let mut connection = schema::create(&path).unwrap();
        connection
            .execute(
                "INSERT INTO applied_events (sequence, digest) VALUES (1, ?1)",
                [DIGEST_1],
            )
            .unwrap();
        connection
            .execute(
                "UPDATE sync_cursor SET sequence = 1, tail_digest = ?1 WHERE id = 1",
                [DIGEST_1],
            )
            .unwrap();
        let workflow = mutation(2, DIGEST_2, Some(DIGEST_1), EventContent::WorkflowStarted);
        let before = snapshot(&connection);

        assert_eq!(apply(&mut connection, &workflow), Err(ApplyError::Conflict));
        assert_eq!(snapshot(&connection), before);

        drop(connection);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn sqlite_failure_rolls_back_projection_and_event_rows() {
        let path = test_path("rollback");
        let mut connection = schema::create(&path).unwrap();
        let genesis = mutation(1, DIGEST_1, None, EventContent::CampaignCreated);
        assert_eq!(apply(&mut connection, &genesis), Ok(ApplyOutcome::Applied));
        connection.execute_batch(FAIL_CURSOR_TRIGGER).unwrap();
        let workflow = mutation(2, DIGEST_2, Some(DIGEST_1), EventContent::WorkflowStarted);
        let before = snapshot(&connection);

        assert_eq!(
            apply(&mut connection, &workflow),
            Err(ApplyError::DatabaseOperationFailed)
        );
        assert_eq!(snapshot(&connection), before);

        drop(connection);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn ready_work_requires_every_scheduling_predicate_and_rotates_once() {
        let path = test_path("ready-work");
        let connection = schema::create(&path).unwrap();
        connection
            .execute_batch(
                "INSERT INTO campaigns (campaign_id, state) VALUES ('campaign', 'active');
                     INSERT INTO workflows (workflow_id, state) VALUES
                         ('wf-a', 'active'), ('wf-b', 'active'), ('wf-z', 'completed');
                     INSERT INTO work_items
                         (work_id, workflow_id, state, budget_remaining, required_capabilities)
                     VALUES
                         ('a-ready', 'wf-a', 'ready', 1, 'gpu rust'),
                         ('b-capability', 'wf-a', 'ready', 1, 'gpu secret'),
                         ('c-budget', 'wf-a', 'ready', 0, ''),
                         ('d-cancelled', 'wf-a', 'cancelled', 1, ''),
                         ('e-inactive-workflow', 'wf-z', 'ready', 1, ''),
                         ('f-missing-dependency', 'wf-a', 'ready', 1, ''),
                         ('g-unsatisfied-dependency', 'wf-a', 'ready', 1, ''),
                         ('h-satisfied', 'wf-a', 'ready', 1, ''),
                         ('i-other-workflow', 'wf-b', 'ready', 1, ''),
                         ('prerequisite-done', 'wf-a', 'done', 0, ''),
                         ('prerequisite-pending', 'wf-a', 'cancelled', 0, ''),
                         ('a-late-insert', 'wf-b', 'ready', 1, '');
                     INSERT INTO dependencies (work_id, depends_on_work_id) VALUES
                         ('f-missing-dependency', 'absent'),
                         ('g-unsatisfied-dependency', 'prerequisite-pending'),
                         ('h-satisfied', 'prerequisite-done');",
            )
            .unwrap();
        let capabilities = vec!["rust".into(), "gpu".into(), "gpu".into()];
        // 'a-late-insert' is inserted last yet sorts between the wf-a rows and
        // 'i-other-workflow', so insertion order and work_id-only order both differ from the
        // required (workflow_id, work_id) order.
        let expected = vec![
            ("wf-a".to_owned(), "a-ready".to_owned()),
            ("wf-a".to_owned(), "h-satisfied".to_owned()),
            ("wf-b".to_owned(), "a-late-insert".to_owned()),
            ("wf-b".to_owned(), "i-other-workflow".to_owned()),
        ];

        assert_eq!(
            list_ready_work(&connection, "campaign", &capabilities, 10, None).unwrap(),
            expected
        );
        assert!(
            list_ready_work(&connection, "other", &capabilities, 10, None)
                .unwrap()
                .is_empty()
        );
        connection
            .execute("UPDATE campaigns SET state = 'completed'", [])
            .unwrap();
        assert!(
            list_ready_work(&connection, "campaign", &capabilities, 10, None)
                .unwrap()
                .is_empty()
        );
        connection
            .execute("UPDATE campaigns SET state = 'active'", [])
            .unwrap();

        assert_eq!(
            list_ready_work(
                &connection,
                "campaign",
                &capabilities,
                10,
                Some(("wf-a".into(), "a-ready".into())),
            )
            .unwrap(),
            vec![
                expected[1].clone(),
                expected[2].clone(),
                expected[3].clone(),
                expected[0].clone(),
            ]
        );
        // A page smaller than the qualifying count proves truncation happens after rotation.
        assert_eq!(
            list_ready_work(
                &connection,
                "campaign",
                &capabilities,
                2,
                Some(("wf-a".into(), "a-ready".into())),
            )
            .unwrap(),
            vec![expected[1].clone(), expected[2].clone()]
        );
        assert_eq!(
            list_ready_work(
                &connection,
                "campaign",
                &capabilities,
                1,
                Some(("zz".into(), "zz".into())),
            )
            .unwrap(),
            vec![expected[0].clone()]
        );
        assert!(
            list_ready_work(&connection, "campaign", &capabilities, 0, None)
                .unwrap()
                .is_empty()
        );

        drop(connection);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn ready_work_limit_is_capped() {
        let path = test_path("ready-limit");
        let mut connection = schema::create(&path).unwrap();
        connection
            .execute_batch(
                "INSERT INTO campaigns (campaign_id, state) VALUES ('campaign', 'active');
                     INSERT INTO workflows (workflow_id, state) VALUES ('workflow', 'active');",
            )
            .unwrap();
        let transaction = connection.transaction().unwrap();
        for index in 0..=MAX_READY_WORK {
            transaction
                .execute(
                    "INSERT INTO work_items
                         (work_id, workflow_id, state, budget_remaining, required_capabilities)
                         VALUES (?1, 'workflow', 'ready', 1, '')",
                    [format!("work-{index:04}")],
                )
                .unwrap();
        }
        transaction.commit().unwrap();

        let ready = list_ready_work(&connection, "campaign", &[], usize::MAX, None).unwrap();
        assert_eq!(ready.len(), MAX_READY_WORK);
        assert_eq!(ready.iter().collect::<BTreeSet<_>>().len(), MAX_READY_WORK);
        assert_eq!(ready.first().unwrap().1, "work-0000");
        assert_eq!(ready.last().unwrap().1, "work-1023");

        drop(connection);
        fs::remove_file(path).unwrap();
    }
}
