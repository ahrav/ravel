# Ravel MVP Epics

These 10 epics define the smallest implementation that can test the MVP thesis. They preserve the hard invariants in `mvp-outline.md` while avoiding public frameworks, generic backends, workflow DSLs, and infrastructure that the two pilots do not require. Child tasks should contain implementation detail; these epics define outcomes and proof obligations.

## E01 — Fix the Pilot and Experiment Contracts

**Description**

Choose the two controlled pilots before building runtime machinery: one evidence-rich Research question and one finite Change migration with a trusted discovery rule, one fixed treatment, and several dozen targets. Check in private, unstable pilot configuration that fixes trust boundaries, safe repositories and branches, provider profiles, evaluator commands, scalar budgets, and precommitted experiment criteria.

The configuration is an input to the MVP, not a new product surface. It is versioned by Git revision and content digest and uses fixed enums, allowlists, and bounds rather than a policy language or compatibility framework.

**Acceptance criteria**

- [ ] The Research question has independently inspectable evidence and a defined method for assessing supported, incorrect, omitted, and unresolved conclusions.
- [ ] The Change migration has trusted deterministic discovery, one fixed treatment, explicit write scopes, several dozen targets, and few or no subjective exemptions.
- [ ] The pilot repository passes a Linux preflight and excludes unsupported repository constructs and candidate-controlled evaluator or workflow paths.
- [ ] One safe code host, repository, campaign branch policy, authority boundary, two model providers, fixed model profiles, trusted evaluator commands, and S3 environment are selected.
- [ ] Fixed caps cover calls or tokens, attempts, parallelism, follow-ups, workflow depth, deadlines, artifact size, and total campaign spend or usage.
- [ ] Inputs, run counts, outcomes, and success criteria are precommitted for the single-agent, single-machine multi-agent, and distributed treatments.
- [ ] Routine Research decisions and safe-branch Change integration are autonomous; any human-only boundary is explicit and outside ordinary pilot progress.
- [ ] The configuration format is private and unstable. No schema migration system, profile registry, policy DSL, public configuration API, or generic workflow infrastructure is introduced.

**Dependencies:** None

**Priority:** 0

## E02 — Establish the S3 Durable Log and Minimal Rust Runtime

**Description**

Create one Cargo package producing one node binary and implement the narrow Amazon S3 correctness boundary used by the campaign: immutable create-if-absent objects and one conditionally replaced campaign head. Events and artifacts are immutable; publication authority resides only in the head. The implementation uses the selected AWS SDK directly and does not hide S3 behind a portable object-store abstraction.

Durable records use one explicit v1 event/head envelope and canonical bytes. The campaign is append-only for the MVP: retained history, leaked orphan objects, and bounded single-request artifacts are preferable to unsafe cleanup, compaction, or multipart machinery.

**Acceptance criteria**

- [ ] A pinned Rust toolchain, edition, async runtime, target set, and locked dependency set build one binary; CI runs formatting, check, clippy with warnings denied, and tests without repository credentials.
- [ ] Immutable events and artifacts are created with `If-None-Match: *`; initial head creation uses the same precondition; head replacement uses `If-Match` with the observed ETag.
- [ ] ETags are treated only as opaque version tokens. Existing immutable keys are accepted only after trusted full-byte SHA-256 and size verification.
- [ ] The versioned envelope records stable commit/operation identity, sequence, parent sequence/digest/key, writer fence, and canonical content; unknown versions or invalid encodings fail closed before conversion to domain types.
- [ ] A frozen v1 history fixture proves decode, digest, and chain behavior without introducing a schema framework.
- [ ] Ambiguous publication checks the current head and, if superseded, walks the complete retained parent chain for the operation identity. A gap remains `UNRESOLVED`, and no object is eagerly deleted.
- [ ] Two processes racing from one observed head produce at most one authoritative publication; stale ETags, duplicate puts, timeout/reset, lost success, and an ambiguous retry followed by `409` or `412` cannot corrupt the chain.
- [ ] Live integration tests against the selected general-purpose S3 bucket and pinned SDK exercise typed `404`, `409`, `412`, timeout/reset, and lost-response behavior. Publication retries are disabled or proven to preserve identical bytes, preconditions, and operation identity.
- [ ] A lower fixture fence cannot replace a higher-fence head; dynamic controller acquisition and stale-controller takeover are deferred to the controller-authority epic.
- [ ] Event, artifact, and head prefixes have no application deletion, GC, compaction, or lifecycle expiration. Pilot artifacts stay below the single-`PutObject` limit; multipart upload is deferred.

**Dependencies:** Fix the Pilot and Experiment Contracts

**Priority:** 0

## E03 — Reconstruct Disposable Local State from Durable History

**Description**

Build the per-node SQLite projection needed for synchronization and the next scheduling milestones. S3 remains the only durable authority. SQLite and the digest-addressed local artifact directory are disposable local accelerators and are never copied between machines.

A node rebuilds by reading a fresh campaign head and traversing immutable parent references, not by treating S3 prefix listing as a publication snapshot. Remote I/O and digest verification happen outside short database transactions.

**Acceptance criteria**

- [ ] A fresh node reconstructs the campaign from the head by traversing the complete immutable parent chain; `LIST` is reserved for diagnosis or orphan accounting.
- [ ] Event bytes are fetched, version-validated, and digest-verified before opening the apply transaction.
- [ ] One transaction validates the next sequence and previous digest, applies all event-derived changes, records the unique event identity, and advances the `(sequence, tail_digest)` cursor.
- [ ] Reapplying the same event is a no-op. A gap, conflicting digest, unknown version, or failed conversion leaves both projection and cursor unchanged and makes readiness fail closed.
- [ ] The projector exposes its verified cursor against a freshly read S3 head. At the same cursor, all event-derived query state is equivalent; cache occupancy, advisory presence, and other ephemeral metadata are excluded.
- [ ] One daemon-owned writer task/connection serializes SQLite writes. No transaction or database guard crosses an `.await`, network work stays outside transactions, and blocking SQLite work does not run on async executor threads.
- [ ] The initial implementation uses serialized/default-journal access. WAL is enabled only after measured reader blocking justifies it, with one-host sidecars, writer-owned checkpointing, bounded busy handling, and verification of the linked SQLite version.
- [ ] The minimal schema has an explicit application/schema version and `NOT NULL` or `UNIQUE` constraints for stable identities, applied events, and cursors. If foreign keys are used, every connection enables and verifies them; rebuilt test databases pass `quick_check` and `foreign_key_check`.
- [ ] Only event/cursor and scheduling tables required by the current milestone are created; Research, Change, judgment, and evaluation tables arrive with their owning epics, with no generic projector, checkpoint, or cache-metadata framework.
- [ ] SQLite contains no uniquely durable state. Version or integrity mismatch stops local users and rebuilds from S3 instead of invoking online/rollback migrations, backup transport, or power-loss durability machinery.
- [ ] Kill and injected-write-failure tests cover before apply, after row mutation but before commit, and immediately after commit; recovery never skips or duplicates an event and never reports controller readiness from an invalid projection.

**Dependencies:** Establish the S3 Durable Log and Minimal Rust Runtime

**Priority:** 0

## E04 — Fence Work Claims and Result Submission

**Description**

Implement simple authoritative work claims separately from campaign-controller authority. A configured actor ID and random per-start instance ID identify a claimant; advisory presence publishes only static capabilities and lease freshness. Presence may improve routing but never proves ownership or drives correctness.

Each work claim is its own S3 CAS domain. Claiming, renewal, reclamation, and submission all transition the same claim object so completion cannot race reclamation through a different key.

**Acceptance criteria**

- [ ] Stable actor identity and ephemeral instance identity are distinct, and every claim binds both identities, the work revision, and a monotonic fence.
- [ ] Presence contains actor, instance, static capabilities, and freshness only; stale or missing presence cannot violate ownership or block recovery.
- [ ] Claim creation, renewal, and reclamation use create-if-absent or `If-Match` on the same claim key, with one frozen lease policy and no generic membership or lease framework.
- [ ] Internal execute/submit APIs require an opaque fence-bearing claim authority value rather than accepting raw IDs supplied by a worker.
- [ ] Completion performs a same-key CAS from `ACTIVE(fence)` to `SEALED/SUBMITTED(fence, result_ref)`; reclamation and completion race on that ETag, and only one can win.
- [ ] A controller records only sealed submissions whose immutable result identity and work revision validate. A stale result may remain as evidence but cannot complete work.
- [ ] Two machines racing for a claim cannot both hold valid authority, and a lower-fence or wrong-revision submission fails closed.
- [ ] Unexpired claims remain valid across controller replacement and their sealed submissions can be processed by the replacement.
- [ ] Fault tests cover lost claim/renewal/submission responses, completion racing reclamation, worker death, a delayed old-fence return, and restart reconciliation without a machine-departure event.

**Dependencies:** Establish the S3 Durable Log and Minimal Rust Runtime; Reconstruct Disposable Local State from Durable History

**Priority:** 0

## E05 — Fence Campaign Authority and Controller Failover

**Description**

Make controller ownership and event publication one atomic CAS domain. The campaign head contains controller owner, lease, fence, event tail, and operation identity together. Acquisition, renewal, takeover, and every authoritative event commit conditionally replace that same object, preventing a stale controller from publishing through an independently observed log-head ETag.

Keep policy separate from authority: deterministic policy proposes transitions from immutable observations, while the fenced authority layer performs and validates S3 changes. The top-level node supervisor owns all long-lived loops, spawned tasks, and bounded admission points.

**Acceptance criteria**

- [ ] Controller owner, lease, monotonic fence, event tail, and operation identity reside in one versioned campaign-head object.
- [ ] Acquisition, renewal, takeover, and event publication all CAS the same observed head ETag; authoritative commit APIs require an opaque controller-authority value and revalidate it in that CAS.
- [ ] Event commits preserve the exact parent chain and cannot regress the controller fence. A stale controller cannot commit after a higher fence has won, even if it retained an older head observation.
- [ ] Before its first authoritative decision, a replacement controller rebuilds and verifies its projection to the exact freshly read S3 head. Gaps, unknown versions, and chain failures prevent readiness.
- [ ] Controller policy performs no S3 or provider I/O and cannot bypass the fenced commit layer; it only proposes deterministic state transitions.
- [ ] Killing the active controller allows another host to take over, process sealed submissions, and continue unexpired claims without requiring the old host to return.
- [ ] The node supervisor bounds every local admission queue and owns every renewal, sync, scheduling, invocation, and publication task. No detached task survives its owner.
- [ ] Shutdown stops admission, requests loop cancellation, classifies interrupted remote effects as known or unknown, performs required reconciliation, and joins or reaps all tasks before exit.
- [ ] Fault tests include lost head-CAS success followed by supersession, a delayed stale-controller write after takeover, takeover from stale SQLite, failure during submission processing, and restart reconciliation with no eager orphan deletion.

**Dependencies:** Fence Work Claims and Result Submission; Reconstruct Disposable Local State from Durable History

**Priority:** 0

## E06 — Prove Bounded Distributed Research Decisions

**Description**

Implement the concrete `workflows::research` pilot together with only the model execution and decision behavior it needs. Two fixed provider adapters use internal concrete dispatch. Model calls create immutable observations; deterministic policy consumes those observations, applies evidence precedence, and creates only the bounded work allowed by the pilot protocol.

The pilot consists of one decomposition step, three to five independent researchers, one critic round, at most one discriminating follow-up for material disagreement, and one synthesis. This proves multi-provider distributed judgment without creating a provider SDK, policy engine, adjudication platform, or recursion framework.

**Acceptance criteria**

- [ ] Exactly the two selected providers are supported through internal concrete dispatch, preferably an enum; there is no public provider API, `dyn` async provider trait, profile registry, or generic agent harness abstraction owned by Ravel.
- [ ] Every call records its immutable starting manifest separately from its dynamic trace, including request identity, exact provider/model/profile, structured result or validation failure, raw request/response artifacts, provider-reported usage, errors, and relevant tool/context digests.
- [ ] Cancellation stops local waiting but does not assert that the remote call stopped. Late results reconcile by request identity, and unknown outcomes have explicit retry or unresolved behavior.
- [ ] Model results are immutable observations. Deterministic policy, not provider code, applies one explicit decision table in which trusted failure or a validated counterexample overrides model approval.
- [ ] Fixed limits bound calls/tokens, attempts, parallelism, critic work, the single follow-up generation, depth, and deadline; exhaustion creates no new work and reports unresolved items.
- [ ] At least three independent hosts execute concurrent research and critic work; a late-joining host reconstructs local state and contributes.
- [ ] A worker can disappear and have work reclaimed, and controller authority can move hosts without losing coherent progress or accepting a stale result.
- [ ] Material disagreement produces at most one evidence-driven discriminating follow-up before synthesis rather than another unbounded model debate.
- [ ] Final synthesis records supported conclusions, evidence, rejected explanations, material uncertainty, and unresolved questions with full provenance and no routine human approval.
- [ ] Interrupted provider/process tasks are reconciled and reaped under the node lifecycle contract; no detached invocation survives shutdown.
- [ ] The MVP has a concrete `workflows::research` module only. No workflow trait or DSL is extracted; shared helpers or data may be extracted later only where Research and Change demonstrate identical semantics.

**Dependencies:** Fence Campaign Authority and Controller Failover

**Priority:** 1

## E07 — Isolate Candidates and Construct Immutable Git Artifacts

**Description**

Establish the local Change trust boundary independently of model, lease, and scheduler machinery. On the controlled Linux pilot, generated code runs in an existing OS sandbox against an exact source base. Trusted code validates a deliberately narrow filesystem delta and uses the Git CLI to construct an immutable candidate.

The MVP supports regular files, directories, and required executable-bit changes under explicit write scopes. It fails closed on repository and filesystem shapes the pilot does not need rather than implementing a general canonicalizer or sandbox backend.

**Acceptance criteria**

- [ ] Candidate execution has no daemon/code-host credentials, hidden evaluator material, writable daemon Git metadata, shared writable caches, or network access.
- [ ] An existing Linux isolation mechanism supplies read-only source/input binds, a private writable overlay and temporary directory, and fixed CPU, memory, process, time, filesystem, and output limits; no custom sandbox runtime or pluggable backend is built.
- [ ] Candidate and evaluator launch specifications are distinct concrete policy types and cannot be substituted for one another.
- [ ] The runner owns a process group, bounds stdout/stderr, and kills and reaps descendants before cleaning or reusing a workspace.
- [ ] Trusted validation accepts only regular-file additions, changes, deletions, directories, and allowed executable-bit changes inside the declared write scope and count/size caps.
- [ ] Symlinks, hard links, special files, nested repositories, submodules, LFS pointers, normalization/case ambiguity, unsupported modes, and any out-of-scope path fail closed before or after generation.
- [ ] Trusted Git commands construct an immutable candidate from the exact validated bytes and record base OID, result tree OID, delta digest, and a transferable artifact.
- [ ] Another machine reconstructs the exact candidate and verifies its identities without trusting the generator's report.
- [ ] A fresh repair attempt receives a new attempt and candidate identity. Rebase support and rename detection are omitted from the MVP rather than mutating prior evidence.
- [ ] Timeout, cancellation, blocked-pipe, and descendant-process tests prove workspace cleanup occurs only after all candidate processes are reaped.

**Dependencies:** Establish the S3 Durable Log and Minimal Rust Runtime; Fix the Pilot and Experiment Contracts

**Priority:** 0

## E08 — Prove the Trusted Evaluation and Code-Host Path

**Description**

Use the selected code host's existing CI matrices, trusted runner labels, required checks, and merge machinery as the primary distributed evaluation and integration path. Retain only a thin trusted wrapper for hidden deterministic commands and a publisher/reconciler for candidate refs, the single campaign branch, and the single campaign PR.

Evaluator execution remains a separate trust domain from candidate generation. The candidate may not alter evaluator/workflow definitions, hidden inputs, parsers, controls, or baselines. Ravel records exact commit and check-run identities but does not build an evaluator plugin platform, custom queue, or merge planner.

**Acceptance criteria**

- [ ] A fixed evaluator allowlist and exact-match capability labels select the trusted CI/runner jobs; there is no capability scoring, dynamic plugin loading, arbitrary evaluator DAG, or model-authored manifest.
- [ ] Each evaluation binds the exact candidate tree/commit, evaluator identity/version, trusted inputs, and policy and yields immutable `PASS`, `FAIL`, `ERROR`, or `TIMEOUT` evidence.
- [ ] Hidden evaluator commands run with immutable hidden inputs, no model access, no network inside the evaluated subprocess, separate writable state, fixed resource/output limits, and process-group kill/reap semantics.
- [ ] Candidate write policy prevents changes to evaluator and workflow paths, and trusted code verifies those inputs before accepting a check result.
- [ ] Required heterogeneous checks can run on remote hosts through existing code-host CI or trusted self-hosted labels; deterministic failure cannot be overridden by semantic judges.
- [ ] Only trusted publisher workers hold code-host credentials. Candidate refs, commit SHA, check-run identity, campaign branch, and campaign PR are recorded in campaign history.
- [ ] Branch push and PR create/update use deterministic external identities and reconcile timeout/lost-response outcomes by reading code-host state before retrying.
- [ ] Accepted non-overlapping candidates can be applied serially to one campaign branch and one campaign PR, after which existing required checks and merge queue or auto-merge perform integration.
- [ ] Fault tests cover evaluator timeout/crash, push success with lost response, duplicate PR request, stale check result, and publisher restart without duplicate authoritative integration.
- [ ] No custom CI service, general code-host interface, custom merge queue, review UI, or per-candidate PR fan-out is built.

**Dependencies:** Isolate Candidates and Construct Immutable Git Artifacts; Fence Campaign Authority and Controller Failover

**Priority:** 0

## E09 — Prove the Distributed Change Workflow

**Description**

Implement the concrete `workflows::change` pilot by composing trusted discovery, deterministic grouping, isolated candidate construction, trusted evaluation, bounded semantic judgment, and the existing code-host path. The migration is a finite proof workload, not a generic planner.

Trusted discovery assigns the pilot's fixed treatment. Targets are stably sorted and grouped only when their write scopes do not overlap and the fixed size cap is respected. Ambiguous targets remain explicit rather than triggering a classification or adjudication subsystem.

**Acceptance criteria**

- [ ] Trusted discovery records source revision, rule identity/digest, stable target identity/location, context, and declared write scope for every target.
- [ ] The fixed treatment and deterministic grouping rule use stable order, non-overlapping write scopes, and a hard target-count cap; no judge-reviewed grouping, dependency planner, or general migration taxonomy is introduced.
- [ ] Ambiguous or unsupported targets become explicit `BLOCKED` or `UNRESOLVED` records and are never silently omitted.
- [ ] Several hosts produce candidates concurrently against the declared base epoch using the candidate-isolation contract.
- [ ] Every candidate passes all required deterministic evidence before independent semantic judgment; mechanical failure always wins.
- [ ] A rejected candidate may receive at most one ordinary fresh attempt with a new identity. The MVP has no generic repair planner or rebase path.
- [ ] Attempt completion, candidate identity, evaluation eligibility, semantic acceptance, and integration state remain separate.
- [ ] Accepted non-overlapping candidates are applied serially through the one campaign branch/PR path, with ambiguous external outcomes reconciled.
- [ ] Every discovered target finishes as resolved, rejected, blocked, or unresolved, and final trusted rediscovery over the integrated source finds no unclassified legacy target.
- [ ] The multi-host migration reaches its configured autonomous stopping condition without humans assigning targets, choosing ordinary candidates, or approving routine integration.
- [ ] The MVP has a concrete `workflows::change` module and proven shared helpers only; it does not add a workflow trait or DSL.

**Dependencies:** Prove Bounded Distributed Research Decisions; Isolate Candidates and Construct Immutable Git Artifacts; Prove the Trusted Evaluation and Code-Host Path

**Priority:** 1

## E10 — Run the Precommitted MVP Feasibility Gate

**Description**

Run the two precommitted three-treatment comparisons and issue a go/no-go report. Reuse the correctness, failure, and distributed proof artifacts produced by the owning epics rather than recreating a cross-cutting recovery framework. Add one final end-to-end multi-machine kill-and-recovery scenario to show that the boundaries compose.

Analysis is offline and descriptive. Existing campaign events, provider usage records, immutable traces, evaluator results, and code-host records supply the measurements; the experiment must not create a telemetry product or change its success definition after observing results.

**Acceptance criteria**

- [ ] Research and Change each run the frozen single-agent, single-machine multi-agent, and distributed multi-machine treatments under the precommitted inputs, bounds, and run counts.
- [ ] The distributed treatment uses at least three independent machines/VM hosts and includes a late join, active-worker loss, controller failover, remote model/judge/evaluator work, and fresh SQLite reconstruction.
- [ ] One final end-to-end scenario kills an active worker and controller around an external unknown outcome, then demonstrates chain-based reconciliation, stale-authority rejection, bounded recovery, and coherent completion or explicit unresolved state.
- [ ] Research reports wall time, supported/incorrect/omitted conclusions, useful evidence, discriminating follow-up, provider usage/cost, duplicate work, and scaling efficiency.
- [ ] Change reports resolved targets, omissions, semantic correction/rejection, conflicts, wasted work, usage/cost per target, utilization, scaling efficiency, and final rediscovery.
- [ ] Autonomous proof shows that humans supplied only objective/configuration and did not assign work, approve routine conclusions, choose ordinary candidates, or perform routine safe-branch integration.
- [ ] Correctness evidence references the owning epic tests for S3 ambiguity, SQLite atomic projection, claim/controller fencing, provider unknown outcomes, process cleanup, trusted evaluation, and code-host reconciliation.
- [ ] A small offline script emits CSV and a Markdown report from retained records. No metrics service, dashboard, exporter framework, permanent baseline mode, adaptive reruns, or significance claim is added.
- [ ] The report gives a go/no-go recommendation and answers where distribution helped, where it stopped scaling, whether judge diversity and disagreement added value, what work was duplicated, and whether S3, controller, or evaluator paths were bottlenecks.
- [ ] MVP completion is denied unless the section 43 invariants and actual multi-machine/failover requirements are demonstrated; a no-go result is still a valid completed feasibility experiment.

**Dependencies:** Prove Bounded Distributed Research Decisions; Prove the Distributed Change Workflow

**Priority:** 1
