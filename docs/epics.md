# Ravel MVP Epics

E01–E04 are complete frozen-v1 proof records. E05–E10, together with the scoped-v2
Phase 1 and Phase 3 structural epics below, define the smallest active implementation
that can test the MVP thesis. They preserve the hard invariants in `mvp-outline.md`
while avoiding public frameworks, generic backends, workflow DSLs, campaign profiles,
and infrastructure that the concrete Research and Change campaigns do
not require. Child tasks should contain implementation detail; these epics define
outcomes and proof obligations.

## E01 — Fix the Pilot and Experiment Contracts

Status: Complete — frozen v1 proof record

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

Status: Open — frozen v1 code, pending the selected-bucket live preflight
(`ravel-aq8.7`), which must close or be deferred on its own recorded evidence

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
- [ ] A lower fixture fence cannot replace a higher-fence v1 head. Dynamic controller acquisition was outside E02; scoped-v2 controller acquisition and stale-controller takeover are specified by V2-P1 and E05 without altering this fixture.
- [ ] Event, artifact, and head prefixes have no application deletion, GC, compaction, or lifecycle expiration. Pilot artifacts stay below the single-`PutObject` limit; multipart upload is deferred.

**Dependencies:** Fix the Pilot and Experiment Contracts

**Priority:** 0

## E03 — Reconstruct Disposable Local State from Durable History

Status: Complete — frozen v1 proof record

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

Status: Complete — frozen v1 proof record

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

## Frozen-v1 / scoped-v2 boundary

E01–E04 remain the complete frozen-v1 proof record. Existing v1 event, head, claim,
projection, artifact, key, encoding, and fixture bytes remain unchanged. Scoped v2 is a
new durable boundary with new scope keys, identities, claims, projections, and
`EventEnvelope`. A v2 campaign starts with a v2 root `Scope`, not a global sequencer;
one authoritative chain never mixes v1 and v2 events.

The scoped-v2 implementation may reuse the v1 algorithms only through explicit v2
types and bindings. It must never reinterpret, rewrite, migrate, or silently route a v1
object through v2 code. The exact v2 event suffix, canonical serialization and digest
encodings, serialized `ScopeHead` and root-genesis forms, and payload schemas remain
open contract decisions and must be fixed before new durable bytes ship.

## V2-P1 — Add the Scoped-v2 Substrate

**Description**

Add the scoped-v2 durable substrate beside the frozen-v1 substrate. Reuse immutable
publication, conditional replacement, exact-chain replay, disposable projection, and
same-key work-claim algorithms through version-specific v2 types. Do not modify the v1
paths or fixtures and do not add controller leases, plan admission, grants, escrow,
certificates, or settlement in this epic.

**Acceptance criteria**

- [ ] Every scoped-v2 durable identity uses the exact axis `campaign_id`, `scope_id`, `parent_scope_id`, `delegation_digest`, `plan_digest`, `work_id`, `work_revision`, `claim_fence`, and `scope_epoch`, with fields required only where the represented object has that relationship.
- [ ] Every scoped-v2 event uses an `EventEnvelope` containing exactly `envelope_version`, `scope_id`, `sequence`, `parent_event`, `writer_epoch`, `operation_id`, `payload_type`, and `payload_version`; envelope and payload versions are validated independently.
- [ ] Scoped-v2 objects use `workspace/{workspace_id}/campaigns/{campaign_id}/scopes/{scope_id}/head`, `scopes/{scope_id}/events/...`, `scopes/{scope_id}/claims/{work_id}/{work_revision}`, `plans/{plan_digest}`, and `artifacts/{digest}`. The unresolved `events/...` suffix and encoding choices are not inferred from v1.
- [ ] Each scope has its own `ScopeHead`, immutable parent-linked event chain, claim keys, verified sequence and tail, active plan reference, and projection cursor. Independent scopes never share a mutable head or replay cursor.
- [ ] Scope-indexed SQLite projection applies one verified event and advances only that scope's cursor atomically; a gap, digest conflict, wrong-scope event, unknown version, conversion failure, or mixed-version parent leaves that scope unchanged and not ready.
- [ ] The sync engine supports scope-selective replay and verifies readiness against a freshly read selected `ScopeHead` without using `LIST` as a publication snapshot.
- [ ] A v2 `ScopeHead` cannot reference a v1 event, a v1 campaign head cannot reference a v2 event, and cross-version negative fixtures fail closed without altering frozen-v1 fixtures.
- [ ] A two-scope integration proof advances and rebuilds the scopes independently, including one scope failing replay while the other remains valid and ready.

**Dependencies:** E04 — Fence Work Claims and Result Submission

**Priority:** 0

## E05 — Fence Scope Authority and Controller Failover

**Description**

Make controller ownership and decision publication one atomic CAS domain per `Scope`.
Each `ScopeHead` binds controller instance, lease, `scope_epoch`, decision tail, active
plan lineage, and operation identity. Acquisition, renewal, takeover, and every scoped
`Decision` commit conditionally replace that same object, preventing a stale controller
from publishing through an independently observed head ETag.

Keep policy separate from authority: deterministic policy proposes transitions from
immutable `Observation`s, while the fenced scope-authority layer performs and validates
durable changes. The top-level node supervisor owns all long-lived loops, spawned tasks,
bounded admission points, and one bounded per-scope takeover-demand queue. This epic
owns generic `SETTLEMENT_PRESSURE` scheduling, not delegation, certificate, escrow, or
settlement policy.

**Acceptance criteria**

- [ ] Controller instance, lease, monotonic `scope_epoch`, decision tail, active plan lineage, and operation identity reside in one versioned `ScopeHead` authority object.
- [ ] Acquisition, renewal, takeover, and decision publication all CAS the same observed `ScopeHead` ETag; authoritative commit APIs require an opaque scope-authority value and revalidate it in that CAS.
- [ ] Decision commits preserve the exact scope-local parent chain and cannot regress `scope_epoch`. A stale scope controller cannot commit after a higher epoch has won, even if it retained an older head observation.
- [ ] Before its first authoritative `Decision`, a replacement controller rebuilds and verifies its scope-selective projection to the exact freshly read `ScopeHead` and active plan lineage. Gaps, mixed versions, unknown versions, and chain failures prevent readiness.
- [ ] Scoped-controller policy performs no S3, provider, evaluator, Git, or code-host I/O and cannot bypass the fenced commit layer; it only proposes deterministic state transitions from immutable inputs.
- [ ] Killing an active scope controller allows another host to take over, process sealed submissions, and continue unexpired claims without requiring the old host to return. Parent and child scope controllers fail and recover independently.
- [ ] The node supervisor bounds every local admission queue and owns every renewal, sync, scheduling, invocation, publication, and reconciliation task. No detached task survives its owner.
- [ ] The node supervisor owns one bounded per-scope takeover-demand queue. It accepts ordinary routing demand, cancellation/drain demand, and a `SETTLEMENT_PRESSURE` reason without embedding delegation, certificate, or settlement policy. V2-P3 supplies and tests the durable expired/unsettled state that triggers that reason.
- [ ] Shutdown stops admission, requests loop cancellation, classifies interrupted remote effects as known or unknown, performs required reconciliation, and joins or reaps all tasks before exit.
- [ ] Fault tests include lost `ScopeHead` CAS success followed by supersession, a delayed stale-scope-controller write after takeover, takeover from stale scope-selective SQLite state, failure during submission processing, independent parent and child controller failure, injected settlement-pressure takeover demand, and restart reconciliation with no eager orphan deletion.

**Dependencies:** V2-P1 — Add the Scoped-v2 Substrate

**Priority:** 0

## V2-P3 — Implement Recursive Admission

**Description**

Implement immutable `PlanRevision`s with typed `proposal_basis` and one shared,
deterministic admission path. Admission is the sole path by which `WorkSpec`s,
`ChildScopeProposal`s, `DelegationGrant`s, `EffectGrant`s, budget spend, and external
effects become authoritative. Model, human, analyzer, discovery, search-policy, judge,
evaluator, and code-host output remains an `Observation` or proposal source and cannot
override an admission failure.

`ClaimSpec` is a semantic goal. A work claim is fenced ownership of one exact
`WorkSpec` revision; it is not a semantic claim and does not authorize an external
effect.

This epic owns delegation, escrow, attenuation, cancellation and drain semantics,
bottom-up sealing, `CompletionCertificate`s, settlement policy, quarantine accounting,
and the end-to-end settlement proof. E05 owns only scoped fencing, takeover, lifecycle
supervision, and generic settlement-pressure scheduling. Exact unresolved durable
schemas and ordering choices must be settled before their bytes ship; this epic must
not invent them through implementation.

**Acceptance criteria**

- [ ] A `PlanRevision` is immutable and content-addressed by `plan_digest`, binds its exact scope and parent plan, and carries typed proposal-basis references, bounded `ClaimSpec`s, `WorkSpec`s, `ChildScopeProposal`s, dependencies, and bounds without exposing a direct workflow authority API.
- [ ] Admission validates proposal-basis existence, type, visibility, scope, and current bindings; dependency existence and acyclicity; exact identities; finite fanout, attempts, deadlines, effects, and resource credits; budget availability; grant attenuation; write/capability containment; and campaign-specific deterministic rules.
- [ ] Campaign policy defines each target predicate and verifier contract. Admission validates their exact bindings, and no decision, certificate, or completion claim may establish more than its configured verifier checks.
- [ ] Fixed initial work and observation-derived work use the same admission path. No model, human, analyzer, discovery rule, search policy, judge, evaluator, publisher, or concrete campaign module can directly release work, create a child, mint a grant, spend budget, authorize an effect, or commit a `Decision`.
- [ ] Root depth is one, a direct child is depth two, and grandchildren are rejected for the MVP. A parent atomically commits one `DelegationGrant` and escrow debit before child genesis can reference that grant and become active.
- [ ] A `DelegationGrant` creates one bounded child authority and escrow domain. An `EffectGrant` authorizes one bounded external operation. Both attenuate parent capabilities, write scope, deadline, budget, and resource authority, but their lifecycles remain separate.
- [ ] Every external worker, model, judge, evaluator, Git, or code-host operation starts only after the trusted launcher jointly validates an admitted `WorkSpec` revision, live claim authority for that revision, and matching `EffectGrant`. The exact durable grant-to-claim-fence and attempt binding is fixed before the grant schema ships.
- [ ] `scope_epoch` fences scoped decisions, while `claim_fence` fences ownership and submission for one exact `WorkSpec` revision. Neither fence substitutes for the other, and claim ownership alone never authorizes an external effect.
- [ ] Plan supersession never rewrites old observations, attempts, work revisions, or claims. The validity and drain rules for already released work, live claims, unexpired grants, and in-flight operations must be resolved explicitly before supersession is enabled.
- [ ] Cancellation blocks new work and effect admission, preserves existing effect deadlines, stops local waits, reconciles remote outcomes, and seals children bottom-up without extending authority.
- [ ] A sealed child produces a `CompletionCertificate` that exactly summarizes terminal decisions, supported and unresolved claims, evidence root, terminal head, policy, confirmed spend, returned budget, and unknown reserve. Parent policy cannot use the certificate to upgrade evidence or bypass required unresolved claims.
- [ ] Settlement is idempotent, cannot create evidence or budget, and conserves `escrowed = confirmed_spend + returned + quarantined_unknown`. Returned budget is released only through settlement, and unknown reserve remains unavailable until a root `QuarantineResolved` decision cites an authoritative external outcome.
- [ ] Certificate evaluation and settlement ordering, root completion representation, cross-scope observation visibility, and provider-specific quarantine evidence remain explicit contract questions; the selected answers require failure and idempotency tests before durable payloads ship.
- [ ] A bounded observation-derived revision completes through admission, and a parent/child proof covers independent controller failure, expired-unsettled-child settlement-pressure takeover, certificate handling, idempotent settlement, exact dependent blocking, and conserved escrow.

**Dependencies:** E05 — Fence Scope Authority and Controller Failover

**Priority:** 0

## E06 — Prove Bounded Distributed Research Decisions

**Description**

Implement the concrete Research campaign together with only the model execution and
decision behavior it needs. Two fixed provider adapters use internal concrete dispatch.
Model, critic, judge, and planner outputs are immutable `Observation`s or proposal
sources. Initial research, critic work, and any observation-derived follow-up become
authoritative only through admitted `PlanRevision`s and scoped `Decision`s.

The campaign consists of one root `Scope`, one initial admitted plan, three to five
independent researchers, one critic round, at most one discriminating follow-up child
scope for material disagreement, and one synthesis. That bounded follow-up uses the one
allowed depth-two child scope. The child seals, returns a certificate, and settles before
root completion, which seals a root certificate. This proves multi-provider distributed
judgment without creating a provider SDK, policy engine, adjudication platform, workflow
trait, campaign profile, or generic discovery interface.

**Acceptance criteria**

- [ ] Exactly the two selected providers are supported through internal concrete dispatch, preferably an enum; there is no public provider API, `dyn` async provider trait, profile registry, generic agent harness, campaign-profile framework, workflow trait, or workflow DSL owned by Ravel.
- [ ] Every model call requires an admitted `WorkSpec`, live claim authority, and matching `EffectGrant`, and records its immutable starting manifest separately from its dynamic trace. Records bind campaign, scope, plan, work revision, `claim_fence`, attempt, grant, stable operation identity, exact provider and model, exact fixed model configuration identifier and digest, structured result or validation failure, raw request/response artifacts, provider-reported usage, errors, and relevant tool/context digests.
- [ ] Cancellation stops local waiting but does not assert that the remote call stopped. Late results reconcile by stable provider request and operation identity, and unknown outcomes have explicit retry, quarantine, or unresolved behavior without reusing stale authority.
- [ ] Model, critic, judge, human, and search-policy results are immutable `Observation`s. Deterministic scoped policy, not provider code, applies one explicit decision table in which trusted failure or a validated counterexample overrides model approval.
- [ ] Fixed campaign configuration bounds calls or tokens, attempts, parallelism, critic work, the single follow-up generation, scope depth, child fanout, deadlines, effects, resources, and spend. Exhaustion creates no direct work and reports unresolved items.
- [ ] At least three independent hosts execute concurrent research and critic `WorkSpec`s; a late-joining host reconstructs selected scoped state and contributes.
- [ ] A worker can disappear and have work reclaimed, and scoped controller authority can move hosts without losing coherent progress, invalidating an unexpired claim, or accepting a stale result.
- [ ] Material disagreement can inform at most one superseding `PlanRevision` for one evidence-driven discriminating follow-up, admitted as the one allowed depth-two child scope; no direct controller-created work, descendant scope, second critic round, or unbounded model debate is permitted.
- [ ] Final synthesis records supported conclusions, evidence, rejected explanations, material uncertainty, and unresolved questions with full scope, plan, work, attempt, producer, evaluator, and policy provenance and no routine human approval. The unresolved synthesis payload-shape question is not decided by this epic text.
- [ ] The follow-up child scope seals, returns a verifier-bounded certificate, and settles idempotently; root completion waits for required claims and settlement, seals a root certificate, and preserves escrow conservation and unknown reserve.
- [ ] Interrupted provider/process tasks are reconciled and reaped under the node lifecycle contract; no detached invocation survives shutdown.
- [ ] The concrete Research module shares only demonstrated non-authority helpers. No workflow trait, DSL, campaign profile, curriculum engine, online model training, learned reward policy, universal state matcher, generic discovery interface, or unbounded task generation is introduced.

**Dependencies:** V2-P3 — Implement Recursive Admission

**Priority:** 1

## E07 — Isolate Candidates and Construct Immutable Git Artifacts

**Description**

Establish the local Change trust boundary independently of model and scheduler
machinery. On the controlled Linux pilot, generated code runs in an existing OS sandbox
against an exact source base. Trusted code validates a deliberately narrow filesystem
delta and uses the Git CLI to construct an immutable candidate. Candidate execution is
an external effect and therefore requires an admitted `WorkSpec`, live claim authority,
and a matching `EffectGrant` checked by the trusted launcher.

The MVP supports regular files, directories, and required executable-bit changes under
explicit write scopes. It fails closed on repository and filesystem shapes the pilot
does not need rather than implementing a general canonicalizer or sandbox backend.
Candidate identity remains the base OID, result tree OID, candidate commit OID, and
bundle artifact digest. There is no standalone serialized delta digest.

> **Amendment note.** The pre-amendment E07 criterion required recording a `delta
> digest`, while the pre-amendment outline already stated that no separate delta stream
> is serialized. The Phase 0 amendment resolves that pre-existing conflict in favor of
> the outline: the base and result tree OIDs already determine the diff, so any diff is
> re-derived from raw trees and no delta digest is stored. This is a deliberate change to
> an original acceptance criterion, not an identity rebind.

**Acceptance criteria**

- [ ] Candidate execution has no daemon/code-host credentials, hidden evaluator material, writable daemon Git metadata, shared writable caches, raw claim/grant material reusable outside the trusted launcher, or network access.
- [ ] An existing Linux isolation mechanism supplies read-only source/input binds, a private writable overlay and temporary directory, and fixed CPU, memory, process, time, filesystem, and output limits; no custom sandbox runtime or pluggable backend is built.
- [ ] Candidate and evaluator launch specifications are distinct concrete policy types and cannot be substituted for one another. Candidate launch binds admitted instructions and inputs, exact scope/plan/work/attempt identities, source base, and `EffectGrant` limits.
- [ ] The runner owns a process group, bounds stdout/stderr, and kills and reaps descendants before cleaning or reusing a workspace.
- [ ] Trusted validation accepts only regular-file additions, changes, deletions, directories, and allowed executable-bit changes inside the declared write scope and count/size caps.
- [ ] Symlinks, hard links, special files, nested repositories, submodules, LFS pointers, normalization/case ambiguity, unsupported modes, and any out-of-scope path fail closed before or after generation.
- [ ] Trusted Git commands construct an immutable candidate from the exact validated bytes and record base OID, result tree OID, candidate commit OID, and bundle artifact digest. Any diff is re-derived from the raw base and result trees; no standalone delta digest is serialized.
- [ ] The immutable candidate `Observation` additionally binds campaign, scope, plan, work revision, `claim_fence`, attempt, applicable `EffectGrant`, producer, policy, and stable operation identity. Bundle artifact publication requires the grant; claim ownership alone is insufficient.
- [ ] Another machine reconstructs the exact candidate from the bundle and verifies its base, tree, commit, and artifact identities without trusting the generator's report.
- [ ] A fresh repair attempt receives a new attempt and candidate identity. Rebase support and rename detection are omitted from the MVP rather than mutating prior evidence.
- [ ] Timeout, cancellation, blocked-pipe, and descendant-process tests prove workspace cleanup occurs only after all candidate processes are reaped.

**Dependencies:** V2-P3 — Implement Recursive Admission; Establish the S3 Durable Log and Minimal Rust Runtime; Fix the Pilot and Experiment Contracts

**Priority:** 0

## E08 — Prove the Trusted Evaluation and Code-Host Path

**Description**

Use the selected code host's existing CI matrices, trusted runner labels, required
checks, and merge machinery as the primary distributed evaluation and integration path.
Retain only a thin trusted wrapper for hidden deterministic commands and a
publisher/reconciler for candidate refs, the single campaign branch, and the single
campaign PR.

Evaluator and code-host operations are admitted, claimable `WorkSpec` execution. Every
operation requires live claim authority and a matching `EffectGrant`. Their outputs are
immutable `Observation`s; only deterministic policy committed by the current scoped
controller can turn validated observations into a `Decision`. Evaluator execution
remains a separate trust domain from candidate generation. Ravel records exact
identities but does not build an evaluator plugin platform, custom queue, merge planner,
or second decision surface.

**Acceptance criteria**

- [ ] A fixed trusted evaluator configuration and exact-match capability labels route admitted evaluation work to trusted CI/runner jobs; capability advertisement is routing metadata, never authority. There is no capability scoring, dynamic plugin loading, arbitrary evaluator DAG, or model-authored manifest.
- [ ] Each evaluator run requires an admitted `WorkSpec`, live claim authority, and matching `EffectGrant`; it binds the exact campaign, scope, plan, work revision, `claim_fence`, attempt, candidate tree/commit, evaluator identity/version, trusted inputs, policy, and operation identity and yields an immutable `PASS`, `FAIL`, `ERROR`, or `TIMEOUT` observation.
- [ ] Hidden evaluator commands run with immutable hidden inputs, no model access, no network inside the evaluated subprocess, separate writable state, fixed resource/output limits, and process-group kill/reap semantics.
- [ ] Candidate write policy prevents changes to evaluator and workflow paths, and trusted code verifies those inputs before accepting an observation.
- [ ] Required heterogeneous checks can run on remote hosts through existing code-host CI or trusted self-hosted labels; deterministic failure cannot be overridden by semantic judges or model agreement.
- [ ] Trusted observation validation checks exact scope, plan, work revision, claim, grant, attempt, subject, evaluator, policy, inputs, and external identities. Mechanical policy derives the canonical scoped `Decision`; E08 introduces no separate evidence-admission or decision surface.
- [ ] Only trusted publisher workers hold code-host credentials. Publication requires an admitted integration `WorkSpec`, live claim authority, and matching `EffectGrant`; candidate refs, candidate commit SHA or campaign-branch head SHA, check-run identity, campaign branch, and campaign PR remain in immutable observations and scoped history.
- [ ] Branch push and PR create/update use deterministic external and operation identities and reconcile timeout/lost-response outcomes by reading code-host state before retrying.
- [ ] Accepted non-overlapping candidates can be applied serially to one campaign branch and one campaign PR only after integration work passes shared admission; a semantic accepted-for-integration decision alone is insufficient. Existing required checks and merge queue or auto-merge perform final integration.
- [ ] Fault tests cover evaluator timeout/crash, push success with lost response, duplicate PR request, stale check result, grant or claim loss before effect start, and publisher restart without duplicate authoritative integration.
- [ ] Publisher capability is advisory routing metadata, not a bearer capability. No cryptographic bearer capability, custom CI service, general code-host interface, custom merge queue, review UI, or per-candidate PR fan-out is built.

**Dependencies:** E07 — Isolate Candidates and Construct Immutable Git Artifacts; V2-P3 — Implement Recursive Admission

**Priority:** 0

## E09 — Prove the Distributed Change Campaign

**Description**

Implement the concrete Change campaign by composing trusted discovery, deterministic
grouping, isolated candidate construction, trusted evaluation, bounded semantic
judgment, and the existing code-host path. The migration is a finite proof workload,
not a generic planner.

Trusted discovery is a planning source, not a campaign type or separate authority
path. It publishes one immutable `Observation` and proposes bounded `ClaimSpec`s and
`WorkSpec`s in a `PlanRevision`. Deterministic admission is the only path that releases
work. The campaign uses fixed treatment assignment and deterministic
grouping. Targets are stably sorted and grouped only when their write scopes do not
overlap and the fixed size cap is respected. Unsupported targets remain explicit
`BLOCKED` or `UNRESOLVED` scoped decisions rather than triggering a classification or
adjudication subsystem. Child scopes are used only for admitted, bounded,
non-overlapping ownership.

**Acceptance criteria**

- [ ] Trusted discovery records source revision, rule identity/digest, stable target identity/location, context, and declared write scope for every target in one immutable, scope- and plan-bound `Observation`.
- [ ] Discovery proposes bounded `ClaimSpec`s and `WorkSpec`s through a `PlanRevision`; deterministic admission is the only path that releases executable work, and no direct discovery authority path is introduced.
- [ ] Ambiguous or unsupported targets become explicit `BLOCKED` or `UNRESOLVED` scoped decisions and are never silently omitted. The unresolved representation question is not answered by adding a canonical `terminal_decisions` field to `PlanRevision`.
- [ ] Fixed treatment assignment and deterministic grouping use stable order, non-overlapping write scopes, and a hard target-count cap; no autonomous target-classification taxonomy, judge-reviewed grouping, dependency planner, or general migration taxonomy is introduced.
- [ ] Several hosts claim admitted `WorkSpec`s and produce candidates concurrently against the exact source base OID and plan lineage using matching `EffectGrant`s and the candidate-isolation contract.
- [ ] Every candidate passes all required deterministic evidence before independent semantic judgment; mechanical failure always wins, and model/judge output remains an `Observation`.
- [ ] A rejected candidate observation may serve as typed proposal basis for at most one ordinary fresh retry `PlanRevision` with a new work revision, claim, attempt, and candidate identity. Semantic rejection never directly creates work; there is no generic repair planner or rebase path.
- [ ] Attempt completion, candidate identity, evaluation eligibility, semantic acceptance, and integration state remain separate and bind exact scope, plan, work revision, `claim_fence`, `scope_epoch` where a decision is committed, grant, subject, and policy identities.
- [ ] Accepted non-overlapping candidates are applied serially through admitted root integration `WorkSpec`s, live claims, matching `EffectGrant`s, one campaign branch, and one campaign PR, with ambiguous external outcomes reconciled before retry.
- [ ] Child scopes, when used, own only bounded non-overlapping target groups, seal before parent use, return verifier-bounded certificates, and settle idempotently. They do not directly integrate into the root branch.
- [ ] Every discovered target finishes as resolved, rejected, blocked, or unresolved, and final trusted rediscovery over the integrated source finds no unclassified legacy target. Root completion cannot exceed the final verifier's claim.
- [ ] The multi-host migration reaches its configured autonomous stopping condition without humans assigning targets, choosing ordinary candidates, or approving routine integration, and preserves escrow conservation and unknown reserve.
- [ ] The concrete Change module and Research share only demonstrated non-authority helpers. No workflow trait, DSL, profile framework, generic discovery interface, classification adjudicator, or port taxonomy is added.

**Dependencies:** E06 — Prove Bounded Distributed Research Decisions; E07 — Isolate Candidates and Construct Immutable Git Artifacts; E08 — Prove the Trusted Evaluation and Code-Host Path

**Priority:** 1

## E10 — Run the Precommitted MVP Feasibility Gate

**Description**

Run the two frozen precommitted three-treatment comparisons and issue one go/no-go
report. Reuse the
correctness, failure, distributed, and recursive proof artifacts produced by the
owning epics rather than recreating a cross-cutting recovery framework. Add one final
end-to-end multi-machine kill-and-recovery scenario showing that scoped heads, claims,
grants, observations, certificates, and settlement compose.

Analysis is offline and descriptive. Existing frozen Research and Change experiment
contracts, scoped campaign decisions, provider usage records, immutable traces,
evaluator results, and code-host records supply the measurements; the experiment must
not create a telemetry product or change its success definition after observing
results.

**Acceptance criteria**

- [ ] Research and Change each run the frozen single-agent, single-machine multi-agent, and distributed multi-machine treatments under the precommitted inputs, bounds, run counts, schedules, and success definitions.
- [ ] The distributed treatment uses at least three independent machines/VM hosts and includes a late join, active-worker loss, scoped-controller failover, remote model/judge/evaluator work, fresh scope-selective SQLite reconstruction, child certification where used, and settlement.
- [ ] One final end-to-end scenario kills an active worker and parent or child controller around an external unknown outcome, then demonstrates exact `ScopeHead` and scope-chain recovery, separate `scope_epoch` and `claim_fence` rejection, grant and operation reconciliation, certificate handling, idempotent settlement, conserved escrow, bounded recovery, and coherent completion or explicit unresolved state.
- [ ] Research reports wall time, supported/incorrect/omitted conclusions, useful evidence, discriminating follow-up, provider usage/cost, duplicate work, scope/grant overhead, settlement, quarantined unknown reserve, and scaling efficiency.
- [ ] Change reports resolved targets, omissions, semantic correction/rejection, conflicts, wasted work, usage/cost per target, utilization, scope/grant overhead, settlement, quarantined unknown reserve, scaling efficiency, and final rediscovery.
- [ ] Autonomous proof shows that humans supplied only objective/configuration or explicitly configured proposal observations and did not assign work, approve routine conclusions, choose ordinary candidates, mint grants, override admission, or perform routine safe-branch integration.
- [ ] Correctness evidence references the owning epic tests for frozen-v1 S3 ambiguity, SQLite atomic projection, and claim fencing and for scoped-v2 mixed-version rejection, selective replay, scope authority, scoped controller fencing, admission, grants, escrow, provider unknown outcomes, process cleanup, trusted evaluation, code-host reconciliation, certificates, and settlement.
- [ ] One small offline renderer emits CSV and Markdown with two fixed tables: Research and Change. No metrics service, dashboard, exporter framework, permanent baseline mode, adaptive reruns, or significance claim is added.
- [ ] The report gives a go/no-go recommendation and answers where distribution helped, where it stopped scaling, whether judge diversity and disagreement added value, what work was duplicated, and whether S3, scoped-controller, admission, settlement, or evaluator paths were bottlenecks.
- [ ] MVP completion is denied unless the section 43 invariants, recursive architecture gates, escrow equation, verifier-bounded completion, and actual multi-machine/failover requirements are demonstrated; a no-go result remains a valid completed feasibility experiment.

**Dependencies:** E06 — Prove Bounded Distributed Research Decisions; E09 — Prove the Distributed Change Campaign; V2-P3 — Implement Recursive Admission

**Priority:** 1
