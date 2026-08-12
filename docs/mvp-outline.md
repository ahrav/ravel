# Distributed Autonomous Engineering Campaign Runtime

## Working Plan and MVP Specification v0.2 — Scoped v2

> **Durable-version convention.** E01, E03, and E04 are complete frozen-v1 proof
> records; E02's frozen v1 code is complete while its selected-bucket live preflight
> (`ravel-aq8.7`) remains open and must close or be deferred on its own recorded
> evidence. Existing v1 event, head, claim, projection, artifact, key, encoding, and
> fixture bytes remain unchanged. Scoped v2 is a new durable boundary with new scope keys,
> identities, claims, projections, and `EventEnvelope`. A v2 campaign starts with a
> v2 root `Scope`; one authoritative chain never mixes v1 and v2 events.
>
> In every section that documents both versions, present the frozen-v1 record first
> and scoped v2 second. Reuse v1 algorithms through explicit v2 types and bindings;
> never reinterpret, rewrite, migrate, or silently route a v1 object through v2 code.

## 0. Executive summary

We are building a **distributed, local-first runtime for autonomous engineering campaigns**.

A user provides:

* An objective.
* Constraints.
* Available repositories, artifacts, and tools.
* A resource budget.
* An authority policy.

A transient fleet of machines can then collaboratively investigate the problem,
generate hypotheses and plans, produce code or other artifacts, run experiments and
deterministic evaluators, judge semantic results using multiple models or providers,
generate additional bounded work, challenge conclusions, integrate validated results,
and recover as machines join, disappear, crash, or reconnect.

The normal control loop is not human-driven.

```text
Generator, human, analyzer, or search policy proposes.
Oracle measures.
Judge interprets.
PlanRevision records the typed proposal basis.
Deterministic admission grants or rejects authority.
The current scoped controller commits the resulting Decision.
```

Generator, human, analyzer, search-policy, judge, and oracle outputs are immutable
`Observation`s or proposal sources. None is authoritative by itself. All authoritative
work, delegation, budget spend, and external effects enter through an admitted
`PlanRevision`; no workflow API bypasses that boundary.

A human may be a proposal source or emit an approval `Observation` required by campaign
policy at an explicitly configured boundary, such as merging to production or
increasing a large budget. Human output does not itself grant authority: it must be
referenced by typed `PlanRevision.proposal_basis` and pass deterministic admission.
The system must not depend on human review for routine planning, evaluation, research
synthesis, or candidate selection.

Scoped v2 keeps three independent structures:

* A rooted authority tree of `Scope` controllers, delegation grants, attenuated
  authority, escrow, completion certificates, and settlement.
* A versioned directed acyclic work graph of `ClaimSpec`s, `WorkSpec`s,
  dependencies, and `ChildScopeProposal`s within an admitted plan lineage.
* An append-only set of immutable observations, artifacts, evaluator results,
  model output, and external outcomes.

A `Campaign` identifies the root objective, immutable configuration, and root `Scope`.
A `WorkSpec` is the smallest claimable unit. A `ClaimSpec` is a semantic goal; a work
claim is fenced ownership of one exact `WorkSpec` revision. The authority tree, work
graph, and observation set do not collapse into one hierarchy.

Each machine remains local-first:

```text
Machine
  ├── scope-indexed local SQLite projection
  ├── local artifact cache
  ├── Rust campaign daemon
  ├── scoped-controller capability
  ├── worker and model runtimes
  ├── judge and evaluator/oracle runtimes
  ├── sandbox
  └── Git support
```

The scoped-v2 topology is distributed without a global sequencer:

```text
                         Shared object storage
          immutable plans, observations, artifacts, and scope logs
                                  |
                +-----------------+------------------+
                |                                    |
                v                                    v
        Root ScopeHead + log                 Child ScopeHead + log
        root scoped controller               child scoped controller
                |                                    |
        admitted WorkSpecs                  admitted WorkSpecs
        and DelegationGrants                and EffectGrants
                |                                    |
                +---------------+--------------------+
                                |
                    transient worker fleet
                                |
                 immutable Observations and
                 CompletionCertificates
```

One daemon may control several scopes, and independent scopes may advance concurrently.
Each scope nevertheless has one fenced decision authority, one `ScopeHead`, one ordered
decision stream, one `scope_epoch`, one active plan lineage, and one replay cursor. The
root handles child certificates and settlement; it does not sequence every leaf
transition.

The frozen-v1 record used one flat campaign controller and one campaign head:

```text
many concurrent workers
one lightweight campaign-level authoritative sequencer
```

That v1 event, head, claim, projection, artifact, key, encoding, and fixture behavior
remains unchanged for E01–E04. Scoped v2 starts at a new root `Scope` with new keys and
a new `EventEnvelope`. A v1 head never references a v2 event, a v2 `ScopeHead` never
references a v1 event, and no object is silently converted between them.

There is no permanent coordinator machine, PostgreSQL, DynamoDB, or distributed
consensus system in the MVP, and no requirement that every machine remain online.
Object storage is the shared durable synchronization and narrow coordination authority.
All expensive execution remains horizontally parallel.

The MVP proves the architecture with two concrete campaign protocols:

1. **Distributed Research** produces evidence-backed conclusions without requiring code
   changes.
2. **Distributed Change** performs a bounded semantic migration and exercises
   deterministic discovery, candidate generation, raw diff validation, trusted
   evaluation, and integration.

The migration is a proof protocol, not product ontology. The design avoids
building a large generic orchestration platform before proving the core behavior. The
equally important correction is that distribution itself is part of what we are trying
to prove.

---

# 1. Product thesis

The north-star product is:

> A distributed, local-first runtime for autonomous engineering campaigns in which a transient fleet of machines collaboratively investigates objectives, generates and evaluates work, challenges results, and converges on validated outputs.

An objective starts planning; it does not authorize execution. Fixed initial work
and environment-derived discoveries use the same path: a planner proposes an
immutable `PlanRevision` with typed `proposal_basis`, campaign-defined target
predicates and verifiers, bounded `WorkSpec`s or `ChildScopeProposal`s, dependencies,
required effects, failure states, and stop conditions. Deterministic admission is the
sole authority path.

Environment-derived work discovery is a planning source, not a campaign type and not
a separate authority path. Exact state equality is one possible verifier, not the
universal abstraction. A completion claim cannot exceed what its configured verifier
actually checks.

Examples of standalone campaigns:

```text
Research why cache lookup p99 spikes under skew.

Document the architecture and invariants of this subsystem.

Port this service from C++ to Rust.

Try to break this pull request.

Search for a faster cache-index design.
```

Examples of composed campaigns:

```text
Port service X from C++ to Rust.

Research
  -> establish behavioral contract
  -> Change
  -> Verify
  -> repair
  -> integrate
```

or:

```text
Reduce MediaCache lookup p99 by 30%
with <=10% memory growth and no correctness regression.

Research
  -> hypotheses
  -> Search
  -> Evaluate
  -> Verify
  -> mutate/combine
  -> Integrate
```

The eventual user should be able to state the objective rather than manually defining
that sequence. Concrete campaign policy and deterministic admission make each bounded
step explicit without introducing a workflow DSL.

---

# 2. Core architectural principles

## 2.1 Agents are never authoritative by declaration

A model, human, analyzer, or search policy may produce:

* A semantic claim or work proposal.
* A candidate or hypothesis.
* A test, reproducer, or document.
* A proposed plan revision or decision.
* A suggested delegation or external operation.

The output is an immutable `Observation` or proposal source. It does not become
authoritative because its producer says it is correct, important, high-confidence, or
valuable. It becomes relevant to authority only as a typed `proposal_basis` reference
in a `PlanRevision` that passes deterministic admission.

Do not use proposer-supplied scalar fields such as:

```text
confidence = 0.95
expected_value = high
severity = critical
```

as decision authority. Model or human agreement cannot override an admission failure.

---

## 2.2 Separate generators, judges, oracles, and scoped controllers

### Generator

Creates novel output such as findings, hypotheses, plans, code, tests, documents, and
candidate counterexamples. A generator may be a model, human, deterministic analyzer,
or search policy. Its output is an `Observation` or proposal source, never authority.

### Judge

Makes a semantic assessment:

* Is this conclusion supported?
* Does this candidate satisfy the requested contract?
* Are two proposals materially duplicates?
* Is a missing concern important?
* Which explanation best fits the evidence?

A judge result is an immutable `Observation`. It cannot release work, mint a grant,
spend budget, or commit a `Decision`.

### Oracle

Produces externally grounded observations through compilers, tests, differential
harnesses, fuzzers, sanitizers, static analyzers, AST queries, Git, benchmarks, traces,
or model checkers. Whenever an oracle can resolve a question, use it rather than
another model. Oracle output is still an `Observation`; campaign policy defines the
claim its verifier can establish.

### Scoped controller

Applies deterministic campaign policy to the active plan lineage, immutable
observations, budgets, semantic goals, dependencies, grants, and external state. Only
the current fenced controller for a `Scope` commits that scope's `Decision`s. It does
not gain authority from model output or presence, and a parent cannot append to a live
child's decision log.

The controller is primarily policy and state-machine code, not one large manager-model
prompt. Deterministic admission remains the sole entry to authoritative work,
delegation, budget spend, and external effects.

---

## 2.3 Deterministic evidence outranks model consensus

This is a daemon-level rule.

```text
2 judge Observations: ACCEPT
1 judge Observation: concrete race reproducer

independent oracle executes reproducer
    -> race confirmed

scoped Decision:
    REJECT
```

Not:

```text
2 votes to 1 => ACCEPT
```

Likewise:

```text
trusted test FAIL
3 model judges PASS

scoped Decision:
    REJECT
```

Model diversity helps reveal different interpretations. It does not turn majority
voting into ground truth. Deterministic contrary evidence cannot be overruled by model,
human, or analyzer agreement.

---

## 2.4 Work completion, result acceptance, and integration are separate

A claimed `WorkSpec` attempt can finish and return structurally valid output while its
candidate fails evaluation. A candidate can pass evaluation while failing integration.
A research worker can complete its investigation while its conclusion is rejected by
scoped policy.

Attempts, immutable observations, semantic acceptance `Decision`s, integration work,
completion certificates, and settlement remain separate records and transitions. They
must never collapse into one `Done` bit.

---

## 2.5 Validation is a projection over immutable observations

Do not persist:

```text
candidate.validated = true
```

Persist an immutable observation bound to:

```text
campaign_id
scope_id
plan_digest
work_id
work_revision
claim_fence
attempt identity
subject identity
producer identity
evaluator or policy identity
inputs and configuration digests
outcome
stable operation identity when an external effect occurred
```

Then derive whether the subject is currently acceptable under the active plan lineage,
campaign-defined verifier contract, and deterministic policy. A replan, rebase,
evaluator change, policy change, or new counterexample can invalidate applicability
without rewriting history.

A `proposal_basis` reference records provenance. It does not establish the referenced
claim. Old observations can inform a new plan, but they satisfy work only when their
exact bindings and verifier remain applicable.

---

## 2.6 No replay of external side effects

A frozen-v1 event log reconstructs frozen-v1 campaign state. A scoped-v2 decision log
reconstructs one scope's authority state. Neither replays model calls, shell commands,
Git pushes, external API calls, evaluator jobs, or build processes.

Every external side effect requires all three:

```text
an admitted WorkSpec revision
live claim authority for that WorkSpec revision
a matching EffectGrant
```

The trusted launcher validates the three together and uses a stable operation identity.
Attempts are retried explicitly. Ambiguous outcomes are reconciled by reading the
external authority before retry. Cancellation stops local waiting but does not assert
that the remote operation stopped. Unknown outcomes remain explicit and their reserve
stays unavailable.

---

## 2.7 Protocol semantics stay outside the kernel

The scoped-v2 kernel authority vocabulary is limited to:

```text
Campaign
Scope
PlanRevision
ClaimSpec
WorkSpec
ChildScopeProposal
DelegationGrant
EffectGrant
Observation
Decision
CompletionCertificate
Settlement
```

`ClaimSpec` is a versioned semantic goal. A work claim is fenced ownership of one exact
`WorkSpec` revision. `scope_epoch` fences scoped decisions; `claim_fence` fences
ownership and submission for one `WorkSpec` revision. `EffectGrant` authorizes one
bounded external operation, `DelegationGrant` creates one bounded child authority and
escrow domain, and `Observation` is never authority.

`Attempt` remains an execution record and `Artifact` remains immutable
content-addressed storage. Neither is a separate authority path.

Protocol-specific concepts remain outside the kernel:

```text
Research:
  Finding
  ResearchClaimObservation
  Evidence
  Question

Change:
  Target
  Candidate
  CheckResult

Search:
  Hypothesis
  CandidateLineage
  Measurement
  Selection

Verify:
  Challenge
  Counterexample

Document:
  SourceSet
  CoverageResult
```

Scoped v2 has no universal `WorkflowInstance` or `WorkItem` authority object.
Concrete protocol state remains outside the kernel, and claimable v2 work is
represented by `WorkSpec`.

The frozen-v1 `WorkItem` remains documented separately as a shipped v1 record.
Promote no additional concept into the kernel without demonstrated reuse. In particular,
do not introduce workflow traits or DSLs, campaign profiles, a generic discovery
interface, a curriculum engine, online model training, learned reward policies, a
universal state matcher, unbounded task generation, arbitrary live reparenting,
multiple authority parents, CRDTs or gossip for correctness, automatic repartitioning,
learned placement, or cryptographic bearer capabilities.

---

# 3. MVP boundaries

## 3.1 In scope

The MVP includes:

* Multiple actual machines, including late join and disappearance during active work.
* Amazon S3 shared authority and disposable local SQLite on every machine.
* The frozen-v1 E01–E04 event, head, claim, projection, artifact, key,
  encoding, and fixture record, unchanged.
* A separate scoped-v2 durable boundary with no mixed-version authoritative chain.
* The exact scoped-v2 identity axis:

  ```text
  campaign_id
  scope_id
  parent_scope_id
  delegation_digest
  plan_digest
  work_id
  work_revision
  claim_fence
  scope_epoch
  ```

* The exact scoped-v2 envelope:

  ```text
  EventEnvelope {
      envelope_version
      scope_id
      sequence
      parent_event
      writer_epoch
      operation_id
      payload_type
      payload_version
  }
  ```

* Per-scope `ScopeHead`s, ordered decision streams, active plan lineages, claims,
  projections, replay cursors, selective replay, controller failover, and independent
  parent/child recovery.
* Immutable content-addressed `PlanRevision`s with typed `proposal_basis` and one
  deterministic admission path for fixed initial and observation-derived work.
* Campaign-defined target predicates and verifier-bounded completion claims.
* Fenced `WorkSpec` claims, same-key submission, and stale-result rejection.
* `DelegationGrant`s, attenuated child authority, atomic escrow debit, and bounded
  `EffectGrant`s for every external operation.
* Bottom-up child sealing, `CompletionCertificate`s, idempotent `Settlement`, explicit
  quarantined unknown reserve, and escrow conservation.
* Finite campaign-configured fanout, attempts, follow-ups, deadlines, effects,
  resources, and spend.
* Scope depth exactly two for the MVP: the root is depth 1, a direct child is depth 2,
  and grandchildren are forbidden.
* Multi-provider generators and judges through two fixed internal adapters.
* Deterministic oracle execution, crash recovery, budget enforcement, safe candidate
  execution, Git integration, and existing code-host CI and merge machinery.
* Two concrete campaign protocols: Distributed Research and Distributed Change.

---

## 3.2 Explicitly deferred

Do not initially implement:

* P2P networking.
* CRDTs or gossip for correctness.
* Multiple writers or concurrent controller authorities for one `ScopeHead`.
  Independent scopes may advance concurrently, but each scope retains one fenced
  decision authority.
* Raft or Paxos.
* PostgreSQL or DynamoDB.
* Cross-region campaigns.
* Statistical performance search or large evolutionary populations.
* Workflow traits, workflow DSLs, or arbitrary user-defined workflow languages.
* Campaign profiles, profile registries, or profile-based authority.
* Curriculum engines, online model training, or learned reward policies.
* Universal state matchers.
* Unbounded task generation or completely open-ended recursive campaign generation.
* Generic discovery interfaces.
* Arbitrary live scope reparenting or multiple authority parents.
* Automatic repartitioning or learned placement.
* Cryptographic bearer capabilities.
* Generic graph databases.
* Custom merge queues or custom code-review UIs.
* Automatic learned model routing.
* Hostile multi-tenant execution.
* Deeper-than-two scope trees.

P2P and CRDTs remain possible later, but neither participates in correctness or
authority. Fixed model configuration identifiers and digests are retained for exact
replay; they do not create a campaign-profile system.

---

# 4. Distributed topology

Every node runs the same Rust binary.

```text
ravel node
  |
  +-- scope-selective sync engine
  +-- scope-indexed SQLite projector
  +-- scoped-controller capability
  +-- worker scheduler
  +-- model runner
  +-- judge runner
  +-- oracle/evaluator runner
  +-- sandbox
  +-- Git support
  +-- artifact cache
```

One daemon may control several scopes, but each scope has its own `ScopeHead`,
`scope_epoch`, ordered decision stream, active plan lineage, and replay cursor.
Advertised controller, worker, model, evaluator, hardware, or publisher capability is
only a routing signal. Presence and capability advertisements grant no authority.

A node can advertise only the capabilities it actually supports.

Example:

```json
{
  "actor_id": "linux-perf-worker",
  "instance_id": "boot-019a...",
  "capabilities": [
    "linux",
    "x86_64",
    "rust",
    "perf",
    "git",
    "model:openai",
    "judge:anthropic"
  ]
}
```

Another machine might advertise:

```text
macos
aarch64
xcode
model:google
```

Another may be primarily a judge runner. No machine has to implement every role.
Independent scopes may advance on different machines; each scope still has exactly one
fenced decision authority at a time.

---

# 5. Durable object-store substrate

## 5.1 MVP backend

> **Frozen-v1 substrate retained.** E02's S3 conditional-write boundary and all current
> S3 requirements below remain unchanged. Scoped v2 reuses those algorithms through
> separate version-specific keys, bytes, and types.

Use Amazon S3 for the first implementation.

Do not prematurely promise equivalent coordination semantics across:

* Git.
* WebDAV.
* Generic S3-compatible stores.
* R2.
* Arbitrary object stores.

The correctness boundary depends on strong conditional writes.

Backend generalization comes later through explicit capability testing.

---

## 5.2 Object layout

### Frozen-v1 layout

The shipped v1 conceptual layout remains:

```text
workspace/{workspace_id}/

  membership/
    actors/{actor_id}.json

  presence/
    {actor_id}/{instance_id}.json

  campaigns/{campaign_id}/

    controller.json

    head.json

    events/
      0000000000000001-{digest}.cbor.zst
      0000000000000002-{digest}.cbor.zst
      ...

    work/
      {work_id}/claim.json

    submissions/
      {attempt_id}.json

    artifacts/
      sha256/{digest}

    checkpoints/
      {checkpoint_digest}
```

The existing v1 keys, suffixes, canonical bytes, compression, digest encoding, and
fixtures are frozen. They are not changed by the scoped-v2 layout.

### Scoped-v2 layout

Scoped v2 uses this separate key axis:

```text
workspace/{workspace_id}/campaigns/{campaign_id}/
  scopes/{scope_id}/head
  scopes/{scope_id}/events/...
  scopes/{scope_id}/claims/{work_id}/{work_revision}
  plans/{plan_digest}
  artifacts/{digest}
```

The scoped-v2 durable identity axis is:

```text
campaign_id
scope_id
parent_scope_id
delegation_digest
plan_digest
work_id
work_revision
claim_fence
scope_epoch
```

Fields are required only where the represented object has that relationship; omission
never aliases a different identity.

The exact v2 event-key suffix, canonical serialization, compression, digest algorithm
and textual encoding, plan bytes, artifact media-type rules, and serialized
`ScopeHead` form remain open contract questions. The implementation must settle them
before shipping v2 bytes and must not infer them from v1.

A v2 key never reinterprets a v1 object. A v2 `ScopeHead` cannot reference a v1 event,
and a v1 campaign head cannot reference a v2 event. Future durable changes require a
new explicit version rather than reinterpretation or silent migration.

---

# 6. Campaign event log

## 6.1 Frozen-v1 campaign event log

> **Frozen v1 record — E02.** The campaign-level event/head format, canonical bytes,
> publication algorithm, operation reconciliation, and fixtures below remain unchanged.
> This is not the scoped-v2 decision chain.

The authoritative campaign history is append-oriented.

An event might represent:

```text
CampaignCreated
WorkflowStarted
WorkCreated
WorkCancelled
AttemptAccepted
EvaluationRecorded
JudgmentRecorded
DecisionRecorded
WorkflowCompleted
CampaignCompleted
```

The global head contains:

```text
sequence
tail event digest
controller fence
operation ID
```

Commit protocol:

1. Controller constructs event `N+1`.
2. Upload immutable event object using create-if-absent.
3. CAS `head.json` using the previously observed ETag.
4. If the response is ambiguous, reread `head.json`.
5. Determine whether the operation ID committed.
6. Retry only if known safe.

Workers do not directly contend on the global campaign head.

That is important.

Workers publish immutable submissions.

The active controller validates those submissions and sequences them into authoritative campaign events.

This gives us:

```text
many concurrent workers
one lightweight authoritative sequencer
```

without requiring consensus for every campaign transition.

## 6.2 Scoped-v2 scope decision logs

A v2 campaign starts with a v2 root scope. Each scope owns one `ScopeHead`, one
ordered decision stream, one `scope_epoch`, one active plan lineage, and one replay
cursor. Independent scopes do not share a mutable head or sequence.

Every v2 event uses:

```text
EventEnvelope {
    envelope_version
    scope_id
    sequence
    parent_event
    writer_epoch
    operation_id
    payload_type
    payload_version
}
```

`writer_epoch` is the committing scope's current `scope_epoch`. Envelope version and
payload version are independent.

The durable authority state for a scope binds:

```text
campaign_id
scope_id
controller_instance_id
scope_epoch
lease_until
sequence
tail_event_digest
active_plan_digest
operation_id
```

Child genesis additionally binds `parent_scope_id` and `delegation_digest`.

Scoped commit protocol:

1. The current scoped controller constructs event `N+1` with the exact parent event,
   current `scope_epoch`, stable `operation_id`, and canonical payload bytes.
2. It creates the immutable event object with create-if-absent semantics.
3. It conditionally replaces the exact observed `ScopeHead`, validating owner, epoch,
   sequence, parent tail, and active plan lineage in the same CAS domain.
4. If the response is ambiguous, it rereads the `ScopeHead` and, when necessary, the
   retained parent chain to locate the stable operation identity.
5. It retries only when the outcome is known safe.

Workers publish immutable observations and same-key sealed work submissions. They do
not commit scoped decisions or write `ScopeHead`s. A parent cannot append to a live
child's decision stream.

A v2 `ScopeHead` never references a v1 event, and a v1 campaign head never references
a v2 event.

The exact event-key suffix and canonical encoding remain open. The serialized
`ScopeHead`, root-scope genesis event and CAS protocol, root `scope_id` derivation,
initial `scope_epoch`, initial plan reference, and child-genesis byte representation
also remain open contract questions. No v2 durable bytes ship until those forms are
fixed and covered by positive and cross-version negative fixtures.

---

# 7. Scoped controller authority

## 7.1 Controller is a role, not a host

Exactly one controller instance holds decision authority for one `Scope` at a time.
One daemon may hold authority for several independent scopes, but each authority is
acquired, renewed, recovered, and fenced separately through that scope's `ScopeHead`.

Conceptually, the head binds:

```text
campaign_id
scope_id
controller_instance_id
scope_epoch
lease_until
sequence
tail_event_digest
active_plan_digest
operation_id
```

If Machine A disappears while controlling one scope:

```text
scope lease expires
Machine C reads and verifies the exact ScopeHead and active plan lineage
Machine C acquires a higher scope_epoch on that same ScopeHead
Machine C resumes scoped decisions
```

The scope does not depend on A returning. Parent and child controllers may run on
separate machines and fail or recover independently. Presence and placement signals do
not grant authority.

The exact serialized `ScopeHead` and root genesis forms remain open as recorded in
section 6.2.

---

## 7.2 Fencing

All authoritative scoped decisions carry the committing `scope_epoch`. Acquisition,
renewal, takeover, and decision publication conditionally replace the same observed
`ScopeHead`; controller ownership cannot race event publication through a separate CAS
domain.

A stale controller at epoch 42 cannot commit after epoch 43 wins, even if it retains an
older ETag or local projection. Before its first decision, a replacement rebuilds and
verifies the selected scope to the exact freshly read head and active plan lineage.

`scope_epoch` fences decisions. `claim_fence` separately fences ownership and submission
for one exact `WorkSpec` revision. Neither substitutes for the other. Lease time is a
liveness mechanism; conservative durations and synchronized clocks do not make clock
precision a correctness assumption.

---

## 7.3 Controller responsibilities

The scoped controller applies deterministic policy to answer:

```text
What semantic claims remain unresolved?
Which admitted WorkSpec revisions are ready?
Which submitted observations have exact current bindings?
Which evaluations are required by campaign-defined verifiers?
Are semantic judgments sufficient under evidence precedence?
Is there material disagreement that may justify a bounded plan revision?
Can another oracle resolve it?
Should a candidate advance?
May a ChildScopeProposal be admitted under current bounds and escrow?
Can a child certificate be accepted without upgrading its claims?
Can settlement proceed idempotently?
Has the scope reached verifier-bounded completion?
Has the scope or campaign exhausted a hard budget?
```

The controller does not execute expensive work and does not directly create work,
delegation, budget spend, or effects. Generative policy may propose a `PlanRevision`;
deterministic admission is the sole path that releases `WorkSpec`s, creates child
authority, debits escrow, or issues `EffectGrant`s. The current fenced controller then
commits the resulting `Decision`.

---

## 7.4 Scope lifecycle, delegation, and settlement pressure

Child scope lifecycle:

```text
PENDING -> ACTIVE -> DRAINING -> SEALED
                    \-> RECOVERING -> SEALED
```

Parent delegation lifecycle:

```text
COMMITTED -> ACTIVE -> SETTLEMENT_PENDING -> SETTLED
                     \-> EXPIRED_PENDING -> SETTLED
```

A parent atomically commits one `DelegationGrant` and escrow debit before child genesis
can reference that grant. A child grant can only attenuate parent capability, write
scope, deadline, budget, effects, and resources. Root depth is 1, a direct child is
depth 2, and grandchildren are rejected in the MVP.

Cancellation is a drain, not an undo:

* It blocks new work and effect admission.
* Existing effect grants retain their original deadlines.
* The supervisor stops local waits and reconciles remote outcomes.
* A drain timeout cannot extend authority.
* Children seal bottom-up.

A sealed child presents a verifier-bounded `CompletionCertificate` that conceptually
contains:

```text
scope_id
delegation_digest
plan_digest
terminal_head_digest
decision_policy_digest
supported_claims
unresolved_claims
evidence_root
confirmed_spend
returned_budget
unknown_reserve
```

Parent policy may accept supported claims only within the certificate's verifier
limits; required unresolved claims block their exact dependents. Settlement is
idempotent and cannot create evidence or budget. It conserves:

```text
escrowed = confirmed_spend + returned + quarantined_unknown
```

Unknown reserve remains unavailable. Only a root `QuarantineResolved` decision based
on an authoritative external outcome may reclassify root unknown reserve. A root may
reach semantic completion while accounting remains open; whichever root-completion
representation is selected must report that unknown reserve. After completion the root
accepts only reconciliation and accounting decisions.

Takeover demand comes from:

* Pending decisions or observations.
* Ordinary work-routing demand.
* Cancellation or drain progress.
* A parent blocked on an expired, unsettled child, represented to the authority layer
  as `SETTLEMENT_PRESSURE`.

The scoped-authority layer owns the generic takeover-demand mechanism and its
`SETTLEMENT_PRESSURE` reason. Recursive admission owns delegation, escrow,
certificates, settlement policy, and the end-to-end settlement transition.

The exact `CompletionCertificate` and `Settlement` payloads remain open. So do
cross-scope observation visibility, whether certificate acceptance and settlement are
one atomic decision or ordered independently idempotent records, and whether root
completion uses an optional-delegation certificate, a distinct root certificate, or a
`Decision` plus accounting record. Until those questions are settled, E05 tests only
an injected settlement-pressure reason; recursive admission owns the live
expired/unsettled proof.

---

# 8. Work model

## 8.1 Frozen-v1 WorkItem record

> **Frozen v1 record — E04.** The `WorkItem` shape below is retained for the shipped
> v1 claim and projection proof. Do not add scope, plan, grant, or v2 fields to this
> structure or its fixtures.

A universal `WorkItem` remains intentionally small.

```rust
struct WorkItem {
    id: WorkId,
    workflow_id: WorkflowId,
    revision: u64,

    instructions: ArtifactRef,
    inputs: Vec<RecordRef>,

    dependencies: Vec<WorkId>,
    required_capabilities: Vec<Capability>,

    execution_profile: ExecutionProfile,
    budget: Budget,

    write_policy: Option<WritePolicy>,
}
```

Protocol-specific behavior determines what the work means.

Examples:

```text
Research:
  Characterize lock contention.

Change:
  Port these five target sites.

Search:
  Produce another implementation of hypothesis H7.

Verify:
  Attempt to falsify cancellation safety.
```

## 8.2 Scoped-v2 planning and work model

Scoped v2 separates semantic goals, claimable execution, and delegation proposals.

```text
PlanRevision {
    scope_id
    parent_plan_digest
    proposal_basis
    claim_specs
    work_specs
    child_scope_proposals
    dependencies
    bounds
}
```

A `PlanRevision` is immutable and content-addressed by `plan_digest`. It proposes the
next bounded changes to the current scope's work graph. Deterministic admission is the
sole path that makes any proposed work, delegation, budget spend, or external effect
authoritative.

Admission validates proposal-basis existence, type, visibility, scope, and current
bindings; exact scope and parent-plan lineage; dependency existence and acyclicity;
stable identities; finite depth, fanout, attempts, deadlines, effects, and resource
bounds; budget availability and child escrow; grant attenuation; write and capability
containment; and campaign-specific deterministic rules. Model, human, analyzer,
discovery, search-policy, judge, evaluator, and publisher output cannot override a
failure.

A `ClaimSpec` describes a versioned semantic goal and its campaign-defined target
predicate and verifier contract. A `WorkSpec` is one bounded, claimable execution
revision. It carries or references its exact instructions, inputs, dependencies,
required capabilities, source or subject identity, write scope, deadline, effect and
resource bounds, and verifier requirements. A `ChildScopeProposal` proposes a bounded
delegation; it is not a child scope or grant until parent admission succeeds.

Every authoritative v2 work identity binds:

```text
campaign_id
scope_id
plan_digest
work_id
work_revision
```

Work claims add `claim_fence`. Scoped decisions add `scope_epoch`. Child work also
binds `parent_scope_id` and `delegation_digest`.

Each admitted revision names its parent and supersedes that predecessor for planning.
It does not rewrite old observations, attempts, work revisions, or claims.
Applicability is derived from the current plan lineage and exact bindings.

The serialized `ClaimSpec`, `WorkSpec`, `ChildScopeProposal`, `DelegationGrant`,
`EffectGrant`, `Decision`, `CompletionCertificate`, and `Settlement` layouts remain
open contract questions. Plan supersession also remains conservative: validity and
drain rules for unclaimed work, live claims, unexpired grants, and in-flight operations
must be specified before supersession is enabled. No current authority is silently
revoked or extended by an unspecified rule.

---

# 9. Distributed work claiming

> **Frozen v1 record — E04.** The following claim and disappearance record remains
> unchanged for the shipped v1 same-key claim proof. Scoped-v2 claims are separate.

Workers compute eligible work from their local SQLite projection.

```text
SELECT ready work
WHERE dependencies satisfied
AND capabilities match local worker
AND budget allows execution
```

Then attempt an authoritative remote claim.

Claim object:

```json
{
  "work_id": "W17",
  "work_revision": 4,
  "owner_actor": "agent-rust",
  "owner_instance": "machine-b/boot-019b",
  "fence": 9,
  "lease_until": "...",
  "operation_id": "..."
}
```

Claim protocol:

1. Read existing claim.
2. Confirm absent or reclaimable.
3. Increment fence.
4. CAS using `If-Match`, or create via `If-None-Match`.
5. Only the successful claimant executes.

Renewal uses another CAS.

---

> **Frozen v1 record — E04.** The claim below uses the shipped v1 claim key,
> identity, fence, lease, and same-key CAS behavior. It is not a scoped-v2 claim.

## 9.1 Worker disappearance

> **Frozen v1 example.** This disappearance and reclamation behavior remains unchanged.

Example:

```text
Machine B claims W17, fence 9.
Machine B starts work.
Machine B loses power.

Lease expires.

Machine D acquires W17, fence 10.
Machine D completes.

Machine B eventually returns and submits fence 9 result.

Controller rejects it as authoritative.
```

The stale result can remain as an artifact if useful, but it cannot complete W17.

## 9.2 Scoped-v2 work claims and worker disappearance

Workers compute eligible `WorkSpec` revisions from a verified scope-indexed projection,
then claim the exact scoped-v2 key:

```text
workspace/{workspace_id}/campaigns/{campaign_id}/
  scopes/{scope_id}/claims/{work_id}/{work_revision}
```

Every claim and sealed submission binds:

```text
campaign_id
scope_id
plan_digest
work_id
work_revision
claim_fence
owner_actor
owner_instance
lease_until
operation_id
```

Claim acquisition, renewal, reclamation, and completion use create-if-absent or
conditional replacement on that same key. Successful acquisition yields an opaque
`ClaimAuthority`; internal execute and submit APIs do not accept worker-supplied raw
identifiers as authority. Completion CASes `ACTIVE(claim_fence)` to a sealed submission,
so reclamation and completion race on the same ETag.

A worker that loses ownership may still publish an immutable late observation, but the
observation cannot complete the `WorkSpec` or authorize a new effect. The current
scoped controller accepts a sealed submission only when campaign, scope, plan, work
revision, `claim_fence`, attempt, subject, and policy bindings match. An unexpired claim
remains valid across scope-controller takeover.

A work claim authorizes ownership of one `WorkSpec` revision. It does not authorize a
scoped `Decision` or an external effect. Before any model, evaluator, sandbox, Git, or
code-host operation starts, the trusted launcher jointly validates the admitted
`WorkSpec`, live `ClaimAuthority`, and matching `EffectGrant`.

The exact `EffectGrant` binding to `claim_fence` and attempt identity, and the rule that
makes a grant unusable after claim reclamation, remain open contract questions. The
grant schema must resolve them before external effects can ship; an old worker must
never start a new external effect after losing ownership.

---

# 10. Machine identity and presence

> **Shared frozen-v1 identity record.** E04's stable actor identity, ephemeral instance
> identity, and advisory-presence behavior remain unchanged. Scoped v2 adds exact scope,
> plan, work revision, and fence bindings where authority requires them.

Each node has:

### Stable actor identity

Represents the logical participant:

```text
rust-worker
research-agent
linux-perf-pool
```

### Ephemeral instance identity

Generated on every node/process incarnation:

```text
machine-b/boot-019b...
```

Claims bind to both.

---

## 10.1 Presence is advisory

> **Shared frozen-v1 behavior.** Stable actor identity, per-start instance identity,
> and advisory presence remain valid in scoped v2. They gain no scope authority.

Presence records include:

```text
capabilities
resource capacity
current load
last heartbeat
expiry
```

They help:

* Estimate fleet capacity.
* Prefer available machines.
* Route hardware-specific tasks.
* Show status.

Presence never establishes ownership.

A stale presence record may reduce scheduling efficiency but must not violate correctness.

---

Presence, advertised capability, hardware labels, and publisher labels are routing
signals only. They do not create a `Scope`, acquire a `ScopeHead`, claim a `WorkSpec`,
mint a grant, authorize an external effect, or establish a result. Missing or stale
presence may reduce efficiency but cannot block correctness or recovery.

---

# 11. Local SQLite projection

## 11.1 Frozen-v1 projection

> **Frozen v1 record — E03.** The single-chain schema, cursor, transactional apply,
> rebuild, and equivalence fixtures below remain unchanged.

Every node maintains its own database.

Never synchronize SQLite files.

SQLite stores projections such as:

```text
campaigns
objectives
workflows
work_items
dependencies
attempts
evaluations
judgments
decisions
sync_cursor
artifact_metadata
worker_presence
```

Protocol modules add their own tables.

For example:

```text
research_findings
research_evidence

change_targets
change_candidates
change_checks
```

The sync engine:

1. Reads current campaign head.
2. Downloads unseen immutable events.
3. Verifies digest chain/order.
4. Applies events transactionally to SQLite.
5. Advances local cursor.

Application queries are local.

S3 is not queried for ordinary task-graph reads.

## 11.2 Scoped-v2 projections

Scoped v2 adds scope-indexed tables and cursors beside the frozen-v1 projection.
SQLite remains disposable and contains no uniquely durable authority.

Each projected scope records:

```text
campaign_id
scope_id
parent_scope_id
delegation_digest
verified sequence
verified tail_event_digest
active plan_digest
scope_epoch
readiness state
```

The sync engine:

1. Reads the exact selected `ScopeHead`.
2. Traverses that scope's immutable parent chain without treating `LIST` as a
   publication snapshot.
3. Validates envelope version, payload version, scope binding, sequence, parent digest,
   `writer_epoch`, operation identity, and canonical bytes before apply.
4. Applies one event and advances that scope's cursor atomically.
5. Reports readiness only when the verified cursor matches the freshly read
   `ScopeHead`.

A gap, mixed-version parent, wrong-scope event, unknown version, digest conflict, or
conversion failure leaves the affected scope projection and cursor unchanged and fails
that scope's readiness closed. It does not invalidate an independent scope.

Scoped projections support:

* Scope-selective replay.
* Bounded-subtree scheduling queries.
* Scope-indexed ready-`WorkSpec` queries.
* Lazy global views.
* Certificate-based ancestor rollups.
* On-demand loading of archived scope history.

Certificates reduce ancestor projection work but never replace durable child history.
There is no global mutable replay cursor.

Cross-scope observation visibility remains an open contract question: the amendment
does not assume that a parent may cite every child observation directly or that a
certificate is the only evidence boundary. Visibility rules must be fixed before typed
`proposal_basis` admission spans scopes.

---

# 12. Artifact model

Large or durable outputs are immutable content-addressed artifacts.

Examples:

```text
source snapshots
Git bundles
patches
model traces
research reports
perf traces
flamegraphs
test logs
benchmark output
reproducers
corpora
documents
```

Each artifact has:

```text
digest
size
media type
producer attempt
creation time
optional retention class
```

Local nodes cache artifacts by digest.

Remote object storage is durable authority.

---

The frozen-v1 artifact path remains `artifacts/sha256/{digest}`. Scoped v2 uses the
campaign-relative `artifacts/{digest}` key from section 5.2. Both remain immutable,
content-addressed, and fully verified before use. A path or artifact reference is not
authority by itself.

The scoped-v2 plan and artifact digest algorithm, algorithm tag, textual encoding,
canonical bytes, compression, and media-type rules remain open contract questions and
must be fixed before the corresponding keys ship.

## 12.1 RunManifest and RunTrace

Every generator, judge, evaluator, candidate, publisher, or other external invocation
records two separate immutable artifacts.

### RunManifest

The manifest freezes starting authority and configuration:

```text
campaign_id
scope_id
parent_scope_id and delegation_digest when applicable
plan_digest
work_id
work_revision
claim_fence
attempt identity
effect_grant_digest
stable request and operation identity
provider or executor identity
exact model identifier when applicable
exact fixed model configuration identifier and digest
prompt and tool-schema digests
source, subject, and candidate identities
context and input artifact digests
environment and trusted-policy digests
network and filesystem policy
resource, effect, deadline, and budget limits
campaign-defined verifier identity
```

For Git candidates, identity remains the base OID, result tree OID, candidate commit
OID, and bundle artifact digest. A validator may re-derive the raw base/result-tree
diff, but neither the manifest nor an observation adds a standalone delta digest.

### RunTrace

The trace records the dynamic trajectory:

```text
messages
tool calls and results
retrievals
shell commands
outputs and truncations
policy denials
provider or external request IDs
reported token or resource use
reported cost
errors
known terminal outcome or explicit unknown outcome
reconciliation observations
```

Initial context and dynamic trajectory remain different artifacts. Reported usage is
not confirmed spend until authoritative reconciliation. A manifest or trace is an
immutable `Observation` input, not authority to execute, accept, or settle work.

---

# 13. Model-provider layer

The MVP supports exactly the two selected providers through internal concrete adapters,
preferably a closed enum. It does not expose a public provider SDK, `dyn` async
provider trait, profile registry, generic agent harness, or campaign-profile system.

A model invocation is an external effect. Before provider contact, the node must have:

```text
an admitted WorkSpec revision
a live ClaimAuthority for that WorkSpec revision
a matching scope-derived EffectGrant
a stable request and operation identity
a persisted RunManifest
a scope-local InvocationStarted decision
```

Required immutable metadata includes:

```text
campaign_id
scope_id
plan_digest
work_id
work_revision
claim_fence
attempt identity
effect_grant_digest
provider
exact model identifier
exact fixed model configuration identifier and digest
system-prompt digest
tool-schema version
context digest
provider request ID
stable operation ID
reported token or resource use
reported cost
known terminal outcome or explicit unknown outcome
```

Provider output is an `Observation` or proposal source. It cannot accept work, create
follow-up work, mint a grant, spend budget, settle accounting, or commit a decision.

Cancellation stops local waiting but does not assert that the remote operation stopped.
Late responses and lost responses reconcile by stable provider request and operation
identity. Reported usage is not confirmed spend until authoritative reconciliation.

---

# 14. Judge ensemble

Semantic policy may require multiple independent judge invocations. Each invocation is
an admitted, claimable `WorkSpec` execution with a matching `EffectGrant`. The output is
an immutable judge `Observation` bound to the exact campaign, scope, plan, work
revision, `claim_fence`, attempt, subject, judge configuration, context, policy, and
stable operation identity.

A judge observation may contain:

```text
subject
judge identity and exact fixed model configuration digest
context digest
verdict
evidence considered
rationale artifact
material objections
requested follow-up proposal
```

A judgment is an observation, not truth or authority. A requested follow-up is only a
proposal source.

---

## 14.1 No blind majority voting

Deterministic scoped policy is evidence-aware:

```text
trusted deterministic failure
    -> reject

validated counterexample
    -> reject

material judge objection with a falsifiable claim
    -> may inform a bounded PlanRevision proposal

judges agree and no contrary evidence exists
    -> semantic gate may pass within its verifier contract

material disagreement remains
    -> may propose adjudication or another oracle, subject to admission and bounds
```

Model count never overrides deterministic evidence or failed admission. Campaign policy
names the target predicate and verifier for each semantic gate; judge output cannot
establish more than that contract permits.

---

## 14.2 Adjudication

An adjudicator receives the exact question, original artifacts, existing evaluator
observations, competing judge observations, relevant deterministic evidence, and their
scope, plan, work, attempt, subject, and policy bindings.

It may publish an immutable `Observation` that recommends:

```text
accept position
reject position
request another oracle
propose one bounded follow-up
leave unresolved
```

It cannot directly decide, release work, or create a child scope. Any follow-up enters a
superseding `PlanRevision` through typed `proposal_basis` and deterministic admission.
Adjudication depth, model calls, attempts, effects, and deadlines are strictly bounded.

---

# 15. Authority policy

Campaign configuration defines deterministic authority policy, target predicates,
verifier contracts, grant limits, budgets, and explicitly configured human boundaries.

Example autonomous sandbox campaign:

```yaml
authority:
  default: autonomous
  require_human: []
```

Example production-sensitive campaign:

```yaml
authority:
  default: autonomous

  require_human:
    - merge_to_main
    - spend_over_usd: 500
    - modify_paths:
        - production/**
        - auth/**
```

A required human action produces an approval or rejection `Observation`. Human output
does not directly grant authority. The relevant `PlanRevision` must cite that
observation through typed `proposal_basis`, and deterministic admission must still
validate every binding, bound, budget, and attenuation rule. Human or model agreement
cannot override admission failure or deterministic contrary evidence.

Deterministic admission is the sole path for:

```text
WorkSpec release
ChildScopeProposal admission
DelegationGrant issuance and escrow debit
EffectGrant issuance
budget spend authorization
external-effect authorization
```

Child grants may only attenuate parent capability, write scope, deadline, budget, and
resource authority. Campaign policy defines the target predicates and verifiers used
for acceptance and completion. A completion claim cannot exceed what its verifier
checks.

Only a root `QuarantineResolved` decision, based on an authoritative external outcome,
may reclassify root unknown reserve. Settlement and quarantine resolution cannot create
evidence or budget. The provider- and code-host-specific evidence that qualifies as an
authoritative quarantine outcome remains a concrete-protocol contract question; there
is no generic effect framework that guesses it.

For MVP testing, campaigns run autonomously against safe branches or repositories.
Humans may grade experiment results afterward; that is measurement, not workflow
authority.

---

# 16. Concrete campaign protocol model

A concrete campaign protocol defines:

1. Input, objective, configuration, and authority-policy contracts.
2. Campaign-defined target predicates and verifier limits.
3. How planners propose the initial `PlanRevision`.
4. Which `ClaimSpec`s, `WorkSpec`s, and `ChildScopeProposal`s may appear.
5. What immutable observations attempts may produce.
6. Which deterministic admission and decision rules apply.
7. How bounded observation-derived revisions may be proposed.
8. How effects, delegation, escrow, cancellation, sealing, certificates, settlement,
   and completion are handled.
9. Which failure and unresolved states are terminal.

Initial and observation-derived work use the same admitted `PlanRevision` path. No
concrete protocol API may directly create authoritative work, delegate authority,
spend budget, or authorize an external effect.

Implement concrete `research` and `change` modules.

Do not implement a workflow trait, workflow DSL, campaign-profile framework, generic
discovery interface, curriculum engine, online model training, learned reward policy,
universal state matcher, or unbounded task generator. Extract only demonstrated
non-authority helpers shared by concrete protocols.

---

# 17. MVP Campaign A: Distributed Research

## 17.1 Goal

Prove that multiple machines and two exact fixed model configurations can
collaboratively produce a better evidence-backed answer than one monolithic research
session while all authority remains scoped, admitted, bounded, and replayable.

Example:

```text
Determine why component X experiences p99 spikes under workload Y.
```

The campaign starts with one root `Scope`, immutable configuration, campaign-defined
research and synthesis verifiers, finite budgets, and one admitted initial
`PlanRevision`.

---

## 17.2 Initial decomposition

A planner proposes three to five independent research `WorkSpec`s in the initial
`PlanRevision`:

```text
R1 source/code-path investigation
R2 runtime/locking investigation
R3 memory/cache investigation
R4 syscall/IO investigation
R5 alternative-explanation investigation
```

Typed `proposal_basis` references the root objective and configuration. Deterministic
admission validates exact bindings, dependencies, capabilities, attempts, effects,
resources, deadlines, and budgets before releasing work. The controller does not
create research work directly.

The initial questions should be somewhat independent to reduce correlated anchoring.
Different machines claim their exact `WorkSpec` revisions in parallel.

---

## 17.3 Research attempt outputs

A research worker may publish immutable observations containing:

```text
Findings
ResearchClaimObservations
Evidence artifacts
Source references
Open questions
Potential falsification methods
Suggested follow-up proposals
```

Each observation binds campaign, scope, plan, work revision, `claim_fence`, attempt,
subject, producer, configuration, and relevant artifact or policy digests. A conclusion
is called a `ResearchClaimObservation` at the protocol layer so it cannot be confused
with the kernel's semantic-goal `ClaimSpec`.

The Research protocol uses a deliberately small structured schema. It does not add a
generic epistemics graph, curriculum engine, or universal discovery interface.

---

## 17.4 Critic judges

Once the required initial observations arrive, a planner may propose bounded critic
`WorkSpec`s through a superseding `PlanRevision`. Deterministic admission releases only
the configured critic work. Judges assess:

```text
Does the evidence support the conclusion?
Are competing explanations still plausible?
Is the conclusion material to the root objective?
What evidence would discriminate among explanations?
Is the finding contradicted elsewhere?
```

Judges run on different machines and fixed model configurations where capacity permits.
Their output remains immutable `Observation`s and cannot directly decide or create work.
There is exactly one critic round.

---

## 17.5 Discriminating work

Suppose observations disagree:

```text
Researcher A: lock contention dominates.
Researcher B: LLC misses dominate.
Researcher C: negative lookups dominate.
```

The controller does not ask a meta-model to guess which sounds best and does not emit
work directly. A planner may cite the exact observations as typed `proposal_basis` in
one superseding `PlanRevision` proposing bounded work such as:

```text
E1 collect lock-wait histogram
E2 collect hardware-counter profile
E3 split positive/negative lookup latency
```

Admission releases the single discriminating follow-up as the one allowed depth-two
child scope. There is no descendant scope, second critic
round, second adjudication loop, or unbounded model debate. The child's
`DelegationGrant`, escrow, `WorkSpec`s, effects, certificate, and settlement follow the
same recursive protocol.

---

## 17.6 Synthesis

Once the configured stopping rule is reached, an admitted synthesis `WorkSpec` consumes
only exactly bound observations and any accepted child certificate. The synthesis
result is an immutable observation; root policy commits any acceptance and completion
`Decision`.

The serialized synthesis payload remains an open contract question. Existing
obligations must be preserved: conclusions, evidence supporting each conclusion,
rejected explanations, material uncertainty, and unresolved questions. The contract
must still choose between exactly those five semantic sections and the outline-survey
variant that also retains `Suggested next workflow`. No v2 payload ships and no
serialized shape is finalized or tested until a human records that ruling.

---

## 17.7 Completion

A bounded completion policy preserves the original rule:

```text
all required questions synthesized

AND

no material contradiction remains unresolved

OR

budget exhausted and all unresolved items are explicit
```

The root can claim only what its configured synthesis verifier checks. Required
unresolved claims block their exact dependents; unrelated evidence remains valid. If a
child was used, it must seal, produce a verifier-bounded `CompletionCertificate`, and
settle idempotently before root semantic completion. Escrow remains conserved and
unknown reserve remains unavailable.

Root completion representation is not invented here; section 7.4 records the open
schema choice. No human "accept report" button is required.

---

# 18. MVP Campaign B: Distributed Change

The first concrete Change workload is a bounded semantic migration. It provides finite
scope, parallelizable work, semantic judgment, mechanical validation, integration, and
a measurable completeness criterion. `Target` remains protocol-specific rather than a
universal kernel type. A finite target universe is essential for migration
completeness.

The root `Scope` freezes the source base, trusted discovery rule, one fixed treatment,
deterministic grouping policy, campaign-defined target and final-completeness
verifiers, write scopes, integration policy, budgets, and stopping rule before work is
admitted.

---

## 18.1 Deterministic target discovery

A trusted discovery operation runs only as admitted `WorkSpec` execution with live
claim authority and a matching `EffectGrant`. It publishes one immutable
`Observation` containing:

```text
source revision
rule identity and digest
target ID
path
semantic locator
context digest
declared write scope
```

The discovery observation is a planning source. A planner cites it through typed
`proposal_basis` and proposes bounded `ClaimSpec`s and `WorkSpec`s in a
`PlanRevision`; deterministic admission is the only path that releases executable
work. There is no direct discovery authority path or generic discovery interface.

Discovered targets that produce no work remain explicit `BLOCKED` or `UNRESOLVED`
scoped `Decision`s rather than disappearing. The representation remains an open
contract question: admission may release a plan and policy may separately commit the
terminal decisions, a workflow-specific payload may carry them, or terminal targets
may be semantic goals without executable work. Do not invent a canonical
`PlanRevision.terminal_decisions` field until that choice is resolved.

---

## 18.2 Fixed treatment assignment

Trusted discovery assigns the single fixed treatment defined by the frozen E01 pilot
configuration. Treatment assignment is not model-driven. There is no autonomous target
classification, classification taxonomy, classification adjudicator, or per-target
treatment choice.

Choose a migration with few or no subjective exemptions so the fixed rule is
sufficient. Unsupported cases become explicit `BLOCKED` or `UNRESOLVED` decisions.

---

## 18.3 Deterministic grouping

Deterministic policy proposes compatible targets as bounded `WorkSpec`s or, only for
bounded non-overlapping ownership, `ChildScopeProposal`s:

```text
stable target identity and total order
deterministic tie-breaking
non-overlapping declared write scopes
deterministic packing rule
positive target-count cap
```

Grouping is a pure function of frozen inputs. It is not reviewed by judges and involves
no dependency planner. Hard caps prevent giant tasks. Deterministic admission validates
every dependency, write scope, capability, effect, resource, deadline, and budget bound
before releasing the grouped work or delegation.

---

## 18.4 Parallel code generation

Suppose 40 target groups are admitted. Multiple workers claim exact `WorkSpec`
revisions simultaneously:

```text
Machine A -> W1
Machine B -> W2
Machine C -> W3
Machine D -> W4
...
```

Workers operate against the exact source base OID and active plan lineage. Each
candidate operation requires the admitted `WorkSpec`, live `ClaimAuthority`, and
matching `EffectGrant`. Attempt completion, candidate identity, evaluation eligibility,
semantic acceptance, and integration state remain separate.

Child scopes, when used, own only bounded non-overlapping target groups. They cannot
integrate directly into the root campaign branch; they seal, return verifier-bounded
certificates, and settle before root integration work may cite them.

---

# 19. Candidate sandbox

Agent generation and candidate execution are separated from trusted daemon state.
Candidate execution starts only for an admitted `WorkSpec` revision held under the
current `claim_fence` and a matching locally validated `EffectGrant`. The candidate
process receives neither the claim authority nor raw grant material that could be
reused outside the trusted launcher.

Candidate sandbox receives:

```text
source files
admitted WorkSpec instructions and inputs
matching EffectGrant limits
private writable overlay
private build directory
prefetched dependencies
```

It does not receive:

```text
writable .git
daemon credentials
hidden evaluator inputs
shared writable caches
unrestricted network
```

Repository content is untrusted model input. Model API access happens through the
trusted generation layer, not candidate processes. Scope-controller authority,
`ClaimAuthority`, and grant validation remain outside the sandbox.

---

## 19.1 Delta validation

After an agent finishes, trusted daemon code validates the actual filesystem delta.
Validate:

```text
changed paths
added/deleted files
renames
untracked files
file modes
symlinks
hard links
special files
submodules
nested repositories
Git LFS pointers
case collisions
Unicode normalization
file count/size limits
```

Reject anything outside the admitted `WorkSpec` write scope and matching
`EffectGrant` limits. This is a security boundary rather than a prompt convention.

The validation result is an immutable `Observation` bound to `campaign_id`,
`scope_id`, `plan_digest`, `work_id`, `work_revision`, `claim_fence`, attempt,
candidate subject, base OID, result tree OID when available, trusted validator
identity, policy digest, and the effect's stable operation identity.

Validation re-derives the raw base/result-tree diff. It does not add a standalone delta
digest.

---

# 20. Git candidate construction

The agent never owns Git authority.

A trusted daemon component:

1. Starts from the exact base tree.
2. Applies validated bytes.
3. Constructs a Git tree.
4. Creates an immutable commit.
5. Records:

   * base OID
   * result tree OID
   * candidate commit OID
6. Creates a Git bundle/patch artifact for transfer.

Candidate identity binds to those Git identities plus the bundle artifact digest; there is no separate serialized delta stream or delta digest. Verification re-derives the raw base/result-tree diff (paths, modes, blob identities) and checks it against declared write scopes.

Candidate records are immutable.

A rebase or repair creates a new candidate.

The immutable candidate observation additionally binds `scope_id`, `plan_digest`,
`work_id`, `work_revision`, `claim_fence`, attempt identity, applicable
`EffectGrant`, producer identity, and policy digest. Artifact publication requires the
grant; claim ownership alone is insufficient.

---

# 21. Distributed candidate evaluation

Evaluation is admitted, claimable `WorkSpec` execution. Every evaluator run requires
a matching locally validated `EffectGrant` and live claim authority.

A candidate may require:

```text
compile evaluator
unit-test evaluator
migration-specific evaluator
static analyzer
platform-specific evaluator
```

These may run on different machines.

```text
Candidate C17

Linux compile       -> Machine A
ARM tests           -> Machine C
Static analysis     -> Machine D
Semantic judges     -> Machines E/F/G
```

The owning scope waits until policy-required evidence is present. Attempt completion,
evaluator output, mechanical acceptance, semantic acceptance, and integration remain
separate.

Evaluator output is an immutable `Observation`. The current scoped controller validates
its exact scope, plan, work revision, attempt, subject, evaluator, policy, inputs, and
grant bindings before deterministic policy may commit a `Decision`.

---

# 22. Trusted evaluators

Candidate agents cannot change:

```text
evaluator code
expected outputs
hidden inputs
output parser
control cases
baseline
```

Evaluator configuration is trusted campaign configuration and a trust root rather than
ordinary generated work. MVP evaluators remain deterministic:

```text
PASS
FAIL
ERROR
TIMEOUT
```

Statistical performance search remains deferred. Each precommitted blocked
experiment uses its campaign-defined analysis contract rather than turning evaluators
into a generic statistical framework.

Campaign policy defines each evaluator's target predicate and the claim it can establish.
An evaluator may establish only that declared claim. Every local or remote evaluator
operation requires an admitted `WorkSpec`, live `ClaimAuthority`, and matching
`EffectGrant`.

---

# 23. Semantic candidate judgment

After mechanical checks pass, independent semantic judges can assess questions not
completely captured by executable checks:

```text
Does this migration preserve the requested error semantics?
Does the change introduce an unsupported externally visible behavior?
Has the agent actually applied the fixed treatment?
```

Mechanical failure overrides semantic approval.

A judge that identifies a potential defect publishes an immutable `Observation`.
Verify-like work becomes authoritative only when a superseding `PlanRevision` cites
that observation through typed `proposal_basis` and passes deterministic admission.
A judge cannot directly create Verify work or override the mechanical gate.

---

# 24. Integration

Do not build a merge queue. Use existing code-host integration machinery and its
required checks or merge machinery.

A trusted publisher/integration worker can:

1. Claim an admitted integration `WorkSpec`.
2. Validate the matching `EffectGrant`.
3. Materialize the exact candidate.
4. Push the deterministic branch name using a stable operation identity.
5. Create or update the PR idempotently.
6. Record immutable external-state observations.
7. Let existing required checks and merge machinery operate.
8. Reconcile ambiguous outcomes by reading code-host state.
9. Return observations to the owning scope for a deterministic `Decision`.

Workers need not all have code-host credentials. Publisher capability is advisory
routing metadata, not a bearer capability. The MVP does not introduce cryptographic
bearer capabilities.

---

## 24.1 Autonomous integration for MVP

For the pilot:

```text
campaign branch
or
safe test repository
```

should permit autonomous integration.

This avoids making a human merge button part of the control loop.

A production `main` branch can remain an optional human authority boundary.

---

## 24.2 Final completeness

After integrations, final trusted discovery runs as an admitted `WorkSpec` with live
claim authority and a matching `EffectGrant` against the exact integrated source.

Root completion requires:

```text
every discovered target has an explicit terminal scoped Decision

AND

all required child scopes have sealed, certified, and settled

AND

final discovery finds no unclassified legacy targets

AND

the final campaign-defined verifier supports the claimed completion
```

Target states include resolved, rejected, `BLOCKED`, and `UNRESOLVED`; no target may
silently disappear. A child certificate cannot upgrade evidence or integrate directly
into the root branch. Root integration work cites accepted observations or certificates
through an admitted plan. Unknown external reserve remains unavailable even when
semantic completion is allowed to close with explicit unresolved accounting.

---

# 25. Crash recovery and unknown outcomes

Distribution does not create this requirement; it makes it more obvious. Even one node
crosses non-atomic boundaries between SQLite, filesystems, S3, model providers,
processes, Git, evaluators, and the code host.

Required principles remain:

```text
at-least-once attempts
idempotent side effects
explicit unknown outcomes
startup reconciliation
no exactly-once claim
```

Scoped recovery is per scope. A replacement rebuilds and verifies the exact selected
`ScopeHead` and active plan lineage before its first authoritative transition.
Root and child controllers recover independently. Work claims reconcile through
`claim_fence`; scope decisions reconcile through `scope_epoch`; external effects
reconcile through stable operation identity and their `EffectGrant`.

Cancellation stops new admission and local waiting but does not assert that a remote
effect stopped. Unknown reserve remains unavailable until authoritative reconciliation.
Concrete provider and code-host policy must define what evidence authoritatively
resolves quarantine; the runtime does not invent one universal outcome rule.

---

## 25.1 Worker crash cases

Test every original case with exact scope, plan, work revision, claim, grant, attempt,
and operation bindings:

```text
worker crashes before model call
worker crashes during model call
model call succeeded but response was lost
artifact uploaded but submission absent
submission uploaded but scoped controller has not committed it
worker returns after claim lease was reclaimed
```

Also test claim loss or grant invalidity before effect start, cancellation while a
remote effect may continue, lost claim-renewal or sealed-submission responses, and
restart reconciliation. A stale worker may leave immutable evidence but cannot complete
work or start a new effect.

---

## 25.2 Scoped-controller crash cases

Test all frozen controller-boundary cases through the scoped-v2 authority object:

```text
controller writes an immutable event but fails before ScopeHead CAS
ScopeHead CAS succeeds but the response is lost
controller expires while processing sealed submissions
replacement takes over from a stale scope-selective SQLite projection
stale controller later returns after a higher scope_epoch wins
```

Add recursive cases:

```text
parent and child controllers fail independently
child controller fails while an external outcome is unknown
parent enters settlement pending for an expired, unsettled child
SETTLEMENT_PRESSURE triggers replacement-child takeover without worker traffic
child seals and publishes a certificate before the parent records receipt
parent fails before, during, or after certificate evaluation
settlement commit succeeds but its response is lost
replacement parent repeats settlement idempotently
unknown reserve remains quarantined through semantic completion
root quarantine reconciliation arrives after completion
```

Fencing must prevent stale authoritative writes. Certificate handling and settlement
must not duplicate evidence, release returned budget twice, lose unknown reserve, or
violate:

```text
escrowed = confirmed_spend + returned + quarantined_unknown
```

The certificate-evaluation/settlement ordering and root-completion payload remain open
contract questions. Failure tests must follow the selected durable ordering once those
questions are resolved; this outline does not invent it.

---

# 26. Budgets and backpressure

Budgets exist at campaign, scope, delegation-escrow, plan, `WorkSpec`, and effect levels.
Every child receives an atomic escrow debit before genesis. Every effect remains within
the admitted plan and applicable grant. Track:

```text
model tokens
reported and confirmed model cost
attempt count
parallelism
CPU seconds
wall time
artifact bytes
oracle cost
judge count
adjudication rounds
generated follow-ups
child fanout and active scopes
confirmed spend
returned budget
quarantined unknown reserve
```

Campaign configuration supplies finite values for:

```text
max campaign cost
max scope and delegated cost
max WorkSpec attempts
max parallel work
max judge invocations per decision
max adjudication rounds
max generated follow-ups
max child fanout
max effects and resource credits
scope depth cap = two
per-effect and per-scope deadlines
```

Depth counting is fixed: root scope is depth 1, a direct child is depth 2, and a
grandchild is rejected. No other numeric defaults are invented here. Each concrete
campaign must seal its own finite fanout, attempt, follow-up, deadline, effect, resource,
parallelism, artifact, and spend bounds before execution.

At a hard limit, deterministic policy stops admitting new work, children, or effects;
allows required cleanup, drain, reconciliation, certification, and settlement; and
commits an explicit unresolved outcome. It never silently expands budget or recycles
quarantined unknown reserve.

Conservation is load-bearing:

```text
escrowed = confirmed_spend + returned + quarantined_unknown
```

Returned budget becomes available only through idempotent settlement. Unknown reserve
stays unavailable until a root `QuarantineResolved` decision cites the concrete
protocol's authoritative external outcome.

---

# 27. Causality and recursion controls

Every proposed or executed action retains exact causal and authority bindings:

```text
campaign_id
scope_id
parent_scope_id when applicable
delegation_digest when applicable
plan_digest
work_id and work_revision when applicable
claim_fence when claimed
scope_epoch when a Decision is committed
root_cause_id
cause_id
generation
attempt_number
maximum_attempts
policy_digest
```

The planner may propose bounded observation-derived work, but deterministic admission
rejects a repeated cause under the same policy, duplicate active work revision,
cyclic dependency, excessive fanout, excessive attempt, expired deadline, or depth
beyond two.

This prevents:

```text
judge Observation proposes research
research Observation proposes identical judgment
identical judgment proposes identical research
...
```

A `ClaimSpec` dependency graph and the `Scope` authority tree remain separate. The
system invalidates or blocks exact dependents of contradicted or unresolved claims
without discarding unrelated observations. No recursive action chain is unbounded.

---

# 28. Security model

MVP threat model:

> Trusted internal worker fleet executing potentially incorrect or prompt-injected generated code.

Not:

> Hostile multi-tenant arbitrary code execution service.

Process-level Linux sandboxing can be an MVP mechanism, but it is not marketed as a
strong multi-tenant isolation boundary.

Security domains remain separate:

```text
1. trusted daemon, admission, and scoped authority
2. model and planning layer
3. candidate execution sandbox
4. evaluator/oracle sandbox
5. trusted publisher and code-host boundary
```

Candidate sandboxes have no credentials, hidden evaluator artifacts, shared writable
caches, writable daemon Git metadata, or network; they have fixed resource and output
limits. Evaluator sandboxes have no model access or network, use immutable evaluator
inputs and separate writable state, and receive stricter resource limits.

The trusted launcher validates an admitted `WorkSpec`, live `ClaimAuthority`, and
matching `EffectGrant` before every external operation. Candidate processes receive no
reusable raw claim or grant authority. Presence and capability are routing metadata.
The MVP introduces no cryptographic bearer capabilities and no shared writable
build/package/compiler cache across trust boundaries.

---

# 29. Observability

The system records distributed behavior without turning telemetry into authority:

```text
work-ready latency
claim latency
claim collision rate
worker utilization
claim renewal rate
claim expiry/reclamation count
scope-controller failovers by scope
scope decision-commit latency
settlement-pressure takeover demand
scope-selective sync lag per node
scope replay and rebuild cost
active scope and child fanout counts
plan proposal and admission outcomes
grant-validation failures
artifact transfer time
S3 requests per WorkSpec
model time
oracle time
judge time
queue depth
wasted work
stale-result count
confirmed cost per accepted result
returned budget
quarantined unknown reserve
certificate and settlement latency
```

The original scaling formulas remain:

```text
speedup(N) = single-worker wall time / N-worker wall time

efficiency(N) = speedup(N) / N
```

We care about both throughput and useful throughput. Twenty machines generating twenty
incompatible or rejected changes is not success.

---

# 30. MVP milestone plan

M0–M3 are complete frozen-v1 proof milestones. Their deliverables, tests,
prohibitions, exit conditions, bytes, and fixtures remain unchanged. M4–M12 are the
active scoped-v2 milestones and reuse v1 algorithms only through explicit v2 types and
bindings. No milestone migrates or reinterprets a v1 object.

The scoped-v2 amendment sequence is:

| Phase | Work | Required proof |
| --- | --- | --- |
| 0. Contract amendment | Revise outline, epics, task graph, identity axis, keys, envelope, and fixtures together | Recursive protocol is coherent before new scoped payloads |
| 1. Scoped substrate | Add scoped heads, events, claims, work references, and selective projection beside v1 | Two scopes advance and rebuild independently; mixed versions fail closed |
| 2. Scoped authority | Add per-scope leases, lazy takeover, lifecycle supervision, and settlement-pressure scheduling | Parent and child controllers fail independently |
| 3. Recursive admission | Add plans, typed proposal bases, shared admission, grants, escrow, sealing, certificates, and settlement | One bounded observation-derived revision completes and conserves budget |
| 4. Campaign proof | Build Research and Change campaigns on that substrate | No flat workflow authority path requires replacement |
| 5. Scale and feasibility proof | Exercise multiple scopes and nodes, selective replay, failover, unknown outcomes, and fixed experiments | Root and projections avoid global hot paths and the go/no-go evidence is complete |

Open durable choices recorded in sections 5–12 must be resolved before their v2 bytes
ship. Milestone labels do not authorize implementations to invent event suffixes,
encodings, payload schemas, root genesis, supersession, grant reclamation,
cross-scope visibility, settlement ordering, or root completion representation.

## M0. Freeze invariants and pilot definitions

> **Status: Complete — frozen v1 proof record.** The following historical deliverables
> and prohibition remain unchanged and are not reopened by scoped v2.

Deliverables:

* Research pilot question.
* Change pilot migration.
* Campaign authority policy.
* Initial judge profiles.
* Evaluator/check manifests.
* S3 bucket/configuration.
* Actor identity format.
* Hard budgets.
* Precommitted success criteria.

Do not code generic workflow infrastructure before these exist.

---

## M1. Object-store protocol

> **Status: Complete — frozen v1 proof record.** The following v1 S3 event, head,
> artifact, reconciliation, and CAS proof remains unchanged. Its historical "fenced
> controller mechanism" exit phrase refers to the v1 head/envelope/CAS boundary, not a
> completed dynamic controller-acquisition proof; scoped acquisition belongs to M4.

Implement:

* S3 client.
* Immutable object publication.
* Conditional create.
* Conditional replacement.
* Unknown-outcome reconciliation.
* Campaign head.
* Event objects.
* Digest verification.
* Content-addressed artifacts.

Tests:

```text
concurrent CAS
lost success response
duplicate immutable publication
stale ETag
timeout
412 conflict
```

Exit condition:

Two processes can safely append through the fenced controller mechanism without corrupting campaign state.

---

## M2. Local SQLite projector and sync

> **Status: Complete — frozen v1 proof record.** The following v1 single-chain replay,
> cursor, transaction, and rebuild proof remains unchanged.

Implement:

* Local schema.
* Event replay.
* Cursor.
* Idempotent projection.
* Local queries.
* Artifact metadata/cache.
* Full rebuild from S3.

Exit condition:

A completely fresh machine can join and reconstruct the current campaign only from remote durable state.

---

## M3. Identity, presence, and work claims

> **Status: Complete — frozen v1 proof record.** The following v1 actor, instance,
> presence, same-key claim, and stale-submission proof remains unchanged.

Implement:

* Actor identity.
* Ephemeral instance identity.
* Capability advertisement.
* Soft presence.
* Work claim CAS.
* Lease renewal.
* Fencing.
* Reclamation.

Exit condition:

Two machines racing for one work item never both obtain valid ownership.

A stale worker cannot complete after reclamation.

---

## M4. Scoped-v2 substrate and controller failover

Implement beside the frozen-v1 paths:

* The exact scoped-v2 identity axis and `EventEnvelope`.
* The scoped-v2 keys from section 5.2.
* Separate `ScopeHead`s, immutable scope-local chains, claim keys, projections, and
  cursors.
* Scope-selective replay and readiness.
* Mixed-version rejection.
* Per-scope controller lease, `scope_epoch`, active plan lineage, submission processing,
  reconciliation, and takeover.
* One bounded per-scope takeover-demand queue, including injected
  `SETTLEMENT_PRESSURE` demand without settlement policy.

Acceptance scenarios:

```text
two scopes advance and rebuild independently
one scope fails replay while the other remains ready
Machine A controls a scope with fixture-seeded active work and claims
A is killed
Machine C verifies the exact ScopeHead and active plan lineage
C acquires a higher scope_epoch
existing unexpired fixture claims continue
C processes fixture-sealed submissions
A returns and cannot commit stale Decisions
parent and child controller failures remain independent
```

M4 precedes shared admission, grants, and admitted `WorkSpec`s (M6), so the work,
claims, and sealed submissions in this scenario are fixture-seeded substrate state,
not admitted work; the live admitted-work failover proof belongs to M6. The live
expired/unsettled-child settlement proof belongs to M6. The exact serialized
head, genesis, event suffix, and encoding must be resolved before M4 ships v2 bytes.

---

## M5. Multi-provider model runtime

Implement:

* Exactly two internal concrete provider adapters, preferably a closed enum.
* Exact fixed model configuration identifier and digest, not a profile registry.
* Structured outputs as immutable observations.
* `RunManifest` and `RunTrace`.
* A pre-contact authority seam checked against fixture-seeded `WorkSpec`, claim,
  and grant records; the admitted-`WorkSpec`/live-claim/`EffectGrant` enforcement
  itself lands with shared admission in M6, which wires real records through this
  seam without weakening the no-effect-without-grant invariant.
* Cancellation, provider request IDs, stable operation identity, reported usage, cost
  reconciliation, and explicit unknown outcomes.

Exit condition:

Different machines run generator and judge work through different fixed providers and
return exactly attributed immutable observations. No provider SDK, async provider trait,
generic agent harness, campaign profile, or authority-bearing model output exists.

---

## M6. Recursive admission and scoped decision loop

Implement:

* Immutable content-addressed `PlanRevision`s and typed `proposal_basis` validation.
* Shared deterministic admission for initial and observation-derived work.
* Campaign-defined target predicates and verifier limits.
* Bounded `ClaimSpec`s, `WorkSpec`s, and `ChildScopeProposal`s.
* `DelegationGrant`, escrow debit, `EffectGrant`, attenuation, and local launch checks.
* Judgment observations, material disagreement detection, evidence precedence,
  adjudication observations, and bounded follow-up proposals.
* Scoped `Decision`s under `scope_epoch`.
* Cancellation and bottom-up drain.
* Child sealing, `CompletionCertificate`, idempotent `Settlement`, quarantine, and
  escrow conservation.

Exit condition:

A bounded observation-derived revision passes admission and completes through exact
claims and grants. A parent/child proof covers independent failure, an
expired/unsettled child, settlement-pressure takeover, verifier-bounded certificate
handling, idempotent settlement, exact dependent blocking, and:

```text
escrowed = confirmed_spend + returned + quarantined_unknown
```

Model or human agreement cannot override deterministic evidence or an admission
failure. Open payload and ordering questions must be settled before durable records
ship.

---

## M7. Distributed Research campaign

Implement:

* One root `Scope` and admitted initial plan.
* Three to five parallel research `WorkSpec`s.
* Small finding, `ResearchClaimObservation`, and evidence schemas.
* One admitted critic round.
* At most one observation-derived discriminating follow-up, in the one allowed
  depth-two child scope.
* Admitted synthesis work and verifier-bounded root completion recorded in the
  root-completion representation V2-P3 selects (§7.4 keeps certificate,
  optional-delegation certificate, and `Decision`-plus-accounting open).
* Child certificate and settlement for that follow-up child.

Required deployment remains at least three independent machines or VM hosts.

Required scenarios preserve the original proof: multiple research jobs execute
concurrently; judge jobs execute on different nodes; a new machine joins mid-campaign;
a worker disappears; scoped controller authority moves machines; and final synthesis
remains coherent. No direct controller-created work, descendant scope, second critic
round, second adjudication loop, workflow trait, DSL, or campaign profile is introduced.

Exit condition:

The campaign produces a traceable evidence-backed result without human control-loop
decisions. The section 17.6 synthesis payload conflict must be resolved before its v2
schema ships.

---

## M8. Candidate sandbox and Git substrate

Implement:

* Trusted local bare repository and exact source materialization.
* Candidate sandbox with no writable Git metadata, network, credentials, hidden
  evaluator data, or shared writable caches.
* `WorkSpec`, live claim, and `EffectGrant` validation in the trusted launcher.
* Raw filesystem-delta validation and write-policy enforcement.
* Trusted Git tree and immutable candidate commit construction.
* Candidate bundle artifact publication under the grant.

Candidate identity remains exactly:

```text
base OID
result tree OID
candidate commit OID
bundle artifact digest
```

There is no standalone delta digest. Another machine must reconstruct and verify the
exact candidate from the bundle and re-derived raw base/result-tree diff.

---

## M9. Distributed oracle/evaluator runner

Implement:

* Trusted evaluator configuration and exact-match capability routing.
* Admitted evaluator `WorkSpec`s, live claims, matching `EffectGrant`s, and stable
  operation identities.
* Deterministic `PASS`, `FAIL`, `ERROR`, and `TIMEOUT` observations.
* Exact scope, plan, work, claim, attempt, subject, candidate, evaluator, policy, input,
  and grant bindings.
* Output artifacts, sandboxing, hidden inputs, process-group cleanup, and result
  submission.

Exit condition:

A candidate requires and receives evaluations from several heterogeneous machines
before deterministic scoped policy allows it to advance. No candidate controls its
evaluator, and no model agreement overrides deterministic failure.

---

## M10. Distributed Change campaign

Implement:

* Trusted target discovery as an immutable observation and planning source.
* Fixed treatment assignment and deterministic grouping.
* Explicit `BLOCKED` and `UNRESOLVED` terminal target decisions.
* Shared plan admission for target work and bounded non-overlapping child ownership.
* Parallel `WorkSpec` claims and candidate generation.
* Deterministic evaluation and semantic judge observations.
* At most one ordinary fresh retry through a superseding `PlanRevision`.
* Admitted root integration work and readiness.
* Child certificates and settlement where child scopes are used.

Required scale remains several concurrent candidate-producing machines.

Exit condition:

A finite semantic migration completes across multiple machines without a human
assigning or approving each work item. There is no autonomous target classification,
classification taxonomy, judge-reviewed grouping, dependency planner, generic discovery
interface, or generic repair planner.

---

## M11. Code-host integration

Implement:

* Trusted publisher capability as routing metadata only.
* Admitted integration `WorkSpec`, live claim, and matching `EffectGrant` checks.
* Deterministic branch naming and stable external operation identity.
* Idempotent push and PR create/update.
* Immutable external-state observations and read-before-retry reconciliation.
* Existing required CI and merge-queue integration.
* Serial application of accepted non-overlapping candidates to one campaign branch and
  one campaign PR.
* Final trusted rediscovery and root completeness decision.

Exit condition:

The campaign autonomously integrates to a safe campaign branch and proves target
completeness through its configured verifier. Publisher credentials and capabilities do
not form a new authority path, and no custom merge queue or bearer capability is built.

---

## M12. Failure-injection matrix

Automate all original kill and timeout points:

```text
S3 object write
head CAS
lease renewal
model request
artifact upload
submission
controller event commit
Git candidate creation
branch push
PR creation
evaluator run
```

Add scoped-v2 points:

```text
v2 immutable event write
ScopeHead CAS and lost success
mixed-version or wrong-scope replay
plan admission before and after commit
claim reclamation racing sealed submission
grant validation and effect start
parent and child controller failure
child cancellation, drain, and seal
certificate publication and parent receipt
settlement before and after commit
settlement-pressure takeover
unknown external outcome and quarantine resolution
root completion with open accounting
```

Exit condition:

No stale actor can perform an authoritative transition; no v1/v2 chain mixes; no
external effect exceeds documented at-least-once and idempotent semantics; no returned
budget releases twice; unknown reserve remains unavailable; and escrow is conserved.

---

# 31. MVP acceptance criteria

The MVP is **not complete** if it only works as multiple subprocesses on one workstation.

Required distributed proof:

* At least three independent machines or VM hosts.
* A v2 root and direct child advance and rebuild independently.
* Scoped-controller failover between hosts, including independent parent/child recovery.
* Worker joins after campaign start and reconstructs selected scopes from object storage.
* Worker disappears with an active claim; a stale result is rejected by `claim_fence`.
* A stale scope controller is rejected by `scope_epoch`.
* Generator and judge work execute concurrently.
* Oracle/evaluator work executes remotely.
* Scope-selective SQLite reconstruction works on a fresh worker.
* Mixed-version, wrong-scope, and invalid-chain input fails closed without invalidating
  an independent scope.
* Child certificate, settlement, and settlement-pressure recovery preserve coherent
  root progress.

Required autonomous proof:

* Human provides objective and configuration or an explicitly configured proposal
  observation.
* Human does not assign individual `WorkSpec`s, approve routine research conclusions,
  choose ordinary candidates, mint grants, override admission, or perform routine
  safe-branch integration.
* Model, human, discovery, judge, evaluator, and code-host output remains observation or
  proposal input.
* Deterministic admission is the sole authority path for work, delegation, spend, and
  effects.
* Campaign-configured finite bounds stop runaway work without silent expansion.

Required correctness proof:

* No candidate controls its evaluator or receives writable daemon Git metadata.
* No out-of-scope change is accepted.
* No stale evaluation applies to a different subject, scope, plan, work revision,
  evaluator, policy, input, or grant.
* No stale controller or worker commits authoritative state.
* No migration target silently disappears; final rediscovery proves completeness.
* No deterministic failure or admission failure is overridden by model judgment.
* `scope_epoch` and `claim_fence` remain separate.
* Every external operation requires admitted work, live claim authority, and a matching
  `EffectGrant`.
* Completion claims do not exceed campaign-defined verifiers.
* Root depth is 1, direct-child depth is 2, and grandchildren are rejected.
* Children seal bottom-up; settlement is idempotent; unknown reserve stays unavailable;
  escrow remains conserved.
* Frozen-v1 chains and fixtures remain unchanged and never mix with v2.

---

# 32. MVP experiments

Research and Change retain the frozen E01 precommitted three-treatment contracts,
inputs, run counts, schedules, and success definitions. Scoped-v2 instrumentation adds
scope, plan, claim, grant, certificate, settlement, and quarantine attribution without
changing those frozen outcomes after results are observed. Analysis remains offline and
descriptive.

## Experiment A: Distributed Research

Compare:

```text
A. One strong agent on one machine.

B. Multiple agents on one machine.

C. Distributed campaign:
   multiple researchers
   multiple judges
   deterministic oracles
   one bounded admitted follow-up.
```

Measure every original outcome:

* Wall-clock time.
* Supported conclusion count.
* Material omission rate.
* Incorrect conclusion rate.
* Useful evidence artifacts.
* Number of discriminating experiments.
* Cost.
* Model invocations.
* Duplicate work.
* Scaling efficiency.
* Scoped-controller idle or bottleneck time.

Also retain scope/grant overhead, child certificate and settlement where used, and
quarantined unknown reserve. The question must have enough independently inspectable
evidence for post-hoc ground-truth assessment.

---

## Experiment B: Distributed Change

Compare:

```text
A. Direct coding agent.

B. Multiple independent coding agents without campaign coordination.

C. Distributed Change campaign.
```

Use several dozen migration targets and preserve the fixed treatment assignment.
Measure every original outcome:

* Correctly resolved targets.
* Wall-clock completion.
* Coverage omissions.
* Semantic correction rate.
* Candidate rejection rate.
* Integration conflict rate.
* Wasted work.
* Cost per resolved target.
* Worker utilization.
* Scaling efficiency.
* Final rediscovery result.

Also retain explicit `BLOCKED` and `UNRESOLVED` counts, scope/grant overhead, child
certificate and settlement where used, and quarantined unknown reserve.

# 33. Post-MVP decision gate

Do not automatically proceed to every later feature. After the two frozen comparisons
and the recursive proof, answer:

```text
Does distributed execution materially improve wall-clock completion?
Where does parallelism stop scaling?
Does judge diversity improve decisions or mainly increase cost?
How often does disagreement generate useful new evidence?
How trustworthy are generated findings and verifier-bounded claims?
Does observation-derived planning through admission improve outcomes?
How much work is duplicated?
Is object-store synchronization fast enough?
Are any ScopeHead, admission, certificate, or settlement paths bottlenecks?
Are evaluator or oracle workloads the real bottleneck?
Does selective replay avoid global hot paths?
Which concrete campaign produces the strongest differentiated value?
```

Use those results to determine follow-up order. A no-go decision or explicit
unresolved results remain valid completed
experiments when evidence and accounting close.

---

# 34. Likely follow-up: Verify campaign

Standalone use:

```text
Try to break candidate/PR X.
```

Input:

* Exact candidate.
* Claimed properties.
* Failure model.
* Existing immutable observations.
* Campaign-defined falsification and acceptance verifiers.

Distributed challenge workers can explore:

```text
race conditions
cancellation
memory pressure
resource exhaustion
malformed input
boundary conditions
skew
partial failure
platform differences
```

Useful counterexamples include failing tests, reproducers, traces, sanitizer reports,
and crash inputs. Each is an immutable observation. A trusted oracle independently
reruns the artifact before deterministic scoped policy treats the counterexample as
established.

Verify can follow Change or run against externally produced code. A planner proposes
its `ClaimSpec`s and `WorkSpec`s through a `PlanRevision`; deterministic admission,
live claims, and matching `EffectGrant`s govern execution. No judge or prior campaign
directly creates Verify work.

---

# 35. Likely follow-up: Document campaign

Standalone:

```text
Document subsystem X.
```

Or composed:

```text
Research -> Document
Change -> Document
Port -> Document
```

Distributed workers can partition sources and sections while judges inspect coverage,
contradictions, unsupported statements, and source provenance. Outputs include:

```text
document
source/provenance map
coverage result
unresolved questions
```

Those outputs remain observations. Any Document work or child scope enters through an
admitted plan, and completion is bounded by the configured coverage and support
verifiers. No universal document or workflow framework is implied.

---

# 36. Likely follow-up: Search / distributed autoresearch

This remains the major scaling use case after the MVP.

Input:

```text
objective function
hard constraints
mutable code scope
trusted evaluators
search budget
```

Example:

```text
Minimize MediaCache lookup p99.

Constraints:
  memory <= +10%
  CPU <= +5%
  correctness checks must pass
```

Protocol concepts remain outside the kernel:

```text
Hypothesis
Candidate
Candidate lineage
Measurement
Selection
Mutation
Combination
```

Distributed execution may spread candidates, evaluators, and judges across many
machines. At that point add repeated measurements, noise estimation, interleaved
baseline/candidate runs, practical-effect thresholds, holdout workloads,
multiple-comparison handling, Pareto selection, population diversity, candidate
lineage, and mutation or recombination.

Performance results remain immutable observations, not timeless validation facts.
Every new candidate or follow-up is proposed through a bounded `PlanRevision`, and
every external run requires admitted work, a live claim, and a matching `EffectGrant`.
Statistical performance search, large evolutionary populations, learned policies, and
unbounded generation are not part of the MVP.

---

# 37. Likely follow-up: Deeper recursive campaign composition

Root-plus-one-child recursion is already an MVP requirement. The MVP root is depth 1, a
direct child is depth 2, and grandchildren are forbidden. This later section concerns
only deeper scope trees or broader compositions after measurement shows that depth two
is insufficient.

A sealed scope may return a verifier-bounded certificate that informs a later plan:

```text
Research certificate
  -> proposal basis for focused Research or Search
Search certificate
  -> proposal basis for Verify
Verify counterexample Observation
  -> proposal basis for Change or another bounded Search
```

No completed scope directly starts another. Cross-scope or cross-campaign work still
requires typed proposal-basis visibility, deterministic admission, attenuated grants,
escrow, and finite depth, fanout, attempts, deadlines, effects, and resources.

Before increasing the depth cap, measure root projection pressure, certificate and
settlement cost, controller placement, failure recovery, and whether deeper recursion
adds useful results. Arbitrary live reparenting and multiple authority parents remain
deferred.

---

# 38. Later: learned generator/judge routing

Exact provider, model, and fixed model configuration identifiers and digests are
recorded from day one. After enough valid observations exist, offline analysis may ask:

```text
which generators produce candidates that survive checks
which judges predict oracle outcomes
which models find confirmed counterexamples
which providers perform best in each domain
cost/quality tradeoffs
```

Routing may eventually become empirical, but learned output remains a proposal source
and cannot bypass deterministic admission. Do not implement model reputation, online
training, learned reward policy, campaign profiles, or learned authority during the
MVP.

---

# 39. Later: P2P fast path

Object storage remains authoritative.

P2P can later improve:

* Work-ready notifications.
* Presence.
* Direct artifact transfer.
* Fast event propagation.
* Large source/index transfer.

Iroh is a likely Rust-first candidate.

The pattern becomes:

```text
fast path:
  peer -> peer

durable path:
  peer -> object storage
```

P2P failure never compromises correctness.

---

# 40. Later: CRDTs

Still optional.

Introduce only if there is a concrete shared mutable object where concurrent offline edits should automatically converge.

Possible examples:

* Collaborative notes.
* Shared evolving design document.
* Annotation map.

Do not use CRDTs for:

* Work ownership.
* Fencing.
* Candidate acceptance.
* Budget consumption.
* Integration decisions.

---

# 41. Later: controller scaling

Scoped v2 already replaces the single global campaign sequencer with one fenced
controller and ordered decision stream per `Scope`. Independent scopes can advance
concurrently in the MVP; the root does not sequence every leaf transition.

If measurements show a hot individual scope, root rollup, placement policy, or
scope-selection path is a bottleneck, later options include:

* Finer admitted child-scope boundaries within a higher measured depth cap.
* More selective projection and archived-history loading.
* Certificate indexing and projection compaction.
* Locally decidable worker transitions that still publish immutable observations.
* Measured scope placement and takeover preference.

Do not introduce multiple concurrent authorities for one `ScopeHead`, partition one
scope's decision sequence, or add automatic repartitioning before measurement and a new
contract amendment. Model calls, compilation, testing, benchmarking, and artifact
movement remain more likely initial bottlenecks.

---

# 42. Suggested implementation tree

```text
ravel/
  src/
    domain/
      campaign.rs
      objective.rs
      scope.rs
      plan.rs
      claim.rs
      work.rs
      grant.rs
      observation.rs
      decision.rs
      certificate.rs
      settlement.rs
      attempt.rs

    distributed/
      identity.rs
      presence.rs
      controller.rs
      claims.rs
      scope_controller.rs
      scope_claims.rs
      fencing.rs

    sync/
      head.rs
      event.rs
      scope_head.rs
      scope_event.rs
      replay.rs
      cursor.rs

    storage/
      s3.rs
      artifacts.rs
      plans.rs

    db/
      schema.rs
      projections.rs
      scope_projections.rs

    controller/
      admission.rs
      scheduler.rs
      policy.rs
      settlement.rs

    models/
      provider.rs
      config.rs
      request.rs
      response.rs

    sandbox/
      process.rs
      filesystem.rs
      policy.rs

    oracle/
      manifest.rs
      runner.rs

    workflows/
      research/
      change/

    git/
      repository.rs
      delta.rs
      candidate.rs
      bundle.rs

    code_host/
      publisher.rs
      state.rs

    recovery/
      reconcile.rs

    pi/
      commands.rs
      status.rs
```

The frozen-v1 paths are `sync/head.rs`, `sync/event.rs`,
`distributed/claims.rs`, and `db/projections.rs`. Their shipped behavior and fixtures
remain unchanged. Scoped-v2 modules sit beside them.

`distributed/controller.rs` is not described as a completed E01–E04 proof. Scoped
controller authority is implemented in `distributed/scope_controller.rs`.

`models/config.rs` records exact fixed model configuration identity and digest. There
is no `models/profiles.rs`, profile registry, workflow trait, DSL, or generic discovery
module.

Do not split into many crates until dependency boundaries make that useful.

---

# 43. Hard invariants

The implementation must enforce all original obligations and the additive scoped-v2
obligations from day one:

1. No worker can authoritatively complete work without the current v1 work fence or v2
   `claim_fence` for the exact work revision.
2. No stale controller can commit after its v1 fence or v2 `scope_epoch` is superseded.
3. No model-generated assertion becomes truth by self-report.
4. No deterministic evaluator failure can be overridden by model consensus.
5. No candidate accesses or changes its trusted evaluator.
6. No candidate receives writable daemon Git metadata.
7. No accepted candidate contains an out-of-policy delta.
8. No evaluation applies to a different subject or evaluator identity.
9. No rebase mutates an existing candidate identity.
10. No external side effect lacks an idempotency and reconciliation path.
11. No exactly-once claim is made.
12. No campaign depends on worker presence records for correctness.
13. No machine departure event is required for recovery.
14. No shared writable build, package, or compiler cache crosses trust boundaries.
15. No recursive action chain is unbounded.
16. No campaign silently exceeds a hard cost or resource budget.
17. No migration campaign completes without final target rediscovery.
18. No graph database is introduced merely because the conceptual model can be viewed
    as graphs.
19. No P2P or CRDT dependency is required for initial correctness.
20. No MVP is declared successful without actual multi-machine execution and failover.
21. No frozen-v1 event, head, claim, projection, artifact, key, encoding, or fixture is
    reinterpreted, rewritten, or silently routed through v2 code.
22. No authoritative chain mixes versions: a v1 head references only v1 events and a
    v2 `ScopeHead` references only v2 events for its exact scope.
23. No authoritative work, delegation, budget spend, or external effect bypasses
    deterministic admission of a `PlanRevision`.
24. No `Observation` becomes authority by producer identity, confidence, agreement, or
    presence; decisions can change applicability but cannot rewrite observations.
25. No observation or decision is accepted without exact campaign, scope, plan, work
    revision, attempt, subject, producer, evaluator or policy, and applicable fence or
    digest bindings.
26. No parent writes a live child's decision stream, and no two controllers hold
    concurrent decision authority for one `ScopeHead`.
27. No external worker, model, judge, evaluator, Git, or code-host operation starts
    without an admitted `WorkSpec`, live claim authority, and matching `EffectGrant`.
28. No `scope_epoch` substitutes for a `claim_fence`, and no `claim_fence` substitutes
    for scoped decision authority.
29. No superseding plan rewrites an old observation, attempt, work revision, or claim;
    applicability follows explicit lineage and the resolved supersession contract.
30. No child grant widens parent capability, write scope, deadline, budget, effect, or
    resource authority.
31. No MVP scope exceeds depth two: root depth is 1, direct-child depth is 2, and
    grandchildren are rejected.
32. No settlement creates evidence or budget, releases returned escrow twice, or makes
    quarantined unknown reserve available without a root `QuarantineResolved` decision.
33. No parent settles before the child seals, and no certificate replaces durable child
    history or upgrades evidence beyond its verifier.
34. No acceptance, certificate, or completion claim exceeds what its campaign-defined
    verifier checks; required unresolved claims block their exact dependents.
35. No workflow trait, DSL, campaign profile, generic discovery interface, curriculum
    engine, online training, learned reward policy, universal state matcher, unbounded
    generator, automatic repartitioner, learned placement mechanism, or cryptographic
    bearer capability enters the MVP.

The escrow equation is invariant at every child boundary:

```text
escrowed = confirmed_spend + returned + quarantined_unknown
```

---

# 44. MVP definition of done

The project has an MVP when all applicable frozen-v1 and scoped-v2 proofs below pass.

### Distributed substrate

* Three or more independent machines participate.
* The frozen-v1 substrate and fixtures remain unchanged and pass their historical
  proofs.
* A fresh machine reconstructs selected scoped-v2 state from object storage.
* A root and direct child advance and rebuild independently; one failed replay does not
  invalidate the other.
* Workers dynamically join and leave.
* Work claims are fenced by exact work revision.
* Scope controllers fail over safely and independently.
* Stale worker and scope-controller results are rejected by separate fences.
* Artifact and state synchronization survives crashes.
* Mixed-version and wrong-scope chains fail closed.

### Autonomous control

* The user supplies objective, constraints, policy, budget, and verifier contracts.
* Planners propose routine work; deterministic admission is the sole authority path.
* The system routes admitted work across machines.
* Multiple fixed model/provider configurations participate.
* Deterministic evidence has precedence.
* Scoped controllers handle routine disagreement without humans.
* Human output, when configured, is an approval or rejection observation cited through
  typed proposal basis and cannot override admission.
* Finite depth, fanout, attempts, effects, resources, deadlines, and budgets stop
  runaway work.
* Every external operation validates admitted work, live claim authority, and a
  matching `EffectGrant`.

### Research

* One root `Scope` and one admitted initial plan exist.
* Three to five researchers run concurrently across machines.
* Critic judges run independently in exactly one bounded critic round.
* The pilot produces at most one and, where required by its frozen proof, at least one
  evidence-driven follow-up through a superseding admitted plan.
* At most one depth-two child is used; if used, it seals, certifies, and settles before
  root completion.
* Final synthesis is produced autonomously and claims only what its verifier checks.
* Full scope, plan, work, attempt, producer, evaluator, policy, certificate, and
  settlement provenance is available.
* The unresolved section 17.6 synthesis payload conflict is settled before durable v2
  bytes ship.

### Change

* A finite target universe is discovered as an immutable observation.
* Fixed treatment assignment and deterministic grouping require no manual assignment.
* Unsupported targets end explicitly as `BLOCKED` or `UNRESOLVED` rather than
  disappearing.
* Several admitted candidate `WorkSpec`s run in parallel.
* Candidates are mechanically evaluated under matching grants.
* Semantic judge observations evaluate surviving candidates, while mechanical failure
  always wins.
* Any retry enters through one fresh superseding plan revision.
* Bounded non-overlapping child scopes, if used, seal, certify, and settle before root
  integration.
* Integration completes through admitted root work and existing code-host machinery.
* Final trusted rediscovery proves verifier-bounded completeness.

### Failure behavior

* A parent or child scope controller can die and authority can move machines.
* A worker can die mid-task and stale submission loses to reclamation.
* Unknown S3, model, evaluator, Git, and code-host outcomes reconcile through stable
  operation identities.
* Cancellation stops new admission and local waits without claiming remote effects
  stopped.
* Settlement-pressure takeover works without ordinary worker traffic.
* Certificates and settlements remain idempotent under lost responses and restarts.
* No duplicated authoritative effect appears under fault injection.
* Escrow remains conserved and unknown reserve remains unavailable.

### Measurement

The frozen Research and Change comparisons retain:

```text
single-agent
single-machine multi-agent
distributed multi-machine campaign
```

The one offline renderer emits fixed Research and
Change tables covering wall-clock time, correctness, useful throughput, cost,
wasted work, scaling efficiency, scope/grant overhead, settlement, and quarantined
unknown reserve.

---

# 45. Final north-star walkthrough

Eventually the system should be able to receive only:

```text
Reduce MediaCache lookup p99 by 30%.
Memory increase <=10%.
CPU increase <=5%.
Do not weaken correctness.
Budget = X.
```

The root `Campaign` fixes the objective, constraints, policy, verifiers, budget, and
root `Scope`. The distributed campaign may then evolve through bounded admitted plans:

```text
Research workers
    publish exactly attributed observations about lookup paths,
    locking, allocations, syscalls, cache behavior, and skew

Judges
    publish semantic observations about explanations and missing evidence

Oracle workers
    run perf, traces, benchmarks, and targeted experiments under EffectGrants

Planner
    proposes a PlanRevision citing the typed observation basis

Deterministic admission
    validates bindings, dependencies, bounds, budget, attenuation, and verifiers

Current scoped controller
    commits the admitted Decision under scope_epoch

Search or Change workers
    claim exact WorkSpec revisions and generate candidates under claim_fence

Evaluation workers
    test correctness and performance on heterogeneous hosts

Verification workers
    attack top candidates and publish counterexample observations

Child scopes, when admitted
    own bounded work, seal bottom-up, return CompletionCertificates,
    and settle escrow idempotently

Integration worker
    executes admitted root integration work under an EffectGrant

Code host
    runs exact required checks and exposes authoritative external state

Root scope
    declares only verifier-supported completion or reports why it could not converge,
    while unresolved external reserve remains quarantined
```

The machines involved can change throughout the campaign. No individual machine is the
system. The durable campaign, its scoped authority tree, admitted work graph, immutable
observation set, and conserved accounting are the system.

Local SQLite makes each participant fast and independently useful. Shared object
storage provides durable rendezvous, immutable plans and artifacts, per-scope ordered
decision chains, and the minimum serialization needed for correctness.

Frozen-v1 records remain valid beside scoped v2; no authoritative chain mixes them.
That is the architecture the MVP should now be built to prove.
