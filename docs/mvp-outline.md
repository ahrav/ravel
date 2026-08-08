# Distributed Autonomous Engineering Campaign Runtime

## Working Plan and MVP Specification v0.1

## 0. Executive summary

We are building a **distributed, local-first runtime for autonomous engineering campaigns**.

A user provides:

* An objective.
* Constraints.
* Available repositories/artifacts/tools.
* A resource budget.
* An authority policy.

A transient fleet of machines can then collaboratively:

* Investigate the problem.
* Generate hypotheses and plans.
* Produce code or other artifacts.
* Run experiments and deterministic evaluators.
* Judge semantic results using multiple models/providers.
* Generate additional bounded work.
* Challenge conclusions.
* Integrate validated results.
* Recover as machines join, disappear, crash, or reconnect.

The normal control loop is not human-driven.

The intended model is:

```text
Generator proposes.
Oracle measures.
Judge interprets.
Controller decides.
```

Humans are an optional authority provider at explicitly configured boundaries, such as merging to production or increasing a large budget. The system must not depend on human review for routine planning, evaluation, research synthesis, or candidate selection.

The architecture is local-first at each machine:

```text
Machine
  ├── local SQLite projection
  ├── local artifact cache
  ├── Rust campaign daemon
  ├── agent/model runtime
  ├── judge runtime
  ├── evaluator/oracle runner
  ├── sandbox
  └── Git support
```

But the campaign itself is distributed:

```text
                    Shared object storage
             durable log + artifacts + CAS
                         |
       +-----------------+------------------+
       |                 |                  |
       v                 v                  v
   Machine A         Machine B          Machine C
  local SQLite      local SQLite       local SQLite
       |                 |                  |
  generators           judges             oracles
  researchers          agents             evaluators
       |                 |                  |
       +-----------------+------------------+
                         |
                         v
                  campaign progresses
```

There is:

* No permanent coordinator machine.
* No PostgreSQL.
* No DynamoDB.
* No distributed consensus system in v0.1.
* No requirement that all machines remain online.

Object storage is the shared durable synchronization and narrow coordination authority.

A **fenced campaign-controller lease** means exactly one controller instance sequences authoritative campaign decisions at a time, but the controller role can move to any machine after failure.

All expensive execution remains horizontally parallel.

The MVP proves this architecture using two deliberately different workflows:

1. **Distributed Research**

   * Produces knowledge, evidence, and conclusions.
   * Does not require code changes.

2. **Distributed Change**

   * Produces code.
   * Uses a bounded semantic migration as the first concrete workload.
   * Exercises candidate generation, exact diff validation, trusted evaluation, and integration.

The migration is a test protocol, not the ontology of the product.

The feedback correctly pushed us away from building a large generic orchestration platform before proving the core behavior.  The equally important correction is that distribution itself is part of what we are trying to prove.

---

# 1. Product thesis

The north-star product is:

> A distributed, local-first runtime for autonomous engineering campaigns in which a transient fleet of machines collaboratively investigates objectives, generates and evaluates work, challenges results, and converges on validated outputs.

Examples of standalone workflows:

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

The eventual user should be able to state the objective rather than manually defining that workflow.

---

# 2. Core architectural principles

## 2.1 Agents are never authoritative by declaration

An agent may produce:

* A claim.
* A work proposal.
* A candidate.
* A hypothesis.
* A test.
* A reproducer.
* A document.
* A proposed decision.

None becomes authoritative because the generating model says it is correct, important, high-confidence, or valuable.

Do not use proposer-supplied scalar fields such as:

```text
confidence = 0.95
expected_value = high
severity = critical
```

as decision authority.

---

## 2.2 Separate generators, judges, oracles, and controller

### Generator

Creates novel output:

* Research findings.
* Hypotheses.
* Plans.
* Code.
* Tests.
* Documents.
* Candidate counterexamples.

Usually an LLM.

### Judge

Makes a semantic assessment:

* Is this conclusion supported?
* Does this candidate satisfy the requested contract?
* Are two proposals materially duplicates?
* Is a missing concern important?
* Which explanation best fits the evidence?

Usually an independent model invocation.

### Oracle

Produces externally grounded observations:

* Compiler.
* Tests.
* Differential harness.
* Fuzzer.
* Sanitizer.
* Static analyzer.
* AST query.
* Git.
* Benchmark.
* Trace.
* Model checker.

Whenever an oracle can resolve something, use it rather than another model.

### Controller

Applies deterministic campaign policy to:

* Current campaign state.
* Evaluations.
* Judgments.
* Budgets.
* Claims.
* Work dependencies.
* External state.

The controller determines what happens next.

It is primarily policy/state-machine code, not one large manager-model prompt.

---

## 2.3 Deterministic evidence outranks model consensus

This must be a daemon-level rule.

For example:

```text
2 judges: ACCEPT
1 judge: produces concrete race reproducer

independent oracle executes reproducer
    -> race confirmed

Decision:
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

Decision:
    REJECT
```

Model diversity helps reveal different interpretations. It does not turn majority voting into ground truth.

---

## 2.4 Work completion, result acceptance, and integration are separate

A work attempt can succeed:

```text
Agent finished task and returned structurally valid output.
```

while its candidate fails evaluation.

A candidate can pass evaluation while failing integration.

A research worker can complete its investigation while its conclusion is rejected by judges.

These must never collapse into one `Done` bit.

---

## 2.5 Validation is a projection over immutable observations

Do not persist:

```text
candidate.validated = true
```

Persist:

```text
Candidate tree = T
Evaluator = E
Policy = P
Inputs = I
Outcome = PASS
```

Then derive whether the candidate is *currently acceptable*.

A rebase, evaluator change, policy change, or new counterexample can invalidate eligibility without rewriting history. The feedback correctly identified timeless validation statuses as a modeling error.

---

## 2.6 No replay of agent side effects

The event log reconstructs campaign state.

It does not replay:

* Model calls.
* Shell commands.
* Git pushes.
* External API calls.
* Build processes.

Attempts are retried explicitly.

External effects are idempotent and reconciled.

---

## 2.7 Protocol semantics stay outside the kernel

The kernel should not know every future domain concept.

Universal kernel concepts:

```text
Campaign
Objective
WorkflowInstance
WorkItem
Attempt
Artifact
Evaluation
Judgment
Decision
```

Protocol-specific concepts:

```text
Research:
  Finding
  Claim
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

Promote something into the kernel only after real reuse appears.

---

# 3. MVP boundaries

## 3.1 In scope

The MVP includes:

* Multiple actual machines.
* Machines joining after campaign start.
* Machines disappearing while work is active.
* Controller failover.
* Object-store synchronization.
* Local SQLite on every machine.
* Work claims and fencing.
* Content-addressed artifacts.
* Multi-provider generators.
* Multi-provider judges.
* Deterministic oracle execution.
* Distributed Research workflow.
* Distributed Change workflow.
* Crash recovery.
* Budget enforcement.
* Safe candidate execution.
* Git integration.
* Existing code-host CI/merge machinery.

---

## 3.2 Explicitly deferred

Do not initially implement:

* P2P networking.
* CRDTs.
* Multi-writer campaign sequencing.
* Raft/Paxos.
* PostgreSQL/DynamoDB.
* Cross-region campaigns.
* Statistical performance search.
* Large evolutionary populations.
* Arbitrary user-defined workflow DSL.
* Generic graph database.
* Custom merge queue.
* Custom code-review UI.
* Automatic learned model routing.
* Hostile multi-tenant execution.
* Completely open-ended recursive campaign generation.

P2P and CRDTs remain possible later, but neither is required for initial correctness.

---

# 4. Distributed topology

Every node runs the same Rust binary.

```text
pi-campaign-node
  |
  +-- sync engine
  +-- SQLite projector
  +-- controller capability
  +-- worker scheduler
  +-- model runner
  +-- judge runner
  +-- oracle runner
  +-- sandbox
  +-- Git support
  +-- artifact cache
```

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

Another may be primarily a judge runner.

No machine has to implement every role.

---

# 5. Durable object-store substrate

## 5.1 MVP backend

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

Conceptually:

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

Exact paths can evolve before wire compatibility is frozen.

---

# 6. Campaign event log

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

---

# 7. Campaign controller

## 7.1 Controller is a role, not a host

Exactly one controller instance holds the campaign lease at a time.

```json
{
  "instance_id": "machine-a/boot-123",
  "fence": 42,
  "lease_until": "...",
  "operation_id": "..."
}
```

If Machine A disappears:

```text
controller lease expires
Machine C acquires fence 43
Machine C syncs campaign log
Machine C resumes control
```

The campaign does not depend on A returning.

---

## 7.2 Fencing

All authoritative controller decisions carry the current controller fence.

A stale controller with fence 42 cannot commit after fence 43 has been acquired.

Correctness depends on fencing.

Lease time is primarily a liveness mechanism.

Use conservative lease durations and synchronized clocks for MVP, but do not make clock precision a correctness assumption.

---

## 7.3 Controller responsibilities

The controller answers:

```text
What remains unresolved?

Which work is ready?

Which work should be created?

Which submitted results are valid?

Which evaluations are required?

Are semantic judgments sufficient?

Is there material disagreement?

Can another oracle resolve it?

Should another bounded attempt be created?

Should a candidate advance?

Has a workflow completed?

Has the campaign exceeded budget?
```

The controller should not execute expensive tasks itself.

It emits work into the distributed fleet.

---

# 8. Work model

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

---

# 9. Distributed work claiming

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

## 9.1 Worker disappearance

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

---

# 10. Machine identity and presence

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

# 11. Local SQLite projection

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

## 12.1 RunManifest and RunTrace

Every generator/judge invocation produces two separate records.

### RunManifest

Immutable starting configuration:

```text
campaign
workflow
work item
provider
model
prompt version
controller version
tool schemas
source revision
context artifacts
environment
tool policy
network policy
budget
reasoning/sampling configuration
```

### RunTrace

Dynamic execution trajectory:

```text
messages
tool calls
tool results
retrievals
shell commands
outputs
truncations
policy denials
provider IDs
token use
cost
errors
```

Initial context and dynamic trajectory are different artifacts, a distinction explicitly called out in the feedback.

---

# 13. Model-provider layer

The MVP deliberately supports multiple providers because judge/model diversity is part of the control model.

Conceptual interface:

```rust
trait ModelProvider {
    async fn execute(
        &self,
        request: ModelRequest
    ) -> Result<ModelResponse>;
}
```

Required metadata:

```text
provider
exact model identifier
model configuration
system-prompt digest
tool schema version
context digest
provider request ID
token usage
settled cost
```

Profiles describe usage:

```text
generator:research
generator:code
judge:semantic
judge:critic
judge:adjudicator
synthesizer
```

Profiles may point to different providers/models.

---

# 14. Judge ensemble

Semantic decisions use multiple independent judgments where policy requires them.

A `Judgment` contains:

```text
subject
judge identity
context digest
verdict
evidence considered
rationale artifact
material objections
requested follow-up
```

A judgment is an observation, not truth.

---

## 14.1 No blind majority voting

Policy is evidence-aware.

Example:

```text
trusted deterministic failure
    -> reject

validated counterexample
    -> reject

material judge objection with falsifiable claim
    -> investigate

judges agree and no contrary evidence
    -> semantic gate may pass

material disagreement remains
    -> adjudicate or obtain additional evidence
```

---

## 14.2 Adjudication

An adjudicator receives:

* The exact question.
* Original artifacts.
* Existing evaluations.
* Competing judgments.
* Relevant deterministic evidence.

It can decide:

```text
accept position
reject position
request another oracle
create bounded follow-up work
leave unresolved
```

Adjudication depth is strictly bounded.

---

# 15. Authority policy

Human review is not required for routine operation.

Campaign configuration declares authority.

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

The same runtime supports both.

For MVP testing, campaigns should run autonomously against a safe branch/repository so human approval is not required to prove the control loop.

Humans may grade experiment results afterward. That is measurement, not workflow authority.

---

# 16. Workflow protocol model

A workflow protocol defines:

1. Input contract.
2. How initial work is created.
3. What outputs attempts may produce.
4. How those outputs are evaluated.
5. How additional bounded work may be created.
6. Completion semantics.

Do not implement a generic workflow DSL.

Implement concrete `research` and `change` modules first.

Only extract a formal trait after the second implementation demonstrates the true shared boundary.

---

# 17. MVP Workflow A: Distributed Research

## 17.1 Goal

Prove that multiple machines and model profiles can collaboratively produce a better evidence-backed answer than one monolithic research session.

Example:

```text
Determine why component X experiences p99 spikes under workload Y.
```

---

## 17.2 Initial decomposition

The controller creates independent research work.

For example:

```text
R1 source/code-path investigation
R2 runtime/locking investigation
R3 memory/cache investigation
R4 syscall/IO investigation
R5 alternative-explanation investigation
```

These should intentionally be somewhat independent initially to reduce correlated anchoring.

Different machines claim them in parallel.

---

## 17.3 Research attempt outputs

A research worker may produce:

```text
Findings
Observations
Claims
Evidence artifacts
Source references
Open questions
Potential falsification methods
Suggested follow-ups
```

The research protocol initially uses a deliberately small structured schema.

No generic epistemics graph is necessary.

---

## 17.4 Critic judges

Once findings arrive, the controller creates judgment work.

Judges assess:

```text
Does the evidence support the conclusion?

Are competing explanations still plausible?

Is the conclusion material to the root objective?

What evidence would discriminate among explanations?

Is the finding contradicted elsewhere?
```

Judges should run on different machines/models where capacity permits.

---

## 17.5 Discriminating work

Suppose:

```text
Researcher A:
  lock contention dominates.

Researcher B:
  LLC misses dominate.

Researcher C:
  negative lookups dominate.
```

The controller should not ask a meta-model to guess which sounds best.

It can create:

```text
E1 collect lock-wait histogram
E2 collect hardware-counter profile
E3 split positive/negative lookup latency
```

Those become distributed oracle or research work.

The system uses disagreement to generate information.

---

## 17.6 Synthesis

Once the evidence reaches the workflow's configured stopping rule, a synthesis judgment produces:

```text
Conclusions
Evidence supporting each conclusion
Rejected explanations
Material uncertainty
Unresolved questions
Suggested next workflow
```

---

## 17.7 Completion

Example bounded completion policy:

```text
all required questions synthesized

AND

no material contradiction remains unresolved

OR

budget exhausted and all unresolved items are explicit
```

No human "accept report" button is required.

---

# 18. MVP Workflow B: Distributed Change

The first concrete Change workload is a bounded semantic migration.

This is chosen because it provides:

* Finite scope.
* Parallelizable work.
* Semantic judgment.
* Mechanical validation.
* Integration.
* A measurable completeness criterion.

`Target` is protocol-specific rather than a universal kernel type.

The feedback correctly identified a finite target universe as essential for migration completeness.

---

## 18.1 Deterministic target discovery

A trusted discovery mechanism produces:

```text
source revision
rule digest
target ID
path
semantic locator
context digest
```

Example target:

```text
Call site using generic Error type at module X/function Y.
```

---

## 18.2 Autonomous classification

The treatment taxonomy is defined by campaign configuration.

Judges classify each target.

Example:

```text
retryable
permanent
public/client-visible
internal
redacted
context-preserving
```

Material disagreement triggers adjudication or focused investigation.

The system does not need a human to classify every target.

For the MVP pilot, choose a migration with few or no subjective exemptions.

---

## 18.3 Autonomous grouping

The controller groups compatible targets into bounded work items using:

```text
file/path overlap
treatment class
dependency relationship
write-scope collision
expected context size
```

The grouping itself can be reviewed by judges.

Hard caps prevent giant tasks.

---

## 18.4 Parallel code generation

Suppose 40 target groups are ready.

Multiple workers claim them simultaneously:

```text
Machine A -> W1
Machine B -> W2
Machine C -> W3
Machine D -> W4
...
```

Workers operate against the same campaign base or a defined base epoch.

---

# 19. Candidate sandbox

Agent generation and candidate execution are separated from trusted daemon state.

Candidate sandbox receives:

```text
source files
task context
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

Repository content is untrusted model input.

Model API access happens through the generation/controller layer, not candidate processes.

---

## 19.1 Delta validation

After an agent finishes, the daemon validates the actual filesystem delta.

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

Reject anything outside the task's write policy.

The feedback correctly treats this as a security boundary rather than a prompt convention.

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
   * delta digest
6. Creates a Git bundle/patch artifact for transfer.

Candidate records are immutable.

A rebase or repair creates a new candidate.

---

# 21. Distributed candidate evaluation

Evaluation is also schedulable work.

A candidate may require:

```text
compile evaluator
unit-test evaluator
migration-specific evaluator
static analyzer
platform-specific evaluator
```

These may run on different machines.

Example:

```text
Candidate C17

Linux compile       -> Machine A
ARM tests           -> Machine C
Static analysis     -> Machine D
Semantic judges     -> Machines E/F/G
```

The controller waits until policy-required evidence is present.

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

Evaluator configuration is trusted campaign configuration. The feedback correctly identifies it as a trust root rather than ordinary agent work.

MVP evaluators are deterministic:

```text
PASS
FAIL
ERROR
TIMEOUT
```

Statistical performance decisions are deferred to Search.

---

# 23. Semantic candidate judgment

After mechanical checks pass, independent semantic judges can assess questions not completely captured by executable checks.

Example:

```text
Does this migration preserve the requested error semantics?

Does the change introduce an unsupported externally visible behavior?

Has the agent actually applied the intended treatment class?
```

Mechanical failure overrides semantic approval.

A judge producing a concrete potential defect may trigger Verify-like follow-up work even before the standalone Verify protocol exists.

---

# 24. Integration

Do not build a merge queue.

Use existing code-host integration machinery. The feedback correctly notes both the existing prior art and correctness problems with simplistic custom batching.

A publisher/integration worker can:

1. Claim a publish job.
2. Materialize the candidate.
3. Push deterministic branch name.
4. Create/update PR idempotently.
5. Record external identity.
6. Let existing required checks/merge queue operate.
7. Sync state back into campaign log.

Workers need not all have code-host credentials.

Publishing can be a capability advertised by a trusted subset.

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

After integrations:

```text
rerun deterministic target discovery
```

Campaign completion requires:

```text
every target resolved according to protocol

AND

final discovery finds no unclassified legacy targets
```

This catches omissions introduced by poor task generation.

---

# 25. Crash recovery and unknown outcomes

Distribution does not create this requirement. It makes it more obvious.

Even one node crosses non-atomic boundaries between:

```text
SQLite
filesystem
S3
model providers
processes
Git
code host
```

The feedback correctly moved crash recovery into the first implementation.

Required principles:

```text
at-least-once attempts
idempotent side effects
explicit unknown outcomes
startup reconciliation
no exactly-once claim
```

---

## 25.1 Worker crash cases

Test:

```text
worker crashes before model call
worker crashes during model call
model call succeeded but response was lost
artifact uploaded but submission absent
submission uploaded but controller has not committed it
worker returns after lease reclaimed
```

---

## 25.2 Controller crash cases

Test:

```text
controller writes event but fails before head CAS
head CAS succeeds but response is lost
controller expires while processing submissions
new controller takes over from stale SQLite projection
stale controller later returns
```

Fencing must prevent stale authoritative writes.

---

# 26. Budgets and backpressure

Budgets are campaign-wide and work-specific.

Track:

```text
model tokens
settled model cost
attempt count
parallelism
CPU seconds
wall time
artifact bytes
oracle cost
judge count
adjudication rounds
generated descendants
```

Hard limits:

```text
max campaign cost
max workflow cost
max work-item attempts
max parallel work
max judge invocations per decision
max adjudication rounds
max generated follow-ups
max workflow depth
deadline
```

Controller behavior at a hard limit:

```text
stop creating new work
allow required cleanup/reconciliation
produce explicit unresolved result
```

No silent budget expansion.

---

# 27. Causality and recursion controls

Every generated action carries:

```text
campaign_id
workflow_id
root_cause_id
cause_id
generation
attempt_number
maximum_attempts
policy_version
```

The scheduler rejects repeated processing of the same cause under the same policy.

This prevents:

```text
judge asks for research
research triggers judge
judge asks identical research
...
```

The prior feedback correctly treats bounded recursive causality as a necessary invariant.

---

# 28. Security model

MVP threat model:

> Trusted internal worker fleet executing potentially incorrect or prompt-injected generated code.

Not:

> Hostile multi-tenant arbitrary code execution service.

Therefore process-level Linux sandboxing can be an MVP mechanism, but it is not marketed as a strong multi-tenant isolation boundary.

Security domains:

```text
1. trusted daemon
2. model/controller layer
3. candidate execution sandbox
4. evaluator/oracle sandbox
```

Candidate sandboxes:

* No credentials.
* No hidden evaluator artifacts.
* No shared writable caches.
* No network.
* Resource limits.
* Output limits.

Evaluator sandboxes:

* No model access.
* No network.
* Immutable evaluator inputs.
* Separate writable area.
* Stricter resource limits.

---

# 29. Observability

The system itself needs measurable distributed behavior.

Record:

```text
work-ready latency
claim latency
claim collision rate
worker utilization
lease renewal rate
lease expiry/reclamation count
controller failovers
controller event-commit latency
sync lag per node
artifact transfer time
S3 requests per work item
model time
oracle time
judge time
queue depth
wasted work
stale-result count
cost per accepted result
```

For distributed scaling:

```text
speedup(N) = single-worker wall time / N-worker wall time

efficiency(N) = speedup(N) / N
```

We care about both throughput and useful throughput.

Twenty machines generating twenty incompatible or rejected changes is not success.

---

# 30. MVP milestone plan

## M0. Freeze invariants and pilot definitions

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

## M4. Controller failover

Implement:

* Controller lease.
* Controller fence.
* Head sequencing.
* Submission processing.
* Reconciliation.
* Takeover.

Acceptance scenario:

```text
Machine A controls campaign.
A creates ready work.
Workers begin execution.
A is killed.
Machine C acquires controller.
C reconstructs state.
Existing valid work continues.
C processes completions.
A returns and cannot commit stale decisions.
```

This is a mandatory MVP milestone.

---

## M5. Multi-provider model runtime

Implement:

* Provider interface.
* Generator profiles.
* Judge profiles.
* Structured outputs.
* RunManifest.
* RunTrace.
* Cancellation.
* Provider request IDs.
* Usage/cost settlement.
* Unknown outcome handling.

Exit condition:

Different machines can run generators/judges from different configured providers and return immutable submissions.

---

## M6. Judge/controller decision loop

Implement:

* Judgment requests.
* Multiple judge profiles.
* Judgment persistence.
* Material disagreement detection.
* Evidence-precedence rules.
* Adjudicator.
* Bounded follow-up.
* Decision records.

Exit condition:

A campaign decision can require multiple independent judgments, reject majority consensus when deterministic contrary evidence exists, and request bounded additional work.

---

## M7. Distributed Research workflow

Implement:

* Research workflow spec.
* Initial decomposition.
* Parallel researchers.
* Finding/evidence schema.
* Critic judgments.
* Discriminating follow-up work.
* Synthesis.
* Completion policy.

Required deployment:

At least three independent machines/hosts.

Required scenarios:

* Multiple research jobs execute concurrently.
* Judge jobs execute on different nodes.
* A new machine joins mid-campaign.
* A worker disappears.
* Controller moves machines.
* Final synthesis remains coherent.

Exit condition:

The distributed workflow produces a traceable evidence-backed result without human control-loop decisions.

---

## M8. Candidate sandbox and Git substrate

Implement:

* Trusted local bare repo.
* Source materialization.
* Candidate sandbox.
* No writable Git metadata.
* Delta canonicalization.
* Write-policy enforcement.
* Trusted Git tree construction.
* Candidate commit.
* Candidate bundle artifact.

Exit condition:

An agent can generate a candidate on Machine B and an evaluator on Machine D can reconstruct and evaluate the exact candidate.

---

## M9. Distributed oracle/evaluator runner

Implement:

* Evaluator manifest.
* Action identity.
* Capability routing.
* Deterministic pass/fail execution.
* Output artifacts.
* Sandboxing.
* Hidden inputs.
* Result submission.

Exit condition:

A candidate may require evaluations from several heterogeneous machines before controller policy allows it to advance.

---

## M10. Distributed Change workflow

Implement:

* Target discovery.
* Autonomous target classification.
* Judge-mediated disagreement handling.
* Autonomous grouping.
* Parallel WorkItems.
* Candidate evaluation.
* Semantic judgments.
* Candidate repair attempts.
* Integration readiness.

Required scale:

Several concurrent candidate-producing machines.

Exit condition:

A finite semantic migration completes across multiple machines without a human assigning or approving each work item.

---

## M11. Code-host integration

Implement:

* Publisher capability.
* Deterministic branch naming.
* Idempotent push.
* PR publication.
* External-state reconciliation.
* Existing CI/merge-queue integration.
* Final rediscovery.

Exit condition:

Campaign can autonomously integrate to a safe campaign branch and prove target completeness.

---

## M12. Failure-injection matrix

Automate kills/timeouts around:

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

Exit condition:

No stale actor can perform an authoritative transition and no external effect is duplicated beyond its documented at-least-once/idempotent semantics.

---

# 31. MVP acceptance criteria

The MVP is **not complete** if it only works as multiple subprocesses on one workstation.

Required distributed proof:

* At least three independent machines/VM hosts.
* Controller failover between hosts.
* Worker joins after campaign start.
* Worker disappears with active lease.
* Stale result is rejected after fencing.
* Generator jobs execute concurrently.
* Judge jobs execute concurrently.
* Oracle/evaluator jobs execute remotely.
* Local SQLite reconstruction on a fresh worker.
* Shared campaign remains coherent after failures.

Required autonomous proof:

* Human provides objective/configuration.
* Human does not assign individual work items.
* Human does not approve routine research conclusions.
* Human does not choose among ordinary candidate results.
* Judges/oracles/controller perform routine decisions.
* Campaign stops cleanly when bounds are exhausted.

Required correctness proof:

* No candidate-controlled evaluator.
* No out-of-scope accepted change.
* No stale evaluation reused for a different subject.
* No stale controller/worker commits authoritative state.
* No migration target silently disappears.
* No deterministic failure overridden by model judgment.

---

# 32. MVP experiments

## Experiment A: Distributed Research

Compare:

```text
A. One strong agent on one machine.

B. Multiple agents on one machine.

C. Distributed campaign:
   multiple researchers
   multiple judges
   deterministic oracles
   controller-directed follow-ups.
```

Measure:

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
* Controller idle/bottleneck time.

The question should have enough independently inspectable evidence that post-hoc ground truth can be assessed.

---

## Experiment B: Distributed Change

Compare:

```text
A. Direct coding agent.

B. Multiple independent coding agents without campaign coordination.

C. Distributed Change workflow.
```

Use several dozen migration targets.

Measure:

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

---

# 33. Post-MVP decision gate

Do not automatically proceed to every later feature.

After Research + Change, answer:

```text
Does distributed execution materially improve wall-clock completion?

Where does parallelism stop scaling?

Does judge diversity improve decisions or mainly increase cost?

How often does disagreement generate useful new evidence?

How trustworthy are agent-generated findings?

Does controller-created work improve outcomes?

How much work is duplicated?

Is object-store synchronization fast enough?

Is controller sequencing a bottleneck?

Are evaluator/oracle workloads the real bottleneck?

Which workflow produces the strongest differentiated value?
```

Use those results to determine follow-up order.

---

# 34. Likely follow-up: Verify workflow

Standalone use:

```text
Try to break candidate/PR X.
```

Input:

* Exact candidate.
* Claimed properties.
* Failure model.
* Existing evaluations.

Distributed challenge agents can explore:

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

Useful counterexamples include:

```text
failing test
reproducer
trace
sanitizer report
crash input
```

Controller independently reruns the artifact through an oracle before treating it as established.

Verify can run:

```text
Change -> Verify
```

or standalone against externally produced code.

---

# 35. Likely follow-up: Document workflow

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

Distributed agents can partition sources/sections, while judges check:

* Coverage.
* Contradictions.
* Unsupported statements.
* Source provenance.

Output:

```text
document
source/provenance map
coverage result
unresolved questions
```

---

# 36. Likely follow-up: Search / distributed autoresearch

This is the major scaling use case.

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

Protocol concepts:

```text
Hypothesis
Candidate
Candidate lineage
Measurement
Selection
Mutation
Combination
```

Distributed execution:

```text
Generation N

Candidate 1 -> Machine A
Candidate 2 -> Machine B
Candidate 3 -> Machine C
Candidate 4 -> Machine D
...

Evaluations:
  x86 perf -> Machine E
  ARM      -> Machine F
  memory   -> Machine G

Judges:
  model A -> Machine H
  model B -> Machine I
```

At this point add:

* Repeated measurements.
* Noise estimation.
* Interleaved baseline/candidate runs.
* Practical effect thresholds.
* Holdout workloads.
* Multiple-comparison handling.
* Pareto selection.
* Population diversity.
* Candidate lineage.
* Mutation/recombination.

Performance results should not be cached as timeless facts.

---

# 37. Likely follow-up: Recursive workflow composition

This is the transition from autonomous workflows to autonomous campaigns.

A completed workflow may propose another workflow.

Example:

```text
Research:
  discovers resize path may dominate.

Controller:
  starts focused Research.

Focused Research:
  identifies two plausible designs.

Controller:
  starts Search.

Search:
  produces C17.

Controller:
  starts Verify.

Verify:
  finds counterexample.

Controller:
  starts Change or another Search iteration.
```

Cross-workflow proposal admission uses:

```text
evidence
judgments
policy
remaining budget
existing-work overlap
root objective relevance
```

Hard bounds remain mandatory.

---

# 38. Later: learned generator/judge routing

Because model/profile identity is recorded from day one, the system can eventually learn:

```text
which generators produce candidates that survive checks
which judges predict oracle outcomes
which models find confirmed counterexamples
which providers perform best in each domain
cost/quality tradeoffs
```

Routing may then become empirical.

Do not implement model reputation before enough observations exist.

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

The initial single fenced campaign sequencer is intentionally simple.

If measurements eventually show it is a bottleneck, options include:

* One controller per workflow.
* One controller per independent objective subtree.
* Partitioned event sequencing.
* Locally decidable transitions that do not require the campaign controller.

Do not solve this before it is measured.

Model calls, compilation, testing, benchmarking, and artifact movement are far more likely initial bottlenecks.

---

# 42. Suggested implementation tree

```text
pi-campaign/
  src/
    domain/
      campaign.rs
      objective.rs
      workflow.rs
      work.rs
      attempt.rs
      evaluation.rs
      judgment.rs
      decision.rs

    distributed/
      identity.rs
      presence.rs
      controller.rs
      claims.rs
      fencing.rs

    sync/
      head.rs
      event.rs
      replay.rs
      cursor.rs

    storage/
      s3.rs
      artifacts.rs

    db/
      schema.rs
      migrations.rs
      projections.rs

    controller/
      scheduler.rs
      policy.rs
      budgets.rs
      adjudication.rs

    models/
      provider.rs
      profiles.rs
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
      outbox.rs
      reconcile.rs

    pi/
      commands.rs
      status.rs
```

Do not split into many crates until dependency boundaries make that useful.

---

# 43. Hard invariants

The implementation should enforce these from day one:

1. No worker can authoritatively complete work without the current work fence.
2. No stale controller can commit after its fence is superseded.
3. No model-generated assertion becomes truth by self-report.
4. No deterministic evaluator failure can be overridden by model consensus.
5. No candidate accesses or changes its trusted evaluator.
6. No candidate receives writable daemon Git metadata.
7. No accepted candidate contains an out-of-policy delta.
8. No evaluation applies to a different subject or evaluator identity.
9. No rebase mutates an existing candidate identity.
10. No external side effect lacks an idempotency/reconciliation path.
11. No exactly-once claim is made.
12. No campaign depends on worker presence records for correctness.
13. No machine departure event is required for recovery.
14. No shared writable build/package/compiler cache crosses trust boundaries.
15. No recursive action chain is unbounded.
16. No campaign silently exceeds a hard cost/resource budget.
17. No migration campaign completes without final target rediscovery.
18. No graph database is introduced merely because the conceptual model can be viewed as graphs.
19. No P2P/CRDT dependency is required for initial correctness.
20. No MVP is declared successful without actual multi-machine execution and failover.

---

# 44. MVP definition of done

The project has an MVP when:

### Distributed substrate

* Three or more independent machines participate.
* Fresh machine reconstructs campaign from object storage.
* Workers dynamically join and leave.
* Work claims are fenced.
* Controller fails over safely.
* Stale worker/controller results are rejected.
* Artifact/state synchronization survives crashes.

### Autonomous control

* User supplies objective, constraints, policy, and budget.
* System creates routine work.
* System routes work across machines.
* Multiple model/provider judges participate.
* Deterministic evidence has precedence.
* Controller handles routine disagreement without humans.
* Bounds stop runaway work.

### Research

* Multiple researchers run concurrently across machines.
* Critic judges run independently.
* Controller creates at least one evidence-driven follow-up.
* Final synthesis is produced autonomously.
* Full provenance is available.

### Change

* Finite target universe is discovered.
* Targets are classified/grouped without manual assignment.
* Several candidate tasks run in parallel.
* Candidates are mechanically evaluated.
* Semantic judge ensemble evaluates surviving candidates.
* Integration completes through existing code-host machinery.
* Final rediscovery proves completeness.

### Failure behavior

* Controller can die and move machines.
* Worker can die mid-task.
* Unknown S3/model/code-host outcomes reconcile safely.
* No duplicated authoritative effect appears under fault injection.

### Measurement

We can compare:

```text
single-agent
single-machine multi-agent
distributed multi-machine campaign
```

on:

* wall-clock time,
* correctness,
* useful throughput,
* cost,
* wasted work,
* scaling efficiency.

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

The distributed campaign may then autonomously evolve into:

```text
Research workers
    characterize lookup path, locking, allocations,
    syscalls, cache behavior, workload skew

Judges
    compare explanations and identify missing evidence

Oracle workers
    run perf, traces, benchmarks, targeted experiments

Controller
    admits supported hypotheses

Search workers
    generate many competing implementations

Evaluation workers
    test correctness and performance on heterogeneous hosts

Judges
    interpret tradeoffs and identify suspicious results

Verification workers
    attack top candidates

Oracle workers
    reproduce or reject counterexamples

Controller
    rejects, mutates, combines, or advances candidates

Integration worker
    materializes the final validated candidate

Code host
    runs exact integration checks

Campaign
    declares objective satisfied or reports why it could not converge
```

The machines involved can change throughout the campaign.

No individual machine is the system.

The durable campaign is the system.

Local SQLite makes each participant fast and independently useful.

Shared object storage provides durable rendezvous, immutable artifacts, and the minimum serialization needed for correctness.

That is the architecture the MVP should now be built to prove.
