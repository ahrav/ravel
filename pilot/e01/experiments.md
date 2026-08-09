# E01 A/B/C experiment precommitment — PRIVATE, UNSTABLE

E01 pilot only; do not build tooling against this file. This document
precommits all six Research/Change A/B/C treatment cells, the schedule,
units, isolation/reset rules, outcomes, and decision rules **before any
measured run**. Amendments require a new Git revision and a new
`pilot/e01/` content digest recorded before any affected run; results from
before and after an amendment are never pooled. No runtime code, schema,
statistics framework, or workflow machinery is defined here (E01 AC8).

## 1. Shared identities and references

- **Subject:** `ahrav/hyperfine` at pinned revision
  `f12f3d9f86f3643b3b7deace5e160b1f0f44d2b7`
  (`environment.yaml` `subject.starting_revision`). Every run of every cell
  starts from this revision.
- **Environment / authority / trust roots / providers:**
  [`environment.yaml`](environment.yaml). All six `role_profiles` are fixed
  there; no cell may vary provider, model, `reasoning_effort`, or token
  ceilings.
- **Research contract (Task 2):** [`research.md`](research.md) — frozen
  question (§1), evidence boundary (§2), reference set (§5), blinded
  grading (§6), outcome classes (§7), recording rules (§8).
- **Change contract (Task 3):** `change/contract.md`, trusted
  `change/discover.sh`, frozen inventory `change/targets.jsonl`,
  `change/fixtures/`. Referenced by these precommitted paths; their exact
  content identity is fixed by the final `pilot/e01/` content digest
  recorded in task ravel-q3w.4 completion evidence.
- **Budgets:** [`budgets.yaml`](budgets.yaml) — one shared flat budget
  file. Per-run deadline: `deadline_run_ab_hours` for A/B cells,
  `deadline_run_c_hours` for C cells. All other caps apply identically to
  every cell.

## 2. Units and interference boundary

- **Treatment/application unit = analysis unit = one complete assigned
  run.** A run is one full execution of one cell from fresh workspace
  through its final output (Research: synthesized answer; Change: final
  rediscovery result).
- **n = 5 independent runs per cell**, 6 cells, 30 runs total. Nested
  targets, conclusions, work items, and agents are **not** independent
  replicates, however many there are; they are measured within their run
  and analyzed only as per-run aggregates.
- **Interference boundary:** no two runs ever overlap in time on shared
  mutable state. Runs are strictly serialized on the campaign branch, the
  S3 prefix, and the machine pool; each run gets its own S3 run prefix
  under `e01/` and its own workspaces.

## 3. Schedule (seed-recorded blocked randomization)

Blocked randomization, 5 blocks per pilot, each block containing exactly
one A, one B, and one C run in randomized order. Blocks execute in order;
runs within a block execute in the listed order.

- **Seed:** `1297367895` (drawn at authoring time via
  `od -An -N4 -tu4 /dev/urandom`).
- **Derivation (recorded for audit, run once at authoring time):**

  ```python
  import random
  random.seed(1297367895)
  for pilot in ("Research", "Change"):
      for block in range(1, 6):
          order = ["A", "B", "C"]
          random.shuffle(order)
          print(pilot, block, "-".join(order))
  ```

- **Resulting fixed order:**

  | Block | Research | Change |
  | --- | --- | --- |
  | 1 | C–A–B | C–A–B |
  | 2 | A–C–B | C–A–B |
  | 3 | B–A–C | A–B–C |
  | 4 | C–A–B | C–A–B |
  | 5 | B–C–A | A–B–C |

- **Combined serialized order (fixed):** the two pilots never
  interleave. All five Research blocks execute first (runs 1–15), then
  all five Change blocks (runs 16–30), each block in the table order
  above. This single 30-run sequence is the only valid execution order.

- **Nuisance blocks named:** machine pool composition, time window,
  provider quota/throttle state, and source reset state. Each block runs
  on the same machine pool within one contiguous time window, and the full
  reset procedure (§5) runs between every pair of runs, so these nuisance
  states are balanced across treatments within a block rather than
  confounded with one treatment.

## 4. Run count, stopping rule, and failure handling

- **Run-count rationale (fixed, precommitted):** n = 5 per cell supports a
  direction-of-effect median comparison with sign-level sensitivity: a
  uniform 5-vs-0 per-block ordering corresponds to a one-sided sign-test
  p ≈ 0.03. This is acknowledged as a small pilot; the decision rules in
  §6/§8 are precommitted and not adaptive, and no statistical framework is
  built.
- **Stopping rule (complete-unit):** stop after exactly 5 complete
  assigned runs per cell, or when the campaign deadline
  (`deadline_campaign_days`) or campaign spend cap (`campaign_spend_usd`)
  is reached, whichever comes first. Runs unfinished at a hard limit are
  recorded `unresolved` per `budgets.yaml` hard-limit behavior. No
  adaptive stopping, no run-count changes, no extension after peeking at
  results.
- **`unresolved` aggregation (fixed):** every hard-limit stop emits the
  explicit `unresolved` run result required by `budgets.yaml`
  hard-limit behavior; the two limit families differ only in whether the
  observation still has numeric values. A *per-run* cap exhausting
  mid-run ends the run as a **complete** observation: it carries the
  `unresolved` result label *and* numeric outcomes computed from work
  integrated/graded up to the stop — unfinished work counts against it
  (omissions, zero resolutions, `unresolved` work items). For Change
  runs, trusted final rediscovery is a measurement step executed by the
  trusted side against a **fresh clean checkout of the run's
  campaign-branch tip** (the integrated end state; `discover.sh`
  refuses dirty worktrees, and un-integrated candidate work is never
  measured) for **every** complete run,
  including per-run-cap-stopped runs (this is the `budgets.yaml`
  hard-limit "required cleanup/reconciliation"), so every complete run
  carries a pass/fail rediscovery result; a run stopped with non-exempt
  unresolved targets simply fails it, and a rediscovery invocation that
  produces no valid verdict (nonzero exit, rule-digest mismatch against
  `change/targets.jsonl`, or any other error) is recorded **fail** for
  that run — never blank, never re-judged. A *campaign*
  hard limit (`deadline_campaign_days`, `campaign_spend_usd`) stopping
  a run mid-flight or preventing it from starting leaves that run with
  no numeric outcome values, and such runs are never imputed, zeroed,
  worst-cased, or excluded-by-choice. **Precedence when both limit
  families fire during one run (fixed):** the campaign limit wins — the
  run is `unresolved` with no numeric values whenever a campaign hard
  limit is reached before the run's outcomes (including final
  rediscovery) are fully measured, regardless of any per-run cap that
  also fired. The §6/§7 decision-rule medians
  are defined only over exactly 5 complete runs per cell; if any cell of
  a pilot has fewer than 5 complete runs when the campaign stops, that
  pilot's precommitted outcome is **Inconclusive (budget-stopped)**,
  recorded with per-cell complete-run counts.
- **Failure handling:** crashes, errors, timeouts, and budget exhaustion
  remain **assigned treatment outcomes** of their run. They are never
  discarded, never retried as fresh observations, never silently
  replaced. (The `attempts_per_work_item` cap governs retries *inside* a
  run; the run itself is one observation regardless.)

## 5. Isolation and reset (all cells, both pilots)

- **Workspace:** every agent in every run gets a fresh workspace checked
  out at the pinned revision; no workspace survives across runs.
- **Caches:** no shared writable build/package/compiler cache crosses a
  trust boundary (§43 invariant 14). Agents in one run may not share a
  writable cache with judges, evaluators, or agents of another run.
- **Candidates and trust roots:** candidate write scopes are exactly those
  in `change/contract.md`; trust roots in `environment.yaml` are never
  candidate-writable. Research treatments are read-only against the frozen
  tree (`research.md` §2).
- **External state:** each run writes only under its own S3 run prefix
  below `e01/` and (Change) its own `campaign/e01/*` branch per
  `environment.yaml` branch policy. Production branches are never touched.
- **Reset between complete runs:** delete all run workspaces; reset the
  campaign branch to the pinned revision; delete the finished run's S3 run
  prefix working area (measurement artifacts are retained outside it);
  then (Change) re-run trusted `change/discover.sh` and confirm the target
  count matches `change/targets.jsonl` before the next run starts.

## 6. Research pilot (docs/mvp-outline.md §32 Experiment A)

**Input (all cells):** the frozen question, `research.md` §1, against the
pinned revision; evidence boundary `research.md` §2. **Output (all
cells):** one single synthesized answer per run, recorded with provenance.

| Attribute | A | B | C |
| --- | --- | --- | --- |
| Agents / machines | 1 agent, 1 machine | 4 agents, 1 machine | Exactly 3 independent machines/VM hosts (distinct hosts; subprocesses on one host do not qualify) and exactly 7 agents: 1 active controller + 2 judge agents on host 1; 2 researcher agents on each of hosts 2–3 (4 researchers total). On controller failover the takeover host inherits this layout: the controller role restarts as exactly one new agent instance on host 2 (fixed), every other agent continues unchanged in role and placement, and the 7-agent role composition is otherwise identical before and after failover |
| Role profiles used (environment.yaml) | `generator:research` (×1); exactly one final `synthesizer` call renders the answer | `generator:research` (×4); exactly one final `synthesizer` call merges the thread reports | `generator:research` (×4 researcher agents); `judge:semantic` (×1) and `judge:critic` (×1) judge agents; `judge:adjudicator` calls only to resolve a semantic/critic disagreement; exactly one final `synthesizer` call. `generator:code` unused; the controller makes model calls only through the calls listed here |
| Assignment & visibility | Sees everything: whole question, whole frozen tree | Disjoint static partitions = the four separable threads of `research.md` §1 (calibration, subtraction, clamping, warning surfaces), one per agent; each agent may read the whole frozen tree but sees only its own thread and workspace, never other agents' outputs | Controller-directed: agents see only their assigned work item plus controller-provided context |
| Communication | None (single agent) | None — independent agents, no coordination, no shared workspace view (§32 Experiment A treatment B) | Only controller-mediated messages/artifacts; no direct agent-to-agent channels |
| Integration | The agent's findings become the single answer via the run's one `synthesizer` call (same single synthesis step as B/C) | One `synthesizer` profile call merges the four independent thread reports into the single answer; no cross-agent iteration | Controller-directed synthesis via the run's one `synthesizer` call |
| Follow-ups / depth | Within `budgets.yaml` caps | Within `budgets.yaml` caps | Controller-created follow-ups, bounded by `generated_followups_per_run` and `workflow_depth_levels` |
| Failover evidence | n/a | n/a | Required once per run at a fixed injection point: kill the active controller immediately after it records the second completed work item of the run (deterministic work-progress event, not a free choice); record takeover by another host (§43 invariant 20) |
| Isolation / reset | §5 | §5 | §5 |
| Run count | 5 | 5 | 5 |
| Budget reference | `budgets.yaml`, `deadline_run_ab_hours` | `budgets.yaml`, `deadline_run_ab_hours` | `budgets.yaml`, `deadline_run_c_hours` |

**Outcomes (verbatim §32 Experiment A measures) and calculation rules** —
grading uses **only** the `research.md` blinded contract (§4–§8); no
treatment self-report anywhere (§43 invariant 3):

| Measure | Unit | Calculation rule (one line) |
| --- | --- | --- |
| Wall-clock time | hours/run | run start (first agent action) to final synthesized answer |
| Supported conclusion count | conclusions/run | `research.md` §7 `supported` count over the run's deduplicated conclusions |
| Material omission rate | fraction/run | `research.md` §7 `omitted` reference items ÷ non-struck reference-set size |
| Incorrect conclusion rate | fraction/run | §7 `incorrect` ÷ graded conclusions in the run |
| Useful evidence artifacts | count/run | artifacts cited by at least one `supported` conclusion's checkable citation |
| Number of discriminating experiments | count/run | distinct follow-up investigations whose recorded evidence changed a conclusion's outcome class |
| Cost | USD/run | summed provider spend attributed to the run |
| Model invocations | calls/run | provider calls counted against `model_calls_per_run` |
| Duplicate work | conclusions/run | §8 duplicate-suppression count for the run |
| Scaling efficiency | ratio | (per-run supported count ÷ A-cell median supported count) ÷ (agent count ÷ 1); agent count fixed per cell: A=1, B=4, C=7 |
| Controller idle/bottleneck time | hours/run | C only: wall-clock with zero in-flight agent work while un-dispatched work exists; 0 by definition for A/B |

**Zero denominators (fixed):** a complete run with zero graded
conclusions records incorrect conclusion rate = 1 (worst case). If the
non-struck reference set is empty (all items struck under `research.md`
§8), material omission rate = 0 for every run of every cell — nothing
can be omitted — so the decision rule stays total. Any
other ratio above whose denominator is 0 (including a zero A-cell
median in scaling efficiency) is recorded `undefined`; `undefined`
values are descriptive only, never imputed, and never enter the
decision rule.

**Primary outcome family (the one per-pilot family):** graded conclusion
quality — supported count, incorrect rate, omission rate per `research.md`
§7. All other measures above are descriptive; no multiplicity rule is
needed because only the primary family drives the decision.

**Decision rule (medians over the 5 runs per cell, within budget):**

- **Success:** median C supported count > median A supported count, AND
  median C incorrect rate ≤ median A, AND median C omission rate ≤
  median A.
- **Failure:** median C supported count < median A, OR C is strictly worse
  than A on both incorrect rate and omission rate.
- **Inconclusive:** anything else.

## 7. Change pilot (docs/mvp-outline.md §32 Experiment B)

**Input (all cells):** the pinned revision plus the frozen target
inventory `change/targets.jsonl`; one fixed semantic treatment and
resolved condition per `change/contract.md`. Correctness and completeness
come **only** from trusted `change/discover.sh`, the trusted evaluators
(`environment.yaml` / `change/contract.md`), and final rediscovery — never
from treatment self-report (§43 invariant 3).

| Attribute | A | B | C |
| --- | --- | --- | --- |
| Agents / machines | 1 coding agent, 1 machine | 4 independent coding agents, 1 machine | Exactly 3 independent machines/VM hosts (distinct hosts; subprocesses on one host do not qualify) and exactly 7 agents: 1 active controller + 2 judge agents on host 1; 2 worker agents on each of hosts 2–3 (4 workers total). On controller failover the takeover host inherits this layout: the controller role restarts as exactly one new agent instance on host 2 (fixed), every other agent continues unchanged in role and placement, and the 7-agent role composition is otherwise identical before and after failover |
| Role profiles used (environment.yaml) | `generator:code` (×1) | `generator:code` (×4) | `generator:code` (×4 worker agents); `judge:semantic` (×1) and `judge:critic` (×1) judge agents; `judge:adjudicator` calls only to resolve a semantic/critic disagreement. `generator:research` and `synthesizer` unused; the controller makes model calls only through the calls listed here |
| Assignment & visibility | Sees everything: full inventory, whole workspace | Disjoint static partitions: `targets.jsonl` sorted by target ID, split into 4 contiguous quarters (remainder to the last quarter), one per agent; each agent sees only its own partition and workspace | Controller-directed claiming: workers see only their assigned targets plus controller-provided context |
| Communication | None (single agent) | None — no coordination, no shared workspace view | Only controller-mediated messages/artifacts; no direct agent-to-agent channels |
| Integration | Autonomous safe integration to the run's `campaign/e01/*` branch per `environment.yaml` authority (no approval gate) | Each agent works an independent branch; branches integrate to the campaign branch autonomously in fixed target-ID order; a merge conflict counts as an integration-conflict outcome for every target in the conflicting candidate | Controller-directed integration to the campaign branch through the judge/evaluator path in `change/contract.md`; conflicts count as integration-conflict outcomes |
| Follow-ups / depth | Within `budgets.yaml` caps | Within `budgets.yaml` caps | Controller-created follow-ups, bounded by `generated_followups_per_run` and `workflow_depth_levels` |
| Failover evidence | n/a | n/a | Required once per run at a fixed injection point: kill the active controller immediately after it records the second completed work item of the run (deterministic work-progress event, not a free choice); record takeover by another host (§43 invariant 20) |
| Isolation / reset | §5 | §5 | §5 |
| Run count | 5 | 5 | 5 |
| Budget reference | `budgets.yaml`, `deadline_run_ab_hours` | `budgets.yaml`, `deadline_run_ab_hours` | `budgets.yaml`, `deadline_run_c_hours` |

**Outcomes (verbatim §32 Experiment B measures) and calculation rules:**

| Measure | Unit | Calculation rule (one line) |
| --- | --- | --- |
| Correctly resolved targets | targets/run | targets meeting the `change/contract.md` resolved condition with all trusted evaluators passing |
| Wall-clock completion | hours/run | run start to final rediscovery result |
| Coverage omissions | targets/run | non-exempt inventory targets with no integrated resolution at run end |
| Semantic correction rate | fraction/run | candidates revised or rejected on semantic-judge verdict ÷ candidates judged |
| Candidate rejection rate | fraction/run | candidates rejected (evaluator or judge) ÷ candidates produced |
| Integration conflict rate | fraction/run | integration attempts ending in conflict ÷ integration attempts |
| Wasted work | attempts/run | candidate attempts producing no integrated change |
| Cost per resolved target | USD/target | run provider spend ÷ correctly resolved targets |
| Worker utilization | fraction/run | agent time on assigned targets ÷ total agent wall-clock |
| Scaling efficiency | ratio | (per-run resolved targets ÷ A-cell median resolved targets) ÷ (agent count ÷ 1); agent count fixed per cell: A=1, B=4, C=7 |
| Final rediscovery result | pass/fail | trusted `change/discover.sh` rerun at run end reports zero non-exempt unresolved legacy targets (§43 invariant 17) |

**Zero denominators (fixed):** any ratio above whose denominator is 0
for a run — including cost per resolved target with zero resolved
targets and scaling efficiency with a zero A-cell median — is recorded
`undefined`; `undefined` values are descriptive only, never imputed,
and never enter the decision rule (which uses only raw resolved-target
counts and the rediscovery pass/fail).

**Primary outcome family:** target resolution — correctly resolved targets
per trusted evaluators plus the final rediscovery result. All other
measures are descriptive; no multiplicity rule is needed.

**Decision rule (medians over the 5 runs per cell, within budget):**

- **Success:** median C correctly resolved targets > median A, AND every
  complete C run passes zero-non-exempt final rediscovery.
- **Failure:** median C correctly resolved targets < median A, OR any
  complete C run fails final rediscovery.
- **Inconclusive:** anything else.

## 8. Autonomy clause

Routine treatment execution — Research decomposition, follow-up creation,
synthesis, and safe campaign-branch Change integration — has **no human
approval gate**, per `environment.yaml` `authority.default: autonomous`
and its unchanged human-only allowlist. Post-hoc grading (`research.md`)
and final rediscovery are measurement only, never workflow gates, and no
*human* approval gate exists anywhere in routine execution (E01 AC7).
Trusted evaluator verdicts, by contrast, do gate candidate integration in
every Change cell per `change/contract.md` §4: a candidate with any FAIL
verdict is rejected automatically — a deterministic, non-overridable
machine check, not a human gate.
