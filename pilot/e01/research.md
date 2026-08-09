# E01 Research pilot & grading contract — PRIVATE, UNSTABLE

E01 pilot only, do not build tooling against this file. Hand-maintained
contract for the E01 Research A/B/C experiment: the question, evidence
boundary, reference set, and grading rules below are fixed **before any
treatment runs**. Grading is post-hoc measurement performed by LLM judges;
it is never a workflow approval gate (E01 AC7). No runtime code, schema,
or framework is defined here (E01 AC8).

Identity: subject `ahrav/hyperfine` at revision
`f12f3d9f86f3643b3b7deace5e160b1f0f44d2b7` (artifact
sha256 `65896a6acb7fdb1fcc2f5d81399bd697364aba346699311c62b9d056974b999b`),
per [`environment.yaml`](environment.yaml) and [`preflight.md`](preflight.md) §2.

## 1. Frozen question

> How does hyperfine measure shell spawning overhead, subtract it from
> benchmark timings, and guard against the correction producing negative
> times?

Reused verbatim from preflight.md §5 (Research viability gate — PASS).
Bound to the frozen revision above; every claim in scope is a claim about
that tree only.

The question supports independent initial investigations — calibration
(how spawn time is measured), subtraction (where and how it is applied),
clamping (the negative-time guard), and warning surfaces (what the user
sees) are separable threads. The preflight §5 discriminating follow-up is
the worked follow-up instance:

> When the calibrated shell-spawning time exceeds a measured benchmark
> time, is the corrected result silently clamped, or does the user see a
> warning? `src/benchmark/executor.rs:216-218` clamps each corrected
> component with `.max(0.0)`; whether `Warnings::FastExecutionTime` in
> `src/output/warnings.rs` fires for exactly this case discriminates
> "clamped with a user-facing warning" from "silently reports zero".

## 2. Input / evidence boundary

Allowed input: **file contents of the subject repository at the frozen
revision only** (`git show f12f3d9f:<path>`, or a clean checkout at that
SHA). Excluded: the web, the upstream `sharkdp/hyperfine` repo and its
issue tracker/PRs/history beyond the frozen tree, any other revision, and
model memory offered as evidence. A claim whose support lies outside this
boundary is unresolvable by definition (§7).

## 3. Evidence inventory

The preflight §5 file list. Each entry is independently inspectable with
`git show f12f3d9f:<path>` — no candidate- or model-produced summary is
needed to inspect any of them (E01 AC1):

| path | role |
| --- | --- |
| `src/benchmark/executor.rs` | `ShellExecutor` calibration, subtraction, `.max(0.0)` clamp |
| `src/benchmark/scheduler.rs` | where calibration is invoked (once per invocation, `scheduler.rs:47`, before the per-command loop — corrects preflight §5's "per benchmark" wording) |
| `src/benchmark/mod.rs` | benchmark run flow consuming corrected timings; warning triggers |
| `src/output/warnings.rs` | user-facing warning definitions and text |
| `src/cli.rs` | `--shell` / `-N` shell-selection surface |
| `README.md` | documented shell-overhead behavior |

Citations elsewhere in the tree are permitted (the boundary is the whole
frozen tree); the inventory lists where the question's evidence actually
lives.

## 4. Material-conclusion unit, equivalence, deduplication

**Unit.** One material conclusion = one falsifiable claim about subject
behavior at the frozen revision, stating subject (the mechanism named),
scope (conditions under which it holds), polarity (asserts vs denies),
and evidentiary basis: ≥ 1 `file:line` citation into the frozen tree.
A claim without a citation is not a material conclusion (it grades
unresolved if submitted; see §7).

**Equivalence.** Two conclusions are equivalent iff they name the same
mechanism (same file/function in the tree) AND assert the same behavior
at the same scope with the same polarity. Paraphrase is irrelevant.
Stronger, weaker, differently scoped, or opposite-polarity claims about
the same mechanism are **not** equivalent. If the judges disagree on
equivalence, the fixed outcome is **not equivalent** (deterministic,
conservative — never adjudicated upward after outputs are visible).

**Deduplication.** Within one treatment's deduplicated output, an
equivalence class counts once. The retained member is the most precisely
cited one (narrowest correct `file:line` range; tie → first emitted).
The number of suppressed duplicates is recorded per treatment (feeds the
mvp-outline §32 duplicate-work metric).

## 5. Reference set (treatment-independent, immutable)

Built now, in this task, directly from the frozen sources — before any
treatment exists. Every citation below was verified against
`git show f12f3d9f:<path>` on a read-only clone whose
`git archive` sha256 matches the frozen artifact checksum.

**Immutability rule:** once any labeled treatment output exists, this set
may not be edited, extended, or re-scoped. The only permitted change is
striking a defective item under the unresolved-reference rule (§8), which
strikes it from the denominator for **all** treatments equally.

**Omission denominator** = |reference set| − struck items = 7 − struck.

- **R1 — calibration mechanism.** `ShellExecutor::calibrate` runs the
  shell with an empty command 50 times (`const COUNT: u64 = 50`,
  `src/benchmark/executor.rs:234`; loop `executor.rs:249-256` invoking
  `Command::new(None, "")`) and stores the arithmetic mean of the real,
  user, and system times as `shell_spawning_time`
  (`executor.rs:287-292`, via `statistical::mean`).
- **R2 — calibration timing.** Calibration runs once per hyperfine
  invocation: `Scheduler::run_benchmarks` calls `executor.calibrate()?`
  (`src/benchmark/scheduler.rs:47`) before the loop over all benchmarked
  commands (`scheduler.rs:49-56`); one calibration is shared by every
  command in the run.
- **R3 — subtraction and clamp.** After each measured shell run,
  `ShellExecutor::run_command_and_measure` subtracts the calibrated
  spawning time component-wise (real, user, system) and clamps each
  corrected component to ≥ 0.0 with `.max(0.0)`
  (`src/benchmark/executor.rs:214-219`; the clamp is `executor.rs:216-218`).
  A negative corrected time is therefore impossible.
- **R4 — no correction without a shell.** `RawExecutor::calibrate` is a
  no-op and its `time_overhead()` returns 0.0
  (`src/benchmark/executor.rs:160-166`). `-N` / `--shell=none`
  (`src/cli.rs:204-225`) select `ExecutorKind::Raw`
  (`src/options.rs:405-406` for `-N`, `options.rs:413` for
  `--shell=none`), so no overhead subtraction occurs.
- **R5 — clamp is not silent (worked follow-up answer).** With a shell
  executor, if any corrected real time is below
  `MIN_EXECUTION_TIME = 5e-3` s (`src/benchmark/mod.rs:32`),
  `Warnings::FastExecutionTime` is pushed
  (`mod.rs:398-402`) and printed to stderr (`mod.rs:432-438`) with the
  text defined at `src/output/warnings.rs:23-30`. The check reads the
  recorded real times only (`times_real`), so a **real** time clamped to
  0.0 in a benchmark run satisfies `t < MIN_EXECUTION_TIME` and always
  produces this user-facing warning — "clamped with a warning", not
  "silently reports zero". (A clamp affecting only the user/system
  components does not trigger it.)
- **R6 — calibration failure aborts.** If the empty shell run fails,
  `calibrate` bails with "Could not measure shell execution time. Make
  sure you can run '<shell> -c \"\"'."
  (`src/benchmark/executor.rs:258-270`); hyperfine aborts rather than
  proceeding uncalibrated.
- **R7 — zero-time secondary surface.** A corrected **mean** of zero
  makes the relative-speed comparison uncomputable
  (`src/benchmark/relative_speed.rs:91-93`); when at least two results
  exist and output is not disabled (`src/benchmark/scheduler.rs:62-68`),
  the scheduler then prints a "Note" to stderr attributing this to
  calibration vs very fast commands and suggesting `--shell=none`/`-N`
  (`scheduler.rs:144-152`). Documented behavior: the
  calibration/subtraction procedure at `README.md:98-100` and the < 5 ms
  `-N` recommendation at `README.md:103-105`.

Coverage: calibration (R1, R2, R6), subtraction (R3, R4), clamping (R3),
warning behavior (R5, R7).

## 6. Grading procedure (LLM judges, treatment-blinded)

Grading happens **after** all treatments complete. No provider calls are
made in this task.

**Blinding.** Before judging, treatment outputs are stripped of treatment
identity (names, timestamps, paths, run IDs, any A/B/C markers) and
relabeled with random IDs. The ID→treatment mapping is written to a
sealed file (committed alongside the grading record but not read) and
opened only after all verdicts and equivalence decisions are recorded.

**Judges.** The two smoked provider profiles from `environment.yaml`,
settings as-is:

- Judge A: provider `bedrock-claude`, role profile `judge:adjudicator`
  (reasoning_effort xhigh, max_tokens 8192; per `environment.yaml`
  `request_fields_rejected`, bedrock-claude rejects `reasoning_effort`
  as a request field, so it applies orchestration-side only — preflight
  §3).
- Judge B: provider `bedrock-gpt`, role profile `judge:semantic`
  (reasoning_effort xhigh, max_output_tokens 8192).

One verdict each per conclusion; one equivalence decision each per
conclusion pair under test — (candidate, reference) pairs for omission
matching, and (candidate, candidate) pairs within one treatment's output
for deduplication (§4). No re-prompting,
no averaging, no third tie-breaker (the disagreement rules in §7/§8 make
one unnecessary).

**Fixed prompts** (verbatim; the only variable parts are the `{…}`
substitutions — the procedure cannot drift after outputs are visible):

Equivalence prompt:

```text
You are judging whether two conclusions about the repository
ahrav/hyperfine at revision f12f3d9f86f3643b3b7deace5e160b1f0f44d2b7
are EQUIVALENT. Equivalent means: they name the same mechanism (same
file/function) AND assert the same behavior at the same scope with the
same polarity. Paraphrase does not matter. Stronger, weaker, differently
scoped, or opposite claims are NOT equivalent.

Conclusion 1: {reference conclusion, citations included}
Conclusion 2: {candidate conclusion, citations included}

Answer with exactly one word on the first line: EQUIVALENT or DISTINCT.
Then one sentence naming the mechanism each conclusion refers to.
```

Verdict prompt:

```text
You are grading one conclusion about the repository ahrav/hyperfine at
revision f12f3d9f86f3643b3b7deace5e160b1f0f44d2b7. The ONLY admissible
evidence is file contents of that repository at that revision, quoted
below. Do not use outside knowledge; do not assume behavior not shown in
the quoted evidence.

Conclusion: {candidate conclusion, citations included}

Evidence (verbatim `git show` excerpts for every file:line the
conclusion cites, plus the contract's evidence inventory files):
{evidence excerpts}

Answer with exactly one word on the first line: SUPPORTED, INCORRECT, or
UNDECIDABLE. Then list the file:line citations that justify your answer.
SUPPORTED requires citations that substantiate the claim as stated.
INCORRECT requires citations that contradict it. If the quoted evidence
cannot decide the claim, answer UNDECIDABLE.
```

**§43-invariant guard** (no model self-report becomes truth): a judge
verdict counts only if it cites `file:line` evidence that checks out at
the frozen revision (the cited lines exist and contain what the verdict
says they contain, verifiable with `git show`). A verdict without a
checkable citation is discarded and the conclusion records as
**unresolved**.

## 7. Outcome classes (objective definitions)

- **supported** — both counted judge verdicts are SUPPORTED, each with
  checkable citations that substantiate the claim at its stated scope.
- **incorrect** — both counted judge verdicts are INCORRECT, each citing
  checkable contradicting evidence.
- **unresolved** — anything else that was graded: the judges disagree, a
  verdict is discarded by the §6 citation guard, the conclusion's own
  citation is uncheckable, or evidence within the §2 boundary cannot
  decide the claim (either judge UNDECIDABLE).
- **omitted** — a reference item (§5) with no equivalent conclusion in
  the treatment's deduplicated output.

Supported/incorrect/unresolved apply to treatment conclusions; omitted
applies to reference items. A treatment conclusion equivalent to a
reference item resolves that item (it is not omitted) and is itself
graded; extra conclusions beyond the reference set are graded too and
reported separately (they never change the denominator).

## 8. Fixed recording rules

- Judge disagreement on a verdict → **unresolved**. On equivalence →
  **not equivalent**. Never re-prompted, never averaged, never escalated.
- Duplicates within one treatment → counted once (most precisely cited
  member kept), suppressed count recorded per treatment.
- Defective reference item discovered during grading (its own citation
  fails the checkability test, or its evidence turns out to conflict) →
  recorded as **unresolved-reference**, reported separately, and struck
  from the omission denominator for all treatments equally. Struck items
  cannot be re-admitted, relabeled, or replaced after treatment results
  are visible.
- Nothing else about §1–§7 may change once labeled treatment output
  exists.

## 9. Autonomy clause

Grading is post-hoc experiment measurement only. No Research workflow
step — decomposition, follow-up creation, synthesis, or ordinary
completion — waits for grading, for a judge, or for any human approval
(E01 AC7). This matches the preflight §7 authority trace and
`environment.yaml` `authority.default: autonomous`; the human-only list
there (production pushes, upstream PRs, budgets) is unchanged by this
contract.

## 10. Compact worked example (fixture — hand-graded, no provider calls)

Reference excerpt (3 items of the real set): **R2, R3, R5**.
Denominator for this fixture = 3.

Fabricated candidate output, four conclusions:

- **C1:** "After subtracting the calibrated shell time, hyperfine floors
  each corrected component at zero using `.max(0.0)`
  (`src/benchmark/executor.rs:216-218`)."
- **C2:** "hyperfine clamps time_real, time_user and time_system after
  shell-overhead subtraction so no negative time can be reported
  (`src/benchmark/executor.rs:214-219`)."
- **C3:** "hyperfine re-runs shell calibration before every individual
  benchmarked command (`src/benchmark/scheduler.rs:47`)."
- **C4:** "The calibration count of 50 was chosen so that calibration
  noise stays below timer resolution
  (`src/benchmark/executor.rs:234`)."

Walkthrough:

1. **Equivalence under different wording:** C1 vs R3 — same mechanism
   (`ShellExecutor::run_command_and_measure` clamp), same behavior, same
   polarity, different phrasing → **equivalent**. (R3's final sentence
   — "a negative corrected time is therefore impossible" — is a stated
   consequence of the claimed behavior, not additional scope.) R3 is
   resolved.
2. **Duplicate suppression:** C2 vs C1 — same equivalence class (both ≡
   R3). C1 is kept (narrower citation, `216-218` vs `214-219`); C2 is
   suppressed. Duplicate tally for this treatment: **1** (§4).
3. **Same mechanism, different behavior → not equivalent:** C3 names the
   same mechanism as R2 (the `scheduler.rs:47` calibration call) but
   asserts different behavior (per-command vs once-per-invocation) →
   **distinct** (§4). So C3 is graded standalone, and R2 has no
   equivalent.
4. **Verdicts:**
   - C1 → both judges SUPPORTED citing `executor.rs:216-218` →
     **supported**.
   - C3 → both judges INCORRECT citing `scheduler.rs:47-56`
     (`calibrate()` precedes the command loop; nothing recalibrates
     inside it) → **incorrect**.
   - C4 → the frozen tree contains the constant (`executor.rs:234`) but
     no evidence of why 50 was chosen; the claim is undecidable within
     the §2 boundary → **unresolved**.
5. **Omissions:** R2 and R5 have no equivalent in the deduplicated output
   {C1, C3, C4} → **omitted** (2 of denominator 3).

Fixture scorecard — reference-matched: supported 1 (C1≡R3);
extra conclusions, reported separately per §7: incorrect 1 (C3),
unresolved 1 (C4); omitted 2/3 (R2, R5); duplicates suppressed 1. All four outcome classes, the equivalence rule,
the polarity/behavior distinction, and duplicate suppression are each
exercised; no real grading occurred.
