# E01 Change migration contract — PRIVATE, UNSTABLE

E01 pilot only; do not build tooling against this file. Hand-maintained
contract for the E01 Change campaign: one semantic treatment, deterministic
trusted discovery, trusted evaluators, explicit candidate write scopes, a
frozen target inventory, an orthogonal audit, and the completion rule are all
fixed here. Docs, one discovery script, and fixtures only — no migration DSL,
target framework, plugin system, evaluator runner, public API, or runtime
module (E01 AC8).

Identity: subject `ahrav/hyperfine` at revision
`f12f3d9f86f3643b3b7deace5e160b1f0f44d2b7` (artifact
sha256 `65896a6acb7fdb1fcc2f5d81399bd697364aba346699311c62b9d056974b999b`),
per [`environment.yaml`](../environment.yaml) and
[`preflight.md`](../preflight.md) §2.

## 1. Treatment and resolved condition

Exactly one semantic treatment, applied uniformly to every target:

> Replace the matched `.unwrap()` call with
> `.expect("<non-empty string literal describing the violated invariant>")`.
> Behavior is otherwise preserved: same receiver expression, same success
> value, still panics on `None`/`Err` — only the panic message changes.

The message must be a non-empty literal; `.expect("")` and any non-literal
message argument do not satisfy the treatment. No alternate treatments exist.
Inline `#[test]`/`#[cfg(test)]` sites inside matched files receive the same
treatment (the scope is path-based; see §2).

**Objective resolved condition (per target):** the target's `.unwrap()`
token no longer exists at its site; rediscovery (§2) at the candidate
revision emits no record for it.

**Objective resolved condition (campaign):** rediscovery at the candidate
revision, under the rule digest in §2, emits zero records that are not
covered by an enumerated exemption in §8.

## 2. Trusted discovery

[`discover.sh`](discover.sh) is the only discovery mechanism. It lives under
the `pilot/` trust root (never candidate-writable), is read-only over the
checkout, and refuses a dirty git worktree (untracked files would produce
phantom targets; ignored files are excluded by `rg`'s default `.gitignore`
handling).

**Rule** (verbatim from the script's `RULE-BEGIN`/`RULE-END` block): every
textual occurrence of `.unwrap()` — `rg` pattern `\.unwrap\(\)` — in Rust
files, excluding `tests/**`, `benches/**`, and `.git/**`; hidden files
otherwise included. The match is textual, so an occurrence inside a comment
or string literal would count (the frozen subject has none; §7 audit).

**Rule digest:** sha256 of the script's own `RULE-BEGIN`..`RULE-END` block
(marker lines included), recomputed at every run — any edit to the pattern or
scope changes the digest. Frozen value:
`8bac9074495a8ae283d21811a84db87e28a302f13285779d95a20fd77fdf0261`.

**Record fields** (one JSONL record per match, sorted by path, then line and
column numerically, `LC_ALL=C`):

| field | definition |
| --- | --- |
| `source_revision` | `git rev-parse HEAD` of the checkout (`"no-git"` for a plain directory, e.g. fixtures). Emitted, not pinned: the same script freezes the inventory at the frozen revision and rediscovers at candidate revisions. |
| `rule_digest` | as above |
| `target_id` | sha256 of the string `<path>:<line>:<col>:<matched line text>` (full line as reported by `rg --vimgrep`, no trailing newline) |
| `path` | repo-relative file path |
| `semantic_locator` | `<path>:<line>:<col> .unwrap() call site`; line and col are the 1-based position of the `.` as reported by `rg --vimgrep` |
| `context_digest` | sha256 of lines `max(1, line-2)`..`line+2` of the file (clamped at EOF), newlines included |

Two matches on one line yield two records distinguished by column.
Records are emitted unescaped; the script refuses any path containing `"`,
`\`, or control characters (none exist in the subject or fixtures).

**Determinism:** two runs at the same revision must produce byte-identical
output — hence identical rule digest, target IDs, paths, locators, context
digests, and count, compared field-for-field. Verified in appendix A.1.

## 3. Candidate write scope

Candidates may write only under this allowlist of the subject repository:

- `src/**`
- `build.rs`

Everything else is out of scope, in particular: the trust roots `pilot/`,
`.github/` (code-host workflow paths), `Cargo.toml`, `Cargo.lock`
(evaluator inputs pinned by `--locked`); `tests/**` and `benches/**`; and
every discovery/evaluator input, parser, control, or baseline named in Task 1
(`environment.yaml`, `preflight.sh`, `preflight.md`) or in this directory.
The allowlist prefixes share no path with any trust-root prefix, so the
scope is disjoint from the trust roots by construction.

All 41 frozen targets (§5) fall inside the allowlist — 15 files:
`build.rs` plus 14 files under `src/` (appendix A.2) — and every path is
within the Task 1 numeric limits (measured at the pin: longest path 41 ≤ 180,
deepest 3 ≤ 10; `preflight.md` §2).

## 4. Trusted evaluators

The four trusted evaluator commands and predeclared verdicts, identical to
`environment.yaml` `trusted_evaluators`, run at the subject revision under
evaluation with a clean worktree and a fresh `CARGO_TARGET_DIR`:

| command | expected |
| --- | --- |
| `cargo build --locked` | PASS |
| `cargo test --locked` | PASS |
| `cargo fmt --check` | PASS |
| `cargo clippy --all-targets --locked` | PASS |

Identity: evaluator code is the pinned Rust toolchain (rustc/cargo 1.94.1
recorded in appendix A.3); inputs are the subject tree plus `Cargo.toml`/
`Cargo.lock` (trust roots, pinned by `--locked`); the parser/control is the
process exit code — 0 is PASS, anything else (including timeout) is FAIL;
the baseline is the frozen-revision run in appendix A.3, where all four
verdicts matched their predeclared PASS. Every candidate must reproduce all
four PASS verdicts.

**Override rule (docs/mvp-outline.md §43, invariants 3–5):** a deterministic
evaluator failure can never be overridden by model consensus, judge vote, or
self-report. A candidate with any FAIL verdict is rejected, no exceptions.
Candidates cannot read or write the evaluators or this contract (§3).

## 5. Frozen target inventory

[`targets.jsonl`](targets.jsonl) is the frozen output of `discover.sh` at the
frozen revision: **41 records** across 15 files, every record carrying
`source_revision` `f12f3d9f…` and the §2 rule digest. All 41 use the single
§1 treatment (the one-treatment shape is fixed here, not per record).

Count reconciliation with Task 1: the preflight gate counted matched *lines*
(`rg -n … | wc -l` = 40 ≥ 36); the inventory counts *occurrences* — one line
(`src/export/tests.rs:15`) contains two `.unwrap()` call sites, hence 41.
Each occurrence is an independently treatable target, and both counts satisfy
the ≥ 36 gate. Per `preflight.md` §1, 21 of the 40 matched lines are inline
test code; the path-based scope decision (task 1 delegated it here) is:
**keep the path-based scope** — narrowing to strictly-non-test sites (19)
would break the "several dozen" epic requirement.

## 6. Fixtures

[`fixtures/run.sh`](fixtures/run.sh) is the single runnable check: it copies
each fixture into a plain temp directory, runs `discover.sh`, and asserts the
expectations below plus two more checks: every fixture compiles standalone
(`rustc --edition 2024`, the evaluator expectation for these single-file
fixtures — in particular the treated form `resolved.rs` still compiles) and
a dirty-worktree refusal case. Any mismatch exits nonzero. Recorded run:
appendix A.4.

| fixture | contents | expected |
| --- | --- | --- |
| `positive.rs` | one legacy `.unwrap()` | exactly one record: `source_revision` `"no-git"`, `path` `positive.rs`, `semantic_locator` `positive.rs:3:18 .unwrap() call site`, 64-hex digests/ID; two runs identical |
| `negative.rs` | lookalike non-targets only: local `unwrap` free function, `.unwrap_or(…)`, `.unwrap_or_default()`, bare-word `unwrap` in a string | zero records; file byte-identical after the run |
| `resolved.rs` | `positive.rs` after the §1 treatment | zero records → completion permitted |
| `remaining.rs` | one unresolved `.unwrap()` left behind | ≥ 1 record → completion blocked |

Constraint on `negative.rs`: the rule is textual (§2), so no line of that
file may contain the exact `.unwrap()` token — comments and strings included.

## 7. Orthogonal inventory audit

Method — independent of `discover.sh`, which it neither calls nor reproduces:

1. `git grep -nF '.unwrap()' -- '*.rs' ':!tests/*' ':!benches/*'` at the
   frozen revision — a different tool (git, not rg) and a different matching
   mode (fixed-string, not regex) over a different file walk (the git index,
   not the filesystem).
2. Per-file occurrence tally of the audit output (counting multiple
   occurrences per line), compared file-by-file against `targets.jsonl`.
3. Manual scan of every audit line for comment- or string-embedded matches
   (which would need an exemption, since the treatment cannot apply).

Every discrepancy must be reconciled before completion as exactly one of:
a missed target (inventory defect), an objective exemption (§8), or a
discovery-rule defect fixed and re-frozen. Recorded result (appendix A.5):
41 audit occurrences across the same 15 files, per-file tallies identical to
`targets.jsonl`, zero comment/string-embedded matches — **zero
discrepancies, nothing to reconcile**.

## 8. Exemptions

**The exemption list is empty.**

An exemption may be added only when a deterministic evaluator failure or the
§7 audit proves a specific site cannot take the §1 treatment (e.g. a receiver
type providing `unwrap` but no `expect`). Each entry must enumerate the
target ID and semantic locator plus a mechanical, checkable justification.
Catch-all, discretionary, and "review later" exemptions are prohibited.

## 9. Final rediscovery and completion

Campaign completion requires a final rediscovery run: `discover.sh` against
the clean candidate integration revision, with the §2 rule digest unchanged
from `targets.jsonl` (a changed digest voids the run).

**Completion is permitted iff rediscovery emits zero records not covered by
§8.** Any other state blocks completion (docs/mvp-outline.md §43
invariant 17):

- ≥ 1 non-exempt record → blocked, regardless of how the remainder is
  classified, grouped, or judged. "Classified but unresolved" is not
  completion.
- Dirty worktree, changed rule digest, or discovery error → no verdict;
  completion stays blocked.

The `resolved.rs`/`remaining.rs` fixtures (§6) are the controlled
demonstration of both sides of this rule.

## Appendix A. Recorded evidence

Executed 2026-08-09 UTC on Linux 6.12.95 aarch64 (same host class as
`preflight.md`), ripgrep 15.1.0, git 2.50.1, rustc/cargo 1.94.1.

### A.1 Determinism run

Fresh clone of `ahrav/hyperfine` checked out at
`f12f3d9f86f3643b3b7deace5e160b1f0f44d2b7`; `discover.sh` run twice:

```text
diff run1.jsonl run2.jsonl   -> empty (byte-identical)
wc -l run1.jsonl             -> 41
diff run1.jsonl targets.jsonl -> empty (frozen inventory matches)
rule_digest (all records)     -> 8bac9074495a8ae283d21811a84db87e28a302f13285779d95a20fd77fdf0261
```

### A.2 Scope check

Distinct paths in `targets.jsonl` (15): `build.rs`,
`src/benchmark/{executor,mod,relative_speed,scheduler}.rs`, `src/command.rs`,
`src/export/{csv,mod,orgmode,tests}.rs`, `src/main.rs`, `src/options.rs`,
`src/parameter/range_step.rs`, `src/timer/windows_timer.rs`,
`src/util/min_max.rs` — all within the §3 allowlist, none under a trust
root, matching the 15-file write scope in `preflight.md` §6.

### A.3 Trusted evaluator run

At the frozen revision, clean worktree, fresh `CARGO_TARGET_DIR`:

```text
PASS  evaluator: cargo build --locked — expected=PASS got=PASS
PASS  evaluator: cargo test --locked — expected=PASS got=PASS
PASS  evaluator: cargo fmt --check — expected=PASS got=PASS
PASS  evaluator: cargo clippy --all-targets --locked — expected=PASS got=PASS
```

### A.4 Fixture run

```text
PASS  positive: two runs field-for-field identical
PASS  positive: exactly one record
PASS  positive: has "source_revision":"no-git"
PASS  positive: has "path":"positive.rs"
PASS  positive: has "semantic_locator":"positive.rs:3:18 .unwrap() call site"
PASS  positive: rule_digest is 64-hex
PASS  positive: target_id is 64-hex
PASS  positive: context_digest is 64-hex
PASS  negative: zero records
PASS  negative: file byte-identical after run
PASS  resolved: zero records (completion permitted)
PASS  remaining: >=1 record (completion blocked)
PASS  positive.rs: compiles (rustc --edition 2024)
PASS  negative.rs: compiles (rustc --edition 2024)
PASS  resolved.rs: compiles (rustc --edition 2024)
PASS  remaining.rs: compiles (rustc --edition 2024)
PASS  dirty worktree: refused with no output
== result: FIXTURES-PASS ==
```

### A.5 Orthogonal audit record

At the frozen revision:

```text
git grep -nF '.unwrap()' -- '*.rs' ':!tests/*' ':!benches/*' | wc -l  -> 40 lines
per-line occurrence sum (awk gsub)                                    -> 41
```

Per-file tallies (audit vs `targets.jsonl`): identical for all 15 files —
`build.rs` 2, `src/benchmark/executor.rs` 2, `src/benchmark/mod.rs` 1,
`src/benchmark/relative_speed.rs` 2, `src/benchmark/scheduler.rs` 1,
`src/command.rs` 16, `src/export/csv.rs` 2, `src/export/mod.rs` 1,
`src/export/orgmode.rs` 1, `src/export/tests.rs` 2, `src/main.rs` 1,
`src/options.rs` 1, `src/parameter/range_step.rs` 4,
`src/timer/windows_timer.rs` 1, `src/util/min_max.rs` 4.
The one line-vs-occurrence difference is `src/export/tests.rs:15` (two call
sites on one line; §5). Comment/string-embedded match scan: none found.
Discrepancies: **zero**. Exemption list stays empty (§8).
