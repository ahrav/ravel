# E01 preflight & smoke evidence — PRIVATE, UNSTABLE

Evidence record for freezing the E01 pilot identity in
[`environment.yaml`](environment.yaml). Executed on Linux
(6.12.95 aarch64, rustc/cargo 1.94.1), 2026-08-08 UTC. All secrets redacted;
credential references are named profiles only.

## 1. Candidate selection (mechanical, first pass wins)

Ordered candidates: `sharkdp/bat`, `sharkdp/hyperfine`, `BurntSushi/ripgrep`.

**Plan deviation — provisional discovery rule substituted.** The plan's
provisional rule (`once_cell::sync::Lazy` / `lazy_static!` → `std::sync::LazyLock`,
≥ 36 sites) failed *every* candidate. Scripted count:

```text
rg -n 'Lazy::new|lazy_static!|once_cell::sync::Lazy' --type rust | wc -l
```

| candidate | Lazy/lazy_static sites | note |
| --- | --- | --- |
| bat @ 2ba8db9c | 10 | also **93 git submodules** → hard hygiene FAIL |
| hyperfine @ f12f3d9f | 2 | |
| ripgrep @ 3fce3b5b | 0 | already migrated to `std::sync::LazyLock`/`OnceLock` |

Substituted equally-mechanical rule (plan marks the rule provisional; task 3
owns the final rule): **`.unwrap()` → `.expect("...")` in non-test code**,
scripted count (excludes `tests/**` and `benches/**`; inline `#[cfg(test)]`
modules inside `src/` are not excluded, so the count slightly overstates
strictly-non-test sites — still well above the gate either way):

```text
rg -n '\.unwrap\(\)' --type rust -g '!tests/**' -g '!benches/**' | wc -l
```

Gate results under the substituted rule, in candidate order:

1. `sharkdp/bat` — **FAIL** (93 submodules; hard hygiene gate, rule count moot).
2. `sharkdp/hyperfine` — **PASS**: 40 targets ≥ 36; 0 submodules, 0 symlinks,
   no LFS/nested repos; all numeric limits hold. **First pass → winner.**
3. `BurntSushi/ripgrep` — not evaluated further (winner already selected).

Winner forked to `ahrav/hyperfine`; pinned revision
`f12f3d9f86f3643b3b7deace5e160b1f0f44d2b7` (upstream `master` at selection).

## 2. Clean-checkout preflight receipt

`bash pilot/e01/preflight.sh` from a fresh clone of the fork:

```text
== E01 preflight receipt ==
date: 2026-08-08T23:16:19Z
host: Linux 6.12.95-124.187.amzn2023.aarch64
rustc: rustc 1.94.1 (e408947bf 2026-03-25)
cargo: cargo 1.94.1 (29ea6fb6a 2026-03-24)
cloning https://github.com/ahrav/hyperfine.git -> /tmp/e01-preflight.JHHr69/hyperfine
PASS  frozen revision — f12f3d9f86f3643b3b7deace5e160b1f0f44d2b7
PASS  clean worktree
PASS  no submodules — count=0
PASS  no symlinks — count=0
PASS  no special modes — count=0
PASS  no LFS pointers — count=0
PASS  no special files on disk — count=0
PASS  no hardlinks (tracked files) — count=0
PASS  no case collisions — count=0
PASS  no unicode-normalization collisions — count=0
PASS  file count <= 2000 — count=66
PASS  total bytes <= 33554432 — bytes=474732
PASS  max file bytes <= 1048576 — largest=88282
PASS  max path length <= 180 — longest=41
PASS  max path depth <= 10 — deepest=3
PASS  trust roots disjoint from change targets — overlaps=0
PASS  change targets >= 36 — count=40
PASS  evaluator: cargo build --locked — expected=PASS got=PASS
PASS  evaluator: cargo test --locked — expected=PASS got=PASS
PASS  evaluator: cargo fmt --check — expected=PASS got=PASS
PASS  evaluator: cargo clippy --all-targets --locked — expected=PASS got=PASS
== result: PREFLIGHT-PASS ==
```

All four trusted-evaluator verdicts were predeclared PASS (measured on the
candidate before freezing) and matched. No unexpected results. Nested-repo
risk is covered by the submodule (gitlink) check: git cannot track a path
containing `.git/`, so no separate check exists.

## 3. Provider smokes

### bedrock-claude — PASS

One minimal Converse request, profile `bw-bedrock` (role redacted to name
only: `bedrock-full-access`, account `144571874263`), region `us-west-2`,
model `us.anthropic.claude-sonnet-4-5-20250929-v1:0`:

```text
prompt:   "Reply with exactly: SMOKE-OK"
response: "SMOKE-OK"
usage:    inputTokens=15 outputTokens=7 totalTokens=22
```

### bedrock-gpt — PASS (with transport deviation)

**Plan deviation — Mantle endpoint unavailable.** The planned Bedrock Mantle
OpenAI endpoint `bedrock-mantle.us-west-2.api.aws/openai/v1` is reachable and
accepts SigV4, but the account's role is hard-denied by IAM:

```text
401 access_denied: User arn:aws:sts::144571874263:assumed-role/bedrock-full-access/<user>
is not authorized to perform: bedrock-mantle:CreateInference on resource:
arn:aws:bedrock-mantle:us-west-2:144571874263:project/default
(no identity-based policy allows the action)
```

The same GPT model family is invocable through the standard `bedrock-runtime`
Converse API, so the second provider was frozen as Converse instead:

```text
model:    openai.gpt-oss-120b-1:0   (region us-west-2, profile bw-bedrock)
prompt:   "Reply with exactly: SMOKE-OK"
response: reasoning + "SMOKE-OK"
usage:    inputTokens=75 outputTokens=64 totalTokens=139
```

Both frozen model IDs were read from the live account
(`bedrock list-foundation-models` / `list-inference-profiles`), not guessed.

## 4. Safe-branch smoke — PASS

Create → force-update → restore → delete `campaign/e01/smoke` on the fork,
with production branches proven unchanged:

```text
fork master before:  f12f3d9f86f3643b3b7deace5e160b1f0f44d2b7
created:             refs/heads/campaign/e01/smoke
updated to:          327d5f4d9107141929f67f062bf9ef59f98b7399  (parent commit)
restored to:         f12f3d9f86f3643b3b7deace5e160b1f0f44d2b7
deleted:             campaign/e01/smoke
fork master after:   f12f3d9f86f3643b3b7deace5e160b1f0f44d2b7   (unchanged)
upstream master:     f12f3d9f86f3643b3b7deace5e160b1f0f44d2b7   (unchanged)
```

## 5. Research viability gate — PASS

Candidate question (bounded, repo-grounded; final contract is task 2's job):

> How does hyperfine measure shell spawning overhead, subtract it from
> benchmark timings, and guard against the correction producing negative
> times?

Enumerated inspectable evidence set (all in-repo at the frozen revision; no
open-ended browsing required):

- `src/benchmark/executor.rs` — `shell_spawning_time` calibration + subtraction
- `src/benchmark/scheduler.rs` — where calibration is invoked per benchmark
- `src/benchmark/mod.rs` — benchmark run flow consuming corrected timings
- `src/output/warnings.rs` — user-facing warnings on suspect measurements
- `src/cli.rs` — `--shell` / shell-selection surface
- `README.md` — documented shell-overhead behavior

## 6. Change viability gate — PASS

- Provisional rule: `.unwrap()` → `.expect("...")` in non-test code
  (substituted; see §1).
- Scripted discovery count at frozen revision: **40 ≥ 36**.
- Write scope (15 files): `build.rs`, `src/main.rs`, `src/command.rs`,
  `src/options.rs`, `src/benchmark/{executor,mod,relative_speed,scheduler}.rs`,
  `src/export/{csv,mod,orgmode,tests}.rs`, `src/parameter/range_step.rs`,
  `src/timer/windows_timer.rs`, `src/util/min_max.rs`.
- Disjoint from trust roots (`pilot/`, `.github/`, `Cargo.toml`, `Cargo.lock`):
  overlaps = 0 (verified by preflight.sh).
- All targets within numeric limits (largest file 88,282 B ≤ 1 MiB; repo total
  474,732 B ≤ 32 MiB).

## 7. Workflow trace (authority boundary)

Trace of one routine loop against `authority` in environment.yaml — no human
action required at any step:

1. Research: pick next question from the contract → autonomous
   (`authority.default: autonomous`; not in `human_only`).
2. Research: read evidence files, record findings to
   `s3://ravel-e01-255653206584/e01/…` → autonomous.
3. Change: pick next `.unwrap()` target, edit on `campaign/e01/<topic>` branch
   of the fork → autonomous.
4. Change: run trusted evaluators, integrate to the campaign branch →
   autonomous (`integration_target: campaign_branch_only`).

Human-only boundary (complete list, matches `authority.human_only`):

- push to any production branch (fork `master`, anything upstream)
- open/update pull requests against `sharkdp/hyperfine`
- change budgets or spending limits

## 8. S3 environment

- Account `255653206584`, bucket `ravel-e01-255653206584` (created — no
  suitable existing bucket; account has no alias, so the account id is used),
  region `us-east-1`, prefix `e01/`.
- Credential reference: AWS profile `personal` (rewired to an ada
  `credential_process` for account `255653206584`; the stale static session
  token previously stored under `[personal]` was removed). Verified via
  `sts get-caller-identity` + `s3api create-bucket`/`head-bucket`.
- S3 conditional-write behavior: out of scope for this task (untested).

## Freeze decision

All freeze conditions passed: clean-checkout preflight (§2), both provider
smokes (§3), safe-branch smoke (§4), Research viability (§5), Change
viability (§6). Identity in `environment.yaml` is frozen.

Recorded deviations from the plan (both evidence-driven, neither blocking):

1. Provisional Change-discovery rule substituted (§1) — original rule had no
   passing candidate.
2. Second provider transport is Converse, not the Mantle OpenAI endpoint
   (§3) — IAM denial, verbatim error recorded.

Residue: an unused fork `ahrav/bat` was created before bat failed the
submodule gate; the token lacks `delete_repo` scope, so it is left in place
and may be deleted manually.
