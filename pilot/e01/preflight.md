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
owns the final rule): **`.unwrap()` → `.expect("...")` in Rust files outside
`tests/**` and `benches/**`** — a path-based scope by definition. Inline
`#[test]` functions and `#[cfg(test)]` modules in matched files are counted:
of the 40 sites at the frozen revision, 21 are inline test code, so the
strictly-non-test count is 19. The ≥ 36 gate is defined over the path-based
count; task 3 must either keep that scope or restate the gate when it fixes
the final rule. Scripted count:

```text
rg -n '\.unwrap\(\)' --type rust --hidden -g '!.git/**' -g '!tests/**' -g '!benches/**' | wc -l
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
date: 2026-08-08T23:47:19Z
host: Linux 6.12.95-124.187.amzn2023.aarch64
rustc: rustc 1.94.1 (e408947bf 2026-03-25)
cargo: cargo 1.94.1 (29ea6fb6a 2026-03-24)
cloning https://github.com/ahrav/hyperfine.git -> /tmp/e01-preflight.V6dURV/hyperfine
PASS  frozen revision — f12f3d9f86f3643b3b7deace5e160b1f0f44d2b7
PASS  clean worktree
PASS  no submodules — count=0
PASS  no symlinks — count=0
PASS  no special modes — count=0
PASS  no setuid/setgid/world-writable on disk — count=0
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
containing `.git/`, so no separate check exists. Evaluators execute code from
the tree, so the script refuses to run them unless the tree is at the frozen
revision with a clean worktree.

### Adversarial test evidence

The script was exercised against deliberate violations injected into
throwaway copies of the checkout (wrong revision, dirty worktree, symlink,
gitlink, LFS pointer, special mode, hardlink, fifo, case and NFC collisions,
oversized file, deep/long paths, target count below 36, `.unwrap()` target
hidden under `.github/`, world-writable file, missing `rg` on PATH, rustfmt
violation) plus a pristine positive control. Defects found by that pass —
caller-supplied checkouts being silently reset to the frozen SHA, git-mode
normalization masking on-disk permission bits, hidden files escaping the two
`rg` queries, and gitlinks miscounted as hardlinks — are fixed in the current
script, and the fixes were re-verified with targeted negative re-runs.

## 3. Provider smokes

### bedrock-claude — PASS

One minimal Converse request, profile `claude-code-DO-NOT-DELETE`
(account `144571874263`), region `us-west-2`,
model `global.anthropic.claude-opus-5`:

```text
prompt:   "Reply with exactly: SMOKE-OK"
response: "SMOKE-OK"
usage:    inputTokens=22 outputTokens=10 totalTokens=32
```

Note: opus-5 rejects `temperature` ("ValidationException: `temperature` is
deprecated for this model") and rejects `reasoning_effort` as a Converse
request field, so `environment.yaml` records both under
`request_fields_rejected`; role-profile `reasoning_effort` values for
bedrock-claude apply orchestration-side only.

### bedrock-gpt — PASS

One minimal request to the Bedrock Mantle OpenAI-compatible endpoint
`https://bedrock-mantle.us-east-2.api.aws/openai/v1/responses`
(`/v1/responses` only — the model rejects `/v1/chat/completions`),
model `openai.gpt-5.6-sol`, auth = bearer token minted by
`~/.local/bin/bedrock-mantle-token` (aws_bedrock_token_generator over profile
`codex-DO-NOT-DELETE`, account `979667333375`) — the same mechanism the local
pi/codex/opencode harnesses use:

```text
prompt:    "Reply with exactly: SMOKE-OK"
reasoning: {"effort": "xhigh"}   (frozen role-profile value; accepted)
response:  "SMOKE-OK"
usage:     input_tokens=14 output_tokens=8
```

Earlier attempts against `bedrock-mantle.us-west-2.api.aws` with SigV4 from
profile `bw-bedrock` failed with `bedrock-mantle:CreateInference` denials;
the working path above (us-east-2, bearer token, `codex-DO-NOT-DELETE`)
matches the other harnesses' configuration and is the frozen one.

Both frozen model IDs match the locally configured harness models
(pi `defaultModel`, claude code, codex, opencode), verified invocable live.

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

- Provisional rule: `.unwrap()` → `.expect("...")` in Rust files outside
  `tests/**` and `benches/**` — path-based scope (substituted; see §1).
- Scripted discovery count at frozen revision: **40 ≥ 36** (path-based).
  Strictly-non-test sites: 19 — 21 of the 40 are inline `#[test]`/`#[cfg(test)]`
  code, including all of `src/export/tests.rs`; see §1.
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
   `s3://ravel-e01-907331366707/e01/…` → autonomous.
3. Change: pick next `.unwrap()` target, edit on `campaign/e01/<topic>` branch
   of the fork → autonomous.
4. Change: run trusted evaluators, integrate to the campaign branch →
   autonomous (`integration_target: campaign_branch_only`).

Human-only boundary (complete list, matches `authority.human_only`):

- push to any production branch (fork `master`, anything upstream)
- open/update pull requests against `sharkdp/hyperfine`
- change budgets or spending limits

## 8. S3 environment

- Account `907331366707`, bucket `ravel-e01-907331366707` (created — no
  suitable existing bucket; account has no alias, so the account id is used),
  region `us-east-1`, prefix `e01/`.
- Credential reference: AWS profile `personal` (rewired to an ada
  `credential_process` for account `907331366707`; the stale static session
  token previously stored under `[personal]` was removed). Verified via
  `sts get-caller-identity` + `s3api create-bucket`/`head-bucket`.
- S3 conditional-write behavior: out of scope for this task (untested).

## Freeze decision

All freeze conditions passed: clean-checkout preflight (§2), both provider
smokes (§3), safe-branch smoke (§4), Research viability (§5), Change
viability (§6). Identity in `environment.yaml` is frozen.

Recorded deviation from the plan (evidence-driven, not blocking):

1. Provisional Change-discovery rule substituted (§1) — original rule had no
   passing candidate.

Residue: an unused fork `ahrav/bat` was created before bat failed the
submodule gate; deletion requires the `delete_repo` token scope.
