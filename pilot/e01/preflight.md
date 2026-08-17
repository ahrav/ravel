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

Artifact checksum — the frozen subject content, independent of git object
storage (recompute with `git archive --format=tar <sha> | sha256sum`):

```text
sha256(git archive f12f3d9f86f3643b3b7deace5e160b1f0f44d2b7) =
65896a6acb7fdb1fcc2f5d81399bd697364aba346699311c62b9d056974b999b
```

```text
== E01 preflight receipt ==
date: 2026-08-09T00:17:01Z
host: Linux 6.12.95-124.187.amzn2023.aarch64
rustc: rustc 1.94.1 (e408947bf 2026-03-25)
cargo: cargo 1.94.1 (29ea6fb6a 2026-03-24)
cloning https://github.com/ahrav/hyperfine.git -> /tmp/e01-preflight.PravGw/hyperfine
PASS  frozen revision — f12f3d9f86f3643b3b7deace5e160b1f0f44d2b7
PASS  clean worktree (incl. ignored files)
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

Plausible discriminating follow-up (required by the gate; grounds two
competing conclusions in specific in-repo evidence):

> When the calibrated shell-spawning time exceeds a measured benchmark time,
> is the corrected result silently clamped, or does the user see a warning?
> `src/benchmark/executor.rs:216-218` clamps each corrected component with
> `.max(0.0)`; whether `Warnings::FastExecutionTime` in
> `src/output/warnings.rs` fires for exactly this case discriminates
> “clamped with a user-facing warning” from “silently reports zero”.

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

## Amendment ravel-j4t smoke

Live re-verification of the amended `pilot/e01/` set (new sibling
[`runtime.md`](runtime.md), `experiments.md` §3/§9, two new `preflight.sh`
check blocks). Executed 2026-08-09 UTC on Linux 6.12.95-124.187.amzn2023.aarch64,
rustc/cargo 1.94.1, ripgrep 15.1.0, bubblewrap 0.10.0 (not setuid) and
`prlimit` from the host distribution.

`bash pilot/e01/preflight.sh` from a fresh clone of the fork — all pre-existing
checks unchanged; the new blocks appended below the change-viability gate:

```text
== E01 preflight receipt ==
date: 2026-08-09T04:47:22Z
host: Linux 6.12.95-124.187.amzn2023.aarch64
cloning https://github.com/ahrav/hyperfine.git -> /tmp/e01-preflight.ILl8xr/hyperfine
PASS  frozen revision — f12f3d9f86f3643b3b7deace5e160b1f0f44d2b7
…all §2 checks PASS, unchanged…
PASS  change targets >= 36 — count=40
unicodedata: 13.0.0 (runtime.md §4 reference: 13.0.0)
PASS  path collision golden vectors (19 rows, 8 reason categories, 3 collision pairs)
PASS  containment tool present: bwrap
PASS  containment tool present: prlimit
PASS  prlimit frozen limits apply
PASS  bwrap frozen-shape smoke (runtime.md §3.1)
PASS  max_user_namespaces > 0 — max_user_namespaces=505718
PASS  sandbox user namespace differs from host — host=user:[4026531837] sandbox=user:[4026532703]
PASS  evaluator: cargo build --locked — expected=PASS got=PASS
PASS  evaluator: cargo test --locked — expected=PASS got=PASS
PASS  evaluator: cargo fmt --check — expected=PASS got=PASS
PASS  evaluator: cargo clippy --all-targets --locked — expected=PASS got=PASS
== result: PREFLIGHT-PASS ==
```

Inventory, fixtures, and orthogonal audit re-run against a second fresh clone
at the pinned revision:

```text
discover.sh records                          -> 41
rule_digest (all records)                    -> 8bac9074495a8ae283d21811a84db87e28a302f13285779d95a20fd77fdf0261
vs change/targets.jsonl                      -> field-for-field identical (target_id, path, locator, context_digest)
git grep -nF '.unwrap()' audit lines         -> 40
audit occurrences (per-line gsub)            -> 41
per-file tallies audit vs targets.jsonl      -> identical, zero discrepancies
comment/string-embedded occurrences          -> 0
fixtures/run.sh                              -> == result: FIXTURES-PASS ==
```

The comment/string scan was recomputed per occurrence (a `.unwrap()` is
embedded only if an unclosed `"` or a preceding `//` covers it), reproducing
the zero from `change/contract.md` appendix A.5.

### Adversarial checks on the new blocks

Every deliberate violation fails before the trusted evaluators run. The
tamper set covers each thing the checks now assert — expected key, row count,
reason-category coverage, both numeric limits, the pair count, and the
containment tools:

```text
frozen expected key tampered (row 2 -> "src/Main.rs"):
  FAIL  path collision golden vectors — vector b'src/Main.rs': want 'src/Main.rs' got 'src/main.rs'
  == result: PREFLIGHT-FAIL (1) ==
git-component vector row deleted:
  FAIL  path collision golden vectors — vector rows: want 18 got 17;
        reason categories with no vector: git-component;
  == result: PREFLIGHT-FAIL (1) ==
MAX_PATH_DEPTH tampered 10 -> 10000:
  FAIL  path collision golden vectors — vector b'a/b/c/d/e/f/g/h/i/j/k.rs':
        want 'REJECT:path-too-deep' got 'a/b/c/d/e/f/g/h/i/j/k.rs';
        reason categories with no vector: path-too-deep;
  == result: PREFLIGHT-FAIL (1) ==
MAX_PATH_LENGTH tampered 180 -> 400:
  FAIL  path collision golden vectors — vector b'src/aaa…' (181 B):
        want 'REJECT:path-too-long' got 'src/aaa…';
        reason categories with no vector: path-too-long;
  == result: PREFLIGHT-FAIL (1) ==
third ASCII-case variant added (src/MAIN.rs), making one 3-way collision:
  FAIL  path collision golden vectors — vector rows: want 18 got 19;
        collision key pairs: want 3 got 5;
  == result: PREFLIGHT-FAIL (1) ==
bwrap shadowed by a stub exiting 1:
  PASS  containment tool present: bwrap
  FAIL  bwrap frozen-shape smoke (runtime.md §3.1) — rc=1:
  FAIL  sandbox user namespace differs from host — frozen-shape smoke did not run
  == result: PREFLIGHT-FAIL (2) ==
```

The 3-way-collision row is the case that distinguishes counting pairs from
counting colliding groups: as three groups it would still report 3 and pass,
so the block counts pairs (`n·(n−1)/2` per group).

The containment quiescence claim in `runtime.md` §3.3 was verified directly on
this host class: inside `bwrap --unshare-all`, `/proc/1/comm` is `bwrap` and
the wrapped command runs as PID 2, so reaping the `bwrap` child is sufficient proof
that the PID namespace — and therefore every descendant — is gone.

`--unshare-all` alone was **not** sufficient for the §3.2 user-namespace
guarantee: `man bwrap` on this host (bubblewrap 0.10.0) defines it as
`--unshare-user-try … --unshare-cgroup-try`, and the `-try` variants skip the
namespace instead of failing. The frozen shape now passes explicit
`--unshare-user --unshare-cgroup` (verified accepted, rc=0), and the smoke's
payload reads `/proc/self/ns/user` so preflight asserts a distinct user
namespace was actually created rather than inferring it from
`max_user_namespaces`.

### Amended identity

The amended `pilot/e01/` Git revision and content digest
(`git ls-files -z pilot/e01 | LC_ALL=C sort -z | xargs -0 sha256sum | sha256sum`)
are recorded in the **ravel-j4t** bd comment, outside the hashed directory —
same convention as ravel-q3w.4. Results measured under the earlier digest and
under this one are never pooled (`budgets.yaml` `amendment_rule`). Its receipt-line set is
superseded by the ravel-amn.1 amendment below.

## Amendment ravel-amn.1 smoke

Live re-verification of the amended containment gate ran on 2026-08-17 UTC on
Linux 6.12.95-124.187.amzn2023.aarch64, bubblewrap 0.10.0 (not setuid),
rustc/cargo 1.94.1, and Python 3.9.25. The overlay checks use `statvfs`
`f_frsize * f_blocks`; on this page-aligned 8 GiB value it equals the runner's
`statfs` `f_bsize * f_blocks` check. The runner behavioural receipt also
observed exactly the three frozen environment values plus `PWD=/work/src`,
which bubblewrap 0.10.0 synthesizes from the frozen `--chdir /work/src`;
ambient and credential-shaped canaries were absent.

```text
== E01 preflight receipt ==
date: 2026-08-17T07:57:17Z
host: Linux 6.12.95-124.187.amzn2023.aarch64
rustc: rustc 1.94.1 (e408947bf 2026-03-25)
cargo: cargo 1.94.1 (29ea6fb6a 2026-03-24)
PASS  frozen revision — f12f3d9f86f3643b3b7deace5e160b1f0f44d2b7
PASS  clean worktree (incl. ignored files)
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
unicodedata: 13.0.0 (runtime.md §4 reference: 13.0.0)
PASS  path collision golden vectors (19 rows, 8 reason categories, 3 collision pairs)
PASS  containment tool present: bwrap
PASS  containment tool present: prlimit
PASS  prlimit frozen limits apply
PASS  bwrap frozen-shape smoke (runtime.md §3.1)
PASS  max_user_namespaces > 0 — max_user_namespaces=505718
PASS  sandbox user namespace differs from host — host=user:[4026531837] sandbox=user:[4026532718]
PASS  attempt overlay: mounter-process capped tmpfs — S1=1 observed=8589934592
PASS  attempt overlay: cap enforced inside the frozen shape (ENOSPC) — S2=1 used=1048576 rc=1
PASS  attempt overlay: post-reap read-back by the mounter — S3=1 bytes=1
PASS  host memory covers frozen concurrency — need=42949672960 have=132654538752
overlay accounting: MemTotal=132654538752 MemAvailable=50672218112 SwapTotal=0 default_nr_inodes=16193181 runner_nr_inodes=262144
PASS  evaluator: cargo build --locked — expected=PASS got=PASS
PASS  evaluator: cargo test --locked — expected=PASS got=PASS
PASS  evaluator: cargo fmt --check — expected=PASS got=PASS
PASS  evaluator: cargo clippy --all-targets --locked — expected=PASS got=PASS
evaluator target tree: bytes=670140495 files=2421
== result: PREFLIGHT-PASS ==
```

### Adversarial checks on the new blocks

Each mutation ran against the same clean frozen checkout and failed before the
trusted evaluator sweep:

```text
frozen S1 size changed 8589934592 -> 8589934593:
  FAIL  attempt overlay: mounter-process capped tmpfs — S1=0 observed=8589938688
  == result: PREFLIGHT-FAIL (1) ==
mount(2) for S1 replaced by a plain mkdir:
  FAIL  attempt overlay: mounter-process capped tmpfs — S1=0 observed=66327269376
  == result: PREFLIGHT-FAIL (1) ==
S2 small cap changed 1048576 -> 8589934592:
  FAIL  attempt overlay: cap enforced inside the frozen shape (ENOSPC) — S2=0 used=4194304 rc=0
  == result: PREFLIGHT-FAIL (1) ==
S2 ENOSPC assignment deleted:
  NameError: name 'enospc' is not defined
  FAIL  attempt overlay: cap enforced inside the frozen shape (ENOSPC)
  == result: PREFLIGHT-FAIL (4) ==
umount moved before S3 read-back:
  FileNotFoundError: .../small/big
  FAIL  attempt overlay: post-reap read-back by the mounter
  == result: PREFLIGHT-FAIL (4) ==
frozen concurrency changed 4 -> 400:
  FAIL  host memory covers frozen concurrency — need=4294967296000 have=132654538752
  == result: PREFLIGHT-FAIL (1) ==
bwrap shadowed by a stub exiting 1:
  FAIL  bwrap frozen-shape smoke (runtime.md §3.1) — rc=1:
  FAIL  sandbox user namespace differs from host — frozen-shape smoke did not run
  FAIL  attempt overlay: cap enforced inside the frozen shape (ENOSPC)
  FAIL  attempt overlay: post-reap read-back by the mounter
  == result: PREFLIGHT-FAIL (6) ==
```

### Amended identity

This section supersedes the ravel-j4t receipt-line identity. The amended
`pilot/e01/` Git revision and content digest
(`git ls-files -z pilot/e01 | LC_ALL=C sort -z | xargs -0 sha256sum | sha256sum`)
are recorded in the **ravel-amn.1** bd comment outside this hashed directory.
Results measured under the ravel-j4t digest and this digest are never pooled,
per `budgets.yaml` `amendment_rule`.
