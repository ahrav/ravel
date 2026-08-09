# E01 downstream runtime contracts — PRIVATE, UNSTABLE

E01 pilot only; do not build tooling against this file. Amendment
**ravel-j4t** to the frozen `pilot/e01/` set. It freezes the values E05
(controller lease), E07 (containment, path/collision rules), and E09
(grouping) consume and that Tasks 1–3 did not already freeze. Prose, flat
scalars, fixed tables, and golden vectors only — no schema, validator,
framework, or runtime module (E01 AC8).

Amendments require a new Git revision and a new `pilot/e01/` content digest
recorded before any affected run; results from before and after an amendment
are never pooled (`budgets.yaml` `amendment_rule`).

## 1. Already frozen elsewhere — cited, never restated

Implementers consume each value below from its cited location. This file adds
nothing to these and must not be treated as a second source.

| Contract | Frozen location |
| --- | --- |
| Stable target identity (`target_id` = sha256 of `<path>:<line>:<col>:<matched line text>`) | `change/contract.md` §2 record fields |
| Total order and tie behavior (sorted by path, then line, then column numerically, `LC_ALL=C`; two matches on one line are distinguished by column) | `change/contract.md` §2 |
| Discovery rule identity and rule digest (`8bac9074…`) | `change/contract.md` §2 |
| Declared candidate write scope (`src/**`, `build.rs`) | `change/contract.md` §3 |
| The one fixed treatment and the objective resolved condition | `change/contract.md` §1 |
| Frozen inventory: 41 targets across 15 files | `change/contract.md` §5, `change/targets.jsonl` |
| Fault placement (kill the active controller immediately after it records the second completed work item; controller restarts as one new agent on host 2) | `experiments.md` §6 and §7, cell C rows |
| Run validity, failure handling, `unresolved` aggregation, campaign-vs-per-run limit precedence, treatment-execution vs trusted-measurement bounding | `experiments.md` §4 |
| Schedule, block order, and run numbering 1–30 | `experiments.md` §3 |
| Isolation and reset between runs | `experiments.md` §5 |
| Repository/path numeric limits (`max_path_length` 180, `max_path_depth` 10, file/total byte and count caps) | `environment.yaml` `repository_limits` |
| Providers, models, role profiles, trust roots, authority | `environment.yaml` |
| Per-run and campaign caps (`attempts_per_work_item`, `model_calls_per_run`, `artifact_size_each_mib`, deadlines, spend) | `budgets.yaml` |

## 2. Controller lease (E05)

Fixed scalars — the pilot's whole lease policy, no other knobs:

| Scalar | Value |
| --- | --- |
| Lease duration | 30 s |
| Renewal cadence | 10 s |
| Stop margin | 5 s |

Rules:

- **Fencing is correctness; the lease is liveness only**
  (`docs/mvp-outline.md` §7.2). No safety property may depend on clock
  precision or on two hosts agreeing about time.
- The holder attempts renewal every **10 s**. A renewal that is
  acknowledged, or positively reconciled by rereading the head, sets the new
  positively known lease term (commit time + **30 s**). An ambiguous renewal
  never extends the pinned deadline.
- **Stop margin:** when less than **5 s** remains on the last *positively
  known* lease term, the controller stops issuing authoritative commits,
  drops its authority value, and may only reacquire from a freshly read
  head. 30 s / 10 s leaves two renewal attempts before the margin, so a
  single lost renewal response does not cost authority.
- **Takeover only after observed expiry:** another host may take over only
  when the freshly read head shows the lease already expired, and only by
  advancing the fence. Never before expiry, never on suspicion.
- This governs **campaign-controller authority only**. The E04 work-claim
  lease is separate policy and is not set here.

## 3. Containment (E07)

**Selected mechanism: bubblewrap (`bwrap`), unprivileged, with user
namespaces.** It is the one mechanism; no custom sandbox runtime, backend
trait, or pluggable policy is built (E07 AC2).

### 3.1 Frozen invocation shape

Placeholders (`<…>`) are resolved per attempt by the launcher; everything
else is fixed:

```text
bwrap --unshare-all --die-with-parent \
  --ro-bind /usr /usr \
  --symlink usr/bin /bin --symlink usr/lib /lib \
  --symlink usr/lib64 /lib64 --symlink usr/sbin /sbin \
  --ro-bind <source_snapshot> /work/src \
  --ro-bind <toolchain_root> /opt/toolchain \
  --bind <attempt_overlay_dir> /work/out \
  --tmpfs /tmp --proc /proc --dev /dev \
  --chdir /work/src --new-session --clearenv \
  --setenv PATH /opt/toolchain/bin:/usr/bin \
  --setenv HOME /work/out --setenv TMPDIR /tmp \
  -- timeout --kill-after=60 1800 \
  prlimit --as=8589934592 --nproc=512 --cpu=900 --nofile=4096 -- \
  <payload argv>
```

**Wrapper order is load-bearing.** `bwrap` is outermost so the runner's
direct child is the `bwrap` process — that is what makes both the §3.3 reap
rule and `--die-with-parent` literally true. With `timeout` outermost, runner
death would leave the orphaned `timeout` as `bwrap`'s surviving parent,
`--die-with-parent` would never fire, and sandbox descendants could keep
writing the quarantined overlay until the wall clock expired. `timeout` and
`prlimit` execute inside the sandbox, resolved from the read-only `/usr`
bind. Wall-clock enforcement is unchanged: when `timeout` kills the payload
and exits, the in-namespace init exits with it and the kernel `SIGKILL`s any
surviving descendants (§3.3).

Mounts, exactly:

| Path in sandbox | Source | Mode |
| --- | --- | --- |
| `/usr` (+ `/bin`, `/lib`, `/lib64`, `/sbin` symlinks) | host runtime | read-only |
| `/work/src` | the run's source snapshot | read-only |
| `/opt/toolchain` | prefetched toolchain + dependency cache | read-only |
| `/work/out` | one attempt's private overlay dir | read-write, single attempt |
| `/tmp` | fresh `tmpfs` | read-write, discarded at exit |
| `/proc`, `/dev` | `bwrap`-managed private `/proc` and minimal `/dev` | as `bwrap` provides |

Nothing else is bound. `--unshare-all` unshares every namespace `bwrap`
supports — including the **network** namespace (only `--share-net` would keep
it) and the PID namespace — so candidate execution has no network. No
credentials, no AWS/code-host configuration, no daemon Git metadata, no shared
writable cache, and no host socket appear in the mount table.

**Candidate output travels through the overlay.** `/work/src` is never
writable: an attempt that changes files writes them — and any build output —
under `/work/out`, and validation consumes that overlay content as the
attempt's delta. In-place edits to the mounted source tree are not part of
any flow; a payload attempting one fails on the read-only bind, which is the
intended fail-closed behavior.

**Environment:** `--clearenv` plus exactly `PATH`, `HOME`, `TMPDIR`. The
ambient process environment is never forwarded and then redacted. Adding a
variable requires an amendment.

**Descriptors:** the runner closes every inherited file descriptor except
stdin/stdout/stderr before exec. This invocation needs no extra descriptor
across exec (no `--json-status-fd`, `--block-fd`, or `--sync-fd`). Adding one
requires an amendment; an inherited connected or listening socket is never
assumed to be neutralized by the network namespace.

### 3.2 Fixed limits

| Limit | Value | Mechanism |
| --- | --- | --- |
| Address space (`RLIMIT_AS`) | 8 GiB (8589934592 B) | `prlimit --as` |
| Processes/threads (`RLIMIT_NPROC`) | 512 | `prlimit --nproc` |
| CPU time (`RLIMIT_CPU`) | 900 s | `prlimit --cpu` |
| Open files (`RLIMIT_NOFILE`) | 4096 | `prlimit --nofile` |
| Wall clock | 1800 s (`SIGTERM`, `SIGKILL` after 60 s) | `timeout --kill-after=60 1800` |
| stdout bytes | 10 MiB | runner byte cap |
| stderr bytes | 10 MiB | runner byte cap |

The 10 MiB stream caps align with `budgets.yaml` `artifact_size_each_mib: 10`.

**Fail closed:** if `bwrap`, `prlimit`, or `timeout` is missing, user
namespaces are unavailable, or any limit cannot be applied, the launch fails.
There is no permissive fallback and no partially-limited execution (E07 AC2).
Availability is checked by `preflight.sh` ("containment" block).

Known ceiling: `RLIMIT_AS` is per-process and `RLIMIT_NPROC` is per-UID, so
neither is an aggregate budget across a fan-out of payload processes. If the
pilot ever needs aggregate accounting, the upgrade path is one cgroup v2
scope around the `bwrap` process — not a second limit mechanism inside it.

### 3.3 Authoritative descendant-quiescence rule

With `--unshare-all`, `bwrap` installs a reaper process as **PID 1 of the new
PID namespace** and the wrapped command runs as its child (verified on the pilot host
class with bubblewrap 0.10.0: inside the sandbox `/proc/1/comm` is `bwrap` and
the wrapped command is PID 2 — with the §3.1 shape that is `timeout`, which
forks the `prlimit` → payload chain). `--as-pid-1`, which would remove that reaper, is
deliberately **not** used — the reaper is what makes the rule below true.

- **Quiescence is exactly one fact: the runner's direct child — the `bwrap`
  process — has been reaped** (`wait()`/`waitpid()` returned its status).
  Death of a PID namespace's init makes the kernel `SIGKILL` every remaining
  process in that namespace, so a reaped `bwrap` proves zero surviving
  descendants.
- **Workspace cleanup or reuse is permitted only after that reap.** Until
  then the attempt overlay stays quarantined. No process-group scan, `/proc`
  poll, output-EOF observation, or timeout heuristic substitutes for the
  reap.
- `--die-with-parent` covers the reverse order: if the runner dies first,
  `bwrap` is killed and the namespace collapses with it, so no descendant
  outlives the runner.

## 4. Path contract (E07)

One predicate, applied to the **raw path bytes** of every entry in a
validated delta. Ordered steps; the first failure wins and yields exactly one
reason category:

1. Decode as UTF-8. Failure → `invalid-utf8`. Invalid bytes fail closed:
   no lossy decode, no byte-string fallback, no repair.
2. Whole path ≤ **180 bytes** (`environment.yaml` `max_path_length`) →
   else `path-too-long`. The limit is bytes, not characters.
3. Component count (split on `/`) ≤ **10** (`environment.yaml`
   `max_path_depth`) → else `path-too-deep`.
4. Every component: non-empty (`empty-component`); not `.` or `..`
   (`dot-component`); not `.git` after `casefold` (`git-component` — a
   nested-repository marker; accepting it would let a validated delta write
   `src/.git/**` and change repository behavior, so it fails closed here to
   give E07 a frozen basis for rejecting nested repos); no U+0000–U+001F and
   no U+007F (`control-char`); no
   `"` and no `\` (`forbidden-char` — the same characters trusted
   `discover.sh` refuses, `change/contract.md` §2).
5. **Collision key** = `NFC(casefold(NFC(path)))`. Normalization form is
   **NFC**; reference Unicode data version **13.0.0**. The operational check
   is not the version string but that the §4.1 golden vectors reproduce; the
   observed `unicodedata.unidata_version` is recorded in the preflight
   receipt.
6. Two distinct accepted raw paths in one validation pass with an equal
   collision key → **the whole pass fails closed** (E07 AC6:
   normalization/case ambiguity is rejected, never silently merged or
   picked between). The collision set is the validated delta's accepted
   paths **plus every tracked path of the base tree the delta applies to**:
   a delta-only check would accept a lone `src/Main.rs` against an unchanged
   tracked `src/main.rs`. Preflight separately proves the frozen base tree
   itself is collision-free, so only delta-vs-delta and delta-vs-base pairs
   can fire.

No separate component-length rule exists: the 180-byte whole-path limit is
stricter than any single-component concern, so a component cap would be
unreachable.

`casefold` output is not guaranteed to be NFC, so the outer `NFC` keeps the
key canonical — one extra call, and it removes a class of collisions that a
single `casefold(NFC(p))` would miss.

### 4.1 Golden vectors

Inputs are raw bytes (Python `bytes`-literal escapes). Expected value is the
collision key, or `REJECT:<reason>`.

| # | Input bytes | Expected |
| --- | --- | --- |
| 1 | `src/main.rs` | `src/main.rs` |
| 2 | `src/Main.rs` | `src/main.rs` |
| 3 | `src/caf\xc3\xa9.rs` (NFC `é`) | `src/café.rs` |
| 4 | `src/cafe\xcc\x81.rs` (NFD `e`+U+0301) | `src/café.rs` |
| 5 | `src/stra\xc3\x9fe.rs` (`ß`) | `src/strasse.rs` |
| 6 | `src/strasse.rs` | `src/strasse.rs` |
| 7 | `src/\xffbad.rs` | `REJECT:invalid-utf8` |
| 8 | `src/../etc/passwd` | `REJECT:dot-component` |
| 9 | `src/.` | `REJECT:dot-component` |
| 10 | `src/a\x01b.rs` | `REJECT:control-char` |
| 11 | `src/a\x7fb.rs` | `REJECT:control-char` |
| 12 | `src/a"b.rs` | `REJECT:forbidden-char` |
| 13 | `src/a\\b.rs` | `REJECT:forbidden-char` |
| 14 | `src//main.rs` | `REJECT:empty-component` |
| 15 | `src/` + `a`×177 (181 bytes) | `REJECT:path-too-long` |
| 16 | `src/.git/config` | `REJECT:git-component` |

Accepted rows form exactly **three** colliding key pairs — (1, 2) ASCII case,
(3, 4) NFC/NFD, (5, 6) `ß`/`ss` casefold — and each pair is a step-6 pass
failure. Executable check: the "path collision golden vectors" block in
[`preflight.sh`](preflight.sh), which recomputes every row, compares it to
the frozen expected value, asserts the three collision pairs, and records
`unicodedata.unidata_version`.

## 5. Grouping (E09)

- **Total order:** exactly the record order of frozen
  `change/targets.jsonl` — path, then line, then column, `LC_ALL=C`
  (`change/contract.md` §2). `(path, line, column)` is unique per record, so
  **ties are impossible** and no secondary key exists. Consumers must not
  re-sort.
- **Group cap: 8 targets** (positive, so a singleton group is always valid
  and there is no "eligible but unplaceable" outcome).
- **Packing rule:** walk the frozen order once. Append the current target to
  the open group iff its path equals the open group's path *and* the open
  group holds fewer than 8 targets; otherwise close the open group and start
  a new one with this target. No lookahead, no bin-packing, no regrouping.
- **Group write scope** = the single file at that group's path — a subset of
  the candidate write scope (`change/contract.md` §3). Groups with distinct
  paths therefore have disjoint scopes by construction and may be produced
  concurrently on different hosts. Multiple chunks of one path share a scope,
  so they are **never** concurrent and integrate in chunk order.

### 5.1 Fixed result at the frozen inventory

41 targets over 15 paths pack into **16 groups** (14 single-chunk files plus
two `src/command.rs` chunks, since 16 > 8):

| Group | Path | Targets |
| --- | --- | --- |
| G01 | `build.rs` | 2 |
| G02 | `src/benchmark/executor.rs` | 2 |
| G03 | `src/benchmark/mod.rs` | 1 |
| G04 | `src/benchmark/relative_speed.rs` | 2 |
| G05 | `src/benchmark/scheduler.rs` | 1 |
| G06 | `src/command.rs` (chunk 1) | 8 |
| G07 | `src/command.rs` (chunk 2) | 8 |
| G08 | `src/export/csv.rs` | 2 |
| G09 | `src/export/mod.rs` | 1 |
| G10 | `src/export/orgmode.rs` | 1 |
| G11 | `src/export/tests.rs` | 2 |
| G12 | `src/main.rs` | 1 |
| G13 | `src/options.rs` | 1 |
| G14 | `src/parameter/range_step.rs` | 4 |
| G15 | `src/timer/windows_timer.rs` | 1 |
| G16 | `src/util/min_max.rs` | 4 |

Group ids are positional: `G<nn>` is the nn-th group produced by the rule
over the frozen order. G06 and G07 are the only pair that may not run
concurrently.
