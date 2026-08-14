# TLA+ model: root-controller head CAS + ambiguity resolution

`ControllerHead.tla` model-checks the one bespoke, interleaving-sensitive slice
of the scoped-v2 substrate: **controller authority transitions over the
`ScopeHead` CAS register with lost and unknown responses, and the `resolve()`
proof rules**. Everything else (claim SQL, shutdown tokens, readiness queries,
encoding) stays covered by unit/integration tests and types.

Method: the `/tla-spec` skill (systems-design 0.33.5) plus its sibling
`lease-fencing-and-ownership-transfer-design/references/testing-and-tla-obligations.md`.
No Rust code changes accompany this spec.

---

## 1. What is being proved

| # | Property | Form | Meaning |
| --- | ---------- | ------ | --------- |
| 1 | `TypeOK` | INVARIANT (first) | domains of every variable |
| 2 | `EpochMonotonic` | INVARIANT | the register never moves back in epoch, and no two distinct authority writes share an epoch |
| 3 | `ResolutionSound` | INVARIANT | every `Proven` conclusion corresponds to a committed authority write authored by that instance at that epoch — the reread proof has **no false positives** |
| 4 | `NoDualAuthority` | INVARIANT | at most one instance ever holds proven ownership of a given epoch |
| 5 | `FencingOrder` (S1) | INVARIANT | no effect fenced at epoch `e` is applied after a register write with a higher epoch |
| L1 | `TransitionResolves` | PROPERTY | every started transition reaches a conclusion (Proven / Superseded / Lost / abandoned) |
| L2 | `AcquisitionProgress` | PROPERTY | while budget remains, an unowned head is eventually acquired |

Deliberately **absent**, per the lease-fencing reference §4:

- No `AtMostOneActiveHolder`-style invariant. It is false in every real design
  (a paused holder still *believes* it is active) and asserting it would force
  the model to be weakened until it held.
- No **S2 (margin)** property. S2 must mention holder deadlines and a drift
  bound; this model is clock-free (§2), so S2 is out of scope and unchecked
  here. Only the unconditional S1 is claimed. The stop-margin arithmetic
  (`LEASE_DURATION_MS` / `RENEWAL_INTERVAL_MS` / `STOP_MARGIN_MS`) stays
  test-covered.

## 2. Failure model (declared in the module header)

| Dimension | Modeled as |
| --- | --- |
| Storage | one **linearizable CAS register** (S3 conditional PUT on ETag). Durable, never reorders or loses committed writes. Assumed, not re-proved (§7). |
| Delivery | `ApplyCas` is a **separate, arbitrarily delayed step** from issuing a request. A request may commit *after* its issuer already reread the register and concluded. |
| Response loss | `GoUncertain` — the issuer sees an unknown outcome while the request stays in flight. |
| Process failure | **crash-recovery**. `Crash` loses volatile state, leaves the request in flight; `Start` restarts with a **fresh instance id** (the code's documented no-reuse assumption for `InstanceId::generate`). |
| Timing | **clock-free**. Lease expiry, takeover eligibility, renewal cadence and the stop margin are pure nondeterminism (`Stop`, and an unguarded `Acquire`). This over-approximates arbitrary clock error and is what tests the code's claim that *fencing alone carries safety and the lease is liveness only*. |
| Partition | not a separate dimension: indistinguishable from lost responses + delayed apply, both present. |
| Membership | fixed controller set; no reconfiguration. |

Liveness rests on **environment progress assumptions** kept separate from
system fairness (`EnvFairness` vs `SysFairness` in the module): storage
eventually decides each in-flight request, responses eventually arrive, decided
slots are eventually reclaimed. `Crash`, `Stop`, `Release` and `PublishEffect`
get **no** fairness — they are adversarial or optional.

## 3. Action ↔ code mapping

Spec is `specs/tla/ControllerHead.tla`; code paths are relative to the repo root.

| Spec action | Code | Notes |
| --- | --- | --- |
| `Init` | `scope::root_genesis` / `ScopeHeadTransition::new` genesis arm | register starts Unowned at epoch 1, tail 0 |
| `Start(c)` | process start; `InstanceId::generate` | fresh `⟨node, incarnation⟩`, never reused |
| `Acquire(c)` | `scope_controller::acquire` (`scope_controller.rs:169`) + `read_supported` (`:325`) + `next_head` (`:341`) | read + issue are one step (see §4 abstraction A2) |
| `Renew(c)` | `scope_controller::renew` (`:210`) | uses the **retained** `ObservedScopeHead`, not a reread; the same-term choice in `TermChoice` is renew re-run with the same `now_ms` (byte-identical candidate) |
| `Stop(c)` | `ControllerAuthority::must_stop` (`:64`) → `RenewOutcome::Stopped`, `stop()` (`:94`) | clock-free: nondeterministic |
| `DropStopped(c)` | dropping a `StoppedAuthority` and reacquiring from a fresh read | the frozen policy in the module doc |
| `Release(c)` | `scope_controller::release` (`:247`) | next-epoch `ScopeAuthority::Unowned` candidate on the retained ETag |
| `PublishEffect(c)` | `ControllerAuthority::into_parent` (`:86`) → `ScopeHeadParent::existing` (`head.rs:98`) → `sync::head::commit` (`head.rs:316`) → `put_if_match` | abstract fenced downstream write: same epoch/authority, advanced tail, CAS on the held ETag; `into_parent` consumes the authority, so the controller returns to `idle` and must reacquire |
| `ApplyCas(i)` | `S3Store::put_if_match` (`s3.rs:281`) at the service | register-side, delayed; commit iff `parent = RegEtag` (the `if-match` condition) |
| `DeliverProven(c)` | `MutationOutcome::Committed { etag: Some(_) }` arm of `transition` (`:267`) | the only outcome that proves without a reread |
| `GoUncertain(c)` | `Committed { etag: None }` \| `Conflict` \| `PreconditionFailed` \| `AmbiguousConflict` \| `Unknown` arms of `transition`, and a lost response | all funnel into `resolve()`; collapsed into one action because the code treats them identically |
| `NotSent(c)` | `MutationOutcome::ProvenNotSent` \| `NotFound` → `Transition::Unresolved` | no write in flight; attempt abandoned (renew keeps its old authority) |
| `ResolveStep(c)` | `scope_controller::resolve` (`:302`) — all three rules verbatim: byte equality → Proven; owner **and** candidate epoch → Proven; `current.scope_epoch >= candidate.scope_epoch` → Superseded; else Unresolved | plus `proven_authority` (`:364`), which the owner rule's `OwnedByNow` conjunct encodes |
| `Crash(c)` | process death | request stays in flight |
| `DropDecided(i)` | request/response lifetime end | model bookkeeping (frees a slot); no code counterpart |
| `Done` | none | terminal self-loop that distinguishes model-bound exhaustion from deadlock (skill Phase 3.2) |
| `BlindRetryCas(c)` | none — **injected bug** | NC2 only; disabled (`BlindRetry = FALSE`) in every non-NC run |

State ↔ code:

| Spec state | Code |
| --- | --- |
| `log` (ghost) | history of the `ScopeHead` object; `RegB` = current head bytes, `RegEtag` = its ETag (modeled as the write sequence number) |
| `ctl[c].obs` | `ObservedScopeHead` (canonical bytes + ETag) retained inside `ControllerAuthority` |
| `ctl[c].cand` | the `ScopeHead` candidate built by `next_head` |
| `b.term` | `ScopeAuthority::Owned { lease_until }`, modeled as an **attempt-unique nonce** so byte-equality proof and owner-and-epoch proof are distinguishable (the retried-renewal-after-silent-commit case) |
| `b.tail` | the event tail + `operation_id` that an event append advances and an authority transition copies |
| `concl` (ghost) | every `Proven` conclusion ever reached (`AcquireOutcome::Acquired`, `RenewOutcome::Renewed`, `ReleaseOutcome::Released`) |

## 4. Abstraction ledger (what the model does *not* say)

Every `MutationOutcome` variant is either modeled or listed here.

| Item | Treatment | Why it is safe to abstract |
| --- | --- | --- |
| A1 `Committed { etag: None }` | folded into `GoUncertain` | the code routes it to `resolve()` exactly like `Unknown`; only the reread mints the next ETag |
| A2 read-then-issue | one atomic step | the CAS carries an ETag condition and its apply is arbitrarily delayed, so "read, stall, issue" is behaviourally covered by "issue, stall the apply" |
| A3 `AcquireOutcome::Held` | not a state change → omitted | refusing a live foreign lease leaves all state unchanged; and the clock-free model lets takeover fire regardless, which is the *stronger* environment |
| A4 `MutationOutcome::TooLarge`, `AuthorityError::InvalidInput`, namespace mismatch (`transition`, `commit`) | omitted | local pre-dispatch rejections: no request reaches the register, no state changes except the caller's error return |
| A5 `NotFound` (404 on the head key) | folded into `NotSent` | both yield `Transition::Unresolved` with no in-flight write |
| A6 `AuthorityError::ScopeMissing` / `ScopeStorage` / `HeadInvalid` (`read_supported`) | omitted | read-path failures return before any candidate is built; `HeadInvalid` (active plan digest, foreign owner after a proven write) is a static/encoding property covered by `root_head_supported` tests |
| A7 head encoding, `MAX_HEAD_BYTES`, scope identity, `operation_id` uniqueness | abstracted into record equality on `Bytes` | byte equality in the model *is* `ObservedScopeHead::canonical_bytes() == bytes`; the tail field keeps event appends byte-distinct from authority writes, which is what stops the model from inventing false byte equalities |
| A8 event publication (`publish_root`) and retained-chain reconciliation (`head::reconcile`) | out of scope; `PublishEffect` models only the fenced head CAS | the event/chain layer is PR 41/42 test-covered; the fencing question is whether a stale-epoch head write can land, which is exactly what S1 checks |
| A9 stop-margin arithmetic and lease durations | nondeterministic `Stop` | clock-free model (§2); S2 not claimed |
| A10 `ScopeHeadCommitOutcome::{CommittedSuperseded, ProvenNotCommitted, RetryIdentically}` | not modeled (append-path outcomes) | they belong to the event-append protocol (A8), not to controller authority |
| A11 the resource that enforces fencing | **is the register itself** | the effect write and the fence register are one S3 object, so `max_seen` is durable by construction: schedules 6/7 of the adversarial matrix (volatile `max_seen` across resource restart) cannot apply |

## 5. Runs

Toolchain (see §8 for the provenance record):

```bash
JAR=/path/to/tla2tools.jar                 # TLC 2.19, sha256 936a2620…
TLC="java -XX:+UseParallelGC -cp $JAR tlc2.TLC"
cd specs/tla

# parse
java -cp $JAR tla2sany.SANY ControllerHead.tla

# 1. safety (deadlock checking ON — no -deadlock flag)
$TLC -workers auto -coverage 5 -config ControllerHead_Safety.cfg ControllerHead.tla

# 2. liveness (no SYMMETRY, no CONSTRAINT anywhere; -lncheck final required)
$TLC -workers auto -lncheck final -config ControllerHead_Liveness.cfg ControllerHead.tla

# 3. reachability witnesses — MUST report a violation (that trace is the witness)
$TLC -workers auto -config ControllerHead_Witnesses.cfg ControllerHead.tla

# 4. negative controls — each MUST report a violation
$TLC -workers auto -config ControllerHead_NC1.cfg ControllerHead.tla
$TLC -workers auto -config ControllerHead_NC2.cfg ControllerHead.tla
$TLC -workers auto -config ControllerHead_NC3.cfg ControllerHead.tla
```

If `/tmp` is small or full, add `-Djava.io.tmpdir=<dir>`: TLC spills its state
queue there and a full `/tmp` surfaces as a confusing SANY
`NullPointerException` while extracting the standard modules.

### Results (all recorded on the toolchain in §8)

| Run | Bounds | Expected | Observed |
| --- | --- | --- | --- |
| Safety | 2 controllers, `MaxInc 2`, `MaxEpoch 4`, `MaxTerm 4`, `MaxTail 1`, `MaxReq 2` | clean | **clean**: 157,895,334 states generated, 40,962,201 distinct, graph depth 40, no deadlock (1m57s; 4m54s with `-coverage`) |
| Liveness | same but `MaxEpoch 3`, `MaxTerm 3` | clean | **clean**: 5,684,115 generated, 1,553,111 distinct (1m50s) |
| Witnesses | safety bounds | `WitnessesIncomplete` violated | **violated at depth 15** (trace in §6) |
| NC1 `ResolveIgnoresEpoch` | safety bounds | fail | **`ResolutionSound` violated**, 8-state trace |
| NC2 `BlindRetry` | safety bounds | fail | **`EpochMonotonic` violated**, 8-state trace |
| NC3 `FencingOff` | safety bounds | fail | **`FencingOrder` violated**, 10-state trace |

Anti-vacuity gate (skill Phase 3.0 + `references/model-validation.md`):

- **Coverage** (`-coverage 5`, safety run): every action fires with nonzero
  count — `Start` 9,683,568 · `Acquire` 544,872 · `Renew` 505,784 · `Stop`
  4,076,466 · `DropStopped` 4,076,466 · `Release` 1,046,524 · `PublishEffect`
  1,513,792 · `Crash` 52,194,834 · `ApplyCas` 25,584,996 · `DropDecided`
  37,671,768 · `DeliverProven` 1,117,840 · `GoUncertain` 5,113,532 ·
  `NotSent` 2,433,068 · `ResolveStep` 12,300,560 · `Done` 31,263.
  `BlindRetryCas` is **0**, intentionally: it is the NC2 bug, gated off by
  `BlindRetry = FALSE`. It fires in the NC2 run.
- **Deadlock gate**: satisfied. TLC's deadlock check is on (no `-deadlock`
  flag) and reports none; the 31,263 terminal states are model-bound
  exhaustion, absorbed by the explicit `Done` self-loop.
- **Liveness non-vacuity**: re-running the liveness cfg against `Spec` instead
  of `LiveSpec` (i.e. dropping all fairness) reports *Temporal properties were
  violated* with a stuttering counterexample — both L1 and L2 depend on the
  stated fairness and are not tautologies. Neither antecedent is empty: an
  unowned head holds at `Init`, and `Ambiguous(c)` is reached in every witness
  trace.
- **Discrimination between properties**: NC1 (`ResolveIgnoresEpoch`) violates
  `ResolutionSound` and `NoDualAuthority` but leaves `FencingOrder` **clean**
  (82,383,557 distinct states, no error). So S1 alone would not have caught the
  resolve bug — invariants 3 and 4 are load-bearing, not S1 restated. NC2 also
  violates `NoDualAuthority`; NC3 also violates `EpochMonotonic` and
  `NoDualAuthority` (its cfg lists only S1 so the reported violation *is* the
  fencing property).

## 6. Traces

### Witnesses (one trace reaching all three, 15 steps)

`Start(c1) → Acquire(c1) → Start(c2) → Acquire(c2) → ApplyCas → DeliverProven(c1) → Renew(c1) → GoUncertain(c1) → ResolveStep(c1) → ApplyCas → NotSent(c2) → Renew(c1) → GoUncertain(c1) → ResolveStep(c1)`

| Witness | Set at | Meaning |
| --- | --- | --- |
| `takeoverDuringRetry` | state 6 (`ApplyCas`) | a rival acquisition commits while the other controller is mid-transition |
| `delayedApply` | state 11 (`ApplyCas`) | a renewal commits **after** its issuer already reread and concluded — the delayed-apply race |
| `ownerEpochProof` | state 15 (`ResolveStep`) | an unknown outcome resolved `Proven` by the *own instance at candidate epoch* rule with bytes **not** equal — the retried-renewal-after-silent-commit case |

### NC1 — `resolve()` owner rule without its epoch conjunct

`Start(c1) → Acquire(c1) → ApplyCas(commit ⟨epoch 2, c1, T1⟩) → DeliverProven → Renew(c1) (candidate ⟨epoch 3, c1, T2⟩) → GoUncertain → ResolveStep`

The renewal is still `inflight`; the register still holds c1's **epoch 2**
write. Without the epoch conjunct, the reread sees "owned by me" and concludes
`Proven` for epoch 3: `concl` gains `⟨c1, epoch 3⟩` while `log` has no epoch-3
write at all. `ResolutionSound` catches the false positive. This is
renew/acquire conflation — row 4 of the adversarial matrix.

### NC2 — blind CAS retry instead of resolving

`Start(c1) → Start(c2) → Acquire(c1) → GoUncertain(c1) → ApplyCas(commit ⟨epoch 2, c1, T1⟩) → BlindRetryCas(c1) → ApplyCas`

The retry re-CASes the *same* candidate against a refreshed ETag, so the log
ends `…, ⟨epoch 2, c1⟩, ⟨epoch 2, c1⟩` — two authority writes at one epoch.
`EpochMonotonic` (and `NoDualAuthority`) catch it.

### NC3 — fenced downstream write without its ETag condition

`… Acquire(c1) → ApplyCas(⟨epoch 2, c1⟩) → Acquire(c2) → DeliverProven(c2) → PublishEffect(c1) → ApplyCas(⟨epoch 3, c2⟩) → ApplyCas(effect)`

Final log: `genesis → ⟨epoch 2, c1⟩ → ⟨epoch 3, c2⟩ → effect⟨epoch 2, c1, tail 1⟩`.
c1's effect, fenced at epoch 2, lands after c2's epoch-3 write: the Kleppmann
zombie (row 2 of the adversarial matrix). `FencingOrder` catches it.

### Adversarial-matrix coverage

Rows of `testing-and-tla-obligations.md` §2 that this model encodes: 1 (pause
past expiry — clock-free `Stop`/`Crash` plus arbitrary delay), 2 (delayed effect
arrives after re-grant — NC3, and rejected under fencing ON), 3 (renewal
committed, ack lost — `GoUncertain` + byte-equality resolve), 4
(renew/acquire conflation — NC1), 8 (two candidates race a steal — CAS on an
exact ETag; `NoDualAuthority`), 9 (crash mid-release — `Crash` from `stopped`
with the release in flight), 10 (delayed duplicate of one's own effect —
delayed `ApplyCas` of an effect request). Rows 5 (coordinator failover /
TTL stretch), 6–7 (resource restart with volatile vs durable `max_seen` — see
A11), 11 (clock drift — §2), 12 (mass-expiry herd) and 13 (lock service
outage) are out of scope for this spec and stay in the test/design layer.

## 7. Assumptions

- **S3 conditional PUT is a linearizable CAS register.** Assumed, not modeled;
  re-proving S3 is out of scope.
- **Instance ids are never reused across incarnations** (`InstanceId::generate`).
  The model gives each incarnation a fresh `⟨node, inc⟩`; a reused id would let
  a successor adopt its predecessor's term, which is the documented
  precondition in `scope_controller.rs`, not something this spec establishes.
- **Clock-free**: safety is checked unconditional on clocks; the margin
  property S2 is out of scope (§1).
- **Small-model bounds.** 2 controllers, 2 incarnations, `MaxEpoch 4`,
  `MaxTerm 4`, `MaxTail 1`, `MaxReq 2` for safety; `MaxEpoch 3` / `MaxTerm 3`
  for liveness (liveness builds a behaviour graph on top of the state graph).
  Epoch and term budgets are enforced by action guards, not by a TLC
  `CONSTRAINT` — no cfg here uses `CONSTRAINT` or `SYMMETRY`, so the liveness
  run is sound per the skill's Soundness Matrix. AWS's 3–5-process heuristic
  applies: this protocol has no quorum threshold, and two controllers plus two
  incarnations is the smallest universe that expresses a takeover *and* a
  successor of a crashed instance. `MaxEpoch 4` was chosen after measurement:
  the state count is ~41M distinct at 4 and superlinear in the epoch budget.
  Raising it does not change what the properties can express, because epoch is
  the only unbounded counter and every action guard is uniform in it. If a
  finding ever demands unbounded epochs, the next step is Apalache with
  `EpochMonotonic`/`FencingOrder` as candidate inductive invariants (no
  Apalache/TLAPS pass was done here).

## 8. Provenance record

```text
Verified with:
- tla2tools.jar    : TLC2 2.19 of 08 Aug 2024 (rev 5a47802)
                     sha256:936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88
- Java runtime     : OpenJDK / Amazon Corretto 21.0.12+8-LTS (aarch64, AL2023)
- CommunityModules : not used
- TLC arguments    : -workers auto [-coverage 5 | -lncheck final]
                     -Djava.io.tmpdir=<scratch> -XX:+UseParallelGC
- Spec commit      : this branch (task/ravel-l7q.2-tla)
- Audit date       : 2026-08-14
```

Rerun the **whole** suite (safety + liveness + witnesses + all three negative
controls) on any `tla2tools.jar` upgrade and re-stamp this block. A negative
control that starts passing is itself a bug.
