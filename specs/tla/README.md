# TLA+ model: root-controller head CAS + ambiguity resolution

`ControllerHead.tla` model-checks the one bespoke, interleaving-sensitive slice
of the scoped-v2 substrate: **controller authority transitions over the
`ScopeHead` CAS register with lost and unknown responses, and the `resolve()`
proof rules**. Everything else (claim SQL, shutdown tokens, readiness queries,
encoding) stays covered by unit/integration tests and types.

Method: the `/tla-spec` skill (systems-design 0.33.5) plus its sibling
`lease-fencing-and-ownership-transfer-design/references/testing-and-tla-obligations.md`.
No Rust code changes accompany this spec. §9 records the review that ran against
it and what was changed as a result.

---

## 1. What is being proved

| # | Property | Form | Meaning |
| --- | --- | --- | --- |
| 1 | `TypeOK` | INVARIANT (first) | domains of every variable |
| 2 | `EpochMonotonic` | INVARIANT | the register never moves back in epoch, and no two distinct authority writes share an epoch |
| 3 | `ResolutionSound` | INVARIANT | every `Proven` conclusion corresponds to a committed authority write authored by that instance at that epoch — the reread proof has **no false positives** |
| 4 | `NoDualAuthority` | INVARIANT | at most one instance ever holds proven ownership of a given epoch |
| 5 | `FencingOrder` (S1) | INVARIANT | clause 1: no effect fenced at epoch `e` is applied after a register write with a higher epoch. clause 2: an applied effect's predecessor in the log is exactly the head version it was fenced on (same epoch, owner, incarnation, term; one tail step) |
| L1 | `TransitionResolves` | PROPERTY | every started transition reaches a conclusion (Proven / Superseded / Lost / abandoned) |
| L2 | `AcquisitionProgress` | PROPERTY | an unowned head does not stay unowned: some controller commits an acquisition |

Two of these are **not independent**, and the review pinned it down (§9):

- `FencingOrder` clause 1 — S1 exactly as the lease-fencing reference states it —
  is *implied* by `EpochMonotonic`, because `log` is append-only and conjunct 1
  of `EpochMonotonic` holds at every reachable state. Clause 2 is what gives S1
  independent detection power: it can be falsified by a bug that keeps epochs
  ordered, e.g. an effect committed against a *different* same-epoch version of
  the head. NC3's trace happens to violate both clauses, so that run alone does
  not separate them.
- `NoDualAuthority` is a corollary of `ResolutionSound` plus the
  authority-epoch-uniqueness conjunct of `EpochMonotonic`. It is kept because it
  is the human-readable statement of the property people actually care about, but
  its failure is not independent evidence.

Deliberately **absent**, per the lease-fencing reference §4:

- No `AtMostOneActiveHolder`-style invariant. It is false in every real design
  (a paused holder still *believes* it is active) and asserting it would force
  the model to be weakened until it held.
- No **S2 (margin)** property. S2 must mention holder deadlines and a drift
  bound; this model is clock-free (§2), so S2 cannot be stated here. Be precise
  about the consequence: **S2 is unchecked in the model *and* in the tests** —
  the Rust tests exercise the `must_stop` / `renewal_due` boundaries, not the
  margin property ("no re-grant while an in-bound holder still believes it is
  active"). Dropping S2 is tolerable for the *head* because every modeled effect
  is register-fenced, but `append_root` publishes immutable event bytes **before**
  the head CAS (`src/sync/head.rs:236-239`: "Every remaining binding check runs
  after publication, so a failure there can leave an unreferenced immutable
  event"). So the residual risk S2 would
  have bounded is: a zombie past its margin publishes durable but unreferenced
  event objects. That is garbage, not a correctness violation of the head, and
  it is not covered here.

## 2. Failure model (declared in the module header)

| Dimension | Modeled as |
| --- | --- |
| Storage | one **linearizable CAS register** (S3 conditional PUT on ETag). Durable, never reorders or loses committed writes. Assumed, not re-proved (§7). |
| Delivery | `ApplyCas` is a **separate, arbitrarily delayed step** from issuing a request. A request may commit *after* its issuer already reread the register and concluded. |
| Response loss | `GoUncertain` — the issuer sees an unknown outcome while the request stays in flight. |
| Process failure | **crash-recovery**. `Crash` loses volatile state, leaves the request in flight; `Start` restarts with a **fresh instance id** (the code's documented no-reuse assumption for `InstanceId::generate`). |
| Timing | **clock-free**. Lease expiry, takeover eligibility, renewal cadence and the stop margin are pure nondeterminism (`Stop`, and an unguarded `Acquire`). |
| Partition | not a separate dimension: indistinguishable from lost responses + delayed apply, both present. |
| Membership | fixed controller set; no reconfiguration. |

The clock-free choice cuts in two directions, and only one of them is
conservative:

- **For safety it is an over-approximation** (a superset of behaviours cannot
  make an invariant easier), which is exactly what tests the code's claim that
  fencing alone carries safety and the lease is liveness only.
- **For liveness it is an under-constrained *friendlier* environment.** The
  implementation's `AcquireOutcome::Held` refuses takeover while a foreign lease
  is live (`scope_controller.rs:169-184`), so real acquisition liveness depends on
  clocks; the model's `Acquire` is unguarded. So L2 says "the register does not
  wedge", **not** "a live-but-silent holder is eventually displaced". Takeover
  liveness against a live holder is unverified here and everywhere else.

Liveness rests on **environment progress assumptions** kept separate from
system fairness (`EnvFairness` vs `SysFairness` in the module): storage
eventually decides each in-flight request, responses eventually arrive, decided
slots are eventually reclaimed, and a dead process is eventually restarted
(`Start` is a supervisor obligation, so it sits in `EnvFairness`). System
fairness is only "a live controller keeps resolving and keeps trying to
acquire". `Crash`, `Stop`, `Release` and `PublishEffect` get **no** fairness —
they are adversarial or optional.

## 3. Action ↔ code mapping

Spec is `specs/tla/ControllerHead.tla`; code paths are relative to the repo root.

| Spec action | Code | Notes |
| --- | --- | --- |
| `Init` | `scope::root_genesis` / `ScopeHeadTransition::new` genesis arm | register starts Unowned at epoch 1, tail 0 |
| `Start(c)` | process start; `InstanceId::generate` | fresh `⟨node, incarnation⟩`, never reused |
| `Acquire(c)` | `scope_controller::acquire` (`scope_controller.rs:169`) + `read_supported` (`:325`) + `next_head` (`:341`) | read + issue are one step (see §4 A2) |
| `Renew(c)` | `scope_controller::renew` (`:210`) | uses the **retained** `ObservedScopeHead`, not a reread; the same-term choice in `TermChoice` is renew re-run with the same `now_ms` (byte-identical candidate) |
| `Stop(c)` | `ControllerAuthority::must_stop` (`:64`) → `RenewOutcome::Stopped`, `stop()` (`:94`) | clock-free: nondeterministic |
| `DropStopped(c)` | dropping a `StoppedAuthority` and reacquiring from a fresh read | the frozen policy in the module doc |
| `Release(c)` | `scope_controller::release` (`:247`) | next-epoch `ScopeAuthority::Unowned` candidate on the retained ETag |
| `PublishEffect(c)` | `ControllerAuthority::into_parent` (`:86`) → `ScopeHeadParent::existing` (`head.rs:98`) → `sync::head::commit` (`head.rs:316`) → `put_if_match` | abstract fenced downstream write: same epoch/authority/term, advanced tail, CAS on the held ETag; `into_parent` consumes the authority, so the controller returns to `idle` and must reacquire |
| `ApplyCas(i)` | `S3Store::put_if_match` (`s3.rs:281`) at the service | register-side, delayed; commits iff `parent = RegEtag` (the `if-match` condition) |
| `DeliverProven(c)` | `MutationOutcome::Committed { etag: Some(_) }` arm of `transition` (`:267`) | the only outcome that proves without a reread |
| `GoUncertain(c)` | `Committed { etag: None }` \| `Conflict` \| `PreconditionFailed` \| `AmbiguousConflict` \| `Unknown` arms of `transition`, and a lost response | all funnel into `resolve()`; collapsed into one action (see §4 A12 for the lifecycle over-approximation this buys) |
| `NotSent(c)` | `MutationOutcome::ProvenNotSent` \| `NotFound` → `Transition::Unresolved` | no write in flight; attempt abandoned (renew keeps its old authority) |
| `ResolveStep(c)` | `scope_controller::resolve` (`:302`) — all three rules verbatim: byte equality → Proven; owner **and** candidate epoch → Proven; `current.scope_epoch >= candidate.scope_epoch` → Superseded; else Unresolved | plus `proven_authority` (`:364`), which the owner rule's `OwnedProof` conjunct encodes |
| `Crash(c)` | process death | request stays in flight |
| `DropDecided(i)` | request/response lifetime end | model bookkeeping (frees a slot); no code counterpart |
| `Done` | none | terminal self-loop, guarded by `Exhausted`, so a successor-less state that is *not* model-bound exhaustion is still reported by TLC as a deadlock (skill Phase 3.2) |
| `BlindRetryCas(c)` | none — **injected bug** | NC2 only (`BlindRetry`) |
| `RefreshedEffectRetry(i)` | none — **injected bug** | NC3 only (`FencingOff`): retries a rejected effect against a refreshed ETag while it still carries stale-epoch bytes |
| `OwnedProof` incarnation conjunct | `proven_authority`'s owner check plus fresh `InstanceId` | NC4 (`IgnoreIncarnation`) makes it incarnation-blind, which is what a reused persisted id would do |

State ↔ code:

| Spec state | Code |
| --- | --- |
| `log` (ghost) | history of the `ScopeHead` object; `RegB` = current head bytes, `RegEtag` = its ETag (modeled as the write sequence number, see §7) |
| `ctl[c].obs` | `ObservedScopeHead` (canonical bytes + ETag) retained inside `ControllerAuthority` |
| `ctl[c].cand` | the `ScopeHead` candidate built by `next_head` |
| `b.term` | `ScopeAuthority::Owned { lease_until }`, modeled as an **attempt-unique nonce** so byte-equality proof and owner-and-epoch proof are distinguishable (the retried-renewal-after-silent-commit case) |
| `b.tail` | the event tail + `operation_id` that an event append advances and an authority transition copies. Load-bearing: without it an append's head bytes could falsely equal an authority candidate's bytes and manufacture a byte-equality proof |
| `concl` (ghost) | every `Proven` conclusion ever reached (`AcquireOutcome::Acquired`, `RenewOutcome::Renewed`, `ReleaseOutcome::Released`) |
| `witness` (ghost) | anti-vacuity bookkeeping only; read by no invariant except the inverted `WitnessesIncomplete` |

## 4. Abstraction ledger (what the model does *not* say)

Every `MutationOutcome` variant is either modeled or listed here.

| Item | Treatment | Why it is safe to abstract |
| --- | --- | --- |
| A1 `Committed { etag: None }` | folded into `GoUncertain` | the code routes it to `resolve()` exactly like `Unknown`; only the reread mints the next ETag |
| A2 read-then-issue | one atomic step | the behaviour this drops is a candidate built on a *stale* read. It is benign because such a request also carries the stale parent ETag, so it can only be rejected, and `resolve()` then verdicts against the current register (`superseded`). Arbitrary apply delay covers the rest |
| A3 `AcquireOutcome::Held` | not a state change → omitted | refusing a live foreign lease leaves all state unchanged; the clock-free model lets takeover fire regardless, which is the stronger environment for safety (and the weaker one for liveness, §2) |
| A4 `MutationOutcome::TooLarge`, `AuthorityError::InvalidInput`, namespace mismatch (`transition`, `commit`) | omitted | local pre-dispatch rejections: no request reaches the register, no state changes except the caller's error return |
| A5 `NotFound` (404 on the head key) | folded into `NotSent` | both yield `Transition::Unresolved` with no in-flight write |
| A6 `AuthorityError::ScopeMissing` / `ScopeStorage` / `HeadInvalid` (`read_supported`) | omitted | read-path failures return before any candidate is built; `HeadInvalid` (active plan digest, foreign owner after a proven write) is a static/encoding property covered by `root_head_supported` tests |
| A7 head encoding, `MAX_HEAD_BYTES`, scope identity, `operation_id` uniqueness | abstracted into record equality on `Bytes` | byte equality in the model *is* `ObservedScopeHead::canonical_bytes() == bytes` |
| A8 event publication (`publish_root`) and retained-chain reconciliation (`head::reconcile`) | out of scope; `PublishEffect` models only the fenced head CAS | the event/chain layer is PR 41/42 test-covered; the fencing question is whether a stale-epoch head write can land, which is what S1 checks. The unfenced part of that path is the residual risk named in §1 |
| A9 stop-margin arithmetic and lease durations | nondeterministic `Stop` | clock-free model (§2); S2 not claimed |
| A10 `ScopeHeadCommitOutcome::{CommittedSuperseded, ProvenNotCommitted, RetryIdentically}` | not modeled (append-path outcomes) | they belong to the event-append protocol (A8), not to controller authority. NC3's injected bug is modeled on the shape of a careless `RetryIdentically` parent refresh |
| A11 the resource that enforces fencing | **is the register itself** | the effect write and the fence register are one S3 object, so `max_seen` is durable by construction: schedules 6/7 of the adversarial matrix (volatile `max_seen` across resource restart) cannot apply |
| A12 outcome *lifecycle* | `GoUncertain` is a conservative union | the code's outcomes carry information the model discards: `Committed { etag: None }` means the write already landed, and a `Conflict`/`PreconditionFailed` with no possible-send evidence means it was rejected — neither can still be in flight, whereas the model lets any uncertain request commit later. This over-approximates (more behaviours), so it cannot hide a safety violation. `AmbiguousConflict` is in fact unreachable on this path, because `transition` builds a fresh `AttemptHistory` per attempt (`scope_controller.rs:278-280`, `s3.rs:127-162`); `AttemptHistory`'s possible-send evidence is therefore not modeled |
| A13 ETag semantics | ETag = the append index (`RegEtag == Len(log)`), so ETags never recur | real S3 ETags are content digests, so a byte-identical rewrite would *revive* a stale precondition. This model is sound only because canonical head bytes can never repeat: an authority transition strictly increases `scope_epoch`, and an append changes the tail and `operation_id` (`head.rs:163-182`). This is the one abstraction that is not obviously conservative; it is a precondition on the encoding, listed again in §7 |

## 5. Runs

Toolchain (see §8 for the provenance record):

```bash
JAR=/path/to/tla2tools.jar                 # TLC 2.19, sha256 936a2620…
TLC="java -XX:+UseParallelGC -cp $JAR tlc2.TLC -workers auto"
cd specs/tla

# parse
java -cp $JAR tla2sany.SANY ControllerHead.tla

# 1. safety (deadlock checking ON — no -deadlock flag)
$TLC -coverage 5 -config ControllerHead_Safety.cfg ControllerHead.tla

# 2. liveness (no SYMMETRY, no CONSTRAINT anywhere; -lncheck final required)
$TLC -lncheck final -config ControllerHead_Liveness.cfg ControllerHead.tla

# 3. reachability witnesses — MUST report a violation (that trace is the witness)
$TLC -config ControllerHead_Witnesses.cfg ControllerHead.tla

# 4. negative controls — each MUST report a violation of its NAMED invariant
$TLC -config ControllerHead_NC1.cfg ControllerHead.tla   # ResolutionSound
$TLC -config ControllerHead_NC2.cfg ControllerHead.tla   # EpochMonotonic
$TLC -config ControllerHead_NC3.cfg ControllerHead.tla   # FencingOrder
$TLC -config ControllerHead_NC4.cfg ControllerHead.tla   # ResolutionSound
```

If `/tmp` is small or full, add `-Djava.io.tmpdir=<dir>`: TLC spills its state
queue there and a full `/tmp` surfaces as a confusing SANY
`NullPointerException` while extracting the standard modules.

### Results (all recorded on the toolchain in §8)

Bounds: 2 controllers, `MaxInc 2`, `MaxReq 2` everywhere; `MaxEpoch 4`,
`MaxTerm 4`, `MaxTail 2` for safety; `MaxTail 1` for the rest; `MaxEpoch 4` /
`MaxTerm 4` for liveness (§7 explains each).

| Run | Expected | Observed |
| --- | --- | --- |
| Safety | clean | **clean**: 196,433,315 states generated, 52,089,141 distinct, graph depth 40, no deadlock (12min 40s with `-coverage 5`) |
| Liveness | clean | **clean**: 179,255,865 generated, 47,051,217 distinct, depth 40; the `-lncheck final` pass ran over a 141,153,651-state behaviour graph (1h 10min) |
| Witnesses | `WitnessesIncomplete` violated | **violated at depth 22**, one trace reaching all five witnesses (§6) |
| NC1 `ResolveIgnoresEpoch` | fail | **`ResolutionSound` violated**, 8-state trace |
| NC2 `BlindRetry` | fail | **`EpochMonotonic` violated**, 10-state trace (`-workers 1`; with `-workers auto` the reported trace is the same shape at 10–12 states) |
| NC3 `FencingOff` | fail | **`FencingOrder` violated**, 11-state trace |
| NC4 `IgnoreIncarnation` | fail | **`ResolutionSound` violated**, 9-state trace |

Anti-vacuity gate (skill Phase 3.0 + `references/model-validation.md`):

- **Coverage** (`-coverage 5`, safety run): every action fires with nonzero
  count — `Start` 3,123,394 · `Acquire` 538,132 · `Renew` 272,597 · `Stop`
  1,786,986 · `DropStopped` 1,573,422 · `Release` 735,872 · `PublishEffect`
  1,599,564 · `Crash` 8,767,252 · `ApplyCas` 17,744,858 · `DropDecided`
  10,049,741 · `DeliverProven` 1,022,053 · `GoUncertain` 1,779,545 · `NotSent`
  316,124 · `ResolveStep` 2,779,600 (distinct states found per action), plus
  136,792 `Done` self-loops. `BlindRetryCas` and `RefreshedEffectRetry` are
  **0**, intentionally: they are the NC2 and NC3 bugs, gated off by
  `BlindRetry = FALSE` / `FencingOff = FALSE`. Both fire in their own NC run.
- **Deadlock gate**: satisfied, and it is a real check — `Done` fires only when
  `Exhausted` holds, so a successor-less state that is not bound exhaustion
  would still be reported by TLC as a deadlock.
- **Liveness non-vacuity**: re-running the liveness cfg against `Spec` instead
  of `LiveSpec` (dropping all fairness) reports *Temporal properties were
  violated* with a stuttering counterexample at state 13 (measured at
  `MaxEpoch 3` for run time) — both L1 and L2 depend on the stated fairness and
  are not tautologies. Neither antecedent is empty: an
  unowned head holds at `Init`, and `Ambiguous(c)` appears in every witness
  trace. L2's escape disjuncts were deliberately narrowed after review so that a
  release followed by a successor's acquisition is *checked* rather than
  satisfied by the epoch budget running out at that exact moment (§9, finding
  A-1).
- **L2's release handoff is in the checked state space** (§9, finding B-2 —
  measured with one-off inverted invariants at the liveness bounds, not committed
  because the `witness` ghost would cost state space in every run):
  - a release commits an unowned head **below** the bound and a *different*
    node's acquisition commits after it: **reachable, 11-state trace**. So L2's
    antecedent does fire in post-release states, and the successor handoff is
    inside the graph the clean liveness run covered — this is the
    `genesis 1 → acquire 2 → release 3 → successor acquires 4` schedule the
    liveness cfg header names.
  - an unowned head at `1 < epoch < MaxEpoch` with `nextTerm <= MaxTerm`:
    **reachable, 8-state trace** — the antecedent holds in states where the
    term-budget escape is not already satisfied.
  - the antecedent's `RegB.epoch < MaxEpoch` conjunct is a *bound*, not a hole:
    with it dropped, L2 is **violated** (18-state stuttering counterexample,
    `MaxEpoch 3` for run time, 1min 05s), and the final state is a release that
    landed on the bound — `⟨epoch 3, unowned⟩` with `nextTerm 3 <= MaxTerm` —
    which `Acquire`'s own `o.b.epoch < MaxEpoch` guard makes unreacquirable. Any
    finite epoch budget has a last epoch a release can land on, so this escape is
    structural to bounding epochs rather than a coverage gap; "reserve an epoch"
    only moves it.
- **Property discrimination**: NC1 (`ResolveIgnoresEpoch`) violates
  `ResolutionSound` but leaves the current two-clause `FencingOrder` **clean** (395,029,419 states generated, 98,063,677 distinct, no error, 12min 37s) —
  S1 would not have caught the resolve bug. Conversely NC3's stale effect is
  invisible to `ResolutionSound` (it makes no false conclusion) and is caught by
  `FencingOrder`. The redundancies that *do* exist are stated in §1 rather than
  being presented as independent evidence.

## 6. Traces

### Witnesses (one trace reaching all five, 22 steps)

Prefix: `Start(c1) → Acquire(c1) → Start(c2) → Acquire(c2) → ApplyCas → …`, then
`GoUncertain → ResolveStep → DeliverProven → PublishEffect → ApplyCas →
DropDecided → ApplyCas → Renew → GoUncertain → ResolveStep → DropDecided →
PublishEffect → ApplyCas`.

| Witness | Meaning |
| --- | --- |
| `takeoverDuringRetry` | a rival acquisition commits while another controller is mid-transition |
| `delayedApply` | a request commits **after** its issuer already reread and concluded |
| `ownerEpochProof` | an unknown outcome resolved `Proven` by the *own instance at candidate epoch* rule with bytes **not** equal (the retried-renewal-after-silent-commit case) |
| `effectCommitted` | a fenced downstream write actually commits, so S1 is not vacuous under fencing ON |
| `staleEffectRejected` | a fenced downstream write is rejected because the register moved under it — the fence firing |

### NC1 — `resolve()` owner rule without its epoch conjunct

`Start(c1) → Acquire(c1) → ApplyCas(commit ⟨epoch 2, c1, T1⟩) → DeliverProven → Renew(c1) (candidate ⟨epoch 3, c1, T2⟩) → GoUncertain → ResolveStep`

The renewal is still `inflight`; the register still holds c1's **epoch 2** write.
Without the epoch conjunct the reread sees "owned by me" and concludes `Proven`
for epoch 3: `concl` gains `⟨c1, epoch 3⟩` while `log` has no epoch-3 write at
all. `ResolutionSound` catches the false positive. This is renew/acquire
conflation — row 4 of the adversarial matrix.

### NC2 — blind CAS retry instead of resolving

`Start(c1) → Acquire(c1) (candidate ⟨epoch 2, c1, T1⟩) → GoUncertain(c1) → Start(c2) → Acquire(c2) (candidate ⟨epoch 2, c2, T2⟩) → ApplyCas(c2 commits ⟨epoch 2, c2, T2⟩) → DeliverProven(c2) → BlindRetryCas(c1) → ApplyCas(c1's stale candidate commits over it)`

`BlindRetryCas` is guarded on `RegB # ctl[c].cand`, so the head must have moved
under the retry. c2's acquisition commits and c2 *concludes* `Proven` for epoch
2; c1's blind retry then re-CASes its own epoch-2 candidate against the refreshed
ETag and overwrites c2's committed authority, so the log ends
`…, ⟨epoch 2, c2, T2⟩, ⟨epoch 2, c1, T1⟩` — two **distinct** authority writes at
one epoch, one of them already proven to its owner. `EpochMonotonic` catches it,
and the `takeoverDuringRetry` witness fires on the same trace.

The guard is what makes this control evidence (§9, finding B-1). Unguarded, the
shortest counterexample was a 7-state trace whose second write was
*byte-identical* to the head it overwrote (`…, ⟨epoch 2, c1⟩, ⟨epoch 2, c1⟩`,
same term, same tail): that is the **safe** `RetryIdentically` path real code
takes behind `parent_is_current` (`head.rs:391-397`), and it repeats canonical
head bytes — the one premise A13 / §7 forbid, since real content-digest ETags
make such a rewrite a register no-op while the model appends an entry and hands
out a fresh index. The property detected both shapes; TLC reports the shortest,
so the recorded evidence was the benign one.

### NC3 — a rejected fenced write retried against a refreshed ETag

`Start(c2) → Acquire(c2) → ApplyCas(⟨epoch 2, c2⟩) → DeliverProven → PublishEffect(c2) → Acquire(c2) → ApplyCas(⟨epoch 3, c2⟩) → ApplyCas(effect rejected) → RefreshedEffectRetry → ApplyCas(effect commits)`

Note this needs only **one** controller: `PublishEffect` consumes the authority,
so the same controller reacquires at epoch 3 and thereby fences out its own
in-flight effect — the ETag no longer matches and the effect is correctly
rejected. The injected retry then refreshes the parent ETag and lands the
stale-epoch bytes anyway, so `⟨epoch 2, tail 1⟩` is applied after the epoch-3
write. `FencingOrder` catches it. This is the Kleppmann zombie (row 2 of the
matrix) in the shape a real careless retry would take: `sync::head::resolve`
refreshes the parent ETag before a `RetryIdentically`, but only behind the
`parent_is_current` byte-equality guard (`head.rs:391-397`) that this control
deletes. "The `if-match` header was omitted" would not have been a code-shaped
bug — `put_if_match` always sends it.

### NC4 — incarnation-blind owner rule

`Start(c1, inc 1) → Acquire(c1) → Crash(c1) → Start(c1, inc 2) → Acquire(c1) → GoUncertain → ApplyCas(inc 1's write commits) → ResolveStep`

The delayed write of the **previous incarnation** lands, and the incarnation-blind
reread lets `inc 2` adopt it as proof of its own transition — exactly what a
reused, persisted instance id would allow. `ResolutionSound` catches it, which is
what makes the "fresh instance id" assumption (§7) a controlled one rather than a
bare claim.

### Adversarial-matrix coverage

Encoded here (rows of `testing-and-tla-obligations.md` §2): **1** (pause past
expiry — clock-free `Stop`/`Crash` plus arbitrary delay), **2** (delayed effect
arrives after re-grant: rejected with fencing ON, applied in NC3), **3**
(renewal committed, ack lost — `GoUncertain` then byte-equality resolve), **4**
(renew/acquire conflation — NC1), **8** (two candidates race a steal — CAS on an
exact ETag), **9** (crash mid-release — `Crash` from `stopped` with the release
in flight).

Out of scope and stated as such: **5** (coordinator failover / TTL stretch),
**6–7** (resource restart with volatile vs durable `max_seen` — see A11), **10**
(delayed *duplicate* of one's own effect: the model issues each effect once and
has no effect-retry action under fencing ON, so what it exercises is row 2, not
row 10; duplicates come from the append path in A10), **11** (clock drift — §2),
**12** (mass-expiry herd), **13** (lock-service outage).

## 7. Assumptions and bounds

- **S3 conditional PUT is a linearizable CAS register.** Assumed, not modeled.
- **Canonical head bytes never repeat.** Required by the ETag abstraction (A13):
  ETags are modeled as a monotone write index, which is only sound because no two
  register versions can be byte-identical.
- **Instance ids are never reused across incarnations** (`InstanceId::generate`).
  The model gives each incarnation a fresh `⟨node, inc⟩`; NC4 demonstrates that
  the invariants detect the violation of this assumption, so it is controlled
  rather than merely documented.
- **Clock-free**: safety is checked unconditional on clocks; S2 is out of scope
  and unchecked anywhere (§1); L2 is checked in an environment friendlier than
  the implementation's (§2).
- **Bounds.** 2 controllers × 2 incarnations is the smallest universe expressing
  both a takeover and a successor of a crashed instance; there is no quorum
  threshold in this protocol, so the AWS 3–5-process heuristic does not bite.
  Epoch/term/tail/slot budgets are enforced by **action guards**, not a TLC
  `CONSTRAINT`, so no cfg here uses `CONSTRAINT` or `SYMMETRY` and the liveness
  run stays sound per the skill's Soundness Matrix. Each bound is a real limit on
  behaviour, so each is named:
  - `MaxEpoch 4`: the state count is superlinear in the epoch budget (~10^8
    distinct at 4). A partial `MaxEpoch 5` run explored 457,333,669 distinct
    states with no violation before it was stopped for time; it is evidence, not
    a completed check.
  - `MaxTail 2` (safety): with `MaxTail 1` only **one** effect can ever commit
    per behaviour, so `FencingOrder` never evaluates an effect-versus-effect
    pair. 2 admits the effect → takeover → second-effect schedules.
  - `MaxReq 2` is a *guard*, not just a tracking bound: `IssueCas` needs a free
    slot, so a three-way race (two stale writes in flight plus a fresh takeover)
    is pruned. A `MaxReq 3` confirmation run (`MaxEpoch 4`, `MaxTail 1`) ran to
    completion **clean**: 3,499,514,983 states generated, 747,105,825 distinct,
    depth 44, no deadlock (1h 02min). The committed cfg keeps `MaxReq 2` so the
    routine run stays minutes rather than an hour.
  - `MaxTerm 4`: term nonces are drawn from a finite pool, so a behaviour that
    retries forever ends in `Exhausted`. L2's consequent names this escape
    explicitly instead of hiding it.
- **No Apalache/TLAPS pass.** If a finding ever demands unbounded epochs, the
  next step is Apalache with `EpochMonotonic` / `FencingOrder` as candidate
  inductive invariants.

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

Rerun the **whole** suite (safety + liveness + witnesses + all four negative
controls) on any `tla2tools.jar` upgrade and re-stamp this block. A negative
control that starts passing is itself a bug.

## 9. Review record

Four independent read-only lanes reviewed the first version of this spec (distinct
models: TLA+ correctness on claude-opus-5, code fidelity on gpt-5.6-sol,
adversarial critique on claude-fable-5, over-modeling hunt on gpt-5.6-terra).
Findings applied:

| Finding | Change |
| --- | --- |
| A-1 **blocking**: L2 was vacuous at `MaxEpoch 3` — a release lands at epoch 3, which made `Exhausted` true and let the property escape instead of checking the handoff | L2 restated with narrow escapes (`NoLiveController`, term budget) that cannot fire at the handoff moment; liveness bounds raised to `MaxEpoch 4` / `MaxTerm 4` |
| T-1: `Done` absorbed *every* successor-less state, so TLC's deadlock check could never fire | `Done` now requires `Exhausted` |
| T-2: `FencingOrder` clause 1 is implied by `EpochMonotonic`, so NC3 was not an independent control for S1 | clause 2 added (an effect's predecessor is exactly the version it fenced on); redundancy documented in §1 |
| T-3: `NoDualAuthority` is a corollary, not independent evidence | documented in §1; NC cfgs narrowed to their named invariant |
| T-6: ETag-as-index is sound only because canonical bytes never repeat | A13 and §7 |
| T-7: the CI control loop treated any nonzero exit as "control failed" | it now greps for the expected named violation; `-coverage` restored |
| F-1: `GoUncertain` is a conservative union of outcomes with different real lifecycles; `AmbiguousConflict` is unreachable on this path | A12 |
| A-2: the fresh-instance-id assumption had no negative control | **NC4** (`IgnoreIncarnation`) added |
| A-3: "clock-free over-approximates" is true for safety only | §2 rewritten; L2's weaker claim stated |
| A-4: S2 is unchecked in the model *and* the tests; residual risk is unreferenced event objects | §1 |
| A-5: NC3 (`if-match` deleted) had no code counterpart | reshaped into `RefreshedEffectRetry`, the careless-parent-refresh shape |
| A-7: no witness that an effect commits, or that a stale effect is rejected, under fencing ON | `effectCommitted` and `staleEffectRejected` witnesses added |
| A-8: `DropDecided` can free a slot an `uncertain` controller still names | comment pinning the invariant that makes it safe |
| A-9/matrix row 10 was overclaimed | reclassified out of scope in §6 |
| T-8/A-2 nits on wording (A2 justification, `Start` fairness placement) | applied |

A second confirmation pass by the lane that raised A-1 re-checked every fix and
found no new defect in the spec. Three of its reporting corrections are applied
above: the NC3 trace in §6 needs only one controller (`PublishEffect` consumes
the authority, so the same controller reacquires and fences out its own in-flight
effect), NC3 violates *both* `FencingOrder` clauses so that run alone does not
separate them (§1), and the NC1-versus-`FencingOrder` discrimination figure was
re-measured against the current two-clause invariant (§5).

PR review (automated reviewers on the change itself) added one finding:

| Finding | Change |
| --- | --- |
| B-1: NC2's shortest counterexample was a **byte-identical** rewrite of the head — the safe `RetryIdentically` shape, and a canonical-byte repeat that A13/§7 forbid — so the run did not exercise a blind retry overwriting a genuinely newer head | `BlindRetryCas` guarded on `RegB # ctl[c].cand`; NC2 now reports the 10-state stale-overwrite trace (§6). Only NC2 sets `BlindRetry = TRUE`, so no other run's state space changes |

Declined, with reasons:

- **Delete the `witness` ghost / the witnesses cfg** (ponytail, `-250` lines):
  reachability witnesses are a mandated part of the skill's anti-vacuity gate,
  and the review itself produced two more of them (A-7). The state-space cost is
  a factor of at most 2^5 on a run that finishes in minutes.
- **Delete `b.tail` / `MaxTail`** (ponytail): the fidelity lane showed `tail` is
  load-bearing — without it an append's head bytes can falsely equal an
  authority candidate's bytes and manufacture a byte-equality proof — and the
  same lane's own S1 strengthening (T-2 clause 2) needs it.
- **Delete `NotSent` and `DropStopped`** (ponytail): each maps 1:1 to real code
  outcomes (`ProvenNotSent`/`NotFound`, and reacquisition after `must_stop`), so
  deleting them would drop rows from the §3 mapping table.
- **Tighten `TypeOK`'s `Nat` fields to bounded ranges** (T-9): under `FencingOff`
  the log can exceed the natural bound, which would make NC3 report a `TypeOK`
  violation instead of the S1 violation that is its point.
- **Sharpen L1 to be crash-blind** (T-10): a crashed process legitimately never
  concludes its transition, so the sharpened property would be false. `Crash`
  carries no fairness, so no counterexample can hide behind it.
- **Condense this README** (ponytail): the mapping table, ledger and provenance
  record are the deliverable's point.

Ponytail verdict recorded verbatim: *"Medium over-modeling; remove
witnesses/tail/out-of-slice paths, retain proof ghosts, nonce, reclamation,
terminal loop, five core configs."* Of its four `delete:` items, one was applied
in a different form (NC cfg narrowing) and three were declined above; its four
`keep:` blockers (`concl`, `term`/`nextTerm`, `DropDecided`, `Done`) all stand.
