--------------------------- MODULE ControllerHead ---------------------------
(***************************************************************************)
(* Root-controller authority over one `ScopeHead` CAS register.             *)
(*                                                                         *)
(* Models `src/distributed/scope_controller.rs` (acquire / renew / release  *)
(* / transition / resolve) against one conditional-PUT register, plus one    *)
(* abstract fenced downstream write standing in for `sync::head::commit`     *)
(* with a `FencedParent`.  `specs/tla/README.md` carries the action <-> code  *)
(* mapping table and the abstraction ledger.                                *)
(*                                                                         *)
(* FAILURE MODEL (declared before the actions, per                          *)
(* tla-spec/references/environment-and-failure-model.md):                   *)
(*                                                                         *)
(*  - Storage: one linearizable compare-and-set register (S3 conditional    *)
(*    PUT on ETag).  Durable; never loses or reorders committed writes.      *)
(*    Re-proving S3's CAS is out of scope and assumed.                       *)
(*  - Delivery: a request may be applied at the register arbitrarily late    *)
(*    (`ApplyCas` is a separate step from issuing), including AFTER its      *)
(*    issuer already reread the register and concluded.  Responses may be    *)
(*    lost (`GoUncertain`), which is also how every non-proven outcome       *)
(*    reaches the caller.                                                    *)
(*  - Process failure: crash-recovery.  A crash loses all volatile state;    *)
(*    the in-flight request stays in flight; the restart uses a FRESH        *)
(*    instance id (the code's documented no-reuse assumption for            *)
(*    `InstanceId::generate`).                                               *)
(*  - Timing: CLOCK-FREE.  Lease expiry, takeover eligibility, renewal       *)
(*    cadence and the stop margin are pure nondeterminism (`Stop`, and an    *)
(*    unguarded `Acquire`), which over-approximates arbitrary clock error.    *)
(*    This is what tests the code's claim that fencing alone carries safety   *)
(*    and the lease is liveness only.  Consequence: the margin property S2   *)
(*    of lease-fencing-and-ownership-transfer-design is NOT checked here —    *)
(*    it needs modeled clocks.  Only the unconditional S1 is.                *)
(*  - Partition / membership: not modeled; a partition is indistinguishable   *)
(*    from lost responses plus delayed apply, both present.                   *)
(*                                                                         *)
(* Liveness rests on environment progress assumptions stated separately from  *)
(* system fairness; see `Fairness` at the bottom.                            *)
(***************************************************************************)
EXTENDS Naturals, Sequences

CONSTANTS
    Controller,           \* set of controller processes
    MaxInc,               \* incarnations per controller (fresh instance id each)
    MaxEpoch,             \* highest representable scope_epoch
    MaxTerm,              \* highest lease-term nonce (attempt identity)
    MaxTail,              \* fenced downstream writes admitted (event appends)
    MaxReq,               \* concurrently tracked in-flight CAS requests
    ResolveIgnoresEpoch,  \* NC1: drop the epoch conjunct from resolve()'s owner rule
    BlindRetry,           \* NC2: re-CAS on a refreshed ETag instead of resolving
    FencingOff            \* NC3: fenced downstream write skips its ETag condition

Unowned == "unowned"      \* ScopeAuthority::Unowned
NoInst  == "noInst"       \* absent author / absent issuer

\* Instance id = <<node, incarnation>>, flattened into scalar fields wherever it
\* is stored (`owner`/`oinc`, `inode`/`iinc`, `anode`/`ainc`).  Flattening keeps
\* every field homogeneous: TLC raises an error when a record is compared to a
\* string, so `Instance \cup {Unowned}`-shaped fields are not usable.
\* Fresh instance id per incarnation; ids are never reused.

(***************************************************************************)
(* Canonical head bytes.  `epoch` is scope_epoch; `auth` is ScopeAuthority   *)
(* (owner instance or Unowned); `term` is the granted lease deadline,        *)
(* modeled as an attempt-unique nonce so that a byte-equality proof and an    *)
(* owner-and-epoch proof are distinguishable; `tail` stands for the event    *)
(* tail + operation id that a fenced downstream write advances and an        *)
(* authority transition copies.  ETags are NOT part of the bytes, matching    *)
(* `ObservedScopeHead::canonical_bytes`.                                     *)
(***************************************************************************)
Bytes == [epoch: 0..MaxEpoch, owner: Controller \cup {Unowned},
          oinc: 0..MaxInc, term: 0..MaxTerm, tail: 0..MaxTail]

\* Absent-value sentinel, shaped like Bytes so no field needs a mixed union.
NullB   == [epoch |-> 0, owner |-> Unowned, oinc |-> 0, term |-> 0, tail |-> 0]
NullObs == [b |-> NullB, etag |-> 0]

Kinds     == {"acquire", "renew", "release", "effect"}
ReqStatus == {"none", "inflight", "committed", "rejected"}
CtlStates == {"down", "idle", "waiting", "uncertain", "holding", "stopped"}
RequestId == 1..MaxReq
Witnesses == {"ownerEpochProof", "takeoverDuringRetry", "delayedApply"}

VARIABLES
    log,        \* ghost: sequence of committed register versions; the register
                \* IS Last(log) and its ETag IS the write sequence number
    reqs,       \* in-flight / decided CAS requests, by slot
    ctl,        \* per-controller local state
    concl,      \* ghost: every Proven conclusion a controller ever reached
    nextTerm,   \* fresh lease-term nonce source
    witness     \* ghost: reachability witnesses observed (anti-vacuity gate)

vars == <<log, reqs, ctl, concl, nextTerm, witness>>

Genesis == [b |-> [epoch |-> 1, owner |-> Unowned, oinc |-> 0,
                   term |-> 0, tail |-> 0],
            anode |-> NoInst, ainc |-> 0, kind |-> "genesis"]
FreeReq == [status |-> "none", inode |-> NoInst, iinc |-> 0, parent |-> 0,
            b |-> NullB, kind |-> "none", cetag |-> 0]

RegB    == log[Len(log)].b       \* current canonical head bytes
RegEtag == Len(log)              \* current ETag = write sequence number

\* "b names c's CURRENT instance as owner"
OwnedByNow(b, c) == b.owner = c /\ b.oinc = ctl[c].inc

TypeOK ==
    /\ Len(log) >= 1
    /\ \A i \in 1..Len(log) :
          /\ log[i].b \in Bytes
          /\ log[i].anode \in Controller \cup {NoInst}
          /\ log[i].ainc \in 0..MaxInc
          /\ log[i].kind \in {"genesis", "auth", "effect"}
    /\ reqs \in [RequestId ->
                    [status: ReqStatus, inode: Controller \cup {NoInst},
                     iinc: 0..MaxInc, parent: Nat, b: Bytes,
                     kind: Kinds \cup {"none"}, cetag: Nat]]
    /\ ctl \in [Controller ->
                   [inc: 0..MaxInc, st: CtlStates, obs: [b: Bytes, etag: Nat],
                    cand: Bytes, kind: Kinds \cup {"none"}, req: 0..MaxReq]]
    /\ concl \subseteq [node: Controller, inc: 1..MaxInc,
                        epoch: Nat, own: BOOLEAN]
    /\ nextTerm \in 1..(MaxTerm + 1)
    /\ witness \subseteq Witnesses

Init ==
    /\ log = << Genesis >>
    /\ reqs = [i \in RequestId |-> FreeReq]
    /\ ctl = [c \in Controller |->
                 [inc |-> 0, st |-> "down", obs |-> NullObs,
                  cand |-> NullB, kind |-> "none", req |-> 0]]
    /\ concl = {}
    /\ nextTerm = 1
    /\ witness = {}

(***************************************************************************)
(* Helpers                                                                  *)
(***************************************************************************)

\* Term nonce choices for one attempt: a fresh nonce, or -- when the retained
\* candidate still fits the observed parent -- the previous attempt's nonce.
\* The latter is `renew` re-run with the same `now_ms`, whose byte-identical
\* candidate is what lets a lost response be recognised by byte equality.
TermChoice(c, o) ==
    ({nextTerm} \cap (1..MaxTerm))
      \cup (IF /\ ctl[c].cand.epoch = o.b.epoch + 1
               /\ OwnedByNow(ctl[c].cand, c)
               /\ ctl[c].cand.tail = o.b.tail
            THEN {ctl[c].cand.term}
            ELSE {})

\* Issue one conditional PUT on an exact ETag and wait for its response.
IssueCas(c, cand, kind, parent, o) ==
    \E i \in RequestId :
       /\ reqs[i].status = "none"
       /\ reqs' = [reqs EXCEPT
                     ![i] = [status |-> "inflight", inode |-> c,
                             iinc |-> ctl[c].inc, parent |-> parent,
                             b |-> cand, kind |-> kind, cetag |-> 0]]
       /\ ctl' = [ctl EXCEPT ![c] = [ctl[c] EXCEPT !.st = "waiting",
                                                  !.obs = o,
                                                  !.cand = cand,
                                                  !.kind = kind,
                                                  !.req = i]]

Cleared(c, st) == [inc |-> ctl[c].inc, st |-> st, obs |-> NullObs,
                   cand |-> NullB, kind |-> "none", req |-> 0]

(***************************************************************************)
(* Controller actions                                                       *)
(***************************************************************************)

\* Process start / restart with a fresh instance id.
Start(c) ==
    /\ ctl[c].st = "down"
    /\ ctl[c].inc < MaxInc
    /\ ctl' = [ctl EXCEPT ![c] = [inc |-> ctl[c].inc + 1, st |-> "idle",
                                  obs |-> NullObs, cand |-> NullB,
                                  kind |-> "none", req |-> 0]]
    /\ UNCHANGED <<log, reqs, concl, nextTerm, witness>>

\* scope_controller::acquire -- read the head, build the next-epoch owned
\* candidate, conditionally replace the exact observed head.  The read and the
\* issue are one step: the CAS is ETag-conditional and its apply is delayed
\* arbitrarily, so read-then-stall-then-issue is already covered.
\* Clock-free: the `Held` refusal for a live foreign lease is not a state
\* change, so takeover eligibility is left unguarded (over-approximation).
Acquire(c) ==
    /\ ctl[c].st = "idle"
    /\ LET o == [b |-> RegB, etag |-> RegEtag] IN
       /\ o.b.epoch < MaxEpoch
       /\ \E t \in TermChoice(c, o) :
             /\ IssueCas(c, [epoch |-> o.b.epoch + 1, owner |-> c,
                             oinc |-> ctl[c].inc, term |-> t,
                             tail |-> o.b.tail],
                         "acquire", o.etag, o)
             /\ nextTerm' = IF t = nextTerm THEN nextTerm + 1 ELSE nextTerm
    /\ UNCHANGED <<log, concl, witness>>

\* scope_controller::renew -- through the RETAINED observation, not a reread.
Renew(c) ==
    /\ ctl[c].st = "holding"
    /\ LET o == ctl[c].obs IN
       /\ o.b.epoch < MaxEpoch
       /\ \E t \in TermChoice(c, o) :
             /\ IssueCas(c, [epoch |-> o.b.epoch + 1, owner |-> c,
                             oinc |-> ctl[c].inc, term |-> t,
                             tail |-> o.b.tail],
                         "renew", o.etag, o)
             /\ nextTerm' = IF t = nextTerm THEN nextTerm + 1 ELSE nextTerm
    /\ UNCHANGED <<log, concl, witness>>

\* scope_controller::renew hitting must_stop -> RenewOutcome::Stopped.
Stop(c) ==
    /\ ctl[c].st = "holding"
    /\ ctl' = [ctl EXCEPT ![c].st = "stopped"]
    /\ UNCHANGED <<log, reqs, concl, nextTerm, witness>>

\* Dropping a StoppedAuthority without relinquishing: the frozen policy allows
\* reacquisition only from a freshly read head.
DropStopped(c) ==
    /\ ctl[c].st = "stopped"
    /\ ctl' = [ctl EXCEPT ![c] = Cleared(c, "idle")]
    /\ UNCHANGED <<log, reqs, concl, nextTerm, witness>>

\* scope_controller::release -- next-epoch Unowned candidate on the retained ETag.
Release(c) ==
    /\ ctl[c].st = "stopped"
    /\ LET o == ctl[c].obs IN
       /\ o.b.epoch < MaxEpoch
       /\ IssueCas(c, [epoch |-> o.b.epoch + 1, owner |-> Unowned,
                       oinc |-> 0, term |-> 0, tail |-> o.b.tail],
                   "release", o.etag, o)
    /\ UNCHANGED <<log, concl, nextTerm, witness>>

\* Abstract fenced downstream write: sync::head::commit under a FencedParent
\* (put_if_match on the held ETag, authority and epoch copied, tail advanced).
\* `into_parent` consumes the authority, so the controller must reacquire.
PublishEffect(c) ==
    /\ ctl[c].st = "holding"
    /\ LET o == ctl[c].obs IN
       /\ o.b.tail < MaxTail
       /\ \E i \in RequestId :
             /\ reqs[i].status = "none"
             /\ reqs' = [reqs EXCEPT
                           ![i] = [status |-> "inflight", inode |-> c,
                                   iinc |-> ctl[c].inc, parent |-> o.etag,
                                   b |-> [o.b EXCEPT !.tail = o.b.tail + 1],
                                   kind |-> "effect", cetag |-> 0]]
       /\ ctl' = [ctl EXCEPT ![c] = Cleared(c, "idle")]
    /\ UNCHANGED <<log, concl, nextTerm, witness>>

\* Crash-recovery: volatile state is lost, the request stays in flight.
Crash(c) ==
    /\ ctl[c].st # "down"
    /\ ctl' = [ctl EXCEPT ![c] = Cleared(c, "down")]
    /\ UNCHANGED <<log, reqs, concl, nextTerm, witness>>

(***************************************************************************)
(* Register side                                                            *)
(***************************************************************************)

WitnessAtCommit(i) ==
    LET r == reqs[i] IN
    (IF /\ r.kind = "acquire"
        /\ \E d \in Controller : /\ d # r.inode
                                 /\ ctl[d].st \in {"waiting", "uncertain"}
     THEN {"takeoverDuringRetry"} ELSE {})
      \cup
    (IF /\ r.kind # "effect"
        /\ ctl[r.inode].inc = r.iinc
        /\ ctl[r.inode].req # i
        /\ ctl[r.inode].st \in {"holding", "idle", "stopped"}
     THEN {"delayedApply"} ELSE {})

\* Delayed, register-side apply of one conditional PUT.  A request may be
\* applied long after its issuer gave up on the response -- including after the
\* issuer's reread concluded, which is the race resolve() must survive.
ApplyCas(i) ==
    /\ reqs[i].status = "inflight"
    /\ LET r      == reqs[i]
           fenced == \/ r.parent = RegEtag
                     \/ (FencingOff /\ r.kind = "effect")
       IN IF fenced
          THEN /\ log' = Append(log,
                            [b |-> r.b, anode |-> r.inode, ainc |-> r.iinc,
                             kind |-> IF r.kind = "effect"
                                      THEN "effect" ELSE "auth"])
               /\ reqs' = [reqs EXCEPT ![i].status = "committed",
                                       ![i].cetag = Len(log) + 1]
               /\ witness' = witness \cup WitnessAtCommit(i)
          ELSE /\ reqs' = [reqs EXCEPT ![i].status = "rejected"]
               /\ UNCHANGED <<log, witness>>
    /\ UNCHANGED <<ctl, concl, nextTerm>>

\* Free a decided slot nobody is waiting on (garbage collection; also how a
\* crashed issuer's or a fire-and-forget effect's slot is reclaimed).
DropDecided(i) ==
    /\ reqs[i].status \in {"committed", "rejected"}
    /\ ~ \E c \in Controller : ctl[c].st = "waiting" /\ ctl[c].req = i
    /\ reqs' = [reqs EXCEPT ![i] = FreeReq]
    /\ UNCHANGED <<log, ctl, concl, nextTerm, witness>>

(***************************************************************************)
(* Response handling                                                        *)
(***************************************************************************)

\* MutationOutcome::Committed { etag: Some(_) } -- proven without a reread.
DeliverProven(c) ==
    /\ ctl[c].st = "waiting"
    /\ LET i == ctl[c].req
           r == reqs[i]
       IN /\ r.status = "committed"
          /\ reqs' = [reqs EXCEPT ![i] = FreeReq]
          /\ ctl' = [ctl EXCEPT ![c] =
                        IF r.kind = "release"
                        THEN Cleared(c, "idle")
                        ELSE [ctl[c] EXCEPT !.st = "holding",
                                            !.obs = [b |-> r.b, etag |-> r.cetag],
                                            !.req = 0]]
          /\ concl' = concl \cup {[node |-> c, inc |-> ctl[c].inc,
                                   epoch |-> r.b.epoch,
                                   own |-> r.kind # "release"]}
    /\ UNCHANGED <<log, nextTerm, witness>>

\* Every non-proven response funnels here: a lost response, Unknown,
\* Committed { etag: None }, Conflict, PreconditionFailed, AmbiguousConflict.
\* The request is NOT withdrawn -- it may still be applied later.
GoUncertain(c) ==
    /\ ctl[c].st = "waiting"
    /\ ctl' = [ctl EXCEPT ![c].st = "uncertain"]
    /\ UNCHANGED <<log, reqs, concl, nextTerm, witness>>

\* MutationOutcome::ProvenNotSent / NotFound -> Transition::Unresolved with no
\* write in flight: the attempt is abandoned and retried from a fresh read.
NotSent(c) ==
    /\ ctl[c].st = "waiting"
    /\ reqs[ctl[c].req].status = "inflight"
    /\ reqs' = [reqs EXCEPT ![ctl[c].req] = FreeReq]
    /\ ctl' = [ctl EXCEPT ![c] = IF ctl[c].kind = "renew"
                                 THEN [ctl[c] EXCEPT !.st = "holding", !.req = 0]
                                 ELSE Cleared(c, "idle")]
    /\ UNCHANGED <<log, concl, nextTerm, witness>>

(***************************************************************************)
(* resolve() -- the three proof rules of scope_controller::resolve           *)
(***************************************************************************)
ResolveStep(c) ==
    /\ ctl[c].st = "uncertain"
    /\ LET cand       == ctl[c].cand
           kind       == ctl[c].kind
           cur        == [b |-> RegB, etag |-> RegEtag]
           hasOwner   == cand.owner # Unowned          \* Option<&InstanceId>
           bytesEqual == cur.b = cand
           ownerProof == /\ hasOwner
                         /\ OwnedByNow(cur.b, c)
                         /\ \/ ResolveIgnoresEpoch
                            \/ cur.b.epoch = cand.epoch
           proven     == bytesEqual \/ ownerProof
           superseded == cur.b.epoch >= cand.epoch
       IN /\ IF proven
             THEN /\ concl' = concl \cup {[node |-> c, inc |-> ctl[c].inc,
                                           epoch |-> cand.epoch,
                                           own |-> kind # "release"]}
                  /\ ctl' = [ctl EXCEPT ![c] =
                                IF kind = "release"
                                THEN Cleared(c, "idle")
                                ELSE [ctl[c] EXCEPT !.st = "holding",
                                                    !.obs = cur,
                                                    !.req = 0]]
                  /\ witness' = witness \cup (IF ownerProof /\ ~bytesEqual
                                              THEN {"ownerEpochProof"}
                                              ELSE {})
             ELSE /\ concl' = concl
                  /\ witness' = witness
                  /\ ctl' = [ctl EXCEPT ![c] =
                                IF superseded
                                THEN Cleared(c, "idle")   \* Superseded / Lost
                                ELSE IF kind = "renew"    \* Unresolved:
                                     THEN [ctl[c] EXCEPT !.st = "holding",
                                                         !.req = 0]
                                     ELSE Cleared(c, "idle")]
    /\ UNCHANGED <<log, reqs, nextTerm>>

\* NC2 only: on an unknown outcome, re-CAS the same candidate against a
\* refreshed ETag instead of resolving -- no proof, no epoch advance.
BlindRetryCas(c) ==
    /\ BlindRetry
    /\ ctl[c].st = "uncertain"
    /\ ctl[c].kind \in {"acquire", "renew", "release"}
    /\ IssueCas(c, ctl[c].cand, ctl[c].kind, RegEtag,
                [b |-> RegB, etag |-> RegEtag])
    /\ UNCHANGED <<log, concl, nextTerm, witness>>

(***************************************************************************)
(* Next-state relation                                                      *)
(***************************************************************************)
Progress ==
    \/ \E c \in Controller :
          \/ Start(c) \/ Acquire(c) \/ Renew(c) \/ Stop(c) \/ DropStopped(c)
          \/ Release(c) \/ PublishEffect(c) \/ Crash(c)
          \/ DeliverProven(c) \/ GoUncertain(c) \/ NotSent(c)
          \/ ResolveStep(c) \/ BlindRetryCas(c)
    \/ \E i \in RequestId : ApplyCas(i) \/ DropDecided(i)

\* Terminal states exist only because the model bounds epochs, terms,
\* incarnations and request slots.  This self-loop distinguishes bound
\* exhaustion from protocol deadlock (Phase 3.2 deadlock gate).
Done == /\ ~ ENABLED Progress
        /\ UNCHANGED vars

Next == Progress \/ Done

\* Environment progress assumptions (storage decides, responses arrive,
\* slots are reclaimed) -- stated apart from the system's own fairness.
EnvFairness ==
    /\ \A i \in RequestId : WF_vars(ApplyCas(i))
    /\ \A i \in RequestId : WF_vars(DropDecided(i))
    /\ \A c \in Controller : WF_vars(DeliverProven(c) \/ GoUncertain(c))

\* System fairness: a live controller keeps resolving and keeps trying to
\* acquire.  No fairness on Crash, Stop, Release or PublishEffect: those are
\* adversarial or optional.
SysFairness ==
    /\ \A c \in Controller : WF_vars(ResolveStep(c))
    /\ \A c \in Controller : WF_vars(Start(c))
    /\ \A c \in Controller : WF_vars(Acquire(c))

Fairness == EnvFairness /\ SysFairness

Spec     == Init /\ [][Next]_vars
LiveSpec == Init /\ [][Next]_vars /\ Fairness

(***************************************************************************)
(* Safety                                                                   *)
(***************************************************************************)

\* The register never moves backwards in epoch, and no two distinct authority
\* writes share an epoch: the register-write log is strictly increasing in
\* epoch across authority transitions.
EpochMonotonic ==
    /\ \A i \in 1..Len(log) : log[i].b.epoch <= RegB.epoch
    /\ \A i, j \in 1..Len(log) :
          /\ log[i].kind = "auth"
          /\ log[j].kind = "auth"
          /\ log[i].b.epoch = log[j].b.epoch
          => i = j

\* Every Proven conclusion corresponds to a committed authority write authored
\* by that instance at that epoch: the reread proof has no false positives.
ResolutionSound ==
    \A x \in concl :
       \E i \in 1..Len(log) :
          /\ log[i].kind = "auth"
          /\ log[i].anode = x.node
          /\ log[i].ainc = x.inc
          /\ log[i].b.epoch = x.epoch
          /\ IF x.own
             THEN log[i].b.owner = x.node /\ log[i].b.oinc = x.inc
             ELSE log[i].b.owner = Unowned

\* At most one instance ever holds proven ownership of a given epoch.
NoDualAuthority ==
    \A x, y \in concl :
       (x.own /\ y.own /\ x.epoch = y.epoch) => (x.node = y.node /\ x.inc = y.inc)

\* S1 (fencing), per lease-fencing-and-ownership-transfer-design: no effect
\* fenced at epoch e is applied after a register write with a higher epoch.
FencingOrder ==
    \A i, j \in 1..Len(log) :
       (i < j /\ log[j].kind = "effect") => log[j].b.epoch >= log[i].b.epoch

(***************************************************************************)
(* Liveness                                                                 *)
(***************************************************************************)

\* Exhaustion of the model's artificial bounds (epochs, term nonces,
\* incarnations); stable once true.  Liveness is claimed only while budget
\* remains -- a bound is not a protocol property.
NoLiveController == \A c \in Controller : ctl[c].st = "down" /\ ctl[c].inc = MaxInc

Exhausted == \/ RegB.epoch = MaxEpoch
             \/ nextTerm > MaxTerm
             \/ NoLiveController

Ambiguous(c) == ctl[c].st \in {"waiting", "uncertain"}

\* Every started transition reaches a conclusion (Proven, Superseded/Lost, or
\* an abandoned attempt); no schedule wedges a controller in ambiguity.
TransitionResolves ==
    \A c \in Controller : Ambiguous(c) ~> ~Ambiguous(c)

\* Once the head is unowned, some controller acquires proven authority -- or
\* the model's epoch/term budget ran out.
AcquisitionProgress ==
    (RegB.owner = Unowned)
      ~> (\/ \E c \in Controller : ctl[c].st \in {"holding", "stopped"}
          \/ Exhausted)

(***************************************************************************)
(* Anti-vacuity: reachability witnesses.  Each is an INVERTED invariant --   *)
(* the counterexample TLC prints IS the witness trace.                       *)
(*   ownerEpochProof      : an Unknown outcome resolved Proven by the        *)
(*                          own-instance-at-candidate-epoch rule, with bytes  *)
(*                          NOT equal (the retried-renewal case).            *)
(*   takeoverDuringRetry  : a rival acquisition commits while another         *)
(*                          controller is mid-transition.                     *)
(*   delayedApply         : a request commits after its issuer already reread  *)
(*                          and concluded.                                    *)
(***************************************************************************)
WitnessesIncomplete == witness # Witnesses
=============================================================================
