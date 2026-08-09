# Live preflight finding: concurrent conditional-write losers receive 412, not 409

## Claim under test (ravel-aq8.7 AC3 / E02 AC8)

"A bounded real conditional-write race produces and retains evidence of
Amazon S3 409 (ConditionalRequestConflict), not an emulator/synthesized
response."

## Observed behavior (bucket ravel-e02-4c038b2f, us-east-1, aws-sdk-s3 =1.135.0)

Four bounded race campaigns (retry-disabled clients, `If-None-Match: *`,
fresh key per round, truly concurrent contenders on separate clients):

| campaign | rounds x contenders | body size | winners | losers -> status |
|---|---|---|---|---|
| live-preflight-1786277980216998317-3017418 | 16 x 4 | ~14 B | 16 | 48 x 412 PreconditionFailed |
| live-preflight-1786278082998481517-3027912 | 16 x 4 | 4 MiB | 16 | 48 x 412 PreconditionFailed |
| live-preflight-1786278443918750842-3042168 | 4 x 16 | 16 KiB | 4 | 60 x 412 PreconditionFailed |
| live-preflight-1786278706003695567-3055753 | 4 x 16 | 16 KiB | 4 | 60 x 412 PreconditionFailed |

Zero 409 responses in 176 concurrent-loser observations.

## Documented service semantics

Amazon S3 User Guide, "How to prevent object overwrites with conditional
writes" (retrieved 2026-08-09):

> "If multiple conditional writes or copies occur for the same object
> name, the first write operation to finish succeeds. Amazon S3 then
> fails subsequent writes with a 412 Precondition Failed response. You
> can also receive a 409 Conflict response in the case of concurrent
> requests if a delete request to an object succeeds before a
> conditional write operation on that object completes."

The PutObject API reference words the same trigger as "a conflicting
operation occurs during the upload".

## Conclusion

The observed behavior matches the documentation: a pure concurrent
conditional PUT race yields 412 for every loser. A 409
ConditionalRequestConflict on PutObject requires a delete completing
during the conditional write (or a conditional CompleteMultipartUpload
flow). Both deletes and multipart are forbidden by E02 AC10 and by this
task's own constraints ("no cleanup", "single PutObject").

AC3 as written is therefore unsatisfiable without violating AC7/AC10.
The preflight retains the bounded-race evidence and fails closed at that
step (no emulator or synthesized status is substituted). Every other
acceptance criterion passed live; see the evidence JSON files beside
this document.

## Disposition

ravel-aq8.7 stays open with a blocker note pending a spec decision:
either accept documented 412-loser evidence as the conflict proof, or
authorize a delete-racing probe on non-durable preflight keys.
