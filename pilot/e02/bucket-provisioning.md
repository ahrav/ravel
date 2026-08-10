# Live S3 bucket provisioning evidence (E02 / ravel-aq8.7, ravel-aq8.8)

Provisioned: 2026-08-09T07:16:17Z (re-verified below at re-capture time)

## Identity

```json
{
    "UserId": "<redacted>",
    "Account": "907331366707",
    "Arn": "arn:aws:sts::907331366707:assumed-role/<redacted>"
}
```

## Create result (original CreateBucket response, 2026-08-09T07:16Z)

```json
{
    "Location": "/ravel-e02-4c038b2f",
    "BucketArn": "arn:aws:s3:::ravel-e02-4c038b2f"
}
```

## Location

```json
{
    "LocationConstraint": null
}
```

## Lifecycle rules (NoSuchLifecycleConfiguration = none configured)

```text

An error occurred (NoSuchLifecycleConfiguration) when calling the GetBucketLifecycleConfiguration operation: The lifecycle configuration does not exist
```

## Versioning (empty = never enabled)

```json
```

## Public access block

```json
{
    "PublicAccessBlockConfiguration": {
        "BlockPublicAcls": true,
        "IgnorePublicAcls": true,
        "BlockPublicPolicy": true,
        "RestrictPublicBuckets": true
    }
}
```

## Encryption

```json
{
    "ServerSideEncryptionConfiguration": {
        "Rules": [
            {
                "ApplyServerSideEncryptionByDefault": {
                    "SSEAlgorithm": "AES256"
                },
                "BucketKeyEnabled": false,
                "BlockedEncryptionTypes": {
                    "EncryptionType": [
                        "SSE-C"
                    ]
                }
            }
        ]
    }
}
```

## Runtime principal — E04 claim retention

Runtime access uses a named AWS profile supplied through
`RAVEL_LIVE_S3_RUNTIME_PROFILE`; credentials are not stored in this repository.
The principal's effective policy must deny both actions below on the whole
selected bucket:

```json
{
    "Effect": "Deny",
    "Action": [
        "s3:DeleteObject",
        "s3:DeleteObjectVersion"
    ],
    "Resource": "arn:aws:s3:::ravel-e02-4c038b2f/*"
}
```

The bucket-wide resource is required because the isolated delete-denial claim
key has a run prefix before `workspace/`. A claim-prefix-only resource would
not cover that object. Denying `s3:PutBucketLifecycleConfiguration` is also recommended
because retained claims rely on the absence of matching lifecycle expiration.
The profile must resolve to an assumed role (for example `role_arn` +
`source_profile`); the evidence check records the assumed-role ARN, so an
IAM-user profile fails it.

`tests/live_s3_preflight.rs` gates delete-denial evidence on the named runtime
profile, requires the exact `AccessDenied` error code, and rereads byte-identical
claim data after the denial. Runtime-principal provisioning and captured evidence
are tracked by `ravel-nkx`.
