# Live S3 bucket provisioning evidence (E02 / ravel-aq8.7, ravel-aq8.8)

Provisioned: 2026-08-09T07:16:17Z (re-verified below at re-capture time)

## Bucket selection

E02 uses `ravel-e02-4c038b2f`, not the `ravel-e01-907331366707` bucket named in
`pilot/e01/environment.yaml`. The divergence is deliberate: E01's bucket is frozen
evidence for E01, and E02 needs a bucket whose lifecycle, versioning, and delete
policy it provisions and proves itself. `EXPECTED_BUCKET` in
`tests/live_s3_preflight.rs` names this bucket so the suite refuses to run
against any other, including E01's.

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
