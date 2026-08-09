# Live S3 bucket provisioning evidence (E02 / ravel-aq8.7, ravel-aq8.8)

Provisioned: 2026-08-09T07:16:17Z (re-verified below at re-capture time)

## Identity

```json
{
    "UserId": "AROA5GQJJ54Z3UPCXJHTX:ahrav@MIDWAY.AMAZON.COM",
    "Account": "907331366707",
    "Arn": "arn:aws:sts::907331366707:assumed-role/IibsAdminAccess-DO-NOT-DELETE/ahrav@MIDWAY.AMAZON.COM"
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
