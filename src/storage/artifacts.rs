//! Raw artifact blobs use `artifacts/sha256/{digest}` keys and contain no metadata.
//!
//! SHA-256 covers the raw bytes. Publication rejects payloads above 10 MiB before
//! hashing or object-store I/O, and duplicate keys require full-byte verification.
//! Per-producer metadata remains in [`ArtifactRef`], so multiple attempts can name
//! the same blob without overwriting metadata.

use sha2::{Digest, Sha256};

use crate::domain::campaign::ArtifactRef;

use super::s3::{PublicationError, S3Store};

/// Artifact publication rejects inputs larger than 10 MiB before hashing or dispatch.
pub const MAX_ARTIFACT_BYTES: usize = 10 * 1024 * 1024;

/// Proof that immutable artifact bytes are present at their digest key.
///
/// Only [`publish`] constructs this witness; artifact-bearing events require it.
///
/// The witness records the object-store namespace it was minted against: the
/// digest key alone is identical in every bucket, so a witness from one store
/// says nothing about whether the bytes exist in another.
#[derive(Debug)]
pub struct PublishedArtifact {
    reference: ArtifactRef,
    namespace: String,
}

impl PublishedArtifact {
    pub fn artifact_ref(&self) -> &ArtifactRef {
        &self.reference
    }

    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// Rebinds the witness to another namespace so store-identity checks can be
    /// exercised without a second live publication.
    #[cfg(test)]
    pub(crate) fn attributed_to(self, namespace: &str) -> Self {
        Self {
            reference: self.reference,
            namespace: namespace.to_owned(),
        }
    }
}

/// Publishes a bytes-only blob and returns metadata authorized to enter an event.
///
/// # Errors
///
/// Returns [`PublicationError`] when the payload exceeds 10 MiB, metadata is invalid,
/// an existing object differs in size or digest, or storage cannot prove publication.
pub async fn publish(
    store: &S3Store,
    bytes: Vec<u8>,
    media_type: String,
    producer_attempt: String,
    creation_time_unix_ms: u64,
    retention_class: Option<String>,
) -> Result<PublishedArtifact, PublicationError> {
    validate_artifact_length(bytes.len())?;
    let digest = format!("{:x}", Sha256::digest(&bytes));
    let reference = ArtifactRef::new(
        digest,
        bytes.len() as u64,
        media_type,
        producer_attempt,
        creation_time_unix_ms,
        retention_class,
    )
    .map_err(|_| PublicationError::InvalidInput)?;
    store
        .publish_immutable(&artifact_key(reference.digest()), bytes, reference.digest())
        .await?;
    Ok(PublishedArtifact {
        reference,
        namespace: store.namespace().to_owned(),
    })
}

fn validate_artifact_length(length: usize) -> Result<(), PublicationError> {
    if length <= MAX_ARTIFACT_BYTES {
        Ok(())
    } else {
        Err(PublicationError::TooLarge)
    }
}

pub(crate) fn artifact_key(digest: &str) -> String {
    format!("artifacts/sha256/{digest}")
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use aws_sdk_s3::{config::Region, primitives::SdkBody};
    use aws_smithy_runtime::client::http::test_util::NeverClient;

    use super::*;
    use crate::storage::s3::test_support::{replay_store, response, test_builder};

    #[tokio::test]
    async fn zero_byte_artifact_uses_the_deterministic_digest_key() {
        const EMPTY_SHA256: &str =
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        const EMPTY_KEY: &str =
            "/artifacts/sha256/e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

        let (store, client) = replay_store(vec![response(200, &[], SdkBody::empty())]);
        let published = publish(
            &store,
            Vec::new(),
            "application/octet-stream".into(),
            "attempt-1".into(),
            1,
            None,
        )
        .await
        .expect("artifact publishes");
        assert_eq!(published.artifact_ref().digest(), EMPTY_SHA256);
        assert_eq!(published.artifact_ref().size(), 0);
        assert_eq!(
            published.artifact_ref().media_type(),
            "application/octet-stream"
        );
        assert_eq!(published.artifact_ref().producer_attempt(), "attempt-1");
        let uri = client
            .actual_requests()
            .next()
            .expect("artifact PUT")
            .uri()
            .parse::<http::Uri>()
            .expect("valid request URI");
        assert_eq!(uri.path(), EMPTY_KEY);
    }

    #[tokio::test]
    async fn artifact_cap_is_inclusive_and_oversize_precedes_dispatch() {
        assert_eq!(validate_artifact_length(MAX_ARTIFACT_BYTES), Ok(()));
        let store = S3Store::new(
            "test-bucket",
            Region::new("us-east-1"),
            test_builder(NeverClient::new()),
        );
        let result = tokio::time::timeout(
            Duration::from_millis(20),
            publish(
                &store,
                vec![0; MAX_ARTIFACT_BYTES + 1],
                "application/octet-stream".into(),
                "attempt".into(),
                1,
                None,
            ),
        )
        .await
        .expect("oversize input returns before dispatch");
        assert!(matches!(result, Err(PublicationError::TooLarge)));
    }

    #[tokio::test]
    async fn publication_failures_do_not_mint_artifact_witnesses() {
        let bytes = b"artifact".to_vec();
        let (store, _) = replay_store(vec![
            response(500, &[], SdkBody::empty()),
            response(500, &[], SdkBody::empty()),
        ]);
        assert!(matches!(
            publish(
                &store,
                bytes.clone(),
                "application/octet-stream".into(),
                "attempt".into(),
                1,
                None,
            )
            .await,
            Err(PublicationError::Unresolved)
        ));

        let (store, _) = replay_store(vec![
            response(409, &[], SdkBody::empty()),
            response(200, &[], b"wrong".to_vec()),
        ]);
        assert!(matches!(
            publish(
                &store,
                bytes,
                "application/octet-stream".into(),
                "attempt".into(),
                1,
                None,
            )
            .await,
            Err(PublicationError::IntegrityMismatch)
        ));
    }

    #[tokio::test]
    async fn one_blob_supports_distinct_published_metadata() {
        let bytes = b"same artifact".to_vec();
        let (store, client) = replay_store(vec![
            response(200, &[], SdkBody::empty()),
            response(409, &[], SdkBody::empty()),
            response(200, &[], bytes.clone()),
        ]);
        let first = publish(
            &store,
            bytes.clone(),
            "text/plain".into(),
            "attempt-1".into(),
            1,
            None,
        )
        .await
        .expect("first publication");
        let second = publish(
            &store,
            bytes,
            "text/plain".into(),
            "attempt-2".into(),
            2,
            Some("pilot".into()),
        )
        .await
        .expect("duplicate verifies");
        assert_eq!(
            first.artifact_ref().digest(),
            second.artifact_ref().digest()
        );
        assert_ne!(
            first.artifact_ref().producer_attempt(),
            second.artifact_ref().producer_attempt()
        );
        assert_ne!(
            first.artifact_ref().creation_time_unix_ms(),
            second.artifact_ref().creation_time_unix_ms()
        );
        assert_eq!(client.actual_requests().count(), 3);
        let first_uri = client.actual_requests().next().expect("first PUT").uri();
        let second_uri = client.actual_requests().nth(1).expect("second PUT").uri();
        assert_eq!(first_uri, second_uri);
    }
}
