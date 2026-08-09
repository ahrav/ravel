use sha2::{Digest, Sha256};

use crate::domain::campaign::ArtifactRef;

use super::s3::{PublicationError, S3Store};

pub const MAX_ARTIFACT_BYTES: usize = 10 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublishedArtifact(ArtifactRef);

impl PublishedArtifact {
    pub fn artifact_ref(&self) -> &ArtifactRef {
        &self.0
    }
}

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
        digest.clone(),
        bytes.len() as u64,
        media_type,
        producer_attempt,
        creation_time_unix_ms,
        retention_class,
    )
    .map_err(|_| PublicationError::InvalidInput)?;
    store
        .publish_immutable(&artifact_key(&digest), bytes, &digest)
        .await?;
    Ok(PublishedArtifact(reference))
}

fn validate_artifact_length(length: usize) -> Result<(), PublicationError> {
    if length <= MAX_ARTIFACT_BYTES {
        Ok(())
    } else {
        Err(PublicationError::TooLarge)
    }
}

fn artifact_key(digest: &str) -> String {
    format!("artifacts/sha256/{digest}")
}

#[cfg(test)]
mod tests {
    use aws_sdk_s3::{
        config::{Builder, Credentials, HttpClient, Region},
        primitives::SdkBody,
    };
    use aws_smithy_runtime::client::http::test_util::{
        NeverClient, ReplayEvent, StaticReplayClient,
    };

    use super::*;

    fn test_builder(http_client: impl HttpClient + 'static) -> Builder {
        aws_sdk_s3::Config::builder()
            .credentials_provider(Credentials::for_tests())
            .endpoint_url("https://s3.test.invalid")
            .http_client(http_client)
    }

    fn store(responses: Vec<http::Response<SdkBody>>) -> (S3Store, StaticReplayClient) {
        let events = responses
            .into_iter()
            .map(|response| ReplayEvent::new(http::Request::new(SdkBody::empty()), response))
            .collect();
        let client = StaticReplayClient::new(events);
        let store = S3Store::new(
            "test-bucket",
            Region::new("us-east-1"),
            test_builder(client.clone()),
        );
        (store, client)
    }

    fn response(status: u16, body: impl Into<SdkBody>) -> http::Response<SdkBody> {
        http::Response::builder()
            .status(status)
            .body(body.into())
            .expect("valid test response")
    }

    #[tokio::test]
    async fn zero_byte_artifact_uses_the_deterministic_digest_key() {
        let (store, client) = store(vec![response(200, SdkBody::empty())]);
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
        let expected = format!("{:x}", Sha256::digest([]));
        assert_eq!(published.artifact_ref().digest(), expected);
        assert_eq!(published.artifact_ref().size(), 0);
        let uri = client
            .actual_requests()
            .next()
            .expect("artifact PUT")
            .uri()
            .parse::<http::Uri>()
            .expect("valid request URI");
        assert_eq!(uri.path(), format!("/{}", artifact_key(&expected)));
    }

    #[tokio::test]
    async fn artifact_cap_is_inclusive_and_oversize_precedes_dispatch() {
        assert_eq!(validate_artifact_length(MAX_ARTIFACT_BYTES), Ok(()));
        let store = S3Store::new(
            "test-bucket",
            Region::new("us-east-1"),
            test_builder(NeverClient::new()),
        );
        assert!(matches!(
            publish(
                &store,
                vec![0; MAX_ARTIFACT_BYTES + 1],
                "application/octet-stream".into(),
                "attempt".into(),
                1,
                None,
            )
            .await,
            Err(PublicationError::TooLarge)
        ));
    }

    #[tokio::test]
    async fn one_blob_supports_distinct_published_metadata() {
        let bytes = b"same artifact".to_vec();
        let (store, client) = store(vec![
            response(200, SdkBody::empty()),
            response(409, SdkBody::empty()),
            response(200, bytes.clone()),
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
