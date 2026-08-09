use std::{error::Error, fmt, time::Duration};

use aws_sdk_s3::{
    config::{Builder, Region, retry::RetryConfig, timeout::TimeoutConfig},
    error::SdkError,
    operation::{
        get_object::GetObjectError,
        put_object::{PutObjectError, PutObjectOutput, builders::PutObjectFluentBuilder},
    },
    primitives::ByteStream,
};

const OPERATION_TIMEOUT: Duration = Duration::from_secs(30);
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Eq, PartialEq)]
pub struct ETag(String);

#[derive(Eq, PartialEq)]
pub enum GetOutcome {
    Found { bytes: Vec<u8>, etag: ETag },
    NotFound,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GetError {
    TooLarge,
    MissingETag,
    Transport,
}

impl fmt::Display for GetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::TooLarge => "object exceeds the read limit",
            Self::MissingETag => "object response is missing a version token",
            Self::Transport => "object read failed",
        })
    }
}

impl Error for GetError {}

#[derive(Eq, PartialEq)]
pub enum MutationOutcome {
    Committed { etag: Option<ETag> },
    NotFound,
    Conflict,
    PreconditionFailed,
    AmbiguousConflict,
    Unknown,
    ProvenNotSent,
}

#[derive(Default)]
pub struct AttemptHistory {
    may_have_been_sent: bool,
}

pub struct S3Store {
    client: aws_sdk_s3::Client,
    bucket: String,
}

impl S3Store {
    pub fn new(bucket: impl Into<String>, region: Region, builder: Builder) -> Self {
        Self {
            client: aws_sdk_s3::Client::from_conf(configured(region, builder)),
            bucket: bucket.into(),
        }
    }

    pub async fn get_object(&self, key: &str, max_bytes: usize) -> Result<GetOutcome, GetError> {
        let output = match self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
        {
            Ok(output) => output,
            Err(error) if service_status(&error) == Some(404) => return Ok(GetOutcome::NotFound),
            Err(_) => return Err(GetError::Transport),
        };

        let declared_length = match output.content_length() {
            Some(length) => usize::try_from(length).map_err(|_| GetError::Transport)?,
            None => 0,
        };
        if declared_length > max_bytes {
            return Err(GetError::TooLarge);
        }
        let etag = output
            .e_tag()
            .map(|value| ETag(value.to_owned()))
            .ok_or(GetError::MissingETag)?;
        let mut body = output.body;
        let mut bytes = Vec::with_capacity(declared_length);
        while let Some(chunk) = body.try_next().await.map_err(|_| GetError::Transport)? {
            if chunk.len() > max_bytes - bytes.len() {
                return Err(GetError::TooLarge);
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(GetOutcome::Found { bytes, etag })
    }

    pub async fn put_if_absent(
        &self,
        key: &str,
        bytes: Vec<u8>,
        history: &mut AttemptHistory,
    ) -> MutationOutcome {
        self.send_mutation(
            self.client
                .put_object()
                .bucket(&self.bucket)
                .key(key)
                .body(ByteStream::from(bytes))
                .if_none_match("*"),
            history,
        )
        .await
    }

    pub async fn put_if_match(
        &self,
        key: &str,
        bytes: Vec<u8>,
        etag: &ETag,
        history: &mut AttemptHistory,
    ) -> MutationOutcome {
        self.send_mutation(
            self.client
                .put_object()
                .bucket(&self.bucket)
                .key(key)
                .body(ByteStream::from(bytes))
                .if_match(&etag.0),
            history,
        )
        .await
    }

    async fn send_mutation(
        &self,
        request: PutObjectFluentBuilder,
        history: &mut AttemptHistory,
    ) -> MutationOutcome {
        let prior_unknown = history.may_have_been_sent;
        history.may_have_been_sent = true;
        let outcome = classify_mutation_result(request.send().await, prior_unknown);
        history.may_have_been_sent = matches!(
            outcome,
            MutationOutcome::Unknown | MutationOutcome::AmbiguousConflict
        );
        outcome
    }
}

fn configured(region: Region, builder: Builder) -> aws_sdk_s3::Config {
    let timeouts = TimeoutConfig::builder()
        .operation_timeout(OPERATION_TIMEOUT)
        .operation_attempt_timeout(ATTEMPT_TIMEOUT)
        .build();
    builder
        .region(region)
        .retry_config(RetryConfig::disabled())
        .timeout_config(timeouts)
        .behavior_version_latest()
        .build()
}

type PutResult = Result<PutObjectOutput, SdkError<PutObjectError>>;

fn classify_mutation_result(result: PutResult, prior_unknown: bool) -> MutationOutcome {
    match result {
        Ok(output) => MutationOutcome::Committed {
            etag: output.e_tag().map(|value| ETag(value.to_owned())),
        },
        Err(SdkError::ConstructionFailure(_)) if !prior_unknown => MutationOutcome::ProvenNotSent,
        Err(SdkError::ServiceError(error)) => match error.raw().status().as_u16() {
            404 => MutationOutcome::NotFound,
            409 | 412 if prior_unknown => MutationOutcome::AmbiguousConflict,
            409 => MutationOutcome::Conflict,
            412 => MutationOutcome::PreconditionFailed,
            _ => MutationOutcome::Unknown,
        },
        Err(_) => MutationOutcome::Unknown,
    }
}

fn service_status(error: &SdkError<GetObjectError>) -> Option<u16> {
    error
        .raw_response()
        .map(|response| response.status().as_u16())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    use aws_sdk_s3::{
        config::{Credentials, HttpClient},
        error::ConnectorError,
    };
    #[allow(deprecated)]
    use aws_smithy_runtime::client::http::test_util::{
        NeverClient, ReplayEvent, StaticReplayClient,
    };
    use aws_smithy_types::body::SdkBody;

    const TEST_ETAG: &str = "\"opaque-token:part-7\"";

    fn test_builder(http_client: impl HttpClient + 'static) -> Builder {
        aws_sdk_s3::Config::builder()
            .credentials_provider(Credentials::for_tests())
            .endpoint_url("https://s3.test.invalid")
            .http_client(http_client)
    }

    fn response(
        status: u16,
        headers: &[(&str, &str)],
        body: impl Into<SdkBody>,
    ) -> http::Response<SdkBody> {
        let mut builder = http::Response::builder().status(status);
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        builder.body(body.into()).expect("valid test response")
    }

    fn replay_store(responses: Vec<http::Response<SdkBody>>) -> (S3Store, StaticReplayClient) {
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

    fn classify(error: SdkError<PutObjectError>, prior_unknown: bool) -> MutationOutcome {
        classify_mutation_result(Err(error), prior_unknown)
    }

    fn raw_response(status: u16) -> aws_sdk_s3::config::http::HttpResponse {
        response(status, &[], SdkBody::empty())
            .try_into()
            .expect("valid SDK response")
    }

    #[tokio::test]
    async fn conditional_headers_preserve_the_opaque_etag() {
        let (create_store, create_client) = replay_store(vec![response(
            200,
            &[("etag", "\"created\"")],
            SdkBody::empty(),
        )]);
        let mut history = AttemptHistory::default();
        let outcome = create_store
            .put_if_absent("events/event.cbor.zst", b"event".to_vec(), &mut history)
            .await;
        assert!(matches!(outcome, MutationOutcome::Committed { .. }));
        let create_header = create_client
            .actual_requests()
            .next()
            .expect("create request")
            .headers()
            .get("if-none-match")
            .map(str::to_owned);
        assert_eq!(create_header.as_deref(), Some("*"));
        assert!(
            create_client
                .actual_requests()
                .next()
                .expect("create request")
                .headers()
                .get("if-match")
                .is_none()
        );

        let (store, client) = replay_store(vec![
            response(
                200,
                &[("content-length", "4"), ("etag", TEST_ETAG)],
                b"head".to_vec(),
            ),
            response(200, &[("etag", "\"replaced\"")], SdkBody::empty()),
        ]);
        let etag = match store
            .get_object("head.json", 4)
            .await
            .expect("get succeeds")
        {
            GetOutcome::Found { bytes, etag } => {
                assert_eq!(bytes, b"head");
                etag
            }
            GetOutcome::NotFound => panic!("object should exist"),
        };
        let outcome = store
            .put_if_match("head.json", b"next".to_vec(), &etag, &mut history)
            .await;
        assert!(matches!(outcome, MutationOutcome::Committed { .. }));
        let match_header = client
            .actual_requests()
            .nth(1)
            .expect("replacement request")
            .headers()
            .get("if-match")
            .map(str::to_owned);
        assert_eq!(match_header.as_deref(), Some(TEST_ETAG));
        assert!(
            client
                .actual_requests()
                .nth(1)
                .expect("replacement request")
                .headers()
                .get("if-none-match")
                .is_none()
        );
    }

    #[tokio::test]
    async fn get_preserves_not_found_and_enforces_both_size_bounds() {
        let (store, _) = replay_store(vec![response(404, &[], SdkBody::empty())]);
        assert!(matches!(
            store.get_object("missing", 8).await,
            Ok(GetOutcome::NotFound)
        ));

        let (store, _) = replay_store(vec![response(500, &[], SdkBody::empty())]);
        assert!(matches!(
            store.get_object("failed", 8).await,
            Err(GetError::Transport)
        ));

        let (store, _) = replay_store(vec![response(
            200,
            &[("content-length", "9"), ("etag", TEST_ETAG)],
            SdkBody::empty(),
        )]);
        assert!(matches!(
            store.get_object("large", 8).await,
            Err(GetError::TooLarge)
        ));

        let (store, _) = replay_store(vec![response(
            200,
            &[("etag", TEST_ETAG)],
            b"123456789".to_vec(),
        )]);
        assert!(matches!(
            store.get_object("streamed-large", 8).await,
            Err(GetError::TooLarge)
        ));

        let (store, _) = replay_store(vec![response(
            200,
            &[("content-length", "-1"), ("etag", TEST_ETAG)],
            SdkBody::empty(),
        )]);
        assert!(matches!(
            store.get_object("invalid-length", 8).await,
            Err(GetError::Transport)
        ));
    }

    #[tokio::test]
    async fn get_returns_exact_bytes_and_requires_an_etag() {
        let (store, _) = replay_store(vec![response(
            200,
            &[("content-length", "5"), ("etag", TEST_ETAG)],
            b"bytes".to_vec(),
        )]);
        match store.get_object("object", 5).await.expect("get succeeds") {
            GetOutcome::Found { bytes, etag } => {
                assert_eq!(bytes, b"bytes");
                assert!(etag == ETag(TEST_ETAG.to_owned()));
            }
            GetOutcome::NotFound => panic!("object should exist"),
        }

        let (store, _) = replay_store(vec![response(
            200,
            &[("content-length", "0")],
            SdkBody::empty(),
        )]);
        assert!(matches!(
            store.get_object("missing-etag", 0).await,
            Err(GetError::MissingETag)
        ));
    }

    #[tokio::test]
    async fn first_attempt_service_statuses_remain_typed() {
        for (status, expected) in [
            (404, MutationOutcome::NotFound),
            (409, MutationOutcome::Conflict),
            (412, MutationOutcome::PreconditionFailed),
            (500, MutationOutcome::Unknown),
        ] {
            let (store, _) = replay_store(vec![response(status, &[], SdkBody::empty())]);
            let mut history = AttemptHistory::default();
            let outcome = store
                .put_if_absent("object", Vec::new(), &mut history)
                .await;
            assert!(outcome == expected, "status {status}");
        }
    }

    #[test]
    fn ambiguous_sdk_failures_remain_unknown() {
        let timeout = SdkError::timeout_error(io::Error::new(io::ErrorKind::TimedOut, "timeout"));
        assert!(classify(timeout, false) == MutationOutcome::Unknown);

        let reset = SdkError::dispatch_failure(ConnectorError::io(
            io::Error::new(io::ErrorKind::ConnectionReset, "reset").into(),
        ));
        assert!(classify(reset, false) == MutationOutcome::Unknown);

        let pre_connection = SdkError::dispatch_failure(
            ConnectorError::user(io::Error::other("invalid request").into()).never_connected(),
        );
        assert!(classify(pre_connection, false) == MutationOutcome::Unknown);

        let lost_response = SdkError::response_error(
            io::Error::new(io::ErrorKind::UnexpectedEof, "lost response"),
            raw_response(200),
        );
        assert!(classify(lost_response, false) == MutationOutcome::Unknown);
    }

    #[test]
    fn construction_failure_is_proven_not_sent_only_with_clean_history() {
        let clean = SdkError::construction_failure(io::Error::other("construction"));
        assert!(classify(clean, false) == MutationOutcome::ProvenNotSent);

        let tainted = SdkError::construction_failure(io::Error::other("construction"));
        assert!(classify(tainted, true) == MutationOutcome::Unknown);
    }

    #[tokio::test]
    async fn cancellation_taints_later_conflicts() {
        let store = S3Store::new(
            "test-bucket",
            Region::new("us-east-1"),
            test_builder(NeverClient::new()),
        );
        let mut history = AttemptHistory::default();
        let timed_out = tokio::time::timeout(
            Duration::from_millis(20),
            store.put_if_absent("object", Vec::new(), &mut history),
        )
        .await;
        assert!(timed_out.is_err());
        assert!(history.may_have_been_sent);

        let (store, _) = replay_store(vec![
            response(409, &[], SdkBody::empty()),
            response(412, &[], SdkBody::empty()),
            response(200, &[], SdkBody::empty()),
        ]);
        let conflict = store
            .put_if_absent("object", Vec::new(), &mut history)
            .await;
        assert!(conflict == MutationOutcome::AmbiguousConflict);
        let precondition = store
            .put_if_absent("object", Vec::new(), &mut history)
            .await;
        assert!(precondition == MutationOutcome::AmbiguousConflict);
        assert!(history.may_have_been_sent);

        let committed = store
            .put_if_absent("object", Vec::new(), &mut history)
            .await;
        assert!(matches!(
            committed,
            MutationOutcome::Committed { etag: None }
        ));
        assert!(!history.may_have_been_sent);
    }

    #[test]
    fn client_configuration_enforces_one_attempt_and_timeouts() {
        let config = configured(Region::new("us-east-1"), aws_sdk_s3::Config::builder());
        assert_eq!(
            config.retry_config().expect("retry config").max_attempts(),
            1
        );
        let timeouts = config.timeout_config().expect("timeout config");
        assert_eq!(timeouts.operation_timeout(), Some(OPERATION_TIMEOUT));
        assert_eq!(timeouts.operation_attempt_timeout(), Some(ATTEMPT_TIMEOUT));
    }

    #[test]
    fn public_error_text_is_generic() {
        assert_eq!(
            GetError::TooLarge.to_string(),
            "object exceeds the read limit"
        );
        assert_eq!(
            GetError::MissingETag.to_string(),
            "object response is missing a version token"
        );
        assert_eq!(GetError::Transport.to_string(), "object read failed");
    }
}
