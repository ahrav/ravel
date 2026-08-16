//! Concrete Amazon S3 boundary for bounded reads and conditional writes.
//!
//! Client construction disables SDK retries and applies a 30-second operation timeout
//! plus a 10-second attempt timeout after caller configuration. Mutation methods mark
//! [`crate::dispatch::AttemptHistory`] before awaiting the SDK, so cancellation retains possible-send
//! evidence. Only the pre-dispatch size rejection and a construction failure with clean
//! history prove that no request was sent; transport, timeout, response, and
//! unclassified service failures remain
//! [`MutationOutcome::Unknown`]. A `409` or `412` after possible-send evidence becomes
//! [`MutationOutcome::AmbiguousConflict`].
//!
//! Immutable publication performs at most two byte-identical create-only PUTs and one
//! exact-key verification GET. Verification ignores ETags, hashes the streamed body,
//! and requires its measured size to match.

use std::{
    error::Error,
    fmt,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use sha2::{Digest, Sha256};

use crate::dispatch::AttemptHistory;
use aws_sdk_s3::{
    config::{
        Builder, Region, StalledStreamProtectionConfig, retry::RetryConfig, timeout::TimeoutConfig,
    },
    error::SdkError,
    operation::put_object::{PutObjectError, PutObjectOutput, builders::PutObjectFluentBuilder},
    primitives::ByteStream,
};

const OPERATION_TIMEOUT: Duration = Duration::from_secs(30);
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_SINGLE_PUT_BYTES: u64 = 5 * 1024 * 1024 * 1024;

/// Opaque S3 version token passed unchanged to `If-Match`.
///
/// The type exposes no content-hash, ordering, parsing, or string-access API.
#[derive(Clone, PartialEq)]
pub struct ETag(String);

/// Result of a bounded full-object read.
pub enum GetOutcome {
    /// Complete bytes coupled to the opaque ETag from the same response.
    Found { bytes: Vec<u8>, etag: ETag },
    /// Service response with HTTP status `404`.
    NotFound,
}

/// Data-free failure category for a bounded object read.
#[derive(Debug)]
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

/// Knowledge retained after one physical conditional-write attempt.
#[derive(PartialEq)]
pub enum MutationOutcome {
    /// S3 returned success; the response may omit an ETag.
    Committed { etag: Option<ETag> },
    /// Service response with HTTP status `404`; send history does not gate this outcome.
    NotFound,
    /// Service response with HTTP status `409` and no prior possible-send evidence.
    Conflict,
    /// Service response with HTTP status `412` and no prior possible-send evidence.
    PreconditionFailed,
    /// `409` or `412` when prior possible-send evidence exists.
    AmbiguousConflict,
    /// No available evidence proves whether S3 accepted the request.
    Unknown,
    /// Request construction failed before any dispatch was possible.
    ProvenNotSent,
    /// Input exceeded the single-PUT limit before request construction.
    TooLarge,
}

/// Data-free failure category for a bounded paginated key listing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ListError {
    /// The listing names more keys than the caller's bound.
    TooMany,
    /// A truncated page without a fresh continuation token, a repeated token, or an
    /// entry without a key.
    Invalid,
    /// Transport, timeout, or service failure.
    Transport,
}

impl fmt::Display for ListError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::TooMany => "listing exceeds the key limit",
            Self::Invalid => "listing response is invalid",
            Self::Transport => "listing failed",
        })
    }
}

impl Error for ListError {}

/// Data-free failure category for immutable publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicationError {
    InvalidInput,
    IntegrityMismatch,
    NotSent,
    StorageNotFound,
    TooLarge,
    Unresolved,
}

impl fmt::Display for PublicationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidInput => "invalid publication input",
            Self::IntegrityMismatch => "immutable object does not match",
            Self::NotSent => "immutable object was not sent",
            Self::StorageNotFound => "object storage is unavailable",
            Self::TooLarge => "immutable object exceeds the write limit",
            Self::Unresolved => "immutable publication is unresolved",
        })
    }
}

impl Error for PublicationError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum VerificationOutcome {
    Matched,
    NotFound,
    Mismatch,
    Transport,
}

/// Narrow S3 client with enforced retry and timeout policy.
pub struct S3Store {
    client: aws_sdk_s3::Client,
    bucket: String,
    namespace: String,
}

impl S3Store {
    /// Builds a client after overriding caller retry, timeout, region, and behavior policy.
    ///
    /// Caller-provided credentials, HTTP clients, and interceptors remain installed.
    pub fn new(bucket: impl Into<String>, region: Region, builder: Builder) -> Self {
        static NEXT_STORE: AtomicU64 = AtomicU64::new(0);

        let bucket = bucket.into();
        let config = configured(region, builder);
        let namespace = format!(
            "{}|{bucket}#{}",
            config.region().map_or("", Region::as_ref),
            NEXT_STORE.fetch_add(1, Ordering::Relaxed)
        );
        Self {
            client: aws_sdk_s3::Client::from_conf(config),
            bucket,
            namespace,
        }
    }

    /// Identifies the object-store namespace whose keys this store resolves.
    ///
    /// Each constructed store gets its own namespace. Region and bucket alone do
    /// not identify an object store, and `aws_sdk_s3::Config` exposes no resolved
    /// endpoint to compare, so a witness is honoured only by the store that wrote
    /// the bytes. That refuses two genuinely equivalent stores, which is the
    /// conservative direction.
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// Reads a complete object without accumulating beyond `max_bytes`.
    ///
    /// A found object must include an ETag, but the ETag does not establish content
    /// identity.
    ///
    /// # Errors
    ///
    /// Returns [`GetError::TooLarge`] when either declared or streamed length exceeds
    /// the bound, [`GetError::MissingETag`] for a successful response without a token,
    /// and [`GetError::Transport`] for every other SDK or body-stream failure.
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
            Err(SdkError::ServiceError(error)) if error.raw().status().as_u16() == 404 => {
                return Ok(GetOutcome::NotFound);
            }
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
            if bytes.len().saturating_add(chunk.len()) > max_bytes {
                return Err(GetError::TooLarge);
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(GetOutcome::Found { bytes, etag })
    }

    /// Lists at most `max_keys` object keys under `prefix`, following pagination.
    ///
    /// Listings are hints: callers must re-verify anything a key claims to name. The
    /// request page size is bounded to one key beyond the caller's limit so an
    /// over-populated prefix is detected without accumulating it.
    ///
    /// # Errors
    ///
    /// Returns [`ListError::TooMany`] when the prefix holds more keys than `max_keys`,
    /// [`ListError::Invalid`] for a truncated page without a fresh continuation token, a
    /// repeated token, an entry without a key, or an endpoint that pages without
    /// delivering keys, and [`ListError::Transport`] for every SDK or service failure.
    pub async fn list_keys(
        &self,
        prefix: &str,
        start_after: Option<&str>,
        max_keys: usize,
    ) -> Result<Vec<String>, ListError> {
        let mut keys: Vec<String> = Vec::new();
        let mut token: Option<String> = None;
        // The page allowance refuses an endpoint that keeps paging without progress.
        let mut pages = max_keys.div_ceil(1_000) + 2;
        loop {
            pages = pages.checked_sub(1).ok_or(ListError::Invalid)?;
            let remaining = max_keys.saturating_sub(keys.len());
            let page = remaining.saturating_add(1).min(1_000) as i32;
            let mut request = self
                .client
                .list_objects_v2()
                .bucket(&self.bucket)
                .prefix(prefix)
                .max_keys(page);
            // `StartAfter` is defined only for the first page; once a continuation token
            // exists it carries the position, and some S3-compatible endpoints reject or
            // mishandle a request that sends both.
            if let Some(token) = &token {
                request = request.continuation_token(token);
            } else if let Some(start_after) = start_after {
                request = request.start_after(start_after);
            }
            let output = request.send().await.map_err(|_| ListError::Transport)?;
            for object in output.contents() {
                let key = object.key().ok_or(ListError::Invalid)?;
                if keys.len() == max_keys {
                    return Err(ListError::TooMany);
                }
                keys.push(key.to_owned());
            }
            if output.is_truncated() != Some(true) {
                return Ok(keys);
            }
            let next = output.next_continuation_token().ok_or(ListError::Invalid)?;
            if token.as_deref() == Some(next) {
                return Err(ListError::Invalid);
            }
            token = Some(next.to_owned());
        }
    }

    /// Sends one create-only PUT and records possible dispatch before awaiting it.
    ///
    /// The request uses `If-None-Match: *`; SDK retries remain disabled.
    pub async fn put_if_absent(
        &self,
        key: &str,
        bytes: Vec<u8>,
        history: &mut AttemptHistory,
    ) -> MutationOutcome {
        if !fits_single_put(bytes.len() as u64) {
            return MutationOutcome::TooLarge;
        }
        history.bind(key);
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

    /// Sends one replacement PUT with the exact opaque token from a validated read.
    ///
    /// Possible dispatch is recorded before awaiting the retry-disabled SDK call.
    pub async fn put_if_match(
        &self,
        key: &str,
        bytes: Vec<u8>,
        etag: &ETag,
        history: &mut AttemptHistory,
    ) -> MutationOutcome {
        if !fits_single_put(bytes.len() as u64) {
            return MutationOutcome::TooLarge;
        }
        history.bind(key);
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

    /// Resolves immutable publication with at most two PUTs and one verification GET.
    pub(crate) async fn publish_immutable(
        &self,
        key: &str,
        bytes: Vec<u8>,
        expected_digest: &str,
    ) -> Result<(), PublicationError> {
        let mut history = AttemptHistory::default();
        self.publish_with_history(key, bytes, expected_digest, &mut history)
            .await
    }

    /// Runs bounded immutable publication while preserving caller-owned send history.
    ///
    /// A typed `404` from verification permits one byte-identical resend. Any second
    /// conflict or unknown result remains unresolved.
    pub(crate) async fn publish_with_history(
        &self,
        key: &str,
        bytes: Vec<u8>,
        expected_digest: &str,
        history: &mut AttemptHistory,
    ) -> Result<(), PublicationError> {
        let expected_size = bytes.len() as u64;
        // The oversize guard has to precede the clone: a body above the single-PUT
        // limit would otherwise be duplicated in memory before put_if_absent
        // reaches its own TooLarge check.
        if !fits_single_put(expected_size) {
            return Err(PublicationError::TooLarge);
        }
        let initial = self.put_if_absent(key, bytes.clone(), history).await;
        if let Some(result) = terminal(&initial) {
            return result;
        }

        match self
            .verify_object(key, expected_digest, expected_size)
            .await
        {
            VerificationOutcome::Matched => Ok(()),
            VerificationOutcome::Mismatch => Err(PublicationError::IntegrityMismatch),
            VerificationOutcome::Transport => Err(PublicationError::Unresolved),
            VerificationOutcome::NotFound => {
                let resent = self.put_if_absent(key, bytes, history).await;
                terminal(&resent).unwrap_or(Err(PublicationError::Unresolved))
            }
        }
    }

    pub(crate) async fn verify_object(
        &self,
        key: &str,
        expected_digest: &str,
        expected_size: u64,
    ) -> VerificationOutcome {
        let output = match self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
        {
            Ok(output) => output,
            Err(SdkError::ServiceError(error)) if error.raw().status().as_u16() == 404 => {
                return VerificationOutcome::NotFound;
            }
            Err(_) => return VerificationOutcome::Transport,
        };
        match output.content_length() {
            Some(length) if length < 0 => return VerificationOutcome::Transport,
            Some(length) if length as u64 != expected_size => {
                return VerificationOutcome::Mismatch;
            }
            _ => {}
        }

        let mut body = output.body;
        let mut measured = 0_u64;
        let mut hasher = Sha256::new();
        loop {
            let chunk = match body.try_next().await {
                Ok(Some(chunk)) => chunk,
                Ok(None) => break,
                Err(_) => return VerificationOutcome::Transport,
            };
            let Ok(chunk_len) = u64::try_from(chunk.len()) else {
                return VerificationOutcome::Mismatch;
            };
            if chunk_len > expected_size - measured {
                return VerificationOutcome::Mismatch;
            }
            measured += chunk_len;
            hasher.update(&chunk);
        }
        if measured == expected_size && format!("{:x}", hasher.finalize()) == expected_digest {
            VerificationOutcome::Matched
        } else {
            VerificationOutcome::Mismatch
        }
    }

    async fn send_mutation(
        &self,
        request: PutObjectFluentBuilder,
        history: &mut AttemptHistory,
    ) -> MutationOutcome {
        let prior_unknown = history.mark_possible_send();
        let outcome = classify_mutation_result(request.send().await, prior_unknown);
        // `Committed` and `ProvenNotSent` clear `may_have_been_sent`: both resolve the object's
        // final state, which is what the ambiguity was about. `NotFound`, `Conflict`,
        // `PreconditionFailed`, and `TooLarge` do not determine whether a prior request was
        // sent, so they carry the prior value forward.
        history.resolve(match outcome {
            MutationOutcome::Committed { .. } | MutationOutcome::ProvenNotSent => false,
            MutationOutcome::Unknown | MutationOutcome::AmbiguousConflict => true,
            MutationOutcome::Conflict
            | MutationOutcome::PreconditionFailed
            | MutationOutcome::NotFound
            | MutationOutcome::TooLarge => prior_unknown,
        });
        outcome
    }
}

fn fits_single_put(length: u64) -> bool {
    length <= MAX_SINGLE_PUT_BYTES
}

fn terminal(outcome: &MutationOutcome) -> Option<Result<(), PublicationError>> {
    match outcome {
        MutationOutcome::Committed { .. } => Some(Ok(())),
        MutationOutcome::ProvenNotSent => Some(Err(PublicationError::NotSent)),
        MutationOutcome::NotFound => Some(Err(PublicationError::StorageNotFound)),
        MutationOutcome::TooLarge => Some(Err(PublicationError::TooLarge)),
        MutationOutcome::Conflict
        | MutationOutcome::PreconditionFailed
        | MutationOutcome::AmbiguousConflict
        | MutationOutcome::Unknown => None,
    }
}

fn configured(region: Region, builder: Builder) -> aws_sdk_s3::Config {
    let timeouts = TimeoutConfig::builder()
        .operation_timeout(OPERATION_TIMEOUT)
        .operation_attempt_timeout(ATTEMPT_TIMEOUT)
        .build();
    // Operation and attempt timeouts stop applying once response headers arrive,
    // so a trickling or stalled body is bounded by stalled-stream protection
    // instead. Setting it after the caller's builder keeps a supplied
    // configuration from disabling it.
    builder
        .region(region)
        .retry_config(RetryConfig::disabled())
        .timeout_config(timeouts)
        .stalled_stream_protection(StalledStreamProtectionConfig::enabled().build())
        .behavior_version_latest()
        .build()
}

fn classify_mutation_result(
    result: Result<PutObjectOutput, SdkError<PutObjectError>>,
    prior_unknown: bool,
) -> MutationOutcome {
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

#[cfg(test)]
pub(crate) mod test_support {
    use aws_sdk_s3::{
        config::{Builder, Credentials, HttpClient, Region},
        primitives::SdkBody,
    };
    use aws_smithy_runtime::client::http::test_util::{ReplayEvent, StaticReplayClient};

    use super::S3Store;

    pub(crate) fn test_builder(http_client: impl HttpClient + 'static) -> Builder {
        aws_sdk_s3::Config::builder()
            .credentials_provider(Credentials::for_tests())
            .endpoint_url("https://s3.test.invalid")
            .http_client(http_client)
    }

    pub(crate) fn response(
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

    /// Builds one scripted `ListObjectsV2` page naming `keys` in order.
    pub(crate) fn list_response(
        keys: &[&str],
        truncated: bool,
        next_token: Option<&str>,
    ) -> http::Response<SdkBody> {
        let mut body = String::from(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
             <ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
             <Name>test-bucket</Name>",
        );
        for key in keys {
            body.push_str(&format!("<Contents><Key>{key}</Key></Contents>"));
        }
        body.push_str(&format!("<IsTruncated>{truncated}</IsTruncated>"));
        if let Some(token) = next_token {
            body.push_str(&format!(
                "<NextContinuationToken>{token}</NextContinuationToken>"
            ));
        }
        body.push_str("</ListBucketResult>");
        response(200, &[("content-type", "application/xml")], body)
    }

    pub(crate) fn replay_store(
        responses: Vec<http::Response<SdkBody>>,
    ) -> (S3Store, StaticReplayClient) {
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

    /// Routes responses by path and query so concurrent requests cannot consume
    /// responses by fetch order.
    pub(crate) fn keyed_store(
        route: impl Fn(&str) -> http::Response<SdkBody> + Send + Sync + 'static,
    ) -> (S3Store, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
        let requests = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorded = requests.clone();
        let client = aws_smithy_http_client::test_util::infallible_client_fn(move |request| {
            let uri = request.uri();
            let line = match uri.query() {
                Some(query) => format!("{} {}?{query}", request.method(), uri.path()),
                None => format!("{} {}", request.method(), uri.path()),
            };
            recorded.lock().unwrap().push(line);
            route(uri.path_and_query().map_or("", |value| value.as_str()))
        });
        let store = S3Store::new(
            "test-bucket",
            Region::new("us-east-1"),
            test_builder(client),
        );
        (store, requests)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io,
        pin::Pin,
        task::{Context, Poll},
    };

    use aws_sdk_s3::{config::Region, error::ConnectorError, primitives::SdkBody};
    use aws_smithy_runtime::client::http::test_util::NeverClient;
    use bytes::Bytes;
    use http_body::{Body, Frame};

    use super::test_support::{list_response, replay_store, response, test_builder};

    const TEST_ETAG: &str = "\"opaque-token:part-7\"";

    fn classify(error: SdkError<PutObjectError>, prior_unknown: bool) -> MutationOutcome {
        classify_mutation_result(Err(error), prior_unknown)
    }

    struct ChunkedBody(Vec<&'static [u8]>);

    impl Body for ChunkedBody {
        type Data = Bytes;
        type Error = io::Error;

        fn poll_frame(
            mut self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            Poll::Ready(
                self.0
                    .pop()
                    .map(|chunk| Ok(Frame::data(Bytes::from_static(chunk)))),
            )
        }
    }

    fn chunked_body() -> SdkBody {
        SdkBody::from_body_1_x(ChunkedBody(vec![b"def", b"abc"]))
    }

    struct OverrunThenError(u8);

    impl Body for OverrunThenError {
        type Data = Bytes;
        type Error = io::Error;

        fn poll_frame(
            mut self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            let frame = match self.0 {
                0 => Some(Ok(Frame::data(Bytes::from_static(b"abcdefg")))),
                1 => Some(Err(io::Error::other("body stream failed"))),
                _ => None,
            };
            self.0 += 1;
            Poll::Ready(frame)
        }
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
        assert!(
            outcome
                == MutationOutcome::Committed {
                    etag: Some(ETag("\"created\"".to_owned())),
                }
        );
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
        let mut history = AttemptHistory::default();
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
            &[("content-length", "-1"), ("etag", TEST_ETAG)],
            SdkBody::empty(),
        )]);
        assert!(matches!(
            store.get_object("invalid-length", 8).await,
            Err(GetError::Transport)
        ));
    }

    #[tokio::test]
    async fn get_bounds_accumulated_stream_chunks() {
        let (store, _) = replay_store(vec![response(200, &[("etag", TEST_ETAG)], chunked_body())]);
        assert!(matches!(
            store.get_object("chunked", 5).await,
            Err(GetError::TooLarge)
        ));

        let (store, _) = replay_store(vec![response(200, &[("etag", TEST_ETAG)], chunked_body())]);
        match store.get_object("chunked", 6).await.expect("get succeeds") {
            GetOutcome::Found { bytes, .. } => assert_eq!(bytes, b"abcdef"),
            GetOutcome::NotFound => panic!("object should exist"),
        }
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
            response(200, &[], SdkBody::empty())
                .try_into()
                .expect("valid SDK response"),
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
        assert!(history.may_have_been_sent());

        let (store, _) = replay_store(vec![
            response(404, &[], SdkBody::empty()),
            response(409, &[], SdkBody::empty()),
            response(412, &[], SdkBody::empty()),
            response(200, &[], SdkBody::empty()),
        ]);
        // A 404 answers only this attempt, so it must not clear the taint.
        let missing = store
            .put_if_absent("object", Vec::new(), &mut history)
            .await;
        assert!(missing == MutationOutcome::NotFound);
        assert!(history.may_have_been_sent());
        let conflict = store
            .put_if_absent("object", Vec::new(), &mut history)
            .await;
        assert!(conflict == MutationOutcome::AmbiguousConflict);
        let precondition = store
            .put_if_absent("object", Vec::new(), &mut history)
            .await;
        assert!(precondition == MutationOutcome::AmbiguousConflict);
        assert!(history.may_have_been_sent());

        let committed = store
            .put_if_absent("object", Vec::new(), &mut history)
            .await;
        assert!(matches!(
            committed,
            MutationOutcome::Committed { etag: None }
        ));
        assert!(!history.may_have_been_sent());
    }

    #[test]
    fn store_configuration_overrides_caller_retry_and_timeouts() {
        let hostile_timeouts = TimeoutConfig::builder()
            .operation_timeout(Duration::from_secs(600))
            .operation_attempt_timeout(Duration::from_secs(600))
            .build();
        let store = S3Store::new(
            "test-bucket",
            Region::new("us-east-1"),
            test_builder(NeverClient::new())
                .retry_config(RetryConfig::standard())
                .timeout_config(hostile_timeouts)
                .stalled_stream_protection(StalledStreamProtectionConfig::disabled()),
        );
        let config = store.client.config();
        assert_eq!(
            config.retry_config().expect("retry config").max_attempts(),
            1
        );
        let timeouts = config.timeout_config().expect("timeout config");
        assert_eq!(timeouts.operation_timeout(), Some(OPERATION_TIMEOUT));
        assert!(
            config
                .stalled_stream_protection()
                .expect("stalled-stream protection is configured")
                .is_enabled(),
            "a caller-supplied builder must not be able to disable it"
        );
        assert_eq!(timeouts.operation_attempt_timeout(), Some(ATTEMPT_TIMEOUT));
    }

    #[tokio::test]
    async fn streamed_verification_requires_exact_digest_and_size_without_an_etag() {
        let expected_digest = format!("{:x}", Sha256::digest(b"abcdef"));
        let (store, _) = replay_store(vec![response(200, &[], chunked_body())]);
        assert_eq!(
            store.verify_object("object", &expected_digest, 6).await,
            VerificationOutcome::Matched
        );

        for body in [b"abcdeg".as_slice(), b"abc", b"abcdefg"] {
            let (store, _) =
                replay_store(vec![response(200, &[("etag", TEST_ETAG)], body.to_vec())]);
            assert_eq!(
                store.verify_object("object", &expected_digest, 6).await,
                VerificationOutcome::Mismatch
            );
        }

        let (store, _) = replay_store(vec![response(
            200,
            &[],
            SdkBody::from_body_1_x(OverrunThenError(0)),
        )]);
        assert_eq!(
            store.verify_object("object", &expected_digest, 6).await,
            VerificationOutcome::Mismatch
        );
    }

    #[tokio::test]
    async fn streamed_verification_classifies_declared_lengths() {
        let expected_digest = format!("{:x}", Sha256::digest(b"abcdef"));
        let (store, _) = replay_store(vec![response(
            200,
            &[("content-length", "7")],
            b"abcdef".to_vec(),
        )]);
        assert_eq!(
            store.verify_object("object", &expected_digest, 6).await,
            VerificationOutcome::Mismatch
        );

        let (store, _) = replay_store(vec![response(
            200,
            &[("content-length", "-1")],
            b"abcdef".to_vec(),
        )]);
        assert_eq!(
            store.verify_object("object", &expected_digest, 6).await,
            VerificationOutcome::Transport
        );

        let (store, _) = replay_store(vec![response(
            200,
            &[("content-length", "5")],
            b"abcdef".to_vec(),
        )]);
        assert_eq!(
            store.verify_object("object", &expected_digest, 6).await,
            VerificationOutcome::Mismatch
        );
    }

    #[tokio::test]
    async fn streamed_verification_preserves_not_found_and_transport() {
        let digest = format!("{:x}", Sha256::digest(b"body"));
        let (store, _) = replay_store(vec![response(404, &[], SdkBody::empty())]);
        assert_eq!(
            store.verify_object("missing", &digest, 4).await,
            VerificationOutcome::NotFound
        );

        let (store, _) = replay_store(vec![response(500, &[], SdkBody::empty())]);
        assert_eq!(
            store.verify_object("failed", &digest, 4).await,
            VerificationOutcome::Transport
        );
    }

    #[tokio::test]
    async fn immutable_publication_reconciles_once_and_resends_identical_bytes() {
        let bytes = b"immutable".to_vec();
        let digest = format!("{:x}", Sha256::digest(&bytes));
        let (store, client) = replay_store(vec![
            response(500, &[], SdkBody::empty()),
            response(404, &[], SdkBody::empty()),
            response(200, &[], SdkBody::empty()),
        ]);
        let mut history = AttemptHistory::default();
        assert_eq!(
            store
                .publish_with_history("artifact-key", bytes.clone(), &digest, &mut history,)
                .await,
            Ok(())
        );
        assert!(!history.may_have_been_sent());
        assert_eq!(client.actual_requests().count(), 3);
        for index in [0, 2] {
            let request = client.actual_requests().nth(index).expect("PUT request");
            assert_eq!(
                request
                    .uri()
                    .parse::<http::Uri>()
                    .expect("valid request URI")
                    .path(),
                "/artifact-key"
            );
            assert_eq!(request.headers().get("if-none-match"), Some("*"));
            assert_eq!(request.body().bytes(), Some(bytes.as_slice()));
        }
    }

    #[tokio::test]
    async fn immutable_publication_verifies_conflict_and_unknown_results() {
        let bytes = b"immutable".to_vec();
        let digest = format!("{:x}", Sha256::digest(&bytes));
        for initial_status in [409, 412, 500] {
            let (store, client) = replay_store(vec![
                response(initial_status, &[], SdkBody::empty()),
                response(200, &[], bytes.clone()),
            ]);
            assert_eq!(
                store
                    .publish_immutable("object", bytes.clone(), &digest)
                    .await,
                Ok(())
            );
            assert_eq!(client.actual_requests().count(), 2);
        }

        let (store, _) = replay_store(vec![
            response(409, &[], SdkBody::empty()),
            response(200, &[], b"different".to_vec()),
        ]);
        assert_eq!(
            store.publish_immutable("object", bytes, &digest).await,
            Err(PublicationError::IntegrityMismatch)
        );
    }

    #[tokio::test]
    async fn immutable_publication_stops_after_the_single_resend() {
        let bytes = b"immutable".to_vec();
        let digest = format!("{:x}", Sha256::digest(&bytes));
        for second_status in [409, 412, 500] {
            let (store, client) = replay_store(vec![
                response(500, &[], SdkBody::empty()),
                response(404, &[], SdkBody::empty()),
                response(second_status, &[], SdkBody::empty()),
            ]);
            assert_eq!(
                store
                    .publish_immutable("object", bytes.clone(), &digest)
                    .await,
                Err(PublicationError::Unresolved)
            );
            assert_eq!(client.actual_requests().count(), 3);
        }

        let (store, client) = replay_store(vec![response(404, &[], SdkBody::empty())]);
        assert_eq!(
            store
                .publish_immutable("object", bytes.clone(), &digest)
                .await,
            Err(PublicationError::StorageNotFound)
        );
        assert_eq!(client.actual_requests().count(), 1);
    }

    #[test]
    fn single_put_limit_is_inclusive() {
        assert!(fits_single_put(MAX_SINGLE_PUT_BYTES));
        assert!(!fits_single_put(MAX_SINGLE_PUT_BYTES + 1));
    }

    #[test]
    fn terminal_maps_not_sent_and_too_large_to_their_errors() {
        assert_eq!(
            terminal(&MutationOutcome::ProvenNotSent),
            Some(Err(PublicationError::NotSent))
        );
        assert_eq!(
            terminal(&MutationOutcome::TooLarge),
            Some(Err(PublicationError::TooLarge))
        );
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
        assert_eq!(
            PublicationError::Unresolved.to_string(),
            "immutable publication is unresolved"
        );
        assert_eq!(
            ListError::TooMany.to_string(),
            "listing exceeds the key limit"
        );
        assert_eq!(
            ListError::Invalid.to_string(),
            "listing response is invalid"
        );
        assert_eq!(ListError::Transport.to_string(), "listing failed");
    }

    #[tokio::test]
    async fn list_returns_zero_results_and_multi_page_keys_in_order() {
        let (store, _) = replay_store(vec![list_response(&[], false, None)]);
        assert_eq!(store.list_keys("events/", None, 8).await, Ok(Vec::new()));

        let (store, client) = replay_store(vec![
            list_response(&["events/a", "events/b"], true, Some("token-1")),
            list_response(&["events/c"], false, None),
        ]);
        assert_eq!(
            store.list_keys("events/", Some("events/0"), 8).await,
            Ok(vec![
                "events/a".to_owned(),
                "events/b".to_owned(),
                "events/c".to_owned(),
            ])
        );
        let requests: Vec<_> = client.actual_requests().collect();
        assert_eq!(requests.len(), 2);
        let first = requests[0].uri().parse::<http::Uri>().unwrap();
        let query = first.query().unwrap();
        assert!(query.contains("start-after=events%2F0"));
        assert!(query.contains("prefix=events%2F"));
        assert!(query.contains("max-keys=9"));
        let second = requests[1].uri().parse::<http::Uri>().unwrap();
        assert!(
            second
                .query()
                .unwrap()
                .contains("continuation-token=token-1")
        );
    }

    #[tokio::test]
    async fn list_rejects_repeated_tokens_missing_tokens_and_over_limit_pages() {
        let (store, _) = replay_store(vec![
            list_response(&["events/a"], true, Some("token-1")),
            list_response(&["events/b"], true, Some("token-1")),
        ]);
        assert_eq!(
            store.list_keys("events/", None, 8).await,
            Err(ListError::Invalid)
        );

        let (store, _) = replay_store(vec![list_response(&["events/a"], true, None)]);
        assert_eq!(
            store.list_keys("events/", None, 8).await,
            Err(ListError::Invalid)
        );

        let (store, _) = replay_store(vec![list_response(&["events/a", "events/b"], false, None)]);
        assert_eq!(
            store.list_keys("events/", None, 1).await,
            Err(ListError::TooMany)
        );

        // The bound applies across pages, not per page.
        let (store, _) = replay_store(vec![
            list_response(&["events/a", "events/b"], true, Some("token-1")),
            list_response(&["events/c"], false, None),
        ]);
        assert_eq!(
            store.list_keys("events/", None, 2).await,
            Err(ListError::TooMany)
        );

        let (store, _) = replay_store(vec![response(500, &[], SdkBody::empty())]);
        assert_eq!(
            store.list_keys("events/", None, 8).await,
            Err(ListError::Transport)
        );

        let (store, _) = replay_store(vec![response(200, &[], b"not-xml".to_vec())]);
        assert_eq!(
            store.list_keys("events/", None, 8).await,
            Err(ListError::Transport)
        );

        // An entry without a key is a malformed listing.
        let keyless = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
             <ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
             <Name>test-bucket</Name>\
             <Contents><Size>1</Size></Contents>\
             <IsTruncated>false</IsTruncated>\
             </ListBucketResult>";
        let (store, _) = replay_store(vec![response(
            200,
            &[("content-type", "application/xml")],
            keyless.to_owned(),
        )]);
        assert_eq!(
            store.list_keys("events/", None, 8).await,
            Err(ListError::Invalid)
        );

        // An endpoint that keeps paging fresh tokens without progress exhausts the page
        // allowance instead of looping forever.
        let mut endless = Vec::new();
        for page in 0..16 {
            endless.push(list_response(&[], true, Some(&format!("token-{page}"))));
        }
        let (store, client) = replay_store(endless);
        assert_eq!(
            store.list_keys("events/", None, 8).await,
            Err(ListError::Invalid)
        );
        assert_eq!(
            client.actual_requests().count(),
            8_usize.div_ceil(1_000) + 2
        );
    }
}
