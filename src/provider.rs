//! Concrete Amazon Bedrock boundary for one bounded model invocation.
//!
//! Dispatch uses the non-streaming `Converse` operation, whose typed inference
//! configuration carries the output-token cap and whose typed response carries the stop
//! reason and reported token use. The opaque-body `InvokeModel` operation would move both
//! into a per-model-family JSON dialect this crate would then own.
//!
//! Client construction disables SDK retries and applies operation and attempt timeouts
//! after caller configuration, so a supplied builder cannot re-enable retries or drop the
//! bounds. Invocation marks [`AttemptHistory`] before awaiting the SDK, so cancellation
//! retains possible-send evidence: only a pre-dispatch refusal and a construction failure
//! with clean history prove no request was sent, while transport, timeout, malformed
//! response, and unclassified service failures leave the outcome unknown.
//!
//! No provider type crosses this boundary. `Converse`'s request and response types print
//! prompt and completion text in full under `Debug` — only `prompt_variables`,
//! `request_metadata`, and reasoning content are redacted — so nothing here logs or
//! debug-prints them, and every outcome carries owned domain values instead.

use std::{error::Error, fmt, num::NonZeroU32, time::Duration};

use aws_sdk_bedrockruntime::{
    config::{
        Builder, Region, StalledStreamProtectionConfig, retry::RetryConfig, timeout::TimeoutConfig,
    },
    error::SdkError,
    operation::converse::{ConverseError, ConverseOutput as ConverseResponse},
    types::{
        ContentBlock, ConversationRole, ConverseOutput as ResponseBody, InferenceConfiguration,
        Message, StopReason, SystemContentBlock,
    },
};
use sha2::{Digest as _, Sha256};

use crate::storage::s3::AttemptHistory;

/// Whole-operation bound, including every byte of the completion.
const OPERATION_TIMEOUT: Duration = Duration::from_secs(120);
/// Per-attempt bound. Retries are disabled, so exactly one attempt runs under it.
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(90);
/// Ceiling on any profile's own output-token ceiling.
///
/// `InferenceConfiguration::max_tokens` is an `i32`, so a cap above this cannot be sent.
const MAX_OUTPUT_TOKEN_CEILING: u32 = i32::MAX as u32;
/// Bound on one prompt or system text, applied before dispatch.
pub const MAX_PROMPT_BYTES: usize = 1024 * 1024;
/// Bound on the completion text retained from one response.
pub const MAX_COMPLETION_BYTES: usize = 1024 * 1024;

const REQUEST_DOMAIN: &[u8] = b"ravel.model.request\0";
const PROFILE_DOMAIN: &[u8] = b"ravel.model.profile\0";

/// The providers this MVP dispatches to.
///
/// A closed enum with no wildcard match anywhere in the crate: a second provider fails to
/// compile until every decision site accounts for it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModelProvider {
    Bedrock,
}

impl ModelProvider {
    /// Stable identifier recorded alongside an invocation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bedrock => "bedrock",
        }
    }
}

/// Static category for a profile or request this boundary refuses to build.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProfileError {
    EmptyIdentifier,
    IdentifierTooLong,
    CeilingOutOfRange,
    CapAboveCeiling,
    ProbabilityOutOfRange,
    TooManyStopSequences,
    TextTooLarge,
    TextEmpty,
}

impl fmt::Display for ProfileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::EmptyIdentifier => "model profile identifier is empty",
            Self::IdentifierTooLong => "model profile identifier exceeds the recorded length",
            Self::CeilingOutOfRange => "model output-token ceiling is outside the sendable range",
            Self::CapAboveCeiling => "output-token cap exceeds the profile ceiling",
            Self::ProbabilityOutOfRange => "sampling probability is outside 0..=1",
            Self::TooManyStopSequences => "profile declares more stop sequences than permitted",
            Self::TextTooLarge => "request text exceeds the prompt limit",
            Self::TextEmpty => "request text is empty",
        })
    }
}

impl Error for ProfileError {}

const MAX_IDENTIFIER_BYTES: usize = 256;
const MAX_STOP_SEQUENCES: usize = 4;

/// One fixed model configuration, pinned before any request is built.
///
/// Sampling knobs are stored as thousandths rather than floats because the profile digest
/// covers them: two runs must derive one address from one configuration, and `f32` gives no
/// such guarantee across formatting or platforms.
///
/// `output_token_ceiling` is the permitted range this boundary validates a cap against. It
/// is part of the pinned configuration rather than a vendor table, because a per-model
/// ceiling this crate hardcodes would be an unverifiable claim about the provider that
/// drifts silently when the provider changes it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelProfile {
    provider: ModelProvider,
    model_id: String,
    configuration_id: String,
    output_token_ceiling: NonZeroU32,
    temperature_thousandths: Option<u32>,
    top_p_thousandths: Option<u32>,
    stop_sequences: Vec<String>,
}

impl ModelProfile {
    /// # Errors
    ///
    /// Returns [`ProfileError`] when an identifier is empty or above
    /// [`MAX_IDENTIFIER_BYTES`], when `output_token_ceiling` exceeds the sendable range,
    /// when a sampling probability is above one, or when more than
    /// [`MAX_STOP_SEQUENCES`] stop sequences are declared.
    pub fn new(
        provider: ModelProvider,
        model_id: String,
        configuration_id: String,
        output_token_ceiling: NonZeroU32,
        temperature_thousandths: Option<u32>,
        top_p_thousandths: Option<u32>,
        stop_sequences: Vec<String>,
    ) -> Result<Self, ProfileError> {
        for identifier in [&model_id, &configuration_id] {
            if identifier.is_empty() {
                return Err(ProfileError::EmptyIdentifier);
            }
            if identifier.len() > MAX_IDENTIFIER_BYTES {
                return Err(ProfileError::IdentifierTooLong);
            }
        }
        if output_token_ceiling.get() > MAX_OUTPUT_TOKEN_CEILING {
            return Err(ProfileError::CeilingOutOfRange);
        }
        for probability in [temperature_thousandths, top_p_thousandths] {
            if probability.is_some_and(|value| value > 1_000) {
                return Err(ProfileError::ProbabilityOutOfRange);
            }
        }
        if stop_sequences.len() > MAX_STOP_SEQUENCES {
            return Err(ProfileError::TooManyStopSequences);
        }
        Ok(Self {
            provider,
            model_id,
            configuration_id,
            output_token_ceiling,
            temperature_thousandths,
            top_p_thousandths,
            stop_sequences,
        })
    }

    pub fn provider(&self) -> ModelProvider {
        self.provider
    }

    pub fn model_id(&self) -> &str {
        &self.model_id
    }

    pub fn configuration_id(&self) -> &str {
        &self.configuration_id
    }

    pub fn output_token_ceiling(&self) -> NonZeroU32 {
        self.output_token_ceiling
    }

    /// Address of this exact configuration, over every field that reaches the provider.
    pub fn configuration_digest(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(PROFILE_DOMAIN);
        for field in [
            self.provider.as_str(),
            self.model_id.as_str(),
            self.configuration_id.as_str(),
        ] {
            absorb(&mut hasher, field.as_bytes());
        }
        absorb_number(&mut hasher, u64::from(self.output_token_ceiling.get()));
        for probability in [self.temperature_thousandths, self.top_p_thousandths] {
            absorb_number(&mut hasher, probability.map_or(u64::MAX, u64::from));
        }
        absorb_number(&mut hasher, self.stop_sequences.len() as u64);
        for sequence in &self.stop_sequences {
            absorb(&mut hasher, sequence.as_bytes());
        }
        format!("{:x}", hasher.finalize())
    }

    fn inference_config(&self, cap: NonZeroU32) -> InferenceConfiguration {
        let thousandths = |value: Option<u32>| value.map(|value| value as f32 / 1_000.0);
        let mut builder = InferenceConfiguration::builder()
            // The cap is validated against `output_token_ceiling` before this runs, and the
            // ceiling is bounded by `i32::MAX`, so the conversion cannot wrap.
            .max_tokens(cap.get() as i32);
        if let Some(temperature) = thousandths(self.temperature_thousandths) {
            builder = builder.temperature(temperature);
        }
        if let Some(top_p) = thousandths(self.top_p_thousandths) {
            builder = builder.top_p(top_p);
        }
        for sequence in &self.stop_sequences {
            builder = builder.stop_sequences(sequence.clone());
        }
        builder.build()
    }
}

/// One invocation this boundary is willing to dispatch.
///
/// The cap is a required field with no default and no zero: a request that does not bound
/// its own output is unrepresentable. Campaign-wide token and spend limits are not this
/// boundary's concern and it reads no budget state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvocationRequest {
    profile: ModelProfile,
    system: String,
    prompt: String,
    max_output_tokens: NonZeroU32,
    operation_id: String,
}

impl InvocationRequest {
    /// # Errors
    ///
    /// Returns [`ProfileError::CapAboveCeiling`] when `max_output_tokens` exceeds the
    /// profile's ceiling, [`ProfileError::TextEmpty`] for an empty prompt, and
    /// [`ProfileError::TextTooLarge`] above [`MAX_PROMPT_BYTES`].
    pub fn new(
        profile: ModelProfile,
        system: String,
        prompt: String,
        max_output_tokens: NonZeroU32,
        operation_id: String,
    ) -> Result<Self, ProfileError> {
        if max_output_tokens > profile.output_token_ceiling {
            return Err(ProfileError::CapAboveCeiling);
        }
        if prompt.is_empty() || operation_id.is_empty() {
            return Err(ProfileError::TextEmpty);
        }
        if system.len() > MAX_PROMPT_BYTES || prompt.len() > MAX_PROMPT_BYTES {
            return Err(ProfileError::TextTooLarge);
        }
        Ok(Self {
            profile,
            system,
            prompt,
            max_output_tokens,
            operation_id,
        })
    }

    pub fn profile(&self) -> &ModelProfile {
        &self.profile
    }

    pub fn max_output_tokens(&self) -> NonZeroU32 {
        self.max_output_tokens
    }

    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    /// Address of this invocation, over the values this boundary sends.
    ///
    /// The digest covers the request as this module owns it, never the SDK's serialized
    /// frame: it exists to tell two invocations apart and to bind a manifest to one, and
    /// hashing vendor-serialized bytes would move every address on an SDK upgrade that
    /// changed field order. It is not a claim that the wire frame can be reproduced.
    ///
    /// Length-prefixing each field keeps two different splits of the same bytes from
    /// colliding.
    pub fn request_digest(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(REQUEST_DOMAIN);
        absorb(&mut hasher, self.profile.configuration_digest().as_bytes());
        absorb(&mut hasher, self.system.as_bytes());
        absorb(&mut hasher, self.prompt.as_bytes());
        absorb_number(&mut hasher, u64::from(self.max_output_tokens.get()));
        absorb(&mut hasher, self.operation_id.as_bytes());
        format!("{:x}", hasher.finalize())
    }
}

fn absorb(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

fn absorb_number(hasher: &mut Sha256, value: u64) {
    hasher.update(value.to_be_bytes());
}

/// Provider-reported token use, copied out of the response as scalars.
///
/// Reported use is evidence, not confirmed spend.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReportedUse {
    input_tokens: u32,
    output_tokens: u32,
    total_tokens: u32,
}

impl ReportedUse {
    pub fn input_tokens(self) -> u32 {
        self.input_tokens
    }

    pub fn output_tokens(self) -> u32 {
        self.output_tokens
    }

    pub fn total_tokens(self) -> u32 {
        self.total_tokens
    }
}

/// Why the provider stopped generating, in this crate's own vocabulary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TerminalReason {
    EndTurn,
    StopSequence,
    /// The output-token cap bounded the completion, so it is truncated rather than whole.
    CapReached,
    ContextWindowExceeded,
    ContentFiltered,
    GuardrailIntervened,
    /// The provider reported its own output as malformed.
    ModelOutputMalformed,
    /// A stop reason this crate does not model, which a provider may add at any time.
    Unrecognized,
}

impl TerminalReason {
    /// A refusal produced no usable completion, whatever text accompanied it.
    fn is_refusal(self) -> bool {
        matches!(self, Self::ContentFiltered | Self::GuardrailIntervened)
    }
}

/// Knowledge retained after one physical invocation attempt.
///
/// Every variant except `Refused` and `Completed` leaves the remote outcome either known
/// to have failed or unknown; none of them asserts the provider did no work.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InvocationOutcome {
    /// The provider returned a completion.
    ///
    /// `reported_use` is `None` only if a response carries no usage block at all. The
    /// current deserializer does not produce that: `usage` is a required member of the
    /// `Converse` output, so an omitted block deserializes to zero counts instead. A
    /// consumer therefore cannot read zeros as proof that no tokens were billed, and the
    /// `None` arm stays because the outcome has to remain total if that changes.
    Completed {
        text: String,
        reason: TerminalReason,
        provider_request_id: Option<String>,
        reported_use: Option<ReportedUse>,
    },
    /// The provider declined to answer. Any accompanying text is discarded.
    Refused {
        reason: TerminalReason,
        provider_request_id: Option<String>,
        reported_use: Option<ReportedUse>,
    },
    /// The provider throttled, exhausted a quota, was unavailable, or was not ready.
    /// Retrying is permitted; the request identity does not change.
    RateLimited,
    /// The provider rejected the request as invalid. Retrying it unchanged cannot succeed.
    Rejected,
    /// A bound elapsed locally or the provider reported its own timeout. Whether the
    /// provider completed the work is unknown.
    TimedOut,
    /// The request never reached construction, so no dispatch was possible.
    ProvenNotSent,
    /// A response arrived that this boundary cannot read as a completion.
    MalformedResponse,
    /// No available evidence proves whether the provider accepted the request.
    Unknown,
}

/// Narrow Bedrock client with enforced retry and timeout policy.
pub struct BedrockTransport {
    client: aws_sdk_bedrockruntime::Client,
}

impl BedrockTransport {
    /// Builds a client after overriding caller retry, timeout, and behavior policy.
    ///
    /// Caller-provided credentials, HTTP clients, and interceptors remain installed.
    pub fn new(region: Region, builder: Builder) -> Self {
        Self {
            client: aws_sdk_bedrockruntime::Client::from_conf(configured(region, builder)),
        }
    }

    /// Dispatches one invocation, recording possible dispatch before awaiting the SDK.
    ///
    /// The cap was validated against the profile ceiling when the request was built, so
    /// the only pre-dispatch refusal left here is a request the SDK cannot construct.
    pub async fn invoke(
        &self,
        request: &InvocationRequest,
        history: &mut AttemptHistory,
    ) -> InvocationOutcome {
        let message = match Message::builder()
            .role(ConversationRole::User)
            .content(ContentBlock::Text(request.prompt.clone()))
            .build()
        {
            Ok(message) => message,
            // A build error means no request exists to send, and history stays clean.
            Err(_) => return InvocationOutcome::ProvenNotSent,
        };
        let mut call = self
            .client
            .converse()
            .model_id(request.profile.model_id())
            .messages(message)
            .inference_config(request.profile.inference_config(request.max_output_tokens));
        if !request.system.is_empty() {
            call = call.system(SystemContentBlock::Text(request.system.clone()));
        }

        history.bind(request.operation_id());
        let prior_unknown = history.may_have_been_sent;
        history.may_have_been_sent = true;
        let outcome = classify(call.send().await);
        // Only a definite provider verdict clears possible-send evidence. Every other
        // outcome carries the prior value forward, which can over-report uncertainty and
        // never under-report it.
        history.may_have_been_sent = match outcome {
            InvocationOutcome::Completed { .. }
            | InvocationOutcome::Refused { .. }
            | InvocationOutcome::Rejected => false,
            InvocationOutcome::ProvenNotSent => prior_unknown,
            InvocationOutcome::RateLimited
            | InvocationOutcome::TimedOut
            | InvocationOutcome::MalformedResponse
            | InvocationOutcome::Unknown => true,
        };
        outcome
    }
}

fn configured(region: Region, builder: Builder) -> aws_sdk_bedrockruntime::Config {
    let timeouts = TimeoutConfig::builder()
        .operation_timeout(OPERATION_TIMEOUT)
        .operation_attempt_timeout(ATTEMPT_TIMEOUT)
        .build();
    // Operation and attempt timeouts stop applying once response headers arrive, so a
    // trickling body is bounded by stalled-stream protection instead. Setting every policy
    // after the caller's builder keeps a supplied configuration from disabling it.
    builder
        .region(region)
        .retry_config(RetryConfig::disabled())
        .timeout_config(timeouts)
        .stalled_stream_protection(StalledStreamProtectionConfig::enabled().build())
        .behavior_version_latest()
        .build()
}

fn classify(result: Result<ConverseResponse, SdkError<ConverseError>>) -> InvocationOutcome {
    let response = match result {
        Ok(response) => response,
        Err(error) => return classify_error(error),
    };
    let reason = terminal_reason(response.stop_reason());
    let reported_use = response.usage().map(|usage| ReportedUse {
        input_tokens: usage.input_tokens().max(0) as u32,
        output_tokens: usage.output_tokens().max(0) as u32,
        total_tokens: usage.total_tokens().max(0) as u32,
    });
    let provider_request_id = request_id(&response);
    if reason.is_refusal() {
        return InvocationOutcome::Refused {
            reason,
            provider_request_id,
            reported_use,
        };
    }
    match completion_text(&response) {
        Some(text) => InvocationOutcome::Completed {
            text,
            reason,
            provider_request_id,
            reported_use,
        },
        None => InvocationOutcome::MalformedResponse,
    }
}

/// Concatenates the response's text blocks, refusing a response with no text at all.
///
/// Non-text blocks are dropped: this boundary requests no tools, documents, or images, so
/// a response carrying them is answering a request this crate did not make.
///
/// A completion past [`MAX_COMPLETION_BYTES`] is refused rather than truncated. The cap
/// this boundary sent bounds output tokens, so exceeding a byte bound this far above it
/// means the response did not honor the request; handing back a silently shortened answer
/// would let a caller treat a partial completion as a whole one.
fn completion_text(response: &ConverseResponse) -> Option<String> {
    let ResponseBody::Message(message) = response.output()? else {
        return None;
    };
    let mut text = String::new();
    for block in message.content() {
        if let ContentBlock::Text(chunk) = block {
            if text.len().saturating_add(chunk.len()) > MAX_COMPLETION_BYTES {
                return None;
            }
            text.push_str(chunk);
        }
    }
    (!text.is_empty()).then_some(text)
}

fn request_id(response: &ConverseResponse) -> Option<String> {
    use aws_sdk_bedrockruntime::operation::RequestId;

    response.request_id().map(str::to_owned)
}

/// Maps the provider's stop reason into this crate's vocabulary.
///
/// `StopReason` is non-exhaustive, so an unmodelled variant is named rather than silently
/// treated as a clean end of turn.
fn terminal_reason(reason: &StopReason) -> TerminalReason {
    match reason {
        StopReason::EndTurn => TerminalReason::EndTurn,
        StopReason::StopSequence => TerminalReason::StopSequence,
        StopReason::MaxTokens => TerminalReason::CapReached,
        StopReason::ModelContextWindowExceeded => TerminalReason::ContextWindowExceeded,
        StopReason::ContentFiltered => TerminalReason::ContentFiltered,
        StopReason::GuardrailIntervened => TerminalReason::GuardrailIntervened,
        StopReason::MalformedModelOutput | StopReason::MalformedToolUse => {
            TerminalReason::ModelOutputMalformed
        }
        _ => TerminalReason::Unrecognized,
    }
}

/// Classifies one SDK failure without reading any provider message string.
///
/// Every retryable service condition is named explicitly. `ModelNotReadyException` is one
/// of them: the SDK would have retried it on its own, and disabling retries moves that
/// decision here.
fn classify_error(error: SdkError<ConverseError>) -> InvocationOutcome {
    match error {
        SdkError::ConstructionFailure(_) => InvocationOutcome::ProvenNotSent,
        SdkError::TimeoutError(_) => InvocationOutcome::TimedOut,
        SdkError::DispatchFailure(_) => InvocationOutcome::Unknown,
        SdkError::ResponseError(_) => InvocationOutcome::MalformedResponse,
        SdkError::ServiceError(service) => match service.err() {
            ConverseError::ThrottlingException(_)
            | ConverseError::ServiceUnavailableException(_)
            | ConverseError::ModelNotReadyException(_) => InvocationOutcome::RateLimited,
            ConverseError::ModelTimeoutException(_) => InvocationOutcome::TimedOut,
            ConverseError::ValidationException(_)
            | ConverseError::AccessDeniedException(_)
            | ConverseError::ResourceNotFoundException(_) => InvocationOutcome::Rejected,
            // `InternalServerException` and `ModelErrorException` say the provider failed,
            // not that it did no work, so neither is a definite refusal.
            ConverseError::InternalServerException(_) | ConverseError::ModelErrorException(_) => {
                InvocationOutcome::Unknown
            }
            // An unmodelled error on a success status is a frame this boundary could not
            // read — a body-deserialization failure arrives here, not as `ResponseError`.
            // On a failure status it is a service condition this crate does not model, and
            // an unnamed condition says nothing about whether the provider did work.
            _ if service.raw().status().is_success() => InvocationOutcome::MalformedResponse,
            _ => InvocationOutcome::Unknown,
        },
        _ => InvocationOutcome::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use aws_sdk_bedrockruntime::config::{Credentials, HttpClient};
    // Bedrock Runtime re-exports no body type, having no streaming payloads of its own.
    // This is the same `aws_smithy_types` body the replay client consumes.
    use aws_sdk_s3::primitives::SdkBody;
    use aws_smithy_runtime::client::http::test_util::{
        NeverClient, ReplayEvent, StaticReplayClient,
    };

    use super::*;

    const MODEL_ID: &str = "anthropic.claude-fixture-v1:0";
    const OPERATION_ID: &str = "invoke-op-1";

    fn cap(value: u32) -> NonZeroU32 {
        NonZeroU32::new(value).unwrap()
    }

    fn profile() -> ModelProfile {
        ModelProfile::new(
            ModelProvider::Bedrock,
            MODEL_ID.into(),
            "profile-a".into(),
            cap(4096),
            Some(250),
            None,
            vec!["</done>".into()],
        )
        .unwrap()
    }

    fn request() -> InvocationRequest {
        InvocationRequest::new(
            profile(),
            "be terse".into(),
            "why is the sky blue".into(),
            cap(512),
            OPERATION_ID.into(),
        )
        .unwrap()
    }

    fn builder(http_client: impl HttpClient + 'static) -> Builder {
        aws_sdk_bedrockruntime::Config::builder()
            .credentials_provider(Credentials::for_tests())
            .endpoint_url("https://bedrock.test.invalid")
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

    fn replay(responses: Vec<http::Response<SdkBody>>) -> (BedrockTransport, StaticReplayClient) {
        let client = StaticReplayClient::new(
            responses
                .into_iter()
                .map(|response| ReplayEvent::new(http::Request::new(SdkBody::empty()), response))
                .collect(),
        );
        let transport = BedrockTransport::new(Region::new("us-east-1"), builder(client.clone()));
        (transport, client)
    }

    /// One `Converse` success frame. `stop_reason` and the usage block are what the outcome
    /// is built from, so each case below varies only those.
    ///
    /// Absent usage omits the key rather than sending `"usage":null`: the deserializer reads
    /// an explicit null as a present block whose required counts default to zero, which is
    /// indistinguishable from a genuine zero-token report.
    fn converse_body(stop_reason: &str, usage: Option<(i32, i32, i32)>, text: &str) -> String {
        let usage = usage.map_or_else(String::new, |(input, output, total)| {
            format!(
                ",\"usage\":{{\"inputTokens\":{input},\"outputTokens\":{output},\
                 \"totalTokens\":{total}}}"
            )
        });
        format!(
            "{{\"output\":{{\"message\":{{\"role\":\"assistant\",\
             \"content\":[{{\"text\":\"{text}\"}}]}}}},\
             \"stopReason\":\"{stop_reason}\"{usage}}}"
        )
    }

    fn json(body: String) -> http::Response<SdkBody> {
        response(200, &[("content-type", "application/json")], body)
    }

    async fn invoke(transport: &BedrockTransport) -> InvocationOutcome {
        let mut history = AttemptHistory::default();
        transport.invoke(&request(), &mut history).await
    }

    #[tokio::test]
    async fn a_success_frame_yields_the_completion_its_reason_and_reported_use() {
        let (transport, client) = replay(vec![json(converse_body(
            "end_turn",
            Some((11, 7, 18)),
            "rayleigh scattering",
        ))]);

        let InvocationOutcome::Completed {
            text,
            reason,
            reported_use,
            ..
        } = invoke(&transport).await
        else {
            panic!("expected a completion");
        };
        assert_eq!(text, "rayleigh scattering");
        assert_eq!(reason, TerminalReason::EndTurn);
        let reported = reported_use.expect("usage block present");
        assert_eq!(
            (
                reported.input_tokens(),
                reported.output_tokens(),
                reported.total_tokens()
            ),
            (11, 7, 18)
        );
        assert_eq!(client.actual_requests().count(), 1);
    }

    /// A cap-bounded completion is still a completion, and it is not an end of turn: the
    /// text is truncated, which a caller has to be able to tell apart.
    #[tokio::test]
    async fn a_cap_bounded_completion_is_distinguishable_from_a_finished_one() {
        let (transport, _) = replay(vec![json(converse_body(
            "max_tokens",
            Some((11, 512, 523)),
            "partial",
        ))]);

        let InvocationOutcome::Completed { reason, .. } = invoke(&transport).await else {
            panic!("expected a completion");
        };
        assert_eq!(reason, TerminalReason::CapReached);
    }

    /// A refusal carries no text forward even when the provider sent some.
    #[tokio::test]
    async fn a_filtered_or_guarded_response_is_a_refusal_without_text() {
        for (wire, expected) in [
            ("content_filtered", TerminalReason::ContentFiltered),
            ("guardrail_intervened", TerminalReason::GuardrailIntervened),
        ] {
            let (transport, _) = replay(vec![json(converse_body(
                wire,
                Some((11, 0, 11)),
                "should not survive",
            ))]);
            let outcome = invoke(&transport).await;
            let InvocationOutcome::Refused { reason, .. } = outcome else {
                panic!("expected a refusal for {wire}, got {outcome:?}");
            };
            assert_eq!(reason, expected);
        }
    }

    /// An omitted usage block reports zeros rather than nothing, because `usage` is a
    /// required member of the `Converse` output. Zeros are therefore not evidence that no
    /// tokens were billed, and this pins that so a consumer is not written against the
    /// weaker assumption.
    #[tokio::test]
    async fn an_omitted_usage_block_reports_zeros_rather_than_absence() {
        let (transport, _) = replay(vec![json(converse_body("end_turn", None, "answer"))]);

        let InvocationOutcome::Completed { reported_use, .. } = invoke(&transport).await else {
            panic!("expected a completion");
        };
        let reported = reported_use.expect("a required usage member is always populated");
        assert_eq!(
            (
                reported.input_tokens(),
                reported.output_tokens(),
                reported.total_tokens()
            ),
            (0, 0, 0)
        );
    }

    /// With retries disabled a throttled attempt is dispatched exactly once, so the caller
    /// owns the decision to retry and the operation identity cannot change underneath it.
    #[tokio::test]
    async fn a_throttled_attempt_is_rate_limited_after_exactly_one_request() {
        let (transport, client) = replay(vec![response(
            429,
            &[("x-amzn-errortype", "ThrottlingException")],
            SdkBody::from("{\"message\":\"slow down\"}"),
        )]);

        assert_eq!(invoke(&transport).await, InvocationOutcome::RateLimited);
        assert_eq!(client.actual_requests().count(), 1);
    }

    /// Every service condition that means "retry later" maps to one outcome, named rather
    /// than swept into a wildcard. `ModelNotReadyException` is here because disabling SDK
    /// retries moved its retry decision to the caller.
    #[tokio::test]
    async fn each_retryable_service_condition_is_rate_limited() {
        for (status, error_type) in [
            (429, "ThrottlingException"),
            (503, "ServiceUnavailableException"),
            (429, "ModelNotReadyException"),
        ] {
            let (transport, _) = replay(vec![response(
                status,
                &[("x-amzn-errortype", error_type)],
                SdkBody::from("{\"message\":\"later\"}"),
            )]);
            assert_eq!(
                invoke(&transport).await,
                InvocationOutcome::RateLimited,
                "{error_type}"
            );
        }
    }

    /// A status alone does not name a service error: variant resolution reads the error-type
    /// discriminator, so a bare 429 is an unclassified failure rather than throttling.
    #[tokio::test]
    async fn a_status_without_an_error_type_discriminator_is_unknown_not_rate_limited() {
        let (transport, _) = replay(vec![response(429, &[], SdkBody::from("{}"))]);

        assert_eq!(invoke(&transport).await, InvocationOutcome::Unknown);
    }

    /// An invalid request is refused definitively: repeating it unchanged cannot succeed,
    /// which is what separates it from a rate limit.
    #[tokio::test]
    async fn a_rejected_request_is_not_retryable() {
        let (transport, _) = replay(vec![response(
            400,
            &[("x-amzn-errortype", "ValidationException")],
            SdkBody::from("{\"message\":\"bad input\"}"),
        )]);

        assert_eq!(invoke(&transport).await, InvocationOutcome::Rejected);
    }

    /// A provider failure says the provider failed, not that it did no work.
    #[tokio::test]
    async fn a_provider_side_failure_leaves_the_outcome_unknown() {
        for (status, error_type) in [
            (500, "InternalServerException"),
            (424, "ModelErrorException"),
        ] {
            let (transport, _) = replay(vec![response(
                status,
                &[("x-amzn-errortype", error_type)],
                SdkBody::from("{\"message\":\"failed\"}"),
            )]);
            assert_eq!(
                invoke(&transport).await,
                InvocationOutcome::Unknown,
                "{error_type}"
            );
        }
    }

    /// A frame this boundary cannot read as a completion is malformed, and malformed is not
    /// the same as unknown: the provider answered, it just did not answer this request.
    #[tokio::test]
    async fn frames_without_readable_text_are_malformed() {
        for body in [
            String::from("{\"stopReason\":\"end_turn\",\"usage\":null}"),
            String::from(
                "{\"output\":{\"message\":{\"role\":\"assistant\",\"content\":[]}},\
                 \"stopReason\":\"end_turn\",\"usage\":null}",
            ),
        ] {
            let (transport, _) = replay(vec![json(body.clone())]);
            assert_eq!(
                invoke(&transport).await,
                InvocationOutcome::MalformedResponse,
                "{body}"
            );
        }
    }

    /// A body that is not a `Converse` frame at all fails inside the SDK's deserializer.
    #[tokio::test]
    async fn an_unparseable_body_is_malformed() {
        let (transport, _) = replay(vec![json(String::from("not json"))]);

        assert_eq!(
            invoke(&transport).await,
            InvocationOutcome::MalformedResponse
        );
    }

    /// A transport that never answers is bounded by the attempt timeout, and the result is
    /// unknown rather than a refusal: the request may well have reached the provider.
    #[tokio::test(start_paused = true)]
    async fn a_transport_that_never_answers_times_out_without_asserting_no_work() {
        let transport =
            BedrockTransport::new(Region::new("us-east-1"), builder(NeverClient::new()));
        let mut history = AttemptHistory::default();

        let outcome = transport.invoke(&request(), &mut history).await;
        assert_eq!(outcome, InvocationOutcome::TimedOut);
        assert!(history.may_have_been_sent());
    }

    /// Dispatch evidence survives every outcome that does not prove the provider's verdict.
    #[tokio::test]
    async fn possible_send_evidence_clears_only_on_a_definite_verdict() {
        let (transport, _) = replay(vec![json(converse_body(
            "end_turn",
            Some((1, 1, 2)),
            "answer",
        ))]);
        let mut history = AttemptHistory::default();
        history.bind(OPERATION_ID);
        history.may_have_been_sent = true;

        assert!(matches!(
            transport.invoke(&request(), &mut history).await,
            InvocationOutcome::Completed { .. }
        ));
        assert!(!history.may_have_been_sent());

        let (transport, _) = replay(vec![response(
            429,
            &[("x-amzn-errortype", "ThrottlingException")],
            SdkBody::from("{}"),
        )]);
        let mut history = AttemptHistory::default();
        assert_eq!(
            transport.invoke(&request(), &mut history).await,
            InvocationOutcome::RateLimited
        );
        assert!(history.may_have_been_sent());
    }

    #[test]
    fn a_profile_pins_every_field_the_provider_sees_in_its_digest() {
        let baseline = profile().configuration_digest();
        let vary = |profile: ModelProfile| {
            assert_ne!(profile.configuration_digest(), baseline, "{profile:?}");
        };

        vary(
            ModelProfile::new(
                ModelProvider::Bedrock,
                "other-model".into(),
                "profile-a".into(),
                cap(4096),
                Some(250),
                None,
                vec!["</done>".into()],
            )
            .unwrap(),
        );
        vary(
            ModelProfile::new(
                ModelProvider::Bedrock,
                MODEL_ID.into(),
                "profile-b".into(),
                cap(4096),
                Some(250),
                None,
                vec!["</done>".into()],
            )
            .unwrap(),
        );
        vary(
            ModelProfile::new(
                ModelProvider::Bedrock,
                MODEL_ID.into(),
                "profile-a".into(),
                cap(2048),
                Some(250),
                None,
                vec!["</done>".into()],
            )
            .unwrap(),
        );
        vary(
            ModelProfile::new(
                ModelProvider::Bedrock,
                MODEL_ID.into(),
                "profile-a".into(),
                cap(4096),
                Some(251),
                None,
                vec!["</done>".into()],
            )
            .unwrap(),
        );
        // An absent probability is not the same configuration as any present one.
        vary(
            ModelProfile::new(
                ModelProvider::Bedrock,
                MODEL_ID.into(),
                "profile-a".into(),
                cap(4096),
                None,
                None,
                vec!["</done>".into()],
            )
            .unwrap(),
        );
        vary(
            ModelProfile::new(
                ModelProvider::Bedrock,
                MODEL_ID.into(),
                "profile-a".into(),
                cap(4096),
                Some(250),
                Some(900),
                vec!["</done>".into()],
            )
            .unwrap(),
        );
        vary(
            ModelProfile::new(
                ModelProvider::Bedrock,
                MODEL_ID.into(),
                "profile-a".into(),
                cap(4096),
                Some(250),
                None,
                Vec::new(),
            )
            .unwrap(),
        );
    }

    #[test]
    fn a_request_digest_covers_the_cap_and_both_texts() {
        let baseline = request().request_digest();
        let vary = |system: &str, prompt: &str, cap_value: u32, operation: &str| {
            let request = InvocationRequest::new(
                profile(),
                system.into(),
                prompt.into(),
                cap(cap_value),
                operation.into(),
            )
            .unwrap();
            assert_ne!(request.request_digest(), baseline);
        };

        vary("be verbose", "why is the sky blue", 512, OPERATION_ID);
        vary("be terse", "why is grass green", 512, OPERATION_ID);
        // Two calls differing only in cap are two invocations, not one repeated.
        vary("be terse", "why is the sky blue", 513, OPERATION_ID);
        vary("be terse", "why is the sky blue", 512, "invoke-op-2");
        // Length prefixing keeps one concatenation from splitting two ways.
        let shifted = InvocationRequest::new(
            profile(),
            "be terse".into(),
            "why is the sky blue".into(),
            cap(512),
            OPERATION_ID.into(),
        )
        .unwrap();
        assert_eq!(shifted.request_digest(), baseline);
    }

    #[test]
    fn every_profile_and_request_rejection_fails_before_any_dispatch() {
        let long = "m".repeat(MAX_IDENTIFIER_BYTES + 1);
        for (result, expected) in [
            (
                ModelProfile::new(
                    ModelProvider::Bedrock,
                    String::new(),
                    "profile-a".into(),
                    cap(1),
                    None,
                    None,
                    Vec::new(),
                ),
                ProfileError::EmptyIdentifier,
            ),
            (
                ModelProfile::new(
                    ModelProvider::Bedrock,
                    MODEL_ID.into(),
                    long,
                    cap(1),
                    None,
                    None,
                    Vec::new(),
                ),
                ProfileError::IdentifierTooLong,
            ),
            (
                ModelProfile::new(
                    ModelProvider::Bedrock,
                    MODEL_ID.into(),
                    "profile-a".into(),
                    cap(1),
                    Some(1_001),
                    None,
                    Vec::new(),
                ),
                ProfileError::ProbabilityOutOfRange,
            ),
            (
                ModelProfile::new(
                    ModelProvider::Bedrock,
                    MODEL_ID.into(),
                    "profile-a".into(),
                    cap(1),
                    None,
                    Some(1_001),
                    Vec::new(),
                ),
                ProfileError::ProbabilityOutOfRange,
            ),
            (
                ModelProfile::new(
                    ModelProvider::Bedrock,
                    MODEL_ID.into(),
                    "profile-a".into(),
                    cap(1),
                    None,
                    None,
                    vec![String::from("a"); MAX_STOP_SEQUENCES + 1],
                ),
                ProfileError::TooManyStopSequences,
            ),
        ] {
            assert_eq!(result.unwrap_err(), expected);
        }

        // The cap is the one bound this boundary enforces before send, and the profile's
        // own ceiling is what it is enforced against.
        assert_eq!(
            InvocationRequest::new(
                profile(),
                String::new(),
                "prompt".into(),
                cap(4097),
                OPERATION_ID.into()
            )
            .unwrap_err(),
            ProfileError::CapAboveCeiling
        );
        assert!(
            InvocationRequest::new(
                profile(),
                String::new(),
                "prompt".into(),
                cap(4096),
                OPERATION_ID.into()
            )
            .is_ok()
        );
        for (system, prompt, operation, expected) in [
            (
                String::new(),
                String::new(),
                OPERATION_ID,
                ProfileError::TextEmpty,
            ),
            (
                String::new(),
                String::from("prompt"),
                "",
                ProfileError::TextEmpty,
            ),
            (
                "s".repeat(MAX_PROMPT_BYTES + 1),
                String::from("prompt"),
                OPERATION_ID,
                ProfileError::TextTooLarge,
            ),
            (
                String::new(),
                "p".repeat(MAX_PROMPT_BYTES + 1),
                OPERATION_ID,
                ProfileError::TextTooLarge,
            ),
        ] {
            assert_eq!(
                InvocationRequest::new(profile(), system, prompt, cap(512), operation.into())
                    .unwrap_err(),
                expected
            );
        }
    }

    /// The cap the request carries is the cap the provider is told, and nothing about a
    /// campaign or a grant reaches the wire.
    #[tokio::test]
    async fn the_request_sends_the_cap_the_caller_bounded_it_with() {
        let (transport, client) = replay(vec![json(converse_body(
            "end_turn",
            Some((1, 1, 2)),
            "answer",
        ))]);
        let _ = invoke(&transport).await;

        let sent = client.actual_requests().next().expect("one request");
        let body = std::str::from_utf8(sent.body().bytes().expect("in-memory body"))
            .expect("utf-8 body")
            .to_owned();
        assert!(body.contains("\"maxTokens\":512"), "{body}");
        assert!(body.contains("\"temperature\":0.25"), "{body}");
        assert!(body.contains("be terse"), "{body}");
        // The model id is one path segment, so its colon is percent-encoded.
        assert!(
            sent.uri()
                .ends_with("/model/anthropic.claude-fixture-v1%3A0/converse"),
            "{}",
            sent.uri()
        );
    }

    /// Retries are off, so the transport dispatches once and stops. A supplied builder that
    /// asks for retries does not change that.
    #[tokio::test]
    async fn a_caller_supplied_retry_policy_cannot_re_enable_retries() {
        let client = StaticReplayClient::new(vec![
            ReplayEvent::new(
                http::Request::new(SdkBody::empty()),
                response(
                    503,
                    &[("x-amzn-errortype", "ServiceUnavailableException")],
                    SdkBody::from("{}"),
                ),
            ),
            ReplayEvent::new(
                http::Request::new(SdkBody::empty()),
                json(converse_body("end_turn", Some((1, 1, 2)), "answer")),
            ),
        ]);
        let transport = BedrockTransport::new(
            Region::new("us-east-1"),
            builder(client.clone()).retry_config(
                aws_sdk_bedrockruntime::config::retry::RetryConfig::standard().with_max_attempts(5),
            ),
        );

        assert_eq!(invoke(&transport).await, InvocationOutcome::RateLimited);
        assert_eq!(client.actual_requests().count(), 1);
    }

    /// Timeouts are enforced even when the caller asks for none.
    #[tokio::test(start_paused = true)]
    async fn a_caller_supplied_timeout_policy_cannot_remove_the_bounds() {
        let transport = BedrockTransport::new(
            Region::new("us-east-1"),
            builder(NeverClient::new())
                .timeout_config(aws_sdk_bedrockruntime::config::timeout::TimeoutConfig::disabled()),
        );
        let mut history = AttemptHistory::default();

        let outcome = tokio::time::timeout(
            Duration::from_secs(600),
            transport.invoke(&request(), &mut history),
        )
        .await
        .expect("the enforced bound fires before this one");
        assert_eq!(outcome, InvocationOutcome::TimedOut);
    }
}
