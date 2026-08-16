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
//! response, and unclassified service failures all leave dispatch uncertainty in place.
//!
//! No provider type appears in an invocation's request or outcome, only in client
//! construction, and no type that does cross carries text into a log. `Converse`'s own
//! request and response types print prompt and completion text in full under `Debug`; the
//! few fields they do redact are ones this module never sets. This module neither logs nor
//! debug-prints them, and [`InvocationRequest`] and [`InvocationOutcome`] implement `Debug`
//! by hand over lengths and digests, so a caller that formats one cannot leak what a
//! derived implementation would have exposed.

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
    OperationIdentityInvalid,
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
            Self::OperationIdentityInvalid => "operation identity is empty or too long",
        })
    }
}

impl Error for ProfileError {}

/// Bound on a model identifier, a configuration identifier, and an operation identity.
pub const MAX_IDENTIFIER_BYTES: usize = 256;
/// Bound on the stop sequences one profile may pin.
pub const MAX_STOP_SEQUENCES: usize = 4;

/// One fixed model configuration, pinned before any request is built.
///
/// Sampling knobs are stored as thousandths rather than floats because the profile digest
/// covers them: an integer has exactly one byte form per value, while a float's address
/// depends on how it is rendered and admits several bit patterns for one configuration.
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

    pub fn model_id(&self) -> &str {
        &self.model_id
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
            // A presence byte rather than a reserved value: an absent knob and any present
            // one stay distinguishable without depending on a value being unreachable.
            match probability {
                None => hasher.update([0]),
                Some(value) => {
                    hasher.update([1]);
                    absorb_number(&mut hasher, u64::from(value));
                }
            }
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
#[derive(Clone, Eq, PartialEq)]
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
    /// profile's ceiling, [`ProfileError::TextEmpty`] for an empty prompt,
    /// [`ProfileError::TextTooLarge`] above [`MAX_PROMPT_BYTES`], and
    /// [`ProfileError::OperationIdentityInvalid`] when `operation_id` is empty or above
    /// [`MAX_IDENTIFIER_BYTES`].
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
        if operation_id.is_empty() || operation_id.len() > MAX_IDENTIFIER_BYTES {
            return Err(ProfileError::OperationIdentityInvalid);
        }
        if prompt.is_empty() {
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
        self.digest_over(&self.profile.configuration_digest())
    }

    fn digest_over(&self, configuration_digest: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(REQUEST_DOMAIN);
        absorb(&mut hasher, configuration_digest.as_bytes());
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

/// Prints what identifies the request, never what it says.
///
/// A derived implementation would reproduce the prompt in any log line that formats a
/// request, which is the exposure this boundary exists to contain.
impl fmt::Debug for InvocationRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `request_digest` absorbs the configuration digest, so computing it once and
        // reusing it keeps one format to two hash passes rather than three.
        let configuration_digest = self.profile.configuration_digest();
        formatter
            .debug_struct("InvocationRequest")
            .field("model_id", &self.profile.model_id)
            .field("configuration_digest", &configuration_digest)
            .field("request_digest", &self.digest_over(&configuration_digest))
            .field("max_output_tokens", &self.max_output_tokens)
            .field("operation_id", &self.operation_id)
            .field("system_bytes", &self.system.len())
            .field("prompt_bytes", &self.prompt.len())
            .finish()
    }
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
    /// Whether this reason is a definite answer that cannot carry a usable completion.
    ///
    /// Each of these may arrive with no assistant text, and any text it does carry is not a
    /// completion. Deciding the outcome from the reason rather than from the text is what
    /// keeps the reason, the provider request id, and the reported use that came with it. A
    /// context-window rejection in particular reports the input tokens the account was
    /// billed for.
    fn precludes_completion(self) -> bool {
        matches!(
            self,
            Self::ContentFiltered
                | Self::GuardrailIntervened
                | Self::ContextWindowExceeded
                | Self::ModelOutputMalformed
        )
    }
}

/// Knowledge retained after one physical invocation attempt.
///
/// `ProvenNotSent` is the only variant that asserts the provider did no work, and it is
/// sound only against a clean history. Every other variant leaves the remote outcome either
/// known to have failed or unknown.
#[derive(Clone, Eq, PartialEq)]
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
    /// The provider gave a definite answer that carries no usable completion: it filtered
    /// the content, a guardrail intervened, the input exceeded the context window, or it
    /// reported its own output as malformed. Any accompanying text is discarded, and the
    /// evidence that came with the verdict is kept.
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
    /// No request was constructed, so no dispatch was possible.
    ///
    /// Neither leg is reachable through this boundary: the message is built from values set
    /// unconditionally, and a missing credential provider still resolves far enough to fail
    /// at the connector, which is [`Self::Unknown`]. The variant stays because the outcome
    /// has to be total, and no test demonstrates the one claim that matters most.
    ProvenNotSent,
    /// A response arrived that this boundary cannot read as a completion, either because a
    /// stop reason this crate does not model carried no usable text or because the frame
    /// itself would not decode. Whatever evidence arrived is kept: a frame that reported
    /// token use was billed whether or not this crate could interpret the rest of it, and a
    /// frame that failed to decode still carries the request id that correlates the call.
    MalformedResponse {
        provider_request_id: Option<String>,
        reported_use: Option<ReportedUse>,
    },
    /// No available evidence proves whether the provider accepted the request.
    Unknown,
}

/// Prints a completion's length, never its text.
///
/// Only `Completed` carries model output. A derived implementation would put it in any log
/// line that formats an outcome, including a test assertion message.
impl fmt::Debug for InvocationOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Completed {
                text,
                reason,
                provider_request_id,
                reported_use,
            } => formatter
                .debug_struct("Completed")
                .field("text_bytes", &text.len())
                .field("reason", reason)
                .field("provider_request_id", provider_request_id)
                .field("reported_use", reported_use)
                .finish(),
            Self::Refused {
                reason,
                provider_request_id,
                reported_use,
            } => formatter
                .debug_struct("Refused")
                .field("reason", reason)
                .field("provider_request_id", provider_request_id)
                .field("reported_use", reported_use)
                .finish(),
            Self::RateLimited => formatter.write_str("RateLimited"),
            Self::Rejected => formatter.write_str("Rejected"),
            Self::TimedOut => formatter.write_str("TimedOut"),
            Self::ProvenNotSent => formatter.write_str("ProvenNotSent"),
            Self::MalformedResponse {
                provider_request_id,
                reported_use,
            } => formatter
                .debug_struct("MalformedResponse")
                .field("provider_request_id", provider_request_id)
                .field("reported_use", reported_use)
                .finish(),
            Self::Unknown => formatter.write_str("Unknown"),
        }
    }
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
            // `MessageBuilder::build` fails only on an absent role or content, both set
            // above, so no input reaches this arm. It stays because the outcome has to be
            // total, and because a request that cannot be built was never dispatched.
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
        let prior_unknown = history.mark_possible_send();
        let outcome = classify(call.send().await);
        // A verdict about this attempt is not a verdict about an earlier one. An invocation
        // has no remote state to reconcile, so nothing retires the possibility that a prior
        // attempt already reached the provider and was billed; the prior value therefore
        // always carries forward, and this attempt can only add uncertainty.
        history.resolve(
            prior_unknown
                || matches!(
                    outcome,
                    InvocationOutcome::RateLimited
                        | InvocationOutcome::TimedOut
                        | InvocationOutcome::MalformedResponse { .. }
                        | InvocationOutcome::Unknown
                ),
        );
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
    if reason.precludes_completion() {
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
        None => InvocationOutcome::MalformedResponse {
            provider_request_id,
            reported_use,
        },
    }
}

/// Concatenates the response's text blocks, refusing a response with no text at all.
///
/// Non-text blocks are dropped: this boundary requests no tools, documents, or images, so
/// a response carrying them is answering a request this crate did not make.
///
/// A completion past [`MAX_COMPLETION_BYTES`] is refused rather than truncated: handing back
/// a silently shortened answer would let a caller treat a partial completion as a whole one.
/// The bound is this boundary's own retention limit and not an inference from the cap, so a
/// profile whose cap can produce more text than this cannot complete through here.
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
    use aws_sdk_bedrockruntime::operation::RequestId;

    let provider_request_id = error.request_id().map(str::to_owned);
    match error {
        SdkError::ConstructionFailure(_) => InvocationOutcome::ProvenNotSent,
        SdkError::TimeoutError(_) => InvocationOutcome::TimedOut,
        SdkError::DispatchFailure(_) => InvocationOutcome::Unknown,
        // No fake here reaches this arm: a body the deserializer rejects arrives as a
        // service error whose source is a deserialization failure, which the success-status
        // guard below catches. It yields no usage either way, and the request id comes off
        // the raw response rather than the decoded body.
        SdkError::ResponseError(_) => InvocationOutcome::MalformedResponse {
            provider_request_id,
            reported_use: None,
        },
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
            _ if service.raw().status().is_success() => InvocationOutcome::MalformedResponse {
                provider_request_id,
                reported_use: None,
            },
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
    const PROVIDER_REQUEST_ID: &str = "req-fixture-1";
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

    /// Success frames carry a provider request id, so every outcome built from one can be
    /// checked for the correlation handle it is meant to keep.
    fn json(body: String) -> http::Response<SdkBody> {
        response(
            200,
            &[
                ("content-type", "application/json"),
                ("x-amzn-requestid", PROVIDER_REQUEST_ID),
            ],
            body,
        )
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
            provider_request_id,
        } = invoke(&transport).await
        else {
            panic!("expected a completion");
        };
        assert_eq!(
            provider_request_id.as_deref(),
            Some(PROVIDER_REQUEST_ID),
            "a completion keeps the handle that correlates it with provider-side logs"
        );
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
            String::from("{\"stopReason\":\"end_turn\"}"),
            String::from(
                "{\"output\":{\"message\":{\"role\":\"assistant\",\"content\":[]}},\
                 \"stopReason\":\"end_turn\"}",
            ),
        ] {
            let (transport, _) = replay(vec![json(body.clone())]);
            let outcome = invoke(&transport).await;
            assert!(
                matches!(outcome, InvocationOutcome::MalformedResponse { .. }),
                "{body} gave {outcome:?}"
            );
        }
    }

    /// An unreadable frame keeps whatever evidence arrived with it. A stop reason this crate
    /// does not model is the reachable case, and dropping its usage would lose spend the
    /// account was charged for the same way a modelled reason would.
    #[tokio::test]
    async fn an_unreadable_frame_keeps_the_evidence_that_arrived_with_it() {
        let (transport, _) = replay(vec![json(String::from(
            "{\"output\":{\"message\":{\"role\":\"assistant\",\"content\":[]}},\
             \"stopReason\":\"a_reason_added_after_this_crate\",\
             \"usage\":{\"inputTokens\":900000,\"outputTokens\":0,\"totalTokens\":900000}}",
        ))]);

        let outcome = invoke(&transport).await;
        let InvocationOutcome::MalformedResponse {
            reported_use,
            provider_request_id,
        } = outcome
        else {
            panic!("expected an unreadable frame, got {outcome:?}");
        };
        assert_eq!(
            reported_use
                .expect("usage survives an unreadable frame")
                .input_tokens(),
            900_000
        );
        assert_eq!(provider_request_id.as_deref(), Some(PROVIDER_REQUEST_ID));

        // A frame the deserializer rejects yields no usage, but the call stays correlatable:
        // the request id comes off the raw response, not the decoded body.
        let (undecodable, _) = replay(vec![json(String::from("not json"))]);
        let outcome = undecodable
            .invoke(&request(), &mut AttemptHistory::default())
            .await;
        let InvocationOutcome::MalformedResponse {
            reported_use,
            provider_request_id,
        } = outcome
        else {
            panic!("expected an unreadable frame, got {outcome:?}");
        };
        assert_eq!(reported_use, None);
        assert_eq!(provider_request_id.as_deref(), Some(PROVIDER_REQUEST_ID));
    }

    /// A body that is not a `Converse` frame at all fails inside the SDK's deserializer.
    #[tokio::test]
    async fn an_unparseable_body_is_malformed() {
        let (transport, _) = replay(vec![json(String::from("not json"))]);

        let outcome = invoke(&transport).await;
        assert!(
            matches!(outcome, InvocationOutcome::MalformedResponse { .. }),
            "{outcome:?}"
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

    /// No attempt's result retires an earlier attempt's possible billable work, so once
    /// evidence is set nothing this boundary learns later can clear it. Without a prior
    /// attempt, only an unresolved result sets it.
    #[tokio::test]
    async fn evidence_never_clears_and_only_unresolved_results_set_it() {
        let definite = converse_body("end_turn", Some((1, 1, 2)), "answer");
        let refused = converse_body("content_filtered", Some((1, 0, 1)), "no");
        let rejected = || {
            response(
                400,
                &[("x-amzn-errortype", "ValidationException")],
                SdkBody::from("{}"),
            )
        };
        let throttled = || {
            response(
                429,
                &[("x-amzn-errortype", "ThrottlingException")],
                SdkBody::from("{}"),
            )
        };

        // On a fresh history only an unresolved result sets the evidence.
        for (frame, expected_clean) in [
            (json(definite.clone()), true),
            (json(refused.clone()), true),
            (rejected(), true),
            (throttled(), false),
            (json(String::from("not json")), false),
            (
                response(
                    500,
                    &[("x-amzn-errortype", "InternalServerException")],
                    SdkBody::from("{}"),
                ),
                false,
            ),
        ] {
            let (transport, _) = replay(vec![frame]);
            let mut history = AttemptHistory::default();
            let outcome = transport.invoke(&request(), &mut history).await;
            assert_eq!(
                !history.may_have_been_sent(),
                expected_clean,
                "{outcome:?} left the wrong evidence"
            );
        }

        // With a prior attempt on record every outcome keeps the evidence, the definite ones
        // included: this attempt's verdict says nothing about that earlier dispatch.
        for frame in [json(definite), json(refused), rejected(), throttled()] {
            let (transport, _) = replay(vec![frame]);
            let mut history = AttemptHistory::default();
            history.bind(OPERATION_ID);
            history.mark_possible_send();
            let outcome = transport.invoke(&request(), &mut history).await;
            assert!(
                history.may_have_been_sent(),
                "{outcome:?} discarded a prior attempt's evidence"
            );
        }
    }

    /// One history covers one operation identity, and the provider path binds its own.
    #[tokio::test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "one operation identity")]
    async fn one_history_cannot_span_two_provider_operations() {
        let (transport, _) = replay(vec![json(converse_body(
            "end_turn",
            Some((1, 1, 2)),
            "answer",
        ))]);
        let mut history = AttemptHistory::default();
        history.bind("some-other-operation");

        let _ = transport.invoke(&request(), &mut history).await;
    }

    /// A connector that cannot reach the service is the one failure that never produced a
    /// response, and it is still unknown rather than proven-not-sent: the bytes may have
    /// left the process. A closed loopback port refuses immediately, so no network is used.
    ///
    /// The default client honors `HTTP_PROXY`, so under a proxy the connect may reach it
    /// instead and a non-success proxy reply reaches the same outcome by another path. The
    /// assertion still holds; what it stops proving is which path produced it. A connect
    /// that timed out instead would fail this test rather than pass it.
    #[tokio::test]
    async fn a_connector_failure_is_unknown_and_keeps_possible_send_evidence() {
        let transport = BedrockTransport::new(
            Region::new("us-east-1"),
            aws_sdk_bedrockruntime::Config::builder()
                .credentials_provider(Credentials::for_tests())
                .endpoint_url("http://127.0.0.1:1"),
        );
        let mut history = AttemptHistory::default();

        assert_eq!(
            transport.invoke(&request(), &mut history).await,
            InvocationOutcome::Unknown
        );
        assert!(history.may_have_been_sent());
    }

    /// A definite verdict that carries no completion keeps the reason and the reported use.
    /// A context-window rejection is the case that matters: it arrives on a success status
    /// with no text and reports the input tokens the account was billed for, so collapsing
    /// it to an unreadable frame would discard the billing evidence.
    #[tokio::test]
    async fn a_textless_definite_verdict_keeps_its_reason_and_reported_use() {
        for (wire, expected) in [
            (
                "model_context_window_exceeded",
                TerminalReason::ContextWindowExceeded,
            ),
            (
                "malformed_model_output",
                TerminalReason::ModelOutputMalformed,
            ),
            // Sharing an arm with the reason above is what makes this a definite verdict
            // rather than a completion, so its own wire string has to be exercised.
            ("malformed_tool_use", TerminalReason::ModelOutputMalformed),
        ] {
            let (transport, _) = replay(vec![json(format!(
                "{{\"output\":{{\"message\":{{\"role\":\"assistant\",\"content\":[]}}}},\
                 \"stopReason\":\"{wire}\",\
                 \"usage\":{{\"inputTokens\":900000,\"outputTokens\":0,\
                 \"totalTokens\":900000}}}}"
            ))]);

            let outcome = transport
                .invoke(&request(), &mut AttemptHistory::default())
                .await;
            let InvocationOutcome::Refused {
                reason,
                reported_use,
                provider_request_id,
            } = outcome
            else {
                panic!("expected a definite verdict for {wire}, got {outcome:?}");
            };
            assert_eq!(reason, expected);
            assert_eq!(provider_request_id.as_deref(), Some(PROVIDER_REQUEST_ID));
            assert_eq!(
                reported_use
                    .expect("usage survives the verdict")
                    .input_tokens(),
                900_000
            );
        }
    }

    /// Every stop reason maps to its own terminal reason, and one this crate does not model
    /// is named rather than folded into a clean end of turn.
    #[tokio::test]
    async fn every_stop_reason_maps_to_its_own_terminal_reason() {
        for (wire, expected) in [
            ("end_turn", TerminalReason::EndTurn),
            ("stop_sequence", TerminalReason::StopSequence),
            ("max_tokens", TerminalReason::CapReached),
            (
                "a_reason_added_after_this_crate",
                TerminalReason::Unrecognized,
            ),
        ] {
            let (transport, _) = replay(vec![json(converse_body(wire, Some((1, 1, 2)), "text"))]);
            let outcome = transport
                .invoke(&request(), &mut AttemptHistory::default())
                .await;
            let InvocationOutcome::Completed { reason, .. } = outcome else {
                panic!("expected a completion for {wire}, got {outcome:?}");
            };
            assert_eq!(reason, expected, "{wire}");
        }
    }

    /// A completion past the retained bound is rejected rather than truncated, so a caller
    /// cannot mistake a shortened answer for a whole one. It is not a `Refused` verdict: the
    /// provider did not decline, it answered in a way this boundary will not carry.
    #[tokio::test]
    async fn a_completion_past_the_retained_bound_is_malformed() {
        // A completion at exactly the bound is kept, so `>` cannot drift to `>=`.
        let (at_bound, _) = replay(vec![json(converse_body(
            "end_turn",
            Some((1, 1, 2)),
            &"x".repeat(MAX_COMPLETION_BYTES),
        ))]);
        assert!(matches!(
            at_bound
                .invoke(&request(), &mut AttemptHistory::default())
                .await,
            InvocationOutcome::Completed { .. }
        ));

        let oversized = "x".repeat(MAX_COMPLETION_BYTES + 1);
        let (transport, _) = replay(vec![json(converse_body(
            "end_turn",
            Some((1, 1, 2)),
            &oversized,
        ))]);

        let outcome = transport
            .invoke(&request(), &mut AttemptHistory::default())
            .await;
        assert!(
            matches!(outcome, InvocationOutcome::MalformedResponse { .. }),
            "{outcome:?}"
        );
    }

    /// The system text and the prompt reach distinct places on the wire, so exchanging them
    /// is a different request rather than the same one.
    #[tokio::test]
    async fn the_system_text_and_the_prompt_reach_distinct_wire_positions() {
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
        let system_at = body.find("be terse").expect("system text on the wire");
        let prompt_at = body
            .find("why is the sky blue")
            .expect("prompt text on the wire");
        let system_block = body.find("\"system\"").expect("a system block");
        let message_block = body.find("\"messages\"").expect("a messages block");
        // Each text sits under its own key, so a swap moves both.
        assert!(system_at > system_block, "{body}");
        assert!(prompt_at > message_block, "{body}");
        assert!(
            (system_at < message_block) == (system_block < message_block),
            "{body}"
        );
    }

    /// The pinned sampling knobs reach their own wire fields, so exchanging the two
    /// probabilities is observable.
    #[tokio::test]
    async fn each_sampling_knob_reaches_its_own_wire_field() {
        let profile = ModelProfile::new(
            ModelProvider::Bedrock,
            MODEL_ID.into(),
            "profile-a".into(),
            cap(4096),
            Some(250),
            Some(900),
            Vec::new(),
        )
        .unwrap();
        let request = InvocationRequest::new(
            profile,
            "be terse".into(),
            "why is the sky blue".into(),
            cap(512),
            OPERATION_ID.into(),
        )
        .unwrap();
        let (transport, client) = replay(vec![json(converse_body(
            "end_turn",
            Some((1, 1, 2)),
            "answer",
        ))]);
        let _ = transport
            .invoke(&request, &mut AttemptHistory::default())
            .await;

        let sent = client.actual_requests().next().expect("one request");
        let body = std::str::from_utf8(sent.body().bytes().expect("in-memory body"))
            .expect("utf-8 body")
            .to_owned();
        assert!(body.contains("\"temperature\":0.25"), "{body}");
        // 0.9 has no exact `f32`, so the wire carries the widened approximation while the
        // digest covers the exact thousandths. Only the digest has to be stable.
        assert!(body.contains("\"topP\":0.8999999761581421"), "{body}");
    }

    /// The enforced policy is read back off the built configuration, which covers the whole
    /// operation bound and stalled-stream protection: both are otherwise only observable
    /// against a slow body no fake here produces.
    #[test]
    fn the_built_configuration_carries_every_enforced_policy() {
        let config = configured(
            Region::new("us-east-1"),
            aws_sdk_bedrockruntime::Config::builder()
                .credentials_provider(Credentials::for_tests())
                .retry_config(
                    aws_sdk_bedrockruntime::config::retry::RetryConfig::standard()
                        .with_max_attempts(5),
                )
                .timeout_config(aws_sdk_bedrockruntime::config::timeout::TimeoutConfig::disabled()),
        );

        let timeouts = config.timeout_config().expect("timeouts are enforced");
        assert_eq!(timeouts.operation_timeout(), Some(OPERATION_TIMEOUT));
        assert_eq!(timeouts.operation_attempt_timeout(), Some(ATTEMPT_TIMEOUT));
        assert_eq!(
            config.retry_config().map(|retry| retry.max_attempts()),
            Some(1)
        );
        assert!(
            config
                .stalled_stream_protection()
                .expect("stalled-stream protection is enforced")
                .is_enabled()
        );
    }

    /// Evidence is written before the await, not after it. Dropping the future partway is
    /// the only way to observe that, and it is the case the boundary exists for: a cancelled
    /// invocation must not read as proof the provider did no work.
    #[tokio::test(start_paused = true)]
    async fn a_cancelled_invocation_still_records_possible_dispatch() {
        let transport =
            BedrockTransport::new(Region::new("us-east-1"), builder(NeverClient::new()));
        let mut history = AttemptHistory::default();

        // One second is far inside the enforced attempt bound, so the future is dropped
        // while the request is still in flight rather than resolved by a timeout.
        assert!(
            tokio::time::timeout(
                Duration::from_secs(1),
                transport.invoke(&request(), &mut history),
            )
            .await
            .is_err()
        );
        assert!(history.may_have_been_sent());
    }

    /// Formatting a request or an outcome must not reproduce the prompt or the completion. A
    /// single `#[derive(Debug)]` in place of either hand-written impl would undo that
    /// silently.
    #[tokio::test]
    async fn formatting_a_request_or_an_outcome_never_reveals_its_text() {
        const SECRET_PROMPT: &str = "a-prompt-that-must-not-be-logged";
        const SECRET_SYSTEM: &str = "a-system-text-that-must-not-be-logged";
        const SECRET_COMPLETION: &str = "a-completion-that-must-not-be-logged";

        let request = InvocationRequest::new(
            profile(),
            SECRET_SYSTEM.into(),
            SECRET_PROMPT.into(),
            cap(512),
            OPERATION_ID.into(),
        )
        .unwrap();
        let rendered = format!("{request:?}");
        assert!(!rendered.contains(SECRET_PROMPT), "{rendered}");
        assert!(!rendered.contains(SECRET_SYSTEM), "{rendered}");
        // What identifies the request is still there, so the redaction stays diagnosable.
        assert!(rendered.contains(&request.request_digest()), "{rendered}");
        assert!(rendered.contains(OPERATION_ID), "{rendered}");

        let (transport, _) = replay(vec![json(converse_body(
            "end_turn",
            Some((1, 1, 2)),
            SECRET_COMPLETION,
        ))]);
        let outcome = transport
            .invoke(&request, &mut AttemptHistory::default())
            .await;
        assert!(
            matches!(outcome, InvocationOutcome::Completed { .. }),
            "{outcome:?}"
        );
        let rendered = format!("{outcome:?}");
        assert!(!rendered.contains(SECRET_COMPLETION), "{rendered}");
        assert!(rendered.contains("text_bytes"), "{rendered}");
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
        // Same count, different text: the length prefix alone must not satisfy this.
        vary(
            ModelProfile::new(
                ModelProvider::Bedrock,
                MODEL_ID.into(),
                "profile-a".into(),
                cap(4096),
                Some(250),
                None,
                vec!["</halt>".into()],
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

        // The profile is digested too, so one prompt against two configurations is two
        // invocations.
        let other_profile = ModelProfile::new(
            ModelProvider::Bedrock,
            MODEL_ID.into(),
            "profile-b".into(),
            cap(4096),
            Some(250),
            None,
            vec!["</done>".into()],
        )
        .unwrap();
        assert_ne!(
            InvocationRequest::new(
                other_profile,
                "be terse".into(),
                "why is the sky blue".into(),
                cap(512),
                OPERATION_ID.into(),
            )
            .unwrap()
            .request_digest(),
            baseline
        );

        // Length prefixing is what keeps one concatenation from splitting two ways: these
        // two requests carry the same bytes across the system/prompt boundary.
        let shifted = InvocationRequest::new(
            profile(),
            "be ters".into(),
            "ewhy is the sky blue".into(),
            cap(512),
            OPERATION_ID.into(),
        )
        .unwrap();
        assert_ne!(shifted.request_digest(), baseline);

        // Identical inputs derive one address.
        let repeated = InvocationRequest::new(
            profile(),
            "be terse".into(),
            "why is the sky blue".into(),
            cap(512),
            OPERATION_ID.into(),
        )
        .unwrap();
        assert_eq!(repeated.request_digest(), baseline);
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
                // This guard is the only thing making the cap's `as i32` conversion sound.
                ModelProfile::new(
                    ModelProvider::Bedrock,
                    MODEL_ID.into(),
                    "profile-a".into(),
                    cap(MAX_OUTPUT_TOKEN_CEILING + 1),
                    None,
                    None,
                    Vec::new(),
                ),
                ProfileError::CeilingOutOfRange,
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

        // A probability of exactly one is inside the range, so the boundary is pinned where
        // it holds as well as where it fails.
        assert!(
            ModelProfile::new(
                ModelProvider::Bedrock,
                MODEL_ID.into(),
                "profile-a".into(),
                cap(1),
                Some(1_000),
                Some(1_000),
                Vec::new(),
            )
            .is_ok()
        );

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
        // Each text and identity bound holds at exactly the limit, so no `>` can drift.
        assert!(
            InvocationRequest::new(
                profile(),
                "s".repeat(MAX_PROMPT_BYTES),
                "p".repeat(MAX_PROMPT_BYTES),
                cap(512),
                "o".repeat(MAX_IDENTIFIER_BYTES),
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
                ProfileError::OperationIdentityInvalid,
            ),
            (
                String::new(),
                String::from("prompt"),
                "o".repeat(MAX_IDENTIFIER_BYTES + 1).leak(),
                ProfileError::OperationIdentityInvalid,
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
