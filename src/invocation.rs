//! Immutable invocation manifests and terminal traces, and the bytes they publish as.
//!
//! A manifest is the starting record of one model invocation and a trace is its terminal
//! record. They are separate objects because the manifest must be durable before provider
//! contact and the trace cannot exist until after it, so no single record can hold both.
//!
//! Each is content-addressed the way a plan object is: the stored bytes are a domain prefix
//! followed by canonical CBOR, and the address is the plain SHA-256 of exactly those bytes.
//! Publication therefore verifies the address with the same integrity check it applies to
//! any blob, and a decoder re-encodes what it read and refuses bytes that do not reproduce
//! themselves — so publication and replay cannot disagree about what a record says.
//!
//! Neither record carries prompt or completion text. A manifest names the request by digest,
//! and a trace retains a bounded prefix of the output beside that output's full length and
//! address. Text a caller must not find in durable history is therefore absent by
//! construction rather than by redaction after the fact.

use std::{error::Error, fmt, io::Cursor, num::NonZeroU64};

use ciborium::{de::from_reader_with_recursion_limit, ser::into_writer};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{
    domain::{proposal::MAX_STORED_INTEGER, work::WorkId},
    provider::{ModelProfile, ModelProvider, ReportedUse},
    scope::{Digest, ScopeId},
};

const MANIFEST_DOMAIN: &[u8] = b"ravel.invocation.manifest\0";
const TRACE_DOMAIN: &[u8] = b"ravel.invocation.trace\0";
const CBOR_RECURSION_LIMIT: usize = 16;

/// Cap on the CBOR body of one manifest or trace object.
pub const MAX_RECORD_CANONICAL_BYTES: usize = 64 * 1024;
/// Cap on the output prefix one trace retains.
///
/// The full output is addressed rather than stored, so this bounds the record without
/// bounding what the record can attest to.
pub const MAX_RETAINED_TEXT_BYTES: usize = 4 * 1024;

/// Media type of a published manifest object.
pub const MANIFEST_MEDIA_TYPE: &str = "application/vnd.ravel.invocation-manifest+cbor";
/// Media type of a published trace object.
pub const TRACE_MEDIA_TYPE: &str = "application/vnd.ravel.invocation-trace+cbor";

/// Static category for a record this module refuses to build or read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordError {
    OutOfRange,
    EmptyIdentifier,
    IdentifierTooLong,
    RecordTooLarge,
    InvalidEncoding,
    DigestMismatch,
}

impl fmt::Display for RecordError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::OutOfRange => "invocation record binding is outside the durable range",
            Self::EmptyIdentifier => "invocation record identifier is empty",
            Self::IdentifierTooLong => "invocation record identifier exceeds the recorded length",
            Self::RecordTooLarge => "invocation record exceeds the canonical size cap",
            Self::InvalidEncoding => "invocation record cannot be canonically encoded",
            Self::DigestMismatch => "invocation record does not match its expected address",
        })
    }
}

impl Error for RecordError {}

const MAX_IDENTIFIER_BYTES: usize = 256;

/// How one invocation ended, in the vocabulary durable history uses.
///
/// This is not the transport's outcome set. `Canceled` has no transport equivalent — the
/// transport reports what one dispatch observed, while a cancellation is decided by the node
/// that stopped waiting, and the two are different facts about the same call.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TerminalOutcome {
    Success,
    /// The provider gave a definite answer carrying no usable completion.
    Refused,
    TimedOut,
    /// Local waiting stopped. It does not assert the provider stopped.
    Canceled,
    /// The provider failed in a way that cannot succeed on an identical retry.
    DefiniteFailure,
    /// No available evidence proves whether the provider accepted the request.
    Unknown,
}

impl TerminalOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Refused => "refused",
            Self::TimedOut => "timed_out",
            Self::Canceled => "canceled",
            Self::DefiniteFailure => "definite_failure",
            Self::Unknown => "unknown",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "success" => Some(Self::Success),
            "refused" => Some(Self::Refused),
            "timed_out" => Some(Self::TimedOut),
            "canceled" => Some(Self::Canceled),
            "definite_failure" => Some(Self::DefiniteFailure),
            "unknown" => Some(Self::Unknown),
            _ => None,
        }
    }
}

/// A bounded prefix of some text, beside the length and address of the whole of it.
///
/// Storing the address rather than the text is what lets a trace stay small while still
/// attesting to output no one wants in durable history. `retained` is cut at a character
/// boundary, so a multi-byte character is dropped whole rather than split.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundedText {
    retained: String,
    full_bytes: u64,
    full_digest: String,
}

impl BoundedText {
    /// Retains at most [`MAX_RETAINED_TEXT_BYTES`] of `text` and addresses all of it.
    pub fn new(text: &str) -> Self {
        let mut cut = MAX_RETAINED_TEXT_BYTES.min(text.len());
        while cut > 0 && !text.is_char_boundary(cut) {
            cut -= 1;
        }
        Self {
            retained: text[..cut].to_owned(),
            full_bytes: text.len() as u64,
            full_digest: format!("{:x}", Sha256::digest(text.as_bytes())),
        }
    }

    pub fn retained(&self) -> &str {
        &self.retained
    }

    pub fn full_bytes(&self) -> u64 {
        self.full_bytes
    }

    pub fn full_digest(&self) -> &str {
        &self.full_digest
    }

    /// Whether the retained prefix is shorter than what it addresses.
    pub fn truncated(&self) -> bool {
        self.retained.len() as u64 != self.full_bytes
    }
}

fn identifier(value: &str) -> Result<(), RecordError> {
    if value.is_empty() {
        return Err(RecordError::EmptyIdentifier);
    }
    if value.len() > MAX_IDENTIFIER_BYTES {
        return Err(RecordError::IdentifierTooLong);
    }
    Ok(())
}

fn bounded(value: u64) -> Result<NonZeroU64, RecordError> {
    NonZeroU64::new(value)
        .filter(|value| value.get() <= MAX_STORED_INTEGER)
        .ok_or(RecordError::OutOfRange)
}

/// The authority one invocation ran under, shared by its manifest and its trace.
///
/// Both records carry it so each stands alone: a trace read without its manifest still names
/// which admitted revision, which grant, and which attempt it describes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvocationBinding {
    scope_id: ScopeId,
    plan_digest: Digest,
    work_id: WorkId,
    work_revision: NonZeroU64,
    claim_fence: NonZeroU64,
    grant_digest: Digest,
    attempt: NonZeroU64,
}

impl InvocationBinding {
    /// # Errors
    ///
    /// Returns [`RecordError::OutOfRange`] when the revision, fence, or attempt is zero or
    /// above the stored-integer range.
    pub fn new(
        scope_id: ScopeId,
        plan_digest: Digest,
        work_id: WorkId,
        work_revision: u64,
        claim_fence: u64,
        grant_digest: Digest,
        attempt: u64,
    ) -> Result<Self, RecordError> {
        Ok(Self {
            scope_id,
            plan_digest,
            work_id,
            work_revision: bounded(work_revision)?,
            claim_fence: bounded(claim_fence)?,
            grant_digest,
            attempt: bounded(attempt)?,
        })
    }

    pub fn scope_id(&self) -> &ScopeId {
        &self.scope_id
    }

    pub fn plan_digest(&self) -> &Digest {
        &self.plan_digest
    }

    pub fn work_id(&self) -> &WorkId {
        &self.work_id
    }

    pub fn work_revision(&self) -> NonZeroU64 {
        self.work_revision
    }

    pub fn claim_fence(&self) -> NonZeroU64 {
        self.claim_fence
    }

    pub fn grant_digest(&self) -> &Digest {
        &self.grant_digest
    }

    pub fn attempt(&self) -> NonZeroU64 {
        self.attempt
    }
}

/// The immutable starting record of one model invocation.
///
/// It is durable before provider contact, so it can name only what is known before the call:
/// the authority, the exact provider and model configuration, the request's address, and the
/// limits the call runs under. Nothing the provider reports belongs here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvocationManifest {
    binding: InvocationBinding,
    provider: ModelProvider,
    model_id: String,
    configuration_digest: Digest,
    request_digest: Digest,
    max_output_tokens: NonZeroU64,
    deadline_unix_ms: NonZeroU64,
    operation_id: String,
}

impl InvocationManifest {
    /// # Errors
    ///
    /// Returns [`RecordError`] for an empty or oversized identifier, or a cap or deadline
    /// outside the durable range.
    pub fn new(
        binding: InvocationBinding,
        profile: &ModelProfile,
        request_digest: Digest,
        max_output_tokens: u64,
        deadline_unix_ms: u64,
        operation_id: String,
    ) -> Result<Self, RecordError> {
        let model_id = profile.model_id().to_owned();
        let configuration_digest = Digest::new(profile.configuration_digest())
            .map_err(|_| RecordError::InvalidEncoding)?;
        identifier(&model_id)?;
        identifier(&operation_id)?;
        Ok(Self {
            binding,
            provider: profile.provider(),
            model_id,
            configuration_digest,
            request_digest,
            max_output_tokens: bounded(max_output_tokens)?,
            deadline_unix_ms: bounded(deadline_unix_ms)?,
            operation_id,
        })
    }

    /// Rebuilds a manifest from durable bytes, where no profile value is available.
    ///
    /// The wire form carries the profile's identity rather than the profile, so a reader
    /// recovers what the invocation ran under without the transport's types.
    #[expect(
        clippy::too_many_arguments,
        reason = "one parameter per wire field, so the rebuild cannot silently drop one"
    )]
    fn from_parts(
        binding: InvocationBinding,
        provider: ModelProvider,
        model_id: String,
        configuration_digest: Digest,
        request_digest: Digest,
        max_output_tokens: u64,
        deadline_unix_ms: u64,
        operation_id: String,
    ) -> Result<Self, RecordError> {
        identifier(&model_id)?;
        identifier(&operation_id)?;
        Ok(Self {
            binding,
            provider,
            model_id,
            configuration_digest,
            request_digest,
            max_output_tokens: bounded(max_output_tokens)?,
            deadline_unix_ms: bounded(deadline_unix_ms)?,
            operation_id,
        })
    }

    pub fn binding(&self) -> &InvocationBinding {
        &self.binding
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    /// The exact bytes to publish, and the address they hash to.
    ///
    /// # Errors
    ///
    /// Returns [`RecordError::RecordTooLarge`] above [`MAX_RECORD_CANONICAL_BYTES`] of CBOR,
    /// and [`RecordError::InvalidEncoding`] on a serialization failure.
    pub fn stored_bytes(&self) -> Result<(Vec<u8>, String), RecordError> {
        encode(MANIFEST_DOMAIN, &WireManifest::from(self))
    }
}

/// The terminal record of one model invocation.
///
/// Usage is copied from what the provider reported and is never derived from the completion:
/// the completion is candidate text, and candidate text cannot be evidence about spend.
/// `reported_use` absent and reported use of zero are different facts and stay distinct in
/// these bytes — a provider that reports zeros has still billed whatever it billed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvocationTrace {
    binding: InvocationBinding,
    manifest_digest: Digest,
    outcome: TerminalOutcome,
    provider_request_id: Option<String>,
    reported_use: Option<ReportedUse>,
    output: Option<BoundedText>,
    diagnostic: Option<BoundedText>,
}

impl InvocationTrace {
    /// # Errors
    ///
    /// Returns [`RecordError`] for an empty or oversized provider request id.
    pub fn new(
        binding: InvocationBinding,
        manifest_digest: Digest,
        outcome: TerminalOutcome,
        provider_request_id: Option<String>,
        reported_use: Option<ReportedUse>,
        output: Option<BoundedText>,
        diagnostic: Option<BoundedText>,
    ) -> Result<Self, RecordError> {
        if let Some(id) = &provider_request_id {
            identifier(id)?;
        }
        Ok(Self {
            binding,
            manifest_digest,
            outcome,
            provider_request_id,
            reported_use,
            output,
            diagnostic,
        })
    }

    pub fn binding(&self) -> &InvocationBinding {
        &self.binding
    }

    /// The manifest this trace terminates, so a reader needs no external index to pair them.
    pub fn manifest_digest(&self) -> &Digest {
        &self.manifest_digest
    }

    pub fn outcome(&self) -> TerminalOutcome {
        self.outcome
    }

    pub fn reported_use(&self) -> Option<ReportedUse> {
        self.reported_use
    }

    pub fn output(&self) -> Option<&BoundedText> {
        self.output.as_ref()
    }

    /// The exact bytes to publish, and the address they hash to.
    ///
    /// # Errors
    ///
    /// Returns [`RecordError::RecordTooLarge`] above [`MAX_RECORD_CANONICAL_BYTES`] of CBOR,
    /// and [`RecordError::InvalidEncoding`] on a serialization failure.
    pub fn stored_bytes(&self) -> Result<(Vec<u8>, String), RecordError> {
        encode(TRACE_DOMAIN, &WireTrace::from(self))
    }
}

fn encode<T: Serialize>(domain: &[u8], wire: &T) -> Result<(Vec<u8>, String), RecordError> {
    let mut cbor = Vec::new();
    into_writer(wire, &mut cbor).map_err(|_| RecordError::InvalidEncoding)?;
    if cbor.len() > MAX_RECORD_CANONICAL_BYTES {
        return Err(RecordError::RecordTooLarge);
    }
    let mut stored = Vec::with_capacity(domain.len() + cbor.len());
    stored.extend_from_slice(domain);
    stored.extend_from_slice(&cbor);
    let digest = format!("{:x}", Sha256::digest(&stored));
    Ok((stored, digest))
}

/// Rebuilds a manifest from stored bytes and proves they address `expected_digest`.
///
/// # Errors
///
/// Returns [`RecordError::InvalidEncoding`] for a missing prefix, malformed CBOR, trailing
/// bytes, an unrepresentable field, or bytes that do not re-encode identically, and
/// [`RecordError::DigestMismatch`] when the bytes address a different record.
pub fn decode_manifest(
    stored_bytes: &[u8],
    expected_digest: &str,
) -> Result<InvocationManifest, RecordError> {
    let wire: WireManifest = decode(MANIFEST_DOMAIN, stored_bytes)?;
    let manifest = wire.into_domain()?;
    verify(
        MANIFEST_DOMAIN,
        &WireManifest::from(&manifest),
        stored_bytes,
        expected_digest,
    )?;
    Ok(manifest)
}

/// Rebuilds a trace from stored bytes and proves they address `expected_digest`.
///
/// # Errors
///
/// Returns the same categories as [`decode_manifest`].
pub fn decode_trace(
    stored_bytes: &[u8],
    expected_digest: &str,
) -> Result<InvocationTrace, RecordError> {
    let wire: WireTrace = decode(TRACE_DOMAIN, stored_bytes)?;
    let trace = wire.into_domain()?;
    verify(
        TRACE_DOMAIN,
        &WireTrace::from(&trace),
        stored_bytes,
        expected_digest,
    )?;
    Ok(trace)
}

fn decode<T: for<'de> Deserialize<'de>>(
    domain: &[u8],
    stored_bytes: &[u8],
) -> Result<T, RecordError> {
    if stored_bytes.len() > domain.len() + MAX_RECORD_CANONICAL_BYTES {
        return Err(RecordError::RecordTooLarge);
    }
    let cbor = stored_bytes
        .strip_prefix(domain)
        .ok_or(RecordError::InvalidEncoding)?;
    let mut reader = Cursor::new(cbor);
    let wire: T = from_reader_with_recursion_limit(&mut reader, CBOR_RECURSION_LIMIT)
        .map_err(|_| RecordError::InvalidEncoding)?;
    if reader.position() != cbor.len() as u64 {
        return Err(RecordError::InvalidEncoding);
    }
    Ok(wire)
}

/// Re-encodes from the rebuilt value so no second byte string addresses one record.
fn verify<T: Serialize>(
    domain: &[u8],
    wire: &T,
    stored_bytes: &[u8],
    expected_digest: &str,
) -> Result<(), RecordError> {
    let (re_encoded, digest) = encode(domain, wire)?;
    if re_encoded != stored_bytes {
        return Err(RecordError::InvalidEncoding);
    }
    if digest != expected_digest {
        return Err(RecordError::DigestMismatch);
    }
    Ok(())
}

/// Canonical form of one binding, in declaration order.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireBinding {
    scope_id: String,
    plan_digest: String,
    work_id: String,
    work_revision: u64,
    claim_fence: u64,
    grant_digest: String,
    attempt: u64,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireManifest {
    binding: WireBinding,
    provider: String,
    model_id: String,
    configuration_digest: String,
    request_digest: String,
    max_output_tokens: u64,
    deadline_unix_ms: u64,
    operation_id: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireReportedUse {
    input_tokens: u32,
    output_tokens: u32,
    total_tokens: u32,
    /// Absent and zero are different facts here too: a provider that reports no cache read has
    /// said something a provider that omits the field has not.
    cache_read_input_tokens: Option<u32>,
    cache_write_input_tokens: Option<u32>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireBoundedText {
    retained: String,
    full_bytes: u64,
    full_digest: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireTrace {
    binding: WireBinding,
    manifest_digest: String,
    outcome: String,
    provider_request_id: Option<String>,
    reported_use: Option<WireReportedUse>,
    output: Option<WireBoundedText>,
    diagnostic: Option<WireBoundedText>,
}

impl From<&InvocationBinding> for WireBinding {
    fn from(binding: &InvocationBinding) -> Self {
        Self {
            scope_id: binding.scope_id.as_str().to_owned(),
            plan_digest: binding.plan_digest.as_str().to_owned(),
            work_id: binding.work_id.as_str().to_owned(),
            work_revision: binding.work_revision.get(),
            claim_fence: binding.claim_fence.get(),
            grant_digest: binding.grant_digest.as_str().to_owned(),
            attempt: binding.attempt.get(),
        }
    }
}

impl WireBinding {
    fn into_domain(self) -> Result<InvocationBinding, RecordError> {
        let digest = |value: String| Digest::new(value).map_err(|_| RecordError::InvalidEncoding);
        InvocationBinding::new(
            ScopeId::new(self.scope_id).map_err(|_| RecordError::InvalidEncoding)?,
            digest(self.plan_digest)?,
            WorkId::new(self.work_id).map_err(|_| RecordError::InvalidEncoding)?,
            self.work_revision,
            self.claim_fence,
            digest(self.grant_digest)?,
            self.attempt,
        )
    }
}

impl From<&InvocationManifest> for WireManifest {
    fn from(manifest: &InvocationManifest) -> Self {
        Self {
            binding: WireBinding::from(&manifest.binding),
            provider: manifest.provider.as_str().to_owned(),
            model_id: manifest.model_id.clone(),
            configuration_digest: manifest.configuration_digest.as_str().to_owned(),
            request_digest: manifest.request_digest.as_str().to_owned(),
            max_output_tokens: manifest.max_output_tokens.get(),
            deadline_unix_ms: manifest.deadline_unix_ms.get(),
            operation_id: manifest.operation_id.clone(),
        }
    }
}

impl WireManifest {
    fn into_domain(self) -> Result<InvocationManifest, RecordError> {
        let digest = |value: String| Digest::new(value).map_err(|_| RecordError::InvalidEncoding);
        let provider = match self.provider.as_str() {
            "bedrock" => ModelProvider::Bedrock,
            _ => return Err(RecordError::InvalidEncoding),
        };
        InvocationManifest::from_parts(
            self.binding.into_domain()?,
            provider,
            self.model_id,
            digest(self.configuration_digest)?,
            digest(self.request_digest)?,
            self.max_output_tokens,
            self.deadline_unix_ms,
            self.operation_id,
        )
    }
}

impl From<&BoundedText> for WireBoundedText {
    fn from(text: &BoundedText) -> Self {
        Self {
            retained: text.retained.clone(),
            full_bytes: text.full_bytes,
            full_digest: text.full_digest.clone(),
        }
    }
}

impl From<&InvocationTrace> for WireTrace {
    fn from(trace: &InvocationTrace) -> Self {
        Self {
            binding: WireBinding::from(&trace.binding),
            manifest_digest: trace.manifest_digest.as_str().to_owned(),
            outcome: trace.outcome.as_str().to_owned(),
            provider_request_id: trace.provider_request_id.clone(),
            reported_use: trace.reported_use.map(|use_| WireReportedUse {
                input_tokens: use_.input_tokens(),
                output_tokens: use_.output_tokens(),
                total_tokens: use_.total_tokens(),
                cache_read_input_tokens: use_.cache_read_input_tokens(),
                cache_write_input_tokens: use_.cache_write_input_tokens(),
            }),
            output: trace.output.as_ref().map(WireBoundedText::from),
            diagnostic: trace.diagnostic.as_ref().map(WireBoundedText::from),
        }
    }
}

impl WireTrace {
    fn into_domain(self) -> Result<InvocationTrace, RecordError> {
        let text = |wire: WireBoundedText| BoundedText {
            retained: wire.retained,
            full_bytes: wire.full_bytes,
            full_digest: wire.full_digest,
        };
        InvocationTrace::new(
            self.binding.into_domain()?,
            Digest::new(self.manifest_digest).map_err(|_| RecordError::InvalidEncoding)?,
            TerminalOutcome::parse(&self.outcome).ok_or(RecordError::InvalidEncoding)?,
            self.provider_request_id,
            self.reported_use.map(|wire| {
                ReportedUse::from_reported(
                    wire.input_tokens,
                    wire.output_tokens,
                    wire.total_tokens,
                    wire.cache_read_input_tokens,
                    wire.cache_write_input_tokens,
                )
            }),
            self.output.map(text),
            self.diagnostic.map(text),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(seed: u8) -> Digest {
        Digest::new(format!("{seed:02x}").repeat(32)).unwrap()
    }

    fn binding() -> InvocationBinding {
        InvocationBinding::new(
            ScopeId::new("0".repeat(64)).unwrap(),
            digest(0x11),
            WorkId::new("work-a".into()).unwrap(),
            3,
            2,
            digest(0x22),
            7,
        )
        .unwrap()
    }

    fn profile() -> ModelProfile {
        ModelProfile::new(
            ModelProvider::Bedrock,
            "anthropic.claude-fixture-v1:0".into(),
            "profile-a".into(),
            NonZeroU64::new(4096).unwrap().try_into().unwrap(),
            Some(250),
            None,
            Vec::new(),
        )
        .unwrap()
    }

    fn manifest() -> InvocationManifest {
        InvocationManifest::new(
            binding(),
            &profile(),
            digest(0x44),
            512,
            1_700_000_060_000,
            "invoke-op-1".into(),
        )
        .unwrap()
    }

    fn trace(reported_use: Option<ReportedUse>, output: Option<BoundedText>) -> InvocationTrace {
        InvocationTrace::new(
            binding(),
            digest(0x55),
            TerminalOutcome::Success,
            Some("req-fixture-1".into()),
            reported_use,
            output,
            None,
        )
        .unwrap()
    }

    #[test]
    fn a_manifest_round_trips_and_addresses_its_own_bytes() {
        let manifest = manifest();
        let (stored, address) = manifest.stored_bytes().unwrap();

        assert!(stored.starts_with(MANIFEST_DOMAIN));
        // The address is the plain digest of the stored bytes, so publication verifies it
        // with the same integrity check it applies to any blob.
        assert_eq!(address, format!("{:x}", Sha256::digest(&stored)));
        assert_eq!(decode_manifest(&stored, &address).unwrap(), manifest);

        // Bytes that address something else are refused even though they are well formed.
        assert_eq!(
            decode_manifest(&stored, digest(0x99).as_str()),
            Err(RecordError::DigestMismatch)
        );
        // Without the domain prefix the same CBOR is not a manifest.
        assert_eq!(
            decode_manifest(&stored[MANIFEST_DOMAIN.len()..], &address),
            Err(RecordError::InvalidEncoding)
        );
        // Trailing bytes change the address and are not canonical.
        let mut padded = stored.clone();
        padded.push(0);
        assert_eq!(
            decode_manifest(&padded, &address),
            Err(RecordError::InvalidEncoding)
        );
        // A manifest's bytes are not a trace's, even at the same address.
        assert_eq!(
            decode_trace(&stored, &address),
            Err(RecordError::InvalidEncoding)
        );
    }

    #[test]
    fn a_trace_round_trips_and_keeps_absent_use_distinct_from_zero() {
        let counted = trace(
            Some(ReportedUse::from_reported(11, 7, 18, Some(4), None)),
            Some(BoundedText::new("rayleigh scattering")),
        );
        let (stored, address) = counted.stored_bytes().unwrap();
        assert_eq!(decode_trace(&stored, &address).unwrap(), counted);

        // Absent reported use and reported use of zero are different facts, and the bytes keep
        // them apart: a provider that reports zeros has still billed whatever it billed, so
        // collapsing one into the other would understate spend in durable history.
        let zeroed = trace(
            Some(ReportedUse::from_reported(0, 0, 0, Some(0), Some(0))),
            None,
        );
        let absent = trace(None, None);
        let (zeroed_bytes, zeroed_address) = zeroed.stored_bytes().unwrap();
        let (absent_bytes, absent_address) = absent.stored_bytes().unwrap();
        assert_ne!(zeroed_bytes, absent_bytes);
        assert_ne!(zeroed_address, absent_address);
        assert_eq!(
            decode_trace(&zeroed_bytes, &zeroed_address)
                .unwrap()
                .reported_use()
                .map(|use_| use_.total_tokens()),
            Some(0)
        );
        assert_eq!(
            decode_trace(&absent_bytes, &absent_address)
                .unwrap()
                .reported_use(),
            None
        );
    }

    /// Every terminal category round-trips, including the one the transport has no equivalent
    /// for: a cancellation is decided locally, so no provider outcome can produce it.
    #[test]
    fn every_terminal_outcome_round_trips() {
        for outcome in [
            TerminalOutcome::Success,
            TerminalOutcome::Refused,
            TerminalOutcome::TimedOut,
            TerminalOutcome::Canceled,
            TerminalOutcome::DefiniteFailure,
            TerminalOutcome::Unknown,
        ] {
            let trace =
                InvocationTrace::new(binding(), digest(0x55), outcome, None, None, None, None)
                    .unwrap();
            let (stored, address) = trace.stored_bytes().unwrap();
            assert_eq!(
                decode_trace(&stored, &address).unwrap().outcome(),
                outcome,
                "{}",
                outcome.as_str()
            );
        }
        assert_eq!(TerminalOutcome::parse("cancelled"), None);
        assert_eq!(TerminalOutcome::parse(""), None);
    }

    /// Output is bounded by retention, not by refusal: the record keeps a prefix and addresses
    /// the whole, so a caller can prove what was produced without durable history holding it.
    #[test]
    fn output_is_retained_up_to_the_bound_and_addressed_in_full() {
        let short = BoundedText::new("brief");
        assert_eq!(short.retained(), "brief");
        assert_eq!(short.full_bytes(), 5);
        assert!(!short.truncated());

        let long = "x".repeat(MAX_RETAINED_TEXT_BYTES * 2);
        let bounded = BoundedText::new(&long);
        assert_eq!(bounded.retained().len(), MAX_RETAINED_TEXT_BYTES);
        assert_eq!(bounded.full_bytes(), long.len() as u64);
        assert!(bounded.truncated());
        // The address covers the whole text, not the prefix.
        assert_eq!(
            bounded.full_digest(),
            format!("{:x}", Sha256::digest(long.as_bytes()))
        );

        // A multi-byte character is dropped whole rather than split, so the retained prefix is
        // always valid text.
        let multibyte = format!("{}é", "y".repeat(MAX_RETAINED_TEXT_BYTES - 1));
        let cut = BoundedText::new(&multibyte);
        assert_eq!(cut.retained().len(), MAX_RETAINED_TEXT_BYTES - 1);
        assert!(cut.truncated());
    }

    #[test]
    fn every_record_rejection_fails_before_any_publication() {
        let long = "m".repeat(MAX_IDENTIFIER_BYTES + 1);
        let max = MAX_STORED_INTEGER;

        for (revision, fence, attempt) in [
            (0, 1, 1),
            (1, 0, 1),
            (1, 1, 0),
            (max + 1, 1, 1),
            (1, max + 1, 1),
            (1, 1, max + 1),
        ] {
            assert_eq!(
                InvocationBinding::new(
                    ScopeId::new("0".repeat(64)).unwrap(),
                    digest(0x11),
                    WorkId::new("work-a".into()).unwrap(),
                    revision,
                    fence,
                    digest(0x22),
                    attempt,
                ),
                Err(RecordError::OutOfRange),
                "{revision} {fence} {attempt}"
            );
        }

        let build = |operation_id: String, cap: u64, deadline: u64| {
            InvocationManifest::new(
                binding(),
                &profile(),
                digest(0x44),
                cap,
                deadline,
                operation_id,
            )
        };
        assert_eq!(
            build(String::new(), 1, 1),
            Err(RecordError::EmptyIdentifier)
        );
        assert_eq!(
            build(long.clone(), 1, 1),
            Err(RecordError::IdentifierTooLong)
        );
        assert_eq!(build("op".into(), 0, 1), Err(RecordError::OutOfRange));
        assert_eq!(build("op".into(), 1, max + 1), Err(RecordError::OutOfRange));
        // The identifier bound holds at exactly the limit.
        assert!(build("o".repeat(MAX_IDENTIFIER_BYTES), max, max).is_ok());

        assert_eq!(
            InvocationTrace::new(
                binding(),
                digest(0x55),
                TerminalOutcome::Success,
                Some(String::new()),
                None,
                None,
                None,
            ),
            Err(RecordError::EmptyIdentifier)
        );
        assert_eq!(
            InvocationTrace::new(
                binding(),
                digest(0x55),
                TerminalOutcome::Success,
                Some(long),
                None,
                None,
                None,
            ),
            Err(RecordError::IdentifierTooLong)
        );
    }

    /// A record above the canonical cap is refused rather than published, so nothing
    /// unbounded reaches an artifact key.
    #[test]
    fn a_record_past_the_canonical_cap_is_refused() {
        let oversized = InvocationTrace::new(
            binding(),
            digest(0x55),
            TerminalOutcome::Unknown,
            None,
            None,
            // `BoundedText` bounds what a caller retains, so reaching the record cap takes a
            // value built past it; the cap is the record's own last line of defence.
            Some(BoundedText {
                retained: "z".repeat(MAX_RECORD_CANONICAL_BYTES + 1),
                full_bytes: (MAX_RECORD_CANONICAL_BYTES + 1) as u64,
                full_digest: digest(0x66).as_str().to_owned(),
            }),
            None,
        )
        .unwrap();

        assert_eq!(oversized.stored_bytes(), Err(RecordError::RecordTooLarge));
    }
}
