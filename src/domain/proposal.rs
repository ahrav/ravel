//! Typed root-plan proposals and the pure gate that runs before admission.
//!
//! A proposal binds its exact root scope, objective, parent plan, and typed bases in its own
//! bytes, and construction normalizes those bases so equivalent citations derive one address.
//!
//! The stored plan object is `"ravel.plan.proposal\0" || CBOR`, and `plan_digest` is the plain
//! SHA-256 of exactly those bytes. Domain separation therefore needs no special verifier: the
//! object-store integrity check recomputes the same digest it would for any blob. The `ciborium`
//! lockfile pin is byte-affecting for this address, as the `zstd-sys` pin is for event bytes.
//!
//! This module decides proposal shape, not admission policy: it accepts any parent equal to the
//! scope's active plan, including a successor. Only durable state knows whether a superseded plan
//! can be drained, so refusing a successor is the durable layer's rule.
//!
//! Two shapes are admissible by design rather than by omission. An empty basis list is allowed,
//! because fixed initial work is proposed from the objective alone. Citing the prior revision is
//! optional, and because bases are part of the address, a proposal that cites it and one that does
//! not are two distinct plans rather than one plan proposed twice.
//!
//! The root-only MVP has exactly two basis kinds; child certificates and delegation bases are
//! post-signal work and are not representable. `root_genesis` is the only supported planning-input
//! payload, because it is the durable objective and configuration record and no observation payload
//! type exists yet. Every other payload type fails closed, the way `payload_type_registered`
//! refuses an unregistered event payload — but against that one constant, not that predicate, whose
//! allow-list also admits the test-only successor payload.

use std::{collections::BTreeSet, error::Error, fmt, io::Cursor, num::NonZeroU64};

use ciborium::{de::from_reader_with_recursion_limit, ser::into_writer};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{
    domain::work::WorkId,
    scope::{Digest, ROOT_GENESIS_PAYLOAD_TYPE, ScopeEventRef, ScopeId, ScopeIdentity},
};

const PLAN_PROPOSAL_DOMAIN: &[u8] = b"ravel.plan.proposal\0";
const CBOR_RECURSION_LIMIT: usize = 16;

/// Highest value the projection's `INTEGER` columns round-trip.
pub const MAX_STORED_INTEGER: u64 = 9_999_999_999_999_999;
/// Cap on the CBOR body of one plan object.
pub const MAX_PLAN_CANONICAL_BYTES: usize = 1024 * 1024;
/// Cap on one stored plan object: the domain prefix plus the CBOR body.
pub const MAX_PLAN_STORED_BYTES: usize = PLAN_PROPOSAL_DOMAIN.len() + MAX_PLAN_CANONICAL_BYTES;
/// Revision every work row of a first admitted plan carries.
pub const INITIAL_WORK_REVISION: u64 = 1;

/// Static category for a rejected proposal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProposalError {
    ScopeMismatch,
    ObjectiveMismatch,
    MissingBasis,
    StaleBasis,
    CrossScopeBasis,
    UnsupportedPlanningInput,
    CyclicBasis,
    DuplicateWork,
    UnknownDependency,
    CyclicDependency,
    BoundOutOfRange,
    BudgetOutOfRange,
    PlanTooLarge,
    PlanDigestMismatch,
    InvalidEncoding,
}

impl fmt::Display for ProposalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ScopeMismatch => "proposal names another scope",
            Self::ObjectiveMismatch => "proposal names another objective",
            Self::MissingBasis => "proposal basis does not exist",
            Self::StaleBasis => "proposal basis is stale",
            Self::CrossScopeBasis => "proposal basis belongs to another scope",
            Self::UnsupportedPlanningInput => "proposal basis is not a planning input",
            Self::CyclicBasis => "proposal basis is cyclic",
            Self::DuplicateWork => "proposal declares one work identity twice",
            Self::UnknownDependency => "proposal dependency names undeclared work",
            Self::CyclicDependency => "proposal dependency graph is cyclic",
            Self::BoundOutOfRange => "proposal target bound is outside the durable range",
            Self::BudgetOutOfRange => "proposal budget is outside the durable range",
            Self::PlanTooLarge => "plan object exceeds the canonical size cap",
            Self::PlanDigestMismatch => "plan object does not match its expected address",
            Self::InvalidEncoding => "proposal cannot be canonically encoded",
        })
    }
}

impl Error for ProposalError {}

/// One typed reference to what informed a proposal.
///
/// A reference records provenance only. It never establishes the referenced claim: an old
/// observation may inform a new plan and still fail its own bindings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProposalBasis {
    /// An event in this proposal's own root-scope log, cited by exact sequence and digest.
    Observation { event: ScopeEventRef },
    /// The plan revision this proposal supersedes, cited by content address.
    PriorRevision { plan_digest: Digest },
}

/// Finite per-work-revision execution limits.
///
/// `deadline_unix_ms` is absolute on the clock base claim leases use, so the same rows and the same
/// clock reading derive the same ready set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TargetBounds {
    max_attempts: NonZeroU64,
    deadline_unix_ms: NonZeroU64,
}

impl TargetBounds {
    /// # Errors
    ///
    /// Returns [`ProposalError::BoundOutOfRange`] outside `1..=MAX_STORED_INTEGER`.
    pub fn new(max_attempts: u64, deadline_unix_ms: u64) -> Result<Self, ProposalError> {
        let bounded = |value: u64| {
            NonZeroU64::new(value)
                .filter(|value| value.get() <= MAX_STORED_INTEGER)
                .ok_or(ProposalError::BoundOutOfRange)
        };
        Ok(Self {
            max_attempts: bounded(max_attempts)?,
            deadline_unix_ms: bounded(deadline_unix_ms)?,
        })
    }

    pub fn max_attempts(&self) -> NonZeroU64 {
        self.max_attempts
    }

    pub fn deadline_unix_ms(&self) -> NonZeroU64 {
        self.deadline_unix_ms
    }
}

/// One claimable unit a proposal declares.
///
/// Dependencies name work this same proposal declares. Admission assigns
/// [`INITIAL_WORK_REVISION`]; the revision is not proposed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkSpec {
    work_id: WorkId,
    dependencies: Vec<WorkId>,
    bounds: TargetBounds,
}

impl WorkSpec {
    /// Sorts and dedups `dependencies` into the order this record is addressed over.
    pub fn new(work_id: WorkId, mut dependencies: Vec<WorkId>, bounds: TargetBounds) -> Self {
        dependencies.sort_unstable_by(|left, right| left.as_str().cmp(right.as_str()));
        dependencies.dedup();
        Self {
            work_id,
            dependencies,
            bounds,
        }
    }

    pub fn work_id(&self) -> &WorkId {
        &self.work_id
    }

    pub fn dependencies(&self) -> &[WorkId] {
        &self.dependencies
    }

    pub fn bounds(&self) -> TargetBounds {
        self.bounds
    }
}

/// What durable state records about one cited observation.
///
/// Construction is infallible: `scope_id` and `event` are already validated domain values, and a
/// `payload_type` other than `root_genesis` fails closed in [`validate_proposal`] rather than here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservationFact {
    scope_id: ScopeId,
    event: ScopeEventRef,
    payload_type: String,
}

impl ObservationFact {
    pub fn new(scope_id: ScopeId, event: ScopeEventRef, payload_type: String) -> Self {
        Self {
            scope_id,
            event,
            payload_type,
        }
    }
}

/// The durable facts one validation call is decided against.
///
/// The caller resolves the head facts and observations from the scope head and projection, and
/// `objective_digest` from the campaign's root-genesis `config_digest` — no projection table and no
/// head field carries the objective. Resolving outside keeps this module free of I/O and makes
/// every basis rejection reachable from a unit test.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProposalFacts<'a> {
    scope: &'a ScopeIdentity,
    objective_digest: &'a Digest,
    active_plan_digest: Option<&'a Digest>,
    tail_sequence: u64,
    observations: &'a [ObservationFact],
}

impl<'a> ProposalFacts<'a> {
    /// `tail_sequence` is the highest sequence the projection has applied; a citation above it
    /// names an event this scope has not seen.
    ///
    /// `observations` must hold at most one fact per sequence, and the first match at a sequence
    /// decides the verdict. `applied_scope_events` is keyed on `(scope_id, sequence)`, so a query
    /// scoped to one scope already satisfies this; a caller that merges more than one scope's rows
    /// must deduplicate first, or slice order silently chooses which rejection fires.
    pub fn new(
        scope: &'a ScopeIdentity,
        objective_digest: &'a Digest,
        active_plan_digest: Option<&'a Digest>,
        tail_sequence: u64,
        observations: &'a [ObservationFact],
    ) -> Self {
        Self {
            scope,
            objective_digest,
            active_plan_digest,
            tail_sequence,
            observations,
        }
    }
}

/// An immutable proposal with its basis list already in canonical order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlanProposal {
    scope_id: ScopeId,
    objective_digest: Digest,
    parent_plan_digest: Option<Digest>,
    bases: Vec<ProposalBasis>,
    work_specs: Vec<WorkSpec>,
    reserved_budget_units: u64,
}

impl PlanProposal {
    /// Normalizes `bases` into the one order this record is content-addressed over:
    /// observations before prior revisions, observations by `(sequence, digest)`, prior revisions
    /// by digest, duplicates removed.
    pub fn new(
        scope_id: ScopeId,
        objective_digest: Digest,
        parent_plan_digest: Option<Digest>,
        mut bases: Vec<ProposalBasis>,
        mut work_specs: Vec<WorkSpec>,
        reserved_budget_units: u64,
    ) -> Self {
        bases.sort_unstable_by(|left, right| sort_key(left).cmp(&sort_key(right)));
        // `dedup` drops only adjacent equals. The sort key carries the variant tag and every
        // field of that variant, so equal keys are equal values and sorting makes them adjacent.
        bases.dedup();
        // Duplicate work identities survive normalization; `validate_work_graph` rejects them.
        work_specs
            .sort_unstable_by(|left, right| left.work_id.as_str().cmp(right.work_id.as_str()));
        work_specs.dedup();
        Self {
            scope_id,
            objective_digest,
            parent_plan_digest,
            bases,
            work_specs,
            reserved_budget_units,
        }
    }

    pub fn scope_id(&self) -> &ScopeId {
        &self.scope_id
    }

    pub fn objective_digest(&self) -> &Digest {
        &self.objective_digest
    }

    pub fn parent_plan_digest(&self) -> Option<&Digest> {
        self.parent_plan_digest.as_ref()
    }

    pub fn bases(&self) -> &[ProposalBasis] {
        &self.bases
    }

    pub fn work_specs(&self) -> &[WorkSpec] {
        &self.work_specs
    }

    pub fn reserved_budget_units(&self) -> u64 {
        self.reserved_budget_units
    }

    /// # Errors
    ///
    /// Returns [`ProposalError::PlanTooLarge`] above [`MAX_PLAN_CANONICAL_BYTES`] of CBOR.
    ///
    /// Returns [`ProposalError::InvalidEncoding`] on a serialization failure, which no field type
    /// here can produce.
    fn encode(&self) -> Result<(Vec<u8>, Digest), ProposalError> {
        let mut cbor = Vec::new();
        into_writer(&WirePlanProposal::from(self), &mut cbor)
            .map_err(|_| ProposalError::InvalidEncoding)?;
        if cbor.len() > MAX_PLAN_CANONICAL_BYTES {
            return Err(ProposalError::PlanTooLarge);
        }
        let mut stored_bytes = Vec::with_capacity(PLAN_PROPOSAL_DOMAIN.len() + cbor.len());
        stored_bytes.extend_from_slice(PLAN_PROPOSAL_DOMAIN);
        stored_bytes.extend_from_slice(&cbor);
        let plan_digest = Digest::new(format!("{:x}", Sha256::digest(&stored_bytes)))
            .map_err(|_| ProposalError::InvalidEncoding)?;
        Ok((stored_bytes, plan_digest))
    }
}

/// A proposal whose every binding held, paired with the bytes that address it.
///
/// The scope is inside the opaque bytes and there is no decode path, so it is carried out
/// separately: a caller keying these bytes by scope reads it from here rather than from a
/// `PlanProposal` it has to keep alongside and could confuse for another scope's.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmissibleProposal {
    scope_id: ScopeId,
    stored_bytes: Vec<u8>,
    plan_digest: Digest,
}

impl AdmissibleProposal {
    pub fn scope_id(&self) -> &ScopeId {
        &self.scope_id
    }

    /// The exact object bytes to publish under `plan_key`, domain prefix included.
    pub fn stored_bytes(&self) -> &[u8] {
        &self.stored_bytes
    }

    pub fn plan_digest(&self) -> &Digest {
        &self.plan_digest
    }
}

/// Decides one proposal against the facts the caller resolved, without touching durable state.
///
/// Bases are decided in canonical order, observations before prior revisions, so a proposal
/// carrying two faults reports the first one in that order and reports it identically for every
/// equivalent input.
///
/// # Errors
///
/// Returns the [`ProposalError`] category of the first binding that fails: header bindings before
/// bases, and bases in canonical order.
pub fn validate_proposal(
    proposal: &PlanProposal,
    facts: &ProposalFacts<'_>,
) -> Result<AdmissibleProposal, ProposalError> {
    let scope_id = facts.scope.scope_id();
    if &proposal.scope_id != scope_id {
        return Err(ProposalError::ScopeMismatch);
    }
    if &proposal.objective_digest != facts.objective_digest {
        return Err(ProposalError::ObjectiveMismatch);
    }
    // A proposal supersedes exactly the revision the scope currently holds, so absent and present
    // parents must agree with the active plan on both sides.
    if proposal.parent_plan_digest.as_ref() != facts.active_plan_digest {
        return Err(ProposalError::StaleBasis);
    }
    for basis in &proposal.bases {
        match basis {
            ProposalBasis::PriorRevision { plan_digest } => {
                if Some(plan_digest) != facts.active_plan_digest {
                    return Err(ProposalError::StaleBasis);
                }
            }
            ProposalBasis::Observation { event } => {
                if event.sequence() > facts.tail_sequence {
                    return Err(ProposalError::MissingBasis);
                }
                let fact = facts
                    .observations
                    .iter()
                    .find(|fact| fact.event.sequence() == event.sequence())
                    .ok_or(ProposalError::MissingBasis)?;
                if &fact.scope_id != scope_id {
                    return Err(ProposalError::CrossScopeBasis);
                }
                // Facts resolve by sequence, so a digest that disagrees at a sequence this scope
                // has applied is stale evidence rather than a missing one.
                if fact.event.digest() != event.digest() {
                    return Err(ProposalError::StaleBasis);
                }
                if fact.payload_type != ROOT_GENESIS_PAYLOAD_TYPE {
                    return Err(ProposalError::UnsupportedPlanningInput);
                }
            }
        }
    }
    validate_work_graph(&proposal.work_specs)?;
    if proposal.reserved_budget_units > MAX_STORED_INTEGER {
        return Err(ProposalError::BudgetOutOfRange);
    }
    let (stored_bytes, plan_digest) = proposal.encode()?;
    // Unreachable by construction: reaching it requires a SHA-256 fixed point. Covered only
    // through `is_cyclic` directly.
    if is_cyclic(&plan_digest, proposal) {
        return Err(ProposalError::CyclicBasis);
    }
    Ok(AdmissibleProposal {
        scope_id: proposal.scope_id.clone(),
        stored_bytes,
        plan_digest,
    })
}

/// Rebuilds a proposal from stored plan bytes and proves they address `expected_digest`.
///
/// A rebuilt projection holds no work rows, so the plan object is the only source of the work,
/// dependencies, and bounds replay reproduces.
///
/// # Errors
///
/// Returns [`ProposalError::PlanTooLarge`] above the prefix plus [`MAX_PLAN_CANONICAL_BYTES`].
///
/// Returns [`ProposalError::InvalidEncoding`] for a missing prefix, malformed CBOR, trailing bytes,
/// an unrepresentable field, or bytes that do not re-encode identically.
///
/// Returns [`ProposalError::PlanDigestMismatch`] when the bytes address a different plan.
pub fn decode_plan(
    stored_bytes: &[u8],
    expected_digest: &Digest,
) -> Result<PlanProposal, ProposalError> {
    if stored_bytes.len() > MAX_PLAN_STORED_BYTES {
        return Err(ProposalError::PlanTooLarge);
    }
    let cbor = stored_bytes
        .strip_prefix(PLAN_PROPOSAL_DOMAIN)
        .ok_or(ProposalError::InvalidEncoding)?;
    let mut reader = Cursor::new(cbor);
    let wire: WirePlanProposal =
        from_reader_with_recursion_limit(&mut reader, CBOR_RECURSION_LIMIT)
            .map_err(|_| ProposalError::InvalidEncoding)?;
    if reader.position() != cbor.len() as u64 {
        return Err(ProposalError::InvalidEncoding);
    }
    let proposal = wire.into_domain()?;
    // Re-encoding from the normalized value rejects a permuted or duplicated list, so no second
    // byte string addresses the same plan.
    let (re_encoded, digest) = proposal.encode()?;
    if re_encoded != stored_bytes {
        return Err(ProposalError::InvalidEncoding);
    }
    if &digest != expected_digest {
        return Err(ProposalError::PlanDigestMismatch);
    }
    Ok(proposal)
}

/// Proves the declared work graph is closed, duplicate-free, and acyclic.
///
/// Closure is over this proposal alone, so an edge naming work outside it fails closed.
fn validate_work_graph(work_specs: &[WorkSpec]) -> Result<(), ProposalError> {
    let declared: BTreeSet<&str> = work_specs
        .iter()
        .map(|spec| spec.work_id.as_str())
        .collect();
    if declared.len() != work_specs.len() {
        return Err(ProposalError::DuplicateWork);
    }
    for spec in work_specs {
        for dependency in &spec.dependencies {
            if !declared.contains(dependency.as_str()) {
                return Err(ProposalError::UnknownDependency);
            }
        }
    }
    if has_cycle(work_specs) {
        return Err(ProposalError::CyclicDependency);
    }
    Ok(())
}

/// Iterative depth-first search over a set already proven closed; a self-edge is a cycle here.
fn has_cycle(work_specs: &[WorkSpec]) -> bool {
    #[derive(Clone, Copy, Eq, PartialEq)]
    enum Mark {
        Unseen,
        InProgress,
        Done,
    }

    let index: std::collections::BTreeMap<&str, usize> = work_specs
        .iter()
        .enumerate()
        .map(|(position, spec)| (spec.work_id.as_str(), position))
        .collect();
    let index = |work_id: &str| index.get(work_id).copied();
    let mut marks = vec![Mark::Unseen; work_specs.len()];
    // Each frame holds one node and how many of its edges are walked, so a deep chain cannot
    // overflow the stack.
    let mut stack: Vec<(usize, usize)> = Vec::new();
    for root in 0..work_specs.len() {
        if marks[root] != Mark::Unseen {
            continue;
        }
        marks[root] = Mark::InProgress;
        stack.push((root, 0));
        while let Some((node, edge)) = stack.pop() {
            match work_specs[node].dependencies.get(edge) {
                None => marks[node] = Mark::Done,
                Some(dependency) => {
                    stack.push((node, edge + 1));
                    let Some(next) = index(dependency.as_str()) else {
                        continue;
                    };
                    match marks[next] {
                        Mark::InProgress => return true,
                        Mark::Done => {}
                        Mark::Unseen => {
                            marks[next] = Mark::InProgress;
                            stack.push((next, 0));
                        }
                    }
                }
            }
        }
    }
    false
}

/// A proposal that cites its own content address as its parent or prior revision is its own
/// ancestor.
///
/// Content addressing makes that a SHA-256 fixed point rather than a value a caller can choose,
/// so no input reaches it today. It stays because the lineage rule has to be total: the day a
/// second plan record or a weaker address arrives, the check is already the one that refuses.
fn is_cyclic(plan_digest: &Digest, proposal: &PlanProposal) -> bool {
    proposal.parent_plan_digest.as_ref() == Some(plan_digest)
        || proposal.bases.iter().any(|basis| match basis {
            ProposalBasis::PriorRevision { plan_digest: prior } => prior == plan_digest,
            ProposalBasis::Observation { .. } => false,
        })
}

/// Total order over bases: the leading tag keeps observations ahead of prior revisions, then
/// observations order by sequence before digest.
fn sort_key(basis: &ProposalBasis) -> (u8, u64, &str) {
    match basis {
        ProposalBasis::Observation { event } => (0, event.sequence(), event.digest().as_str()),
        ProposalBasis::PriorRevision { plan_digest } => (1, 0, plan_digest.as_str()),
    }
}

/// Canonical form, in declaration order, of one plan object's CBOR body.
///
/// One owned shape serves both directions so encode and decode cannot disagree about the layout.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WirePlanProposal {
    scope_id: String,
    objective_digest: String,
    parent_plan_digest: Option<String>,
    bases: Vec<WireProposalBasis>,
    work_specs: Vec<WireWorkSpec>,
    reserved_budget_units: u64,
}

/// Externally tagged, unlike the internally tagged JSON records in `distributed::claims`: CBOR
/// writes the default one-entry map `{variant: {fields}}`, while an internal tag would fold the tag
/// into the field map and change these bytes.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
enum WireProposalBasis {
    Observation { sequence: u64, digest: String },
    PriorRevision { plan_digest: String },
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireWorkSpec {
    work_id: String,
    dependencies: Vec<String>,
    bounds: WireTargetBounds,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireTargetBounds {
    max_attempts: u64,
    deadline_unix_ms: u64,
}

impl From<&PlanProposal> for WirePlanProposal {
    fn from(proposal: &PlanProposal) -> Self {
        Self {
            scope_id: proposal.scope_id.as_str().to_owned(),
            objective_digest: proposal.objective_digest.as_str().to_owned(),
            parent_plan_digest: proposal
                .parent_plan_digest
                .as_ref()
                .map(|digest| digest.as_str().to_owned()),
            bases: proposal
                .bases
                .iter()
                .map(|basis| match basis {
                    ProposalBasis::Observation { event } => WireProposalBasis::Observation {
                        sequence: event.sequence(),
                        digest: event.digest().as_str().to_owned(),
                    },
                    ProposalBasis::PriorRevision { plan_digest } => {
                        WireProposalBasis::PriorRevision {
                            plan_digest: plan_digest.as_str().to_owned(),
                        }
                    }
                })
                .collect(),
            work_specs: proposal
                .work_specs
                .iter()
                .map(|spec| WireWorkSpec {
                    work_id: spec.work_id.as_str().to_owned(),
                    dependencies: spec
                        .dependencies
                        .iter()
                        .map(|dependency| dependency.as_str().to_owned())
                        .collect(),
                    bounds: WireTargetBounds {
                        max_attempts: spec.bounds.max_attempts.get(),
                        deadline_unix_ms: spec.bounds.deadline_unix_ms.get(),
                    },
                })
                .collect(),
            reserved_budget_units: proposal.reserved_budget_units,
        }
    }
}

impl WirePlanProposal {
    fn into_domain(self) -> Result<PlanProposal, ProposalError> {
        let digest = |value: String| Digest::new(value).map_err(|_| ProposalError::InvalidEncoding);
        let work_id =
            |value: String| WorkId::new(value).map_err(|_| ProposalError::InvalidEncoding);
        let bases = self
            .bases
            .into_iter()
            .map(|basis| match basis {
                WireProposalBasis::Observation { sequence, digest } => {
                    let event = ScopeEventRef::new(
                        sequence,
                        Digest::new(digest).map_err(|_| ProposalError::InvalidEncoding)?,
                    )
                    .map_err(|_| ProposalError::InvalidEncoding)?;
                    Ok(ProposalBasis::Observation { event })
                }
                WireProposalBasis::PriorRevision { plan_digest } => {
                    Ok(ProposalBasis::PriorRevision {
                        plan_digest: Digest::new(plan_digest)
                            .map_err(|_| ProposalError::InvalidEncoding)?,
                    })
                }
            })
            .collect::<Result<Vec<_>, ProposalError>>()?;
        let work_specs = self
            .work_specs
            .into_iter()
            .map(|spec| {
                Ok(WorkSpec::new(
                    work_id(spec.work_id)?,
                    spec.dependencies
                        .into_iter()
                        .map(work_id)
                        .collect::<Result<Vec<_>, ProposalError>>()?,
                    TargetBounds::new(spec.bounds.max_attempts, spec.bounds.deadline_unix_ms)?,
                ))
            })
            .collect::<Result<Vec<_>, ProposalError>>()?;
        Ok(PlanProposal::new(
            ScopeId::new(self.scope_id).map_err(|_| ProposalError::InvalidEncoding)?,
            digest(self.objective_digest)?,
            self.parent_plan_digest.map(digest).transpose()?,
            bases,
            work_specs,
            self.reserved_budget_units,
        ))
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        distributed::identity::WorkspaceId,
        scope::{CampaignId, TEST_SUCCESSOR_PAYLOAD_TYPE},
    };

    use super::*;

    /// Pins the content address of the fixture proposal, which no relation between two
    /// implementation runs can pin: it is the only assertion that fails if the domain prefix is
    /// dropped, a wire field is renamed, or two wire fields swap declaration order.
    const GENESIS_PLAN_DIGEST: &str =
        "2d69e9913e2c0c30749f84648eb55313aaf643433e159a9bd6b0826db2994d90";

    fn digest(seed: u8) -> Digest {
        Digest::new(format!("{seed:02x}").repeat(32)).unwrap()
    }

    fn scope() -> ScopeIdentity {
        ScopeIdentity::root(
            WorkspaceId::new("workspace-a".into()).unwrap(),
            CampaignId::new("campaign-a".into()).unwrap(),
        )
        .unwrap()
    }

    fn other_scope_id() -> ScopeId {
        ScopeId::new("f".repeat(64)).unwrap()
    }

    fn event(sequence: u64, seed: u8) -> ScopeEventRef {
        ScopeEventRef::new(sequence, digest(seed)).unwrap()
    }

    fn fact(scope_id: ScopeId, sequence: u64, seed: u8, payload_type: &str) -> ObservationFact {
        ObservationFact::new(scope_id, event(sequence, seed), payload_type.to_owned())
    }

    fn genesis_fact() -> ObservationFact {
        fact(
            scope().scope_id().clone(),
            1,
            0xaa,
            ROOT_GENESIS_PAYLOAD_TYPE,
        )
    }

    /// A first root plan: no active plan, bases cited against the genesis event.
    fn genesis_proposal(bases: Vec<ProposalBasis>) -> PlanProposal {
        PlanProposal::new(
            scope().scope_id().clone(),
            digest(0x11),
            None,
            bases,
            Vec::new(),
            0,
        )
    }

    fn observation_basis(sequence: u64, seed: u8) -> ProposalBasis {
        ProposalBasis::Observation {
            event: event(sequence, seed),
        }
    }

    fn prior_basis(seed: u8) -> ProposalBasis {
        ProposalBasis::PriorRevision {
            plan_digest: digest(seed),
        }
    }

    #[test]
    fn genesis_proposal_binds_its_identities_and_addresses_its_own_bytes() {
        let scope = scope();
        let objective = digest(0x11);
        let proposal = genesis_proposal(vec![observation_basis(1, 0xaa)]);

        assert_eq!(proposal.scope_id(), scope.scope_id());
        assert_eq!(proposal.objective_digest(), &objective);
        assert_eq!(proposal.parent_plan_digest(), None);
        assert_eq!(proposal.bases(), [observation_basis(1, 0xaa)]);

        let facts = [genesis_fact()];
        let admissible = validate_proposal(
            &proposal,
            &ProposalFacts::new(&scope, &objective, None, 1, &facts),
        )
        .unwrap();
        assert_eq!(admissible.scope_id(), scope.scope_id());
        assert_eq!(admissible.plan_digest().as_str(), GENESIS_PLAN_DIGEST);
    }

    #[test]
    fn equivalent_basis_multisets_normalize_to_one_byte_string_and_digest() {
        let scope = scope();
        let objective = digest(0x11);
        let facts = [
            genesis_fact(),
            // Sequence 2 is forward-looking: durable state holds no `root_genesis` row above
            // sequence 1, and normalization does not read the payload type.
            fact(scope.scope_id().clone(), 2, 0xbb, ROOT_GENESIS_PAYLOAD_TYPE),
        ];
        let active = digest(0x22);
        let ordered = [
            observation_basis(1, 0xaa),
            observation_basis(2, 0xbb),
            prior_basis(0x22),
        ];

        let mut admitted = Vec::new();
        for bases in [
            ordered.to_vec(),
            // Reversed, and with every basis duplicated.
            vec![
                prior_basis(0x22),
                observation_basis(2, 0xbb),
                observation_basis(1, 0xaa),
                prior_basis(0x22),
                observation_basis(1, 0xaa),
                observation_basis(2, 0xbb),
            ],
        ] {
            let proposal = PlanProposal::new(
                scope.scope_id().clone(),
                objective.clone(),
                Some(active.clone()),
                bases,
                Vec::new(),
                0,
            );
            assert_eq!(proposal.bases(), ordered, "normalized order");
            admitted.push(
                validate_proposal(
                    &proposal,
                    &ProposalFacts::new(&scope, &objective, Some(&active), 2, &facts),
                )
                .unwrap(),
            );
        }
        assert!(admitted.windows(2).all(|pair| pair[0] == pair[1]));
    }

    /// Each tiebreak below is invisible when the fixture's sequence order and digest order agree,
    /// so every pair here makes them disagree.
    #[test]
    fn canonical_order_ranks_sequence_over_digest_and_orders_prior_revisions() {
        let scope_id = scope().scope_id().clone();

        for (input, expected) in [
            (
                vec![observation_basis(2, 0xaa), observation_basis(1, 0xbb)],
                vec![observation_basis(1, 0xbb), observation_basis(2, 0xaa)],
            ),
            (
                vec![observation_basis(1, 0xbb), observation_basis(1, 0xaa)],
                vec![observation_basis(1, 0xaa), observation_basis(1, 0xbb)],
            ),
            (
                vec![prior_basis(0x33), prior_basis(0x22)],
                vec![prior_basis(0x22), prior_basis(0x33)],
            ),
        ] {
            assert_eq!(
                PlanProposal::new(scope_id.clone(), digest(0x11), None, input, Vec::new(), 0)
                    .bases(),
                expected
            );
        }
    }

    #[test]
    fn every_header_and_basis_field_changes_the_plan_digest() {
        let scope = scope();
        let objective = digest(0x11);
        let baseline = genesis_proposal(vec![observation_basis(1, 0xaa)])
            .encode()
            .unwrap()
            .1;

        for changed in [
            PlanProposal::new(
                other_scope_id(),
                objective.clone(),
                None,
                vec![observation_basis(1, 0xaa)],
                Vec::new(),
                0,
            ),
            genesis_proposal(vec![observation_basis(2, 0xaa)]),
            genesis_proposal(vec![observation_basis(1, 0xbb)]),
            genesis_proposal(vec![prior_basis(0xaa)]),
            genesis_proposal(vec![]),
            PlanProposal::new(
                scope.scope_id().clone(),
                digest(0x12),
                None,
                vec![observation_basis(1, 0xaa)],
                Vec::new(),
                0,
            ),
            PlanProposal::new(
                scope.scope_id().clone(),
                objective.clone(),
                Some(digest(0x22)),
                vec![observation_basis(1, 0xaa)],
                Vec::new(),
                0,
            ),
        ] {
            assert_ne!(changed.encode().unwrap().1, baseline, "{changed:?}");
        }
    }

    #[test]
    fn every_basis_rejection_fails_closed_before_any_mutation() {
        let scope = scope();
        let scope_id = scope.scope_id().clone();
        let objective = digest(0x11);
        let active = digest(0x22);
        let genesis = [genesis_fact()];
        let cross_scope = [fact(other_scope_id(), 1, 0xaa, ROOT_GENESIS_PAYLOAD_TYPE)];
        let wrong_digest = [fact(scope_id.clone(), 1, 0xcc, ROOT_GENESIS_PAYLOAD_TYPE)];
        // Valid in every respect except that the scope has not applied sequence 2 yet, so only
        // the projected-tail guard can reject it.
        let beyond_tail = [
            genesis_fact(),
            fact(scope_id.clone(), 2, 0xbb, ROOT_GENESIS_PAYLOAD_TYPE),
        ];
        let successor_payload = [fact(scope_id.clone(), 1, 0xaa, TEST_SUCCESSOR_PAYLOAD_TYPE)];
        let one_observation = vec![observation_basis(1, 0xaa)];

        let cases: [(PlanProposal, Option<&Digest>, u64, &[ObservationFact], _); 12] = [
            (
                PlanProposal::new(
                    other_scope_id(),
                    objective.clone(),
                    None,
                    one_observation.clone(),
                    Vec::new(),
                    0,
                ),
                None,
                1,
                &genesis,
                ProposalError::ScopeMismatch,
            ),
            (
                PlanProposal::new(
                    scope_id.clone(),
                    digest(0x99),
                    None,
                    one_observation.clone(),
                    Vec::new(),
                    0,
                ),
                None,
                1,
                &genesis,
                ProposalError::ObjectiveMismatch,
            ),
            // The projected-tail guard rejects sequence 2 although its supplied fact matches,
            // because the tail is 1.
            (
                genesis_proposal(vec![observation_basis(2, 0xbb)]),
                None,
                1,
                &beyond_tail,
                ProposalError::MissingBasis,
            ),
            // Within the tail, but no fact was resolved at that sequence.
            (
                genesis_proposal(one_observation.clone()),
                None,
                1,
                &[],
                ProposalError::MissingBasis,
            ),
            (
                genesis_proposal(one_observation.clone()),
                None,
                1,
                &wrong_digest,
                ProposalError::StaleBasis,
            ),
            // The three illegal parent/active combinations.
            (
                PlanProposal::new(
                    scope_id.clone(),
                    objective.clone(),
                    Some(digest(0x33)),
                    one_observation.clone(),
                    Vec::new(),
                    0,
                ),
                Some(&active),
                1,
                &genesis,
                ProposalError::StaleBasis,
            ),
            (
                genesis_proposal(one_observation.clone()),
                Some(&active),
                1,
                &genesis,
                ProposalError::StaleBasis,
            ),
            // A parent naming a plan this scope does not hold at all.
            (
                PlanProposal::new(
                    scope_id.clone(),
                    objective.clone(),
                    Some(active.clone()),
                    one_observation.clone(),
                    Vec::new(),
                    0,
                ),
                None,
                1,
                &genesis,
                ProposalError::StaleBasis,
            ),
            // A prior revision with no active plan to supersede.
            (
                genesis_proposal(vec![prior_basis(0x22)]),
                None,
                1,
                &genesis,
                ProposalError::StaleBasis,
            ),
            // Two citations at one sequence: the lower digest passes, the other is stale.
            (
                genesis_proposal(vec![observation_basis(1, 0xaa), observation_basis(1, 0xbb)]),
                None,
                1,
                &genesis,
                ProposalError::StaleBasis,
            ),
            (
                genesis_proposal(one_observation.clone()),
                None,
                1,
                &cross_scope,
                ProposalError::CrossScopeBasis,
            ),
            // The planning-input check accepts only `root_genesis`, not every payload type
            // `payload_type_registered` accepts.
            (
                genesis_proposal(one_observation.clone()),
                None,
                1,
                &successor_payload,
                ProposalError::UnsupportedPlanningInput,
            ),
        ];

        for (proposal, active_plan, tail, observations, expected) in cases {
            let facts = ProposalFacts::new(&scope, &objective, active_plan, tail, observations);
            assert_eq!(
                validate_proposal(&proposal, &facts),
                Err(expected),
                "{proposal:?} against {facts:?}"
            );
        }

        // Canonical order decides which of two faults is reported: observations rank ahead of
        // prior revisions, so the unseen citation wins over the stale prior revision.
        assert_eq!(
            validate_proposal(
                &genesis_proposal(vec![observation_basis(2, 0xaa), prior_basis(0x22)]),
                &ProposalFacts::new(&scope, &objective, None, 1, &genesis),
            ),
            Err(ProposalError::MissingBasis)
        );
        // An empty basis list carries no rejection rule of its own.
        assert!(
            validate_proposal(
                &genesis_proposal(Vec::new()),
                &ProposalFacts::new(&scope, &objective, None, 1, &genesis),
            )
            .is_ok()
        );
    }

    /// Predicate-level only: `validate_proposal` cannot reach this without a SHA-256 fixed point.
    #[test]
    fn a_proposal_naming_its_own_address_is_cyclic() {
        let scope_id = scope().scope_id().clone();
        let own = digest(0x44);
        let observation = ProposalBasis::Observation {
            event: ScopeEventRef::new(1, own.clone()).unwrap(),
        };

        assert!(is_cyclic(
            &own,
            &PlanProposal::new(
                scope_id.clone(),
                digest(0x11),
                Some(own.clone()),
                Vec::new(),
                Vec::new(),
                0,
            ),
        ));
        assert!(is_cyclic(
            &own,
            &PlanProposal::new(
                scope_id.clone(),
                digest(0x11),
                None,
                vec![ProposalBasis::PriorRevision {
                    plan_digest: own.clone()
                }],
                Vec::new(),
                0,
            ),
        ));
        // An observation whose event digest matches is not a lineage edge.
        assert!(!is_cyclic(
            &own,
            &PlanProposal::new(
                scope_id,
                digest(0x11),
                None,
                vec![observation],
                Vec::new(),
                0
            ),
        ));
    }

    fn bounds() -> TargetBounds {
        TargetBounds::new(3, 1_700_000_000_000).unwrap()
    }

    fn spec(work_id: &str, dependencies: &[&str]) -> WorkSpec {
        WorkSpec::new(
            WorkId::new(work_id.into()).unwrap(),
            dependencies
                .iter()
                .map(|id| WorkId::new((*id).into()).unwrap())
                .collect(),
            bounds(),
        )
    }

    fn planned(work_specs: Vec<WorkSpec>, reserved_budget_units: u64) -> PlanProposal {
        PlanProposal::new(
            scope().scope_id().clone(),
            digest(0x11),
            None,
            vec![observation_basis(1, 0xaa)],
            work_specs,
            reserved_budget_units,
        )
    }

    fn admit(proposal: &PlanProposal) -> Result<AdmissibleProposal, ProposalError> {
        let scope = scope();
        let objective = digest(0x11);
        let facts = [genesis_fact()];
        validate_proposal(
            proposal,
            &ProposalFacts::new(&scope, &objective, None, 1, &facts),
        )
    }

    #[test]
    fn a_closed_acyclic_work_graph_is_admissible_and_addresses_its_own_bytes() {
        let proposal = planned(vec![spec("work-b", &["work-a"]), spec("work-a", &[])], 7);

        // Normalization orders work by identity, so the declared order does not reach the bytes.
        assert_eq!(
            proposal
                .work_specs()
                .iter()
                .map(|spec| spec.work_id().as_str())
                .collect::<Vec<_>>(),
            ["work-a", "work-b"]
        );
        let admissible = admit(&proposal).unwrap();
        assert_eq!(proposal.reserved_budget_units(), 7);
        assert!(admissible.stored_bytes().starts_with(PLAN_PROPOSAL_DOMAIN));
        // The address is the plain digest of the stored bytes, so the store verifies it unchanged.
        assert_eq!(
            admissible.plan_digest().as_str(),
            format!("{:x}", Sha256::digest(admissible.stored_bytes()))
        );
    }

    #[test]
    fn every_work_graph_bound_and_budget_rejection_fails_closed() {
        for (proposal, expected) in [
            (
                planned(vec![spec("work-a", &[]), spec("work-a", &["work-b"])], 0),
                ProposalError::DuplicateWork,
            ),
            (
                planned(vec![spec("work-a", &["work-missing"])], 0),
                ProposalError::UnknownDependency,
            ),
            (
                planned(vec![spec("work-a", &["work-a"])], 0),
                ProposalError::CyclicDependency,
            ),
            (
                planned(
                    vec![spec("work-a", &["work-b"]), spec("work-b", &["work-a"])],
                    0,
                ),
                ProposalError::CyclicDependency,
            ),
            (
                planned(
                    vec![
                        spec("work-a", &["work-c"]),
                        spec("work-b", &["work-a"]),
                        spec("work-c", &["work-b"]),
                    ],
                    0,
                ),
                ProposalError::CyclicDependency,
            ),
            (
                planned(vec![spec("work-a", &[])], MAX_STORED_INTEGER + 1),
                ProposalError::BudgetOutOfRange,
            ),
        ] {
            assert_eq!(admit(&proposal), Err(expected), "{proposal:?}");
        }

        // A bound is unrepresentable rather than rejected later, so no proposal can carry one.
        for (max_attempts, deadline_unix_ms) in [
            (0, 1),
            (1, 0),
            (MAX_STORED_INTEGER + 1, 1),
            (1, MAX_STORED_INTEGER + 1),
        ] {
            assert_eq!(
                TargetBounds::new(max_attempts, deadline_unix_ms),
                Err(ProposalError::BoundOutOfRange)
            );
        }

        // A long chain is acyclic and must not be refused by the cycle search.
        let chain = (0..64)
            .map(|index| {
                let dependency = format!("work-{:02}", index + 1);
                if index == 63 {
                    spec(&format!("work-{index:02}"), &[])
                } else {
                    spec(&format!("work-{index:02}"), &[dependency.as_str()])
                }
            })
            .collect();
        assert!(admit(&planned(chain, 0)).is_ok());
    }

    #[test]
    fn stored_plan_bytes_round_trip_and_reject_every_corruption() {
        let proposal = planned(vec![spec("work-b", &["work-a"]), spec("work-a", &[])], 5);
        let admissible = admit(&proposal).unwrap();
        let stored = admissible.stored_bytes();

        assert_eq!(
            decode_plan(stored, admissible.plan_digest()).unwrap(),
            proposal
        );

        // A plan that addresses something else is refused even though its bytes are well formed.
        assert_eq!(
            decode_plan(stored, &digest(0x77)),
            Err(ProposalError::PlanDigestMismatch)
        );
        // Without the domain prefix the same CBOR is not a plan object.
        assert_eq!(
            decode_plan(
                &stored[PLAN_PROPOSAL_DOMAIN.len()..],
                admissible.plan_digest()
            ),
            Err(ProposalError::InvalidEncoding)
        );
        // Trailing bytes change the address and are not canonical.
        let mut padded = stored.to_vec();
        padded.push(0);
        assert_eq!(
            decode_plan(&padded, admissible.plan_digest()),
            Err(ProposalError::InvalidEncoding)
        );
        assert_eq!(
            decode_plan(PLAN_PROPOSAL_DOMAIN, admissible.plan_digest()),
            Err(ProposalError::InvalidEncoding)
        );
        let mut oversized = PLAN_PROPOSAL_DOMAIN.to_vec();
        oversized.resize(PLAN_PROPOSAL_DOMAIN.len() + MAX_PLAN_CANONICAL_BYTES + 1, 0);
        assert_eq!(
            decode_plan(&oversized, admissible.plan_digest()),
            Err(ProposalError::PlanTooLarge)
        );
    }
}
