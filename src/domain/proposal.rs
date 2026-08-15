//! Typed root-plan proposals and the pure gate that runs before admission.
//!
//! A proposal binds its exact root scope, objective, parent plan, and typed bases in its own
//! bytes, and construction normalizes those bases so equivalent citations derive one address.
//!
//! The content address is `SHA-256("ravel.plan.proposal\0" || CBOR)`, matching how
//! [`crate::scope::root_scope_id`] domain-separates its own seed. It is therefore *not*
//! `sha256(canonical_bytes)`, which is the digest every store-side integrity check recomputes: a
//! publisher that puts these bytes under a content-addressed key must prepend the same domain or
//! carry the plain digest separately. The `ciborium` lockfile pin is byte-affecting for this
//! address, as the `zstd-sys` pin is for event bytes.
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

use std::{error::Error, fmt};

use ciborium::ser::into_writer;
use serde::Serialize;
use sha2::{Digest as _, Sha256};

use crate::scope::{Digest, ROOT_GENESIS_PAYLOAD_TYPE, ScopeEventRef, ScopeId, ScopeIdentity};

const PLAN_PROPOSAL_DOMAIN: &[u8] = b"ravel.plan.proposal\0";

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
    ) -> Self {
        bases.sort_unstable_by(|left, right| sort_key(left).cmp(&sort_key(right)));
        // `dedup` drops only adjacent equals. The sort key carries the variant tag and every
        // field of that variant, so equal keys are equal values and sorting makes them adjacent.
        bases.dedup();
        Self {
            scope_id,
            objective_digest,
            parent_plan_digest,
            bases,
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

    /// Derives the canonical bytes and the content address they hash to.
    ///
    /// Both failure paths map to [`ProposalError::InvalidEncoding`] and neither is reachable: the
    /// writer is a `Vec<u8>`, whose `ciborium_io::Write::Error` is `Infallible`, no `Serialize` impl
    /// reached from [`WirePlanProposal`] raises a custom error, and a SHA-256 rendered with `{:x}`
    /// is always 64 lowercase hexadecimal bytes. The variant keeps the boundary total rather than
    /// forcing a panic here.
    fn encode(&self) -> Result<(Vec<u8>, Digest), ProposalError> {
        let wire = WirePlanProposal {
            scope_id: self.scope_id.as_str(),
            objective_digest: self.objective_digest.as_str(),
            parent_plan_digest: self.parent_plan_digest.as_ref().map(Digest::as_str),
            bases: self.bases.iter().map(WireProposalBasis::from).collect(),
        };
        let mut canonical_bytes = Vec::new();
        into_writer(&wire, &mut canonical_bytes).map_err(|_| ProposalError::InvalidEncoding)?;
        let mut hasher = Sha256::new();
        hasher.update(PLAN_PROPOSAL_DOMAIN);
        hasher.update(&canonical_bytes);
        let plan_digest = Digest::new(format!("{:x}", hasher.finalize()))
            .map_err(|_| ProposalError::InvalidEncoding)?;
        Ok((canonical_bytes, plan_digest))
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
    canonical_bytes: Vec<u8>,
    plan_digest: Digest,
}

impl AdmissibleProposal {
    pub fn scope_id(&self) -> &ScopeId {
        &self.scope_id
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
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
    let (canonical_bytes, plan_digest) = proposal.encode()?;
    // Unreachable by construction: reaching it requires a SHA-256 fixed point. Covered only
    // through `is_cyclic` directly.
    if is_cyclic(&plan_digest, proposal) {
        return Err(ProposalError::CyclicBasis);
    }
    Ok(AdmissibleProposal {
        scope_id: proposal.scope_id.clone(),
        canonical_bytes,
        plan_digest,
    })
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

/// Serialize-only canonical form: the hash input is [`PLAN_PROPOSAL_DOMAIN`] followed by
/// declaration-order CBOR of `scope_id`, `objective_digest`, `parent_plan_digest`, then `bases`,
/// which is what a second producer has to reproduce to derive the same address. There is no decode
/// path: a proposal is validated from typed values and addressed by these bytes, never
/// reconstructed from them.
#[derive(Serialize)]
struct WirePlanProposal<'a> {
    scope_id: &'a str,
    objective_digest: &'a str,
    parent_plan_digest: Option<&'a str>,
    bases: Vec<WireProposalBasis<'a>>,
}

/// Externally tagged, unlike the internally tagged JSON records in `distributed::claims`: CBOR
/// writes the default one-entry map `{variant: {fields}}`, while an internal tag would fold the tag
/// into the field map and change these bytes.
#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum WireProposalBasis<'a> {
    Observation { sequence: u64, digest: &'a str },
    PriorRevision { plan_digest: &'a str },
}

impl<'a> From<&'a ProposalBasis> for WireProposalBasis<'a> {
    fn from(basis: &'a ProposalBasis) -> Self {
        match basis {
            ProposalBasis::Observation { event } => Self::Observation {
                sequence: event.sequence(),
                digest: event.digest().as_str(),
            },
            ProposalBasis::PriorRevision { plan_digest } => Self::PriorRevision {
                plan_digest: plan_digest.as_str(),
            },
        }
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
        "606c97aae5c1d8cbdd129d6af94b9200d97de3b09e506dc89a188849e87fc4ca";

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
        PlanProposal::new(scope().scope_id().clone(), digest(0x11), None, bases)
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
                PlanProposal::new(scope_id.clone(), digest(0x11), None, input).bases(),
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
            ),
            PlanProposal::new(
                scope.scope_id().clone(),
                objective.clone(),
                Some(digest(0x22)),
                vec![observation_basis(1, 0xaa)],
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
                Vec::new()
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
            ),
        ));
        // An observation whose event digest matches is not a lineage edge.
        assert!(!is_cyclic(
            &own,
            &PlanProposal::new(scope_id, digest(0x11), None, vec![observation]),
        ));
    }
}
