//! Typed root-plan proposals and the pure gate that runs before admission.
//!
//! A proposal binds its exact root scope, objective, parent plan, and typed bases in its own
//! bytes. Construction normalizes the basis list into one total order and drops duplicates, so
//! two callers that cite the same bases in different order derive byte-identical canonical bytes
//! and one `plan_digest`. The content address is `SHA-256("ravel.plan.proposal\0" || CBOR)`,
//! matching how [`crate::scope::root_scope_id`] domain-separates its own seed.
//!
//! [`validate_proposal`] performs no I/O: every durable fact it needs arrives in
//! [`ProposalFacts`], which the admitting transaction resolves. That is what "fails before
//! mutation" means here — the gate cannot reach durable state to mutate it.
//!
//! The root-only MVP has exactly two basis kinds. Child certificates and delegation bases are
//! post-signal work and are not representable. `root_genesis` is the only supported
//! planning-input payload, because it is the durable objective and configuration record and no
//! observation payload type exists yet; every other payload type fails closed, exactly as
//! [`crate::scope::payload_type_registered`] does for events.

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
/// Construction is infallible because every field is already a validated domain value. Whether
/// the payload type is a planning input is [`validate_proposal`]'s decision, not this type's.
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
/// The caller resolves these from the scope head and projection before validating, which keeps
/// this module free of I/O and makes every rejection reachable from a unit test.
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
    ///
    /// Construction cannot fail: every argument is already a validated domain value, and
    /// ordering has no rejectable input.
    pub fn new(
        scope_id: ScopeId,
        objective_digest: Digest,
        parent_plan_digest: Option<Digest>,
        mut bases: Vec<ProposalBasis>,
    ) -> Self {
        bases.sort_unstable_by(|left, right| sort_key(left).cmp(&sort_key(right)));
        // The sort key determines the basis, so equal keys are equal values and land adjacent.
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
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmissibleProposal {
    canonical_bytes: Vec<u8>,
    plan_digest: Digest,
}

impl AdmissibleProposal {
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub fn plan_digest(&self) -> &Digest {
        &self.plan_digest
    }
}

/// Decides one proposal against the facts the caller resolved, without touching durable state.
///
/// # Errors
///
/// Returns [`ProposalError::ScopeMismatch`] when the proposal names another scope and
/// [`ProposalError::ObjectiveMismatch`] when it names another objective. Returns
/// [`ProposalError::StaleBasis`] when the parent plan is not the scope's active plan, a prior
/// revision names anything other than the active plan, or a cited observation's digest differs
/// at that sequence; [`ProposalError::MissingBasis`] when a citation is above the projected tail
/// or has no resolved fact; [`ProposalError::CrossScopeBasis`] when a resolved fact belongs to
/// another scope; [`ProposalError::UnsupportedPlanningInput`] when its payload type is not a
/// planning input; [`ProposalError::CyclicBasis`] when the proposal is its own ancestor; and
/// [`ProposalError::InvalidEncoding`] when canonical bytes cannot be derived.
pub fn validate_proposal(
    proposal: &PlanProposal,
    facts: &ProposalFacts<'_>,
) -> Result<AdmissibleProposal, ProposalError> {
    if &proposal.scope_id != facts.scope.scope_id() {
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
                // Facts are resolved by sequence, so a digest that disagrees at a sequence the
                // scope has applied is stale evidence rather than a missing one.
                let fact = facts
                    .observations
                    .iter()
                    .find(|fact| fact.event.sequence() == event.sequence())
                    .ok_or(ProposalError::MissingBasis)?;
                if &fact.scope_id != facts.scope.scope_id() {
                    return Err(ProposalError::CrossScopeBasis);
                }
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
    if is_cyclic(&plan_digest, proposal) {
        return Err(ProposalError::CyclicBasis);
    }
    Ok(AdmissibleProposal {
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

/// Total order over bases. The leading tag keeps observations ahead of prior revisions, and the
/// remaining fields determine the basis, so equal keys mean equal values.
fn sort_key(basis: &ProposalBasis) -> (u8, u64, &str) {
    match basis {
        ProposalBasis::Observation { event } => (0, event.sequence(), event.digest().as_str()),
        ProposalBasis::PriorRevision { plan_digest } => (1, 0, plan_digest.as_str()),
    }
}

/// Serialize-only canonical form. There is no decode path: a proposal is validated from typed
/// values and addressed by these bytes, never reconstructed from them.
#[derive(Serialize)]
struct WirePlanProposal<'a> {
    scope_id: &'a str,
    objective_digest: &'a str,
    parent_plan_digest: Option<&'a str>,
    bases: Vec<WireProposalBasis<'a>>,
}

/// Externally tagged, unlike the internally tagged JSON records in `distributed::claims`: CBOR
/// encodes the default representation directly, while an internal tag would buffer the variant
/// through serde's `Content` before writing.
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

    fn genesis_fact() -> ObservationFact {
        ObservationFact::new(
            scope().scope_id().clone(),
            event(1, 0xaa),
            ROOT_GENESIS_PAYLOAD_TYPE.to_owned(),
        )
    }

    /// A first root plan: no active plan, one observation basis naming the genesis event.
    fn genesis_proposal(bases: Vec<ProposalBasis>) -> PlanProposal {
        PlanProposal::new(scope().scope_id().clone(), digest(0x11), None, bases)
    }

    fn observation_basis(sequence: u64, seed: u8) -> ProposalBasis {
        ProposalBasis::Observation {
            event: event(sequence, seed),
        }
    }

    #[test]
    fn genesis_proposal_binds_its_identities_and_admits_the_root_genesis_basis() {
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
        assert!(!admissible.canonical_bytes().is_empty());
        // The address is derived, so it must not collide with any input digest.
        assert_ne!(admissible.plan_digest(), &objective);
    }

    #[test]
    fn a_successor_admits_the_active_plan_as_its_parent_and_prior_revision() {
        let scope = scope();
        let objective = digest(0x11);
        let active = digest(0x22);
        let proposal = PlanProposal::new(
            scope.scope_id().clone(),
            objective.clone(),
            Some(active.clone()),
            vec![
                ProposalBasis::PriorRevision {
                    plan_digest: active.clone(),
                },
                observation_basis(1, 0xaa),
            ],
        );
        let facts = [genesis_fact()];

        assert!(
            validate_proposal(
                &proposal,
                &ProposalFacts::new(&scope, &objective, Some(&active), 1, &facts),
            )
            .is_ok()
        );
    }

    #[test]
    fn equivalent_basis_multisets_normalize_to_one_byte_string_and_digest() {
        let scope = scope();
        let objective = digest(0x11);
        let facts = [
            genesis_fact(),
            ObservationFact::new(
                scope.scope_id().clone(),
                event(2, 0xbb),
                ROOT_GENESIS_PAYLOAD_TYPE.to_owned(),
            ),
        ];
        let active = digest(0x22);
        let prior = ProposalBasis::PriorRevision {
            plan_digest: active.clone(),
        };
        let ordered = [
            observation_basis(1, 0xaa),
            observation_basis(2, 0xbb),
            prior.clone(),
        ];

        let mut admitted = Vec::new();
        for bases in [
            ordered.to_vec(),
            // Reversed, and with every basis duplicated.
            vec![
                prior.clone(),
                observation_basis(2, 0xbb),
                observation_basis(1, 0xaa),
                prior.clone(),
                observation_basis(1, 0xaa),
                observation_basis(2, 0xbb),
            ],
            vec![
                observation_basis(2, 0xbb),
                prior.clone(),
                observation_basis(1, 0xaa),
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
            genesis_proposal(vec![ProposalBasis::PriorRevision {
                plan_digest: digest(0xaa),
            }]),
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
    fn every_rejection_category_fails_closed_before_any_mutation() {
        let scope = scope();
        let objective = digest(0x11);
        let active = digest(0x22);
        let genesis = [genesis_fact()];
        let cross_scope = [ObservationFact::new(
            other_scope_id(),
            event(1, 0xaa),
            ROOT_GENESIS_PAYLOAD_TYPE.to_owned(),
        )];
        let wrong_digest = [ObservationFact::new(
            scope.scope_id().clone(),
            event(1, 0xcc),
            ROOT_GENESIS_PAYLOAD_TYPE.to_owned(),
        )];
        let successor_payload = [ObservationFact::new(
            scope.scope_id().clone(),
            event(1, 0xaa),
            TEST_SUCCESSOR_PAYLOAD_TYPE.to_owned(),
        )];
        let unknown_payload = [ObservationFact::new(
            scope.scope_id().clone(),
            event(1, 0xaa),
            "plan_admitted".to_owned(),
        )];
        let one_observation = vec![observation_basis(1, 0xaa)];

        let cases: [(PlanProposal, Option<&Digest>, u64, &[ObservationFact], _); 10] = [
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
                    scope.scope_id().clone(),
                    digest(0x99),
                    None,
                    one_observation.clone(),
                ),
                None,
                1,
                &genesis,
                ProposalError::ObjectiveMismatch,
            ),
            // A citation the scope has not applied yet.
            (
                genesis_proposal(vec![observation_basis(2, 0xaa)]),
                None,
                1,
                &genesis,
                ProposalError::MissingBasis,
            ),
            // Within the tail, but no fact was resolved at that sequence.
            (
                genesis_proposal(vec![observation_basis(1, 0xaa)]),
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
            // Parent disagrees with the active plan in both directions.
            (
                PlanProposal::new(
                    scope.scope_id().clone(),
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
            // A prior revision with no active plan to supersede.
            (
                genesis_proposal(vec![ProposalBasis::PriorRevision {
                    plan_digest: active.clone(),
                }]),
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
            (
                genesis_proposal(one_observation.clone()),
                None,
                1,
                &successor_payload,
                ProposalError::UnsupportedPlanningInput,
            ),
        ];

        for (proposal, active_plan, tail, observations, expected) in cases {
            assert_eq!(
                validate_proposal(
                    &proposal,
                    &ProposalFacts::new(&scope, &objective, active_plan, tail, observations),
                ),
                Err(expected),
                "{proposal:?}"
            );
        }

        // A payload type that will exist later is still not a planning input today.
        assert_eq!(
            validate_proposal(
                &genesis_proposal(one_observation),
                &ProposalFacts::new(&scope, &objective, None, 1, &unknown_payload),
            ),
            Err(ProposalError::UnsupportedPlanningInput)
        );
    }

    #[test]
    fn a_proposal_naming_its_own_address_is_cyclic() {
        let scope_id = scope().scope_id().clone();
        let own = digest(0x44);

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
                    plan_digest: own.clone(),
                }],
            ),
        ));
        // An observation whose event digest matches is not a lineage edge.
        let observation = ProposalBasis::Observation {
            event: ScopeEventRef::new(1, own.clone()).unwrap(),
        };
        assert!(!is_cyclic(
            &own,
            &PlanProposal::new(scope_id, digest(0x11), None, vec![observation]),
        ));
    }
}
