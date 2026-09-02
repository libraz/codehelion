//! The candidate-selection funnel: what each stage passed on, why items
//! were dropped, and how the record survives a round trip through the store.

use codehelion_store::snapshot::{FunnelDropRow, FunnelStageRow};
use serde::Serialize;

/// One stage of the candidate pipeline.
#[derive(Debug, Serialize)]
pub struct FunnelStage {
    /// What the stage counts, as a short name.
    pub stage: String,
    /// Items the stage handed to the next one.
    pub passed: u64,
    /// Items the stage dropped, by cause. Causes that dropped nothing are
    /// left out.
    pub dropped: Vec<FunnelDrop>,
}

impl FunnelStage {
    /// A stage that passed `passed` items on and has yet to record any drop.
    #[must_use]
    pub fn new(stage: &str, passed: u64) -> Self {
        Self {
            stage: stage.to_string(),
            passed,
            dropped: Vec::new(),
        }
    }

    /// Record `count` items dropped for `cause`, ignoring a cause that
    /// dropped nothing.
    #[must_use]
    pub fn dropping(mut self, cause: FunnelCause, count: u64) -> Self {
        if count > 0 {
            self.dropped.push(FunnelDrop {
                cause: cause.name().to_string(),
                count,
            });
        }
        self
    }
}

/// Every reason a funnel stage can drop what it was handed.
///
/// The funnel is serialized as data so a stored run can be rendered by a newer
/// binary, but a producer names a variant rather than spelling a cause: two
/// spellings of one reason read as two reasons, and a reason nothing can
/// resolve reads as a ceiling nobody has to explain. Keeping the vocabulary in
/// one enum is also what makes the predicates below total — a cause added here
/// stops [`FunnelCause::truncates_the_search`] compiling until somebody decides
/// whether it means the report is incomplete.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FunnelCause {
    /// Index values dropped because more places share them than the posting
    /// ceiling admits.
    OversharedValues,
    /// The occurrence entries those values held, dropped along with them.
    OversharedPostings,
    /// Candidates left unexamined because a pairing pass spent its allowance.
    PairBudget,
    /// Control headers too long or malformed to locate a block safely.
    ControlHeaderLimit,
    /// Block bodies left uncut because they nest deeper than the extraction
    /// ceiling.
    NestingLimit,
    /// Files whose parse stopped at the structural depth ceiling.
    DepthLimit,
    /// Fragment classes dropped for holding more members than the ceiling
    /// admits.
    ClassCap,
    /// Members evicted from a class whose normal form did not match its hash.
    HashCollision,
    /// Pairs that cannot coexist because they occupy alternative preprocessor
    /// arms.
    ConditionalArms,
    /// Findings a wider finding already covers.
    Subsumed,
    /// Pairs dropped because a wider pair of the same class already stated the
    /// same duplication between the same two occurrences.
    AWiderPairSaysItAlready,
    /// Units carrying too few shingles for a near-match estimate to mean
    /// anything.
    TooFewShingles,
    /// Units left unsigned once the signing ceiling was reached.
    SignedUnitLimit,
    /// Near-match buckets dropped for holding more members than the ceiling
    /// admits.
    CrowdedBucket,
    /// Proposals whose two sides differ too much in length to be clones.
    LengthRatio,
    /// Proposals the estimated Jaccard gate declined.
    EstimatedJaccard,
    /// Near-miss diagnostics beyond the retention ceiling.
    RetentionCap,
    /// Sibling candidates left uncompared once the sweep spent its allowance.
    SiblingCandidateBudget,
    /// Sibling candidates left out once their group reached its ceiling.
    SiblingPerGroupCap,
    /// Sibling candidates left out once the run reached its ceiling.
    SiblingTotalCap,
    /// Signature-sibling candidates left uncompared once the sweep spent its
    /// allowance.
    SignatureSiblingCandidateBudget,
    /// Signature siblings left out once their group reached its ceiling.
    SignatureSiblingPerGroupCap,
    /// Signature siblings left out once the run reached its ceiling.
    SignatureSiblingTotalCap,
    /// Signature keys too widely shared to count as sibling evidence.
    SignatureSharedByTooManyUnits,
    /// Control-flow skeletons with too little shape to compare.
    SkeletonTooSmall,
    /// Control-flow skeletons dropped for being shared by too many units.
    OversharedSkeletons,
    /// The postings those skeletons held, dropped along with them.
    OversharedSkeletonPostings,
    /// Candidate pairs dropped because one unit encloses the other.
    Nested,
    /// Candidate pairs whose two units hold too different a mix of shapes.
    DivergentShapes,
    /// Candidates shorter than the configured minimum clone length.
    BelowMinCloneTokens,
    /// Pairs left unverified once verification spent its allowance.
    VerificationBudget,
    /// Verified pairs no reported group holds both halves of.
    NoGroupHoldsBoth,
    /// Verified pairs a group already relates from both sides.
    AGroupSaysItAlready,
    /// Verified pairs whose two sides the component ceiling cut apart.
    TheCeilingCutTheSet,
    /// Units that ended as singletons rather than in a group.
    LeftAlone,
    /// Run seeds whose occurrences did not agree on how far the run extends.
    DivergentExtent,
    /// Runs shorter than the minimum a run has to reach.
    BelowMinimum,
    /// Runs whose own occurrences overlap each other.
    SelfOverlapping,
    /// Runs a longer run already covers.
    Contained,
    /// Runs folded into another run holding the same content.
    SameContent,
    /// Occurrences holding content no other occurrence of their run shared.
    UnsharedContent,
    /// Occurrences whose tokens could never be established.
    UnresolvedOccurrence,
    /// Occurrences covering source a kept occurrence already covers.
    OverlappingOccurrence,
    /// Occurrences continuing a kept occurrence statement for statement.
    AdjoiningOccurrence,
    /// API observations outside the registered vocabulary.
    OutsideRegisteredVocabulary,
    /// Graphs the extractor found ineligible.
    Ineligible,
    /// Units holding no registered operation.
    NoRegisteredOperations,
    /// Units no registered rule claimed.
    NoRegisteredRuleMatched,
    /// Candidate buckets dropped for holding more members than the ceiling
    /// admits.
    BucketMemberCap,
    /// Pairs a disabled rule kept out of grouping.
    RuleDisabled,
    /// Grouping input that did not describe a pair of units.
    InvalidGroupingInput,
    /// A relation grouping had already been given.
    DuplicateRelation,
    /// Records removed because an exact duplicate identity was emitted.
    ExactDuplicateIdentity,
}

impl FunnelCause {
    /// The cause as it is serialized and stored.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::OversharedValues => "overshared_values",
            Self::OversharedPostings => "overshared_postings",
            Self::PairBudget => "pair_budget",
            Self::ControlHeaderLimit => "control_header_limit",
            Self::NestingLimit => "nesting_limit",
            Self::DepthLimit => "depth_limit",
            Self::ClassCap => "class_cap",
            Self::HashCollision => "hash_collision",
            Self::ConditionalArms => "conditional_arms",
            Self::Subsumed => "subsumed",
            Self::AWiderPairSaysItAlready => "a_wider_pair_says_it_already",
            Self::TooFewShingles => "too_few_shingles",
            Self::SignedUnitLimit => "signed_unit_limit",
            Self::CrowdedBucket => "crowded_bucket",
            Self::LengthRatio => "length_ratio",
            Self::EstimatedJaccard => "estimated_jaccard",
            Self::RetentionCap => "retention_cap",
            Self::SiblingCandidateBudget => "sibling_candidate_budget",
            Self::SiblingPerGroupCap => "sibling_per_group_cap",
            Self::SiblingTotalCap => "sibling_total_cap",
            Self::SignatureSiblingCandidateBudget => "signature_sibling_candidate_budget",
            Self::SignatureSiblingPerGroupCap => "signature_sibling_per_group_cap",
            Self::SignatureSiblingTotalCap => "signature_sibling_total_cap",
            Self::SignatureSharedByTooManyUnits => "signature_shared_by_too_many_units",
            Self::SkeletonTooSmall => "skeleton_too_small",
            Self::OversharedSkeletons => "overshared_skeletons",
            Self::OversharedSkeletonPostings => "overshared_skeleton_postings",
            Self::Nested => "nested",
            Self::DivergentShapes => "divergent_shapes",
            Self::BelowMinCloneTokens => "below_min_clone_tokens",
            Self::VerificationBudget => "verification_budget",
            Self::NoGroupHoldsBoth => "no_group_holds_both",
            Self::AGroupSaysItAlready => "a_group_says_it_already",
            Self::TheCeilingCutTheSet => "the_ceiling_cut_the_set",
            Self::LeftAlone => "left_alone",
            Self::DivergentExtent => "divergent_extent",
            Self::BelowMinimum => "below_minimum",
            Self::SelfOverlapping => "self_overlapping",
            Self::Contained => "contained",
            Self::SameContent => "same_content",
            Self::UnsharedContent => "unshared_content",
            Self::UnresolvedOccurrence => "unresolved_occurrence",
            Self::OverlappingOccurrence => "overlapping_occurrence",
            Self::AdjoiningOccurrence => "adjoining_occurrence",
            Self::OutsideRegisteredVocabulary => "outside_registered_vocabulary",
            Self::Ineligible => "ineligible",
            Self::NoRegisteredOperations => "no_registered_operations",
            Self::NoRegisteredRuleMatched => "no_registered_rule_matched",
            Self::BucketMemberCap => "bucket_member_cap",
            Self::RuleDisabled => "rule_disabled",
            Self::InvalidGroupingInput => "invalid_grouping_input",
            Self::DuplicateRelation => "duplicate_relation",
            Self::ExactDuplicateIdentity => "exact_duplicate_identity",
        }
    }

    /// Every cause, so a reader of stored data can resolve one by its name and
    /// a test can check the vocabulary is spelled distinctly.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::OversharedValues,
            Self::OversharedPostings,
            Self::PairBudget,
            Self::ControlHeaderLimit,
            Self::NestingLimit,
            Self::DepthLimit,
            Self::ClassCap,
            Self::HashCollision,
            Self::ConditionalArms,
            Self::Subsumed,
            Self::AWiderPairSaysItAlready,
            Self::TooFewShingles,
            Self::SignedUnitLimit,
            Self::CrowdedBucket,
            Self::LengthRatio,
            Self::EstimatedJaccard,
            Self::RetentionCap,
            Self::SiblingCandidateBudget,
            Self::SiblingPerGroupCap,
            Self::SiblingTotalCap,
            Self::SignatureSiblingCandidateBudget,
            Self::SignatureSiblingPerGroupCap,
            Self::SignatureSiblingTotalCap,
            Self::SignatureSharedByTooManyUnits,
            Self::SkeletonTooSmall,
            Self::OversharedSkeletons,
            Self::OversharedSkeletonPostings,
            Self::Nested,
            Self::DivergentShapes,
            Self::BelowMinCloneTokens,
            Self::VerificationBudget,
            Self::NoGroupHoldsBoth,
            Self::AGroupSaysItAlready,
            Self::TheCeilingCutTheSet,
            Self::LeftAlone,
            Self::DivergentExtent,
            Self::BelowMinimum,
            Self::SelfOverlapping,
            Self::Contained,
            Self::SameContent,
            Self::UnsharedContent,
            Self::UnresolvedOccurrence,
            Self::OverlappingOccurrence,
            Self::AdjoiningOccurrence,
            Self::OutsideRegisteredVocabulary,
            Self::Ineligible,
            Self::NoRegisteredOperations,
            Self::NoRegisteredRuleMatched,
            Self::BucketMemberCap,
            Self::RuleDisabled,
            Self::InvalidGroupingInput,
            Self::DuplicateRelation,
            Self::ExactDuplicateIdentity,
        ]
    }

    /// The cause a stored name refers to, or `None` for a name this build does
    /// not know.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::all()
            .iter()
            .copied()
            .find(|cause| cause.name() == name)
    }

    /// Whether this drop was imposed by a resource ceiling rather than by an
    /// analysis judgement about the candidate itself.
    ///
    /// Exhaustive on purpose: a cause added above stops this compiling until
    /// somebody decides whether it makes the default report look complete when
    /// it is not.
    #[must_use]
    pub const fn truncates_the_search(self) -> bool {
        match self {
            Self::OversharedValues
            | Self::OversharedPostings
            | Self::ClassCap
            | Self::PairBudget
            | Self::VerificationBudget
            | Self::CrowdedBucket
            | Self::OversharedSkeletons
            | Self::OversharedSkeletonPostings
            | Self::BucketMemberCap
            | Self::TheCeilingCutTheSet => true,
            Self::ControlHeaderLimit
            | Self::NestingLimit
            | Self::DepthLimit
            | Self::HashCollision
            | Self::ConditionalArms
            | Self::Subsumed
            | Self::AWiderPairSaysItAlready
            | Self::TooFewShingles
            | Self::SignedUnitLimit
            | Self::LengthRatio
            | Self::EstimatedJaccard
            | Self::RetentionCap
            | Self::SiblingCandidateBudget
            | Self::SiblingPerGroupCap
            | Self::SiblingTotalCap
            | Self::SignatureSiblingCandidateBudget
            | Self::SignatureSiblingPerGroupCap
            | Self::SignatureSiblingTotalCap
            | Self::SignatureSharedByTooManyUnits
            | Self::SkeletonTooSmall
            | Self::Nested
            | Self::DivergentShapes
            | Self::BelowMinCloneTokens
            | Self::NoGroupHoldsBoth
            | Self::AGroupSaysItAlready
            | Self::LeftAlone
            | Self::DivergentExtent
            | Self::BelowMinimum
            | Self::SelfOverlapping
            | Self::Contained
            | Self::SameContent
            | Self::UnsharedContent
            | Self::UnresolvedOccurrence
            | Self::OverlappingOccurrence
            | Self::AdjoiningOccurrence
            | Self::OutsideRegisteredVocabulary
            | Self::Ineligible
            | Self::NoRegisteredOperations
            | Self::NoRegisteredRuleMatched
            | Self::RuleDisabled
            | Self::InvalidGroupingInput
            | Self::DuplicateRelation
            | Self::ExactDuplicateIdentity => false,
        }
    }
}

/// Items one stage dropped for a single reason.
#[derive(Debug, Serialize)]
pub struct FunnelDrop {
    /// Why the items were dropped, as a `snake_case` cause.
    pub cause: String,
    /// How many were dropped.
    pub count: u64,
}

/// Whether a funnel drop was imposed by a resource ceiling rather than by an
/// analysis judgement about the candidate itself.
///
/// The funnel retains its cause vocabulary as data so stored reports can be
/// rendered by newer binaries, so this resolves the stored spelling back to
/// [`FunnelCause`] rather than keeping a second list of names. A cause this
/// build does not know is not treated as a ceiling: claiming truncation from a
/// word alone would let any future spelling qualify the whole report.
#[must_use]
pub fn is_search_truncation(cause: &str) -> bool {
    FunnelCause::from_name(cause).is_some_and(FunnelCause::truncates_the_search)
}

/// Whether any candidate-search ceiling made the report potentially
/// incomplete.
#[must_use]
pub fn search_truncated(funnel: &[FunnelStage]) -> bool {
    funnel
        .iter()
        .flat_map(|stage| &stage.dropped)
        .any(|drop| is_search_truncation(&drop.cause))
}

impl FunnelDrop {
    /// The cause as it reads in the text views.
    #[must_use]
    pub fn label(&self) -> String {
        self.cause.replace('_', " ")
    }
}

/// The run's funnel in the shape the audit database stores it.
#[must_use]
pub fn stored_funnel(funnel: &[FunnelStage]) -> Vec<FunnelStageRow> {
    funnel
        .iter()
        .map(|stage| FunnelStageRow {
            name: stage.stage.clone(),
            passed: stage.passed,
            dropped: stage
                .dropped
                .iter()
                .map(|drop| FunnelDropRow {
                    cause: drop.cause.clone(),
                    count: drop.count,
                })
                .collect(),
        })
        .collect()
}

/// Add the persisted form of the stable-identity normalization stage.
#[allow(clippy::redundant_pub_crate)]
pub(crate) fn append_stored_identity_stage(
    funnel: &mut Vec<FunnelStageRow>,
    groups: usize,
    identity_collapsed: u64,
) {
    if identity_collapsed > 0 {
        funnel.push(FunnelStageRow {
            name: "identity normalization".to_string(),
            passed: u64::try_from(groups).unwrap_or(u64::MAX),
            dropped: vec![FunnelDropRow {
                cause: FunnelCause::ExactDuplicateIdentity.name().to_string(),
                count: identity_collapsed,
            }],
        });
    }
}

/// Recover the number of records removed at the identity boundary.
#[must_use]
pub fn identity_collapsed(funnel: &[FunnelStage]) -> u64 {
    funnel
        .iter()
        .flat_map(|stage| &stage.dropped)
        .filter(|drop| drop.cause == FunnelCause::ExactDuplicateIdentity.name())
        .map(|drop| drop.count)
        .fold(0, u64::saturating_add)
}

/// Recover the number of persisted records removed at the identity boundary.
#[must_use]
pub fn stored_identity_collapsed(funnel: &[FunnelStageRow]) -> u64 {
    funnel
        .iter()
        .flat_map(|stage| &stage.dropped)
        .filter(|drop| drop.cause == FunnelCause::ExactDuplicateIdentity.name())
        .map(|drop| drop.count)
        .fold(0, u64::saturating_add)
}
