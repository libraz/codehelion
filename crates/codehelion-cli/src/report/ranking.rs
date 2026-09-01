//! Report ordering, persisted-summary restoration, and suppression labels.

use super::{
    Boilerplate, CloneClass, CloneScope, ExcludedCounts, FileCounts, FunnelDropRow, FunnelStageRow,
    Group, GroupCounts, GroupFacts, Guardrails, GuardrailsRow, Ordering, Priority, PriorityInputs,
    Serialize, Similarity, Summary, SummaryRow, SuppressedCounts, SuppressionConfig,
    UnparsedCounts, UnusedRuleRow, VENDORED_SCOPE, Weights, priority,
};
use crate::suppress::{CLONE_ID_SCOPE, multi_match_clone_ids};
use codehelion_store::directory_of;

impl Guardrails {
    /// Record the concrete resource ceilings an untrusted invocation used.
    ///
    /// `Limits::clamp_to_untrusted` first materialises the optional pairing
    /// limits. The profile is still supplied as a defensive fallback so this
    /// renderer cannot ever claim a zero or missing effective ceiling.
    ///
    /// `enforced` decides which ceilings this run states at all. A ceiling the
    /// selected mode never consults is left absent rather than filled in: a
    /// number printed beside the ones that fired reads as a bound the run
    /// worked under, and a reader who then lowered it would be adjusting a
    /// stage this mode does not run.
    /// Every ceiling stated, as a mode whose stages take all of them reports
    /// them. Only tests reach for this shorthand; a scan states the ceilings
    /// its own mode enforces and nothing else.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn untrusted(
        limits: &crate::config::Limits,
        profile: &codehelion_core::execution::Limits,
    ) -> Self {
        Self::untrusted_under(
            limits,
            profile,
            crate::scan::runtime::enforced_ceilings(crate::cli::Mode::Structural),
        )
    }

    /// The same ceilings, holding back the ones `enforced` says this run's
    /// stages never consult.
    #[must_use]
    pub(crate) fn untrusted_under(
        limits: &crate::config::Limits,
        profile: &codehelion_core::execution::Limits,
        enforced: crate::scan::runtime::EnforcedCeilings,
    ) -> Self {
        use crate::scan::runtime::Ceiling;
        let verification = enforced.holds(Ceiling::Verification);
        let grouping = enforced.holds(Ceiling::Grouping);
        let near_match = enforced.holds(Ceiling::NearMatch);
        let siblings = enforced.holds(Ceiling::Siblings);
        Self {
            profile: "untrusted".to_string(),
            max_file_bytes: limits.max_file_bytes,
            parse_timeout_ms: limits.parse_timeout_ms,
            helper_timeout_ms: limits.helper_timeout_ms,
            posting_cap: limits.posting_cap.unwrap_or(profile.posting_cap),
            pair_budget: limits.pair_budget.unwrap_or(profile.max_candidates),
            verification_budget: verification.then(|| {
                limits
                    .verification_budget
                    .unwrap_or(profile.verification_budget)
            }),
            max_alignment_cells: verification.then(|| {
                limits
                    .max_alignment_cells
                    .unwrap_or(profile.max_alignment_cells)
            }),
            near_miss_delta: near_match.then(|| {
                limits.near_miss_delta.unwrap_or_else(|| {
                    codehelion_core::near_match::NearMatchConfig::default().near_miss_delta
                })
            }),
            near_miss_cap: near_match.then(|| {
                limits.near_miss_cap.unwrap_or_else(|| {
                    codehelion_core::near_match::NearMatchConfig::default().near_miss_cap
                })
            }),
            sibling_candidate_budget: siblings.then(|| {
                limits.sibling_candidate_budget.unwrap_or_else(|| {
                    codehelion_core::structural::SiblingConfig::default().candidate_budget
                })
            }),
            sibling_per_group_cap: siblings.then(|| {
                limits.sibling_per_group_cap.unwrap_or_else(|| {
                    codehelion_core::structural::SiblingConfig::default().per_group_cap
                })
            }),
            sibling_total_cap: siblings.then(|| {
                limits.sibling_total_cap.unwrap_or_else(|| {
                    codehelion_core::structural::SiblingConfig::default().total_cap
                })
            }),
            signature_sibling_candidate_budget: siblings.then(|| {
                limits
                    .signature_sibling_candidate_budget
                    .unwrap_or_else(|| {
                        codehelion_core::structural::SignatureSiblingConfig::default()
                            .candidate_budget
                    })
            }),
            signature_sibling_per_group_cap: siblings.then(|| {
                limits.signature_sibling_per_group_cap.unwrap_or_else(|| {
                    codehelion_core::structural::SignatureSiblingConfig::default().per_group_cap
                })
            }),
            signature_sibling_total_cap: siblings.then(|| {
                limits.signature_sibling_total_cap.unwrap_or_else(|| {
                    codehelion_core::structural::SignatureSiblingConfig::default().total_cap
                })
            }),
            signature_sibling_max_units_per_signature: siblings.then(|| {
                limits
                    .signature_sibling_max_units_per_signature
                    .unwrap_or_else(|| {
                        codehelion_core::structural::SignatureSiblingConfig::default()
                            .max_units_per_signature
                    })
            }),
            max_component: grouping.then_some(limits.max_component),
        }
    }
}

impl From<&GuardrailsRow> for Guardrails {
    fn from(row: &GuardrailsRow) -> Self {
        let count =
            |value: Option<u64>| value.map(|value| usize::try_from(value).unwrap_or(usize::MAX));
        Self {
            profile: row.profile.clone(),
            max_file_bytes: row.max_file_bytes,
            parse_timeout_ms: row.parse_timeout_ms,
            helper_timeout_ms: row.helper_timeout_ms,
            posting_cap: usize::try_from(row.posting_cap).unwrap_or(usize::MAX),
            pair_budget: usize::try_from(row.pair_budget).unwrap_or(usize::MAX),
            verification_budget: count(row.verification_budget),
            max_alignment_cells: count(row.max_alignment_cells),
            near_miss_delta: row.near_miss_delta_bits.map(f64::from_bits),
            near_miss_cap: count(row.near_miss_cap),
            sibling_candidate_budget: count(row.sibling_candidate_budget),
            sibling_per_group_cap: count(row.sibling_per_group_cap),
            sibling_total_cap: count(row.sibling_total_cap),
            signature_sibling_candidate_budget: count(row.signature_sibling_candidate_budget),
            signature_sibling_per_group_cap: count(row.signature_sibling_per_group_cap),
            signature_sibling_total_cap: count(row.signature_sibling_total_cap),
            signature_sibling_max_units_per_signature: count(
                row.signature_sibling_max_units_per_signature,
            ),
            max_component: count(row.max_component),
        }
    }
}

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

/// An axis a report can be put in order on.
///
/// The ranking exists because no single measure orders duplication well, and
/// the same reasoning says a reader may know which measure matters to the work
/// in front of them. Offering the axes outright is cheaper than pretending the
/// composed value fits every job — and it is what a reader who distrusts the
/// ranking would otherwise do by hand.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Sort {
    /// The composed ranking value.
    #[default]
    Priority,
    /// Raw identifier agreement against the canonical member: how much of the
    /// vocabulary the copies share before normalization.
    IdentifierJaccard,
    /// Tokens the group repeats past its canonical member.
    DuplicatedTokens,
    /// Number of occurrences.
    Instances,
}

impl Sort {
    /// What this axis is called on the command line and in a heading.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Priority => "priority",
            Self::IdentifierJaccard => "identifier Jaccard",
            Self::DuplicatedTokens => "duplicated tokens",
            Self::Instances => "instances",
        }
    }

    /// Which of two entries the axis puts first, before ties are broken.
    ///
    /// Each axis compares in its own arithmetic rather than through a shared
    /// numeric key: a count is an integer, and widening one to compare it
    /// against a score would trade exactness for a uniformity nothing needs.
    fn compare(self, a: &Group, b: &Group) -> Ordering {
        match self {
            Self::Priority => descending(Some(a.priority.value), Some(b.priority.value)),
            Self::IdentifierJaccard => descending(a.identifier_jaccard, b.identifier_jaccard),
            Self::DuplicatedTokens => duplicated_tokens(b).cmp(&duplicated_tokens(a)),
            Self::Instances => b
                .priority
                .inputs
                .instances
                .cmp(&a.priority.inputs.instances),
        }
    }
}

/// Biggest first, with a measurement nobody made last.
///
/// Absent is not the same as low: putting the unmeasured in with the worst
/// would report a guess as a reading.
fn descending(a: Option<f64>, b: Option<f64>) -> Ordering {
    match (a, b) {
        (Some(a), Some(b)) => b.total_cmp(&a),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => Ordering::Equal,
    }
}

/// Compare two entries on one axis, biggest first, then by the composed
/// ranking, then by fingerprint so the result is the same on every machine.
///
/// A single axis ties often, and the ties are where the reader is left. Raw
/// identifier agreement is the clearest case: a tree with any repetition in it
/// has dozens of entries at exactly 1.00, and ordering those by fingerprint
/// puts the largest and the most trivial of them in hash order, which is the
/// order of nothing. The composed ranking is the best statement available
/// about which of two otherwise indistinguishable entries is worth reading
/// first, so it decides before the identifier does. Fingerprint stays last and
/// still settles the remainder.
///
/// Separate from [`order`] because a view rebuilt from the database has the
/// entries but not the configuration that decides what gets ranked down, and
/// the axis has to mean the same thing in both.
#[must_use]
pub fn compare_on(a: &Group, b: &Group, sort: Sort) -> Ordering {
    sort.compare(a, b)
        .then_with(|| Sort::Priority.compare(a, b))
        .then_with(|| a.fingerprint.cmp(&b.fingerprint))
}

/// Which occurrence of a group is the one it is measured against.
///
/// One rule for every view, because the answer is read by the text listing,
/// the SARIF primary location, and a frozen baseline anchor, and those naming
/// different occurrences of the same group would be three accounts of one
/// fact. A group whose members carry no flag at all — which a partially
/// written or hand-edited database can hold — resolves to its first member
/// rather than to nothing, so the fact stays single-valued.
///
/// Generic over the member type: a report member and a stored member spell the
/// flag differently, and the rule is about neither spelling.
#[must_use]
pub fn canonical_position<T>(members: &[T], flagged: impl Fn(&T) -> bool) -> Option<usize> {
    if members.is_empty() {
        return None;
    }
    Some(members.iter().position(flagged).unwrap_or(0))
}

/// The occurrence a report group is measured against.
#[must_use]
pub fn canonical_member(group: &Group) -> Option<&Member> {
    canonical_position(&group.members, |member| member.canonical)
        .and_then(|index| group.members.get(index))
}

/// Tokens a group repeats: everything past the one copy a reader would keep.
#[must_use]
pub fn duplicated_tokens(group: &Group) -> u64 {
    let total: u64 = group.members.iter().map(|member| member.tokens).sum();
    let canonical = canonical_member(group).map_or(0, |member| member.tokens);
    total.saturating_sub(canonical)
}

/// Put the entries in the order every view of a report shows them in.
///
/// Whether the configuration ranks the entry down comes first, and then
/// [`compare_on`] settles the rest. The rank-down key is what keeps
/// boilerplate and test-suite repetition below the code under test without
/// changing what either of them scored. Changing the axis does not touch it —
/// what is ranked down stays ranked down, because that is a statement about
/// the finding rather than about which measure the reader is following.
///
/// One function rather than one per pipeline: the order is a property of the
/// report, and a scan that assembled its entries and a run rebuilt from the
/// database have to agree about it.
pub fn order(groups: &mut [Group], suppression: &SuppressionConfig, sort: Sort) {
    for group in groups.iter_mut() {
        group.ranked_down = ranks_down(group, suppression);
    }
    groups.sort_by(|a, b| {
        a.ranked_down
            .cmp(&b.ranked_down)
            .then_with(|| compare_on(a, b, sort))
    });
}

/// Whether one finding is placed after ordinary findings by presentation
/// policy, independently of its numeric priority.
#[must_use]
pub fn ranks_down(group: &Group, suppression: &SuppressionConfig) -> bool {
    suppression.ranks_down(
        group
            .boilerplate
            .as_deref()
            .and_then(Boilerplate::from_name),
        group.test_code,
        group.width_family,
        group.split_pair,
    )
}

/// Replay ordering using the rank-down verdict persisted with the run.
pub fn order_recorded(
    groups: &mut [Group],
    ranked_down: &std::collections::BTreeMap<String, bool>,
    sort: Sort,
) {
    for group in groups.iter_mut() {
        group.ranked_down = ranked_down
            .get(&group.fingerprint)
            .copied()
            .unwrap_or(false);
    }
    groups.sort_by(|a, b| {
        a.ranked_down
            .cmp(&b.ranked_down)
            .then_with(|| compare_on(a, b, sort))
    });
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

/// The rules that hid nothing, in the shape the audit database stores them.
///
/// A rule that covered several groups is left out: it hid something, and the
/// report derives that notice from the groups themselves on every path.
#[must_use]
pub fn stored_rules(rules: &[UnusedRule]) -> Vec<UnusedRuleRow> {
    rules
        .iter()
        .filter(|rule| rule.matched == 0)
        .map(|rule| UnusedRuleRow {
            scope: rule.scope.clone(),
            pattern: rule.pattern.clone(),
        })
        .collect()
}

/// The configured clone ids this report shows covering more than one group.
///
/// Read off the groups rather than counted beside the rules, because a clone
/// id outranks every other suppression rule in every mode: a group its prefix
/// covers is hidden by it and cites it, so the report itself holds the count.
/// That also makes a replayed run say what the scan said, since the groups a
/// run recorded carry the rule each of them was hidden by.
fn clone_ids_covering_several_groups(groups: &[Group]) -> Vec<UnusedRule> {
    let cited = groups.iter().filter_map(|group| {
        let suppression = group.suppressed.as_ref()?;
        if suppression.scope.as_deref() != Some(CLONE_ID_SCOPE) {
            return None;
        }
        suppression.pattern.as_deref()
    });
    multi_match_clone_ids(cited)
        .into_iter()
        .map(|(pattern, matched)| UnusedRule {
            scope: CLONE_ID_SCOPE.to_string(),
            pattern,
            matched,
        })
        .collect()
}

/// The summary a stored row and the groups it belongs to describe together.
///
/// Everything a group carries is counted off `groups` and everything else is
/// read from `stored`; nothing is held in both places. What a run measured
/// about its comparisons — the tree changes, the audit states, what a baseline
/// hid — is left absent here, because those are statements about *this*
/// invocation rather than about the recorded run.
#[must_use]
#[allow(
    clippy::too_many_lines,
    reason = "restoration keeps every persisted summary field visible beside its source"
)]
pub fn restored(stored: &SummaryRow, groups: &[Group], analysis_mode: &str) -> Summary {
    let count = |predicate: &dyn Fn(&Group) -> bool| {
        u64::try_from(groups.iter().filter(|group| predicate(group)).count()).unwrap_or(u64::MAX)
    };
    let suppressed_as = |kind: SuppressionKind| {
        count(&|group| {
            group
                .suppressed
                .as_ref()
                .is_some_and(|suppression| suppression.kind == kind)
        })
    };
    let funnel: Vec<FunnelStage> = stored
        .funnel
        .iter()
        .map(|stage| FunnelStage {
            stage: stage.name.clone(),
            passed: stage.passed,
            dropped: stage
                .dropped
                .iter()
                .map(|drop| FunnelDrop {
                    cause: drop.cause.clone(),
                    count: drop.count,
                })
                .collect(),
        })
        .collect();
    let search_truncated = search_truncated(&funnel);
    Summary {
        top_churn: None,
        files: FileCounts {
            total: stored.analyzed_files.total,
            rust: stored.analyzed_files.rust,
            c: stored.analyzed_files.c,
            cpp: stored.analyzed_files.cpp,
        },
        lines: stored.lines,
        tokens: stored.tokens,
        lexer_diagnostics: stored.lexer_diagnostics,
        unparsed: stored
            .unparsed
            .map(|row| UnparsedCounts::from_counts(row.files, row.tokens, stored.tokens)),
        excluded: ExcludedCounts {
            generated: stored.excluded_generated,
            by_glob: stored.excluded_by_glob,
            skipped: stored.excluded_skipped,
            too_large: stored.excluded_too_large,
            oversized_metadata: stored.excluded_oversized_metadata,
            binary: stored.excluded_binary,
            unreadable: stored.excluded_unreadable,
            symlinks: stored.excluded_symlinks,
            walk_errors: stored.excluded_walk_errors,
            timed_out: stored.excluded_timed_out,
            language_excluded: stored.excluded_language,
            symlink_files: stored.excluded_symlink_files,
            symlink_directories: stored.excluded_symlink_directories,
        },
        baseline: None,
        changes: None,
        guardrails: stored.guardrails.as_ref().map(Guardrails::from),
        // Nor this: what a compiler answered belongs to the run that asked
        // it, and this report is a recorded run read back.
        compiler: None,
        groups: GroupCounts {
            total: u64::try_from(groups.len()).unwrap_or(u64::MAX),
            type_1: count(&|group| group.clone_type == CloneClass::Type1.name()),
            type_2: count(&|group| group.clone_type == CloneClass::Type2.name()),
            type_3: count(&|group| group.clone_type == CloneClass::Type3.name()),
            restricted_semantic: count(&|group| {
                group.clone_type == CloneClass::RestrictedSemantic.name()
            }),
            fragment_scope: count(&|group| group.scope == CloneScope::Fragment.name()),
            folded_runs: stored.folded_runs,
            subsumed_runs: stored.subsumed_runs,
            test_code: count(&|group| group.test_code),
        },
        suppressed: SuppressedCounts {
            noise: suppressed_as(SuppressionKind::Noise),
            by_rule: suppressed_as(SuppressionKind::Rule),
            vendored: count(&|group| {
                group
                    .suppressed
                    .as_ref()
                    .and_then(|cause| cause.scope.as_deref())
                    == Some(VENDORED_SCOPE)
            }),
        },
        // Supplemental rows are assembled outside the persisted summary row;
        // the report envelope fills these from the final vectors after mode
        // specific assembly (and replay does the same after hydration).
        siblings: 0,
        near_misses: 0,
        unmeasured_in_this_mode: unmeasured_in_this_mode(analysis_mode),
        unused_suppressions: stored
            .unused_suppressions
            .iter()
            .map(|rule| UnusedRule {
                scope: rule.scope.clone(),
                pattern: rule.pattern.clone(),
                matched: 0,
            })
            .chain(clone_ids_covering_several_groups(groups))
            .collect(),
        unapplied_suppression_policies: unapplied_suppression_policies(analysis_mode),
        funnel,
        split_components: stored.split_components,
        common_signatures_skipped: stored.common_signatures_skipped,
        largest_skipped_signature_units: stored.largest_skipped_signature_units,
        pair_budget_exhausted: stored.pair_budget_exhausted,
        search_truncated,
        identity_collapsed: stored_identity_collapsed(&stored.funnel),
    }
}

/// Configured suppression policies that a given analysis mode cannot apply.
///
/// This is derived from the mode rather than stored in the summary row: the
/// limitation is a property of the frontend, and a replay must present the
/// same limitation as the original report.
#[must_use]
pub fn unapplied_suppression_policies(analysis_mode: &str) -> Vec<String> {
    if analysis_mode == "fast" {
        [
            "suppression.boilerplate",
            "suppression.test-code",
            "suppression.width-family",
        ]
        .into_iter()
        .map(str::to_string)
        .collect()
    } else {
        Vec::new()
    }
}

/// Measurements unavailable in one analysis mode.
///
/// This is derived from the mode rather than stored in the summary row so a
/// replay carries the same contract as the source run. Fast intentionally
/// leaves all four Structural supplemental measures out.
#[must_use]
pub fn unmeasured_in_this_mode(analysis_mode: &str) -> Vec<String> {
    if analysis_mode == "fast" {
        [
            "identifier agreement",
            "similarity breakdown",
            "siblings",
            "near misses",
        ]
        .into_iter()
        .map(str::to_string)
        .collect()
    } else {
        Vec::new()
    }
}

/// One configured suppression rule a report has to name.
///
/// Either the rule matched nothing, or — for a clone id, whose whole purpose
/// is to name one duplication — its prefix currently covers several groups.
/// Both are a rule doing something other than what it says.
#[derive(Debug, Serialize)]
pub struct UnusedRule {
    /// Rule scope (`path_glob`, `symbol_pattern`, `stable_clone_id`).
    pub scope: String,
    /// The pattern as configured.
    pub pattern: String,
    /// How many groups the rule covers: `0` for a rule that hid nothing, and
    /// the number of groups for a clone id whose prefix covers more than one.
    pub matched: u64,
}

impl UnusedRule {
    /// One-line rendering for the text views, matching how a rule that *did*
    /// match is named.
    #[must_use]
    pub fn label(&self) -> String {
        match self.scope.as_str() {
            "path_glob" => format!("path glob {:?}", self.pattern),
            "symbol_pattern" => format!("symbol glob {:?}", self.pattern),
            CLONE_ID_SCOPE => format!("clone id {}", self.pattern),
            scope => format!("{scope} {:?}", self.pattern),
        }
    }
}

/// How the run composed its ranking.
///
/// A run-level setting rather than a per-group one, and reported because two
/// reports ordered under different weights are different orderings of the same
/// findings, which nothing else in the document would say.
#[derive(Debug, Clone, Serialize)]
pub struct RankingInfo {
    /// Version of the ranking rules together with the weights applied.
    pub recipe: String,
    /// Weight given to what keeping the copies in step costs.
    pub maintenance_risk: u32,
    /// Weight given to how cheap the duplication would be to remove.
    pub refactoring_ease: u32,
}

impl Priority {
    /// The value a group carries between being built and being ranked.
    ///
    /// No report holds one: every group is handed straight to [`ranked`], which
    /// is also what the ranking has to read the group to do. Zero throughout,
    /// so a group that somehow escaped ranking sorts last rather than first.
    #[must_use]
    pub const fn unranked() -> Self {
        Self {
            value: 0.0,
            clone_confidence: 0.0,
            maintenance_risk: 0.0,
            refactoring_difficulty: 0.0,
            semantic_confidence: None,
            source_artifact_confidence: None,
            savings_confidence: None,
            inputs: PriorityInputs {
                smallest_member_tokens: 0,
                largest_member_tokens: 0,
                instances: 0,
                similarity: 0.0,
                files: 0,
                directories: 0,
                languages: 0,
                min_clone_tokens: 0,
                identifier_jaccard: None,
                api_similarity: None,
                has_loop: None,
                has_dynamic_allocation: None,
                call_count: None,
                churn: None,
                ownership_spread: None,
            },
        }
    }
}

impl Group {
    /// What the ranking reads about this group.
    ///
    /// Taken from the assembled report entry rather than from each mode's own
    /// data structures, so that Fast and Structural cannot rank the same facts
    /// differently, and so that anyone holding the JSON report can reproduce
    /// the ranking from it.
    ///
    /// `min_clone_tokens` is the run's length floor, which is a setting rather
    /// than a property of the group and so is not carried on it.
    fn facts(&self, min_clone_tokens: u64) -> GroupFacts {
        let tokens = || self.members.iter().map(|member| member.tokens);
        let distinct = |values: Vec<&str>| {
            let mut seen: Vec<&str> = values;
            seen.sort_unstable();
            seen.dedup();
            u64::try_from(seen.len()).unwrap_or(u64::MAX)
        };
        GroupFacts {
            clone_type: CloneClass::from_name(&self.clone_type).unwrap_or(CloneClass::Type3),
            scope: CloneScope::from_name(&self.scope).unwrap_or(CloneScope::Unit),
            instances: u64::try_from(self.members.len()).unwrap_or(u64::MAX),
            smallest_member_tokens: tokens().min().unwrap_or(0),
            largest_member_tokens: tokens().max().unwrap_or(0),
            min_pairwise: self.confidence,
            files: distinct(
                self.members
                    .iter()
                    .map(|member| member.file.as_str())
                    .collect(),
            ),
            directories: distinct(
                self.members
                    .iter()
                    .map(|member| directory_of(&member.file))
                    .collect(),
            ),
            languages: distinct(
                self.members
                    .iter()
                    .map(|member| member.language.as_str())
                    .collect(),
            ),
            min_clone_tokens,
            identifier_jaccard: self.identifier_jaccard,
            api_similarity: self
                .similarity
                .as_ref()
                .and_then(|similarity| similarity.api),
            has_loop: self.body_materiality.map(|body| body.has_loop),
            has_dynamic_allocation: self
                .body_materiality
                .map(|body| body.has_dynamic_allocation),
            call_count: self.body_materiality.map(|body| body.call_count),
            churn: None,
            ownership_spread: None,
        }
    }
}

/// Rank one assembled group.
///
/// Every construction site hands its group through here, which is what keeps
/// one ranking rule over both analysis modes and all four kinds of entry.
#[must_use]
pub fn ranked(mut group: Group, weights: &Weights, min_clone_tokens: u64) -> Group {
    let facts = group.facts(min_clone_tokens);
    let ranked = priority::rank(&facts, weights);
    group.priority = Priority {
        value: ranked.final_priority,
        clone_confidence: ranked.clone_confidence,
        maintenance_risk: ranked.maintenance_risk,
        refactoring_difficulty: ranked.refactoring_difficulty,
        semantic_confidence: ranked.semantic_confidence,
        source_artifact_confidence: ranked.source_artifact_confidence,
        savings_confidence: ranked.savings_confidence,
        inputs: PriorityInputs {
            smallest_member_tokens: facts.smallest_member_tokens,
            largest_member_tokens: facts.largest_member_tokens,
            instances: facts.instances,
            similarity: facts.min_pairwise,
            files: facts.files,
            directories: facts.directories,
            languages: facts.languages,
            min_clone_tokens: facts.min_clone_tokens,
            identifier_jaccard: facts.identifier_jaccard,
            api_similarity: facts.api_similarity,
            has_loop: facts.has_loop,
            has_dynamic_allocation: facts.has_dynamic_allocation,
            call_count: facts.call_count,
            churn: facts.churn,
            ownership_spread: facts.ownership_spread,
        },
    };
    group
}

/// Which mechanism suppressed a group.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SuppressionKind {
    /// The engine marked the group as noise.
    Noise,
    /// A configured or inline suppression rule matched every member.
    Rule,
}

/// Why a group is hidden from default reports.
#[derive(Debug, Clone, Serialize)]
pub struct Suppression {
    /// The suppressing mechanism.
    pub kind: SuppressionKind,
    /// Engine noise category or suppression-rule judgement, when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Suppression-rule scope, present when `kind` is rule.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// Suppression-rule pattern, present when `kind` is rule.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,
    /// Whether the stored rule was active, present when `kind` is rule.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active: Option<bool>,
}

impl Suppression {
    /// Human-readable label for the text views.
    #[must_use]
    pub fn label(&self) -> String {
        match self.kind {
            SuppressionKind::Noise => {
                format!("{} noise", self.reason.as_deref().unwrap_or("engine"))
            }
            SuppressionKind::Rule => {
                let pattern = self.pattern.as_deref().unwrap_or("");
                match self.scope.as_deref() {
                    Some("path_glob") => format!("path glob {pattern:?}"),
                    Some("symbol_pattern") => format!("symbol glob {pattern:?}"),
                    Some("stable_clone_id") => format!("clone id {pattern}"),
                    Some("inline_comment") => format!("{pattern} marker"),
                    Some("ast_pattern") => self.reason.as_deref().map_or_else(
                        || format!("structural shape: {pattern}"),
                        |reason| format!("{reason}: {pattern}"),
                    ),
                    Some("attribute") => format!("{pattern} attribute"),
                    Some(scope) => format!("{scope} {pattern:?}"),
                    None => "rule".to_string(),
                }
            }
        }
    }
}

impl Similarity {
    /// One-line rendering of the breakdown for the text views. An unavailable
    /// dimension prints as `n/a`, never as a number.
    #[must_use]
    pub fn line(&self) -> String {
        let type_similarity = self
            .type_similarity
            .map_or_else(|| "n/a".to_string(), |value| format!("{value:.2}"));
        let api = self
            .api
            .map_or_else(|| "n/a".to_string(), |value| format!("{value:.2}"));
        let control_flow = self
            .control_flow
            .map_or_else(|| "n/a".to_string(), |value| format!("{value:.2}"));
        let band = self.confidence_band.as_deref().unwrap_or("n/a");
        format!(
            "similarity: composite {:.2} (lexical {:.2}, structural {:.2}, \
             control-flow {control_flow}, type {type_similarity}, api {api}); \
             cohesion {:.2}; confidence {band} [{}]",
            self.composite, self.lexical, self.structural, self.min_pairwise, self.weight_version,
        )
    }
}

/// One occurrence of a group's content.
#[derive(Debug, Clone, Serialize)]
pub struct Member {
    /// Stable per-occurrence finding identifier, hex-encoded.
    pub finding_id: String,
    /// Content fingerprint of the matched slice, hex-encoded.
    ///
    /// What makes an exported report comparable with a later run: the finding
    /// id is derived from the group fingerprint and moves whenever the group's
    /// content does, so a diff keyed on it can only see identity, never
    /// history.
    pub content: String,
    /// File path relative to the scan root.
    pub file: String,
    /// Language the occurrence was read as (`rust`, `c`, `cpp`).
    ///
    /// Which grammar read a file decides what the analysis could see in it,
    /// and a bare `.h` header is read as whichever of C and C++ the tree is
    /// written in. Recorded per occurrence so that a group spanning two
    /// languages is visible as one.
    pub language: String,
    /// 1-based first line.
    pub start_line: u32,
    /// 1-based last line.
    pub end_line: u32,
    /// Name of the enclosing unit, when anchored to one.
    ///
    /// `None` denotes a top-level fragment such as a file-scope initializer;
    /// it never means that the reporter failed to resolve an available unit.
    pub unit: Option<String>,
    /// Boilerplate shape of the enclosing whole unit, when Structural mode
    /// classified it. A missing value for a fragment means it has no whole
    /// body to classify; for a unit, no conservative shape fit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub boilerplate: Option<String>,
    /// Size in tokens.
    pub tokens: u64,
    /// Whether this is the group's canonical instance.
    pub canonical: bool,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{
        CLONE_ID_SCOPE, Group, Priority, SummaryRow, Suppression, SuppressionKind, UnusedRule,
        restored,
    };
    use crate::report::{TextOptions, tests::sample_report};

    /// A group the clone id `rule` hid, whose own id starts with that rule.
    fn hidden_by_clone_id(fingerprint: &str, rule: &str) -> Group {
        Group {
            fingerprint: fingerprint.to_string(),
            clone_type: "type-1".to_string(),
            scope: "unit".to_string(),
            statements: None,
            confidence: 1.0,
            entropy_bits: 2.0,
            priority: Priority::unranked(),
            identity: None,
            similarity: None,
            identifier_jaccard: None,
            body_materiality: None,
            boilerplate: None,
            test_code: false,
            test_code_evidence: None,
            width_family: false,
            split_pair: false,
            ranked_down: false,
            suppressed: Some(Suppression {
                kind: SuppressionKind::Rule,
                reason: None,
                scope: Some(CLONE_ID_SCOPE.to_string()),
                pattern: Some(rule.to_string()),
                active: Some(true),
            }),
            baseline: None,
            semantic: None,
            artifact_savings: Vec::new(),
            members: Vec::new(),
        }
    }

    #[test]
    fn a_clone_id_hiding_more_than_the_group_it_names_is_reported_with_the_count() {
        // Two groups whose ids share the configured prefix: the id was written
        // about one duplication and now hides a second nobody judged.
        let groups = vec![
            hidden_by_clone_id(&format!("0123abcd{}", "11".repeat(12)), "0123abcd"),
            hidden_by_clone_id(&format!("0123abcd{}", "22".repeat(12)), "0123abcd"),
        ];

        let summary = restored(&SummaryRow::default(), &groups, "fast");
        let covering: Vec<&UnusedRule> = summary
            .unused_suppressions
            .iter()
            .filter(|rule| rule.matched > 1)
            .collect();
        assert_eq!(covering.len(), 1);
        assert_eq!(covering[0].scope, CLONE_ID_SCOPE);
        assert_eq!(covering[0].pattern, "0123abcd");
        assert_eq!(covering[0].matched, 2);

        // The machine surface carries the count beside the rule.
        let value = serde_json::to_value(&summary).unwrap();
        assert_eq!(value["unused_suppressions"][0]["matched"], 2);

        // And so does the text one, where a reader meets it.
        let mut report = sample_report();
        report.summary.unused_suppressions = summary.unused_suppressions;
        let mut buffer = Vec::new();
        report
            .render_notes(TextOptions::default(), &mut buffer)
            .unwrap();
        let text = String::from_utf8(buffer).unwrap();
        assert!(
            text.contains(
                "note: 1 suppression rule(s) hide more than the one group they name: \
                 clone id 0123abcd (2 groups)"
            ),
            "{text}"
        );
    }

    #[test]
    fn a_clone_id_that_still_names_one_group_is_left_alone() {
        let groups = vec![
            hidden_by_clone_id(&format!("0123abcd{}", "11".repeat(12)), "0123abcd"),
            hidden_by_clone_id(&format!("9999beef{}", "22".repeat(12)), "9999beef"),
        ];

        let summary = restored(&SummaryRow::default(), &groups, "fast");
        assert!(summary.unused_suppressions.is_empty());
    }
}
