//! Where a run's ceilings become the configuration a stage works under.
//!
//! [`Limits`] says what a run may spend. Every stage of the pipeline has its
//! own configuration struct with its own field for the ceiling it holds:
//! discovery reads no more than so many bytes, candidate generation fans out no
//! wider than so many postings, grouping refines no larger a component. This
//! module is the single place the first becomes the second.
//!
//! Written as one exhaustive destructuring on purpose. A ceiling that is added
//! to the profile and wired into some stages but not others is a ceiling a run
//! reports and does not hold, which is worse than not having it: the report
//! says the tree was read under a bound nobody applied. Adding a field to
//! [`Limits`] stops [`StageLimits::of`] compiling until the new ceiling has
//! been given a stage.
//!
//! A ceiling also names the stage that holds it ([`Ceiling::stage`]), and a
//! stage says which analysis modes reach it ([`Stage::runs_in`]), so a run can
//! present a ceiling as applied only where something applies it.

use std::time::Duration;

use crate::discovery::AnalysisMode;
use crate::engine::EngineConfig;
use crate::execution::Limits;
use crate::grouping::GroupingConfig;
use crate::semantic::SemanticCandidateConfig;

/// A stage of the pipeline: what holds a ceiling once a run is under way.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Stage {
    /// Finding and reading source files.
    Discovery,
    /// Narrowing the tree to candidate pairs.
    Pairing,
    /// Refining related units into cohesive groups.
    Grouping,
    /// Comparing a candidate pair precisely.
    Verification,
    /// The scanner process itself and any process it owns.
    Process,
    /// Asking a compiler helper about a source unit.
    Compiler,
}

impl Stage {
    /// Whether a run in `mode` reaches this stage.
    ///
    /// A mode that never reaches a stage cannot enforce that stage's ceilings,
    /// however the profile spells them.
    #[must_use]
    pub const fn runs_in(self, mode: AnalysisMode) -> bool {
        match self {
            // Every mode discovers files, pairs candidates, and runs in a
            // process whose memory a profile may bound.
            Self::Discovery | Self::Pairing | Self::Process => true,
            // Fast reports token-level clones: it neither refines components
            // nor aligns a pair precisely, so it holds neither ceiling.
            Self::Grouping | Self::Verification => {
                matches!(mode, AnalysisMode::Structural | AnalysisMode::Semantic)
            }
            // Only Semantic asks a compiler anything.
            Self::Compiler => matches!(mode, AnalysisMode::Semantic),
        }
    }
}

/// One ceiling a run states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Ceiling {
    /// Largest file read.
    FileBytes,
    /// Per-file parse work.
    ParseWork,
    /// Address space a process this run owns may take.
    ProcessMemory,
    /// Candidate pairs one pairing pass may produce.
    PairBudget,
    /// Longest posting list or bucket admitted to pairing.
    PostingCap,
    /// Largest related set refined as one group.
    Component,
    /// Pairs admitted to precise verification.
    VerificationBudget,
    /// Dynamic-programming cells one alignment may use.
    AlignmentCells,
    /// Longest a compiler helper may spend on one unit.
    HelperResponse,
}

/// Every ceiling, in a fixed order.
///
/// A list rather than a derivation, so that adding one is a decision made once
/// and then visible everywhere ceilings are enumerated.
pub const CEILINGS: [Ceiling; 9] = [
    Ceiling::FileBytes,
    Ceiling::ParseWork,
    Ceiling::ProcessMemory,
    Ceiling::PairBudget,
    Ceiling::PostingCap,
    Ceiling::Component,
    Ceiling::VerificationBudget,
    Ceiling::AlignmentCells,
    Ceiling::HelperResponse,
];

impl Ceiling {
    /// The name a configuration file and a report use for it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::FileBytes => "max-file-bytes",
            Self::ParseWork => "parse-timeout-ms",
            Self::ProcessMemory => "max-subprocess-bytes",
            Self::PairBudget => "pair-budget",
            Self::PostingCap => "posting-cap",
            Self::Component => "max-component",
            Self::VerificationBudget => "verification-budget",
            Self::AlignmentCells => "max-alignment-cells",
            Self::HelperResponse => "helper-timeout-ms",
        }
    }

    /// The stage that holds it.
    #[must_use]
    pub const fn stage(self) -> Stage {
        match self {
            Self::FileBytes | Self::ParseWork => Stage::Discovery,
            Self::ProcessMemory => Stage::Process,
            Self::PairBudget | Self::PostingCap => Stage::Pairing,
            Self::Component => Stage::Grouping,
            Self::VerificationBudget | Self::AlignmentCells => Stage::Verification,
            Self::HelperResponse => Stage::Compiler,
        }
    }

    /// Whether a run in `mode` reaches the stage that holds it.
    #[must_use]
    pub const fn enforced_in(self, mode: AnalysisMode) -> bool {
        self.stage().runs_in(mode)
    }
}

/// What one ceiling is set to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CeilingValue {
    /// A byte count.
    Bytes(u64),
    /// A count of items.
    Count(usize),
    /// A span of time.
    Time(Duration),
}

/// What discovery may read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiscoveryLimits {
    /// Largest file read; a larger one is skipped and counted.
    pub max_file_bytes: u64,
    /// Per-file parse-work budget.
    pub parse_timeout: Duration,
}

/// How far candidate generation may fan out.
///
/// `None` leaves a stage at the default measured for it, which is not the same
/// number for every stage: the fast token index, the structural posting lists
/// and the registered-rule bucket index each admit a different width before
/// the work stops being worth it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PairingLimits {
    /// Longest posting list or bucket admitted to pairing.
    pub posting_cap: Option<usize>,
    /// Largest number of candidate pairs one pass may produce.
    pub pair_budget: Option<usize>,
}

/// How large a related set may be refined as one group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GroupingLimits {
    /// Largest component refined as one piece.
    pub max_component: usize,
}

/// What precise verification may spend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerificationLimits {
    /// Pairs admitted to precise verification, or `None` for the stage default.
    pub verification_budget: Option<usize>,
    /// Cells one alignment may use, or `None` for the stage default.
    pub max_alignment_cells: Option<usize>,
}

/// What a process this run owns may spend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessLimits {
    /// Largest address space a process this run owns may take, where the
    /// operating system can hold it to one. `None` states no ceiling.
    pub max_memory_bytes: Option<u64>,
    /// Longest a compiler helper may spend on one unit.
    pub helper_timeout: Duration,
}

/// The ceilings each stage of one run works under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StageLimits {
    /// Finding and reading files.
    pub discovery: DiscoveryLimits,
    /// Narrowing to candidate pairs.
    pub pairing: PairingLimits,
    /// Refining related units into groups.
    pub grouping: GroupingLimits,
    /// Comparing a pair precisely.
    pub verification: VerificationLimits,
    /// The processes this run owns.
    pub process: ProcessLimits,
}

impl StageLimits {
    /// The stages of a run working under `limits`.
    ///
    /// A profile states every ceiling it has, so each stage takes the profile's
    /// number rather than its own default.
    #[must_use]
    pub const fn of(limits: &Limits) -> Self {
        // Exhaustively destructured on purpose: a ceiling added to the profile
        // stops this compiling until it has been given a stage below.
        let Limits {
            max_file_bytes,
            parse_timeout,
            max_subprocess_bytes,
            max_candidates,
            posting_cap,
            max_component,
            verification_budget,
            max_alignment_cells,
            helper_timeout,
            // What may run is not a ceiling. It is answered by the policy
            // itself wherever execution is considered, not by a stage's
            // configuration.
            execution: _,
        } = limits;
        Self {
            discovery: DiscoveryLimits {
                max_file_bytes: *max_file_bytes,
                parse_timeout: *parse_timeout,
            },
            pairing: PairingLimits {
                posting_cap: Some(*posting_cap),
                pair_budget: Some(*max_candidates),
            },
            grouping: GroupingLimits {
                max_component: *max_component,
            },
            verification: VerificationLimits {
                verification_budget: Some(*verification_budget),
                max_alignment_cells: Some(*max_alignment_cells),
            },
            process: ProcessLimits {
                max_memory_bytes: *max_subprocess_bytes,
                helper_timeout: *helper_timeout,
            },
        }
    }

    /// What these stages hold `ceiling` to, or `None` when it is left to the
    /// stage's own default.
    #[must_use]
    pub const fn value(&self, ceiling: Ceiling) -> Option<CeilingValue> {
        match ceiling {
            Ceiling::FileBytes => Some(CeilingValue::Bytes(self.discovery.max_file_bytes)),
            Ceiling::ParseWork => Some(CeilingValue::Time(self.discovery.parse_timeout)),
            Ceiling::ProcessMemory => match self.process.max_memory_bytes {
                Some(bytes) => Some(CeilingValue::Bytes(bytes)),
                None => None,
            },
            Ceiling::PairBudget => counted(self.pairing.pair_budget),
            Ceiling::PostingCap => counted(self.pairing.posting_cap),
            Ceiling::Component => Some(CeilingValue::Count(self.grouping.max_component)),
            Ceiling::VerificationBudget => counted(self.verification.verification_budget),
            Ceiling::AlignmentCells => counted(self.verification.max_alignment_cells),
            Ceiling::HelperResponse => Some(CeilingValue::Time(self.process.helper_timeout)),
        }
    }
}

/// A stated count as a ceiling value.
const fn counted(count: Option<usize>) -> Option<CeilingValue> {
    match count {
        Some(count) => Some(CeilingValue::Count(count)),
        None => None,
    }
}

impl PairingLimits {
    /// The registered-rule semantic candidate index under these ceilings.
    ///
    /// The bucket width is the posting ceiling: a bucket is the semantic
    /// index's posting list, and a run that reports a posting ceiling has to
    /// cut buckets at it like every other pairing path.
    #[must_use]
    pub fn semantic_candidates(&self) -> SemanticCandidateConfig {
        let defaults = SemanticCandidateConfig::default();
        SemanticCandidateConfig {
            max_bucket_members: self.posting_cap.unwrap_or(defaults.max_bucket_members),
            max_candidate_pairs: self.pair_budget.unwrap_or(defaults.max_candidate_pairs),
        }
    }

    /// Apply these ceilings to the fast engine's candidate stages.
    pub const fn apply_to_engine(&self, engine: &mut EngineConfig) {
        if let Some(cap) = self.posting_cap {
            engine.posting_cap = cap;
        }
        if let Some(budget) = self.pair_budget {
            engine.pair_budget = budget;
        }
    }
}

impl GroupingLimits {
    /// Grouping under these ceilings.
    #[must_use]
    pub fn grouping(&self) -> GroupingConfig {
        GroupingConfig {
            max_component: self.max_component,
            ..GroupingConfig::default()
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{CEILINGS, Ceiling, CeilingValue, Stage, StageLimits};
    use crate::discovery::AnalysisMode;
    use crate::execution::Limits;

    const MODES: [AnalysisMode; 3] = [
        AnalysisMode::Fast,
        AnalysisMode::Structural,
        AnalysisMode::Semantic,
    ];

    /// The mapping is only worth having if every ceiling arrives with the
    /// number the profile states. One left behind is a ceiling a report can
    /// name and no stage holds.
    #[test]
    fn every_stated_ceiling_reaches_a_stage_with_the_profile_number() {
        let profile = Limits::untrusted();
        let stages = StageLimits::of(&profile);
        assert_eq!(
            stages.value(Ceiling::FileBytes),
            Some(CeilingValue::Bytes(profile.max_file_bytes))
        );
        assert_eq!(
            stages.value(Ceiling::ParseWork),
            Some(CeilingValue::Time(profile.parse_timeout))
        );
        assert_eq!(
            stages.value(Ceiling::ProcessMemory),
            profile.max_subprocess_bytes.map(CeilingValue::Bytes)
        );
        assert_eq!(
            stages.value(Ceiling::PairBudget),
            Some(CeilingValue::Count(profile.max_candidates))
        );
        assert_eq!(
            stages.value(Ceiling::PostingCap),
            Some(CeilingValue::Count(profile.posting_cap))
        );
        assert_eq!(
            stages.value(Ceiling::Component),
            Some(CeilingValue::Count(profile.max_component))
        );
        assert_eq!(
            stages.value(Ceiling::VerificationBudget),
            Some(CeilingValue::Count(profile.verification_budget))
        );
        assert_eq!(
            stages.value(Ceiling::AlignmentCells),
            Some(CeilingValue::Count(profile.max_alignment_cells))
        );
        assert_eq!(
            stages.value(Ceiling::HelperResponse),
            Some(CeilingValue::Time(profile.helper_timeout))
        );
    }

    /// The registered-rule bucket index is a pairing path, so it takes the
    /// stated posting ceiling rather than the width it measured for itself.
    #[test]
    fn the_semantic_candidate_index_takes_the_stated_posting_ceiling() {
        let profile = Limits::untrusted();
        let candidates = StageLimits::of(&profile).pairing.semantic_candidates();
        assert_eq!(candidates.max_bucket_members, profile.posting_cap);
        assert_eq!(candidates.max_candidate_pairs, profile.max_candidates);
    }

    /// Refinement is quadratic in the size of the piece it refines, so the
    /// stated component ceiling has to be the one grouping works under.
    #[test]
    fn grouping_takes_the_stated_component_ceiling() {
        let profile = Limits::untrusted();
        let grouping = StageLimits::of(&profile).grouping.grouping();
        assert_eq!(grouping.max_component, profile.max_component);
    }

    /// A stage nothing runs cannot hold a ceiling, and saying otherwise is how
    /// a report comes to present a bound that was never applied.
    #[test]
    fn a_ceiling_is_enforced_only_where_its_stage_runs() {
        assert!(Ceiling::PostingCap.enforced_in(AnalysisMode::Fast));
        assert!(Ceiling::FileBytes.enforced_in(AnalysisMode::Fast));
        assert!(Ceiling::ProcessMemory.enforced_in(AnalysisMode::Fast));
        assert!(!Ceiling::Component.enforced_in(AnalysisMode::Fast));
        assert!(!Ceiling::VerificationBudget.enforced_in(AnalysisMode::Fast));
        assert!(!Ceiling::HelperResponse.enforced_in(AnalysisMode::Fast));
        assert!(Ceiling::Component.enforced_in(AnalysisMode::Structural));
        assert!(!Ceiling::HelperResponse.enforced_in(AnalysisMode::Structural));
        assert!(Ceiling::HelperResponse.enforced_in(AnalysisMode::Semantic));
        for mode in MODES {
            assert!(Stage::Discovery.runs_in(mode), "{mode:?}");
            assert!(Stage::Pairing.runs_in(mode), "{mode:?}");
            assert!(Stage::Process.runs_in(mode), "{mode:?}");
        }
    }

    #[test]
    fn every_ceiling_has_a_distinct_name_and_a_stage() {
        let mut names: Vec<&str> = CEILINGS.iter().map(|ceiling| ceiling.name()).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), CEILINGS.len());
        for ceiling in CEILINGS {
            assert!(
                MODES.iter().any(|mode| ceiling.enforced_in(*mode)),
                "{ceiling:?}"
            );
        }
    }
}
