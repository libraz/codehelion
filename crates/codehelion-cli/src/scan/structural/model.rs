//! The values the structural and semantic pipelines carry between stages.

use std::collections::BTreeSet;

use codehelion_core::discovery::{ContentHash, Language};
use codehelion_core::frontend::Token;
use codehelion_core::ir::{ByteRange, SyntaxIrFile};
use codehelion_core::semantic::{
    SemanticCandidateStats, SemanticGroupingStats, SemanticOperationGraph, SemanticRule,
};
use codehelion_core::stable_id;
use codehelion_store::snapshot::StagedSnapshotPart;

use crate::Outcome;
use crate::report::Report;

/// The reporting metadata of one parsed source file.
pub(super) struct SourceMeta {
    pub(super) relative_path: String,
    /// Repository-relative parent key used only to build opaque core
    /// directory partitions for signature siblings.
    pub(super) directory_key: String,
    pub(super) language: Language,
    /// 1-based lines carrying an inline suppression marker.
    pub(super) marker_lines: Vec<u32>,
    /// Source lines in the file.
    pub(super) lines: u64,
    pub(super) diagnostics: usize,
    /// Tokens the parser could not attach to any structure.
    pub(super) unaccounted_tokens: u64,
    /// Whether parsing stopped at the structural depth ceiling.
    pub(super) depth_truncated: bool,
}

/// One parsed source file: its Syntax IR plus the metadata that travels with
/// it. The two are split apart before analysis, which consumes the IR files
/// as one slice.
pub(super) struct ParsedSource {
    pub(super) meta: SourceMeta,
    pub(super) ir: SyntaxIrFile,
}

/// One normalized SOG anchored to the syntactic unit it describes.
#[derive(Debug, Clone)]
pub(super) struct SemanticUnitGraph {
    pub(super) unit: usize,
    /// Deterministic rank of this window among the semantic windows hosted by
    /// the same stable source unit. It distinguishes identical occurrences
    /// without making a source position part of a stable identifier.
    pub(super) occurrence_rank: u32,
    /// Exact source bytes for this semantic window, used only for reporting.
    pub(super) range: ByteRange,
    /// First source line covered by this semantic window.
    pub(super) start_line: u32,
    /// Last source line covered by this semantic window.
    pub(super) end_line: u32,
    /// Parsed tokens covered by this semantic window.
    pub(super) token_count: usize,
    pub(super) graph: SemanticOperationGraph,
    pub(super) content: stable_id::FragmentFingerprint,
    /// How completely the closed API registry described this parser-owned
    /// unit. This may lower semantic confidence but never invents or removes
    /// a registered-rule match.
    pub(super) normalization_confidence: f64,
    /// Closed interactions observed inside this exact SOG window. An empty
    /// set is unknown evidence, never a purity claim.
    pub(super) interactions: BTreeSet<String>,
    /// Compiler-confirmed direct `filter`/`map` receiver flows in this exact
    /// window. Missing evidence is neutral rather than a claim that no flow
    /// exists.
    pub(super) data_flows: BTreeSet<(String, String)>,
    /// Compiler-produced CFG shape that overlaps this exact window. It is
    /// supplementary confidence evidence only; absence never removes a match.
    pub(super) cfg_shape: Option<CfgShape>,
}

/// A deliberately small, language-neutral summary of the CFG that covers one
/// semantic window.
///
/// The summary counts blocks and interior edge kinds rather than preserving
/// compiler-local block indices. It cannot establish semantic equivalence; it
/// only corroborates or weakens a match the closed SOG rule already verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct CfgShape {
    pub(super) blocks: u32,
    pub(super) flow_edges: u32,
    pub(super) taken_edges: u32,
    pub(super) not_taken_edges: u32,
    pub(super) unwind_edges: u32,
    pub(super) return_edges: u32,
}

/// Non-authoritative compiler evidence that can adjust one SOG match's
/// confidence without changing whether the registered rule matched.
#[derive(Clone, Copy)]
pub(super) struct SemanticConfidenceEvidence<'a> {
    pub(super) normalization: f64,
    pub(super) interactions: &'a BTreeSet<String>,
    pub(super) data_flows: &'a BTreeSet<(String, String)>,
    pub(super) cfg_shape: Option<CfgShape>,
}

impl SemanticUnitGraph {
    pub(super) const fn confidence_evidence(&self) -> SemanticConfidenceEvidence<'_> {
        SemanticConfidenceEvidence {
            normalization: self.normalization_confidence,
            interactions: &self.interactions,
            data_flows: &self.data_flows,
            cfg_shape: self.cfg_shape,
        }
    }
}

/// One registered semantic correspondence between two whole units that no
/// cohesive semantic group jointly represents.
#[derive(Debug, Clone)]
pub(super) struct SemanticPair {
    pub(super) canonical: SemanticUnitGraph,
    pub(super) corresponding: SemanticUnitGraph,
    pub(super) rule: SemanticRule,
    /// Rule confidence after the two normalizations' coverage is considered.
    pub(super) semantic_confidence: f64,
}

/// A cohesive registered-rule correspondence group, with a medoid chosen by
/// the core-owned complete-linkage adapter.
#[derive(Debug, Clone)]
pub(super) struct SemanticGroup {
    pub(super) canonical: SemanticUnitGraph,
    /// The canonical member is first; every other member has a separately
    /// verified correspondence to every member in this group.
    pub(super) members: Vec<SemanticUnitGraph>,
    pub(super) rule: SemanticRule,
    pub(super) semantic_confidence: f64,
}

/// Bounded registered-semantic matching plus the accounting that makes every
/// omitted candidate visible in the scan funnel.
#[derive(Debug, Clone)]
pub(super) struct SemanticDetection {
    pub(super) groups: Vec<SemanticGroup>,
    pub(super) pairs: Vec<SemanticPair>,
    /// Every normalized graph retained for an explicit cross-language
    /// comparison. Ordinary partition reports never inspect this collection.
    pub(super) units: Vec<SemanticUnitGraph>,
    pub(super) candidates: SemanticCandidateStats,
    /// Compiler-resolved API observations accepted by the closed registry.
    pub(super) registered_observations: usize,
    /// Compiler-resolved API observations that the closed registry declined
    /// to normalize. They remain visible in the funnel but never become a
    /// semantic finding by approximation.
    pub(super) excluded_observations: usize,
    /// Parser-owned units in which normalization found no registered
    /// operation at all: the closed registry recognized nothing the compiler
    /// resolved there.
    pub(super) units_without_registered_operations: usize,
    /// Parser-owned units that did hold registered operations, none of which
    /// any registered rule claimed. Kept apart from
    /// [`Self::units_without_registered_operations`] because the two send a
    /// reader investigating a thin run to different places: one is a gap in
    /// what the helper was asked, the other a gap in the rules.
    pub(super) units_no_registered_rule_claimed: usize,
    pub(super) verified_pairs: usize,
    pub(super) disabled_pairs: usize,
    pub(super) grouping: SemanticGroupingStats,
}

/// One owned unit retained solely until an opt-in cross-variant comparison is
/// recorded. Normal partition reports never hold or consume these values.
pub(super) struct CrossComparisonUnit {
    pub(super) origin_variant: String,
    pub(super) language: Language,
    pub(super) file_path: String,
    pub(super) start_line: u32,
    pub(super) end_line: u32,
    pub(super) name: Option<String>,
    pub(super) tokens: Vec<Token>,
}

/// One owned semantic unit retained solely for an opt-in Rust-to-C++ comparison.
pub(super) struct CrossLanguageComparisonUnit {
    pub(super) origin_variant: String,
    pub(super) language: Language,
    pub(super) file_path: String,
    pub(super) start_line: u32,
    pub(super) end_line: u32,
    pub(super) name: Option<String>,
    pub(super) graph: SemanticOperationGraph,
    pub(super) occurrence: stable_id::FragmentFingerprint,
    pub(super) normalization_confidence: f64,
    pub(super) interactions: BTreeSet<String>,
    pub(super) data_flows: BTreeSet<(String, String)>,
    pub(super) cfg_shape: Option<CfgShape>,
}

impl CrossLanguageComparisonUnit {
    pub(super) const fn confidence_evidence(&self) -> SemanticConfidenceEvidence<'_> {
        SemanticConfidenceEvidence {
            normalization: self.normalization_confidence,
            interactions: &self.interactions,
            data_flows: &self.data_flows,
            cfg_shape: self.cfg_shape,
        }
    }
}

/// The ordinary report plus source units available to an opt-in comparison.
pub(super) struct PartitionOutcome {
    pub(super) outcome: Outcome,
    pub(super) report: Report,
    pub(super) comparison_units: Vec<CrossComparisonUnit>,
    pub(super) cross_language_units: Vec<CrossLanguageComparisonUnit>,
    /// Persistence errors are returned with the already-built report so the
    /// caller can still publish an unrecorded result.
    pub(super) recording_error: Option<anyhow::Error>,
    pub(super) staged: Option<StagedSnapshotPart>,
    /// The key the staged part was recorded under, read back by a later reuse
    /// decision instead of rebuilt from a second copy of the recipe.
    pub(super) reuse_key: Option<ContentHash>,
}
