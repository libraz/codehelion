//! Everything one structural or semantic partition's report and snapshot are
//! assembled from.

use std::collections::BTreeSet;
use std::path::Path;

use codehelion_core::discovery::BuildVariant;
use codehelion_core::engine::{self, LiteralNorm};
use codehelion_core::frontend::Token;
use codehelion_core::ir::SyntaxIrFile;
use codehelion_core::priority::Weights;
use codehelion_core::structural::{RegionOccurrence, StructuralReport, StructuralUnit};

use super::suppression::ReportableRegions;
use super::{SemanticDetection, SemanticGroup, SemanticPair, SourceMeta};
use crate::config;
use crate::report;
use crate::scan::shared;
use crate::semantic;
use crate::suppress;

/// Everything the report and the snapshot are assembled from.
pub(super) struct ReportInputs<'a> {
    pub(super) root: &'a Path,
    pub(super) db_path: &'a Path,
    /// The `--db` the commands this report prints have to repeat.
    pub(super) replay_database: Option<&'a str>,
    pub(super) configuration: &'a report::ConfigurationInfo,
    pub(super) started_at: &'a str,
    pub(super) finished_at: &'a str,
    pub(super) variant: &'a BuildVariant,
    pub(super) files: &'a [SourceMeta],
    pub(super) irs: &'a [SyntaxIrFile],
    pub(super) analysis: &'a StructuralReport,
    /// Cohesive registered-rule findings from complete-linkage refinement.
    pub(super) semantic_groups: &'a [SemanticGroup],
    /// Explainable restricted-semantic correspondences produced from compiler
    /// facts for this exact `BuildVariant`.
    pub(super) semantic_pairs: &'a [SemanticPair],
    /// Bounded-candidate accounting for the restricted-semantic branch.
    pub(super) semantic_detection: &'a SemanticDetection,
    /// Compiler answers whose IR schema versions qualify this run's detector
    /// set. `None` for Structural mode, which does not ask a helper.
    pub(super) compiler_answers: Option<&'a semantic::Answers>,
    pub(super) rules: &'a suppress::Rules,
    /// Selectors that matched scanned source, independently from the rule
    /// that ultimately hid each finding.
    pub(super) matched_rules: &'a BTreeSet<usize>,
    pub(super) group_suppressed: &'a [Option<usize>],
    /// The duplicated runs the report lists.
    pub(super) regions: &'a ReportableRegions,
    /// The rule hiding each listed run, parallel to [`Self::regions`].
    pub(super) region_suppressed: &'a [Option<usize>],
    /// What the report does with each classification a group can carry:
    /// boilerplate shape, test-suite residence, width family, and being a
    /// pair no group could hold.
    pub(super) suppression: &'a config::Suppression,
    /// The rule hiding each verified pair no group could hold, parallel to
    /// the analysis's own list of them.
    pub(super) pair_suppressed: &'a [Option<usize>],
    /// The rule hiding each restricted-semantic pair, parallel to
    /// [`Self::semantic_pairs`].
    pub(super) semantic_pair_suppressed: &'a [Option<usize>],
    /// The rule hiding each cohesive semantic group, parallel to
    /// [`Self::semantic_groups`].
    pub(super) semantic_group_suppressed: &'a [Option<usize>],
    /// Rules hiding supplemental siblings, parallel to the nested sibling lists.
    pub(super) sibling_suppressed: &'a [Vec<Option<usize>>],
    /// Rules hiding bounded near-match diagnostics.
    pub(super) near_miss_suppressed: &'a [Option<usize>],
    /// Lowest normalized content-entropy ratio before a finding is noise.
    pub(super) entropy_ratio_floor: f64,
    /// Literal strategy the group content is scored under.
    pub(super) literals: LiteralNorm,
    pub(super) glob_excluded: usize,
    pub(super) unreadable: u64,
    pub(super) timed_out: u64,
    /// How the run weighs the priority measures against one another.
    pub(super) weights: Weights,
    /// The run's minimum clone length, which the ranking reads sizes against.
    pub(super) min_clone_tokens: u64,
    /// The axis the run puts its entries in order on.
    pub(super) sort: report::Sort,
    pub(super) reuse_allowed: bool,
    pub(super) untrusted: bool,
    /// Whether the signature-based sibling detector ran for this snapshot.
    pub(super) siblings_by_signature: bool,
}

impl ReportInputs<'_> {
    pub(super) fn low_entropy(&self, entropy_bits: f64, token_count: usize) -> bool {
        engine::entropy_ratio(entropy_bits, token_count) < self.entropy_ratio_floor
    }

    pub(super) fn finding_suppression(
        &self,
        entropy_bits: f64,
        token_count: usize,
        rule: Option<usize>,
    ) -> Option<report::Suppression> {
        if self.low_entropy(entropy_bits, token_count) {
            Some(report::Suppression {
                kind: report::SuppressionKind::Noise,
                reason: Some("low-entropy".to_string()),
                scope: None,
                pattern: None,
                active: None,
            })
        } else {
            rule.map(|rule| self.suppression(rule))
        }
    }

    pub(super) fn entropy_suppress_reason(
        &self,
        entropy_bits: f64,
        token_count: usize,
    ) -> Option<String> {
        self.low_entropy(entropy_bits, token_count)
            .then(|| "low-entropy".to_string())
    }

    /// The tokens one analysed unit covers, in its own file.
    pub(super) fn unit_tokens(&self, unit: &StructuralUnit) -> &[Token] {
        codehelion_core::frontend::tokens_in_range(
            &self.irs[unit.file].tokens,
            unit.token_start,
            unit.token_end,
        )
    }

    /// The configured suppression rules whose selectors matched no scanned
    /// source or finding in this run.
    pub(super) fn unused_suppressions(&self) -> Vec<report::UnusedRule> {
        shared::unused_suppressions(
            self.rules,
            self.matched_rules.iter().copied().chain(
                self.group_suppressed
                    .iter()
                    .chain(self.region_suppressed)
                    .chain(self.pair_suppressed)
                    .chain(self.semantic_pair_suppressed)
                    .chain(self.semantic_group_suppressed)
                    .chain(self.sibling_suppressed.iter().flatten())
                    .chain(self.near_miss_suppressed)
                    .filter_map(|rule| *rule),
            ),
        )
    }

    /// The tokens one occurrence of a duplicated run covers, in its own file.
    pub(super) fn region_tokens(&self, occurrence: &RegionOccurrence) -> &[Token] {
        codehelion_core::frontend::tokens_in_range(
            &self.irs[occurrence.file].tokens,
            occurrence.token_start,
            occurrence.token_end,
        )
    }

    /// The suppression a report entry carries, from the index of the rule
    /// that hid it.
    pub(super) fn suppression(&self, rule: usize) -> report::Suppression {
        shared::rule_suppression(self.rules, rule)
    }
}
