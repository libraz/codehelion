//! Bounded post-grouping search for incomplete local mirrors.
//!
//! Primary grouping is complete before this module runs. A sibling can only
//! be an ungrouped unit in a file that already hosts a member of an
//! established group, and it is compared only to that group's medoid. The
//! sweep never emits a primary edge and never edits a group, so it cannot turn
//! a local incomplete copy into transitive group membership.

use std::collections::{BTreeMap, BTreeSet};

use super::{
    FileFeatures, GroupSiblings, GroupingSet, SiblingConfig, SiblingSweepStats, StructuralSibling,
    SyntaxIrFile, Unit, UnitEvidence, VerifyConfig, verify, view,
};
use crate::clone_class::CloneClass;
use crate::verify::Confidence;

/// Sweep ungrouped units beside established groups for incomplete mirrors.
#[allow(
    clippy::too_many_lines,
    reason = "the bounded sweep keeps its ordered caps and accounting together for auditability"
)]
pub(super) fn sweep_siblings(
    groups: &GroupingSet,
    units: &[Unit],
    files: &[SyntaxIrFile],
    feature_files: &[FileFeatures],
    evidence: &UnitEvidence,
    verify_config: &VerifyConfig,
    config: &SiblingConfig,
) -> (Vec<GroupSiblings>, SiblingSweepStats) {
    let mut stats = SiblingSweepStats::default();
    let grouped: BTreeSet<usize> = groups
        .groups
        .iter()
        .flat_map(|group| group.members.iter().copied())
        .collect();
    let mut ungrouped_by_file: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for (index, unit) in units.iter().enumerate() {
        if !grouped.contains(&index) {
            ungrouped_by_file.entry(unit.file).or_default().push(index);
        }
    }
    for candidates in ungrouped_by_file.values_mut() {
        candidates.sort_by(|left, right| {
            units[*left]
                .fingerprint
                .cmp(&units[*right].fingerprint)
                .then(left.cmp(right))
        });
    }

    // Form the file-scoped work lists before spending the budget. This makes
    // every dropped count exact while comparison work itself remains bounded.
    let candidate_lists: Vec<Vec<usize>> = groups
        .groups
        .iter()
        .map(|group| {
            let files: BTreeSet<usize> = group
                .members
                .iter()
                .map(|&member| units[member].file)
                .collect();
            files
                .into_iter()
                .flat_map(|file| ungrouped_by_file.get(&file).into_iter().flatten().copied())
                .collect()
        })
        .collect();
    stats.groups_considered = groups.groups.len();
    stats.eligible_candidates = candidate_lists.iter().map(Vec::len).sum();

    let relaxed_threshold = (verify_config.type3_min_composite
        - config
            .similarity_delta
            .clamp(0.0, verify_config.type3_min_composite))
    .max(0.0);
    let mut accepted = 0usize;
    let mut out = Vec::new();
    'groups: for (group_index, (group, group_candidates)) in
        groups.groups.iter().zip(&candidate_lists).enumerate()
    {
        let mut siblings = Vec::new();
        for (position, &unit) in group_candidates.iter().enumerate() {
            if accepted >= config.total_cap {
                stats.total_cap_dropped = stats.total_cap_dropped.saturating_add(
                    group_candidates.len().saturating_sub(position)
                        + candidate_lists[group_index + 1..]
                            .iter()
                            .map(Vec::len)
                            .sum::<usize>(),
                );
                break 'groups;
            }
            if siblings.len() >= config.per_group_cap {
                stats.per_group_cap_dropped = stats
                    .per_group_cap_dropped
                    .saturating_add(group_candidates.len().saturating_sub(position));
                break;
            }
            if stats.candidates_examined >= config.candidate_budget {
                break 'groups;
            }
            let canonical = view(group.canonical, units, files, feature_files, evidence);
            let sibling = view(unit, units, files, feature_files, evidence);
            let verdict = verify::verify(&canonical, &sibling, verify_config);
            stats.candidates_examined += 1;
            if verdict.breakdown.composite < relaxed_threshold {
                continue;
            }
            let (clone_type, confidence) = match (verdict.class, verdict.confidence) {
                (Some(class), Some(confidence)) => (class, confidence),
                _ => (CloneClass::Type3, Confidence::Low),
            };
            siblings.push(StructuralSibling {
                unit,
                clone_type,
                confidence,
                breakdown: verdict.breakdown,
            });
            accepted += 1;
            stats.accepted += 1;
        }
        if !siblings.is_empty() {
            out.push(GroupSiblings {
                group: group_index,
                siblings,
            });
        }
    }
    stats.candidate_budget_dropped = stats
        .eligible_candidates
        .saturating_sub(stats.candidates_examined)
        .saturating_sub(stats.per_group_cap_dropped)
        .saturating_sub(stats.total_cap_dropped);
    (out, stats)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::{BuildVariant, Language, LanguageSelection};
    use crate::features;
    use crate::frontend::{SourceSpan, Token, TokenKind};
    use crate::grouping::{self, GroupingConfig, GroupingUnit, SimilarityEdge};
    use crate::ir::{ByteRange, IR_SCHEMA_VERSION, IrNode, Shape};
    use crate::structural::{ResolvedTypes, flatten_units, unit_evidence};

    fn variant() -> BuildVariant {
        BuildVariant::structural(
            LanguageSelection {
                rust: true,
                c: false,
                cpp: false,
            },
            Language::Rust,
        )
    }

    fn file(names: &[&str]) -> SyntaxIrFile {
        let tokens = names
            .iter()
            .enumerate()
            .map(|(index, name)| Token {
                kind: TokenKind::Identifier,
                text: (*name).into(),
                span: SourceSpan {
                    start_byte: index,
                    end_byte: index + 1,
                    start_line: 1,
                    start_column: u32::try_from(index + 1).unwrap_or(u32::MAX),
                },
            })
            .collect();
        let roots = names
            .iter()
            .enumerate()
            .map(|(index, name)| {
                let range = ByteRange {
                    start: index,
                    end: index + 1,
                };
                IrNode {
                    shape: Shape::Function,
                    name: Some((*name).into()),
                    token_start: index,
                    token_end: index + 1,
                    range,
                    children: vec![IrNode {
                        shape: Shape::Block,
                        name: None,
                        token_start: index,
                        token_end: index + 1,
                        range,
                        children: vec![IrNode {
                            shape: Shape::Return,
                            name: None,
                            token_start: index,
                            token_end: index + 1,
                            range,
                            children: Vec::new(),
                        }],
                    }],
                }
            })
            .collect();
        SyntaxIrFile {
            language: Language::Rust,
            frontend_version: "test",
            ir_schema_version: IR_SCHEMA_VERSION,
            tokens,
            roots,
            diagnostics: Vec::new(),
            error_ranges: Vec::new(),
            depth_truncated: false,
            test_module: false,
        }
    }

    fn inputs() -> (
        Vec<Unit>,
        Vec<SyntaxIrFile>,
        Vec<FileFeatures>,
        UnitEvidence,
        GroupingSet,
    ) {
        // File 0 has a primary member and three ungrouped local candidates.
        // File 1 supplies the other primary member; file 2 is deliberately
        // outside the group's host files and must never enter the sweep.
        let files = vec![
            file(&["anchor", "zeta", "alpha", "middle"]),
            file(&["peer"]),
            file(&["outside"]),
        ];
        let feature_files = files.iter().map(features::extract).collect();
        let (units, _) = flatten_units(&files, &variant());
        let evidence = unit_evidence(&units, &ResolvedTypes::default());
        let grouping_units = units
            .iter()
            .map(|unit| GroupingUnit {
                key: *unit.fingerprint.as_bytes(),
            })
            .collect::<Vec<_>>();
        let groups = grouping::group(
            &grouping_units,
            &[SimilarityEdge {
                a: 0,
                b: 4,
                similarity: 1.0,
                class: CloneClass::Type1,
                confidence: Confidence::High,
            }],
            &GroupingConfig::default(),
        );
        (units, files, feature_files, evidence, groups)
    }

    #[test]
    fn sweep_is_file_scoped_and_orders_siblings_by_fingerprint() {
        let (units, files, feature_files, evidence, groups) = inputs();
        let (siblings, stats) = sweep_siblings(
            &groups,
            &units,
            &files,
            &feature_files,
            &evidence,
            &VerifyConfig::default(),
            &SiblingConfig::default(),
        );

        let mut expected = vec![1, 2, 3];
        expected.sort_by(|left, right| {
            units[*left]
                .fingerprint
                .cmp(&units[*right].fingerprint)
                .then(left.cmp(right))
        });
        assert_eq!(siblings.len(), 1);
        assert_eq!(
            siblings[0]
                .siblings
                .iter()
                .map(|sibling| sibling.unit)
                .collect::<Vec<_>>(),
            expected
        );
        assert!(!siblings[0].siblings.iter().any(|sibling| sibling.unit == 5));
        assert_eq!(stats.eligible_candidates, 3);
        assert_eq!(stats.candidates_examined, 3);
        assert_eq!(stats.accepted, 3);
        assert_eq!(groups.groups[0].members.len(), 2);

        let (again, again_stats) = sweep_siblings(
            &groups,
            &units,
            &files,
            &feature_files,
            &evidence,
            &VerifyConfig::default(),
            &SiblingConfig::default(),
        );
        assert_eq!(again, siblings);
        assert_eq!(again_stats, stats);
    }

    #[test]
    fn sweep_caps_bound_comparisons_and_retained_siblings() {
        let (units, files, feature_files, evidence, groups) = inputs();
        let mut ordered = vec![1, 2, 3];
        ordered.sort_by(|left, right| {
            units[*left]
                .fingerprint
                .cmp(&units[*right].fingerprint)
                .then(left.cmp(right))
        });
        let expected_first = ordered.remove(0);

        let (per_group, per_group_stats) = sweep_siblings(
            &groups,
            &units,
            &files,
            &feature_files,
            &evidence,
            &VerifyConfig::default(),
            &SiblingConfig {
                similarity_delta: 0.10,
                candidate_budget: 10,
                per_group_cap: 1,
                total_cap: 10,
            },
        );
        assert_eq!(per_group[0].siblings[0].unit, expected_first);
        assert_eq!(per_group_stats.candidates_examined, 1);
        assert_eq!(per_group_stats.per_group_cap_dropped, 2);

        let (_, total_stats) = sweep_siblings(
            &groups,
            &units,
            &files,
            &feature_files,
            &evidence,
            &VerifyConfig::default(),
            &SiblingConfig {
                similarity_delta: 0.10,
                candidate_budget: 10,
                per_group_cap: 8,
                total_cap: 1,
            },
        );
        assert_eq!(total_stats.candidates_examined, 1);
        assert_eq!(total_stats.total_cap_dropped, 2);

        let (_, budget_stats) = sweep_siblings(
            &groups,
            &units,
            &files,
            &feature_files,
            &evidence,
            &VerifyConfig::default(),
            &SiblingConfig {
                similarity_delta: 0.10,
                candidate_budget: 1,
                per_group_cap: 8,
                total_cap: 10,
            },
        );
        assert_eq!(budget_stats.candidates_examined, 1);
        assert_eq!(budget_stats.candidate_budget_dropped, 2);
    }
}
