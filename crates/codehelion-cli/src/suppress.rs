//! Configuration- and comment-driven suppression of findings.
//!
//! Suppression never deletes a finding: a suppressed group is still detected,
//! recorded and counted; it is hidden from the default report and its stored
//! finding references the rule that matched. Two rule kinds exist here:
//!
//! - **path globs** (`[suppression] paths` in the configuration): every
//!   occurrence inside a matching file is suppressed;
//! - **inline markers**: a comment line containing `codehelion:ignore`
//!   suppresses the unit it appears in, or — when it sits between units —
//!   the next unit that starts below it. An occurrence outside any unit is
//!   suppressed when a marker line falls inside its own line range.
//!
//! A group's finding is suppressed only when *every* member is suppressed:
//! as long as one occurrence lives in unsuppressed code, the duplication is
//! still actionable and stays visible. (Generated-file markers are a third
//! mechanism, applied earlier: those files are excluded during discovery,
//! before any candidate exists.)

use anyhow::{Context, Result};
use codehelion_store::snapshot::SuppressionRuleRow;
use globset::{Glob, GlobMatcher};

/// The marker text an inline suppression comment must contain.
pub(crate) const INLINE_MARKER: &str = "codehelion:ignore";

/// 1-based lines of `text` that contain the inline marker.
pub(crate) fn marker_lines(text: &str) -> Vec<u32> {
    text.lines()
        .enumerate()
        .filter(|(_, line)| line.contains(INLINE_MARKER))
        .map(|(index, _)| u32::try_from(index).unwrap_or(u32::MAX).saturating_add(1))
        .collect()
}

/// Compiled suppression rules for one scan.
///
/// `rows` is what the snapshot records; rule indices returned by the
/// evaluation methods index into it.
pub(crate) struct Rules {
    path_matchers: Vec<GlobMatcher>,
    /// Index of the inline-marker rule in `rows`, present only when at least
    /// one marker was seen in the scanned sources.
    inline_rule: Option<usize>,
    pub(crate) rows: Vec<SuppressionRuleRow>,
}

/// Per-file evaluation result, computed once per file.
pub(crate) struct FileSuppression {
    /// Rule index when the whole file matches a path glob.
    path_rule: Option<usize>,
    /// Whether each unit of the file is marker-suppressed.
    suppressed_units: Vec<bool>,
    /// The file's marker lines, for occurrences outside any unit.
    marker_lines: Vec<u32>,
}

impl Rules {
    /// Compile the configured path globs, appending the inline-marker rule
    /// when any marker exists in the scanned sources.
    pub(crate) fn compile(paths: &[String], any_markers: bool) -> Result<Self> {
        let mut path_matchers = Vec::with_capacity(paths.len());
        let mut rows = Vec::with_capacity(paths.len() + 1);
        for pattern in paths {
            let glob =
                Glob::new(pattern).with_context(|| format!("suppression path glob {pattern:?}"))?;
            path_matchers.push(glob.compile_matcher());
            rows.push(SuppressionRuleRow {
                scope: "path_glob".to_string(),
                pattern: pattern.clone(),
                reason: None,
            });
        }
        let inline_rule = any_markers.then(|| {
            rows.push(SuppressionRuleRow {
                scope: "inline_comment".to_string(),
                pattern: INLINE_MARKER.to_string(),
                reason: None,
            });
            rows.len() - 1
        });
        Ok(Self {
            path_matchers,
            inline_rule,
            rows,
        })
    }

    /// Human-readable label of rule `index`, for the report.
    pub(crate) fn label(&self, index: usize) -> String {
        let row = &self.rows[index];
        match row.scope.as_str() {
            "path_glob" => format!("path glob {:?}", row.pattern),
            "inline_comment" => format!("{} marker", row.pattern),
            other => format!("{other} {:?}", row.pattern),
        }
    }

    /// Evaluate one file: its path against the globs, and its marker lines
    /// against its unit spans.
    pub(crate) fn evaluate_file(
        &self,
        path: &str,
        markers: &[u32],
        unit_lines: &[(u32, u32)],
    ) -> FileSuppression {
        let path_rule = self
            .path_matchers
            .iter()
            .position(|matcher| matcher.is_match(path));
        FileSuppression {
            path_rule,
            suppressed_units: suppressed_units(markers, unit_lines),
            marker_lines: markers.to_vec(),
        }
    }

    /// The rule suppressing one occurrence, if any. Path rules take
    /// precedence over the inline marker (they are broader and cheaper to
    /// explain).
    pub(crate) fn member_rule(
        &self,
        file: &FileSuppression,
        start_line: u32,
        end_line: u32,
        unit: Option<usize>,
    ) -> Option<usize> {
        if let Some(index) = file.path_rule {
            return Some(index);
        }
        let inline = self.inline_rule?;
        let marked = unit.map_or_else(
            || {
                file.marker_lines
                    .iter()
                    .any(|line| *line >= start_line && *line <= end_line)
            },
            |unit_index| file.suppressed_units.get(unit_index).copied() == Some(true),
        );
        marked.then_some(inline)
    }
}

/// Which units a file's marker lines suppress.
///
/// A marker inside a unit suppresses every unit whose span contains it (a
/// marker in a closure body also covers the enclosing function — suppression
/// errs on the broad side). A marker outside any unit suppresses the next
/// unit that starts below it.
fn suppressed_units(markers: &[u32], unit_lines: &[(u32, u32)]) -> Vec<bool> {
    let mut flags = vec![false; unit_lines.len()];
    for &line in markers {
        let mut contained = false;
        for (index, &(start, end)) in unit_lines.iter().enumerate() {
            if line >= start && line <= end {
                flags[index] = true;
                contained = true;
            }
        }
        if contained {
            continue;
        }
        if let Some((index, _)) = unit_lines
            .iter()
            .enumerate()
            .filter(|&(_, &(start, _))| start > line)
            .min_by_key(|&(_, &(start, _))| start)
        {
            flags[index] = true;
        }
    }
    flags
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn marker_lines_are_one_based() {
        let text = "fn a() {}\n// codehelion:ignore\nfn b() {}\n";
        assert_eq!(marker_lines(text), vec![2]);
        assert!(marker_lines("fn clean() {}\n").is_empty());
    }

    #[test]
    fn a_marker_between_units_suppresses_the_next_unit() {
        // Units on lines 1-3 and 6-8; marker on line 5.
        let flags = suppressed_units(&[5], &[(1, 3), (6, 8)]);
        assert_eq!(flags, vec![false, true]);
    }

    #[test]
    fn a_marker_inside_a_unit_suppresses_every_containing_unit() {
        // A function on lines 1-10 holding a closure on lines 4-6.
        let flags = suppressed_units(&[5], &[(1, 10), (4, 6)]);
        assert_eq!(flags, vec![true, true]);
    }

    #[test]
    fn a_trailing_marker_with_no_following_unit_suppresses_nothing() {
        let flags = suppressed_units(&[20], &[(1, 3)]);
        assert_eq!(flags, vec![false]);
    }

    #[test]
    fn path_rules_take_precedence_and_files_without_rules_pass() {
        let rules = Rules::compile(&["vendor/**".to_string()], true).unwrap();
        assert_eq!(rules.rows.len(), 2);

        let vendored = rules.evaluate_file("vendor/lib.rs", &[2], &[(1, 5)]);
        // Both the glob and the marker match; the glob (rule 0) wins.
        assert_eq!(rules.member_rule(&vendored, 1, 5, Some(0)), Some(0));

        let marked = rules.evaluate_file("src/lib.rs", &[2], &[(1, 5)]);
        assert_eq!(rules.member_rule(&marked, 1, 5, Some(0)), Some(1));

        let clean = rules.evaluate_file("src/other.rs", &[], &[(1, 5)]);
        assert_eq!(rules.member_rule(&clean, 1, 5, Some(0)), None);
    }

    #[test]
    fn hostless_occurrences_use_their_own_line_range() {
        let rules = Rules::compile(&[], true).unwrap();
        let file = rules.evaluate_file("src/lib.rs", &[7], &[]);
        assert_eq!(rules.member_rule(&file, 5, 9, None), Some(0));
        assert_eq!(rules.member_rule(&file, 10, 14, None), None);
    }

    #[test]
    fn without_markers_no_inline_rule_is_recorded() {
        let rules = Rules::compile(&[], false).unwrap();
        assert!(rules.rows.is_empty());
        let file = rules.evaluate_file("src/lib.rs", &[], &[(1, 5)]);
        assert_eq!(rules.member_rule(&file, 1, 5, Some(0)), None);
    }

    #[test]
    fn malformed_suppression_globs_are_an_error() {
        assert!(Rules::compile(&["src/[".to_string()], false).is_err());
    }
}
