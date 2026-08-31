//! Configuration- and comment-driven suppression of findings.
//!
//! Suppression never deletes a finding: a suppressed group is still detected,
//! recorded and counted; it is hidden from the default report and its stored
//! finding references the rule that matched. Four rule kinds select
//! occurrences:
//!
//! - **path globs** (`[suppression] paths` in the configuration): every
//!   occurrence inside a matching file is suppressed;
//! - **vendored globs** (`[suppression] vendored-paths`): the same, over the
//!   trees a project vendors rather than writes. The one rule kind carrying
//!   defaults, so a run that applied it says so and names
//!   `--include-vendored`; a glob somebody wrote outranks it, so a hidden
//!   finding is attributed to the decision actually made about it;
//! - **symbol globs** (`[suppression] symbols`): every occurrence sitting in
//!   a unit whose name matches is suppressed, wherever that unit lives;
//! - **inline markers**: a comment line containing `codehelion:ignore`
//!   suppresses the unit it appears in, or — when it sits between units —
//!   the next unit that starts below it. An occurrence outside any unit is
//!   suppressed when a marker line falls inside its own line range.
//!
//! A group's finding is suppressed only when *every* member is suppressed:
//! as long as one occurrence lives in unsuppressed code, the duplication is
//! still actionable and stays visible.
//!
//! A further rule kind names whole groups rather than occurrences:
//! **stable clone ids** (`[suppression] clone-ids`) suppress the group whose
//! fingerprint they identify. An id describes that group's content, so it
//! stops matching as soon as the content changes — which is the point: a
//! judgement made about one duplication does not silently carry over to a
//! different one.
//!
//! A **baseline** (see [`crate::baseline`]) is the same kind of rule applied
//! wholesale: the ids a recorded scan reported, frozen so that a later scan
//! reports what came after. It is consulted last of all, because it is the
//! weakest thing that can be said about a finding — that it is not new — and
//! every other rule says something about the code itself.
//!
//! (Generated-file markers are a further mechanism, applied earlier: those
//! files are excluded during discovery, before any candidate exists.)

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, bail};
use codehelion_store::snapshot::SuppressionRuleRow;
use globset::{Glob, GlobMatcher};

use crate::FULL_ID_CHARS;
use crate::config::Suppression;

/// The marker text an inline suppression comment must contain.
pub(crate) const INLINE_MARKER: &str = "codehelion:ignore";

/// Rule scope recorded for a vendored-tree glob.
///
/// Kept apart from `path_glob` because this is the one rule kind that fires
/// without anybody having configured it: a reader has to be able to see that
/// a finding was hidden by a default, and to tell that default apart from
/// their own rules when deciding what to change.
pub(crate) const VENDORED_SCOPE: &str = "vendored_path";

/// Rule scope recorded for a configured stable clone id.
///
/// Named because two surfaces have to agree on it: the rule a suppressed group
/// cites, and the report that counts how many groups one clone id covers.
pub(crate) const CLONE_ID_SCOPE: &str = "stable_clone_id";

/// Shortest accepted clone-id prefix.
///
/// Abbreviating an id is convenient, but too short a prefix would suppress
/// unrelated groups as the codebase grows; eight hex characters keep an
/// accidental match unlikely without demanding the full id.
pub(crate) const MIN_CLONE_ID_CHARS: usize = 8;

/// One unit of a file, as the suppression rules see it.
pub(crate) struct UnitSpan<'a> {
    /// First line of the unit.
    pub(crate) start_line: u32,
    /// Last line of the unit.
    pub(crate) end_line: u32,
    /// Declared name, when the frontend recovered one.
    pub(crate) name: Option<&'a str>,
}

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
/// `rows` is what the snapshot records; every compiled matcher carries the
/// index of the row it represents.
#[derive(Debug)]
pub(crate) struct Rules {
    /// Path globs paired with their rule index in `rows`.
    path_matchers: Vec<(GlobMatcher, usize)>,
    /// Vendored-tree globs paired with their rule index in `rows`.
    vendored_matchers: Vec<(GlobMatcher, usize)>,
    /// Symbol globs paired with their rule index in `rows`.
    symbol_matchers: Vec<(GlobMatcher, usize)>,
    /// Lower-case clone-id prefixes paired with their rule index in `rows`.
    clone_ids: Vec<(String, usize)>,
    /// Index of the inline-marker rule in `rows`, present only when at least
    /// one marker was seen in the scanned sources.
    inline_rule: Option<usize>,
    /// The group ids and maximum covered occurrence count a baseline froze,
    /// plus the index of the rule that hides them. One rule stands for the
    /// whole file: which entry matched is the file's business, and it is
    /// where the reader has to look anyway.
    baseline: Option<(BTreeMap<String, u64>, usize)>,
    pub(crate) rows: Vec<SuppressionRuleRow>,
}

/// Per-file evaluation result, computed once per file.
pub(crate) struct FileSuppression {
    /// Rule index when the whole file matches a path glob.
    path_rule: Option<usize>,
    /// Rule index when the file sits in a vendored tree.
    vendored_rule: Option<usize>,
    /// Rule index of the symbol glob matching each unit's name, if any.
    symbol_units: Vec<Option<usize>>,
    /// Whether each unit of the file is marker-suppressed.
    suppressed_units: Vec<bool>,
    /// The file's marker lines, for occurrences outside any unit.
    marker_lines: Vec<u32>,
    /// Every configured selector that matched this file or one of its units.
    ///
    /// This deliberately includes a selector that lost precedence for a
    /// particular finding: a matched rule is not stale merely because a more
    /// specific rule decided what the report displays.
    matched_rules: BTreeSet<usize>,
}

impl FileSuppression {
    /// Every selector that matched this file or one of its units.
    pub(crate) fn matched_rules(&self) -> impl Iterator<Item = usize> + '_ {
        self.matched_rules.iter().copied()
    }
}

impl Rules {
    /// Compile the configured rules, appending the inline-marker rule when
    /// any marker exists in the scanned sources.
    ///
    /// # Errors
    ///
    /// Returns an error if a glob is malformed or a clone id is not a hex
    /// string of between [`MIN_CLONE_ID_CHARS`] and [`FULL_ID_CHARS`]
    /// characters.
    pub(crate) fn compile(suppression: &Suppression, any_markers: bool) -> Result<Self> {
        let mut path_matchers = Vec::with_capacity(suppression.paths.len());
        let mut symbol_matchers = Vec::with_capacity(suppression.symbols.len());
        let mut clone_ids = Vec::with_capacity(suppression.clone_ids.len());
        let mut rows = Vec::new();
        for pattern in &suppression.paths {
            let glob =
                Glob::new(pattern).with_context(|| format!("suppression path glob {pattern:?}"))?;
            rows.push(SuppressionRuleRow {
                scope: "path_glob".to_string(),
                pattern: pattern.clone(),
                reason: None,
            });
            path_matchers.push((glob.compile_matcher(), rows.len() - 1));
        }
        let mut vendored_matchers = Vec::with_capacity(suppression.vendored_paths.len());
        for pattern in &suppression.vendored_paths {
            let glob = Glob::new(pattern)
                .with_context(|| format!("suppression vendored path glob {pattern:?}"))?;
            rows.push(SuppressionRuleRow {
                scope: VENDORED_SCOPE.to_string(),
                pattern: pattern.clone(),
                reason: Some("vendored code, which this project does not write".to_string()),
            });
            vendored_matchers.push((glob.compile_matcher(), rows.len() - 1));
        }
        for pattern in &suppression.symbols {
            let glob = Glob::new(pattern)
                .with_context(|| format!("suppression symbol glob {pattern:?}"))?;
            rows.push(SuppressionRuleRow {
                scope: "symbol_pattern".to_string(),
                pattern: pattern.clone(),
                reason: None,
            });
            symbol_matchers.push((glob.compile_matcher(), rows.len() - 1));
        }
        for id in &suppression.clone_ids {
            let normalized = clone_id_prefix(id)?;
            rows.push(SuppressionRuleRow {
                scope: CLONE_ID_SCOPE.to_string(),
                pattern: normalized.clone(),
                reason: None,
            });
            clone_ids.push((normalized, rows.len() - 1));
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
            vendored_matchers,
            symbol_matchers,
            clone_ids,
            inline_rule,
            baseline: None,
            rows,
        })
    }

    /// Register the baseline `file` as a rule hiding the groups it froze,
    /// returning its index.
    ///
    /// The rule's pattern is the file rather than any one id: a baseline is a
    /// decision recorded in one place, and pointing at that place is what a
    /// reader needs in order to reverse it.
    pub(crate) fn add_baseline(&mut self, file: &str, covered: BTreeMap<String, u64>) -> usize {
        self.rows.push(SuppressionRuleRow {
            scope: "baseline".to_string(),
            pattern: file.to_string(),
            reason: Some("recorded before this baseline".to_string()),
        });
        let index = self.rows.len() - 1;
        self.baseline = Some((covered, index));
        index
    }

    /// The rule hiding a group because a baseline froze it, if one did.
    pub(crate) fn baseline_rule(&self, fingerprint_hex: &str, instances: u64) -> Option<usize> {
        let (covered, rule) = self.baseline.as_ref()?;
        (instances <= *covered.get(fingerprint_hex)?).then_some(*rule)
    }

    /// Register a rule that matches by code shape rather than by location,
    /// returning its index.
    ///
    /// This is how a configured boilerplate category suppresses a group: the
    /// rule describes what the group *is*, so it applies to every member at
    /// once instead of being evaluated per file.
    pub(crate) fn add_shape_rule(&mut self, pattern: &str, reason: &str) -> usize {
        self.rows.push(SuppressionRuleRow {
            scope: "ast_pattern".to_string(),
            pattern: pattern.to_string(),
            reason: Some(reason.to_string()),
        });
        self.rows.len() - 1
    }

    /// The configured rules whose selectors matched no source or finding in
    /// this run, in the order they were written.
    ///
    /// A rule that matches nothing is the worst failure mode suppression has:
    /// it reads as an instruction that took effect while the findings it was
    /// meant to cover are still being reported, or — for a clone id — the
    /// duplication it judged has changed and the judgement no longer applies
    /// to anything. Either way the user has to be told.
    ///
    /// Source selectors are counted when they match, even if a
    /// higher-precedence selector later decides which rule the report cites.
    /// Only rules the user wrote are considered. The inline-marker rule is
    /// registered from markers actually found in the sources, and the shape
    /// and attribute rules are registered from categories this run actually
    /// produced, so neither can be stale in this sense.
    pub(crate) fn unused(&self, used: &BTreeSet<usize>) -> Vec<&SuppressionRuleRow> {
        self.rows
            .iter()
            .enumerate()
            .filter(|(index, row)| {
                !used.contains(index)
                    && matches!(
                        row.scope.as_str(),
                        "path_glob" | "symbol_pattern" | CLONE_ID_SCOPE
                    )
            })
            .map(|(_, row)| row)
            .collect()
    }

    /// Register a rule that matches by an attribute in the source, returning
    /// its index.
    ///
    /// Unlike a shape rule this states what the code says about itself: a unit
    /// carrying the test attribute is a test because it was declared one. As
    /// with a shape rule, it applies to a whole group rather than per file.
    pub(crate) fn add_attribute_rule(&mut self, pattern: &str, reason: &str) -> usize {
        self.rows.push(SuppressionRuleRow {
            scope: "attribute".to_string(),
            pattern: pattern.to_string(),
            reason: Some(reason.to_string()),
        });
        self.rows.len() - 1
    }

    /// Evaluate one file: its path against the path globs, its unit names
    /// against the symbol globs, and its marker lines against its unit spans.
    pub(crate) fn evaluate_file(
        &self,
        path: &str,
        markers: &[u32],
        units: &[UnitSpan<'_>],
    ) -> FileSuppression {
        let path_matches: Vec<usize> = self
            .path_matchers
            .iter()
            .filter_map(|(matcher, rule)| matcher.is_match(path).then_some(*rule))
            .collect();
        let path_rule = path_matches.first().copied();
        let vendored_matches: Vec<usize> = self
            .vendored_matchers
            .iter()
            .filter_map(|(matcher, rule)| matcher.is_match(path).then_some(*rule))
            .collect();
        let vendored_rule = vendored_matches.first().copied();
        let mut matched_rules: BTreeSet<usize> = path_matches.into_iter().collect();
        matched_rules.extend(vendored_matches);
        let symbol_units = units
            .iter()
            .map(|unit| {
                let name = unit.name?;
                let matches: Vec<usize> = self
                    .symbol_matchers
                    .iter()
                    .filter_map(|(matcher, rule)| matcher.is_match(name).then_some(*rule))
                    .collect();
                matched_rules.extend(&matches);
                matches.first().copied()
            })
            .collect();
        if let Some(rule) = self.inline_rule.filter(|_| !markers.is_empty()) {
            matched_rules.insert(rule);
        }
        let lines: Vec<(u32, u32)> = units
            .iter()
            .map(|unit| (unit.start_line, unit.end_line))
            .collect();
        FileSuppression {
            path_rule,
            vendored_rule,
            symbol_units,
            suppressed_units: suppressed_units(markers, &lines),
            marker_lines: markers.to_vec(),
            matched_rules,
        }
    }

    /// The rule suppressing a whole group by its stable clone id, if any.
    ///
    /// The configured ids are prefixes, so the comparison is on the hex form
    /// rather than the raw bytes.
    pub(crate) fn clone_id_rule(&self, fingerprint_hex: &str) -> Option<usize> {
        self.clone_ids
            .iter()
            .find(|(prefix, _)| fingerprint_hex.starts_with(prefix.as_str()))
            .map(|&(_, rule)| rule)
    }

    /// The rule suppressing one occurrence, if any.
    ///
    /// Configured rules come before the in-source marker, and the broader
    /// configured rule comes first: a path glob covers whole files, a symbol
    /// glob covers named units, the marker covers one unit.
    ///
    /// A rule somebody wrote outranks the vendored default, so that a report
    /// attributes a hidden finding to the decision that was actually made
    /// about it.
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
        if let Some(index) = file.vendored_rule {
            return Some(index);
        }
        if let Some(index) = unit.and_then(|index| file.symbol_units.get(index).copied().flatten())
        {
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

/// The configured clone ids covering more than one group, with how many groups
/// each covers.
///
/// A clone id is a prefix, so a rule written about one duplication starts
/// hiding a second as soon as the tree grows a group whose id shares that
/// prefix. Every matching group is hidden, which is what the rule says; what
/// nothing else would say is that a judgement made about one duplication has
/// become a judgement about several, and a group is then missing from the
/// report without the user having decided anything about it. Naming the id
/// with its count is the same answer an ambiguous id gets when it is used to
/// look one group up: the reader is told what the prefix currently resolves to
/// instead of being handed the first match.
///
/// `patterns` is the clone id each suppressed group cites, one entry per
/// group. The result is ordered by id so that two runs over one tree read the
/// same.
pub(crate) fn multi_match_clone_ids<'a>(
    patterns: impl IntoIterator<Item = &'a str>,
) -> Vec<(String, u64)> {
    let mut covered: BTreeMap<&str, u64> = BTreeMap::new();
    for pattern in patterns {
        let groups = covered.entry(pattern).or_insert(0);
        *groups = groups.saturating_add(1);
    }
    covered
        .into_iter()
        .filter(|&(_, groups)| groups > 1)
        .map(|(pattern, groups)| (pattern.to_string(), groups))
        .collect()
}

/// Validate one configured clone id and return it in the form the comparison
/// uses: lower-case hex.
///
/// A malformed id is an error rather than a rule that quietly matches
/// nothing — a suppression that never fires is indistinguishable from a
/// suppression that works until someone reads the report.
fn clone_id_prefix(id: &str) -> Result<String> {
    if id.len() < MIN_CLONE_ID_CHARS {
        bail!(
            "suppression clone id {id:?} is shorter than {MIN_CLONE_ID_CHARS} characters; \
             use a longer prefix of the id shown in the report"
        );
    }
    // An id longer than a whole one cannot be a prefix of any id there is, so
    // the rule could never fire. Refused for the same reason a short one is:
    // the alternative is a rule that reads as working.
    if id.len() > FULL_ID_CHARS {
        bail!(
            "suppression clone id {id:?} is longer than the {FULL_ID_CHARS} characters an id has; \
             use the id shown in the report, or a prefix of it"
        );
    }
    if !id.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("suppression clone id {id:?} is not hexadecimal");
    }
    Ok(id.to_ascii_lowercase())
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

    /// A configuration carrying only the rules a test cares about.
    ///
    /// The vendored defaults are cleared: a test naming its own globs is about
    /// those globs, and eleven more compiled behind them would make every rule
    /// index in it depend on a list nobody here wrote.
    fn suppression(paths: &[&str], symbols: &[&str], clone_ids: &[&str]) -> Suppression {
        Suppression {
            paths: paths.iter().map(|p| (*p).to_string()).collect(),
            vendored_paths: Vec::new(),
            symbols: symbols.iter().map(|s| (*s).to_string()).collect(),
            clone_ids: clone_ids.iter().map(|c| (*c).to_string()).collect(),
            ..Suppression::default()
        }
    }

    /// One named unit spanning `lines`.
    fn unit(name: Option<&str>, lines: (u32, u32)) -> UnitSpan<'_> {
        UnitSpan {
            start_line: lines.0,
            end_line: lines.1,
            name,
        }
    }

    #[test]
    fn a_vendored_glob_matches_whole_path_components_and_yields_to_a_written_rule() {
        let mut config = suppression(&["src/generated/**"], &[], &[]);
        config.vendored_paths = vec![
            "**/external/**".to_string(),
            "**/src/generated/**".to_string(),
        ];
        let rules = Rules::compile(&config, false).unwrap();

        // A vendored tree anywhere, at the root or nested.
        for path in ["external/lib.rs", "deep/external/lib.rs"] {
            let file = rules.evaluate_file(path, &[], &[unit(None, (1, 5))]);
            let rule = rules.member_rule(&file, 1, 5, Some(0)).expect("hidden");
            assert_eq!(rules.rows[rule].scope, VENDORED_SCOPE, "{path}");
        }

        // A directory whose name only starts like a vendored one is the
        // project's own code.
        let lookalike = rules.evaluate_file("external_api/lib.rs", &[], &[unit(None, (1, 5))]);
        assert_eq!(rules.member_rule(&lookalike, 1, 5, Some(0)), None);

        // Both rules cover this file. A report attributes it to the one
        // somebody wrote, which is the one they can change.
        let both = rules.evaluate_file("src/generated/lib.rs", &[], &[unit(None, (1, 5))]);
        let rule = rules.member_rule(&both, 1, 5, Some(0)).expect("hidden");
        assert_eq!(rules.rows[rule].scope, "path_glob");
    }

    #[test]
    fn a_vendored_default_that_matched_nothing_is_not_reported_as_an_unused_rule() {
        let mut config = suppression(&[], &[], &[]);
        config.vendored_paths = vec!["**/external/**".to_string()];
        let rules = Rules::compile(&config, false).unwrap();

        // The unused-rule note exists to catch a rule somebody wrote that took
        // no effect. Saying that about a default would fire on every project
        // that vendors nothing, which is most of them.
        assert!(rules.unused(&BTreeSet::new()).is_empty());
    }

    #[test]
    fn path_rules_take_precedence_and_files_without_rules_pass() {
        let rules = Rules::compile(&suppression(&["vendor/**"], &[], &[]), true).unwrap();
        assert_eq!(rules.rows.len(), 2);

        let vendored = rules.evaluate_file("vendor/lib.rs", &[2], &[unit(None, (1, 5))]);
        // Both the glob and the marker match; the glob (rule 0) wins.
        assert_eq!(rules.member_rule(&vendored, 1, 5, Some(0)), Some(0));

        let marked = rules.evaluate_file("src/lib.rs", &[2], &[unit(None, (1, 5))]);
        assert_eq!(rules.member_rule(&marked, 1, 5, Some(0)), Some(1));

        let clean = rules.evaluate_file("src/other.rs", &[], &[unit(None, (1, 5))]);
        assert_eq!(rules.member_rule(&clean, 1, 5, Some(0)), None);
    }

    #[test]
    fn path_matchers_hold_the_row_of_the_rule_they_represent() {
        let rules = Rules::compile(
            &suppression(&["generated/**", "vendor/**"], &["test_*"], &[]),
            false,
        )
        .unwrap();
        let file = rules.evaluate_file("vendor/lib.rs", &[], &[unit(None, (1, 5))]);
        let rule = rules
            .member_rule(&file, 1, 5, Some(0))
            .expect("path matches");
        assert_eq!(rules.rows[rule].scope, "path_glob");
        assert_eq!(rules.rows[rule].pattern, "vendor/**");
        assert_eq!(
            rules
                .path_matchers
                .iter()
                .map(|(_, row)| *row)
                .collect::<Vec<_>>(),
            vec![0, 1]
        );
    }

    #[test]
    fn a_symbol_glob_matches_by_unit_name_wherever_the_unit_lives() {
        let rules = Rules::compile(&suppression(&[], &["test_*"], &[]), false).unwrap();
        assert_eq!(rules.rows[0].scope, "symbol_pattern");

        let file = rules.evaluate_file(
            "src/lib.rs",
            &[],
            &[
                unit(Some("test_parses"), (1, 5)),
                unit(Some("parse"), (7, 20)),
            ],
        );
        assert_eq!(rules.member_rule(&file, 1, 5, Some(0)), Some(0));
        assert_eq!(rules.member_rule(&file, 7, 20, Some(1)), None);

        // The same name is suppressed in any file.
        let other = rules.evaluate_file("tests/api.rs", &[], &[unit(Some("test_parses"), (3, 9))]);
        assert_eq!(rules.member_rule(&other, 3, 9, Some(0)), Some(0));
    }

    #[test]
    fn an_unnamed_unit_is_never_symbol_suppressed() {
        let rules = Rules::compile(&suppression(&[], &["*"], &[]), false).unwrap();
        let file = rules.evaluate_file("src/lib.rs", &[], &[unit(None, (1, 5))]);
        assert_eq!(rules.member_rule(&file, 1, 5, Some(0)), None);
        // Neither is an occurrence that sits in no unit at all.
        assert_eq!(rules.member_rule(&file, 1, 5, None), None);
    }

    #[test]
    fn a_path_glob_outranks_a_symbol_glob() {
        let rules = Rules::compile(&suppression(&["vendor/**"], &["parse"], &[]), false).unwrap();
        let file = rules.evaluate_file("vendor/lib.rs", &[], &[unit(Some("parse"), (1, 5))]);
        assert_eq!(rules.member_rule(&file, 1, 5, Some(0)), Some(0));
    }

    #[test]
    fn a_symbol_glob_outranks_an_inline_marker() {
        let rules = Rules::compile(&suppression(&[], &["parse"], &[]), true).unwrap();
        let file = rules.evaluate_file("src/lib.rs", &[3], &[unit(Some("parse"), (1, 5))]);
        assert_eq!(rules.member_rule(&file, 1, 5, Some(0)), Some(0));
    }

    #[test]
    fn a_clone_id_suppresses_the_group_it_names_by_prefix() {
        let rules = Rules::compile(&suppression(&[], &[], &["0123ABCD"]), false).unwrap();
        assert_eq!(rules.rows[0].scope, "stable_clone_id");
        // Recorded and compared in lower case, whatever the configured case.
        assert_eq!(rules.rows[0].pattern, "0123abcd");

        assert_eq!(
            rules.clone_id_rule(&format!("0123abcd{}", "ef".repeat(12))),
            Some(0)
        );
        assert_eq!(rules.clone_id_rule(&"9".repeat(32)), None);
    }

    #[test]
    fn a_clone_id_covering_several_groups_is_named_with_how_many() {
        // Two groups cite the same id, so the prefix no longer identifies the
        // one duplication it was written about.
        assert_eq!(
            multi_match_clone_ids(["0123abcd", "9999beef", "0123abcd"]),
            vec![("0123abcd".to_string(), 2)]
        );

        // An id that resolves to a single group says exactly what it said when
        // it was written, and there is nothing to report about it.
        assert!(multi_match_clone_ids(["0123abcd", "9999beef"]).is_empty());
        assert!(multi_match_clone_ids([]).is_empty());
    }

    #[test]
    fn a_clone_id_that_could_not_identify_a_group_is_an_error() {
        let err = Rules::compile(&suppression(&[], &[], &["0123ab"]), false)
            .expect_err("too short to identify one group");
        assert!(format!("{err:#}").contains("shorter than"));

        let err = Rules::compile(&suppression(&[], &[], &["not-a-hex-id"]), false)
            .expect_err("ids are hexadecimal");
        assert!(format!("{err:#}").contains("hexadecimal"));

        // Nothing is longer than a whole id, so a longer rule matches nothing
        // no matter what the tree holds.
        let whole = "a".repeat(FULL_ID_CHARS);
        let overlong = "a".repeat(FULL_ID_CHARS + 1);
        let err = Rules::compile(&suppression(&[], &[], &[&overlong]), false)
            .expect_err("longer than an id");
        assert!(format!("{err:#}").contains("longer than"));

        // A whole id remains the exact rule it looks like.
        Rules::compile(&suppression(&[], &[], &[&whole]), false)
            .expect("a whole id is a valid rule");
    }

    #[test]
    fn hostless_occurrences_use_their_own_line_range() {
        let rules = Rules::compile(&suppression(&[], &[], &[]), true).unwrap();
        let inline = rules.rows.len() - 1;
        let file = rules.evaluate_file("src/lib.rs", &[7], &[]);
        assert_eq!(rules.member_rule(&file, 5, 9, None), Some(inline));
        assert_eq!(rules.member_rule(&file, 10, 14, None), None);
    }

    #[test]
    fn without_markers_no_inline_rule_is_recorded() {
        let rules = Rules::compile(&suppression(&[], &[], &[]), false).unwrap();
        assert!(rules.rows.is_empty());
        let file = rules.evaluate_file("src/lib.rs", &[], &[unit(None, (1, 5))]);
        assert_eq!(rules.member_rule(&file, 1, 5, Some(0)), None);
    }

    #[test]
    fn malformed_suppression_globs_are_an_error() {
        assert!(Rules::compile(&suppression(&["src/["], &[], &[]), false).is_err());
        assert!(Rules::compile(&suppression(&[], &["fn_["], &[]), false).is_err());
    }
}
