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
//!   suppressed when a marker line falls inside its own line range. Only a
//!   comment counts: the same characters in a string literal, a character
//!   literal or an identifier suppress nothing, because a rule the tree could
//!   write by accident is not a rule anybody decided on.
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
use codehelion_core::discovery::Language;
use codehelion_store::snapshot::SuppressionRuleRow;
use globset::{Glob, GlobMatcher};

use crate::FULL_ID_CHARS;
use crate::config::Suppression;
use crate::provenance::FromScannedTree;

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

/// Longest delimiter a C++ raw string literal may carry.
const MAX_RAW_STRING_DELIMITER: usize = 16;

/// 1-based lines of one source file that carry the inline marker in a comment.
///
/// The marker hides findings, so the tree must not be able to write one
/// anywhere it likes. Only text the file's own language treats as a comment
/// counts: the same characters inside a string literal, a character literal or
/// an identifier are the text they are, not an instruction. A file listing the
/// markers a project uses, a template it embeds, or a test asserting on this
/// tool's own output therefore reports its duplication as usual.
///
/// The argument type is what keeps that true — raw source text cannot reach
/// this function, only text narrowed to its comments.
pub(crate) fn marker_lines(source: &FromScannedTree<&str>, language: Language) -> Vec<u32> {
    let mut lines: Vec<u32> = source
        .comments(language)
        .into_iter()
        .filter(|(_, comment)| comment.contains(INLINE_MARKER))
        .map(|(line, _)| line)
        .collect();
    lines.dedup();
    lines
}

/// The comment text `text` holds, as `(1-based line, text)` pairs.
///
/// One entry per line a comment covers, so a marker inside a block comment is
/// attributed to the line it was written on rather than to the line the
/// comment opened on.
///
/// This is reached through [`FromScannedTree::comments`], which is what makes
/// it the only way suppression reads a scanned file.
pub(crate) fn comments_of(text: &str, language: Language) -> Vec<(u32, &str)> {
    CommentScan::new(text, language).run()
}

/// Walks a source file and keeps only what its language calls a comment.
///
/// Not a parser: it recognises comments, string and character literals, and
/// nothing else. Every ambiguity is resolved towards *not* a comment, because
/// the two mistakes are not symmetric. Skipping a comment loses a marker,
/// which reports a finding that could have been suppressed — visible, and
/// undone by writing the marker somewhere this can read. Mistaking code for a
/// comment hides a finding nobody chose to hide, which is the failure that
/// cannot be seen from the report.
struct CommentScan<'a> {
    /// The whole file.
    text: &'a str,
    /// Whose comment syntax to read it under.
    language: Language,
    /// Byte offset of the cursor.
    index: usize,
    /// 1-based line the cursor sits on.
    line: u32,
    /// What has been recognised so far.
    comments: Vec<(u32, &'a str)>,
}

impl<'a> CommentScan<'a> {
    const fn new(text: &'a str, language: Language) -> Self {
        Self {
            text,
            language,
            index: 0,
            line: 1,
            comments: Vec::new(),
        }
    }

    /// Every comment in the file, in the order they are written.
    fn run(mut self) -> Vec<(u32, &'a str)> {
        while self.index < self.text.len() {
            match self.byte(0) {
                Some(b'/') if self.byte(1) == Some(b'/') => self.line_comment(),
                Some(b'/') if self.byte(1) == Some(b'*') => self.block_comment(),
                Some(b'"') => self.quoted(b'"'),
                Some(b'\'') => self.character_literal(),
                _ => {
                    if !self.raw_string() {
                        self.advance(1);
                    }
                }
            }
        }
        self.comments
    }

    /// The byte `offset` positions ahead of the cursor.
    ///
    /// Every delimiter this looks for is ASCII, and no byte of a multi-byte
    /// character can equal one, so walking bytes never cuts a character in
    /// half.
    fn byte(&self, offset: usize) -> Option<u8> {
        self.text
            .as_bytes()
            .get(self.index.saturating_add(offset))
            .copied()
    }

    /// Move the cursor on by `count` bytes, counting the lines crossed.
    fn advance(&mut self, count: usize) {
        for _ in 0..count {
            if self.byte(0) == Some(b'\n') {
                self.line = self.line.saturating_add(1);
            }
            self.index = self.index.saturating_add(1);
        }
        self.index = self.index.min(self.text.len());
    }

    /// Record the comment running from `start` to the cursor.
    fn record(&mut self, start: usize, start_line: u32) {
        let body = self.text.get(start..self.index).unwrap_or_default();
        for (offset, fragment) in body.split('\n').enumerate() {
            if fragment.is_empty() {
                continue;
            }
            let line = start_line.saturating_add(u32::try_from(offset).unwrap_or(u32::MAX));
            self.comments.push((line, fragment));
        }
    }

    /// Whether the byte before the cursor could end an identifier or a number.
    fn preceded_by_identifier(&self) -> bool {
        self.text
            .as_bytes()
            .get(..self.index)
            .and_then(<[u8]>::last)
            .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
    }

    /// Consume `//` to the end of the line.
    ///
    /// C and C++ splice a line ending in a backslash onto the next one, and a
    /// comment spliced that way runs on. Rust has no such splice.
    fn line_comment(&mut self) {
        let (start, start_line) = (self.index, self.line);
        self.advance(2);
        while let Some(byte) = self.byte(0) {
            if byte == b'\n' {
                if self.spliced() {
                    self.advance(1);
                    continue;
                }
                break;
            }
            self.advance(1);
        }
        self.record(start, start_line);
    }

    /// Whether the newline at the cursor joins its line to the next one.
    fn spliced(&self) -> bool {
        if matches!(self.language, Language::Rust) {
            return false;
        }
        let before = self.text.as_bytes().get(..self.index).unwrap_or_default();
        let before = before.strip_suffix(b"\r").unwrap_or(before);
        before.last() == Some(&b'\\')
    }

    /// Consume `/* ... */`. Rust nests these; C and C++ do not.
    ///
    /// An unterminated one runs to the end of the file, which is what the
    /// compilers do with it too.
    fn block_comment(&mut self) {
        let (start, start_line) = (self.index, self.line);
        let nests = matches!(self.language, Language::Rust);
        self.advance(2);
        let mut depth = 1usize;
        while self.index < self.text.len() {
            if nests && self.byte(0) == Some(b'/') && self.byte(1) == Some(b'*') {
                depth = depth.saturating_add(1);
                self.advance(2);
                continue;
            }
            if self.byte(0) == Some(b'*') && self.byte(1) == Some(b'/') {
                depth = depth.saturating_sub(1);
                self.advance(2);
                if depth == 0 {
                    break;
                }
                continue;
            }
            self.advance(1);
        }
        self.record(start, start_line);
    }

    /// Consume a literal delimited by `terminator`, honouring backslash
    /// escapes.
    ///
    /// An unterminated one runs to the end of the file: skipping too much can
    /// only lose a marker, whereas stopping early would let the text after it
    /// read as code.
    fn quoted(&mut self, terminator: u8) {
        self.advance(1);
        while let Some(byte) = self.byte(0) {
            if byte == b'\\' {
                self.advance(2);
                continue;
            }
            self.advance(1);
            if byte == terminator {
                return;
            }
        }
    }

    /// Consume a character literal, or step over an apostrophe that is not
    /// one.
    fn character_literal(&mut self) {
        match self.language {
            Language::Rust => self.rust_character_literal(),
            Language::C | Language::Cpp => self.c_character_literal(),
        }
    }

    /// A Rust apostrophe opens a character literal or names a lifetime, and
    /// reading `'static` as a literal would swallow the code after it.
    fn rust_character_literal(&mut self) {
        if self.byte(1) == Some(b'\\') {
            self.quoted(b'\'');
            return;
        }
        let rest = self
            .text
            .get(self.index.saturating_add(1)..)
            .unwrap_or_default();
        let width = rest.chars().next().map_or(0, char::len_utf8);
        // One character followed by a closing quote is a literal; anything
        // else is a lifetime, which is the apostrophe alone.
        if width > 0 && self.byte(width.saturating_add(1)) == Some(b'\'') {
            self.advance(width.saturating_add(2));
        } else {
            self.advance(1);
        }
    }

    /// A C or C++ apostrophe opens a character literal, separates the digits
    /// of a number, or is prose in a preprocessor message.
    fn c_character_literal(&mut self) {
        // `1'000'000`: a separator, not a literal.
        if self.preceded_by_identifier() {
            self.advance(1);
            return;
        }
        // A character literal cannot cross a line, so an apostrophe with no
        // partner on its own line is not one.
        let rest = self
            .text
            .get(self.index.saturating_add(1)..)
            .unwrap_or_default();
        let line = rest.split('\n').next().unwrap_or_default();
        if holds_closing_quote(line) {
            self.quoted(b'\'');
        } else {
            self.advance(1);
        }
    }

    /// Consume a raw string literal at the cursor, reporting whether one was
    /// there.
    ///
    /// A raw string is the one literal whose closing quote need not be the
    /// next one: reading `r#"a "b" // c"#` as an ordinary string would end it
    /// at `"b`, and the rest of the line would then read as code carrying a
    /// comment.
    fn raw_string(&mut self) -> bool {
        if self.preceded_by_identifier() {
            return false;
        }
        match self.language {
            Language::Rust => self.rust_raw_string(),
            Language::Cpp => self.cpp_raw_string(),
            Language::C => false,
        }
    }

    /// `r"..."`, `br"..."` and `cr"..."`, each with any number of `#` pads.
    fn rust_raw_string(&mut self) -> bool {
        let prefix = usize::from(matches!(self.byte(0), Some(b'b' | b'c')));
        if self.byte(prefix) != Some(b'r') {
            return false;
        }
        let opening = prefix.saturating_add(1);
        let mut hashes = 0usize;
        while self.byte(opening.saturating_add(hashes)) == Some(b'#') {
            hashes = hashes.saturating_add(1);
        }
        if self.byte(opening.saturating_add(hashes)) != Some(b'"') {
            return false;
        }
        self.advance(opening.saturating_add(hashes).saturating_add(1));
        while self.index < self.text.len() {
            if self.byte(0) == Some(b'"')
                && (1..=hashes).all(|offset| self.byte(offset) == Some(b'#'))
            {
                self.advance(hashes.saturating_add(1));
                return true;
            }
            self.advance(1);
        }
        true
    }

    /// `R"delimiter( ... )delimiter"`, with any of the encoding prefixes.
    fn cpp_raw_string(&mut self) -> bool {
        let prefix = match (self.byte(0), self.byte(1), self.byte(2)) {
            (Some(b'R'), _, _) => 0usize,
            (Some(b'L' | b'u' | b'U'), Some(b'R'), _) => 1,
            (Some(b'u'), Some(b'8'), Some(b'R')) => 2,
            _ => return false,
        };
        if self.byte(prefix.saturating_add(1)) != Some(b'"') {
            return false;
        }
        let opening = self.index.saturating_add(prefix).saturating_add(2);
        let rest = self.text.get(opening..).unwrap_or_default();
        let Some(length) = rest.find('(') else {
            return false;
        };
        let Some(delimiter) = rest.get(..length) else {
            return false;
        };
        if length > MAX_RAW_STRING_DELIMITER
            || delimiter
                .bytes()
                .any(|byte| byte == b')' || byte == b'\\' || byte.is_ascii_whitespace())
        {
            return false;
        }
        let terminator = format!("){delimiter}\"");
        self.advance(
            prefix
                .saturating_add(2)
                .saturating_add(length)
                .saturating_add(1),
        );
        let body = self.text.get(self.index..).unwrap_or_default();
        let consumed = body
            .find(&terminator)
            .map_or(body.len(), |at| at.saturating_add(terminator.len()));
        self.advance(consumed);
        true
    }
}

/// Whether `line` holds an unescaped apostrophe.
fn holds_closing_quote(line: &str) -> bool {
    let mut bytes = line.as_bytes().iter();
    while let Some(byte) = bytes.next() {
        match byte {
            b'\\' => {
                bytes.next();
            }
            b'\'' => return true,
            _ => {}
        }
    }
    false
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

    /// The marker lines of `text`, read as `language`.
    fn markers(text: &str, language: Language) -> Vec<u32> {
        marker_lines(&FromScannedTree::found(text), language)
    }

    #[test]
    fn marker_lines_are_one_based() {
        let text = "fn a() {}\n// codehelion:ignore\nfn b() {}\n";
        assert_eq!(markers(text, Language::Rust), vec![2]);
        assert!(markers("fn clean() {}\n", Language::Rust).is_empty());
    }

    /// The marker is an instruction only where the language says a comment
    /// is. A project that lists the markers it uses, embeds a template, or
    /// asserts on this tool's own output writes the same characters into a
    /// string, and none of that is a decision to hide anything.
    #[test]
    fn a_marker_in_a_literal_or_an_identifier_suppresses_nothing() {
        let rust = concat!(
            "fn documented() {\n",
            "    let listed = \"codehelion:ignore\";\n",
            "    let escaped = \"say \\\" codehelion:ignore\";\n",
            "    let raw = r#\"a \"quoted\" // codehelion:ignore\"#;\n",
            "    let byte = br\"codehelion:ignore\";\n",
            "    let slash = '/';\n",
            "    let codehelion_ignore_count = 0;\n",
            "}\n",
        );
        assert!(
            markers(rust, Language::Rust).is_empty(),
            "{:?}",
            markers(rust, Language::Rust)
        );

        let c_family = concat!(
            "void documented(void) {\n",
            "    const char *listed = \"codehelion:ignore\";\n",
            "    const char *escaped = \"say \\\" codehelion:ignore\";\n",
            "    char slash = '/';\n",
            "    long grouped = 1'000'000;\n",
            "}\n",
        );
        for language in [Language::C, Language::Cpp] {
            assert!(
                markers(c_family, language).is_empty(),
                "{language:?}: {:?}",
                markers(c_family, language)
            );
        }

        let cpp_raw = "auto embedded = R\"sql(a \"b\" // codehelion:ignore)sql\";\n";
        assert!(markers(cpp_raw, Language::Cpp).is_empty());
    }

    /// Every comment spelling each language has, including a marker trailing
    /// the code it is written about, which is the established way to write
    /// one.
    #[test]
    fn a_marker_in_any_comment_spelling_is_read() {
        let rust = concat!(
            "// codehelion:ignore\n",
            "/// codehelion:ignore\n",
            "/* codehelion:ignore */\n",
            "/*\n",
            " codehelion:ignore\n",
            "*/\n",
            "/* /* codehelion:ignore */ still a comment */\n",
            "let trailing = 1; // codehelion:ignore\n",
        );
        assert_eq!(markers(rust, Language::Rust), vec![1, 2, 3, 5, 7, 8]);

        let c_family = concat!(
            "// codehelion:ignore\n",
            "/* codehelion:ignore */\n",
            "int trailing = 1; /* codehelion:ignore */\n",
        );
        for language in [Language::C, Language::Cpp] {
            assert_eq!(markers(c_family, language), vec![1, 2, 3], "{language:?}");
        }
    }

    /// A lifetime is not a character literal, so the code after one is still
    /// read — a marker written below `'static` has to keep working.
    #[test]
    fn a_rust_lifetime_does_not_swallow_the_comment_after_it() {
        let text = concat!(
            "fn borrow<'a>(value: &'a str) -> &'a str {\n",
            "    // codehelion:ignore\n",
            "    value\n",
            "}\n",
        );
        assert_eq!(markers(text, Language::Rust), vec![2]);
    }

    /// An apostrophe in a preprocessor message is prose, not an unterminated
    /// character literal, and must not swallow the rest of the file.
    #[test]
    fn a_c_apostrophe_outside_a_literal_does_not_swallow_the_file() {
        let text = concat!(
            "#error don't do that\n",
            "// codehelion:ignore\n",
            "int kept(void) { return 0; }\n",
        );
        for language in [Language::C, Language::Cpp] {
            assert_eq!(markers(text, language), vec![2], "{language:?}");
        }
    }

    /// A comment ending in a backslash is spliced onto the next line in C and
    /// C++, so what looks like code below it is still inside the comment.
    /// Rust has no such splice.
    #[test]
    fn a_spliced_line_comment_carries_on_in_c_but_not_in_rust() {
        let text = "// spliced \\\ncodehelion:ignore\n";
        for language in [Language::C, Language::Cpp] {
            assert_eq!(markers(text, language), vec![2], "{language:?}");
        }
        assert!(markers(text, Language::Rust).is_empty());
    }

    /// A file that ends mid-literal is malformed, and reading the rest of it
    /// as comments would let a truncated string open one. Losing a marker is
    /// the safe direction: the finding is reported.
    #[test]
    fn an_unterminated_literal_does_not_open_a_comment() {
        let text = "let broken = \"unterminated\n// codehelion:ignore\n";
        assert!(markers(text, Language::Rust).is_empty());
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
