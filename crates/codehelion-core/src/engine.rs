//! The Fast-mode clone-detection engine.
//!
//! Input is the lexed token stream and unit boundaries of every file in
//! scope; output is a set of clone groups with per-group noise signals and
//! run statistics. Two passes run over the input:
//!
//! - a **raw pass** that finds Type-1 (verbatim) clones anywhere — winnowed
//!   k-gram fingerprints seed candidates, each seed is verified token-by-token
//!   and extended to a maximal run bounded by function boundaries;
//! - a **fragment pass** that finds Type-2 (consistently renamed) clones —
//!   candidate fragments are normalized scope-locally and matched whole, so a
//!   renamed statement run transplanted into an unrelated host function still
//!   matches its origin.
//!
//! The engine never executes the code it reads, uses no randomness, and sorts
//! every output deterministically: the same input produces the same report,
//! token by token. Candidate-explosion controls (posting caps, a global pair
//! budget, rarest-first pairing) act before the quadratic pairing step, and
//! everything they drop is counted in [`EngineStats`] rather than vanishing.

pub mod fingerprint;
pub mod normalize;

mod detect;
mod group;
mod segment;

pub use group::group_pairs;
pub use normalize::LiteralNorm;

use crate::frontend::{Token, Unit};

/// One lexed file, as the engine consumes it.
///
/// The `file` index of every [`Instance`] in the report refers to the position
/// of its file in the slice passed to [`detect`].
#[derive(Debug, Clone, Copy)]
pub struct InputFile<'a> {
    /// The file's token stream.
    pub tokens: &'a [Token],
    /// The file's unit boundaries, used as barriers and report anchors.
    pub units: &'a [Unit],
}

/// Engine tuning. The defaults are the evaluated configuration.
#[derive(Debug, Clone)]
pub struct EngineConfig {
    /// Smallest clone length in tokens; also the k-gram length.
    pub min_clone_tokens: usize,
    /// Winnowing window: every run of at least `winnow_window +
    /// min_clone_tokens - 1` shared tokens is guaranteed a shared fingerprint.
    pub winnow_window: usize,
    /// Literal-normalization strategy for the Type-2 pass.
    pub literals: LiteralNorm,
    /// Longest posting list (raw pass) or fragment class (Type-2 pass) that
    /// still enters pairing; longer ones are dropped and counted.
    pub posting_cap: usize,
    /// Upper bound on candidate pairs examined across both passes. Pairing is
    /// rarest-first, so exhaustion sacrifices the lowest-signal candidates.
    pub pair_budget: usize,
    /// Largest number of consecutive statements cut as one candidate fragment.
    pub max_statement_window: usize,
    /// Groups whose content entropy is below this many bits are marked
    /// suppressed as degenerate repetition.
    pub entropy_floor: f64,
    /// Groups with more members than this are marked suppressed as recurring
    /// boilerplate.
    pub degree_cap: usize,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            min_clone_tokens: 20,
            winnow_window: 4,
            literals: LiteralNorm::Full,
            posting_cap: 64,
            pair_budget: 1_000_000,
            max_statement_window: 8,
            entropy_floor: 3.9,
            degree_cap: 16,
        }
    }
}

/// One occurrence of matched content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Instance {
    /// Index of the file in the input slice.
    pub file: usize,
    /// First matched token.
    pub token_start: usize,
    /// One past the last matched token.
    pub token_end: usize,
    /// 1-based first line, for reporting.
    pub start_line: u32,
    /// 1-based last line, for reporting.
    pub end_line: u32,
    /// Index into the file's `units` of the innermost enclosing unit, when
    /// the match sits inside one; the report anchor for partial clones.
    pub unit: Option<usize>,
}

/// Clone classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloneType {
    /// Verbatim copy (formatting and comments aside).
    Type1,
    /// Copy with consistent renames and/or changed literals.
    Type2,
}

impl CloneType {
    /// Stable lowercase identifier used in reports.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Type1 => "type-1",
            Self::Type2 => "type-2",
        }
    }
}

/// Why a group was marked suppressed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuppressReason {
    /// Content entropy below the floor: degenerate repetition.
    LowEntropy,
    /// More instances than the degree cap: recurring boilerplate.
    HighFrequency,
}

impl SuppressReason {
    /// Stable lowercase identifier used in reports.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::LowEntropy => "low-entropy",
            Self::HighFrequency => "high-frequency",
        }
    }
}

/// A verified match between two instances of the same content.
#[derive(Debug, Clone)]
pub struct ClonePair {
    /// Hash of the matched content; pairs with equal keys carry identical
    /// content and merge into one group.
    pub content_key: u64,
    /// Clone classification.
    pub clone_type: CloneType,
    /// Fraction of positions whose raw text also matches (1.0 for Type-1).
    pub score: f64,
    /// First instance (smaller `(file, token_start)`).
    pub a: Instance,
    /// Second instance.
    pub b: Instance,
}

/// A set of instances sharing identical matched content.
#[derive(Debug, Clone)]
pub struct CloneGroup {
    /// Hash of the shared content.
    pub content_key: u64,
    /// Clone classification: Type-2 if any member differs in raw text.
    pub clone_type: CloneType,
    /// Minimum pairwise raw-text similarity across the group (1.0 for Type-1).
    pub score: f64,
    /// Deduplicated instances, sorted by `(file, token range)`; the first
    /// member is the canonical instance.
    pub members: Vec<Instance>,
    /// Shannon entropy of the content's normalized-token distribution.
    pub entropy_bits: f64,
    /// Noise marker, if a suppression signal fired. The group is still
    /// reported; presentation decides what to do with marked groups.
    pub suppressed: Option<SuppressReason>,
}

/// Counters describing what a detection run saw and dropped.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EngineStats {
    /// Files analysed.
    pub files: usize,
    /// Tokens across all files.
    pub tokens: usize,
    /// Winnowed fingerprints indexed by the raw pass.
    pub raw_fingerprints: usize,
    /// Distinct fingerprint values in the raw index.
    pub raw_distinct: usize,
    /// Distinct fingerprints dropped for exceeding the posting cap.
    pub stop_fingerprints: usize,
    /// Postings dropped with them.
    pub stop_postings: usize,
    /// Candidate fragments cut for the Type-2 pass.
    pub fragments: usize,
    /// Fragment classes (≥ 2 members) that entered pairing.
    pub fragment_classes: usize,
    /// Fragment classes dropped for exceeding the posting cap.
    pub class_cap_dropped: usize,
    /// Candidate seed pairs examined by the raw pass.
    pub seed_candidates: usize,
    /// Verified clone pairs across both passes.
    pub pairs: usize,
    /// Members evicted from a class whose normal form did not match its hash.
    pub hash_collisions: usize,
    /// Whether the pair budget ran out before all candidates were examined.
    pub pair_budget_exhausted: bool,
}

/// The engine's output: clone groups plus run statistics.
#[derive(Debug, Clone)]
pub struct EngineReport {
    /// Detected clone groups, deterministically ordered.
    pub groups: Vec<CloneGroup>,
    /// What the run saw and dropped.
    pub stats: EngineStats,
}

/// Detect clones across `files`.
///
/// The result is a pure function of the input: file order only affects the
/// `file` indices inside instances, and every collection in the report is
/// deterministically sorted.
#[must_use]
pub fn detect(files: &[InputFile<'_>], config: &EngineConfig) -> EngineReport {
    let mut stats = EngineStats {
        files: files.len(),
        tokens: files.iter().map(|f| f.tokens.len()).sum(),
        ..EngineStats::default()
    };

    let segments: Vec<Vec<segment::SegmentId>> = files
        .iter()
        .map(|f| segment::segment_ids(f.tokens, f.units))
        .collect();
    let anchors: Vec<Vec<Option<usize>>> = files
        .iter()
        .map(|f| segment::anchor_ids(f.tokens, f.units))
        .collect();

    let mut budget = detect::PairBudget::new(config.pair_budget);
    let mut pairs = detect::raw_pass(files, &segments, &anchors, config, &mut stats, &mut budget);
    pairs.extend(detect::fragment_pass(
        files,
        &anchors,
        config,
        &mut stats,
        &mut budget,
    ));
    stats.pairs = pairs.len();
    stats.pair_budget_exhausted = budget.exhausted();

    let groups = group_pairs(&pairs, files, config);
    EngineReport { groups, stats }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::frontend::{SourceSpan, TokenKind, UnitKind};

    /// Tokenize a whitespace-separated pseudo-source: known keywords become
    /// keywords, words become identifiers, digit-words become integer
    /// literals, everything else punctuation. One word per line for stable
    /// line numbers.
    fn quick(src: &str) -> Vec<Token> {
        src.split_whitespace()
            .enumerate()
            .map(|(i, w)| {
                let kind = match w {
                    "fn" | "let" | "for" | "while" | "loop" | "if" | "else" | "match" | "in"
                    | "return" => TokenKind::Keyword,
                    _ if w.chars().all(|c| c.is_ascii_digit()) => {
                        TokenKind::Literal(crate::frontend::LiteralKind::Integer)
                    }
                    _ if w
                        .chars()
                        .next()
                        .is_some_and(|c| c.is_alphabetic() || c == '_') =>
                    {
                        TokenKind::Identifier
                    }
                    _ => TokenKind::Punctuation,
                };
                Token {
                    kind,
                    text: w.into(),
                    span: SourceSpan {
                        start_byte: i,
                        end_byte: i + 1,
                        start_line: u32::try_from(i).unwrap_or(u32::MAX) + 1,
                        start_column: 1,
                    },
                }
            })
            .collect()
    }

    fn function_unit(token_start: usize, token_end: usize) -> Unit {
        Unit {
            kind: UnitKind::Function,
            name: None,
            token_start,
            token_end,
            span: SourceSpan {
                start_byte: 0,
                end_byte: 0,
                start_line: 1,
                start_column: 1,
            },
        }
    }

    /// A 24-token function with distinctive content and no internal repetition.
    const FN_A: &str =
        "fn alpha ( ) { let acc = base + rate * step ; emit ( acc , base , rate , step ) ; }";
    /// The same function with every local consistently renamed.
    const FN_A_RENAMED: &str =
        "fn beta ( ) { let sum = seed + gain * width ; emit ( sum , seed , gain , width ) ; }";
    /// An unrelated function of similar length.
    const FN_OTHER: &str = "fn omega ( ) { while cursor < bound { cursor = cursor + probe ; } yield_all ( cursor , bound ) ; }";

    #[test]
    fn empty_input_yields_an_empty_report() {
        let report = detect(&[], &EngineConfig::default());
        assert!(report.groups.is_empty());
        assert_eq!(report.stats.files, 0);
    }

    #[test]
    fn verbatim_functions_across_files_form_a_type1_group() {
        let a = quick(&format!("{FN_A} {FN_OTHER}"));
        let b = quick(FN_A);
        let units_a = vec![function_unit(0, 24), function_unit(24, a.len())];
        let units_b = vec![function_unit(0, 24)];
        let files = [
            InputFile {
                tokens: &a,
                units: &units_a,
            },
            InputFile {
                tokens: &b,
                units: &units_b,
            },
        ];
        let report = detect(&files, &EngineConfig::default());
        let type1: Vec<_> = report
            .groups
            .iter()
            .filter(|g| g.clone_type == CloneType::Type1)
            .collect();
        assert_eq!(type1.len(), 1, "groups: {:?}", report.groups);
        let group = type1[0];
        assert_eq!(group.members.len(), 2);
        assert_eq!(group.members[0].file, 0);
        assert_eq!(group.members[1].file, 1);
        // The match is anchored to the enclosing function on both sides.
        assert_eq!(group.members[0].unit, Some(0));
        assert!((group.score - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn renamed_function_bodies_form_a_type2_group() {
        let a = quick(FN_A);
        let b = quick(FN_A_RENAMED);
        let units_a = vec![function_unit(0, a.len())];
        let units_b = vec![function_unit(0, b.len())];
        let files = [
            InputFile {
                tokens: &a,
                units: &units_a,
            },
            InputFile {
                tokens: &b,
                units: &units_b,
            },
        ];
        let report = detect(&files, &EngineConfig::default());
        let type2: Vec<_> = report
            .groups
            .iter()
            .filter(|g| g.clone_type == CloneType::Type2)
            .collect();
        assert_eq!(type2.len(), 1, "groups: {:?}", report.groups);
        let group = type2[0];
        assert_eq!(group.members.len(), 2);
        assert!(group.score < 1.0, "renames must lower raw similarity");
        // No Type-1 group: the renames leave no 20-token verbatim run.
        assert!(
            report
                .groups
                .iter()
                .all(|g| g.clone_type != CloneType::Type1)
        );
    }

    #[test]
    fn unrelated_functions_do_not_match() {
        let a = quick(FN_A);
        let b = quick(FN_OTHER);
        let units_a = vec![function_unit(0, a.len())];
        let units_b = vec![function_unit(0, b.len())];
        let files = [
            InputFile {
                tokens: &a,
                units: &units_a,
            },
            InputFile {
                tokens: &b,
                units: &units_b,
            },
        ];
        let report = detect(&files, &EngineConfig::default());
        assert!(report.groups.is_empty(), "groups: {:?}", report.groups);
    }

    #[test]
    fn intra_file_duplicates_are_found() {
        let src = format!("{FN_A} {FN_A}");
        let tokens = quick(&src);
        let units = vec![function_unit(0, 24), function_unit(24, 48)];
        let files = [InputFile {
            tokens: &tokens,
            units: &units,
        }];
        let report = detect(&files, &EngineConfig::default());
        assert_eq!(report.groups.len(), 1);
        assert_eq!(report.groups[0].members.len(), 2);
        assert_eq!(report.groups[0].members[0].file, 0);
        assert_eq!(report.groups[0].members[1].file, 0);
    }

    #[test]
    fn maximal_runs_stop_at_function_boundaries() {
        // Two identical files, each holding two identical adjacent functions:
        // the match must not fuse across the boundary into one giant run.
        let src = format!("{FN_A} {FN_A}");
        let a = quick(&src);
        let b = quick(&src);
        let units = vec![function_unit(0, 24), function_unit(24, 48)];
        let files = [
            InputFile {
                tokens: &a,
                units: &units,
            },
            InputFile {
                tokens: &b,
                units: &units,
            },
        ];
        let report = detect(&files, &EngineConfig::default());
        for group in &report.groups {
            for member in &group.members {
                assert!(
                    member.token_end - member.token_start <= 24,
                    "run crossed a function boundary: {member:?}"
                );
            }
        }
    }

    #[test]
    fn exhausted_pair_budget_is_reported_not_silent() {
        let a = quick(FN_A);
        let b = quick(FN_A);
        let units_a = vec![function_unit(0, a.len())];
        let units_b = vec![function_unit(0, b.len())];
        let files = [
            InputFile {
                tokens: &a,
                units: &units_a,
            },
            InputFile {
                tokens: &b,
                units: &units_b,
            },
        ];
        let config = EngineConfig {
            pair_budget: 0,
            ..EngineConfig::default()
        };
        let report = detect(&files, &config);
        assert!(report.stats.pair_budget_exhausted);
        assert!(report.groups.is_empty());
    }

    #[test]
    fn posting_cap_drops_and_counts_high_frequency_fingerprints() {
        let a = quick(FN_A);
        let units: Vec<Unit> = vec![function_unit(0, a.len())];
        let many: Vec<InputFile<'_>> = (0..3)
            .map(|_| InputFile {
                tokens: &a,
                units: &units,
            })
            .collect();
        let config = EngineConfig {
            posting_cap: 1,
            ..EngineConfig::default()
        };
        let report = detect(&many, &config);
        assert!(report.stats.stop_fingerprints > 0);
        assert!(report.stats.stop_postings > 0);
    }

    #[test]
    fn degenerate_repetition_is_marked_low_entropy() {
        // 30 identical tokens: entropy 0, still reported but marked.
        let src = "x ".repeat(30);
        let a = quick(&src);
        let b = quick(&src);
        let files = [
            InputFile {
                tokens: &a,
                units: &[],
            },
            InputFile {
                tokens: &b,
                units: &[],
            },
        ];
        let report = detect(&files, &EngineConfig::default());
        assert!(!report.groups.is_empty());
        assert_eq!(
            report.groups[0].suppressed,
            Some(SuppressReason::LowEntropy)
        );
    }

    #[test]
    fn detection_is_deterministic() {
        let a = quick(&format!("{FN_A} {FN_OTHER}"));
        let b = quick(FN_A_RENAMED);
        let units_a = vec![function_unit(0, 24), function_unit(24, a.len())];
        let units_b = vec![function_unit(0, b.len())];
        let files = [
            InputFile {
                tokens: &a,
                units: &units_a,
            },
            InputFile {
                tokens: &b,
                units: &units_b,
            },
        ];
        let first = detect(&files, &EngineConfig::default());
        let second = detect(&files, &EngineConfig::default());
        assert_eq!(first.stats, second.stats);
        assert_eq!(first.groups.len(), second.groups.len());
        for (x, y) in first.groups.iter().zip(second.groups.iter()) {
            assert_eq!(x.content_key, y.content_key);
            assert_eq!(x.members, y.members);
        }
    }
}
