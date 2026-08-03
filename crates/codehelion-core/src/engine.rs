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

pub use group::{content_entropy_bits, entropy_ratio, group_pairs};
pub use normalize::LiteralNorm;

use crate::clone_class::CloneClass;
use crate::conditional::ArmPath;
use crate::frontend::{Token, Unit};

/// Version of Fast-mode detection and cross-pass consolidation rules.
pub const ENGINE_VERSION: &str = "fast-engine-v1";

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
    /// Upper bound on candidate pairs examined *by each pass*. Pairing is
    /// rarest-first, so exhaustion sacrifices the lowest-signal candidates.
    /// The allowance is per pass rather than shared: the raw pass runs first
    /// and would otherwise be able to spend the whole of it, which stops the
    /// renamed-copy pass finding anything at all.
    pub pair_budget: usize,
    /// Largest number of consecutive statements cut as one candidate fragment.
    pub max_statement_window: usize,
    /// Groups whose normalized content-entropy ratio is below this value are
    /// marked suppressed as degenerate repetition.
    pub entropy_ratio_floor: f64,
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
            entropy_ratio_floor: 0.60,
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
    /// Compact candidate-derived content key retained for deterministic
    /// presentation ordering.
    pub content_key: u64,
    /// Collision-resistant matched-content identity used for grouping.
    pub(crate) content_digest: fingerprint::ContentDigest,
    /// Clone classification.
    pub clone_type: CloneClass,
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
    /// Compact content key retained for deterministic presentation ordering.
    pub content_key: u64,
    /// Clone classification: Type-2 if any member differs in raw text.
    pub clone_type: CloneClass,
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
    /// Malformed or excessively long control headers that did not become
    /// Type-2 body fragments.
    pub control_headers_over_limit: usize,
    /// Fragment classes (≥ 2 members) that entered pairing.
    pub fragment_classes: usize,
    /// Fragment classes dropped for exceeding the posting cap.
    pub class_cap_dropped: usize,
    /// Candidate seed pairs examined by the raw pass.
    pub seed_candidates: usize,
    /// Pairs the raw pass's eligible posting lists held in total.
    ///
    /// Reported beside what was examined so a truncated run says how much of
    /// its work it did. "The budget ran out" is compatible with having skipped
    /// one candidate and with having skipped nine in ten, and those are not
    /// the same result to hand someone.
    pub raw_pairs_available: usize,
    /// Candidate fragment pairs examined by the fragment pass.
    pub fragment_candidates: usize,
    /// Pairs the fragment pass's eligible classes held in total.
    pub fragment_pairs_available: usize,
    /// Verified clone pairs across both passes.
    pub pairs: usize,
    /// Members evicted from a class whose normal form did not match its hash.
    pub hash_collisions: usize,
    /// Whether the pair budget ran out before all candidates were examined.
    pub pair_budget_exhausted: bool,
    /// Candidate pairs that cannot coexist because they occupy alternative
    /// preprocessor arms, or an arm known to be unreachable.
    pub conditional_pairs: usize,
    /// Type-1 groups absorbed by a containing Type-2 group after both passes.
    pub subsumed_groups: usize,
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
    detect_inner(files, None, config)
}

/// Detect clones while excluding pairs separated by C-family preprocessor arms.
///
/// `arm_paths` is parallel to `files`, and each path slice is parallel to its
/// file's token stream. Invalid metadata is ignored rather than causing an
/// analysis failure; the ordinary Fast result is safer than trusting a partial
/// conditional map.
#[must_use]
pub fn detect_with_arm_paths(
    files: &[InputFile<'_>],
    arm_paths: &[Option<&[ArmPath]>],
    config: &EngineConfig,
) -> EngineReport {
    let arm_paths = (arm_paths.len() == files.len()
        && arm_paths
            .iter()
            .zip(files)
            .all(|(paths, file)| paths.is_none_or(|paths| paths.len() == file.tokens.len())))
    .then_some(arm_paths);
    detect_inner(files, arm_paths, config)
}

/// Shared Fast detection implementation, with optional preprocessor context.
fn detect_inner(
    files: &[InputFile<'_>],
    arm_paths: Option<&[Option<&[ArmPath]>]>,
    config: &EngineConfig,
) -> EngineReport {
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

    // One allowance per pass, not one between them. The two passes answer
    // different questions over different candidate spaces, and the raw pass
    // runs first: sharing an allowance lets it spend the whole thing and
    // leave the renamed-copy pass none, which does not slow the mode down —
    // it turns half of it off, and says only that some budget somewhere ran
    // out.
    let mut raw_budget = detect::PairBudget::new(config.pair_budget);
    let mut fragment_budget = detect::PairBudget::new(config.pair_budget);
    let mut pairs = detect::raw_pass(
        files,
        &segments,
        &anchors,
        config,
        &mut stats,
        &mut raw_budget,
    );
    pairs.extend(detect::fragment_pass(
        files,
        &anchors,
        config,
        &mut stats,
        &mut fragment_budget,
    ));
    if let Some(arm_paths) = arm_paths {
        let before = pairs.len();
        pairs.retain(|pair| pair_can_coexist(arm_paths, pair));
        stats.conditional_pairs = before.saturating_sub(pairs.len());
    }
    stats.pairs = pairs.len();
    stats.pair_budget_exhausted = raw_budget.exhausted() || fragment_budget.exhausted();

    let mut groups = group_pairs(&pairs, files, config);
    stats.subsumed_groups = drop_subsumed_type1_groups(&mut groups);
    EngineReport { groups, stats }
}

/// Remove an exact group already represented by a broader renamed class.
///
/// The fragment pass can connect two verbatim instances through a third,
/// renamed instance even though it correctly leaves their direct exact pair
/// to the raw pass. Once grouped, that produces one Type-1 group whose every
/// member occupies the same or a containing/contained range as one member of
/// the Type-2 group. Retaining both would count the shared instances twice.
fn drop_subsumed_type1_groups(groups: &mut Vec<CloneGroup>) -> usize {
    let mut dropped = vec![false; groups.len()];
    for (index, group) in groups.iter().enumerate() {
        if group.clone_type != CloneClass::Type1 {
            continue;
        }
        dropped[index] = groups.iter().any(|outer| {
            outer.clone_type == CloneClass::Type2
                && group.members.iter().all(|member| {
                    outer.members.iter().any(|candidate| {
                        candidate.file == member.file
                            && ((candidate.token_start <= member.token_start
                                && member.token_end <= candidate.token_end)
                                || (member.token_start <= candidate.token_start
                                    && candidate.token_end <= member.token_end))
                    })
                })
        });
    }
    let count = dropped.iter().filter(|&&drop| drop).count();
    let mut position = 0;
    groups.retain(|_| {
        let keep = !dropped[position];
        position += 1;
        keep
    });
    count
}

/// Whether a reported pair can be present in one C-family build.
fn pair_can_coexist(paths: &[Option<&[ArmPath]>], pair: &ClonePair) -> bool {
    let left = paths.get(pair.a.file).and_then(|paths| *paths);
    let right = paths.get(pair.b.file).and_then(|paths| *paths);
    match (left, right) {
        (Some(left), Some(right)) => instance_arm_path(left, &pair.a)
            .zip(instance_arm_path(right, &pair.b))
            .is_none_or(|(left, right)| {
                !left.is_unreachable()
                    && !right.is_unreachable()
                    && (pair.a.file != pair.b.file || !left.excludes(right))
            }),
        _ => true,
    }
}

/// Return a common conditional path only when a match remains in one arm.
fn instance_arm_path<'a>(paths: &'a [ArmPath], instance: &Instance) -> Option<&'a ArmPath> {
    let range = paths.get(instance.token_start..instance.token_end)?;
    let first = range.first()?;
    range.iter().all(|path| path == first).then_some(first)
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
            .filter(|g| g.clone_type == CloneClass::Type1)
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
    fn alternative_preprocessor_arms_do_not_form_a_fast_clone_group() {
        use crate::conditional::{ArmTracker, StaticCondition};

        let first = quick(FN_A);
        let mut tokens = first.clone();
        tokens.extend(quick(FN_A));
        let split = first.len();
        let units = [function_unit(0, split), function_unit(split, tokens.len())];
        let files = [InputFile {
            tokens: &tokens,
            units: &units,
        }];
        let mut tracker = ArmTracker::default();
        tracker.begin(StaticCondition::Unknown);
        let mut paths = vec![tracker.current(); split];
        tracker.next_arm(StaticCondition::Unknown);
        paths.extend(vec![tracker.current(); tokens.len() - split]);

        let report = detect_with_arm_paths(&files, &[Some(&paths)], &EngineConfig::default());
        assert!(report.groups.is_empty(), "groups: {:?}", report.groups);
        assert!(report.stats.conditional_pairs > 0);
    }

    #[test]
    fn literal_false_preprocessor_arm_does_not_form_a_fast_clone_group() {
        use crate::conditional::{ArmTracker, StaticCondition};

        let first = quick(FN_A);
        let mut tokens = first.clone();
        tokens.extend(quick(FN_A));
        let split = first.len();
        let units = [function_unit(0, split), function_unit(split, tokens.len())];
        let files = [InputFile {
            tokens: &tokens,
            units: &units,
        }];
        let mut tracker = ArmTracker::default();
        tracker.begin(StaticCondition::False);
        let mut paths = vec![tracker.current(); split];
        tracker.end();
        paths.extend(vec![tracker.current(); tokens.len() - split]);

        let report = detect_with_arm_paths(&files, &[Some(&paths)], &EngineConfig::default());
        assert!(report.groups.is_empty(), "groups: {:?}", report.groups);
        assert!(report.stats.conditional_pairs > 0);
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
            .filter(|g| g.clone_type == CloneClass::Type2)
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
                .all(|g| g.clone_type != CloneClass::Type1)
        );
    }

    #[test]
    fn a_type2_group_absorbs_its_exact_type1_subset() {
        let first = quick(FN_A);
        let second = quick(FN_A);
        let renamed = quick(FN_A_RENAMED);
        let first_units = [function_unit(0, first.len())];
        let second_units = [function_unit(0, second.len())];
        let renamed_units = [function_unit(0, renamed.len())];
        let files = [
            InputFile {
                tokens: &first,
                units: &first_units,
            },
            InputFile {
                tokens: &second,
                units: &second_units,
            },
            InputFile {
                tokens: &renamed,
                units: &renamed_units,
            },
        ];

        let report = detect(&files, &EngineConfig::default());

        assert_eq!(report.groups.len(), 1, "groups: {:#?}", report.groups);
        assert_eq!(report.groups[0].clone_type, CloneClass::Type2);
        assert_eq!(report.groups[0].members.len(), 3);
        assert_eq!(report.stats.subsumed_groups, 1);
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
    fn a_pair_budget_never_reports_a_partial_candidate_class() {
        // Seven consistently renamed bodies share one Type-2 candidate class
        // with 21 relationships. A budget for only three relationships must
        // omit the entire class, not report an arbitrary three-member group.
        let sources: Vec<Vec<Token>> = (0..7)
            .map(|index| {
                quick(&format!(
                    "fn function_{index} ( ) {{ let local_{index} = input_{index} + delta_{index} ; emit ( local_{index} , input_{index} , delta_{index} ) ; }}"
                ))
            })
            .collect();
        let units: Vec<Vec<Unit>> = sources
            .iter()
            .map(|tokens| vec![function_unit(0, tokens.len())])
            .collect();
        let files: Vec<InputFile<'_>> = sources
            .iter()
            .zip(&units)
            .map(|(tokens, units)| InputFile { tokens, units })
            .collect();
        let complete = EngineConfig {
            min_clone_tokens: 12,
            posting_cap: 7,
            pair_budget: 21,
            ..EngineConfig::default()
        };
        let complete_report = detect(&files, &complete);
        let complete_groups: Vec<_> = complete_report
            .groups
            .iter()
            .filter(|group| group.clone_type == CloneClass::Type2)
            .collect();
        assert_eq!(complete_groups.len(), 1, "groups: {complete_groups:#?}");
        assert_eq!(complete_groups[0].members.len(), 7);

        let truncated = EngineConfig {
            pair_budget: 3,
            ..complete
        };
        let truncated_report = detect(&files, &truncated);
        assert!(truncated_report.stats.pair_budget_exhausted);
        assert_eq!(truncated_report.stats.fragment_pairs_available, 21);
        assert_eq!(truncated_report.stats.fragment_candidates, 0);
        assert!(
            truncated_report.groups.is_empty(),
            "a partial class must not become a smaller group: {:?}",
            truncated_report.groups
        );

        // Fast-mode Type-1 seeding uses the same whole-class rule. The
        // repeated source yields several eligible winnow lists, each with
        // seven members; none may leak a three-member prefix.
        let repeated = quick(FN_A);
        let repeated_units = vec![function_unit(0, repeated.len())];
        let repeated_files: Vec<InputFile<'_>> = (0..7)
            .map(|_| InputFile {
                tokens: &repeated,
                units: &repeated_units,
            })
            .collect();
        let raw_report = detect(&repeated_files, &truncated);
        assert!(raw_report.stats.pair_budget_exhausted);
        assert!(raw_report.stats.raw_pairs_available >= 21);
        assert_eq!(raw_report.stats.seed_candidates, 0);
        assert!(
            raw_report.groups.is_empty(),
            "groups: {:?}",
            raw_report.groups
        );
    }

    /// The pass that finds renamed copies must not be starved by the pass
    /// that finds verbatim ones.
    ///
    /// The raw pass runs first over a much larger candidate space. Sharing one
    /// allowance between the two means that on any sizeable tree the raw pass
    /// spends all of it, and renamed-copy detection — half of what the mode
    /// claims to do — quietly stops happening. The report would say a budget
    /// ran out, which reads as "some low-signal candidates were skipped", not
    /// as "one of the two detectors did not run".
    #[test]
    fn spending_the_allowance_on_verbatim_copies_still_leaves_renamed_ones_found() {
        // Eight copies of one function give the raw pass far more seeds than
        // the allowance covers; the renamed copy of another function is
        // reachable only through the fragment pass.
        let mut sources = vec![
            quick(&format!("{FN_A} {FN_OTHER}")),
            quick(&format!("{FN_A_RENAMED} {FN_OTHER}")),
        ];
        sources.extend((0..6).map(|_| quick(FN_OTHER)));
        let units: Vec<Vec<Unit>> = sources
            .iter()
            .enumerate()
            .map(|(index, tokens)| {
                if index < 2 {
                    vec![function_unit(0, 26), function_unit(26, tokens.len())]
                } else {
                    vec![function_unit(0, tokens.len())]
                }
            })
            .collect();
        let files: Vec<InputFile<'_>> = sources
            .iter()
            .zip(&units)
            .map(|(tokens, units)| InputFile { tokens, units })
            .collect();
        let config = EngineConfig {
            pair_budget: 20,
            ..EngineConfig::default()
        };
        let report = detect(&files, &config);
        assert!(
            report.stats.pair_budget_exhausted,
            "the allowance has to run out for this to be measuring anything"
        );
        let found: Vec<CloneClass> = report.groups.iter().map(|group| group.clone_type).collect();
        assert!(
            found.contains(&CloneClass::Type2),
            "the renamed copy is still found: {found:?}"
        );
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
