use super::*;
use crate::features::{
    ApiCallFeature, CfgFeature, CharacteristicVector, FeatureHash, SubtreeFeature, UnitFeatures,
    WindowFeature,
};
use crate::frontend::Lexeme;
use crate::ir::ByteRange;
use crate::types::{ApiEvidence, TypeTag};

/// A statement with no text of its own. Enough for the tests that only
/// exercise alignment, which reads shapes and never the tokens.
fn summary(shape_tag: u8) -> StatementSummary {
    StatementSummary {
        shape_tag,
        native_kind: None,
        token_start: 0,
        token_end: 0,
    }
}

/// A statement sequence and the token stream it spans, built together: a
/// statement's span is only meaningful against the stream it was cut from,
/// so a test that cares about text has to own both.
struct Statements {
    tokens: Vec<Token>,
    summaries: Vec<StatementSummary>,
}

impl Statements {
    fn view<'a>(&'a self, features: &'a UnitFeatures) -> UnitView<'a> {
        UnitView {
            statements: &self.summaries,
            tokens: &self.tokens,
            content: FragmentFingerprint::from_bytes(
                [u8::try_from(self.tokens.len()).unwrap_or(u8::MAX); 16],
            ),
            features,
            types: None,
            apis: None,
        }
    }

    fn view_typed<'a>(
        &'a self,
        features: &'a UnitFeatures,
        types: &'a TypeEvidence,
    ) -> UnitView<'a> {
        UnitView {
            types: Some(types),
            ..self.view(features)
        }
    }

    fn view_with_apis<'a>(
        &'a self,
        features: &'a UnitFeatures,
        apis: &'a ApiEvidence,
    ) -> UnitView<'a> {
        UnitView {
            apis: Some(apis),
            ..self.view(features)
        }
    }
}

/// Build statements from `(shape tag, token texts)` pairs, laying the
/// tokens out consecutively.
fn statements(spec: &[(u8, &[&str])]) -> Statements {
    let mut built = Statements {
        tokens: Vec::new(),
        summaries: Vec::new(),
    };
    for &(shape_tag, texts) in spec {
        let token_start = built.tokens.len();
        for text in texts {
            let start_byte = built.tokens.len() * 8;
            built.tokens.push(Token {
                kind: crate::frontend::TokenKind::Identifier,
                text: Lexeme::from(*text),
                span: crate::frontend::SourceSpan {
                    start_byte,
                    end_byte: start_byte + text.len(),
                    start_line: 1,
                    start_column: 1,
                },
            });
        }
        built.summaries.push(StatementSummary {
            shape_tag,
            native_kind: None,
            token_start,
            token_end: built.tokens.len(),
        });
    }
    built
}

/// Features with a chosen characteristic vector, subtree-hash set, cfg hash
/// and api names, enough to drive each dimension.
fn features(vector_counts: [u32; 23], subtrees: &[u8], cfg: u8, api: &[&str]) -> UnitFeatures {
    let subtrees = subtrees
        .iter()
        .map(|&seed| SubtreeFeature {
            hash: FeatureHash::from_bytes([seed; 16]),
            node_count: 6,
            range: ByteRange { start: 0, end: 8 },
        })
        .collect();
    UnitFeatures {
        name: None,
        shape_tag: 1,
        range: ByteRange { start: 0, end: 100 },
        windows: Vec::<WindowFeature>::new(),
        subtrees,
        vector: CharacteristicVector {
            counts: vector_counts,
            max_depth: 4,
            node_count: vector_counts.iter().sum(),
        },
        cfg: CfgFeature {
            hash: FeatureHash::from_bytes([cfg; 16]),
            skeleton_hash: FeatureHash::from_bytes([cfg; 16]),
            op_count: 5,
            skeleton_ops: 5,
            max_loop_depth: 1,
            branch_count: 1,
        },
        api: ApiCallFeature {
            names: api.iter().map(|n| Lexeme::from(*n)).collect(),
            sequence_hash: FeatureHash::from_bytes([0; 16]),
            multiset_hash: FeatureHash::from_bytes([0; 16]),
        },
    }
}

/// Remove feature families that did not produce comparable evidence.
fn without_control_flow_or_subtrees(mut features: UnitFeatures) -> UnitFeatures {
    features.subtrees.clear();
    features.cfg = CfgFeature {
        hash: FeatureHash::from_bytes([0; 16]),
        skeleton_hash: FeatureHash::from_bytes([0; 16]),
        op_count: 0,
        skeleton_ops: 0,
        max_loop_depth: 0,
        branch_count: 0,
    };
    features
}

fn counts(fill: u32) -> [u32; 23] {
    let mut c = [0u32; 23];
    c[1] = fill;
    c[6] = fill / 2;
    c
}

#[test]
fn identical_units_are_a_type1_clone() {
    let stmts = statements(&[(3, &["if", "x"]), (12, &["let", "y"])]);
    let feats = features(counts(4), &[1, 2, 3], 9, &["push", "len"]);
    let view = stmts.view(&feats);
    let verdict = verify(&view, &view, &VerifyConfig::default());
    assert_eq!(verdict.class, Some(CloneClass::Type1));
    assert_eq!(verdict.confidence, Some(Confidence::High));
    assert!((verdict.breakdown.composite - 1.0).abs() < 1e-9);
    assert!(verdict.alignment.only_a.is_empty());
    assert!(verdict.alignment.only_b.is_empty());
}

#[test]
fn low_lexical_structural_match_is_not_a_type2_clone() {
    let a = statements(&[(3, &["if", "acc"]), (12, &["let", "count"])]);
    let b = statements(&[(3, &["if", "state"]), (12, &["let", "seen"])]);
    let feats = features(counts(4), &[1, 2, 3], 9, &["push"]);
    let va = a.view(&feats);
    let vb = b.view(&feats);
    let verdict = verify(&va, &vb, &VerifyConfig::default());
    assert_eq!(verdict.class, Some(CloneClass::Type3));
    assert!(verdict.breakdown.lexical < VerifyConfig::default().type2_min_lexical);
    assert!((verdict.breakdown.structural - 1.0).abs() < 1e-9);
}

#[test]
fn a_rename_past_the_opening_tokens_still_shows_in_the_text() {
    // The two statements open identically and diverge only afterwards.
    // Reading a fixed number of leading tokens would call this pair
    // verbatim and hand it a Type-1 classification, which asserts the two
    // units differ in nothing but whitespace — a claim this pair does not
    // support. The whole statement is compared for exactly this reason.
    let a = statements(&[(12, &["let", "total", "=", "first", "+", "second"])]);
    let b = statements(&[(12, &["let", "total", "=", "first", "-", "third"])]);
    let feats = features(counts(4), &[1, 2, 3], 9, &[]);
    let verdict = verify(&a.view(&feats), &b.view(&feats), &VerifyConfig::default());
    assert!(
        verdict.breakdown.lexical < 1.0,
        "the divergence past the opening tokens must show, got {}",
        verdict.breakdown.lexical
    );
    assert_ne!(verdict.class, Some(CloneClass::Type1));
    // Four of the six tokens still agree, so this is a near-copy, not a
    // pair with nothing in common.
    assert!((verdict.breakdown.lexical - 4.0 / 6.0).abs() < 1e-9);
}

#[test]
fn a_compound_statement_is_compared_over_everything_it_encloses() {
    // A statement's span covers its body, so two loops that open the same
    // way but enclose different code do not read as the same statement.
    let a = statements(&[(7, &["for", "row", "in", "rows", "total", "+=", "row"])]);
    let b = statements(&[(7, &["for", "row", "in", "rows", "widest", "=", "row"])]);
    let feats = features(counts(4), &[1, 2, 3], 9, &[]);
    let verdict = verify(&a.view(&feats), &b.view(&feats), &VerifyConfig::default());
    // The four header tokens and the trailing operand agree; the two the
    // body differs in do not. Had only the header been read, the pair
    // would have scored a verbatim match on a body that was rewritten.
    assert!(
        (verdict.breakdown.lexical - 5.0 / 7.0).abs() < 1e-9,
        "five of the seven tokens agree, got {}",
        verdict.breakdown.lexical
    );
}

#[test]
fn a_renamed_call_surface_is_type2_however_quiet_the_heads_are() {
    // Both sides read identically and their structure is identical, so
    // the only dimension carrying the rename is the call surface. This is
    // the case the api dimension exists for: the statements cannot show a
    // difference the features do.
    let stmts = statements(&[(3, &["let", "x", "=", "y"])]);
    let fa = features(counts(4), &[1, 2, 3], 9, &["abs", "min"]);
    let fb = features(counts(4), &[1, 2, 3], 9, &["signum", "rem_euclid"]);
    let va = stmts.view(&fa);
    let vb = stmts.view(&fb);
    let verdict = verify(&va, &vb, &VerifyConfig::default());
    assert!((verdict.breakdown.lexical - 1.0).abs() < 1e-9);
    assert!((verdict.breakdown.structural - 1.0).abs() < 1e-9);
    assert_eq!(verdict.breakdown.api, Some(0.0));
    assert_eq!(verdict.class, Some(CloneClass::Type2));
}

#[test]
fn two_call_free_units_have_no_api_dimension_rather_than_a_perfect_one() {
    // Neither unit calls anything, so there is no call surface to compare.
    // Scoring that as agreement would hand the dimension's whole weight to
    // every pair of call-free units on no evidence, which is exactly the
    // shape of code — small helpers — where a false positive is cheapest
    // to produce.
    let a = statements(&[(12, &["let", "total"]), (4, &["return"])]);
    let b = statements(&[(12, &["let", "count"]), (4, &["return"])]);
    let fa = features(counts(4), &[1, 2, 3], 9, &[]);
    let fb = features(counts(5), &[1, 2, 4], 8, &[]);
    let va = a.view(&fa);
    let vb = b.view(&fb);
    let verdict = verify(&va, &vb, &VerifyConfig::default());
    assert_eq!(verdict.breakdown.api, None);

    // The composite is the mean over what was measured, so the absent
    // dimension does not quietly pull the score towards 1.0.
    let weights = Weights::default();
    let measured = weights.lexical + weights.structural + weights.control_flow;
    let expected = weights.lexical.mul_add(
        verdict.breakdown.lexical,
        weights.structural.mul_add(
            verdict.breakdown.structural,
            weights.control_flow * verdict.breakdown.control_flow.unwrap(),
        ),
    ) / measured;
    assert!((verdict.breakdown.composite - expected).abs() < 1e-9);
}

#[test]
fn empty_cfg_and_subtrees_do_not_create_a_type3_finding() {
    // These straight-line units have no control-flow operations and are
    // both below `MIN_SUBTREE_NODES`. Treating either empty feature family
    // as a perfect match used to push this otherwise below-threshold pair
    // across the Type-3 boundary.
    let a = statements(&[(12, &["let", "total", "=", "first", ";"])]);
    let b = statements(&[(12, &["let", "count", "=", "first", ";"])]);
    let mut a_counts = [0; 23];
    a_counts[1] = 1;
    let mut b_counts = [0; 23];
    b_counts[1] = 1;
    b_counts[2] = 4;
    let fa = without_control_flow_or_subtrees(features(a_counts, &[], 1, &[]));
    let fb = without_control_flow_or_subtrees(features(b_counts, &[], 2, &[]));
    let config = VerifyConfig::default();
    let verdict = verify(&a.view(&fa), &b.view(&fb), &config);

    assert_eq!(verdict.breakdown.control_flow, None);
    assert_eq!(verdict.breakdown.api, None);
    assert!(verdict.breakdown.composite < config.type3_min_composite);
    assert_eq!(verdict.class, None);

    let former_score = composite(
        &config.weights,
        verdict.breakdown.lexical,
        verdict.breakdown.structural,
        Some(1.0),
        None,
        None,
    );
    assert!(former_score >= config.type3_min_composite);
}

#[test]
fn a_call_free_verbatim_copy_is_still_a_type1_clone() {
    // An absent dimension is not evidence against the strong claim: with
    // nothing to compare, it cannot contradict identical structure and
    // identical heads.
    let stmts = statements(&[(12, &["let", "total"]), (4, &["return"])]);
    let feats = features(counts(4), &[1, 2, 3], 9, &[]);
    let view = stmts.view(&feats);
    let verdict = verify(&view, &view, &VerifyConfig::default());
    assert_eq!(verdict.breakdown.api, None);
    assert_eq!(verdict.class, Some(CloneClass::Type1));
    assert!((verdict.breakdown.composite - 1.0).abs() < 1e-9);
}

#[test]
fn a_pair_scores_the_same_whichever_unit_leads() {
    // `a` opens with a `let` the other side lacks and continues with `let`s
    // that repeat, so two alignments are equally long: one skips `a`'s
    // opening statement and matches the repeated ones verbatim, the other
    // matches the opening statement and pays for its differing head. Which
    // one the recurrence settles on follows the order of the arguments, so
    // the lexical dimension moves with it.
    let a = statements(&[
        (12, &["let", "seen"]),
        (12, &["let", "total"]),
        (12, &["let", "total"]),
        (12, &["let", "total"]),
    ]);
    let b = statements(&[
        (4, &["return", "total"]),
        (12, &["let", "total"]),
        (12, &["let", "total"]),
    ]);
    let fa = features(counts(6), &[1, 2, 3, 4], 9, &["push"]);
    let fb = features(counts(5), &[1, 2, 3], 8, &["push"]);
    let va = a.view(&fa);
    let vb = b.view(&fb);
    let forward = verify(&va, &vb, &VerifyConfig::default());
    let backward = verify(&vb, &va, &VerifyConfig::default());
    assert_eq!(forward.breakdown, backward.breakdown);
    assert_eq!(forward.class, backward.class);
    assert_eq!(forward.confidence, backward.confidence);
    // The alignment is reported from the caller's side either way.
    assert_eq!(forward.alignment.only_a, backward.alignment.only_b);
    assert_eq!(forward.alignment.only_b, backward.alignment.only_a);
    let mirrored: Vec<(usize, usize)> = backward
        .alignment
        .matched
        .iter()
        .map(|&(i, j)| (j, i))
        .collect();
    assert_eq!(forward.alignment.matched, mirrored);
}

#[test]
fn content_fingerprint_breaks_feature_ordering_ties() {
    let statements = statements(&[(12, &["let", "total"])]);
    let features = features(counts(2), &[1, 2], 9, &[]);
    let mut first = statements.view(&features);
    let mut second = statements.view(&features);
    first.content = FragmentFingerprint::from_bytes([1; 16]);
    second.content = FragmentFingerprint::from_bytes([2; 16]);

    assert!(order_key(&first) < order_key(&second));
    assert!(
        order_key(&second) > order_key(&first),
        "the final tiebreak is position-free content, never caller order"
    );
}

#[test]
fn a_gapped_edit_is_a_type3_clone_and_the_gap_shows_in_the_alignment() {
    // b has one extra leading statement; the rest align.
    let a = statements(&[(3, &["if"]), (12, &["let"]), (4, &["return"])]);
    let b = statements(&[
        (11, &["loop"]),
        (3, &["if"]),
        (12, &["let"]),
        (4, &["return"]),
    ]);
    let fa = features(counts(6), &[1, 2, 3, 4], 9, &["push", "len"]);
    let fb = features(counts(7), &[1, 2, 3, 5], 8, &["push", "len", "clear"]);
    let va = a.view(&fa);
    let vb = b.view(&fb);
    let verdict = verify(&va, &vb, &VerifyConfig::default());
    assert_eq!(verdict.class, Some(CloneClass::Type3));
    // The type dimension is unavailable, so a Type-3 is capped at medium.
    assert_ne!(verdict.confidence, Some(Confidence::High));
    assert_eq!(verdict.alignment.only_b, vec![0]);
    assert_eq!(verdict.alignment.matched.len(), 3);
    assert!(verdict.breakdown.type_similarity.is_none());
}

/// The same pair with a compiler's answer about its types. The dimension
/// appears, and the cap that stood in for it is lifted: the band was
/// lowered because nothing had looked, not because something had looked and
/// disagreed.
#[test]
fn resolved_types_supply_the_dimension_that_was_standing_in_for_them() {
    let a = statements(&[(3, &["if"]), (12, &["let"]), (4, &["return"])]);
    let b = statements(&[
        (11, &["loop"]),
        (3, &["if"]),
        (12, &["let"]),
        (4, &["return"]),
    ]);
    let fa = features(counts(6), &[1, 2, 3, 4], 9, &["push", "len"]);
    let fb = features(counts(7), &[1, 2, 3, 5], 8, &["push", "len", "clear"]);
    let same = TypeEvidence::from_tags([TypeTag::Integer, TypeTag::Sequence]);

    let untyped = verify(&a.view(&fa), &b.view(&fb), &VerifyConfig::default());
    let typed = verify(
        &a.view_typed(&fa, &same),
        &b.view_typed(&fb, &same),
        &VerifyConfig::default(),
    );
    assert_eq!(typed.class, Some(CloneClass::Type3));
    assert_eq!(typed.breakdown.type_similarity, Some(1.0));
    assert_eq!(typed.confidence, Some(Confidence::High));
    assert_ne!(untyped.confidence, typed.confidence);
}

/// Evidence that disagrees is evidence: it lowers the composite rather than
/// leaving the dimension out, which is the whole difference between a
/// measurement and its absence.
#[test]
fn types_that_disagree_are_not_the_same_as_types_nobody_resolved() {
    let a = statements(&[(3, &["if"]), (12, &["let"]), (4, &["return"])]);
    let b = statements(&[
        (11, &["loop"]),
        (3, &["if"]),
        (12, &["let"]),
        (4, &["return"]),
    ]);
    let fa = features(counts(6), &[1, 2, 3, 4], 9, &["push", "len"]);
    let fb = features(counts(7), &[1, 2, 3, 5], 8, &["push", "len", "clear"]);
    let numbers = TypeEvidence::from_tags([TypeTag::Integer, TypeTag::Integer]);
    let maps = TypeEvidence::from_tags([TypeTag::Mapping, TypeTag::Mapping]);

    let untyped = verify(&a.view(&fa), &b.view(&fb), &VerifyConfig::default());
    let disagreeing = verify(
        &a.view_typed(&fa, &numbers),
        &b.view_typed(&fb, &maps),
        &VerifyConfig::default(),
    );
    assert_eq!(disagreeing.breakdown.type_similarity, Some(0.0));
    assert!(
        disagreeing.breakdown.composite < untyped.breakdown.composite,
        "{} !< {}",
        disagreeing.breakdown.composite,
        untyped.breakdown.composite
    );
}

/// Compiler identities distinguish calls that the Structural lexer sees
/// under the same source spelling. The fallback remains useful when only
/// one side was resolved, so an unavailable helper does not turn evidence
/// into a synthetic mismatch.
#[test]
fn resolved_api_targets_refine_call_names_without_penalising_missing_data() {
    let a = statements(&[(3, &["run"])]);
    let b = statements(&[(3, &["run"])]);
    let features = features(counts(1), &[1], 1, &["run"]);
    let left = ApiEvidence::from_targets(["static:crate::left::run".to_string()]);
    let right = ApiEvidence::from_targets(["static:crate::right::run".to_string()]);

    let structural = verify(
        &a.view(&features),
        &b.view(&features),
        &VerifyConfig::default(),
    );
    let semantic = verify(
        &a.view_with_apis(&features, &left),
        &b.view_with_apis(&features, &right),
        &VerifyConfig::default(),
    );
    let partial = verify(
        &a.view_with_apis(&features, &left),
        &b.view(&features),
        &VerifyConfig::default(),
    );
    assert_eq!(structural.breakdown.api, Some(1.0));
    assert_eq!(semantic.breakdown.api, Some(0.0));
    assert_eq!(partial.breakdown.api, Some(1.0));
}

/// A sequence of `len` statements whose shapes cycle, so that alignment is
/// a real search rather than a run of identical statements.
fn sequence(len: usize) -> Vec<StatementSummary> {
    (0..len)
        .map(|index| summary(u8::try_from(index % 7).unwrap_or(0)))
        .collect()
}

#[test]
fn the_band_recovers_the_exact_alignment_of_a_gapped_copy() {
    // A copy with a run of statements inserted in the middle: the edit is
    // well inside the band, so the banded search finds the whole original
    // sequence, exactly as an unbounded one would.
    let a = sequence(400);
    let mut b = a.clone();
    for extra in 0..16 {
        b.insert(200 + extra, summary(9));
    }
    let (lcs, alignment) = align(&a, &b, &VerifyConfig::default());
    assert_eq!(lcs, a.len());
    assert_eq!(alignment.matched.len(), a.len());
    assert!(alignment.only_a.is_empty());
    assert_eq!(alignment.only_b.len(), 16);
}

#[test]
fn a_narrower_band_never_reports_more_than_a_wider_one() {
    // The gap is wider than the narrow band, so the narrow search cannot
    // follow the alignment across it; what it reports stays a real common
    // subsequence, never an overestimate.
    let a = sequence(200);
    let mut b = a.clone();
    for extra in 0..80 {
        b.insert(100 + extra, summary(9));
    }
    let narrow = VerifyConfig {
        alignment_band: 4,
        ..VerifyConfig::default()
    };
    let (narrow_lcs, _) = align(&a, &b, &narrow);
    let (wide_lcs, _) = align(&a, &b, &VerifyConfig::default());
    assert_eq!(wide_lcs, a.len());
    assert!(
        narrow_lcs <= wide_lcs,
        "narrow band reported {narrow_lcs}, above the wider band's {wide_lcs}"
    );
}

#[test]
fn the_cell_ceiling_bounds_a_pair_of_very_different_lengths() {
    // Lengths far enough apart that the diagonal span alone would dominate
    // the table; the ceiling narrows the band instead of letting it grow.
    let a = sequence(64);
    let b = sequence(4096);
    let config = VerifyConfig {
        max_alignment_cells: 8_000,
        ..VerifyConfig::default()
    };
    let band = Band::new(a.len(), b.len(), &config);
    assert!(
        (a.len() + 1) * band.width() <= config.max_alignment_cells,
        "table of {} cells exceeds the ceiling",
        (a.len() + 1) * band.width()
    );
    // The band still covers the start corner, so the search begins where
    // the backtrace does.
    assert_eq!(band.first(0), 0);
    // And it still produces a real alignment.
    let (lcs, alignment) = align(&a, &b, &config);
    assert!(lcs <= a.len());
    assert_eq!(alignment.matched.len() + alignment.only_a.len(), a.len());
}

#[test]
fn alignment_band_never_allocates_beyond_either_sequence() {
    let config = VerifyConfig {
        alignment_band: 10_000,
        ..VerifyConfig::default()
    };
    let band = Band::new(3, 5, &config);

    assert_eq!(band.back, 3);
    assert_eq!(band.forward, 5);
    assert_eq!(band.width(), 9);
}

#[test]
fn unrelated_units_are_not_a_clone() {
    let a = statements(&[(3, &["if"]), (4, &["return"])]);
    let b = statements(&[(12, &["let"]), (10, &["match"])]);
    let fa = features(counts(4), &[1, 2], 9, &["push"]);
    let fb = features(counts(1), &[7, 8], 5, &["draw"]);
    // Give the vectors nothing in common.
    let mut cb = [0u32; 23];
    cb[10] = 4;
    let fb = UnitFeatures {
        vector: CharacteristicVector {
            counts: cb,
            ..fb.vector
        },
        ..fb
    };
    let va = a.view(&fa);
    let vb = b.view(&fb);
    let verdict = verify(&va, &vb, &VerifyConfig::default());
    assert_eq!(verdict.class, None);
    assert_eq!(verdict.confidence, None);
}

#[test]
fn the_composite_renormalises_when_type_is_absent() {
    // With type absent, the composite is the weighted mean of the other
    // four dimensions; here all are 1.0 so it must be exactly 1.0.
    let value = composite(&Weights::default(), 1.0, 1.0, Some(1.0), None, Some(1.0));
    assert!((value - 1.0).abs() < 1e-9);
    // Present type similarity participates.
    let value = composite(
        &Weights::default(),
        1.0,
        1.0,
        Some(1.0),
        Some(0.0),
        Some(1.0),
    );
    assert!(value < 1.0);
}

#[test]
fn cfg_similarity_is_one_on_equal_hashes_and_falls_otherwise() {
    let base = CfgFeature {
        hash: FeatureHash::from_bytes([1; 16]),
        skeleton_hash: FeatureHash::from_bytes([1; 16]),
        op_count: 5,
        skeleton_ops: 5,
        max_loop_depth: 1,
        branch_count: 1,
    };
    assert!((cfg_similarity(&base, &base).unwrap() - 1.0).abs() < 1e-9);
    let other = CfgFeature {
        hash: FeatureHash::from_bytes([2; 16]),
        skeleton_hash: FeatureHash::from_bytes([2; 16]),
        op_count: 10,
        skeleton_ops: 10,
        max_loop_depth: 2,
        branch_count: 3,
    };
    let sim = cfg_similarity(&base, &other);
    assert!(sim.is_some_and(|value| value > 0.0 && value < 1.0));
}

#[test]
fn empty_cfg_and_subtree_sets_are_unmeasured_not_perfect() {
    let empty_cfg = CfgFeature {
        hash: FeatureHash::from_bytes([0; 16]),
        skeleton_hash: FeatureHash::from_bytes([0; 16]),
        op_count: 0,
        skeleton_ops: 0,
        max_loop_depth: 0,
        branch_count: 0,
    };
    assert_eq!(cfg_similarity(&empty_cfg, &empty_cfg), None);
    assert_eq!(subtree_jaccard(&[], &[]), None);
}

/// Two sets holding nothing agree about nothing, so the dimension is reported
/// as unmeasured rather than as perfect agreement. A pair carrying none of the
/// evidence would otherwise outscore one carrying most of it.
#[test]
fn set_jaccard_reports_no_score_for_two_empty_sets() {
    assert_eq!(set_jaccard::<u8>(&[], &[]), None);
    assert_eq!(set_jaccard::<u8>(&[], &[1]), Some(0.0));
    assert!(set_jaccard(&[1, 2, 3], &[2, 3, 4]).is_some_and(|value| (value - 0.5).abs() < 1e-9));
    assert!(set_jaccard(&[1, 2], &[3, 4]).is_some_and(|value| value.abs() < 1e-9));
}

/// The module documentation quotes both numbers when it explains why the
/// default composite leans on shape and what that costs at the acceptance
/// threshold, so the weights and that explanation move together.
#[test]
fn the_default_composite_weights_shape_over_text() {
    let weights = Weights::default();
    assert!((weights.structural - 0.45).abs() < 1e-9);
    assert!((weights.lexical - 0.20).abs() < 1e-9);
    assert!(weights.structural > weights.lexical);
}

#[test]
fn verification_is_deterministic() {
    let a = statements(&[(3, &["if"]), (12, &["let"])]);
    let feats = features(counts(4), &[1, 2, 3], 9, &["push"]);
    let view = a.view(&feats);
    let cfg = VerifyConfig::default();
    assert_eq!(verify(&view, &view, &cfg), verify(&view, &view, &cfg));
}
