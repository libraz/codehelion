use super::*;
use crate::labels::{LabelPair, NonClone};
use crate::schema::Axes;

fn fragment(file: &str, start: u32, end: u32) -> Fragment {
    Fragment {
        file: file.to_string(),
        start_line: start,
        end_line: end,
        tokens: 0,
    }
}

fn finding(id: &str, score: f64, fragments: Vec<Fragment>) -> Finding {
    Finding {
        size_tokens: 0,
        id: id.to_string(),
        clone_type: CloneType::Type2,
        rule_ids: Vec::new(),
        score,
        band: None,
        actionable: true,
        axes: Axes::default(),
        width_family: false,
        fragments,
    }
}

/// Hand-crafted self-test: 2 clone pairs, 3 findings. Exactly 1 pair is
/// covered, exactly 2 findings are true positives, 1 is a false positive.
fn self_test_inputs() -> (DetectionResult, LabelSet) {
    let results = DetectionResult {
        schema_version: 1,
        language: "rust".to_string(),
        findings: vec![
            // Covers pair A exactly -> true positive.
            finding(
                "f-001",
                0.9,
                vec![fragment("x.rs", 1, 10), fragment("y.rs", 1, 10)],
            ),
            // Overlaps pair A ~0.818 -> true positive.
            finding(
                "f-002",
                0.8,
                vec![fragment("x.rs", 2, 11), fragment("y.rs", 2, 11)],
            ),
            // Covers nothing labelled as a clone -> false positive, and it
            // covers the non-clone region.
            finding(
                "f-003",
                0.95,
                vec![fragment("x.rs", 200, 210), fragment("y.rs", 200, 210)],
            ),
        ],
        withheld: Vec::new(),
    };
    let labels = LabelSet {
        schema_version: 1,
        language: "rust".to_string(),
        files: vec!["x.rs".to_string(), "y.rs".to_string()],
        clone_pairs: vec![
            LabelPair {
                id: "cp-001".to_string(),
                clone_type: CloneType::Type2,
                rule_id: None,
                fragments: vec![fragment("x.rs", 1, 10), fragment("y.rs", 1, 10)],
            },
            LabelPair {
                id: "cp-002".to_string(),
                clone_type: CloneType::Type3,
                rule_id: None,
                fragments: vec![fragment("x.rs", 100, 110), fragment("y.rs", 100, 110)],
            },
        ],
        non_clones: vec![NonClone {
            id: "nc-001".to_string(),
            reason: "unrelated".to_string(),
            rule_id: None,
            fragments: vec![fragment("x.rs", 200, 210), fragment("y.rs", 200, 210)],
        }],
    };
    (results, labels)
}

#[test]
fn evaluate_matches_hand_computed_values() {
    let (results, labels) = self_test_inputs();
    let metrics = evaluate(&results, &labels, 100, DEFAULT_MATCH_THRESHOLD, 3);

    assert_eq!(metrics.recall_overall, Some(0.5));
    assert_eq!(metrics.precision_overall, Some(2.0 / 3.0));
    assert_eq!(metrics.true_positives, 2);
    assert_eq!(metrics.false_positives, 1);

    // 3 findings / 100 LOC * 1000 = 30; 1 FP / 100 * 1000 = 10.
    assert_eq!(metrics.findings_per_kloc, Some(30.0));
    assert_eq!(metrics.false_positives_per_kloc, Some(10.0));

    // Per-type recall: type-2 pair covered (1.0), type-3 pair not (0.0).
    assert!((metrics.recall_by_type[&CloneType::Type2] - 1.0).abs() < 1e-9);
    assert!(metrics.recall_by_type[&CloneType::Type3].abs() < 1e-9);

    // One finding lands on the non-clone region.
    assert_eq!(metrics.non_clone_hits, 1);

    // Top-3 precision equals overall precision here.
    assert_eq!(metrics.precision_at_k, Some(2.0 / 3.0));
}

#[test]
fn a_zero_denominator_is_unmeasured_while_a_zero_numerator_is_zero() {
    assert_eq!(ratio(0, 0), None);
    assert_eq!(ratio(0, 1), Some(0.0));

    let (results, labels) = self_test_inputs();
    let no_findings = DetectionResult {
        schema_version: results.schema_version,
        language: results.language,
        findings: Vec::new(),
        withheld: Vec::new(),
    };
    let metrics = evaluate(&no_findings, &labels, 0, DEFAULT_MATCH_THRESHOLD, 10);
    assert_eq!(metrics.recall_overall, Some(0.0));
    assert_eq!(metrics.precision_overall, None);
    assert_eq!(metrics.precision_at_k, None);
    assert_eq!(metrics.findings_per_kloc, None);
    assert_eq!(metrics.false_positives_per_kloc, None);
    assert!(format!("{metrics}").contains("n/a"));
}

#[test]
fn an_empty_label_does_not_vacuously_cover_every_finding() {
    let (results, _) = self_test_inputs();
    assert!(!covers(&results.findings[0], &[], DEFAULT_MATCH_THRESHOLD));
}

#[test]
fn evaluate_by_rule_keeps_registered_rules_and_their_labels_separate() {
    let (mut results, mut labels) = self_test_inputs();
    results.findings[0].rule_ids = vec!["rule-a".to_string()];
    results.findings[1].rule_ids = vec!["rule-b".to_string()];
    results.findings[2].rule_ids = vec!["rule-a".to_string()];
    labels.clone_pairs[0].rule_id = Some("rule-a".to_string());
    labels.clone_pairs[1].rule_id = Some("rule-b".to_string());
    labels.non_clones[0].rule_id = Some("rule-a".to_string());

    let by_rule = evaluate_by_rule(&results, &labels, 100, DEFAULT_MATCH_THRESHOLD, 10);

    let rule_a = &by_rule["rule-a"];
    assert_eq!(rule_a.recall_overall, Some(1.0));
    assert_eq!(rule_a.precision_overall, Some(0.5));
    assert_eq!(rule_a.non_clone_hits, 1);

    let rule_b = &by_rule["rule-b"];
    assert_eq!(rule_b.recall_overall, Some(0.0));
    assert_eq!(rule_b.precision_overall, Some(0.0));
    assert_eq!(rule_b.total_findings, 1);
}

#[test]
fn precision_at_k_ranks_by_score() {
    let (results, labels) = self_test_inputs();
    // Ranked by score: f-003 (0.95, FP), f-001 (0.9, TP), f-002 (0.8, TP).
    // Top-2 contains one TP -> 0.5.
    let metrics = evaluate(&results, &labels, 100, DEFAULT_MATCH_THRESHOLD, 2);
    assert_eq!(metrics.precision_at_k, Some(0.5));
}

#[test]
fn adjudication_scores_only_what_the_labels_speak_about() {
    let (results, labels) = self_test_inputs();
    // f-001 and f-002 cover clone pair A; f-003 covers the non-clone.
    let ruled = adjudicate(&results, &labels, DEFAULT_MATCH_THRESHOLD);
    assert_eq!(ruled.confirmed, 2);
    assert_eq!(ruled.refuted, 1);
    assert_eq!(ruled.conflicting, 0);
    assert_eq!(ruled.unjudged, 0);
    assert_eq!(ruled.precision(), Some(2.0 / 3.0));
}

#[test]
fn an_unlabelled_finding_counts_against_nothing() {
    let (mut results, labels) = self_test_inputs();
    // A finding in a region no label mentions: not a wrong answer, an
    // unasked question. `evaluate` would call it a false positive.
    results.findings.push(finding(
        "f-004",
        0.7,
        vec![fragment("x.rs", 500, 510), fragment("y.rs", 500, 510)],
    ));

    let ruled = adjudicate(&results, &labels, DEFAULT_MATCH_THRESHOLD);
    assert_eq!(ruled.unjudged, 1);
    assert_eq!(ruled.judged(), 3);
    assert_eq!(
        ruled.precision(),
        Some(2.0 / 3.0),
        "precision is unchanged by a finding nobody ruled on"
    );

    let metrics = evaluate(&results, &labels, 100, DEFAULT_MATCH_THRESHOLD, 4);
    assert_eq!(
        metrics.precision_overall,
        Some(0.5),
        "the fully-labelled measure charges the same finding as a miss"
    );
}

#[test]
fn a_finding_both_labels_claim_is_a_corpus_defect() {
    let (results, mut labels) = self_test_inputs();
    // Label the region f-003 reports as a clone as well as a non-clone.
    labels.clone_pairs.push(LabelPair {
        id: "cp-003".to_string(),
        clone_type: CloneType::Type1,
        rule_id: None,
        fragments: vec![fragment("x.rs", 200, 210), fragment("y.rs", 200, 210)],
    });

    let ruled = adjudicate(&results, &labels, DEFAULT_MATCH_THRESHOLD);
    assert_eq!(ruled.conflicting, 1);
    assert_eq!(ruled.refuted, 0, "a conflict is neither verdict");
    assert_eq!(ruled.confirmed, 2);
}

#[test]
fn nothing_judged_has_no_precision_measurement() {
    let (results, _) = self_test_inputs();
    let empty = LabelSet {
        schema_version: 1,
        language: "rust".to_string(),
        files: vec![],
        clone_pairs: vec![],
        non_clones: vec![],
    };
    let ruled = adjudicate(&results, &empty, DEFAULT_MATCH_THRESHOLD);
    assert_eq!(ruled.judged(), 0);
    assert_eq!(ruled.unjudged, 3);
    assert_eq!(ruled.precision(), None);
}

#[test]
fn the_size_split_measures_the_smallest_member_of_each_judged_finding() {
    let (results, labels) = self_test_inputs();
    let mut split = SizeSplit::default();
    split.record(&results, &labels, DEFAULT_MATCH_THRESHOLD);

    // f-001 and f-002 are confirmed, f-003 refuted; every fragment above
    // spans 10 or 11 lines.
    assert_eq!(split.confirmed, vec![10, 10]);
    assert_eq!(split.refuted, vec![11]);
}

#[test]
fn a_split_that_separates_by_length_costs_nothing() {
    let split = SizeSplit {
        confirmed: vec![20, 30, 40],
        refuted: vec![3, 4, 5],
    };
    assert_eq!(
        split.confirmed_within_refuted_range(),
        0,
        "no confirmed finding is as short as the longest lookalike, so a \
             floor at 6 lines removes the lookalikes for free"
    );
}

#[test]
fn a_split_that_overlaps_prices_the_floor_in_real_clones() {
    let split = SizeSplit {
        confirmed: vec![4, 9, 40],
        refuted: vec![3, 4, 12],
    };
    assert_eq!(
        split.confirmed_within_refuted_range(),
        2,
        "a floor above 12 lines takes the 4- and 9-line clones with it"
    );
}

#[test]
fn nothing_refuted_leaves_a_floor_unpriced() {
    let split = SizeSplit {
        confirmed: vec![4, 9],
        refuted: vec![],
    };
    assert_eq!(
        split.confirmed_within_refuted_range(),
        0,
        "with no lookalikes to remove there is no floor to price"
    );
}

#[test]
fn stability_identical_runs() {
    let (results, _) = self_test_inputs();
    let s = stability(&results, &results);
    assert!(s.identical);
    assert!((s.jaccard - 1.0).abs() < 1e-9);
    assert!(s.churn.abs() < 1e-9);
}

#[test]
fn stability_disjoint_runs() {
    let a = DetectionResult {
        schema_version: 1,
        language: "rust".to_string(),
        findings: vec![finding("f-a", 1.0, vec![fragment("x.rs", 1, 10)])],
        withheld: Vec::new(),
    };
    let b = DetectionResult {
        schema_version: 1,
        language: "rust".to_string(),
        findings: vec![finding("f-b", 1.0, vec![fragment("x.rs", 50, 60)])],
        withheld: Vec::new(),
    };
    let s = stability(&a, &b);
    assert!(!s.identical);
    assert!(s.jaccard.abs() < 1e-9);
    assert!((s.churn - 1.0).abs() < 1e-9);
}

#[test]
fn stability_partial_overlap_has_known_jaccard() {
    // Shared key K2; A also has K1, B also has K3 -> intersection 1, union 3.
    let k1 = vec![fragment("x.rs", 1, 10)];
    let k2 = vec![fragment("y.rs", 1, 10)];
    let k3 = vec![fragment("z.rs", 1, 10)];
    let a = DetectionResult {
        schema_version: 1,
        language: "rust".to_string(),
        findings: vec![finding("a1", 1.0, k1), finding("a2", 1.0, k2.clone())],
        withheld: Vec::new(),
    };
    let b = DetectionResult {
        schema_version: 1,
        language: "rust".to_string(),
        // Different id and clone_type for the shared key: identity is by
        // fragments only.
        findings: vec![
            Finding {
                size_tokens: 0,
                id: "b2".to_string(),
                clone_type: CloneType::Type1,
                rule_ids: Vec::new(),
                score: 1.0,
                band: None,
                actionable: true,
                axes: Axes::default(),
                width_family: false,
                fragments: k2,
            },
            finding("b3", 1.0, k3),
        ],
        withheld: Vec::new(),
    };
    let s = stability(&a, &b);
    assert!(!s.identical);
    assert!((s.jaccard - 1.0 / 3.0).abs() < 1e-9);
}

#[test]
fn rule_stability_exposes_a_removed_rule_without_affecting_another() {
    let mut unchanged = finding("stable", 1.0, vec![fragment("stable.rs", 1, 4)]);
    unchanged.rule_ids = vec!["rule-stable-v1".to_string()];
    let mut removed = finding("removed", 1.0, vec![fragment("removed.rs", 1, 4)]);
    removed.rule_ids = vec!["rule-removed-v1".to_string()];
    let before = DetectionResult {
        schema_version: 1,
        language: "rust".to_string(),
        findings: vec![unchanged.clone(), removed],
        withheld: Vec::new(),
    };
    let after = DetectionResult {
        schema_version: 1,
        language: "rust".to_string(),
        findings: vec![unchanged],
        withheld: Vec::new(),
    };

    let by_rule = stability_by_rule(&before, &after);
    assert!(by_rule["rule-stable-v1"].identical);
    assert!((by_rule["rule-stable-v1"].churn).abs() < f64::EPSILON);
    assert!(!by_rule["rule-removed-v1"].identical);
    assert!((by_rule["rule-removed-v1"].churn - 1.0).abs() < f64::EPSILON);
}

#[test]
fn stability_empty_runs_are_identical() {
    let empty = DetectionResult {
        schema_version: 1,
        language: "rust".to_string(),
        findings: vec![],
        withheld: Vec::new(),
    };
    let s = stability(&empty, &empty);
    assert!(s.identical);
    assert!((s.jaccard - 1.0).abs() < 1e-9);
}
