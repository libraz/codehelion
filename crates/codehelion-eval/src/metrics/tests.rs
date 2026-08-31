use super::*;
use crate::detected::{DetectedSibling, DetectedSiblingGroup, DetectedSiblingSimilarity};
use crate::labels::{KnownSibling, LabelPair, NonClone};
use crate::schema::{Axes, SiblingBasis};

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
        known_siblings: Vec::new(),
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
fn sibling_metrics_match_owner_primaries_and_count_signature_volume_separately() {
    let labels = LabelSet {
        schema_version: 1,
        language: "cpp".to_string(),
        files: vec!["seed.cpp".to_string(), "mirror.cpp".to_string()],
        clone_pairs: Vec::new(),
        non_clones: Vec::new(),
        known_siblings: vec![KnownSibling {
            id: "ks-001".to_string(),
            basis: SiblingBasis::Signature,
            primary_fragments: [fragment("seed.cpp", 1, 10), fragment("copy.cpp", 1, 10)],
            sibling: fragment("mirror.cpp", 1, 12),
        }],
    };
    let sibling_groups = vec![DetectedSiblingGroup {
        owner_group_fingerprint: "primary".to_string(),
        owner_members: vec![fragment("seed.cpp", 1, 10), fragment("copy.cpp", 1, 10)],
        siblings: vec![DetectedSibling {
            clone_type: CloneType::Type3,
            confidence_band: "low".to_string(),
            basis: SiblingBasis::Signature,
            signature: Some("int(const int*,int)".to_string()),
            similarity: DetectedSiblingSimilarity {
                lexical: Some(0.2),
                structural: Some(0.5),
                control_flow: None,
                api: None,
                composite: 0.42,
            },
            member: fragment("mirror.cpp", 1, 12),
        }],
    }];
    let metrics = evaluate_siblings(&sibling_groups, &labels, DEFAULT_MATCH_THRESHOLD);
    assert_eq!(metrics.known_mirrors_recovered, 1);
    assert_eq!(metrics.known_mirrors_total, 1);
    assert_eq!(metrics.signature_siblings_total, 1);
    assert_eq!(
        metrics.to_string(),
        "known mirrors recovered     1 / 1\nsignature-derived siblings  1"
    );
}

#[test]
fn sibling_metrics_require_both_labelled_primaries_in_one_owner() {
    let labels = LabelSet {
        schema_version: 1,
        language: "cpp".to_string(),
        files: vec![
            "seed.cpp".to_string(),
            "copy.cpp".to_string(),
            "other.cpp".to_string(),
        ],
        clone_pairs: Vec::new(),
        non_clones: Vec::new(),
        known_siblings: vec![KnownSibling {
            id: "ks-001".to_string(),
            basis: SiblingBasis::Signature,
            primary_fragments: [fragment("seed.cpp", 1, 10), fragment("copy.cpp", 1, 10)],
            sibling: fragment("mirror.cpp", 1, 12),
        }],
    };
    let sibling_groups = vec![DetectedSiblingGroup {
        owner_group_fingerprint: "wrong-owner".to_string(),
        owner_members: vec![fragment("seed.cpp", 1, 10), fragment("other.cpp", 1, 10)],
        siblings: vec![DetectedSibling {
            clone_type: CloneType::Type3,
            confidence_band: "low".to_string(),
            basis: SiblingBasis::Signature,
            signature: Some("int(const int*,int)".to_string()),
            similarity: DetectedSiblingSimilarity {
                lexical: None,
                structural: Some(0.5),
                control_flow: None,
                api: None,
                composite: 0.5,
            },
            member: fragment("mirror.cpp", 1, 12),
        }],
    }];

    let metrics = evaluate_siblings(&sibling_groups, &labels, DEFAULT_MATCH_THRESHOLD);
    assert_eq!(metrics.known_mirrors_recovered, 0);
    assert_eq!(metrics.known_mirrors_total, 1);
    assert_eq!(metrics.signature_siblings_total, 1);
}

#[test]
fn duplicate_sibling_detections_recover_one_label_but_count_twice() {
    let labels = LabelSet {
        schema_version: 1,
        language: "cpp".to_string(),
        files: vec![
            "seed.cpp".to_string(),
            "copy.cpp".to_string(),
            "mirror.cpp".to_string(),
        ],
        clone_pairs: Vec::new(),
        non_clones: Vec::new(),
        known_siblings: vec![KnownSibling {
            id: "ks-001".to_string(),
            basis: SiblingBasis::Signature,
            primary_fragments: [fragment("seed.cpp", 1, 10), fragment("copy.cpp", 1, 10)],
            sibling: fragment("mirror.cpp", 1, 12),
        }],
    };
    let duplicate = || DetectedSibling {
        clone_type: CloneType::Type3,
        confidence_band: "low".to_string(),
        basis: SiblingBasis::Signature,
        signature: Some("int(const int*,int)".to_string()),
        similarity: DetectedSiblingSimilarity {
            lexical: None,
            structural: Some(0.5),
            control_flow: None,
            api: None,
            composite: 0.5,
        },
        member: fragment("mirror.cpp", 1, 12),
    };
    let sibling_groups = vec![DetectedSiblingGroup {
        owner_group_fingerprint: "primary".to_string(),
        owner_members: vec![fragment("seed.cpp", 1, 10), fragment("copy.cpp", 1, 10)],
        siblings: vec![duplicate(), duplicate()],
    }];

    let metrics = evaluate_siblings(&sibling_groups, &labels, DEFAULT_MATCH_THRESHOLD);
    assert_eq!(metrics.known_mirrors_recovered, 1);
    assert_eq!(metrics.known_mirrors_total, 1);
    assert_eq!(metrics.signature_siblings_total, 2);
}

#[test]
fn an_unlabelled_sibling_is_not_a_primary_false_positive() {
    let labels = LabelSet {
        schema_version: 1,
        language: "cpp".to_string(),
        files: Vec::new(),
        clone_pairs: Vec::new(),
        non_clones: Vec::new(),
        known_siblings: Vec::new(),
    };
    let sibling_groups = vec![DetectedSiblingGroup {
        owner_group_fingerprint: "primary".to_string(),
        owner_members: vec![fragment("a.cpp", 1, 4), fragment("b.cpp", 1, 4)],
        siblings: vec![DetectedSibling {
            clone_type: CloneType::Type3,
            confidence_band: "low".to_string(),
            basis: SiblingBasis::Similarity,
            signature: None,
            similarity: DetectedSiblingSimilarity {
                lexical: None,
                structural: Some(0.4),
                control_flow: None,
                api: None,
                composite: 0.4,
            },
            member: fragment("c.cpp", 1, 4),
        }],
    }];
    let metrics = evaluate_siblings(&sibling_groups, &labels, DEFAULT_MATCH_THRESHOLD);
    assert_eq!(metrics.known_mirrors_recovered, 0);
    assert_eq!(metrics.known_mirrors_total, 0);
    assert_eq!(metrics.signature_siblings_total, 0);
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
        known_siblings: vec![],
    };
    let ruled = adjudicate(&results, &empty, DEFAULT_MATCH_THRESHOLD);
    assert_eq!(ruled.judged(), 0);
    assert_eq!(ruled.unjudged, 3);
    assert_eq!(ruled.precision(), None);
}

/// The ranking cut-off is read from a whole order, so both ends of `k` and
/// the direction ties break in are behaviour a caller depends on.
#[test]
fn precision_at_clamps_k_and_breaks_ties_against_the_ranking() {
    let (results, labels) = self_test_inputs();
    let mut ranked = RankedVerdicts::default();
    ranked.record(&results, &labels, DEFAULT_MATCH_THRESHOLD, |finding| {
        finding.score
    });
    // Ordered by score: f-003 (0.95, refuted), f-001 (0.9), f-002 (0.8).
    assert_eq!(ranked.len(), 3);
    assert!(!ranked.is_empty());
    assert_eq!(ranked.precision_at(1), Some(0.0));
    assert_eq!(ranked.precision_at(2), Some(0.5));
    assert_eq!(
        ranked.precision_at(99),
        Some(2.0 / 3.0),
        "a cut-off past the end scores every entry rather than running off it"
    );
    assert_eq!(
        ranked.precision_at(0),
        None,
        "an empty top set is unmeasured"
    );
    assert_eq!(RankedVerdicts::default().precision_at(3), None);

    // At one score the refuted finding sorts first: a ranking is not credited
    // for an order it never expressed.
    let (mut tied, labels) = self_test_inputs();
    tied.findings[0].score = 0.5;
    tied.findings[2].score = 0.5;
    tied.findings[1].score = 0.1;
    let mut ranked = RankedVerdicts::default();
    ranked.record(&tied, &labels, DEFAULT_MATCH_THRESHOLD, |finding| {
        finding.score
    });
    assert_eq!(ranked.precision_at(1), Some(0.0));
}

/// Mean average precision answers with a number for every ranking, including
/// one with nothing to find, so it can be averaged across corpora.
#[test]
fn mean_average_precision_reads_the_whole_order_and_is_zero_without_a_hit() {
    let (results, labels) = self_test_inputs();
    let record = |score: fn(&Finding) -> f64| {
        let mut ranked = RankedVerdicts::default();
        ranked.record(&results, &labels, DEFAULT_MATCH_THRESHOLD, score);
        ranked.mean_average_precision()
    };
    // By the detector's own score the refuted finding leads: (1/2 + 2/3) / 2.
    let by_score = record(|finding| finding.score);
    assert!(
        (by_score - f64::midpoint(0.5, 2.0 / 3.0)).abs() < 1e-9,
        "{by_score}"
    );
    // A ranking that puts both confirmed findings first scores perfectly, so
    // the measure separates two orderings of one result set.
    let by_id = record(|finding| if finding.id == "f-003" { 0.0 } else { 1.0 });
    assert!((by_id - 1.0).abs() < 1e-9, "{by_id}");
    assert!(by_score < by_id);

    let mut refuted_only = RankedVerdicts::default();
    let (only, labels) = self_test_inputs();
    let only = DetectionResult {
        findings: vec![only.findings[2].clone()],
        ..only
    };
    refuted_only.record(&only, &labels, DEFAULT_MATCH_THRESHOLD, |finding| {
        finding.score
    });
    assert_eq!(refuted_only.len(), 1);
    assert!(
        refuted_only.mean_average_precision().abs() < f64::EPSILON,
        "a ranking with nothing confirmed is worth zero, not undefined"
    );
    assert!(RankedVerdicts::default().mean_average_precision().abs() < f64::EPSILON);
}

/// The band table accounts for every judged finding, including the ones the
/// detector never scored a band for.
#[test]
fn the_band_split_keeps_the_unscored_findings_in_their_own_row() {
    let (mut results, labels) = self_test_inputs();
    results.findings[0].band = Some("high".to_string());
    results.findings[1].band = None;
    results.findings[2].band = Some("high".to_string());

    let mut split = BandSplit::default();
    split.record(&results, &labels, DEFAULT_MATCH_THRESHOLD);
    assert_eq!(split.bands["high"], (1, 1));
    assert_eq!(
        split.bands["(unscored)"],
        (1, 0),
        "a split pair carries no band and is still a judged finding"
    );
    let judged: usize = split
        .bands
        .values()
        .map(|&(confirmed, refuted)| confirmed + refuted)
        .sum();
    assert_eq!(judged, 3);

    let table = split.to_string();
    let (high, unscored) = (
        table.find("high").expect("the table shows the band"),
        table.find("(unscored)").expect("and the unscored row"),
    );
    assert!(
        high < unscored,
        "the strongest band leads and the unscored row trails: {table}"
    );
}

/// The lookalike table is counted over labels: a class is reached or it is
/// not, however many findings reached it.
#[test]
fn the_reason_split_counts_labels_rather_than_the_findings_over_them() {
    let (mut results, mut labels) = self_test_inputs();
    labels.non_clones[0].reason = "getter-boilerplate".to_string();
    // A second label of the same class that no finding reaches.
    labels.non_clones.push(NonClone {
        id: "nc-002".to_string(),
        reason: "getter-boilerplate".to_string(),
        rule_id: None,
        fragments: vec![fragment("x.rs", 300, 310), fragment("y.rs", 300, 310)],
    });
    // A second finding over the region the first label covers.
    results.findings.push(finding(
        "f-004",
        0.6,
        vec![fragment("x.rs", 200, 210), fragment("y.rs", 200, 210)],
    ));

    let mut split = ReasonSplit::default();
    split.record(&results, &labels, DEFAULT_MATCH_THRESHOLD);
    assert_eq!(
        split.reasons["getter-boilerplate"],
        (1, 1, 2),
        "two findings over one label are one label reached, of two labelled"
    );
    assert_eq!(
        split.still_reported(),
        vec![("getter-boilerplate", 1, 1, 2)]
    );

    // Filing both findings below the fold leaves the class shown but no
    // longer put forward, which is the distinction the table exists for.
    for finding in &mut results.findings {
        finding.actionable = false;
    }
    let mut filed = ReasonSplit::default();
    filed.record(&results, &labels, DEFAULT_MATCH_THRESHOLD);
    assert_eq!(filed.reasons["getter-boilerplate"], (0, 1, 2));
}

/// Acting on the width rule moves everything it reaches out of the report, so
/// a count read only from the report would answer "nothing" the moment the
/// rule was turned on.
#[test]
fn the_width_family_reads_the_withheld_findings_beside_the_reported_ones() {
    let (mut results, labels) = self_test_inputs();
    let mut withheld = results.findings.remove(2);
    withheld.width_family = true;
    results.withheld.push(withheld);
    results.findings[0].width_family = true;

    let mut family = WidthFamily::default();
    family.record(
        &results,
        &labels,
        DEFAULT_MATCH_THRESHOLD,
        |finding| match finding.id.as_str() {
            "f-001" => Some(codehelion_core::substitution::Witness {
                changes: Vec::new(),
                edits: 3,
            }),
            _ => None,
        },
    );
    assert_eq!(family.confirmed, 1, "the reported finding the rule reaches");
    assert_eq!(family.refuted, 1, "and the withheld one it also reaches");
    assert_eq!(
        family.untouched, 1,
        "f-002 is judged and outside the rule, so it is asked about and not reached"
    );
    assert_eq!(
        family.unalignable, 1,
        "the withheld finding was reached with no gap to read"
    );
    assert_eq!(family.most_edits, 3);
}

/// The fold was drawn to improve the precision of what a reader meets first,
/// so that is the figure that says whether drawing it worked.
#[test]
fn actionable_precision_scores_only_the_findings_put_forward() {
    let (mut results, labels) = self_test_inputs();
    // One confirmed finding filed below the fold: overall precision is
    // unchanged, and the reader now meets one confirmed and one refuted.
    results.findings[1].actionable = false;

    let ruled = adjudicate(&results, &labels, DEFAULT_MATCH_THRESHOLD);
    assert_eq!(ruled.precision(), Some(2.0 / 3.0));
    assert_eq!(ruled.actionable_confirmed, 1);
    assert_eq!(ruled.actionable_refuted, 1);
    assert_eq!(ruled.actionable_precision(), Some(0.5));

    for finding in &mut results.findings {
        finding.actionable = false;
    }
    let filed = adjudicate(&results, &labels, DEFAULT_MATCH_THRESHOLD);
    assert_eq!(
        filed.actionable_precision(),
        None,
        "a report that puts nothing forward is unmeasured rather than perfect"
    );
    assert_eq!(filed.precision(), Some(2.0 / 3.0));
}

/// The floor is the lowest confirmed value, and what it removes is what the
/// axis is worth as a filter.
#[test]
fn the_axis_floor_is_the_lowest_confirmed_value_and_prices_the_lookalikes() {
    let (mut results, labels) = self_test_inputs();
    results.findings[0].axes.lexical = Some(0.9);
    results.findings[1].axes.lexical = Some(0.7);
    results.findings[2].axes.lexical = Some(0.4);

    let mut split = AxisSplit::default();
    split.record(&results, &labels, DEFAULT_MATCH_THRESHOLD);
    assert_eq!(split.axes(), vec!["lexical"]);
    assert_eq!(split.floor_that_costs_nothing("lexical"), Some((0.7, 1)));
    assert!(split.to_string().contains("lexical"));
}

/// An axis with lookalikes on it but no confirmed finding left has no floor
/// to name, which is a different thing from an axis nobody was scored on.
#[test]
fn an_axis_without_a_confirmed_finding_is_still_a_measured_axis() {
    let (mut results, labels) = self_test_inputs();
    results.findings[2].axes.api = Some(0.4);

    let mut split = AxisSplit::default();
    split.record(&results, &labels, DEFAULT_MATCH_THRESHOLD);
    assert_eq!(split.floor_that_costs_nothing("api"), None);
    assert!(
        split.scored("api"),
        "the refuted findings carry the axis; what is missing is a confirmed \
         finding for the floor to stand on"
    );
    assert!(
        !split.scored("composite"),
        "no finding carried a composite value, so nobody was scored on it"
    );
    assert!(split.floor_that_costs_nothing("composite").is_none());
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
