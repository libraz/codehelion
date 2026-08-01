use super::*;

const SEED: &str = "\
// seed

fn add(a: i32, b: i32) -> i32 {
    let sum = a + b;
    sum
}

fn twice(x: i32) -> i32 {
    let y = x * 2;
    y
}
";

fn base_spec() -> MutationSpec {
    MutationSpec {
        schema_version: 1,
        language: "rust".to_string(),
        seed: "seed.rs".to_string(),
        variants: Vec::new(),
        non_clones: Vec::new(),
    }
}

fn item(key: &str) -> ItemSpec {
    ItemSpec {
        item: key.to_string(),
        labelled: true,
        clone_type: None,
        rename: BTreeMap::new(),
        literals: BTreeMap::new(),
        transplants: Vec::new(),
        edits: Vec::new(),
        target_change_rate: None,
    }
}

fn transplant(donor: &str, from: &str, to: &str, after: &str) -> TransplantSpec {
    TransplantSpec {
        donor: donor.to_string(),
        from: from.to_string(),
        to: to.to_string(),
        after: after.to_string(),
        labelled: false,
        clone_type: None,
        rename: BTreeMap::new(),
        literals: BTreeMap::new(),
        non_clone: None,
    }
}

fn map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|&(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn type2_spec() -> MutationSpec {
    let mut spec = base_spec();
    spec.variants.push(VariantSpec {
        file: "v2.rs".to_string(),
        clone_type: CloneType::Type2,
        header_comment: "Type-2 variant.".to_string(),
        items: vec![ItemSpec {
            rename: map(&[("a", "p"), ("b", "q"), ("sum", "total")]),
            ..item("fn add")
        }],
    });
    spec
}

#[test]
fn generate_is_deterministic() {
    let first = generate(&type2_spec(), SEED).expect("first run");
    let second = generate(&type2_spec(), SEED).expect("second run");
    assert_eq!(first, second);
}

#[test]
fn rejects_an_unclosed_seed_item_before_generating_ground_truth() {
    let seed = "fn incomplete() {\n    let template = \"{ literal\";\n";
    let error = generate(&type2_spec(), seed).expect_err("unclosed seed is invalid");
    assert!(matches!(
        error,
        Error::UnclosedSeedItem { ref key, start_line: 1 } if key == "fn incomplete"
    ));
}

#[test]
fn type2_variant_renames_whole_tokens_and_preserves_structure() {
    let corpus = generate(&type2_spec(), SEED).expect("generates");
    let expected = format!(
        "// Type-2 variant.\n{GENERATED_MARKER}\n\n\
             fn add(p: i32, q: i32) -> i32 {{\n    let total = p + q;\n    total\n}}\n"
    );
    assert_eq!(corpus.files["v2.rs"], expected);
}

#[test]
fn label_ranges_are_computed_from_the_actual_edits() {
    let corpus = generate(&type2_spec(), SEED).expect("generates");
    assert_eq!(corpus.labels.clone_pairs.len(), 1);
    let pair = &corpus.labels.clone_pairs[0];
    assert_eq!(pair.id, "cp-001");
    assert_eq!(pair.clone_type, CloneType::Type2);
    // Seed: `fn add` spans lines 3..=6. Variant: header comment, marker
    // and one blank line precede it, so it spans lines 4..=7.
    assert_eq!(
        pair.fragments,
        vec![
            Fragment {
                file: "seed.rs".to_string(),
                start_line: 3,
                end_line: 6,
                tokens: 0,
            },
            Fragment {
                file: "v2.rs".to_string(),
                start_line: 4,
                end_line: 7,
                tokens: 0,
            },
        ]
    );
}

#[test]
fn type1_comment_before_stays_outside_the_labelled_range() {
    let mut spec = base_spec();
    spec.variants.push(VariantSpec {
        file: "v1.rs".to_string(),
        clone_type: CloneType::Type1,
        header_comment: "Type-1 variant.".to_string(),
        items: vec![ItemSpec {
            edits: vec![
                EditOp::CommentBefore {
                    text: "Adds two numbers.".to_string(),
                },
                EditOp::BlankAfter {
                    anchor: "let sum = a + b;".to_string(),
                },
            ],
            ..item("fn add")
        }],
    });
    let corpus = generate(&spec, SEED).expect("generates");
    let pair = &corpus.labels.clone_pairs[0];
    // Line 4 is the inserted comment; the fragment starts at the `fn`
    // header on line 5 and the inserted blank line stays inside the span.
    assert_eq!(pair.fragments[1].start_line, 5);
    assert_eq!(pair.fragments[1].end_line, 9);
}

#[test]
fn type3_records_the_achieved_change_rate() {
    let mut spec = base_spec();
    spec.variants.push(VariantSpec {
        file: "v3.rs".to_string(),
        clone_type: CloneType::Type3,
        header_comment: "Type-3 variant.".to_string(),
        items: vec![ItemSpec {
            target_change_rate: Some(0.5),
            edits: vec![EditOp::InsertAfter {
                anchor: "let sum = a + b;".to_string(),
                lines: vec!["    let extra = 0;".to_string()],
            }],
            ..item("fn add")
        }],
    });
    let corpus = generate(&spec, SEED).expect("generates");
    assert_eq!(corpus.change_rates.len(), 1);
    let rate = &corpus.change_rates[0];
    // `fn add` has two statement lines; one statement was inserted.
    assert_eq!(rate.changed_statements, 1);
    assert_eq!(rate.total_statements, 2);
    assert!((rate.achieved() - 0.5).abs() < 1e-9);
    // The inserted statement extends the variant fragment by one line.
    let pair = &corpus.labels.clone_pairs[0];
    assert_eq!(pair.fragments[1].start_line, 4);
    assert_eq!(pair.fragments[1].end_line, 8);
}

#[test]
fn delete_shrinks_the_range_and_counts_as_change() {
    let mut spec = base_spec();
    spec.variants.push(VariantSpec {
        file: "v3.rs".to_string(),
        clone_type: CloneType::Type3,
        header_comment: "Type-3 variant.".to_string(),
        items: vec![ItemSpec {
            edits: vec![EditOp::Delete {
                anchor: "let y = x * 2;".to_string(),
            }],
            ..item("fn twice")
        }],
    });
    let corpus = generate(&spec, SEED).expect("generates");
    assert_eq!(corpus.change_rates[0].changed_statements, 1);
    let pair = &corpus.labels.clone_pairs[0];
    assert_eq!(pair.fragments[1].start_line, 4);
    assert_eq!(pair.fragments[1].end_line, 6);
}

#[test]
fn replace_leaves_the_range_alone_and_counts_both_sides() {
    // The edit a delete beside an insert cannot express: the sequence
    // keeps its length and one position holds something else. Both the
    // statement that went and the one that arrived count towards the
    // change rate, or a variant with every statement swapped would score
    // the same as one with half of them removed.
    let mut spec = base_spec();
    spec.variants.push(VariantSpec {
        file: "v3.rs".to_string(),
        clone_type: CloneType::Type3,
        header_comment: "Type-3 variant.".to_string(),
        items: vec![ItemSpec {
            edits: vec![EditOp::Replace {
                anchor: "let y = x * 2;".to_string(),
                lines: vec!["    let y = x + x;".to_string()],
            }],
            ..item("fn twice")
        }],
    });
    let corpus = generate(&spec, SEED).expect("generates");
    assert_eq!(corpus.change_rates[0].changed_statements, 2);
    let pair = &corpus.labels.clone_pairs[0];
    assert_eq!(pair.fragments[1].start_line, 4);
    assert_eq!(pair.fragments[1].end_line, 7);
    assert!(corpus.files["v3.rs"].contains("let y = x + x;"));
    assert!(!corpus.files["v3.rs"].contains("let y = x * 2;"));
}

#[test]
fn a_replacement_needs_the_type_that_allows_statement_edits() {
    let mut spec = base_spec();
    spec.variants.push(VariantSpec {
        file: "v1.rs".to_string(),
        clone_type: CloneType::Type1,
        header_comment: "Type-1 variant.".to_string(),
        items: vec![ItemSpec {
            edits: vec![EditOp::Replace {
                anchor: "let y = x * 2;".to_string(),
                lines: vec!["    let y = x + x;".to_string()],
            }],
            ..item("fn twice")
        }],
    });
    let error = generate(&spec, SEED).expect_err("a type-1 variant refuses it");
    assert!(matches!(error, Error::DisallowedEdit { .. }));
}

#[test]
fn non_clone_ranges_are_recomputed() {
    let mut spec = type2_spec();
    spec.non_clones.push(NonCloneSpec {
        reason: "helper-boilerplate".to_string(),
        function: "fn add".to_string(),
        counterpart: None,
        variant: "v2.rs".to_string(),
    });
    let corpus = generate(&spec, SEED).expect("generates");
    assert_eq!(corpus.labels.non_clones.len(), 1);
    let non_clone = &corpus.labels.non_clones[0];
    assert_eq!(non_clone.id, "nc-001");
    assert_eq!(non_clone.fragments[0].start_line, 3);
    assert_eq!(non_clone.fragments[1].start_line, 4);
}

#[test]
fn a_non_clone_can_name_a_different_counterpart() {
    let mut spec = type2_spec();
    spec.variants[0].items.push(item("fn twice"));
    spec.non_clones.push(NonCloneSpec {
        reason: "same-skeleton-different-logic".to_string(),
        function: "fn add".to_string(),
        counterpart: Some("fn twice".to_string()),
        variant: "v2.rs".to_string(),
    });
    let corpus = generate(&spec, SEED).expect("generates");
    let non_clone = &corpus.labels.non_clones[0];
    // The seed fragment is `fn add`, the variant fragment is `fn twice`
    // as the variant carries it — two different functions, which is what
    // makes the pair a negative rather than an unreportable copy.
    assert_eq!(non_clone.fragments[0].start_line, 3);
    assert_eq!(non_clone.fragments[1].start_line, 9);
}

#[test]
fn a_non_clone_counterpart_must_exist() {
    let mut spec = type2_spec();
    spec.non_clones.push(NonCloneSpec {
        reason: "same-skeleton-different-logic".to_string(),
        function: "fn add".to_string(),
        counterpart: Some("fn missing".to_string()),
        variant: "v2.rs".to_string(),
    });
    let error = generate(&spec, SEED).expect_err("the counterpart is unknown");
    assert!(matches!(
        error,
        Error::UnknownNonCloneRef { ref reference } if reference == "fn missing"
    ));
}

#[test]
fn item_clone_type_override_is_used_in_labels() {
    let mut spec = base_spec();
    spec.variants.push(VariantSpec {
        file: "v3.rs".to_string(),
        clone_type: CloneType::Type3,
        header_comment: "Type-3 variant.".to_string(),
        items: vec![
            ItemSpec {
                edits: vec![EditOp::Delete {
                    anchor: "let sum = a + b;".to_string(),
                }],
                ..item("fn add")
            },
            ItemSpec {
                clone_type: Some(CloneType::Type1),
                ..item("fn twice")
            },
        ],
    });
    let corpus = generate(&spec, SEED).expect("generates");
    assert_eq!(corpus.labels.clone_pairs[0].clone_type, CloneType::Type3);
    assert_eq!(corpus.labels.clone_pairs[1].clone_type, CloneType::Type1);
}

#[test]
fn reindent_changes_indentation_only() {
    let mut spec = base_spec();
    spec.variants.push(VariantSpec {
        file: "v1.rs".to_string(),
        clone_type: CloneType::Type1,
        header_comment: "Type-1 variant.".to_string(),
        items: vec![ItemSpec {
            edits: vec![EditOp::Reindent { unit: 2 }],
            ..item("fn add")
        }],
    });
    let corpus = generate(&spec, SEED).expect("generates");
    assert!(corpus.files["v1.rs"].contains("\n  let sum = a + b;\n"));
}

/// Seed for the transplant tests. `fn donor` spans lines 3..=9 with the
/// fragment `let mut total = 0;` .. `total` on lines 4..=8; `fn host`
/// spans lines 11..=17.
const PARTIAL_SEED: &str = "\
// seed

fn donor(values: &[i32]) -> i32 {
    let mut total = 0;
    for value in values {
        total += *value;
    }
    total
}

fn host(items: &[i32]) -> i32 {
    let mut count = 0;
    for item in items {
        count += 1;
    }
    count
}
";

fn partial_spec() -> MutationSpec {
    let mut spec = base_spec();
    spec.variants.push(VariantSpec {
        file: "partial.rs".to_string(),
        clone_type: CloneType::Type3,
        header_comment: "Partial variant.".to_string(),
        items: vec![ItemSpec {
            labelled: false,
            transplants: vec![TransplantSpec {
                labelled: true,
                clone_type: Some(CloneType::Type1),
                ..transplant(
                    "fn donor",
                    "let mut total = 0;",
                    "total",
                    "let mut count = 0;",
                )
            }],
            ..item("fn host")
        }],
    });
    spec
}

#[test]
fn transplant_inserts_the_donor_fragment_verbatim() {
    let corpus = generate(&partial_spec(), PARTIAL_SEED).expect("generates");
    let expected = format!(
        "// Partial variant.\n{GENERATED_MARKER}\n\n\
             fn host(items: &[i32]) -> i32 {{\n    let mut count = 0;\n    let mut total = 0;\n    for value in values {{\n        total += *value;\n    }}\n    total\n    for item in items {{\n        count += 1;\n    }}\n    count\n}}\n"
    );
    assert_eq!(corpus.files["partial.rs"], expected);
    // The transplanted statements count toward the host's change rate.
    assert_eq!(corpus.change_rates.len(), 1);
    assert_eq!(corpus.change_rates[0].changed_statements, 4);
    assert_eq!(corpus.change_rates[0].total_statements, 4);
}

#[test]
fn transplant_pairs_the_donor_fragment_with_the_transplanted_lines() {
    let corpus = generate(&partial_spec(), PARTIAL_SEED).expect("generates");
    assert_eq!(corpus.labels.clone_pairs.len(), 1);
    let pair = &corpus.labels.clone_pairs[0];
    assert_eq!(pair.clone_type, CloneType::Type1);
    // Donor fragment: seed lines 4..=8. Variant: header, marker, blank
    // line and the host's first two lines precede it, so lines 6..=10.
    assert_eq!(
        pair.fragments,
        vec![
            Fragment {
                file: "seed.rs".to_string(),
                start_line: 4,
                end_line: 8,
                tokens: 0,
            },
            Fragment {
                file: "partial.rs".to_string(),
                start_line: 6,
                end_line: 10,
                tokens: 0,
            },
        ]
    );
}

#[test]
fn renamed_transplant_is_a_type2_partial_clone() {
    let mut spec = partial_spec();
    let transplanted = &mut spec.variants[0].items[0].transplants[0];
    transplanted.clone_type = Some(CloneType::Type2);
    transplanted.rename = map(&[("total", "sum"), ("value", "entry"), ("values", "items")]);
    transplanted.literals = map(&[("0", "1")]);
    let corpus = generate(&spec, PARTIAL_SEED).expect("generates");
    let text = &corpus.files["partial.rs"];
    assert!(text.contains(
        "\n    let mut sum = 1;\n    for entry in items {\n        sum += *entry;\n    }\n    sum\n"
    ));
    let pair = &corpus.labels.clone_pairs[0];
    assert_eq!(pair.clone_type, CloneType::Type2);
    // Substitution preserves line structure, so the ranges are unchanged.
    assert_eq!(pair.fragments[0].start_line, 4);
    assert_eq!(pair.fragments[0].end_line, 8);
    assert_eq!(pair.fragments[1].start_line, 6);
    assert_eq!(pair.fragments[1].end_line, 10);
}

#[test]
fn transplant_non_clone_is_labelled_at_fragment_granularity() {
    let mut spec = partial_spec();
    let transplanted = &mut spec.variants[0].items[0].transplants[0];
    transplanted.labelled = false;
    transplanted.clone_type = None;
    transplanted.non_clone = Some("loop-boilerplate".to_string());
    spec.non_clones.push(NonCloneSpec {
        reason: "host-scaffold".to_string(),
        function: "fn host".to_string(),
        counterpart: None,
        variant: "partial.rs".to_string(),
    });
    let corpus = generate(&spec, PARTIAL_SEED).expect("generates");
    assert!(corpus.labels.clone_pairs.is_empty());
    assert_eq!(corpus.labels.non_clones.len(), 2);
    // Spec-level non-clones come first; the transplant-derived one
    // continues the id numbering at fragment granularity.
    assert_eq!(corpus.labels.non_clones[0].id, "nc-001");
    assert_eq!(corpus.labels.non_clones[0].reason, "host-scaffold");
    let fragment_level = &corpus.labels.non_clones[1];
    assert_eq!(fragment_level.id, "nc-002");
    assert_eq!(fragment_level.reason, "loop-boilerplate");
    assert_eq!(
        fragment_level.fragments,
        vec![
            Fragment {
                file: "seed.rs".to_string(),
                start_line: 4,
                end_line: 8,
                tokens: 0,
            },
            Fragment {
                file: "partial.rs".to_string(),
                start_line: 6,
                end_line: 10,
                tokens: 0,
            },
        ]
    );
}

#[test]
fn transplant_range_survives_a_donor_copy_in_the_same_variant() {
    let mut spec = partial_spec();
    spec.variants[0].items.insert(
        0,
        ItemSpec {
            clone_type: Some(CloneType::Type1),
            ..item("fn donor")
        },
    );
    let corpus = generate(&spec, PARTIAL_SEED).expect("generates");
    assert_eq!(corpus.labels.clone_pairs.len(), 2);
    // The donor's own copy maps by provenance (variant lines 4..=10);
    // the transplant maps by insertion identity, unaffected by the donor
    // copy carrying the same seed lines.
    assert_eq!(corpus.labels.clone_pairs[0].fragments[1].start_line, 4);
    assert_eq!(corpus.labels.clone_pairs[0].fragments[1].end_line, 10);
    assert_eq!(corpus.labels.clone_pairs[1].fragments[0].start_line, 4);
    assert_eq!(corpus.labels.clone_pairs[1].fragments[0].end_line, 8);
    assert_eq!(corpus.labels.clone_pairs[1].fragments[1].start_line, 14);
    assert_eq!(corpus.labels.clone_pairs[1].fragments[1].end_line, 18);
}

#[test]
fn transplant_generation_is_deterministic() {
    let first = generate(&partial_spec(), PARTIAL_SEED).expect("first run");
    let second = generate(&partial_spec(), PARTIAL_SEED).expect("second run");
    assert_eq!(first, second);
}

#[test]
fn transplant_requires_a_type3_host() {
    let mut spec = partial_spec();
    spec.variants[0].clone_type = CloneType::Type2;
    spec.variants[0].items[0].transplants[0].clone_type = Some(CloneType::Type1);
    assert!(matches!(
        generate(&spec, PARTIAL_SEED),
        Err(Error::DisallowedEdit { .. })
    ));
}

#[test]
fn labelled_transplant_must_declare_type1_or_type2() {
    let mut spec = partial_spec();
    // Without an override the label type defaults to the variant's
    // type-3, which a labelled transplant cannot carry.
    spec.variants[0].items[0].transplants[0].clone_type = None;
    assert!(matches!(
        generate(&spec, PARTIAL_SEED),
        Err(Error::DisallowedEdit { .. })
    ));
}

#[test]
fn type1_transplant_rejects_substitution() {
    let mut spec = partial_spec();
    spec.variants[0].items[0].transplants[0].rename = map(&[("total", "sum")]);
    assert!(matches!(
        generate(&spec, PARTIAL_SEED),
        Err(Error::DisallowedEdit { .. })
    ));
}

#[test]
fn transplant_cannot_be_both_labelled_and_non_clone() {
    let mut spec = partial_spec();
    spec.variants[0].items[0].transplants[0].non_clone = Some("boilerplate".to_string());
    assert!(matches!(
        generate(&spec, PARTIAL_SEED),
        Err(Error::DisallowedEdit { .. })
    ));
}

#[test]
fn transplant_unknown_donor_is_an_error() {
    let mut spec = partial_spec();
    spec.variants[0].items[0].transplants[0].donor = "fn missing".to_string();
    assert!(matches!(
        generate(&spec, PARTIAL_SEED),
        Err(Error::UnknownItem { .. })
    ));
}

#[test]
fn unbalanced_transplant_fragment_is_rejected() {
    let mut spec = partial_spec();
    spec.variants[0].items[0].transplants[0] = TransplantSpec {
        labelled: true,
        clone_type: Some(CloneType::Type1),
        ..transplant(
            "fn donor",
            "for value in values {",
            "total += *value;",
            "let mut count = 0;",
        )
    };
    assert!(matches!(
        generate(&spec, PARTIAL_SEED),
        Err(Error::DisallowedEdit { .. })
    ));
}

#[test]
fn reversed_transplant_anchors_are_rejected() {
    let mut spec = partial_spec();
    spec.variants[0].items[0].transplants[0] = TransplantSpec {
        labelled: true,
        clone_type: Some(CloneType::Type1),
        ..transplant(
            "fn donor",
            "total",
            "let mut total = 0;",
            "let mut count = 0;",
        )
    };
    assert!(matches!(
        generate(&spec, PARTIAL_SEED),
        Err(Error::DisallowedEdit { .. })
    ));
}

#[test]
fn unknown_item_is_an_error() {
    let mut spec = type2_spec();
    spec.variants[0].items[0].item = "fn missing".to_string();
    assert!(matches!(
        generate(&spec, SEED),
        Err(Error::UnknownItem { .. })
    ));
}

#[test]
fn ambiguous_anchor_is_an_error() {
    let seed = "fn f() {\n    same();\n    same();\n}\n";
    let mut spec = base_spec();
    spec.variants.push(VariantSpec {
        file: "v3.rs".to_string(),
        clone_type: CloneType::Type3,
        header_comment: "Variant.".to_string(),
        items: vec![ItemSpec {
            edits: vec![EditOp::Delete {
                anchor: "same();".to_string(),
            }],
            ..item("fn f")
        }],
    });
    assert!(matches!(
        generate(&spec, seed),
        Err(Error::AmbiguousAnchor { .. })
    ));
}

#[test]
fn missing_anchor_is_an_error() {
    let mut spec = base_spec();
    spec.variants.push(VariantSpec {
        file: "v3.rs".to_string(),
        clone_type: CloneType::Type3,
        header_comment: "Variant.".to_string(),
        items: vec![ItemSpec {
            edits: vec![EditOp::Delete {
                anchor: "nowhere();".to_string(),
            }],
            ..item("fn add")
        }],
    });
    assert!(matches!(
        generate(&spec, SEED),
        Err(Error::AnchorNotFound { .. })
    ));
}

#[test]
fn type1_rejects_substitution() {
    let mut spec = base_spec();
    spec.variants.push(VariantSpec {
        file: "v1.rs".to_string(),
        clone_type: CloneType::Type1,
        header_comment: "Variant.".to_string(),
        items: vec![ItemSpec {
            rename: map(&[("a", "b")]),
            ..item("fn add")
        }],
    });
    assert!(matches!(
        generate(&spec, SEED),
        Err(Error::DisallowedEdit { .. })
    ));
}

#[test]
fn type2_rejects_statement_edits() {
    let mut spec = type2_spec();
    spec.variants[0].items[0].edits.push(EditOp::Delete {
        anchor: "sum".to_string(),
    });
    assert!(matches!(
        generate(&spec, SEED),
        Err(Error::DisallowedEdit { .. })
    ));
}

#[test]
fn unknown_language_is_rejected() {
    let mut spec = type2_spec();
    spec.language = "fortran".to_string();
    assert!(matches!(
        generate(&spec, SEED),
        Err(Error::UnsupportedLanguage { .. })
    ));
}

#[test]
fn c_seed_items_are_mutated_like_rust_ones() {
    let seed = "\
int add(int a, int b) {
    int sum = a + b;
    return sum;
}
";
    let mut spec = base_spec();
    spec.language = "c".to_string();
    spec.seed = "seed.c".to_string();
    spec.variants.push(VariantSpec {
        file: "v2.c".to_string(),
        clone_type: CloneType::Type2,
        header_comment: "Type-2 variant.".to_string(),
        items: vec![ItemSpec {
            rename: map(&[("a", "p"), ("b", "q"), ("sum", "total")]),
            ..item("fn add")
        }],
    });
    let corpus = generate(&spec, seed).expect("generates");
    let expected = format!(
        "// Type-2 variant.\n{GENERATED_MARKER}\n\n\
             int add(int p, int q) {{\n    int total = p + q;\n    return total;\n}}\n"
    );
    assert_eq!(corpus.files["v2.c"], expected);
    assert_eq!(corpus.labels.language, "c");
}

#[test]
fn wrong_schema_version_is_rejected() {
    let mut spec = type2_spec();
    spec.schema_version = 99;
    assert!(matches!(
        generate(&spec, SEED),
        Err(Error::UnsupportedSchemaVersion(99))
    ));
}

#[test]
fn labels_file_round_trips_through_the_eval_parser() {
    let corpus = generate(&type2_spec(), SEED).expect("generates");
    let parsed = LabelSet::from_json(&corpus.files[LABELS_FILE]).expect("labels parse");
    assert_eq!(parsed, corpus.labels);
}

#[test]
fn first_difference_reports_the_first_diverging_line() {
    assert_eq!(first_difference("a\nb\n", "a\nb\n"), None);
    assert_eq!(first_difference("a\nb\n", "a\nc\n"), Some(2));
    assert_eq!(first_difference("a\n", "a\nb\n"), Some(2));
}
