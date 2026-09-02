use super::*;
use crate::corpus::generate::generate;
use crate::corpus::generate::tests::{
    PARTIAL_SEED, SEED, base_spec, item, map, partial_spec, transplant, type2_spec,
};

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
    spec.variants[0].items[0].transplants[0].non_clone = Some("list-walk-idiom".to_string());
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
