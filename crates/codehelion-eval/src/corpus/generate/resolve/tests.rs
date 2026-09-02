use super::*;
use crate::corpus::generate::generate;
use crate::corpus::generate::tests::{
    PARTIAL_SEED, SEED, base_spec, item, partial_spec, type2_spec,
};
use crate::corpus::spec::{EditOp, ItemSpec, VariantSpec};
use crate::schema::{CloneType, SiblingBasis};

#[test]
fn known_siblings_resolve_seed_and_variant_items_to_exact_ranges() {
    let mut spec = base_spec();
    spec.variants.push(VariantSpec {
        file: "v1.rs".to_string(),
        clone_type: CloneType::Type1,
        header_comment: "Mirror variant.".to_string(),
        items: vec![item("fn add"), item("fn twice")],
    });
    spec.known_siblings.push(KnownSiblingSpec {
        basis: SiblingBasis::Signature,
        primary_fragments: [
            ItemRef {
                file: "seed.rs".to_string(),
                item: "fn add".to_string(),
            },
            ItemRef {
                file: "v1.rs".to_string(),
                item: "fn add".to_string(),
            },
        ],
        sibling: ItemRef {
            file: "v1.rs".to_string(),
            item: "fn twice".to_string(),
        },
    });
    let corpus = generate(&spec, SEED).expect("generates known sibling");
    assert_eq!(corpus.labels.known_siblings.len(), 1);
    let known = &corpus.labels.known_siblings[0];
    assert_eq!(known.id, "ks-001");
    assert_eq!(known.basis, SiblingBasis::Signature);
    assert_eq!(
        known.primary_fragments[0],
        Fragment {
            file: "seed.rs".to_string(),
            start_line: 3,
            end_line: 6,
            tokens: 0,
        }
    );
    assert_eq!(
        known.primary_fragments[1],
        Fragment {
            file: "v1.rs".to_string(),
            start_line: 4,
            end_line: 7,
            tokens: 0,
        }
    );
    assert_eq!(
        known.sibling,
        Fragment {
            file: "v1.rs".to_string(),
            start_line: 9,
            end_line: 12,
            tokens: 0,
        }
    );
}

#[test]
fn known_sibling_ranges_include_inserted_lines_not_just_seed_provenance() {
    let mut spec = base_spec();
    spec.variants.push(VariantSpec {
        file: "v3.rs".to_string(),
        clone_type: CloneType::Type3,
        header_comment: "Inserted mirror variant.".to_string(),
        items: vec![ItemSpec {
            edits: vec![EditOp::InsertBefore {
                anchor: "fn add(a: i32, b: i32) -> i32 {".to_string(),
                lines: vec![
                    "fn generated_header() -> i32 {".to_string(),
                    "    7".to_string(),
                    "}".to_string(),
                ],
            }],
            ..item("fn add")
        }],
    });
    spec.known_siblings.push(KnownSiblingSpec {
        basis: SiblingBasis::Similarity,
        primary_fragments: [
            ItemRef {
                file: "seed.rs".to_string(),
                item: "fn add".to_string(),
            },
            ItemRef {
                file: "seed.rs".to_string(),
                item: "fn twice".to_string(),
            },
        ],
        sibling: ItemRef {
            file: "v3.rs".to_string(),
            item: "fn add".to_string(),
        },
    });
    let corpus = generate(&spec, SEED).expect("generates inserted lines");
    assert_eq!(
        corpus.labels.known_siblings[0].sibling,
        Fragment {
            file: "v3.rs".to_string(),
            start_line: 4,
            end_line: 10,
            tokens: 0,
        }
    );
}

#[test]
fn unknown_known_sibling_item_is_rejected() {
    let mut spec = base_spec();
    spec.known_siblings.push(KnownSiblingSpec {
        basis: SiblingBasis::Signature,
        primary_fragments: [
            ItemRef {
                file: "seed.rs".to_string(),
                item: "fn missing".to_string(),
            },
            ItemRef {
                file: "seed.rs".to_string(),
                item: "fn twice".to_string(),
            },
        ],
        sibling: ItemRef {
            file: "seed.rs".to_string(),
            item: "fn add".to_string(),
        },
    });
    assert!(matches!(
        generate(&spec, SEED),
        Err(Error::UnknownKnownSiblingRef { .. })
    ));
}

#[test]
fn duplicate_known_sibling_relationship_is_rejected() {
    let mut spec = base_spec();
    for file in ["v1.rs", "v2.rs"] {
        spec.variants.push(VariantSpec {
            file: file.to_string(),
            clone_type: CloneType::Type1,
            header_comment: "Mirror variant.".to_string(),
            items: vec![item("fn add")],
        });
    }
    let declaration = KnownSiblingSpec {
        basis: SiblingBasis::Signature,
        primary_fragments: [
            ItemRef {
                file: "seed.rs".to_string(),
                item: "fn add".to_string(),
            },
            ItemRef {
                file: "seed.rs".to_string(),
                item: "fn twice".to_string(),
            },
        ],
        sibling: ItemRef {
            file: "v1.rs".to_string(),
            item: "fn add".to_string(),
        },
    };
    spec.known_siblings.push(declaration.clone());
    spec.known_siblings.push(declaration);
    assert!(matches!(
        generate(&spec, SEED),
        Err(Error::DuplicateKnownSiblingRef { .. })
    ));
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
fn non_clone_ranges_are_recomputed() {
    let mut spec = type2_spec();
    spec.non_clones.push(NonCloneSpec {
        reason: "single-expression-return".to_string(),
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
        reason: "different-computation-skeleton".to_string(),
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
        reason: "different-computation-skeleton".to_string(),
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
fn transplant_non_clone_is_labelled_at_fragment_granularity() {
    let mut spec = partial_spec();
    let transplanted = &mut spec.variants[0].items[0].transplants[0];
    transplanted.labelled = false;
    transplanted.clone_type = None;
    transplanted.non_clone = Some("list-walk-idiom".to_string());
    spec.non_clones.push(NonCloneSpec {
        reason: "declaration-run".to_string(),
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
    assert_eq!(corpus.labels.non_clones[0].reason, "declaration-run");
    let fragment_level = &corpus.labels.non_clones[1];
    assert_eq!(fragment_level.id, "nc-002");
    assert_eq!(fragment_level.reason, "list-walk-idiom");
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
