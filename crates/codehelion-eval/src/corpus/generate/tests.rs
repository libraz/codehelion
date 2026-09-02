use super::*;
use crate::corpus::spec::{ItemSpec, NonCloneSpec, TransplantSpec, VariantSpec};

pub(super) const SEED: &str = "\
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

pub(super) fn base_spec() -> MutationSpec {
    MutationSpec {
        schema_version: 1,
        language: "rust".to_string(),
        seed: "seed.rs".to_string(),
        variants: Vec::new(),
        non_clones: Vec::new(),
        known_siblings: Vec::new(),
    }
}

pub(super) fn item(key: &str) -> ItemSpec {
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

pub(super) fn transplant(donor: &str, from: &str, to: &str, after: &str) -> TransplantSpec {
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

pub(super) fn map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|&(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

pub(super) fn type2_spec() -> MutationSpec {
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

/// Seed for the transplant tests. `fn donor` spans lines 3..=9 with the
/// fragment `let mut total = 0;` .. `total` on lines 4..=8; `fn host`
/// spans lines 11..=17.
pub(super) const PARTIAL_SEED: &str = "\
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

pub(super) fn partial_spec() -> MutationSpec {
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

/// A reason the scorers do not know is a corpus that generates cleanly and
/// then fails every reader. The generator answers instead of the reader.
#[test]
fn a_spec_level_non_clone_reason_must_be_registered() {
    let mut spec = type2_spec();
    spec.non_clones.push(NonCloneSpec {
        reason: "helper-boilerplate".to_string(),
        function: "fn add".to_string(),
        counterpart: None,
        variant: "v2.rs".to_string(),
    });
    let error = generate(&spec, SEED).expect_err("the reason is not a recorded class");
    assert!(
        matches!(
            error,
            Error::UnsupportedNonCloneReason { ref label, ref reason }
                if label == "nc-001" && reason == "helper-boilerplate"
        ),
        "{error}"
    );
}

#[test]
fn a_transplant_non_clone_reason_must_be_registered() {
    let mut spec = partial_spec();
    let transplanted = &mut spec.variants[0].items[0].transplants[0];
    transplanted.labelled = false;
    transplanted.clone_type = None;
    transplanted.non_clone = Some("loop-boilerplate".to_string());
    let error = generate(&spec, PARTIAL_SEED).expect_err("the reason is not a recorded class");
    assert!(
        matches!(
            error,
            Error::UnsupportedNonCloneReason { ref reason, .. } if reason == "loop-boilerplate"
        ),
        "{error}"
    );
}

/// The generated document is read back by the same parser every scorer uses,
/// so a corpus that generates is a corpus that scores.
#[test]
fn a_generated_label_document_is_accepted_by_the_label_reader() {
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
    let labels = LabelSet::from_json(&corpus.files[LABELS_FILE])
        .expect("the reader accepts every generated reason");
    assert_eq!(labels.non_clones.len(), 2);
    assert_eq!(
        labels
            .non_clones
            .iter()
            .map(|n| n.reason.as_str())
            .collect::<Vec<_>>(),
        vec!["declaration-run", "list-walk-idiom"]
    );
}

#[test]
fn transplant_generation_is_deterministic() {
    let first = generate(&partial_spec(), PARTIAL_SEED).expect("first run");
    let second = generate(&partial_spec(), PARTIAL_SEED).expect("second run");
    assert_eq!(first, second);
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
