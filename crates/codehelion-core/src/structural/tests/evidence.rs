//! Evidence primitives: identifier-set agreement and allocation APIs.

use super::*;

#[test]
fn identifier_jaccard_compares_raw_identifier_sets() {
    let first = BTreeSet::from(["candidate", "token", "value"]);
    let second = BTreeSet::from(["candidate", "other", "value"]);
    let empty = BTreeSet::new();

    assert_eq!(set_jaccard(&first, &first), Some(1.0));
    assert_eq!(set_jaccard(&first, &second), Some(0.5));
    assert_eq!(
        set_jaccard(&empty, &empty),
        None,
        "two spans naming nothing agree about nothing"
    );
    assert_eq!(
        set_jaccard(&first, &empty),
        Some(0.0),
        "one side naming something is a comparison that was made"
    );
}

#[test]
fn allocation_evidence_accepts_explicit_apis_without_guessing_wrappers() {
    assert!(is_allocation_api(&"with_capacity".into()));
    assert!(is_allocation_api(&"malloc".into()));
    assert!(!is_allocation_api(&"build_buffer".into()));
}
