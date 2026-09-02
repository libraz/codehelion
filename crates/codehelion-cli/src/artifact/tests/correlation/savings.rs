//! Estimated refactor savings and the confidence they are reported with.

use super::*;
use crate::artifact::correlation::savings::{
    estimate_refactor_savings_bytes, refactor_savings_model,
};

/// A savings row reports the weakest mapping that paid into it, so a group
/// divided by source lines cannot read like one split exactly.
#[test]
fn savings_confidence_follows_the_weakest_contributing_mapping() {
    let rows = line_proportional_rows();

    let savings = clone_group_savings(&rows);

    assert_eq!(savings.len(), 1);
    assert_eq!(savings[0].duplicated_bytes, 9);
    assert_eq!(savings[0].mapping_confidence, EvidenceConfidence::Medium);
    assert_ne!(savings[0].mapping_confidence, EvidenceConfidence::High);
    let json = serde_json::to_value(&savings[0]).unwrap();
    let assumptions = json["assumptions"].as_array().unwrap();
    assert!(
        assumptions
            .iter()
            .any(|assumption| assumption["kind"] == "attribution_is_line_proportional"),
        "{json}"
    );
    let artifact = ArtifactIr::empty(BinaryFormat::Elf, b"fixture");
    let report = ArtifactReport::from_ir(FilePath::new("fixture.so"), &artifact, None, None)
        .with_correlation(Some(ArtifactCorrelationReport::from_rows(
            7, &artifact, &rows,
        )));
    let mut text = Vec::new();
    render_text(&report, false, &mut text).unwrap();
    let text = String::from_utf8(text).unwrap();
    assert!(text.contains("mapping Medium"), "{text}");
    assert!(
        text.contains("divided across its symbol's source lines rather than observed"),
        "{text}"
    );
    let mut csv = Vec::new();
    render_csv(&report, &mut csv).unwrap();
    let csv = String::from_utf8(csv).unwrap();
    assert!(csv.contains("attribution_is_line_proportional"), "{csv}");
}

/// An ambiguous mapping paid no bytes anyone can stand behind, so the group it
/// touched reports no savings row rather than a graded one.
#[test]
fn an_ambiguous_contributing_mapping_removes_the_savings_row() {
    let mut rows = line_proportional_rows();
    rows.mappings[0].evidence = MappingEvidence::new(
        vec![MappingEvidenceFact::Dwarf {
            source_path: "src/two.rs".to_owned(),
        }],
        2,
        false,
    );

    assert!(clone_group_savings(&rows).is_empty());
}

#[test]
fn refactoring_estimate_keeps_negative_overhead_outcomes_visible() {
    let mut model = refactor_savings_model();
    model.call_overhead_per_replaced_member_bytes = 12;
    assert_eq!(estimate_refactor_savings_bytes(9, 1, &model), -3);
}
