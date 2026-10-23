//! Every scalar fact a report states reaches its text, CSV and JSON renderings.

use super::*;

/// The value a JSON field carries, spelled as the fact table spells it.
fn json_fact(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::Null => None,
        serde_json::Value::String(text) => Some(text.clone()),
        serde_json::Value::Array(items) if items.is_empty() => None,
        serde_json::Value::Array(items) => Some(
            items
                .iter()
                .map(|item| item.as_str().unwrap().to_owned())
                .collect::<Vec<_>>()
                .join(", "),
        ),
        other => Some(other.to_string()),
    }
}

/// Check every fact of `facts` against one report's three renderings.
fn assert_facts_reach_every_rendering<R: Serialize>(
    facts: &[ReportFact<R>],
    report: &R,
    header: &[&str],
    text: &str,
    csv: &str,
) {
    let json = serde_json::to_value(report).unwrap();
    let mut records = csv.lines();
    let columns = artifact_csv_fields(records.next().unwrap());
    let summary = artifact_csv_fields(records.next().unwrap());
    assert_eq!(columns, header);
    for fact in facts {
        let value = (fact.value)(report);
        assert!(value.is_some(), "the fixture states no {}", fact.column);
        assert_eq!(
            header
                .iter()
                .filter(|column| **column == fact.column)
                .count(),
            1,
            "{} names one column",
            fact.column
        );
        let index = header
            .iter()
            .position(|column| *column == fact.column)
            .unwrap();
        assert_eq!(
            summary[index],
            value.clone().unwrap(),
            "CSV {}",
            fact.column
        );
        assert_eq!(
            json.pointer(fact.json_pointer).and_then(json_fact),
            value,
            "JSON {}",
            fact.json_pointer
        );
        let line = format!("{}: {}", fact.label, value.unwrap());
        assert!(
            text.lines().any(|candidate| candidate == line),
            "text {line}\n{text}"
        );
    }
}

#[test]
fn every_artifact_fact_reaches_text_csv_and_json() {
    let mut artifact = ArtifactIr::empty(BinaryFormat::MachO, b"fixture");
    artifact.architecture = Some("arm64".to_owned());
    artifact.skipped_architectures = vec!["x86_64".to_owned(), "arm64e".to_owned()];
    let report = ArtifactReport::from_ir(
        std::path::Path::new("fixture.dylib"),
        &artifact,
        Some(5),
        None,
    );
    let mut text = Vec::new();
    render_text(&report, false, &mut text).unwrap();
    let mut csv = Vec::new();
    render_csv(&report, &mut csv).unwrap();
    let text = String::from_utf8(text).unwrap();
    assert!(text.contains("analysis: 5"), "{text}");
    assert_facts_reach_every_rendering(
        ARTIFACT_FACTS,
        &report,
        ARTIFACT_CSV_HEADER,
        &text,
        &String::from_utf8(csv).unwrap(),
    );
}

#[test]
fn every_comparison_fact_reaches_text_csv_and_json() {
    let side = |bytes: &[u8], architecture: &str| {
        let mut artifact = ArtifactIr::empty(BinaryFormat::MachO, bytes);
        artifact.architecture = Some(architecture.to_owned());
        artifact.skipped_architectures = vec!["x86_64".to_owned()];
        artifact
    };
    let variant = |path: &str| ComparisonBuildVariant {
        manifest_path: path.to_owned(),
        fingerprint: "cd".repeat(16),
    };
    let report = ArtifactComparisonReport::new(
        std::path::Path::new("before.dylib"),
        &side(b"before", "arm64"),
        Some(variant("before.json")),
        std::path::Path::new("after.dylib"),
        &side(b"after", "arm64"),
        Some(variant("after.json")),
    );
    let mut text = Vec::new();
    render_compare_text(&report, &mut text).unwrap();
    let mut csv = Vec::new();
    render_compare_csv(&report, &mut csv).unwrap();
    assert_facts_reach_every_rendering(
        COMPARISON_FACTS,
        &report,
        COMPARE_CSV_HEADER,
        &String::from_utf8(text).unwrap(),
        &String::from_utf8(csv).unwrap(),
    );
}
