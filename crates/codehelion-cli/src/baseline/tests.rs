use super::*;
use codehelion_store::query::{StoredMember, StoredSuppressionRef};

fn origin() -> RunOrigin {
    RunOrigin {
        id: 7,
        root_path: "/repo".to_string(),
        tool_version: "0.1.0".to_string(),
        config_source: "defaults".to_string(),
        config_path: None,
        min_clone_tokens: 20,
        analysis_mode: "structural".to_string(),
        started_at: "2026-07-27T00:00:00Z".to_string(),
        finished_at: "2026-07-27T00:00:05Z".to_string(),
        variant_fingerprint: "abcdef0123456789".to_string(),
        normalization_version: 1,
        detector_versions: vec![("fp-schema".to_string(), "fp-schema-v1".to_string())],
    }
}

fn only_partition(baseline: &Baseline) -> &BaselinePartition {
    baseline
        .partitions
        .first()
        .expect("the one-run fixture has one partition")
}

fn member(finding: &str, path: &str, canonical: bool) -> StoredMember {
    StoredMember {
        language: "rust".to_string(),
        content_hex: "c0".repeat(16),
        finding_hex: finding.to_string(),
        file_path: path.to_string(),
        start_line: Some(10),
        end_line: Some(20),
        token_count: 42,
        unit_name: Some("parse".to_string()),
        boilerplate: None,
        is_canonical: canonical,
    }
}

fn group(fingerprint: &str) -> StoredGroup {
    StoredGroup {
        fingerprint_hex: fingerprint.to_string(),
        clone_type: "type-2".to_string(),
        member_scope: "unit".to_string(),
        score: 0.9,
        entropy_bits: 4.0,
        suppress_reason: None,
        boilerplate: None,
        split_pair: false,
        test_code: false,
        test_code_evidence: None,
        width_family: false,
        statements: None,
        identifier_jaccard: None,
        has_loop: None,
        has_dynamic_allocation: None,
        call_count: None,
        similarity: None,
        semantic: None,
        suppressed_by: None,
        siblings: Vec::new(),
        members: vec![
            member("f1", "src/a.rs", true),
            member("f2", "src/b.rs", false),
        ],
    }
}

#[test]
fn freezing_a_run_records_what_it_reported_and_what_it_was() {
    let groups = vec![group("aa11"), group("bb22")];
    let baseline = Baseline::from_run(&origin(), &groups, "2026-07-27T01:00:00Z");
    let partition = only_partition(&baseline);

    assert_eq!(baseline.schema_version, SCHEMA_VERSION);
    assert_eq!(partition.from_run, 7);
    assert_eq!(partition.build_variant.fingerprint, "abcdef0123456789");
    assert_eq!(partition.entries.len(), 2);
    assert_eq!(partition.entries[0].group, "aa11");
    assert_eq!(partition.entries[0].instances, 2);
    let sites: Vec<&str> = partition.entries[0]
        .occurrences
        .iter()
        .map(|occurrence| occurrence.file.as_str())
        .collect();
    assert_eq!(sites, vec!["src/a.rs", "src/b.rs"]);
    let findings: Vec<&str> = partition.entries[0]
        .occurrences
        .iter()
        .map(|occurrence| occurrence.finding.as_str())
        .collect();
    assert_eq!(findings, vec!["f1", "f2"]);
    // Two 42-token copies repeat everything past the one a reader keeps.
    assert_eq!(partition.entries[0].duplicated_tokens, 42);
    let anchor = partition.entries[0].anchor.as_ref().expect("an anchor");
    assert_eq!(anchor.file, "src/a.rs");
    assert_eq!(anchor.unit.as_deref(), Some("parse"));
}

#[test]
fn a_group_the_run_already_hid_is_not_frozen_again() {
    let mut hidden = group("cc33");
    hidden.suppressed_by = Some(StoredSuppressionRef {
        scope: "path_glob".to_string(),
        pattern: "vendor/**".to_string(),
        reason: None,
        active: Some(true),
    });
    let mut noisy = group("dd44");
    noisy.suppress_reason = Some("low-entropy".to_string());

    let baseline = Baseline::from_run(
        &origin(),
        &[group("aa11"), hidden, noisy],
        "2026-07-27T01:00:00Z",
    );
    // Freezing a hidden group would outlive the rule that hid it.
    assert_eq!(baseline.ids(), BTreeSet::from(["aa11"]));
}

#[test]
fn a_baseline_keeps_each_invocation_variant_in_its_own_partition() {
    let mut second = origin();
    second.id = 8;
    second.analysis_mode = "semantic".to_string();
    second.variant_fingerprint = "1122334455667788".to_string();
    let baseline = Baseline::from_runs(
        &[
            (origin(), vec![group("aa11")]),
            (second.clone(), vec![group("bb22")]),
        ],
        "2026-07-27T01:00:00Z",
    )
    .expect("two parts of one invocation form one baseline");

    assert_eq!(baseline.partitions.len(), 2);
    assert_eq!(
        baseline
            .partition("abcdef0123456789")
            .expect("first variant")
            .entries[0]
            .group,
        "aa11"
    );
    assert_eq!(
        baseline
            .partition(&second.variant_fingerprint)
            .expect("second variant")
            .entries[0]
            .group,
        "bb22"
    );

    let present = BTreeSet::from(["aa11".to_string()]);
    let (pruned, dropped) = baseline.pruned_partition("abcdef0123456789", &present);
    assert!(dropped.is_empty());
    assert_eq!(
        pruned
            .partition(&second.variant_fingerprint)
            .expect("an unrelated variant is retained")
            .entries[0]
            .group,
        "bb22"
    );
}

#[test]
fn a_baseline_refuses_to_mix_partitions_from_different_invocations() {
    let mut later = origin();
    later.id = 8;
    later.started_at = "2026-07-28T00:00:00Z".to_string();
    let error = Baseline::from_runs(
        &[
            (origin(), vec![group("aa11")]),
            (later, vec![group("bb22")]),
        ],
        "2026-07-28T01:00:00Z",
    )
    .expect_err("runs from separate invocations cannot make one baseline");
    assert!(format!("{error:#}").contains("different invocations"));
}

#[test]
fn pruning_drops_what_is_gone_and_adopts_nothing_new() {
    let baseline = Baseline::from_run(
        &origin(),
        &[group("aa11"), group("bb22")],
        "2026-07-27T01:00:00Z",
    );
    let present: BTreeSet<String> = ["aa11".to_string(), "ee55".to_string()]
        .into_iter()
        .collect();

    let (pruned, dropped) = baseline.pruned_partition("abcdef0123456789", &present);
    assert_eq!(dropped, vec!["bb22".to_string()]);
    // `ee55` appeared after the baseline was recorded: that is precisely
    // what the baseline exists to show, so it is not taken in.
    assert_eq!(pruned.ids(), BTreeSet::from(["aa11"]));
}

/// A scan group standing at `sites`, with `tokens` repeated.
fn scanned<'a>(group: &'a str, tokens: u64, sites: &[(&'a str, &'a str)]) -> ScanGroup<'a> {
    ScanGroup {
        group,
        instances: as_u64(sites.len()),
        duplicated_tokens: tokens,
        sites: sites
            .iter()
            .map(|(file, unit)| (*file, Some(*unit)))
            .collect(),
    }
}

#[test]
fn a_delta_sorts_a_scan_into_gone_continuing_and_appeared() {
    let baseline = Baseline::from_run(
        &origin(),
        &[group("aa11"), group("bb22")],
        "2026-07-27T01:00:00Z",
    );

    let delta = only_partition(&baseline).delta(&[
        scanned("aa11", 40, &[("src/a.rs", "parse")]),
        scanned("ee55", 90, &[("src/z.rs", "other")]),
    ]);

    assert_eq!(delta.continuing, 1);
    assert_eq!(delta.gone.len(), 1);
    assert_eq!(delta.gone[0].group, "bb22");
    assert_eq!(delta.gone[0].duplicated_tokens, 42);
    assert_eq!(delta.appeared.len(), 1);
    assert_eq!(delta.appeared[0].group, "ee55");
    assert_eq!(delta.appeared[0].duplicated_tokens, 90);
    // Nothing vacated `src/z.rs`, so nothing is claimed about where it
    // came from.
    assert_eq!(delta.appeared[0].derived_from, None);
}

#[test]
fn a_repeated_member_added_to_a_frozen_group_is_not_covered() {
    let baseline = Baseline::from_run(&origin(), &[group("aa11")], "2026-07-27T01:00:00Z");

    // A group fingerprint represents the distinct member content. A
    // third occurrence of the same content can therefore retain `aa11`,
    // but it is newly introduced duplication and must remain visible.
    let delta = only_partition(&baseline).delta(&[scanned(
        "aa11",
        84,
        &[
            ("src/a.rs", "parse"),
            ("src/b.rs", "parse"),
            ("src/c.rs", "parse"),
        ],
    )]);

    assert_eq!(delta.continuing, 1);
    assert!(delta.appeared.is_empty());
    assert_eq!(delta.expanded.len(), 1);
    assert_eq!(delta.expanded[0].group, "aa11");
    assert_eq!(delta.expanded[0].added_instances, 1);
    assert_eq!(delta.expanded[0].added_tokens, 42);
}

#[test]
fn a_group_standing_where_a_gone_entry_stood_is_named_as_its_successor() {
    // Both entries were frozen over the same two units, which is what
    // happens when one duplication sits inside another.
    let baseline = Baseline::from_run(
        &origin(),
        &[group("aa11"), group("bb22")],
        "2026-07-27T01:00:00Z",
    );

    // `bb22` is gone; a group nobody has seen before now stands in the
    // same two units. Reporting it as plain "new" would read as a
    // regression to whoever had just removed `bb22`.
    let delta = only_partition(&baseline).delta(&[
        scanned("aa11", 42, &[("src/a.rs", "parse"), ("src/b.rs", "parse")]),
        scanned("ff66", 30, &[("src/a.rs", "parse"), ("src/b.rs", "parse")]),
    ]);

    let derived = delta.appeared[0]
        .derived_from
        .as_ref()
        .expect("a predecessor at the same sites");
    assert_eq!(derived.group, "bb22");
    assert_eq!(derived.shared_sites, 2);
}

#[test]
fn an_entry_that_is_still_reported_is_not_offered_as_a_predecessor() {
    let baseline = Baseline::from_run(&origin(), &[group("aa11")], "2026-07-27T01:00:00Z");

    // `aa11` still stands, so a second group over the same units is
    // duplication that was added, not duplication that moved.
    let delta = only_partition(&baseline).delta(&[
        scanned("aa11", 42, &[("src/a.rs", "parse")]),
        scanned("ff66", 30, &[("src/a.rs", "parse")]),
    ]);

    assert_eq!(delta.appeared.len(), 1);
    assert_eq!(delta.appeared[0].derived_from, None);
}

#[test]
fn a_baseline_round_trips_through_a_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("nested/baseline.json");
    let baseline = Baseline::from_run(&origin(), &[group("aa11")], "2026-07-27T01:00:00Z");

    baseline.write(&path).unwrap();
    assert_eq!(Baseline::load(&path).unwrap(), baseline);

    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.ends_with('\n'), "a text file ends with a newline");
    assert!(text.contains("\"group\": \"aa11\""), "readable by hand");
}

#[test]
fn a_file_from_a_schema_this_build_does_not_read_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("baseline.json");
    let mut baseline = Baseline::from_run(&origin(), &[], "2026-07-27T01:00:00Z");
    baseline.schema_version = SCHEMA_VERSION + 1;
    baseline.write(&path).unwrap();

    let err = Baseline::load(&path).expect_err("an unreadable schema version");
    assert!(format!("{err:#}").contains("schema version"));
}

#[test]
fn a_baseline_says_when_it_describes_a_different_run() {
    let baseline = Baseline::from_run(&origin(), &[group("aa11")], "2026-07-27T01:00:00Z");
    let detectors = vec![("fp-schema".to_string(), "fp-schema-v1".to_string())];

    let fit = baseline
        .partition("abcdef0123456789")
        .expect("the expected partition")
        .compatibility(&detectors);
    assert_eq!(fit.mismatch, None);

    assert!(baseline.partition("999999999999").is_none());

    let bumped = vec![(
        "fp-schema".to_string(),
        "different-fingerprint-v1".to_string(),
    )];
    let other_detector = baseline
        .partition("abcdef0123456789")
        .expect("the expected partition")
        .compatibility(&bumped)
        .mismatch
        .expect("a moved fingerprint schema is a mismatch");
    assert!(other_detector.contains("different detector versions"));
    assert!(other_detector.contains("recreate the baseline"));
}
