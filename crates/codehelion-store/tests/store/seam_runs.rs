//! Seam-run persistence against a real `SQLite` database: what a recorded run
//! reads back as, which run counts as the previous generation, and what a
//! seam mapping is allowed to read of a finding.

use super::*;

use codehelion_store::seam::{FindingLocation, SeamEntryRecord, SeamRunRecord};

fn entry(seam_id: &str, members: &[&str]) -> SeamEntryRecord {
    SeamEntryRecord {
        seam_id: seam_id.to_string(),
        members: members.iter().map(|member| (*member).to_string()).collect(),
        note: Some(format!("{seam_id} is implemented twice")),
        asymmetric_changes: 3,
        breaches: 1,
        last_breach: Some("cafebabe".to_string()),
        findings: 2,
    }
}

/// A run with every field distinguishable from every other, so a round-trip
/// that swaps two of them fails instead of passing.
fn sample_seam_run() -> SeamRunRecord {
    SeamRunRecord {
        root_path: "/repo".to_string(),
        settings_digest: "settings-a".to_string(),
        first_commit: Some("0000111".to_string()),
        last_commit: Some("2222333".to_string()),
        commit_count: 41,
        scan_run_id: None,
        recorded_at: "2026-07-24T00:00:00Z".to_string(),
        entries: vec![
            entry("wire-format", &["src/encode.rs", "src/decode.rs"]),
            entry("almanac", &["src/almanac/*.rs"]),
        ],
    }
}

#[test]
fn a_recorded_seam_run_reads_back_as_it_was_written() {
    let mut store = Store::open_in_memory().unwrap();
    let run = sample_seam_run();

    let id = store.record_seam_run(&run).unwrap();
    let stored = store.latest_seam_run("/repo").unwrap().expect("a seam run");

    assert_eq!(stored.id, id);
    assert_eq!(stored.run, run);
    // The ledger's order, not the alphabetical one a sorted read would give.
    assert_eq!(
        stored
            .run
            .entries
            .iter()
            .map(|entry| entry.seam_id.as_str())
            .collect::<Vec<_>>(),
        ["wire-format", "almanac"]
    );
}

#[test]
fn the_newest_run_is_the_latest_and_the_one_before_it_is_its_predecessor() {
    let mut store = Store::open_in_memory().unwrap();
    let older = sample_seam_run();
    let mut newer = sample_seam_run();
    newer.recorded_at = "2026-07-25T00:00:00Z".to_string();
    newer.commit_count = 44;

    let older_id = store.record_seam_run(&older).unwrap();
    let newer_id = store.record_seam_run(&newer).unwrap();

    let latest = store.latest_seam_run("/repo").unwrap().expect("a seam run");
    assert_eq!(latest.id, newer_id);
    assert_eq!(latest.run.commit_count, 44);

    let previous = store
        .preceding_seam_run("/repo", latest.id, "settings-a")
        .unwrap()
        .expect("a previous generation");
    assert_eq!(previous.id, older_id);
    assert_eq!(previous.run, older);
}

#[test]
fn a_run_under_other_settings_is_not_a_previous_generation() {
    let mut store = Store::open_in_memory().unwrap();
    let mut older = sample_seam_run();
    older.settings_digest = "settings-b".to_string();
    let newer = sample_seam_run();

    store.record_seam_run(&older).unwrap();
    let newer_id = store.record_seam_run(&newer).unwrap();

    assert_eq!(
        store
            .preceding_seam_run("/repo", newer_id, "settings-a")
            .unwrap(),
        None,
        "a run computed under other settings answered as an earlier generation"
    );
    // The same run is the predecessor of a comparison taken under its own
    // settings, so the digest is what excluded it and not its recency.
    assert!(
        store
            .preceding_seam_run("/repo", newer_id, "settings-b")
            .unwrap()
            .is_some()
    );
}

#[test]
fn a_predecessor_is_looked_for_under_one_root_only() {
    let mut store = Store::open_in_memory().unwrap();
    let mut other_root = sample_seam_run();
    other_root.root_path = "/other".to_string();
    let here = sample_seam_run();

    store.record_seam_run(&other_root).unwrap();
    let here_id = store.record_seam_run(&here).unwrap();

    assert_eq!(
        store
            .preceding_seam_run("/repo", here_id, "settings-a")
            .unwrap(),
        None,
        "a run recorded for another root answered as this root's earlier generation"
    );
}

#[test]
fn an_absent_note_and_an_absent_breach_read_back_as_absent() {
    let mut store = Store::open_in_memory().unwrap();
    let mut run = sample_seam_run();
    run.first_commit = None;
    run.last_commit = None;
    run.entries = vec![SeamEntryRecord {
        seam_id: "quiet".to_string(),
        members: vec!["src/one.rs".to_string(), "src/two.rs".to_string()],
        note: None,
        asymmetric_changes: 0,
        breaches: 0,
        last_breach: None,
        findings: 0,
    }];

    store.record_seam_run(&run).unwrap();
    let stored = store.latest_seam_run("/repo").unwrap().expect("a seam run");

    assert_eq!(stored.run, run);
    assert_eq!(stored.run.entries[0].note, None);
    assert_eq!(stored.run.entries[0].last_breach, None);
}

#[test]
fn losing_the_mapped_scan_run_keeps_the_seam_run_it_measured() {
    let variant = BuildVariant::fast(LanguageSelection::default(), Language::C);
    let detectors = detector_versions();
    let mut store = Store::open_in_memory().unwrap();
    let scan_run_id = store
        .record_snapshot_part(&sample_snapshot(&variant, &detectors))
        .unwrap();
    let mut run = sample_seam_run();
    run.scan_run_id = Some(scan_run_id);
    store.record_seam_run(&run).unwrap();

    store.discard_run(scan_run_id).unwrap();

    let stored = store.latest_seam_run("/repo").unwrap().expect("a seam run");
    assert_eq!(
        stored.run.scan_run_id, None,
        "the removed scan run left a dangling reference"
    );
    // The seam figures are read from the history, so they outlive the scan run
    // whose findings they happened to be mapped against.
    assert_eq!(stored.run.commit_count, 41);
    assert_eq!(stored.run.entries.len(), 2);
}

#[test]
fn finding_locations_are_one_run_s_own_members_in_a_fixed_order() {
    let variant = BuildVariant::fast(LanguageSelection::default(), Language::C);
    let detectors = detector_versions();
    let mut store = Store::open_in_memory().unwrap();
    let first = store
        .record_snapshot(&sample_snapshot(&variant, &detectors))
        .unwrap();

    let mut other = sample_snapshot(&variant, &detectors);
    other.units[0].file_path = "src/elsewhere.rs".to_string();
    other.units[1].file_path = "src/elsewhere_too.rs".to_string();
    other.groups[0].members[0].file_path = "src/elsewhere.rs".to_string();
    other.groups[0].members[1].file_path = "src/elsewhere_too.rs".to_string();
    other.files[0].relative_path = "src/elsewhere.rs".to_string();
    other.files[1].relative_path = "src/elsewhere_too.rs".to_string();
    let second = store.record_snapshot(&other).unwrap();

    assert_eq!(
        store.run_finding_locations(first).unwrap(),
        vec![
            FindingLocation {
                file_path: "src/a.rs".to_string(),
                start_line: 10,
            },
            FindingLocation {
                file_path: "src/b.rs".to_string(),
                start_line: 10,
            },
        ]
    );
    assert_eq!(
        store
            .run_finding_locations(second)
            .unwrap()
            .iter()
            .map(|location| location.file_path.as_str())
            .collect::<Vec<_>>(),
        ["src/elsewhere.rs", "src/elsewhere_too.rs"],
        "a run answered with another run's findings"
    );
}

#[test]
fn an_empty_ledger_records_a_run_with_no_entries() {
    let mut store = Store::open_in_memory().unwrap();
    let mut run = sample_seam_run();
    run.entries = Vec::new();

    let id = store.record_seam_run(&run).unwrap();
    let stored = store.latest_seam_run("/repo").unwrap().expect("a seam run");

    assert_eq!(stored.id, id);
    assert_eq!(stored.run, run);
    assert!(stored.run.entries.is_empty());
}

/// A range with no commits in it is a measurement, not a failure: a repository
/// can be read before anything was committed to it, and the run that says so
/// is what a later comparison needs as its earlier generation.
#[test]
fn a_range_with_no_commits_is_a_recordable_seam_run() {
    let mut store = Store::open_in_memory().unwrap();
    let mut run = sample_seam_run();
    run.commit_count = 0;
    run.first_commit = None;
    run.last_commit = None;

    store.record_seam_run(&run).unwrap();
    let stored = store.latest_seam_run("/repo").unwrap().expect("a seam run");

    assert_eq!(stored.run.commit_count, 0);
    assert_eq!(stored.run.entries.len(), 2);
}

#[test]
fn a_seam_without_a_name_or_without_paths_is_refused_whole() {
    let mut store = Store::open_in_memory().unwrap();
    for broken in [
        SeamEntryRecord {
            seam_id: String::new(),
            ..entry("named", &["src/one.rs"])
        },
        SeamEntryRecord {
            members: Vec::new(),
            ..entry("empty", &["src/one.rs"])
        },
        SeamEntryRecord {
            members: vec!["src/one.rs\nsrc/two.rs".to_string()],
            ..entry("smuggled", &["src/one.rs"])
        },
    ] {
        let mut run = sample_seam_run();
        run.entries.push(broken);
        let error = store.record_seam_run(&run).unwrap_err();

        assert!(
            matches!(error, StoreError::InvalidSeamEntry { .. }),
            "{error:?}"
        );
        assert_eq!(
            store.latest_seam_run("/repo").unwrap(),
            None,
            "a rejected ledger left the run it belonged to behind"
        );
    }
}

/// A seam run is recorded against a file-backed database exactly as against an
/// in-memory one, so the read path does not depend on the connection it was
/// opened through.
#[test]
fn a_seam_run_survives_reopening_a_file_backed_database() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("audit.db");
    let run = sample_seam_run();
    {
        let mut store = Store::open(&path).unwrap();
        store.record_seam_run(&run).unwrap();
    }

    let reopened = Store::open_existing(&path).unwrap();
    let stored = reopened
        .latest_seam_run("/repo")
        .unwrap()
        .expect("a seam run");

    assert_eq!(stored.run, run);
}
