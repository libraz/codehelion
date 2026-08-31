use super::*;

/// Large enough to reach every language: the mix cycles by file index, so
/// a target that fits in a couple of files says nothing about it.
fn small_spec() -> CorpusSpec {
    CorpusSpec {
        target_lines: 8_000,
        seed: 42,
        clone_percent: 20,
    }
}

fn tree_digest(root: &Path) -> Vec<(String, u64, u32)> {
    let mut entries = Vec::new();
    for dir in std::fs::read_dir(root).unwrap() {
        let dir = dir.unwrap().path();
        for file in std::fs::read_dir(&dir).unwrap() {
            let file = file.unwrap().path();
            let text = std::fs::read_to_string(&file).unwrap();
            let sum = text.bytes().fold(0u32, |acc, b| {
                acc.wrapping_mul(31).wrapping_add(u32::from(b))
            });
            entries.push((
                file.file_name().unwrap().to_string_lossy().into_owned(),
                u64::try_from(text.len()).unwrap(),
                sum,
            ));
        }
    }
    entries.sort();
    entries
}

#[test]
fn corpus_generation_is_deterministic_and_reaches_the_target() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let stats_a = generate_corpus(&small_spec(), a.path()).unwrap();
    let stats_b = generate_corpus(&small_spec(), b.path()).unwrap();
    assert_eq!(stats_a, stats_b);
    assert!(stats_a.lines >= small_spec().target_lines);
    assert!(stats_a.files >= 4, "several files: {}", stats_a.files);
    assert_eq!(tree_digest(a.path()), tree_digest(b.path()));
}

#[test]
fn corpus_injects_clones_and_mixes_languages() {
    let dir = tempfile::tempdir().unwrap();
    let stats = generate_corpus(&small_spec(), dir.path()).unwrap();
    assert!(stats.cloned_functions > 0);
    assert!(stats.cloned_functions < stats.functions / 2);
    let digest = tree_digest(dir.path());
    for extension in [".rs", ".c", ".cc"] {
        assert!(
            digest.iter().any(|(name, ..)| Path::new(name).extension()
                == Some(std::ffi::OsStr::new(&extension[1..]))),
            "no {extension} file generated"
        );
    }
}

#[test]
fn different_seeds_produce_different_corpora() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let mut other = small_spec();
    other.seed = 43;
    generate_corpus(&small_spec(), a.path()).unwrap();
    generate_corpus(&other, b.path()).unwrap();
    assert_ne!(tree_digest(a.path()), tree_digest(b.path()));
}

#[test]
fn corpus_generation_refuses_a_previous_generation() {
    let dir = tempfile::tempdir().unwrap();
    let stale = dir.path().join("stale.rs");
    std::fs::write(&stale, "fn stale() {}\n").unwrap();

    let error = generate_corpus(&small_spec(), dir.path()).unwrap_err();
    assert!(error.to_string().contains("must be empty"), "{error:#}");
    assert!(stale.exists(), "rejection must not alter the old corpus");
    assert!(!dir.path().join("mod_0").exists());
}

#[test]
fn max_rss_parses_both_time_formats() {
    let bsd = "        3.21 real         2.90 user         0.20 sys\n         123456789  maximum resident set size\n";
    assert_eq!(parse_max_rss(bsd), Some(123_456_789));
    let gnu = "\tMaximum resident set size (kbytes): 204800\n";
    assert_eq!(parse_max_rss(gnu), Some(204_800 * 1024));
    assert_eq!(parse_max_rss("no such line"), None);
}

/// A report with two pairing stages, the second of which ran out.
fn truncated_report() -> serde_json::Value {
    serde_json::json!({
        "summary": {
            "files": {"total": 400},
            "lines": 100_000,
            "tokens": 900_000,
            "groups": {"total": 12},
            "search_truncated": true,
            "funnel": [
                {"stage": "seed pairs", "passed": 4_000, "dropped": []},
                {"stage": "fragment pairs", "passed": 40, "dropped": [
                    {"cause": "pair_budget", "count": 60},
                ]},
            ],
        }
    })
}

#[test]
fn the_summary_keeps_the_sizes_and_the_whole_pipeline_block() {
    let summary = summarize(&truncated_report());
    assert!(summary.contains("files: 400 analysed"));
    assert!(summary.contains("clone groups: 12"));
    assert!(summary.contains("seed pairs"));
    // A run that stopped early is fast for a reason the timing hides.
    assert!(summary.contains("pair_budget 60"));
}

/// Only the stages the ceiling stopped are counted. A pass that finished
/// its own search would otherwise dilute the share, and the number is
/// there to say how much of the search was abandoned.
#[test]
fn the_pipeline_counts_cover_the_stages_the_ceiling_stopped() {
    let counted = count_pipeline(&truncated_report());
    assert_eq!(counted.lines, 100_000);
    // The seed-pair stage passed 4000 and lost nothing to the allowance, so
    // it is outside both sides of the ratio.
    assert_eq!(counted.truncated_stage_examined_pairs, 40);
    assert_eq!(counted.skipped_pairs, 60);
    assert!(counted.search_truncated);
}

/// A run no allowance cut short has no cut-short stage, so the count is zero
/// and reads as one: the share is zero and nothing is reported about it.
#[test]
fn a_complete_run_has_no_cut_stage_to_count() {
    let report = serde_json::json!({
        "summary": {
            "files": {"total": 400},
            "lines": 100_000,
            "search_truncated": false,
            "funnel": [
                {"stage": "seed pairs", "passed": 4_000, "dropped": []},
                {"stage": "fragment pairs", "passed": 2_500, "dropped": [
                    {"cause": "min_tokens", "count": 1_500},
                ]},
            ],
        }
    });
    let counted = count_pipeline(&report);
    assert!(!counted.search_truncated);
    assert_eq!(
        (
            counted.truncated_stage_examined_pairs,
            counted.skipped_pairs
        ),
        (0, 0),
        "6500 pairs passed the funnel, but none of them at a stage an \
         allowance stopped"
    );

    let measured = ScanMeasurement {
        wall: Duration::from_secs(1),
        max_rss_bytes: Some(1),
        lines: counted.lines,
        truncated_stage_examined_pairs: counted.truncated_stage_examined_pairs,
        skipped_pairs: counted.skipped_pairs,
        search_truncated: counted.search_truncated,
        summary: String::new(),
    };
    assert!(measured.truncation_share().abs() < f64::EPSILON);
    assert!(
        Slo::for_lines(100_000).shortfalls(&measured).is_empty(),
        "a complete run is never charged for the zero"
    );
}

fn measurement(
    wall_secs: u64,
    rss: Option<u64>,
    lines: u64,
    skipped: u64,
    search_truncated: bool,
) -> ScanMeasurement {
    ScanMeasurement {
        wall: Duration::from_secs(wall_secs),
        max_rss_bytes: rss,
        lines,
        truncated_stage_examined_pairs: 1_000,
        skipped_pairs: skipped,
        search_truncated,
        summary: String::new(),
    }
}

#[test]
fn the_allowance_scales_from_the_two_named_sizes() {
    assert_eq!(Slo::for_lines(1_000).wall, Duration::from_secs(10));
    assert_eq!(Slo::for_lines(100_000).wall, Duration::from_secs(10));
    assert_eq!(Slo::for_lines(1_000_000).wall, Duration::from_secs(60));
    assert_eq!(Slo::for_lines(2_000_000).wall, Duration::from_secs(120));
    // Memory scales at every measured size; a small tree is not granted
    // the million-line allowance.
    assert_eq!(
        Slo::for_lines(10_000).max_rss_bytes,
        LARGE_TREE_RSS_BYTES / 100
    );
    assert_eq!(
        Slo::for_lines(100_000).max_rss_bytes,
        LARGE_TREE_RSS_BYTES / 10
    );
}

/// A scan that reached its time by abandoning most of its candidates has
/// changed the question rather than answered it faster, so the search
/// finishing is part of the target and not a footnote to it.
#[test]
fn a_fast_run_that_stopped_early_still_misses_the_target() {
    let slo = Slo::for_lines(1_000_000);
    let quick = measurement(5, Some(1_000_000_000), 1_000_000, 0, false);
    assert!(slo.shortfalls(&quick).is_empty());

    let truncated = measurement(5, Some(1_000_000_000), 1_000_000, 3_000, true);
    let missed = slo.shortfalls(&truncated);
    assert_eq!(missed.len(), 1, "{missed:?}");
    assert!(missed[0].contains("after 1000 of its 4000"), "{missed:?}");
    assert!(missed[0].contains("75%"));
}

/// Every shortfall is reported, not the first: a run that is both slow and
/// truncated has two problems, and fixing the one that surfaced would hide
/// the other behind a re-run.
#[test]
fn every_missed_target_is_named() {
    let slo = Slo::for_lines(1_000_000);
    let bad = measurement(300, Some(8_000_000_000), 1_000_000, 9_000, true);
    assert_eq!(slo.shortfalls(&bad).len(), 3);
}

#[test]
fn a_non_pair_ceiling_is_still_an_incomplete_search() {
    let report = serde_json::json!({
        "summary": {
            "lines": 100_000,
            "search_truncated": true,
            "funnel": [{
                "stage": "postings",
                "passed": 0,
                "dropped": [{"cause": "high_frequency_postings", "count": 200}]
            }],
        }
    });
    let counted = count_pipeline(&report);
    assert!(counted.search_truncated);
    assert_eq!(
        (
            counted.truncated_stage_examined_pairs,
            counted.skipped_pairs
        ),
        (0, 0)
    );

    let missed = Slo::for_lines(100_000).shortfalls(&measurement(
        1,
        Some(1),
        100_000,
        0,
        counted.search_truncated,
    ));
    assert_eq!(missed.len(), 1, "{missed:?}");
    assert!(missed[0].contains("resource ceiling"));
}

#[test]
fn a_warm_scan_keeps_the_history_a_cold_scan_throws_away() {
    let dir = tempfile::tempdir().unwrap();
    let db = prepare_database(dir.path(), ScanStart::Cold).unwrap();
    std::fs::write(&db, b"recorded").unwrap();

    assert_eq!(prepare_database(dir.path(), ScanStart::Warm).unwrap(), db);
    assert!(db.exists(), "a warm scan scans into what is already there");

    prepare_database(dir.path(), ScanStart::Cold).unwrap();
    assert!(
        !db.exists(),
        "a cold scan starts with no history of the tree"
    );
}

#[test]
fn the_summary_says_what_the_warm_scan_recognised() {
    let report = serde_json::json!({
        "summary": {
            "files": {"total": 3},
            "lines": 4_926,
            "tokens": 20_013,
            "groups": {"total": 2},
            "changes": {
                "since_run_id": 1, "unchanged": 3,
                "modified": 0, "added": 0, "removed": 0,
            },
            "funnel": [],
        }
    });
    let summary = summarize(&report);
    // Without this line a warm number is indistinguishable from a cold
    // one that happened to run fast.
    assert!(summary.contains("since run 1: 3 unchanged"));
}

#[test]
fn store_insert_measurement_writes_real_rows() {
    let dir = tempfile::tempdir().unwrap();
    let measurement = measure_store_insert(50, 20, 3, dir.path()).unwrap();
    assert_eq!(measurement.units, 50);
    assert_eq!(measurement.members, 60);
    let store = Store::open(&dir.path().join("store-bench.db")).unwrap();
    let run = store.latest_run().unwrap().expect("run recorded");
    assert_eq!(store.run_groups(run.id).unwrap().len(), 20);
}
