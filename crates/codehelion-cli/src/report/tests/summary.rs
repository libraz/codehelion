//! The summary section: run status, exclusions, guardrails, parse and
//! compiler coverage.

use super::*;

#[test]
fn text_exclusion_total_counts_each_cause_once() {
    let mut report = sample_report();
    report.summary.excluded = ExcludedCounts {
        generated: 1,
        by_glob: 2,
        skipped: 42,
        too_large: 3,
        oversized_metadata: 2,
        binary: 4,
        unreadable: 5,
        symlinks: 7,
        walk_errors: 8,
        timed_out: 9,
        language_excluded: 6,
        symlink_files: 3,
        symlink_directories: 4,
    };
    let mut rendered = Vec::new();
    report
        .render_text(
            TextOptions {
                verbosity: 1,
                ..TextOptions::default()
            },
            &mut rendered,
        )
        .expect("render report with exclusions");
    let text = String::from_utf8(rendered).expect("UTF-8 report");
    assert!(
        text.contains("7 symlinks, 8 walk errors, 9 timed out (47 total)"),
        "{text}"
    );
    // A metadata file the size ceiling excluded is named by its own cause. It
    // is not a skipped source, and folding it into that count would leave the
    // total larger than the causes that explain it.
    assert!(text.contains("2 build metadata too large"), "{text}");
}

/// A compilation database or manifest left unread describes a build nothing
/// else describes, so it has to reach the reader rather than disappearing into
/// the skipped total.
#[test]
fn a_metadata_file_over_the_size_ceiling_is_named_in_text_and_in_json() {
    let mut report = sample_report();
    report.summary.excluded.oversized_metadata = 5;
    report.summary.excluded.skipped = 5;

    let mut rendered = Vec::new();
    report
        .render_text(
            TextOptions {
                verbosity: 1,
                ..TextOptions::default()
            },
            &mut rendered,
        )
        .expect("render report with an oversized metadata file");
    let text = String::from_utf8(rendered).expect("UTF-8 report");
    assert!(text.contains("5 build metadata too large"), "{text}");

    let json: serde_json::Value =
        serde_json::from_str(&report.to_json().expect("serialize")).expect("valid JSON");
    assert_eq!(json["summary"]["excluded"]["oversized_metadata"], 5);
}

#[test]
fn text_names_the_run_required_for_replay() {
    let report = sample_report();
    let mut buffer = Vec::new();
    report
        .render_text(TextOptions::default(), &mut buffer)
        .unwrap();
    let text = String::from_utf8(buffer).unwrap();

    assert!(
        text.contains("run 1 (replay: codehelion report --run 1)"),
        "{text}"
    );
    // The run label is the last field of the counts line, and a field is
    // separated the way every other one on that line is.
    assert!(
        text.contains("tokens · run 1"),
        "the run label lost the spacing its separator carries: {text}"
    );

    let mut detailed = Vec::new();
    report
        .render_text(
            TextOptions {
                verbosity: 1,
                ..TextOptions::default()
            },
            &mut detailed,
        )
        .unwrap();
    let detailed = String::from_utf8(detailed).unwrap();
    assert!(
        detailed.contains("snapshot: .codehelion/audit.db"),
        "{detailed}"
    );
}

#[test]
fn text_run_status_names_reuse_and_the_exact_tree_delta() {
    let mut reused = sample_report();
    reused.run.reused = true;
    let mut rendered = Vec::new();
    reused
        .render_text(TextOptions::default(), &mut rendered)
        .unwrap();
    let rendered = String::from_utf8(rendered).unwrap();
    assert!(
        rendered.contains("run 1 (reused: tree unchanged; replay: codehelion report --run 1)"),
        "{rendered}"
    );

    let mut changed = sample_report();
    changed.summary.changes = Some(TreeChanges {
        since_run_id: 7,
        modified: 1,
        added: 1,
        removed: 1,
        unchanged: 4,
    });
    let mut rendered = Vec::new();
    changed
        .render_text(TextOptions::default(), &mut rendered)
        .unwrap();
    let rendered = String::from_utf8(rendered).unwrap();
    assert!(
        rendered.contains("run 1 (3 file(s) changed; replay: codehelion report --run 1)"),
        "{rendered}"
    );
    assert!(!rendered.contains("reused: tree unchanged"), "{rendered}");
}

/// A set of ceilings whose numbers are all different, so a rendering that
/// reads one where it meant another is visible rather than coincidentally
/// right.
fn sample_guardrails() -> Guardrails {
    Guardrails {
        profile: "untrusted".to_string(),
        max_file_bytes: 1,
        parse_timeout_ms: 2,
        helper_timeout_ms: 3,
        posting_cap: 4,
        pair_budget: 5,
        verification_budget: Some(6),
        max_alignment_cells: Some(7),
        near_miss_delta: Some(0.1),
        near_miss_cap: Some(8),
        sibling_candidate_budget: Some(9),
        sibling_per_group_cap: Some(10),
        sibling_total_cap: Some(11),
        signature_sibling_candidate_budget: Some(12),
        signature_sibling_per_group_cap: Some(13),
        signature_sibling_total_cap: Some(14),
        signature_sibling_max_units_per_signature: Some(16),
        max_component: Some(15),
    }
}

/// The parse budget is an amount of work, not an amount of time, and the views
/// that state it have to say so in the same terms. A reader who takes it for a
/// wall-clock deadline expects a busy machine to report fewer findings, which
/// is the one thing a deterministic budget exists to rule out.
#[test]
fn the_parse_budget_is_stated_as_work_rather_than_elapsed_time() {
    let mut report = sample_report();
    report.summary.guardrails = Some(sample_guardrails());

    let mut text = Vec::new();
    report
        .render_text(
            TextOptions {
                verbosity: 2,
                ..TextOptions::default()
            },
            &mut text,
        )
        .unwrap();
    let text = String::from_utf8(text).unwrap();
    assert!(
        text.contains(&format!(
            "parse work capped at min(file ceiling, 2 ms × {} bytes)",
            crate::scan::runtime::PARSE_BYTES_PER_MILLISECOND
        )),
        "{text}"
    );

    let schema: serde_json::Value = serde_json::from_str(JSON_SCHEMA).unwrap();
    let described = schema["$defs"]["summary"]["properties"]["guardrails"]["properties"]
        ["parse_timeout_ms"]["description"]
        .as_str()
        .expect("the shipped schema describes the field it publishes");
    assert!(
        described.contains(&format!(
            "{} input bytes",
            crate::scan::runtime::PARSE_BYTES_PER_MILLISECOND
        )),
        "{described}"
    );
    assert!(
        described.contains("Not a wall-clock deadline"),
        "a consumer reading only the schema would take the budget for a \
         deadline: {described}"
    );
}

#[test]
fn the_unparsed_share_counts_files_and_tokens_against_the_whole_scan() {
    let counts = UnparsedCounts::new([0, 250, 0, 750], 4000);
    assert_eq!(counts.files, 2, "only the files that lost something count");
    assert_eq!(counts.tokens, 1000);
    assert!((counts.share - 0.25).abs() < f64::EPSILON);
}

#[test]
fn a_scan_the_parser_followed_reports_a_share_of_nothing() {
    let clean = UnparsedCounts::new([0, 0], 4000);
    assert_eq!((clean.files, clean.tokens), (0, 0));
    assert!(clean.share.abs() < f64::EPSILON);
    // An empty scan divides by nothing rather than producing a NaN that
    // would serialize as `null` and read as "not measured".
    let empty = UnparsedCounts::new([], 0);
    assert!(empty.share.abs() < f64::EPSILON);
}

#[test]
fn a_lexing_mode_reports_no_parse_coverage_rather_than_a_clean_one() {
    // Fast mode has no parser, so `unparsed` is absent from its JSON. A
    // zero there would claim the parser followed everything.
    let value: serde_json::Value =
        serde_json::from_str(&sample_report().to_json().unwrap()).unwrap();
    assert!(value["summary"].get("unparsed").is_none());
}

#[test]
fn denied_execution_is_actionable_in_json_and_text() {
    let mut report = sample_report();
    report.summary.compiler = Some(CompilerCoverage {
        answered: 0,
        not_asked: 0,
        not_asked_reasons: BTreeMap::new(),
        unavailable: BTreeMap::from([("requires_execution".to_string(), 2)]),
        diagnostics: BTreeMap::from([("compiler library unavailable".to_string(), 2)]),
        execution_refusals: vec![ExecutionRefusal {
            execution: "build-script".to_string(),
            files: 2,
            cost: "types and items that only exist after a build script has generated them"
                .to_string(),
            permission_argument: "--allow-execution=build-script".to_string(),
            message: "skipped build-script: not permitted, so this run has no types and items that only exist after a build script has generated them. Pass --allow-execution=build-script to allow it."
                .to_string(),
        }],
        restarts: 0,
    });

    let json: serde_json::Value = serde_json::from_str(&report.to_json().unwrap()).unwrap();
    let refusal = &json["summary"]["compiler"]["execution_refusals"][0];
    assert_eq!(refusal["execution"], "build-script");
    assert_eq!(refusal["files"], 2);
    assert_eq!(
        json["summary"]["compiler"]["diagnostics"]["compiler library unavailable"],
        2
    );
    assert!(refusal["cost"].as_str().unwrap().contains("build script"));
    assert_eq!(
        refusal["permission_argument"],
        "--allow-execution=build-script"
    );

    let mut text = Vec::new();
    report
        .render_text(
            TextOptions {
                verbosity: 1,
                ..TextOptions::default()
            },
            &mut text,
        )
        .unwrap();
    let text = String::from_utf8(text).unwrap();
    assert!(text.contains("2 helper diagnostic: compiler library unavailable"));
    assert!(text.contains("build script has generated them"), "{text}");
    assert!(text.contains("--allow-execution=build-script"), "{text}");
}

/// A tree nothing describes how to compile and a language no installed helper
/// reads are both files a compiler was never put to, and they call for
/// different work. The count alone cannot be acted on, so each surface names
/// the reason beside it.
#[test]
fn a_file_no_compiler_was_asked_about_is_named_by_its_reason_in_json_and_text() {
    let mut report = sample_report();
    report.summary.compiler = Some(CompilerCoverage {
        answered: 0,
        not_asked: 3,
        not_asked_reasons: BTreeMap::from([
            ("no_build_information".to_string(), 2),
            ("not_supported".to_string(), 1),
        ]),
        unavailable: BTreeMap::new(),
        diagnostics: BTreeMap::new(),
        execution_refusals: Vec::new(),
        restarts: 0,
    });

    let json: serde_json::Value = serde_json::from_str(&report.to_json().unwrap()).unwrap();
    let coverage = &json["summary"]["compiler"];
    assert_eq!(coverage["not_asked"], 3);
    assert_eq!(coverage["not_asked_reasons"]["no_build_information"], 2);
    assert_eq!(coverage["not_asked_reasons"]["not_supported"], 1);

    let mut text = Vec::new();
    report
        .render_text(
            TextOptions {
                verbosity: 1,
                ..TextOptions::default()
            },
            &mut text,
        )
        .unwrap();
    let text = String::from_utf8(text).unwrap();
    assert!(
        text.contains("not asked: 2 no_build_information, 1 not_supported"),
        "{text}"
    );
}
