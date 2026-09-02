use super::output::*;
use super::runtime::*;
use super::*;
use crate::cli::SortAxis;
use boon::{Compiler, Schemas};

fn assert_valid_partitioned_schema(value: &Value) {
    let mut schemas = Schemas::new();
    let mut compiler = Compiler::new();
    for (uri, source) in [
        (
            "https://github.com/libraz/codehelion/blob/main/crates/codehelion-cli/schema/scan-report-v2.schema.json",
            report::JSON_SCHEMA,
        ),
        (
            PARTITIONED_REPORT_SCHEMA_URI,
            include_str!("../../schema/partitioned-scan-report-v2.schema.json"),
        ),
    ] {
        compiler
            .add_resource(
                uri,
                serde_json::from_str(source).expect("valid shipped schema"),
            )
            .expect("schema resource");
    }
    let index = compiler
        .compile(PARTITIONED_REPORT_SCHEMA_URI, &mut schemas)
        .expect("compile partitioned report schema");
    schemas.validate(value, index).expect("validate envelope");
}

#[test]
fn cross_language_comparison_stays_in_its_own_report_domain() {
    let comparison = report::CrossLanguageComparison {
        policy_version: "cross-language-semantic-v1".to_string(),
        comparison_id: "aabb".to_string(),
        comparison_kind: "restricted-semantic-rust-cpp-pipelines".to_string(),
        origin_variants: vec!["cpp".to_string(), "rust".to_string()],
        funnel: vec![
            report::FunnelStage::new("cross-language candidate buckets", 1)
                .dropping(report::FunnelCause::BucketMemberCap, 1),
        ],
        search_truncated: true,
        groups: Vec::new(),
    };
    let json: Value = serde_json::from_str(
        &partitioned_json(&[], None, None, Some(&comparison), None).expect("JSON report"),
    )
    .expect("valid JSON");
    assert_eq!(json["schema_version"], PARTITIONED_REPORT_SCHEMA_VERSION);
    assert_eq!(json["$schema"], PARTITIONED_REPORT_SCHEMA_URI);
    assert_valid_partitioned_schema(&json);
    assert!(json.get("cross_variant_comparison").is_none());
    assert_eq!(
        json["cross_language_comparison"]["comparison_kind"],
        "restricted-semantic-rust-cpp-pipelines"
    );
    assert_eq!(json["cross_language_comparison"]["search_truncated"], true);

    let sarif: Value = serde_json::from_str(
        &partitioned_sarif(&[], None, None, Some(&comparison), None).expect("SARIF report"),
    )
    .expect("valid SARIF JSON");
    assert_eq!(
        sarif["runs"][0]["automationDetails"]["id"],
        "codehelion/cross-language"
    );

    let text = partitioned_text(&scan_args(false), &[], None, None, Some(&comparison), None)
        .expect("text report");
    assert!(text.contains("candidate search was truncated"));
}

#[test]
fn comparison_sarif_runs_share_escaped_source_locations_and_schema() {
    let comparison = report::CrossVariantComparison {
        policy_version: "cross-variant-v1".to_string(),
        comparison_id: "aabb".to_string(),
        comparison_kind: "exact-type-1-whole-units".to_string(),
        origin_variants: vec!["one".to_string(), "two".to_string()],
        groups: vec![report::CrossVariantGroup {
            id: "ccdd".to_string(),
            clone_type: "type-1".to_string(),
            members: vec![report::CrossVariantMember {
                origin_variant: "one".to_string(),
                language: "rust".to_string(),
                file: "src/a b.rs".to_string(),
                start_line: 1,
                end_line: 4,
                name: None,
                token_count: 20,
            }],
        }],
    };
    let run = cross_variant_sarif_run(&comparison, "/work/a root");
    assert_eq!(
        run["originalUriBaseIds"][report::sarif::SRCROOT]["uri"],
        "file:///work/a%20root/"
    );
    let location = &run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"];
    assert_eq!(location["uri"], "src/a%20b.rs");
    assert_eq!(location["uriBaseId"], report::sarif::SRCROOT);

    let log: Value = serde_json::from_str(
        &partitioned_sarif(&[], Some(&comparison), None, None, None).expect("SARIF report"),
    )
    .expect("valid SARIF JSON");
    assert_eq!(log["$schema"], report::sarif::SARIF_SCHEMA_URI);
}

#[test]
fn requested_cross_variant_comparison_that_cannot_run_is_explicit_in_every_format() {
    let status = report::CrossVariantComparisonNotRun {
        status: "not_run".to_string(),
        comparison_kind: "exact-type-1-whole-units".to_string(),
        reason: "fewer than two build-variant partitions were available".to_string(),
        origin_variants: vec!["aabb".to_string()],
    };
    let json: Value = serde_json::from_str(
        &partitioned_json(&[], None, Some(&status), None, None).expect("JSON report"),
    )
    .expect("valid JSON");
    assert_valid_partitioned_schema(&json);
    assert_eq!(json["cross_variant_comparison_status"]["status"], "not_run");
    assert!(json.get("cross_variant_comparison").is_none());

    let text = partitioned_text(&scan_args(false), &[], None, Some(&status), None, None)
        .expect("text report");
    assert!(text.contains("Cross-build-variant comparison was not run"));
    assert!(text.contains("fewer than two build-variant partitions"));

    let sarif: Value = serde_json::from_str(
        &partitioned_sarif(&[], None, Some(&status), None, None).expect("SARIF report"),
    )
    .expect("valid SARIF JSON");
    assert_eq!(
        sarif["runs"][0]["properties"]["crossVariantComparisonStatus"]["status"],
        "not_run"
    );
}

#[test]
fn requested_cross_language_comparison_that_cannot_run_is_explicit_in_every_format() {
    let status = report::CrossLanguageComparisonNotRun {
        status: "not_run".to_string(),
        comparison_kind: "registered-rust-cpp-semantic".to_string(),
        reason: "no eligible C++ semantic windows were available".to_string(),
        origin_variants: vec!["rust".to_string()],
    };
    let json: Value = serde_json::from_str(
        &partitioned_json(&[], None, None, None, Some(&status)).expect("JSON report"),
    )
    .expect("valid JSON");
    assert_valid_partitioned_schema(&json);
    assert_eq!(
        json["cross_language_comparison_status"]["status"],
        "not_run"
    );
    assert!(json.get("cross_language_comparison").is_none());

    let text = partitioned_text(&scan_args(false), &[], None, None, None, Some(&status))
        .expect("text report");
    assert!(text.contains("Cross-language comparison was not run"));
    assert!(text.contains("no eligible C++ semantic windows"));

    let sarif: Value = serde_json::from_str(
        &partitioned_sarif(&[], None, None, None, Some(&status)).expect("SARIF report"),
    )
    .expect("valid SARIF JSON");
    assert_eq!(
        sarif["runs"][0]["properties"]["crossLanguageComparisonStatus"]["status"],
        "not_run"
    );
}

#[test]
fn partitioned_machine_reports_reject_text_only_flags() {
    for flag in ["--show-suppressed", "--show-siblings", "--show-near-misses"] {
        for format in [Format::Json, Format::Sarif] {
            let mut args = scan_args(false);
            args.format = format;
            match flag {
                "--show-suppressed" => args.show_suppressed = true,
                "--show-siblings" => args.show_siblings = true,
                "--show-near-misses" => args.show_near_misses = true,
                _ => unreachable!("the fixture uses only known text-only flags"),
            }
            let error =
                write_partitioned_reports(&args, &mut Vec::new(), &[], None, None, None, None)
                    .expect_err("machine reports reject text-only flags");
            assert!(format!("{error:#}").contains(flag));
        }
    }
}

#[test]
fn partitioned_reports_refuse_to_overwrite_every_format_without_force() {
    let status = report::CrossVariantComparisonNotRun {
        status: "not_run".to_string(),
        comparison_kind: "exact-type-1-whole-units".to_string(),
        reason: "fixture has one partition".to_string(),
        origin_variants: vec!["aabb".to_string()],
    };
    let directory = tempfile::tempdir().expect("temporary output directory");

    for (format, extension) in [
        (Format::Text, "txt"),
        (Format::Json, "json"),
        (Format::Sarif, "sarif"),
    ] {
        let path = directory.path().join(format!("report.{extension}"));
        std::fs::write(&path, "preserve this report").expect("write existing output");
        let mut args = scan_args(false);
        args.format = format;
        args.output = Some(path.clone());
        let mut out = Vec::new();

        let error =
            write_partitioned_reports(&args, &mut out, &[], None, Some(&status), None, None)
                .expect_err("partitioned output must not overwrite without --force");
        assert!(error.to_string().contains("refusing to overwrite"));
        assert_eq!(
            std::fs::read_to_string(path).expect("read existing output"),
            "preserve this report"
        );
    }
}

#[test]
fn partition_heading_carries_the_stable_build_variant_identity() {
    let heading = partition_heading(&report::BuildVariantInfo {
        mode: "semantic".to_string(),
        languages: vec!["c".to_string(), "cpp".to_string()],
        headers: Some("cpp".to_string()),
        normalization_version: 1,
        fingerprint: "aabb".to_string(),
        settings: BTreeMap::new(),
    });
    assert_eq!(
        heading,
        "Build variant aabb (mode: semantic; languages: c, cpp)"
    );
}

fn scan_args(untrusted: bool) -> ScanArgs {
    scan_args_for(Mode::Fast, untrusted)
}

fn scan_args_for(mode: Mode, untrusted: bool) -> ScanArgs {
    ScanArgs {
        helpers: Vec::new(),
        sort: SortAxis::default(),
        min_identifier_jaccard: None,
        path: PathBuf::from("."),
        mode,
        format: Format::Text,
        output: None,
        force: false,
        config: None,
        no_ignore: false,
        follow_links: false,
        compile_commands: None,
        jobs: None,
        db: None,
        baseline: None,
        baseline_mode: BaselineMode::Suppress,
        allow_execution: None,
        compare_build_variants: false,
        compare_languages: false,
        show_suppressed: false,
        show_siblings: false,
        siblings_by_signature: false,
        show_near_misses: false,
        include_trivial: false,
        include_vendored: false,
        view: ViewArgs::default(),
        no_reuse: false,
        fail_on_findings: false,
        untrusted,
    }
}

#[test]
fn a_scan_that_was_not_told_to_distrust_the_tree_keeps_its_settings() {
    let before = Config::default();
    let (after, guardrails) = guarded(Config::default(), &scan_args(false));
    assert_eq!(after.limits, before.limits);
    assert!(guardrails.is_none());
}

/// The ceilings a repository nobody vouches for is read under, and the
/// report line that says so — a scan that read less has to be
/// distinguishable from a tree that holds less.
#[test]
fn distrusting_the_tree_lowers_every_ceiling_and_says_which() {
    let profile = codehelion_core::execution::Limits::untrusted();
    let lax = Config {
        limits: config::Limits {
            max_file_bytes: u64::MAX,
            parse_timeout_ms: u64::MAX,
            helper_timeout_ms: u64::MAX,
            posting_cap: Some(usize::MAX),
            pair_budget: Some(usize::MAX),
            near_miss_delta: Some(codehelion_core::near_match::DEFAULT_NEAR_MISS_DELTA),
            near_miss_cap: Some(usize::MAX),
            sibling_candidate_budget: Some(usize::MAX),
            sibling_per_group_cap: Some(usize::MAX),
            sibling_total_cap: Some(usize::MAX),
            signature_sibling_candidate_budget: Some(usize::MAX),
            signature_sibling_per_group_cap: Some(usize::MAX),
            signature_sibling_total_cap: Some(usize::MAX),
            signature_sibling_max_units_per_signature: Some(usize::MAX),
            verification_budget: Some(usize::MAX),
            max_alignment_cells: Some(usize::MAX),
            max_component: usize::MAX,
        },
        ..Config::default()
    };
    let (tightened, guardrails) = guarded(lax, &scan_args_for(Mode::Structural, true));
    let reported = guardrails.expect("a lowered ceiling is reported");
    assert_eq!(reported.profile, "untrusted");
    assert_eq!(tightened.limits.max_file_bytes, profile.max_file_bytes);
    assert_eq!(
        tightened.limits.parse_timeout_ms,
        u64::try_from(profile.parse_timeout.as_millis()).unwrap()
    );
    assert_eq!(
        tightened.limits.helper_timeout_ms,
        u64::try_from(profile.helper_timeout.as_millis()).unwrap()
    );
    assert_eq!(tightened.limits.posting_cap, Some(profile.posting_cap));
    assert_eq!(tightened.limits.pair_budget, Some(profile.max_candidates));
    assert_eq!(
        tightened.limits.verification_budget,
        Some(profile.verification_budget)
    );
    assert_eq!(
        tightened.limits.max_alignment_cells,
        Some(profile.max_alignment_cells)
    );
    assert_eq!(tightened.limits.max_component, profile.max_component);
    // The rarity limit is a detection knob elsewhere, but a tree nobody
    // vouches for does not get to widen the signatures its own layout made
    // common, so distrust brings it back to the channel default.
    assert_eq!(
        tightened.limits.signature_sibling_max_units_per_signature,
        Some(
            codehelion_core::structural::SignatureSiblingConfig::default().max_units_per_signature
        )
    );

    // `Limits` is serialized with every ceiling as a named key. Under a mode
    // whose stages take all of them, the guardrail object must be precisely
    // that effective limit set plus its profile name, so a new `Limits` field
    // cannot quietly avoid either clamping or report exposure.
    let expected = serde_json::to_value(&tightened.limits)
        .expect("limits serialize as an object")
        .as_object()
        .expect("limits serialize as an object")
        .iter()
        .map(|(key, value)| (key.replace('-', "_"), value.clone()))
        .collect();
    let mut actual = serde_json::to_value(reported).unwrap();
    actual
        .as_object_mut()
        .expect("guardrails serialize as an object")
        .remove("profile");
    assert_eq!(actual, Value::Object(expected));
}

/// Asking for less trust must not hand back more room. A configuration
/// already stricter than the profile is the stricter of the two, or the
/// flag would be a way to loosen a deliberately tight setting.
#[test]
fn a_setting_already_stricter_than_the_profile_survives_it() {
    let mut cfg = Config::default();
    cfg.limits.max_file_bytes = 1024;
    cfg.limits.parse_timeout_ms = 1;
    cfg.limits.helper_timeout_ms = 1;
    cfg.limits.posting_cap = Some(1);
    cfg.limits.pair_budget = Some(10);
    cfg.limits.max_component = 1;
    let (tightened, _) = guarded(cfg, &scan_args(true));
    assert_eq!(tightened.limits.max_file_bytes, 1024);
    assert_eq!(tightened.limits.parse_timeout_ms, 1);
    assert_eq!(tightened.limits.helper_timeout_ms, 1);
    assert_eq!(tightened.limits.posting_cap, Some(1));
    assert_eq!(tightened.limits.pair_budget, Some(10));
    assert_eq!(tightened.limits.max_component, 1);
}

/// A distrusting scan keeps the stricter ceilings in its effective
/// configuration, so it never reads more of the tree than requested.
#[test]
fn distrust_changes_the_effective_configuration() {
    let plain = Config::default().to_toml().unwrap();
    let (tightened, _) = guarded(Config::default(), &scan_args(true));
    assert_ne!(tightened.to_toml().unwrap(), plain);
}

#[test]
fn jobs_resolution_prefers_flag_then_config() {
    assert_eq!(effective_jobs(Some(3), Some(8)).unwrap(), 3);
    assert_eq!(effective_jobs(None, Some(8)).unwrap(), 8);
    assert!(effective_jobs(None, None).unwrap() >= 1);
    assert!(effective_jobs(Some(0), None).is_err());
    let maximum = maximum_jobs();
    assert_eq!(effective_jobs(Some(usize::MAX), None).unwrap(), maximum);
    assert_eq!(effective_jobs(None, Some(usize::MAX)).unwrap(), maximum);
}

#[test]
fn source_mapping_rejects_zero_workers_before_chunking() {
    let sources = Vec::<SourceUnit>::new();
    let error = map_sources(&sources, 0, |_| FileOutcome::<()>::Unreadable).unwrap_err();
    assert!(error.to_string().contains("jobs must be at least 1"));
}

#[test]
fn source_mapping_keeps_discovery_order_after_workers_claim_work_dynamically() {
    let sources = [
        "src/first.rs",
        "src/missing.rs",
        "src/third.rs",
        "src/slow.rs",
    ]
    .iter()
    .map(|path| SourceUnit {
        relative_path: PathBuf::from(path),
        absolute_path: PathBuf::from(path),
        language: Language::Rust,
        is_header: false,
        content_hash: ContentHash::of(b""),
        source_bytes: Vec::new().into(),
        byte_len: 0,
        package: None,
        crate_name: None,
        target_kind: discovery::TargetKind::Library,
    })
    .collect::<Vec<_>>();

    let (analysed, unreadable, timed_out) =
        map_sources(&sources, 3, |source| match source.relative_path.to_str() {
            Some("src/missing.rs") | None => FileOutcome::Unreadable,
            Some("src/slow.rs") => FileOutcome::TimedOut,
            Some(path) => FileOutcome::Done(Box::new(path.to_string())),
        })
        .unwrap();

    assert_eq!(analysed, ["src/first.rs", "src/third.rs"]);
    assert_eq!(unreadable, 1);
    assert_eq!(timed_out, 1);
}

#[test]
fn parse_work_budget_is_a_fixed_function_of_input_bytes_and_the_file_ceiling() {
    let one_millisecond = std::time::Duration::from_millis(1);
    assert_eq!(parse_work_byte_limit(1024, one_millisecond), 256);
    assert_eq!(parse_work_byte_limit(128, one_millisecond), 128);
    assert_eq!(parse_work_byte_limit(1024, std::time::Duration::ZERO), 0);
}

#[test]
fn engine_config_applies_configured_ceilings() {
    let cfg = Config {
        limits: config::Limits {
            posting_cap: Some(5),
            pair_budget: Some(7),
            ..config::Limits::default()
        },
        ..Config::default()
    };
    let engine = engine_config(&cfg).unwrap();
    assert_eq!(engine.posting_cap, 5);
    assert_eq!(engine.pair_budget, 7);
    // Detection knobs stay at their defaults.
    assert_eq!(engine.min_clone_tokens, 20);
    assert!((engine.entropy_ratio_floor - 0.60).abs() < f64::EPSILON);
}

/// An unset ceiling leaves the mode at the default measured for it, rather
/// than at a number carried over from the configuration type.
#[test]
fn an_unset_ceiling_leaves_the_engine_at_its_own_default() {
    let engine = engine_config(&Config::default()).unwrap();
    let defaults = EngineConfig::default();
    assert_eq!(engine.posting_cap, defaults.posting_cap);
    assert_eq!(engine.pair_budget, defaults.pair_budget);
}

#[test]
fn glob_filter_applies_include_then_exclude() {
    let cfg = Config {
        include: vec!["src/**".to_string()],
        exclude: vec!["src/gen/**".to_string()],
        ..Config::default()
    };
    let sources = ["src/a.rs", "src/gen/b.rs", "vendor/c.rs"]
        .iter()
        .map(|path| SourceUnit {
            relative_path: PathBuf::from(path),
            absolute_path: PathBuf::from(path),
            language: Language::Rust,
            is_header: false,
            content_hash: ContentHash::of(b""),
            source_bytes: Vec::new().into(),
            byte_len: 0,
            package: None,
            crate_name: None,
            target_kind: discovery::TargetKind::Library,
        })
        .collect();
    let (kept, excluded) = filter_globs(&cfg, sources).unwrap();
    assert_eq!(kept.len(), 1);
    assert_eq!(kept[0].relative_path, PathBuf::from("src/a.rs"));
    assert_eq!(excluded, 2);
}

#[test]
fn malformed_globs_are_an_error() {
    let cfg = Config {
        include: vec!["src/[".to_string()],
        ..Config::default()
    };
    assert!(filter_globs(&cfg, Vec::new()).is_err());
}
