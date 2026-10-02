use super::*;

/// Cross-build comparison is an explicit, separate result: a normal semantic
/// scan retains the partition-only schema and snapshot meaning, while the
/// opt-in comparison names every member's source build variant.
#[test]
fn explicit_cross_build_comparison_is_separate_and_origin_aware() {
    require_clang_helper();
    let dir = tempfile::tempdir().expect("temp dir");
    let root = codehelion_fixtures::copy_cpp("header-only", dir.path()).expect("plant fixture");

    let ordinary = scan(&root);
    assert!(
        ordinary.get("cross_variant_comparison").is_none(),
        "the default output is unchanged: {ordinary}"
    );
    let store = Store::open(&root.join(".codehelion/audit.db")).expect("open audit database");
    assert_eq!(
        store
            .cross_variant_comparison_count()
            .expect("count comparisons"),
        0,
        "ordinary scan runs are not comparisons"
    );

    let compared = comparison_json(&root);
    let comparison = &compared["cross_variant_comparison"];
    let origins = comparison["origin_variants"]
        .as_array()
        .expect("comparison origins");
    assert_eq!(
        origins.len(),
        2,
        "two compile commands are compared: {compared}"
    );
    assert_eq!(comparison["comparison_kind"], "exact-type-1-whole-units");
    let groups = comparison["groups"].as_array().expect("comparison groups");
    assert!(
        !groups.is_empty(),
        "the shared header has exact units: {compared}"
    );
    assert!(groups.iter().all(|group| {
        group["members"]
            .as_array()
            .expect("group members")
            .iter()
            .all(|member| member.get("origin_variant").is_some())
    }));
    let store = Store::open(&root.join(".codehelion/audit.db")).expect("reopen audit database");
    assert_eq!(
        store
            .cross_variant_comparison_count()
            .expect("count comparisons"),
        1,
        "one opt-in invocation writes one comparison outside scan runs"
    );

    let text = scan_comparing(&root, "text");
    assert!(
        text.status.success(),
        "{}",
        String::from_utf8_lossy(&text.stderr)
    );
    let text = String::from_utf8(text.stdout).expect("text report");
    assert!(text.contains("Cross-build-variant comparison"));
    assert!(text.contains("origin variants:"));

    let sarif = scan_comparing(&root, "sarif");
    assert!(
        sarif.status.success(),
        "{}",
        String::from_utf8_lossy(&sarif.stderr)
    );
    let sarif: Value = serde_json::from_slice(&sarif.stdout).expect("SARIF JSON");
    let comparison_run = sarif["runs"]
        .as_array()
        .expect("SARIF runs")
        .iter()
        .find(|run| run["automationDetails"]["id"] == "codehelion/cross-build-variants")
        .expect("cross comparison SARIF run");
    assert!(comparison_run["properties"]["crossVariantComparison"]["origin_variants"].is_array());
}

/// Asking for comparison does not fabricate a result when all C++ units came
/// from one build variant, but the report must say why it could not run.
#[test]
fn one_build_variant_reports_a_cross_comparison_that_did_not_run() {
    require_clang_helper();
    let dir = tempfile::tempdir().expect("temp dir");
    let root =
        codehelion_fixtures::copy_cpp("template-instantiation", dir.path()).expect("plant fixture");
    let output = scan_comparing(&root, "json");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("JSON report");
    assert!(
        report.get("cross_variant_comparison").is_none(),
        "one origin must not become a comparison: {report}"
    );
    assert_eq!(
        report["cross_variant_comparison_status"]["status"], "not_run",
        "the request must not disappear: {report}"
    );
    assert_eq!(
        report["cross_variant_comparison_status"]["origin_variants"]
            .as_array()
            .map(Vec::len),
        Some(1),
        "the available partition is retained: {report}"
    );
    let text = scan_comparing(&root, "text");
    assert!(
        text.status.success(),
        "{}",
        String::from_utf8_lossy(&text.stderr)
    );
    assert!(
        String::from_utf8(text.stdout)
            .expect("text report")
            .contains("Cross-build-variant comparison was not run")
    );
    let sarif = scan_comparing(&root, "sarif");
    assert!(
        sarif.status.success(),
        "{}",
        String::from_utf8_lossy(&sarif.stderr)
    );
    let sarif: Value = serde_json::from_slice(&sarif.stdout).expect("SARIF JSON");
    assert!(
        sarif["runs"]
            .as_array()
            .is_some_and(|runs| runs.iter().any(|run| {
                run["properties"]["crossVariantComparisonStatus"]["status"] == "not_run"
            }))
    );
    let store = Store::open(&root.join(".codehelion/audit.db")).expect("open audit database");
    assert_eq!(
        store
            .cross_variant_comparison_count()
            .expect("count comparisons"),
        0
    );
}

/// A database describes only the entries it contains. A neighboring C++
/// source it does not name gets its own no-build partition and explicit
/// coverage result instead of being omitted or borrowed into a real variant.
#[test]
fn a_cpp_source_missing_from_the_database_is_recorded_as_no_build_information() {
    require_clang_helper();
    let dir = tempfile::tempdir().expect("temp dir");
    let root = codehelion_fixtures::copy_cpp("header-only", dir.path()).expect("plant the fixture");
    std::fs::write(
        root.join("src/unlisted.cpp"),
        "int unlisted() { return 0; }\n",
    )
    .expect("add source absent from the database");

    let report = scan(&root);
    let partitions = reports(&report);
    assert_eq!(
        partitions.len(),
        3,
        "the unlisted source gets its own report: {report}"
    );
    let no_build = partitions
        .iter()
        .find(|partition| {
            partition["summary"]["compiler"]["not_asked_reasons"]["no_build_information"].as_u64()
                == Some(1)
        })
        .expect("an explicit no-build report");
    let run_id = no_build["run"]["run_id"].as_i64().expect("recorded run");
    let store = Store::open(&root.join(".codehelion/audit.db")).expect("open audit database");
    assert!(
        store
            .run_tree(run_id)
            .expect("read recorded files")
            .contains_key("src/unlisted.cpp"),
        "the source was recorded instead of silently omitted"
    );
}

/// An invocation that reuses some partitions and records the rest is one
/// invocation: the latest-invocation lookup names every partition the scan
/// reported, so a baseline frozen from it covers them all and the next
/// baseline-checked scan finds a partition for each of its own.
#[test]
fn a_partly_reused_invocation_is_read_back_whole() {
    require_clang_helper();
    let dir = tempfile::tempdir().expect("temp dir");
    let root = codehelion_fixtures::copy_cpp("header-only", dir.path()).expect("plant the fixture");
    let unlisted = root.join("src/unlisted.cpp");
    std::fs::write(&unlisted, "int unlisted() { return 0; }\n").expect("add unlisted source");
    let first = scan(&root);
    std::fs::write(&unlisted, "int unlisted() { return 1; }\n").expect("edit unlisted source");

    let second = scan(&root);
    let partitions = reports(&second);
    assert!(
        partitions
            .iter()
            .any(|partition| partition["run"]["reused"] == true),
        "an untouched partition is reused: {second}"
    );
    assert!(
        partitions
            .iter()
            .any(|partition| partition["run"]["reused"] != true),
        "the edited partition is recorded afresh: {second}"
    );
    let mut reported: Vec<i64> = partitions
        .iter()
        .map(|partition| partition["run"]["run_id"].as_i64().expect("recorded run"))
        .collect();
    reported.sort_unstable();
    assert_eq!(reported.len(), reports(&first).len());

    let store = Store::open(&root.join(".codehelion/audit.db")).expect("open audit database");
    let key = codehelion_store::path_key(
        &codehelion_core::paths::canonical(&root).expect("canonical root"),
    );
    let latest: Vec<i64> = store
        .latest_completed_invocation(&key)
        .expect("read the latest invocation")
        .iter()
        .map(|origin| origin.id)
        .collect();
    assert_eq!(latest, reported);
    drop(store);

    let created = cmd()
        .current_dir(&root)
        .args(["baseline", "create", ".", "--file", "baseline.json"])
        .output()
        .expect("create a baseline");
    assert!(created.status.success(), "{created:?}");
    let checked = cmd()
        .current_dir(&root)
        .args([
            "scan",
            ".",
            "--mode",
            "semantic",
            "--format",
            "json",
            "--baseline",
            "baseline.json",
        ])
        .output()
        .expect("scan against the baseline");
    assert!(
        checked.status.success(),
        "{}",
        String::from_utf8_lossy(&checked.stderr)
    );
}

/// A report with no `--run` replays the scan it names, which for a
/// partitioned scan is every partition it printed, in the same document shape.
#[test]
fn a_bare_report_replays_every_partition_the_scan_printed() {
    require_clang_helper();
    let dir = tempfile::tempdir().expect("temp dir");
    let root = codehelion_fixtures::copy_cpp("header-only", dir.path()).expect("plant the fixture");
    std::fs::write(
        root.join("src/unlisted.cpp"),
        "int unlisted() { return 0; }\n",
    )
    .expect("add source absent from the database");
    let scanned = scan(&root);

    let output = cmd()
        .current_dir(&root)
        .args(["report", "--format", "json"])
        .output()
        .expect("run report");
    assert!(output.status.success(), "{output:?}");
    let replayed: Value = serde_json::from_slice(&output.stdout).expect("report JSON");

    let run_ids = |value: &Value| -> Vec<Value> {
        reports(value)
            .iter()
            .map(|partition| partition["run"]["run_id"].clone())
            .collect()
    };
    assert!(replayed.get("partitions").is_some(), "{replayed}");
    assert_eq!(replayed["schema_version"], scanned["schema_version"]);
    assert_eq!(run_ids(&replayed), run_ids(&scanned));
    let group_counts = |value: &Value| -> Vec<usize> {
        reports(value)
            .iter()
            .map(|partition| partition["groups"].as_array().map_or(0, Vec::len))
            .collect()
    };
    assert_eq!(group_counts(&replayed), group_counts(&scanned));
}

/// A generated database may legitimately compile the exact same source twice.
/// The selector is the full command rather than the source path, so both
/// entries survive planning and each Clang request chooses its own `-D`.
#[test]
fn a_duplicate_source_command_selects_each_exact_build_entry() {
    require_clang_helper();
    let dir = tempfile::tempdir().expect("temp dir");
    let root = codehelion_fixtures::copy_cpp("header-only", dir.path()).expect("plant the fixture");
    let database = root.join("compile_commands.json");
    let mut commands: Vec<Value> = serde_json::from_slice(
        &std::fs::read(&database).expect("read rendered compilation database"),
    )
    .expect("compilation database JSON");
    let source = commands[0]["file"].clone();
    commands[1]["file"] = source.clone();
    let arguments = commands[1]["arguments"]
        .as_array_mut()
        .expect("arguments array");
    *arguments.last_mut().expect("source argument") = source;
    std::fs::write(
        &database,
        serde_json::to_vec_pretty(&commands).expect("write compilation database"),
    )
    .expect("replace compilation database");

    let report = scan(&root);
    let partitions = reports(&report);
    let configured: Vec<&Value> = partitions
        .iter()
        .copied()
        .filter(|partition| partition["summary"]["compiler"]["answered"].as_u64() == Some(2))
        .collect();
    assert_eq!(
        configured.len(),
        2,
        "both duplicate-source commands are independent: {report}"
    );
    let store = Store::open(&root.join(".codehelion/audit.db")).expect("open audit database");
    let totals = configured
        .iter()
        .map(|partition| {
            let run_id = partition["run"]["run_id"].as_i64().expect("recorded run");
            store
                .run_compiler_units(run_id)
                .expect("read compiler results")
                .iter()
                .find_map(|stored| match &stored.outcome {
                    CompilerOutcome::Analyzed(ir)
                        if names_the_file(&ir.unit.file, "include/accumulate.hpp") =>
                    {
                        ir.symbols.iter().find_map(|symbol| {
                            (symbol.name == "total")
                                .then_some(symbol.type_index)
                                .flatten()
                                .and_then(|index| usize::try_from(index).ok())
                                .and_then(|index| ir.types.get(index))
                                .map(|ty| ty.display.clone())
                        })
                    }
                    CompilerOutcome::Analyzed(_) | CompilerOutcome::Unavailable { .. } => None,
                })
                .expect("the selected command answered its header")
        })
        .collect::<Vec<_>>();
    assert_ne!(
        totals[0], totals[1],
        "the exact -D command changes the answer"
    );
}

/// A template use written in a header is reported by both translation units
/// that read it. The CLI keeps the common answer, including a valid type-table
/// index, instead of selecting one unit or dropping template data while it
/// backfills the header.
#[test]
fn template_instantiations_survive_header_agreement_and_storage() {
    require_clang_helper();
    let dir = tempfile::tempdir().expect("temp dir");
    let root =
        codehelion_fixtures::copy_cpp("template-instantiation", dir.path()).expect("plant fixture");

    let report = scan(&root);
    assert!(
        report.get("partitions").is_none(),
        "one build keeps the established report schema: {report}"
    );
    let run_id = report["run"]["run_id"].as_i64().expect("recorded run");
    let store = Store::open(&root.join(".codehelion/audit.db")).expect("open audit database");
    let units = store
        .run_compiler_units(run_id)
        .expect("read compiler results");
    let header = units
        .iter()
        .find_map(|stored| match &stored.outcome {
            CompilerOutcome::Analyzed(ir)
                if names_the_file(&ir.unit.file, "include/templates.hpp") =>
            {
                Some(ir)
            }
            CompilerOutcome::Analyzed(_) | CompilerOutcome::Unavailable { .. } => None,
        })
        .expect("the units agree on an answer for the header");
    let stamp = header
        .instantiations
        .iter()
        .find(|stamp| stamp.anchor.expansion.file == "include/templates.hpp")
        .expect("the agreed header template use was retained");
    assert!(stamp.instantiation_key.starts_with("clang-usr-v1:"));
    assert!(
        stamp
            .artifact_match_key
            .as_deref()
            .is_some_and(|key| key.starts_with("clang-display-v1:"))
    );
    assert_eq!(stamp.arguments.len(), 1);
    let argument = usize::try_from(stamp.arguments[0]).expect("type index fits");
    assert_eq!(
        header.types[argument].category,
        codehelion_helper::ir::TypeCategory::Integer
    );
}
