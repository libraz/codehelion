//! A semantic scan of a C++ tree, from the command line to the compiler and
//! back.
//!
//! The unit tests either side of this fix one half each: that the run puts each
//! file to the helper that reads its language, and that the helper answers
//! about a translation unit it is given. Neither says the two halves agree
//! about how a file is named, which is the thing that goes wrong quietly — a
//! mismatch there produces a scan that succeeds, reports itself as semantic and
//! answered about nothing.
//!
//! Whether either helper is installed is a property of the machine, so these
//! read what `doctor` says and leave rather than fail when the answer is no.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use assert_cmd::Command;
use codehelion_helper::ir::CallTarget;
use codehelion_store::Store;
use codehelion_store::compiler::CompilerOutcome;
use serde_json::Value;

fn cmd() -> Command {
    Command::cargo_bin("codehelion").expect("binary should build")
}

/// Whether the helper that answers about C and C++ is here and usable.
fn clang_helper_is_usable() -> bool {
    let output = cmd().arg("doctor").output().expect("doctor should run");
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .any(|line| line.contains("clang-helper") && line.contains("available"))
}

/// A scan of `root` in semantic mode, as the report puts it.
fn scan(root: &std::path::Path) -> Value {
    let output = cmd()
        .current_dir(root)
        .args(["scan", ".", "--mode", "semantic", "--format", "json"])
        .output()
        .expect("run scan");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("stdout is one JSON document")
}

fn scan_comparing(root: &std::path::Path, format: &str) -> std::process::Output {
    cmd()
        .current_dir(root)
        .args([
            "scan",
            ".",
            "--mode",
            "semantic",
            "--format",
            format,
            "--compare-build-variants",
        ])
        .output()
        .expect("run scan")
}

fn comparison_json(root: &std::path::Path) -> Value {
    let output = scan_comparing(root, "json");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("stdout is one JSON document")
}

/// One report for an ordinary scan, or one per independent C/C++ variant.
fn reports(value: &Value) -> Vec<&Value> {
    value
        .get("partitions")
        .and_then(Value::as_array)
        .map_or_else(|| vec![value], |partitions| partitions.iter().collect())
}

/// The scan and the helper have to agree about how a file is named, and nothing
/// short of running both says whether they do: a run that named its units one
/// way while the helper looked them up another would come back a full,
/// successful, semantic scan that a compiler answered nothing in.
#[test]
fn a_cpp_tree_is_answered_about_rather_than_reported_as_unreadable() {
    if !clang_helper_is_usable() {
        return;
    }
    let dir = tempfile::tempdir().expect("temp dir");
    let root = codehelion_fixtures::copy_cpp("header-only", dir.path()).expect("plant the fixture");

    let report = scan(&root);
    let partitions = reports(&report);
    assert_eq!(partitions.len(), 2, "-D creates two reports: {report}");
    for partition in &partitions {
        let coverage = &partition["summary"]["compiler"];
        // One translation unit plus the header it reads. The shared header is
        // intentionally answered inside each build rather than reconciled
        // across two programs with different definitions.
        assert_eq!(coverage["answered"].as_u64(), Some(2), "{coverage}");
        assert!(
            coverage["unavailable"]
                .as_object()
                .is_none_or(serde_json::Map::is_empty),
            "nothing was left unanswerable: {coverage}"
        );
    }
    let store = Store::open(&root.join(".codehelion/audit.db")).expect("open audit database");
    let variants = partitions
        .iter()
        .map(|partition| {
            let fingerprint = partition["run"]["build_variant"]["fingerprint"]
                .as_str()
                .expect("variant fingerprint");
            store
                .build_variant(fingerprint)
                .expect("read variant")
                .expect("stored variant")
        })
        .collect::<Vec<_>>();
    assert_ne!(variants[0].fingerprint, variants[1].fingerprint);
    assert!(variants.iter().any(|variant| {
        variant
            .settings
            .iter()
            .any(|setting| setting.name == "macros" && setting.value == "-DACCUM_WIDTH=64")
    }));
    assert!(variants.iter().any(|variant| {
        !variant
            .settings
            .iter()
            .any(|setting| setting.name == "macros" && setting.value == "-DACCUM_WIDTH=64")
    }));
    assert!(variants.iter().all(|variant| {
        variant
            .settings
            .iter()
            .any(|setting| setting.name == "compiler" && setting.value == "clang++")
            && variant.settings.iter().any(|setting| {
                setting.name == "compiler_version" && setting.value.contains("clang")
            })
    }));
}

/// Compiler-confirmed C++ standard API names permit the same closed sequence
/// rule used for other SOGs without recovering names from Clang USRs.
#[test]
fn cplusplus_standard_api_calls_form_a_restricted_semantic_finding() {
    if !clang_helper_is_usable() {
        return;
    }
    let directory = tempfile::tempdir().expect("temp dir");
    let root = codehelion_fixtures::copy_cpp("overload-resolution", directory.path())
        .expect("plant fixture");
    let report = scan(&root);
    let group = reports(&report)
        .into_iter()
        .flat_map(|partition| partition["groups"].as_array().into_iter().flatten())
        .find(|group| {
            group["clone_type"] == "restricted-semantic"
                && group["semantic"]["rules"][0]["id"] == "sequence-pipeline-v1"
                && group["semantic"]["graphs"]
                    .as_array()
                    .is_some_and(|graphs| {
                        graphs.iter().all(|graph| {
                            graph["nodes"].as_array().is_some_and(|nodes| {
                                nodes
                                    .iter()
                                    .map(|node| node["kind"].as_str())
                                    .eq([Some("source"), Some("collect")])
                            })
                        })
                    })
        })
        .expect("two C++ standard API sequences form a semantic finding");
    assert_eq!(group["members"].as_array().map(Vec::len), Some(2));
    for graph in group["semantic"]["graphs"]
        .as_array()
        .expect("semantic graphs")
    {
        assert_eq!(
            graph["nodes"]
                .as_array()
                .expect("graph nodes")
                .iter()
                .map(|node| node["kind"].as_str())
                .collect::<Vec<_>>(),
            vec![Some("source"), Some("collect")]
        );
    }
}

/// A direct standard `lock_guard` is recorded as a matched lexical resource
/// lifetime, including the explicit resource edge persisted with the SOG.
#[test]
fn cplusplus_direct_lock_guard_lifetimes_form_a_restricted_semantic_finding() {
    if !clang_helper_is_usable() {
        return;
    }
    let directory = tempfile::tempdir().expect("temp dir");
    let root = codehelion_fixtures::copy_cpp("overload-resolution", directory.path())
        .expect("plant fixture");
    let report = scan(&root);
    let group = reports(&report)
        .into_iter()
        .flat_map(|partition| partition["groups"].as_array().into_iter().flatten())
        .find(|group| {
            group["clone_type"] == "restricted-semantic"
                && group["semantic"]["rules"][0]["id"] == "resource-lifecycle-v1"
        })
        .unwrap_or_else(|| panic!("two C++ lock guards form a semantic finding: {report}"));
    assert_eq!(group["members"].as_array().map(Vec::len), Some(2));
    for graph in group["semantic"]["graphs"]
        .as_array()
        .expect("semantic graphs")
    {
        assert_eq!(
            graph["nodes"]
                .as_array()
                .expect("graph nodes")
                .iter()
                .map(|node| node["kind"].as_str())
                .collect::<Vec<_>>(),
            vec![Some("acquire_resource"), Some("release_resource")]
        );
        assert_eq!(
            graph["edges"]
                .as_array()
                .expect("graph edges")
                .iter()
                .filter(|edge| edge["kind"] == "resource_lifetime")
                .count(),
            1
        );
    }
}

#[test]
fn cplusplus_standard_algorithm_calls_form_a_restricted_semantic_finding() {
    if !clang_helper_is_usable() {
        return;
    }
    let directory = tempfile::tempdir().expect("temp dir");
    let root = codehelion_fixtures::copy_cpp("overload-resolution", directory.path())
        .expect("plant fixture");
    let report = scan(&root);
    let group = reports(&report)
        .into_iter()
        .flat_map(|partition| partition["groups"].as_array().into_iter().flatten())
        .find(|group| {
            group["clone_type"] == "restricted-semantic"
                && group["semantic"]["rules"][0]["id"] == "sequence-pipeline-v1"
                && group["semantic"]["graphs"]
                    .as_array()
                    .is_some_and(|graphs| {
                        graphs.iter().all(|graph| {
                            graph["nodes"].as_array().is_some_and(|nodes| {
                                nodes
                                    .iter()
                                    .map(|node| node["kind"].as_str())
                                    .eq([Some("source"), Some("map")])
                            })
                        })
                    })
        })
        .expect("two C++ transforms form a semantic finding");
    assert_eq!(group["members"].as_array().map(Vec::len), Some(2));
}

#[test]
fn cplusplus_standard_filter_calls_form_a_restricted_semantic_finding() {
    if !clang_helper_is_usable() {
        return;
    }
    let directory = tempfile::tempdir().expect("temp dir");
    let root = codehelion_fixtures::copy_cpp("overload-resolution", directory.path())
        .expect("plant fixture");
    let report = scan(&root);
    let group = reports(&report)
        .into_iter()
        .flat_map(|partition| partition["groups"].as_array().into_iter().flatten())
        .find(|group| {
            group["clone_type"] == "restricted-semantic"
                && group["semantic"]["rules"][0]["id"] == "sequence-pipeline-v1"
                && group["semantic"]["graphs"]
                    .as_array()
                    .is_some_and(|graphs| {
                        graphs.iter().all(|graph| {
                            graph["nodes"].as_array().is_some_and(|nodes| {
                                nodes
                                    .iter()
                                    .map(|node| node["kind"].as_str())
                                    .eq([Some("source"), Some("filter")])
                            })
                        })
                    })
        })
        .expect("two C++ filters form a semantic finding");
    assert_eq!(group["members"].as_array().map(Vec::len), Some(2));
}

/// Cross-build comparison is an explicit, separate result: a normal semantic
/// scan retains the partition-only schema and snapshot meaning, while the
/// opt-in comparison names every member's source build variant.
#[test]
fn explicit_cross_build_comparison_is_separate_and_origin_aware() {
    if !clang_helper_is_usable() {
        return;
    }
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
/// from one build variant.
#[test]
fn one_build_variant_does_not_emit_or_persist_a_cross_comparison() {
    if !clang_helper_is_usable() {
        return;
    }
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
    if !clang_helper_is_usable() {
        return;
    }
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
            partition["summary"]["compiler"]["unavailable"]["no_build_information"].as_u64()
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

/// A generated database may legitimately compile the exact same source twice.
/// The selector is the full command rather than the source path, so both
/// entries survive planning and each Clang request chooses its own `-D`.
#[test]
fn a_duplicate_source_command_selects_each_exact_build_entry() {
    if !clang_helper_is_usable() {
        return;
    }
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
                        if ir.unit.file.ends_with("include/accumulate.hpp") =>
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
    if !clang_helper_is_usable() {
        return;
    }
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
            CompilerOutcome::Analyzed(ir) if ir.unit.file.ends_with("include/templates.hpp") => {
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
    assert_eq!(stamp.arguments.len(), 1);
    let argument = usize::try_from(stamp.arguments[0]).expect("type index fits");
    assert_eq!(
        header.types[argument].category,
        codehelion_helper::ir::TypeCategory::Integer
    );
}

/// A header's calls remain inside their exact C++ build partition. A selected
/// overload may differ across `-DWIDE_CALL`, but neither reading becomes the
/// other partition's answer.
#[test]
fn call_targets_survive_header_agreement_and_sqlite_round_trip() {
    if !clang_helper_is_usable() {
        return;
    }
    let dir = tempfile::tempdir().expect("temp dir");
    let root =
        codehelion_fixtures::copy_cpp("overload-resolution", dir.path()).expect("plant fixture");
    let header_source =
        std::fs::read_to_string(root.join("include/calls.hpp")).expect("read fixture header");
    let stable = u64::try_from(header_source.find("direct(8)").expect("stable call")).unwrap();
    let selected = u64::try_from(
        header_source
            .find("choose(HEADER_ARGUMENT)")
            .expect("variant call"),
    )
    .unwrap();

    let report = scan(&root);
    let partitions = reports(&report);
    assert_eq!(partitions.len(), 2, "-D creates two reports: {report}");
    let store = Store::open(&root.join(".codehelion/audit.db")).expect("open audit database");
    let headers = partitions
        .iter()
        .map(|partition| {
            let run_id = partition["run"]["run_id"].as_i64().expect("recorded run");
            let units = store
                .run_compiler_units(run_id)
                .expect("read compiler results");
            units
                .iter()
                .find_map(|stored| match &stored.outcome {
                    CompilerOutcome::Analyzed(ir)
                        if ir.unit.file.ends_with("include/calls.hpp") =>
                    {
                        Some(ir.clone())
                    }
                    CompilerOutcome::Analyzed(_) | CompilerOutcome::Unavailable { .. } => None,
                })
                .expect("each partition answered its header")
        })
        .collect::<Vec<_>>();
    let targets = headers
        .iter()
        .map(|header| {
            let stable_call = header
                .calls
                .iter()
                .find(|call| call.anchor.expansion.start_byte == stable)
                .expect("the direct call survived storage");
            assert!(matches!(stable_call.target, CallTarget::Static { .. }));
            let selected_call = header
                .calls
                .iter()
                .find(|call| call.anchor.expansion.start_byte == selected)
                .expect("the selected overload stayed in its partition");
            match &selected_call.target {
                CallTarget::Static { symbol } => symbol.clone(),
                CallTarget::Dynamic { .. } | CallTarget::Unresolved => {
                    panic!(
                        "the overload should resolve statically: {:?}",
                        selected_call.target
                    )
                }
            }
        })
        .collect::<Vec<_>>();
    assert_ne!(
        targets[0], targets[1],
        "each variant selected its own overload"
    );
}

/// A tree with no compilation database is a tree this helper has nothing to say
/// about, and saying so per file is what keeps a mixed project scannable. A run
/// that failed here would make one language's missing build stop the other
/// language's analysis.
#[test]
fn a_cpp_tree_with_no_compilation_database_is_reported_rather_than_refused() {
    if !clang_helper_is_usable() {
        return;
    }
    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path().join("src");
    std::fs::create_dir_all(&root).expect("create the tree");
    std::fs::write(
        root.join("accumulate.cpp"),
        "int total(int a, int b) { return a + b; }\n",
    )
    .expect("write a source");

    let report = scan(dir.path());
    let coverage = &report["summary"]["compiler"];
    assert_eq!(coverage["answered"].as_u64(), Some(0), "{coverage}");
    assert_eq!(
        coverage["unavailable"]["no_build_information"].as_u64(),
        Some(1),
        "{coverage}"
    );
}
