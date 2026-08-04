use super::*;

/// A C++ template specialization can still correlate to a stripped object
/// through its compiler display key and demangled symbol name. Debug locations
/// are deliberately absent here, so the generic-origin evidence is the only
/// route that can produce the report entry.
#[test]
#[allow(
    clippy::disallowed_types,
    clippy::too_many_lines,
    reason = "the integration fixture is compiled outside the product scan path"
)]
fn cpp_template_specializations_correlate_to_a_debugless_object() {
    require_clang_helper();
    let dir = tempfile::tempdir().expect("temp dir");
    let root =
        codehelion_fixtures::copy_cpp("template-instantiation", dir.path()).expect("plant fixture");
    let source_report = scan(&root);
    let source_run = source_report["run"]["run_id"]
        .as_i64()
        .expect("recorded source run");
    let object = root.join("templates.o");
    let status = std::process::Command::new("clang++")
        .current_dir(&root)
        .args([
            "-std=c++17",
            "-g0",
            "-O0",
            "-fno-inline",
            "-I",
            "include",
            "-c",
            "src/templates.cpp",
            "-o",
            "templates.o",
        ])
        .status()
        .expect("compile debugless C++ object");
    assert!(status.success(), "template fixture should compile");
    let manifest = root.join("artifact-build-variant.json");
    std::fs::write(
        &manifest,
        r#"{"target":"fixture","optimization_level":0,"debug_info":false}"#,
    )
    .expect("write artifact build variant");
    let database = root.join(".codehelion/audit.db");
    let store = Store::open(&database).expect("open source database");
    let source_instantiations = store
        .source_instantiations(source_run)
        .expect("read source instantiations");
    let source_units = store.source_units(source_run).expect("read source units");
    assert!(
        source_units
            .iter()
            .any(|unit| unit.file_path == "include/templates.hpp"
                && unit.name.as_deref() == Some("twice")),
        "the source clone fixture must retain the generic definition unit: {source_units:#?}"
    );
    assert!(
        source_instantiations.iter().any(|instantiation| {
            instantiation
                .artifact_match_key
                .as_deref()
                .is_some_and(|key| key.starts_with("clang-display-v1:templates::twice"))
        }),
        "{source_instantiations:#?}"
    );
    let output = cmd()
        .current_dir(&root)
        .args([
            "artifact",
            "analyze",
            object.to_str().expect("object path"),
            "--format",
            "json",
            "--build-variant",
            manifest.to_str().expect("manifest path"),
            "--source-run",
            &source_run.to_string(),
            "--db",
            database.to_str().expect("database path"),
        ])
        .output()
        .expect("analyse debugless C++ object");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("artifact JSON report");
    let origins = report["correlation"]["generic_origins"]
        .as_array()
        .expect("generic origins are reported");
    assert!(
        origins.iter().any(|origin| {
            origin["specializations"]
                .as_array()
                .is_some_and(|specializations| {
                    specializations.iter().any(|specialization| {
                        specialization["instantiation_key"]
                            .as_str()
                            .is_some_and(|key| key.starts_with("clang-usr-v1:"))
                            && specialization["observed_symbol_bytes"]
                                .as_u64()
                                .is_some_and(|bytes| bytes > 0)
                    })
                })
        }),
        "artifact report: {report}\nsource instantiations: {source_instantiations:#?}\nsource units: {source_units:#?}"
    );
    assert!(
        origins.iter().any(|origin| {
            origin["specializations"]
                .as_array()
                .is_some_and(|specializations| {
                    specializations.iter().any(|specialization| {
                        specialization["instantiation_key"]
                            .as_str()
                            .is_some_and(|key| key.contains("@S@Buffer>"))
                            && specialization["observed_symbol_bytes"]
                                .as_u64()
                                .is_some_and(|bytes| bytes > 0)
                    })
                })
        }),
        "the emitted class-template member should retain generic-origin evidence: {report}\nsource instantiations: {source_instantiations:#?}\nsource units: {source_units:#?}"
    );
    assert_eq!(
        report["correlation"]["mappings"].as_u64(),
        Some(6),
        "two function specializations and four class-member specializations map once each: {report}"
    );
    assert_eq!(
        origins.len(),
        3,
        "three template origins should rank separately: {report}"
    );
    assert!(
        origins[0]["observed_symbol_bytes"]
            .as_u64()
            .zip(origins[1]["observed_symbol_bytes"].as_u64())
            .is_some_and(|(higher, lower)| higher > lower),
        "generic origins must be ordered by observed symbol bytes: {report}"
    );
    assert!(
        origins[1]["observed_symbol_bytes"]
            .as_u64()
            .zip(origins[2]["observed_symbol_bytes"].as_u64())
            .is_some_and(|(higher, lower)| higher > lower),
        "generic origins must retain their complete byte ordering: {report}"
    );
    assert_eq!(origins[0]["instantiations"].as_u64(), Some(3), "{report}");
    assert_eq!(origins[1]["instantiations"].as_u64(), Some(2), "{report}");
    assert_eq!(origins[2]["instantiations"].as_u64(), Some(1), "{report}");
    assert!(
        origins[0]["specializations"]
            .as_array()
            .is_some_and(
                |specializations| specializations.iter().all(|specialization| {
                    specialization["instantiation_key"]
                        .as_str()
                        .is_some_and(|key| key.contains("@S@Buffer>"))
                })
            ),
        "the higher-ranked origin is the three-specialization Buffer template: {report}"
    );
    assert!(
        origins[2]["specializations"]
            .as_array()
            .is_some_and(
                |specializations| specializations.iter().all(|specialization| {
                    specialization["instantiation_key"]
                        .as_str()
                        .is_some_and(|key| key.contains("@S@BufferForComparison>"))
                })
            ),
        "the lower-ranked origin remains distinct despite sharing member names: {report}"
    );
}

/// A header's calls remain inside their exact C++ build partition. A selected
/// overload may differ across `-DWIDE_CALL`, but neither reading becomes the
/// other partition's answer.
#[test]
fn call_targets_survive_header_agreement_and_sqlite_round_trip() {
    require_clang_helper();
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
                        if names_the_file(&ir.unit.file, "include/calls.hpp") =>
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
    require_clang_helper();
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

/// A Rust partition must not hide C/C++ sources just because no compilation
/// database exists. The C++ pair still belongs to its own explicit no-build
/// partition and remains visible as a structural finding.
#[test]
fn a_mixed_tree_without_a_compilation_database_keeps_cpp_findings() {
    require_clang_helper();
    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path().join("src");
    std::fs::create_dir_all(&root).expect("create the tree");
    let cpp = r"
int total(const int *values, int count) {
    int sum = 0;
    for (int index = 0; index < count; ++index) {
        if (values[index] % 2 == 0) {
            sum += values[index];
        } else {
            sum -= values[index];
        }
    }
    return sum;
}
";
    std::fs::write(root.join("first.cpp"), cpp).expect("write first C++ source");
    std::fs::write(root.join("second.cpp"), cpp).expect("write second C++ source");
    std::fs::write(root.join("lib.rs"), "pub fn marker() {}\n").expect("write Rust source");

    let report = scan(dir.path());
    let no_build_sources: u64 = reports(&report)
        .into_iter()
        .filter_map(|partition| {
            partition["summary"]["compiler"]["unavailable"]["no_build_information"].as_u64()
        })
        .sum();
    assert_eq!(no_build_sources, 2, "{report}");

    let cpp_members = reports(&report)
        .into_iter()
        .flat_map(|partition| partition["groups"].as_array().into_iter().flatten())
        .flat_map(|group| group["members"].as_array().into_iter().flatten())
        .filter(|member| {
            member["file"].as_str().is_some_and(|file| {
                std::path::Path::new(file)
                    .extension()
                    .is_some_and(|extension| extension.eq_ignore_ascii_case("cpp"))
            })
        })
        .count();
    assert!(cpp_members >= 2, "{report}");
}
