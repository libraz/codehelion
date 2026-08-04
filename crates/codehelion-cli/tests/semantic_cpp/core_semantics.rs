use super::*;

#[test]
fn a_cpp_tree_is_answered_about_rather_than_reported_as_unreadable() {
    require_clang_helper();
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

#[test]
fn shared_discovery_exclusions_are_counted_once_across_semantic_partitions() {
    require_clang_helper();
    let dir = tempfile::tempdir().expect("temp dir");
    let root = codehelion_fixtures::copy_cpp("header-only", dir.path()).expect("plant the fixture");
    std::fs::write(
        root.join("src/generated.cpp"),
        "// @generated\nint generated() { return 0; }\n",
    )
    .expect("write generated source");
    std::fs::write(root.join("src/blob.cpp"), [0_u8, 1, 2, 3]).expect("write binary source");

    let report = scan(&root);
    let partitions = reports(&report);
    assert_eq!(partitions.len(), 2, "-D creates two reports: {report}");
    for (field, expected) in [("generated", 1), ("binary", 1), ("skipped", 1)] {
        let total: u64 = partitions
            .iter()
            .filter_map(|partition| partition["summary"]["excluded"][field].as_u64())
            .sum();
        assert_eq!(total, expected, "{field} is counted once: {report}");
    }
}

#[test]
fn a_semantic_baseline_freezes_and_reapplies_every_completed_build_variant() {
    require_clang_helper();
    let directory = tempfile::tempdir().expect("temp dir");
    let root =
        codehelion_fixtures::copy_cpp("header-only", directory.path()).expect("plant fixture");
    let report = scan(&root);
    let expected: std::collections::BTreeSet<_> = reports(&report)
        .into_iter()
        .filter_map(|partition| {
            partition["run"]["build_variant"]["fingerprint"]
                .as_str()
                .map(ToOwned::to_owned)
        })
        .collect();
    assert_eq!(expected.len(), 2, "fixture has two build variants");

    cmd()
        .current_dir(&root)
        .args(["baseline", "create", ".", "--file", "baseline.json"])
        .assert()
        .success()
        .stdout(predicates::str::contains("2 build variants"));
    let baseline: Value = serde_json::from_slice(
        &std::fs::read(root.join("baseline.json")).expect("read written baseline"),
    )
    .expect("parse baseline JSON");
    let actual: std::collections::BTreeSet<_> = baseline["partitions"]
        .as_array()
        .expect("partitions")
        .iter()
        .filter_map(|partition| {
            partition["build_variant"]["fingerprint"]
                .as_str()
                .map(ToOwned::to_owned)
        })
        .collect();
    assert_eq!(actual, expected);
    let output = cmd()
        .current_dir(&root)
        .args([
            "scan",
            ".",
            "--mode",
            "semantic",
            "--baseline",
            "baseline.json",
            "--format",
            "json",
        ])
        .output()
        .expect("reapply semantic baseline");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Compiler-confirmed C++ standard API names permit the same closed sequence
/// rule used for other SOGs without recovering names from Clang USRs.
#[test]
fn cplusplus_standard_api_calls_form_a_restricted_semantic_finding() {
    require_clang_helper();
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
                && group["members"].as_array().is_some_and(|members| {
                    let units: Vec<_> = members
                        .iter()
                        .filter_map(|member| member["unit"].as_str())
                        .collect();
                    units.contains(&"standard_api_names")
                        && units.contains(&"standard_api_names_again")
                })
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
    assert!(
        group["semantic"]["graphs"]
            .as_array()
            .is_some_and(|graphs| {
                graphs
                    .iter()
                    .filter(|graph| {
                        graph["nodes"].as_array().is_some_and(|nodes| {
                            nodes
                                .iter()
                                .map(|node| node["kind"].as_str())
                                .eq([Some("source"), Some("collect")])
                                && nodes[0]["attributes"]["api_names"]
                                    == serde_json::json!(["std::begin"])
                                && nodes[1]["attributes"]["api_names"]
                                    == serde_json::json!(["std::push_back"])
                        })
                    })
                    .count()
                    == 2
            }),
        "the original API observations remain compiler-confirmed: {group}"
    );
}

#[test]
fn cplusplus_semantic_scan_requires_a_helper_that_reads_cpp() {
    require_clang_helper();
    let directory = tempfile::tempdir().expect("temp dir");
    let root = codehelion_fixtures::copy_cpp("overload-resolution", directory.path())
        .expect("plant fixture");

    let with_cfg = scan(&root);
    assert!(
        !restricted_finding_set(&with_cfg).is_empty(),
        "a usable C++ helper produces restricted-semantic findings"
    );

    let no_helper_path = tempfile::tempdir().expect("empty PATH directory");
    cmd()
        .current_dir(&root)
        .env("PATH", no_helper_path.path())
        .args([
            "scan",
            ".",
            "--mode",
            "semantic",
            "--helper",
            "clang=/definitely-missing-codehelion-backend-clang",
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains("found no helper that reads cpp"));
}

#[test]
fn cplusplus_plain_range_loops_match_as_closed_collections() {
    require_clang_helper();
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
                && group["members"].as_array().is_some_and(|members| {
                    let units: Vec<_> = members
                        .iter()
                        .filter_map(|member| member["unit"].as_str())
                        .collect();
                    units.contains(&"copied")
                        && units.contains(&"copied_again")
                        && !units.contains(&"transformed")
                })
        })
        .unwrap_or_else(|| panic!("two direct C++ range loops form a semantic finding: {report}"));
    assert!(
        group["semantic"]["graphs"]
            .as_array()
            .is_some_and(|graphs| {
                graphs
                    .iter()
                    .filter(|graph| {
                        graph["nodes"].as_array().is_some_and(|nodes| {
                            nodes
                                .iter()
                                .map(|node| node["kind"].as_str())
                                .eq([Some("source"), Some("collect")])
                                && nodes.iter().all(|node| {
                                    node["attributes"]["api_names"]
                                        .as_array()
                                        .is_some_and(Vec::is_empty)
                                })
                        })
                    })
                    .count()
                    == 2
            }),
        "the two range loops retain the closed source/collect shape: {group}"
    );
}

/// Both loops reduce every element of one standard sequence, so they are the
/// same registered claim however their accumulators differ. The loop that adds
/// one before accumulating is a different sequence and stays outside.
#[test]
fn cplusplus_plain_range_loops_match_as_closed_reductions() {
    require_clang_helper();
    let directory = tempfile::tempdir().expect("temp dir");
    let root = codehelion_fixtures::copy_cpp("overload-resolution", directory.path())
        .expect("plant fixture");
    let report = scan(&root);
    assert_sequence_family(
        &report,
        &["summed", "summed_again"],
        &["source", "reduce"],
        &["transformed_sum", "copied"],
    );
}

/// A direct standard `lock_guard` is recorded as a matched lexical resource
/// lifetime, including the explicit resource edge persisted with the SOG.
#[test]
fn cplusplus_direct_lock_guard_lifetimes_form_a_restricted_semantic_finding() {
    require_clang_helper();
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

/// A registered rule compares the operation sequence the compiler resolved,
/// not the expression handed to each operation. Three `std::transform` calls
/// therefore form one family however their lambdas differ, and the loop that
/// collects without transforming stays out of it.
#[test]
fn cplusplus_standard_algorithm_calls_match_across_transformations() {
    require_clang_helper();
    let directory = tempfile::tempdir().expect("temp dir");
    let root = codehelion_fixtures::copy_cpp("overload-resolution", directory.path())
        .expect("plant fixture");
    let report = scan(&root);
    assert_sequence_family(
        &report,
        &["doubled", "doubled_again", "tripled"],
        &["source", "map"],
        &["copied", "summed"],
    );
}

/// The predicates differ and the operation sequence does not, which is the
/// case the rule exists for. A transformation is a different sequence and
/// stays outside.
#[test]
fn cplusplus_standard_filter_calls_match_across_predicates() {
    require_clang_helper();
    let directory = tempfile::tempdir().expect("temp dir");
    let root = codehelion_fixtures::copy_cpp("overload-resolution", directory.path())
        .expect("plant fixture");
    let report = scan(&root);
    assert_sequence_family(
        &report,
        &["positive", "even"],
        &["source", "filter"],
        &["doubled", "copied"],
    );
}

/// Find the one `sequence-pipeline-v1` group holding exactly `members`, check
/// the operation sequence every member's graph carries, and check that each
/// named outsider is somewhere else.
fn assert_sequence_family(
    report: &Value,
    members: &[&str],
    operations: &[&str],
    outsiders: &[&str],
) {
    let group = reports(report)
        .into_iter()
        .flat_map(|partition| partition["groups"].as_array().into_iter().flatten())
        .find(|group| {
            group["clone_type"] == "restricted-semantic"
                && group["semantic"]["rules"][0]["id"] == "sequence-pipeline-v1"
                && group["members"].as_array().is_some_and(|found| {
                    let units: Vec<_> = found
                        .iter()
                        .filter_map(|member| member["unit"].as_str())
                        .collect();
                    units.len() == members.len()
                        && members.iter().all(|member| units.contains(member))
                })
        })
        .unwrap_or_else(|| panic!("{members:?} form one semantic finding: {report}"));
    for graph in group["semantic"]["graphs"]
        .as_array()
        .expect("semantic graphs")
    {
        assert_eq!(
            graph["nodes"]
                .as_array()
                .expect("graph nodes")
                .iter()
                .filter_map(|node| node["kind"].as_str())
                .collect::<Vec<_>>(),
            operations,
            "a member left the operation sequence the family is about: {group}"
        );
    }
    let units: Vec<_> = group["members"]
        .as_array()
        .expect("group members")
        .iter()
        .filter_map(|member| member["unit"].as_str())
        .collect();
    for outsider in outsiders {
        assert!(
            !units.contains(outsider),
            "a different operation sequence entered the family: {group}"
        );
    }
}

/// The compiler's answer and the fragments cut from the same file have to be
/// about the same bytes of the same file, and three separate things have to
/// line up for that: how the analysis names the file, whether it says anything
/// about it, and whether what it says points where the scan read.
///
/// Each is checked separately because a scan that loses any one of them looks
/// identical from the outside — a full, successful, semantic run that reports
/// nothing a compiler contributed. Which of the three went is the difference
/// between a spelling fault, a compiler that answered about nothing, and
/// offsets measured against a different copy of the file.
#[test]
fn a_cpp_answer_is_about_the_bytes_the_scan_read() {
    require_clang_helper();
    let directory = tempfile::tempdir().expect("temp dir");
    let root = codehelion_fixtures::copy_cpp("overload-resolution", directory.path())
        .expect("plant fixture");
    let report = scan(&root);
    // Every partition, because a `-D` splits this tree into two programs with
    // a run of their own, and the file asked about below belongs to one of
    // them. Reading whichever comes first would make the answer depend on the
    // order two independent programs happen to be reported in.
    let run_ids: Vec<i64> = reports(&report)
        .iter()
        .filter_map(|partition| partition["run"]["run_id"].as_i64())
        .collect();
    assert!(!run_ids.is_empty(), "the scan records a run id: {report}");

    let store = Store::open(&root.join(".codehelion/audit.db")).expect("open audit database");
    let source = root.join("src").join("range_loop.cpp");
    let absolute = codehelion_core::paths::canonical(&source).expect("the planted source resolves");
    let text = std::fs::read_to_string(&source).expect("the planted source is readable");

    let irs: Vec<_> = run_ids
        .iter()
        .flat_map(|run_id| {
            store
                .run_compiler_units(*run_id)
                .expect("read compiler rows")
        })
        .filter_map(|unit| match unit.outcome {
            CompilerOutcome::Analyzed(ir) => Some(ir),
            CompilerOutcome::Unavailable { .. } => None,
        })
        .collect();
    assert!(!irs.is_empty(), "no unit of this tree was analyzed");

    // How a reader holding the file asks about it, written by the same rule the
    // helper wrote its anchors with. Everything below is filed under this name.
    let named: Vec<String> = irs.iter().map(|ir| ir.spelling(&absolute)).collect();
    let anchored: Vec<&str> = irs
        .iter()
        .flat_map(|ir| {
            ir.calls
                .iter()
                .map(|call| call.anchor.expansion.file.as_str())
        })
        .collect();
    assert!(
        named.iter().any(|name| anchored.contains(&name.as_str())),
        "no answer is filed under the name a reader looks this file up by.\n\
         looked up as: {named:?}\n\
         answers are filed under: {:?}\n\
         anchored at: {:?}",
        anchored
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>(),
        irs.iter().map(|ir| &ir.anchored_at).collect::<Vec<_>>()
    );

    let spelling = named
        .iter()
        .find(|name| anchored.contains(&name.as_str()))
        .expect("one of the answers is about this file");
    let ir = irs
        .iter()
        .find(|ir| {
            ir.calls
                .iter()
                .any(|call| call.anchor.expansion.file == *spelling)
        })
        .expect("the answer about this file");

    // What it says about it. A standard call is the smallest thing every rule
    // over this fixture is built out of.
    let standard: Vec<_> = ir
        .calls
        .iter()
        .filter(|call| call.anchor.expansion.file == *spelling)
        .filter(|call| call.api_name.as_deref() == Some("std::push_back"))
        .collect();
    assert!(
        !standard.is_empty(),
        "the compiler resolved no standard call in a file written out of them: {:?}",
        ir.calls
            .iter()
            .filter(|call| call.anchor.expansion.file == *spelling)
            .filter_map(|call| call.api_name.as_deref())
            .collect::<std::collections::BTreeSet<_>>()
    );
    assert!(
        ir.semantic_constructs
            .iter()
            .any(|construct| construct.anchor.expansion.file == *spelling),
        "the compiler reported no construct in a file of range loops"
    );

    // And where. An offset is only an offset into some copy of the file, so it
    // is checked against the copy the scan read rather than assumed to be the
    // same one.
    for call in standard {
        let range = &call.anchor.expansion;
        let start = usize::try_from(range.start_byte).expect("an offset within this file");
        let end = usize::try_from(range.end_byte).expect("an offset within this file");
        let written = text
            .get(start..end)
            .unwrap_or_else(|| panic!("{start}..{end} is outside the {} bytes read", text.len()));
        assert!(
            written.contains("push_back"),
            "the offsets point at {written:?}, not at the call they were reported for"
        );
    }
}
