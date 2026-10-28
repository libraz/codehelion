//! Name stems: bodies that differ only in template arguments, closure
//! numbering or parameter lists, in an analysis and in a comparison.

use super::*;

const NOTE: &str = "  note: a stem groups bodies whose names differ only in template arguments, closure numbering or parameter lists; one source template written once can account for all of them, so the bytes are what the artifact spends, not what consolidating source would remove";
const ASSUMPTION: &str = "name stems follow symbol names only, so overloads and same-named copies share a stem with template instantiations, and unnamed symbols belong to none";
const HEADING: &str = "name stems emitted as several bodies (observed, not savings):";

/// Symbols named and sized as given; the seed is the index, so equal names
/// still carry distinct identities.
fn symbols_of(entries: &[(&str, u64)]) -> Vec<codehelion_artifact::ArtifactSymbol> {
    entries
        .iter()
        .enumerate()
        .map(|(index, (name, size))| {
            comparison_symbol(Some(name), format!("{name}#{index}").as_bytes(), *size)
        })
        .collect()
}

fn artifact_of(entries: &[(&str, u64)]) -> ArtifactIr {
    let mut artifact = WasmBackend.parse(b"\0asm\x01\0\0\0").unwrap();
    artifact.symbols = symbols_of(entries);
    artifact
}

fn report_of(entries: &[(&str, u64)]) -> ArtifactReport {
    ArtifactReport::from_ir(
        FilePath::new("fixture.wasm"),
        &artifact_of(entries),
        None,
        None,
    )
}

fn stems_json(report: &ArtifactReport) -> Vec<serde_json::Value> {
    serde_json::to_value(report).unwrap()["name_stems"]
        .as_array()
        .unwrap()
        .clone()
}

const PROBES: [(&str, u64); 3] = [
    ("int probe<f::$_0>(char const*, f::$_0)", 340),
    ("int probe<f::$_1>(char const*, f::$_1)", 304),
    ("int probe<f::$_2>(char const*, f::$_2)", 304),
];

fn six_symbols() -> Vec<(&'static str, u64)> {
    let mut entries = PROBES.to_vec();
    entries.extend([
        ("std::__2::deque<int>::push_back(int&&)", 100),
        ("std::__2::deque<int>::pop_front()", 80),
        ("solo()", 10),
    ]);
    entries
}

#[test]
fn template_instances_and_container_members_group_under_their_stems() {
    let report = report_of(&six_symbols());
    let stems = stems_json(&report);

    assert_eq!(stems.len(), 2, "{stems:?}");
    assert_eq!(stems[0]["stem"], "probe<>");
    assert_eq!(stems[0]["parameterized"], true);
    assert_eq!(stems[0]["owner"], "<global>");
    assert_eq!(stems[0]["ownership"], "other");
    assert_eq!(stems[0]["bodies"], 3);
    assert_eq!(stems[0]["instances"], 3);
    assert_eq!(stems[0]["size_bytes"], 948);
    assert_eq!(stems[1]["stem"], "std::__2::deque<>");
    assert_eq!(stems[1]["parameterized"], true);
    assert_eq!(stems[1]["owner"], "std");
    assert_eq!(stems[1]["ownership"], "toolchain");
    assert_eq!(stems[1]["bodies"], 2);
    assert_eq!(stems[1]["instances"], 1);
    assert_eq!(stems[1]["size_bytes"], 180);
    assert_eq!(
        stems[0]["instance_details"],
        serde_json::json!([
            {"instance": "probe<f::$_0>", "bodies": 1, "size_bytes": 340},
            {"instance": "probe<f::$_1>", "bodies": 1, "size_bytes": 304},
            {"instance": "probe<f::$_2>", "bodies": 1, "size_bytes": 304},
        ])
    );
    assert_eq!(
        stems[1]["instance_details"],
        serde_json::json!([
            {"instance": "std::__2::deque<int>", "bodies": 2, "size_bytes": 180},
        ])
    );
}

#[test]
fn a_stem_with_one_body_and_unnamed_symbols_are_not_listed() {
    let mut artifact = artifact_of(&[("solo()", 10), ("other(int)", 12)]);
    artifact
        .symbols
        .push(comparison_symbol(None, b"nameless-a", 6));
    artifact
        .symbols
        .push(comparison_symbol(None, b"nameless-b", 6));
    let report = ArtifactReport::from_ir(FilePath::new("fixture.wasm"), &artifact, None, None);

    assert_eq!(stems_json(&report).len(), 0);
    let json = serde_json::to_value(&report).unwrap();
    assert_eq!(json["name_stem_assumptions"], serde_json::json!([]));
    let text = rendered_text(&report, true);
    assert!(!text.contains(HEADING), "{text}");
    assert!(!text.contains(ASSUMPTION), "{text}");
    assert_eq!(artifact_csv_records_of(&report, "name-stem").len(), 0);
}

#[test]
fn overloads_and_same_named_copies_share_one_stem() {
    let report = report_of(&[
        ("foo(int)", 40),
        ("foo(unsigned int)", 44),
        ("foo(int)", 40),
    ]);
    let stems = stems_json(&report);

    assert_eq!(stems.len(), 1);
    assert_eq!(stems[0]["stem"], "foo");
    assert_eq!(stems[0]["parameterized"], false);
    assert_eq!(stems[0]["bodies"], 3);
    assert_eq!(stems[0]["instances"], 2);
    assert_eq!(stems[0]["size_bytes"], 124);
    // Larger instance first.
    assert_eq!(stems[0]["instance_details"][0]["instance"], "foo(int)");
    assert_eq!(stems[0]["instance_details"][0]["bodies"], 2);
}

#[test]
fn closure_members_take_the_owner_of_their_symbol_not_of_the_stem() {
    let report = report_of(&[
        ("f()::$_0::operator()(char) const", 20),
        ("f()::$_1::operator()(char) const", 22),
    ]);
    let stems = stems_json(&report);

    assert_eq!(stems.len(), 1);
    assert_eq!(stems[0]["stem"], "f::{closure}");
    assert_eq!(stems[0]["owner"], "<global>");
    assert_eq!(stems[0]["bodies"], 2);
    assert_eq!(stems[0]["instances"], 2);
    let json = serde_json::to_value(&report).unwrap();
    for symbol in json["symbols"].as_array().unwrap() {
        assert_eq!(symbol["owner"], stems[0]["owner"]);
    }
}

#[test]
fn a_stem_split_across_two_owners_is_two_rows() {
    let report = report_of(&[
        ("f()::$_0::operator()(char) const", 20),
        ("f()::$_1::operator()(char) const", 22),
        ("f::{{closure}}", 30),
        ("f::{closure#0}", 31),
    ]);
    let stems = stems_json(&report);

    assert_eq!(stems.len(), 2, "{stems:?}");
    assert!(stems.iter().all(|row| row["stem"] == "f::{closure}"));
    let owners: Vec<&str> = stems
        .iter()
        .map(|row| row["owner"].as_str().unwrap())
        .collect();
    // Larger bytes first.
    assert_eq!(owners, ["f", "<global>"]);
    assert_eq!(stems[0]["size_bytes"], 61);
    assert_eq!(stems[1]["size_bytes"], 42);
}

#[test]
fn stems_are_ordered_by_bytes_then_bodies_then_name_then_owner() {
    let report = report_of(&[
        ("b<int>()", 10),
        ("b<long>()", 10),
        ("a<int>()", 10),
        ("a<long>()", 10),
        ("c<int>()", 5),
        ("c<long>()", 5),
        ("c<char>()", 5),
        ("d<int>()", 40),
        ("d<long>()", 10),
    ]);
    let order: Vec<String> = stems_json(&report)
        .iter()
        .map(|row| row["stem"].as_str().unwrap().to_owned())
        .collect();
    // d 50 bytes; a and b 20 bytes in 2 bodies; c 15 bytes.
    assert_eq!(order, ["d<>", "a<>", "b<>", "c<>"]);

    let tied = stems_json(&report_of(&[
        ("a<int>()", 10),
        ("a<long>()", 10),
        ("b<int>()", 5),
        ("b<long>()", 5),
        ("b<char>()", 5),
        ("b<short>()", 5),
    ]));
    // Equal bytes: more bodies first.
    assert_eq!(tied[0]["stem"], "b<>");
    assert_eq!(tied[1]["stem"], "a<>");
}

#[test]
fn text_lists_the_stems_between_ownership_and_the_toolchain_holders() {
    let report = report_of(&six_symbols());
    let text = rendered_text(&report, false);

    assert!(
        text.contains(&format!(
            "{HEADING}\n  probe<> (other): 3 bodies in 3 instances, 948 bytes\n  std::__2::deque<> (toolchain): 2 bodies in 1 instance, 180 bytes\n{NOTE}\n  assumption: {ASSUMPTION}\n"
        )),
        "{text}"
    );
    assert!(!text.contains("probe<f::$_0>: 1 body"), "{text}");
    let ownership = text.find("ownership:").unwrap();
    let stems = text.find(HEADING).unwrap();
    let holders = text.find("toolchain holders").unwrap();
    assert!(ownership < stems && stems < holders, "{text}");
    assert_eq!(text.matches(NOTE).count(), 1);
}

#[test]
fn verbose_text_lists_each_instance_under_its_stem() {
    let text = rendered_text(&report_of(&six_symbols()), true);

    assert!(
        text.contains(
            "  probe<> (other): 3 bodies in 3 instances, 948 bytes\n    probe<f::$_0>: 1 body, 340 bytes\n    probe<f::$_1>: 1 body, 304 bytes\n    probe<f::$_2>: 1 body, 304 bytes\n  std::__2::deque<> (toolchain): 2 bodies in 1 instance, 180 bytes\n    std::__2::deque<int>: 2 bodies, 180 bytes\n"
        ),
        "{text}"
    );
}

#[test]
fn text_caps_the_listed_stems_and_counts_the_rest() {
    let names: Vec<String> = (0..12)
        .flat_map(|index| {
            [
                format!("s{index:02}<int>()"),
                format!("s{index:02}<long>()"),
            ]
        })
        .collect();
    let entries: Vec<(&str, u64)> = names.iter().map(|name| (name.as_str(), 10)).collect();
    let text = rendered_text(&report_of(&entries), false);

    assert_eq!(text.matches(" bodies in 2 instances, 20 bytes").count(), 10);
    assert!(text.contains("\n  2 more stems\n"), "{text}");
    // Stems tie on bytes and bodies, so the name decides which are listed.
    assert!(text.contains("  s09<> (other)"), "{text}");
    assert!(!text.contains("  s10<> (other)"), "{text}");
}

#[test]
fn the_stem_statement_is_stated_in_every_format_exactly_when_stems_are_listed() {
    let report = report_of(&six_symbols());
    let json = serde_json::to_value(&report).unwrap();

    assert_eq!(
        json["name_stem_assumptions"],
        serde_json::json!([ASSUMPTION])
    );
    let csv = artifact_csv_records_of(&report, "assumption");
    let stems: Vec<&Vec<String>> = csv
        .iter()
        .filter(|record| record[column::ASSUMPTION_SCOPE] == "name_stems")
        .collect();
    assert_eq!(stems.len(), 1);
    assert_eq!(stems[0][column::ASSUMPTION], ASSUMPTION);
}

#[test]
fn csv_writes_a_record_per_stem_and_per_instance_after_the_ownership_summary() {
    let report = report_of(&six_symbols());
    let kinds: Vec<String> = artifact_csv_records(&report)
        .into_iter()
        .map(|record| record[column::RECORD_TYPE].clone())
        .collect();
    let summary = kinds.iter().position(|kind| kind == "ownership-summary");
    let first = kinds.iter().position(|kind| kind == "name-stem");
    assert_eq!(first, summary.map(|at| at + 1), "{kinds:?}");
    assert_eq!(
        &kinds[first.unwrap()..first.unwrap() + 6],
        [
            "name-stem",
            "name-stem-instance",
            "name-stem-instance",
            "name-stem-instance",
            "name-stem",
            "name-stem-instance"
        ]
    );

    let stems = artifact_csv_records_of(&report, "name-stem");
    assert_eq!(stems.len(), 2);
    assert_eq!(stems[0][column::NAME_STEM], "probe<>");
    assert_eq!(stems[0][column::STEM_PARAMETERIZED], "true");
    assert_eq!(stems[0][column::OWNER], "<global>");
    assert_eq!(stems[0][column::OWNERSHIP], "other");
    assert_eq!(stems[0][column::EMITTED_BODIES], "3");
    assert_eq!(stems[0][column::STEM_INSTANCES], "3");
    assert_eq!(stems[0][column::SIZE], "948");

    let instances = artifact_csv_records_of(&report, "name-stem-instance");
    assert_eq!(instances.len(), 4);
    assert_eq!(instances[0][column::NAME_STEM], "probe<>");
    assert_eq!(instances[0][column::OWNER], "<global>");
    assert_eq!(instances[0][column::NAME], "probe<f::$_0>");
    assert_eq!(instances[0][column::EMITTED_BODIES], "1");
    assert_eq!(instances[0][column::SIZE], "340");
    assert_eq!(instances[3][column::NAME_STEM], "std::__2::deque<>");
    assert_eq!(instances[3][column::NAME], "std::__2::deque<int>");
    assert_eq!(instances[3][column::EMITTED_BODIES], "2");
}

#[test]
fn a_declared_own_owner_relabels_its_stem_rows() {
    let report = report_of(&six_symbols());
    let declared = report.with_own_declaration(&["<global>".to_owned()]);
    let stems = stems_json(&declared);

    assert_eq!(stems.len(), 2);
    assert_eq!(stems[0]["owner"], "<global>");
    assert_eq!(stems[0]["ownership"], "own");
    // Toolchain code is not moved by a declaration.
    assert_eq!(stems[1]["ownership"], "toolchain");
    assert!(rendered_text(&declared, false).contains("  probe<> (own): 3 bodies"));
}

fn comparison_of(before: &[(&str, u64)], after: &[(&str, u64)]) -> ArtifactComparisonReport {
    symbol_comparison(symbols_of(before), symbols_of(after))
}

fn stem_deltas_json(report: &ArtifactComparisonReport) -> Vec<serde_json::Value> {
    serde_json::to_value(report).unwrap()["stem_deltas"]
        .as_array()
        .unwrap()
        .clone()
}

#[test]
fn a_signature_change_is_one_stem_delta_not_a_removal_and_an_addition() {
    let report = comparison_of(&[("foo(int)", 40)], &[("foo(unsigned int)", 44)]);
    let rows = stem_deltas_json(&report);

    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0]["stem"], "foo");
    assert_eq!(rows[0]["parameterized"], false);
    assert_eq!(rows[0]["before_bodies"], 1);
    assert_eq!(rows[0]["after_bodies"], 1);
    assert_eq!(rows[0]["delta_bytes"], 4);
    let json = serde_json::to_value(&report).unwrap();
    assert_eq!(rows[0]["owner"], json["symbol_deltas"][0]["owner"]);
    assert_eq!(rows[0]["ownership"], json["symbol_deltas"][0]["ownership"]);
}

fn probes_before() -> Vec<(&'static str, u64)> {
    PROBES.to_vec()
}

#[test]
fn removed_instances_are_counted_against_the_whole_artifact() {
    let report = comparison_of(&probes_before(), &PROBES[..1]);
    let rows = stem_deltas_json(&report);

    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0]["stem"], "probe<>");
    assert_eq!(rows[0]["parameterized"], true);
    assert_eq!(rows[0]["before_bodies"], 3);
    assert_eq!(rows[0]["after_bodies"], 1);
    assert_eq!(rows[0]["delta_bytes"], -608);
}

#[test]
fn losing_one_of_three_instances_still_yields_a_row() {
    let report = comparison_of(&probes_before(), &PROBES[..2]);
    let rows = stem_deltas_json(&report);

    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0]["before_bodies"], 3);
    assert_eq!(rows[0]["after_bodies"], 2);
    assert_eq!(rows[0]["delta_bytes"], -304);
}

#[test]
fn one_delta_with_unchanged_bodies_yields_no_row() {
    // Same identity on both sides, bytes differ in size: one paired delta.
    let before = vec![comparison_symbol(Some("foo(int)"), b"same", 40)];
    let after = vec![comparison_symbol(Some("foo(int)"), b"same", 44)];
    let report = symbol_comparison(before, after);

    assert_eq!(report.symbol_deltas.len(), 1);
    assert_eq!(stem_deltas_json(&report).len(), 0);
    // A single removal of the only body changes the count to zero, which is
    // below two on both sides.
    let report = comparison_of(&[("foo(int)", 40)], &[]);
    assert_eq!(report.symbol_deltas.len(), 1);
    assert_eq!(stem_deltas_json(&report).len(), 0);
}

#[test]
fn stem_deltas_are_ordered_by_absolute_change_then_name() {
    let report = comparison_of(
        &[("a<int>()", 10), ("a<long>()", 10)],
        &[
            ("a<char>()", 11),
            ("a<short>()", 11),
            ("b<int>()", 30),
            ("b<long>()", 30),
            ("c<int>()", 11),
            ("c<long>()", 11),
        ],
    );
    let order: Vec<(String, i64)> = stem_deltas_json(&report)
        .iter()
        .map(|row| {
            (
                row["stem"].as_str().unwrap().to_owned(),
                row["delta_bytes"].as_i64().unwrap(),
            )
        })
        .collect();
    // b +60; a is -20 +22 = +2; c +22.
    assert_eq!(
        order,
        [
            ("b<>".to_owned(), 60),
            ("c<>".to_owned(), 22),
            ("a<>".to_owned(), 2)
        ]
    );
}

#[test]
fn a_declaration_relabels_a_stem_delta_without_changing_its_bodies() {
    let report = comparison_of(&[], &[("g<int>()", 8), ("g<long>()", 9)]);
    let declared = report.with_own_declaration(&["<global>".to_owned()]);
    let rows = stem_deltas_json(&declared);

    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["ownership"], "own");
    assert_eq!(rows[0]["before_bodies"], 0);
    assert_eq!(rows[0]["after_bodies"], 2);
}

#[test]
fn comparison_text_lists_stem_deltas_after_the_ownership_delta() {
    let report = comparison_of(&probes_before(), &PROBES[..1]);
    let text = rendered_compare_text(&report);

    assert!(
        text.contains("stem delta:\n  probe<> (other): 3 -> 1 body, -608 bytes\n"),
        "{text}"
    );
    let owners = text.find("ownership delta:").unwrap();
    let stems = text.find("stem delta:").unwrap();
    let assumption = text.find("assumption:").unwrap();
    assert!(owners < stems && stems < assumption, "{text}");

    let none = comparison_of(&[("solo()", 4)], &[("solo()", 4)]);
    assert!(!rendered_compare_text(&none).contains("stem delta:"));
}

#[test]
fn comparison_text_caps_the_listed_stems_and_owners() {
    let names: Vec<String> = (0..12)
        .flat_map(|index| {
            [
                format!("s{index:02}<int>()"),
                format!("s{index:02}<long>()"),
            ]
        })
        .collect();
    let after: Vec<(&str, u64)> = names.iter().map(|name| (name.as_str(), 10)).collect();
    let text = rendered_compare_text(&comparison_of(&[], &after));

    assert!(text.contains("\n  2 more stems\n"), "{text}");
    assert_eq!(
        text.matches(" -> 2 bodies, +20 bytes").count(),
        10,
        "{text}"
    );

    let owners: Vec<String> = (0..12).map(|index| format!("lib{index:02}::f()")).collect();
    let after: Vec<(&str, u64)> = owners.iter().map(|name| (name.as_str(), 10)).collect();
    let text = rendered_compare_text(&comparison_of(&[], &after));
    assert!(text.contains("\n  2 more owners\n"), "{text}");
}

#[test]
fn comparison_csv_writes_a_stem_delta_record_after_the_owner_deltas() {
    let report = comparison_of(&probes_before(), &PROBES[..1]);
    let records = compare_csv_records(&report);
    let kinds: Vec<&str> = records
        .iter()
        .map(|record| record[compare_column::RECORD_TYPE].as_str())
        .collect();
    let last_owner = kinds
        .iter()
        .rposition(|kind| *kind == "owner-delta")
        .unwrap();
    assert_eq!(kinds[last_owner + 1], "stem-delta", "{kinds:?}");

    let record = &records[last_owner + 1];
    assert_eq!(record[compare_column::NAME_STEM], "probe<>");
    assert_eq!(record[compare_column::STEM_PARAMETERIZED], "true");
    assert_eq!(record[compare_column::OWNER], "<global>");
    assert_eq!(record[compare_column::OWNERSHIP], "other");
    assert_eq!(record[compare_column::BEFORE_BODIES], "3");
    assert_eq!(record[compare_column::AFTER_BODIES], "1");
    assert_eq!(record[compare_column::SYMBOL_SIZE_DELTA_BYTES], "-608");
}

#[test]
fn a_comparison_without_stem_changes_writes_an_empty_array() {
    let report = comparison_of(&[("solo()", 4)], &[("solo()", 4)]);
    assert_eq!(
        serde_json::to_value(&report).unwrap()["stem_deltas"],
        serde_json::json!([])
    );
}

/// Fail when a plural noun follows a count of exactly one, whichever words
/// sit between the number and the noun.
fn assert_counts_agree(text: &str) {
    const PLURALS: [&str; 17] = [
        "bytes",
        "symbols",
        "bodies",
        "members",
        "groups",
        "instances",
        "instantiations",
        "mappings",
        "sources",
        "copies",
        "owners",
        "stems",
        "heads",
        "holders",
        "entries",
        "changes",
        "units",
    ];
    const SINGULARS: [&str; 17] = [
        "byte",
        "symbol",
        "body",
        "member",
        "group",
        "instance",
        "instantiation",
        "mapping",
        "source",
        "copy",
        "owner",
        "stem",
        "head",
        "holder",
        "entry",
        "change",
        "unit",
    ];
    for line in text.lines() {
        let words: Vec<&str> = line.split_whitespace().collect();
        for (index, word) in words.iter().enumerate() {
            let number = word
                .trim_start_matches('(')
                .rsplit(['/', '+', '-'])
                .next()
                .unwrap_or_default();
            if number != "1" {
                continue;
            }
            // The noun agreeing with the count is the first plural or
            // singular noun within the next few words.
            for noun in words.iter().skip(index + 1).take(3) {
                let noun = noun.trim_end_matches([',', ')', ';', ':', '.']);
                assert!(
                    !PLURALS.contains(&noun),
                    "a count of one is followed by {noun:?}: {line}"
                );
                if SINGULARS.contains(&noun) || noun.starts_with(|c: char| c.is_ascii_digit()) {
                    break;
                }
            }
        }
    }
}

/// Every noun follows the count right before it: one of a thing is singular
/// and any other number, zero included, is plural.
#[test]
fn counts_agree_with_their_numbers() {
    // Analysis: one dead symbol, one body per instance, one stem past the cap.
    let mut artifact = artifact_of(&[("root", 4), ("dead", 6)]);
    artifact.capabilities.call_graph = true;
    artifact.symbols[0].exported = true;
    let report = ArtifactReport::from_ir(FilePath::new("fixture.wasm"), &artifact, None, None);
    let text = rendered_text(&report, false);
    assert!(text.contains("dead code definitive: 1 symbol\n"), "{text}");
    assert_counts_agree(&text);

    let verbose = rendered_text(&report_of(&six_symbols()), true);
    assert!(
        verbose.contains("probe<f::$_0>: 1 body, 340 bytes"),
        "{verbose}"
    );
    assert!(
        verbose.contains("deque<int>: 2 bodies, 180 bytes"),
        "{verbose}"
    );
    assert_counts_agree(&verbose);

    let names: Vec<String> = (0..11)
        .flat_map(|index| {
            [
                format!("s{index:02}<int>()"),
                format!("s{index:02}<long>()"),
            ]
        })
        .collect();
    let entries: Vec<(&str, u64)> = names.iter().map(|name| (name.as_str(), 10)).collect();
    let capped = rendered_text(&report_of(&entries), false);
    assert!(capped.contains("\n  1 more stem\n"), "{capped}");
    assert_counts_agree(&capped);

    // Comparison: bodies, bytes and members.
    let stems = rendered_compare_text(&comparison_of(&probes_before(), &PROBES[..1]));
    assert!(
        stems.contains("probe<> (other): 3 -> 1 body, -608 bytes\n"),
        "{stems}"
    );
    assert_counts_agree(&stems);

    let grown = rendered_compare_text(&comparison_of(&[("solo()", 4)], &[("solo()", 5)]));
    assert!(grown.contains(" +1 byte\n"), "{grown}");
    assert_counts_agree(&grown);

    let groups = rendered_compare_text(&symbol_comparison(
        symbols_of(&[("a", 10), ("b", 10)]),
        symbols_of(&[("a", 10), ("b", 10), ("c", 10)]),
    ));
    assert!(groups.contains(", +1 member\n"), "{groups}");
    assert_counts_agree(&groups);

    // The note for symbols without names counts its own entries.
    let note = " has no name; its before and after cannot be paired — compare artifacts that keep their symbol names (an unstripped symbol table or the WASM name section)\n";
    let alone = rendered_compare_text(&symbol_comparison(
        vec![comparison_symbol(None, b"nameless", 4)],
        Vec::new(),
    ));
    assert!(
        alone.contains(&format!("  note: 1 of 1 listed symbol change{note}")),
        "{alone}"
    );
    let among = rendered_compare_text(&symbol_comparison(
        vec![
            comparison_symbol(None, b"nameless", 4),
            comparison_symbol(Some("one"), b"one", 6),
            comparison_symbol(Some("two"), b"two", 8),
        ],
        Vec::new(),
    ));
    assert!(
        among.contains(&format!("  note: 1 of 3 listed symbol changes{note}")),
        "{among}"
    );
    assert_counts_agree(&alone);
    assert_counts_agree(&among);
}
