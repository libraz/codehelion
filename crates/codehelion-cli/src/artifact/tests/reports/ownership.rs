//! Owner labels and toolchain holders through the artifact reports.

use super::*;

/// A WASM module exporting `parse`, which calls `strtof`, which calls
/// `strtox`, which calls `__addtf3`, all named in the name section.
///
/// `padding` inserts that many `nop` instructions into `parse`, so two builds
/// differ in one body.
fn toolchain_chain_module(padding: usize) -> Vec<u8> {
    fn section(id: u8, content: &[u8]) -> Vec<u8> {
        let mut bytes = vec![id, u8::try_from(content.len()).unwrap()];
        bytes.extend_from_slice(content);
        bytes
    }
    fn body(instructions: &[u8]) -> Vec<u8> {
        let mut bytes = vec![u8::try_from(instructions.len() + 1).unwrap(), 0];
        bytes.extend_from_slice(instructions);
        bytes
    }
    let mut parse = vec![0x01; padding];
    parse.extend_from_slice(&[0x10, 1, 0x0b]);
    let mut code = vec![4];
    code.extend(body(&parse));
    code.extend(body(&[0x10, 2, 0x0b]));
    code.extend(body(&[0x10, 3, 0x0b]));
    code.extend(body(&[0x0b]));
    let mut names = vec![4];
    for (index, name) in ["parse", "strtof", "strtox", "__addtf3"]
        .into_iter()
        .enumerate()
    {
        names.push(u8::try_from(index).unwrap());
        names.push(u8::try_from(name.len()).unwrap());
        names.extend_from_slice(name.as_bytes());
    }
    let mut custom = vec![4];
    custom.extend_from_slice(b"name");
    custom.extend(section(1, &names));

    let mut module = b"\0asm\x01\0\0\0".to_vec();
    module.extend(section(1, &[1, 0x60, 0, 0]));
    module.extend(section(3, &[4, 0, 0, 0, 0]));
    module.extend(section(7, &[1, 5, b'p', b'a', b'r', b's', b'e', 0, 0]));
    module.extend(section(10, &code));
    module.extend(section(0, &custom));
    module
}

/// The fingerprint the report gives the symbol named `name`.
fn fingerprint_of(json: &serde_json::Value, name: &str) -> String {
    json["symbols"]
        .as_array()
        .unwrap()
        .iter()
        .find(|symbol| symbol["name"] == name)
        .unwrap()["fingerprint"]
        .as_str()
        .unwrap()
        .to_owned()
}

/// `(ownership, size_bytes, symbols)` of every class, in report order.
fn class_totals(json: &serde_json::Value) -> Vec<(String, u64, u64)> {
    json["ownership"]["classes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|class| {
            (
                class["ownership"].as_str().unwrap().to_owned(),
                class["size_bytes"].as_u64().unwrap(),
                class["symbols"].as_u64().unwrap(),
            )
        })
        .collect()
}

fn class(ownership: &str, size_bytes: u64, symbols: u64) -> (String, u64, u64) {
    (ownership.to_owned(), size_bytes, symbols)
}

/// The toolchain chain below an exported function is held by that function:
/// `strtof` and `__addtf3` by name, `strtox` by absorption. Declaring
/// `<global>` own moves the unqualified functions into own and leaves the
/// holder where it was.
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one chain is followed from the analysis through the declaration to the text"
)]
fn a_toolchain_chain_is_held_by_its_caller() {
    let artifact = WasmBackend.parse(&toolchain_chain_module(0)).unwrap();
    let report = ArtifactReport::from_ir(FilePath::new("chain.wasm"), &artifact, None, None);
    let json = serde_json::to_value(&report).unwrap();
    assert_no_raw_bytes(&json, "report");

    let parse = fingerprint_of(&json, "parse");
    let strtof = fingerprint_of(&json, "strtof");
    let owners: Vec<(&str, &str)> = json["symbols"]
        .as_array()
        .unwrap()
        .iter()
        .map(|symbol| {
            (
                symbol["owner"].as_str().unwrap(),
                symbol["ownership"].as_str().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        owners,
        [
            ("<global>", "other"),
            ("c-std", "toolchain"),
            ("<global>", "other"),
            ("reserved", "toolchain"),
        ]
    );

    // Bodies are 4, 4, 4 and 2 bytes; the code section adds a count byte and
    // one size byte per body.
    let ownership = &json["ownership"];
    assert_eq!(ownership["declared_own"], serde_json::json!([]));
    assert_eq!(
        class_totals(&json),
        [
            class("own", 0, 0),
            class("toolchain", 6, 2),
            class("other", 8, 2),
            class("unnamed", 0, 0),
        ]
    );
    assert_eq!(
        ownership["owners"],
        serde_json::json!([
            { "key": "<global>", "ownership": "other", "family": null, "size_bytes": 8, "symbols": 2 },
            { "key": "c-std", "ownership": "toolchain", "family": "c_std", "size_bytes": 4, "symbols": 1 },
            { "key": "reserved", "ownership": "toolchain", "family": "reserved", "size_bytes": 2, "symbols": 1 },
        ])
    );
    assert_eq!(ownership["outside_symbols_bytes"], 5);
    assert_eq!(
        ownership["assumptions"],
        serde_json::json!([
            "ownership follows the defining path of each symbol name, so generic code instantiated for your types is counted under the library that defines it",
            "no own owners are declared in [artifact] own, so named code outside the toolchain is reported as other",
        ])
    );

    let holdings = &json["toolchain_holdings"];
    assert_eq!(
        holdings["holdings"],
        serde_json::json!([{
            "holder": parse,
            "holder_name": "parse",
            "holder_ownership": "other",
            "held_bytes": 10,
            "held_symbols": 3,
            "absorbed_bytes": 4,
            "absorbed_symbols": 1,
            "heads": [{ "symbol": strtof, "name": "strtof", "held_bytes": 10 }],
        }])
    );
    assert_eq!(holdings["shared"], serde_json::json!([]));
    assert_eq!(holdings["shared_bytes"], 0);
    assert_eq!(holdings["shared_symbols"], 0);
    assert!(
        holdings["assumptions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value
                .as_str()
                .unwrap()
                .starts_with("unqualified functions reached only through toolchain code")),
        "{holdings}"
    );
    assert_valid_schema(
        "https://github.com/libraz/codehelion/blob/main/crates/codehelion-cli/schema/artifact-report-v2.schema.json",
        ARTIFACT_REPORT_JSON_SCHEMA,
        &json,
    );

    let declared = report.with_own_declaration(&["<global>".to_owned()]);
    let json = serde_json::to_value(&declared).unwrap();
    assert_eq!(
        json["ownership"]["declared_own"],
        serde_json::json!(["<global>"])
    );
    assert_eq!(
        class_totals(&json),
        [
            class("own", 8, 2),
            class("toolchain", 6, 2),
            class("other", 0, 0),
            class("unnamed", 0, 0),
        ]
    );
    assert_eq!(json["ownership"]["owners"][0]["ownership"], "own");
    assert_eq!(json["symbols"][0]["ownership"], "own");
    assert_eq!(json["symbols"][2]["ownership"], "own");
    assert_eq!(
        json["ownership"]["assumptions"],
        serde_json::json!([
            "ownership follows the defining path of each symbol name, so generic code instantiated for your types is counted under the library that defines it",
        ])
    );
    let holding = &json["toolchain_holdings"]["holdings"][0];
    assert_eq!(holding["holder"], parse);
    assert_eq!(holding["holder_ownership"], "own");
    assert_eq!(holding["held_symbols"], 3);
    assert_eq!(holding["absorbed_symbols"], 1);
    assert_valid_schema(
        "https://github.com/libraz/codehelion/blob/main/crates/codehelion-cli/schema/artifact-report-v2.schema.json",
        ARTIFACT_REPORT_JSON_SCHEMA,
        &json,
    );

    let text = rendered_text(&declared, false);
    assert!(
        text.contains(
            "ownership: own 8 bytes (2 symbols), toolchain 6 bytes (2 symbols), other 0 bytes (0 symbols), unnamed 0 bytes (0 symbols)"
        ),
        "{text}"
    );
    assert!(text.contains("  outside symbols: 5 bytes"), "{text}");
    assert!(
        text.contains(&format!(
            "  parse (own) {parse}: 10 bytes in 3 symbols, 4 bytes in 1 symbols absorbed"
        )),
        "{text}"
    );
    assert!(
        text.contains(&format!("    head strtof {strtof}: 10 bytes")),
        "{text}"
    );
}

/// An empty declaration changes nothing, so a run without `[artifact] own`
/// renders exactly what the report computed.
#[test]
fn an_empty_own_declaration_leaves_the_report_unchanged() {
    let artifact = WasmBackend.parse(&toolchain_chain_module(0)).unwrap();
    let report = ArtifactReport::from_ir(FilePath::new("chain.wasm"), &artifact, None, None);
    let before = serde_json::to_value(&report).unwrap();
    let after = serde_json::to_value(report.with_own_declaration(&[])).unwrap();
    assert_eq!(before, after);
}

/// A body that grows by two bytes moves the class it belongs to by two bytes,
/// and every code byte lands in exactly one class or outside the symbols.
#[test]
fn a_comparison_splits_the_code_delta_by_owner_class() {
    let before = WasmBackend.parse(&toolchain_chain_module(0)).unwrap();
    let after = WasmBackend.parse(&toolchain_chain_module(2)).unwrap();
    let report = ArtifactComparisonReport::new(
        FilePath::new("before.wasm"),
        &before,
        None,
        FilePath::new("after.wasm"),
        &after,
        None,
    );
    let json = serde_json::to_value(&report).unwrap();
    assert_no_raw_bytes(&json, "comparison");

    // The fingerprint covers the body, so `parse` is a removal and an addition.
    let deltas: Vec<(&str, &str, &str, &str, i64)> = json["symbol_deltas"]
        .as_array()
        .unwrap()
        .iter()
        .map(|delta| {
            (
                delta["kind"].as_str().unwrap(),
                delta["name"].as_str().unwrap(),
                delta["owner"].as_str().unwrap(),
                delta["ownership"].as_str().unwrap(),
                delta["size_delta_bytes"].as_i64().unwrap(),
            )
        })
        .collect();
    assert_eq!(deltas.len(), 2, "{deltas:?}");
    assert!(deltas.contains(&("added", "parse", "<global>", "other", 6)));
    assert!(deltas.contains(&("removed", "parse", "<global>", "other", -4)));

    let ownership = &json["ownership_deltas"];
    assert_eq!(
        ownership["classes"],
        serde_json::json!([
            { "ownership": "own", "delta_bytes": 0 },
            { "ownership": "toolchain", "delta_bytes": 0 },
            { "ownership": "other", "delta_bytes": 2 },
            { "ownership": "unnamed", "delta_bytes": 0 },
        ])
    );
    assert_eq!(
        ownership["owners"],
        serde_json::json!([{ "key": "<global>", "ownership": "other", "delta_bytes": 2 }])
    );
    assert_eq!(json["code_section_delta_bytes"], 2);
    assert_eq!(ownership["outside_symbols_delta_bytes"], 0);
    let classes: i64 = ownership["classes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|class| class["delta_bytes"].as_i64().unwrap())
        .sum();
    let symbols: i64 = deltas.iter().map(|delta| delta.4).sum();
    assert_eq!(classes, symbols);
    assert!(
        report.assumptions.iter().any(|value| value
            == "no own owners are declared in [artifact] own, so named code outside the toolchain is reported as other"),
        "{:?}",
        report.assumptions
    );
    assert_valid_schema(
        "https://github.com/libraz/codehelion/blob/main/crates/codehelion-cli/schema/artifact-comparison-report-v2.schema.json",
        ARTIFACT_COMPARISON_REPORT_JSON_SCHEMA,
        &json,
    );

    let declared = report.with_own_declaration(&["<global>".to_owned()]);
    let json = serde_json::to_value(&declared).unwrap();
    assert_eq!(
        json["ownership_deltas"]["classes"][0],
        serde_json::json!({ "ownership": "own", "delta_bytes": 2 })
    );
    assert_eq!(
        json["ownership_deltas"]["owners"],
        serde_json::json!([{ "key": "<global>", "ownership": "own", "delta_bytes": 2 }])
    );
    assert!(
        json["symbol_deltas"]
            .as_array()
            .unwrap()
            .iter()
            .all(|delta| delta["ownership"] == "own")
    );
    assert!(
        !declared
            .assumptions
            .iter()
            .any(|value| value.starts_with("no own owners are declared")),
        "{:?}",
        declared.assumptions
    );
    let text = rendered_compare_text(&declared);
    assert!(
        text.contains(
            "ownership delta: own +2 bytes, toolchain +0 bytes, other +0 bytes, unnamed +0 bytes"
        ),
        "{text}"
    );
    assert!(text.contains("  <global> (own): +2 bytes"), "{text}");
    assert!(text.contains("  outside symbols: +0 bytes"), "{text}");
}

/// Holders and owners beyond the text caps are left to the JSON output, and
/// text says how many it left out.
#[test]
fn text_lists_the_largest_owners_and_says_how_many_it_left_out() {
    let mut artifact = resolved_call_graph_artifact();
    artifact.symbols = (0..12_u64)
        .map(|index| {
            let mut symbol = normalizable_symbol(100 + index, &[1, 2], &[9]);
            symbol.name = Some(format!("crate{index:02}::f"));
            symbol
        })
        .collect();
    let report = ArtifactReport::from_ir(FilePath::new("owners.wasm"), &artifact, None, None);
    assert_eq!(report.ownership.owners.len(), 12);
    let text = rendered_text(&report, false);
    let listed = text
        .lines()
        .filter(|line| line.starts_with("  crate") && line.contains("(other)"))
        .count();
    assert_eq!(listed, 10, "{text}");
    assert!(text.contains("  2 more owners"), "{text}");
}

/// Without retained sizes there are no holders, and the line saying so does
/// not repeat the reason the retained-size line already gave.
#[test]
fn unavailable_holders_point_at_the_retained_size_conditions() {
    let mut artifact = resolved_call_graph_artifact();
    artifact.symbols[1].fingerprint = artifact.symbols[0].fingerprint;
    let report = ArtifactReport::from_ir(FilePath::new("fixture.wasm"), &artifact, None, None);
    assert!(report.toolchain_holdings.is_none());
    let json = serde_json::to_value(&report).unwrap();
    assert!(json["toolchain_holdings"].is_null());
    let text = rendered_text(&report, false);
    assert!(
        text.contains("toolchain holders: unavailable (same conditions as retained sizes)"),
        "{text}"
    );
    assert_eq!(
        text.lines()
            .filter(|line| line.contains("one symbol per content fingerprint"))
            .count(),
        1,
        "{text}"
    );
}
