//! CSV rendering: quoting, record kinds, and the columns each one fills.

use super::*;
use crate::artifact::model::{ARTIFACT_CSV_HEADER, COMPARE_CSV_HEADER};
use crate::artifact::render::{attribution_column, stated_bytes};
use codehelion_artifact::metrics::ReportedSize;

#[test]
fn csv_quotes_delimiters_and_embedded_quotes() {
    assert_eq!(csv("plain"), "plain");
    assert_eq!(csv("a,b"), "\"a,b\"");
    assert_eq!(csv("a\"b"), "\"a\"\"b\"");
    assert_eq!(
        csv("=HYPERLINK(\"https://example.invalid\")"),
        "\"'=HYPERLINK(\"\"https://example.invalid\"\")\""
    );
    assert_eq!(csv("+SUM(1,2)"), "\"'+SUM(1,2)\"");
    assert_eq!(csv("-1+2"), "'-1+2");
    assert_eq!(csv("@command"), "'@command");
    assert_eq!(csv("\tformula"), "'\tformula");
}

/// A CSV reader gets every size category the other two formats publish.
#[test]
fn the_csv_summary_carries_every_size_category() {
    let artifact = resolved_call_graph_artifact();
    let report = ArtifactReport::from_ir(FilePath::new("fixture.wasm"), &artifact, None, None);
    let summary = artifact_csv_records_of(&report, "summary")
        .pop()
        .expect("one summary record");

    // Named for every category, so it checks every category: the one that
    // went missing before was reachable in the text and JSON views while the
    // record a consumer parses left it out, and a test naming one column
    // could not have seen that.
    let text = rendered_text(&report, false);
    let json = serde_json::to_value(&report).unwrap();
    for (category, bytes) in report.sizes.stated() {
        assert!(
            ARTIFACT_CSV_HEADER.contains(&category.key()),
            "no column carries {}",
            category.key()
        );
        let column = ARTIFACT_CSV_HEADER
            .iter()
            .position(|name| *name == category.key())
            .expect("the header was just checked to hold this name");
        assert_eq!(
            summary[column],
            stated_bytes(bytes),
            "the summary record states {}",
            category.key()
        );
        assert!(
            text.contains(&format!("  {}: {}", category.key(), stated_bytes(bytes))),
            "the text report states {}",
            category.key()
        );
        assert!(
            json["sizes"].get(category.key()).is_some(),
            "the JSON report states {}",
            category.key()
        );
    }
    assert_eq!(
        summary[column::CLONE_CONFIDENCE],
        format!("{:?}", report.sizes.clone_confidence)
    );
    assert_eq!(
        summary[column::SAVINGS_CONFIDENCE],
        format!("{:?}", report.sizes.savings_confidence)
    );
    assert_eq!(
        summary[column::CODE_SECTION_BYTES],
        report.code_section_bytes.to_string()
    );
    assert_eq!(
        summary[column::DATA_SEGMENT_BYTES],
        report.data_segment_bytes.to_string()
    );
}

/// A report exercising every kind of record the CSV can write.
///
/// Some kinds come out of the analysis and some are attached afterwards, so
/// the ones the fixture cannot produce are set on the report directly. What
/// matters is that each kind appears: a kind nothing exercises is a
/// declaration nothing checks.
fn report_of_every_record_kind() -> ArtifactReport {
    let artifact = artifact_with_a_toolchain_holder();
    let mut report = ArtifactReport::from_ir(FilePath::new("fixture.wasm"), &artifact, None, None)
        .with_correlation(Some(populated_correlation()));
    report.containment = Some(ArtifactContainment {
        max_input_bytes: 4096,
        worker_timeout_seconds: 30,
        worker_memory_limit_bytes: 8192,
        max_debug_derived_items: 4096,
    });
    report.build_variant = Some(
        BuildVariantEvidence {
            manifest_path: "build-variant.json".to_owned(),
            fingerprint: codehelion_artifact::ArtifactFingerprint::from_content(
                "artifact-build-variant",
                b"variant",
            ),
        }
        .for_report(),
    );
    report.archive_members = vec![ArchiveMemberReport {
        name: "member.o".to_owned(),
        fingerprint: "bb".repeat(16),
        offset: Some(32),
        size: Some(8),
        format: Some(BinaryFormat::Elf),
        thin: false,
        parse_error: None,
    }];
    report.import_details = vec![ImportReport {
        module: Some("env".to_owned()),
        name: Some("host".to_owned()),
        kind: codehelion_artifact::ArtifactImportKind::Function,
    }];
    report.relocation_details = vec![RelocationReport {
        section: Some(1),
        offset: 4,
        kind: "call".to_owned(),
        target: Some("cc".repeat(16)),
    }];
    report.source_maps = vec![SourceMapResolution {
        uri: "app.wasm.map".to_owned(),
        status: SourceMapResolutionStatus::Resolved {
            local_path: "dist/app.wasm.map".to_owned(),
            sources: vec!["src/app.rs".to_owned()],
            locations: Vec::new(),
        },
    }];
    report.dead_code = Some(DeadCodeReport {
        symbols: vec![artifact.symbols[0].fingerprint.to_hex()],
        definitive: true,
        assumptions: Vec::new(),
    });
    report.retained_sizes = Some(vec![RetainedSizeReport {
        symbol: artifact.symbols[0].fingerprint.to_hex(),
        retained_bytes: 4,
    }]);
    report
}

/// The fixture with `parse, fast` calling the toolchain function `strtof`,
/// which a second, unnamed function calls as well, so no single function
/// dominates it, and `malloc`, which only `parse, fast` reaches.
fn artifact_with_a_toolchain_holder() -> ArtifactIr {
    let mut artifact = resolved_call_graph_artifact();
    artifact.symbols[0].name = Some("parse, fast".to_owned());
    artifact.symbols[1].name = Some("strtof".to_owned());
    artifact
        .symbols
        .push(normalizable_symbol(30, &[1, 4], &[9]));
    artifact.symbols[2].exported = true;
    artifact.calls.push(codehelion_artifact::ArtifactCall {
        caller: artifact.symbols[2].fingerprint,
        target: Some(artifact.symbols[1].fingerprint),
        unresolved: None,
    });
    artifact
        .symbols
        .push(normalizable_symbol(40, &[1, 5], &[9]));
    artifact.symbols[3].name = Some("malloc".to_owned());
    artifact.calls.push(codehelion_artifact::ArtifactCall {
        caller: artifact.symbols[0].fingerprint,
        target: Some(artifact.symbols[3].fingerprint),
        unresolved: None,
    });
    artifact
}

/// Add an unqualified function below a toolchain entry so the holding report
/// has a nonzero absorbed total to carry through CSV.
fn artifact_with_absorbed_toolchain_code() -> ArtifactIr {
    let mut artifact = artifact_with_a_toolchain_holder();
    let second_root = artifact.symbols[2].fingerprint;
    artifact.calls.retain(|call| call.caller != second_root);
    let mut absorbed = normalizable_symbol(50, &[1, 6], &[9]);
    absorbed.name = Some("helper".to_owned());
    let absorbed_fingerprint = absorbed.fingerprint;
    artifact.symbols.push(absorbed);
    artifact.calls.push(codehelion_artifact::ArtifactCall {
        caller: artifact.symbols[1].fingerprint,
        target: Some(absorbed_fingerprint),
        unresolved: None,
    });
    artifact
}

/// No record fills a column its kind was not declared to carry, and every
/// declared kind is one this check actually meets.
///
/// The CSV is one wide row and each kind of record fills a subset of it, so
/// nothing about a row says which columns belong to it. A writer that started
/// filling a column meant for another kind would produce a document a consumer
/// reads as saying something it does not.
#[test]
fn every_csv_record_fills_only_the_columns_its_kind_declares() {
    let report = report_of_every_record_kind();
    let mut met: BTreeSet<&str> = BTreeSet::new();
    for record in artifact_csv_records(&report) {
        let kind = record[column::RECORD_TYPE].as_str();
        assert!(
            RECORD_COLUMNS.iter().any(|entry| entry.record_type == kind),
            "no columns are declared for a {kind} record"
        );
        let declared = RECORD_COLUMNS
            .iter()
            .find(|entry| entry.record_type == kind)
            .expect("the declarations were just checked to hold this kind");
        met.insert(declared.record_type);
        for (index, field) in record.iter().enumerate() {
            assert!(
                field.is_empty()
                    || EVERY_RECORD.contains(&index)
                    || declared.columns.contains(&index),
                "a {kind} record fills {}, which its kind does not carry",
                ARTIFACT_CSV_HEADER[index]
            );
        }
    }
    let unmet: Vec<&str> = RECORD_COLUMNS
        .iter()
        .map(|entry| entry.record_type)
        .filter(|kind| !met.contains(kind))
        .collect();
    assert!(
        unmet.is_empty(),
        "no record of these kinds was produced, so their columns are declared and unchecked: {unmet:?}"
    );
}

/// A named CSV column carries the quantity its name states, for every record
/// type that fills it.
#[test]
fn csv_columns_carry_the_quantity_their_name_states() {
    let artifact = resolved_call_graph_artifact();
    let report = ArtifactReport::from_ir(FilePath::new("fixture.wasm"), &artifact, None, None)
        .with_correlation(Some(populated_correlation()));
    let records = artifact_csv_records(&report);

    let attribution = records
        .iter()
        .find(|record| record[column::RECORD_TYPE] == "clone-group-attribution")
        .expect("one attribution record");
    // The text states "X / Y noncanonical members attributed"; both numbers
    // are recoverable, and neither one occupies the instantiation column.
    assert_eq!(attribution[column::MEMBERS], "2");
    assert_eq!(attribution[column::ATTRIBUTED_NONCANONICAL_MEMBERS], "1");
    assert_eq!(attribution[column::INSTANTIATIONS], "");

    let macro_origin = records
        .iter()
        .find(|record| record[column::RECORD_TYPE] == "macro-origin")
        .expect("one macro origin record");
    assert_eq!(macro_origin[column::ARTIFACT_SYMBOLS], "1");
    assert_eq!(macro_origin[column::DEFINITION_PATH_COUNT], "1");
    assert_eq!(macro_origin[column::INSTANTIATIONS], "");
    assert_eq!(macro_origin[column::TRANSLATION_UNITS], "");

    // Only a generic origin counts instantiations.
    for record in &records {
        if record[column::INSTANTIATIONS].is_empty() {
            continue;
        }
        assert!(
            record[column::RECORD_TYPE].starts_with("generic-"),
            "{record:?}"
        );
    }
    let generic = records
        .iter()
        .find(|record| record[column::RECORD_TYPE] == "generic-origin")
        .expect("one generic origin record");
    assert_eq!(generic[column::INSTANTIATIONS], "1");
    assert_eq!(generic[column::ARTIFACT_SYMBOLS], "1");
    assert_eq!(generic[column::RETAINED_BYTES], "4");
}

/// Every byte count one clone-group attribution states reaches all three
/// renderings, under the name that identifies it.
///
/// The clone-group counterpart of the artifact-wide check: three numbers of
/// three different kinds sit on one record, and a reader taking any of them by
/// position must never receive another.
#[test]
fn every_clone_group_byte_count_reaches_every_rendering() {
    let artifact = resolved_call_graph_artifact();
    let report = ArtifactReport::from_ir(FilePath::new("fixture.wasm"), &artifact, None, None)
        .with_correlation(Some(populated_correlation()));
    let record = artifact_csv_records(&report)
        .into_iter()
        .find(|record| record[column::RECORD_TYPE] == "clone-group-attribution")
        .expect("one attribution record");
    let text = rendered_text(&report, false);
    let json = serde_json::to_value(&report).unwrap();
    let attribution = &report
        .correlation
        .as_ref()
        .expect("the report carries its correlation")
        .clone_group_attributions[0];

    for (category, bytes) in attribution.stated() {
        assert!(
            ARTIFACT_CSV_HEADER.contains(&category.key()),
            "no column carries {}",
            category.key()
        );
        assert_eq!(
            record[attribution_column(category)],
            bytes.map_or_else(String::new, |bytes| bytes.to_string()),
            "the attribution record states {}",
            category.key()
        );
        assert!(
            json["correlation"]["clone_group_attributions"][0]
                .get(category.key())
                .is_some(),
            "the JSON report states {}",
            category.key()
        );
        if let Some(bytes) = bytes {
            assert!(
                text.contains(&bytes.to_string()),
                "the text report states {}",
                category.key()
            );
        }
    }
}

/// Every owner row of the table is written, carrying its class, bytes and
/// symbol count.
#[test]
fn an_owner_record_is_written_for_every_owner() {
    let artifact = artifact_with_a_toolchain_holder();
    let report = ArtifactReport::from_ir(FilePath::new("fixture.wasm"), &artifact, None, None)
        .with_own_declaration(&["<global>".to_owned()]);
    let records = artifact_csv_records_of(&report, "owner");
    assert_eq!(records.len(), report.ownership.owners.len());
    for (record, owner) in records.iter().zip(&report.ownership.owners) {
        assert_eq!(record[column::NAME], owner.key);
        assert_eq!(record[column::KIND], ownership_label(owner.ownership));
        assert_eq!(record[column::SIZE], owner.size_bytes.to_string());
        assert_eq!(record[column::ARTIFACT_SYMBOLS], owner.symbols.to_string());
    }
    let own = records
        .iter()
        .find(|record| record[column::KIND] == "own")
        .expect("the declared owner is written");
    assert_eq!(own[column::NAME], "<global>");
    assert_eq!(own[column::ARTIFACT_SYMBOLS], "1");
}

/// A holder and a shared toolchain entry each keep to the columns that name
/// what they state, and no record is written while holdings are unavailable.
#[test]
fn holding_and_shared_records_carry_held_bytes_in_their_own_columns() {
    let artifact = artifact_with_a_toolchain_holder();
    let mut report = ArtifactReport::from_ir(FilePath::new("fixture.wasm"), &artifact, None, None)
        .with_own_declaration(&["<global>".to_owned()]);

    let holding = artifact_csv_records_of(&report, "toolchain-holding")
        .pop()
        .expect("one holding record");
    assert_eq!(
        holding[column::FINGERPRINT],
        artifact.symbols[0].fingerprint.to_hex()
    );
    assert_eq!(holding[column::NAME], "parse, fast");
    assert_eq!(holding[column::KIND], "own");
    assert_eq!(
        holding[column::RETAINED_BYTES],
        artifact.symbols[3].size.to_string()
    );
    assert_eq!(holding[column::ARTIFACT_SYMBOLS], "1");
    assert_eq!(holding[column::SHARED_DEPENDENCY_BYTES], "");

    let shared = artifact_csv_records_of(&report, "toolchain-shared")
        .pop()
        .expect("one shared record");
    assert_eq!(
        shared[column::FINGERPRINT],
        artifact.symbols[1].fingerprint.to_hex()
    );
    assert_eq!(shared[column::NAME], "strtof");
    assert_eq!(shared[column::KIND], "toolchain");
    assert_eq!(
        shared[column::SHARED_DEPENDENCY_BYTES],
        artifact.symbols[1].size.to_string()
    );
    assert_eq!(shared[column::RETAINED_BYTES], "");

    report.toolchain_holdings = None;
    assert_eq!(
        artifact_csv_records_of(&report, "toolchain-holding").len(),
        0
    );
    assert_eq!(
        artifact_csv_records_of(&report, "toolchain-shared").len(),
        0
    );
    assert_eq!(
        artifact_csv_records_of(&report, "toolchain-holdings-summary").len(),
        0
    );
}

/// Symbol, ownership and toolchain records keep every identity and ownership
/// field that the JSON and text reports expose.
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one fixture checks every ownership-related CSV record"
)]
fn artifact_csv_carries_symbol_ownership_and_toolchain_details() {
    let mut artifact = artifact_with_absorbed_toolchain_code();
    let copy = codehelion_artifact::ArtifactFingerprint::from_content("copy", b"same-body");
    artifact.symbols[0].content_fingerprint = Some(copy);
    artifact.symbols[0].identity_by_order = true;
    let report = ArtifactReport::from_ir(FilePath::new("fixture.wasm"), &artifact, None, None)
        .with_own_declaration(&["<global>".to_owned(), "owner,with,comma".to_owned()]);

    let column = |name: &str| {
        ARTIFACT_CSV_HEADER
            .iter()
            .position(|candidate| *candidate == name)
            .expect("CSV header carries the requested field")
    };
    let content_fingerprint = column("content_fingerprint");
    let identity_by_order = column("identity_by_order");
    let owner = column("owner");
    let ownership = column("ownership");
    let toolchain_family = column("toolchain_family");
    let absorbed_bytes = column("absorbed_bytes");
    let absorbed_symbols = column("absorbed_symbols");
    let root = column("root");
    let outside_symbols_bytes = column("outside_symbols_bytes");
    let declared_own_json = column("declared_own_json");
    let holder_fingerprint = column("holder_fingerprint");
    let head_fingerprint = column("head_fingerprint");
    let shared_bytes = column("shared_bytes");
    let shared_symbols = column("shared_symbols");
    let shared_absorbed_bytes = column("shared_absorbed_bytes");
    let shared_absorbed_symbols = column("shared_absorbed_symbols");

    let symbols = artifact_csv_records_of(&report, "symbol");
    let symbol = symbols
        .iter()
        .find(|record| record[column("name")] == "parse, fast")
        .expect("the symbol record is written");
    assert_eq!(symbol[content_fingerprint], copy.to_hex());
    assert_eq!(symbol[identity_by_order], "true");
    assert_eq!(symbol[owner], "<global>");
    assert_eq!(symbol[ownership], "own");
    assert_eq!(
        symbol[column("offset")],
        artifact.symbols[0].offset.to_string()
    );
    assert_eq!(symbol[column("size")], artifact.symbols[0].size.to_string());

    let ownership_summary = artifact_csv_records_of(&report, "ownership-summary")
        .pop()
        .expect("the ownership summary record is written");
    assert_eq!(
        ownership_summary[outside_symbols_bytes],
        report.ownership.outside_symbols_bytes.to_string()
    );
    assert_eq!(
        ownership_summary[declared_own_json],
        serde_json::to_string(&report.ownership.declared_own).unwrap()
    );
    assert!(
        ownership_summary[declared_own_json].contains(','),
        "the declaration list must exercise CSV quoting"
    );

    let owner_record = artifact_csv_records_of(&report, "owner")
        .into_iter()
        .find(|record| record[column("name")] == "c-std")
        .expect("the c-std owner record is written");
    assert_eq!(owner_record[toolchain_family], "c_std");

    let holding_model = &report.toolchain_holdings.as_ref().unwrap().holdings[0];
    let holding = artifact_csv_records_of(&report, "toolchain-holding")
        .pop()
        .expect("the holding record is written");
    assert_eq!(
        holding[absorbed_bytes],
        holding_model.absorbed_bytes.to_string()
    );
    assert_eq!(
        holding[absorbed_symbols],
        holding_model.absorbed_symbols.to_string()
    );
    assert_ne!(holding[absorbed_bytes], "0");
    assert_ne!(holding[absorbed_symbols], "0");

    let head = artifact_csv_records_of(&report, "toolchain-head")
        .into_iter()
        .find(|record| record[column("name")] == "strtof")
        .expect("the head record is written");
    assert_eq!(
        head[column("fingerprint")],
        artifact.symbols[1].fingerprint.to_hex()
    );
    assert_eq!(head[column("name")], "strtof");
    assert_eq!(
        head[column("retained_bytes")],
        report.toolchain_holdings.as_ref().unwrap().holdings[0].heads[0]
            .held_bytes
            .to_string()
    );
    assert_eq!(head[holder_fingerprint], holding_model.holder);

    let shared_report = ArtifactReport::from_ir(
        FilePath::new("fixture.wasm"),
        &artifact_with_a_toolchain_holder(),
        None,
        None,
    )
    .with_own_declaration(&["<global>".to_owned()]);
    let shared_model = &shared_report.toolchain_holdings.as_ref().unwrap().shared[0];
    let shared = artifact_csv_records_of(&shared_report, "toolchain-shared")
        .pop()
        .expect("the shared record is written");
    assert_eq!(shared[root], shared_model.root.to_string());

    let caller = artifact_csv_records_of(&shared_report, "toolchain-caller")
        .into_iter()
        .find(|record| record[column("name")] == "parse, fast")
        .expect("the caller record is written");
    assert_eq!(
        caller[column("fingerprint")],
        artifact.symbols[0].fingerprint.to_hex()
    );
    assert_eq!(caller[column("kind")], "own");
    assert_eq!(caller[head_fingerprint], shared_model.symbol.clone());

    let holdings_summary = artifact_csv_records_of(&shared_report, "toolchain-holdings-summary")
        .pop()
        .expect("the holdings summary record is written");
    let shared_holdings = shared_report.toolchain_holdings.as_ref().unwrap();
    assert_eq!(
        holdings_summary[shared_bytes],
        shared_holdings.shared_bytes.to_string()
    );
    assert_eq!(
        holdings_summary[shared_symbols],
        shared_holdings.shared_symbols.to_string()
    );
    assert_eq!(
        holdings_summary[shared_absorbed_bytes],
        shared_holdings.shared_absorbed_bytes.to_string()
    );
    assert_eq!(
        holdings_summary[shared_absorbed_symbols],
        shared_holdings.shared_absorbed_symbols.to_string()
    );
}

/// Comparison CSV keeps the owner split on symbol rows and the uncovered code
/// delta on its summary row.
#[test]
fn comparison_csv_carries_symbol_ownership_and_outside_delta() {
    let mut before = resolved_call_graph_artifact();
    before.symbols[0].name = Some("parse, fast".to_owned());
    let mut after = before.clone();
    after.symbols[0].size += 2;
    let report = ArtifactComparisonReport::new(
        FilePath::new("before.wasm"),
        &before,
        None,
        FilePath::new("after.wasm"),
        &after,
        None,
    );
    let column = |name: &str| {
        COMPARE_CSV_HEADER
            .iter()
            .position(|candidate| *candidate == name)
            .expect("comparison CSV header carries the requested field")
    };
    let symbol = compare_csv_records(&report)
        .into_iter()
        .find(|record| record[compare_column::RECORD_TYPE] == "symbol-delta")
        .expect("the symbol delta record is written");
    assert_eq!(symbol[column("owner")], "<global>");
    assert_eq!(symbol[column("ownership")], "other");
    let summary = compare_csv_records(&report)
        .into_iter()
        .find(|record| record[compare_column::RECORD_TYPE] == "summary")
        .expect("the summary record is written");
    assert_eq!(
        summary[column("outside_symbols_delta_bytes")],
        report
            .ownership_deltas
            .outside_symbols_delta_bytes
            .to_string()
    );
}

/// Each owner whose bytes moved is one comparison record naming its class.
#[test]
fn an_owner_delta_record_is_written_for_every_changed_owner() {
    let report = ArtifactComparisonReport::new(
        FilePath::new("before.wasm"),
        &resolved_call_graph_artifact(),
        None,
        FilePath::new("after.wasm"),
        &{
            let mut after = resolved_call_graph_artifact();
            after.symbols[0].size += 2;
            after
        },
        None,
    );
    assert!(!report.ownership_deltas.owners.is_empty());
    let records: Vec<_> = compare_csv_records(&report)
        .into_iter()
        .filter(|record| record[compare_column::RECORD_TYPE] == "owner-delta")
        .collect();
    assert_eq!(records.len(), report.ownership_deltas.owners.len());
    for (record, owner) in records.iter().zip(&report.ownership_deltas.owners) {
        assert_eq!(
            record[compare_column::CHANGE_KIND],
            ownership_label(owner.ownership)
        );
        assert_eq!(record[compare_column::NAME], owner.key);
        assert_eq!(
            record[compare_column::SYMBOL_SIZE_DELTA_BYTES],
            owner.delta_bytes.to_string()
        );
    }
}
