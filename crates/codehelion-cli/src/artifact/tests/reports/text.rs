//! Human-readable rendering: duplicates, reachability, and archive members.

use super::*;

#[test]
fn text_report_says_when_normalized_duplicates_are_unavailable() {
    let artifact = ArtifactIr::empty(BinaryFormat::Elf, b"fixture");
    let report = ArtifactReport::from_ir(FilePath::new("fixture.so"), &artifact, None, None);
    let mut text = Vec::new();

    render_text(&report, false, &mut text).unwrap();

    let text = String::from_utf8(text).unwrap();
    assert!(text.contains("normalized unavailable (no normalizer for this architecture)"));
    // The size categories say the same thing in the same words rather than
    // printing a zero that reads as "none found".
    assert!(
        text.contains("duplicated_bytes_normalized: unavailable"),
        "{text}"
    );
}

/// The size categories report the same normalized total the duplicate listing
/// does, each naming the evidence behind it.
///
/// The two blocks are read by different readers — one came for the groups, one
/// came for the size — and only one of them saw the larger number.
#[test]
fn size_categories_report_the_same_normalized_total_the_duplicate_listing_does() {
    let mut artifact = ArtifactIr::empty(BinaryFormat::Wasm, b"fixture");
    artifact.capabilities.normalized_duplicates = true;
    artifact.observed_bytes = 100;
    artifact.symbols = vec![
        normalizable_symbol(10, &[1, 2], &[9]),
        normalizable_symbol(20, &[1, 3], &[9]),
        normalizable_symbol(30, &[1, 4], &[9]),
    ];
    let report = ArtifactReport::from_ir(FilePath::new("fixture.wasm"), &artifact, None, None);
    let mut text = Vec::new();

    render_text(&report, false, &mut text).unwrap();

    let text = String::from_utf8(text).unwrap();
    let normalized = report.duplicates.normalized_duplicated_bytes;
    assert!(normalized > 0, "the fixture normalizes to one group");
    assert_eq!(report.sizes.duplicated_bytes_normalized, Some(normalized));
    assert!(
        text.contains(&format!(
            "duplicated_bytes_normalized: {normalized} (weaker evidence: equal after normalization)"
        )),
        "{text}"
    );
    assert!(
        text.contains("duplicated_bytes: 0 (byte-identical groups only)"),
        "{text}"
    );
    // The observation stays out of the bound that claims to be one.
    assert_eq!(report.sizes.upper_bound_savings_bytes, Some(0));
}

#[test]
fn text_report_calls_duplicate_bytes_observed_not_savings() {
    let artifact = WasmBackend.parse(b"\0asm\x01\0\0\0").unwrap();
    let report =
        ArtifactReport::from_ir(std::path::Path::new("fixture.wasm"), &artifact, None, None);
    let mut text = Vec::new();
    render_text(&report, false, &mut text).unwrap();
    let text = String::from_utf8(text).unwrap();
    for category in [
        "observed_bytes",
        "duplicated_bytes",
        "retained_bytes",
        "shared_dependency_bytes",
        "duplicated_data_bytes",
        "upper_bound_savings_bytes",
        "estimated_refactor_savings_bytes",
        "verified_savings_bytes",
    ] {
        assert!(
            text.contains(category),
            "missing {category} from text report"
        );
    }
    assert!(text.contains("observed duplicate bytes"));
    assert!(text.contains("upper bound, not guaranteed"));
    assert!(text.contains("estimated_refactor_savings_bytes: unavailable"));
    assert!(text.contains("clone_confidence: High"));
    assert!(text.contains("savings_confidence: Unavailable"));
    let json = serde_json::to_value(&report).unwrap();
    assert_eq!(json["schema_version"], ARTIFACT_REPORT_SCHEMA_VERSION);
    for category in [
        "observed_bytes",
        "duplicated_bytes",
        "retained_bytes",
        "shared_dependency_bytes",
        "duplicated_data_bytes",
        "upper_bound_savings_bytes",
        "estimated_refactor_savings_bytes",
        "verified_savings_bytes",
        "clone_confidence",
        "savings_confidence",
        "assumptions",
    ] {
        assert!(
            json["sizes"].get(category).is_some(),
            "missing {category} from JSON report"
        );
    }

    let mut csv = Vec::new();
    render_csv(&report, &mut csv).unwrap();
    let csv = String::from_utf8(csv).unwrap();
    let mut lines = csv.lines();
    let header = artifact_csv_fields(lines.next().unwrap());
    let summary = artifact_csv_fields(lines.next().unwrap());
    assert_eq!(header.len(), summary.len());
    for (field, expected) in [
        ("observed_bytes", "8"),
        ("duplicated_bytes", "0"),
        ("upper_bound_savings_bytes", "0"),
        ("estimated_refactor_savings_bytes", "unavailable"),
        ("verified_savings_bytes", "unavailable"),
    ] {
        let index = header.iter().position(|value| *value == field).unwrap();
        assert_eq!(summary[index], expected, "unexpected {field} value");
    }
}

#[test]
fn report_keeps_duplicate_group_members_without_emitting_code() {
    let mut artifact = WasmBackend.parse(b"\0asm\x01\0\0\0").unwrap();
    artifact.symbols = [10_u64, 20]
        .into_iter()
        .map(|offset| codehelion_artifact::ArtifactSymbol {
            fingerprint: codehelion_artifact::ArtifactFingerprint::from_content(
                "symbol",
                &offset.to_le_bytes(),
            ),
            name: None,
            exported: false,
            section: None,
            offset,
            size: 2,
            size_inferred: false,
            code: vec![1, 2],
            normalized: None,
            body_fingerprint: None,
            inline_stack: Vec::new(),
            content_fingerprint: None,
            identity_by_order: false,
        })
        .collect();
    artifact.symbols[0].exported = true;
    artifact.capabilities.call_graph = true;
    let report =
        ArtifactReport::from_ir(std::path::Path::new("fixture.wasm"), &artifact, None, None);
    assert_eq!(report.duplicate_groups.exact.len(), 1);
    let mut text = Vec::new();
    render_text(&report, false, &mut text).unwrap();
    let text = String::from_utf8(text).unwrap();
    assert!(text.contains("exact duplicate groups:"));
    assert!(text.contains("offset 10 size 2"));
    assert!(text.contains("dead code definitive: 1 symbol"));
    assert!(!text.contains("[1, 2]"));
    let mut csv = Vec::new();
    render_csv(&report, &mut csv).unwrap();
    let csv = String::from_utf8(csv).unwrap();
    assert!(csv.contains("duplicate-group,fixture.wasm,wasm,exact,"));
    assert!(csv.contains("duplicate-member,fixture.wasm,wasm,exact,"));
    assert!(csv.contains("dead-code,fixture.wasm,wasm,"));
    let mut rows = csv.lines();
    let columns = artifact_csv_fields(rows.next().unwrap()).len();
    let widths: Vec<_> = rows.map(|row| artifact_csv_fields(row).len()).collect();
    assert_eq!(widths, vec![columns; widths.len()]);
}

/// Reachability follows content-derived identities, so an unreachable function
/// with an exported byte-identical twin disappears into it. The report may not
/// call that answer definitive.
#[test]
fn dead_code_is_a_candidate_list_when_two_symbols_share_one_fingerprint() {
    let mut artifact = WasmBackend.parse(b"\0asm\x01\0\0\0").unwrap();
    artifact.capabilities.call_graph = true;
    artifact.symbols = [true, false]
        .into_iter()
        .enumerate()
        .map(|(index, exported)| codehelion_artifact::ArtifactSymbol {
            fingerprint: codehelion_artifact::ArtifactFingerprint::from_content("symbol", b"same"),
            name: None,
            exported,
            section: None,
            offset: index as u64 * 4,
            size: 2,
            size_inferred: false,
            code: vec![1, 2],
            normalized: None,
            body_fingerprint: None,
            inline_stack: Vec::new(),
            content_fingerprint: None,
            identity_by_order: false,
        })
        .collect();

    let report =
        ArtifactReport::from_ir(std::path::Path::new("fixture.wasm"), &artifact, None, None);

    let dead_code = report.dead_code.as_ref().expect("an exported root exists");
    assert!(!dead_code.definitive);
    assert!(
        dead_code
            .assumptions
            .iter()
            .any(|assumption| assumption.contains("share one content fingerprint")),
        "{:?}",
        dead_code.assumptions
    );
    let mut text = Vec::new();
    render_text(&report, false, &mut text).unwrap();
    let text = String::from_utf8(text).unwrap();
    assert!(text.contains("dead code candidates:"), "{text}");
    assert!(!text.contains("dead code definitive:"), "{text}");
}

/// A call whose endpoint is not one of the artifact's symbols leaves the same
/// graph incomplete, and an incomplete graph proves nothing unreachable.
#[test]
fn dead_code_is_a_candidate_list_when_a_call_endpoint_matches_no_symbol() {
    let mut artifact = WasmBackend.parse(b"\0asm\x01\0\0\0").unwrap();
    artifact.capabilities.call_graph = true;
    artifact.symbols = vec![codehelion_artifact::ArtifactSymbol {
        fingerprint: codehelion_artifact::ArtifactFingerprint::from_content("symbol", b"root"),
        name: None,
        exported: true,
        section: None,
        offset: 0,
        size: 2,
        size_inferred: false,
        code: vec![1, 2],
        normalized: None,
        body_fingerprint: None,
        inline_stack: Vec::new(),
        content_fingerprint: None,
        identity_by_order: false,
    }];
    artifact.calls.push(codehelion_artifact::ArtifactCall {
        caller: artifact.symbols[0].fingerprint,
        target: Some(codehelion_artifact::ArtifactFingerprint::from_content(
            "symbol", b"absent",
        )),
        unresolved: None,
    });

    let report =
        ArtifactReport::from_ir(std::path::Path::new("fixture.wasm"), &artifact, None, None);

    let dead_code = report.dead_code.as_ref().expect("an exported root exists");
    assert!(!dead_code.definitive);
    assert!(
        dead_code
            .assumptions
            .iter()
            .any(|assumption| assumption.contains("matches no symbol")),
        "{:?}",
        dead_code.assumptions
    );
}

/// An archive keeps no call graph, so a report over one with equal member
/// identities offers no reachability answer at all.
#[test]
fn an_archive_with_repeated_member_identities_reports_no_reachability() {
    let mut archive = ArtifactIr::empty(BinaryFormat::Archive, b"archive");
    let fingerprint =
        codehelion_artifact::ArtifactFingerprint::from_content("archive-member", b"member");
    archive.archive_members = ["first.o", "second.o"]
        .into_iter()
        .map(|name| codehelion_artifact::ArtifactArchiveMember {
            name: name.to_owned(),
            fingerprint,
            offset: Some(32),
            size: Some(8),
            format: Some(BinaryFormat::Elf),
            thin: false,
            parse_error: None,
        })
        .collect();

    let report = ArtifactReport::from_ir(FilePath::new("fixture.a"), &archive, None, None);

    assert!(report.dead_code.is_none());
    let mut text = Vec::new();
    render_text(&report, false, &mut text).unwrap();
    // The reason names the condition that actually held: an archive carries no
    // call edges at all, which is not the same as carrying no roots.
    assert!(
        String::from_utf8(text)
            .unwrap()
            .contains("dead code: unavailable (this format backend establishes no call edges)")
    );
}

#[test]
fn archive_report_retains_member_failures_without_raw_member_bytes() {
    let mut archive = ArtifactIr::empty(BinaryFormat::Archive, b"archive");
    archive
        .archive_members
        .push(codehelion_artifact::ArtifactArchiveMember {
            name: "thin-member.o".to_owned(),
            fingerprint: codehelion_artifact::ArtifactFingerprint::from_content(
                "archive-member",
                b"member",
            ),
            offset: None,
            size: None,
            format: Some(BinaryFormat::Elf),
            thin: true,
            parse_error: Some("external member paths are not followed".to_owned()),
        });

    let report = ArtifactReport::from_ir(FilePath::new("fixture.a"), &archive, None, None);
    let json = serde_json::to_value(&report).unwrap();
    assert_eq!(json["archive_members"][0]["name"], "thin-member.o");
    assert_eq!(json["archive_members"][0]["thin"], true);
    // A member the archive only names has no position in it and no observed
    // length, and the document says so rather than putting a zero where a
    // measurement goes.
    assert!(json["archive_members"][0]["offset"].is_null());
    assert!(json["archive_members"][0]["size"].is_null());
    assert!(
        json["archive_members"][0]["parse_error"]
            .as_str()
            .unwrap()
            .contains("not followed")
    );
    let mut text = Vec::new();
    render_text(&report, false, &mut text).unwrap();
    assert!(
        String::from_utf8(text)
            .unwrap()
            .contains("archive members: 0 parsed, 1 unavailable")
    );
    let mut csv = Vec::new();
    render_csv(&report, &mut csv).unwrap();
    let csv = String::from_utf8(csv).unwrap();
    assert!(csv.contains("archive-member,fixture.a,archive,elf"));
    assert!(csv.contains("thin-member.o"));
    assert!(csv.contains("external member paths are not followed"));
}

/// The ownership table and the holders follow the retained sizes, with the
/// unnamed-symbol caveat under the table that counted them.
#[test]
fn text_reports_ownership_classes_and_toolchain_holders() {
    let artifact = resolved_call_graph_artifact();
    let report = ArtifactReport::from_ir(FilePath::new("fixture.wasm"), &artifact, None, None);
    let text = rendered_text(&report, false);
    assert!(
        text.contains(
            "ownership: own 0 bytes (0 symbols), toolchain 0 bytes (0 symbols), other 0 bytes (0 symbols), unnamed 4 bytes (2 symbols)"
        ),
        "{text}"
    );
    // The unnamed class has one key, so no owner row repeats the class line.
    assert!(!text.contains("<unnamed> (unnamed)"), "{text}");
    assert!(text.contains("  outside symbols: 44 bytes"), "{text}");
    assert!(
        text.contains("  assumption: functions without a name cannot be assigned an owner"),
        "{text}"
    );
    assert!(text.contains("toolchain holders"), "{text}");
    assert!(
        text.contains("  shared: 0 bytes in 0 symbols, 0 bytes in 0 symbols absorbed"),
        "{text}"
    );
    let ownership = text.find("ownership:").unwrap();
    let holders = text.find("toolchain holders").unwrap();
    let retained = text.find("retained sizes").unwrap();
    assert!(retained < ownership && ownership < holders, "{text}");
}

/// The stem section sits between the ownership table and the toolchain
/// holders, and the comparison's stem section between the ownership delta and
/// the assumptions.
#[test]
fn text_places_the_stem_sections_after_the_ownership_tables() {
    let mut artifact = ArtifactIr::empty(BinaryFormat::Wasm, b"fixture");
    artifact.symbols = vec![
        normalizable_symbol(10, &[1, 2], &[9]),
        normalizable_symbol(20, &[1, 3], &[9]),
    ];
    artifact.symbols[0].name = Some("emit<int>()".to_owned());
    artifact.symbols[1].name = Some("emit<long>()".to_owned());
    let report = ArtifactReport::from_ir(FilePath::new("fixture.wasm"), &artifact, None, None);
    let text = rendered_text(&report, false);
    let ownership = text.find("ownership:").unwrap();
    let stems = text.find("name stems emitted as several bodies").unwrap();
    let holders = text.find("toolchain holders").unwrap();
    assert!(ownership < stems && stems < holders, "{text}");

    let comparison = ArtifactComparisonReport::new(
        FilePath::new("before.wasm"),
        &ArtifactIr::empty(BinaryFormat::Wasm, b"fixture"),
        None,
        FilePath::new("after.wasm"),
        &artifact,
        None,
    );
    let text = rendered_compare_text(&comparison);
    let owners = text.find("ownership delta:").unwrap();
    let stems = text.find("stem delta:").unwrap();
    let assumption = text.find("assumption:").unwrap();
    assert!(owners < stems && stems < assumption, "{text}");
}

/// The compressed sizes follow the data segment line and lead the section
/// list, so the lines that were already there keep their relative order.
#[test]
fn text_places_compressed_sizes_between_data_segments_and_section_sizes() {
    let mut artifact = ArtifactIr::empty(BinaryFormat::Elf, b"fixture");
    artifact
        .sections
        .push(codehelion_artifact::ArtifactSection {
            name: Some(".text".to_owned()),
            offset: 16,
            size: 32,
            executable: true,
        });
    artifact.compressed_sizes = vec![codehelion_artifact::compression::CompressedSize {
        algorithm: CompressionAlgorithm::Gzip,
        parameters: "level 9".to_owned(),
        encoder: "flate2 (miniz_oxide)".to_owned(),
        bytes: 20,
    }];
    let report = ArtifactReport::from_ir(FilePath::new("fixture.so"), &artifact, None, None);
    let text = rendered_text(&report, false);
    let data = text.find("data segment bytes:").unwrap();
    let compressed = text.find("compressed bytes (").unwrap();
    let sections = text.find("section sizes:").unwrap();
    assert!(data < compressed && compressed < sections, "{text}");
}

/// Dead code, retained sizes and exact duplicate members name their symbol
/// before its fingerprint; a symbol without a name reads `<unnamed>`, and a
/// data member, which is a segment rather than a symbol, stays unnamed.
#[test]
fn text_lists_name_dead_code_retained_and_duplicate_members() {
    let report = listed_symbols_report("copy_a");
    let text = rendered_text(&report, false);
    let root = listed_symbol_at(&report, 0).fingerprint.clone();
    let helper = listed_symbol_at(&report, 30).fingerprint.clone();
    let first_copy = listed_symbol_at(&report, 10).fingerprint.clone();
    let second_copy = listed_symbol_at(&report, 20).fingerprint.clone();

    assert!(
        text.contains(&format!("\n  copy_a {first_copy}\n")),
        "{text}"
    );
    assert!(
        text.contains(&format!("\n  <unnamed> {second_copy}\n")),
        "{text}"
    );

    let retained = report.retained_sizes.as_ref().expect("a complete graph");
    let bytes_of = |fingerprint: &str| {
        retained
            .iter()
            .find(|item| item.symbol == fingerprint)
            .expect("a reachable symbol is listed")
            .retained_bytes
    };
    assert!(
        text.contains(&format!("\n  root {root}: {} bytes\n", bytes_of(&root))),
        "{text}"
    );
    assert!(
        text.contains(&format!(
            "\n  <unnamed> {helper}: {} bytes\n",
            bytes_of(&helper)
        )),
        "{text}"
    );

    assert!(
        text.contains(&format!("\n    copy_a {first_copy} offset 10 size 2\n")),
        "{text}"
    );
    assert!(
        text.contains(&format!("\n    <unnamed> {second_copy} offset 20 size 2\n")),
        "{text}"
    );

    let data = &text[text.find("data duplicate groups:").expect("a data group")..];
    let segment = &report.duplicate_groups.data[0].members[0].symbol;
    for offset in [64, 96] {
        assert!(
            data.contains(&format!("\n    {segment} offset {offset} size 16\n")),
            "{text}"
        );
    }
    assert!(!data.contains("<unnamed>"), "{text}");
}

/// Every fingerprint a list prints for a symbol is in the name index, checked
/// directly so a missing entry cannot hide behind the `<unnamed>` fallback.
#[test]
fn symbol_names_cover_every_listed_symbol_fingerprint() {
    let report = listed_symbols_report("copy_a");
    let names = render::symbol_names(&report);

    let mut listed: Vec<&str> = report
        .dead_code
        .as_ref()
        .expect("an exported root exists")
        .symbols
        .iter()
        .map(String::as_str)
        .collect();
    listed.extend(
        report
            .retained_sizes
            .as_ref()
            .expect("a complete graph")
            .iter()
            .map(|item| item.symbol.as_str()),
    );
    for group in report
        .duplicate_groups
        .exact
        .iter()
        .chain(&report.duplicate_groups.normalized)
    {
        listed.extend(group.members.iter().map(|member| member.symbol.as_str()));
    }
    assert!(listed.len() >= 5, "the fixture lists symbols: {listed:?}");
    for fingerprint in listed {
        assert!(
            names.contains_key(fingerprint),
            "{fingerprint} is listed but not indexed"
        );
    }
    assert_eq!(names.len(), report.symbols.len());
    assert_eq!(
        names[listed_symbol_at(&report, 10).fingerprint.as_str()],
        ["copy_a"]
    );
    assert_eq!(
        names[listed_symbol_at(&report, 20).fingerprint.as_str()],
        [] as [&str; 0]
    );
    // A data member names a segment, which the index does not hold.
    for member in &report.duplicate_groups.data[0].members {
        assert!(!names.contains_key(member.symbol.as_str()));
    }
}

const LONG_NAME: &str = "std::vector<std::pair<int, int>>::push_back(int&&)";
const SHORT_NAME: &str = "std::vector<std::pair<…>>::push_back(int&&)";

/// A text report shortens nested template arguments unless `-v` is given; the
/// symbol inventory, JSON and CSV carry the full name either way.
#[test]
fn text_shortens_names_unless_verbose() {
    assert_eq!(
        codehelion_artifact::short_name::short_name(LONG_NAME),
        SHORT_NAME
    );
    let report = listed_symbols_report(LONG_NAME);
    let copy = listed_symbol_at(&report, 10).fingerprint.clone();

    let text = rendered_text(&report, false);
    assert!(
        text.contains(&format!("\n  {SHORT_NAME} {copy}\n")),
        "{text}"
    );
    assert!(text.contains(&format!("\n    {SHORT_NAME} {copy} offset 10")));
    assert!(!text.contains(LONG_NAME), "{text}");

    let verbose = rendered_text(&report, true);
    assert!(
        verbose.contains(&format!("\n  {LONG_NAME} {copy}\n")),
        "{verbose}"
    );
    assert!(verbose.contains(&format!("\n    {LONG_NAME} {copy} offset 10")));
    assert!(
        verbose.contains(&format!("\n  symbol {copy} {LONG_NAME} offset 10 size 2")),
        "{verbose}"
    );

    let json = serde_json::to_value(&report).unwrap();
    assert!(
        json["symbols"]
            .as_array()
            .unwrap()
            .iter()
            .any(|symbol| symbol["name"] == LONG_NAME)
    );
    let dead = artifact_csv_records_of(&report, "dead-code");
    assert!(
        dead.iter()
            .any(|record| record[column::NAME] == LONG_NAME && record[column::FINGERPRINT] == copy)
    );

    // The same holds for a comparison.
    let before = vec![comparison_symbol(Some(LONG_NAME), b"before", 8)];
    let after = vec![comparison_symbol(Some(LONG_NAME), b"after", 4)];
    let comparison = symbol_comparison(before, after);
    let text = rendered_compare_text(&comparison);
    assert!(
        text.contains(&format!("  replaced {SHORT_NAME} ")),
        "{text}"
    );
    assert!(!text.contains(LONG_NAME), "{text}");
    let mut verbose = Vec::new();
    render_compare_text(&comparison, true, &mut verbose).unwrap();
    let verbose = String::from_utf8(verbose).unwrap();
    assert!(
        verbose.contains(&format!("  replaced {LONG_NAME} ")),
        "{verbose}"
    );
    let json = serde_json::to_value(&comparison).unwrap();
    assert!(
        json["symbol_deltas"]
            .as_array()
            .unwrap()
            .iter()
            .all(|delta| delta["name"] == LONG_NAME)
    );
    assert!(
        compare_csv_records(&comparison)
            .iter()
            .filter(|record| record[compare_column::RECORD_TYPE] == "symbol-delta")
            .all(|record| record[compare_column::NAME] == LONG_NAME)
    );
}

/// Two byte-identical symbols that share one fingerprint, each with its own
/// (possibly absent) name, so one fingerprint stands for several symbols.
fn shared_fingerprint_report(names: [Option<&str>; 2]) -> ArtifactReport {
    let mut artifact = WasmBackend.parse(b"\0asm\x01\0\0\0").unwrap();
    artifact.capabilities.call_graph = true;
    artifact.symbols = names
        .into_iter()
        .enumerate()
        .map(|(index, name)| {
            let mut symbol = comparison_symbol(name, b"same", 2);
            symbol.exported = index == 0;
            symbol.offset = index as u64 * 4;
            symbol
        })
        .collect();
    ArtifactReport::from_ir(FilePath::new("fixture.wasm"), &artifact, None, None)
}

/// A fingerprint shared by symbols with different names lists every distinct
/// name, joined with ` | `; a shared name appears once and no name reads
/// `<unnamed>`. CSV carries the same names in full.
#[test]
fn symbols_sharing_a_fingerprint_list_their_distinct_names() {
    let line = |report: &ArtifactReport, verbose: bool, shown: &str| {
        let fingerprint = &report.symbols[0].fingerprint;
        let text = rendered_text(report, verbose);
        assert!(
            text.contains(&format!("\n    {shown} {fingerprint} offset 0 size 2\n")),
            "{text}"
        );
    };
    let csv_name = |report: &ArtifactReport| {
        artifact_csv_records_of(report, "duplicate-member")[0][column::NAME].clone()
    };

    let different = shared_fingerprint_report([Some("first<a<b>>"), Some("second")]);
    assert_eq!(
        render::symbol_names(&different)[different.symbols[0].fingerprint.as_str()],
        ["first<a<b>>", "second"]
    );
    line(&different, false, "first<a<…>> | second");
    line(&different, true, "first<a<b>> | second");
    assert_eq!(csv_name(&different), "first<a<b>> | second");

    let same = shared_fingerprint_report([Some("only"), Some("only")]);
    line(&same, false, "only");
    assert_eq!(csv_name(&same), "only");

    let one_named = shared_fingerprint_report([None, Some("only")]);
    line(&one_named, false, "only");

    let none = shared_fingerprint_report([None, None]);
    line(&none, false, "<unnamed>");
    assert_eq!(csv_name(&none), "");
}
