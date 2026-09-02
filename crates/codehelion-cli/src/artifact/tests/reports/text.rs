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
    let header: Vec<_> = lines.next().unwrap().split(',').collect();
    let summary: Vec<_> = lines.next().unwrap().split(',').collect();
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
    assert!(text.contains("dead code definitive: 1 symbols"));
    assert!(!text.contains("[1, 2]"));
    let mut csv = Vec::new();
    render_csv(&report, &mut csv).unwrap();
    let csv = String::from_utf8(csv).unwrap();
    assert!(csv.contains("duplicate-group,fixture.wasm,wasm,exact,"));
    assert!(csv.contains("duplicate-member,fixture.wasm,wasm,exact,"));
    assert!(csv.contains("dead-code,fixture.wasm,wasm,"));
    let mut rows = csv.lines();
    let columns = rows.next().unwrap().split(',').count();
    let widths: Vec<_> = rows.map(|row| row.split(',').count()).collect();
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
