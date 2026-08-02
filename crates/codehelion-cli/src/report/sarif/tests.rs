use super::*;
use crate::report::tests::{sample_near_miss, sample_report, sample_siblings, structural_group};

fn sarif(report: &Report) -> serde_json::Value {
    serde_json::from_str(&report.to_sarif().unwrap()).unwrap()
}

#[test]
fn the_log_names_its_version_and_the_tool_that_produced_it() {
    let value = sarif(&sample_report());
    assert_eq!(value["version"], "2.1.0");
    assert_eq!(value["$schema"], SARIF_SCHEMA_URI);
    assert_eq!(value["runs"].as_array().unwrap().len(), 1);

    let driver = &value["runs"][0]["tool"]["driver"];
    assert_eq!(driver["name"], "codehelion");
    assert_eq!(driver["version"], "0.1.0");
    // The rule table is fixed, so a rule index means the same thing in
    // every log this tool writes.
    let rules = driver["rules"].as_array().unwrap();
    assert_eq!(rules.len(), 4);
    assert_eq!(rules[2]["id"], "clone/type-3");
    assert_eq!(rules[2]["defaultConfiguration"]["level"], "note");
    assert_eq!(rules[3]["id"], "clone/restricted-semantic");

    let run = &value["runs"][0];
    assert_eq!(run["automationDetails"]["id"], "codehelion/fast");
    assert_eq!(
        run["originalUriBaseIds"]["SRCROOT"]["uri"],
        "file:///work/project/"
    );
    assert_eq!(run["invocations"][0]["executionSuccessful"], true);
    // SARIF timestamps carry milliseconds, not the microseconds the JSON
    // report records.
    assert_eq!(
        run["invocations"][0]["startTimeUtc"],
        "2026-01-01T00:00:00.000Z"
    );
}

#[test]
fn a_group_becomes_one_result_pointing_at_its_canonical_instance() {
    let value = sarif(&sample_report());
    let result = &value["runs"][0]["results"][0];
    assert_eq!(result["ruleId"], "clone/type-1");
    assert_eq!(result["ruleIndex"], 0);
    assert_eq!(result["level"], "note");
    assert_eq!(result["occurrenceCount"], 7);
    assert!(
        result["message"]["text"]
            .as_str()
            .unwrap()
            .starts_with("type-1 clone group: 7 occurrences, 80 tokens")
    );

    let primary = &result["locations"][0];
    assert_eq!(
        primary["physicalLocation"]["artifactLocation"]["uri"],
        "src/file0.rs"
    );
    assert_eq!(
        primary["physicalLocation"]["artifactLocation"]["uriBaseId"],
        "SRCROOT"
    );
    assert_eq!(primary["physicalLocation"]["region"]["startLine"], 1);
    assert_eq!(primary["physicalLocation"]["region"]["endLine"], 9);
    assert_eq!(primary["logicalLocations"][0]["name"], "checksum");
    assert_eq!(primary["properties"]["canonical"], true);

    // Every member is reachable, the canonical one included.
    let related = result["relatedLocations"].as_array().unwrap();
    assert_eq!(related.len(), 7);
    assert_eq!(related[0]["id"], 0);
    assert_eq!(
        related[0]["message"]["text"],
        "occurrence 1 of 7 (canonical instance)"
    );
    assert_eq!(related[6]["message"]["text"], "occurrence 7 of 7");
    assert_eq!(
        related[6]["properties"]["finding_id"],
        format!("{:032x}", 6)
    );

    // The stable clone id travels with the result.
    assert_eq!(
        result["partialFingerprints"][FINGERPRINT_KEY],
        "0b".repeat(16)
    );
}

#[test]
fn a_sibling_is_a_property_of_its_primary_result_not_a_result_of_its_own() {
    let mut report = sample_report();
    report.siblings = vec![sample_siblings()];
    let value = sarif(&report);
    let results = value["runs"][0]["results"].as_array().unwrap();

    assert_eq!(results.len(), report.groups.len());
    assert_eq!(
        results[0]["properties"]["siblings"][0]["member"]["file"],
        "src/incomplete.rs"
    );
    assert_eq!(
        results[0]["properties"]["siblings"][0]["similarity"]["composite"],
        0.76
    );
    assert_eq!(results[1]["properties"]["siblings"], serde_json::json!([]));
}

#[test]
fn a_near_miss_is_a_run_property_not_a_primary_sarif_result() {
    let mut report = sample_report();
    report.near_misses = vec![sample_near_miss()];
    let value = sarif(&report);

    assert_eq!(
        value["runs"][0]["properties"]["near_misses"][0]["left"]["file"],
        "src/left.rs"
    );
    assert_eq!(
        value["runs"][0]["properties"]["near_misses"][0]["estimated_jaccard"],
        0.28
    );
    assert_eq!(
        value["runs"][0]["results"].as_array().unwrap().len(),
        report.groups.len(),
        "a below-threshold proposal must never become a SARIF finding"
    );
}

#[test]
fn restricted_semantic_group_uses_its_own_rule_and_preserves_evidence() {
    let mut report = sample_report();
    let group = &mut report.groups[0];
    group.clone_type = "restricted-semantic".to_string();
    group.semantic = Some(super::super::SemanticEvidence {
        schema_version: "sog-v1".to_string(),
        rules: vec![super::super::SemanticRuleEvidence {
            id: "sequence-pipeline-v1".to_string(),
            version: 1,
            confidence: 0.7,
        }],
        graphs: vec![
            super::super::tests::semantic_graph(),
            super::super::tests::semantic_graph(),
        ],
        node_mappings: vec![super::super::SemanticNodeMapping {
            corresponding_member: 1,
            canonical: 0,
            corresponding: 0,
        }],
    });
    let value = sarif(&report);
    let result = &value["runs"][0]["results"][0];
    assert_eq!(result["ruleId"], "clone/restricted-semantic");
    assert_eq!(
        result["properties"]["semantic"]["rules"][0]["id"],
        "sequence-pipeline-v1"
    );
}

#[test]
fn the_similarity_breakdown_reaches_the_result_intact() {
    let mut report = sample_report();
    report.groups.push(structural_group());
    let value = sarif(&report);
    let result = &value["runs"][0]["results"][2];

    assert_eq!(result["ruleId"], "clone/type-3");
    assert_eq!(result["ruleIndex"], 2);
    let properties = &result["properties"];
    assert_eq!(properties["clone_type"], "type-3");
    assert_eq!(
        properties["priority"]["inputs"]["largest_member_tokens"],
        60
    );
    assert_eq!(properties["similarity"]["composite"], 0.82);
    for key in ["identifier_jaccard", "body_materiality", "width_family"] {
        assert!(
            properties.get(key).is_some(),
            "SARIF properties retain the report field {key}"
        );
    }
    assert_eq!(properties["identifier_jaccard"], 0.5);
    assert_eq!(properties["body_materiality"]["call_count"], 3);
    assert_eq!(properties["width_family"], false);
    assert_eq!(
        properties["similarity"]["weight_version"],
        "structural-verify-v1"
    );
    // The dimension the mode could not measure stays absent here too.
    assert_eq!(
        properties["similarity"]["type_similarity"],
        serde_json::Value::Null
    );
    assert!(
        result["message"]["text"]
            .as_str()
            .unwrap()
            .contains("type n/a")
    );
    // The classified shape travels with the result too, so no reporter
    // says less about a group than another.
    let mut classified = sample_report();
    let mut group = structural_group();
    group.boilerplate = Some("macro-repetition".to_string());
    classified.groups.push(group);
    assert_eq!(
        sarif(&classified)["runs"][0]["results"][2]["properties"]["boilerplate"],
        "macro-repetition"
    );

    // As does whether the group lives wholly in a test suite, which is why
    // it may sit low in a report that still lists it.
    let mut suite = sample_report();
    let mut group = structural_group();
    group.test_code = true;
    group.test_code_evidence = Some(codehelion_core::test_code::TestCodeEvidence::Marker);
    suite.groups.push(group);
    let log = sarif(&suite);
    assert_eq!(
        log["runs"][0]["results"][2]["properties"]["test_code"],
        true
    );
    assert_eq!(
        log["runs"][0]["results"][0]["properties"]["test_code"],
        false
    );
    assert_eq!(
        log["runs"][0]["results"][2]["properties"]["test_code_evidence"],
        "marker"
    );

    // A mode that scores no dimensions omits the key rather than
    // inventing values.
    assert!(
        value["runs"][0]["results"][0]["properties"]
            .get("similarity")
            .is_none()
    );
}

#[test]
fn a_suppressed_group_is_reported_as_suppressed_not_dropped() {
    let value = sarif(&sample_report());
    let results = value["runs"][0]["results"].as_array().unwrap();
    assert_eq!(results.len(), 2, "the hidden group is still reported");

    let suppression = &results[1]["suppressions"][0];
    assert_eq!(suppression["kind"], "external");
    assert_eq!(suppression["justification"], "path glob \"vendor/**\"");
    assert_eq!(results[1]["properties"]["suppressed"]["scope"], "path_glob");
    assert_eq!(results[0]["suppressions"], serde_json::json!([]));
}

#[test]
fn an_inline_marker_is_the_only_in_source_suppression() {
    let inline = Suppression {
        kind: SuppressionKind::Rule,
        reason: None,
        scope: Some("inline_comment".to_string()),
        pattern: Some("codehelion:ignore".to_string()),
        active: Some(true),
    };
    assert_eq!(SuppressionEntry::from(&inline).kind, "inSource");

    let noise = Suppression {
        kind: SuppressionKind::Noise,
        reason: Some("low-entropy".to_string()),
        scope: None,
        pattern: None,
        active: None,
    };
    let entry = SuppressionEntry::from(&noise);
    assert_eq!(entry.kind, "external");
    assert_eq!(entry.justification, "low-entropy noise");
}

#[test]
fn the_run_property_bag_keeps_what_sarif_has_no_field_for() {
    let value = sarif(&sample_report());
    let properties = &value["runs"][0]["properties"];
    assert_eq!(
        properties["report_schema_version"],
        crate::report::SCHEMA_VERSION
    );
    assert_eq!(properties["mode"], "fast");
    assert_eq!(properties["build_variant"]["normalization_version"], 1);
    assert_eq!(properties["detector_versions"][0]["component"], "fp-schema");
    assert_eq!(properties["summary"]["files"]["total"], 2);
    assert_eq!(properties["run_id"], 1);
}

fn coverage(not_asked: u64, unavailable: &[(&str, u64)]) -> CompilerCoverage {
    CompilerCoverage {
        answered: 3,
        not_asked,
        unavailable: unavailable
            .iter()
            .map(|(reason, count)| ((*reason).to_string(), *count))
            .collect(),
        execution_refusals: Vec::new(),
        restarts: 2,
    }
}

/// A short result list is what a clean tree and an unreadable one both look
/// like. Which one this is has to be said outright, in the place a consumer
/// reads without having been taught this tool's property keys.
#[test]
fn what_a_run_could_not_read_is_said_rather_than_left_to_the_property_bag() {
    let mut report = sample_report();
    report.summary.search_truncated = false;
    let mut compiler = coverage(5, &[("helper_died", 1), ("requires_execution", 2)]);
    compiler
        .execution_refusals
        .push(crate::report::ExecutionRefusal {
            execution: "build-script".to_string(),
            files: 2,
            cost: "types and items that only exist after a build script has generated them"
                .to_string(),
            permission_argument: "--allow-execution=build-script".to_string(),
            message: "skipped build-script: not permitted, so this run has no types and items that only exist after a build script has generated them. Pass --allow-execution=build-script to allow it."
                .to_string(),
        });
    report.summary.compiler = Some(compiler);
    let value = sarif(&report);
    let run = &value["runs"][0];
    let notifications = run["invocations"][0]["toolExecutionNotifications"]
        .as_array()
        .unwrap();
    assert_eq!(notifications.len(), 3);

    assert_eq!(notifications[0]["descriptor"]["id"], "coverage/not-asked");
    assert_eq!(notifications[0]["level"], "note");
    assert_eq!(notifications[0]["properties"]["files"], 5);

    // One per reason: a build script nobody allowed to run and a helper
    // that died call for different things, and one total would leave a
    // reader to guess which they have.
    for (at, reason, files) in [(1, "helper_died", 1), (2, "requires_execution", 2)] {
        let notification = &notifications[at];
        assert_eq!(notification["descriptor"]["id"], "coverage/unanswered");
        assert_eq!(notification["level"], "warning");
        assert_eq!(notification["properties"]["reason"], reason);
        assert_eq!(notification["properties"]["files"], files);
        let message = notification["message"]["text"].as_str().unwrap();
        if reason == "requires_execution" {
            assert!(
                message.contains("build script has generated them"),
                "{message}"
            );
            assert!(
                message.contains("--allow-execution=build-script"),
                "{message}"
            );
        } else {
            assert!(message.contains(reason), "{message}");
        }
    }

    // Reading less of a tree than it holds is an outcome, not a failure.
    assert_eq!(run["invocations"][0]["executionSuccessful"], true);

    // And the index has to land on the descriptor it names, or a consumer
    // resolving it by position gets somebody else's sentence.
    let declared = run["tool"]["driver"]["notifications"].as_array().unwrap();
    assert_eq!(declared.len(), NOTICES.len());
    for notification in notifications {
        let index = notification["descriptor"]["index"].as_u64().unwrap();
        let at = usize::try_from(index).unwrap();
        assert_eq!(declared[at]["id"], notification["descriptor"]["id"]);
    }
}

/// A run told to stop comparing before it ran out of things to compare has
/// findings missing for a reason that is not the tree's.
#[test]
fn a_candidate_search_truncated_by_a_ceiling_says_so() {
    let mut report = sample_report();
    report.summary.search_truncated = true;
    let value = sarif(&report);
    let notifications = value["runs"][0]["invocations"][0]["toolExecutionNotifications"]
        .as_array()
        .unwrap();
    assert_eq!(notifications.len(), 1);
    assert_eq!(
        notifications[0]["descriptor"]["id"],
        "coverage/search-truncated"
    );
    assert_eq!(notifications[0]["level"], "warning");
    // Nothing was counted in files, so nothing claims to have been.
    assert!(notifications[0]["properties"].get("files").is_none());
}

#[test]
fn grouping_and_parser_coverage_have_distinct_warnings() {
    let mut report = sample_report();
    report.summary.search_truncated = false;
    report.summary.funnel.push(
        crate::report::FunnelStage::new("grouping", 12).dropping("the_ceiling_cut_the_set", 7),
    );
    report.summary.unparsed = Some(crate::report::UnparsedCounts::from_counts(2, 75, 300));

    let value = sarif(&report);
    let notifications = value["runs"][0]["invocations"][0]["toolExecutionNotifications"]
        .as_array()
        .expect("coverage notifications");
    let grouping = notifications
        .iter()
        .find(|notification| notification["descriptor"]["id"] == "coverage/grouping-ceiling")
        .expect("grouping ceiling warning");
    assert_eq!(grouping["level"], "warning");
    assert_eq!(grouping["properties"]["relationships"], 7);

    let parser = notifications
        .iter()
        .find(|notification| notification["descriptor"]["id"] == "coverage/parser-recovery")
        .expect("parser coverage warning");
    assert_eq!(parser["level"], "warning");
    assert_eq!(parser["properties"]["files"], 2);
    assert_eq!(parser["properties"]["unparsed_tokens"], 75);
    assert_eq!(parser["properties"]["unparsed_share"], 0.25);
}

/// Silence and an empty complaint are different claims. A mode that asks no
/// compiler never had one to make, and a run that asked about everything it
/// read has nothing outstanding — neither is served by an empty array that
/// reads as a report that came back clean.
#[test]
fn a_run_with_nothing_to_report_about_itself_reports_nothing() {
    let mut report = sample_report();
    report.summary.search_truncated = false;
    let value = sarif(&report);
    assert!(
        value["runs"][0]["invocations"][0]
            .get("toolExecutionNotifications")
            .is_none()
    );
    // The catalogue is still there, because what the tool can say does not
    // depend on what this run had to say.
    assert_eq!(
        value["runs"][0]["tool"]["driver"]["notifications"]
            .as_array()
            .unwrap()
            .len(),
        NOTICES.len()
    );

    // Nor does a compiler that answered about everything file an empty one.
    let mut answered = sample_report();
    answered.summary.search_truncated = false;
    answered.summary.compiler = Some(coverage(0, &[]));
    let value = sarif(&answered);
    assert!(
        value["runs"][0]["invocations"][0]
            .get("toolExecutionNotifications")
            .is_none()
    );
}

#[test]
fn paths_are_escaped_into_valid_uri_references() {
    assert_eq!(uri_reference("src/lib.rs"), "src/lib.rs");
    assert_eq!(uri_reference("src/a b.rs"), "src/a%20b.rs");
    assert_eq!(uri_reference("src\\win.rs"), "src/win.rs");
    assert_eq!(uri_reference("src/日本.rs"), "src/%E6%97%A5%E6%9C%AC.rs");
    assert_eq!(root_uri("/work/my project"), "file:///work/my%20project/");
    assert_eq!(root_uri("C:\\work"), "file:///C:/work/");
}

#[test]
fn timestamps_are_restated_at_millisecond_precision() {
    assert_eq!(
        millisecond_timestamp("2026-01-01T00:00:00.123456Z"),
        "2026-01-01T00:00:00.123Z"
    );
    assert_eq!(
        millisecond_timestamp("2026-01-01T00:00:00Z"),
        "2026-01-01T00:00:00.000Z"
    );
    // Anything else is passed through rather than mangled.
    assert_eq!(millisecond_timestamp("unknown"), "unknown");
}

#[test]
fn a_member_without_lines_reports_no_region() {
    let mut report = sample_report();
    report.groups[0].members[0].start_line = 0;
    report.groups[0].members[0].end_line = 0;
    let value = sarif(&report);
    let physical = &value["runs"][0]["results"][0]["locations"][0]["physicalLocation"];
    assert!(physical.get("region").is_none());
    assert_eq!(physical["artifactLocation"]["uri"], "src/file0.rs");
}
