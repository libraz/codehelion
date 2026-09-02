use super::*;
use crate::report::tests::{sample_near_miss, sample_report, sample_siblings, structural_group};
use crate::report::{CompilerCoverage, FunnelCause};

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
    assert_eq!(run["automationDetails"]["id"], "codehelion/fast/1");
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
    let report = sample_report();
    let value = sarif(&report);
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
    assert_eq!(
        primary["properties"]["content"],
        report.groups[0].members[0].content
    );
    assert_eq!(
        primary["properties"]["language"],
        report.groups[0].members[0].language
    );
    assert_eq!(
        result["properties"]["entropy_bits"],
        serde_json::json!(report.groups[0].entropy_bits)
    );

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
fn baseline_status_reaches_the_result_properties() {
    let mut report = sample_report();
    report.groups[0].baseline = Some(super::super::GroupBaseline {
        state: "expanded".to_string(),
        added_instances: Some(2),
        derived_from: None,
    });

    let value = sarif(&report);
    assert_eq!(
        value["runs"][0]["results"][0]["properties"]["baseline"]["state"],
        "expanded"
    );
    assert_eq!(
        value["runs"][0]["results"][0]["properties"]["baseline"]["added_instances"],
        2
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

    // A mode that scores no dimensions says so rather than inventing values,
    // and says it where the JSON report says it: the key is stated as null in
    // both views, so a consumer reading either finds the same answer.
    assert_eq!(
        value["runs"][0]["results"][0]["properties"]["similarity"],
        serde_json::Value::Null
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

/// Coverage whose `not_asked` total is exactly what its reasons account for,
/// because that is the only shape either producer can build.
fn coverage(not_asked_reasons: &[(&str, u64)], unavailable: &[(&str, u64)]) -> CompilerCoverage {
    let by_reason = |counts: &[(&str, u64)]| {
        counts
            .iter()
            .map(|(reason, count)| ((*reason).to_string(), *count))
            .collect::<BTreeMap<_, _>>()
    };
    CompilerCoverage {
        answered: 3,
        not_asked: not_asked_reasons.iter().map(|(_, count)| *count).sum(),
        not_asked_reasons: by_reason(not_asked_reasons),
        unavailable: by_reason(unavailable),
        diagnostics: BTreeMap::new(),
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
    let mut compiler = coverage(
        &[("no_build_information", 4), ("not_supported", 1)],
        &[("helper_died", 1), ("requires_execution", 2)],
    );
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
    assert_eq!(notifications.len(), 4);

    // A file nothing describes how to compile and a file whose language no
    // helper reads are both unasked, and each is named: a consumer reading
    // one total cannot tell which of the two this run met.
    for (at, reason, files) in [(0, "no_build_information", 4), (1, "not_supported", 1)] {
        let notification = &notifications[at];
        assert_eq!(notification["descriptor"]["id"], "coverage/not-asked");
        assert_eq!(notification["level"], "note");
        assert_eq!(notification["properties"]["reason"], reason);
        assert_eq!(notification["properties"]["files"], files);
        let message = notification["message"]["text"].as_str().unwrap();
        assert!(message.contains(reason), "{message}");
    }

    // One per reason: a build script nobody allowed to run and a helper
    // that died call for different things, and one total would leave a
    // reader to guess which they have.
    for (at, reason, files) in [(2, "helper_died", 1), (3, "requires_execution", 2)] {
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
        crate::report::FunnelStage::new("grouping", 12)
            .dropping(FunnelCause::TheCeilingCutTheSet, 7),
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
    answered.summary.compiler = Some(coverage(&[], &[]));
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
    assert_eq!(uri_reference("src:generated/a.rs"), "src%3Agenerated/a.rs");
    assert_eq!(uri_reference("src\\win.rs"), "src/win.rs");
    assert_eq!(uri_reference("src/日本.rs"), "src/%E6%97%A5%E6%9C%AC.rs");
    assert_eq!(root_uri("/work/my project"), "file:///work/my%20project/");
    assert_eq!(root_uri("C:\\work"), "file:///C:/work/");
    assert_eq!(root_uri("/work:tree"), "file:///work%3Atree/");
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

/// Where a reader finds one JSON-report field that SARIF carries in a
/// first-class place instead of a property bag: the JSON key, then the SARIF
/// field that carries it.
///
/// Kept as data so the two machine-readable views can be checked against each
/// other field for field: anything absent from both these tables and the
/// property bag is a field one view publishes and the other drops.
type FirstClass = (&'static str, &'static str);

const RUN_FIRST_CLASS: &[FirstClass] = &[
    ("tool_version", "driver version"),
    ("started_at", "invocation start time"),
    ("finished_at", "invocation end time"),
];

const GROUP_FIRST_CLASS: &[FirstClass] = &[
    ("fingerprint", "partial fingerprints"),
    ("members", "related locations"),
];

const MEMBER_FIRST_CLASS: &[FirstClass] = &[
    ("file", "artifact location"),
    ("start_line", "region"),
    ("end_line", "region"),
    ("unit", "logical location"),
];

const REPORT_FIRST_CLASS: &[FirstClass] = &[
    ("schema_version", "report_schema_version run property"),
    ("groups", "results"),
    // Spread across the run rather than nested under one key; its own fields
    // are checked one level down.
    ("run", "run properties and invocation"),
    // Attached to the result that owns them, where a consumer reading one
    // finding sees them without cross-referencing a run-level list.
    ("siblings", "the owning result's siblings property"),
];

/// Assert every key of one JSON-report object reaches the SARIF log, either
/// through the matching property bag or through a named first-class field.
fn assert_every_key_reaches_sarif(
    object: &serde_json::Value,
    properties: &serde_json::Value,
    first_class: &[FirstClass],
) {
    for key in object.as_object().unwrap().keys() {
        let reachable = properties.get(key).is_some()
            || first_class.iter().any(|(carried, _)| *carried == *key);
        assert!(
            reachable,
            "field {key:?} is published by the JSON report and reaches no SARIF field"
        );
    }
}

#[test]
fn every_json_report_field_reaches_the_sarif_log() {
    let mut report = sample_report();
    report.siblings = vec![sample_siblings()];
    report.near_misses = vec![sample_near_miss()];
    report.run.reused = true;
    report.groups[0].identity = Some(crate::report::GroupIdentity {
        origin: crate::report::IDENTITY_ADOPTED.to_string(),
        compared_with_run: 1,
        adopted_from: Some("ab".repeat(16)),
        shared_members: Some(2),
        compared_members: Some(3),
    });
    report.groups[0].members[0].boilerplate = Some("forwarding".to_string());

    let json: serde_json::Value = serde_json::from_str(&report.to_json().unwrap()).unwrap();
    let log = sarif(&report);
    let run = &log["runs"][0];

    assert_every_key_reaches_sarif(&json, &run["properties"], REPORT_FIRST_CLASS);
    assert_every_key_reaches_sarif(&json["run"], &run["properties"], RUN_FIRST_CLASS);
    let result = &run["results"][0];
    assert_every_key_reaches_sarif(&json["groups"][0], &result["properties"], GROUP_FIRST_CLASS);
    assert_every_key_reaches_sarif(
        &json["groups"][0]["members"][0],
        &result["relatedLocations"][0]["properties"],
        MEMBER_FIRST_CLASS,
    );

    // The values, not only the keys: a bag that repeats a field under the
    // right name with the wrong contents agrees with nothing.
    assert_eq!(
        result["properties"]["identity"],
        json["groups"][0]["identity"]
    );
    assert_eq!(
        result["properties"]["ranked_down"],
        json["groups"][0]["ranked_down"]
    );
    assert_eq!(
        run["properties"]["configuration"],
        json["run"]["configuration"]
    );
    assert_eq!(run["properties"]["reused"], json["run"]["reused"]);
    assert_eq!(
        result["relatedLocations"][0]["properties"]["boilerplate"],
        json["groups"][0]["members"][0]["boilerplate"]
    );
}

/// A root the filesystem names in bytes no text can hold is still a root a
/// report has to print and a SARIF log has to base its URIs on. The stored key
/// keeps those bytes reversibly, under a reserved marker that is not a path:
/// left in place it would put a bare control character and a colon into
/// `SRCROOT`, and the two commands that render one run would disagree about
/// which tree it was.
#[cfg(unix)]
#[test]
fn a_root_that_is_not_utf8_reaches_the_log_as_a_uri_without_the_stored_marker() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;
    use std::path::PathBuf;

    let root = PathBuf::from(OsString::from_vec(b"/work/\x80project".to_vec()));
    let key = codehelion_store::path_key(&root);
    // What a live scan prints and what a replay of the recorded run prints.
    let live = codehelion_store::path_label(&root);
    let replayed = codehelion_store::display_path(&key);
    assert_eq!(live, replayed);

    let mut report = sample_report();
    report.run.root = replayed;
    let value = sarif(&report);
    let uri = value["runs"][0]["originalUriBaseIds"]["SRCROOT"]["uri"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(uri.starts_with("file:///"), "{uri}");
    assert!(uri.ends_with('/'), "{uri}");
    assert!(!uri.contains("codehelion-path-bytes"), "{uri}");
    assert!(!uri.contains('\u{001f}'), "{uri}");
    assert!(!root_uri(&key).eq(&uri));
}
