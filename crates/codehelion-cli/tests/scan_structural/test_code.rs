use super::*;

/// A module compiled only for tests, holding two cases that differ in nothing
/// but their names and values.
const SUITE_RS: &str = "pub fn width_of(text: &str) -> usize {
    text.trim().chars().count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_measures_a_short_string() {
        let input = String::from(\"  hi  \");
        let measured = width_of(&input);
        let doubled = measured * 2;
        assert_eq!(measured, 2);
        assert_eq!(doubled, 4);
    }

    #[test]
    fn it_measures_a_longer_string() {
        let input = String::from(\"  hello  \");
        let measured = width_of(&input);
        let doubled = measured * 2;
        assert_eq!(measured, 5);
        assert_eq!(doubled, 10);
    }
}
";

fn suite_fixture() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path();
    std::fs::create_dir_all(root.join(".git")).unwrap();
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(root.join("src/measure.rs"), SUITE_RS).unwrap();
    dir
}

#[test]
fn duplication_inside_a_test_suite_is_reported_and_marked() {
    let dir = suite_fixture();
    cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "--mode", "structural", "-v"])
        .assert()
        .success()
        // Ranked down, not hidden: the count is stated and the entry says why
        // it sits where it does.
        .stdout(predicate::str::contains("[test code]"))
        .stdout(predicate::str::contains(
            "of the 1 listed group, 1 are duplication inside test code",
        ));

    let value = scan_json(dir.path());
    assert_eq!(value["summary"]["groups"]["test_code"], 1);
    assert_eq!(value["summary"]["suppressed"]["by_rule"], 0);
    assert!(
        value["groups"]
            .as_array()
            .unwrap()
            .iter()
            .all(|group| group["test_code_evidence"] == "marker")
    );
    assert!(
        value["groups"]
            .as_array()
            .unwrap()
            .iter()
            .all(|group| group["test_code"] == true)
    );
}

#[test]
fn a_policy_that_hides_test_code_records_the_marker_that_hid_it() {
    let dir = suite_fixture();
    std::fs::write(
        dir.path().join("codehelion.toml"),
        "[suppression]\ntest-code = \"hide\"\n",
    )
    .unwrap();
    cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "--mode", "structural", "-v"])
        .assert()
        .success()
        .stdout(predicate::str::contains("1 by rule"));

    // Hidden, not deleted: the rule that hid it names the marker it read.
    let store = open_store(dir.path());
    let run = store.latest_run().unwrap().expect("a recorded run");
    let findings = store.run_findings(run.id).unwrap();
    assert!(
        findings
            .iter()
            .any(|finding| finding.suppression_scope.as_deref() == Some("attribute"))
    );
}

#[test]
fn a_policy_that_reports_test_code_keeps_it_visible_without_suppression() {
    let dir = suite_fixture();
    std::fs::write(
        dir.path().join("codehelion.toml"),
        "[suppression]\ntest-code = \"report\"\n",
    )
    .unwrap();

    let value = scan_json(dir.path());
    assert_eq!(value["summary"]["groups"]["test_code"], 1);
    assert_eq!(value["summary"]["suppressed"]["by_rule"], 0);
    assert!(
        value["groups"]
            .as_array()
            .unwrap()
            .iter()
            .all(|group| group["suppressed"].is_null())
    );
}

#[test]
fn a_marker_under_a_test_path_names_marker_evidence() {
    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path();
    std::fs::create_dir_all(root.join(".git")).unwrap();
    std::fs::create_dir_all(root.join("tests")).unwrap();
    std::fs::write(root.join("tests/measure.rs"), SUITE_RS).unwrap();

    let value = scan_json(root);
    let groups = value["groups"].as_array().unwrap();
    assert!(!groups.is_empty(), "the marked cases form a group");
    assert!(
        groups
            .iter()
            .all(|group| group["test_code_evidence"] == "marker")
    );
}

/// The crate root, which declares the suite and holds the routine it covers.
/// `{}` is where the declaration's attribute goes, or does not.
const SPLIT_ROOT_RS: &str = "pub fn width_of(text: &str) -> usize {
    text.trim().chars().count()
}

{}
mod tests;
";

/// The suite's own root: nothing but the file it hands on to.
const SPLIT_SUITE_RS: &str = "mod width;\n";

/// Two helpers of the suite, identical and neither marked: the duplication is
/// recognisable as test code only through the declaration two files above.
const SPLIT_CASES_RS: &str = "use super::super::width_of;

#[track_caller]
fn short_case(input: &str, expected: usize) {
    let measured = width_of(input);
    let doubled = measured * 2;
    assert_eq!(measured, expected);
    assert_eq!(doubled, expected * 2);
}

#[track_caller]
fn long_case(input: &str, expected: usize) {
    let measured = width_of(input);
    let doubled = measured * 2;
    assert_eq!(measured, expected);
    assert_eq!(doubled, expected * 2);
}
";

/// A suite declared in one file and written in two others, optionally marked
/// as test-only where it is declared.
fn split_suite_fixture(declared_for_tests: bool) -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path();
    std::fs::create_dir_all(root.join(".git")).unwrap();
    std::fs::create_dir_all(root.join("src/tests")).unwrap();
    let attribute = if declared_for_tests {
        "#[cfg(test)]"
    } else {
        ""
    };
    std::fs::write(
        root.join("src/lib.rs"),
        SPLIT_ROOT_RS.replace("{}", attribute),
    )
    .unwrap();
    std::fs::write(root.join("src/tests.rs"), SPLIT_SUITE_RS).unwrap();
    std::fs::write(root.join("src/tests/width.rs"), SPLIT_CASES_RS).unwrap();
    dir
}

#[test]
fn a_suite_declared_in_one_file_and_written_in_another_is_still_a_suite() {
    let value = scan_json(split_suite_fixture(true).path());
    let groups = value["groups"].as_array().unwrap();
    assert_eq!(groups.len(), 1, "{groups:#?}");
    // Neither helper carries a marker; the only one in the tree is on the
    // declaration in the crate root, two files above them.
    assert_eq!(groups[0]["test_code"], true);
    assert_eq!(value["summary"]["groups"]["test_code"], 1);
}

#[test]
fn plain_functions_under_tests_are_test_code_with_path_evidence() {
    // The same three files, with the attribute taken off the declaration. The
    // unmarked helpers live under the default `tests/` path convention.
    let value = scan_json(split_suite_fixture(false).path());
    let groups = value["groups"].as_array().unwrap();
    assert_eq!(groups.len(), 1, "{groups:#?}");
    assert_eq!(groups[0]["test_code"], true);
    assert_eq!(groups[0]["test_code_evidence"], "path");
    assert_eq!(value["summary"]["groups"]["test_code"], 1);
}

#[test]
fn disabling_test_paths_removes_path_evidence_without_affecting_marker_evidence() {
    let path_only = split_suite_fixture(false);
    std::fs::write(
        path_only.path().join("codehelion.toml"),
        "[suppression]\ntest-paths = []\n",
    )
    .unwrap();
    let path_value = scan_json(path_only.path());
    assert_eq!(path_value["groups"][0]["test_code"], false);
    assert!(path_value["groups"][0]["test_code_evidence"].is_null());

    let marker_only = suite_fixture();
    std::fs::write(
        marker_only.path().join("codehelion.toml"),
        "[suppression]\ntest-paths = []\n",
    )
    .unwrap();
    let marker_value = scan_json(marker_only.path());
    assert_eq!(marker_value["groups"][0]["test_code"], true);
    assert_eq!(marker_value["groups"][0]["test_code_evidence"], "marker");
}

#[test]
fn invalid_test_path_glob_is_a_configuration_error_without_a_structural_hint() {
    let dir = fixture();
    std::fs::write(
        dir.path().join("codehelion.toml"),
        "[suppression]\ntest-paths = [\"[\"]\n",
    )
    .unwrap();
    let output = cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "--mode", "structural", "--format", "json"])
        .output()
        .expect("run structural scan with invalid test-path glob");
    assert!(!output.status.success(), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("in suppression test-paths"), "{stderr}");
    assert!(
        !stderr.contains("hint: "),
        "configuration error is not analysis: {stderr}"
    );
}

#[test]
fn a_recorded_run_reemits_test_code_evidence() {
    let dir = split_suite_fixture(false);
    let scanned = scan_json(dir.path());
    let run_id = scanned["run"]["run_id"]
        .as_i64()
        .expect("scan JSON carries the recorded run id");

    let output = cmd()
        .current_dir(dir.path())
        .args(["report", "--run", &run_id.to_string(), "--format", "json"])
        .output()
        .expect("reformat recorded Structural report");
    assert!(output.status.success(), "{output:?}");
    let recorded: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("recorded report is JSON");
    assert_eq!(recorded["groups"], scanned["groups"]);
    assert_eq!(recorded["groups"][0]["test_code_evidence"], "path");
}

/// A snapshot view applies the same rank-down policy as the scan that made
/// it, so its first text entries and SARIF results remain reproducible.
#[test]
fn a_recorded_run_reapplies_suppression_ordering() {
    let dir = suite_fixture();
    let root = dir.path();
    std::fs::write(root.join("src/production_a.rs"), ALPHA_RS).unwrap();
    std::fs::write(root.join("src/production_b.rs"), ALPHA_RS).unwrap();

    let scanned = scan_json(root);
    let scanned_groups = scanned["groups"].as_array().expect("groups array");
    let first_test = scanned_groups
        .iter()
        .position(|group| group["test_code"] == true)
        .expect("test-suite duplication");
    let first_production = scanned_groups
        .iter()
        .position(|group| group["test_code"] == false)
        .expect("production duplication");
    assert!(
        first_production < first_test,
        "rank-down puts test-suite duplication after production findings"
    );
    let run_id = scanned["run"]["run_id"]
        .as_i64()
        .expect("scan JSON carries the recorded run id");

    // Replay must not reinterpret the historical ordering through whatever
    // policy happens to be on disk now.
    std::fs::write(
        root.join("codehelion.toml"),
        "[suppression]\ntest-code = \"report\"\n",
    )
    .unwrap();

    let output = cmd()
        .current_dir(root)
        .args(["report", "--run", &run_id.to_string(), "--format", "json"])
        .output()
        .expect("reformat recorded Structural report");
    assert!(output.status.success(), "{output:?}");
    let recorded: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("recorded report is JSON");
    assert_eq!(
        recorded["groups"], scanned["groups"],
        "report preserves the recorded suppression-aware ordering after the current policy changes"
    );
}
