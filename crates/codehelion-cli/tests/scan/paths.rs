//! Where the audit database and the written report end up, which paths a
//! scan will follow, and the hints about the database directory.

use super::*;

/// A configuration naming where the database goes.
///
/// Written as a TOML literal string rather than a basic one, because a
/// Windows path is mostly backslashes and a basic string reads each of them
/// as the start of an escape.
fn database_setting(path: &Path) -> String {
    format!("database = '{}'\n", path.display())
}

#[test]
fn output_flag_writes_the_report_to_a_file() {
    let dir = fixture();
    let output = cmd()
        .current_dir(dir.path())
        .args([
            "scan",
            ".",
            "--decoration",
            "unicode",
            "--output",
            "report.txt",
        ])
        .output()
        .expect("run redirected scan");
    assert!(output.status.success(), "{output:?}");
    let expected_hint = database_directory_hint_line(dir.path());
    assert_database_hint_lines(&output.stderr, Some(&expected_hint), 1);
    // Progress about a redirected report and the first-run hint both belong
    // on stderr, never in the report's place on standard output.
    assert!(
        output.stdout.is_empty(),
        "redirected report unexpectedly wrote stdout: {}",
        String::from_utf8_lossy(&output.stdout),
    );
    assert!(
        !String::from_utf8_lossy(&output.stdout).contains(DATABASE_DIRECTORY_HINT),
        "database-directory hint leaked into stdout: {}",
        String::from_utf8_lossy(&output.stdout),
    );
    assert!(
        !String::from_utf8_lossy(&output.stdout).contains("wrote report.txt"),
        "redirect progress leaked into stdout: {}",
        String::from_utf8_lossy(&output.stdout),
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("wrote report.txt"),
        "redirect progress missing from stderr: {}",
        String::from_utf8_lossy(&output.stderr),
    );
    let report = std::fs::read_to_string(dir.path().join("report.txt")).unwrap();
    assert!(report.contains("codehelion scan · fast mode ·"));
    assert!(report.contains("groups"));
    assert!(
        !report.contains(DATABASE_DIRECTORY_HINT),
        "database-directory hint leaked into report file: {report}",
    );
}

#[test]
fn output_flag_preserves_an_existing_file_unless_forced() {
    let dir = fixture();
    let destination = dir.path().join("report.txt");
    std::fs::write(&destination, "do not replace\n").expect("write existing report");

    let failed = cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "--output", "report.txt"])
        .output()
        .expect("run scan with an existing output");
    assert!(!failed.status.success(), "{failed:?}");
    assert!(
        String::from_utf8_lossy(&failed.stderr).contains("refusing to overwrite"),
        "{}",
        String::from_utf8_lossy(&failed.stderr),
    );
    assert_database_hint_lines(&failed.stderr, None, 0);
    assert!(
        dir.path().join(".codehelion").is_dir(),
        "database directory is created before report output is attempted",
    );
    assert_eq!(
        std::fs::read_to_string(&destination).expect("read preserved report"),
        "do not replace\n"
    );

    cmd()
        .current_dir(dir.path())
        .args([
            "scan",
            ".",
            "--decoration",
            "unicode",
            "--output",
            "report.txt",
            "--force",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("wrote report.txt"));
    let report = std::fs::read_to_string(destination).expect("read forced report");
    assert!(report.contains("codehelion scan · fast mode ·"));
}

#[test]
fn db_flag_overrides_the_database_location() {
    let dir = fixture();
    cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "--db", "custom/audit.db"])
        .assert()
        .success();
    assert!(dir.path().join("custom/audit.db").is_file());
    assert!(!dir.path().join(".codehelion/audit.db").exists());
}

/// A discovered repository configuration has no authority to direct storage
/// outside the tree. Both scan's `SQLite` creation and cache clear use the same
/// resolver, while a person who names `--db` still deliberately has that
/// authority.
#[test]
fn discovered_database_paths_cannot_escape_the_scan_tree() {
    let tree = tempfile::tempdir().expect("temp tree");
    let root = tree.path().join("repository");
    let outside = tree.path().join("outside");
    std::fs::create_dir_all(root.join(".git")).unwrap();
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(root.join("src/a.rs"), CHECKSUM_RS).unwrap();
    std::fs::write(root.join("src/b.rs"), CHECKSUM_RS).unwrap();

    let absolute = outside.join("absolute.db");
    for database in [
        database_setting(&absolute),
        "database = \"../outside/traversal.db\"\n".to_string(),
    ] {
        std::fs::write(root.join("codehelion.toml"), database).unwrap();
        cmd()
            .current_dir(&root)
            .args(["scan", "."])
            .assert()
            .failure()
            .stderr(predicate::str::contains("refusing database path"))
            .stderr(predicate::str::contains("--db <path>"));
        assert!(!absolute.exists());
        assert!(!outside.join("traversal.db").exists());
    }

    let retained = outside.join("retain.db");
    std::fs::write(&retained, "must survive cache clear").unwrap();
    for database in [
        database_setting(&retained),
        "database = \"../outside/retain.db\"\n".to_string(),
    ] {
        std::fs::write(root.join("codehelion.toml"), database).unwrap();
        cmd()
            .current_dir(&root)
            .args(["cache", "clear", "--force"])
            .assert()
            .failure()
            .stderr(predicate::str::contains("refusing database path"));
        assert_eq!(
            std::fs::read_to_string(&retained).unwrap(),
            "must survive cache clear"
        );
    }

    let trusted_configured = outside.join("trusted-configured.db");
    std::fs::write(
        root.join("codehelion.toml"),
        database_setting(&trusted_configured),
    )
    .unwrap();
    cmd()
        .current_dir(&root)
        .args(["scan", ".", "--config", "codehelion.toml"])
        .assert()
        .success();
    assert!(trusted_configured.is_file());

    let untrusted_configured = outside.join("untrusted-configured.db");
    std::fs::write(
        root.join("codehelion.toml"),
        database_setting(&untrusted_configured),
    )
    .unwrap();
    cmd()
        .current_dir(&root)
        .args(["scan", ".", "--config", "codehelion.toml", "--untrusted"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("refusing database path"));
    assert!(!untrusted_configured.exists());

    let explicit = outside.join("explicit.db");
    cmd()
        .current_dir(&root)
        .args([
            "scan",
            ".",
            "--untrusted",
            "--db",
            explicit.to_str().expect("temporary path is UTF-8"),
        ])
        .assert()
        .success();
    assert!(explicit.is_file());
    cmd()
        .current_dir(&root)
        .args([
            "cache",
            "clear",
            "--force",
            "--db",
            explicit.to_str().expect("temporary path is UTF-8"),
        ])
        .assert()
        .success();
    assert!(!explicit.exists());
}

/// Reading a recorded audit is confined by the same boundary that recording
/// one is: a configuration a distrusting run was handed cannot send the read
/// outside the tree either. The database there is real and a trusting run
/// replays it, so the refusal is what the flag did rather than a missing file.
#[test]
fn a_distrusting_report_cannot_read_a_database_outside_the_scan_tree() {
    let tree = tempfile::tempdir().expect("temp tree");
    let root = tree.path().join("repository");
    let outside = tree.path().join("outside");
    std::fs::create_dir_all(root.join(".git")).unwrap();
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(root.join("src/a.rs"), CHECKSUM_RS).unwrap();
    std::fs::write(root.join("src/b.rs"), CHECKSUM_RS).unwrap();

    let recorded = outside.join("recorded.db");
    cmd()
        .current_dir(&root)
        .args([
            "scan",
            ".",
            "--db",
            recorded.to_str().expect("temporary path is UTF-8"),
        ])
        .assert()
        .success();
    assert!(recorded.is_file());

    std::fs::write(root.join("codehelion.toml"), database_setting(&recorded)).unwrap();
    cmd()
        .current_dir(&root)
        .args(["report", "--config", "codehelion.toml", "--format", "json"])
        .assert()
        .success();
    cmd()
        .current_dir(&root)
        .args([
            "report",
            "--config",
            "codehelion.toml",
            "--format",
            "json",
            "--untrusted",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("refusing database path"))
        .stderr(predicate::str::contains("--db <path>"));
}

/// A lexical relative path is not enough: a repository can place a symlink
/// below its root that would redirect `SQLite` creation or cache deletion.
#[cfg(unix)]
#[test]
fn discovered_database_paths_cannot_escape_through_existing_symlinks() {
    let tree = tempfile::tempdir().expect("temp tree");
    let root = tree.path().join("repository");
    let outside = tree.path().join("outside");
    std::fs::create_dir_all(root.join(".git")).unwrap();
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(root.join("src/a.rs"), CHECKSUM_RS).unwrap();
    std::fs::write(root.join("src/b.rs"), CHECKSUM_RS).unwrap();
    std::os::unix::fs::symlink(&outside, root.join("storage")).unwrap();

    std::fs::write(
        root.join("codehelion.toml"),
        "database = \"storage/scan.db\"\n",
    )
    .unwrap();
    cmd()
        .current_dir(&root)
        .args(["scan", "."])
        .assert()
        .failure()
        .stderr(predicate::str::contains("refusing database path"));
    assert!(!outside.join("scan.db").exists());

    let retained = outside.join("retained.db");
    std::fs::write(&retained, "must survive symlinked cache clear").unwrap();
    std::fs::write(
        root.join("codehelion.toml"),
        "database = \"storage/retained.db\"\n",
    )
    .unwrap();
    cmd()
        .current_dir(&root)
        .args(["cache", "clear", "--force"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("refusing database path"));
    assert_eq!(
        std::fs::read_to_string(retained).unwrap(),
        "must survive symlinked cache clear"
    );
}

#[test]
fn default_database_is_placed_at_the_repository_root_for_a_subtree_scan() {
    let dir = fixture();
    cmd()
        .current_dir(dir.path())
        .args(["scan", "src"])
        .assert()
        .success();

    assert!(dir.path().join(".codehelion/audit.db").is_file());
    assert!(!dir.path().join("src/.codehelion/audit.db").exists());
}

#[test]
fn doctor_hints_until_the_database_is_gitignored() {
    let dir = fixture();
    cmd()
        .current_dir(dir.path())
        .arg("doctor")
        .assert()
        .success()
        .stdout(predicate::str::contains("local database:"))
        .stdout(predicate::str::contains("hint:"));

    std::fs::write(dir.path().join(".gitignore"), ".codehelion/\n").unwrap();
    cmd()
        .current_dir(dir.path())
        .arg("doctor")
        .assert()
        .success()
        .stdout(predicate::str::contains("hint:").not());
}

const DATABASE_DIRECTORY_HINT: &str = "created local database directory";

fn database_directory_hint_line(root: &Path) -> String {
    let directory = codehelion_core::paths::canonical(root)
        .expect("canonicalize scan root")
        .join(".codehelion");
    format!(
        "note: created local database directory {}; consider adding `.codehelion/` to .gitignore",
        directory.display(),
    )
}

fn assert_database_hint_lines(stderr: &[u8], expected: Option<&str>, count: usize) {
    let stderr = String::from_utf8_lossy(stderr);
    let lines: Vec<_> = stderr
        .lines()
        .filter(|line| line.contains(DATABASE_DIRECTORY_HINT))
        .collect();
    assert_eq!(
        lines.len(),
        count,
        "database-directory hint lines: {lines:?}; full stderr: {stderr}",
    );
    if let Some(expected) = expected {
        assert_eq!(
            lines,
            vec![expected],
            "database-directory hint must be one exact line; full stderr: {stderr}",
        );
    }
}

fn parse_json_scan(output: &std::process::Output) -> serde_json::Value {
    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains(DATABASE_DIRECTORY_HINT),
        "database-directory hint leaked into stdout: {stdout}",
    );
    serde_json::from_slice(&output.stdout).expect("scan output is one JSON document")
}

#[test]
fn the_first_scan_hints_about_a_new_unignored_database_directory_only_once() {
    let dir = fixture();
    let first = cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "--format", "json"])
        .output()
        .expect("run first scan");
    let first_report = parse_json_scan(&first);
    assert!(first_report["run"]["run_id"].is_number());
    let expected_hint = database_directory_hint_line(dir.path());
    assert_database_hint_lines(&first.stderr, Some(&expected_hint), 1);

    let second = cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "--format", "json"])
        .output()
        .expect("run second scan");
    let second_report = parse_json_scan(&second);
    assert_eq!(
        second_report["run"]["run_id"],
        first_report["run"]["run_id"]
    );
    assert_database_hint_lines(&second.stderr, None, 0);
}

#[test]
fn a_gitignored_database_directory_does_not_get_a_first_scan_hint() {
    let dir = fixture();
    std::fs::write(dir.path().join(".gitignore"), ".codehelion/\n").unwrap();
    let output = cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "--format", "json"])
        .output()
        .expect("run ignored-directory scan");
    parse_json_scan(&output);
    assert_database_hint_lines(&output.stderr, None, 0);
}

#[test]
fn an_explicit_database_path_does_not_get_a_default_directory_hint() {
    let dir = fixture();
    let external = tempfile::tempdir().expect("external database directory");
    let database = external.path().join("audit.db");
    let output = cmd()
        .current_dir(dir.path())
        .args([
            "scan",
            ".",
            "--format",
            "json",
            "--db",
            database.to_str().expect("temporary path is UTF-8"),
        ])
        .output()
        .expect("run explicit-database scan");
    parse_json_scan(&output);
    assert!(database.is_file());
    assert_database_hint_lines(&output.stderr, None, 0);
}

#[test]
fn structural_scans_use_the_same_first_directory_hint() {
    let dir = fixture();
    let output = cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "--mode", "structural", "--format", "json"])
        .output()
        .expect("run first structural scan");
    parse_json_scan(&output);
    let expected_hint = database_directory_hint_line(dir.path());
    assert_database_hint_lines(&output.stderr, Some(&expected_hint), 1);
}
