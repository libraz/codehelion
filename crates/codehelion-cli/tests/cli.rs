//! End-to-end tests that run the compiled binary.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use assert_cmd::Command;
use fs2::FileExt;
use object::write::{Object as WriteObject, StandardSection, Symbol, SymbolSection};
use object::{Architecture, BinaryFormat, Endianness, SymbolFlags, SymbolKind, SymbolScope};
use predicates::prelude::*;
use std::fs::OpenOptions;

fn cmd() -> Command {
    Command::cargo_bin("codehelion").expect("binary should build")
}

/// A temporary directory, spelled the way the commands under test spell it.
///
/// [`std::fs::canonicalize`] answers a Windows path in the verbatim `\\?\`
/// form. No command prints that form: each resolves the path it was given
/// through [`codehelion_core::paths::canonical`], which drops the prefix
/// wherever the ordinary spelling names the same file. A fixture built from
/// the other form therefore expects a path that appears in no output, and the
/// test fails on Windows for a reason that has nothing to do with what it is
/// checking.
fn resolved_root(directory: &tempfile::TempDir) -> std::path::PathBuf {
    codehelion_core::paths::canonical(directory.path()).expect("resolve temp dir")
}

fn macho_fixture() -> Vec<u8> {
    let mut object = WriteObject::new(
        BinaryFormat::MachO,
        Architecture::X86_64,
        Endianness::Little,
    );
    let text = object.section_id(StandardSection::Text);
    let offset = object.append_section_data(text, &[0x90, 0xc3], 1);
    object.add_symbol(Symbol {
        name: b"render".to_vec(),
        value: offset,
        size: 2,
        kind: SymbolKind::Text,
        scope: SymbolScope::Dynamic,
        weak: false,
        section: SymbolSection::Section(text),
        flags: SymbolFlags::None,
    });
    object.write().expect("write Mach-O fixture")
}

#[test]
fn doctor_succeeds() {
    cmd().arg("doctor").assert().success();
}

#[test]
fn doctor_reports_own_version() {
    cmd()
        .arg("doctor")
        .assert()
        .success()
        .stdout(predicate::str::contains("codehelion"))
        .stdout(predicate::str::contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn doctor_reports_an_incompatible_database_without_replacing_it() {
    let directory = tempfile::tempdir().expect("temp dir");
    let cache = directory.path().join(".codehelion");
    let database = cache.join("audit.db");
    std::fs::create_dir_all(&cache).expect("create cache directory");
    codehelion_store::Store::open(&database).expect("create database");
    let connection = rusqlite::Connection::open(&database).expect("open database");
    connection
        .execute("UPDATE schema_meta SET version = 999", [])
        .expect("change schema version");

    cmd()
        .current_dir(directory.path())
        .arg("doctor")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "database health: unreadable (database schema version 999",
        ));

    let version: i64 = connection
        .query_row("SELECT version FROM schema_meta", [], |row| row.get(0))
        .expect("read schema version");
    assert_eq!(version, 999, "doctor must not replace the database");
}

#[test]
fn doctor_and_cache_status_report_a_live_database_lease() {
    let directory = tempfile::tempdir().expect("temp dir");
    let cache = directory.path().join(".codehelion");
    let database = cache.join("audit.db");
    std::fs::create_dir_all(&cache).expect("create cache directory");
    codehelion_store::Store::open(&database).expect("create database");
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(cache.join("audit.db.lock"))
        .expect("open database lease");
    FileExt::try_lock_exclusive(&lock).expect("test holds database lease");

    for arguments in [["doctor"].as_slice(), ["cache", "status"].as_slice()] {
        cmd()
            .current_dir(directory.path())
            .args(arguments)
            .assert()
            .success()
            .stdout(predicate::str::contains(
                "database lease: held by another codehelion scan or cache command",
            ));
    }
}

/// A tree with one source file and a real database whose recorded schema
/// version is not the one this build writes.
///
/// The version is taken from the build rather than written as a literal, so
/// the fixture keeps describing "another schema version" after the store's own
/// version moves.
fn tree_with_a_database_from_another_schema_version(
    root: &std::path::Path,
    database: &std::path::Path,
) {
    std::fs::write(root.join("lib.rs"), "pub fn tiny() {}\n").expect("write source");
    if let Some(parent) = database.parent() {
        std::fs::create_dir_all(parent).expect("create database directory");
    }
    codehelion_store::Store::open(database).expect("create database");
    let connection = rusqlite::Connection::open(database).expect("open database");
    connection
        .execute(
            "UPDATE schema_meta SET version = ?1",
            [other_schema_version()],
        )
        .expect("record another schema version");
}

/// A schema version this build does not write.
const fn other_schema_version() -> i64 {
    codehelion_store::schema::SCHEMA_VERSION + 1
}

/// The name a run gives the database it writes beside an incompatible one.
fn database_name_for_this_schema() -> String {
    format!("audit-v{}.db", codehelion_store::schema::SCHEMA_VERSION)
}

#[test]
fn scan_records_beside_a_default_database_written_by_another_schema_version() {
    let directory = tempfile::tempdir().expect("temp dir");
    let root = resolved_root(&directory);
    let cache = root.join(".codehelion");
    tree_with_a_database_from_another_schema_version(&root, &cache.join("audit.db"));

    cmd()
        .args(["scan", root.to_str().expect("scan path")])
        .assert()
        .success();

    let recorded = cache.join(database_name_for_this_schema());
    let store = codehelion_store::Store::open_existing(&recorded)
        .expect("the run recorded itself beside the incompatible database");
    assert_eq!(
        store.schema_version().expect("recorded schema version"),
        codehelion_store::schema::SCHEMA_VERSION
    );
    assert_eq!(
        store.table_count("scan_run").expect("recorded runs"),
        1,
        "the completed run must be readable from the database it used"
    );
}

#[test]
fn stepping_around_a_default_database_says_so_and_leaves_it_unchanged() {
    let directory = tempfile::tempdir().expect("temp dir");
    let root = resolved_root(&directory);
    let cache = root.join(".codehelion");
    let incompatible = cache.join("audit.db");
    tree_with_a_database_from_another_schema_version(&root, &incompatible);
    let before = std::fs::read(&incompatible).expect("read database before the scan");

    let output = cmd()
        .args(["scan", root.to_str().expect("scan path")])
        .output()
        .expect("run scan beside an incompatible database");

    assert!(output.status.success(), "scan unexpectedly failed");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(&format!(
            "note: {} was written by another schema version and was left unchanged; codehelion used {}",
            incompatible.display(),
            cache.join(database_name_for_this_schema()).display(),
        )),
        "{stderr}"
    );
    assert_eq!(
        std::fs::read(&incompatible).expect("read database after the scan"),
        before,
        "the database this build cannot open must be left byte for byte as it was"
    );
}

#[test]
fn an_explicitly_named_incompatible_database_is_still_refused() {
    let directory = tempfile::tempdir().expect("temp dir");
    let root = resolved_root(&directory);
    let named = root.join("audit.db");
    tree_with_a_database_from_another_schema_version(&root, &named);

    let output = cmd()
        .args([
            "scan",
            root.to_str().expect("scan path"),
            "--db",
            named.to_str().expect("database path"),
        ])
        .output()
        .expect("run scan against a named incompatible database");

    assert!(
        !output.status.success(),
        "a named database that could not be written must not report success"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(&format!(
            "database schema version {} is not supported",
            other_schema_version()
        )),
        "{stderr}"
    );
    assert!(
        !stderr.contains("codehelion used"),
        "a named database must not be traded for another one: {stderr}"
    );
    // Refusing is right; refusing without naming a way forward is not. The
    // reader cannot guess the neighbour's name, because the naming rule is
    // this build's, so the refusal spells it and both ways out of it.
    let sibling = root.join(database_name_for_this_schema());
    assert!(
        stderr.contains(&format!(
            "record beside it with --db {}, or drop --db to let codehelion choose a database it can open",
            sibling.display()
        )),
        "{stderr}"
    );
    assert!(
        !sibling.exists(),
        "a named database must not gain a neighbour nobody asked for"
    );
}

#[test]
fn a_compatible_default_database_is_used_without_creating_a_second_one() {
    let directory = tempfile::tempdir().expect("temp dir");
    let root = resolved_root(&directory);
    let cache = root.join(".codehelion");
    std::fs::write(root.join("lib.rs"), "pub fn tiny() {}\n").expect("write source");
    std::fs::create_dir_all(&cache).expect("create database directory");
    codehelion_store::Store::open(&cache.join("audit.db")).expect("create database");

    let output = cmd()
        .args(["scan", root.to_str().expect("scan path")])
        .output()
        .expect("run scan against a compatible database");

    assert!(output.status.success(), "scan unexpectedly failed");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("was written by another schema version"),
        "{stderr}"
    );
    assert!(
        !cache.join(database_name_for_this_schema()).exists(),
        "a database this build can open is the one it must keep writing"
    );
}

/// Every reader arrives at the database the scan recorded into.
///
/// The scan settling on a neighbour and the next command opening the original
/// is one tool disagreeing with itself: the report the scan just printed names
/// findings the reader is then told do not exist.
#[test]
fn readers_open_the_database_the_scan_recorded_into() {
    let directory = tempfile::tempdir().expect("temp dir");
    let root = resolved_root(&directory);
    let cache = root.join(".codehelion");
    tree_with_a_database_from_another_schema_version(&root, &cache.join("audit.db"));
    cmd()
        .args(["scan", root.to_str().expect("scan path")])
        .assert()
        .success();
    let recorded = cache.join(database_name_for_this_schema());
    assert!(recorded.is_file(), "the scan recorded beside the old one");

    for arguments in [
        vec!["report".to_owned()],
        vec!["baseline".to_owned(), "create".to_owned()],
        vec!["cache".to_owned(), "status".to_owned()],
    ] {
        let output = cmd()
            .current_dir(&root)
            .args(&arguments)
            .output()
            .expect("run a reader beside an incompatible database");
        assert!(
            output.status.success(),
            "{arguments:?} did not find the recorded run: {output:?}"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains(&format!(
                "was written by another schema version and was left unchanged; codehelion used {}",
                recorded.display()
            )),
            "{arguments:?} stepped aside without saying so: {stderr}"
        );
    }
}

/// A reader makes no database. Being unable to open the one that is there and
/// having nothing scanned yet are different situations, and inventing an empty
/// neighbour would report the second when the first is true.
#[test]
fn a_reader_does_not_create_the_neighbour_a_scan_would() {
    let directory = tempfile::tempdir().expect("temp dir");
    let root = resolved_root(&directory);
    let cache = root.join(".codehelion");
    tree_with_a_database_from_another_schema_version(&root, &cache.join("audit.db"));

    let output = cmd()
        .current_dir(&root)
        .arg("report")
        .output()
        .expect("run report before any scan");

    assert!(
        !output.status.success(),
        "there is no recorded run to report on"
    );
    assert!(
        !cache.join(database_name_for_this_schema()).exists(),
        "a reader must not leave an empty audit database behind"
    );
    // Refused, and told where the two ways forward are.
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--db"), "{stderr}");
}

/// `cache clear` and `cache prune` act on the file they were pointed at.
///
/// Following the step-aside rule here would delete the history in use while
/// leaving the stale file the reader meant to be rid of.
#[test]
fn clearing_the_cache_does_not_follow_the_step_aside_rule() {
    let directory = tempfile::tempdir().expect("temp dir");
    let root = resolved_root(&directory);
    let cache = root.join(".codehelion");
    let incompatible = cache.join("audit.db");
    tree_with_a_database_from_another_schema_version(&root, &incompatible);
    cmd()
        .args(["scan", root.to_str().expect("scan path")])
        .assert()
        .success();
    let recorded = cache.join(database_name_for_this_schema());
    assert!(recorded.is_file());

    cmd()
        .current_dir(&root)
        .args(["cache", "clear", "--force"])
        .assert()
        .success();

    assert!(
        !incompatible.exists(),
        "the database that was named is the one that goes"
    );
    assert!(
        recorded.is_file(),
        "the history this build actually writes must survive a clear aimed elsewhere"
    );
    // And doctor said as much before anyone typed --force.
    cmd()
        .current_dir(&root)
        .arg("doctor")
        .assert()
        .success()
        .stdout(predicate::str::contains("a read would use"));
}

/// The only recording failure a run steps around is the one it can settle by
/// itself. Everything else still fails, so a gated pipeline cannot go green
/// against a database it never wrote to.
#[cfg(unix)]
#[test]
fn a_recording_failure_that_is_not_a_schema_mismatch_still_fails_the_scan() {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempfile::tempdir().expect("temp dir");
    let root = resolved_root(&directory);
    let cache = root.join(".codehelion");
    let database = cache.join("audit.db");
    std::fs::write(root.join("lib.rs"), "pub fn tiny() {}\n").expect("write source");
    std::fs::create_dir_all(&cache).expect("create database directory");
    codehelion_store::Store::open(&database).expect("create database");
    std::fs::set_permissions(&database, std::fs::Permissions::from_mode(0o444))
        .expect("make the database read-only");

    let output = cmd()
        .args(["scan", root.to_str().expect("scan path")])
        .output()
        .expect("run scan against a read-only database");

    std::fs::set_permissions(&database, std::fs::Permissions::from_mode(0o644))
        .expect("restore the database permissions");
    assert!(
        !output.status.success(),
        "a run that recorded nothing must not report success"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("this run was not recorded"), "{stderr}");
    assert!(
        !cache.join(database_name_for_this_schema()).exists(),
        "only a schema version this build cannot open is written around"
    );
}

#[test]
fn doctor_lists_the_databases_in_the_directory_and_names_the_one_a_scan_would_use() {
    let directory = tempfile::tempdir().expect("temp dir");
    let root = resolved_root(&directory);
    let cache = root.join(".codehelion");
    tree_with_a_database_from_another_schema_version(&root, &cache.join("audit.db"));
    let recorded = cache.join(database_name_for_this_schema());
    codehelion_store::Store::open(&recorded).expect("create the database for this build");

    cmd()
        .args(["doctor", "--path", root.to_str().expect("doctor path")])
        .assert()
        .success()
        .stdout(predicate::str::contains(format!(
            "  databases in {}:",
            cache.display()
        )))
        .stdout(predicate::str::contains(format!(
            "audit.db: schema {}, not readable by this build",
            other_schema_version()
        )))
        .stdout(predicate::str::contains(format!(
            "{}: schema {}, readable by this build",
            database_name_for_this_schema(),
            codehelion_store::schema::SCHEMA_VERSION
        )))
        .stdout(predicate::str::contains(format!(
            "  a scan would use {}",
            recorded.display()
        )));
}

#[test]
fn scan_rejects_an_incompatible_database_without_replacing_it() {
    let directory = tempfile::tempdir().expect("temp dir");
    let database = directory.path().join("audit.db");
    let source = directory.path().join("lib.rs");
    std::fs::write(&source, "pub fn tiny() {}\n").expect("write source");
    codehelion_store::Store::open(&database).expect("create database");
    let connection = rusqlite::Connection::open(&database).expect("open database");
    connection
        .execute("UPDATE schema_meta SET version = 1", [])
        .expect("change schema version");
    connection
        .execute_batch(
            "CREATE TABLE sentinel (value TEXT NOT NULL);
             INSERT INTO sentinel (value) VALUES ('keep-me');",
        )
        .expect("write sentinel data");
    drop(connection);

    let before_main = std::fs::read(&database).expect("read database before rejection");
    let sidecars = [
        database.with_file_name("audit.db-wal"),
        database.with_file_name("audit.db-shm"),
    ];
    std::fs::write(&sidecars[0], b"wal-sentinel").expect("write WAL sentinel");
    std::fs::write(&sidecars[1], b"shm-sentinel").expect("write SHM sentinel");
    let before_sidecars = sidecars
        .iter()
        .map(|path| std::fs::read(path).expect("read sidecar before rejection"))
        .collect::<Vec<_>>();

    let output = cmd()
        .args([
            "scan",
            directory.path().to_str().expect("scan path"),
            "--db",
            database.to_str().expect("database path"),
        ])
        .output()
        .expect("run scan against incompatible database");
    assert!(!output.status.success(), "scan unexpectedly succeeded");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("database schema version 1"), "{stderr}");
    assert!(
        stderr.contains("automatic migration is not supported"),
        "{stderr}"
    );
    assert!(
        stderr.contains("existing database was left unchanged"),
        "{stderr}"
    );
    assert!(stderr.contains("fresh scan"), "{stderr}");
    assert_eq!(
        std::fs::read(&database).expect("read database after rejection"),
        before_main
    );
    // The write-ahead log is durable state and has to survive byte for byte.
    // The shared-memory index beside it is not: SQLite rebuilds it whenever it
    // opens the database, including the read-only open the version check uses,
    // so only its presence is a fact about the rejection.
    assert_eq!(
        std::fs::read(&sidecars[0]).expect("read write-ahead log after rejection"),
        before_sidecars[0]
    );
    assert!(
        sidecars[1].exists(),
        "the shared-memory index was removed rather than left in place"
    );
    let verification = directory.path().join("verification.db");
    std::fs::copy(&database, &verification).expect("copy main database for verification");
    let verification_connection = rusqlite::Connection::open(&verification)
        .expect("open verified copy of unchanged main database");
    assert_eq!(
        verification_connection
            .query_row("SELECT version FROM schema_meta", [], |row| row
                .get::<_, i64>(0))
            .expect("read preserved schema version"),
        1
    );
    assert_eq!(
        verification_connection
            .query_row("SELECT value FROM sentinel", [], |row| row
                .get::<_, String>(0))
            .expect("read preserved sentinel"),
        "keep-me"
    );
}

#[test]
fn doctor_reports_the_restricted_semantic_rule_registry() {
    cmd()
        .arg("doctor")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "restricted semantic rules: 8 enabled; 4 cross-language rules require --compare-languages",
        ))
        .stdout(predicate::str::contains("semantic-rule-registry-v1"));
}

#[test]
fn doctor_reports_the_platform_sandbox_limitations() {
    let expected = if cfg!(target_os = "linux") {
        "OS memory ceilings available; network and filesystem containment unavailable"
    } else {
        "OS memory, network, and filesystem containment unavailable"
    };
    cmd()
        .arg("doctor")
        .assert()
        .success()
        .stdout(predicate::str::contains("child-process isolation"))
        .stdout(predicate::str::contains(expected));
}

#[test]
fn scan_help_marks_the_other_execution_classes_as_unimplemented() {
    cmd()
        .args(["scan", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Only build-script is implemented"))
        .stdout(predicate::str::contains("reserved protocol values"));
}

#[test]
fn scan_help_limits_jobs_to_the_parallel_frontend_stage() {
    cmd()
        .args(["scan", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Frontend read-and-lex worker threads",
        ))
        .stdout(predicate::str::contains(
            "Clone grouping and report rendering remain serial",
        ));
}

#[test]
fn artifact_compare_help_exposes_the_input_format_assertion() {
    cmd()
        .args(["artifact", "compare", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--input-format"))
        .stdout(predicate::str::contains("--untrusted"))
        .stdout(predicate::str::contains(
            "This is an assertion, not an override",
        ));
}

#[test]
fn artifact_calibration_rejects_a_source_run_that_does_not_exist() {
    let directory = tempfile::tempdir().expect("database directory");
    let database = directory.path().join("audit.db");
    codehelion_store::Store::open(&database).expect("create empty database");
    cmd()
        .args([
            "artifact",
            "calibration",
            "--source-run",
            "999",
            "--db",
            database.to_str().expect("database path"),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "scan run 999 was not found in this database",
        ));
}

#[test]
fn artifact_read_commands_do_not_create_an_absent_database() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("missing.db");
    let database_arg = database.to_str().expect("database path");

    cmd()
        .args([
            "artifact",
            "report",
            "--analysis",
            "1",
            "--db",
            database_arg,
        ])
        .assert()
        .failure();
    assert!(
        !database.exists(),
        "artifact report created its input database"
    );

    cmd()
        .args([
            "artifact",
            "calibration",
            "--source-run",
            "1",
            "--db",
            database_arg,
        ])
        .assert()
        .failure();
    assert!(
        !database.exists(),
        "artifact calibration created its input database"
    );
}

#[test]
fn corrupted_database_error_is_not_repeated_in_the_cli_context_chain() {
    let database = tempfile::NamedTempFile::new().expect("database path");
    std::fs::write(database.path(), b"not an sqlite database").expect("write corrupt database");
    let assertion = cmd()
        .args([
            "artifact",
            "calibration",
            "--source-run",
            "1",
            "--db",
            database.path().to_str().expect("database path"),
        ])
        .assert()
        .failure();
    let stderr = String::from_utf8_lossy(&assertion.get_output().stderr);
    assert_eq!(
        stderr.matches("file is not a database").count(),
        1,
        "{stderr}"
    );
}

#[test]
fn semantic_scan_rejects_an_invalid_compilation_database() {
    let directory = tempfile::tempdir().expect("project directory");
    std::fs::write(directory.path().join("compile_commands.json"), b"[{")
        .expect("write truncated compilation database");

    cmd()
        .current_dir(directory.path())
        .args(["scan", ".", "--mode", "semantic"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "cannot read compile_commands.json for semantic analysis",
        ));
}

#[test]
fn structural_scan_does_not_report_different_binary_operators_as_type2() {
    let directory = tempfile::tempdir().expect("project directory");
    std::fs::create_dir_all(directory.path().join("src")).expect("create source directory");
    std::fs::write(
        directory.path().join("src/lib.rs"),
        "pub fn add(values: &[u64]) -> u64 {\n    let mut total = 0;\n    for value in values {\n        total = total + *value;\n    }\n    total\n}\n\npub fn divide(values: &[u64]) -> u64 {\n    let mut total = 1;\n    for value in values {\n        total = total / (*value).max(1);\n    }\n    total\n}\n",
    )
    .expect("write source");
    std::fs::write(
        directory.path().join("codehelion.toml"),
        "min-clone-tokens = 1\n",
    )
    .expect("write configuration");

    let output = cmd()
        .current_dir(directory.path())
        .args(["scan", ".", "--mode", "structural", "--format", "json"])
        .output()
        .expect("run structural scan");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON report");
    assert!(
        report["groups"]
            .as_array()
            .expect("groups")
            .iter()
            .all(|group| group["clone_type"] != "type-2"),
        "{report}"
    );
}

#[test]
fn artifact_worker_failure_has_one_user_facing_error_prefix() {
    let directory = tempfile::tempdir().expect("fixture directory");
    let file = directory.path().join("not-an-artifact");
    let database = directory.path().join("artifact.sqlite");
    std::fs::write(&file, b"not an artifact").expect("write invalid artifact");
    // A database of its own: a run that names none takes the lease on the
    // one belonging to whatever directory the test happened to start in,
    // which two tests running at once cannot both hold.
    cmd()
        .args([
            "artifact",
            "analyze",
            file.to_str().expect("artifact path"),
            "--db",
            database.to_str().expect("database path"),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "artifact worker failed: could not recognise input as a supported artifact format",
        ))
        .stderr(predicate::str::contains("error: error:").not());
}

#[test]
fn debug_companion_is_accepted_without_a_source_run() {
    let directory = tempfile::tempdir().expect("fixture directory");
    let artifact = directory.path().join("module.wasm");
    let debug_file = directory.path().join("module.debug");
    let database = directory.path().join("artifact.sqlite");
    std::fs::write(&artifact, b"\0asm\x01\0\0\0").expect("write wasm fixture");
    std::fs::write(&debug_file, b"").expect("write debug companion");
    cmd()
        .args([
            "artifact",
            "analyze",
            artifact.to_str().expect("artifact path"),
            "--debug-file",
            debug_file.to_str().expect("debug companion path"),
            "--db",
            database.to_str().expect("database path"),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "--debug-file is only supported for ELF, Mach-O, and PE artifacts",
        ))
        .stderr(predicate::str::contains("--source-run").not());
}

#[test]
fn stale_automatically_discovered_dsym_is_reported_without_failing_analysis() {
    let directory = tempfile::tempdir().expect("fixture directory");
    let artifact = directory.path().join("app");
    let dsym = directory
        .path()
        .join("app.dSYM/Contents/Resources/DWARF/app");
    let database = directory.path().join("artifact.sqlite");
    std::fs::create_dir_all(dsym.parent().expect("dSYM parent")).expect("create dSYM parent");
    let bytes = macho_fixture();
    std::fs::write(&artifact, &bytes).expect("write Mach-O artifact");
    std::fs::write(&dsym, &bytes).expect("write stale dSYM");

    cmd()
        .args([
            "artifact",
            "analyze",
            artifact.to_str().expect("artifact path"),
            "--db",
            database.to_str().expect("database path"),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("source mappings: 0"))
        .stderr(predicate::str::contains(
            "warning: automatically discovered dSYM",
        ))
        .stderr(predicate::str::contains(
            "does not have the artifact's Mach-O UUID",
        ));
}

#[test]
fn readmes_document_the_cli_operations_flags_and_exit_statuses() {
    for readme in [
        include_str!("../../../README.md"),
        include_str!("../../../README_ja.md"),
    ] {
        for snippet in [
            "codehelion report --run 1",
            "codehelion explain <ID> --format json",
            "codehelion baseline create",
            "codehelion config show",
            "codehelion artifact report --analysis 1",
            "codehelion artifact calibration --source-run 1",
            "--debug-file companion",
            "--jobs <n>",
            "--db <path>",
            "--baseline <file>",
            "--config <file>",
            "--no-ignore",
            "--show-suppressed",
            "--include-trivial",
            "--fail-on-findings",
            "--compare-build-variants",
            "--compare-languages",
            "`3`:",
        ] {
            assert!(readme.contains(snippet), "README is missing {snippet}");
        }
    }
}

#[test]
fn readmes_document_canonical_build_variant_json_identities() {
    for readme in [
        include_str!("../../../README.md"),
        include_str!("../../../README_ja.md"),
    ] {
        assert!(readme.contains("--build-variant manifest.json"));
    }
    assert!(include_str!("../../../README.md").contains("whitespace and object-member ordering"));
    assert!(include_str!("../../../README_ja.md").contains("空白や object member の順序"));
}

/// Compression is explained as a mechanism, never as a measured ratio.
///
/// The size a compressor charges for a second copy of a byte sequence is
/// nearly nothing, which is exactly the redundancy deduplication removes. A
/// figure written by hand would be right for one build and wrong for the next,
/// and nothing here re-derives it, so both READMEs say why rather than how
/// much.
#[test]
fn readmes_explain_compressed_size_without_quoting_a_measured_ratio() {
    let english = include_str!("../../../README.md");
    for snippet in [
        "Compressed size moves less than uncompressed size does",
        "repeated byte sequence is the first thing a compressor folds away",
        "If your size budget is a compressed number, deduplication",
        "Measure both before and after your own refactor",
    ] {
        assert!(
            english.contains(snippet),
            "English README is missing {snippet}"
        );
    }

    let japanese = include_str!("../../../README_ja.md");
    for snippet in [
        "圧縮後のサイズは、非圧縮のサイズほどには動きません",
        "圧縮器が真っ先に畳むもの",
        "サイズの上限が圧縮後の値であるプロジェクトにとって、重複の解消はそのための手段ではありません",
        "自分のリファクタの前後で両方を測ってください",
    ] {
        assert!(
            japanese.contains(snippet),
            "Japanese README is missing {snippet}"
        );
    }
}

/// A baseline is for CI; following your own progress needs no baseline.
#[test]
fn readmes_tell_the_two_baseline_uses_apart() {
    let english = include_str!("../../../README.md");
    for snippet in [
        "A baseline is for freezing a threshold and defending it in CI",
        "own progress through a refactor does not need one",
        "nothing has to be created, kept in step, or committed",
    ] {
        assert!(
            english.contains(snippet),
            "English README is missing {snippet}"
        );
    }

    let japanese = include_str!("../../../README_ja.md");
    for snippet in [
        "baseline は閾値を凍結して CI で守るためのもの",
        "リファクタの進み具合を自分で追うだけなら baseline は要りません",
        "コミットするものもありません",
    ] {
        assert!(
            japanese.contains(snippet),
            "Japanese README is missing {snippet}"
        );
    }
}

/// How to read a similarity breakdown, stated as a reading and not a rule.
///
/// The tool reports what the occurrences have in common; deciding that two of
/// them collapse into one function is outside what it claims to know, so the
/// paragraph has to say so in as many words.
#[test]
fn readmes_read_a_similarity_breakdown_without_claiming_to_decide_it() {
    let english = include_str!("../../../README.md");
    for snippet in [
        "A group whose structure and control flow agree exactly",
        "function taking an argument for whatever differs",
        "of reading the numbers, not a rule the tool applies",
    ] {
        assert!(
            english.contains(snippet),
            "English README is missing {snippet}"
        );
    }

    let japanese = include_str!("../../../README_ja.md");
    for snippet in [
        "構造と制御フローが完全に一致していて識別子だけが一致しない",
        "違う部分を引数に取る 1 つの関数に畳めます",
        "数値の読み方であって、ツールが適用する規則ではありません",
    ] {
        assert!(
            japanese.contains(snippet),
            "Japanese README is missing {snippet}"
        );
    }
}

/// A build-variant manifest is written, not found.
///
/// The word names two things — the file describing how an artifact was built,
/// and the digest qualifying how sources were read — and a reader who takes
/// them for one thing goes looking for a source digest to copy into the file.
/// There is none, so both READMEs say so and show the file being written.
#[test]
fn readmes_say_a_build_variant_manifest_is_written_rather_than_found() {
    let english = include_str!("../../../README.md");
    for snippet in [
        "takes a file you write, not one to go looking for",
        "echo '{\"profile\":\"release\",\"target\":\"wasm32\",\"toolchain\":\"emcc-5.0.2\"}' > build-variant.json",
        "no source digest to find and copy into the manifest",
    ] {
        assert!(
            english.contains(snippet),
            "English README is missing {snippet}"
        );
    }

    let japanese = include_str!("../../../README_ja.md");
    for snippet in [
        "自分で書くファイルで、どこかにある既存のファイルを探すものではありません",
        "echo '{\"profile\":\"release\",\"target\":\"wasm32\",\"toolchain\":\"emcc-5.0.2\"}' > build-variant.json",
        "manifest に書き写すべき source 側の digest は存在しません",
    ] {
        assert!(
            japanese.contains(snippet),
            "Japanese README is missing {snippet}"
        );
    }
}

/// The manifest the README writes is a manifest the tool accepts.
#[test]
fn the_build_variant_manifest_the_readme_writes_is_accepted() {
    let directory = tempfile::tempdir().expect("fixture directory");
    let manifest = directory.path().join("build-variant.json");
    let artifact = directory.path().join("app.wasm");
    let database = directory.path().join("artifact.sqlite");
    std::fs::write(
        &manifest,
        r#"{"profile":"release","target":"wasm32","toolchain":"emcc-5.0.2"}"#,
    )
    .expect("write the manifest the README writes");
    std::fs::write(&artifact, b"\0asm\x01\0\0\0").expect("write wasm fixture");

    cmd()
        .args([
            "artifact",
            "analyze",
            artifact.to_str().expect("artifact path"),
            "--build-variant",
            manifest.to_str().expect("manifest path"),
            "--db",
            database.to_str().expect("database path"),
        ])
        .assert()
        .success()
        // The manifest path and its digest are told apart on the line that
        // prints both.
        .stdout(predicate::str::contains("build variant: "))
        .stdout(predicate::str::contains("(digest "));
}

/// The flag's own help says the same thing the README does.
#[test]
fn build_variant_help_says_the_two_conditions_are_not_matched_against_each_other() {
    let output = cmd()
        .args(["artifact", "analyze", "--help"])
        .output()
        .expect("artifact analyze help");
    assert!(output.status.success(), "{output:?}");
    let help = String::from_utf8(output.stdout).expect("help output");
    assert!(help.contains("JSON manifest you write"), "{help}");
    assert!(help.contains("does not have to match"), "{help}");
    assert!(
        help.contains("recorded side by side rather than checked against each other"),
        "{help}"
    );
}

#[test]
fn readmes_limit_jobs_to_frontend_parallelism() {
    assert!(
        include_str!("../../../README.md")
            .contains("clone grouping and report rendering remain serial")
    );
    assert!(
        include_str!("../../../README_ja.md")
            .contains("clone grouping と report rendering は serial")
    );
}

#[test]
fn japanese_readme_explains_the_fast_mode_comment_and_whitespace_normalization() {
    assert!(
        include_str!("../../../README_ja.md").contains("コメントと空白を除く"),
        "Japanese README must retain Fast-mode normalization semantics"
    );
}

#[test]
fn mode_help_describes_measurement_differences_and_safety() {
    let output = cmd().args(["scan", "--help"]).output().expect("scan help");
    assert!(output.status.success(), "{output:?}");
    let help = String::from_utf8(output.stdout).expect("help output");
    assert!(help.contains("identifier agreement"), "{help}");
    assert!(help.contains("similarity breakdown"), "{help}");
    assert!(help.contains("siblings"), "{help}");
    assert!(help.contains("near misses"), "{help}");
    assert!(help.contains("never runs target code"), "{help}");
    assert!(help.contains("--allow-execution"), "{help}");
}

#[test]
fn readmes_document_the_rescan_after_refactor_loop() {
    let english = include_str!("../../../README.md");
    for snippet in [
        "Rescanning after a refactor",
        "replacement you missed",
        "finishes in seconds",
        "codehelion artifact analyze path/to/binary",
    ] {
        assert!(
            english.contains(snippet),
            "English README is missing {snippet}"
        );
    }

    let japanese = include_str!("../../../README_ja.md");
    for snippet in [
        "リファクタ直後の再スキャン",
        "その呼び出し元は置換漏れです",
        "数秒で終わる",
        "codehelion artifact analyze path/to/binary",
    ] {
        assert!(
            japanese.contains(snippet),
            "Japanese README is missing {snippet}"
        );
    }
}

/// The relationship between exact and normalized duplication is stated as an
/// order of magnitude, never as a measured byte count: nothing re-derives a
/// figure written by hand, so one would drift the moment a build changed.
#[test]
fn readmes_scale_identical_code_folding_without_a_measured_byte_count() {
    let english = include_str!("../../../README.md");
    assert!(english.contains("thousands of times larger"));
    assert!(english.contains("exact and the normalized figure"));

    let japanese = include_str!("../../../README_ja.md");
    assert!(japanese.contains("その数千倍あります"));
    assert!(japanese.contains("exact と normalized の値"));
}

#[test]
fn readmes_explain_artifact_folding_and_size_relevance() {
    let english = include_str!("../../../README.md");
    let japanese = include_str!("../../../README_ja.md");
    assert!(english.contains("Identical code folding"));
    assert!(english.contains("Type-1 copies"));
    assert!(english.contains("Type-2 and Type-3 copies"));
    assert!(japanese.contains("identical code folding"));
    assert!(japanese.contains("Type-1"));
    assert!(japanese.contains("Type-2 / Type-3"));
}

/// The channel's own blind spot is documented, and the counts it produces are
/// left to the run that produces them: a figure written here has nothing that
/// re-derives it, and the summary now names both numbers per run.
#[test]
fn readmes_name_the_shape_of_code_signature_siblings_cannot_help() {
    let english = include_str!("../../../README.md");
    for snippet in [
        "A layer built on one signature gets nothing from that channel",
        "dispatch or callback table",
        "limits.signature-sibling-max-units-per-signature",
        "how far the widest one reached",
    ] {
        assert!(
            english.contains(snippet),
            "English README is missing {snippet}"
        );
    }

    let japanese = include_str!("../../../README_ja.md");
    for snippet in [
        "1 つのシグネチャで駆動する層に、このチャネルは何も与えません",
        "callback table",
        "limits.signature-sibling-max-units-per-signature",
        "いちばん広く共有されていたもの",
    ] {
        assert!(
            japanese.contains(snippet),
            "Japanese README is missing {snippet}"
        );
    }
}

#[test]
fn readmes_describe_opt_in_sibling_evidence_limits() {
    let english = include_str!("../../../README.md");
    for snippet in [
        "--siblings-by-signature",
        "off by default",
        "low-confidence sibling",
        "normalized signature",
        "same directory",
        "sibling-search ceiling",
        "mirror-consistency checker",
    ] {
        assert!(
            english.contains(snippet),
            "English README is missing {snippet}"
        );
    }

    let japanese = include_str!("../../../README_ja.md");
    for snippet in [
        "--siblings-by-signature",
        "既定では無効",
        "正規化済みシグネチャ",
        "低信頼度の sibling",
        "別ディレクトリ",
        "探索の上限",
        "ミラー整合性検査ツールではありません",
    ] {
        assert!(
            japanese.contains(snippet),
            "Japanese README is missing {snippet}"
        );
    }
}

#[test]
fn readmes_document_current_defaults_and_database_lifecycle() {
    for readme in [
        include_str!("../../../README.md"),
        include_str!("../../../README_ja.md"),
    ] {
        for snippet in [
            "codehelion.svg",
            "auto-generated",
            "autogenerated",
            ".codehelion/",
            "clippy.toml",
            "codehelion-helper-conformance/",
        ] {
            assert!(readme.contains(snippet), "README is missing {snippet}");
        }
    }
    assert!(
        include_str!("../../../README.md").contains("at least 8 characters"),
        "English README must state the clone-id prefix minimum"
    );
    assert!(
        include_str!("../../../README_ja.md").contains("8 文字以上"),
        "Japanese README must state the clone-id prefix minimum"
    );
}

#[test]
fn readmes_distinguish_the_cli_and_rust_helper_toolchain_requirements() {
    let english = include_str!("../../../README.md");
    assert!(english.contains("Rust 1.85 or newer"));
    assert!(english.contains("Rust 1.95-or-newer"));

    let japanese = include_str!("../../../README_ja.md");
    assert!(japanese.contains("Rust 1.85 以降"));
    assert!(japanese.contains("Rust 1.95 以降"));
}

#[test]
fn doctor_lists_supported_and_recognised_artifact_formats() {
    cmd()
        .arg("doctor")
        .assert()
        .success()
        .stdout(predicate::str::contains("wasm: available"))
        .stdout(predicate::str::contains("elf: available"))
        .stdout(predicate::str::contains(
            "macho: available (symbols, relocations, data; matching dSYM source mappings)",
        ));
}

#[cfg(not(target_os = "linux"))]
#[test]
fn untrusted_semantic_refuses_an_unenforceable_helper_memory_limit() {
    cmd()
        .args(["scan", ".", "--mode", "semantic", "--untrusted"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "cannot enforce the requested helper memory limit",
        ))
        .stderr(predicate::str::contains(
            "OS memory containment is unavailable",
        ));
}

/// Every helper is listed whether or not this machine has it, and every one is
/// optional. A report that left out the ones nobody installed would answer
/// "what can this do here" by saying only what it can already do.
///
/// What a missing one has to carry is fixed here too, and it is the thing a row
/// saying "not found" does not: something to do about it. Whether either helper
/// is installed depends on the machine, so the absent case is asserted where it
/// can be arranged rather than where it might happen to occur.
#[test]
fn doctor_lists_every_helper_as_optional_whether_or_not_it_is_installed() {
    let output = cmd().arg("doctor").output().expect("doctor should run");
    let text = String::from_utf8(output.stdout).expect("output is utf-8");
    for helper in ["rust-compiler-helper", "clang-helper"] {
        let row = text
            .lines()
            .find(|line| line.contains(helper))
            .unwrap_or_else(|| panic!("{helper} is listed: {text}"));
        assert!(row.contains("optional"), "{row}");
        if row.contains("not found") {
            assert!(row.contains("not needed for fast or structural"), "{row}");
            assert!(
                row.contains("codehelion-backend-"),
                "a missing helper names the program to install: {row}"
            );
        }
    }
}

/// Being on disk is not being usable, so a row that claims a helper is there
/// has to carry what the handshake settled — which compiler will answer and
/// what it will answer about. Whether one is installed depends on the machine,
/// so what is fixed here is the pairing rather than the outcome: available
/// comes with what it said, unusable comes with why it said nothing.
#[test]
fn a_helper_reported_as_present_says_what_it_answered() {
    let output = cmd().arg("doctor").output().expect("doctor should run");
    let text = String::from_utf8(output.stdout).expect("output is utf-8");
    let lines: Vec<&str> = text.lines().collect();
    let at = lines
        .iter()
        .position(|line| line.contains("rust-compiler-helper"))
        .expect("the helper is listed whether or not it is installed");
    let row = lines[at];
    let following = lines[at + 1..].join("\n");
    if row.contains("available") {
        assert!(following.starts_with("  "), "{text}");
        assert!(lines[at + 1].contains("version "), "{text}");
        assert!(
            lines[at + 1..at + 4]
                .iter()
                .any(|l| l.contains("supplies:")),
            "{text}"
        );
    } else if row.contains("unusable") {
        assert!(lines[at + 1].contains("could not talk to it"), "{text}");
    } else {
        assert!(row.contains("not found"), "{text}");
    }
}

#[test]
fn missing_subcommand_is_an_error() {
    cmd()
        .assert()
        .failure()
        .stderr(predicate::str::contains("Usage:"));
}

#[test]
fn help_flag_succeeds() {
    cmd()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("codehelion"));
}

#[test]
fn artifact_reports_a_minimal_wasm_without_executing_it() {
    let file = tempfile::NamedTempFile::new().expect("fixture file");
    let db_dir = tempfile::tempdir().expect("database directory");
    let db = db_dir.path().join("artifact.db");
    std::fs::write(file.path(), b"\0asm\x01\0\0\0").expect("write wasm fixture");
    cmd()
        .args([
            "artifact",
            "analyze",
            file.path().to_str().expect("utf-8 fixture path"),
            "--format",
            "json",
            "--db",
            db.to_str().expect("utf-8 database path"),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("artifact-report-v2"))
        .stdout(predicate::str::contains("\"format\": \"wasm\""))
        .stdout(predicate::str::contains("\"analysis_id\": 1"));
    assert!(db.is_file());
}

#[test]
fn the_artifact_schema_declares_each_field_where_the_report_writes_it() {
    let file = tempfile::NamedTempFile::new().expect("fixture file");
    let db_dir = tempfile::tempdir().expect("database directory");
    let db = db_dir.path().join("artifact.db");
    std::fs::write(file.path(), b"\0asm\x01\0\0\0").expect("write wasm fixture");
    let output = cmd()
        .args([
            "artifact",
            "analyze",
            file.path().to_str().expect("utf-8 fixture path"),
            "--format",
            "json",
            "--db",
            db.to_str().expect("utf-8 database path"),
        ])
        .output()
        .expect("run artifact analyze");
    assert!(output.status.success(), "{output:?}");
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("artifact report is JSON");
    let schema: serde_json::Value =
        serde_json::from_str(codehelion::artifact::ARTIFACT_REPORT_JSON_SCHEMA)
            .expect("shipped artifact schema is JSON");

    let declared = &schema["properties"];

    // Attributing a symbol to the definition it was instantiated from needs a
    // correlated source run, so the report writes those origins inside the
    // correlation. A top-level declaration would describe a document no run
    // produces.
    assert!(
        !report
            .as_object()
            .expect("report is an object")
            .contains_key("generic_origins"),
        "{report}"
    );
    assert!(declared.get("generic_origins").is_none(), "{declared}");
    assert!(
        schema["$defs"]["correlation"]["properties"]["generic_origins"].is_object(),
        "{schema}"
    );
}

#[test]
fn artifact_analysis_refuses_a_database_held_by_another_writer() {
    let artifact = tempfile::NamedTempFile::new().expect("artifact fixture");
    let database_directory = tempfile::tempdir().expect("database directory");
    let database = database_directory.path().join("artifact.db");
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(database_directory.path().join("artifact.db.lock"))
        .expect("open database lease");
    FileExt::try_lock_exclusive(&lock).expect("test holds database lease");
    std::fs::write(artifact.path(), b"\0asm\x01\0\0\0").expect("write WASM fixture");

    cmd()
        .args([
            "artifact",
            "analyze",
            artifact.path().to_str().expect("UTF-8 artifact path"),
            "--db",
            database.to_str().expect("UTF-8 database path"),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "another codehelion scan or cache clear",
        ));
}

#[test]
fn artifact_calibration_write_refuses_a_database_held_by_another_writer() {
    let before = tempfile::NamedTempFile::new().expect("before artifact fixture");
    let after = tempfile::NamedTempFile::new().expect("after artifact fixture");
    let variant = tempfile::NamedTempFile::new().expect("build variant fixture");
    let database_directory = tempfile::tempdir().expect("database directory");
    let database = database_directory.path().join("artifact.db");
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(database_directory.path().join("artifact.db.lock"))
        .expect("open database lease");
    FileExt::try_lock_exclusive(&lock).expect("test holds database lease");
    std::fs::write(before.path(), b"\0asm\x01\0\0\0").expect("write before WASM fixture");
    std::fs::write(after.path(), b"\0asm\x01\0\0\0").expect("write after WASM fixture");
    std::fs::write(variant.path(), "{}\n").expect("write build variant");

    cmd()
        .args([
            "artifact",
            "compare",
            before.path().to_str().expect("UTF-8 before path"),
            after.path().to_str().expect("UTF-8 after path"),
            "--source-run",
            "1",
            "--clone-group",
            "deadbeef",
            "--db",
            database.to_str().expect("UTF-8 database path"),
            "--before-build-variant",
            variant.path().to_str().expect("UTF-8 variant path"),
            "--after-build-variant",
            variant.path().to_str().expect("UTF-8 variant path"),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "another codehelion scan or cache clear",
        ));
}

#[test]
fn artifact_report_rerenders_a_saved_analysis_after_its_input_is_removed() {
    let file = tempfile::NamedTempFile::new().expect("fixture file");
    let db_dir = tempfile::tempdir().expect("database directory");
    let db = db_dir.path().join("artifact.db");
    std::fs::write(file.path(), b"\0asm\x01\0\0\0").expect("write wasm fixture");
    cmd()
        .args([
            "artifact",
            "analyze",
            file.path().to_str().expect("utf-8 fixture path"),
            "--format",
            "json",
            "--db",
            db.to_str().expect("utf-8 database path"),
        ])
        .assert()
        .success();
    std::fs::remove_file(file.path()).expect("remove analyzed artifact");
    cmd()
        .args([
            "artifact",
            "report",
            "--analysis",
            "1",
            "--format",
            "json",
            "--db",
            db.to_str().expect("utf-8 database path"),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("artifact-report-v2"))
        .stdout(predicate::str::contains("\"analysis_id\": 1"))
        .stdout(predicate::str::contains("\"format\": \"wasm\""));
}

/// Analysing against a scan records a correlation, and the documented
/// workflow is to analyse once and re-render later. A re-render therefore has
/// to show the correlation the analysis recorded, in every format: a script
/// reading a saved analysis must not receive a structurally poorer document
/// than the analysis it names printed.
#[test]
fn artifact_report_renders_the_correlation_its_analysis_recorded() {
    let directory = tempfile::tempdir().expect("temp dir");
    let root = resolved_root(&directory);
    std::fs::write(
        root.join("ledger.rs"),
        "pub fn total(values: &[u32]) -> u32 {\n    values.iter().copied().sum()\n}\n",
    )
    .expect("write source fixture");
    let artifact = root.join("ledger.wasm");
    std::fs::write(&artifact, b"\0asm\x01\0\0\0").expect("write wasm fixture");
    let variant = root.join("artifact-build-variant.json");
    std::fs::write(&variant, "{\"target\":\"fixture\"}\n").expect("write build variant");
    let db = root.join("audit.db");
    let db_path = db.to_str().expect("utf-8 database path");

    let scanned = cmd()
        .args([
            "scan",
            root.to_str().expect("utf-8 fixture root"),
            "--format",
            "json",
            "--db",
            db_path,
        ])
        .output()
        .expect("scan the fixture tree");
    assert!(
        scanned.status.success(),
        "{}",
        String::from_utf8_lossy(&scanned.stderr)
    );
    let source: serde_json::Value =
        serde_json::from_slice(&scanned.stdout).expect("scan report is JSON");
    let source_run = source["run"]["run_id"]
        .as_i64()
        .expect("the scan recorded a run")
        .to_string();

    let analyzed = cmd()
        .args([
            "artifact",
            "analyze",
            artifact.to_str().expect("utf-8 artifact path"),
            "--format",
            "json",
            "--build-variant",
            variant.to_str().expect("utf-8 build variant path"),
            "--source-run",
            &source_run,
            "--db",
            db_path,
        ])
        .output()
        .expect("analyse the artifact against the scan");
    assert!(
        analyzed.status.success(),
        "{}",
        String::from_utf8_lossy(&analyzed.stderr)
    );
    let analysis: serde_json::Value =
        serde_json::from_slice(&analyzed.stdout).expect("analysis report is JSON");
    assert!(
        !analysis["correlation"].is_null(),
        "the analysis recorded no correlation to re-render: {analysis}"
    );

    let rendered = cmd()
        .args(["artifact", "report", "--format", "json", "--db", db_path])
        .output()
        .expect("re-render the saved analysis");
    assert!(
        rendered.status.success(),
        "{}",
        String::from_utf8_lossy(&rendered.stderr)
    );
    let saved: serde_json::Value =
        serde_json::from_slice(&rendered.stdout).expect("saved report is JSON");
    assert_eq!(
        saved["correlation"], analysis["correlation"],
        "the re-rendered correlation differs from the recorded one: {saved}"
    );
    assert_eq!(
        saved["correlation"]["source_run"]
            .as_i64()
            .map(|run| run.to_string()),
        Some(source_run.clone()),
        "the re-render names another scan than the analysis did: {saved}"
    );

    let csv = cmd()
        .args(["artifact", "report", "--format", "csv", "--db", db_path])
        .output()
        .expect("re-render the saved analysis as CSV");
    assert!(
        csv.status.success(),
        "{}",
        String::from_utf8_lossy(&csv.stderr)
    );
    assert!(
        String::from_utf8_lossy(&csv.stdout).contains(source_run.as_str()),
        "the CSV re-render names the correlated scan: {}",
        String::from_utf8_lossy(&csv.stdout)
    );
}

#[cfg(target_os = "linux")]
#[test]
fn artifact_accepts_an_enforced_linux_memory_ceiling() {
    let file = tempfile::NamedTempFile::new().expect("fixture file");
    let db_dir = tempfile::tempdir().expect("database directory");
    let db = db_dir.path().join("artifact.db");
    std::fs::write(file.path(), b"\0asm\x01\0\0\0").expect("write wasm fixture");
    cmd()
        .args([
            "artifact",
            "analyze",
            file.path().to_str().expect("utf-8 fixture path"),
            "--format",
            "json",
            "--db",
            db.to_str().expect("utf-8 database path"),
            "--max-memory-bytes",
            "268435456",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("artifact-report-v2"));
}

#[cfg(not(target_os = "linux"))]
#[test]
fn artifact_refuses_an_unenforceable_memory_ceiling() {
    let file = tempfile::NamedTempFile::new().expect("fixture file");
    std::fs::write(file.path(), b"\0asm\x01\0\0\0").expect("write wasm fixture");
    cmd()
        .args([
            "artifact",
            "analyze",
            file.path().to_str().expect("utf-8 fixture path"),
            "--max-memory-bytes",
            "268435456",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "cannot enforce the requested artifact worker memory limit",
        ));
}

#[test]
fn artifact_compare_reports_the_measured_byte_delta() {
    let before = tempfile::NamedTempFile::new().expect("before fixture");
    let after = tempfile::NamedTempFile::new().expect("after fixture");
    std::fs::write(before.path(), b"\0asm\x01\0\0\0").expect("write before wasm");
    std::fs::write(after.path(), b"\0asm\x01\0\0\0").expect("write after wasm");
    cmd()
        .args([
            "artifact",
            "compare",
            before.path().to_str().expect("utf-8 before path"),
            after.path().to_str().expect("utf-8 after path"),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "observed size: +0 bytes (no change)",
        ))
        .stdout(predicate::str::contains(
            "duplicated code: +0 bytes (no change)",
        ));
}

#[test]
fn artifact_compare_refuses_a_database_that_selects_no_calibration() {
    let before = tempfile::NamedTempFile::new().expect("before fixture");
    let after = tempfile::NamedTempFile::new().expect("after fixture");
    let database_directory = tempfile::tempdir().expect("database directory");
    std::fs::write(before.path(), b"\0asm\x01\0\0\0").expect("write before wasm");
    std::fs::write(after.path(), b"\0asm\x01\0\0\0").expect("write after wasm");
    cmd()
        .args([
            "artifact",
            "compare",
            before.path().to_str().expect("utf-8 before path"),
            after.path().to_str().expect("utf-8 after path"),
            "--db",
            database_directory
                .path()
                .join("audit.db")
                .to_str()
                .expect("utf-8 database path"),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "--db was given without --source-run and --clone-group; artifact compare uses --db only to record a calibration",
        ));
}

#[test]
fn artifact_compare_calibrates_against_the_configured_database_without_a_database_flag() {
    let repository = tempfile::tempdir().expect("repository directory");
    let before = repository.path().join("before.wasm");
    let after = repository.path().join("after.wasm");
    let variant = repository.path().join("build-variant.json");
    std::fs::write(&before, b"\0asm\x01\0\0\0").expect("write before wasm");
    std::fs::write(&after, b"\0asm\x01\0\0\0").expect("write after wasm");
    std::fs::write(&variant, b"{}\n").expect("write build variant");
    let configured = repository.path().join(".codehelion").join("audit.db");
    cmd()
        .current_dir(repository.path())
        .args([
            "artifact",
            "analyze",
            before.to_str().expect("utf-8 before path"),
            "--db",
            configured.to_str().expect("utf-8 database path"),
        ])
        .assert()
        .success();

    cmd()
        .current_dir(repository.path())
        .args([
            "artifact",
            "compare",
            before.to_str().expect("utf-8 before path"),
            after.to_str().expect("utf-8 after path"),
            "--source-run",
            "1",
            "--clone-group",
            &"ab".repeat(16),
            "--before-build-variant",
            variant.to_str().expect("utf-8 variant path"),
            "--after-build-variant",
            variant.to_str().expect("utf-8 variant path"),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "calibration needs exactly one matching saved estimate",
        ));
}

#[test]
fn config_show_prints_defaults_when_no_file() {
    let dir = tempfile::tempdir().expect("temp dir");
    cmd()
        .current_dir(dir.path())
        .args(["config", "show"])
        .assert()
        .success()
        .stdout(predicate::str::contains("built-in defaults"))
        .stdout(predicate::str::contains("min-clone-tokens = 20"))
        .stdout(predicate::str::contains("jobs: automatic worker count"))
        .stdout(predicate::str::contains(
            "limits.posting-cap: mode-specific default",
        ))
        .stdout(predicate::str::contains(
            "limits.pair-budget: mode-specific default",
        ))
        .stdout(predicate::str::contains(
            "limits.signature-sibling-candidate-budget: default used only with --siblings-by-signature",
        ));
}

#[test]
fn config_init_writes_a_template_then_refuses_overwrite() {
    let dir = tempfile::tempdir().expect("temp dir");
    cmd()
        .current_dir(dir.path())
        .args(["config", "init"])
        .assert()
        .success()
        .stdout(predicate::str::contains("wrote"));

    let written = std::fs::read_to_string(dir.path().join("codehelion.toml")).expect("template");
    assert!(written.contains("codehelion configuration"));
    assert!(written.contains("example, not the built-in default"));
    assert!(written.contains("auto-generated"));
    assert!(written.contains("prefix of at least 8 characters"));
    assert!(written.contains("# split-pairs = \"rank-down\""));
    assert!(written.contains("# width-family = \"hide\""));

    // A second init without --force must not clobber the file.
    cmd()
        .current_dir(dir.path())
        .args(["config", "init"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("already exists"));

    cmd()
        .current_dir(dir.path())
        .args(["config", "init", "--force"])
        .assert()
        .success();
}

#[test]
fn config_show_reads_a_discovered_file() {
    let dir = tempfile::tempdir().expect("temp dir");
    std::fs::write(
        dir.path().join("codehelion.toml"),
        "min-clone-tokens = 42\n",
    )
    .expect("write config");
    cmd()
        .current_dir(dir.path())
        .args(["config", "show"])
        .assert()
        .success()
        .stdout(predicate::str::contains("min-clone-tokens = 42"))
        .stdout(predicate::str::contains("codehelion.toml"));
}

#[test]
fn config_show_rejects_unknown_keys() {
    let dir = tempfile::tempdir().expect("temp dir");
    std::fs::write(
        dir.path().join("codehelion.toml"),
        "min_clone_tokens = 42\n",
    )
    .expect("write config");
    cmd()
        .current_dir(dir.path())
        .args(["config", "show"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("unknown field"));
}

#[test]
fn cache_status_reports_absent_database() {
    let dir = tempfile::tempdir().expect("temp dir");
    cmd()
        .current_dir(dir.path())
        .args(["cache", "status"])
        .assert()
        .success()
        .stdout(predicate::str::contains("absent"));
}

#[test]
fn cache_clear_requires_confirmation_even_when_the_database_is_absent() {
    let dir = tempfile::tempdir().expect("temp dir");
    cmd()
        .current_dir(dir.path())
        .args(["cache", "clear"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("pass --force to confirm"));
    cmd()
        .current_dir(dir.path())
        .args(["cache", "clear", "--force"])
        .assert()
        .success()
        .stdout(predicate::str::contains("nothing to remove"));
    assert!(
        !dir.path().join(".codehelion").exists(),
        "clearing an unscanned tree must not create cache state"
    );
}

#[test]
fn cache_clear_removes_wal_sidecars_and_status_counts_them() {
    let dir = tempfile::tempdir().expect("temp dir");
    let database = dir.path().join("audit.db");
    let wal = dir.path().join("audit.db-wal");
    let shm = dir.path().join("audit.db-shm");
    std::fs::write(&database, [0_u8]).expect("write database");
    std::fs::write(&wal, [0_u8; 2]).expect("write WAL sidecar");
    std::fs::write(&shm, [0_u8; 3]).expect("write shared-memory sidecar");
    let database_arg = database.to_str().expect("temporary database path is UTF-8");

    cmd()
        .current_dir(dir.path())
        .args(["cache", "status", "--db", database_arg])
        .assert()
        .success()
        .stdout(predicate::str::contains("(6 bytes)"));
    cmd()
        .current_dir(dir.path())
        .args(["cache", "clear", "--force", "--db", database_arg])
        .assert()
        .success()
        .stdout(predicate::str::contains("removed"));

    assert!(!database.exists(), "main database was removed");
    assert!(!wal.exists(), "WAL sidecar was removed");
    assert!(!shm.exists(), "shared-memory sidecar was removed");
}

#[test]
fn cache_status_breaks_down_valid_storage_and_prune_compacts_it() {
    let directory = tempfile::tempdir().expect("temp dir");
    let database = directory.path().join("audit.db");
    let source = directory.path().join("lib.rs");
    std::fs::write(&source, "pub fn tiny() {}\n").expect("write source");
    let database_arg = database.to_str().expect("database path");

    cmd()
        .args([
            "scan",
            directory.path().to_str().expect("scan path"),
            "--db",
            database_arg,
        ])
        .assert()
        .success();
    cmd()
        .args(["cache", "status", "--db", database_arg])
        .assert()
        .success()
        .stdout(predicate::str::contains("table storage:"))
        .stdout(predicate::str::contains("scan_run:"));
    cmd()
        .args([
            "cache",
            "prune",
            "--db",
            database_arg,
            "--keep-artifacts",
            "0",
            "--keep-comparisons",
            "0",
            "--force",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("pruned"));
}
