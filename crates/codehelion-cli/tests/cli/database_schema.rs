//! Tests for how every command reacts to an audit database written by
//! another schema version, and for the step-aside rule that follows from it.

use super::*;

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
