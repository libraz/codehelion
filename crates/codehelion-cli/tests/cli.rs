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

#[test]
fn scan_recreates_an_incompatible_pre_release_database() {
    let directory = tempfile::tempdir().expect("temp dir");
    let database = directory.path().join("audit.db");
    let source = directory.path().join("lib.rs");
    std::fs::write(&source, "pub fn tiny() {}\n").expect("write source");
    codehelion_store::Store::open(&database).expect("create database");
    let connection = rusqlite::Connection::open(&database).expect("open database");
    connection
        .execute("UPDATE schema_meta SET version = 999", [])
        .expect("change schema version");
    drop(connection);

    cmd()
        .args([
            "scan",
            directory.path().to_str().expect("scan path"),
            "--db",
            database.to_str().expect("database path"),
        ])
        .assert()
        .success();

    let store = codehelion_store::Store::open_existing(&database).expect("recreated database");
    assert_eq!(
        store.schema_version().expect("schema version"),
        codehelion_store::schema::SCHEMA_VERSION
    );
    assert_eq!(store.table_count("scan_run").expect("scan runs"), 1);
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
    let file = tempfile::NamedTempFile::new().expect("invalid artifact file");
    std::fs::write(file.path(), b"not an artifact").expect("write invalid artifact");
    cmd()
        .args([
            "artifact",
            "analyze",
            file.path().to_str().expect("artifact path"),
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
    let artifact = tempfile::NamedTempFile::new().expect("wasm artifact file");
    let debug_file = tempfile::NamedTempFile::new().expect("debug companion file");
    std::fs::write(artifact.path(), b"\0asm\x01\0\0\0").expect("write wasm fixture");
    cmd()
        .args([
            "artifact",
            "analyze",
            artifact.path().to_str().expect("artifact path"),
            "--debug-file",
            debug_file.path().to_str().expect("debug companion path"),
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
fn readmes_document_current_defaults_and_database_lifecycle() {
    for readme in [
        include_str!("../../../README.md"),
        include_str!("../../../README_ja.md"),
    ] {
        for snippet in [
            "codehelion-cli.svg",
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
        .stdout(predicate::str::contains("artifact-report-v1"))
        .stdout(predicate::str::contains("\"format\": \"wasm\""))
        .stdout(predicate::str::contains("\"analysis_id\": 1"));
    assert!(db.is_file());
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
        .stdout(predicate::str::contains("artifact-report-v1"))
        .stdout(predicate::str::contains("\"analysis_id\": 1"))
        .stdout(predicate::str::contains("\"format\": \"wasm\""));
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
        .stdout(predicate::str::contains("artifact-report-v1"));
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
            "observed_size_reduction_bytes: +0",
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
