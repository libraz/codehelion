use super::*;

/// Keep only fixture-relative values in a compiler IR golden.
///
/// The protocol deliberately carries the actual path that a helper analysed,
/// but a temporary fixture root is not a compiler result. Replacing it here
/// keeps the snapshot about IR shape, symbols, types and anchors rather than
/// the operating system's temporary-directory name.
fn normalized_golden_ir(ir: impl serde::Serialize, relative_file: &str, unit: &str) -> Value {
    let mut value = serde_json::to_value(ir).expect("compiler IR is serializable");
    value["unit"]["file"] = serde_json::json!(format!("<fixture>/{relative_file}"));
    value["unit"]["unit"] = serde_json::json!(unit);
    // A C/C++ variant includes the compile-database content hash, whose
    // `directory` deliberately names this temporary fixture. Variant
    // construction has its own tests; the IR golden holds its semantic body.
    value["unit"]["variant"] = serde_json::json!("<variant>");
    value["anchored_at"] = serde_json::json!("<fixture>");
    value
}

/// A fixed Rust fixture supplies a complete compiler IR snapshot. The helper
/// test matrix fixes its Rust and rust-analyzer versions, so a semantic change
/// has to deliberately update this contract instead of moving unnoticed.
#[test]
#[ignore = "requires codehelion-backend-rust"]
fn rust_compiler_ir_matches_its_golden_snapshot() {
    let fixture = rust_fixture();
    let report = scan(fixture.path());
    let run_id = report["run"]["run_id"].as_i64().expect("run id");
    let store = Store::open(&fixture.path().join(".codehelion/audit.db")).expect("open store");
    let ir = store
        .run_compiler_units(run_id)
        .expect("read compiler rows")
        .into_iter()
        .find_map(|unit| match unit.outcome {
            CompilerOutcome::Analyzed(ir) => Some(ir),
            CompilerOutcome::Unavailable { .. } => None,
        })
        .expect("Rust helper returned an IR");
    let expected: Value = serde_json::from_str(include_str!("../fixtures/semantic/rust-ir.json"))
        .expect("Rust golden IR is JSON");
    assert_eq!(
        normalized_golden_ir(ir, "src/lib.rs", "semantic_fixture"),
        expected,
        "the Rust helper IR changed; update the versioned golden intentionally"
    );
}

fn c_golden_fixture() -> tempfile::TempDir {
    let directory = tempfile::tempdir().expect("temporary C fixture");
    let root = directory.path();
    std::fs::create_dir_all(root.join("src")).expect("create C source directory");
    std::fs::write(
        root.join("src/counter.c"),
        "typedef unsigned Counter;\n\
         Counter increment(Counter value) { return value + 1; }\n",
    )
    .expect("write C source");
    let database = serde_json::json!([{
        "directory": root.display().to_string(),
        "file": "src/counter.c",
        "arguments": ["clang", "-std=c11", "-c", "src/counter.c"]
    }]);
    std::fs::write(
        root.join("compile_commands.json"),
        serde_json::to_string(&database).expect("compile database is JSON"),
    )
    .expect("write compile database");
    directory
}

fn cpp_golden_fixture() -> tempfile::TempDir {
    let directory = tempfile::tempdir().expect("temporary C++ fixture");
    let root = directory.path();
    std::fs::create_dir_all(root.join("src")).expect("create C++ source directory");
    std::fs::write(
        root.join("src/counter.cpp"),
        "namespace counter {\n\
         using Count = unsigned;\n\
         Count increment(Count value) { return value + 1; }\n\
         }\n",
    )
    .expect("write C++ source");
    let database = serde_json::json!([{
        "directory": root.display().to_string(),
        "file": "src/counter.cpp",
        "arguments": ["clang++", "-std=c++17", "-c", "src/counter.cpp"]
    }]);
    std::fs::write(
        root.join("compile_commands.json"),
        serde_json::to_string(&database).expect("compile database is JSON"),
    )
    .expect("write compile database");
    directory
}

/// A C fixture without system headers keeps the Clang golden independent of
/// the host standard library while still exercising compile-database routing.
#[test]
#[ignore = "requires codehelion-backend-clang and libclang"]
fn c_compiler_ir_matches_its_golden_snapshot() {
    let fixture = c_golden_fixture();
    let report = scan(fixture.path());
    let run_id = report["run"]["run_id"].as_i64().expect("run id");
    let store = Store::open(&fixture.path().join(".codehelion/audit.db")).expect("open store");
    let ir = store
        .run_compiler_units(run_id)
        .expect("read compiler rows")
        .into_iter()
        .find_map(|unit| match unit.outcome {
            CompilerOutcome::Analyzed(ir) => Some(ir),
            CompilerOutcome::Unavailable { .. } => None,
        })
        .expect("C helper returned an IR");
    let expected: Value = serde_json::from_str(include_str!("../fixtures/semantic/c-ir.json"))
        .expect("C golden IR is JSON");
    assert_eq!(
        normalized_golden_ir(ir, "src/counter.c", "<fixture>/src/counter.c"),
        expected,
        "the C helper IR changed; update the versioned golden intentionally"
    );
}

/// A C++ fixture without system headers keeps the Clang golden independent of
/// the host standard library while exercising the C++ frontend and database.
#[test]
#[ignore = "requires codehelion-backend-clang and libclang"]
fn cpp_compiler_ir_matches_its_golden_snapshot() {
    let fixture = cpp_golden_fixture();
    let report = scan(fixture.path());
    let run_id = report["run"]["run_id"].as_i64().expect("run id");
    let store = Store::open(&fixture.path().join(".codehelion/audit.db")).expect("open store");
    let ir = store
        .run_compiler_units(run_id)
        .expect("read compiler rows")
        .into_iter()
        .find_map(|unit| match unit.outcome {
            CompilerOutcome::Analyzed(ir) => Some(ir),
            CompilerOutcome::Unavailable { .. } => None,
        })
        .expect("C++ helper returned an IR");
    let expected: Value = serde_json::from_str(include_str!("../fixtures/semantic/cpp-ir.json"))
        .expect("C++ golden IR is JSON");
    assert_eq!(
        normalized_golden_ir(ir, "src/counter.cpp", "<fixture>/src/counter.cpp"),
        expected,
        "the C++ helper IR changed; update the versioned golden intentionally"
    );
}

/// Semantic analysis reads a project's build metadata but does not execute a
/// procedural macro or `CMake` configure step unless a future helper explicitly
/// implements and receives that permission.
#[test]
#[ignore = "requires codehelion-backend-rust, codehelion-backend-clang, and libclang"]
fn semantic_scan_does_not_execute_proc_macros_or_cmake_by_default() {
    let rust_directory = tempfile::tempdir().expect("temporary Rust fixture");
    let rust_root = codehelion_fixtures::copy_rust("proc-macro", rust_directory.path())
        .expect("copy proc-macro fixture");
    let proc_marker = rust_root.join("proc-macro-ran.marker");
    let rust_output = cmd()
        .current_dir(&rust_root)
        .env("CODEHELION_PROC_MACRO_MARKER", &proc_marker)
        .args(["scan", ".", "--mode", "semantic", "--format", "json"])
        .output()
        .expect("run Rust semantic scan");
    assert!(
        rust_output.status.success(),
        "{}",
        String::from_utf8_lossy(&rust_output.stderr)
    );
    assert!(
        !proc_marker.exists(),
        "the default Semantic scan executed a procedural macro"
    );

    let cpp_directory = tempfile::tempdir().expect("temporary C++ fixture");
    let cpp_root =
        codehelion_fixtures::copy_cpp("cmake", cpp_directory.path()).expect("copy CMake fixture");
    let cmake_marker = cpp_root.join("cmake-ran.marker");
    let cpp_output = cmd()
        .current_dir(&cpp_root)
        .env("CODEHELION_CMAKE_MARKER", &cmake_marker)
        .args(["scan", ".", "--mode", "semantic", "--format", "json"])
        .output()
        .expect("run C++ semantic scan");
    assert!(
        cpp_output.status.success(),
        "{}",
        String::from_utf8_lossy(&cpp_output.stderr)
    );
    assert!(
        !cmake_marker.exists(),
        "the default Semantic scan ran CMake configure"
    );
}
