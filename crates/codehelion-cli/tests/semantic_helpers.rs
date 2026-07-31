//! Semantic scan integration tests that require both optional compiler helpers.
//!
//! The test is ignored by default so a normal CLI-only test run remains useful
//! on a machine without the optional programs. CI builds both helpers beside
//! the CLI and runs it explicitly, exercising the complete process boundary
//! and `SQLite` persistence path.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use codehelion_eval::detected;
use codehelion_eval::labels::LabelSet;
use codehelion_eval::metrics::{DEFAULT_MATCH_THRESHOLD, evaluate, evaluate_by_rule};
use codehelion_store::Store;
use codehelion_store::compiler::CompilerOutcome;
use serde_json::Value;

fn cmd() -> Command {
    Command::cargo_bin("codehelion").expect("binary should build")
}

fn scan(root: &Path) -> Value {
    scan_mode(root, "semantic")
}

fn scan_mode(root: &Path, mode: &str) -> Value {
    let output = cmd()
        .current_dir(root)
        .args(["scan", ".", "--mode", mode, "--format", "json"])
        .output()
        .expect("run semantic scan");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("semantic scan emits JSON")
}

fn scan_comparing_languages(root: &Path) -> Value {
    let output = cmd()
        .current_dir(root)
        .args([
            "scan",
            ".",
            "--mode",
            "semantic",
            "--format",
            "json",
            "--compare-languages",
        ])
        .output()
        .expect("run cross-language semantic scan");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("cross-language scan emits JSON")
}

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("the CLI crate is two levels below the repository root")
        .to_path_buf()
}

/// The committed Rust corpus as a small Cargo library, with label paths made
/// relative to its actual source root. Semantic mode needs Cargo metadata;
/// the corpus itself intentionally remains build-system independent.
fn semantic_rust_corpus() -> (tempfile::TempDir, LabelSet) {
    let directory = tempfile::tempdir().expect("temporary Rust corpus");
    let root = directory.path();
    let source = repository_root().join("corpus/synthetic/rust");
    std::fs::create_dir_all(root.join("src")).expect("create corpus source directory");
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"semantic-corpus\"\nversion = \"0.1.0\"\nedition = \"2024\"\npublish = false\n",
    )
    .expect("write corpus manifest");
    for name in ["type1.rs", "type2.rs", "type3.rs"] {
        std::fs::copy(source.join(name), root.join("src").join(name))
            .unwrap_or_else(|error| panic!("copying corpus {name}: {error}"));
    }
    std::fs::copy(source.join("seed.rs"), root.join("src/lib.rs"))
        .expect("copy corpus seed as the library root");
    std::fs::write(
        root.join("src/lib.rs"),
        format!(
            "{}\nmod type1;\nmod type2;\nmod type3;\n",
            std::fs::read_to_string(root.join("src/lib.rs")).expect("read corpus library root")
        ),
    )
    .expect("wire corpus variants into the library");

    let labels_text =
        std::fs::read_to_string(source.join("labels.json")).expect("read committed corpus labels");
    let mut labels = LabelSet::from_json(&labels_text).expect("parse committed corpus labels");
    let source_path = |file: &mut String| {
        *file = if file == "seed.rs" {
            "src/lib.rs".to_owned()
        } else {
            format!("src/{file}")
        };
    };
    for file in &mut labels.files {
        source_path(file);
    }
    for pair in &mut labels.clone_pairs {
        for fragment in &mut pair.fragments {
            source_path(&mut fragment.file);
        }
    }
    for pair in &mut labels.non_clones {
        for fragment in &mut pair.fragments {
            source_path(&mut fragment.file);
        }
    }
    (directory, labels)
}

/// A hand-labelled Rust corpus for every initially registered same-language
/// semantic rule. It is intentionally kept separate from the generated
/// structural corpus because compiler-resolved constructs, rather than text
/// mutations, define its ground truth.
fn restricted_semantic_rust_corpus() -> (tempfile::TempDir, LabelSet) {
    let directory = tempfile::tempdir().expect("temporary restricted semantic corpus");
    let root = directory.path();
    let source = repository_root().join("corpus/synthetic/rust-restricted-semantic");
    std::fs::create_dir_all(root.join("src")).expect("create corpus source directory");
    for relative in ["Cargo.toml", "src/lib.rs", "labels.json"] {
        std::fs::copy(source.join(relative), root.join(relative)).unwrap_or_else(|error| {
            panic!("copying restricted semantic corpus {relative}: {error}")
        });
    }
    let labels = LabelSet::from_json(
        &std::fs::read_to_string(root.join("labels.json"))
            .expect("read restricted semantic corpus labels"),
    )
    .expect("parse restricted semantic corpus labels");
    (directory, labels)
}

/// A hand-labelled C++ corpus for the closed standard-library serialization
/// rule. The compilation database supplies the parse settings without ever
/// executing a build command.
fn restricted_semantic_cpp_corpus() -> (tempfile::TempDir, LabelSet) {
    let directory = tempfile::tempdir().expect("temporary C++ restricted semantic corpus");
    let root = directory.path();
    let source = repository_root().join("corpus/synthetic/cpp-restricted-semantic");
    std::fs::create_dir_all(root.join("cpp")).expect("create corpus C++ source directory");
    std::fs::copy(source.join("cpp/direct.cpp"), root.join("cpp/direct.cpp"))
        .expect("copy restricted C++ semantic corpus source");
    let labels_text =
        std::fs::read_to_string(source.join("labels.json")).expect("read C++ corpus labels");
    let labels = LabelSet::from_json(&labels_text).expect("parse C++ corpus labels");
    let mut arguments = vec![
        "clang++".to_owned(),
        "-std=c++17".to_owned(),
        "-c".to_owned(),
        "cpp/direct.cpp".to_owned(),
    ];
    arguments.extend(cpp_standard_library_arguments());
    let database = serde_json::json!([{
        "directory": root.display().to_string(),
        "file": "cpp/direct.cpp",
        "arguments": arguments,
    }]);
    std::fs::write(
        root.join("compile_commands.json"),
        serde_json::to_string(&database).expect("compile database is JSON"),
    )
    .expect("write C++ corpus compilation database");
    (directory, labels)
}

/// A hand-labelled C++ corpus for the direct range-for forms admitted by the
/// sequence rule. The compilation database supplies parse settings only; the
/// scanner neither builds nor executes this source.
fn restricted_semantic_cpp_loop_corpus() -> (tempfile::TempDir, LabelSet) {
    let directory = tempfile::tempdir().expect("temporary C++ loop semantic corpus");
    let root = directory.path();
    let source = repository_root().join("corpus/synthetic/cpp-loop-restricted-semantic");
    std::fs::create_dir_all(root.join("cpp")).expect("create corpus C++ source directory");
    std::fs::copy(
        source.join("cpp/range_loop.cpp"),
        root.join("cpp/range_loop.cpp"),
    )
    .expect("copy restricted C++ loop corpus source");
    let labels_text =
        std::fs::read_to_string(source.join("labels.json")).expect("read C++ loop corpus labels");
    let labels = LabelSet::from_json(&labels_text).expect("parse C++ loop corpus labels");
    let mut arguments = vec![
        "clang++".to_owned(),
        "-std=c++17".to_owned(),
        "-c".to_owned(),
        "cpp/range_loop.cpp".to_owned(),
    ];
    arguments.extend(cpp_standard_library_arguments());
    let database = serde_json::json!([{
        "directory": root.display().to_string(),
        "file": "cpp/range_loop.cpp",
        "arguments": arguments,
    }]);
    std::fs::write(
        root.join("compile_commands.json"),
        serde_json::to_string(&database).expect("compile database is JSON"),
    )
    .expect("write C++ loop corpus compilation database");
    (directory, labels)
}

fn rust_fixture() -> tempfile::TempDir {
    let directory = tempfile::tempdir().expect("temporary Rust project");
    let root = directory.path();
    std::fs::create_dir_all(root.join("src")).expect("create Rust source directory");
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"semantic-fixture\"\nversion = \"0.1.0\"\nedition = \"2024\"\npublish = false\n",
    )
    .expect("write Rust manifest");
    std::fs::write(
        root.join("src/lib.rs"),
        "pub fn total(values: &[u64]) -> u64 { values.iter().sum() }\n",
    )
    .expect("write Rust source");
    directory
}

/// A real compiler-backed pipeline pair. The predicates differ, so this is
/// not a text clone claim; the registered rule deliberately compares only the
/// resolved source/filter/collect operation sequence.
fn rust_pipeline_fixture() -> tempfile::TempDir {
    let directory = tempfile::tempdir().expect("temporary Rust pipeline project");
    let root = directory.path();
    std::fs::create_dir_all(root.join("src")).expect("create Rust source directory");
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"semantic-pipeline-fixture\"\nversion = \"0.1.0\"\nedition = \"2024\"\npublish = false\n",
    )
    .expect("write Rust manifest");
    std::fs::write(
        root.join("src/lib.rs"),
        "pub fn odds(values: &[u64]) -> Vec<u64> {\n    values.iter().filter(|value| **value % 2 == 1).map(|value| *value).collect()\n}\n\npub fn evens(values: &[u64]) -> Vec<u64> {\n    values.iter().filter(|value| **value % 2 == 0).map(|value| *value).collect()\n}\n",
    )
    .expect("write Rust pipeline source");
    directory
}

/// A C++ standard-library serialization pair and a nearby non-pair. The
/// compile database is written only for the helper; nothing in this fixture is
/// compiled or run by the scan.
fn cpp_serialization_fixture() -> tempfile::TempDir {
    let directory = tempfile::tempdir().expect("temporary C++ serialization project");
    let root = directory.path();
    std::fs::create_dir_all(root.join("cpp")).expect("create C++ source directory");
    std::fs::write(
        root.join("cpp/direct.cpp"),
        "#include <string>\n\nunsigned long long first(unsigned long long value) {\n    const auto text = std::to_string(value);\n    return std::stoull(text);\n}\n\nunsigned long long second(unsigned long long value) {\n    const auto text = std::to_string(value);\n    return std::stoull(text);\n}\n\nstd::size_t formats_twice(unsigned long long value) {\n    return (std::to_string(value) + std::to_string(value)).size();\n}\n",
    )
    .expect("write C++ serialization source");
    let mut arguments = vec![
        "clang++".to_owned(),
        "-std=c++17".to_owned(),
        "-c".to_owned(),
        "cpp/direct.cpp".to_owned(),
    ];
    arguments.extend(cpp_standard_library_arguments());
    let database = serde_json::json!([{
        "directory": root.display().to_string(),
        "file": "cpp/direct.cpp",
        "arguments": arguments
    }]);
    std::fs::write(
        root.join("compile_commands.json"),
        serde_json::to_string(&database).expect("compile database is JSON"),
    )
    .expect("write compilation database");
    directory
}

/// Two registered iterator pipelines embedded in larger functions. The
/// presence checks deliberately sit outside the sequence rule's vocabulary,
/// so a semantic finding must report only the pipeline source range.
fn rust_partial_pipeline_fixture() -> tempfile::TempDir {
    let directory = tempfile::tempdir().expect("temporary partial pipeline project");
    let root = directory.path();
    std::fs::create_dir_all(root.join("src")).expect("create Rust source directory");
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"semantic-partial-pipeline-fixture\"\nversion = \"0.1.0\"\nedition = \"2024\"\npublish = false\n",
    )
    .expect("write Rust manifest");
    std::fs::write(
        root.join("src/lib.rs"),
        "pub fn odds(values: &[u64], keep: Option<u64>) -> Vec<u64> {\n    let collected: Vec<_> = values.iter().filter(|value| **value % 2 == 1).map(|value| *value).collect();\n    if keep.is_some() { collected } else { Vec::new() }\n}\n\npub fn evens(values: &[u64], keep: Option<u64>) -> Vec<u64> {\n    let collected: Vec<_> = values.iter().filter(|value| **value % 2 == 0).map(|value| *value).collect();\n    if keep.is_some() { collected } else { Vec::new() }\n}\n",
    )
    .expect("write Rust source");
    directory
}

/// A compiler-backed pair whose only registered correspondence is an explicit
/// standard-`Vec` collection loop and a plain iterator collection pipeline.
fn rust_loop_pipeline_fixture() -> tempfile::TempDir {
    let directory = tempfile::tempdir().expect("temporary Rust loop-pipeline project");
    let root = directory.path();
    std::fs::create_dir_all(root.join("src")).expect("create Rust source directory");
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"semantic-loop-pipeline-fixture\"\nversion = \"0.1.0\"\nedition = \"2024\"\npublish = false\n",
    )
    .expect("write Rust manifest");
    std::fs::write(
        root.join("src/lib.rs"),
        "pub fn explicit<'a>(values: &'a [u64]) -> Vec<&'a u64> {\n    let mut collected = Vec::new();\n    for value in values {\n        collected.push(value);\n    }\n    collected\n}\n\npub fn iterator<'a>(values: &'a [u64]) -> Vec<&'a u64> {\n    values.iter().collect()\n}\n",
    )
    .expect("write Rust source");
    directory
}

/// Two reductions that share only the compiler-resolved iterator source and
/// fold operations. Their accumulator expressions deliberately differ.
fn rust_reduce_pipeline_fixture() -> tempfile::TempDir {
    let directory = tempfile::tempdir().expect("temporary Rust reduce project");
    let root = directory.path();
    std::fs::create_dir_all(root.join("src")).expect("create Rust source directory");
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"semantic-reduce-pipeline-fixture\"\nversion = \"0.1.0\"\nedition = \"2024\"\npublish = false\n",
    )
    .expect("write Rust manifest");
    std::fs::write(
        root.join("src/lib.rs"),
        "pub fn sum(values: &[u64]) -> u64 {\n    values.iter().fold(0, |total, value| total + value)\n}\n\npub fn product(values: &[u64]) -> u64 {\n    values.iter().fold(1, |total, value| total * value)\n}\n",
    )
    .expect("write Rust reduce pipelines");
    directory
}

/// Direct arithmetic accumulation over one standard sequence, paired with an
/// iterator reduction. The guarded control must remain outside the closed
/// loop form because it no longer reduces every element.
fn rust_loop_reduce_fixture() -> tempfile::TempDir {
    let directory = tempfile::tempdir().expect("temporary loop-reduce project");
    let root = directory.path();
    std::fs::create_dir_all(root.join("src")).expect("create Rust source directory");
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"semantic-loop-reduce-fixture\"\nversion = \"0.1.0\"\nedition = \"2024\"\npublish = false\n",
    )
    .expect("write Rust manifest");
    std::fs::write(
        root.join("src/lib.rs"),
        "pub fn explicit(values: &[u64]) -> u64 {\n    let mut total = 0;\n    for value in values {\n        total += *value;\n    }\n    total\n}\n\npub fn iterator(values: &[u64]) -> u64 {\n    values.iter().fold(0, |total, value| total + *value)\n}\n\npub fn guarded(values: &[u64]) -> u64 {\n    let mut total = 0;\n    for value in values {\n        if *value > 0 {\n            total += *value;\n        }\n    }\n    total\n}\n",
    )
    .expect("write Rust source");
    directory
}

/// Three lexical standard-file lifetimes. `unwrap` keeps the fixture free of a
/// propagation construct, so the registered resource rule sees only the
/// compiler-resolved acquisition and the function-scope `Drop`.
fn rust_resource_lifetime_fixture() -> tempfile::TempDir {
    let directory = tempfile::tempdir().expect("temporary Rust resource project");
    let root = directory.path();
    std::fs::create_dir_all(root.join("src")).expect("create Rust source directory");
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"semantic-resource-fixture\"\nversion = \"0.1.0\"\nedition = \"2024\"\npublish = false\n",
    )
    .expect("write Rust manifest");
    std::fs::write(
        root.join("src/lib.rs"),
        "pub fn inspect_first(path: &std::path::Path) {\n    let _file = std::fs::File::open(path).unwrap();\n}\n\npub fn inspect_second(path: &std::path::Path) {\n    let _file = std::fs::File::open(path).unwrap();\n}\n\npub fn inspect_third(path: &std::path::Path) {\n    let _file = std::fs::File::open(path).unwrap();\n}\n",
    )
    .expect("write Rust resource source");
    directory
}

/// Direct `Result` and `Option` adapter pairs whose only semantic
/// correspondences are the closed propagation forms. The transformed forms
/// are negative controls: they must not be treated as identity adapters.
fn rust_direct_propagation_fixture() -> tempfile::TempDir {
    let directory = tempfile::tempdir().expect("temporary direct propagation project");
    let root = directory.path();
    std::fs::create_dir_all(root.join("src")).expect("create Rust source directory");
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"semantic-direct-result-fixture\"\nversion = \"0.1.0\"\nedition = \"2024\"\npublish = false\n",
    )
    .expect("write Rust manifest");
    std::fs::write(
        root.join("src/lib.rs"),
        "pub fn operator(value: Result<u64, ()>) -> Result<u64, ()> {\n    Ok(value?)\n}\n\npub fn branches(value: Result<u64, ()>) -> Result<u64, ()> {\n    match value {\n        Ok(value) => Ok(value),\n        Err(error) => Err(error),\n    }\n}\n\npub fn transformed(value: Result<u64, ()>) -> Result<u64, ()> {\n    let value = value?;\n    Ok(value.saturating_add(1))\n}\n\npub fn option_operator(value: Option<u64>) -> Option<u64> {\n    Some(value?)\n}\n\npub fn option_branches(value: Option<u64>) -> Option<u64> {\n    match value {\n        Some(value) => Some(value),\n        None => None,\n    }\n}\n\npub fn option_transformed(value: Option<u64>) -> Option<u64> {\n    Some(value?.saturating_add(1))\n}\n\nmod project_lookalike {\n    #[allow(non_snake_case)]\n    fn Some(value: u64) -> Option<u64> {\n        Option::Some(value)\n    }\n\n    pub fn project_named_some(value: Option<u64>) -> Option<u64> {\n        Some(value?)\n    }\n}\n",
    )
    .expect("write Rust source");
    directory
}

/// Direct standard-`Option` presence checks, a match, and two narrow early
/// unit-return guards. Compound conditions and non-returning/value-returning
/// negative branches remain outside the closed validation operation.
fn rust_optional_validation_fixture() -> tempfile::TempDir {
    let directory = tempfile::tempdir().expect("temporary optional validation project");
    let root = directory.path();
    std::fs::create_dir_all(root.join("src")).expect("create Rust source directory");
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"semantic-optional-validation-fixture\"\nversion = \"0.1.0\"\nedition = \"2024\"\npublish = false\n",
    )
    .expect("write Rust manifest");
    std::fs::write(
        root.join("src/lib.rs"),
        "pub fn first(value: Option<u64>) -> bool {\n    if value.is_some() {\n        true\n    } else {\n        false\n    }\n}\n\npub fn second(value: Option<u64>) -> bool {\n    if value.is_some() {\n        false\n    } else {\n        true\n    }\n}\n\npub fn matched(value: Option<u64>) -> bool {\n    match value {\n        Some(_) => true,\n        None => false,\n    }\n}\n\npub fn early_first(value: Option<u64>) {\n    if !value.is_some() {\n        return;\n    }\n    let _ = value;\n}\n\npub fn early_second(value: Option<u64>) {\n    if !value.is_some() {\n        return;\n    }\n    let _ = value;\n}\n\npub fn compound(value: Option<u64>, keep: bool) -> bool {\n    if value.is_some() && keep {\n        true\n    } else {\n        false\n    }\n}\n\npub fn negative_nonreturn(value: Option<u64>) {\n    if !value.is_some() {\n        let _ = value;\n    }\n}\n\npub fn negative_value_return(value: Option<u64>) -> Option<u64> {\n    if !value.is_some() {\n        return None;\n    }\n    value\n}\n",
    )
    .expect("write Rust source");
    directory
}

/// Two direct standard-`Result` presence checks, plus compound and project
/// lookalike negatives. Only the compiler-resolved standard method may enter
/// the closed validation rule.
fn rust_result_validation_fixture() -> tempfile::TempDir {
    let directory = tempfile::tempdir().expect("temporary result validation project");
    let root = directory.path();
    std::fs::create_dir_all(root.join("src")).expect("create Rust source directory");
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"semantic-result-validation-fixture\"\nversion = \"0.1.0\"\nedition = \"2024\"\npublish = false\n",
    )
    .expect("write Rust manifest");
    std::fs::write(
        root.join("src/lib.rs"),
        "pub fn first(value: Result<u64, ()>) -> bool {\n    if value.is_ok() {\n        true\n    } else {\n        false\n    }\n}\n\npub fn second(value: Result<u64, ()>) -> bool {\n    if value.is_ok() {\n        false\n    } else {\n        true\n    }\n}\n\npub fn compound(value: Result<u64, ()>, keep: bool) -> bool {\n    if value.is_ok() && keep {\n        true\n    } else {\n        false\n    }\n}\n\nstruct Lookalike;\n\nimpl Lookalike {\n    fn is_ok(&self) -> bool {\n        true\n    }\n}\n\nfn lookalike(value: Lookalike) -> bool {\n    if value.is_ok() {\n        true\n    } else {\n        false\n    }\n}\n",
    )
    .expect("write Rust source");
    directory
}

/// One Rust pipeline and one manually ported C++ pipeline. They share only
/// the closed source/collection correspondence; their source text and build
/// variants are intentionally independent.
fn cross_language_pipeline_fixture() -> tempfile::TempDir {
    let directory = tempfile::tempdir().expect("temporary cross-language project");
    let root = directory.path();
    let corpus = repository_root().join("corpus/synthetic/rust-cpp-semantic");
    std::fs::create_dir_all(root.join("src")).expect("create Rust source directory");
    std::fs::create_dir_all(root.join("cpp")).expect("create C++ source directory");
    for relative in ["Cargo.toml", "src/lib.rs", "cpp/copied.cpp", "labels.json"] {
        std::fs::copy(corpus.join(relative), root.join(relative))
            .unwrap_or_else(|error| panic!("copying cross-language corpus {relative}: {error}"));
    }
    let mut arguments = vec!["clang++".to_string(), "-std=c++17".to_string()];
    arguments.extend(cpp_standard_library_arguments());
    arguments.extend(["-c".to_string(), "cpp/copied.cpp".to_string()]);
    let database = serde_json::json!([{
        "directory": root.display().to_string(),
        "file": "cpp/copied.cpp",
        "arguments": arguments
    }]);
    std::fs::write(
        root.join("compile_commands.json"),
        serde_json::to_string(&database).expect("compile database is JSON"),
    )
    .expect("write compilation database");
    directory
}

/// Rust and C++ direct loops whose correspondence is established by the
/// compiler-confirmed construct form, not an inferred or invented API name.
fn cross_language_direct_loop_fixture() -> tempfile::TempDir {
    let directory = tempfile::tempdir().expect("temporary cross-language loop project");
    let root = directory.path();
    let corpus = repository_root().join("corpus/synthetic/rust-cpp-loop-semantic");
    std::fs::create_dir_all(root.join("src")).expect("create Rust source directory");
    std::fs::create_dir_all(root.join("cpp")).expect("create C++ source directory");
    for relative in [
        "Cargo.toml",
        "src/lib.rs",
        "cpp/range_loop.cpp",
        "labels.json",
    ] {
        std::fs::copy(corpus.join(relative), root.join(relative)).unwrap_or_else(|error| {
            panic!("copying cross-language loop corpus {relative}: {error}")
        });
    }
    let mut arguments = vec!["clang++".to_string(), "-std=c++17".to_string()];
    arguments.extend(cpp_standard_library_arguments());
    arguments.extend(["-c".to_string(), "cpp/range_loop.cpp".to_string()]);
    let database = serde_json::json!([{
        "directory": root.display().to_string(),
        "file": "cpp/range_loop.cpp",
        "arguments": arguments,
    }]);
    std::fs::write(
        root.join("compile_commands.json"),
        serde_json::to_string(&database).expect("compile database is JSON"),
    )
    .expect("write compilation database");
    directory
}

/// A Rust `Result` adapter and the closed C++23 `expected` identity-return
/// counterpart. Their only cross-language relationship is the registered
/// propagation correspondence; the C++ function has no API-call sequence to
/// borrow a pipeline match from.
fn cross_language_result_expected_fixture() -> tempfile::TempDir {
    let directory = tempfile::tempdir().expect("temporary result/expected project");
    let root = directory.path();
    let corpus = repository_root().join("corpus/synthetic/rust-cpp-result-expected-semantic");
    std::fs::create_dir_all(root.join("src")).expect("create Rust source directory");
    std::fs::create_dir_all(root.join("cpp")).expect("create C++ source directory");
    for relative in ["Cargo.toml", "src/lib.rs", "cpp/direct.cpp", "labels.json"] {
        std::fs::copy(corpus.join(relative), root.join(relative))
            .unwrap_or_else(|error| panic!("copying result/expected corpus {relative}: {error}"));
    }
    let mut arguments = vec!["clang++".to_string(), "-std=c++23".to_string()];
    arguments.extend(cpp_standard_library_arguments());
    arguments.extend(["-c".to_string(), "cpp/direct.cpp".to_string()]);
    let database = serde_json::json!([{
        "directory": root.display().to_string(),
        "file": "cpp/direct.cpp",
        "arguments": arguments
    }]);
    std::fs::write(
        root.join("compile_commands.json"),
        serde_json::to_string(&database).expect("compile database is JSON"),
    )
    .expect("write compilation database");
    directory
}

/// The project fixture renderer adds this flag on macOS because Clang does not
/// discover Xcode's C++ headers from an arbitrary compilation database.
fn cpp_standard_library_arguments() -> Vec<String> {
    if !cfg!(target_os = "macos") {
        return Vec::new();
    }
    let configured = std::env::var_os("SDKROOT").map(PathBuf::from);
    let sdk = configured.into_iter().chain([
        PathBuf::from("/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk"),
        PathBuf::from("/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk"),
    ]).find(|path| path.is_dir());
    sdk.and_then(|path| path.to_str().map(str::to_string))
        .map_or_else(Vec::new, |path| vec!["-isysroot".to_string(), path])
}

fn stored_ir(root: &Path, run_id: i64) -> bool {
    Store::open(&root.join(".codehelion/audit.db"))
        .expect("open audit database")
        .run_compiler_units(run_id)
        .expect("read compiler IR")
        .iter()
        .any(|unit| matches!(unit.outcome, CompilerOutcome::Analyzed(_)))
}

/// A Semantic scan emits a restricted-semantic finding only after the real
/// Rust helper supplies resolved API calls, and persists both normalized
/// graphs and the registered-rule evidence beside the ordinary snapshot.
#[test]
#[ignore = "requires codehelion-backend-rust"]
fn semantic_scan_records_registered_pipeline_evidence() {
    let fixture = rust_pipeline_fixture();
    let root = fixture.path();
    let report = scan(root);
    let group = report["groups"]
        .as_array()
        .expect("groups array")
        .iter()
        .find(|group| {
            group["clone_type"] == "restricted-semantic"
                && group["semantic"]["rules"][0]["id"] == "sequence-pipeline-v1"
        })
        .expect("registered pipeline finding");
    assert_eq!(group["members"].as_array().map(Vec::len), Some(2));
    assert_eq!(group["split_pair"], false);
    assert_eq!(
        group["semantic"]["graphs"][0]["nodes"]
            .as_array()
            .expect("canonical graph nodes")
            .iter()
            .map(|node| node["kind"].as_str())
            .collect::<Vec<_>>(),
        vec![Some("source"), Some("filter"), Some("map"), Some("collect")],
        "the nested iterator calls lost their written order: {group:#}"
    );
    assert_eq!(
        group["semantic"]["node_mappings"].as_array().map(Vec::len),
        Some(4),
        "registered graph did not retain the iterator operations: {group:#}"
    );
    let confidence = group["semantic"]["rules"][0]["confidence"]
        .as_f64()
        .expect("semantic confidence");
    assert!(
        (confidence - 0.735).abs() < f64::EPSILON,
        "matching compiler-confirmed filter/map flow should corroborate the rule: {confidence}"
    );

    let run_id = report["run"]["run_id"].as_i64().expect("run id");
    let store = Store::open(&root.join(".codehelion/audit.db")).expect("open audit database");
    let stored = store.run_groups(run_id).expect("read groups");
    let semantic = stored
        .iter()
        .find_map(|group| group.semantic.as_ref())
        .expect("stored semantic evidence");
    assert_eq!(semantic.rule_id, "sequence-pipeline-v1");
    assert!((semantic.rule_confidence - confidence).abs() < f64::EPSILON);
    assert_eq!(semantic.graphs.len(), 2);
    assert_eq!(semantic.node_mappings.len(), 4);
    let stored_ir = store.run_compiler_units(run_id).expect("read compiler IR");
    let data_flow = stored_ir
        .iter()
        .find_map(|unit| match &unit.outcome {
            CompilerOutcome::Analyzed(ir) => Some(&ir.data_flow),
            CompilerOutcome::Unavailable { .. } => None,
        })
        .expect("stored Rust compiler IR");
    assert!(data_flow.computed);
    assert_eq!(data_flow.flows.len(), 2, "{data_flow:?}");
}

/// C++ serialization is admitted only as its exact resolved conversion pair.
#[test]
#[ignore = "requires codehelion-backend-clang and libclang"]
fn semantic_scan_matches_only_closed_cpp_serialization_round_trips() {
    let fixture = cpp_serialization_fixture();
    let report = scan(fixture.path());
    let group = report["groups"]
        .as_array()
        .expect("groups array")
        .iter()
        .find(|group| {
            group["clone_type"] == "restricted-semantic"
                && group["semantic"]["rules"][0]["id"] == "cpp-serialization-round-trip-v1"
        })
        .expect("closed C++ serialization pair");
    assert_eq!(group["members"].as_array().map(Vec::len), Some(2));
    assert_eq!(
        group["semantic"]["graphs"][0]["nodes"]
            .as_array()
            .expect("serialization graph nodes")
            .iter()
            .map(|node| node["kind"].as_str())
            .collect::<Vec<_>>(),
        vec![Some("map"), Some("map")]
    );
}

/// Every same-language rule starts enabled only because a labelled corpus
/// exercises its positive and deliberately close negative forms through the
/// real helper process. The assertion is a regression check, not a CI score
/// gate or a claim that this compact corpus estimates field precision.
#[test]
#[ignore = "requires codehelion-backend-rust"]
fn semantic_rules_have_closed_corpus_evidence() {
    let (corpus, labels) = restricted_semantic_rust_corpus();
    let report = scan(corpus.path());
    let report_json = serde_json::to_string(&report).expect("report remains serializable");
    let (detected, lines) =
        detected::from_report_json(&report_json).expect("semantic report is measurable");
    let by_rule = evaluate_by_rule(&detected, &labels, lines, DEFAULT_MATCH_THRESHOLD, 10);

    for rule_id in [
        "sequence-pipeline-v1",
        "result-direct-propagation-v1",
        "option-direct-propagation-v1",
        "optional-validation-v1",
        "result-validation-v1",
        "resource-lifecycle-v1",
        "rust-serialization-round-trip-v1",
    ] {
        let metrics = &by_rule[rule_id];
        assert!(
            (metrics.recall_overall - 1.0).abs() < f64::EPSILON,
            "{rule_id}: {metrics:?}"
        );
        assert!(
            (metrics.precision_overall - 1.0).abs() < f64::EPSILON,
            "{rule_id}: {metrics:?}"
        );
        assert_eq!(metrics.non_clone_hits, 0, "{rule_id}: {metrics:?}");
    }
}

/// The C++ serialization rule is enabled only after the Clang helper resolves
/// both conversion calls in its labelled positive and negative corpus forms.
#[test]
#[ignore = "requires codehelion-backend-clang and libclang"]
fn cpp_serialization_rule_has_closed_corpus_evidence() {
    let (corpus, labels) = restricted_semantic_cpp_corpus();
    let report = scan(corpus.path());
    let report_json = serde_json::to_string(&report).expect("report remains serializable");
    let (detected, lines) =
        detected::from_report_json(&report_json).expect("semantic report is measurable");
    let metrics = &evaluate_by_rule(&detected, &labels, lines, DEFAULT_MATCH_THRESHOLD, 10)["cpp-serialization-round-trip-v1"];
    assert!(
        (metrics.recall_overall - 1.0).abs() < f64::EPSILON,
        "{metrics:?}"
    );
    assert!(
        (metrics.precision_overall - 1.0).abs() < f64::EPSILON,
        "{metrics:?}"
    );
    assert_eq!(metrics.non_clone_hits, 0, "{metrics:?}");
}

/// The C++ direct range-for collection and reduction forms are enabled only
/// after their real-helper corpus accepts both registered pairs and rejects
/// transformed near misses.
#[test]
#[ignore = "requires codehelion-backend-clang and libclang"]
fn cpp_plain_range_loop_forms_have_closed_corpus_evidence() {
    let (corpus, labels) = restricted_semantic_cpp_loop_corpus();
    let report = scan(corpus.path());
    let report_json = serde_json::to_string(&report).expect("report remains serializable");
    let (detected, lines) =
        detected::from_report_json(&report_json).expect("semantic report is measurable");
    let metrics = &evaluate_by_rule(&detected, &labels, lines, DEFAULT_MATCH_THRESHOLD, 10)["sequence-pipeline-v1"];
    assert!(
        (metrics.recall_overall - 1.0).abs() < f64::EPSILON,
        "{metrics:?}"
    );
    assert!(
        (metrics.precision_overall - 1.0).abs() < f64::EPSILON,
        "{metrics:?}"
    );
    assert_eq!(metrics.non_clone_hits, 0, "{metrics:?}");
}

/// Repeating a real-helper scan preserves the direct range-for findings and
/// their rule-specific measurement.
#[test]
#[ignore = "requires codehelion-backend-clang and libclang"]
fn cpp_plain_range_loop_metrics_are_stable_across_fresh_scans() {
    let (corpus, labels) = restricted_semantic_cpp_loop_corpus();
    let measure = |report: &Value| {
        let report_json = serde_json::to_string(report).expect("report remains serializable");
        let (detected, lines) =
            detected::from_report_json(&report_json).expect("semantic report is measurable");
        let metrics = evaluate_by_rule(&detected, &labels, lines, DEFAULT_MATCH_THRESHOLD, 10);
        (detected, metrics)
    };
    let first = scan(corpus.path());
    let second = scan(corpus.path());
    assert_eq!(measure(&first), measure(&second));
}

/// Fresh C++ scans retain the same closed-rule findings and measurements.
#[test]
#[ignore = "requires codehelion-backend-clang and libclang"]
fn cpp_serialization_rule_metrics_are_stable_across_fresh_scans() {
    let (corpus, labels) = restricted_semantic_cpp_corpus();
    let measure = |report: &Value| {
        let report_json = serde_json::to_string(report).expect("report remains serializable");
        let (detected, lines) =
            detected::from_report_json(&report_json).expect("semantic report is measurable");
        let metrics = evaluate_by_rule(&detected, &labels, lines, DEFAULT_MATCH_THRESHOLD, 10);
        (detected, metrics)
    };
    let first = scan(corpus.path());
    let second = scan(corpus.path());
    assert_eq!(measure(&first), measure(&second));
}

/// Repeating a real-helper scan of the same labelled semantic corpus must
/// preserve both the reported findings and every per-rule metric. This keeps
/// result stability and the per-kLOC rates in the same regression contract as
/// the closed positive and negative examples.
#[test]
#[ignore = "requires codehelion-backend-rust"]
fn semantic_rule_metrics_are_stable_across_fresh_scans() {
    let (corpus, labels) = restricted_semantic_rust_corpus();
    let first = scan(corpus.path());
    let second = scan(corpus.path());
    let measure = |report: &Value| {
        let report_json = serde_json::to_string(report).expect("report remains serializable");
        let (detected, lines) =
            detected::from_report_json(&report_json).expect("semantic report is measurable");
        let metrics = evaluate_by_rule(&detected, &labels, lines, DEFAULT_MATCH_THRESHOLD, 10);
        (detected, metrics)
    };
    let (first_detected, first_metrics) = measure(&first);
    let (second_detected, second_metrics) = measure(&second);
    assert_eq!(first_detected, second_detected);
    assert_eq!(first_metrics, second_metrics);
    assert!(first_metrics.values().all(|metrics| {
        metrics.findings_per_kloc > 0.0
            && metrics.false_positives_per_kloc == 0.0
            && metrics.non_clone_hits == 0
    }));
}

/// A registered sequence embedded beside unrelated registered constructs is a
/// fragment finding. Its source lines must name the iterator expression, not
/// the enclosing function, while its graph retains only the sequence nodes.
#[test]
#[ignore = "requires codehelion-backend-rust"]
fn semantic_scan_reports_partial_pipeline_source_ranges() {
    let fixture = rust_partial_pipeline_fixture();
    let report = scan(fixture.path());
    let group = report["groups"]
        .as_array()
        .expect("groups array")
        .iter()
        .find(|group| {
            group["clone_type"] == "restricted-semantic"
                && group["semantic"]["rules"][0]["id"] == "sequence-pipeline-v1"
        })
        .unwrap_or_else(|| panic!("partial pipelines form a semantic finding: {report}"));
    assert_eq!(group["scope"], "fragment");
    for member in group["members"].as_array().expect("group members") {
        assert!(
            matches!(member["start_line"].as_u64(), Some(2 | 7)),
            "the finding must start at its iterator expression: {member:#}"
        );
        assert_eq!(member["start_line"], member["end_line"]);
    }
    for graph in group["semantic"]["graphs"]
        .as_array()
        .expect("semantic graphs")
    {
        assert_eq!(
            graph["nodes"]
                .as_array()
                .expect("graph nodes")
                .iter()
                .map(|node| node["kind"].as_str())
                .collect::<Vec<_>>(),
            vec![Some("source"), Some("filter"), Some("map"), Some("collect")]
        );
    }
}

/// A plain explicit collection loop is comparable to the registered iterator
/// collection pipeline when both represent only source and collection.
#[test]
#[ignore = "requires codehelion-backend-rust"]
fn semantic_scan_matches_a_plain_collection_loop_to_an_iterator_pipeline() {
    let fixture = rust_loop_pipeline_fixture();
    let report = scan(fixture.path());
    let group = report["groups"]
        .as_array()
        .expect("groups array")
        .iter()
        .find(|group| {
            group["clone_type"] == "restricted-semantic"
                && group["semantic"]["rules"][0]["id"] == "sequence-pipeline-v1"
                && group["members"].as_array().map(Vec::len) == Some(2)
        })
        .unwrap_or_else(|| {
            panic!("plain loop and iterator pipeline form a semantic finding: {report}")
        });
    for graph in group["semantic"]["graphs"]
        .as_array()
        .expect("semantic graphs")
    {
        assert_eq!(
            graph["nodes"]
                .as_array()
                .expect("graph nodes")
                .iter()
                .map(|node| node["kind"].as_str())
                .collect::<Vec<_>>(),
            vec![Some("source"), Some("collect")],
            "the loop normalizer admitted an unregistered operation: {graph:#}"
        );
    }
}

/// The resource rule is available only when the Rust helper proved the direct
/// standard acquisition and the lexical scope supplied its `Drop` boundary.
#[test]
#[ignore = "requires codehelion-backend-rust"]
fn semantic_scan_matches_direct_standard_file_lifetimes() {
    let fixture = rust_resource_lifetime_fixture();
    let report = scan(fixture.path());
    let group = report["groups"]
        .as_array()
        .expect("groups array")
        .iter()
        .find(|group| {
            group["clone_type"] == "restricted-semantic"
                && group["semantic"]["rules"][0]["id"] == "resource-lifecycle-v1"
        })
        .unwrap_or_else(|| panic!("direct standard file lifetimes form a finding: {report}"));
    assert_eq!(group["members"].as_array().map(Vec::len), Some(3));
    assert_eq!(group["split_pair"], false);
    assert!(
        group["semantic"]["rules"][0]["confidence"]
            .as_f64()
            .is_some_and(|confidence| (confidence - 0.4725).abs() < f64::EPSILON),
        "{group:#}"
    );
    assert_eq!(
        group["semantic"]["node_mappings"].as_array().map(Vec::len),
        Some(4),
        "each non-canonical graph must retain both resource-node mappings: {group:#}"
    );
    for graph in group["semantic"]["graphs"]
        .as_array()
        .expect("semantic graphs")
    {
        assert_eq!(
            graph["nodes"]
                .as_array()
                .expect("graph nodes")
                .iter()
                .map(|node| node["kind"].as_str())
                .collect::<Vec<_>>(),
            vec![Some("acquire_resource"), Some("release_resource")],
            "the resource graph admitted an unrelated operation: {graph:#}"
        );
        assert_eq!(
            graph["edges"]
                .as_array()
                .expect("graph edges")
                .iter()
                .filter(|edge| edge["kind"] == "resource_lifetime")
                .count(),
            1,
            "the resource graph lost its lifecycle edge: {graph:#}"
        );
    }
}

/// `Iterator::fold` is a closed reduce operation, not an API-name suffix
/// guess: the helper must resolve both the source and fold calls before the
/// same sequence rule may compare the two functions.
#[test]
#[ignore = "requires codehelion-backend-rust"]
fn semantic_scan_matches_registered_iterator_reductions() {
    let fixture = rust_reduce_pipeline_fixture();
    let report = scan(fixture.path());
    let group = report["groups"]
        .as_array()
        .expect("groups array")
        .iter()
        .find(|group| {
            group["clone_type"] == "restricted-semantic"
                && group["semantic"]["rules"][0]["id"] == "sequence-pipeline-v1"
                && group["semantic"]["graphs"]
                    .as_array()
                    .is_some_and(|graphs| {
                        graphs.iter().all(|graph| {
                            graph["nodes"].as_array().is_some_and(|nodes| {
                                nodes
                                    .iter()
                                    .map(|node| node["kind"].as_str())
                                    .eq([Some("source"), Some("reduce")])
                            })
                        })
                    })
        })
        .unwrap_or_else(|| {
            panic!("two registered iterator reductions form a semantic finding: {report}")
        });
    assert_eq!(group["members"].as_array().map(Vec::len), Some(2));
    assert_eq!(
        group["semantic"]["node_mappings"].as_array().map(Vec::len),
        Some(2)
    );
}

/// A direct arithmetic loop is admitted only as SOURCE/REDUCE and therefore
/// pairs with the same closed iterator reduction. Its guarded sibling is not
/// reconstructed as a reduction of every element.
#[test]
#[ignore = "requires codehelion-backend-rust"]
fn semantic_scan_matches_a_plain_reduce_loop_to_an_iterator_reduction() {
    let fixture = rust_loop_reduce_fixture();
    let report = scan(fixture.path());
    let run_id = report["run"]["run_id"].as_i64().expect("run id");
    let compiler_units = Store::open(&fixture.path().join(".codehelion/audit.db"))
        .expect("open audit database")
        .run_compiler_units(run_id)
        .expect("read compiler analyses");
    let compiler_ir = compiler_units
        .iter()
        .find_map(|analysis| match &analysis.outcome {
            CompilerOutcome::Analyzed(ir) => Some(ir),
            CompilerOutcome::Unavailable { .. } => None,
        })
        .expect("Rust helper analysis");
    let constructs = &compiler_ir.semantic_constructs;
    assert_eq!(
        constructs
            .iter()
            .filter(|construct| construct.kind.name() == "reduce")
            .count(),
        1,
        "the guarded loop must not enter the reduction vocabulary: {constructs:?}"
    );
    let group = report["groups"]
        .as_array()
        .expect("groups array")
        .iter()
        .find(|group| {
            group["clone_type"] == "restricted-semantic"
                && group["semantic"]["rules"][0]["id"] == "sequence-pipeline-v1"
                && group["semantic"]["graphs"]
                    .as_array()
                    .is_some_and(|graphs| {
                        graphs.iter().all(|graph| {
                            graph["nodes"].as_array().is_some_and(|nodes| {
                                nodes
                                    .iter()
                                    .map(|node| node["kind"].as_str())
                                    .eq([Some("source"), Some("reduce")])
                            })
                        })
                    })
        })
        .unwrap_or_else(|| {
            panic!(
                "plain loop and iterator reduction form a finding; constructs: {constructs:?}; calls: {:?}; report: {report}",
                compiler_ir.calls
            )
        });
    assert_eq!(group["members"].as_array().map(Vec::len), Some(2));
}

/// The direct `Result` rule needs the helper-confirmed form on both sides;
/// a naked propagation expression is insufficient evidence for a finding.
#[test]
#[ignore = "requires codehelion-backend-rust"]
fn semantic_scan_matches_only_direct_result_propagation_forms() {
    let fixture = rust_direct_propagation_fixture();
    let report = scan(fixture.path());
    let groups = report["groups"].as_array().expect("groups array");
    let group = groups
        .iter()
        .find(|group| {
            group["clone_type"] == "restricted-semantic"
                && group["semantic"]["rules"][0]["id"] == "result-direct-propagation-v1"
        })
        .expect("direct Result adapters form a semantic finding");
    assert_eq!(group["members"].as_array().map(Vec::len), Some(2));
    for graph in group["semantic"]["graphs"]
        .as_array()
        .expect("semantic graphs")
    {
        assert_eq!(
            graph["nodes"]
                .as_array()
                .expect("graph nodes")
                .iter()
                .map(|node| node["kind"].as_str())
                .collect::<Vec<_>>(),
            vec![Some("propagate_error")]
        );
        assert_eq!(
            graph["nodes"][0]["attributes"]["direct_propagation"],
            "result_adapter"
        );
    }
    assert!(groups.iter().all(|group| {
        group["semantic"]["rules"][0]["id"] != "result-direct-propagation-v1"
            || group["members"].as_array().map(Vec::len) != Some(3)
    }));
}

/// Direct `Option` adapters need compiler confirmation of an identity form;
/// a transformation after `?` and a project constructor named `Some` remain
/// non-matches even though both functions have the same standard fallible type.
#[test]
#[ignore = "requires codehelion-backend-rust"]
fn semantic_scan_matches_only_direct_option_propagation_forms() {
    let fixture = rust_direct_propagation_fixture();
    let report = scan(fixture.path());
    let groups = report["groups"].as_array().expect("groups array");
    let group = groups
        .iter()
        .find(|group| {
            group["clone_type"] == "restricted-semantic"
                && group["semantic"]["rules"][0]["id"] == "option-direct-propagation-v1"
        })
        .unwrap_or_else(|| panic!("direct Option adapters form a semantic finding: {report}"));
    assert_eq!(group["members"].as_array().map(Vec::len), Some(2));
    for graph in group["semantic"]["graphs"]
        .as_array()
        .expect("semantic graphs")
    {
        assert_eq!(graph["nodes"][0]["attributes"]["fallible_kind"], "option");
        assert_eq!(
            graph["nodes"][0]["attributes"]["direct_propagation"],
            "option_adapter"
        );
    }
    assert!(groups.iter().all(|group| {
        group["semantic"]["rules"][0]["id"] != "option-direct-propagation-v1"
            || group["members"].as_array().map(Vec::len) != Some(3)
    }));
}

/// Direct standard `Option::is_some`, a standard `Option` match, and the
/// narrow early unit-return guard have the same closed validation evidence.
/// Compound and other inverted conditions remain outside the vocabulary.
#[test]
#[ignore = "requires codehelion-backend-rust"]
fn semantic_scan_matches_only_direct_option_presence_checks() {
    let fixture = rust_optional_validation_fixture();
    let report = scan(fixture.path());
    let groups = report["groups"].as_array().expect("groups array");
    let group = groups
        .iter()
        .find(|group| {
            group["clone_type"] == "restricted-semantic"
                && group["semantic"]["rules"][0]["id"] == "optional-validation-v1"
        })
        .unwrap_or_else(|| panic!("direct optional checks form a semantic finding: {report}"));
    assert_eq!(group["members"].as_array().map(Vec::len), Some(5));
    for graph in group["semantic"]["graphs"]
        .as_array()
        .expect("semantic graphs")
    {
        assert_eq!(
            graph["nodes"]
                .as_array()
                .expect("graph nodes")
                .iter()
                .map(|node| node["kind"].as_str())
                .collect::<Vec<_>>(),
            vec![Some("validate")]
        );
        assert_eq!(graph["nodes"][0]["attributes"]["fallible_kind"], "option");
        assert!(graph["nodes"][0]["attributes"]["direct_propagation"].is_null());
    }
    assert!(groups.iter().all(|group| {
        group["semantic"]["rules"][0]["id"] != "optional-validation-v1"
            || group["members"].as_array().map(Vec::len) != Some(6)
    }));
}

/// A direct standard `Result::is_ok` condition is independently comparable.
/// Compound and project-defined `is_ok` conditions stay outside the closed
/// vocabulary, despite sharing the same source-level method spelling.
#[test]
#[ignore = "requires codehelion-backend-rust"]
fn semantic_scan_matches_only_direct_result_presence_checks() {
    let fixture = rust_result_validation_fixture();
    let report = scan(fixture.path());
    let groups = report["groups"].as_array().expect("groups array");
    let group = groups
        .iter()
        .find(|group| {
            group["clone_type"] == "restricted-semantic"
                && group["semantic"]["rules"][0]["id"] == "result-validation-v1"
        })
        .unwrap_or_else(|| panic!("direct result checks form a semantic finding: {report}"));
    assert_eq!(group["members"].as_array().map(Vec::len), Some(2));
    for graph in group["semantic"]["graphs"]
        .as_array()
        .expect("semantic graphs")
    {
        assert_eq!(
            graph["nodes"]
                .as_array()
                .expect("graph nodes")
                .iter()
                .map(|node| node["kind"].as_str())
                .collect::<Vec<_>>(),
            vec![Some("validate")]
        );
        assert_eq!(graph["nodes"][0]["attributes"]["fallible_kind"], "result");
        assert!(graph["nodes"][0]["attributes"]["direct_propagation"].is_null());
    }
    assert!(groups.iter().all(|group| {
        group["semantic"]["rules"][0]["id"] != "result-validation-v1"
            || group["members"].as_array().map(Vec::len) != Some(3)
    }));
}

/// The Rust `Ok(value?)` and C++23 `return expected_value;` forms meet only
/// through the explicit result/expected propagation rule. Transformed forms
/// are not candidates for the direct-adapter correspondence.
#[test]
#[ignore = "requires codehelion-backend-rust, codehelion-backend-clang, and libclang"]
fn semantic_cross_language_result_expected_uses_closed_propagation_evidence() {
    let fixture = cross_language_result_expected_fixture();
    let report = scan_comparing_languages(fixture.path());
    let comparison = report["cross_language_comparison"]
        .as_object()
        .expect("cross-language comparison");
    let group = comparison["groups"]
        .as_array()
        .expect("comparison groups")
        .iter()
        .find(|group| {
            group["rule_id"] == "cross-language-result-direct-propagation-v1"
                && group["correspondence_ids"]
                    == serde_json::json!(["result-expected-direct-propagation-v1"])
        })
        .unwrap_or_else(|| panic!("closed Result/expected correspondence: {comparison:?}"));
    assert_eq!(group["members"].as_array().map(Vec::len), Some(2));
    assert!(group["members"].as_array().is_some_and(|members| {
        members.iter().all(|member| {
            member["graph"]["nodes"].as_array().is_some_and(|nodes| {
                nodes.len() == 1
                    && nodes[0]["kind"] == "propagate_error"
                    && nodes[0]["attributes"]["fallible_kind"] == "result"
                    && nodes[0]["attributes"]["direct_propagation"] == "result_adapter"
            })
        })
    }));
    assert!(comparison["groups"].as_array().is_some_and(|groups| {
        groups.iter().all(|other| {
            other["rule_id"] != "cross-language-result-direct-propagation-v1"
                || other["members"].as_array().map(Vec::len) != Some(3)
        })
    }));

    let labels = LabelSet::from_json(
        &std::fs::read_to_string(fixture.path().join("labels.json"))
            .expect("read result/expected corpus labels"),
    )
    .expect("parse result/expected corpus labels");
    let (detected, lines) = detected::from_cross_language_comparison_json(
        &serde_json::to_string(&report).expect("comparison remains serializable"),
    )
    .expect("comparison is measurable");
    let metrics = evaluate(&detected, &labels, lines, DEFAULT_MATCH_THRESHOLD, 10);
    assert!(
        (metrics.recall_overall - 1.0).abs() < f64::EPSILON,
        "{metrics:?}\nlabels: {labels:?}\ndetected: {detected:?}"
    );
    assert!(
        (metrics.precision_overall - 1.0).abs() < f64::EPSILON,
        "{metrics:?}"
    );
    assert_eq!(metrics.non_clone_hits, 0, "{metrics:?}");
    let by_rule = evaluate_by_rule(&detected, &labels, lines, DEFAULT_MATCH_THRESHOLD, 10);
    for rule_id in [
        "cross-language-result-direct-propagation-v1",
        "cross-language-result-validation-v1",
    ] {
        let rule_metrics = &by_rule[rule_id];
        assert!(
            (rule_metrics.recall_overall - 1.0).abs() < f64::EPSILON,
            "{rule_id}: {rule_metrics:?}"
        );
        assert!(
            (rule_metrics.precision_overall - 1.0).abs() < f64::EPSILON,
            "{rule_id}: {rule_metrics:?}"
        );
    }
}

/// A presence branch is compared independently from propagation: the helpers
/// must resolve `Result::is_ok()` and `expected::has_value()` to their standard
/// families, while the compound forms remain outside the closed rule.
#[test]
#[ignore = "requires codehelion-backend-rust, codehelion-backend-clang, and libclang"]
fn semantic_cross_language_result_expected_uses_closed_validation_evidence() {
    let fixture = cross_language_result_expected_fixture();
    let report = scan_comparing_languages(fixture.path());
    let comparison = report["cross_language_comparison"]
        .as_object()
        .expect("cross-language comparison");
    let group = comparison["groups"]
        .as_array()
        .expect("comparison groups")
        .iter()
        .find(|group| {
            group["rule_id"] == "cross-language-result-validation-v1"
                && group["correspondence_ids"]
                    == serde_json::json!(["result-expected-validation-v1"])
        })
        .unwrap_or_else(|| panic!("closed Result/expected validation: {comparison:?}"));
    assert_eq!(group["members"].as_array().map(Vec::len), Some(2));
    assert!(group["members"].as_array().is_some_and(|members| {
        members.iter().all(|member| {
            member["graph"]["nodes"].as_array().is_some_and(|nodes| {
                nodes.len() == 1
                    && nodes[0]["kind"] == "validate"
                    && nodes[0]["attributes"]["fallible_kind"] == "result"
                    && nodes[0]["attributes"]["direct_propagation"].is_null()
            })
        })
    }));
    assert!(comparison["groups"].as_array().is_some_and(|groups| {
        groups.iter().all(|other| {
            other["rule_id"] != "cross-language-result-validation-v1"
                || other["members"].as_array().map(Vec::len) != Some(3)
        })
    }));
}

/// Disabling a stable rule ID removes only that registered semantic verdict;
/// the compiler-backed scan still completes and retains its ordinary
/// structural findings.
#[test]
#[ignore = "requires codehelion-backend-rust"]
fn semantic_rule_registry_can_disable_a_registered_pipeline() {
    let fixture = rust_pipeline_fixture();
    std::fs::write(
        fixture.path().join("codehelion.toml"),
        "[semantic]\ndisabled = [\"sequence-pipeline-v1\"]\n",
    )
    .expect("write semantic configuration");
    let report = scan(fixture.path());
    assert!(
        report["groups"]
            .as_array()
            .expect("groups array")
            .iter()
            .all(|group| group["clone_type"] != "restricted-semantic"),
        "a disabled rule emitted a restricted-semantic finding"
    );
    let disabled = report["summary"]["funnel"]
        .as_array()
        .expect("funnel array")
        .iter()
        .find(|stage| stage["stage"] == "semantic verified pairs")
        .and_then(|stage| stage["dropped"].as_array())
        .expect("semantic verifier accounted for the disabled rule");
    assert!(disabled.iter().any(|drop| {
        drop["cause"] == "rule_disabled" && drop["count"].as_u64().unwrap_or(0) > 0
    }));
}

/// Both helpers must answer a real Semantic CLI scan and persist their IR.
#[test]
#[ignore = "requires codehelion-backend-rust, codehelion-backend-clang, and libclang"]
fn semantic_helpers_store_compiler_ir_for_rust_and_cpp() {
    let rust_dir = rust_fixture();
    let rust_root = rust_dir.path();
    let rust_report = scan(rust_root);
    let rust_run = rust_report["run"]["run_id"].as_i64().expect("Rust run id");
    assert_eq!(rust_report["summary"]["compiler"]["answered"], 1);
    assert!(stored_ir(rust_root, rust_run), "Rust helper stored no IR");

    let cpp_dir = tempfile::tempdir().expect("temporary C++ project");
    let cpp_root = codehelion_fixtures::copy_cpp("header-only", cpp_dir.path())
        .expect("copy C++ fixture with its compilation database");
    let cpp_report = scan(&cpp_root);
    let partitions = cpp_report["partitions"]
        .as_array()
        .expect("C++ definitions produce independent reports");
    assert_eq!(partitions.len(), 2);
    assert!(partitions.iter().all(|partition| {
        let run_id = partition["run"]["run_id"].as_i64().expect("C++ run id");
        partition["summary"]["compiler"]["answered"] == 2 && stored_ir(&cpp_root, run_id)
    }));
}

/// An opt-in comparison keeps the Rust and C++ normal scans independent while
/// recording a separately justified correspondence with both source graphs.
#[test]
#[ignore = "requires codehelion-backend-rust, codehelion-backend-clang, and libclang"]
#[allow(
    clippy::too_many_lines,
    reason = "the end-to-end assertion fixes output, evidence, persistence, and measurement together"
)]
fn semantic_cross_language_comparison_records_closed_api_evidence() {
    let fixture = cross_language_pipeline_fixture();
    let root = fixture.path().to_path_buf();

    let ordinary = scan(&root);
    assert!(
        ordinary.get("cross_language_comparison").is_none(),
        "ordinary semantic scans do not join language partitions: {ordinary}"
    );
    let store = Store::open(&root.join(".codehelion/audit.db")).expect("open audit database");
    assert_eq!(
        store
            .table_count("cross_language_comparison")
            .expect("count comparisons"),
        0
    );

    let compared = scan_comparing_languages(&root);
    let comparison = &compared["cross_language_comparison"];
    assert_eq!(
        comparison["comparison_kind"], "restricted-semantic-rust-cpp-pipelines",
        "cross-language comparison was not emitted: {compared}"
    );
    assert_eq!(
        comparison["origin_variants"].as_array().map(Vec::len),
        Some(2),
        "the comparison domain holds one Rust and one C++ variant: {compared}"
    );
    let group = comparison["groups"]
        .as_array()
        .expect("cross-language groups")
        .iter()
        .find(|group| {
            group["rule_id"] == "cross-language-sequence-pipeline-v1"
                && group["correspondence_ids"].as_array().is_some_and(|ids| {
                    ids.iter()
                        .map(Value::as_str)
                        .eq([Some("sequence-source-v1"), Some("sequence-collect-v1")])
                })
        })
        .unwrap_or_else(|| panic!("closed Rust/C++ pipeline correspondence: {comparison}"));
    assert!(
        group["semantic_confidence"]
            .as_f64()
            .is_some_and(|confidence| (0.0..=0.55).contains(&confidence)),
        "cross-language confidence must stay at or below its lower policy base: {group}"
    );
    let members = group["members"].as_array().expect("comparison members");
    assert_eq!(members.len(), 2);
    assert!(members.iter().any(|member| member["language"] == "rust"));
    assert!(members.iter().any(|member| member["language"] == "cpp"));
    assert!(members.iter().all(|member| {
        member["graph"]["nodes"].as_array().is_some_and(|nodes| {
            nodes
                .iter()
                .map(|node| node["kind"].as_str())
                .eq([Some("source"), Some("collect")])
        })
    }));
    let optional = comparison["groups"]
        .as_array()
        .expect("cross-language groups")
        .iter()
        .find(|group| {
            group["rule_id"] == "cross-language-optional-validation-v1"
                && group["correspondence_ids"]
                    == serde_json::json!(["optional-presence-validation-v1"])
        })
        .unwrap_or_else(|| panic!("closed Rust/C++ optional correspondence: {comparison}"));
    assert!(optional["members"].as_array().is_some_and(|members| {
        members.iter().all(|member| {
            member["graph"]["nodes"].as_array().is_some_and(|nodes| {
                nodes.len() == 1
                    && nodes[0]["kind"] == "validate"
                    && nodes[0]["attributes"]["fallible_kind"] == "option"
            })
        })
    }));

    let labels = LabelSet::from_json(
        &std::fs::read_to_string(root.join("labels.json")).expect("read corpus labels"),
    )
    .expect("parse cross-language corpus labels");
    let (detected, lines) = detected::from_cross_language_comparison_json(
        &serde_json::to_string(&compared).expect("comparison remains serializable"),
    )
    .expect("comparison is measurable");
    let metrics = evaluate(&detected, &labels, lines, DEFAULT_MATCH_THRESHOLD, 10);
    assert!(
        (metrics.recall_overall - 1.0).abs() < f64::EPSILON,
        "{metrics:?}"
    );
    assert!(
        (metrics.precision_overall - 1.0).abs() < f64::EPSILON,
        "{metrics:?}"
    );
    assert_eq!(metrics.non_clone_hits, 0, "{metrics:?}");
    let by_rule = evaluate_by_rule(&detected, &labels, lines, DEFAULT_MATCH_THRESHOLD, 10);
    for rule_id in [
        "cross-language-sequence-pipeline-v1",
        "cross-language-optional-validation-v1",
    ] {
        let rule_metrics = &by_rule[rule_id];
        assert!(
            (rule_metrics.recall_overall - 1.0).abs() < f64::EPSILON,
            "{rule_id}: {rule_metrics:?}"
        );
        assert!(
            (rule_metrics.precision_overall - 1.0).abs() < f64::EPSILON,
            "{rule_id}: {rule_metrics:?}"
        );
    }

    let store = Store::open(&root.join(".codehelion/audit.db")).expect("reopen audit database");
    assert_eq!(
        store
            .table_count("cross_language_comparison")
            .expect("count comparisons"),
        1
    );
    assert_eq!(
        store
            .table_count("cross_language_semantic_group")
            .expect("count groups"),
        2
    );
    assert_eq!(
        store
            .table_count("cross_language_semantic_member")
            .expect("count members"),
        4
    );
}

/// Direct loop correspondence stays cross-language only when both compiler
/// helpers establish the narrow, untransformed construct form.
#[test]
#[ignore = "requires codehelion-backend-rust, codehelion-backend-clang, and libclang"]
fn semantic_cross_language_direct_loops_have_closed_construct_evidence() {
    let fixture = cross_language_direct_loop_fixture();
    let root = fixture.path();
    let compared = scan_comparing_languages(root);
    let groups = compared["cross_language_comparison"]["groups"]
        .as_array()
        .expect("cross-language groups");
    let direct_groups: Vec<_> = groups
        .iter()
        .filter(|group| {
            group["rule_id"] == "cross-language-sequence-pipeline-v1"
                && group["correspondence_ids"] == serde_json::json!(["direct-loop-sequence-v1"])
        })
        .collect();
    assert_eq!(direct_groups.len(), 2, "{groups:?}");
    assert!(direct_groups.iter().all(|group| {
        group["members"].as_array().is_some_and(|members| {
            members.iter().all(|member| {
                member["graph"]["nodes"].as_array().is_some_and(|nodes| {
                    nodes.len() == 2
                        && nodes[0]["kind"] == "source"
                        && matches!(nodes[1]["kind"].as_str(), Some("collect" | "reduce"))
                        && nodes
                            .iter()
                            .all(|node| node["attributes"]["api_names"] == serde_json::json!([]))
                })
            })
        })
    }));

    let labels = LabelSet::from_json(
        &std::fs::read_to_string(root.join("labels.json")).expect("read corpus labels"),
    )
    .expect("parse cross-language loop labels");
    let (detected, lines) = detected::from_cross_language_comparison_json(
        &serde_json::to_string(&compared).expect("comparison remains serializable"),
    )
    .expect("comparison is measurable");
    let metrics = &evaluate_by_rule(&detected, &labels, lines, DEFAULT_MATCH_THRESHOLD, 10)["cross-language-sequence-pipeline-v1"];
    assert!(
        (metrics.recall_overall - 1.0).abs() < f64::EPSILON,
        "{metrics:?}"
    );
    assert!(
        (metrics.precision_overall - 1.0).abs() < f64::EPSILON,
        "{metrics:?}"
    );
    assert_eq!(metrics.non_clone_hits, 0, "{metrics:?}");
}

/// A helper re-run, rather than a reused snapshot, must return the same IR
/// under an unchanged build variant.
#[test]
#[ignore = "requires codehelion-backend-rust"]
fn semantic_rust_ir_is_deterministic_across_fresh_scans() {
    let fixture = rust_fixture();
    let root = fixture.path();
    let first = scan(root);
    let second = scan(root);
    let first_run = first["run"]["run_id"].as_i64().expect("first run id");
    let second_run = second["run"]["run_id"].as_i64().expect("second run id");
    let store = Store::open(&root.join(".codehelion/audit.db")).expect("open audit database");
    assert_eq!(
        store
            .run_compiler_units(first_run)
            .expect("read first compiler IR"),
        store
            .run_compiler_units(second_run)
            .expect("read second compiler IR")
    );
    assert_eq!(
        first["run"]["build_variant"],
        second["run"]["build_variant"]
    );
    assert_eq!(first["summary"]["compiler"], second["summary"]["compiler"]);
}

/// The compiler-backed pipeline must preserve the committed corpus's full
/// Type-1/2/3 coverage. In particular, the Type-3 mutation has a valid edge
/// that complete linkage reports as a split pair rather than silently losing
/// it while the neighbouring exact copies form a group.
#[test]
#[ignore = "requires codehelion-backend-rust"]
fn semantic_rust_corpus_keeps_structural_coverage_and_reports_the_split_type3_pair() {
    let (corpus, labels) = semantic_rust_corpus();
    let structural = scan_mode(corpus.path(), "structural");
    let semantic = scan(corpus.path());

    for (mode, report) in [("structural", &structural), ("semantic", &semantic)] {
        let report_json = serde_json::to_string(report).expect("report remains serializable");
        let (result, lines) = detected::from_report_json(&report_json)
            .unwrap_or_else(|error| panic!("read {mode} corpus report: {error}"));
        let metrics = evaluate(&result, &labels, lines, DEFAULT_MATCH_THRESHOLD, 10);
        assert!(
            (metrics.recall_overall - 1.0).abs() < f64::EPSILON,
            "{mode} recall: {}",
            metrics.recall_overall
        );
        assert!(
            (metrics.precision_overall - 1.0).abs() < f64::EPSILON,
            "{mode} precision: {}",
            metrics.precision_overall
        );
        assert_eq!(metrics.non_clone_hits, 0, "{mode} non-clone hits");
    }

    assert_eq!(semantic["summary"]["compiler"]["answered"], 4);
    let split_type3 = semantic["groups"]
        .as_array()
        .expect("Semantic report groups")
        .iter()
        .find(|group| group["clone_type"] == "type-3" && group["split_pair"] == true)
        .expect("Semantic report retains the Type-3 split pair");
    let members = split_type3["members"]
        .as_array()
        .expect("split pair members");
    assert!(members.iter().any(|member| {
        member["file"] == "src/lib.rs" && member["start_line"] == 4 && member["end_line"] == 12
    }));
    assert!(members.iter().any(|member| {
        member["file"] == "src/type3.rs" && member["start_line"] == 4 && member["end_line"] == 15
    }));
}

/// C++ compilation-database partitions are independently re-asked and keep
/// both their selected build variant and their compiler IR across fresh runs.
#[test]
#[ignore = "requires codehelion-backend-clang and libclang"]
fn semantic_cpp_ir_is_deterministic_across_fresh_scans() {
    let directory = tempfile::tempdir().expect("temporary C++ project");
    let root = codehelion_fixtures::copy_cpp("header-only", directory.path())
        .expect("copy C++ fixture with its compilation database");
    let first = scan(&root);
    let second = scan(&root);
    let first_partitions = first["partitions"].as_array().expect("first partitions");
    let second_partitions = second["partitions"].as_array().expect("second partitions");
    assert_eq!(first_partitions.len(), second_partitions.len());
    let store = Store::open(&root.join(".codehelion/audit.db")).expect("open audit database");
    for (first, second) in first_partitions.iter().zip(second_partitions) {
        let first_run = first["run"]["run_id"].as_i64().expect("first run id");
        let second_run = second["run"]["run_id"].as_i64().expect("second run id");
        assert_eq!(
            first["run"]["build_variant"],
            second["run"]["build_variant"]
        );
        assert_eq!(first["summary"]["compiler"], second["summary"]["compiler"]);
        assert_eq!(
            store
                .run_compiler_units(first_run)
                .expect("read first compiler IR"),
            store
                .run_compiler_units(second_run)
                .expect("read second compiler IR")
        );
    }
}

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
    let expected: Value = serde_json::from_str(include_str!("fixtures/semantic/rust-ir.json"))
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
    let expected: Value = serde_json::from_str(include_str!("fixtures/semantic/c-ir.json"))
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
    let expected: Value = serde_json::from_str(include_str!("fixtures/semantic/cpp-ir.json"))
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
