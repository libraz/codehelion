//! What this helper reports about projects whose answer is known by reading
//! them.
//!
//! Driven through the real client against the real program, because everything
//! worth checking here is a claim about two processes: that the handshake
//! agrees, that a unit comes back with the types a person can verify by opening
//! the fixture, and — the claim this language exists to make — that one header
//! read by two translation units comes back as two different programs.
//!
//! `CARGO_BIN_EXE_` rather than a constructed path: a test that guesses where a
//! binary lands can run a stale copy and report success.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::time::Duration;

use codehelion_helper::ir::{ResolvedType, TypeCategory, Unavailability, UnitRef};
use codehelion_helper::protocol::{Capability, Execution};
use codehelion_helper::{Analysis, COMPILER_IR_SCHEMA_VERSION, CompilerIr, Helper};

/// Parsing a translation unit reads every header it includes, which on a cold
/// machine is slower than the protocol's default.
const PATIENT: Duration = Duration::from_secs(120);

fn helper() -> Helper {
    Helper::start(
        Path::new(env!("CARGO_BIN_EXE_codehelion-backend-clang")),
        PATIENT,
    )
    .expect("the helper should start and shake hands")
}

/// A fixture copied somewhere its rendered database can sit beside its sources.
struct Planted {
    /// Kept so the directory outlives the test that reads it.
    _directory: tempfile::TempDir,
    root: PathBuf,
}

fn plant(fixture: &str) -> Planted {
    let directory = tempfile::tempdir().expect("temp dir");
    let root = codehelion_fixtures::copy_cpp(fixture, directory.path()).expect("copy the fixture");
    Planted {
        // Resolved because a scan resolves the path it was pointed at, and the
        // answers are spelled against the tree as the filesystem has it. A test
        // that named the same tree another way would be testing an arrangement
        // no run makes.
        root: root.canonicalize().expect("the copy is there"),
        _directory: directory,
    }
}

impl Planted {
    /// The file `file`, as read by the translation unit `unit`.
    fn unit(&self, unit: &str, file: &str) -> UnitRef {
        UnitRef {
            unit: unit.to_string(),
            file: self.root.join(file).display().to_string(),
            variant: "host".to_string(),
        }
    }
}

fn analyze(unit: &UnitRef) -> Analysis {
    let mut helper = helper();
    let analysis = helper
        .analyze(unit, &[Capability::Types])
        .expect("the helper should answer");
    helper.shutdown().expect("the helper should stop cleanly");
    analysis
}

fn analyzed(unit: &UnitRef) -> Box<CompilerIr> {
    match analyze(unit) {
        Analysis::Done(ir) => ir,
        Analysis::Missing(reason) => panic!("expected an analysis, got {reason:?}"),
    }
}

/// The resolved type of the first symbol called `name`.
fn type_of<'a>(ir: &'a CompilerIr, name: &str) -> &'a ResolvedType {
    let symbol = ir
        .symbols
        .iter()
        .find(|symbol| symbol.name == name && symbol.type_index.is_some())
        .unwrap_or_else(|| {
            panic!(
                "no typed symbol called {name}; the unit holds {:?}",
                ir.symbols.iter().map(|s| &s.name).collect::<Vec<_>>()
            )
        });
    &ir.types[symbol.type_index.unwrap() as usize]
}

#[test]
fn the_helper_says_which_compiler_will_answer_and_what_it_will_not_do() {
    let helper = helper();
    let identity = helper.identity();
    assert_eq!(identity.name, "codehelion-backend-clang");
    assert!(
        identity
            .toolchains
            .first()
            .is_some_and(|toolchain| toolchain.contains("clang")),
        "{:?}",
        identity.toolchains
    );
    assert!(helper.offers(Capability::Types));
    assert!(helper.offers(Capability::NameResolution));
    // libclang does not expose Clang's control-flow graph. Claiming it and
    // answering nothing would leave a run recording that it got an answer.
    assert!(!helper.offers(Capability::MirCfg));
    // And nothing out of the project runs at any permission, which is what
    // lets permitting something be refused instead of quietly doing nothing.
    for class in [
        Execution::Configure,
        Execution::BuildScript,
        Execution::GeneratedSource,
    ] {
        assert!(!helper.executes(class), "{class:?}");
    }
    helper.shutdown().expect("the helper should stop cleanly");
}

/// The claim C++ exists to make here. One header, two translation units, and
/// the same characters declare a 32-bit accumulator in one and a 64-bit one in
/// the other — so an answer about the file alone would be one of the two
/// readings presented as the reading.
#[test]
fn one_header_read_by_two_units_is_two_different_programs() {
    let planted = plant("header-only");
    let header = "include/accumulate.hpp";

    let narrow = analyzed(&planted.unit("src/narrow.cpp", header));
    let wide = analyzed(&planted.unit("src/wide.cpp", header));

    // Both readings are of the same file, and both say so.
    for ir in [&narrow, &wide] {
        assert_eq!(ir.schema_version, COMPILER_IR_SCHEMA_VERSION);
        assert_eq!(
            ir.anchored_at.as_deref(),
            Some(planted.root.to_str().unwrap())
        );
        assert!(
            ir.symbols
                .iter()
                .any(|symbol| symbol.anchor.expansion.file == header),
            "the header the unit read is reported on"
        );
    }

    // And the compiler resolved one name to two widths, which is the whole
    // reason a unit is part of what is asked about. Both are integers — the
    // category is coarse on purpose — so what says they differ is the resolved
    // form, which is why that is what a type is recorded as.
    assert_eq!(type_of(&narrow, "total").category, TypeCategory::Integer);
    assert_eq!(type_of(&wide, "total").category, TypeCategory::Integer);
    assert_ne!(
        type_of(&narrow, "total").display,
        type_of(&wide, "total").display,
        "the same declaration resolves to a different type in each reading"
    );
}

/// A header is compiled by no command of its own, so nothing can be asked about
/// it as a unit. What reads it is a translation unit, and the answer about that
/// unit is where the header's names are — filed under the header, because a
/// name reported under the unit's own file would be attributed to a file it was
/// never written in.
///
/// What the unit read from outside the project stays out. `<vector>` is not
/// this project's code, nothing in the scan can be cut from it, and reporting
/// its thousands of declarations would bury the tree's own in them.
#[test]
fn a_header_is_answered_under_the_unit_that_reads_it() {
    let planted = plant("header-only");
    let ir = analyzed(&planted.unit("src/narrow.cpp", "src/narrow.cpp"));

    let files: std::collections::BTreeSet<&str> = ir
        .symbols
        .iter()
        .map(|symbol| symbol.anchor.expansion.file.as_str())
        .collect();
    assert!(
        files.contains("include/accumulate.hpp"),
        "the header the unit read is reported on: {files:?}"
    );
    assert!(
        files.contains("src/narrow.cpp"),
        "and so is the unit's own source: {files:?}"
    );
    assert_eq!(
        files.len(),
        2,
        "nothing from outside the tree is reported: {files:?}"
    );

    // Anchored where it is written, not where the request pointed: `sum` is
    // declared in the header and called from the source, and the two are
    // different places in different files.
    let declared = ir
        .symbols
        .iter()
        .find(|symbol| {
            symbol.name == "sum" && symbol.kind == codehelion_helper::ir::SymbolKind::Function
        })
        .expect("the header declares sum");
    assert_eq!(declared.anchor.expansion.file, "include/accumulate.hpp");
}

/// The categories are a claim about what libclang reports, so they are checked
/// against a fixture a person can open: `values` is a reference to a vector,
/// and what the code holds is the reference.
#[test]
fn a_type_is_reported_as_the_shape_another_language_would_recognise() {
    let planted = plant("header-only");
    let ir = analyzed(&planted.unit("src/narrow.cpp", "include/accumulate.hpp"));
    assert_eq!(type_of(&ir, "values").category, TypeCategory::Handle);
    assert_eq!(type_of(&ir, "total").category, TypeCategory::Integer);
    assert_eq!(type_of(&ir, "value").category, TypeCategory::Integer);
    // What the reference points at is recorded too, and it is the standard
    // library's sequence rather than a record that happens to be called vector.
    let element = type_of(&ir, "values")
        .arguments
        .first()
        .copied()
        .expect("what the reference points at");
    assert_eq!(ir.types[element as usize].category, TypeCategory::Sequence);
}

/// What the normalizer asks the compiler for: whether a name is this project's
/// own or one it shares with everything else that includes the same header.
#[test]
fn a_name_from_outside_the_tree_is_told_apart_from_the_projects_own() {
    let planted = plant("header-only");
    let ir = analyzed(&planted.unit("src/narrow.cpp", "include/accumulate.hpp"));
    let external = |name: &str| {
        ir.symbols
            .iter()
            .find(|symbol| symbol.name == name)
            .unwrap_or_else(|| panic!("no symbol called {name}"))
            .external
    };
    assert!(
        external("vector"),
        "the standard library is not this project"
    );
    assert!(!external("sum"), "the fixture's own function is");
    assert!(!external("accumulate"), "and so is its namespace");
}

/// A file no compilation database mentions is one nothing says how to compile.
/// Analysing it under some other unit's command would answer about a program it
/// is not part of.
#[test]
fn a_file_no_command_mentions_is_reported_rather_than_guessed_at() {
    let planted = plant("header-only");
    let stranger = planted.unit("src/nobody.cpp", "include/accumulate.hpp");
    assert!(matches!(
        analyze(&stranger),
        Analysis::Missing(Unavailability::NoBuildInformation)
    ));
}

/// A tree with no database at all is not a tree with an empty one: every C or
/// C++ file in it is a file nobody can speak for, and saying so is what tells a
/// thin answer apart from a project with nothing in it.
#[test]
fn a_tree_with_no_compilation_database_is_said_to_have_no_build_information() {
    let directory = tempfile::tempdir().expect("temp dir");
    std::fs::write(
        directory.path().join("lonely.cpp"),
        "int main() { return 0; }\n",
    )
    .unwrap();
    let unit = UnitRef {
        unit: "lonely.cpp".to_string(),
        file: directory.path().join("lonely.cpp").display().to_string(),
        variant: "host".to_string(),
    };
    assert!(matches!(
        analyze(&unit),
        Analysis::Missing(Unavailability::NoBuildInformation)
    ));
}

/// What a run files its answers under. The macros a unit is compiled with
/// decide which declarations its headers contain at all, so two readings of one
/// tree under different definitions are two programs and have to be filed
/// apart.
#[test]
fn a_tree_is_described_by_the_conditions_its_units_are_compiled_under() {
    let planted = plant("header-only");
    let mut helper = helper();
    let described = helper.describe(&planted.root).expect("it describes");
    assert_eq!(described.cfgs, vec!["-DACCUM_WIDTH=64".to_string()]);
    assert!(described.features.is_empty(), "a C++ build has no features");

    // A tree with no database has no C or C++ build to describe, which is an
    // answer: a project that is entirely Rust is not missing one, and refusing
    // here would stop a scan of it because this helper happened to be
    // installed.
    let empty = tempfile::tempdir().expect("temp dir");
    let nothing = helper.describe(empty.path()).expect("it describes");
    assert!(nothing.cfgs.is_empty(), "{nothing:?}");
    helper.shutdown().expect("the helper should stop cleanly");
}
