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

use codehelion_helper::ir::{
    CallSite, CallTarget, FallibleKind, ResolvedType, SemanticConstructKind, TypeCategory,
    Unavailability, UnitRef,
};
use codehelion_helper::protocol::{Capability, Execution};
use codehelion_helper::{Analysis, COMPILER_IR_SCHEMA_VERSION, CompilerIr, Helper};

/// Parsing a translation unit reads every header it includes, which on a cold
/// machine is slower than the protocol's default.
const PATIENT: Duration = Duration::from_secs(120);

/// Fixture prelude that includes `<expected>` where the standard library behind
/// this build has it, and records which way that went in a form the analysis
/// carries back.
///
/// Which standard library a machine compiles against is not this repository's
/// to pin, and it is not stable either: the same runner image has come with one
/// that has `<expected>` and one that does not on consecutive days. A case that
/// needs the type therefore reads back what was compiled rather than assuming
/// it, because the alternative reports the machine's standard library as a
/// defect in this code. What the case is about — that Clang resolved the
/// standard declaration — is unchanged where the type is there.
const EXPECTED_AVAILABILITY: &str = concat!(
    "#if __has_include(<version>)\n",
    "#include <version>\n",
    "#endif\n",
    "#if __has_include(<expected>) && defined(__cpp_lib_expected)\n",
    "#include <expected>\n",
    "#define CODEHELION_EXPECTED 1\n",
    "#endif\n",
    // Named rather than inspected as a macro: a preprocessor answer only
    // reaches this side of the helper by being compiled into something the
    // analysis reports, and a call is what puts a name in the symbol table.
    "namespace expected_availability {\n",
    "#ifdef CODEHELION_EXPECTED\n",
    "void standard_expected_is_present() {}\n",
    "void probe() { standard_expected_is_present(); }\n",
    "#else\n",
    "void standard_expected_is_absent() {}\n",
    "void probe() { standard_expected_is_absent(); }\n",
    "#endif\n",
    "}  // namespace expected_availability\n",
);

/// Whether the analyzed unit was compiled against a standard library carrying
/// `std::expected`, as [`EXPECTED_AVAILABILITY`] recorded it.
fn standard_expected_available(ir: &CompilerIr) -> bool {
    let present = ir
        .symbols
        .iter()
        .any(|symbol| symbol.name == "standard_expected_is_present");
    if !present {
        println!(
            "this build's standard library has no <expected>, so the C++23 half of this case \
             was compiled out and not judged"
        );
    }
    present
}

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
        .analyze(
            unit,
            &[
                Capability::Types,
                Capability::NameResolution,
                Capability::CallTargets,
                Capability::MacroExpansion,
                Capability::TemplateInstantiation,
            ],
        )
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

fn template_ir(planted: &Planted) -> Box<CompilerIr> {
    analyzed(&planted.unit("src/templates.cpp", "src/templates.cpp"))
}

fn template_source(planted: &Planted, file: &str) -> String {
    std::fs::read_to_string(planted.root.join(file))
        .unwrap_or_else(|error| panic!("read {file}: {error}"))
}

fn stamp_at<'a>(
    ir: &'a CompilerIr,
    file: &str,
    start: usize,
) -> &'a codehelion_helper::ir::Instantiation {
    ir.instantiations
        .iter()
        .find(|stamp| {
            stamp.anchor.expansion.file == file
                && stamp.anchor.expansion.start_byte == u64::try_from(start).unwrap()
        })
        .unwrap_or_else(|| {
            panic!(
                "no template stamp at {file}:{start}: {:?}",
                ir.instantiations
            )
        })
}

#[test]
fn project_arguments_cannot_reparse_options_from_config_or_response_files() {
    for nested_option in ["--config={path}", "@{path}"] {
        let directory = tempfile::tempdir().expect("temp dir");
        let root = directory.path().canonicalize().expect("temp dir exists");
        let source = root.join("unit.cpp");
        let options = root.join("project-options.cfg");
        std::fs::write(
            &source,
            "#ifdef OPTIONS_WERE_REPARSED\nint injected_by_options() { return 1; }\n#endif\n",
        )
        .expect("write source");
        std::fs::write(&options, "-DOPTIONS_WERE_REPARSED\n").expect("write nested options");
        let nested_option = nested_option.replace("{path}", &options.display().to_string());
        let database = serde_json::json!([{
            "directory": root,
            "arguments": ["clang++", "-std=c++20", nested_option, source],
            "file": source,
        }]);
        std::fs::write(
            root.join("compile_commands.json"),
            serde_json::to_vec_pretty(&database).expect("serialize database"),
        )
        .expect("write database");
        let unit = UnitRef {
            unit: source.display().to_string(),
            file: source.display().to_string(),
            variant: "host".to_string(),
        };

        let mut helper = helper();
        let analysis = helper
            .analyze(&unit, &[Capability::Types, Capability::MirCfg])
            .expect("the helper should reject the command without crashing");
        helper.shutdown().expect("the helper should stop cleanly");
        assert_eq!(
            analysis,
            Analysis::Missing(Unavailability::NoBuildInformation),
            "project-controlled nested options must fail closed: {nested_option}"
        );
    }
}

/// What the helper has said so far, waited for rather than raced.
///
/// The reason travels on one stream and the answer on another, and the client
/// collects the first on a thread of its own. A check that read them in the
/// order they were written would be reading a coincidence, so this waits for
/// the sentence to arrive and gives up long before a stuck helper could stall
/// the suite.
fn said_by(asked: &Helper) -> Vec<String> {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let said = asked.diagnostics();
        if !said.is_empty() || std::time::Instant::now() >= deadline {
            return said;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// A unit is refused for a reason, and this side is the only side that knows
/// it. Kept here, a report says how many units went unanswered and nothing
/// about whether the fix is a compiler argument this helper will not forward,
/// a database that is not there, or a header no command compiles — which have
/// different answers.
#[test]
fn a_unit_that_cannot_be_analysed_says_why_on_standard_error() {
    let directory = tempfile::tempdir().expect("temp dir");
    let root = directory.path().canonicalize().expect("temp dir exists");
    let source = root.join("unit.cpp");
    std::fs::write(&source, "int answer() { return 1; }\n").expect("write source");
    let unit = UnitRef {
        unit: source.display().to_string(),
        file: source.display().to_string(),
        variant: "host".to_string(),
    };

    // No database anywhere above the file, which is one thing that can be
    // wrong with it.
    let mut without_a_database = helper();
    let analysis = without_a_database
        .analyze(&unit, &[Capability::Types])
        .expect("the helper should answer without crashing");
    assert_eq!(
        analysis,
        Analysis::Missing(Unavailability::NoBuildInformation)
    );
    let said = said_by(&without_a_database);
    without_a_database
        .shutdown()
        .expect("the helper should stop cleanly");
    assert!(
        said.iter()
            .any(|line| line.contains("no compilation database") && line.contains("unit.cpp")),
        "{said:?}"
    );

    // And a database that does list the unit, under a command carrying an
    // option this helper will not hand a compiler. The same enum comes back
    // for both, and only the sentence tells them apart.
    let database = serde_json::json!([{
        "directory": root,
        "arguments": ["clang++", "-std=c++20", "-Xclang", "-load", source],
        "file": source,
    }]);
    std::fs::write(
        root.join("compile_commands.json"),
        serde_json::to_vec_pretty(&database).expect("serialize database"),
    )
    .expect("write database");

    let mut with_a_refused_argument = helper();
    let analysis = with_a_refused_argument
        .analyze(&unit, &[Capability::Types])
        .expect("the helper should answer without crashing");
    assert_eq!(
        analysis,
        Analysis::Missing(Unavailability::NoBuildInformation)
    );
    let said = said_by(&with_a_refused_argument);
    with_a_refused_argument
        .shutdown()
        .expect("the helper should stop cleanly");
    assert!(
        said.iter()
            .any(|line| line.contains("-Xclang") && line.contains("unit.cpp")),
        "{said:?}"
    );
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
    assert!(helper.offers(Capability::CallTargets));
    assert!(helper.offers(Capability::MacroExpansion));
    assert!(helper.offers(Capability::TemplateInstantiation));
    // libclang does not expose Clang's CFG, so this capability proves the
    // helper also found its fixed, syntax-only Clang frontend.
    assert!(helper.offers(Capability::MirCfg));
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

#[path = "analyzes_a_translation_unit/build_information.rs"]
mod build_information;
#[path = "analyzes_a_translation_unit/calls_and_semantics.rs"]
mod calls_and_semantics;
#[path = "analyzes_a_translation_unit/source_and_control_flow.rs"]
mod source_and_control_flow;
#[path = "analyzes_a_translation_unit/templates.rs"]
mod templates;
