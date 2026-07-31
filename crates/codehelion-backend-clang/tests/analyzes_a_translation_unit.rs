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

/// What a macro produced, and where the two halves of that are.
///
/// A macro invoked three times produces three identical bodies. Nobody wrote
/// them three times and nobody can delete one of them, so a detector reading
/// only the text reports repetition that cannot be acted on. What tells that
/// apart is that all three were written in one place — which is what the
/// spelling location says and the expansion location cannot.
#[test]
fn what_a_macro_produced_says_where_it_was_written() {
    let planted = plant("macro-expansion");
    let header = "include/accessor.hpp";
    let ir = analyzed(&planted.unit("src/frame.cpp", "src/frame.cpp"));

    let stamped: Vec<_> = ["width_", "height_", "depth_"]
        .iter()
        .map(|name| {
            ir.symbols
                .iter()
                .find(|symbol| {
                    symbol.name == *name && symbol.kind == codehelion_helper::ir::SymbolKind::Field
                })
                .unwrap_or_else(|| panic!("the macro-produced field {name} is reported"))
        })
        .collect();

    // Three invocations, three places in the file, one place they were written.
    // The second half is what turns three findings into one, and is the only
    // part the characters in the file cannot supply.
    let invocations: std::collections::BTreeSet<(u64, u64)> = stamped
        .iter()
        .map(|symbol| {
            assert_eq!(symbol.anchor.expansion.file, header);
            (
                symbol.anchor.expansion.start_byte,
                symbol.anchor.expansion.end_byte,
            )
        })
        .collect();
    assert_eq!(invocations.len(), 3, "{invocations:?}");
    let written = stamped[0]
        .anchor
        .definition
        .as_ref()
        .expect("an expanded name says where it was written");
    assert_eq!(
        written,
        &codehelion_helper::ir::SourceRange {
            file: header.into(),
            start_byte: 549,
            end_byte: 741,
            start_line: 13,
        },
        "the definition is the complete macro body, not an AST cursor's mixed spelling range"
    );
    for symbol in stamped.iter().skip(1) {
        assert_eq!(
            symbol.anchor.definition.as_ref(),
            Some(written),
            "every invocation maps to the exact same definition cursor"
        );
    }

    // And a declaration written where it reads carries no second place, or the
    // answer would be the same for everything and say nothing.
    let plain = ir
        .symbols
        .iter()
        .find(|symbol| symbol.name == "volume")
        .expect("the fixture declares a function outside the macro");
    assert!(!plain.anchor.is_expanded(), "{:?}", plain.anchor);
}

/// A macro body outside the project is still where generated code was written.
///
/// This uses an ordinary local include directory beside the planted project:
/// external means outside the scan root, not remote, untrusted, or unavailable.
#[test]
fn a_macro_definition_outside_the_tree_keeps_its_own_path() {
    let planted = plant("macro-expansion");
    let dependency = tempfile::tempdir().expect("external include directory");
    let external_header = dependency.path().join("external_accessor.hpp");
    std::fs::write(
        &external_header,
        "#pragma once\n#define EXTERNAL_FIELD(type, name) type name##_; \n",
    )
    .expect("write the external header");

    let project_header = planted.root.join("include/accessor.hpp");
    let source = std::fs::read_to_string(&project_header).expect("read the project header");
    let source = source
        .replace(
            "#include <cstdint>\n",
            "#include <cstdint>\n#include <external_accessor.hpp>\n",
        )
        .replace(
            "struct Frame {\n",
            "struct Frame {\n  EXTERNAL_FIELD(std::uint32_t, external)\n",
        );
    std::fs::write(&project_header, source).expect("include and invoke the external macro");

    let database_path = planted.root.join("compile_commands.json");
    let mut database: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&database_path).expect("read the compilation database"),
    )
    .expect("the database is JSON");
    let arguments = database[0]["arguments"]
        .as_array_mut()
        .expect("the fixture uses an arguments array");
    arguments.insert(
        1,
        serde_json::Value::String(format!("-I{}", dependency.path().display())),
    );
    std::fs::write(
        &database_path,
        serde_json::to_vec_pretty(&database).expect("render the database"),
    )
    .expect("add the external include path");

    let ir = analyzed(&planted.unit("src/frame.cpp", "src/frame.cpp"));
    let field = ir
        .symbols
        .iter()
        .find(|symbol| {
            symbol.name == "external_" && symbol.kind == codehelion_helper::ir::SymbolKind::Field
        })
        .expect("the external macro produced a field");
    assert_eq!(field.anchor.expansion.file, "include/accessor.hpp");
    let definition = field
        .anchor
        .definition
        .as_ref()
        .expect("the field keeps the macro definition");
    assert_eq!(
        definition.file,
        external_header
            .canonicalize()
            .expect("the external header exists")
            .display()
            .to_string()
    );
    assert!(definition.end_byte > definition.start_byte);
}

fn template_ir(planted: &Planted) -> Box<CompilerIr> {
    analyzed(&planted.unit("src/templates.cpp", "src/templates.cpp"))
}

fn template_source(planted: &Planted, file: &str) -> String {
    std::fs::read_to_string(planted.root.join(file))
        .unwrap_or_else(|error| panic!("read {file}: {error}"))
}

fn overload_ir(planted: &Planted) -> Box<CompilerIr> {
    analyzed(&planted.unit("src/calls.cpp", "src/calls.cpp"))
}

fn call_at<'a>(ir: &'a CompilerIr, file: &str, start: usize) -> &'a CallSite {
    ir.calls
        .iter()
        .find(|call| {
            call.anchor.expansion.file == file
                && call.anchor.expansion.start_byte == u64::try_from(start).unwrap()
        })
        .unwrap_or_else(|| panic!("no call at {file}:{start}: {:?}", ir.calls))
}

fn static_symbol(call: &CallSite) -> &str {
    match &call.target {
        CallTarget::Static { symbol } => symbol,
        target => panic!("expected a static target, got {target:?}"),
    }
}

/// The referenced callable USR is Clang's overload-resolution answer. The two
/// free overloads and two member overloads therefore remain distinct, while a
/// direct non-overloaded call and a declaration outside the tree are resolved
/// by exactly the same rule.
#[test]
fn direct_calls_keep_the_selected_callable_usr() {
    let planted = plant("overload-resolution");
    let source = template_source(&planted, "src/calls.cpp");
    let ir = overload_ir(&planted);
    let call = |text: &str| call_at(&ir, "src/calls.cpp", source.find(text).unwrap());

    let free_integer = static_symbol(call("choose(1)"));
    let free_long = static_symbol(call("choose(1L)"));
    assert_ne!(free_integer, free_long);

    let member_integer = static_symbol(call("mixer.mix(2)"));
    let member_long = static_symbol(call("mixer.mix(2L)"));
    assert_ne!(member_integer, member_long);
    assert_ne!(free_integer, member_integer);

    let direct = static_symbol(call("direct(9)"));
    let declared = ir
        .symbols
        .iter()
        .find(|symbol| {
            symbol.name == "direct"
                && symbol.kind == codehelion_helper::ir::SymbolKind::Function
                && !symbol.external
        })
        .expect("the direct function declaration is resolved");
    assert_eq!(direct, declared.id);

    let external = static_symbol(call("std::puts"));
    assert!(
        !external.is_empty(),
        "an external declaration still has a USR"
    );
    assert_ne!(external, direct);
}

/// A standard-library API label is supplementary evidence: the USR remains
/// the static call identity, while a closed semantic normalizer can use the
/// label without parsing a platform-specific USR spelling.
#[test]
fn standard_library_calls_carry_closed_api_names() {
    let planted = plant("overload-resolution");
    let ir = overload_ir(&planted);
    let begin = ir
        .calls
        .iter()
        .find(|call| call.api_name.as_deref() == Some("std::begin"))
        .expect("standard begin call");
    let push = ir
        .calls
        .iter()
        .find(|call| call.api_name.as_deref() == Some("std::push_back"))
        .expect("standard push_back call");
    assert_eq!(begin.api_name.as_deref(), Some("std::begin"));
    assert_eq!(push.api_name.as_deref(), Some("std::push_back"));
    assert!(matches!(begin.target, CallTarget::Static { .. }));
    assert!(matches!(push.target, CallTarget::Static { .. }));
}

/// An `optional` check enters the restricted vocabulary only after Clang has
/// resolved the selected method or conversion to the standard-library
/// declaration. A local lookalike is ordinary control flow, not evidence of
/// optional validation.
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one fixture keeps the accepted standard forms and rejected lookalikes under the same compiler invocation"
)]
fn standard_optional_presence_checks_are_validation_constructs() {
    let planted = plant("overload-resolution");
    let path = planted.root.join("src/calls.cpp");
    let source = std::fs::read_to_string(&path).expect("read C++ fixture");
    let source = format!(
        "#include <optional>\n#include <expected>\n\
         #define HAS_OPTION_VALUE(value) ((value).has_value())\n\
         {source}\n\
         namespace optional_checks {{\n\
         struct Lookalike {{ bool has_value() const {{ return true; }} }};\n\
         struct ConversionLookalike {{ explicit operator bool() const {{ return true; }} }};\n\
         bool standard(std::optional<long> value) {{\n\
           if (value.has_value()) {{ return true; }}\n\
           return false;\n\
         }}\n\
         bool direct_conversion(std::optional<long> value) {{\n\
           if (value) {{ return true; }}\n\
           return false;\n\
         }}\n\
         bool macro_standard(std::optional<long> value) {{\n\
           if (HAS_OPTION_VALUE(value)) {{ return true; }}\n\
           return false;\n\
         }}\n\
         bool lookalike(Lookalike value) {{\n\
           if (value.has_value()) {{ return true; }}\n\
           return false;\n\
         }}\n\
         bool conversion_lookalike(ConversionLookalike value) {{\n\
           if (value) {{ return true; }}\n\
           return false;\n\
         }}\n\
         bool compound(std::optional<long> value, bool keep) {{\n\
           if (value.has_value() && keep) {{ return true; }}\n\
           return false;\n\
         }}\n\
         bool expected_standard(std::expected<long, int> expected_value) {{\n\
           if (expected_value.has_value()) {{ return true; }}\n\
           return false;\n\
         }}\n\
         bool expected_direct_conversion(std::expected<long, int> expected_value) {{\n\
           if (expected_value) {{ return true; }}\n\
           return false;\n\
         }}\n\
         bool expected_compound(std::expected<long, int> expected_value, bool keep) {{\n\
           if (expected_value.has_value() && keep) {{ return true; }}\n\
           return false;\n\
         }}\n\
         }}  // namespace optional_checks\n"
    );
    std::fs::write(&path, &source).expect("extend C++ fixture");
    let database_path = planted.root.join("compile_commands.json");
    let database = std::fs::read_to_string(&database_path).expect("read compilation database");
    std::fs::write(&database_path, database.replace("-std=c++17", "-std=c++23"))
        .expect("enable C++23 expected fixture");

    let ir = overload_ir(&planted);
    let validates = ir
        .semantic_constructs
        .iter()
        .filter(|construct| construct.kind == SemanticConstructKind::Validate)
        .collect::<Vec<_>>();
    assert_eq!(validates.len(), 5, "{:?}", ir.semantic_constructs);
    assert_eq!(
        validates
            .iter()
            .filter(|construct| construct.fallible_kind == Some(FallibleKind::Option))
            .count(),
        3
    );
    assert_eq!(
        validates
            .iter()
            .filter(|construct| construct.fallible_kind == Some(FallibleKind::Result))
            .count(),
        2
    );
    let invocation = u64::try_from(
        source
            .rfind("HAS_OPTION_VALUE(value)")
            .expect("macro invocation"),
    )
    .expect("source offset fits in u64");
    let macro_validation = validates
        .iter()
        .find(|construct| {
            construct.fallible_kind == Some(FallibleKind::Option)
                && construct.anchor.expansion.start_byte == invocation
        })
        .expect("macro optional check is anchored at the invocation");
    assert!(
        macro_validation.anchor.definition.is_some(),
        "macro-origin validation keeps its written definition"
    );
    let spellings = validates
        .iter()
        .map(|construct| {
            let start =
                usize::try_from(construct.anchor.expansion.start_byte).expect("range start");
            let end = usize::try_from(construct.anchor.expansion.end_byte).expect("range end");
            source[start..end].to_string()
        })
        .collect::<Vec<_>>();
    assert!(
        spellings
            .iter()
            .any(|spelling| spelling.contains("value.has_value()"))
    );
    assert!(spellings.iter().any(|spelling| spelling.trim() == "value"));
    assert!(
        spellings
            .iter()
            .any(|spelling| spelling.contains("expected_value.has_value()"))
    );
    assert!(
        spellings
            .iter()
            .all(|spelling| !spelling.contains("&& keep"))
    );
}

/// A standard `expected` is a direct propagation adapter only when the whole
/// function forwards its single same-typed parameter unchanged. This gives the
/// cross-language normalizer a compiler-confirmed counterpart to Rust's
/// `Ok(value?)` without treating ordinary expected-using functions as such.
#[test]
fn standard_expected_identity_return_is_a_propagation_construct() {
    let planted = plant("overload-resolution");
    let path = planted.root.join("src/calls.cpp");
    let source = std::fs::read_to_string(&path).expect("read C++ fixture");
    let source = format!(
        "#include <expected>\n{source}\n\
         namespace expected_checks {{\n\
         std::expected<long, int> direct(std::expected<long, int> value) {{\n\
           return value;\n\
         }}\n\
         std::expected<long, int> transformed(std::expected<long, int> value) {{\n\
           return std::expected<long, int>(value.value_or(0));\n\
         }}\n\
         std::expected<long, int> extra(std::expected<long, int> value) {{\n\
           auto copy = value;\n\
           return value;\n\
         }}\n\
         }}  // namespace expected_checks\n"
    );
    std::fs::write(&path, &source).expect("extend C++ fixture");

    let database_path = planted.root.join("compile_commands.json");
    let mut database: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&database_path).expect("read the compilation database"),
    )
    .expect("the database is JSON");
    let arguments = database[0]["arguments"]
        .as_array_mut()
        .expect("the fixture uses an arguments array");
    let standard = arguments
        .iter_mut()
        .find(|argument| argument.as_str() == Some("-std=c++17"))
        .expect("fixture declares C++17");
    *standard = serde_json::Value::String("-std=c++23".to_string());
    std::fs::write(
        &database_path,
        serde_json::to_vec_pretty(&database).expect("render the database"),
    )
    .expect("select C++23 for expected");

    let ir = overload_ir(&planted);
    let propagated = ir
        .semantic_constructs
        .iter()
        .filter(|construct| construct.kind == SemanticConstructKind::PropagateError)
        .collect::<Vec<_>>();
    assert_eq!(propagated.len(), 1, "{:?}", ir.semantic_constructs);
    assert_eq!(propagated[0].fallible_kind, Some(FallibleKind::Result));
    assert_eq!(
        propagated[0].direct_propagation,
        Some(codehelion_helper::ir::DirectPropagation::ResultAdapter)
    );
    let start = usize::try_from(propagated[0].anchor.expansion.start_byte).expect("range start");
    let end = usize::try_from(propagated[0].anchor.expansion.end_byte).expect("range end");
    assert_eq!(&source[start..end], "return value");
}

/// A direct standard `lock_guard` binding has a compiler-known acquisition and
/// the lexical function endpoint where its destructor releases the lock.
/// Multiple direct guards and a nested guard remain outside this first form.
#[test]
fn direct_standard_lock_guard_lifetimes_are_reported_at_function_scope() {
    let planted = plant("overload-resolution");
    let ir = overload_ir(&planted);
    let lifetimes = ir
        .semantic_constructs
        .iter()
        .filter(|construct| {
            matches!(
                construct.kind,
                SemanticConstructKind::AcquireResource | SemanticConstructKind::ReleaseResource
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(lifetimes.len(), 4, "{:?}", ir.semantic_constructs);
    for pair in lifetimes.chunks_exact(2) {
        assert_eq!(pair[0].kind, SemanticConstructKind::AcquireResource);
        assert_eq!(pair[1].kind, SemanticConstructKind::ReleaseResource);
        assert_eq!(pair[0].resource_kind.as_deref(), Some("lock"));
        assert_eq!(pair[1].resource_kind.as_deref(), Some("lock"));
        assert!(pair[0].anchor.expansion.start_byte < pair[1].anchor.expansion.start_byte);
    }
}

/// `unique_lock` has the same compiler-known lexical release boundary as
/// `lock_guard` when it is directly bound once in a function body. It remains
/// a closed standard type check rather than a name-based project convention.
#[test]
fn direct_standard_unique_lock_lifetimes_are_reported_at_function_scope() {
    let planted = plant("overload-resolution");
    let path = planted.root.join("src/calls.cpp");
    let source = std::fs::read_to_string(&path).expect("read C++ fixture");
    let appended_at = u64::try_from(source.len()).expect("fixture offset fits in u64");
    let source = format!(
        "{source}\nnamespace unique_lock_checks {{\n\
         std::mutex mutex;\n\
         void first() {{ std::unique_lock<std::mutex> guard(mutex); }}\n\
         void second() {{ std::unique_lock<std::mutex> guard(mutex); }}\n\
         void multiple() {{\n\
           std::unique_lock<std::mutex> first_guard(mutex);\n\
           std::unique_lock<std::mutex> second_guard(mutex);\n\
         }}\n\
         void nested() {{\n\
           if (true) {{ std::unique_lock<std::mutex> guard(mutex); }}\n\
         }}\n\
         }}  // namespace unique_lock_checks\n"
    );
    std::fs::write(&path, source).expect("append unique lock fixture");

    let ir = overload_ir(&planted);
    let lifetimes = ir
        .semantic_constructs
        .iter()
        .filter(|construct| construct.anchor.expansion.start_byte >= appended_at)
        .filter(|construct| {
            matches!(
                construct.kind,
                SemanticConstructKind::AcquireResource | SemanticConstructKind::ReleaseResource
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(lifetimes.len(), 4, "{:?}", ir.semantic_constructs);
    for pair in lifetimes.chunks_exact(2) {
        assert_eq!(pair[0].kind, SemanticConstructKind::AcquireResource);
        assert_eq!(pair[1].kind, SemanticConstructKind::ReleaseResource);
        assert_eq!(pair[0].resource_kind.as_deref(), Some("lock"));
        assert_eq!(pair[1].resource_kind.as_deref(), Some("lock"));
    }
}

#[test]
fn standard_algorithm_calls_carry_closed_api_names() {
    let planted = plant("overload-resolution");
    let ir = overload_ir(&planted);
    assert_eq!(
        ir.calls
            .iter()
            .filter(|call| call.api_name.as_deref() == Some("std::transform"))
            .count(),
        2
    );
    assert_eq!(
        ir.calls
            .iter()
            .filter(|call| call.api_name.as_deref() == Some("std::copy_if"))
            .count(),
        2
    );
    assert_eq!(
        ir.calls
            .iter()
            .filter(|call| call.api_name.as_deref() == Some("std::begin"))
            .count(),
        6,
        "two collection, two transform, and two filter functions each contribute one input source"
    );
}

/// A qualified virtual call names one base implementation. An ordinary
/// virtual call does not: libclang cannot enumerate all derived overrides, so
/// emitting a partial dynamic candidate list would overstate the answer.
#[test]
fn virtual_dispatch_is_unresolved_but_a_qualified_call_is_static() {
    let planted = plant("overload-resolution");
    let source = template_source(&planted, "src/calls.cpp");
    let ir = overload_ir(&planted);
    let target = |text: &str| &call_at(&ir, "src/calls.cpp", source.find(text).unwrap()).target;

    assert!(matches!(target("base.run(3)"), CallTarget::Unresolved));
    assert!(matches!(target("derived.run(5)"), CallTarget::Unresolved));
    assert!(matches!(
        target("derived.Base::run(4)"),
        CallTarget::Static { .. }
    ));
    assert!(
        ir.calls
            .iter()
            .all(|call| !matches!(call.target, CallTarget::Dynamic { .. })),
        "an incomplete dynamic candidate set was manufactured"
    );
}

/// A function-pointer variable is not the function eventually reached, and a
/// dependent call has no selected overload until instantiation. Neither is
/// assigned a positional identity or a compile-time overload set.
#[test]
fn indirect_and_dependent_calls_stay_unresolved() {
    let planted = plant("overload-resolution");
    let source = template_source(&planted, "src/calls.cpp");
    let header = template_source(&planted, "include/calls.hpp");
    let ir = overload_ir(&planted);

    assert!(matches!(
        call_at(&ir, "src/calls.cpp", source.find("pointer(6)").unwrap()).target,
        CallTarget::Unresolved
    ));
    assert!(matches!(
        call_at(
            &ir,
            "include/calls.hpp",
            header.find("choose(value)").unwrap()
        )
        .target,
        CallTarget::Unresolved
    ));
}

/// Call anchors use the same macro index as symbols. The expanded call sits at
/// the invocation, carries the macro-body definition, and remains one call in
/// a deterministic, duplicate-free result.
#[test]
fn macro_calls_are_anchored_at_the_invocation_and_results_are_stable() {
    let planted = plant("overload-resolution");
    let source = template_source(&planted, "src/calls.cpp");
    let ir = overload_ir(&planted);
    let start = source.find("CALL_DIRECT(7)").unwrap();
    let call = call_at(&ir, "src/calls.cpp", start);
    assert_eq!(
        &source[start..usize::try_from(call.anchor.expansion.end_byte).unwrap()],
        "CALL_DIRECT(7)"
    );
    assert!(
        call.anchor
            .definition
            .as_ref()
            .is_some_and(|range| range.file == "include/calls.hpp")
    );
    assert!(matches!(call.target, CallTarget::Static { .. }));

    assert_eq!(
        ir.calls
            .iter()
            .filter(|call| call.anchor.expansion.file == "src/calls.cpp")
            .count(),
        57,
        "every written source CallExpr is represented exactly once"
    );
    assert_eq!(
        ir.calls
            .iter()
            .filter(|call| call.anchor.expansion.file == "include/calls.hpp")
            .count(),
        3,
        "every written header CallExpr is represented exactly once"
    );
    assert!(
        ir.calls.windows(2).all(|pair| {
            let left = &pair[0];
            let right = &pair[1];
            (
                &left.anchor.expansion.file,
                left.anchor.expansion.start_byte,
                left.anchor.expansion.end_byte,
            ) <= (
                &right.anchor.expansion.file,
                right.anchor.expansion.start_byte,
                right.anchor.expansion.end_byte,
            ) && left != right
        }),
        "calls are not sorted and deduplicated: {:?}",
        ir.calls
    );
    let repeated = overload_ir(&planted);
    assert_eq!(
        ir.calls, repeated.calls,
        "AST traversal order leaked into IR"
    );
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

/// One function body instantiated at two substitutions is one definition and
/// two families. Repeating one substitution is still one family at two written
/// uses, and each use is anchored on the name rather than the enclosing call.
#[test]
fn function_template_uses_share_the_origin_and_key_by_specialization() {
    let planted = plant("template-instantiation");
    let source = template_source(&planted, "src/templates.cpp");
    let ir = template_ir(&planted);
    let uses: Vec<usize> = source.match_indices("twice(").map(|(at, _)| at).collect();
    assert_eq!(uses.len(), 3);
    let stamps: Vec<_> = uses
        .iter()
        .map(|at| stamp_at(&ir, "src/templates.cpp", *at))
        .collect();

    assert_eq!(stamps[0].definition, stamps[1].definition);
    assert_eq!(stamps[1].definition, stamps[2].definition);
    assert_eq!(stamps[0].instantiation_key, stamps[1].instantiation_key);
    assert_ne!(stamps[1].instantiation_key, stamps[2].instantiation_key);
    assert!(
        stamps
            .iter()
            .all(|stamp| stamp.instantiation_key.starts_with("clang-usr-v1:"))
    );
    assert!(
        stamps.iter().all(|stamp| stamp.arguments.is_empty()),
        "clang 2.0/runtime has no unversioned function-template argument API"
    );
    for (stamp, start) in stamps.iter().zip(uses) {
        assert_eq!(
            &source[start..usize::try_from(stamp.anchor.expansion.end_byte).unwrap()],
            "twice"
        );
        let definition = stamp
            .anchor
            .definition
            .as_ref()
            .expect("the selected template body has a source range");
        assert_eq!(definition.file, "include/templates.hpp");
    }
}

/// Class specializations expose their type arguments even when another
/// argument is non-type. The concrete USR keeps the missing non-type value in
/// the key, so two array lengths do not collapse into one family.
#[test]
fn class_template_keys_keep_non_type_arguments_and_types_keep_categories() {
    let planted = plant("template-instantiation");
    let source = template_source(&planted, "src/templates.cpp");
    let ir = template_ir(&planted);
    let four = stamp_at(
        &ir,
        "src/templates.cpp",
        source.find("Buffer<int, 4>").unwrap(),
    );
    let eight = stamp_at(
        &ir,
        "src/templates.cpp",
        source.find("Buffer<int, 8>").unwrap(),
    );
    let floating = stamp_at(
        &ir,
        "src/templates.cpp",
        source.find("Buffer<double, 4>").unwrap(),
    );

    assert_eq!(four.definition, eight.definition);
    assert_eq!(eight.definition, floating.definition);
    assert_ne!(four.instantiation_key, eight.instantiation_key);
    assert_ne!(four.instantiation_key, floating.instantiation_key);
    assert_eq!(four.arguments.len(), 1, "the non-type argument is key-only");
    assert_eq!(
        eight.arguments.len(),
        1,
        "the non-type argument is key-only"
    );
    assert_eq!(
        ir.types[four.arguments[0] as usize].category,
        TypeCategory::Integer
    );
    assert_eq!(
        ir.types[floating.arguments[0] as usize].category,
        TypeCategory::Float
    );
}

/// Clang identifies the selected partial specialization directly. A full
/// explicit specialization owns another body and is therefore not attributed
/// to the primary, while external and ordinary controls produce no stamps.
#[test]
fn selected_partial_and_controls_are_not_misattributed() {
    let planted = plant("template-instantiation");
    let source = template_source(&planted, "src/templates.cpp");
    let ir = template_ir(&planted);
    let partial = stamp_at(
        &ir,
        "src/templates.cpp",
        source.find("Holder<int*>").unwrap(),
    );
    assert!(
        partial.definition.contains("@SP>"),
        "the selected partial-specialization USR is the origin: {partial:?}"
    );
    let written = partial
        .anchor
        .definition
        .as_ref()
        .expect("the partial specialization has a body");
    let header = template_source(&planted, "include/templates.hpp");
    assert!(
        header[usize::try_from(written.start_byte).unwrap()
            ..usize::try_from(written.end_byte).unwrap()]
            .contains("struct Holder<T*>")
    );

    for control in ["Holder<bool>", "std::vector<int>", "ordinary("] {
        let at = source.find(control).unwrap();
        let end = at + control.len();
        assert!(
            ir.instantiations.iter().all(|stamp| {
                if stamp.anchor.expansion.file != "src/templates.cpp" {
                    return true;
                }
                let start = usize::try_from(stamp.anchor.expansion.start_byte).unwrap();
                !(at..end).contains(&start)
            }),
            "{control} was reported as an instantiation: {:?}",
            ir.instantiations
        );
    }
    assert!(
        ir.instantiations.windows(2).all(|pair| {
            let left = &pair[0];
            let right = &pair[1];
            (
                &left.anchor.expansion.file,
                left.anchor.expansion.start_byte,
                left.anchor.expansion.end_byte,
                &left.instantiation_key,
            ) < (
                &right.anchor.expansion.file,
                right.anchor.expansion.start_byte,
                right.anchor.expansion.end_byte,
                &right.instantiation_key,
            )
        }),
        "stamps are not sorted and deduplicated: {:?}",
        ir.instantiations
    );
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
