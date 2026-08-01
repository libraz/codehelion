//! What this helper reports about projects whose answer is known by reading
//! them.
//!
//! Driven through the real client against the real program, because everything
//! worth checking here is a claim about two processes: that the handshake
//! agrees, that a unit comes back with types a person can verify by looking at
//! the fixture, that a crate needing a build script is declined rather than
//! half-answered, and that declining it leaves no trace of having run it.
//!
//! `CARGO_BIN_EXE_` rather than a constructed path: a test that guesses where a
//! binary lands can run a stale copy and report success.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex, PoisonError};
use std::time::Duration;

use codehelion_helper::ir::{
    CallTarget, DirectPropagation, FallibleKind, Instantiation, ResolvedSymbol,
    SemanticConstructKind, SymbolKind, TypeCategory, Unavailability, UnexpandedMacroReason,
    UnitRef,
};
use codehelion_helper::protocol::{Capability, Execution};
use codehelion_helper::{Analysis, COMPILER_IR_SCHEMA_VERSION, CompilerIr, Helper};

/// Loading a workspace reads its sysroot and its metadata, which on a cold
/// machine is slower than the protocol's default.
const PATIENT: Duration = Duration::from_mins(5);

fn helper() -> Helper {
    Helper::start(
        Path::new(env!("CARGO_BIN_EXE_codehelion-backend-rust")),
        PATIENT,
    )
    .expect("the helper should start and shake hands")
}

fn unit(fixture: &str, member: &str, crate_name: &str) -> UnitRef {
    let file = codehelion_fixtures::rust(fixture)
        .unwrap()
        .join(member)
        .join("src/lib.rs");
    UnitRef {
        unit: crate_name.to_string(),
        file: file.display().to_string(),
        variant: "host".to_string(),
    }
}

/// One helper per fixture, for the analyses that only read.
///
/// Answering the first question about a project means reading its metadata and
/// indexing the standard library, which the helper keeps for as long as its
/// process lives. A test that starts its own helper pays that again, and this
/// file asks a handful of fixtures the same read-only questions from dozens of
/// tests: on a cold machine the repeated indexing is most of what this file
/// costs and none of what it checks.
///
/// Per fixture rather than one for the whole file, because a single helper
/// would serialize tests that have nothing to do with each other. Each still
/// makes a real request over the wire; what is shared is the reading, which is
/// what the helper caches anyway. The tests that are about the process itself
/// — the handshake, a granted execution permission, a clean shutdown — still
/// start one of their own.
static READING: LazyLock<Mutex<BTreeMap<PathBuf, &'static Mutex<Helper>>>> =
    LazyLock::new(|| Mutex::new(BTreeMap::new()));

/// The fixture `file` belongs to, which is what decides the project a helper
/// would have to read. A path outside the fixtures stands for itself.
fn fixture_of(file: &Path) -> PathBuf {
    let rust = codehelion_fixtures::root().join("rust");
    file.ancestors()
        .find(|path| path.parent() == Some(rust.as_path()))
        .unwrap_or(file)
        .to_path_buf()
}

fn reading(file: &Path) -> &'static Mutex<Helper> {
    READING
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .entry(fixture_of(file))
        // Leaked deliberately: the helper is meant to outlive every test that
        // reads this fixture, and the process it owns goes when the test binary
        // does.
        .or_insert_with(|| Box::leak(Box::new(Mutex::new(helper()))))
}

fn analyze(unit: &UnitRef) -> Analysis {
    reading(Path::new(&unit.file))
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .analyze(unit, &[Capability::Types])
        .expect("the helper should answer")
}

fn analyzed(unit: &UnitRef) -> Box<CompilerIr> {
    match analyze(unit) {
        Analysis::Done(ir) => ir,
        Analysis::Missing(reason) => panic!("expected an analysis, got {reason:?}"),
    }
}

fn category_of(ir: &CompilerIr, name: &str) -> TypeCategory {
    let symbol = ir
        .symbols
        .iter()
        .find(|symbol| symbol.name == name)
        .unwrap_or_else(|| {
            panic!(
                "no symbol called {name}; the unit holds {:?}",
                ir.symbols.iter().map(|s| &s.name).collect::<Vec<_>>()
            )
        });
    let index = symbol
        .type_index
        .unwrap_or_else(|| panic!("{name} has no resolved type")) as usize;
    ir.types[index].category
}

/// Every name written in `file`, in the order they were written.
fn names<'a>(ir: &'a CompilerIr, name: &str) -> Vec<&'a ResolvedSymbol> {
    ir.symbols
        .iter()
        .filter(|symbol| symbol.name == name)
        .collect()
}

fn stamped() -> Box<CompilerIr> {
    let file = codehelion_fixtures::rust("generic")
        .unwrap()
        .join("src/lib.rs");
    analyzed(&UnitRef {
        unit: "stamped".to_string(),
        file: file.display().to_string(),
        variant: "host".to_string(),
    })
}

fn stamps<'a>(ir: &'a CompilerIr, definition: &str) -> Vec<&'a Instantiation> {
    ir.instantiations
        .iter()
        .filter(|instantiation| instantiation.definition == definition)
        .collect()
}

fn body_of(source: &str, enclosing: &str) -> std::ops::Range<usize> {
    let start = source
        .find(enclosing)
        .unwrap_or_else(|| panic!("the fixture no longer contains {enclosing}"));
    let open = start + source[start..].find('{').expect("a body");
    let mut depth = 0_i32;
    for (offset, character) in source[open..].char_indices() {
        match character {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return open..open + offset;
                }
            }
            _ => {}
        }
    }
    panic!("{enclosing} has no closing brace");
}

fn source_of(fixture: &str) -> String {
    let path = codehelion_fixtures::rust(fixture)
        .unwrap()
        .join("src/lib.rs");
    std::fs::read_to_string(path).expect("the fixture is readable")
}

#[path = "analyzes_a_workspace/generics.rs"]
mod generics;
#[path = "analyzes_a_workspace/macros.rs"]
mod macros;
#[path = "analyzes_a_workspace/project_boundaries.rs"]
mod project_boundaries;
#[path = "analyzes_a_workspace/semantic_constructs.rs"]
mod semantic_constructs;
#[path = "analyzes_a_workspace/symbols_and_dispatch.rs"]
mod symbols_and_dispatch;
