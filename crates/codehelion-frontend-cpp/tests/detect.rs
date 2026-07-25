//! End-to-end detection over inline C++ sources: lex with the C++ frontend,
//! run the engine, and check that a verbatim method copy (Type-1) and a
//! renamed copy (Type-2) are both recovered across classes.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use codehelion_core::clone_class::CloneClass;
use codehelion_core::engine::{self, EngineConfig, InputFile};
use codehelion_core::frontend::{Frontend, LexedFile, UnitKind};
use codehelion_frontend_cpp::CppFrontend;

/// The donor: a smoothing loop inside a class method.
const SEED: &str = "\
class Tracker {
public:
    double smooth(const double *xs, unsigned n) {
        double acc = 0.25;
        for (unsigned i = 0; i < n; ++i) {
            acc = acc * 0.75 + xs[i] * 0.25;
            acc = acc + (acc / 16.0);
        }
        return acc;
    }
private:
    double last_ = 0.0;
};
";

/// A verbatim copy of the method body in an unrelated free function (Type-1).
const VERBATIM: &str = "\
double smooth_series(const double *xs, unsigned n) {
    double acc = 0.25;
    for (unsigned i = 0; i < n; ++i) {
        acc = acc * 0.75 + xs[i] * 0.25;
        acc = acc + (acc / 16.0);
    }
    return acc;
}
";

/// The same body with consistently renamed identifiers and changed literals
/// (Type-2).
const RENAMED: &str = "\
class Meter {
public:
    double blend(const double *vals, unsigned count) {
        double state = 0.5;
        for (unsigned k = 0; k < count; ++k) {
            state = state * 0.5 + vals[k] * 0.5;
            state = state + (state / 8.0);
        }
        return state;
    }
};
";

fn lex_all() -> Vec<LexedFile> {
    [SEED, VERBATIM, RENAMED]
        .iter()
        .map(|src| CppFrontend.lex(src))
        .collect()
}

fn detect_all(lexed: &[LexedFile]) -> engine::EngineReport {
    let files: Vec<InputFile<'_>> = lexed
        .iter()
        .map(|l| InputFile {
            tokens: &l.tokens,
            units: &l.units,
        })
        .collect();
    engine::detect(&files, &EngineConfig::default())
}

/// Whether some group of `clone_type` has members in both files.
fn linked(
    report: &engine::EngineReport,
    clone_type: CloneClass,
    file_a: usize,
    file_b: usize,
) -> bool {
    report.groups.iter().any(|g| {
        g.clone_type == clone_type
            && g.members.iter().any(|m| m.file == file_a)
            && g.members.iter().any(|m| m.file == file_b)
    })
}

#[test]
fn cpp_sources_lex_clean_with_method_units() {
    let lexed = lex_all();
    for file in &lexed {
        assert!(file.diagnostics.is_empty(), "{:#?}", file.diagnostics);
    }
    assert!(
        lexed[0].units.iter().any(|u| u.kind == UnitKind::Method),
        "the seed's smoothing loop lives in a method: {:#?}",
        lexed[0].units
    );
}

#[test]
fn verbatim_method_copy_is_recovered_as_type1() {
    let lexed = lex_all();
    let report = detect_all(&lexed);
    assert!(
        linked(&report, CloneClass::Type1, 0, 1),
        "type-1 method <-> free function copy not found; groups: {:#?}",
        report.groups
    );
}

#[test]
fn renamed_method_copy_is_recovered_as_type2() {
    let lexed = lex_all();
    let report = detect_all(&lexed);
    assert!(
        linked(&report, CloneClass::Type2, 0, 2),
        "type-2 renamed method copy not found; groups: {:#?}",
        report.groups
    );
}

#[test]
fn cpp_detection_is_deterministic() {
    let lexed = lex_all();
    let first = detect_all(&lexed);
    let second = detect_all(&lexed);
    assert_eq!(first.stats, second.stats);
    assert_eq!(first.groups.len(), second.groups.len());
    for (a, b) in first.groups.iter().zip(second.groups.iter()) {
        assert_eq!(a.content_key, b.content_key);
        assert_eq!(a.members, b.members);
    }
}
