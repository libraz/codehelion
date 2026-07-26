//! Which units a real parse marks as test code.
//!
//! The marker is an attribute, and whether an attribute reaches the analysis
//! depends on the parser putting it inside the item it decorates. That is a
//! property of the frontend, not of the recognition rules, so it is pinned
//! here over parsed sources rather than over hand-built tokens.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use codehelion_core::discovery::{BuildVariant, Language, LanguageSelection};
use codehelion_core::ir::{StructuralFrontend, SyntaxIrFile};
use codehelion_core::structural::{self, StructuralConfig, StructuralReport};
use codehelion_frontend_rust::ir::RustStructuralFrontend;

/// A production function, an annotated test, and a helper the test module
/// carries without a marker of its own.
const SOURCE: &str = "\
pub fn width_of(text: &str) -> usize {
    text.trim().chars().count()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> String {
        String::from(\"  hi  \")
    }

    #[test]
    fn it_trims() {
        assert_eq!(width_of(&sample()), 2);
    }
}
";

/// A test module that is compiled unconditionally, so the only marker in it
/// sits on the case itself.
const UNGATED: &str = "\
pub fn double(value: usize) -> usize {
    value * 2
}

mod checks {
    fn helper() -> usize {
        7
    }

    #[test]
    fn it_doubles() {
        assert_eq!(super::double(helper()), 14);
    }
}
";

fn analyze(sources: &[&str]) -> StructuralReport {
    let files: Vec<SyntaxIrFile> = sources
        .iter()
        .map(|source| RustStructuralFrontend.parse(source))
        .collect();
    let variant = BuildVariant::structural(LanguageSelection::default(), Language::C);
    structural::analyze(&files, &variant, &StructuralConfig::default())
}

/// Each unit as `(name, is test code)`, in analysis order.
fn marks(report: &StructuralReport) -> Vec<(String, bool)> {
    report
        .units
        .iter()
        .map(|unit| {
            let name = unit
                .name
                .as_ref()
                .map_or_else(|| "<anonymous>".to_string(), ToString::to_string);
            (name, unit.test_code)
        })
        .collect()
}

#[test]
fn a_test_only_module_marks_every_unit_inside_it() {
    let report = analyze(&[SOURCE]);
    assert_eq!(
        marks(&report),
        vec![
            ("width_of".to_string(), false),
            // Unmarked itself: it is test code because of where it sits.
            ("sample".to_string(), true),
            ("it_trims".to_string(), true),
        ]
    );
}

#[test]
fn an_unmarked_module_marks_only_the_cases_inside_it() {
    // Without a module-level marker the helper is ordinary code as far as the
    // source says. Guessing from the module's name would be inference, and a
    // module called `checks` in production code would then be misread.
    let report = analyze(&[UNGATED]);
    assert_eq!(
        marks(&report),
        vec![
            ("double".to_string(), false),
            ("helper".to_string(), false),
            ("it_doubles".to_string(), true),
        ]
    );
}

#[test]
fn a_group_is_test_code_only_when_every_member_is() {
    // The same body in a production function and in a test helper: the group
    // spans both, and duplication between the suite and the code it exercises
    // is exactly what must not be ranked away with the suite.
    let production = "\
pub fn build_label(name: &str) -> String {
    let trimmed = name.trim();
    let width = trimmed.chars().count();
    format!(\"{trimmed}:{width}\")
}
";
    let suite = "\
#[cfg(test)]
mod tests {
    fn build_label(name: &str) -> String {
        let trimmed = name.trim();
        let width = trimmed.chars().count();
        format!(\"{trimmed}:{width}\")
    }
}
";
    let report = analyze(&[production, suite]);
    assert_eq!(report.details.len(), 1, "the two copies form one group");
    assert!(!report.details[0].test_code);
}

#[test]
fn a_group_wholly_inside_the_suite_says_so() {
    let first = "\
#[cfg(test)]
mod tests {
    fn build_label(name: &str) -> String {
        let trimmed = name.trim();
        let width = trimmed.chars().count();
        format!(\"{trimmed}:{width}\")
    }
}
";
    let second = "\
#[cfg(test)]
mod cases {
    fn make_label(value: &str) -> String {
        let trimmed = value.trim();
        let width = trimmed.chars().count();
        format!(\"{trimmed}:{width}\")
    }
}
";
    let report = analyze(&[first, second]);
    assert_eq!(report.details.len(), 1, "the two copies form one group");
    assert!(report.details[0].test_code);
}
