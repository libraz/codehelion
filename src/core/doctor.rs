//! Environment diagnostics.
//!
//! `doctor` reports which analysis components are usable on the current
//! machine. It is a diagnostic, never a gate: it inspects the environment and
//! always succeeds. Compiler and artifact helpers are optional, out-of-process
//! components delivered by later work; their checks are registered here as
//! placeholders so that running `doctor` never links a compiler into the tool.

use std::io::{self, Write};

/// Availability of a diagnostic component.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComponentStatus {
    /// Present and usable.
    Available,
    /// Looked for but not found on this system.
    NotFound,
    /// Planned, but not yet provided by this build.
    NotImplemented,
}

impl ComponentStatus {
    /// Short human-readable label for reports.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Available => "available",
            Self::NotFound => "not found",
            Self::NotImplemented => "not implemented",
        }
    }
}

/// Whether a component is required for core functionality.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Requirement {
    /// Core source auditing depends on this component.
    Required,
    /// Enables optional analysis modes only; the tool works without it.
    Optional,
}

impl Requirement {
    /// Short human-readable label for reports.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Required => "required",
            Self::Optional => "optional",
        }
    }
}

/// Outcome of inspecting one component.
#[derive(Debug, Clone)]
pub struct ComponentReport {
    /// Component name shown to the user.
    pub name: &'static str,
    /// Whether the component is required or optional.
    pub requirement: Requirement,
    /// Detected availability.
    pub status: ComponentStatus,
    /// Extra detail: a version string, or why the component is unavailable.
    pub detail: String,
}

/// A registered diagnostic check.
struct Check {
    name: &'static str,
    requirement: Requirement,
    inspect: fn() -> (ComponentStatus, String),
}

fn inspect_self() -> (ComponentStatus, String) {
    (
        ComponentStatus::Available,
        format!("codehelion {}", env!("CARGO_PKG_VERSION")),
    )
}

/// Placeholder for the out-of-process Rust compiler helper.
///
/// The helper is an optional, separately built binary; it is not part of this
/// build. The check deliberately performs no detection so that `doctor` stays
/// free of any compiler dependency.
fn inspect_rust_compiler_helper() -> (ComponentStatus, String) {
    (
        ComponentStatus::NotImplemented,
        "optional compiler helper, planned for a later release".to_string(),
    )
}

/// Placeholder for the out-of-process Clang helper. See
/// [`inspect_rust_compiler_helper`] for why detection is intentionally empty.
fn inspect_clang_helper() -> (ComponentStatus, String) {
    (
        ComponentStatus::NotImplemented,
        "optional compiler helper, planned for a later release".to_string(),
    )
}

const CHECKS: &[Check] = &[
    Check {
        name: "codehelion",
        requirement: Requirement::Required,
        inspect: inspect_self,
    },
    Check {
        name: "rust-compiler-helper",
        requirement: Requirement::Optional,
        inspect: inspect_rust_compiler_helper,
    },
    Check {
        name: "clang-helper",
        requirement: Requirement::Optional,
        inspect: inspect_clang_helper,
    },
];

/// Run every registered diagnostic check and collect the reports.
///
/// The order is stable (registry order) so that output is deterministic.
#[must_use]
pub fn diagnose() -> Vec<ComponentReport> {
    CHECKS
        .iter()
        .map(|check| {
            let (status, detail) = (check.inspect)();
            ComponentReport {
                name: check.name,
                requirement: check.requirement,
                status,
                detail,
            }
        })
        .collect()
}

/// Render `reports` as an aligned plain-text table.
///
/// # Errors
///
/// Returns an error if writing to `out` fails.
pub fn render(reports: &[ComponentReport], out: &mut impl Write) -> io::Result<()> {
    writeln!(out, "codehelion environment diagnostics")?;
    writeln!(out)?;
    let name_width = reports.iter().map(|r| r.name.len()).max().unwrap_or(0);
    for report in reports {
        writeln!(
            out,
            "  {name:<name_width$}  {req:<8}  {status:<15}  {detail}",
            name = report.name,
            req = report.requirement.label(),
            status = report.status.label(),
            detail = report.detail,
        )?;
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn diagnose_reports_codehelion_first_and_available() {
        let reports = diagnose();
        let first = reports.first().expect("at least one report");
        assert_eq!(first.name, "codehelion");
        assert_eq!(first.requirement, Requirement::Required);
        assert_eq!(first.status, ComponentStatus::Available);
        assert!(first.detail.contains(env!("CARGO_PKG_VERSION")));
    }

    #[test]
    fn helpers_are_optional_placeholders() {
        let reports = diagnose();
        let helpers: Vec<_> = reports.iter().filter(|r| r.name != "codehelion").collect();
        assert!(!helpers.is_empty());
        for helper in helpers {
            assert_eq!(helper.requirement, Requirement::Optional);
            assert_eq!(helper.status, ComponentStatus::NotImplemented);
        }
    }

    #[test]
    fn render_lists_every_component_and_the_version() {
        let mut buffer = Vec::new();
        render(&diagnose(), &mut buffer).expect("render should succeed");
        let text = String::from_utf8(buffer).expect("output is utf-8");
        assert!(text.contains("codehelion"));
        assert!(text.contains(env!("CARGO_PKG_VERSION")));
        assert!(text.contains("rust-compiler-helper"));
        assert!(text.contains("not implemented"));
    }
}
