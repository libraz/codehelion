//! Environment diagnostics.
//!
//! `doctor` reports which analysis components are usable on the current
//! machine. It is a diagnostic, never a gate: it inspects the environment and
//! always succeeds.
//!
//! Compiler helpers are separate programs, and this module does not know how to
//! run one — it is handed a way to look for them. That keeps the crate that
//! compares programs free of the crate that starts processes, and it is also
//! what makes the absence of a helper testable: a lookup that finds nothing is
//! a machine without helpers, which is the case worth being sure about.
//!
//! An absent helper is reported as what is still available rather than as a
//! problem. Fast and Structural analysis do not need one, so a report that
//! read as a failure would be telling somebody to fix something that is not
//! broken.

use std::io::{self, Write};
use std::path::PathBuf;

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

/// An optional out-of-process helper, and what a machine without it loses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HelperComponent {
    /// The name reported for it.
    pub name: &'static str,
    /// The program to look for.
    pub binary: &'static str,
    /// What having it makes possible.
    pub enables: &'static str,
    /// What to do about not having it.
    pub advice: &'static str,
}

/// The helpers a run can use, in a fixed order.
pub const OPTIONAL_HELPERS: [HelperComponent; 2] = [
    HelperComponent {
        name: "rust-compiler-helper",
        binary: "codehelion-backend-rust",
        enables: "semantic analysis of Rust",
        advice: "install codehelion-backend-rust beside this binary or on PATH",
    },
    HelperComponent {
        name: "clang-helper",
        binary: "codehelion-backend-clang",
        enables: "semantic analysis of C and C++",
        advice: "install codehelion-backend-clang beside this binary or on PATH",
    },
];

fn inspect_self() -> ComponentReport {
    ComponentReport {
        name: "codehelion",
        requirement: Requirement::Required,
        status: ComponentStatus::Available,
        detail: format!("codehelion {}", env!("CARGO_PKG_VERSION")),
    }
}

fn inspect_helper(helper: HelperComponent, found: Option<PathBuf>) -> ComponentReport {
    // Says what is unaffected before what to do about it: the usual reason
    // somebody reads this line is to find out whether it matters.
    let (status, detail) = found.map_or_else(
        || {
            (
                ComponentStatus::NotFound,
                format!(
                    "not needed for fast or structural analysis; enables {}. To add it, {}.",
                    helper.enables, helper.advice
                ),
            )
        },
        |path| (ComponentStatus::Available, path.display().to_string()),
    );
    ComponentReport {
        name: helper.name,
        requirement: Requirement::Optional,
        status,
        detail,
    }
}

/// Diagnose the environment, asking `find` where each optional helper is.
///
/// `find` is given a program name and returns where it is, if anywhere. It is
/// a parameter rather than a call because looking for a program is the business
/// of the layer that runs one, and this crate does not run anything.
///
/// The order is stable so that output is deterministic.
#[must_use]
pub fn diagnose_with(find: &dyn Fn(&str) -> Option<PathBuf>) -> Vec<ComponentReport> {
    let mut reports = vec![inspect_self()];
    for helper in OPTIONAL_HELPERS {
        reports.push(inspect_helper(helper, find(helper.binary)));
    }
    reports
}

/// Diagnose the environment without looking for any helper.
///
/// The report a machine with no helpers would get, which is also the report a
/// caller that cannot look for them should give: claiming a helper is missing
/// and claiming nobody looked are the same sentence here only because the
/// outcome is the same either way — nothing semantic is available.
#[must_use]
pub fn diagnose() -> Vec<ComponentReport> {
    diagnose_with(&|_| None)
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

    /// A machine with no helpers is not a machine with a problem: fast and
    /// structural analysis need none, and a report that read as a failure
    /// would send somebody to fix something that is not broken.
    #[test]
    fn a_machine_without_helpers_is_told_what_it_still_has() {
        let reports = diagnose();
        let helpers: Vec<_> = reports.iter().filter(|r| r.name != "codehelion").collect();
        assert_eq!(helpers.len(), OPTIONAL_HELPERS.len());
        for helper in helpers {
            assert_eq!(helper.requirement, Requirement::Optional);
            assert_eq!(helper.status, ComponentStatus::NotFound);
            assert!(
                helper.detail.contains("not needed for fast or structural"),
                "{}",
                helper.detail
            );
        }
    }

    /// And the advice has to name the program that would satisfy the lookup,
    /// or it is advice for a different tool.
    #[test]
    fn the_advice_names_the_program_that_was_looked_for() {
        for helper in OPTIONAL_HELPERS {
            let report = inspect_helper(helper, None);
            assert!(report.detail.contains(helper.binary), "{}", report.detail);
        }
    }

    #[test]
    fn a_helper_that_is_there_is_reported_with_where_it_is() {
        let reports = diagnose_with(&|name| {
            (name == OPTIONAL_HELPERS[0].binary).then(|| PathBuf::from("/opt/bin").join(name))
        });
        let found = &reports[1];
        assert_eq!(found.name, OPTIONAL_HELPERS[0].name);
        assert_eq!(found.status, ComponentStatus::Available);
        assert!(found.detail.contains("/opt/bin"), "{}", found.detail);
        // And the one that was not found still says so, rather than inheriting
        // the answer of the helper beside it.
        assert_eq!(reports[2].status, ComponentStatus::NotFound);
    }

    #[test]
    fn render_lists_every_component_and_the_version() {
        let mut buffer = Vec::new();
        render(&diagnose(), &mut buffer).expect("render should succeed");
        let text = String::from_utf8(buffer).expect("output is utf-8");
        assert!(text.contains("codehelion"));
        assert!(text.contains(env!("CARGO_PKG_VERSION")));
        assert!(text.contains("rust-compiler-helper"));
        assert!(text.contains("not found"));
    }
}
