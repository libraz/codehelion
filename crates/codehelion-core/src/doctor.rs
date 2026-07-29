//! Environment diagnostics.
//!
//! `doctor` reports which analysis components are usable on the current
//! machine. It is a diagnostic, never a gate: it inspects the environment and
//! always succeeds.
//!
//! Compiler helpers are separate programs, and this module does not know how to
//! run one — it is handed what was found out about them. That keeps the crate
//! that compares programs free of the crate that starts processes, and it is
//! also what makes the absence of a helper testable: a lookup that finds
//! nothing is a machine without helpers, which is the case worth being sure
//! about.
//!
//! An absent helper is reported as what is still available rather than as a
//! problem. Fast and Structural analysis do not need one, so a report that
//! read as a failure would be telling somebody to fix something that is not
//! broken.
//!
//! # Why being there is not the same as being usable
//!
//! A helper that is installed can still be one this build cannot talk to: an
//! older protocol, a program that dies on startup, a name that resolves to
//! something else entirely. Reporting that as "available" sends somebody to
//! debug a scan that was never going to work, and reporting it as "not found"
//! sends them to install what is already installed. It is its own state, and
//! what the helper said — or why it said nothing — is the part worth printing.
//!
//! The same state covers the helper that talks perfectly and is still no use:
//! one whose revision predates a question every run asks before it analyses
//! anything. Nothing is wrong with that program, and no run will get past it,
//! so the row says so here rather than leaving it to be discovered from a scan
//! that refuses immediately.

use std::io::{self, Write};
use std::path::PathBuf;

use crate::discovery::Language;

/// Availability of a diagnostic component.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComponentStatus {
    /// Present and usable.
    Available,
    /// Looked for but not found on this system.
    NotFound,
    /// Found, but this build could not use it.
    Unusable,
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
            Self::Unusable => "unusable",
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
    /// Lines printed under the component, in the order they were added.
    ///
    /// What a helper said about itself does not fit on the line that says
    /// whether it is there, and squeezing it in would make the common case —
    /// reading down the status column — harder for the sake of the rare one.
    pub notes: Vec<String>,
}

/// What one helper turned out to be, once somebody went and looked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelperFacts {
    /// Where the program is.
    pub path: PathBuf,
    /// Whether it can be talked to, and what it said.
    pub state: HelperState,
}

/// Whether a helper that is present can be used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HelperState {
    /// It answered the handshake, and this is what it answered.
    Answered(Greeting),
    /// It is there and this build could not talk to it, with the reason.
    Silent(String),
}

/// What a helper said about itself at the handshake.
///
/// Spelled as text rather than as the protocol's own types: this crate does not
/// read the protocol, and a diagnostic that made it do so would put the crate
/// that compares programs downstream of the crate that starts them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Greeting {
    /// The helper's own version.
    pub version: String,
    /// The protocol version the two settled on.
    pub protocol: u32,
    /// The compilers it analyses with — its own, not the project's.
    pub toolchains: Vec<String>,
    /// What it offers to supply, in the spelling the protocol uses.
    pub capabilities: Vec<String>,
    /// The classes of execution it acts on when permitted, in the spelling a
    /// person types to permit them.
    ///
    /// Reported because permitting something is a decision, and the person
    /// making it should be able to find out beforehand whether the program
    /// they are permitting would do anything with it.
    pub executes: Vec<String>,
    /// What a run has to ask that the revision the two sides settled on has no
    /// way to carry, each named as a person would say it.
    ///
    /// Empty for a helper a run can use. A non-empty list is the difference
    /// between a helper that answers and a helper that is any good: these are
    /// asked before a line of the project is analysed, so a revision short of
    /// one of them stops the run at its first question rather than making it
    /// report less.
    pub predates: Vec<String>,
}

/// An optional out-of-process helper, and what a machine without it loses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HelperComponent {
    /// The name reported for it.
    pub name: &'static str,
    /// The program to look for.
    pub binary: &'static str,
    /// The languages it is the one to ask about.
    ///
    /// Beside the sentence that says the same thing to a reader, rather than
    /// parsed back out of it: a run picking a helper per file and a report
    /// saying what having it makes possible are then two readings of one
    /// answer, and neither can drift from the other.
    pub analyses: &'static [Language],
    /// What having it makes possible.
    pub enables: &'static str,
    /// What to do about not having it.
    pub advice: &'static str,
}

/// The helper that answers about Rust.
///
/// Named here rather than only inside the list, so that the run which needs it
/// and the report which says whether it is there name one value: advice that
/// drifts from the mechanism it describes is advice that points nowhere.
pub const RUST_HELPER: HelperComponent = HelperComponent {
    name: "rust-compiler-helper",
    binary: "codehelion-backend-rust",
    analyses: &[Language::Rust],
    enables: "semantic analysis of Rust",
    advice: "install codehelion-backend-rust beside this binary or on PATH",
};

/// The helper that answers about C and C++.
pub const CLANG_HELPER: HelperComponent = HelperComponent {
    name: "clang-helper",
    binary: "codehelion-backend-clang",
    analyses: &[Language::C, Language::Cpp],
    enables: "semantic analysis of C and C++",
    advice: "install codehelion-backend-clang beside this binary or on PATH",
};

/// The helpers a run can use, in a fixed order.
pub const OPTIONAL_HELPERS: [HelperComponent; 2] = [RUST_HELPER, CLANG_HELPER];

fn inspect_self() -> ComponentReport {
    ComponentReport {
        name: "codehelion",
        requirement: Requirement::Required,
        status: ComponentStatus::Available,
        detail: format!("codehelion {}", env!("CARGO_PKG_VERSION")),
        notes: Vec::new(),
    }
}

fn inspect_helper(helper: HelperComponent, found: Option<HelperFacts>) -> ComponentReport {
    let (status, detail, notes) = match found {
        // Says what is unaffected before what to do about it: the usual reason
        // somebody reads this line is to find out whether it matters.
        None => (
            ComponentStatus::NotFound,
            format!(
                "not needed for fast or structural analysis; enables {}. To add it, {}.",
                helper.enables, helper.advice
            ),
            Vec::new(),
        ),
        Some(facts) => {
            let path = facts.path.display().to_string();
            match facts.state {
                // Answering is not the same as being usable. A revision that
                // cannot carry what a run asks first is one no run gets past,
                // and calling it available sends somebody to debug a scan that
                // stops on its opening question.
                HelperState::Answered(greeting) => {
                    let status = if greeting.predates.is_empty() {
                        ComponentStatus::Available
                    } else {
                        ComponentStatus::Unusable
                    };
                    (status, path, describe(&greeting))
                }
                // The reason goes on its own line rather than beside the path,
                // because it is the sentence somebody came here for.
                HelperState::Silent(reason) => (
                    ComponentStatus::Unusable,
                    path,
                    vec![format!("this build could not talk to it: {reason}")],
                ),
            }
        }
    };
    ComponentReport {
        name: helper.name,
        requirement: Requirement::Optional,
        status,
        detail,
        notes,
    }
}

/// What a helper said, as the lines a reader gets.
///
/// The toolchain line says whose compiler answered, which is the helper's own
/// rather than the project's — a scan analysed by a different compiler than the
/// one that builds the project is a fact worth reading off the diagnostic
/// instead of discovering in a result.
fn describe(greeting: &Greeting) -> Vec<String> {
    let mut notes = vec![format!(
        "version {}, protocol {}",
        greeting.version, greeting.protocol
    )];
    // Next to the number it explains, because the revision on the line above is
    // what somebody would otherwise have to know by heart to read this off.
    if !greeting.predates.is_empty() {
        notes.push(format!(
            "too old for a semantic run: it cannot be asked to {}. Update it.",
            greeting.predates.join(", ")
        ));
    }
    if !greeting.toolchains.is_empty() {
        notes.push(format!("analyses with: {}", greeting.toolchains.join(", ")));
    }
    // A helper that offers nothing is a helper that will answer every request
    // with a refusal, so the empty case is stated rather than left off.
    if greeting.capabilities.is_empty() {
        notes.push("supplies: nothing this build asked about".to_string());
    } else {
        notes.push(format!("supplies: {}", greeting.capabilities.join(", ")));
    }
    // Stated either way, because "runs nothing" is the answer somebody
    // deciding whether to permit something needs just as much as a list is.
    if greeting.executes.is_empty() {
        notes.push("runs nothing out of a project, whatever is permitted".to_string());
    } else {
        notes.push(format!(
            "runs when permitted: {}",
            greeting.executes.join(", ")
        ));
    }
    notes
}

/// Diagnose the environment, asking `find` what each optional helper turned out
/// to be.
///
/// `find` is given a program name and returns what was found out about it, if
/// anything. It is a parameter rather than a call because looking for a program
/// — and starting it — is the business of the layer that runs one, and this
/// crate does not run anything.
///
/// The order is stable so that output is deterministic.
#[must_use]
pub fn diagnose_with(find: &dyn Fn(&str) -> Option<HelperFacts>) -> Vec<ComponentReport> {
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
        for note in &report.notes {
            writeln!(out, "  {:<name_width$}  {note}", "")?;
        }
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

    fn greeting() -> Greeting {
        Greeting {
            version: "0.1.0".to_string(),
            protocol: 1,
            toolchains: vec!["rust-analyzer 0.0.344".to_string()],
            capabilities: vec!["types".to_string(), "name_resolution".to_string()],
            executes: vec!["build-script".to_string()],
            predates: Vec::new(),
        }
    }

    fn answered(name: &str) -> HelperFacts {
        HelperFacts {
            path: PathBuf::from("/opt/bin").join(name),
            state: HelperState::Answered(greeting()),
        }
    }

    #[test]
    fn a_helper_that_is_there_is_reported_with_where_it_is() {
        let reports =
            diagnose_with(&|name| (name == OPTIONAL_HELPERS[0].binary).then(|| answered(name)));
        let found = &reports[1];
        assert_eq!(found.name, OPTIONAL_HELPERS[0].name);
        assert_eq!(found.status, ComponentStatus::Available);
        assert!(found.detail.contains("/opt/bin"), "{}", found.detail);
        // And the one that was not found still says so, rather than inheriting
        // the answer of the helper beside it.
        assert_eq!(reports[2].status, ComponentStatus::NotFound);
    }

    /// The point of shaking hands rather than stopping at the path. Which
    /// compiler will answer, and what it will answer about, decide whether a
    /// semantic run is worth starting — and neither is knowable from a program
    /// being on disk.
    #[test]
    fn a_helper_that_answered_says_what_it_is_and_what_it_supplies() {
        let reports =
            diagnose_with(&|name| (name == OPTIONAL_HELPERS[0].binary).then(|| answered(name)));
        let notes = reports[1].notes.join("\n");
        assert!(notes.contains("version 0.1.0"), "{notes}");
        assert!(notes.contains("protocol 1"), "{notes}");
        assert!(notes.contains("rust-analyzer 0.0.344"), "{notes}");
        assert!(notes.contains("types, name_resolution"), "{notes}");
        // And what permitting something would actually get, which is the fact
        // a person needs before granting it rather than after.
        assert!(
            notes.contains("runs when permitted: build-script"),
            "{notes}"
        );
    }

    /// A helper offering nothing would refuse every request it is sent, which
    /// is a different situation from one whose capabilities were not printed.
    #[test]
    fn a_helper_that_offers_nothing_says_so_rather_than_saying_less() {
        let report = inspect_helper(
            OPTIONAL_HELPERS[0],
            Some(HelperFacts {
                path: PathBuf::from("/opt/bin/helper"),
                state: HelperState::Answered(Greeting {
                    capabilities: Vec::new(),
                    executes: Vec::new(),
                    ..greeting()
                }),
            }),
        );
        assert!(
            report
                .notes
                .iter()
                .any(|note| note.starts_with("supplies:")),
            "{:?}",
            report.notes
        );
        // The same for what it runs: "nothing, whatever you permit" is an
        // answer, and leaving the line off reads as a question nobody asked.
        assert!(
            report
                .notes
                .iter()
                .any(|note| note.contains("runs nothing")),
            "{:?}",
            report.notes
        );
    }

    /// Installed and unusable is its own state. Calling it available sends
    /// somebody to debug a scan that was never going to work; calling it
    /// missing sends them to install what is already there.
    #[test]
    fn a_helper_that_would_not_answer_is_neither_available_nor_missing() {
        let report = inspect_helper(
            OPTIONAL_HELPERS[0],
            Some(HelperFacts {
                path: PathBuf::from("/opt/bin/helper"),
                state: HelperState::Silent("speaks protocol 2, this build speaks 1".to_string()),
            }),
        );
        assert_eq!(report.status, ComponentStatus::Unusable);
        assert!(
            report.detail.contains("/opt/bin/helper"),
            "{}",
            report.detail
        );
        assert!(
            report.notes.iter().any(|note| note.contains("protocol 2")),
            "{:?}",
            report.notes
        );
    }

    /// A helper can answer everything it is asked and still be one no run gets
    /// past, because the questions a run asks first are ones its revision never
    /// had. Reporting that as available leaves somebody to find out from a scan
    /// that refuses before it reads anything.
    #[test]
    fn a_helper_too_old_to_be_asked_what_a_run_asks_first_is_not_called_available() {
        let report = inspect_helper(
            OPTIONAL_HELPERS[0],
            Some(HelperFacts {
                path: PathBuf::from("/opt/bin/helper"),
                state: HelperState::Answered(Greeting {
                    protocol: 1,
                    predates: vec!["describe the build".to_string()],
                    ..greeting()
                }),
            }),
        );
        assert_eq!(report.status, ComponentStatus::Unusable);
        let notes = report.notes.join("\n");
        // Naming the question rather than only the number: a revision is a
        // fact about the program, and what it cannot be asked is the fact
        // about the run.
        assert!(notes.contains("describe the build"), "{notes}");
        assert!(notes.contains("Update it"), "{notes}");
        // And it still says what it is, because deciding whether to update
        // takes knowing which build is installed.
        assert!(notes.contains("version 0.1.0"), "{notes}");
    }

    #[test]
    fn what_a_helper_said_is_printed_under_it() {
        let mut buffer = Vec::new();
        let reports =
            diagnose_with(&|name| (name == OPTIONAL_HELPERS[0].binary).then(|| answered(name)));
        render(&reports, &mut buffer).expect("render should succeed");
        let text = String::from_utf8(buffer).expect("output is utf-8");
        let lines: Vec<&str> = text.lines().collect();
        let at = lines
            .iter()
            .position(|line| line.contains(OPTIONAL_HELPERS[0].name))
            .expect("the helper is listed");
        assert!(lines[at + 1].contains("version 0.1.0"), "{text}");
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
