//! What a run is allowed to run, and what it reads instead.
//!
//! Semantic analysis wants things only a build can produce: a table a build
//! script writes, the items a derive macro expands to, the flags a configure
//! step decides. Producing them means running code out of the project being
//! audited, which is the one thing a tool pointed at somebody else's repository
//! must not do by accident.
//!
//! So execution is not a mode this tool has and can be talked into leaving. The
//! default is that no class of execution is permitted, permission is granted a
//! class at a time, and everything refused is reported: what was skipped, what
//! it cost, and the exact thing to type to allow it. A skip nobody is told
//! about reads as an answer.
//!
//! # Why per class
//!
//! One switch for "run things" collapses decisions of very different weight.
//! Expanding a procedural macro runs a compiler plugin the project already
//! trusts its own developers with; running a configure step runs a shell
//! script that may reach the network. Somebody willing to do the first is not
//! thereby willing to do the second, and a single flag would make agreeing to
//! either mean agreeing to both.
//!
//! # What is always allowed
//!
//! Reading what the project already has: manifests, a compilation database,
//! artifacts a build left behind, debug information. None of them run anything,
//! and they are listed explicitly ([`Reading`]) rather than left as "whatever
//! is not execution", so that a new information source has to be classified
//! before it can be used.

use std::collections::BTreeSet;
use std::time::Duration;

/// Something that would run code supplied by the project being audited.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Execution {
    /// A Cargo build script.
    BuildScript,
    /// A procedural macro, expanded by compiling and calling it.
    ProceduralMacro,
    /// A configure step: `CMake`, autotools, or a generator script.
    Configure,
    /// A compiler wrapper the project interposes.
    CompilerWrapper,
    /// A command that generates source files.
    GeneratedSource,
}

/// Every class, in a fixed order.
///
/// Kept as a list rather than derived, so adding a class is a decision that has
/// to be made once here and then shows up everywhere it matters — including in
/// the test that checks a permission for one class grants nothing else.
pub const EXECUTION_CLASSES: [Execution; 5] = [
    Execution::BuildScript,
    Execution::ProceduralMacro,
    Execution::Configure,
    Execution::CompilerWrapper,
    Execution::GeneratedSource,
];

impl Execution {
    /// Stable lowercase identifier: what a person types to permit it, and what
    /// a report prints when it was refused.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::BuildScript => "build-script",
            Self::ProceduralMacro => "proc-macro",
            Self::Configure => "configure",
            Self::CompilerWrapper => "compiler-wrapper",
            Self::GeneratedSource => "generated-source",
        }
    }

    /// The class a name refers to, or `None` for a name this build has never
    /// heard of — which is refused rather than ignored, since silently
    /// dropping an unrecognised permission would leave somebody believing they
    /// had granted one.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        EXECUTION_CLASSES
            .into_iter()
            .find(|class| class.name() == name)
    }

    /// What is lost by refusing it, in the words a report uses.
    #[must_use]
    pub const fn cost(self) -> &'static str {
        match self {
            Self::BuildScript => {
                "types and items that only exist after a build script has generated them"
            }
            Self::ProceduralMacro => "the items a derive or attribute macro expands to",
            Self::Configure => "the compile flags a configure step would have decided",
            Self::CompilerWrapper => "whatever the project's own compiler wrapper adds",
            Self::GeneratedSource => "source files that a command produces rather than a person",
        }
    }

    /// The argument that permits this class.
    #[must_use]
    pub fn permission_argument(self) -> String {
        format!("--allow-execution={}", self.name())
    }
}

/// Something a run may read without running anything.
///
/// Listed rather than assumed: a source of information that is not on this list
/// has not been thought about yet, and the way to add one is to decide which
/// side of the line it falls on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Reading {
    /// Source files.
    Source,
    /// Cargo manifests and the metadata derived from them without a build.
    CargoMetadata,
    /// A `compile_commands.json` that already exists.
    CompilationDatabase,
    /// Artifacts a previous build left behind.
    ExistingArtifacts,
    /// Debug information inside those artifacts.
    DebugInformation,
}

/// What a run is permitted to run.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ExecutionPolicy {
    allowed: BTreeSet<Execution>,
}

/// Why something was not done, and how to change that.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// The class that was refused.
    pub execution: Execution,
    /// What the refusal cost.
    pub cost: &'static str,
    /// The argument that would permit it.
    pub permission_argument: String,
}

impl Refusal {
    /// A single line for a report or a log.
    #[must_use]
    pub fn describe(&self) -> String {
        format!(
            "skipped {}: not permitted, so this run has no {}. Pass {} to allow it.",
            self.execution.name(),
            self.cost,
            self.permission_argument
        )
    }
}

impl ExecutionPolicy {
    /// The default: nothing may run.
    #[must_use]
    pub fn deny_all() -> Self {
        Self::default()
    }

    /// The same policy with one more class permitted.
    #[must_use]
    pub fn allowing(mut self, execution: Execution) -> Self {
        self.allowed.insert(execution);
        self
    }

    /// The policy described by a comma-separated list of class names.
    ///
    /// # Errors
    ///
    /// Returns the first name that is not a class, so that a typo in a
    /// permission is refused rather than quietly granting nothing.
    pub fn parse(names: &str) -> Result<Self, UnknownExecution> {
        let mut policy = Self::deny_all();
        for name in names.split(',').map(str::trim).filter(|n| !n.is_empty()) {
            let execution = Execution::from_name(name).ok_or_else(|| UnknownExecution {
                name: name.to_string(),
            })?;
            policy = policy.allowing(execution);
        }
        Ok(policy)
    }

    /// Whether this class may run.
    #[must_use]
    pub fn permits(&self, execution: Execution) -> bool {
        self.allowed.contains(&execution)
    }

    /// Reading never needs permission; the method exists so that the two sides
    /// of the line are asked the same way and a caller cannot reach a source
    /// this build has not classified.
    #[must_use]
    pub const fn permits_reading(&self, _reading: Reading) -> bool {
        true
    }

    /// What refusing this class means, or `None` if it is permitted.
    #[must_use]
    pub fn refusal(&self, execution: Execution) -> Option<Refusal> {
        if self.permits(execution) {
            return None;
        }
        Some(Refusal {
            execution,
            cost: execution.cost(),
            permission_argument: execution.permission_argument(),
        })
    }

    /// The classes permitted, in a fixed order.
    #[must_use]
    pub fn permitted(&self) -> Vec<Execution> {
        self.allowed.iter().copied().collect()
    }
}

/// A permission naming a class that does not exist.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "no execution class is called `{name}`; the classes are \
     build-script, proc-macro, configure, compiler-wrapper, generated-source"
)]
pub struct UnknownExecution {
    /// The name that was given.
    pub name: String,
}

/// The ceilings a run works under.
///
/// Separate from the execution policy because they answer a different question:
/// the policy says what may run, and these say how much a run may spend on
/// input that turns out to be hostile rather than merely large.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    /// Largest file read.
    pub max_file_bytes: u64,
    /// Longest a single file may be parsed for.
    pub parse_timeout: Duration,
    /// Largest amount of memory a subprocess may use, where the platform can
    /// say so.
    pub max_subprocess_bytes: Option<u64>,
    /// Largest number of candidate pairs generated before a run gives up on
    /// generating more and says so.
    pub max_candidates: usize,
    /// Longest posting list or fragment class admitted to candidate pairing.
    ///
    /// This bounds the fan-out before the pair budget applies. Keeping it
    /// separate makes the untrusted profile cap both the number of lists and
    /// the work one high-frequency list can create.
    pub posting_cap: usize,
    /// Largest related component refined as one group.
    ///
    /// Complete-linkage refinement can repeatedly compare a component, so a
    /// distinct ceiling keeps an adversarially large related set bounded even
    /// after candidate generation has stopped.
    pub max_component: usize,
    /// Largest distinct Structural pairs admitted to precise verification.
    pub verification_budget: usize,
    /// Largest dynamic-programming cell count for one Structural alignment.
    pub max_alignment_cells: usize,
    /// Longest a compiler helper may spend answering for one source unit.
    pub helper_timeout: Duration,
    /// What may run.
    pub execution: ExecutionPolicy,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_file_bytes: crate::discovery::DEFAULT_MAX_FILE_BYTES,
            parse_timeout: Duration::from_secs(30),
            max_subprocess_bytes: None,
            max_candidates: 5_000_000,
            // The structural candidate pipeline's default is the largest
            // shipped posting ceiling. The untrusted profile below is lower
            // than both it and the Fast pipeline's smaller default.
            posting_cap: 256,
            max_component: 1024,
            verification_budget: 1_000_000,
            max_alignment_cells: 4_000_000,
            helper_timeout: Duration::from_secs(300),
            execution: ExecutionPolicy::deny_all(),
        }
    }
}

impl Limits {
    /// The profile for a repository nobody vouches for.
    ///
    /// Every ceiling lower than the default and nothing permitted to run. It is
    /// a starting point rather than a sandbox: it bounds what a hostile input
    /// can cost, and it cannot bound what a program does once something has
    /// agreed to run it, which is why it grants no execution at all.
    #[must_use]
    pub fn untrusted() -> Self {
        Self {
            max_file_bytes: 512 * 1024,
            parse_timeout: Duration::from_secs(5),
            max_subprocess_bytes: Some(1024 * 1024 * 1024),
            max_candidates: 500_000,
            // 32 is below Fast's 64 and Structural's 256 default caps, so it
            // constrains every shipped pairing path rather than only one.
            posting_cap: 32,
            // Refinement has super-linear worst-case cost. 128 keeps the
            // contained piece small enough for the profile while preserving a
            // useful amount of context for ordinary duplicate families.
            max_component: 128,
            verification_budget: 100_000,
            max_alignment_cells: 250_000,
            // Compiler helpers may legitimately take longer than a lexer,
            // but five minutes makes a stalled helper an unbounded wait for an
            // untrusted tree. Thirty seconds is deliberately conservative.
            helper_timeout: Duration::from_secs(30),
            execution: ExecutionPolicy::deny_all(),
        }
    }

    /// Whether every ceiling here is at or below `other`'s.
    ///
    /// A profile that claims to be stricter has to be stricter in every
    /// dimension; one that tightened a timeout while raising a size ceiling
    /// would be a different trade, not a stricter one.
    #[must_use]
    pub fn is_at_most(&self, other: &Self) -> bool {
        self.max_file_bytes <= other.max_file_bytes
            && self.parse_timeout <= other.parse_timeout
            && self.max_candidates <= other.max_candidates
            && self.posting_cap <= other.posting_cap
            && self.verification_budget <= other.verification_budget
            && self.max_alignment_cells <= other.max_alignment_cells
            && self.max_component <= other.max_component
            && self.helper_timeout <= other.helper_timeout
            && option_ceiling_at_most(self.max_subprocess_bytes, other.max_subprocess_bytes)
            && self
                .execution
                .permitted()
                .iter()
                .all(|class| other.execution.permits(*class))
    }
}

/// Whether an optional memory ceiling is no weaker than another one.
///
/// `None` means no ceiling, so a bounded profile is at most an unbounded one,
/// while an unbounded profile is never at most a bounded one.
const fn option_ceiling_at_most(left: Option<u64>, right: Option<u64>) -> bool {
    match (left, right) {
        (_, None) => true,
        (Some(left), Some(right)) => left <= right,
        (None, Some(_)) => false,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn nothing_runs_unless_it_was_asked_for() {
        let policy = ExecutionPolicy::deny_all();
        for class in EXECUTION_CLASSES {
            assert!(!policy.permits(class), "{class:?}");
            assert!(policy.refusal(class).is_some(), "{class:?}");
        }
        assert_eq!(ExecutionPolicy::default(), policy);
    }

    /// The whole point of classifying: agreeing to expand a macro is not
    /// agreeing to run a configure script.
    #[test]
    fn permitting_one_class_permits_only_that_class() {
        let policy = ExecutionPolicy::deny_all().allowing(Execution::ProceduralMacro);
        assert!(policy.permits(Execution::ProceduralMacro));
        for class in EXECUTION_CLASSES {
            if class != Execution::ProceduralMacro {
                assert!(!policy.permits(class), "{class:?}");
            }
        }
    }

    /// The advice in a refusal has to work. Writing the argument as prose
    /// beside the code that parses it leaves the two free to drift, and the
    /// drift shows up as a message telling somebody to type something that does
    /// nothing.
    #[test]
    fn the_argument_a_refusal_names_is_the_argument_that_permits_it() {
        for class in EXECUTION_CLASSES {
            let refusal = ExecutionPolicy::deny_all().refusal(class).unwrap();
            let value = refusal
                .permission_argument
                .split_once('=')
                .map(|(_, value)| value)
                .unwrap();
            let policy = ExecutionPolicy::parse(value).unwrap();
            assert!(policy.permits(class), "{class:?}: {refusal:?}");
            assert!(refusal.describe().contains(class.name()));
        }
    }

    #[test]
    fn several_permissions_can_be_given_at_once() {
        let policy = ExecutionPolicy::parse("build-script, proc-macro").unwrap();
        assert_eq!(
            policy.permitted(),
            vec![Execution::BuildScript, Execution::ProceduralMacro]
        );
    }

    /// A misspelled permission grants nothing, and somebody who misspelled one
    /// believes they granted something. Refusing is the only outcome that does
    /// not mislead.
    #[test]
    fn a_permission_nobody_can_grant_is_an_error_rather_than_a_shrug() {
        let error = ExecutionPolicy::parse("build-scripts").unwrap_err();
        assert_eq!(error.name, "build-scripts");
        assert!(error.to_string().contains("build-script"));
    }

    #[test]
    fn every_class_has_a_name_that_maps_back() {
        for class in EXECUTION_CLASSES {
            assert_eq!(Execution::from_name(class.name()), Some(class), "{class:?}");
        }
        assert_eq!(Execution::from_name("run-everything"), None);
    }

    #[test]
    fn reading_what_the_project_already_has_needs_no_permission() {
        let policy = ExecutionPolicy::deny_all();
        for reading in [
            Reading::Source,
            Reading::CargoMetadata,
            Reading::CompilationDatabase,
            Reading::ExistingArtifacts,
            Reading::DebugInformation,
        ] {
            assert!(policy.permits_reading(reading), "{reading:?}");
        }
    }

    #[test]
    fn the_untrusted_profile_is_stricter_in_every_dimension() {
        let untrusted = Limits::untrusted();
        let default = Limits::default();
        assert!(untrusted.is_at_most(&default));
        assert!(!default.is_at_most(&untrusted));
        for class in EXECUTION_CLASSES {
            assert!(!untrusted.execution.permits(class), "{class:?}");
        }
    }

    /// A profile is only stricter if it is stricter everywhere; the comparison
    /// has to notice a trade rather than call it an improvement.
    #[test]
    fn a_profile_that_trades_one_ceiling_for_another_is_not_stricter() {
        let traded = Limits {
            max_file_bytes: u64::MAX,
            ..Limits::untrusted()
        };
        assert!(!traded.is_at_most(&Limits::default()));
    }
}
