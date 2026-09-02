//! Keeping one helper answering across a whole run.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::Helper;
use super::diagnostics::bounded;
use super::error::{HelperError, explanation, unavailability};
use crate::ir::{CompilerIr, Unavailability, UnitRef};
use crate::protocol::{Capability, CompileCommandSelector, Execution, HelperIdentity};
use crate::sandbox::SandboxRequest;

/// What came back from asking about one unit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Analysis {
    /// The compiler IR for the unit.
    Done(Box<CompilerIr>),
    /// There is none, and why.
    Missing(Unavailability),
}

/// How many times a helper may be restarted before a run stops trying.
pub const DEFAULT_MAX_RESTARTS: u32 = 3;

/// A helper kept running across many units, restarted when it breaks.
///
/// A compiler helper analyzing a real project will meet input that kills it —
/// that is what compilers do on the code that finds their bugs. Handing that
/// failure to the caller as an error would end a scan on its first bad file, so
/// this owns the recovery instead: the helper is restarted, the unit that broke
/// it is tried once more, and if it breaks the helper again that unit is set
/// aside and the rest of the project is analyzed.
///
/// Setting the unit aside rather than the helper is the important half. A crash
/// says something about the pair, and only re-running the same input tells you
/// which of the two it was about.
#[derive(Debug)]
pub struct Supervisor {
    program: PathBuf,
    args: Vec<String>,
    timeout: Duration,
    sandbox: SandboxRequest,
    max_restarts: u32,
    /// Consecutive restarts since the last complete helper response.
    consecutive_restarts: u32,
    restarts: u32,
    helper: Option<Helper>,
    /// What the last helper to answer a handshake said it is, kept after that
    /// helper is gone.
    ///
    /// A run records who answered it, and by the time it does the helper has
    /// been shut down and every restart along the way has been and gone. Read
    /// off the live process instead, the answer would be "nobody" for every
    /// run that finished — which is every run that gets recorded.
    spoke_with: Option<HelperIdentity>,
    /// What every helper started here may run out of the project.
    permitted: Vec<Execution>,
    /// Units that have already broken a helper once, under what broke it.
    poisoned: BTreeMap<UnitRef, Explained>,
    /// Bounded stderr emitted while answering the most recent unavailable unit.
    diagnostics: Vec<String>,
    /// The diagnostics behind the most recently failed attempt.
    ///
    /// Kept apart from `diagnostics`, which the next unit's call clears before
    /// its own attempt runs. The attempt that finally spends the restart
    /// budget happened while answering an earlier unit, so by the time a run
    /// gives up over it `diagnostics` has already been reset for whoever asked
    /// next. This survives that reset, so give-up carries what was actually
    /// said rather than the empty span the next call started with.
    last_failure: Vec<String>,
    /// Whether a helper has ever been started, which is what tells a first
    /// start apart from a restart.
    started: bool,
    /// Set once the run stops starting helpers, under the condition that
    /// stopped it.
    given_up: Option<Explained>,
}

/// A reason a unit has no compiler IR, with what was said while it arose.
///
/// The two travel together because a run reports them together: a reason with
/// no sentence beside it tells somebody that something is wrong and nothing
/// about what to do, and the sentence is only available at the moment the
/// reason is produced.
#[derive(Debug, Clone)]
struct Explained {
    /// The condition that prevented the analysis.
    reason: Unavailability,
    /// What the helper said about it, bounded as collected.
    diagnostics: Vec<String>,
}

impl Supervisor {
    /// Supervise the helper at `program`, started with `args`.
    #[must_use]
    pub const fn new(program: PathBuf, args: Vec<String>, timeout: Duration) -> Self {
        Self {
            program,
            args,
            timeout,
            sandbox: SandboxRequest::unrestricted(),
            max_restarts: DEFAULT_MAX_RESTARTS,
            consecutive_restarts: 0,
            restarts: 0,
            helper: None,
            spoke_with: None,
            permitted: Vec::new(),
            poisoned: BTreeMap::new(),
            diagnostics: Vec::new(),
            last_failure: Vec::new(),
            started: false,
            given_up: None,
        }
    }

    /// Allow at most `restarts` restarts before giving up on the helper.
    #[must_use]
    pub const fn with_max_restarts(mut self, restarts: u32) -> Self {
        self.max_restarts = restarts;
        self
    }

    /// Require this containment policy for every helper start and restart.
    #[must_use]
    pub const fn sandboxed(mut self, sandbox: SandboxRequest) -> Self {
        self.sandbox = sandbox;
        self
    }

    /// Permit `permitted` for every helper this supervises, restarts included.
    ///
    /// Held here rather than on the helper because a restart replaces the
    /// process: a permission that lived only on the first one would quietly
    /// lapse the moment a unit killed it, and the rest of the run would answer
    /// under rules nobody chose.
    #[must_use]
    pub fn permitting(mut self, permitted: Vec<Execution>) -> Self {
        self.permitted = permitted;
        self
    }

    /// How many times the helper has been restarted.
    #[must_use]
    pub const fn restarts(&self) -> u32 {
        self.restarts
    }

    /// What the helper said it is.
    ///
    /// `None` until one has answered a handshake: a program that never started
    /// described itself to nobody, and a run that names it anyway would be
    /// crediting answers to a helper that never spoke.
    #[must_use]
    pub const fn spoke_with(&self) -> Option<&HelperIdentity> {
        self.spoke_with.as_ref()
    }

    /// Whether `unit` has been set aside as one the helper cannot survive.
    #[must_use]
    pub fn has_set_aside(&self, unit: &UnitRef) -> bool {
        self.poisoned.contains_key(unit)
    }

    /// Take the helper diagnostics from the most recent unavailable request.
    ///
    /// A successful response clears these diagnostics: stderr describes the
    /// failure that produced it, not the next unit the helper happens to read.
    #[must_use]
    pub fn take_diagnostics(&mut self) -> Vec<String> {
        std::mem::take(&mut self.diagnostics)
    }

    /// Get one unit's compiler IR, restarting and retrying as needed.
    ///
    /// Never fails: every way this can go wrong is a reason the unit has no
    /// compiler IR, which is a result a scan can report and carry on from.
    pub fn analyze(&mut self, unit: &UnitRef, want: &[Capability]) -> Analysis {
        self.analyze_with_command(unit, None, want)
    }

    /// Get one unit's compiler IR under one exact compilation command.
    ///
    /// The retry boundary remains the unit: a selector only refines how a C or
    /// C++ unit is read, and each semantic build partition owns its supervisor.
    pub fn analyze_with_command(
        &mut self,
        unit: &UnitRef,
        compile_command: Option<&CompileCommandSelector>,
        want: &[Capability],
    ) -> Analysis {
        self.analyze_with_command_and_boundary(unit, compile_command, None, want)
    }

    /// Get one unit's compiler IR while confining compiler reads.
    pub fn analyze_with_command_and_boundary(
        &mut self,
        unit: &UnitRef,
        compile_command: Option<&CompileCommandSelector>,
        read_boundary: Option<&Path>,
        want: &[Capability],
    ) -> Analysis {
        self.diagnostics.clear();
        // A run that stopped asking, and a unit already set aside, are both
        // answered from what was found out at the time. Answering either with a
        // fresh generic reason would bury the one condition that explains the
        // whole run under one repeated symptom of it.
        if let Some(given_up) = self.given_up.clone() {
            self.diagnostics = given_up.diagnostics;
            return Analysis::Missing(given_up.reason);
        }
        if let Some(set_aside) = self.poisoned.get(unit).cloned() {
            // It broke a helper twice already. Asking again costs another
            // restart and answers nothing new.
            self.diagnostics = set_aside.diagnostics;
            return Analysis::Missing(set_aside.reason);
        }
        match self.attempt(unit, compile_command, read_boundary, want) {
            Ok(analysis) => {
                self.consecutive_restarts = 0;
                self.keep_what_was_said_about(&analysis);
                analysis
            }
            Err(first) => {
                let explained = self.explained(&first);
                self.diagnostics.clone_from(&explained.diagnostics);
                if !explained.reason.worth_retrying() {
                    return Analysis::Missing(explained.reason);
                }
                self.helper = None;
                match self.attempt(unit, compile_command, read_boundary, want) {
                    Ok(analysis) => {
                        self.consecutive_restarts = 0;
                        self.diagnostics.clear();
                        self.keep_what_was_said_about(&analysis);
                        analysis
                    }
                    Err(second) => {
                        let explained = self.explained(&second);
                        self.diagnostics.clone_from(&explained.diagnostics);
                        // Twice on the same unit: the unit is what the helper
                        // cannot survive, so it is the unit that is set aside,
                        // under what it did rather than under a later guess.
                        let reason = explained.reason;
                        self.poisoned.insert(unit.clone(), explained);
                        self.helper = None;
                        Analysis::Missing(reason)
                    }
                }
            }
        }
    }

    /// Keep what the helper said about a unit it could not answer for.
    ///
    /// A helper that says a unit is unavailable has usually said why, and that
    /// sentence is the whole difference between a report somebody can act on
    /// and a count of a reason's name.
    ///
    /// The answer is preferred over the standard error stream because only the
    /// answer is ordered against the unit it belongs to. The stream is drained
    /// either way — including after a unit that was answered — so that a line
    /// delivered late is not read as belonging to whatever came next.
    fn keep_what_was_said_about(&mut self, analysis: &Analysis) {
        let Some(helper) = self.helper.as_mut() else {
            return;
        };
        let printed = helper.recent_diagnostics();
        let answered = helper.take_answer_diagnostics();
        if matches!(analysis, Analysis::Missing(_)) {
            self.diagnostics = if answered.is_empty() {
                printed
            } else {
                answered
            };
        }
    }

    /// Why a unit has no IR, with everything said while finding that out.
    ///
    /// Both halves are kept: the error carries what the helper refused in its
    /// own words, and the process carries what it printed while doing so. A
    /// helper that timed out says nothing in the error and may have said
    /// everything on its standard error.
    fn explained(&mut self, error: &HelperError) -> Explained {
        let mut diagnostics = explanation(error);
        if let Some(helper) = self.helper.as_mut() {
            for line in helper.recent_diagnostics() {
                if !diagnostics.contains(&line) {
                    diagnostics.push(line);
                }
            }
        }
        let diagnostics = bounded(diagnostics, 0);
        self.last_failure.clone_from(&diagnostics);
        Explained {
            reason: unavailability(error),
            diagnostics,
        }
    }

    /// One attempt, starting the helper if it is not running.
    fn attempt(
        &mut self,
        unit: &UnitRef,
        compile_command: Option<&CompileCommandSelector>,
        read_boundary: Option<&Path>,
        want: &[Capability],
    ) -> Result<Analysis, HelperError> {
        if self.helper.is_none() {
            if self.started {
                if self.consecutive_restarts >= self.max_restarts {
                    self.given_up = Some(Explained {
                        reason: Unavailability::RestartBudgetExhausted,
                        diagnostics: self.last_failure.clone(),
                    });
                    return Ok(Analysis::Missing(Unavailability::RestartBudgetExhausted));
                }
                self.restarts = self.restarts.saturating_add(1);
                self.consecutive_restarts = self.consecutive_restarts.saturating_add(1);
            }
            self.started = true;
            let arguments: Vec<&str> = self.args.iter().map(String::as_str).collect();
            let started =
                Helper::start_with_sandbox(&self.program, &arguments, self.timeout, self.sandbox);
            let helper = match started {
                Ok(helper) => helper.permitting(self.permitted.clone()),
                Err(error) => {
                    // A helper that will not start will not start for the next
                    // unit either, so the run stops asking rather than paying a
                    // process spawn per file to be told the same thing — and it
                    // keeps why, because every unit after this one is reported
                    // under it.
                    self.given_up = Some(Explained {
                        reason: unavailability(&error),
                        diagnostics: explanation(&error),
                    });
                    return Err(error);
                }
            };
            self.spoke_with = Some(helper.identity().clone());
            self.helper = Some(helper);
        }
        let Some(helper) = self.helper.as_mut() else {
            return Ok(Analysis::Missing(Unavailability::HelperDied));
        };
        helper.analyze_with_command_and_boundary(unit, compile_command, read_boundary, want)
    }

    /// Stop the helper, if one is running.
    pub fn shutdown(&mut self) {
        if let Some(helper) = self.helper.take() {
            let _ = helper.shutdown();
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::client::DEFAULT_TIMEOUT;

    /// A unit reported under an exhausted restart budget must still carry the
    /// explanation for what spent it.
    ///
    /// `attempt` decides a budget is exhausted before it ever spawns a
    /// process, so the crash that actually spent the budget is reproduced
    /// through `explained` — the same private path a real dying helper goes
    /// through — rather than through a real subprocess. `diagnostics` is then
    /// cleared exactly as `analyze_with_command_and_boundary` clears it at the
    /// start of the next unit's call, before that unit's own attempt runs.
    #[test]
    fn a_unit_that_exhausts_the_restart_budget_still_names_why() {
        let mut supervisor = Supervisor::new(PathBuf::from("unused"), Vec::new(), DEFAULT_TIMEOUT)
            .with_max_restarts(2);
        supervisor.explained(&HelperError::Died {
            stderr: vec!["the helper crashed analysing src/broken.rs".into()],
        });
        supervisor.diagnostics.clear();
        supervisor.started = true;
        supervisor.consecutive_restarts = supervisor.max_restarts;

        let next = UnitRef {
            unit: "crate".into(),
            file: "src/after.rs".into(),
            variant: "variant-0".into(),
        };
        let outcome = supervisor
            .attempt(&next, None, None, &[])
            .expect("giving up is an answer, not a failure");
        assert_eq!(
            outcome,
            Analysis::Missing(Unavailability::RestartBudgetExhausted)
        );
        let given_up = supervisor
            .given_up
            .as_ref()
            .expect("the run recorded what stopped it");
        assert!(
            !given_up.diagnostics.is_empty(),
            "a unit reported under an exhausted budget carried no explanation"
        );
        assert!(
            given_up
                .diagnostics
                .iter()
                .any(|line| line.contains("src/broken.rs")),
            "the explanation lost the crash that actually spent the budget: {:?}",
            given_up.diagnostics
        );
    }
}
