//! Driving a helper process from core's side.
//!
//! A helper is a separate program with its own compiler dependency, so every
//! way it can fail is a way core must not. It can be absent, be built for a
//! protocol revision this build does not speak, answer slowly, answer wrongly,
//! or die mid-request. None of those may take the run down with it: a scan that
//! cannot get semantic information is a scan that reports less, not a scan that
//! crashes.
//!
//! So the client treats a dead helper as an ordinary outcome. Reads happen on a
//! thread and are collected with a deadline, which is the only way to put a
//! bound on a peer that has stopped answering — a blocking read on a pipe has
//! no timeout, and a helper stuck in a compiler loop will never close it. The
//! helper's standard error is drained the whole time and kept, because the
//! sentence that explains the failure is almost always there and is lost the
//! moment the process is reaped.

use std::collections::BTreeSet;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, RecvTimeoutError, sync_channel};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

#[allow(clippy::disallowed_types)]
use std::process::{Child, ChildStdin};

use crate::ir::{CompilerIr, Unavailability, UnitRef};
use crate::protocol::{
    Analyze, BuildDescription, Capability, ClientIdentity, CompileCommandSelector, DescribeBuild,
    Execution, FrameError, HelperIdentity, PROTOCOL_VERSION, Request, RequestBody, Response,
    ResponseBody, read_frame, write_frame,
};
use crate::sandbox::{SandboxError, SandboxRequest, spawn};

/// How long a request waits before the helper is treated as unresponsive.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);

/// Lines of helper standard error kept for diagnostics.
///
/// Enough to carry a compiler's complaint and a backtrace, bounded so a helper
/// looping on a warning cannot grow this without limit.
pub const MAX_DIAGNOSTIC_LINES: usize = 256;

/// Why talking to a helper did not work.
#[derive(Debug, thiserror::Error)]
pub enum HelperError {
    /// No such program was found.
    #[error("no helper named {name} was found (looked beside the executable and on PATH)")]
    NotFound {
        /// The helper that was wanted.
        name: String,
    },
    /// Core and helper have no protocol revision in common.
    #[error("the helper speaks protocol {helper}, but this build requires protocol {required}")]
    NoCommonProtocol {
        /// Revision the helper announced.
        helper: u32,
        /// Revision this build requires.
        required: u32,
    },
    /// The helper cannot supply something semantic analysis cannot do without.
    #[error("the helper does not supply {missing:?}, which semantic analysis cannot go without")]
    MissingRequiredCapability {
        /// What it could not supply.
        missing: Capability,
    },
    /// The helper did not answer in time.
    #[error("the helper did not answer within {}s", timeout.as_secs())]
    TimedOut {
        /// The deadline that passed.
        timeout: Duration,
    },
    /// The helper ended before answering.
    #[error("the helper stopped before answering{}", describe(.stderr))]
    Died {
        /// What it printed on standard error before it went.
        stderr: Vec<String>,
    },
    /// The helper answered, but not the thing that was asked.
    #[error("the helper answered request {answered} while {expected} was outstanding")]
    Mismatched {
        /// The id it answered.
        answered: u64,
        /// The id that was asked.
        expected: u64,
    },
    /// The helper changed the protocol revision after the conversation had
    /// already settled on one.
    #[error(
        "the helper answered using protocol {received}, but this conversation settled on {expected}"
    )]
    ProtocolMismatch {
        /// Revision carried by the response frame.
        received: u32,
        /// Revision the request and response must use after negotiation.
        expected: u32,
    },
    /// The helper reported that it could not do the thing.
    #[error("the helper refused: {code}: {message}")]
    Refused {
        /// Its stable code.
        code: String,
        /// Its explanation.
        message: String,
    },
    /// The conversation itself broke.
    #[error(transparent)]
    Frame(#[from] FrameError),
    /// The requested helper containment cannot be enforced on this platform.
    #[error(transparent)]
    Sandbox(#[from] SandboxError),
}

/// Render collected standard error for an error message.
fn describe(stderr: &[String]) -> String {
    if stderr.is_empty() {
        String::from(" and said nothing about why")
    } else {
        format!(", saying: {}", stderr.join(" / "))
    }
}

/// Where to look for a helper, in the order the search tries.
///
/// An explicitly configured path is tried first. The plan for this search put
/// configuration last, which is the wrong way round: a setting that loses to
/// whatever happens to be on `PATH` cannot be used to pin a helper, which is
/// the only reason to write one down.
#[must_use]
pub fn locate(name: &str, configured: Option<&Path>) -> Option<PathBuf> {
    if let Some(path) = configured {
        return path.is_file().then(|| path.to_path_buf());
    }
    let file = format!("{name}{}", std::env::consts::EXE_SUFFIX);
    if let Ok(current) = std::env::current_exe()
        && let Some(directory) = current.parent()
    {
        let beside = directory.join(&file);
        if beside.is_file() {
            return Some(beside);
        }
    }
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|directory| directory.join(&file))
        .find(|candidate| candidate.is_file())
}

/// A running helper and the conversation with it.
#[derive(Debug)]
pub struct Helper {
    #[allow(clippy::disallowed_types)]
    child: Child,
    stdin: ChildStdin,
    responses: Receiver<Result<Response, FrameError>>,
    stderr: Arc<Mutex<Vec<String>>>,
    identity: HelperIdentity,
    protocol_version: u32,
    timeout: Duration,
    next_id: u64,
    permitted: Vec<Execution>,
}

impl Helper {
    /// Start the helper at `path`, shake hands, and settle on a revision.
    ///
    /// # Errors
    ///
    /// Fails if the program will not start, has no revision in common with this
    /// build, cannot supply a capability that [`Capability::absence`] calls
    /// load-bearing, or does not answer the handshake in time.
    pub fn start(path: &Path, timeout: Duration) -> Result<Self, HelperError> {
        Self::start_with_sandbox(path, &[], timeout, SandboxRequest::unrestricted())
    }

    /// Start the helper at `path` with `args`, then as [`Helper::start`].
    ///
    /// A helper that serves more than one toolchain is told which one on its
    /// command line, before any message is exchanged.
    ///
    /// # Errors
    ///
    /// As [`Helper::start`].
    pub fn start_with(path: &Path, args: &[&str], timeout: Duration) -> Result<Self, HelperError> {
        Self::start_with_sandbox(path, args, timeout, SandboxRequest::unrestricted())
    }

    /// Start the helper with a containment request, then as [`Helper::start`].
    ///
    /// A required OS-level memory limit is rejected before spawning when this
    /// build cannot enforce it; it is never silently ignored.
    ///
    /// # Errors
    ///
    /// As [`Helper::start`], or if the requested containment is unavailable.
    pub fn start_with_sandbox(
        path: &Path,
        args: &[&str],
        timeout: Duration,
        sandbox: SandboxRequest,
    ) -> Result<Self, HelperError> {
        let mut child = spawn(path, args, sandbox)?;

        let Some(stdin) = child.stdin.take() else {
            return Err(HelperError::Died {
                stderr: vec!["the helper was started without a standard input".into()],
            });
        };
        let stderr = Arc::new(Mutex::new(Vec::new()));
        if let Some(stream) = child.stderr.take() {
            drain_stderr(stream, Arc::clone(&stderr));
        }
        let responses = read_responses(child.stdout.take());

        let mut helper = Self {
            child,
            stdin,
            responses,
            stderr,
            identity: unknown_identity(),
            // The handshake uses the one protocol revision this build speaks.
            protocol_version: PROTOCOL_VERSION,
            timeout,
            next_id: 0,
            permitted: Vec::new(),
        };
        helper.shake_hands()?;
        Ok(helper)
    }

    /// What the helper said it is.
    #[must_use]
    pub const fn identity(&self) -> &HelperIdentity {
        &self.identity
    }

    /// The revision both sides settled on.
    #[must_use]
    pub const fn protocol_version(&self) -> u32 {
        self.protocol_version
    }

    /// Whether the helper offers `capability`.
    #[must_use]
    pub fn offers(&self, capability: Capability) -> bool {
        self.identity.capabilities.contains(&capability)
    }

    /// Whether the helper acts on `execution` when it is permitted.
    #[must_use]
    pub fn executes(&self, execution: Execution) -> bool {
        self.identity.executes.contains(&execution)
    }

    /// Permit `permitted` for every unit this helper is asked about.
    ///
    /// Set once for a whole run rather than per unit: what somebody agreed to
    /// let a project run is a decision about the project, and a permission that
    /// could vary between two of its files would be one nobody made.
    #[must_use]
    pub fn permitting(mut self, permitted: Vec<Execution>) -> Self {
        self.permitted = permitted;
        self
    }

    /// Everything the helper has printed on standard error so far.
    #[must_use]
    pub fn diagnostics(&self) -> Vec<String> {
        self.stderr
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Ask the helper to finish and wait for it to go.
    ///
    /// A helper that will not leave is killed: a scan that has its answers must
    /// not be held open by a process that has stopped listening.
    ///
    /// # Errors
    ///
    /// Fails if the request cannot be written. A helper that dies rather than
    /// acknowledging is not an error — it left, which is what was asked.
    pub fn shutdown(mut self) -> Result<(), HelperError> {
        let id = self.send(RequestBody::Shutdown)?;
        match self.receive(id) {
            Ok(ResponseBody::Shutdown) | Err(HelperError::Died { .. }) => {}
            Ok(_) | Err(_) => {
                let _ = self.child.kill();
            }
        }
        let _ = self.child.wait();
        Ok(())
    }

    /// Ask for one unit's compiler IR.
    ///
    /// `want` is narrowed to what the helper said it can do, so a request never
    /// asks for something the handshake already ruled out.
    ///
    /// # Errors
    ///
    /// Fails if the helper cannot be written to, does not answer in time, dies,
    /// or answers something other than what was asked.
    pub fn analyze(
        &mut self,
        unit: &UnitRef,
        want: &[Capability],
    ) -> Result<Analysis, HelperError> {
        self.analyze_with_command(unit, None, want)
    }

    /// Ask for one unit's compiler IR under one exact C/C++ command.
    ///
    /// The selector is optional because Rust crates have no compilation
    /// database. Protocol v1 carries it directly, so a C/C++ helper always
    /// receives the exact selected command rather than choosing one itself.
    ///
    /// # Errors
    ///
    /// Returns an error when the helper cannot be contacted or cannot return a
    /// readable answer.
    pub fn analyze_with_command(
        &mut self,
        unit: &UnitRef,
        compile_command: Option<&CompileCommandSelector>,
        want: &[Capability],
    ) -> Result<Analysis, HelperError> {
        let want = want
            .iter()
            .copied()
            .filter(|capability| self.offers(*capability))
            .collect();
        let id = self.send(RequestBody::Analyze(Analyze {
            unit: unit.clone(),
            compile_command: compile_command.cloned(),
            want,
            // Not narrowed to what the helper said it acts on. A permission it
            // will not act on has to be refused where somebody can be told
            // about it, and quietly dropping it here is what makes that
            // impossible.
            permitted: self.permitted.clone(),
        }))?;
        match self.receive(id)? {
            ResponseBody::Analyzed(ir) => {
                if ir.is_readable() {
                    Ok(Analysis::Done(ir))
                } else {
                    // A helper from another schema is not a helper that failed:
                    // it answered, and the answer cannot be read. Saying which
                    // is what lets `doctor` tell someone to update the helper
                    // rather than to debug their project.
                    Ok(Analysis::Missing(Unavailability::UnreadableSchema))
                }
            }
            ResponseBody::Unavailable { reason, .. } => Ok(Analysis::Missing(reason)),
            _ => Err(HelperError::Died {
                stderr: vec!["the helper answered an analysis with something else".into()],
            }),
        }
    }

    /// Ask what the tree at `root` is analysed under.
    ///
    /// # Errors
    ///
    /// Fails if the helper cannot be written to, does not answer in time, dies,
    /// or answers something else. A helper that answers with a failure is
    /// reported as having refused: conditions nobody could name are not
    /// conditions a run may record its answers under.
    pub fn describe(&mut self, root: &Path) -> Result<BuildDescription, HelperError> {
        let id = self.send(RequestBody::DescribeBuild(DescribeBuild {
            root: root.display().to_string(),
        }))?;
        match self.receive(id)? {
            ResponseBody::Build(build) => Ok(*build),
            _ => Err(HelperError::Died {
                stderr: vec!["the helper answered a build description with something else".into()],
            }),
        }
    }

    /// Send the handshake and take what comes back.
    fn shake_hands(&mut self) -> Result<(), HelperError> {
        let id = self.send(RequestBody::Handshake(ClientIdentity {
            client: env!("CARGO_PKG_NAME").into(),
            client_version: env!("CARGO_PKG_VERSION").into(),
            protocol: PROTOCOL_VERSION,
        }))?;
        let ResponseBody::Handshake(identity) = self.receive(id)? else {
            return Err(HelperError::Died {
                stderr: vec!["the helper answered the handshake with something else".into()],
            });
        };
        if identity.protocol != PROTOCOL_VERSION {
            return Err(HelperError::NoCommonProtocol {
                helper: identity.protocol,
                required: PROTOCOL_VERSION,
            });
        }
        for required in [Capability::Types] {
            if !identity.capabilities.contains(&required) {
                return Err(HelperError::MissingRequiredCapability { missing: required });
            }
        }
        self.identity = *identity;
        self.protocol_version = PROTOCOL_VERSION;
        Ok(())
    }

    /// Write a request and return the id it was given.
    fn send(&mut self, body: RequestBody) -> Result<u64, HelperError> {
        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);
        write_frame(
            &mut self.stdin,
            &Request {
                protocol_version: self.protocol_version,
                id,
                body,
            },
        )
        .map_err(|error| self.explain(error))?;
        Ok(id)
    }

    /// Wait for the answer to `expected`, or for the deadline.
    fn receive(&mut self, expected: u64) -> Result<ResponseBody, HelperError> {
        match self.responses.recv_timeout(self.timeout) {
            Ok(Ok(response)) => {
                // Both the handshake and every later response use the one
                // revision this build accepts.
                let valid_revision = if self.identity.name.is_empty() {
                    response.protocol_version == PROTOCOL_VERSION
                } else {
                    response.protocol_version == self.protocol_version
                };
                if !valid_revision {
                    return Err(HelperError::ProtocolMismatch {
                        received: response.protocol_version,
                        expected: self.protocol_version,
                    });
                }
                if response.id == expected {
                    match response.body {
                        ResponseBody::Failed(failure) => Err(HelperError::Refused {
                            code: failure.code,
                            message: failure.message,
                        }),
                        body => Ok(body),
                    }
                } else {
                    Err(HelperError::Mismatched {
                        answered: response.id,
                        expected,
                    })
                }
            }
            Ok(Err(error)) => Err(self.explain(error)),
            Err(RecvTimeoutError::Timeout) => Err(HelperError::TimedOut {
                timeout: self.timeout,
            }),
            Err(RecvTimeoutError::Disconnected) => Err(HelperError::Died {
                stderr: self.diagnostics(),
            }),
        }
    }

    /// Turn a frame failure into the more useful of the two explanations.
    ///
    /// A helper that dies mid-message shows up first as a broken pipe, which
    /// says nothing. What it printed before it went usually says everything, so
    /// a stream failure against a process that has already exited is reported
    /// as the death it was.
    fn explain(&mut self, error: FrameError) -> HelperError {
        if matches!(self.child.try_wait(), Ok(Some(_))) {
            HelperError::Died {
                stderr: self.diagnostics(),
            }
        } else {
            HelperError::Frame(error)
        }
    }
}

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
    /// Units that have already broken a helper once.
    poisoned: BTreeSet<UnitRef>,
    /// Whether a helper has ever been started, which is what tells a first
    /// start apart from a restart.
    started: bool,
    /// Set once restarts run out: the helper is not started again.
    given_up: bool,
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
            restarts: 0,
            helper: None,
            spoke_with: None,
            permitted: Vec::new(),
            poisoned: BTreeSet::new(),
            started: false,
            given_up: false,
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
        self.poisoned.contains(unit)
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
        if self.given_up {
            return Analysis::Missing(Unavailability::HelperDied);
        }
        if self.poisoned.contains(unit) {
            // It broke a helper twice already. Asking again costs another
            // restart and answers nothing new.
            return Analysis::Missing(Unavailability::HelperDied);
        }
        match self.attempt(unit, compile_command, want) {
            Ok(analysis) => analysis,
            Err(first) => {
                if !unavailability(&first).worth_retrying() {
                    return Analysis::Missing(unavailability(&first));
                }
                self.helper = None;
                match self.attempt(unit, compile_command, want) {
                    Ok(analysis) => analysis,
                    Err(second) => {
                        // Twice on the same unit: the unit is what the helper
                        // cannot survive, so it is the unit that is set aside.
                        self.poisoned.insert(unit.clone());
                        self.helper = None;
                        Analysis::Missing(unavailability(&second))
                    }
                }
            }
        }
    }

    /// One attempt, starting the helper if it is not running.
    fn attempt(
        &mut self,
        unit: &UnitRef,
        compile_command: Option<&CompileCommandSelector>,
        want: &[Capability],
    ) -> Result<Analysis, HelperError> {
        if self.helper.is_none() {
            if self.started {
                if self.restarts >= self.max_restarts {
                    self.given_up = true;
                    return Ok(Analysis::Missing(Unavailability::HelperDied));
                }
                self.restarts = self.restarts.saturating_add(1);
            }
            self.started = true;
            let arguments: Vec<&str> = self.args.iter().map(String::as_str).collect();
            let helper =
                Helper::start_with_sandbox(&self.program, &arguments, self.timeout, self.sandbox)
                    .inspect_err(|_| {
                        // A helper that will not start will not start for the next
                        // unit either, so the run stops asking rather than paying a
                        // process spawn per file to be told the same thing.
                        self.given_up = true;
                    })?
                    .permitting(self.permitted.clone());
            self.spoke_with = Some(helper.identity().clone());
            self.helper = Some(helper);
        }
        let Some(helper) = self.helper.as_mut() else {
            return Ok(Analysis::Missing(Unavailability::HelperDied));
        };
        helper.analyze_with_command(unit, compile_command, want)
    }

    /// Stop the helper, if one is running.
    pub fn shutdown(&mut self) {
        if let Some(helper) = self.helper.take() {
            let _ = helper.shutdown();
        }
    }
}

/// The reason a unit has no IR, given how talking to the helper went.
const fn unavailability(error: &HelperError) -> Unavailability {
    match error {
        HelperError::TimedOut { .. } => Unavailability::HelperTimedOut,
        HelperError::NoCommonProtocol { .. }
        | HelperError::MissingRequiredCapability { .. }
        | HelperError::ProtocolMismatch { .. } => Unavailability::ToolchainMismatch,
        _ => Unavailability::HelperDied,
    }
}

impl Drop for Helper {
    fn drop(&mut self) {
        // A helper outliving the run would hold a compiler process open for as
        // long as the scan lives. Whatever state the conversation is in, the
        // process goes.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The identity assumed before the helper has said anything.
const fn unknown_identity() -> HelperIdentity {
    HelperIdentity {
        name: String::new(),
        version: String::new(),
        protocol: PROTOCOL_VERSION,
        toolchains: Vec::new(),
        capabilities: Vec::new(),
        executes: Vec::new(),
    }
}

/// Read frames off the helper's output on a thread.
///
/// The channel is bounded: a helper writing faster than the run reads is made
/// to wait rather than allowed to fill memory with answers nobody has asked
/// for yet.
fn read_responses(
    stdout: Option<std::process::ChildStdout>,
) -> Receiver<Result<Response, FrameError>> {
    let (sender, receiver) = sync_channel(16);
    let Some(mut stdout) = stdout else {
        return receiver;
    };
    std::thread::spawn(move || {
        loop {
            match read_frame(&mut stdout) {
                Ok(Some(response)) => {
                    if sender.send(Ok(response)).is_err() {
                        break;
                    }
                }
                Ok(None) => break,
                Err(error) => {
                    let _ = sender.send(Err(error));
                    break;
                }
            }
        }
    });
    receiver
}

/// Keep the helper's standard error, bounded, on a thread.
fn drain_stderr(stream: std::process::ChildStderr, sink: Arc<Mutex<Vec<String>>>) {
    std::thread::spawn(move || {
        for line in BufReader::new(stream).lines().map_while(Result::ok) {
            // Take the lock for one line and let it go: the helper writing to
            // its standard error must never be what stops a caller from
            // reading what it has written so far.
            let full = {
                let mut kept = sink.lock().unwrap_or_else(PoisonError::into_inner);
                if kept.len() < MAX_DIAGNOSTIC_LINES {
                    kept.push(line);
                }
                kept.len() >= MAX_DIAGNOSTIC_LINES
            };
            if full {
                break;
            }
        }
    });
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::sandbox::SandboxError;

    #[test]
    fn a_configured_path_that_is_not_there_is_not_replaced_by_one_that_is() {
        // Falling back to PATH would silently run a different build than the
        // one the setting names, which is the failure a setting exists to stop.
        let missing = Path::new("/nonexistent/codehelion-backend-rust");
        assert_eq!(locate("codehelion-backend-rust", Some(missing)), None);
    }

    #[test]
    fn a_helper_nobody_has_installed_is_not_found() {
        assert_eq!(locate("codehelion-backend-nothing-at-all", None), None);
    }

    #[test]
    fn a_required_memory_limit_is_rejected_before_starting_the_helper() {
        let error = Helper::start_with_sandbox(
            Path::new("/this/helper/does/not/need/to/exist"),
            &[],
            DEFAULT_TIMEOUT,
            SandboxRequest::require_memory_limit(4096),
        )
        .expect_err("the unavailable memory limit must be reported before spawn");
        assert!(matches!(
            error,
            HelperError::Sandbox(SandboxError::MemoryLimitUnavailable { bytes: 4096 })
        ));
    }
}
