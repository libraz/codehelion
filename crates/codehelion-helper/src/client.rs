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

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, TrySendError, sync_channel};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use crate::ir::{CompilerIr, Unavailability, UnitRef};
use crate::protocol::{
    Absence, Analyze, BuildDescription, Capability, ClientIdentity, CompileCommandSelector,
    DescribeBuild, Execution, FrameError, HelperIdentity, PROTOCOL_VERSION, Request, RequestBody,
    Response, ResponseBody, read_frame, write_frame,
};
use crate::sandbox::{HelperProcess, SandboxError, SandboxRequest, spawn};

/// How long a request waits before the helper is treated as unresponsive.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);

/// Longest time shutdown waits for an acknowledgement before killing a helper.
///
/// A shutdown follows completed work, so an unresponsive helper has already
/// spent its useful time. Letting cleanup consume the full analysis deadline
/// turns each hung helper into a second timeout.
const SHUTDOWN_ACK_TIMEOUT: Duration = Duration::from_millis(250);

/// Lines of helper standard error kept for diagnostics.
///
/// Enough to carry a compiler's complaint and a backtrace, bounded so a helper
/// looping on a warning cannot grow this without limit. The bound applies to
/// what has not been reported yet rather than to the whole process: one helper
/// answers about many units, and a ceiling on its lifetime output would spend
/// itself on the first few and leave every later unit with no explanation.
pub const MAX_DIAGNOSTIC_LINES: usize = 256;

/// Helper standard error that has not been reported yet, and what did not fit.
///
/// The count is kept rather than the lines: a run that drops an explanation has
/// to say so, because diagnostics that end silently read exactly like a helper
/// that had nothing more to say.
#[derive(Debug, Default)]
struct Diagnostics {
    /// Lines collected since the last time they were handed out.
    kept: Vec<String>,
    /// Lines the ceiling left out over the same span.
    dropped: usize,
}

impl Diagnostics {
    /// Keep `line` if there is room, and count it if there is not.
    fn push(&mut self, line: String) {
        if self.kept.len() < MAX_DIAGNOSTIC_LINES {
            self.kept.push(line);
        } else {
            self.dropped = self.dropped.saturating_add(1);
        }
    }

    /// What has been collected, without consuming it.
    fn peek(&self) -> Vec<String> {
        bounded(self.kept.clone(), self.dropped)
    }

    /// What has been collected, leaving the next span empty.
    fn take(&mut self) -> Vec<String> {
        let dropped = std::mem::take(&mut self.dropped);
        bounded(std::mem::take(&mut self.kept), dropped)
    }
}

/// Cut `lines` to the ceiling, ending with a note for what a limit left out.
///
/// `already_dropped` lines were discarded before this point. The note is part
/// of the ceiling rather than an extra line past it, so what a caller receives
/// is bounded whether or not anything was left out.
fn bounded(mut lines: Vec<String>, already_dropped: usize) -> Vec<String> {
    let mut dropped = already_dropped;
    if lines.len().saturating_add(usize::from(dropped > 0)) > MAX_DIAGNOSTIC_LINES {
        let room = MAX_DIAGNOSTIC_LINES.saturating_sub(1);
        dropped = dropped.saturating_add(lines.len().saturating_sub(room));
        lines.truncate(room);
    }
    if dropped > 0 {
        lines.push(format!(
            "{dropped} further line(s) the helper printed were not kept"
        ));
    }
    lines
}

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
    /// A timeout left an unread response that makes this conversation unsafe.
    #[error("the helper conversation timed out and cannot be reused; start a new helper")]
    PoisonedAfterTimeout,
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

/// Who chose where a helper is looked for.
///
/// Starting a program is not something a location alone may decide, so every
/// configured location arrives with the answer to this question attached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HelperAuthority {
    /// An operator: a command line, or a configuration file the caller named.
    Operator,
    /// The tree under analysis, through a configuration file found inside it.
    Scanned,
}

/// Where a helper was configured to be, together with who said so.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfiguredHelper<'a> {
    /// The configured location.
    pub path: &'a Path,
    /// Who chose it.
    pub authority: HelperAuthority,
}

impl<'a> ConfiguredHelper<'a> {
    /// A location an operator chose.
    #[must_use]
    pub const fn operator(path: &'a Path) -> Self {
        Self {
            path,
            authority: HelperAuthority::Operator,
        }
    }

    /// A location the tree under analysis supplied.
    #[must_use]
    pub const fn scanned(path: &'a Path) -> Self {
        Self {
            path,
            authority: HelperAuthority::Scanned,
        }
    }
}

/// Where to look for a helper, in the order the search tries.
///
/// An operator's configured path is tried first. The plan for this search put
/// configuration last, which is the wrong way round: a setting that loses to
/// whatever happens to be on `PATH` cannot be used to pin a helper, which is
/// the only reason to write one down.
///
/// A location the scanned tree supplied is passed over as though it had not
/// been written, and the search goes on beside this executable and along
/// `PATH`. Following it would let a repository name the program that a scan of
/// it starts, and there is no confining such a path the way a storage path is
/// confined — a program inside the tree is exactly what it would name. Passing
/// it over rather than refusing keeps the repository from choosing the helper
/// and from denying the run one.
#[must_use]
pub fn locate(name: &str, configured: Option<ConfiguredHelper<'_>>) -> Option<PathBuf> {
    if let Some(configured) = configured
        && configured.authority == HelperAuthority::Operator
    {
        return configured
            .path
            .is_file()
            .then(|| configured.path.to_path_buf());
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
    child: HelperProcess,
    requests: SyncSender<Outgoing>,
    responses: Receiver<Result<Response, FrameError>>,
    stderr: Arc<Mutex<Diagnostics>>,
    identity: HelperIdentity,
    protocol_version: u32,
    timeout: Duration,
    next_id: u64,
    /// Set after a response deadline expires, because the late response may
    /// still be waiting in the channel for a later request.
    poisoned_after_timeout: bool,
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

        let Some(stdin) = child.take_stdin() else {
            return Err(HelperError::Died {
                stderr: vec!["the helper was started without a standard input".into()],
            });
        };
        let stderr = Arc::new(Mutex::new(Diagnostics::default()));
        if let Some(stream) = child.take_stderr() {
            drain_stderr(stream, Arc::clone(&stderr));
        }
        let responses = read_responses(child.take_stdout());
        let requests = write_requests(stdin);

        let mut helper = Self {
            child,
            requests,
            responses,
            stderr,
            identity: unknown_identity(),
            // The handshake uses the one protocol revision this build speaks.
            protocol_version: PROTOCOL_VERSION,
            timeout,
            next_id: 0,
            poisoned_after_timeout: false,
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

    /// What the helper has printed on standard error and nobody has taken.
    ///
    /// Ends with a line counting whatever the ceiling left out, so a caller is
    /// never handed a shortened explanation that looks complete.
    #[must_use]
    pub fn diagnostics(&self) -> Vec<String> {
        self.stderr
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .peek()
    }

    /// What the helper has printed on standard error since this was last asked.
    ///
    /// One helper answers about many units, and what it printed while refusing
    /// one of them explains that one. Read whole every time, the same sentence
    /// would be attached to every unit that came after it, which reads as a
    /// project where everything went wrong for the same reason.
    #[must_use]
    pub fn recent_diagnostics(&mut self) -> Vec<String> {
        self.stderr
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
    }

    /// Whether a timeout made this helper conversation unsafe to reuse.
    #[must_use]
    pub const fn is_poisoned_after_timeout(&self) -> bool {
        self.poisoned_after_timeout
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
        if self.poisoned_after_timeout {
            self.child.terminate();
            self.child.wait();
            return Ok(());
        }
        let ack = self.timeout.min(SHUTDOWN_ACK_TIMEOUT);
        let id = match self.send_within(RequestBody::Shutdown, ack) {
            Ok(id) => id,
            Err(HelperError::TimedOut { .. }) => {
                // It has stopped reading, so asking is over. It leaves the way
                // a helper that will not leave always does.
                self.child.terminate();
                self.child.wait();
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        match self.receive_with_timeout(id, ack) {
            Ok(ResponseBody::Shutdown) | Err(HelperError::Died { .. }) => {}
            Ok(_) | Err(_) => {
                self.child.terminate();
            }
        }
        self.child.wait();
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
    /// or answers something other than what was asked. After a timeout, this
    /// helper is poisoned and further calls return
    /// [`HelperError::PoisonedAfterTimeout`]; start a new helper instead.
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
        self.analyze_with_command_and_boundary(unit, compile_command, None, want)
    }

    /// Ask for one unit's compiler IR while confining compiler reads.
    ///
    /// `read_boundary` is sent only for an untrusted scan. It is a canonical
    /// directory supplied by the caller, not a helper-discovered project root.
    ///
    /// # Errors
    ///
    /// Returns an error when the helper cannot be contacted or cannot return a
    /// readable answer.
    pub fn analyze_with_command_and_boundary(
        &mut self,
        unit: &UnitRef,
        compile_command: Option<&CompileCommandSelector>,
        read_boundary: Option<&Path>,
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
            read_boundary: read_boundary.map(|boundary| boundary.display().to_string()),
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
        for capability in Capability::ALL {
            if capability.absence() == Absence::Refuse
                && !identity.capabilities.contains(&capability)
            {
                return Err(HelperError::MissingRequiredCapability {
                    missing: capability,
                });
            }
        }
        self.identity = *identity;
        self.protocol_version = PROTOCOL_VERSION;
        Ok(())
    }

    /// Write a request and return the id it was given.
    fn send(&mut self, body: RequestBody) -> Result<u64, HelperError> {
        self.send_within(body, self.timeout)
    }

    /// Write a request subject to one operation's deadline.
    ///
    /// A request larger than the pipe's buffer is only written as fast as the
    /// helper reads it, so a helper that has stopped reading blocks the writer
    /// exactly as a helper that has stopped answering blocks the reader. Both
    /// therefore happen away from the caller and are collected with a deadline.
    fn send_within(&mut self, body: RequestBody, timeout: Duration) -> Result<u64, HelperError> {
        if self.poisoned_after_timeout {
            return Err(HelperError::PoisonedAfterTimeout);
        }
        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);
        let request = Request {
            protocol_version: self.protocol_version,
            id,
            body,
        };
        match deliver(&self.requests, request, timeout) {
            Ok(()) => Ok(id),
            Err(Delivery::Timeout) => {
                // Part of a frame may already be in the pipe, so what the
                // helper reads next is not a message either side can name.
                self.poisoned_after_timeout = true;
                Err(HelperError::TimedOut { timeout })
            }
            Err(Delivery::Failed(error)) => Err(self.explain(error)),
        }
    }

    /// Wait for the answer to `expected`, or for the deadline.
    fn receive(&mut self, expected: u64) -> Result<ResponseBody, HelperError> {
        self.receive_with_timeout(expected, self.timeout)
    }

    /// Wait for the answer to `expected`, subject to one operation's deadline.
    fn receive_with_timeout(
        &mut self,
        expected: u64,
        timeout: Duration,
    ) -> Result<ResponseBody, HelperError> {
        match self.responses.recv_timeout(timeout) {
            Ok(Ok(response)) => {
                // The handshake is exempt, and it is the only message that is:
                // it is how two peers find out what they can say to each other,
                // so refusing it for arriving in an unknown revision would make
                // a difference in revisions undiscoverable by either side.
                // `shake_hands` compares the revision it announces instead, and
                // names both.
                let settled = !matches!(response.body, ResponseBody::Handshake(_));
                if settled && response.protocol_version != self.protocol_version {
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
            Err(RecvTimeoutError::Timeout) => {
                self.poisoned_after_timeout = true;
                Err(HelperError::TimedOut { timeout })
            }
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
        if matches!(error, FrameError::Io(_)) && self.child.has_exited() {
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

    /// Keep what the helper printed while refusing a unit it answered about.
    ///
    /// A helper that says a unit is unavailable has usually said why on its
    /// standard error, and that sentence is the whole difference between a
    /// report somebody can act on and a count of a reason's name.
    fn keep_what_was_said_about(&mut self, analysis: &Analysis) {
        let Some(helper) = self.helper.as_mut() else {
            return;
        };
        let said = helper.recent_diagnostics();
        if matches!(analysis, Analysis::Missing(_)) {
            self.diagnostics = said;
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
                        diagnostics: self.diagnostics.clone(),
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

/// The reason a unit has no IR, given how talking to the helper went.
///
/// A refusal is not a crash. The helper received the request, understood it,
/// and answered that it would not handle it — a restart puts the same question
/// to the same program, so it is classified as something a retry cannot change.
const fn unavailability(error: &HelperError) -> Unavailability {
    match error {
        HelperError::TimedOut { .. } => Unavailability::HelperTimedOut,
        HelperError::NoCommonProtocol { .. }
        | HelperError::MissingRequiredCapability { .. }
        | HelperError::ProtocolMismatch { .. } => Unavailability::ToolchainMismatch,
        HelperError::Refused { .. } => Unavailability::NotSupported,
        _ => Unavailability::HelperDied,
    }
}

/// What a failure says for itself, in sentences.
///
/// A helper's collected standard error is kept as it was printed, already
/// bounded by [`drain_stderr`]. Everything else is rendered, because a reason
/// that reaches a report as a bare name tells somebody that something is wrong
/// and nothing about which thing.
fn explanation(error: &HelperError) -> Vec<String> {
    match error {
        // Its own rendering repeats these lines, so they are reported as the
        // helper wrote them rather than folded into one sentence.
        HelperError::Died { stderr } => stderr.clone(),
        other => vec![other.to_string()],
    }
}

impl Drop for Helper {
    fn drop(&mut self) {
        // A helper outliving the run would hold a compiler process open for as
        // long as the scan lives. Whatever state the conversation is in, the
        // process goes — unless it has already gone, in which case both of
        // these are the no-ops that keep its number out of a signal.
        self.child.terminate();
        self.child.wait();
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

/// One request on its way to the helper, with where its outcome goes.
#[derive(Debug)]
struct Outgoing {
    /// The frame to write.
    request: Request,
    /// Where the writer reports whether the frame reached the helper.
    outcome: SyncSender<Result<(), FrameError>>,
}

/// How handing a request to the writer can fail.
#[derive(Debug)]
enum Delivery {
    /// The deadline passed with the request still unwritten.
    Timeout,
    /// The stream refused it.
    Failed(FrameError),
}

/// Write requests to the helper on a thread.
///
/// The writer is a thread for the same reason the reader is: a pipe write
/// blocks until the peer reads, and a helper that has stopped reading would
/// otherwise hold the run inside a call that cannot be given a deadline.
fn write_requests<W: Write + Send + 'static>(mut stdin: W) -> SyncSender<Outgoing> {
    let (sender, receiver) = sync_channel::<Outgoing>(1);
    std::thread::spawn(move || {
        while let Ok(outgoing) = receiver.recv() {
            let result = write_frame(&mut stdin, &outgoing.request);
            let failed = result.is_err();
            let _ = outgoing.outcome.send(result);
            if failed {
                // The stream is no longer one whole frames can be written to,
                // so the pipe closes here rather than carrying half a message.
                break;
            }
        }
    });
    sender
}

/// Hand `request` to the writer and wait, no longer than `timeout`, for it to
/// reach the helper.
fn deliver(
    requests: &SyncSender<Outgoing>,
    request: Request,
    timeout: Duration,
) -> Result<(), Delivery> {
    let started = Instant::now();
    let (outcome, written) = sync_channel(1);
    match requests.try_send(Outgoing { request, outcome }) {
        Ok(()) => {}
        // One request is outstanding at a time, so a full queue means the
        // writer is still on a frame whose deadline has already passed.
        Err(TrySendError::Full(_)) => return Err(Delivery::Timeout),
        Err(TrySendError::Disconnected(_)) => return Err(Delivery::Failed(broken_pipe())),
    }
    match written.recv_timeout(timeout.saturating_sub(started.elapsed())) {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(Delivery::Failed(error)),
        Err(RecvTimeoutError::Timeout) => Err(Delivery::Timeout),
        Err(RecvTimeoutError::Disconnected) => Err(Delivery::Failed(broken_pipe())),
    }
}

/// The stream failure a writer that has gone leaves behind.
fn broken_pipe() -> FrameError {
    FrameError::Io(std::io::Error::new(
        std::io::ErrorKind::BrokenPipe,
        "the helper's standard input was closed",
    ))
}

/// Keep the helper's standard error, bounded, on a thread.
fn drain_stderr(stream: std::process::ChildStderr, sink: Arc<Mutex<Diagnostics>>) {
    std::thread::spawn(move || {
        collect_stderr(BufReader::new(stream), &sink);
    });
}

/// Read all of one helper stderr stream while retaining the bounded prefix of
/// each span between two reads.
fn collect_stderr(reader: impl BufRead, sink: &Arc<Mutex<Diagnostics>>) {
    for line in reader.lines().map_while(Result::ok) {
        // Take the lock for one line and let it go: the helper writing to
        // its standard error must never be what stops a caller from
        // reading what it has written so far.
        sink.lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(line);
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::sandbox::SandboxError;

    #[test]
    fn stderr_drain_keeps_its_prefix_and_consumes_the_remaining_lines() {
        use std::fmt::Write as _;

        let mut input = String::new();
        for line in 0..=MAX_DIAGNOSTIC_LINES {
            writeln!(input, "line-{line}").unwrap();
        }
        let sink = Arc::new(Mutex::new(Diagnostics::default()));
        collect_stderr(std::io::Cursor::new(input), &sink);
        let kept = sink.lock().unwrap().peek();
        assert_eq!(kept.len(), MAX_DIAGNOSTIC_LINES);
        assert_eq!(kept.first().map(String::as_str), Some("line-0"));
        let expected_last = format!("line-{}", MAX_DIAGNOSTIC_LINES - 2);
        assert_eq!(
            kept.get(MAX_DIAGNOSTIC_LINES - 2).map(String::as_str),
            Some(expected_last.as_str())
        );
    }

    #[test]
    fn lines_a_ceiling_left_out_are_counted_where_the_kept_ones_are_reported() {
        use std::fmt::Write as _;

        let overshoot = 7;
        let mut input = String::new();
        for line in 0..MAX_DIAGNOSTIC_LINES + overshoot {
            writeln!(input, "line-{line}").unwrap();
        }
        let sink = Arc::new(Mutex::new(Diagnostics::default()));
        collect_stderr(std::io::Cursor::new(input), &sink);

        let reported = sink.lock().unwrap().take();
        assert_eq!(reported.len(), MAX_DIAGNOSTIC_LINES);
        // One kept line gives up its place to the note that accounts for the
        // rest, so the count names every line that was not kept.
        let expected = format!("{} further line(s)", overshoot + 1);
        let note = reported.last().cloned().unwrap_or_default();
        assert!(note.contains(&expected), "{note}");
    }

    #[test]
    fn what_one_unit_was_refused_for_is_not_spent_by_the_units_before_it() {
        // A helper explaining every unit it refuses prints far more lines over
        // its life than any one report may carry. Each unit's reasons must
        // still be its own, however many units came first.
        let sink = Arc::new(Mutex::new(Diagnostics::default()));
        let units = MAX_DIAGNOSTIC_LINES * 2;
        for unit in 0..units {
            sink.lock().unwrap().push(format!("refused unit-{unit}"));
            let reported = sink.lock().unwrap().take();
            assert_eq!(reported, vec![format!("refused unit-{unit}")]);
        }
    }

    #[test]
    fn a_span_that_was_read_starts_the_next_one_empty() {
        let sink = Arc::new(Mutex::new(Diagnostics::default()));
        sink.lock().unwrap().push("first".to_string());
        assert_eq!(sink.lock().unwrap().take(), vec!["first".to_string()]);
        assert!(sink.lock().unwrap().take().is_empty());
        assert!(sink.lock().unwrap().peek().is_empty());
    }

    /// A stream that accepts nothing, the way a pipe behaves once the peer at
    /// the other end has stopped reading it.
    struct NeverAccepts;

    impl Write for NeverAccepts {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            std::thread::sleep(Duration::from_secs(30));
            Ok(buffer.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn shutdown_request() -> Request {
        Request {
            protocol_version: PROTOCOL_VERSION,
            id: 0,
            body: RequestBody::Shutdown,
        }
    }

    #[test]
    fn a_request_a_helper_will_not_read_gives_up_on_its_deadline() {
        let deadline = Duration::from_millis(200);
        let requests = write_requests(NeverAccepts);

        let started = Instant::now();
        let outcome = deliver(&requests, shutdown_request(), deadline);
        let waited = started.elapsed();

        assert!(matches!(outcome, Err(Delivery::Timeout)), "{outcome:?}");
        assert!(
            waited < Duration::from_secs(5),
            "the write waited {waited:?} on a {deadline:?} deadline"
        );
    }

    #[test]
    fn a_request_a_helper_reads_completes_rather_than_waiting_out_its_deadline() {
        let requests = write_requests(std::io::sink());

        let started = Instant::now();
        let outcome = deliver(&requests, shutdown_request(), Duration::from_secs(30));

        assert!(outcome.is_ok(), "{outcome:?}");
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn a_configured_path_that_is_not_there_is_not_replaced_by_one_that_is() {
        // Falling back to PATH would silently run a different build than the
        // one the setting names, which is the failure a setting exists to stop.
        let missing = Path::new("/nonexistent/codehelion-backend-rust");
        assert_eq!(
            locate(
                "codehelion-backend-rust",
                Some(ConfiguredHelper::operator(missing))
            ),
            None
        );
    }

    #[test]
    fn a_helper_nobody_has_installed_is_not_found() {
        assert_eq!(locate("codehelion-backend-nothing-at-all", None), None);
    }

    #[test]
    fn a_program_the_scanned_tree_named_is_never_where_a_helper_is_looked_for() {
        // One file that certainly exists, offered by each of the two
        // authorities: who chose it, not whether it is there, is what decides.
        let present = std::env::current_exe().expect("this test is a file on disk");
        assert_eq!(
            locate(
                "codehelion-backend-nothing-at-all",
                Some(ConfiguredHelper::operator(&present))
            ),
            Some(present.clone())
        );
        assert_eq!(
            locate(
                "codehelion-backend-nothing-at-all",
                Some(ConfiguredHelper::scanned(&present))
            ),
            None
        );
    }

    #[cfg(not(target_os = "linux"))]
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

    #[cfg(target_os = "linux")]
    #[test]
    fn an_enforceable_memory_limit_reaches_process_startup() {
        let error = Helper::start_with_sandbox(
            Path::new("/this/helper/does/not/need/to/exist"),
            &[],
            DEFAULT_TIMEOUT,
            SandboxRequest::require_memory_limit(4096),
        )
        .expect_err("the nonexistent program must fail at startup");
        assert!(matches!(
            error,
            HelperError::Sandbox(SandboxError::NotStarted { .. })
        ));
    }
}
