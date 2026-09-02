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
//! helper's standard error is drained the whole time and kept, because a helper
//! that dies explains itself there or nowhere, and what it said is lost the
//! moment the process is reaped.
//!
//! What that stream is not is a way to explain one unit. It is drained by its
//! own thread and has no order against the answers, so a sentence written just
//! before an answer went out reaches this side at no fixed time: read after the
//! next request, it describes a unit it has nothing to do with. A helper that
//! has something to say about the unit it is answering puts it in that answer.

mod diagnostics;
mod error;
mod io;
mod locate;
mod supervisor;

use std::path::Path;
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use crate::ir::{Unavailability, UnitRef};
use crate::protocol::{
    Absence, Analyze, BuildDescription, Capability, ClientIdentity, CompileCommandSelector,
    DescribeBuild, Execution, FrameError, HelperIdentity, PROTOCOL_VERSION, Request, RequestBody,
    Response, ResponseBody,
};
use crate::sandbox::{HelperProcess, SandboxRequest, spawn};

use diagnostics::Diagnostics;
use io::{Delivery, Outgoing, deliver, drain_stderr, read_responses, write_requests};

pub use error::HelperError;
pub use locate::{ConfiguredHelper, HelperAuthority, locate};
pub use supervisor::{Analysis, DEFAULT_MAX_RESTARTS, Supervisor};

use error::unknown_identity;

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
    /// What the most recent answer said about the unit it was about.
    ///
    /// Kept apart from [`Self::stderr`] because it arrives with the answer:
    /// there is no order between an answer and the standard error stream, so a
    /// sentence taken from that stream belongs to whichever unit was being
    /// asked about when it happened to be delivered, which under load is not
    /// the unit it explains.
    answer_diagnostics: Vec<String>,
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
            answer_diagnostics: Vec::new(),
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
    ///
    /// Draining is what keeps that from happening, and it is why this is called
    /// after every unit rather than only after a refused one. It is not,
    /// however, enough to make what it returns belong to the unit just
    /// answered: see [`Self::take_answer_diagnostics`].
    #[must_use]
    pub fn recent_diagnostics(&mut self) -> Vec<String> {
        self.stderr
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
    }

    /// What the most recent answer said about the unit it was about.
    ///
    /// This is the explanation a report can rely on. The helper put it in the
    /// answer, so it arrived with the answer and is about that unit; what the
    /// same helper printed on standard error arrives on a stream with no order
    /// against the answers, and under load reaches the client after the unit it
    /// explains has already been reported.
    ///
    /// Empty from a helper that puts nothing in its answers, which is the older
    /// behaviour and leaves the standard error stream as the only source.
    #[must_use]
    pub fn take_answer_diagnostics(&mut self) -> Vec<String> {
        std::mem::take(&mut self.answer_diagnostics)
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
            ResponseBody::Unavailable {
                reason,
                diagnostics,
                ..
            } => {
                self.answer_diagnostics = diagnostics;
                Ok(Analysis::Missing(reason))
            }
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

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::sandbox::SandboxError;

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
