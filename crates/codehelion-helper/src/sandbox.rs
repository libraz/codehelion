//! Honest process-containment capabilities for compiler helpers.
//!
//! The helper protocol already provides a process boundary and the client
//! applies request deadlines. Those properties are useful containment, but
//! they are not an operating-system sandbox: this implementation does not
//! claim to restrict a helper's filesystem or network access. On Linux it can
//! install an address-space ceiling inside the child before that child reads a
//! request. Other platforms refuse that requested policy rather than claiming
//! it was applied.

use std::env;
use std::path::Path;

#[allow(clippy::disallowed_types)]
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, Stdio};

/// Environment variable carrying a parent-requested helper memory ceiling.
///
/// [`spawn`] overwrites or removes this variable for every helper it starts,
/// and helper binaries call [`enforce_current_process_limit_from_environment`]
/// before serving their protocol.
pub const MEMORY_LIMIT_ENV: &str = "CODEHELION_HELPER_MAX_MEMORY_BYTES";

/// A memory ceiling requested for a helper process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SandboxRequest {
    max_memory_bytes: Option<u64>,
}

impl SandboxRequest {
    /// Start a helper without requesting OS-level memory containment.
    #[must_use]
    pub const fn unrestricted() -> Self {
        Self {
            max_memory_bytes: None,
        }
    }

    /// Require the operating system to enforce this helper memory ceiling.
    #[must_use]
    pub const fn require_memory_limit(max_memory_bytes: u64) -> Self {
        Self {
            max_memory_bytes: Some(max_memory_bytes),
        }
    }

    /// The requested memory ceiling, if one is required.
    #[must_use]
    pub const fn max_memory_bytes(self) -> Option<u64> {
        self.max_memory_bytes
    }
}

impl Default for SandboxRequest {
    fn default() -> Self {
        Self::unrestricted()
    }
}

/// What this build can actually contain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SandboxAvailability {
    /// A helper runs in a child process, not inside the scanner process.
    pub process_isolation: bool,
    /// The client stops waiting after its request deadline.
    pub request_timeout: bool,
    /// Whether a requested OS-enforced memory ceiling can be installed.
    pub memory_limit: bool,
}

/// Return the containment properties of this build.
///
#[must_use]
pub const fn availability() -> SandboxAvailability {
    SandboxAvailability {
        process_isolation: true,
        request_timeout: true,
        memory_limit: cfg!(target_os = "linux"),
    }
}

/// Explain the available containment in a doctor-friendly single line.
#[must_use]
pub const fn doctor_summary() -> &'static str {
    if cfg!(target_os = "linux") {
        "sandbox: child-process isolation, request timeouts, and OS memory ceilings available; network and filesystem containment unavailable"
    } else {
        "sandbox: child-process isolation and request timeouts available; OS memory, network, and filesystem containment unavailable"
    }
}

/// Why a requested containment policy could not be applied.
#[derive(Debug, thiserror::Error)]
pub enum SandboxError {
    /// A required memory ceiling cannot be enforced on this build.
    #[error(
        "cannot enforce the requested helper memory limit of {bytes} bytes on this build; \
         OS memory containment is unavailable"
    )]
    MemoryLimitUnavailable {
        /// The ceiling that was required.
        bytes: u64,
    },
    /// The parent supplied an invalid ceiling to a helper child.
    #[error("the requested helper memory limit is not a valid byte count: {value}")]
    InvalidMemoryLimit {
        /// The invalid environment value.
        value: String,
    },
    /// The operating system declined a requested memory ceiling.
    #[error("could not enforce the requested helper memory limit of {bytes} bytes: {reason}")]
    MemoryLimitNotInstalled {
        /// The requested ceiling.
        bytes: u64,
        /// The operating-system error, rendered without losing context.
        reason: String,
    },
    /// The child process could not be started.
    #[error("the helper at {path} could not be started: {source}")]
    NotStarted {
        /// The requested program path.
        path: std::path::PathBuf,
        /// The operating-system error.
        source: std::io::Error,
    },
}

/// Refuse policies this build cannot enforce before starting a helper.
///
/// # Errors
///
/// Returns an error when a required memory ceiling is unavailable.
pub const fn validate(request: SandboxRequest) -> Result<(), SandboxError> {
    if let Some(bytes) = request.max_memory_bytes()
        && !availability().memory_limit
    {
        return Err(SandboxError::MemoryLimitUnavailable { bytes });
    }
    Ok(())
}

/// Install an address-space ceiling in the current process.
///
/// Helper binaries call this before reading any protocol input. Artifact
/// workers use the same operation before parsing untrusted artifact bytes.
///
/// # Errors
///
/// Returns an error when this platform cannot enforce the ceiling or the
/// operating system rejects it.
#[cfg(target_os = "linux")]
pub fn enforce_current_process_memory_limit(max_memory_bytes: u64) -> Result<(), SandboxError> {
    use nix::sys::resource::{Resource, rlim_t, setrlimit};

    let limit = rlim_t::try_from(max_memory_bytes).map_err(|error| {
        SandboxError::MemoryLimitNotInstalled {
            bytes: max_memory_bytes,
            reason: error.to_string(),
        }
    })?;
    setrlimit(Resource::RLIMIT_AS, limit, limit).map_err(|error| {
        SandboxError::MemoryLimitNotInstalled {
            bytes: max_memory_bytes,
            reason: error.to_string(),
        }
    })
}

/// Install an address-space ceiling in the current process.
///
/// # Errors
///
/// Always reports that the requested ceiling is unavailable on this platform.
#[cfg(not(target_os = "linux"))]
pub const fn enforce_current_process_memory_limit(
    max_memory_bytes: u64,
) -> Result<(), SandboxError> {
    Err(SandboxError::MemoryLimitUnavailable {
        bytes: max_memory_bytes,
    })
}

/// Apply the parent-requested memory ceiling, if any, before serving a helper.
///
/// # Errors
///
/// Returns an error if the value cannot be parsed or cannot be enforced.
pub fn enforce_current_process_limit_from_environment() -> Result<(), SandboxError> {
    let Some(value) = env::var_os(MEMORY_LIMIT_ENV) else {
        return Ok(());
    };
    let value = value.to_string_lossy().into_owned();
    let max_memory_bytes = value
        .parse::<u64>()
        .map_err(|_| SandboxError::InvalidMemoryLimit {
            value: value.clone(),
        })?;
    enforce_current_process_memory_limit(max_memory_bytes)
}

/// Start a helper after enforcing the requested containment policy.
///
/// # Errors
///
/// Returns an error if required containment is unavailable or the process
/// cannot be started.
pub fn spawn(
    path: &Path,
    args: &[&str],
    request: SandboxRequest,
) -> Result<HelperProcess, SandboxError> {
    validate(request)?;
    #[allow(clippy::disallowed_types)]
    let mut command = Command::new(path);
    command
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    configure_child_memory_limit(&mut command, request);
    configure_child_process_group(&mut command);
    command
        .spawn()
        .map(HelperProcess::new)
        .map_err(|source| SandboxError::NotStarted {
            path: path.to_path_buf(),
            source,
        })
}

/// A running helper, and the one termination it is owed.
///
/// A signal is addressed to a number, and that number names the process it was
/// given to only until the process is reaped: afterwards the operating system
/// is free to hand it to something else. So whether the child has been waited
/// for travels with the child, and every path that would signal it asks first.
/// That is what keeps the drop following an explicit shutdown from killing a
/// stranger's process group.
#[derive(Debug)]
pub struct HelperProcess {
    #[allow(clippy::disallowed_types)]
    child: Child,
    /// Set once the child has been waited for and its number released.
    reaped: bool,
}

impl HelperProcess {
    /// Take ownership of a started helper.
    #[must_use]
    #[allow(clippy::disallowed_types)]
    pub const fn new(child: Child) -> Self {
        Self {
            child,
            reaped: false,
        }
    }

    /// Take the pipe requests are written to.
    pub const fn take_stdin(&mut self) -> Option<ChildStdin> {
        self.child.stdin.take()
    }

    /// Take the pipe responses are read from.
    pub const fn take_stdout(&mut self) -> Option<ChildStdout> {
        self.child.stdout.take()
    }

    /// Take the pipe diagnostics are read from.
    pub const fn take_stderr(&mut self) -> Option<ChildStderr> {
        self.child.stderr.take()
    }

    /// The process group [`Self::terminate`] would signal.
    ///
    /// `None` once the child has been reaped, because the number then names
    /// whatever the operating system has handed it to since.
    #[must_use]
    pub fn signal_target(&self) -> Option<u32> {
        (!self.reaped).then(|| self.child.id())
    }

    /// Terminate the helper and every compiler process in its dedicated group.
    ///
    /// Does nothing once the child has been reaped.
    pub fn terminate(&mut self) {
        let Some(group) = self.signal_target() else {
            return;
        };
        signal_process_group(group);
        let _ = self.child.kill();
    }

    /// Wait for the helper to go, releasing its number.
    pub fn wait(&mut self) {
        if self.reaped {
            return;
        }
        let _ = self.child.wait();
        self.reaped = true;
    }

    /// Whether the helper has already exited.
    ///
    /// Asking reaps a child that has, so this also ends the life of its
    /// number: nothing may signal the process after this has answered `true`.
    pub fn has_exited(&mut self) -> bool {
        if self.reaped {
            return true;
        }
        if matches!(self.child.try_wait(), Ok(Some(_))) {
            self.reaped = true;
        }
        self.reaped
    }
}

/// Put the helper in a separate process group so its compiler descendants can
/// be terminated with it after a request deadline.
#[cfg(unix)]
#[allow(clippy::disallowed_types)]
fn configure_child_process_group(command: &mut Command) {
    use std::os::unix::process::CommandExt;

    command.process_group(0);
}

/// Process groups are unavailable on this platform; the direct child remains
/// the best containment boundary available to the caller.
#[cfg(not(unix))]
#[allow(clippy::disallowed_types)]
const fn configure_child_process_group(_command: &mut Command) {}

/// Kill everything in the group a live helper leads.
#[cfg(unix)]
fn signal_process_group(group: u32) {
    use nix::sys::signal::{Signal, kill};
    use nix::unistd::Pid;

    if let Ok(pid) = i32::try_from(group) {
        let _ = kill(Pid::from_raw(-pid), Signal::SIGKILL);
    }
}

/// Process groups are unavailable on this platform; killing the direct child
/// remains the best containment the caller has.
#[cfg(not(unix))]
const fn signal_process_group(_group: u32) {}

/// Put the requested limit in the child environment, never inheriting an
/// unrelated value from the scanner's own environment.
#[allow(clippy::disallowed_types)]
fn configure_child_memory_limit(command: &mut Command, request: SandboxRequest) {
    if let Some(max_memory_bytes) = request.max_memory_bytes() {
        command.env(MEMORY_LIMIT_ENV, max_memory_bytes.to_string());
    } else {
        command.env_remove(MEMORY_LIMIT_ENV);
    }
}

#[cfg(test)]
#[allow(clippy::disallowed_types, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn terminating_a_helper_kills_its_whole_process_group() {
        use std::thread;
        use std::time::{Duration, Instant};

        use nix::errno::Errno;
        use nix::sys::signal::kill;
        use nix::unistd::Pid;

        let mut helper = spawn(
            Path::new("/bin/sh"),
            &["-c", "sleep 30 & wait"],
            SandboxRequest::unrestricted(),
        )
        .expect("start helper with compiler-like background child");
        let group = i32::try_from(helper.signal_target().expect("a live helper has a group"))
            .expect("process id fits pid_t");

        helper.terminate();
        helper.wait();

        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            match kill(Pid::from_raw(-group), None) {
                Err(Errno::ESRCH) => break,
                Ok(()) | Err(_) if Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(10));
                }
                Ok(()) => panic!("compiler descendant process group survived termination"),
                Err(error) => panic!("checking helper process group failed: {error}"),
            }
        }
    }

    /// A number identifies a process only while that process exists. Once a
    /// helper has been waited for, nothing this owns may be aimed at its
    /// number again — not the drop that follows an explicit shutdown, and not
    /// a second termination of any other kind.
    #[cfg(unix)]
    #[test]
    fn a_reaped_helper_is_never_signalled_again() {
        let mut helper = spawn(
            Path::new("/bin/sh"),
            &["-c", "exit 0"],
            SandboxRequest::unrestricted(),
        )
        .expect("start a helper that ends on its own");
        assert!(helper.signal_target().is_some());

        helper.wait();
        assert_eq!(
            helper.signal_target(),
            None,
            "a reaped helper still names a signal target"
        );
        // The termination a drop would run after a shutdown: it must find
        // nothing to aim at rather than aim at a reused number.
        helper.terminate();
        assert_eq!(helper.signal_target(), None);
    }

    /// Asking whether a helper has gone reaps it when it has, so that question
    /// ends the life of its number as surely as waiting for it does.
    #[cfg(unix)]
    #[test]
    fn a_helper_found_to_have_exited_is_no_longer_a_signal_target() {
        use std::thread;
        use std::time::{Duration, Instant};

        let mut helper = spawn(
            Path::new("/bin/sh"),
            &["-c", "exit 0"],
            SandboxRequest::unrestricted(),
        )
        .expect("start a helper that ends on its own");
        let deadline = Instant::now() + Duration::from_secs(5);
        while !helper.has_exited() {
            assert!(Instant::now() < deadline, "the helper never exited");
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(helper.signal_target(), None);
    }

    #[test]
    fn unrestricted_helpers_are_supported_on_the_portable_backend() {
        assert!(validate(SandboxRequest::unrestricted()).is_ok());
        let available = availability();
        assert!(available.process_isolation);
        assert!(available.request_timeout);
    }

    #[test]
    #[cfg(not(target_os = "linux"))]
    fn a_required_memory_limit_is_refused_instead_of_ignored() {
        let error = validate(SandboxRequest::require_memory_limit(4096))
            .expect_err("portable backend must not claim an unenforced limit");
        assert!(matches!(
            error,
            SandboxError::MemoryLimitUnavailable { bytes: 4096 }
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_required_memory_limit_is_available_on_linux() {
        assert!(availability().memory_limit);
        assert!(validate(SandboxRequest::require_memory_limit(4096)).is_ok());
    }

    #[test]
    fn child_environment_carries_only_the_requested_memory_limit() {
        let mut limited = Command::new("helper");
        configure_child_memory_limit(&mut limited, SandboxRequest::require_memory_limit(4_096));
        let value = limited
            .get_envs()
            .find(|(name, _)| *name == MEMORY_LIMIT_ENV)
            .and_then(|(_, value)| value)
            .expect("requested limit is passed to the child");
        assert_eq!(value, "4096");

        let mut unrestricted = Command::new("helper");
        unrestricted.env(MEMORY_LIMIT_ENV, "inherited value");
        configure_child_memory_limit(&mut unrestricted, SandboxRequest::unrestricted());
        let value = unrestricted
            .get_envs()
            .find(|(name, _)| *name == MEMORY_LIMIT_ENV)
            .expect("the inherited setting is explicitly removed")
            .1;
        assert_eq!(value, None);
    }
}
