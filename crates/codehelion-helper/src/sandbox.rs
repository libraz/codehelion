//! Honest process-containment capabilities for compiler helpers.
//!
//! The helper protocol already provides a process boundary and the client
//! applies request deadlines. Those properties are useful containment, but
//! they are not an operating-system sandbox: this portable implementation does
//! not claim to restrict a helper's filesystem or network access, and it does
//! not pretend that a requested memory limit was installed when it was not.

use std::path::Path;

#[allow(clippy::disallowed_types)]
use std::process::{Child, Command, Stdio};

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
/// Platform-specific limit mechanisms require OS APIs that this crate does not
/// call. Until an implementation can enforce a limit on every advertised
/// platform, reporting it unavailable is safer than silently running bare.
#[must_use]
pub const fn availability() -> SandboxAvailability {
    SandboxAvailability {
        process_isolation: true,
        request_timeout: true,
        memory_limit: false,
    }
}

/// Explain the available containment in a doctor-friendly single line.
#[must_use]
pub const fn doctor_summary() -> &'static str {
    "sandbox: child-process isolation and request timeouts available; OS memory, network, and filesystem containment unavailable"
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

/// Start a helper after enforcing the requested portable policy.
///
/// # Errors
///
/// Returns an error if required containment is unavailable or the process
/// cannot be started.
pub fn spawn(path: &Path, args: &[&str], request: SandboxRequest) -> Result<Child, SandboxError> {
    validate(request)?;
    #[allow(clippy::disallowed_types)]
    Command::new(path)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|source| SandboxError::NotStarted {
            path: path.to_path_buf(),
            source,
        })
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn unrestricted_helpers_are_supported_on_the_portable_backend() {
        assert!(validate(SandboxRequest::unrestricted()).is_ok());
        let available = availability();
        assert!(available.process_isolation);
        assert!(available.request_timeout);
    }

    #[test]
    fn a_required_memory_limit_is_refused_instead_of_ignored() {
        let error = validate(SandboxRequest::require_memory_limit(4096))
            .expect_err("portable backend must not claim an unenforced limit");
        assert!(matches!(
            error,
            SandboxError::MemoryLimitUnavailable { bytes: 4096 }
        ));
    }
}
