//! Why talking to a helper did not work, and what that means for a unit.

use std::time::Duration;

use crate::ir::Unavailability;
use crate::protocol::{Capability, FrameError, HelperIdentity, PROTOCOL_VERSION};
use crate::sandbox::SandboxError;

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

/// The reason a unit has no IR, given how talking to the helper went.
///
/// A refusal is not a crash. The helper received the request, understood it,
/// and answered that it would not handle it — a restart puts the same question
/// to the same program, so it is classified as something a retry cannot change.
pub(super) const fn unavailability(error: &HelperError) -> Unavailability {
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
/// bounded by [`super::io::drain_stderr`]. Everything else is rendered, because
/// a reason that reaches a report as a bare name tells somebody that something
/// is wrong and nothing about which thing.
pub(super) fn explanation(error: &HelperError) -> Vec<String> {
    match error {
        // Its own rendering repeats these lines, so they are reported as the
        // helper wrote them rather than folded into one sentence.
        HelperError::Died { stderr } => stderr.clone(),
        other => vec![other.to_string()],
    }
}

/// The identity assumed before the helper has said anything.
pub(super) const fn unknown_identity() -> HelperIdentity {
    HelperIdentity {
        name: String::new(),
        version: String::new(),
        protocol: PROTOCOL_VERSION,
        toolchains: Vec::new(),
        capabilities: Vec::new(),
        executes: Vec::new(),
    }
}
