//! The Rust compiler helper: one program, one compiler, one protocol.
//!
//! codehelion never links a compiler. This program does, and talks to the tool
//! over the length-prefixed protocol in `codehelion-helper` — so a compiler
//! that will not build, will not start, or takes forever costs a scan its
//! semantic answers and nothing else.
//!
//! It analyses with the compiler it carries rather than the one the project
//! builds with, and says so at the handshake: the toolchain it reports is its
//! own, and what a negotiation settles is whether it can read a project rather
//! than whether it matches one.
//!
//! It runs nothing out of the project. See [`analysis`] for why that is a
//! property of the code rather than of a setting.

// In a binary crate the two visibility lints disagree: `unreachable_pub` wants
// items in these modules to be `pub(crate)`, and `redundant_pub_crate` wants
// them to be `pub` because the modules are private. Nothing here is reachable
// from outside the program either way, so one of them has to give.
#![allow(clippy::redundant_pub_crate)]

mod analysis;
mod calls;
mod expansions;
mod instantiations;
mod occurrences;
mod types;

use codehelion_helper::PROTOCOL_VERSION;
use codehelion_helper::ir::COMPILER_IR_SCHEMA_VERSION;
use codehelion_helper::protocol::{Analyze, Capability, HelperIdentity, VersionRange};
use codehelion_helper::server::{Answer, Backend, serve};

use crate::analysis::{Outcome, Workspaces};

/// The name this helper is known by, in `doctor` and in the audit database.
const NAME: &str = "codehelion-backend-rust";

fn main() -> std::process::ExitCode {
    let mut backend = RustBackend::default();
    let mut input = std::io::stdin().lock();
    let mut output = std::io::stdout().lock();
    match serve(&mut backend, &mut input, &mut output) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            // Standard error, because standard output is the protocol: a
            // diagnostic written there would be read as a malformed frame. The
            // client collects this stream and reports it, which is usually the
            // only sentence explaining why a helper stopped.
            eprintln!("{NAME}: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

/// Everything this process has read, and what it will answer.
#[derive(Default)]
struct RustBackend {
    workspaces: Workspaces,
}

impl Backend for RustBackend {
    fn identity(&self) -> HelperIdentity {
        HelperIdentity {
            name: NAME.to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            protocol: VersionRange::exactly(PROTOCOL_VERSION),
            // The compiler that will answer, which is this program's own. A
            // project built with a different one can still be analysed; what
            // cannot happen is this being mistaken for the project's compiler.
            toolchains: vec![format!("rust-analyzer {}", RA_VERSION)],
            // Only what is implemented. A capability listed here is a promise,
            // and a helper that claims call targets and returns none is worse
            // than one that never claimed them: the run would stop recording
            // that it did not get any.
            capabilities: vec![
                Capability::Types,
                Capability::NameResolution,
                Capability::CallTargets,
                Capability::MacroExpansion,
                Capability::TemplateInstantiation,
            ],
        }
    }

    fn analyze(&mut self, request: &Analyze) -> Answer {
        match self.workspaces.analyze(&request.unit) {
            Outcome::Analyzed(mut ir) => {
                ir.schema_version = COMPILER_IR_SCHEMA_VERSION.to_string();
                Answer::Analyzed(ir)
            }
            Outcome::Unavailable(reason) => Answer::Unavailable(reason),
        }
    }
}

/// The analysis library's version, which is the compiler's version here.
const RA_VERSION: &str = "0.0.344";
