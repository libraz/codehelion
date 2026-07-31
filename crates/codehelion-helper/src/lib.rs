//! The process boundary between codehelion and a compiler.
//!
//! Semantic analysis wants what a compiler knows — resolved types, call
//! targets, which template a body was instantiated from — and getting it means
//! depending on compiler internals, which are unstable by construction: a
//! rustc release moves them, and a Clang release moves different ones. Linking
//! that into the analysis crates would make the whole tool only as buildable as
//! the newest compiler it has been taught about.
//!
//! So it is not linked. Each compiler lives behind its own program, and this
//! crate is the only thing the two sides share: a wire format
//! ([`protocol`]) and the code that runs one of those programs
//! ([`client`]). The analysis crates know a message shape and nothing about
//! any compiler; a helper knows the same message shape and one compiler.
//!
//! What that buys is not only buildability. A helper can be absent, be built
//! for a compiler the project does not use, take forever, or die, and the run
//! goes on and says what it did not get — none of which is available to a
//! design where the compiler is a library call.

#![doc(html_root_url = "https://docs.rs/codehelion-helper")]

pub mod client;
pub mod effects;
pub mod ir;
pub mod protocol;
pub mod sandbox;
pub mod server;

pub use client::{Analysis, DEFAULT_TIMEOUT, Helper, HelperError, Supervisor, locate};
pub use ir::{COMPILER_IR_SCHEMA_VERSION, CompilerIr, Unavailability, UnitRef};
pub use protocol::{
    Absence, BuildDescription, Capability, CompileCommandSelector, Execution, HelperIdentity,
    PROTOCOL_VERSION,
};
pub use sandbox::{
    SandboxAvailability, SandboxError, SandboxRequest, availability, doctor_summary,
};
pub use server::{Answer, Backend, Description, serve};
