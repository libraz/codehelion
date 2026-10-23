//! Versioned messages exchanged with compiler helper processes.
//!
//! This crate contains only the serializable compiler IR, the framed wire
//! protocol, the reading of the compilation-database entry both sides of
//! that protocol name a translation unit by, and the one bounded reader every
//! side uses for a file the scanned tree supplies. Process supervision, sandboxing,
//! and backend execution live in
//! `codehelion-helper`, so storage and other protocol consumers do not acquire
//! process-management dependencies.

#![doc(html_root_url = "https://docs.rs/codehelion-helper-protocol")]

pub mod compile_commands;
pub mod ir;
pub mod protocol;
pub mod tree_file;

pub use compile_commands::{RecordedCommand, split_command};
pub use ir::{COMPILER_IR_SCHEMA_VERSION, CompilerIr, Unavailability, UnitRef};
pub use protocol::{
    Absence, BuildDescription, Capability, CompilationDatabase, CompileCommandSelector, Execution,
    HelperIdentity, PROTOCOL_VERSION,
};
