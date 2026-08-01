//! Versioned messages exchanged with compiler helper processes.
//!
//! This crate contains only the serializable compiler IR and the framed wire
//! protocol. Process supervision, sandboxing, and backend execution live in
//! `codehelion-helper`, so storage and other protocol consumers do not acquire
//! process-management dependencies.

#![doc(html_root_url = "https://docs.rs/codehelion-helper-protocol")]

pub mod ir;
pub mod protocol;

pub use ir::{COMPILER_IR_SCHEMA_VERSION, CompilerIr, Unavailability, UnitRef};
pub use protocol::{
    Absence, BuildDescription, Capability, CompileCommandSelector, Execution, HelperIdentity,
    PROTOCOL_VERSION,
};
