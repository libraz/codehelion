//! Analysis core: engine-side logic that the CLI layer drives.
//!
//! This module is the in-crate stand-in for the future `codehelion-core`
//! crate. The dependency direction is strictly `cli -> core`: nothing here may
//! reach back into [`crate::cli`]. Keeping the boundary now makes the eventual
//! crate split a move rather than a rewrite.

pub mod doctor;
