//! Analysis core for codehelion: engine-side logic that the CLI layer drives.
//!
//! This is the engine layer of the workspace. The dependency direction is
//! strictly `cli -> core`: nothing here may reach back into the CLI, the store
//! or any frontend crate. Keeping the boundary at the crate level makes it
//! mechanically enforceable.

pub mod candidate;
pub mod clone_class;
pub mod discovery;
pub mod doctor;
pub mod engine;
pub mod features;
pub mod frontend;
pub mod grouping;
pub mod ir;
pub mod near_match;
pub mod stable_id;
pub mod structural;
pub mod verify;
