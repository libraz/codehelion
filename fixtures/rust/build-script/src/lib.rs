//! A crate that cannot be understood without running its build script.
//!
//! `SIZES` is written by `build.rs`, so a helper that refuses to run build
//! scripts cannot resolve `largest`'s body. The right answer is to say the
//! crate requires execution — not to guess, and not to report a resolved type
//! it never obtained.

include!(concat!(env!("OUT_DIR"), "/table.rs"));

/// The largest generated size.
pub fn largest() -> u32 {
    SIZES.iter().copied().max().unwrap_or(0)
}
