//! Writes a table the crate cannot be compiled without — and, next to it, a
//! marker recording that this program ran.
//!
//! The marker is the whole reason the fixture exists. "The target's code was
//! not executed" is not observable from a scan's output, because a scan that
//! declined to run this and a scan that ran it and ignored the result look the
//! same from outside. A file that only this program writes makes the two
//! distinguishable: its absence after a scan is evidence, and its presence is
//! a failure with a name.

use std::io::Write;

fn main() {
    // Next to the manifest rather than in OUT_DIR: a test should be able to
    // look for it without reconstructing cargo's target layout, and cargo
    // removes OUT_DIR contents on rebuilds.
    let marker = concat!(env!("CARGO_MANIFEST_DIR"), "/build-script-ran.marker");
    if let Ok(mut file) = std::fs::File::create(marker) {
        let _ = writeln!(file, "the build script of this fixture was executed");
    }

    let out = std::env::var("OUT_DIR").unwrap_or_else(|_| ".".to_string());
    let table = std::path::Path::new(&out).join("table.rs");
    let _ = std::fs::write(&table, "pub const SIZES: [u32; 3] = [1, 2, 4];\n");
    println!("cargo:rerun-if-changed=build.rs");
}
