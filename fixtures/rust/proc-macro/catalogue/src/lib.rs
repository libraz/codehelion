//! Types whose most interesting method appears in no source file.

use labelled_derive::Labelled;

/// A shelf of things.
#[derive(Labelled)]
pub struct Shelf {
    /// How many fit.
    pub capacity: u32,
}

/// A crate of things.
#[derive(Labelled)]
pub struct Crate {
    /// How many fit.
    pub capacity: u32,
}

/// Describes both, using methods that only exist after expansion.
pub fn describe(shelf: &Shelf, packing: &Crate) -> String {
    format!(
        "{} holds {}, {} holds {}",
        shelf.label(),
        shelf.capacity,
        packing.label(),
        packing.capacity
    )
}
