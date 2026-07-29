//! One generic body used at two types, beside a body that is not generic.
//!
//! A generic is written once and stamped out per set of type arguments. The
//! stamps are the same text with a substitution, so reporting them as separate
//! bodies would count one thing several times — and reporting nothing at all
//! would lose the reason a binary carries several copies of it.
//!
//! The non-generic function at the end is the control: nothing about it is
//! stamped out, so an analysis that attributes an instantiation to it is
//! attributing one to every call in the crate.

/// The one body. Every call to this is a stamp of this text.
pub fn widest<T: Ord + Copy>(values: &[T]) -> Option<T> {
    let mut best = *values.first()?;
    for value in values {
        if *value > best {
            best = *value;
        }
    }
    Some(best)
}

/// A pair whose halves are the same type, whatever that type is.
pub struct Pair<T> {
    /// One half.
    pub left: T,
    /// The other.
    pub right: T,
}

/// One stamp of `widest`.
pub fn longest(spans: &[i64]) -> Option<i64> {
    widest(spans)
}

/// Another stamp of the same body, at a different type.
pub fn largest(counts: &[u32]) -> Option<u32> {
    widest(counts)
}

/// One stamp of `Pair`.
pub fn span() -> Pair<i64> {
    Pair { left: 0, right: 1 }
}

/// A body written out rather than stamped. Nothing here is instantiated.
pub fn total(values: &[i64]) -> i64 {
    let mut sum = 0;
    for value in values {
        sum += *value;
    }
    sum
}
