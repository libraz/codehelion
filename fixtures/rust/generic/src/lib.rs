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

/// A standard optional branch that restricted semantic normalization may name.
pub fn retain_positive(value: Option<i64>) -> Option<i64> {
    match value {
        Some(value) if value > 0 => Some(value),
        _ => None,
    }
}

/// A direct standard optional-presence branch for semantic normalization.
pub fn retain_present(value: Option<i64>) -> bool {
    if value.is_some() {
        true
    } else {
        false
    }
}

/// A compound optional condition remains outside the closed normalizer.
pub fn retain_present_with_flag(value: Option<i64>, keep: bool) -> bool {
    if value.is_some() && keep {
        true
    } else {
        false
    }
}

/// A direct standard result-presence branch for semantic normalization.
pub fn retain_success(value: Result<i64, ()>) -> bool {
    if value.is_ok() {
        true
    } else {
        false
    }
}

/// A compound result condition remains outside the closed normalizer.
pub fn retain_success_with_flag(value: Result<i64, ()>, keep: bool) -> bool {
    if value.is_ok() && keep {
        true
    } else {
        false
    }
}

/// A standard error branch that restricted semantic normalization may name.
pub fn preserve_result(value: Result<i64, ()>) -> Result<i64, ()> {
    match value {
        Ok(value) => Ok(value),
        Err(error) => Err(error),
    }
}

/// A direct `Result` adapter using the propagation operator.
pub fn propagate_result(value: Result<i64, ()>) -> Result<i64, ()> {
    Ok(value?)
}

/// An error propagation whose success value is deliberately transformed.
pub fn transform_result(value: Result<i64, ()>) -> Result<i64, ()> {
    let value = value?;
    Ok(value.saturating_add(1))
}

/// A project-defined enum must not be mistaken for fallible control flow.
pub enum Direction {
    /// Move forward.
    Forward,
    /// Move backward.
    Backward,
}

/// Use an ordinary enum in a branch as the negative control.
pub fn reverse(direction: Direction) -> Direction {
    match direction {
        Direction::Forward => Direction::Backward,
        Direction::Backward => Direction::Forward,
    }
}

/// Materialize a sequence with the narrow explicit-loop shape recognized by
/// restricted semantic normalization.
pub fn collect_loop(values: Vec<i64>) -> Vec<i64> {
    let mut collected = Vec::new();
    for value in values {
        collected.push(value);
    }
    collected
}

/// The iterator spelling corresponding to [`collect_loop`].
pub fn collect_pipeline(values: Vec<i64>) -> Vec<i64> {
    values.into_iter().collect()
}

/// A loop that looks similar but transforms the value, so it is outside the
/// plain-collection normalizer.
pub fn collect_transformed(values: Vec<i64>) -> Vec<i64> {
    let mut collected = Vec::new();
    for value in values {
        collected.push(value.saturating_add(1));
    }
    collected
}
