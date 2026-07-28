//! A counter whose width is a build-time decision.

/// The counter's underlying integer, narrow by default.
#[cfg(not(feature = "wide"))]
pub type Count = u32;

/// The counter's underlying integer, widened by the `wide` feature.
#[cfg(feature = "wide")]
pub type Count = u64;

/// Counts how many entries pass the test.
///
/// The body is the same text under either feature; only the type it produces
/// differs. Nothing about the characters here says which.
pub fn tally(values: &[i64], at_least: i64) -> Count {
    let mut count: Count = 0;
    for value in values {
        if *value >= at_least {
            count += 1;
        }
    }
    count
}

/// Whether the tally would overflow the counter.
pub fn would_overflow(values: usize) -> bool {
    Count::try_from(values).is_err()
}
