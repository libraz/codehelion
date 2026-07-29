//! Calls whose target is settled in four different ways.
//!
//! Every call below is written so that a reader can say, without running
//! anything, whether the body it reaches is decided here or somewhere else.

/// Something with a size.
pub trait Measured {
    /// The size, which every implementation decides for itself.
    fn extent(&self) -> i64;

    /// Twice the size. Nothing here overrides it, so this body is the one
    /// every implementation gets.
    fn doubled(&self) -> i64 {
        self.extent() * 2
    }
}

/// A span between two points.
pub struct Segment {
    /// Where it starts.
    pub from: i64,
    /// Where it ends.
    pub to: i64,
}

impl Segment {
    /// An inherent method: one definition, reached without a trait.
    pub fn width(&self) -> i64 {
        self.to - self.from
    }
}

impl Measured for Segment {
    fn extent(&self) -> i64 {
        self.width()
    }
}

/// A count of things.
pub struct Tally {
    /// How many.
    pub items: i64,
}

impl Measured for Tally {
    fn extent(&self) -> i64 {
        self.items
    }
}

/// A concrete receiver. `extent` reaches the implementation written for
/// `Segment`; `doubled` reaches the trait's own body, because nothing
/// overrides it. Both are one body, known from here.
pub fn concrete(segment: &Segment) -> i64 {
    segment.extent() + segment.doubled()
}

/// A type parameter. Which body runs is decided where this is instantiated,
/// which is not here.
pub fn generic<T: Measured>(subject: &T) -> i64 {
    subject.extent()
}

/// A trait object. Which body runs is decided while the program runs.
pub fn erased(subject: &dyn Measured) -> i64 {
    subject.extent()
}

/// Calling a value rather than a name. There is no definition to point at.
pub fn indirect(measure: impl Fn(i64) -> i64) -> i64 {
    measure(3)
}
