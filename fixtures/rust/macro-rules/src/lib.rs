//! One macro written once and invoked twice, beside the same shape written
//! out by hand.
//!
//! The two invocations produce bodies that are identical in every respect a
//! textual reading can see. Nobody wrote them twice, and nobody can delete one
//! of them, which is why what came out of a macro has to be distinguishable
//! from what somebody typed.

/// Declares a counter type and the one method that reads it.
macro_rules! counter {
    ($name:ident) => {
        /// Something counted.
        pub struct $name {
            /// How many.
            pub count: i64,
        }

        impl $name {
            /// The count, read back.
            pub fn count(&self) -> i64 {
                self.count
            }
        }
    };
}

counter!(Reads);

counter!(Writes);

/// Calls the counter method from expansion syntax rather than from a call
/// expression written in the source file.
macro_rules! count_from_expansion {
    ($counter:expr) => {
        $counter.count()
    };
}

/// A call whose target exists only after expanding `count_from_expansion!`.
pub fn expanded_call(reads: &Reads) -> i64 {
    count_from_expansion!(reads)
}

/// The same shape, written out. This one somebody did type.
pub struct Manual {
    /// How many.
    pub count: i64,
}

impl Manual {
    /// The count, read back.
    pub fn count(&self) -> i64 {
        self.count
    }
}
