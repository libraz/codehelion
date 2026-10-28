//! Name stems: the part of a symbol name that template arguments, closure
//! numbering and parameter lists do not change.
//!
//! A stem runs up to the first parameterized path component, so a function
//! template groups by function, a class template by class instance, and a
//! closure by its enclosing function. Grouping is exact equality of the stem
//! string, an equivalence relation, not similarity.

/// The stem of one symbol name and the instance spelling it was taken from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameStem {
    /// Grouping key: the path up to its first parameterized component, with
    /// template arguments written `<>` and closures `{closure}`; no parameter
    /// list, return type, or toolchain decoration.
    pub stem: String,
    /// The same prefix with the arguments kept (for a name with no
    /// parameterized component, the whole normalized name).
    pub instance: String,
    /// Whether a component was erased to form the stem.
    pub parameterized: bool,
}
