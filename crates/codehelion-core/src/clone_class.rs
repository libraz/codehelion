//! The clone classification vocabulary, shared by every analysis mode.
//!
//! Classification is a property of a finding, not of the mode that produced
//! it: a verbatim copy is a Type-1 clone whether the Fast engine matched it
//! token-by-token or the Structural verifier scored it across dimensions. One
//! enum for all modes keeps reports, storage and lineage comparable across
//! modes; the names here are the identifiers the store and the JSON reports
//! use.
//!
//! Not every mode produces every class: the Fast engine reports no gapped
//! (Type-3) clones, since it only matches identical normalized content.

/// How closely a clone group's members match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CloneClass {
    /// Verbatim copy (formatting and comments aside).
    Type1,
    /// Copy with consistent renames and/or changed literals.
    Type2,
    /// Similar but not identical: a gapped clone, with inserted, deleted or
    /// modified statements.
    Type3,
}

impl CloneClass {
    /// Stable lowercase identifier used in reports and storage.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Type1 => "type-1",
            Self::Type2 => "type-2",
            Self::Type3 => "type-3",
        }
    }

    /// Whether the class asserts equality rather than resemblance.
    ///
    /// Type-1 and Type-2 both mean the copies agree statement for statement,
    /// verbatim or up to renaming. Type-3 means only that they are alike
    /// overall, and says nothing about any particular stretch.
    #[must_use]
    pub const fn is_exact(self) -> bool {
        matches!(self, Self::Type1 | Self::Type2)
    }
}

/// What the members of a clone group are.
///
/// Orthogonal to [`CloneClass`]: a run of statements duplicated verbatim is a
/// Type-1 clone exactly as a duplicated function is, and the two say different
/// things about the code. A reader has to be able to tell "these functions are
/// copies" from "these functions share a copied stretch", so the distinction
/// is recorded rather than inferred from how the line ranges compare.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CloneScope {
    /// Each member is a whole unit: a function, method, impl block or record.
    Unit,
    /// Each member is a run of statements inside a unit. The enclosing units
    /// need not be clones of each other, and usually are not.
    Fragment,
}

impl CloneScope {
    /// Stable lowercase identifier used in reports and storage.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Unit => "unit",
            Self::Fragment => "fragment",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{CloneClass, CloneScope};

    #[test]
    fn names_are_the_stable_report_identifiers() {
        assert_eq!(CloneClass::Type1.name(), "type-1");
        assert_eq!(CloneClass::Type2.name(), "type-2");
        assert_eq!(CloneClass::Type3.name(), "type-3");
        assert_eq!(CloneScope::Unit.name(), "unit");
        assert_eq!(CloneScope::Fragment.name(), "fragment");
    }

    #[test]
    fn ordering_runs_from_exact_to_gapped() {
        let mut classes = [CloneClass::Type3, CloneClass::Type1, CloneClass::Type2];
        classes.sort_unstable();
        assert_eq!(
            classes,
            [CloneClass::Type1, CloneClass::Type2, CloneClass::Type3]
        );
    }
}
