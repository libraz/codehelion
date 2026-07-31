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
    /// A correspondence justified only by one or more registered semantic
    /// rules, never by a general equivalence claim.
    RestrictedSemantic,
}

impl CloneClass {
    /// Stable lowercase identifier used in reports and storage.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Type1 => "type-1",
            Self::Type2 => "type-2",
            Self::Type3 => "type-3",
            Self::RestrictedSemantic => "restricted-semantic",
        }
    }

    /// Read back a classification written by [`Self::name`].
    ///
    /// `None` for anything else, including a name a newer release writes:
    /// guessing which class an unknown one resembles would put a finding in a
    /// category the tool that recorded it did not choose.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "type-1" => Some(Self::Type1),
            "type-2" => Some(Self::Type2),
            "type-3" => Some(Self::Type3),
            "restricted-semantic" => Some(Self::RestrictedSemantic),
            _ => None,
        }
    }

    /// Whether the class asserts equality rather than resemblance.
    ///
    /// Type-1 and Type-2 both mean the copies agree statement for statement,
    /// verbatim or up to renaming. Type-3 and restricted semantic findings
    /// are explainable correspondences, not claims of textual equality.
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

    /// Read back a scope written by [`Self::name`], or `None` for anything
    /// else.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "unit" => Some(Self::Unit),
            "fragment" => Some(Self::Fragment),
            _ => None,
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
        assert_eq!(CloneClass::RestrictedSemantic.name(), "restricted-semantic");
        assert_eq!(CloneScope::Unit.name(), "unit");
        assert_eq!(CloneScope::Fragment.name(), "fragment");
    }

    #[test]
    fn a_recorded_name_reads_back_as_what_wrote_it() {
        for class in [
            CloneClass::Type1,
            CloneClass::Type2,
            CloneClass::Type3,
            CloneClass::RestrictedSemantic,
        ] {
            assert_eq!(CloneClass::from_name(class.name()), Some(class));
        }
        for scope in [CloneScope::Unit, CloneScope::Fragment] {
            assert_eq!(CloneScope::from_name(scope.name()), Some(scope));
        }
        // A name this release does not know stays unknown rather than being
        // rounded to the nearest one it does.
        assert_eq!(CloneClass::from_name("type-4"), None);
        assert_eq!(CloneScope::from_name("statement"), None);
    }

    #[test]
    fn ordering_runs_from_exact_to_gapped() {
        let mut classes = [
            CloneClass::RestrictedSemantic,
            CloneClass::Type3,
            CloneClass::Type1,
            CloneClass::Type2,
        ];
        classes.sort_unstable();
        assert_eq!(
            classes,
            [
                CloneClass::Type1,
                CloneClass::Type2,
                CloneClass::Type3,
                CloneClass::RestrictedSemantic,
            ]
        );
    }
}
