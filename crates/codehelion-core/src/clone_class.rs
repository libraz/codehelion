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
}

#[cfg(test)]
mod tests {
    use super::CloneClass;

    #[test]
    fn names_are_the_stable_report_identifiers() {
        assert_eq!(CloneClass::Type1.name(), "type-1");
        assert_eq!(CloneClass::Type2.name(), "type-2");
        assert_eq!(CloneClass::Type3.name(), "type-3");
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
