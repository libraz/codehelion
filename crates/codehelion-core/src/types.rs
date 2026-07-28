//! Type evidence: what a compiler knows about a unit's types, in the form the
//! verifier compares.
//!
//! Structural mode resolves no types, so the type dimension of a similarity
//! breakdown is absent rather than zero. When something *can* resolve them —
//! a compiler helper — the dimension becomes available, and this is the shape
//! it arrives in.
//!
//! The vocabulary is stated here rather than taken from the helper protocol on
//! purpose. This crate compares programs and must not link a compiler or the
//! code that runs one; the protocol crate says what a compiler can report.
//! Two vocabularies that happen to agree, with a conversion where they meet,
//! is what keeps the boundary a boundary — and it is also what makes the
//! dimension's input replaceable, since anything that can produce these tags
//! can supply the evidence without this crate learning where it came from.
//!
//! [`TypeTag`] is deliberately coarse for the reason the protocol's own
//! category is: two languages do not agree on what a type *is*, and comparing
//! spelled type names compares vocabularies rather than programs. What
//! survives translation is the shape.

use std::collections::BTreeMap;

/// The normalized kind of a type, coarse enough to mean the same thing in
/// every language this tool reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TypeTag {
    /// Any integer width or signedness.
    Integer,
    /// Any floating-point width.
    Float,
    /// A boolean.
    Boolean,
    /// A character or code point.
    Character,
    /// A string or string slice.
    Text,
    /// A raw pointer or a reference.
    Handle,
    /// A contiguous sequence: array, slice, vector.
    Sequence,
    /// An associative container.
    Mapping,
    /// A fixed heterogeneous group: tuple, pair.
    Tuple,
    /// A record with named fields.
    Record,
    /// A closed set of alternatives.
    Enumeration,
    /// An interface: trait, abstract base, concept.
    Interface,
    /// Something callable: function, method, closure.
    Callable,
    /// A type parameter not yet substituted.
    Parameter,
    /// The absence of a value: unit, void.
    Nothing,
}

impl TypeTag {
    /// Stable lowercase identifier.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Integer => "integer",
            Self::Float => "float",
            Self::Boolean => "boolean",
            Self::Character => "character",
            Self::Text => "text",
            Self::Handle => "handle",
            Self::Sequence => "sequence",
            Self::Mapping => "mapping",
            Self::Tuple => "tuple",
            Self::Record => "record",
            Self::Enumeration => "enumeration",
            Self::Interface => "interface",
            Self::Callable => "callable",
            Self::Parameter => "parameter",
            Self::Nothing => "nothing",
        }
    }

    /// The tag a compiler's category name maps to, or `None` for a category
    /// that carries no evidence.
    ///
    /// A type the compiler could not resolve maps to nothing: it is the
    /// compiler saying it does not know, and counting it would let two units
    /// full of unresolved types agree perfectly about nothing. An unrecognised
    /// name maps to nothing for the same reason — a newer helper's category is
    /// a fact this build cannot compare, not a fact it can compare as equal.
    #[must_use]
    pub fn from_category(name: &str) -> Option<Self> {
        match name {
            "integer" => Some(Self::Integer),
            "float" => Some(Self::Float),
            "boolean" => Some(Self::Boolean),
            "character" => Some(Self::Character),
            "text" => Some(Self::Text),
            "handle" => Some(Self::Handle),
            "sequence" => Some(Self::Sequence),
            "mapping" => Some(Self::Mapping),
            "tuple" => Some(Self::Tuple),
            "record" => Some(Self::Record),
            "enumeration" => Some(Self::Enumeration),
            "interface" => Some(Self::Interface),
            "callable" => Some(Self::Callable),
            "parameter" => Some(Self::Parameter),
            "nothing" => Some(Self::Nothing),
            _ => None,
        }
    }
}

/// The types a compiler resolved inside one unit, as counts per tag.
///
/// Counts rather than a set: a unit that works over one map and twenty
/// integers is doing something different from one that works over twenty maps
/// and one integer, and a set of the tags present cannot tell them apart.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TypeEvidence {
    counts: BTreeMap<TypeTag, u32>,
    total: u32,
}

impl TypeEvidence {
    /// Collect evidence from the tags of every typed thing in a unit, one tag
    /// per occurrence.
    #[must_use]
    pub fn from_tags(tags: impl IntoIterator<Item = TypeTag>) -> Self {
        let mut evidence = Self::default();
        for tag in tags {
            *evidence.counts.entry(tag).or_default() += 1;
            evidence.total += 1;
        }
        evidence
    }

    /// Whether nothing typed was resolved here.
    ///
    /// True both for a unit with no typed things in it and for one whose types
    /// a compiler could not resolve; from the comparison's side those are the
    /// same, because neither can support a claim about agreement.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.total == 0
    }

    /// How many resolved types this evidence covers.
    #[must_use]
    pub const fn len(&self) -> u32 {
        self.total
    }

    /// Agreement with `other`, or `None` when neither side resolved anything.
    ///
    /// Shared count over total count, which is the set Jaccard the call-surface
    /// dimension uses, extended to keep multiplicity. `None` rather than `1.0`
    /// for two empty sides: agreeing about nothing is not agreement, and
    /// reporting it as perfect would hand the dimension's full weight to a pair
    /// no compiler said anything about.
    #[must_use]
    pub fn agreement(&self, other: &Self) -> Option<f64> {
        if self.is_empty() && other.is_empty() {
            return None;
        }
        let mut shared = 0_u64;
        for (tag, count) in &self.counts {
            shared += u64::from(*count.min(other.counts.get(tag).unwrap_or(&0)));
        }
        let total = u64::from(self.total) + u64::from(other.total) - shared;
        if total == 0 {
            return Some(1.0);
        }
        #[allow(clippy::cast_precision_loss)]
        Some(shared as f64 / total as f64)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn evidence(tags: &[TypeTag]) -> TypeEvidence {
        TypeEvidence::from_tags(tags.iter().copied())
    }

    #[test]
    fn the_same_types_in_the_same_numbers_agree_completely() {
        let a = evidence(&[TypeTag::Integer, TypeTag::Integer, TypeTag::Text]);
        let b = evidence(&[TypeTag::Text, TypeTag::Integer, TypeTag::Integer]);
        assert_eq!(a.agreement(&b), Some(1.0));
    }

    /// The counts are the point: two units over the same two tags in opposite
    /// proportions are not doing the same thing, and a set of tags says they
    /// are.
    #[test]
    fn the_proportions_are_compared_and_not_only_the_tags_present() {
        let mostly_numbers = evidence(&[
            TypeTag::Integer,
            TypeTag::Integer,
            TypeTag::Integer,
            TypeTag::Mapping,
        ]);
        let mostly_maps = evidence(&[
            TypeTag::Mapping,
            TypeTag::Mapping,
            TypeTag::Mapping,
            TypeTag::Integer,
        ]);
        let agreement = mostly_numbers.agreement(&mostly_maps).unwrap();
        assert!(agreement < 0.5, "{agreement}");
        // The same tags are present in both, so a set comparison would call
        // this a perfect match.
        assert_eq!(
            evidence(&[TypeTag::Integer, TypeTag::Mapping])
                .agreement(&evidence(&[TypeTag::Mapping, TypeTag::Integer])),
            Some(1.0)
        );
    }

    #[test]
    fn nothing_in_common_is_no_agreement() {
        let a = evidence(&[TypeTag::Integer]);
        let b = evidence(&[TypeTag::Mapping]);
        assert_eq!(a.agreement(&b), Some(0.0));
    }

    /// Two units nobody resolved anything for have no dimension, not a perfect
    /// one; the difference decides whether the pair is scored on evidence or on
    /// its absence.
    #[test]
    fn two_units_with_no_resolved_types_have_no_dimension() {
        assert_eq!(
            TypeEvidence::default().agreement(&TypeEvidence::default()),
            None
        );
        // One side having evidence is a real, and low, agreement.
        assert_eq!(
            evidence(&[TypeTag::Integer]).agreement(&TypeEvidence::default()),
            Some(0.0)
        );
    }

    /// A type the compiler could not resolve is the compiler saying it does not
    /// know. Counting it would let two units full of unknowns agree perfectly.
    #[test]
    fn an_unresolved_type_is_not_evidence() {
        assert_eq!(TypeTag::from_category("unresolved"), None);
        assert_eq!(TypeTag::from_category("something-newer"), None);
        assert_eq!(TypeTag::from_category("mapping"), Some(TypeTag::Mapping));
    }

    #[test]
    fn every_tag_has_a_name_that_maps_back() {
        for tag in [
            TypeTag::Integer,
            TypeTag::Float,
            TypeTag::Boolean,
            TypeTag::Character,
            TypeTag::Text,
            TypeTag::Handle,
            TypeTag::Sequence,
            TypeTag::Mapping,
            TypeTag::Tuple,
            TypeTag::Record,
            TypeTag::Enumeration,
            TypeTag::Interface,
            TypeTag::Callable,
            TypeTag::Parameter,
            TypeTag::Nothing,
        ] {
            assert_eq!(TypeTag::from_category(tag.name()), Some(tag), "{tag:?}");
        }
    }
}
