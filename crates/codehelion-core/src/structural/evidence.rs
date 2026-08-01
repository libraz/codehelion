use super::{ApiEvidence, ByteRange, TypeEvidence, TypeTag, Unit};

/// Whether a parsed token count reaches the configured report floor.
///
/// Counts wider than the configuration representation can only be above the
/// floor, so a narrowing failure is a positive result rather than a wrapped
/// comparison.
pub(super) fn token_count_meets_minimum(token_count: usize, minimum: u32) -> bool {
    u32::try_from(token_count).map_or(true, |count| count >= minimum)
}

/// Whether an analysed unit is long enough to enter clone verification.
pub(super) fn unit_meets_minimum(unit: &Unit, minimum: u32) -> bool {
    token_count_meets_minimum(unit.tokens.1.saturating_sub(unit.tokens.0), minimum)
}

/// What a compiler resolved about the files being analysed.
///
/// Held per file and anchored at bytes, because that is what a compiler
/// answers about: it reports the types it resolved where they were written,
/// and which unit a byte belongs to is this crate's own reading of the tree.
/// The two are matched here rather than by whoever asked the compiler, so that
/// a caller cannot attribute a type to a unit this crate never saw.
#[derive(Debug, Clone, Default)]
pub struct ResolvedTypes {
    per_file: Vec<Vec<(ByteRange, TypeTag)>>,
    apis_per_file: Vec<Vec<(ByteRange, String)>>,
}

impl ResolvedTypes {
    /// Collect what was resolved in each file, indexed as the files are.
    ///
    /// A file nobody asked about contributes an empty list, which is the same
    /// to a comparison as a file whose types nobody could resolve: neither
    /// supports a claim about agreement.
    #[must_use]
    pub fn per_file(mut per_file: Vec<Vec<(ByteRange, TypeTag)>>) -> Self {
        for file in &mut per_file {
            file.sort_by_key(|(range, _)| (range.start, range.end));
        }
        Self {
            per_file,
            apis_per_file: Vec::new(),
        }
    }

    /// Collect types and compiler-resolved call targets by file.
    ///
    /// Target strings are opaque stable symbols or canonical candidate-set
    /// keys. They cross the compiler boundary as data, never as compiler API
    /// types, preserving the core's helper independence.
    #[must_use]
    pub fn per_file_with_apis(
        mut per_file: Vec<Vec<(ByteRange, TypeTag)>>,
        mut apis_per_file: Vec<Vec<(ByteRange, String)>>,
    ) -> Self {
        for file in &mut per_file {
            file.sort_by_key(|(range, _)| (range.start, range.end));
        }
        for file in &mut apis_per_file {
            file.sort_by_key(|(range, _)| (range.start, range.end));
        }
        Self {
            per_file,
            apis_per_file,
        }
    }

    /// Whether no type or call target was resolved anywhere.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.per_file.iter().all(Vec::is_empty) && self.apis_per_file.iter().all(Vec::is_empty)
    }

    /// The evidence for one unit: everything resolved within its bytes.
    ///
    /// `None` when nothing was, so that a unit no compiler spoke about is
    /// compared as one nobody measured rather than as one measured to hold no
    /// types.
    pub(super) fn within(&self, unit: &Unit) -> Option<TypeEvidence> {
        let file = self.per_file.get(unit.file)?;
        let from = file.partition_point(|(range, _)| range.start < unit.range.start);
        let tags = file[from..]
            .iter()
            .take_while(|(range, _)| range.start < unit.range.end)
            .filter(|(range, _)| range.end <= unit.range.end)
            .map(|(_, tag)| *tag);
        let evidence = TypeEvidence::from_tags(tags);
        (!evidence.is_empty()).then_some(evidence)
    }

    /// Compiler-resolved call targets whose source anchors sit within `unit`.
    pub(super) fn apis_within(&self, unit: &Unit) -> Option<ApiEvidence> {
        let file = self.apis_per_file.get(unit.file)?;
        let from = file.partition_point(|(range, _)| range.start < unit.range.start);
        let targets = file[from..]
            .iter()
            .take_while(|(range, _)| range.start < unit.range.end)
            .filter(|(range, _)| range.end <= unit.range.end)
            .map(|(_, target)| target.clone());
        let evidence = ApiEvidence::from_targets(targets);
        (!evidence.is_empty()).then_some(evidence)
    }
}

/// Compiler evidence attributed to each parsed unit.
///
/// Keeping the parallel dimensions together ensures every verification path
/// receives the same byte-to-unit attribution without growing its argument
/// list whenever Semantic mode learns another comparison fact.
pub(super) struct UnitEvidence {
    pub(super) types: Vec<Option<TypeEvidence>>,
    pub(super) apis: Vec<Option<ApiEvidence>>,
}

pub(super) fn unit_evidence(units: &[Unit], resolved: &ResolvedTypes) -> UnitEvidence {
    UnitEvidence {
        types: units.iter().map(|unit| resolved.within(unit)).collect(),
        apis: units
            .iter()
            .map(|unit| resolved.apis_within(unit))
            .collect(),
    }
}
