use super::{
    BTreeMap, BTreeSet, Boilerplate, ByteRange, CandidateConfig, CandidateStats, CloneClass,
    CloneGroupFingerprint, ControlFlowConfig, ControlFlowStats, CrossVariantComparisonId,
    CrossVariantGroupId, FragmentFingerprint, GroupingConfig, GroupingSet, GroupingStats, Language,
    Lexeme, LiteralNorm, MaximalConfig, NearMatchConfig, NearMatchStats, RegionStats,
    SimilarityBreakdown, TestCodeEvidence, Token, UnitFingerprint, UnitKind, VerifyConfig,
    stable_id, test_code, verify,
};

/// Default largest shape-mix divergence a candidate pair may span.
///
/// Chosen to say about the shape mix what
/// [`DEFAULT_MAX_LENGTH_RATIO`](crate::near_match::DEFAULT_MAX_LENGTH_RATIO)
/// says about size: at 3.0 the two sizes alone put a pair at 0.5. Measured
/// over four projects between 39 and 480 kLOC, the most divergent pair
/// verification has ever accepted sat at 0.41, and the limit takes 15% to 36%
/// of the proposals out of verification without touching a single one of them.
///
/// Removing it entirely changes no group on any corpus this project has, which
/// is what a gate that only sheds work should do. That is also why the value
/// is not tuned against results: there are none to tune it on. What would move
/// it is a measurement of what it costs to keep, not of what it finds.
pub const DEFAULT_MAX_SHAPE_DIVERGENCE: f64 = 0.5;

/// Largest number of distinct unit pairs the precise verifier may inspect.
///
/// Candidate generation is deliberately broader than verification; without a
/// second ceiling, every candidate stage can be bounded while their union
/// still asks the expensive sequence aligner to do unbounded work.
pub const DEFAULT_VERIFICATION_BUDGET: usize = 2_000_000;

/// Tuning for a whole structural run: one config per stage.
#[derive(Debug, Clone, PartialEq)]
pub struct StructuralConfig {
    /// Smallest whole-unit or statement-run clone length, in parsed tokens,
    /// that the structural pipeline reports.
    ///
    /// Candidate extraction can still see shorter code so its other funnel
    /// counters describe the full search space. Short candidates leave before
    /// precise verification and are accounted for in [`StructuralStats`].
    pub min_clone_tokens: u32,
    /// Exact-seed candidate extraction.
    pub candidate: CandidateConfig,
    /// MinHash/LSH near-match extraction.
    pub near_match: NearMatchConfig,
    /// Control-flow skeleton extraction.
    pub control_flow: ControlFlowConfig,
    /// Folding seed matches into maximal shared runs.
    pub maximal: MaximalConfig,
    /// Literal strategy the duplicated runs are confirmed under: it decides
    /// whether two runs differing only in literal values are the same run.
    pub literals: LiteralNorm,
    /// Precise verification.
    pub verify: VerifyConfig,
    /// Upper bound on distinct unit pairs passed to precise verification.
    ///
    /// Pairs are ordered canonically before this budget is spent, so lowering
    /// it changes coverage deterministically and is reported in the funnel.
    pub verification_budget: usize,
    /// How far apart two units' shape mixes may be and still be worth
    /// verifying; see
    /// [`shape_divergence`](crate::features::CharacteristicVector::shape_divergence).
    pub max_shape_divergence: f64,
    /// Medoid grouping.
    pub grouping: GroupingConfig,
    /// Bounded post-grouping search for incomplete copies beside an established
    /// group. This never changes primary group membership.
    pub siblings: SiblingConfig,
}

impl Default for StructuralConfig {
    fn default() -> Self {
        Self {
            min_clone_tokens: 20,
            candidate: CandidateConfig::default(),
            near_match: NearMatchConfig::default(),
            control_flow: ControlFlowConfig::default(),
            maximal: MaximalConfig::default(),
            literals: LiteralNorm::default(),
            verify: VerifyConfig::default(),
            verification_budget: DEFAULT_VERIFICATION_BUDGET,
            max_shape_divergence: DEFAULT_MAX_SHAPE_DIVERGENCE,
            grouping: GroupingConfig::default(),
            siblings: SiblingConfig::default(),
        }
    }
}

/// Tuning for the post-grouping sibling sweep.
///
/// A sibling is deliberately weaker than a group member: it is an ungrouped
/// unit in a file that already hosts a cohesive group member, compared only
/// to that group's canonical unit. The sweep finds incomplete local mirrors
/// without inventing primary similarity edges or allowing a near-copy to pull
/// a group apart or together.
#[derive(Debug, Clone, PartialEq)]
pub struct SiblingConfig {
    /// How far below the normal Type-3 threshold a sibling may land.
    ///
    /// The effective threshold is clamped to the normal threshold's
    /// non-negative range, so an invalidly large delta cannot turn every
    /// unrelated unit into a sibling.
    pub similarity_delta: f64,
    /// Maximum canonical-to-ungrouped comparisons in the sweep.
    pub candidate_budget: usize,
    /// Maximum siblings retained for one primary group.
    pub per_group_cap: usize,
    /// Maximum siblings retained over the whole structural report.
    pub total_cap: usize,
}

impl Default for SiblingConfig {
    fn default() -> Self {
        Self {
            // The normal Type-3 gate has a narrow measured 0.69/0.71 gap.
            // Siblings are intentionally triage evidence, not primary clone
            // membership, so they may recover a small omitted tail while
            // still requiring substantial verifier agreement.
            similarity_delta: 0.10,
            candidate_budget: 50_000,
            per_group_cap: 8,
            total_cap: 1_000,
        }
    }
}

/// One analysed unit, kept so a caller can map a group's member indices back to
/// source locations. The index of a unit in [`StructuralReport::units`] is the
/// index grouping refers to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructuralUnit {
    /// Index of the file this unit belongs to (into the input slice).
    pub file: usize,
    /// What kind of unit this is; reporting only.
    pub kind: UnitKind,
    /// Source bytes the unit covers; reporting only.
    pub range: ByteRange,
    /// 1-based first line; reporting only, never an identity input.
    pub start_line: u32,
    /// 1-based last line; reporting only, never an identity input.
    pub end_line: u32,
    /// Index of the unit's first token in its file's stream.
    pub token_start: usize,
    /// Index one past the unit's last token in its file's stream.
    pub token_end: usize,
    /// The unit's declared name, when the frontend recovered one.
    pub name: Option<Lexeme>,
    /// The boilerplate shape the unit matches, when it matches one. Recorded,
    /// not acted on: a classified unit is analysed and grouped like any other.
    pub boilerplate: Option<Boilerplate>,
    /// Whether the unit is test code: marked as a test itself, or sitting
    /// inside an item that is. Recorded, not acted on, as `boilerplate` is.
    pub test_code: bool,
    /// Why this unit is test code, when it is test code.
    ///
    /// Structural analysis initially records marker evidence. A caller that
    /// knows the scan's configured test paths can add path evidence after the
    /// analysis, without changing candidate extraction or grouping.
    pub test_code_evidence: Option<TestCodeEvidence>,
    /// The unit's raw content fingerprint: its stable grouping key and unit
    /// identity.
    pub fingerprint: UnitFingerprint,
    /// The unit's content fingerprint in fragment form, used as its member
    /// content id when composing a group fingerprint (a whole-unit clone is a
    /// fragment spanning the unit; keeping this as a fragment fingerprint keeps
    /// the group id forward-compatible with sub-unit members).
    pub content: FragmentFingerprint,
    /// Identifier-normalized content used only for non-Type-1 group identity.
    /// Unit identity remains raw so distinct renamed occurrences never merge.
    pub normalized_content: FragmentFingerprint,
}

/// A verified clone relation between two contents that no reported group
/// could hold.
///
/// The two contents are clones of each other by the judge's own verdict; what
/// they are not is members of one set whose every pair is a clone, which is
/// what a group asserts. Similarity is not transitive, so a unit can be a
/// clone of two others that are not clones of each other, and a partition into
/// groups can keep only one of those relations. The other is evidence the
/// judge accepted, and it leaves the analysis here rather than being dropped.
///
/// The entry describes *contents*, not one pair of places. Where a codebase
/// holds eight copies of one content and eight of another, the judge reaches
/// the same verdict about all sixty-four crossings of them, and reporting
/// sixty-four entries states one fact sixty-four times — all of them under one
/// identity, because a clone id is composed from member content and two
/// entries over the same two contents cannot differ. So every unit the folded
/// verdicts touched is a member here, and there is one entry per pair of
/// contents.
#[derive(Debug, Clone, PartialEq)]
pub struct VerifiedPair {
    /// Every unit the folded verdicts touched, in unit-index order.
    pub members: Vec<usize>,
    /// Which member is the canonical instance. Which *content* is canonical
    /// follows content order, so it does not depend on where either was found;
    /// among the occurrences of that content the first in member order stands
    /// for it, and they are interchangeable by construction.
    pub canonical: usize,
    /// The relation's stable, position-free clone id, composed exactly as a
    /// group's is: a pair is a group of two contents, and nothing about its
    /// identity should say otherwise.
    pub fingerprint: CloneGroupFingerprint,
    /// The strongest composite similarity among the folded verdicts.
    pub similarity: f64,
    /// Per-dimension evidence for the weakest accepted crossing represented
    /// by this pair. It is absent only for callers that constructed a scalar
    /// edge without verifier evidence.
    pub breakdown: Option<SimilarityBreakdown>,
    /// What the judge classified the relation as.
    pub class: CloneClass,
    /// The judge's confidence in that classification.
    pub confidence: verify::Confidence,
    /// The boilerplate category shared by the relation's members, when one
    /// category dominates them under the same policy used for normal groups.
    pub boilerplate: Option<Boilerplate>,
    /// Whether the relation is one routine written once per integer width.
    pub width_family: bool,
}

impl VerifiedPair {
    /// Whether `unit` is one of the members.
    #[must_use]
    pub fn holds(&self, unit: usize) -> bool {
        self.members.binary_search(&unit).is_ok()
    }
}

/// Reporting detail for one clone group, parallel to the group at the same
/// index in [`StructuralReport::groups`].
#[derive(Debug, Clone, PartialEq)]
pub struct GroupDetail {
    /// The group's stable, position-free fingerprint (its clone id).
    pub fingerprint: CloneGroupFingerprint,
    /// The similarity breakdown of the medoid against each member, parallel to
    /// the group's `members` (the medoid's own entry is a perfect self-match).
    pub member_breakdowns: Vec<SimilarityBreakdown>,
    /// The verifier breakdown for the actual weakest pair in the cohesive
    /// group. This is the evidence that establishes `min_pairwise`.
    pub cohesion_breakdown: SimilarityBreakdown,
    /// Smallest raw-identifier Jaccard agreement against the canonical unit.
    /// It is evidence only: detection, clone class, and priority ignore it.
    pub identifier_jaccard: f64,
    /// Conservative evidence that every member carries a material body.
    ///
    /// This is not a code-size estimate. It records only syntactic work that
    /// a maintainer must understand while changing each copy.
    pub body_materiality: BodyMateriality,
    /// The dominant boilerplate shape of the whole group, when at least four
    /// fifths of its members match it. The per-member classifications remain
    /// available in reports so the exceptional bodies are never hidden.
    pub boilerplate: Option<Boilerplate>,
    /// Whether every member is test code. A group with even one member outside
    /// the suite is duplication between test and tested code, which is the
    /// interesting case and must not be ranked with the suite.
    pub test_code: bool,
    /// The aggregate evidence for [`Self::test_code`].
    ///
    /// Marker takes precedence when any member has it; path is named only
    /// when every member is path-derived. `None` means at least one member is
    /// not test code.
    pub test_code_evidence: Option<TestCodeEvidence>,
    /// Whether the group reads as one routine written once per integer width.
    ///
    /// A [`Boilerplate`] category is a judgement about one body, aggregated to
    /// the group only when every member agrees. This is not: it is a statement
    /// about how two bodies differ, which no member can carry on its own, so it
    /// sits beside the category rather than inside it.
    pub width_family: bool,
}

/// Material operations shared by every member of a structural clone group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BodyMateriality {
    /// Every member contains at least one loop.
    pub has_loop: bool,
    /// Every member calls a recognised allocation API.
    pub has_dynamic_allocation: bool,
    /// Fewest recovered call sites in any member.
    pub call_count: u64,
}

/// One occurrence of a duplicated statement run, resolved against the source
/// it was found in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegionOccurrence {
    /// Index of the file this occurrence sits in.
    pub file: usize,
    /// Index of the enclosing unit in [`StructuralReport::units`].
    pub unit: usize,
    /// Source bytes the run covers; reporting only.
    pub range: ByteRange,
    /// 1-based first line; reporting only, never an identity input.
    pub start_line: u32,
    /// 1-based last line; reporting only, never an identity input.
    pub end_line: u32,
    /// Index of the run's first token in its file's stream.
    pub token_start: usize,
    /// Index one past the run's last token in its file's stream.
    pub token_end: usize,
    /// The occurrence's raw content fingerprint: its member content id.
    pub content: FragmentFingerprint,
}

/// A half-open token span in one [`SyntaxIrFile`](crate::ir::SyntaxIrFile).
///
/// This is a reporting anchor, not an identity input. Callers use it to
/// measure raw source evidence after structural detection has completed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceTokenSpan {
    /// Index of the source file in the IR slice.
    pub file: usize,
    /// Index of the first token in the span.
    pub token_start: usize,
    /// Index one past the final token in the span.
    pub token_end: usize,
}

impl SourceTokenSpan {
    /// Construct a source-token span from half-open token indices.
    #[must_use]
    pub const fn new(file: usize, token_start: usize, token_end: usize) -> Self {
        Self {
            file,
            token_start,
            token_end,
        }
    }
}

/// A duplicated run of statements and every place it occurs.
///
/// Unlike a [`GroupDetail`], whose members are only *similar*, every
/// occurrence here holds the same content under the group's classification:
/// the same tokens for [`CloneClass::Type1`], the same tokens up to consistent
/// renaming for [`CloneClass::Type2`]. The enclosing units need not be clones
/// of each other — that is the point of reporting runs separately.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructuralRegion {
    /// The run's stable, position-free clone-group fingerprint.
    pub fingerprint: CloneGroupFingerprint,
    /// How the occurrences match: verbatim or up to renaming.
    pub clone_type: CloneClass,
    /// Length of the run, in statements.
    pub statements: u32,
    /// Where the run occurs, at least twice, in ascending source order.
    pub occurrences: Vec<RegionOccurrence>,
}

/// Funnel counters across the whole run: how many fragments, candidate pairs
/// and verified pairs each stage saw.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StructuralStats {
    /// Files analysed.
    pub files: usize,
    /// Units across all files.
    pub units: usize,
    /// Exact-seed candidate extraction statistics.
    pub candidate: CandidateStats,
    /// Near-match extraction statistics.
    pub near_match: NearMatchStats,
    /// Control-flow skeleton extraction statistics.
    pub control_flow: ControlFlowStats,
    /// Maximal-region consolidation statistics.
    pub maximal: RegionStats,
    /// Duplicated runs confirmed against the source tokens.
    pub regions: usize,
    /// Occurrences dropped for holding content no other occurrence of their
    /// candidate run shared: the statement summaries agreed but the code did
    /// not.
    pub region_singletons: usize,
    /// Occurrences dropped for covering source a kept occurrence of the same
    /// run already covers, which makes them one stretch of code rather than
    /// two instances of it.
    pub region_overlapping: usize,
    /// Occurrences dropped for continuing a kept occurrence of the same run,
    /// statement for statement, inside one block. Those tile one stretch of
    /// code, so the run is that stretch's period rather than a copy of it.
    pub region_adjoining: usize,
    /// Confirmed runs dropped because a longer run covers every one of their
    /// occurrences and claims at least as much about them.
    pub region_subsumed: usize,
    /// Longer runs made by joining confirmed runs that describe one stretch at
    /// two offsets. The parts they cover leave through `region_subsumed`.
    pub region_merged: usize,
    /// Confirmed runs folded into another run holding the same content. Two
    /// candidates can propose one duplication, and a run is identified by what
    /// it holds, so both are the same run and are reported once.
    pub region_folded: usize,
    /// Confirmed duplicated statement runs dropped because at least one
    /// occurrence is shorter than the configured minimum clone length.
    pub below_min_clone_token_regions: usize,
    /// Candidate pairs dropped because one unit encloses the other.
    pub nested_pairs: usize,
    /// Candidate pairs dropped because the two units sit under different arms
    /// of one preprocessor conditional, so no build holds both.
    pub alternative_pairs: usize,
    /// Candidate pairs dropped because the two units hold too different a mix
    /// of shapes for verification to have anything to find.
    pub divergent_shape_pairs: usize,
    /// Candidate unit pairs dropped because one member is shorter than the
    /// configured minimum clone length.
    pub below_min_clone_token_pairs: usize,
    /// Distinct unit pairs handed to verification.
    pub unit_pairs: usize,
    /// Candidate unit pairs left unverified after the verification budget was
    /// spent. A nonzero count means the reported groups can be incomplete.
    pub verification_budget_dropped: usize,
    /// Unit pairs that verification accepted as clones.
    pub verified_pairs: usize,
    /// Verified pairs no reported group holds both halves of.
    pub unrepresented_pairs: usize,
    /// Verified pairs left out of that carry-out because a group already
    /// relates their two sides, one of them holding a unit nested inside the
    /// other side.
    pub described_pairs: usize,
    /// Verified pairs left out because the component ceiling cut their two
    /// sides into separate pieces, so no group was ever in a position to hold
    /// both. Zero unless [`GroupingConfig::max_component`] fired.
    pub severed_pairs: usize,
    /// Grouping statistics.
    pub grouping: GroupingStats,
    /// Post-grouping sibling-sweep accounting.
    pub siblings: SiblingSweepStats,
}

/// Counters for the bounded post-grouping sibling sweep.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SiblingSweepStats {
    /// Established primary groups considered for local siblings.
    pub groups_considered: usize,
    /// Canonical-to-ungrouped comparisons eligible under the file, minimum,
    /// nesting, conditional-arm, and shape-divergence rules.
    pub eligible_candidates: usize,
    /// Candidates handed to the verifier.
    pub candidates_examined: usize,
    /// Siblings retained after the relaxed verifier threshold.
    pub accepted: usize,
    /// Candidates left unexamined because `candidate_budget` was reached.
    pub candidate_budget_dropped: usize,
    /// Candidates left unexamined after their group reached `per_group_cap`.
    pub per_group_cap_dropped: usize,
    /// Candidates left unexamined after the report reached `total_cap`.
    pub total_cap_dropped: usize,
}

/// One incomplete local mirror attached to an established primary group.
#[derive(Debug, Clone, PartialEq)]
pub struct StructuralSibling {
    /// The ungrouped unit. It is never added to `StructuralGroup::members`.
    pub unit: usize,
    /// The verifier's clone classification, or Type-3 for a relaxed-only hit.
    pub clone_type: CloneClass,
    /// The verifier confidence, clamped to low below the normal Type-3
    /// threshold even when an exact-structure shortcut classified the pair.
    pub confidence: verify::Confidence,
    /// The canonical-to-sibling similarity breakdown.
    pub breakdown: SimilarityBreakdown,
}

/// Siblings of one primary group, addressed by its index in
/// [`StructuralReport::groups`].
#[derive(Debug, Clone, PartialEq)]
pub struct GroupSiblings {
    /// Index of the owning primary group.
    pub group: usize,
    /// Siblings in deterministic unit-fingerprint order.
    pub siblings: Vec<StructuralSibling>,
}

/// One LSH-proposed unit pair that passed the size gate but landed inside the
/// bounded estimate band immediately below the primary near-match threshold.
///
/// This is run-scoped diagnostic telemetry, not a similarity edge. It never
/// reaches verification, grouping, group membership, or primary findings.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct StructuralNearMiss {
    /// Index of the lower unit in [`StructuralReport::units`].
    pub a: usize,
    /// Index of the higher unit in [`StructuralReport::units`].
    pub b: usize,
    /// MinHash-estimated Jaccard similarity that missed the primary gate.
    pub estimated_jaccard: f64,
}

/// The structural run's output: cohesive groups over [`Self::units`], plus the
/// funnel statistics.
#[derive(Debug, Clone, PartialEq)]
pub struct StructuralReport {
    /// Analysed units; a group's member indices index this slice.
    pub units: Vec<StructuralUnit>,
    /// Cohesive clone groups.
    pub groups: GroupingSet,
    /// Duplicated statement runs, each with every place it occurs. The units
    /// involved need not be clones of each other: this is the sub-unit view of
    /// the same corpus.
    pub regions: Vec<StructuralRegion>,
    /// Reporting detail per group, parallel to `groups.groups`: stable clone id
    /// and the medoid-to-member similarity breakdowns.
    pub details: Vec<GroupDetail>,
    /// Verified clone pairs no group holds both halves of, strongest first.
    /// Real copies that a partition into groups cannot express.
    pub unrepresented: Vec<VerifiedPair>,
    /// Incomplete local mirrors attached to primary groups without changing
    /// the primary grouping relation.
    pub siblings: Vec<GroupSiblings>,
    /// Bounded LSH diagnostics immediately below the primary near-match
    /// estimate gate. These pairs are not primary findings.
    pub near_misses: Vec<StructuralNearMiss>,
    /// Funnel statistics.
    pub stats: StructuralStats,
}

impl StructuralReport {
    /// Add configured test-path evidence to units in matching files.
    ///
    /// `test_files` is indexed like the source slice passed to structural
    /// analysis. Marker evidence is never overwritten. The method then
    /// recomputes the parallel group facts, keeping `test_code` true only
    /// where every member remains test code. Candidate extraction,
    /// verification, and grouping have already finished and are untouched.
    pub fn apply_test_path_evidence(&mut self, test_files: &[bool]) {
        for unit in &mut self.units {
            if unit.test_code_evidence.is_none()
                && test_files.get(unit.file).copied().unwrap_or(false)
            {
                unit.test_code_evidence = Some(TestCodeEvidence::Path);
            }
            unit.test_code = unit.test_code_evidence.is_some();
        }
        for (group, detail) in self.groups.groups.iter().zip(&mut self.details) {
            let evidence = test_code::aggregate_evidence(
                group
                    .members
                    .iter()
                    .map(|&member| self.units[member].test_code_evidence),
            );
            detail.test_code = evidence.is_some();
            detail.test_code_evidence = evidence;
        }
    }
}

/// One unit offered to an explicit build-variant comparison.
///
/// The unit still records the variant that produced it. This is deliberately
/// not a `BuildVariant`-less intermediate representation: comparison is an
/// opt-in relation between independent programs, not another program.
#[derive(Debug, Clone, Copy)]
pub struct CrossVariantUnit<'a> {
    /// Fingerprint of the partition that produced this unit.
    pub origin_variant: &'a str,
    /// Language of the source unit.
    pub language: Language,
    /// Reporting anchor relative to the scanned root.
    pub file_path: &'a str,
    /// Reporting anchor, 1-based.
    pub start_line: u32,
    /// Reporting anchor, 1-based.
    pub end_line: u32,
    /// The unit's declared name, when parsing recovered it.
    pub name: Option<&'a str>,
    /// Tokens covering precisely this unit.
    pub tokens: &'a [Token],
}

/// A member of a cross-build-variant exact clone group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrossVariantMember {
    /// Stable occurrence identity; source anchors are reporting only.
    pub id: stable_id::CrossVariantMemberId,
    /// The normal partition that produced this member; never synthesized.
    pub origin_variant: String,
    /// Language of the source unit.
    pub language: Language,
    /// Reporting anchor relative to the scanned root.
    pub file_path: String,
    /// Reporting anchor, 1-based.
    pub start_line: u32,
    /// Reporting anchor, 1-based.
    pub end_line: u32,
    /// Best-effort unit name.
    pub name: Option<String>,
    /// Token count of the matched unit.
    pub token_count: usize,
}

/// One exact group found across independent build variants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrossVariantGroup {
    /// Comparison-domain stable identifier, distinct from clone-group ids.
    pub id: CrossVariantGroupId,
    /// Exact clones only in the current policy.
    pub clone_type: CloneClass,
    /// Every occurrence, each retaining its origin variant.
    pub members: Vec<CrossVariantMember>,
}

/// The result of an explicit cross-build-variant comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrossVariantComparison {
    /// Comparison-domain identity, including policy and the origin set.
    pub id: CrossVariantComparisonId,
    /// Sorted, deduplicated fingerprints of all partitions compared.
    pub origin_variants: Vec<String>,
    /// Exact groups with members from at least two origin variants.
    pub groups: Vec<CrossVariantGroup>,
}

/// Compare exact whole units across C/C++ build partitions.
///
/// This deliberately covers Type-1 units only. It is a separate, bounded
/// operation from a partition's structural pipeline: normal Type-2/3 groups,
/// their snapshots, baselines and histories remain partition-local. The
/// function does compare source units directly; it never joins groups that a
/// partition happened to report.
#[must_use]
pub fn compare_build_variants(units: &[CrossVariantUnit<'_>]) -> Option<CrossVariantComparison> {
    let mut origins: Vec<String> = units
        .iter()
        .map(|unit| unit.origin_variant.to_string())
        .collect();
    origins.sort_unstable();
    origins.dedup();
    if origins.len() < 2 {
        return None;
    }
    let id = stable_id::cross_variant_comparison_id(&origins);
    let mut classes: BTreeMap<(String, [u8; 16]), Vec<&CrossVariantUnit<'_>>> = BTreeMap::new();
    for unit in units {
        let mut content = blake3::Hasher::new();
        content.update(b"cross-variant-raw-unit-v1");
        for token in unit.tokens {
            content.update(&[token.kind.tag()]);
            let length = u32::try_from(token.text.len()).unwrap_or(u32::MAX);
            content.update(&length.to_le_bytes());
            content.update(token.text.as_bytes());
        }
        let mut digest = [0_u8; 16];
        digest.copy_from_slice(&content.finalize().as_bytes()[..16]);
        classes
            .entry((unit.language.name().to_string(), digest))
            .or_default()
            .push(unit);
    }
    let mut groups = Vec::new();
    for ((language, content), members) in classes {
        let origins_in_group: BTreeSet<&str> =
            members.iter().map(|member| member.origin_variant).collect();
        if origins_in_group.len() < 2 {
            continue;
        }
        let mut members: Vec<CrossVariantMember> = members
            .into_iter()
            .map(|member| CrossVariantMember {
                id: stable_id::CrossVariantMemberId::from_bytes([0; 16]),
                origin_variant: member.origin_variant.to_string(),
                language: member.language,
                file_path: member.file_path.to_string(),
                start_line: member.start_line,
                end_line: member.end_line,
                name: member.name.map(ToString::to_string),
                token_count: member.tokens.len(),
            })
            .collect();
        members.sort_by(|left, right| {
            left.origin_variant
                .cmp(&right.origin_variant)
                .then_with(|| left.file_path.cmp(&right.file_path))
                .then_with(|| left.start_line.cmp(&right.start_line))
                .then_with(|| left.end_line.cmp(&right.end_line))
                .then_with(|| left.name.cmp(&right.name))
        });
        let language = match language.as_str() {
            "c" => Language::C,
            "cpp" => Language::Cpp,
            _ => Language::Rust,
        };
        let group_id =
            stable_id::cross_variant_group_id(&id, CloneClass::Type1, language, &content);
        let mut origin_ranks = BTreeMap::<(&str, &str), u32>::new();
        for member in &mut members {
            let rank = origin_ranks
                .entry((&member.origin_variant, member.language.name()))
                .or_default();
            member.id = stable_id::cross_variant_member_id(
                &group_id,
                &member.origin_variant,
                member.language,
                *rank,
            );
            *rank = rank.saturating_add(1);
        }
        groups.push(CrossVariantGroup {
            id: group_id,
            clone_type: CloneClass::Type1,
            members,
        });
    }
    groups.sort_by_key(|group| group.id);
    Some(CrossVariantComparison {
        id,
        origin_variants: origins,
        groups,
    })
}
