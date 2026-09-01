//! Stable, position-free identifiers for clone-audit entities.
//!
//! Audit continuity across scans hinges on identifiers that survive the edits
//! they should survive: unrelated changes elsewhere in the file, formatting
//! and comments, and file moves must not change an identifier, while a change
//! to the identified content must. Every identifier here is therefore a
//! 128-bit BLAKE3 digest of *content and analysis context only* — line
//! numbers, byte offsets, file paths, token indices and input ordering are
//! never hashed. Reporting positions live in anchors (see
//! [`Instance`](crate::engine::Instance)), which are carried next to the
//! identifiers and updated freely on re-scan.
//!
//! The identifier kinds are distinct newtypes, so a unit fingerprint can
//! never be passed where a group fingerprint is expected; the confusion is a
//! compile error rather than a silent mismatch. Each kind also hashes under
//! its own domain tag, so equal content in different roles yields unrelated
//! digests.
//!
//! Hash inputs are length-prefixed and include the schema version, the
//! normalization ruleset version, the frontend version, the analysis mode,
//! the language and the build variant, so results from incompatible
//! configurations never collide silently. 128 bits are persisted because
//! these are long-lived identity keys: a truncated key that collides would
//! fuse two clones' histories without any symptom.

use core::fmt;
use std::collections::BTreeMap;

use crate::clone_class::CloneClass;
use crate::discovery::{BuildVariant, Language};
use crate::engine::normalize::{self, LiteralNorm, NormAtom, Resolution};
use crate::engine::{EngineReport, InputFile};
use crate::frontend::{Token, tokens_in_range};
use crate::semantic::{SOG_SCHEMA_VERSION, SemanticOperationGraph};

/// Version of the identifier-hashing recipe. Bump on any change to the hash
/// inputs, their encoding or their order.
pub const FP_SCHEMA_VERSION: &str = "fp-schema-v1";

/// The hash algorithm behind every identifier, recorded so a future
/// algorithm change is an explicit versioned event rather than a silent one.
pub const HASH_ALGORITHM: &str = "blake3-128";

macro_rules! stable_id {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name([u8; 16]);

        impl $name {
            /// Wrap identifier bytes produced earlier by this tool (for
            /// example, loaded back from the store).
            #[must_use]
            pub const fn from_bytes(bytes: [u8; 16]) -> Self {
                Self(bytes)
            }

            /// The identifier's raw bytes.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 16] {
                &self.0
            }

            /// Lowercase hex form used in reports.
            #[must_use]
            pub fn to_hex(&self) -> String {
                self.to_string()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                for byte in self.0 {
                    write!(f, "{byte:02x}")?;
                }
                Ok(())
            }
        }
    };
}

stable_id!(
    /// Fingerprint of one whole code unit (function, method, impl/record
    /// block, closure), hashed from its token content.
    UnitFingerprint
);
stable_id!(
    /// Fingerprint of a sub-unit content slice: a candidate fragment or a
    /// matched run. Content-identical slices share one fingerprint;
    /// occurrences are told apart by [`FindingId`], never by position.
    FragmentFingerprint
);
stable_id!(
    /// Fingerprint of a clone group, derived order-independently from the
    /// deduplicated content fingerprints of its members.
    CloneGroupFingerprint
);
stable_id!(
    /// Stable identity of a clone group's history across fingerprint changes.
    ///
    /// A lineage begins from a group fingerprint but has its own hash domain;
    /// later runs may adopt it through explicit, recorded overlap evidence.
    GroupLineageId
);
stable_id!(
    /// Identifier of one finding: a specific occurrence of a group's content,
    /// discriminated by its host unit and an in-host occurrence rank rather
    /// than by any source position.
    FindingId
);
stable_id!(
    /// Identity of an opt-in comparison across distinct build variants.
    ///
    /// This deliberately lives outside every normal scan and clone-group
    /// domain: a cross-variant result is not a new build variant.
    CrossVariantComparisonId
);
stable_id!(
    /// Stable identity of one group found by a cross-variant comparison.
    CrossVariantGroupId
);
stable_id!(
    /// Position-free identity of one cross-variant group occurrence.
    CrossVariantMemberId
);
stable_id!(
    /// Identity of an explicitly requested Rust-to-C++ semantic comparison.
    ///
    /// It lives outside normal snapshots and cross-build exact comparisons:
    /// the same origin variants may be compared under both policies without
    /// making either result look like a continuation of the other.
    CrossLanguageComparisonId
);
stable_id!(
    /// Stable identity of one group found by a Rust-to-C++ semantic comparison.
    CrossLanguageGroupId
);
stable_id!(
    /// Position-free identity of one cross-language group occurrence.
    CrossLanguageMemberId
);

/// Version of the policy that defines cross-build-variant comparisons.
pub const CROSS_VARIANT_POLICY_VERSION: &str = "cross-variant-exact-v1";

/// Version of the explicit Rust-to-C++ semantic comparison policy.
pub const CROSS_LANGUAGE_POLICY_VERSION: &str = "cross-language-semantic-v1";

/// How content is folded before hashing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentNorm {
    /// Kind tags plus raw lexeme text: Type-1 identity.
    Raw,
    /// Scope-local alpha renaming with the given literal strategy: Type-2
    /// identity (see [`normalize`]).
    Normalized(LiteralNorm),
    /// Scope-local alpha renaming corrected by compiler name resolution.
    ///
    /// The compiler answer is optional at each token: when it has no answer,
    /// the lexical fallback remains in force.  This nevertheless has a
    /// distinct fingerprint domain because a semantic run must not share
    /// stored identity with a purely lexical one.
    ResolvedNormalized(LiteralNorm),
}

impl ContentNorm {
    /// Stable label fed into the hash, so raw and normalized digests of the
    /// same tokens never collide.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Raw => "raw",
            Self::Normalized(LiteralNorm::Preserve) => "alpha-lit-preserve",
            Self::Normalized(LiteralNorm::Category) => "alpha-lit-category",
            Self::Normalized(LiteralNorm::Full) => "alpha-lit-full",
            Self::ResolvedNormalized(LiteralNorm::Preserve) => "alpha-resolved-lit-preserve",
            Self::ResolvedNormalized(LiteralNorm::Category) => "alpha-resolved-lit-category",
            Self::ResolvedNormalized(LiteralNorm::Full) => "alpha-resolved-lit-full",
        }
    }
}

/// Per-file analysis context that participates in content hashing.
///
/// The engine identifies files by index only; language and frontend version
/// are supplied alongside, typically copied from the
/// [`LexedFile`](crate::frontend::LexedFile) the tokens came from.
#[derive(Debug, Clone, Copy)]
pub struct FileContext<'a> {
    /// Version tag of the frontend that produced the tokens.
    pub frontend_version: &'a str,
    /// Language the file was lexed as.
    pub language: Language,
}

/// Length-prefixed BLAKE3 hashing with a leading domain tag.
struct IdHasher {
    hasher: blake3::Hasher,
}

impl IdHasher {
    fn new(domain: &str) -> Self {
        let mut this = Self {
            hasher: blake3::Hasher::new(),
        };
        this.write_bytes(domain.as_bytes());
        this
    }

    fn write_bytes(&mut self, bytes: &[u8]) {
        let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
        self.hasher.update(&len.to_le_bytes());
        self.hasher.update(bytes);
    }

    fn write_str(&mut self, text: &str) {
        self.write_bytes(text.as_bytes());
    }

    fn write_u8(&mut self, value: u8) {
        self.hasher.update(&[value]);
    }

    fn write_u32(&mut self, value: u32) {
        self.hasher.update(&value.to_le_bytes());
    }

    /// The shared context prefix: schema, normalization, frontend, mode,
    /// language, build variant — in this fixed order.
    fn write_context(&mut self, variant: &BuildVariant, file: &FileContext<'_>, norm: ContentNorm) {
        self.write_str(FP_SCHEMA_VERSION);
        self.write_str(HASH_ALGORITHM);
        self.write_str(norm.label());
        self.write_u32(variant.normalization_version);
        self.write_str(file.frontend_version);
        self.write_str(variant.mode.name());
        self.write_str(file.language.name());
        self.write_str(&variant.canonical());
    }

    /// Token content under the chosen normalization. Only kind tags and
    /// (normalized) text enter the hash; spans never do.
    fn write_content(
        &mut self,
        tokens: &[Token],
        norm: ContentNorm,
        resolution: Option<&Resolution>,
    ) {
        match norm {
            ContentNorm::Raw => {
                for token in tokens {
                    self.write_u8(token.kind.tag());
                    self.write_bytes(token.text.as_bytes());
                }
            }
            ContentNorm::Normalized(literals) | ContentNorm::ResolvedNormalized(literals) => {
                let mut normalized = Vec::new();
                normalize::normalize_resolved_into(
                    tokens,
                    literals,
                    matches!(norm, ContentNorm::ResolvedNormalized(_))
                        .then_some(resolution)
                        .flatten(),
                    &mut normalized,
                );
                for norm_token in normalized {
                    self.write_u8(norm_token.tag);
                    match norm_token.atom {
                        NormAtom::Renamed(n) => {
                            self.write_u8(1);
                            self.write_u32(n);
                        }
                        NormAtom::Text(text) => {
                            self.write_u8(2);
                            self.write_bytes(text.as_bytes());
                        }
                        NormAtom::Literal(class) => {
                            self.write_u8(3);
                            self.write_u8(class);
                        }
                    }
                }
            }
        }
    }

    fn finish(self) -> [u8; 16] {
        let digest = self.hasher.finalize();
        let mut out = [0u8; 16];
        out.copy_from_slice(&digest.as_bytes()[..16]);
        out
    }
}

/// Fingerprint a whole unit's token stream.
///
/// The rename scope of a normalized unit fingerprint is the unit itself, so
/// the digest depends only on the unit's own content.
#[must_use]
pub fn unit_fingerprint(
    variant: &BuildVariant,
    file: &FileContext<'_>,
    tokens: &[Token],
    norm: ContentNorm,
) -> UnitFingerprint {
    let mut hasher = IdHasher::new("unit");
    hasher.write_context(variant, file, norm);
    hasher.write_content(tokens, norm, None);
    UnitFingerprint(hasher.finish())
}

/// Fingerprint a content slice (candidate fragment or matched run).
///
/// `kind` names the syntactic shape the slice was cut from (for example
/// `body`, `loop`, `member`); slices of different shapes hash apart even with
/// equal content. The rename scope is the slice itself, so the digest is
/// independent of the enclosing function.
#[must_use]
pub fn fragment_fingerprint(
    variant: &BuildVariant,
    file: &FileContext<'_>,
    kind: &str,
    tokens: &[Token],
    norm: ContentNorm,
) -> FragmentFingerprint {
    let mut hasher = IdHasher::new("fragment");
    hasher.write_context(variant, file, norm);
    hasher.write_str(kind);
    hasher.write_content(tokens, norm, None);
    FragmentFingerprint(hasher.finish())
}

/// Fingerprint a fragment with compiler-derived name-resolution evidence.
///
/// Only [`ContentNorm::ResolvedNormalized`] consumes `resolution`; callers
/// selecting a raw or lexical domain get the same digest as
/// [`fragment_fingerprint`].  This keeps the compiler boundary in the caller
/// while making the semantic normalization rule explicit in the ID context.
#[must_use]
pub fn resolved_fragment_fingerprint(
    variant: &BuildVariant,
    file: &FileContext<'_>,
    kind: &str,
    tokens: &[Token],
    norm: ContentNorm,
    resolution: Option<&Resolution>,
) -> FragmentFingerprint {
    let mut hasher = IdHasher::new("fragment");
    hasher.write_context(variant, file, norm);
    hasher.write_str(kind);
    hasher.write_content(tokens, norm, resolution);
    FragmentFingerprint(hasher.finish())
}

/// Fingerprint one normalized semantic graph as a finding fragment.
///
/// The graph material is written directly instead of serializing an
/// implementation-specific helper IR. It includes the SOG schema, the
/// graph's language and the full `BuildVariant` context, while source
/// positions remain absent. This makes a normalization-rule revision an
/// explicit identity boundary rather than an accidental finding rename.
#[must_use]
pub fn semantic_fragment_fingerprint(
    variant: &BuildVariant,
    graph: &SemanticOperationGraph,
) -> FragmentFingerprint {
    let mut hasher = IdHasher::new("fragment-semantic");
    hasher.write_context(
        variant,
        &FileContext {
            frontend_version: SOG_SCHEMA_VERSION,
            language: graph.language,
        },
        ContentNorm::Raw,
    );
    hasher.write_str(&graph.schema_version);
    hasher.write_u32(u32::try_from(graph.nodes.len()).unwrap_or(u32::MAX));
    for node in &graph.nodes {
        hasher.write_str(node.kind.name());
        match node.attributes.type_tag {
            Some(tag) => {
                hasher.write_u8(1);
                hasher.write_str(tag.name());
            }
            None => hasher.write_u8(0),
        }
        hasher.write_u32(u32::try_from(node.attributes.api_names.len()).unwrap_or(u32::MAX));
        for api_name in &node.attributes.api_names {
            hasher.write_str(api_name);
        }
        match &node.attributes.resource_kind {
            Some(resource_kind) => {
                hasher.write_u8(1);
                hasher.write_str(resource_kind);
            }
            None => hasher.write_u8(0),
        }
        match node.attributes.fallible_kind {
            Some(kind) => {
                hasher.write_u8(1);
                hasher.write_str(kind.name());
            }
            None => hasher.write_u8(0),
        }
        match node.attributes.direct_propagation {
            Some(kind) => {
                hasher.write_u8(1);
                hasher.write_str(kind.name());
            }
            None => hasher.write_u8(0),
        }
        match node.attributes.structure_fingerprint {
            Some(fingerprint) => {
                hasher.write_u8(1);
                hasher.write_bytes(&fingerprint);
            }
            None => hasher.write_u8(0),
        }
    }
    hasher.write_u32(u32::try_from(graph.edges.len()).unwrap_or(u32::MAX));
    for edge in &graph.edges {
        hasher.write_u32(edge.from);
        hasher.write_u32(edge.to);
        hasher.write_str(edge.kind.name());
    }
    FragmentFingerprint(hasher.finish())
}

/// Fingerprint source structure attached to a bounded semantic window.
///
/// The Structural frontend selects the token slice with source spans, but
/// only token kind and text enter the digest. Consequently, moving an
/// unchanged window does not change the value. The signature is deliberately
/// separate from normal clone content: it is conservative same-variant
/// evidence used to distinguish the expressions supplied to registered APIs.
#[must_use]
pub fn semantic_structure_fingerprint(
    variant: &BuildVariant,
    file: &FileContext<'_>,
    tokens: &[Token],
) -> [u8; 16] {
    let mut hasher = IdHasher::new("semantic-source-structure-v1");
    hasher.write_context(variant, file, ContentNorm::Raw);
    hasher.write_content(tokens, ContentNorm::Raw, None);
    hasher.finish()
}

/// Identify one semantic fragment occurrence inside its stable host unit.
///
/// Semantic content intentionally excludes source position, so identical
/// windows in distinct hosts need this separate identity before they can form
/// a group without collapsing. The rank is assigned once per host by the scan
/// after deterministic window extraction; it is not a source offset.
#[must_use]
pub fn semantic_occurrence_fingerprint(
    content: FragmentFingerprint,
    host: &UnitFingerprint,
    occurrence_rank: u32,
) -> FragmentFingerprint {
    let mut hasher = IdHasher::new("semantic-occurrence-v1");
    hasher.write_str(FP_SCHEMA_VERSION);
    hasher.write_bytes(content.as_bytes());
    hasher.write_bytes(host.as_bytes());
    hasher.write_u32(occurrence_rank);
    FragmentFingerprint(hasher.finish())
}

/// Fingerprint a clone group from its members' content fingerprints.
///
/// Member fingerprints are sorted and deduplicated first, so the digest is
/// independent of member order and of how many occurrences share identical
/// content: adding another copy of known content leaves the group fingerprint
/// unchanged, while genuinely new member content changes it.
#[must_use]
pub fn clone_group_fingerprint(
    variant: &BuildVariant,
    clone_type: CloneClass,
    members: &[FragmentFingerprint],
) -> CloneGroupFingerprint {
    let mut distinct: Vec<[u8; 16]> = members.iter().map(|m| m.0).collect();
    distinct.sort_unstable();
    distinct.dedup();

    let mut hasher = IdHasher::new("group");
    hasher.write_str(FP_SCHEMA_VERSION);
    hasher.write_str(HASH_ALGORITHM);
    hasher.write_str(variant.mode.name());
    hasher.write_str(&variant.canonical());
    hasher.write_str(clone_type.name());
    hasher.write_u32(u32::try_from(distinct.len()).unwrap_or(u32::MAX));
    for bytes in &distinct {
        hasher.write_bytes(bytes);
    }
    CloneGroupFingerprint(hasher.finish())
}

/// Start a clone-group history from the fingerprint that first identified it.
///
/// The separate domain ensures a lineage identifier cannot be mistaken for a
/// current finding identifier even when both are rendered as hexadecimal.
#[must_use]
pub fn group_lineage_id(group: &CloneGroupFingerprint) -> GroupLineageId {
    let mut hasher = IdHasher::new("group-lineage");
    hasher.write_str(FP_SCHEMA_VERSION);
    hasher.write_str(HASH_ALGORITHM);
    hasher.write_bytes(group.as_bytes());
    GroupLineageId(hasher.finish())
}

/// Fingerprint a restricted-semantic group after a registered rule matched.
///
/// This keeps rule identity and revision separate from the normalized graph
/// fragments. A future change to a rule cannot silently claim continuity with
/// a finding justified by different semantics.
#[must_use]
pub fn semantic_clone_group_fingerprint(
    variant: &BuildVariant,
    rule_id: &str,
    rule_version: u32,
    members: &[FragmentFingerprint],
) -> CloneGroupFingerprint {
    let mut occurrences: Vec<[u8; 16]> = members.iter().map(|member| member.0).collect();
    occurrences.sort_unstable();

    let mut hasher = IdHasher::new("group-semantic");
    hasher.write_str(FP_SCHEMA_VERSION);
    hasher.write_str(HASH_ALGORITHM);
    hasher.write_str(variant.mode.name());
    hasher.write_str(&variant.canonical());
    hasher.write_str(CloneClass::RestrictedSemantic.name());
    hasher.write_str(SOG_SCHEMA_VERSION);
    hasher.write_str(rule_id);
    hasher.write_u32(rule_version);
    hasher.write_u32(u32::try_from(occurrences.len()).unwrap_or(u32::MAX));
    for bytes in &occurrences {
        hasher.write_bytes(bytes);
    }
    CloneGroupFingerprint(hasher.finish())
}

/// Fingerprint a Structural (Type-3) clone group, anchored on its canonical
/// instance.
///
/// A Type-3 group's members are similar but not identical, so — unlike a
/// Type-1/2 group, whose members share one content fingerprint — there is no
/// single content to hash. The group is instead identified by its canonical
/// instance (the medoid, see [`crate::grouping`]) *and* the order-independent,
/// deduplicated set of its members' own content fingerprints. Anchoring on the
/// medoid keeps the identity tied to a concrete instance; folding in the whole
/// member set means adding genuinely new member content changes the
/// fingerprint, while reordering members or repeating identical content does
/// not.
///
/// The `canonical` fingerprint should also appear in `members`; it is hashed a
/// second time, in a distinct anchor position, so two groups with the same
/// member set but different medoids hash apart.
#[must_use]
pub fn structural_clone_group_fingerprint(
    variant: &BuildVariant,
    class: CloneClass,
    canonical: &FragmentFingerprint,
    members: &[FragmentFingerprint],
) -> CloneGroupFingerprint {
    let mut distinct: Vec<[u8; 16]> = members.iter().map(|m| m.0).collect();
    distinct.sort_unstable();
    distinct.dedup();

    let mut hasher = IdHasher::new("group-structural");
    hasher.write_str(FP_SCHEMA_VERSION);
    hasher.write_str(HASH_ALGORITHM);
    hasher.write_str(variant.mode.name());
    hasher.write_str(&variant.canonical());
    hasher.write_str(class.name());
    // Anchor on the canonical instance, then the order-independent member set.
    hasher.write_bytes(&canonical.0);
    hasher.write_u32(u32::try_from(distinct.len()).unwrap_or(u32::MAX));
    for bytes in &distinct {
        hasher.write_bytes(bytes);
    }
    CloneGroupFingerprint(hasher.finish())
}

/// What tells two occurrences of the same content apart.
///
/// Every constructor takes content — a token stream, a unit fingerprint, a
/// fragment fingerprint, an occurrence identifier — and combining two
/// discriminators yields another one. There is deliberately no constructor
/// taking a byte range, a line, a column, a token index or a file path, and
/// [`occurrence_ranks`] accepts nothing else, so a source position cannot
/// decide an occurrence rank by accident: it cannot be spelled.
///
/// Each constructor hashes under its own domain tag, so a discriminator drawn
/// from a unit and one drawn from a file never collide even if their bytes
/// came from the same content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OccurrenceDiscriminator([u8; 16]);

impl OccurrenceDiscriminator {
    /// Discriminate by the content of a token stream: the file an occurrence
    /// sits in, or the unit it was cut from.
    #[must_use]
    pub fn of_tokens(tokens: &[Token]) -> Self {
        let mut hasher = IdHasher::new("occurrence-tokens-v1");
        hasher.write_str(FP_SCHEMA_VERSION);
        hasher.write_content(tokens, ContentNorm::Raw, None);
        Self(hasher.finish())
    }

    /// Discriminate by the unit an occurrence sits in.
    #[must_use]
    pub fn of_unit(unit: &UnitFingerprint) -> Self {
        let mut hasher = IdHasher::new("occurrence-unit-v1");
        hasher.write_str(FP_SCHEMA_VERSION);
        hasher.write_bytes(&unit.0);
        Self(hasher.finish())
    }

    /// Discriminate by the occurrence's own matched content.
    #[must_use]
    pub fn of_fragment(fragment: &FragmentFingerprint) -> Self {
        let mut hasher = IdHasher::new("occurrence-fragment-v1");
        hasher.write_str(FP_SCHEMA_VERSION);
        hasher.write_bytes(&fragment.0);
        Self(hasher.finish())
    }

    /// Discriminate by an occurrence's own finding identity.
    #[must_use]
    pub fn of_finding(finding: &FindingId) -> Self {
        let mut hasher = IdHasher::new("occurrence-finding-v1");
        hasher.write_str(FP_SCHEMA_VERSION);
        hasher.write_bytes(&finding.0);
        Self(hasher.finish())
    }

    /// Both discriminators at once: two occurrences share the result only when
    /// they agree on each part.
    #[must_use]
    pub fn and(self, other: Self) -> Self {
        let mut hasher = IdHasher::new("occurrence-pair-v1");
        hasher.write_str(FP_SCHEMA_VERSION);
        hasher.write_bytes(&self.0);
        hasher.write_bytes(&other.0);
        Self(hasher.finish())
    }

    /// The discriminator's raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Rank occurrences inside their own discriminator.
///
/// Each occurrence's rank is its ordinal among the occurrences sharing its
/// discriminator, counted in the order given. Occurrences with different
/// discriminators never share a rank sequence, so adding, removing or
/// reordering occurrences that content tells apart — a copy in another unit,
/// in another file, or of other content — cannot move an existing occurrence's
/// rank. Only occurrences that content cannot separate at all fall back to the
/// caller's order, which is the last discrimination left once every
/// content-derived one has agreed.
#[must_use]
pub fn occurrence_ranks(discriminators: &[OccurrenceDiscriminator]) -> Vec<u32> {
    let mut next: BTreeMap<OccurrenceDiscriminator, u32> = BTreeMap::new();
    discriminators
        .iter()
        .map(|discriminator| {
            let slot = next.entry(*discriminator).or_insert(0);
            let rank = *slot;
            *slot = slot.saturating_add(1);
            rank
        })
        .collect()
}

/// The canonical occurrence of a set whose members are equally representative.
///
/// A clone group nominates one member as its canonical instance: the copy
/// duplication accounting keeps rather than counts as duplicated. Where
/// similarity picks that member — a Structural group's medoid — this is not
/// needed; where every member shares one content and similarity has nothing to
/// choose between them, the nomination falls to the smallest discriminator, so
/// it follows content and cannot move because a file was renamed or the walk
/// order changed. `None` for an empty set.
#[must_use]
pub fn canonical_occurrence(discriminators: &[OccurrenceDiscriminator]) -> Option<usize> {
    discriminators
        .iter()
        .enumerate()
        .min_by_key(|&(_, discriminator)| discriminator)
        .map(|(index, _)| index)
}

/// What one occurrence of a group's content is identified inside of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OccurrenceScope<'a> {
    /// Inside a code unit, identified by that unit's own content fingerprint.
    Unit(&'a UnitFingerprint),
    /// Outside every unit — a top-level macro, record or global — where the
    /// enclosing file's content stands in for a host. Occurrences in files of
    /// different content therefore rank independently, instead of competing
    /// for one scan-wide sequence that any new copy anywhere would shift.
    File(OccurrenceDiscriminator),
}

impl OccurrenceScope<'_> {
    /// The content-derived discriminator occurrences of this scope rank under.
    #[must_use]
    pub fn discriminator(&self) -> OccurrenceDiscriminator {
        match *self {
            Self::Unit(unit) => OccurrenceDiscriminator::of_unit(unit),
            Self::File(file) => file,
        }
    }
}

/// Identify one occurrence of a group's content.
///
/// Content-identical occurrences share their content fingerprint, so a finding
/// is discriminated by what it sits inside — its host unit's (raw) fingerprint,
/// or, outside every unit, its file's content — plus its occurrence rank
/// *within that scope*. Both inputs are content-relative; neither is a source
/// position.
#[must_use]
pub fn finding_id(
    group: &CloneGroupFingerprint,
    scope: OccurrenceScope<'_>,
    rank_in_scope: u32,
) -> FindingId {
    let mut hasher = IdHasher::new("finding");
    hasher.write_str(FP_SCHEMA_VERSION);
    hasher.write_bytes(&group.0);
    match scope {
        OccurrenceScope::Unit(unit) => {
            hasher.write_u8(1);
            hasher.write_bytes(&unit.0);
        }
        OccurrenceScope::File(file) => {
            hasher.write_u8(2);
            hasher.write_bytes(&file.0);
        }
    }
    hasher.write_u32(rank_in_scope);
    FindingId(hasher.finish())
}

/// Identify an opt-in comparison over the sorted set of origin variants.
///
/// The caller supplies variant fingerprints rather than a synthesized
/// [`BuildVariant`]: comparison members remain attributed to the program that
/// produced them.
#[must_use]
pub fn cross_variant_comparison_id(origins: &[String]) -> CrossVariantComparisonId {
    let mut origins = origins.to_vec();
    origins.sort_unstable();
    origins.dedup();
    let mut hasher = IdHasher::new("cross-variant-comparison");
    hasher.write_str(FP_SCHEMA_VERSION);
    hasher.write_str(CROSS_VARIANT_POLICY_VERSION);
    hasher.write_u32(u32::try_from(origins.len()).unwrap_or(u32::MAX));
    for origin in origins {
        hasher.write_str(&origin);
    }
    CrossVariantComparisonId(hasher.finish())
}

/// Identify an explicit Rust-to-C++ semantic comparison over origin variants.
///
/// The origin list is canonicalised before hashing, while every compared graph
/// retains its own full `BuildVariant` fingerprint. This identifier is only the
/// comparison domain used to prevent unrelated requests from joining.
#[must_use]
pub fn cross_language_comparison_id(origins: &[String]) -> CrossLanguageComparisonId {
    let mut origins = origins.to_vec();
    origins.sort_unstable();
    origins.dedup();
    let mut hasher = IdHasher::new("cross-language-comparison");
    hasher.write_str(FP_SCHEMA_VERSION);
    hasher.write_str(CROSS_LANGUAGE_POLICY_VERSION);
    hasher.write_u32(u32::try_from(origins.len()).unwrap_or(u32::MAX));
    for origin in origins {
        hasher.write_str(&origin);
    }
    CrossLanguageComparisonId(hasher.finish())
}

/// Identify a verified group from an explicit Rust-to-C++ semantic comparison.
///
/// Member fingerprints already include each graph's language, schema and full
/// `BuildVariant` context. The comparison identity, rule revision and sorted
/// member set make this separate from normal semantic and exact-comparison
/// group identities.
#[must_use]
pub fn cross_language_group_id(
    comparison: &CrossLanguageComparisonId,
    rule_id: &str,
    rule_version: u32,
    members: &[FragmentFingerprint],
) -> CrossLanguageGroupId {
    let mut members = members.to_vec();
    members.sort_unstable();
    let mut hasher = IdHasher::new("cross-language-group");
    hasher.write_str(FP_SCHEMA_VERSION);
    hasher.write_str(CROSS_LANGUAGE_POLICY_VERSION);
    hasher.write_bytes(comparison.as_bytes());
    hasher.write_str(rule_id);
    hasher.write_u32(rule_version);
    hasher.write_u32(u32::try_from(members.len()).unwrap_or(u32::MAX));
    for member in members {
        hasher.write_bytes(member.as_bytes());
    }
    CrossLanguageGroupId(hasher.finish())
}

/// Identify an exact group produced by a cross-build-variant comparison.
///
/// `content` is a position-free digest of the matched token stream. The
/// comparison id carries the complete origin-variant set, so adding another
/// compared program cannot silently continue an older comparison's history.
#[must_use]
pub fn cross_variant_group_id(
    comparison: &CrossVariantComparisonId,
    class: CloneClass,
    language: Language,
    content: &[u8; 16],
) -> CrossVariantGroupId {
    let mut hasher = IdHasher::new("cross-variant-group");
    hasher.write_str(FP_SCHEMA_VERSION);
    hasher.write_str(CROSS_VARIANT_POLICY_VERSION);
    hasher.write_bytes(comparison.as_bytes());
    hasher.write_str(class.name());
    hasher.write_str(language.name());
    hasher.write_bytes(content);
    CrossVariantGroupId(hasher.finish())
}

/// Identify one occurrence inside a cross-build-variant group.
///
/// Exact duplicates inside one origin are distinguished by a deterministic
/// occurrence rank, never by their path or line anchor.
#[must_use]
pub fn cross_variant_member_id(
    group: &CrossVariantGroupId,
    origin_variant: &str,
    language: Language,
    occurrence_rank: u32,
) -> CrossVariantMemberId {
    let mut hasher = IdHasher::new("cross-variant-member");
    hasher.write_str(FP_SCHEMA_VERSION);
    hasher.write_str(CROSS_VARIANT_POLICY_VERSION);
    hasher.write_bytes(group.as_bytes());
    hasher.write_str(origin_variant);
    hasher.write_str(language.name());
    hasher.write_u32(occurrence_rank);
    CrossVariantMemberId(hasher.finish())
}

/// Identify one occurrence inside a cross-language semantic group.
#[must_use]
pub fn cross_language_member_id(
    group: &CrossLanguageGroupId,
    origin_variant: &str,
    occurrence: &FragmentFingerprint,
) -> CrossLanguageMemberId {
    let mut hasher = IdHasher::new("cross-language-member");
    hasher.write_str(FP_SCHEMA_VERSION);
    hasher.write_str(CROSS_LANGUAGE_POLICY_VERSION);
    hasher.write_bytes(group.as_bytes());
    hasher.write_str(origin_variant);
    hasher.write_bytes(occurrence.as_bytes());
    CrossLanguageMemberId(hasher.finish())
}

/// Stable identifiers of one group member, parallel to
/// [`CloneGroup::members`](crate::engine::CloneGroup::members).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberIds {
    /// Content fingerprint of the matched slice.
    pub content: FragmentFingerprint,
    /// This occurrence's finding identifier.
    pub finding: FindingId,
}

/// Stable identifiers of one clone group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupIds {
    /// The group's fingerprint.
    pub fingerprint: CloneGroupFingerprint,
    /// Per-member identifiers, in the group's member order.
    pub members: Vec<MemberIds>,
}

/// Compute stable identifiers for every group of an engine report.
///
/// `contexts` runs parallel to `files`. Type-1 groups hash their members
/// raw; Type-2 groups hash them under scope-local normalization with
/// `literals` (the strategy the detection ran with), so the fingerprint
/// captures exactly the identity that made the members a group. The engine
/// this reads reports no gapped clones, so only those two classes occur;
/// gapped groups are identified by
/// [`structural_clone_group_fingerprint`] instead, which anchors on a
/// canonical instance rather than on one shared content.
///
/// Occurrences are scoped before they are ranked (see [`OccurrenceScope`]), so
/// an occurrence outside every unit is discriminated by the content of its own
/// file. Its identity therefore does not depend on how many other occurrences
/// the scan happened to sort ahead of it.
#[must_use]
pub fn report_ids(
    files: &[InputFile<'_>],
    contexts: &[FileContext<'_>],
    variant: &BuildVariant,
    report: &EngineReport,
    literals: LiteralNorm,
) -> Vec<GroupIds> {
    // One file's content digest serves every occurrence outside a unit in it.
    let mut file_discriminators: BTreeMap<usize, OccurrenceDiscriminator> = BTreeMap::new();
    let mut groups = Vec::with_capacity(report.groups.len());
    for group in &report.groups {
        let norm = match group.clone_type {
            CloneClass::Type1 => ContentNorm::Raw,
            CloneClass::Type2 | CloneClass::Type3 | CloneClass::RestrictedSemantic => {
                ContentNorm::Normalized(literals)
            }
        };
        let member_fps: Vec<FragmentFingerprint> = group
            .members
            .iter()
            .map(|member| {
                let file = &files[member.file];
                let tokens = tokens_in_range(file.tokens, member.token_start, member.token_end);
                fragment_fingerprint(variant, &contexts[member.file], "member", tokens, norm)
            })
            .collect();
        let fingerprint = clone_group_fingerprint(variant, group.clone_type, &member_fps);

        let hosts: Vec<Option<UnitFingerprint>> = group
            .members
            .iter()
            .map(|member| {
                member.unit.map(|unit_idx| {
                    let file = &files[member.file];
                    let unit = &file.units[unit_idx];
                    let tokens = tokens_in_range(file.tokens, unit.token_start, unit.token_end);
                    unit_fingerprint(variant, &contexts[member.file], tokens, ContentNorm::Raw)
                })
            })
            .collect();
        #[allow(
            clippy::option_if_let_else,
            reason = "the None arm mutably borrows the memo while the Some arm borrows the host, so the closure form the lint asks for does not type-check"
        )]
        let scopes: Vec<OccurrenceScope<'_>> = group
            .members
            .iter()
            .zip(&hosts)
            .map(|(member, host)| match host {
                Some(unit) => OccurrenceScope::Unit(unit),
                None => {
                    OccurrenceScope::File(*file_discriminators.entry(member.file).or_insert_with(
                        || OccurrenceDiscriminator::of_tokens(files[member.file].tokens),
                    ))
                }
            })
            .collect();

        // Rank each occurrence inside its own scope: content-relative inputs,
        // never source positions and never a scan-wide running count.
        let discriminators: Vec<OccurrenceDiscriminator> =
            scopes.iter().map(OccurrenceScope::discriminator).collect();
        let members = member_fps
            .iter()
            .zip(&scopes)
            .zip(occurrence_ranks(&discriminators))
            .map(|((content, scope), rank)| MemberIds {
                content: *content,
                finding: finding_id(&fingerprint, *scope, rank),
            })
            .collect();
        groups.push(GroupIds {
            fingerprint,
            members,
        });
    }
    groups
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests;
