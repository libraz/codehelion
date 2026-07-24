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

use crate::discovery::{BuildVariant, Language};
use crate::engine::normalize::{self, LiteralNorm, NormAtom};
use crate::engine::{CloneType, EngineReport, InputFile};
use crate::frontend::Token;

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
    /// Identifier of one finding: a specific occurrence of a group's content,
    /// discriminated by its host unit and an in-host occurrence rank rather
    /// than by any source position.
    FindingId
);
stable_id!(
    /// Identifier tying a clone group's history together across scans even as
    /// its membership drifts. Defined now so schemas can carry the column;
    /// population (member-overlap lineage) is a later-phase concern.
    GroupLineageId
);

/// How content is folded before hashing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentNorm {
    /// Kind tags plus raw lexeme text: Type-1 identity.
    Raw,
    /// Scope-local alpha renaming with the given literal strategy: Type-2
    /// identity (see [`normalize`]).
    Normalized(LiteralNorm),
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
    fn write_content(&mut self, tokens: &[Token], norm: ContentNorm) {
        match norm {
            ContentNorm::Raw => {
                for token in tokens {
                    self.write_u8(token.kind.tag());
                    self.write_bytes(token.text.as_bytes());
                }
            }
            ContentNorm::Normalized(literals) => {
                for norm_token in normalize::normalize(tokens, literals) {
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
    hasher.write_content(tokens, norm);
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
    hasher.write_content(tokens, norm);
    FragmentFingerprint(hasher.finish())
}

/// Fingerprint a clone group from its members' content fingerprints.
///
/// Member fingerprints are sorted and deduplicated first, so the digest is
/// independent of member order and of how many occurrences share identical
/// content: adding another copy of known content leaves the group fingerprint
/// unchanged, while genuinely new member content changes it. Continuity
/// across membership drift is [`GroupLineageId`]'s job, not proximity of
/// group fingerprints.
#[must_use]
pub fn clone_group_fingerprint(
    variant: &BuildVariant,
    clone_type: CloneType,
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

/// Identify one occurrence of a group's content.
///
/// Content-identical occurrences share their content fingerprint, so a
/// finding is discriminated by its host unit's (raw) fingerprint plus its
/// occurrence rank *within that host* — content-relative inputs, not source
/// positions. An occurrence outside any unit uses an absent-host marker; two
/// such occurrences are then told apart by rank alone, which is the weakest
/// (but position-free) discriminator available at this layer.
#[must_use]
pub fn finding_id(
    group: &CloneGroupFingerprint,
    host: Option<&UnitFingerprint>,
    rank_in_host: u32,
) -> FindingId {
    let mut hasher = IdHasher::new("finding");
    hasher.write_str(FP_SCHEMA_VERSION);
    hasher.write_bytes(&group.0);
    match host {
        Some(unit) => {
            hasher.write_u8(1);
            hasher.write_bytes(&unit.0);
        }
        None => hasher.write_u8(0),
    }
    hasher.write_u32(rank_in_host);
    FindingId(hasher.finish())
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
/// captures exactly the identity that made the members a group.
#[must_use]
pub fn report_ids(
    files: &[InputFile<'_>],
    contexts: &[FileContext<'_>],
    variant: &BuildVariant,
    report: &EngineReport,
    literals: LiteralNorm,
) -> Vec<GroupIds> {
    report
        .groups
        .iter()
        .map(|group| {
            let norm = match group.clone_type {
                CloneType::Type1 => ContentNorm::Raw,
                CloneType::Type2 => ContentNorm::Normalized(literals),
            };
            let member_fps: Vec<FragmentFingerprint> = group
                .members
                .iter()
                .map(|member| {
                    let tokens = &files[member.file].tokens[member.token_start..member.token_end];
                    fragment_fingerprint(variant, &contexts[member.file], "member", tokens, norm)
                })
                .collect();
            let fingerprint = clone_group_fingerprint(variant, group.clone_type, &member_fps);

            // Rank occurrences within their host unit, in member order (which
            // is deterministic); the rank is content-relative, not positional.
            let hosts: Vec<Option<UnitFingerprint>> = group
                .members
                .iter()
                .map(|member| {
                    member.unit.map(|unit_idx| {
                        let unit = &files[member.file].units[unit_idx];
                        let tokens = &files[member.file].tokens
                            [unit.token_start..unit.token_end.min(files[member.file].tokens.len())];
                        unit_fingerprint(variant, &contexts[member.file], tokens, ContentNorm::Raw)
                    })
                })
                .collect();
            let members = member_fps
                .iter()
                .zip(hosts.iter())
                .enumerate()
                .map(|(i, (content, host))| {
                    let rank = hosts[..i].iter().filter(|h| *h == host).count();
                    MemberIds {
                        content: *content,
                        finding: finding_id(
                            &fingerprint,
                            host.as_ref(),
                            u32::try_from(rank).unwrap_or(u32::MAX),
                        ),
                    }
                })
                .collect();
            GroupIds {
                fingerprint,
                members,
            }
        })
        .collect()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::discovery::LanguageSelection;
    use crate::frontend::{LiteralKind, SourceSpan, TokenKind};

    fn variant() -> BuildVariant {
        BuildVariant::fast(LanguageSelection::default())
    }

    fn ctx() -> FileContext<'static> {
        FileContext {
            frontend_version: "test-lexer-v0",
            language: Language::Rust,
        }
    }

    /// Build a token stream from `(kind, text)` pairs; spans are dummies and
    /// must never influence any identifier.
    fn toks(spec: &[(TokenKind, &str)]) -> Vec<Token> {
        spec.iter()
            .enumerate()
            .map(|(i, (kind, text))| Token {
                kind: *kind,
                text: (*text).to_string(),
                span: SourceSpan {
                    start_byte: i * 7,
                    end_byte: i * 7 + 1,
                    start_line: u32::try_from(i).unwrap() + 1,
                    start_column: 1,
                },
            })
            .collect()
    }

    use TokenKind::{Identifier as Id, Keyword as Kw, Punctuation as Pu};
    const INT: TokenKind = TokenKind::Literal(LiteralKind::Integer);

    fn sample() -> Vec<Token> {
        toks(&[
            (Kw, "let"),
            (Id, "total"),
            (Pu, "="),
            (Id, "base"),
            (Pu, "+"),
            (INT, "1"),
            (Pu, ";"),
        ])
    }

    fn renamed_sample() -> Vec<Token> {
        toks(&[
            (Kw, "let"),
            (Id, "sum"),
            (Pu, "="),
            (Id, "seed"),
            (Pu, "+"),
            (INT, "2"),
            (Pu, ";"),
        ])
    }

    #[test]
    fn hex_form_is_32_lowercase_chars_and_bytes_roundtrip() {
        let fp = unit_fingerprint(&variant(), &ctx(), &sample(), ContentNorm::Raw);
        let hex = fp.to_hex();
        assert_eq!(hex.len(), 32);
        assert!(
            hex.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
        assert_eq!(UnitFingerprint::from_bytes(*fp.as_bytes()), fp);
    }

    #[test]
    fn spans_never_influence_identifiers() {
        let mut moved = sample();
        for token in &mut moved {
            token.span.start_byte += 1000;
            token.span.start_line += 50;
        }
        assert_eq!(
            unit_fingerprint(&variant(), &ctx(), &sample(), ContentNorm::Raw),
            unit_fingerprint(&variant(), &ctx(), &moved, ContentNorm::Raw),
        );
    }

    #[test]
    fn raw_and_normalized_digests_are_distinct_domains() {
        let tokens = sample();
        let raw = unit_fingerprint(&variant(), &ctx(), &tokens, ContentNorm::Raw);
        let norm = unit_fingerprint(
            &variant(),
            &ctx(),
            &tokens,
            ContentNorm::Normalized(LiteralNorm::Full),
        );
        assert_ne!(raw.as_bytes(), norm.as_bytes());
    }

    #[test]
    fn unit_and_fragment_digests_of_equal_content_differ() {
        let tokens = sample();
        let unit = unit_fingerprint(&variant(), &ctx(), &tokens, ContentNorm::Raw);
        let fragment =
            fragment_fingerprint(&variant(), &ctx(), "member", &tokens, ContentNorm::Raw);
        assert_ne!(unit.as_bytes(), fragment.as_bytes());
    }

    #[test]
    fn consistent_renames_survive_normalized_fingerprints_only() {
        let a = sample();
        let b = renamed_sample();
        assert_ne!(
            unit_fingerprint(&variant(), &ctx(), &a, ContentNorm::Raw),
            unit_fingerprint(&variant(), &ctx(), &b, ContentNorm::Raw),
        );
        assert_eq!(
            unit_fingerprint(
                &variant(),
                &ctx(),
                &a,
                ContentNorm::Normalized(LiteralNorm::Full)
            ),
            unit_fingerprint(
                &variant(),
                &ctx(),
                &b,
                ContentNorm::Normalized(LiteralNorm::Full)
            ),
        );
    }

    #[test]
    fn context_changes_change_the_digest() {
        let tokens = sample();
        let base = unit_fingerprint(&variant(), &ctx(), &tokens, ContentNorm::Raw);
        let other_frontend = FileContext {
            frontend_version: "test-lexer-v1",
            ..ctx()
        };
        assert_ne!(
            base,
            unit_fingerprint(&variant(), &other_frontend, &tokens, ContentNorm::Raw)
        );
        let other_language = FileContext {
            language: Language::C,
            ..ctx()
        };
        assert_ne!(
            base,
            unit_fingerprint(&variant(), &other_language, &tokens, ContentNorm::Raw)
        );
    }

    #[test]
    fn group_fingerprint_is_order_independent_and_deduplicated() {
        let a = fragment_fingerprint(&variant(), &ctx(), "member", &sample(), ContentNorm::Raw);
        let b = fragment_fingerprint(
            &variant(),
            &ctx(),
            "member",
            &renamed_sample(),
            ContentNorm::Raw,
        );
        let forward = clone_group_fingerprint(&variant(), CloneType::Type1, &[a, b]);
        let reversed = clone_group_fingerprint(&variant(), CloneType::Type1, &[b, a]);
        assert_eq!(forward, reversed);
        // Another copy of known content leaves the fingerprint unchanged.
        let duplicated = clone_group_fingerprint(&variant(), CloneType::Type1, &[a, b, a]);
        assert_eq!(forward, duplicated);
        // New member content changes it.
        let single = clone_group_fingerprint(&variant(), CloneType::Type1, &[a]);
        assert_ne!(forward, single);
    }

    #[test]
    fn finding_ids_discriminate_host_and_rank() {
        let group = clone_group_fingerprint(
            &variant(),
            CloneType::Type1,
            &[fragment_fingerprint(
                &variant(),
                &ctx(),
                "member",
                &sample(),
                ContentNorm::Raw,
            )],
        );
        let host = unit_fingerprint(&variant(), &ctx(), &sample(), ContentNorm::Raw);
        let first = finding_id(&group, Some(&host), 0);
        let second = finding_id(&group, Some(&host), 1);
        let hostless = finding_id(&group, None, 0);
        assert_ne!(first, second);
        assert_ne!(first, hostless);
        // Deterministic: same inputs, same id.
        assert_eq!(first, finding_id(&group, Some(&host), 0));
    }
}
