//! Literal digests of every identifier recipe, so a change to a hash input,
//! its encoding or its order cannot pass unnoticed.
//!
//! These are long-lived identity keys: they name rows in every audit database
//! on disk, every committed baseline and every configured clone id. Relative
//! comparisons cannot see a hasher rewrite that moves all of them together,
//! which is precisely the change that invalidates stored history while the
//! recorded detector version still claims compatibility.
//!
//! Every constructor in this module has a row here, so adding one means
//! adding a row. Every value below is the digest of the fixture named beside
//! it. Changing a
//! domain tag, the field order in [`IdHasher::write_context`], a
//! [`ContentNorm::label`], a [`NormAtom`] discriminant, the length prefixing,
//! the hash algorithm or the truncation width moves at least one of them.

use super::*;

/// Every recipe under one fixed set of inputs, keyed by the identifier it
/// produces. The fixtures are deliberately small: one seven-token
/// statement, one two-operation graph and two named origin variants.
const RECIPES: &[(&str, &str)] = &[
    ("unit/raw", "689cdefab804c6f24f3c5345446a1c4d"),
    ("unit/normalized", "9baa2adf8056a522153154e60393bd5b"),
    (
        "unit/raw/structural-variant",
        "0015db42c13098a743722fd0d4f4e3be",
    ),
    ("fragment/raw", "dce9b0e272cce8ed7087e2d23c678069"),
    ("fragment/normalized", "2e0dcf4c8169cb3b0ddcf84274e10986"),
    (
        "fragment/normalized-literal-category",
        "3a6d9d072723a733bff5df4a68f25bb8",
    ),
    (
        "fragment/resolved-normalized",
        "c86908ad9f0559111c9a870a42085e1d",
    ),
    ("fragment/semantic", "0e509c4b2ebdc1f89146f3808c587610"),
    (
        "fragment/semantic-occurrence",
        "167ac343dfbdcaafec94ae29987f42bc",
    ),
    (
        "semantic-source-structure",
        "7b08c9008d02b39a8937952ae474a6b0",
    ),
    ("group/exact", "9935e39ca6d1704796d3f6154e3c7a86"),
    ("group/structural", "5e5aafde805206ea470409037e0a8484"),
    ("group/semantic", "6cda7c75620e742ffc9c619149be49b2"),
    ("group-lineage", "d935a760b7b58b6ed4d7583d812a2083"),
    ("occurrence/tokens", "04bc4899e55afb6a38e81a9ee5e069e4"),
    ("occurrence/unit", "ca8da0431af8266dbd15f26479bb6555"),
    ("occurrence/fragment", "df2b6109841c444d0c39c8a44ee3e9c1"),
    ("occurrence/finding", "5fce062c3959385b5e8bf406124d835c"),
    ("occurrence/pair", "342c168d89f6caba98565f2e416f49ed"),
    ("finding", "f71e71af3b692afdcd12c56d15ce20ab"),
    ("finding/outside-units", "7ac55433389a44dfdd2c0f82da6a132e"),
    (
        "cross-variant/comparison",
        "259aa78892a91311fa96b6acd0a10a6e",
    ),
    ("cross-variant/group", "7f4eaff88f85b99467d02c18aef039e4"),
    ("cross-variant/member", "32383a2544344d0598e34efeba5d263b"),
    (
        "cross-language/comparison",
        "2c3333f53aac9cbc32f0d86670226092",
    ),
    ("cross-language/group", "cfe87596aea9f3377db91718f0ac6680"),
    ("cross-language/member", "9016b35747fb9718df7adb509cd49682"),
];

/// The two origin variants every cross-program identity below is taken
/// over.
const ORIGINS: [&str; 2] = ["cpp-release", "rust-release"];

/// Matched content a cross-variant group is built over, a fixed byte
/// pattern so that recipe is read from this table and not from another.
const CROSS_VARIANT_CONTENT: [u8; 16] = [0xa5; 16];

/// Lowercase hex of a bare digest, matching the newtypes' `Display`.
fn hex(bytes: &[u8; 16]) -> String {
    use core::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

/// A build variant differing from [`variant`] in analysis mode alone, so
/// the pair of `unit/raw` rows shows the variant reaching the digest.
fn structural_variant() -> BuildVariant {
    BuildVariant::structural(LanguageSelection::default(), Language::C)
}

/// A fixed two-operation graph. The observation offsets are source
/// positions and must not reach any digest.
fn semantic_graph() -> SemanticOperationGraph {
    normalize_registered_apis(
        Language::Rust,
        [13; 32],
        vec![
            OperationObservation {
                source_offset: 5,
                api_name: "rust::Iterator::filter".to_owned(),
                type_tag: None,
            },
            OperationObservation {
                source_offset: 6,
                api_name: "rust::Iterator::collect".to_owned(),
                type_tag: None,
            },
        ],
    )
    .expect("registered observations normalize")
    .graph
    .expect("registered observations produce a graph")
}

/// Compute every row of [`RECIPES`] from `tokens`, which the caller may
/// have moved: the content is what the digests are of, and where it sits
/// is not.
#[allow(
    clippy::too_many_lines,
    reason = "one table row per recipe, read beside the recorded table"
)]
fn recipes_of(tokens: &[Token]) -> Vec<(&'static str, String)> {
    let variant = variant();
    let file = ctx();
    let other_tokens = renamed_sample();

    let unit_raw = unit_fingerprint(&variant, &file, tokens, ContentNorm::Raw);
    let fragment_raw = fragment_fingerprint(&variant, &file, "member", tokens, ContentNorm::Raw);
    let other_fragment =
        fragment_fingerprint(&variant, &file, "member", &other_tokens, ContentNorm::Raw);
    let semantic_fragment = semantic_fragment_fingerprint(&variant, &semantic_graph());
    let group =
        clone_group_fingerprint(&variant, CloneClass::Type1, &[fragment_raw, other_fragment]);
    let origins = ORIGINS.map(str::to_owned).to_vec();
    let cross_variant_comparison = cross_variant_comparison_id(&origins);
    let cross_variant_group = cross_variant_group_id(
        &cross_variant_comparison,
        CloneClass::Type1,
        Language::Rust,
        &CROSS_VARIANT_CONTENT,
    );
    let cross_language_comparison = cross_language_comparison_id(&origins);
    let cross_language_group = cross_language_group_id(
        &cross_language_comparison,
        "cross-language-sequence-pipeline-v1",
        1,
        &[semantic_fragment],
    );

    vec![
        ("unit/raw", unit_raw.to_hex()),
        (
            "unit/normalized",
            unit_fingerprint(
                &variant,
                &file,
                tokens,
                ContentNorm::Normalized(LiteralNorm::Full),
            )
            .to_hex(),
        ),
        (
            "unit/raw/structural-variant",
            unit_fingerprint(&structural_variant(), &file, tokens, ContentNorm::Raw).to_hex(),
        ),
        ("fragment/raw", fragment_raw.to_hex()),
        (
            "fragment/normalized",
            fragment_fingerprint(
                &variant,
                &file,
                "member",
                tokens,
                ContentNorm::Normalized(LiteralNorm::Full),
            )
            .to_hex(),
        ),
        (
            "fragment/normalized-literal-category",
            fragment_fingerprint(
                &variant,
                &file,
                "member",
                tokens,
                ContentNorm::Normalized(LiteralNorm::Category),
            )
            .to_hex(),
        ),
        (
            "fragment/resolved-normalized",
            resolved_fragment_fingerprint(
                &variant,
                &file,
                "member",
                tokens,
                ContentNorm::ResolvedNormalized(LiteralNorm::Full),
                None,
            )
            .to_hex(),
        ),
        ("fragment/semantic", semantic_fragment.to_hex()),
        (
            "fragment/semantic-occurrence",
            semantic_occurrence_fingerprint(fragment_raw, &unit_raw, 0).to_hex(),
        ),
        (
            "semantic-source-structure",
            hex(&semantic_structure_fingerprint(&variant, &file, tokens)),
        ),
        ("group/exact", group.to_hex()),
        (
            "group/structural",
            structural_clone_group_fingerprint(
                &variant,
                CloneClass::Type3,
                &fragment_raw,
                &[fragment_raw, other_fragment],
            )
            .to_hex(),
        ),
        (
            "group/semantic",
            semantic_clone_group_fingerprint(
                &variant,
                "sequence-pipeline-v1",
                1,
                &[semantic_fragment],
            )
            .to_hex(),
        ),
        ("group-lineage", group_lineage_id(&group).to_hex()),
        (
            "occurrence/tokens",
            hex(OccurrenceDiscriminator::of_tokens(tokens).as_bytes()),
        ),
        (
            "occurrence/unit",
            hex(OccurrenceDiscriminator::of_unit(&unit_raw).as_bytes()),
        ),
        (
            "occurrence/fragment",
            hex(OccurrenceDiscriminator::of_fragment(&fragment_raw).as_bytes()),
        ),
        (
            "occurrence/finding",
            hex(OccurrenceDiscriminator::of_finding(&finding_id(
                &group,
                OccurrenceScope::Unit(&unit_raw),
                0,
            ))
            .as_bytes()),
        ),
        (
            "occurrence/pair",
            hex(OccurrenceDiscriminator::of_unit(&unit_raw)
                .and(OccurrenceDiscriminator::of_fragment(&fragment_raw))
                .as_bytes()),
        ),
        (
            "finding",
            finding_id(&group, OccurrenceScope::Unit(&unit_raw), 0).to_hex(),
        ),
        (
            "finding/outside-units",
            finding_id(
                &group,
                OccurrenceScope::File(OccurrenceDiscriminator::of_tokens(tokens)),
                0,
            )
            .to_hex(),
        ),
        (
            "cross-variant/comparison",
            cross_variant_comparison.to_hex(),
        ),
        ("cross-variant/group", cross_variant_group.to_hex()),
        (
            "cross-variant/member",
            cross_variant_member_id(&cross_variant_group, "rust-release", Language::Rust, 0)
                .to_hex(),
        ),
        (
            "cross-language/comparison",
            cross_language_comparison.to_hex(),
        ),
        ("cross-language/group", cross_language_group.to_hex()),
        (
            "cross-language/member",
            cross_language_member_id(&cross_language_group, "rust-release", &semantic_fragment)
                .to_hex(),
        ),
    ]
}

/// The recorded table as owned rows, for comparison against a computed one.
fn recorded() -> Vec<(&'static str, String)> {
    RECIPES
        .iter()
        .map(|&(name, digest)| (name, digest.to_owned()))
        .collect()
}

/// The recorded digest of one recipe, by the name it is listed under.
fn recorded_digest(wanted: &str) -> String {
    RECIPES
        .iter()
        .find(|(name, _)| *name == wanted)
        .map(|&(_, digest)| digest.to_owned())
        .expect("the table lists this recipe")
}

/// The context every recipe hashes under, spelled out so a digest that
/// moves can be read as a recipe change rather than a fixture change.
#[test]
fn the_recorded_digests_name_the_context_they_were_taken_under() {
    assert_eq!(FP_SCHEMA_VERSION, "fp-schema-v1");
    assert_eq!(HASH_ALGORITHM, "blake3-128");
    assert_eq!(CROSS_VARIANT_POLICY_VERSION, "cross-variant-exact-v1");
    assert_eq!(CROSS_LANGUAGE_POLICY_VERSION, "cross-language-semantic-v1");
    assert_eq!(
        variant().canonical(),
        "mode=fast;languages=rust,c,cpp;headers=c;normalization=1"
    );
    assert_eq!(
        structural_variant().canonical(),
        "mode=structural;languages=rust,c,cpp;headers=c;normalization=1"
    );
    assert_eq!(ctx().frontend_version, "test-lexer-v1");
    assert_eq!(ctx().language.name(), "rust");
}

#[test]
fn every_identifier_recipe_matches_its_recorded_digest() {
    assert_eq!(recipes_of(&sample()), recorded());
}

/// Two runs that differ only in analysis mode land on different digests,
/// and on the two the table records: the build variant reaches the hash
/// rather than merely accompanying it.
#[test]
fn one_build_variant_apart_is_one_digest_apart() {
    let tokens = sample();
    let fast = unit_fingerprint(&variant(), &ctx(), &tokens, ContentNorm::Raw);
    let structural = unit_fingerprint(&structural_variant(), &ctx(), &tokens, ContentNorm::Raw);
    assert_ne!(
        fast, structural,
        "one content read under two build variants is two identities"
    );
    assert_eq!(fast.to_hex(), recorded_digest("unit/raw"));
    assert_eq!(
        structural.to_hex(),
        recorded_digest("unit/raw/structural-variant")
    );
}

/// Line numbers, byte offsets and the index a unit happens to occupy in
/// its file are reporting data, never identity. Moving the same content
/// leaves every recorded digest where it is.
///
/// This is the mechanical form of the rule that separates anchors from
/// identifiers: an identifier changes only when the content or the
/// analysis context does.
#[test]
fn moving_content_leaves_every_recorded_digest_unchanged() {
    let mut moved = sample();
    for token in &mut moved {
        token.span.start_byte += 4_096;
        token.span.end_byte += 4_096;
        token.span.start_line += 137;
        token.span.start_column += 9;
    }
    assert_eq!(recipes_of(&moved), recorded());
}

/// The same for a whole scan's identifiers: one unit read at the head of
/// a file and again deep inside a larger one, at different lines and
/// different token indices, is one identity.
#[test]
fn a_relocated_unit_keeps_its_group_and_finding_identifiers() {
    // Recorded so the recipe behind a scan's reported ids is fixed too,
    // not only the recipe behind each identifier in isolation.
    const GROUP: &str = "65c474904ea6b8415eb016e4a6f96855";
    const FINDING: &str = "50e01cb21fc32d2bbcbbdfc6c1409849";

    let ids = |ids: &[GroupIds]| {
        ids.iter()
            .map(|group| {
                (
                    group.fingerprint.to_hex(),
                    group
                        .members
                        .iter()
                        .map(|member| (member.content.to_hex(), member.finding.to_hex()))
                        .collect::<Vec<_>>(),
                )
            })
            .collect::<Vec<_>>()
    };

    let head = ids(&report_ids(
        &[relocated_file(0, 1).as_input()],
        &[ctx()],
        &variant(),
        &relocated_report(0, 1),
        LiteralNorm::Full,
    ));
    let deep = ids(&report_ids(
        &[relocated_file(11, 900).as_input()],
        &[ctx()],
        &variant(),
        &relocated_report(11, 900),
        LiteralNorm::Full,
    ));

    assert_eq!(head, deep);
    assert_eq!(head.len(), 1);
    assert_eq!(head[0].0, GROUP);
    assert_eq!(
        head[0].1,
        vec![(recorded_digest("fragment/raw"), FINDING.to_owned())],
        "a reported member carries the digest the fragment recipe takes \
         directly"
    );
}

/// Tokens and units of one file, holding the borrowed slices an
/// [`InputFile`] points into.
struct RelocatedFile {
    tokens: Vec<Token>,
    units: Vec<crate::frontend::Unit>,
}

impl RelocatedFile {
    fn as_input(&self) -> InputFile<'_> {
        InputFile {
            tokens: &self.tokens,
            units: &self.units,
        }
    }
}

/// The sample statement as a single unit, preceded by `pad` unrelated
/// tokens and starting at line `line`.
fn relocated_file(pad: usize, line: u32) -> RelocatedFile {
    const PADDING: [(TokenKind, &str); 4] = [(Kw, "fn"), (Id, "unrelated"), (Pu, "("), (Pu, ")")];
    let padding: Vec<(TokenKind, &str)> = PADDING.iter().copied().cycle().take(pad).collect();
    let mut tokens = toks(&padding);
    let unit_start = tokens.len();
    tokens.extend(sample());
    for token in &mut tokens {
        token.span.start_line += line;
    }
    let units = vec![crate::frontend::Unit {
        kind: crate::frontend::UnitKind::Function,
        name: None,
        token_start: unit_start,
        token_end: tokens.len(),
        span: SourceSpan {
            start_byte: 0,
            end_byte: 0,
            start_line: line,
            start_column: 1,
        },
    }];
    RelocatedFile { tokens, units }
}

/// One Type-1 group over the relocated file's only unit.
fn relocated_report(pad: usize, line: u32) -> EngineReport {
    EngineReport {
        groups: vec![crate::engine::CloneGroup {
            content_key: 0,
            clone_type: CloneClass::Type1,
            score: 1.0,
            members: vec![crate::engine::Instance {
                file: 0,
                token_start: pad,
                token_end: pad + sample().len(),
                start_line: line,
                end_line: line + 6,
                unit: Some(0),
            }],
            entropy_bits: 0.0,
            suppressed: None,
        }],
        stats: crate::engine::EngineStats::default(),
    }
}
