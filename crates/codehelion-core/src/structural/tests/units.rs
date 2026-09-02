//! Flattening IR trees into units, and what normalization reads.

use super::*;

/// A file whose first walked unit shape covers no token, as a tree cut off at
/// a depth limit leaves one, followed by a unit that covers the file.
fn file_with_a_tokenless_unit(words: &[&str]) -> SyntaxIrFile {
    let mut file = rich_cohesion_file(words);
    file.roots[0].name = Some("kept".into());
    file.roots.insert(
        0,
        IrNode {
            shape: Shape::Function,
            name: Some("tokenless".into()),
            token_start: words.len(),
            token_end: words.len(),
            range: ByteRange { start: 0, end: 0 },
            children: Vec::new(),
        },
    );
    file
}

/// Line numbers are 1-based, so a zero is not a position a reader can look at.
/// A unit shape covering no token has none to report, and reporting it anyway
/// would put a value in the line columns that reads like a place in the file.
#[test]
fn a_unit_shape_covering_no_token_is_not_reported_at_line_zero() {
    let words = ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j"];
    let files = vec![
        file_with_a_tokenless_unit(&words),
        rich_cohesion_file(&words),
    ];
    let variant = BuildVariant::structural(
        LanguageSelection {
            rust: true,
            c: false,
            cpp: false,
        },
        Language::Rust,
    );
    let config = StructuralConfig::default();

    let (units, index) =
        flatten_units(&files, &variant, config.literals, &ResolvedTypes::default());

    assert_eq!(units.len(), 2, "the tokenless shape becomes no unit");
    assert_eq!(
        index.global(0, 0),
        None,
        "a candidate naming the tokenless walk position resolves to no unit"
    );
    assert_eq!(
        index.global(0, 1),
        Some(0),
        "the unit after it keeps its own global index rather than the one before"
    );
    assert_eq!(index.global(1, 0), Some(1));
    let feature_files: Vec<_> = files.iter().map(features::extract).collect();
    assert_eq!(
        feature_files[0].units[units[0].local].name.as_deref(),
        Some("kept"),
        "the recorded unit still addresses its own features"
    );

    let report = crate::structural::analyze(&files, &variant, &config);

    assert_eq!(report.units.len(), 2);
    assert!(
        report
            .units
            .iter()
            .all(|unit| unit.start_line >= 1 && unit.end_line >= 1)
    );
    assert!(
        report
            .regions
            .iter()
            .flat_map(|region| &region.occurrences)
            .all(|occurrence| occurrence.start_line >= 1 && occurrence.end_line >= 1)
    );
}
#[test]
fn compiler_name_resolution_changes_semantic_unit_normalization() {
    let files = vec![cohesion_file(&["external_name"])];
    let variant = BuildVariant::semantic(
        LanguageSelection {
            rust: true,
            c: false,
            cpp: false,
        },
        Language::Rust,
        Vec::new(),
    );
    let (lexical, _) = flatten_units(
        &files,
        &variant,
        LiteralNorm::Full,
        &ResolvedTypes::default(),
    );
    let mut names = Resolution::new();
    names.insert(0, true);
    let resolved = ResolvedTypes::per_file_with_semantic_normalization(
        vec![Vec::new()],
        vec![Vec::new()],
        vec![names],
    );
    let (compiler_aware, _) = flatten_units(&files, &variant, LiteralNorm::Full, &resolved);

    assert_ne!(
        lexical[0].normalized_content,
        compiler_aware[0].normalized_content
    );
    assert_eq!(lexical[0].content, compiler_aware[0].content);
}
