use super::*;

/// The helper reports Rust `?` as a compiler-parsed, closed construct rather
/// than asking the semantic core to infer it from a token sequence.
#[test]
fn an_error_propagation_operator_is_reported_as_a_semantic_construct() {
    let ir = stamped();
    let source = source_of("generic");
    let constructs = ir
        .semantic_constructs
        .iter()
        .filter(|construct| construct.kind == SemanticConstructKind::PropagateError)
        .collect::<Vec<_>>();
    assert_eq!(constructs.len(), 4, "{:?}", ir.semantic_constructs);
    let try_expression_count = constructs
        .iter()
        .filter(|construct| {
            let range = &construct.anchor.expansion;
            let start = usize::try_from(range.start_byte).expect("range start fits");
            let end = usize::try_from(range.end_byte).expect("range end fits");
            source[start..end].ends_with('?')
        })
        .count();
    assert_eq!(try_expression_count, 3, "{:?}", ir.semantic_constructs);
    assert_eq!(constructs[0].fallible_kind, Some(FallibleKind::Option));
}

/// Standard `Result` and `Option` matches, plus direct standard presence
/// conditions, become closed validation constructs. A project enum's branches
/// and compound presence conditions remain outside the vocabulary.
#[test]
fn standard_fallible_matches_are_reported_as_validation_constructs() {
    let ir = stamped();
    let source = source_of("generic");
    let validates = ir
        .semantic_constructs
        .iter()
        .filter(|construct| construct.kind == SemanticConstructKind::Validate)
        .collect::<Vec<_>>();
    assert_eq!(validates.len(), 3, "{:?}", ir.semantic_constructs);
    let spellings = validates
        .iter()
        .map(|construct| {
            let range = &construct.anchor.expansion;
            let start = usize::try_from(range.start_byte).expect("range start fits");
            let end = usize::try_from(range.end_byte).expect("range end fits");
            source[start..end].to_string()
        })
        .collect::<Vec<_>>();
    assert!(
        spellings
            .iter()
            .any(|spelling| spelling.starts_with("match "))
    );
    assert!(
        spellings
            .iter()
            .any(|spelling| spelling.starts_with("if value.is_some()"))
    );
    assert!(
        spellings
            .iter()
            .any(|spelling| spelling.starts_with("if value.is_ok()"))
    );
    assert!(
        spellings
            .iter()
            .all(|spelling| !spelling.contains("&& keep"))
    );
    let kinds = validates
        .iter()
        .map(|construct| construct.fallible_kind)
        .collect::<Vec<_>>();
    assert_eq!(
        kinds,
        vec![
            Some(FallibleKind::Option),
            Some(FallibleKind::Option),
            Some(FallibleKind::Result),
        ]
    );
}

/// Direct `Result` propagation has two deliberately closed spellings. A
/// transformed success value is retained as a normal propagation operation.
#[test]
fn direct_result_propagation_forms_are_reported_without_admitting_transformations() {
    let ir = stamped();
    let source = source_of("generic");
    let direct = ir
        .semantic_constructs
        .iter()
        .filter(|construct| construct.direct_propagation == Some(DirectPropagation::ResultAdapter))
        .collect::<Vec<_>>();
    assert_eq!(direct.len(), 2, "{:?}", ir.semantic_constructs);
    assert!(direct.iter().all(|construct| {
        construct.kind == SemanticConstructKind::PropagateError
            && construct.fallible_kind == Some(FallibleKind::Result)
    }));
    let transformed = ir.semantic_constructs.iter().find(|construct| {
        let range = &construct.anchor.expansion;
        let start = usize::try_from(range.start_byte).expect("range start fits");
        let end = usize::try_from(range.end_byte).expect("range end fits");
        &source[start..end] == "value?"
            && construct.fallible_kind == Some(FallibleKind::Result)
            && construct.direct_propagation.is_none()
    });
    assert!(transformed.is_some(), "{:?}", ir.semantic_constructs);
}

/// A `for` loop only enters the closed vocabulary when it is a compiler-typed
/// standard-sequence to standard-`Vec` transfer of the exact loop binding.
#[test]
fn a_plain_vec_collection_loop_is_reported_without_guessing_transforms() {
    let ir = stamped();
    let source = source_of("generic");
    let loop_constructs = ir
        .semantic_constructs
        .iter()
        .filter(|construct| {
            matches!(
                construct.kind,
                SemanticConstructKind::Source | SemanticConstructKind::Collect
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(loop_constructs.len(), 3, "{:?}", ir.semantic_constructs);
    assert_eq!(loop_constructs[1].kind, SemanticConstructKind::Source);
    assert_eq!(loop_constructs[2].kind, SemanticConstructKind::Collect);
    let source_start =
        usize::try_from(loop_constructs[1].anchor.expansion.start_byte).expect("source start fits");
    let source_end =
        usize::try_from(loop_constructs[1].anchor.expansion.end_byte).expect("source end fits");
    assert_eq!(&source[source_start..source_end], "values");
    let collect_start = usize::try_from(loop_constructs[2].anchor.expansion.start_byte)
        .expect("collect start fits");
    let collect_end =
        usize::try_from(loop_constructs[2].anchor.expansion.end_byte).expect("collect end fits");
    assert_eq!(&source[collect_start..collect_end], "push");
}

/// A direct numeric accumulation is the closed loop counterpart of an
/// iterator reduction. The conditional loop in the same fixture remains
/// outside this form: a guard changes which values reach the accumulator.
#[test]
fn a_plain_numeric_reduce_loop_is_reported_without_admitting_guards() {
    let ir = stamped();
    let source = source_of("generic");
    let reductions = ir
        .semantic_constructs
        .iter()
        .filter(|construct| construct.kind == SemanticConstructKind::Reduce)
        .collect::<Vec<_>>();
    assert_eq!(reductions.len(), 1, "{:?}", ir.semantic_constructs);
    let source_construct = ir
        .semantic_constructs
        .iter()
        .find(|construct| {
            construct.kind == SemanticConstructKind::Source
                && construct.anchor.expansion.start_line
                    == reductions[0].anchor.expansion.start_line.saturating_sub(1)
        })
        .expect("the reduction retains its immediately preceding sequence source");
    let source_start =
        usize::try_from(source_construct.anchor.expansion.start_byte).expect("source start fits");
    let source_end =
        usize::try_from(source_construct.anchor.expansion.end_byte).expect("source end fits");
    assert_eq!(&source[source_start..source_end], "values");
    let reduce_start =
        usize::try_from(reductions[0].anchor.expansion.start_byte).expect("reduce start fits");
    let reduce_end =
        usize::try_from(reductions[0].anchor.expansion.end_byte).expect("reduce end fits");
    assert_eq!(&source[reduce_start..reduce_end], "sum += *value");
}

/// A direct standard-file binding has one compiler-resolved acquisition and a
/// Rust scope-end `Drop`. A function holding two files remains absent rather
/// than being reduced to a guessed pair.
#[test]
fn a_direct_standard_file_acquisition_is_paired_with_its_scope_drop() {
    let ir = analyzed(&unit("plain", "ledger", "ledger"));
    assert!(ir.effects.computed);
    assert_eq!(ir.effects.interactions, ["file_io"]);
    assert!(ir.effects.writes.is_empty());
    let lifetimes = ir
        .semantic_constructs
        .iter()
        .filter(|construct| {
            matches!(
                construct.kind,
                SemanticConstructKind::AcquireResource | SemanticConstructKind::ReleaseResource
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(lifetimes.len(), 2, "{:?}", ir.semantic_constructs);
    assert_eq!(lifetimes[0].kind, SemanticConstructKind::AcquireResource);
    assert_eq!(lifetimes[1].kind, SemanticConstructKind::ReleaseResource);
    assert!(
        lifetimes
            .iter()
            .all(|construct| construct.resource_kind.as_deref() == Some("file"))
    );
    assert!(lifetimes[0].anchor.expansion.start_byte < lifetimes[1].anchor.expansion.start_byte);
    let source = std::fs::read_to_string(
        codehelion_fixtures::rust("plain")
            .expect("plain fixture exists")
            .join("ledger/src/lib.rs"),
    )
    .expect("plain fixture source is readable");
    let two_files = source
        .find("pub fn inspect_two_files")
        .expect("fixture holds the multi-resource negative case");
    assert!(lifetimes.iter().all(|construct| {
        usize::try_from(construct.anchor.expansion.start_byte).is_ok_and(|start| start < two_files)
    }));
}
