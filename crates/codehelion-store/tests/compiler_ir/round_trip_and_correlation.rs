use super::*;

#[test]
fn everything_a_compiler_answered_comes_back_unchanged() {
    let written = full_analysis(unit_ref("render", "src/render.rs"));
    assert_eq!(round_trip(written.clone()), written);
}
#[test]
fn a_resource_category_survives_the_sqlite_round_trip() {
    let mut written = full_analysis(unit_ref("render", "src/render.rs"));
    written.semantic_constructs.push(SemanticConstruct {
        anchor: Anchor::written_here(range("src/render.rs", 656)),
        kind: SemanticConstructKind::AcquireResource,
        fallible_kind: None,
        direct_propagation: None,
        resource_kind: Some("file".to_owned()),
    });
    written.semantic_constructs.push(SemanticConstruct {
        anchor: Anchor::written_here(range("src/render.rs", 720)),
        kind: SemanticConstructKind::ReleaseResource,
        fallible_kind: None,
        direct_propagation: None,
        resource_kind: Some("file".to_owned()),
    });
    assert_eq!(round_trip(written.clone()), written);
}

#[test]
fn local_resolved_function_anchors_remain_available_for_correlation() {
    let (_dir, mut store, _path) = on_disk();
    let variant = variant();
    let run = store
        .record_snapshot(&snapshot(
            "/tree",
            &variant,
            vec![helper_row()],
            vec![answered(full_analysis(unit_ref("render", "src/render.rs")))],
        ))
        .unwrap();

    assert_eq!(
        store.source_resolved_symbols(run).unwrap(),
        vec![codehelion_store::query::SourceResolvedSymbol {
            name: "render".to_owned(),
            file_path: "src/render.rs".to_owned(),
            line: 1,
            macro_definition: None,
        }]
    );
}

#[test]
fn local_macro_defined_function_anchors_preserve_the_definition_origin() {
    let (_dir, mut store, _path) = on_disk();
    let variant = variant();
    let mut analysis = full_analysis(unit_ref("render", "src/render.rs"));
    analysis.symbols = vec![ResolvedSymbol {
        id: "crate::generated::render".to_owned(),
        name: "render".to_owned(),
        kind: SymbolKind::Function,
        anchor: Anchor {
            expansion: range("src/render.rs", 128),
            definition: Some(range("src/macros.rs", 32)),
        },
        type_index: None,
        external: false,
    }];
    let run = store
        .record_snapshot(&snapshot(
            "/tree",
            &variant,
            vec![helper_row()],
            vec![answered(analysis)],
        ))
        .unwrap();

    assert_eq!(
        store.source_resolved_symbols(run).unwrap(),
        vec![codehelion_store::query::SourceResolvedSymbol {
            name: "render".to_owned(),
            file_path: "src/macros.rs".to_owned(),
            line: 2,
            macro_definition: Some(codehelion_store::query::SourceMacroDefinition {
                file_path: "src/macros.rs".to_owned(),
                line: 2,
            }),
        }]
    );
}

#[test]
fn local_resolved_call_anchors_remain_available_for_correlation() {
    let (_dir, mut store, _path) = on_disk();
    let variant = variant();
    let run = store
        .record_snapshot(&snapshot(
            "/tree",
            &variant,
            vec![helper_row()],
            vec![answered(full_analysis(unit_ref("render", "src/render.rs")))],
        ))
        .unwrap();

    assert_eq!(
        store.source_resolved_calls(run).unwrap(),
        vec![codehelion_store::query::SourceResolvedCall {
            target_name: "crate::escape".to_owned(),
            file_path: "src/render.rs".to_owned(),
            line: 7,
        }]
    );
}

#[test]
fn local_instantiation_anchors_remain_available_for_correlation() {
    let (_dir, mut store, _path) = on_disk();
    let variant = variant();
    let run = store
        .record_snapshot(&snapshot(
            "/tree",
            &variant,
            vec![helper_row()],
            vec![answered(full_analysis(unit_ref("render", "src/render.rs")))],
        ))
        .unwrap();

    assert_eq!(
        store.source_instantiations(run).unwrap(),
        vec![codehelion_store::query::SourceInstantiation {
            definition: "crate::Buffer::push".to_owned(),
            artifact_match_key: None,
            instantiation_key: "crate::Buffer::push<String>".to_owned(),
            file_path: "src/generic.rs".to_owned(),
            line: 4,
            definition_end_line: None,
            translation_unit: "src/render.rs".to_owned(),
        }]
    );
}
