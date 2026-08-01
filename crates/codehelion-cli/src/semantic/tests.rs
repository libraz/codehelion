use super::*;
use codehelion_core::semantic::OperationEdgeKind;
use codehelion_helper::ir::{
    Anchor, CallTarget, FallibleKind as HelperFallibleKind, ResolvedExpression, ResolvedSymbol,
    ResolvedType, SemanticConstruct, SemanticConstructKind, SourceRange, SymbolKind, TypeCategory,
    UnexpandedMacro, UnexpandedMacroReason, UnitRef,
};

fn symbol(name: &str, file: &str, start: u64, width: u64, external: bool) -> ResolvedSymbol {
    ResolvedSymbol {
        id: format!("{file}::{name}@{start}"),
        name: name.to_string(),
        kind: SymbolKind::Binding,
        anchor: Anchor::written_here(SourceRange {
            file: file.to_string(),
            start_byte: start,
            end_byte: start + width,
            start_line: 1,
        }),
        type_index: None,
        external,
    }
}

fn ir(symbols: Vec<ResolvedSymbol>) -> CompilerIr {
    let mut ir = CompilerIr::empty(UnitRef {
        unit: "ledger".into(),
        file: "src/lib.rs".into(),
        variant: "host".into(),
    });
    ir.symbols = symbols;
    ir
}

#[test]
fn a_name_keeps_the_verdict_it_was_given() {
    let analysis = ir(vec![
        symbol("String", "src/lib.rs", 10, 6, true),
        symbol("total", "src/lib.rs", 40, 5, false),
    ]);
    let resolution = resolution_for(&analysis, "src/lib.rs");
    assert!(!resolution.is_empty());
    // Round-tripped through the type's own accessor rather than its
    // internals, because what a caller can see is what has to be right.
    assert_eq!(resolution, {
        let mut expected = Resolution::new();
        expected.insert(10, true);
        expected.insert(40, false);
        expected
    });
}

#[test]
fn compiler_ir_api_facts_cross_the_protocol_boundary_into_sog() {
    let mut analysis = ir(Vec::new());
    analysis.calls.push(CallSite {
        anchor: Anchor::written_here(SourceRange {
            file: "src/lib.rs".to_owned(),
            start_byte: 12,
            end_byte: 20,
            start_line: 1,
        }),
        target: CallTarget::Static {
            symbol: "Iterator::filter".to_owned(),
        },
        api_name: Some("rust::Iterator::filter".to_owned()),
    });
    let normalized = registered_sog_for(&analysis, "src/lib.rs", Language::Rust, [9; 32])
        .expect("adapter only forwards validated core observations");
    let graph = normalized.graph.expect("registered API produces SOG");
    assert_eq!(graph.nodes.len(), 1);
    assert_eq!(graph.nodes[0].kind.name(), "filter");
}

#[test]
fn compiler_confirmed_api_name_overrides_an_opaque_call_identity() {
    let mut analysis = ir(Vec::new());
    analysis.calls.push(CallSite {
        anchor: Anchor::written_here(SourceRange {
            file: "src/lib.rs".to_owned(),
            start_byte: 12,
            end_byte: 20,
            start_line: 1,
        }),
        target: CallTarget::Static {
            symbol: "c:@N@std@S@vector@F@push_back#".to_owned(),
        },
        api_name: Some("std::push_back".to_owned()),
    });
    let normalized = registered_sog_for(&analysis, "src/lib.rs", Language::Cpp, [15; 32])
        .expect("adapter only forwards compiler-confirmed API names");
    let graph = normalized.graph.expect("recognized C++ API produces a SOG");
    assert_eq!(graph.nodes[0].kind, OperationKind::Collect);
    assert_eq!(
        graph.nodes[0].attributes.api_names,
        BTreeSet::from(["std::push_back".to_owned()])
    );
}

#[test]
fn a_call_target_function_type_is_not_pipeline_value_type_evidence() {
    let mut analysis = ir(Vec::new());
    analysis.types.push(ResolvedType {
        display: "fn(&[u64]) -> Vec<u64>".into(),
        category: TypeCategory::Callable,
        arguments: Vec::new(),
        definition: None,
    });
    analysis.expressions.push(ResolvedExpression {
        anchor: Anchor::written_here(SourceRange {
            file: "src/lib.rs".to_owned(),
            start_byte: 12,
            end_byte: 20,
            start_line: 1,
        }),
        type_index: 0,
    });
    analysis.calls.push(CallSite {
        anchor: Anchor::written_here(SourceRange {
            file: "src/lib.rs".to_owned(),
            start_byte: 12,
            end_byte: 20,
            start_line: 1,
        }),
        target: CallTarget::Static {
            symbol: "Iterator::collect".to_owned(),
        },
        api_name: Some("rust::Iterator::collect".to_owned()),
    });

    let normalized = registered_sog_for(&analysis, "src/lib.rs", Language::Rust, [16; 32])
        .expect("adapter only forwards validated core observations");
    let graph = normalized.graph.expect("registered API produces a SOG");
    assert_eq!(graph.nodes.len(), 1);
    assert_eq!(graph.nodes[0].attributes.type_tag, None);
}

#[test]
fn compiler_confirmed_validation_crosses_the_protocol_boundary_into_sog() {
    let mut analysis = ir(Vec::new());
    analysis.semantic_constructs.push(SemanticConstruct {
        anchor: Anchor::written_here(SourceRange {
            file: "src/lib.rs".to_owned(),
            start_byte: 12,
            end_byte: 48,
            start_line: 1,
        }),
        kind: SemanticConstructKind::Validate,
        fallible_kind: Some(HelperFallibleKind::Option),
        direct_propagation: None,
        resource_kind: None,
    });
    let normalized = registered_sog_for(&analysis, "src/lib.rs", Language::Rust, [11; 32])
        .expect("adapter only forwards compiler-confirmed constructs");
    let graph = normalized.graph.expect("validation construct produces SOG");
    assert_eq!(graph.nodes.len(), 1);
    assert_eq!(graph.nodes[0].kind, OperationKind::Validate);
    assert_eq!(
        graph.nodes[0].attributes.fallible_kind,
        Some(CoreFallibleKind::Option)
    );
}

#[test]
fn direct_result_propagation_crosses_the_protocol_boundary_into_sog() {
    let mut analysis = ir(Vec::new());
    analysis.semantic_constructs.push(SemanticConstruct {
        anchor: Anchor::written_here(SourceRange {
            file: "src/lib.rs".to_owned(),
            start_byte: 12,
            end_byte: 24,
            start_line: 1,
        }),
        kind: SemanticConstructKind::PropagateError,
        fallible_kind: Some(HelperFallibleKind::Result),
        direct_propagation: Some(HelperDirectPropagation::ResultAdapter),
        resource_kind: None,
    });
    let normalized = registered_sog_for(&analysis, "src/lib.rs", Language::Rust, [13; 32])
        .expect("adapter only forwards compiler-confirmed constructs");
    let graph = normalized
        .graph
        .expect("propagation construct produces a SOG");
    assert_eq!(graph.nodes.len(), 1);
    assert_eq!(graph.nodes[0].kind, OperationKind::PropagateError);
    assert_eq!(
        graph.nodes[0].attributes.direct_propagation,
        Some(CoreDirectPropagation::ResultAdapter)
    );
}

#[test]
fn direct_option_propagation_crosses_the_protocol_boundary_into_sog() {
    let mut analysis = ir(Vec::new());
    analysis.semantic_constructs.push(SemanticConstruct {
        anchor: Anchor::written_here(SourceRange {
            file: "src/lib.rs".to_owned(),
            start_byte: 12,
            end_byte: 24,
            start_line: 1,
        }),
        kind: SemanticConstructKind::PropagateError,
        fallible_kind: Some(HelperFallibleKind::Option),
        direct_propagation: Some(HelperDirectPropagation::OptionAdapter),
        resource_kind: None,
    });
    let normalized = registered_sog_for(&analysis, "src/lib.rs", Language::Rust, [14; 32])
        .expect("adapter only forwards compiler-confirmed constructs");
    let graph = normalized.graph.expect("option propagation produces a SOG");
    assert_eq!(
        graph.nodes[0].attributes.direct_propagation,
        Some(CoreDirectPropagation::OptionAdapter)
    );
}

#[test]
fn compiler_confirmed_loop_operations_cross_the_protocol_boundary_into_sog() {
    let mut analysis = ir(Vec::new());
    for (offset, kind) in [
        (12, SemanticConstructKind::Source),
        (36, SemanticConstructKind::Collect),
    ] {
        analysis.semantic_constructs.push(SemanticConstruct {
            anchor: Anchor::written_here(SourceRange {
                file: "src/lib.rs".to_owned(),
                start_byte: offset,
                end_byte: offset + 4,
                start_line: 1,
            }),
            kind,
            fallible_kind: None,
            direct_propagation: None,
            resource_kind: None,
        });
    }
    let normalized = registered_sog_for(&analysis, "src/lib.rs", Language::Rust, [12; 32])
        .expect("adapter only forwards compiler-confirmed constructs");
    let graph = normalized.graph.expect("loop constructs produce SOG");
    assert_eq!(
        graph.nodes.iter().map(|node| node.kind).collect::<Vec<_>>(),
        vec![OperationKind::Source, OperationKind::Collect]
    );
}

#[test]
fn compiler_confirmed_resource_lifetime_crosses_the_protocol_boundary_into_sog() {
    let mut analysis = ir(Vec::new());
    for (offset, kind) in [
        (12, SemanticConstructKind::AcquireResource),
        (36, SemanticConstructKind::ReleaseResource),
    ] {
        analysis.semantic_constructs.push(SemanticConstruct {
            anchor: Anchor::written_here(SourceRange {
                file: "src/lib.rs".to_owned(),
                start_byte: offset,
                end_byte: offset + 4,
                start_line: 1,
            }),
            kind,
            fallible_kind: None,
            direct_propagation: None,
            resource_kind: Some("file".to_owned()),
        });
    }
    let normalized = registered_sog_for(&analysis, "src/lib.rs", Language::Rust, [19; 32])
        .expect("adapter only forwards compiler-confirmed constructs");
    let graph = normalized.graph.expect("resource constructs produce SOG");
    assert_eq!(
        graph.nodes.iter().map(|node| node.kind).collect::<Vec<_>>(),
        vec![
            OperationKind::AcquireResource,
            OperationKind::ReleaseResource
        ]
    );
    assert!(graph.edges.iter().any(|edge| {
        edge.kind == OperationEdgeKind::ResourceLifetime && edge.from == 0 && edge.to == 1
    }));
}

#[test]
fn unit_range_keeps_unrelated_compiler_calls_out_of_one_sog_sequence() {
    let mut analysis = ir(Vec::new());
    analysis.calls = vec![
        CallSite {
            anchor: Anchor::written_here(SourceRange {
                file: "src/lib.rs".to_owned(),
                start_byte: 12,
                end_byte: 20,
                start_line: 1,
            }),
            target: CallTarget::Static {
                symbol: "Iterator::filter".to_owned(),
            },
            api_name: Some("rust::Iterator::filter".to_owned()),
        },
        CallSite {
            anchor: Anchor::written_here(SourceRange {
                file: "src/lib.rs".to_owned(),
                start_byte: 120,
                end_byte: 128,
                start_line: 10,
            }),
            target: CallTarget::Static {
                symbol: "Iterator::collect".to_owned(),
            },
            api_name: Some("rust::Iterator::collect".to_owned()),
        },
    ];
    let normalized = registered_sog_in_range(
        &analysis,
        "src/lib.rs",
        Language::Rust,
        [10; 32],
        Some(ByteRange { start: 0, end: 64 }),
    )
    .expect("adapter only forwards validated core observations");
    let graph = normalized.graph.expect("the first call is in the unit");
    assert_eq!(graph.nodes.len(), 1);
    assert_eq!(graph.nodes[0].kind.name(), "filter");
}

#[test]
fn an_expanded_expression_contributes_type_evidence_at_its_invocation() {
    let mut analysis = ir(Vec::new());
    analysis.types.push(ResolvedType {
        display: "i64".into(),
        category: TypeCategory::Integer,
        arguments: Vec::new(),
        definition: None,
    });
    analysis.expressions.push(ResolvedExpression {
        anchor: Anchor {
            expansion: SourceRange {
                file: "src/lib.rs".into(),
                start_byte: 40,
                end_byte: 70,
                start_line: 3,
            },
            definition: Some(SourceRange {
                file: "src/macros.rs".into(),
                start_byte: 8,
                end_byte: 36,
                start_line: 1,
            }),
        },
        type_index: 0,
    });
    assert_eq!(
        resolved_types_for(&analysis, "src/lib.rs"),
        vec![(ByteRange { start: 40, end: 70 }, TypeTag::Integer)]
    );
}

/// Offsets are per file. A crate's other files answering for this one would
/// be wrong in whichever direction their bytes happened to line up.
#[test]
fn another_file_in_the_same_crate_does_not_answer_for_this_one() {
    let analysis = ir(vec![
        symbol("total", "src/lib.rs", 40, 5, false),
        symbol("Vec", "src/report.rs", 40, 3, true),
    ]);
    let resolution = resolution_for(&analysis, "src/lib.rs");
    let mut expected = Resolution::new();
    expected.insert(40, false);
    assert_eq!(resolution, expected);
}

/// A declaration's anchor spans the item it declares, so its start byte is
/// whatever the item opens with — an attribute, a doc comment, `pub`. Read
/// as a name occurrence it would give a verdict about a token nobody asked
/// about.
#[test]
fn a_declaration_is_not_read_as_a_name_occurrence() {
    let mut declaration = symbol("debits", "src/lib.rs", 100, 6, false);
    declaration.anchor.expansion.end_byte = 260;
    declaration.kind = SymbolKind::Function;
    let resolution = resolution_for(&ir(vec![declaration]), "src/lib.rs");
    assert!(resolution.is_empty());
}

#[test]
fn an_analysis_that_resolved_nothing_leaves_normalization_as_it_was() {
    let resolution = resolution_for(&ir(Vec::new()), "src/lib.rs");
    assert!(resolution.is_empty());
}

#[test]
fn semantic_requests_control_flow_capability() {
    assert!(WANTED.contains(&Capability::MirCfg));
}

fn source(path: &str, language: Language, crate_name: Option<&str>) -> SourceUnit {
    SourceUnit {
        relative_path: PathBuf::from(path),
        absolute_path: PathBuf::from("/repo").join(path),
        language,
        is_header: false,
        content_hash: codehelion_core::discovery::ContentHash::of(b""),
        byte_len: 0,
        package: crate_name.map(ToString::to_string),
        crate_name: crate_name.map(ToString::to_string),
        target_kind: codehelion_core::discovery::TargetKind::Library,
    }
}

/// The only helper installed reads Rust.
const RUST_ONLY: [&[Language]; 1] = [&[Language::Rust]];

/// Every source gets an entry, in the order it was given: a run reports
/// per file what it got, and a list that skipped the files nobody asked
/// about would have to be re-aligned by whoever reads it.
#[test]
fn every_source_is_accounted_for_in_the_order_it_was_given() {
    let sources = [
        source("src/lib.rs", Language::Rust, Some("ledger")),
        source("src/native.c", Language::C, None),
        source("build.rs", Language::Rust, None),
    ];
    let mut asked = Vec::new();
    let answers = gather(
        &RUST_ONLY,
        &sources,
        "host",
        &BTreeMap::new(),
        &mut |_, unit, _| {
            asked.push(unit.clone());
            Analysis::Done(Box::new(CompilerIr::empty(unit.clone())))
        },
    );
    assert!(matches!(answers[0], Gathered::Analyzed { .. }));
    // A C file, with no helper here that reads C.
    assert!(matches!(
        answers[1],
        Gathered::NotAsked {
            reason: Unavailability::NotSupported,
            ..
        }
    ));
    // A build script belongs to no crate the layout can name.
    assert!(matches!(
        answers[2],
        Gathered::NotAsked {
            reason: Unavailability::NoBuildInformation,
            ..
        }
    ));
    assert_eq!(asked.len(), 1);
    assert_eq!(asked[0].unit, "ledger");
    assert_eq!(asked[0].file, "/repo/src/lib.rs");
    assert_eq!(asked[0].variant, "host");
}

/// A helper that was asked and could not answer is not a helper that was
/// never asked: one says the run is thin because the file is hard, the
/// other because nothing here reads it.
#[test]
fn being_unable_to_answer_is_not_the_same_as_never_being_asked() {
    let sources = [
        source("src/lib.rs", Language::Rust, Some("ledger")),
        source("src/native.c", Language::C, None),
    ];
    let answers = gather(
        &RUST_ONLY,
        &sources,
        "host",
        &BTreeMap::new(),
        &mut |_, _, _| Analysis::Missing(Unavailability::RequiresExecution),
    );
    let Gathered::Unavailable { unit, reason, .. } = &answers[0] else {
        panic!("the helper was asked and could not answer");
    };
    assert_eq!(*reason, Unavailability::RequiresExecution);
    // The unit is kept: a run records what it asked about, and a reason
    // with nothing attached names no file.
    assert_eq!(unit.unit, "ledger");
    assert_eq!(unit.file, "/repo/src/lib.rs");
    assert!(matches!(answers[1], Gathered::NotAsked { .. }));
}

/// A file nobody could be asked about is still named, so the run can say
/// which files those were. Its unit name is empty because there is none —
/// the alternative is inventing one, which is what makes an answer land on
/// the wrong file.
#[test]
fn a_file_nobody_was_asked_about_is_named_without_a_unit_being_invented() {
    let sources = [source("build.rs", Language::Rust, None)];
    let answers = gather(
        &RUST_ONLY,
        &sources,
        "host",
        &BTreeMap::new(),
        &mut |_, _, _| panic!("nothing should be asked"),
    );
    let Gathered::NotAsked { unit, reason } = &answers[0] else {
        panic!("nobody was asked about it");
    };
    assert_eq!(*reason, Unavailability::NoBuildInformation);
    assert_eq!(unit.file, "/repo/build.rs");
    assert!(unit.unit.is_empty());
}

/// Two helpers, and each file goes to the one that reads its language. A
/// run that sent every file to the first would report the C++ half as
/// unanswerable by a compiler that was never going to be asked about it.
#[test]
fn each_file_is_put_to_the_helper_that_reads_its_language() {
    let analyzes: [&[Language]; 2] = [&[Language::Rust], &[Language::C, Language::Cpp]];
    let sources = [
        source("src/lib.rs", Language::Rust, Some("ledger")),
        source("src/accumulate.cpp", Language::Cpp, None),
        source("src/native.c", Language::C, None),
    ];
    let mut asked: Vec<(usize, String)> = Vec::new();
    let answers = gather(
        &analyzes,
        &sources,
        "host",
        &BTreeMap::new(),
        &mut |backend, unit, _| {
            asked.push((backend, unit.unit.clone()));
            Analysis::Done(Box::new(CompilerIr::empty(unit.clone())))
        },
    );
    assert!(
        answers
            .iter()
            .all(|answer| matches!(answer, Gathered::Analyzed { .. }))
    );
    assert_eq!(
        asked,
        vec![
            (0, "ledger".to_string()),
            // A C or C++ file is its own translation unit, named by where
            // it is: no layout says which command compiles it, and the
            // helper reads that from the compilation database itself.
            (1, "/repo/src/accumulate.cpp".to_string()),
            (1, "/repo/src/native.c".to_string()),
        ]
    );
}

/// A C++ file belongs to no crate, and a run that asked a Cargo layout for
/// one would rule out every C++ file in the tree before anything was asked
/// — reported as a project that says nothing about itself rather than as
/// the question having been the wrong one.
#[test]
fn a_cpp_file_is_not_ruled_out_for_belonging_to_no_crate() {
    let analyzes: [&[Language]; 1] = [&[Language::C, Language::Cpp]];
    let sources = [source("src/accumulate.cpp", Language::Cpp, None)];
    let answers = gather(
        &analyzes,
        &sources,
        "host",
        &BTreeMap::new(),
        &mut |_, unit, _| Analysis::Done(Box::new(CompilerIr::empty(unit.clone()))),
    );
    assert!(matches!(answers[0], Gathered::Analyzed { .. }));
}

/// One reading of a file, as a helper that read the whole unit reports it.
mod agreement;
