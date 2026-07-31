//! The wire shape of the compiler IR, frozen.
//!
//! A helper and the tool that reads it are built and shipped separately, so
//! the only thing keeping them able to talk is the schema version — and a
//! version is only worth anything if changing the shape is hard to do without
//! noticing. This is what makes it hard: a canonical analysis is serialized
//! and compared against a stored document named after the version it belongs
//! to. Adding, removing or renaming a field fails here, and the way to make it
//! pass is to write a new document under a new version, which is the change
//! that was needed anyway.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use codehelion_helper::ir::{
    Anchor, BasicBlock, COMPILER_IR_SCHEMA_VERSION, CallSite, CallTarget, CompilerIr,
    ControlFlowGraph, DataFlowSummary, DirectPropagation, Edge, EdgeKind, EffectSummary,
    FallibleKind, Instantiation, ResolvedExpression, ResolvedSymbol, ResolvedType,
    SemanticConstruct, SemanticConstructKind, SourceRange, SymbolKind, TypeCategory,
    UnexpandedMacro, UnexpandedMacroReason, UnitRef,
};

/// Every field of every message occupied, so nothing can change unobserved.
#[allow(clippy::too_many_lines)]
fn canonical() -> CompilerIr {
    CompilerIr {
        schema_version: COMPILER_IR_SCHEMA_VERSION.to_string(),
        unit: UnitRef {
            unit: "render".to_string(),
            file: "src/render.rs".to_string(),
            variant: "target=host".to_string(),
        },
        anchored_at: Some("/projects/ledger".to_string()),
        symbols: vec![
            ResolvedSymbol {
                id: "crate::render".to_string(),
                name: "render".to_string(),
                kind: SymbolKind::Function,
                anchor: Anchor::written_here(range("src/render.rs", 0)),
                type_index: Some(1),
                external: false,
            },
            ResolvedSymbol {
                id: "std::fmt::Display::fmt".to_string(),
                name: "fmt".to_string(),
                kind: SymbolKind::Other,
                anchor: Anchor {
                    expansion: range("src/render.rs", 128),
                    definition: Some(range("src/macros.rs", 32)),
                },
                type_index: None,
                external: true,
            },
        ],
        types: vec![
            ResolvedType {
                display: "String".to_string(),
                category: TypeCategory::Text,
                arguments: Vec::new(),
                definition: Some("alloc::string::String".to_string()),
            },
            ResolvedType {
                display: "Vec<String>".to_string(),
                category: TypeCategory::Sequence,
                arguments: vec![0],
                definition: Some("alloc::vec::Vec".to_string()),
            },
        ],
        calls: vec![
            CallSite {
                anchor: Anchor::written_here(range("src/render.rs", 192)),
                target: CallTarget::Static {
                    symbol: "crate::escape".to_string(),
                },
                api_name: Some("std::push_back".to_string()),
            },
            CallSite {
                anchor: Anchor::written_here(range("src/render.rs", 256)),
                target: CallTarget::Dynamic {
                    candidates: vec!["crate::Html".to_string()],
                },
                api_name: None,
            },
            CallSite {
                anchor: Anchor::written_here(range("src/render.rs", 320)),
                target: CallTarget::Unresolved,
                api_name: None,
            },
        ],
        semantic_constructs: vec![
            SemanticConstruct {
                anchor: Anchor::written_here(range("src/render.rs", 336)),
                kind: SemanticConstructKind::PropagateError,
                fallible_kind: Some(FallibleKind::Result),
                direct_propagation: Some(DirectPropagation::ResultAdapter),
                resource_kind: None,
            },
            SemanticConstruct {
                anchor: Anchor::written_here(range("src/render.rs", 400)),
                kind: SemanticConstructKind::Validate,
                fallible_kind: Some(FallibleKind::Option),
                direct_propagation: None,
                resource_kind: None,
            },
            SemanticConstruct {
                anchor: Anchor::written_here(range("src/render.rs", 464)),
                kind: SemanticConstructKind::Source,
                fallible_kind: None,
                direct_propagation: None,
                resource_kind: None,
            },
            SemanticConstruct {
                anchor: Anchor::written_here(range("src/render.rs", 528)),
                kind: SemanticConstructKind::Collect,
                fallible_kind: None,
                direct_propagation: None,
                resource_kind: None,
            },
        ],
        expressions: sample_expressions(),
        unexpanded_macros: vec![UnexpandedMacro {
            invocation: range("src/render.rs", 352),
            reason: UnexpandedMacroReason::RequiresExecution,
        }],
        cfg: Some(ControlFlowGraph {
            blocks: vec![BasicBlock {
                anchor: Anchor::written_here(range("src/render.rs", 0)),
                length: 4,
            }],
            edges: vec![Edge {
                from: 0,
                to: 0,
                kind: EdgeKind::Return,
            }],
        }),
        instantiations: vec![Instantiation {
            anchor: Anchor {
                expansion: range("src/render.rs", 384),
                definition: Some(range("src/generic.rs", 96)),
            },
            definition: "crate::Buffer::push".to_string(),
            instantiation_key: "crate::Buffer::push<String>".to_string(),
            arguments: vec![0],
        }],
        effects: EffectSummary {
            computed: true,
            writes: vec!["crate::COUNTER".to_string()],
            interactions: vec!["file".to_string()],
        },
        data_flow: DataFlowSummary {
            computed: true,
            flows: vec![("input".to_string(), "output".to_string())],
        },
    }
}

fn range(file: &str, start: u64) -> SourceRange {
    SourceRange {
        file: file.to_string(),
        start_byte: start,
        end_byte: start + 64,
        start_line: u32::try_from(start / 32).unwrap() + 1,
    }
}

fn sample_expressions() -> Vec<ResolvedExpression> {
    vec![ResolvedExpression {
        anchor: Anchor {
            expansion: range("src/render.rs", 352),
            definition: Some(range("src/macros.rs", 32)),
        },
        type_index: 0,
    }]
}

/// The stored document for the version this build writes. A new version means
/// a new file beside the last, not an edit to it — the shapes that have been
/// shipped stay on disk to say what a stored analysis written against them
/// meant.
const GOLDEN_V11: &str = include_str!("golden/compiler-ir-v11.json");

/// The shape before explicit loop reductions were retained.
const GOLDEN_V10: &str = include_str!("golden/compiler-ir-v10.json");

/// The shape before resource categories were retained on semantic constructs.
const GOLDEN_V9: &str = include_str!("golden/compiler-ir-v9.json");

/// The shape before compiler-confirmed API names accompanied call identities.
const GOLDEN_V8: &str = include_str!("golden/compiler-ir-v8.json");

/// The shape before direct propagation forms were retained.
const GOLDEN_V7: &str = include_str!("golden/compiler-ir-v7.json");

/// The shape before explicit loop operations were retained.
const GOLDEN_V6: &str = include_str!("golden/compiler-ir-v6.json");

/// The shape before standard fallible container kinds were retained.
const GOLDEN_V5: &str = include_str!("golden/compiler-ir-v5.json");

/// The shape before compiler-confirmed validation constructs were reported.
const GOLDEN_V4: &str = include_str!("golden/compiler-ir-v4.json");

/// The shape before compiler-confirmed semantic constructs were reported.
const GOLDEN_V3: &str = include_str!("golden/compiler-ir-v3.json");

/// The shape before expanded expression types were reported.
const GOLDEN_V2: &str = include_str!("golden/compiler-ir-v2.json");

/// The shape before skipped macro invocations were made visible.
const GOLDEN_V1: &str = include_str!("golden/compiler-ir-v1.json");

/// The shape before the analysis said what its paths were spelled against.
const GOLDEN_V0: &str = include_str!("golden/compiler-ir-v0.json");

#[test]
fn the_wire_shape_matches_the_document_for_this_version() {
    assert_eq!(COMPILER_IR_SCHEMA_VERSION, "compiler-ir-v11");
    let written = serde_json::to_string_pretty(&canonical()).unwrap();
    assert_eq!(written, GOLDEN_V11.trim_end());
}

/// The document is also what a reader of that version has to accept, so it is
/// read back as well as written: a shape that serializes right and parses
/// wrong would pass the check above.
#[test]
fn the_document_reads_back_as_what_produced_it() {
    let parsed: CompilerIr = serde_json::from_str(GOLDEN_V11).unwrap();
    assert_eq!(parsed, canonical());
    assert!(parsed.is_readable());
}

/// Resource categories are optional for older producers, but when a current
/// helper establishes one the wire document must preserve it exactly.
#[test]
fn a_resource_category_round_trips_when_present() {
    let construct = SemanticConstruct {
        anchor: Anchor::written_here(range("src/render.rs", 640)),
        kind: SemanticConstructKind::AcquireResource,
        fallible_kind: None,
        direct_propagation: None,
        resource_kind: Some("file".to_owned()),
    };
    let written = serde_json::to_string(&construct).unwrap();
    assert!(written.contains("\"resource_kind\":\"file\""));
    assert_eq!(
        serde_json::from_str::<SemanticConstruct>(&written).unwrap(),
        construct
    );
}

#[test]
fn the_previous_document_remains_parseable_as_thin_coverage() {
    let parsed: CompilerIr = serde_json::from_str(GOLDEN_V10).unwrap();
    assert!(
        parsed
            .semantic_constructs
            .iter()
            .all(|construct| construct.kind != SemanticConstructKind::Reduce)
    );
    let parsed: CompilerIr = serde_json::from_str(GOLDEN_V9).unwrap();
    assert!(
        parsed
            .semantic_constructs
            .iter()
            .all(|construct| construct.resource_kind.is_none())
    );
    let parsed: CompilerIr = serde_json::from_str(GOLDEN_V8).unwrap();
    assert!(parsed.calls.iter().all(|call| call.api_name.is_none()));
    let parsed: CompilerIr = serde_json::from_str(GOLDEN_V7).unwrap();
    assert!(
        parsed
            .semantic_constructs
            .iter()
            .all(|construct| construct.direct_propagation.is_none())
    );
    let parsed: CompilerIr = serde_json::from_str(GOLDEN_V6).unwrap();
    assert!(parsed.semantic_constructs.iter().all(|construct| {
        matches!(
            construct.kind,
            SemanticConstructKind::PropagateError | SemanticConstructKind::Validate
        )
    }));
    let parsed: CompilerIr = serde_json::from_str(GOLDEN_V5).unwrap();
    assert!(
        parsed
            .semantic_constructs
            .iter()
            .all(|construct| construct.fallible_kind.is_none())
    );
    let parsed: CompilerIr = serde_json::from_str(GOLDEN_V4).unwrap();
    assert!(
        parsed
            .semantic_constructs
            .iter()
            .all(|construct| { construct.kind == SemanticConstructKind::PropagateError })
    );
    let parsed: CompilerIr = serde_json::from_str(GOLDEN_V3).unwrap();
    assert!(parsed.semantic_constructs.is_empty());
    let parsed: CompilerIr = serde_json::from_str(GOLDEN_V2).unwrap();
    assert!(parsed.expressions.is_empty());
    let parsed: CompilerIr = serde_json::from_str(GOLDEN_V1).unwrap();
    assert!(parsed.expressions.is_empty());
    assert!(parsed.unexpanded_macros.is_empty());
}

/// An analysis from an earlier schema has to arrive before it can be turned
/// away. Refusing it at the parser instead would report a helper from another
/// release as a helper that broke, and send someone to debug their project
/// rather than to update a program.
#[test]
fn an_answer_from_an_earlier_schema_arrives_and_is_turned_away() {
    let parsed: CompilerIr = serde_json::from_str(GOLDEN_V0)
        .expect("a shape this build no longer writes still has to parse");
    assert!(!parsed.is_readable());
    // The field it predates reads as absent rather than as a claim: what a v0
    // analysis spelled its paths against is exactly what nobody recorded.
    assert_eq!(parsed.anchored_at, None);
}
