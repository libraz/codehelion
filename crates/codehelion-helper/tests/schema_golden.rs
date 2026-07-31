//! The wire shape of the compiler IR.
//!
//! A helper and the tool that reads it are built and shipped separately, so
//! the only thing keeping them able to talk is the schema version — and a
//! version is only worth anything if changing the shape is hard to do without
//! noticing. This is what makes it hard: a canonical analysis is serialized
//! and compared against the one stored document that defines the current
//! contract. Adding, removing or renaming a field fails here.
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
            definition_end_line: None,
            artifact_match_key: None,
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

/// The stored document for the only compiler-IR contract this build writes.
const GOLDEN: &str = include_str!("golden/compiler-ir-v1.json");

#[test]
fn the_wire_shape_matches_the_document_for_this_version() {
    assert_eq!(COMPILER_IR_SCHEMA_VERSION, "compiler-ir-v1");
    let written = serde_json::to_string_pretty(&canonical()).unwrap();
    assert_eq!(written, GOLDEN.trim_end());
}

/// The document is also what a reader of that version has to accept, so it is
/// read back as well as written: a shape that serializes right and parses
/// wrong would pass the check above.
#[test]
fn the_document_reads_back_as_what_produced_it() {
    let parsed: CompilerIr = serde_json::from_str(GOLDEN).unwrap();
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
