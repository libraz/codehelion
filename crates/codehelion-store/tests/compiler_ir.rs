//! Compiler-IR storage against a real on-disk `SQLite` database: what a helper
//! answered comes back unchanged, what nothing could answer comes back as the
//! reason it could not, and the two are never each other.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use codehelion_core::discovery::{BuildVariant, Language, LanguageSelection};
use codehelion_core::engine::normalize::Resolution;
use codehelion_core::types::{TypeEvidence, TypeTag};
use codehelion_helper_protocol::ir::{
    Anchor, BasicBlock, CallSite, CallTarget, CompilerIr, ControlFlowGraph, DataFlowSummary,
    DirectPropagation, Edge, EdgeKind, EffectSummary, FallibleKind, Instantiation,
    ResolvedExpression, ResolvedSymbol, ResolvedType, SemanticConstruct, SemanticConstructKind,
    SourceRange, SymbolKind, TypeCategory, Unavailability, UnexpandedMacro, UnexpandedMacroReason,
    UnitRef,
};
use codehelion_helper_protocol::protocol::{Capability, Execution, HelperIdentity};
use codehelion_store::compiler::{CompilerHelperRow, CompilerOutcome, CompilerUnitRow};
use codehelion_store::snapshot::{Snapshot, SummaryRow};
use codehelion_store::{Store, StoreError};
use rusqlite::Connection;
use std::path::{Path, PathBuf};

/// A store on disk rather than in memory: the write path goes through real
/// files, real transactions and a real rollback. The path comes back so a
/// test can also look at the database the way anything else would.
fn on_disk() -> (tempfile::TempDir, Store, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.db");
    let store = Store::open(&path).unwrap();
    (dir, store, path)
}

/// A second connection to the same file, with references enforced — for the
/// questions the store has no API for because nothing but a test asks them.
fn peek(path: &Path) -> Connection {
    let conn = Connection::open(path).unwrap();
    conn.pragma_update(None, "foreign_keys", true).unwrap();
    conn
}

/// Every table the compiler IR writes into, parents before children.
const COMPILER_TABLES: [&str; 18] = [
    "compiler_helper",
    "compiler_helper_capability",
    "compiler_helper_toolchain",
    "compiler_unit",
    "compiler_type",
    "compiler_type_argument",
    "compiler_symbol",
    "compiler_call",
    "compiler_call_candidate",
    "compiler_semantic_construct",
    "compiler_expression",
    "compiler_unexpanded_macro",
    "compiler_block",
    "compiler_edge",
    "compiler_instantiation",
    "compiler_instantiation_argument",
    "compiler_effect",
    "compiler_data_flow",
];

fn count(conn: &Connection, table: &str) -> i64 {
    conn.query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
        row.get(0)
    })
    .unwrap()
}

fn variant() -> BuildVariant {
    BuildVariant::fast(LanguageSelection::default(), Language::Rust)
}

fn range(file: &str, start: u64) -> SourceRange {
    SourceRange {
        file: file.to_string(),
        start_byte: start,
        end_byte: start + 64,
        start_line: u32::try_from(start / 32).unwrap() + 1,
    }
}

fn unit_ref(unit: &str, file: &str) -> UnitRef {
    UnitRef {
        unit: unit.to_string(),
        file: file.to_string(),
        variant: "target=host,features=default".to_string(),
    }
}

/// A helper that granted everything, so that a stored capability set has more
/// than one member and an order that a round-trip can get wrong.
fn helper_row() -> CompilerHelperRow {
    CompilerHelperRow {
        identity: HelperIdentity {
            name: "codehelion-backend-rust".to_string(),
            version: "0.1.0".to_string(),
            protocol: 1,
            toolchains: vec!["1.85.0".to_string(), "1.86.0".to_string()],
            capabilities: vec![
                Capability::CallTargets,
                Capability::MirCfg,
                Capability::TemplateInstantiation,
                Capability::Types,
            ],
            executes: vec![Execution::BuildScript, Execution::ProcMacro],
        },
        restarts: Some(2),
    }
}

/// An analysis with every field populated and no two fields alike, so a
/// round-trip that swaps or drops one fails instead of passing.
fn full_analysis(unit: UnitRef) -> CompilerIr {
    CompilerIr {
        schema_version: codehelion_helper_protocol::ir::COMPILER_IR_SCHEMA_VERSION.to_string(),
        unit,
        anchored_at: Some("/projects/ledger".to_string()),
        symbols: sample_symbols(),
        types: sample_types(),
        calls: sample_calls(),
        semantic_constructs: vec![
            SemanticConstruct {
                anchor: Anchor {
                    expansion: range("src/render.rs", 400),
                    definition: Some(range("src/macros.rs", 144)),
                },
                kind: SemanticConstructKind::PropagateError,
                fallible_kind: Some(FallibleKind::Result),
                direct_propagation: Some(DirectPropagation::ResultAdapter),
                resource_kind: None,
            },
            SemanticConstruct {
                anchor: Anchor::written_here(range("src/render.rs", 464)),
                kind: SemanticConstructKind::Validate,
                fallible_kind: Some(FallibleKind::Option),
                direct_propagation: None,
                resource_kind: None,
            },
            SemanticConstruct {
                anchor: Anchor::written_here(range("src/render.rs", 496)),
                kind: SemanticConstructKind::PropagateError,
                fallible_kind: Some(FallibleKind::Option),
                direct_propagation: Some(DirectPropagation::OptionAdapter),
                resource_kind: None,
            },
            SemanticConstruct {
                anchor: Anchor::written_here(range("src/render.rs", 528)),
                kind: SemanticConstructKind::Source,
                fallible_kind: None,
                direct_propagation: None,
                resource_kind: None,
            },
            SemanticConstruct {
                anchor: Anchor::written_here(range("src/render.rs", 592)),
                kind: SemanticConstructKind::Collect,
                fallible_kind: None,
                direct_propagation: None,
                resource_kind: None,
            },
            SemanticConstruct {
                anchor: Anchor::written_here(range("src/render.rs", 624)),
                kind: SemanticConstructKind::Reduce,
                fallible_kind: None,
                direct_propagation: None,
                resource_kind: None,
            },
        ],
        expressions: vec![ResolvedExpression {
            anchor: Anchor {
                expansion: range("src/render.rs", 416),
                definition: Some(range("src/macros.rs", 160)),
            },
            type_index: 2,
        }],
        unexpanded_macros: vec![UnexpandedMacro {
            invocation: range("src/render.rs", 448),
            reason: UnexpandedMacroReason::RequiresExecution,
        }],
        cfg: Some(sample_cfg()),
        instantiations: vec![Instantiation {
            anchor: Anchor {
                expansion: range("src/render.rs", 384),
                definition: Some(range("src/generic.rs", 96)),
            },
            definition: "crate::Buffer::push".to_string(),
            definition_end_line: None,
            artifact_match_key: None,
            instantiation_key: "crate::Buffer::push<String>".to_string(),
            arguments: vec![1, 2],
        }],
        effects: EffectSummary {
            computed: true,
            writes: vec!["crate::COUNTER".to_string()],
            interactions: vec!["file".to_string(), "process".to_string()],
        },
        data_flow: DataFlowSummary {
            computed: true,
            flows: vec![("input".to_string(), "output".to_string())],
        },
    }
}

fn sample_symbols() -> Vec<ResolvedSymbol> {
    vec![
        ResolvedSymbol {
            id: "crate::render".to_string(),
            name: "render".to_string(),
            kind: SymbolKind::Function,
            anchor: Anchor::written_here(range("src/render.rs", 0)),
            type_index: Some(2),
            external: false,
        },
        // Written inside a macro body and read somewhere else: the pair of
        // places is the whole point of the anchor, so one symbol carries both.
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
    ]
}

fn sample_types() -> Vec<ResolvedType> {
    vec![
        ResolvedType {
            display: "u32".to_string(),
            category: TypeCategory::Integer,
            arguments: Vec::new(),
            definition: None,
        },
        ResolvedType {
            display: "String".to_string(),
            category: TypeCategory::Text,
            arguments: Vec::new(),
            definition: Some("alloc::string::String".to_string()),
        },
        ResolvedType {
            display: "Vec<String>".to_string(),
            category: TypeCategory::Sequence,
            arguments: vec![1],
            definition: Some("alloc::vec::Vec".to_string()),
        },
    ]
}

fn sample_calls() -> Vec<CallSite> {
    vec![
        CallSite {
            anchor: Anchor::written_here(range("src/render.rs", 192)),
            target: CallTarget::Static {
                symbol: "crate::escape".to_string(),
            },
            api_name: Some("crate::escape".to_string()),
        },
        CallSite {
            anchor: Anchor::written_here(range("src/render.rs", 256)),
            target: CallTarget::Dynamic {
                candidates: vec!["crate::Html".to_string(), "crate::Text".to_string()],
            },
            api_name: None,
        },
        CallSite {
            anchor: Anchor::written_here(range("src/render.rs", 320)),
            target: CallTarget::Unresolved,
            api_name: None,
        },
    ]
}

fn sample_cfg() -> ControlFlowGraph {
    ControlFlowGraph {
        blocks: vec![
            BasicBlock {
                anchor: Anchor::written_here(range("src/render.rs", 0)),
                length: 4,
            },
            BasicBlock {
                anchor: Anchor::written_here(range("src/render.rs", 64)),
                length: 7,
            },
        ],
        edges: vec![
            Edge {
                from: 0,
                to: 1,
                kind: EdgeKind::Taken,
            },
            Edge {
                from: 1,
                to: 1,
                kind: EdgeKind::Unwind,
            },
        ],
    }
}

fn snapshot<'a>(
    root: &'a str,
    variant: &'a BuildVariant,
    helpers: Vec<CompilerHelperRow>,
    units: Vec<CompilerUnitRow>,
) -> Snapshot<'a> {
    Snapshot {
        root_path: root,
        tool_version: "0.1.0",
        config_hash: "cfg",
        config_source: "defaults",
        config_path: None,
        started_at: "2026-01-01T00:00:00Z",
        finished_at: "2026-01-01T00:00:05Z",
        variant,
        min_clone_tokens: 40,
        detector_versions: &[],
        suppressions: Vec::new(),
        units: Vec::new(),
        groups: Vec::new(),
        sibling_groups: Vec::new(),
        features: Vec::new(),
        files: Vec::new(),
        compiler_helpers: helpers,
        compiler_units: units,
        summary: SummaryRow::default(),
    }
}

fn answered(ir: CompilerIr) -> CompilerUnitRow {
    CompilerUnitRow {
        helper: Some(0),
        outcome: CompilerOutcome::Analyzed(Box::new(ir)),
    }
}

const fn unavailable(
    unit: UnitRef,
    reason: Unavailability,
    helper: Option<usize>,
) -> CompilerUnitRow {
    CompilerUnitRow {
        helper,
        outcome: CompilerOutcome::Unavailable { unit, reason },
    }
}

/// Store an analysis and read it back; the two must be the same value.
fn round_trip(ir: CompilerIr) -> CompilerIr {
    let (_dir, mut store, _path) = on_disk();
    let variant = variant();
    let run = store
        .record_snapshot(&snapshot(
            "/tree",
            &variant,
            vec![helper_row()],
            vec![answered(ir)],
        ))
        .unwrap();
    let mut stored = store.run_compiler_units(run).unwrap();
    assert_eq!(stored.len(), 1);
    match stored.remove(0).outcome {
        CompilerOutcome::Analyzed(ir) => *ir,
        other @ CompilerOutcome::Unavailable { .. } => {
            panic!("expected an analysis, got {other:?}")
        }
    }
}

/// Every compiler-IR schema version `run` declares as a detector version.
fn declared(conn: &Connection, run: i64) -> Vec<String> {
    let mut statement = conn
        .prepare(
            "SELECT d.version FROM detector_version d
             JOIN scan_run_detector_version r ON r.detector_version_id = d.id
             WHERE r.scan_run_id = ?1 AND d.component = 'compiler_ir'
             ORDER BY d.version",
        )
        .unwrap();
    statement
        .query_map([run], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

#[path = "compiler_ir/families_and_metadata.rs"]
mod families_and_metadata;
#[path = "compiler_ir/lifecycle_and_determinism.rs"]
mod lifecycle_and_determinism;
#[path = "compiler_ir/outcomes_and_coverage.rs"]
mod outcomes_and_coverage;
#[path = "compiler_ir/round_trip_and_correlation.rs"]
mod round_trip_and_correlation;
