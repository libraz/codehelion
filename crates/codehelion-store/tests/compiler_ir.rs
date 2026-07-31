//! Compiler-IR storage against a real on-disk `SQLite` database: what a helper
//! answered comes back unchanged, what nothing could answer comes back as the
//! reason it could not, and the two are never each other.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use codehelion_core::discovery::{BuildVariant, Language, LanguageSelection};
use codehelion_core::engine::normalize::Resolution;
use codehelion_core::types::{TypeEvidence, TypeTag};
use codehelion_helper::ir::{
    Anchor, BasicBlock, CallSite, CallTarget, CompilerIr, ControlFlowGraph, DataFlowSummary,
    DirectPropagation, Edge, EdgeKind, EffectSummary, FallibleKind, Instantiation,
    ResolvedExpression, ResolvedSymbol, ResolvedType, SemanticConstruct, SemanticConstructKind,
    SourceRange, SymbolKind, TypeCategory, Unavailability, UnexpandedMacro, UnexpandedMacroReason,
    UnitRef,
};
use codehelion_helper::protocol::{Capability, Execution, HelperIdentity};
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
        schema_version: codehelion_helper::ir::COMPILER_IR_SCHEMA_VERSION.to_string(),
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
        started_at: "2026-01-01T00:00:00Z",
        finished_at: "2026-01-01T00:00:05Z",
        variant,
        min_clone_tokens: 40,
        detector_versions: &[],
        suppressions: Vec::new(),
        units: Vec::new(),
        groups: Vec::new(),
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
            instantiation_key: "crate::Buffer::push<String>".to_owned(),
            file_path: "src/generic.rs".to_owned(),
            line: 4,
            translation_unit: "src/render.rs".to_owned(),
        }]
    );
}

/// A unit nobody could analyse is an outcome of scanning a real project, not
/// a gap in the record: it has a row, and the row says which reason applied.
#[test]
fn a_unit_nobody_could_analyse_is_recorded_with_the_reason() {
    let (_dir, mut store, _path) = on_disk();
    let variant = variant();
    let build = unit_ref("build-script", "build.rs");
    let missing = unit_ref("vendored", "vendor/blob.c");
    let run = store
        .record_snapshot(&snapshot(
            "/tree",
            &variant,
            vec![helper_row()],
            vec![
                unavailable(build.clone(), Unavailability::RequiresExecution, None),
                unavailable(missing.clone(), Unavailability::NoBuildInformation, Some(0)),
            ],
        ))
        .unwrap();

    let stored = store.run_compiler_units(run).unwrap();
    assert_eq!(stored.len(), 2);
    assert_eq!(
        stored[0].outcome,
        CompilerOutcome::Unavailable {
            unit: build,
            reason: Unavailability::RequiresExecution,
        }
    );
    // Ruled out before any helper was involved, so nothing names one.
    assert!(stored[0].helper.is_none());
    assert_eq!(
        stored[1].outcome,
        CompilerOutcome::Unavailable {
            unit: missing,
            reason: Unavailability::NoBuildInformation,
        }
    );
    assert_eq!(
        stored[1].helper.as_ref().map(|helper| helper.name.as_str()),
        Some("codehelion-backend-rust")
    );
}

/// A scan that asked nothing and one whose every answer was unavailable are
/// different records, and only the latter has compiler-unit rows.
#[test]
fn asking_and_failing_does_not_read_as_never_asking() {
    let (_dir, mut store, _path) = on_disk();
    let variant = variant();
    let silent = store
        .record_snapshot(&snapshot("/a", &variant, Vec::new(), Vec::new()))
        .unwrap();
    assert!(store.run_compiler_units(silent).unwrap().is_empty());

    let asked = store
        .record_snapshot(&snapshot(
            "/b",
            &variant,
            Vec::new(),
            vec![unavailable(
                unit_ref("crate", "src/lib.rs"),
                Unavailability::ToolchainMismatch,
                None,
            )],
        ))
        .unwrap();
    assert_eq!(store.run_compiler_units(asked).unwrap().len(), 1);
    // A run that started no helper restarted nothing, which is a count rather
    // than a gap in the record: nothing was left uncounted.
    let coverage = store.run_compiler_coverage(asked).unwrap().unwrap();
    assert_eq!(coverage.restarts, Some(0));
    assert_eq!(coverage.not_asked, 1);
}

/// The counts a run reports about itself have to survive being recorded, and
/// the three outcomes have to survive it separately: a summed pair would say a
/// helper failed on files nobody showed it.
#[test]
fn how_much_a_compiler_spoke_for_is_counted_off_the_rows() {
    let (_dir, mut store, _path) = on_disk();
    let variant = variant();
    let run = store
        .record_snapshot(&snapshot(
            "/tree",
            &variant,
            vec![helper_row()],
            vec![
                answered(full_analysis(unit_ref("render", "src/render.rs"))),
                answered(full_analysis(unit_ref("ledger", "src/ledger.rs"))),
                unavailable(
                    unit_ref("build-script", "build.rs"),
                    Unavailability::RequiresExecution,
                    Some(0),
                ),
                unavailable(
                    unit_ref("hooks", "hooks.rs"),
                    Unavailability::RequiresExecution,
                    Some(0),
                ),
                unavailable(
                    unit_ref("crate", "src/slow.rs"),
                    Unavailability::HelperTimedOut,
                    Some(0),
                ),
                // Nobody was asked: no helper here reads it.
                unavailable(
                    unit_ref("", "vendor/blob.c"),
                    Unavailability::NotSupported,
                    None,
                ),
            ],
        ))
        .unwrap();

    let coverage = store
        .run_compiler_coverage(run)
        .unwrap()
        .expect("a compiler was asked about this run");
    assert_eq!(coverage.answered, 2);
    assert_eq!(coverage.not_asked, 1);
    assert_eq!(
        coverage.unavailable,
        [
            ("requires_execution".to_string(), 2),
            ("helper_timed_out".to_string(), 1),
        ]
        .into_iter()
        .collect()
    );
    assert_eq!(coverage.restarts, helper_row().restarts);
}

/// Asking nobody is not asking and being told nothing, so the run that put
/// nothing to a compiler has no coverage rather than an empty one.
#[test]
fn a_run_that_asked_nobody_reports_no_coverage_rather_than_an_empty_one() {
    let (_dir, mut store, _path) = on_disk();
    let variant = variant();
    let run = store
        .record_snapshot(&snapshot("/tree", &variant, Vec::new(), Vec::new()))
        .unwrap();
    assert_eq!(store.run_compiler_coverage(run).unwrap(), None);
}

/// Anchors are stored the way the analysis spelled them, so what they were
/// spelled against has to be stored beside them. Without it a relative path
/// reads as relative to wherever the reader is standing, and the answers land
/// on a file nobody asked about — quietly, since the two can look alike.
#[test]
fn an_analysis_keeps_what_its_paths_were_spelled_against() {
    let written = full_analysis(unit_ref("render", "src/render.rs"));
    assert_eq!(
        round_trip(written).anchored_at.as_deref(),
        Some("/projects/ledger")
    );

    let mut standalone = full_analysis(unit_ref("render", "src/render.rs"));
    standalone.anchored_at = None;
    assert_eq!(round_trip(standalone).anchored_at, None);
}

/// A graph with no blocks and a helper that builds no graph both store zero
/// blocks, so the presence of the graph is stored separately or the two are
/// the same record.
#[test]
fn an_empty_graph_does_not_read_as_no_graph() {
    let mut empty = full_analysis(unit_ref("crate", "src/lib.rs"));
    empty.cfg = Some(ControlFlowGraph::default());
    let mut absent = empty.clone();
    absent.cfg = None;

    assert_eq!(round_trip(empty).cfg, Some(ControlFlowGraph::default()));
    assert_eq!(round_trip(absent).cfg, None);
}

/// The same argument one level down: a summary that found nothing and one
/// nobody computed are the same empty lists and different claims.
#[test]
fn a_summary_nobody_computed_does_not_read_as_one_that_found_nothing() {
    let mut looked = full_analysis(unit_ref("crate", "src/lib.rs"));
    looked.effects = EffectSummary {
        computed: true,
        ..EffectSummary::default()
    };
    looked.data_flow = DataFlowSummary {
        computed: true,
        flows: Vec::new(),
    };
    let mut skipped = looked.clone();
    skipped.effects.computed = false;
    skipped.data_flow.computed = false;

    let read_looked = round_trip(looked);
    assert!(read_looked.effects.computed && read_looked.effects.writes.is_empty());
    assert!(read_looked.data_flow.computed);
    let read_skipped = round_trip(skipped);
    assert!(!read_skipped.effects.computed);
    assert!(!read_skipped.data_flow.computed);
}

/// A dynamic call the compiler narrowed to nothing still says it is dynamic.
/// Both it and an unresolved call store no candidate rows, so collapsing them
/// would be the easy mistake.
#[test]
fn a_dynamic_call_with_no_candidates_is_not_an_unresolved_one() {
    let mut ir = full_analysis(unit_ref("crate", "src/lib.rs"));
    ir.calls = vec![
        CallSite {
            anchor: Anchor::written_here(range("src/lib.rs", 0)),
            target: CallTarget::Dynamic {
                candidates: Vec::new(),
            },
            api_name: None,
        },
        CallSite {
            anchor: Anchor::written_here(range("src/lib.rs", 64)),
            target: CallTarget::Unresolved,
            api_name: None,
        },
    ];
    let stored = round_trip(ir);
    assert_eq!(
        stored.calls[0].target,
        CallTarget::Dynamic {
            candidates: Vec::new()
        }
    );
    assert_eq!(stored.calls[1].target, CallTarget::Unresolved);
}

/// One definition and every place it was stamped out, gathered across the
/// units they live in — the query the expansion/definition anchoring exists to
/// answer, and the reason the key is indexed without a unit in front of it.
#[test]
fn the_expansions_of_one_definition_are_one_family_across_units() {
    let (_dir, mut store, _path) = on_disk();
    let variant = variant();
    let key = "crate::Buffer::push<String>";

    let mut first = full_analysis(unit_ref("render", "src/render.rs"));
    first.instantiations[0].instantiation_key = key.to_string();
    let mut second = full_analysis(unit_ref("parse", "src/parse.rs"));
    second.instantiations = vec![
        Instantiation {
            anchor: Anchor {
                expansion: range("src/parse.rs", 128),
                definition: Some(range("src/generic.rs", 96)),
            },
            definition: "crate::Buffer::push".to_string(),
            instantiation_key: key.to_string(),
            arguments: vec![1],
        },
        Instantiation {
            anchor: Anchor::written_here(range("src/parse.rs", 256)),
            definition: "crate::Buffer::push".to_string(),
            instantiation_key: "crate::Buffer::push<u32>".to_string(),
            arguments: vec![0],
        },
    ];
    let run = store
        .record_snapshot(&snapshot(
            "/tree",
            &variant,
            vec![helper_row()],
            vec![answered(first), answered(second)],
        ))
        .unwrap();

    let family = store.instantiation_family(run, key).unwrap();
    assert_eq!(family.len(), 2, "{family:?}");
    assert_eq!(family[0].unit.unit, "render");
    assert_eq!(family[1].unit.unit, "parse");
    // Every member names one definition, which is what makes the family a
    // repetition of one thing rather than several copies of a body.
    assert!(
        family
            .iter()
            .all(|site| site.definition == "crate::Buffer::push")
    );
    assert_eq!(
        family[0]
            .anchor
            .definition
            .as_ref()
            .map(|d| d.file.as_str()),
        Some("src/generic.rs")
    );
    // The other key is its own family, not part of this one.
    assert_eq!(
        store
            .instantiation_family(run, "crate::Buffer::push<u32>")
            .unwrap()
            .len(),
        1
    );
}

/// The family query has to be answerable without walking every instantiation
/// in the database, which is the whole reason for the index — and an index
/// that exists but is not reachable from the query is the same as none.
#[test]
fn the_family_query_reaches_the_instantiation_index() {
    let (_dir, store, path) = on_disk();
    drop(store);
    let conn = peek(&path);
    let mut statement = conn
        .prepare(
            "EXPLAIN QUERY PLAN
             SELECT i.id FROM compiler_instantiation i
             JOIN compiler_unit u ON u.id = i.compiler_unit_id
             WHERE i.instantiation_key = ?1 AND u.scan_run_id = ?2",
        )
        .unwrap();
    let plan: Vec<String> = statement
        .query_map(rusqlite::params!["some::key", 1_i64], |row| {
            row.get::<_, String>(3)
        })
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert!(
        plan.iter()
            .any(|step| step.contains("idx_compiler_instantiation_key")),
        "the query plan does not use the index: {plan:?}"
    );
}

/// A run that holds compiler IR says which schema it was written against; a
/// stored run whose schema this build no longer reads has to be recognisable
/// without reading every unit row.
#[test]
fn a_run_holding_compiler_ir_declares_the_schema_it_used() {
    let (_dir, mut store, path) = on_disk();
    let build_variant = variant();
    let with = store
        .record_snapshot(&snapshot(
            "/a",
            &build_variant,
            vec![helper_row()],
            vec![answered(full_analysis(unit_ref("crate", "src/lib.rs")))],
        ))
        .unwrap();

    drop(store);
    let conn = peek(&path);
    assert_eq!(
        declared(&conn, with),
        vec![codehelion_helper::ir::COMPILER_IR_SCHEMA_VERSION.to_string()]
    );

    let (_dir, mut store, path) = on_disk();
    let variant = variant();
    let without = store
        .record_snapshot(&snapshot("/b", &variant, Vec::new(), Vec::new()))
        .unwrap();

    drop(store);
    let conn = peek(&path);
    // A scan that asked no compiler claims no IR schema: declaring one would
    // say the scan used something it never did.
    assert!(declared(&conn, without).is_empty());
}

/// A unit that was answered for out of a schema this build cannot read comes
/// back naming that schema rather than passing as current.
#[test]
fn an_answer_from_another_schema_is_not_read_as_current() {
    let mut ir = full_analysis(unit_ref("crate", "src/lib.rs"));
    ir.schema_version = "compiler-ir-unsupported".to_string();
    let stored = round_trip(ir);
    assert!(!stored.is_readable());
    assert_eq!(stored.schema_version, "compiler-ir-unsupported");
}

/// The handshake result is the only place that says why a whole run has no
/// control-flow graphs anywhere, and it is gone once the helper exits.
#[test]
fn the_helper_that_answered_is_recorded_with_what_it_granted() {
    let (_dir, mut store, _path) = on_disk();
    let variant = variant();
    let run = store
        .record_snapshot(&snapshot(
            "/tree",
            &variant,
            vec![helper_row()],
            vec![answered(full_analysis(unit_ref("crate", "src/lib.rs")))],
        ))
        .unwrap();
    let helpers = store.run_compiler_helpers(run).unwrap();
    assert_eq!(helpers, vec![helper_row()]);
    // How often it fell over is the other thing the run cannot reconstruct:
    // the unit rows say which files came back empty, not that the emptiness
    // was the helper's doing.
    assert_eq!(helpers[0].restarts, Some(2));
    // What it said it would run if permitted, which answers "why did nothing
    // run" without the helper still being there to ask. What it *was*
    // permitted is a different fact and lives in the variant, because results
    // depend on it.
    assert_eq!(
        helpers[0].identity.executes,
        vec![Execution::BuildScript, Execution::ProcMacro]
    );
}

/// A helper that survived the tree and one recorded before restarts were kept
/// are different claims, and zero is only the first of them.
#[test]
fn a_run_that_did_not_count_restarts_is_not_a_run_with_none() {
    let (_dir, mut store, _path) = on_disk();
    let variant = variant();
    let mut uncounted = helper_row();
    uncounted.restarts = None;
    let run = store
        .record_snapshot(&snapshot(
            "/tree",
            &variant,
            vec![uncounted.clone()],
            vec![answered(full_analysis(unit_ref("crate", "src/lib.rs")))],
        ))
        .unwrap();
    assert_eq!(store.run_compiler_helpers(run).unwrap(), vec![uncounted]);
}

/// One header analysed from two translation units is two analyses of one
/// file, so the unit is part of the identity and the file alone is not.
#[test]
fn a_header_read_from_two_units_is_two_analyses() {
    let (_dir, mut store, _path) = on_disk();
    let variant = variant();
    let run = store
        .record_snapshot(&snapshot(
            "/tree",
            &variant,
            vec![helper_row()],
            vec![
                answered(full_analysis(unit_ref("a.o", "include/shared.h"))),
                answered(full_analysis(unit_ref("b.o", "include/shared.h"))),
            ],
        ))
        .unwrap();
    let stored = store.run_compiler_units(run).unwrap();
    assert_eq!(stored.len(), 2);
    assert_eq!(stored[0].outcome.unit().file, stored[1].outcome.unit().file);
    assert_ne!(stored[0].outcome.unit().unit, stored[1].outcome.unit().unit);
}

/// A snapshot naming a helper it does not carry is rejected, and rejecting it
/// takes the whole run with it rather than leaving a scan that half happened.
#[test]
fn a_helper_that_is_not_in_the_snapshot_rolls_the_run_back() {
    let (_dir, mut store, _path) = on_disk();
    let variant = variant();
    let mut row = answered(full_analysis(unit_ref("crate", "src/lib.rs")));
    row.helper = Some(4);
    let error = store
        .record_snapshot(&snapshot("/tree", &variant, vec![helper_row()], vec![row]))
        .unwrap_err();
    assert!(
        matches!(
            error,
            StoreError::UnknownHelperIndex { index, helpers } if index == 4 && helpers == 1
        ),
        "unexpected error: {error}"
    );
    assert_eq!(store.table_count("scan_run").unwrap(), 0);
    assert_eq!(store.table_count("compiler_unit").unwrap(), 0);
    assert_eq!(store.table_count("compiler_helper").unwrap(), 0);
}

/// Deleting a run takes its compiler rows with it, all the way down: an
/// orphaned candidate or type argument would outlive the analysis it belongs
/// to and be counted by the next thing that looks.
#[test]
fn deleting_a_run_takes_its_compiler_rows_with_it() {
    let (_dir, mut store, path) = on_disk();
    let variant = variant();
    let run = store
        .record_snapshot(&snapshot(
            "/tree",
            &variant,
            vec![helper_row()],
            vec![answered(full_analysis(unit_ref("crate", "src/lib.rs")))],
        ))
        .unwrap();
    assert!(store.table_count("compiler_call_candidate").unwrap() > 0);
    assert!(store.table_count("compiler_type_argument").unwrap() > 0);

    drop(store);
    let conn = peek(&path);
    conn.execute("DELETE FROM scan_run WHERE id = ?1", [run])
        .unwrap();
    for table in COMPILER_TABLES {
        assert_eq!(count(&conn, table), 0, "{table} outlived its run");
    }
}

/// What storing an analysis is for: the engine's type dimension and its
/// answer about which names are external both come out of a stored answer,
/// and the analysis crate that consumes them never learns that a compiler
/// exists. That is the sense in which the dimension's input is replaceable —
/// anything able to produce the tags can supply it.
#[test]
fn a_stored_analysis_supplies_evidence_the_engine_cannot_obtain_itself() {
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
    let mut stored = store.run_compiler_units(run).unwrap();
    let CompilerOutcome::Analyzed(ir) = stored.remove(0).outcome else {
        panic!("expected an analysis")
    };

    // One tag per typed symbol, not one per distinct type: the evidence is
    // about what the unit works with, and a type used ten times is ten facts.
    let evidence = TypeEvidence::from_tags(ir.symbols.iter().filter_map(|symbol| {
        let index = usize::try_from(symbol.type_index?).ok()?;
        TypeTag::from_category(ir.types.get(index)?.category.name())
    }));
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence.agreement(&evidence), Some(1.0));

    // And the compiler's verdict on each name, keyed by where the name sits.
    let mut resolution = Resolution::new();
    for symbol in &ir.symbols {
        let start = usize::try_from(symbol.anchor.expansion.start_byte).unwrap();
        resolution.insert(start, symbol.external);
    }
    assert!(!resolution.is_empty());
}

/// The same answer stored twice is stored identically, row for row. Anything
/// that reached a hash map's iteration order or a timestamp on the way in
/// would show up here as two databases that hold the same analysis and do not
/// agree about it.
#[test]
fn storing_one_answer_twice_writes_the_same_rows_both_times() {
    let rows = || {
        let (dir, mut store, path) = on_disk();
        store
            .record_snapshot(&snapshot(
                "/tree",
                &variant(),
                vec![helper_row()],
                vec![
                    answered(full_analysis(unit_ref("render", "src/render.rs"))),
                    unavailable(
                        unit_ref("build-script", "build.rs"),
                        Unavailability::RequiresExecution,
                        None,
                    ),
                ],
            ))
            .unwrap();
        drop(store);
        let conn = peek(&path);
        let dumped = dump(&conn);
        drop(dir);
        dumped
    };
    assert_eq!(rows(), rows());
}

/// Every compiler row in the database, as text, in a fixed order.
fn dump(conn: &Connection) -> Vec<String> {
    let mut out = Vec::new();
    for table in COMPILER_TABLES {
        let mut statement = conn.prepare(&format!("SELECT * FROM {table}")).unwrap();
        let columns = statement.column_count();
        let mut rows: Vec<String> = statement
            .query_map([], |row| {
                let mut cells = Vec::with_capacity(columns);
                for index in 0..columns {
                    cells.push(format!("{:?}", row.get_ref(index)?));
                }
                Ok(cells.join("|"))
            })
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        rows.sort();
        for row in rows {
            out.push(format!("{table}: {row}"));
        }
    }
    out
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
