//! Deterministic work-quantity benchmark for candidate guardrails.
//!
//! Wall-clock timings are printed for local comparison, but the assertions use
//! stage counters: reducing a budget must reduce the work admitted downstream.

use std::hint::black_box;
use std::time::{Duration, Instant};

use codehelion_core::control_flow::{self, ControlFlowConfig};
use codehelion_core::discovery::{BuildVariant, Language, LanguageSelection};
use codehelion_core::features::{
    ApiCallFeature, CfgFeature, CharacteristicVector, FeatureHash, FileFeatures, SubtreeFeature,
    UnitFeatures, WindowFeature,
};
use codehelion_core::frontend::{Lexeme, SourceSpan, Token, TokenKind};
use codehelion_core::ir::{ByteRange, IR_SCHEMA_VERSION, IrNode, Shape, SyntaxIrFile};
use codehelion_core::near_match::{self, NearMatchConfig};
use codehelion_core::structural::{self, StructuralConfig};

const ITERATIONS: u32 = 25;

const fn hash(seed: u8) -> FeatureHash {
    FeatureHash::from_bytes([seed; 16])
}

fn candidate_unit() -> UnitFeatures {
    UnitFeatures {
        name: None,
        shape_tag: Shape::Function.tag(),
        range: ByteRange { start: 0, end: 20 },
        windows: (1..=4)
            .map(|seed| WindowFeature {
                hash: hash(seed),
                length: 4,
                range: ByteRange { start: 0, end: 20 },
                block: 0,
                offset: 0,
            })
            .collect(),
        subtrees: (5..=6)
            .map(|seed| SubtreeFeature {
                hash: hash(seed),
                node_count: 6,
                range: ByteRange { start: 0, end: 20 },
            })
            .collect(),
        vector: CharacteristicVector {
            node_count: 20,
            ..CharacteristicVector::default()
        },
        cfg: CfgFeature {
            hash: hash(7),
            skeleton_hash: hash(7),
            op_count: 4,
            skeleton_ops: 4,
            max_loop_depth: 1,
            branch_count: 1,
        },
        api: ApiCallFeature {
            names: Vec::new(),
            sequence_hash: hash(8),
            multiset_hash: hash(9),
        },
    }
}

fn candidate_files() -> Vec<FileFeatures> {
    vec![FileFeatures {
        units: vec![
            candidate_unit(),
            candidate_unit(),
            candidate_unit(),
            candidate_unit(),
        ],
    }]
}

fn token(index: usize) -> Token {
    Token {
        kind: TokenKind::Identifier,
        text: Lexeme::from("value"),
        span: SourceSpan {
            start_byte: index,
            end_byte: index + 1,
            start_line: 1,
            start_column: u32::try_from(index + 1).unwrap_or(u32::MAX),
        },
    }
}

const fn node(shape: Shape, start: usize, end: usize, children: Vec<IrNode>) -> IrNode {
    IrNode {
        shape,
        name: None,
        token_start: start,
        token_end: end,
        range: ByteRange { start, end },
        children,
    }
}

fn structural_file() -> SyntaxIrFile {
    let tokens = (0..20).map(token).collect();
    let statements = (0..4)
        .map(|statement| {
            let start = statement * 5;
            node(Shape::ExprStmt, start, start + 5, Vec::new())
        })
        .collect();
    let body = node(Shape::Block, 0, 20, statements);
    SyntaxIrFile {
        language: Language::Rust,
        frontend_version: "guardrail-work-bench",
        ir_schema_version: IR_SCHEMA_VERSION,
        tokens,
        roots: vec![node(Shape::Function, 0, 20, vec![body])],
        diagnostics: Vec::new(),
        error_ranges: Vec::new(),
        depth_truncated: false,
        test_module: false,
    }
}

fn structural_files() -> Vec<SyntaxIrFile> {
    (0..4).map(|_| structural_file()).collect()
}

fn structural_work(files: &[SyntaxIrFile], budget: usize) -> usize {
    let variant = BuildVariant::structural(LanguageSelection::default(), Language::C);
    let config = StructuralConfig {
        min_clone_tokens: 1,
        verification_budget: budget,
        ..StructuralConfig::default()
    };
    let stats = structural::analyze(files, &variant, &config).stats;
    stats
        .unit_pairs
        .saturating_sub(stats.verification_budget_dropped)
}

fn elapsed(mut work: impl FnMut() -> usize) -> Duration {
    let started = Instant::now();
    for _ in 0..ITERATIONS {
        black_box(work());
    }
    started.elapsed()
}

fn report(stage: &str, low_work: usize, high_work: usize, low: Duration, high: Duration) {
    println!(
        "{stage}: low_work={low_work}, high_work={high_work}, low_time={low:?}, high_time={high:?}"
    );
    assert!(
        low_work < high_work,
        "lowering the {stage} budget must reduce admitted work ({low_work} !< {high_work})"
    );
}

fn main() {
    let features = candidate_files();
    let low_control = ControlFlowConfig {
        pair_budget: 1,
        ..ControlFlowConfig::default()
    };
    let high_control = ControlFlowConfig {
        pair_budget: 6,
        ..ControlFlowConfig::default()
    };
    let low_control_work = control_flow::generate(&features, &low_control)
        .stats
        .candidate_pairs;
    let high_control_work = control_flow::generate(&features, &high_control)
        .stats
        .candidate_pairs;
    report(
        "control-flow pairing",
        low_control_work,
        high_control_work,
        elapsed(|| {
            control_flow::generate(&features, &low_control)
                .stats
                .candidate_pairs
        }),
        elapsed(|| {
            control_flow::generate(&features, &high_control)
                .stats
                .candidate_pairs
        }),
    );

    let low_near = NearMatchConfig {
        pair_budget: 1,
        ..NearMatchConfig::default()
    };
    let high_near = NearMatchConfig {
        pair_budget: 6,
        ..NearMatchConfig::default()
    };
    let low_near_work = near_match::generate(&features, &low_near)
        .stats
        .proposed_pairs;
    let high_near_work = near_match::generate(&features, &high_near)
        .stats
        .proposed_pairs;
    report(
        "near-match pairing",
        low_near_work,
        high_near_work,
        elapsed(|| {
            near_match::generate(&features, &low_near)
                .stats
                .proposed_pairs
        }),
        elapsed(|| {
            near_match::generate(&features, &high_near)
                .stats
                .proposed_pairs
        }),
    );

    let syntax = structural_files();
    let low_verification_work = structural_work(&syntax, 1);
    let high_verification_work = structural_work(&syntax, 6);
    report(
        "structural verification",
        low_verification_work,
        high_verification_work,
        elapsed(|| structural_work(&syntax, 1)),
        elapsed(|| structural_work(&syntax, 6)),
    );
}
