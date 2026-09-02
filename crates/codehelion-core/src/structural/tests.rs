use super::regions::Dropped;
use super::reporting::{PairEvidence, group_detail, group_fingerprint, verifier_calls};
use super::{
    Boilerplate, CloneClass, Confirmed, CrossVariantComparison, CrossVariantUnit,
    DirectoryPartition, RegionOccurrence, RegionSide, ResolvedTypes, SignatureSiblingSweepStats,
    StructuralConfig, StructuralRegion, Unit, compare_build_variants, covers_run,
    dominant_boilerplate, drop_subsumed, features, flatten_units, fold_by_content,
    is_allocation_api, merge_adjacent, set_jaccard, unit_evidence, unrepresented_pairs, view,
};
use crate::candidate::StatementRun;
use crate::conditional::{ArmPath, ArmTracker, StaticCondition};
use crate::discovery::{BuildVariant, Language, LanguageSelection};
use crate::engine::{LiteralNorm, normalize::Resolution};
use crate::frontend::{SourceSpan, Token, TokenKind, UnitKind};
use crate::grouping;
use crate::ir::{ByteRange, IR_SCHEMA_VERSION, IrNode, Shape, Signature, SyntaxIrFile};
use crate::stable_id::{CloneGroupFingerprint, FragmentFingerprint, UnitFingerprint};
use crate::types::TypeTag;
use crate::verify::{Confidence, SimilarityBreakdown};
use std::collections::BTreeSet;

mod cross_variant;
mod evidence;
mod model;
mod pairs;
mod regions;
mod reporting;
mod units;

fn unit_at(file: usize, start: usize, end: usize) -> Unit {
    Unit {
        file,
        local: 0,
        kind: UnitKind::Function,
        statements: Vec::new(),
        fingerprint: UnitFingerprint::from_bytes([0; 16]),
        content: FragmentFingerprint::from_bytes([0; 16]),
        normalized_content: FragmentFingerprint::from_bytes([0; 16]),
        signature: None,
        directory: None,
        range: ByteRange { start, end },
        lines: (1, 2),
        tokens: (0, 0),
        name: None,
        boilerplate: None,
        test_code: false,
        test_code_evidence: None,
        arms: ArmPath::default(),
    }
}
fn cohesion_file(words: &[&str]) -> SyntaxIrFile {
    let tokens = words
        .iter()
        .enumerate()
        .map(|(index, word)| Token {
            kind: TokenKind::Identifier,
            text: (*word).into(),
            span: SourceSpan {
                start_byte: index * 8,
                end_byte: index * 8 + word.len(),
                start_line: 1,
                start_column: 1,
            },
        })
        .collect();
    let token_end = words.len();
    SyntaxIrFile {
        language: Language::Rust,
        frontend_version: "test",
        ir_schema_version: IR_SCHEMA_VERSION,
        tokens,
        signatures: Vec::new(),
        roots: vec![IrNode {
            shape: Shape::Function,
            name: None,
            token_start: 0,
            token_end,
            range: ByteRange {
                start: 0,
                end: token_end * 8,
            },
            children: vec![IrNode {
                shape: Shape::Block,
                name: None,
                token_start: 0,
                token_end,
                range: ByteRange {
                    start: 0,
                    end: token_end * 8,
                },
                children: vec![IrNode {
                    shape: Shape::ExprStmt,
                    name: None,
                    token_start: 0,
                    token_end,
                    range: ByteRange {
                        start: 0,
                        end: token_end * 8,
                    },
                    children: Vec::new(),
                }],
            }],
        }],
        diagnostics: Vec::new(),
        error_ranges: Vec::new(),
        depth_truncated: false,
        test_module: false,
    }
}

fn rich_cohesion_file(words: &[&str]) -> SyntaxIrFile {
    let mut file = cohesion_file(words);
    file.roots[0].children[0].children = words
        .iter()
        .enumerate()
        .map(|(index, _)| IrNode {
            shape: Shape::ExprStmt,
            name: None,
            token_start: index,
            token_end: index + 1,
            range: ByteRange {
                start: index * 8,
                end: index * 8 + 1,
            },
            children: Vec::new(),
        })
        .collect();
    file
}
fn divergent_cohesion_file(words: &[&str]) -> SyntaxIrFile {
    let mut file = rich_cohesion_file(words);
    for child in &mut file.roots[0].children[0].children {
        child.shape = Shape::Return;
    }
    file
}

fn second_divergent_cohesion_file(words: &[&str]) -> SyntaxIrFile {
    let mut file = rich_cohesion_file(words);
    for child in &mut file.roots[0].children[0].children {
        child.shape = Shape::Break;
    }
    file
}
#[test]
fn signature_context_is_cross_file_scoped_and_cardinality_safe() {
    let mut files = vec![
        rich_cohesion_file(&["a", "b", "c", "d", "e", "f", "g", "h", "i", "j"]),
        rich_cohesion_file(&["a", "b", "c", "d", "e", "f", "g", "h", "i", "j"]),
        divergent_cohesion_file(&["a", "b", "c", "d", "e", "f", "g", "h", "i", "x"]),
        second_divergent_cohesion_file(&["q", "r", "s", "t", "u", "v", "w", "x", "y", "z"]),
    ];
    let signature = Signature::new(Language::Rust, "rust|params=[]|return=()");
    for file in &mut files {
        file.signatures = vec![(file.roots[0].range, signature.clone())];
    }
    let config = StructuralConfig {
        min_clone_tokens: 1,
        ..StructuralConfig::default()
    };
    let report = crate::structural::analyze_with_context(
        &files,
        &BuildVariant::structural(
            LanguageSelection {
                rust: true,
                c: false,
                cpp: false,
            },
            Language::Rust,
        ),
        &config,
        &[
            DirectoryPartition::new(0),
            DirectoryPartition::new(0),
            DirectoryPartition::new(0),
            DirectoryPartition::new(1),
        ],
    );
    assert_eq!(report.stats.signature_siblings.groups_considered, 1);
    assert_eq!(report.stats.signature_siblings.eligible_candidates, 1);
    assert_eq!(report.stats.signature_siblings.candidates_examined, 1);
    assert_eq!(report.stats.signature_siblings.accepted, 1);
    assert_eq!(report.siblings.len(), 1);
    assert_eq!(report.siblings[0].siblings.len(), 1);
    assert_eq!(report.siblings[0].siblings[0].unit, 2);
    assert_eq!(
        report.siblings[0].siblings[0].basis,
        super::SiblingBasis::Signature
    );

    let variant = BuildVariant::structural(
        LanguageSelection {
            rust: true,
            c: false,
            cpp: false,
        },
        Language::Rust,
    );
    let legacy = crate::structural::analyze(&files, &variant, &config);
    assert_eq!(
        legacy.stats.signature_siblings,
        SignatureSiblingSweepStats::default()
    );
    assert!(legacy.siblings.is_empty());
    assert_eq!(report.units, legacy.units);
    assert_eq!(report.groups, legacy.groups);
    assert_eq!(report.regions, legacy.regions);
    assert_eq!(report.details, legacy.details);
    assert_eq!(report.unrepresented, legacy.unrepresented);
    assert_eq!(report.near_misses, legacy.near_misses);
    assert_eq!(report.stats.siblings, legacy.stats.siblings);
    let mut primary_stats = report.stats;
    primary_stats.signature_siblings = SignatureSiblingSweepStats::default();
    assert_eq!(primary_stats, legacy.stats);

    let mismatch = crate::structural::analyze_with_context(
        &files,
        &variant,
        &config,
        &[DirectoryPartition::new(0)],
    );
    assert_eq!(mismatch, legacy);
}
