//! A focused reproduction of hand-written enum-string conversion mirrors.
//!
//! Three public surfaces carry four conversion functions.  Three conversion
//! tables are exact mirrors everywhere; `band_type` has one alias branch
//! missing from the Node surface.  The test pins the input so the structural
//! funnel can be measured without conflating its candidate sources.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use codehelion_core::candidate::{self, CandidateConfig, CandidateSet};
use codehelion_core::control_flow::{self, ControlFlowConfig, ControlFlowSet};
use codehelion_core::discovery::{BuildVariant, Language, LanguageSelection};
use codehelion_core::features::{self, FileFeatures};
use codehelion_core::ir::{Shape, StructuralFrontend, SyntaxIrFile};
use codehelion_core::near_match::{self, NearMatchConfig, NearMatchSet};
use codehelion_core::stable_id::FragmentFingerprint;
use codehelion_core::structural::{self, StructuralConfig, StructuralReport};
use codehelion_core::verify::{self, Verdict};
use codehelion_frontend_rust::ir::RustStructuralFrontend;

const C_ABI: &str = r#"
fn placement_from_string(value: &str) -> Option<Placement> {
    match value {
        "pre" => Some(Placement::Pre),
        "post" => Some(Placement::Post),
        "center" => Some(Placement::Center),
        _ => None,
    }
}

fn phase_mode_from_string(value: &str) -> Option<PhaseMode> {
    match value {
        "minimum" => Some(PhaseMode::Minimum),
        "linear" => Some(PhaseMode::Linear),
        "mixed" => Some(PhaseMode::Mixed),
        "maximum" => Some(PhaseMode::Maximum),
        _ => None,
    }
}

fn phase_mode_from_integer(value: &str) -> Option<PhaseMode> {
    match value {
        "0" => Some(PhaseMode::Minimum),
        "1" => Some(PhaseMode::Linear),
        "2" => Some(PhaseMode::Mixed),
        "3" => Some(PhaseMode::Maximum),
        "4" => Some(PhaseMode::Hold),
        _ => None,
    }
}

fn coeff_mode_from_string(value: &str) -> Option<CoeffMode> {
    match value {
        "raw" => Some(CoeffMode::Raw),
        "normalized" => Some(CoeffMode::Normalized),
        "weighted" => Some(CoeffMode::Weighted),
        "adaptive" => Some(CoeffMode::Adaptive),
        "fixed" => Some(CoeffMode::Fixed),
        "dynamic" => Some(CoeffMode::Dynamic),
        _ => None,
    }
}

fn band_type_from_string(value: &str) -> Option<BandType> {
    match value {
        "low_pass" => Some(BandType::LowPass),
        "high_pass" => Some(BandType::HighPass),
        "band_pass" => Some(BandType::BandPass),
        "band_stop" => Some(BandType::BandStop),
        "bell" | "highCut" | "lowCut" => Some(BandType::Bell),
        _ => None,
    }
}
"#;

const WASM: &str = C_ABI;

const NODE: &str = r#"
fn placement_from_string(value: &str) -> Option<Placement> {
    match value {
        "pre" => Some(Placement::Pre),
        "post" => Some(Placement::Post),
        "center" => Some(Placement::Center),
        _ => None,
    }
}

fn phase_mode_from_string(value: &str) -> Option<PhaseMode> {
    match value {
        "minimum" => Some(PhaseMode::Minimum),
        "linear" => Some(PhaseMode::Linear),
        "mixed" => Some(PhaseMode::Mixed),
        "maximum" => Some(PhaseMode::Maximum),
        _ => None,
    }
}

fn phase_mode_from_integer(value: &str) -> Option<PhaseMode> {
    match value {
        "0" => Some(PhaseMode::Minimum),
        "1" => Some(PhaseMode::Linear),
        "2" => Some(PhaseMode::Mixed),
        "3" => Some(PhaseMode::Maximum),
        "4" => Some(PhaseMode::Hold),
        _ => None,
    }
}

fn coeff_mode_from_string(value: &str) -> Option<CoeffMode> {
    match value {
        "raw" => Some(CoeffMode::Raw),
        "normalized" => Some(CoeffMode::Normalized),
        "weighted" => Some(CoeffMode::Weighted),
        "adaptive" => Some(CoeffMode::Adaptive),
        "fixed" => Some(CoeffMode::Fixed),
        "dynamic" => Some(CoeffMode::Dynamic),
        _ => None,
    }
}

fn band_type_from_string(value: &str) -> Option<BandType> {
    match value {
        "low_pass" => Some(BandType::LowPass),
        "high_pass" => Some(BandType::HighPass),
        "band_pass" => Some(BandType::BandPass),
        "band_stop" => Some(BandType::BandStop),
        _ => None,
    }
}
"#;

const BAND_TYPE_C_ABI: &str = r#"
fn band_type_from_string(value: &str) -> Option<BandType> {
    match value {
        "low_pass" => Some(BandType::LowPass),
        "high_pass" => Some(BandType::HighPass),
        "band_pass" => Some(BandType::BandPass),
        "band_stop" => Some(BandType::BandStop),
        "bell" | "highCut" | "lowCut" => Some(BandType::Bell),
        _ => None,
    }
}
"#;

const BAND_TYPE_NODE: &str = r#"
fn band_type_from_string(value: &str) -> Option<BandType> {
    match value {
        "low_pass" => Some(BandType::LowPass),
        "high_pass" => Some(BandType::HighPass),
        "band_pass" => Some(BandType::BandPass),
        "band_stop" => Some(BandType::BandStop),
        _ => None,
    }
}
"#;

fn parse(source: &str) -> SyntaxIrFile {
    RustStructuralFrontend.parse(source)
}

fn variant() -> BuildVariant {
    BuildVariant::structural(LanguageSelection::default(), Language::C)
}

fn unit_id(report: &StructuralReport, file: usize, name: &str) -> usize {
    report
        .units
        .iter()
        .position(|unit| unit.file == file && unit.name.as_deref() == Some(name))
        .unwrap_or_else(|| panic!("{name} is an analysed unit in surface {file}"))
}

fn group_with(
    report: &StructuralReport,
    unit: usize,
) -> &codehelion_core::grouping::StructuralGroup {
    report
        .groups
        .groups
        .iter()
        .find(|group| group.members.contains(&unit))
        .unwrap_or_else(|| panic!("unit {unit} belongs to a clone group"))
}

fn function_statements(file: &SyntaxIrFile) -> Vec<codehelion_core::ir::StatementSummary> {
    let mut statements = None;
    file.walk(&mut |node| {
        if statements.is_none() && matches!(node.shape, Shape::Function) {
            statements = Some(verify::statement_sequence(node, &file.tokens));
        }
    });
    statements.expect("the single-function source has one function")
}

struct PairFunnel {
    exact: CandidateSet,
    near: NearMatchSet,
    control_flow: ControlFlowSet,
    report: StructuralReport,
    verdict: Verdict,
}

fn single_pair_funnel(left: &str, right: &str) -> PairFunnel {
    let files = vec![parse(left), parse(right)];
    let features: Vec<FileFeatures> = files.iter().map(features::extract).collect();
    let exact = candidate::generate(&features, &CandidateConfig::default());
    let near = near_match::generate(&features, &NearMatchConfig::default());
    let control_flow = control_flow::generate(&features, &ControlFlowConfig::default());
    let statements = [
        function_statements(&files[0]),
        function_statements(&files[1]),
    ];
    let verdict = verify::verify(
        &verify::UnitView {
            statements: &statements[0],
            tokens: &files[0].tokens,
            content: FragmentFingerprint::from_bytes([0; 16]),
            features: &features[0].units[0],
            types: None,
            apis: None,
        },
        &verify::UnitView {
            statements: &statements[1],
            tokens: &files[1].tokens,
            content: FragmentFingerprint::from_bytes([1; 16]),
            features: &features[1].units[0],
            types: None,
            apis: None,
        },
        &StructuralConfig::default().verify,
    );
    let report = structural::analyze(&files, &variant(), &StructuralConfig::default());
    PairFunnel {
        exact,
        near,
        control_flow,
        report,
        verdict,
    }
}

#[test]
fn exact_conversion_mirrors_are_grouped_but_the_shorter_band_type_is_not() {
    let files = [parse(C_ABI), parse(WASM), parse(NODE)];
    let report = structural::analyze(&files, &variant(), &StructuralConfig::default());

    for name in [
        "placement_from_string",
        "phase_mode_from_string",
        "phase_mode_from_integer",
        "coeff_mode_from_string",
    ] {
        let c_abi = unit_id(&report, 0, name);
        let wasm = unit_id(&report, 1, name);
        let node = unit_id(&report, 2, name);
        let group = group_with(&report, c_abi);
        assert!(group.members.contains(&wasm), "{name} C ABI/WASM mirror");
        assert!(group.members.contains(&node), "{name} C ABI/Node mirror");
    }

    let c_abi = unit_id(&report, 0, "band_type_from_string");
    let wasm = unit_id(&report, 1, "band_type_from_string");
    let node = unit_id(&report, 2, "band_type_from_string");
    let group = group_with(&report, c_abi);
    assert!(
        group.members.contains(&wasm),
        "the exact band-type mirror joins"
    );
    assert!(
        !group.members.contains(&node),
        "the shorter Node band-type table must not join the full mirrors"
    );
}

#[test]
fn shorter_band_type_funnel_is_measured_on_only_that_pair() {
    let funnel = single_pair_funnel(BAND_TYPE_C_ABI, BAND_TYPE_NODE);

    // The asymmetry is not proposed by any of the three candidate sources.
    // This is intentionally a two-unit run, so every counter below belongs to
    // this one pair instead of being an aggregate over the other mirrors.
    assert_eq!(funnel.exact.stats.candidate_pairs, 0);
    assert_eq!(funnel.near.stats.signed_units, 0);
    assert_eq!(funnel.near.stats.skipped_small, 2);
    assert_eq!(funnel.near.stats.proposed_pairs, 0);
    assert_eq!(funnel.near.stats.filtered_by_size, 0);
    assert_eq!(funnel.near.stats.filtered_by_jaccard, 0);
    assert_eq!(funnel.near.stats.candidate_pairs, 0);
    assert_eq!(funnel.control_flow.stats.candidate_pairs, 0);
    assert_eq!(funnel.report.stats.unit_pairs, 0);
    assert_eq!(funnel.report.stats.verified_pairs, 0);
    assert!(funnel.report.groups.groups.is_empty());

    // The verifier would accept the pair as a Type-3 clone.  Its absence is
    // therefore pre-gate candidate loss, not a verification rejection.
    assert!(funnel.verdict.class.is_some());
}
