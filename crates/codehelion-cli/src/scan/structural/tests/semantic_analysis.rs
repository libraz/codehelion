//! Semantic windows, the confidence they carry, and the programs sources
//! belong to.

use crate::config::Config;
use codehelion_core::discovery::{
    BuildVariant, DiscoveryReport, Language, LanguageSelection, SkipReport, SourceUnit, TargetKind,
};
use std::path::PathBuf;

/// One source unit as discovery would have handed it over.
fn discovered_source(relative_path: &str, language: Language, is_header: bool) -> SourceUnit {
    let bytes: std::sync::Arc<[u8]> = std::sync::Arc::from(Vec::new());
    SourceUnit {
        relative_path: PathBuf::from(relative_path),
        absolute_path: PathBuf::from("/tree").join(relative_path),
        language,
        is_header,
        content_hash: codehelion_core::discovery::ContentHash::of(&bytes),
        source_bytes: bytes,
        byte_len: 0,
        package: None,
        crate_name: None,
        target_kind: TargetKind::Library,
    }
}

#[test]
fn incomplete_normalization_lowers_confidence_without_affecting_matching() {
    assert!((super::normalization_confidence(3, 0) - 1.0).abs() < f64::EPSILON);
    assert!((super::normalization_confidence(0, 2) - 0.0).abs() < f64::EPSILON);
    let empty_interactions = std::collections::BTreeSet::new();
    let empty_data_flows = std::collections::BTreeSet::new();
    assert!(
        (super::semantic_confidence(
            0.7,
            super::SemanticConfidenceEvidence {
                normalization: 1.0,
                interactions: &empty_interactions,
                data_flows: &empty_data_flows,
                cfg_shape: None,
            },
            super::SemanticConfidenceEvidence {
                normalization: 0.5,
                interactions: &empty_interactions,
                data_flows: &empty_data_flows,
                cfg_shape: None,
            },
        ) - 0.35)
            .abs()
            < f64::EPSILON
    );
    let file = std::collections::BTreeSet::from(["file_io".to_owned()]);
    let lock = std::collections::BTreeSet::from(["synchronization".to_owned()]);
    assert!((super::interaction_confidence(&file, &file) - 1.05).abs() < f64::EPSILON);
    assert!((super::interaction_confidence(&file, &lock) - 0.85).abs() < f64::EPSILON);
    assert!(
        (super::interaction_confidence(&file, &std::collections::BTreeSet::new()) - 1.0).abs()
            < f64::EPSILON
    );
    let filter_map = std::collections::BTreeSet::from([(
        "rust::Iterator::filter".to_owned(),
        "rust::Iterator::map".to_owned(),
    )]);
    let map_filter = std::collections::BTreeSet::from([(
        "rust::Iterator::map".to_owned(),
        "rust::Iterator::filter".to_owned(),
    )]);
    assert!((super::data_flow_confidence(&filter_map, &filter_map) - 1.05).abs() < f64::EPSILON);
    assert!((super::data_flow_confidence(&filter_map, &map_filter) - 0.85).abs() < f64::EPSILON);
    assert!(
        (super::data_flow_confidence(&filter_map, &std::collections::BTreeSet::new()) - 1.0).abs()
            < f64::EPSILON
    );
    let straight = super::CfgShape {
        blocks: 2,
        flow_edges: 1,
        taken_edges: 0,
        not_taken_edges: 0,
        unwind_edges: 0,
        return_edges: 0,
    };
    let branch = super::CfgShape {
        taken_edges: 1,
        not_taken_edges: 1,
        ..straight
    };
    assert!((super::cfg_confidence(Some(straight), Some(straight)) - 1.05).abs() < f64::EPSILON);
    assert!((super::cfg_confidence(Some(straight), Some(branch)) - 0.85).abs() < f64::EPSILON);
    assert!((super::cfg_confidence(Some(straight), None) - 1.0).abs() < f64::EPSILON);
}

#[test]
fn compiler_cfg_is_reduced_to_the_overlapping_semantic_window() {
    let anchor = |start_byte, end_byte| {
        codehelion_helper::ir::Anchor::written_here(codehelion_helper::ir::SourceRange {
            file: "src/lib.rs".to_string(),
            start_byte,
            end_byte,
            start_line: 1,
        })
    };
    let cfg = codehelion_helper::ir::ControlFlowGraph {
        blocks: vec![
            codehelion_helper::ir::BasicBlock {
                anchor: anchor(10, 20),
                length: 2,
            },
            codehelion_helper::ir::BasicBlock {
                anchor: anchor(20, 30),
                length: 1,
            },
            codehelion_helper::ir::BasicBlock {
                anchor: anchor(40, 50),
                length: 1,
            },
        ],
        edges: vec![
            codehelion_helper::ir::Edge {
                from: 0,
                to: 1,
                kind: codehelion_helper::ir::EdgeKind::Flow,
            },
            codehelion_helper::ir::Edge {
                from: 1,
                to: 2,
                kind: codehelion_helper::ir::EdgeKind::Taken,
            },
        ],
    };
    assert_eq!(
        super::semantic_window_cfg_shape(
            Some(&cfg),
            "src/lib.rs",
            codehelion_core::semantic::SemanticSourceRange { start: 10, end: 30 },
        ),
        Some(super::CfgShape {
            blocks: 2,
            flow_edges: 1,
            taken_edges: 0,
            not_taken_edges: 0,
            unwind_edges: 0,
            return_edges: 0,
        })
    );
    assert!(
        super::semantic_window_cfg_shape(
            Some(&cfg),
            "src/lib.rs",
            codehelion_core::semantic::SemanticSourceRange { start: 30, end: 40 },
        )
        .is_none()
    );
}

#[test]
fn direct_data_flow_is_scoped_to_its_semantic_window() {
    let summary = codehelion_helper::ir::DataFlowSummary {
        computed: true,
        flows: vec![
            (
                "10:16:rust::Iterator::filter".to_owned(),
                "17:20:rust::Iterator::map".to_owned(),
            ),
            (
                "40:46:rust::Iterator::filter".to_owned(),
                "47:50:rust::Iterator::map".to_owned(),
            ),
        ],
    };
    let first = super::semantic_window_data_flows(
        &summary,
        codehelion_core::semantic::SemanticSourceRange { start: 0, end: 30 },
    );
    assert_eq!(
        first,
        std::collections::BTreeSet::from([(
            "rust::Iterator::filter".to_owned(),
            "rust::Iterator::map".to_owned(),
        )])
    );
    assert!(
        super::semantic_window_data_flows(
            &summary,
            codehelion_core::semantic::SemanticSourceRange { start: 21, end: 39 },
        )
        .is_empty()
    );
}

/// A tree the compilation database does not describe still has to account for
/// every file it kept: a header the semantic run reads under no program is a
/// file the structural run analysed and this one silently lost.
#[test]
fn a_header_no_command_claims_belongs_to_the_no_build_program() {
    let sources = [
        discovered_source("src/a.cpp", Language::Cpp, false),
        discovered_source("include/a.hpp", Language::Cpp, true),
    ];
    let discovery = DiscoveryReport {
        units: Vec::new(),
        build_variant: BuildVariant::structural(LanguageSelection::default(), Language::Cpp),
        header_language: Language::Cpp,
        packages: Vec::new(),
        suppressed_generated: Vec::new(),
        skipped: SkipReport::default(),
        compile_commands: None,
        compile_commands_error: None,
    };

    let partitions = super::semantic_partitions(
        &discovery,
        &sources,
        &Config::default(),
        None,
        std::path::Path::new("/tree"),
        std::time::Duration::from_millis(1),
    )
    .expect("partitions are built");

    let analysed: std::collections::BTreeSet<PathBuf> = partitions
        .iter()
        .flat_map(|partition| partition.sources.iter())
        .map(|source| source.relative_path.clone())
        .collect();
    let discovered: std::collections::BTreeSet<PathBuf> = sources
        .iter()
        .map(|source| source.relative_path.clone())
        .collect();
    assert_eq!(
        analysed, discovered,
        "every source the globs kept belongs to a program"
    );
}

/// Headers stay with the translation units that give them meaning: a run whose
/// commands already hold them does not analyse them a second time under the
/// no-build program.
#[test]
fn a_header_a_command_already_holds_is_not_repeated_by_the_no_build_program() {
    let sources = [
        discovered_source("src/a.cpp", Language::Cpp, false),
        discovered_source("include/a.hpp", Language::Cpp, true),
    ];
    let discovery = DiscoveryReport {
        units: Vec::new(),
        build_variant: BuildVariant::structural(LanguageSelection::default(), Language::Cpp),
        header_language: Language::Cpp,
        packages: Vec::new(),
        suppressed_generated: Vec::new(),
        skipped: SkipReport::default(),
        compile_commands: None,
        compile_commands_error: None,
    };

    let claimed = super::unconfigured_cpp_partition(&discovery, &sources, false)
        .expect("the translation unit needs a program");
    assert!(
        claimed.sources.iter().all(|source| !source.is_header),
        "a header a command partition holds is not analysed twice"
    );
}
