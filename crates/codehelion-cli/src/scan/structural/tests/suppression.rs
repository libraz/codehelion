//! Suppression rules, the presentation policy, and the structural
//! ceilings a configuration carries.

use super::*;

#[test]
fn include_trivial_overrides_only_this_invocations_presentation_policy() {
    let config = Config::default();
    assert_eq!(
        config.suppression.boilerplate.trivial_body,
        CategoryAction::RankDown
    );
    let presentation = presentation_suppression(&config, true);
    assert_eq!(
        presentation.boilerplate.trivial_body,
        CategoryAction::Report
    );
    assert_eq!(
        config.suppression.boilerplate.trivial_body,
        CategoryAction::RankDown,
        "the flag does not change the persisted configuration"
    );
}

#[test]
fn hiding_boilerplate_requires_every_member_to_share_its_category() {
    let category = Boilerplate::TrivialBody;
    assert_eq!(
        unanimous_boilerplate([Some(category), Some(category)]),
        Some(category)
    );
    assert_eq!(
        unanimous_boilerplate([Some(category), None]),
        None,
        "a non-boilerplate member remains a visible finding"
    );
}

/// A sibling whose host holds the same content as a primary member carries the
/// member's host fingerprint, so only the rank tells the two findings apart.
/// The id pasted from a report has to be the id suppression matches, and it has
/// to name the sibling alone: matching on the member's id would hide a finding
/// nobody wrote a rule about.
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the group, its sibling, and both candidate ids stay visible in one fixture"
)]
fn a_sibling_answers_to_the_finding_id_its_own_run_reports() {
    let variant = BuildVariant::structural(LanguageSelection::default(), Language::Rust);
    // One content in three places: two of them the primary group holds, the
    // third a sibling of that group.
    let host = UnitFingerprint::from_bytes([3; 16]);
    let units = (0..3)
        .map(|index| StructuralUnit {
            file: index,
            kind: UnitKind::Function,
            range: ByteRange { start: 0, end: 1 },
            start_line: 1,
            end_line: 1,
            token_start: 0,
            token_end: 1,
            name: Some(format!("unit_{index}").as_str().into()),
            boilerplate: None,
            test_code: false,
            test_code_evidence: None,
            fingerprint: host,
            content: FragmentFingerprint::from_bytes([11; 16]),
            normalized_content: FragmentFingerprint::from_bytes([21; 16]),
        })
        .collect::<Vec<_>>();
    let grouping_units = units
        .iter()
        .map(|unit| GroupingUnit {
            key: *unit.fingerprint.as_bytes(),
        })
        .collect::<Vec<_>>();
    let groups = group_units(
        &grouping_units,
        &[SimilarityEdge {
            a: 0,
            b: 1,
            similarity: 1.0,
            breakdown: None,
            class: CloneClass::Type1,
            confidence: Confidence::High,
        }],
        &GroupingConfig::default(),
    );
    assert_eq!(groups.groups[0].members, vec![0, 1]);
    let perfect = SimilarityBreakdown {
        lexical: 1.0,
        structural: 1.0,
        control_flow: None,
        type_similarity: None,
        api: None,
        composite: 1.0,
    };
    let fingerprint = CloneGroupFingerprint::from_bytes([42; 16]);
    let analysis = StructuralReport {
        units,
        groups,
        regions: Vec::new(),
        details: vec![GroupDetail {
            fingerprint,
            member_breakdowns: vec![perfect, perfect],
            cohesion_breakdown: perfect,
            identifier_jaccard: Some(1.0),
            body_materiality: BodyMateriality {
                has_loop: false,
                has_dynamic_allocation: false,
                call_count: 0,
            },
            boilerplate: None,
            test_code: false,
            test_code_evidence: None,
            width_family: false,
        }],
        unrepresented: Vec::new(),
        siblings: vec![GroupSiblings {
            group: 0,
            siblings: vec![StructuralSibling {
                unit: 2,
                clone_type: CloneClass::Type3,
                confidence: Confidence::Low,
                breakdown: perfect,
                basis: codehelion_core::structural::SiblingBasis::Similarity,
                signature: None,
                signature_units: None,
            }],
        }],
        near_misses: Vec::new(),
        stats: codehelion_core::structural::StructuralStats::default(),
    };
    let files = ["src/a.rs", "src/b.rs", "src/c.rs"]
        .into_iter()
        .map(|relative_path| SourceMeta {
            relative_path: relative_path.to_string(),
            directory_key: std::path::Path::new(relative_path)
                .parent()
                .map(crate::scan::path_key)
                .unwrap_or_default(),
            language: Language::Rust,
            marker_lines: Vec::new(),
            lines: 1,
            diagnostics: 0,
            unaccounted_tokens: 0,
            depth_truncated: false,
        })
        .collect::<Vec<_>>();
    // The rank a sibling's own host fingerprint reaches after the primary
    // members carrying it, which is what the report and the audit database
    // compose its finding id from.
    let sibling_finding = codehelion_core::stable_id::finding_id(
        &fingerprint,
        codehelion_core::stable_id::OccurrenceScope::Unit(&host),
        2,
    );
    let member_finding = codehelion_core::stable_id::finding_id(
        &fingerprint,
        codehelion_core::stable_id::OccurrenceScope::Unit(&host),
        0,
    );
    let verdict = |clone_id: &str| {
        let mut config = Config::default();
        config.suppression.clone_ids = vec![clone_id.to_string()];
        config.suppression.vendored_paths.clear();
        let mut rules = compile_rules(&config, &files, &analysis).expect("compile clone-id rule");
        let regions = reportable_regions(&analysis);
        evaluate_suppression(&config, &mut rules, &analysis, &regions, &[], &[], &variant).siblings
            [0][0]
    };

    assert!(
        verdict(&sibling_finding.to_hex()).is_some(),
        "the id the run reports for this sibling is the id it answers to"
    );
    assert!(
        verdict(&member_finding.to_hex()).is_none(),
        "a rule naming the primary member leaves the sibling visible"
    );
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the closed primary, sibling, and near-miss fixture keeps every suppression input visible"
)]
fn supplemental_diagnostics_apply_path_suppression_like_primary_findings() {
    let variant = BuildVariant::structural(LanguageSelection::default(), Language::Rust);
    let units = (0..5)
        .map(|index| StructuralUnit {
            file: index,
            kind: UnitKind::Function,
            range: ByteRange { start: 0, end: 1 },
            start_line: 1,
            end_line: 1,
            token_start: 0,
            token_end: 1,
            name: Some(format!("unit_{index}").as_str().into()),
            boilerplate: None,
            test_code: false,
            test_code_evidence: None,
            fingerprint: UnitFingerprint::from_bytes([u8::try_from(index + 1).unwrap(); 16]),
            content: FragmentFingerprint::from_bytes([u8::try_from(index + 11).unwrap(); 16]),
            normalized_content: FragmentFingerprint::from_bytes(
                [u8::try_from(index + 21).unwrap(); 16],
            ),
        })
        .collect::<Vec<_>>();
    let grouping_units = units
        .iter()
        .map(|unit| GroupingUnit {
            key: *unit.fingerprint.as_bytes(),
        })
        .collect::<Vec<_>>();
    let groups = group_units(
        &grouping_units,
        &[SimilarityEdge {
            a: 0,
            b: 1,
            similarity: 1.0,
            breakdown: None,
            class: CloneClass::Type1,
            confidence: Confidence::High,
        }],
        &GroupingConfig::default(),
    );
    let perfect = SimilarityBreakdown {
        lexical: 1.0,
        structural: 1.0,
        control_flow: None,
        type_similarity: None,
        api: None,
        composite: 1.0,
    };
    let analysis = StructuralReport {
        units,
        groups,
        regions: Vec::new(),
        details: vec![GroupDetail {
            fingerprint: CloneGroupFingerprint::from_bytes([42; 16]),
            member_breakdowns: vec![perfect, perfect],
            cohesion_breakdown: perfect,
            identifier_jaccard: Some(1.0),
            body_materiality: BodyMateriality {
                has_loop: false,
                has_dynamic_allocation: false,
                call_count: 0,
            },
            boilerplate: None,
            test_code: false,
            test_code_evidence: None,
            width_family: false,
        }],
        unrepresented: Vec::new(),
        siblings: vec![GroupSiblings {
            group: 0,
            siblings: vec![StructuralSibling {
                unit: 2,
                clone_type: CloneClass::Type3,
                confidence: Confidence::Low,
                breakdown: perfect,
                basis: codehelion_core::structural::SiblingBasis::Similarity,
                signature: None,
                signature_units: None,
            }],
        }],
        near_misses: vec![StructuralNearMiss {
            a: 3,
            b: 4,
            estimated_jaccard: 0.25,
        }],
        stats: codehelion_core::structural::StructuralStats::default(),
    };
    let files = [
        "src/a.rs",
        "src/b.rs",
        "vendor/sibling.rs",
        "vendor/left.rs",
        "vendor/right.rs",
    ]
    .into_iter()
    .map(|relative_path| SourceMeta {
        relative_path: relative_path.to_string(),
        directory_key: std::path::Path::new(relative_path)
            .parent()
            .map(crate::scan::path_key)
            .unwrap_or_default(),
        language: Language::Rust,
        marker_lines: Vec::new(),
        lines: 1,
        diagnostics: 0,
        unaccounted_tokens: 0,
        depth_truncated: false,
    })
    .collect::<Vec<_>>();
    let mut config = Config::default();
    config.suppression.paths = vec!["vendor/**".to_string()];
    config.suppression.vendored_paths.clear();
    let mut rules = compile_rules(&config, &files, &analysis).expect("compile path rule");
    let regions = reportable_regions(&analysis);
    let verdicts =
        evaluate_suppression(&config, &mut rules, &analysis, &regions, &[], &[], &variant);

    assert_eq!(verdicts.groups, vec![None]);
    assert!(verdicts.siblings[0][0].is_some());
    assert!(verdicts.near_misses[0].is_some());
}

#[test]
fn split_pair_shape_suppression_keeps_group_precedence() {
    let pair = VerifiedPair {
        members: vec![0, 1],
        canonical: 0,
        fingerprint: CloneGroupFingerprint::from_bytes([7; 16]),
        similarity: 0.9,
        breakdown: None,
        class: CloneClass::Type2,
        confidence: Confidence::High,
        boilerplate: Some(Boilerplate::MacroRepetition),
        width_family: true,
    };
    let hidden = BTreeMap::from([(Boilerplate::MacroRepetition, 3)]);
    assert_eq!(
        pair_shape_suppression(pair.boilerplate, pair.width_family, &hidden, Some(4)),
        Some(3)
    );

    let only_width = VerifiedPair {
        boilerplate: None,
        ..pair
    };
    assert_eq!(
        pair_shape_suppression(
            only_width.boilerplate,
            only_width.width_family,
            &hidden,
            Some(4)
        ),
        Some(4)
    );
}

#[test]
fn a_dominant_split_pair_shape_is_ranked_but_not_hidden() {
    let category = Boilerplate::MacroRepetition;
    let dominant = unanimous_boilerplate([
        Some(category),
        Some(category),
        Some(category),
        Some(category),
        None,
    ]);
    let hidden = BTreeMap::from([(category, 3)]);

    assert_eq!(dominant, None);
    assert_eq!(pair_shape_suppression(dominant, false, &hidden, None), None);
}

/// Structural pairs statement fragments where Fast pairs token windows, and
/// the two need different ceilings. Reading one number from the
/// configuration for both would hand this mode a limit chosen for the other
/// — which is how a ceiling meant as a safety valve becomes a silent cut.
#[test]
fn an_unset_ceiling_leaves_every_stage_at_its_own_default() {
    let config = structural_config(&Config::default());
    let defaults = StructuralConfig::default();
    assert_eq!(config.min_clone_tokens, defaults.min_clone_tokens);
    assert_eq!(config.candidate.posting_cap, defaults.candidate.posting_cap);
    assert_eq!(config.candidate.pair_budget, defaults.candidate.pair_budget);
    assert_eq!(
        config.near_match.posting_cap,
        defaults.near_match.posting_cap
    );
    assert_eq!(
        config.control_flow.pair_budget,
        defaults.control_flow.pair_budget
    );
    assert_eq!(
        config.signature_siblings, defaults.signature_siblings,
        "unset signature sibling limits keep the independent core defaults"
    );
}

/// A ceiling that is set bounds the whole funnel, not one stage of it.
#[test]
fn a_configured_ceiling_reaches_every_candidate_stage() {
    let cfg = Config {
        min_clone_tokens: 37,
        limits: crate::config::Limits {
            posting_cap: Some(9),
            pair_budget: Some(11),
            verification_budget: Some(13),
            max_alignment_cells: Some(17),
            ..crate::config::Limits::default()
        },
        ..Config::default()
    };
    let config = structural_config(&cfg);
    assert_eq!(config.min_clone_tokens, 37);
    for cap in [
        config.candidate.posting_cap,
        config.near_match.posting_cap,
        config.control_flow.posting_cap,
    ] {
        assert_eq!(cap, 9);
    }
    for budget in [
        config.candidate.pair_budget,
        config.near_match.pair_budget,
        config.control_flow.pair_budget,
    ] {
        assert_eq!(budget, 11);
    }
    assert_eq!(config.verification_budget, 13);
    assert_eq!(config.verify.max_alignment_cells, 17);
}

#[test]
fn signature_sibling_limits_reach_core_without_reusing_similarity_limits() {
    let cfg = Config {
        limits: crate::config::Limits {
            sibling_candidate_budget: Some(7),
            sibling_per_group_cap: Some(11),
            sibling_total_cap: Some(13),
            signature_sibling_candidate_budget: Some(17),
            signature_sibling_per_group_cap: Some(19),
            signature_sibling_total_cap: Some(23),
            ..crate::config::Limits::default()
        },
        ..Config::default()
    };
    let config = structural_config(&cfg);
    assert_eq!(config.siblings.candidate_budget, 7);
    assert_eq!(config.siblings.per_group_cap, 11);
    assert_eq!(config.siblings.total_cap, 13);
    assert_eq!(config.signature_siblings.candidate_budget, 17);
    assert_eq!(config.signature_siblings.per_group_cap, 19);
    assert_eq!(config.signature_siblings.total_cap, 23);
}

#[test]
fn untrusted_clamp_reaches_signature_sibling_core_limits() {
    let mut cfg = Config {
        limits: crate::config::Limits {
            signature_sibling_candidate_budget: Some(usize::MAX),
            signature_sibling_per_group_cap: Some(usize::MAX),
            signature_sibling_total_cap: Some(usize::MAX),
            ..crate::config::Limits::default()
        },
        ..Config::default()
    };
    cfg.limits
        .clamp_to_untrusted(&codehelion_core::execution::Limits::untrusted());
    let config = structural_config(&cfg);
    let defaults = codehelion_core::structural::SignatureSiblingConfig::default();
    assert_eq!(
        config.signature_siblings.candidate_budget,
        defaults.candidate_budget
    );
    assert_eq!(
        config.signature_siblings.per_group_cap,
        defaults.per_group_cap
    );
    assert_eq!(config.signature_siblings.total_cap, defaults.total_cap);
}
