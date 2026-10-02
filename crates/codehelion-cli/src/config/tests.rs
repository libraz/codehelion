use super::*;

#[test]
fn defaults_are_the_evaluated_values() {
    let config = Config::default();
    assert_eq!(config.min_clone_tokens, 20);
    assert!((config.entropy_ratio_floor - 0.60).abs() < f64::EPSILON);
    assert_eq!(config.literal_normalization, LiteralNormalization::Full);
    assert!(config.languages.rust && config.languages.c && config.languages.cpp);
    assert_eq!(config.database, PathBuf::from(".codehelion/audit.db"));
    assert!(config.semantic.enabled("sequence-pipeline-v1"));
    assert!(
        config
            .semantic
            .enabled("cross-language-sequence-pipeline-v1")
    );
}

#[test]
fn missing_keys_fall_back_to_defaults() {
    let config = Config::from_toml("min-clone-tokens = 30").unwrap();
    assert_eq!(config.min_clone_tokens, 30);
    // Untouched keys keep their defaults.
    assert_eq!(config.literal_normalization, LiteralNormalization::Full);
    assert!(config.languages.rust);
    assert_eq!(config.limits, Limits::default());
}

#[test]
fn zero_minimum_clone_tokens_is_rejected_before_a_scan_can_rank_it() {
    let error = Config::from_toml("min-clone-tokens = 0")
        .expect_err("zero would make every priority's size factor zero");
    assert!(format!("{error:#}").contains("min-clone-tokens must be at least 1"));
}

#[test]
fn degenerate_numeric_settings_are_rejected_with_their_key() {
    for (key, text) in [
        ("jobs", "jobs = 0"),
        ("limits.max-file-bytes", "[limits]\nmax-file-bytes = 0"),
        ("limits.parse-timeout-ms", "[limits]\nparse-timeout-ms = 0"),
        (
            "limits.helper-timeout-ms",
            "[limits]\nhelper-timeout-ms = 0",
        ),
        ("limits.posting-cap", "[limits]\nposting-cap = 1"),
        ("limits.pair-budget", "[limits]\npair-budget = 0"),
        ("limits.near-miss-delta", "[limits]\nnear-miss-delta = 0"),
        ("limits.near-miss-cap", "[limits]\nnear-miss-cap = 0"),
        (
            "limits.signature-sibling-candidate-budget",
            "[limits]\nsignature-sibling-candidate-budget = 0",
        ),
        (
            "limits.signature-sibling-per-group-cap",
            "[limits]\nsignature-sibling-per-group-cap = 0",
        ),
        (
            "limits.signature-sibling-total-cap",
            "[limits]\nsignature-sibling-total-cap = 0",
        ),
        ("limits.max-component", "[limits]\nmax-component = 1"),
    ] {
        let error = Config::from_toml(text).expect_err("degenerate value must be rejected");
        assert!(format!("{error:#}").contains(key));
    }
}

#[test]
fn entropy_ratio_floor_is_configurable_and_bounded() {
    let config = Config::from_toml("entropy-ratio-floor = 0.45").unwrap();
    assert!((config.entropy_ratio_floor - 0.45).abs() < f64::EPSILON);

    for value in ["-0.01", "1.01"] {
        let error = Config::from_toml(&format!("entropy-ratio-floor = {value}"))
            .expect_err("the normalized entropy floor must stay in range");
        assert!(format!("{error:#}").contains("entropy-ratio-floor"));
    }
}

#[test]
fn unknown_key_is_rejected() {
    let err = Config::from_toml("min_clone_tokens = 30")
        .expect_err("snake_case key is unknown; kebab-case is expected");
    assert!(format!("{err:#}").contains("unknown field"));
}

#[test]
fn round_trips_through_toml() {
    let config = Config::default();
    let text = config.to_toml().unwrap();
    let back = Config::from_toml(&text).unwrap();
    assert_eq!(config, back);
}

#[test]
fn template_parses_as_defaults() {
    // Every setting in the template is commented out, so it parses to an
    // empty table and resolves to the defaults.
    let config = Config::from_toml(TEMPLATE).unwrap();
    assert_eq!(config, Config::default());
}

/// The setting names one text spells, taken without the table they sit in so
/// each is compared the way a reader searches the file for it.
fn setting_names(text: &str) -> std::collections::BTreeSet<&str> {
    let mut names = std::collections::BTreeSet::new();
    for line in text.lines() {
        let line = line.trim().trim_start_matches('#').trim();
        // `config show` states an unset optional setting as `table.key: what
        // its absence selects`; every other setting is an assignment.
        let Some((name, _)) = line.split_once(" = ").or_else(|| line.split_once(": ")) else {
            continue;
        };
        let leaf = name.rsplit('.').next().unwrap_or(name);
        let spelled_as_a_key = !leaf.is_empty()
            && leaf
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
        if spelled_as_a_key {
            names.insert(leaf);
        }
    }
    names
}

/// A configuration carrying a value for every optional setting, so serializing
/// it names the keys an all-defaults one leaves out.
fn every_setting_carried() -> Config {
    let mut config = Config::default();
    config
        .limits
        .clamp_to_untrusted(&codehelion_core::execution::Limits::untrusted());
    config.helpers = Helpers {
        rust: Some(PathBuf::from("/opt/rust")),
        clang: Some(PathBuf::from("/opt/clang")),
    };
    config
}

#[test]
fn the_template_offers_every_setting_a_configuration_accepts() {
    let carried = every_setting_carried().to_toml().unwrap();
    // The all-defaults rendering states the optional settings as absences, and
    // `config init` is the file where those absences get filled in.
    let shown = Config::default().to_display_toml().unwrap();
    let mut settable = setting_names(&carried);
    settable.extend(setting_names(&shown));
    let template = setting_names(TEMPLATE);
    let missing: Vec<&&str> = settable.difference(&template).collect();
    assert!(
        missing.is_empty(),
        "the template offers no entry for {missing:?}"
    );
}

/// The template with every key and table header uncommented where it stands,
/// so a key's table is the one the file actually places it under.
fn template_uncommented_in_place() -> String {
    let mut out = String::new();
    for line in TEMPLATE.lines() {
        let body = line.strip_prefix("# ").unwrap_or("");
        let is_header = body.starts_with('[') && body.ends_with(']');
        let is_assignment = body.split_once(" = ").is_some_and(|(key, _)| {
            !key.is_empty() && key.chars().all(|c| c.is_ascii_lowercase() || c == '-')
        });
        out.push_str(if is_header || is_assignment {
            body
        } else {
            line
        });
        out.push('\n');
    }
    out
}

#[test]
fn every_template_key_parses_under_the_table_it_sits_in() {
    let text = template_uncommented_in_place();
    let config = Config::from_toml(&text).expect("the template parses with every key uncommented");
    // The keys really were uncommented rather than skipped.
    assert_eq!(config.limits.verification_budget, Some(2_000_000));
    assert_eq!(config.seam.len(), 1);
    assert_eq!(config.report.churn_top, 100);
    assert_eq!(config.suppression.split_pairs, CategoryAction::RankDown);
    assert_eq!(config.suppression.width_family, CategoryAction::Hide);
}

#[test]
fn template_limits_match_the_defaults_the_engines_use() {
    let limits = Config::from_toml(&template_uncommented_in_place())
        .unwrap()
        .limits;
    let fast = codehelion_core::engine::EngineConfig::default();
    assert_eq!(limits.posting_cap, Some(fast.posting_cap));
    assert_eq!(limits.pair_budget, Some(fast.pair_budget));
    let structural = codehelion_core::structural::StructuralConfig::default();
    assert_eq!(
        limits.verification_budget,
        Some(structural.verification_budget)
    );
    assert_eq!(
        limits.max_alignment_cells,
        Some(structural.verify.max_alignment_cells)
    );
    assert_eq!(
        limits.near_miss_delta,
        Some(structural.near_match.near_miss_delta)
    );
    assert_eq!(
        limits.near_miss_cap,
        Some(structural.near_match.near_miss_cap)
    );
    assert_eq!(
        limits.sibling_candidate_budget,
        Some(structural.siblings.candidate_budget)
    );
    assert_eq!(
        limits.sibling_per_group_cap,
        Some(structural.siblings.per_group_cap)
    );
    assert_eq!(
        limits.sibling_total_cap,
        Some(structural.siblings.total_cap)
    );
    let signature = &structural.signature_siblings;
    assert_eq!(
        limits.signature_sibling_candidate_budget,
        Some(signature.candidate_budget)
    );
    assert_eq!(
        limits.signature_sibling_per_group_cap,
        Some(signature.per_group_cap)
    );
    assert_eq!(
        limits.signature_sibling_total_cap,
        Some(signature.total_cap)
    );
    assert_eq!(
        limits.signature_sibling_max_units_per_signature,
        Some(signature.max_units_per_signature)
    );
    // The mode-dependent defaults are stated per mode, not as one number.
    assert!(TEMPLATE.contains("Defaults: Fast 64, Structural 256."));
    assert_eq!(structural.near_match.posting_cap, 256);
    assert!(TEMPLATE.contains("Defaults: Fast 1000000, Structural 2000000."));
    assert_eq!(structural.near_match.pair_budget, 2_000_000);
}

#[test]
fn config_show_lists_every_unset_optional_limit_and_only_those() {
    let shown = Config::default().to_display_toml().unwrap();
    for limit in limits::OPTIONAL_LIMITS {
        assert!(
            shown.contains(&format!("# limits.{}: {}", limit.key, limit.absence)),
            "{} missing from\n{shown}",
            limit.key
        );
    }
    assert!(shown.contains("# limits.verification-budget: structural default"));
    assert!(shown.contains("# limits.max-alignment-cells: verifier default"));

    let mut config = every_setting_carried();
    config.jobs = Some(2);
    config.limits.near_miss_delta = Some(0.05);
    let shown = config.to_display_toml().unwrap();
    assert!(!shown.contains("Unset optional settings"), "{shown}");
    assert!(
        shown.contains("verification-budget"),
        "set ceilings are printed"
    );
}
