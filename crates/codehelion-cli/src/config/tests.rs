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
fn semantic_rules_can_be_disabled_by_their_stable_identifier() {
    let config = Config::from_toml(
        "[semantic]\ndisabled = [\"sequence-pipeline-v1\", \
         \"cross-language-sequence-pipeline-v1\"]\n",
    )
    .expect("semantic rule selection parses");
    assert!(!config.semantic.enabled("sequence-pipeline-v1"));
    assert!(
        !config
            .semantic
            .enabled("cross-language-sequence-pipeline-v1")
    );
    assert!(config.semantic.enabled("unregistered-rule"));
}

#[test]
fn an_unknown_semantic_rule_is_rejected() {
    let error = Config::from_toml("[semantic]\ndisabled = [\"misspelled-rule\"]\n")
        .expect_err("unknown semantic rule must not silently do nothing");
    assert!(format!("{error:#}").contains("unknown restricted-semantic rule"));
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
        ("limits.max-component", "[limits]\nmax-component = 1"),
    ] {
        let error = Config::from_toml(text).expect_err("degenerate value must be rejected");
        assert!(format!("{error:#}").contains(key));
    }
}

#[test]
fn invalid_numeric_value_names_its_configuration_file() {
    let directory = tempfile::tempdir().expect("temporary configuration directory");
    let path = directory.path().join(CONFIG_FILE_NAME);
    std::fs::write(&path, "[limits]\npair-budget = 0").expect("write invalid configuration");

    let error = load(Some(&path), directory.path())
        .expect_err("an explicit invalid configuration must fail");
    let rendered = format!("{error:#}");
    assert!(rendered.contains("limits.pair-budget"));
    assert!(rendered.contains(&path.display().to_string()));
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
fn limit_defaults_match_the_engine_and_discovery_defaults() {
    let limits = Limits::default();
    assert_eq!(
        limits.max_file_bytes,
        codehelion_core::discovery::DEFAULT_MAX_FILE_BYTES
    );
    // The pairing ceilings are overrides, not values: unset leaves each
    // mode at its own default rather than imposing one mode's on both.
    assert_eq!(limits.posting_cap, None);
    assert_eq!(limits.pair_budget, None);
    let grouping = codehelion_core::grouping::GroupingConfig::default();
    assert_eq!(limits.max_component, grouping.max_component);
    assert!(
        limits.max_component > grouping.sampling_threshold,
        "a set between the two ceilings is still compared whole, with a sampled medoid"
    );
    assert!(limits.parse_timeout_ms > 0);
    assert!(limits.helper_timeout_ms > 0);
}

#[test]
fn partial_limits_section_keeps_other_ceilings_at_their_defaults() {
    let config = Config::from_toml("[limits]\nmax-file-bytes = 1024").unwrap();
    assert_eq!(config.limits.max_file_bytes, 1024);
    assert_eq!(config.limits.posting_cap, Limits::default().posting_cap);
    assert_eq!(config.limits.pair_budget, Limits::default().pair_budget);
    assert_eq!(config.limits.max_component, Limits::default().max_component);
    assert_eq!(
        config.limits.helper_timeout_ms,
        Limits::default().helper_timeout_ms
    );
}

#[test]
fn boilerplate_policy_defaults_set_aside_the_shapes_that_say_nothing() {
    let policy = Suppression::default().boilerplate;
    assert_eq!(
        policy.action(Boilerplate::TrivialBody),
        CategoryAction::RankDown
    );
    // A group of wrappers has never been worth acting on in the labelled
    // projects, so it is set aside rather than merely ranked down.
    assert_eq!(policy.action(Boilerplate::Forwarding), CategoryAction::Hide);
    assert_eq!(
        policy.action(Boilerplate::GuardedDispatch),
        CategoryAction::Hide
    );
    // A run of macro invocations can still be worth consolidating.
    assert_eq!(
        policy.action(Boilerplate::MacroRepetition),
        CategoryAction::RankDown
    );
}

#[test]
fn a_boilerplate_category_can_be_overridden_on_its_own() {
    let config = Config::from_toml("[suppression.boilerplate]\nforwarding = \"report\"").unwrap();
    let policy = &config.suppression.boilerplate;
    assert_eq!(
        policy.action(Boilerplate::Forwarding),
        CategoryAction::Report
    );
    // The categories not named keep their defaults, as does the rest of
    // the suppression section.
    assert_eq!(
        policy.action(Boilerplate::MacroRepetition),
        CategoryAction::RankDown
    );
    assert_eq!(
        policy.action(Boilerplate::TrivialBody),
        CategoryAction::RankDown
    );
    assert_eq!(
        config.suppression.generated_markers,
        Suppression::default().generated_markers
    );
}

#[test]
fn test_code_is_ranked_down_by_default_and_can_be_set() {
    // Repetition across a suite is worth reading, just not first, so the
    // default lowers it rather than removing it.
    assert_eq!(Suppression::default().test_code, CategoryAction::RankDown);

    let config = Config::from_toml("[suppression]\ntest-code = \"hide\"").unwrap();
    assert_eq!(config.suppression.test_code, CategoryAction::Hide);
    // Setting one policy leaves the other alone.
    assert_eq!(config.suppression.boilerplate, BoilerplatePolicy::default());
}

#[test]
fn test_paths_default_to_the_documented_conventions_and_can_be_disabled() {
    assert_eq!(
        Suppression::default().test_paths,
        DEFAULT_TEST_PATHS
            .iter()
            .map(|path| (*path).to_string())
            .collect::<Vec<_>>()
    );

    let config = Config::from_toml("[suppression]\ntest-paths = []").unwrap();
    assert!(config.suppression.test_paths.is_empty());
    assert_eq!(config.suppression.test_code, CategoryAction::RankDown);
}

#[test]
fn a_width_family_is_hidden_by_default_and_can_be_reported() {
    // Nobody can collapse a family the language made them write, so the
    // default withholds it. A project with a macro or a generic to hand
    // can ask for it back, which is the case the setting exists for.
    assert_eq!(Suppression::default().width_family, CategoryAction::Hide);

    let config = Config::from_toml("[suppression]\nwidth-family = \"report\"").unwrap();
    assert_eq!(config.suppression.width_family, CategoryAction::Report);
    assert_eq!(config.suppression.test_code, CategoryAction::RankDown);
}

#[test]
fn an_unknown_boilerplate_action_is_rejected() {
    let err = Config::from_toml("[suppression.boilerplate]\nforwarding = \"delete\"")
        .expect_err("only the documented actions are accepted");
    assert!(format!("{err:#}").contains("unknown variant"));
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

#[test]
fn explicit_missing_file_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("nope.toml");
    assert!(load(Some(&missing), dir.path()).is_err());
}

#[test]
fn explicitly_named_and_discovered_configurations_keep_distinct_provenance() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join(CONFIG_FILE_NAME);
    std::fs::write(&file, "database = \"audit.db\"").unwrap();

    let explicit = load(Some(&file), dir.path()).unwrap();
    assert_eq!(explicit.source, ConfigSource::Explicit(file.clone()));

    let discovered = load(None, dir.path()).unwrap();
    assert_eq!(discovered.source, ConfigSource::Discovered(file));
}

#[test]
fn discovery_does_not_inherit_a_parent_configuration() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(CONFIG_FILE_NAME), "min-clone-tokens = 15").unwrap();
    let nested = dir.path().join("a/b");
    std::fs::create_dir_all(&nested).unwrap();
    let resolved = load(None, &nested).unwrap();
    assert_eq!(resolved.config, Config::default());
    assert_eq!(resolved.source, ConfigSource::Defaults);
}

#[test]
fn no_file_resolves_to_defaults() {
    let dir = tempfile::tempdir().unwrap();
    let resolved = load(None, dir.path()).unwrap();
    assert_eq!(resolved.source, ConfigSource::Defaults);
    assert_eq!(resolved.config, Config::default());
}
