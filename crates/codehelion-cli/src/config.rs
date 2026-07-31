//! Configuration model, discovery and resolution.
//!
//! Configuration comes from three layers, highest precedence first: explicit
//! command-line flags, a `codehelion.toml` file, then built-in defaults. This
//! module owns the file layer and the defaults; each command applies its own
//! flag overrides on top of the [`Config`] it receives.
//!
//! The file is discovered by walking up from the scan directory to the
//! filesystem root and taking the first `codehelion.toml`. Unknown keys are
//! rejected so a typo surfaces as an error rather than being silently ignored.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use codehelion_core::boilerplate::Boilerplate;
use codehelion_core::discovery::{DEFAULT_MARKERS, HeaderPolicy};
use serde::{Deserialize, Serialize};

/// File name discovered by the upward search.
pub const CONFIG_FILE_NAME: &str = "codehelion.toml";

/// Literal-normalization strategy for Type-2 detection.
///
/// The default is [`Full`](LiteralNormalization::Full): normalizing every
/// literal recovers renamed-literal (Type-2) clones that a value-preserving
/// pass would miss.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LiteralNormalization {
    /// Keep literal values distinct (normalize identifiers only).
    Preserve,
    /// Normalize literals by category (integer, float, string, char).
    Category,
    /// Normalize every literal to a single placeholder.
    #[default]
    Full,
}

/// Which grammar reads a bare `.h`, the one extension C and C++ share.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HeaderGrammar {
    /// Follow the rest of the tree: whichever of C and C++ more of its
    /// unambiguously-named files are written in.
    #[default]
    Detect,
    /// Always C.
    C,
    /// Always C++.
    Cpp,
}

impl From<HeaderGrammar> for HeaderPolicy {
    fn from(grammar: HeaderGrammar) -> Self {
        match grammar {
            HeaderGrammar::Detect => Self::Detect,
            HeaderGrammar::C => Self::C,
            HeaderGrammar::Cpp => Self::Cpp,
        }
    }
}

/// Languages the scan analyses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
pub struct Languages {
    /// Analyse Rust sources.
    pub rust: bool,
    /// Analyse C sources.
    pub c: bool,
    /// Analyse C++ sources.
    pub cpp: bool,
    /// Which grammar reads a bare `.h`.
    pub headers: HeaderGrammar,
}

impl Default for Languages {
    fn default() -> Self {
        Self {
            rust: true,
            c: true,
            cpp: true,
            headers: HeaderGrammar::default(),
        }
    }
}

/// What a report does with a clone group that falls into one recognised
/// category: a boilerplate shape, or a group living wholly in a test suite.
///
/// The category itself is always recorded; this only decides how the group is
/// presented.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CategoryAction {
    /// Hide from default reports, recording why. `--show-suppressed` lists it.
    Hide,
    /// Report it, but below every group that carries behaviour.
    #[default]
    RankDown,
    /// Report it like any other group.
    Report,
}

/// Per-category presentation policy for classified boilerplate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
pub struct BoilerplatePolicy {
    /// Bodies that move one value and do nothing else: getters, setters,
    /// stubs. Ranked down by default, so a deliberate review can still find
    /// them without allowing large predicate families to lead the report.
    pub trivial_body: CategoryAction,
    /// Wrappers that delegate with a single call. Hidden by default — every
    /// such group in the labelled corpora turned out to be a lookalike.
    pub forwarding: CategoryAction,
    /// Bodies that are nothing but macro invocations.
    pub macro_repetition: CategoryAction,
    /// Bodies that are one guard and an answer on each side of it. Hidden by
    /// default, on the same evidence as the wrappers.
    pub guarded_dispatch: CategoryAction,
    /// Bodies whose answer the build configuration picks. Hidden by default —
    /// what two of them share is a platform split or a feature flag, which is
    /// not duplication anyone can remove.
    pub configured_answer: CategoryAction,
}

impl Default for BoilerplatePolicy {
    fn default() -> Self {
        Self {
            trivial_body: CategoryAction::RankDown,
            // A wrapper looked like something worth consolidating until there
            // was real code to check it against: across the labelled projects
            // every group of them was a lookalike, and none was a duplication
            // anyone could act on. Hidden means set aside, not dropped — the
            // suppressed section still lists them.
            forwarding: CategoryAction::Hide,
            // A run of macro invocations can genuinely be worth consolidating,
            // so it is ranked down rather than hidden.
            macro_repetition: CategoryAction::RankDown,
            // A unit that picks between two answers behaves like a wrapper in
            // the corpora and is set aside on the same footing. Note that a
            // guard whose answer is computed cannot be told from one that
            // reads a field, so this is the category to raise to "report"
            // first when a real duplication goes missing.
            guarded_dispatch: CategoryAction::Hide,
            // Every body this reaches across the labelled projects is one
            // routine written per platform or per feature flag, in all three
            // languages. None of them is a duplicate a reader could remove,
            // and none was ever ruled a clone worth reporting.
            configured_answer: CategoryAction::Hide,
        }
    }
}

impl BoilerplatePolicy {
    /// The action configured for one category.
    #[must_use]
    pub const fn action(&self, category: Boilerplate) -> CategoryAction {
        match category {
            Boilerplate::TrivialBody => self.trivial_body,
            Boilerplate::Forwarding => self.forwarding,
            Boilerplate::MacroRepetition => self.macro_repetition,
            Boilerplate::GuardedDispatch => self.guarded_dispatch,
            Boilerplate::ConfiguredAnswer => self.configured_answer,
        }
    }
}

/// Suppression settings applied before candidate generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
pub struct Suppression {
    /// Path globs whose matches are excluded from findings.
    pub paths: Vec<String>,
    /// Globs matched against the name of the unit an occurrence sits in, for
    /// suppressing families of functions or types wherever they live.
    pub symbols: Vec<String>,
    /// Stable clone-group ids, as hex or a hex prefix, naming individual
    /// groups to suppress. An id identifies one group's content, so it stops
    /// matching once that content changes.
    pub clone_ids: Vec<String>,
    /// Markers that, when found in a file's first lines, flag it as generated
    /// and exclude it before candidate generation.
    pub generated_markers: Vec<String>,
    /// What to do with each recognised boilerplate shape.
    pub boilerplate: BoilerplatePolicy,
    /// What to do with a group every member of which is test code.
    ///
    /// A suite repeats itself deliberately, and on a well-tested project it
    /// holds most of the duplication there is, so left level with everything
    /// else it buries the code under test. Ranked down by default rather than
    /// hidden: repetition across a suite is worth reading, just not first.
    pub test_code: CategoryAction,
    /// What to do with a verified clone pair that no group could hold.
    ///
    /// Being a clone is not transitive, so a unit can be a copy of two units
    /// that are not copies of each other, and a set whose every member is a
    /// copy of every other cannot hold all three. The pair such a set leaves
    /// out is a verdict the judge reached, and there are more of them than
    /// there are groups. Ranked down by default: reported, but below the
    /// groups, which say more per finding.
    pub split_pairs: CategoryAction,
    /// What to do with a group whose members differ by one integer width and
    /// nothing else.
    ///
    /// A typed language makes an author write the same routine once per width,
    /// and what comes out is duplication nobody can remove without a way to
    /// write the family once. Hidden by default: across every labelled project
    /// the rule has been measured against it has reached lookalikes only, never
    /// a clone anybody confirmed, in two languages by different authors.
    ///
    /// Raise it to `report` on a codebase that does have such a way — a macro,
    /// a generic, a template — because there collapsing the family is exactly
    /// the change worth making.
    pub width_family: CategoryAction,
}

impl Suppression {
    /// Whether a group is reported below every group that carries behaviour.
    ///
    /// Read from the classifications a group carries rather than from where it
    /// came from in the pipeline, so that a report assembled by a scan and one
    /// rebuilt from a recorded run put the same findings in the same order.
    #[must_use]
    pub fn ranks_down(
        &self,
        boilerplate: Option<Boilerplate>,
        test_code: bool,
        width_family: bool,
        split_pair: bool,
    ) -> bool {
        boilerplate.is_some_and(|shape| self.boilerplate.action(shape) == CategoryAction::RankDown)
            || (test_code && self.test_code == CategoryAction::RankDown)
            || (width_family && self.width_family == CategoryAction::RankDown)
            || (split_pair && self.split_pairs == CategoryAction::RankDown)
    }
}

impl Default for Suppression {
    fn default() -> Self {
        Self {
            paths: Vec::new(),
            symbols: Vec::new(),
            clone_ids: Vec::new(),
            generated_markers: DEFAULT_MARKERS.iter().map(|m| (*m).to_string()).collect(),
            boilerplate: BoilerplatePolicy::default(),
            test_code: CategoryAction::RankDown,
            split_pairs: CategoryAction::RankDown,
            width_family: CategoryAction::Hide,
        }
    }
}

/// Resource ceilings applied while scanning, sized so that scanning an
/// untrusted repository stays bounded in time and memory.
///
/// Every ceiling is accounted for in the report when it fires — oversized
/// files land in the skipped count, an exhausted pairing budget states in the
/// funnel how many candidates it left unexamined — so nothing is dropped
/// silently.
///
/// The two pairing ceilings are overrides rather than values. The modes pair
/// different things — token-window fingerprints against statement fragments —
/// and their candidate counts differ by an order of magnitude on the same
/// tree, so one number set here for both would be chosen for one mode and
/// merely survived by the other. Left unset, each stays at the default its own
/// measurements picked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
pub struct Limits {
    /// Per-file size ceiling in bytes; larger files are skipped and counted.
    pub max_file_bytes: u64,
    /// Per-file lexing time ceiling in milliseconds; files that exceed it are
    /// excluded from analysis and counted as skipped. The frontends are
    /// single-pass and linear, so with the size ceiling in place this is a
    /// safety valve rather than the primary bound.
    pub parse_timeout_ms: u64,
    /// Per-unit compiler-helper response ceiling in milliseconds. This only
    /// applies to Semantic mode after a helper has described the build; a
    /// timed-out unit is recorded as unavailable and the scan continues.
    pub helper_timeout_ms: u64,
    /// Longest posting list or fragment class that still enters pairing;
    /// longer ones are dropped and counted. Unset leaves each mode at its own
    /// default.
    pub posting_cap: Option<usize>,
    /// Upper bound on candidate pairs each pairing pass examines. Unset leaves
    /// each mode at its own default.
    ///
    /// The allowance is per pass, not shared between them: the passes search
    /// different spaces, and one number spent by whichever runs first would
    /// silence the other.
    pub pair_budget: Option<usize>,
    /// Largest set of related units compared as one piece when forming
    /// groups; a larger set is cut, and the cut is reported. Comparing a set
    /// costs time quadratic in its size, so without a ceiling a codebase of
    /// thousands of interchangeable units makes a scan arbitrarily expensive.
    pub max_component: usize,
}

/// Selection of the deliberately small restricted-semantic rule registry.
///
/// The registry is enabled only in Semantic mode. A disabled rule stays
/// visible in `doctor` and in the recorded registry version, but cannot emit
/// a finding for this project.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
pub struct SemanticRules {
    /// Registered rule identifiers disabled for this project.
    pub disabled: Vec<String>,
}

impl SemanticRules {
    /// Whether a registered rule may emit findings.
    #[must_use]
    pub fn enabled(&self, rule_id: &str) -> bool {
        !self.disabled.iter().any(|disabled| disabled == rule_id)
    }

    /// Reject a misspelled rule ID instead of treating it as a rule that did
    /// nothing. A registry setting is a request to change detector behaviour,
    /// so silently accepting an unknown name would make that request
    /// impossible to audit.
    ///
    /// # Errors
    ///
    /// Returns an error when a disabled identifier is absent from the built-in
    /// registry this build ships.
    pub fn validate(&self) -> Result<()> {
        for disabled in &self.disabled {
            if !codehelion_core::semantic::registered_rules()
                .iter()
                .any(|rule| rule.id == disabled)
            {
                bail!("unknown restricted-semantic rule {disabled:?}");
            }
        }
        Ok(())
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_file_bytes: codehelion_core::discovery::DEFAULT_MAX_FILE_BYTES,
            parse_timeout_ms: 10_000,
            helper_timeout_ms: 300_000,
            posting_cap: None,
            pair_budget: None,
            max_component: codehelion_core::grouping::GroupingConfig::default().max_component,
        }
    }
}

/// How the separated priority measures are weighed against one another.
///
/// Only the composition is configurable. The measures themselves are not: what
/// a duplication costs to keep and what it costs to remove are questions about
/// the code, and a setting that changed the answers would make two projects'
/// reports incomparable. What differs between projects is how much each answer
/// should count, which is what these are.
///
/// Whole numbers, read as shares. Setting both to zero ranks on clone
/// confidence alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
pub struct Priority {
    /// Weight of what keeping the copies in step costs.
    pub maintenance_risk: u32,
    /// Weight of how cheap the duplication would be to remove.
    pub refactoring_ease: u32,
}

impl Default for Priority {
    fn default() -> Self {
        let weights = codehelion_core::priority::Weights::default();
        Self {
            maintenance_risk: weights.maintenance_risk,
            refactoring_ease: weights.refactoring_ease,
        }
    }
}

impl Priority {
    /// These settings as the ranking reads them.
    #[must_use]
    pub const fn weights(&self) -> codehelion_core::priority::Weights {
        codehelion_core::priority::Weights {
            maintenance_risk: self.maintenance_risk,
            refactoring_ease: self.refactoring_ease,
        }
    }
}

/// Effective analysis configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
pub struct Config {
    /// Path globs to include; empty means every supported source file.
    pub include: Vec<String>,
    /// Path globs to exclude from the include set.
    pub exclude: Vec<String>,
    /// Smallest clone length, in tokens, that is reported.
    pub min_clone_tokens: u32,
    /// Literal-normalization strategy.
    pub literal_normalization: LiteralNormalization,
    /// Languages to analyse.
    pub languages: Languages,
    /// Suppression settings.
    pub suppression: Suppression,
    /// How the priority measures are weighed against one another.
    pub priority: Priority,
    /// Resource ceilings.
    pub limits: Limits,
    /// Restricted-semantic rule selection.
    pub semantic: SemanticRules,
    /// Audit-database location, relative to the repository root unless absolute.
    pub database: PathBuf,
    /// Worker-thread count; `None` selects a count automatically.
    pub jobs: Option<usize>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            include: Vec::new(),
            exclude: Vec::new(),
            // 20 tokens is the smallest clone length that stays clear of the
            // short spurious matches (partial signatures, boilerplate) seen on
            // the evaluation corpus.
            min_clone_tokens: 20,
            literal_normalization: LiteralNormalization::default(),
            languages: Languages::default(),
            suppression: Suppression::default(),
            priority: Priority::default(),
            limits: Limits::default(),
            semantic: SemanticRules::default(),
            database: PathBuf::from(".codehelion/audit.db"),
            jobs: None,
        }
    }
}

impl Config {
    /// Parse a [`Config`] from its TOML representation.
    ///
    /// # Errors
    ///
    /// Returns an error if the text is not valid TOML or contains an unknown
    /// key.
    pub fn from_toml(text: &str) -> Result<Self> {
        let config: Self = toml::from_str(text).context("parsing configuration")?;
        config.semantic.validate()?;
        Ok(config)
    }

    /// Serialize this configuration to TOML.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails (for example, a non-UTF-8
    /// database path).
    pub fn to_toml(&self) -> Result<String> {
        toml::to_string_pretty(self).context("serializing configuration")
    }
}

/// Where the resolved configuration came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigSource {
    /// Loaded from this file.
    File(PathBuf),
    /// No file found; built-in defaults were used.
    Defaults,
}

/// A resolved configuration together with its provenance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedConfig {
    /// The effective configuration.
    pub config: Config,
    /// Where it came from.
    pub source: ConfigSource,
}

/// Resolve the configuration for a scan rooted at `start_dir`.
///
/// When `explicit` is given, that file is loaded and a missing or invalid file
/// is an error. Otherwise the first `codehelion.toml` found by walking up from
/// `start_dir` is used, falling back to defaults when none exists.
///
/// # Errors
///
/// Returns an error if a named or discovered file cannot be read or parsed.
pub fn load(explicit: Option<&Path>, start_dir: &Path) -> Result<ResolvedConfig> {
    if let Some(path) = explicit {
        let config = read_file(path)?;
        return Ok(ResolvedConfig {
            config,
            source: ConfigSource::File(path.to_path_buf()),
        });
    }
    match find_upward(start_dir) {
        Some(path) => {
            let config = read_file(&path)?;
            Ok(ResolvedConfig {
                config,
                source: ConfigSource::File(path),
            })
        }
        None => Ok(ResolvedConfig {
            config: Config::default(),
            source: ConfigSource::Defaults,
        }),
    }
}

fn read_file(path: &Path) -> Result<Config> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading configuration file {}", path.display()))?;
    Config::from_toml(&text).with_context(|| format!("in configuration file {}", path.display()))
}

/// Walk up from `start_dir` to the filesystem root, returning the first
/// `codehelion.toml` found.
fn find_upward(start_dir: &Path) -> Option<PathBuf> {
    let mut dir = Some(start_dir);
    while let Some(current) = dir {
        let candidate = current.join(CONFIG_FILE_NAME);
        if candidate.is_file() {
            return Some(candidate);
        }
        dir = current.parent();
    }
    None
}

/// A commented template written by `config init`, holding every key at its
/// default so it can be uncommented and edited.
pub const TEMPLATE: &str = "\
# codehelion configuration. Every key below shows its built-in default;
# uncomment and edit the ones you want to change.

# Path globs to include; empty means every supported source file.
# include = []
# Path globs to exclude from the include set.
# exclude = []

# Smallest clone length, in tokens, that is reported.
# min-clone-tokens = 20

# Literal-normalization strategy: \"preserve\", \"category\" or \"full\".
# literal-normalization = \"full\"

# Audit-database location, relative to the repository root unless absolute.
# database = \".codehelion/audit.db\"

# Worker-thread count; omit for automatic.
# jobs = 4

# [languages]
# rust = true
# c = true
# cpp = true
# Which grammar reads a bare \".h\", the one extension C and C++ share:
# \"detect\", \"c\" or \"cpp\". Detection counts the files whose extension is not
# in doubt and follows the majority, because a C++ project spells its headers
# \".h\" out of convention. The choice is part of the run's build variant, so
# changing it puts the results in a separate space from the previous ones.
# headers = \"detect\"

# [suppression]
# Globs matched against a file's path, relative to the scan root. A vendored
# or imported tree is the usual entry — \"third_party/**\", \"vendor/**\" —
# because nothing else here reads provenance from a path, and duplication you
# did not write is duplication you cannot act on.
# paths = []
# Globs matched against the name of the unit an occurrence sits in.
# symbols = []
# Stable clone-group ids (hex, or a prefix of at least 8 characters). An id
# describes one group's content, so it stops matching once that content
# changes.
# clone-ids = []
# Markers that flag a file as machine output when they appear in its first
# lines, matched without regard to case. Setting this replaces the defaults, so
# a project adding its own generator's banner lists these alongside it.
# generated-markers = [\"@generated\", \"do not edit\", \"automatically generated\", \"auto-generated\", \"autogenerated\"]
# What to do with a clone group every member of which is test code, recognised
# from the marker in the source — the test attribute in Rust, the framework's
# case macro in C++: \"hide\", \"rank-down\" or \"report\". A Rust module the
# crate declares as test-only counts wherever it is written, including the
# files it is split across. A group spanning both a suite and the code it
# exercises is not test code.
# test-code = \"rank-down\"

# What to do with a clone group whose every member matches a boilerplate
# shape: \"hide\", \"rank-down\" or \"report\". The classification is recorded
# either way.
# [suppression.boilerplate]
# trivial-body = \"rank-down\"
# forwarding = \"hide\"
# macro-repetition = \"rank-down\"
# guarded-dispatch = \"hide\"
# configured-answer = \"hide\"

# How the separated priority measures are weighed against one another when a
# report is put in order. Whole numbers, read as shares. Only the composition
# is settable: what a duplication costs to keep and what it costs to remove
# are questions about the code, and a setting that changed the answers would
# make two projects' reports incomparable. Every finding carries all three
# measures whatever these are set to; setting both to zero orders the report
# on clone confidence alone.
# [priority]
# maintenance-risk = 2
# refactoring-ease = 1

# Restricted Semantic rules are all enabled by default. List a stable rule ID
# here to disable it for this project without broadening the detector.
# [semantic]
# disabled = [\"sequence-pipeline-v1\"]

# Resource ceilings; every ceiling that fires is accounted for in the report.
# There is deliberately no trust setting here. `codehelion scan --untrusted`
# lowers every ceiling below at once, and it is a command-line flag because this
# file is discovered inside the tree being scanned — a repository must not get to
# say how much it should be trusted.
# [limits]
# Per-file size ceiling in bytes; larger files are skipped and counted.
# max-file-bytes = 2097152
# Per-file lexing time ceiling in milliseconds.
# parse-timeout-ms = 10000
# Per-unit compiler-helper response ceiling in milliseconds. A timed-out
# Semantic unit is recorded as unavailable while the rest of the scan continues.
# helper-timeout-ms = 300000
# The two pairing ceilings below override both modes at once. Left out, each
# mode keeps the default its own measurements picked — the modes pair different
# things, and their candidate counts differ by an order of magnitude on the same
# tree, so a number set here suits one of them and is merely survived by the
# other. Set them to bound a scan that is taking longer than you will wait; the
# report then states how many candidates the ceiling left unexamined.
# Longest posting list or fragment class that still enters pairing.
# posting-cap = 64
# Upper bound on candidate pairs each pairing pass examines.
# pair-budget = 1000000
# Largest set of related units compared as one piece when forming groups.
# max-component = 1024
";

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_the_evaluated_values() {
        let config = Config::default();
        assert_eq!(config.min_clone_tokens, 20);
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
        let config =
            Config::from_toml("[suppression.boilerplate]\nforwarding = \"report\"").unwrap();
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
    fn upward_search_finds_a_parent_config() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(CONFIG_FILE_NAME), "min-clone-tokens = 15").unwrap();
        let nested = dir.path().join("a/b");
        std::fs::create_dir_all(&nested).unwrap();
        let resolved = load(None, &nested).unwrap();
        assert_eq!(resolved.config.min_clone_tokens, 15);
        assert!(matches!(resolved.source, ConfigSource::File(_)));
    }

    #[test]
    fn no_file_resolves_to_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let resolved = load(None, dir.path()).unwrap();
        assert_eq!(resolved.source, ConfigSource::Defaults);
        assert_eq!(resolved.config, Config::default());
    }
}
