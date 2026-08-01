//! Configuration model, discovery and resolution.
//!
//! Configuration comes from three layers, highest precedence first: explicit
//! command-line flags, a `codehelion.toml` file, then built-in defaults. This
//! module owns the file layer and the defaults; each command applies its own
//! flag overrides on top of the [`Config`] it receives.
//!
//! The file is discovered only at the scan directory as `codehelion.toml`.
//! A scan must not silently inherit settings from an enclosing checkout.
//! Unknown keys are rejected so a typo surfaces as an error rather than being
//! silently ignored.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use codehelion_core::boilerplate::Boilerplate;
use codehelion_core::discovery::{DEFAULT_MARKERS, HeaderPolicy};
use codehelion_core::test_code::DEFAULT_TEST_PATHS;
use serde::{Deserialize, Serialize};

/// File name discovered at a scan root.
pub const CONFIG_FILE_NAME: &str = "codehelion.toml";

/// Directories a project conventionally vendors upstream code into, as globs.
///
/// Written as globs rather than names so that what is matched is what the
/// configuration says, in the syntax `[suppression] paths` already uses, and
/// so a project can extend the list in the same form. The leading `**/` lets
/// a vendored tree sit anywhere; matching whole path components is what keeps
/// `external/` from also claiming `external_api/`.
///
/// `.gitignore` is honoured during discovery and covers the trees nobody
/// commits, which is why fetched-dependency directories appear here: a
/// vendored tree is committed, so nothing else excludes it.
pub const DEFAULT_VENDORED_PATHS: &[&str] = &[
    "**/third_party/**",
    "**/thirdparty/**",
    "**/vendor/**",
    "**/vendored/**",
    "**/external/**",
    "**/extern/**",
    "**/deps/**",
    "**/subprojects/**",
    "**/node_modules/**",
    "**/Godeps/**",
    "**/.venv/**",
];

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
/// Structural and Semantic modes record the category itself; this only decides
/// how the group is presented. Fast mode reports explicitly when it cannot
/// apply these classifications.
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
    /// Path globs naming trees the project vendors rather than writes.
    ///
    /// Separate from [`paths`](Self::paths) because it carries defaults and
    /// that one does not: a reader has to be able to tell what they asked for
    /// apart from what they were given. Upstream code duplicating itself is
    /// nobody's maintenance burden here — a copy of it cannot be unified with
    /// anything, and it drowns the tree the project does write. A group
    /// spanning a vendored tree and the project's own code stays visible, as
    /// with every other rule: a group is hidden only when every member is.
    ///
    /// Set to `[]` to scan vendored trees like anything else.
    pub vendored_paths: Vec<String>,
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
    /// Path globs whose matches are test code in addition to source markers.
    ///
    /// These defaults classify unmarked test helpers so the existing
    /// [`test_code`](Self::test_code) policy can rank them below production
    /// findings. Set this to `[]` to disable path evidence only; source
    /// markers still classify tests.
    pub test_paths: Vec<String>,
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
            vendored_paths: DEFAULT_VENDORED_PATHS
                .iter()
                .map(|glob| (*glob).to_string())
                .collect(),
            symbols: Vec::new(),
            clone_ids: Vec::new(),
            generated_markers: DEFAULT_MARKERS.iter().map(|m| (*m).to_string()).collect(),
            test_paths: DEFAULT_TEST_PATHS
                .iter()
                .map(|glob| (*glob).to_string())
                .collect(),
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
    /// Per-file deterministic parse-work budget, expressed in compatibility
    /// milliseconds. Each millisecond admits 256 input bytes; files above the
    /// resulting byte budget are excluded and counted as skipped. This keeps
    /// host load and worker count from changing a scan's result.
    pub parse_timeout_ms: u64,
    /// Compiler-helper response ceiling in milliseconds, including build
    /// description. A timed-out analysis unit is recorded as unavailable and
    /// the scan continues.
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

impl Limits {
    /// Reject ceilings that would turn an enabled scan mode into an empty run.
    ///
    /// # Errors
    ///
    /// Returns an error naming the invalid configuration key.
    fn validate(&self) -> Result<()> {
        if self.max_file_bytes == 0 {
            bail!("limits.max-file-bytes must be at least 1");
        }
        if self.parse_timeout_ms == 0 {
            bail!("limits.parse-timeout-ms must be at least 1");
        }
        if self.helper_timeout_ms == 0 {
            bail!("limits.helper-timeout-ms must be at least 1");
        }
        if self.posting_cap.is_some_and(|cap| cap < 2) {
            bail!("limits.posting-cap must be at least 2 when set");
        }
        if self.pair_budget == Some(0) {
            bail!("limits.pair-budget must be at least 1 when set");
        }
        if self.max_component < 2 {
            bail!("limits.max-component must be at least 2");
        }
        Ok(())
    }

    /// Lower every configurable resource ceiling to the untrusted profile.
    ///
    /// The optional pairing settings mean "use the mode-specific default" in
    /// normal runs. An untrusted run cannot leave that choice open: it turns
    /// both into concrete profile ceilings so Fast, Structural, and Semantic
    /// all receive the same bound.
    pub(crate) fn clamp_to_untrusted(&mut self, profile: &codehelion_core::execution::Limits) {
        self.max_file_bytes = self.max_file_bytes.min(profile.max_file_bytes);
        self.parse_timeout_ms = self
            .parse_timeout_ms
            .min(duration_millis(profile.parse_timeout));
        self.helper_timeout_ms = self
            .helper_timeout_ms
            .min(duration_millis(profile.helper_timeout));
        self.posting_cap = Some(
            self.posting_cap
                .map_or(profile.posting_cap, |cap| cap.min(profile.posting_cap)),
        );
        self.pair_budget = Some(self.pair_budget.map_or(profile.max_candidates, |budget| {
            budget.min(profile.max_candidates)
        }));
        self.max_component = self.max_component.min(profile.max_component);
    }
}

/// Convert a duration to the millisecond configuration representation without
/// wrapping a pathological value into a smaller, unsafe ceiling.
fn duration_millis(duration: std::time::Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
pub struct Config {
    /// Path globs to include; empty means every supported source file.
    pub include: Vec<String>,
    /// Path globs to exclude from the include set.
    pub exclude: Vec<String>,
    /// Smallest clone length, in tokens, that is reported.
    pub min_clone_tokens: u32,
    /// Lowest normalized content-entropy ratio before a group is marked as
    /// degenerate repetition.
    pub entropy_ratio_floor: f64,
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
    /// Frontend read-and-lex worker count; `None` selects it automatically.
    /// Clone grouping and report rendering remain serial.
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
            // Normalized by the largest entropy a sequence of the group's
            // length can have, so short clones are not suppressed merely for
            // being short.
            entropy_ratio_floor: 0.60,
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
        config.validate()?;
        Ok(config)
    }

    /// Validate values whose meaning depends on more than TOML's type system.
    ///
    /// # Errors
    ///
    /// Returns an error when a value would make one of the scan modes produce
    /// a meaningless result.
    pub fn validate(&self) -> Result<()> {
        if self.min_clone_tokens == 0 {
            bail!("min-clone-tokens must be at least 1");
        }
        if self.jobs == Some(0) {
            bail!("jobs must be at least 1 when set");
        }
        self.limits.validate()?;
        self.semantic.validate()?;
        if !(0.0..=1.0).contains(&self.entropy_ratio_floor) {
            bail!("entropy-ratio-floor must be in 0..=1");
        }
        Ok(())
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

    /// Serialize this configuration for `config show`, including unset
    /// optional settings and the behaviour each absence selects.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails (for example, a non-UTF-8
    /// database path).
    pub fn to_display_toml(&self) -> Result<String> {
        let mut text = self.to_toml()?;
        if self.jobs.is_none()
            || self.limits.posting_cap.is_none()
            || self.limits.pair_budget.is_none()
        {
            text.push_str("\n# Unset optional settings\n");
            if self.jobs.is_none() {
                text.push_str("# jobs: automatic worker count\n");
            }
            if self.limits.posting_cap.is_none() {
                text.push_str("# limits.posting-cap: mode-specific default\n");
            }
            if self.limits.pair_budget.is_none() {
                text.push_str("# limits.pair-budget: mode-specific default\n");
            }
        }
        Ok(text)
    }
}

/// Where the resolved configuration came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigSource {
    /// Loaded from a file the user named with `--config`.
    ///
    /// Naming a configuration is an explicit authority decision. In
    /// particular, path-like settings in it are not treated as values supplied
    /// by the repository being scanned.
    Explicit(PathBuf),
    /// Found at the scanned root.
    ///
    /// A discovered file can belong to the tree being inspected, so consumers
    /// must treat path-like settings in it as untrusted unless they first
    /// confine them to that tree.
    Discovered(PathBuf),
    /// No file found; built-in defaults were used.
    Defaults,
}

/// A resolved configuration together with its provenance.
#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedConfig {
    /// The effective configuration.
    pub config: Config,
    /// Where it came from.
    pub source: ConfigSource,
}

/// Resolve the configuration for a scan rooted at `start_dir`.
///
/// When `explicit` is given, that file is loaded and a missing or invalid file
/// is an error. Otherwise only `start_dir/codehelion.toml` is used, falling
/// back to defaults when it does not exist.
///
/// # Errors
///
/// Returns an error if a named or discovered file cannot be read or parsed.
pub fn load(explicit: Option<&Path>, start_dir: &Path) -> Result<ResolvedConfig> {
    if let Some(path) = explicit {
        let config = read_file(path)?;
        return Ok(ResolvedConfig {
            config,
            source: ConfigSource::Explicit(path.to_path_buf()),
        });
    }
    match find_at_root(start_dir) {
        Some(path) => {
            let config = read_file(&path)?;
            Ok(ResolvedConfig {
                config,
                source: ConfigSource::Discovered(path),
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

/// Return the configuration file immediately inside `start_dir`, if present.
fn find_at_root(start_dir: &Path) -> Option<PathBuf> {
    let candidate = start_dir.join(CONFIG_FILE_NAME);
    candidate.is_file().then_some(candidate)
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

# Groups below this normalized content-entropy ratio are marked as degenerate
# repetition. The value is relative to the largest entropy a group of the same
# token length can carry, so it does not turn clone length into a noise filter.
# entropy-ratio-floor = 0.60

# Literal-normalization strategy: \"preserve\", \"category\" or \"full\".
# literal-normalization = \"full\"

# Audit-database location, relative to the repository root unless absolute.
# database = \".codehelion/audit.db\"

# Frontend read-and-lex worker count; clone grouping and report rendering remain
# serial. Omit for automatic. The value below is an explicit example, not the built-in default.
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
# Globs matched against a file's path, relative to the scan root, that hide
# findings. This is where a tree the project does not maintain goes when the
# vendored defaults below do not already name it.
# paths = []
# Globs naming the trees the project vendors rather than writes. Setting this
# replaces the defaults shown; set it to [] to read vendored code like any
# other. Duplication spanning a vendored tree and the project's own code stays
# visible either way, as with every rule here: a group is hidden only when
# every occurrence in it is. `--include-vendored` undoes this for one run.
# vendored-paths = [\"**/third_party/**\", \"**/thirdparty/**\", \"**/vendor/**\", \"**/vendored/**\", \"**/external/**\", \"**/extern/**\", \"**/deps/**\", \"**/subprojects/**\", \"**/node_modules/**\", \"**/Godeps/**\", \"**/.venv/**\"]
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
# Paths whose matching files are test code in addition to source markers. This
# replaces the defaults; use [] to turn off path evidence while retaining the
# source marker — a Rust attribute or C/C++ framework case macro. The defaults
# cover tests/, test/, __tests__/, and *_test.*, *_tests.*, test_*.*, and
# *_spec.* source files.
# test-paths = [\"**/tests/**\", \"**/test/**\", \"**/__tests__/**\", \"**/*_test.*\", \"**/*_tests.*\", \"**/test_*.*\", \"**/*_spec.*\"]
# What to do with a clone group every member of which is test code: \"hide\",
# \"rank-down\" or \"report\". A Rust module the crate declares as test-only
# counts wherever it is written, including files it is split across. A group
# spanning both a suite and the code it exercises is not test code.
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

# What to do with a verified clone pair that no clone group can hold: \"hide\",
# \"rank-down\" or \"report\". Clone similarity is not transitive, so this is a
# real finding that is kept separate rather than forcing unrelated units into a
# group. It is reported below complete groups by default.
# split-pairs = \"rank-down\"

# What to do with a family whose members differ only by integer width: \"hide\",
# \"rank-down\" or \"report\". These are hidden by default because a typed
# language often requires one routine per width. Set this to \"report\" where a
# macro, generic or template can express the family once.
# width-family = \"hide\"

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
# Per-file deterministic parse-work budget, in compatibility milliseconds
# (256 input bytes per millisecond). It is not a wall-clock deadline.
# parse-timeout-ms = 10000
# Compiler-helper response ceiling in milliseconds, including build description.
# A timed-out Semantic unit is recorded as unavailable while the scan continues.
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
mod tests;
