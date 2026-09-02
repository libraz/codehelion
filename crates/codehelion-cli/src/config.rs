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

use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

mod limits;
mod load;
mod paths;
mod seam;
mod settings;

pub use limits::Limits;
pub use load::{CONFIG_FILE_NAME, ConfigSource, ResolvedConfig, load};
pub use paths::{disregarded_helpers_note, helper_paths};
pub use seam::{SeamLedgerEntry, SeamTracking};
pub use settings::{
    BoilerplatePolicy, CategoryAction, DEFAULT_VENDORED_PATHS, HeaderGrammar, Helpers, Languages,
    LiteralNormalization, Priority, ReportSettings, SemanticRules, Suppression,
};

pub(crate) use paths::configured_paths;

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
    /// Explicit compiler-helper locations.
    pub helpers: Helpers,
    /// Audit-database location, relative to the repository root unless absolute.
    pub database: PathBuf,
    /// The seam ledger: which sets of paths this project says are one thing
    /// implemented in more than one place.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub seam: Vec<SeamLedgerEntry>,
    /// Thresholds the seam analysis is computed under.
    pub seam_tracking: SeamTracking,
    /// What a report states about the run before it.
    pub report: ReportSettings,
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
            helpers: Helpers::default(),
            database: PathBuf::from(".codehelion/audit.db"),
            seam: Vec::new(),
            seam_tracking: SeamTracking::default(),
            report: ReportSettings::default(),
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
        if self.report.churn_top == 0 {
            bail!("report.churn-top must be at least 1");
        }
        if self.jobs == Some(0) {
            bail!("jobs must be at least 1 when set");
        }
        self.limits.validate()?;
        self.semantic.validate()?;
        if !(0.0..=1.0).contains(&self.entropy_ratio_floor) {
            bail!("entropy-ratio-floor must be in 0..=1");
        }
        self.seam_tracking.settings().validate()?;
        // Compiling the ledger is what checks it: a malformed glob or a seam
        // written with one member is a mistake worth naming here rather than
        // at the moment a guard silently judges nothing.
        self.ledger()?;
        Ok(())
    }

    /// The seam ledger, compiled.
    ///
    /// # Errors
    ///
    /// Returns an error naming the seam whose entry is malformed.
    pub fn ledger(&self) -> Result<codehelion_seam::Ledger> {
        let entries = self
            .seam
            .iter()
            .map(|entry| codehelion_seam::SeamEntry {
                id: entry.id.clone(),
                members: entry.members.clone(),
                note: entry.note.clone(),
            })
            .collect();
        Ok(codehelion_seam::Ledger::new(entries)?)
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
            || self.limits.near_miss_delta.is_none()
            || self.limits.near_miss_cap.is_none()
            || self.limits.sibling_candidate_budget.is_none()
            || self.limits.sibling_per_group_cap.is_none()
            || self.limits.sibling_total_cap.is_none()
            || self.limits.signature_sibling_candidate_budget.is_none()
            || self.limits.signature_sibling_per_group_cap.is_none()
            || self.limits.signature_sibling_total_cap.is_none()
            || self
                .limits
                .signature_sibling_max_units_per_signature
                .is_none()
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
            if self.limits.near_miss_delta.is_none() {
                text.push_str("# limits.near-miss-delta: structural default\n");
            }
            if self.limits.near_miss_cap.is_none() {
                text.push_str("# limits.near-miss-cap: structural default\n");
            }
            if self.limits.sibling_candidate_budget.is_none() {
                text.push_str("# limits.sibling-candidate-budget: structural default\n");
            }
            if self.limits.sibling_per_group_cap.is_none() {
                text.push_str("# limits.sibling-per-group-cap: structural default\n");
            }
            if self.limits.sibling_total_cap.is_none() {
                text.push_str("# limits.sibling-total-cap: structural default\n");
            }
            if self.limits.signature_sibling_candidate_budget.is_none() {
                text.push_str(
                    "# limits.signature-sibling-candidate-budget: default used only with --siblings-by-signature\n",
                );
            }
            if self.limits.signature_sibling_per_group_cap.is_none() {
                text.push_str(
                    "# limits.signature-sibling-per-group-cap: default used only with --siblings-by-signature\n",
                );
            }
            if self.limits.signature_sibling_total_cap.is_none() {
                text.push_str(
                    "# limits.signature-sibling-total-cap: default used only with --siblings-by-signature\n",
                );
            }
            if self
                .limits
                .signature_sibling_max_units_per_signature
                .is_none()
            {
                text.push_str(
                    "# limits.signature-sibling-max-units-per-signature: default used only with --siblings-by-signature\n",
                );
            }
        }
        Ok(text)
    }
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
# composed-answer = \"hide\"
# built-answer = \"hide\"

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

# Explicit compiler-helper locations, useful for hermetic CI or a package
# manager installation outside PATH. Command-line --helper overrides these.
# These are read only from a configuration named with `--config`: this file is
# discovered inside the tree being scanned, and a repository must not get to
# choose which program a scan of it starts. In a file found at the scan root the
# section is ignored, with a note saying so; pass `--helper rust=<path>` or name
# this file with `--config` to pin a helper.
# [helpers]
# rust = \"/opt/codehelion/codehelion-backend-rust\"
# clang = \"/opt/codehelion/codehelion-backend-clang\"

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
# Width of Structural's diagnostic near-miss band below its primary gate.
# near-miss-delta = 0.05
# Maximum diagnostic near misses retained in one Structural report.
# near-miss-cap = 1000
# Maximum post-grouping Structural sibling comparisons.
# sibling-candidate-budget = 50000
# Maximum incomplete local mirrors retained for one primary group.
# sibling-per-group-cap = 8
# Maximum incomplete local mirrors retained in one Structural report.
# sibling-total-cap = 1000
# The signature-based limits below are used only with --siblings-by-signature.
# Maximum signature-based sibling comparisons.
# signature-sibling-candidate-budget = 50000
# Maximum signature-based incomplete local mirrors retained for one primary group.
# signature-sibling-per-group-cap = 8
# Maximum signature-based incomplete local mirrors retained in one Structural report.
# signature-sibling-total-cap = 1000
# Largest number of units that may share one signature before that signature
# stops being sibling evidence. A rarity threshold rather than a resource
# ceiling: a signature shared by much of a tree proposes work without proposing
# duplication. The caps above bound what raising it costs.
# signature-sibling-max-units-per-signature = 8
# Maximum Structural candidate pairs that enter precise verification.
# verification-budget = 1000000
# Maximum dynamic-programming cells used by one Structural alignment.
# max-alignment-cells = 4000000
# Largest set of related units compared as one piece when forming groups.
# max-component = 1024

# The seam ledger: sets of paths this project says are one thing implemented in
# more than one place, and that have to be changed together. `codehelion guard`
# judges a change against these and nothing else, because a subject recomputed
# from history every day would make the same change pass today and fail
# tomorrow. `codehelion seam --suggest` proposes candidates from co-change; it
# never writes here, and promoting one is a decision a person makes.
# Members are path globs in the syntax [suppression] paths uses. A seam needs at
# least two of them.
# [[seam]]
# id = \"frontend-c-cpp\"
# members = [\"crates/frontend-c/**\", \"crates/frontend-cpp/**\"]
# note = \"same semantics implemented twice across the two frontends\"

# Thresholds the seam analysis is computed under. Spelled \"seam-tracking\"
# rather than \"seam\" because the ledger above already claims that name.
# [seam-tracking]
# How many commits after an asymmetric change a fix still counts as a breach of
# it. Counted in commits rather than in time, so the answer does not depend on
# when somebody took a weekend.
# breach-window = 20
# Ceiling on how many commits are read, newest first. A resource ceiling and a
# determinism tool at once: without a fixed range, a repository that grew
# between two runs cannot be compared with itself.
# history-limit = 2000
# Commits touching more paths than this are left out of coupling, because a
# commit that touches most of the tree hands support to every pair of paths in
# it. They stay in breach detection: a sweeping commit that broke a seam broke
# it.
# max-commit-size = 30
# The floors --suggest proposes a pair at: the smaller of the two directional
# confidences, and the number of commits behind it.
# min-coupling = 0.60
# min-support = 3
# How many leading path components make the unit --suggest counts co-change
# over. A file is too fine to see a pair of parallel implementations in; the
# whole tree is too coarse to see anything.
# suggest-depth = 2

# What a report states about the run before it.
# [report]
# How many of each run's highest-ranked groups are compared when saying what
# became of the work worth looking at. A total counts duplication rather than
# progress: closing a handful of groups out of thousands leaves it almost where
# it was, so the comparison is made over the top of each run.
# churn-top = 100
";

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests;
