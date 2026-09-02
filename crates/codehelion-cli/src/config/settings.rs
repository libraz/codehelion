//! The settings a configuration carries: what is analysed, what is
//! suppressed, and how the results are presented.

use std::path::PathBuf;

use anyhow::{Result, bail};
use codehelion_core::boilerplate::Boilerplate;
use codehelion_core::discovery::{DEFAULT_MARKERS, HeaderPolicy};
use codehelion_core::test_code::DEFAULT_TEST_PATHS;
use serde::{Deserialize, Serialize};

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
    /// Bodies that are one handed-back expression naming more than one callee.
    /// Hidden by default, on the same evidence as the wrappers they extend.
    pub composed_answer: CategoryAction,
    /// Bodies that make one value behind a guard and hand it back. Hidden by
    /// default; a creator that also says what to do when creating fails has a
    /// second exit and is not this shape.
    pub built_answer: CategoryAction,
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
            // The wrapper rule with a second callee in the expression. Across
            // three of the labelled projects, by different authors, the shape
            // reached lookalikes only: a trace call beside a delegation, a
            // conditional between two readers, a predicate oring two tests.
            // Hidden on the evidence that put the one-call spelling here.
            composed_answer: CategoryAction::Hide,
            // A creator that names its kind and nothing else. Where two of
            // them also repeat what to do when creating fails, the body has a
            // second exit and this rule does not reach it, so what is hidden
            // is the family a reader cannot collapse without a way to write it
            // once.
            built_answer: CategoryAction::Hide,
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
            Boilerplate::ComposedAnswer => self.composed_answer,
            Boilerplate::BuiltAnswer => self.built_answer,
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

/// How much of a run the report states about a run before it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
pub struct ReportSettings {
    /// How many of each run's highest-ranked groups are compared when saying
    /// what became of the work worth looking at.
    ///
    /// A total counts duplication rather than progress: closing a handful of
    /// groups out of thousands leaves it almost where it was. Comparing the
    /// top of each run measures the part anyone acted on.
    pub churn_top: usize,
}

impl Default for ReportSettings {
    fn default() -> Self {
        // Enough to cover far more than a person works through between two
        // scans, and small enough that entering it means something.
        Self { churn_top: 100 }
    }
}

/// Explicit compiler-helper locations for environments without a usable PATH.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
pub struct Helpers {
    /// Path to the Rust compiler helper.
    pub rust: Option<PathBuf>,
    /// Path to the Clang compiler helper.
    pub clang: Option<PathBuf>,
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::config::Config;

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
        // The two shapes that extend the wrapper and the creator are set aside on
        // the evidence that put those there: refuted labels in more than one
        // project, and no confirmed one.
        assert_eq!(
            policy.action(Boilerplate::ComposedAnswer),
            CategoryAction::Hide
        );
        assert_eq!(
            policy.action(Boilerplate::BuiltAnswer),
            CategoryAction::Hide
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
}
