//! The durable provenance every source scan reports about itself: where its
//! configuration came from, which build variant it describes, what it read,
//! and when it ran.

#![allow(
    clippy::redundant_pub_crate,
    reason = "the implementation module shares run metadata across scan modes"
)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use codehelion_core::discovery::{BuildVariant, Language};
use codehelion_store::snapshot::{FileCountsRow, GuardrailsRow, PriorityRow};

use super::build::as_u64;
use super::{database_path, path_label};
use crate::cli::ScanArgs;
use crate::config::{self, ConfigSource};
use crate::report;

/// Turn configuration selection into durable report provenance.
#[must_use]
pub(crate) fn configuration_info(
    source: &ConfigSource,
    min_clone_tokens: u32,
) -> report::ConfigurationInfo {
    let (source, path) = match source {
        ConfigSource::Explicit(path) => ("explicit", Some(path.display().to_string())),
        ConfigSource::Discovered(path) => ("root", Some(path.display().to_string())),
        ConfigSource::Defaults => ("defaults", None),
    };
    report::ConfigurationInfo {
        source: source.to_string(),
        path,
        min_clone_tokens,
    }
}

/// A first-run hint for the local audit database directory.
///
/// The scan lock creates the directory before the source pipeline starts, so
/// this value is captured by the command dispatcher before a mode acquires
/// that lock. It is emitted only after the mode and its report have completed.
pub(crate) struct DatabaseDirectoryHint {
    directory: PathBuf,
    ignore_entry: String,
}

impl DatabaseDirectoryHint {
    pub(crate) fn emit(self) {
        eprintln!(
            "note: created local database directory {}; consider adding `{}` to .gitignore",
            self.directory.display(),
            self.ignore_entry,
        );
    }
}

/// Capture whether this scan will create a new, unignored database directory.
///
/// An explicit `--db` is an intentional storage choice and never receives this
/// default-database hint. For all other paths, including a database selected by
/// configuration, the actual parent-directory state is the authority: this is
/// what the lock acquisition will create. Git classification is delegated to
/// the same helpers used by `doctor`.
pub(crate) fn new_database_directory_hint(
    args: &ScanArgs,
) -> Result<Option<DatabaseDirectoryHint>> {
    if args.db.is_some() {
        return Ok(None);
    }
    let root = codehelion_core::paths::canonical(&args.path)
        .with_context(|| format!("resolving scan path {}", args.path.display()))?;
    if !root.is_dir() {
        // Let the selected mode return its usual actionable scan-path error.
        return Ok(None);
    }
    let resolved_config = config::load(args.config.as_deref(), &root)?;
    let db_path = database_path(&root, None, &resolved_config, args.untrusted)?;
    let Some(directory) = db_path.parent().filter(|path| !path.as_os_str().is_empty()) else {
        return Ok(None);
    };
    if directory.exists() {
        return Ok(None);
    }
    let Some(repo_root) = crate::find_git_root(&root) else {
        return Ok(None);
    };
    if crate::is_git_ignored(&repo_root, &db_path) {
        return Ok(None);
    }
    let ignore_entry = db_path
        .strip_prefix(&repo_root)
        .ok()
        .and_then(Path::parent)
        .filter(|path| !path.as_os_str().is_empty())
        .map_or_else(
            || directory.display().to_string(),
            |path| format!("{}/", path.to_string_lossy().replace('\\', "/")),
        );
    Ok(Some(DatabaseDirectoryHint {
        directory: directory.to_path_buf(),
        ignore_entry,
    }))
}

/// Count analyzed files by language in the persisted summary shape.
pub(crate) fn file_counts(languages: impl IntoIterator<Item = Language>) -> FileCountsRow {
    let mut counts = FileCountsRow::default();
    for language in languages {
        counts.total = counts.total.saturating_add(1);
        match language {
            Language::Rust => counts.rust = counts.rust.saturating_add(1),
            Language::C => counts.c = counts.c.saturating_add(1),
            Language::Cpp => counts.cpp = counts.cpp.saturating_add(1),
        }
    }
    counts
}

/// Convert one effective execution ceiling into its persisted summary shape.
pub(crate) fn guardrails_row(guardrails: &report::Guardrails) -> GuardrailsRow {
    // A ceiling this run's mode never consulted stays absent all the way into
    // storage, so a replayed report states exactly the bounds the scan held
    // itself to.
    let ceiling = |value: Option<usize>| value.map(as_u64);
    GuardrailsRow {
        profile: guardrails.profile.clone(),
        max_file_bytes: guardrails.max_file_bytes,
        parse_timeout_ms: guardrails.parse_timeout_ms,
        helper_timeout_ms: guardrails.helper_timeout_ms,
        posting_cap: as_u64(guardrails.posting_cap),
        pair_budget: as_u64(guardrails.pair_budget),
        near_miss_delta_bits: guardrails.near_miss_delta.map(f64::to_bits),
        near_miss_cap: ceiling(guardrails.near_miss_cap),
        verification_budget: ceiling(guardrails.verification_budget),
        max_alignment_cells: ceiling(guardrails.max_alignment_cells),
        sibling_candidate_budget: ceiling(guardrails.sibling_candidate_budget),
        sibling_per_group_cap: ceiling(guardrails.sibling_per_group_cap),
        sibling_total_cap: ceiling(guardrails.sibling_total_cap),
        signature_sibling_candidate_budget: ceiling(guardrails.signature_sibling_candidate_budget),
        signature_sibling_per_group_cap: ceiling(guardrails.signature_sibling_per_group_cap),
        signature_sibling_total_cap: ceiling(guardrails.signature_sibling_total_cap),
        signature_sibling_max_units_per_signature: ceiling(
            guardrails.signature_sibling_max_units_per_signature,
        ),
        max_component: ceiling(guardrails.max_component),
    }
}

/// Common inputs for the durable metadata every source scan reports.
pub(crate) struct RunInfoInputs<'a> {
    /// Scan root.
    pub root: &'a Path,
    /// Local audit database path.
    pub db_path: &'a Path,
    /// The `--db` the commands this report prints have to repeat.
    ///
    /// A database nobody named is the one every other command resolves for
    /// itself, so those commands leave `--db` off. A named one has to be
    /// repeated, or the next command reads somewhere else.
    pub replay_database: Option<&'a str>,
    /// Effective configuration recorded with the scan.
    pub configuration: &'a report::ConfigurationInfo,
    /// Persisted scan run identifier.
    pub run_id: Option<i64>,
    /// Invocation start timestamp.
    pub started_at: &'a str,
    /// Invocation finish timestamp.
    pub finished_at: &'a str,
    /// First-class build variant that produced this partition.
    pub variant: &'a BuildVariant,
    /// Detector versions that affect this mode's findings.
    pub detector_versions: Vec<report::DetectorVersion>,
    /// Priority recipe used to rank the report entries.
    pub weights: &'a codehelion_core::priority::Weights,
}

/// Build the report metadata shared by Fast, Structural, and Semantic scans.
pub(crate) fn common_run_info(mut inputs: RunInfoInputs<'_>) -> report::RunInfo {
    let variant = inputs.variant;
    // The store restores these rows by their natural identity. Emit that same
    // canonical order from a fresh scan so a later `report --run` is a true
    // rendering change rather than a metadata change.
    inputs.detector_versions.sort_unstable_by(|left, right| {
        left.component
            .cmp(&right.component)
            .then_with(|| left.version.cmp(&right.version))
    });
    report::RunInfo {
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        mode: variant.mode.name().to_string(),
        // Through the key the run is recorded under, so that replaying this
        // run names its root exactly as this rendering does.
        root: path_label(inputs.root),
        configuration: inputs.configuration.clone(),
        started_at: inputs.started_at.to_string(),
        finished_at: inputs.finished_at.to_string(),
        build_variant: report::BuildVariantInfo {
            mode: variant.mode.name().to_string(),
            languages: variant
                .languages
                .enabled()
                .into_iter()
                .map(|language| language.name().to_string())
                .collect(),
            headers: variant.headers.map(|language| language.name().to_string()),
            normalization_version: variant.normalization_version,
            fingerprint: variant.fingerprint(),
            settings: build_variant_settings(variant),
        },
        detector_versions: inputs.detector_versions,
        ranking: report::RankingInfo {
            recipe: inputs.weights.recipe(),
            maintenance_risk: inputs.weights.maintenance_risk,
            refactoring_ease: inputs.weights.refactoring_ease,
        },
        database: inputs.db_path.display().to_string(),
        replay_database: inputs.replay_database.map(ToOwned::to_owned),
        // Filled in after recording, which is the half this cannot know about
        // yet, by the same code that fills in the run id.
        timings: None,
        run_id: inputs.run_id,
        reused: false,
    }
}

/// `path`, spelled the way it is shortest to type from here.
///
/// A printed command is read on one line beside everything else the report
/// says, and an absolute path in the middle of it costs more width than it
/// carries meaning. Anything outside the current directory keeps its full
/// spelling, because a relative path to it would be the longer of the two.
pub(crate) fn spelled_for_a_command(path: &Path) -> String {
    let relative = std::env::current_dir()
        .ok()
        .and_then(|current| path.strip_prefix(current).ok().map(Path::to_path_buf));
    relative.as_deref().unwrap_or(path).display().to_string()
}

/// Renderable settings that explain the identity of a resolved build variant.
///
/// The map's ordering matches the persisted query order, so a fresh report and
/// a `report --run` replay serialize the same evidence.
pub(crate) fn build_variant_settings(
    variant: &BuildVariant,
) -> BTreeMap<String, BTreeMap<String, Vec<String>>> {
    let mut settings = BTreeMap::new();
    for build in &variant.builds {
        let language = build.language().to_string();
        for setting in build.settings() {
            let values = setting
                .shape
                .values()
                .into_iter()
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>();
            if !values.is_empty() {
                settings
                    .entry(language.clone())
                    .or_insert_with(BTreeMap::new)
                    .insert(setting.name.to_string(), values);
            }
        }
    }
    settings
}

/// A report entry's ranking as the audit database records it.
///
/// Both analysis modes go through here, so what the store holds is what the
/// report showed rather than a second derivation of it.
pub(crate) const fn priority_row(priority: &report::Priority) -> PriorityRow {
    PriorityRow {
        clone_confidence: priority.clone_confidence,
        maintenance_risk: priority.maintenance_risk,
        refactoring_difficulty: priority.refactoring_difficulty,
        final_priority: priority.value,
        semantic_confidence: priority.semantic_confidence,
        source_artifact_confidence: priority.source_artifact_confidence,
        savings_confidence: priority.savings_confidence,
    }
}

/// The current time as fixed-width RFC 3339 UTC with microsecond precision.
///
/// Hand-formatted so the width never varies: lexicographic order then equals
/// chronological order, which the store's latest-run ordering relies on.
pub(crate) fn rfc3339_now() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let seconds = i64::try_from(now.as_secs()).unwrap_or(i64::MAX);
    let micros = now.subsec_micros();
    let (year, month, day) = civil_from_days(seconds.div_euclid(86_400));
    let rem = seconds.rem_euclid(86_400);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{micros:06}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60,
    )
}

/// Convert days since 1970-01-01 to a proleptic-Gregorian civil date.
const fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_point = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_point + 2) / 5 + 1;
    let month = if month_point < 10 {
        month_point + 3
    } else {
        month_point - 9
    };
    let year = year_of_era + era * 400 + if month <= 2 { 1 } else { 0 };
    (year, month, day)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use codehelion_core::discovery::{
        BuildConfiguration, BuildVariant, CppBuild, Language, LanguageSelection,
    };
    use codehelion_store::snapshot::FileCountsRow;
    use std::collections::BTreeMap;

    use super::{build_variant_settings, civil_from_days, file_counts, rfc3339_now};

    #[test]
    fn fresh_variant_settings_expose_the_compiler_inputs_that_define_identity() {
        let variant = BuildVariant::semantic(
            LanguageSelection {
                rust: false,
                c: false,
                cpp: true,
            },
            Language::Cpp,
            vec![BuildConfiguration::Cpp(Box::new(CppBuild {
                compiler: "clang++".to_string(),
                macros: vec!["-DENABLED=1".to_string()],
                include_paths: vec!["include".to_string(), "generated".to_string()],
                flags: vec!["-std=c++20".to_string()],
                ..CppBuild::default()
            }))],
        );

        assert_eq!(
            build_variant_settings(&variant),
            BTreeMap::from([(
                String::from("cpp"),
                BTreeMap::from([
                    (String::from("compiler"), vec![String::from("clang++")]),
                    (String::from("flags"), vec![String::from("-std=c++20")]),
                    (
                        String::from("includes"),
                        vec![String::from("include"), String::from("generated")]
                    ),
                    (String::from("macros"), vec![String::from("-DENABLED=1")]),
                ])
            )])
        );
    }

    #[test]
    fn civil_conversion_matches_known_dates() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(1), (1970, 1, 2));
        assert_eq!(civil_from_days(19_723), (2024, 1, 1)); // leap year start
        assert_eq!(civil_from_days(19_783), (2024, 3, 1)); // day after Feb 29
        assert_eq!(civil_from_days(-1), (1969, 12, 31));
    }

    #[test]
    fn timestamps_are_fixed_width_rfc3339() {
        let stamp = rfc3339_now();
        assert_eq!(stamp.len(), "1970-01-01T00:00:00.000000Z".len());
        assert!(stamp.ends_with('Z'));
        assert_eq!(stamp.as_bytes()[10], b'T');
    }

    #[test]
    fn summary_file_counts_use_one_cross_mode_shape() {
        assert_eq!(
            file_counts([Language::Rust, Language::Cpp, Language::Rust, Language::C]),
            FileCountsRow {
                total: 4,
                rust: 2,
                c: 1,
                cpp: 1,
            }
        );
    }
}
