//! Command-line interface definition, built with `clap`'s derive API.
//!
//! This module only declares the surface: the parsed [`Cli`] is handed to
//! [`crate::run`], which dispatches each [`Command`]. Commands that depend on
//! parts of the engine or store that do not exist yet parse and validate their
//! arguments here, then fail with an explicit message at dispatch.

use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};

/// Top-level command-line parser.
#[derive(Debug, Parser)]
#[command(name = "codehelion", version, about, long_about = None)]
pub struct Cli {
    /// Subcommand to run.
    #[command(subcommand)]
    pub command: Command,
}

/// Supported subcommands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Scan a codebase for duplicate logic.
    Scan(ScanArgs),
    /// Reformat one recorded scan without scanning the source tree again.
    Report(ReportArgs),
    /// Inspect or initialise configuration.
    Config {
        /// Configuration action.
        #[command(subcommand)]
        action: ConfigAction,
    },
    /// Explain a finding or explicit cross-language comparison group by its stable ID.
    Explain(ExplainArgs),
    /// Record or manage scan baselines.
    Baseline {
        /// Baseline action.
        #[command(subcommand)]
        action: BaselineAction,
    },
    /// Report which analysis components are available on this machine.
    Doctor,
    /// Inspect or clear cached scan state.
    Cache {
        /// Cache action.
        #[command(subcommand)]
        action: CacheAction,
    },
    /// Analyse or compare compiled artifacts without executing them.
    Artifact {
        /// Artifact action.
        #[command(subcommand)]
        action: ArtifactAction,
    },
}

/// Analysis mode selecting how much work the scan performs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Mode {
    /// Token-level Type-1/Type-2 and partial-clone detection; never runs the
    /// target code.
    Fast,
    /// Syntax-structural detection: gapped Type-3 clones and duplicated
    /// statement runs, judged on a similarity breakdown. Parses the sources
    /// and never runs the target code.
    Structural,
    /// Adds the clones a registered rule recognises across differing syntax,
    /// judged on what an out-of-process compiler helper resolved. Needs a
    /// helper `doctor` reports as available, and runs none of the project's
    /// own code unless `--allow-execution` names a class.
    Semantic,
}

impl Mode {
    /// What this mode is called, as it is typed and as a message names it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Fast => "fast",
            Self::Structural => "structural",
            Self::Semantic => "semantic",
        }
    }
}

/// Output format for a scan report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Format {
    /// Human-readable aligned text.
    Text,
    /// Machine-readable JSON (versioned schema).
    Json,
    /// SARIF 2.1.0 log, for static-analysis result consumers.
    Sarif,
}

/// What a scan does with the findings its baseline froze.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum BaselineMode {
    /// Hide them, so the report is what came after the baseline.
    Suppress,
    /// Hide nothing, and mark each group as one the baseline froze or one it
    /// did not.
    Compare,
}

impl BaselineMode {
    /// The name this mode is reported under.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Suppress => crate::report::BASELINE_SUPPRESS,
            Self::Compare => crate::report::BASELINE_COMPARE,
        }
    }
}

/// Output format for a single finding's detail view.
///
/// Kept apart from [`Format`]: SARIF describes a run's results, so offering it
/// for a one-occurrence lookup would advertise a format the command could not
/// produce.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum DetailFormat {
    /// Human-readable text.
    Text,
    /// Machine-readable JSON.
    Json,
}

/// Output format for compiled-artifact analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
pub enum ArtifactFormat {
    /// Human-readable summary.
    Text,
    /// Machine-readable JSON with a versioned schema.
    Json,
    /// Comma-separated summary or symbol-delta rows.
    Csv,
}

/// Input artifact format accepted by the parsers in this build.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
pub enum ArtifactInputFormat {
    /// WebAssembly core module.
    Wasm,
    /// ELF executable, shared object, or relocatable object.
    Elf,
    /// Mach-O executable, dynamic library, or relocatable object.
    MachO,
    /// Static archive containing local object members.
    Archive,
    /// PE image or COFF relocatable object.
    PeCoff,
}

/// Default maximum number of artifact bytes read by one command invocation.
///
/// This ceiling bounds the input retained by in-process parsers. It can be
/// lowered for an untrusted artifact or raised deliberately for a known one.
pub const DEFAULT_ARTIFACT_MAX_BYTES: u64 = 512 * 1024 * 1024;

/// Default wall-clock ceiling for one isolated artifact worker.
pub const DEFAULT_ARTIFACT_TIMEOUT_SECONDS: u64 = 30;

/// Arguments for the `artifact` subcommand.
#[derive(Debug, Clone, clap::Args, Serialize, Deserialize)]
pub struct ArtifactArgs {
    /// Compiled artifact to inspect.
    pub path: PathBuf,
    /// Report format.
    #[arg(long, value_enum, default_value_t = ArtifactFormat::Text)]
    pub format: ArtifactFormat,
    /// Require this input format instead of accepting automatic detection.
    #[arg(long, value_enum)]
    pub input_format: Option<ArtifactInputFormat>,
    /// Write the report to this file instead of standard output.
    #[arg(long)]
    pub output: Option<PathBuf>,
    /// Include every extracted symbol in a text report.
    #[arg(long)]
    pub verbose: bool,
    /// Reject an artifact larger than this many bytes before parsing it.
    #[arg(long, default_value_t = DEFAULT_ARTIFACT_MAX_BYTES)]
    pub max_bytes: u64,
    /// Stop the isolated artifact worker after this many seconds.
    ///
    /// The worker is a separate process, so this remains enforceable when a
    /// malformed input makes a parser stop making progress.
    #[arg(
        long,
        default_value_t = DEFAULT_ARTIFACT_TIMEOUT_SECONDS,
        value_parser = clap::value_parser!(u64).range(1..)
    )]
    pub timeout_seconds: u64,
    /// Require the artifact worker to stay within this virtual-memory ceiling.
    ///
    /// Linux enforces this through the operating system; other platforms
    /// refuse the request rather than silently ignoring it.
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
    pub max_memory_bytes: Option<u64>,
    /// JSON manifest describing this artifact's build variant.
    #[arg(long)]
    pub build_variant: Option<PathBuf>,
    /// Completed source scan whose units may be correlated using debug evidence.
    /// Requires `--build-variant` so artifact and source conditions remain explicit.
    #[arg(long, requires = "build_variant")]
    pub source_run: Option<i64>,
    /// Existing local linker map used as additional source-artifact evidence.
    ///
    /// The map is read only when a source run was explicitly selected; this
    /// command never invokes a linker or builds the inspected project.
    #[arg(long, requires = "source_run")]
    pub linker_map: Option<PathBuf>,
    /// Existing external ELF, Mach-O, or PE debug companion for this exact artifact build.
    ///
    /// It is read locally without invoking a compiler. The artifact backend
    /// accepts ELF companions only with the same GNU build ID, Mach-O companions
    /// only with the same `LC_UUID`, and PE companions only with the matching
    /// `CodeView` PDB GUID and an eligible PDB age. Without this option,
    /// Mach-O analysis also checks its conventional sibling dSYM bundle.
    #[arg(long, requires = "source_run")]
    pub debug_file: Option<PathBuf>,
    /// Local database path, overriding the configured location.
    #[arg(long)]
    pub db: Option<PathBuf>,
}

/// Actions available below `artifact`.
#[derive(Debug, Subcommand)]
pub enum ArtifactAction {
    /// Analyse one compiled artifact.
    Analyze(ArtifactArgs),
    /// Run an already validated artifact request inside the isolated worker.
    #[command(hide = true)]
    Isolated(ArtifactIsolatedArgs),
    /// Compare two compiled artifacts.
    Compare(ArtifactCompareArgs),
    /// Summarize controlled savings-calibration measurements.
    Calibration(ArtifactCalibrationArgs),
}

/// Private file-based request passed from an artifact command to its worker.
#[derive(Debug, clap::Args)]
pub struct ArtifactIsolatedArgs {
    /// JSON request written by the parent command.
    #[arg(long)]
    pub request: PathBuf,
}

/// Arguments for `artifact calibration`.
#[derive(Debug, clap::Args)]
pub struct ArtifactCalibrationArgs {
    /// Source scan whose controlled measurements are summarized.
    #[arg(long)]
    pub source_run: i64,
    /// Earlier local calibration JSON report to compare without enforcing a threshold.
    #[arg(long)]
    pub baseline: Option<PathBuf>,
    /// Local database path holding the controlled measurements.
    #[arg(long)]
    pub db: Option<PathBuf>,
    /// Report format.
    #[arg(long, value_enum, default_value_t = ArtifactFormat::Text)]
    pub format: ArtifactFormat,
    /// Write the report to this file instead of standard output.
    #[arg(long)]
    pub output: Option<PathBuf>,
}

/// Arguments for `artifact compare`.
#[derive(Debug, Clone, clap::Args, Serialize, Deserialize)]
pub struct ArtifactCompareArgs {
    /// Earlier artifact.
    pub before: PathBuf,
    /// Later artifact.
    pub after: PathBuf,
    /// JSON manifest describing the earlier artifact's build variant.
    ///
    /// Supplying both manifests lets the comparison report warn when build
    /// conditions differ without pretending that a byte difference comes
    /// from a source-level change alone.
    #[arg(long)]
    pub before_build_variant: Option<PathBuf>,
    /// JSON manifest describing the later artifact's build variant.
    #[arg(long)]
    pub after_build_variant: Option<PathBuf>,
    /// Report format.
    #[arg(long, value_enum, default_value_t = ArtifactFormat::Text)]
    pub format: ArtifactFormat,
    /// Write the report to this file instead of standard output.
    #[arg(long)]
    pub output: Option<PathBuf>,
    /// Reject either artifact larger than this many bytes before parsing it.
    #[arg(long, default_value_t = DEFAULT_ARTIFACT_MAX_BYTES)]
    pub max_bytes: u64,
    /// Stop the isolated artifact worker after this many seconds.
    #[arg(
        long,
        default_value_t = DEFAULT_ARTIFACT_TIMEOUT_SECONDS,
        value_parser = clap::value_parser!(u64).range(1..)
    )]
    pub timeout_seconds: u64,
    /// Require the artifact worker to stay within this virtual-memory ceiling.
    ///
    /// Linux enforces this through the operating system; other platforms
    /// refuse the request rather than silently ignoring it.
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
    pub max_memory_bytes: Option<u64>,
    /// Source scan that produced the clone group being calibrated.
    ///
    /// Must be used with `--clone-group`, both build-variant manifests, and
    /// `--db`; a whole-artifact difference is never assigned to a group by
    /// inference.
    #[arg(long)]
    pub source_run: Option<i64>,
    /// Stable clone-group fingerprint to evaluate against this comparison.
    #[arg(long)]
    pub clone_group: Option<String>,
    /// Local database path used to read the estimate and persist calibration.
    #[arg(long)]
    pub db: Option<PathBuf>,
}

/// Arguments for the `scan` subcommand.
#[derive(Debug, clap::Args)]
#[allow(clippy::struct_excessive_bools)] // independent CLI switches, not a state machine
pub struct ScanArgs {
    /// Path to scan.
    #[arg(default_value = ".")]
    pub path: PathBuf,
    /// Analysis mode.
    #[arg(long, value_enum, default_value_t = Mode::Fast)]
    pub mode: Mode,
    /// Report format.
    #[arg(long, value_enum, default_value_t = Format::Text)]
    pub format: Format,
    /// Write the report to this file instead of standard output.
    #[arg(long)]
    pub output: Option<PathBuf>,
    /// Configuration file to use instead of the discovered `codehelion.toml`.
    #[arg(long)]
    pub config: Option<PathBuf>,
    /// Also scan files that `.gitignore` and related ignore files would hide.
    #[arg(long)]
    pub no_ignore: bool,
    /// Number of worker threads (default: automatic).
    #[arg(long)]
    pub jobs: Option<usize>,
    /// Local database path, overriding the configured location.
    #[arg(long)]
    pub db: Option<PathBuf>,
    /// Read this baseline file, reporting what came after it.
    #[arg(long)]
    pub baseline: Option<PathBuf>,
    /// What to do with the findings the baseline froze: hide them, or hide
    /// nothing and report every group against it.
    ///
    /// Hiding is the right default for a tree with duplication somebody has
    /// already decided about. Comparing is what working duplication down
    /// needs, where the question is what moved rather than what is left.
    #[arg(long, value_enum, default_value_t = BaselineMode::Suppress, requires = "baseline")]
    pub baseline_mode: BaselineMode,
    /// Also compare exact duplicate units between distinct C/C++ build variants.
    ///
    /// Normal scan snapshots remain partition-local. This opt-in emits and
    /// stores a separate comparison; it never changes a partition's variant.
    #[arg(long)]
    pub compare_build_variants: bool,
    /// Compare registered Rust and C++ semantic pipelines across explicitly
    /// selected compilation partitions.
    ///
    /// This requires Semantic mode. Normal scan snapshots remain
    /// partition-local; the result is a separate comparison with both origin
    /// variants retained.
    #[arg(long)]
    pub compare_languages: bool,
    /// Also list suppressed groups, with the reason each was hidden.
    #[arg(long)]
    pub show_suppressed: bool,
    /// Report duplication inside vendored trees, which is hidden by default.
    ///
    /// A flag rather than only a configuration key because the default is one
    /// the tool applies unasked, and undoing it for one run should not need a
    /// file edit.
    #[arg(long)]
    pub include_vendored: bool,
    /// Keep trivially-shaped predicate groups at their measured priority.
    ///
    /// By default these groups are reported below behavioural duplication;
    /// this switch is for an explicit review of the predicate families.
    #[arg(long)]
    pub include_trivial: bool,
    /// List every group and every member instead of the summarised excerpt.
    #[arg(long)]
    pub verbose: bool,
    /// Exit with a non-zero status if any findings are reported.
    #[arg(long)]
    pub fail_on_findings: bool,
    /// Read the tree under the ceilings for a repository nobody vouches for.
    ///
    /// Deliberately a flag and not a configuration key. The configuration file
    /// is discovered inside the tree being scanned, so a repository could set
    /// its own trust level — which is the one setting whose whole point is that
    /// its subject does not choose it.
    #[arg(long)]
    pub untrusted: bool,
    /// Let a compiler helper run these classes of the project's own code:
    /// build-script, proc-macro, configure, compiler-wrapper, generated-source.
    ///
    /// Nothing runs without this. A flag rather than a configuration key for
    /// the same reason as `--untrusted`, and stronger: the file that would
    /// carry the setting is one the tree being scanned supplies.
    #[arg(long, value_name = "CLASS[,CLASS]")]
    pub allow_execution: Option<String>,
}

/// Arguments for the `report` subcommand.
#[derive(Debug, clap::Args)]
pub struct ReportArgs {
    /// Row id of the completed scan to render again, as the scan that recorded
    /// it reported. The database keeps one scan, so this names that snapshot
    /// rather than picking one out of a history.
    #[arg(long)]
    pub run: i64,
    /// Report format.
    #[arg(long, value_enum, default_value_t = Format::Text)]
    pub format: Format,
    /// Write the report to this file instead of standard output.
    #[arg(long)]
    pub output: Option<PathBuf>,
    /// Also list suppressed groups, with the reason each was hidden.
    #[arg(long)]
    pub show_suppressed: bool,
    /// List every group and every member instead of the summarised excerpt.
    #[arg(long)]
    pub verbose: bool,
    /// Local database path, overriding the configured location.
    #[arg(long)]
    pub db: Option<PathBuf>,
}

/// Arguments for the `explain` subcommand.
#[derive(Debug, clap::Args)]
pub struct ExplainArgs {
    /// Stable finding or cross-language comparison group ID to explain.
    pub finding_id: String,
    /// Output format for the detail view.
    #[arg(long, value_enum, default_value_t = DetailFormat::Text)]
    pub format: DetailFormat,
    /// Local database path, overriding the configured location.
    #[arg(long)]
    pub db: Option<PathBuf>,
}

/// Actions for the `config` subcommand.
#[derive(Debug, Subcommand)]
pub enum ConfigAction {
    /// Print the effective configuration after resolving files and defaults.
    Show {
        /// Configuration file to use instead of the discovered one.
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Write a commented configuration template.
    Init {
        /// Destination file (default: `codehelion.toml` in the current
        /// directory).
        #[arg(long)]
        output: Option<PathBuf>,
        /// Overwrite the destination if it already exists.
        #[arg(long)]
        force: bool,
    },
}

/// Default baseline file, relative to the working directory.
///
/// Unlike the local database this is meant to be committed: it is a decision
/// the project made, and it has to travel with the code the decision is about.
pub const BASELINE_FILE_NAME: &str = "codehelion-baseline.json";

/// Actions for the `baseline` subcommand.
#[derive(Debug, Subcommand)]
pub enum BaselineAction {
    /// Freeze the last scan's reported findings as a baseline.
    Create(BaselineArgs),
    /// Drop the baseline entries the last scan no longer reports.
    Update(BaselineArgs),
}

/// Arguments shared by the `baseline` actions.
#[derive(Debug, clap::Args)]
pub struct BaselineArgs {
    /// Scanned path whose recorded run the baseline is taken from.
    #[arg(default_value = ".")]
    pub path: PathBuf,
    /// Baseline file to write.
    #[arg(long, default_value = BASELINE_FILE_NAME)]
    pub file: PathBuf,
    /// Overwrite an existing baseline file.
    #[arg(long)]
    pub force: bool,
    /// Local database path, overriding the configured location.
    #[arg(long)]
    pub db: Option<PathBuf>,
}

/// Actions for the `cache` subcommand.
#[derive(Debug, Subcommand)]
pub enum CacheAction {
    /// Show the local database's location and size.
    Status {
        /// Local database path, overriding the configured location.
        #[arg(long)]
        db: Option<PathBuf>,
    },
    /// Delete the local database.
    Clear {
        /// Local database path, overriding the configured location.
        #[arg(long)]
        db: Option<PathBuf>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{CommandFactory, Parser};

    #[test]
    fn cli_definition_is_valid() {
        // `debug_assert` catches structural mistakes in the clap definition.
        Cli::command().debug_assert();
    }

    #[test]
    #[allow(clippy::expect_used)] // Parsed flag state is the test subject.
    fn include_trivial_keeps_predicate_groups_at_their_measured_priority() {
        let parsed = Cli::try_parse_from(["codehelion", "scan", "--include-trivial"])
            .expect("the explicit predicate-review flag parses");
        assert!(matches!(
            parsed.command,
            Command::Scan(ScanArgs {
                include_trivial: true,
                ..
            })
        ));
    }

    #[test]
    #[allow(clippy::expect_used)] // Expected parse outcomes are the test subject.
    fn linker_map_requires_an_explicit_correlated_source_run() {
        let error = Cli::try_parse_from([
            "codehelion",
            "artifact",
            "analyze",
            "fixture.so",
            "--linker-map",
            "fixture.map",
        ])
        .expect_err("linker map without a source run must be rejected");
        assert!(error.to_string().contains("--source-run"));

        let parsed = Cli::try_parse_from([
            "codehelion",
            "artifact",
            "analyze",
            "fixture.so",
            "--source-run",
            "7",
            "--build-variant",
            "variant.json",
            "--linker-map",
            "fixture.map",
        ])
        .expect("a linker map with its required correlation inputs parses");
        assert!(matches!(
            &parsed.command,
            Command::Artifact {
                action: ArtifactAction::Analyze(_),
            }
        ));
        let Command::Artifact {
            action: ArtifactAction::Analyze(args),
        } = parsed.command
        else {
            return;
        };
        assert_eq!(args.source_run, Some(7));
        assert_eq!(args.linker_map, Some(PathBuf::from("fixture.map")));
    }

    #[test]
    #[allow(clippy::expect_used)] // Expected parse outcomes are the test subject.
    fn debug_file_requires_an_explicit_correlated_source_run() {
        let error = Cli::try_parse_from([
            "codehelion",
            "artifact",
            "analyze",
            "fixture.so",
            "--debug-file",
            "fixture.debug",
        ])
        .expect_err("debug file without a source run must be rejected");
        assert!(error.to_string().contains("--source-run"));
    }
}
