//! Argument declarations for the `artifact` subcommand and its actions.

use std::path::PathBuf;

use clap::{Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};

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
///
/// Each name is the one the reports print, so an assertion on the command
/// line and the format a report names are the same word.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
pub enum ArtifactInputFormat {
    /// WebAssembly core module.
    Wasm,
    /// ELF executable, shared object, or relocatable object.
    Elf,
    /// Mach-O executable, dynamic library, or relocatable object.
    #[value(name = "macho")]
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

/// Largest deliberate artifact-worker deadline accepted from the command line.
///
/// A day is ample for a known artifact while keeping the deadline representable
/// by [`std::time::Instant`] on every supported platform.
pub const MAX_ARTIFACT_TIMEOUT_SECONDS: u64 = 24 * 60 * 60;

/// Maximum input accepted by the untrusted artifact preset.
pub const UNTRUSTED_ARTIFACT_MAX_BYTES: u64 = 64 * 1024 * 1024;

/// Worker deadline applied by the untrusted artifact preset.
pub const UNTRUSTED_ARTIFACT_TIMEOUT_SECONDS: u64 = 10;

/// Address-space ceiling applied by the untrusted preset where enforceable.
pub const UNTRUSTED_ARTIFACT_MAX_MEMORY_BYTES: u64 = 512 * 1024 * 1024;

/// Arguments for the `artifact` subcommand.
#[derive(Debug, Clone, clap::Args, Serialize, Deserialize)]
pub struct ArtifactArgs {
    /// Compiled artifact to inspect.
    pub path: PathBuf,
    /// Report format.
    #[arg(long, value_enum, default_value_t = ArtifactFormat::Text)]
    pub format: ArtifactFormat,
    /// Require magic-byte detection to identify the input as this format.
    ///
    /// This is an assertion, not an override: a mismatch is rejected.
    #[arg(long, value_enum)]
    pub input_format: Option<ArtifactInputFormat>,
    /// Architecture slice to inspect from a universal Mach-O binary.
    ///
    /// Multi-slice Mach-O inputs require this explicit selection. Other
    /// formats reject the option so it cannot be mistaken for a build target.
    #[arg(long)]
    pub arch: Option<String>,
    /// Write the report to this file instead of standard output.
    #[arg(long)]
    pub output: Option<PathBuf>,
    /// Replace an existing output file.
    #[arg(long, requires = "output")]
    pub force: bool,
    /// Add every extracted import, relocation, data segment, and symbol to a
    /// text report; JSON and CSV already carry them regardless of this flag.
    #[arg(short, long)]
    pub verbose: bool,
    /// Reject an artifact larger than this many bytes before parsing it.
    #[arg(long, default_value_t = DEFAULT_ARTIFACT_MAX_BYTES)]
    pub max_bytes: u64,
    /// Stop the full isolated artifact operation after this many seconds.
    ///
    /// The worker is a separate process, so this remains enforceable when a
    /// malformed input makes a parser stop making progress. Correlation,
    /// persistence, and rendering run in the same isolated operation.
    #[arg(
        long,
        default_value_t = DEFAULT_ARTIFACT_TIMEOUT_SECONDS,
        value_parser = clap::value_parser!(u64).range(1..=MAX_ARTIFACT_TIMEOUT_SECONDS)
    )]
    pub timeout_seconds: u64,
    /// Require the artifact worker to stay within this virtual-memory ceiling.
    ///
    /// Linux enforces this through the operating system; other platforms
    /// refuse the request rather than silently ignoring it.
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
    pub max_memory_bytes: Option<u64>,
    /// Clamp input, time, and supported memory ceilings for an artifact nobody vouches for.
    ///
    /// The memory ceiling is part of the preset rather than optional, so this
    /// runs on Linux only; elsewhere it is refused.
    #[arg(long)]
    pub untrusted: bool,
    /// JSON manifest you write describing the conditions this artifact was
    /// built under.
    ///
    /// Its contents are yours to choose: the file is a declaration that only
    /// artifacts built the same way are compared with one another, and its
    /// digest is what makes that comparison possible. It is a separate thing
    /// from a source run's build variant digest and does not have to match
    /// one; nothing looks for a file that already exists.
    #[arg(long)]
    pub build_variant: Option<PathBuf>,
    /// Completed source scan whose units may be correlated using debug evidence.
    ///
    /// Requires `--build-variant` so artifact and source conditions remain
    /// explicit. The two conditions are recorded side by side rather than
    /// checked against each other: the source digest is not something to look
    /// up and write into the manifest.
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
    /// This input is independent of source correlation; only `--source-run`
    /// requires a matching build-variant manifest.
    #[arg(long)]
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
    /// Re-render one saved compiled-artifact analysis without reopening its input.
    Report(ArtifactReportArgs),
    /// Run an already validated artifact request inside the isolated worker.
    #[command(hide = true)]
    Isolated(ArtifactIsolatedArgs),
    /// Compare two compiled artifacts.
    Compare(ArtifactCompareArgs),
    /// Summarize controlled savings-calibration measurements.
    Calibration(ArtifactCalibrationArgs),
}

/// Arguments for `artifact report`.
#[derive(Debug, clap::Args)]
pub struct ArtifactReportArgs {
    /// Saved artifact analysis to re-render. Defaults to the latest saved analysis.
    #[arg(long)]
    pub analysis: Option<i64>,
    /// Local database path holding the saved analysis.
    #[arg(long)]
    pub db: Option<PathBuf>,
    /// Report format.
    #[arg(long, value_enum, default_value_t = ArtifactFormat::Text)]
    pub format: ArtifactFormat,
    /// Write the report to this file instead of standard output.
    #[arg(long)]
    pub output: Option<PathBuf>,
    /// Replace an existing output file.
    #[arg(long, requires = "output")]
    pub force: bool,
    /// Add every extracted import, relocation, data segment, and symbol to a
    /// text report; JSON and CSV already carry them regardless of this flag.
    #[arg(short, long)]
    pub verbose: bool,
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
    /// Source scan whose controlled measurements are summarized. Defaults to the latest completed scan.
    #[arg(long)]
    pub source_run: Option<i64>,
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
    /// Replace an existing output file.
    #[arg(long, requires = "output")]
    pub force: bool,
}

/// Arguments for `artifact compare`.
#[derive(Debug, Clone, clap::Args, Serialize, Deserialize)]
pub struct ArtifactCompareArgs {
    /// Earlier artifact.
    pub before: PathBuf,
    /// Later artifact.
    pub after: PathBuf,
    /// Require magic-byte detection to identify both artifacts as this format.
    ///
    /// This is an assertion, not an override: either mismatch is rejected.
    #[arg(long, value_enum)]
    pub input_format: Option<ArtifactInputFormat>,
    /// Architecture slice to compare from both universal Mach-O binaries.
    ///
    /// One shared selection keeps a comparison from silently pairing different
    /// architecture slices because their container orders differ.
    #[arg(long)]
    pub arch: Option<String>,
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
    /// Replace an existing output file.
    #[arg(long, requires = "output")]
    pub force: bool,
    /// Reject either artifact larger than this many bytes before parsing it.
    #[arg(long, default_value_t = DEFAULT_ARTIFACT_MAX_BYTES)]
    pub max_bytes: u64,
    /// Stop the full isolated artifact operation after this many seconds.
    #[arg(
        long,
        default_value_t = DEFAULT_ARTIFACT_TIMEOUT_SECONDS,
        value_parser = clap::value_parser!(u64).range(1..=MAX_ARTIFACT_TIMEOUT_SECONDS)
    )]
    pub timeout_seconds: u64,
    /// Require the artifact worker to stay within this virtual-memory ceiling.
    ///
    /// Linux enforces this through the operating system; other platforms
    /// refuse the request rather than silently ignoring it.
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
    pub max_memory_bytes: Option<u64>,
    /// Clamp input, time, and supported memory ceilings for artifacts nobody vouches for.
    ///
    /// The memory ceiling is part of the preset rather than optional, so this
    /// runs on Linux only; elsewhere it is refused.
    #[arg(long)]
    pub untrusted: bool,
    /// Source scan that produced the clone group being calibrated.
    ///
    /// Must be used with `--clone-group` and both build-variant manifests; a
    /// whole-artifact difference is never assigned to a group by inference.
    /// `--db` is optional here and resolves to the same local database every
    /// other command resolves; it is the pair above that decides whether a
    /// calibration is recorded at all. The resulting `verified_savings_bytes`
    /// attributes the whole observed artifact difference to this clone group,
    /// which holds only when the two artifacts differ in nothing else besides
    /// the refactoring being measured.
    #[arg(long)]
    pub source_run: Option<i64>,
    /// Stable clone-group fingerprint to evaluate against this comparison.
    #[arg(long)]
    pub clone_group: Option<String>,
    /// Local database path used to read the estimate and persist calibration.
    #[arg(long)]
    pub db: Option<PathBuf>,
}
