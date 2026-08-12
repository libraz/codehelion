//! Command-line interface definition, built with `clap`'s derive API.
//!
//! This module only declares the surface: the parsed [`Cli`] is handed to
//! [`crate::run`], which dispatches each [`Command`]. Commands that depend on
//! parts of the engine or store that do not exist yet parse and validate their
//! arguments here, then fail with an explicit message at dispatch.

use std::io::IsTerminal;
use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};
use codehelion_core::discovery::AnalysisMode;
use serde::{Deserialize, Serialize};

use crate::report;

/// Top-level command-line parser.
#[derive(Debug, Parser)]
#[command(
    name = "codehelion",
    version,
    about = "Index source duplication for maintainability; artifact analysis is optional.",
    long_about = None
)]
pub struct Cli {
    /// Subcommand to run.
    #[command(subcommand)]
    pub command: Command,
}

/// Parse a finite Jaccard threshold that remains meaningful as a percentage.
fn parse_identifier_jaccard(value: &str) -> Result<f64, String> {
    let parsed = value
        .parse::<f64>()
        .map_err(|_| "must be a finite number in 0.0..=1.0".to_string())?;
    if parsed.is_finite() && (0.0..=1.0).contains(&parsed) {
        Ok(parsed)
    } else {
        Err("must be a finite number in 0.0..=1.0".to_string())
    }
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
    Doctor(DoctorArgs),
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
    /// Measures token equality and identifier/literal changes for Type-1 and
    /// Type-2 copies. It does not measure identifier agreement, similarity
    /// breakdowns, siblings or near misses, and never runs target code.
    Fast,
    /// Measures gapped Type-3 copies and duplicated statement runs, with
    /// identifier agreement, similarity breakdowns and near misses. Sibling
    /// generation is opt-in with `--siblings-by-signature`. Parses sources
    /// and never runs target code.
    Structural,
    /// Adds registered semantic matches and compiler-resolved type/name
    /// evidence to Structural measurements. Needs a helper `doctor` reports
    /// as available, and runs none of the project's own code unless
    /// `--allow-execution` names a class.
    Semantic,
}

impl Mode {
    /// What this mode is called, as it is typed and as a message names it.
    #[must_use]
    pub fn name(self) -> &'static str {
        AnalysisMode::from(self).name()
    }
}

impl From<Mode> for AnalysisMode {
    fn from(mode: Mode) -> Self {
        match mode {
            Mode::Fast => Self::Fast,
            Mode::Structural => Self::Structural,
            Mode::Semantic => Self::Semantic,
        }
    }
}

impl From<AnalysisMode> for Mode {
    fn from(mode: AnalysisMode) -> Self {
        match mode {
            AnalysisMode::Fast => Self::Fast,
            AnalysisMode::Structural => Self::Structural,
            AnalysisMode::Semantic => Self::Semantic,
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

/// When a text report emits ANSI colour codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum)]
pub enum ColorChoice {
    /// Colour a report going to a terminal, unless `NO_COLOR` is set.
    #[default]
    Auto,
    /// Colour the report even when it is piped or written to a file.
    Always,
    /// Emit no ANSI codes.
    Never,
}

impl ColorChoice {
    /// Whether this choice colours a report, given whether it is going to
    /// standard output rather than to a file.
    ///
    /// `Auto` follows the two things a user of any other command-line tool
    /// expects to control it: whether the destination is a terminal, and the
    /// `NO_COLOR` convention.
    #[must_use]
    pub fn enabled(self, to_stdout: bool) -> bool {
        match self {
            Self::Always => true,
            Self::Never => false,
            Self::Auto => {
                to_stdout
                    && std::io::stdout().is_terminal()
                    && std::env::var_os("NO_COLOR").is_none_or(|value| value.is_empty())
            }
        }
    }
}

/// Which glyphs a text report draws its structure with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum)]
pub enum DecorationChoice {
    /// Box-drawing characters for a terminal, ASCII stand-ins elsewhere.
    #[default]
    Auto,
    /// Box-drawing characters and symbols.
    Unicode,
    /// ASCII stand-ins for every glyph.
    Ascii,
    /// No tree and no marks, for a report something else reads.
    None,
}

impl DecorationChoice {
    /// The glyph set this choice draws with.
    ///
    /// Deliberately not conditioned on the destination being a terminal, as
    /// colour is. Colour in a file is damage; a box-drawing character in a
    /// file is a box-drawing character, and the reader who opens that file
    /// wants the same structure the terminal showed. What decides the glyph is
    /// whether the console can draw it, which is a platform question: every
    /// target this tool builds for reads UTF-8 by default except Windows,
    /// whose console still depends on the active code page.
    #[must_use]
    pub const fn resolve(self) -> report::Decoration {
        match self {
            Self::Unicode => report::Decoration::Unicode,
            Self::Ascii => report::Decoration::Ascii,
            Self::None => report::Decoration::None,
            Self::Auto => {
                if cfg!(windows) {
                    report::Decoration::Ascii
                } else {
                    report::Decoration::Unicode
                }
            }
        }
    }
}

/// How much of a text report to print, shared by every command that renders
/// one.
///
/// Detail and length are separate knobs on purpose. `--verbose` says how much
/// is written about each group, `--limit` says how many groups are written
/// about; conflating them means a reader who wants one more number has to
/// accept every group in the tree along with it.
#[derive(Debug, Clone, Copy, Default, clap::Args)]
pub struct ViewArgs {
    /// Print more about each group. Repeat for more: `-v` adds the ranking
    /// inputs and what the scan read, `-vv` adds the candidate pipeline, the
    /// ceilings that applied, and full identifiers.
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,
    /// Print the groups alone, without the heading, the summary, or the notes.
    #[arg(short, long, conflicts_with = "verbose")]
    pub quiet: bool,
    /// List at most this many groups; `0` lists every group and every
    /// occurrence.
    #[arg(long, value_name = "N")]
    pub limit: Option<usize>,
    /// When to colour the report.
    #[arg(long, value_enum, default_value_t = ColorChoice::Auto)]
    pub color: ColorChoice,
    /// Which glyphs the listing draws its structure with.
    #[arg(long, value_enum, default_value_t = DecorationChoice::Auto)]
    pub decoration: DecorationChoice,
}

/// An axis a report can be put in order on.
///
/// Offered because no one measure orders duplication well for every job, and
/// a reader who knows which measure matters to the work in front of them
/// should not have to re-sort the output by hand.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum)]
pub enum SortAxis {
    /// The composed ranking value.
    #[default]
    Priority,
    /// Raw identifier agreement against the canonical member.
    IdentifierJaccard,
    /// Tokens the group repeats past its canonical member.
    DuplicatedTokens,
    /// Number of occurrences.
    Instances,
}

impl SortAxis {
    /// The report-side axis this selects.
    #[must_use]
    pub const fn axis(self) -> report::Sort {
        match self {
            Self::Priority => report::Sort::Priority,
            Self::IdentifierJaccard => report::Sort::IdentifierJaccard,
            Self::DuplicatedTokens => report::Sort::DuplicatedTokens,
            Self::Instances => report::Sort::Instances,
        }
    }
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
            Self::Suppress => report::BASELINE_SUPPRESS,
            Self::Compare => report::BASELINE_COMPARE,
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
    /// Include every extracted symbol in a text report.
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,
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
    #[arg(long)]
    pub untrusted: bool,
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
    /// Include every extracted symbol in a text report.
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,
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
    #[arg(long)]
    pub untrusted: bool,
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

/// Arguments for the `doctor` subcommand.
#[derive(Debug, clap::Args)]
pub struct DoctorArgs {
    /// Repository path whose configuration and local database to inspect.
    #[arg(long, default_value = ".")]
    pub path: PathBuf,
    /// Configuration file to use instead of the one discovered from `--path`.
    #[arg(long)]
    pub config: Option<PathBuf>,
    /// Override one compiler-helper location as `rust=PATH` or `clang=PATH`.
    #[arg(long = "helper", value_name = "NAME=PATH")]
    pub helpers: Vec<String>,
    /// Local database path, overriding the configured location.
    #[arg(long)]
    pub db: Option<PathBuf>,
    /// Treat the selected repository and its configuration as untrusted.
    ///
    /// A configured database path must remain inside `--path`; an explicit
    /// `--db` remains a deliberate operator choice.
    #[arg(long)]
    pub untrusted: bool,
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
    /// Replace an existing output file.
    #[arg(long)]
    pub force: bool,
    /// Configuration file to use instead of the discovered `codehelion.toml`.
    #[arg(long)]
    pub config: Option<PathBuf>,
    /// Override one compiler-helper location as `rust=PATH` or `clang=PATH`.
    #[arg(long = "helper", value_name = "NAME=PATH")]
    pub helpers: Vec<String>,
    /// Also scan files that `.gitignore` and related ignore files would hide.
    #[arg(long)]
    pub no_ignore: bool,
    /// Follow symbolic links while discovering source files.
    ///
    /// The walker detects directory cycles; without this flag links are
    /// excluded and reported by type.
    #[arg(long)]
    pub follow_links: bool,
    /// Use this compilation database instead of automatically selecting one.
    ///
    /// Relative paths are resolved from the scan root.
    #[arg(long, value_name = "PATH")]
    pub compile_commands: Option<PathBuf>,
    /// Frontend read-and-lex worker threads (default: automatic).
    ///
    /// Clone grouping and report rendering remain serial.
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
    /// Requires Semantic mode. Normal scan snapshots remain partition-local.
    /// This opt-in emits and stores a separate comparison; it never changes a
    /// partition's variant.
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
    /// Also list suppressed groups in a text report, with the reason each was
    /// hidden. JSON and SARIF always retain suppressed findings.
    #[arg(long)]
    pub show_suppressed: bool,
    /// Also list incomplete local mirrors beneath their owning primary group.
    /// JSON and SARIF always retain sibling data.
    #[arg(long)]
    pub show_siblings: bool,
    /// Generate sibling evidence from normalized signatures.
    ///
    /// This is separate from `--show-siblings`, which only changes text
    /// presentation. The flag is available in Structural and Semantic modes;
    /// it is off by default because signature matching is bounded by the
    /// configured sibling ceilings.
    #[arg(long)]
    pub siblings_by_signature: bool,
    /// Also list bounded LSH proposals that narrowly missed the primary
    /// near-match estimate gate. JSON and SARIF always retain these diagnostics.
    #[arg(long)]
    pub show_near_misses: bool,
    /// Order the report on this axis instead of the composed priority.
    #[arg(long, value_enum, default_value_t = SortAxis::Priority)]
    pub sort: SortAxis,
    /// Leave groups below this raw identifier agreement out of the text
    /// listing, saying how many were left out.
    ///
    /// A view over the same findings: nothing is recorded, no count moves,
    /// and the JSON and SARIF exports are unaffected.
    #[arg(long, value_name = "JACCARD", value_parser = parse_identifier_jaccard)]
    pub min_identifier_jaccard: Option<f64>,
    /// How much of the text report to print.
    #[command(flatten)]
    pub view: ViewArgs,
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
    /// Exit with a non-zero status if any findings are reported.
    #[arg(long)]
    pub fail_on_findings: bool,
    /// Analyse even when an identical completed run is available locally.
    #[arg(long)]
    pub no_reuse: bool,
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
    /// Only build-script is implemented by a compiler helper at present.
    /// The other class names are reserved protocol values and are rejected
    /// as unavailable rather than as a missing installation.
    ///
    /// Nothing runs without this. A flag rather than a configuration key for
    /// the same reason as `--untrusted`, and stronger: the file that would
    /// carry the setting is one the tree being scanned supplies.
    #[arg(long, value_name = "CLASS[,CLASS]")]
    pub allow_execution: Option<String>,
}

/// Arguments for the `report` subcommand.
#[allow(
    clippy::struct_excessive_bools,
    reason = "the command-line flags map directly to independently composable report views"
)]
#[derive(Debug, clap::Args)]
pub struct ReportArgs {
    /// Repository path whose configuration and local database to use.
    #[arg(long, default_value = ".")]
    pub path: PathBuf,
    /// Configuration file to use instead of the one discovered from `--path`.
    #[arg(long)]
    pub config: Option<PathBuf>,
    /// Row id of the completed scan to render again. Defaults to the latest
    /// completed scan of `--path`. Every scan format prints this id for later
    /// replay.
    #[arg(long)]
    pub run: Option<i64>,
    /// Report format.
    #[arg(long, value_enum, default_value_t = Format::Text)]
    pub format: Format,
    /// Write the report to this file instead of standard output.
    #[arg(long)]
    pub output: Option<PathBuf>,
    /// Replace an existing output file.
    #[arg(long)]
    pub force: bool,
    /// Also list suppressed groups in a text report, with the reason each was
    /// hidden. JSON and SARIF always retain suppressed findings.
    #[arg(long)]
    pub show_suppressed: bool,
    /// Also list incomplete local mirrors beneath their owning primary group.
    /// JSON and SARIF always retain sibling data.
    #[arg(long)]
    pub show_siblings: bool,
    /// Also list bounded LSH proposals that narrowly missed the primary
    /// near-match estimate gate. JSON and SARIF always retain these diagnostics.
    #[arg(long)]
    pub show_near_misses: bool,
    /// Order the report on this axis instead of the composed priority.
    #[arg(long, value_enum, default_value_t = SortAxis::Priority)]
    pub sort: SortAxis,
    /// Leave groups below this raw identifier agreement out of the text
    /// listing, saying how many were left out.
    ///
    /// A view over the same findings: nothing is recorded, no count moves,
    /// and the JSON and SARIF exports are unaffected.
    #[arg(long, value_name = "JACCARD", value_parser = parse_identifier_jaccard)]
    pub min_identifier_jaccard: Option<f64>,
    /// How much of the text report to print.
    #[command(flatten)]
    pub view: ViewArgs,
    /// Local database path, overriding the configured location.
    #[arg(long)]
    pub db: Option<PathBuf>,
    /// Treat the selected repository and its configuration as untrusted.
    ///
    /// A configured database path must remain inside `--path`; an explicit
    /// `--db` remains a deliberate operator choice.
    #[arg(long)]
    pub untrusted: bool,
}

/// Arguments for the `explain` subcommand.
#[derive(Debug, clap::Args)]
pub struct ExplainArgs {
    /// Repository path whose configuration and local database to use.
    #[arg(long, default_value = ".")]
    pub path: PathBuf,
    /// Configuration file to use instead of the one discovered from `--path`.
    #[arg(long)]
    pub config: Option<PathBuf>,
    /// Stable finding or cross-language comparison group ID to explain.
    pub finding_id: String,
    /// Output format for the detail view.
    #[arg(long, value_enum, default_value_t = DetailFormat::Text)]
    pub format: DetailFormat,
    /// Which glyphs the occurrence list draws its structure with.
    #[arg(long, value_enum, default_value_t = DecorationChoice::Auto)]
    pub decoration: DecorationChoice,
    /// Local database path, overriding the configured location.
    #[arg(long)]
    pub db: Option<PathBuf>,
    /// Treat the selected repository and its configuration as untrusted.
    ///
    /// A configured database path must remain inside `--path`; an explicit
    /// `--db` remains a deliberate operator choice.
    #[arg(long)]
    pub untrusted: bool,
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
    Create(BaselineCreateArgs),
    /// Drop the baseline entries the last scan no longer reports.
    Update(BaselineArgs),
}

/// Arguments shared by the `baseline` actions.
#[derive(Debug, clap::Args)]
pub struct BaselineArgs {
    /// Scanned path whose recorded run the baseline is taken from.
    #[arg(default_value = ".")]
    pub path: PathBuf,
    /// Configuration file to use instead of the one discovered from the scanned path.
    #[arg(long)]
    pub config: Option<PathBuf>,
    /// Baseline file to write.
    #[arg(long, default_value = BASELINE_FILE_NAME)]
    pub file: PathBuf,
    /// Local database path, overriding the configured location.
    #[arg(long)]
    pub db: Option<PathBuf>,
}

/// Arguments for `baseline create`.
#[derive(Debug, clap::Args)]
pub struct BaselineCreateArgs {
    /// Arguments shared with `baseline update`.
    #[command(flatten)]
    pub common: BaselineArgs,
    /// Overwrite an existing baseline file.
    #[arg(long)]
    pub force: bool,
}

/// Actions for the `cache` subcommand.
#[derive(Debug, Subcommand)]
pub enum CacheAction {
    /// Show the local database's location and size.
    Status {
        /// Repository path whose configuration and local database to use.
        #[arg(long, default_value = ".")]
        path: PathBuf,
        /// Configuration file to use instead of the one discovered from `--path`.
        #[arg(long)]
        config: Option<PathBuf>,
        /// Local database path, overriding the configured location.
        #[arg(long)]
        db: Option<PathBuf>,
        /// Treat the selected repository and its configuration as untrusted.
        #[arg(long)]
        untrusted: bool,
    },
    /// Apply retention limits and compact the local database.
    Prune {
        /// Repository path whose configuration and local database to use.
        #[arg(long, default_value = ".")]
        path: PathBuf,
        /// Configuration file to use instead of the one discovered from `--path`.
        #[arg(long)]
        config: Option<PathBuf>,
        /// Local database path, overriding the configured location.
        #[arg(long)]
        db: Option<PathBuf>,
        /// Treat the selected repository and its configuration as untrusted.
        #[arg(long)]
        untrusted: bool,
        /// Newest standalone artifact analyses to retain.
        #[arg(long, default_value_t = 20)]
        keep_artifacts: usize,
        /// Newest comparisons of each kind to retain.
        #[arg(long, default_value_t = 20)]
        keep_comparisons: usize,
        /// Confirm deletion of retained local audit history.
        #[arg(long)]
        force: bool,
    },
    /// Permanently delete the local database.
    Clear {
        /// Repository path whose configuration and local database to use.
        #[arg(long, default_value = ".")]
        path: PathBuf,
        /// Configuration file to use instead of the one discovered from `--path`.
        #[arg(long)]
        config: Option<PathBuf>,
        /// Local database path, overriding the configured location.
        #[arg(long)]
        db: Option<PathBuf>,
        /// Treat the selected repository and its configuration as untrusted.
        #[arg(long)]
        untrusted: bool,
        /// Confirm permanent deletion of the local audit database.
        #[arg(long)]
        force: bool,
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
    fn cli_modes_round_trip_through_the_core_mode_identity() {
        for mode in [Mode::Fast, Mode::Structural, Mode::Semantic] {
            let core = AnalysisMode::from(mode);
            assert_eq!(Mode::from(core), mode);
            assert_eq!(mode.name(), core.name());
        }
    }

    #[test]
    #[allow(clippy::expect_used)] // Parsed view state is the test subject.
    fn the_view_separates_how_much_is_said_from_how_much_is_listed() {
        let parsed = Cli::try_parse_from(["codehelion", "scan", "-vv", "--limit", "0"])
            .expect("a repeated depth flag and an explicit length parse");
        let Command::Scan(args) = parsed.command else {
            unreachable!("a scan invocation parses as a scan");
        };
        assert_eq!(args.view.verbose, 2);
        assert_eq!(args.view.limit, Some(0));
        assert!(!args.view.quiet);

        // Asking for more and for less at once names no view, so it is
        // rejected at the boundary rather than resolved by precedence.
        let error = Cli::try_parse_from(["codehelion", "scan", "-v", "-q"])
            .expect_err("depth and quiet cannot both be requested");
        assert!(error.to_string().contains("--quiet"), "{error}");
    }

    #[test]
    #[allow(clippy::expect_used)] // Parsed colour state is the test subject.
    fn colour_is_a_three_way_choice_defaulting_to_the_destination() {
        let parsed =
            Cli::try_parse_from(["codehelion", "report"]).expect("report without a colour choice");
        let Command::Report(args) = parsed.command else {
            unreachable!("a report invocation parses as a report");
        };
        assert_eq!(args.view.color, ColorChoice::Auto);
        assert!(ColorChoice::Always.enabled(false));
        assert!(!ColorChoice::Never.enabled(true));
        // A report going to a file is never a terminal, whatever this
        // process's own standard output is.
        assert!(!ColorChoice::Auto.enabled(false));
    }

    #[test]
    #[allow(clippy::expect_used)] // Parsed glyph state is the test subject.
    fn decoration_is_chosen_apart_from_colour() {
        let parsed = Cli::try_parse_from(["codehelion", "scan"])
            .expect("a scan without a decoration choice");
        let Command::Scan(args) = parsed.command else {
            unreachable!("a scan invocation parses as a scan");
        };
        assert_eq!(args.view.decoration, DecorationChoice::Auto);
        assert_eq!(DecorationChoice::Ascii.resolve(), report::Decoration::Ascii);
        assert_eq!(DecorationChoice::None.resolve(), report::Decoration::None);
        // Unlike colour, the choice does not turn on where the report is
        // going: a file gets the same glyphs the terminal would have shown.
        assert_eq!(
            DecorationChoice::Unicode.resolve(),
            report::Decoration::Unicode
        );
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
    #[allow(clippy::expect_used)] // Parsed opt-in state is the test subject.
    fn siblings_by_signature_is_a_scan_generation_flag() {
        let parsed = Cli::try_parse_from([
            "codehelion",
            "scan",
            "--mode",
            "structural",
            "--siblings-by-signature",
        ])
        .expect("the signature-sibling generation flag parses");
        assert!(matches!(
            parsed.command,
            Command::Scan(ScanArgs {
                mode: Mode::Structural,
                siblings_by_signature: true,
                ..
            })
        ));
    }

    #[test]
    #[allow(clippy::expect_used)] // Parsed flag state is the test subject.
    fn follow_links_is_opt_in_for_source_discovery() {
        let parsed = Cli::try_parse_from(["codehelion", "scan", "--follow-links"])
            .expect("the source-discovery flag parses");
        assert!(matches!(
            parsed.command,
            Command::Scan(ScanArgs {
                follow_links: true,
                ..
            })
        ));
    }

    #[test]
    #[allow(clippy::expect_used)] // Parsed path and override state are the test subject.
    fn doctor_accepts_the_same_root_and_database_overrides_as_other_local_commands() {
        let parsed = Cli::try_parse_from([
            "codehelion",
            "doctor",
            "--path",
            "fixture-repository",
            "--config",
            "fixture.toml",
            "--db",
            "fixture.db",
        ])
        .expect("doctor root and database overrides parse");
        assert!(matches!(
            parsed.command,
            Command::Doctor(DoctorArgs {
                path,
                config: Some(config),
                db: Some(db),
                ..
            }) if path == std::path::Path::new("fixture-repository")
                && config == std::path::Path::new("fixture.toml")
                && db == std::path::Path::new("fixture.db")
        ));
    }

    #[test]
    #[allow(clippy::expect_used)] // Expected parse rejection is the test subject.
    fn artifact_timeout_rejects_values_outside_the_platform_safe_range() {
        for args in [
            vec![
                "codehelion",
                "artifact",
                "analyze",
                "fixture.wasm",
                "--timeout-seconds",
                "18446744073709551615",
            ],
            vec![
                "codehelion",
                "artifact",
                "compare",
                "before.wasm",
                "after.wasm",
                "--timeout-seconds",
                "18446744073709551615",
            ],
        ] {
            let error = Cli::try_parse_from(args)
                .expect_err("an unrepresentable timeout must be rejected at the CLI boundary");
            assert!(error.to_string().contains("1..=86400"));
        }
    }

    #[test]
    #[allow(clippy::expect_used)] // Expected parse rejection is the test subject.
    fn identifier_jaccard_rejects_non_finite_and_out_of_range_values() {
        for args in [
            vec!["codehelion", "scan", "--min-identifier-jaccard", "NaN"],
            vec!["codehelion", "scan", "--min-identifier-jaccard", "inf"],
            vec!["codehelion", "scan", "--min-identifier-jaccard=-0.01"],
            vec!["codehelion", "scan", "--min-identifier-jaccard", "1.01"],
        ] {
            let error =
                Cli::try_parse_from(args).expect_err("invalid Jaccard floor must be rejected");
            assert!(error.to_string().contains("finite number in 0.0..=1.0"));
        }
        let parsed =
            Cli::try_parse_from(["codehelion", "scan", "--min-identifier-jaccard", "0.75"])
                .expect("a valid Jaccard floor parses");
        assert!(matches!(
            parsed.command,
            Command::Scan(ScanArgs {
                min_identifier_jaccard: Some(value),
                ..
            }) if (value - 0.75).abs() < f64::EPSILON
        ));
    }

    #[test]
    #[allow(clippy::expect_used)] // Expected parse rejection is the test subject.
    fn baseline_update_does_not_accept_create_only_force_flag() {
        let error = Cli::try_parse_from(["codehelion", "baseline", "update", ".", "--force"])
            .expect_err("baseline update does not overwrite an arbitrary file");
        assert!(error.to_string().contains("--force"));

        Cli::try_parse_from(["codehelion", "baseline", "create", ".", "--force"])
            .expect("baseline create retains its explicit overwrite confirmation");
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
    fn debug_file_can_be_used_without_source_correlation() {
        let parsed = Cli::try_parse_from([
            "codehelion",
            "artifact",
            "analyze",
            "fixture.so",
            "--debug-file",
            "fixture.debug",
        ])
        .expect("a debug file is valid without source correlation");
        let Command::Artifact {
            action: ArtifactAction::Analyze(args),
        } = parsed.command
        else {
            return;
        };
        assert_eq!(args.source_run, None);
        assert_eq!(args.debug_file, Some(PathBuf::from("fixture.debug")));
    }

    #[test]
    #[allow(clippy::expect_used)] // Parsed default state is the test subject.
    fn replay_commands_default_to_the_latest_recorded_item() {
        let report =
            Cli::try_parse_from(["codehelion", "report"]).expect("report without a row id parses");
        assert!(matches!(
            report.command,
            Command::Report(ReportArgs { run: None, .. })
        ));

        let artifact_report = Cli::try_parse_from(["codehelion", "artifact", "report"])
            .expect("artifact report without an id parses");
        assert!(matches!(
            artifact_report.command,
            Command::Artifact {
                action: ArtifactAction::Report(ArtifactReportArgs { analysis: None, .. })
            }
        ));

        let calibration = Cli::try_parse_from(["codehelion", "artifact", "calibration"])
            .expect("artifact calibration without a source run parses");
        assert!(matches!(
            calibration.command,
            Command::Artifact {
                action: ArtifactAction::Calibration(ArtifactCalibrationArgs {
                    source_run: None,
                    ..
                })
            }
        ));
    }

    #[test]
    #[allow(clippy::expect_used)] // Parsed architecture selections are the test subject.
    fn artifact_architecture_selection_reaches_analyze_and_compare() {
        let analyze = Cli::try_parse_from([
            "codehelion",
            "artifact",
            "analyze",
            "universal",
            "--arch",
            "aarch64",
        ])
        .expect("analysis architecture selection parses");
        assert!(matches!(
            analyze.command,
            Command::Artifact {
                action: ArtifactAction::Analyze(ArtifactArgs { arch: Some(ref arch), .. }),
            } if arch == "aarch64"
        ));

        let compare = Cli::try_parse_from([
            "codehelion",
            "artifact",
            "compare",
            "before-universal",
            "after-universal",
            "--arch",
            "x86_64",
        ])
        .expect("comparison architecture selection parses");
        assert!(matches!(
            compare.command,
            Command::Artifact {
                action: ArtifactAction::Compare(ArtifactCompareArgs { arch: Some(ref arch), .. }),
            } if arch == "x86_64"
        ));
    }

    #[test]
    #[allow(clippy::expect_used)] // Expected parse outcomes are the test subject.
    fn every_artifact_output_surface_requires_a_destination_for_force() {
        let valid = [
            vec![
                "codehelion",
                "artifact",
                "analyze",
                "fixture.wasm",
                "--output",
                "report.txt",
                "--force",
            ],
            vec![
                "codehelion",
                "artifact",
                "report",
                "--analysis",
                "1",
                "--output",
                "report.txt",
                "--force",
            ],
            vec![
                "codehelion",
                "artifact",
                "calibration",
                "--source-run",
                "1",
                "--output",
                "report.txt",
                "--force",
            ],
            vec![
                "codehelion",
                "artifact",
                "compare",
                "before.wasm",
                "after.wasm",
                "--output",
                "report.txt",
                "--force",
            ],
        ];
        for args in valid {
            Cli::try_parse_from(args).expect("artifact output with force parses");
        }

        for args in [
            vec![
                "codehelion",
                "artifact",
                "analyze",
                "fixture.wasm",
                "--force",
            ],
            vec![
                "codehelion",
                "artifact",
                "report",
                "--analysis",
                "1",
                "--force",
            ],
            vec![
                "codehelion",
                "artifact",
                "calibration",
                "--source-run",
                "1",
                "--force",
            ],
            vec![
                "codehelion",
                "artifact",
                "compare",
                "before.wasm",
                "after.wasm",
                "--force",
            ],
        ] {
            let error = Cli::try_parse_from(args).expect_err("force without output is rejected");
            assert!(error.to_string().contains("--output"));
        }
    }
}
