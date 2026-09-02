//! Argument declarations for the `scan` subcommand.

use std::path::PathBuf;

use super::{BaselineMode, Format, Mode, SortAxis, ViewArgs, parse_identifier_jaccard};

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
    #[arg(long, requires = "output")]
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
    /// Also generate sibling evidence from normalized signatures.
    ///
    /// This adds the signature channel to the similarity one, which runs
    /// whether or not this flag is given. It is separate from
    /// `--show-siblings`, which only changes text presentation. The flag is
    /// available in Structural and Semantic modes; it is off by default
    /// because signature matching is bounded by the configured sibling
    /// ceilings.
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
    ///
    /// What reuse saves is the recording half of a run; `-v` prints the two
    /// halves separately, so how much this costs is measurable rather than
    /// guessed at.
    #[arg(long)]
    pub no_reuse: bool,
    /// Read the tree under the ceilings for a repository nobody vouches for.
    ///
    /// Deliberately a flag and not a configuration key. The configuration file
    /// is discovered inside the tree being scanned, so a repository could set
    /// its own trust level — which is the one setting whose whole point is that
    /// its subject does not choose it.
    ///
    /// A configured database path must remain inside `--path`; an explicit
    /// `--db` remains a deliberate operator choice.
    ///
    /// Semantic mode additionally requires an OS-enforced helper memory
    /// ceiling, so `--untrusted --mode semantic` runs on Linux only.
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
