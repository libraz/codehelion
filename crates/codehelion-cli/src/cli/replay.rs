//! Argument declarations for the commands that re-read a recorded run:
//! `report` and `explain`.

use std::path::PathBuf;

use super::{
    ColorChoice, DecorationChoice, DetailFormat, Format, SortAxis, ViewArgs,
    parse_identifier_jaccard,
};

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
    #[arg(long, requires = "output")]
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
    /// When to colour the detail view.
    ///
    /// Spelled and defaulted like the same option on the commands that render
    /// a report: a display option a reader has learned once should not have to
    /// be looked up again for the command that shows one group.
    #[arg(long, value_enum, default_value_t = ColorChoice::Auto)]
    pub color: ColorChoice,
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
