//! Command-line interface definition, built with `clap`'s derive API.
//!
//! This module only declares the surface: the parsed [`Cli`] is handed to
//! [`crate::run`], which dispatches each [`Command`]. What a flag means to a
//! run is decided by the command that receives it; what is declared here is
//! only which flags exist and which combinations of them parse.

use std::io::IsTerminal;

use clap::{Parser, Subcommand, ValueEnum};
use codehelion_core::discovery::AnalysisMode;

use crate::report;

mod artifact;
mod maintenance;
mod replay;
mod scan;
mod seam;

pub use artifact::{
    ArtifactAction, ArtifactArgs, ArtifactCalibrationArgs, ArtifactCompareArgs, ArtifactFormat,
    ArtifactInputFormat, ArtifactIsolatedArgs, ArtifactReportArgs, DEFAULT_ARTIFACT_MAX_BYTES,
    DEFAULT_ARTIFACT_TIMEOUT_SECONDS, MAX_ARTIFACT_TIMEOUT_SECONDS, UNTRUSTED_ARTIFACT_MAX_BYTES,
    UNTRUSTED_ARTIFACT_MAX_MEMORY_BYTES, UNTRUSTED_ARTIFACT_TIMEOUT_SECONDS,
};
pub use maintenance::{
    BASELINE_FILE_NAME, BaselineAction, BaselineArgs, BaselineCreateArgs, CacheAction,
    ConfigAction, DoctorArgs,
};
pub use replay::{ExplainArgs, ReportArgs};
pub use scan::ScanArgs;
pub use seam::{GuardArgs, HistoryArgs, SeamArgs, SeamCommonArgs, SeamFormat};

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
    /// Summarise the local commit history this repository's seam metrics are
    /// computed over.
    History(HistoryArgs),
    /// Report what the seam ledger's entries have cost, or propose candidates
    /// for it.
    Seam(SeamArgs),
    /// Report a change that touched some of a seam's members and not the rest.
    Guard(GuardArgs),
}

/// Analysis mode selecting how much work the scan performs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Mode {
    /// Measures token equality and identifier/literal changes for Type-1 and
    /// Type-2 copies. It does not measure identifier agreement, similarity
    /// breakdowns, siblings or near misses, and never runs target code.
    Fast,
    /// Measures gapped Type-3 copies and duplicated statement runs, with
    /// identifier agreement, similarity breakdowns and near misses. The
    /// similarity sibling channel always runs; the signature one is opt-in
    /// with `--siblings-by-signature`. Parses sources and never runs target
    /// code.
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
    /// occurrence. Left out, a text report lists 10 groups with 5 occurrences
    /// under each; any value other than `0` changes the group count alone.
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

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{CommandFactory, Parser};
    use std::path::PathBuf;

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
    #[allow(clippy::expect_used)] // The rendered help text is the test subject.
    fn artifact_compare_help_states_what_its_database_option_actually_requires() {
        let mut command = Cli::command();
        let compare = command
            .find_subcommand_mut("artifact")
            .and_then(|artifact| artifact.find_subcommand_mut("compare"))
            .expect("artifact compare is a declared subcommand");
        let help = compare.render_long_help().to_string();
        // Rejoined on whitespace so the assertion is about the sentence rather
        // than about where the renderer chose to wrap it.
        let flowed = help.split_whitespace().collect::<Vec<_>>().join(" ");
        // The calibration pair is what the comparison cannot infer; the
        // database resolves the way it does for every other command, so the
        // help may not present it as a further thing the caller must supply.
        assert!(flowed.contains("`--db` is optional here"), "{help}");
    }

    #[test]
    #[allow(clippy::expect_used)] // Expected parse outcomes are the test subject.
    fn every_output_surface_requires_a_destination_for_force() {
        let valid = [
            vec![
                "codehelion",
                "scan",
                ".",
                "--output",
                "report.txt",
                "--force",
            ],
            vec!["codehelion", "report", "--output", "report.txt", "--force"],
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

        // A flag whose whole effect is conditioned on another one is refused
        // when the other is absent, on every command that offers it: the same
        // mistyped invocation cannot be a usage error on one surface and a
        // silent no-op on the next.
        for args in [
            vec!["codehelion", "scan", ".", "--force"],
            vec!["codehelion", "report", "--force"],
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

    #[test]
    #[allow(clippy::expect_used)] // Parsed verbose state and its rejection are the test subject.
    fn artifact_verbose_is_a_single_switch_not_a_repeatable_depth() {
        for args in [
            vec!["codehelion", "artifact", "analyze", "fixture.wasm", "-v"],
            vec!["codehelion", "artifact", "report", "--analysis", "1", "-v"],
        ] {
            let parsed = Cli::try_parse_from(args).expect("a single -v parses");
            match parsed.command {
                Command::Artifact {
                    action: ArtifactAction::Analyze(args),
                } => assert!(args.verbose),
                Command::Artifact {
                    action: ArtifactAction::Report(args),
                } => assert!(args.verbose),
                other => unreachable!("unexpected command: {other:?}"),
            }
        }

        // A second repetition offers no output the first level does not
        // already produce, so the flag no longer syntactically accepts it.
        for args in [
            vec!["codehelion", "artifact", "analyze", "fixture.wasm", "-vv"],
            vec!["codehelion", "artifact", "report", "--analysis", "1", "-vv"],
        ] {
            let error = Cli::try_parse_from(args)
                .expect_err("a repeated -v is rejected rather than silently accepted");
            assert!(error.to_string().contains("--verbose"), "{error}");
        }
    }
}
