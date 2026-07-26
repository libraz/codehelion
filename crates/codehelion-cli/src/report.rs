//! Report model and its text and JSON views.
//!
//! One [`Report`] value carries everything a scan shows: the JSON reporter
//! serializes it verbatim and the text reporter renders the same value, so
//! the two views cannot drift apart. [`FindingDetail`] plays the same role
//! for `codehelion explain`.
//!
//! # Schema versioning
//!
//! JSON reports carry a top-level `schema_version` field, currently
//! [`SCHEMA_VERSION`]. The JSON Schema document shipped with this crate
//! ([`JSON_SCHEMA`], `schema/scan-report-v1.schema.json`) describes the
//! format. A change that breaks field compatibility — renaming or removing
//! a field, or changing a field's type or meaning — must increment the
//! version and ship a new schema document; purely additive fields keep the
//! version.
//!
//! [`sarif`] renders the same value as a SARIF 2.1.0 log for static-analysis
//! consumers.

pub mod sarif;

use std::io::{self, Write};

use serde::{Deserialize, Serialize};

/// Version of the JSON report format.
pub const SCHEMA_VERSION: u32 = 1;

/// The JSON Schema document describing [`Report`]'s JSON form.
pub const JSON_SCHEMA: &str = include_str!("../schema/scan-report-v1.schema.json");

/// [`Group::scope`] value of a group whose members are runs of statements.
const SCOPE_FRAGMENT: &str = "fragment";

/// Number of groups the default (non-verbose) text report lists.
const TEXT_GROUP_LIMIT: usize = 10;

/// Number of members per group the default text report lists.
const TEXT_MEMBER_LIMIT: usize = 5;

/// A complete scan result: run metadata, summary counts and every group.
#[derive(Debug, Serialize)]
pub struct Report {
    /// JSON report format version.
    pub schema_version: u32,
    /// Metadata identifying the run that produced this report.
    pub run: RunInfo,
    /// Aggregate counts over the scan.
    pub summary: Summary,
    /// Every detected group, suppressed ones included, ordered by priority
    /// descending with the fingerprint bytes as a tie-break.
    pub groups: Vec<Group>,
}

/// Metadata identifying one scan run.
#[derive(Debug, Serialize)]
pub struct RunInfo {
    /// Version of the tool that produced the report.
    pub tool_version: String,
    /// Analysis mode the scan ran in.
    pub mode: String,
    /// Absolute path of the scanned directory.
    pub root: String,
    /// RFC 3339 UTC start time.
    pub started_at: String,
    /// RFC 3339 UTC finish time.
    pub finished_at: String,
    /// The build variant the results belong to.
    pub build_variant: BuildVariantInfo,
    /// Versions of every detection component involved.
    pub detector_versions: Vec<DetectorVersion>,
    /// Path of the audit database the snapshot was recorded in.
    pub database: String,
    /// Row id of the recorded scan run.
    pub run_id: i64,
}

/// The build variant a scan's results belong to.
#[derive(Debug, Serialize)]
pub struct BuildVariantInfo {
    /// Analysis mode component of the variant.
    pub mode: String,
    /// Languages enabled for the run.
    pub languages: Vec<String>,
    /// The language bare `.h` headers were read as, absent when the run
    /// enumerated neither C nor C++.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub headers: Option<String>,
    /// Normalization ruleset version.
    pub normalization_version: u32,
    /// Stable fingerprint of the variant.
    pub fingerprint: String,
}

/// Version of one detection component.
///
/// Readable back as well as writable: a baseline records the versions its ids
/// were computed under, and a later run has to compare against them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectorVersion {
    /// Component name, such as `fp-schema` or `frontend.rust`.
    pub component: String,
    /// Its version identifier.
    pub version: String,
}

/// Aggregate counts over one scan.
#[derive(Debug, Serialize)]
pub struct Summary {
    /// Analysed-file counts by language.
    pub files: FileCounts,
    /// Total source lines across analysed files.
    pub lines: u64,
    /// Total tokens across analysed files.
    pub tokens: u64,
    /// Lexer diagnostics emitted while reading the sources.
    pub lexer_diagnostics: u64,
    /// How much of the source the parser could not follow, in the modes that
    /// parse. Absent in Fast mode, which lexes and does not.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unparsed: Option<UnparsedCounts>,
    /// Files the scan dropped, by cause.
    pub excluded: ExcludedCounts,
    /// What moved since the previous scan of this tree, when there is one to
    /// compare against.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub changes: Option<TreeChanges>,
    /// What the baseline hid, when the scan was given one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub baseline: Option<BaselineStatus>,
    /// Clone-group counts by type.
    pub groups: GroupCounts,
    /// Suppressed-group counts by mechanism.
    pub suppressed: SuppressedCounts,
    /// Configured suppression rules that hid nothing in this run.
    ///
    /// A rule that matches nothing reads as an instruction that took effect
    /// while the findings it was meant to cover are still being reported, so
    /// it is named rather than left to be discovered by accident.
    pub unused_suppressions: Vec<UnusedRule>,
    /// How many items each stage of the candidate pipeline passed on, in run
    /// order.
    ///
    /// A scan finds duplication by narrowing: everything the sources hold
    /// goes in and a few findings come out. Without the intermediate counts a
    /// run that found nothing looks the same as a run whose filters threw the
    /// evidence away. The stage vocabulary differs between the modes, and the
    /// structural run splits after candidate extraction into whole-unit
    /// verification and sub-unit run consolidation, so the list is a record of
    /// what happened rather than a single arithmetic chain.
    pub funnel: Vec<FunnelStage>,
    /// Groups of related units too large to refine as one piece, which were
    /// cut so grouping stays bounded.
    ///
    /// Every reported group is still cohesive; what the cut costs is the
    /// chance that two members on opposite sides of it would have been
    /// reported together.
    pub split_components: u64,
    /// Whether the candidate-pair budget ran out, making results
    /// potentially incomplete.
    pub pair_budget_exhausted: bool,
}

/// One stage of the candidate pipeline.
#[derive(Debug, Serialize)]
pub struct FunnelStage {
    /// What the stage counts, as a short name.
    pub stage: String,
    /// Items the stage handed to the next one.
    pub passed: u64,
    /// Items the stage dropped, by cause. Causes that dropped nothing are
    /// left out.
    pub dropped: Vec<FunnelDrop>,
}

impl FunnelStage {
    /// A stage that passed `passed` items on and has yet to record any drop.
    #[must_use]
    pub fn new(stage: &str, passed: u64) -> Self {
        Self {
            stage: stage.to_string(),
            passed,
            dropped: Vec::new(),
        }
    }

    /// Record `count` items dropped for `cause`, ignoring a cause that
    /// dropped nothing.
    #[must_use]
    pub fn dropping(mut self, cause: &str, count: u64) -> Self {
        if count > 0 {
            self.dropped.push(FunnelDrop {
                cause: cause.to_string(),
                count,
            });
        }
        self
    }
}

/// Items one stage dropped for a single reason.
#[derive(Debug, Serialize)]
pub struct FunnelDrop {
    /// Why the items were dropped, as a `snake_case` cause.
    pub cause: String,
    /// How many were dropped.
    pub count: u64,
}

impl FunnelDrop {
    /// The cause as it reads in the text views.
    #[must_use]
    pub fn label(&self) -> String {
        self.cause.replace('_', " ")
    }
}

/// One configured suppression rule that matched nothing.
#[derive(Debug, Serialize)]
pub struct UnusedRule {
    /// Rule scope (`path_glob`, `symbol_pattern`, `stable_clone_id`).
    pub scope: String,
    /// The pattern as configured.
    pub pattern: String,
}

impl UnusedRule {
    /// One-line rendering for the text views, matching how a rule that *did*
    /// match is named.
    #[must_use]
    pub fn label(&self) -> String {
        match self.scope.as_str() {
            "path_glob" => format!("path glob {:?}", self.pattern),
            "symbol_pattern" => format!("symbol glob {:?}", self.pattern),
            "stable_clone_id" => format!("clone id {}", self.pattern),
            scope => format!("{scope} {:?}", self.pattern),
        }
    }
}

/// Analysed-file counts by language.
#[derive(Debug, Serialize)]
pub struct FileCounts {
    /// All analysed files.
    pub total: u64,
    /// Rust files.
    pub rust: u64,
    /// C files.
    pub c: u64,
    /// C++ files.
    pub cpp: u64,
}

/// What moved in the tree since the previous scan of it.
///
/// Absent when there is no run to compare against: the first scan of a tree,
/// a scan under settings nothing has been scanned under before, or a database
/// written before runs recorded the files they read. Absent means "not
/// comparable", never "nothing changed".
#[derive(Debug, Clone, Copy, Serialize)]
pub struct TreeChanges {
    /// Row id of the run this is measured against.
    pub since_run_id: i64,
    /// Files present in both scans, hashing the same.
    pub unchanged: u64,
    /// Files present in both scans, hashing differently.
    pub modified: u64,
    /// Files this scan read and the previous one did not.
    pub added: u64,
    /// Files the previous scan read and this one did not.
    pub removed: u64,
}

/// What a baseline did to this run's findings.
///
/// An entry that matched nothing is reported rather than left implicit, and
/// it is deliberately not phrased as a problem: a baseline going stale is a
/// duplication that got fixed. The number is what tells the reader that
/// `baseline update` has something to drop.
///
/// `mismatch` is the other case entirely — the baseline is intact but was
/// recorded under conditions that give every id a different value, so it
/// covers nothing at all. That is stated outright, because a suppression
/// silently covering nothing looks exactly like one that worked.
#[derive(Debug, Clone, Serialize)]
pub struct BaselineStatus {
    /// The baseline file, as it was given on the command line.
    pub file: String,
    /// Entries the file holds.
    pub entries: u64,
    /// Entries that hid a finding in this run.
    pub matched: u64,
    /// Entries that hid nothing, the duplication they covered being gone.
    pub stale: u64,
    /// Why the baseline does not describe this run, when it does not.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mismatch: Option<String>,
}

/// Files the scan dropped, by cause. Nothing is omitted silently.
#[derive(Debug, Serialize)]
pub struct ExcludedCounts {
    /// Files excluded for carrying a generated-code marker.
    pub generated: u64,
    /// Files excluded by the configured include/exclude globs.
    pub by_glob: u64,
    /// Files skipped for other causes (size, binary content, read errors).
    pub skipped: u64,
}

/// How much of the source the parser could not follow.
///
/// A parser that recovers keeps going, so a file it could not follow still
/// produces units and still reaches detection — the difference is that those
/// units describe error recovery rather than the code. Without this the two
/// are indistinguishable in a report: a scan that read a tenth of a project
/// looks exactly like a scan that read all of it and found little.
///
/// The measure is tokens rather than bytes, and it excludes what recovery
/// salvaged. Recovery routinely opens one error region around far more than
/// the construct that caused it, so the region's extent is not a measure of
/// anything; see [`SyntaxIrFile::unaccounted_tokens`].
///
/// [`SyntaxIrFile::unaccounted_tokens`]: codehelion_core::ir::SyntaxIrFile::unaccounted_tokens
#[derive(Debug, Serialize)]
pub struct UnparsedCounts {
    /// Files holding at least one token the parser could not attach to any
    /// structure.
    pub files: u64,
    /// How many such tokens there are.
    pub tokens: u64,
    /// Those tokens as a share of every analysed token, rounded to four
    /// places.
    pub share: f64,
}

impl UnparsedCounts {
    /// Tally the unaccounted tokens `per_file` against `total` analysed
    /// tokens.
    #[must_use]
    pub fn new(per_file: impl IntoIterator<Item = u64>, total: u64) -> Self {
        let mut files = 0;
        let mut unparsed = 0;
        for tokens in per_file {
            if tokens > 0 {
                files += 1;
                unparsed += tokens;
            }
        }
        // Ratios of counts this size lose nothing that a report shows.
        #[allow(clippy::cast_precision_loss)]
        let share = if total == 0 {
            0.0
        } else {
            ((unparsed as f64 / total as f64) * 10_000.0).round() / 10_000.0
        };
        Self {
            files,
            tokens: unparsed,
            share,
        }
    }
}

/// Clone-group counts by type.
#[derive(Debug, Serialize)]
pub struct GroupCounts {
    /// All groups.
    pub total: u64,
    /// Verbatim (Type-1) groups.
    pub type_1: u64,
    /// Renamed (Type-2) groups.
    pub type_2: u64,
    /// Gapped (Type-3) groups. Always zero in modes that report no gapped
    /// clones.
    pub type_3: u64,
    /// How many of the total describe a duplicated run inside units that are
    /// not clones of each other, rather than whole duplicated units. Always
    /// zero in modes that only compare whole units.
    pub fragment_scope: u64,
    /// Duplicated runs left out of the listing because a reported whole-unit
    /// group already covers them — the same duplication described twice.
    /// Reported so the fold is visible rather than silent.
    pub folded_runs: u64,
    /// Duplicated runs left out because a longer run covers every one of
    /// their occurrences and claims at least as much about them.
    pub subsumed_runs: u64,
    /// How many of the total live wholly in a test suite. Always zero in modes
    /// that cannot read the marker.
    pub test_code: u64,
}

/// Suppressed-group counts by mechanism.
#[derive(Debug, Serialize)]
pub struct SuppressedCounts {
    /// Groups the engine marked as noise.
    pub noise: u64,
    /// Groups hidden by a configured or inline suppression rule.
    pub by_rule: u64,
}

/// One clone group.
#[derive(Debug, Serialize)]
pub struct Group {
    /// Stable clone-group fingerprint, hex-encoded.
    pub fingerprint: String,
    /// Clone classification (`type-1`, `type-2`, `type-3`).
    pub clone_type: String,
    /// What each member is: `unit` for a whole duplicated unit, `fragment`
    /// for a run of statements duplicated inside units that need not be
    /// clones of each other.
    ///
    /// The two answer different questions about the same code, so a reader
    /// has to be able to tell them apart. They share one ranking because they
    /// compete for the same attention.
    pub scope: String,
    /// Statements each member covers, for fragment-scope groups; `None` for
    /// unit-scope groups, whose extent is the unit itself.
    pub statements: Option<u64>,
    /// Minimum pairwise similarity across the group.
    pub confidence: f64,
    /// Ranking value with the inputs it was computed from.
    pub priority: Priority,
    /// Per-dimension similarity evidence, when the mode measured it; `None`
    /// in modes that match content exactly and score no dimensions.
    pub similarity: Option<Similarity>,
    /// The boilerplate shape every member matches, when they all match one
    /// (`trivial-body`, `forwarding`, `macro-repetition`). What the report
    /// does with such a group is configured per category; the classification
    /// is stated either way.
    pub boilerplate: Option<String>,
    /// Whether every member is test code, recognised from the test marker in
    /// the source. A group spanning a suite and the code it exercises is not
    /// test code: that duplication crosses the boundary, which is the case
    /// worth reading.
    pub test_code: bool,
    /// Whether this is a pair reported on its own because no group could hold
    /// both its members.
    ///
    /// A group asserts that every member is a copy of every other; being a
    /// copy is not transitive, so a unit can be a copy of two units that are
    /// not copies of each other, and only one of those relations fits in a
    /// group. Such a pair is reported as its own two-member finding, which
    /// means its members also appear elsewhere: these are the only findings
    /// that overlap.
    pub split_pair: bool,
    /// Why the group is hidden from default reports; `None` when visible.
    pub suppressed: Option<Suppression>,
    /// Every occurrence, the canonical instance first.
    pub members: Vec<Member>,
}

/// A group's similarity evidence, one measured dimension per field.
///
/// Every dimension stays visible: the composite never replaces the
/// breakdown. An unavailable dimension is `None` — reported as absent, not
/// as a guessed number.
#[derive(Debug, Serialize)]
pub struct Similarity {
    /// The composite-weight recipe version the group was scored under.
    pub weight_version: String,
    /// Verbatim agreement of aligned statements' leading tokens.
    pub lexical: f64,
    /// Rename-invariant structural agreement.
    pub structural: f64,
    /// Control-flow-profile agreement.
    pub control_flow: f64,
    /// Type agreement, or `None` when types are unavailable.
    pub type_similarity: Option<f64>,
    /// Call-name multiset agreement, or `None` when neither unit calls
    /// anything and there is nothing to compare.
    pub api: Option<f64>,
    /// Weighted mean of the measured dimensions.
    pub composite: f64,
    /// Weakest pairwise similarity inside the group: its cohesion.
    pub min_pairwise: f64,
    /// Confidence band of the classification (`high`, `medium`, `low`).
    ///
    /// A scan always reports one. It is `None` only when the evidence comes
    /// from a stored run recorded before the band was persisted: a band is a
    /// judgement, so an unrecorded one is reported as absent rather than
    /// re-derived from the numbers.
    pub confidence_band: Option<String>,
}

/// A group's ranking value together with its inputs. The collapsed number
/// never replaces the inputs in any view.
#[derive(Debug, Serialize)]
pub struct Priority {
    /// `largest_member_tokens × extra_instances × similarity`.
    pub value: f64,
    /// Token count of the group's largest member.
    pub largest_member_tokens: u64,
    /// Number of instances beyond the first.
    pub extra_instances: u64,
    /// Minimum pairwise similarity across the group.
    pub similarity: f64,
}

/// Which mechanism suppressed a group.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SuppressionKind {
    /// The engine marked the group as noise.
    Noise,
    /// A configured or inline suppression rule matched every member.
    Rule,
}

/// Why a group is hidden from default reports.
#[derive(Debug, Serialize)]
pub struct Suppression {
    /// The suppressing mechanism.
    pub kind: SuppressionKind,
    /// Engine noise category, present when `kind` is noise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Suppression-rule scope, present when `kind` is rule.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// Suppression-rule pattern, present when `kind` is rule.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,
}

impl Suppression {
    /// Human-readable label for the text views.
    #[must_use]
    pub fn label(&self) -> String {
        match self.kind {
            SuppressionKind::Noise => {
                format!("{} noise", self.reason.as_deref().unwrap_or("engine"))
            }
            SuppressionKind::Rule => {
                let pattern = self.pattern.as_deref().unwrap_or("");
                match self.scope.as_deref() {
                    Some("path_glob") => format!("path glob {pattern:?}"),
                    Some("symbol_pattern") => format!("symbol glob {pattern:?}"),
                    Some("stable_clone_id") => format!("clone id {pattern}"),
                    Some("inline_comment") => format!("{pattern} marker"),
                    Some("ast_pattern") => format!("boilerplate: {pattern}"),
                    Some("attribute") => format!("{pattern} attribute"),
                    Some(scope) => format!("{scope} {pattern:?}"),
                    None => "rule".to_string(),
                }
            }
        }
    }
}

impl Similarity {
    /// One-line rendering of the breakdown for the text views. An unavailable
    /// dimension prints as `n/a`, never as a number.
    #[must_use]
    pub fn line(&self) -> String {
        let type_similarity = self
            .type_similarity
            .map_or_else(|| "n/a".to_string(), |value| format!("{value:.2}"));
        let api = self
            .api
            .map_or_else(|| "n/a".to_string(), |value| format!("{value:.2}"));
        let band = self.confidence_band.as_deref().unwrap_or("n/a");
        format!(
            "similarity: composite {:.2} (lexical {:.2}, structural {:.2}, \
             control-flow {:.2}, type {type_similarity}, api {api}); \
             cohesion {:.2}; confidence {band} [{}]",
            self.composite,
            self.lexical,
            self.structural,
            self.control_flow,
            self.min_pairwise,
            self.weight_version,
        )
    }
}

/// One occurrence of a group's content.
#[derive(Debug, Serialize)]
pub struct Member {
    /// Stable per-occurrence finding identifier, hex-encoded.
    pub finding_id: String,
    /// File path relative to the scan root.
    pub file: String,
    /// 1-based first line.
    pub start_line: u32,
    /// 1-based last line.
    pub end_line: u32,
    /// Name of the enclosing unit, when anchored to one.
    pub unit: Option<String>,
    /// Size in tokens.
    pub tokens: u64,
    /// Whether this is the group's canonical instance.
    pub canonical: bool,
}

/// Rendering options for the text view of a [`Report`].
#[derive(Debug, Clone, Copy, Default)]
pub struct TextOptions {
    /// List every group and every member instead of the summarised excerpt.
    pub verbose: bool,
    /// Emit ANSI colour codes.
    pub color: bool,
    /// Also list suppressed groups, with the reason each was hidden.
    pub show_suppressed: bool,
}

/// Minimal ANSI styling, disabled when the output is not a terminal.
struct Palette {
    enabled: bool,
}

impl Palette {
    fn paint(&self, code: &str, text: &str) -> String {
        if self.enabled {
            format!("\x1b[{code}m{text}\x1b[0m")
        } else {
            text.to_string()
        }
    }

    fn bold(&self, text: &str) -> String {
        self.paint("1", text)
    }

    fn cyan(&self, text: &str) -> String {
        self.paint("36", text)
    }

    fn yellow(&self, text: &str) -> String {
        self.paint("33", text)
    }
}

impl Report {
    /// The report as pretty-printed JSON, newline-terminated.
    ///
    /// # Errors
    ///
    /// Returns an error when serialization fails.
    pub fn to_json(&self) -> serde_json::Result<String> {
        let mut text = serde_json::to_string_pretty(self)?;
        text.push('\n');
        Ok(text)
    }

    /// Render the human-readable text view.
    ///
    /// # Errors
    ///
    /// Returns any error from the writer.
    pub fn render_text(&self, opts: TextOptions, out: &mut impl Write) -> io::Result<()> {
        let palette = Palette {
            enabled: opts.color,
        };
        self.render_summary(&palette, out)?;
        if opts.verbose {
            self.render_funnel(&palette, out)?;
        }
        self.render_groups(opts, &palette, out)
    }

    /// The stage-by-stage pass counts, wide enough to be read as a column.
    fn render_funnel(&self, palette: &Palette, out: &mut impl Write) -> io::Result<()> {
        if self.summary.funnel.is_empty() {
            return Ok(());
        }
        let width = self
            .summary
            .funnel
            .iter()
            .map(|stage| stage.stage.len())
            .max()
            .unwrap_or(0);
        writeln!(out)?;
        writeln!(out, "{}", palette.bold("candidate pipeline:"))?;
        for stage in &self.summary.funnel {
            write!(out, "  {:width$}  {}", stage.stage, stage.passed)?;
            if !stage.dropped.is_empty() {
                let causes: Vec<String> = stage
                    .dropped
                    .iter()
                    .map(|drop| format!("{} {}", drop.label(), drop.count))
                    .collect();
                write!(out, "  (dropped: {})", causes.join(", "))?;
            }
            writeln!(out)?;
        }
        Ok(())
    }

    /// What the scan read: how much, what was left out, and what moved since
    /// the last time. Everything here is about the input, before a single
    /// group is mentioned.
    fn render_inputs(&self, out: &mut impl Write) -> io::Result<()> {
        let summary = &self.summary;
        writeln!(
            out,
            "  files: {} analysed (rust {}, c {}, cpp {})",
            summary.files.total, summary.files.rust, summary.files.c, summary.files.cpp,
        )?;
        // Which grammar read the bare `.h` headers decides what the analysis
        // could see in them, so a run that read any says so rather than
        // leaving the reader to infer it from the language counts.
        if summary.files.c + summary.files.cpp > 0
            && let Some(headers) = &self.run.build_variant.headers
        {
            writeln!(out, "    bare .h headers read as {headers}")?;
        }
        writeln!(
            out,
            "  excluded: {} generated, {} by glob, {} skipped",
            summary.excluded.generated, summary.excluded.by_glob, summary.excluded.skipped,
        )?;
        writeln!(
            out,
            "  lines: {}; tokens: {}; lexer diagnostics: {}",
            summary.lines, summary.tokens, summary.lexer_diagnostics,
        )?;
        // Said only when there is a run to say it against. A first scan
        // reports nothing here rather than calling every file new, which
        // would read as a tree that had just been written from scratch.
        if let Some(changes) = &summary.changes {
            writeln!(
                out,
                "  since run {}: {} unchanged, {} modified, {} added, {} removed",
                changes.since_run_id,
                changes.unchanged,
                changes.modified,
                changes.added,
                changes.removed,
            )?;
        }
        if let Some(baseline) = &summary.baseline {
            writeln!(
                out,
                "  baseline {}: {} of {} entries matched, {} no longer found",
                baseline.file, baseline.matched, baseline.entries, baseline.stale,
            )?;
            // A baseline that covers nothing hides nothing, and that is
            // indistinguishable from a baseline that worked unless it is said.
            if let Some(reason) = &baseline.mismatch {
                writeln!(out, "    warning: this baseline hid nothing — {reason}")?;
            }
        }
        Ok(())
    }

    fn render_summary(&self, palette: &Palette, out: &mut impl Write) -> io::Result<()> {
        let summary = &self.summary;
        writeln!(
            out,
            "{}",
            palette.bold(&format!("codehelion scan ({} mode)", self.run.mode))
        )?;
        writeln!(out, "  root: {}", self.run.root)?;
        self.render_inputs(out)?;
        // A recovering parser reports no failure, so the share it could not
        // follow is the only thing separating "little duplication here" from
        // "most of this was never read".
        if let Some(unparsed) = &summary.unparsed
            && unparsed.files > 0
        {
            writeln!(
                out,
                "    the parser could not follow {:.2}% of the tokens, over {} of {} files",
                unparsed.share * 100.0,
                unparsed.files,
                summary.files.total,
            )?;
        }
        writeln!(
            out,
            "  clone groups: {} (type-1 {}, type-2 {}, type-3 {}; suppressed: {} noise, {} by rule)",
            summary.groups.total,
            summary.groups.type_1,
            summary.groups.type_2,
            summary.groups.type_3,
            summary.suppressed.noise,
            summary.suppressed.by_rule,
        )?;
        let runs = &summary.groups;
        if runs.fragment_scope > 0 || runs.folded_runs > 0 || runs.subsumed_runs > 0 {
            writeln!(
                out,
                "    {} of them are runs duplicated inside units that are not clones of each \
                 other; {} more were folded into the groups that already cover them and {} \
                 into longer runs",
                runs.fragment_scope, runs.folded_runs, runs.subsumed_runs,
            )?;
        }
        if summary.groups.test_code > 0 {
            writeln!(
                out,
                "    {} of them are duplication inside test code, which repeats itself by \
                 design; a group spanning a test and what it exercises is not counted here",
                summary.groups.test_code,
            )?;
        }
        writeln!(
            out,
            "  snapshot: run {} in {}",
            self.run.run_id, self.run.database
        )?;
        if !summary.unused_suppressions.is_empty() {
            let names: Vec<String> = summary
                .unused_suppressions
                .iter()
                .map(UnusedRule::label)
                .collect();
            writeln!(
                out,
                "  note: {} suppression rule(s) matched nothing: {}",
                summary.unused_suppressions.len(),
                names.join(", "),
            )?;
        }
        if summary.split_components > 0 {
            writeln!(
                out,
                "  note: {} set(s) of related units were too large to compare as one and were \
                 cut; clones of each other may be reported as separate groups",
                summary.split_components,
            )?;
        }
        if summary.pair_budget_exhausted {
            writeln!(
                out,
                "  note: the candidate-pair budget was exhausted; results may be incomplete"
            )?;
        }
        Ok(())
    }

    fn render_groups(
        &self,
        opts: TextOptions,
        palette: &Palette,
        out: &mut impl Write,
    ) -> io::Result<()> {
        let visible: Vec<&Group> = self
            .groups
            .iter()
            .filter(|group| group.suppressed.is_none())
            .collect();
        if !visible.is_empty() {
            let limit = if opts.verbose {
                visible.len()
            } else {
                TEXT_GROUP_LIMIT
            };
            writeln!(out)?;
            writeln!(out, "{}", palette.bold("top groups by priority:"))?;
            for group in visible.iter().take(limit) {
                render_group(group, opts, palette, out)?;
            }
            if visible.len() > limit {
                writeln!(out, "  ... and {} more groups", visible.len() - limit)?;
            }
        }

        if opts.show_suppressed {
            let suppressed: Vec<&Group> = self
                .groups
                .iter()
                .filter(|group| group.suppressed.is_some())
                .collect();
            if !suppressed.is_empty() {
                writeln!(out)?;
                writeln!(out, "{}", palette.bold("suppressed groups:"))?;
                for group in &suppressed {
                    render_group(group, opts, palette, out)?;
                }
            }
        }
        Ok(())
    }
}

/// Render one group: the priority with its inputs spelled out, then its
/// members. The non-verbose view truncates long member lists with an
/// explicit count, never silently.
fn render_group(
    group: &Group,
    opts: TextOptions,
    palette: &Palette,
    out: &mut impl Write,
) -> io::Result<()> {
    // A group that is shown but ranked down says why: its place in the
    // ranking is explained rather than silently lowered.
    let marker = match (&group.suppressed, &group.boilerplate, group.test_code) {
        (Some(cause), _, _) => format!(
            " {}",
            palette.yellow(&format!("[suppressed: {}]", cause.label()))
        ),
        (None, Some(category), _) => {
            format!(" {}", palette.yellow(&format!("[boilerplate: {category}]")))
        }
        (None, None, true) => format!(" {}", palette.yellow("[test code]")),
        (None, None, false) => String::new(),
    };
    // A pair reported on its own is the one kind of finding whose members
    // turn up in other findings too. Saying so is what stops it reading as a
    // second, contradictory account of the same code.
    let overlap = if group.split_pair {
        format!(" {}", palette.yellow("[pair no group holds]"))
    } else {
        String::new()
    };
    // A fragment-scope group states its extent: without it "type-1, 40
    // tokens" reads as a duplicated unit, which it is not.
    let scope = match (group.scope.as_str(), group.statements) {
        (SCOPE_FRAGMENT, Some(statements)) => format!(" run of {statements} statements"),
        (SCOPE_FRAGMENT, None) => " run".to_string(),
        _ => String::new(),
    };
    writeln!(
        out,
        "  {} {}{scope} priority {:.1} ({} tokens x {} extra x {:.2} similarity){overlap}{marker}",
        palette.cyan(&group.fingerprint),
        group.clone_type,
        group.priority.value,
        group.priority.largest_member_tokens,
        group.priority.extra_instances,
        group.priority.similarity,
    )?;
    if let Some(similarity) = &group.similarity {
        writeln!(out, "    {}", similarity.line())?;
    }
    let limit = if opts.verbose {
        group.members.len()
    } else {
        TEXT_MEMBER_LIMIT
    };
    for member in group.members.iter().take(limit) {
        let unit = member
            .unit
            .as_deref()
            .map_or_else(String::new, |name| format!(" ({name})"));
        let canonical = if member.canonical { " [canonical]" } else { "" };
        writeln!(
            out,
            "    {}:{}-{}{unit}{canonical}",
            member.file, member.start_line, member.end_line,
        )?;
    }
    if group.members.len() > limit {
        writeln!(
            out,
            "    ... and {} more occurrences",
            group.members.len() - limit
        )?;
    }
    Ok(())
}

/// The detail view of one occurrence, shared by `codehelion explain`'s text
/// and JSON output.
#[derive(Debug, Serialize)]
pub struct FindingDetail {
    /// The occurrence itself, in the same shape as a report member.
    #[serde(flatten)]
    pub member: Member,
    /// The owning group.
    pub group: GroupRef,
    /// Row id of the scan run the occurrence belongs to.
    pub scan_run: i64,
}

/// A reference to an occurrence's owning group, carrying the evidence that
/// made it a finding rather than its identity alone.
#[derive(Debug, Serialize)]
pub struct GroupRef {
    /// Stable clone-group fingerprint, hex-encoded.
    pub fingerprint: String,
    /// Clone classification (`type-1`, `type-2`, `type-3`).
    pub clone_type: String,
    /// What each member is (`unit` or `fragment`), as recorded with the run.
    pub scope: String,
    /// Minimum pairwise similarity across the group.
    pub confidence: f64,
    /// Number of occurrences in the group, this one included.
    pub members: u64,
    /// The boilerplate shape every member matches, when they all match one.
    pub boilerplate: Option<String>,
    /// Whether every member of the group is test code, as recorded with the
    /// run.
    pub test_code: bool,
    /// Whether the group is a verified pair no larger group could hold, as
    /// recorded with the run.
    pub split_pair: bool,
    /// Per-dimension evidence, absent when the mode measured none (Fast).
    pub similarity: Option<Similarity>,
    /// The rule that suppressed the group in the recorded run, if one
    /// matched. A suppressed finding is still recorded and still explainable.
    pub suppressed: Option<Suppression>,
}

impl FindingDetail {
    /// The detail as pretty-printed JSON, newline-terminated.
    ///
    /// # Errors
    ///
    /// Returns an error when serialization fails.
    pub fn to_json(&self) -> serde_json::Result<String> {
        let mut text = serde_json::to_string_pretty(self)?;
        text.push('\n');
        Ok(text)
    }

    /// Render the human-readable text view.
    ///
    /// # Errors
    ///
    /// Returns any error from the writer.
    pub fn render_text(&self, out: &mut impl Write) -> io::Result<()> {
        writeln!(out, "finding {}", self.member.finding_id)?;
        writeln!(
            out,
            "  location: {}:{}-{}",
            self.member.file, self.member.start_line, self.member.end_line,
        )?;
        if let Some(name) = &self.member.unit {
            writeln!(out, "  unit: {name}")?;
        }
        writeln!(out, "  tokens: {}", self.member.tokens)?;
        writeln!(
            out,
            "  canonical: {}",
            if self.member.canonical { "yes" } else { "no" }
        )?;
        // Which of the two the occurrence is decides how to read its span:
        // the whole unit is the clone, or a run inside it is.
        let scope = if self.group.scope == SCOPE_FRAGMENT {
            "duplicated run"
        } else {
            "duplicated unit"
        };
        writeln!(
            out,
            "  group: {} ({scope}, {}, score {:.2}, {} instances)",
            self.group.fingerprint,
            self.group.clone_type,
            self.group.confidence,
            self.group.members,
        )?;
        if let Some(similarity) = &self.group.similarity {
            writeln!(out, "    {}", similarity.line())?;
        }
        if let Some(category) = &self.group.boilerplate {
            writeln!(out, "  boilerplate: {category}")?;
        }
        if self.group.split_pair {
            writeln!(
                out,
                "  pair: reported on its own, because no group holds both its members"
            )?;
        }
        if self.group.test_code {
            writeln!(out, "  test code: every occurrence is inside a test")?;
        }
        if let Some(cause) = &self.group.suppressed {
            writeln!(out, "  suppressed: {}", cause.label())?;
        }
        writeln!(out, "  scan run: {}", self.scan_run)?;
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
pub(super) mod tests {
    use super::*;

    /// A two-group report whose second group is hidden by a path rule; shared
    /// with the sibling reporter tests.
    pub(super) fn sample_report() -> Report {
        Report {
            schema_version: SCHEMA_VERSION,
            run: RunInfo {
                tool_version: "0.1.0".to_string(),
                mode: "fast".to_string(),
                root: "/work/project".to_string(),
                started_at: "2026-01-01T00:00:00.000000Z".to_string(),
                finished_at: "2026-01-01T00:00:01.000000Z".to_string(),
                build_variant: BuildVariantInfo {
                    mode: "fast".to_string(),
                    languages: vec!["rust".to_string()],
                    headers: Some("c".to_string()),
                    normalization_version: 2,
                    fingerprint: "aa".repeat(32),
                },
                detector_versions: vec![DetectorVersion {
                    component: "fp-schema".to_string(),
                    version: "1".to_string(),
                }],
                database: ".codehelion/audit.db".to_string(),
                run_id: 1,
            },
            summary: Summary {
                files: FileCounts {
                    total: 2,
                    rust: 2,
                    c: 0,
                    cpp: 0,
                },
                lines: 40,
                tokens: 200,
                lexer_diagnostics: 0,
                unparsed: None,
                excluded: ExcludedCounts {
                    generated: 0,
                    by_glob: 0,
                    skipped: 0,
                },
                changes: None,
                baseline: None,
                groups: GroupCounts {
                    total: 2,
                    type_1: 2,
                    type_2: 0,
                    type_3: 0,
                    fragment_scope: 0,
                    folded_runs: 0,
                    subsumed_runs: 0,
                    test_code: 0,
                },
                suppressed: SuppressedCounts {
                    noise: 0,
                    by_rule: 1,
                },
                unused_suppressions: Vec::new(),
                funnel: vec![
                    FunnelStage::new("tokens", 200),
                    FunnelStage::new("fingerprints", 64)
                        .dropping("high_frequency", 3)
                        .dropping("hash_collision", 0),
                    FunnelStage::new("verified pairs", 2),
                ],
                split_components: 0,
                pair_budget_exhausted: false,
            },
            groups: vec![visible_group(), suppressed_group()],
        }
    }

    /// A plain visible group: the highest-priority entry of the sample report.
    fn visible_group() -> Group {
        Group {
            fingerprint: "0b".repeat(16),
            clone_type: "type-1".to_string(),
            scope: "unit".to_string(),
            statements: None,
            confidence: 1.0,
            priority: Priority {
                value: 80.0,
                largest_member_tokens: 80,
                extra_instances: 1,
                similarity: 1.0,
            },
            similarity: None,
            boilerplate: None,
            test_code: false,
            suppressed: None,
            split_pair: false,
            members: (0..7)
                .map(|index| Member {
                    finding_id: format!("{index:032x}"),
                    file: format!("src/file{index}.rs"),
                    start_line: 1,
                    end_line: 9,
                    unit: Some("checksum".to_string()),
                    tokens: 80,
                    canonical: index == 0,
                })
                .collect(),
        }
    }

    /// A group a path rule hid, kept in the report rather than dropped.
    fn suppressed_group() -> Group {
        Group {
            fingerprint: "0c".repeat(16),
            clone_type: "type-1".to_string(),
            scope: "unit".to_string(),
            statements: None,
            confidence: 1.0,
            priority: Priority {
                value: 30.0,
                largest_member_tokens: 30,
                extra_instances: 1,
                similarity: 1.0,
            },
            similarity: None,
            boilerplate: None,
            test_code: false,
            suppressed: Some(Suppression {
                kind: SuppressionKind::Rule,
                reason: None,
                scope: Some("path_glob".to_string()),
                pattern: Some("vendor/**".to_string()),
            }),
            split_pair: false,
            members: vec![
                Member {
                    finding_id: "1".repeat(32),
                    file: "vendor/a.rs".to_string(),
                    start_line: 1,
                    end_line: 5,
                    unit: None,
                    tokens: 30,
                    canonical: true,
                },
                Member {
                    finding_id: "2".repeat(32),
                    file: "vendor/b.rs".to_string(),
                    start_line: 1,
                    end_line: 5,
                    unit: None,
                    tokens: 30,
                    canonical: false,
                },
            ],
        }
    }

    /// A gapped group as a mode that scores dimensions reports it: a
    /// similarity breakdown whose type dimension was never measured.
    pub(super) fn structural_group() -> Group {
        Group {
            fingerprint: "0d".repeat(16),
            clone_type: "type-3".to_string(),
            scope: "unit".to_string(),
            statements: None,
            confidence: 0.79,
            priority: Priority {
                value: 47.4,
                largest_member_tokens: 60,
                extra_instances: 1,
                similarity: 0.79,
            },
            similarity: Some(Similarity {
                weight_version: "structural-verify-v4".to_string(),
                lexical: 0.71,
                structural: 0.88,
                control_flow: 0.90,
                type_similarity: None,
                api: Some(0.75),
                composite: 0.82,
                min_pairwise: 0.79,
                confidence_band: Some("medium".to_string()),
            }),
            boilerplate: None,
            test_code: false,
            suppressed: None,
            split_pair: false,
            members: vec![
                Member {
                    finding_id: "3".repeat(32),
                    file: "src/parse.rs".to_string(),
                    start_line: 10,
                    end_line: 30,
                    unit: Some("parse_header".to_string()),
                    tokens: 60,
                    canonical: true,
                },
                Member {
                    finding_id: "4".repeat(32),
                    file: "src/parse.rs".to_string(),
                    start_line: 40,
                    end_line: 62,
                    unit: Some("parse_trailer".to_string()),
                    tokens: 58,
                    canonical: false,
                },
            ],
        }
    }

    /// A run duplicated inside two units that are not clones of each other:
    /// the members are stretches of their hosts, not the hosts.
    pub(super) fn fragment_group() -> Group {
        Group {
            fingerprint: "0e".repeat(16),
            clone_type: "type-1".to_string(),
            scope: SCOPE_FRAGMENT.to_string(),
            statements: Some(5),
            confidence: 1.0,
            priority: Priority {
                value: 39.0,
                largest_member_tokens: 39,
                extra_instances: 1,
                similarity: 1.0,
            },
            similarity: None,
            boilerplate: None,
            test_code: false,
            suppressed: None,
            split_pair: false,
            members: vec![
                Member {
                    finding_id: "5".repeat(32),
                    file: "src/render.rs".to_string(),
                    start_line: 17,
                    end_line: 21,
                    unit: Some("render_rows".to_string()),
                    tokens: 39,
                    canonical: true,
                },
                Member {
                    finding_id: "6".repeat(32),
                    file: "src/audit.rs".to_string(),
                    start_line: 11,
                    end_line: 15,
                    unit: Some("audit_entries".to_string()),
                    tokens: 39,
                    canonical: false,
                },
            ],
        }
    }

    #[test]
    fn a_duplicated_run_states_its_extent_in_every_view() {
        let mut report = sample_report();
        report.summary.groups.total = 3;
        report.summary.groups.fragment_scope = 1;
        report.summary.groups.folded_runs = 4;
        report.summary.groups.subsumed_runs = 2;
        report.groups.insert(0, fragment_group());

        let value: serde_json::Value = serde_json::from_str(&report.to_json().unwrap()).unwrap();
        let group = &value["groups"][0];
        assert_eq!(group["scope"], "fragment");
        assert_eq!(group["statements"], 5);
        // A whole-unit group says so, and says it has no such extent.
        assert_eq!(value["groups"][1]["scope"], "unit");
        assert_eq!(value["groups"][1]["statements"], serde_json::Value::Null);

        let mut buffer = Vec::new();
        report
            .render_text(TextOptions::default(), &mut buffer)
            .unwrap();
        let text = String::from_utf8(buffer).unwrap();
        assert!(text.contains("type-1 run of 5 statements priority 39.0"));
        // What was folded away is stated rather than silently dropped.
        assert!(text.contains(
            "1 of them are runs duplicated inside units that are not clones of each other; \
             4 more were folded into the groups that already cover them and 2 into longer runs"
        ));
    }

    #[test]
    fn a_rule_that_matched_nothing_is_named_not_left_to_be_noticed() {
        let mut report = sample_report();
        report.summary.unused_suppressions = vec![
            UnusedRule {
                scope: "path_glob".to_string(),
                pattern: "third_party/**".to_string(),
            },
            UnusedRule {
                scope: "stable_clone_id".to_string(),
                pattern: "abcd1234".to_string(),
            },
        ];

        let value: serde_json::Value = serde_json::from_str(&report.to_json().unwrap()).unwrap();
        assert_eq!(
            value["summary"]["unused_suppressions"][0]["scope"],
            "path_glob"
        );
        assert_eq!(
            value["summary"]["unused_suppressions"][1]["pattern"],
            "abcd1234"
        );

        let mut buffer = Vec::new();
        report
            .render_text(TextOptions::default(), &mut buffer)
            .unwrap();
        let text = String::from_utf8(buffer).unwrap();
        // Named the way a rule that did match is named, so the two read alike.
        assert!(text.contains(
            "note: 2 suppression rule(s) matched nothing: path glob \"third_party/**\", \
             clone id abcd1234"
        ));
    }

    #[test]
    fn a_run_with_every_rule_matching_says_nothing_about_them() {
        let mut buffer = Vec::new();
        sample_report()
            .render_text(TextOptions::default(), &mut buffer)
            .unwrap();
        assert!(
            !String::from_utf8(buffer)
                .unwrap()
                .contains("matched nothing")
        );
    }

    #[test]
    fn a_group_inside_the_suite_says_so_in_every_view() {
        let mut report = sample_report();
        report.summary.groups.test_code = 1;
        let mut group = fragment_group();
        group.test_code = true;
        report.groups.insert(0, group);

        let value: serde_json::Value = serde_json::from_str(&report.to_json().unwrap()).unwrap();
        assert_eq!(value["groups"][0]["test_code"], true);
        // A group reaching outside the suite is the interesting case, and says
        // as much rather than leaving the field out.
        assert_eq!(value["groups"][1]["test_code"], false);

        let mut buffer = Vec::new();
        report
            .render_text(TextOptions::default(), &mut buffer)
            .unwrap();
        let text = String::from_utf8(buffer).unwrap();
        // Shown, not hidden, and its place in the ranking is explained.
        assert!(text.contains("[test code]"));
        assert!(text.contains("1 of them are duplication inside test code"));
    }

    #[test]
    fn an_occurrence_inside_the_suite_explains_why() {
        let mut group = fragment_group();
        group.test_code = true;
        let detail = FindingDetail {
            member: group.members.remove(0),
            group: GroupRef {
                fingerprint: "0e".repeat(16),
                clone_type: "type-1".to_string(),
                scope: SCOPE_FRAGMENT.to_string(),
                confidence: 1.0,
                members: 2,
                boilerplate: None,
                test_code: true,
                split_pair: false,
                similarity: None,
                suppressed: None,
            },
            scan_run: 3,
        };
        let mut buffer = Vec::new();
        detail.render_text(&mut buffer).unwrap();
        assert!(
            String::from_utf8(buffer)
                .unwrap()
                .contains("test code: every occurrence is inside a test")
        );
    }

    #[test]
    fn an_occurrence_of_a_run_explains_itself_as_a_run() {
        let mut detail = FindingDetail {
            member: fragment_group().members.remove(0),
            group: GroupRef {
                fingerprint: "0e".repeat(16),
                clone_type: "type-1".to_string(),
                scope: SCOPE_FRAGMENT.to_string(),
                confidence: 1.0,
                members: 2,
                boilerplate: None,
                test_code: false,
                split_pair: false,
                similarity: None,
                suppressed: None,
            },
            scan_run: 3,
        };
        let mut buffer = Vec::new();
        detail.render_text(&mut buffer).unwrap();
        let text = String::from_utf8(buffer).unwrap();
        assert!(text.contains("duplicated run, type-1"));

        // The same occurrence in a whole-unit group reads the other way.
        detail.group.scope = "unit".to_string();
        let mut buffer = Vec::new();
        detail.render_text(&mut buffer).unwrap();
        assert!(
            String::from_utf8(buffer)
                .unwrap()
                .contains("duplicated unit")
        );
    }

    #[test]
    fn the_unparsed_share_counts_files_and_tokens_against_the_whole_scan() {
        let counts = UnparsedCounts::new([0, 250, 0, 750], 4000);
        assert_eq!(counts.files, 2, "only the files that lost something count");
        assert_eq!(counts.tokens, 1000);
        assert!((counts.share - 0.25).abs() < f64::EPSILON);
    }

    #[test]
    fn a_scan_the_parser_followed_reports_a_share_of_nothing() {
        let clean = UnparsedCounts::new([0, 0], 4000);
        assert_eq!((clean.files, clean.tokens), (0, 0));
        assert!(clean.share.abs() < f64::EPSILON);
        // An empty scan divides by nothing rather than producing a NaN that
        // would serialize as `null` and read as "not measured".
        let empty = UnparsedCounts::new([], 0);
        assert!(empty.share.abs() < f64::EPSILON);
    }

    #[test]
    fn a_lexing_mode_reports_no_parse_coverage_rather_than_a_clean_one() {
        // Fast mode has no parser, so `unparsed` is absent from its JSON. A
        // zero there would claim the parser followed everything.
        let value: serde_json::Value =
            serde_json::from_str(&sample_report().to_json().unwrap()).unwrap();
        assert!(value["summary"].get("unparsed").is_none());
    }

    #[test]
    fn json_view_serializes_the_documented_shape() {
        let value: serde_json::Value =
            serde_json::from_str(&sample_report().to_json().unwrap()).unwrap();
        assert_eq!(value["schema_version"], 1);
        assert_eq!(value["run"]["mode"], "fast");
        assert_eq!(value["run"]["build_variant"]["normalization_version"], 2);
        assert_eq!(value["summary"]["files"]["total"], 2);
        assert_eq!(value["summary"]["pair_budget_exhausted"], false);
        let group = &value["groups"][0];
        assert_eq!(group["clone_type"], "type-1");
        assert_eq!(group["priority"]["largest_member_tokens"], 80);
        assert_eq!(group["suppressed"], serde_json::Value::Null);
        assert_eq!(group["members"][0]["canonical"], true);
        let suppressed = &value["groups"][1]["suppressed"];
        assert_eq!(suppressed["kind"], "rule");
        assert_eq!(suppressed["scope"], "path_glob");
        assert!(suppressed.get("reason").is_none());
    }

    #[test]
    fn a_scored_group_reports_every_dimension_and_marks_the_absent_one() {
        let mut report = sample_report();
        report.summary.groups.type_3 = 1;
        report.groups.push(structural_group());
        let value: serde_json::Value = serde_json::from_str(&report.to_json().unwrap()).unwrap();

        let similarity = &value["groups"][2]["similarity"];
        assert_eq!(similarity["composite"], 0.82);
        assert_eq!(similarity["min_pairwise"], 0.79);
        assert_eq!(similarity["weight_version"], "structural-verify-v4");
        assert_eq!(similarity["confidence_band"], "medium");
        // Unavailable, not guessed: the dimension is reported as absent.
        assert_eq!(similarity["type_similarity"], serde_json::Value::Null);
        // A mode that scores no dimensions says so rather than omitting the key.
        assert_eq!(value["groups"][0]["similarity"], serde_json::Value::Null);
        assert_eq!(value["summary"]["groups"]["type_3"], 1);

        let mut buffer = Vec::new();
        report
            .render_text(TextOptions::default(), &mut buffer)
            .unwrap();
        let text = String::from_utf8(buffer).unwrap();
        assert!(text.contains("type-1 2, type-2 0, type-3 1"));
        assert!(text.contains(
            "similarity: composite 0.82 (lexical 0.71, structural 0.88, \
             control-flow 0.90, type n/a, api 0.75); cohesion 0.79; \
             confidence medium [structural-verify-v4]"
        ));
    }

    #[test]
    fn json_field_names_appear_in_the_shipped_schema() {
        let schema: serde_json::Value = serde_json::from_str(JSON_SCHEMA).unwrap();
        assert_eq!(
            schema["properties"]["schema_version"]["const"],
            i64::from(SCHEMA_VERSION)
        );
        let mut report = sample_report();
        report.groups.push(structural_group());
        report.groups.push(fragment_group());
        report.summary.baseline = Some(BaselineStatus {
            file: "codehelion-baseline.json".to_string(),
            entries: 12,
            matched: 11,
            stale: 1,
            mismatch: Some("recorded under another build variant".to_string()),
        });
        let value: serde_json::Value = serde_json::from_str(&report.to_json().unwrap()).unwrap();
        let checks = [
            (&value["groups"][3], &schema["$defs"]["group"]["properties"]),
            (
                &value["summary"]["baseline"],
                &schema["$defs"]["summary"]["properties"]["baseline"]["properties"],
            ),
            (&value, &schema["properties"]),
            (&value["run"], &schema["$defs"]["run"]["properties"]),
            (&value["summary"], &schema["$defs"]["summary"]["properties"]),
            (
                &value["summary"]["groups"],
                &schema["$defs"]["summary"]["properties"]["groups"]["properties"],
            ),
            (&value["groups"][0], &schema["$defs"]["group"]["properties"]),
            (
                &value["groups"][0]["members"][0],
                &schema["$defs"]["member"]["properties"],
            ),
            (
                &value["groups"][1]["suppressed"],
                &schema["$defs"]["suppression"]["properties"],
            ),
            (
                &value["groups"][2]["similarity"],
                &schema["$defs"]["similarity"]["properties"],
            ),
        ];
        for (object, properties) in checks {
            for key in object.as_object().unwrap().keys() {
                assert!(
                    properties.get(key).is_some(),
                    "field {key:?} missing from the shipped schema"
                );
            }
        }
    }

    #[test]
    fn a_baseline_that_covered_nothing_says_so_rather_than_reading_as_success() {
        let mut report = sample_report();
        report.summary.baseline = Some(BaselineStatus {
            file: "codehelion-baseline.json".to_string(),
            entries: 12,
            matched: 0,
            stale: 12,
            mismatch: Some("recorded under build variant aaaa in fast mode".to_string()),
        });
        let mut buffer = Vec::new();
        report
            .render_text(TextOptions::default(), &mut buffer)
            .unwrap();
        let text = String::from_utf8(buffer).unwrap();
        assert!(text.contains("baseline codehelion-baseline.json: 0 of 12 entries matched"));
        // Without this the run is indistinguishable from one whose baseline
        // hid everything it was meant to.
        assert!(text.contains("warning: this baseline hid nothing"));

        // A baseline that applies says only what it did.
        report.summary.baseline = Some(BaselineStatus {
            file: "codehelion-baseline.json".to_string(),
            entries: 12,
            matched: 11,
            stale: 1,
            mismatch: None,
        });
        let mut buffer = Vec::new();
        report
            .render_text(TextOptions::default(), &mut buffer)
            .unwrap();
        let text = String::from_utf8(buffer).unwrap();
        assert!(text.contains("11 of 12 entries matched, 1 no longer found"));
        assert!(!text.contains("warning:"));
    }

    #[test]
    fn text_view_truncates_with_an_explicit_count() {
        let mut buffer = Vec::new();
        sample_report()
            .render_text(TextOptions::default(), &mut buffer)
            .unwrap();
        let text = String::from_utf8(buffer).unwrap();
        assert!(text.contains("lines: 40; tokens: 200"));
        assert!(text.contains("... and 2 more occurrences"));
        assert!(!text.contains("src/file6.rs"));
        assert!(!text.contains("vendor/a.rs")); // suppressed and not requested
        assert!(!text.contains('\x1b'));
    }

    #[test]
    fn verbose_text_lists_every_member_and_suppressed_section_is_opt_in() {
        let opts = TextOptions {
            verbose: true,
            color: false,
            show_suppressed: true,
        };
        let mut buffer = Vec::new();
        sample_report().render_text(opts, &mut buffer).unwrap();
        let text = String::from_utf8(buffer).unwrap();
        assert!(text.contains("src/file6.rs"));
        assert!(!text.contains("more occurrences"));
        assert!(text.contains("suppressed groups:"));
        assert!(text.contains("[suppressed: path glob \"vendor/**\"]"));
    }

    #[test]
    fn the_pipeline_counts_are_detail_the_verbose_view_asks_for() {
        let render = |verbose| {
            let opts = TextOptions {
                verbose,
                color: false,
                show_suppressed: false,
            };
            let mut buffer = Vec::new();
            sample_report().render_text(opts, &mut buffer).unwrap();
            String::from_utf8(buffer).unwrap()
        };
        let verbose = render(true);
        assert!(verbose.contains("candidate pipeline:"));
        assert!(verbose.contains("tokens"));
        assert!(verbose.contains("(dropped: high frequency 3)"));
        // A cause that dropped nothing says nothing.
        assert!(!verbose.contains("hash collision"));
        assert!(!render(false).contains("candidate pipeline:"));
    }

    #[test]
    fn colored_text_uses_ansi_codes_only_when_enabled() {
        let opts = TextOptions {
            verbose: false,
            color: true,
            show_suppressed: false,
        };
        let mut buffer = Vec::new();
        sample_report().render_text(opts, &mut buffer).unwrap();
        let text = String::from_utf8(buffer).unwrap();
        assert!(text.contains("\x1b[1mcodehelion scan (fast mode)\x1b[0m"));
        assert!(text.contains("\x1b[36m"));
    }

    #[test]
    fn finding_detail_shares_the_member_shape_across_views() {
        let detail = FindingDetail {
            member: Member {
                finding_id: "ab".repeat(16),
                file: "src/lib.rs".to_string(),
                start_line: 3,
                end_line: 12,
                unit: Some("checksum".to_string()),
                tokens: 64,
                canonical: true,
            },
            group: GroupRef {
                fingerprint: "cd".repeat(16),
                clone_type: "type-1".to_string(),
                scope: "unit".to_string(),
                confidence: 1.0,
                members: 2,
                boilerplate: None,
                test_code: false,
                split_pair: false,
                similarity: None,
                suppressed: None,
            },
            scan_run: 7,
        };
        let value: serde_json::Value = serde_json::from_str(&detail.to_json().unwrap()).unwrap();
        assert_eq!(value["finding_id"], "ab".repeat(16));
        assert_eq!(value["group"]["clone_type"], "type-1");
        assert_eq!(value["scan_run"], 7);
        // A Fast-mode occurrence measured no dimensions; the field is present
        // and null rather than filled with a guess.
        assert!(value["group"]["similarity"].is_null());

        let mut buffer = Vec::new();
        detail.render_text(&mut buffer).unwrap();
        let text = String::from_utf8(buffer).unwrap();
        assert!(text.contains(&format!("finding {}", "ab".repeat(16))));
        assert!(text.contains("location: src/lib.rs:3-12"));
        assert!(text.contains("canonical: yes"));
        assert!(text.contains("2 instances"));
    }

    #[test]
    fn a_structural_occurrence_explains_itself_with_the_recorded_evidence() {
        let detail = FindingDetail {
            member: Member {
                finding_id: "ef".repeat(16),
                file: "src/b.rs".to_string(),
                start_line: 1,
                end_line: 20,
                unit: Some("beta".to_string()),
                tokens: 90,
                canonical: false,
            },
            group: GroupRef {
                fingerprint: "cd".repeat(16),
                clone_type: "type-3".to_string(),
                scope: "unit".to_string(),
                confidence: 0.87,
                members: 2,
                boilerplate: Some("macro-repetition".to_string()),
                test_code: false,
                split_pair: false,
                similarity: Some(Similarity {
                    weight_version: "structural-verify-v4".to_string(),
                    lexical: 0.71,
                    structural: 0.92,
                    control_flow: 1.0,
                    type_similarity: None,
                    api: Some(0.8),
                    composite: 0.87,
                    min_pairwise: 0.87,
                    confidence_band: Some("medium".to_string()),
                }),
                suppressed: Some(Suppression {
                    kind: SuppressionKind::Rule,
                    reason: None,
                    scope: Some("symbol_pattern".to_string()),
                    pattern: Some("beta".to_string()),
                }),
            },
            scan_run: 9,
        };
        let mut buffer = Vec::new();
        detail.render_text(&mut buffer).unwrap();
        let text = String::from_utf8(buffer).unwrap();
        assert!(text.contains("similarity: composite 0.87"));
        // The unmeasured dimension is named, never guessed.
        assert!(text.contains("type n/a"));
        assert!(text.contains("confidence medium"));
        assert!(text.contains("boilerplate: macro-repetition"));
        // A suppressed finding is still recorded and still explainable.
        assert!(text.contains("suppressed: symbol glob \"beta\""));
    }

    #[test]
    fn an_unrecorded_confidence_band_prints_as_absent() {
        let similarity = Similarity {
            weight_version: "structural-verify-v4".to_string(),
            lexical: 0.5,
            structural: 0.5,
            control_flow: 0.5,
            type_similarity: None,
            api: Some(0.5),
            composite: 0.5,
            min_pairwise: 0.5,
            confidence_band: None,
        };
        assert!(similarity.line().contains("confidence n/a"));
    }
}
