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

use serde::Serialize;

/// Version of the JSON report format.
pub const SCHEMA_VERSION: u32 = 1;

/// The JSON Schema document describing [`Report`]'s JSON form.
pub const JSON_SCHEMA: &str = include_str!("../schema/scan-report-v1.schema.json");

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
    /// Normalization ruleset version.
    pub normalization_version: u32,
    /// Stable fingerprint of the variant.
    pub fingerprint: String,
}

/// Version of one detection component.
#[derive(Debug, Serialize)]
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
    /// Files the scan dropped, by cause.
    pub excluded: ExcludedCounts,
    /// Clone-group counts by type.
    pub groups: GroupCounts,
    /// Suppressed-group counts by mechanism.
    pub suppressed: SuppressedCounts,
    /// Whether the candidate-pair budget ran out, making results
    /// potentially incomplete.
    pub pair_budget_exhausted: bool,
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
    /// Call-name multiset agreement.
    pub api: f64,
    /// Weighted mean of the measured dimensions.
    pub composite: f64,
    /// Weakest pairwise similarity inside the group: its cohesion.
    pub min_pairwise: f64,
    /// Confidence band of the classification (`high`, `medium`, `low`).
    pub confidence_band: String,
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
        format!(
            "similarity: composite {:.2} (lexical {:.2}, structural {:.2}, \
             control-flow {:.2}, type {type_similarity}, api {:.2}); \
             cohesion {:.2}; confidence {} [{}]",
            self.composite,
            self.lexical,
            self.structural,
            self.control_flow,
            self.api,
            self.min_pairwise,
            self.confidence_band,
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
        self.render_groups(opts, &palette, out)
    }

    fn render_summary(&self, palette: &Palette, out: &mut impl Write) -> io::Result<()> {
        let summary = &self.summary;
        writeln!(
            out,
            "{}",
            palette.bold(&format!("codehelion scan ({} mode)", self.run.mode))
        )?;
        writeln!(out, "  root: {}", self.run.root)?;
        writeln!(
            out,
            "  files: {} analysed (rust {}, c {}, cpp {})",
            summary.files.total, summary.files.rust, summary.files.c, summary.files.cpp,
        )?;
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
        writeln!(
            out,
            "  snapshot: run {} in {}",
            self.run.run_id, self.run.database
        )?;
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
    let marker = match (&group.suppressed, &group.boilerplate) {
        (Some(cause), _) => format!(
            " {}",
            palette.yellow(&format!("[suppressed: {}]", cause.label()))
        ),
        // A group that is boilerplate but still shown says so: its place in
        // the ranking is explained rather than silently lowered.
        (None, Some(category)) => {
            format!(" {}", palette.yellow(&format!("[boilerplate: {category}]")))
        }
        (None, None) => String::new(),
    };
    writeln!(
        out,
        "  {} {} priority {:.1} ({} tokens x {} extra x {:.2} similarity){marker}",
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

/// A reference to an occurrence's owning group.
#[derive(Debug, Serialize)]
pub struct GroupRef {
    /// Stable clone-group fingerprint, hex-encoded.
    pub fingerprint: String,
    /// Clone classification (`type-1`, `type-2`, `type-3`).
    pub clone_type: String,
    /// Minimum pairwise similarity across the group.
    pub confidence: f64,
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
        writeln!(
            out,
            "  group: {} ({}, score {:.2})",
            self.group.fingerprint, self.group.clone_type, self.group.confidence,
        )?;
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
                excluded: ExcludedCounts {
                    generated: 0,
                    by_glob: 0,
                    skipped: 0,
                },
                groups: GroupCounts {
                    total: 2,
                    type_1: 2,
                    type_2: 0,
                    type_3: 0,
                },
                suppressed: SuppressedCounts {
                    noise: 0,
                    by_rule: 1,
                },
                pair_budget_exhausted: false,
            },
            groups: vec![
                Group {
                    fingerprint: "0b".repeat(16),
                    clone_type: "type-1".to_string(),
                    confidence: 1.0,
                    priority: Priority {
                        value: 80.0,
                        largest_member_tokens: 80,
                        extra_instances: 1,
                        similarity: 1.0,
                    },
                    similarity: None,
                    boilerplate: None,
                    suppressed: None,
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
                },
                Group {
                    fingerprint: "0c".repeat(16),
                    clone_type: "type-1".to_string(),
                    confidence: 1.0,
                    priority: Priority {
                        value: 30.0,
                        largest_member_tokens: 30,
                        extra_instances: 1,
                        similarity: 1.0,
                    },
                    similarity: None,
                    boilerplate: None,
                    suppressed: Some(Suppression {
                        kind: SuppressionKind::Rule,
                        reason: None,
                        scope: Some("path_glob".to_string()),
                        pattern: Some("vendor/**".to_string()),
                    }),
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
            confidence: 0.79,
            priority: Priority {
                value: 47.4,
                largest_member_tokens: 60,
                extra_instances: 1,
                similarity: 0.79,
            },
            similarity: Some(Similarity {
                weight_version: "structural-verify-v0".to_string(),
                lexical: 0.71,
                structural: 0.88,
                control_flow: 0.90,
                type_similarity: None,
                api: 0.75,
                composite: 0.82,
                min_pairwise: 0.79,
                confidence_band: "medium".to_string(),
            }),
            boilerplate: None,
            suppressed: None,
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
        assert_eq!(similarity["weight_version"], "structural-verify-v0");
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
             confidence medium [structural-verify-v0]"
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
        let value: serde_json::Value = serde_json::from_str(&report.to_json().unwrap()).unwrap();
        let checks = [
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
                confidence: 1.0,
            },
            scan_run: 7,
        };
        let value: serde_json::Value = serde_json::from_str(&detail.to_json().unwrap()).unwrap();
        assert_eq!(value["finding_id"], "ab".repeat(16));
        assert_eq!(value["group"]["clone_type"], "type-1");
        assert_eq!(value["scan_run"], 7);

        let mut buffer = Vec::new();
        detail.render_text(&mut buffer).unwrap();
        let text = String::from_utf8(buffer).unwrap();
        assert!(text.contains(&format!("finding {}", "ab".repeat(16))));
        assert!(text.contains("location: src/lib.rs:3-12"));
        assert!(text.contains("canonical: yes"));
    }
}
