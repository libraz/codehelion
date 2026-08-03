//! Scan-performance benchmark support: large synthetic corpora and
//! measurement of the shipped binary.
//!
//! Three pieces, driven by the `codehelion-bench` binary:
//!
//! - [`generate_corpus`] writes a deterministic multi-language source tree
//!   of a requested size, structurally varied so it does not collapse into
//!   one clone class, with a controlled fraction of injected clones;
//! - [`measure_scan`] runs the real `codehelion` binary over a corpus, with
//!   or without a previous scan of it on record, and takes wall time plus
//!   peak resident set size;
//! - [`measure_store_insert`] times one snapshot insert of synthetic rows,
//!   isolating the `SQLite` write cost from the rest of the pipeline.
//!
//! Nothing here executes generated code: the corpus only ever gets lexed.

// The benchmark harness legitimately spawns the compiled `codehelion` binary
// it measures; it is not part of the scan path the workspace-wide lint locks.
#![allow(clippy::disallowed_types)]

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail, ensure};
use codehelion_core::clone_class::{CloneClass, CloneScope};
use codehelion_core::discovery::{BuildVariant, Language, LanguageSelection};
use codehelion_core::frontend::UnitKind;
use codehelion_core::stable_id::{
    CloneGroupFingerprint, FindingId, FragmentFingerprint, UnitFingerprint,
};
use codehelion_store::Store;
use codehelion_store::snapshot::{
    GroupOrigin, GroupRow, MemberRow, PriorityRow, Snapshot, SummaryRow, UnitRow,
};

mod generation;

pub use generation::{CorpusSpec, CorpusStats, generate_corpus};

/// What a measured scan knows about the tree before it starts.
///
/// The distinction is the audit database, not the file system cache: a warm
/// scan is one that has a previous scan of the same tree to compare against,
/// which is the state a periodic audit is almost always in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanStart {
    /// No previous scan: the database is removed first.
    Cold,
    /// The database a previous scan of the same tree left behind.
    Warm,
}

/// One scan of a corpus by the real binary.
#[derive(Debug)]
pub struct ScanMeasurement {
    /// Wall-clock duration of the whole scan process.
    pub wall: Duration,
    /// Peak resident set size in bytes, when the platform reports it.
    pub max_rss_bytes: Option<u64>,
    /// Source lines the scan analysed.
    pub lines: u64,
    /// Candidate pairs the pairing passes examined.
    pub examined_pairs: u64,
    /// Candidate pairs a spent allowance left unexamined.
    pub skipped_pairs: u64,
    /// Whether any candidate-search resource ceiling truncated the scan.
    ///
    /// This is the report's completeness signal. It covers ceilings whose
    /// drops are not candidate pairs, such as posting-list and bucket caps.
    pub search_truncated: bool,
    /// The scan report's summary lines, for context next to the numbers.
    pub summary: String,
}

impl ScanMeasurement {
    /// Share of the candidate pairs a spent allowance left unexamined, in
    /// `0.0..=1.0`. Zero when nothing was cut, including when there was
    /// nothing to cut.
    #[must_use]
    #[allow(clippy::cast_precision_loss)] // ratio of display-scale counts
    pub fn truncation_share(&self) -> f64 {
        let total = self.examined_pairs.saturating_add(self.skipped_pairs);
        if total == 0 {
            return 0.0;
        }
        self.skipped_pairs as f64 / total as f64
    }
}

/// What a scan of a given size is expected to cost, and what it is expected to
/// have done for the cost.
///
/// Three of the four are the size targets the tool holds itself to: a hundred
/// thousand lines in seconds, a million in tens of seconds, and peak memory
/// under two gigabytes at a million lines. Between and beyond those two named
/// sizes the allowance is scaled linearly. Memory has run 730 to 850 bytes per
/// line across four tree sizes, so granting the million-line allowance to a
/// smaller tree would make its memory target meaningless.
///
/// The fourth is not a cost. At the size the targets name, the search is
/// expected to have finished rather than to have been cut short by an
/// allowance — because a run that reaches a time target by abandoning three
/// quarters of its candidates has not met the target, it has changed the
/// question. Without this condition a timing regression can always be fixed by
/// lowering a ceiling, and the report would get quieter while looking faster.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Slo {
    /// Wall-clock time the scan is allowed at the measured size.
    pub wall: Duration,
    /// Peak resident bytes the scan is allowed at the measured size.
    pub max_rss_bytes: u64,
}

/// Lines by which the "in seconds" target is stated.
const SMALL_TREE_LINES: u64 = 100_000;

/// Seconds allowed at [`SMALL_TREE_LINES`] and below.
const SMALL_TREE_SECONDS: u64 = 10;

/// Lines by which the "tens of seconds" and memory targets are stated.
const LARGE_TREE_LINES: u64 = 1_000_000;

/// Seconds allowed at [`LARGE_TREE_LINES`].
const LARGE_TREE_SECONDS: u64 = 60;

/// Peak resident bytes allowed at [`LARGE_TREE_LINES`].
const LARGE_TREE_RSS_BYTES: u64 = 2 * 1024 * 1024 * 1024;

impl Slo {
    /// The allowance for a tree of `lines` source lines.
    #[must_use]
    pub const fn for_lines(lines: u64) -> Self {
        // Scaled from the larger named size, floored at the smaller one, so a
        // tree measured at neither still gets an allowance derived from the
        // stated targets rather than from whatever it happened to cost.
        let scaled_seconds = LARGE_TREE_SECONDS.saturating_mul(lines) / LARGE_TREE_LINES;
        let seconds = if lines <= SMALL_TREE_LINES || scaled_seconds < SMALL_TREE_SECONDS {
            SMALL_TREE_SECONDS
        } else {
            scaled_seconds
        };
        let rss_lines = if lines == 0 { 1 } else { lines };
        let scaled_rss = LARGE_TREE_RSS_BYTES.saturating_mul(rss_lines) / LARGE_TREE_LINES;
        Self {
            wall: Duration::from_secs(seconds),
            max_rss_bytes: scaled_rss,
        }
    }

    /// Every way `measurement` fell short of this allowance, as sentences.
    ///
    /// Empty means it met all of them. Every shortfall is reported rather than
    /// the first, because a run that is both slow and truncated has two
    /// problems and fixing the one that surfaced first would hide the other.
    #[must_use]
    #[allow(clippy::cast_precision_loss)] // display-scale counts and ratios
    pub fn shortfalls(&self, measurement: &ScanMeasurement) -> Vec<String> {
        let mut missed = Vec::new();
        if measurement.wall > self.wall {
            missed.push(format!(
                "took {:.1}s against an allowance of {}s at {} lines",
                measurement.wall.as_secs_f64(),
                self.wall.as_secs(),
                measurement.lines,
            ));
        }
        if let Some(rss) = measurement.max_rss_bytes
            && rss > self.max_rss_bytes
        {
            let mib = |bytes: u64| bytes as f64 / (1024.0 * 1024.0);
            missed.push(format!(
                "peaked at {:.0} MiB against an allowance of {:.0} MiB",
                mib(rss),
                mib(self.max_rss_bytes),
            ));
        }
        if measurement.search_truncated {
            if measurement.skipped_pairs > 0 {
                missed.push(format!(
                    "examined {} of {} candidate pairs; the allowance stopped the search \
                     {:.0}% short",
                    measurement.examined_pairs,
                    measurement.examined_pairs + measurement.skipped_pairs,
                    measurement.truncation_share() * 100.0,
                ));
            } else {
                missed.push(
                    "a candidate-search resource ceiling truncated the search; results may be incomplete"
                        .to_string(),
                );
            }
        }
        missed
    }
}

/// Run `binary scan corpus` once under the platform's `time` wrapper to
/// capture peak memory, either cold or warm.
///
/// The report is taken as JSON, so the pipeline's stage counts are read as
/// numbers rather than scraped back out of the text the tool printed for
/// people. At this size the question is not only how long a mode takes but
/// which stage the time went into, and whether it got to the end of the work
/// at all.
///
/// # Errors
///
/// Returns an error when the scan cannot be spawned, exits non-zero, or
/// writes a report this harness cannot read.
pub fn measure_scan(
    binary: &Path,
    corpus: &Path,
    mode: &str,
    jobs: Option<usize>,
    work_dir: &Path,
    start_state: ScanStart,
) -> Result<ScanMeasurement> {
    let db = prepare_database(work_dir, start_state)?;
    let report = work_dir.join("report.json");

    let mut command = time_wrapped_command(binary);
    command
        .arg("scan")
        .arg(corpus)
        .args(["--mode", mode, "--format", "json"])
        // A timing run measures the work of reading a tree, and skipping part
        // of one on a presentation setting would make two corpora's numbers
        // depend on their directory names.
        .arg("--include-vendored")
        .arg("--db")
        .arg(&db)
        .arg("--output")
        .arg(&report);
    if let Some(jobs) = jobs {
        command.args(["--jobs", &jobs.to_string()]);
    }

    let start = Instant::now();
    let output = command
        .output()
        .with_context(|| format!("spawning {}", binary.display()))?;
    let wall = start.elapsed();
    if !output.status.success() {
        bail!(
            "scan failed ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let max_rss_bytes = parse_max_rss(&String::from_utf8_lossy(&output.stderr));
    let text = std::fs::read_to_string(&report)
        .with_context(|| format!("reading {}", report.display()))?;
    let value: serde_json::Value =
        serde_json::from_str(&text).with_context(|| format!("parsing {}", report.display()))?;
    let counted = count_pipeline(&value);
    Ok(ScanMeasurement {
        wall,
        max_rss_bytes,
        lines: counted.lines,
        examined_pairs: counted.examined_pairs,
        skipped_pairs: counted.skipped_pairs,
        search_truncated: counted.search_truncated,
        summary: summarize(&value),
    })
}

/// The numbers a size measurement needs from a scan report.
struct PipelineCounts {
    lines: u64,
    examined_pairs: u64,
    skipped_pairs: u64,
    search_truncated: bool,
}

/// Read the analysed size and the pairing stages' own accounting out of a
/// report.
///
/// `summary.search_truncated` is the completeness signal. Pair-budget counts
/// remain a useful diagnostic when available, but not every ceiling drops
/// pairs, so they must never decide whether an SLO was met.
fn count_pipeline(report: &serde_json::Value) -> PipelineCounts {
    let summary = &report["summary"];
    let mut counts = PipelineCounts {
        lines: summary["lines"].as_u64().unwrap_or(0),
        examined_pairs: 0,
        skipped_pairs: 0,
        // A new report schema requires this field. Treat an older or malformed
        // report as incomplete rather than allowing an absent signal to claim
        // a complete search.
        search_truncated: summary["search_truncated"].as_bool().unwrap_or(true),
    };
    let Some(funnel) = summary["funnel"].as_array() else {
        return counts;
    };
    for stage in funnel {
        let skipped: u64 = stage["dropped"].as_array().map_or(0, |drops| {
            drops
                .iter()
                .filter(|drop| drop["cause"] == "pair_budget")
                .filter_map(|drop| drop["count"].as_u64())
                .sum()
        });
        if skipped == 0 {
            continue;
        }
        counts.examined_pairs = counts
            .examined_pairs
            .saturating_add(stage["passed"].as_u64().unwrap_or(0));
        counts.skipped_pairs = counts.skipped_pairs.saturating_add(skipped);
    }
    counts
}

/// The audit database to scan into, in the state the requested start calls
/// for: absent for a cold scan, left as it stands for a warm one.
///
/// A warm scan does not require the file to exist — the first scan of a tree
/// creates it — so the only difference is whether an existing one survives.
fn prepare_database(work_dir: &Path, start_state: ScanStart) -> Result<PathBuf> {
    let db = work_dir.join("audit.db");
    if start_state == ScanStart::Cold && db.exists() {
        std::fs::remove_file(&db).with_context(|| format!("removing {}", db.display()))?;
    }
    Ok(db)
}

/// The size of what was scanned, what came of it, and the whole candidate
/// pipeline stage by stage.
///
/// That is what a timing number needs beside it to mean anything, and the
/// drops matter most: a run that exhausted an allowance is fast partly
/// because it stopped early, which the timing alone would hide.
#[must_use]
pub fn summarize(report: &serde_json::Value) -> String {
    let summary = &report["summary"];
    let count = |path: &str, key: &str| summary[path][key].as_u64().unwrap_or(0);
    let mut out = format!(
        "files: {} analysed; lines: {}; tokens: {}",
        count("files", "total"),
        summary["lines"].as_u64().unwrap_or(0),
        summary["tokens"].as_u64().unwrap_or(0),
    );
    // What the scan recognised of the tree, when it had a previous run to
    // compare against. Without it a warm number is indistinguishable from a
    // cold one that happened to run fast.
    if let Some(changes) = summary["changes"].as_object() {
        let field = |key: &str| changes.get(key).and_then(serde_json::Value::as_u64);
        let _ = write!(
            out,
            "\nsince run {}: {} unchanged, {} modified, {} added, {} removed",
            field("since_run_id").unwrap_or(0),
            field("unchanged").unwrap_or(0),
            field("modified").unwrap_or(0),
            field("added").unwrap_or(0),
            field("removed").unwrap_or(0),
        );
    }
    let _ = write!(out, "\nclone groups: {}", count("groups", "total"));
    if let Some(funnel) = summary["funnel"].as_array() {
        out.push_str("\ncandidate pipeline:");
        for stage in funnel {
            let _ = write!(
                out,
                "\n  {:<18} {:>12}",
                stage["stage"].as_str().unwrap_or("?"),
                stage["passed"].as_u64().unwrap_or(0),
            );
            let drops: Vec<String> = stage["dropped"]
                .as_array()
                .map(|drops| {
                    drops
                        .iter()
                        .map(|drop| {
                            format!(
                                "{} {}",
                                drop["cause"].as_str().unwrap_or("?"),
                                drop["count"].as_u64().unwrap_or(0)
                            )
                        })
                        .collect()
                })
                .unwrap_or_default();
            if !drops.is_empty() {
                let _ = write!(out, "  (dropped: {})", drops.join(", "));
            }
        }
    }
    out
}

/// The command that runs `binary` under a resource-reporting wrapper where
/// one exists (`/usr/bin/time -l` on macOS reports bytes, GNU `time -v` on
/// Linux reports kbytes); elsewhere the binary runs bare and peak memory is
/// unavailable.
fn time_wrapped_command(binary: &Path) -> Command {
    let wrapper = Path::new("/usr/bin/time");
    let flag = if cfg!(target_os = "macos") {
        Some("-l")
    } else if cfg!(target_os = "linux") {
        Some("-v")
    } else {
        None
    };
    match flag {
        Some(flag) if wrapper.exists() => {
            let mut command = Command::new(wrapper);
            command.arg(flag).arg(binary);
            command
        }
        _ => Command::new(binary),
    }
}

/// Extract the peak resident set size in bytes from a `time` wrapper's
/// stderr, understanding both the BSD/macOS format (bytes, number first)
/// and the GNU format (`(kbytes)`, number last).
#[must_use]
pub fn parse_max_rss(stderr: &str) -> Option<u64> {
    for line in stderr.lines() {
        let lower = line.to_ascii_lowercase();
        if !lower.contains("maximum resident set size") {
            continue;
        }
        let numbers: Vec<u64> = line
            .split(|c: char| !c.is_ascii_digit())
            .filter(|piece| !piece.is_empty())
            .filter_map(|piece| piece.parse().ok())
            .collect();
        if lower.contains("kbytes") {
            return numbers.last().map(|kb| kb * 1024);
        }
        return numbers.first().copied();
    }
    None
}

/// One timed snapshot insert of synthetic rows.
#[derive(Debug)]
pub struct StoreMeasurement {
    /// Unit rows written.
    pub units: usize,
    /// Group rows written.
    pub groups: usize,
    /// Member rows written.
    pub members: usize,
    /// Time spent inside `record_snapshot` (one transaction).
    pub elapsed: Duration,
}

/// Time one `record_snapshot` call against a fresh database in `work_dir`.
///
/// Writes `units` unit rows and `groups` groups of `members_per_group`
/// members each. Fingerprints are synthetic and distinct, so nothing dedups
/// away and the measurement covers full insert volume.
///
/// # Errors
///
/// Returns an error when the database cannot be created or written.
#[allow(
    clippy::too_many_lines,
    reason = "the benchmark builds one complete snapshot fixture beside its measurement"
)]
pub fn measure_store_insert(
    units: usize,
    groups: usize,
    members_per_group: usize,
    work_dir: &Path,
) -> Result<StoreMeasurement> {
    ensure!(units > 0, "at least one unit row is required");
    let fp = |tag: u64, index: usize| -> [u8; 16] {
        let mut bytes = [0u8; 16];
        bytes[..8].copy_from_slice(&tag.to_be_bytes());
        bytes[8..].copy_from_slice(&(index as u64).to_be_bytes());
        bytes
    };
    let unit_rows: Vec<UnitRow> = (0..units)
        .map(|index| UnitRow {
            fingerprint: UnitFingerprint::from_bytes(fp(1, index)),
            language: Language::Rust,
            kind: UnitKind::Function,
            name: Some(format!("synthetic_{index}")),
            file_path: format!("mod_{}/file_{}.rs", index / 256, index),
            start_line: 1,
            end_line: 40,
            token_count: 160,
        })
        .collect();
    let group_rows: Vec<GroupRow> = (0..groups)
        .map(|group| GroupRow {
            fingerprint: CloneGroupFingerprint::from_bytes(fp(2, group)),
            history: GroupOrigin::unconnected(&CloneGroupFingerprint::from_bytes(fp(2, group))),
            clone_type: CloneClass::Type1,
            split_pair: false,
            member_scope: CloneScope::Unit,
            statements: None,
            test_code: false,
            test_code_evidence: None,
            score: 1.0,
            entropy_bits: 24.0,
            suppress_reason: None,
            boilerplate: None,
            identifier_jaccard: None,
            has_loop: None,
            has_dynamic_allocation: None,
            call_count: None,
            width_family: false,
            ranked_down: false,
            suppressed_by: None,
            priority: PriorityRow {
                clone_confidence: 0.9,
                maintenance_risk: 0.4,
                refactoring_difficulty: 0.3,
                final_priority: 0.5,
                semantic_confidence: None,
                source_artifact_confidence: None,
                savings_confidence: None,
            },
            similarity: None,
            semantic: None,
            members: (0..members_per_group)
                .map(|member| {
                    let index = group * members_per_group + member;
                    MemberRow {
                        content: FragmentFingerprint::from_bytes(fp(3, group)),
                        finding: FindingId::from_bytes(fp(4, index)),
                        language: Language::Rust,
                        host_unit: Some(index % units),
                        boilerplate: None,
                        file_path: format!("mod_{}/file_{}.rs", index / 256, index),
                        start_line: 1,
                        end_line: 40,
                        token_count: 160,
                    }
                })
                .collect(),
        })
        .collect();

    let variant = BuildVariant::fast(LanguageSelection::default(), Language::C);
    let snapshot = Snapshot {
        root_path: "/synthetic",
        tool_version: "bench",
        config_hash: "0",
        config_source: "defaults",
        config_path: None,
        started_at: "2026-01-01T00:00:00.000000Z",
        finished_at: "2026-01-01T00:00:01.000000Z",
        variant: &variant,
        min_clone_tokens: 20,
        detector_versions: &[],
        suppressions: Vec::new(),
        units: unit_rows,
        groups: group_rows,
        sibling_groups: Vec::new(),
        near_misses: Vec::new(),
        files: Vec::new(),
        compiler_helpers: Vec::new(),
        compiler_units: Vec::new(),
        summary: SummaryRow::default(),
    };

    let db = work_dir.join("store-bench.db");
    if db.exists() {
        std::fs::remove_file(&db).with_context(|| format!("removing {}", db.display()))?;
    }
    let mut store = Store::open(&db)?;
    let start = Instant::now();
    store.record_snapshot(&snapshot)?;
    let elapsed = start.elapsed();
    Ok(StoreMeasurement {
        units,
        groups,
        members: groups * members_per_group,
        elapsed,
    })
}

/// Locate the release `codehelion` binary relative to the workspace target
/// directory, for the common `cargo build --release` workflow.
#[must_use]
pub fn default_binary() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/release/codehelion")
        .components()
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests;
