//! The three commands that read the repository's own history: `history`,
//! `seam` and `guard`.
//!
//! What separates these from the rest of the tool is their input. A scan reads
//! source text; these read commits. Nothing here parses a file or asks a
//! compiler helper anything.
//!
//! Of the three, only `seam` opens the audit database, and only to write to it:
//! its counts are a measurement, and a measurement nobody keeps cannot be
//! compared with the next one. `history` and `guard` open none. `history`
//! reports the extent of a range rather than anything about the code in it, and
//! `guard` judges the change in front of it, which the ledger and the working
//! tree answer between them — requiring a recorded run would make it
//! unanswerable in exactly the checkouts it exists to run in.
//!
//! # What each answers
//!
//! - `history` counts commits and says nothing about the code in them. It is
//!   the layer underneath the other two, exposed so that a number they print
//!   can be checked against the range it was taken over.
//! - `seam` reports what each ledger entry has cost — how often a change
//!   touched some of its members and not the rest, and how often a `fix`
//!   followed — and records that as one generation of the measurement, which
//!   `codehelion report` reads back beside the next one. `--suggest` proposes
//!   candidates from co-change instead, and writes nothing.
//! - `guard` judges one change against the ledger.
//!
//! # Why the ledger and not discovery
//!
//! `guard` reads the ledger written in `codehelion.toml` and never the
//! candidates history proposes. A subject recomputed from history on each run
//! moves as the repository grows, which would make the same change pass on one
//! day and fail on the next with nothing between them but somebody else's
//! commits. Promotion from candidate to ledger entry is a decision a person
//! makes, and that decision is what is committed.

use std::fmt::Write as _;
use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result};
use codehelion_history::{History, HistoryRange, HistoryRequest, RepoPath};
use codehelion_store::seam::{FindingLocation, SeamEntryRecord, SeamRunRecord};
use globset::Glob;
use serde::Serialize;

use crate::cli::{GuardArgs, HistoryArgs, SeamArgs, SeamCommonArgs, SeamFormat};
use crate::config::{self, Config, ResolvedConfig};
use crate::{Outcome, scan};

/// Version of the JSON these commands emit.
///
/// Independent of the release version and of the audit database's schema: what
/// it describes is the shape of one document, and a reader that parses this
/// shape should not have to care which build wrote it.
pub const SEAM_SCHEMA_VERSION: u32 = 1;

/// Summarise the commit history, without a ledger and without reading a source
/// file.
///
/// # Errors
///
/// Returns an error when the repository or the configuration cannot be read,
/// when `--until` names nothing, or when the report cannot be written.
pub fn history(args: &HistoryArgs, out: &mut impl Write) -> Result<Outcome> {
    let (root, resolved) = resolve(&args.common)?;
    let history = read_history(&root, &resolved.config, args.until.as_deref())?;

    let mut sizes: Vec<usize> = history
        .commits()
        .iter()
        .map(|commit| commit.paths.len())
        .collect();
    sizes.sort_unstable();
    let mut fix = 0usize;
    let mut feat = 0usize;
    let mut other = 0usize;
    for commit in history.commits() {
        match commit.kind {
            codehelion_history::CommitKind::Fix => fix += 1,
            codehelion_history::CommitKind::Feat => feat += 1,
            codehelion_history::CommitKind::Other => other += 1,
        }
    }

    let report = HistoryReport {
        schema_version: SEAM_SCHEMA_VERSION,
        range: history.range(),
        shallow: history.is_shallow(),
        kinds: CommitKinds { fix, feat, other },
        commit_size: CommitSizes {
            median: percentile(&sizes, 50),
            p75: percentile(&sizes, 75),
            p90: percentile(&sizes, 90),
            largest: sizes.last().copied().unwrap_or(0),
        },
    };

    let text = match args.common.format {
        SeamFormat::Json => json(&report)?,
        SeamFormat::Text => render_history(&report)?,
    };
    deliver(&args.common, text.as_bytes(), out)
}

/// Report the ledger's entries against the history, or propose candidates for
/// it.
///
/// # Errors
///
/// Returns an error when the repository or the configuration cannot be read,
/// when `--until` names nothing, or when the report cannot be written.
pub fn seam(args: &SeamArgs, out: &mut impl Write) -> Result<Outcome> {
    let (root, resolved) = resolve(&args.common)?;
    let ledger = resolved.config.ledger()?;
    let settings = resolved.config.seam_tracking.settings();
    let history = read_history(&root, &resolved.config, args.until.as_deref())?;

    if args.suggest {
        // A candidate naming a directory that is no longer there is a proposal
        // nobody can act on, and the history is full of them: a pair of crates
        // since folded into one moved together in every commit either appeared
        // in, which reads as a perfect coupling. This is the one place a
        // suggestion consults the tree, and it consults it for existence
        // alone — no file is opened and nothing is parsed.
        let suggestion = codehelion_seam::suggest(&ledger, &history, &settings).retaining(|unit| {
            // A unit is spelled with forward slashes whatever the platform,
            // which is a shape `Path::join` accepts everywhere.
            root.join(unit).exists()
        });
        let text = match args.common.format {
            SeamFormat::Json => json(&SuggestReport {
                schema_version: SEAM_SCHEMA_VERSION,
                suggestion: &suggestion,
            })?,
            SeamFormat::Text => render_suggestion(&suggestion)?,
        };
        // Nothing is recorded here. A proposal is not a measurement: these
        // candidates were never evaluated against the ledger, and filing them
        // as the newest generation of what the ledger costs would answer a
        // question nobody asked.
        return deliver(&args.common, text.as_bytes(), out);
    }

    let evaluation = codehelion_seam::evaluate(&ledger, &history, &settings);
    let text = match args.common.format {
        SeamFormat::Json => json(&EvaluationReport {
            schema_version: SEAM_SCHEMA_VERSION,
            evaluation: &evaluation,
        })?,
        SeamFormat::Text => render_evaluation(&evaluation)?,
    };
    let outcome = deliver(&args.common, text.as_bytes(), out)?;
    if records(args)
        && let Err(error) = record_evaluation(&root, &resolved, args.db.as_deref(), &evaluation)
    {
        // The report has already gone out, and it is the answer this command
        // was run for. A checkout nobody can write to, or a database this
        // build cannot open, costs the next run its comparison point and
        // nothing else, so it is said on the error stream the way a shallow
        // history is rather than turning a complete answer into a failure.
        eprintln!(
            "warning: this evaluation was not recorded ({error:#}); the counts above stand, but the next run has no earlier generation of them to compare itself with"
        );
    }
    Ok(outcome)
}

/// Whether this invocation's evaluation becomes the newest recorded generation
/// of the measurement.
///
/// Two ways it does not, beyond `--suggest`, which never reaches here because a
/// proposal is not a measurement:
///
/// - `--until` reads a range somebody deliberately cut short. Recorded as the
///   newest generation, the next comparison would read the shortened range as a
///   change in the code rather than as a shorter question.
/// - `--no-record` is the explicit opt-out.
const fn records(args: &SeamArgs) -> bool {
    !args.no_record && args.until.is_none()
}

/// Record one evaluation as the newest generation of this repository's seam
/// measurement.
///
/// # Errors
///
/// Returns an error when the database cannot be resolved, opened or written,
/// and when a member glob the ledger holds cannot be compiled.
fn record_evaluation(
    root: &Path,
    resolved: &ResolvedConfig,
    db: Option<&Path>,
    evaluation: &codehelion_seam::Evaluation,
) -> Result<i64> {
    let path = scan::database_path_for(scan::DatabaseUse::Recording, root, db, resolved, false)?;
    let mut store = scan::open_store(&path)?;
    // Spelled through the same key a scan records its run under, because that
    // is what a later report looks this run up by.
    let root_path = scan::path_key(root);
    // Findings come from the newest completed scan of this tree, if there is
    // one. Without a scan there is nothing to map, and every count stays zero
    // beside a run id that says why.
    let scan_run_id = store
        .latest_completed_run(&root_path)?
        .map(|origin| origin.id);
    let locations = match scan_run_id {
        Some(run_id) => store.run_finding_locations(run_id)?,
        None => Vec::new(),
    };
    let entries = evaluation
        .seams
        .iter()
        .map(|metrics| {
            Ok(SeamEntryRecord {
                seam_id: metrics.id.clone(),
                members: metrics.members.clone(),
                note: metrics.note.clone(),
                asymmetric_changes: recorded_count(metrics.asymmetric_changes),
                breaches: recorded_count(metrics.breaches),
                last_breach: metrics
                    .last_breach
                    .as_ref()
                    .map(|commit| commit.as_str().to_owned()),
                findings: findings_inside(&metrics.members, &locations)?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    store
        .record_seam_run(&SeamRunRecord {
            root_path,
            settings_digest: evaluation.settings_digest.clone(),
            first_commit: evaluation
                .range
                .first
                .as_ref()
                .map(|commit| commit.as_str().to_owned()),
            last_commit: evaluation
                .range
                .last
                .as_ref()
                .map(|commit| commit.as_str().to_owned()),
            commit_count: recorded_count(evaluation.range.commits),
            scan_run_id,
            recorded_at: scan::rfc3339_now(),
            entries,
        })
        .map_err(Into::into)
}

/// How many recorded findings sit inside one seam.
///
/// A finding is counted once for the seam it falls in however many of that
/// seam's members cover it: the count answers how much duplication the seam
/// holds, and a path matched by two globs is not two findings.
///
/// # Errors
///
/// Returns an error when a member glob cannot be compiled.
fn findings_inside(members: &[String], locations: &[FindingLocation]) -> Result<i64> {
    let mut matchers = Vec::with_capacity(members.len());
    for member in members {
        matchers.push(
            Glob::new(member)
                .with_context(|| format!("seam member glob {member:?}"))?
                .compile_matcher(),
        );
    }
    Ok(recorded_count(
        locations
            .iter()
            .filter(|location| {
                matchers
                    .iter()
                    .any(|matcher| matcher.is_match(&location.file_path))
            })
            .count(),
    ))
}

/// A count as a recorded run carries it.
///
/// Saturating rather than fallible: a repository with more commits than an
/// `i64` can hold is past anything a stored comparison would say about it.
fn recorded_count(value: usize) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

/// Judge a change against the ledger, or look up which seam a path sits in.
///
/// # Errors
///
/// Returns an error when the configuration cannot be read, when the repository
/// or revision cannot be read in the modes that need one, or when the report
/// cannot be written.
pub fn guard(args: &GuardArgs, out: &mut impl Write) -> Result<Outcome> {
    let (root, resolved) = resolve(&args.common)?;
    let ledger = resolved.config.ledger()?;

    if !args.paths.is_empty() {
        // The lookup mode opens nothing. A person asking which seam a file
        // belongs to has not committed anything yet, and requiring a readable
        // history to answer would make the question unanswerable exactly when
        // it is worth asking.
        let paths: Vec<RepoPath> = args.paths.iter().map(RepoPath::new).collect();
        let lookups = codehelion_seam::look_up(&ledger, &paths);
        let text = match args.common.format {
            SeamFormat::Json => json(&LookupReport {
                schema_version: SEAM_SCHEMA_VERSION,
                paths: &lookups,
            })?,
            SeamFormat::Text => render_lookup(&lookups)?,
        };
        return deliver(&args.common, text.as_bytes(), out);
    }

    // An empty ledger is not an error, and it is answered without opening the
    // repository: a project that has written nothing down has said that it
    // knows of no seam, and there is no change that could contradict it.
    let changed = if ledger.is_empty() {
        Vec::new()
    } else {
        match args.since.as_deref() {
            Some(revision) => codehelion_history::changes_since(&root, revision)?,
            None => codehelion_history::working_tree_changes(&root)?,
        }
    };
    let report = codehelion_seam::guard(&ledger, &changed);

    let text = match args.common.format {
        SeamFormat::Json => json(&GuardReport {
            schema_version: SEAM_SCHEMA_VERSION,
            ledger_seams: ledger.entries().len(),
            changed_paths: changed.len(),
            report: &report,
        })?,
        SeamFormat::Text => render_guard(&report, ledger.entries().len())?,
    };
    let outcome = if args.deny_asymmetric && !report.is_empty() {
        Outcome::FindingsPresent
    } else {
        Outcome::Success
    };
    deliver(&args.common, text.as_bytes(), out)?;
    Ok(outcome)
}

/// Resolve the repository root and its configuration.
///
/// The whole resolution is carried rather than the configuration alone: where
/// the configuration came from is what decides which database `seam` records
/// into, and loading it a second time to find that out could answer with a
/// different file than the one these counts were computed under.
fn resolve(common: &SeamCommonArgs) -> Result<(std::path::PathBuf, ResolvedConfig)> {
    let root = codehelion_core::paths::canonical(&common.path)
        .with_context(|| format!("resolving path {}", common.path.display()))?;
    let resolved = config::load(common.config.as_deref(), &root)?;
    Ok((root, resolved))
}

/// Read the history under the configured ceiling, saying when it is cut.
fn read_history(root: &Path, config: &Config, until: Option<&str>) -> Result<History> {
    let history = codehelion_history::read(
        root,
        &HistoryRequest {
            limit: config.seam_tracking.history_limit,
            until: until.map(ToString::to_string),
        },
    )?;
    if history.is_shallow() {
        // Warned rather than refused: a shallow checkout still says what its
        // one commit touched, which is what `guard` reads. What it cannot say
        // is how often two paths moved together, and a count over one commit
        // would look like an answer to that.
        eprintln!(
            "warning: this is a shallow clone, so the counts below are taken over a history somebody else's depth setting cut; fetch the full history (in GitHub Actions, `actions/checkout` with `fetch-depth: 0`) to compare them with anything"
        );
    }
    Ok(history)
}

/// Write a completed report where the caller asked for it.
fn deliver(common: &SeamCommonArgs, text: &[u8], out: &mut impl Write) -> Result<Outcome> {
    match common.output.as_deref() {
        Some(path) => scan::write_output(path, text, common.force)?,
        None => out.write_all(text).context("writing the report")?,
    }
    Ok(Outcome::Success)
}

/// Serialize a report as the JSON a reader parses.
fn json<T: Serialize>(value: &T) -> Result<String> {
    let mut text = serde_json::to_string_pretty(value).context("serializing the report")?;
    text.push('\n');
    Ok(text)
}

/// The value at a percentile of an ascending list, or zero for an empty one.
///
/// Nearest-rank rather than interpolated: the quantity is a file count, and a
/// commit that touched four and a half files is not a thing anybody can look
/// at.
fn percentile(ascending: &[usize], percent: usize) -> usize {
    if ascending.is_empty() {
        return 0;
    }
    let rank = (ascending.len() * percent).div_ceil(100).max(1);
    ascending[rank.min(ascending.len()) - 1]
}

/// What `history` reports.
#[derive(Debug, Serialize)]
struct HistoryReport {
    /// Shape of this document.
    schema_version: u32,
    /// Which commits were read.
    range: HistoryRange,
    /// Whether the repository's history is cut by a shallow clone.
    shallow: bool,
    /// How the commits classify.
    kinds: CommitKinds,
    /// How large the commits are, which is what the coupling ceiling is set
    /// against.
    commit_size: CommitSizes,
}

/// How many commits of each declared kind were read.
#[derive(Debug, Serialize)]
struct CommitKinds {
    /// Commits prefixed `fix`.
    fix: usize,
    /// Commits prefixed `feat`.
    feat: usize,
    /// Everything else, including commits with no prefix at all.
    other: usize,
}

/// The distribution of files per commit.
#[derive(Debug, Serialize)]
struct CommitSizes {
    /// Half the commits touch this many files or fewer.
    median: usize,
    /// Three quarters of them do.
    p75: usize,
    /// Nine tenths of them do.
    p90: usize,
    /// The largest commit read.
    largest: usize,
}

/// What `seam` reports.
#[derive(Debug, Serialize)]
struct EvaluationReport<'a> {
    /// Shape of this document.
    schema_version: u32,
    /// The ledger against the history.
    #[serde(flatten)]
    evaluation: &'a codehelion_seam::Evaluation,
}

/// What `seam --suggest` reports.
#[derive(Debug, Serialize)]
struct SuggestReport<'a> {
    /// Shape of this document.
    schema_version: u32,
    /// The candidates and what is behind each.
    #[serde(flatten)]
    suggestion: &'a codehelion_seam::Suggestion,
}

/// What `guard` reports about a change.
#[derive(Debug, Serialize)]
struct GuardReport<'a> {
    /// Shape of this document.
    schema_version: u32,
    /// How many seams the ledger holds.
    ledger_seams: usize,
    /// How many paths the change touched.
    changed_paths: usize,
    /// The seams changed on one side only.
    #[serde(flatten)]
    report: &'a codehelion_seam::GuardReport,
}

/// What `guard --paths` reports.
#[derive(Debug, Serialize)]
struct LookupReport<'a> {
    /// Shape of this document.
    schema_version: u32,
    /// Each path and the seams it sits in.
    paths: &'a [codehelion_seam::PathLookup],
}

/// Render `history` for a reader.
///
/// The renderers below write into a `String` rather than into the destination
/// directly, because the destination may be a file this run refuses to
/// overwrite: composing the whole report first means that refusal happens
/// before anything has been written rather than halfway through.
///
/// # Errors
///
/// Returns an error only if formatting into a string fails, which it does not.
fn render_history(report: &HistoryReport) -> Result<String> {
    let mut text = String::new();
    let range = &report.range;
    match (&range.first, &range.last) {
        (Some(first), Some(last)) => writeln!(
            text,
            "history: {} commits, {}..{}",
            range.commits,
            first.abbreviated(),
            last.abbreviated()
        )?,
        _ => writeln!(text, "history: no commits")?,
    }
    writeln!(
        text,
        "  declared kinds    fix {}, feat {}, other {}",
        report.kinds.fix, report.kinds.feat, report.kinds.other
    )?;
    writeln!(
        text,
        "  files per commit  median {}, p75 {}, p90 {}, largest {}",
        report.commit_size.median,
        report.commit_size.p75,
        report.commit_size.p90,
        report.commit_size.largest
    )?;
    if report.shallow {
        writeln!(text, "  history is cut by a shallow clone")?;
    }
    Ok(text)
}

/// Render `seam` for a reader.
///
/// # Errors
///
/// Returns an error only if formatting into a string fails, which it does not.
fn render_evaluation(evaluation: &codehelion_seam::Evaluation) -> Result<String> {
    let mut text = String::new();
    if evaluation.seams.is_empty() {
        writeln!(
            text,
            "seams: none written down; add a [[seam]] entry to codehelion.toml to track one"
        )?;
        return Ok(text);
    }
    writeln!(
        text,
        "seams: {} over {} commits (settings {})",
        evaluation.seams.len(),
        evaluation.range.commits,
        abbreviated_digest(&evaluation.settings_digest)
    )?;
    for metrics in &evaluation.seams {
        write!(
            text,
            "  {}  asymmetric {}, breached {}",
            metrics.id, metrics.asymmetric_changes, metrics.breaches
        )?;
        if let Some(last) = &metrics.last_breach {
            write!(text, ", last breach {}", last.abbreviated())?;
        }
        writeln!(text)?;
        if let Some(note) = &metrics.note {
            writeln!(text, "    {note}")?;
        }
        for member in &metrics.members {
            writeln!(text, "    member  {member}")?;
        }
    }
    Ok(text)
}

/// Render `seam --suggest` for a reader.
///
/// # Errors
///
/// Returns an error only if formatting into a string fails, which it does not.
fn render_suggestion(suggestion: &codehelion_seam::Suggestion) -> Result<String> {
    let mut text = String::new();
    writeln!(
        text,
        "seam candidates: {} over {} commits (settings {})",
        suggestion.candidates.len(),
        suggestion.range.commits,
        abbreviated_digest(&suggestion.settings_digest)
    )?;
    if suggestion.candidates.is_empty() {
        writeln!(
            text,
            "  nothing reached both floors; lower min-coupling or min-support to see more"
        )?;
        return Ok(text);
    }
    for candidate in &suggestion.candidates {
        writeln!(
            text,
            "  coupling {:.2}  support {:>4}  {} <-> {}{}",
            candidate.coupling,
            candidate.support,
            candidate.left,
            candidate.right,
            if candidate.in_ledger {
                "  (already in the ledger)"
            } else {
                ""
            }
        )?;
    }
    writeln!(
        text,
        "  nothing here was written to the ledger; promoting a candidate is yours to do"
    )?;
    Ok(text)
}

/// Render `guard` for a reader.
///
/// # Errors
///
/// Returns an error only if formatting into a string fails, which it does not.
fn render_guard(report: &codehelion_seam::GuardReport, ledger_seams: usize) -> Result<String> {
    let mut text = String::new();
    if ledger_seams == 0 {
        writeln!(text, "guard: no seams are written down in codehelion.toml")?;
        return Ok(text);
    }
    let seams = plural(ledger_seams, "seam");
    if report.is_empty() {
        writeln!(
            text,
            "guard: {ledger_seams} {seams}, none changed on one side only"
        )?;
        return Ok(text);
    }
    writeln!(
        text,
        "guard: {} of {ledger_seams} {seams} changed on one side only",
        report.seams.len()
    )?;
    for verdict in &report.seams {
        writeln!(text, "  {}", verdict.id)?;
        for member in &verdict.touched {
            writeln!(text, "    changed    {member}")?;
        }
        for member in &verdict.untouched {
            writeln!(text, "    unchanged  {member}")?;
        }
    }
    Ok(text)
}

/// Render `guard --paths` for a reader.
///
/// # Errors
///
/// Returns an error only if formatting into a string fails, which it does not.
fn render_lookup(lookups: &[codehelion_seam::PathLookup]) -> Result<String> {
    let mut text = String::new();
    for lookup in lookups {
        writeln!(text, "{}", lookup.path)?;
        if lookup.seams.is_empty() {
            writeln!(text, "  in no seam")?;
            continue;
        }
        for placement in &lookup.seams {
            writeln!(text, "  {} via {}", placement.seam, placement.member)?;
            for other in &placement.other_members {
                writeln!(text, "    moves with  {other}")?;
            }
        }
    }
    Ok(text)
}

/// A noun as a count of that many, so a report does not say "1 seams".
fn plural(count: usize, noun: &str) -> String {
    if count == 1 {
        noun.to_string()
    } else {
        format!("{noun}s")
    }
}

/// The leading part of a settings digest a text report prints.
fn abbreviated_digest(digest: &str) -> &str {
    &digest[..DIGEST_PREFIX.min(digest.len())]
}

/// How much of a settings digest a text report prints.
///
/// Enough to tell two configurations apart at a glance, with the whole digest
/// in the JSON for anything that compares them properly.
const DIGEST_PREFIX: usize = 12;
