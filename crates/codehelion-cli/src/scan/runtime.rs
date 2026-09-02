//! Scan resource limits, discovery, parallel mapping, and database confinement.

#![allow(
    clippy::redundant_pub_crate,
    reason = "the implementation module shares runtime helpers across scan modes"
)]

use std::sync::atomic::{AtomicUsize, Ordering};

use codehelion_core::config::{
    DiscoveryLimits, GroupingLimits, PairingLimits, ProcessLimits, StageLimits, VerificationLimits,
};

use super::{
    Config, Context, DEFAULT_SCAN_LINES, DiscoveryConfig, DiscoveryReport, EngineConfig, Frontend,
    GeneratedMarkers, Glob, GlobSet, GlobSetBuilder, Language, LanguageSelection, LexedSource,
    LiteralNorm, LiteralNormalization, Path, Result, ScanArgs, SourceUnit, bail, discovery,
    path_key, report, suppress,
};
use crate::provenance::FromScannedTree;

mod database;

pub(crate) use database::{
    DatabaseUse, database_path, database_path_for, incompatible_database_advice,
    incompatible_database_replacement, readable_here, scan_database_path,
};

/// Maximum parser workers accepted from either the command line or config.
///
/// A deliberate user value can use more workers than the automatic setting,
/// but never enough to turn an accidental large value into a resource-exhaustion
/// request.
pub(super) fn maximum_jobs() -> usize {
    std::thread::available_parallelism()
        .map_or(1, std::num::NonZeroUsize::get)
        .saturating_mul(4)
}

/// Resolve the worker-thread count: flag over configuration over the number
/// of available CPUs, with an explicit resource ceiling.
pub(crate) fn effective_jobs(flag: Option<usize>, configured: Option<usize>) -> Result<usize> {
    match flag.or(configured) {
        Some(0) => bail!("jobs must be at least 1"),
        Some(jobs) => Ok(jobs.min(maximum_jobs())),
        None => Ok(std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get)),
    }
}

/// The configuration a scan actually works under, once the command line has
/// had its say, and what to report about it.
///
/// The profile only ever *lowers* a ceiling. A configuration already stricter
/// than the profile stays where it is: taking the profile's number outright
/// would let asking for less trust loosen a deliberately tight setting, which
/// is the opposite of what asking for it means.
///
/// The candidate ceiling is set rather than clamped because leaving it unset
/// means "each pass keeps its own default", and every one of those defaults is
/// above the profile's number.
pub(crate) fn guarded(mut cfg: Config, args: &ScanArgs) -> (Config, Option<report::Guardrails>) {
    // Undoing a default the tool applied unasked, for this run only: the
    // configuration file is not edited and the next run hides them again.
    if args.include_vendored {
        cfg.suppression.vendored_paths.clear();
    }
    if !args.untrusted {
        return (cfg, None);
    }
    let profile = codehelion_core::execution::Limits::untrusted();
    cfg.limits.clamp_to_untrusted(&profile);
    announce_process_memory(&hold_this_process_to(&StageLimits::of(&profile).process));
    let guardrails =
        report::Guardrails::untrusted_under(&cfg.limits, &profile, enforced_ceilings(args.mode));
    (cfg, Some(guardrails))
}

/// Which of the configured ceilings a mode's own stages actually consult.
///
/// The ceilings [`stage_limits`] hands to discovery, pairing and the process
/// are taken by every source mode. The rest belong to stages only some modes
/// run, and a mode that reports one it never consults is describing a bound
/// nothing held it to. Stated here, beside the mapping that hands each stage
/// its ceiling, so the answer is given once rather than restated by whoever
/// prints it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Ceiling {
    /// Precise verification: the pair allowance and the alignment cell count.
    Verification,
    /// The largest related component refined as one group.
    Grouping,
    /// The estimated-Jaccard band and the near-miss retention ceiling.
    NearMatch,
    /// The two post-grouping sibling channels and their caps.
    Siblings,
}

/// The ceilings one mode's stages take, as the list of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct EnforcedCeilings(&'static [Ceiling]);

impl EnforcedCeilings {
    /// Whether this mode's own stages consult `ceiling`.
    #[must_use]
    pub(crate) fn holds(self, ceiling: Ceiling) -> bool {
        self.0.contains(&ceiling)
    }
}

/// The ceilings `mode` holds itself to.
///
/// Fast lexes and pairs. It verifies a candidate by comparing tokens rather
/// than by alignment, compares whole units so nothing needs refining to a
/// component ceiling, and runs neither the near-match band nor either sibling
/// sweep — see [`engine_config`], which gives the engine the pairing limits
/// and nothing else. Structural and Semantic build the stages that hold the
/// rest (`scan::structural::suppression::structural_config`).
pub(crate) const fn enforced_ceilings(mode: crate::cli::Mode) -> EnforcedCeilings {
    match mode {
        crate::cli::Mode::Fast => EnforcedCeilings(&[]),
        crate::cli::Mode::Structural | crate::cli::Mode::Semantic => EnforcedCeilings(&[
            Ceiling::Verification,
            Ceiling::Grouping,
            Ceiling::NearMatch,
            Ceiling::Siblings,
        ]),
    }
}

/// The ceilings this run's stages work under.
///
/// The one place a configured ceiling becomes stage configuration. A stage that
/// read the configuration for itself is how a number came to be reported as
/// applied while the stage that was supposed to hold it kept its own default,
/// so a stage takes its ceilings from here or does not have them.
///
/// `None` means the stage keeps the default measured for it, which is not the
/// same number at every stage.
pub(crate) const fn stage_limits(cfg: &Config) -> StageLimits {
    // Exhaustively destructured on purpose: a ceiling added to the
    // configuration stops this compiling until it has been given a stage.
    let crate::config::Limits {
        max_file_bytes,
        parse_timeout_ms,
        helper_timeout_ms,
        posting_cap,
        pair_budget,
        max_component,
        verification_budget,
        max_alignment_cells,
        // The near-match band and the two sibling channels exist only in the
        // structural pipeline, which builds its own stage configuration from
        // these and has no counterpart in the other modes.
        near_miss_delta: _,
        near_miss_cap: _,
        sibling_candidate_budget: _,
        sibling_per_group_cap: _,
        sibling_total_cap: _,
        signature_sibling_candidate_budget: _,
        signature_sibling_per_group_cap: _,
        signature_sibling_total_cap: _,
        signature_sibling_max_units_per_signature: _,
    } = &cfg.limits;
    StageLimits {
        discovery: DiscoveryLimits {
            max_file_bytes: *max_file_bytes,
            parse_timeout: std::time::Duration::from_millis(*parse_timeout_ms),
        },
        pairing: PairingLimits {
            posting_cap: *posting_cap,
            pair_budget: *pair_budget,
        },
        grouping: GroupingLimits {
            max_component: *max_component,
        },
        verification: VerificationLimits {
            verification_budget: *verification_budget,
            max_alignment_cells: *max_alignment_cells,
        },
        process: ProcessLimits {
            // A configuration states no memory ceiling: only a profile does,
            // and `guarded` puts that one into force for the whole run.
            max_memory_bytes: None,
            helper_timeout: std::time::Duration::from_millis(*helper_timeout_ms),
        },
    }
}

/// What became of the memory ceiling a profile states for this process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ProcessMemory {
    /// The profile states no ceiling.
    Unbounded,
    /// The operating system now holds this process to `bytes`.
    Held {
        /// The installed ceiling.
        bytes: u64,
    },
    /// A ceiling was stated and could not be installed.
    Unenforceable {
        /// The ceiling that was asked for.
        bytes: u64,
        /// What the operating system or this build said about it.
        reason: String,
    },
    /// Left uninstalled while this crate's own tests run. The ceiling is
    /// process-wide and cannot be lifted again, so a test that installed one
    /// would impose it on every other test sharing the process.
    Withheld {
        /// The ceiling that was asked for.
        bytes: u64,
    },
}

/// Put a profile's memory ceiling into force for the scanner process.
///
/// The ceilings that bound one file, one posting list or one component all act
/// after the bytes have been read; a tree of files each just under the size
/// ceiling costs whatever their total is. This is the one that bounds the run
/// itself, so it is installed where the profile is resolved, before any of the
/// tree has been read.
fn hold_this_process_to(limits: &ProcessLimits) -> ProcessMemory {
    let Some(bytes) = limits.max_memory_bytes else {
        return ProcessMemory::Unbounded;
    };
    if cfg!(test) {
        return ProcessMemory::Withheld { bytes };
    }
    codehelion_helper::enforce_current_process_memory_limit(bytes).map_or_else(
        |error| ProcessMemory::Unenforceable {
            bytes,
            reason: error.to_string(),
        },
        |()| ProcessMemory::Held { bytes },
    )
}

/// Say when a stated memory ceiling is not in force.
///
/// Not every platform can hold a process to one, and on those the flag still
/// buys the ceilings that are enforced inside this process — what is read, how
/// wide pairing fans out, how large a group is refined. What it does not buy is
/// a bound on the run's own memory, and a reader who was not told that would
/// take a scan of a hostile tree for a contained one.
fn announce_process_memory(outcome: &ProcessMemory) {
    if let ProcessMemory::Unenforceable { bytes, reason } = outcome {
        eprintln!(
            "note: this build cannot hold the scanner process to the {bytes}-byte memory ceiling \
             the untrusted profile states ({reason}); the run continues under the ceilings it \
             does enforce on file size, parse work, candidate pairing, grouping and verification"
        );
    }
}

/// Build the engine configuration from the effective scan configuration:
/// detection knobs plus the ceilings this run's pairing stage works under.
pub(super) fn engine_config(cfg: &Config) -> Result<EngineConfig> {
    let mut engine = EngineConfig {
        min_clone_tokens: usize::try_from(cfg.min_clone_tokens)
            .context("min-clone-tokens out of range")?,
        entropy_ratio_floor: cfg.entropy_ratio_floor,
        literals: literal_norm(cfg.literal_normalization),
        ..EngineConfig::default()
    };
    stage_limits(cfg).pairing.apply_to_engine(&mut engine);
    Ok(engine)
}

/// Map the configured literal strategy onto the engine's.
pub(crate) const fn literal_norm(setting: LiteralNormalization) -> LiteralNorm {
    match setting {
        LiteralNormalization::Preserve => LiteralNorm::Preserve,
        LiteralNormalization::Category => LiteralNorm::Category,
        LiteralNormalization::Full => LiteralNorm::Full,
    }
}

/// Run project discovery under the effective configuration.
pub(crate) fn discover_sources(
    root: &Path,
    cfg: &Config,
    no_ignore: bool,
    follow_links: bool,
    compile_commands: Option<&Path>,
) -> Result<DiscoveryReport> {
    // The read ceiling is the discovery stage's own, taken from the same
    // mapping every other stage takes its ceilings from: it bounds what a file
    // costs to read, so it has to be the number the run reports.
    let discovery_config = DiscoveryConfig {
        respect_gitignore: !no_ignore,
        max_file_bytes: stage_limits(cfg).discovery.max_file_bytes,
        languages: LanguageSelection {
            rust: cfg.languages.rust,
            c: cfg.languages.c,
            cpp: cfg.languages.cpp,
        },
        header_policy: cfg.languages.headers.into(),
        generated_markers: GeneratedMarkers::new(
            &cfg.suppression.generated_markers,
            DEFAULT_SCAN_LINES,
        ),
        compile_commands: compile_commands.map(Path::to_path_buf),
        follow_links,
    };
    Ok(discovery::discover(root, &discovery_config)?)
}

/// Apply the configured include/exclude globs to the discovered sources.
/// Returns the retained sources and how many were filtered out.
pub(crate) fn filter_globs(
    cfg: &Config,
    sources: Vec<SourceUnit>,
) -> Result<(Vec<SourceUnit>, usize)> {
    let include = build_globset(&cfg.include).context("in include globs")?;
    let exclude = build_globset(&cfg.exclude).context("in exclude globs")?;
    let before = sources.len();
    let kept: Vec<SourceUnit> = sources
        .into_iter()
        .filter(|source| {
            let path = &source.relative_path;
            include.as_ref().is_none_or(|globs| globs.is_match(path))
                && exclude.as_ref().is_none_or(|globs| !globs.is_match(path))
        })
        .collect();
    let excluded = before - kept.len();
    Ok((kept, excluded))
}

pub(crate) fn build_globset(patterns: &[String]) -> Result<Option<GlobSet>> {
    if patterns.is_empty() {
        return Ok(None);
    }
    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        builder.add(Glob::new(pattern).with_context(|| format!("glob pattern {pattern:?}"))?);
    }
    Ok(Some(builder.build()?))
}

/// What became of one source file handed to a frontend.
pub(crate) enum FileOutcome<T> {
    /// Read and analysed within the deterministic parse-work budget.
    Done(Box<T>),
    /// The file could not be read.
    #[cfg(test)]
    Unreadable,
    /// The file exceeded the configured parse-work budget; the file is
    /// excluded.
    TimedOut,
}

/// Parse-work capacity represented by one configured millisecond. The public
/// setting keeps its established unit for configuration compatibility, but the
/// decision is a pure function of input bytes rather than wall-clock load.
pub(crate) const PARSE_BYTES_PER_MILLISECOND: u64 = 256;

/// The effective byte ceiling for one frontend's deterministic parse work.
///
/// `parse-timeout-ms` is a compatibility spelling for a work budget, not a
/// wall-clock deadline. It can tighten the discovery ceiling but never loosen
/// it, so the report's two limits describe the exact enforced bound.
#[must_use]
pub(crate) fn parse_work_byte_limit(max_file_bytes: u64, budget: std::time::Duration) -> u64 {
    let milliseconds = u64::try_from(budget.as_millis()).unwrap_or(u64::MAX);
    max_file_bytes.min(milliseconds.saturating_mul(PARSE_BYTES_PER_MILLISECOND))
}

/// One source file's text, with the facts about the file itself that every
/// analysis mode records.
///
/// Fast and Structural hand the text to different frontends, but what reading
/// a file established has to be the same in both: the same lossy decoding, the
/// same in-source suppression markers, and the same line count. Two readers
/// deciding any of those separately would let one mode hide a finding the other
/// reports.
pub(crate) struct ReadSource<'a> {
    /// The file as every frontend sees it.
    pub(crate) text: std::borrow::Cow<'a, str>,
    /// The lines carrying an in-source suppression marker.
    pub(crate) marker_lines: Vec<u32>,
    /// How many lines the file holds.
    pub(crate) lines: u64,
}

/// Read one source file, or refuse it because the deterministic parse-work
/// budget does not stretch to its size.
///
/// The refusal comes before any frontend work and before the file is decoded,
/// which is what makes the budget a bound on work rather than a report of it.
pub(crate) fn read_within_budget(
    source: &SourceUnit,
    max_file_bytes: u64,
    budget: std::time::Duration,
) -> Option<ReadSource<'_>> {
    let limit = parse_work_byte_limit(max_file_bytes, budget);
    if u64::try_from(source.source_bytes.len()).unwrap_or(u64::MAX) > limit {
        return None;
    }
    let text = String::from_utf8_lossy(&source.source_bytes);
    Some(ReadSource {
        marker_lines: suppress::marker_lines(
            &FromScannedTree::found(text.as_ref()),
            source.language,
        ),
        lines: u64::try_from(text.lines().count()).unwrap_or(u64::MAX),
        text,
    })
}

/// Run `frontend` over every source, letting `jobs` worker threads claim the
/// next available source as soon as they finish their prior one.
///
/// Chunks are joined in order, so the result order equals the (deterministic)
/// discovery order regardless of thread scheduling. Files that vanished since
/// discovery or exceeded the parse-work budget are counted, not fatal. Returns the
/// analysed files plus the unreadable and timed-out counts.
///
/// A `frontend` panic is not converted into a returned error: the workspace's
/// release profile sets `panic = "abort"`, so in a shipped build a worker
/// panic already aborts the whole process before any `Result` could reach
/// this function's caller. Catching the panic here and reporting it as a
/// clean `anyhow` error would only ever run in `panic = "unwind"` builds
/// (tests, `cargo run` in dev), promising a recovery the shipped binary
/// cannot perform. Resuming the original panic keeps the one behaviour —
/// an unrecovered panic — consistent across every profile instead.
pub(crate) fn map_sources<T: Send>(
    sources: &[SourceUnit],
    jobs: usize,
    frontend: impl Fn(&SourceUnit) -> FileOutcome<T> + Sync,
) -> Result<(Vec<T>, u64, u64)> {
    if jobs == 0 {
        bail!("jobs must be at least 1");
    }
    if sources.is_empty() {
        return Ok((Vec::new(), 0, 0));
    }
    let next_source = AtomicUsize::new(0);
    let mut indexed_results: Vec<(usize, FileOutcome<T>)> = Vec::with_capacity(sources.len());
    let frontend = &frontend;
    let next_source = &next_source;
    std::thread::scope(|scope| -> Result<()> {
        let handles: Result<Vec<_>> = (0..jobs.min(sources.len()))
            .map(|_| {
                std::thread::Builder::new()
                    .spawn_scoped(scope, move || {
                        let mut results = Vec::new();
                        loop {
                            let index = next_source.fetch_add(1, Ordering::Relaxed);
                            let Some(source) = sources.get(index) else {
                                break;
                            };
                            results.push((index, frontend(source)));
                        }
                        results
                    })
                    .context("starting frontend worker thread")
            })
            .collect();
        for handle in handles? {
            match handle.join() {
                Ok(results) => indexed_results.extend(results),
                // See the function doc: this can only be reached in
                // `panic = "unwind"` builds, and resuming the panic is
                // honest about that instead of downgrading a worker bug
                // into a message claiming a recovery this build lacks.
                Err(payload) => std::panic::resume_unwind(payload),
            }
        }
        Ok(())
    })?;
    indexed_results.sort_unstable_by_key(|(index, _)| *index);
    let mut analysed = Vec::with_capacity(sources.len());
    #[cfg(test)]
    let mut unreadable = 0u64;
    #[cfg(not(test))]
    let unreadable = 0u64;
    let mut timed_out = 0u64;
    for (_, result) in indexed_results {
        match result {
            FileOutcome::Done(file) => analysed.push(*file),
            #[cfg(test)]
            FileOutcome::Unreadable => unreadable += 1,
            FileOutcome::TimedOut => timed_out += 1,
        }
    }
    Ok((analysed, unreadable, timed_out))
}

/// Lex every source with the Fast frontends.
pub(super) fn lex_sources(
    sources: &[SourceUnit],
    jobs: usize,
    max_file_bytes: u64,
    timeout: std::time::Duration,
) -> Result<(Vec<LexedSource>, u64, u64)> {
    map_sources(sources, jobs, |source| {
        lex_one(source, max_file_bytes, timeout)
    })
}

/// Read and lex one source file, enforcing the deterministic parse-work
/// budget before frontend work begins.
fn lex_one(
    source: &SourceUnit,
    max_file_bytes: u64,
    budget: std::time::Duration,
) -> FileOutcome<LexedSource> {
    let Some(read) = read_within_budget(source, max_file_bytes, budget) else {
        return FileOutcome::TimedOut;
    };
    let text = read.text;
    // One lex per file: the C-family arm paths are derived from the directives
    // that same lex passed, so no source is read twice.
    let (file, arm_paths) = match source.language {
        Language::Rust => (codehelion_frontend_rust::RustFrontend.lex(&text), None),
        Language::C => {
            let (file, paths) = codehelion_frontend_c::CFrontend.lex_with_arm_paths(&text);
            (file, Some(paths))
        }
        Language::Cpp => {
            let (file, paths) = codehelion_frontend_cpp::CppFrontend.lex_with_arm_paths(&text);
            (file, Some(paths))
        }
    };
    let unit_lines = file
        .units
        .iter()
        .map(|unit| {
            let end_line = codehelion_core::frontend::tokens_in_range(
                &file.tokens,
                unit.token_start,
                unit.token_end,
            )
            .last()
            .map_or(unit.span.start_line, |token| token.span.start_line);
            (unit.span.start_line, end_line)
        })
        .collect();
    FileOutcome::Done(Box::new(LexedSource {
        relative_path: path_key(&source.relative_path),
        language: file.language,
        frontend_version: file.frontend_version,
        tokens: file.tokens,
        arm_paths,
        units: file.units,
        unit_lines,
        marker_lines: read.marker_lines,
        lines: read.lines,
        diagnostics: file.diagnostics.len(),
    }))
}
#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use std::path::PathBuf;

    use codehelion_core::discovery::{ContentHash, TargetKind};
    use codehelion_core::execution::Limits;
    use codehelion_core::ir::{IrNode, MAX_IR_DEPTH, Shape, StructuralFrontend, SyntaxIrFile};
    use codehelion_core::semantic::SemanticCandidateConfig;

    use super::{
        EngineConfig, FileOutcome, Language, ProcessLimits, ProcessMemory, SourceUnit, StageLimits,
        engine_config, hold_this_process_to, map_sources, stage_limits,
    };
    use crate::config::Config;
    use crate::report::Guardrails;

    /// A run reports the ceilings it was given and every stage takes them from
    /// one place, so the two cannot disagree: the posting ceiling a report
    /// names is the width the registered-rule bucket index cuts at, and the
    /// component ceiling it names is what semantic grouping refines to.
    #[test]
    fn the_ceilings_a_distrusting_run_reports_are_the_ones_its_stages_take() {
        let profile = Limits::untrusted();
        let mut cfg = Config::default();
        cfg.limits.posting_cap = Some(4_096);
        cfg.limits.max_component = 4_096;
        cfg.limits.pair_budget = Some(4_000_000);
        cfg.limits.clamp_to_untrusted(&profile);
        let reported = Guardrails::untrusted(&cfg.limits, &profile);

        let stages = stage_limits(&cfg);
        let candidates = stages.pairing.semantic_candidates();
        assert_eq!(candidates.max_bucket_members, reported.posting_cap);
        assert_eq!(candidates.max_candidate_pairs, reported.pair_budget);
        assert_eq!(
            Some(stages.grouping.grouping().max_component),
            reported.max_component
        );

        let mut engine = EngineConfig::default();
        stages.pairing.apply_to_engine(&mut engine);
        assert_eq!(engine.posting_cap, reported.posting_cap);
        assert_eq!(engine.pair_budget, reported.pair_budget);
    }

    /// A mode must not name a ceiling nothing it runs ever consults. Fast
    /// lexes and pairs, so the verification, grouping, near-match and sibling
    /// ceilings are absent from what it reports rather than printed beside the
    /// ones that actually bounded the run.
    #[test]
    fn a_fast_run_reports_only_the_ceilings_its_own_stages_take() {
        let profile = Limits::untrusted();
        let mut cfg = Config::default();
        cfg.limits.clamp_to_untrusted(&profile);

        let fast = Guardrails::untrusted_under(
            &cfg.limits,
            &profile,
            super::enforced_ceilings(crate::cli::Mode::Fast),
        );
        assert_eq!(fast.verification_budget, None);
        assert_eq!(fast.max_alignment_cells, None);
        assert_eq!(fast.max_component, None);
        assert_eq!(fast.near_miss_delta, None);
        assert_eq!(fast.near_miss_cap, None);
        assert_eq!(fast.sibling_candidate_budget, None);
        assert_eq!(fast.sibling_per_group_cap, None);
        assert_eq!(fast.sibling_total_cap, None);
        assert_eq!(fast.signature_sibling_candidate_budget, None);
        assert_eq!(fast.signature_sibling_per_group_cap, None);
        assert_eq!(fast.signature_sibling_total_cap, None);
        assert_eq!(fast.signature_sibling_max_units_per_signature, None);
        // What every source mode does hold itself to is still stated, or the
        // flag would report nothing at all.
        assert_eq!(fast.max_file_bytes, profile.max_file_bytes);
        assert_eq!(fast.posting_cap, profile.posting_cap);

        // A mode whose stages take them says so, and the numbers are the ones
        // that pipeline configures its stages with.
        for mode in [crate::cli::Mode::Structural, crate::cli::Mode::Semantic] {
            let reported =
                Guardrails::untrusted_under(&cfg.limits, &profile, super::enforced_ceilings(mode));
            assert_eq!(
                reported.verification_budget,
                Some(profile.verification_budget)
            );
            assert_eq!(reported.max_component, Some(cfg.limits.max_component));
            assert!(reported.near_miss_delta.is_some());
            assert!(reported.sibling_total_cap.is_some());
        }
    }

    /// A ceiling nobody set leaves each stage at the width measured for it.
    /// One number for all of them would silently widen the narrowest stage,
    /// which is the pairing path most likely to blow up.
    #[test]
    fn a_run_with_no_configured_ceilings_leaves_each_stage_at_its_own_default() {
        let stages = stage_limits(&Config::default());
        assert_eq!(
            stages.pairing.semantic_candidates(),
            SemanticCandidateConfig::default()
        );
        let engine = engine_config(&Config::default()).expect("default engine configuration");
        assert_eq!(engine.posting_cap, EngineConfig::default().posting_cap);
        assert_eq!(engine.pair_budget, EngineConfig::default().pair_budget);
    }

    /// The discovery ceiling comes from the same mapping, because it is the
    /// one that bounds what a file costs before anything else can bound it.
    #[test]
    fn the_read_ceiling_a_distrusting_run_reports_is_the_one_discovery_takes() {
        let profile = Limits::untrusted();
        let mut cfg = Config::default();
        cfg.limits.max_file_bytes = 8 * 1024 * 1024;
        cfg.limits.clamp_to_untrusted(&profile);
        assert_eq!(
            stage_limits(&cfg).discovery.max_file_bytes,
            profile.max_file_bytes
        );
    }

    /// A profile that states no memory ceiling asks nothing of the operating
    /// system, and one that states a ceiling is answered rather than ignored.
    #[test]
    fn a_stated_memory_ceiling_is_answered_and_an_absent_one_asks_nothing() {
        let unbounded = ProcessLimits {
            max_memory_bytes: None,
            ..StageLimits::of(&Limits::untrusted()).process
        };
        assert_eq!(hold_this_process_to(&unbounded), ProcessMemory::Unbounded);

        let profile = Limits::untrusted();
        let stated = StageLimits::of(&profile).process;
        let bytes = profile
            .max_subprocess_bytes
            .expect("the untrusted profile states a memory ceiling");
        // Withheld here on purpose: this process is shared with every other
        // test, and the ceiling could not be lifted again.
        assert_eq!(
            hold_this_process_to(&stated),
            ProcessMemory::Withheld { bytes }
        );
    }

    /// Depth of nesting to put past the structural budget. The Rust frontend
    /// refuses recursive parsing above `MAX_IR_DEPTH` delimiters and the
    /// C-family walker stops descending at the same ceiling, so this exceeds
    /// both. One level per line keeps the columns short enough to check every
    /// token's position against the source.
    fn budget_exceeding_depth() -> usize {
        MAX_IR_DEPTH + 100
    }

    /// The same source shape in each language: a healthy definition holding a
    /// multi-byte literal, then a generated definition nested past the budget.
    fn agreement_sources() -> [(Language, String); 3] {
        let nest = |open: &str, inner: &str| {
            let depth = budget_exceeding_depth();
            let mut text = String::from(open);
            text.push_str(&"{\n".repeat(depth));
            text.push_str(inner);
            text.push_str(&"}\n".repeat(depth));
            text
        };
        let rust = format!(
            "fn healthy() {{\n    let marker = \"\u{3b1}\u{3b2}\u{3b3}\";\n}}\n{}",
            nest("fn generated() ", "()\n")
        );
        let c_family = format!(
            "void healthy(void) {{\n    const char *marker = \"\u{3b1}\u{3b2}\u{3b3}\";\n}}\n{}",
            nest("void generated(void) ", ";\n")
        );
        [
            (Language::Rust, rust),
            (Language::C, c_family.clone()),
            (Language::Cpp, c_family),
        ]
    }

    fn parse_structurally(language: Language, source: &str) -> SyntaxIrFile {
        match language {
            Language::Rust => codehelion_frontend_rust::ir::RustStructuralFrontend.parse(source),
            Language::C => codehelion_frontend_c::ir::CStructuralFrontend.parse(source),
            Language::Cpp => codehelion_frontend_cpp::ir::CppStructuralFrontend.parse(source),
        }
    }

    /// The 1-based line and character column of `byte`, read straight from the
    /// text. This is what every frontend's token positions are checked against.
    fn position_in(source: &str, byte: usize) -> (u32, u32) {
        let head = source.get(..byte).unwrap_or("");
        let line = head.bytes().filter(|byte| *byte == b'\n').count() + 1;
        let column = head.rsplit('\n').next().unwrap_or("").chars().count() + 1;
        (
            u32::try_from(line).unwrap_or(u32::MAX),
            u32::try_from(column).unwrap_or(u32::MAX),
        )
    }

    /// Assert what the shared assembly owns for one language's parse: token
    /// positions, the token a node begins at, and the recovery data a walk
    /// that ran out of depth budget leaves behind.
    fn assert_assembled_alike(language: Language, source: &str, file: &SyntaxIrFile) {
        let name = language.name();
        assert!(!file.tokens.is_empty(), "{name}: the file has tokens");
        for token in &file.tokens {
            assert_eq!(
                (token.span.start_line, token.span.start_column),
                position_in(source, token.span.start_byte),
                "{name}: token {:?} is reported at the wrong position",
                token.text.as_str()
            );
        }

        file.walk(&mut |node| {
            assert!(
                node.token_start <= node.token_end && node.token_end <= file.tokens.len(),
                "{name}: node token range {}..{} is not a range of the file's {} tokens",
                node.token_start,
                node.token_end,
                file.tokens.len()
            );
            if node.token_start < node.token_end {
                assert_eq!(
                    file.tokens[node.token_start].span.start_byte, node.range.start,
                    "{name}: a node of shape {:?} begins at another stream's token",
                    node.shape
                );
            }
        });

        assert!(
            file.depth_truncated,
            "{name}: a depth-limited parse is distinguished from ordinary recovery"
        );
        let mut deepest = 0;
        let mut truncation_leaves = Vec::new();
        let mut pending: Vec<(&IrNode, usize)> = file.roots.iter().map(|root| (root, 1)).collect();
        while let Some((node, depth)) = pending.pop() {
            deepest = deepest.max(depth);
            if node.shape == Shape::Error && node.children.is_empty() {
                truncation_leaves.push(node.range);
            }
            pending.extend(node.children.iter().rev().map(|child| (child, depth + 1)));
        }
        assert!(
            deepest <= MAX_IR_DEPTH,
            "{name}: IR depth {deepest} exceeds the budget {MAX_IR_DEPTH}"
        );
        assert!(
            truncation_leaves.iter().any(|range| {
                !range.is_empty() && range.end <= source.len() && file.error_ranges.contains(range)
            }),
            "{name}: the omitted region is kept as an Error leaf and an error range"
        );
        assert!(
            file.error_ranges
                .windows(2)
                .all(|pair| (pair[0].start, pair[0].end) < (pair[1].start, pair[1].end)),
            "{name}: error ranges are ordered and carry no duplicates"
        );
    }

    /// One assembly builds every Structural file, so the frontends this scan
    /// dispatches answer the same source shape the same way: the same reading
    /// of where a byte sits, the same token a node begins at, and the same
    /// recovery data when a parse runs out of depth budget. An edge case
    /// found in one language is therefore settled in all of them, and no
    /// language can drift on these concerns unnoticed.
    #[test]
    fn every_structural_frontend_assembles_positions_and_truncation_alike() {
        for (language, source) in agreement_sources() {
            let file = parse_structurally(language, &source);
            assert_assembled_alike(language, &source, &file);
        }
    }

    /// A source unit whose content this test never reads: only its presence
    /// in the slice `map_sources` walks matters.
    fn placeholder_source(relative_path: &str) -> SourceUnit {
        SourceUnit {
            relative_path: PathBuf::from(relative_path),
            absolute_path: PathBuf::from(relative_path),
            language: Language::Rust,
            is_header: false,
            content_hash: ContentHash::of(b""),
            source_bytes: Vec::new().into(),
            byte_len: 0,
            package: None,
            crate_name: None,
            target_kind: TargetKind::Library,
        }
    }

    /// A frontend worker panicking is a bug, not a recoverable condition to
    /// downgrade into a clean `anyhow` error: the shipping release profile
    /// sets `panic = "abort"`, so a worker panic there already takes the
    /// whole process down before any `Result` could reach this function's
    /// caller. `map_sources` must not pretend otherwise by swallowing the
    /// panic into `Ok`/`Err` in the builds where it technically could.
    #[test]
    #[allow(clippy::panic)]
    fn a_frontend_worker_panic_propagates_instead_of_becoming_a_swallowed_error() {
        let sources = vec![placeholder_source("panics.rs")];
        let previous_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            map_sources(&sources, 1, |_| -> FileOutcome<()> {
                panic!("a frontend worker panicked");
            })
        }));
        std::panic::set_hook(previous_hook);
        assert!(
            outcome.is_err(),
            "a worker panic must not be observed as a returned Result"
        );
    }
}
