//! Core library for the `codehelion` command-line tool.
//!
//! The binary in `main.rs` is a thin wrapper: it parses arguments into
//! [`cli::Cli`] and hands them to [`run`]. Keeping the logic here makes it
//! directly unit-testable without spawning a process.
//!
//! [`cli`] is the command layer; the engine lives in the `codehelion-core`
//! crate. This crate is the composition root: it wires the per-language
//! frontends and the store crate into the core engine, while `core` itself
//! depends on none of them.
//!
//! # Exit status
//!
//! `run` returns an [`Outcome`] that maps to a process exit code: `0` on
//! success (whether or not findings were reported), and [`EXIT_FINDINGS`] when
//! a scan reported findings and `--fail-on-findings` was set. Any error maps to
//! `1` in `main`, and `clap` uses `2` for usage errors. Commands whose engine
//! or store support is not built yet fail with an explicit message.

pub mod artifact;
pub mod baseline;
pub mod cli;
pub mod config;
pub mod report;
pub mod scan;
pub mod semantic;
pub mod suppress;

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use codehelion_core::doctor;
use codehelion_store::Store;

use crate::cli::{
    ArtifactAction, BaselineAction, CacheAction, Cli, Command, ConfigAction, DetailFormat,
    ExplainArgs, Mode, ScanArgs,
};
use crate::config::ConfigSource;

/// Exit code returned when a scan reports findings and gating is requested.
pub const EXIT_FINDINGS: u8 = 3;

/// Successful command outcome, carrying the process exit status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The command completed; exit `0`.
    Success,
    /// A scan reported findings and `--fail-on-findings` was set; exit
    /// [`EXIT_FINDINGS`].
    FindingsPresent,
}

impl Outcome {
    /// Process exit code for this outcome.
    #[must_use]
    pub fn exit_code(self) -> ExitCode {
        match self {
            Self::Success => ExitCode::SUCCESS,
            Self::FindingsPresent => ExitCode::from(EXIT_FINDINGS),
        }
    }
}

/// Execute the parsed command, writing output to stdout.
///
/// # Errors
///
/// Returns an error if a command fails, including commands whose support is not
/// built in this release.
pub fn run(cli: &Cli) -> Result<Outcome> {
    let stdout = io::stdout();
    let mut out = stdout.lock();
    dispatch(&cli.command, &mut out)
}

/// Dispatch a command to the given writer.
///
/// Separated from [`run`] so tests can capture output into an in-memory buffer.
fn dispatch(command: &Command, out: &mut impl Write) -> Result<Outcome> {
    match command {
        Command::Doctor => {
            // The lookup is supplied here rather than by the engine: starting
            // a program is this layer's business, and keeping it out of the
            // engine is what stops a compiler helper from becoming something
            // the analysis crates link.
            doctor::render(
                &doctor::diagnose_with(&|name| {
                    interrogate(
                        name,
                        None,
                        codehelion_helper::SandboxRequest::unrestricted(),
                    )
                }),
                out,
            )?;
            writeln!(out, "  {}", codehelion_helper::doctor_summary())?;
            writeln!(
                out,
                "  restricted semantic rules: {} enabled (registry {})",
                codehelion_core::semantic::registered_rules().len(),
                codehelion_core::semantic::SEMANTIC_RULE_REGISTRY_VERSION,
            )?;
            doctor_install(out)?;
            doctor_database(out)?;
            doctor_artifacts(out)?;
            Ok(Outcome::Success)
        }
        Command::Config { action } => config_command(action, out),
        Command::Cache { action } => cache_command(action, out),
        Command::Scan(args) => scan_command(args, out),
        Command::Explain(args) => explain(args, out),
        Command::Baseline { action } => baseline(action, out),
        Command::Artifact { action } => match action {
            ArtifactAction::Analyze(args) => artifact::run(args, out),
            ArtifactAction::Compare(args) => artifact::compare(args, out),
            ArtifactAction::Calibration(args) => artifact::calibration(args, out),
        },
    }
}

/// How long a diagnostic waits for a helper to introduce itself.
///
/// Shorter than a scan's, because a handshake reads nothing: a helper that
/// takes longer than this to say its own name is one a person is waiting on,
/// and reporting it as unusable with the reason beats hanging the command that
/// exists to explain what is wrong.
const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Find a helper and ask it what it is.
///
/// Going as far as the handshake rather than stopping at the path, because a
/// program being on disk says nothing about whether this build can talk to it,
/// which compiler will answer, or what it will answer about. All three decide
/// whether a semantic run is worth starting.
///
/// The helper is shut down again. `doctor` inspects; it does not leave a
/// process running behind a command that printed a table and returned. The
/// caller supplies containment so semantic discovery and later analysis start
/// under the same policy.
fn interrogate(
    name: &str,
    configured: Option<&Path>,
    sandbox: codehelion_helper::SandboxRequest,
) -> Option<doctor::HelperFacts> {
    let path = codehelion_helper::locate(name, configured)?;
    let state =
        match codehelion_helper::Helper::start_with_sandbox(&path, &[], HANDSHAKE_TIMEOUT, sandbox)
        {
            Ok(helper) => {
                let identity = helper.identity();
                let greeting = doctor::Greeting {
                    version: identity.version.clone(),
                    protocol: helper.protocol_version(),
                    toolchains: identity.toolchains.clone(),
                    capabilities: identity
                        .capabilities
                        .iter()
                        .map(|capability| capability.name().to_string())
                        .collect(),
                    executes: identity
                        .executes
                        .iter()
                        .map(|execution| execution.name().to_string())
                        .collect(),
                    // Asked of the conversation rather than worked out from the
                    // number beside it: which revision can carry which request is
                    // the protocol's business, and a diagnostic that decided it
                    // here would go stale the first time a request was added.
                    predates: helper
                        .predates()
                        .into_iter()
                        .map(ToString::to_string)
                        .collect(),
                };
                // Failing to stop cleanly is not a reason to withhold what it
                // already said: the answer was given before the goodbye.
                drop(helper.shutdown());
                doctor::HelperState::Answered(greeting)
            }
            Err(error) => doctor::HelperState::Silent(format!("{error}")),
        };
    Some(doctor::HelperFacts { path, state })
}

/// Describe artifact formats this build can inspect without running them.
///
/// Kept in the composition root alongside helper discovery: format backends
/// are optional CLI capabilities and are not dependencies of the source
/// clone engine.
fn doctor_artifacts(out: &mut impl Write) -> Result<()> {
    writeln!(out, "  artifacts:")?;
    writeln!(out, "    wasm: available (core modules; wasmparser)")?;
    writeln!(out, "    elf: available (sized text symbols; object)")?;
    writeln!(out, "    macho: recognised, parser unavailable")?;
    writeln!(out, "    pe-coff: recognised, parser unavailable")?;
    writeln!(out, "    archive: recognised, parser unavailable")?;
    Ok(())
}

fn scan_command(args: &ScanArgs, out: &mut impl Write) -> Result<Outcome> {
    if args.compare_languages && args.mode != Mode::Semantic {
        bail!("--compare-languages requires --mode semantic");
    }
    // Resolved before the mode is dispatched on, because a permission that
    // nothing in the chosen mode could act on is refused rather than accepted:
    // Fast and Structural run nothing whatever they are told, and somebody who
    // granted an execution to one of them is owed the sentence saying so.
    let permitted = scan::permitted(args)?;
    match args.mode {
        Mode::Semantic => scan::structural::semantic(args, &permitted, out),
        Mode::Structural => scan::structural::run(args, out),
        Mode::Fast => scan::run(args, out),
    }
}

/// Look one occurrence up by its stable finding id and print its detail.
///
/// Both output formats render the same [`report::FindingDetail`] value, in
/// the shape a scan report's member entries use.
#[allow(
    clippy::too_many_lines,
    reason = "the lookup and both reporter forms share one complete finding detail"
)]
fn explain(args: &ExplainArgs, out: &mut impl Write) -> Result<Outcome> {
    let path = resolve_db(args.db.as_deref())?;
    if !path.is_file() {
        bail!(
            "no local database at {}; run `codehelion scan` first",
            path.display()
        );
    }
    let store = Store::open(&path)?;
    let Some(occurrence) = store.occurrence(&args.finding_id)? else {
        bail!(
            "no occurrence with finding id {} in {}",
            args.finding_id,
            path.display()
        );
    };
    let source_artifact_mappings = store
        .artifact_fragment_mappings(&args.finding_id)?
        .into_iter()
        .map(|mapping| report::SourceArtifactMappingDetail {
            artifact_analysis_id: mapping.analysis_id,
            artifact_symbol_fingerprint: mapping_fingerprint_hex(
                mapping.artifact_symbol_fingerprint,
            ),
            source_build_variant_fingerprint: mapping_fingerprint_hex(
                mapping.source_build_variant_fingerprint,
            ),
            artifact_build_variant_fingerprint: mapping_fingerprint_hex(
                mapping.build_variant_fingerprint,
            ),
            confidence: mapping_confidence_label(mapping.confidence).to_owned(),
            evidence: mapping.evidence,
            attributed_bytes: mapping.attributed_bytes,
        })
        .collect();
    let clone_group_savings = store
        .clone_group_savings(occurrence.scan_run_id, &occurrence.group_fingerprint_hex)?
        .into_iter()
        .map(|(artifact_analysis_id, savings)| {
            Ok(report::CloneGroupSavingsDetail {
                artifact_analysis_id,
                source_build_variant_fingerprint: mapping_fingerprint_hex(
                    savings.source_build_variant_fingerprint,
                ),
                artifact_build_variant_fingerprint: mapping_fingerprint_hex(
                    savings.artifact_build_variant_fingerprint,
                ),
                duplicated_bytes: savings.duplicated_bytes,
                estimated_refactor_savings_bytes: savings.estimated_refactor_savings_bytes,
                mapping_confidence: savings_confidence_label(savings.mapping_confidence).to_owned(),
                clone_confidence: savings.clone_confidence,
                model_confidence: savings_confidence_label(savings.model_confidence).to_owned(),
                savings_confidence: savings_confidence_label(savings.savings_confidence).to_owned(),
                model_schema_version: savings.model_schema_version,
                assumptions: serde_json::from_str(&savings.assumptions_json)
                    .context("parsing persisted structured savings assumptions")?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let line = |value: Option<i64>| u32::try_from(value.unwrap_or(0)).unwrap_or(0);
    let detail = report::FindingDetail {
        member: report::Member {
            finding_id: occurrence.member.finding_hex,
            content: occurrence.member.content_hex,
            file: occurrence.member.file_path,
            language: occurrence.member.language,
            start_line: line(occurrence.member.start_line),
            end_line: line(occurrence.member.end_line),
            unit: occurrence.member.unit_name,
            tokens: u64::try_from(occurrence.member.token_count).unwrap_or(0),
            canonical: occurrence.member.is_canonical,
        },
        group: report::GroupRef {
            fingerprint: occurrence.group_fingerprint_hex,
            clone_type: occurrence.clone_type,
            scope: occurrence.member_scope,
            confidence: occurrence.score,
            priority: occurrence.priority.as_ref().map(recorded_priority),
            members: u64::try_from(occurrence.member_count).unwrap_or(0),
            boilerplate: occurrence.boilerplate,
            test_code: occurrence.test_code,
            split_pair: occurrence.split_pair,
            similarity: occurrence.similarity.map(|stored| report::Similarity {
                weight_version: stored.weight_version,
                lexical: stored.lexical,
                structural: stored.structural,
                control_flow: stored.control_flow,
                type_similarity: stored.type_similarity,
                api: stored.api,
                composite: stored.composite,
                min_pairwise: stored.min_pairwise,
                confidence_band: stored.confidence_band,
            }),
            semantic: occurrence
                .semantic
                .map(|evidence| report::SemanticEvidence {
                    schema_version: evidence.schema_version,
                    rules: vec![report::SemanticRuleEvidence {
                        id: evidence.rule_id,
                        version: evidence.rule_version,
                        confidence: evidence.rule_confidence,
                    }],
                    graphs: evidence.graphs,
                    node_mappings: evidence
                        .node_mappings
                        .into_iter()
                        .map(|mapping| report::SemanticNodeMapping {
                            corresponding_member: mapping.corresponding_member,
                            canonical: mapping.canonical,
                            corresponding: mapping.corresponding,
                        })
                        .collect(),
                }),
            suppressed: occurrence.suppression.map(|rule| report::Suppression {
                kind: report::SuppressionKind::Rule,
                reason: None,
                scope: Some(rule.scope),
                pattern: Some(rule.pattern),
            }),
        },
        scan_run: occurrence.scan_run_id,
        source_artifact_mappings,
        clone_group_savings,
    };
    match args.format {
        DetailFormat::Json => write!(out, "{}", detail.to_json()?)?,
        DetailFormat::Text => detail.render_text(out)?,
    }
    Ok(Outcome::Success)
}

fn mapping_fingerprint_hex(fingerprint: [u8; 16]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut hex = String::with_capacity(fingerprint.len().saturating_mul(2));
    for byte in fingerprint {
        hex.push(char::from(HEX[usize::from(byte >> 4)]));
        hex.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    hex
}

const fn mapping_confidence_label(
    confidence: codehelion_store::artifact::ArtifactAnalysisMappingConfidence,
) -> &'static str {
    match confidence {
        codehelion_store::artifact::ArtifactAnalysisMappingConfidence::Exact => "exact",
        codehelion_store::artifact::ArtifactAnalysisMappingConfidence::Strong => "strong",
        codehelion_store::artifact::ArtifactAnalysisMappingConfidence::Weak => "weak",
        codehelion_store::artifact::ArtifactAnalysisMappingConfidence::Ambiguous => "ambiguous",
    }
}

const fn savings_confidence_label(
    confidence: codehelion_store::artifact::ArtifactAnalysisSavingsConfidence,
) -> &'static str {
    match confidence {
        codehelion_store::artifact::ArtifactAnalysisSavingsConfidence::High => "high",
        codehelion_store::artifact::ArtifactAnalysisSavingsConfidence::Medium => "medium",
        codehelion_store::artifact::ArtifactAnalysisSavingsConfidence::Low => "low",
        codehelion_store::artifact::ArtifactAnalysisSavingsConfidence::Unavailable => "unavailable",
    }
}

/// A stored ranking as the detail view shows it.
///
/// A count that will not fit is reported at the ceiling rather than wrapping:
/// a group with more occurrences than a `u64` can hold is past anything the
/// derivation would say about it anyway.
fn recorded_priority(stored: &codehelion_store::query::StoredPriority) -> report::RecordedPriority {
    let count = |value: i64| u64::try_from(value).unwrap_or(u64::MAX);
    report::RecordedPriority {
        value: stored.final_priority,
        clone_confidence: stored.clone_confidence,
        maintenance_risk: stored.maintenance_risk,
        refactoring_difficulty: stored.refactoring_difficulty,
        semantic_confidence: stored.semantic_confidence,
        source_artifact_confidence: stored.source_artifact_confidence,
        savings_confidence: stored.savings_confidence,
        inputs: report::RecordedInputs {
            smallest_member_tokens: count(stored.facts.smallest_member_tokens),
            largest_member_tokens: count(stored.facts.largest_member_tokens),
            instances: count(stored.facts.instances),
            files: count(stored.facts.files),
            directories: count(stored.facts.directories),
            languages: count(stored.facts.languages),
            min_clone_tokens: stored.facts.min_clone_tokens.map(count),
        },
    }
}

/// Append the binary's install channel and location to the doctor report.
fn doctor_install(out: &mut impl Write) -> Result<()> {
    let exe = std::env::current_exe().context("resolving the executable path")?;
    writeln!(out)?;
    writeln!(
        out,
        "  install: {} ({})",
        install_channel(&exe),
        exe.display()
    )?;
    Ok(())
}

/// The distribution channel this binary appears to come from, inferred from
/// its on-disk location. A heuristic for diagnostics only: an unrecognised
/// location reports as a standalone install rather than failing.
fn install_channel(exe: &Path) -> &'static str {
    let components: Vec<String> = exe
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect();
    let has = |name: &str| components.iter().any(|c| c == name);
    if has("Cellar") || has("homebrew") || has(".linuxbrew") {
        return "homebrew";
    }
    if has(".cargo") {
        return "cargo (crates.io)";
    }
    if has("site-packages") {
        return "pypi";
    }
    let is_cargo_target = components
        .iter()
        .zip(components.iter().skip(1))
        .any(|(a, b)| a == "target" && (b == "debug" || b == "release"));
    if is_cargo_target {
        return "local build";
    }
    "standalone (archive or manual install)"
}

/// Append the local database's location to the doctor report, with a hint
/// when the database would be committed to version control.
fn doctor_database(out: &mut impl Write) -> Result<()> {
    let cwd = std::env::current_dir().context("resolving the current directory")?;
    let db = resolve_db(None)?;
    let db_abs = if db.is_absolute() {
        db.clone()
    } else {
        cwd.join(&db)
    };
    writeln!(out)?;
    match std::fs::metadata(&db_abs) {
        Ok(meta) => writeln!(
            out,
            "  local database: {} ({} bytes)",
            db.display(),
            meta.len()
        )?,
        Err(_) => writeln!(out, "  local database: {} (absent)", db.display())?,
    }
    if let Some(repo_root) = find_git_root(&cwd) {
        if !is_git_ignored(&repo_root, &db_abs) {
            writeln!(
                out,
                "  hint: the local database is not matched by .gitignore; \
                 consider ignoring it (for example, add `.codehelion/`)"
            )?;
        }
    }
    Ok(())
}

/// The enclosing git repository root, found by walking up for a `.git` entry.
fn find_git_root(start: &Path) -> Option<PathBuf> {
    let mut dir = Some(start);
    while let Some(current) = dir {
        if current.join(".git").exists() {
            return Some(current.to_path_buf());
        }
        dir = current.parent();
    }
    None
}

/// Whether the repository root's `.gitignore` ignores `target`.
///
/// Only the root ignore file is consulted — this backs a hint, not an access
/// decision. Paths outside the repository are reported as ignored so the
/// hint stays quiet about them.
fn is_git_ignored(repo_root: &Path, target: &Path) -> bool {
    let Ok(relative) = target.strip_prefix(repo_root) else {
        return true;
    };
    let (gitignore, _error) = ignore::gitignore::Gitignore::new(repo_root.join(".gitignore"));
    gitignore
        .matched_path_or_any_parents(relative, false)
        .is_ignore()
}

/// Freeze or prune a baseline against the last recorded scan of a tree.
///
/// Both actions read a scan that already happened rather than performing one:
/// a baseline is a judgement about a result, and taking it from the recorded
/// result keeps the judgement and the report it refers to the same thing.
fn baseline(action: &BaselineAction, out: &mut impl Write) -> Result<Outcome> {
    let (args, create) = match action {
        BaselineAction::Create(args) => (args, true),
        BaselineAction::Update(args) => (args, false),
    };
    let root = args
        .path
        .canonicalize()
        .with_context(|| format!("resolving path {}", args.path.display()))?;
    let cfg = config::load(None, &root)?.config;
    let db_path = scan::database_path(&root, args.db.as_deref(), &cfg);
    if !db_path.is_file() {
        bail!(
            "no local database at {}; run `codehelion scan` first",
            db_path.display()
        );
    }
    let store = Store::open(&db_path)?;
    let root_path = root.to_string_lossy();
    let Some(origin) = store.latest_completed_run(&root_path)? else {
        bail!(
            "{} holds no completed scan of {}; run `codehelion scan` first",
            db_path.display(),
            root.display()
        );
    };
    let groups = store.run_groups(origin.id)?;

    if create {
        if args.file.exists() && !args.force {
            bail!(
                "{} already exists; pass --force to overwrite",
                args.file.display()
            );
        }
        let recorded = baseline::Baseline::from_run(&origin, &groups, &scan::rfc3339_now());
        recorded.write(&args.file)?;
        writeln!(
            out,
            "wrote {} ({} findings frozen from run {}, {} mode)",
            args.file.display(),
            recorded.entries.len(),
            origin.id,
            origin.analysis_mode,
        )?;
        return Ok(Outcome::Success);
    }

    let existing = baseline::Baseline::load(&args.file)?;
    let fit = existing.compatibility(&origin.variant_fingerprint, &origin.detector_versions);
    if let Some(reason) = fit.mismatch {
        bail!(
            "{} does not describe run {}: {}",
            args.file.display(),
            origin.id,
            reason
        );
    }
    if let Some(caveat) = fit.caveat {
        writeln!(out, "note: {caveat}")?;
    }
    let present: std::collections::BTreeSet<String> = groups
        .iter()
        .map(|group| group.fingerprint_hex.clone())
        .collect();
    let (pruned, dropped) = existing.pruned(&present);
    pruned.write(&args.file)?;
    writeln!(
        out,
        "updated {} ({} entries kept, {} resolved and dropped)",
        args.file.display(),
        pruned.entries.len(),
        dropped.len(),
    )?;
    for id in &dropped {
        writeln!(out, "  resolved: {id}")?;
    }
    Ok(Outcome::Success)
}

fn config_command(action: &ConfigAction, out: &mut impl Write) -> Result<Outcome> {
    match action {
        ConfigAction::Show { config } => {
            let start = std::env::current_dir().context("resolving the current directory")?;
            let resolved = config::load(config.as_deref(), &start)?;
            match &resolved.source {
                ConfigSource::File(path) => writeln!(out, "# source: {}", path.display())?,
                ConfigSource::Defaults => writeln!(out, "# source: built-in defaults")?,
            }
            write!(out, "{}", resolved.config.to_toml()?)?;
            Ok(Outcome::Success)
        }
        ConfigAction::Init { output, force } => {
            let path = output
                .clone()
                .unwrap_or_else(|| PathBuf::from(config::CONFIG_FILE_NAME));
            if path.exists() && !force {
                bail!(
                    "{} already exists; pass --force to overwrite",
                    path.display()
                );
            }
            std::fs::write(&path, config::TEMPLATE)
                .with_context(|| format!("writing {}", path.display()))?;
            writeln!(out, "wrote {}", path.display())?;
            Ok(Outcome::Success)
        }
    }
}

fn cache_command(action: &CacheAction, out: &mut impl Write) -> Result<Outcome> {
    match action {
        CacheAction::Status { db } => {
            let path = resolve_db(db.as_deref())?;
            match std::fs::metadata(&path) {
                Ok(meta) => writeln!(out, "database: {} ({} bytes)", path.display(), meta.len())?,
                Err(_) => writeln!(out, "database: {} (absent)", path.display())?,
            }
            Ok(Outcome::Success)
        }
        CacheAction::Clear { db } => {
            let path = resolve_db(db.as_deref())?;
            if path.exists() {
                std::fs::remove_file(&path)
                    .with_context(|| format!("removing {}", path.display()))?;
                writeln!(out, "removed {}", path.display())?;
            } else {
                writeln!(out, "nothing to remove at {}", path.display())?;
            }
            Ok(Outcome::Success)
        }
    }
}

/// Resolve the local-database path: an explicit flag wins, otherwise the
/// configured location (discovered `codehelion.toml` or defaults).
fn resolve_db(flag: Option<&Path>) -> Result<PathBuf> {
    if let Some(path) = flag {
        return Ok(path.to_path_buf());
    }
    let start = std::env::current_dir().context("resolving the current directory")?;
    Ok(config::load(None, &start)?.config.database)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn cross_language_comparison_requires_semantic_mode() {
        let args = ScanArgs {
            path: PathBuf::from("."),
            mode: Mode::Fast,
            format: cli::Format::Text,
            output: None,
            config: None,
            no_ignore: false,
            jobs: None,
            db: None,
            baseline: None,
            allow_execution: None,
            compare_build_variants: false,
            compare_languages: true,
            show_suppressed: false,
            verbose: false,
            fail_on_findings: false,
            untrusted: false,
        };
        let error = scan_command(&args, &mut Vec::new()).expect_err("mode must be semantic");
        assert!(format!("{error:#}").contains("--compare-languages requires --mode semantic"));
    }

    #[test]
    fn dispatch_doctor_writes_diagnostics() {
        let mut buffer = Vec::new();
        let outcome = dispatch(&Command::Doctor, &mut buffer).expect("dispatch should succeed");
        assert_eq!(outcome, Outcome::Success);
        let text = String::from_utf8(buffer).expect("output is utf-8");
        assert!(text.contains("codehelion"));
        assert!(text.contains(env!("CARGO_PKG_VERSION")));
        // The test binary runs from the cargo target directory.
        assert!(text.contains("install: local build"));
        assert!(text.contains("OS memory, network, and filesystem containment unavailable"));
        assert!(text.contains("artifacts:"));
        assert!(text.contains("wasm: available"));
        assert!(text.contains("restricted semantic rules: 10 enabled"));
    }

    #[test]
    fn interrogating_a_helper_honours_the_requested_containment() {
        let program = tempfile::NamedTempFile::new().expect("creating placeholder helper");
        let facts = interrogate(
            "placeholder-helper",
            Some(program.path()),
            codehelion_helper::SandboxRequest::require_memory_limit(4096),
        )
        .expect("configured file is considered for interrogation");
        let doctor::HelperState::Silent(why) = facts.state else {
            panic!("an unenforceable limit must stop before starting: {facts:?}");
        };
        assert!(
            why.contains("OS memory containment is unavailable"),
            "{why}"
        );
    }

    #[test]
    fn install_channel_is_inferred_from_the_executable_location() {
        let channel = |path: &str| install_channel(Path::new(path));
        assert_eq!(
            channel("/opt/homebrew/Cellar/codehelion/0.1.0/bin/codehelion"),
            "homebrew"
        );
        assert_eq!(channel("/home/user/.linuxbrew/bin/codehelion"), "homebrew");
        assert_eq!(
            channel("/home/user/.cargo/bin/codehelion"),
            "cargo (crates.io)"
        );
        assert_eq!(
            channel("/venv/lib/python3.12/site-packages/codehelion/bin/codehelion"),
            "pypi"
        );
        assert_eq!(
            channel("/work/codehelion/target/release/codehelion"),
            "local build"
        );
        assert_eq!(
            channel("/usr/local/bin/codehelion"),
            "standalone (archive or manual install)"
        );
    }

    #[test]
    fn findings_outcome_maps_to_dedicated_exit_code() {
        assert_eq!(Outcome::Success.exit_code(), ExitCode::SUCCESS);
        assert_eq!(
            Outcome::FindingsPresent.exit_code(),
            ExitCode::from(EXIT_FINDINGS)
        );
    }
}
