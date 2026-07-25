//! Scan-performance benchmark support: large synthetic corpora and
//! measurement of the shipped binary.
//!
//! Three pieces, driven by the `codehelion-bench` binary:
//!
//! - [`generate_corpus`] writes a deterministic multi-language source tree
//!   of a requested size, structurally varied so it does not collapse into
//!   one clone class, with a controlled fraction of injected clones;
//! - [`measure_scan`] runs the real `codehelion` binary cold over a corpus
//!   and records wall time plus peak resident set size;
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
use codehelion_store::snapshot::{GroupRow, MemberRow, Snapshot, UnitRow};

/// Deterministic xorshift64* generator; quality is irrelevant here, only
/// reproducibility across runs and platforms.
struct Rng(u64);

impl Rng {
    const fn new(seed: u64) -> Self {
        // One splitmix64 scramble so nearby seeds diverge; the all-zero
        // fixed point is remapped.
        let mut z = seed.wrapping_add(0x9e37_79b9_7f4a_7c15);
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^= z >> 31;
        Self(if z == 0 { 1 } else { z })
    }

    const fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    /// A value in `0..bound` (`bound` must be non-zero).
    const fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound
    }
}

/// Parameters of one generated benchmark corpus.
#[derive(Debug, Clone, Copy)]
pub struct CorpusSpec {
    /// Total source lines to emit (reached within one file's overshoot).
    pub target_lines: u64,
    /// Generator seed; equal seeds produce byte-identical corpora.
    pub seed: u64,
    /// Percent of functions re-emitted as clones of an earlier function
    /// (half verbatim, half consistently renamed).
    pub clone_percent: u8,
}

/// What [`generate_corpus`] wrote.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CorpusStats {
    /// Source files written.
    pub files: u64,
    /// Source lines written.
    pub lines: u64,
    /// Functions emitted in total.
    pub functions: u64,
    /// Functions that are injected clones of an earlier one.
    pub cloned_functions: u64,
}

/// Operators sampled for binary expressions.
const BINARY_OPS: &[&str] = &["+", "^", "|", "&", "*", ">>", "<<", "%"];

/// Method calls that spice up Rust expressions.
const RUST_METHODS: &[&str] = &[
    "wrapping_add",
    "wrapping_mul",
    "wrapping_sub",
    "rotate_left",
    "rotate_right",
    "swap_bytes",
];

/// Compound-assignment operators sampled for statements.
const COMPOUND_OPS: &[&str] = &["^=", "|=", "&="];

/// One remembered function, available for clone re-emission.
struct EmittedFunction {
    language: Language,
    body: String,
    /// Identifier suffix used throughout the body, for consistent renaming.
    tag: u64,
}

/// How many earlier functions stay available as clone sources.
const CLONE_POOL: usize = 128;

/// Functions per generated file.
const FUNCTIONS_PER_FILE: u64 = 16;

/// Files per generated directory.
const FILES_PER_DIR: u64 = 64;

/// Generate a deterministic benchmark corpus under `out_dir`.
///
/// The language mix is roughly 60% Rust, 20% C and 20% C++ by file count.
/// The tree is `mod_<n>/file_<m>.<ext>`; nothing is nested deeper, which
/// keeps discovery cost proportional to file count.
///
/// # Errors
///
/// Returns an error when a directory or file cannot be written.
pub fn generate_corpus(spec: &CorpusSpec, out_dir: &Path) -> Result<CorpusStats> {
    ensure!(spec.target_lines > 0, "target size must be positive");
    ensure!(spec.clone_percent <= 100, "clone percent is a percentage");
    let mut rng = Rng::new(spec.seed);
    let mut pool: Vec<EmittedFunction> = Vec::new();
    let mut stats = CorpusStats {
        files: 0,
        lines: 0,
        functions: 0,
        cloned_functions: 0,
    };

    while stats.lines < spec.target_lines {
        let file_index = stats.files;
        let language = match file_index % 5 {
            0..=2 => Language::Rust,
            3 => Language::C,
            _ => Language::Cpp,
        };
        let dir = out_dir.join(format!("mod_{}", file_index / FILES_PER_DIR));
        std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        let extension = match language {
            Language::Rust => "rs",
            Language::C => "c",
            Language::Cpp => "cc",
        };
        let path = dir.join(format!("file_{file_index}.{extension}"));
        let text = generate_file(language, file_index, spec, &mut rng, &mut pool, &mut stats);
        stats.lines += u64::try_from(text.lines().count()).unwrap_or(0);
        stats.files += 1;
        std::fs::write(&path, text).with_context(|| format!("writing {}", path.display()))?;
    }
    Ok(stats)
}

/// Generate one source file and update the clone pool and counters.
fn generate_file(
    language: Language,
    file_index: u64,
    spec: &CorpusSpec,
    rng: &mut Rng,
    pool: &mut Vec<EmittedFunction>,
    stats: &mut CorpusStats,
) -> String {
    let mut text = String::new();
    if language == Language::C {
        text.push_str("#include <stddef.h>\n\n");
    }
    for slot in 0..FUNCTIONS_PER_FILE {
        let name = format!("work_{file_index}_{slot}");
        let clone_candidates: Vec<usize> = pool
            .iter()
            .enumerate()
            .filter(|(_, f)| f.language == language)
            .map(|(i, _)| i)
            .collect();
        let make_clone =
            !clone_candidates.is_empty() && rng.below(100) < u64::from(spec.clone_percent);
        let body = if make_clone {
            stats.cloned_functions += 1;
            let source = &pool[clone_candidates
                [usize::try_from(rng.below(clone_candidates.len() as u64)).unwrap_or(0)]];
            if rng.below(2) == 0 {
                // Verbatim re-emission: a Type-1 clone (the corpus is never
                // compiled, so duplicate symbols are harmless).
                source.body.clone()
            } else {
                // Consistent rename of every tagged identifier: a Type-2
                // clone.
                source.body.replace(&format!("_{}", source.tag), "_rn")
            }
        } else {
            // A globally unique identifier tag per fresh function: raw token
            // runs can then only repeat through deliberate clone injection,
            // while identifier-normalized (Type-2) overlap stays possible,
            // as in real code.
            let tag = 1000 + stats.functions;
            let body = generate_function(language, &name, tag, rng);
            pool.push(EmittedFunction {
                language,
                body: body.clone(),
                tag,
            });
            if pool.len() > CLONE_POOL {
                pool.remove(0);
            }
            body
        };
        stats.functions += 1;
        text.push_str(&body);
        text.push('\n');
    }
    text
}

/// Identifier context of the function being generated. Every name carries
/// the function's tag suffix, so signatures and prologues differ between
/// functions at the raw-token level too — a shared prologue would otherwise
/// hand every function pair an identical clone-sized token run, which no
/// real codebase exhibits.
struct FnNames {
    slice: String,
    len: String,
    locals: Vec<String>,
    tag: u64,
}

/// Assemble one fresh function from randomly built statements.
///
/// Bodies are grown from a recursive expression generator over a growing
/// local-variable pool, so the space of statement sequences is combinatorial
/// and unrelated functions almost never share a fragment-sized token run —
/// unlike template-based generation, which collapses into one giant clone
/// class under literal normalization. The corpus is only ever lexed, so the
/// code merely has to look real, not compile or terminate.
fn generate_function(language: Language, name: &str, tag: u64, rng: &mut Rng) -> String {
    let rust = language == Language::Rust;
    let scalar_pool = ["seed", "limit", "shift", "mask"];
    let scalar_count = 1 + rng.below(3);
    let scalars: Vec<String> = scalar_pool
        .iter()
        .take(usize::try_from(scalar_count).unwrap_or(1))
        .map(|scalar| format!("{scalar}_{tag}"))
        .collect();
    let mut names = FnNames {
        slice: format!("data_{tag}"),
        len: format!("len_{tag}"),
        locals: scalars.clone(),
        tag,
    };

    let mut body = String::new();
    if rust {
        let params = scalars
            .iter()
            .map(|scalar| format!("{scalar}: u64"))
            .collect::<Vec<_>>()
            .join(", ");
        let _ = writeln!(
            body,
            "pub fn {name}({}: &[u64], {params}) -> u64 {{",
            names.slice
        );
    } else {
        let params = scalars
            .iter()
            .map(|scalar| format!("unsigned long {scalar}"))
            .collect::<Vec<_>>()
            .join(", ");
        let _ = writeln!(
            body,
            "unsigned long {name}(const unsigned long *{}, size_t {}, {params}) {{",
            names.slice, names.len
        );
    }
    for index in 0..=rng.below(2) {
        let depth = 1 + rng.below(2);
        let value = generate_expr(rng, &names.locals, depth, rust);
        let local = format!("t{index}_{tag}");
        if rust {
            let _ = writeln!(body, "    let mut {local} = {value};");
        } else {
            let _ = writeln!(body, "    unsigned long {local} = {value};");
        }
        names.locals.push(local);
    }
    let count = 6 + rng.below(8);
    for _ in 0..count {
        let statement = generate_statement(rng, &mut names, rust);
        body.push_str(&statement);
        body.push('\n');
    }
    let result = pick(rng, &names.locals).clone();
    if rust {
        let _ = writeln!(body, "    {result}\n}}");
    } else {
        let _ = writeln!(body, "    return {result};\n}}");
    }
    body
}

/// One random statement over the current locals; may introduce a new local.
fn generate_statement(rng: &mut Rng, names: &mut FnNames, rust: bool) -> String {
    let target = pick(rng, &names.locals).clone();
    let value = generate_expr(rng, &names.locals, 2, rust);
    match rng.below(6) {
        0 if names.locals.len() < 10 => {
            let local = format!("v{}_{}", names.locals.len(), names.tag);
            names.locals.push(local.clone());
            if rust {
                format!("    let {local} = {value};")
            } else {
                format!("    unsigned long {local} = {value};")
            }
        }
        1 => {
            let op = pick(rng, COMPOUND_OPS);
            format!("    {target} {op} {value};")
        }
        2 => {
            let guard = generate_expr(rng, &names.locals, 1, rust);
            if rust {
                format!("    if {target} > {guard} {{ {target} = {value}; }}")
            } else {
                format!("    if ({target} > {guard}) {{ {target} = {value}; }}")
            }
        }
        3 => {
            let item = format!("x_{}", names.tag);
            if rust {
                format!(
                    "    for {item} in {} {{ {target} = {target} ^ (*{item} ^ {value}); }}",
                    names.slice
                )
            } else {
                format!(
                    "    for (size_t {item} = 0; {item} < {}; {item}++) {{ {target} = {target} ^ ({}[{item}] ^ {value}); }}",
                    names.len, names.slice
                )
            }
        }
        4 => {
            let guard = generate_expr(rng, &names.locals, 1, rust);
            if rust {
                format!("    while {target} > {guard} {{ {target} = {value}; }}")
            } else {
                format!("    while ({target} > {guard}) {{ {target} = {value}; }}")
            }
        }
        _ => format!("    {target} = {value};"),
    }
}

/// A random expression tree of at most `depth` operator levels.
fn generate_expr(rng: &mut Rng, locals: &[String], depth: u64, rust: bool) -> String {
    if depth == 0 || rng.below(4) == 0 {
        return if rng.below(3) == 0 {
            let literal = 2 + rng.below(997);
            if rust {
                format!("{literal}")
            } else {
                format!("{literal}UL")
            }
        } else {
            pick(rng, locals).clone()
        };
    }
    if rust && rng.below(3) == 0 {
        let method = pick(rng, RUST_METHODS);
        let receiver = pick(rng, locals).clone();
        let argument = generate_expr(rng, locals, depth - 1, rust);
        return format!("{receiver}.{method}({argument})");
    }
    let op = pick(rng, BINARY_OPS);
    let left = generate_expr(rng, locals, depth - 1, rust);
    let right = generate_expr(rng, locals, depth - 1, rust);
    format!("({left} {op} {right})")
}

/// Pick one element of a non-empty slice.
fn pick<'a, T>(rng: &mut Rng, items: &'a [T]) -> &'a T {
    &items[usize::try_from(rng.below(items.len() as u64)).unwrap_or(0)]
}

/// One cold scan of a corpus by the real binary.
#[derive(Debug)]
pub struct ScanMeasurement {
    /// Wall-clock duration of the whole scan process.
    pub wall: Duration,
    /// Peak resident set size in bytes, when the platform reports it.
    pub max_rss_bytes: Option<u64>,
    /// The scan report's summary lines, for context next to the numbers.
    pub summary: String,
}

/// Run `binary scan corpus` once, cold (fresh database), under the
/// platform's `time` wrapper to capture peak memory.
///
/// # Errors
///
/// Returns an error when the scan cannot be spawned or exits non-zero.
pub fn measure_scan(
    binary: &Path,
    corpus: &Path,
    jobs: Option<usize>,
    work_dir: &Path,
) -> Result<ScanMeasurement> {
    let db = work_dir.join("audit.db");
    let report = work_dir.join("report.txt");
    if db.exists() {
        std::fs::remove_file(&db).with_context(|| format!("removing {}", db.display()))?;
    }

    let mut command = time_wrapped_command(binary);
    command
        .arg("scan")
        .arg(corpus)
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
    let summary = std::fs::read_to_string(&report)
        .unwrap_or_default()
        .lines()
        .filter(|line| {
            line.contains("files:") || line.contains("lines:") || line.contains("clone groups:")
        })
        .collect::<Vec<_>>()
        .join("\n");
    Ok(ScanMeasurement {
        wall,
        max_rss_bytes,
        summary,
    })
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
            clone_type: CloneClass::Type1,
            member_scope: CloneScope::Unit,
            test_code: false,
            score: 1.0,
            entropy_bits: 24.0,
            suppress_reason: None,
            boilerplate: None,
            suppressed_by: None,
            final_priority: 100.0,
            similarity: None,
            members: (0..members_per_group)
                .map(|member| {
                    let index = group * members_per_group + member;
                    MemberRow {
                        content: FragmentFingerprint::from_bytes(fp(3, group)),
                        finding: FindingId::from_bytes(fp(4, index)),
                        language: Language::Rust,
                        host_unit: Some(index % units),
                        file_path: format!("mod_{}/file_{}.rs", index / 256, index),
                        start_line: 1,
                        end_line: 40,
                        token_count: 160,
                    }
                })
                .collect(),
        })
        .collect();

    let variant = BuildVariant::fast(LanguageSelection::default());
    let snapshot = Snapshot {
        root_path: "/synthetic",
        tool_version: "bench",
        config_hash: "0",
        started_at: "2026-01-01T00:00:00.000000Z",
        finished_at: "2026-01-01T00:00:01.000000Z",
        variant: &variant,
        detector_versions: &[],
        suppressions: Vec::new(),
        units: unit_rows,
        groups: group_rows,
        features: Vec::new(),
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
mod tests {
    use super::*;

    fn small_spec() -> CorpusSpec {
        CorpusSpec {
            target_lines: 2_000,
            seed: 42,
            clone_percent: 20,
        }
    }

    fn tree_digest(root: &Path) -> Vec<(String, u64, u32)> {
        let mut entries = Vec::new();
        for dir in std::fs::read_dir(root).unwrap() {
            let dir = dir.unwrap().path();
            for file in std::fs::read_dir(&dir).unwrap() {
                let file = file.unwrap().path();
                let text = std::fs::read_to_string(&file).unwrap();
                let sum = text.bytes().fold(0u32, |acc, b| {
                    acc.wrapping_mul(31).wrapping_add(u32::from(b))
                });
                entries.push((
                    file.file_name().unwrap().to_string_lossy().into_owned(),
                    u64::try_from(text.len()).unwrap(),
                    sum,
                ));
            }
        }
        entries.sort();
        entries
    }

    #[test]
    fn corpus_generation_is_deterministic_and_reaches_the_target() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        let stats_a = generate_corpus(&small_spec(), a.path()).unwrap();
        let stats_b = generate_corpus(&small_spec(), b.path()).unwrap();
        assert_eq!(stats_a, stats_b);
        assert!(stats_a.lines >= 2_000);
        assert!(stats_a.files >= 4, "several files: {}", stats_a.files);
        assert_eq!(tree_digest(a.path()), tree_digest(b.path()));
    }

    #[test]
    fn corpus_injects_clones_and_mixes_languages() {
        let dir = tempfile::tempdir().unwrap();
        let stats = generate_corpus(&small_spec(), dir.path()).unwrap();
        assert!(stats.cloned_functions > 0);
        assert!(stats.cloned_functions < stats.functions / 2);
        let digest = tree_digest(dir.path());
        for extension in [".rs", ".c", ".cc"] {
            assert!(
                digest.iter().any(|(name, ..)| Path::new(name).extension()
                    == Some(std::ffi::OsStr::new(&extension[1..]))),
                "no {extension} file generated"
            );
        }
    }

    #[test]
    fn different_seeds_produce_different_corpora() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        let mut other = small_spec();
        other.seed = 43;
        generate_corpus(&small_spec(), a.path()).unwrap();
        generate_corpus(&other, b.path()).unwrap();
        assert_ne!(tree_digest(a.path()), tree_digest(b.path()));
    }

    #[test]
    fn max_rss_parses_both_time_formats() {
        let bsd = "        3.21 real         2.90 user         0.20 sys\n         123456789  maximum resident set size\n";
        assert_eq!(parse_max_rss(bsd), Some(123_456_789));
        let gnu = "\tMaximum resident set size (kbytes): 204800\n";
        assert_eq!(parse_max_rss(gnu), Some(204_800 * 1024));
        assert_eq!(parse_max_rss("no such line"), None);
    }

    #[test]
    fn store_insert_measurement_writes_real_rows() {
        let dir = tempfile::tempdir().unwrap();
        let measurement = measure_store_insert(50, 20, 3, dir.path()).unwrap();
        assert_eq!(measurement.units, 50);
        assert_eq!(measurement.members, 60);
        let store = Store::open(&dir.path().join("store-bench.db")).unwrap();
        let run = store.latest_run().unwrap().expect("run recorded");
        assert_eq!(store.run_groups(run.id).unwrap().len(), 20);
    }
}
