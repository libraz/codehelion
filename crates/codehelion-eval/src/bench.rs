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
    GroupOrigin, GroupRow, MemberRow, PriorityRow, Snapshot, UnitRow,
};

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
///
/// Chosen against the size of a generated body rather than as a round number:
/// bodies nest, so a file of sixteen of them runs past a thousand lines, which
/// is not the shape of a source file anyone writes.
const FUNCTIONS_PER_FILE: u64 = 6;

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
    /// A local array, when the body declared one, for assignment through an
    /// element. The parameter slice cannot stand in: it is borrowed as
    /// immutable, and a corpus that does not parse measures nothing.
    buffer: Option<String>,
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
///
/// Statement *shape* is varied for the same reason, and separately, because
/// the modes that pair statement windows read a statement as its shape and
/// the kinds of its first few tokens — never its identifiers. Bodies
/// therefore mix declarations, assignments through fields and elements,
/// calls, early returns, multi-way branches and loops carrying exits, and
/// they nest, so windows are cut from blocks at several depths rather than
/// from one flat sequence per function.
///
/// It still proposes more statement-window candidates per line than real code
/// does — under three times as many, measured against a real tree a third
/// larger, where a flat body of six forms proposed nine. Read the corpus as a
/// stress case for the modes that pair statement shapes, not as a stand-in for
/// a codebase: an absolute figure taken from it is comparable across runs of
/// one generator, and to nothing else.
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
        buffer: None,
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
    // Most bodies, not all: a form every function has is a form that tells
    // two functions apart in nothing.
    if rng.below(3) > 0 {
        let buffer = format!("buf_{tag}");
        if rust {
            let _ = writeln!(body, "    let mut {buffer} = [0u64; 8];");
        } else {
            let _ = writeln!(body, "    unsigned long {buffer}[8] = {{0}};");
        }
        names.buffer = Some(buffer);
    }
    let count = 4 + rng.below(6);
    for _ in 0..count {
        let statement = generate_statement(rng, &mut names, rust, 0);
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

/// Deepest a generated statement nests its own block.
///
/// Two is enough to put windows at more than one depth without letting a
/// single statement grow to the size of a function.
const MAX_NESTING: u64 = 2;

/// Most locals one generated body carries.
const LOCAL_POOL: usize = 10;

/// Statement forms that nest nothing, and so stay available at any depth.
const LEAF_FORMS: u64 = 8;

/// Every statement form, the nesting ones included.
const ALL_FORMS: u64 = 14;

/// Indentation for a statement at `depth` levels of nesting.
fn indent(depth: u64) -> String {
    " ".repeat(usize::try_from(4 + depth * 4).unwrap_or(4))
}

/// A run of statements, as the body of a nested block.
///
/// Long enough to be cut into windows in its own right: windows are four
/// statements and up, so blocks that never reach four would leave every
/// window in the corpus coming from one flat sequence per function.
fn generate_block(rng: &mut Rng, names: &mut FnNames, rust: bool, depth: u64) -> String {
    let count = 2 + rng.below(5);
    (0..count)
        .map(|_| generate_statement(rng, names, rust, depth))
        .collect::<Vec<_>>()
        .join("\n")
}

/// One random statement over the current locals; may introduce a new local.
///
/// The forms differ in what the statement-window features read: the shape the
/// parser gives the statement, and the kinds of its first few tokens. A body
/// of assignments and `if`s is realistic at the token level and uniform at
/// this one, which is the difference between a corpus that measures Fast and
/// a corpus that measures the modes pairing statement shapes.
#[allow(clippy::too_many_lines)] // one arm per statement form; splitting hides the vocabulary
fn generate_statement(rng: &mut Rng, names: &mut FnNames, rust: bool, depth: u64) -> String {
    let pad = indent(depth);
    let target = pick(rng, &names.locals).clone();
    let value = generate_expr(rng, &names.locals, 2, rust);
    // Nesting stops widening the vocabulary once it is deep enough; below the
    // limit every form is available.
    let form = if depth >= MAX_NESTING {
        rng.below(LEAF_FORMS)
    } else {
        rng.below(ALL_FORMS)
    };
    match form {
        // No `if` guard on this arm: an arm that declines falls through to
        // the catch-all, and the catch-all nests, so a declined arm deep in a
        // body would recurse without a bottom.
        0 => {
            if names.locals.len() >= LOCAL_POOL {
                return format!("{pad}{target} = {value};");
            }
            let local = format!("v{}_{}", names.locals.len(), names.tag);
            names.locals.push(local.clone());
            // Three spellings of a declaration, because a statement is read as
            // its shape plus the kinds of its leading tokens, and these three
            // differ in those kinds: keyword-keyword-name, keyword-name-punct
            // and keyword-name-punct-name.
            match rng.below(3) {
                0 if rust => format!("{pad}let mut {local} = {value};"),
                0 => format!("{pad}register unsigned long {local} = {value};"),
                1 if rust => format!("{pad}let {local}: u64 = {value};"),
                1 => format!("{pad}const unsigned long {local} = {value};"),
                _ if rust => format!("{pad}let {local} = {value};"),
                _ => format!("{pad}unsigned long {local} = {value};"),
            }
        }
        1 => {
            let op = pick(rng, COMPOUND_OPS);
            format!("{pad}{target} {op} {value};")
        }
        2 => {
            // Assignment through an element: the leading tokens read
            // identifier-bracket rather than identifier-operator.
            let index = generate_expr(rng, &names.locals, 0, rust);
            format!(
                "{pad}{}[({index}) & 7] = {value};",
                names.buffer.clone().unwrap_or_else(|| target.clone())
            )
        }
        3 => {
            // A call in statement position, which is a shape of its own and
            // the commonest statement in real code that these bodies had none
            // of. Nothing here is ever compiled or run.
            let other = pick(rng, &names.locals).clone();
            format!("{pad}absorb_{}({target}, {other});", names.tag)
        }
        4 => {
            let argument = generate_expr(rng, &names.locals, 1, rust);
            if names.locals.len() >= LOCAL_POOL {
                return format!("{pad}{target} = blend_{}({argument});", names.tag);
            }
            let local = format!("c{}_{}", names.locals.len(), names.tag);
            names.locals.push(local.clone());
            if rust {
                format!("{pad}let {local} = blend_{}({argument});", names.tag)
            } else {
                format!(
                    "{pad}unsigned long {local} = blend_{}({argument});",
                    names.tag
                )
            }
        }
        5 => format!("{pad}{target} = {value};"),
        6 => {
            // A statement that leaves the function, in leaf position. What
            // follows it is unreachable, which costs nothing: the corpus is
            // read and never run.
            format!("{pad}return {value};")
        }
        7 => {
            // A shape each language reaches for and the other does not.
            if rust {
                let other = pick(rng, &names.locals).clone();
                format!("{pad}debug_assert_ne!({target}, {other});")
            } else {
                let index = generate_expr(rng, &names.locals, 0, rust);
                format!(
                    "{pad}{}[({index}) & 7] |= {value};",
                    names.buffer.clone().unwrap_or_else(|| target.clone())
                )
            }
        }
        8 => {
            let guard = generate_expr(rng, &names.locals, 1, rust);
            let body = generate_block(rng, names, rust, depth + 1);
            let head = if rust {
                format!("{pad}if {target} > {guard} {{")
            } else {
                format!("{pad}if ({target} > {guard}) {{")
            };
            format!("{head}\n{body}\n{pad}}}")
        }
        9 => {
            let guard = generate_expr(rng, &names.locals, 1, rust);
            let taken = generate_block(rng, names, rust, depth + 1);
            let otherwise = generate_block(rng, names, rust, depth + 1);
            let head = if rust {
                format!("{pad}if {target} < {guard} {{")
            } else {
                format!("{pad}if ({target} < {guard}) {{")
            };
            format!("{head}\n{taken}\n{pad}}} else {{\n{otherwise}\n{pad}}}")
        }
        10 => {
            // An early exit: a branch whose body leaves the function.
            let guard = generate_expr(rng, &names.locals, 1, rust);
            let head = if rust {
                format!("{pad}if {target} == {guard} {{")
            } else {
                format!("{pad}if ({target} == {guard}) {{")
            };
            format!("{head}\n{}return {value};\n{pad}}}", indent(depth + 1))
        }
        11 => {
            let item = format!("x{depth}_{}", names.tag);
            let body = generate_block(rng, names, rust, depth + 1);
            let exit = if rng.below(2) == 0 {
                format!("\n{}break;", indent(depth + 1))
            } else {
                String::new()
            };
            let head = if rust {
                format!("{pad}for {item} in {} {{", names.slice)
            } else {
                format!(
                    "{pad}for (size_t {item} = 0; {item} < {}; {item}++) {{",
                    names.len
                )
            };
            format!("{head}\n{body}{exit}\n{pad}}}")
        }
        12 => {
            let guard = generate_expr(rng, &names.locals, 1, rust);
            let body = generate_block(rng, names, rust, depth + 1);
            let head = if rust {
                format!("{pad}while {target} > {guard} {{")
            } else {
                format!("{pad}while ({target} > {guard}) {{")
            };
            format!("{head}\n{body}\n{}continue;\n{pad}}}", indent(depth + 1))
        }
        _ => {
            // A multi-way branch. The arms are blocks, so the windows cut
            // from them sit two levels below the function body.
            let arms: Vec<String> = (0..3)
                .map(|arm| {
                    let body = generate_block(rng, names, rust, depth + 2);
                    let inner = indent(depth + 1);
                    if rust {
                        let label = if arm == 2 {
                            "_".to_string()
                        } else {
                            arm.to_string()
                        };
                        format!("{inner}{label} => {{\n{body}\n{inner}}}")
                    } else {
                        let label = if arm == 2 {
                            "default:".to_string()
                        } else {
                            format!("case {arm}:")
                        };
                        format!(
                            "{inner}{label} {{\n{body}\n{}break;\n{inner}}}",
                            indent(depth + 2)
                        )
                    }
                })
                .collect();
            let head = if rust {
                format!("{pad}match {target} & 3 {{")
            } else {
                format!("{pad}switch ({target} & 3) {{")
            };
            format!("{head}\n{}\n{pad}}}", arms.join("\n"))
        }
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
/// sizes the allowance is scaled linearly, which is what the measurements
/// show the cost doing — memory has run 730 to 850 bytes per line across four
/// tree sizes.
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
        let scaled_rss = LARGE_TREE_RSS_BYTES.saturating_mul(lines) / LARGE_TREE_LINES;
        Self {
            wall: Duration::from_secs(seconds),
            max_rss_bytes: if scaled_rss < LARGE_TREE_RSS_BYTES {
                LARGE_TREE_RSS_BYTES
            } else {
                scaled_rss
            },
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
        if measurement.skipped_pairs > 0 {
            missed.push(format!(
                "examined {} of {} candidate pairs; the allowance stopped the search \
                 {:.0}% short",
                measurement.examined_pairs,
                measurement.examined_pairs + measurement.skipped_pairs,
                measurement.truncation_share() * 100.0,
            ));
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
        summary: summarize(&value),
    })
}

/// The numbers a size measurement needs from a scan report.
struct PipelineCounts {
    lines: u64,
    examined_pairs: u64,
    skipped_pairs: u64,
}

/// Read the analysed size and the pairing stages' own accounting out of a
/// report.
///
/// Only the stages that recorded the allowance running out are counted, and
/// they are found by that record rather than by name: each pairing pass holds
/// its own allowance, and a list of stage names written down here would let a
/// pass added later go uncounted and read as complete.
fn count_pipeline(report: &serde_json::Value) -> PipelineCounts {
    let summary = &report["summary"];
    let mut counts = PipelineCounts {
        lines: summary["lines"].as_u64().unwrap_or(0),
        examined_pairs: 0,
        skipped_pairs: 0,
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
            test_code: false,
            score: 1.0,
            entropy_bits: 24.0,
            suppress_reason: None,
            boilerplate: None,
            width_family: false,
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

    let variant = BuildVariant::fast(LanguageSelection::default(), Language::C);
    let snapshot = Snapshot {
        root_path: "/synthetic",
        tool_version: "bench",
        config_hash: "0",
        started_at: "2026-01-01T00:00:00.000000Z",
        finished_at: "2026-01-01T00:00:01.000000Z",
        variant: &variant,
        min_clone_tokens: 20,
        detector_versions: &[],
        suppressions: Vec::new(),
        units: unit_rows,
        groups: group_rows,
        features: Vec::new(),
        files: Vec::new(),
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

    /// Large enough to reach every language: the mix cycles by file index, so
    /// a target that fits in a couple of files says nothing about it.
    fn small_spec() -> CorpusSpec {
        CorpusSpec {
            target_lines: 8_000,
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
        assert!(stats_a.lines >= small_spec().target_lines);
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

    /// A report with two pairing stages, the second of which ran out.
    fn truncated_report() -> serde_json::Value {
        serde_json::json!({
            "summary": {
                "files": {"total": 400},
                "lines": 100_000,
                "tokens": 900_000,
                "groups": {"total": 12},
                "funnel": [
                    {"stage": "seed pairs", "passed": 4_000, "dropped": []},
                    {"stage": "fragment pairs", "passed": 40, "dropped": [
                        {"cause": "pair_budget", "count": 60},
                    ]},
                ],
            }
        })
    }

    #[test]
    fn the_summary_keeps_the_sizes_and_the_whole_pipeline_block() {
        let summary = summarize(&truncated_report());
        assert!(summary.contains("files: 400 analysed"));
        assert!(summary.contains("clone groups: 12"));
        assert!(summary.contains("seed pairs"));
        // A run that stopped early is fast for a reason the timing hides.
        assert!(summary.contains("pair_budget 60"));
    }

    /// Only the stages the ceiling stopped are counted. A pass that finished
    /// its own search would otherwise dilute the share, and the number is
    /// there to say how much of the search was abandoned.
    #[test]
    fn the_pipeline_counts_cover_the_stages_the_ceiling_stopped() {
        let counted = count_pipeline(&truncated_report());
        assert_eq!(counted.lines, 100_000);
        assert_eq!(counted.examined_pairs, 40);
        assert_eq!(counted.skipped_pairs, 60);
    }

    fn measurement(wall_secs: u64, rss: Option<u64>, lines: u64, skipped: u64) -> ScanMeasurement {
        ScanMeasurement {
            wall: Duration::from_secs(wall_secs),
            max_rss_bytes: rss,
            lines,
            examined_pairs: 1_000,
            skipped_pairs: skipped,
            summary: String::new(),
        }
    }

    #[test]
    fn the_allowance_scales_from_the_two_named_sizes() {
        assert_eq!(Slo::for_lines(1_000).wall, Duration::from_secs(10));
        assert_eq!(Slo::for_lines(100_000).wall, Duration::from_secs(10));
        assert_eq!(Slo::for_lines(1_000_000).wall, Duration::from_secs(60));
        assert_eq!(Slo::for_lines(2_000_000).wall, Duration::from_secs(120));
        // Memory is floored at the figure it is stated by, never scaled below.
        assert_eq!(
            Slo::for_lines(10_000).max_rss_bytes,
            Slo::for_lines(1_000_000).max_rss_bytes
        );
    }

    /// A scan that reached its time by abandoning most of its candidates has
    /// changed the question rather than answered it faster, so the search
    /// finishing is part of the target and not a footnote to it.
    #[test]
    fn a_fast_run_that_stopped_early_still_misses_the_target() {
        let slo = Slo::for_lines(1_000_000);
        let quick = measurement(5, Some(1_000_000_000), 1_000_000, 0);
        assert!(slo.shortfalls(&quick).is_empty());

        let truncated = measurement(5, Some(1_000_000_000), 1_000_000, 3_000);
        let missed = slo.shortfalls(&truncated);
        assert_eq!(missed.len(), 1, "{missed:?}");
        assert!(missed[0].contains("examined 1000 of 4000"));
        assert!(missed[0].contains("75%"));
    }

    /// Every shortfall is reported, not the first: a run that is both slow and
    /// truncated has two problems, and fixing the one that surfaced would hide
    /// the other behind a re-run.
    #[test]
    fn every_missed_target_is_named() {
        let slo = Slo::for_lines(1_000_000);
        let bad = measurement(300, Some(8_000_000_000), 1_000_000, 9_000);
        assert_eq!(slo.shortfalls(&bad).len(), 3);
    }

    #[test]
    fn a_warm_scan_keeps_the_history_a_cold_scan_throws_away() {
        let dir = tempfile::tempdir().unwrap();
        let db = prepare_database(dir.path(), ScanStart::Cold).unwrap();
        std::fs::write(&db, b"recorded").unwrap();

        assert_eq!(prepare_database(dir.path(), ScanStart::Warm).unwrap(), db);
        assert!(db.exists(), "a warm scan scans into what is already there");

        prepare_database(dir.path(), ScanStart::Cold).unwrap();
        assert!(
            !db.exists(),
            "a cold scan starts with no history of the tree"
        );
    }

    #[test]
    fn the_summary_says_what_the_warm_scan_recognised() {
        let report = serde_json::json!({
            "summary": {
                "files": {"total": 3},
                "lines": 4_926,
                "tokens": 20_013,
                "groups": {"total": 2},
                "changes": {
                    "since_run_id": 1, "unchanged": 3,
                    "modified": 0, "added": 0, "removed": 0,
                },
                "funnel": [],
            }
        });
        let summary = summarize(&report);
        // Without this line a warm number is indistinguishable from a cold
        // one that happened to run fast.
        assert!(summary.contains("since run 1: 3 unchanged"));
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
