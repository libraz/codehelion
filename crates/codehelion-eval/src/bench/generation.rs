use std::fmt::Write as _;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use codehelion_core::discovery::Language;

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
/// Returns an error when the output directory is not empty or a directory or
/// file cannot be written.
pub fn generate_corpus(spec: &CorpusSpec, out_dir: &Path) -> Result<CorpusStats> {
    ensure!(spec.target_lines > 0, "target size must be positive");
    ensure!(spec.clone_percent <= 100, "clone percent is a percentage");
    if out_dir.exists() {
        let mut entries = std::fs::read_dir(out_dir)
            .with_context(|| format!("reading corpus output directory {}", out_dir.display()))?;
        ensure!(
            entries.next().is_none(),
            "corpus output directory {} must be empty",
            out_dir.display()
        );
    }
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
