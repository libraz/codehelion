//! Print, for every labelled unit in a corpus case, what its body counts.
//!
//! The boilerplate classifier decides from counts over a unit's IR subtree, so
//! a proposed rule is a predicate over those counts and whether it is safe is
//! whether it separates the refuted labels from the confirmed ones. Reading one
//! unit's tree — what [`ir-dump`](../examples/ir-dump.rs) prints — says why a
//! particular unit was not classified; it cannot say what a rule reaching that
//! unit would cost. This prints the counts for the whole corpus as one table,
//! so a candidate predicate can be tried against every verdict at once.
//!
//! ```sh
//! cargo run -p codehelion-eval --example boilerplate-screen -- corpus/labeled/spdlog
//! ```
//!
//! One tab-separated row per labelled fragment: the case, the verdict, the
//! lookalike class for a refuted one, the label, the fragment, the innermost
//! unit containing it, how much of that unit the fragment covers, and the
//! counts. A fragment covering only part of a unit is a run rather than a unit,
//! and the classifier never sees it — the coverage column is what lets those
//! rows be dropped.

use std::path::{Path, PathBuf};

use codehelion_core::boilerplate::{self, Boilerplate, BoilerplateCounts};
use codehelion_core::discovery::Language;
use codehelion_core::ir::{IrNode, Shape, StructuralFrontend, SyntaxIrFile};
use codehelion_eval::labels::LabelSet;
use codehelion_eval::schema::Fragment;

/// A labelled case: the verdicts, and the tree they are verdicts about.
struct Case {
    name: String,
    root: PathBuf,
    language: Language,
}

/// The innermost unit containing a fragment, and what it counts.
struct Located {
    name: String,
    first: usize,
    last: usize,
    tokens: usize,
    verdict: Option<Boilerplate>,
    counts: BoilerplateCounts,
}

fn main() {
    let Some(argument) = std::env::args().nth(1) else {
        eprintln!("usage: boilerplate-screen <corpus/labeled/CASE>");
        std::process::exit(2);
    };
    let directory = PathBuf::from(&argument);
    let labels = match read_labels(&directory) {
        Ok(labels) => labels,
        Err(error) => {
            eprintln!("{argument}: {error}");
            std::process::exit(1);
        }
    };
    let Some(language) = language_of(&labels.language) else {
        eprintln!("{argument}: unknown language {}", labels.language);
        std::process::exit(1);
    };
    let case = Case {
        name: directory
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .unwrap_or("?")
            .to_owned(),
        root: directory.join("snapshot"),
        language,
    };

    for pair in &labels.clone_pairs {
        for fragment in &pair.fragments {
            print(&case, "confirmed", &pair.id, "-", fragment);
        }
    }
    for lookalike in &labels.non_clones {
        for fragment in &lookalike.fragments {
            print(&case, "refuted", &lookalike.id, &lookalike.reason, fragment);
        }
    }
}

fn read_labels(directory: &Path) -> Result<LabelSet, String> {
    let path = directory.join("labels.json");
    let json = std::fs::read_to_string(&path).map_err(|error| format!("{error}"))?;
    LabelSet::from_json(&json).map_err(|error| format!("{error}"))
}

fn language_of(name: &str) -> Option<Language> {
    match name {
        "rust" => Some(Language::Rust),
        "c" => Some(Language::C),
        "cpp" => Some(Language::Cpp),
        _ => None,
    }
}

fn print(case: &Case, verdict: &str, id: &str, reason: &str, fragment: &Fragment) {
    let where_ = format!(
        "{}:{}-{}",
        fragment.file, fragment.start_line, fragment.end_line
    );
    let prefix = format!("{}\t{verdict}\t{reason}\t{id}\t{where_}", case.name);
    let path = case.root.join(&fragment.file);
    let Ok(source) = std::fs::read_to_string(&path) else {
        eprintln!("missing {}", path.display());
        return;
    };
    match locate(case.language, &source, fragment) {
        Some(unit) => {
            let lines = unit.last - unit.first + 1;
            let span = usize::try_from(fragment.end_line - fragment.start_line + 1).unwrap_or(0);
            #[allow(clippy::cast_precision_loss)]
            let covers = span as f64 / lines as f64;
            let counts = unit.counts;
            println!(
                "{prefix}\t{}\t{}-{}\t{covers:.2}\t{}\t{}\tcontrol={} calls={} macros={} stmt={} work={} branch={} decl={} ret={}",
                unit.name,
                unit.first,
                unit.last,
                unit.tokens,
                unit.verdict.map_or("none", Boilerplate::name),
                counts.control,
                counts.calls,
                counts.macros,
                counts.statements,
                counts.work,
                counts.branches,
                counts.declarations,
                counts.returns,
            );
        }
        None => println!("{prefix}\t(no unit)\t-\t-\t-\t-\t-"),
    }
}

/// The smallest unit whose lines contain the whole fragment.
///
/// Smallest rather than outermost: a unit written inside another one is the
/// unit the classifier would be deciding about.
fn locate(language: Language, source: &str, fragment: &Fragment) -> Option<Located> {
    let file = parse(language, source);
    let starts = line_starts(source);
    let wanted = (
        usize::try_from(fragment.start_line).unwrap_or(0),
        usize::try_from(fragment.end_line).unwrap_or(0),
    );
    let mut best: Option<Located> = None;
    for root in &file.roots {
        walk(root, &starts, &mut |node, first, last| {
            if first > wanted.0 || last < wanted.1 {
                return;
            }
            let span = last - first;
            if best
                .as_ref()
                .is_none_or(|found| span < found.last - found.first)
            {
                best = Some(Located {
                    name: node
                        .name
                        .as_ref()
                        .map_or_else(|| "(anonymous)".to_owned(), ToString::to_string),
                    first,
                    last,
                    tokens: node.token_len(),
                    verdict: boilerplate::classify(node),
                    counts: boilerplate::counts(node),
                });
            }
        });
    }
    best
}

/// Call `visit` for every unit under `node`, with the lines it spans.
fn walk(node: &IrNode, starts: &[usize], visit: &mut impl FnMut(&IrNode, usize, usize)) {
    if matches!(node.shape, Shape::Function | Shape::Method) {
        let first = line_of(starts, node.range.start);
        let last = line_of(starts, node.range.end.saturating_sub(1));
        visit(node, first, last);
    }
    for child in &node.children {
        walk(child, starts, visit);
    }
}

fn parse(language: Language, source: &str) -> SyntaxIrFile {
    match language {
        Language::Rust => codehelion_frontend_rust::ir::RustStructuralFrontend.parse(source),
        Language::C => codehelion_frontend_c::ir::CStructuralFrontend.parse(source),
        Language::Cpp => codehelion_frontend_cpp::ir::CppStructuralFrontend.parse(source),
    }
}

fn line_starts(source: &str) -> Vec<usize> {
    let mut starts = vec![0];
    starts.extend(
        source
            .bytes()
            .enumerate()
            .filter(|&(_, byte)| byte == b'\n')
            .map(|(offset, _)| offset + 1),
    );
    starts
}

fn line_of(starts: &[usize], offset: usize) -> usize {
    starts.partition_point(|&start| start <= offset)
}
