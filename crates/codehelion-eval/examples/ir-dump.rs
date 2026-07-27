//! Print the Syntax IR of one source file, unit by unit.
//!
//! The boilerplate classifier decides from the shape of a body, and the shape
//! of a body is not something reading the source tells you: a declaration whose
//! initialiser calls something is one node, a macro is one node whatever it
//! expands to, and a header compiled two ways contributes both ways. Every rule
//! that module has was settled by dumping the tree for a unit that ought to be
//! classified and was not, and each time the dumping was done by hand and then
//! thrown away. This is that, kept.
//!
//! ```sh
//! cargo run -p codehelion-eval --example ir-dump -- path/to/file.rs
//! cargo run -p codehelion-eval --example ir-dump -- os-inl.h 87 --lang cpp
//! ```
//!
//! With a line, only the units covering it are printed; without one, all of
//! them. `--lang` settles a bare `.h`, which C and C++ share — a scan settles
//! it from the rest of the tree, and one file on its own carries no such
//! evidence.

use std::path::Path;

use codehelion_core::boilerplate;
use codehelion_core::discovery::Language;
use codehelion_core::ir::{IrNode, Shape, StructuralFrontend, SyntaxIrFile};

fn main() {
    let mut args = std::env::args().skip(1);
    let Some(path) = args.next() else {
        eprintln!("usage: ir-dump <file> [line] [--lang rust|c|cpp]");
        std::process::exit(2);
    };
    let mut line = None;
    let mut language = None;
    while let Some(argument) = args.next() {
        if argument == "--lang" {
            language = args.next().and_then(|name| match name.as_str() {
                "rust" => Some(Language::Rust),
                "c" => Some(Language::C),
                "cpp" => Some(Language::Cpp),
                _ => None,
            });
        } else if let Ok(number) = argument.parse() {
            line = Some(number);
        }
    }

    let path = Path::new(&path);
    let Some(language) = language.or_else(|| by_extension(path)) else {
        eprintln!(
            "cannot tell what language {} is; pass --lang",
            path.display()
        );
        std::process::exit(2);
    };
    let source = match std::fs::read_to_string(path) {
        Ok(source) => source,
        Err(error) => {
            eprintln!("reading {}: {error}", path.display());
            std::process::exit(1);
        }
    };

    let file = parse(language, &source);
    let starts = line_starts(&source);
    let mut printed = 0usize;
    for root in &file.roots {
        printed += dump_units(root, &starts, line);
    }
    if printed == 0 {
        println!("no unit found");
    }
}

/// The language a file's extension names, where it names one on its own.
fn by_extension(path: &Path) -> Option<Language> {
    match path.extension()?.to_str()? {
        "rs" => Some(Language::Rust),
        "c" => Some(Language::C),
        "cc" | "cpp" | "cxx" | "hpp" | "hh" | "inl" | "tpp" | "ipp" => Some(Language::Cpp),
        _ => None,
    }
}

fn parse(language: Language, source: &str) -> SyntaxIrFile {
    match language {
        Language::Rust => codehelion_frontend_rust::ir::RustStructuralFrontend.parse(source),
        Language::C => codehelion_frontend_c::ir::CStructuralFrontend.parse(source),
        Language::Cpp => codehelion_frontend_cpp::ir::CppStructuralFrontend.parse(source),
    }
}

/// Byte offset of the start of each line, for turning a node's range into
/// something that can be compared with what an editor shows.
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

/// The 1-based line a byte offset falls on.
fn line_of(starts: &[usize], offset: usize) -> usize {
    starts.partition_point(|&start| start <= offset)
}

/// Print every unit under `node` that covers `wanted`, and return how many.
fn dump_units(node: &IrNode, starts: &[usize], wanted: Option<usize>) -> usize {
    if matches!(node.shape, Shape::Function | Shape::Method) {
        let first = line_of(starts, node.range.start);
        let last = line_of(starts, node.range.end.saturating_sub(1));
        if wanted.is_none_or(|line| (first..=last).contains(&line)) {
            let name = node
                .name
                .as_ref()
                .map_or_else(|| "(anonymous)".to_owned(), ToString::to_string);
            let verdict = boilerplate::classify(node)
                .map_or_else(|| "none".to_owned(), |kind| kind.name().to_owned());
            println!(
                "\n{first}-{last}  {name}  [{} tokens]  -> {verdict}",
                node.token_len()
            );
            dump_tree(node, starts, 0);
            return 1;
        }
        // A unit written inside another one is still a unit.
    }
    node.children
        .iter()
        .map(|child| dump_units(child, starts, wanted))
        .sum()
}

/// Print one subtree, one node per line.
fn dump_tree(node: &IrNode, starts: &[usize], depth: usize) {
    let name = node
        .name
        .as_ref()
        .map_or_else(String::new, |name| format!(" {name}"));
    println!(
        "{:>5}  {:indent$}{:?}{name}",
        line_of(starts, node.range.start),
        "",
        node.shape,
        indent = depth * 2,
    );
    for child in &node.children {
        dump_tree(child, starts, depth + 1);
    }
}
