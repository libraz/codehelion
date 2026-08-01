//! A deliberately narrow bridge from Clang's CFG diagnostic checker.
//!
//! libclang does not expose `clang::CFG`.  This module therefore invokes a
//! fixed compiler executable, never the compile command's executable, with
//! `-fsyntax-only` and Clang's own `debug.DumpCFG` checker.  The compilation
//! database contributes only arguments that [`crate::database::Entry`] has
//! accepted as read-only.  If that cannot be guaranteed, CFG evidence is
//! absent rather than approximated or obtained by executing project code.

// This is the isolated compiler-helper binary, the explicit exception to the
// workspace rule that scan-path crates must not spawn a process. The executable
// and added arguments below are fixed; project commands are never executed.
#![allow(clippy::disallowed_types)]

use std::collections::BTreeMap;
use std::path::Path;
use std::process::{Command, Stdio};

use codehelion_helper::ir::{Anchor, BasicBlock, ControlFlowGraph, Edge, EdgeKind};

use crate::database::ValidatedArguments;

/// The one source definition to which a dumped compiler CFG can be anchored.
#[derive(Debug, Clone)]
pub(crate) struct FunctionAnchor {
    /// The declaration name printed by Clang in its CFG header.
    pub(crate) name: String,
    /// The complete function definition range.
    pub(crate) anchor: Anchor,
}

/// Whether this process can supply at least one C or C++ CFG frontend.
pub(crate) fn available() -> bool {
    compiler_available("clang") || compiler_available("clang++")
}

fn compiler_available(name: &str) -> bool {
    Command::new(name)
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

/// Read compiler-produced CFGs for the definitions Clang just parsed.
///
/// A dump has a human-oriented function heading rather than a stable cursor
/// ID.  It is used only when exactly one dump and exactly one in-tree function
/// definition share a name; overloads or ambiguous compiler output are
/// omitted.  That conservatism keeps a graph from being attached to the wrong
/// source range.
pub(crate) fn produce(
    file: &Path,
    arguments: &ValidatedArguments,
    functions: &[FunctionAnchor],
) -> Option<ControlFlowGraph> {
    let compiler = compiler_for(file)?;
    let output = Command::new(compiler)
        // Clang otherwise searches user, system, and executable-relative
        // default configuration files selected by the database's target.
        // None of those files is part of the reviewed argument set.
        .arg("--no-default-config")
        .args(arguments.as_slice())
        // Place these after database arguments so the helper owns the mode
        // even if a build command originally requested an object file.
        .arg("-fsyntax-only")
        .args([
            "-Xclang",
            "-analyze",
            "-Xclang",
            "-analyzer-checker=debug.DumpCFG",
        ])
        .arg(file)
        .stdin(Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let output = String::from_utf8(output.stderr).ok()?;
    from_dump(&output, functions)
}

fn compiler_for(path: &Path) -> Option<&'static str> {
    let extension = path.extension()?.to_str()?.to_ascii_lowercase();
    match extension.as_str() {
        "c" => compiler_available("clang").then_some("clang"),
        "cc" | "cp" | "cpp" | "cxx" | "c++" => compiler_available("clang++").then_some("clang++"),
        _ => None,
    }
}

/// A CFG block before the special entry/exit nodes have been removed.
#[derive(Debug, Clone, PartialEq, Eq)]
struct DumpBlock {
    number: u32,
    statements: u32,
    successors: Vec<u32>,
    conditional: bool,
    entry: bool,
    exit: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DumpFunction {
    heading: String,
    blocks: Vec<DumpBlock>,
}

/// Convert unambiguous portions of Clang's diagnostic format to protocol IR.
fn from_dump(text: &str, functions: &[FunctionAnchor]) -> Option<ControlFlowGraph> {
    let dumped = dump_functions(text);
    let mut graph = ControlFlowGraph::default();
    for function in functions {
        let matching: Vec<_> = dumped
            .iter()
            .filter(|candidate| heading_names(candidate, &function.name))
            .collect();
        if matching.len() != 1
            || functions
                .iter()
                .filter(|candidate| candidate.name == function.name)
                .count()
                != 1
        {
            continue;
        }
        append_function(&mut graph, matching[0], &function.anchor);
    }
    (!graph.blocks.is_empty()).then_some(graph)
}

fn heading_names(function: &DumpFunction, name: &str) -> bool {
    function.heading.contains(&format!("{name}("))
}

fn append_function(graph: &mut ControlFlowGraph, function: &DumpFunction, anchor: &Anchor) {
    let ordinary: Vec<_> = function
        .blocks
        .iter()
        .filter(|block| !block.entry && !block.exit)
        .collect();
    let start = u32::try_from(graph.blocks.len()).unwrap_or(u32::MAX);
    let mut indices = BTreeMap::new();
    for (offset, block) in ordinary.iter().enumerate() {
        let Ok(offset) = u32::try_from(offset) else {
            return;
        };
        let Some(index) = start.checked_add(offset) else {
            return;
        };
        indices.insert(block.number, index);
    }
    if indices.len() != ordinary.len() {
        return;
    }
    graph.blocks.extend(ordinary.iter().map(|block| BasicBlock {
        anchor: anchor.clone(),
        length: block.statements,
    }));
    for block in ordinary {
        let Some(&from) = indices.get(&block.number) else {
            continue;
        };
        for (position, successor) in block.successors.iter().enumerate() {
            let kind = edge_kind(block, position);
            if let Some(&to) = indices.get(successor) {
                graph.edges.push(Edge { from, to, kind });
            } else if *successor == 0 {
                graph.edges.push(Edge {
                    from,
                    to: from,
                    // The protocol has no synthetic exit node. Preserve a
                    // conditional branch's polarity even when its destination
                    // is that omitted node; an unconditional jump to it is a
                    // return to the caller.
                    kind: if block.conditional {
                        kind
                    } else {
                        EdgeKind::Return
                    },
                });
            }
        }
    }
}

fn edge_kind(block: &DumpBlock, position: usize) -> EdgeKind {
    if block.conditional && block.successors.len() == 2 {
        return if position == 0 {
            EdgeKind::Taken
        } else {
            EdgeKind::NotTaken
        };
    }
    EdgeKind::Flow
}

/// Parse only the regular block records that the `debug.DumpCFG` checker
/// prints.  The checker output is intentionally diagnostic rather than a wire
/// format, so unknown lines are ignored and an ambiguous result is not used.
fn dump_functions(text: &str) -> Vec<DumpFunction> {
    let mut functions = Vec::new();
    let mut heading: Option<String> = None;
    let mut blocks = Vec::new();
    let mut current: Option<DumpBlock> = None;
    for line in text.lines() {
        let trimmed = line.trim();
        if !line.starts_with(char::is_whitespace) && !trimmed.is_empty() {
            finish_block(&mut blocks, &mut current);
            if !blocks.is_empty() {
                if let Some(heading) = heading.take() {
                    functions.push(DumpFunction { heading, blocks });
                }
                blocks = Vec::new();
            }
            heading = Some(trimmed.to_owned());
            continue;
        }
        if let Some((number, entry, exit)) = block_number(trimmed) {
            finish_block(&mut blocks, &mut current);
            current = Some(DumpBlock {
                number,
                statements: 0,
                successors: Vec::new(),
                conditional: false,
                entry,
                exit,
            });
        } else if trimmed.starts_with("T:") {
            if let Some(block) = &mut current {
                block.conditional = true;
            }
        } else if let Some(rest) = trimmed.strip_prefix("Succs (")
            && let Some((_, numbers)) = rest.split_once(": ")
            && let Some(block) = &mut current
        {
            block.successors = numbers
                .split_whitespace()
                .filter_map(|value| value.strip_prefix('B'))
                .filter_map(|value| value.parse().ok())
                .collect();
        } else if trimmed
            .chars()
            .next()
            .is_some_and(|character| character.is_ascii_digit())
            && let Some(block) = &mut current
        {
            block.statements = block.statements.saturating_add(1);
        }
    }
    finish_block(&mut blocks, &mut current);
    if !blocks.is_empty()
        && let Some(heading) = heading
    {
        functions.push(DumpFunction { heading, blocks });
    }
    functions
}

fn finish_block(blocks: &mut Vec<DumpBlock>, current: &mut Option<DumpBlock>) {
    if let Some(block) = current.take() {
        blocks.push(block);
    }
}

fn block_number(line: &str) -> Option<(u32, bool, bool)> {
    let rest = line.strip_prefix("[B")?;
    let number = rest.split([' ', ']']).next()?.parse().ok()?;
    Some((number, rest.contains("(ENTRY)"), rest.contains("(EXIT)")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use codehelion_helper::ir::{Anchor, SourceRange};

    fn anchor() -> Anchor {
        Anchor::written_here(SourceRange {
            file: "source.cpp".to_string(),
            start_byte: 0,
            end_byte: 20,
            start_line: 1,
        })
    }

    #[test]
    #[allow(clippy::panic)]
    fn maps_a_conditional_dump_without_entry_or_exit_blocks() {
        let text = concat!(
            "int choose(bool value)\n",
            " [B3 (ENTRY)]\n",
            "   Succs (1): B2\n",
            " [B2]\n",
            "   1: value\n",
            "   T: if (value)\n",
            "   Succs (2): B1 B0\n",
            " [B1]\n",
            "   1: return 1;\n",
            "   Succs (1): B0\n",
            " [B0 (EXIT)]\n",
            "   Preds (2): B2 B1\n",
        );
        let graph = from_dump(
            text,
            &[FunctionAnchor {
                name: "choose".to_string(),
                anchor: anchor(),
            }],
        )
        .unwrap_or_else(|| panic!("one unambiguous CFG: {:?}", dump_functions(text)));
        assert_eq!(graph.blocks.len(), 2);
        assert_eq!(graph.blocks[0].length, 1);
        assert_eq!(
            graph.edges,
            vec![
                Edge {
                    from: 0,
                    to: 1,
                    kind: EdgeKind::Taken,
                },
                Edge {
                    from: 0,
                    to: 0,
                    kind: EdgeKind::NotTaken,
                },
                Edge {
                    from: 1,
                    to: 1,
                    kind: EdgeKind::Return,
                },
            ]
        );
    }

    #[test]
    fn refuses_to_anchor_overloaded_functions_by_name() {
        assert!(
            from_dump(
                "int value()\n [B1]\n  Succs (1): B0\n [B0 (EXIT)]\n",
                &[
                    FunctionAnchor {
                        name: "value".to_string(),
                        anchor: anchor(),
                    },
                    FunctionAnchor {
                        name: "value".to_string(),
                        anchor: anchor(),
                    },
                ],
            )
            .is_none()
        );
    }
}
