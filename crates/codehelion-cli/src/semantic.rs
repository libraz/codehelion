//! Turning what a compiler helper answered into what normalization reads.
//!
//! The two sides were built to meet here and nowhere else. A helper reports
//! resolved names as symbols anchored at byte offsets in a file;
//! [`Resolution`] answers, for one byte offset, whether the name starting
//! there was defined outside the code being scanned. This is the only place
//! that knows both shapes — the engine crate does not depend on the protocol
//! crate, so that comparing programs stays independent of how a compiler was
//! asked about them.
//!
//! # Why the file has to be named
//!
//! One analysis covers a crate, and a crate is many files. Offsets are per
//! file, so folding two files' symbols into one resolution would have byte 400
//! of each answering for the other — silently, and in the direction that keeps
//! names a normalizer should have replaced.

use codehelion_core::engine::normalize::Resolution;
use codehelion_helper::ir::CompilerIr;

/// What `ir` resolved about the names written in `file`.
///
/// `file` is matched against the path the helper reported, which is how the
/// project spells it rather than how this machine does.
#[must_use]
pub fn resolution_for(ir: &CompilerIr, file: &str) -> Resolution {
    let mut resolution = Resolution::new();
    for symbol in &ir.symbols {
        let anchor = &symbol.anchor.expansion;
        if anchor.file != file {
            continue;
        }
        // A symbol whose anchor spans more than the name it reports is a
        // declaration, not a name occurrence: its range covers the whole item,
        // attributes and doc comment included. Feeding its start offset in
        // would answer for whatever token happens to begin there.
        if anchor.end_byte.saturating_sub(anchor.start_byte) != symbol.name.len() as u64 {
            continue;
        }
        let Ok(start) = usize::try_from(anchor.start_byte) else {
            continue;
        };
        resolution.insert(start, symbol.external);
    }
    resolution
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use codehelion_helper::ir::{Anchor, ResolvedSymbol, SourceRange, SymbolKind, UnitRef};

    fn symbol(name: &str, file: &str, start: u64, width: u64, external: bool) -> ResolvedSymbol {
        ResolvedSymbol {
            id: format!("{file}::{name}@{start}"),
            name: name.to_string(),
            kind: SymbolKind::Binding,
            anchor: Anchor::written_here(SourceRange {
                file: file.to_string(),
                start_byte: start,
                end_byte: start + width,
                start_line: 1,
            }),
            type_index: None,
            external,
        }
    }

    fn ir(symbols: Vec<ResolvedSymbol>) -> CompilerIr {
        let mut ir = CompilerIr::empty(UnitRef {
            unit: "ledger".into(),
            file: "src/lib.rs".into(),
            variant: "host".into(),
        });
        ir.symbols = symbols;
        ir
    }

    #[test]
    fn a_name_keeps_the_verdict_it_was_given() {
        let analysis = ir(vec![
            symbol("String", "src/lib.rs", 10, 6, true),
            symbol("total", "src/lib.rs", 40, 5, false),
        ]);
        let resolution = resolution_for(&analysis, "src/lib.rs");
        assert!(!resolution.is_empty());
        // Round-tripped through the type's own accessor rather than its
        // internals, because what a caller can see is what has to be right.
        assert_eq!(resolution, {
            let mut expected = Resolution::new();
            expected.insert(10, true);
            expected.insert(40, false);
            expected
        });
    }

    /// Offsets are per file. A crate's other files answering for this one would
    /// be wrong in whichever direction their bytes happened to line up.
    #[test]
    fn another_file_in_the_same_crate_does_not_answer_for_this_one() {
        let analysis = ir(vec![
            symbol("total", "src/lib.rs", 40, 5, false),
            symbol("Vec", "src/report.rs", 40, 3, true),
        ]);
        let resolution = resolution_for(&analysis, "src/lib.rs");
        let mut expected = Resolution::new();
        expected.insert(40, false);
        assert_eq!(resolution, expected);
    }

    /// A declaration's anchor spans the item it declares, so its start byte is
    /// whatever the item opens with — an attribute, a doc comment, `pub`. Read
    /// as a name occurrence it would give a verdict about a token nobody asked
    /// about.
    #[test]
    fn a_declaration_is_not_read_as_a_name_occurrence() {
        let mut declaration = symbol("debits", "src/lib.rs", 100, 6, false);
        declaration.anchor.expansion.end_byte = 260;
        declaration.kind = SymbolKind::Function;
        let resolution = resolution_for(&ir(vec![declaration]), "src/lib.rs");
        assert!(resolution.is_empty());
    }

    #[test]
    fn an_analysis_that_resolved_nothing_leaves_normalization_as_it_was() {
        let resolution = resolution_for(&ir(Vec::new()), "src/lib.rs");
        assert!(resolution.is_empty());
    }
}
