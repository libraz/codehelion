//! What a macro produced, and where the two halves of that are.
//!
//! # Why this is worth the trouble
//!
//! A macro invoked twenty times produces twenty identical bodies. Nobody wrote
//! them twice and nobody can delete one of them, so a detector that sees only
//! the text reports twenty duplications that cannot be acted on. What tells
//! that apart from real duplication is that all twenty were written once: they
//! share a definition site and differ only in where they were invoked.
//!
//! So every declaration a macro produced anchors at the invocation — that is
//! the only place in a file it can be pointed at — and carries the macro's own
//! source as its definition. Grouping on the definition turns twenty findings
//! into one.
//!
//! # Why only declarative macros
//!
//! Expanding a `macro_rules!` is reading it. Expanding a procedural macro is
//! running the crate that defines it, which nothing here does. A procedural
//! macro invocation is therefore passed over rather than reported as having
//! produced nothing.

use std::path::Path;

use codehelion_helper::ir::{Anchor, SourceRange};
use ra_ap_hir::{Adt, HasSource, Macro, ModuleDef, Semantics};
use ra_ap_ide_db::RootDatabase;
use ra_ap_syntax::{AstNode, ast};

use crate::analysis::{Loaded, file_of, real_file, source_range};

/// One declaration a macro produced, and where to say it is.
pub(crate) struct Expanded {
    /// What the compiler made of it.
    pub(crate) definition: ModuleDef,
    /// The invocation it came out of, and the macro it was written in.
    pub(crate) anchor: Anchor,
}

/// Everything the macros invoked in `file` declared.
pub(crate) fn collect(loaded: &Loaded, file: &Path) -> Vec<Expanded> {
    let mut found = Vec::new();
    let Some(file_id) = file_of(loaded, file) else {
        return found;
    };
    let db = &loaded.db;
    let sema = Semantics::new(db);
    let Some(editioned) = sema.attach_first_edition_opt(file_id) else {
        return found;
    };
    let source = sema.parse(editioned);
    for call in source
        .syntax()
        .descendants()
        .filter_map(ast::MacroCall::cast)
    {
        let Some(macro_) = sema.resolve_macro_call(&call) else {
            continue;
        };
        if macro_.is_proc_macro() {
            continue;
        }
        let Some(written) = written_at(loaded, macro_, db) else {
            continue;
        };
        let Some(expansion) = sema.expand_macro_call(&call) else {
            continue;
        };
        let anchor = Anchor {
            expansion: source_range(loaded, file_id, call.syntax().text_range()),
            definition: Some(written),
        };
        for item in expansion.value.descendants().filter_map(ast::Item::cast) {
            if let Some(definition) = declared(&sema, &item) {
                found.push(Expanded {
                    definition,
                    anchor: anchor.clone(),
                });
            }
        }
    }
    found
}

/// Where the macro itself was written.
///
/// A macro defined inside another macro has no place in a file of its own; it
/// is left out rather than attributed to whichever expansion happened to
/// contain it.
fn written_at(loaded: &Loaded, macro_: Macro, db: &RootDatabase) -> Option<SourceRange> {
    let source = macro_.source(db)?;
    let file = real_file(source.file_id, db)?;
    let range = source.value.as_ref().either(
        |definition| definition.syntax().text_range(),
        |function| function.syntax().text_range(),
    );
    Some(source_range(loaded, file, range))
}

/// What the compiler made of one item in an expansion.
///
/// Only the kinds the declaration pass knows how to describe. An item it would
/// pass over anyway is not worth resolving.
fn declared(sema: &Semantics<'_, RootDatabase>, item: &ast::Item) -> Option<ModuleDef> {
    match item {
        ast::Item::Fn(item) => sema.to_def(item).map(ModuleDef::Function),
        ast::Item::Struct(item) => sema.to_def(item).map(|it| ModuleDef::Adt(Adt::Struct(it))),
        ast::Item::Enum(item) => sema.to_def(item).map(|it| ModuleDef::Adt(Adt::Enum(it))),
        ast::Item::Union(item) => sema.to_def(item).map(|it| ModuleDef::Adt(Adt::Union(it))),
        ast::Item::Const(item) => sema.to_def(item).map(ModuleDef::Const),
        ast::Item::Static(item) => sema.to_def(item).map(ModuleDef::Static),
        _ => None,
    }
}
