//! Every place a generic body was used at particular types.
//!
//! # Why the use is what there is to point at
//!
//! Rust stamps out a copy of a generic body per set of type arguments, but it
//! does that in a back end this helper never reaches, and the copies it makes
//! have no place in any file. What a reader can point at is the use: the name
//! of the generic, with the arguments the compiler settled on there. So an
//! instantiation anchors at the use and carries the generic's own source as the
//! body it came from — the same two halves a macro expansion carries, for the
//! same reason. Twenty uses of one generic are one thing written once, and a
//! detector that saw only the stamped-out text would report twenty bodies
//! nobody wrote and nobody can delete.
//!
//! # Why the arguments are part of the key and not of the definition
//!
//! `widest::<i64>` and `widest::<u32>` come from one body and produce two, so
//! they name the same definition and belong to different families. Which of the
//! two questions is being asked decides which field to read: the definition
//! says what there is to fix, the key says how many copies of it exist.
//!
//! The key spells its arguments the way Rust spells them, while the argument
//! indices point into the unit's type table, which records shapes rather than
//! spellings. The two answer different questions on purpose: `i64` and `u32`
//! are one shape and two families, because they are one thing to compare across
//! languages and two copies in a binary.
//!
//! # Why only what the scan holds
//!
//! An ordinary iterator chain instantiates a dozen generics from the standard
//! library. None of them are repetition anyone scanning this project can act
//! on, and letting the dependency tree into the family index makes the index
//! the dependency tree.
//!
//! # The two places a substitution shows up
//!
//! Inside a body the compiler infers one, and a resolved name carries it. In a
//! signature or an annotation it is written out, and the name carries nothing —
//! the substitution is the type itself. Both are read, because a project that
//! passes its generic types through signatures would otherwise report none.
//!
//! # Why this walks the file again
//!
//! Names are classified once per pass rather than once per file, as the calls
//! pass also does. The expensive half of classifying — inferring the types of a
//! body — is answered from the database's own cache the second time, so what a
//! shared walk would save is the walk, and what it would cost is a module that
//! answers two questions at once.

use std::path::Path;

use codehelion_helper::ir::{Anchor, Instantiation, SourceRange};
use ra_ap_hir::{Crate, DisplayTarget, HasSource, HirDisplay, Semantics, Type};
use ra_ap_ide_db::RootDatabase;
use ra_ap_ide_db::defs::{Definition, IdentClass};
use ra_ap_syntax::{AstNode, SyntaxKind, TextRange, ast};

use crate::analysis::{
    Loaded, TypeTable, adt_range, definition_range, file_of, path_of, source_range,
};
use crate::calls;
use crate::occurrences::is_external;

/// One entry per use of a generic the scan holds, in `file`.
pub(crate) fn collect(
    loaded: &Loaded,
    file: &Path,
    krate: Crate,
    types: &mut TypeTable,
) -> Vec<Instantiation> {
    let mut found = Vec::new();
    let Some(file_id) = file_of(loaded, file) else {
        return found;
    };
    let db = &loaded.db;
    let sema = Semantics::new(db);
    let Some(editioned) = sema.attach_first_edition_opt(file_id) else {
        return found;
    };
    // The crate being read decides how a type is spelled, because the edition
    // it is written in decides what some of those spellings are.
    let target = krate.to_display_target(db);
    let source = sema.parse(editioned);
    for token in source
        .syntax()
        .descendants_with_tokens()
        .filter_map(ra_ap_syntax::NodeOrToken::into_token)
    {
        if token.kind() != SyntaxKind::IDENT {
            continue;
        }
        let Some(class) = IdentClass::classify_token(&sema, &token) else {
            continue;
        };
        // A name can resolve to two things at once, and only one of them need
        // be generic — the field of `Foo { field }` carries the substitution
        // its struct was used at, while the local it binds carries none.
        let Some((definition, substitution)) = class
            .definitions()
            .into_iter()
            .find_map(|(definition, substitution)| Some((definition, substitution?)))
        else {
            continue;
        };
        let Some((name, written)) = instantiated(loaded, definition, db) else {
            continue;
        };
        let arguments: Vec<Type<'_>> = substitution
            .types(db)
            .into_iter()
            .map(|(_, argument)| argument)
            .collect();
        if let Some(instantiation) = record(
            loaded,
            file_id,
            token.text_range(),
            (name, written),
            &arguments,
            target,
            types,
        ) {
            found.push(instantiation);
        }
    }
    for node in source
        .syntax()
        .descendants()
        .filter_map(ast::PathType::cast)
    {
        if let Some(instantiation) = through_type(loaded, file_id, &sema, &node, target, types) {
            found.push(instantiation);
        }
    }
    found.sort_by(|a, b| {
        (a.anchor.expansion.start_byte, &a.instantiation_key)
            .cmp(&(b.anchor.expansion.start_byte, &b.instantiation_key))
    });
    // One name can be reached by both readings. Reporting it twice would say a
    // family has more members than there are places in the file.
    found.dedup_by(|a, b| {
        a.anchor.expansion.start_byte == b.anchor.expansion.start_byte
            && a.instantiation_key == b.instantiation_key
    });
    found
}

/// What a type written out amounts to, if it names a generic the scan holds.
fn through_type(
    loaded: &Loaded,
    file_id: ra_ap_vfs::FileId,
    sema: &Semantics<'_, RootDatabase>,
    node: &ast::PathType,
    target: DisplayTarget,
    types: &mut TypeTable,
) -> Option<Instantiation> {
    let db = &loaded.db;
    // The name alone, so that a written-out type anchors where a resolved name
    // would: `Pair` rather than `Pair<i64>`.
    let name = node.path()?.segment()?.name_ref()?;
    let resolved = sema.resolve_type(&ast::Type::PathType(node.clone()))?;
    let adt = resolved.as_adt()?;
    let arguments: Vec<Type<'_>> = resolved.type_arguments().collect();
    if arguments.is_empty() {
        return None;
    }
    let named = instantiated(loaded, Definition::Adt(adt), db)?;
    record(
        loaded,
        file_id,
        name.syntax().text_range(),
        named,
        &arguments,
        target,
        types,
    )
}

/// One instantiation, given what it is of and what it substitutes.
fn record(
    loaded: &Loaded,
    file_id: ra_ap_vfs::FileId,
    at: TextRange,
    (name, written): (String, Option<SourceRange>),
    arguments: &[Type<'_>],
    target: DisplayTarget,
    types: &mut TypeTable,
) -> Option<Instantiation> {
    // A definition with no type parameters is used, not stamped out. The
    // compiler hands a substitution back for every resolution it can settle,
    // generic or not.
    if arguments.is_empty() {
        return None;
    }
    let db = &loaded.db;
    let spelled: Vec<String> = arguments
        .iter()
        .map(|argument| argument.display(db, target).to_string())
        .collect();
    let indices = arguments
        .iter()
        .map(|argument| types.intern(argument, db))
        .collect();
    Some(Instantiation {
        anchor: Anchor {
            expansion: source_range(loaded, file_id, at),
            definition: written,
        },
        instantiation_key: format!("{name}<{}>", spelled.join(", ")),
        definition: name,
        arguments: indices,
    })
}

/// What is being stamped out, and where its one body was written.
///
/// Only functions and types the scan holds: those are what a compiler makes
/// copies of. A field of a generic struct is part of one such copy rather than
/// another one, and counting it would report a struct with four fields as five
/// instantiations.
fn instantiated(
    loaded: &Loaded,
    definition: Definition<'_>,
    db: &RootDatabase,
) -> Option<(String, Option<SourceRange>)> {
    if is_external(definition, db) {
        return None;
    }
    match definition {
        Definition::Function(function) => Some((
            calls::identity(function, db),
            definition_range(loaded, function.source(db)),
        )),
        Definition::Adt(adt) => Some((
            path_of(adt.name(db).as_str(), adt.module(db), db),
            adt_range(loaded, adt),
        )),
        _ => None,
    }
}
