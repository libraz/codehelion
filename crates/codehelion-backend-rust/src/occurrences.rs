//! Every name written in one file, and what the compiler resolved it to.
//!
//! # Why this is the reading the normalizer wants
//!
//! Normalization has to decide, for each identifier, whether to keep it or
//! replace it with a placeholder. Kept names are the vocabulary two fragments
//! are compared on; replaced ones are the details a type-2 clone is allowed to
//! differ in. Without a compiler that decision is a lexical guess — capitalised
//! means a type, followed by `::` means a path — and the guess is wrong in both
//! directions at once: a closure named like a method survives when it should
//! not, and a lowercase free function from another crate is renamed when it
//! should not be. Both errors are silent, and the second is the expensive one,
//! because two fragments calling the same library function stop looking alike.
//!
//! What a compiler answers instead is where the definition lives. A name whose
//! definition is outside the scanned code is a shared interface: two fragments
//! that both call it are alike in a way that survives renaming everything they
//! own. A name defined inside the scan is a detail of one of them.
//!
//! # Why the crate, not the file, decides "outside"
//!
//! A path check would call a dependency vendored into the tree local and a
//! workspace member reached through a symlink external. The build system
//! already partitions crates into members and everything else, which is the
//! same question asked where it has an answer.
//!
//! # Why this pass is scoped to the requested file
//!
//! Unlike the declarations, which are collected for the whole crate, name
//! occurrences are collected only for the file that was asked about. A crate is
//! asked about once per file, so crate-wide occurrences would be re-read once
//! per file — quadratic in the size of the crate for evidence the caller reads
//! one file at a time.

use std::path::Path;

use codehelion_helper::ir::{Anchor, ResolvedSymbol, SymbolKind};
use ra_ap_hir::Semantics;
use ra_ap_ide_db::RootDatabase;
use ra_ap_ide_db::defs::{Definition, IdentClass};
use ra_ap_syntax::{AstNode, SyntaxKind};

use crate::analysis::{Loaded, TypeTable, path_of, real_file, source_range};

/// One symbol per resolved name in `file`.
///
/// A name the compiler could not place is left out rather than reported as
/// unresolved: the lexical rules are a better answer than a wrong one, and
/// they are what the normalizer falls back to for a byte nobody spoke about.
pub(crate) fn collect(loaded: &Loaded, file: &Path, types: &mut TypeTable) -> Vec<ResolvedSymbol> {
    let mut found = Vec::new();
    let Some(file_id) = file_of(loaded, file) else {
        return found;
    };
    let db = &loaded.db;
    let sema = Semantics::new(db);
    // The file's own crate decides the edition. Parsing with the wrong one
    // moves the boundary between identifier and keyword, which is the same
    // hazard as reading a file with the wrong parser.
    let Some(editioned) = sema.attach_first_edition_opt(file_id) else {
        return found;
    };
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
        // A name can name two things at once — `Foo { field }` binds a local
        // and refers to a field. Both are defined in the same place, so the
        // verdict is the same either way and the first is enough.
        let Some((definition, _)) = class.definitions().into_iter().next() else {
            continue;
        };
        let anchor = Anchor::written_here(source_range(loaded, file_id, token.text_range()));
        found.push(ResolvedSymbol {
            id: identity(loaded, definition, db),
            name: token.text().to_string(),
            kind: kind_of(definition),
            anchor,
            type_index: type_of(definition, db, types),
            external: is_external(definition, db),
        });
    }
    found
}

/// The file the workspace holds for `path`, if it holds one.
///
/// Compared against what the loader recorded rather than resolved on the
/// filesystem for every candidate: a workspace holds thousands of files, and
/// asking the operating system about each of them to answer one question is a
/// cost paid on every request.
fn file_of(loaded: &Loaded, path: &Path) -> Option<ra_ap_vfs::FileId> {
    let canonical = path.canonicalize().ok();
    loaded.vfs.iter().find_map(|(id, vfs_path)| {
        let candidate = Path::new(vfs_path.as_path()?.as_str());
        (candidate == path || Some(candidate) == canonical.as_deref()).then_some(id)
    })
}

/// Whether the definition of `definition` is outside the code being scanned.
///
/// A definition belonging to no crate at all — a primitive, a built-in
/// attribute — counts as outside. Nobody in the scan wrote `u32`, and a
/// normalizer that renamed it would be comparing two fragments on a vocabulary
/// neither of them chose.
fn is_external(definition: Definition<'_>, db: &RootDatabase) -> bool {
    definition
        .krate(db)
        .is_none_or(|krate| !krate.origin(db).is_local())
}

/// What kind of thing a name names.
const fn kind_of(definition: Definition<'_>) -> SymbolKind {
    match definition {
        Definition::Function(_) => SymbolKind::Function,
        Definition::Adt(_)
        | Definition::Trait(_)
        | Definition::TypeAlias(_)
        | Definition::SelfType(_)
        | Definition::BuiltinType(_) => SymbolKind::Type,
        Definition::Field(_) | Definition::TupleField(_) => SymbolKind::Field,
        Definition::EnumVariant(_) => SymbolKind::Variant,
        Definition::Const(_) | Definition::Static(_) => SymbolKind::Constant,
        Definition::Module(_) | Definition::Crate(_) | Definition::ExternCrateDecl(_) => {
            SymbolKind::Namespace
        }
        Definition::Local(_) | Definition::GenericParam(_) | Definition::Label(_) => {
            SymbolKind::Binding
        }
        _ => SymbolKind::Other,
    }
}

/// The identity of what a name resolved to.
///
/// Locals carry where they were bound as well as their path, because a path
/// alone gives the two `total`s of two neighbouring functions the same
/// identity, and an identity two definitions share is not one. The compiler's
/// own number for a binding does not settle it either: it counts within one
/// body, so the first binding of every function carries the same number.
fn identity(loaded: &Loaded, definition: Definition<'_>, db: &RootDatabase) -> String {
    let name = definition
        .name(db)
        .map_or_else(String::new, |name| name.as_str().to_string());
    let path = definition
        .module(db)
        .map_or_else(|| name.clone(), |module| path_of(&name, module, db));
    let Definition::Local(local) = definition else {
        return path;
    };
    let source = local.primary_source(db);
    // A binding produced by a macro has no place in a file to be named by, so
    // it falls back to the number — unique within the body, which is as far as
    // this can go without expanding the macro.
    real_file(source.file(), db).map_or_else(
        || format!("{path}#{}", local.as_id()),
        |file| {
            let range = source_range(loaded, file, source.syntax().text_range());
            format!("{path}@{}:{}", range.file, range.start_byte)
        },
    )
}

/// The type of what a name resolved to, where a name has one.
///
/// Only bindings and fields: the declarations pass already records the type of
/// every function, constant and field the crate declares, and re-deriving it
/// per occurrence would pay for the same answer once per mention. A local's
/// type is the one nothing else records, and it is the one a structural
/// reading cannot see.
fn type_of(definition: Definition<'_>, db: &RootDatabase, types: &mut TypeTable) -> Option<u32> {
    match definition {
        Definition::Local(local) => Some(types.intern(&local.ty(db), db)),
        Definition::Field(field) => Some(types.intern(&field.ty(db), db)),
        _ => None,
    }
}
