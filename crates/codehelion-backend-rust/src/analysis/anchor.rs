//! Where the compiler's answers sit in the files somebody wrote.
//!
//! A definition, a byte range and a type each have to be spelled the way the
//! project spells them before they can travel, and the spelling has to be one
//! rule rather than two that agree. Everything that turns a rust-analyzer
//! handle into a location, a path or an interned type is here.

use std::collections::BTreeMap;
use std::path::Path;

use codehelion_helper::ir::{Anchor, ResolvedSymbol, ResolvedType, SourceRange};
use ra_ap_hir::{Adt, HasSource, HirFileId};
use ra_ap_ide_db::RootDatabase;
use ra_ap_ide_db::base_db::SourceDatabase;
use ra_ap_syntax::AstNode;

use super::Loaded;
use crate::types::category;

/// Where a symbol sits, which is what makes two entries the same entry.
pub(super) fn place(symbol: &ResolvedSymbol) -> (String, u64) {
    (
        symbol.anchor.expansion.file.clone(),
        symbol.anchor.expansion.start_byte,
    )
}

pub(super) fn adt_anchor(loaded: &Loaded, origin: Option<&Anchor>, adt: Adt) -> Option<Anchor> {
    origin
        .cloned()
        .or_else(|| adt_range(loaded, adt).map(Anchor::written_here))
}

/// Where a type was written.
pub(crate) fn adt_range(loaded: &Loaded, adt: Adt) -> Option<SourceRange> {
    let db = &loaded.db;
    match adt {
        Adt::Struct(item) => definition_range(loaded, item.source(db)),
        Adt::Enum(item) => definition_range(loaded, item.source(db)),
        Adt::Union(item) => definition_range(loaded, item.source(db)),
    }
}

/// Where a declaration is, given what it came out of.
pub(super) fn anchored<T: AstNode>(
    loaded: &Loaded,
    origin: Option<&Anchor>,
    source: Option<ra_ap_hir::InFile<T>>,
) -> Option<Anchor> {
    origin.cloned().or_else(|| anchor_of(loaded, source))
}

/// The path a definition is known by, as the compiler spells it.
pub(crate) fn path_of(name: &str, module: ra_ap_hir::Module, db: &RootDatabase) -> String {
    let mut segments: Vec<String> = module
        .path_to_root(db)
        .into_iter()
        .rev()
        .filter_map(|part| part.name(db).map(|name| name.as_str().to_string()))
        .collect();
    let krate = module
        .krate(db)
        .display_name(db)
        .map_or_else(|| "crate".to_string(), |name| name.to_string());
    segments.insert(0, krate);
    segments.push(name.to_string());
    segments.join("::")
}

/// Where a definition sits, in the file it sits in.
///
/// `None` for anything whose source is inside a macro expansion rather than in
/// a file. Reporting it against the expansion site would place a definition
/// nobody wrote at a location somebody did, which is exactly the confusion the
/// anchor's two halves exist to prevent — and until macro expansion is a
/// capability this helper offers, leaving it out is the honest answer.
fn anchor_of<T: AstNode>(loaded: &Loaded, source: Option<ra_ap_hir::InFile<T>>) -> Option<Anchor> {
    definition_range(loaded, source).map(Anchor::written_here)
}

/// The range a declaration occupies in a file, if it occupies one.
pub(crate) fn definition_range<T: AstNode>(
    loaded: &Loaded,
    source: Option<ra_ap_hir::InFile<T>>,
) -> Option<SourceRange> {
    let source = source?;
    let file_id = real_file(source.file_id, &loaded.db)?;
    Some(source_range(
        loaded,
        file_id,
        source.value.syntax().text_range(),
    ))
}

/// The file the workspace holds for `path`, if it holds one.
///
/// Compared against what the loader recorded rather than resolved on the
/// filesystem for every candidate: a workspace holds thousands of files, and
/// asking the operating system about each of them to answer one question is a
/// cost paid on every request.
pub(crate) fn file_of(loaded: &Loaded, path: &Path) -> Option<ra_ap_vfs::FileId> {
    let canonical = path.canonicalize().ok();
    loaded.vfs.iter().find_map(|(id, vfs_path)| {
        let candidate = Path::new(vfs_path.as_path()?.as_str());
        (candidate == path || Some(candidate) == canonical.as_deref()).then_some(id)
    })
}

/// A byte range of one file, spelled the way the project spells the file.
///
/// Against the workspace root this process read the project from, which the
/// analysis states in [`codehelion_helper::ir::CompilerIr::anchored_at`] — the
/// spelling is written and read back by one shared rule rather than by two that
/// have to agree.
pub(crate) fn source_range(
    loaded: &Loaded,
    file_id: ra_ap_vfs::FileId,
    range: ra_ap_syntax::TextRange,
) -> SourceRange {
    let start = u32::from(range.start());
    let text = loaded.db.file_text(file_id).text(&loaded.db).to_string();
    let path = loaded
        .vfs
        .file_path(file_id)
        .as_path()
        .map(|path| codehelion_helper::ir::spell(Some(&loaded.root), Path::new(path.as_str())))
        .unwrap_or_default();
    SourceRange {
        file: path,
        start_byte: u64::from(start),
        end_byte: u64::from(u32::from(range.end())),
        start_line: line_of(&text, start as usize),
    }
}

pub(crate) fn real_file(file_id: HirFileId, db: &RootDatabase) -> Option<ra_ap_vfs::FileId> {
    file_id.file_id().map(|file| file.file_id(db))
}

/// The one-based line the byte at `offset` falls on.
fn line_of(text: &str, offset: usize) -> u32 {
    let counted = text
        .get(..offset.min(text.len()))
        .map_or(0, |head| head.bytes().filter(|byte| *byte == b'\n').count());
    u32::try_from(counted).unwrap_or(u32::MAX).saturating_add(1)
}

/// The types a unit mentions, each recorded once.
#[derive(Default)]
pub(crate) struct TypeTable {
    seen: BTreeMap<(String, &'static str), u32>,
    entries: Vec<ResolvedType>,
}

impl TypeTable {
    /// The index of `ty` in the table, adding it if this is its first mention.
    pub(crate) fn intern(&mut self, ty: &ra_ap_hir::Type<'_>, db: &RootDatabase) -> u32 {
        let category = category(ty, db);
        let display = display_of(ty, db);
        let key = (display.clone(), category.name());
        if let Some(index) = self.seen.get(&key) {
            return *index;
        }
        let index = u32::try_from(self.entries.len()).unwrap_or(u32::MAX);
        self.entries.push(ResolvedType {
            display,
            category,
            // Left empty until a use asks for it: filling in every type
            // argument of every type pulls in the whole standard library's
            // generic surface for evidence nothing yet reads.
            arguments: Vec::new(),
            definition: ty.as_adt().map(|adt| adt.name(db).as_str().to_string()),
        });
        self.seen.insert(key, index);
        index
    }

    pub(super) fn finish(self) -> Vec<ResolvedType> {
        self.entries
    }
}

fn display_of(ty: &ra_ap_hir::Type<'_>, db: &RootDatabase) -> String {
    ty.as_adt().map_or_else(
        || category(ty, db).name().to_string(),
        |adt| adt.name(db).as_str().to_string(),
    )
}
