//! Loading a Cargo workspace and reading what the compiler knows about it.
//!
//! # Nothing here runs the project's code
//!
//! Not by policy but by construction: the two settings that would run it —
//! executing build scripts to learn their output directories, and starting a
//! procedural-macro server — are written as constants with no way to reach
//! them. There is no flag to pass and no configuration to get wrong, because
//! the code that would do it is not present. `cargo metadata` is read, which
//! compiles nothing.
//!
//! The cost is visible rather than hidden. A crate with a build script is
//! reported as [`Unavailability::RequiresExecution`] instead of being analysed
//! with whatever happens to resolve, because a build script can generate types
//! the rest of the crate is written against, and there is no way to tell from
//! outside how much of an answer is missing.
//!
//! # Which compiler answers
//!
//! This program's own, bundled as a library — not the one the project builds
//! with. So the toolchain it reports is its own, and the question a handshake
//! settles is whether it can analyse a project rather than whether it matches
//! it.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use codehelion_helper::ir::{
    Anchor, CompilerIr, ResolvedSymbol, ResolvedType, SourceRange, SymbolKind, Unavailability,
    UnitRef,
};
use ra_ap_hir::{Adt, Crate, HasSource, HirFileId, ModuleDef};
use ra_ap_ide_db::RootDatabase;
use ra_ap_ide_db::base_db::SourceDatabase;
use ra_ap_syntax::AstNode;
use ra_ap_vfs::Vfs;

use crate::types::category;
use crate::{calls, expansions, instantiations, occurrences};

/// A workspace that has been read, kept so a second request about the same
/// project does not pay to read it again.
pub(crate) struct Loaded {
    pub(crate) db: RootDatabase,
    pub(crate) vfs: Vfs,
    pub(crate) root: PathBuf,
}

/// Every workspace this process has read, by the manifest that identifies it.
#[derive(Default)]
pub(crate) struct Workspaces {
    loaded: BTreeMap<PathBuf, Result<Loaded, String>>,
}

/// Why a unit could not be analysed, or the analysis itself.
pub(crate) enum Outcome {
    /// What the compiler knows.
    Analyzed(Box<CompilerIr>),
    /// Nothing can be known, and why.
    Unavailable(Unavailability),
}

impl Workspaces {
    /// Analyse one crate of one workspace.
    pub(crate) fn analyze(&mut self, unit: &UnitRef) -> Outcome {
        let anchor = Path::new(&unit.file);
        let Some(manifest) = nearest_manifest(anchor) else {
            return Outcome::Unavailable(Unavailability::NoBuildInformation);
        };
        // The package's own manifest decides this, not the workspace's: one
        // member having a build script says nothing about its neighbours.
        if has_build_script(&manifest) {
            return Outcome::Unavailable(Unavailability::RequiresExecution);
        }
        // Loaded and cached by workspace rather than by package. Reading a
        // member reads the whole workspace anyway, so keying on the member
        // would read the same thing once per member — and would report every
        // path relative to the member it was asked through, which is not how
        // the project spells it.
        let root = workspace_manifest(&manifest);
        let loaded = self
            .loaded
            .entry(root.clone())
            .or_insert_with(|| load(&root));
        match loaded {
            Err(_) => Outcome::Unavailable(Unavailability::NoBuildInformation),
            Ok(loaded) => ra_ap_hir::attach_db(&loaded.db, || analyze_crate(loaded, unit)),
        }
    }
}

/// The `Cargo.toml` governing `path`, found by walking up from it.
fn nearest_manifest(path: &Path) -> Option<PathBuf> {
    let start = if path.is_dir() { path } else { path.parent()? };
    start.ancestors().find_map(|directory| {
        let manifest = directory.join("Cargo.toml");
        manifest.is_file().then_some(manifest)
    })
}

/// The manifest of the workspace `manifest` belongs to, or `manifest` itself
/// when it is not a member of one.
///
/// The *nearest* enclosing declaration wins, and the search stops there. Taking
/// the outermost instead would attach a project to whatever workspace happens
/// to sit above it on this machine — a checkout under another repository would
/// be read as part of it.
fn workspace_manifest(manifest: &Path) -> PathBuf {
    manifest
        .parent()
        .into_iter()
        .flat_map(Path::ancestors)
        .map(|directory| directory.join("Cargo.toml"))
        .find(|candidate| candidate.is_file() && declares_workspace(candidate))
        .unwrap_or_else(|| manifest.to_path_buf())
}

fn declares_workspace(manifest: &Path) -> bool {
    std::fs::read_to_string(manifest)
        .is_ok_and(|text| text.lines().any(|line| line.trim() == "[workspace]"))
}

/// Whether the package at `manifest` builds something before it compiles.
///
/// Deliberately coarse. The claim being made is "this crate has a build script
/// and nothing ran it", which is exactly what a `build.rs` beside the manifest
/// or a `build =` key inside it establishes; how much of the crate depends on
/// what that script would have produced is not knowable without running it,
/// which is the thing being declined.
fn has_build_script(manifest: &Path) -> bool {
    if manifest.with_file_name("build.rs").is_file() {
        return true;
    }
    std::fs::read_to_string(manifest).is_ok_and(|text| {
        text.lines()
            .any(|line| line.trim_start().starts_with("build ="))
    })
}

fn load(manifest: &Path) -> Result<Loaded, String> {
    let config = ra_ap_project_model::CargoConfig {
        // Without the standard library almost every type resolves to nothing,
        // and evidence made of unknowns is worse than no evidence: it looks
        // like agreement.
        sysroot: Some(ra_ap_project_model::RustLibSource::Discover),
        ..ra_ap_project_model::CargoConfig::default()
    };
    let load_config = ra_ap_load_cargo::LoadCargoConfig {
        // The two settings that would run the project's code. Constants, with
        // nothing that can change them.
        load_out_dirs_from_check: false,
        with_proc_macro_server: ra_ap_load_cargo::ProcMacroServerChoice::None,
        prefill_caches: false,
        num_worker_threads: 1,
        proc_macro_processes: 0,
    };
    let root = manifest
        .parent()
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
    let (db, vfs, _proc_macro) =
        ra_ap_load_cargo::load_workspace_at(manifest, &config, &load_config, &|_| {})
            .map_err(|error| error.to_string())?;
    Ok(Loaded { db, vfs, root })
}

/// Everything the compiler knows about one crate, collected into the wire IR.
fn analyze_crate(loaded: &Loaded, unit: &UnitRef) -> Outcome {
    let db = &loaded.db;
    let Some(krate) = Crate::all(db).into_iter().find(|krate| {
        krate
            .display_name(db)
            .is_some_and(|name| name.to_string() == unit.unit)
    }) else {
        return Outcome::Unavailable(Unavailability::NoBuildInformation);
    };

    let mut ir = CompilerIr::empty(unit.clone());
    let mut types = TypeTable::default();
    let mut modules = vec![krate.root_module(db)];
    while let Some(module) = modules.pop() {
        modules.extend(module.children(db));
        for definition in module.declarations(db) {
            collect(loaded, definition, None, &mut ir, &mut types);
        }
    }
    // What the macros invoked in this file declared. The walk above passes
    // those over, because a declaration inside an expansion has no place in a
    // file until somebody says which invocation it came out of.
    for expanded in expansions::collect(loaded, Path::new(&unit.file)) {
        collect(
            loaded,
            expanded.definition,
            Some(&expanded.anchor),
            &mut ir,
            &mut types,
        );
    }
    // Names, after declarations, so that a name occurring exactly where a
    // declaration begins is dropped rather than recorded twice. That can only
    // happen where the declaration opens with its own name — a field, and
    // nothing else — so the entry that survives is the one that says more.
    let declared: BTreeSet<(String, u64)> = ir.symbols.iter().map(place).collect();
    for occurrence in occurrences::collect(loaded, Path::new(&unit.file), &mut types) {
        if !declared.contains(&place(&occurrence)) {
            ir.symbols.push(occurrence);
        }
    }
    ir.instantiations = instantiations::collect(loaded, Path::new(&unit.file), krate, &mut types);
    ir.calls = calls::collect(loaded, Path::new(&unit.file));
    ir.calls.sort_by_key(|call| {
        (
            call.anchor.expansion.start_byte,
            call.anchor.expansion.end_byte,
        )
    });
    ir.types = types.finish();
    // Sorted so that two runs over one unchanged workspace produce the same
    // document: the module walk above visits in whatever order the database
    // hands things back.
    ir.symbols.sort_by(|a, b| {
        (
            &a.anchor.expansion.file,
            a.anchor.expansion.start_byte,
            &a.id,
        )
            .cmp(&(
                &b.anchor.expansion.file,
                b.anchor.expansion.start_byte,
                &b.id,
            ))
    });
    Outcome::Analyzed(Box::new(ir))
}

/// Where a symbol sits, which is what makes two entries the same entry.
fn place(symbol: &ResolvedSymbol) -> (String, u64) {
    (
        symbol.anchor.expansion.file.clone(),
        symbol.anchor.expansion.start_byte,
    )
}

/// Add what the compiler knows about one declaration to `ir`.
///
/// `origin` is set for a declaration a macro produced. Everything it declares
/// — the item, and the fields inside it — anchors at the invocation, because
/// that is the only place in a file any of it can be pointed at.
fn collect(
    loaded: &Loaded,
    definition: ModuleDef,
    origin: Option<&Anchor>,
    ir: &mut CompilerIr,
    types: &mut TypeTable,
) {
    let db = &loaded.db;
    match definition {
        ModuleDef::Function(function) => {
            let Some(anchor) = anchored(loaded, origin, function.source(db)) else {
                return;
            };
            let returns = types.intern(&function.ret_type(db), db);
            ir.symbols.push(ResolvedSymbol {
                id: path_of(function.name(db).as_str(), function.module(db), db),
                name: function.name(db).as_str().to_string(),
                kind: SymbolKind::Function,
                anchor,
                type_index: Some(returns),
                // Every declaration collected here is one this crate holds. A
                // use that resolves elsewhere is a different question, asked of
                // occurrences rather than of definitions.
                external: false,
            });
        }
        ModuleDef::Adt(adt) => {
            let name = adt.name(db).as_str().to_string();
            if let Some(anchor) = adt_anchor(loaded, origin, adt) {
                ir.symbols.push(ResolvedSymbol {
                    id: path_of(&name, adt.module(db), db),
                    name: name.clone(),
                    kind: SymbolKind::Type,
                    anchor,
                    type_index: None,
                    external: false,
                });
            }
            if let Adt::Struct(structure) = adt {
                for field in structure.fields(db) {
                    let Some(anchor) = anchored(loaded, origin, field.source(db)) else {
                        continue;
                    };
                    let field_name = field.name(db).as_str().to_string();
                    let index = types.intern(&field.ty(db), db);
                    ir.symbols.push(ResolvedSymbol {
                        id: format!("{}::{field_name}", path_of(&name, adt.module(db), db)),
                        name: field_name,
                        kind: SymbolKind::Field,
                        anchor,
                        type_index: Some(index),
                        external: false,
                    });
                }
            }
        }
        ModuleDef::Const(konst) => {
            let Some(anchor) = anchored(loaded, origin, konst.source(db)) else {
                return;
            };
            let name = konst
                .name(db)
                .map(|name| name.as_str().to_string())
                .unwrap_or_default();
            let index = types.intern(&konst.ty(db), db);
            ir.symbols.push(ResolvedSymbol {
                id: path_of(&name, konst.module(db), db),
                name,
                kind: SymbolKind::Constant,
                anchor,
                type_index: Some(index),
                external: false,
            });
        }
        ModuleDef::Static(statik) => {
            let Some(anchor) = anchored(loaded, origin, statik.source(db)) else {
                return;
            };
            let name = statik.name(db).as_str().to_string();
            let index = types.intern(&statik.ty(db), db);
            ir.symbols.push(ResolvedSymbol {
                id: path_of(&name, statik.module(db), db),
                name,
                kind: SymbolKind::Constant,
                anchor,
                type_index: Some(index),
                external: false,
            });
        }
        _ => {}
    }
}

fn adt_anchor(loaded: &Loaded, origin: Option<&Anchor>, adt: Adt) -> Option<Anchor> {
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
fn anchored<T: AstNode>(
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
        .map(|path| {
            let path = Path::new(path.as_str());
            path.strip_prefix(&loaded.root)
                .unwrap_or(path)
                .display()
                .to_string()
        })
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

    fn finish(self) -> Vec<ResolvedType> {
        self.entries
    }
}

fn display_of(ty: &ra_ap_hir::Type<'_>, db: &RootDatabase) -> String {
    ty.as_adt().map_or_else(
        || category(ty, db).name().to_string(),
        |adt| adt.name(db).as_str().to_string(),
    )
}
