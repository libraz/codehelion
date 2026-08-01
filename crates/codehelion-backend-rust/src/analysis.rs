//! Loading a Cargo workspace and reading what the compiler knows about it.
//!
//! # Nothing here runs the project's code unless the request said so
//!
//! One value decides it, and it arrives in the request: [`Permissions`] is
//! built from what the client permitted and from nothing else. There is no
//! default that grants anything, no setting to get wrong and no path that
//! reaches an executing configuration without a permission having travelled to
//! this process — a run that permits nothing and a build of this program that
//! could not execute at all behave identically.
//!
//! Starting a procedural-macro server is not among the things a permission can
//! turn on here: this helper does not offer that class at all, so a person who
//! permits it is told rather than left with a thinner answer than they asked
//! for.
//!
//! The cost of refusing is visible rather than hidden. A crate with a build
//! script nobody permitted is reported as
//! [`Unavailability::RequiresExecution`] instead of being analysed with
//! whatever happens to resolve, because a build script can generate types the
//! rest of the crate is written against, and there is no way to tell from
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
use codehelion_helper::protocol::{BuildDescription, Execution};
use ra_ap_hir::{Adt, Crate, HasSource, HirFileId, ModuleDef};
use ra_ap_ide_db::RootDatabase;
use ra_ap_ide_db::base_db::SourceDatabase;
use ra_ap_syntax::AstNode;
use ra_ap_vfs::Vfs;

use crate::types::category;
use crate::{calls, constructs, expansions, instantiations, occurrences};

/// A workspace that has been read, kept so a second request about the same
/// project does not pay to read it again.
pub(crate) struct Loaded {
    pub(crate) db: RootDatabase,
    pub(crate) vfs: Vfs,
    pub(crate) root: PathBuf,
}

/// What a request permitted this process to run out of the project.
///
/// One field, because one class is all this helper acts on. A permission it
/// does not act on never reaches here: the handshake says what it will do, and
/// granting anything else is refused where somebody can be told.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Permissions {
    /// Whether build scripts may be run and their output read.
    pub(crate) build_scripts: bool,
}

impl Permissions {
    /// What `permitted` allows, ignoring classes this helper does not act on.
    pub(crate) fn of(permitted: &[Execution]) -> Self {
        Self {
            build_scripts: permitted.contains(&Execution::BuildScript),
        }
    }
}

/// Every workspace this process has read, by the manifest that identifies it
/// and the permissions it was read under.
///
/// Keyed by both, because a workspace read with its build scripts run is not
/// the same reading as one read without them: a cache on the path alone would
/// answer a permitted request from a refused reading, or the reverse.
#[derive(Default)]
pub(crate) struct Workspaces {
    loaded: BTreeMap<(PathBuf, Permissions), Result<Loaded, String>>,
    described: BTreeMap<PathBuf, Result<BuildDescription, String>>,
}

/// Why a unit could not be analysed, or the analysis itself.
pub(crate) enum Outcome {
    /// What the compiler knows.
    Analyzed(Box<CompilerIr>),
    /// Nothing can be known, and why.
    Unavailable(Unavailability),
}

impl Workspaces {
    /// What the code under `root` is analysed under.
    ///
    /// `Ok(None)` when there is no Cargo project here at all, which is a thing
    /// this can say rather than a failure to say anything: a tree with no
    /// manifest has no build to be described, and every answer about it will
    /// be the same one.
    ///
    /// Read from `cargo metadata` and the compiler's own `--print cfg` before
    /// loading the workspace, so a request with no project can be declined
    /// without constructing compiler state.
    pub(crate) fn describe(&mut self, root: &Path) -> Result<Option<BuildDescription>, String> {
        let Some(manifest) = nearest_manifest(root) else {
            return Ok(None);
        };
        let workspace = workspace_manifest(&manifest);
        self.described
            .entry(workspace.clone())
            .or_insert_with(|| describe_workspace(&workspace))
            .clone()
            .map(Some)
    }

    /// Analyse one crate of one workspace, running only what `permitted` says.
    pub(crate) fn analyze(&mut self, unit: &UnitRef, permitted: Permissions) -> Outcome {
        let anchor = Path::new(&unit.file);
        let Some(manifest) = nearest_manifest(anchor) else {
            return Outcome::Unavailable(Unavailability::NoBuildInformation);
        };
        // The package's own manifest decides this, not the workspace's: one
        // member having a build script says nothing about its neighbours.
        if !permitted.build_scripts && has_build_script(&manifest) {
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
            .entry((root.clone(), permitted))
            .or_insert_with(|| load(&root, permitted));
        match loaded {
            Err(_) => Outcome::Unavailable(Unavailability::MetadataUnavailable),
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

/// How this process reads a project, wherever it reads one.
///
/// One value, so that what a run is told it was analysed under and what it was
/// actually analysed under cannot drift apart: the description below and the
/// load above are two readings of the same configuration.
fn cargo_config() -> ra_ap_project_model::CargoConfig {
    ra_ap_project_model::CargoConfig {
        // Without the standard library almost every type resolves to nothing,
        // and evidence made of unknowns is worse than no evidence: it looks
        // like agreement.
        sysroot: Some(ra_ap_project_model::RustLibSource::Discover),
        // Resolving a target project is part of reading it. It must neither
        // contact a registry. `project_workspace` first proves that Cargo can
        // read this project with `--offline --locked`; rust-analyzer then
        // redirects its own offline read to an isolated lockfile copy. The
        // metadata list is separate because rust-analyzer forwards it
        // independently.
        extra_args: vec!["--offline".to_owned()],
        metadata_extra_args: vec!["--offline".to_owned()],
        ..ra_ap_project_model::CargoConfig::default()
    }
}

fn project_workspace(manifest: &Path) -> Result<ra_ap_project_model::ProjectWorkspace, String> {
    verify_locked_offline_metadata(manifest)?;
    let path = manifest
        .to_str()
        .and_then(|path| ra_ap_vfs::AbsPathBuf::try_from(path).ok())
        .ok_or_else(|| {
            format!(
                "the manifest path is not absolute utf-8: {}",
                manifest.display()
            )
        })?;
    let found = ra_ap_project_model::ProjectManifest::from_manifest_file(path)
        .map_err(|error| error.to_string())?;
    let workspace = ra_ap_project_model::ProjectWorkspace::load(found, &cargo_config(), &|_| {})
        .map_err(|error| error.to_string())?;
    if let ra_ap_project_model::ProjectWorkspaceKind::Cargo {
        error: Some(error), ..
    } = &workspace.kind
    {
        return Err(format!(
            "Cargo metadata requires a local locked dependency resolution: {error}"
        ));
    }
    Ok(workspace)
}

/// Prove that Cargo can resolve the project without either network access or a
/// lockfile update before rust-analyzer loads it through its isolated copy.
#[allow(
    clippy::disallowed_types,
    reason = "this compiler helper is the designated subprocess isolation boundary"
)]
fn verify_locked_offline_metadata(manifest: &Path) -> Result<(), String> {
    let output = std::process::Command::new("cargo")
        .args([
            "metadata",
            "--format-version=1",
            "--offline",
            "--locked",
            "--manifest-path",
        ])
        .arg(manifest)
        .current_dir(manifest.parent().unwrap_or_else(|| Path::new(".")))
        .output()
        .map_err(|error| format!("could not start Cargo metadata: {error}"))?;
    if output.status.success() {
        return Ok(());
    }
    Err(format!(
        "Cargo metadata requires a local locked dependency resolution: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    ))
}

/// What the workspace at `manifest` is read under.
///
/// A member's own features and those of its direct dependencies. A direct
/// dependency's feature selection lives in the member's manifest, yet it does
/// not necessarily change `Cargo.lock`; omitting it could therefore merge two
/// different resolved programs. Transitive packages remain out: their feature
/// sets are derived from the direct selections and the lockfile, and recording
/// every resolver-internal choice would split a variant when Cargo changes an
/// irrelevant implementation detail.
fn describe_workspace(manifest: &Path) -> Result<BuildDescription, String> {
    let workspace = project_workspace(manifest)?;
    let mut cfgs: Vec<String> = workspace
        .rustc_cfg
        .iter()
        .map(ToString::to_string)
        .collect();
    let mut features = Vec::new();
    if let ra_ap_project_model::ProjectWorkspaceKind::Cargo { cargo, .. } = &workspace.kind {
        for package in cargo.packages() {
            let data = &cargo[package];
            if !data.is_member {
                continue;
            }
            for feature in &data.active_features {
                features.push(format!("{}/{feature}", data.name));
            }
            for dependency in &data.dependencies {
                let dependency = &cargo[dependency.pkg];
                for feature in &dependency.active_features {
                    features.push(format!("{}/{feature}", dependency.name));
                }
            }
        }
    }
    cfgs.sort();
    cfgs.dedup();
    features.sort();
    features.dedup();
    Ok(BuildDescription { features, cfgs })
}

fn load(manifest: &Path, permitted: Permissions) -> Result<Loaded, String> {
    let config = cargo_config();
    let load_config = ra_ap_load_cargo::LoadCargoConfig {
        // The one setting here that runs the project's code, and the only
        // thing that turns it on is a permission that travelled with the
        // request. Running build scripts is what makes the output directory
        // they wrote readable, which is the whole of what permitting them buys.
        load_out_dirs_from_check: permitted.build_scripts,
        // Not reachable by any permission: starting a procedural-macro server
        // is a class this helper does not offer, so nobody can be under the
        // impression they turned it on.
        with_proc_macro_server: ra_ap_load_cargo::ProcMacroServerChoice::None,
        prefill_caches: false,
        num_worker_threads: 1,
        proc_macro_processes: 0,
    };
    let root = manifest
        .parent()
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
    project_workspace(manifest)?;
    let (db, vfs, _proc_macro) =
        ra_ap_load_cargo::load_workspace_at(manifest, &config, &load_config, &|_| {})
            .map_err(|error| error.to_string())?;
    Ok(Loaded { db, vfs, root })
}

/// Everything the compiler knows about one crate, collected into the wire IR.
fn analyze_crate(loaded: &Loaded, unit: &UnitRef) -> Outcome {
    let db = &loaded.db;
    let requested_path = Path::new(&unit.file);
    if file_of(loaded, requested_path).is_none() {
        return Outcome::Unavailable(Unavailability::NoBuildInformation);
    }
    let requested_file = codehelion_helper::ir::spell(Some(&loaded.root), requested_path);
    let Some(krate) = Crate::all(db).into_iter().find(|krate| {
        krate
            .display_name(db)
            .is_some_and(|name| name.to_string() == unit.unit)
    }) else {
        return Outcome::Unavailable(Unavailability::NoBuildInformation);
    };

    let mut ir = CompilerIr::empty(unit.clone());
    ir.anchored_at = Some(loaded.root.display().to_string());
    let mut types = TypeTable::default();
    let mut modules = vec![krate.root_module(db)];
    while let Some(module) = modules.pop() {
        modules.extend(module.children(db));
        for definition in module.declarations(db) {
            collect(
                loaded,
                definition,
                None,
                &requested_file,
                &mut ir,
                &mut types,
            );
        }
    }
    // What the macros invoked in this file declared. The walk above passes
    // those over, because a declaration inside an expansion has no place in a
    // file until somebody says which invocation it came out of.
    let macros = expansions::collect(loaded, Path::new(&unit.file), &mut types);
    for expanded in macros.expanded {
        collect(
            loaded,
            expanded.definition,
            Some(&expanded.anchor),
            &requested_file,
            &mut ir,
            &mut types,
        );
    }
    ir.unexpanded_macros = macros.unexpanded;
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
    ir.semantic_constructs = constructs::collect(loaded, Path::new(&unit.file));
    ir.effects = codehelion_helper::effects::summarize(&ir.semantic_constructs);
    ir.data_flow = crate::data_flow::collect(loaded, Path::new(&unit.file), &ir.calls);
    ir.calls.extend(macros.calls);
    ir.expressions = macros.expressions;
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

/// Keep one declaration for each compiler symbol when the module walk and an
/// explicit macro-expansion walk both reached it.
///
/// Rust-analyzer can expose an item from a declarative macro through a module
/// declaration as well as through the expansion tree. The latter carries the
/// invocation-to-definition anchor the protocol promises, so it wins over an
/// otherwise identical ordinary anchor. Different declarations cannot share
/// this key inside a well-formed crate; their module path is part of `id`.
/// Add what the compiler knows about one declaration to `ir`.
///
/// `origin` is set for a declaration a macro produced. Everything it declares
/// — the item, and the fields inside it — anchors at the invocation, because
/// that is the only place in a file any of it can be pointed at.
fn collect(
    loaded: &Loaded,
    definition: ModuleDef,
    origin: Option<&Anchor>,
    requested_file: &str,
    ir: &mut CompilerIr,
    types: &mut TypeTable,
) {
    let db = &loaded.db;
    match definition {
        ModuleDef::Function(function) => {
            let Some(anchor) = anchored(loaded, origin, function.source(db)) else {
                return;
            };
            if anchor.expansion.file != requested_file {
                return;
            }
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
            let Some(anchor) = adt_anchor(loaded, origin, adt) else {
                return;
            };
            if anchor.expansion.file != requested_file {
                return;
            }
            ir.symbols.push(ResolvedSymbol {
                id: path_of(&name, adt.module(db), db),
                name: name.clone(),
                kind: SymbolKind::Type,
                anchor,
                type_index: None,
                external: false,
            });
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
            if anchor.expansion.file != requested_file {
                return;
            }
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
            if anchor.expansion.file != requested_file {
                return;
            }
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
///
/// Against the workspace root this process read the project from, which the
/// analysis states in [`CompilerIr::anchored_at`] — the spelling is written and
/// read back by one shared rule rather than by two that have to agree.
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

#[cfg(test)]
mod tests {
    use super::cargo_config;

    #[test]
    fn rust_analyzer_metadata_is_offline_after_the_locked_preflight() {
        let config = cargo_config();
        assert_eq!(config.extra_args, ["--offline"]);
        assert_eq!(config.metadata_extra_args, ["--offline"]);
    }
}
