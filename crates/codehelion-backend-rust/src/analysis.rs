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
//! # And an untrusted request is answered from inside its boundary or not at
//! all
//!
//! A request may carry a [`ReadBoundary`], and then every path this analysis
//! resolves for itself has to land under it: the file, its package manifest,
//! and the workspace manifest the package is read through. What each of those
//! costs to check is what deciding to decline costs; nothing outside the
//! boundary reaches an answer. See [`crate::boundary`] for what a boundary does
//! not cover.
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
//!
//! That is a claim about a program on disk, not only about a version string.
//! Cargo reads a configuration file out of the directory it is started in, and
//! the directory it is started in for a target workspace is inside that
//! workspace, so `build.rustc` and the `build.rustc-wrapper` keys beside it are
//! a tree naming a program to run as whoever started this process. The
//! environment in `cargo::compiler_environment` settles which program that is
//! before any of it is read, on every path, including the first handshake —
//! where no permission has been negotiated yet and none can therefore have been
//! given.

mod anchor;
mod cargo;
mod manifest;
mod toolchain;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use codehelion_helper::ir::{
    Anchor, CompilerIr, ResolvedSymbol, SymbolKind, Unavailability, UnitRef,
};
use codehelion_helper::protocol::{BuildDescription, Execution};
use ra_ap_hir::{Adt, Crate, HasSource, ModuleDef};
use ra_ap_ide_db::RootDatabase;
use ra_ap_vfs::Vfs;

use crate::boundary::ReadBoundary;
use crate::{calls, constructs, expansions, instantiations, occurrences};

pub(crate) use anchor::{
    TypeTable, adt_range, definition_range, file_of, path_of, real_file, source_range,
};
pub(crate) use toolchain::require_toolchain;

use anchor::{adt_anchor, anchored, place};
use cargo::{cargo_config_for_workspace, describe_workspace, project_workspace_with_toolchain};
use manifest::{has_build_script, nearest_manifest, program_named_by, within, workspace_manifest};
use toolchain::helper_toolchain;

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
    Unavailable {
        /// The reason a run files the unit under, which travels on the wire.
        reason: Unavailability,
        /// Which of the situations behind that reason this was.
        ///
        /// Several of them stand for more than one: a file with no project
        /// above it, a project outside the boundary the request set and a
        /// crate the workspace does not build all arrive as
        /// [`Unavailability::NoBuildInformation`], and a run that sees only
        /// the reason cannot tell somebody which happened.
        why: String,
    },
}

impl Outcome {
    /// A unit that cannot be analysed, for `why`.
    fn unavailable(reason: Unavailability, why: impl Into<String>) -> Self {
        Self::Unavailable {
            reason,
            why: why.into(),
        }
    }
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
        let Some(manifest) = nearest_manifest(root, None) else {
            return Ok(None);
        };
        let workspace = workspace_manifest(&manifest);
        self.described
            .entry(workspace.clone())
            .or_insert_with(|| describe_workspace(&workspace))
            .clone()
            .map(Some)
    }

    /// Analyse one crate of one workspace, running only what `permitted` says
    /// and reading only inside `boundary`.
    pub(crate) fn analyze(
        &mut self,
        unit: &UnitRef,
        permitted: Permissions,
        boundary: Option<&Path>,
    ) -> Outcome {
        let boundary = boundary.map(ReadBoundary::new);
        let boundary = boundary.as_ref();
        let anchor = Path::new(&unit.file);
        // The file itself, before anything is resolved from it: a request for a
        // file outside the boundary has no answer that respects the boundary.
        if !within(anchor, boundary) {
            return Outcome::unavailable(
                Unavailability::NoBuildInformation,
                format!(
                    "{} is outside the directory this request confined reading to",
                    unit.file
                ),
            );
        }
        let Some(manifest) = nearest_manifest(anchor, boundary) else {
            return Outcome::unavailable(
                Unavailability::NoBuildInformation,
                format!("no Cargo manifest governs {}", unit.file),
            );
        };
        // The package's own manifest decides this, not the workspace's: one
        // member having a build script says nothing about its neighbours.
        if !permitted.build_scripts && has_build_script(&manifest) {
            return Outcome::unavailable(
                Unavailability::RequiresExecution,
                format!(
                    "{} declares a build script, and nothing permitted running it",
                    manifest.display()
                ),
            );
        }
        // Loaded and cached by workspace rather than by package. Reading a
        // member reads the whole workspace anyway, so keying on the member
        // would read the same thing once per member — and would report every
        // path relative to the member it was asked through, which is not how
        // the project spells it.
        let root = workspace_manifest(&manifest);
        // A package whose workspace sits outside the boundary is declined
        // rather than read: the workspace manifest names the members, the
        // profiles and the patched dependencies the package is compiled with,
        // so an answer about this package is an answer about that file too.
        if !within(&root, boundary) {
            return Outcome::unavailable(
                Unavailability::NoBuildInformation,
                format!(
                    "the workspace manifest {} is outside the directory this request confined reading to",
                    root.display()
                ),
            );
        }
        // A workspace is read from inside itself, so the Cargo configuration
        // beside it is the one Cargo obeys, and the keys in it name programs to
        // start. Nothing named there is ever started without a permission —
        // [`compiler_environment`] settles that on its own — and a tree that
        // names one is told so rather than read under a configuration this
        // process disabled behind its back.
        if !permitted.build_scripts
            && let Some(named) = program_named_by(root.parent().unwrap_or(&root))
        {
            return Outcome::unavailable(
                Unavailability::RequiresExecution,
                format!(
                    "{} sets {}, which names a program for Cargo to run, and nothing permitted running it",
                    named.file.display(),
                    named.key
                ),
            );
        }
        let loaded = self
            .loaded
            .entry((root.clone(), permitted))
            .or_insert_with(|| load(&root, permitted));
        match loaded {
            Err(why) => Outcome::unavailable(
                Unavailability::MetadataUnavailable,
                format!("{}: {why}", root.display()),
            ),
            Ok(loaded) => ra_ap_hir::attach_db(&loaded.db, || analyze_crate(loaded, unit)),
        }
    }
}

/// Settings for turning a read [`ra_ap_project_model::ProjectWorkspace`] into
/// the crate graph and VFS a request answers from.
///
/// Its own function so a test can build the identical value without
/// duplicating the reasoning beside each field.
const fn load_cargo_config(permitted: Permissions) -> ra_ap_load_cargo::LoadCargoConfig {
    ra_ap_load_cargo::LoadCargoConfig {
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
    }
}

fn load(manifest: &Path, permitted: Permissions) -> Result<Loaded, String> {
    let toolchain = helper_toolchain()?;
    let config = cargo_config_for_workspace(&toolchain, manifest, permitted);
    let load_config = load_cargo_config(permitted);
    let root = manifest
        .parent()
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
    // Read the workspace once and carry the result forward, instead of
    // reading it here only to have `ra_ap_load_cargo::load_workspace_at`
    // read it again from scratch: `cargo metadata` and sysroot discovery are
    // the expensive part of a semantic scan, and a large workspace paying for
    // them twice is time taken straight out of `helper-timeout-ms`. Running
    // the build scripts and handing the workspace to `load_workspace` is
    // exactly what `load_workspace_at` does internally, minus its own
    // `ProjectWorkspace::load`.
    let mut workspace = project_workspace_with_toolchain(manifest, &toolchain, permitted)?;
    if load_config.load_out_dirs_from_check {
        let build_scripts = workspace
            .run_build_scripts(&config, &|_| {})
            .map_err(|error| error.to_string())?;
        workspace.set_build_scripts(build_scripts);
    }
    let (db, vfs, _proc_macro) =
        ra_ap_load_cargo::load_workspace(workspace, &config.extra_env, &load_config)
            .map_err(|error| error.to_string())?;
    Ok(Loaded { db, vfs, root })
}

/// Everything the compiler knows about one crate, collected into the wire IR.
fn analyze_crate(loaded: &Loaded, unit: &UnitRef) -> Outcome {
    let db = &loaded.db;
    let requested_path = Path::new(&unit.file);
    let Some(requested_id) = file_of(loaded, requested_path) else {
        return Outcome::unavailable(
            Unavailability::NoBuildInformation,
            format!(
                "the workspace at {} holds no file called {}",
                loaded.root.display(),
                unit.file
            ),
        );
    };
    // Spelled from the file the workspace resolved the request to, not from the
    // path the request arrived as. Every anchor below is spelled from the
    // workspace's own copy, and this string decides by equality which of them
    // belong to the requested file: derived from the caller's spelling it would
    // be a second rendering of the same file that only has to agree, and one
    // that names a separator differently agrees on no symbol at all.
    let requested_file = loaded
        .vfs
        .file_path(requested_id)
        .as_path()
        .map(|path| codehelion_helper::ir::spell(Some(&loaded.root), Path::new(path.as_str())))
        .unwrap_or_default();
    let Some(krate) = Crate::all(db).into_iter().find(|krate| {
        krate
            .display_name(db)
            .is_some_and(|name| name.to_string() == unit.unit)
    }) else {
        return Outcome::unavailable(
            Unavailability::NoBuildInformation,
            format!(
                "the workspace at {} builds no crate called {}",
                loaded.root.display(),
                unit.unit
            ),
        );
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
