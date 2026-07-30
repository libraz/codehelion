//! Reading one translation unit with Clang and reporting what it knows about
//! one file of it.
//!
//! # Why a file is asked about through a translation unit
//!
//! In C and C++ a header is not a program. `accumulate.hpp` compiled with
//! `-DACCUM_WIDTH=64` declares different types from the same characters
//! compiled without it, and both readings are real — they are what the two
//! translation units that include it actually compile. So an answer here is
//! about a pair: this file, as read by this unit. Asking about the file alone
//! would mean picking one of the readings and presenting it as the reading.
//!
//! That is also why the same header asked about through two units is two
//! analyses rather than one repeated: they disagree, and the disagreement is
//! the point.
//!
//! # Why an answer covers the whole unit
//!
//! What comes back is everything the unit read that lies inside the tree, each
//! name filed under the file it is written in — not only the file the request
//! named. A header is compiled by no command of its own, so a request naming it
//! as its own unit is one nothing can answer; the only thing that ever reads it
//! is a translation unit, and that unit's answer is where its names are. The
//! file the request names still decides which unit is read, which is the whole
//! of what it decides.
//!
//! Reporting a unit's other files under the requested file's name would be the
//! one thing that must not happen, and is why every anchor is spelled from the
//! file the compiler puts the entity in rather than from the file that was
//! asked about.
//!
//! # Nothing here runs anything
//!
//! The compilation database is read where it is, and the commands in it are
//! parsed rather than run. This helper offers no execution class at all, so a
//! run cannot permit it to configure a build — which is the only way a C++
//! project would produce a database it does not already have.

use std::collections::BTreeMap;
use std::path::Path;

use clang::{Clang, Entity, EntityKind, EntityVisitResult, Index, Type};
use codehelion_helper::ir::{
    Anchor, CallSite, CallTarget, CompilerIr, Instantiation, ResolvedSymbol, ResolvedType,
    SourceRange, SymbolKind, Unavailability, UnitRef, spell,
};

use crate::database::{Database, canonical};
use crate::types::category;

/// What came of being asked about one unit.
pub(crate) enum Outcome {
    /// It was read, and this is what the compiler knew.
    Analyzed(Box<CompilerIr>),
    /// It was not, and why.
    Unavailable(Unavailability),
}

/// Read `unit` and report what Clang knows about the file it names.
pub(crate) fn analyze(clang: &Clang, unit: &UnitRef, database: &Database) -> Outcome {
    let Some(entry) = database.unit(&unit.unit) else {
        // Nothing in the database is this unit. Analysing the file under some
        // other unit's command would answer about a program this one is not.
        return Outcome::Unavailable(Unavailability::NoBuildInformation);
    };
    let index = Index::new(clang, false, false);
    let Ok(parsed) = index
        .parser(&entry.file)
        .arguments(&entry.arguments)
        .detailed_preprocessing_record(true)
        .skip_function_bodies(false)
        .parse()
    else {
        // The recorded command did not yield a translation unit at all. A file
        // read with no command is a different program from the one the project
        // builds, so it is reported as having no build information rather than
        // analysed under whatever would parse.
        return Outcome::Unavailable(Unavailability::NoBuildInformation);
    };
    let file = canonical(Path::new(&unit.file));
    if parsed.get_file(&file).is_none() {
        // The unit was read and this file is no part of what it read, so the
        // pair the request named does not exist. Answering anyway would report
        // one unit's contents against a file that unit never opened.
        return Outcome::Unavailable(Unavailability::NoBuildInformation);
    }
    let mut reading = Reading::new(&database.root);
    reading.walk(parsed.get_entity());
    let mut ir = CompilerIr::empty(unit.clone());
    ir.anchored_at = Some(database.root.display().to_string());
    ir.symbols = reading.symbols;
    ir.calls = reading.calls;
    ir.instantiations = reading.instantiations;
    ir.types = reading.types.into_vec();
    Outcome::Analyzed(Box::new(ir))
}

/// What one pass over a translation unit has found so far.
struct Reading<'a> {
    /// What paths are spelled against.
    root: &'a Path,
    /// What is known about each file the unit has reached so far.
    ///
    /// Keyed by what the compiler calls a file rather than by how a path is
    /// written: a file reached through an include search path is reported with
    /// the spelling that search produced, which is a different string from the
    /// one a caller names it by and the same file. Resolved once per file
    /// rather than once per name — a unit holds thousands of names and tens of
    /// files.
    known: BTreeMap<(u64, u64, u64), Spelled>,
    /// Macro invocations paired with the definitions they expanded.
    macros: Vec<MacroStamp>,
    types: TypeTable,
    symbols: Vec<ResolvedSymbol>,
    calls: Vec<CallSite>,
    instantiations: Vec<Instantiation>,
}

/// One file the unit read, as this analysis reports it.
struct Spelled {
    /// How the project spells it, or its own path when it is not the
    /// project's.
    name: String,
    /// Whether it is one of the project's own.
    ///
    /// The project root decides it. A C++ build has no membership list to ask —
    /// there is no manifest saying which of the files a command reaches belong
    /// to the project — so where a file sits is what there is. It gets the cases
    /// that matter: the standard library and every installed dependency are
    /// outside the tree, and the project's own headers are in it, whichever
    /// include path reached them.
    inside: bool,
}

/// One macro invocation and the body it expanded.
struct MacroStamp {
    /// Clang's identity for the file containing the invocation.
    file: (u64, u64, u64),
    /// Invocation bytes, used to associate AST cursor locations with it.
    start: u64,
    end: u64,
    /// The two source ranges reported for every cursor produced by it.
    anchor: Anchor,
}

impl<'a> Reading<'a> {
    fn new(root: &'a Path) -> Self {
        Self {
            root,
            known: BTreeMap::new(),
            macros: Vec::new(),
            types: TypeTable::default(),
            symbols: Vec::new(),
            calls: Vec::new(),
            instantiations: Vec::new(),
        }
    }

    /// What is known about `file`, working it out the first time it is seen.
    fn known(&mut self, file: &clang::source::File<'_>) -> &Spelled {
        let root = self.root;
        self.known.entry(file.get_id()).or_insert_with(|| {
            let path = canonical(&file.get_path());
            Spelled {
                inside: path.starts_with(root),
                name: spell(Some(root), &path),
            }
        })
    }

    /// Visit every entity of the unit, keeping the ones written in the tree.
    ///
    /// The whole unit is walked because Clang's tree is the unit's: each file is
    /// a region of it, reached by including, and there is no subtree that is one
    /// file. What is dropped is what the unit read from outside the project —
    /// the standard library and every installed dependency, which nobody in the
    /// scan wrote and no fragment can be cut from.
    fn walk(&mut self, root: Entity<'_>) {
        // A preprocessing cursor carries the direct MacroExpansion →
        // MacroDefinition relation. Build that index before visiting AST
        // cursors: their spelling endpoints can come from different places
        // when a function-like macro mixes an argument with its body, so an
        // AST range cannot reconstruct this relation.
        root.visit_children(|entity, _| {
            if entity.get_kind() == EntityKind::MacroExpansion {
                self.remember_macro(entity);
            }
            EntityVisitResult::Recurse
        });
        root.visit_children(|entity, parent| {
            self.remember_instantiation(entity, parent);
            self.remember_call(entity);
            self.visit(entity);
            EntityVisitResult::Recurse
        });
        self.calls.sort_by(|left, right| {
            anchor_order(&left.anchor, &right.anchor)
                .then_with(|| call_target_order(&left.target, &right.target))
        });
        self.calls.dedup();
        self.instantiations.sort_by(|left, right| {
            (
                &left.anchor.expansion.file,
                left.anchor.expansion.start_byte,
                left.anchor.expansion.end_byte,
                &left.instantiation_key,
            )
                .cmp(&(
                    &right.anchor.expansion.file,
                    right.anchor.expansion.start_byte,
                    right.anchor.expansion.end_byte,
                    &right.instantiation_key,
                ))
        });
        self.instantiations.dedup_by(|left, right| {
            left.anchor.expansion == right.anchor.expansion
                && left.instantiation_key == right.instantiation_key
        });
    }

    /// Remember what one written call expression was found to invoke.
    ///
    /// `get_reference` is Clang's overload-resolution answer for a direct
    /// call. It can also return the variable holding a function pointer, which
    /// is not a callable identity, so only callable declarations with a USR
    /// become static targets. Virtual dispatch stays unresolved: libclang can
    /// walk overridden methods toward their bases, but cannot enumerate every
    /// derived implementation that may run, and an incomplete dynamic set
    /// would be more misleading than no set.
    fn remember_call(&mut self, entity: Entity<'_>) {
        if entity.get_kind() != EntityKind::CallExpr {
            return;
        }
        let Some(anchor) = self.anchor(entity) else {
            return;
        };
        let target = if entity.is_dynamic_call() {
            CallTarget::Unresolved
        } else {
            entity
                .get_reference()
                .map(|target| target.get_canonical_entity())
                .filter(|target| callable(target.get_kind()))
                .and_then(|target| target.get_usr())
                .map_or(CallTarget::Unresolved, |symbol| CallTarget::Static {
                    symbol: symbol.0,
                })
        };
        self.calls.push(CallSite { anchor, target });
    }

    /// Remember a concrete template specialization named at this cursor.
    ///
    /// A free-function use exposes its specialization directly from the
    /// `DeclRefExpr`. A class use exposes the template name as a `TemplateRef`,
    /// while the containing declaration carries the concrete type. Restricting
    /// the two cases to those cursor kinds gives one stamp per written use
    /// instead of also counting the enclosing call and implicit conversions.
    fn remember_instantiation(&mut self, entity: Entity<'_>, parent: Entity<'_>) {
        let (specialization, argument_type) = match entity.get_kind() {
            EntityKind::DeclRefExpr => {
                let Some(specialization) = entity.get_reference() else {
                    return;
                };
                (specialization, None)
            }
            EntityKind::TemplateRef => {
                let Some(ty) = parent.get_type().map(|ty| ty.get_canonical_type()) else {
                    return;
                };
                let Some(specialization) = ty.get_declaration() else {
                    return;
                };
                (specialization, Some(ty))
            }
            _ => return,
        };
        let Some(origin) = specialization.get_template() else {
            return;
        };
        let origin = origin.get_canonical_entity();
        if self.is_external(origin) || !same_definition_site(specialization, origin) {
            // A full explicit specialization owns the body at its own source
            // location. libclang still points it at the primary template, but
            // attributing that separate body to the primary would manufacture
            // repetition. Implicit specializations point at the selected
            // primary or partial-specialization location instead.
            return;
        }
        let (Some(definition), Some(specialization_usr)) =
            (origin.get_usr(), specialization.get_usr())
        else {
            // Source positions are not stable instantiation identities. If
            // Clang cannot name either side, omit the stamp rather than make a
            // key that moves whenever the file does.
            return;
        };
        let Some(origin_range) = self.definition_range(origin) else {
            return;
        };
        let Some(mut anchor) = self.anchor(entity) else {
            return;
        };
        anchor.definition = Some(origin_range);
        let arguments = argument_type.map_or_else(Vec::new, |ty| {
            ty.get_template_argument_types()
                .unwrap_or_default()
                .into_iter()
                .flatten()
                .map(|argument| self.types.intern(argument))
                .collect()
        });
        // The unversioned libclang surface exposed by clang 2.0/runtime can
        // enumerate class type arguments but not function template arguments:
        // Entity::get_template_arguments() requires the optional clang_3_6
        // feature. The concrete function USR still carries every substitution,
        // so it remains a stable, distinct key while `arguments` stays empty.
        self.instantiations.push(Instantiation {
            anchor,
            definition: definition.0,
            instantiation_key: format!("clang-usr-v1:{}", specialization_usr.0),
            arguments,
        });
    }

    /// Remember the definition the preprocessing record associates with one
    /// macro invocation.
    fn remember_macro(&mut self, expansion: Entity<'_>) {
        let Some(definition) = expansion
            .get_reference()
            .or_else(|| expansion.get_definition())
            .filter(|entity| entity.get_kind() == EntityKind::MacroDefinition)
        else {
            return;
        };
        let Some(invocation) = expansion.get_range() else {
            return;
        };
        let start = invocation.get_start().get_expansion_location();
        let end = invocation.get_end().get_expansion_location();
        let (Some(start_file), Some(end_file)) = (start.file, end.file) else {
            return;
        };
        if start_file.get_id() != end_file.get_id() || end.offset <= start.offset {
            return;
        }
        let Some(written) = self.definition_range(definition) else {
            return;
        };
        let file_name = self.known(&start_file).name.clone();
        self.macros.push(MacroStamp {
            file: start_file.get_id(),
            start: u64::from(start.offset),
            end: u64::from(end.offset),
            anchor: Anchor {
                expansion: SourceRange {
                    file: file_name,
                    start_byte: u64::from(start.offset),
                    end_byte: u64::from(end.offset),
                    start_line: start.line,
                },
                definition: Some(written),
            },
        });
    }

    /// The non-empty source range of a macro definition cursor.
    fn definition_range(&mut self, definition: Entity<'_>) -> Option<SourceRange> {
        let range = definition.get_range()?;
        let start = range.get_start().get_spelling_location();
        let end = range.get_end().get_spelling_location();
        let (start_file, end_file) = (start.file?, end.file?);
        if start_file.get_id() != end_file.get_id() || end.offset <= start.offset {
            return None;
        }
        Some(SourceRange {
            file: self.known(&start_file).name.clone(),
            start_byte: u64::from(start.offset),
            end_byte: u64::from(end.offset),
            start_line: start.line,
        })
    }

    fn visit(&mut self, entity: Entity<'_>) {
        let Some(anchor) = self.anchor(entity) else {
            return;
        };
        // A use names what it refers to; a declaration names itself. Both are
        // names written in this file, which is what the normalizer is deciding
        // about, and the referenced definition is what says whether the name is
        // this project's own vocabulary or one it shares.
        let named = entity.get_reference().unwrap_or(entity);
        let Some(kind) = symbol_kind(named.get_kind()) else {
            return;
        };
        let Some(name) = entity.get_name().or_else(|| named.get_name()) else {
            return;
        };
        let type_index = named.get_type().map(|ty| self.types.intern(ty));
        let external = self.is_external(named);
        self.symbols.push(ResolvedSymbol {
            id: identity(named),
            name,
            kind,
            anchor,
            type_index,
            external,
        });
    }

    /// Where `entity` sits, if it sits in a file of this project, and where it
    /// was written when a macro put it somewhere else.
    ///
    /// The expansion location is what a node anchors to: code produced by a
    /// macro physically occupies the place the macro was invoked, and that is
    /// the only place a fragment can be cut from.
    fn anchor(&mut self, entity: Entity<'_>) -> Option<Anchor> {
        let at = entity.get_location()?.get_expansion_location();
        let file = at.file?;
        if !self.known(&file).inside {
            return None;
        }
        let offset = u64::from(at.offset);
        if let Some(anchor) = self
            .macros
            .iter()
            .filter(|stamp| {
                stamp.file == file.get_id() && stamp.start <= offset && offset <= stamp.end
            })
            .min_by_key(|stamp| stamp.end - stamp.start)
            .map(|stamp| stamp.anchor.clone())
        {
            return Some(anchor);
        }

        let range = entity.get_range()?;
        let start = range.get_start().get_expansion_location();
        let end = range.get_end().get_expansion_location();
        let known = self.known(&start.file?);
        if !known.inside {
            return None;
        }
        let expansion = SourceRange {
            file: known.name.clone(),
            start_byte: u64::from(start.offset),
            end_byte: u64::from(end.offset.max(start.offset)),
            start_line: start.line,
        };
        Some(Anchor::written_here(expansion))
    }

    /// Whether the definition of `entity` is outside the code being scanned.
    ///
    /// Where the definition sits answers it, which is the same question
    /// [`Spelled::inside`] records and so the same answer.
    ///
    /// A definition with no location at all is a compiler builtin, which counts
    /// as outside for the same reason a primitive does: nobody in the scan
    /// wrote it, so a normalizer that renamed it would be comparing two
    /// fragments on a vocabulary neither of them chose.
    fn is_external(&mut self, entity: Entity<'_>) -> bool {
        let Some(location) = entity.get_location() else {
            return true;
        };
        if location.is_in_system_header() {
            return true;
        }
        let Some(file) = location.get_expansion_location().file else {
            return true;
        };
        !self.known(&file).inside
    }
}

/// Whether an implicit specialization still occupies its selected template's
/// source location.
///
/// A full explicit specialization has a body of its own and therefore a
/// different declaration location. Comparing Clang's file identities and byte
/// offsets avoids treating path spelling as identity.
fn same_definition_site(specialization: Entity<'_>, origin: Entity<'_>) -> bool {
    let Some(specialized) = specialization.get_location() else {
        return false;
    };
    let Some(original) = origin.get_location() else {
        return false;
    };
    let specialized = specialized.get_spelling_location();
    let original = original.get_spelling_location();
    let (Some(specialized_file), Some(original_file)) = (specialized.file, original.file) else {
        return false;
    };
    specialized_file.get_id() == original_file.get_id() && specialized.offset == original.offset
}

/// A stable order for call anchors, independent of AST traversal order.
fn anchor_order(left: &Anchor, right: &Anchor) -> std::cmp::Ordering {
    source_range_order(&left.expansion, &right.expansion).then_with(|| {
        match (&left.definition, &right.definition) {
            (Some(left), Some(right)) => source_range_order(left, right),
            (None, None) => std::cmp::Ordering::Equal,
            (None, Some(_)) => std::cmp::Ordering::Less,
            (Some(_), None) => std::cmp::Ordering::Greater,
        }
    })
}

fn source_range_order(left: &SourceRange, right: &SourceRange) -> std::cmp::Ordering {
    (
        left.file.as_str(),
        left.start_byte,
        left.end_byte,
        left.start_line,
    )
        .cmp(&(
            right.file.as_str(),
            right.start_byte,
            right.end_byte,
            right.start_line,
        ))
}

/// A stable order for the three call-target representations.
fn call_target_order(left: &CallTarget, right: &CallTarget) -> std::cmp::Ordering {
    match (left, right) {
        (CallTarget::Static { symbol: left }, CallTarget::Static { symbol: right }) => {
            left.cmp(right)
        }
        (CallTarget::Dynamic { candidates: left }, CallTarget::Dynamic { candidates: right }) => {
            left.cmp(right)
        }
        (CallTarget::Unresolved, CallTarget::Unresolved) => std::cmp::Ordering::Equal,
        (CallTarget::Static { .. }, _) | (CallTarget::Dynamic { .. }, CallTarget::Unresolved) => {
            std::cmp::Ordering::Less
        }
        (_, CallTarget::Static { .. }) | (CallTarget::Unresolved, CallTarget::Dynamic { .. }) => {
            std::cmp::Ordering::Greater
        }
    }
}

/// Whether an entity is itself something a call can name.
const fn callable(kind: EntityKind) -> bool {
    matches!(
        kind,
        EntityKind::FunctionDecl
            | EntityKind::Method
            | EntityKind::Constructor
            | EntityKind::Destructor
            | EntityKind::ConversionFunction
            | EntityKind::FunctionTemplate
    )
}

/// The identity of what a name resolved to.
///
/// A USR where Clang has one: it is the compiler's own answer to "are these the
/// same declaration", stable across translation units, and it already
/// distinguishes overloads that share a name. Locals and parameters have none —
/// they are not externally nameable — so they fall back to where they were
/// declared, because two neighbouring functions each declaring `total` are two
/// bindings and an identity they shared would say otherwise.
fn identity(entity: Entity<'_>) -> String {
    if let Some(usr) = entity.get_usr() {
        return usr.0;
    }
    let name = entity.get_name().unwrap_or_default();
    let Some(location) = entity.get_location() else {
        return name;
    };
    let at = location.get_expansion_location();
    at.file.map_or_else(
        || name.clone(),
        |file| format!("{name}@{}:{}", file.get_path().display(), at.offset),
    )
}

/// What kind of thing a declaration is, or nothing when it is not a name.
///
/// Everything a person could write down and mean something by is here; the
/// expressions and statements around them are not, because the normalizer is
/// deciding about identifiers and a `for` loop is not one.
const fn symbol_kind(kind: EntityKind) -> Option<SymbolKind> {
    Some(match kind {
        EntityKind::FunctionDecl
        | EntityKind::Method
        | EntityKind::Constructor
        | EntityKind::Destructor
        | EntityKind::ConversionFunction
        | EntityKind::FunctionTemplate => SymbolKind::Function,
        EntityKind::StructDecl
        | EntityKind::UnionDecl
        | EntityKind::ClassDecl
        | EntityKind::EnumDecl
        | EntityKind::TypedefDecl
        | EntityKind::TypeAliasDecl
        | EntityKind::TypeAliasTemplateDecl
        | EntityKind::ClassTemplate
        | EntityKind::ClassTemplatePartialSpecialization
        | EntityKind::TemplateTypeParameter => SymbolKind::Type,
        EntityKind::FieldDecl => SymbolKind::Field,
        EntityKind::EnumConstantDecl => SymbolKind::Variant,
        EntityKind::ParmDecl | EntityKind::VarDecl | EntityKind::NonTypeTemplateParameter => {
            SymbolKind::Binding
        }
        EntityKind::Namespace | EntityKind::NamespaceAlias => SymbolKind::Namespace,
        _ => return None,
    })
}

/// The types one analysis mentions, each recorded once.
///
/// # Why a type is recorded as the compiler resolved it
///
/// C and C++ let one type be written many ways. `Total`, `uint32_t` and
/// `unsigned int` can all name the same thing, and recording what was written
/// would file one type under three names — while recording the resolved form
/// files three spellings under one, which is what they are.
///
/// It also makes the answer say something the source text cannot. The same
/// header read by two translation units spells one type identically in both,
/// and a table of spellings would come back identical from two readings that
/// resolved it to different widths. What the compiler was asked for is what it
/// resolved; how it was written is in the file, where the syntactic side
/// already reads it.
#[derive(Default)]
struct TypeTable {
    /// Position of each type, keyed by the resolved form.
    at: BTreeMap<String, u32>,
    resolved: Vec<ResolvedType>,
}

impl TypeTable {
    /// The index of `ty`, recording it if this is the first mention.
    fn intern(&mut self, ty: Type<'_>) -> u32 {
        let canonical = ty.get_canonical_type();
        let display = canonical.get_display_name();
        if let Some(index) = self.at.get(&display) {
            return *index;
        }
        // Reserved before the arguments are interned: a template argument can
        // be the type being interned (`struct node { node* next; }`), and
        // recording the place first is what stops that from recursing.
        let index = u32::try_from(self.resolved.len()).unwrap_or(u32::MAX);
        self.at.insert(display.clone(), index);
        self.resolved.push(ResolvedType {
            display,
            category: category(ty),
            arguments: Vec::new(),
            definition: canonical.get_declaration().map(identity),
        });
        let arguments = self.arguments(canonical);
        if let Some(recorded) = self.resolved.get_mut(index as usize) {
            recorded.arguments = arguments;
        }
        index
    }

    /// The types `ty` is built from: what it points at, what it holds, what it
    /// was instantiated with.
    fn arguments(&mut self, ty: Type<'_>) -> Vec<u32> {
        if let Some(pointee) = ty.get_pointee_type() {
            return vec![self.intern(pointee)];
        }
        if let Some(element) = ty.get_element_type() {
            return vec![self.intern(element)];
        }
        ty.get_template_argument_types()
            .unwrap_or_default()
            .into_iter()
            .flatten()
            .map(|argument| self.intern(argument))
            .collect()
    }

    fn into_vec(self) -> Vec<ResolvedType> {
        self.resolved
    }
}
