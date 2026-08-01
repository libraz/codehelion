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
use codehelion_helper::CompileCommandSelector;
use codehelion_helper::ir::{
    Anchor, CallSite, CallTarget, CompilerIr, DirectPropagation, FallibleKind, Instantiation,
    ResolvedSymbol, ResolvedType, SemanticConstruct, SemanticConstructKind, SourceRange,
    SymbolKind, Unavailability, UnitRef, spell,
};
use codehelion_helper::protocol::Capability;

use crate::cfg_dump;
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
pub(crate) fn analyze(
    clang: &Clang,
    unit: &UnitRef,
    database: &Database,
    selector: Option<&CompileCommandSelector>,
    want: &[Capability],
) -> Outcome {
    let Some(entry) = database.unit(&unit.unit, selector) else {
        // Nothing in the database is this unit. Analysing the file under some
        // other unit's command would answer about a program this one is not.
        return Outcome::Unavailable(Unavailability::NoBuildInformation);
    };
    let Ok(arguments) = entry.arguments() else {
        // Validation happens before constructing a libclang index. A command
        // with an unknown or executable option is not a partial reading: it is
        // a build variant this helper cannot safely answer about.
        return Outcome::Unavailable(Unavailability::NoBuildInformation);
    };
    let index = Index::new(clang, false, false);
    let Ok(parsed) = index
        .parser(&entry.file)
        .arguments(arguments.as_slice())
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
    let cfg = want
        .contains(&Capability::MirCfg)
        .then(|| cfg_dump::produce(&entry.file, arguments, &reading.functions))
        .flatten();
    let mut ir = CompilerIr::empty(unit.clone());
    ir.anchored_at = Some(database.root.display().to_string());
    ir.symbols = reading.symbols;
    ir.calls = reading.calls;
    ir.semantic_constructs = reading.semantic_constructs;
    ir.effects = codehelion_helper::effects::summarize(&ir.semantic_constructs);
    ir.instantiations = reading.instantiations;
    ir.types = reading.types.into_vec();
    ir.cfg = cfg;
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
    semantic_constructs: Vec<SemanticConstruct>,
    instantiations: Vec<Instantiation>,
    /// Function definitions whose compiler CFG dump can be anchored without
    /// guessing from a line number or AST node ID.
    functions: Vec<cfg_dump::FunctionAnchor>,
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
            semantic_constructs: Vec::new(),
            instantiations: Vec::new(),
            functions: Vec::new(),
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
            self.remember_function(entity);
            self.remember_instantiation(entity, parent);
            self.remember_call(entity);
            self.remember_plain_range_collection(entity);
            self.remember_plain_range_reduce(entity);
            self.remember_fallible_validation(entity);
            self.remember_expected_identity_propagation(entity);
            self.remember_direct_lock_lifetime(entity);
            self.visit(entity);
            EntityVisitResult::Recurse
        });
        self.calls.sort_by(|left, right| {
            anchor_order(&left.anchor, &right.anchor)
                .then_with(|| call_target_order(&left.target, &right.target))
        });
        self.calls.dedup();
        self.semantic_constructs.sort_by(|left, right| {
            (
                &left.anchor.expansion.file,
                left.anchor.expansion.start_byte,
                left.anchor.expansion.end_byte,
                left.kind.name(),
            )
                .cmp(&(
                    &right.anchor.expansion.file,
                    right.anchor.expansion.start_byte,
                    right.anchor.expansion.end_byte,
                    right.kind.name(),
                ))
        });
        self.semantic_constructs.dedup();
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
        self.functions.sort_by(|left, right| {
            (
                &left.name,
                &left.anchor.expansion.file,
                left.anchor.expansion.start_byte,
            )
                .cmp(&(
                    &right.name,
                    &right.anchor.expansion.file,
                    right.anchor.expansion.start_byte,
                ))
        });
        self.functions.dedup_by(|left, right| {
            left.name == right.name && left.anchor.expansion == right.anchor.expansion
        });
    }

    /// Keep a complete definition range only when the declaration has a body.
    /// A declaration with no compound body has no compiler CFG to associate
    /// with it, and declarations with the same name must remain distinct until
    /// the dump bridge rejects an ambiguity rather than merging them here.
    fn remember_function(&mut self, entity: Entity<'_>) {
        if !callable(entity.get_kind())
            || !entity
                .get_children()
                .iter()
                .any(|child| child.get_kind() == EntityKind::CompoundStmt)
        {
            return;
        }
        let (Some(name), Some(anchor)) = (entity.get_name(), self.anchor(entity)) else {
            return;
        };
        self.functions
            .push(cfg_dump::FunctionAnchor { name, anchor });
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
        let reference = (!entity.is_dynamic_call())
            .then(|| entity.get_reference())
            .flatten()
            .map(|target| target.get_canonical_entity())
            .filter(|target| callable(target.get_kind()));
        let api_name = reference
            .as_ref()
            .and_then(|target| standard_api_name(*target));
        let target = reference
            .and_then(|target| target.get_usr())
            .map_or(CallTarget::Unresolved, |symbol| CallTarget::Static {
                symbol: symbol.0,
            });
        self.calls.push(CallSite {
            anchor,
            target,
            api_name,
        });
    }

    /// Record the deliberately small C++ counterpart of a plain Rust
    /// `for value in input { output.push(value) }` collection loop.
    ///
    /// A range-for loop is accepted only when its written range is one direct
    /// `std::vector` binding and its body is exactly one direct
    /// `std::vector::push_back(binding)` call.  The compiler resolves both
    /// vectors and the selected method; the token check only proves that the
    /// sole argument is the range binding rather than a transformed expression.
    fn remember_plain_range_collection(&mut self, entity: Entity<'_>) {
        if entity.get_kind() != EntityKind::ForRangeStmt {
            return;
        }
        let Some((source, binding)) = direct_range_bindings(entity) else {
            return;
        };
        let Some(source_anchor) = direct_standard_vector_reference(entity, &source)
            .and_then(|source| self.anchor(source))
        else {
            return;
        };
        let Some(body) = entity
            .get_children()
            .into_iter()
            .find(|child| child.get_kind() == EntityKind::CompoundStmt)
        else {
            return;
        };
        let statements = body.get_children();
        let [call] = statements.as_slice() else {
            return;
        };
        if call.get_kind() != EntityKind::CallExpr
            || !call.get_reference().is_some_and(is_standard_vector_push)
            || !direct_call_argument_is(*call, &binding)
        {
            return;
        }
        let Some(collect_anchor) = self.anchor(*call) else {
            return;
        };
        self.semantic_constructs.extend([
            SemanticConstruct {
                anchor: source_anchor,
                kind: SemanticConstructKind::Source,
                fallible_kind: None,
                direct_propagation: None,
                resource_kind: None,
            },
            SemanticConstruct {
                anchor: collect_anchor,
                kind: SemanticConstructKind::Collect,
                fallible_kind: None,
                direct_propagation: None,
                resource_kind: None,
            },
        ]);
    }

    /// Record a direct numeric range-for accumulation as SOURCE/REDUCE.
    ///
    /// This is the exact C++ analogue of the Rust helper's closed loop rule:
    /// one standard vector binding, one statement, numeric accumulator, and
    /// the written loop binding as the untransformed right-hand side. It does
    /// not infer initialization, reduction identities, guards, or calls.
    fn remember_plain_range_reduce(&mut self, entity: Entity<'_>) {
        if entity.get_kind() != EntityKind::ForRangeStmt {
            return;
        }
        let Some((source, binding)) = direct_range_bindings(entity) else {
            return;
        };
        let Some(source_anchor) = direct_standard_vector_reference(entity, &source)
            .and_then(|source| self.anchor(source))
        else {
            return;
        };
        let Some(body) = entity
            .get_children()
            .into_iter()
            .find(|child| child.get_kind() == EntityKind::CompoundStmt)
        else {
            return;
        };
        let statements = body.get_children();
        let [accumulation] = statements.as_slice() else {
            return;
        };
        if accumulation.get_kind() != EntityKind::CompoundAssignOperator
            || !direct_numeric_accumulation(*accumulation, &binding)
        {
            return;
        }
        let Some(reduce_anchor) = self.anchor(*accumulation) else {
            return;
        };
        self.semantic_constructs.extend([
            SemanticConstruct {
                anchor: source_anchor,
                kind: SemanticConstructKind::Source,
                fallible_kind: None,
                direct_propagation: None,
                resource_kind: None,
            },
            SemanticConstruct {
                anchor: reduce_anchor,
                kind: SemanticConstructKind::Reduce,
                fallible_kind: None,
                direct_propagation: None,
                resource_kind: None,
            },
        ]);
    }

    /// Keep an `if` that directly asks a standard fallible value whether it
    /// holds a value as one closed validation operation.
    ///
    /// The callee's declaration, rather than a method spelling, decides this.
    /// A project type with a similar method or conversion is not an `optional`,
    /// and a compound condition adds semantics this compact vocabulary does not
    /// claim to understand.
    fn remember_fallible_validation(&mut self, entity: Entity<'_>) {
        if entity.get_kind() != EntityKind::IfStmt {
            return;
        }
        let children = entity.get_children();
        let Some(condition) = children.first().copied() else {
            return;
        };
        let fallible_kind = is_direct_standard_fallible_presence_check(condition)
            .or_else(|| direct_standard_fallible_early_return(&children, condition));
        let Some(fallible_kind) = fallible_kind else {
            return;
        };
        // The condition is the semantic operation. Anchoring the enclosing
        // `if` would miss a macro invocation inside it and report a spelling
        // range that does not identify the operation Clang resolved.
        let Some(anchor) = self.anchor(condition) else {
            return;
        };
        self.semantic_constructs.push(SemanticConstruct {
            anchor,
            kind: SemanticConstructKind::Validate,
            fallible_kind: Some(fallible_kind),
            direct_propagation: None,
            resource_kind: None,
        });
    }

    /// Keep the exact C++ `expected` identity adapter as closed error
    /// propagation evidence.
    ///
    /// The accepted form is intentionally narrower than an error-handling
    /// idiom: a project-written function must accept and return exactly the
    /// same standard `expected` type, have one parameter, and consist only of
    /// `return parameter;`. It forwards both the value and error alternative
    /// unchanged, which is the C++ counterpart of the registered Rust
    /// `Ok(value?)` adapter. Any inspection, conversion, construction, or
    /// additional statement is left outside this rule.
    fn remember_expected_identity_propagation(&mut self, entity: Entity<'_>) {
        if entity.get_kind() != EntityKind::FunctionDecl {
            return;
        }
        let Some(result_type) = entity.get_result_type() else {
            return;
        };
        if !is_standard_expected_type(result_type) {
            return;
        }
        let Some(arguments) = entity.get_arguments() else {
            return;
        };
        let [argument] = arguments.as_slice() else {
            return;
        };
        let Some(argument_type) = argument.get_type() else {
            return;
        };
        if !is_standard_expected_type(argument_type)
            || result_type.get_canonical_type().get_display_name()
                != argument_type.get_canonical_type().get_display_name()
        {
            return;
        }
        let Some(argument_name) = argument.get_name() else {
            return;
        };
        let Some(body) = entity
            .get_children()
            .into_iter()
            .find(|child| child.get_kind() == EntityKind::CompoundStmt)
        else {
            return;
        };
        let statements = body.get_children();
        let [returned] = statements.as_slice() else {
            return;
        };
        if returned.get_kind() != EntityKind::ReturnStmt
            || direct_returned_name(*returned).as_deref() != Some(argument_name.as_str())
        {
            return;
        }
        let Some(anchor) = self.anchor(*returned) else {
            return;
        };
        self.semantic_constructs.push(SemanticConstruct {
            anchor,
            kind: SemanticConstructKind::PropagateError,
            // The SOG category is intentionally language-neutral: standard
            // `expected<T, E>` and Rust `Result<T, E>` both carry one success
            // and one error alternative. The rule still requires the direct
            // adapter form, so this coarse correspondence cannot generalize
            // arbitrary expected-using functions into Result matches.
            fallible_kind: Some(FallibleKind::Result),
            direct_propagation: Some(DirectPropagation::ResultAdapter),
            resource_kind: None,
        });
    }

    /// Record the smallest C++ RAII lifetime Clang can establish without
    /// control-flow reconstruction: one direct standard `lock_guard` or
    /// `unique_lock` binding
    /// in a function body and that body's closing scope. Nested scopes,
    /// multiple guards and project-defined lookalikes remain outside the
    /// restricted vocabulary.
    fn remember_direct_lock_lifetime(&mut self, entity: Entity<'_>) {
        if entity.get_kind() != EntityKind::FunctionDecl {
            return;
        }
        let Some(body) = entity
            .get_children()
            .into_iter()
            .find(|child| child.get_kind() == EntityKind::CompoundStmt)
        else {
            return;
        };
        let acquisitions: Vec<_> = body
            .get_children()
            .into_iter()
            .filter(|statement| statement.get_kind() == EntityKind::DeclStmt)
            .flat_map(|statement| statement.get_children())
            .filter(|declaration| declaration.get_kind() == EntityKind::VarDecl)
            .filter(|declaration| declaration.get_type().is_some_and(is_standard_lock_type))
            .filter_map(|declaration| self.anchor(declaration))
            .collect();
        let [acquire] = acquisitions.as_slice() else {
            return;
        };
        let Some(release) = self.scope_end_anchor(body) else {
            return;
        };
        self.semantic_constructs.extend([
            SemanticConstruct {
                anchor: acquire.clone(),
                kind: SemanticConstructKind::AcquireResource,
                fallible_kind: None,
                direct_propagation: None,
                resource_kind: Some("lock".to_owned()),
            },
            SemanticConstruct {
                anchor: release,
                kind: SemanticConstructKind::ReleaseResource,
                fallible_kind: None,
                direct_propagation: None,
                resource_kind: Some("lock".to_owned()),
            },
        ]);
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
        // The source definition and USR retain their existing roles. The
        // optional artifact key is separately shaped for the correlator: a demangled C++
        // function or a class-template member spells its specialization through
        // a qualified display name, not through Clang's USR grammar. Keeping
        // the two facts distinct avoids pretending those independent spellings
        // are interchangeable stable identities.
        self.instantiations.push(Instantiation {
            anchor,
            definition: definition.0,
            definition_end_line: definition_end_line(origin),
            artifact_match_key: specialization_display_key(specialization),
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

    /// Anchor the endpoint of a direct lexical scope as its `Drop` boundary.
    fn scope_end_anchor(&mut self, scope: Entity<'_>) -> Option<Anchor> {
        let range = scope.get_range()?;
        let end = range.get_end().get_expansion_location();
        let file = end.file?;
        let known = self.known(&file);
        if !known.inside {
            return None;
        }
        Some(Anchor::written_here(SourceRange {
            file: known.name.clone(),
            start_byte: u64::from(end.offset),
            end_byte: u64::from(end.offset),
            start_line: end.line,
        }))
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

/// The final line of a definition range, when Clang keeps it in one file.
fn definition_end_line(definition: Entity<'_>) -> Option<u32> {
    let range = definition.get_range()?;
    let start = range.get_start().get_expansion_location();
    let end = range.get_end().get_expansion_location();
    (start.file?.get_id() == end.file?.get_id()).then_some(end.line)
}

/// A qualified display spelling for a compiler-resolved template specialization.
///
/// This is comparison evidence only. The stable specialization key remains the
/// USR in [`Instantiation::instantiation_key`]; the artifact side can use this
/// display form solely after it has independently demangled a function name.
fn specialization_display_key(specialization: Entity<'_>) -> Option<String> {
    let display = specialization.get_display_name()?;
    let mut parents = Vec::new();
    let mut parent = specialization.get_semantic_parent();
    while let Some(current) = parent {
        if matches!(
            current.get_kind(),
            EntityKind::Namespace | EntityKind::StructDecl | EntityKind::ClassDecl
        ) && let Some(name) = current.get_name()
            && !name.is_empty()
        {
            parents.push(name);
        }
        parent = current.get_semantic_parent();
    }
    parents.reverse();
    parents.push(display);
    Some(format!("clang-display-v1:{}", parents.join("::")))
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
/// A deliberately small semantic API vocabulary named only after Clang has
/// resolved the target into the standard library.
fn standard_api_name(entity: Entity<'_>) -> Option<String> {
    if !crate::types::in_standard_namespace(entity) {
        return None;
    }
    let name = entity.get_name()?;
    matches!(
        name.as_str(),
        "begin"
            | "filter"
            | "copy_if"
            | "map"
            | "transform"
            | "fold"
            | "accumulate"
            | "collect"
            | "push_back"
            | "to_string"
            | "stoull"
    )
    .then(|| format!("std::{name}"))
}

/// Return the family of a resolved standard fallible presence check.
///
/// Both `has_value()` and the explicit `operator bool` conversion carry the
/// same presence fact. The declaration must still belong to the standard
/// optional or expected family, so a project conversion operator cannot enter the closed
/// semantic vocabulary by sharing either spelling.
fn standard_fallible_presence_method(method: Entity<'_>) -> Option<FallibleKind> {
    method
        .get_name()
        .filter(|name| matches!(name.as_str(), "has_value" | "operator bool"))?;
    method.get_semantic_parent().and_then(|parent| {
        // libc++ exposes this inherited method on `__optional_storage_base`,
        // whereas other standard libraries can expose it on `optional`
        // itself. In both cases the declaration is inside `std` and its
        // compiler-owned type name identifies it as the optional family.
        crate::types::in_standard_namespace(parent).then_some(())?;
        let name = parent.get_name()?.to_ascii_lowercase();
        if name.contains("optional") {
            Some(FallibleKind::Option)
        } else if name.contains("expected") {
            Some(FallibleKind::Result)
        } else {
            None
        }
    })
}

/// Return the family when the condition is exactly one resolved standard
/// optional/expected presence call.
fn is_direct_standard_fallible_presence_check(condition: Entity<'_>) -> Option<FallibleKind> {
    let mut current = condition;
    let call = loop {
        match current.get_kind() {
            EntityKind::CallExpr => break Some(current),
            // A macro that contributes only parentheses around a direct
            // standard call appears as one or more of these wrappers. They
            // carry no operation of their own, unlike a unary or binary
            // expression, so following exactly one child preserves the same
            // closed condition accepted for source-written code.
            EntityKind::UnexposedExpr | EntityKind::ParenExpr => {
                let mut children = current.get_children().into_iter();
                let Some(child) = children.next() else {
                    break None;
                };
                if children.next().is_some() {
                    break None;
                }
                current = child;
            }
            _ => break None,
        }
    };
    call.and_then(|call| call.get_reference())
        .map(|reference| reference.get_canonical_entity())
        .and_then(standard_fallible_presence_method)
}

/// Return the family for an exact C++ early return guard.
///
/// Only `if (!value.has_value()) return;` and its single-statement braced
/// spelling enter the vocabulary. The `!` expression must contain exactly one
/// direct standard presence check, the then branch must contain exactly a bare
/// return, and the `if` must have no else branch. This keeps the accepted form
/// equivalent to the Rust unit-return guard without inferring the meaning of
/// arbitrary control flow.
fn direct_standard_fallible_early_return(
    if_children: &[Entity<'_>],
    condition: Entity<'_>,
) -> Option<FallibleKind> {
    let [_, then_branch] = if_children else {
        return None;
    };
    if condition.get_kind() != EntityKind::UnaryOperator
        || condition
            .get_range()
            .map(|range| range.tokenize())
            .is_none_or(|tokens| {
                tokens
                    .first()
                    .is_none_or(|token| token.get_spelling() != "!")
            })
    {
        return None;
    }
    let mut condition_children = condition.get_children().into_iter();
    let operand = condition_children.next()?;
    if condition_children.next().is_some() || !then_branch_is_unit_return(*then_branch) {
        return None;
    }
    is_direct_standard_fallible_presence_check(operand)
}

/// Whether a C++ branch is precisely one bare `return;` statement.
fn then_branch_is_unit_return(branch: Entity<'_>) -> bool {
    let returned = match branch.get_kind() {
        EntityKind::ReturnStmt => branch,
        EntityKind::CompoundStmt => {
            let statements = branch.get_children();
            let [returned] = statements.as_slice() else {
                return false;
            };
            *returned
        }
        _ => return false,
    };
    returned.get_kind() == EntityKind::ReturnStmt && returned.get_children().is_empty()
}

/// Whether `ty` resolves to the standard `expected` family.
fn is_standard_expected_type(ty: Type<'_>) -> bool {
    ty.get_canonical_type()
        .get_declaration()
        .is_some_and(|declaration| {
            crate::types::in_standard_namespace(declaration)
                && declaration.get_name().as_deref() == Some("expected")
        })
}

/// Whether `ty` is one of the standard lexical RAII lock types this helper
/// supports.
fn is_standard_lock_type(ty: Type<'_>) -> bool {
    ty.get_canonical_type()
        .get_declaration()
        .is_some_and(|declaration| {
            crate::types::in_standard_namespace(declaration)
                && matches!(
                    declaration.get_name().as_deref(),
                    Some("lock_guard" | "unique_lock")
                )
        })
}

/// Return the sole declaration-reference name under an identity return.
///
/// A copied `expected` value normally has compiler-inserted construct and cast
/// cursors between the return statement and the written reference. Following
/// only single-child wrappers admits that representation while rejecting calls,
/// operators, and any expression with additional semantic operands.
fn direct_returned_name(returned: Entity<'_>) -> Option<String> {
    let mut current = returned.get_children().into_iter().next()?;
    loop {
        if current.get_kind() == EntityKind::DeclRefExpr {
            return current.get_name();
        }
        let mut children = current.get_children().into_iter();
        current = children.next()?;
        if children.next().is_some() {
            return None;
        }
    }
}

/// The direct source and element bindings written in one C++ range-for loop.
///
/// The cursor includes compiler-generated `__range`/`__begin` variables, so
/// user spelling is read from the loop tokens and the element binding is the
/// unique non-generated `VarDecl` in the loop's desugaring.
fn direct_range_bindings(loop_: Entity<'_>) -> Option<(String, String)> {
    let tokens = loop_.get_range()?.tokenize();
    let tokens: Vec<_> = tokens
        .iter()
        .map(clang::token::Token::get_spelling)
        .collect();
    let colon = tokens.iter().position(|token| token == ":")?;
    let source = tokens.get(colon.checked_add(1)?)?.clone();
    if !is_plain_identifier(&source) || tokens.get(colon.checked_add(2)?) != Some(&")".to_owned()) {
        return None;
    }
    let bindings: Vec<_> = loop_
        .get_children()
        .into_iter()
        .filter(|child| child.get_kind() == EntityKind::VarDecl)
        .filter_map(|child| child.get_name())
        .filter(|name| !name.starts_with("__"))
        .collect();
    let [binding] = bindings.as_slice() else {
        return None;
    };
    (binding != &source).then(|| (source, binding.clone()))
}

/// Find the written range expression only if Clang resolved it as a standard
/// `std::vector` binding.  Range customization points and project containers
/// deliberately remain outside the first closed loop vocabulary.
fn direct_standard_vector_reference<'clang>(
    loop_: Entity<'clang>,
    source: &str,
) -> Option<Entity<'clang>> {
    let mut references = Vec::new();
    loop_.visit_children(|entity, _| {
        if entity.get_kind() == EntityKind::DeclRefExpr
            && entity.get_name().as_deref() == Some(source)
            && entity.get_type().is_some_and(is_standard_vector_type)
        {
            references.push(entity);
        }
        EntityVisitResult::Recurse
    });
    (references.len() == 1).then(|| references[0])
}

/// Whether a resolved expression has exactly the standard vector family.
fn is_standard_vector_type(ty: Type<'_>) -> bool {
    ty.get_canonical_type()
        .get_declaration()
        .is_some_and(|declaration| {
            crate::types::in_standard_namespace(declaration)
                && declaration.get_name().as_deref() == Some("vector")
        })
}

/// Whether a resolved call selected `std::vector::push_back`.
fn is_standard_vector_push(method: Entity<'_>) -> bool {
    method.get_name().as_deref() == Some("push_back")
        && method.get_semantic_parent().is_some_and(|parent| {
            crate::types::in_standard_namespace(parent)
                && parent.get_name().as_deref() == Some("vector")
        })
}

/// Whether a call's only written argument is the loop element unchanged.
fn direct_call_argument_is(call: Entity<'_>, binding: &str) -> bool {
    let Some(range) = call.get_range() else {
        return false;
    };
    let tokens = range.tokenize();
    let tokens: Vec<_> = tokens
        .iter()
        .map(clang::token::Token::get_spelling)
        .collect();
    let Some(opening) = tokens.iter().rposition(|token| token == "(") else {
        return false;
    };
    let Some(argument) = opening.checked_add(1) else {
        return false;
    };
    let Some(closing) = opening.checked_add(2) else {
        return false;
    };
    let Some(after) = opening.checked_add(3) else {
        return false;
    };
    tokens.get(argument).is_some_and(|token| token == binding)
        && tokens.get(closing).is_some_and(|token| token == ")")
        && tokens.get(after).is_none()
}

/// Whether a statement is exactly `numeric_binding += loop_binding` or `*=`.
fn direct_numeric_accumulation(statement: Entity<'_>, binding: &str) -> bool {
    let Some(range) = statement.get_range() else {
        return false;
    };
    let tokens = range.tokenize();
    let tokens: Vec<_> = tokens
        .iter()
        .map(clang::token::Token::get_spelling)
        .collect();
    let [accumulator, operator, value] = tokens.as_slice() else {
        return false;
    };
    if !is_plain_identifier(accumulator)
        || accumulator == binding
        || !matches!(operator.as_str(), "+=" | "*=")
        || value != binding
    {
        return false;
    }
    let mut references = Vec::new();
    statement.visit_children(|entity, _| {
        if entity.get_kind() == EntityKind::DeclRefExpr
            && entity.get_name().as_deref() == Some(accumulator)
            && entity.get_type().is_some_and(is_numeric_type)
        {
            references.push(entity);
        }
        EntityVisitResult::Recurse
    });
    references.len() == 1
}

/// Whether Clang resolved an expression as a number that a direct reduction
/// can accumulate without inventing conversion semantics.
fn is_numeric_type(ty: Type<'_>) -> bool {
    matches!(
        category(ty),
        codehelion_helper::ir::TypeCategory::Integer | codehelion_helper::ir::TypeCategory::Float
    )
}

/// A conservative source identifier, never a member expression, call, or
/// qualified name that would need a broader normalizer to interpret.
fn is_plain_identifier(name: &str) -> bool {
    let mut characters = name.chars();
    characters
        .next()
        .is_some_and(|character| character == '_' || character.is_ascii_alphabetic())
        && characters.all(|character| character == '_' || character.is_ascii_alphanumeric())
}

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
