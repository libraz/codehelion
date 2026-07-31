//! Every call written in one file, and what it reaches.
//!
//! # The receiver decides, not where the body was written
//!
//! The tempting rule is that a method found on a trait is dynamic and one
//! found on an inherent implementation is static. It is wrong in both
//! directions.
//!
//! A trait method with a default body that nothing overrides *is* the body
//! that runs, and a call to it through a concrete receiver reaches exactly
//! that one — calling it dynamic understates what the compiler settled.
//! Meanwhile enumerating the implementations of a widely-implemented trait
//! produces a candidate list with thousands of entries, which is not the
//! "same small set of implementations" a candidate list exists to record; it
//! is a list nothing can compare.
//!
//! So the question asked here is the one Rust actually answers: what is the
//! receiver? A concrete type pins one body, wherever that body was written. A
//! type parameter or a trait object does not, and the call is one of the
//! implementations.
//!
//! # What a candidate list holds
//!
//! Implementations the scan can see, plus the trait's own body when it has
//! one, because an implementation that overrides nothing reaches it. A trait
//! implemented only outside the scanned code yields nothing to compare, and
//! that is reported as unresolved rather than as an empty set of
//! possibilities — an empty list reads as "nothing can be called".

use std::path::Path;

use codehelion_helper::ir::{Anchor, CallSite, CallTarget};
use ra_ap_hir::{
    AsAssocItem, AssocItem, AssocItemContainer, Function, Impl, PathResolution, Semantics, Trait,
};
use ra_ap_ide_db::RootDatabase;
use ra_ap_syntax::{AstNode, SyntaxNode, ast};

use crate::analysis::{Loaded, file_of, path_of, source_range};

/// One entry per call written in `file`.
///
/// Parsed separately from the name pass rather than sharing its walk: the
/// parse itself is cached by the database, and one question per pass is worth
/// more than one traversal saved.
pub(crate) fn collect(loaded: &Loaded, file: &Path) -> Vec<CallSite> {
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
    for node in source.syntax().descendants() {
        if let Some(target) = target_for(&sema, db, &node) {
            found.push(CallSite {
                anchor: Anchor::written_here(source_range(
                    loaded,
                    file_id,
                    written_callee_range(&node),
                )),
                api_name: standard_api_name(&target),
                target,
            });
        }
    }
    found
}

/// The spelling that selects a call target, rather than the whole nested call.
///
/// A fluent call chain nests every outer call around the calls before it. Its
/// expression range therefore starts at the same source byte for `iter`,
/// `filter`, and `collect`; using that range would turn source order into an
/// incidental lexical sort in the SOG adapter. Method names and direct callee
/// expressions have their own ranges, so they retain the order a reader sees.
fn written_callee_range(node: &SyntaxNode) -> ra_ap_syntax::TextRange {
    ast::MethodCallExpr::cast(node.clone())
        .and_then(|call| call.name_ref().map(|name| name.syntax().text_range()))
        .or_else(|| {
            ast::CallExpr::cast(node.clone()).and_then(|call| {
                call.expr()
                    .map(|expression| expression.syntax().text_range())
            })
        })
        .unwrap_or_else(|| node.text_range())
}

/// Calls a declarative macro produced, all anchored at its invocation.
///
/// An expansion has no physical source range of its own. Reusing the
/// invocation's two-sided anchor says both what a fragment can point at and
/// where the generated expression was actually written, while still allowing
/// the compiler to resolve the call in the expanded syntax tree.
pub(crate) fn collect_expansion(
    sema: &Semantics<'_, RootDatabase>,
    db: &RootDatabase,
    syntax: &SyntaxNode,
    anchor: &Anchor,
) -> Vec<CallSite> {
    syntax
        .descendants()
        .filter_map(|node| {
            target_for(sema, db, &node).map(|target| CallSite {
                anchor: anchor.clone(),
                api_name: standard_api_name(&target),
                target,
            })
        })
        .collect()
}

/// The closed Rust standard-library vocabulary that semantic rules may use.
///
/// The stable call target remains the primary identity.  This supplemental
/// name exists only for calls whose resolved definition is in a language crate
/// and whose operation belongs to the small cross-language correspondence
/// table.  A workspace method merely named `map` or `push` therefore never
/// gains semantic API evidence.
fn standard_api_name(target: &CallTarget) -> Option<String> {
    let CallTarget::Static { symbol } = target else {
        return None;
    };
    let standard_library = ["core::", "alloc::", "std::"]
        .iter()
        .any(|prefix| symbol.starts_with(prefix));
    if !standard_library {
        return None;
    }
    let api_name = if standard_iterator_method(symbol, "filter") {
        "rust::Iterator::filter"
    } else if standard_iterator_method(symbol, "map") {
        "rust::Iterator::map"
    } else if standard_iterator_method(symbol, "fold") {
        "rust::Iterator::fold"
    } else if standard_iterator_method(symbol, "collect") {
        "rust::Iterator::collect"
    } else if symbol.ends_with("::IntoIterator::into_iter") {
        "rust::IntoIterator::into_iter"
    } else if symbol.ends_with("::slice::iter") || symbol.ends_with("::slice::_::iter") {
        "rust::slice::iter"
    } else if symbol.ends_with("::Vec::push") {
        "rust::Vec::push"
    } else {
        return None;
    };
    Some(api_name.to_string())
}

/// Whether a resolved standard symbol denotes one `Iterator` trait method.
///
/// rust-analyzer spells an implementation-selected call as either
/// `...::Iterator::method` or `...<Concrete as Iterator>::method`. Both name
/// the standard trait operation; the concrete receiver does not broaden the
/// closed vocabulary.
fn standard_iterator_method(symbol: &str, method: &str) -> bool {
    let Some(prefix) = symbol.strip_suffix(method) else {
        return false;
    };
    prefix.ends_with("::Iterator::")
        || prefix.ends_with("::Iterator>::")
        || prefix.ends_with(" as Iterator>::")
}

/// The target selected for one syntax node, when it is a call expression.
fn target_for(
    sema: &Semantics<'_, RootDatabase>,
    db: &RootDatabase,
    node: &SyntaxNode,
) -> Option<CallTarget> {
    ast::MethodCallExpr::cast(node.clone()).map_or_else(
        || ast::CallExpr::cast(node.clone()).map(|call| through_name(sema, db, &call)),
        |call| Some(through_method(sema, db, &call)),
    )
}

/// What `receiver.method(..)` reaches.
fn through_method(
    sema: &Semantics<'_, RootDatabase>,
    db: &RootDatabase,
    call: &ast::MethodCallExpr,
) -> CallTarget {
    let Some(function) = sema.resolve_method_call(call) else {
        return CallTarget::Unresolved;
    };
    let symbol = identity(function, db);
    if !is_dispatched(sema, db, call) {
        return CallTarget::Static { symbol };
    }
    let Some(trait_) = declaring_trait(function, db) else {
        return CallTarget::Static { symbol };
    };
    let mut candidates = implementations(db, trait_, function.name(db).as_str());
    // An implementation that overrides nothing reaches the trait's own body,
    // so it is one of the possibilities rather than the absence of them.
    if function.has_body(db) {
        candidates.push(symbol);
    }
    candidates.sort_unstable();
    candidates.dedup();
    if candidates.is_empty() {
        CallTarget::Unresolved
    } else {
        CallTarget::Dynamic { candidates }
    }
}

/// What `name(..)` reaches.
///
/// A callee that is a value rather than a name — a closure held in a variable,
/// a function pointer, a field — has no definition to point at, and saying so
/// is the answer.
fn through_name(
    sema: &Semantics<'_, RootDatabase>,
    db: &RootDatabase,
    call: &ast::CallExpr,
) -> CallTarget {
    let Some(ast::Expr::PathExpr(path_expr)) = call.expr() else {
        return CallTarget::Unresolved;
    };
    let Some(path) = path_expr.path() else {
        return CallTarget::Unresolved;
    };
    match sema.resolve_path(&path) {
        Some(PathResolution::Def(ra_ap_hir::ModuleDef::Function(function))) => CallTarget::Static {
            symbol: identity(function, db),
        },
        // A tuple struct or a tuple variant is called like a function and is
        // exactly one definition, so it is static in the sense that matters.
        Some(PathResolution::Def(ra_ap_hir::ModuleDef::Adt(adt))) => CallTarget::Static {
            symbol: path_of(adt.name(db).as_str(), adt.module(db), db),
        },
        Some(PathResolution::Def(ra_ap_hir::ModuleDef::EnumVariant(variant))) => {
            CallTarget::Static {
                symbol: path_of(variant.name(db).as_str(), variant.module(db), db),
            }
        }
        _ => CallTarget::Unresolved,
    }
}

/// Whether the receiver leaves the body undecided.
///
/// References are looked through, because `&Segment` and `Segment` pin the
/// same implementation. What does not pin one is a type parameter or a trait
/// object; a receiver whose type the compiler could not give is treated the
/// same way, since claiming a single target would be claiming more than was
/// established.
fn is_dispatched(
    sema: &Semantics<'_, RootDatabase>,
    db: &RootDatabase,
    call: &ast::MethodCallExpr,
) -> bool {
    let Some(receiver) = call.receiver() else {
        return true;
    };
    let Some(info) = sema.type_of_expr(&receiver) else {
        return true;
    };
    let receiver = info.original().strip_references();
    receiver.as_type_param(db).is_some()
        || receiver.as_dyn_trait().is_some()
        || receiver.as_impl_traits(db).is_some()
}

/// The trait a method belongs to, whether it was found on the trait itself or
/// on an implementation of it.
fn declaring_trait(function: Function, db: &RootDatabase) -> Option<Trait> {
    match function.as_assoc_item(db)?.container(db) {
        AssocItemContainer::Trait(trait_) => Some(trait_),
        AssocItemContainer::Impl(imp) => imp.trait_(db),
    }
}

/// Every implementation of `name` on `trait_` that the scanned code holds.
///
/// Bounded to workspace members deliberately. The set exists so that two calls
/// dispatching over the same implementations can be recognised as doing the
/// same thing, and a set that grows with the dependency tree cannot do that.
fn implementations(db: &RootDatabase, trait_: Trait, name: &str) -> Vec<String> {
    Impl::all_for_trait(db, trait_)
        .into_iter()
        .filter(|imp| imp.module(db).krate(db).origin(db).is_local())
        .flat_map(|imp| imp.items(db))
        .filter_map(|item| match item {
            AssocItem::Function(function) if function.name(db).as_str() == name => {
                Some(identity(function, db))
            }
            _ => None,
        })
        .collect()
}

/// How a function is named in the IR.
///
/// An associated function carries what it is associated with, spelled the way
/// Rust spells a qualified path. Its module alone would give every
/// implementation of one trait method the same name, and two implementations
/// that share a name are two things the IR cannot tell apart.
pub(crate) fn identity(function: Function, db: &RootDatabase) -> String {
    let name = function.name(db);
    let name = name.as_str();
    let module = function.module(db);
    match function.as_assoc_item(db).map(|item| item.container(db)) {
        Some(AssocItemContainer::Trait(trait_)) => {
            path_of(&format!("{}::{name}", trait_.name(db).as_str()), module, db)
        }
        Some(AssocItemContainer::Impl(imp)) => {
            let owner = imp
                .self_ty(db)
                .as_adt()
                .map_or_else(|| "_".to_string(), |adt| adt.name(db).as_str().to_string());
            let qualified = imp.trait_(db).map_or_else(
                || format!("{owner}::{name}"),
                |trait_| format!("<{owner} as {}>::{name}", trait_.name(db).as_str()),
            );
            path_of(&qualified, module, db)
        }
        None => path_of(name, module, db),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lowered_slice_iteration_keeps_its_closed_standard_api_name() {
        let target = CallTarget::Static {
            symbol: "core::slice::_::iter".to_owned(),
        };
        assert_eq!(
            standard_api_name(&target),
            Some("rust::slice::iter".to_owned())
        );
    }

    #[test]
    fn implementation_selected_iterator_fold_keeps_its_closed_standard_api_name() {
        let target = CallTarget::Static {
            symbol: "core::slice::iter::<Iter as Iterator>::fold".to_owned(),
        };
        assert_eq!(
            standard_api_name(&target),
            Some("rust::Iterator::fold".to_owned())
        );
    }
}
