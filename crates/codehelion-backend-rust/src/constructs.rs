//! Compiler-confirmed constructs used by restricted semantic normalization.
//!
//! This stays in the helper: the core receives only the closed construct
//! vocabulary and anchors, never rust-analyzer syntax values.

use std::path::Path;

use codehelion_helper::ir::{
    Anchor, CallSite, CallTarget, DirectPropagation, FallibleKind, SemanticConstruct,
    SemanticConstructKind,
};
use ra_ap_hir::{HasCrate, PathResolution, Semantics};
use ra_ap_ide_db::RootDatabase;
use ra_ap_syntax::ast::{ArithOp, BinaryOp, HasArgList, HasLoopBody, HasName};
use ra_ap_syntax::{AstNode, TextRange, ast};

use crate::analysis::{Loaded, file_of, source_range};

/// Collect Rust constructs within the closed restricted-semantic vocabulary.
///
/// `TRY_EXPR`, `MATCH_EXPR`, `IF_EXPR`, and `FOR_EXPR` are compiler-parsed
/// syntax. A fallible match or optional-presence condition must resolve to a
/// standard `Result` or `Option`; an arbitrary enum or method does not become
/// a validation operation merely because it has branches or shares a name. A
/// loop must satisfy [`collect_plain_vec_loop`] or [`collect_plain_reduce_loop`]
/// exactly.
pub(crate) fn collect(loaded: &Loaded, file: &Path) -> Vec<SemanticConstruct> {
    let Some(file_id) = file_of(loaded, file) else {
        return Vec::new();
    };
    let sema = Semantics::<RootDatabase>::new(&loaded.db);
    let Some(editioned) = sema.attach_first_edition_opt(file_id) else {
        return Vec::new();
    };
    let parse = sema.parse(editioned);
    let mut constructs = collect_fallible_and_loop_constructs(loaded, file_id, &sema, &parse);
    constructs.extend(collect_file_scope_lifetimes(loaded, file, file_id, &parse));
    constructs.sort_by_key(|construct| {
        (
            construct.anchor.expansion.start_byte,
            construct.anchor.expansion.end_byte,
            construct.kind.name(),
        )
    });
    constructs
}

/// Collect the closed constructs that do not describe resource lifetimes.
fn collect_fallible_and_loop_constructs(
    loaded: &Loaded,
    file_id: ra_ap_vfs::FileId,
    sema: &Semantics<'_, RootDatabase>,
    parse: &ra_ap_syntax::SourceFile,
) -> Vec<SemanticConstruct> {
    parse
        .syntax()
        .descendants()
        .filter_map(ast::TryExpr::cast)
        .filter_map(|tried| {
            standard_fallible_kind(sema, &loaded.db, &tried.expr()?).map(|fallible_kind| {
                SemanticConstruct {
                    anchor: Anchor::written_here(source_range(
                        loaded,
                        file_id,
                        tried.syntax().text_range(),
                    )),
                    kind: SemanticConstructKind::PropagateError,
                    fallible_kind: Some(fallible_kind),
                    direct_propagation: direct_try_adapter(sema, &loaded.db, &tried, fallible_kind),
                    resource_kind: None,
                }
            })
        })
        .chain(
            parse
                .syntax()
                .descendants()
                .filter_map(ast::MatchExpr::cast)
                .filter_map(|matched| {
                    standard_fallible_kind(sema, &loaded.db, &matched.expr()?).map(
                        |fallible_kind| {
                            let direct_propagation =
                                direct_match_adapter(sema, &loaded.db, &matched, fallible_kind);
                            SemanticConstruct {
                                anchor: Anchor::written_here(source_range(
                                    loaded,
                                    file_id,
                                    matched.syntax().text_range(),
                                )),
                                kind: if direct_propagation.is_some() {
                                    SemanticConstructKind::PropagateError
                                } else {
                                    SemanticConstructKind::Validate
                                },
                                fallible_kind: Some(fallible_kind),
                                direct_propagation,
                                resource_kind: None,
                            }
                        },
                    )
                }),
        )
        .chain(
            parse
                .syntax()
                .descendants()
                .filter_map(ast::IfExpr::cast)
                .filter_map(|conditional| {
                    direct_standard_fallible_presence_check(sema, &loaded.db, &conditional).map(
                        |fallible_kind| SemanticConstruct {
                            anchor: Anchor::written_here(source_range(
                                loaded,
                                file_id,
                                conditional.syntax().text_range(),
                            )),
                            kind: SemanticConstructKind::Validate,
                            fallible_kind: Some(fallible_kind),
                            direct_propagation: None,
                            resource_kind: None,
                        },
                    )
                }),
        )
        .chain(
            parse
                .syntax()
                .descendants()
                .filter_map(ast::ForExpr::cast)
                .flat_map(|loop_| {
                    collect_plain_vec_loop(sema, &loaded.db, loaded, file_id, &loop_)
                }),
        )
        .chain(
            parse
                .syntax()
                .descendants()
                .filter_map(ast::ForExpr::cast)
                .flat_map(|loop_| {
                    collect_plain_reduce_loop(sema, &loaded.db, loaded, file_id, &loop_)
                }),
        )
        .collect()
}

/// Record the smallest resource-lifetime form whose boundaries the helper can
/// establish without data-flow reconstruction: exactly one standard `File`
/// acquisition bound directly in a function body. The binding leaves scope at
/// that body's closing brace, so the paired release is a Rust `Drop` event,
/// not a guessed `close` call. Nested bindings, multiple files, custom types,
/// and values whose lifetime depends on control flow remain outside the closed
/// vocabulary until a dedicated data-flow normalizer can prove them.
fn collect_file_scope_lifetimes(
    loaded: &Loaded,
    file: &Path,
    file_id: ra_ap_vfs::FileId,
    parse: &ra_ap_syntax::SourceFile,
) -> Vec<SemanticConstruct> {
    let calls = crate::calls::collect(loaded, file);
    parse
        .syntax()
        .descendants()
        .filter_map(ast::Fn::cast)
        .filter_map(|function| {
            let body = function.body()?;
            let statements = body.stmt_list()?;
            let scope = body.syntax().text_range();
            let acquisitions: Vec<_> = statements
                .statements()
                .filter_map(|statement| match statement {
                    ast::Stmt::LetStmt(binding) => Some(binding),
                    _ => None,
                })
                .filter_map(|binding| binding.initializer())
                .filter_map(|initializer| {
                    let range = initializer.syntax().text_range();
                    calls.iter().find(|call| {
                        range_contains_call(range, call) && is_standard_file_open(call)
                    })
                })
                .collect();
            (acquisitions.len() == 1).then(|| {
                let acquire = acquisitions[0];
                let end = scope.end();
                [
                    SemanticConstruct {
                        anchor: acquire.anchor.clone(),
                        kind: SemanticConstructKind::AcquireResource,
                        fallible_kind: None,
                        direct_propagation: None,
                        resource_kind: Some("file".to_owned()),
                    },
                    SemanticConstruct {
                        anchor: Anchor::written_here(source_range(
                            loaded,
                            file_id,
                            TextRange::new(end, end),
                        )),
                        kind: SemanticConstructKind::ReleaseResource,
                        fallible_kind: None,
                        direct_propagation: None,
                        resource_kind: Some("file".to_owned()),
                    },
                ]
            })
        })
        .flatten()
        .collect()
}

fn range_contains_call(range: TextRange, call: &CallSite) -> bool {
    let start = u32::try_from(call.anchor.expansion.start_byte).ok();
    let end = u32::try_from(call.anchor.expansion.end_byte).ok();
    start.zip(end).is_some_and(|(start, end)| {
        range.start() <= ra_ap_syntax::TextSize::from(start)
            && ra_ap_syntax::TextSize::from(end) <= range.end()
    })
}

fn is_standard_file_open(call: &CallSite) -> bool {
    matches!(
        &call.target,
        CallTarget::Static { symbol }
            if symbol == "std::fs::File::open" || symbol == "std::fs::File::create"
    )
}

/// Recognize one direct standard fallible-presence branch as validation.
///
/// The receiver must resolve to the standard `Option` or `Result` ADT, and the
/// method call must have no arguments or surrounding operators. The former
/// makes the inherent method compiler-confirmed instead of accepting a project
/// method with the same name; the latter keeps compound conditions and
/// inversions outside this deliberately small vocabulary.
fn direct_standard_fallible_presence_check(
    sema: &Semantics<'_, RootDatabase>,
    db: &RootDatabase,
    conditional: &ast::IfExpr,
) -> Option<FallibleKind> {
    let Some(ast::Expr::MethodCallExpr(call)) = conditional.condition() else {
        return None;
    };
    if call
        .arg_list()
        .is_none_or(|arguments| arguments.args().next().is_some())
    {
        return None;
    }
    let receiver = call.receiver()?;
    let fallible_kind = standard_fallible_kind(sema, db, &receiver)?;
    let expected_name = match fallible_kind {
        FallibleKind::Option => "is_some",
        FallibleKind::Result => "is_ok",
    };
    (call
        .name_ref()
        .is_some_and(|name| name.text() == expected_name))
    .then_some(fallible_kind)
}

/// Recognize the deliberately small explicit-loop counterpart of a plain
/// `into_iter().collect()` pipeline.
///
/// The loop must consume a compiler-resolved standard sequence, have one body
/// statement, and put that exact binding into a compiler-resolved standard
/// `Vec::push`. Anything richer is left for a later, separately evidenced
/// normalizer: treating a transformed value, a guard, or an arbitrary `push`
/// method as a plain collection would be a false semantic claim.
fn collect_plain_vec_loop(
    sema: &Semantics<'_, RootDatabase>,
    db: &RootDatabase,
    loaded: &Loaded,
    file_id: ra_ap_vfs::FileId,
    loop_: &ast::ForExpr,
) -> Vec<SemanticConstruct> {
    let Some(iterable) = loop_.iterable() else {
        return Vec::new();
    };
    if !is_standard_sequence(sema, db, &iterable) {
        return Vec::new();
    }
    let Some(ast::Pat::IdentPat(binding)) = loop_.pat() else {
        return Vec::new();
    };
    let Some(name) = binding.name() else {
        return Vec::new();
    };
    let binding = name.text().to_string();
    let Some(body) = loop_.loop_body() else {
        return Vec::new();
    };
    let Some(statements) = body.stmt_list() else {
        return Vec::new();
    };
    let mut statements = statements.statements();
    let Some(ast::Stmt::ExprStmt(statement)) = statements.next() else {
        return Vec::new();
    };
    if statements.next().is_some() {
        return Vec::new();
    }
    let Some(ast::Expr::MethodCallExpr(push)) = statement.expr() else {
        return Vec::new();
    };
    if !is_plain_standard_vec_push(sema, db, &push, &binding) {
        return Vec::new();
    }
    let Some(push_name) = push.name_ref() else {
        return Vec::new();
    };
    vec![
        SemanticConstruct {
            anchor: Anchor::written_here(source_range(
                loaded,
                file_id,
                iterable.syntax().text_range(),
            )),
            kind: SemanticConstructKind::Source,
            fallible_kind: None,
            direct_propagation: None,
            resource_kind: None,
        },
        SemanticConstruct {
            anchor: Anchor::written_here(source_range(
                loaded,
                file_id,
                push_name.syntax().text_range(),
            )),
            kind: SemanticConstructKind::Collect,
            fallible_kind: None,
            direct_propagation: None,
            resource_kind: None,
        },
    ]
}

/// Recognize a direct arithmetic accumulation over a standard sequence.
///
/// This is intentionally smaller than generic loop equivalence: the body must
/// be one `+=` or `*=` statement, its right-hand side must be the loop binding
/// (or the one dereference needed for slice iteration), and the accumulator
/// must have a compiler-resolved numeric category. Conditions, conversions,
/// method calls, and rewritten arithmetic remain outside the vocabulary until
/// a data-flow-aware rule can explain them.
fn collect_plain_reduce_loop(
    sema: &Semantics<'_, RootDatabase>,
    db: &RootDatabase,
    loaded: &Loaded,
    file_id: ra_ap_vfs::FileId,
    loop_: &ast::ForExpr,
) -> Vec<SemanticConstruct> {
    let Some(iterable) = loop_.iterable() else {
        return Vec::new();
    };
    if !is_standard_sequence(sema, db, &iterable) {
        return Vec::new();
    }
    let Some(ast::Pat::IdentPat(binding)) = loop_.pat() else {
        return Vec::new();
    };
    let Some(name) = binding.name() else {
        return Vec::new();
    };
    let binding = name.text().to_string();
    let Some(body) = loop_.loop_body() else {
        return Vec::new();
    };
    let Some(statements) = body.stmt_list() else {
        return Vec::new();
    };
    let mut statements = statements.statements();
    let Some(ast::Stmt::ExprStmt(statement)) = statements.next() else {
        return Vec::new();
    };
    if statements.next().is_some() {
        return Vec::new();
    }
    let Some(ast::Expr::BinExpr(accumulation)) = statement.expr() else {
        return Vec::new();
    };
    if !matches!(
        accumulation.op_kind(),
        Some(BinaryOp::Assignment {
            op: Some(ArithOp::Add | ArithOp::Mul)
        })
    ) {
        return Vec::new();
    }
    let Some(accumulator) = accumulation.lhs() else {
        return Vec::new();
    };
    if !is_numeric_expression(sema, db, &accumulator) {
        return Vec::new();
    }
    let Some(value) = accumulation.rhs() else {
        return Vec::new();
    };
    if !is_direct_loop_binding(&value, &binding) {
        return Vec::new();
    }
    vec![
        SemanticConstruct {
            anchor: Anchor::written_here(source_range(
                loaded,
                file_id,
                iterable.syntax().text_range(),
            )),
            kind: SemanticConstructKind::Source,
            fallible_kind: None,
            direct_propagation: None,
            resource_kind: None,
        },
        SemanticConstruct {
            anchor: Anchor::written_here(source_range(
                loaded,
                file_id,
                accumulation.syntax().text_range(),
            )),
            kind: SemanticConstructKind::Reduce,
            fallible_kind: None,
            direct_propagation: None,
            resource_kind: None,
        },
    ]
}

fn is_numeric_expression(
    sema: &Semantics<'_, RootDatabase>,
    db: &RootDatabase,
    expression: &ast::Expr,
) -> bool {
    sema.type_of_expr(expression).is_some_and(|info| {
        matches!(
            crate::types::category(&info.original().strip_references(), db),
            codehelion_helper::ir::TypeCategory::Integer
                | codehelion_helper::ir::TypeCategory::Float
        )
    })
}

fn is_direct_loop_binding(expression: &ast::Expr, binding: &str) -> bool {
    matches!(compact_syntax(expression).as_str(), value if value == binding || value == format!("*{binding}"))
}

fn direct_try_adapter(
    sema: &Semantics<'_, RootDatabase>,
    db: &RootDatabase,
    tried: &ast::TryExpr,
    fallible_kind: FallibleKind,
) -> Option<DirectPropagation> {
    let call = tried.syntax().ancestors().find_map(ast::CallExpr::cast)?;
    let callee = call.expr()?;
    let (constructor, direct_propagation) = match fallible_kind {
        FallibleKind::Result => ("Ok", DirectPropagation::ResultAdapter),
        FallibleKind::Option => ("Some", DirectPropagation::OptionAdapter),
    };
    if compact_syntax(&callee) != constructor {
        return None;
    }
    is_standard_variant_constructor(sema, db, &call, constructor).then_some(direct_propagation)
}

/// Confirm that a constructor spelling resolves to the standard-library
/// variant rather than a project function with the same short name.
fn is_standard_variant_constructor(
    sema: &Semantics<'_, RootDatabase>,
    db: &RootDatabase,
    call: &ast::CallExpr,
    constructor: &str,
) -> bool {
    let Some(ast::Expr::PathExpr(path_expression)) = call.expr() else {
        return false;
    };
    let Some(path) = path_expression.path() else {
        return false;
    };
    let Some(PathResolution::Def(ra_ap_hir::ModuleDef::EnumVariant(variant))) =
        sema.resolve_path(&path)
    else {
        return false;
    };
    variant.name(db).as_str() == constructor
        && variant
            .module(db)
            .krate(db)
            .display_name(db)
            .is_some_and(|name| matches!(name.as_str(), "core" | "std" | "alloc"))
}

fn direct_match_adapter(
    sema: &Semantics<'_, RootDatabase>,
    db: &RootDatabase,
    matched: &ast::MatchExpr,
    fallible_kind: FallibleKind,
) -> Option<DirectPropagation> {
    match fallible_kind {
        FallibleKind::Result => is_direct_result_match_adapter(sema, db, matched)
            .then_some(DirectPropagation::ResultAdapter),
        FallibleKind::Option => is_direct_option_match_adapter(sema, db, matched)
            .then_some(DirectPropagation::OptionAdapter),
    }
}

fn is_direct_result_match_adapter(
    sema: &Semantics<'_, RootDatabase>,
    db: &RootDatabase,
    matched: &ast::MatchExpr,
) -> bool {
    if standard_fallible_kind(sema, db, &ast::Expr::MatchExpr(matched.clone()))
        != Some(FallibleKind::Result)
    {
        return false;
    }
    let Some(arms) = matched.match_arm_list() else {
        return false;
    };
    let mut found_ok = false;
    let mut found_err = false;
    for arm in arms.arms() {
        if arm.guard().is_some() {
            return false;
        }
        let (Some(pattern), Some(expression)) = (arm.pat(), arm.expr()) else {
            return false;
        };
        let pattern = compact_syntax(&pattern);
        let expression = compact_syntax(&expression);
        let (variant, binding) = direct_result_arm(&pattern, &expression);
        match variant {
            Some("Ok") if !found_ok => found_ok = true,
            Some("Err") if !found_err => found_err = true,
            _ => return false,
        }
        if !is_plain_identifier(binding) {
            return false;
        }
    }
    found_ok && found_err
}

fn direct_result_arm<'a>(pattern: &'a str, expression: &'a str) -> (Option<&'static str>, &'a str) {
    for variant in ["Ok", "Err"] {
        let Some(binding) = pattern
            .strip_prefix(variant)
            .and_then(|text| text.strip_prefix('('))
            .and_then(|text| text.strip_suffix(')'))
        else {
            continue;
        };
        if expression == format!("{variant}({binding})") {
            return (Some(variant), binding);
        }
    }
    (None, "")
}

fn is_direct_option_match_adapter(
    sema: &Semantics<'_, RootDatabase>,
    db: &RootDatabase,
    matched: &ast::MatchExpr,
) -> bool {
    if standard_fallible_kind(sema, db, &ast::Expr::MatchExpr(matched.clone()))
        != Some(FallibleKind::Option)
    {
        return false;
    }
    let Some(arms) = matched.match_arm_list() else {
        return false;
    };
    let mut found_some = false;
    let mut found_none = false;
    for arm in arms.arms() {
        if arm.guard().is_some() {
            return false;
        }
        let (Some(pattern), Some(expression)) = (arm.pat(), arm.expr()) else {
            return false;
        };
        let pattern = compact_syntax(&pattern);
        let expression = compact_syntax(&expression);
        if let Some(binding) = pattern
            .strip_prefix("Some(")
            .and_then(|text| text.strip_suffix(')'))
        {
            if found_some
                || expression != format!("Some({binding})")
                || !is_plain_identifier(binding)
            {
                return false;
            }
            found_some = true;
        } else if pattern == "None" && expression == "None" && !found_none {
            found_none = true;
        } else {
            return false;
        }
    }
    found_some && found_none
}

fn compact_syntax(node: &impl AstNode) -> String {
    node.syntax()
        .text()
        .to_string()
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

fn is_plain_identifier(text: &str) -> bool {
    let mut characters = text.chars();
    let Some(first) = characters.next() else {
        return false;
    };
    (first == '_' || first.is_alphabetic())
        && characters.all(|character| character == '_' || character.is_alphanumeric())
}

fn is_standard_sequence(
    sema: &Semantics<'_, RootDatabase>,
    db: &RootDatabase,
    expression: &ast::Expr,
) -> bool {
    sema.type_of_expr(expression).is_some_and(|info| {
        crate::types::category(&info.original().strip_references(), db)
            == codehelion_helper::ir::TypeCategory::Sequence
    })
}

fn is_plain_standard_vec_push(
    sema: &Semantics<'_, RootDatabase>,
    db: &RootDatabase,
    push: &ast::MethodCallExpr,
    binding: &str,
) -> bool {
    if push.name_ref().is_none_or(|name| name.text() != "push") {
        return false;
    }
    let Some(receiver) = push.receiver() else {
        return false;
    };
    let Some(adt) = sema
        .type_of_expr(&receiver)
        .map(|info| info.original().strip_references())
        .and_then(|ty| ty.as_adt())
    else {
        return false;
    };
    let Some(krate) = adt.krate(db).display_name(db) else {
        return false;
    };
    if !matches!(krate.to_string().as_str(), "std" | "alloc") || adt.name(db).as_str() != "Vec" {
        return false;
    }
    let written = push.syntax().text().to_string();
    let compact = written
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>();
    compact.ends_with(&format!(".push({binding})"))
}

fn standard_fallible_kind(
    sema: &Semantics<'_, RootDatabase>,
    db: &RootDatabase,
    expression: &ast::Expr,
) -> Option<FallibleKind> {
    let adt = sema
        .type_of_expr(expression)
        .map(|info| info.original().strip_references())
        .and_then(|ty| ty.as_adt())?;
    let krate = adt.krate(db).display_name(db)?;
    if !matches!(krate.to_string().as_str(), "std" | "core" | "alloc") {
        return None;
    }
    match adt.name(db).as_str() {
        "Result" => Some(FallibleKind::Result),
        "Option" => Some(FallibleKind::Option),
        _ => None,
    }
}
