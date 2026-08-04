use clang::{Entity, EntityKind, EntityVisitResult, Type};
use codehelion_helper::ir::{
    DirectPropagation, FallibleKind, SemanticConstruct, SemanticConstructKind,
};

use crate::types::category;

use super::Reading;

impl Reading<'_> {
    /// Record the deliberately small C++ counterpart of a plain Rust
    /// `for value in input { output.push(value) }` collection loop.
    ///
    /// A range-for loop is accepted only when its written range is one direct
    /// `std::vector` binding and its body is exactly one direct
    /// `std::vector::push_back(binding)` call.  The compiler resolves both
    /// vectors and the selected method; the token check only proves that the
    /// sole argument is the range binding rather than a transformed expression.
    pub(super) fn remember_plain_range_collection(&mut self, entity: Entity<'_>) {
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
    pub(super) fn remember_plain_range_reduce(&mut self, entity: Entity<'_>) {
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
    pub(super) fn remember_fallible_validation(&mut self, entity: Entity<'_>) {
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
    pub(super) fn remember_expected_identity_propagation(&mut self, entity: Entity<'_>) {
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
    pub(super) fn remember_direct_lock_lifetime(&mut self, entity: Entity<'_>) {
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
}

/// A deliberately small semantic API vocabulary named only after Clang has
/// resolved the target into the standard library.
pub(super) fn standard_api_name(entity: Entity<'_>) -> Option<String> {
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
            .map(written_tokens)
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

/// The tokens written across `range`, or none when there are none to read.
///
/// Every caller here reads a fixed shape out of the tokens of one construct,
/// so a range that is not a stretch of one file has nothing to say to them: it
/// reaches into no file at all, its two ends are in different files, or it
/// covers nothing. Tokenizing those would answer a question nobody asked, and
/// the empty answer they produce is the one libclang is least careful with.
fn written_tokens(range: clang::source::SourceRange<'_>) -> Vec<clang::token::Token<'_>> {
    let start = range.get_start().get_file_location();
    let end = range.get_end().get_file_location();
    let (Some(from), Some(to)) = (start.file, end.file) else {
        return Vec::new();
    };
    if from != to || end.offset <= start.offset {
        return Vec::new();
    }
    range.tokenize()
}

/// The direct source and element bindings written in one C++ range-for loop.
///
/// The cursor includes compiler-generated `__range`/`__begin` variables, so
/// user spelling is read from the loop tokens and the element binding is the
/// unique non-generated `VarDecl` in the loop's desugaring.
fn direct_range_bindings(loop_: Entity<'_>) -> Option<(String, String)> {
    let tokens = written_tokens(loop_.get_range()?);
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
    let tokens = written_tokens(range);
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
    let tokens = written_tokens(range);
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
