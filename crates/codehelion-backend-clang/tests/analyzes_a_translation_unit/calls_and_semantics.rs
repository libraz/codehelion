use super::*;

fn overload_ir(planted: &Planted) -> Box<CompilerIr> {
    analyzed(&planted.unit("src/calls.cpp", "src/calls.cpp"))
}

fn call_at<'a>(ir: &'a CompilerIr, file: &str, start: usize) -> &'a CallSite {
    ir.calls
        .iter()
        .find(|call| {
            call.anchor.expansion.file == file
                && call.anchor.expansion.start_byte == u64::try_from(start).unwrap()
        })
        .unwrap_or_else(|| panic!("no call at {file}:{start}: {:?}", ir.calls))
}

fn static_symbol(call: &CallSite) -> &str {
    match &call.target {
        CallTarget::Static { symbol } => symbol,
        target => panic!("expected a static target, got {target:?}"),
    }
}

/// The referenced callable USR is Clang's overload-resolution answer. The two
/// free overloads and two member overloads therefore remain distinct, while a
/// direct non-overloaded call and a declaration outside the tree are resolved
/// by exactly the same rule.
#[test]
fn direct_calls_keep_the_selected_callable_usr() {
    let planted = plant("overload-resolution");
    let source = template_source(&planted, "src/calls.cpp");
    let ir = overload_ir(&planted);
    let call = |text: &str| call_at(&ir, "src/calls.cpp", source.find(text).unwrap());

    let free_integer = static_symbol(call("choose(1)"));
    let free_long = static_symbol(call("choose(1L)"));
    assert_ne!(free_integer, free_long);

    let member_integer = static_symbol(call("mixer.mix(2)"));
    let member_long = static_symbol(call("mixer.mix(2L)"));
    assert_ne!(member_integer, member_long);
    assert_ne!(free_integer, member_integer);

    let direct = static_symbol(call("direct(9)"));
    let declared = ir
        .symbols
        .iter()
        .find(|symbol| {
            symbol.name == "direct"
                && symbol.kind == codehelion_helper::ir::SymbolKind::Function
                && !symbol.external
        })
        .expect("the direct function declaration is resolved");
    assert_eq!(direct, declared.id);

    let external = static_symbol(call("std::puts"));
    assert!(
        !external.is_empty(),
        "an external declaration still has a USR"
    );
    assert_ne!(external, direct);
}

/// A standard-library API label is supplementary evidence: the USR remains
/// the static call identity, while a closed semantic normalizer can use the
/// label without parsing a platform-specific USR spelling.
#[test]
fn standard_library_calls_carry_closed_api_names() {
    let planted = plant("overload-resolution");
    let ir = overload_ir(&planted);
    let begin = ir
        .calls
        .iter()
        .find(|call| call.api_name.as_deref() == Some("std::begin"))
        .expect("standard begin call");
    let push = ir
        .calls
        .iter()
        .find(|call| call.api_name.as_deref() == Some("std::push_back"))
        .expect("standard push_back call");
    assert_eq!(begin.api_name.as_deref(), Some("std::begin"));
    assert_eq!(push.api_name.as_deref(), Some("std::push_back"));
    assert!(matches!(begin.target, CallTarget::Static { .. }));
    assert!(matches!(push.target, CallTarget::Static { .. }));
}

/// An `optional` check enters the restricted vocabulary only after Clang has
/// resolved the selected method or conversion to the standard-library
/// declaration. A local lookalike is ordinary control flow, not evidence of
/// optional validation.
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one fixture keeps the accepted standard forms and rejected lookalikes under the same compiler invocation"
)]
fn standard_optional_presence_checks_are_validation_constructs() {
    let planted = plant("overload-resolution");
    let path = planted.root.join("src/calls.cpp");
    let source = std::fs::read_to_string(&path).expect("read C++ fixture");
    let source = format!(
        "#include <optional>\n{EXPECTED_AVAILABILITY}\
         #define HAS_OPTION_VALUE(value) ((value).has_value())\n\
         {source}\n\
         namespace optional_checks {{\n\
         struct Lookalike {{ bool has_value() const {{ return true; }} }};\n\
         struct ConversionLookalike {{ explicit operator bool() const {{ return true; }} }};\n\
         bool standard(std::optional<long> value) {{\n\
           if (value.has_value()) {{ return true; }}\n\
           return false;\n\
         }}\n\
         bool direct_conversion(std::optional<long> value) {{\n\
           if (value) {{ return true; }}\n\
           return false;\n\
         }}\n\
         bool macro_standard(std::optional<long> value) {{\n\
           if (HAS_OPTION_VALUE(value)) {{ return true; }}\n\
           return false;\n\
         }}\n\
         bool lookalike(Lookalike value) {{\n\
           if (value.has_value()) {{ return true; }}\n\
           return false;\n\
         }}\n\
         bool conversion_lookalike(ConversionLookalike value) {{\n\
           if (value) {{ return true; }}\n\
           return false;\n\
         }}\n\
         bool compound(std::optional<long> value, bool keep) {{\n\
           if (value.has_value() && keep) {{ return true; }}\n\
           return false;\n\
         }}\n\
         void early_return(std::optional<long> value) {{\n\
           if (!value.has_value()) return;\n\
           (void)value;\n\
         }}\n\
         void braced_early_return(std::optional<long> value) {{\n\
           if (!value.has_value()) {{ return; }}\n\
           (void)value;\n\
         }}\n\
         bool value_return(std::optional<long> value) {{\n\
           if (!value.has_value()) return false;\n\
           return true;\n\
         }}\n\
         void else_branch(std::optional<long> value) {{\n\
           if (!value.has_value()) return;\n\
           else (void)value;\n\
         }}\n\
         #ifdef CODEHELION_EXPECTED\n\
         bool expected_standard(std::expected<long, int> expected_value) {{\n\
           if (expected_value.has_value()) {{ return true; }}\n\
           return false;\n\
         }}\n\
         bool expected_direct_conversion(std::expected<long, int> expected_value) {{\n\
           if (expected_value) {{ return true; }}\n\
           return false;\n\
         }}\n\
         bool expected_compound(std::expected<long, int> expected_value, bool keep) {{\n\
           if (expected_value.has_value() && keep) {{ return true; }}\n\
           return false;\n\
         }}\n\
         #endif\n\
         }}  // namespace optional_checks\n"
    );
    std::fs::write(&path, &source).expect("extend C++ fixture");
    let database_path = planted.root.join("compile_commands.json");
    let database = std::fs::read_to_string(&database_path).expect("read compilation database");
    std::fs::write(&database_path, database.replace("-std=c++17", "-std=c++23"))
        .expect("enable C++23 expected fixture");

    let ir = overload_ir(&planted);
    // The two `expected` checks the fixture accepts, where the type was there
    // to compile. The `optional` half stands on its own either way.
    let expected_validations = usize::from(standard_expected_available(&ir)) * 2;
    let validates = ir
        .semantic_constructs
        .iter()
        .filter(|construct| construct.kind == SemanticConstructKind::Validate)
        .collect::<Vec<_>>();
    assert_eq!(
        validates.len(),
        5 + expected_validations,
        "{:?}",
        ir.semantic_constructs
    );
    assert_eq!(
        validates
            .iter()
            .filter(|construct| construct.fallible_kind == Some(FallibleKind::Option))
            .count(),
        5
    );
    assert_eq!(
        validates
            .iter()
            .filter(|construct| construct.fallible_kind == Some(FallibleKind::Result))
            .count(),
        expected_validations
    );
    let invocation = u64::try_from(
        source
            .rfind("HAS_OPTION_VALUE(value)")
            .expect("macro invocation"),
    )
    .expect("source offset fits in u64");
    let macro_validation = validates
        .iter()
        .find(|construct| {
            construct.fallible_kind == Some(FallibleKind::Option)
                && construct.anchor.expansion.start_byte == invocation
        })
        .expect("macro optional check is anchored at the invocation");
    assert!(
        macro_validation.anchor.definition.is_some(),
        "macro-origin validation keeps its written definition"
    );
    let spellings = validates
        .iter()
        .map(|construct| {
            let start =
                usize::try_from(construct.anchor.expansion.start_byte).expect("range start");
            let end = usize::try_from(construct.anchor.expansion.end_byte).expect("range end");
            source[start..end].to_string()
        })
        .collect::<Vec<_>>();
    assert!(
        spellings
            .iter()
            .any(|spelling| spelling.contains("value.has_value()"))
    );
    assert_eq!(
        spellings
            .iter()
            .filter(|spelling| spelling.trim() == "!value.has_value()")
            .count(),
        2
    );
    assert!(spellings.iter().any(|spelling| spelling.trim() == "value"));
    assert_eq!(
        spellings
            .iter()
            .any(|spelling| spelling.contains("expected_value.has_value()")),
        expected_validations > 0
    );
    assert!(
        spellings
            .iter()
            .all(|spelling| !spelling.contains("&& keep"))
    );
}

/// A standard `expected` is a direct propagation adapter only when the whole
/// function forwards its single same-typed parameter unchanged. This gives the
/// cross-language normalizer a compiler-confirmed counterpart to Rust's
/// `Ok(value?)` without treating ordinary expected-using functions as such.
#[test]
fn standard_expected_identity_return_is_a_propagation_construct() {
    let planted = plant("overload-resolution");
    let path = planted.root.join("src/calls.cpp");
    let source = std::fs::read_to_string(&path).expect("read C++ fixture");
    let source = format!(
        "{EXPECTED_AVAILABILITY}{source}\n\
         #ifdef CODEHELION_EXPECTED\n\
         namespace expected_checks {{\n\
         std::expected<long, int> direct(std::expected<long, int> value) {{\n\
           return value;\n\
         }}\n\
         std::expected<long, int> transformed(std::expected<long, int> value) {{\n\
           return std::expected<long, int>(value.value_or(0));\n\
         }}\n\
         std::expected<long, int> extra(std::expected<long, int> value) {{\n\
           auto copy = value;\n\
           return value;\n\
         }}\n\
         }}  // namespace expected_checks\n\
         #endif\n"
    );
    std::fs::write(&path, &source).expect("extend C++ fixture");

    let database_path = planted.root.join("compile_commands.json");
    let mut database: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&database_path).expect("read the compilation database"),
    )
    .expect("the database is JSON");
    let arguments = database[0]["arguments"]
        .as_array_mut()
        .expect("the fixture uses an arguments array");
    let standard = arguments
        .iter_mut()
        .find(|argument| argument.as_str() == Some("-std=c++17"))
        .expect("fixture declares C++17");
    *standard = serde_json::Value::String("-std=c++23".to_string());
    std::fs::write(
        &database_path,
        serde_json::to_vec_pretty(&database).expect("render the database"),
    )
    .expect("select C++23 for expected");

    let ir = overload_ir(&planted);
    // The whole case is about `std::expected`, so a build without the type has
    // nothing here to judge. It still says the fixture reached the compiler.
    if !standard_expected_available(&ir) {
        return;
    }
    let propagated = ir
        .semantic_constructs
        .iter()
        .filter(|construct| construct.kind == SemanticConstructKind::PropagateError)
        .collect::<Vec<_>>();
    assert_eq!(propagated.len(), 1, "{:?}", ir.semantic_constructs);
    assert_eq!(propagated[0].fallible_kind, Some(FallibleKind::Result));
    assert_eq!(
        propagated[0].direct_propagation,
        Some(codehelion_helper::ir::DirectPropagation::ResultAdapter)
    );
    let start = usize::try_from(propagated[0].anchor.expansion.start_byte).expect("range start");
    let end = usize::try_from(propagated[0].anchor.expansion.end_byte).expect("range end");
    assert_eq!(&source[start..end], "return value");
}

/// A direct standard `lock_guard` binding has a compiler-known acquisition and
/// the lexical function endpoint where its destructor releases the lock.
/// Multiple direct guards and a nested guard remain outside this first form.
#[test]
fn direct_standard_lock_guard_lifetimes_are_reported_at_function_scope() {
    let planted = plant("overload-resolution");
    let ir = overload_ir(&planted);
    assert!(ir.effects.computed);
    assert_eq!(ir.effects.interactions, ["synchronization"]);
    assert!(ir.effects.writes.is_empty());
    let lifetimes = ir
        .semantic_constructs
        .iter()
        .filter(|construct| {
            matches!(
                construct.kind,
                SemanticConstructKind::AcquireResource | SemanticConstructKind::ReleaseResource
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(lifetimes.len(), 4, "{:?}", ir.semantic_constructs);
    for pair in lifetimes.chunks_exact(2) {
        assert_eq!(pair[0].kind, SemanticConstructKind::AcquireResource);
        assert_eq!(pair[1].kind, SemanticConstructKind::ReleaseResource);
        assert_eq!(pair[0].resource_kind.as_deref(), Some("lock"));
        assert_eq!(pair[1].resource_kind.as_deref(), Some("lock"));
        assert!(pair[0].anchor.expansion.start_byte < pair[1].anchor.expansion.start_byte);
    }
}

/// `unique_lock` has the same compiler-known lexical release boundary as
/// `lock_guard` when it is directly bound once in a function body. It remains
/// a closed standard type check rather than a name-based project convention.
#[test]
fn direct_standard_unique_lock_lifetimes_are_reported_at_function_scope() {
    let planted = plant("overload-resolution");
    let path = planted.root.join("src/calls.cpp");
    let source = std::fs::read_to_string(&path).expect("read C++ fixture");
    let appended_at = u64::try_from(source.len()).expect("fixture offset fits in u64");
    let source = format!(
        "{source}\nnamespace unique_lock_checks {{\n\
         std::mutex mutex;\n\
         void first() {{ std::unique_lock<std::mutex> guard(mutex); }}\n\
         void second() {{ std::unique_lock<std::mutex> guard(mutex); }}\n\
         void multiple() {{\n\
           std::unique_lock<std::mutex> first_guard(mutex);\n\
           std::unique_lock<std::mutex> second_guard(mutex);\n\
         }}\n\
         void nested() {{\n\
           if (true) {{ std::unique_lock<std::mutex> guard(mutex); }}\n\
         }}\n\
         }}  // namespace unique_lock_checks\n"
    );
    std::fs::write(&path, source).expect("append unique lock fixture");

    let ir = overload_ir(&planted);
    let lifetimes = ir
        .semantic_constructs
        .iter()
        .filter(|construct| construct.anchor.expansion.start_byte >= appended_at)
        .filter(|construct| {
            matches!(
                construct.kind,
                SemanticConstructKind::AcquireResource | SemanticConstructKind::ReleaseResource
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(lifetimes.len(), 4, "{:?}", ir.semantic_constructs);
    for pair in lifetimes.chunks_exact(2) {
        assert_eq!(pair[0].kind, SemanticConstructKind::AcquireResource);
        assert_eq!(pair[1].kind, SemanticConstructKind::ReleaseResource);
        assert_eq!(pair[0].resource_kind.as_deref(), Some("lock"));
        assert_eq!(pair[1].resource_kind.as_deref(), Some("lock"));
    }
}

#[test]
fn standard_algorithm_calls_carry_closed_api_names() {
    let planted = plant("overload-resolution");
    let ir = overload_ir(&planted);
    assert_eq!(
        ir.calls
            .iter()
            .filter(|call| call.api_name.as_deref() == Some("std::transform"))
            .count(),
        3
    );
    assert_eq!(
        ir.calls
            .iter()
            .filter(|call| call.api_name.as_deref() == Some("std::copy_if"))
            .count(),
        2
    );
    assert_eq!(
        ir.calls
            .iter()
            .filter(|call| call.api_name.as_deref() == Some("std::begin"))
            .count(),
        7,
        "two collection, three transform, and two filter functions each contribute one input source"
    );
}

/// A qualified virtual call names one base implementation. An ordinary
/// virtual call does not: libclang cannot enumerate all derived overrides, so
/// emitting a partial dynamic candidate list would overstate the answer.
#[test]
fn virtual_dispatch_is_unresolved_but_a_qualified_call_is_static() {
    let planted = plant("overload-resolution");
    let source = template_source(&planted, "src/calls.cpp");
    let ir = overload_ir(&planted);
    let target = |text: &str| &call_at(&ir, "src/calls.cpp", source.find(text).unwrap()).target;

    assert!(matches!(target("base.run(3)"), CallTarget::Unresolved));
    assert!(matches!(target("derived.run(5)"), CallTarget::Unresolved));
    assert!(matches!(
        target("derived.Base::run(4)"),
        CallTarget::Static { .. }
    ));
    assert!(
        ir.calls
            .iter()
            .all(|call| !matches!(call.target, CallTarget::Dynamic { .. })),
        "an incomplete dynamic candidate set was manufactured"
    );
}

/// A function-pointer variable is not the function eventually reached, and a
/// dependent call has no selected overload until instantiation. Neither is
/// assigned a positional identity or a compile-time overload set.
#[test]
fn indirect_and_dependent_calls_stay_unresolved() {
    let planted = plant("overload-resolution");
    let source = template_source(&planted, "src/calls.cpp");
    let header = template_source(&planted, "include/calls.hpp");
    let ir = overload_ir(&planted);

    assert!(matches!(
        call_at(&ir, "src/calls.cpp", source.find("pointer(6)").unwrap()).target,
        CallTarget::Unresolved
    ));
    assert!(matches!(
        call_at(
            &ir,
            "include/calls.hpp",
            header.find("choose(value)").unwrap()
        )
        .target,
        CallTarget::Unresolved
    ));
}

/// Call anchors use the same macro index as symbols. The expanded call sits at
/// the invocation, carries the macro-body definition, and remains one call in
/// a deterministic, duplicate-free result.
#[test]
fn macro_calls_are_anchored_at_the_invocation_and_results_are_stable() {
    let planted = plant("overload-resolution");
    let source = template_source(&planted, "src/calls.cpp");
    let ir = overload_ir(&planted);
    let start = source.find("CALL_DIRECT(7)").unwrap();
    let call = call_at(&ir, "src/calls.cpp", start);
    assert_eq!(
        &source[start..usize::try_from(call.anchor.expansion.end_byte).unwrap()],
        "CALL_DIRECT(7)"
    );
    assert!(
        call.anchor
            .definition
            .as_ref()
            .is_some_and(|range| range.file == "include/calls.hpp")
    );
    assert!(matches!(call.target, CallTarget::Static { .. }));

    assert_eq!(
        ir.calls
            .iter()
            .filter(|call| call.anchor.expansion.file == "src/calls.cpp")
            .count(),
        64,
        "every written source CallExpr is represented exactly once"
    );
    assert_eq!(
        ir.calls
            .iter()
            .filter(|call| call.anchor.expansion.file == "include/calls.hpp")
            .count(),
        3,
        "every written header CallExpr is represented exactly once"
    );
    assert!(
        ir.calls.windows(2).all(|pair| {
            let left = &pair[0];
            let right = &pair[1];
            (
                &left.anchor.expansion.file,
                left.anchor.expansion.start_byte,
                left.anchor.expansion.end_byte,
            ) <= (
                &right.anchor.expansion.file,
                right.anchor.expansion.start_byte,
                right.anchor.expansion.end_byte,
            ) && left != right
        }),
        "calls are not sorted and deduplicated: {:?}",
        ir.calls
    );
    let repeated = overload_ir(&planted);
    assert_eq!(
        ir.calls, repeated.calls,
        "AST traversal order leaked into IR"
    );
}
