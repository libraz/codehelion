use crate::ir::tests::parse;

#[test]
fn signatures_are_sorted_exact_and_ignore_parameter_names() {
    let source = "const int *first(const char *left, int values[4]) { return 0; }\nconst int *second(const char *right, int items[4]) { return 0; }";
    let file = parse(source);
    assert!(
        file.error_ranges.is_empty(),
        "unexpected parse errors: {:?}",
        file.error_ranges
    );
    assert_eq!(file.signatures.len(), 2);
    assert!(file.signatures.windows(2).all(|pair| pair[0].0 < pair[1].0));
    let first = file.signature_for_range(file.signatures[0].0).unwrap();
    let second = file.signature_for_range(file.signatures[1].0).unwrap();
    assert_eq!(first.normalized, second.normalized);
    assert_eq!(first.key, second.key);
    assert!(first.normalized.contains("t3:int"));
    assert!(first.normalized.contains("t5:const"));
    assert!(first.normalized.contains("t4:char"));
    assert!(first.normalized.contains("t1:4"));
}

#[test]
fn signatures_distinguish_return_type_changes() {
    let int_file = parse("int first(int value) { return value; }");
    let long_file = parse("long first(int value) { return value; }");
    assert_eq!(int_file.signatures.len(), 1);
    assert_eq!(long_file.signatures.len(), 1);
    assert_ne!(int_file.signatures[0].1.key, long_file.signatures[0].1.key);
}

#[test]
fn signatures_alpha_normalize_vla_parameter_references() {
    let first = parse("int first(int count, int values[count]) { return count; }");
    let second = parse("int second(int renamed, int items[renamed]) { return renamed; }");
    assert!(first.error_ranges.is_empty(), "{:?}", first.error_ranges);
    assert!(second.error_ranges.is_empty(), "{:?}", second.error_ranges);
    assert_eq!(first.signatures.len(), 1);
    assert_eq!(second.signatures.len(), 1);
    assert_eq!(first.signatures[0].1, second.signatures[0].1);
    assert!(
        first.signatures[0]
            .1
            .normalized
            .contains("t3:intt1:[p0;t1:]")
    );

    let non_parameter_type = parse(
        "int first(int count, int values[limit]) { return count; }\nint second(int renamed, int items[other_limit]) { return renamed; }",
    );
    assert!(non_parameter_type.error_ranges.is_empty());
    assert_eq!(non_parameter_type.signatures.len(), 2);
    assert_ne!(
        non_parameter_type.signatures[0].1.key,
        non_parameter_type.signatures[1].1.key
    );
}

#[test]
fn signatures_respect_parameter_declaration_order_in_vla_bounds() {
    let external = parse(
        "enum { N = 4 }; enum { M = 5 }; int first(int values[N], int N) { return N; }\nint second(int values[M], int M) { return M; }",
    );
    assert!(
        external.error_ranges.is_empty(),
        "{:?}",
        external.error_ranges
    );
    assert_eq!(external.signatures.len(), 2);
    assert_ne!(external.signatures[0].1.key, external.signatures[1].1.key);

    let renamed = parse(
        "enum { N = 4 }; int first(int values[N], int N) { return N; }\nint second(int items[N], int M) { return M; }",
    );
    assert!(
        renamed.error_ranges.is_empty(),
        "{:?}",
        renamed.error_ranges
    );
    assert_eq!(renamed.signatures.len(), 2);
    assert_eq!(renamed.signatures[0].1.key, renamed.signatures[1].1.key);
}

#[test]
fn signatures_preserve_c_token_boundaries() {
    let file = parse(
        "typedef int unsignedlong; unsigned long first(int value) { return 0; }\nunsignedlong second(int value) { return 0; }",
    );
    assert!(file.error_ranges.is_empty(), "{:?}", file.error_ranges);
    assert_eq!(file.signatures.len(), 2);
    assert_ne!(file.signatures[0].1.key, file.signatures[1].1.key);
    assert!(
        file.signatures[0]
            .1
            .normalized
            .contains("t8:unsignedt4:long")
    );
}

#[test]
fn signatures_skip_parameter_list_comments() {
    let comments = parse(
        "int first(int left /* parameter */, /* between */ int right) { return 0; }\nint second(int left, int right) { return 0; }",
    );
    assert!(
        comments.error_ranges.is_empty(),
        "{:?}",
        comments.error_ranges
    );
    assert_eq!(comments.signatures.len(), 2);
    assert_eq!(comments.signatures[0].1, comments.signatures[1].1);
}

#[test]
fn signatures_reject_c_attributes_and_calling_convention_extensions() {
    let attributes = parse(
        "int first(int value) __attribute__((nonnull)) { return value; }\nint second(int value) __attribute__((nothrow)) { return value; }",
    );
    assert!(attributes.signatures.is_empty());

    let declspec = parse(
        "__declspec(noinline) int first(int value) { return value; }\n__declspec(nothrow) int second(int value) { return value; }",
    );
    assert!(declspec.signatures.is_empty());

    let calling_convention = parse(
        "int __cdecl first(int value) { return value; }\nint __stdcall second(int value) { return value; }",
    );
    assert!(calling_convention.signatures.is_empty());
}

#[test]
fn signatures_reject_variadic_and_function_pointer_parameters() {
    for source in [
        "int variadic(int first, ...) { return first; }",
        "int callback(int (*handler)(int)) { return 0; }",
        "int broken(int value { return value; }",
    ] {
        let file = parse(source);
        assert!(
            file.signatures.is_empty(),
            "unsupported signature must not be guessed: {source:?}"
        );
    }
}

#[test]
fn signatures_keep_healthy_units_when_another_header_is_broken() {
    let source = "int healthy(int value) { MACRO_BODY(value); return value; }\nint broken(int value { return value; }";
    let file = parse(source);
    assert!(!file.error_ranges.is_empty());
    assert_eq!(file.signatures.len(), 1);
    let (range, signature) = &file.signatures[0];
    assert!(source[range.start..range.end].contains("healthy"));
    assert!(signature.normalized.contains("receiver=free"));
}

#[test]
fn signatures_keep_a_healthy_header_when_its_body_has_an_error() {
    let source =
        "int healthy(int value) { @@@ return value; }\nint broken(int value { return value; }";
    let file = parse(source);
    assert!(!file.error_ranges.is_empty());
    assert_eq!(file.signatures.len(), 1);
    let (range, _) = &file.signatures[0];
    assert!(source[range.start..range.end].contains("healthy"));
}

#[test]
fn macro_built_function_declarations_are_not_signatures() {
    for source in [
        "API(int) first(int value) { return value; }",
        "API(foo)(int value) { return value; }",
        "TEST(Suite, Case) { return 0; }",
    ] {
        let file = parse(source);
        assert!(
            file.signatures.is_empty(),
            "macro-built declaration must be unsupported: {source:?}"
        );
    }
    let body_macro = parse("int body_macro(int value) { API(value); return value; }");
    assert_eq!(body_macro.signatures.len(), 1);
}
