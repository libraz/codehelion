use super::*;

/// One function body instantiated at two substitutions is one definition and
/// two families. Repeating one substitution is still one family at two written
/// uses, and each use is anchored on the name rather than the enclosing call.
#[test]
fn function_template_uses_share_the_origin_and_key_by_specialization() {
    let planted = plant("template-instantiation");
    let source = template_source(&planted, "src/templates.cpp");
    let ir = template_ir(&planted);
    let uses: Vec<usize> = source.match_indices("twice(").map(|(at, _)| at).collect();
    assert_eq!(uses.len(), 3);
    let stamps: Vec<_> = uses
        .iter()
        .map(|at| stamp_at(&ir, "src/templates.cpp", *at))
        .collect();

    assert_eq!(stamps[0].definition, stamps[1].definition);
    assert_eq!(stamps[1].definition, stamps[2].definition);
    assert_eq!(stamps[0].instantiation_key, stamps[1].instantiation_key);
    assert_ne!(stamps[1].instantiation_key, stamps[2].instantiation_key);
    assert!(
        stamps
            .iter()
            .all(|stamp| stamp.instantiation_key.starts_with("clang-usr-v1:"))
    );
    assert!(
        stamps.iter().all(|stamp| {
            stamp
                .artifact_match_key
                .as_deref()
                .is_some_and(|key| key.starts_with("clang-display-v1:templates::twice"))
        }),
        "function template specializations retain their compiler display spelling: {stamps:#?}"
    );
    assert_eq!(stamps[0].artifact_match_key, stamps[1].artifact_match_key);
    assert_ne!(stamps[1].artifact_match_key, stamps[2].artifact_match_key);
    assert!(
        stamps.iter().all(|stamp| stamp.arguments.is_empty()),
        "clang 2.0/runtime has no unversioned function-template argument API"
    );
    for (stamp, start) in stamps.iter().zip(uses) {
        assert_eq!(
            &source[start..usize::try_from(stamp.anchor.expansion.end_byte).unwrap()],
            "twice"
        );
        let definition = stamp
            .anchor
            .definition
            .as_ref()
            .expect("the selected template body has a source range");
        assert_eq!(definition.file, "include/templates.hpp");
    }
}

/// Class specializations expose their type arguments even when another
/// argument is non-type. The concrete USR keeps the missing non-type value in
/// the key, so two array lengths do not collapse into one family.
#[test]
fn class_template_keys_keep_non_type_arguments_and_types_keep_categories() {
    let planted = plant("template-instantiation");
    let source = template_source(&planted, "src/templates.cpp");
    let ir = template_ir(&planted);
    let four = stamp_at(
        &ir,
        "src/templates.cpp",
        source.find("Buffer<int, 4>").unwrap(),
    );
    let eight = stamp_at(
        &ir,
        "src/templates.cpp",
        source.find("Buffer<int, 8>").unwrap(),
    );
    let floating = stamp_at(
        &ir,
        "src/templates.cpp",
        source.find("Buffer<double, 4>").unwrap(),
    );

    assert_eq!(four.definition, eight.definition);
    assert_eq!(eight.definition, floating.definition);
    assert_ne!(four.instantiation_key, eight.instantiation_key);
    assert_ne!(four.instantiation_key, floating.instantiation_key);
    assert_eq!(
        four.artifact_match_key.as_deref(),
        Some("clang-display-v1:templates::Buffer<int, 4>")
    );
    assert_eq!(
        eight.artifact_match_key.as_deref(),
        Some("clang-display-v1:templates::Buffer<int, 8>")
    );
    assert_eq!(
        floating.artifact_match_key.as_deref(),
        Some("clang-display-v1:templates::Buffer<double, 4>")
    );
    assert!(
        four.definition_end_line.is_some_and(|line| line > 36),
        "the class definition extent contains its inline member: {four:#?}"
    );
    assert_eq!(four.arguments.len(), 1, "the non-type argument is key-only");
    assert_eq!(
        eight.arguments.len(),
        1,
        "the non-type argument is key-only"
    );
    assert_eq!(
        ir.types[four.arguments[0] as usize].category,
        TypeCategory::Integer
    );
    assert_eq!(
        ir.types[floating.arguments[0] as usize].category,
        TypeCategory::Float
    );
}

/// Clang identifies the selected partial specialization directly. A full
/// explicit specialization owns another body and is therefore not attributed
/// to the primary, while external and ordinary controls produce no stamps.
#[test]
fn selected_partial_and_controls_are_not_misattributed() {
    let planted = plant("template-instantiation");
    let source = template_source(&planted, "src/templates.cpp");
    let ir = template_ir(&planted);
    let partial = stamp_at(
        &ir,
        "src/templates.cpp",
        source.find("Holder<int*>").unwrap(),
    );
    assert!(
        partial.definition.contains("@SP>"),
        "the selected partial-specialization USR is the origin: {partial:?}"
    );
    let written = partial
        .anchor
        .definition
        .as_ref()
        .expect("the partial specialization has a body");
    let header = template_source(&planted, "include/templates.hpp");
    assert!(
        header[usize::try_from(written.start_byte).unwrap()
            ..usize::try_from(written.end_byte).unwrap()]
            .contains("struct Holder<T*>")
    );

    for control in ["Holder<bool>", "std::vector<int>", "ordinary("] {
        let at = source.find(control).unwrap();
        let end = at + control.len();
        assert!(
            ir.instantiations.iter().all(|stamp| {
                if stamp.anchor.expansion.file != "src/templates.cpp" {
                    return true;
                }
                let start = usize::try_from(stamp.anchor.expansion.start_byte).unwrap();
                !(at..end).contains(&start)
            }),
            "{control} was reported as an instantiation: {:?}",
            ir.instantiations
        );
    }
    assert!(
        ir.instantiations.windows(2).all(|pair| {
            let left = &pair[0];
            let right = &pair[1];
            (
                &left.anchor.expansion.file,
                left.anchor.expansion.start_byte,
                left.anchor.expansion.end_byte,
                &left.instantiation_key,
            ) < (
                &right.anchor.expansion.file,
                right.anchor.expansion.start_byte,
                right.anchor.expansion.end_byte,
                &right.instantiation_key,
            )
        }),
        "stamps are not sorted and deduplicated: {:?}",
        ir.instantiations
    );
}
