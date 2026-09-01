use super::*;

/// Every non-value return form has to keep its control flow, or a checker
/// reading `debug.DumpCFG` headings loses the graph for anything but a
/// function returning by value. Built as its own self-contained project
/// (rather than reusing the `CMake` fixture) so the source is visible right
/// here next to what it asserts.
#[test]
fn pointer_and_reference_returning_functions_keep_their_cfg_blocks() {
    let directory = tempfile::tempdir().expect("temp dir");
    let root = directory.path().canonicalize().expect("temp dir exists");
    let source = root.join("unit.cpp");
    std::fs::write(
        &source,
        concat!(
            "struct S { int value; };\n",
            "\n",
            "int *pick(int v) {\n",
            "  static int a = 1;\n",
            "  static int b = 2;\n",
            "  if (v > 0) {\n",
            "    return &a;\n",
            "  }\n",
            "  return &b;\n",
            "}\n",
            "\n",
            "int &ref(S &s) {\n",
            "  if (s.value > 0) {\n",
            "    return s.value;\n",
            "  }\n",
            "  s.value = 0;\n",
            "  return s.value;\n",
            "}\n",
        ),
    )
    .expect("write source");
    let database = serde_json::json!([{
        "directory": root,
        "arguments": ["clang++", "-std=c++20", "-c", "-o", "unit.o", source],
        "file": source,
    }]);
    std::fs::write(
        root.join("compile_commands.json"),
        serde_json::to_vec_pretty(&database).expect("serialize database"),
    )
    .expect("write database");

    let unit = UnitRef {
        unit: source.display().to_string(),
        file: source.display().to_string(),
        variant: "host".to_string(),
    };
    let mut helper = helper();
    let analysis = helper
        .analyze(&unit, &[Capability::MirCfg])
        .expect("the helper should answer");
    helper.shutdown().expect("the helper should stop cleanly");
    let Analysis::Done(ir) = analysis else {
        panic!("a pointer- and reference-returning translation unit is readable");
    };
    let cfg = ir
        .cfg
        .expect("pointer- and reference-returning functions still produce a CFG");
    let anchors: std::collections::BTreeSet<_> = cfg
        .blocks
        .iter()
        .map(|block| {
            (
                block.anchor.expansion.start_byte,
                block.anchor.expansion.end_byte,
            )
        })
        .collect();
    assert_eq!(
        anchors.len(),
        2,
        "both the pointer-returning and the reference-returning definition keep blocks: {cfg:?}"
    );
}

#[test]
fn compiler_cfgs_are_anchored_to_unambiguous_function_definitions() {
    let planted = plant("cmake");
    let unit = planted.unit("src/geometry.cpp", "src/geometry.cpp");
    let mut helper = helper();
    let analysis = helper
        .analyze(&unit, &[Capability::MirCfg])
        .expect("the helper should answer");
    helper.shutdown().expect("the helper should stop cleanly");
    let Analysis::Done(ir) = analysis else {
        panic!("the CMake fixture has a readable translation unit");
    };
    let cfg = ir.cfg.expect("the fixed Clang frontend produced a CFG");
    assert!(cfg.blocks.len() >= 10, "{cfg:?}");
    assert!(
        cfg.blocks
            .iter()
            .all(|block| block.anchor.expansion.file == "src/geometry.cpp"),
        "{cfg:?}"
    );
    assert!(
        cfg.edges.iter().any(|edge| edge.kind.name() == "taken")
            && cfg.edges.iter().any(|edge| edge.kind.name() == "not_taken"),
        "{cfg:?}"
    );
}

#[test]
fn a_plain_standard_vector_range_loop_is_a_closed_collection_construct() {
    let planted = plant("overload-resolution");
    let ir = analyzed(&planted.unit("src/range_loop.cpp", "src/range_loop.cpp"));
    let constructs: Vec<_> = ir
        .semantic_constructs
        .iter()
        .filter(|construct| {
            construct.anchor.expansion.file == "src/range_loop.cpp"
                && matches!(
                    construct.kind,
                    SemanticConstructKind::Source
                        | SemanticConstructKind::Collect
                        | SemanticConstructKind::Reduce
                )
        })
        .collect();
    assert_eq!(
        constructs
            .iter()
            .map(|construct| construct.kind)
            .collect::<Vec<_>>(),
        vec![
            SemanticConstructKind::Source,
            SemanticConstructKind::Collect,
            SemanticConstructKind::Source,
            SemanticConstructKind::Collect,
            SemanticConstructKind::Source,
            SemanticConstructKind::Reduce,
            SemanticConstructKind::Source,
            SemanticConstructKind::Reduce,
        ],
        "only direct collection and numeric reduction range loops are normalized: {constructs:?}"
    );
}

/// The claim C++ exists to make here. One header, two translation units, and
/// the same characters declare a 32-bit accumulator in one and a 64-bit one in
/// the other — so an answer about the file alone would be one of the two
/// readings presented as the reading.
#[test]
fn one_header_read_by_two_units_is_two_different_programs() {
    let planted = plant("header-only");
    let header = "include/accumulate.hpp";

    let narrow = analyzed(&planted.unit("src/narrow.cpp", header));
    let wide = analyzed(&planted.unit("src/wide.cpp", header));

    // Both readings are of the same file, and both say so.
    for ir in [&narrow, &wide] {
        assert_eq!(ir.schema_version, COMPILER_IR_SCHEMA_VERSION);
        assert_eq!(
            ir.anchored_at.as_deref(),
            Some(planted.root.to_str().unwrap())
        );
        assert!(
            ir.symbols
                .iter()
                .any(|symbol| symbol.anchor.expansion.file == header),
            "the header the unit read is reported on"
        );
    }

    // And the compiler resolved one name to two widths, which is the whole
    // reason a unit is part of what is asked about. Both are integers — the
    // category is coarse on purpose — so what says they differ is the resolved
    // form, which is why that is what a type is recorded as.
    assert_eq!(type_of(&narrow, "total").category, TypeCategory::Integer);
    assert_eq!(type_of(&wide, "total").category, TypeCategory::Integer);
    assert_ne!(
        type_of(&narrow, "total").display,
        type_of(&wide, "total").display,
        "the same declaration resolves to a different type in each reading"
    );
}

/// A header is compiled by no command of its own, so nothing can be asked about
/// it as a unit. What reads it is a translation unit, and the answer about that
/// unit is where the header's names are — filed under the header, because a
/// name reported under the unit's own file would be attributed to a file it was
/// never written in.
///
/// What the unit read from outside the project stays out. `<vector>` is not
/// this project's code, nothing in the scan can be cut from it, and reporting
/// its thousands of declarations would bury the tree's own in them.
#[test]
fn a_header_is_answered_under_the_unit_that_reads_it() {
    let planted = plant("header-only");
    let ir = analyzed(&planted.unit("src/narrow.cpp", "src/narrow.cpp"));

    let files: std::collections::BTreeSet<&str> = ir
        .symbols
        .iter()
        .map(|symbol| symbol.anchor.expansion.file.as_str())
        .collect();
    assert!(
        files.contains("include/accumulate.hpp"),
        "the header the unit read is reported on: {files:?}"
    );
    assert!(
        files.contains("src/narrow.cpp"),
        "and so is the unit's own source: {files:?}"
    );
    assert_eq!(
        files.len(),
        2,
        "nothing from outside the tree is reported: {files:?}"
    );

    // Anchored where it is written, not where the request pointed: `sum` is
    // declared in the header and called from the source, and the two are
    // different places in different files.
    let declared = ir
        .symbols
        .iter()
        .find(|symbol| {
            symbol.name == "sum" && symbol.kind == codehelion_helper::ir::SymbolKind::Function
        })
        .expect("the header declares sum");
    assert_eq!(declared.anchor.expansion.file, "include/accumulate.hpp");
}

/// The categories are a claim about what libclang reports, so they are checked
/// against a fixture a person can open: `values` is a reference to a vector,
/// and what the code holds is the reference.
#[test]
fn a_type_is_reported_as_the_shape_another_language_would_recognise() {
    let planted = plant("header-only");
    let ir = analyzed(&planted.unit("src/narrow.cpp", "include/accumulate.hpp"));
    assert_eq!(type_of(&ir, "values").category, TypeCategory::Handle);
    assert_eq!(type_of(&ir, "total").category, TypeCategory::Integer);
    assert_eq!(type_of(&ir, "value").category, TypeCategory::Integer);
    // What the reference points at is recorded too, and it is the standard
    // library's sequence rather than a record that happens to be called vector.
    let element = type_of(&ir, "values")
        .arguments
        .first()
        .copied()
        .expect("what the reference points at");
    assert_eq!(ir.types[element as usize].category, TypeCategory::Sequence);
}

/// Not every declaration is externally nameable, and for the ones Clang has no
/// identity for this helper builds one out of where they were declared. Built
/// from the path the filesystem has, that identity would be one only the
/// machine that produced it can arrive at: two runs over one tree reached by
/// different paths would disagree about a declaration neither of them changed,
/// and a comparison across them would find nothing.
///
/// Asserted over every identity the answer carries rather than over one that is
/// known to fall back, because which declarations a given libclang can spell is
/// its business and not something a fixture can pin down.
#[test]
fn no_identity_carries_the_path_this_tree_happens_to_sit_at() {
    let planted = plant("header-only");
    let ir = analyzed(&planted.unit("src/narrow.cpp", "include/accumulate.hpp"));
    let elsewhere = planted.root.display().to_string();
    let leaked = ir
        .symbols
        .iter()
        .map(|symbol| symbol.id.as_str())
        .chain(ir.types.iter().filter_map(|ty| ty.definition.as_deref()))
        .filter(|id| id.contains(&elsewhere))
        .collect::<Vec<_>>();
    assert!(leaked.is_empty(), "{leaked:?}");
}

/// The category the Rust helper reports for the counterpart of these types,
/// which is the whole reason it is named rather than derived: a function taking
/// `std::optional<T>` and one taking the optional of another language are the
/// same shape, and a comparison that saw two shapes would score a real clone
/// down for a disagreement between the two helpers rather than a difference
/// between the two programs.
#[test]
fn a_standard_optional_and_a_standard_fallible_are_one_category() {
    let planted = plant("overload-resolution");
    let path = planted.root.join("src/calls.cpp");
    let source = std::fs::read_to_string(&path).expect("read C++ fixture");
    std::fs::write(
        &path,
        format!(
            "#include <optional>\n{EXPECTED_AVAILABILITY}{source}\n\
             namespace shapes {{\n\
             long optional_shape(std::optional<long> maybe_total) {{\n\
               return maybe_total.value_or(0);\n\
             }}\n\
             #ifdef CODEHELION_EXPECTED\n\
             long fallible_shape(std::expected<long, int> maybe_result) {{\n\
               return maybe_result.value_or(0);\n\
             }}\n\
             #endif\n\
             }}  // namespace shapes\n"
        ),
    )
    .expect("extend C++ fixture");
    let database_path = planted.root.join("compile_commands.json");
    let database = std::fs::read_to_string(&database_path).expect("read compilation database");
    std::fs::write(&database_path, database.replace("-std=c++17", "-std=c++23"))
        .expect("compile the fixture under the standard that has the fallible type");

    let ir = analyzed(&planted.unit("src/calls.cpp", "src/calls.cpp"));
    assert_eq!(
        type_of(&ir, "maybe_total").category,
        TypeCategory::Enumeration
    );
    // The other half only where the standard library behind this build has the
    // type at all; where it does not, the fixture compiled it out.
    if standard_expected_available(&ir) {
        assert_eq!(
            type_of(&ir, "maybe_result").category,
            TypeCategory::Enumeration
        );
    }
}

/// What the normalizer asks the compiler for: whether a name is this project's
/// own or one it shares with everything else that includes the same header.
#[test]
fn a_name_from_outside_the_tree_is_told_apart_from_the_projects_own() {
    let planted = plant("header-only");
    let ir = analyzed(&planted.unit("src/narrow.cpp", "include/accumulate.hpp"));
    let external = |name: &str| {
        ir.symbols
            .iter()
            .find(|symbol| symbol.name == name)
            .unwrap_or_else(|| panic!("no symbol called {name}"))
            .external
    };
    assert!(
        external("vector"),
        "the standard library is not this project"
    );
    assert!(!external("sum"), "the fixture's own function is");
    assert!(!external("accumulate"), "and so is its namespace");
}

/// What a macro produced, and where the two halves of that are.
///
/// A macro invoked three times produces three identical bodies. Nobody wrote
/// them three times and nobody can delete one of them, so a detector reading
/// only the text reports repetition that cannot be acted on. What tells that
/// apart is that all three were written in one place — which is what the
/// spelling location says and the expansion location cannot.
#[test]
fn what_a_macro_produced_says_where_it_was_written() {
    let planted = plant("macro-expansion");
    let header = "include/accessor.hpp";
    let ir = analyzed(&planted.unit("src/frame.cpp", "src/frame.cpp"));

    let stamped: Vec<_> = ["width_", "height_", "depth_"]
        .iter()
        .map(|name| {
            ir.symbols
                .iter()
                .find(|symbol| {
                    symbol.name == *name && symbol.kind == codehelion_helper::ir::SymbolKind::Field
                })
                .unwrap_or_else(|| panic!("the macro-produced field {name} is reported"))
        })
        .collect();

    // Three invocations, three places in the file, one place they were written.
    // The second half is what turns three findings into one, and is the only
    // part the characters in the file cannot supply.
    let invocations: std::collections::BTreeSet<(u64, u64)> = stamped
        .iter()
        .map(|symbol| {
            assert_eq!(symbol.anchor.expansion.file, header);
            (
                symbol.anchor.expansion.start_byte,
                symbol.anchor.expansion.end_byte,
            )
        })
        .collect();
    assert_eq!(invocations.len(), 3, "{invocations:?}");
    let written = stamped[0]
        .anchor
        .definition
        .as_ref()
        .expect("an expanded name says where it was written");
    assert_eq!(
        written,
        &codehelion_helper::ir::SourceRange {
            file: header.into(),
            start_byte: 549,
            end_byte: 741,
            start_line: 13,
        },
        "the definition is the complete macro body, not an AST cursor's mixed spelling range"
    );
    for symbol in stamped.iter().skip(1) {
        assert_eq!(
            symbol.anchor.definition.as_ref(),
            Some(written),
            "every invocation maps to the exact same definition cursor"
        );
    }

    // And a declaration written where it reads carries no second place, or the
    // answer would be the same for everything and say nothing.
    let plain = ir
        .symbols
        .iter()
        .find(|symbol| symbol.name == "volume")
        .expect("the fixture declares a function outside the macro");
    assert!(!plain.anchor.is_expanded(), "{:?}", plain.anchor);
}

/// A macro body outside the project is still where generated code was written.
///
/// This uses an ordinary local include directory beside the planted project:
/// external means outside the scan root, not remote, untrusted, or unavailable.
#[test]
fn a_macro_definition_outside_the_tree_keeps_its_own_path() {
    let planted = plant("macro-expansion");
    let dependency = tempfile::tempdir().expect("external include directory");
    let external_header = dependency.path().join("external_accessor.hpp");
    std::fs::write(
        &external_header,
        "#pragma once\n#define EXTERNAL_FIELD(type, name) type name##_; \n",
    )
    .expect("write the external header");

    let project_header = planted.root.join("include/accessor.hpp");
    let source = std::fs::read_to_string(&project_header).expect("read the project header");
    let source = source
        .replace(
            "#include <cstdint>\n",
            "#include <cstdint>\n#include <external_accessor.hpp>\n",
        )
        .replace(
            "struct Frame {\n",
            "struct Frame {\n  EXTERNAL_FIELD(std::uint32_t, external)\n",
        );
    std::fs::write(&project_header, source).expect("include and invoke the external macro");

    let database_path = planted.root.join("compile_commands.json");
    let mut database: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&database_path).expect("read the compilation database"),
    )
    .expect("the database is JSON");
    let arguments = database[0]["arguments"]
        .as_array_mut()
        .expect("the fixture uses an arguments array");
    arguments.insert(
        1,
        serde_json::Value::String(format!("-I{}", dependency.path().display())),
    );
    std::fs::write(
        &database_path,
        serde_json::to_vec_pretty(&database).expect("render the database"),
    )
    .expect("add the external include path");

    let ir = analyzed(&planted.unit("src/frame.cpp", "src/frame.cpp"));
    let field = ir
        .symbols
        .iter()
        .find(|symbol| {
            symbol.name == "external_" && symbol.kind == codehelion_helper::ir::SymbolKind::Field
        })
        .expect("the external macro produced a field");
    assert_eq!(field.anchor.expansion.file, "include/accessor.hpp");
    let definition = field
        .anchor
        .definition
        .as_ref()
        .expect("the field keeps the macro definition");
    assert_eq!(
        definition.file,
        external_header
            .canonicalize()
            .expect("the external header exists")
            .display()
            .to_string()
    );
    assert!(definition.end_byte > definition.start_byte);
}
