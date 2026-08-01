use super::*;

fn read(unit: &str, symbols: Vec<ResolvedSymbol>, types: Vec<ResolvedType>) -> Gathered {
    read_with_instantiations(unit, symbols, types, Vec::new())
}

fn read_with_instantiations(
    unit: &str,
    symbols: Vec<ResolvedSymbol>,
    types: Vec<ResolvedType>,
    instantiations: Vec<Instantiation>,
) -> Gathered {
    let mut ir = CompilerIr::empty(UnitRef {
        unit: format!("/repo/src/{unit}"),
        file: format!("/repo/src/{unit}"),
        variant: "host".into(),
    });
    ir.anchored_at = Some("/repo".into());
    ir.symbols = symbols;
    ir.types = types;
    ir.instantiations = instantiations;
    Gathered::Analyzed {
        backend: 0,
        ir: Box::new(ir),
    }
}

fn read_with_calls(unit: &str, calls: Vec<CallSite>) -> Gathered {
    let mut gathered = read(unit, Vec::new(), Vec::new());
    let Gathered::Analyzed { ir, .. } = &mut gathered else {
        unreachable!("read always produces an analysis");
    };
    ir.calls = calls;
    gathered
}

fn read_with_unexpanded_macros(unit: &str, macros: Vec<UnexpandedMacro>) -> Gathered {
    let mut gathered = read(unit, Vec::new(), Vec::new());
    let Gathered::Analyzed { ir, .. } = &mut gathered else {
        unreachable!("read always produces an analysis");
    };
    ir.unexpanded_macros = macros;
    gathered
}

fn unexpanded_macro(start: u64, reason: UnexpandedMacroReason) -> UnexpandedMacro {
    UnexpandedMacro {
        invocation: SourceRange {
            file: "include/accumulate.hpp".into(),
            start_byte: start,
            end_byte: start + 12,
            start_line: 20,
        },
        reason,
    }
}

fn call(start: u64, target: CallTarget, definition: Option<&str>) -> CallSite {
    CallSite {
        anchor: Anchor {
            expansion: SourceRange {
                file: "include/accumulate.hpp".into(),
                start_byte: start,
                end_byte: start + 8,
                start_line: 20,
            },
            definition: definition.map(|file| SourceRange {
                file: file.into(),
                start_byte: 10,
                end_byte: 30,
                start_line: 2,
            }),
        },
        target,
        api_name: None,
    }
}

#[test]
fn resolved_api_targets_keep_static_and_dynamic_calls_distinct() {
    let gathered = read_with_calls(
        "fixture.cpp",
        vec![
            call(
                10,
                CallTarget::Static {
                    symbol: "c:@F@run#I#".into(),
                },
                None,
            ),
            call(
                20,
                CallTarget::Dynamic {
                    candidates: vec!["c:@F@right#".into(), "c:@F@left#".into()],
                },
                None,
            ),
            call(30, CallTarget::Unresolved, None),
        ],
    );
    let Gathered::Analyzed { ir, .. } = gathered else {
        panic!("the fixture helper answer is analyzed");
    };
    assert_eq!(
        resolved_api_for(&ir, "include/accumulate.hpp"),
        vec![
            (
                ByteRange { start: 10, end: 18 },
                "static:c:@F@run#I#".into(),
            ),
            (
                ByteRange { start: 20, end: 28 },
                "dynamic:c:@F@left#\u{1f}c:@F@right#".into(),
            ),
        ]
    );
}

fn typed(mut symbol: ResolvedSymbol, at: u32) -> ResolvedSymbol {
    symbol.type_index = Some(at);
    symbol
}

fn defined(mut symbol: ResolvedSymbol, file: &str, start: u64) -> ResolvedSymbol {
    symbol.anchor.definition = Some(SourceRange {
        file: file.into(),
        start_byte: start,
        end_byte: start + 10,
        start_line: 1,
    });
    symbol
}

fn integer(display: &str) -> ResolvedType {
    ResolvedType {
        display: display.into(),
        category: TypeCategory::Integer,
        arguments: Vec::new(),
        definition: None,
    }
}

fn instantiation(key: &str, argument: u32) -> Instantiation {
    Instantiation {
        anchor: Anchor {
            expansion: SourceRange {
                file: "include/accumulate.hpp".into(),
                start_byte: 600,
                end_byte: 606,
                start_line: 20,
            },
            definition: Some(SourceRange {
                file: "include/templates.hpp".into(),
                start_byte: 20,
                end_byte: 80,
                start_line: 3,
            }),
        },
        definition: "c:@N@accumulate@FT@sum".into(),
        definition_end_line: None,
        artifact_match_key: None,
        instantiation_key: key.into(),
        arguments: vec![argument],
    }
}

fn header() -> SourceUnit {
    let mut source = source("include/accumulate.hpp", Language::Cpp, None);
    source.is_header = true;
    source
}

fn unanswerable(source: &SourceUnit) -> Gathered {
    Gathered::Unavailable {
        backend: 0,
        unit: unit_ref(source, "host"),
        reason: Unavailability::NoBuildInformation,
    }
}

/// No command compiles a header, so nothing can be asked about it as a unit
/// of its own. The unit that includes it read it, and its names are in that
/// unit's answer — which is the only place they are.
#[test]
fn a_file_no_command_compiles_is_answered_by_the_unit_that_read_it() {
    let sources = [source("src/narrow.cpp", Language::Cpp, None), header()];
    let mut gathered = vec![
        read(
            "narrow.cpp",
            vec![symbol("sum", "include/accumulate.hpp", 300, 3, false)],
            Vec::new(),
        ),
        unanswerable(&sources[1]),
    ];
    read_by_other_units(&mut gathered, &sources);
    let Gathered::Analyzed { ir, .. } = &gathered[1] else {
        panic!("the header is answered by the unit that read it");
    };
    // Filed under the header, and under the unit that read it — which is
    // the program these names were resolved in, and is not the header.
    assert_eq!(ir.unit.file, "/repo/include/accumulate.hpp");
    assert_eq!(ir.unit.unit, "/repo/src/narrow.cpp");
    assert_eq!(ir.anchored_at.as_deref(), Some("/repo"));
    assert_eq!(ir.symbols.len(), 1);
    assert_eq!(ir.symbols[0].name, "sum");
}

/// A source file that the compiler could not answer for is not a header.
/// A declaration another unit happened to expose about it is not an answer
/// for that source file and must remain visible as missing coverage.
#[test]
fn an_unavailable_translation_unit_is_not_answered_by_a_reader() {
    let sources = [
        source("src/reader.cpp", Language::Cpp, None),
        source("src/unavailable.cpp", Language::Cpp, None),
    ];
    let mut gathered = vec![
        read(
            "reader.cpp",
            vec![symbol("leaked", "src/unavailable.cpp", 300, 3, true)],
            Vec::new(),
        ),
        unanswerable(&sources[1]),
    ];

    read_by_other_units(&mut gathered, &sources);

    assert!(matches!(gathered[1], Gathered::Unavailable { .. }));
}

/// Two units can compile one header into two different programs. A run with
/// one build variant has nowhere to keep both readings apart, so what it
/// says about the header is what both agree on — and the names they differ
/// over are left to be compared as they are written.
#[test]
fn what_two_readings_of_one_header_disagree_about_is_left_unsaid() {
    let sources = [
        source("src/narrow.cpp", Language::Cpp, None),
        source("src/wide.cpp", Language::Cpp, None),
        header(),
    ];
    let agree = symbol("values", "include/accumulate.hpp", 400, 6, false);
    let differ = symbol("total", "include/accumulate.hpp", 500, 5, false);
    let mut gathered = vec![
        read(
            "narrow.cpp",
            vec![agree.clone(), typed(differ.clone(), 0)],
            vec![integer("unsigned int")],
        ),
        read(
            "wide.cpp",
            vec![agree, typed(differ, 0)],
            vec![integer("unsigned long long")],
        ),
        unanswerable(&sources[2]),
    ];
    read_by_other_units(&mut gathered, &sources);
    let Gathered::Analyzed { ir, .. } = &gathered[2] else {
        panic!("the header is answered by the units that read it");
    };
    assert_eq!(
        ir.symbols.iter().map(|s| &s.name).collect::<Vec<_>>(),
        vec!["values"],
        "the name the two readings resolved differently is not reported"
    );
    // An agreement between two readings is an answer about no single unit,
    // and naming one of them would file it under that reading's program.
    assert!(ir.unit.unit.is_empty(), "{:?}", ir.unit);
    // And what did survive carries no type it never had: the table holds
    // what the kept names refer to and nothing else.
    assert!(ir.types.is_empty());
}

/// A macro selected differently in two translation units can stamp a name
/// at the same bytes with the same type and definition identity. Its body
/// anchor is still part of the answer: retaining the first reading would
/// claim a definition site the other unit explicitly contradicts.
#[test]
fn macro_definition_anchors_must_agree_across_translation_units() {
    let sources = [
        source("src/narrow.cpp", Language::Cpp, None),
        source("src/wide.cpp", Language::Cpp, None),
        header(),
    ];
    let stable = symbol("values", "include/accumulate.hpp", 400, 6, false);
    let expanded = symbol("total", "include/accumulate.hpp", 500, 5, false);
    let mut gathered = vec![
        read(
            "narrow.cpp",
            vec![
                stable.clone(),
                defined(expanded.clone(), "include/narrow_macro.hpp", 20),
            ],
            Vec::new(),
        ),
        read(
            "wide.cpp",
            vec![stable, defined(expanded, "include/wide_macro.hpp", 30)],
            Vec::new(),
        ),
        unanswerable(&sources[2]),
    ];

    read_by_other_units(&mut gathered, &sources);
    let Gathered::Analyzed { ir, .. } = &gathered[2] else {
        panic!("the stable part of the header is still answered");
    };
    assert_eq!(
        ir.symbols
            .iter()
            .map(|symbol| &symbol.name)
            .collect::<Vec<_>>(),
        vec!["values"],
        "a representative macro definition was retained despite disagreement"
    );
}

/// A header can be known only through template uses, so reader discovery
/// cannot be driven by symbols alone. The type index belongs to the first
/// translation unit's table and must be remapped into the merged table.
#[test]
fn agreed_header_instantiations_are_retained_with_remapped_types() {
    let sources = [
        source("src/narrow.cpp", Language::Cpp, None),
        source("src/wide.cpp", Language::Cpp, None),
        header(),
    ];
    let key = "clang-usr-v1:c:@N@accumulate@F@sum<#I>";
    let mut gathered = vec![
        read_with_instantiations(
            "narrow.cpp",
            Vec::new(),
            vec![integer("unused"), integer("int")],
            vec![instantiation(key, 1)],
        ),
        read_with_instantiations(
            "wide.cpp",
            Vec::new(),
            vec![integer("int")],
            vec![instantiation(key, 0)],
        ),
        unanswerable(&sources[2]),
    ];

    read_by_other_units(&mut gathered, &sources);
    let Gathered::Analyzed { ir, .. } = &gathered[2] else {
        panic!("the agreed template use answers the header");
    };
    assert!(ir.symbols.is_empty());
    assert_eq!(ir.instantiations.len(), 1);
    assert_eq!(ir.instantiations[0].instantiation_key, key);
    assert_eq!(ir.instantiations[0].arguments, [0]);
    assert_eq!(ir.types.len(), 1);
    assert_eq!(ir.types[0].display, "int");
}

/// Picking the first translation unit would silently select one concrete
/// specialization for a header whose build-dependent reading disagrees.
/// With no common answer, the header stays unavailable.
#[test]
fn disagreeing_header_instantiations_do_not_choose_a_representative() {
    let sources = [
        source("src/narrow.cpp", Language::Cpp, None),
        source("src/wide.cpp", Language::Cpp, None),
        header(),
    ];
    let mut gathered = vec![
        read_with_instantiations(
            "narrow.cpp",
            Vec::new(),
            vec![integer("int")],
            vec![instantiation("clang-usr-v1:int", 0)],
        ),
        read_with_instantiations(
            "wide.cpp",
            Vec::new(),
            vec![integer("long")],
            vec![instantiation("clang-usr-v1:long", 0)],
        ),
        unanswerable(&sources[2]),
    ];

    read_by_other_units(&mut gathered, &sources);
    assert!(
        matches!(gathered[2], Gathered::Unavailable { .. }),
        "one translation unit's specialization was selected"
    );
}

/// Header calls are useful only when every translation unit reports the
/// same macro-aware anchor and exact target. A stable direct call survives;
/// overload and macro-definition disagreements are omitted instead of
/// selecting whichever translation unit happened to be first.
#[test]
fn header_calls_survive_only_exact_translation_unit_agreement() {
    let sources = [
        source("src/narrow.cpp", Language::Cpp, None),
        source("src/wide.cpp", Language::Cpp, None),
        header(),
    ];
    let stable = call(
        700,
        CallTarget::Static {
            symbol: "c:@F@stable#I#".into(),
        },
        None,
    );
    let selected = call(
        800,
        CallTarget::Static {
            symbol: "c:@F@choose#I#".into(),
        },
        None,
    );
    let expanded = call(
        900,
        CallTarget::Static {
            symbol: "c:@F@macro_call#I#".into(),
        },
        Some("include/first.hpp"),
    );
    let mut gathered = vec![
        read_with_calls("narrow.cpp", vec![stable.clone(), selected, expanded]),
        read_with_calls(
            "wide.cpp",
            vec![
                stable.clone(),
                call(
                    800,
                    CallTarget::Static {
                        symbol: "c:@F@choose#L#".into(),
                    },
                    None,
                ),
                call(
                    900,
                    CallTarget::Static {
                        symbol: "c:@F@macro_call#I#".into(),
                    },
                    Some("include/second.hpp"),
                ),
            ],
        ),
        unanswerable(&sources[2]),
    ];

    read_by_other_units(&mut gathered, &sources);
    let Gathered::Analyzed { ir, .. } = &gathered[2] else {
        panic!("the agreed call answers the header");
    };
    assert!(ir.symbols.is_empty());
    assert!(ir.instantiations.is_empty());
    assert_eq!(ir.calls, [stable]);
}

/// With no agreed call, choosing the first reading would turn a
/// build-dependent overload into a false static answer.
#[test]
fn a_header_with_only_disagreeing_calls_stays_unavailable() {
    let sources = [
        source("src/narrow.cpp", Language::Cpp, None),
        source("src/wide.cpp", Language::Cpp, None),
        header(),
    ];
    let mut gathered = vec![
        read_with_calls(
            "narrow.cpp",
            vec![call(
                800,
                CallTarget::Static {
                    symbol: "c:@F@choose#I#".into(),
                },
                None,
            )],
        ),
        read_with_calls(
            "wide.cpp",
            vec![call(
                800,
                CallTarget::Static {
                    symbol: "c:@F@choose#L#".into(),
                },
                None,
            )],
        ),
        unanswerable(&sources[2]),
    ];

    read_by_other_units(&mut gathered, &sources);
    assert!(
        matches!(gathered[2], Gathered::Unavailable { .. }),
        "one translation unit's call target was selected"
    );
}

/// A header can carry only a coverage fact. Retain it when every reader
/// agrees, so a failed direct query does not turn a known macro gap into a
/// claim that nothing was found.
#[test]
fn header_unexpanded_macros_survive_only_exact_agreement() {
    let sources = [
        source("src/narrow.cpp", Language::Cpp, None),
        source("src/wide.cpp", Language::Cpp, None),
        header(),
    ];
    let stable = unexpanded_macro(700, UnexpandedMacroReason::RequiresExecution);
    let mut gathered = vec![
        read_with_unexpanded_macros("narrow.cpp", vec![stable.clone()]),
        read_with_unexpanded_macros("wide.cpp", vec![stable.clone()]),
        unanswerable(&sources[2]),
    ];

    read_by_other_units(&mut gathered, &sources);
    let Gathered::Analyzed { ir, .. } = &gathered[2] else {
        panic!("the agreed coverage fact answers the header");
    };
    assert!(ir.symbols.is_empty());
    assert!(ir.instantiations.is_empty());
    assert!(ir.calls.is_empty());
    assert_eq!(
        ir.unexpanded_macros.as_slice(),
        std::slice::from_ref(&stable)
    );

    let mut disagreeing = vec![
        read_with_unexpanded_macros("narrow.cpp", vec![stable]),
        read_with_unexpanded_macros(
            "wide.cpp",
            vec![unexpanded_macro(700, UnexpandedMacroReason::Unresolved)],
        ),
        unanswerable(&sources[2]),
    ];
    read_by_other_units(&mut disagreeing, &sources);
    assert!(matches!(disagreeing[2], Gathered::Unavailable { .. }));
}

/// A file that is its own unit was answered about the program it actually
/// is. Replacing that with what some other unit saw of it would be a worse
/// answer arrived at indirectly.
#[test]
fn a_file_that_is_its_own_unit_keeps_the_answer_about_itself() {
    let sources = [
        source("src/narrow.cpp", Language::Cpp, None),
        source("src/wide.cpp", Language::Cpp, None),
    ];
    let mut gathered = vec![
        read(
            "narrow.cpp",
            vec![symbol("narrow_sum", "src/narrow.cpp", 80, 10, false)],
            Vec::new(),
        ),
        // A unity build: one unit includes the other's source outright.
        read(
            "wide.cpp",
            vec![symbol("narrow_sum", "src/narrow.cpp", 80, 10, true)],
            Vec::new(),
        ),
    ];
    read_by_other_units(&mut gathered, &sources);
    let Gathered::Analyzed { ir, .. } = &gathered[0] else {
        panic!("it was answered about itself");
    };
    assert!(!ir.symbols[0].external, "its own answer, not the other's");
}

/// A helper that never got as far as saying who it was leaves no row, and
/// the answers it did produce must not point at another helper's.
#[test]
fn an_answer_names_the_helper_that_produced_it_rather_than_a_position() {
    let row = [None, Some(0)];
    let unit = UnitRef {
        unit: "ledger".into(),
        file: "/repo/src/lib.rs".into(),
        variant: "host".into(),
    };
    let silent = Gathered::Unavailable {
        backend: 0,
        unit: unit.clone(),
        reason: Unavailability::HelperDied,
    }
    .pointing_at(&row);
    assert!(matches!(silent, Answer::Unavailable { helper: None, .. }));
    let answered = Gathered::Analyzed {
        backend: 1,
        ir: Box::new(CompilerIr::empty(unit)),
    }
    .pointing_at(&row);
    assert!(matches!(answered, Answer::Analyzed { helper: 0, .. }));
}
