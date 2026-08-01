use super::*;

/// The macro fixture is one crate whose file is its own root.
fn repeated() -> Box<CompilerIr> {
    let file = codehelion_fixtures::rust("macro-rules")
        .unwrap()
        .join("src/lib.rs");
    analyzed(&UnitRef {
        unit: "repeated".to_string(),
        file: file.display().to_string(),
        variant: "host".to_string(),
    })
}

/// A declarative macro is expanded by reading it, so what it declared is
/// there to be reported. Leaving it out would report a file as holding less
/// than it does.
#[test]
fn what_a_declarative_macro_declared_is_reported() {
    let ir = repeated();
    for produced in ["Reads", "Writes"] {
        // Exactly one declaration: a macro expansion can also contain an
        // ordinary type use with the same spelling, which is symbol evidence
        // rather than another declaration. The two-sided anchor is what
        // distinguishes the one this expansion declared.
        let found = names(&ir, produced)
            .into_iter()
            .filter(|symbol| symbol.kind == SymbolKind::Type && symbol.anchor.definition.is_some())
            .count();
        assert_eq!(
            found,
            1,
            "{produced}: {:?}",
            ir.symbols.iter().map(|s| &s.name).collect::<Vec<_>>()
        );
    }
}

/// The claim the whole two-part anchor exists for. Both types came out of one
/// macro, so they share a definition site and differ only in where they were
/// invoked — which is what lets a group say "written once, expanded twice"
/// instead of reporting a duplication nobody can remove.
#[test]
fn two_expansions_of_one_macro_share_the_place_it_was_written() {
    let ir = repeated();
    let reads = expanded_type(&ir, "Reads");
    let writes = expanded_type(&ir, "Writes");
    assert_eq!(
        reads.anchor.definition, writes.anchor.definition,
        "two expansions of one macro were attributed to two definitions"
    );
    assert_ne!(
        reads.anchor.expansion, writes.anchor.expansion,
        "two invocations were reported at one place"
    );
}

/// A call produced by a declarative macro is compiler-resolved from the
/// expanded syntax, but it remains attached to the invocation and macro
/// definition rather than claiming a source range that does not exist.
#[test]
fn a_call_from_a_macro_expression_keeps_the_two_sided_anchor() {
    let ir = repeated();
    let call = ir
        .calls
        .iter()
        .find(|call| {
            matches!(
                &call.target,
                CallTarget::Static { symbol } if symbol.ends_with("Reads::count")
            )
        })
        .expect("the call produced by the macro expression");
    let source = std::fs::read_to_string(
        codehelion_fixtures::rust("macro-rules")
            .unwrap()
            .join("src/lib.rs"),
    )
    .expect("the macro fixture source is readable");
    let start = usize::try_from(call.anchor.expansion.start_byte).unwrap();
    let end = usize::try_from(call.anchor.expansion.end_byte).unwrap();
    assert!(source[start..end].contains("count_from_expansion!(reads)"));
    let definition = call
        .anchor
        .definition
        .as_ref()
        .expect("a macro expression has a definition anchor");
    let start = usize::try_from(definition.start_byte).unwrap();
    let end = usize::try_from(definition.end_byte).unwrap();
    assert!(source[start..end].contains("macro_rules! count_from_expansion"));
    let expression = ir
        .expressions
        .iter()
        .find(|expression| expression.anchor == call.anchor)
        .expect("the macro expansion's expression type");
    assert_eq!(
        ir.types[usize::try_from(expression.type_index).unwrap()].category,
        TypeCategory::Integer
    );
}

/// And what somebody typed carries no second place, or the distinction the
/// definition site draws would be no distinction at all.
#[test]
fn what_was_typed_out_is_not_attributed_to_a_macro() {
    let ir = repeated();
    let manual = ir
        .symbols
        .iter()
        .find(|symbol| symbol.name == "Manual")
        .expect("the hand-written type");
    assert_eq!(manual.anchor.definition, None);
}

/// A procedural macro is not silently treated as a macro that produced no
/// declarations. The helper never runs it by default, but the surrounding
/// crate remains useful enough to analyse, so this is per-invocation coverage
/// rather than a unit-level refusal.
#[test]
fn a_proc_macro_invocation_is_recorded_as_unexpanded() {
    let ir = analyzed(&unit("proc-macro", "catalogue", "catalogue"));
    let skipped = ir
        .unexpanded_macros
        .iter()
        .filter(|macro_| macro_.reason == UnexpandedMacroReason::Unresolved)
        .collect::<Vec<_>>();
    assert_eq!(skipped.len(), 2, "{:#?}", ir.unexpanded_macros);
    let source = std::fs::read_to_string(
        codehelion_fixtures::rust("proc-macro")
            .unwrap()
            .join("catalogue/src/lib.rs"),
    )
    .expect("the proc-macro fixture source is readable");
    for macro_ in skipped {
        let start = usize::try_from(macro_.invocation.start_byte).unwrap();
        let end = usize::try_from(macro_.invocation.end_byte).unwrap();
        assert!(source[start..end].contains("derive(Labelled)"));
    }
}

/// An expansion anchors at the invocation, because that is the only place in
/// the file it can be pointed at: the text of the produced item is not there.
#[test]
fn an_expansion_anchors_on_the_invocation_that_produced_it() {
    let path = codehelion_fixtures::rust("macro-rules")
        .unwrap()
        .join("src/lib.rs");
    let text = std::fs::read_to_string(path).expect("the fixture is readable");
    let ir = repeated();
    let reads = expanded_type(&ir, "Reads");
    let range = &reads.anchor.expansion;
    let start = usize::try_from(range.start_byte).unwrap();
    let end = usize::try_from(range.end_byte).unwrap();
    assert_eq!(&text[start..end], "counter!(Reads);");
    // And the definition site is the macro, which is somewhere else entirely.
    // It spans the item as written, doc comment included, the same way every
    // other declaration's anchor does.
    let written = reads.anchor.definition.as_ref().expect("a definition site");
    let start = usize::try_from(written.start_byte).unwrap();
    let end = usize::try_from(written.end_byte).unwrap();
    let source = &text[start..end];
    assert!(source.contains("macro_rules! counter"), "{source:?}");
    assert!(end <= usize::try_from(range.start_byte).unwrap());
}

fn expanded_type<'a>(ir: &'a CompilerIr, name: &str) -> &'a ResolvedSymbol {
    ir.symbols
        .iter()
        .find(|symbol| symbol.name == name && symbol.kind == SymbolKind::Type)
        .unwrap_or_else(|| panic!("no type called {name}"))
}
