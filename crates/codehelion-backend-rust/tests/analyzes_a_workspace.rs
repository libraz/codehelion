//! What this helper reports about projects whose answer is known by reading
//! them.
//!
//! Driven through the real client against the real program, because everything
//! worth checking here is a claim about two processes: that the handshake
//! agrees, that a unit comes back with types a person can verify by looking at
//! the fixture, that a crate needing a build script is declined rather than
//! half-answered, and that declining it leaves no trace of having run it.
//!
//! `CARGO_BIN_EXE_` rather than a constructed path: a test that guesses where a
//! binary lands can run a stale copy and report success.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::time::Duration;

use codehelion_helper::ir::{
    CallTarget, DirectPropagation, FallibleKind, Instantiation, ResolvedSymbol,
    SemanticConstructKind, SymbolKind, TypeCategory, Unavailability, UnexpandedMacroReason,
    UnitRef,
};
use codehelion_helper::protocol::{Capability, Execution};
use codehelion_helper::{Analysis, COMPILER_IR_SCHEMA_VERSION, CompilerIr, Helper};

/// Loading a workspace reads its sysroot and its metadata, which on a cold
/// machine is slower than the protocol's default.
const PATIENT: Duration = Duration::from_mins(5);

fn helper() -> Helper {
    Helper::start(
        std::path::Path::new(env!("CARGO_BIN_EXE_codehelion-backend-rust")),
        PATIENT,
    )
    .expect("the helper should start and shake hands")
}

fn unit(fixture: &str, member: &str, crate_name: &str) -> UnitRef {
    let file = codehelion_fixtures::rust(fixture)
        .unwrap()
        .join(member)
        .join("src/lib.rs");
    UnitRef {
        unit: crate_name.to_string(),
        file: file.display().to_string(),
        variant: "host".to_string(),
    }
}

fn analyze(unit: &UnitRef) -> Analysis {
    let mut helper = helper();
    let analysis = helper
        .analyze(unit, &[Capability::Types])
        .expect("the helper should answer");
    helper.shutdown().expect("the helper should stop cleanly");
    analysis
}

fn analyzed(unit: &UnitRef) -> Box<CompilerIr> {
    match analyze(unit) {
        Analysis::Done(ir) => ir,
        Analysis::Missing(reason) => panic!("expected an analysis, got {reason:?}"),
    }
}

fn category_of(ir: &CompilerIr, name: &str) -> TypeCategory {
    let symbol = ir
        .symbols
        .iter()
        .find(|symbol| symbol.name == name)
        .unwrap_or_else(|| {
            panic!(
                "no symbol called {name}; the unit holds {:?}",
                ir.symbols.iter().map(|s| &s.name).collect::<Vec<_>>()
            )
        });
    let index = symbol
        .type_index
        .unwrap_or_else(|| panic!("{name} has no resolved type")) as usize;
    ir.types[index].category
}

/// Every name written in `file`, in the order they were written.
fn names<'a>(ir: &'a CompilerIr, name: &str) -> Vec<&'a ResolvedSymbol> {
    ir.symbols
        .iter()
        .filter(|symbol| symbol.name == name)
        .collect()
}

/// The handshake is where a helper says what it is. Claiming a capability it
/// does not have would be worse than claiming none: a run stops recording that
/// it did not get something once it has been told it would.
#[test]
fn the_helper_says_which_compiler_will_answer_and_what_it_can_supply() {
    let helper = helper();
    assert!(helper.offers(Capability::Types));
    assert!(helper.offers(Capability::NameResolution));
    assert!(helper.offers(Capability::CallTargets));
    assert!(helper.offers(Capability::MacroExpansion));
    assert!(helper.offers(Capability::TemplateInstantiation));
    assert!(!helper.offers(Capability::MirCfg));
    helper.shutdown().unwrap();
}

/// What normalization is for. A name defined outside the scan is an interface
/// two fragments genuinely share and is compared on; a name defined inside it
/// is a detail one of them happens to have chosen, and is not.
#[test]
fn a_name_the_project_did_not_write_is_marked_as_coming_from_outside() {
    let ir = analyzed(&unit("plain", "ledger", "ledger"));
    for outside in ["String", "Vec", "i64"] {
        let found = names(&ir, outside);
        assert!(!found.is_empty(), "{outside} was never resolved");
        for symbol in found {
            assert!(symbol.external, "{outside} was called part of the scan");
        }
    }
    for inside in ["Entry", "debits", "total", "entries"] {
        let found = names(&ir, inside);
        assert!(!found.is_empty(), "{inside} was never resolved");
        for symbol in found {
            assert!(!symbol.external, "{inside} was called a library name");
        }
    }
}

/// The offsets are the whole mechanism: normalization looks a name up by the
/// byte it starts at, so an anchor pointing anywhere near the name rather than
/// at it resolves a different name, or none, without saying so.
#[test]
fn a_name_is_anchored_on_the_name_rather_than_near_it() {
    let source = codehelion_fixtures::rust("plain")
        .unwrap()
        .join("ledger/src/lib.rs");
    let text = std::fs::read_to_string(source).expect("the fixture is readable");
    let ir = analyzed(&unit("plain", "ledger", "ledger"));
    // Bindings only, because a declaration's anchor spans the whole item it
    // declares. A binding is only ever reported as an occurrence.
    let bindings: Vec<_> = ir
        .symbols
        .iter()
        .filter(|symbol| symbol.kind == SymbolKind::Binding)
        .collect();
    assert!(!bindings.is_empty(), "no binding was resolved at all");
    for symbol in bindings {
        let range = &symbol.anchor.expansion;
        let start = usize::try_from(range.start_byte).unwrap();
        let end = usize::try_from(range.end_byte).unwrap();
        assert_eq!(&text[start..end], symbol.name);
    }
}

/// `total` is written in both `debits` and `credits`, and they are two
/// bindings. An identity two definitions share is not an identity, and here it
/// would make the two functions look like they touch one variable.
#[test]
fn two_bindings_that_share_a_name_do_not_share_an_identity() {
    let ir = analyzed(&unit("plain", "ledger", "ledger"));
    let totals = names(&ir, "total");
    assert!(totals.len() >= 4, "expected several mentions of total");
    let identities: std::collections::BTreeSet<&str> =
        totals.iter().map(|symbol| symbol.id.as_str()).collect();
    assert_eq!(identities.len(), 2, "{identities:?}");
}

/// A local's type is the one nothing else records and the one a structural
/// reading cannot see: `total` is only ever written as `0`.
#[test]
fn a_binding_carries_the_type_the_compiler_inferred_for_it() {
    let ir = analyzed(&unit("plain", "ledger", "ledger"));
    assert_eq!(category_of(&ir, "total"), TypeCategory::Integer);
}

/// The dispatch fixture is one crate whose file is its own root.
fn dispatch() -> Box<CompilerIr> {
    let file = codehelion_fixtures::rust("dispatch")
        .unwrap()
        .join("src/lib.rs");
    analyzed(&UnitRef {
        unit: "dispatch".to_string(),
        file: file.display().to_string(),
        variant: "host".to_string(),
    })
}

/// What a call written inside `enclosing` was found to reach.
fn targets(ir: &CompilerIr, source: &str, enclosing: &str) -> Vec<CallTarget> {
    let body = body_of(source, enclosing);
    ir.calls
        .iter()
        .filter(|call| {
            let range = &call.anchor.expansion;
            body.contains(&usize::try_from(range.start_byte).unwrap())
        })
        .map(|call| call.target.clone())
        .collect()
}

/// The byte range of one function's body, found by reading the fixture the
/// same way a person would.
fn body_of(source: &str, enclosing: &str) -> std::ops::Range<usize> {
    let start = source
        .find(enclosing)
        .unwrap_or_else(|| panic!("the fixture no longer contains {enclosing}"));
    let open = start + source[start..].find('{').expect("a body");
    let mut depth = 0_i32;
    for (offset, character) in source[open..].char_indices() {
        match character {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return open..open + offset;
                }
            }
            _ => {}
        }
    }
    panic!("{enclosing} has no closing brace");
}

fn fixture_source() -> String {
    source_of("dispatch")
}

/// The text of a single-crate fixture, read the way a person checking the
/// answer by eye would read it.
fn source_of(fixture: &str) -> String {
    let path = codehelion_fixtures::rust(fixture)
        .unwrap()
        .join("src/lib.rs");
    std::fs::read_to_string(path).expect("the fixture is readable")
}

/// A concrete receiver settles which body runs, and it settles it even when
/// the body was written on the trait: nothing overrides `doubled`, so the
/// trait's own body is the one that runs. Calling that dynamic would say the
/// compiler knew less than it did.
#[test]
fn a_concrete_receiver_reaches_one_body_wherever_that_body_was_written() {
    let ir = dispatch();
    let found = targets(&ir, &fixture_source(), "pub fn concrete");
    assert_eq!(found.len(), 2, "{found:?}");
    for target in &found {
        assert!(
            matches!(target, CallTarget::Static { .. }),
            "a concrete receiver was reported as undecided: {target:?}"
        );
    }
    let symbols: Vec<&str> = found
        .iter()
        .filter_map(|target| match target {
            CallTarget::Static { symbol } => Some(symbol.as_str()),
            _ => None,
        })
        .collect();
    assert!(
        symbols.iter().any(|symbol| symbol.contains("Segment")),
        "{symbols:?}"
    );
    assert!(
        symbols.iter().any(|symbol| symbol.contains("doubled")),
        "{symbols:?}"
    );
}

/// A type parameter does not settle it. Which body runs is decided where the
/// function is instantiated, and the honest answer is the set the scan can
/// see — here, the two implementations written beside it.
#[test]
fn a_type_parameter_receiver_is_one_of_the_implementations_in_the_scan() {
    let ir = dispatch();
    let found = targets(&ir, &fixture_source(), "pub fn generic");
    assert_eq!(found.len(), 1, "{found:?}");
    match &found[0] {
        CallTarget::Dynamic { candidates } => {
            assert_eq!(candidates.len(), 2, "{candidates:?}");
            assert!(candidates.iter().any(|c| c.contains("Segment")));
            assert!(candidates.iter().any(|c| c.contains("Tally")));
        }
        other => panic!("a generic receiver was reported as settled: {other:?}"),
    }
}

/// And a trait object does not settle it either, for a different reason: the
/// choice is made while the program runs rather than while it is compiled.
/// The evidence is the same set, which is the point of keeping the set.
#[test]
fn a_trait_object_receiver_is_the_same_set_as_a_type_parameter() {
    let ir = dispatch();
    let source = fixture_source();
    let erased = targets(&ir, &source, "pub fn erased");
    let generic = targets(&ir, &source, "pub fn generic");
    assert_eq!(erased, generic, "{erased:?} against {generic:?}");
}

/// Calling a value has no definition to point at, and saying so is the
/// answer. A call reported as reaching something it does not would be worse
/// than one reported as unknown.
#[test]
fn calling_a_value_rather_than_a_name_reaches_nothing_nameable() {
    let ir = dispatch();
    let found = targets(&ir, &fixture_source(), "pub fn indirect");
    assert_eq!(found, vec![CallTarget::Unresolved], "{found:?}");
}

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

/// The baseline. Every category asserted here can be checked by opening the
/// fixture: `amount` is an `i64`, `label` is a `String`, and `labels` returns a
/// `Vec<String>`.
#[test]
fn a_plain_workspace_comes_back_with_types_a_reader_can_check() {
    let ir = analyzed(&unit("plain", "ledger", "ledger"));
    assert_eq!(ir.schema_version, COMPILER_IR_SCHEMA_VERSION);
    assert_eq!(category_of(&ir, "amount"), TypeCategory::Integer);
    // A struct in the standard library, reported by its shape rather than as
    // the record it technically is: the category exists so that this and a C++
    // `std::string` are the same answer.
    assert_eq!(category_of(&ir, "label"), TypeCategory::Text);
    assert_eq!(category_of(&ir, "labels"), TypeCategory::Sequence);
    assert_eq!(category_of(&ir, "debits"), TypeCategory::Integer);
}

/// Closed standard API evidence is separate from the stable definition
/// identity, so a later cross-language rule never recovers meaning from an
/// arbitrary workspace method name.
#[test]
fn standard_iterator_calls_carry_closed_api_names() {
    let ir = analyzed(&unit("plain", "ledger", "ledger"));
    let names = ir
        .calls
        .iter()
        .filter_map(|call| call.api_name.as_deref())
        .collect::<Vec<_>>();
    assert!(names.contains(&"rust::Iterator::map"), "{names:?}");
    assert!(names.contains(&"rust::Iterator::collect"), "{names:?}");
    assert!(names.contains(&"rust::slice::iter"), "{names:?}");
}

/// Anchors have to point at the fixture's own text, since a fragment is cut
/// from a file and a finding anchored anywhere else is unusable.
#[test]
fn every_symbol_is_anchored_where_it_was_written() {
    let ir = analyzed(&unit("plain", "ledger", "ledger"));
    assert!(!ir.symbols.is_empty());
    for symbol in &ir.symbols {
        let anchor = &symbol.anchor.expansion;
        assert_eq!(anchor.file, "ledger/src/lib.rs", "{}", symbol.name);
        assert!(anchor.end_byte > anchor.start_byte, "{}", symbol.name);
        assert!(anchor.start_line >= 1, "{}", symbol.name);
        // Written where it stands: nothing here comes from a macro, and
        // claiming otherwise would put a definition nobody wrote at a place
        // somebody did.
        assert_eq!(symbol.anchor.definition, None, "{}", symbol.name);
    }
}

/// A crate whose types only exist after a build script has run cannot be
/// analysed without running it. Answering with whatever happens to resolve
/// would report a partial reading as a complete one.
#[test]
fn a_crate_that_needs_its_build_script_is_declined_by_name() {
    let file = codehelion_fixtures::rust("build-script")
        .unwrap()
        .join("src/lib.rs");
    let unit = UnitRef {
        unit: "generated-tables".to_string(),
        file: file.display().to_string(),
        variant: "host".to_string(),
    };
    match analyze(&unit) {
        Analysis::Missing(reason) => assert_eq!(reason, Unavailability::RequiresExecution),
        Analysis::Done(ir) => panic!("analysed a crate it could not have read: {ir:?}"),
    }
}

/// And declining it has to leave no trace of having run it. The two are not the
/// same claim: a helper that ran the build script and then reported
/// `RequiresExecution` would pass the test above.
#[test]
fn declining_a_build_script_does_not_run_it() {
    let marker = codehelion_fixtures::execution_marker("build-script").unwrap();
    assert!(
        !marker.exists(),
        "{} existed before the helper was asked anything",
        marker.display()
    );
    let file = codehelion_fixtures::rust("build-script")
        .unwrap()
        .join("src/lib.rs");
    let _ = analyze(&UnitRef {
        unit: "generated-tables".to_string(),
        file: file.display().to_string(),
        variant: "host".to_string(),
    });
    assert!(
        !marker.exists(),
        "{} appeared: the helper ran the fixture's build script",
        marker.display()
    );
}

/// The other half of refusing: permitted, the crate is analysed rather than
/// declined, and the script that was declined before has now run.
///
/// Against a copy, not the fixture. The fixture's marker is the evidence that
/// nothing in this checkout ran its build script, and a test that ran it in
/// place would spend that evidence to prove one thing about permission.
#[test]
fn permitting_a_build_script_runs_it_and_analyses_what_it_wrote() {
    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path().join("build-script");
    copy_fixture(&codehelion_fixtures::rust("build-script").unwrap(), &root);
    let marker = root.join(codehelion_fixtures::EXECUTION_MARKER);
    assert!(!marker.exists(), "the copy starts as the fixture does");

    let unit = UnitRef {
        // The crate, not the package: cargo's `generated-tables` is compiled
        // as `generated_tables`, and a unit is named by what the compiler
        // calls it.
        unit: "generated_tables".to_string(),
        file: root.join("src/lib.rs").display().to_string(),
        variant: "host".to_string(),
    };
    let mut helper = helper().permitting(vec![Execution::BuildScript]);
    let analysis = helper
        .analyze(&unit, &[Capability::Types])
        .expect("the helper should answer");
    helper.shutdown().expect("the helper should stop cleanly");

    assert!(
        matches!(analysis, Analysis::Done(_)),
        "permitted, the crate is read rather than declined: {analysis:?}"
    );
    assert!(
        marker.exists(),
        "{} is missing: nothing ran, so permitting it bought nothing",
        marker.display()
    );
}

/// Copy a fixture's own files, and only those: a `target` directory left by an
/// earlier run would be carried into a tree whose whole point is that nothing
/// has been built in it yet.
fn copy_fixture(from: &std::path::Path, to: &std::path::Path) {
    std::fs::create_dir_all(to).expect("create the copy");
    for entry in std::fs::read_dir(from).expect("read the fixture") {
        let entry = entry.expect("read an entry");
        let name = entry.file_name();
        if name == "target" {
            continue;
        }
        let source = entry.path();
        let destination = to.join(&name);
        if source.is_dir() {
            copy_fixture(&source, &destination);
        } else {
            std::fs::copy(&source, &destination).expect("copy a file");
        }
    }
}

/// One process, asked twice, must not answer differently the second time. The
/// workspace is cached between requests, and a cache that changed an answer
/// would be a cache that made results depend on what was asked before.
#[test]
fn asking_twice_in_one_process_gives_the_same_answer() {
    let target = unit("plain", "ledger", "ledger");
    let mut helper = helper();
    let first = helper.analyze(&target, &[Capability::Types]).unwrap();
    let second = helper.analyze(&target, &[Capability::Types]).unwrap();
    helper.shutdown().unwrap();
    assert_eq!(first, second);
}

/// What a run files its answers under, asked of the side that resolves it.
///
/// Both halves matter. The features name the package that enables them,
/// because two packages' features of one name are unrelated; the settings are
/// the compiler's own, so that the same source read for two targets is two
/// readings rather than one.
#[test]
fn a_project_says_which_features_it_is_read_with() {
    let described = describe(&codehelion_fixtures::rust("features").unwrap());
    assert_eq!(described.features, vec!["counters/default".to_string()]);
    assert!(
        described
            .cfgs
            .iter()
            .any(|cfg| cfg.starts_with("target_os")),
        "the compiler's own settings should be there: {:?}",
        described.cfgs
    );
}

/// A member can change a direct dependency's features without moving the
/// lockfile. Those flags alter the resolved program, so describing only the
/// member's own feature set would let two different readings share a variant.
#[test]
fn a_direct_dependency_feature_is_part_of_the_build_description() {
    let directory = tempfile::tempdir().expect("temporary workspace");
    let root = directory.path();
    std::fs::create_dir_all(root.join("app/src")).expect("create app source");
    std::fs::create_dir_all(root.join("support/src")).expect("create dependency source");
    std::fs::write(
        root.join("Cargo.toml"),
        "[workspace]\nmembers = [\"app\", \"support\"]\nresolver = \"2\"\n",
    )
    .expect("write workspace manifest");
    let app_manifest = |features: &str| {
        format!(
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2024\"\npublish = false\n\n\
             [dependencies]\nsupport = {{ path = \"../support\"{features} }}\n"
        )
    };
    std::fs::write(root.join("app/Cargo.toml"), app_manifest(""))
        .expect("write app manifest without the dependency feature");
    std::fs::write(
        root.join("app/src/lib.rs"),
        "pub fn answer() -> u8 { 42 }\n",
    )
    .expect("write app source");
    std::fs::write(
        root.join("support/Cargo.toml"),
        "[package]\nname = \"support\"\nversion = \"0.1.0\"\nedition = \"2024\"\npublish = false\n\n\
         [features]\ndefault = [\"wide\"]\nwide = []\nextra = []\n",
    )
    .expect("write dependency manifest");
    std::fs::write(root.join("support/src/lib.rs"), "pub struct Support;\n")
        .expect("write dependency source");

    let without_extra = describe(root);
    assert!(
        !without_extra
            .features
            .iter()
            .any(|feature| feature == "support/extra"),
        "{without_extra:?}"
    );

    std::fs::write(
        root.join("app/Cargo.toml"),
        app_manifest(", features = [\"extra\"]"),
    )
    .expect("enable dependency feature");
    let with_extra = describe(root);
    assert!(
        with_extra
            .features
            .iter()
            .any(|feature| feature == "support/extra"),
        "{with_extra:?}"
    );
}

/// A tree with no project in it is described as having no build, which is not
/// the same as failing to describe it: every run over such a tree reads it the
/// same way, so an empty answer is the answer.
#[test]
fn a_tree_with_no_project_in_it_is_described_as_having_no_build() {
    let described = describe(std::path::Path::new("/nowhere/at/all"));
    assert_eq!(described, codehelion_helper::BuildDescription::default());
}

/// A described build always has settings — the target alone supplies dozens —
/// so the empty description above says what it says without a flag for it.
#[test]
fn a_project_that_enables_nothing_is_still_described_by_its_target() {
    let described = describe(&codehelion_fixtures::rust("plain").unwrap());
    assert!(described.features.is_empty(), "{:?}", described.features);
    assert!(!described.cfgs.is_empty());
}

fn describe(root: &std::path::Path) -> codehelion_helper::BuildDescription {
    let mut helper = helper();
    let described = helper.describe(root).expect("the helper should answer");
    helper.shutdown().expect("the helper should stop cleanly");
    described
}

/// A unit nobody can place is refused rather than guessed at.
#[test]
fn a_unit_outside_any_project_is_reported_as_having_no_build_information() {
    let unit = UnitRef {
        unit: "nothing".to_string(),
        file: "/nowhere/at/all/src/lib.rs".to_string(),
        variant: "host".to_string(),
    };
    match analyze(&unit) {
        Analysis::Missing(reason) => assert_eq!(reason, Unavailability::NoBuildInformation),
        Analysis::Done(ir) => panic!("analysed a project that is not there: {ir:?}"),
    }
}

fn stamped() -> Box<CompilerIr> {
    let file = codehelion_fixtures::rust("generic")
        .unwrap()
        .join("src/lib.rs");
    analyzed(&UnitRef {
        unit: "stamped".to_string(),
        file: file.display().to_string(),
        variant: "host".to_string(),
    })
}

/// The helper reports Rust `?` as a compiler-parsed, closed construct rather
/// than asking the semantic core to infer it from a token sequence.
#[test]
fn an_error_propagation_operator_is_reported_as_a_semantic_construct() {
    let ir = stamped();
    let source = source_of("generic");
    let constructs = ir
        .semantic_constructs
        .iter()
        .filter(|construct| construct.kind == SemanticConstructKind::PropagateError)
        .collect::<Vec<_>>();
    assert_eq!(constructs.len(), 4, "{:?}", ir.semantic_constructs);
    let try_expression_count = constructs
        .iter()
        .filter(|construct| {
            let range = &construct.anchor.expansion;
            let start = usize::try_from(range.start_byte).expect("range start fits");
            let end = usize::try_from(range.end_byte).expect("range end fits");
            source[start..end].ends_with('?')
        })
        .count();
    assert_eq!(try_expression_count, 3, "{:?}", ir.semantic_constructs);
    assert_eq!(constructs[0].fallible_kind, Some(FallibleKind::Option));
}

/// Standard `Result` and `Option` matches, plus direct standard presence
/// conditions, become closed validation constructs. A project enum's branches
/// and compound presence conditions remain outside the vocabulary.
#[test]
fn standard_fallible_matches_are_reported_as_validation_constructs() {
    let ir = stamped();
    let source = source_of("generic");
    let validates = ir
        .semantic_constructs
        .iter()
        .filter(|construct| construct.kind == SemanticConstructKind::Validate)
        .collect::<Vec<_>>();
    assert_eq!(validates.len(), 3, "{:?}", ir.semantic_constructs);
    let spellings = validates
        .iter()
        .map(|construct| {
            let range = &construct.anchor.expansion;
            let start = usize::try_from(range.start_byte).expect("range start fits");
            let end = usize::try_from(range.end_byte).expect("range end fits");
            source[start..end].to_string()
        })
        .collect::<Vec<_>>();
    assert!(
        spellings
            .iter()
            .any(|spelling| spelling.starts_with("match "))
    );
    assert!(
        spellings
            .iter()
            .any(|spelling| spelling.starts_with("if value.is_some()"))
    );
    assert!(
        spellings
            .iter()
            .any(|spelling| spelling.starts_with("if value.is_ok()"))
    );
    assert!(
        spellings
            .iter()
            .all(|spelling| !spelling.contains("&& keep"))
    );
    let kinds = validates
        .iter()
        .map(|construct| construct.fallible_kind)
        .collect::<Vec<_>>();
    assert_eq!(
        kinds,
        vec![
            Some(FallibleKind::Option),
            Some(FallibleKind::Option),
            Some(FallibleKind::Result),
        ]
    );
}

/// Direct `Result` propagation has two deliberately closed spellings. A
/// transformed success value is retained as a normal propagation operation.
#[test]
fn direct_result_propagation_forms_are_reported_without_admitting_transformations() {
    let ir = stamped();
    let source = source_of("generic");
    let direct = ir
        .semantic_constructs
        .iter()
        .filter(|construct| construct.direct_propagation == Some(DirectPropagation::ResultAdapter))
        .collect::<Vec<_>>();
    assert_eq!(direct.len(), 2, "{:?}", ir.semantic_constructs);
    assert!(direct.iter().all(|construct| {
        construct.kind == SemanticConstructKind::PropagateError
            && construct.fallible_kind == Some(FallibleKind::Result)
    }));
    let transformed = ir.semantic_constructs.iter().find(|construct| {
        let range = &construct.anchor.expansion;
        let start = usize::try_from(range.start_byte).expect("range start fits");
        let end = usize::try_from(range.end_byte).expect("range end fits");
        &source[start..end] == "value?"
            && construct.fallible_kind == Some(FallibleKind::Result)
            && construct.direct_propagation.is_none()
    });
    assert!(transformed.is_some(), "{:?}", ir.semantic_constructs);
}

/// A `for` loop only enters the closed vocabulary when it is a compiler-typed
/// standard-sequence to standard-`Vec` transfer of the exact loop binding.
#[test]
fn a_plain_vec_collection_loop_is_reported_without_guessing_transforms() {
    let ir = stamped();
    let source = source_of("generic");
    let loop_constructs = ir
        .semantic_constructs
        .iter()
        .filter(|construct| {
            matches!(
                construct.kind,
                SemanticConstructKind::Source | SemanticConstructKind::Collect
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(loop_constructs.len(), 3, "{:?}", ir.semantic_constructs);
    assert_eq!(loop_constructs[1].kind, SemanticConstructKind::Source);
    assert_eq!(loop_constructs[2].kind, SemanticConstructKind::Collect);
    let source_start =
        usize::try_from(loop_constructs[1].anchor.expansion.start_byte).expect("source start fits");
    let source_end =
        usize::try_from(loop_constructs[1].anchor.expansion.end_byte).expect("source end fits");
    assert_eq!(&source[source_start..source_end], "values");
    let collect_start = usize::try_from(loop_constructs[2].anchor.expansion.start_byte)
        .expect("collect start fits");
    let collect_end =
        usize::try_from(loop_constructs[2].anchor.expansion.end_byte).expect("collect end fits");
    assert_eq!(&source[collect_start..collect_end], "push");
}

/// A direct numeric accumulation is the closed loop counterpart of an
/// iterator reduction. The conditional loop in the same fixture remains
/// outside this form: a guard changes which values reach the accumulator.
#[test]
fn a_plain_numeric_reduce_loop_is_reported_without_admitting_guards() {
    let ir = stamped();
    let source = source_of("generic");
    let reductions = ir
        .semantic_constructs
        .iter()
        .filter(|construct| construct.kind == SemanticConstructKind::Reduce)
        .collect::<Vec<_>>();
    assert_eq!(reductions.len(), 1, "{:?}", ir.semantic_constructs);
    let source_construct = ir
        .semantic_constructs
        .iter()
        .find(|construct| {
            construct.kind == SemanticConstructKind::Source
                && construct.anchor.expansion.start_line
                    == reductions[0].anchor.expansion.start_line.saturating_sub(1)
        })
        .expect("the reduction retains its immediately preceding sequence source");
    let source_start =
        usize::try_from(source_construct.anchor.expansion.start_byte).expect("source start fits");
    let source_end =
        usize::try_from(source_construct.anchor.expansion.end_byte).expect("source end fits");
    assert_eq!(&source[source_start..source_end], "values");
    let reduce_start =
        usize::try_from(reductions[0].anchor.expansion.start_byte).expect("reduce start fits");
    let reduce_end =
        usize::try_from(reductions[0].anchor.expansion.end_byte).expect("reduce end fits");
    assert_eq!(&source[reduce_start..reduce_end], "sum += *value");
}

/// A direct standard-file binding has one compiler-resolved acquisition and a
/// Rust scope-end `Drop`. A function holding two files remains absent rather
/// than being reduced to a guessed pair.
#[test]
fn a_direct_standard_file_acquisition_is_paired_with_its_scope_drop() {
    let ir = analyzed(&unit("plain", "ledger", "ledger"));
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
    assert_eq!(lifetimes.len(), 2, "{:?}", ir.semantic_constructs);
    assert_eq!(lifetimes[0].kind, SemanticConstructKind::AcquireResource);
    assert_eq!(lifetimes[1].kind, SemanticConstructKind::ReleaseResource);
    assert!(
        lifetimes
            .iter()
            .all(|construct| construct.resource_kind.as_deref() == Some("file"))
    );
    assert!(lifetimes[0].anchor.expansion.start_byte < lifetimes[1].anchor.expansion.start_byte);
    let source = std::fs::read_to_string(
        codehelion_fixtures::rust("plain")
            .expect("plain fixture exists")
            .join("ledger/src/lib.rs"),
    )
    .expect("plain fixture source is readable");
    let two_files = source
        .find("pub fn inspect_two_files")
        .expect("fixture holds the multi-resource negative case");
    assert!(lifetimes.iter().all(|construct| {
        usize::try_from(construct.anchor.expansion.start_byte).is_ok_and(|start| start < two_files)
    }));
}

/// Every instantiation of one definition, in the order they were written.
fn stamps<'a>(ir: &'a CompilerIr, definition: &str) -> Vec<&'a Instantiation> {
    ir.instantiations
        .iter()
        .filter(|instantiation| instantiation.definition == definition)
        .collect()
}

/// The whole point of recording an instantiation: two calls that produce two
/// copies of a body have to say which one body they came from, or they read as
/// two bodies that happen to agree.
#[test]
fn two_uses_of_one_generic_name_the_body_they_share() {
    let ir = stamped();
    let found = stamps(&ir, "stamped::widest");
    assert_eq!(found.len(), 2, "{:?}", ir.instantiations);
    let source = source_of("generic");
    let written = found[0]
        .anchor
        .definition
        .as_ref()
        .expect("an instantiation names where its body was written");
    assert_eq!(
        found[1].anchor.definition.as_ref(),
        Some(written),
        "the two stamps disagree about where the one body is"
    );
    let start = usize::try_from(written.start_byte).unwrap();
    let end = usize::try_from(written.end_byte).unwrap();
    assert!(
        source[start..end].contains("pub fn widest<T: Ord + Copy>"),
        "the definition range is not the generic: {:?}",
        &source[start..end]
    );
    // And each is anchored on the use, which is the only place in this file
    // either of them can be pointed at.
    for stamp in found {
        let at = usize::try_from(stamp.anchor.expansion.start_byte).unwrap();
        let to = usize::try_from(stamp.anchor.expansion.end_byte).unwrap();
        assert_eq!(&source[at..to], "widest");
    }
}

/// The other half of the same answer. One definition is what there is to fix;
/// the number of families is how many copies of it a build carries, and those
/// are different questions with different answers.
#[test]
fn substituting_a_different_type_is_a_different_family() {
    let ir = stamped();
    let mut keys: Vec<&str> = stamps(&ir, "stamped::widest")
        .iter()
        .map(|stamp| stamp.instantiation_key.as_str())
        .collect();
    keys.sort_unstable();
    assert_eq!(keys, ["stamped::widest<i64>", "stamped::widest<u32>"]);
}

/// A type is stamped out the same way a function is, and it is stamped out
/// wherever it is named — in a signature as much as in a body. A reading that
/// only looked inside bodies would report nothing at all about a project that
/// passes its generic types through signatures.
#[test]
fn a_generic_type_is_stamped_out_wherever_it_is_named() {
    let ir = stamped();
    let found = stamps(&ir, "stamped::Pair");
    assert_eq!(found.len(), 2, "{:?}", ir.instantiations);
    assert!(
        found
            .iter()
            .all(|stamp| stamp.instantiation_key == "stamped::Pair<i64>"),
        "one type at one argument is one family: {found:?}"
    );
    let source = source_of("generic");
    let signature = source.find("-> Pair<i64>").expect("the signature") + "-> ".len();
    let literal = source.find("Pair { left").expect("the literal");
    let places: Vec<usize> = found
        .iter()
        .map(|stamp| usize::try_from(stamp.anchor.expansion.start_byte).unwrap())
        .collect();
    assert_eq!(
        places,
        [signature, literal],
        "the two stamps are not the signature and the literal"
    );
}

/// The substituted types are recorded as the shapes the unit compares on
/// rather than as their spellings, which is why the key carries the spelling.
#[test]
fn what_was_substituted_is_recorded_as_a_shape() {
    let ir = stamped();
    let stamp = stamps(&ir, "stamped::widest")
        .into_iter()
        .find(|stamp| stamp.instantiation_key == "stamped::widest<i64>")
        .expect("the i64 stamp");
    assert_eq!(stamp.arguments.len(), 1);
    let argument = usize::try_from(stamp.arguments[0]).unwrap();
    assert_eq!(ir.types[argument].category, TypeCategory::Integer);
}

/// Reading `values.first()` instantiates a standard-library generic, and so
/// does nearly every line of nearly every crate. None of it is repetition
/// anybody scanning this project can act on, and counting it would make the
/// family index a reading of the dependency tree.
#[test]
fn a_body_the_project_did_not_write_is_not_counted_as_repetition() {
    let ir = stamped();
    assert!(!ir.instantiations.is_empty());
    for stamp in &ir.instantiations {
        assert!(
            stamp.definition.starts_with("stamped::"),
            "{} came from outside the scan",
            stamp.definition
        );
    }
}

/// The control. Nothing about a function that is not generic gets stamped out,
/// so an analysis that reports one here is reporting one for every call in
/// every crate.
#[test]
fn a_body_that_is_not_generic_stamps_out_nothing() {
    let ir = stamped();
    let body = body_of(&source_of("generic"), "pub fn total");
    let inside: Vec<&Instantiation> = ir
        .instantiations
        .iter()
        .filter(|stamp| body.contains(&usize::try_from(stamp.anchor.expansion.start_byte).unwrap()))
        .collect();
    assert!(inside.is_empty(), "{inside:?}");
}
