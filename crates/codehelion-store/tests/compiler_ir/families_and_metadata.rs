use super::*;

/// One definition and every place it was stamped out, gathered across the
/// units they live in — the query the expansion/definition anchoring exists to
/// answer, and the reason the key is indexed without a unit in front of it.
#[test]
fn the_expansions_of_one_definition_are_one_family_across_units() {
    let (_dir, mut store, _path) = on_disk();
    let variant = variant();
    let key = "crate::Buffer::push<String>";

    let mut first = full_analysis(unit_ref("render", "src/render.rs"));
    first.instantiations[0].instantiation_key = key.to_string();
    let mut second = full_analysis(unit_ref("parse", "src/parse.rs"));
    second.instantiations = vec![
        Instantiation {
            anchor: Anchor {
                expansion: range("src/parse.rs", 128),
                definition: Some(range("src/generic.rs", 96)),
            },
            definition: "crate::Buffer::push".to_string(),
            definition_end_line: None,
            artifact_match_key: None,
            instantiation_key: key.to_string(),
            arguments: vec![1],
        },
        Instantiation {
            anchor: Anchor::written_here(range("src/parse.rs", 256)),
            definition: "crate::Buffer::push".to_string(),
            definition_end_line: None,
            artifact_match_key: None,
            instantiation_key: "crate::Buffer::push<u32>".to_string(),
            arguments: vec![0],
        },
    ];
    let run = store
        .record_snapshot(&snapshot(
            "/tree",
            &variant,
            vec![helper_row()],
            vec![answered(first), answered(second)],
        ))
        .unwrap();

    let family = store.instantiation_family(run, key).unwrap();
    assert_eq!(family.len(), 2, "{family:?}");
    assert_eq!(family[0].unit.unit, "render");
    assert_eq!(family[1].unit.unit, "parse");
    // Every member names one definition, which is what makes the family a
    // repetition of one thing rather than several copies of a body.
    assert!(
        family
            .iter()
            .all(|site| site.definition == "crate::Buffer::push")
    );
    assert_eq!(
        family[0]
            .anchor
            .definition
            .as_ref()
            .map(|d| d.file.as_str()),
        Some("src/generic.rs")
    );
    // The other key is its own family, not part of this one.
    assert_eq!(
        store
            .instantiation_family(run, "crate::Buffer::push<u32>")
            .unwrap()
            .len(),
        1
    );
}
/// The family query has to be answerable without walking every instantiation
/// in the database, which is the whole reason for the index — and an index
/// that exists but is not reachable from the query is the same as none.
#[test]
fn the_family_query_reaches_the_instantiation_index() {
    let (_dir, store, path) = on_disk();
    drop(store);
    let conn = peek(&path);
    let mut statement = conn
        .prepare(
            "EXPLAIN QUERY PLAN
             SELECT i.id FROM compiler_instantiation i
             JOIN compiler_unit u ON u.id = i.compiler_unit_id
             WHERE i.instantiation_key = ?1 AND u.scan_run_id = ?2",
        )
        .unwrap();
    let plan: Vec<String> = statement
        .query_map(rusqlite::params!["some::key", 1_i64], |row| {
            row.get::<_, String>(3)
        })
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert!(
        plan.iter()
            .any(|step| step.contains("idx_compiler_instantiation_key")),
        "the query plan does not use the index: {plan:?}"
    );
}

/// A run that holds compiler IR says which schema it was written against; a
/// stored run whose schema this build no longer reads has to be recognisable
/// without reading every unit row.
#[test]
fn a_run_holding_compiler_ir_declares_the_schema_it_used() {
    let (_dir, mut store, path) = on_disk();
    let build_variant = variant();
    let with = store
        .record_snapshot(&snapshot(
            "/a",
            &build_variant,
            vec![helper_row()],
            vec![answered(full_analysis(unit_ref("crate", "src/lib.rs")))],
        ))
        .unwrap();

    drop(store);
    let conn = peek(&path);
    assert_eq!(
        declared(&conn, with),
        vec![codehelion_helper_protocol::ir::COMPILER_IR_SCHEMA_VERSION.to_string()]
    );

    let (_dir, mut store, path) = on_disk();
    let variant = variant();
    let without = store
        .record_snapshot(&snapshot("/b", &variant, Vec::new(), Vec::new()))
        .unwrap();

    drop(store);
    let conn = peek(&path);
    // A scan that asked no compiler claims no IR schema: declaring one would
    // say the scan used something it never did.
    assert!(declared(&conn, without).is_empty());
}

/// A unit that was answered for out of a schema this build cannot read comes
/// back naming that schema rather than passing as current.
#[test]
fn an_answer_from_another_schema_is_not_read_as_current() {
    let mut ir = full_analysis(unit_ref("crate", "src/lib.rs"));
    ir.schema_version = "compiler-ir-unsupported".to_string();
    let stored = round_trip(ir);
    assert!(!stored.is_readable());
    assert_eq!(stored.schema_version, "compiler-ir-unsupported");
}

/// The handshake result is the only place that says why a whole run has no
/// control-flow graphs anywhere, and it is gone once the helper exits.
#[test]
fn the_helper_that_answered_is_recorded_with_what_it_granted() {
    let (_dir, mut store, _path) = on_disk();
    let variant = variant();
    let run = store
        .record_snapshot(&snapshot(
            "/tree",
            &variant,
            vec![helper_row()],
            vec![answered(full_analysis(unit_ref("crate", "src/lib.rs")))],
        ))
        .unwrap();
    let helpers = store.run_compiler_helpers(run).unwrap();
    assert_eq!(helpers, vec![helper_row()]);
    // How often it fell over is the other thing the run cannot reconstruct:
    // the unit rows say which files came back empty, not that the emptiness
    // was the helper's doing.
    assert_eq!(helpers[0].restarts, Some(2));
    // What it said it would run if permitted, which answers "why did nothing
    // run" without the helper still being there to ask. What it *was*
    // permitted is a different fact and lives in the variant, because results
    // depend on it.
    assert_eq!(
        helpers[0].identity.executes,
        vec![Execution::BuildScript, Execution::ProcMacro]
    );
}

/// A helper that survived the tree and one recorded before restarts were kept
/// are different claims, and zero is only the first of them.
#[test]
fn a_run_that_did_not_count_restarts_is_not_a_run_with_none() {
    let (_dir, mut store, _path) = on_disk();
    let variant = variant();
    let mut uncounted = helper_row();
    uncounted.restarts = None;
    let run = store
        .record_snapshot(&snapshot(
            "/tree",
            &variant,
            vec![uncounted.clone()],
            vec![answered(full_analysis(unit_ref("crate", "src/lib.rs")))],
        ))
        .unwrap();
    assert_eq!(store.run_compiler_helpers(run).unwrap(), vec![uncounted]);
}
