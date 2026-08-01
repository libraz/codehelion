use super::*;

/// One header analysed from two translation units is two analyses of one
/// file, so the unit is part of the identity and the file alone is not.
#[test]
fn a_header_read_from_two_units_is_two_analyses() {
    let (_dir, mut store, _path) = on_disk();
    let variant = variant();
    let run = store
        .record_snapshot(&snapshot(
            "/tree",
            &variant,
            vec![helper_row()],
            vec![
                answered(full_analysis(unit_ref("a.o", "include/shared.h"))),
                answered(full_analysis(unit_ref("b.o", "include/shared.h"))),
            ],
        ))
        .unwrap();
    let stored = store.run_compiler_units(run).unwrap();
    assert_eq!(stored.len(), 2);
    assert_eq!(stored[0].outcome.unit().file, stored[1].outcome.unit().file);
    assert_ne!(stored[0].outcome.unit().unit, stored[1].outcome.unit().unit);
}

/// A snapshot naming a helper it does not carry is rejected, and rejecting it
/// takes the whole run with it rather than leaving a scan that half happened.
#[test]
fn a_helper_that_is_not_in_the_snapshot_rolls_the_run_back() {
    let (_dir, mut store, _path) = on_disk();
    let variant = variant();
    let mut row = answered(full_analysis(unit_ref("crate", "src/lib.rs")));
    row.helper = Some(4);
    let error = store
        .record_snapshot(&snapshot("/tree", &variant, vec![helper_row()], vec![row]))
        .unwrap_err();
    assert!(
        matches!(
            error,
            StoreError::UnknownHelperIndex { index, helpers } if index == 4 && helpers == 1
        ),
        "unexpected error: {error}"
    );
    assert_eq!(store.table_count("scan_run").unwrap(), 0);
    assert_eq!(store.table_count("compiler_unit").unwrap(), 0);
    assert_eq!(store.table_count("compiler_helper").unwrap(), 0);
}

/// Deleting a run takes its compiler rows with it, all the way down: an
/// orphaned candidate or type argument would outlive the analysis it belongs
/// to and be counted by the next thing that looks.
#[test]
fn deleting_a_run_takes_its_compiler_rows_with_it() {
    let (_dir, mut store, path) = on_disk();
    let variant = variant();
    let run = store
        .record_snapshot(&snapshot(
            "/tree",
            &variant,
            vec![helper_row()],
            vec![answered(full_analysis(unit_ref("crate", "src/lib.rs")))],
        ))
        .unwrap();
    assert!(store.table_count("compiler_call_candidate").unwrap() > 0);
    assert!(store.table_count("compiler_type_argument").unwrap() > 0);

    drop(store);
    let conn = peek(&path);
    conn.execute("DELETE FROM scan_run WHERE id = ?1", [run])
        .unwrap();
    for table in COMPILER_TABLES {
        assert_eq!(count(&conn, table), 0, "{table} outlived its run");
    }
}

/// What storing an analysis is for: the engine's type dimension and its
/// answer about which names are external both come out of a stored answer,
/// and the analysis crate that consumes them never learns that a compiler
/// exists. That is the sense in which the dimension's input is replaceable —
/// anything able to produce the tags can supply it.
#[test]
fn a_stored_analysis_supplies_evidence_the_engine_cannot_obtain_itself() {
    let (_dir, mut store, _path) = on_disk();
    let variant = variant();
    let run = store
        .record_snapshot(&snapshot(
            "/tree",
            &variant,
            vec![helper_row()],
            vec![answered(full_analysis(unit_ref("render", "src/render.rs")))],
        ))
        .unwrap();
    let mut stored = store.run_compiler_units(run).unwrap();
    let CompilerOutcome::Analyzed(ir) = stored.remove(0).outcome else {
        panic!("expected an analysis")
    };

    // One tag per typed symbol, not one per distinct type: the evidence is
    // about what the unit works with, and a type used ten times is ten facts.
    let evidence = TypeEvidence::from_tags(ir.symbols.iter().filter_map(|symbol| {
        let index = usize::try_from(symbol.type_index?).ok()?;
        TypeTag::from_category(ir.types.get(index)?.category.name())
    }));
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence.agreement(&evidence), Some(1.0));

    // And the compiler's verdict on each name, keyed by where the name sits.
    let mut resolution = Resolution::new();
    for symbol in &ir.symbols {
        let start = usize::try_from(symbol.anchor.expansion.start_byte).unwrap();
        resolution.insert(start, symbol.external);
    }
    assert!(!resolution.is_empty());
}

/// The same answer stored twice is stored identically, row for row. Anything
/// that reached a hash map's iteration order or a timestamp on the way in
/// would show up here as two databases that hold the same analysis and do not
/// agree about it.
#[test]
fn storing_one_answer_twice_writes_the_same_rows_both_times() {
    let rows = || {
        let (dir, mut store, path) = on_disk();
        store
            .record_snapshot(&snapshot(
                "/tree",
                &variant(),
                vec![helper_row()],
                vec![
                    answered(full_analysis(unit_ref("render", "src/render.rs"))),
                    unavailable(
                        unit_ref("build-script", "build.rs"),
                        Unavailability::RequiresExecution,
                        None,
                    ),
                ],
            ))
            .unwrap();
        drop(store);
        let conn = peek(&path);
        let dumped = dump(&conn);
        drop(dir);
        dumped
    };
    assert_eq!(rows(), rows());
}

/// Every compiler row in the database, as text, in a fixed order.
fn dump(conn: &Connection) -> Vec<String> {
    let mut out = Vec::new();
    for table in COMPILER_TABLES {
        let mut statement = conn.prepare(&format!("SELECT * FROM {table}")).unwrap();
        let columns = statement.column_count();
        let mut rows: Vec<String> = statement
            .query_map([], |row| {
                let mut cells = Vec::with_capacity(columns);
                for index in 0..columns {
                    cells.push(format!("{:?}", row.get_ref(index)?));
                }
                Ok(cells.join("|"))
            })
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        rows.sort();
        for row in rows {
            out.push(format!("{table}: {row}"));
        }
    }
    out
}
