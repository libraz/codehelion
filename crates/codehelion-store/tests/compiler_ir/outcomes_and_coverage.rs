use super::*;

/// A unit nobody could analyse is an outcome of scanning a real project, not
/// a gap in the record: it has a row, and the row says which reason applied.
#[test]
fn a_unit_nobody_could_analyse_is_recorded_with_the_reason() {
    let (_dir, mut store, _path) = on_disk();
    let variant = variant();
    let build = unit_ref("build-script", "build.rs");
    let missing = unit_ref("vendored", "vendor/blob.c");
    let run = store
        .record_snapshot(&snapshot(
            "/tree",
            &variant,
            vec![helper_row()],
            vec![
                unavailable(build.clone(), Unavailability::RequiresExecution, None),
                unavailable(missing.clone(), Unavailability::NoBuildInformation, Some(0)),
            ],
        ))
        .unwrap();

    let stored = store.run_compiler_units(run).unwrap();
    assert_eq!(stored.len(), 2);
    assert_eq!(
        stored[0].outcome,
        CompilerOutcome::Unavailable {
            unit: build,
            reason: Unavailability::RequiresExecution,
            diagnostic: None,
        }
    );
    // Ruled out before any helper was involved, so nothing names one.
    assert!(stored[0].helper.is_none());
    assert_eq!(
        stored[1].outcome,
        CompilerOutcome::Unavailable {
            unit: missing,
            reason: Unavailability::NoBuildInformation,
            diagnostic: None,
        }
    );
    assert_eq!(
        stored[1].helper.as_ref().map(|helper| helper.name.as_str()),
        Some("codehelion-backend-rust")
    );
}

#[test]
fn a_helpers_bounded_diagnostic_round_trips_with_its_unavailable_unit() {
    let (_dir, mut store, _path) = on_disk();
    let variant = variant();
    let unit = unit_ref("crate", "src/lib.rs");
    let row = CompilerUnitRow {
        helper: Some(0),
        outcome: CompilerOutcome::Unavailable {
            unit: unit.clone(),
            reason: Unavailability::HelperDied,
            diagnostic: Some("no compiler library is installed".to_string()),
        },
    };
    let run = store
        .record_snapshot(&snapshot("/tree", &variant, vec![helper_row()], vec![row]))
        .unwrap();
    let stored = store.run_compiler_units(run).unwrap();
    assert_eq!(
        stored[0].outcome,
        CompilerOutcome::Unavailable {
            unit,
            reason: Unavailability::HelperDied,
            diagnostic: Some("no compiler library is installed".to_string()),
        }
    );
    let coverage = store.run_compiler_coverage(run).unwrap().unwrap();
    assert_eq!(coverage.diagnostics["no compiler library is installed"], 1);
}
/// A scan that asked nothing and one whose every answer was unavailable are
/// different records, and only the latter has compiler-unit rows.
#[test]
fn asking_and_failing_does_not_read_as_never_asking() {
    let (_dir, mut store, _path) = on_disk();
    let variant = variant();
    let silent = store
        .record_snapshot(&snapshot("/a", &variant, Vec::new(), Vec::new()))
        .unwrap();
    assert!(store.run_compiler_units(silent).unwrap().is_empty());

    let asked = store
        .record_snapshot(&snapshot(
            "/b",
            &variant,
            Vec::new(),
            vec![unavailable(
                unit_ref("crate", "src/lib.rs"),
                Unavailability::ToolchainMismatch,
                None,
            )],
        ))
        .unwrap();
    assert_eq!(store.run_compiler_units(asked).unwrap().len(), 1);
    // A run that started no helper restarted nothing, which is a count rather
    // than a gap in the record: nothing was left uncounted.
    let coverage = store.run_compiler_coverage(asked).unwrap().unwrap();
    assert_eq!(coverage.restarts, Some(0));
    assert_eq!(coverage.not_asked, 1);
}

/// The counts a run reports about itself have to survive being recorded, and
/// the three outcomes have to survive it separately: a summed pair would say a
/// helper failed on files nobody showed it.
#[test]
fn how_much_a_compiler_spoke_for_is_counted_off_the_rows() {
    let (_dir, mut store, _path) = on_disk();
    let variant = variant();
    let run = store
        .record_snapshot(&snapshot(
            "/tree",
            &variant,
            vec![helper_row()],
            vec![
                answered(full_analysis(unit_ref("render", "src/render.rs"))),
                answered(full_analysis(unit_ref("ledger", "src/ledger.rs"))),
                unavailable(
                    unit_ref("build-script", "build.rs"),
                    Unavailability::RequiresExecution,
                    Some(0),
                ),
                unavailable(
                    unit_ref("hooks", "hooks.rs"),
                    Unavailability::RequiresExecution,
                    Some(0),
                ),
                unavailable(
                    unit_ref("crate", "src/slow.rs"),
                    Unavailability::HelperTimedOut,
                    Some(0),
                ),
                // Nobody was asked: no helper here reads it.
                unavailable(
                    unit_ref("", "vendor/blob.c"),
                    Unavailability::NotSupported,
                    None,
                ),
            ],
        ))
        .unwrap();

    let coverage = store
        .run_compiler_coverage(run)
        .unwrap()
        .expect("a compiler was asked about this run");
    assert_eq!(coverage.answered, 2);
    assert_eq!(coverage.not_asked, 1);
    assert_eq!(
        coverage.unavailable,
        [
            ("requires_execution".to_string(), 2),
            ("helper_timed_out".to_string(), 1),
        ]
        .into_iter()
        .collect()
    );
    assert_eq!(coverage.restarts, helper_row().restarts);
}

/// Asking nobody is not asking and being told nothing, so the run that put
/// nothing to a compiler has no coverage rather than an empty one.
#[test]
fn a_run_that_asked_nobody_reports_no_coverage_rather_than_an_empty_one() {
    let (_dir, mut store, _path) = on_disk();
    let variant = variant();
    let run = store
        .record_snapshot(&snapshot("/tree", &variant, Vec::new(), Vec::new()))
        .unwrap();
    assert_eq!(store.run_compiler_coverage(run).unwrap(), None);
}

/// Anchors are stored the way the analysis spelled them, so what they were
/// spelled against has to be stored beside them. Without it a relative path
/// reads as relative to wherever the reader is standing, and the answers land
/// on a file nobody asked about — quietly, since the two can look alike.
#[test]
fn an_analysis_keeps_what_its_paths_were_spelled_against() {
    let written = full_analysis(unit_ref("render", "src/render.rs"));
    assert_eq!(
        round_trip(written).anchored_at.as_deref(),
        Some("/projects/ledger")
    );

    let mut standalone = full_analysis(unit_ref("render", "src/render.rs"));
    standalone.anchored_at = None;
    assert_eq!(round_trip(standalone).anchored_at, None);
}

/// A graph with no blocks and a helper that builds no graph both store zero
/// blocks, so the presence of the graph is stored separately or the two are
/// the same record.
#[test]
fn an_empty_graph_does_not_read_as_no_graph() {
    let mut empty = full_analysis(unit_ref("crate", "src/lib.rs"));
    empty.cfg = Some(ControlFlowGraph::default());
    let mut absent = empty.clone();
    absent.cfg = None;

    assert_eq!(round_trip(empty).cfg, Some(ControlFlowGraph::default()));
    assert_eq!(round_trip(absent).cfg, None);
}

/// The same argument one level down: a summary that found nothing and one
/// nobody computed are the same empty lists and different claims.
#[test]
fn a_summary_nobody_computed_does_not_read_as_one_that_found_nothing() {
    let mut looked = full_analysis(unit_ref("crate", "src/lib.rs"));
    looked.effects = EffectSummary {
        computed: true,
        ..EffectSummary::default()
    };
    looked.data_flow = DataFlowSummary {
        computed: true,
        flows: Vec::new(),
    };
    let mut skipped = looked.clone();
    skipped.effects.computed = false;
    skipped.data_flow.computed = false;

    let read_looked = round_trip(looked);
    assert!(read_looked.effects.computed && read_looked.effects.writes.is_empty());
    assert!(read_looked.data_flow.computed);
    let read_skipped = round_trip(skipped);
    assert!(!read_skipped.effects.computed);
    assert!(!read_skipped.data_flow.computed);
}

/// A dynamic call the compiler narrowed to nothing still says it is dynamic.
/// Both it and an unresolved call store no candidate rows, so collapsing them
/// would be the easy mistake.
#[test]
fn a_dynamic_call_with_no_candidates_is_not_an_unresolved_one() {
    let mut ir = full_analysis(unit_ref("crate", "src/lib.rs"));
    ir.calls = vec![
        CallSite {
            anchor: Anchor::written_here(range("src/lib.rs", 0)),
            target: CallTarget::Dynamic {
                candidates: Vec::new(),
            },
            api_name: None,
        },
        CallSite {
            anchor: Anchor::written_here(range("src/lib.rs", 64)),
            target: CallTarget::Unresolved,
            api_name: None,
        },
    ];
    let stored = round_trip(ir);
    assert_eq!(
        stored.calls[0].target,
        CallTarget::Dynamic {
            candidates: Vec::new()
        }
    );
    assert_eq!(stored.calls[1].target, CallTarget::Unresolved);
}
