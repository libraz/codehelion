use super::*;

/// A variant resolved from a compilation database entry.
fn compiled_variant(macros: &[&str]) -> BuildVariant {
    let mut command = vec!["clang++".to_string(), "-std=c++17".to_string()];
    command.extend(macros.iter().map(|setting| (*setting).to_string()));
    command.extend(
        [
            "-I/w/vendor",
            "-I/w/local",
            "-c",
            "-o",
            "wide.o",
            "/w/src/wide.cpp",
        ]
        .iter()
        .map(|argument| (*argument).to_string()),
    );
    BuildVariant::semantic(
        LanguageSelection::default(),
        Language::Cpp,
        vec![BuildConfiguration::Cpp(Box::new(CppBuild::from_command(
            &command,
            Path::new("/w/src/wide.cpp"),
        )))],
    )
}

fn values_of<'a>(variant: &'a StoredVariant, name: &str) -> Vec<&'a str> {
    variant
        .settings
        .iter()
        .filter(|setting| setting.name == name)
        .map(|setting| setting.value.as_str())
        .collect()
}

/// A stored variant that can only be compared with another is a stored variant
/// nobody can act on: two runs are shown to be incomparable and nothing says
/// what the difference was.
#[test]
fn what_a_compiler_was_told_is_recorded_beside_the_variant_it_identifies() {
    let variant = compiled_variant(&["-DACCUM_WIDTH=64"]);
    let detectors = detector_versions();
    let mut store = Store::open_in_memory().unwrap();
    store
        .record_snapshot(&sample_snapshot(&variant, &detectors))
        .unwrap();

    let stored = store
        .build_variant(&variant.fingerprint())
        .unwrap()
        .expect("the variant the run was recorded under");
    assert_eq!(stored.analysis_mode, "semantic");
    assert_eq!(stored.languages.as_deref(), Some("rust,c,cpp"));
    assert_eq!(stored.header_language.as_deref(), Some("cpp"));
    assert_eq!(stored.build_language.as_deref(), Some("cpp"));
    assert_eq!(values_of(&stored, "compiler"), vec!["clang++"]);
    assert_eq!(values_of(&stored, "macros"), vec!["-DACCUM_WIDTH=64"]);
    assert_eq!(values_of(&stored, "flags"), vec!["-std=c++17"]);
    // The search order is the meaning of an include path, so it comes back in
    // the order it was given rather than in any order the database found handy.
    assert_eq!(
        values_of(&stored, "includes"),
        vec!["/w/vendor", "/w/local"]
    );
    // Nobody ran the compiler to ask its version, and a setting nobody
    // resolved is absent rather than empty.
    assert!(values_of(&stored, "compiler_version").is_empty());
    assert!(values_of(&stored, "linker").is_empty());
}

/// A tree holding both languages is answered by a compiler for each, and both
/// have a `compiler_version`. Recorded under the setting name alone, one would
/// stand for the other — and a reader comparing two runs would be shown a
/// compiler that never touched half the tree.
#[test]
fn what_two_compilers_were_told_is_kept_apart_by_the_language_each_answered_for() {
    let variant = BuildVariant::semantic(
        LanguageSelection::default(),
        Language::Cpp,
        vec![
            BuildConfiguration::Cpp(Box::new(CppBuild {
                compiler: "clang++".into(),
                compiler_version: Some("Apple clang version 21.0.0".into()),
                ..CppBuild::default()
            })),
            BuildConfiguration::Rust(Box::new(RustBuild {
                compiler_version: "rust-analyzer 0.0.344".into(),
                ..RustBuild::default()
            })),
        ],
    );
    let detectors = detector_versions();
    let mut store = Store::open_in_memory().unwrap();
    store
        .record_snapshot(&sample_snapshot(&variant, &detectors))
        .unwrap();

    let stored = store
        .build_variant(&variant.fingerprint())
        .unwrap()
        .expect("the variant the run was recorded under");
    assert_eq!(stored.build_language.as_deref(), Some("cpp,rust"));
    let version = |language: &str| {
        stored
            .settings
            .iter()
            .filter(|setting| setting.language == language && setting.name == "compiler_version")
            .map(|setting| setting.value.as_str())
            .collect::<Vec<_>>()
    };
    assert_eq!(version("cpp"), vec!["Apple clang version 21.0.0"]);
    assert_eq!(version("rust"), vec!["rust-analyzer 0.0.344"]);
}

/// Two builds of one source tree are two variants, and what tells them apart
/// has to be readable, not just hashable.
#[test]
fn two_builds_of_one_tree_are_told_apart_by_what_they_were_told() {
    let narrow = compiled_variant(&[]);
    let wide = compiled_variant(&["-DACCUM_WIDTH=64"]);
    let detectors = detector_versions();
    let mut store = Store::open_in_memory().unwrap();
    store
        .record_snapshot(&sample_snapshot(&narrow, &detectors))
        .unwrap();
    store
        .record_snapshot(&sample_snapshot(&wide, &detectors))
        .unwrap();

    let stored_narrow = store.build_variant(&narrow.fingerprint()).unwrap().unwrap();
    let stored_wide = store.build_variant(&wide.fingerprint()).unwrap().unwrap();
    assert_ne!(stored_narrow.id, stored_wide.id);
    assert!(values_of(&stored_narrow, "macros").is_empty());
    assert_eq!(values_of(&stored_wide, "macros"), vec!["-DACCUM_WIDTH=64"]);
}

/// The same variant seen again is the same variant: its settings are rewritten
/// rather than added to, or a tree scanned twice would report every define
/// twice.
#[test]
fn recording_one_variant_twice_records_its_settings_once() {
    let variant = compiled_variant(&["-DACCUM_WIDTH=64"]);
    let detectors = detector_versions();
    let mut store = Store::open_in_memory().unwrap();
    for _ in 0..2 {
        store
            .record_snapshot(&sample_snapshot(&variant, &detectors))
            .unwrap();
    }
    let stored = store
        .build_variant(&variant.fingerprint())
        .unwrap()
        .unwrap();
    assert_eq!(values_of(&stored, "macros"), vec!["-DACCUM_WIDTH=64"]);
    assert_eq!(
        values_of(&stored, "includes"),
        vec!["/w/vendor", "/w/local"]
    );
}

/// A run of the same tree under rules that named every group differently.
fn renamed_snapshot<'a>(
    variant: &'a BuildVariant,
    detectors: &'a [(String, String)],
) -> Snapshot<'a> {
    let mut snapshot = sample_snapshot(variant, detectors);
    snapshot.started_at = "2026-07-25T00:00:00Z";
    snapshot.finished_at = "2026-07-25T00:00:05Z";
    snapshot.groups[0].fingerprint = group_fp(77);
    snapshot.groups[0].history = GroupOrigin::unconnected(&group_fp(77));
    for (index, member) in snapshot.groups[0].members.iter_mut().enumerate() {
        // Content ids moved with the rule change, exactly as group ids did;
        // placement is all the two runs still have in common.
        member.content = frag_fp(70 + u8::try_from(index).unwrap());
        member.finding = finding(170 + u8::try_from(index).unwrap());
    }
    snapshot
}

#[test]
fn a_history_carries_across_a_change_that_moved_every_identifier() {
    let variant = BuildVariant::fast(LanguageSelection::default(), Language::C);
    let detectors = detector_versions();
    let mut store = Store::open_in_memory().unwrap();
    let before = store
        .record_snapshot(&sample_snapshot(&variant, &detectors))
        .unwrap();
    let after = store
        .record_snapshot(&renamed_snapshot(&variant, &detectors))
        .unwrap();

    let history = group_lineage_id(&group_fp(9));
    // The comparison could connect nothing: the two runs share no identifier.
    assert_eq!(
        store.run_group_snapshots(after).unwrap()[0].lineage,
        Some(group_lineage_id(&group_fp(77)))
    );

    let adopted = store
        .adopt_lineage(
            after,
            before,
            &[LineageAdoption {
                group: group_fp(77).to_hex(),
                previous_group: group_fp(9).to_hex(),
                lineage: history.to_hex(),
                shared: 2,
                overlap: 1.0,
            }],
        )
        .unwrap();

    assert_eq!(adopted.taken, vec![group_fp(77).to_hex()]);
    assert!(adopted.already_connected.is_empty());
    assert!(adopted.unknown.is_empty());
    assert_eq!(
        store.run_group_snapshots(after).unwrap()[0].lineage,
        Some(history),
        "the newer run now belongs to the history the older one started"
    );
}

#[test]
fn matching_member_content_adopts_the_predecessors_lineage() {
    let variant = BuildVariant::fast(LanguageSelection::default(), Language::C);
    let detectors = detector_versions();
    let mut store = Store::open_in_memory().unwrap();
    let before = store
        .record_snapshot(&sample_snapshot(&variant, &detectors))
        .unwrap();
    let mut after_snapshot = sample_snapshot(&variant, &detectors);
    after_snapshot.started_at = "2026-07-25T00:00:00Z";
    after_snapshot.finished_at = "2026-07-25T00:00:05Z";
    after_snapshot.groups[0].fingerprint = group_fp(77);
    after_snapshot.groups[0].history = GroupOrigin::unconnected(&group_fp(77));
    let after = store.record_snapshot(&after_snapshot).unwrap();

    let adopted = store.adopt_matching_lineages(after, before).unwrap();
    assert_eq!(adopted.taken, vec![group_fp(77).to_hex()]);
    assert_eq!(
        store.run_group_snapshots(after).unwrap()[0].lineage,
        Some(group_lineage_id(&group_fp(9)))
    );
}

#[test]
fn an_unchanged_group_needs_no_lineage_adoption() {
    let variant = BuildVariant::fast(LanguageSelection::default(), Language::C);
    let detectors = detector_versions();
    let mut store = Store::open_in_memory().unwrap();
    let before = store
        .record_snapshot(&sample_snapshot(&variant, &detectors))
        .unwrap();
    let mut after_snapshot = sample_snapshot(&variant, &detectors);
    after_snapshot.started_at = "2026-07-25T00:00:00Z";
    after_snapshot.finished_at = "2026-07-25T00:00:05Z";
    let after = store.record_snapshot(&after_snapshot).unwrap();

    let adopted = store.adopt_matching_lineages(after, before).unwrap();
    assert!(adopted.taken.is_empty());
    assert_eq!(
        store.run_group_snapshots(after).unwrap()[0].lineage,
        Some(group_lineage_id(&group_fp(9)))
    );
}

#[test]
fn a_group_the_comparison_already_connected_is_left_as_it_was() {
    let variant = BuildVariant::fast(LanguageSelection::default(), Language::C);
    let detectors = detector_versions();
    let mut store = Store::open_in_memory().unwrap();
    let before = store
        .record_snapshot(&sample_snapshot(&variant, &detectors))
        .unwrap();

    let evidence = group_lineage_id(&group_fp(9));
    let mut snapshot = renamed_snapshot(&variant, &detectors);
    snapshot.groups[0].history = GroupOrigin {
        state: AuditState::Expanded,
        lineage: evidence,
        parents: vec![LineageParent {
            fingerprint: group_fp(9),
            lineage: evidence,
            primary: true,
            shared_content: 2,
            overlap: 1.0,
        }],
    };
    let after = store.record_snapshot(&snapshot).unwrap();

    // Matched on content, so the rule change did not touch it. A conversion
    // must not replace an answer the evidence supported with one from
    // placement.
    let invented = group_lineage_id(&group_fp(123));
    let adopted = store
        .adopt_lineage(
            after,
            before,
            &[LineageAdoption {
                group: group_fp(77).to_hex(),
                previous_group: group_fp(9).to_hex(),
                lineage: invented.to_hex(),
                shared: 1,
                overlap: 0.5,
            }],
        )
        .unwrap();

    assert!(adopted.taken.is_empty());
    assert_eq!(adopted.already_connected, vec![group_fp(77).to_hex()]);
    assert_eq!(
        store.run_group_snapshots(after).unwrap()[0].lineage,
        Some(evidence)
    );
}

#[test]
fn a_group_a_run_does_not_hold_is_named_rather_than_passed_over() {
    let variant = BuildVariant::fast(LanguageSelection::default(), Language::C);
    let detectors = detector_versions();
    let mut store = Store::open_in_memory().unwrap();
    let before = store
        .record_snapshot(&sample_snapshot(&variant, &detectors))
        .unwrap();
    let after = store
        .record_snapshot(&renamed_snapshot(&variant, &detectors))
        .unwrap();

    let adopted = store
        .adopt_lineage(
            after,
            before,
            &[LineageAdoption {
                group: group_fp(200).to_hex(),
                previous_group: group_fp(9).to_hex(),
                lineage: group_lineage_id(&group_fp(9)).to_hex(),
                shared: 2,
                overlap: 1.0,
            }],
        )
        .unwrap();

    assert!(adopted.taken.is_empty());
    assert_eq!(adopted.unknown, vec![group_fp(200).to_hex()]);
}

#[test]
fn a_malformed_identifier_stops_the_rewrite_rather_than_half_applying_it() {
    let variant = BuildVariant::fast(LanguageSelection::default(), Language::C);
    let detectors = detector_versions();
    let mut store = Store::open_in_memory().unwrap();
    let before = store
        .record_snapshot(&sample_snapshot(&variant, &detectors))
        .unwrap();
    let after = store
        .record_snapshot(&renamed_snapshot(&variant, &detectors))
        .unwrap();

    let error = store
        .adopt_lineage(
            after,
            before,
            &[LineageAdoption {
                group: group_fp(77).to_hex(),
                previous_group: group_fp(9).to_hex(),
                lineage: "not-a-lineage".to_string(),
                shared: 2,
                overlap: 1.0,
            }],
        )
        .unwrap_err();

    assert!(matches!(error, StoreError::MalformedId { .. }));
    assert_eq!(
        store.run_group_snapshots(after).unwrap()[0].lineage,
        Some(group_lineage_id(&group_fp(77))),
        "a rewrite that could not finish left nothing behind"
    );
}
