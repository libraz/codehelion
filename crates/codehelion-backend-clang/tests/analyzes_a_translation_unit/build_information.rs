use super::*;

/// A file no compilation database mentions is one nothing says how to compile.
/// Analysing it under some other unit's command would answer about a program it
/// is not part of.
#[test]
fn a_file_no_command_mentions_is_reported_rather_than_guessed_at() {
    let planted = plant("header-only");
    let stranger = planted.unit("src/nobody.cpp", "include/accumulate.hpp");
    assert!(matches!(
        analyze(&stranger),
        Analysis::Missing(Unavailability::NoBuildInformation)
    ));
}

/// A tree with no database at all is not a tree with an empty one: every C or
/// C++ file in it is a file nobody can speak for, and saying so is what tells a
/// thin answer apart from a project with nothing in it.
#[test]
fn a_tree_with_no_compilation_database_is_said_to_have_no_build_information() {
    let directory = tempfile::tempdir().expect("temp dir");
    std::fs::write(
        directory.path().join("lonely.cpp"),
        "int main() { return 0; }\n",
    )
    .unwrap();
    let unit = UnitRef {
        unit: "lonely.cpp".to_string(),
        file: directory.path().join("lonely.cpp").display().to_string(),
        variant: "host".to_string(),
    };
    assert!(matches!(
        analyze(&unit),
        Analysis::Missing(Unavailability::NoBuildInformation)
    ));
}

/// What a run files its answers under. The macros a unit is compiled with
/// decide which declarations its headers contain at all, so two readings of one
/// tree under different definitions are two programs and have to be filed
/// apart.
#[test]
fn a_tree_is_described_by_the_conditions_its_units_are_compiled_under() {
    let planted = plant("header-only");
    let mut helper = helper();
    let described = helper.describe(&planted.root).expect("it describes");
    assert_eq!(described.cfgs, vec!["-DACCUM_WIDTH=64".to_string()]);
    assert!(described.features.is_empty(), "a C++ build has no features");

    // A tree with no database has no C or C++ build to describe, which is an
    // answer: a project that is entirely Rust is not missing one, and refusing
    // here would stop a scan of it because this helper happened to be
    // installed.
    let empty = tempfile::tempdir().expect("temp dir");
    let nothing = helper.describe(empty.path()).expect("it describes");
    assert!(nothing.cfgs.is_empty(), "{nothing:?}");
    helper.shutdown().expect("the helper should stop cleanly");
}

/// A database that is there and cannot be read leaves the conditions of the
/// build unknown. Describing the tree as having none would file the run under
/// conditions nobody established.
#[test]
fn a_database_that_cannot_be_read_stops_the_description() {
    let broken = tempfile::tempdir().expect("temp dir");
    std::fs::write(broken.path().join("compile_commands.json"), b"{ not json").unwrap();
    let mut helper = helper();

    let error = helper
        .describe(broken.path())
        .expect_err("an unreadable database must not describe as an empty one");

    assert!(
        error
            .to_string()
            .contains("unreadable_compilation_database"),
        "{error}"
    );
    helper.shutdown().expect("the helper should stop cleanly");
}

/// What a unit is told about why it was refused is about that unit. The
/// sentence explaining a database nobody could read belongs to the request
/// that met it, not to whichever unit is asked about next.
#[test]
fn a_refusal_is_not_carried_into_the_answer_to_a_later_request() {
    let broken = tempfile::tempdir().expect("temp dir");
    std::fs::write(broken.path().join("compile_commands.json"), b"{ not json").unwrap();
    let lonely = tempfile::tempdir().expect("temp dir");
    std::fs::write(
        lonely.path().join("lonely.cpp"),
        "int main() { return 0; }\n",
    )
    .unwrap();
    let unit = UnitRef {
        unit: "lonely.cpp".to_string(),
        file: lonely.path().join("lonely.cpp").display().to_string(),
        variant: "host".to_string(),
    };
    let mut helper = helper();
    let _ = helper.describe(broken.path());

    let analysis = helper
        .analyze(&unit, &[Capability::Types])
        .expect("the helper should answer");

    assert!(matches!(
        analysis,
        Analysis::Missing(Unavailability::NoBuildInformation)
    ));
    let said = helper.take_answer_diagnostics();
    assert_eq!(said.len(), 1, "{said:?}");
    assert!(
        said[0].contains("no compilation database above"),
        "{said:?}"
    );
    helper.shutdown().expect("the helper should stop cleanly");
}
