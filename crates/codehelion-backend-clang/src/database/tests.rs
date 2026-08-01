use super::*;

fn words(command: &str) -> Vec<String> {
    split(command)
}

#[test]
fn a_command_written_as_one_line_is_split_the_way_a_shell_would() {
    assert_eq!(words("clang++ -c a.cpp"), ["clang++", "-c", "a.cpp"]);
    assert_eq!(
        words(r#"clang++ -I"/o p/inc" -DA=\"x\" a.cpp"#),
        ["clang++", "-I/o p/inc", r#"-DA="x""#, "a.cpp"]
    );
    // An empty quoted argument is an argument, not nothing: `-DA=` and no
    // `-D` at all are different commands.
    assert_eq!(words(r#"clang++ "" a.cpp"#), ["clang++", "", "a.cpp"]);
}

#[test]
fn what_a_unit_is_compiled_with_is_kept_and_where_it_writes_is_not() {
    let entry = RawEntry {
        file: "src/a.cpp".to_string(),
        directory: Some("/work/build".to_string()),
        arguments: Some(
            [
                "clang++",
                "-std=c++17",
                "-DWIDE=64",
                "-I../include",
                "-c",
                "-o",
                "a.o",
                "src/a.cpp",
            ]
            .map(str::to_string)
            .to_vec(),
        ),
        command: None,
    }
    .entry()
    .expect("the entry carries a command");

    assert_eq!(entry.file, Path::new("/work/build/src/a.cpp"));
    assert_eq!(
        entry
            .arguments()
            .expect("ordinary compilation arguments are safe")
            .as_slice(),
        [
            "-working-directory=/work/build",
            "-std=c++17",
            "-DWIDE=64",
            "-I../include",
        ]
    );
    assert_eq!(entry.definitions, ["-DWIDE=64"]);
}

#[test]
fn compiler_arguments_fail_closed_for_execution_and_output_options() {
    let rejected: &[&[&str]] = &[
        &["--config", "evil.cfg"],
        &["--config=evil.cfg"],
        &["--config-user-dir", "/tmp/config"],
        &["--config-user-dir=/tmp/config"],
        &["--config-system-dir", "/tmp/config"],
        &["--config-system-dir=/tmp/config"],
        &["-B", "/tmp/toolchain"],
        &["-B/tmp/toolchain"],
        &["@evil.rsp"],
        &["-Xclang", "-load"],
        &["-load", "/tmp/plugin.so"],
        &["-plugin", "example"],
        &["-add-plugin", "example"],
        &["-fplugin=/tmp/plugin.so"],
        &["-fplugin-arg-example=value"],
        &["-fpass-plugin=/tmp/pass.so"],
        &["-fmodules"],
        &["-fmodule-file=/tmp/module.pcm"],
        &["-fmodule-map-file=/tmp/module.modulemap"],
        &["-fimplicit-modules"],
        &["-include-pch", "/tmp/header.pch"],
        &["-emit-pch"],
        &["-emit-module"],
        &["-ast-merge", "/tmp/unit.ast"],
        &["-emit-ast"],
        &["-o", "/tmp/output"],
        &["-save-temps"],
        &["-serialize-diagnostics", "/tmp/diagnostics.dia"],
        &["-ftime-trace"],
        &["-MJ", "/tmp/fragment.json"],
        &["-analyzer-checker=example"],
        &["-Xanalyzer", "-analyzer-output=text"],
        &["-mllvm", "-example"],
        &["-Xpreprocessor", "-example"],
        &["-Wp,-example"],
        &["-Xlinker", "-example"],
        &["-Wl,-example"],
        &["-Xassembler", "-example"],
        &["-Wa,-example"],
        &["--future-unknown-option"],
        &["positional-operand.cpp"],
    ];
    for arguments in rejected {
        let arguments: Vec<String> = arguments.iter().map(ToString::to_string).collect();
        assert!(
            ValidatedArguments::parse(&arguments).is_err(),
            "unexpectedly accepted {arguments:?}"
        );
    }
}

#[test]
fn allow_list_retains_joined_and_separate_semantic_inputs() {
    let arguments = [
        "-working-directory=/work/build",
        "-working-directory",
        "/work/other-build",
        "-std=c++20",
        "-std",
        "c++23",
        "-DLEVEL=2",
        "-D",
        "FEATURE=1",
        "-UOLD",
        "-U",
        "OLDER",
        "-I/work/include",
        "-I",
        "/work/generated",
        "-isystem",
        "/opt/sdk/include",
        "-include",
        "/work/prefix.hpp",
        "--target=x86_64-unknown-linux-gnu",
        "-target",
        "aarch64-apple-darwin",
        "-m64",
        "-mabi=lp64",
    ]
    .map(str::to_string)
    .to_vec();
    assert_eq!(
        ValidatedArguments::parse(&arguments)
            .expect("ordinary parsing flags are safe")
            .as_slice(),
        arguments
    );
}

#[test]
fn option_operands_are_consumed_once_and_missing_operands_are_rejected() {
    let arguments = ["-I", "-Xclang", "-D", "-load", "-include", "-plugin"]
        .map(str::to_string)
        .to_vec();
    assert_eq!(
        ValidatedArguments::parse(&arguments)
            .expect("option-looking paths and macro names are still operands")
            .as_slice(),
        arguments
    );
    for option in SAFE_WITH_VALUE {
        assert!(
            ValidatedArguments::parse(&[(*option).to_string()]).is_err(),
            "accepted {option} without its operand"
        );
    }
}

#[test]
fn both_compilation_database_command_forms_reach_the_same_allow_list() {
    let from_arguments = RawEntry {
        file: "/work/src/a.cpp".to_string(),
        directory: Some("/work/build".to_string()),
        arguments: Some(
            [
                "clang++",
                "-D",
                "LEVEL=2",
                "-UOLD",
                "-I",
                "../include",
                "-isystem",
                "/opt/sdk/include",
                "-include",
                "prefix.hpp",
                "-std",
                "c++20",
                "--target=x86_64-unknown-linux-gnu",
                "/work/src/a.cpp",
            ]
            .map(str::to_string)
            .to_vec(),
        ),
        command: None,
    }
    .entry()
    .expect("arguments entry");
    assert!(from_arguments.arguments().is_ok());

    let from_command = RawEntry {
        file: "/work/src/a.cpp".to_string(),
        directory: Some("/work/build".to_string()),
        arguments: None,
        command: Some(
            "clang++ -DLEVEL=2 -U OLD -I../include -isystem /opt/sdk/include \
             -include prefix.hpp -std=c++20 -target x86_64-unknown-linux-gnu \
             /work/src/a.cpp"
                .to_string(),
        ),
    }
    .entry()
    .expect("command entry");
    assert!(from_command.arguments().is_ok());

    for unsafe_entry in [
        RawEntry {
            file: "/work/src/a.cpp".to_string(),
            directory: Some("/work/build".to_string()),
            arguments: Some(
                ["clang++", "--config=evil.cfg", "/work/src/a.cpp"]
                    .map(str::to_string)
                    .to_vec(),
            ),
            command: None,
        },
        RawEntry {
            file: "/work/src/a.cpp".to_string(),
            directory: Some("/work/build".to_string()),
            arguments: None,
            command: Some("clang++ @evil.rsp /work/src/a.cpp".to_string()),
        },
    ] {
        assert!(
            unsafe_entry
                .entry()
                .expect("entry is retained so analysis can report unavailable")
                .arguments()
                .is_err()
        );
    }
}

/// The relative include path in the entry above is relative to the
/// directory the command was to run in, which is never this process's. A
/// helper that dropped that would resolve `../include` against wherever a
/// scan happened to be started and read a different header, or none.
#[test]
fn a_command_is_read_from_the_directory_it_was_to_run_in() {
    let entry = RawEntry {
        file: "/work/src/a.cpp".to_string(),
        directory: Some("/work/build".to_string()),
        arguments: Some(
            ["clang++", "-I../include", "/work/src/a.cpp"]
                .map(str::to_string)
                .to_vec(),
        ),
        command: None,
    }
    .entry()
    .expect("the entry carries a command");
    assert_eq!(
        entry
            .arguments()
            .expect("include path is safe")
            .as_slice()
            .first()
            .map(String::as_str),
        Some("-working-directory=/work/build")
    );
}

#[test]
fn a_definition_is_collected_however_the_flag_spells_it() {
    let joined = ["-DA", "-DB=2", "-U", "C", "-D", "E=5", "-Iwherever"].map(str::to_string);
    assert_eq!(definitions(&joined), ["-DA", "-DB=2", "-UC", "-DE=5"]);
}

/// The caller and the database need not stand in the same place. A scan
/// rooted inside a tree spells its files against its own root, which is not
/// the one this database was found from, so a unit is found by where it is
/// as well as by how this project spells it.
#[test]
fn a_unit_is_found_by_where_it_is_as_well_as_by_how_the_project_spells_it() {
    let database = Database {
        root: PathBuf::from("/work"),
        entries: vec![
            RawEntry {
                file: "/work/src/a.cpp".to_string(),
                directory: Some("/work/build".to_string()),
                arguments: Some(
                    ["clang++", "-std=c++17", "/work/src/a.cpp"]
                        .map(str::to_string)
                        .to_vec(),
                ),
                command: None,
            }
            .entry()
            .expect("the entry carries a command"),
        ],
    };
    assert!(database.unit("src/a.cpp", None).is_some());
    assert!(database.unit("/work/src/a.cpp", None).is_some());
    // A file this database says nothing about stays unanswerable, whichever
    // way it is named: finding the nearest entry would analyse one unit and
    // report it as another.
    assert!(database.unit("/work/src/b.cpp", None).is_none());
    assert!(database.unit("src/b.cpp", None).is_none());
}

#[test]
fn an_exact_selector_never_falls_back_to_another_command_for_the_same_file() {
    let narrow = RawEntry {
        file: "/work/src/a.cpp".to_string(),
        directory: Some("/work".to_string()),
        arguments: Some(
            ["clang++", "-DNARROW", "-c", "/work/src/a.cpp"]
                .map(str::to_string)
                .to_vec(),
        ),
        command: None,
    }
    .entry()
    .expect("the entry carries a command");
    let wide = RawEntry {
        file: "/work/src/a.cpp".to_string(),
        directory: Some("/work".to_string()),
        arguments: Some(
            ["clang++", "-DWIDE", "-c", "/work/src/a.cpp"]
                .map(str::to_string)
                .to_vec(),
        ),
        command: None,
    }
    .entry()
    .expect("the entry carries a command");
    let database = Database {
        root: PathBuf::from("/work"),
        entries: vec![narrow, wide],
    };
    let wide_selector = database.entries[1].selector.clone();
    let selected = database
        .unit("/work/src/a.cpp", Some(&wide_selector))
        .expect("the requested command is present");
    assert_eq!(selected.selector, wide_selector);
    let missing = CompileCommandSelector {
        arguments: vec!["clang++".to_string(), "-DOTHER".to_string()],
        ..wide_selector
    };
    assert!(database.unit("/work/src/a.cpp", Some(&missing)).is_none());
}

/// A generator run from a build directory names its sources through the
/// directory above. That is the same file a caller names directly, and a
/// comparison of the two spellings as text says it is not.
#[test]
fn a_source_named_through_the_directory_above_is_the_file_it_names() {
    let entry = RawEntry {
        file: "../src/a.cpp".to_string(),
        directory: Some("/work/build".to_string()),
        arguments: Some(
            ["clang++", "-std=c++17", "../src/a.cpp"]
                .map(str::to_string)
                .to_vec(),
        ),
        command: None,
    }
    .entry()
    .expect("the entry carries a command");
    assert_eq!(entry.file, Path::new("/work/src/a.cpp"));
    // The unit's own source still says which unit this is rather than how
    // it is read, so it is still not one of the arguments.
    assert_eq!(
        entry
            .arguments()
            .expect("standard selection is safe")
            .as_slice(),
        ["-working-directory=/work/build", "-std=c++17"]
    );
}

/// An entry with neither form of command describes no compilation, and a
/// unit invented from one would be analysed with no flags at all — which is
/// a different program from the one the project builds.
#[test]
fn an_entry_that_records_no_command_is_not_a_translation_unit() {
    assert!(
        RawEntry {
            file: "src/a.cpp".to_string(),
            directory: None,
            arguments: None,
            command: None,
        }
        .entry()
        .is_none()
    );
}
