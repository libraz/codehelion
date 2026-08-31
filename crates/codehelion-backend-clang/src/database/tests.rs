use super::*;

/// The selector this side compares against is built from the words the shared
/// reader produces, which is the same reader the scanner names the entry with.
/// A split of this helper's own would leave an entry the scanner can name and
/// this side cannot find, and nothing would say so.
#[test]
fn a_recorded_command_is_split_by_the_reader_both_sides_share() {
    let command = "clang++ -DTEXT='a b'\t-I/o/inc\n-c /w/a.cpp";
    let entry = RecordedCommand {
        file: "/w/a.cpp".to_string(),
        directory: Some("/w".to_string()),
        arguments: None,
        command: Some(command.to_string()),
    }
    .entry()
    .expect("the entry carries a command");
    assert_eq!(
        entry.selector.arguments,
        codehelion_helper_protocol::split_command(command)
    );
    assert_eq!(
        entry.selector.arguments,
        ["clang++", "-DTEXT=a b", "-I/o/inc", "-c", "/w/a.cpp"]
    );
}

#[test]
fn what_a_unit_is_compiled_with_is_kept_and_where_it_writes_is_not() {
    let entry = RecordedCommand {
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

/// What a build generator writes by default. None of it changes which code is
/// read, so none of it may cost the unit its analysis: a project that builds a
/// shared library, targets an SDK version, or turns its warnings up is the
/// ordinary case rather than an exotic one.
#[test]
fn an_ordinary_generated_command_is_analysed_rather_than_refused() {
    let entry = RecordedCommand {
        file: "/w/src/a.cpp".to_string(),
        directory: Some("/w/build".to_string()),
        arguments: Some(
            [
                "/usr/bin/ccache",
                "/usr/bin/clang++",
                "-DPROJECT_EXPORTS",
                "-I/w/include",
                "-isystem",
                "/opt/sdk/include",
                "-std=gnu++20",
                "-fPIC",
                "-fvisibility=hidden",
                "-fvisibility-inlines-hidden",
                "-fcolor-diagnostics",
                "-fno-omit-frame-pointer",
                "-ffunction-sections",
                "-fstack-protector-strong",
                "-mmacosx-version-min=11.0",
                "-mavx2",
                "-O2",
                "-g",
                "-gdwarf-4",
                "-Wall",
                "-Wextra",
                "-Werror",
                "--coverage",
                "-pipe",
                "-MD",
                "-MT",
                "src/a.cpp.o",
                "-MF",
                "src/a.cpp.o.d",
                "-o",
                "src/a.cpp.o",
                "-c",
                "/w/src/a.cpp",
            ]
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
            .expect("a generated command is analysable")
            .as_slice(),
        [
            "-working-directory=/w/build",
            "-DPROJECT_EXPORTS",
            "-I/w/include",
            "-isystem",
            "/opt/sdk/include",
            "-std=gnu++20",
            // Kept because they decide what is read: a header asking about
            // `__PIC__` or `__SSP_STRONG__` declares different things with and
            // without them, and the deployment target decides which SDK
            // declarations exist at all. The rest of this command decides only
            // what the compiler would have produced.
            "-fPIC",
            "-fvisibility=hidden",
            "-fstack-protector-strong",
            "-mmacosx-version-min=11.0",
        ]
    );
}

/// A project that interposes a compiler cache records it in front of the
/// compiler. Reading only the first word as the program that ran leaves the
/// real compiler behind as an operand no allow list can account for, and the
/// unit is refused for naming its own compiler.
#[test]
fn a_compiler_launcher_in_front_of_the_compiler_is_not_read_as_an_operand() {
    for command in [
        "ccache clang++ -DA -c /w/a.cpp",
        "/usr/lib/ccache/bin/sccache /usr/bin/clang++ -DA -c /w/a.cpp",
        "distcc icecc clang++ -DA -c /w/a.cpp",
        "clang++ -DA -c /w/a.cpp",
    ] {
        let entry = RecordedCommand {
            file: "/w/a.cpp".to_string(),
            directory: Some("/w".to_string()),
            arguments: None,
            command: Some(command.to_string()),
        }
        .entry()
        .expect("the entry carries a command");
        assert_eq!(
            entry
                .arguments()
                .expect("the compiler is not one of its own operands")
                .as_slice(),
            ["-working-directory=/w", "-DA"],
            "{command}"
        );
    }
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
fn untrusted_direct_reads_stay_under_the_scan_boundary() {
    let directory = tempfile::tempdir().expect("create boundary");
    let boundary = directory.path();
    std::fs::create_dir(boundary.join("include")).expect("create include directory");
    std::fs::write(boundary.join("include/generated.h"), "#define OK 1")
        .expect("create included header");
    let outside = tempfile::NamedTempFile::new().expect("create outside header");

    let accepted = ValidatedArguments::parse(&[
        format!("-working-directory={}", boundary.display()),
        "-include".to_string(),
        "include/generated.h".to_string(),
        "-imacros".to_string(),
        "include/generated.h".to_string(),
    ])
    .expect("arguments parse");
    assert!(accepted.reads_within(boundary));

    let escaped = ValidatedArguments::parse(&[
        format!("-working-directory={}", boundary.display()),
        "-include".to_string(),
        outside.path().display().to_string(),
    ])
    .expect("arguments parse");
    assert!(!escaped.reads_within(boundary));

    let external_directory = ValidatedArguments::parse(&[
        format!(
            "-working-directory={}",
            outside.path().parent().unwrap().display()
        ),
        "-imacros".to_string(),
        outside.path().display().to_string(),
    ])
    .expect("arguments parse");
    assert!(!external_directory.reads_within(boundary));
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
    let from_arguments = RecordedCommand {
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

    let from_command = RecordedCommand {
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
        RecordedCommand {
            file: "/work/src/a.cpp".to_string(),
            directory: Some("/work/build".to_string()),
            arguments: Some(
                ["clang++", "--config=evil.cfg", "/work/src/a.cpp"]
                    .map(str::to_string)
                    .to_vec(),
            ),
            command: None,
        },
        RecordedCommand {
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
    let entry = RecordedCommand {
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
            RecordedCommand {
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
    let narrow = RecordedCommand {
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
    let wide = RecordedCommand {
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
    let entry = RecordedCommand {
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
        RecordedCommand {
            file: "src/a.cpp".to_string(),
            directory: None,
            arguments: None,
            command: None,
        }
        .entry()
        .is_none()
    );
}

/// One project's units are all governed by one database, so the parse is a
/// cost of the project rather than of each of its files. Rewriting the file
/// after the first lookup is how a second read would show itself.
#[test]
fn a_database_is_read_once_however_many_units_ask_about_it() {
    let project = tempfile::tempdir().expect("a directory to hold the project");
    let root = project.path();
    std::fs::write(
        root.join("compile_commands.json"),
        serde_json::to_string(&[serde_json::json!({
            "file": "a.cpp",
            "directory": root,
            "arguments": ["clang++", "-DFIRST=1", "-c", "a.cpp"],
        })])
        .expect("the database serializes"),
    )
    .expect("the database is written");

    let mut databases = Databases::default();
    assert_eq!(
        databases
            .nearest(&root.join("a.cpp"))
            .expect("the database is beside the unit")
            .definitions(),
        ["-DFIRST=1"]
    );

    std::fs::write(root.join("compile_commands.json"), b"not a database at all")
        .expect("the database is replaced");

    for unit in ["a.cpp", "b.cpp", "c.cpp"] {
        assert_eq!(
            databases
                .nearest(&root.join(unit))
                .expect("the database read for the first unit answers for the rest")
                .definitions(),
            ["-DFIRST=1"],
            "{unit} paid for a second read of the database"
        );
    }
}

/// A directory with no database above it is answered without walking the tree
/// again for every file in it.
#[test]
fn a_tree_with_no_database_is_searched_once_per_directory() {
    let project = tempfile::tempdir().expect("a directory to hold the project");
    let root = project.path();
    let mut databases = Databases::default();

    assert!(databases.nearest(&root.join("a.rs")).is_none());
    std::fs::write(
        root.join("compile_commands.json"),
        serde_json::to_string(&[serde_json::json!({
            "file": "a.cpp",
            "directory": root,
            "arguments": ["clang++", "-c", "a.cpp"],
        })])
        .expect("the database serializes"),
    )
    .expect("the database is written");

    assert!(
        databases.nearest(&root.join("b.rs")).is_none(),
        "the search from one directory was walked twice"
    );
}

/// A database that is there and unreadable refuses each unit that asks, not
/// only the first: the sentence explaining it is what a coverage report shows
/// beside that unit, and a unit reported with no sentence reads as a unit
/// nobody looked at.
#[test]
fn an_unreadable_database_refuses_every_unit_that_asks_about_it() {
    let project = tempfile::tempdir().expect("a directory to hold the project");
    let root = project.path();
    std::fs::write(root.join("compile_commands.json"), b"{ not json")
        .expect("the database is written");

    let mut databases = Databases::default();
    for unit in ["a.cpp", "b.cpp", "c.cpp"] {
        assert!(
            databases.nearest(&root.join(unit)).is_none(),
            "{unit} was answered from a database that could not be read"
        );
    }
}
