//! What a scan finds in a header, measured against what it finds in a file
//! that is its own translation unit.
//!
//! No command compiles a header, so everything known about one arrives through
//! the translation units that include it. Whatever is lost on that way back is
//! invisible from the outside — the scan succeeds, calls itself semantic, and
//! simply states fewer patterns about headers than about sources, which for a
//! header-only library is most of the library.

use super::*;

/// Two resource lifetimes a header states.
///
/// Written twice so the header holds a clone of its own, and compiled by two
/// translation units so what answers for it is what both of them agreed it
/// holds rather than one reading of it.
const LIFETIME_HEADER: &str = r"#pragma once

#include <mutex>

namespace lifetime {

inline std::mutex& shared_mutex() {
  static std::mutex mutex;
  return mutex;
}

inline void guard_in_header() {
  std::lock_guard<std::mutex> guard(shared_mutex());
}

inline void guard_in_header_again() {
  std::lock_guard<std::mutex> guard(shared_mutex());
}

}  // namespace lifetime
";

/// The same two lifetimes, in a file that is compiled as itself.
const LIFETIME_SOURCE: &str = r"#include <mutex>

namespace {
std::mutex written_mutex;
}  // namespace

void guard_in_source() {
  std::lock_guard<std::mutex> guard(written_mutex);
}

void guard_in_source_again() {
  std::lock_guard<std::mutex> guard(written_mutex);
}
";

/// A translation unit that compiles the header, entering it by `entry`.
fn reader(entry: &str) -> String {
    format!(
        r#"#include "lifetime.hpp"

void {entry}() {{
  lifetime::guard_in_header();
  lifetime::guard_in_header_again();
}}
"#
    )
}

/// The translation units that compile the header.
const READERS: [&str; 2] = ["reads_once.cpp", "reads_twice.cpp"];

/// Plant a tree whose header and whose source state the same pattern, and
/// return its root.
///
/// It starts as a copied fixture for its compilation database. What a real
/// database on this machine carries beyond a fixture's own arguments — where
/// the standard library is — is the fixture crate's answer to give, and
/// working it out a second time here would be one more place for it to be
/// wrong. The tree itself is then this test's, and the database is pointed at
/// it.
fn plant(destination: &std::path::Path) -> std::path::PathBuf {
    let root = codehelion_fixtures::copy_cpp("header-only", destination).expect("plant a C++ tree");
    let database = root.join("compile_commands.json");
    let planted: Vec<codehelion_fixtures::CompileCommand> =
        serde_json::from_slice(&std::fs::read(&database).expect("read the planted database"))
            .expect("the planted database is one JSON document");
    // An invocation that defines nothing of its own, so this tree is one
    // program rather than as many as the fixture's `-D` arguments make.
    let template = planted
        .iter()
        .find(|entry| entry.defines().is_empty())
        .expect("the fixture carries an invocation that defines nothing");
    let invocation: Vec<String> = template
        .arguments
        .iter()
        .take_while(|argument| *argument != "-c")
        .cloned()
        .collect();

    std::fs::remove_file(root.join("CMakeLists.txt")).expect("drop the fixture's build script");
    for directory in ["include", "src"] {
        let directory = root.join(directory);
        std::fs::remove_dir_all(&directory).expect("clear the fixture's own sources");
        std::fs::create_dir(&directory).expect("make room for this tree's sources");
    }
    std::fs::write(root.join("include").join("lifetime.hpp"), LIFETIME_HEADER)
        .expect("write the header");
    let mut sources: Vec<(&str, String)> = vec![("written_here.cpp", LIFETIME_SOURCE.to_owned())];
    sources.extend(
        READERS
            .iter()
            .map(|name| (*name, reader(name.trim_end_matches(".cpp")))),
    );
    let mut commands = Vec::new();
    for (name, text) in sources {
        let file = root.join("src").join(name);
        std::fs::write(&file, text).expect("write a translation unit");
        let mut arguments = invocation.clone();
        arguments.extend([
            "-c".to_owned(),
            "-o".to_owned(),
            format!("{name}.o"),
            file.display().to_string(),
        ]);
        commands.push(codehelion_fixtures::CompileCommand {
            directory: root.display().to_string(),
            arguments,
            file: file.display().to_string(),
        });
    }
    std::fs::write(
        &database,
        serde_json::to_vec_pretty(&commands).expect("render a compilation database"),
    )
    .expect("write the compilation database");
    root
}

/// The units `rule` was found in inside the file `tail` names, in one order
/// whatever order they were reported in.
fn found_in(report: &Value, rule: &str, tail: &str) -> Vec<String> {
    let mut units: Vec<String> = reports(report)
        .into_iter()
        .flat_map(|partition| partition["groups"].as_array().into_iter().flatten())
        .filter(|group| group["clone_type"] == "restricted-semantic")
        .filter(|group| {
            group["semantic"]["rules"]
                .as_array()
                .is_some_and(|rules| rules.iter().any(|found| found["id"] == rule))
        })
        .flat_map(|group| group["members"].as_array().into_iter().flatten())
        .filter(|member| {
            member["file"]
                .as_str()
                .is_some_and(|file| names_the_file(file, tail))
        })
        .filter_map(|member| member["unit"].as_str().map(ToOwned::to_owned))
        .collect();
    units.sort();
    units.dedup();
    units
}

/// A pattern is the same pattern wherever it is written, so a header states as
/// many of them as an equivalent source file and a scan has to recover as
/// many. A resource lifetime is the case that says so plainly: nothing about
/// an acquire and its release is legible from resolved names alone, so it
/// reaches a rule only through what the compiler confirmed about the file, and
/// for a header that is what its readers confirmed about it.
#[test]
fn a_pattern_a_header_states_is_found_as_often_as_one_a_source_writes() {
    require_clang_helper();
    let directory = tempfile::tempdir().expect("temp dir");
    let root = plant(directory.path());
    let report = scan(&root);

    let from_source = found_in(&report, "resource-lifecycle-v1", "src/written_here.cpp");
    assert_eq!(
        from_source,
        ["guard_in_source", "guard_in_source_again"],
        "a lifetime written in its own translation unit is not found: {report}"
    );
    let from_header = found_in(&report, "resource-lifecycle-v1", "include/lifetime.hpp");
    assert_eq!(
        from_header.len(),
        from_source.len(),
        "the header states as many lifetimes as the source and fewer were recovered from it: \
         {report}"
    );
    assert_eq!(
        from_header,
        ["guard_in_header", "guard_in_header_again"],
        "the lifetimes recovered from the header are not the ones it states: {report}"
    );
}
