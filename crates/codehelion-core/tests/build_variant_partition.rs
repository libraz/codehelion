//! Build variants read off a real compilation database.
//!
//! The unit tests build configurations by hand, which proves the identity rules
//! hold for the arguments they were given. What they cannot show is that those
//! rules survive a compilation database as a build system actually writes one —
//! with absolute paths, an object file per unit, and the flags a project sets
//! rather than the ones a test would choose. These drive the fixtures for that,
//! and each asserts one of the two answers a partition has to be able to give:
//! that two units belong together, and that two do not.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::Path;

use codehelion_core::discovery::{
    BuildConfiguration, BuildVariant, CompileCommands, CppBuild, Language, LanguageSelection,
    partition,
};

/// The variant each translation unit of a fixture was compiled under.
fn variants(fixture: &str) -> Vec<(BuildVariant, String)> {
    let directory = tempfile::tempdir().unwrap();
    let database = codehelion_fixtures::write_compile_commands(fixture, directory.path()).unwrap();
    let commands = CompileCommands::read(&database).unwrap();
    let hash = commands.content_hash.clone();
    commands
        .entries
        .iter()
        .map(|entry| {
            let build = CppBuild {
                database_hash: hash.clone(),
                ..CppBuild::from_command(&entry.arguments, &entry.file)
            };
            let variant = BuildVariant::semantic(
                LanguageSelection::default(),
                Language::Cpp,
                BuildConfiguration::Cpp(Box::new(build)),
            );
            let name = Path::new(&entry.file)
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_default();
            (variant, name)
        })
        .collect()
}

/// Two units of one library compiled the same way. Their object paths differ
/// and their sources differ, and neither of those is a build configuration — if
/// either leaked into the identity, every unit would sit alone in a partition
/// of one and nothing would ever be compared.
#[test]
fn units_compiled_the_same_way_share_one_variant() {
    let units = variants("cmake");
    assert_eq!(units.len(), 2, "the fixture no longer has two units");
    let partitions = partition(units);
    assert_eq!(
        partitions.len(),
        1,
        "two units of one library landed in different partitions: {:?}",
        partitions.values().map(|p| &p.units).collect::<Vec<_>>()
    );
    let only = partitions.values().next().unwrap();
    assert_eq!(only.units.len(), 2);
}

/// The case the C++ side exists for: one header, two translation units, two
/// meanings. A shared fragment found across these is not a duplication anyone
/// can remove, because the two copies are not the same code.
#[test]
fn one_header_read_two_ways_is_two_variants() {
    let units = variants("header-only");
    assert_eq!(units.len(), 2);
    let partitions = partition(units);
    assert_eq!(
        partitions.len(),
        2,
        "the two readings of the shared header were treated as one build"
    );
    for entry in partitions.values() {
        assert_eq!(entry.units.len(), 1);
    }
}

/// What separates them has to be the define, not an incidental difference in
/// the paths: a partition that splits for the wrong reason is right by accident
/// and stops being right as soon as the fixture is regenerated.
#[test]
fn what_separates_the_two_readings_is_the_define() {
    let commands = codehelion_fixtures::compile_commands("header-only").unwrap();
    let builds: Vec<CppBuild> = commands
        .iter()
        .map(|entry| CppBuild::from_command(&entry.arguments, Path::new(&entry.file)))
        .collect();
    assert_eq!(builds.len(), 2);
    assert_eq!(builds[0].include_paths, builds[1].include_paths);
    assert_eq!(builds[0].flags, builds[1].flags);
    assert_ne!(builds[0].macros, builds[1].macros);
    assert!(
        builds
            .iter()
            .any(|build| build.defines().contains(&"ACCUM_WIDTH=64")),
        "neither reading widens the accumulator"
    );
}

/// A database is where every unit's arguments come from, so it is part of what
/// they were built under — two runs reading different databases described
/// different builds even where the commands they hold happen to agree.
#[test]
fn the_database_a_unit_came_from_is_part_of_its_variant() {
    let with_database = variants("cmake");
    let without: Vec<BuildVariant> = codehelion_fixtures::compile_commands("cmake")
        .unwrap()
        .iter()
        .map(|entry| {
            BuildVariant::semantic(
                LanguageSelection::default(),
                Language::Cpp,
                BuildConfiguration::Cpp(Box::new(CppBuild::from_command(
                    &entry.arguments,
                    Path::new(&entry.file),
                ))),
            )
        })
        .collect();
    assert_ne!(with_database[0].0.fingerprint(), without[0].fingerprint());
}
