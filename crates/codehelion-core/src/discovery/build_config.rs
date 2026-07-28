//! What a compiler was told, in the form an identity is decided on.
//!
//! Two compilations of the same text are the same program only if the compiler
//! was told the same things. A define changes which branch of a header exists,
//! a feature changes which type a name resolves to, an optimization level
//! changes what the artifact contains. So the arguments are part of the variant
//! rather than context beside it, and a run that resolved them carries a
//! [`BuildConfiguration`].
//!
//! # What counts towards identity
//!
//! Everything, minus a short explicit exclusion list. The rule is deliberately
//! that way round: a flag wrongly included splits one variant into two, which
//! costs recall and is visible; a flag wrongly excluded merges two programs
//! into one identity, which produces confident findings about code that was
//! never compiled the same way and is not visible at all. The exclusion list
//! ([`EXCLUDED`], [`EXCLUDED_WITH_VALUE`]) is therefore short, and grows only
//! for arguments that provably cannot change what a compiler resolves —
//! diagnostic presentation, dependency-file bookkeeping, and the output path,
//! which would otherwise give every translation unit a variant of its own and
//! leave nothing to partition.
//!
//! # Where order is normalized, and where it is not
//!
//! Only where order provably does not matter. Macro settings are reduced to one
//! entry per macro — the state its last mention left it in, so that `-DX -UX`
//! and `-UX -DX` stay different — and then sorted by name, which makes the
//! order they were written in irrelevant. Include directories are a search
//! path, so their order is meaning and is preserved; sorting them would merge
//! two builds that find different headers under the same name. Remaining flags
//! keep their order too, because last-one-wins options like `-O1 -O2` are
//! common and nothing here can tell which flags those are.
//!
//! # Encoding
//!
//! The canonical form is length-prefixed rather than delimiter-separated.
//! Compiler arguments are arbitrary text and routinely contain the punctuation
//! a delimiter scheme would use: `-Dpair=a,b` and `-Dpair=a -Db` are different
//! builds that any comma-joined encoding reports as the same one. Prefixing
//! each value with its length makes the encoding injective whatever the values
//! contain.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// Arguments dropped from a compilation before it becomes an identity.
///
/// Each is either a statement about how to present diagnostics or about where
/// to write bookkeeping files. None can change what the compiler resolves.
pub const EXCLUDED: [&str; 8] = [
    "-c",
    "-M",
    "-MM",
    "-MD",
    "-MMD",
    "-MP",
    "-fcolor-diagnostics",
    "-fno-color-diagnostics",
];

/// Arguments dropped together with the value that follows them.
///
/// `-o` is here for a second reason: an object path is unique per translation
/// unit, so keeping it would give every unit its own variant and leave the
/// partition with one member each.
pub const EXCLUDED_WITH_VALUE: [&str; 4] = ["-o", "-MF", "-MT", "-MQ"];

/// A stable hex hash of a file's contents, for the build inputs that are
/// identified by what they say rather than by where they are.
#[must_use]
pub fn content_hash(text: &str) -> String {
    blake3::hash(text.as_bytes()).to_hex().to_string()
}

/// What a C or C++ translation unit was compiled with.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CppBuild {
    /// The compiler as the database spells it.
    pub compiler: String,
    /// Its version, which only something that ran it can know.
    pub compiler_version: Option<String>,
    /// The linker, for the variants that reach a link step.
    pub linker: Option<String>,
    /// One entry per macro, in the flag form its last mention left it in
    /// (`-DNAME=value` or `-UNAME`), sorted by macro name.
    pub macros: Vec<String>,
    /// Include directories in search order, without the `-I`.
    pub include_paths: Vec<String>,
    /// Everything else that was passed, in the order it was passed.
    pub flags: Vec<String>,
    /// A hash of the compilation database this came from.
    pub database_hash: Option<String>,
}

impl CppBuild {
    /// The identity of one entry of a compilation database.
    ///
    /// `file` is the translation unit's own source, which is dropped: it says
    /// which unit this is, not which variant it belongs to.
    #[must_use]
    pub fn from_command(arguments: &[String], file: &Path) -> Self {
        let mut build = Self {
            compiler: arguments.first().cloned().unwrap_or_default(),
            ..Self::default()
        };
        let mut macros = Vec::new();
        let mut index = 1;
        while index < arguments.len() {
            let argument = arguments[index].as_str();
            index += 1;
            if Path::new(argument) == file {
                continue;
            }
            if EXCLUDED_WITH_VALUE.contains(&argument) {
                index += 1;
                continue;
            }
            if EXCLUDED.contains(&argument) || argument.starts_with("-fdiagnostics-color") {
                continue;
            }
            match separated(argument, arguments.get(index).map(String::as_str)) {
                Some(Separated::Macro(setting, consumed)) => {
                    macros.push(setting);
                    index += usize::from(consumed);
                }
                Some(Separated::Include(path, consumed)) => {
                    build.include_paths.push(path);
                    index += usize::from(consumed);
                }
                None => build.flags.push(argument.to_string()),
            }
        }
        build.macros = last_mention_wins(macros);
        build
    }

    /// The macros left defined, without the `-D`.
    #[must_use]
    pub fn defines(&self) -> Vec<&str> {
        self.macros
            .iter()
            .filter_map(|setting| setting.strip_prefix("-D"))
            .collect()
    }

    fn encode(&self, out: &mut String) {
        scalar(out, "compiler", &self.compiler);
        optional(out, "compiler_version", self.compiler_version.as_deref());
        optional(out, "linker", self.linker.as_deref());
        list(out, "macros", &self.macros);
        list(out, "includes", &self.include_paths);
        list(out, "flags", &self.flags);
        optional(out, "database", self.database_hash.as_deref());
    }
}

/// What a Rust crate was built with.
///
/// Recorded rather than assumed: a helper analyses with the compiler it holds,
/// which need not be the one the project builds with, so the version here is
/// the one that produced the answers.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RustBuild {
    /// The target triple.
    pub target: String,
    /// Enabled cargo features, deduplicated and sorted: they are a set, and
    /// nothing about the order they were requested in reaches the compiler.
    pub features: Vec<String>,
    /// `--cfg` settings, deduplicated and sorted for the same reason.
    pub cfgs: Vec<String>,
    /// The compiler that produced the answers.
    pub compiler_version: String,
    /// Optimization level, as cargo spells it.
    pub opt_level: String,
    /// Link-time optimization setting.
    pub lto: String,
    /// Codegen units, when pinned.
    pub codegen_units: Option<u32>,
    /// Panic strategy.
    pub panic: String,
    /// A hash of `Cargo.lock`: the dependency versions are part of what the
    /// source means, and the lockfile is the only place that records them all.
    pub lockfile_hash: Option<String>,
    /// A hash of the command the build was requested with.
    pub build_command_hash: Option<String>,
}

impl RustBuild {
    /// The same build with its features and cfgs reduced to sets.
    #[must_use]
    pub fn normalized(mut self) -> Self {
        self.features = self
            .features
            .into_iter()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        self.cfgs = self
            .cfgs
            .into_iter()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        self
    }

    fn encode(&self, out: &mut String) {
        scalar(out, "target", &self.target);
        list(out, "features", &self.features);
        list(out, "cfgs", &self.cfgs);
        scalar(out, "compiler_version", &self.compiler_version);
        scalar(out, "opt_level", &self.opt_level);
        scalar(out, "lto", &self.lto);
        optional(
            out,
            "codegen_units",
            self.codegen_units.map(|units| units.to_string()).as_deref(),
        );
        scalar(out, "panic", &self.panic);
        optional(out, "lockfile", self.lockfile_hash.as_deref());
        optional(out, "build_command", self.build_command_hash.as_deref());
    }
}

/// The build configuration a variant was resolved under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuildConfiguration {
    /// A Rust crate.
    Rust(Box<RustBuild>),
    /// A C or C++ translation unit.
    Cpp(Box<CppBuild>),
}

impl BuildConfiguration {
    /// The canonical, injective encoding of this configuration.
    ///
    /// Two configurations produce the same string exactly when they are equal,
    /// whatever punctuation their arguments contain.
    #[must_use]
    pub fn canonical(&self) -> String {
        let mut out = String::new();
        match self {
            Self::Rust(build) => {
                scalar(&mut out, "language", "rust");
                build.encode(&mut out);
            }
            Self::Cpp(build) => {
                scalar(&mut out, "language", "cpp");
                build.encode(&mut out);
            }
        }
        out
    }

    /// A stable hex fingerprint of the canonical form.
    #[must_use]
    pub fn fingerprint(&self) -> String {
        blake3::hash(self.canonical().as_bytes())
            .to_hex()
            .to_string()
    }
}

/// An argument that may carry its value in the next position.
enum Separated {
    /// A macro setting, and whether the next argument was consumed.
    Macro(String, bool),
    /// An include directory, and whether the next argument was consumed.
    Include(String, bool),
}

/// Classifies `argument`, reading `next` only for the separated spellings
/// (`-D NAME` beside `-DNAME`), which both compilers accept.
fn separated(argument: &str, next: Option<&str>) -> Option<Separated> {
    for prefix in ["-D", "-U"] {
        if let Some(rest) = argument.strip_prefix(prefix) {
            return Some(if rest.is_empty() {
                Separated::Macro(format!("{prefix}{}", next.unwrap_or_default()), true)
            } else {
                Separated::Macro(argument.to_string(), false)
            });
        }
    }
    if let Some(rest) = argument.strip_prefix("-I") {
        return Some(if rest.is_empty() {
            Separated::Include(next.unwrap_or_default().to_string(), true)
        } else {
            Separated::Include(rest.to_string(), false)
        });
    }
    None
}

/// One entry per macro, keeping the last mention and sorting by name.
///
/// Last mention rather than first because that is what the preprocessor does,
/// and keeping `-D` and `-U` in the same reduction is what makes `-DX -UX`
/// and `-UX -DX` two identities rather than one.
fn last_mention_wins(settings: Vec<String>) -> Vec<String> {
    let mut latest: BTreeMap<String, String> = BTreeMap::new();
    for setting in settings {
        let name = setting
            .trim_start_matches("-D")
            .trim_start_matches("-U")
            .split('=')
            .next()
            .unwrap_or_default()
            .to_string();
        latest.insert(name, setting);
    }
    latest.into_values().collect()
}

fn scalar(out: &mut String, name: &str, value: &str) {
    out.push_str(name);
    out.push('=');
    push_sized(out, value);
    out.push(';');
}

fn optional(out: &mut String, name: &str, value: Option<&str>) {
    out.push_str(name);
    out.push('=');
    match value {
        Some(value) => {
            out.push_str("some");
            push_sized(out, value);
        }
        // Distinct from a present empty value, which is a different claim.
        None => out.push_str("none"),
    }
    out.push(';');
}

fn list(out: &mut String, name: &str, values: &[String]) {
    out.push_str(name);
    out.push('=');
    out.push_str(&values.len().to_string());
    out.push('[');
    for value in values {
        push_sized(out, value);
    }
    out.push_str("];");
}

fn push_sized(out: &mut String, value: &str) {
    out.push_str(&value.len().to_string());
    out.push(':');
    out.push_str(value);
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn command(arguments: &[&str]) -> Vec<String> {
        arguments.iter().map(|a| (*a).to_string()).collect()
    }

    fn cpp(arguments: &[&str], file: &str) -> CppBuild {
        CppBuild::from_command(&command(arguments), Path::new(file))
    }

    #[test]
    fn the_compiler_and_what_it_was_told_are_read_off_the_command() {
        let build = cpp(
            &[
                "clang++",
                "-std=c++17",
                "-DACCUM_WIDTH=64",
                "-I/w/include",
                "-c",
                "-o",
                "wide.o",
                "/w/src/wide.cpp",
            ],
            "/w/src/wide.cpp",
        );
        assert_eq!(build.compiler, "clang++");
        assert_eq!(build.macros, vec!["-DACCUM_WIDTH=64"]);
        assert_eq!(build.include_paths, vec!["/w/include"]);
        assert_eq!(build.flags, vec!["-std=c++17"]);
        assert_eq!(build.defines(), vec!["ACCUM_WIDTH=64"]);
    }

    /// The output path is unique per unit. Keeping it would give every
    /// translation unit its own variant, which is the same as having none.
    #[test]
    fn the_object_path_does_not_become_part_of_the_identity() {
        let narrow = cpp(&["cc", "-O2", "-o", "a/narrow.o", "-c", "/w/a.c"], "/w/a.c");
        let wide = cpp(&["cc", "-O2", "-o", "b/wide.o", "-c", "/w/a.c"], "/w/a.c");
        assert_eq!(narrow, wide);
        assert!(narrow.flags.iter().all(|flag| !flag.contains("narrow.o")));
    }

    #[test]
    fn dependency_bookkeeping_and_diagnostic_colour_are_not_identity() {
        let plain = cpp(&["cc", "-O2", "/w/a.c"], "/w/a.c");
        let noisy = cpp(
            &[
                "cc",
                "-O2",
                "-MD",
                "-MF",
                "a.d",
                "-MT",
                "a.o",
                "-fcolor-diagnostics",
                "-fdiagnostics-color=always",
                "/w/a.c",
            ],
            "/w/a.c",
        );
        assert_eq!(plain, noisy);
    }

    /// An unrecognised flag is kept. The exclusion list is the whole of what is
    /// dropped, because a flag wrongly dropped merges two programs into one
    /// identity and nothing downstream can notice.
    #[test]
    fn an_unrecognised_flag_counts_towards_identity() {
        let plain = cpp(&["cc", "/w/a.c"], "/w/a.c");
        let odd = cpp(&["cc", "-fsomething-nobody-here-knows", "/w/a.c"], "/w/a.c");
        assert_ne!(plain, odd);
        assert_eq!(odd.flags, vec!["-fsomething-nobody-here-knows"]);
    }

    #[test]
    fn the_separated_spellings_mean_the_same_as_the_joined_ones() {
        let joined = cpp(&["cc", "-DWIDTH=64", "-I/w/inc", "/w/a.c"], "/w/a.c");
        let separated = cpp(
            &["cc", "-D", "WIDTH=64", "-I", "/w/inc", "/w/a.c"],
            "/w/a.c",
        );
        assert_eq!(joined, separated);
    }

    /// Macro order is not meaning, so it is normalized away — but only after
    /// the last mention has won, which is what the preprocessor does.
    #[test]
    fn macros_are_sorted_but_the_last_mention_still_decides() {
        let one = cpp(&["cc", "-DB=2", "-DA=1", "/w/a.c"], "/w/a.c");
        let other = cpp(&["cc", "-DA=1", "-DB=2", "/w/a.c"], "/w/a.c");
        assert_eq!(one, other);
        assert_eq!(one.macros, vec!["-DA=1", "-DB=2"]);

        let redefined = cpp(&["cc", "-DA=1", "-DA=2", "/w/a.c"], "/w/a.c");
        assert_eq!(redefined.macros, vec!["-DA=2"]);
    }

    /// Sorting a define beside an undefine of the same macro would lose which
    /// one the compiler saw last, and those are two different programs.
    #[test]
    fn defining_then_undefining_is_not_the_same_as_the_reverse() {
        let defined_last = cpp(&["cc", "-UA", "-DA=1", "/w/a.c"], "/w/a.c");
        let undefined_last = cpp(&["cc", "-DA=1", "-UA", "/w/a.c"], "/w/a.c");
        assert_ne!(defined_last, undefined_last);
        assert_eq!(defined_last.macros, vec!["-DA=1"]);
        assert_eq!(undefined_last.macros, vec!["-UA"]);
    }

    /// Include directories are a search order. Two builds that reach different
    /// headers under the same name are not one variant.
    #[test]
    fn include_order_is_meaning_and_is_kept() {
        let vendor_first = cpp(&["cc", "-I/vendor", "-I/local", "/w/a.c"], "/w/a.c");
        let local_first = cpp(&["cc", "-I/local", "-I/vendor", "/w/a.c"], "/w/a.c");
        assert_ne!(vendor_first, local_first);
        assert_eq!(vendor_first.include_paths, vec!["/vendor", "/local"]);
    }

    /// A delimiter-joined encoding reports these two as the same build. The
    /// length prefix is what keeps them apart.
    #[test]
    fn punctuation_inside_an_argument_cannot_forge_another_argument() {
        let one = cpp(&["cc", "-Dpair=a,b", "/w/a.c"], "/w/a.c");
        let two = cpp(&["cc", "-Dpair=a", "-Db", "/w/a.c"], "/w/a.c");
        let one = BuildConfiguration::Cpp(Box::new(one));
        let two = BuildConfiguration::Cpp(Box::new(two));
        assert_ne!(one.canonical(), two.canonical());
        assert_ne!(one.fingerprint(), two.fingerprint());
    }

    #[test]
    fn an_absent_value_is_not_an_empty_one() {
        let absent = BuildConfiguration::Cpp(Box::new(CppBuild {
            compiler: "cc".into(),
            compiler_version: None,
            ..CppBuild::default()
        }));
        let empty = BuildConfiguration::Cpp(Box::new(CppBuild {
            compiler: "cc".into(),
            compiler_version: Some(String::new()),
            ..CppBuild::default()
        }));
        assert_ne!(absent.fingerprint(), empty.fingerprint());
    }

    #[test]
    fn the_fingerprint_is_a_function_of_the_configuration_alone() {
        let build = || {
            BuildConfiguration::Cpp(Box::new(cpp(
                &["clang++", "-std=c++17", "-DA=1", "/w/a.c"],
                "/w/a.c",
            )))
        };
        assert_eq!(build().fingerprint(), build().fingerprint());
    }

    #[test]
    fn rust_features_are_a_set_and_are_ordered_like_one() {
        let one = RustBuild {
            features: vec!["wide".into(), "serde".into(), "wide".into()],
            ..RustBuild::default()
        }
        .normalized();
        let other = RustBuild {
            features: vec!["serde".into(), "wide".into()],
            ..RustBuild::default()
        }
        .normalized();
        assert_eq!(one, other);
        assert_eq!(one.features, vec!["serde", "wide"]);
    }

    /// Two runs of the same source under different dependency versions are not
    /// comparable, and the lockfile is the only record of what those were.
    #[test]
    fn a_different_lockfile_is_a_different_build() {
        let base = RustBuild {
            target: "aarch64-apple-darwin".into(),
            compiler_version: "rustc 1.85.0".into(),
            lockfile_hash: Some(content_hash("one")),
            ..RustBuild::default()
        };
        let moved = RustBuild {
            lockfile_hash: Some(content_hash("another")),
            ..base.clone()
        };
        assert_ne!(
            BuildConfiguration::Rust(Box::new(base)).fingerprint(),
            BuildConfiguration::Rust(Box::new(moved)).fingerprint()
        );
    }

    /// A Rust build and a C++ build cannot collide however their fields line
    /// up, because the language is part of what is hashed.
    #[test]
    fn the_two_languages_are_in_different_identity_spaces() {
        let rust = BuildConfiguration::Rust(Box::default());
        let cpp = BuildConfiguration::Cpp(Box::default());
        assert_ne!(rust.fingerprint(), cpp.fingerprint());
    }
}
