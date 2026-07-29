//! Build variants: the first-class context every result is attributed to.
//!
//! A [`BuildVariant`] records the analysis mode, the enabled languages, the
//! grammar bare `.h` headers were read with and the normalization ruleset
//! version. Results produced under different variants must never be compared
//! or merged, so the variant is attached to discovery output from the start
//! rather than bolted on later. In Fast mode no build configuration is
//! resolved, so a single implicit variant covers the whole run.

use std::collections::BTreeMap;

use super::build_config::BuildConfiguration;
use super::language::{Language, LanguageSelection};

/// Version of the lexing/normalization ruleset.
///
/// Bump this on any change that alters how sources are tokenised or normalised,
/// so that fingerprints and cached results from an older ruleset are not
/// silently treated as compatible.
pub const NORMALIZATION_VERSION: u32 = 2;

/// The analysis mode a run was performed under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnalysisMode {
    /// Lexical analysis only; the target code is never executed.
    Fast,
    /// Structural (AST-level) analysis; the target code is never executed.
    Structural,
    /// Semantic analysis, using out-of-process compiler helpers.
    Semantic,
}

impl AnalysisMode {
    /// Stable lowercase identifier used in reports and fingerprints.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Fast => "fast",
            Self::Structural => "structural",
            Self::Semantic => "semantic",
        }
    }
}

/// The context a set of results belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildVariant {
    /// Analysis mode.
    pub mode: AnalysisMode,
    /// Languages enabled for the run.
    pub languages: LanguageSelection,
    /// The language bare `.h` headers were read as, when C or C++ is enabled
    /// at all. Two runs that read the same header with different grammars see
    /// different code in it, so this belongs to the variant rather than
    /// alongside it.
    pub headers: Option<Language>,
    /// Normalization ruleset version.
    pub normalization_version: u32,
    /// What each compiler was told, for the runs that resolved it.
    ///
    /// Empty in Fast and Structural mode, which read source and ask no
    /// compiler anything: there is no build configuration to differ over, so a
    /// single implicit variant covers the run.
    ///
    /// A list because a tree is answered by one compiler per language, and a
    /// run of a tree holding both is one run: what either compiler was told is
    /// part of what its results mean, and a variant that named only one of them
    /// would give two differently built trees the same identity. Sorted by
    /// fingerprint when the variant is made, so that the order helpers happened
    /// to be reached in — an accident of what is installed — cannot move it.
    pub builds: Vec<BuildConfiguration>,
}

impl BuildVariant {
    /// The implicit single variant used by a Fast-mode run over `languages`,
    /// reading bare `.h` headers as `headers`.
    #[must_use]
    pub const fn fast(languages: LanguageSelection, headers: Language) -> Self {
        Self {
            mode: AnalysisMode::Fast,
            languages,
            headers: Self::headers_of(languages, headers),
            normalization_version: NORMALIZATION_VERSION,
            builds: Vec::new(),
        }
    }

    /// The implicit single variant used by a Structural-mode run over
    /// `languages`. Like Fast mode, Structural resolves no build configuration,
    /// so one implicit variant covers the run; only the mode differs, which is
    /// enough to keep Fast and Structural fingerprints in separate spaces.
    #[must_use]
    pub const fn structural(languages: LanguageSelection, headers: Language) -> Self {
        Self {
            mode: AnalysisMode::Structural,
            languages,
            headers: Self::headers_of(languages, headers),
            normalization_version: NORMALIZATION_VERSION,
            builds: Vec::new(),
        }
    }

    /// The variant a semantic run analyses one unit under.
    ///
    /// Unlike Fast and Structural, semantic mode has as many variants as the
    /// project has build configurations: a crate under two feature sets and a
    /// header under two sets of defines are different programs that happen to
    /// share their text.
    #[must_use]
    pub fn semantic(
        languages: LanguageSelection,
        headers: Language,
        mut builds: Vec<BuildConfiguration>,
    ) -> Self {
        builds.sort_by_cached_key(BuildConfiguration::fingerprint);
        Self {
            mode: AnalysisMode::Semantic,
            languages,
            headers: Self::headers_of(languages, headers),
            normalization_version: NORMALIZATION_VERSION,
            builds,
        }
    }

    /// The header language worth recording: none when the run enumerates
    /// neither C nor C++, so that a Rust-only scan keeps one variant whatever
    /// C or C++ files happen to sit beside it.
    const fn headers_of(languages: LanguageSelection, headers: Language) -> Option<Language> {
        if languages.includes(Language::C) || languages.includes(Language::Cpp) {
            Some(headers)
        } else {
            None
        }
    }

    /// A canonical, order-stable string describing this variant.
    ///
    /// Two variants are equal exactly when their canonical strings match, which
    /// makes this string safe to use as a grouping key or fingerprint input.
    ///
    /// A resolved build configuration is appended as its fingerprint rather
    /// than its own canonical form: compiler arguments are arbitrary text and
    /// would otherwise be free to contain this string's own separators. Several
    /// are appended comma-separated, which is safe for the same reason it is
    /// not safe for the arguments themselves — a fingerprint is fixed-width hex
    /// and holds no punctuation to be mistaken for a separator.
    ///
    /// Appended only when the run resolved something, so that the modes which
    /// resolve nothing keep the identity they had before the field existed —
    /// an audit database written by an earlier build still lines up with one
    /// written by this one. A run that resolved exactly one configuration keeps
    /// its identity too, which is what stops the field growing a list from
    /// re-identifying every Rust-only tree already recorded.
    #[must_use]
    pub fn canonical(&self) -> String {
        let langs = self
            .languages
            .enabled()
            .into_iter()
            .map(Language::name)
            .collect::<Vec<_>>()
            .join(",");
        let mut canonical = format!(
            "mode={};languages={};headers={};normalization={}",
            self.mode.name(),
            langs,
            self.headers.map_or("none", Language::name),
            self.normalization_version,
        );
        if !self.builds.is_empty() {
            canonical.push_str(";build=");
            canonical.push_str(
                &self
                    .builds
                    .iter()
                    .map(BuildConfiguration::fingerprint)
                    .collect::<Vec<_>>()
                    .join(","),
            );
        }
        canonical
    }

    /// A stable hex fingerprint of this variant.
    #[must_use]
    pub fn fingerprint(&self) -> String {
        blake3::hash(self.canonical().as_bytes())
            .to_hex()
            .to_string()
    }
}

/// One variant and everything analysed under it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Partition<T> {
    /// The variant these were analysed under.
    pub variant: BuildVariant,
    /// The units, in the order they were given.
    pub units: Vec<T>,
}

/// Groups units by the variant they were analysed under.
///
/// Clone comparison runs inside one partition by default. Two units compiled
/// differently are not two spellings of one thing: the text they share may
/// resolve to different types, take different branches of a header, or exist in
/// only one of the two builds, and a duplication reported across them cannot be
/// removed by editing either one.
///
/// Keyed by variant fingerprint so that the grouping is stable across runs and
/// independent of the order units were discovered in.
#[must_use]
pub fn partition<T>(
    units: impl IntoIterator<Item = (BuildVariant, T)>,
) -> BTreeMap<String, Partition<T>> {
    let mut partitions: BTreeMap<String, Partition<T>> = BTreeMap::new();
    for (variant, unit) in units {
        partitions
            .entry(variant.fingerprint())
            .or_insert_with(|| Partition {
                variant,
                units: Vec::new(),
            })
            .units
            .push(unit);
    }
    partitions
}

#[cfg(test)]
mod tests {
    use super::super::build_config::{CppBuild, RustBuild};
    use super::*;

    #[test]
    fn fast_variant_carries_mode_and_normalization_version() {
        let variant = BuildVariant::fast(LanguageSelection::default(), Language::C);
        assert_eq!(variant.mode, AnalysisMode::Fast);
        assert_eq!(variant.normalization_version, NORMALIZATION_VERSION);
    }

    #[test]
    fn structural_variant_differs_from_fast_only_in_mode() {
        let languages = LanguageSelection::default();
        let fast = BuildVariant::fast(languages, Language::C);
        let structural = BuildVariant::structural(languages, Language::C);
        assert_eq!(structural.mode, AnalysisMode::Structural);
        assert_eq!(structural.languages, fast.languages);
        assert_eq!(structural.headers, fast.headers);
        assert_eq!(structural.normalization_version, fast.normalization_version);
        // Distinct modes must land in distinct fingerprint spaces.
        assert_ne!(fast.fingerprint(), structural.fingerprint());
    }

    #[test]
    fn canonical_reflects_enabled_languages_in_fixed_order() {
        let variant = BuildVariant::fast(
            LanguageSelection {
                rust: true,
                c: false,
                cpp: true,
            },
            Language::Cpp,
        );
        assert_eq!(
            variant.canonical(),
            "mode=fast;languages=rust,cpp;headers=cpp;normalization=2"
        );
    }

    #[test]
    fn distinct_variants_have_distinct_fingerprints() {
        let all = BuildVariant::fast(LanguageSelection::default(), Language::C);
        let rust_only = BuildVariant::fast(
            LanguageSelection {
                rust: true,
                c: false,
                cpp: false,
            },
            Language::C,
        );
        assert_ne!(all.fingerprint(), rust_only.fingerprint());
        // Fingerprint is a pure function of the canonical form.
        assert_eq!(
            all.fingerprint(),
            BuildVariant::fast(LanguageSelection::default(), Language::C).fingerprint()
        );
    }

    #[test]
    fn reading_headers_with_a_different_grammar_is_a_different_variant() {
        // The two runs see different code in the same header, so their
        // findings are not comparable and must not share a fingerprint space.
        let languages = LanguageSelection::default();
        let as_c = BuildVariant::fast(languages, Language::C);
        let as_cpp = BuildVariant::fast(languages, Language::Cpp);
        assert_ne!(as_c, as_cpp);
        assert_ne!(as_c.fingerprint(), as_cpp.fingerprint());
    }

    #[test]
    fn a_run_that_enumerates_no_c_records_no_header_grammar() {
        // A Rust-only scan reads no headers, so its variant must not move
        // because the tree happens to hold more `.cpp` than `.c` files.
        let rust_only = LanguageSelection {
            rust: true,
            c: false,
            cpp: false,
        };
        let with_c = BuildVariant::fast(rust_only, Language::C);
        let with_cpp = BuildVariant::fast(rust_only, Language::Cpp);
        assert_eq!(with_c.headers, None);
        assert_eq!(with_c, with_cpp);
        assert_eq!(
            with_c.canonical(),
            "mode=fast;languages=rust;headers=none;normalization=2"
        );
    }

    /// A mode that resolves no build configuration must keep the identity it
    /// had before variants could carry one, or every stored run stops lining up
    /// with the runs that follow it.
    #[test]
    fn a_run_that_resolved_no_build_configuration_is_identified_as_it_always_was() {
        let variant = BuildVariant::fast(LanguageSelection::default(), Language::C);
        assert!(variant.builds.is_empty());
        assert!(
            !variant.canonical().contains("build="),
            "{}",
            variant.canonical()
        );
    }

    #[test]
    fn two_builds_of_one_source_tree_are_two_variants() {
        let languages = LanguageSelection::default();
        let narrow = BuildVariant::semantic(
            languages,
            Language::Cpp,
            vec![BuildConfiguration::Cpp(Box::new(CppBuild {
                compiler: "clang++".into(),
                ..CppBuild::default()
            }))],
        );
        let wide = BuildVariant::semantic(
            languages,
            Language::Cpp,
            vec![BuildConfiguration::Cpp(Box::new(CppBuild {
                compiler: "clang++".into(),
                macros: vec!["-DACCUM_WIDTH=64".into()],
                ..CppBuild::default()
            }))],
        );
        assert_ne!(narrow, wide);
        assert_ne!(narrow.fingerprint(), wide.fingerprint());
    }

    /// A tree holding both languages is answered by both helpers, and the run
    /// is one run: the variant names what each was told, because results that
    /// came out of two compilers mean what both of them were told.
    #[test]
    fn a_tree_answered_by_two_compilers_is_one_variant_naming_both() {
        let languages = LanguageSelection::default();
        let rust = BuildConfiguration::Rust(Box::new(RustBuild {
            compiler_version: "rustc 1.85.0".into(),
            ..RustBuild::default()
        }));
        let cpp = BuildConfiguration::Cpp(Box::new(CppBuild {
            compiler: "clang++".into(),
            ..CppBuild::default()
        }));
        let both =
            BuildVariant::semantic(languages, Language::Cpp, vec![rust.clone(), cpp.clone()]);
        let rust_only = BuildVariant::semantic(languages, Language::Cpp, vec![rust]);
        assert_eq!(both.builds.len(), 2);
        assert_ne!(both.fingerprint(), rust_only.fingerprint());
        assert!(
            both.canonical().contains(&cpp.fingerprint()),
            "{}",
            both.canonical()
        );
    }

    /// Which helper was reached first is a fact about the machine, not about
    /// the tree. A variant that moved with it would give one project two
    /// identities across two installations and compare neither with the other.
    #[test]
    fn the_order_the_compilers_were_reached_in_is_not_part_of_the_identity() {
        let languages = LanguageSelection::default();
        let rust = || BuildConfiguration::Rust(Box::default());
        let cpp = || BuildConfiguration::Cpp(Box::default());
        let one = BuildVariant::semantic(languages, Language::Cpp, vec![rust(), cpp()]);
        let other = BuildVariant::semantic(languages, Language::Cpp, vec![cpp(), rust()]);
        assert_eq!(one, other);
        assert_eq!(one.fingerprint(), other.fingerprint());
    }

    /// Half a tree built differently is a differently built tree. The Rust side
    /// resolving the same way says nothing about whether the C++ results can be
    /// compared with the ones recorded before.
    #[test]
    fn one_language_building_differently_moves_the_whole_run() {
        let languages = LanguageSelection::default();
        let variant = |macros: Vec<String>| {
            BuildVariant::semantic(
                languages,
                Language::Cpp,
                vec![
                    BuildConfiguration::Rust(Box::default()),
                    BuildConfiguration::Cpp(Box::new(CppBuild {
                        compiler: "clang++".into(),
                        macros,
                        ..CppBuild::default()
                    })),
                ],
            )
        };
        assert_ne!(
            variant(Vec::new()).fingerprint(),
            variant(vec!["-DACCUM_WIDTH=64".into()]).fingerprint()
        );
    }

    /// A run that resolved exactly one configuration keeps the identity it had
    /// before a variant could hold several, or every semantic run already
    /// recorded stops lining up with the runs that follow it.
    #[test]
    fn resolving_one_configuration_identifies_a_run_as_it_always_did() {
        let build = BuildConfiguration::Rust(Box::default());
        let variant = BuildVariant::semantic(
            LanguageSelection::default(),
            Language::Cpp,
            vec![build.clone()],
        );
        assert!(
            variant
                .canonical()
                .ends_with(&format!(";build={}", build.fingerprint())),
            "{}",
            variant.canonical()
        );
    }

    /// The languages are separate identity spaces one level down as well, so a
    /// Rust variant and a C++ variant cannot collide by having equally empty
    /// build configurations.
    #[test]
    fn a_rust_variant_and_a_cpp_variant_are_never_the_same_variant() {
        let languages = LanguageSelection::default();
        let rust = BuildVariant::semantic(
            languages,
            Language::Cpp,
            vec![BuildConfiguration::Rust(Box::default())],
        );
        let cpp = BuildVariant::semantic(
            languages,
            Language::Cpp,
            vec![BuildConfiguration::Cpp(Box::default())],
        );
        assert_ne!(rust.fingerprint(), cpp.fingerprint());
    }

    #[test]
    fn units_are_grouped_by_the_variant_they_were_analysed_under() {
        let languages = LanguageSelection::default();
        let variant = |macros: Vec<String>| {
            BuildVariant::semantic(
                languages,
                Language::Cpp,
                vec![BuildConfiguration::Cpp(Box::new(CppBuild {
                    compiler: "clang++".into(),
                    macros,
                    ..CppBuild::default()
                }))],
            )
        };
        let narrow = variant(Vec::new());
        let wide = variant(vec!["-DACCUM_WIDTH=64".into()]);
        let partitions = partition([
            (narrow.clone(), "narrow.cpp"),
            (wide.clone(), "wide.cpp"),
            (narrow.clone(), "also-narrow.cpp"),
        ]);
        assert_eq!(partitions.len(), 2);
        assert_eq!(
            partitions[&narrow.fingerprint()].units,
            vec!["narrow.cpp", "also-narrow.cpp"]
        );
        assert_eq!(partitions[&wide.fingerprint()].units, vec!["wide.cpp"]);
    }

    /// The grouping is a property of the variants, not of the order units
    /// happened to be discovered in.
    #[test]
    fn the_grouping_does_not_depend_on_the_order_units_arrive_in() {
        let languages = LanguageSelection::default();
        let fast = BuildVariant::fast(languages, Language::C);
        let structural = BuildVariant::structural(languages, Language::C);
        let forwards = partition([(fast.clone(), 1), (structural.clone(), 2)]);
        let backwards = partition([(structural, 2), (fast, 1)]);
        assert_eq!(
            forwards.keys().collect::<Vec<_>>(),
            backwards.keys().collect::<Vec<_>>()
        );
    }
}
