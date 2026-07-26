//! Language classification of source files by extension.
//!
//! Classification is filename-based. The one genuinely ambiguous case is the
//! bare `.h` extension, which C and C++ share; the caller picks a
//! [`HeaderPolicy`] to resolve it. Extensions that unambiguously belong to C++
//! by convention (capitalised `.C`/`.H`, `.hpp`, `.cxx`, ...) are classified
//! directly regardless of the policy.
//!
//! # Why `.h` is worth resolving rather than assuming
//!
//! The grammar a header is read with decides what the analysis can see in it.
//! Reading a C++ header with the C grammar does not merely lose the C++-only
//! declarations: error recovery reshapes what surrounds them, so the damage
//! spreads past the construct that caused it. Measured over one C++ project's
//! 9,627 bare headers, the C grammar left 38.5% of their bytes inside error
//! regions where the C++ grammar left 25.9%.
//!
//! [`HeaderPolicy::Detect`] therefore settles `.h` from the files whose
//! extension is not in doubt — see [`HeaderEvidence`]. It is one decision per
//! run, not one per file: a header's language is part of the build variant
//! every result is attributed to, and two copies of the same code must not
//! land in different languages because one of them happened to parse better.

use std::path::Path;

/// A source language codehelion can enumerate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Language {
    /// Rust.
    Rust,
    /// C.
    C,
    /// C++.
    Cpp,
}

impl Language {
    /// Stable lowercase identifier used in reports and fingerprints.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Rust => "rust",
            Self::C => "c",
            Self::Cpp => "cpp",
        }
    }
}

/// How to classify a bare `.h` header, which C and C++ share.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HeaderPolicy {
    /// Treat `.h` as C.
    C,
    /// Treat `.h` as C++.
    Cpp,
    /// Settle `.h` from the rest of the tree, by [`HeaderEvidence`].
    #[default]
    Detect,
}

impl HeaderPolicy {
    /// Stable lowercase identifier used in reports and configuration.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::C => "c",
            Self::Cpp => "cpp",
            Self::Detect => "detect",
        }
    }
}

/// A tally of the files whose extension names their language outright, used to
/// settle the bare `.h` headers whose extension does not.
///
/// The rule is the plain reading of a mixed tree: a project written mostly in
/// C++ spells its headers `.h` because the extension is conventional, not
/// because those headers are C. A project written mostly in C means C.
///
/// Only unambiguous extensions count, so the headers being settled never vote
/// on their own language, and the verdict does not depend on how many of them
/// there are.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HeaderEvidence {
    c: usize,
    cpp: usize,
}

impl HeaderEvidence {
    /// Count one classified file, ignoring the ones that prove nothing:
    /// Rust sources, and the `.h` headers awaiting this verdict.
    pub const fn observe(&mut self, classification: Classification) {
        if classification.provisional {
            return;
        }
        match classification.language {
            Language::C => self.c += 1,
            Language::Cpp => self.cpp += 1,
            Language::Rust => {}
        }
    }

    /// The language to read bare `.h` headers as.
    ///
    /// C++ only when the tree holds strictly more unambiguous C++ files than C
    /// ones, so a tree that offers no evidence — no C or C++ sources at all —
    /// settles on C, the narrower of the two grammars.
    #[must_use]
    pub const fn verdict(self) -> Language {
        if self.cpp > self.c {
            Language::Cpp
        } else {
            Language::C
        }
    }
}

/// The languages a discovery run is allowed to enumerate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LanguageSelection {
    /// Include Rust sources.
    pub rust: bool,
    /// Include C sources.
    pub c: bool,
    /// Include C++ sources.
    pub cpp: bool,
}

impl Default for LanguageSelection {
    fn default() -> Self {
        Self {
            rust: true,
            c: true,
            cpp: true,
        }
    }
}

impl LanguageSelection {
    /// Whether `language` is enabled in this selection.
    #[must_use]
    pub const fn includes(self, language: Language) -> bool {
        match language {
            Language::Rust => self.rust,
            Language::C => self.c,
            Language::Cpp => self.cpp,
        }
    }

    /// The enabled languages in a fixed order, for stable serialisation.
    #[must_use]
    pub fn enabled(self) -> Vec<Language> {
        let mut out = Vec::new();
        if self.rust {
            out.push(Language::Rust);
        }
        if self.c {
            out.push(Language::C);
        }
        if self.cpp {
            out.push(Language::Cpp);
        }
        out
    }
}

/// The result of classifying one file: its language and whether it is a header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Classification {
    /// The detected language.
    pub language: Language,
    /// Whether the file is a header (declarations) rather than a translation
    /// unit. Always `false` for Rust.
    pub is_header: bool,
    /// Whether [`language`](Self::language) is a placeholder awaiting the
    /// tree-wide verdict, rather than a reading of the extension. Only ever
    /// true for a bare `.h` under [`HeaderPolicy::Detect`].
    pub provisional: bool,
}

impl Classification {
    /// The same classification with a settled language, for a header the
    /// policy left to detection. Anything already settled is returned as is.
    #[must_use]
    pub const fn settled(self, language: Language) -> Self {
        if self.provisional {
            Self {
                language,
                is_header: self.is_header,
                provisional: false,
            }
        } else {
            self
        }
    }
}

/// Classify `path` by its extension, returning `None` for unsupported files.
///
/// The bare `.h` extension is resolved with `header_policy`; all other
/// extensions map unambiguously. Under [`HeaderPolicy::Detect`] a `.h` comes
/// back `provisional`, carrying C as a placeholder until
/// [`HeaderEvidence::verdict`] settles it.
#[must_use]
pub(super) fn classify(path: &Path, header_policy: HeaderPolicy) -> Option<Classification> {
    // Match the raw extension: capitalisation is meaningful (`.C`/`.H` are the
    // classic C++ spellings), so it is not lowercased first.
    let ext = path.extension()?.to_str()?;
    let (language, is_header, provisional) = match ext {
        "rs" => (Language::Rust, false, false),
        "c" => (Language::C, false, false),
        "h" => match header_policy {
            HeaderPolicy::C => (Language::C, true, false),
            HeaderPolicy::Cpp => (Language::Cpp, true, false),
            HeaderPolicy::Detect => (Language::C, true, true),
        },
        "cc" | "cpp" | "cxx" | "c++" | "C" => (Language::Cpp, false, false),
        "hpp" | "hh" | "hxx" | "h++" | "H" | "tpp" | "ipp" | "inl" => (Language::Cpp, true, false),
        _ => return None,
    };
    Some(Classification {
        language,
        is_header,
        provisional,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn classify_str(name: &str, policy: HeaderPolicy) -> Option<Classification> {
        classify(&PathBuf::from(name), policy)
    }

    #[test]
    fn rust_and_c_sources_classify_by_extension() {
        assert_eq!(
            classify_str("a/b/main.rs", HeaderPolicy::C),
            Some(Classification {
                language: Language::Rust,
                is_header: false,
                provisional: false,
            })
        );
        assert_eq!(
            classify_str("lib.c", HeaderPolicy::C),
            Some(Classification {
                language: Language::C,
                is_header: false,
                provisional: false,
            })
        );
    }

    #[test]
    fn cpp_extensions_are_cpp_regardless_of_policy() {
        for name in ["a.cpp", "a.cc", "a.cxx", "a.C", "a.hpp", "a.H"] {
            let cls = classify_str(name, HeaderPolicy::C).expect("classified");
            assert_eq!(cls.language, Language::Cpp, "{name}");
        }
    }

    #[test]
    fn bare_h_follows_the_header_policy() {
        assert_eq!(
            classify_str("a.h", HeaderPolicy::C).map(|c| c.language),
            Some(Language::C)
        );
        assert_eq!(
            classify_str("a.h", HeaderPolicy::Cpp).map(|c| c.language),
            Some(Language::Cpp)
        );
        assert!(classify_str("a.h", HeaderPolicy::C).is_some_and(|c| c.is_header));
    }

    #[test]
    fn unsupported_and_extensionless_files_are_ignored() {
        assert_eq!(classify_str("README.md", HeaderPolicy::C), None);
        assert_eq!(classify_str("Makefile", HeaderPolicy::C), None);
        assert_eq!(classify_str("a.py", HeaderPolicy::C), None);
    }

    #[test]
    fn a_detected_header_is_provisional_until_it_is_settled() {
        let header = classify_str("a.h", HeaderPolicy::Detect).expect("classified");
        assert!(header.provisional, "the extension has not decided this");
        assert!(header.is_header);

        let settled = header.settled(Language::Cpp);
        assert_eq!(settled.language, Language::Cpp);
        assert!(!settled.provisional, "the verdict is final");
        assert!(settled.is_header, "settling does not change what it is");
    }

    #[test]
    fn settling_leaves_a_file_the_extension_already_named_alone() {
        // A `.hpp` is C++ whatever the tree says, so the verdict must not
        // reach it. Otherwise a mostly-C project would rewrite its C++
        // headers into C.
        let cpp_header = classify_str("a.hpp", HeaderPolicy::Detect).expect("classified");
        assert_eq!(cpp_header.settled(Language::C).language, Language::Cpp);
        let c_source = classify_str("a.c", HeaderPolicy::Detect).expect("classified");
        assert_eq!(c_source.settled(Language::Cpp).language, Language::C);
    }

    /// Tally `names` the way discovery does, and return the verdict.
    fn verdict_over(names: &[&str]) -> Language {
        let mut evidence = HeaderEvidence::default();
        for name in names {
            if let Some(classification) = classify_str(name, HeaderPolicy::Detect) {
                evidence.observe(classification);
            }
        }
        evidence.verdict()
    }

    #[test]
    fn a_tree_written_mostly_in_cpp_reads_its_bare_headers_as_cpp() {
        assert_eq!(
            verdict_over(&["a.cpp", "b.cc", "c.hpp", "vendored.c", "x.h", "y.h"]),
            Language::Cpp
        );
    }

    #[test]
    fn a_tree_written_mostly_in_c_reads_its_bare_headers_as_c() {
        // Two vendored C++ fuzz harnesses do not make a C project C++.
        assert_eq!(
            verdict_over(&["a.c", "b.c", "c.c", "fuzz.cc", "bench.cc", "a.h"]),
            Language::C
        );
    }

    #[test]
    fn a_tree_with_nothing_to_go_on_reads_its_bare_headers_as_c() {
        // No C or C++ translation unit anywhere: a lone header in a Rust
        // tree, or a header-only library shipped by itself. C is the narrower
        // grammar, so it is the one that claims least.
        assert_eq!(verdict_over(&["main.rs", "lib.rs", "a.h"]), Language::C);
        assert_eq!(verdict_over(&[]), Language::C);
        // A tie is not evidence either.
        assert_eq!(verdict_over(&["a.c", "b.cpp"]), Language::C);
    }

    #[test]
    fn the_headers_being_settled_do_not_vote_on_their_own_language() {
        // Under `Detect` a `.h` is provisionally C. If it counted, a C++
        // project with more headers than sources would settle on C by its own
        // placeholder.
        let mut evidence = HeaderEvidence::default();
        for name in ["a.cpp", "one.h", "two.h", "three.h", "four.h"] {
            evidence.observe(classify_str(name, HeaderPolicy::Detect).expect("classified"));
        }
        assert_eq!(evidence.verdict(), Language::Cpp);
    }

    #[test]
    fn header_policy_names_are_stable() {
        assert_eq!(HeaderPolicy::C.name(), "c");
        assert_eq!(HeaderPolicy::Cpp.name(), "cpp");
        assert_eq!(HeaderPolicy::Detect.name(), "detect");
        assert_eq!(HeaderPolicy::default(), HeaderPolicy::Detect);
    }

    #[test]
    fn selection_filters_and_enumerates_in_order() {
        let selection = LanguageSelection {
            rust: true,
            c: false,
            cpp: true,
        };
        assert!(selection.includes(Language::Rust));
        assert!(!selection.includes(Language::C));
        assert_eq!(selection.enabled(), vec![Language::Rust, Language::Cpp]);
    }
}
