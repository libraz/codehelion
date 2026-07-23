//! Language classification of source files by extension.
//!
//! Classification is filename-based. The one genuinely ambiguous case is the
//! bare `.h` extension, which C and C++ share; the caller picks a
//! [`HeaderPolicy`] to resolve it. Extensions that unambiguously belong to C++
//! by convention (capitalised `.C`/`.H`, `.hpp`, `.cxx`, ...) are classified
//! directly regardless of the policy.

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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderPolicy {
    /// Treat `.h` as C.
    C,
    /// Treat `.h` as C++.
    Cpp,
}

impl Default for HeaderPolicy {
    /// `.h` defaults to C; projects that are C++-only can override the policy.
    fn default() -> Self {
        Self::C
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
}

/// Classify `path` by its extension, returning `None` for unsupported files.
///
/// The bare `.h` extension is resolved with `header_policy`; all other
/// extensions map unambiguously.
#[must_use]
pub(super) fn classify(path: &Path, header_policy: HeaderPolicy) -> Option<Classification> {
    // Match the raw extension: capitalisation is meaningful (`.C`/`.H` are the
    // classic C++ spellings), so it is not lowercased first.
    let ext = path.extension()?.to_str()?;
    let (language, is_header) = match ext {
        "rs" => (Language::Rust, false),
        "c" => (Language::C, false),
        "h" => {
            let language = match header_policy {
                HeaderPolicy::C => Language::C,
                HeaderPolicy::Cpp => Language::Cpp,
            };
            (language, true)
        }
        "cc" | "cpp" | "cxx" | "c++" | "C" => (Language::Cpp, false),
        "hpp" | "hh" | "hxx" | "h++" | "H" | "tpp" | "ipp" | "inl" => (Language::Cpp, true),
        _ => return None,
    };
    Some(Classification {
        language,
        is_header,
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
            })
        );
        assert_eq!(
            classify_str("lib.c", HeaderPolicy::C),
            Some(Classification {
                language: Language::C,
                is_header: false,
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
