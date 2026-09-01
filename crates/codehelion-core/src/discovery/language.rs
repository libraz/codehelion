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
//!
//! A header-only library offers no such files at all, and it is the case where
//! guessing costs the most: every line of the project is in the headers. There
//! the headers are read for something only C++ spells — see [`speaks_cpp`].

use std::path::Path;

use serde::{Deserialize, Serialize};

/// A source language codehelion can enumerate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
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

    /// The language to read bare `.h` headers as, when the tree says.
    ///
    /// C++ only when the tree holds strictly more unambiguous C++ files than C
    /// ones. [`None`] when it holds neither, which is not a tie to be broken
    /// but a question this tally cannot answer: a header-only library has no
    /// files outside the headers, so there is nothing here to read the headers
    /// against.
    #[must_use]
    pub const fn verdict(self) -> Option<Language> {
        match (self.c, self.cpp) {
            (0, 0) => None,
            (c, cpp) if cpp > c => Some(Language::Cpp),
            _ => Some(Language::C),
        }
    }
}

/// Whether `source` spells something only C++ has.
///
/// The fallback for a tree whose extensions settle nothing. It is a spelling
/// check and not a parse: comments and literals are skipped, and what is left
/// is searched for four constructs C has no reading of — a scope resolution,
/// a template's angle bracket, a named namespace, and an include of a standard
/// header without an extension.
///
/// One header saying C++ settles the whole run, because the two mistakes are
/// not the same size. C++ is nearly a superset, so a C header read with the
/// C++ grammar parses; a C++ header read with the C grammar does not, and the
/// error recovery spreads the damage past the construct that caused it. Where
/// the evidence is this thin, the reading that survives being wrong is the one
/// to take.
pub(super) fn speaks_cpp(source: &str) -> bool {
    let bytes = source.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let rest = &bytes[index..];
        match rest {
            [b'/', b'/', ..] => index += skip_until(rest, b"\n"),
            [b'/', b'*', ..] => index += skip_until(&rest[2..], b"*/") + 2,
            [b'"', ..] => index += skip_literal(rest, b'"'),
            [b'\'', ..] => index += skip_literal(rest, b'\''),
            [b':', b':', ..] => return true,
            [b'#', ..] => {
                let line = &rest[..skip_until(rest, b"\n")];
                if bare_standard_include(line) {
                    return true;
                }
                index += line.len();
            }
            [first, ..] if first.is_ascii_alphabetic() || *first == b'_' => {
                let word = word_at(rest);
                // `template` and `namespace` are ordinary identifiers in C, so
                // it is what follows that makes them C++: an angle bracket
                // opening a parameter list, a name or a brace opening a scope.
                let after = rest[word.len()..]
                    .iter()
                    .position(|byte| !byte.is_ascii_whitespace())
                    .map(|offset| rest[word.len() + offset]);
                match (word, after) {
                    (b"template", Some(b'<')) => return true,
                    (b"namespace", Some(byte))
                        if byte.is_ascii_alphabetic() || byte == b'_' || byte == b'{' =>
                    {
                        return true;
                    }
                    _ => {}
                }
                index += word.len();
            }
            _ => index += 1,
        }
    }
    false
}

/// Bytes up to and including the first `needle`, or all of `bytes`.
fn skip_until(bytes: &[u8], needle: &[u8]) -> usize {
    bytes
        .windows(needle.len())
        .position(|window| window == needle)
        .map_or(bytes.len(), |offset| offset + needle.len())
}

/// Bytes of the literal starting at `bytes[0]`, closing on an unescaped
/// `quote`. An unterminated literal swallows the rest, which is the reading
/// that cannot loop.
const fn skip_literal(bytes: &[u8], quote: u8) -> usize {
    let mut index = 1;
    while index < bytes.len() {
        match bytes[index] {
            b'\\' => index += 2,
            byte if byte == quote => return index + 1,
            _ => index += 1,
        }
    }
    bytes.len()
}

/// The identifier at the start of `bytes`.
fn word_at(bytes: &[u8]) -> &[u8] {
    let end = bytes
        .iter()
        .position(|byte| !(byte.is_ascii_alphanumeric() || *byte == b'_'))
        .unwrap_or(bytes.len());
    &bytes[..end]
}

/// Whether a preprocessor line includes an angle-bracketed header with no
/// extension: `<memory>` is a C++ standard header, `<string.h>` is C's.
fn bare_standard_include(line: &[u8]) -> bool {
    let Some(open) = line.iter().position(|byte| *byte == b'<') else {
        return false;
    };
    let Some(close) = line[open..].iter().position(|byte| *byte == b'>') else {
        return false;
    };
    let name = &line[open + 1..open + close];
    !name.is_empty()
        && !name.contains(&b'.')
        && !name.contains(&b'/')
        && name
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
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
    fn verdict_over(names: &[&str]) -> Option<Language> {
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
            Some(Language::Cpp)
        );
    }

    #[test]
    fn a_tree_written_mostly_in_c_reads_its_bare_headers_as_c() {
        // Two vendored C++ fuzz harnesses do not make a C project C++.
        assert_eq!(
            verdict_over(&["a.c", "b.c", "c.c", "fuzz.cc", "bench.cc", "a.h"]),
            Some(Language::C)
        );
    }

    #[test]
    fn a_tree_with_nothing_to_go_on_leaves_the_question_open() {
        // No C or C++ translation unit anywhere: a lone header in a Rust
        // tree, or a header-only library shipped by itself. The tally has
        // nothing to say, and saying so is what sends the caller to read the
        // headers instead of settling them by default.
        assert_eq!(verdict_over(&["main.rs", "lib.rs", "a.h"]), None);
        assert_eq!(verdict_over(&[]), None);
        // A tie between translation units is evidence, and it reads as C: a
        // project with as many C files as C++ ones is not a C++ project.
        assert_eq!(verdict_over(&["a.c", "b.cpp"]), Some(Language::C));
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
        assert_eq!(evidence.verdict(), Some(Language::Cpp));
    }

    #[test]
    fn a_header_that_spells_something_only_cpp_has_is_read_as_cpp() {
        for source in [
            "namespace spdlog {\nint f(void);\n}\n",
            "template <typename T>\nT identity(T value) { return value; }\n",
            "int width = detail::pad_to(8);\n",
            "#include <memory>\n",
        ] {
            assert!(speaks_cpp(source), "missed C++ in {source:?}");
        }
    }

    #[test]
    fn a_c_header_is_not_talked_into_cpp_by_its_prose() {
        for source in [
            // The words are all C++, and every one of them is in a comment,
            // a string or a name C is entitled to use.
            "/* A class of namespace, template :: style. */\nint f(void);\n",
            "// namespace ::template\nint f(void);\n",
            "static const char *doc = \"namespace x { template <int> };\";\n",
            "#include <string.h>\n#include <sys/types.h>\n",
            "struct s { int template; int namespace; };\n",
            // A bitfield's colon, twice, is not a scope resolution.
            "struct s { unsigned a : 1; unsigned b : 1; };\n",
            // An unterminated literal must not read past itself into a
            // verdict, and must not loop.
            "static const char *unclosed = \"namespace\n",
        ] {
            assert!(!speaks_cpp(source), "read C++ into {source:?}");
        }
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
