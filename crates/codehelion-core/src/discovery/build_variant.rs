//! Build variants: the first-class context every result is attributed to.
//!
//! A [`BuildVariant`] records the analysis mode, the enabled languages and the
//! normalization ruleset version. Results produced under different variants
//! must never be compared or merged, so the variant is attached to discovery
//! output from the start rather than bolted on later. In Fast mode no build
//! configuration is resolved, so a single implicit variant covers the whole
//! run.

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
    /// Normalization ruleset version.
    pub normalization_version: u32,
}

impl BuildVariant {
    /// The implicit single variant used by a Fast-mode run over `languages`.
    #[must_use]
    pub const fn fast(languages: LanguageSelection) -> Self {
        Self {
            mode: AnalysisMode::Fast,
            languages,
            normalization_version: NORMALIZATION_VERSION,
        }
    }

    /// The implicit single variant used by a Structural-mode run over
    /// `languages`. Like Fast mode, Structural resolves no build configuration,
    /// so one implicit variant covers the run; only the mode differs, which is
    /// enough to keep Fast and Structural fingerprints in separate spaces.
    #[must_use]
    pub const fn structural(languages: LanguageSelection) -> Self {
        Self {
            mode: AnalysisMode::Structural,
            languages,
            normalization_version: NORMALIZATION_VERSION,
        }
    }

    /// A canonical, order-stable string describing this variant.
    ///
    /// Two variants are equal exactly when their canonical strings match, which
    /// makes this string safe to use as a grouping key or fingerprint input.
    #[must_use]
    pub fn canonical(&self) -> String {
        let langs = self
            .languages
            .enabled()
            .into_iter()
            .map(Language::name)
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "mode={};languages={};normalization={}",
            self.mode.name(),
            langs,
            self.normalization_version,
        )
    }

    /// A stable hex fingerprint of this variant.
    #[must_use]
    pub fn fingerprint(&self) -> String {
        blake3::hash(self.canonical().as_bytes())
            .to_hex()
            .to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fast_variant_carries_mode_and_normalization_version() {
        let variant = BuildVariant::fast(LanguageSelection::default());
        assert_eq!(variant.mode, AnalysisMode::Fast);
        assert_eq!(variant.normalization_version, NORMALIZATION_VERSION);
    }

    #[test]
    fn structural_variant_differs_from_fast_only_in_mode() {
        let languages = LanguageSelection::default();
        let fast = BuildVariant::fast(languages);
        let structural = BuildVariant::structural(languages);
        assert_eq!(structural.mode, AnalysisMode::Structural);
        assert_eq!(structural.languages, fast.languages);
        assert_eq!(structural.normalization_version, fast.normalization_version);
        // Distinct modes must land in distinct fingerprint spaces.
        assert_ne!(fast.fingerprint(), structural.fingerprint());
    }

    #[test]
    fn canonical_reflects_enabled_languages_in_fixed_order() {
        let variant = BuildVariant::fast(LanguageSelection {
            rust: true,
            c: false,
            cpp: true,
        });
        assert_eq!(
            variant.canonical(),
            "mode=fast;languages=rust,cpp;normalization=2"
        );
    }

    #[test]
    fn distinct_variants_have_distinct_fingerprints() {
        let all = BuildVariant::fast(LanguageSelection::default());
        let rust_only = BuildVariant::fast(LanguageSelection {
            rust: true,
            c: false,
            cpp: false,
        });
        assert_ne!(all.fingerprint(), rust_only.fingerprint());
        // Fingerprint is a pure function of the canonical form.
        assert_eq!(
            all.fingerprint(),
            BuildVariant::fast(LanguageSelection::default()).fingerprint()
        );
    }
}
