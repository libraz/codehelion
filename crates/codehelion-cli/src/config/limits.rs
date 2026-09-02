//! The resource ceilings a scan runs under.

#![allow(
    clippy::redundant_pub_crate,
    reason = "the module holds ceilings the command layer clamps for an untrusted tree"
)]

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

/// Resource ceilings applied while scanning, sized so that scanning an
/// untrusted repository stays bounded in time and memory.
///
/// Every ceiling is accounted for in the report when it fires — oversized
/// files land in the skipped count, an exhausted pairing budget states in the
/// funnel how many candidates it left unexamined — so nothing is dropped
/// silently.
///
/// The two pairing ceilings are overrides rather than values. The modes pair
/// different things — token-window fingerprints against statement fragments —
/// and their candidate counts differ by an order of magnitude on the same
/// tree, so one number set here for both would be chosen for one mode and
/// merely survived by the other. Left unset, each stays at the default its own
/// measurements picked.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
pub struct Limits {
    /// Per-file size ceiling in bytes; larger files are skipped and counted.
    pub max_file_bytes: u64,
    /// Per-file deterministic parse-work budget, expressed in compatibility
    /// milliseconds. Each millisecond admits 256 input bytes; files above the
    /// resulting byte budget are excluded and counted as skipped. This keeps
    /// host load and worker count from changing a scan's result.
    pub parse_timeout_ms: u64,
    /// Compiler-helper response ceiling in milliseconds, including build
    /// description. A timed-out analysis unit is recorded as unavailable and
    /// the scan continues.
    pub helper_timeout_ms: u64,
    /// Longest posting list or fragment class that still enters pairing;
    /// longer ones are dropped and counted. Unset leaves each mode at its own
    /// default.
    pub posting_cap: Option<usize>,
    /// Upper bound on candidate pairs each pairing pass examines. Unset leaves
    /// each mode at its own default.
    ///
    /// The allowance is per pass, not shared between them: the passes search
    /// different spaces, and one number spent by whichever runs first would
    /// silence the other.
    pub pair_budget: Option<usize>,
    /// Width of the diagnostic estimated-Jaccard band retained immediately
    /// below Structural mode's primary near-match threshold. Unset selects the
    /// structural default.
    pub near_miss_delta: Option<f64>,
    /// Maximum LSH-proposed near misses retained over one structural report.
    /// Unset selects the structural default.
    pub near_miss_cap: Option<usize>,
    /// Upper bound on the post-grouping sibling sweep's verifier comparisons.
    /// Unset selects the structural default.
    pub sibling_candidate_budget: Option<usize>,
    /// Maximum incomplete local mirrors retained for each primary group.
    /// Unset selects the structural default.
    pub sibling_per_group_cap: Option<usize>,
    /// Maximum incomplete local mirrors retained in one structural report.
    /// Unset selects the structural default.
    pub sibling_total_cap: Option<usize>,
    /// Upper bound on signature-based sibling candidates examined by one
    /// structural report. Unset selects the signature-channel default. Used
    /// only when `--siblings-by-signature` enables that channel.
    pub signature_sibling_candidate_budget: Option<usize>,
    /// Maximum signature-based incomplete local mirrors retained for each
    /// primary group. Unset selects the signature-channel default. Used only
    /// when `--siblings-by-signature` enables that channel.
    pub signature_sibling_per_group_cap: Option<usize>,
    /// Maximum signature-based incomplete local mirrors retained in one
    /// structural report. Unset selects the signature-channel default. Used
    /// only when `--siblings-by-signature` enables that channel.
    pub signature_sibling_total_cap: Option<usize>,
    /// Largest number of units that may share one signature before that
    /// signature stops being sibling evidence. Unset selects the
    /// signature-channel default. Used only when `--siblings-by-signature`
    /// enables that channel.
    ///
    /// This is a rarity threshold, not a resource ceiling: a signature shared
    /// by much of a tree proposes work without proposing duplication. Raising
    /// it admits more candidates, and the channel's caps bound what that
    /// costs, so a project whose signatures are genuinely distinctive may
    /// raise it.
    pub signature_sibling_max_units_per_signature: Option<usize>,
    /// Upper bound on Structural pairs passed to precise verification.
    /// Unset selects the structural default.
    pub verification_budget: Option<usize>,
    /// Maximum dynamic-programming cells used by one Structural alignment.
    /// Unset selects the verifier default.
    pub max_alignment_cells: Option<usize>,
    /// Largest set of related units compared as one piece when forming
    /// groups; a larger set is cut, and the cut is reported. Comparing a set
    /// costs time quadratic in its size, so without a ceiling a codebase of
    /// thousands of interchangeable units makes a scan arbitrarily expensive.
    pub max_component: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_file_bytes: codehelion_core::discovery::DEFAULT_MAX_FILE_BYTES,
            parse_timeout_ms: 10_000,
            helper_timeout_ms: 300_000,
            posting_cap: None,
            pair_budget: None,
            near_miss_delta: None,
            near_miss_cap: None,
            sibling_candidate_budget: None,
            sibling_per_group_cap: None,
            sibling_total_cap: None,
            signature_sibling_candidate_budget: None,
            signature_sibling_per_group_cap: None,
            signature_sibling_total_cap: None,
            signature_sibling_max_units_per_signature: None,
            verification_budget: None,
            max_alignment_cells: None,
            max_component: codehelion_core::grouping::GroupingConfig::default().max_component,
        }
    }
}

impl Limits {
    /// Reject ceilings that would turn an enabled scan mode into an empty run.
    ///
    /// # Errors
    ///
    /// Returns an error naming the invalid configuration key.
    pub(super) fn validate(&self) -> Result<()> {
        if self.max_file_bytes == 0 {
            bail!("limits.max-file-bytes must be at least 1");
        }
        if self.parse_timeout_ms == 0 {
            bail!("limits.parse-timeout-ms must be at least 1");
        }
        if self.helper_timeout_ms == 0 {
            bail!("limits.helper-timeout-ms must be at least 1");
        }
        if self.posting_cap.is_some_and(|cap| cap < 2) {
            bail!("limits.posting-cap must be at least 2 when set");
        }
        if self.pair_budget == Some(0) {
            bail!("limits.pair-budget must be at least 1 when set");
        }
        if self.near_miss_delta.is_some_and(|delta| {
            !delta.is_finite()
                || !(0.0..=codehelion_core::near_match::DEFAULT_MIN_ESTIMATED_JACCARD)
                    .contains(&delta)
                || delta == 0.0
        }) {
            bail!(
                "limits.near-miss-delta must be finite and in (0.0, {}] when set",
                codehelion_core::near_match::DEFAULT_MIN_ESTIMATED_JACCARD
            );
        }
        if self.near_miss_cap == Some(0) {
            bail!("limits.near-miss-cap must be at least 1 when set");
        }
        if self.sibling_candidate_budget == Some(0) {
            bail!("limits.sibling-candidate-budget must be at least 1 when set");
        }
        if self.sibling_per_group_cap == Some(0) {
            bail!("limits.sibling-per-group-cap must be at least 1 when set");
        }
        if self.sibling_total_cap == Some(0) {
            bail!("limits.sibling-total-cap must be at least 1 when set");
        }
        if self.signature_sibling_candidate_budget == Some(0) {
            bail!("limits.signature-sibling-candidate-budget must be at least 1 when set");
        }
        if self.signature_sibling_per_group_cap == Some(0) {
            bail!("limits.signature-sibling-per-group-cap must be at least 1 when set");
        }
        if self.signature_sibling_total_cap == Some(0) {
            bail!("limits.signature-sibling-total-cap must be at least 1 when set");
        }
        // A sibling needs two units sharing a signature, so a limit below two
        // silences the channel instead of tuning it. Enabling a channel and
        // configuring it to find nothing is a mistake worth naming.
        if self
            .signature_sibling_max_units_per_signature
            .is_some_and(|limit| limit < 2)
        {
            bail!("limits.signature-sibling-max-units-per-signature must be at least 2 when set");
        }
        if self.verification_budget == Some(0) {
            bail!("limits.verification-budget must be at least 1 when set");
        }
        if self.max_alignment_cells == Some(0) {
            bail!("limits.max-alignment-cells must be at least 1 when set");
        }
        if self.max_component < 2 {
            bail!("limits.max-component must be at least 2");
        }
        Ok(())
    }

    /// Lower every configurable resource ceiling to the untrusted profile.
    ///
    /// The optional pairing settings mean "use the mode-specific default" in
    /// normal runs. An untrusted run cannot leave that choice open: it turns
    /// them into concrete ceilings. Pairing uses the untrusted profile; the
    /// structural-only sibling sweep uses its already-bounded defaults.
    pub(crate) fn clamp_to_untrusted(&mut self, profile: &codehelion_core::execution::Limits) {
        self.max_file_bytes = self.max_file_bytes.min(profile.max_file_bytes);
        self.parse_timeout_ms = self
            .parse_timeout_ms
            .min(duration_millis(profile.parse_timeout));
        self.helper_timeout_ms = self
            .helper_timeout_ms
            .min(duration_millis(profile.helper_timeout));
        self.posting_cap = Some(
            self.posting_cap
                .map_or(profile.posting_cap, |cap| cap.min(profile.posting_cap)),
        );
        self.pair_budget = Some(self.pair_budget.map_or(profile.max_candidates, |budget| {
            budget.min(profile.max_candidates)
        }));
        let near_match_defaults = codehelion_core::near_match::NearMatchConfig::default();
        self.near_miss_cap = Some(
            self.near_miss_cap
                .map_or(near_match_defaults.near_miss_cap, |cap| {
                    cap.min(near_match_defaults.near_miss_cap)
                }),
        );
        let sibling_defaults = codehelion_core::structural::SiblingConfig::default();
        self.sibling_candidate_budget = Some(
            self.sibling_candidate_budget
                .map_or(sibling_defaults.candidate_budget, |budget| {
                    budget.min(sibling_defaults.candidate_budget)
                }),
        );
        self.sibling_per_group_cap = Some(
            self.sibling_per_group_cap
                .map_or(sibling_defaults.per_group_cap, |cap| {
                    cap.min(sibling_defaults.per_group_cap)
                }),
        );
        self.sibling_total_cap = Some(
            self.sibling_total_cap
                .map_or(sibling_defaults.total_cap, |cap| {
                    cap.min(sibling_defaults.total_cap)
                }),
        );
        let signature_sibling_defaults =
            codehelion_core::structural::SignatureSiblingConfig::default();
        self.signature_sibling_candidate_budget = Some(
            self.signature_sibling_candidate_budget
                .map_or(signature_sibling_defaults.candidate_budget, |budget| {
                    budget.min(signature_sibling_defaults.candidate_budget)
                }),
        );
        self.signature_sibling_per_group_cap = Some(
            self.signature_sibling_per_group_cap
                .map_or(signature_sibling_defaults.per_group_cap, |cap| {
                    cap.min(signature_sibling_defaults.per_group_cap)
                }),
        );
        self.signature_sibling_total_cap = Some(
            self.signature_sibling_total_cap
                .map_or(signature_sibling_defaults.total_cap, |cap| {
                    cap.min(signature_sibling_defaults.total_cap)
                }),
        );
        // The rarity limit is a detection knob a trusted project may raise,
        // but the configuration carrying that request can come from the tree
        // being scanned. An untrusted tree therefore does not get to widen the
        // signatures its own layout made common, so this is clamped down like
        // the ceilings above.
        self.signature_sibling_max_units_per_signature =
            Some(self.signature_sibling_max_units_per_signature.map_or(
                signature_sibling_defaults.max_units_per_signature,
                |limit| limit.min(signature_sibling_defaults.max_units_per_signature),
            ));
        self.max_component = self.max_component.min(profile.max_component);
        self.verification_budget = Some(
            self.verification_budget
                .map_or(profile.verification_budget, |budget| {
                    budget.min(profile.verification_budget)
                }),
        );
        self.max_alignment_cells = Some(
            self.max_alignment_cells
                .map_or(profile.max_alignment_cells, |cells| {
                    cells.min(profile.max_alignment_cells)
                }),
        );
    }
}

/// Convert a duration to the millisecond configuration representation without
/// wrapping a pathological value into a smaller, unsafe ceiling.
fn duration_millis(duration: std::time::Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::config::Config;

    #[test]
    fn limit_defaults_match_the_engine_and_discovery_defaults() {
        let limits = Limits::default();
        assert_eq!(
            limits.max_file_bytes,
            codehelion_core::discovery::DEFAULT_MAX_FILE_BYTES
        );
        // The pairing ceilings are overrides, not values: unset leaves each
        // mode at its own default rather than imposing one mode's on both.
        assert_eq!(limits.posting_cap, None);
        assert_eq!(limits.pair_budget, None);
        assert_eq!(limits.near_miss_delta, None);
        assert_eq!(limits.near_miss_cap, None);
        let grouping = codehelion_core::grouping::GroupingConfig::default();
        assert_eq!(limits.max_component, grouping.max_component);
        assert!(
            limits.max_component > grouping.sampling_threshold,
            "a set between the two ceilings is still compared whole, with a sampled medoid"
        );
        assert!(limits.parse_timeout_ms > 0);
        assert!(limits.helper_timeout_ms > 0);
    }

    #[test]
    fn partial_limits_section_keeps_other_ceilings_at_their_defaults() {
        let config = Config::from_toml("[limits]\nmax-file-bytes = 1024").unwrap();
        assert_eq!(config.limits.max_file_bytes, 1024);
        assert_eq!(config.limits.posting_cap, Limits::default().posting_cap);
        assert_eq!(config.limits.pair_budget, Limits::default().pair_budget);
        assert_eq!(
            config.limits.near_miss_delta,
            Limits::default().near_miss_delta
        );
        assert_eq!(config.limits.near_miss_cap, Limits::default().near_miss_cap);
        assert_eq!(config.limits.max_component, Limits::default().max_component);
        assert_eq!(
            config.limits.helper_timeout_ms,
            Limits::default().helper_timeout_ms
        );
    }

    #[test]
    fn near_miss_diagnostic_band_and_cap_are_configurable_and_bounded() {
        let config = Config::from_toml("[limits]\nnear-miss-delta = 0.04\nnear-miss-cap = 7")
            .expect("near-miss settings parse");
        assert_eq!(config.limits.near_miss_delta, Some(0.04));
        assert_eq!(config.limits.near_miss_cap, Some(7));

        let error = Config::from_toml("[limits]\nnear-miss-delta = 0.31")
            .expect_err("the default estimate threshold bounds the diagnostic band");
        assert!(format!("{error:#}").contains("limits.near-miss-delta"));
        assert!(format!("{error:#}").contains("(0.0, 0.3]"));
    }

    #[test]
    fn signature_sibling_limits_are_independent_and_parseable() {
        let config = Config::from_toml(
            "[limits]\nsignature-sibling-candidate-budget = 13\nsignature-sibling-per-group-cap = 5\nsignature-sibling-total-cap = 17",
        )
        .expect("signature sibling settings parse");
        assert_eq!(config.limits.signature_sibling_candidate_budget, Some(13));
        assert_eq!(config.limits.signature_sibling_per_group_cap, Some(5));
        assert_eq!(config.limits.signature_sibling_total_cap, Some(17));
        assert_eq!(config.limits.sibling_candidate_budget, None);
        assert_eq!(config.limits.sibling_per_group_cap, None);
        assert_eq!(config.limits.sibling_total_cap, None);
    }

    #[test]
    fn the_signature_sharing_limit_is_configurable_but_must_leave_room_for_a_pair() {
        let config = Config::from_toml("[limits]\nsignature-sibling-max-units-per-signature = 64")
            .expect("a widened sharing limit parses");
        assert_eq!(
            config.limits.signature_sibling_max_units_per_signature,
            Some(64)
        );

        let error = Config::from_toml("[limits]\nsignature-sibling-max-units-per-signature = 1")
            .expect_err("a limit below two silences the channel instead of tuning it");
        assert!(
            format!("{error:#}").contains("limits.signature-sibling-max-units-per-signature"),
            "{error:#}"
        );
    }
}
