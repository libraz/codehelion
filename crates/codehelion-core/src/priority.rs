//! What a clone group is worth attending to, as separated measures.
//!
//! A ranking that collapses to one number cannot be argued with. Three
//! different questions decide where a finding belongs in a report, and they
//! have different answers and different evidence:
//!
//! - [`Priority::clone_confidence`] — is this duplication real, and worth
//!   calling duplication at all?
//! - [`Priority::maintenance_risk`] — what does keeping the copies in step
//!   cost?
//! - [`Priority::refactoring_difficulty`] — what would removing it cost?
//!
//! [`Priority::final_priority`] composes them into one order, because a report
//! has to be printed in some order. It never replaces them: every view carries
//! all four, and [`Priority::inputs`] carries the values they were read from,
//! so a reader who disagrees with the ranking can see exactly which input
//! produced it.
//!
//! # Why the composition multiplies rather than adds
//!
//! Risk and difficulty are statements about a finding that is real. Added to
//! confidence they can outvote it, and a lookalike with many copies then
//! outranks a genuine duplication with two — which is the failure mode the
//! separation exists to prevent. Multiplying makes confidence the leading
//! term: the maintenance argument moves a finding within the band its
//! confidence puts it in, and cannot lift it out of that band.
//!
//! Measured over the labelled corpora, an additive composition costs mean
//! average precision against a multiplicative one at the same weights; see
//! `precision_at_k` in the evaluation harness, which pins the comparison.
//!
//! # Why the values do not depend on the other findings
//!
//! Every measure here is computed from one group's own facts. Nothing is
//! ranked against the rest of the run, and nothing is scaled by the run's
//! maximum. A rank-based composition reads well on one report and falls apart
//! across two: adding a single group renumbers every other group's rank, so a
//! finding's priority would move for reasons that have nothing to do with it,
//! and `codehelion audit` could not say whether a priority rose because the
//! duplication got worse or because something else was found. Absolute values
//! are comparable between runs; ranks are not.
//!
//! Counts are mapped onto `0..1` by [`saturating`], which has no cliff to
//! calibrate and no ceiling to saturate against: a value twice the reference
//! scores two-thirds, ten times the reference scores ten-elevenths, and
//! nothing ever reaches 1. That last part is deliberate — none of these
//! measures is ever certain.

use crate::clone_class::{CloneClass, CloneScope};

/// Version of the ranking recipe, recorded with every run.
///
/// The constants below decide where findings land in a report, so two runs
/// ranked under different constants are not comparable orderings even when
/// every fingerprint agrees. Increment this whenever a constant or a formula
/// moves.
pub const RECIPE_VERSION: &str = "1";

/// Discount applied to a match the normalization had to reshape before it
/// agreed.
///
/// A Type-1 group matched on the source as written. Anything else matched
/// after identifiers, literals or whole statements were set aside, and two
/// units that agree only once their names are gone can genuinely do different
/// things. Over the labelled corpora the renamed class is where the lookalikes
/// concentrate, which is what this expresses.
const NORMALIZED_MATCH_DISCOUNT: f64 = 0.8;

/// Multiple of the configured minimum clone length at which a group's size
/// earns half the available size credit.
///
/// Anchored to the floor rather than fixed, because the floor is the length
/// below which the scan already refuses to report: a clone sitting exactly on
/// it is the least convincing one the run can produce, whatever the floor was
/// set to.
const SIZE_HALF_CREDIT_MULTIPLE: u64 = 2;

/// Instances beyond the first at which the count earns half the risk credit.
const RISK_HALF_INSTANCES: f64 = 2.0;

/// Token count at which a group's extent earns half the risk credit.
const RISK_HALF_TOKENS: f64 = 120.0;

/// Directories beyond the first at which spread earns half the risk credit.
const RISK_HALF_DIRECTORIES: f64 = 1.0;

/// Token count at which a group's extent earns half the difficulty credit.
///
/// Larger than [`RISK_HALF_TOKENS`]: a duplicated block becomes expensive to
/// maintain sooner than it becomes hard to lift out.
const DIFFICULTY_HALF_TOKENS: f64 = 200.0;

/// Share of a finding's confidence that survives the weakest possible
/// maintenance argument.
///
/// Not zero: a finding whose duplication is cheap to keep and awkward to
/// remove is still a finding, and dropping it to nothing would order the tail
/// of a report by rounding error. Half is inside the range the labelled
/// corpora are indifferent to — anything from roughly a third upwards ranks
/// them the same.
const WORTH_FLOOR: f64 = 0.5;

/// How the separated measures are weighted against each other when they are
/// composed into one order.
///
/// Whole numbers rather than fractions: these are shares, they are read from
/// and written back to a configuration file, and a float round-trip through
/// TOML is a difference nobody meant to express.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Weights {
    /// Weight of what keeping the copies in step costs.
    pub maintenance_risk: u32,
    /// Weight of how cheap the duplication would be to remove.
    pub refactoring_ease: u32,
}

impl Default for Weights {
    fn default() -> Self {
        // Risk leads: what the duplication costs to live with is the reason to
        // read the report at all, and how easy it would be to remove is a
        // question that only arises once it is worth removing. The labelled
        // corpora rank the same for any ratio between 1:1 and 3:1, so this is
        // the round choice inside a flat range rather than a fitted optimum.
        Self {
            maintenance_risk: 2,
            refactoring_ease: 1,
        }
    }
}

impl Weights {
    /// The ranking recipe this run applied: the version of the rules together
    /// with the weights they were composed under.
    ///
    /// Recorded with the run, because a report ordered under other weights is
    /// a different ordering of the same findings and nothing else says so.
    #[must_use]
    pub fn recipe(&self) -> String {
        format!(
            "{RECIPE_VERSION}-risk{}-ease{}",
            self.maintenance_risk, self.refactoring_ease
        )
    }

    /// Blend of the two arguments a finding makes for itself, on `0..1`.
    ///
    /// Weights that are both zero leave no argument to weigh, and the blend is
    /// the midpoint rather than an error: a reader who turns both off is
    /// asking to rank on confidence alone, and confidence alone is what they
    /// then get.
    fn worth(self, risk: f64, difficulty: f64) -> f64 {
        let total = f64::from(self.maintenance_risk) + f64::from(self.refactoring_ease);
        if total <= 0.0 {
            return 0.5;
        }
        f64::from(self.refactoring_ease)
            .mul_add(1.0 - difficulty, f64::from(self.maintenance_risk) * risk)
            / total
    }
}

/// What the ranking reads about one clone group.
///
/// Every field is a fact the scan established, not a judgement: the judgements
/// are what [`rank`] derives from them. The reserved fields are inputs the
/// requirements name that no analysis mode can supply yet; they are declared
/// here and reported as absent rather than defaulted, so that the day a
/// backend supplies one, nothing has to be told the difference between a
/// missing value and a zero.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct GroupFacts {
    /// How closely the members match.
    pub clone_type: CloneClass,
    /// Whether the members are whole units or runs inside them.
    pub scope: CloneScope,
    /// Occurrences in the group.
    pub instances: u64,
    /// Token count of the smallest occurrence.
    ///
    /// The smallest rather than the largest: a group is only as convincing as
    /// its least substantial member, since that is the one that could most
    /// easily have matched by coincidence.
    pub smallest_member_tokens: u64,
    /// Token count of the largest occurrence, which is what a reader would
    /// have to read, keep in step, or lift out.
    pub largest_member_tokens: u64,
    /// Weakest pairwise similarity across the group. Exactly 1 for a group
    /// matched on identical content.
    pub min_pairwise: f64,
    /// Distinct files the occurrences sit in.
    pub files: u64,
    /// Distinct directories the occurrences sit in.
    pub directories: u64,
    /// Distinct languages the occurrences are written in.
    ///
    /// One, in every mode that exists today: content fingerprints are computed
    /// per language, so no group can span two. The input is read anyway, so
    /// that a cross-language frontend starts affecting the ranking by being
    /// implemented rather than by also being wired in here.
    pub languages: u64,
    /// The run's minimum clone length, which the sizes above are read against.
    pub min_clone_tokens: u64,
    /// How often the duplicated code changed. Reserved: this needs repository
    /// history, which no analysis mode reads yet.
    pub churn: Option<f64>,
    /// How many people own the copies. Reserved, on the same footing as
    /// [`Self::churn`].
    pub ownership_spread: Option<f64>,
}

/// Where one clone group belongs in a report, and on what grounds.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Priority {
    /// How sure the finding is duplication worth reporting, on `0..1`.
    pub clone_confidence: f64,
    /// What keeping the copies in step costs, on `0..1`.
    pub maintenance_risk: f64,
    /// What removing the duplication would cost, on `0..1`.
    pub refactoring_difficulty: f64,
    /// The composed ranking value, on `0..1`.
    pub final_priority: f64,
    /// How sure the finding is semantically equivalent. Reserved for the
    /// compiler backends; absent until one runs.
    pub semantic_confidence: Option<f64>,
    /// How sure the source is the source of a given artifact. Reserved for the
    /// artifact backends.
    pub source_artifact_confidence: Option<f64>,
    /// How sure the reported savings are. Reserved: nothing measures savings
    /// yet, and a number here would be read as a guarantee.
    pub savings_confidence: Option<f64>,
    /// The facts every measure above was read from.
    pub inputs: GroupFacts,
}

/// A count mapped onto `0..1` by how far past `half` it reaches.
///
/// `half` earns exactly one half; nothing earns 1. A negative or zero `half`
/// has no reference to measure against and scores nothing, rather than
/// dividing by zero.
#[must_use]
pub fn saturating(value: f64, half: f64) -> f64 {
    if half <= 0.0 || value <= 0.0 {
        return 0.0;
    }
    value / (value + half)
}

/// `count` as a float, for the ratios above.
///
/// Counts this size lose nothing a ranking can see.
#[allow(clippy::cast_precision_loss)]
const fn as_f64(count: u64) -> f64 {
    count as f64
}

/// How sure the finding is duplication worth reporting.
///
/// Three things decide it, and they multiply because each is a way the finding
/// could fail to be one: the copies might not agree, the agreement might be
/// too short to mean anything, and the agreement might be an artefact of what
/// normalization threw away.
#[must_use]
pub fn clone_confidence(facts: &GroupFacts) -> f64 {
    let half = as_f64(
        facts
            .min_clone_tokens
            .saturating_mul(SIZE_HALF_CREDIT_MULTIPLE),
    );
    let length = saturating(as_f64(facts.smallest_member_tokens), half);
    let reshaped = if facts.clone_type == CloneClass::Type1 {
        1.0
    } else {
        NORMALIZED_MATCH_DISCOUNT
    };
    facts.min_pairwise.clamp(0.0, 1.0) * length * reshaped
}

/// What keeping the copies in step costs.
///
/// Copies drift. What decides how expensive that is: how many places have to
/// receive the same edit, how much code each of them is, and how far apart
/// they sit — copies in one file are read together and tend to be changed
/// together, copies in different directories are not and do not.
///
/// [`GroupFacts::churn`] and [`GroupFacts::ownership_spread`] belong here too
/// and are not read: nothing supplies them yet, and inventing a value for a
/// missing input would put findings in an order the evidence does not support.
#[must_use]
pub fn maintenance_risk(facts: &GroupFacts) -> f64 {
    let copies = saturating(
        as_f64(facts.instances.saturating_sub(1)),
        RISK_HALF_INSTANCES,
    );
    let extent = saturating(as_f64(facts.largest_member_tokens), RISK_HALF_TOKENS);
    let spread = saturating(
        as_f64(facts.directories.saturating_sub(1)),
        RISK_HALF_DIRECTORIES,
    );
    0.50f64.mul_add(copies, 0.35f64.mul_add(extent, 0.15 * spread))
}

/// What removing the duplication would cost.
///
/// The extent is the bulk of it, but three other things change the answer: a
/// run inside a unit has no boundary to lift it out at and has to be given
/// one, everything the copies do differently becomes a parameter of whatever
/// replaces them, and copies in different languages cannot share code at all
/// without an interface between them.
///
/// Higher is harder. It lowers a finding's place in the report rather than
/// raising it — a duplication nobody can act on is worth less attention than
/// one anybody can — but only within the band its confidence puts it in.
#[must_use]
pub fn refactoring_difficulty(facts: &GroupFacts) -> f64 {
    let extent = saturating(as_f64(facts.largest_member_tokens), DIFFICULTY_HALF_TOKENS);
    let unbounded = f64::from(facts.scope == CloneScope::Fragment);
    let divergence = 1.0 - facts.min_pairwise.clamp(0.0, 1.0);
    let cross_language = f64::from(facts.languages > 1);
    0.40f64.mul_add(
        extent,
        0.25f64.mul_add(
            unbounded,
            0.20f64.mul_add(divergence, 0.15 * cross_language),
        ),
    )
}

/// Rank one clone group: every measure, and the facts they came from.
#[must_use]
pub fn rank(facts: &GroupFacts, weights: &Weights) -> Priority {
    let confidence = clone_confidence(facts);
    let risk = maintenance_risk(facts);
    let difficulty = refactoring_difficulty(facts);
    let worth = weights.worth(risk, difficulty);
    Priority {
        clone_confidence: confidence,
        maintenance_risk: risk,
        refactoring_difficulty: difficulty,
        final_priority: confidence * (1.0 - WORTH_FLOOR).mul_add(worth, WORTH_FLOOR),
        // Reserved until a backend supplies them. Absent, never zero: zero is
        // a measurement, and none of these has been taken.
        semantic_confidence: None,
        source_artifact_confidence: None,
        savings_confidence: None,
        inputs: *facts,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// A plain two-instance verbatim group of comfortably reportable size.
    fn facts() -> GroupFacts {
        GroupFacts {
            clone_type: CloneClass::Type1,
            scope: CloneScope::Unit,
            instances: 2,
            smallest_member_tokens: 80,
            largest_member_tokens: 80,
            min_pairwise: 1.0,
            files: 2,
            directories: 1,
            languages: 1,
            min_clone_tokens: 20,
            churn: None,
            ownership_spread: None,
        }
    }

    #[test]
    fn every_measure_stays_inside_the_range_it_claims() {
        // The extremes a scan can actually produce, at both ends.
        let mut smallest = facts();
        smallest.instances = 2;
        smallest.smallest_member_tokens = 1;
        smallest.largest_member_tokens = 1;
        smallest.min_pairwise = 0.0;
        smallest.clone_type = CloneClass::Type3;
        smallest.scope = CloneScope::Fragment;

        let mut largest = facts();
        largest.instances = u64::MAX;
        largest.smallest_member_tokens = u64::MAX;
        largest.largest_member_tokens = u64::MAX;
        largest.directories = u64::MAX;
        largest.languages = 3;
        largest.scope = CloneScope::Fragment;

        for probe in [smallest, largest, facts()] {
            let ranked = rank(&probe, &Weights::default());
            for (name, value) in [
                ("clone confidence", ranked.clone_confidence),
                ("maintenance risk", ranked.maintenance_risk),
                ("refactoring difficulty", ranked.refactoring_difficulty),
                ("final priority", ranked.final_priority),
            ] {
                assert!(
                    (0.0..=1.0).contains(&value),
                    "{name} left its range at {value}"
                );
            }
        }
    }

    #[test]
    fn a_clone_sitting_on_the_length_floor_is_the_least_convincing_one() {
        // The floor is where the scan stops reporting, so a clone exactly on
        // it is the weakest evidence the run can produce — and it says so
        // whatever the floor was set to.
        for floor in [10, 20, 50] {
            let mut probe = facts();
            probe.min_clone_tokens = floor;
            probe.smallest_member_tokens = floor;
            probe.largest_member_tokens = floor;
            let at_floor = clone_confidence(&probe);

            probe.smallest_member_tokens = floor * 8;
            probe.largest_member_tokens = floor * 8;
            let well_past = clone_confidence(&probe);

            assert!(at_floor < 0.4, "floor {floor}: {at_floor}");
            assert!(well_past > 0.7, "floor {floor}: {well_past}");
        }
    }

    #[test]
    fn a_match_the_normalization_had_to_reshape_is_trusted_less() {
        let mut verbatim = facts();
        verbatim.clone_type = CloneClass::Type1;
        let mut renamed = facts();
        renamed.clone_type = CloneClass::Type2;

        assert!(clone_confidence(&renamed) < clone_confidence(&verbatim));
    }

    #[test]
    fn a_gapped_group_is_discounted_twice_over() {
        // Once for having been reshaped, and again for the members not
        // agreeing. The two are separate facts and both belong in the answer.
        let mut renamed = facts();
        renamed.clone_type = CloneClass::Type2;
        let mut gapped = facts();
        gapped.clone_type = CloneClass::Type3;
        gapped.min_pairwise = 0.8;

        assert!(clone_confidence(&gapped) < clone_confidence(&renamed));
    }

    #[test]
    fn more_copies_further_apart_cost_more_to_keep_in_step() {
        let base = maintenance_risk(&facts());

        let mut many = facts();
        many.instances = 9;
        assert!(maintenance_risk(&many) > base);

        let mut scattered = facts();
        scattered.directories = 4;
        assert!(maintenance_risk(&scattered) > base);
    }

    #[test]
    fn a_run_inside_a_unit_is_harder_to_lift_out_than_a_whole_unit() {
        let mut whole = facts();
        whole.scope = CloneScope::Unit;
        let mut run = facts();
        run.scope = CloneScope::Fragment;

        assert!(refactoring_difficulty(&run) > refactoring_difficulty(&whole));
    }

    #[test]
    fn copies_in_two_languages_are_harder_to_share_than_copies_in_one() {
        let mut one = facts();
        one.languages = 1;
        let mut two = facts();
        two.languages = 2;

        assert!(refactoring_difficulty(&two) > refactoring_difficulty(&one));
    }

    #[test]
    fn the_maintenance_argument_cannot_lift_a_finding_past_its_confidence() {
        // The whole reason the composition multiplies. A short renamed pair
        // with every risk input at its maximum still ranks below a long
        // verbatim group with none of them.
        let mut lookalike = facts();
        lookalike.clone_type = CloneClass::Type2;
        lookalike.smallest_member_tokens = 20;
        lookalike.largest_member_tokens = 20;
        lookalike.instances = 40;
        lookalike.directories = 12;

        let mut genuine = facts();
        genuine.smallest_member_tokens = 400;
        genuine.largest_member_tokens = 400;
        genuine.instances = 2;
        genuine.directories = 1;

        let weights = Weights::default();
        assert!(maintenance_risk(&lookalike) > maintenance_risk(&genuine));
        assert!(
            rank(&lookalike, &weights).final_priority < rank(&genuine, &weights).final_priority
        );
    }

    #[test]
    fn a_findings_place_does_not_depend_on_what_else_was_found() {
        // What makes a priority comparable between two runs: it is computed
        // from the group and nothing else, so it cannot move because the scan
        // next door found one more group.
        let weights = Weights::default();
        let alone = rank(&facts(), &weights);
        let mut crowd = facts();
        crowd.instances = 300;
        let _ = rank(&crowd, &weights);
        assert_eq!(rank(&facts(), &weights), alone);
    }

    #[test]
    fn turning_both_weights_off_ranks_on_confidence_alone() {
        let off = Weights {
            maintenance_risk: 0,
            refactoring_ease: 0,
        };
        let mut risky = facts();
        risky.instances = 20;
        let calm = facts();

        // Same confidence, wildly different risk: with nothing weighing the
        // maintenance argument, they land together rather than in an order
        // taken from an input nobody asked for.
        let a = rank(&risky, &off);
        let b = rank(&calm, &off);
        assert!((a.final_priority - b.final_priority).abs() < 1e-12);
        assert!(a.maintenance_risk > b.maintenance_risk);
    }

    #[test]
    fn the_reserved_measures_are_reported_absent_rather_than_zero() {
        let ranked = rank(&facts(), &Weights::default());
        assert_eq!(ranked.semantic_confidence, None);
        assert_eq!(ranked.source_artifact_confidence, None);
        assert_eq!(ranked.savings_confidence, None);
        assert_eq!(ranked.inputs.churn, None);
        assert_eq!(ranked.inputs.ownership_spread, None);
    }

    #[test]
    fn the_recipe_names_the_weights_it_was_composed_under() {
        // Two runs ranked under different weights order the same findings
        // differently, and the recorded recipe is what says so.
        assert_eq!(Weights::default().recipe(), "1-risk2-ease1");
        assert_ne!(
            Weights {
                maintenance_risk: 1,
                refactoring_ease: 3,
            }
            .recipe(),
            Weights::default().recipe()
        );
    }
}
