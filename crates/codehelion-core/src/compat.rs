//! What a version bump does to results that were already recorded.
//!
//! Every stable id in this tool is a hash of rules as much as of code: the
//! fingerprint schema, the normalization, the frontend that decided where a
//! unit begins. Improving any of them is the ordinary business of the project
//! and it moves identifiers that a user's baseline, history and suppressions
//! are written in terms of. Without a way to say which change did that, the
//! only safe reading of *any* version difference is the worst one, and a
//! release that renamed a field would throw away a year of recorded history.
//!
//! # The question this module answers
//!
//! Given two sets of `(component, version)` pairs — one recorded beside a past
//! run, one describing the build in hand — what, if anything, does the
//! difference invalidate? Three answers are possible and they are ordered:
//!
//! - [`Impact::Identifiers`]: ids were computed under different rules. Nothing
//!   recorded under the old ones matches, and matching nothing looks exactly
//!   like a duplication that went away, which is the failure worth the most
//!   care to avoid.
//! - [`Impact::Grouping`]: the same code still hashes to the same content, but
//!   which occurrences are cohesive enough to sit together can differ. Most
//!   findings survive; some group ids move because their membership did.
//! - [`Impact::Reporting`]: nothing an identifier or a group membership rests
//!   on. The same findings, said differently.
//!
//! A component this build has never heard of is read as
//! [`Impact::Identifiers`]. A rule whose effects are unknown could have moved
//! anything, and the alternative — assuming a strange name is harmless —
//! accepts a baseline that silently matches nothing.
//!
//! # Measuring what actually moved
//!
//! The classification above is a promise made when the version is bumped, and
//! a promise is worth what it is checked against. [`Churn`] is the check: run
//! the same tree twice and compare the two sets of finding ids. A change
//! declared [`Impact::Reporting`] that moves an id is a mistake in the
//! declaration, and it is visible as a churn rate above zero.

use std::collections::BTreeSet;

/// What a difference in one component's version can do to recorded results.
///
/// Ordered by how much it invalidates, so the worst of a set of differences is
/// its maximum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Impact {
    /// Which findings are shown and in what order. No identifier and no
    /// group membership rests on it.
    Reporting,
    /// Which occurrences sit together can change, so a group id can move
    /// without any code changing. Member content ids do not move.
    Grouping,
    /// Every stable id is computed differently. Nothing recorded under the
    /// previous rules matches anything found under these.
    Identifiers,
}

impl Impact {
    /// Stable lowercase identifier used in reports and messages.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Reporting => "reporting",
            Self::Grouping => "grouping",
            Self::Identifiers => "identifiers",
        }
    }

    /// Whether a difference at this level stops recorded ids from matching.
    #[must_use]
    pub const fn breaks_identity(self) -> bool {
        matches!(self, Self::Identifiers)
    }

    /// One sentence a reader can act on.
    #[must_use]
    pub const fn consequence(self) -> &'static str {
        match self {
            Self::Reporting => "the same findings, reported differently",
            Self::Grouping => {
                "the same occurrences, which may be grouped differently, \
                 so some group ids move"
            }
            Self::Identifiers => {
                "identifiers computed under different rules, \
                 so nothing recorded before matches"
            }
        }
    }
}

/// One versioned component of the detector, and what bumping it costs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Component {
    /// The name recorded beside a run.
    pub name: &'static str,
    /// What a difference in its version does.
    pub impact: Impact,
    /// Why it does that, for the reader who has to decide whether to migrate.
    pub note: &'static str,
}

/// Prefix every language frontend's component name carries.
const FRONTEND_PREFIX: &str = "frontend.";

/// The components whose effect on recorded results is known.
///
/// Frontends are matched on their shared `frontend.` prefix rather than listed
/// one per language: a new language arrives with a new name, and a table that
/// has to be edited to keep an unrelated language safe is a table that will
/// not be.
pub const COMPONENTS: &[Component] = &[
    Component {
        name: "fp-schema",
        impact: Impact::Identifiers,
        note: "folded into every stable id, so a bump moves all of them at once",
    },
    Component {
        name: "normalization",
        impact: Impact::Identifiers,
        note: "what tokens are reduced to before hashing; \
               different normalization is different content",
    },
    Component {
        name: "literals",
        impact: Impact::Identifiers,
        note: "how literal values are folded before hashing, \
               which is part of what a normalized content id is",
    },
    Component {
        name: "frontend",
        impact: Impact::Identifiers,
        note: "where a unit begins and ends and which tokens it holds",
    },
    Component {
        name: "grouping",
        impact: Impact::Grouping,
        note: "which occurrences are cohesive enough to sit together; \
               the occurrences do not move, the groups they form do",
    },
    Component {
        name: "features",
        impact: Impact::Grouping,
        note: "which pairs are proposed for comparison at all, \
               so which of them can end up in one group",
    },
    Component {
        name: "verify-weights",
        impact: Impact::Grouping,
        note: "how similar two occurrences are judged to be, \
               which decides where a group is cut",
    },
    Component {
        name: "boilerplate",
        impact: Impact::Reporting,
        note: "which groups are named as a recognised shape; \
               the group is found and identified either way",
    },
    Component {
        name: "test-code",
        impact: Impact::Reporting,
        note: "which occurrences are read as test code; \
               the group is found and identified either way",
    },
    Component {
        name: "ranking",
        impact: Impact::Reporting,
        note: "the order findings are read in; no id and no membership rests on it",
    },
];

/// What a difference in `component`'s version does, and why.
///
/// A name this build does not know answers [`Impact::Identifiers`]: a rule
/// nobody here can describe may have moved anything, and the cost of being
/// wrong the other way is a suppression that silently stops suppressing.
#[must_use]
pub fn component(name: &str) -> Component {
    let base = name
        .strip_prefix(FRONTEND_PREFIX)
        .map_or(name, |_| "frontend");
    COMPONENTS
        .iter()
        .find(|known| known.name == base)
        .copied()
        .unwrap_or(Component {
            name: "unknown",
            impact: Impact::Identifiers,
            note: "a component this build does not know, read at its worst \
                   because an unknown rule may have moved anything",
        })
}

/// One component whose version differs between two runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Drift {
    /// The component's recorded name.
    pub component: String,
    /// The version the earlier result was produced under; absent when the
    /// component did not exist yet.
    pub previous: Option<String>,
    /// The version in hand; absent when the component is gone.
    pub current: Option<String>,
    /// What the difference does to results recorded under `previous`.
    pub impact: Impact,
}

impl Drift {
    /// One line naming the component, both versions and the consequence.
    #[must_use]
    pub fn describe(&self) -> String {
        fn side(version: Option<&String>) -> &str {
            version.map_or("absent", String::as_str)
        }
        format!(
            "{} {} -> {} ({})",
            self.component,
            side(self.previous.as_ref()),
            side(self.current.as_ref()),
            self.impact.name(),
        )
    }
}

/// Every component whose version differs between the two recorded sets.
///
/// A component present on only one side counts: gaining a frontend changes
/// what is read, and losing one changes it back. Both are reported with the
/// missing side absent rather than filled in with a guess.
///
/// The result is ordered by component name, so one pair of runs always
/// produces one listing.
#[must_use]
pub fn drift(previous: &[(String, String)], current: &[(String, String)]) -> Vec<Drift> {
    let names: BTreeSet<&str> = previous
        .iter()
        .chain(current)
        .map(|(name, _)| name.as_str())
        .collect();
    let version_in = |set: &[(String, String)], name: &str| {
        set.iter()
            .find(|(component, _)| component == name)
            .map(|(_, version)| version.clone())
    };
    names
        .into_iter()
        .filter_map(|name| {
            let before = version_in(previous, name);
            let after = version_in(current, name);
            (before != after).then(|| Drift {
                component: name.to_string(),
                previous: before,
                current: after,
                impact: component(name).impact,
            })
        })
        .collect()
}

/// The most invalidating impact among a set of differences, or `None` when
/// nothing differs.
#[must_use]
pub fn worst(drifts: &[Drift]) -> Option<Impact> {
    drifts.iter().map(|entry| entry.impact).max()
}

/// How many finding ids one run kept from another over the same source.
///
/// Both sides must describe the same tree under the same build variant.
/// Anything else measures the code changing rather than the rules, which is
/// what an ordinary audit is for.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Churn {
    /// Ids the earlier run reported.
    pub before: usize,
    /// Ids the later run reported.
    pub after: usize,
    /// Ids both reported.
    pub kept: usize,
}

impl Churn {
    /// Compare two sets of finding ids.
    #[must_use]
    pub fn between<'a, P, C>(previous: P, current: C) -> Self
    where
        P: IntoIterator<Item = &'a str>,
        C: IntoIterator<Item = &'a str>,
    {
        let before: BTreeSet<&str> = previous.into_iter().collect();
        let after: BTreeSet<&str> = current.into_iter().collect();
        Self {
            kept: before.intersection(&after).count(),
            before: before.len(),
            after: after.len(),
        }
    }

    /// Ids the later run no longer reports.
    #[must_use]
    pub const fn lost(&self) -> usize {
        self.before - self.kept
    }

    /// Ids the later run reports that the earlier one did not.
    #[must_use]
    pub const fn gained(&self) -> usize {
        self.after - self.kept
    }

    /// The fraction of ids that moved, counting both directions.
    ///
    /// Zero when the two runs report exactly the same ids and one when they
    /// share none. Both sides are counted because a change that keeps every
    /// old id and adds a hundred new ones has not left a user's history
    /// intact — it has buried it — and a measure reading only survival would
    /// call that perfect.
    ///
    /// Two runs that both found nothing have nothing that could have moved,
    /// and answer zero.
    #[must_use]
    pub fn rate(&self) -> f64 {
        let union = self.before + self.after - self.kept;
        if union == 0 {
            return 0.0;
        }
        #[allow(clippy::cast_precision_loss)] // finding counts are far below 2^53
        {
            (union - self.kept) as f64 / union as f64
        }
    }

    /// Whether every id survived in both directions.
    #[must_use]
    pub const fn is_stable(&self) -> bool {
        self.before == self.kept && self.after == self.kept
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn versions(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(name, version)| ((*name).to_string(), (*version).to_string()))
            .collect()
    }

    #[test]
    fn every_language_frontend_is_known_without_being_listed() {
        // A frontend arriving with a new language must not read as unknown:
        // that would make every result recorded before it unusable the day the
        // language is added, for a component that was never involved.
        assert_eq!(component("frontend.rust").impact, Impact::Identifiers);
        assert_eq!(component("frontend.zig").impact, Impact::Identifiers);
        assert_eq!(component("frontend.rust").name, "frontend");
    }

    #[test]
    fn a_component_nobody_here_can_describe_is_read_at_its_worst() {
        let unknown = component("some-future-rule");
        assert_eq!(unknown.impact, Impact::Identifiers);
        assert!(unknown.note.contains("does not know"));
    }

    #[test]
    fn the_known_components_say_what_they_cost() {
        assert_eq!(component("fp-schema").impact, Impact::Identifiers);
        assert_eq!(component("normalization").impact, Impact::Identifiers);
        assert_eq!(component("literals").impact, Impact::Identifiers);
        assert_eq!(component("grouping").impact, Impact::Grouping);
        assert_eq!(component("ranking").impact, Impact::Reporting);
        assert_eq!(component("verify-weights").impact, Impact::Grouping);
        assert_eq!(component("boilerplate").impact, Impact::Reporting);
        assert!(COMPONENTS.iter().all(|entry| !entry.note.is_empty()));
    }

    #[test]
    fn two_runs_of_one_build_have_drifted_in_nothing() {
        let recorded = versions(&[("fp-schema", "v1"), ("ranking", "1-risk2-ease1")]);
        assert!(drift(&recorded, &recorded).is_empty());
        assert_eq!(worst(&[]), None);
    }

    #[test]
    fn a_reordered_recording_is_not_a_difference() {
        // The pairs are stored ordered, but nothing about the comparison may
        // depend on that: a set read back in another order is the same set.
        let one = versions(&[("fp-schema", "v1"), ("normalization", "2")]);
        let other = versions(&[("normalization", "2"), ("fp-schema", "v1")]);
        assert!(drift(&one, &other).is_empty());
    }

    #[test]
    fn changing_the_order_findings_are_read_in_moves_no_identifier() {
        let before = versions(&[("fp-schema", "v1"), ("ranking", "1-risk2-ease1")]);
        let after = versions(&[("fp-schema", "v1"), ("ranking", "1-risk1-ease1")]);

        let moved = drift(&before, &after);
        assert_eq!(moved.len(), 1);
        assert_eq!(moved[0].component, "ranking");
        assert_eq!(worst(&moved), Some(Impact::Reporting));
        assert!(!moved[0].impact.breaks_identity());
    }

    #[test]
    fn one_identifier_change_among_harmless_ones_decides_the_verdict() {
        let before = versions(&[
            ("fp-schema", "v1"),
            ("grouping", "grouping-v1"),
            ("ranking", "1-risk2-ease1"),
        ]);
        let after = versions(&[
            ("fp-schema", "v2"),
            ("grouping", "grouping-v2"),
            ("ranking", "1-risk1-ease1"),
        ]);

        let moved = drift(&before, &after);
        assert_eq!(moved.len(), 3);
        assert_eq!(worst(&moved), Some(Impact::Identifiers));
    }

    #[test]
    fn gaining_a_language_is_a_difference_with_one_side_absent() {
        let before = versions(&[("frontend.rust", "rust-ir-v0")]);
        let after = versions(&[("frontend.rust", "rust-ir-v0"), ("frontend.c", "c-ir-v0")]);

        let moved = drift(&before, &after);
        assert_eq!(moved.len(), 1);
        assert_eq!(moved[0].component, "frontend.c");
        assert_eq!(moved[0].previous, None);
        assert!(moved[0].describe().contains("absent -> c-ir-v0"));
    }

    #[test]
    fn the_listing_does_not_depend_on_the_order_the_pairs_arrived_in() {
        let before = versions(&[("normalization", "1"), ("fp-schema", "v1")]);
        let after = versions(&[("fp-schema", "v2"), ("normalization", "2")]);

        let names: Vec<String> = drift(&before, &after)
            .into_iter()
            .map(|entry| entry.component)
            .collect();
        assert_eq!(names, vec!["fp-schema", "normalization"]);
    }

    #[test]
    fn a_tree_whose_ids_all_survived_has_churned_by_nothing() {
        let churn = Churn::between(["a", "b", "c"], ["c", "b", "a"]);
        assert_eq!(churn.kept, 3);
        assert_eq!(churn.lost(), 0);
        assert_eq!(churn.gained(), 0);
        assert!(churn.rate().abs() < f64::EPSILON);
        assert!(churn.is_stable());
    }

    #[test]
    fn ids_that_all_moved_have_churned_completely() {
        let churn = Churn::between(["a", "b"], ["c", "d"]);
        assert_eq!(churn.kept, 0);
        assert!((churn.rate() - 1.0).abs() < f64::EPSILON);
        assert!(!churn.is_stable());
    }

    #[test]
    fn findings_added_without_losing_any_still_count_as_movement() {
        // Keeping every old id while burying it under new ones is not a run a
        // user's history survived, and a measure reading only survival would
        // call it perfect.
        let churn = Churn::between(["a", "b"], ["a", "b", "c", "d"]);
        assert_eq!(churn.lost(), 0);
        assert_eq!(churn.gained(), 2);
        assert!((churn.rate() - 0.5).abs() < f64::EPSILON);
        assert!(!churn.is_stable());
    }

    #[test]
    fn two_runs_that_found_nothing_have_nothing_that_could_have_moved() {
        let churn = Churn::between([], []);
        assert!(churn.rate().abs() < f64::EPSILON);
        assert!(churn.is_stable());
    }
}
