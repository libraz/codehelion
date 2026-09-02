//! Naming the wider finding that already reports a narrower cut's lines.

use super::Member;
use crate::report::Group;
use std::collections::{BTreeMap, BTreeSet};

/// Name, on every finding that has one, the finding already reporting a wider
/// cut of the same stretch.
///
/// A duplicated stretch of code is duplicated at more than one extent, and the
/// engine folds the extents that state the same thing: whole units through
/// containment among the settled groups, statement runs through run
/// subsumption. What it deliberately keeps apart is the cuts that state
/// *different* things about one place — four statements matching verbatim
/// inside eight that match up to renaming is two facts, and folding either
/// into the other would report less than was measured.
///
/// Both facts are worth keeping and neither is worth reading twice. Read down
/// a listing in priority order, cuts of one stretch arrive as separate entries
/// about the same lines, and nothing on them says so. This is what says so.
///
/// A cover has to report strictly more lines and has to account for each
/// occurrence with an occurrence of its own: a run repeated twice inside a
/// single duplicated function is not that function seen smaller, because the
/// repetition within one copy is a fact the function's own finding does not
/// carry. Where several findings cover one, the widest is named — it is the
/// single entry that subsumes the rest of the chain.
pub(super) fn mark_narrower_cuts(groups: &mut [Group]) {
    let extents: Vec<u64> = groups.iter().map(covered_lines).collect();
    let index = OccurrenceIndex::of(groups);
    let covers: Vec<Option<String>> = groups
        .iter()
        .enumerate()
        .map(|(inner, group)| {
            index
                .covering(group)
                .into_iter()
                .filter(|&outer| outer != inner && extents[outer] > extents[inner])
                .filter(|&outer| accounts_for(&groups[outer], group))
                .max_by(|&left, &right| {
                    extents[left].cmp(&extents[right]).then_with(|| {
                        // Widest first, then the smaller identifier, so a run
                        // naming a cover does not depend on the order the
                        // findings were assembled in.
                        groups[right].fingerprint.cmp(&groups[left].fingerprint)
                    })
                })
                .map(|outer| groups[outer].fingerprint.clone())
        })
        .collect();
    for (group, cover) in groups.iter_mut().zip(covers) {
        group.narrower_cut_of = cover;
    }
}

/// Source lines a finding's occurrences cover, summed.
fn covered_lines(group: &Group) -> u64 {
    group
        .members
        .iter()
        .map(|member| u64::from(member.end_line.saturating_sub(member.start_line)) + 1)
        .sum()
}

/// Whether `outer` reports the code `inner` reports, in the same places.
///
/// Each of `inner`'s occurrences must sit inside an occurrence of `outer`, and
/// no two of them inside the same one. The tightest containing occurrence is
/// claimed first so that a wide occurrence cannot be spent on a copy a narrow
/// one would have accounted for.
fn accounts_for(outer: &Group, inner: &Group) -> bool {
    let mut claimed = vec![false; outer.members.len()];
    for held in &inner.members {
        let tightest = outer
            .members
            .iter()
            .enumerate()
            .filter(|&(position, cover)| !claimed[position] && contains(cover, held))
            .min_by_key(|&(_, cover)| cover.end_line.saturating_sub(cover.start_line))
            .map(|(position, _)| position);
        match tightest {
            Some(position) => claimed[position] = true,
            None => return false,
        }
    }
    true
}

/// Whether one occurrence lies within another, in the same file.
fn contains(cover: &Member, held: &Member) -> bool {
    cover.file == held.file
        && cover.start_line <= held.start_line
        && held.end_line <= cover.end_line
}

/// The occurrences of every finding in a run, looked up by the place they sit.
///
/// A report can hold thousands of findings and asking each against every other
/// is quadratic in a way a large scan feels. Only a finding with an occurrence
/// covering one of the candidate's can account for it, so the search starts
/// from the candidate's least popular occurrence and [`accounts_for`] settles
/// the rest.
#[derive(Default)]
struct OccurrenceIndex<'a> {
    by_file: BTreeMap<&'a str, BTreeMap<u32, Vec<IndexedOccurrence>>>,
}

/// One indexed occurrence: where it ends, and which finding wrote it. Where it
/// starts is the key it is filed under.
#[derive(Clone, Copy)]
struct IndexedOccurrence {
    end_line: u32,
    group: usize,
}

impl<'a> OccurrenceIndex<'a> {
    fn of(groups: &'a [Group]) -> Self {
        let mut index = Self::default();
        for (group, entry) in groups.iter().enumerate() {
            for member in &entry.members {
                index
                    .by_file
                    .entry(member.file.as_str())
                    .or_default()
                    .entry(member.start_line)
                    .or_default()
                    .push(IndexedOccurrence {
                        end_line: member.end_line,
                        group,
                    });
            }
        }
        index
    }

    /// Findings with an occurrence covering the rarest occurrence of `group`.
    fn covering(&self, group: &Group) -> BTreeSet<usize> {
        let mut fewest: Option<BTreeSet<usize>> = None;
        for member in &group.members {
            let candidates = self.over(member);
            if candidates.is_empty() {
                return candidates;
            }
            if fewest
                .as_ref()
                .is_none_or(|current| candidates.len() < current.len())
            {
                fewest = Some(candidates);
            }
        }
        fewest.unwrap_or_default()
    }

    fn over(&self, member: &Member) -> BTreeSet<usize> {
        let Some(starts) = self.by_file.get(member.file.as_str()) else {
            return BTreeSet::new();
        };
        starts
            .range(..=member.start_line)
            .flat_map(|(_, covers)| covers)
            .filter(|cover| member.end_line <= cover.end_line)
            .map(|cover| cover.group)
            .collect()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::mark_narrower_cuts;
    use crate::report::ranking::fixtures::hidden_by_clone_id;
    use crate::report::{Group, Member};

    /// A finding covering the given stretches of one file.
    fn cut(id: u8, clone_type: &str, spans: &[(u32, u32)]) -> Group {
        let mut group = hidden_by_clone_id(&format!("{id:02x}").repeat(16), "unused");
        group.clone_type = clone_type.to_string();
        group.scope = "fragment".to_string();
        group.suppressed = None;
        group.members = spans
            .iter()
            .enumerate()
            .map(|(index, &(start_line, end_line))| Member {
                finding_id: format!("{id:02x}{index:030x}"),
                content: format!("{id:02x}").repeat(16),
                file: "src/suffix.cpp".to_string(),
                language: "cpp".to_string(),
                start_line,
                end_line,
                unit: Some("generate_candidates".to_string()),
                boilerplate: None,
                tokens: u64::from(end_line - start_line) * 8,
                canonical: index == 0,
            })
            .collect();
        group
    }

    fn named_covers(groups: &[Group]) -> Vec<Option<&str>> {
        groups
            .iter()
            .map(|group| group.narrower_cut_of.as_deref())
            .collect()
    }

    #[test]
    fn each_cut_of_one_stretch_names_the_widest_finding_reporting_it() {
        // Three cuts of one pair of regions inside one function. The engine
        // keeps them apart because they classify differently — the widest
        // matches only with a gap, the narrowest verbatim — and a reader going
        // down the list meets three entries about the same lines.
        let mut groups = vec![
            cut(1, "type-2", &[(306, 322), (354, 373)]),
            cut(2, "type-1", &[(305, 313), (353, 364)]),
            cut(3, "type-3", &[(305, 330), (353, 381)]),
        ];
        mark_narrower_cuts(&mut groups);
        let widest = "03".repeat(16);
        assert_eq!(
            named_covers(&groups),
            vec![Some(widest.as_str()), Some(widest.as_str()), None],
            "both narrower cuts name the one entry that reports the whole stretch"
        );
    }

    #[test]
    fn a_cut_covered_by_several_names_the_widest_of_them() {
        let mut groups = vec![
            cut(1, "type-1", &[(10, 12), (50, 52)]),
            cut(2, "type-1", &[(10, 20), (50, 60)]),
            cut(3, "type-1", &[(10, 40), (50, 80)]),
        ];
        mark_narrower_cuts(&mut groups);
        assert_eq!(
            named_covers(&groups),
            vec![
                Some("03".repeat(16).as_str()),
                Some("03".repeat(16).as_str()),
                None
            ],
            "the entry that subsumes the whole chain is the one worth going to"
        );
    }

    #[test]
    fn a_repetition_inside_one_copy_is_not_that_copy_seen_smaller() {
        // Both occurrences of the run sit inside the same occurrence of the
        // unit finding, so the unit finding does not report it: that the code
        // repeats within one copy is a fact only the run carries.
        let mut groups = vec![
            cut(1, "type-1", &[(12, 16), (20, 24)]),
            cut(2, "type-1", &[(10, 40), (50, 80)]),
        ];
        mark_narrower_cuts(&mut groups);
        assert_eq!(named_covers(&groups), vec![None, None]);
    }

    #[test]
    fn a_cut_with_a_copy_the_wider_finding_misses_names_nothing() {
        let mut groups = vec![
            cut(1, "type-1", &[(10, 12), (50, 52), (90, 92)]),
            cut(2, "type-1", &[(10, 40), (50, 80)]),
        ];
        mark_narrower_cuts(&mut groups);
        assert_eq!(named_covers(&groups), vec![None, None]);
    }

    #[test]
    fn two_findings_reporting_the_same_lines_do_not_name_each_other() {
        // Equal extents: neither reports more than the other, and a pair that
        // each called a narrower cut of the other would send a reader in a
        // circle.
        let mut groups = vec![
            cut(1, "type-1", &[(10, 40), (50, 80)]),
            cut(2, "type-2", &[(10, 40), (50, 80)]),
        ];
        mark_narrower_cuts(&mut groups);
        assert_eq!(named_covers(&groups), vec![None, None]);
    }

    #[test]
    fn a_cut_covered_only_in_another_file_names_nothing() {
        let mut groups = vec![
            cut(1, "type-1", &[(10, 12), (50, 52)]),
            cut(2, "type-1", &[(10, 40), (50, 80)]),
        ];
        groups[0].members[1].file = "src/other.cpp".to_string();
        mark_narrower_cuts(&mut groups);
        assert_eq!(named_covers(&groups), vec![None, None]);
    }

    #[test]
    fn which_finding_a_cut_names_does_not_depend_on_the_order_they_arrive_in() {
        let build = || {
            vec![
                cut(1, "type-1", &[(10, 12), (50, 52)]),
                cut(2, "type-1", &[(10, 20), (50, 60)]),
                cut(3, "type-1", &[(10, 40), (50, 80)]),
            ]
        };
        let mut forward = build();
        mark_narrower_cuts(&mut forward);
        let mut reversed: Vec<Group> = build().into_iter().rev().collect();
        mark_narrower_cuts(&mut reversed);
        let mut reversed_covers = named_covers(&reversed);
        reversed_covers.reverse();
        assert_eq!(named_covers(&forward), reversed_covers);
    }
}
