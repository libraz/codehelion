//! An offline two-dimensional containment index over rectangles.
//!
//! Several stages ask one question of a bucket of matches: is this pair of
//! spans covered on both sides by a pair already accepted? Asked pairwise the
//! question costs `O(m²)` in the buckets that grow largest — generated code and
//! repetitive blocks — which is where it must not.
//!
//! The caller sweeps its rectangles in first-span order, widest first at equal
//! starts, so a container is always inserted before anything it covers; that
//! sweep is what supplies the first-span start condition. Each Fenwick node
//! covers a prefix of second-span starts and holds a second Fenwick tree over
//! first-span ends, whose values are the greatest matching second-span end. A
//! query therefore answers the three remaining conditions in `O(log² m)`
//! instead of scanning the bucket.
//!
//! The index knows nothing about what a rectangle describes: matched token
//! runs, fragment matches, clone pairs and folded statement regions each
//! convert to a [`Rectangle`] at their own call site.

#![allow(clippy::redundant_pub_crate)] // shared helper reached from sibling modules

/// Two spans of one match, as `(first_start, first_end, second_start,
/// second_end)`.
///
/// The first-span start is carried so a rectangle spells out the whole match,
/// but it never enters the index: the caller's sweep order already decides that
/// half of the containment condition.
pub(crate) type Rectangle = (usize, usize, usize, usize);

/// Rectangles inserted so far, queryable for two-span containment.
pub(crate) struct ContainmentIndex {
    /// Sorted unique second-span starts.
    second_starts: Vec<usize>,
    /// Per outer Fenwick node, sorted unique first-span ends that can enter it.
    first_ends: Vec<Vec<usize>>,
    /// Per outer Fenwick node, a max Fenwick tree over reversed first-end
    /// positions. Reversing turns an `end >= threshold` query into a prefix.
    greatest_second_end: Vec<Vec<usize>>,
}

impl ContainmentIndex {
    /// Shape the index for every rectangle that may later be inserted.
    pub(crate) fn new(rectangles: &[Rectangle]) -> Self {
        let mut second_starts: Vec<usize> =
            rectangles.iter().map(|&(_, _, start, _)| start).collect();
        second_starts.sort_unstable();
        second_starts.dedup();
        let mut first_ends = vec![Vec::new(); second_starts.len() + 1];
        for &(_, first_end, second_start, _) in rectangles {
            let mut node = second_starts.partition_point(|&start| start < second_start) + 1;
            while node < first_ends.len() {
                first_ends[node].push(first_end);
                node += lowbit(node);
            }
        }
        for ends in &mut first_ends {
            ends.sort_unstable();
            ends.dedup();
        }
        let greatest_second_end = first_ends
            .iter()
            .map(|ends| vec![0; ends.len() + 1])
            .collect();
        Self {
            second_starts,
            first_ends,
            greatest_second_end,
        }
    }

    /// Record a rectangle as a possible container of later queries.
    pub(crate) fn insert(
        &mut self,
        (_first_start, first_end, second_start, second_end): Rectangle,
    ) {
        let mut node = self
            .second_starts
            .partition_point(|&start| start < second_start)
            + 1;
        while node < self.first_ends.len() {
            let ends = &self.first_ends[node];
            let reversed = ends.len() - ends.partition_point(|&end| end < first_end);
            let values = &mut self.greatest_second_end[node];
            let mut position = reversed;
            while position < values.len() {
                values[position] = values[position].max(second_end);
                position += lowbit(position);
            }
            node += lowbit(node);
        }
    }

    /// Whether an already inserted rectangle covers both spans of this one.
    pub(crate) fn contains(
        &self,
        (_first_start, first_end, second_start, second_end): Rectangle,
    ) -> bool {
        let mut node = self
            .second_starts
            .partition_point(|&start| start <= second_start);
        while node > 0 {
            let ends = &self.first_ends[node];
            let reversed = ends.len() - ends.partition_point(|&end| end < first_end);
            let values = &self.greatest_second_end[node];
            let mut position = reversed;
            let mut greatest = 0;
            while position > 0 {
                greatest = greatest.max(values[position]);
                position -= lowbit(position);
            }
            if greatest >= second_end {
                return true;
            }
            node -= lowbit(node);
        }
        false
    }
}

/// Least significant set bit of a one-based Fenwick index.
const fn lowbit(index: usize) -> usize {
    index.isolate_lowest_one()
}
