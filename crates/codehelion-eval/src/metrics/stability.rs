use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::schema::{DetectionResult, Finding};

use super::ratio;

/// Run-to-run stability of two detection results over the same input.
///
/// Finding identity is the sorted set of `(file, start_line, end_line)`
/// fragments, never the detector-assigned `id` (which may vary across runs).
#[derive(Debug, Clone, PartialEq)]
pub struct Stability {
    /// Whether both runs reported exactly the same set of findings.
    pub identical: bool,
    /// Jaccard similarity of the two finding-key sets. `1.0` when both runs are
    /// empty.
    pub jaccard: f64,
    /// `1.0 - jaccard`: the fraction of findings that changed.
    pub churn: f64,
}

/// Canonical, id-independent key for a finding: its fragments as sorted tuples.
type FindingKey = Vec<(String, u32, u32)>;

fn key_set<'a>(findings: impl Iterator<Item = &'a Finding>) -> BTreeSet<FindingKey> {
    findings
        .map(|finding| {
            let mut key: FindingKey = finding
                .fragments
                .iter()
                .map(|fragment| {
                    (
                        fragment.file.clone(),
                        fragment.start_line,
                        fragment.end_line,
                    )
                })
                .collect();
            key.sort();
            key
        })
        .collect()
}

/// Compare the finding sets of two runs `a` and `b` over the same input.
#[must_use]
pub fn stability(a: &DetectionResult, b: &DetectionResult) -> Stability {
    stability_for_key_sets(&key_set(a.findings.iter()), &key_set(b.findings.iter()))
}

/// Compare semantic finding sets separately for every registered rule.
///
/// A finding established by more than one registered rule is included in each
/// corresponding rule's set. Rules absent from one result are still present in
/// the returned map, so a removed or newly introduced rule reports its full
/// churn rather than disappearing from the comparison.
#[must_use]
pub fn stability_by_rule(a: &DetectionResult, b: &DetectionResult) -> BTreeMap<String, Stability> {
    let rule_ids: BTreeSet<&str> = a
        .findings
        .iter()
        .chain(&b.findings)
        .flat_map(|finding| finding.rule_ids.iter().map(String::as_str))
        .collect();
    rule_ids
        .into_iter()
        .map(|rule_id| {
            let left = key_set(
                a.findings
                    .iter()
                    .filter(|finding| finding.rule_ids.iter().any(|id| id == rule_id)),
            );
            let right = key_set(
                b.findings
                    .iter()
                    .filter(|finding| finding.rule_ids.iter().any(|id| id == rule_id)),
            );
            (rule_id.to_string(), stability_for_key_sets(&left, &right))
        })
        .collect()
}

fn stability_for_key_sets(
    keys_a: &BTreeSet<FindingKey>,
    keys_b: &BTreeSet<FindingKey>,
) -> Stability {
    let intersection = keys_a.intersection(keys_b).count();
    let union = keys_a.union(keys_b).count();
    let jaccard = ratio(intersection, union).unwrap_or(1.0);
    Stability {
        identical: keys_a == keys_b,
        jaccard,
        churn: 1.0 - jaccard,
    }
}

impl fmt::Display for Stability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "identical                 {}", self.identical)?;
        writeln!(f, "jaccard                   {:.4}", self.jaccard)?;
        write!(f, "churn                     {:.4}", self.churn)
    }
}
