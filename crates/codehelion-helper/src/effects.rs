//! Conservative effect summaries from closed compiler-confirmed constructs.
//!
//! The summary is evidence, not a proof of purity: an empty interaction list
//! means this deliberately small vocabulary observed nothing, never that a
//! unit has no effects. Consumers may reward matching non-empty evidence but
//! must not reject a finding or infer purity from its absence.

use crate::ir::{EffectSummary, SemanticConstruct, SemanticConstructKind};

/// Summarize the closed interactions represented by semantic constructs.
#[must_use]
pub fn summarize(constructs: &[SemanticConstruct]) -> EffectSummary {
    let mut interactions = constructs
        .iter()
        .filter(|construct| construct.kind == SemanticConstructKind::AcquireResource)
        .filter_map(|construct| match construct.resource_kind.as_deref() {
            Some("file") => Some("file_io".to_owned()),
            Some("lock") => Some("synchronization".to_owned()),
            _ => None,
        })
        .collect::<Vec<_>>();
    interactions.sort();
    interactions.dedup();
    EffectSummary {
        computed: true,
        writes: Vec::new(),
        interactions,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::ir::{Anchor, SourceRange};

    fn construct(kind: SemanticConstructKind, resource_kind: Option<&str>) -> SemanticConstruct {
        SemanticConstruct {
            anchor: Anchor::written_here(SourceRange {
                file: "fixture.rs".to_owned(),
                start_byte: 0,
                end_byte: 1,
                start_line: 1,
            }),
            kind,
            fallible_kind: None,
            direct_propagation: None,
            resource_kind: resource_kind.map(ToOwned::to_owned),
        }
    }

    #[test]
    fn records_only_closed_resource_interactions() {
        let summary = summarize(&[
            construct(SemanticConstructKind::AcquireResource, Some("file")),
            construct(SemanticConstructKind::ReleaseResource, Some("file")),
            construct(SemanticConstructKind::AcquireResource, Some("lock")),
            construct(SemanticConstructKind::AcquireResource, Some("lock")),
        ]);
        assert!(summary.computed);
        assert_eq!(summary.interactions, ["file_io", "synchronization"]);
        assert!(summary.writes.is_empty());
    }
}
