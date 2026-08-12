//! Small helpers for keeping stable-identity records unique.
//!
//! Stable identifiers are a last-mile contract between the analysis core and
//! its consumers.  A consumer may encounter the same record twice while
//! assembling several evidence families, but it must never silently choose
//! between two different payloads carrying the same identifier.  This module
//! owns that narrow policy without knowing anything about report or storage
//! models.

use std::collections::BTreeMap;

/// The result of exact identity normalization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollapseResult {
    /// Input positions retained in their original deterministic order.
    pub retained: Vec<usize>,
    /// Number of exact duplicate records removed.
    pub collapsed: u64,
}

/// An identity collision whose payloads disagree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityConflict<K> {
    /// The stable identity that was emitted with two different payloads.
    pub identity: K,
}

/// Keep one record for each identity, rejecting unequal payloads.
///
/// Records are retained in input order.  Callers must provide a deterministic
/// order; the helper deliberately does not inspect or sort payloads because
/// doing so would make it a canonical encoder for every consumer model.  An
/// equal identity with exactly equal payload is one record and increments
/// [`CollapseResult::collapsed`].  An equal identity with a different payload
/// is an invariant violation and is returned to the caller.
///
/// # Errors
///
/// Returns [`IdentityConflict`] when one stable identity is associated with
/// unequal payloads.
pub fn collapse_exact<K, P>(records: &[(K, P)]) -> Result<CollapseResult, IdentityConflict<K>>
where
    K: Clone + Ord,
    P: Eq,
{
    let mut seen = BTreeMap::<K, &P>::new();
    let mut retained = Vec::with_capacity(records.len());
    let mut collapsed = 0_u64;
    for (index, (identity, payload)) in records.iter().enumerate() {
        if let Some(existing) = seen.get(identity) {
            if *existing == payload {
                collapsed = collapsed.saturating_add(1);
                continue;
            }
            return Err(IdentityConflict {
                identity: identity.clone(),
            });
        }
        seen.insert(identity.clone(), payload);
        retained.push(index);
    }
    Ok(CollapseResult {
        retained,
        collapsed,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::{IdentityConflict, collapse_exact};

    #[test]
    fn collapses_only_exactly_equal_payloads() {
        let result = collapse_exact(&[
            (1_u8, b"same".as_slice()),
            (2, b"other".as_slice()),
            (1, b"same".as_slice()),
        ])
        .expect("equal payload should be accepted");
        assert_eq!(result.retained, vec![0, 1]);
        assert_eq!(result.collapsed, 1);
    }

    #[test]
    fn rejects_equal_identity_with_different_payload() {
        let error = collapse_exact(&[(1_u8, b"first".as_slice()), (1, b"second".as_slice())])
            .expect_err("unequal payload must remain an invariant error");
        assert_eq!(error, IdentityConflict { identity: 1 });
    }
}
