//! Structural-mode analysis: the whole Type-2/Type-3 pipeline, wired end to
//! end over already-parsed IR.
//!
//! The stages each live in their own module; this one composes them into the
//! funnel the mode runs:
//!
//! 1. [`crate::features`] turns each file's IR into candidate-extraction
//!    features (statement windows, subtrees, characteristic vector, approximate
//!    CFG, API calls);
//! 2. [`crate::candidate`] seeds exact-hash fragment pairs and [`crate::near_match`]
//!    proposes near-clone unit pairs by MinHash/LSH — both over-approximate
//!    cheaply, and both are lifted here to *unit* pairs;
//! 3. [`crate::maximal`] folds the sliding-window seeds back into the maximal
//!    shared statement runs they describe, so a duplicated block is one region
//!    rather than a fan of overlapping window matches;
//! 4. [`crate::verify`] judges each distinct unit pair precisely, keeping only
//!    the ones that clear the clone threshold;
//! 5. [`crate::grouping`] turns the surviving pairs into cohesive medoid groups,
//!    so non-transitive Type-3 chains do not fuse.
//!
//! Regions and groups answer different questions and neither replaces the
//! other: a group says two whole units are copies of each other, a region says
//! one stretch of statements is shared, which happens between units that are
//! not copies at all.
//!
//! Every unit carries its raw [`UnitFingerprint`] as its stable, position-free
//! grouping key ([`crate::stable_id`]). The whole function is deterministic: the
//! unit order follows the IR walk, candidate pairs are deduplicated through an
//! ordered set, and grouping orders its own output. Nothing here executes target
//! code — it only reads IR that was already produced from source.

use std::collections::{BTreeMap, BTreeSet};

use crate::boilerplate::{self, Boilerplate};
use crate::candidate::{self, CandidateConfig, CandidateStats};
use crate::clone_class::CloneClass;
use crate::conditional::ArmPath;
use crate::control_flow::{self, ControlFlowConfig, ControlFlowStats};
use crate::discovery::{BuildVariant, Language};
use crate::engine::{LiteralNorm, normalize::Resolution};
use crate::features::{self, FileFeatures};
use crate::frontend::{Lexeme, Token, TokenKind, UnitKind};
use crate::grouping::{
    self, GroupingConfig, GroupingSet, GroupingStats, GroupingUnit, SimilarityEdge,
};
use crate::ir::{ByteRange, IrNode, Shape, SyntaxIrFile};
use crate::maximal::{self, MaximalConfig, RegionSide, RegionStats, SharedRegion};
use crate::near_match::{self, NearMatchConfig, NearMatchStats};
use crate::stable_id::{
    self, CloneGroupFingerprint, ContentNorm, CrossVariantComparisonId, CrossVariantGroupId,
    FileContext, FragmentFingerprint, UnitFingerprint,
};
use crate::substitution;
use crate::test_code::{self, TestCodeEvidence};
use crate::types::{ApiEvidence, TypeEvidence, TypeTag};
use crate::verify::{self, SimilarityBreakdown, UnitView, VerifyConfig};

mod analysis;
mod evidence;
mod model;
mod pairs;
mod regions;
mod reporting;
mod siblings;
mod units;

use evidence::{UnitEvidence, token_count_meets_minimum, unit_evidence, unit_meets_minimum};
use pairs::{lift_to_unit_pairs, unrepresented_pairs};
use regions::{confirm_regions, drop_subsumed, fold_by_content, grow_runs};
use reporting::{dominant_boilerplate_members, group_detail, written_once_per_width_members};
use siblings::sweep_siblings;
use units::{flatten_units, line_range, view};

#[cfg(test)]
use regions::{Confirmed, covers_run, merge_adjacent};
#[cfg(test)]
use reporting::{dominant_boilerplate, is_allocation_api, set_jaccard};

pub use analysis::*;
pub use evidence::*;
pub use model::*;
pub use reporting::span_identifier_jaccard;

/// One analysed unit's data, held together for verification and grouping.
struct Unit {
    file: usize,
    local: usize,
    kind: UnitKind,
    statements: Vec<crate::ir::StatementSummary>,
    fingerprint: UnitFingerprint,
    content: FragmentFingerprint,
    normalized_content: FragmentFingerprint,
    range: ByteRange,
    lines: (u32, u32),
    tokens: (usize, usize),
    name: Option<Lexeme>,
    boilerplate: Option<Boilerplate>,
    test_code: bool,
    test_code_evidence: Option<TestCodeEvidence>,
    /// The preprocessor conditionals the unit sits under, if any.
    arms: ArmPath,
}

impl Unit {
    /// Content domain used to identify a clone relation of `class`.
    const fn group_content(&self, class: CloneClass) -> FragmentFingerprint {
        if matches!(class, CloneClass::Type1) {
            self.content
        } else {
            self.normalized_content
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests;
