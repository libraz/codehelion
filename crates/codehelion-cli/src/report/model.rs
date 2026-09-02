//! The serialized report model, grouped by what each record describes.
//!
//! Every type here is part of the JSON report shape and is re-exported from
//! [`crate::report`]; the split is by subject — the run, its clone groups, the
//! comparisons kept beside them, and what a baseline did — so that one record
//! and the counts taken over it stay in one place.

mod baseline;
mod comparison;
mod group;
mod run;

pub use baseline::{
    BaselineStatus, Derivation, ExcludedCounts, GoneAnchor, GoneGroup, GroupBaseline,
    UnparsedCounts,
};
pub use comparison::{
    CrossLanguageComparison, CrossLanguageComparisonNotRun, CrossLanguageGroup,
    CrossLanguageMember, CrossVariantComparison, CrossVariantComparisonNotRun, CrossVariantGroup,
    CrossVariantMember, GroupSiblings, NearMiss, NearMissUnit, Sibling, SiblingSimilarity,
};
pub use group::{
    ArtifactSavings, BodyMateriality, Group, GroupCounts, GroupIdentity, IDENTITY_ADOPTED,
    IDENTITY_RETAINED, Priority, PriorityInputs, SemanticEvidence, SemanticNodeMapping,
    SemanticRuleEvidence, Similarity, SuppressedCounts,
};
pub use run::{
    BuildVariantInfo, CompilerCoverage, ConfigurationInfo, DetectorVersion, ExecutionRefusal,
    FileCounts, Guardrails, ReportedSeam, RunInfo, RunTimings, SeamReport, Summary, TopChurn,
    TreeChanges,
};
