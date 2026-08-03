//! Standalone finding-detail serialization and text rendering.

use super::{
    EXPLAIN_RESPONSE_CLONE_GROUP, EXPLAIN_RESPONSE_CROSS_LANGUAGE_GROUP,
    EXPLAIN_RESPONSE_CROSS_VARIANT_GROUP, EXPLAIN_RESPONSE_OCCURRENCE, EXPLAIN_RESPONSE_SIBLING,
    FINDING_DETAIL_SCHEMA_VERSION, Group, MappingEvidence, Member, Palette, SCOPE_FRAGMENT,
    SemanticEvidence, SemanticOperationGraph, Serialize, Sibling, Similarity, Suppression,
    TestCodeEvidence, TextOptions, Write, detail_json, io, render_group,
};

/// Where a stored run ranked a finding, as it was recorded.
///
/// Deliberately not [`Priority`](crate::report::Priority). That one is what a scan just computed, and
/// every measure in it exists by construction. This one is what a database
/// holds, which may have been written by a release that took fewer measures
/// than this one does — so a measure is `None` when the run did not take it,
/// rather than filled in with today's rules applied to yesterday's facts.
#[derive(Debug, Clone, Serialize)]
pub struct RecordedPriority {
    /// The composed ranking value the run acted on.
    pub value: f64,
    /// How sure the run was that the finding was worth reporting.
    pub clone_confidence: f64,
    /// What the run judged keeping the copies in step to cost.
    pub maintenance_risk: Option<f64>,
    /// What the run judged removing the duplication to cost.
    pub refactoring_difficulty: Option<f64>,
    /// How sure the finding is semantically equivalent.
    pub semantic_confidence: Option<f64>,
    /// How sure the source is the source of a given artifact.
    pub source_artifact_confidence: Option<f64>,
    /// How sure the reported savings are.
    pub savings_confidence: Option<f64>,
    /// The group facts behind the measures, as the stored run holds them.
    pub inputs: RecordedInputs,
}

/// The stored facts a recorded ranking was read from.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct RecordedInputs {
    /// Token count of the smallest occurrence.
    pub smallest_member_tokens: u64,
    /// Token count of the largest occurrence.
    pub largest_member_tokens: u64,
    /// Occurrences in the group.
    pub instances: u64,
    /// Distinct files the occurrences sit in.
    pub files: u64,
    /// Distinct directories the occurrences sit in.
    pub directories: u64,
    /// Distinct languages the occurrences are written in.
    pub languages: u64,
    /// The floor the run reported under. `None` for a run recorded before runs
    /// stored it, which is the one input a stored ranking can be missing while
    /// still having been computed from it.
    pub min_clone_tokens: Option<u64>,
}

/// The detail view of one occurrence, shared by `codehelion explain`'s text
/// and JSON output.
#[derive(Debug, Serialize)]
pub struct FindingDetail {
    /// The occurrence itself, in the same shape as a report member.
    #[serde(flatten)]
    pub member: Member,
    /// The owning group.
    pub group: GroupRef,
    /// Row id of the scan run the occurrence belongs to.
    pub scan_run: i64,
    /// Source/artifact mappings for this exact fragment occurrence.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub source_artifact_mappings: Vec<SourceArtifactMappingDetail>,
    /// Refactoring estimates retained for this finding's group.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub clone_group_savings: Vec<CloneGroupSavingsDetail>,
}

/// Standalone explain view of one supplemental sibling finding.
#[derive(Debug, Serialize)]
pub struct SiblingDetail {
    /// Row id of the scan run that recorded the sibling.
    pub scan_run: i64,
    /// Primary clone group the supplemental finding belongs to.
    pub group_fingerprint: String,
    /// Sibling member and canonical-to-sibling verifier evidence.
    pub sibling: Sibling,
}

/// The standalone explain view of one explicitly requested Rust-to-C++
/// semantic comparison group.
#[derive(Debug, Serialize)]
pub struct CrossLanguageGroupDetail {
    /// Stable comparison-domain group identity.
    pub group_id: String,
    /// Stable identity of the comparison that recorded this group.
    pub comparison_id: String,
    /// Version of the comparison policy.
    pub policy_version: String,
    /// Root shared by the compared partitions.
    pub root_path: String,
    /// Origin build variants kept separate by the comparison.
    pub origin_variants: Vec<String>,
    /// Registered closed semantic rule that matched.
    pub rule_id: String,
    /// Registered rule revision.
    pub rule_version: u32,
    /// Confidence after the available semantic evidence was combined.
    pub semantic_confidence: f64,
    /// Closed API or compiler-construct correspondence identifiers used by the rule.
    pub correspondence_ids: Vec<String>,
    /// Origin-aware members and their normalized operation graphs.
    pub members: Vec<CrossLanguageGroupMemberDetail>,
}

/// Standalone explain view of one explicit cross-build-variant clone group.
#[derive(Debug, Serialize)]
pub struct CrossVariantGroupDetail {
    /// Stable comparison-domain group identity.
    pub group_id: String,
    /// Stable identity of the comparison that recorded this group.
    pub comparison_id: String,
    /// Version of the comparison policy.
    pub policy_version: String,
    /// Root shared by the compared partitions.
    pub root_path: String,
    /// Origin build variants kept separate by the comparison.
    pub origin_variants: Vec<String>,
    /// Exact clone classification under the comparison policy.
    pub clone_type: String,
    /// Origin-aware exact-clone members.
    pub members: Vec<CrossVariantGroupMemberDetail>,
}

/// One origin-aware member of a cross-build-variant explain result.
#[derive(Debug, Serialize)]
pub struct CrossVariantGroupMemberDetail {
    /// Origin build variant of this member's normal partition.
    pub origin_variant: String,
    /// Source language.
    pub language: String,
    /// Source location relative to the comparison root.
    pub file: String,
    /// One-based source range start.
    pub start_line: u32,
    /// One-based source range end.
    pub end_line: u32,
    /// Best-effort enclosing unit name.
    pub unit: Option<String>,
    /// Matched token count.
    pub token_count: usize,
}

/// One clone group looked up on its own.
///
/// The group itself is the same [`Group`] a report carries, rendered by the
/// same code: a lookup that described a finding differently from the report it
/// came out of would be a second account of the same facts.
#[derive(Debug, Serialize)]
pub struct CloneGroupDetail {
    /// Local database the group was read from.
    pub database: String,
    /// Row id of the scan run that recorded the group.
    pub scan_run: i64,
    /// Analysis mode that computed the group's stable identity.
    pub analysis_mode: String,
    /// Build variant fingerprint that qualifies the group.
    pub build_variant: String,
    /// The group, with its members and the inputs its ranking read.
    pub group: Group,
}

impl CloneGroupDetail {
    /// Version this detail document is emitted under.
    pub const SCHEMA_VERSION: &'static str = FINDING_DETAIL_SCHEMA_VERSION;

    /// The detail as pretty-printed JSON, newline-terminated.
    ///
    /// # Errors
    ///
    /// Returns an error when serialization fails.
    pub fn to_json(&self) -> serde_json::Result<String> {
        detail_json(EXPLAIN_RESPONSE_CLONE_GROUP, self)
    }

    /// Render the group the way a report lists it, with every member.
    ///
    /// # Errors
    ///
    /// Returns any error from the writer.
    pub fn render_text(&self, out: &mut impl Write) -> io::Result<()> {
        writeln!(out, "clone group {}", self.group.fingerprint)?;
        writeln!(out, "  database: {}", self.database)?;
        writeln!(
            out,
            "  run: {} ({}; build variant {})",
            self.scan_run, self.analysis_mode, self.build_variant
        )?;
        render_group(
            &self.group,
            // A detail view is the one place that shows everything: full
            // identifiers, every occurrence, and the numbers behind the
            // ranking. Its reader asked about this one group by name.
            TextOptions {
                verbosity: 2,
                limit: Some(0),
                show_suppressed: true,
                ..TextOptions::default()
            },
            &Palette { enabled: false },
            out,
        )
    }
}

impl SiblingDetail {
    /// The detail as pretty-printed JSON, newline-terminated.
    ///
    /// # Errors
    ///
    /// Returns an error when serialization fails.
    pub fn to_json(&self) -> serde_json::Result<String> {
        detail_json(EXPLAIN_RESPONSE_SIBLING, self)
    }

    /// Render the supplemental finding and its verifier evidence.
    ///
    /// # Errors
    ///
    /// Returns any error from the writer.
    pub fn render_text(&self, out: &mut impl Write) -> io::Result<()> {
        writeln!(out, "sibling finding {}", self.sibling.member.finding_id)?;
        writeln!(out, "  scan run: {}", self.scan_run)?;
        writeln!(out, "  primary group: {}", self.group_fingerprint)?;
        writeln!(
            out,
            "  {} {}:{}-{} ({}, confidence {}, similarity {:.3})",
            self.sibling.member.language,
            self.sibling.member.file,
            self.sibling.member.start_line,
            self.sibling.member.end_line,
            self.sibling.clone_type,
            self.sibling.confidence_band,
            self.sibling.similarity.composite,
        )?;
        if let Some(unit) = &self.sibling.member.unit {
            writeln!(out, "    unit: {unit}")?;
        }
        Ok(())
    }
}

/// One origin-aware member of a cross-language explain result.
#[derive(Debug, Serialize)]
pub struct CrossLanguageGroupMemberDetail {
    /// Origin build variant of this member's normal partition.
    pub origin_variant: String,
    /// Source language.
    pub language: String,
    /// Source location relative to the comparison root.
    pub file: String,
    /// One-based source range start.
    pub start_line: u32,
    /// One-based source range end.
    pub end_line: u32,
    /// Best-effort enclosing unit name.
    pub unit: Option<String>,
    /// Revalidated normalized operation graph.
    pub graph: SemanticOperationGraph,
}

/// One explicit source/artifact mapping shown by `explain`.
#[derive(Debug, Serialize)]
pub struct SourceArtifactMappingDetail {
    /// Standalone artifact analysis which supplied the correspondence.
    pub artifact_analysis_id: i64,
    /// Mapped artifact symbol identity.
    pub artifact_symbol_fingerprint: String,
    /// Source and artifact `BuildVariant` identities, never merged.
    pub source_build_variant_fingerprint: String,
    /// Artifact `BuildVariant` identity.
    pub artifact_build_variant_fingerprint: String,
    /// Derived mapping confidence label.
    pub confidence: String,
    /// Independent facts that justify the correspondence.
    pub evidence: MappingEvidence,
    /// Observed bytes attributed to this occurrence, when uniquely established.
    pub attributed_bytes: Option<u64>,
}

/// One persisted clone-group refactoring estimate shown by `explain`.
#[derive(Debug, Serialize)]
pub struct CloneGroupSavingsDetail {
    /// Artifact analysis which stored this estimate.
    pub artifact_analysis_id: i64,
    /// Source and artifact `BuildVariant` identities, never merged.
    pub source_build_variant_fingerprint: String,
    /// Artifact `BuildVariant` identity.
    pub artifact_build_variant_fingerprint: String,
    /// Fully attributed observed duplicate bytes.
    pub duplicated_bytes: u64,
    /// Estimated refactoring reduction; negative values remain visible.
    pub estimated_refactor_savings_bytes: i64,
    /// Mapping, source-clone, model, and estimate confidence remain separate.
    pub mapping_confidence: String,
    /// Source clone score.
    pub clone_confidence: f64,
    /// Confidence in the model assumptions.
    pub model_confidence: String,
    /// Confidence in this estimate.
    pub savings_confidence: String,
    /// Version of the structured assumptions model.
    pub model_schema_version: String,
    /// Structured model assumptions.
    pub assumptions: serde_json::Value,
}

/// A reference to an occurrence's owning group, carrying the evidence that
/// made it a finding rather than its identity alone.
#[derive(Debug, Serialize)]
pub struct GroupRef {
    /// Stable clone-group fingerprint, hex-encoded.
    pub fingerprint: String,
    /// Clone classification (`type-1`, `type-2`, `type-3`).
    pub clone_type: String,
    /// What each member is (`unit` or `fragment`), as recorded with the run.
    pub scope: String,
    /// Minimum pairwise similarity across the group.
    pub confidence: f64,
    /// Shannon entropy, in bits, of the canonical occurrence's normalized
    /// token distribution.
    pub entropy_bits: f64,
    /// Where the group was ranked, as recorded with the run, together with the
    /// facts it was ranked on. Absent for a group with no audited finding row.
    pub priority: Option<RecordedPriority>,
    /// Number of occurrences in the group, this one included.
    pub members: u64,
    /// The boilerplate shape every member matches, when they all match one.
    pub boilerplate: Option<String>,
    /// Whether every member of the group is test code, as recorded with the
    /// run.
    pub test_code: bool,
    /// Why every member of the group is test code, as recorded with the run.
    pub test_code_evidence: Option<TestCodeEvidence>,
    /// Whether the group is a verified pair no larger group could hold, as
    /// recorded with the run.
    pub split_pair: bool,
    /// Per-dimension evidence, absent when the mode measured none (Fast).
    pub similarity: Option<Similarity>,
    /// Registered semantic evidence, when this is a restricted-semantic
    /// finding. `explain` retains the stored graphs rather than summarizing
    /// them into an opaque score.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub semantic: Option<SemanticEvidence>,
    /// The rule that suppressed the group in the recorded run, if one
    /// matched. A suppressed finding is still recorded and still explainable.
    pub suppressed: Option<Suppression>,
}

impl FindingDetail {
    /// The detail as pretty-printed JSON, newline-terminated.
    ///
    /// # Errors
    ///
    /// Returns an error when serialization fails.
    pub fn to_json(&self) -> serde_json::Result<String> {
        detail_json(EXPLAIN_RESPONSE_OCCURRENCE, self)
    }

    /// Render the human-readable text view.
    ///
    /// # Errors
    ///
    /// Returns any error from the writer.
    #[allow(clippy::too_many_lines)] // The public explain-text order is one contract.
    pub fn render_text(&self, out: &mut impl Write) -> io::Result<()> {
        writeln!(out, "finding {}", self.member.finding_id)?;
        writeln!(
            out,
            "  location: {}:{}-{}",
            self.member.file, self.member.start_line, self.member.end_line,
        )?;
        if let Some(name) = &self.member.unit {
            writeln!(out, "  unit: {name}")?;
        }
        writeln!(out, "  tokens: {}", self.member.tokens)?;
        writeln!(
            out,
            "  canonical: {}",
            if self.member.canonical { "yes" } else { "no" }
        )?;
        // Which of the two the occurrence is decides how to read its span:
        // the whole unit is the clone, or a run inside it is.
        let scope = if self.group.scope == SCOPE_FRAGMENT {
            "duplicated run"
        } else {
            "duplicated unit"
        };
        writeln!(
            out,
            "  group: {} ({scope}, {}, score {:.2}, {} instances)",
            self.group.fingerprint,
            self.group.clone_type,
            self.group.confidence,
            self.group.members,
        )?;
        if let Some(similarity) = &self.group.similarity {
            writeln!(out, "    {}", similarity.line())?;
        }
        writeln!(
            out,
            "    content entropy: {:.2} bits",
            self.group.entropy_bits
        )?;
        self.render_priority(out)?;
        if let Some(category) = &self.group.boilerplate {
            writeln!(out, "  boilerplate: {category}")?;
        }
        if self.group.split_pair {
            writeln!(
                out,
                "  pair: reported on its own, because no group holds both its members"
            )?;
        }
        if self.group.test_code {
            writeln!(out, "  test code: every occurrence is inside a test")?;
        }
        if let Some(cause) = &self.group.suppressed {
            writeln!(out, "  suppressed: {}", cause.label())?;
        }
        self.render_semantic_evidence(out)?;
        if !self.source_artifact_mappings.is_empty() {
            writeln!(out, "  source-artifact mappings:")?;
            for mapping in &self.source_artifact_mappings {
                writeln!(
                    out,
                    "    analysis {}: {} ({}) — {} bytes, {} facts, {} candidate(s){}",
                    mapping.artifact_analysis_id,
                    mapping.artifact_symbol_fingerprint,
                    mapping.confidence,
                    mapping
                        .attributed_bytes
                        .map_or_else(|| "unattributed".to_owned(), |bytes| bytes.to_string()),
                    mapping.evidence.facts.len(),
                    mapping.evidence.candidate_count,
                    if mapping.evidence.has_conflict {
                        "; conflicting evidence retained"
                    } else {
                        ""
                    },
                )?;
            }
        }
        if !self.clone_group_savings.is_empty() {
            writeln!(out, "  refactoring estimates (not guaranteed):")?;
            for savings in &self.clone_group_savings {
                writeln!(
                    out,
                    "    analysis {}: {} estimated bytes from {} attributed duplicate bytes; mapping {}, clone {:.3}, model {}, savings {}",
                    savings.artifact_analysis_id,
                    savings.estimated_refactor_savings_bytes,
                    savings.duplicated_bytes,
                    savings.mapping_confidence,
                    savings.clone_confidence,
                    savings.model_confidence,
                    savings.savings_confidence,
                )?;
                writeln!(
                    out,
                    "      source build variant: {}",
                    savings.source_build_variant_fingerprint
                )?;
                writeln!(
                    out,
                    "      artifact build variant: {}",
                    savings.artifact_build_variant_fingerprint
                )?;
                writeln!(out, "      model schema: {}", savings.model_schema_version)?;
                writeln!(out, "      assumptions: {}", savings.assumptions)?;
            }
        }
        writeln!(out, "  scan run: {}", self.scan_run)?;
        Ok(())
    }

    /// Render the persisted graph evidence without collapsing it into a
    /// confidence score, so a reader can check the exact registered rule.
    fn render_semantic_evidence(&self, out: &mut impl Write) -> io::Result<()> {
        let Some(semantic) = &self.group.semantic else {
            return Ok(());
        };
        writeln!(out, "  semantic evidence: {}", semantic.schema_version)?;
        for rule in &semantic.rules {
            writeln!(
                out,
                "    rule {}@{} (confidence {:.2})",
                rule.id, rule.version, rule.confidence
            )?;
        }
        for (member, graph) in semantic.graphs.iter().enumerate() {
            let operations = graph
                .nodes
                .iter()
                .map(|node| node.kind.name())
                .collect::<Vec<_>>()
                .join(" -> ");
            writeln!(out, "    graph {}: {operations}", member + 1)?;
        }
        if !semantic.node_mappings.is_empty() {
            let mappings = semantic
                .node_mappings
                .iter()
                .map(|mapping| format!("{}→{}", mapping.canonical, mapping.corresponding))
                .collect::<Vec<_>>()
                .join(", ");
            writeln!(out, "    node mapping: {mappings}")?;
        }
        Ok(())
    }

    /// Why the finding is ranked where it is: each measure, the facts it read,
    /// and the rule that turned the one into the other.
    ///
    /// The rules are stated in words rather than as the arithmetic, because
    /// what a reader needs in order to argue with a placement is which fact
    /// drove it, not the constant it was multiplied by. The constants are in
    /// the ranking recipe the run recorded.
    fn render_priority(&self, out: &mut impl Write) -> io::Result<()> {
        let Some(priority) = &self.group.priority else {
            return Ok(());
        };
        let inputs = &priority.inputs;
        let measure = |value: Option<f64>| {
            value.map_or_else(|| "n/a".to_string(), |value| format!("{value:.2}"))
        };
        writeln!(out, "  priority: {:.2}", priority.value)?;
        writeln!(
            out,
            "    clone confidence {:.2} — {} tokens in the smallest occurrence{}, \
             {:.2} similarity, matched as {}",
            priority.clone_confidence,
            inputs.smallest_member_tokens,
            inputs.min_clone_tokens.map_or_else(
                // The floor decides how much a length is worth, so a run that
                // did not record it leaves the confidence readable but not
                // reproducible, and says which of the two this is.
                || " (the run did not record the length floor it used)".to_string(),
                |floor| format!(" against a {floor}-token floor"),
            ),
            self.group.confidence,
            self.group.clone_type,
        )?;
        writeln!(
            out,
            "    maintenance risk {} — {} occurrences over {} file(s) in {} \
             director(y/ies), largest {} tokens",
            measure(priority.maintenance_risk),
            inputs.instances,
            inputs.files,
            inputs.directories,
            inputs.largest_member_tokens,
        )?;
        writeln!(
            out,
            "    refactoring difficulty {} — {} tokens to move, {}, {} language(s)",
            measure(priority.refactoring_difficulty),
            inputs.largest_member_tokens,
            if self.group.scope == SCOPE_FRAGMENT {
                "a run inside its units, with no boundary to lift it out at"
            } else {
                "whole units, which already have a boundary"
            },
            inputs.languages,
        )?;
        // Named rather than left implicit: an input nobody has measured is not
        // an input worth zero, and a reader comparing two releases needs to
        // know which of the two it was.
        let reserved: Vec<&str> = [
            ("semantic confidence", priority.semantic_confidence),
            (
                "source-artifact confidence",
                priority.source_artifact_confidence,
            ),
            ("savings confidence", priority.savings_confidence),
        ]
        .into_iter()
        .filter(|(_, value)| value.is_none())
        .map(|(name, _)| name)
        .collect();
        if !reserved.is_empty() {
            writeln!(
                out,
                "    not measured by this run, and so not weighed: {}, churn, \
                 ownership spread",
                reserved.join(", "),
            )?;
        }
        Ok(())
    }
}

impl CrossLanguageGroupDetail {
    /// The detail as pretty-printed JSON, newline-terminated.
    ///
    /// # Errors
    ///
    /// Returns an error when serialization fails.
    pub fn to_json(&self) -> serde_json::Result<String> {
        detail_json(EXPLAIN_RESPONSE_CROSS_LANGUAGE_GROUP, self)
    }

    /// Render the closed correspondence and every origin-aware operation graph.
    ///
    /// # Errors
    ///
    /// Returns any error from the writer.
    pub fn render_text(&self, out: &mut impl Write) -> io::Result<()> {
        writeln!(out, "cross-language semantic group {}", self.group_id)?;
        writeln!(out, "  comparison: {}", self.comparison_id)?;
        writeln!(out, "  policy: {}", self.policy_version)?;
        writeln!(out, "  root: {}", self.root_path)?;
        writeln!(
            out,
            "  origin variants: {}",
            self.origin_variants.join(", ")
        )?;
        writeln!(
            out,
            "  rule: {}@{} (confidence {:.2})",
            self.rule_id, self.rule_version, self.semantic_confidence
        )?;
        writeln!(
            out,
            "  Correspondences: {}",
            self.correspondence_ids.join(", ")
        )?;
        for member in &self.members {
            writeln!(
                out,
                "  {} {}:{}-{} ({})",
                member.language,
                member.file,
                member.start_line,
                member.end_line,
                member.origin_variant,
            )?;
            if let Some(unit) = &member.unit {
                writeln!(out, "    unit: {unit}")?;
            }
            let operations = member
                .graph
                .nodes
                .iter()
                .map(|node| node.kind.name())
                .collect::<Vec<_>>()
                .join(" -> ");
            writeln!(
                out,
                "    graph {}: {operations}",
                member.graph.schema_version
            )?;
        }
        Ok(())
    }
}

impl CrossVariantGroupDetail {
    /// The detail as pretty-printed JSON, newline-terminated.
    ///
    /// # Errors
    ///
    /// Returns an error when serialization fails.
    pub fn to_json(&self) -> serde_json::Result<String> {
        detail_json(EXPLAIN_RESPONSE_CROSS_VARIANT_GROUP, self)
    }

    /// Render every origin-aware exact-clone member.
    ///
    /// # Errors
    ///
    /// Returns any error from the writer.
    pub fn render_text(&self, out: &mut impl Write) -> io::Result<()> {
        writeln!(out, "cross-build-variant clone group {}", self.group_id)?;
        writeln!(out, "  comparison: {}", self.comparison_id)?;
        writeln!(out, "  policy: {}", self.policy_version)?;
        writeln!(out, "  root: {}", self.root_path)?;
        writeln!(
            out,
            "  origin variants: {}",
            self.origin_variants.join(", ")
        )?;
        writeln!(out, "  clone type: {}", self.clone_type)?;
        for member in &self.members {
            writeln!(
                out,
                "  {} {}:{}-{} ({}, {} tokens)",
                member.language,
                member.file,
                member.start_line,
                member.end_line,
                member.origin_variant,
                member.token_count,
            )?;
            if let Some(unit) = &member.unit {
                writeln!(out, "    unit: {unit}")?;
            }
        }
        Ok(())
    }
}
