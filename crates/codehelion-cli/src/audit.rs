//! The `audit` command: what became of the duplication since last time.
//!
//! A scan answers "what is duplicated here". This answers "what changed about
//! it", which a periodic audit needs and a pair of scan reports cannot give:
//! duplication that moved to another file reads as one finding gone and
//! another appearing, and duplication whose copies drifted apart reads as the
//! same finding still there. Both readings are wrong, and both are what a
//! textual comparison of two reports produces.
//!
//! # What is compared
//!
//! Two recorded runs of one tree, or one recorded run and an exported report
//! of another. The exported form exists for the case the database cannot
//! cover: a result produced on a different machine, in a pipeline that keeps
//! artefacts rather than state. Either way both sides must belong to the same
//! build variant, which is checked rather than assumed — identifiers computed
//! under different rules do not disagree, they simply never meet, and the
//! comparison would report every group as new and every previous group as
//! resolved without anything having happened.
//!
//! Sameness of build variant is necessary and not sufficient. The detector
//! versions each run recorded are compared too, because a rule can change
//! without the variant noticing, and a change to how identifiers are made
//! turns every group into one that went away and one that arrived. That case
//! is refused rather than reported: it is not a comparison with a caveat, it
//! is two vocabularies. What differs at any lesser level is carried into the
//! report, so a reader can tell duplication that moved from grouping rules
//! that did.
//!
//! The judgement itself lives in [`codehelion_core::lineage`]; this module
//! decides which two results to hand it and how to say what came back.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result, bail};
use codehelion_core::clone_class::{CloneClass, CloneScope};
use codehelion_core::compat::{self, Impact};
use codehelion_core::lineage::{self, AuditDiff, AuditState, GroupSnapshot, MemberSnapshot};
use codehelion_core::stable_id::{CloneGroupFingerprint, FragmentFingerprint};
use codehelion_store::Store;
use codehelion_store::query::RunOrigin;
use serde::{Deserialize, Serialize};

use crate::cli::{AuditArgs, DetailFormat};
use crate::{Outcome, config, report, scan};

/// Version of the audit JSON output format.
pub const SCHEMA_VERSION: u32 = 1;

/// The audit report's JSON schema, embedded so the format ships with the tool
/// that writes it.
pub const JSON_SCHEMA: &str = include_str!("../schema/audit-report-v1.schema.json");

/// One side of a comparison: the result, and where it came from.
struct Side {
    /// How the result was reached, for the report's header.
    source: String,
    /// Row id of the recorded run, absent for an exported report.
    run_id: Option<i64>,
    /// When the run finished.
    finished_at: String,
    /// The build variant the result belongs to.
    variant_fingerprint: String,
    /// The detection component versions it was produced under.
    detector_versions: Vec<(String, String)>,
    /// Its clone groups, as history compares them.
    groups: Vec<GroupSnapshot>,
}

/// Execute `codehelion audit`.
///
/// # Errors
///
/// Returns an error when the path or database cannot be resolved, when there
/// is no pair of results to compare, when the two sides belong to different
/// build variants, or when an exported report cannot be read.
pub fn run(args: &AuditArgs, out: &mut impl Write) -> Result<Outcome> {
    let root = args
        .path
        .canonicalize()
        .with_context(|| format!("resolving path {}", args.path.display()))?;
    let cfg = config::load(None, &root)?.config;
    let db_path = scan::database_path(&root, args.db.as_deref(), &cfg);
    if !db_path.is_file() {
        bail!(
            "no audit database at {}; run `codehelion scan` first",
            db_path.display()
        );
    }
    let store = Store::open(&db_path)?;
    let root_path = root.to_string_lossy();
    let (previous, current) = sides(&store, &root_path, args)?;
    if previous.variant_fingerprint != current.variant_fingerprint {
        bail!(
            "the two results are not comparable: {} belongs to build variant {}, \
             and {} to {}; rescan both under the same settings",
            previous.source,
            previous.variant_fingerprint,
            current.source,
            current.variant_fingerprint,
        );
    }
    let drift = compat::drift(&previous.detector_versions, &current.detector_versions);
    if let Some(blocking) = drift.iter().find(|entry| entry.impact.breaks_identity()) {
        bail!(
            "{} and {} name their findings differently ({}), so every group of one \
             would read as gone and every group of the other as new; \
             `codehelion baseline migrate` carries a frozen result across a change \
             like this",
            previous.source,
            current.source,
            blocking.describe(),
        );
    }
    let diff = lineage::diff(&previous.groups, &current.groups);
    let model = build(
        &root_path,
        &previous,
        &current,
        &diff,
        args.show_unchanged,
        &drift,
    );
    match args.format {
        DetailFormat::Json => writeln!(out, "{}", serde_json::to_string_pretty(&model)?)?,
        DetailFormat::Text => render_text(&model, out)?,
    }
    let alarming = diff
        .entries
        .iter()
        .any(|entry| entry.state.needs_attention());
    if args.fail_on_new && alarming {
        return Ok(Outcome::FindingsPresent);
    }
    Ok(Outcome::Success)
}

/// Settle which two results are being compared.
fn sides(store: &Store, root_path: &str, args: &AuditArgs) -> Result<(Side, Side)> {
    let runs = store.completed_runs(root_path, 2)?;
    let Some(latest) = runs.first() else {
        bail!("no completed scan of {root_path} is recorded; run `codehelion scan` first");
    };
    let current = recorded_side(store, latest)?;
    if let Some(path) = &args.previous {
        return Ok((exported_side(path)?, current));
    }
    let Some(earlier) = runs.get(1) else {
        bail!(
            "only one scan of {root_path} is recorded (run {}); \
             there is nothing to compare it against yet",
            latest.id
        );
    };
    Ok((recorded_side(store, earlier)?, current))
}

/// One side read out of the audit database.
fn recorded_side(store: &Store, origin: &RunOrigin) -> Result<Side> {
    Ok(Side {
        source: format!("run {}", origin.id),
        run_id: Some(origin.id),
        finished_at: origin.finished_at.clone(),
        variant_fingerprint: origin.variant_fingerprint.clone(),
        detector_versions: origin.detector_versions.clone(),
        groups: store.run_group_snapshots(origin.id)?,
    })
}

/// The parts of an exported scan report a comparison reads.
///
/// Declared apart from [`report::Report`] rather than deriving `Deserialize`
/// on it: a comparison needs content identities and placement, and reading
/// only those means a report written by a later release, carrying fields this
/// one has never heard of, still loads.
#[derive(Debug, Deserialize)]
struct ExportedReport {
    schema_version: u32,
    run: ExportedRun,
    groups: Vec<ExportedGroup>,
}

#[derive(Debug, Deserialize)]
struct ExportedRun {
    run_id: i64,
    finished_at: String,
    build_variant: ExportedVariant,
    /// Absent from a report written before the versions travelled with it, in
    /// which case there is nothing to compare and nothing is claimed.
    #[serde(default)]
    detector_versions: Vec<ExportedDetectorVersion>,
}

#[derive(Debug, Deserialize)]
struct ExportedDetectorVersion {
    component: String,
    version: String,
}

#[derive(Debug, Deserialize)]
struct ExportedVariant {
    fingerprint: String,
}

#[derive(Debug, Deserialize)]
struct ExportedGroup {
    fingerprint: String,
    clone_type: String,
    scope: String,
    confidence: f64,
    members: Vec<ExportedMember>,
}

#[derive(Debug, Deserialize)]
struct ExportedMember {
    content: String,
    file: String,
    unit: Option<String>,
    canonical: bool,
}

/// One side read from an exported JSON scan report.
fn exported_side(path: &Path) -> Result<Side> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading exported report {}", path.display()))?;
    let exported: ExportedReport = serde_json::from_str(&text)
        .with_context(|| format!("parsing exported report {}", path.display()))?;
    if exported.schema_version != report::SCHEMA_VERSION {
        bail!(
            "{} is a version {} scan report; this build reads version {}",
            path.display(),
            exported.schema_version,
            report::SCHEMA_VERSION,
        );
    }
    let groups = exported
        .groups
        .iter()
        .map(|group| exported_group(group, path))
        .collect::<Result<_>>()?;
    Ok(Side {
        source: path.display().to_string(),
        run_id: Some(exported.run.run_id),
        finished_at: exported.run.finished_at,
        variant_fingerprint: exported.run.build_variant.fingerprint,
        detector_versions: exported
            .run
            .detector_versions
            .into_iter()
            .map(|entry| (entry.component, entry.version))
            .collect(),
        groups,
    })
}

fn exported_group(group: &ExportedGroup, path: &Path) -> Result<GroupSnapshot> {
    let unknown = |field: &str, value: &str| {
        anyhow::anyhow!(
            "{} names a {field} this build does not know: {value:?}",
            path.display()
        )
    };
    let members: Vec<MemberSnapshot> = group
        .members
        .iter()
        .map(|member| {
            Ok(MemberSnapshot {
                content: FragmentFingerprint::from_bytes(hex16(&member.content, path)?),
                anchor: lineage::Anchor {
                    file: member.file.clone(),
                    unit: member.unit.clone(),
                },
            })
        })
        .collect::<Result<_>>()?;
    Ok(GroupSnapshot {
        fingerprint: CloneGroupFingerprint::from_bytes(hex16(&group.fingerprint, path)?),
        clone_type: CloneClass::from_name(&group.clone_type)
            .ok_or_else(|| unknown("clone type", &group.clone_type))?,
        scope: CloneScope::from_name(&group.scope)
            .ok_or_else(|| unknown("member scope", &group.scope))?,
        score: group.confidence,
        canonical: group
            .members
            .iter()
            .position(|member| member.canonical)
            .and_then(|index| members.get(index))
            .map(|member| member.content),
        // An exported report carries no lineage: the history a group belongs
        // to is recorded beside the run, not in the result it exported. The
        // comparison starts the history at this group, which is what "as far
        // back as this file goes" means.
        lineage: None,
        members,
    })
}

/// Decode a 32-digit hex identifier from an exported report.
fn hex16(text: &str, path: &Path) -> Result<[u8; 16]> {
    if text.len() != 32 {
        bail!(
            "{} holds a malformed identifier {text:?}: expected 32 hex digits",
            path.display()
        );
    }
    let mut out = [0u8; 16];
    for (slot, chunk) in out.iter_mut().zip(text.as_bytes().chunks_exact(2)) {
        let pair = core::str::from_utf8(chunk).unwrap_or("");
        *slot = u8::from_str_radix(pair, 16).map_err(|_| {
            anyhow::anyhow!(
                "{} holds a malformed identifier {text:?}: expected 32 hex digits",
                path.display()
            )
        })?;
    }
    Ok(out)
}

/// What one audit concluded, in the shape both output formats render.
#[derive(Debug, Serialize)]
pub struct AuditReport {
    /// JSON audit format version.
    pub schema_version: u32,
    /// Absolute path of the audited tree.
    pub root: String,
    /// The result being compared against.
    pub previous: ResultRef,
    /// The result being judged.
    pub current: ResultRef,
    /// The build variant both belong to.
    pub build_variant: String,
    /// Version differences between the two results that did not stop the
    /// comparison, one line each. Empty when the two were produced by the same
    /// rules, which is the ordinary case.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub version_drift: Vec<String>,
    /// How many groups are in each state, states with no group omitted.
    pub summary: Vec<report::StateCount>,
    /// One entry per group, in state order.
    pub entries: Vec<Entry>,
}

/// Where one side of the comparison came from.
#[derive(Debug, Serialize)]
pub struct ResultRef {
    /// How it was reached: a run id, or the path of an exported report.
    pub source: String,
    /// Row id of the run, when it is one this database recorded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_id: Option<i64>,
    /// When the run finished.
    pub finished_at: String,
}

/// What became of one clone group, with the evidence behind the verdict.
#[derive(Debug, Serialize)]
pub struct Entry {
    /// The state (`new`, `expanded`, `resolved`, ...).
    pub state: String,
    /// The history the group belongs to, hex-encoded.
    pub lineage: String,
    /// The group's fingerprint now; absent for a resolved group.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    /// The fingerprint of the group it descends from; absent for a new one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_group: Option<String>,
    /// Clone classification, as it is now or as it last was.
    pub clone_type: String,
    /// What the members are, as they are now or as they last were.
    pub scope: String,
    /// Occurrences now; absent for a resolved group.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub members: Option<u64>,
    /// Occurrences before; absent for a new group.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_members: Option<u64>,
    /// Member contents both sides hold.
    pub shared_content: u64,
    /// Shared content as a fraction of the smaller group.
    pub overlap: f64,
    /// Previous groups this one descends from; more than one is a merge.
    pub parents: u64,
    /// Groups the primary parent fed; more than one is a split.
    pub siblings: u64,
    /// Where content that stayed the same went, for a moved group.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub relocations: Vec<Move>,
    /// Where the group's occurrences are, or last were.
    pub occurrences: Vec<Occurrence>,
}

/// One occurrence's placement.
#[derive(Debug, Clone, Serialize)]
pub struct Occurrence {
    /// File path relative to the scan root.
    pub file: String,
    /// Name of the enclosing unit, when it has one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
}

/// One occurrence's content staying put while its address changed.
#[derive(Debug, Serialize)]
pub struct Move {
    /// Where it was.
    pub from: Occurrence,
    /// Where it is now.
    pub to: Occurrence,
}

/// Assemble the report from the comparison and the two sides it read.
fn build(
    root: &str,
    previous: &Side,
    current: &Side,
    diff: &AuditDiff,
    show_unchanged: bool,
    drift: &[compat::Drift],
) -> AuditReport {
    let index = |groups: &[GroupSnapshot]| -> BTreeMap<String, Vec<Occurrence>> {
        groups
            .iter()
            .map(|group| (group.fingerprint.to_hex(), occurrences(group)))
            .collect()
    };
    let here = index(&current.groups);
    let there = index(&previous.groups);
    let entries = diff
        .entries
        .iter()
        .filter(|entry| show_unchanged || entry.state != AuditState::Unchanged)
        .map(|entry| entry_of(entry, &here, &there))
        .collect();
    AuditReport {
        schema_version: SCHEMA_VERSION,
        root: root.to_string(),
        previous: ResultRef {
            source: previous.source.clone(),
            run_id: previous.run_id,
            finished_at: previous.finished_at.clone(),
        },
        current: ResultRef {
            source: current.source.clone(),
            run_id: current.run_id,
            finished_at: current.finished_at.clone(),
        },
        build_variant: current.variant_fingerprint.clone(),
        version_drift: drift.iter().map(compat::Drift::describe).collect(),
        summary: report::state_counts(diff),
        entries,
    }
}

fn occurrences(group: &GroupSnapshot) -> Vec<Occurrence> {
    let mut places: Vec<Occurrence> = group
        .members
        .iter()
        .map(|member| Occurrence {
            file: member.anchor.file.clone(),
            unit: member.anchor.unit.clone(),
        })
        .collect();
    places.sort_by(|a, b| a.file.cmp(&b.file).then_with(|| a.unit.cmp(&b.unit)));
    places
}

fn entry_of(
    entry: &lineage::GroupHistory,
    here: &BTreeMap<String, Vec<Occurrence>>,
    there: &BTreeMap<String, Vec<Occurrence>>,
) -> Entry {
    let shape = entry.current.or(entry.previous);
    let group = entry.current.map(|group| group.fingerprint.to_hex());
    let previous_group = entry.previous.map(|group| group.fingerprint.to_hex());
    let occurrences = group
        .as_ref()
        .and_then(|id| here.get(id))
        .or_else(|| previous_group.as_ref().and_then(|id| there.get(id)));
    Entry {
        state: entry.state.name().to_string(),
        lineage: entry.lineage.to_hex(),
        group,
        previous_group,
        clone_type: shape.map_or_else(String::new, |group| group.clone_type.name().to_string()),
        scope: shape.map_or_else(String::new, |group| group.scope.name().to_string()),
        members: entry.current.map(|group| as_u64(group.members)),
        previous_members: entry.previous.map(|group| as_u64(group.members)),
        shared_content: as_u64(entry.shared_content),
        overlap: entry.overlap,
        parents: as_u64(entry.parents),
        siblings: as_u64(entry.siblings),
        relocations: entry
            .relocations
            .iter()
            .map(|moved| Move {
                from: Occurrence {
                    file: moved.from.file.clone(),
                    unit: moved.from.unit.clone(),
                },
                to: Occurrence {
                    file: moved.to.file.clone(),
                    unit: moved.to.unit.clone(),
                },
            })
            .collect(),
        occurrences: occurrences.cloned().unwrap_or_default(),
    }
}

fn as_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

/// Render the human-readable view: the header, the counts, then the groups
/// grouped by what happened to them.
fn render_text(model: &AuditReport, out: &mut impl Write) -> std::io::Result<()> {
    writeln!(out, "codehelion audit")?;
    writeln!(out, "  root: {}", model.root)?;
    writeln!(
        out,
        "  comparing {} ({}) against {} ({})",
        model.current.source,
        model.current.finished_at,
        model.previous.source,
        model.previous.finished_at,
    )?;
    writeln!(out, "  build variant: {}", model.build_variant)?;
    for line in &model.version_drift {
        writeln!(out, "  version drift: {line}")?;
    }
    if model
        .version_drift
        .iter()
        .any(|line| line.ends_with(&format!("({})", Impact::Grouping.name())))
    {
        writeln!(out, "    note: {}", Impact::Grouping.consequence())?;
    }
    writeln!(out)?;
    if model.summary.is_empty() {
        writeln!(out, "  neither result holds any clone group.")?;
        return Ok(());
    }
    let counts: Vec<String> = model
        .summary
        .iter()
        .map(|entry| format!("{} {}", entry.count, entry.state))
        .collect();
    writeln!(out, "  {}", counts.join(", "))?;
    for state in AuditState::all() {
        let listed: Vec<&Entry> = model
            .entries
            .iter()
            .filter(|entry| entry.state == state.name())
            .collect();
        if listed.is_empty() {
            continue;
        }
        writeln!(out)?;
        writeln!(out, "{}:", state.name())?;
        for entry in listed {
            render_entry(entry, out)?;
        }
    }
    Ok(())
}

fn render_entry(entry: &Entry, out: &mut impl Write) -> std::io::Result<()> {
    let id = entry
        .group
        .as_ref()
        .or(entry.previous_group.as_ref())
        .map_or("", String::as_str);
    let short = id.get(..12).unwrap_or(id);
    writeln!(
        out,
        "  {short}  {} {}, {}",
        entry.clone_type,
        entry.scope,
        occurrence_count(entry),
    )?;
    if let Some(note) = evidence(entry) {
        writeln!(out, "      {note}")?;
    }
    for moved in &entry.relocations {
        writeln!(
            out,
            "      moved {} -> {}",
            place(&moved.from),
            place(&moved.to)
        )?;
    }
    for occurrence in &entry.occurrences {
        writeln!(out, "      {}", place(occurrence))?;
    }
    Ok(())
}

fn occurrence_count(entry: &Entry) -> String {
    match (entry.members, entry.previous_members) {
        (Some(now), Some(before)) if now != before => {
            format!("{now} occurrences (was {before})")
        }
        (Some(now), _) => format!("{now} occurrences"),
        (None, Some(before)) => format!("{before} occurrences, gone"),
        (None, None) => "no occurrences".to_string(),
    }
}

/// The one line that says how much the verdict rests on, said only where it is
/// not obvious: a group whose fingerprint did not move shares everything, and
/// a group with no past shares nothing.
fn evidence(entry: &Entry) -> Option<String> {
    let mut notes = Vec::new();
    if entry.previous_group.is_some() && entry.overlap < 1.0 {
        notes.push(format!(
            "sharing {} member contents ({:.0}% of the smaller group)",
            entry.shared_content,
            entry.overlap * 100.0,
        ));
    }
    if entry.parents > 1 {
        notes.push(format!("merged from {} groups", entry.parents));
    }
    if entry.siblings > 1 {
        notes.push(format!("one of {} pieces it split into", entry.siblings));
    }
    if entry.previous_group.is_some() && entry.previous_group != entry.group {
        notes.push(format!(
            "was {}",
            entry
                .previous_group
                .as_deref()
                .and_then(|id| id.get(..12))
                .unwrap_or_default()
        ));
    }
    (!notes.is_empty()).then(|| notes.join("; "))
}

fn place(occurrence: &Occurrence) -> String {
    occurrence.unit.as_ref().map_or_else(
        || occurrence.file.clone(),
        |unit| format!("{} {unit}", occurrence.file),
    )
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn the_embedded_schema_describes_the_version_the_code_writes() {
        let schema: serde_json::Value = serde_json::from_str(JSON_SCHEMA).unwrap();
        let version = &schema["properties"]["schema_version"]["const"];
        assert_eq!(version.as_u64(), Some(u64::from(SCHEMA_VERSION)));
        // The schema forbids unknown properties, so a field the code writes
        // and the document does not describe makes every report invalid.
        assert!(schema["properties"]["version_drift"].is_object());
    }

    #[test]
    fn a_malformed_identifier_names_the_file_it_came_from() {
        let error = hex16("nothex", Path::new("/tmp/report.json")).unwrap_err();
        let text = format!("{error:#}");
        assert!(text.contains("/tmp/report.json"), "{text}");
        assert!(text.contains("32 hex digits"), "{text}");
    }

    #[test]
    fn a_relocation_reads_as_a_place_and_not_a_line_number() {
        let entry = Entry {
            state: "moved".to_string(),
            lineage: "aa".to_string(),
            group: Some("bb".to_string()),
            previous_group: Some("bb".to_string()),
            clone_type: "type-2".to_string(),
            scope: "unit".to_string(),
            members: Some(2),
            previous_members: Some(2),
            shared_content: 2,
            overlap: 1.0,
            parents: 1,
            siblings: 1,
            relocations: vec![Move {
                from: Occurrence {
                    file: "old.rs".to_string(),
                    unit: Some("parse".to_string()),
                },
                to: Occurrence {
                    file: "new.rs".to_string(),
                    unit: Some("parse".to_string()),
                },
            }],
            occurrences: Vec::new(),
        };
        let mut buffer = Vec::new();
        render_entry(&entry, &mut buffer).unwrap();
        let text = String::from_utf8(buffer).unwrap();
        assert!(
            text.contains("moved old.rs parse -> new.rs parse"),
            "{text}"
        );
        // A group whose fingerprint did not move shares everything, and saying
        // so would be noise on every unchanged line.
        assert!(!text.contains("sharing"), "{text}");
    }

    #[test]
    fn a_thin_connection_says_how_thin_rather_than_stating_the_state_alone() {
        let entry = Entry {
            state: "expanded".to_string(),
            lineage: "aa".to_string(),
            group: Some("bbbbbbbbbbbbbb".to_string()),
            previous_group: Some("cccccccccccccc".to_string()),
            clone_type: "type-2".to_string(),
            scope: "unit".to_string(),
            members: Some(4),
            previous_members: Some(2),
            shared_content: 1,
            overlap: 0.5,
            parents: 1,
            siblings: 1,
            relocations: Vec::new(),
            occurrences: Vec::new(),
        };
        let mut buffer = Vec::new();
        render_entry(&entry, &mut buffer).unwrap();
        let text = String::from_utf8(buffer).unwrap();
        assert!(text.contains("4 occurrences (was 2)"), "{text}");
        assert!(text.contains("sharing 1 member contents (50%"), "{text}");
        assert!(text.contains("was cccccccccccc"), "{text}");
    }
}
