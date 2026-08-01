use super::{
    BTreeMap, BTreeSet, BodyMateriality, Boilerplate, BuildVariant, FileFeatures,
    FragmentFingerprint, GroupDetail, Lexeme, SourceTokenSpan, StructuralConfig, SyntaxIrFile,
    Token, TokenKind, Unit, UnitEvidence, features, grouping, stable_id, substitution, test_code,
    verify, view,
};

/// Compute one group's reporting detail: its stable clone fingerprint (anchored
/// on the medoid's content, folding the member set) and the medoid-to-member
/// similarity breakdowns.
pub(super) fn group_detail(
    group: &grouping::StructuralGroup,
    units: &[Unit],
    files: &[SyntaxIrFile],
    feature_files: &[FileFeatures],
    evidence: &UnitEvidence,
    variant: &BuildVariant,
    config: &StructuralConfig,
) -> GroupDetail {
    let medoid_view = view(group.canonical, units, files, feature_files, evidence);
    let member_breakdowns = group
        .members
        .iter()
        .map(|&member| {
            verify::verify(
                &medoid_view,
                &view(member, units, files, feature_files, evidence),
                &config.verify,
            )
            .breakdown
        })
        .collect();

    let member_contents: Vec<FragmentFingerprint> =
        group.members.iter().map(|&m| units[m].content).collect();
    let fingerprint = stable_id::structural_clone_group_fingerprint(
        variant,
        group.clone_type,
        &units[group.canonical].content,
        &member_contents,
    );

    GroupDetail {
        fingerprint,
        member_breakdowns,
        identifier_jaccard: group_identifier_jaccard(group, units, files),
        body_materiality: group_body_materiality(group, units, feature_files),
        boilerplate: dominant_boilerplate(group, units),
        test_code: group.members.iter().all(|&member| units[member].test_code),
        test_code_evidence: test_code::aggregate_evidence(
            group
                .members
                .iter()
                .map(|&member| units[member].test_code_evidence),
        ),
        width_family: written_once_per_width(group, units, files),
    }
}

/// Material work that exists in every member rather than just the medoid.
pub(super) fn group_body_materiality(
    group: &grouping::StructuralGroup,
    units: &[Unit],
    feature_files: &[FileFeatures],
) -> BodyMateriality {
    let members: Vec<&features::UnitFeatures> = group
        .members
        .iter()
        .map(|&member| {
            let unit = &units[member];
            &feature_files[unit.file].units[unit.local]
        })
        .collect();
    BodyMateriality {
        has_loop: members
            .iter()
            .all(|features| features.cfg.max_loop_depth > 0),
        has_dynamic_allocation: members
            .iter()
            .all(|features| features.api.names.iter().any(is_allocation_api)),
        call_count: members
            .iter()
            .map(|features| u64::try_from(features.api.names.len()).unwrap_or(u64::MAX))
            .min()
            .unwrap_or(0),
    }
}

/// Allocation APIs recognised without a compiler backend.
///
/// The lexical frontend intentionally recognises only explicit, portable
/// allocator names. An unfamiliar wrapper is absence of evidence, not a
/// guess that the call allocates.
pub(super) fn is_allocation_api(name: &Lexeme) -> bool {
    matches!(
        name.as_str(),
        "aligned_alloc"
            | "calloc"
            | "make_shared"
            | "make_unique"
            | "malloc"
            | "realloc"
            | "reserve"
            | "reserve_exact"
            | "try_reserve"
            | "try_reserve_exact"
            | "with_capacity"
            | "with_capacity_and_hasher"
    )
}

/// The weakest raw identifier-set agreement between a canonical span and its
/// corresponding spans.
///
/// This is reporting and triage evidence only. In particular, a duplicated
/// run may have exact normalized content while this value is low because its
/// names differ; the value is a proxy for whether a shared refactoring target
/// may exist, not a similarity measurement and never an input to detection or
/// grouping.
#[must_use]
pub fn span_identifier_jaccard(
    files: &[SyntaxIrFile],
    canonical: SourceTokenSpan,
    corresponding: impl IntoIterator<Item = SourceTokenSpan>,
) -> f64 {
    let canonical = identifier_set(files, canonical);
    corresponding
        .into_iter()
        .map(|span| set_jaccard(&canonical, &identifier_set(files, span)))
        .min_by(f64::total_cmp)
        .unwrap_or(1.0)
}

/// The weakest identifier-set agreement between a canonical unit and its
/// group members.
fn group_identifier_jaccard(
    group: &grouping::StructuralGroup,
    units: &[Unit],
    files: &[SyntaxIrFile],
) -> f64 {
    span_identifier_jaccard(
        files,
        unit_token_span(&units[group.canonical]),
        group
            .members
            .iter()
            .filter(|&&member| member != group.canonical)
            .map(|&member| unit_token_span(&units[member])),
    )
}

const fn unit_token_span(unit: &Unit) -> SourceTokenSpan {
    SourceTokenSpan::new(unit.file, unit.tokens.0, unit.tokens.1)
}

fn identifier_set(files: &[SyntaxIrFile], span: SourceTokenSpan) -> BTreeSet<&str> {
    let tokens = files
        .get(span.file)
        .and_then(|file| file.tokens.get(span.token_start..span.token_end))
        .unwrap_or(&[]);
    tokens
        .iter()
        .filter(|token| matches!(token.kind, TokenKind::Identifier))
        .map(|token| token.text.as_str())
        .collect()
}

#[allow(clippy::cast_precision_loss)]
pub(super) fn set_jaccard(left: &BTreeSet<&str>, right: &BTreeSet<&str>) -> f64 {
    let union = left.union(right).count();
    if union == 0 {
        return 1.0;
    }
    // One set entry requires one input token; discovery's file-size ceiling
    // bounds this far below the integer range where a report ratio loses a
    // meaningful displayed digit.
    left.intersection(right).count() as f64 / union as f64
}

/// Whether every member differs from the medoid by one integer width and
/// nothing else.
///
/// Asked of each member against the medoid rather than of one pair, because the
/// answer decides what the whole group is. A family written for four widths
/// gives four different swaps against the same medoid and each is one, which is
/// the point; a group where one member is a real copy and another a width
/// variant is not a family and must not read as one.
///
/// A group whose members are the same text answers no. Nothing was substituted,
/// so nothing says the two were written per width — that is a plain copy.
pub(super) fn written_once_per_width(
    group: &grouping::StructuralGroup,
    units: &[Unit],
    files: &[SyntaxIrFile],
) -> bool {
    written_once_per_width_members(group.canonical, &group.members, units, files)
}

/// The pair counterpart of [`written_once_per_width`].
pub(super) fn written_once_per_width_members(
    canonical: usize,
    members: &[usize],
    units: &[Unit],
    files: &[SyntaxIrFile],
) -> bool {
    let medoid = unit_tokens(&units[canonical], files);
    let mut compared = 0usize;
    for &member in members {
        if member == canonical {
            continue;
        }
        compared += 1;
        let alike = substitution::witness(medoid, unit_tokens(&units[member], files))
            .is_some_and(|witness| witness.written_once_per_width());
        if !alike {
            return false;
        }
    }
    compared > 0
}

/// The tokens one unit covers, in its file's stream.
fn unit_tokens<'a>(unit: &Unit, files: &'a [SyntaxIrFile]) -> &'a [Token] {
    &files[unit.file].tokens[unit.tokens.0..unit.tokens.1]
}

/// The category that covers at least four fifths of one cohesive group.
///
/// Clone grouping permits structurally similar bodies to differ in a small
/// number of details. Requiring unanimity therefore let a single exceptional
/// body erase the useful classification of a large predicate family. The
/// threshold is intentionally strict: a two-member pair still needs both
/// members to agree, while a high-instance group can retain a few explicitly
/// visible exceptions.
pub(super) fn dominant_boilerplate(
    group: &grouping::StructuralGroup,
    units: &[Unit],
) -> Option<Boilerplate> {
    dominant_boilerplate_members(&group.members, units)
}

/// The pair counterpart of [`dominant_boilerplate`].
pub(super) fn dominant_boilerplate_members(
    members: &[usize],
    units: &[Unit],
) -> Option<Boilerplate> {
    let mut counts = BTreeMap::new();
    for &member in members {
        if let Some(category) = units[member].boilerplate {
            *counts.entry(category).or_insert(0usize) += 1;
        }
    }
    let (category, count) = counts
        .into_iter()
        .max_by_key(|(category, count)| (*count, *category))?;
    (count.saturating_mul(5) >= members.len().saturating_mul(4)).then_some(category)
}
