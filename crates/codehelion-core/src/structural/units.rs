use super::{
    ArmPath, BuildVariant, ContentNorm, DirectoryPartition, FileContext, FileFeatures, IrNode,
    Resolution, ResolvedTypes, Shape, SyntaxIrFile, TestCodeEvidence, Token, Unit, UnitEvidence,
    UnitKind, UnitView, boilerplate, stable_id, test_code, verify,
};

/// Flatten every file's units into one global list, in IR-walk order, and
/// record each file's starting offset. The unit order matches
/// [`features::extract`]'s, so a `(file, local)` index pair maps to the global
/// index `offsets[file] + local`.
#[cfg(test)]
pub(super) fn flatten_units(
    files: &[SyntaxIrFile],
    variant: &BuildVariant,
    literals: crate::engine::LiteralNorm,
    resolved: &ResolvedTypes,
) -> (Vec<Unit>, Vec<usize>) {
    flatten_units_with_context(files, variant, literals, resolved, None)
}

/// Flatten units while carrying an optional opaque directory context for the
/// signature sibling channel. A context with the wrong cardinality disables
/// that channel for the whole run rather than guessing which file a partition
/// belongs to.
pub(super) fn flatten_units_with_context(
    files: &[SyntaxIrFile],
    variant: &BuildVariant,
    literals: crate::engine::LiteralNorm,
    resolved: &ResolvedTypes,
    directory_partitions: Option<&[DirectoryPartition]>,
) -> (Vec<Unit>, Vec<usize>) {
    let directory_partitions =
        directory_partitions.filter(|partitions| partitions.len() == files.len());
    let mut units = Vec::new();
    let mut offsets = Vec::with_capacity(files.len());
    // Conditional identifiers run across the whole corpus rather than per
    // file, so that two files' conditionals can never be taken for one.
    let mut next_conditional = 0u32;
    for (file_index, file) in files.iter().enumerate() {
        offsets.push(units.len());
        let mut walk = UnitWalk {
            file: file_index,
            source: file,
            context: FileContext {
                frontend_version: file.frontend_version,
                language: file.language,
            },
            variant,
            literals,
            resolution: resolved.names_for(file_index),
            local: 0,
            next_conditional: &mut next_conditional,
            directory: directory_partitions
                .and_then(|partitions| partitions.get(file_index).copied()),
            units: &mut units,
        };
        // A file the tree declares as a test module starts marked: the
        // attribute saying so is on the declaration, which is in some other
        // file, so nothing in this one would carry it.
        for root in &file.roots {
            walk.visit(root, file.test_module, &ArmPath::default());
        }
    }
    (units, offsets)
}

/// A depth-first walk over one file's IR that collects its analysed units.
///
/// [`IrNode::walk`] would do for the units themselves, but a unit inherits
/// facts from the items enclosing it — a function inside a test-only module is
/// test code without carrying a marker of its own, and one inside a `#ifdef`
/// belongs to that arm — and a flat visitor has no ancestors to inherit from.
/// The order matches [`IrNode::walk`]'s, and so [`features::extract`]'s:
/// pre-order, children in source order.
struct UnitWalk<'a> {
    file: usize,
    source: &'a SyntaxIrFile,
    context: FileContext<'a>,
    variant: &'a BuildVariant,
    literals: crate::engine::LiteralNorm,
    resolution: Option<&'a Resolution>,
    directory: Option<DirectoryPartition>,
    local: usize,
    /// Hands out conditional identifiers; shared across every file in a run.
    next_conditional: &'a mut u32,
    units: &'a mut Vec<Unit>,
}

impl UnitWalk<'_> {
    /// Visit one node, recording it when it is an analysed unit, then its
    /// children. `test_code` and `arms` are what the enclosing items
    /// established.
    fn visit(&mut self, node: &IrNode, test_code: bool, arms: &ArmPath) {
        let end = node.token_end.min(self.source.tokens.len());
        let start = node.token_start.min(end);
        let tokens = &self.source.tokens[start..end];
        let test_code = test_code || test_code::is_marked(self.source.language, tokens);
        let test_code_evidence = test_code.then_some(TestCodeEvidence::Marker);
        // Only a conditional's own node allocates a path; everything else
        // keeps the one it was handed. A conditional the parser stumbled
        // inside is entered but believed nothing of: see [`crate::conditional`]
        // for why an invented arm costs more than a missed one.
        let descended = arms.descend(node, self.next_conditional);
        let arms = descended.as_ref().unwrap_or(arms);

        if let Some(kind) = unit_kind(&node.shape) {
            let fingerprint =
                stable_id::unit_fingerprint(self.variant, &self.context, tokens, ContentNorm::Raw);
            let content = stable_id::fragment_fingerprint(
                self.variant,
                &self.context,
                "unit",
                tokens,
                ContentNorm::Raw,
            );
            let normalized_content = stable_id::resolved_fragment_fingerprint(
                self.variant,
                &self.context,
                "unit",
                tokens,
                ContentNorm::ResolvedNormalized(self.literals),
                self.resolution,
            );
            self.units.push(Unit {
                file: self.file,
                local: self.local,
                kind,
                statements: verify::statement_sequence(node, &self.source.tokens),
                fingerprint,
                content,
                normalized_content,
                signature: self.source.signature_for_range(node.range).cloned(),
                directory: self.directory,
                range: node.range,
                lines: line_range(tokens),
                tokens: (start, end),
                name: node.name.clone(),
                boilerplate: boilerplate::classify(node),
                test_code,
                test_code_evidence,
                arms: arms.clone(),
            });
            self.local += 1;
        }

        for child in &node.children {
            self.visit(child, test_code, arms);
        }
    }
}

/// The reportable unit kind of an IR shape, or `None` for a shape that is not
/// an analysed unit. The unit shapes here are exactly the ones
/// [`features::extract`] walks, so unit indices stay aligned.
const fn unit_kind(shape: &Shape) -> Option<UnitKind> {
    match *shape {
        Shape::Function => Some(UnitKind::Function),
        Shape::Method => Some(UnitKind::Method),
        Shape::Closure => Some(UnitKind::Closure),
        _ => None,
    }
}

/// The 1-based line range a token slice covers, following the Fast engine's
/// rule: the last token's own newlines extend its end line, so a unit ending
/// in a multi-line literal reports its true last line.
pub(super) fn line_range(tokens: &[Token]) -> (u32, u32) {
    let (Some(first), Some(last)) = (tokens.first(), tokens.last()) else {
        return (0, 0);
    };
    let newlines = u32::try_from(last.text.matches('\n').count()).unwrap_or(0);
    (
        first.span.start_line,
        last.span.start_line.saturating_add(newlines),
    )
}

/// Build a unit's verification view from its statements, the token stream they
/// span, and its features.
pub(super) fn view<'a>(
    index: usize,
    units: &'a [Unit],
    files: &'a [SyntaxIrFile],
    feature_files: &'a [FileFeatures],
    evidence: &'a UnitEvidence,
) -> UnitView<'a> {
    let unit = &units[index];
    UnitView {
        statements: &unit.statements,
        tokens: &files[unit.file].tokens,
        content: unit.content,
        features: &feature_files[unit.file].units[unit.local],
        // Absent unless a compiler resolved types inside this unit's bytes.
        types: evidence.types.get(index).and_then(Option::as_ref),
        apis: evidence.apis.get(index).and_then(Option::as_ref),
    }
}
