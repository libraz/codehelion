use super::Unit;
use super::evidence::{ResolvedTypes, UnitEvidence};
use super::model::DirectoryPartition;
use crate::boilerplate;
use crate::conditional::ArmPath;
use crate::discovery::BuildVariant;
use crate::engine::normalize::Resolution;
use crate::features::FileFeatures;
use crate::frontend::{Token, UnitKind};
use crate::ir::{IrNode, Shape, SyntaxIrFile};
use crate::stable_id::{self, ContentNorm, FileContext};
use crate::test_code::{self, TestCodeEvidence};
use crate::verify::{self, UnitView};

/// Flatten every file's units into one global list, in IR-walk order, together
/// with the index that maps a walk position to it. The walk order matches
/// [`features::extract`]'s, so a `(file, local)` index pair addresses one
/// walked unit shape in both.
#[cfg(test)]
pub(super) fn flatten_units(
    files: &[SyntaxIrFile],
    variant: &BuildVariant,
    literals: crate::engine::LiteralNorm,
    resolved: &ResolvedTypes,
) -> (Vec<Unit>, UnitIndex) {
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
) -> (Vec<Unit>, UnitIndex) {
    let directory_partitions =
        directory_partitions.filter(|partitions| partitions.len() == files.len());
    let mut units = Vec::new();
    let mut index = UnitIndex {
        offsets: Vec::with_capacity(files.len()),
        skipped: Vec::with_capacity(files.len()),
    };
    // Conditional identifiers run across the whole corpus rather than per
    // file, so that two files' conditionals can never be taken for one.
    let mut next_conditional = 0u32;
    for (file_index, file) in files.iter().enumerate() {
        index.offsets.push(units.len());
        index.skipped.push(Vec::new());
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
            skipped: &mut index.skipped[file_index],
        };
        // A file the tree declares as a test module starts marked: the
        // attribute saying so is on the declaration, which is in some other
        // file, so nothing in this one would carry it.
        for root in &file.roots {
            walk.visit(root, file.test_module, &ArmPath::default());
        }
    }
    (units, index)
}

/// Where each file's analysed units sit in the global list.
///
/// A candidate stage names a unit by its position in [`features::extract`]'s
/// walk, and this is what turns that position into a global unit index. The
/// two walks visit the same shapes, but a shape the walk could read no tokens
/// for becomes no unit at all, so the mapping is not always the plain sum of a
/// file's offset and the position.
pub(super) struct UnitIndex {
    /// Global index of each file's first analysed unit.
    offsets: Vec<usize>,
    /// Walk positions each file recorded no unit for, in ascending order.
    /// Empty for every file whose units were all readable, which is the
    /// ordinary case.
    skipped: Vec<Vec<usize>>,
}

impl UnitIndex {
    /// An index over files whose every walked unit shape became a unit.
    #[cfg(test)]
    pub(super) fn dense(offsets: Vec<usize>) -> Self {
        let skipped = vec![Vec::new(); offsets.len()];
        Self { offsets, skipped }
    }

    /// The global index of the unit at one walk position, or `None` where the
    /// walk recorded none.
    pub(super) fn global(&self, file: usize, local: usize) -> Option<usize> {
        let offset = *self.offsets.get(file)?;
        let skipped = self.skipped.get(file)?;
        if skipped.is_empty() {
            return Some(offset + local);
        }
        if skipped.binary_search(&local).is_ok() {
            return None;
        }
        Some(offset + local - skipped.partition_point(|&position| position < local))
    }
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
    /// This file's walk positions that produced no unit.
    skipped: &'a mut Vec<usize>,
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
        // Only a conditional's own node allocates a path; everything else
        // keeps the one it was handed. A conditional the parser stumbled
        // inside is entered but believed nothing of: see [`crate::conditional`]
        // for why an invented arm costs more than a missed one.
        //
        // The condition is read off the same tokens, so an arm no build takes
        // is entered unreachable here rather than only in the Fast lexer, and
        // one gate decides a pair the same way in every mode.
        let descended = arms.descend_with_condition(
            node,
            self.next_conditional,
            crate::conditional::literal_condition(tokens),
        );
        let arms = descended.as_ref().unwrap_or(arms);

        // A unit shape whose token range names no token has no line span to
        // report and no content to compare, so the walk records the position
        // and no unit. A candidate stage naming that position then resolves to
        // no unit rather than to its neighbour.
        if let Some(kind) = unit_kind(&node.shape) {
            match line_range(tokens) {
                None => self.skipped.push(self.local),
                Some(lines) => self.record(node, kind, tokens, lines, test_code, arms),
            }
            self.local += 1;
        }

        for child in &node.children {
            self.visit(child, test_code, arms);
        }
    }

    /// Record one analysed unit at the walk's current position.
    fn record(
        &mut self,
        node: &IrNode,
        kind: UnitKind,
        tokens: &[Token],
        lines: (u32, u32),
        test_code: bool,
        arms: &ArmPath,
    ) {
        let test_code_evidence = test_code.then_some(TestCodeEvidence::Marker);
        let end = node.token_end.min(self.source.tokens.len());
        let start = node.token_start.min(end);
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
            lines,
            tokens: (start, end),
            name: node.name.clone(),
            boilerplate: boilerplate::classify(node),
            test_code,
            test_code_evidence,
            arms: arms.clone(),
        });
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
///
/// `None` for an empty slice. Line numbers start at 1, so there is no line a
/// span covering nothing could name, and a zero reported in their place is
/// indistinguishable from a real position.
pub(super) fn line_range(tokens: &[Token]) -> Option<(u32, u32)> {
    let (Some(first), Some(last)) = (tokens.first(), tokens.last()) else {
        return None;
    };
    let newlines = u32::try_from(last.text.matches('\n').count()).unwrap_or(0);
    Some((
        first.span.start_line,
        last.span.start_line.saturating_add(newlines),
    ))
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
