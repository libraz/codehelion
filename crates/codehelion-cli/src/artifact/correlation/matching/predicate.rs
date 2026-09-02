//! Path and source-extent predicates shared by every correlation pass.

use super::name::uniformly_separated;
use crate::artifact::{FilePath, SourceFragmentIdentity, SourceInstantiation, SourceUnitIdentity};

/// Whether the artifact-side `source_path` names the scanned file
/// `recorded_path`.
///
/// One rule for every path identity question this module asks, so the same
/// pair of paths cannot be a match where a symbol is being placed and a
/// mismatch where its bytes are being attributed. The recorded path is relative
/// to the scan root, and debug information carries it either way, so both
/// readings are accepted.
pub(in crate::artifact) fn paths_match(
    source_path: &str,
    scan_root: &FilePath,
    recorded_path: &str,
) -> bool {
    let source_path = uniformly_separated(source_path);
    let recorded_path = uniformly_separated(recorded_path);
    if source_path == recorded_path {
        return true;
    }
    let scan_root = uniformly_separated(&scan_root.to_string_lossy());
    let scan_root = scan_root.strip_suffix('/').unwrap_or(&scan_root);
    source_path
        .strip_prefix(scan_root)
        .and_then(|inside| inside.strip_prefix('/'))
        .is_some_and(|inside| inside == recorded_path)
}

pub(in crate::artifact) fn source_unit_matches(
    source_path: &str,
    source_line: Option<u32>,
    scan_root: &FilePath,
    unit: &SourceUnitIdentity,
) -> bool {
    if !paths_match(source_path, scan_root, &unit.file_path) {
        return false;
    }
    match (source_line, unit.start_line, unit.end_line) {
        (Some(line), Some(start), Some(end)) => start <= line && line <= end,
        _ => true,
    }
}

/// Match a compiler's generic-definition anchor to a source unit.
///
/// Clang reports a function template at its declaration line, whereas the
/// structural frontend anchors its function unit at the opening brace on the
/// following line.  That one-line difference is syntax-derived rather than a
/// fuzzy location match, and is limited to generic-origin evidence.
pub(in crate::artifact) fn source_generic_unit_matches(
    source_path: &str,
    source_line: Option<u32>,
    scan_root: &FilePath,
    unit: &SourceUnitIdentity,
) -> bool {
    if source_unit_matches(source_path, source_line, scan_root, unit) {
        return true;
    }
    let (Some(line), Some(start_line)) = (source_line, unit.start_line) else {
        return false;
    };
    paths_match(source_path, scan_root, &unit.file_path) && line.checked_add(1) == Some(start_line)
}

/// Whether a source unit is wholly inside a class-template definition.
///
/// Class template instantiations are anchored at the class declaration, while
/// emitted symbols commonly name an inline member body.  The compiler-supplied
/// definition extent lets this match that member without guessing from its
/// short name.  Both endpoints must be present, so a partial range remains
/// unmapped.
pub(in crate::artifact) fn source_template_definition_contains_unit(
    instantiation: &SourceInstantiation,
    scan_root: &FilePath,
    unit: &SourceUnitIdentity,
) -> bool {
    let (Some(definition_end_line), Some(unit_start_line), Some(unit_end_line)) = (
        instantiation.definition_end_line,
        unit.start_line,
        unit.end_line,
    ) else {
        return false;
    };
    paths_match(&instantiation.file_path, scan_root, &unit.file_path)
        && instantiation.line <= unit_start_line
        && unit_end_line <= definition_end_line
}

pub(in crate::artifact) fn source_fragment_matches(
    source_path: &str,
    source_line: Option<u32>,
    scan_root: &FilePath,
    fragment: &SourceFragmentIdentity,
) -> bool {
    if !paths_match(source_path, scan_root, &fragment.file_path) {
        return false;
    }
    match (source_line, fragment.start_line, fragment.end_line) {
        (Some(line), Some(start), Some(end)) => start <= line && line <= end,
        // A file path alone cannot select a clone fragment: treating every
        // fragment in the file as a DWARF match would make a missing line
        // look like evidence and could attribute bytes to an arbitrary
        // duplicate. Whole units may remain an explicitly ambiguous mapping,
        // but fragment-level attribution is fail-closed.
        _ => false,
    }
}
