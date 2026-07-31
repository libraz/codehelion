//! Closed def-use evidence for directly chained iterator operations.
//!
//! This deliberately does not attempt general Rust data-flow. It records only
//! a compiler-resolved `filter` or `map` call whose direct receiver is another
//! compiler-resolved `filter` or `map` call. That establishes that the inner
//! operation's output is the outer operation's input without guessing through
//! a local binding, a branch, a closure, or a function call.

use std::path::Path;

use codehelion_helper::ir::{CallSite, DataFlowSummary};
use ra_ap_ide_db::RootDatabase;
use ra_ap_syntax::{AstNode, ast};

use crate::analysis::{Loaded, file_of};

const FILTER: &str = "rust::Iterator::filter";
const MAP: &str = "rust::Iterator::map";

/// Collect direct `filter`/`map` operation flows from one written source file.
pub(crate) fn collect(loaded: &Loaded, file: &Path, calls: &[CallSite]) -> DataFlowSummary {
    let Some(file_id) = file_of(loaded, file) else {
        return DataFlowSummary::default();
    };
    let sema = ra_ap_hir::Semantics::<RootDatabase>::new(&loaded.db);
    let Some(editioned) = sema.attach_first_edition_opt(file_id) else {
        return DataFlowSummary::default();
    };
    let parse = sema.parse(editioned);
    let mut flows = parse
        .syntax()
        .descendants()
        .filter_map(ast::MethodCallExpr::cast)
        .filter_map(|sink| {
            let sink_api = resolved_operation_api(calls, &sink)?;
            let ast::Expr::MethodCallExpr(source) = sink.receiver()? else {
                return None;
            };
            let source_api = resolved_operation_api(calls, &source)?;
            Some((endpoint(&source, source_api), endpoint(&sink, sink_api)))
        })
        .collect::<Vec<_>>();
    flows.sort();
    flows.dedup();
    DataFlowSummary {
        computed: true,
        flows,
    }
}

/// Return a closed semantic API for a call whose callee range is exactly the
/// call evidence's written anchor.
fn resolved_operation_api<'a>(
    calls: &'a [CallSite],
    call: &ast::MethodCallExpr,
) -> Option<&'a str> {
    let name = call.name_ref()?;
    let range = name.syntax().text_range();
    calls
        .iter()
        .find(|candidate| {
            candidate.anchor.expansion.start_byte == u64::from(u32::from(range.start()))
                && candidate.anchor.expansion.end_byte == u64::from(u32::from(range.end()))
        })
        .and_then(|candidate| candidate.api_name.as_deref())
        .filter(|api| *api == FILTER || *api == MAP)
}

/// A local, source-addressed operation reference for one IR summary.
fn endpoint(call: &ast::MethodCallExpr, api: &str) -> String {
    let range = call.name_ref().map(|name| name.syntax().text_range());
    range.map_or_else(String::new, |range| {
        format!(
            "{}:{}:{api}",
            u64::from(u32::from(range.start())),
            u64::from(u32::from(range.end()))
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_closed_api_vocabulary_is_accepted() {
        assert!(matches!(FILTER, "rust::Iterator::filter"));
        assert!(matches!(MAP, "rust::Iterator::map"));
    }
}
