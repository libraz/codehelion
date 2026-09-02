//! Identifiers assigned to a whole engine report.

use super::*;

#[test]
fn report_ids_clamp_both_ends_of_malformed_token_ranges() {
    let tokens = sample();
    let units = vec![crate::frontend::Unit {
        kind: crate::frontend::UnitKind::Function,
        name: None,
        token_start: tokens.len() + 3,
        token_end: tokens.len() + 7,
        span: SourceSpan {
            start_byte: 0,
            end_byte: 0,
            start_line: 1,
            start_column: 1,
        },
    }];
    let report = EngineReport {
        groups: vec![crate::engine::CloneGroup {
            content_key: 0,
            clone_type: CloneClass::Type1,
            score: 1.0,
            members: vec![crate::engine::Instance {
                file: 0,
                token_start: tokens.len() + 5,
                token_end: tokens.len() + 9,
                start_line: 1,
                end_line: 1,
                unit: Some(0),
            }],
            entropy_bits: 0.0,
            suppressed: None,
        }],
        stats: crate::engine::EngineStats::default(),
    };
    let files = [InputFile {
        tokens: &tokens,
        units: &units,
    }];
    let contexts = [ctx()];

    assert_eq!(
        report_ids(&files, &contexts, &variant(), &report, LiteralNorm::Full).len(),
        1
    );
}
/// A file with no units at all: its copy of the sample statement is preceded
/// by `distinct`, so the files differ in content while the copies do not. This
/// is the C and C++ shape a duplicated top-level macro, record or global takes,
/// where the occurrence sits outside every unit.
fn file_without_units(distinct: &str) -> Vec<Token> {
    let mut tokens = toks(&[(Id, distinct), (Pu, ";")]);
    tokens.extend(sample());
    tokens
}

/// One Type-1 group over the sample statement in each of `files`, none of the
/// occurrences inside a unit.
fn report_over_files_without_units(files: &[Vec<Token>]) -> EngineReport {
    EngineReport {
        groups: vec![crate::engine::CloneGroup {
            content_key: 0,
            clone_type: CloneClass::Type1,
            score: 1.0,
            members: files
                .iter()
                .enumerate()
                .map(|(index, tokens)| crate::engine::Instance {
                    file: index,
                    token_start: tokens.len() - sample().len(),
                    token_end: tokens.len(),
                    start_line: 1,
                    end_line: 1,
                    unit: None,
                })
                .collect(),
            entropy_bits: 0.0,
            suppressed: None,
        }],
        stats: crate::engine::EngineStats::default(),
    }
}

/// Pasting one more copy of known content in a new file leaves the identifiers
/// of the occurrences already reported exactly where they were, even when the
/// new copy is walked first and so is inserted ahead of them in member order.
///
/// The group fingerprint is deliberately unchanged too: it folds deduplicated
/// content, so another copy of known content is not a new group. An identifier
/// that moved here would silently redirect a recorded `explain` argument and a
/// `stable_clone_id` suppression onto a different occurrence.
#[test]
fn a_duplicate_pasted_in_another_file_moves_no_existing_finding_id() {
    fn inputs<'a>(
        files: &'a [Vec<Token>],
        no_units: &'a [crate::frontend::Unit],
    ) -> Vec<InputFile<'a>> {
        files
            .iter()
            .map(|tokens| InputFile {
                tokens,
                units: no_units,
            })
            .collect()
    }

    let existing = [file_without_units("alpha"), file_without_units("beta")];
    let with_new_copy = [
        file_without_units("aardvark"),
        file_without_units("alpha"),
        file_without_units("beta"),
    ];
    let no_units: Vec<crate::frontend::Unit> = Vec::new();
    let contexts = [ctx(); 3];
    let ids = |files: &[Vec<Token>]| {
        report_ids(
            &inputs(files, &no_units),
            &contexts[..files.len()],
            &variant(),
            &report_over_files_without_units(files),
            LiteralNorm::Full,
        )
    };

    let before = ids(&existing);
    let after = ids(&with_new_copy);

    assert_eq!(
        before[0].fingerprint, after[0].fingerprint,
        "another copy of known content is the same group"
    );
    assert_eq!(before[0].members.len(), 2);
    assert_eq!(after[0].members.len(), 3);
    assert_eq!(
        before[0]
            .members
            .iter()
            .map(|member| member.finding)
            .collect::<Vec<_>>(),
        after[0].members[1..]
            .iter()
            .map(|member| member.finding)
            .collect::<Vec<_>>(),
        "the occurrences that did not change keep their identifiers"
    );
    let distinct: BTreeSet<FindingId> = after[0]
        .members
        .iter()
        .map(|member| member.finding)
        .collect();
    assert_eq!(distinct.len(), 3, "each occurrence keeps its own identity");
}
