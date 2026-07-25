//! Precision over the committed negative corpus.
//!
//! The corpus holds four functions built on the same skeleton — accumulate
//! over a slice under a branch, return the accumulator — that compute
//! genuinely different things, plus a file of verbatim copies of all four. The
//! copies are real clones; every pairing of two *different* functions is
//! labelled a non-clone. What must come out is four groups, one per function,
//! and nothing that mixes two of them.
//!
//! Sharing a skeleton is the whole construction of the corpus, which makes it
//! the adversarial case for the candidate stage that indexes skeletons: the
//! look-alikes are proposed, and only the judge separates them from the
//! copies. What the corpus measures is therefore that separation, not the
//! narrowness of what reaches it.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;
use std::path::PathBuf;

use codehelion_core::clone_class::CloneClass;
use codehelion_core::discovery::{BuildVariant, LanguageSelection};
use codehelion_core::features;
use codehelion_core::ir::{Shape, StructuralFrontend, SyntaxIrFile};
use codehelion_core::structural::{self, StructuralConfig, StructuralReport};
use codehelion_core::verify::{self, UnitView, Verdict, VerifyConfig};
use codehelion_frontend_rust::ir::RustStructuralFrontend;

const CORPUS: &str = "../../corpus/synthetic/rust-negative";
const FILES: [&str; 2] = ["seed.rs", "copies.rs"];

/// The seed's functions, in source order.
const FUNCTIONS: [&str; 4] = [
    "sum_positive",
    "longest_run",
    "count_transitions",
    "narrowest_gap",
];

fn parse(name: &str) -> SyntaxIrFile {
    let path = PathBuf::from(CORPUS).join(name);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
    RustStructuralFrontend.parse(&text)
}

fn analyze() -> StructuralReport {
    let files: Vec<SyntaxIrFile> = FILES.iter().map(|name| parse(name)).collect();
    let variant = BuildVariant::structural(LanguageSelection::default());
    structural::analyze(&files, &variant, &StructuralConfig::default())
}

/// Every pairing of two different seed functions, scored by the judge
/// directly, labelled and in source order.
fn negative_verdicts() -> Vec<(String, Verdict)> {
    let file = parse("seed.rs");
    let extracted = features::extract(&file);
    let mut units = Vec::new();
    file.walk(&mut |node| {
        if matches!(node.shape, Shape::Function) {
            units.push((
                node.name
                    .as_ref()
                    .map_or("?", |name| name.as_str())
                    .to_string(),
                verify::statement_sequence(node, &file.tokens),
            ));
        }
    });
    assert_eq!(units.len(), FUNCTIONS.len());

    let mut scored = Vec::new();
    for (i, first) in units.iter().enumerate() {
        for (j, second) in units.iter().enumerate().skip(i + 1) {
            let verdict = verify::verify(
                &UnitView {
                    statements: &first.1,
                    tokens: &file.tokens,
                    features: &extracted.units[i],
                },
                &UnitView {
                    statements: &second.1,
                    tokens: &file.tokens,
                    features: &extracted.units[j],
                },
                &VerifyConfig::default(),
            );
            scored.push((format!("{} x {}", first.0, second.0), verdict));
        }
    }
    scored
}

#[test]
fn only_the_verbatim_copies_are_reported() {
    let report = analyze();
    assert_eq!(report.units.len(), FUNCTIONS.len() * FILES.len());
    assert_eq!(report.groups.groups.len(), FUNCTIONS.len());

    let mut grouped = BTreeSet::new();
    for group in &report.groups.groups {
        assert_eq!(group.clone_type, CloneClass::Type1);
        let names: BTreeSet<&str> = group
            .members
            .iter()
            .map(|&member| {
                report.units[member]
                    .name
                    .as_ref()
                    .map_or("?", |name| name.as_str())
            })
            .collect();
        assert_eq!(
            names.len(),
            1,
            "a group mixes two different functions: {names:?}"
        );
        assert_eq!(group.members.len(), FILES.len());
        grouped.extend(names);
    }
    assert_eq!(grouped, FUNCTIONS.iter().copied().collect::<BTreeSet<_>>());
}

#[test]
fn the_negative_pairs_are_proposed_and_then_rejected() {
    let report = analyze();
    // These four functions were written around one control-flow skeleton, so
    // the skeleton is the one description of them under which they are
    // indistinguishable — and candidate extraction indexes exactly that. Every
    // cross pairing is therefore proposed here, on top of the four real copies
    // the exact-seed layer finds, and the judge is the only thing standing
    // between the corpus and sixteen findings.
    //
    // The counts are pinned rather than bounded. A rise means candidate
    // extraction reaches further into a family built to defeat it, which is
    // worth knowing even when the judge still holds; a fall in the verified
    // count means a real copy went missing.
    assert!(report.stats.unit_pairs > FUNCTIONS.len());
    assert_eq!(report.stats.unit_pairs, 16);
    assert_eq!(report.stats.verified_pairs, FUNCTIONS.len());
}

#[test]
fn the_judge_rejects_every_negative_pair() {
    // These are the pairs the acceptance threshold is calibrated against: the
    // highest-scoring of them is what the threshold has to sit above. Fixing
    // the rejection here is what stops a future weight or threshold change
    // from quietly re-admitting them.
    let config = VerifyConfig::default();
    for (pair, verdict) in negative_verdicts() {
        assert_eq!(verdict.class, None, "{pair} is not a clone");
        assert!(
            verdict.breakdown.composite < config.type3_min_composite,
            "{pair} scored {:.4}, at or above the acceptance threshold {:.2}",
            verdict.breakdown.composite,
            config.type3_min_composite
        );
        assert!(
            verdict.breakdown.structural < 1.0,
            "{pair} does not have identical structure"
        );
    }
}

#[test]
fn lexical_agreement_is_what_separates_these_from_real_copies() {
    // The family shares a skeleton by construction, so shape agreement runs
    // high for clone and lookalike alike and cannot tell them apart. Only the
    // text does. Recording the ceiling these reach keeps that visible: a
    // dimension reweighting that leans further on shape than on text is moving
    // away from the one signal that works here, however it scores elsewhere.
    for (pair, verdict) in negative_verdicts() {
        assert!(
            verdict.breakdown.lexical < 0.60,
            "{pair} agrees lexically to {:.4}",
            verdict.breakdown.lexical
        );
    }

    // The real copies in the same corpus agree lexically in full, so the gap
    // the text opens up between the two populations is the whole of it.
    let report = analyze();
    for detail in &report.details {
        for breakdown in &detail.member_breakdowns {
            assert!(
                breakdown.lexical > 0.99,
                "a verbatim copy agrees lexically to only {:.4}",
                breakdown.lexical
            );
        }
    }
}

#[test]
fn the_call_free_negatives_carry_no_api_evidence() {
    // None of these functions calls anything, so the dimension has nothing to
    // compare. Reporting that as agreement would hand each of these pairs the
    // dimension's whole weight for free — and this family, small helpers built
    // on a shared skeleton, is exactly where that inflation does damage.
    for (pair, verdict) in negative_verdicts() {
        assert_eq!(
            verdict.breakdown.api, None,
            "{pair} has no call surface to compare"
        );
    }
}

#[test]
fn the_corpus_measures_the_same_twice() {
    let composites = |scored: Vec<(String, Verdict)>| -> Vec<(String, f64)> {
        scored
            .into_iter()
            .map(|(pair, verdict)| (pair, verdict.breakdown.composite))
            .collect()
    };
    assert_eq!(
        composites(negative_verdicts()),
        composites(negative_verdicts())
    );
}
