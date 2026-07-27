//! Controlled refactoring over the evaluation corpora: what the audit says
//! once the duplication it reported has actually been removed.
//!
//! The audit tests reach each state on a fixture holding one clone pair, which
//! settles that the state is reachable but not that it is reached alone.
//! Grouping is a decision over the whole tree — a group's canonical instance is
//! chosen from its members, so taking one member away can re-form the rest —
//! and removing a unit shifts every line below it in four files at once. Either
//! could show up as movement in findings nobody touched. This asks the question
//! at corpus scale: extract one duplicated unit, and see whether anything
//! *other* than that unit's groups moves.
//!
//! The refactoring is derived from the labels rather than written down, so it
//! cannot drift from the corpus: pairs that share a seed fragment are the same
//! unit written more than once, their union is every site an extraction has to
//! touch, and the labels are generated from the same spec as the sources.
//!
//! Two things it deliberately does not model. The corpus has no callers, so
//! this is the removal half of an extraction and not the rewrite half — real
//! call sites are themselves near-identical lines, and whether a report should
//! group them is a separate question from this one. And `rust-partial` is left
//! out: its labels are runs of statements inside a host function, so lifting
//! one out edits the host as well as removing the copy, which is two changes
//! and not a controlled one.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use assert_cmd::Command;
use codehelion_eval::labels::LabelSet;
use serde_json::Value;

/// One corpus and what a single extraction leaves behind, family by family.
struct Case {
    /// Directory under `corpus/synthetic`.
    name: &'static str,
    /// Per labelled family, in the order the labels first mention it: how many
    /// groups the extraction dissolved and how many it left untouched.
    ///
    /// A family does not always dissolve one group. Where the detector splits
    /// it — the copies that agree closely in one group, the one that drifted in
    /// another — an extraction that removes the unit everywhere dissolves both,
    /// which is why the reference cases show two.
    families: &'static [(usize, usize)],
}

/// The corpora this runs over, with the counts last measured.
///
/// The counts are records, not claims: how many groups a family occupies is a
/// grouping decision, and a change to grouping moves these legitimately. What
/// is claimed is the partition itself — dissolved groups held only units the
/// extraction removed, surviving groups hold none of them, and no state other
/// than those two is reached — and that is asserted per entry regardless of
/// what the counts say.
const CASES: &[Case] = &[
    Case {
        name: "rust",
        families: &[(2, 1), (1, 2)],
    },
    Case {
        name: "c",
        families: &[(2, 1), (1, 2)],
    },
    Case {
        name: "cpp",
        families: &[(2, 1), (1, 2)],
    },
    Case {
        name: "rust-negative",
        families: &[(1, 3), (1, 3), (1, 3), (1, 3)],
    },
    Case {
        name: "rust-graded",
        families: &[(4, 0)],
    },
    Case {
        name: "rust-replaced",
        families: &[(1, 0)],
    },
    Case {
        name: "rust-literals",
        families: &[(1, 0)],
    },
    Case {
        name: "rust-divergent",
        families: &[(3, 0)],
    },
];

/// A labelled family: every place one duplicated unit is written.
struct Family {
    /// Where the labels first mention it, for the printed table.
    origin: String,
    /// The file holding the original, whose text an extraction unifies on.
    seed: String,
    /// File to the inclusive line range the unit occupies there.
    sites: BTreeMap<String, (u32, u32)>,
}

/// The families a label set describes.
///
/// Every labelled pair names the seed side first, so pairs sharing a seed
/// fragment are copies of one unit. The pairwise labels never say so directly;
/// this is where the copies of one thing are collected back together.
fn families(labels: &LabelSet) -> Vec<Family> {
    let mut found: Vec<((String, u32, u32), Family)> = Vec::new();
    for pair in &labels.clone_pairs {
        assert_eq!(
            pair.fragments.len(),
            2,
            "a labelled pair holds exactly two fragments"
        );
        let seed = &pair.fragments[0];
        let copy = &pair.fragments[1];
        let key = (seed.file.clone(), seed.start_line, seed.end_line);
        let index = found
            .iter()
            .position(|(known, _)| *known == key)
            .unwrap_or_else(|| {
                found.push((
                    key,
                    Family {
                        origin: format!("{}:{}", seed.file, seed.start_line),
                        seed: seed.file.clone(),
                        sites: BTreeMap::new(),
                    },
                ));
                found.len() - 1
            });
        for fragment in [seed, copy] {
            found[index].1.sites.insert(
                fragment.file.clone(),
                (fragment.start_line, fragment.end_line),
            );
        }
    }
    found.into_iter().map(|(_, family)| family).collect()
}

/// The unit a line declares, read as the identifier before the parameter list.
///
/// A labelled range starts at the declaration in all three languages, so the
/// last word before the first `(` is the name: `fn sum_even(`, `int sum_even(`.
/// It is only used to say what the extraction took away, so that the audit's
/// account of what it dissolved can be held against it.
fn unit_name(declaration: &str) -> String {
    declaration
        .split('(')
        .next()
        .unwrap_or(declaration)
        .split(|character: char| !character.is_alphanumeric() && character != '_')
        .rfind(|word| !word.is_empty())
        .unwrap_or_default()
        .to_owned()
}

/// Copy a corpus case into a tree of its own, so the edits stay in the scratch
/// directory and the committed corpus is only ever read.
fn stage(case: &Path, into: &Path) {
    std::fs::create_dir_all(into.join(".git")).unwrap();
    for entry in std::fs::read_dir(case).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_file() {
            std::fs::copy(entry.path(), into.join(entry.file_name())).unwrap();
        }
    }
}

/// Extract one family: the unit is written once, in a file of its own, and
/// every place that held a copy loses it.
///
/// Returns the file and unit name of each site it removed, which is what the
/// dissolved groups have to be made of.
fn extract(tree: &Path, family: &Family, extension: &str) -> BTreeSet<(String, String)> {
    let mut removed = BTreeSet::new();
    let mut lifted: Option<String> = None;
    for (file, &(start, end)) in &family.sites {
        let path = tree.join(file);
        let text = std::fs::read_to_string(&path).unwrap();
        let mut lines: Vec<&str> = text.lines().collect();
        let first = usize::try_from(start).unwrap() - 1;
        let last = usize::try_from(end).unwrap();
        removed.insert((file.clone(), unit_name(lines[first])));
        // An extraction unifies the copies on one text; the corpus calls one of
        // them the original, so that is the one that survives.
        if *file == family.seed {
            lifted = Some(lines[first..last].join("\n"));
        }
        lines.drain(first..last);
        std::fs::write(&path, format!("{}\n", lines.join("\n"))).unwrap();
    }
    let shared = lifted.expect("the family names the file its original is written in");
    std::fs::write(
        tree.join(format!("shared.{extension}")),
        format!("{shared}\n"),
    )
    .unwrap();
    removed
}

/// Repository root, from this test's manifest directory.
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("the crate sits two levels below the repository root")
        .to_path_buf()
}

fn cmd() -> Command {
    Command::cargo_bin("codehelion").expect("binary should build")
}

fn scan(tree: &Path) {
    cmd()
        .current_dir(tree)
        .args(["scan", ".", "--mode", "structural"])
        .assert()
        .success();
}

/// Audit the latest run against the one before it, unchanged groups included —
/// the ones this is about are the ones that did not move.
fn audit_json(tree: &Path) -> Value {
    let output = cmd()
        .current_dir(tree)
        .args(["audit", ".", "--format", "json", "--show-unchanged"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    serde_json::from_slice(&output).expect("audit report is json")
}

/// The (file, unit) an entry says the group is written in.
fn occurrences(entry: &Value) -> BTreeSet<(String, String)> {
    entry["occurrences"]
        .as_array()
        .unwrap()
        .iter()
        .map(|occurrence| {
            (
                occurrence["file"].as_str().unwrap().to_owned(),
                occurrence["unit"].as_str().unwrap().to_owned(),
            )
        })
        .collect()
}

#[test]
fn extracting_one_duplicated_unit_resolves_it_and_leaves_the_rest_alone() {
    let root = repo_root();
    let mut table = String::from("\ncorpus           family         sites  resolved  unchanged\n");
    let mut complaints = String::new();

    for case in CASES {
        let dir = root.join("corpus/synthetic").join(case.name);
        let labels_text = std::fs::read_to_string(dir.join("labels.json"))
            .unwrap_or_else(|error| panic!("reading the labels for {}: {error}", case.name));
        let labels = LabelSet::from_json(&labels_text).expect("labels parse");
        let extension = match labels.language.as_str() {
            "rust" => "rs",
            "c" => "c",
            "cpp" => "cpp",
            other => panic!("{}: unknown corpus language {other}", case.name),
        };
        let found = families(&labels);
        if found.len() != case.families.len() {
            writeln!(
                complaints,
                "{}: labels describe {} families, recorded as {}",
                case.name,
                found.len(),
                case.families.len(),
            )
            .expect("writing to a string cannot fail");
            continue;
        }

        for (family, &(dissolved, survived)) in found.iter().zip(case.families) {
            let scratch = tempfile::tempdir().expect("temp dir");
            let tree = scratch.path();
            stage(&dir, tree);
            scan(tree);
            let removed = extract(tree, family, extension);
            scan(tree);
            let report = audit_json(tree);

            let mut resolved = 0usize;
            let mut unchanged = 0usize;
            for entry in report["entries"].as_array().unwrap() {
                let state = entry["state"].as_str().unwrap();
                let occurrences = occurrences(entry);
                match state {
                    "resolved" => {
                        resolved += 1;
                        let stray: Vec<_> = occurrences.difference(&removed).collect();
                        if !stray.is_empty() {
                            writeln!(
                                complaints,
                                "{} {}: dissolved a group written where the extraction never \
                                 reached: {stray:?}",
                                case.name, family.origin,
                            )
                            .expect("writing to a string cannot fail");
                        }
                    }
                    "unchanged" => {
                        unchanged += 1;
                        let held: Vec<_> = occurrences.intersection(&removed).collect();
                        if !held.is_empty() {
                            writeln!(
                                complaints,
                                "{} {}: a surviving group still counts a unit the extraction \
                                 removed: {held:?}",
                                case.name, family.origin,
                            )
                            .expect("writing to a string cannot fail");
                        }
                    }
                    // Removing duplication reaches neither the states that mean
                    // there is more of it than there was, nor the ones that mean
                    // the same duplication is written differently now.
                    other => writeln!(
                        complaints,
                        "{} {}: reported {other} for a group written in {occurrences:?}",
                        case.name, family.origin,
                    )
                    .expect("writing to a string cannot fail"),
                }
            }

            writeln!(
                table,
                "{:<16} {:<14} {:>5} {:>9} {:>10}",
                case.name,
                family.origin,
                family.sites.len(),
                resolved,
                unchanged,
            )
            .expect("writing to a string cannot fail");
            if (resolved, unchanged) != (dissolved, survived) {
                writeln!(
                    complaints,
                    "{} {}: dissolved {resolved} and left {unchanged}, recorded as \
                     {dissolved} and {survived}",
                    case.name, family.origin,
                )
                .expect("writing to a string cannot fail");
            }
        }
    }

    // Printed so a run leaves the figures behind, the way the accuracy run does.
    println!("{table}");
    assert!(complaints.is_empty(), "\n{complaints}");
}
