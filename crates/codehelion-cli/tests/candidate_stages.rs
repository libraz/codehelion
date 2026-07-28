//! What each candidate-generation stage is worth, measured by removing it.
//!
//! Every stage before verification is a proposal mechanism: it decides which
//! pairs are worth the expensive comparison and nothing else. That makes its
//! settings invisible in a report — a pair a gate rejected leaves no trace,
//! so no number a scan prints can say whether the gate was set well.
//!
//! Ablation can say it. Running one corpus twice, once with a stage disabled,
//! and comparing the groups that come out measures exactly what the stage
//! contributes: a stage that changes no group proposed nothing the others did
//! not, however many pairs it put forward.
//!
//! What the numbers below record is that the near-match stage and the
//! shape-divergence gate change no result on any corpus this project has.
//! That is not a claim that they never would — near-match exists for the
//! gapped clones that exact seeds miss, and the largest case here is under
//! half a million lines. It is the reason their thresholds are not calibrated
//! against the corpus: there is nothing yet to calibrate them on, and a number
//! tuned against a stage that changes nothing would be tuned against noise.
//!
//! The pins are records, not claims. A stage that starts contributing is a
//! change worth explaining, not a failure.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use codehelion_core::discovery::{BuildVariant, Language, LanguageSelection};
use codehelion_core::ir::{StructuralFrontend, SyntaxIrFile};
use codehelion_core::near_match::NearMatchConfig;
use codehelion_core::structural::{self, StructuralConfig, StructuralReport};

/// A corpus and the groups it reports, with each stage removed in turn.
///
/// `groups` is the count the default settings reach. The two that follow are
/// the counts without that stage; equal numbers are the finding that the stage
/// changed nothing, and the test also checks the groups themselves rather than
/// only how many there are.
///
/// These are the groups the engine forms, not the ones a scan lists: nothing
/// here is folded, suppressed or ranked, because none of that is what a
/// candidate stage decides. The counts therefore differ from the ones the
/// precision harness reports about the same corpus.
struct Expected {
    /// Directory under `corpus`.
    path: &'static str,
    groups: usize,
    without_near_match: usize,
    without_shape_gate: usize,
}

/// Every corpus, with what each stage is worth on it.
const CORPORA: &[Expected] = &[
    Expected {
        path: "synthetic/rust",
        groups: 2,
        without_near_match: 2,
        without_shape_gate: 2,
    },
    Expected {
        path: "synthetic/c",
        groups: 2,
        without_near_match: 2,
        without_shape_gate: 2,
    },
    Expected {
        path: "synthetic/cpp",
        groups: 2,
        without_near_match: 2,
        without_shape_gate: 2,
    },
    Expected {
        path: "synthetic/rust-graded",
        groups: 1,
        without_near_match: 1,
        without_shape_gate: 1,
    },
    Expected {
        path: "synthetic/rust-literals",
        groups: 1,
        without_near_match: 1,
        without_shape_gate: 1,
    },
    Expected {
        path: "synthetic/rust-replaced",
        groups: 1,
        without_near_match: 1,
        without_shape_gate: 1,
    },
    Expected {
        path: "synthetic/rust-negative",
        groups: 4,
        without_near_match: 4,
        without_shape_gate: 4,
    },
    Expected {
        path: "synthetic/rust-partial",
        groups: 3,
        without_near_match: 3,
        without_shape_gate: 3,
    },
    Expected {
        path: "synthetic/rust-divergent",
        groups: 2,
        without_near_match: 2,
        without_shape_gate: 2,
    },
    Expected {
        path: "labeled/fast-yaml-cpp/snapshot",
        groups: 16,
        without_near_match: 16,
        without_shape_gate: 16,
    },
    Expected {
        path: "labeled/fast-yaml/snapshot",
        groups: 1,
        without_near_match: 1,
        without_shape_gate: 1,
    },
    Expected {
        path: "labeled/codehelion-store/snapshot",
        groups: 4,
        without_near_match: 4,
        without_shape_gate: 4,
    },
    Expected {
        path: "labeled/cjson/snapshot",
        groups: 18,
        without_near_match: 18,
        without_shape_gate: 18,
    },
    Expected {
        path: "labeled/lz4/snapshot",
        groups: 29,
        without_near_match: 29,
        without_shape_gate: 29,
    },
    Expected {
        path: "labeled/serde-json/snapshot",
        groups: 75,
        without_near_match: 75,
        without_shape_gate: 75,
    },
    Expected {
        path: "labeled/spdlog/snapshot",
        groups: 51,
        without_near_match: 51,
        without_shape_gate: 51,
    },
    Expected {
        path: "labeled/bitflags/snapshot",
        groups: 18,
        without_near_match: 18,
        without_shape_gate: 18,
    },
    Expected {
        path: "labeled/tinyxml2/snapshot",
        groups: 28,
        without_near_match: 28,
        without_shape_gate: 28,
    },
];

/// Repository root, from this test's manifest directory.
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("the crate sits two levels below the repository root")
        .to_path_buf()
}

/// Which grammar reads a file, or `None` when nothing here does.
///
/// A bare `.h` is read as C++, which is what the scan settles per tree. The
/// choice only has to be the same for both runs of one corpus: this measures
/// the difference a stage makes, not what a scan of the tree would report.
fn language_of(path: &Path) -> Option<Language> {
    match path.extension()?.to_str()? {
        "rs" => Some(Language::Rust),
        "c" => Some(Language::C),
        "cpp" | "cc" | "cxx" | "hpp" | "inl" | "h" => Some(Language::Cpp),
        _ => None,
    }
}

/// Parse every source under `root`, in a deterministic order.
fn parse_tree(root: &Path) -> (Vec<SyntaxIrFile>, LanguageSelection) {
    let mut paths = Vec::new();
    collect(root, &mut paths);
    paths.sort();
    let mut irs = Vec::new();
    let mut languages = LanguageSelection {
        rust: false,
        c: false,
        cpp: false,
    };
    for path in paths {
        let Some(language) = language_of(&path) else {
            continue;
        };
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        let text = String::from_utf8_lossy(&bytes);
        irs.push(match language {
            Language::Rust => {
                languages.rust = true;
                codehelion_frontend_rust::ir::RustStructuralFrontend.parse(&text)
            }
            Language::C => {
                languages.c = true;
                codehelion_frontend_c::ir::CStructuralFrontend.parse(&text)
            }
            Language::Cpp => {
                languages.cpp = true;
                codehelion_frontend_cpp::ir::CppStructuralFrontend.parse(&text)
            }
        });
    }
    (irs, languages)
}

fn collect(dir: &Path, into: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect(&path, into);
        } else {
            into.push(path);
        }
    }
}

/// The groups a run reported, as the fingerprints that name them.
fn fingerprints(report: &StructuralReport) -> Vec<String> {
    let mut ids: Vec<String> = report
        .details
        .iter()
        .map(|detail| detail.fingerprint.to_hex())
        .collect();
    ids.sort();
    ids
}

fn analyze(
    irs: &[SyntaxIrFile],
    languages: LanguageSelection,
    config: &StructuralConfig,
) -> StructuralReport {
    let variant = BuildVariant::structural(languages, Language::Cpp);
    structural::analyze(irs, &variant, config)
}

#[test]
fn removing_a_candidate_stage_changes_nothing_it_was_recorded_to_change() {
    let root = repo_root();
    let mut table = String::from(
        "\ncorpus                            groups  without near-match  without shape gate\n",
    );
    let mut complaints = String::new();
    let mut unmaterialized = 0usize;

    for expected in CORPORA {
        let corpus = root.join("corpus").join(expected.path);
        if !corpus.is_dir() {
            // The labelled sources belong to the projects they came from and
            // are fetched, not committed. Say so rather than passing quietly.
            writeln!(table, "{:32}  (not materialized)", expected.path).unwrap();
            unmaterialized += 1;
            continue;
        }
        let (irs, languages) = parse_tree(&corpus);

        let full = analyze(&irs, languages, &StructuralConfig::default());

        // A Jaccard no estimate can reach empties the stage without touching
        // the ones around it.
        let no_near = StructuralConfig {
            near_match: NearMatchConfig {
                min_estimated_jaccard: 2.0,
                ..NearMatchConfig::default()
            },
            ..StructuralConfig::default()
        };
        let without_near_match = analyze(&irs, languages, &no_near);

        // A divergence no pair can exceed is the gate not being there.
        let no_gate = StructuralConfig {
            max_shape_divergence: f64::INFINITY,
            ..StructuralConfig::default()
        };
        let without_shape_gate = analyze(&irs, languages, &no_gate);

        let (base, near, gate) = (
            fingerprints(&full),
            fingerprints(&without_near_match),
            fingerprints(&without_shape_gate),
        );
        writeln!(
            table,
            "{:32} {:7} {:19} {:19}",
            expected.path,
            base.len(),
            near.len(),
            gate.len()
        )
        .unwrap();

        let mut check = |what: &str, seen: &[String], recorded: usize| {
            if seen.len() != recorded {
                writeln!(
                    complaints,
                    "{}: {what} reports {} groups, recorded as {recorded}",
                    expected.path,
                    seen.len(),
                )
                .unwrap();
            }
            // Equal counts and different groups is the case a count hides.
            if seen.len() == base.len() && seen != base {
                writeln!(
                    complaints,
                    "{}: {what} reports as many groups as the default settings \
                     but not the same ones",
                    expected.path,
                )
                .unwrap();
            }
        };
        check("the default settings", &base, expected.groups);
        check("without near-match", &near, expected.without_near_match);
        check("without the shape gate", &gate, expected.without_shape_gate);
    }

    if unmaterialized > 0 {
        writeln!(
            table,
            "\n{unmaterialized} labelled case(s) not materialized; run \
             corpus/scripts/materialize-labeled.sh to score them",
        )
        .unwrap();
    }
    println!("{table}");
    assert!(complaints.is_empty(), "\n{complaints}");
}
