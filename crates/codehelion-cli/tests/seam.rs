//! The three history-reading commands, end to end.
//!
//! Two kinds of test live here. Most of them plant a small repository whose
//! right answer is known by construction, which is how the command surface,
//! the exit statuses and the JSON shape are checked. One of them reads this
//! repository's own history, and it is the reason the feature exists: the
//! figures it asserts were measured by hand before any of this was written, so
//! a run that disagrees with them means the implementation and the formula
//! have parted company.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;

use assert_cmd::Command;
use codehelion_fixtures::git::{PlannedCommit, plant};
use predicates::prelude::*;

/// The command under test.
fn cmd() -> Command {
    Command::cargo_bin("codehelion").expect("the binary this repository builds")
}

/// This repository's root, from the manifest rather than the working
/// directory, so the test finds it wherever it is run from.
fn repository_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("the crate sits two levels below the repository root")
}

/// The commit the hand measurement was taken at.
///
/// The range is pinned rather than left at `HEAD` because the figures below
/// are counts over a fixed set of commits. Left open, they would move every
/// time somebody committed anything, and a test that has to be re-derived
/// after every commit is not measuring the implementation.
const MEASURED_AT: &str = "476df3a52630eec66d8ad90b404faeb90691a835";

/// A seam ledger naming two directories that are meant to move together.
const LEDGER: &str = r#"
[[seam]]
id = "pair"
members = ["left/**", "right/**"]
note = "two spellings of one rule"
"#;

/// Plant a repository whose history breaches its seam exactly once.
fn planted(root: &Path) {
    plant(
        root,
        &[
            PlannedCommit {
                subject: "feat: start both sides",
                writes: &[("left/a.txt", "one\n"), ("right/a.txt", "one\n")],
                removes: &[],
            },
            PlannedCommit {
                subject: "feat: teach the left side a rule",
                writes: &[("left/a.txt", "one\ntwo\n")],
                removes: &[],
            },
            PlannedCommit {
                subject: "docs: say what the rule is",
                writes: &[("README.md", "a rule\n")],
                removes: &[],
            },
            PlannedCommit {
                subject: "fix: carry the rule to the right side",
                writes: &[("right/a.txt", "one\ntwo\n")],
                removes: &[],
            },
        ],
    )
    .expect("planting a fixture repository");
    std::fs::write(root.join("codehelion.toml"), LEDGER).expect("writing the ledger");
}

#[test]
fn history_counts_commits_without_a_ledger_and_without_reading_source() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let root = directory.path();
    plant(
        root,
        &[
            PlannedCommit {
                subject: "feat: the first thing",
                writes: &[("a.txt", "a\n")],
                removes: &[],
            },
            PlannedCommit {
                subject: "fix: the second thing",
                writes: &[("b.txt", "b\n")],
                removes: &[],
            },
            PlannedCommit {
                subject: "unprefixed subject",
                writes: &[("c.txt", "c\n")],
                removes: &[],
            },
        ],
    )
    .expect("planting a fixture repository");

    cmd()
        .args(["history", "--path", root.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("history: 3 commits"))
        .stdout(predicate::str::contains(
            "declared kinds    fix 1, feat 1, other 1",
        ));

    let output = cmd()
        .args([
            "history",
            "--path",
            root.to_str().unwrap(),
            "--format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let document: serde_json::Value = serde_json::from_slice(&output).expect("valid JSON");
    assert_eq!(document["schema_version"], 1);
    assert_eq!(document["range"]["commits"], 3);
    assert_eq!(document["kinds"]["fix"], 1);
    assert_eq!(document["shallow"], false);
}

#[test]
fn seam_reports_the_ledgers_asymmetric_changes_and_breaches() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let root = directory.path();
    planted(root);

    let output = cmd()
        .args(["seam", "--path", root.to_str().unwrap(), "--format", "json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let document: serde_json::Value = serde_json::from_slice(&output).expect("valid JSON");
    let seam = &document["seams"][0];
    assert_eq!(seam["id"], "pair");
    // The first commit touched both members and is not asymmetric. The second
    // touched the left alone, and the fix two commits later touched the right,
    // which is the breach. That repair is itself a one-sided change and is
    // counted as one: the tool reports the shape it sees, and a change that
    // moved one member is that shape whether or not it was the right thing to
    // do. Hence two asymmetric changes and one breach.
    assert_eq!(seam["asymmetric_changes"], 2);
    assert_eq!(seam["breaches"], 1);
    assert_eq!(seam["changes"][0]["breach"]["distance"], 2);
    assert!(seam["changes"][1]["breach"].is_null());
    // Every result says what it was computed under, so a figure that moved can
    // be told apart from a setting that moved.
    assert!(
        document["settings_digest"]
            .as_str()
            .is_some_and(|digest| digest.len() == 64)
    );
}

#[test]
fn seam_says_so_when_nothing_is_written_down() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let root = directory.path();
    plant(
        root,
        &[PlannedCommit {
            subject: "feat: the only thing",
            writes: &[("a.txt", "a\n")],
            removes: &[],
        }],
    )
    .expect("planting a fixture repository");

    cmd()
        .args(["seam", "--path", root.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("seams: none written down"));
}

#[test]
fn guard_reports_a_working_tree_that_moved_one_side_of_a_seam() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let root = directory.path();
    planted(root);
    std::fs::write(root.join("left").join("a.txt"), "one\ntwo\nthree\n")
        .expect("editing one side of the seam");

    cmd()
        .args(["guard", "--path", root.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "guard: 1 of 1 seam changed on one side only",
        ))
        .stdout(predicate::str::contains("changed    left/**"))
        .stdout(predicate::str::contains("unchanged  right/**"));
}

#[test]
fn guard_reports_nothing_when_both_sides_moved() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let root = directory.path();
    planted(root);
    std::fs::write(root.join("left").join("a.txt"), "one\ntwo\nthree\n").expect("editing the left");
    std::fs::write(root.join("right").join("a.txt"), "one\ntwo\nthree\n")
        .expect("editing the right");

    cmd()
        .args(["guard", "--path", root.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("none changed on one side only"));
}

#[test]
fn deny_asymmetric_is_what_turns_a_report_into_a_failure() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let root = directory.path();
    planted(root);
    std::fs::write(root.join("left").join("a.txt"), "one\ntwo\nthree\n")
        .expect("editing one side of the seam");

    // Reporting is the default, because a change to one member alone is often
    // the right change and nothing here can tell the two apart.
    cmd()
        .args(["guard", "--path", root.to_str().unwrap()])
        .assert()
        .success();
    cmd()
        .args([
            "guard",
            "--path",
            root.to_str().unwrap(),
            "--deny-asymmetric",
        ])
        .assert()
        .code(3);
}

#[test]
fn guard_accepts_a_repository_with_no_ledger_rather_than_refusing_it() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let root = directory.path();
    plant(
        root,
        &[PlannedCommit {
            subject: "feat: the only thing",
            writes: &[("a.txt", "a\n")],
            removes: &[],
        }],
    )
    .expect("planting a fixture repository");

    cmd()
        .args([
            "guard",
            "--path",
            root.to_str().unwrap(),
            "--deny-asymmetric",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "no seams are written down in codehelion.toml",
        ));
}

/// The lookup answers from the ledger alone, with no repository to read.
///
/// Asserted by pointing the command at a directory that is not a git
/// repository at all: if anything on this path opened git, this would fail
/// rather than answer. The question — which seam does this file belong to — is
/// one somebody asks before editing, when there is nothing committed to read.
#[test]
fn the_path_lookup_never_opens_git() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let root = directory.path();
    std::fs::write(root.join("codehelion.toml"), LEDGER).expect("writing the ledger");
    assert!(!root.join(".git").exists());

    cmd()
        .args([
            "guard",
            "--path",
            root.to_str().unwrap(),
            "--paths",
            "left/a.txt",
            "other/b.txt",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("pair via left/**"))
        .stdout(predicate::str::contains("moves with  right/**"))
        .stdout(predicate::str::contains("in no seam"));
}

/// Two runs over the same input produce the same bytes.
///
/// The reason this feature exists is that the previous way of finding seams
/// gave a different answer each time it was asked. A result that varies run to
/// run would put this back where it started, so this is checked ahead of any
/// particular figure it produces.
#[test]
fn the_same_input_produces_the_same_bytes_twice() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let root = directory.path();
    planted(root);

    let run = || {
        cmd()
            .args([
                "seam",
                "--path",
                root.to_str().unwrap(),
                "--until",
                "HEAD",
                "--format",
                "json",
            ])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone()
    };
    assert_eq!(run(), run());

    let suggest = || {
        cmd()
            .args([
                "seam",
                "--path",
                root.to_str().unwrap(),
                "--suggest",
                "--format",
                "json",
            ])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone()
    };
    assert_eq!(suggest(), suggest());
}

/// The seam this repository writes down reproduces the figures measured by
/// hand before the implementation existed.
///
/// Four numbers, over the 434 commits ending at [`MEASURED_AT`]: the two
/// frontends were changed apart 12 times and a fix followed 7 of those; of
/// those, the changes that moved the C frontend and left the C++ one alone
/// number 9, and 4 of them were followed by a fix to C++. The last pair is the
/// measurement the design was argued from, and the first pair is the same
/// measurement taken in both directions.
///
/// A mismatch here is not a stale expectation to update. It means the counting
/// stopped following the definition, and the definition is what the reports
/// claim to be.
#[test]
fn the_measured_frontend_seam_is_reproduced_from_this_repositorys_history() {
    let root = repository_root();
    let output = cmd()
        .args([
            "seam",
            "--path",
            root.to_str().unwrap(),
            "--until",
            MEASURED_AT,
            "--format",
            "json",
        ])
        .assert();
    let output = output.get_output();
    assert!(
        output.status.success(),
        "reading this repository's own history failed. It needs the full history: a \
         shallow checkout cannot reach {MEASURED_AT}, which in GitHub Actions means \
         `actions/checkout` with `fetch-depth: 0`.\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let document: serde_json::Value = serde_json::from_slice(&output.stdout).expect("valid JSON");
    assert_eq!(document["range"]["commits"], 434);

    let seam = document["seams"]
        .as_array()
        .expect("the ledger holds seams")
        .iter()
        .find(|seam| seam["id"] == "frontend-c-cpp")
        .expect("this repository's ledger names the frontend seam");
    assert_eq!(seam["asymmetric_changes"], 12);
    assert_eq!(seam["breaches"], 7);

    // The C frontend is the first member in the ledger, so a change that
    // touched member 0 and not member 1 is one that moved C and left C++ alone.
    let members = seam["members"].as_array().expect("members");
    assert!(
        members[0]
            .as_str()
            .expect("a member glob")
            .contains("frontend-c/")
    );
    let changes = seam["changes"].as_array().expect("changes");
    let c_only: Vec<&serde_json::Value> = changes
        .iter()
        .filter(|change| change["touched"] == serde_json::json!([0]))
        .collect();
    assert_eq!(c_only.len(), 9);
    assert_eq!(
        c_only
            .iter()
            .filter(|change| !change["breach"].is_null())
            .count(),
        4
    );
}

/// `--suggest` does not propose a directory that is no longer in the tree.
///
/// A pair of crates since folded into one moved together in every commit
/// either of them appeared in, so it reads as a perfect coupling forever. The
/// proposal is arithmetically sound and useless: there is nothing left to
/// write a seam about.
#[test]
fn a_suggestion_leaves_out_units_the_tree_no_longer_has() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let root = directory.path();
    plant(
        root,
        &[
            PlannedCommit {
                subject: "feat: three parts that move together",
                writes: &[
                    ("crates/live-a/x.txt", "a\n"),
                    ("crates/live-b/x.txt", "b\n"),
                    ("crates/gone/x.txt", "g\n"),
                ],
                removes: &[],
            },
            PlannedCommit {
                subject: "feat: move all three again",
                writes: &[
                    ("crates/live-a/x.txt", "aa\n"),
                    ("crates/live-b/x.txt", "bb\n"),
                    ("crates/gone/x.txt", "gg\n"),
                ],
                removes: &[],
            },
            PlannedCommit {
                subject: "feat: and once more",
                writes: &[
                    ("crates/live-a/x.txt", "aaa\n"),
                    ("crates/live-b/x.txt", "bbb\n"),
                    ("crates/gone/x.txt", "ggg\n"),
                ],
                removes: &[],
            },
            PlannedCommit {
                subject: "refactor: fold the third part away",
                writes: &[],
                removes: &["crates/gone/x.txt"],
            },
        ],
    )
    .expect("planting a fixture repository");

    let output = cmd()
        .args([
            "seam",
            "--path",
            root.to_str().unwrap(),
            "--suggest",
            "--format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let document: serde_json::Value = serde_json::from_slice(&output).expect("valid JSON");
    let candidates = document["candidates"].as_array().expect("candidates");
    // The two directories still there are proposed; neither pair naming the
    // removed one survives, though the history remembers all three moving as
    // one.
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0]["left"], "crates/live-a");
    assert_eq!(candidates[0]["right"], "crates/live-b");
}
