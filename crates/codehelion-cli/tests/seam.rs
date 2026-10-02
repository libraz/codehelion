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
use codehelion_fixtures::git::{PlannedCommit, Planter, plant};
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

/// A history that breaches its seam exactly once: a rule taught to the left
/// side, and carried to the right two commits later.
const PAIR_HISTORY: &[PlannedCommit] = &[
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
];

/// Plant a repository whose history breaches its seam exactly once.
fn planted(root: &Path) {
    plant(root, PAIR_HISTORY).expect("planting a fixture repository");
    std::fs::write(root.join("codehelion.toml"), LEDGER).expect("writing the ledger");
}

/// The same repository, with the planter kept so a test can commit again after
/// the command under test has read the history once.
fn planted_and_still_open(root: &Path) -> Planter {
    let mut planter = Planter::initialise(root).expect("initialising a fixture repository");
    for commit in PAIR_HISTORY {
        planter.commit(commit).expect("planting a commit");
    }
    std::fs::write(root.join("codehelion.toml"), LEDGER).expect("writing the ledger");
    planter
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

/// Run git in `root` with a fixed identity, for the repository shapes the
/// planter does not build itself.
#[allow(
    clippy::disallowed_types,
    reason = "the fixture repository is built by git itself"
)]
fn git_in(root: &Path, args: &[&str]) {
    let status = std::process::Command::new("git")
        .current_dir(root)
        .args([
            "-c",
            "user.name=planter",
            "-c",
            "user.email=planter@example.invalid",
        ])
        .args(args)
        .status()
        .expect("run git");
    assert!(status.success(), "git {args:?} failed");
}

/// The commits a `history --until` read, as its JSON range counts them.
fn history_commits(root: &Path, until: &str) -> serde_json::Value {
    let output = cmd()
        .args([
            "history",
            "--path",
            root.to_str().unwrap(),
            "--until",
            until,
            "--format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let document: serde_json::Value = serde_json::from_slice(&output).expect("valid JSON");
    document["range"]["commits"].clone()
}

#[test]
fn an_annotated_tag_bounds_history_and_seam_like_the_commit_it_names() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let root = directory.path();
    let mut planter = Planter::initialise(root).expect("initialise a repository");
    for planned in &PAIR_HISTORY[..2] {
        planter.commit(planned).expect("commit");
    }
    git_in(root, &["tag", "-a", "v1", "-m", "release"]);
    for planned in &PAIR_HISTORY[2..] {
        planter.commit(planned).expect("commit");
    }
    std::fs::write(root.join("codehelion.toml"), LEDGER).expect("writing the ledger");

    assert_eq!(history_commits(root, "v1"), 2);
    assert_eq!(
        history_commits(root, "v1"),
        history_commits(root, "v1^{commit}")
    );
    cmd()
        .args([
            "seam",
            "--path",
            root.to_str().unwrap(),
            "--until",
            "v1",
            "--no-record",
        ])
        .assert()
        .success();
}

#[test]
fn a_shallow_clone_is_read_up_to_its_depth_with_a_warning() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let origin = directory.path().join("origin");
    std::fs::create_dir_all(&origin).expect("origin directory");
    planted(&origin);
    let source = format!("file://{}", origin.display());
    git_in(
        directory.path(),
        &["clone", "--quiet", "--depth", "2", &source, "shallow"],
    );
    let shallow = directory.path().join("shallow");

    let output = cmd()
        .args([
            "history",
            "--path",
            shallow.to_str().unwrap(),
            "--format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let document: serde_json::Value = serde_json::from_slice(&output).expect("valid JSON");
    assert_eq!(document["shallow"], true);
    assert_eq!(document["range"]["commits"], 1);

    cmd()
        .args(["seam", "--path", shallow.to_str().unwrap(), "--no-record"])
        .assert()
        .success()
        .stderr(predicate::str::contains("this is a shallow clone"));
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

/// The database `seam` records into when nothing names another one.
fn default_database(root: &Path) -> std::path::PathBuf {
    root.join(".codehelion").join("audit.db")
}

/// Enough of a database's state to tell whether anything was written to it.
///
/// `None` for a database that is not there, which is the state this
/// repository's own checkout is usually in on a machine that has never scanned
/// it. Where one does exist it is left over from somebody's scan, so the test
/// compares it with itself rather than requiring its absence.
fn recorded_state(path: &Path) -> Option<(u64, std::time::SystemTime)> {
    let metadata = std::fs::metadata(path).ok()?;
    Some((metadata.len(), metadata.modified().ok()?))
}

/// An evaluation is a measurement, and a measurement nobody keeps cannot be
/// compared with the next one, so the counts that were printed are recorded
/// where the next run can find them.
#[test]
fn seam_records_the_evaluation_it_prints() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let root = directory.path();
    planted(root);
    assert!(!default_database(root).exists());

    cmd()
        .args(["seam", "--path", root.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("pair  asymmetric 2, breached 1"));

    assert!(default_database(root).is_file());
}

/// The report shows the recorded seam run beside the scan it belongs to, and
/// says what moved between the two generations of it.
#[test]
fn report_shows_the_seam_section_for_a_recorded_run() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let root = directory.path();
    let mut planter = planted_and_still_open(root);

    cmd()
        .args(["scan", root.to_str().unwrap()])
        .assert()
        .success();
    cmd()
        .args(["seam", "--path", root.to_str().unwrap()])
        .assert()
        .success();

    // One more one-sided change, so the second generation of the measurement
    // has something to differ by.
    planter
        .commit(&PlannedCommit {
            subject: "feat: teach the left side one more rule",
            writes: &[("left/a.txt", "one\ntwo\nthree\n")],
            removes: &[],
        })
        .expect("planting one more commit");
    cmd()
        .args(["seam", "--path", root.to_str().unwrap()])
        .assert()
        .success();

    cmd()
        .args(["report", "--path", root.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "seams: pair 3 asymmetric changes, 1 breach",
        ))
        .stdout(predicate::str::contains(
            "since seam run 1: pair +1 asymmetric change",
        ));

    let output = cmd()
        .args([
            "report",
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
    let seam = &document["seam"];
    assert_eq!(seam["seam_run_id"], 2);
    assert_eq!(seam["since_seam_run_id"], 1);
    assert_eq!(seam["seams"][0]["id"], "pair");
    assert_eq!(seam["seams"][0]["asymmetric_changes"], 3);
    assert_eq!(seam["seams"][0]["breaches"], 1);
    assert_eq!(seam["seams"][0]["asymmetric_changes_since"], 1);
    // Nothing was breached in between, and a count that stood still is a delta
    // of zero rather than no delta at all.
    assert_eq!(seam["seams"][0]["breaches_since"], 0);
}

/// Three ways an invocation records nothing, each for its own reason: a
/// proposal is not a measurement, a deliberately truncated range is not a
/// generation of the current one, and `--no-record` is the explicit opt-out.
#[test]
fn suggest_until_and_no_record_leave_the_database_untouched() {
    for arguments in [
        vec!["--suggest"],
        vec!["--until", "HEAD"],
        vec!["--no-record"],
    ] {
        let directory = tempfile::tempdir().expect("temporary directory");
        let root = directory.path();
        planted(root);

        let mut command = cmd();
        command.args(["seam", "--path", root.to_str().unwrap()]);
        command.args(&arguments);
        command.assert().success();

        assert!(
            !root.join(".codehelion").exists(),
            "`seam {}` recorded a run",
            arguments.join(" ")
        );
    }
}

/// An explicitly named database is the one written to, and the default one is
/// then left alone.
#[test]
fn a_named_database_is_the_one_the_evaluation_is_recorded_in() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let root = directory.path();
    planted(root);
    let elsewhere = directory.path().join("elsewhere").join("audit.db");

    cmd()
        .args([
            "seam",
            "--path",
            root.to_str().unwrap(),
            "--db",
            elsewhere.to_str().unwrap(),
        ])
        .assert()
        .success();

    assert!(elsewhere.is_file());
    assert!(!default_database(root).exists());
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
    // A run over a range somebody cut short is not a generation of the current
    // measurement, so this reads the repository and writes nothing into it.
    let before = recorded_state(&default_database(root));
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
    assert_eq!(
        recorded_state(&default_database(root)),
        before,
        "reading this repository's history recorded something into it"
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

/// A function long enough to be reported as a clone when it is written twice.
const DUPLICATED_RS: &str = "pub fn checksum_block(seed: u64, data: &[u64]) -> u64 {
    let mut acc = seed;
    for (index, value) in data.iter().enumerate() {
        acc = acc.wrapping_mul(31).wrapping_add(*value ^ index as u64);
        if acc % 7 == 0 {
            acc = acc.rotate_left(3);
        }
    }
    acc
}
";

/// A repository whose seam holds the same function on both sides, so a scan of
/// it has findings inside the seam.
fn planted_with_duplication(root: &Path) -> Planter {
    let mut planter = planted_and_still_open(root);
    planter
        .commit(&PlannedCommit {
            subject: "feat: write the rule in both languages",
            writes: &[
                ("left/rule.rs", DUPLICATED_RS),
                ("right/rule.rs", DUPLICATED_RS),
            ],
            removes: &[],
        })
        .expect("planting the duplicated rule");
    planter
}

/// Run a command under `root` and parse its JSON standard output.
fn json_of(root: &Path, args: &[&str]) -> serde_json::Value {
    let output = cmd()
        .args(args)
        .arg("--path")
        .arg(root)
        .args(["--format", "json"])
        .output()
        .expect("run the command");
    assert!(output.status.success(), "{args:?}: {output:?}");
    serde_json::from_slice(&output.stdout).expect("valid JSON")
}

/// Run `scan` of `root` with extra arguments, as JSON.
fn scan_of(root: &Path, extra: &[&str]) -> serde_json::Value {
    let output = cmd()
        .arg("scan")
        .arg(root)
        .args(extra)
        .args(["--format", "json"])
        .output()
        .expect("run scan");
    assert!(output.status.success(), "{output:?}");
    serde_json::from_slice(&output.stdout).expect("valid JSON")
}

fn open_audit_store(root: &Path) -> codehelion_store::Store {
    codehelion_store::Store::open(&default_database(root)).expect("open the audit database")
}

/// The seam figures a report replays belong to the scan it replays: an earlier
/// run is shown the seam run taken against it, not one recorded after a later
/// scan superseded it.
#[test]
fn a_replayed_run_shows_the_seam_run_taken_against_it() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let root = directory.path();
    let mut planter = planted_with_duplication(root);

    let first = scan_of(root, &[]);
    cmd().args(["seam", "--path"]).arg(root).assert().success();
    planter
        .commit(&PlannedCommit {
            subject: "feat: teach the left side one more rule",
            writes: &[("left/a.txt", "one\ntwo\nthree\n")],
            removes: &[],
        })
        .expect("planting one more commit");
    std::fs::write(root.join("left/extra.rs"), "pub fn extra() -> u8 { 1 }\n")
        .expect("change the tree");
    let second = scan_of(root, &[]);
    assert_ne!(first["run"]["run_id"], second["run"]["run_id"]);
    cmd().args(["seam", "--path"]).arg(root).assert().success();

    let first_id = first["run"]["run_id"].to_string();
    let replayed = json_of(root, &["report", "--run", &first_id]);
    assert_eq!(replayed["seam"]["seam_run_id"], 1, "{replayed}");
    let latest = json_of(root, &["report"]);
    assert_eq!(latest["seam"]["seam_run_id"], 2, "{latest}");
    assert_eq!(latest["seam"]["since_seam_run_id"], 1, "{latest}");
}

/// A findings delta is a statement about the code only when both generations
/// counted findings from the same kind of scan; across a change of mode it is
/// left out while the history deltas, which no scan decides, remain.
#[test]
fn a_findings_delta_across_a_change_of_scan_mode_is_left_out() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let root = directory.path();
    planted_with_duplication(root);

    scan_of(root, &["--mode", "fast"]);
    cmd().args(["seam", "--path"]).arg(root).assert().success();
    scan_of(root, &["--mode", "structural"]);
    cmd().args(["seam", "--path"]).arg(root).assert().success();

    let report = json_of(root, &["report"]);
    let seam = &report["seam"]["seams"][0];
    assert_eq!(report["seam"]["since_seam_run_id"], 1, "{report}");
    assert_eq!(seam["asymmetric_changes_since"], 0, "{report}");
    assert!(seam["findings_since"].is_null(), "{report}");
}

/// A seam run counts the findings of every partition of the scan it maps, not
/// of whichever partition happens to be newest.
#[test]
fn seam_findings_cover_every_partition_of_the_mapped_scan() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let root = directory.path();
    planted_with_duplication(root);
    let fast = scan_of(root, &["--mode", "fast"]);
    let structural = scan_of(root, &["--mode", "structural"]);
    let fast_id = fast["run"]["run_id"].as_i64().expect("fast run");
    let structural_id = structural["run"]["run_id"]
        .as_i64()
        .expect("structural run");
    // Two partitions of one invocation are two runs sharing a start time.
    rusqlite::Connection::open(default_database(root))
        .expect("open the audit database")
        .execute(
            "UPDATE scan_run SET started_at = (SELECT started_at FROM scan_run WHERE id = ?1)
             WHERE id = ?2",
            [fast_id, structural_id],
        )
        .expect("join the runs into one invocation");
    let store = open_audit_store(root);
    let expected: usize = [fast_id, structural_id]
        .iter()
        .map(|&run_id| {
            store
                .run_finding_locations(run_id)
                .expect("locations")
                .len()
        })
        .sum();
    let single = store
        .run_finding_locations(fast_id)
        .expect("locations")
        .len()
        .max(
            store
                .run_finding_locations(structural_id)
                .expect("locations")
                .len(),
        );
    assert!(expected > single, "both partitions hold findings");
    drop(store);

    cmd().args(["seam", "--path"]).arg(root).assert().success();

    let store = open_audit_store(root);
    let key = codehelion_store::path_key(&root.canonicalize().expect("canonical root"));
    let recorded = store
        .latest_seam_run(&key)
        .expect("read the seam run")
        .expect("a recorded seam run");
    assert_eq!(
        recorded.run.entries[0].findings,
        i64::try_from(expected).expect("count")
    );
    assert!(
        [fast_id, structural_id].contains(&recorded.run.scan_run_id.expect("a mapped scan")),
        "the seam run names the invocation it counted"
    );
}

/// Recording a seam run writes the audit database, so it waits its turn behind
/// the lock every other writer takes; a held lock leaves the database as it was.
#[test]
fn seam_recording_takes_the_database_lock() {
    use fs2::FileExt;

    let directory = tempfile::tempdir().expect("temporary directory");
    let root = directory.path();
    planted(root);
    scan_of(root, &[]);
    let database = default_database(root);
    let before = recorded_state(&database);
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(root.join(".codehelion/audit.db.lock"))
        .expect("the scan created its database lock");
    FileExt::try_lock_exclusive(&lock).expect("the test owns the lock");

    cmd()
        .args(["seam", "--path"])
        .arg(root)
        .assert()
        .success()
        .stderr(predicate::str::contains("this evaluation was not recorded"));

    assert_eq!(recorded_state(&database), before);
}

/// Every spelling of one file under the root names the same seam, and a path
/// that leaves the root is refused instead of reported as in no seam.
#[test]
fn the_path_lookup_reads_every_spelling_of_one_file_alike() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let root = directory.path();
    std::fs::write(root.join("codehelion.toml"), LEDGER).expect("writing the ledger");
    let absolute = root.join("left").join("a.txt");

    for spelling in [
        "left/a.txt".to_owned(),
        "./left/a.txt".to_owned(),
        "left/../left/./a.txt".to_owned(),
        absolute.to_str().unwrap().to_owned(),
    ] {
        cmd()
            .args([
                "guard",
                "--path",
                root.to_str().unwrap(),
                "--paths",
                &spelling,
            ])
            .assert()
            .success()
            .stdout(predicate::str::contains("pair via left/**"))
            .stdout(predicate::str::contains("in no seam").not());
    }

    let outside = directory.path().parent().unwrap().join("elsewhere.txt");
    for spelling in ["../elsewhere.txt", outside.to_str().unwrap()] {
        cmd()
            .args([
                "guard",
                "--path",
                root.to_str().unwrap(),
                "--paths",
                spelling,
            ])
            .assert()
            .failure()
            .stderr(predicate::str::contains("is outside the repository"));
    }
}
