//! What this crate must say about a repository whose contents are known.
//!
//! Every one of these reads a repository planted from a table, so the right
//! answer is settled before anything is read. The expectations are written out
//! rather than computed, including the commit ids: an expectation derived from
//! the code under test agrees with it by construction, and would go on agreeing
//! after the reading changed.
//!
//! What is being pinned is not only that the numbers are right today. A seam
//! report compares one generation of a repository against the next, so a
//! reading that shifts between two runs — with the walk order, with a rename
//! threshold, with which side of a merge was visited — makes every comparison
//! built on it meaningless. That is why the order, the merge rule and the
//! absence of rename detection each have a test of their own.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::path::Path;

use codehelion_fixtures::git::{self, COMMIT_INTERVAL, FIRST_COMMIT_TIME, PlannedCommit, Planter};
use codehelion_history::{
    CommitKind, CommitRecord, History, HistoryError, HistoryRequest, RepoPath, changes_since, read,
    working_tree_changes,
};
use tempfile::TempDir;

/// A history across four directories, mixing every kind of subject a reader has
/// to classify, and moving a file in and out of the tree.
const GOLDEN: [PlannedCommit; 8] = [
    PlannedCommit::writing(
        "feat: plant the workspace",
        &[
            ("Cargo.toml", "[workspace]\nmembers = [\"crates/*\"]\n"),
            ("crates/ledger/src/lib.rs", "pub fn total() -> u32 { 0 }\n"),
            ("README.md", "# planted\n"),
        ],
    ),
    PlannedCommit::writing(
        "feat(report): add the second crate",
        &[(
            "crates/report/src/lib.rs",
            "pub fn render() -> String { String::new() }\n",
        )],
    ),
    PlannedCommit::writing(
        "fix(ledger): count the last entry",
        &[("crates/ledger/src/lib.rs", "pub fn total() -> u32 { 1 }\n")],
    ),
    PlannedCommit::writing(
        "docs: describe both crates",
        &[("docs/overview.md", "the ledger and the report\n")],
    ),
    PlannedCommit::writing(
        "Add a helper without declaring what kind of change it is",
        &[("crates/report/src/helper.rs", "pub fn helper() {}\n")],
    ),
    PlannedCommit::writing(
        "fix(report): follow the ledger",
        &[
            (
                "crates/report/src/lib.rs",
                "pub fn render() -> String { \"1\".to_string() }\n",
            ),
            ("crates/ledger/src/lib.rs", "pub fn total() -> u32 { 2 }\n"),
        ],
    ),
    PlannedCommit::removing(
        "refactor: fold the helper away",
        &["crates/report/src/helper.rs"],
    ),
    PlannedCommit::writing(
        "feat(docs): add a second page",
        &[("docs/detail.md", "detail\n")],
    ),
];

/// One commit as it must come back: id, committer time, kind, subject, paths.
type Expected = (
    &'static str,
    i64,
    CommitKind,
    &'static str,
    &'static [&'static str],
);

/// What [`GOLDEN`] reads back as.
///
/// The ids are the ones the pinned identity, the pinned clock and these trees
/// hash to. They are properties of the plan above, not of the machine that ran
/// it, and a change to either one has to be made here deliberately.
const GOLDEN_RECORDS: [Expected; 8] = [
    (
        "a97d6eee8e059644710efcda3aae37747a9f97d6",
        1_700_000_000,
        CommitKind::Feat,
        "feat: plant the workspace",
        &["Cargo.toml", "README.md", "crates/ledger/src/lib.rs"],
    ),
    (
        "c111907654f4edea955b88b85db7e24027d60287",
        1_700_000_060,
        CommitKind::Feat,
        "feat(report): add the second crate",
        &["crates/report/src/lib.rs"],
    ),
    (
        "c797391a322eac5abc430fb8bb7cf9381ec66ff2",
        1_700_000_120,
        CommitKind::Fix,
        "fix(ledger): count the last entry",
        &["crates/ledger/src/lib.rs"],
    ),
    (
        "1eedcf7467224c02b1c1c59f6e8975677ac9934f",
        1_700_000_180,
        // A prefix that is neither `fix` nor `feat` is neither, rather than
        // being guessed at from the words after it.
        CommitKind::Other,
        "docs: describe both crates",
        &["docs/overview.md"],
    ),
    (
        "02350dea74a42d3be35fdcb40d0d153fcae518f1",
        1_700_000_240,
        CommitKind::Other,
        "Add a helper without declaring what kind of change it is",
        &["crates/report/src/helper.rs"],
    ),
    (
        "98c898481f6c268bb075263525069e2d53279793",
        1_700_000_300,
        CommitKind::Fix,
        "fix(report): follow the ledger",
        &["crates/ledger/src/lib.rs", "crates/report/src/lib.rs"],
    ),
    (
        "c220cc51c97e4a1ded2d5996601e8ac34e4e656a",
        1_700_000_360,
        CommitKind::Other,
        "refactor: fold the helper away",
        // A deletion is a change to the path that was deleted.
        &["crates/report/src/helper.rs"],
    ),
    (
        "fdd4e81ffbb10f55c6bc8ee35979b7d9f988ee8c",
        1_700_000_420,
        CommitKind::Feat,
        "feat(docs): add a second page",
        &["docs/detail.md"],
    ),
];

/// Plant a repository in a directory of its own and hand back both.
fn planted(commits: &[PlannedCommit]) -> TempDir {
    let repository = tempfile::tempdir().expect("a directory to plant in");
    git::plant(repository.path(), commits).expect("plant the repository");
    repository
}

/// Read everything a repository holds.
fn read_all(root: &Path) -> History {
    read(root, &HistoryRequest::default()).expect("read the planted repository")
}

/// One record in the shape the expectations are written in.
fn shaped(record: &CommitRecord) -> (&str, i64, CommitKind, &str, Vec<&str>) {
    (
        record.id.as_str(),
        record.committer_time,
        record.kind,
        record.subject.as_str(),
        record.paths.iter().map(RepoPath::as_str).collect(),
    )
}

/// The subject of every commit read, in the order they came back.
fn subjects(history: &History) -> Vec<&str> {
    history
        .commits()
        .iter()
        .map(|record| record.subject.as_str())
        .collect()
}

/// The paths of the commit whose subject is `subject`.
fn paths_of<'a>(history: &'a History, subject: &str) -> Vec<&'a str> {
    let record = history
        .commits()
        .iter()
        .find(|record| record.subject == subject)
        .unwrap_or_else(|| panic!("no commit named {subject:?} in {:?}", subjects(history)));
    record.paths.iter().map(RepoPath::as_str).collect()
}

/// The whole reading, against a table written by hand.
///
/// A path in a record names a file: it is what a ledger glob is matched
/// against, what a report prints, and what a commit's size is counted in.
#[test]
fn a_planted_history_reads_back_exactly_as_it_was_planted() {
    let repository = planted(&GOLDEN);

    let history = read_all(repository.path());

    let actual: Vec<_> = history.commits().iter().map(shaped).collect();
    let expected: Vec<_> = GOLDEN_RECORDS
        .iter()
        .map(|(id, time, kind, subject, paths)| (*id, *time, *kind, *subject, paths.to_vec()))
        .collect();
    assert_eq!(actual, expected);
    assert!(!history.is_shallow(), "a planted repository is complete");
    assert_eq!(history.range().commits, GOLDEN.len());
}

/// The property the rest of the feature rests on: the same repository read
/// twice is the same reading, down to the bytes it serialises to. A count that
/// moves between two runs cannot say anything about the two generations it was
/// supposed to be comparing.
#[test]
fn reading_the_same_repository_twice_gives_the_same_bytes() {
    let repository = planted(&GOLDEN);

    let first = read_all(repository.path());
    let second = read_all(repository.path());

    assert_eq!(first, second);
    let left = serde_json::to_vec(first.commits()).expect("records serialise");
    let right = serde_json::to_vec(second.commits()).expect("records serialise");
    assert_eq!(left, right);
    assert_eq!(first.range(), second.range());
}

/// Ordered by `(committer time, commit id)` and by nothing else. Git walks
/// newest first along the graph; this order is a property of the commits, so
/// four commits sharing one second come back in the same sequence however they
/// were reached.
#[test]
fn commits_come_back_ordered_by_time_then_id_rather_than_in_the_walks_order() {
    let repository = tempfile::tempdir().unwrap();
    let mut planter = Planter::initialise(repository.path()).unwrap();
    planter
        .commit(&PlannedCommit::writing("feat: first", &[("a.txt", "a\n")]))
        .unwrap();
    // Everything after this shares one second, so only the id can decide.
    planter.hold_clock();
    for planned in [
        PlannedCommit::writing("feat: second", &[("b.txt", "x\n")]),
        PlannedCommit::writing("feat: third", &[("c.txt", "x\n")]),
        PlannedCommit::writing("feat: fourth", &[("d.txt", "x\n")]),
    ] {
        planter.commit(&planned).unwrap();
    }
    let planting_order = planter.ids().to_vec();

    let history = read_all(repository.path());

    let read_order: Vec<&str> = history
        .commits()
        .iter()
        .map(|record| record.id.as_str())
        .collect();
    assert_eq!(
        read_order,
        [
            "ecbc964389e4b8cb449bfbafd518622306a66a8c",
            "0c204153b4af1f21a8f62f4f47d871823caaaf25",
            "22c91f4f5bba50b1211669aa82a4cee3636e93a1",
            "c2ffc74db4dd189d43b442ae869d6ba9ea899b12",
        ]
    );
    assert!(
        history
            .commits()
            .windows(2)
            .all(|pair| (pair[0].committer_time, &pair[0].id)
                <= (pair[1].committer_time, &pair[1].id)),
        "the reading is not ascending in (committer time, commit id)"
    );
    // Git reaches these newest first, so its walk reversed is the order they
    // were planted in. The reading is neither.
    assert_ne!(read_order, planting_order);
    let mut walk_order = planting_order;
    walk_order.reverse();
    assert_ne!(read_order, walk_order);
}

/// The first commit has no parent to be compared against, so everything in it
/// is new. Answering "nothing changed" there would leave a hole in the
/// co-change counts exactly where a project's original structure is.
#[test]
fn a_root_commit_reports_every_path_in_it() {
    let repository = planted(&[PlannedCommit::writing(
        "feat: plant everything at once",
        &[
            ("README.md", "# planted\n"),
            ("crates/ledger/src/lib.rs", "pub fn total() {}\n"),
            ("docs/overview.md", "overview\n"),
        ],
    )]);

    let history = read_all(repository.path());

    assert_eq!(history.commits().len(), 1);
    for planted in ["README.md", "crates/ledger/src/lib.rs", "docs/overview.md"] {
        assert!(
            paths_of(&history, "feat: plant everything at once").contains(&planted),
            "the root commit does not report {planted}"
        );
    }
}

/// A move is read as the two changes it is made of. Git can be asked to guess
/// that one deletion and one addition were the same file, but the guess has a
/// similarity threshold behind it, and a number that moves with a threshold
/// nobody chose is not evidence.
#[test]
fn a_rename_is_read_as_a_deletion_and_an_addition() {
    const MOVED: &str = "pub fn shared() -> u32 { 7 }\n";
    let repository = planted(&[
        PlannedCommit::writing(
            "feat: plant the file",
            &[("crates/ledger/src/old.rs", MOVED)],
        ),
        PlannedCommit {
            subject: "refactor: move the file without touching it",
            // Byte-identical contents, which is the case rename detection is
            // surest about.
            writes: &[("crates/ledger/src/new.rs", MOVED)],
            removes: &["crates/ledger/src/old.rs"],
        },
    ]);

    let history = read_all(repository.path());

    let paths = paths_of(&history, "refactor: move the file without touching it");
    assert!(
        paths.contains(&"crates/ledger/src/old.rs"),
        "the path the file left is missing: {paths:?}"
    );
    assert!(
        paths.contains(&"crates/ledger/src/new.rs"),
        "the path the file arrived at is missing: {paths:?}"
    );
}

/// The ceiling reads the newest commits, because those are the ones a report is
/// about, and the range says which ones were read so that two runs can be
/// compared honestly.
#[test]
fn a_limit_reads_the_newest_commits_and_the_range_says_which() {
    let repository = planted(&GOLDEN);

    let history = read(
        repository.path(),
        &HistoryRequest {
            limit: 3,
            until: None,
        },
    )
    .unwrap();

    assert_eq!(
        subjects(&history),
        [
            "fix(report): follow the ledger",
            "refactor: fold the helper away",
            "feat(docs): add a second page",
        ]
    );
    let range = history.range();
    assert_eq!(range.commits, 3);
    assert_eq!(
        range.first.unwrap().as_str(),
        "98c898481f6c268bb075263525069e2d53279793"
    );
    assert_eq!(
        range.last.unwrap().as_str(),
        "fdd4e81ffbb10f55c6bc8ee35979b7d9f988ee8c"
    );
}

/// Naming where the walk starts is what makes one generation's numbers
/// comparable with another's: the range is fixed by the operator rather than by
/// how much the repository has grown since.
#[test]
fn an_until_starts_the_walk_where_it_names_and_refuses_a_name_that_is_nothing() {
    let repository = tempfile::tempdir().unwrap();
    let mut planter = Planter::initialise(repository.path()).unwrap();
    for planned in &GOLDEN[..4] {
        planter.commit(planned).unwrap();
    }
    planter.tag("release").unwrap();
    for planned in &GOLDEN[4..] {
        planter.commit(planned).unwrap();
    }

    let history = read(
        repository.path(),
        &HistoryRequest {
            limit: 100,
            until: Some("release".to_string()),
        },
    )
    .unwrap();

    assert_eq!(
        subjects(&history),
        [
            "feat: plant the workspace",
            "feat(report): add the second crate",
            "fix(ledger): count the last entry",
            "docs: describe both crates",
        ]
    );
    // The same repository, read to its head, holds all eight.
    assert_eq!(read_all(repository.path()).commits().len(), 8);

    let error = read(
        repository.path(),
        &HistoryRequest {
            limit: 100,
            until: Some("no-such-revision".to_string()),
        },
    )
    .unwrap_err();
    let HistoryError::UnknownRevision { revision, .. } = &error else {
        panic!("a revision naming nothing is not reported as such: {error:?}");
    };
    assert_eq!(revision, "no-such-revision");
}

/// A merge is followed along its first parent alone. What a topic branch did
/// on its way is not what the trunk received, and counting both would make a
/// history's numbers depend on whether the branch was squashed.
#[test]
fn a_merge_is_followed_by_first_parent_only() {
    let repository = tempfile::tempdir().unwrap();
    let mut planter = Planter::initialise(repository.path()).unwrap();
    planter
        .commit(&PlannedCommit::writing(
            "feat: plant the trunk",
            &[("crates/ledger/src/lib.rs", "pub fn total() -> u32 { 0 }\n")],
        ))
        .unwrap();
    planter.branch("side").unwrap();
    planter
        .commit(&PlannedCommit::writing(
            "feat: change only on the side branch",
            &[("crates/report/src/lib.rs", "pub fn render() {}\n")],
        ))
        .unwrap();
    planter.switch("main").unwrap();
    planter
        .commit(&PlannedCommit::writing(
            "fix: land on the trunk",
            &[("crates/ledger/src/lib.rs", "pub fn total() -> u32 { 1 }\n")],
        ))
        .unwrap();
    planter
        .merge("side", "chore: merge the side branch")
        .unwrap();

    let history = read_all(repository.path());

    assert_eq!(
        subjects(&history),
        [
            "feat: plant the trunk",
            "fix: land on the trunk",
            "chore: merge the side branch",
        ]
    );
}

/// What `guard` compares against a ledger before anything is committed: both
/// halves of the working tree, and the files git has not been told about yet.
/// Adding a file to one member of a seam and not to the other is precisely the
/// change worth reporting, so an untracked file counts — and an ignored one
/// does not, because nobody chose to write it.
#[test]
fn the_working_tree_reports_staged_unstaged_and_untracked_but_not_ignored() {
    let repository = tempfile::tempdir().unwrap();
    let mut planter = Planter::initialise(repository.path()).unwrap();
    planter
        .commit(&PlannedCommit::writing(
            "feat: plant the tree",
            &[
                (".gitignore", "build/\n"),
                ("src/staged.rs", "pub fn one() {}\n"),
                ("src/unstaged.rs", "pub fn two() {}\n"),
            ],
        ))
        .unwrap();
    // Written into the working tree directly, which is the state `guard` reads:
    // one change told to git, one not, one file git has never seen, and one git
    // was told to ignore.
    let write = |path: &str, contents: &str| {
        let target = repository.path().join(path);
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        std::fs::write(target, contents).unwrap();
    };
    write("src/staged.rs", "pub fn one() -> u8 { 1 }\n");
    planter.stage("src/staged.rs").unwrap();
    write("src/unstaged.rs", "pub fn two() -> u8 { 2 }\n");
    write("src/untracked.rs", "pub fn three() {}\n");
    write("build/artifact.o", "not source\n");

    let changed = working_tree_changes(repository.path()).unwrap();

    let changed: Vec<&str> = changed.iter().map(RepoPath::as_str).collect();
    assert_eq!(
        changed,
        ["src/staged.rs", "src/unstaged.rs", "src/untracked.rs"]
    );
}

/// The same question asked of two revisions rather than of the working tree:
/// every path that differs between them, once each, however many commits
/// touched it on the way.
#[test]
fn changes_since_a_revision_are_the_union_of_what_moved_after_it() {
    let repository = tempfile::tempdir().unwrap();
    let mut planter = Planter::initialise(repository.path()).unwrap();
    planter
        .commit(&PlannedCommit::writing(
            "feat: plant the tree",
            &[
                ("README.md", "# planted\n"),
                ("crates/ledger/src/lib.rs", "pub fn total() -> u32 { 0 }\n"),
            ],
        ))
        .unwrap();
    planter.tag("release").unwrap();
    // Touched twice after the tag, and reported once.
    planter
        .commit(&PlannedCommit::writing(
            "fix(ledger): count the last entry",
            &[("crates/ledger/src/lib.rs", "pub fn total() -> u32 { 1 }\n")],
        ))
        .unwrap();
    planter
        .commit(&PlannedCommit::writing(
            "fix(ledger): count the first entry too",
            &[("crates/ledger/src/lib.rs", "pub fn total() -> u32 { 2 }\n")],
        ))
        .unwrap();
    planter
        .commit(&PlannedCommit {
            subject: "docs: move the overview out of the readme",
            writes: &[("docs/overview.md", "overview\n")],
            removes: &["README.md"],
        })
        .unwrap();

    let changed = changes_since(repository.path(), "release").unwrap();

    let changed: Vec<&str> = changed.iter().map(RepoPath::as_str).collect();
    assert_eq!(
        changed,
        ["README.md", "crates/ledger/src/lib.rs", "docs/overview.md",]
    );
}

/// A directory that holds no repository is told apart from a repository that
/// holds no commits, because the two are fixed by different actions.
#[test]
fn a_directory_that_is_not_a_repository_says_so() {
    let empty = tempfile::tempdir().unwrap();
    std::fs::write(empty.path().join("Cargo.toml"), "[package]\n").unwrap();

    let error = read(empty.path(), &HistoryRequest::default()).unwrap_err();

    let HistoryError::NotARepository { path, .. } = &error else {
        panic!("a directory with no repository in it is not reported as such: {error:?}");
    };
    assert_eq!(path, empty.path());
}

/// The clock the fixtures pin is the clock the records carry. If planting ever
/// stopped fixing the timestamps, the golden ids above would go on matching
/// nothing in particular, and this says so directly.
#[test]
fn the_fixtures_clock_is_the_one_the_records_report() {
    let repository = planted(&GOLDEN);

    let history = read_all(repository.path());

    let times: Vec<i64> = history
        .commits()
        .iter()
        .map(|record| record.committer_time)
        .collect();
    let expected: Vec<i64> = (0..i64::try_from(GOLDEN.len()).unwrap())
        .map(|step| FIRST_COMMIT_TIME + step * COMMIT_INTERVAL)
        .collect();
    assert_eq!(times, expected);
}
