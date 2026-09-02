//! The seam analysis, exercised against hand-built histories.
//!
//! No repository is created anywhere here. Every input is a
//! [`History`] assembled from records written in the test, which is what the
//! crate's boundary is for: the numbers a report prints are decided by the
//! rules in `codehelion-seam`, and a test that had to commit files in order to
//! ask about a breach window would be testing git.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use codehelion_history::{CommitId, CommitKind, CommitRecord, History, RepoPath};
use codehelion_seam::{Ledger, SeamEntry, SeamError, Settings, evaluate, guard, look_up, suggest};

/// A commit id from a short name, padded to the width a real one has.
///
/// `codehelion-history` keeps the id's constructor to itself so that nothing
/// invents one outside the git reader; a test reads one the same way a stored
/// report does. Every name here is the same length, so padding leaves their
/// order alone — and the order matters, since it breaks ties in the history's
/// sort.
fn id(name: &str) -> CommitId {
    serde_json::from_value(serde_json::Value::String(format!("{name:0>40}")))
        .expect("a commit id is a string")
}

/// One commit, with its kind read from its subject.
///
/// The kind is derived rather than passed in, exactly as the git reader
/// derives it: a test that could label a `feat:` subject as a fix would be
/// asserting about a history no repository can produce.
fn commit(name: &str, time: i64, subject: &str, paths: &[&str]) -> CommitRecord {
    CommitRecord {
        id: id(name),
        committer_time: time,
        kind: CommitKind::from_subject(subject),
        subject: subject.to_string(),
        paths: paths.iter().map(|path| RepoPath::new(*path)).collect(),
    }
}

/// A history from records in the order they are written, timed by position.
fn history(commits: &[(&str, &str, &[&str])]) -> History {
    let records = commits
        .iter()
        .enumerate()
        .map(|(index, (name, subject, paths))| {
            commit(name, i64::try_from(index).unwrap(), subject, paths)
        })
        .collect();
    History::new(records, false)
}

/// A ledger of one seam over the two frontend directories.
fn two_member_ledger() -> Ledger {
    Ledger::new(vec![SeamEntry {
        id: "frontends".to_string(),
        members: vec!["crates/a/**".to_string(), "crates/b/**".to_string()],
        note: Some("the same rules implemented twice".to_string()),
    }])
    .expect("a well-formed ledger")
}

/// Settings differing from the defaults only where a test says so.
fn settings(breach_window: usize) -> Settings {
    Settings {
        breach_window,
        ..Settings::default()
    }
}

/// The paths of a change, as `guard` and `look_up` take them.
fn paths(paths: &[&str]) -> Vec<RepoPath> {
    paths.iter().map(|path| RepoPath::new(*path)).collect()
}

#[test]
fn a_path_belongs_to_every_member_whose_glob_matches_it_and_to_no_other() {
    let ledger = Ledger::new(vec![
        SeamEntry {
            id: "frontends".to_string(),
            members: vec!["crates/a/**".to_string(), "crates/b/**".to_string()],
            note: None,
        },
        SeamEntry {
            id: "code-and-docs".to_string(),
            members: vec!["crates/**".to_string(), "docs/**".to_string()],
            note: None,
        },
    ])
    .unwrap();

    let found = look_up(
        &ledger,
        &paths(&["crates/a/src/lib.rs", "docs/en/cli.md", "README.md"]),
    );
    assert_eq!(found.len(), 3);

    // One member of the first seam, and a member of the second at the same
    // time: membership is not exclusive, and a path under a broad glob is
    // still under the narrow one that also covers it.
    let placements = &found[0].seams;
    assert_eq!(placements.len(), 2);
    assert_eq!(placements[0].seam, "frontends");
    assert_eq!(placements[0].member, "crates/a/**");
    assert_eq!(placements[1].seam, "code-and-docs");
    assert_eq!(placements[1].member, "crates/**");

    // Matching the other side of the second seam and neither side of the
    // first.
    assert_eq!(found[1].seams.len(), 1);
    assert_eq!(found[1].seams[0].member, "docs/**");

    // A path in no seam is still answered, with nothing.
    assert!(found[2].seams.is_empty());
}

#[test]
fn a_commit_touching_all_or_none_of_the_members_is_not_an_asymmetric_change() {
    let history = history(&[
        (
            "c01",
            "feat: both sides",
            &["crates/a/x.rs", "crates/b/x.rs"],
        ),
        ("c02", "docs: neither side", &["README.md"]),
    ]);
    let report = evaluate(&two_member_ledger(), &history, &settings(20));
    assert_eq!(report.seams.len(), 1);
    assert_eq!(report.seams[0].asymmetric_changes, 0);
    assert!(report.seams[0].changes.is_empty());
    assert_eq!(report.seams[0].breaches, 0);
    assert_eq!(report.seams[0].last_breach, None);
    // The seam is reported even with nothing to say about it.
    assert_eq!(report.seams[0].id, "frontends");
    assert_eq!(
        report.seams[0].note.as_deref(),
        Some("the same rules implemented twice")
    );
}

#[test]
fn a_commit_touching_part_of_a_seam_partitions_its_members() {
    let history = history(&[("c01", "feat: one side", &["crates/a/x.rs"])]);
    let report = evaluate(&two_member_ledger(), &history, &settings(20));
    let seam = &report.seams[0];
    assert_eq!(seam.asymmetric_changes, 1);
    assert_eq!(seam.changes[0].commit, id("c01"));
    assert_eq!(seam.changes[0].committer_time, 0);
    assert_eq!(seam.changes[0].subject, "feat: one side");
    assert_eq!(seam.changes[0].touched, vec![0]);
    assert_eq!(seam.changes[0].untouched, vec![1]);
    assert_eq!(seam.changes[0].breach, None);
}

#[test]
fn a_fix_exactly_at_the_window_breaches_and_one_past_it_does_not() {
    // Three commits of room: the change, then room for a fix at distance one,
    // two or three.
    let window = 3;
    let mut commits: Vec<(&str, &str, &[&str])> = vec![
        ("c01", "feat: one side", &["crates/a/x.rs"]),
        ("c02", "docs: unrelated", &["README.md"]),
        ("c03", "docs: unrelated", &["README.md"]),
    ];

    let mut at_the_edge = commits.clone();
    at_the_edge.push(("c04", "fix: the other side", &["crates/b/x.rs"]));
    let report = evaluate(
        &two_member_ledger(),
        &history(&at_the_edge),
        &settings(window),
    );
    let breach = report.seams[0].changes[0]
        .breach
        .as_ref()
        .expect("a fix at exactly the window is inside it");
    assert_eq!(breach.distance, window);
    assert_eq!(breach.commit, id("c04"));
    assert_eq!(breach.subject, "fix: the other side");
    assert_eq!(breach.member, 1);
    assert_eq!(report.seams[0].breaches, 1);
    assert_eq!(report.seams[0].last_breach, Some(id("c04")));

    // One commit further along, and the same fix is no longer evidence about
    // the same change.
    commits.push(("c04", "docs: unrelated", &["README.md"]));
    commits.push(("c05", "fix: the other side", &["crates/b/x.rs"]));
    let report = evaluate(&two_member_ledger(), &history(&commits), &settings(window));
    assert_eq!(report.seams[0].changes[0].breach, None);
    assert_eq!(report.seams[0].breaches, 0);
    assert_eq!(report.seams[0].last_breach, None);
}

#[test]
fn only_a_fix_breaches_a_seam() {
    for subject in [
        "feat: the other side",
        "docs: the other side",
        "the other side",
    ] {
        let history = history(&[
            ("c01", "feat: one side", &["crates/a/x.rs"]),
            ("c02", subject, &["crates/b/x.rs"]),
        ]);
        let report = evaluate(&two_member_ledger(), &history, &settings(20));
        assert_eq!(
            report.seams[0].changes[0].breach, None,
            "subject {subject:?} is not a fix"
        );
        assert_eq!(report.seams[0].breaches, 0);
    }
}

#[test]
fn the_first_qualifying_fix_in_the_window_is_the_breach() {
    let history = history(&[
        ("c01", "feat: one side", &["crates/a/x.rs"]),
        // Not a fix, so it is not the breach even though it lands on the
        // member that was left alone.
        ("c02", "feat: the other side", &["crates/b/x.rs"]),
        ("c03", "fix: the other side", &["crates/b/x.rs"]),
        ("c04", "fix: the other side again", &["crates/b/x.rs"]),
    ]);
    let report = evaluate(&two_member_ledger(), &history, &settings(20));
    let breach = report.seams[0].changes[0]
        .breach
        .as_ref()
        .expect("breached");
    assert_eq!(breach.commit, id("c03"));
    assert_eq!(breach.distance, 2);
    // One breach per asymmetric change: the second fix is not a second
    // breach of the same change.
    assert_eq!(report.seams[0].changes[0].breach.iter().count(), 1);
}

#[test]
fn a_breach_names_the_lowest_member_the_fix_reached() {
    let ledger = Ledger::new(vec![SeamEntry {
        id: "three-ways".to_string(),
        members: vec![
            "crates/a/**".to_string(),
            "crates/b/**".to_string(),
            "crates/c/**".to_string(),
        ],
        note: None,
    }])
    .unwrap();
    let history = history(&[
        ("c01", "feat: one side", &["crates/a/x.rs"]),
        (
            "c02",
            "fix: both other sides",
            &["crates/b/x.rs", "crates/c/x.rs"],
        ),
    ]);
    let report = evaluate(&ledger, &history, &settings(20));
    assert_eq!(report.seams[0].changes[0].untouched, vec![1, 2]);
    assert_eq!(
        report.seams[0].changes[0].breach.as_ref().unwrap().member,
        1
    );
}

#[test]
fn a_sweeping_commit_still_breaks_a_seam_and_still_says_nothing_about_coupling() {
    let ledger = Ledger::new(vec![SeamEntry {
        id: "three-ways".to_string(),
        members: vec![
            "crates/a/**".to_string(),
            "crates/b/**".to_string(),
            "crates/c/**".to_string(),
        ],
        note: None,
    }])
    .unwrap();
    let history = history(&[(
        "c01",
        "refactor: four files at once",
        &[
            "crates/a/x.rs",
            "crates/a/y.rs",
            "crates/b/x.rs",
            "crates/b/y.rs",
        ],
    )]);
    let sweeping = Settings {
        max_commit_size: 3,
        min_support: 1,
        min_coupling: 0.0,
        ..Settings::default()
    };

    // The ceiling belongs to coupling alone: a commit too large to be
    // evidence of co-change is still a commit that left one member behind.
    let report = evaluate(&ledger, &history, &sweeping);
    assert_eq!(report.seams[0].asymmetric_changes, 1);
    assert_eq!(report.seams[0].changes[0].touched, vec![0, 1]);
    assert_eq!(report.seams[0].changes[0].untouched, vec![2]);

    assert!(suggest(&ledger, &history, &sweeping).candidates.is_empty());

    // The same commit under a ceiling it fits inside contributes as usual,
    // which is what shows the emptiness above came from the ceiling.
    let roomy = Settings {
        max_commit_size: 4,
        ..sweeping
    };
    let proposed = suggest(&ledger, &history, &roomy);
    assert_eq!(proposed.candidates.len(), 1);
    assert_eq!(proposed.candidates[0].left, "crates/a");
    assert_eq!(proposed.candidates[0].right, "crates/b");
}

#[test]
fn coupling_is_the_lower_confidence_and_both_floors_are_applied() {
    // C(a) = 4, C(b) = 4, C(c) = 1.
    // support(a, b) = 3 -> confidence 3/4 both ways, coupling 0.75.
    // support(b, c) = 1 -> confidence 1/4 and 1/1, coupling 0.25.
    let history = history(&[
        ("c01", "feat: a", &["crates/a/x.rs"]),
        ("c02", "feat: a and b", &["crates/a/x.rs", "crates/b/x.rs"]),
        ("c03", "feat: a and b", &["crates/a/y.rs", "crates/b/y.rs"]),
        ("c04", "feat: a and b", &["crates/a/z.rs", "crates/b/z.rs"]),
        ("c05", "feat: b and c", &["crates/b/x.rs", "crates/c/x.rs"]),
    ]);
    let ledger = Ledger::new(Vec::new()).unwrap();
    let permissive = Settings {
        min_support: 1,
        min_coupling: 0.6,
        ..Settings::default()
    };

    let proposed = suggest(&ledger, &history, &permissive);
    assert_eq!(proposed.candidates.len(), 1, "{:?}", proposed.candidates);
    let candidate = &proposed.candidates[0];
    assert_eq!(
        (candidate.left.as_str(), candidate.right.as_str()),
        ("crates/a", "crates/b")
    );
    assert_eq!(candidate.support, 3);
    assert!((candidate.confidence_left_right - 0.75).abs() < f64::EPSILON);
    assert!((candidate.confidence_right_left - 0.75).abs() < f64::EPSILON);
    assert!((candidate.coupling - 0.75).abs() < f64::EPSILON);
    assert!(!candidate.in_ledger);

    // The support floor removes the pair the coupling floor kept.
    let demanding = Settings {
        min_support: 4,
        ..permissive
    };
    assert!(suggest(&ledger, &history, &demanding).candidates.is_empty());

    // Dropping the coupling floor lets the one-sided pair through, which is
    // what shows the floor was what removed it.
    let unfiltered = Settings {
        min_coupling: 0.0,
        ..permissive
    };
    let all = suggest(&ledger, &history, &unfiltered);
    let weak = all
        .candidates
        .iter()
        .find(|candidate| candidate.right == "crates/c")
        .expect("the one-sided pair");
    assert!((weak.confidence_left_right - 0.25).abs() < f64::EPSILON);
    assert!((weak.confidence_right_left - 1.0).abs() < f64::EPSILON);
    assert!((weak.coupling - 0.25).abs() < f64::EPSILON);
}

#[test]
fn candidates_are_ordered_by_coupling_then_support_then_both_names() {
    // Three pairs at coupling 1.0 with two different supports, and two pairs
    // sharing a coupling, a support and a left unit — so every level of the
    // comparison decides at least one adjacent pair.
    let history = history(&[
        ("c01", "feat: ab", &["crates/a/x.rs", "crates/b/x.rs"]),
        ("c02", "feat: ab", &["crates/a/y.rs", "crates/b/y.rs"]),
        ("c03", "feat: ab", &["crates/a/z.rs", "crates/b/z.rs"]),
        ("c04", "feat: cd", &["crates/c/x.rs", "crates/d/x.rs"]),
        ("c05", "feat: cd", &["crates/c/y.rs", "crates/d/y.rs"]),
        ("c06", "feat: ef", &["crates/e/x.rs", "crates/f/x.rs"]),
        ("c07", "feat: ef", &["crates/e/y.rs", "crates/f/y.rs"]),
        ("c08", "feat: ef", &["crates/e/z.rs", "crates/f/z.rs"]),
        ("c09", "feat: gh", &["crates/g/x.rs", "crates/h/x.rs"]),
        ("c10", "feat: gh", &["crates/g/y.rs", "crates/h/y.rs"]),
        ("c11", "feat: gi", &["crates/g/x.rs", "crates/i/x.rs"]),
        ("c12", "feat: gi", &["crates/g/y.rs", "crates/i/y.rs"]),
    ]);
    let proposed = suggest(
        &Ledger::new(Vec::new()).unwrap(),
        &history,
        &Settings {
            min_support: 2,
            min_coupling: 0.5,
            ..Settings::default()
        },
    );
    let order: Vec<(&str, &str)> = proposed
        .candidates
        .iter()
        .map(|candidate| (candidate.left.as_str(), candidate.right.as_str()))
        .collect();
    assert_eq!(
        order,
        vec![
            // Coupling 1.0, support 3, and `crates/a` sorts before `crates/e`.
            ("crates/a", "crates/b"),
            ("crates/e", "crates/f"),
            // Coupling 1.0 still, but two commits rather than three.
            ("crates/c", "crates/d"),
            // Coupling 0.5, equal support, equal left unit: the right unit
            // decides, and nothing is left to tie.
            ("crates/g", "crates/h"),
            ("crates/g", "crates/i"),
        ]
    );
}

#[test]
fn a_candidate_is_marked_when_one_seam_already_spans_it() {
    let history = history(&[
        ("c01", "feat: ab", &["crates/a/x.rs", "crates/b/x.rs"]),
        ("c02", "feat: ab", &["crates/a/y.rs", "crates/b/y.rs"]),
    ]);
    let settings = Settings {
        min_support: 2,
        min_coupling: 0.5,
        ..Settings::default()
    };

    let spanned = suggest(&two_member_ledger(), &history, &settings);
    assert_eq!(spanned.candidates.len(), 1);
    assert!(spanned.candidates[0].in_ledger);

    // One glob covering both units is not a statement about how they relate,
    // so it does not mark the pair.
    let broad = Ledger::new(vec![SeamEntry {
        id: "everything".to_string(),
        members: vec!["crates/**".to_string(), "docs/**".to_string()],
        note: None,
    }])
    .unwrap();
    let unspanned = suggest(&broad, &history, &settings);
    assert_eq!(unspanned.candidates.len(), 1);
    assert!(!unspanned.candidates[0].in_ledger);
}

#[test]
fn a_lookup_names_the_members_that_have_not_moved() {
    let found = look_up(
        &two_member_ledger(),
        &paths(&["crates/a/src/lib.rs", "Makefile"]),
    );
    assert_eq!(found.len(), 2);
    assert_eq!(found[0].path, RepoPath::new("crates/a/src/lib.rs"));
    assert_eq!(found[0].seams.len(), 1);
    assert_eq!(found[0].seams[0].seam, "frontends");
    assert_eq!(found[0].seams[0].member, "crates/a/**");
    assert_eq!(
        found[0].seams[0].other_members,
        vec!["crates/b/**".to_string()]
    );
    assert!(found[1].seams.is_empty());
}

#[test]
fn guard_reports_a_partial_change_and_nothing_else() {
    // A repository that has not written a ledger has not broken a seam.
    let empty = Ledger::new(Vec::new()).unwrap();
    assert!(empty.is_empty());
    assert!(guard(&empty, &paths(&["crates/a/x.rs"])).is_empty());

    let ledger = two_member_ledger();
    assert!(!ledger.is_empty());
    assert_eq!(ledger.entries().len(), 1);

    // Both sides moved, so the seam held.
    assert!(guard(&ledger, &paths(&["crates/a/x.rs", "crates/b/x.rs"])).is_empty());
    // Neither side moved.
    assert!(guard(&ledger, &paths(&["README.md"])).is_empty());
    // Nothing moved at all.
    assert!(guard(&ledger, &[]).is_empty());

    let report = guard(&ledger, &paths(&["crates/a/x.rs", "README.md"]));
    assert!(!report.is_empty());
    assert_eq!(report.seams.len(), 1);
    assert_eq!(report.seams[0].id, "frontends");
    assert_eq!(report.seams[0].touched, vec!["crates/a/**".to_string()]);
    assert_eq!(report.seams[0].untouched, vec!["crates/b/**".to_string()]);
}

#[test]
fn two_equal_inputs_serialise_to_the_same_bytes() {
    // Built twice, from two sets of records, arriving in two different orders:
    // what the results have in common is the data, and if any of it reached
    // the output through the order it was assembled in, the bytes below would
    // differ.
    let entries = || {
        vec![
            SeamEntry {
                id: "frontends".to_string(),
                members: vec!["crates/a/**".to_string(), "crates/b/**".to_string()],
                note: Some("two implementations of one thing".to_string()),
            },
            SeamEntry {
                id: "code-and-docs".to_string(),
                members: vec!["crates/**".to_string(), "docs/**".to_string()],
                note: None,
            },
        ]
    };
    let records = [
        ("c01", "feat: one side", &["crates/a/x.rs"][..]),
        (
            "c02",
            "feat: both sides",
            &["crates/a/y.rs", "crates/b/y.rs"][..],
        ),
        ("c03", "fix: the other side", &["crates/b/x.rs"][..]),
        ("c04", "docs: write it down", &["docs/en/cli.md"][..]),
        ("c05", "feat: one side again", &["crates/a/z.rs"][..]),
    ];
    let forwards: Vec<CommitRecord> = records
        .iter()
        .enumerate()
        .map(|(index, (name, subject, files))| {
            commit(name, i64::try_from(index).unwrap(), subject, files)
        })
        .collect();
    let backwards: Vec<CommitRecord> = forwards.iter().rev().cloned().collect();

    let settings = Settings {
        min_support: 1,
        min_coupling: 0.0,
        ..Settings::default()
    };
    let first = (
        Ledger::new(entries()).unwrap(),
        History::new(forwards, false),
    );
    let second = (
        Ledger::new(entries()).unwrap(),
        History::new(backwards, false),
    );
    assert_eq!(first.0, second.0);
    assert_eq!(first.1, second.1);

    let render = |(ledger, history): &(Ledger, History)| {
        (
            serde_json::to_vec(&evaluate(ledger, history, &settings)).unwrap(),
            serde_json::to_vec(&suggest(ledger, history, &settings)).unwrap(),
        )
    };
    let (evaluation, suggestion) = render(&first);
    assert_eq!(render(&second), (evaluation.clone(), suggestion.clone()));
    // The same input rendered again, in case anything cached a first answer.
    assert_eq!(render(&first), (evaluation, suggestion));

    // The results are not trivially empty, or they would agree for the wrong
    // reason.
    let report = evaluate(&first.0, &first.1, &settings);
    assert_eq!(report.seams[0].asymmetric_changes, 3);
    assert_eq!(report.seams[0].breaches, 1);
    assert!(!suggest(&first.0, &first.1, &settings).candidates.is_empty());
    assert_eq!(report.settings_digest, settings.digest());
    assert_eq!(report.range.commits, 5);
    assert_eq!(report.range.first, Some(id("c01")));
    assert_eq!(report.range.last, Some(id("c05")));
}

#[test]
fn the_settings_digest_moves_with_every_field_and_with_nothing_else() {
    let settings = Settings::default();
    assert_eq!(settings.digest(), Settings::default().digest());
    assert_eq!(settings.digest(), settings.digest());

    let moved = [
        Settings {
            breach_window: 21,
            ..Settings::default()
        },
        Settings {
            history_limit: 1999,
            ..Settings::default()
        },
        Settings {
            max_commit_size: 31,
            ..Settings::default()
        },
        Settings {
            min_coupling: 0.61,
            ..Settings::default()
        },
        Settings {
            min_support: 4,
            ..Settings::default()
        },
        Settings {
            suggest_depth: 3,
            ..Settings::default()
        },
    ];
    let mut digests: Vec<String> = moved.iter().map(Settings::digest).collect();
    digests.push(settings.digest());
    let distinct: std::collections::BTreeSet<&String> = digests.iter().collect();
    assert_eq!(
        distinct.len(),
        digests.len(),
        "one field moved and the digest did not"
    );

    // A difference far below the printed precision is a difference the digest
    // cannot see. That is the deliberate cost of a fixed rendering: the
    // digest describes the configuration a reader can write, not the bits.
    let indistinguishable = Settings {
        min_coupling: 0.60 + 1e-12,
        ..Settings::default()
    };
    assert_eq!(indistinguishable.digest(), settings.digest());
}

#[test]
fn a_setting_that_would_empty_the_result_is_refused() {
    Settings::default()
        .validate()
        .expect("the defaults are valid");

    let cases: Vec<(Settings, &str)> = vec![
        (
            Settings {
                breach_window: 0,
                ..Settings::default()
            },
            "seam-tracking.breach-window",
        ),
        (
            Settings {
                history_limit: 0,
                ..Settings::default()
            },
            "seam-tracking.history-limit",
        ),
        (
            Settings {
                max_commit_size: 0,
                ..Settings::default()
            },
            "seam-tracking.max-commit-size",
        ),
        (
            Settings {
                min_support: 0,
                ..Settings::default()
            },
            "seam-tracking.min-support",
        ),
        (
            Settings {
                suggest_depth: 0,
                ..Settings::default()
            },
            "seam-tracking.suggest-depth",
        ),
        (
            Settings {
                min_coupling: 1.5,
                ..Settings::default()
            },
            "seam-tracking.min-coupling",
        ),
        (
            Settings {
                min_coupling: -0.5,
                ..Settings::default()
            },
            "seam-tracking.min-coupling",
        ),
        (
            Settings {
                min_coupling: f64::NAN,
                ..Settings::default()
            },
            "seam-tracking.min-coupling",
        ),
    ];
    for (settings, key) in cases {
        let error = settings.validate().expect_err("out of range");
        assert!(
            matches!(error, SeamError::InvalidSetting(ref message) if message.contains(key)),
            "expected {key} to be named, got {error}"
        );
    }
}

#[test]
fn a_ledger_that_would_watch_nothing_is_refused() {
    let entry = |id: &str, members: &[&str]| SeamEntry {
        id: id.to_string(),
        members: members.iter().map(|member| (*member).to_string()).collect(),
        note: None,
    };

    assert!(matches!(
        Ledger::new(vec![entry("  ", &["a/**", "b/**"])]).expect_err("blank id"),
        SeamError::EmptyId
    ));

    assert!(matches!(
        Ledger::new(vec![
            entry("frontends", &["a/**", "b/**"]),
            entry("frontends", &["c/**", "d/**"]),
        ])
        .expect_err("repeated id"),
        SeamError::DuplicateId { ref id } if id == "frontends"
    ));

    assert!(matches!(
        Ledger::new(vec![entry("lonely", &["a/**"])]).expect_err("one member"),
        SeamError::TooFewMembers { ref id, members } if id == "lonely" && members == 1
    ));
    assert!(matches!(
        Ledger::new(vec![entry("empty", &[])]).expect_err("no members"),
        SeamError::TooFewMembers { members: 0, .. }
    ));

    assert!(matches!(
        Ledger::new(vec![entry("blank-member", &["a/**", ""])]).expect_err("blank member"),
        SeamError::EmptyMember { ref id } if id == "blank-member"
    ));

    let error = Ledger::new(vec![entry("bad-glob", &["a/**", "b/["])]).expect_err("bad glob");
    assert!(
        matches!(error, SeamError::BadGlob { ref id, ref glob, .. } if id == "bad-glob" && glob == "b/["),
        "got {error}"
    );

    // Every message names what to edit.
    let message = Ledger::new(vec![entry("lonely", &["a/**"])])
        .expect_err("one member")
        .to_string();
    assert!(
        message.contains("[[seam]]") && message.contains("lonely"),
        "{message}"
    );
}
