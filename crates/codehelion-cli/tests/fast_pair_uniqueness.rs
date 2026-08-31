//! One duplication relation reaches the reader once.
//!
//! Fast mode looks for verbatim copies twice over: a raw pass that extends an
//! equal run inside one function segment at a time, and a fragment pass that
//! matches whole fragments and so reaches across a nested function the raw
//! pass cannot extend through. Both can arrive at the same two occurrences and
//! stop at different widths. Reported side by side, one duplication becomes
//! two findings, and every count taken over findings reads the narrower one as
//! a second result.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::path::Path;

use assert_cmd::Command;
use serde_json::Value;

/// A function whose body holds a nested function, so the body is one fragment
/// but three segments. Copied verbatim into a second file below.
const OUTER_RS: &str = "pub fn outer(data: &[u32]) -> u32 {
    let mut acc = 0u32;
    for value in data {
        acc = acc.wrapping_add(*value);
        acc = acc.rotate_left(3);
    }
    fn helper(seed: u32, scale: u32) -> u32 {
        let mixed = seed.wrapping_mul(scale);
        let folded = mixed ^ (mixed >> 7);
        folded.wrapping_add(scale)
    }
    let tail = helper(acc, 11);
    acc = acc.wrapping_mul(tail);
    acc.wrapping_sub(1)
}
";

fn fixture() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("temp dir");
    let source = dir.path().join("src");
    std::fs::create_dir_all(&source).unwrap();
    std::fs::write(source.join("one.rs"), OUTER_RS).unwrap();
    std::fs::write(
        source.join("two.rs"),
        OUTER_RS.replace("pub fn outer(", "pub fn outer_copy("),
    )
    .unwrap();
    dir
}

/// Run `scan --mode fast --format json` in `root` and parse the report.
fn scan_fast(root: &Path) -> Value {
    let output = Command::cargo_bin("codehelion")
        .expect("binary should build")
        .current_dir(root)
        .args(["scan", ".", "--mode", "fast", "--format", "json"])
        .output()
        .expect("run scan");
    assert!(output.status.success(), "{output:?}");
    serde_json::from_slice(&output.stdout).expect("stdout is one JSON document")
}

/// One occurrence: the file it sits in and the lines it spans.
type Occurrence = (String, u64, u64);

/// The occurrences of a finding that is not marked as noise. A marked finding
/// is a signal about the codebase rather than a result to read, so it is not
/// part of what this asserts.
fn primary_occurrences(group: &Value) -> Option<Vec<Occurrence>> {
    if !group["suppressed"].is_null() {
        return None;
    }
    Some(
        group["members"]
            .as_array()
            .expect("members")
            .iter()
            .map(|member| {
                (
                    member["file"].as_str().expect("file").to_owned(),
                    member["start_line"].as_u64().expect("start line"),
                    member["end_line"].as_u64().expect("end line"),
                )
            })
            .collect(),
    )
}

fn inside(member: &Occurrence, outer: &Occurrence) -> bool {
    member.0 == outer.0 && outer.1 <= member.1 && member.2 <= outer.2
}

/// Whether `narrow` states an occurrence pair `wide` already states, over a
/// smaller stretch of both occurrences.
fn restates_a_pair(narrow: &[Occurrence], wide: &[Occurrence]) -> bool {
    narrow.iter().enumerate().any(|(i, first)| {
        narrow[i + 1..].iter().any(|second| {
            wide.iter().enumerate().any(|(j, host)| {
                wide[j + 1..].iter().any(|other| {
                    let covered = (inside(first, host) && inside(second, other))
                        || (inside(first, other) && inside(second, host));
                    let identical =
                        (first == host && second == other) || (first == other && second == host);
                    covered && !identical
                })
            })
        })
    })
}

#[test]
fn a_duplication_relation_reaches_the_report_at_one_width() {
    let dir = fixture();
    let report = scan_fast(dir.path());
    let groups = report["groups"].as_array().expect("groups");
    let primary: Vec<Vec<Occurrence>> = groups.iter().filter_map(primary_occurrences).collect();
    assert!(!primary.is_empty(), "the copy must be found: {report:#}");

    for narrow in &primary {
        for wide in &primary {
            assert!(
                !restates_a_pair(narrow, wide),
                "one relation reported at two widths: {narrow:?} inside {wide:?}"
            );
        }
    }

    // The width that survives is the whole shared body, not the nested
    // function the raw pass could reach on its own.
    let body = (String::from("src/one.rs"), 2, 14);
    assert!(
        primary
            .iter()
            .any(|occurrences| occurrences.contains(&body)),
        "the shared body must still be reported: {primary:?}"
    );
}
