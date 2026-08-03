use super::*;
use std::fmt::Write as _;

/// A tree holding several copies of a family of functions that are clones of
/// one another, but not transitively so.
///
/// This is what a dependency directory looks like when it carries a library at
/// more than one version, or a project that keeps one algorithm per target
/// architecture: the same handful of shapes, over and over. Similarity is not
/// transitive, so no one group can hold the whole family, and the verdicts
/// left over recur once per crossing of the copies — the same fact, with many
/// places to say it about.
fn fixture_with_repeated_copies(copies: usize) -> tempfile::TempDir {
    const FAMILY: [&str; 6] = [
        "seed",
        "calls_swapped",
        "rewritten",
        "guard_added",
        "loop_nested",
        "exits_removed",
    ];
    let corpus = Path::new("../../corpus/synthetic/rust-divergent");
    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path();
    std::fs::create_dir_all(root.join(".git")).unwrap();
    std::fs::create_dir_all(root.join("src")).unwrap();
    for copy in 0..copies {
        for member in FAMILY {
            let text = std::fs::read_to_string(corpus.join(format!("{member}.rs")))
                .unwrap_or_else(|e| panic!("reading the divergence corpus: {e}"));
            std::fs::write(root.join(format!("src/{member}_{copy}.rs")), text).unwrap();
        }
    }
    dir
}

/// Every identifier a report hands out has to name one thing.
///
/// A reader freezes a finding by its clone id and follows it by its finding
/// id. Two rows under one clone id means freezing either hides both; two
/// occurrences under one finding id means neither can be suppressed or
/// followed on its own. Neither failure announces itself — a baseline that
/// hides more than it was pointed at looks exactly like one that worked.
#[test]
fn every_identifier_a_report_hands_out_names_one_thing() {
    let dir = fixture_with_repeated_copies(6);
    let value = scan_json(dir.path());
    let groups = value["groups"].as_array().unwrap();
    assert!(groups.len() > 1, "the fixture reports several findings");

    let clone_ids: Vec<&str> = groups
        .iter()
        .map(|group| group["fingerprint"].as_str().unwrap())
        .collect();
    let distinct: std::collections::BTreeSet<&str> = clone_ids.iter().copied().collect();
    assert_eq!(
        clone_ids.len(),
        distinct.len(),
        "{} of {} rows share a clone id with another row",
        clone_ids.len() - distinct.len(),
        clone_ids.len()
    );

    let finding_ids: Vec<&str> = groups
        .iter()
        .flat_map(|group| group["members"].as_array().unwrap())
        .map(|member| member["finding_id"].as_str().unwrap())
        .collect();
    let distinct: std::collections::BTreeSet<&str> = finding_ids.iter().copied().collect();
    assert_eq!(
        finding_ids.len(),
        distinct.len(),
        "{} of {} occurrences share a finding id with another occurrence",
        finding_ids.len() - distinct.len(),
        finding_ids.len()
    );
}

/// The same relation observed in many places is one finding, not many.
///
/// Six copies of one shape against six of another is thirty-six crossings and
/// one fact. Reported one crossing at a time it fills the report with rows
/// that differ in nothing a reader can act on — and, since a clone id is
/// composed from member content, all thirty-six carry the same id anyway.
#[test]
fn one_relation_seen_in_many_places_is_reported_once() {
    let copies = 6;
    let dir = fixture_with_repeated_copies(copies);
    let value = scan_json(dir.path());
    let split: Vec<&serde_json::Value> = value["groups"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|group| group["split_pair"] == true)
        .collect();
    assert_eq!(
        split.len(),
        1,
        "the relation between the two shapes is stated {} times",
        split.len()
    );
    // And it carries every place it was seen rather than one representative
    // pair, so a reader who acts on it knows the whole extent of the work.
    let members = split[0]["members"].as_array().unwrap();
    assert_eq!(members.len(), copies * 2);
    assert!(
        split[0]["identifier_jaccard"].is_number(),
        "a split pair carries raw-identifier triage evidence"
    );
    let similarity = split[0]["similarity"]
        .as_object()
        .expect("a split pair preserves its per-dimension verifier evidence");
    for dimension in ["lexical", "structural", "composite", "min_pairwise"] {
        assert!(
            similarity[dimension].is_number(),
            "split-pair similarity includes {dimension}: {similarity:#?}"
        );
    }
    let run_id = value["run"]["run_id"].as_i64().expect("recorded run id");
    let output = cmd()
        .current_dir(dir.path())
        .args(["report", "--run", &run_id.to_string(), "--format", "json"])
        .output()
        .expect("replay structural report");
    assert!(output.status.success(), "{output:?}");
    let replayed: serde_json::Value = serde_json::from_slice(&output.stdout).expect("report JSON");
    let replayed_pair = replayed["groups"]
        .as_array()
        .expect("replayed groups")
        .iter()
        .find(|group| group["fingerprint"] == split[0]["fingerprint"])
        .expect("replayed split pair");
    assert_eq!(replayed_pair["similarity"], split[0]["similarity"]);
    assert_eq!(
        members
            .iter()
            .filter(|member| member["canonical"] == true)
            .count(),
        1
    );
}

/// Two functions copied whole, each holding a nested helper.
///
/// The shape that produces a crossing nothing can act on: the helpers are
/// copies of each other and so are their parents, which leaves each helper
/// agreeing with the *other* parent as well — not because it was copied there
/// but because its own twin lives inside it.
const NESTED_TWINS_RS: &str = "\
fn build_index(rows: &[u64]) -> (u64, usize) {
    fn fold(rows: &[u64], seed: u64) -> u64 {
        let mut acc = seed;
        for row in rows {
            acc = acc.wrapping_mul(31).wrapping_add(*row);
            if *row == 0 {
                acc = acc.rotate_left(7);
            }
            acc ^= acc >> 13;
        }
        return acc;
    }
    return (fold(rows, 17), rows.len());
}

fn build_table(rows: &[u64]) -> (u64, usize) {
    fn fold(rows: &[u64], seed: u64) -> u64 {
        let mut acc = seed;
        for row in rows {
            acc = acc.wrapping_mul(31).wrapping_add(*row);
            if *row == 0 {
                acc = acc.rotate_left(7);
            }
            acc ^= acc >> 13;
        }
        return acc;
    }
    return (fold(rows, 17), rows.len());
}
";

/// A crossing two reported groups already account for is not a third finding.
///
/// A helper nested in one function and copied into another agrees with that
/// other function too, over the stretch its own twin occupies there. The
/// verdict is not wrong — the tokens do line up — but the report has already
/// said it twice, once for the pair of helpers and once for the pair of
/// parents, and stating it a third time at a two-to-one size ratio points a
/// reader at work that does not exist. Both real groups have to survive:
/// dropping the crossing must not cost the facts it was derived from.
#[test]
fn a_crossing_two_groups_already_account_for_is_not_reported_again() {
    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path();
    std::fs::create_dir_all(root.join(".git")).unwrap();
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(root.join("src/nested.rs"), NESTED_TWINS_RS).unwrap();

    let value = scan_json(root);
    let groups = value["groups"].as_array().unwrap();
    let units: Vec<&str> = groups
        .iter()
        .filter(|group| group["split_pair"] == false)
        .map(|group| group["members"][0]["unit"].as_str().unwrap())
        .collect();
    assert!(
        units.contains(&"fold"),
        "the two nested helpers are no longer grouped: {units:?}"
    );
    assert!(
        units.iter().any(|unit| unit.starts_with("build_")),
        "the two parents are no longer grouped: {units:?}"
    );
    let crossings: Vec<&serde_json::Value> = groups
        .iter()
        .filter(|group| group["split_pair"] == true)
        .collect();
    assert!(
        crossings.is_empty(),
        "a helper is still reported against the parent that holds its twin: {crossings:#?}"
    );
    // And the run says how many it left out, so the drop is a number in the
    // funnel rather than findings that quietly went missing.
    let verified = value["summary"]["funnel"]
        .as_array()
        .unwrap()
        .iter()
        .find(|stage| stage["stage"] == "verified pairs")
        .expect("the funnel reports the verified-pair stage");
    assert_eq!(
        verified["dropped"]
            .as_array()
            .unwrap()
            .iter()
            .find(|drop| drop["cause"] == "a_group_says_it_already")
            .map(|drop| drop["count"].as_u64().unwrap()),
        Some(2),
        "expected both crossings counted: {verified:#?}"
    );
}

/// Two copies of one function have the same content and therefore the same
/// unit fingerprint, so what tells their occurrences apart is the rank the
/// identifier carries. A report that prints one id and a database that holds
/// another leave `explain` unable to answer about a finding the report named.
#[test]
fn every_occurrence_the_report_names_can_be_explained() {
    let dir = tempfile::tempdir().expect("temp dir");
    let src = dir.path().join("src");
    std::fs::create_dir_all(&src).expect("create src");
    // Three verbatim copies: one group whose members share a fingerprint.
    for name in ["a.rs", "b.rs", "c.rs"] {
        std::fs::write(src.join(name), ALPHA_RS).expect("write source");
    }

    let value = scan_json(dir.path());
    let members = value["groups"][0]["members"]
        .as_array()
        .expect("the group lists its occurrences");
    assert_eq!(members.len(), 3, "{value:#?}");

    for member in members {
        let id = member["finding_id"].as_str().expect("a finding id");
        cmd()
            .current_dir(dir.path())
            .args(["explain", id])
            .assert()
            .success()
            .stdout(predicate::str::contains(
                member["file"].as_str().expect("a file path"),
            ));
    }
}

/// One member of a renamed family, spelled with names of its own.
///
/// Eight of these share every window and subtree hash, so one posting list
/// holds twenty-eight pairs — more than the ceilings below allow, which is the
/// point.
fn family_member(index: usize) -> String {
    format!(
        "pub fn member{index}(input{index}: &[u32]) -> u32 {{
    let mut total{index} = 0u32;
    let mut seen{index} = 0u32;
    for value{index} in input{index} {{
        if *value{index} > 10 {{
            total{index} = total{index}.wrapping_add(*value{index});
        }} else {{
            total{index} = total{index}.wrapping_sub(1);
        }}
        seen{index} += 1;
    }}
    total{index} = total{index}.wrapping_mul(3);
    return total{index} + seen{index};
}}
"
    )
}

/// One member of a smaller family, shaped unlike the first.
///
/// Three of these, against eight of the other, so a cap between the two sizes
/// drops one family and keeps the other — without a second size, every posting
/// cap either keeps everything or drops everything and the sweep below says
/// nothing about the settings between.
fn smaller_family_member(index: usize) -> String {
    format!(
        "pub fn narrow{index}(text{index}: &str) -> usize {{
    let mut width{index} = 0usize;
    while width{index} < text{index}.len() {{
        width{index} = width{index}.saturating_add(2);
    }}
    return width{index};
}}
"
    )
}

/// Tightening a ceiling must never lengthen the report.
///
/// Grouping reads a pair nothing proposed as a pair that is not similar, which
/// is sound while the stage above it finished and is not once a ceiling cut a
/// posting list in half. A family compared to itself only in part arrives there
/// looking like a family that disagrees: it is broken up, and the comparisons
/// that did survive come back out one at a time as pairs no group holds both
/// halves of. The report then *grows* as the allowance shrinks — the reader is
/// handed more rows, saying less, exactly when the tool is under pressure.
///
/// So the property worth holding is not how much a squeezed run finds but that
/// squeezing it cannot inflate it, and it is worth holding for every ceiling
/// rather than the one that was found breaking it. Both of these spend
/// themselves a whole posting list at a time — one by refusing a list it cannot
/// pair entirely, the other by dropping a list outright — and this is what says
/// so from outside.
#[test]
fn a_tighter_ceiling_never_makes_the_report_longer() {
    let dir = tempfile::tempdir().expect("temp dir");
    let src = dir.path().join("src");
    std::fs::create_dir_all(&src).expect("create src");
    for index in 0..8 {
        std::fs::write(src.join(format!("m{index}.rs")), family_member(index))
            .expect("write source");
    }
    for index in 0..3 {
        std::fs::write(
            src.join(format!("n{index}.rs")),
            smaller_family_member(index),
        )
        .expect("write source");
    }

    for (limit, settings) in [
        ("pair-budget", [100_000usize, 400, 200, 100, 60, 40, 20, 10]),
        ("posting-cap", [1024, 32, 16, 8, 6, 5, 4, 2]),
    ] {
        let mut previous = usize::MAX;
        let mut ceilings = String::new();
        for setting in settings {
            std::fs::write(
                dir.path().join("codehelion.toml"),
                format!("[limits]\n{limit} = {setting}\n"),
            )
            .expect("write the ceiling");
            let value = scan_json(dir.path());
            let groups = value["groups"]
                .as_array()
                .expect("the report lists its groups")
                .len();
            let _ = writeln!(ceilings, "  {limit} {setting}: {groups} groups");
            assert!(
                groups <= previous,
                "a tighter ceiling reported more groups\n{ceilings}"
            );
            previous = groups;
        }
        // And the family is found at all where the allowance is there, so the
        // run above is not monotone merely by finding nothing throughout.
        assert!(previous < 8, "{ceilings}");
    }
}

/// A ceiling that cuts a set apart must not then report the cut as findings.
///
/// Refinement runs on sets, and comparing a set costs time quadratic in its
/// size, so a set past the ceiling is cut into pieces and each piece refined on
/// its own. Two members in different pieces are then never weighed against each
/// other — and the relation between them, which verification had already
/// accepted, comes back out as a pair no group holds both halves of. The
/// ceiling exists so that a repository of thousands of interchangeable units
/// cannot make a scan expensive; reporting what it severed would move that
/// expense onto the reader, one pair at a time, at the size of the set squared.
///
/// So the severed relations are counted under a cause of their own instead of
/// being listed. What the ceiling costs is a coarser partition, which is the
/// price it was always documented to charge; what it must not cost is a report
/// made of the same duplication restated.
#[test]
fn a_set_the_ceiling_cut_is_not_reported_as_the_pairs_it_severed() {
    let dir = tempfile::tempdir().expect("temp dir");
    let src = dir.path().join("src");
    std::fs::create_dir_all(&src).expect("create src");
    for index in 0..8 {
        std::fs::write(src.join(format!("m{index}.rs")), family_member(index))
            .expect("write source");
    }

    let whole = scan_json(dir.path());
    // Whole-unit findings only: the statement run the eight share is a
    // sub-unit view of the same code, and the ceiling is about sets of units.
    let units = |value: &serde_json::Value| {
        value["groups"]
            .as_array()
            .expect("the report lists its groups")
            .iter()
            .filter(|group| group["scope"] == "unit")
            .count()
    };
    assert_eq!(
        units(&whole),
        1,
        "the family is one group when nothing cuts"
    );

    std::fs::write(
        dir.path().join("codehelion.toml"),
        "[limits]\nmax-component = 3\n",
    )
    .expect("write the ceiling");
    let cut = scan_json(dir.path());
    assert_eq!(cut["summary"]["split_components"], 1, "{cut:#?}");

    // The ceiling may not split one normalized-content equivalence class. The
    // members are therefore retained as one primary group rather than three
    // position-dependent groups with the same stable clone fingerprint.
    assert_eq!(units(&cut), 1, "{cut:#?}");
    assert!(
        cut["groups"]
            .as_array()
            .expect("groups")
            .iter()
            .all(|group| group["split_pair"] == false),
        "{cut:#?}"
    );

    // No relation was actually severed: the normalized-content equivalence
    // class stayed atomic even though the component itself exceeded the
    // configured ceiling.
    let verified = cut["summary"]["funnel"]
        .as_array()
        .expect("a funnel")
        .iter()
        .find(|stage| stage["stage"] == "verified pairs")
        .expect("the funnel names the verification stage");
    assert!(
        verified["dropped"]
            .as_array()
            .expect("the stage accounts for what it dropped")
            .iter()
            .all(|drop| drop["cause"] != "the_ceiling_cut_the_set"),
        "an atomic equivalence class did not lose relations to the ceiling: {cut:#?}"
    );
}
