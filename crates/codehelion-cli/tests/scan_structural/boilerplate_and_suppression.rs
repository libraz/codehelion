use super::*;

#[test]
fn structural_entropy_floor_marks_and_persists_low_entropy_noise() {
    let dir = fixture();
    std::fs::write(
        dir.path().join("codehelion.toml"),
        "entropy-ratio-floor = 1.0\n",
    )
    .unwrap();

    let report = scan_json(dir.path());
    let groups = report["groups"].as_array().expect("groups");
    assert!(!groups.is_empty());
    assert!(groups.iter().all(|group| {
        group["suppressed"]["kind"] == "noise" && group["suppressed"]["reason"] == "low-entropy"
    }));
    assert!(
        report["run"]["detector_versions"]
            .as_array()
            .expect("detector versions")
            .iter()
            .any(|version| {
                version["component"] == "entropy-ratio"
                    && version["version"] == "entropy-ratio-v1:1.000000"
            })
    );

    let store = open_store(dir.path());
    let run = store.latest_run().unwrap().expect("recorded run");
    let stored = store.run_groups(run.id).unwrap();
    assert!(!stored.is_empty());
    assert!(
        stored
            .iter()
            .all(|group| group.suppress_reason.as_deref() == Some("low-entropy"))
    );
}

/// Two routines that are nothing but macro invocations: a duplicate a reader
/// would not act on, and larger than the real clone above so ranking, not
/// size, decides where it lands.
const DUMP_A: &str = "pub fn dump_config(config: &Config) {
    println!(\"a: {}\", config.a);
    println!(\"b: {}\", config.b);
    println!(\"c: {}\", config.c);
    println!(\"d: {}\", config.d);
    println!(\"e: {}\", config.e);
    println!(\"f: {}\", config.f);
    println!(\"g: {}\", config.g);
    println!(\"h: {}\", config.h);
}
";

const DUMP_B: &str = "pub fn dump_limits(limits: &Limits) {
    println!(\"a: {}\", limits.a);
    println!(\"b: {}\", limits.b);
    println!(\"c: {}\", limits.c);
    println!(\"d: {}\", limits.d);
    println!(\"e: {}\", limits.e);
    println!(\"f: {}\", limits.f);
    println!(\"g: {}\", limits.g);
    println!(\"h: {}\", limits.h);
}
";

/// Two folds of the same shape, one per integer width — what a language
/// without a way to write the family once forces an author to type twice.
/// Every name that differs does so by the width, and no constant moves.
const FOLD_32: &str = "pub fn fold_u32(bytes: &[u8]) -> u32 {
    let mut acc: u32 = 0;
    for byte in bytes {
        acc = acc.rotate_left(5);
        acc ^= u32::from(*byte);
        acc = acc.wrapping_mul(31);
    }
    acc
}
";

const FOLD_64: &str = "pub fn fold_u64(bytes: &[u8]) -> u64 {
    let mut acc: u64 = 0;
    for byte in bytes {
        acc = acc.rotate_left(5);
        acc ^= u64::from(*byte);
        acc = acc.wrapping_mul(31);
    }
    acc
}
";

#[test]
fn a_family_written_once_per_width_is_named_and_withheld() {
    let dir = fixture();
    std::fs::write(dir.path().join("src/fold32.rs"), FOLD_32).unwrap();
    std::fs::write(dir.path().join("src/fold64.rs"), FOLD_64).unwrap();
    let value = scan_json(dir.path());
    let groups = value["groups"].as_array().unwrap();

    let family = groups
        .iter()
        .find(|group| group["width_family"] == serde_json::json!(true))
        .expect("the two folds are one family");
    // Hidden, and the rule that hid it says which judgement it was rather
    // than leaving the reader to guess from the shape of the members.
    assert_eq!(family["suppressed"]["scope"], "ast_pattern");
    assert_eq!(family["suppressed"]["pattern"], "width-family");
    assert_eq!(
        family["suppressed"]["reason"],
        "one routine per integer width"
    );
    assert_eq!(family["suppressed"]["active"], true);

    let run = value["run"]["run_id"]
        .as_i64()
        .expect("scan JSON carries the recorded run id");
    let replay = cmd()
        .current_dir(dir.path())
        .args(["report", "--run", &run.to_string(), "--format", "json"])
        .output()
        .expect("replay recorded report");
    assert!(replay.status.success(), "{replay:?}");
    let replay: serde_json::Value =
        serde_json::from_slice(&replay.stdout).expect("replayed report is JSON");
    let replay_family = replay["groups"]
        .as_array()
        .expect("groups are an array")
        .iter()
        .find(|group| group["width_family"] == serde_json::json!(true))
        .expect("the width family remains in the recorded report");
    assert_eq!(replay_family["suppressed"], family["suppressed"]);

    cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "--mode", "structural", "--show-suppressed"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "[suppressed: one routine per integer width: width-family]",
        ));
    // Nothing else in the fixture reads as one: the claim is about these two
    // bodies, not about anything that merely looks alike.
    assert_eq!(
        groups
            .iter()
            .filter(|group| group["width_family"] == serde_json::json!(true))
            .count(),
        1
    );

    let store = open_store(dir.path());
    let run = store.latest_run().unwrap().expect("a recorded run");
    let stored = store.run_groups(run.id).unwrap();
    assert!(
        stored.iter().any(|group| group.width_family),
        "what the group is was recorded, not only what the report did with it"
    );
}

#[test]
fn one_member_that_is_a_plain_copy_stops_the_group_being_a_family() {
    let dir = fixture();
    std::fs::write(dir.path().join("src/fold32.rs"), FOLD_32).unwrap();
    std::fs::write(dir.path().join("src/fold64.rs"), FOLD_64).unwrap();
    // The same routine again under a name that has nothing to do with a width.
    // Two of the three members are still a width apart; the group is not, and
    // hiding it would hide a copy somebody made by hand.
    std::fs::write(
        dir.path().join("src/digest.rs"),
        FOLD_32.replace("fold_u32", "digest_bytes"),
    )
    .unwrap();
    let value = scan_json(dir.path());

    let family = value["groups"]
        .as_array()
        .unwrap()
        .iter()
        .find(|group| group["width_family"] == serde_json::json!(true));
    assert!(
        family.is_none(),
        "a group holding a hand-made copy is not one routine written per width"
    );
}

/// Two units whose answer a feature flag picks. Nothing in either body chooses
/// between the two returns, because the attribute that does never reaches the
/// IR — which is what makes them alike, and what makes the likeness worthless.
const FLAGGED_A: &str = "pub fn entries(map: &Map) -> usize {
    #[cfg(feature = \"ordered\")]
    return map.ordered_len();
    #[cfg(not(feature = \"ordered\"))]
    return map.plain_len();
}
";

const FLAGGED_B: &str = "pub fn slots(map: &Map) -> usize {
    #[cfg(feature = \"ordered\")]
    return map.ordered_slots();
    #[cfg(not(feature = \"ordered\"))]
    return map.plain_slots();
}
";

#[test]
fn a_body_the_build_configuration_answers_for_is_named_and_withheld() {
    let dir = fixture();
    std::fs::write(dir.path().join("src/entries.rs"), FLAGGED_A).unwrap();
    std::fs::write(dir.path().join("src/slots.rs"), FLAGGED_B).unwrap();
    let value = scan_json(dir.path());
    let groups = value["groups"].as_array().unwrap();

    let configured = groups
        .iter()
        .find(|group| group["boilerplate"] == serde_json::json!("configured-answer"))
        .expect("two bodies a feature flag answers for");
    assert!(
        configured["suppressed"].is_object(),
        "hidden by default, and the suppressed section still lists it"
    );

    let store = open_store(dir.path());
    let run = store.latest_run().unwrap().expect("a recorded run");
    let stored = store.run_groups(run.id).unwrap();
    assert!(
        stored
            .iter()
            .any(|group| group.boilerplate.as_deref() == Some("configured-answer")),
        "what the group is was recorded, not only what the report did with it"
    );
}

#[test]
fn an_arm_that_does_work_is_not_the_configuration_answering() {
    let dir = fixture();
    // The same pair of arms, with one of them computing its answer. That work
    // is written once per configuration, which is duplication worth reading.
    let working = FLAGGED_A.replace(
        "    #[cfg(feature = \"ordered\")]",
        "    let scale = map.scale();\n    #[cfg(feature = \"ordered\")]",
    );
    std::fs::write(dir.path().join("src/entries.rs"), &working).unwrap();
    std::fs::write(
        dir.path().join("src/slots.rs"),
        working
            .replace("entries", "slots")
            .replace("_len", "_slots"),
    )
    .unwrap();
    let value = scan_json(dir.path());

    assert!(
        value["groups"]
            .as_array()
            .unwrap()
            .iter()
            .all(|group| group["boilerplate"] != serde_json::json!("configured-answer")),
        "an arm that computes is not an answer the build picked"
    );
}

fn fixture_with_boilerplate() -> tempfile::TempDir {
    let dir = fixture();
    std::fs::write(dir.path().join("src/dump_a.rs"), DUMP_A).unwrap();
    std::fs::write(dir.path().join("src/dump_b.rs"), DUMP_B).unwrap();
    dir
}

#[test]
fn boilerplate_is_named_and_ranked_below_code_that_carries_behaviour() {
    let dir = fixture_with_boilerplate();
    let value = scan_json(dir.path());
    let groups = value["groups"].as_array().unwrap();

    let position = |category: serde_json::Value| {
        groups
            .iter()
            .position(|group| group["boilerplate"] == category)
            .unwrap_or_else(|| panic!("a group with boilerplate {category}"))
    };
    let boilerplate = position(serde_json::json!("macro-repetition"));
    let behaviour = position(serde_json::Value::Null);
    assert!(
        behaviour < boilerplate,
        "the gapped clone outranks the larger run of macro invocations"
    );
    // Ranked down, not hidden, and its size is reported unchanged: the
    // ranking moved, the measurements did not.
    assert_eq!(groups[boilerplate]["suppressed"], serde_json::Value::Null);
    assert!(
        groups[boilerplate]["priority"]["value"].as_f64().unwrap()
            > groups[behaviour]["priority"]["value"].as_f64().unwrap()
    );

    // The classifier's rules are versioned like every other detector.
    assert!(
        value["run"]["detector_versions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["component"] == "boilerplate")
    );

    let store = open_store(dir.path());
    let run = store.latest_run().unwrap().expect("a recorded run");
    let stored = store.run_groups(run.id).unwrap();
    assert!(
        stored
            .iter()
            .any(|group| group.boilerplate.as_deref() == Some("macro-repetition")),
        "the classification is recorded, not just displayed"
    );
    let macro_group = stored
        .iter()
        .find(|group| group.boilerplate.as_deref() == Some("macro-repetition"))
        .expect("the recorded macro group");
    assert!(
        macro_group
            .members
            .iter()
            .all(|member| member.boilerplate.as_deref() == Some("macro-repetition")),
        "each member says why the group is classified"
    );

    let output = cmd()
        .current_dir(dir.path())
        .args(["report", "--run", &run.id.to_string(), "--format", "json"])
        .output()
        .expect("reformat the recorded structural run");
    assert!(output.status.success(), "{output:?}");
    let recorded: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("recorded report is JSON");
    assert!(
        recorded["groups"]
            .as_array()
            .expect("recorded groups")
            .iter()
            .filter(|group| group["boilerplate"] == "macro-repetition")
            .flat_map(|group| group["members"].as_array().into_iter().flatten())
            .all(|member| member["boilerplate"] == "macro-repetition"),
        "reformatting reads the member classification from SQLite"
    );
}

#[test]
fn a_hidden_boilerplate_category_is_recorded_with_the_rule_that_hid_it() {
    let dir = fixture_with_boilerplate();
    std::fs::write(
        dir.path().join("codehelion.toml"),
        "[suppression.boilerplate]\nmacro-repetition = \"hide\"\n",
    )
    .unwrap();
    cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "--mode", "structural", "-v"])
        .assert()
        .success()
        .stdout(predicate::str::contains("1 by rule"))
        .stdout(predicate::str::contains("dump_config").not());

    // Hidden, not deleted: the finding names the rule that hid it.
    let store = open_store(dir.path());
    let run = store.latest_run().unwrap().expect("a recorded run");
    let findings = store.run_findings(run.id).unwrap();
    assert!(
        findings
            .iter()
            .any(|f| f.suppression_scope.as_deref() == Some("ast_pattern")),
    );
    assert!(
        store
            .run_groups(run.id)
            .unwrap()
            .iter()
            .any(|group| group.boilerplate.as_deref() == Some("macro-repetition"))
    );

    cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "--mode", "structural", "--show-suppressed"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "[suppressed: boilerplate shape: macro-repetition]",
        ));
}

#[test]
fn a_symbol_glob_hides_a_group_only_when_it_names_every_member() {
    let dir = fixture();
    // beta is the gapped copy of alpha; naming one of the two leaves the
    // duplication actionable.
    std::fs::write(
        dir.path().join("codehelion.toml"),
        "[suppression]\nsymbols = [\"beta\"]\n",
    )
    .unwrap();
    cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "--mode", "structural", "-v"])
        .assert()
        .success()
        .stdout(predicate::str::contains("0 by rule"))
        .stdout(predicate::str::contains("src/a.rs"));

    std::fs::write(
        dir.path().join("codehelion.toml"),
        "[suppression]\nsymbols = [\"alpha\", \"beta\"]\n",
    )
    .unwrap();
    cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "--mode", "structural", "-v"])
        .assert()
        .success()
        .stdout(predicate::str::contains("1 by rule"))
        .stdout(predicate::str::contains("src/a.rs").not());

    let store = open_store(dir.path());
    let run = store.latest_run().unwrap().expect("a recorded run");
    assert!(
        store
            .run_findings(run.id)
            .unwrap()
            .iter()
            .any(|f| f.suppression_scope.as_deref() == Some("symbol_pattern"))
    );
}

#[test]
fn a_clone_id_hides_exactly_the_group_it_names() {
    let dir = fixture();
    let report = scan_json(dir.path());
    let fingerprint = report["groups"][0]["fingerprint"]
        .as_str()
        .expect("a detected group")
        .to_string();

    // An id that identifies no group changes nothing.
    std::fs::write(
        dir.path().join("codehelion.toml"),
        "[suppression]\nclone-ids = [\"deadbeefdeadbeef\"]\n",
    )
    .unwrap();
    cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "--mode", "structural", "-v"])
        .assert()
        .success()
        .stdout(predicate::str::contains("0 by rule"));

    // A prefix of the reported id hides that group, and says so.
    let prefix = &fingerprint[..12];
    std::fs::write(
        dir.path().join("codehelion.toml"),
        format!("[suppression]\nclone-ids = [\"{prefix}\"]\n"),
    )
    .unwrap();
    cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "--mode", "structural", "-v"])
        .assert()
        .success()
        .stdout(predicate::str::contains("1 by rule"))
        .stdout(predicate::str::contains(fingerprint.as_str()).not());

    let store = open_store(dir.path());
    let run = store.latest_run().unwrap().expect("a recorded run");
    assert!(
        store
            .run_findings(run.id)
            .unwrap()
            .iter()
            .any(|f| f.suppression_scope.as_deref() == Some("stable_clone_id"))
    );

    cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "--mode", "structural", "--show-suppressed"])
        .assert()
        .success()
        .stdout(predicate::str::contains(format!(
            "[suppressed: clone id {prefix}]"
        )));
}

#[test]
fn a_clone_id_that_could_not_identify_a_group_fails_the_scan() {
    let dir = fixture();
    std::fs::write(
        dir.path().join("codehelion.toml"),
        "[suppression]\nclone-ids = [\"abc\"]\n",
    )
    .unwrap();
    cmd()
        .current_dir(dir.path())
        .args(["scan", ".", "--mode", "structural"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("shorter than"));
}
