//! The order entries are listed in, and which occurrence a group is
//! measured against.

use super::*;

#[test]
fn replay_order_uses_the_recorded_rank_down_verdict() {
    let ordinary = visible_group();
    let delayed = suppressed_group();
    let ordinary_id = ordinary.fingerprint.clone();
    let delayed_id = delayed.fingerprint.clone();
    let recorded = BTreeMap::from([(delayed_id.clone(), true), (ordinary_id.clone(), false)]);
    let mut groups = vec![delayed, ordinary];

    order_recorded(&mut groups, &recorded, Sort::Priority);

    assert_eq!(groups[0].fingerprint, ordinary_id);
    assert_eq!(groups[1].fingerprint, delayed_id);
}

/// Absent is not low. A mode that measures identifier agreement on some
/// entries and not others would otherwise report the unmeasured ones as
/// the least alike, which is a claim nothing was made about.
#[test]
fn an_entry_with_no_measurement_on_the_axis_is_listed_after_the_measured() {
    let mut measured = visible_group();
    measured.identifier_jaccard = Some(0.1);
    let mut unmeasured = suppressed_group();
    unmeasured.identifier_jaccard = None;

    assert_eq!(
        compare_on(&measured, &unmeasured, Sort::IdentifierJaccard),
        Ordering::Less,
    );
    assert_eq!(
        compare_on(&unmeasured, &measured, Sort::IdentifierJaccard),
        Ordering::Greater,
    );
}

/// A tie on the axis is the ordinary case rather than the corner: raw
/// identifier agreement pins whole cohorts at exactly 1.00. Leaving those to
/// the fingerprint would hand the reader the tier in hash order, so the
/// composed ranking decides inside a tie.
#[test]
fn entries_that_tie_on_the_axis_are_ordered_by_the_composed_ranking() {
    let mut stronger = visible_group();
    let mut weaker = suppressed_group();
    stronger.identifier_jaccard = Some(1.0);
    weaker.identifier_jaccard = Some(1.0);
    // The weaker entry takes the smaller fingerprint, so hash order and
    // ranking order disagree and only one of the two can be deciding.
    std::mem::swap(&mut stronger.fingerprint, &mut weaker.fingerprint);

    assert!(weaker.fingerprint < stronger.fingerprint);
    assert!(stronger.priority.value > weaker.priority.value);
    assert_eq!(
        compare_on(&stronger, &weaker, Sort::IdentifierJaccard),
        Ordering::Less,
    );
}

/// Two entries that tie on the axis and on the ranking still have to come out
/// in one order, or a reader citing a position cites a coin toss.
#[test]
fn entries_that_tie_on_the_axis_fall_back_to_the_stable_id() {
    let left = visible_group();
    let mut right = suppressed_group();
    right.priority = left.priority.clone();

    assert!(left.fingerprint < right.fingerprint);
    assert_eq!(compare_on(&left, &right, Sort::Priority), Ordering::Less);
}

#[test]
fn repeated_tokens_count_everything_past_the_copy_that_would_be_kept() {
    let group = visible_group();
    let total: u64 = group.members.iter().map(|member| member.tokens).sum();
    let canonical = group
        .members
        .iter()
        .find(|member| member.canonical)
        .expect("a canonical member")
        .tokens;
    assert_eq!(duplicated_tokens(&group), total - canonical);
}

/// A group whose stored members flag none of them is what a partially written
/// or hand-edited database holds. Every view still has to answer "which
/// occurrence is this group measured against" the same way, or a report, a
/// SARIF log and a frozen baseline describe three different occurrences of one
/// group.
#[test]
fn every_view_resolves_the_same_occurrence_when_no_member_is_flagged() {
    let mut report = sample_report();
    let mut group = visible_group();
    for member in &mut group.members {
        member.canonical = false;
    }
    let first = group.members[0].clone();
    let total: u64 = group.members.iter().map(|member| member.tokens).sum();
    let fingerprint = group.fingerprint.clone();
    report.groups = vec![group];

    let group = &report.groups[0];
    assert_eq!(
        canonical_member(group).map(|member| member.finding_id.as_str()),
        Some(first.finding_id.as_str()),
    );
    // The token count the listing prints is taken past that same occurrence.
    assert_eq!(duplicated_tokens(group), total - first.tokens);

    // The listing leads with that same occurrence, which is what its mark says
    // the group is measured against.
    let mut text = Vec::new();
    report
        .render_text(TextOptions::default(), &mut text)
        .unwrap();
    let text = String::from_utf8(text).unwrap();
    let leads = text.find(first.file.as_str());
    let follows = text.find(report.groups[0].members[1].file.as_str());
    assert!(leads.is_some() && leads < follows, "{text}");

    let sarif: serde_json::Value = serde_json::from_str(&report.to_sarif().unwrap()).unwrap();
    let result = &sarif["runs"][0]["results"][0];
    assert_eq!(
        result["partialFingerprints"]["cloneGroupFingerprint/v1"],
        fingerprint
    );
    let primary = &result["locations"][0];
    assert_eq!(
        primary["physicalLocation"]["region"]["startLine"],
        first.start_line
    );
    // The occurrence chosen as the primary location is the occurrence this log
    // calls canonical, and it is the only one.
    assert_eq!(primary["properties"]["canonical"], true);
    let related = result["relatedLocations"].as_array().unwrap();
    assert_eq!(
        related
            .iter()
            .filter(|location| location["properties"]["canonical"] == true)
            .count(),
        1,
    );
    assert_eq!(related[0]["properties"]["canonical"], true);
    assert!(
        related[0]["message"]["text"]
            .as_str()
            .unwrap()
            .contains("(canonical instance)")
    );
}
