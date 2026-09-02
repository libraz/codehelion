//! How the group listing is drawn and what its composition lines say.

use super::*;

/// The listing renders as text, with the options a caller passes.
fn rendered(report: &Report, opts: TextOptions) -> String {
    let mut buffer = Vec::new();
    report.render_text(opts, &mut buffer).unwrap();
    String::from_utf8(buffer).unwrap()
}

#[test]
fn text_view_truncates_with_an_explicit_count() {
    let mut buffer = Vec::new();
    sample_report()
        .render_text(TextOptions::default(), &mut buffer)
        .unwrap();
    let text = String::from_utf8(buffer).unwrap();
    assert!(text.contains("2 files, 40 lines, 200 tokens"), "{text}");
    // Every occurrence is listed under the group, canonical included, so the
    // seven stop at five and the count says what is missing.
    assert!(text.contains("... and 2 more occurrences"), "{text}");
    assert!(!text.contains("src/file6.rs"));
    assert!(!text.contains("vendor/a.rs")); // suppressed and not requested
    assert!(!text.contains('\x1b'));
}

#[test]
fn each_group_is_numbered_and_its_occurrences_hang_from_it() {
    let text = rendered(&sample_report(), TextOptions::default());
    assert!(text.contains(" #1  "), "{text}");
    assert!(text.contains("├─ "), "{text}");
    assert!(text.contains("└─ "), "{text}");
    // The number is what `explain` is offered against, so it exists for the
    // reader to name one entry among the others.
    let numbered = text.lines().filter(|line| line.contains('#')).count();
    assert!(numbered >= 1, "{text}");
}

#[test]
fn the_canonical_occurrence_leads_its_group_and_is_marked() {
    let text = rendered(&sample_report(), TextOptions::default());
    let occurrences: Vec<&str> = text
        .lines()
        .filter(|line| line.contains("src/file"))
        .collect();
    let first = occurrences.first().copied().unwrap_or_default();
    // file0 is the canonical member of the sample group.
    assert!(first.contains("src/file0.rs"), "{text}");
    assert!(first.contains('◆'), "{text}");
    // Exactly one occurrence carries the mark.
    assert_eq!(
        occurrences.iter().filter(|line| line.contains('◆')).count(),
        1,
        "{text}"
    );
}

#[test]
fn an_ascii_listing_carries_nothing_outside_ascii() {
    let text = rendered(
        &sample_report(),
        TextOptions {
            decoration: Decoration::Ascii,
            ..TextOptions::default()
        },
    );
    // The whole point of asking for it: a console that draws no box-drawing
    // character gets a report with none in it, heading and summary included.
    assert!(text.is_ascii(), "{text}");
    assert!(text.contains("|- "), "{text}");
    assert!(text.contains("`- "), "{text}");
}

#[test]
fn an_undecorated_listing_draws_no_glyphs_but_keeps_its_columns() {
    let text = rendered(
        &sample_report(),
        TextOptions {
            decoration: Decoration::None,
            ..TextOptions::default()
        },
    );
    // No tree, no marks: the occurrences are a plain indented list, which is
    // what something reading this report line by line wants.
    for glyph in ['├', '└', '◆', '×', '·'] {
        assert!(!text.contains(glyph), "{glyph} in {text}");
    }
    assert!(text.is_ascii(), "{text}");
    // The structure indentation and the columns still carry.
    assert!(text.contains(" #1  "), "{text}");
    assert!(text.contains("src/file0.rs"), "{text}");
}

#[test]
fn one_listings_headings_share_their_columns() {
    let mut report = sample_report();
    // A second group whose kind is wider than the first's, which is what
    // pushes every column right if the widths are measured per row.
    report.groups[1].suppressed = None;
    report.groups[1].scope = SCOPE_FRAGMENT.to_string();
    let text = rendered(&report, TextOptions::default());
    let headings: Vec<&str> = text
        .lines()
        .filter(|line| line.contains(" tokens  "))
        .collect();
    assert_eq!(headings.len(), 2, "{text}");
    let columns: Vec<Option<usize>> = headings.iter().map(|line| line.find(" tokens")).collect();
    assert_eq!(columns[0], columns[1], "{text}");
}

#[test]
fn the_report_closes_with_the_marks_it_used_and_what_to_type_next() {
    let text = rendered(&sample_report(), TextOptions::default());
    assert!(
        text.contains("◆ the occurrence a group is measured against"),
        "{text}"
    );
    assert!(text.contains("codehelion explain 0b0b0b0b"), "{text}");
    assert!(text.contains("--limit 0"), "{text}");
    // "run" is not a word this report used, so it is not a word this report
    // explains.
    assert!(!text.contains("\"run\""), "{text}");
}

#[test]
fn a_listing_of_runs_says_what_a_run_is() {
    let mut report = sample_report();
    report.groups[0].scope = SCOPE_FRAGMENT.to_string();
    let text = rendered(&report, TextOptions::default());
    assert!(text.contains("type-1 run ×"), "{text}");
    assert!(text.contains("\"run\" a repeated stretch"), "{text}");
}

#[test]
fn a_listing_says_what_the_count_after_the_heading_counts() {
    let text = rendered(&sample_report(), TextOptions::default());
    // The mark is on every heading, and reads as a multiple of the code until
    // the legend says it counts occurrences.
    assert!(text.contains("×N the number of occurrences"), "{text}");
}

#[test]
fn a_listing_of_nothing_explains_no_marks() {
    let mut report = sample_report();
    report.groups.clear();
    let text = rendered(&report, TextOptions::default());
    assert!(!text.contains("the number of occurrences"), "{text}");
    assert!(
        !text.contains("the occurrence a group is measured against"),
        "{text}"
    );
    assert!(!text.contains("codehelion explain"), "{text}");
}

/// One word must not name two populations in one view. The composition lines
/// count every group the report holds, while the legend counts the groups
/// `--limit` actually enumerated; calling both "listed" tells a reader the
/// listing holds groups it does not.
#[test]
fn the_composition_lines_do_not_call_an_unenumerated_population_listed() {
    let mut report = sample_report();
    report.summary.groups.total = 9;
    report.summary.groups.fragment_scope = 1;
    report.summary.groups.folded_runs = 4;
    report.summary.groups.test_code = 1;
    let text = rendered(&report, composition_detail());

    for line in text.lines().filter(|line| line.contains("reported group")) {
        assert!(
            !line.contains("listed group"),
            "a count of every group calls itself listed: {line}"
        );
    }
    assert!(text.contains("of the 9 reported groups"), "{text}");
    // The total is larger than what the listing enumerates, which is the case
    // the two words have to stay apart in.
    assert!(
        report.summary.groups.total > u64::try_from(report.groups.len()).unwrap(),
        "the fixture has to hold more groups than it lists"
    );
}

/// The depth at which the composition of the group total is written.
fn composition_detail() -> TextOptions {
    TextOptions {
        verbosity: 1,
        ..TextOptions::default()
    }
}

#[test]
fn each_part_of_the_group_total_names_the_total_it_is_part_of() {
    let mut report = sample_report();
    report.summary.groups.total = 3;
    report.summary.groups.fragment_scope = 1;
    report.summary.groups.folded_runs = 4;
    report.summary.groups.subsumed_runs = 2;
    report.summary.groups.test_code = 1;
    let text = rendered(&report, composition_detail());

    // Three of these counts are read against a different total, so no line
    // stands in for its total with a pronoun.
    assert!(!text.contains("of them"), "{text}");
    let line = |needle: &str| {
        text.lines()
            .find(|line| line.contains(needle))
            .unwrap_or_default()
            .to_string()
    };
    let runs = line("describe a repeated run");
    assert!(
        runs.contains("of the 3 reported groups, 1 describe"),
        "{text}"
    );
    let left_out = line("folded into groups that already cover them");
    assert!(
        left_out.contains("findings not among the 3 reported groups: 4 folded"),
        "{text}"
    );
    assert!(left_out.contains("2 covered by a longer finding"), "{text}");
    let suite = line("duplication inside test code");
    assert!(suite.contains("of the 3 reported groups, 1 are"), "{text}");

    // The breakdown shares no total with the suppression split, which stands
    // after it rather than reading as its heading.
    let suppressed = text
        .lines()
        .position(|line| line.contains("suppressed: "))
        .expect("the suppression split is written at this depth");
    let last_part = text
        .lines()
        .position(|line| line.contains("duplication inside test code"))
        .expect("the test-code part is written at this depth");
    assert!(suppressed > last_part, "{text}");
}

#[test]
fn runs_left_out_of_the_listing_are_named_only_when_there_were_some() {
    let mut report = sample_report();
    report.summary.groups.fragment_scope = 1;
    let text = rendered(&report, composition_detail());
    assert!(!text.contains("findings not among the"), "{text}");

    report.summary.groups.folded_runs = 4;
    let folded = rendered(&report, composition_detail());
    assert!(
        folded.contains(
            "findings not among the 2 reported groups: 4 folded into groups that already \
             cover them\n"
        ),
        "{folded}"
    );

    report.summary.groups.folded_runs = 0;
    report.summary.groups.subsumed_runs = 2;
    let subsumed = rendered(&report, composition_detail());
    assert!(
        subsumed
            .contains("findings not among the 2 reported groups: 2 covered by a longer finding\n"),
        "{subsumed}"
    );
}

#[test]
fn the_parts_of_the_group_total_are_written_with_thousands_separators() {
    let mut report = sample_report();
    report.summary.groups.total = 10_853;
    report.summary.groups.fragment_scope = 1_036;
    report.summary.groups.folded_runs = 3_070;
    report.summary.groups.subsumed_runs = 1_423;
    report.summary.groups.test_code = 8_087;
    report.summary.suppressed.noise = 1_811;
    report.summary.suppressed.by_rule = 1_640;
    let text = rendered(&report, composition_detail());
    // A count written one way in the headline and another in the breakdown
    // reads as a count of something else.
    for written in [
        "10,853", "1,036", "3,070", "1,423", "8,087", "1,811", "1,640",
    ] {
        assert!(text.contains(written), "{written} in {text}");
    }
}

#[test]
fn a_quiet_listing_is_the_groups_alone() {
    let text = rendered(
        &sample_report(),
        TextOptions {
            quiet: true,
            ..TextOptions::default()
        },
    );
    assert!(!text.contains("codehelion scan"), "{text}");
    assert!(
        !text.contains("the occurrence a group is measured against"),
        "{text}"
    );
    assert!(!text.contains("codehelion explain"), "{text}");
    assert!(text.contains("src/file0.rs"), "{text}");
}

#[test]
fn text_view_states_each_groups_file_spread() {
    let mut report = sample_report();
    report.groups[0].priority.inputs.files = 1;
    report.groups[1].priority.inputs.files = 2;
    report.groups[1].priority.inputs.directories = 1;
    report.groups[1].suppressed = None;
    let mut third = fragment_group();
    third.priority.inputs.files = 2;
    third.priority.inputs.directories = 2;
    report.groups.push(third);

    let mut buffer = Vec::new();
    report
        .render_text(
            TextOptions {
                verbosity: 1,
                ..TextOptions::default()
            },
            &mut buffer,
        )
        .unwrap();
    let text = String::from_utf8(buffer).unwrap();
    assert!(text.contains("within one file,"), "{text}");
    assert!(text.contains("within one directory,"), "{text}");
    assert!(text.contains("across directories,"), "{text}");
}

#[test]
fn verbose_text_lists_every_member_and_suppressed_section_is_opt_in() {
    let opts = TextOptions {
        limit: Some(0),
        show_suppressed: true,
        ..TextOptions::default()
    };
    let mut buffer = Vec::new();
    sample_report().render_text(opts, &mut buffer).unwrap();
    let text = String::from_utf8(buffer).unwrap();
    assert!(text.contains("src/file6.rs"));
    assert!(!text.contains("more occurrences"));
    assert!(text.contains("suppressed groups:"));
    assert!(text.contains("[suppressed: path glob \"vendor/**\"]"));
}

#[test]
fn suppressed_text_listing_has_the_same_default_cap_as_visible_groups() {
    let mut report = sample_report();
    for index in 0..TEXT_GROUP_LIMIT {
        let mut group = suppressed_group();
        group.fingerprint = format!("{index:032x}");
        report.groups.push(group);
    }

    let render = |limit| {
        let mut buffer = Vec::new();
        report
            .render_text(
                TextOptions {
                    limit,
                    show_suppressed: true,
                    ..TextOptions::default()
                },
                &mut buffer,
            )
            .unwrap();
        String::from_utf8(buffer).unwrap()
    };
    assert!(render(None).contains("... and 1 more suppressed group"));
    assert!(!render(Some(0)).contains("more suppressed groups"));
}

#[test]
fn the_pipeline_counts_are_detail_the_verbose_view_asks_for() {
    let render = |verbosity| {
        let opts = TextOptions {
            verbosity,
            ..TextOptions::default()
        };
        let mut buffer = Vec::new();
        sample_report().render_text(opts, &mut buffer).unwrap();
        String::from_utf8(buffer).unwrap()
    };
    let verbose = render(2);
    assert!(verbose.contains("candidate pipeline:"));
    assert!(verbose.contains("tokens"));
    assert!(verbose.contains("(dropped: overshared values 3)"));
    // A cause that dropped nothing says nothing.
    assert!(!verbose.contains("hash collision"));
    assert!(!render(1).contains("candidate pipeline:"));
    assert!(!render(0).contains("candidate pipeline:"));
}

#[test]
fn colored_text_uses_ansi_codes_only_when_enabled() {
    let opts = TextOptions {
        color: true,
        ..TextOptions::default()
    };
    let mut buffer = Vec::new();
    sample_report().render_text(opts, &mut buffer).unwrap();
    let text = String::from_utf8(buffer).unwrap();
    assert!(text.contains("\x1b[1mcodehelion scan · fast mode · /work/project\x1b[0m"));
    assert!(text.contains("\x1b[36m"));
}

#[test]
fn the_quiet_view_prints_the_groups_and_nothing_around_them() {
    let opts = TextOptions {
        quiet: true,
        ..TextOptions::default()
    };
    let mut buffer = Vec::new();
    sample_report().render_text(opts, &mut buffer).unwrap();
    let text = String::from_utf8(buffer).unwrap();
    assert!(text.contains("src/file0.rs:1-9"), "{text}");
    assert!(!text.contains("codehelion scan"), "{text}");
    assert!(!text.contains("sorted by"), "{text}");
    assert!(!text.contains("replay"), "{text}");
}

/// An id a report prints has to be one the lookup accepts, so the listing
/// abbreviates to exactly the prefix `codehelion explain` takes and no less.
#[test]
fn the_listing_abbreviates_identifiers_and_the_diagnostic_view_spells_them_out() {
    let report = sample_report();
    let fingerprint = report.groups[0].fingerprint.clone();

    let render = |verbosity| {
        let mut buffer = Vec::new();
        report
            .render_text(
                TextOptions {
                    verbosity,
                    ..TextOptions::default()
                },
                &mut buffer,
            )
            .unwrap();
        String::from_utf8(buffer).unwrap()
    };
    let listed = render(0);
    assert!(listed.contains(&fingerprint[..crate::suppress::MIN_CLONE_ID_CHARS]));
    assert!(!listed.contains(&fingerprint), "{listed}");
    assert!(render(2).contains(&fingerprint));
}

#[test]
fn the_group_limit_is_separate_from_how_much_each_group_says() {
    let mut report = sample_report();
    for index in 0..TEXT_GROUP_LIMIT {
        let mut group = visible_group();
        group.fingerprint = format!("{index:032x}");
        report.groups.push(group);
    }

    let render = |limit| {
        let mut buffer = Vec::new();
        report
            .render_text(
                TextOptions {
                    limit,
                    ..TextOptions::default()
                },
                &mut buffer,
            )
            .unwrap();
        String::from_utf8(buffer).unwrap()
    };
    assert!(
        render(None).contains("... and 1 more group (--limit 0 lists every one)"),
        "{}",
        render(None)
    );
    assert!(
        render(Some(2)).contains("... and 9 more groups"),
        "{}",
        render(Some(2))
    );
    assert!(
        !render(Some(0)).contains("more group"),
        "{}",
        render(Some(0))
    );
}

#[test]
fn a_scored_group_reports_every_dimension_and_marks_the_absent_one() {
    let mut report = sample_report();
    report.summary.groups.type_3 = 1;
    report.groups.push(structural_group());
    let value: serde_json::Value = serde_json::from_str(&report.to_json().unwrap()).unwrap();

    let similarity = &value["groups"][2]["similarity"];
    assert_eq!(similarity["composite"], 0.82);
    assert_eq!(similarity["min_pairwise"], 0.79);
    assert_eq!(similarity["weight_version"], "structural-verify-v1");
    assert_eq!(similarity["confidence_band"], "medium");
    assert_eq!(value["groups"][2]["entropy_bits"], 5.4);
    assert_eq!(value["groups"][2]["identifier_jaccard"], 0.5);
    assert_eq!(
        value["groups"][2]["priority"]["inputs"]["identifier_jaccard"],
        0.5
    );
    assert_eq!(
        value["groups"][2]["priority"]["inputs"]["api_similarity"],
        0.75
    );
    assert_eq!(value["groups"][2]["body_materiality"]["call_count"], 3);
    // Unavailable, not guessed: the dimension is reported as absent.
    assert_eq!(similarity["type_similarity"], serde_json::Value::Null);
    // A mode that scores no dimensions says so rather than omitting the key.
    assert_eq!(value["groups"][0]["similarity"], serde_json::Value::Null);
    assert_eq!(value["summary"]["groups"]["type_3"], 1);

    let mut buffer = Vec::new();
    report
        .render_text(
            TextOptions {
                verbosity: 1,
                ..TextOptions::default()
            },
            &mut buffer,
        )
        .unwrap();
    let text = String::from_utf8(buffer).unwrap();
    // A type this mode reported none of is left out rather than printed
    // as a zero the eye has to dismiss.
    assert!(text.contains("type-1 2, type-3 1"), "{text}");
    assert!(!text.contains("type-2 0"), "{text}");
    assert!(text.contains(
        "similarity: composite 0.82 (lexical 0.71, structural 0.88, \
         control-flow 0.90, type n/a, api 0.75); cohesion 0.79; \
         confidence medium [structural-verify-v1]"
    ));
    // On the heading, beside the value the default order reads, because a
    // reader following identifier agreement needs it where the ordering
    // can be checked against it.
    assert!(text.contains("identifiers 0.50"));
    assert!(text.contains("body evidence: loop yes"));
    assert!(text.contains("content entropy: 5.40 bits"));
}

#[test]
fn unmeasured_control_flow_is_json_null_and_text_na() {
    let mut report = sample_report();
    report.groups.push(structural_group());
    let similarity = report.groups[2]
        .similarity
        .as_mut()
        .expect("the structural sample has a similarity breakdown");
    similarity.control_flow = None;

    let value: serde_json::Value = serde_json::from_str(&report.to_json().unwrap()).unwrap();
    assert_eq!(
        value["groups"][2]["similarity"]["control_flow"],
        serde_json::Value::Null
    );

    let mut buffer = Vec::new();
    report
        .render_text(
            TextOptions {
                verbosity: 1,
                ..TextOptions::default()
            },
            &mut buffer,
        )
        .unwrap();
    let text = String::from_utf8(buffer).unwrap();
    assert!(text.contains("control-flow n/a"));
}

#[test]
fn an_unrecorded_confidence_band_prints_as_absent() {
    let similarity = Similarity {
        weight_version: "structural-verify-v1".to_string(),
        lexical: 0.5,
        structural: 0.5,
        control_flow: Some(0.5),
        type_similarity: None,
        api: Some(0.5),
        composite: 0.5,
        min_pairwise: 0.5,
        confidence_band: None,
    };
    assert!(similarity.line().contains("confidence n/a"));
}

#[test]
fn identifier_floor_reports_the_exact_unmeasured_count() {
    let mut report = sample_report();
    let mut measured = structural_group();
    measured.identifier_jaccard = Some(0.5);
    report.groups.push(measured);

    let mut rendered = Vec::new();
    report
        .render_text(
            TextOptions {
                min_identifier_jaccard: Some(0.9),
                ..TextOptions::default()
            },
            &mut rendered,
        )
        .unwrap();
    let rendered = String::from_utf8(rendered).unwrap();
    assert!(
        rendered.contains(
            "2 group(s) are not listed: raw identifier agreement below 0.90 (1 of them were not measured in this mode)"
        ),
        "{rendered}"
    );
}

#[test]
fn the_legend_opens_a_group_the_identifier_floor_left_listed() {
    let mut report = sample_report();
    let mut measured = structural_group();
    measured.identifier_jaccard = Some(0.95);
    report.groups.push(measured);

    let mut rendered = Vec::new();
    report
        .render_text(
            TextOptions {
                min_identifier_jaccard: Some(0.9),
                ..TextOptions::default()
            },
            &mut rendered,
        )
        .unwrap();
    let rendered = String::from_utf8(rendered).unwrap();
    let legend = rendered
        .lines()
        .find(|line| line.contains("open one:"))
        .expect("a listing offers the group it listed");
    assert!(legend.contains("0d0d0d0d"), "{legend}");
    assert!(!legend.contains("0b0b0b0b"), "{legend}");
}

#[test]
fn a_listing_the_identifier_floor_emptied_offers_nothing_to_open() {
    let mut rendered = Vec::new();
    sample_report()
        .render_text(
            TextOptions {
                min_identifier_jaccard: Some(0.9),
                ..TextOptions::default()
            },
            &mut rendered,
        )
        .unwrap();
    let rendered = String::from_utf8(rendered).unwrap();
    assert!(!rendered.contains("open one:"), "{rendered}");
}

#[test]
fn identifier_floor_omits_unmeasured_clause_when_every_group_has_a_measure() {
    let mut report = sample_report();
    report.groups[0].identifier_jaccard = Some(0.5);
    let mut measured = structural_group();
    measured.identifier_jaccard = Some(0.6);
    report.groups.push(measured);

    let mut rendered = Vec::new();
    report
        .render_text(
            TextOptions {
                min_identifier_jaccard: Some(0.9),
                ..TextOptions::default()
            },
            &mut rendered,
        )
        .unwrap();
    let rendered = String::from_utf8(rendered).unwrap();
    assert!(
        rendered.contains("2 group(s) are not listed: raw identifier agreement below 0.90\n"),
        "{rendered}"
    );
    assert!(
        !rendered.contains("not measured in this mode"),
        "{rendered}"
    );
}

#[test]
fn identifier_floor_names_no_threshold_when_the_mode_measured_none() {
    // A mode that measures no identifier agreement leaves nothing below the
    // floor, so a threshold is not one of the reasons a group is missing.
    let mut rendered = Vec::new();
    sample_report()
        .render_text(
            TextOptions {
                min_identifier_jaccard: Some(0.9),
                ..TextOptions::default()
            },
            &mut rendered,
        )
        .unwrap();
    let rendered = String::from_utf8(rendered).unwrap();
    assert!(
        rendered.contains(
            "1 group(s) are not listed: raw identifier agreement is not measured in this mode"
        ),
        "{rendered}"
    );
    assert!(
        !rendered.contains("raw identifier agreement below"),
        "{rendered}"
    );
}
