use super::*;

/// Fast and Structural each stay at their measured human-label precision.
///
/// The detailed structural test below additionally pins the ranking and every
/// aggregate diagnostic. This test has the narrower purpose of ensuring that
/// neither source-analysis mode can lose its measurement behind the other.
#[test]
fn every_labelled_corpus_stays_at_its_recorded_precision_in_each_mode() {
    let root = repo_root();
    let scratch = tempfile::tempdir().expect("temp dir");
    let mut table = String::from(
        "\nmode       corpus            precision  put forward  confirmed  refuted  unjudged  conflicts\n",
    );
    let mut complaints = String::new();
    let mut materialized = 0usize;
    for mode in ["fast", "structural"] {
        for expected in CORPORA {
            let corpus = root.join("corpus/labeled").join(expected.name);
            let labels_path = corpus.join("labels.json");
            let labels_text = std::fs::read_to_string(&labels_path)
                .unwrap_or_else(|error| panic!("reading {}: {error}", labels_path.display()));
            let labels = LabelSet::from_json(&labels_text).expect("labels parse");
            let snapshot = corpus.join("snapshot");
            if !snapshot.is_dir() {
                if expected.has_origin {
                    writeln!(
                        complaints,
                        "{mode} {} has a reproducible origin but no materialized snapshot",
                        expected.name,
                    )
                    .expect("writing to a string cannot fail");
                }
                continue;
            }
            materialized += 1;
            let database = scratch.path().join(format!("{mode}-{}.db", expected.name));
            let report = scan(&snapshot, mode, &database);
            let (result, _lines) = detected::from_report_json(&report).unwrap_or_else(|error| {
                panic!("reading the {mode} report for {}: {error}", expected.name)
            });
            let ruled = adjudicate(&result, &labels, DEFAULT_MATCH_THRESHOLD);
            let recorded = recorded_verdicts(expected, mode);
            writeln!(
                table,
                "{mode:<10} {:<16} {:>9} {:>12} {:>10} {:>8} {:>9} {:>10}",
                expected.name,
                show_measure(ruled.precision()),
                show_measure(ruled.actionable_precision()),
                ruled.confirmed,
                ruled.refuted,
                ruled.unjudged,
                ruled.conflicting,
            )
            .expect("writing to a string cannot fail");
            let measured = (
                ruled.confirmed,
                ruled.refuted,
                ruled.actionable_confirmed,
                ruled.actionable_refuted,
                ruled.unjudged,
                ruled.conflicting,
            );
            let pinned = (
                recorded.confirmed,
                recorded.refuted,
                recorded.forward_confirmed,
                recorded.forward_refuted,
                recorded.unjudged,
                recorded.conflicting,
            );
            if measured != pinned {
                writeln!(
                    complaints,
                    "{mode} {}: verdict split {measured:?}, recorded as {pinned:?}",
                    expected.name,
                )
                .expect("writing to a string cannot fail");
            }
        }
    }
    println!("{table}");
    assert!(
        materialized > 0,
        "no labelled corpus snapshot was materialized, so no precision was measured"
    );
    assert!(complaints.is_empty(), "\n{complaints}");
}

#[allow(clippy::too_many_lines)]
#[test]
fn every_labelled_group_still_gets_the_verdict_it_was_given() {
    let root = repo_root();
    let scratch = tempfile::tempdir().expect("temp dir");
    // "put forward" is precision over the findings the report asks to be read
    // first, which is the number a reader's first impression is made of. It
    // sits beside the overall figure rather than replacing it: the difference
    // between the two is what ranking a finding down is worth.
    let mut table = String::from(
        "\ncorpus            precision  put forward  confirmed  refuted  unjudged  conflicts\n",
    );
    let mut complaints = String::new();
    let mut unmaterialized = 0usize;
    let mut unmaterialized_with_origin = 0usize;
    // The same verdicts added up across every case that was scored. Nothing
    // here is pinned — each corpus's split already is, and this is their sum —
    // but no per-corpus row asks the question it answers, which is what ranking
    // a finding down does to the population it is applied to.
    let mut every = Adjudication {
        confirmed: 0,
        refuted: 0,
        conflicting: 0,
        unjudged: 0,
        actionable_confirmed: 0,
        actionable_refuted: 0,
    };
    let mut sizes = SizeSplit::default();
    let mut axes = AxisSplit::default();
    // Which corpora the "written once per width" rule reaches, and in total.
    let mut widths = String::from("\nwritten once per width\n");
    let mut every_width = WidthFamily::default();
    let mut bands = BandSplit::default();
    // Which classes of lookalike the report still shows, which is what says
    // where the next rule would have to work.
    let mut reasons = ReasonSplit::default();
    // Two orderings of the same verdicts: the one the tool prints, and the one
    // anybody would reach for without it.
    let mut ranked = RankedVerdicts::default();
    let mut by_size = RankedVerdicts::default();

    for expected in CORPORA {
        let corpus = root.join("corpus/labeled").join(expected.name);
        let labels_path = corpus.join("labels.json");
        let labels_text = std::fs::read_to_string(&labels_path)
            .unwrap_or_else(|error| panic!("reading {}: {error}", labels_path.display()));
        let labels = LabelSet::from_json(&labels_text).expect("labels parse");

        // The sources belong to the projects they came from and are not
        // committed here; the case records the commit they are cut from, and
        // the script rebuilds them. Say so rather than passing quietly.
        let snapshot = corpus.join("snapshot");
        if !snapshot.is_dir() {
            unscored_row(expected.name, &mut table);
            unmaterialized += 1;
            if expected.has_origin {
                unmaterialized_with_origin += 1;
                writeln!(
                    complaints,
                    "{} has a reproducible origin but no materialized snapshot",
                    expected.name,
                )
                .expect("writing to a string cannot fail");
            }
            continue;
        }

        let database = scratch.path().join(format!("{}.db", expected.name));
        let report = scan(&snapshot, "structural", &database);
        let (result, _lines) = detected::from_report_json(&report)
            .unwrap_or_else(|error| panic!("reading the report for {}: {error}", expected.name));

        let ruled = adjudicate(&result, &labels, DEFAULT_MATCH_THRESHOLD);
        row(expected.name, &ruled, &mut table);
        compare_verdicts(expected, &ruled, &mut complaints);
        for finding in result.findings.iter().filter(|finding| {
            verdict(finding, &labels, DEFAULT_MATCH_THRESHOLD) == Verdict::Unjudged
        }) {
            writeln!(
                complaints,
                "{} unjudged {} ({:?}, actionable={}):",
                expected.name, finding.id, finding.clone_type, finding.actionable,
            )
            .expect("writing to a string cannot fail");
            for fragment in &finding.fragments {
                writeln!(
                    complaints,
                    "  {}:{}-{} ({} tokens)",
                    fragment.file, fragment.start_line, fragment.end_line, fragment.tokens,
                )
                .expect("writing to a string cannot fail");
            }
        }
        if expected.has_origin {
            sizes.record(&result, &labels, DEFAULT_MATCH_THRESHOLD);
            axes.record(&result, &labels, DEFAULT_MATCH_THRESHOLD);
            width_family(
                expected.name,
                &snapshot,
                &result,
                &labels,
                &mut every_width,
                &mut widths,
                &mut complaints,
            );
            bands.record(&result, &labels, DEFAULT_MATCH_THRESHOLD);
            reasons.record(&result, &labels, DEFAULT_MATCH_THRESHOLD);
            ranked.record(&result, &labels, DEFAULT_MATCH_THRESHOLD, |finding| {
                finding.score
            });
            #[allow(clippy::cast_precision_loss)]
            by_size.record(
                &result,
                &labels,
                DEFAULT_MATCH_THRESHOLD,
                |finding: &Finding| finding.size_tokens as f64,
            );
            absorb(&mut every, &ruled);
        }
    }
    if every.judged() > 0 {
        row("reproducible cases", &every, &mut table);
    }

    // Every measure below this line accumulates across the whole corpus, so a
    // partial set produces a number that is not the recorded one and is not a
    // regression either. Print it, compare nothing.
    let whole = unmaterialized_with_origin == 0;
    if !ranked.is_empty() {
        report_ranking(&ranked, &by_size, whole, &mut complaints);
    }
    println!("{table}");
    if every.judged() > 0 {
        println!(
            "ranking down filed {} confirmed and {} refuted below the rest\n",
            every.confirmed - every.actionable_confirmed,
            every.refuted - every.actionable_refuted,
        );
    }
    print_measures(&sizes, &axes, &widths, &every_width, &bands, &reasons);
    if whole {
        compare_bands(&bands, &mut complaints);
        compare_reasons(&reasons, &mut complaints);
        compare_sizes(&sizes, &mut complaints);
        compare_floors(&axes, &mut complaints);
    } else {
        println!(
            "\n{unmaterialized_with_origin} reproducible labelled corpora have no snapshot, \
             so the aggregate measures were printed and not compared.\n\
             Run corpus/scripts/materialize-labeled.sh to cut them from their pinned commits.",
        );
    }
    if unmaterialized > 0 {
        println!(
            "\n{unmaterialized} labelled corpora were unmaterialized; local-only cases are \
             excluded from the aggregate precision population."
        );
    }
    assert!(
        has_materialized_snapshot(unmaterialized, CORPORA.len()),
        "no labelled corpus snapshot was materialized, so no precision was measured"
    );
    assert!(complaints.is_empty(), "\n{complaints}");
}
