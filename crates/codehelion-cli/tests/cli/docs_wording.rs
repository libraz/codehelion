//! Tests that read the shipped documents and assert the wording they carry.
//!
//! They are kept together because they share one failure mode: an assertion
//! looks for a fixed substring, so re-wrapping an English paragraph in
//! `docs/` splits that substring across a line break and the test fails on a
//! sentence nobody meant to change. When that happens, this file is the one
//! place to look.
//!
//! The `include_str!` paths are relative to this file, so they carry one more
//! `..` than a document reference written in a top-level test would.

#[test]
fn command_line_documents_state_the_operations_flags_and_exit_statuses() {
    for document in [
        include_str!("../../../../docs/en/cli.md"),
        include_str!("../../../../docs/ja/cli.md"),
    ] {
        for snippet in [
            "codehelion report --run 1",
            "codehelion explain <ID> --format json",
            "codehelion baseline create",
            "codehelion config show",
            "codehelion artifact report --analysis 1",
            "codehelion artifact calibration --source-run 1",
            "--debug-file companion",
            "--jobs <n>",
            "--db <path>",
            "--baseline <file>",
            "--config <file>",
            "--no-ignore",
            "--show-suppressed",
            "--include-trivial",
            "--fail-on-findings",
            "--compare-build-variants",
            "--compare-languages",
            "`3`:",
        ] {
            assert!(
                document.contains(snippet),
                "the command-line document is missing {snippet}"
            );
        }
    }
}

/// How the artifact document names one format in prose, in English and
/// Japanese.
///
/// Matched exhaustively: a format added to the enum stops this compiling until
/// it says how a reader is told about it, which is what stops a format
/// shipping that the documents never mention.
const fn document_names(format: codehelion_artifact::ArtifactFormat) -> [&'static str; 2] {
    use codehelion_artifact::ArtifactFormat;
    match format {
        ArtifactFormat::Wasm => ["WASM", "WASM"],
        ArtifactFormat::Elf => ["ELF", "ELF"],
        ArtifactFormat::MachO => ["Mach-O", "Mach-O"],
        ArtifactFormat::PeCoff => ["PE/COFF", "PE/COFF"],
        ArtifactFormat::Archive => ["static archives", "静的アーカイブ"],
    }
}

/// The formats a capability holds for, as each artifact document lists them.
fn named_formats(
    holds: impl Fn(&codehelion_artifact::ArtifactCapabilities) -> bool,
) -> [String; 2] {
    let mut listed: [Vec<&str>; 2] = [Vec::new(), Vec::new()];
    for row in &codehelion_artifact::FORMAT_SUPPORT {
        if !holds(&row.capabilities) {
            continue;
        }
        for (language, name) in document_names(row.format).into_iter().enumerate() {
            listed[language].push(name);
        }
    }
    [english_list(&listed[0]), listed[1].join("、")]
}

/// Names joined the way English prose joins them.
fn english_list(names: &[&str]) -> String {
    match names {
        [] => String::new(),
        [only] => (*only).to_string(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
}

/// Both artifact documents name every format this build reads, and name the
/// right ones as supplying each derived quantity.
///
/// The lists are written out of the support definitions rather than copied
/// from them: a format added there, or a capability moved between formats,
/// fails here until the documents say the same thing. What stays prose is the
/// sentence around the lists.
#[test]
fn artifact_documents_name_every_format_and_what_each_one_supplies() {
    let documents = [
        include_str!("../../../../docs/en/artifact-analysis.md"),
        include_str!("../../../../docs/ja/artifact-analysis.md"),
    ];
    let languages = ["English", "Japanese"];
    for row in &codehelion_artifact::FORMAT_SUPPORT {
        for (language, name) in document_names(row.format).into_iter().enumerate() {
            assert!(
                documents[language].contains(name),
                "the {} artifact document does not name {name}",
                languages[language]
            );
        }
    }
    for (what, listed) in [
        (
            "a call graph",
            named_formats(|capabilities| capabilities.call_graph),
        ),
        (
            "independently sized data regions",
            named_formats(|capabilities| capabilities.independent_data_segments),
        ),
    ] {
        for (language, list) in listed.into_iter().enumerate() {
            assert!(
                documents[language].contains(&list),
                "the {} artifact document does not name {list:?} as the formats supplying {what}",
                languages[language]
            );
        }
    }
}

#[test]
fn artifact_documents_state_canonical_build_variant_json_identities() {
    for document in [
        include_str!("../../../../docs/en/artifact-analysis.md"),
        include_str!("../../../../docs/ja/artifact-analysis.md"),
    ] {
        assert!(document.contains("--build-variant manifest.json"));
    }
    assert!(
        include_str!("../../../../docs/en/artifact-analysis.md")
            .contains("whitespace and object-member ordering")
    );
    assert!(
        include_str!("../../../../docs/ja/artifact-analysis.md")
            .contains("空白や object member の順序")
    );
}

/// Compression is explained as a mechanism, never as a measured ratio.
///
/// The size a compressor charges for a second copy of a byte sequence is
/// nearly nothing, which is exactly the redundancy deduplication removes. A
/// figure written by hand would be right for one build and wrong for the next,
/// and nothing here re-derives it, so both limitation documents say why rather
/// than how much.
#[test]
fn limitation_documents_explain_compressed_size_without_quoting_a_measured_ratio() {
    let english = include_str!("../../../../docs/en/limitations.md");
    for snippet in [
        "Compressed size moves less than uncompressed size does",
        "repeated byte sequence is the first thing a compressor folds away",
        "If your size budget is a compressed number, deduplication",
        "Measure both before and after your own refactor",
    ] {
        assert!(
            english.contains(snippet),
            "English limitation document is missing {snippet}"
        );
    }

    let japanese = include_str!("../../../../docs/ja/limitations.md");
    for snippet in [
        "圧縮後のサイズは、非圧縮のサイズほどには動きません",
        "圧縮器が真っ先に畳むもの",
        "サイズの上限が圧縮後の値であるプロジェクトにとって、重複の解消はそのための手段ではありません",
        "自分のリファクタの前後で両方を測ってください",
    ] {
        assert!(
            japanese.contains(snippet),
            "Japanese limitation document is missing {snippet}"
        );
    }
}

/// A baseline is for CI; following your own progress needs no baseline.
#[test]
fn baseline_documents_tell_the_two_uses_apart() {
    let english = include_str!("../../../../docs/en/baselines.md");
    for snippet in [
        "A baseline is for freezing a threshold and defending it in CI",
        "own progress through a refactor does not need one",
        "nothing has to be created, kept in step, or committed",
    ] {
        assert!(
            english.contains(snippet),
            "English baseline document is missing {snippet}"
        );
    }

    let japanese = include_str!("../../../../docs/ja/baselines.md");
    for snippet in [
        "baseline は閾値を凍結して CI で守るためのもの",
        "リファクタの進み具合を自分で追うだけなら baseline は要りません",
        "コミットするものもありません",
    ] {
        assert!(
            japanese.contains(snippet),
            "Japanese baseline document is missing {snippet}"
        );
    }
}

/// How to read a similarity breakdown, stated as a reading and not a rule.
///
/// The tool reports what the occurrences have in common; deciding that two of
/// them collapse into one function is outside what it claims to know, so the
/// paragraph has to say so in as many words.
#[test]
fn workflow_documents_read_a_similarity_breakdown_without_claiming_to_decide_it() {
    let english = include_str!("../../../../docs/en/refactoring-workflow.md");
    for snippet in [
        "A group whose structure and control flow agree exactly",
        "function taking an argument for whatever differs",
        "of reading the numbers, not a rule the tool applies",
    ] {
        assert!(
            english.contains(snippet),
            "English workflow document is missing {snippet}"
        );
    }

    let japanese = include_str!("../../../../docs/ja/refactoring-workflow.md");
    for snippet in [
        "構造と制御フローが完全に一致していて識別子だけが一致しない",
        "違う部分を引数に取る 1 つの関数に畳めます",
        "数値の読み方であって、ツールが適用する規則ではありません",
    ] {
        assert!(
            japanese.contains(snippet),
            "Japanese workflow document is missing {snippet}"
        );
    }
}

/// A build-variant manifest is written, not found.
///
/// The word names two things — the file describing how an artifact was built,
/// and the digest qualifying how sources were read — and a reader who takes
/// them for one thing goes looking for a source digest to copy into the file.
/// There is none, so both artifact documents say so and show the file being
/// written.
#[test]
fn artifact_documents_say_a_build_variant_manifest_is_written_rather_than_found() {
    let english = include_str!("../../../../docs/en/artifact-analysis.md");
    for snippet in [
        "takes a file you write, not one to go looking for",
        "echo '{\"profile\":\"release\",\"target\":\"wasm32\",\"toolchain\":\"emcc-5.0.2\"}' > build-variant.json",
        "no source digest to find and copy into the manifest",
    ] {
        assert!(
            english.contains(snippet),
            "English artifact document is missing {snippet}"
        );
    }

    let japanese = include_str!("../../../../docs/ja/artifact-analysis.md");
    for snippet in [
        "自分で書くファイルで、どこかにある既存のファイルを探すものではありません",
        "echo '{\"profile\":\"release\",\"target\":\"wasm32\",\"toolchain\":\"emcc-5.0.2\"}' > build-variant.json",
        "manifest に書き写すべき source 側の digest は存在しません",
    ] {
        assert!(
            japanese.contains(snippet),
            "Japanese artifact document is missing {snippet}"
        );
    }
}

#[test]
fn command_line_documents_limit_jobs_to_frontend_parallelism() {
    assert!(
        include_str!("../../../../docs/en/cli.md")
            .contains("clone grouping and report rendering remain serial")
    );
    assert!(
        include_str!("../../../../docs/ja/cli.md")
            .contains("clone grouping と report rendering は serial")
    );
}

#[test]
fn japanese_mode_document_explains_the_fast_mode_comment_and_whitespace_normalization() {
    assert!(
        include_str!("../../../../docs/ja/analysis-modes.md").contains("コメントと空白を除く"),
        "the Japanese analysis-mode document must retain Fast-mode normalization semantics"
    );
}

#[test]
fn workflow_documents_state_the_rescan_after_refactor_loop() {
    let english = include_str!("../../../../docs/en/refactoring-workflow.md");
    for snippet in [
        "Rescanning after a refactor",
        "replacement you missed",
        "finishes in seconds",
        "codehelion artifact analyze path/to/binary",
    ] {
        assert!(
            english.contains(snippet),
            "English workflow document is missing {snippet}"
        );
    }

    let japanese = include_str!("../../../../docs/ja/refactoring-workflow.md");
    for snippet in [
        "リファクタ直後の再スキャン",
        "その呼び出し元は置換漏れです",
        "数秒で終わる",
        "codehelion artifact analyze path/to/binary",
    ] {
        assert!(
            japanese.contains(snippet),
            "Japanese workflow document is missing {snippet}"
        );
    }
}

/// The relationship between exact and normalized duplication is stated as an
/// order of magnitude, never as a measured byte count: nothing re-derives a
/// figure written by hand, so one would drift the moment a build changed.
#[test]
fn limitation_documents_scale_identical_code_folding_without_a_measured_byte_count() {
    let english = include_str!("../../../../docs/en/limitations.md");
    assert!(english.contains("thousands of times larger"));
    assert!(english.contains("exact and the normalized figure"));

    let japanese = include_str!("../../../../docs/ja/limitations.md");
    assert!(japanese.contains("その数千倍あります"));
    assert!(japanese.contains("exact と normalized の値"));
}

#[test]
fn limitation_documents_explain_artifact_folding_and_size_relevance() {
    let english = include_str!("../../../../docs/en/limitations.md");
    let japanese = include_str!("../../../../docs/ja/limitations.md");
    assert!(english.contains("Identical code folding"));
    assert!(english.contains("Type-1 copies"));
    assert!(english.contains("Type-2 and Type-3 copies"));
    assert!(japanese.contains("identical code folding"));
    assert!(japanese.contains("Type-1"));
    assert!(japanese.contains("Type-2 / Type-3"));
}

/// The channel's own blind spot is documented, and the counts it produces are
/// left to the run that produces them: a figure written here has nothing that
/// re-derives it, and the summary now names both numbers per run.
#[test]
fn limitation_documents_name_the_shape_of_code_signature_siblings_cannot_help() {
    let english = include_str!("../../../../docs/en/limitations.md");
    for snippet in [
        "A layer built on one signature gets nothing from that channel",
        "dispatch or callback table",
        "limits.signature-sibling-max-units-per-signature",
        "how far the widest one reached",
    ] {
        assert!(
            english.contains(snippet),
            "English limitation document is missing {snippet}"
        );
    }

    let japanese = include_str!("../../../../docs/ja/limitations.md");
    for snippet in [
        "1 つのシグネチャで駆動する層に、このチャネルは何も与えません",
        "callback table",
        "limits.signature-sibling-max-units-per-signature",
        "いちばん広く共有されていたもの",
    ] {
        assert!(
            japanese.contains(snippet),
            "Japanese limitation document is missing {snippet}"
        );
    }
}

#[test]
fn limitation_documents_describe_opt_in_sibling_evidence_limits() {
    let english = include_str!("../../../../docs/en/limitations.md");
    for snippet in [
        "--siblings-by-signature",
        "off by default",
        "low-confidence sibling",
        "normalized signature",
        "same directory",
        "sibling-search ceiling",
        "mirror-consistency checker",
    ] {
        assert!(
            english.contains(snippet),
            "English limitation document is missing {snippet}"
        );
    }

    let japanese = include_str!("../../../../docs/ja/limitations.md");
    for snippet in [
        "--siblings-by-signature",
        "既定では無効",
        "正規化済みシグネチャ",
        "低信頼度の sibling",
        "別ディレクトリ",
        "探索の上限",
        "ミラー整合性検査ツールではありません",
    ] {
        assert!(
            japanese.contains(snippet),
            "Japanese limitation document is missing {snippet}"
        );
    }
}

/// The documents that carry a default or a lifecycle rule each state it.
///
/// Split by subject rather than gathered into one document, because that is
/// where a reader looking for the rule arrives: the configuration document owns
/// the suppression defaults and the database's lifecycle, the trust document
/// owns what enforces the execution ban, and the architecture document owns the
/// conformance cases. The README keeps only the registry badge.
#[test]
fn documents_state_current_defaults_and_database_lifecycle() {
    for configuration in [
        include_str!("../../../../docs/en/configuration.md"),
        include_str!("../../../../docs/ja/configuration.md"),
    ] {
        for snippet in ["auto-generated", "autogenerated", ".codehelion/"] {
            assert!(
                configuration.contains(snippet),
                "a configuration document is missing {snippet}"
            );
        }
    }
    for trust in [
        include_str!("../../../../docs/en/security.md"),
        include_str!("../../../../docs/ja/security.md"),
    ] {
        assert!(
            trust.contains("clippy.toml"),
            "a trust document is missing clippy.toml"
        );
    }
    for architecture in [
        include_str!("../../../../docs/en/architecture.md"),
        include_str!("../../../../docs/ja/architecture.md"),
    ] {
        assert!(
            architecture.contains("codehelion-helper-conformance/"),
            "an architecture document is missing the conformance cases"
        );
    }
    for readme in [
        include_str!("../../../../README.md"),
        include_str!("../../../../README_ja.md"),
    ] {
        assert!(
            readme.contains("codehelion.svg"),
            "a README is missing the registry badge"
        );
    }
    assert!(
        include_str!("../../../../docs/en/configuration.md").contains("at least 8 characters"),
        "the English configuration document must state the clone-id prefix minimum"
    );
    assert!(
        include_str!("../../../../docs/ja/configuration.md").contains("8 文字以上"),
        "the Japanese configuration document must state the clone-id prefix minimum"
    );
}

#[test]
fn documents_state_the_toolchain_requirement_the_manifest_declares() {
    // Read from the manifest rather than written out again, so raising the
    // requirement cannot leave a document quoting the old one.
    let version = env!("CARGO_PKG_RUST_VERSION");

    for english in [
        include_str!("../../../../README.md"),
        include_str!("../../../../docs/en/getting-started.md"),
    ] {
        assert!(
            english.contains(&format!("Rust {version} or newer")),
            "an English document must state Rust {version} as the requirement"
        );
    }
    assert!(
        include_str!("../../../../README.md").contains(&format!("Rust-{version}%2B")),
        "English README badge must state Rust {version}"
    );

    for japanese in [
        include_str!("../../../../README_ja.md"),
        include_str!("../../../../docs/ja/getting-started.md"),
    ] {
        assert!(
            japanese.contains(&format!("Rust {version} 以降")),
            "a Japanese document must state Rust {version} as the requirement"
        );
    }
    assert!(
        include_str!("../../../../README_ja.md").contains(&format!("Rust-{version}%2B")),
        "Japanese README badge must state Rust {version}"
    );
}

/// The seam feature's four limitations are stated, in both languages, in the
/// words the implementation actually holds to.
///
/// Pinned rather than left to prose because the limitations are the part of
/// this feature nobody discovers by using it: an asymmetric change that was
/// the right change looks exactly like one that was not, and a reader who has
/// not been told that will read the first report as a defect list. If the
/// implementation stops being able to make one of these statements, this fails
/// until the document says so too.
#[test]
fn limitation_documents_state_what_seam_tracking_cannot_tell_apart() {
    let english = include_str!("../../../../docs/en/limitations.md");
    for snippet in [
        "A correct one-sided change cannot be told from a broken one.",
        "History does not survive a rename.",
        "Duplication inside a single file carries no time axis, because co-change is",
        "A repository without Conventional Commits prefixes reports no breaches, while",
    ] {
        assert!(
            english.contains(snippet),
            "English limitation document is missing {snippet}"
        );
    }

    let japanese = include_str!("../../../../docs/ja/limitations.md");
    for snippet in [
        "片側だけを直した正しい変更と、壊れた変更とを区別できません。",
        "履歴はリネームをまたぎません。",
        "共変更はパス単位で測るため、同一ファイル内の重複には時間軸が付きません。",
        "Conventional Commits の prefix を持たないリポジトリでは breach が 1 件も出ませんが、非対称変更は変わらず検出できます。",
    ] {
        assert!(
            japanese.contains(snippet),
            "Japanese limitation document is missing {snippet}"
        );
    }
}

/// Both seam-tracking pages state the ledger's shape, the three commands, and
/// why a candidate is promoted by hand.
#[test]
fn seam_tracking_documents_state_the_ledger_the_commands_and_manual_promotion() {
    for document in [
        include_str!("../../../../docs/en/seam-tracking.md"),
        include_str!("../../../../docs/ja/seam-tracking.md"),
    ] {
        for snippet in [
            "[[seam]]",
            "[seam-tracking]",
            "codehelion history",
            "codehelion seam --suggest",
            "codehelion guard --paths",
            "--deny-asymmetric",
            "fetch-depth: 0",
            "coupling(a, b)    = min(confidence(a\u{2192}b), confidence(b\u{2192}a))",
        ] {
            assert!(
                document.contains(snippet),
                "a seam-tracking document is missing {snippet}"
            );
        }
    }
}

/// The command-line documents name every seam-tracking subcommand and the
/// flags that change what one of them does.
#[test]
fn command_line_documents_state_the_history_seam_and_guard_surfaces() {
    for document in [
        include_str!("../../../../docs/en/cli.md"),
        include_str!("../../../../docs/ja/cli.md"),
    ] {
        for snippet in [
            "codehelion history",
            "codehelion seam",
            "codehelion guard",
            "--suggest",
            "--until <rev>",
            "--since <rev>",
            "--paths <p>",
            "--deny-asymmetric",
        ] {
            assert!(
                document.contains(snippet),
                "the command-line document is missing {snippet}"
            );
        }
    }
}

/// Both configuration documents state every `[seam-tracking]` key with the
/// default this build applies.
///
/// Read out of the built-in settings rather than copied from them: a default
/// changed in the code fails here until the document says the same number.
#[test]
fn configuration_documents_state_every_seam_setting_and_its_default() {
    let defaults = codehelion_seam::Settings::default();
    let documents = [
        include_str!("../../../../docs/en/configuration.md"),
        include_str!("../../../../docs/ja/configuration.md"),
    ];
    let expected = [
        ("breach-window", defaults.breach_window.to_string()),
        ("history-limit", defaults.history_limit.to_string()),
        ("max-commit-size", defaults.max_commit_size.to_string()),
        ("min-coupling", format!("{:.2}", defaults.min_coupling)),
        ("min-support", defaults.min_support.to_string()),
        ("suggest-depth", defaults.suggest_depth.to_string()),
    ];
    for document in documents {
        for (key, default) in &expected {
            assert!(
                document.contains(key),
                "a configuration document does not name {key}"
            );
            assert!(
                document.contains(&format!("{key} = {default}")),
                "a configuration document does not give {key} its default of {default}"
            );
        }
    }
}

/// Both report documents say when the seam block is absent, and what the
/// finding count beside a seam was counted from.
///
/// Pinned because both are read wrongly by default. An absent block looks like
/// a ledger that costs nothing rather than one nobody has evaluated, and a
/// finding count printed beside two history-derived numbers looks like a third
/// one, when it comes from a scan of the tree taken at the moment the seam run
/// was recorded.
#[test]
fn report_documents_state_when_the_seam_block_is_absent_and_what_it_counts() {
    let english = include_str!("../../../../docs/en/reading-a-report.md");
    for snippet in [
        "The block appears only when a `codehelion seam` run has been recorded for this",
        "A report with no block is a ledger nobody has evaluated, not a ledger whose",
        "taken from the newest completed scan of the same tree at the moment the seam run",
        "A seam with no scan behind it carries no finding counts.",
    ] {
        assert!(
            english.contains(snippet),
            "English report document is missing {snippet}"
        );
    }

    let japanese = include_str!("../../../../docs/ja/reading-a-report.md");
    for snippet in [
        "この区画が出るのは、そのツリーについて `codehelion seam` の実行が記録されているときだけです。",
        "誰も評価していない台帳です",
        "その seam run を記録した時点で同じツリーについて最も新しく完了していたスキャンです",
        "背後にスキャンの無い seam は finding の件数を持ちません。",
    ] {
        assert!(
            japanese.contains(snippet),
            "Japanese report document is missing {snippet}"
        );
    }
}

/// Both seam-tracking documents say which invocations become a recorded
/// generation and which do not, with the reason `--until` is among them.
///
/// The three exclusions have nothing in common on the surface, so a reader who
/// is told only that `seam` records will read a missing generation as a bug.
/// `--until` is the one nobody would guess: it is the flag the same page
/// recommends for comparing two generations, and it is excluded precisely
/// because a shortened range kept as the newest one would be read as movement
/// in the code.
#[test]
fn seam_tracking_documents_state_which_invocations_record_and_which_do_not() {
    let english = include_str!("../../../../docs/en/seam-tracking.md");
    for snippet in [
        "Three invocations record nothing, each for its own reason:",
        "`--until <rev>` reads a range somebody deliberately cut short. Kept as the",
        "newest generation, it would make the next comparison read the shorter question",
        "`--no-record` is the explicit opt-out.",
        "`history` and `guard` open no database at all.",
    ] {
        assert!(
            english.contains(snippet),
            "English seam-tracking document is missing {snippet}"
        );
    }

    let japanese = include_str!("../../../../docs/ja/seam-tracking.md");
    for snippet in [
        "記録しない実行が 3 つあり、理由はそれぞれ別です。",
        "`--until <rev>` が読むのは、誰かが意図的に短く切った範囲です。",
        "「問いが短くなった」ことを「コードが動いた」こととして読んでしまいます",
        "`--no-record` は明示的な opt-out です。",
        "`history` と `guard` はデータベースを一切開きません。",
    ] {
        assert!(
            japanese.contains(snippet),
            "Japanese seam-tracking document is missing {snippet}"
        );
    }
}

/// Both configuration documents say that a database an earlier build wrote is
/// not migrated, and what a run does instead.
///
/// The reader meets this as a second file appearing beside the first with no
/// history in it, which reads as data loss unless the document has already
/// said that the database holds derived state and that the old file was left
/// alone deliberately.
#[test]
fn configuration_documents_state_that_an_earlier_schema_database_is_not_migrated() {
    let english = include_str!("../../../../docs/en/configuration.md");
    for snippet in [
        "A database written under a different schema is never migrated.",
        "`audit-v<schema>.db` beside it, and says which file it used",
        "Nothing is lost that a fresh scan does not recreate.",
    ] {
        assert!(
            english.contains(snippet),
            "English configuration document is missing {snippet}"
        );
    }

    let japanese = include_str!("../../../../docs/ja/configuration.md");
    for snippet in [
        "別のスキーマで書かれたデータベースが移行されることはありません。",
        "隣の `audit-v<スキーマ>.db` へ記録して",
        "それで失われるものは、スキャンをやり直せば復元できないものではありません。",
    ] {
        assert!(
            japanese.contains(snippet),
            "Japanese configuration document is missing {snippet}"
        );
    }
}
