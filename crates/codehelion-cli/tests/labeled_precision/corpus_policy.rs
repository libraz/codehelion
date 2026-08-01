use super::*;

#[test]
fn labelled_origin_policy_matches_the_case_manifests() {
    let root = repo_root();
    for expected in CORPORA {
        let manifest = root
            .join("corpus/labeled")
            .join(expected.name)
            .join("snapshot.toml");
        let source = std::fs::read_to_string(&manifest)
            .unwrap_or_else(|error| panic!("reading {}: {error}", manifest.display()));
        let origin = source.lines().any(|line| line.starts_with("origin = \""));
        assert_eq!(
            origin, expected.has_origin,
            "{} origin policy drifted from its manifest",
            expected.name,
        );
        if origin {
            let commit = source
                .lines()
                .find_map(|line| line.strip_prefix("commit = \"")?.strip_suffix('"'))
                .expect("an origin case records its commit");
            assert!(
                commit.len() == 40 && commit.bytes().all(|byte| byte.is_ascii_hexdigit()),
                "{} origin case has a full commit hash",
                expected.name,
            );
        }
    }
}

#[test]
fn every_unmaterialized_case_means_no_precision_was_measured() {
    assert!(!has_materialized_snapshot(CORPORA.len(), CORPORA.len()));
    assert!(has_materialized_snapshot(CORPORA.len() - 1, CORPORA.len()));
}
