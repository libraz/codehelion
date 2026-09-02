//! Comparing the same sources built under different build variants.

use super::*;

#[test]
fn cross_variant_comparison_keeps_origins_and_is_order_stable() {
    let tokens = [Token {
        kind: TokenKind::Identifier,
        text: "same".into(),
        span: SourceSpan {
            start_byte: 0,
            end_byte: 4,
            start_line: 1,
            start_column: 1,
        },
    }];
    let left = CrossVariantUnit {
        origin_variant: "b",
        language: Language::Cpp,
        file_path: "left.cpp",
        start_line: 2,
        end_line: 4,
        name: Some("left"),
        tokens: &tokens,
    };
    let right = CrossVariantUnit {
        origin_variant: "a",
        language: Language::Cpp,
        file_path: "right.cpp",
        start_line: 5,
        end_line: 7,
        name: Some("right"),
        tokens: &tokens,
    };
    let forward = compare_build_variants(&[left, right]).expect("two distinct build variants");
    let reverse = compare_build_variants(&[right, left]).expect("two distinct build variants");
    assert_eq!(forward, reverse);
    assert_eq!(forward.origin_variants, vec!["a", "b"]);
    assert_eq!(forward.groups.len(), 1);
    assert_eq!(forward.groups[0].members[0].origin_variant, "a");
    assert!(compare_build_variants(&[left]).is_none());

    let moved_left = CrossVariantUnit {
        file_path: "moved/left.cpp",
        start_line: 200,
        end_line: 204,
        ..left
    };
    let moved_right = CrossVariantUnit {
        file_path: "moved/right.cpp",
        start_line: 500,
        end_line: 507,
        ..right
    };
    let moved = compare_build_variants(&[moved_left, moved_right]).expect("moved comparison");
    assert_eq!(forward.groups[0].id, moved.groups[0].id);
    assert_eq!(
        forward.groups[0]
            .members
            .iter()
            .map(|member| member.id)
            .collect::<Vec<_>>(),
        moved.groups[0]
            .members
            .iter()
            .map(|member| member.id)
            .collect::<Vec<_>>()
    );
}

/// Two content-identical units of one origin keep the identities they were
/// given when one of the files is renamed. The reporting order follows the new
/// paths; the identities do not follow the reporting order.
#[test]
fn renaming_a_file_moves_no_cross_variant_member_identity() {
    let tokens = [Token {
        kind: TokenKind::Identifier,
        text: "same".into(),
        span: SourceSpan {
            start_byte: 0,
            end_byte: 4,
            start_line: 1,
            start_column: 1,
        },
    }];
    let unit = |origin_variant, file_path, start_line| CrossVariantUnit {
        origin_variant,
        language: Language::C,
        file_path,
        start_line,
        end_line: start_line + 2,
        name: Some("same"),
        tokens: &tokens,
    };
    let identities = |comparison: &CrossVariantComparison| {
        comparison
            .groups
            .iter()
            .flat_map(|group| group.members.iter().map(|member| member.id))
            .collect::<BTreeSet<_>>()
    };

    let units = [
        unit("a", "src/alpha.c", 1),
        unit("a", "src/zeta.c", 40),
        unit("b", "other/alpha.c", 1),
    ];
    let before = compare_build_variants(&units).expect("two origins");
    // The same tree with one file renamed past its sibling in path order.
    let renamed = [
        unit("a", "src/omega.c", 1),
        unit("a", "src/zeta.c", 40),
        unit("b", "other/alpha.c", 1),
    ];
    let after = compare_build_variants(&renamed).expect("two origins");

    assert_eq!(before.groups.len(), 1);
    assert_eq!(before.groups[0].members.len(), 3);
    assert_eq!(identities(&before), identities(&after));
    assert_eq!(
        after.groups[0]
            .members
            .iter()
            .map(|member| member.file_path.as_str())
            .collect::<Vec<_>>(),
        vec!["src/omega.c", "src/zeta.c", "other/alpha.c"],
        "the reporting order still follows the origin variant and then the paths"
    );
}

#[test]
fn cross_variant_group_identity_includes_the_language_class_axis() {
    let tokens = [Token {
        kind: TokenKind::Identifier,
        text: "same".into(),
        span: SourceSpan {
            start_byte: 0,
            end_byte: 4,
            start_line: 1,
            start_column: 1,
        },
    }];
    let unit = |origin_variant, language, file_path| CrossVariantUnit {
        origin_variant,
        language,
        file_path,
        start_line: 1,
        end_line: 1,
        name: Some("same"),
        tokens: &tokens,
    };
    let comparison = compare_build_variants(&[
        unit("a", Language::C, "a.c"),
        unit("b", Language::C, "b.c"),
        unit("a", Language::Cpp, "a.cpp"),
        unit("b", Language::Cpp, "b.cpp"),
    ])
    .expect("two origins in both language classes");

    assert_eq!(comparison.groups.len(), 2);
    assert_ne!(comparison.groups[0].id, comparison.groups[1].id);
}
