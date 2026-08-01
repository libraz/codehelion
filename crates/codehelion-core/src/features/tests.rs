use super::*;
use crate::discovery::Language;
use crate::frontend::{SourceSpan, TokenKind};
use crate::ir::IR_SCHEMA_VERSION;

fn tok(kind: TokenKind, text: &str, index: usize) -> Token {
    Token {
        kind,
        text: Lexeme::from(text),
        span: SourceSpan {
            start_byte: index * 8,
            end_byte: index * 8 + text.len(),
            start_line: 1,
            start_column: 1,
        },
    }
}

/// `count` identifier tokens named `<prefix><i>`; byte layout follows
/// the token index.
fn ident_tokens(count: usize, prefix: &str) -> Vec<Token> {
    (0..count)
        .map(|i| tok(TokenKind::Identifier, &format!("{prefix}{i}"), i))
        .collect()
}

/// A node over `token_start..token_end` whose byte range is the token
/// range scaled by 8, matching `tok`'s layout.
fn node(shape: Shape, token_start: usize, token_end: usize, children: Vec<IrNode>) -> IrNode {
    IrNode {
        shape,
        name: None,
        token_start,
        token_end,
        range: ByteRange {
            start: token_start * 8,
            end: token_end * 8,
        },
        children,
    }
}

fn file_of(roots: Vec<IrNode>, tokens: Vec<Token>) -> SyntaxIrFile {
    SyntaxIrFile {
        language: Language::Rust,
        frontend_version: "test-ir-v1",
        ir_schema_version: IR_SCHEMA_VERSION,
        tokens,
        roots,
        diagnostics: Vec::new(),
        error_ranges: Vec::new(),
        depth_truncated: false,
        test_module: false,
    }
}

/// A function whose block holds one two-token statement per given shape.
fn statement_unit(shapes: &[Shape]) -> IrNode {
    let statements: Vec<IrNode> = shapes
        .iter()
        .enumerate()
        .map(|(i, shape)| node(shape.clone(), i * 2, i * 2 + 2, Vec::new()))
        .collect();
    let token_end = shapes.len() * 2;
    node(
        Shape::Function,
        0,
        token_end,
        vec![node(Shape::Block, 0, token_end, statements)],
    )
}

#[test]
fn five_statements_yield_two_windows_of_length_four() {
    let unit = statement_unit(&[
        Shape::ExprStmt,
        Shape::ExprStmt,
        Shape::ExprStmt,
        Shape::ExprStmt,
        Shape::ExprStmt,
    ]);
    let features = extract(&file_of(vec![unit], ident_tokens(10, "t")));
    assert_eq!(features.units.len(), 1);
    let unit = &features.units[0];
    assert_eq!(unit.windows.len(), 2, "5 statements: 2x len-4, 0x len-8");
    assert!(unit.windows.iter().all(|window| window.length == 4));
    // First window spans statements 0..=3, second spans 1..=4.
    assert_eq!(unit.windows[0].range, ByteRange { start: 0, end: 64 });
    assert_eq!(unit.windows[1].range, ByteRange { start: 16, end: 80 });
}

#[test]
fn window_hashes_use_token_kinds_not_texts() {
    let shapes = [
        Shape::VarDecl,
        Shape::ExprStmt,
        Shape::Assign,
        Shape::Return,
    ];
    let first = extract(&file_of(
        vec![statement_unit(&shapes)],
        ident_tokens(8, "a"),
    ));
    let renamed = extract(&file_of(
        vec![statement_unit(&shapes)],
        ident_tokens(8, "b"),
    ));
    assert_eq!(
        first.units[0].windows[0].hash, renamed.units[0].windows[0].hash,
        "identifier texts must not reach the window hash"
    );

    // A different statement shape changes the hash.
    let reshaped = extract(&file_of(
        vec![statement_unit(&[
            Shape::VarDecl,
            Shape::ExprStmt,
            Shape::Assign,
            Shape::Break,
        ])],
        ident_tokens(8, "a"),
    ));
    assert_ne!(
        first.units[0].windows[0].hash,
        reshaped.units[0].windows[0].hash
    );

    // A different head-token kind changes the hash.
    let mut keyword_tokens = ident_tokens(8, "a");
    keyword_tokens[0] = tok(TokenKind::Keyword, "a0", 0);
    let rekinded = extract(&file_of(vec![statement_unit(&shapes)], keyword_tokens));
    assert_ne!(
        first.units[0].windows[0].hash,
        rekinded.units[0].windows[0].hash
    );
}

/// Function -> Block -> Loop -> Block -> `last`: five nodes.
fn chain_unit(last: Shape) -> IrNode {
    node(
        Shape::Function,
        0,
        4,
        vec![node(
            Shape::Block,
            0,
            4,
            vec![node(
                Shape::Loop,
                0,
                4,
                vec![node(Shape::Block, 0, 4, vec![node(last, 0, 4, Vec::new())])],
            )],
        )],
    )
}

#[test]
fn subtree_merkle_ignores_names_and_tokens_but_not_shapes() {
    let base = extract(&file_of(
        vec![chain_unit(Shape::Return)],
        ident_tokens(4, "t"),
    ));
    let unit = &base.units[0];
    assert_eq!(unit.subtrees.len(), 1, "only the 5-node root qualifies");
    assert_eq!(unit.subtrees[0].node_count, 5);
    assert_eq!(unit.subtrees[0].range, ByteRange { start: 0, end: 32 });

    // Different unit name and token texts: same structure, same hash.
    let mut renamed = chain_unit(Shape::Return);
    renamed.name = Some(Lexeme::from("renamed"));
    let other = extract(&file_of(vec![renamed], ident_tokens(4, "u")));
    assert_eq!(other.units[0].subtrees[0].hash, unit.subtrees[0].hash);

    // A different leaf shape changes the root hash.
    let reshaped = extract(&file_of(
        vec![chain_unit(Shape::Break)],
        ident_tokens(4, "t"),
    ));
    assert_ne!(reshaped.units[0].subtrees[0].hash, unit.subtrees[0].hash);
}

#[test]
fn subtree_cutoff_and_counts_follow_the_post_order_pass() {
    // Function -> Block -> Loop -> Block -> [Return, Break]: six nodes.
    let unit = node(
        Shape::Function,
        0,
        4,
        vec![node(
            Shape::Block,
            0,
            4,
            vec![node(
                Shape::Loop,
                0,
                4,
                vec![node(
                    Shape::Block,
                    0,
                    4,
                    vec![
                        node(Shape::Return, 0, 2, Vec::new()),
                        node(Shape::Break, 2, 4, Vec::new()),
                    ],
                )],
            )],
        )],
    );
    let features = extract(&file_of(vec![unit], ident_tokens(4, "t")));
    let counts: Vec<usize> = features.units[0]
        .subtrees
        .iter()
        .map(|subtree| subtree.node_count)
        .collect();
    // The 3- and 4-node subtrees fall below MIN_SUBTREE_NODES; children
    // are emitted before ancestors.
    assert_eq!(counts, vec![5, 6]);
}

#[test]
fn characteristic_vector_counts_and_depth() {
    let features = extract(&file_of(
        vec![chain_unit(Shape::Return)],
        ident_tokens(4, "t"),
    ));
    let vector = &features.units[0].vector;
    assert_eq!(vector.node_count, 5);
    assert_eq!(vector.max_depth, 5);
    assert_eq!(vector.counts[usize::from(Shape::Function.tag())], 1);
    assert_eq!(vector.counts[usize::from(Shape::Block.tag())], 2);
    assert_eq!(vector.counts[usize::from(Shape::Loop.tag())], 1);
    assert_eq!(vector.counts[usize::from(Shape::Return.tag())], 1);
    assert_eq!(vector.counts[0], 0, "slot 0 is unused");
}

#[test]
fn l1_and_cosine_match_known_values() {
    let mut a = CharacteristicVector::default();
    a.counts[1] = 3;
    a.counts[2] = 4;
    let b = a.clone();
    assert_eq!(a.l1_distance(&b), 0);
    assert!((a.cosine_similarity(&b) - 1.0).abs() < 1e-9);

    let mut c = CharacteristicVector::default();
    c.counts[1] = 1;
    c.counts[2] = 1;
    assert_eq!(a.l1_distance(&c), 5);
    let expected = 7.0 / (5.0 * 2.0f64.sqrt());
    assert!((a.cosine_similarity(&c) - expected).abs() < 1e-9);

    let zero = CharacteristicVector::default();
    assert!(a.cosine_similarity(&zero).abs() < f64::EPSILON);
    assert!(zero.cosine_similarity(&zero).abs() < f64::EPSILON);
}

#[test]
fn shape_divergence_spans_the_unit_range() {
    let mut a = CharacteristicVector::default();
    a.counts[1] = 3;
    a.counts[2] = 4;
    a.node_count = 7;

    // The same shapes in the same numbers are not apart at all.
    assert!(a.shape_divergence(&a).abs() < f64::EPSILON);

    // Nothing to tell apart is not divergence either.
    let zero = CharacteristicVector::default();
    assert!(zero.shape_divergence(&zero).abs() < f64::EPSILON);

    // Sharing no shape at all is the far end of the range.
    let mut disjoint = CharacteristicVector::default();
    disjoint.counts[3] = 5;
    disjoint.node_count = 5;
    assert!((a.shape_divergence(&disjoint) - 1.0).abs() < 1e-9);
    assert!(
        (disjoint.shape_divergence(&a) - a.shape_divergence(&disjoint)).abs() < f64::EPSILON,
        "the measure does not depend on which unit is asked first"
    );
}

#[test]
fn a_threefold_size_difference_alone_reaches_the_default_limit() {
    // Same shape mix, three times as many of it: the documented floor of
    // `(r - 1) / (r + 1)` puts the pair at 0.5 before any difference in
    // mix is counted, which is what `max_length_ratio`'s 3.0 says.
    let mut small = CharacteristicVector::default();
    small.counts[1] = 2;
    small.counts[2] = 2;
    small.node_count = 4;

    let mut large = CharacteristicVector::default();
    large.counts[1] = 6;
    large.counts[2] = 6;
    large.node_count = 12;

    assert!((small.shape_divergence(&large) - 0.5).abs() < 1e-9);
}

/// Function -> Block -> [Loop -> Block, Branch -> Block], in either order.
fn control_unit(loop_first: bool) -> IrNode {
    let loop_node = node(
        Shape::Loop,
        0,
        2,
        vec![node(Shape::Block, 0, 2, Vec::new())],
    );
    let branch_node = node(
        Shape::Branch,
        2,
        4,
        vec![node(Shape::Block, 2, 4, Vec::new())],
    );
    let children = if loop_first {
        vec![loop_node, branch_node]
    } else {
        vec![branch_node, loop_node]
    };
    node(
        Shape::Function,
        0,
        4,
        vec![node(Shape::Block, 0, 4, children)],
    )
}

#[test]
fn cfg_hash_is_order_sensitive() {
    let loop_first = extract(&file_of(vec![control_unit(true)], ident_tokens(4, "t")));
    let branch_first = extract(&file_of(vec![control_unit(false)], ident_tokens(4, "t")));
    let first = &loop_first.units[0].cfg;
    let second = &branch_first.units[0].cfg;
    assert_ne!(first.hash, second.hash, "op order must reach the hash");
    assert_eq!(first.op_count, 4);
    assert_eq!(second.op_count, 4);
    assert_eq!(first.branch_count, 1);
    assert_eq!(first.max_loop_depth, 1);
}

#[test]
fn cfg_tracks_loop_depth_and_branch_count() {
    // Function -> Block -> Loop -> Block -> Loop -> Block.
    let nested = node(
        Shape::Function,
        0,
        4,
        vec![node(
            Shape::Block,
            0,
            4,
            vec![node(
                Shape::Loop,
                0,
                4,
                vec![node(
                    Shape::Block,
                    0,
                    4,
                    vec![node(
                        Shape::Loop,
                        0,
                        4,
                        vec![node(Shape::Block, 0, 4, Vec::new())],
                    )],
                )],
            )],
        )],
    );
    let features = extract(&file_of(vec![nested], ident_tokens(4, "t")));
    let cfg = &features.units[0].cfg;
    assert_eq!(cfg.max_loop_depth, 2);
    assert_eq!(cfg.branch_count, 0);
    assert_eq!(cfg.op_count, 4);

    // Two sibling branches count individually.
    let branches = node(
        Shape::Function,
        0,
        4,
        vec![node(
            Shape::Block,
            0,
            4,
            vec![
                node(Shape::Branch, 0, 2, Vec::new()),
                node(Shape::Branch, 2, 4, Vec::new()),
            ],
        )],
    );
    let features = extract(&file_of(vec![branches], ident_tokens(4, "t")));
    assert_eq!(features.units[0].cfg.branch_count, 2);
}

/// Tokens for `foo(); x.bar()` plus one nameless call range `( )`.
fn call_tokens_forward() -> Vec<Token> {
    vec![
        tok(TokenKind::Identifier, "foo", 0),
        tok(TokenKind::Punctuation, "(", 1),
        tok(TokenKind::Punctuation, ")", 2),
        tok(TokenKind::Punctuation, ";", 3),
        tok(TokenKind::Identifier, "x", 4),
        tok(TokenKind::Punctuation, ".", 5),
        tok(TokenKind::Identifier, "bar", 6),
        tok(TokenKind::Punctuation, "(", 7),
        tok(TokenKind::Punctuation, ")", 8),
    ]
}

fn call_unit(call_ranges: &[(usize, usize)]) -> IrNode {
    let calls: Vec<IrNode> = call_ranges
        .iter()
        .map(|&(start, end)| node(Shape::Call, start, end, Vec::new()))
        .collect();
    node(Shape::Function, 0, 9, vec![node(Shape::Block, 0, 9, calls)])
}

#[test]
fn api_callee_extraction_and_hash_domains() {
    // `foo()` then method-style `x . bar ( )`; the `( )` range yields no
    // callee and is skipped.
    let forward = extract(&file_of(
        vec![call_unit(&[(0, 3), (4, 9), (1, 3)])],
        call_tokens_forward(),
    ));
    let api = &forward.units[0].api;
    let names: Vec<&str> = api.names.iter().map(Lexeme::as_str).collect();
    assert_eq!(names, vec!["foo", "bar"]);
    assert_ne!(
        api.sequence_hash, api.multiset_hash,
        "ordered and multiset domains must hash apart"
    );

    // Reversed call order: `x.bar(); foo()`.
    let reversed_tokens = vec![
        tok(TokenKind::Identifier, "x", 0),
        tok(TokenKind::Punctuation, ".", 1),
        tok(TokenKind::Identifier, "bar", 2),
        tok(TokenKind::Punctuation, "(", 3),
        tok(TokenKind::Punctuation, ")", 4),
        tok(TokenKind::Punctuation, ";", 5),
        tok(TokenKind::Identifier, "foo", 6),
        tok(TokenKind::Punctuation, "(", 7),
        tok(TokenKind::Punctuation, ")", 8),
    ];
    let reversed = extract(&file_of(
        vec![call_unit(&[(0, 5), (6, 9)])],
        reversed_tokens,
    ));
    let reversed_api = &reversed.units[0].api;
    let reversed_names: Vec<&str> = reversed_api.names.iter().map(Lexeme::as_str).collect();
    assert_eq!(reversed_names, vec!["bar", "foo"]);
    assert_ne!(api.sequence_hash, reversed_api.sequence_hash);
    assert_eq!(api.multiset_hash, reversed_api.multiset_hash);
}

#[test]
fn nested_units_get_their_own_entries() {
    let closure = node(
        Shape::Closure,
        1,
        3,
        vec![node(Shape::Block, 1, 3, Vec::new())],
    );
    let unit = node(
        Shape::Function,
        0,
        4,
        vec![node(Shape::Block, 0, 4, vec![closure])],
    );
    let features = extract(&file_of(vec![unit], ident_tokens(4, "t")));
    assert_eq!(features.units.len(), 2);
    assert_eq!(features.units[0].shape_tag, Shape::Function.tag());
    assert_eq!(features.units[1].shape_tag, Shape::Closure.tag());
    // The host's features cover the nested unit's subtree too.
    assert_eq!(features.units[0].vector.node_count, 4);
    assert_eq!(features.units[1].vector.node_count, 2);
}

#[test]
fn feature_hash_hex_and_byte_roundtrip() {
    let fixed = FeatureHash::from_bytes([0xab; 16]);
    assert_eq!(fixed.to_hex(), "ab".repeat(16));
    assert_eq!(FeatureHash::from_bytes(*fixed.as_bytes()), fixed);

    let computed = extract(&file_of(vec![control_unit(true)], ident_tokens(4, "t")));
    let hex = computed.units[0].cfg.hash.to_hex();
    assert_eq!(hex.len(), 32);
    assert!(
        hex.chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    );
}

#[test]
fn extraction_is_deterministic() {
    let roots = vec![
        control_unit(true),
        chain_unit(Shape::Return),
        call_unit(&[(0, 3), (4, 9)]),
    ];
    let file = file_of(roots, call_tokens_forward());
    assert_eq!(extract(&file), extract(&file));
}

#[test]
fn feature_kind_names_round_trip_and_are_distinct() {
    let mut seen = std::collections::BTreeSet::new();
    for kind in FeatureKind::ALL {
        assert!(seen.insert(kind.name()), "duplicate name {}", kind.name());
        assert_eq!(FeatureKind::from_name(kind.name()), Some(kind));
    }
    assert_eq!(FeatureKind::from_name("nope"), None);
}
