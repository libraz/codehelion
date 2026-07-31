//! Structural-mode candidate-extraction features over the Syntax IR.
//!
//! Structural mode never compares whole units pairwise — that is quadratic in
//! corpus size. Instead every unit (function, method, closure) is reduced to a
//! set of cheap per-unit features, and candidate pairs are proposed only where
//! features collide or lie close. One pass over a [`SyntaxIrFile`] extracts
//! four feature families per unit:
//!
//! - statement windows ([`WindowFeature`]): hashes of fixed-length runs of
//!   adjacent statements, the fragment-level candidate signal;
//! - subtree fingerprints ([`SubtreeFeature`]): Merkle hashes over the IR
//!   tree, the exact structural-match signal;
//! - a characteristic vector ([`CharacteristicVector`]): shape-tag counts
//!   used as a cheap candidate filter;
//! - an approximate control-flow profile ([`CfgFeature`]) and an API-call
//!   profile ([`ApiCallFeature`]).
//!
//! # Rename invariance
//!
//! Candidate extraction must survive Type-2 edits, so no identifier text and
//! no literal text enters any hash, with one deliberate exception: API-call
//! names. Lexical signal comes exclusively from token kind tags
//! ([`TokenKind::tag`]) and shape tags ([`Shape::tag`]). API-call names are
//! exempt because external API names are normalization-exempt, matching the
//! Fast engine's treatment of external names.
//!
//! # The control-flow profile is syntactic
//!
//! [`CfgFeature`] is a syntactic approximation built from AST control shapes,
//! not a real control-flow graph: it linearises loop, branch and match
//! nesting plus control statements in source order. A compiler-provided CFG
//! can replace it behind the same feature interface in a later phase; doing
//! so changes feature derivation and therefore bumps
//! [`FEATURE_SCHEMA_VERSION`].
//!
//! # Determinism
//!
//! Every output is derived from source order alone; no hash-map iteration
//! order reaches any feature. Extracting twice from the same IR yields
//! identical results.

use core::fmt;

use crate::frontend::{Lexeme, Token, TokenKind};
use crate::ir::{ByteRange, IrNode, SUMMARY_HEAD_TOKENS, Shape, SyntaxIrFile};

/// Version of the feature-derivation recipe.
///
/// Written into every feature hash after the domain string. Bump it when any
/// feature's input derivation changes, so features from incompatible recipes
/// never collide silently.
pub const FEATURE_SCHEMA_VERSION: &str = "ir-features-v1";

/// Statement-window lengths, in statements. Windows slide with stride 1 over
/// each block's statement sequence; a block shorter than a length yields no
/// window of that length.
pub const WINDOW_LENGTHS: &[usize] = &[4, 8, 16];

/// Minimum subtree size, in nodes (the subtree root included), for a
/// [`SubtreeFeature`] to be emitted. Smaller subtrees are ubiquitous and
/// would only inflate the candidate index.
pub const MIN_SUBTREE_NODES: usize = 5;

/// Number of slots in [`CharacteristicVector::counts`]: one per [`Shape`]
/// tag, with slot 0 unused because tags start at 1.
pub const SHAPE_TAG_SLOTS: usize = 23;

/// The kind of a persisted feature hash.
///
/// These name the hash-valued feature families the candidate index keys on.
/// Unlike a stable identifier, a feature hash is only meaningful within one
/// [`FEATURE_SCHEMA_VERSION`]; the persistence layer stores that version
/// alongside the hash so hashes from incompatible recipes never merge.
///
/// The [`CharacteristicVector`] is deliberately absent: it is a count vector,
/// not a single hash, and is persisted as scalars rather than an index key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FeatureKind {
    /// A [`WindowFeature`]: a fixed-length run of adjacent statements.
    StatementWindow,
    /// A [`SubtreeFeature`]: a Merkle hash over an IR subtree.
    Subtree,
    /// A [`CfgFeature`]: the approximate control-flow op sequence.
    Cfg,
    /// An [`ApiCallFeature::sequence_hash`]: callee names in source order.
    ApiCallSequence,
    /// An [`ApiCallFeature::multiset_hash`]: the order-independent callee set.
    ApiCallMultiset,
}

impl FeatureKind {
    /// Every kind, in declaration order.
    pub const ALL: [Self; 5] = [
        Self::StatementWindow,
        Self::Subtree,
        Self::Cfg,
        Self::ApiCallSequence,
        Self::ApiCallMultiset,
    ];

    /// The stable snake-case name used in storage and reports.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::StatementWindow => "statement_window",
            Self::Subtree => "subtree",
            Self::Cfg => "cfg",
            Self::ApiCallSequence => "api_call_sequence",
            Self::ApiCallMultiset => "api_call_multiset",
        }
    }

    /// Parse a [`name`](Self::name) back into its kind.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.name() == name)
    }
}

/// A 128-bit feature hash.
///
/// Feature hashes are candidate-index keys, not stable identifiers: they are
/// valid only within one [`FEATURE_SCHEMA_VERSION`]. Each is a BLAKE3 digest
/// over a domain string, the schema version and the feature's length-prefixed
/// inputs, truncated to 16 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FeatureHash([u8; 16]);

impl FeatureHash {
    /// Wrap hash bytes produced earlier by this module.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// The hash's raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Lowercase hex form used in reports.
    #[must_use]
    pub fn to_hex(&self) -> String {
        self.to_string()
    }
}

impl fmt::Display for FeatureHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Length-prefixed BLAKE3 hashing with a leading domain tag, following the
/// same conventions as the stable-identifier hasher: the domain string is
/// written first, then [`FEATURE_SCHEMA_VERSION`], then the caller's fields;
/// variable-length fields are length-prefixed.
struct FeatureHasher {
    hasher: blake3::Hasher,
}

impl FeatureHasher {
    fn new(domain: &str) -> Self {
        let mut this = Self {
            hasher: blake3::Hasher::new(),
        };
        this.write_bytes(domain.as_bytes());
        this.write_bytes(FEATURE_SCHEMA_VERSION.as_bytes());
        this
    }

    fn write_bytes(&mut self, bytes: &[u8]) {
        let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
        self.hasher.update(&len.to_le_bytes());
        self.hasher.update(bytes);
    }

    fn write_str(&mut self, text: &str) {
        self.write_bytes(text.as_bytes());
    }

    fn write_u8(&mut self, value: u8) {
        self.hasher.update(&[value]);
    }

    fn write_u32(&mut self, value: u32) {
        self.hasher.update(&value.to_le_bytes());
    }

    fn finish(self) -> FeatureHash {
        let digest = self.hasher.finalize();
        let mut out = [0u8; 16];
        out.copy_from_slice(&digest.as_bytes()[..16]);
        FeatureHash(out)
    }
}

/// The features of every unit in one file, in pre-order source order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileFeatures {
    /// Per-unit features, one entry per function, method or closure node.
    pub units: Vec<UnitFeatures>,
}

/// The candidate-extraction features of one unit.
///
/// A unit's features are computed over its full subtree, nested closures and
/// local functions included, while each nested unit also gets an entry of its
/// own. This double counting is deliberate v0 granularity: the outer unit
/// stays comparable as a whole, and the nested unit remains independently
/// discoverable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnitFeatures {
    /// The unit's declared name, when the frontend recovered one.
    pub name: Option<Lexeme>,
    /// Shape tag of the unit node (see [`Shape::tag`]).
    pub shape_tag: u8,
    /// Source bytes the unit covers; reporting only.
    pub range: ByteRange,
    /// Statement-window hashes over every block in the unit subtree.
    pub windows: Vec<WindowFeature>,
    /// Merkle subtree fingerprints of size [`MIN_SUBTREE_NODES`] and up,
    /// emitted in post-order.
    pub subtrees: Vec<SubtreeFeature>,
    /// The unit's characteristic vector.
    pub vector: CharacteristicVector,
    /// The unit's approximate control-flow profile.
    pub cfg: CfgFeature,
    /// The unit's API-call profile.
    pub api: ApiCallFeature,
}

/// A reference to one unit inside a slice of [`FileFeatures`].
///
/// The unit-level candidate stages all speak in these: `file` indexes the slice
/// they were given, `unit` indexes that file's [`FileFeatures::units`], and
/// `node_count` is carried along because every stage that proposes unit pairs
/// gates them on relative size.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct UnitRef {
    /// Index of the file in the input slice.
    pub file: usize,
    /// Index of the unit in the file's units.
    pub unit: usize,
    /// Node count of the unit subtree; the size used by length-ratio gates.
    pub node_count: u32,
}

impl UnitRef {
    /// Whether this unit and `other` are within `max_ratio` of each other in
    /// size. A large and a small unit are not a gapped copy of one another
    /// however their features happened to meet, so every stage that proposes
    /// unit pairs applies this before emitting one.
    #[must_use]
    pub fn within_length_ratio(self, other: Self, max_ratio: f64) -> bool {
        let (small, large) = if self.node_count <= other.node_count {
            (self.node_count, other.node_count)
        } else {
            (other.node_count, self.node_count)
        };
        if small == 0 {
            return large == 0;
        }
        f64::from(large) / f64::from(small) <= max_ratio
    }
}

/// One statement window: a fixed-length run of adjacent statements inside one
/// block, hashed from per-statement summaries.
///
/// The statements of a block are its direct children selected exactly as
/// [`IrNode::statement_summaries`] selects them: statement shapes plus
/// [`Shape::Native`] children. Each statement contributes its shape tag, its
/// native kind name (empty for common shapes) and the kind tags of its first
/// [`SUMMARY_HEAD_TOKENS`] tokens — kinds, never texts, so consistent renames
/// leave the hash unchanged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowFeature {
    /// Hash over the window's per-statement summaries.
    pub hash: FeatureHash,
    /// Window length, in statements.
    pub length: usize,
    /// Bytes from the first through the last statement; reporting only.
    pub range: ByteRange,
    /// Ordinal of the enclosing block within the unit, in walk order.
    ///
    /// Position, never identity: this locates the window so adjacent windows
    /// can be folded back into one statement run, and it never enters a hash
    /// (AGENTS.md invariant 3).
    pub block: u32,
    /// Index of the window's first statement within its block's statement
    /// sequence. Position, never identity, as for [`Self::block`].
    pub offset: u32,
}

/// One subtree fingerprint: a Merkle hash over an IR subtree.
///
/// `hash(node)` covers the node's shape tag, its native kind name and its
/// children's hashes in order — names and tokens are excluded, so two
/// subtrees match exactly when their shapes match node for node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubtreeFeature {
    /// The subtree's Merkle hash.
    pub hash: FeatureHash,
    /// Number of nodes in the subtree, its root included.
    pub node_count: usize,
    /// Source bytes the subtree root covers; reporting only.
    pub range: ByteRange,
}

/// Shape-tag counts plus tree size and depth: a candidate filter.
///
/// The count vector is a cheap lower-bound proxy for tree edit distance: two
/// subtrees within edit distance `d` differ by at most `2 * d` in L1 count
/// distance, so a large [`CharacteristicVector::l1_distance`] rules a pair
/// out without touching either tree. That is what
/// [`CharacteristicVector::shape_divergence`] gates candidate pairs on, and
/// what [`CharacteristicVector::cosine_similarity`] contributes to the
/// structural dimension of a verdict.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CharacteristicVector {
    /// Node count per shape tag; index = tag, index 0 unused.
    pub counts: [u32; SHAPE_TAG_SLOTS],
    /// Number of nodes on the longest root-to-leaf path of the unit subtree;
    /// a lone node has depth 1.
    pub max_depth: u32,
    /// Total number of nodes in the unit subtree.
    pub node_count: u32,
}

impl CharacteristicVector {
    /// L1 distance between the two count vectors. Depth and node count do
    /// not participate.
    #[must_use]
    pub fn l1_distance(&self, other: &Self) -> u64 {
        self.counts
            .iter()
            .zip(other.counts.iter())
            .map(|(&a, &b)| u64::from(a.abs_diff(b)))
            .sum()
    }

    /// How far apart the two shape mixes are, on a `0.0`–`1.0` scale: the L1
    /// count distance over the nodes the two units have between them. `0.0`
    /// when they hold the same shapes in the same numbers, `1.0` when they
    /// share no shape at all. `0.0` for two empty vectors, which are not
    /// divergent — they are simply nothing to tell apart.
    ///
    /// Size is part of it, and deliberately so: the vectors sum to their unit
    /// node counts, so the distance is at least `|na - nb| / (na + nb)` and a
    /// pair whose sizes differ by a factor of `r` scores at least
    /// `(r - 1) / (r + 1)` before any difference in shape mix is counted.
    /// A limit of 0.5 therefore says exactly what
    /// [`max_length_ratio`](crate::near_match::NearMatchConfig::max_length_ratio)'s
    /// 3.0 says about size, and says it about the shape mix too.
    #[must_use]
    pub fn shape_divergence(&self, other: &Self) -> f64 {
        let span = u64::from(self.node_count) + u64::from(other.node_count);
        if span == 0 {
            return 0.0;
        }
        // Both vectors sum to at most their node counts, so the distance
        // cannot exceed the span and the result stays inside the unit range.
        #[expect(
            clippy::cast_precision_loss,
            reason = "node counts of this size lose nothing a threshold comparison would notice"
        )]
        {
            self.l1_distance(other) as f64 / span as f64
        }
    }

    /// Cosine similarity of the two count vectors, `0.0` when either vector
    /// is all-zero. Depth and node count do not participate.
    #[must_use]
    pub fn cosine_similarity(&self, other: &Self) -> f64 {
        if self.counts.iter().all(|&c| c == 0) || other.counts.iter().all(|&c| c == 0) {
            return 0.0;
        }
        let mut dot = 0.0f64;
        let mut norm_self = 0.0f64;
        let mut norm_other = 0.0f64;
        for (&a, &b) in self.counts.iter().zip(other.counts.iter()) {
            let (a, b) = (f64::from(a), f64::from(b));
            dot = a.mul_add(b, dot);
            norm_self = a.mul_add(a, norm_self);
            norm_other = b.mul_add(b, norm_other);
        }
        dot / (norm_self * norm_other).sqrt()
    }
}

/// The approximate control-flow profile of one unit.
///
/// Built by one pre-order walk that emits a control-op byte sequence: loop,
/// branch and match-arm enters and exits, a match enter carrying its arm
/// count, and single ops for `try`, `return`, `break`, `continue` and calls.
/// See the module documentation for why this is a syntactic approximation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CfgFeature {
    /// Hash over the control-op sequence.
    pub hash: FeatureHash,
    /// Hash over the same sequence with calls left out: the unit's branching
    /// and looping shape alone.
    ///
    /// A call is an operation the unit performs, not a fork in the path
    /// through it, and codehelion already describes calls separately in
    /// [`ApiCallFeature`]. Keeping them out of one of the two hashes gives a
    /// key that survives an edit which only adds calls, which is what makes it
    /// usable as a candidate-extraction index.
    pub skeleton_hash: FeatureHash,
    /// Number of control ops emitted.
    pub op_count: u32,
    /// Number of ops behind [`Self::skeleton_hash`]: `op_count` less the calls.
    pub skeleton_ops: u32,
    /// Deepest loop nesting in the unit subtree; `0` without loops.
    pub max_loop_depth: u32,
    /// Number of two-way conditionals in the unit subtree.
    pub branch_count: u32,
}

/// The API-call profile of one unit.
///
/// This is the one feature where identifier text enters hashes — by design:
/// external API names are normalization-exempt, matching the Fast engine's
/// treatment of external names. The callee of a call is approximated as the
/// last identifier token strictly before the call's first `(` token, which
/// covers `f(...)`, `obj.method(...)` and `ns::f(...)`; calls where no such
/// identifier exists are skipped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiCallFeature {
    /// Callee names in source order.
    pub names: Vec<Lexeme>,
    /// Hash over the names in source order.
    pub sequence_hash: FeatureHash,
    /// Hash over the sorted names: the order-independent multiset view.
    pub multiset_hash: FeatureHash,
}

/// Control-op byte values of the [`CfgFeature`] sequence.
const OP_LOOP_ENTER: u8 = 1;
const OP_LOOP_EXIT: u8 = 2;
const OP_BRANCH_ENTER: u8 = 3;
const OP_BRANCH_EXIT: u8 = 4;
const OP_MATCH_ENTER: u8 = 5;
const OP_MATCH_EXIT: u8 = 6;
const OP_ARM_ENTER: u8 = 7;
const OP_ARM_EXIT: u8 = 8;
const OP_TRY: u8 = 9;
const OP_RETURN: u8 = 10;
const OP_BREAK: u8 = 11;
const OP_CONTINUE: u8 = 12;
const OP_CALL: u8 = 13;

/// Extract the candidate features of every unit in `file`.
///
/// Units are the nodes whose shape is [`Shape::Function`], [`Shape::Method`]
/// or [`Shape::Closure`], visited in pre-order, so a nested closure or local
/// function yields its own entry after its host's.
#[must_use]
pub fn extract(file: &SyntaxIrFile) -> FileFeatures {
    let mut units = Vec::new();
    file.walk(&mut |node| {
        if matches!(node.shape, Shape::Function | Shape::Method | Shape::Closure) {
            units.push(unit_features(node, &file.tokens));
        }
    });
    FileFeatures { units }
}

/// Compute all four feature families for one unit subtree.
fn unit_features(unit: &IrNode, tokens: &[Token]) -> UnitFeatures {
    let mut windows = Vec::new();
    let mut block = 0u32;
    unit.walk(&mut |node| {
        if matches!(node.shape, Shape::Block) {
            block_windows(node, block, tokens, &mut windows);
            block = block.saturating_add(1);
        }
    });

    let mut subtrees = Vec::new();
    let _ = subtree_features(unit, &mut subtrees);

    let mut vector = CharacteristicVector::default();
    accumulate_vector(unit, 1, &mut vector);

    UnitFeatures {
        name: unit.name.clone(),
        shape_tag: unit.shape.tag(),
        range: unit.range,
        windows,
        subtrees,
        vector,
        cfg: cfg_feature(unit),
        api: api_feature(unit, tokens),
    }
}

/// The native kind name of a shape; empty for the common shapes.
fn native_kind(shape: &Shape) -> &str {
    match shape {
        Shape::Native(kind) => kind.as_str(),
        _ => "",
    }
}

/// Slide every window length over one block's statement sequence.
fn block_windows(block: &IrNode, ordinal: u32, tokens: &[Token], out: &mut Vec<WindowFeature>) {
    let statements: Vec<&IrNode> = block
        .children
        .iter()
        .filter(|child| child.shape.is_statement() || matches!(child.shape, Shape::Native(_)))
        .collect();
    for &length in WINDOW_LENGTHS {
        for (offset, window) in statements.windows(length).enumerate() {
            let mut hasher = FeatureHasher::new("stmt-window");
            hasher.write_u32(u32::try_from(length).unwrap_or(u32::MAX));
            for statement in window {
                write_statement(&mut hasher, statement, tokens);
            }
            out.push(WindowFeature {
                hash: hasher.finish(),
                length,
                range: ByteRange {
                    start: window[0].range.start,
                    end: window[length - 1].range.end,
                },
                block: ordinal,
                offset: u32::try_from(offset).unwrap_or(u32::MAX),
            });
        }
    }
}

/// Write one statement's summary: shape tag, native kind name, and the kind
/// tags — never the texts — of its leading tokens.
fn write_statement(hasher: &mut FeatureHasher, statement: &IrNode, tokens: &[Token]) {
    hasher.write_u8(statement.shape.tag());
    hasher.write_str(native_kind(&statement.shape));
    let end = statement.token_end.min(tokens.len());
    let start = statement.token_start.min(end);
    let head_tags: Vec<u8> = tokens[start..end]
        .iter()
        .take(SUMMARY_HEAD_TOKENS)
        .map(|token| token.kind.tag())
        .collect();
    hasher.write_bytes(&head_tags);
}

/// One post-order pass computing every node's Merkle hash and subtree size,
/// emitting a [`SubtreeFeature`] for subtrees of qualifying size. Children
/// are emitted before their ancestors.
fn subtree_features(node: &IrNode, out: &mut Vec<SubtreeFeature>) -> (FeatureHash, usize) {
    let mut child_hashes = Vec::with_capacity(node.children.len());
    let mut node_count = 1usize;
    for child in &node.children {
        let (hash, count) = subtree_features(child, out);
        node_count += count;
        child_hashes.push(hash);
    }

    let mut hasher = FeatureHasher::new("subtree");
    hasher.write_u8(node.shape.tag());
    hasher.write_str(native_kind(&node.shape));
    hasher.write_u32(u32::try_from(child_hashes.len()).unwrap_or(u32::MAX));
    for hash in &child_hashes {
        hasher.write_bytes(hash.as_bytes());
    }
    let hash = hasher.finish();

    if node_count >= MIN_SUBTREE_NODES {
        out.push(SubtreeFeature {
            hash,
            node_count,
            range: node.range,
        });
    }
    (hash, node_count)
}

/// Accumulate shape counts, depth and size over one subtree. The subtree
/// root is at depth 1.
fn accumulate_vector(node: &IrNode, depth: u32, vector: &mut CharacteristicVector) {
    vector.node_count += 1;
    vector.max_depth = vector.max_depth.max(depth);
    vector.counts[usize::from(node.shape.tag())] += 1;
    for child in &node.children {
        accumulate_vector(child, depth + 1, vector);
    }
}

/// State of the control-op walk behind [`CfgFeature`].
#[derive(Default)]
struct CfgWalk {
    ops: Vec<u8>,
    skeleton: Vec<u8>,
    op_count: u32,
    skeleton_ops: u32,
    branch_count: u32,
    loop_depth: u32,
    max_loop_depth: u32,
}

impl CfgWalk {
    fn push_op(&mut self, op: u8) {
        self.ops.push(op);
        self.op_count += 1;
        if op != OP_CALL {
            self.skeleton.push(op);
            self.skeleton_ops += 1;
        }
    }

    /// Write raw operand bytes to both sequences: they qualify the op they
    /// follow rather than being ops themselves, so they are not counted.
    fn push_operand(&mut self, bytes: &[u8]) {
        self.ops.extend_from_slice(bytes);
        self.skeleton.extend_from_slice(bytes);
    }

    fn visit_children(&mut self, node: &IrNode) {
        for child in &node.children {
            self.visit(child);
        }
    }

    fn visit(&mut self, node: &IrNode) {
        match &node.shape {
            Shape::Loop => {
                self.push_op(OP_LOOP_ENTER);
                self.loop_depth += 1;
                self.max_loop_depth = self.max_loop_depth.max(self.loop_depth);
                self.visit_children(node);
                self.loop_depth -= 1;
                self.push_op(OP_LOOP_EXIT);
            }
            Shape::Branch => {
                self.push_op(OP_BRANCH_ENTER);
                self.branch_count += 1;
                self.visit_children(node);
                self.push_op(OP_BRANCH_EXIT);
            }
            Shape::Match => {
                self.push_op(OP_MATCH_ENTER);
                let arms = node
                    .children
                    .iter()
                    .filter(|child| matches!(child.shape, Shape::MatchArm))
                    .count();
                let arms = u32::try_from(arms).unwrap_or(u32::MAX);
                self.push_operand(&arms.to_le_bytes());
                self.visit_children(node);
                self.push_op(OP_MATCH_EXIT);
            }
            Shape::MatchArm => {
                self.push_op(OP_ARM_ENTER);
                self.visit_children(node);
                self.push_op(OP_ARM_EXIT);
            }
            Shape::Try => {
                self.push_op(OP_TRY);
                self.visit_children(node);
            }
            Shape::Return => {
                self.push_op(OP_RETURN);
                self.visit_children(node);
            }
            Shape::Break => {
                self.push_op(OP_BREAK);
                self.visit_children(node);
            }
            Shape::Continue => {
                self.push_op(OP_CONTINUE);
                self.visit_children(node);
            }
            Shape::Call => {
                self.push_op(OP_CALL);
                self.visit_children(node);
            }
            _ => self.visit_children(node),
        }
    }
}

/// Build the control-flow profile of one unit subtree.
fn cfg_feature(unit: &IrNode) -> CfgFeature {
    let mut walk = CfgWalk::default();
    walk.visit(unit);
    let mut hasher = FeatureHasher::new("cfg");
    hasher.write_bytes(&walk.ops);
    // A separate domain, so the two never collide for a unit that calls
    // nothing and whose sequences are therefore byte-identical.
    let mut skeleton = FeatureHasher::new("cfg-skeleton");
    skeleton.write_bytes(&walk.skeleton);
    CfgFeature {
        hash: hasher.finish(),
        skeleton_hash: skeleton.finish(),
        op_count: walk.op_count,
        skeleton_ops: walk.skeleton_ops,
        max_loop_depth: walk.max_loop_depth,
        branch_count: walk.branch_count,
    }
}

/// The callee name of one call node: the text of the last identifier token
/// strictly before the call's first `(` token, or `None` when either is
/// missing from the call's token range.
fn callee_name(call: &IrNode, tokens: &[Token]) -> Option<Lexeme> {
    let end = call.token_end.min(tokens.len());
    let start = call.token_start.min(end);
    let slice = &tokens[start..end];
    let open = slice
        .iter()
        .position(|token| matches!(token.kind, TokenKind::Punctuation) && token.text == "(")?;
    slice[..open]
        .iter()
        .rev()
        .find(|token| matches!(token.kind, TokenKind::Identifier))
        .map(|token| token.text.clone())
}

/// Build the API-call profile of one unit subtree.
fn api_feature(unit: &IrNode, tokens: &[Token]) -> ApiCallFeature {
    let mut names: Vec<Lexeme> = Vec::new();
    unit.walk(&mut |node| {
        if matches!(node.shape, Shape::Call) {
            if let Some(name) = callee_name(node, tokens) {
                names.push(name);
            }
        }
    });

    let mut sequence = FeatureHasher::new("api-call");
    for name in &names {
        sequence.write_str(name);
    }

    let mut sorted: Vec<&Lexeme> = names.iter().collect();
    sorted.sort_unstable_by(|a, b| a.as_str().cmp(b.as_str()));
    let mut multiset = FeatureHasher::new("api-call-set");
    for name in sorted {
        multiset.write_str(name);
    }

    ApiCallFeature {
        names,
        sequence_hash: sequence.finish(),
        multiset_hash: multiset.finish(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
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
}
