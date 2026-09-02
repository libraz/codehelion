//! Nesting preflight for the Rust structural frontend.
//!
//! The recursive CST parser is only entered while a nonrecursive budget,
//! charged token by token over the lexer's stream, can still bound both its
//! recursion and the structural IR it would produce. When the budget is
//! exceeded, the file is represented as the healthy prefix plus one explicit
//! Error leaf over the omitted region.

use codehelion_core::discovery::Language;
use codehelion_core::frontend::Token;
use codehelion_core::ir::{
    ByteRange, IR_SCHEMA_VERSION, MAX_IR_DEPTH, SyntaxIrFile, canonicalize_signatures,
};
use ra_ap_syntax::SourceFile;

use super::{IrBuilder, PARSE_EDITION, STRUCTURAL_FRONTEND_VERSION};

/// Tokens that end both a generic argument list and an expression, so any `<`
/// or assignment still open in the current group has been given back by the
/// time one is reached. `for` is deliberately absent: `for<'a>` binders are
/// part of the type grammar.
const CHAIN_CLEARING_TOKENS: &[&str] = &[
    ";", "=>", "let", "if", "while", "loop", "match", "return", "break", "continue",
];

/// Right-associative assignment operators. Each one makes the parser descend
/// into the rest of the expression, so `x = y = z` nests as deeply as it is
/// long.
const ASSIGNMENT_TOKENS: &[&str] = &[
    "=", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "<<=", ">>=",
];

/// The nesting one operator token contributes, or `None` when the token is not
/// an operator. Prefix, infix and postfix operators are charged alike: each one
/// makes the parser descend once, whichever side its operand is on, and the
/// resulting CST is that deep no matter which way the operator associates. The
/// lexer glues `&&` into a single token, so a double reference costs two
/// levels. `<`, `>` and their glued forms are absent because they are already
/// charged as generic-argument nesting.
fn operator_nesting(text: &str) -> Option<usize> {
    match text {
        "&&" => Some(2),
        "+" | "-" | "*" | "/" | "%" | "&" | "|" | "^" | "!" | "?" | "." | "::" | "as" | "||"
        | ".." | "..=" | "..." | "==" | "!=" | "<=" | ">=" => Some(1),
        _ => None,
    }
}

/// One `{`, `(` or `[` group, together with the nesting opened directly inside
/// it by constructs that no delimiter pair can span.
struct NestingFrame {
    /// The closing token this group expects, or `None` for the file itself.
    closer: Option<&'static str>,
    /// Generic-argument and assignment nesting opened inside this group and
    /// not yet given back.
    chains: usize,
    /// Operator nesting accumulated inside this group since the last token
    /// that ended an expression.
    operators: usize,
}

/// Upper bound on the CST depth the recursive Rust parser would reach,
/// accumulated token by token over the nonrecursive lexer's stream.
///
/// Every production that makes the parser descend draws on one budget:
/// delimiter groups, generic argument lists, assignments and operator chains.
/// Each group carries its own counts and gives them back when it closes,
/// because none of those constructs spans a delimiter pair.
///
/// Delimiter groups are unambiguous. Angle brackets are not — `a < b` is a
/// comparison, not a nested type — so they are counted as an upper bound,
/// cleared by [`CHAIN_CLEARING_TOKENS`] and never by a token a generic argument
/// list may contain. That is why a `Map<K, Map<K, …>>` chain stays charged for
/// its full depth even though a comma sits at every level, while a comma does
/// clear the operator count: a comma always ends the expression it separates.
struct NestingDepth {
    /// The file is the outermost frame, so this is never empty.
    frames: Vec<NestingFrame>,
    /// Chain depth summed over every open frame.
    chains: usize,
    /// Operator depth summed over every open frame.
    operators: usize,
}

impl NestingDepth {
    fn new() -> Self {
        Self {
            frames: vec![NestingFrame {
                closer: None,
                chains: 0,
                operators: 0,
            }],
            chains: 0,
            operators: 0,
        }
    }

    /// The budget spent so far. The file's own frame is not nesting, so it is
    /// excluded from the group count.
    const fn depth(&self) -> usize {
        self.frames.len() - 1 + self.chains + self.operators
    }

    /// Open `opened` levels of chain nesting in the innermost group.
    fn open_chain(&mut self, opened: usize) {
        if let Some(frame) = self.frames.last_mut() {
            frame.chains += opened;
            self.chains += opened;
        }
    }

    /// Give back at most `requested` levels of chain nesting.
    fn close_chain(&mut self, requested: usize) {
        if let Some(frame) = self.frames.last_mut() {
            let closed = requested.min(frame.chains);
            frame.chains -= closed;
            self.chains -= closed;
        }
    }

    /// Open `opened` levels of operator nesting in the innermost group.
    fn open_operators(&mut self, opened: usize) {
        if let Some(frame) = self.frames.last_mut() {
            frame.operators += opened;
            self.operators += opened;
        }
    }

    /// Give back the innermost group's operator nesting, which one ended
    /// expression cannot carry into the next.
    fn clear_operators(&mut self) {
        if let Some(frame) = self.frames.last_mut() {
            self.operators -= frame.operators;
            frame.operators = 0;
        }
    }

    /// Charge one token against the budget and report the depth it reaches.
    fn feed(&mut self, text: &str) -> usize {
        match text {
            "{" | "(" | "[" => {
                let closer = match text {
                    "{" => "}",
                    "(" => ")",
                    _ => "]",
                };
                self.frames.push(NestingFrame {
                    closer: Some(closer),
                    chains: 0,
                    operators: 0,
                });
            }
            "}" | ")" | "]" => {
                if self
                    .frames
                    .last()
                    .is_some_and(|frame| frame.closer == Some(text))
                    && let Some(frame) = self.frames.pop()
                {
                    self.chains -= frame.chains;
                    self.operators -= frame.operators;
                }
            }
            // A closing run reaches the preflight glued into `>>` tokens, so
            // each one gives back both of the levels it closes.
            "<" => self.open_chain(1),
            "<<" => self.open_chain(2),
            ">" => self.close_chain(1),
            ">>" => self.close_chain(2),
            "," => self.clear_operators(),
            _ => {
                if let Some(step) = operator_nesting(text) {
                    self.open_operators(step);
                } else if ASSIGNMENT_TOKENS.contains(&text) {
                    self.open_chain(1);
                } else if CHAIN_CLEARING_TOKENS.contains(&text) {
                    self.close_chain(self.chains);
                    self.clear_operators();
                }
            }
        }
        self.depth()
    }
}

/// Return the source range that must not enter the recursive Rust CST parser.
///
/// The Rust lexer is nonrecursive and already treats comments and literals as
/// atomic tokens, so nesting punctuation inside either cannot be mistaken for
/// syntax here. The parser is only entered while this same nesting budget can
/// still bound both its own recursion and the structural IR it would produce.
pub(super) fn nesting_overflow(tokens: &[Token], source_len: usize) -> Option<ByteRange> {
    let mut nesting = NestingDepth::new();
    for token in tokens {
        if nesting.feed(&token.text) > MAX_IR_DEPTH {
            return Some(ByteRange {
                start: token.span.start_byte,
                end: source_len,
            });
        }
    }
    None
}

/// Build the explicit partial result returned when preflight blocks CST
/// construction for excessive nesting.
///
/// `tokens` is the preflight stream over the whole file. Node token indices
/// address the stream this returns, so the prefix's own parse supplies every
/// token a node can cover, and the omitted region contributes its tokens after
/// them under one Error leaf.
pub(super) fn depth_error_file(source: &str, tokens: Vec<Token>, range: ByteRange) -> SyntaxIrFile {
    // The nesting preflight tells us where recursive parsing must stop, but
    // it does not make the source before that point unusable. Parse that
    // prefix independently so healthy functions remain available even when a
    // later generated expression exceeds the depth budget.
    let prefix_end = safe_depth_prefix_end(&tokens, range);
    let omitted_range = ByteRange {
        start: prefix_end,
        end: range.end,
    };
    let prefix = source.get(..prefix_end).unwrap_or("");
    let parse = SourceFile::parse(prefix, PARSE_EDITION);
    let root = parse.syntax_node();
    let mut builder = IrBuilder::new(prefix);
    builder.collect_tokens(&root);
    let mut roots = Vec::new();
    for child in root.children() {
        builder.visit(&child, &mut roots, 1);
    }
    for error in parse.errors() {
        let error_range = error.range();
        builder.assembly.record_error_range(ByteRange {
            start: usize::from(error_range.start()),
            end: usize::from(error_range.end()),
        });
    }

    // The prefix parse produced the tokens the nodes above were indexed
    // against; the omitted region has no parse, so its tokens are appended
    // from the preflight stream and covered by the Error leaf alone. Their
    // positions come from the whole-file preflight, not from the prefix the
    // assembly was given, so they are appended with the spans they carry.
    for token in tokens {
        if token.span.start_byte >= omitted_range.start {
            builder
                .assembly
                .push_spanned_token(token.kind, &token.text, token.span);
        }
    }
    roots.push(builder.assembly.truncate_at_depth(omitted_range));

    let signatures = canonicalize_signatures(builder.signatures);
    let assembled = builder.assembly.finish();
    SyntaxIrFile {
        language: Language::Rust,
        frontend_version: STRUCTURAL_FRONTEND_VERSION,
        ir_schema_version: IR_SCHEMA_VERSION,
        tokens: assembled.tokens,
        signatures,
        roots,
        diagnostics: Vec::new(),
        error_ranges: assembled.error_ranges,
        depth_truncated: assembled.depth_truncated,
        test_module: false,
    }
}

/// Keep the recovery parse shallow enough that the parser itself cannot
/// overflow its native call stack while still retaining top-level units that
/// precede a pathological nesting run. The omitted range is represented as
/// one explicit Error leaf below.
fn safe_depth_prefix_end(tokens: &[Token], overflow: ByteRange) -> usize {
    let safe_limit = (MAX_IR_DEPTH / 8).max(1);
    let mut nesting = NestingDepth::new();
    for token in tokens {
        if token.span.start_byte >= overflow.start {
            break;
        }
        if nesting.feed(&token.text) >= safe_limit {
            return token.span.start_byte;
        }
    }
    overflow.start
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::ir::test_support::parse;
    use codehelion_core::ir::{IrNode, Shape};

    fn assert_bounded_depth_truncation(file: &SyntaxIrFile, source_len: usize) {
        assert!(
            file.depth_truncated,
            "a depth-limited parse must be distinguished from ordinary recovery"
        );
        let mut deepest = 0;
        let mut error_leaves = Vec::new();
        let mut pending: Vec<(&IrNode, usize)> = file.roots.iter().map(|root| (root, 1)).collect();
        while let Some((node, depth)) = pending.pop() {
            deepest = deepest.max(depth);
            if node.shape == Shape::Error && node.children.is_empty() {
                error_leaves.push(node.range);
            }
            pending.extend(node.children.iter().rev().map(|child| (child, depth + 1)));
        }

        assert!(
            deepest <= MAX_IR_DEPTH,
            "IR depth {deepest} exceeds the frontend limit {MAX_IR_DEPTH}"
        );
        assert!(
            error_leaves.iter().any(|range| {
                !range.is_empty() && range.end <= source_len && file.error_ranges.contains(range)
            }),
            "depth truncation must be represented by an Error leaf and error range"
        );

        let mut visited = 0;
        file.walk(&mut |_| visited += 1);
        assert_eq!(visited, file.node_count());
    }

    #[test]
    fn deeply_nested_rust_is_truncated_without_unbounded_ir() {
        let depth = 10_000;
        let ignored_braces = "{".repeat(depth);
        let control_source =
            format!("fn control() {{ /* {ignored_braces} */ let text = \"{ignored_braces}\"; }}");
        let control = parse(&control_source);
        assert!(control.error_ranges.is_empty());
        assert!(
            control.roots.iter().all(|node| node.shape != Shape::Error),
            "delimiters in comments and literals must not consume nesting budget"
        );

        let mut builder_guard_source = String::from("fn builder_guard() ");
        builder_guard_source.push_str(&"{".repeat(MAX_IR_DEPTH));
        builder_guard_source.push_str("()");
        builder_guard_source.push_str(&"}".repeat(MAX_IR_DEPTH));
        let builder_guard_file = parse(&builder_guard_source);
        assert_bounded_depth_truncation(&builder_guard_file, builder_guard_source.len());

        let mut source = String::from("fn deeply_nested() ");
        source.push_str(&"{".repeat(depth));
        source.push_str("()");
        source.push_str(&"}".repeat(depth));

        let file = parse(&source);
        assert_bounded_depth_truncation(&file, source.len());
        drop(file);
        drop(builder_guard_file);
        drop(control);
    }

    #[test]
    fn a_truncated_file_indexes_the_stream_it_returns() {
        // Nested generics close as one `>>` token for the preflight lexer and
        // as two `>` tokens for the parser, so every node after them resolves
        // to the wrong token unless the stream returned is the one the node
        // ranges were measured against.
        let mut source = String::from(
            "fn healthy(v: Vec<Vec<u8>>) -> usize { let total = v.len(); total }\nfn generated() ",
        );
        source.push_str(&"{".repeat(10_000));
        source.push_str("()");
        source.push_str(&"}".repeat(10_000));

        let file = parse(&source);
        assert!(file.depth_truncated);
        let mut nodes = 0;
        file.walk(&mut |node| {
            nodes += 1;
            assert!(
                node.token_start <= node.token_end && node.token_end <= file.tokens.len(),
                "node token range {}..{} is not a range of the file's {} tokens",
                node.token_start,
                node.token_end,
                file.tokens.len()
            );
            if node.token_start < node.token_end {
                assert_eq!(
                    file.tokens[node.token_start].span.start_byte, node.range.start,
                    "node of shape {:?} starts at a token from another stream",
                    node.shape
                );
                assert!(file.tokens[node.token_end - 1].span.end_byte <= node.range.end);
            }
        });
        assert!(nodes > 1, "the healthy prefix must survive truncation");

        let omitted = file
            .roots
            .last()
            .expect("a truncated file keeps the omitted region as a root");
        assert_eq!(omitted.shape, Shape::Error);
        assert_eq!(omitted.token_end, file.tokens.len());
        assert!(
            omitted.token_start < omitted.token_end,
            "the omitted region's tokens stay in the stream it is indexed against"
        );
    }

    /// The stack the pathological-nesting regressions run on. A generous
    /// default stack hides how close the parser's recursive descent comes to
    /// overflowing, so these cases are measured against a fixed small one; if
    /// preflight lets them through, the thread overflows and takes the whole
    /// process down instead of failing an assertion.
    const BOUNDED_STACK_BYTES: usize = 2 * 1024 * 1024;

    fn parse_on_bounded_stack(source: String) -> SyntaxIrFile {
        std::thread::Builder::new()
            .stack_size(BOUNDED_STACK_BYTES)
            .spawn(move || parse(&source))
            .expect("the parse thread must start")
            .join()
            .expect("parse must return a file instead of aborting the process")
    }

    #[test]
    fn deeply_nested_generics_are_truncated_instead_of_reaching_the_parser() {
        let nesting = 1_200;
        let mut source = String::from("fn generated(value: ");
        source.push_str(&"Vec<".repeat(nesting));
        source.push_str("u8");
        source.push_str(&">".repeat(nesting));
        source.push_str(") { let _ = value; }");

        let source_len = source.len();
        let file = parse_on_bounded_stack(source);
        assert_bounded_depth_truncation(&file, source_len);
    }

    #[test]
    fn a_long_prefix_operator_chain_is_truncated_instead_of_reaching_the_parser() {
        let nesting = 20_000;
        let mut source = String::from("fn generated() -> i64 { ");
        source.push_str(&"-".repeat(nesting));
        source.push_str("1 }");

        let source_len = source.len();
        let file = parse_on_bounded_stack(source);
        assert_bounded_depth_truncation(&file, source_len);
    }

    #[test]
    fn a_long_range_operator_chain_is_truncated_instead_of_reaching_the_parser() {
        let nesting = 20_000;
        let mut source = String::from("fn generated() { let _ = ");
        source.push_str(&"..".repeat(nesting));
        source.push_str("1; }");

        let source_len = source.len();
        let file = parse_on_bounded_stack(source);
        assert_bounded_depth_truncation(&file, source_len);
    }

    #[test]
    fn a_long_assignment_chain_is_truncated_instead_of_reaching_the_parser() {
        // Assignment is right-associative, so the parser descends once per
        // `=` even though an operand separates them and no chain of prefix
        // operators is present.
        let nesting = 20_000;
        let mut source = String::from("fn generated() { ");
        source.push_str(&"x = ".repeat(nesting));
        source.push_str("1; }");

        let source_len = source.len();
        let file = parse_on_bounded_stack(source);
        assert_bounded_depth_truncation(&file, source_len);
    }

    #[test]
    fn long_operator_chains_are_truncated_instead_of_reaching_the_parser() {
        // A left-associative chain nests to the left instead of the right, and
        // arrives as a plain run of operators rather than as nesting
        // punctuation, but the CST it produces is exactly as deep.
        let nesting = 20_000;
        for source in [
            format!("fn generated() -> i64 {{ {}1 }}", "x + ".repeat(nesting)),
            format!("fn generated() -> i64 {{ x{} }}", " as i64".repeat(nesting)),
            format!(
                "fn generated() {{ let _ = x{}; }}",
                ".field".repeat(nesting)
            ),
            format!(
                "fn generated() {{ let _ = {}x; }}",
                "module::".repeat(nesting)
            ),
            format!("fn generated() {{ let _ = x{}; }}", "?".repeat(nesting)),
        ] {
            let source_len = source.len();
            let file = parse_on_bounded_stack(source);
            assert_bounded_depth_truncation(&file, source_len);
        }
    }

    #[test]
    fn nested_generics_stay_charged_across_the_comma_at_every_level() {
        // A comma separates generic arguments, so clearing the count at one
        // would leave a `Map<K, Map<K, …>>` chain measured as a single level
        // and hand the parser the nesting the budget exists to keep out.
        let nesting = 1_200;
        let mut source = String::from("fn generated(value: ");
        source.push_str(&"HashMap<u8, ".repeat(nesting));
        source.push_str("u8");
        source.push_str(&">".repeat(nesting));
        source.push_str(") { let _ = value; }");

        let source_len = source.len();
        let file = parse_on_bounded_stack(source);
        assert_bounded_depth_truncation(&file, source_len);
    }

    #[test]
    fn a_closing_run_gives_back_every_level_it_closes() {
        // The lexer glues a closing run into `>>` tokens. Charging one back
        // per token would leave residue behind every nested type and truncate
        // a file whose nesting never approaches the budget.
        use core::fmt::Write as _;

        let parameters = MAX_IR_DEPTH * 2;
        let mut source = String::from("fn generated(");
        for index in 0..parameters {
            let _ = write!(source, "p{index}: Vec<Vec<Vec<u8>>>, ");
        }
        source.push_str(") { }");

        let file = parse(&source);
        assert!(
            !file.depth_truncated,
            "balanced generic arguments must not accumulate nesting"
        );
    }

    #[test]
    fn comparisons_do_not_accumulate_against_the_nesting_budget() {
        // `<` is a comparison as often as it opens a type, and the preflight
        // cannot tell the two apart. A statement or block keyword ends any
        // generic argument list, so an unclosed comparison is given back there
        // rather than left to add up over a long function.
        use core::fmt::Write as _;

        let statements = MAX_IR_DEPTH * 4;
        let mut source = String::from("fn generated(a: u64, b: u64) -> u64 { let mut total = 0;\n");
        for index in 0..statements {
            let _ = writeln!(source, "if a < b {{ total += {index}; }}");
        }
        source.push_str("total }\n");

        let file = parse(&source);
        assert!(file.error_ranges.is_empty(), "{:?}", file.error_ranges);
        assert!(
            !file.depth_truncated,
            "ordinary comparisons must not exhaust the nesting budget"
        );
    }
}
