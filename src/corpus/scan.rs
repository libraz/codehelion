//! Brace-depth scanner locating items in a controlled-style seed source.
//!
//! This is deliberately not a parser. It relies on the controlled corpus
//! authoring style, shared by every supported language:
//!
//! - one statement per line;
//! - braces never appear inside string or character literals;
//! - only `//` line comments (`/* */` block comments are not supported);
//! - an item's opening `{` sits on its header line and its closing `}` on its
//!   own line (single-line bodies such as `struct X;` are also accepted for
//!   Rust);
//! - `impl` headers name a plain type (no trait impls).
//!
//! Header recognition is driven by the seed's [`Language`]:
//!
//! - **Rust** — top-level `fn` / `struct` / `enum` / `trait` / `impl` items
//!   plus the functions nested directly inside `impl` or `trait` blocks.
//! - **C / C++** — a function is a brace-opening header of the form
//!   `<stuff> <name>(<args>) {`, where the name is the identifier immediately
//!   before the first `(`; record headers are `struct <Name> {` (and, for
//!   C++, `class <Name> {`) with nothing else between the name and the `{`.
//!   Functions nested directly inside a `struct`/`class` body (C++ inline
//!   methods) are reported like Rust `impl` methods. Control-flow headers
//!   (`if (...) {`, `for (...) {`, ...) are never treated as functions.
//!
//! Item keys use the same scheme for every language: functions are keyed
//! `fn <name>` (even in C/C++, where `fn` is not a keyword), records
//! `struct <Name>` / `class <Name>`, so specs and labels stay uniform across
//! languages. The scanner reports inclusive 1-based line ranges.

/// Source language of a seed, selecting the item-header syntax the scanner
/// recognizes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Language {
    /// Rust: `fn` / `struct` / `enum` / `trait` / `impl` headers.
    Rust,
    /// C: `<stuff> <name>(<args>) {` functions and `struct <Name> {` records.
    C,
    /// C++: the C headers plus `class <Name> {` records.
    Cpp,
}

impl Language {
    /// Resolve a spec's `language` field (`rust` | `c` | `cpp`).
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "rust" => Some(Self::Rust),
            "c" => Some(Self::C),
            "cpp" => Some(Self::Cpp),
            _ => None,
        }
    }
}

/// One item found in the seed source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    /// Item key: the item keyword plus its name, e.g. `fn sum_even`,
    /// `struct Counter`, `impl Counter`.
    pub key: String,
    /// First line of the item (inclusive, 1-based).
    pub start_line: u32,
    /// Last line of the item (inclusive, 1-based).
    pub end_line: u32,
    /// Whether the item is a function nested inside an `impl`/`trait` block.
    pub nested: bool,
}

/// Keywords that begin a Rust item header.
const ITEM_KEYWORDS: [&str; 5] = ["fn", "struct", "enum", "trait", "impl"];

/// C/C++ keywords that can precede `(` on a brace-opening line but never name
/// a function.
const C_NON_FUNCTION_KEYWORDS: [&str; 6] = ["if", "for", "while", "switch", "return", "sizeof"];

const fn is_ident_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// Extract `keyword name` from a Rust item header line, if it is one.
fn rust_item_key(trimmed: &str) -> Option<String> {
    let rest = trimmed.strip_prefix("pub ").unwrap_or(trimmed);
    let keyword = ITEM_KEYWORDS
        .iter()
        .find(|&&kw| rest.strip_prefix(kw).is_some_and(|r| r.starts_with(' ')))?;
    let after = rest[keyword.len()..].trim_start();
    let name: String = after.chars().take_while(|&c| is_ident_char(c)).collect();
    if name.is_empty() {
        None
    } else {
        Some(format!("{keyword} {name}"))
    }
}

/// Extract a key from a C/C++ item header line, if it is one. Recognizes
/// `struct <Name> {` (plus `class <Name> {` when `allow_class` is set), keyed
/// as written, and brace-opening function headers, keyed `fn <name>` from the
/// identifier immediately before the first `(`. Any trailing `//` comment is
/// ignored; a header must end with its opening `{` on the same line, so
/// prototypes (`int f(int);`) are never items.
fn c_item_key(trimmed: &str, allow_class: bool) -> Option<String> {
    let code = trimmed.split("//").next().unwrap_or(trimmed).trim_end();
    let body = code.strip_suffix('{')?;
    for keyword in ["struct", "class"] {
        if keyword == "class" && !allow_class {
            continue;
        }
        if let Some(rest) = body.strip_prefix(keyword) {
            if rest.starts_with(' ') {
                let after = rest.trim_start();
                let name: String = after.chars().take_while(|&c| is_ident_char(c)).collect();
                // Only a bare record header (`struct Name {`) is an item; a
                // declaration with an initializer list is not.
                if !name.is_empty() && after[name.len()..].trim().is_empty() {
                    return Some(format!("{keyword} {name}"));
                }
            }
        }
    }
    let head = body[..body.find('(')?].trim_end();
    let name_start = head
        .char_indices()
        .rev()
        .take_while(|&(_, c)| is_ident_char(c))
        .last()
        .map(|(index, _)| index)?;
    let name = &head[name_start..];
    let named_like_function = name.chars().next().is_some_and(|c| !c.is_ascii_digit());
    if named_like_function && !C_NON_FUNCTION_KEYWORDS.contains(&name) {
        Some(format!("fn {name}"))
    } else {
        None
    }
}

/// Extract an item key from a header line under `language`'s syntax.
fn item_key(trimmed: &str, language: Language) -> Option<String> {
    match language {
        Language::Rust => rust_item_key(trimmed),
        Language::C => c_item_key(trimmed, false),
        Language::Cpp => c_item_key(trimmed, true),
    }
}

/// Net brace balance of a line, ignoring any trailing line comment.
fn brace_balance(line: &str) -> i32 {
    let code = line.split("//").next().unwrap_or(line);
    let mut balance = 0;
    for c in code.chars() {
        match c {
            '{' => balance += 1,
            '}' => balance -= 1,
            _ => {}
        }
    }
    balance
}

/// Scan `text` under `language`'s header syntax and return every item in
/// source order.
///
/// Duplicate keys are returned as-is; consumers that need unambiguous lookup
/// must reject them.
#[must_use]
pub fn scan_items(text: &str, language: Language) -> Vec<Item> {
    let mut items: Vec<Item> = Vec::new();
    // Indices into `items` of the still-open items, with the depth at which
    // each was opened.
    let mut open: Vec<(usize, i32)> = Vec::new();
    let mut depth: i32 = 0;

    for (index, line) in text.lines().enumerate() {
        let line_no = u32::try_from(index).unwrap_or(u32::MAX).saturating_add(1);
        let trimmed = line.trim();
        let balance = brace_balance(line);

        if !trimmed.is_empty() && !trimmed.starts_with("//") {
            let is_header_position = depth == 0 || (depth == 1 && !open.is_empty());
            if is_header_position {
                if let Some(key) = item_key(trimmed, language) {
                    let nested = depth == 1;
                    if !nested || key.starts_with("fn ") {
                        items.push(Item {
                            key,
                            start_line: line_no,
                            end_line: line_no,
                            nested,
                        });
                        if balance > 0 {
                            open.push((items.len() - 1, depth));
                        }
                        // A braceless single-line item (`struct X;`) is
                        // already complete with start == end.
                    }
                }
            }
        }

        depth += balance;
        while let Some(&(item_index, open_depth)) = open.last() {
            if depth <= open_depth {
                if let Some(item) = items.get_mut(item_index) {
                    item.end_line = line_no;
                }
                open.pop();
            } else {
                break;
            }
        }
    }
    items
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
// header comment

fn alpha(x: i32) -> i32 {
    if x > 0 {
        x
    } else {
        0
    }
}

struct Counter {
    count: u32,
}

impl Counter {
    fn value(&self) -> u32 {
        self.count
    }
}
";

    fn find<'a>(items: &'a [Item], key: &str) -> &'a Item {
        items
            .iter()
            .find(|item| item.key == key)
            .unwrap_or_else(|| panic!("item {key} not found in {items:?}"))
    }

    const C_SAMPLE: &str = "\
// header comment

int sum_even(const int *values, int count) {
    int total = 0;
    for (int i = 0; i < count; i++) {
        if (values[i] % 2 == 0) {
            total += values[i];
        }
    }
    return total;
}

struct counter {
    int count;
};

int counter_value(const struct counter *self) {
    return self->count;
}
";

    const CPP_SAMPLE: &str = "\
// header comment

int sum_even(const int *values, int count) {
    int total = 0;
    return total;
}

class Counter {
public:
    int value() const {
        return count_;
    }

private:
    int count_;
};
";

    #[test]
    fn finds_top_level_items_with_exact_ranges() {
        let items = scan_items(SAMPLE, Language::Rust);
        let alpha = find(&items, "fn alpha");
        assert_eq!((alpha.start_line, alpha.end_line), (3, 9));
        assert!(!alpha.nested);
        let counter = find(&items, "struct Counter");
        assert_eq!((counter.start_line, counter.end_line), (11, 13));
        let imp = find(&items, "impl Counter");
        assert_eq!((imp.start_line, imp.end_line), (15, 19));
    }

    #[test]
    fn finds_nested_functions() {
        let items = scan_items(SAMPLE, Language::Rust);
        let value = find(&items, "fn value");
        assert_eq!((value.start_line, value.end_line), (16, 18));
        assert!(value.nested);
    }

    #[test]
    fn else_branches_do_not_end_an_item() {
        let items = scan_items(SAMPLE, Language::Rust);
        let alpha = find(&items, "fn alpha");
        // The `} else {` on line 6 must not close `fn alpha`.
        assert_eq!(alpha.end_line, 9);
    }

    #[test]
    fn pub_items_and_braceless_items_are_found() {
        let text = "pub fn one() {\n    1\n}\n\nstruct Unit;\n";
        let items = scan_items(text, Language::Rust);
        let one = find(&items, "fn one");
        assert_eq!((one.start_line, one.end_line), (1, 3));
        let unit = find(&items, "struct Unit");
        assert_eq!((unit.start_line, unit.end_line), (5, 5));
    }

    #[test]
    fn braces_in_comments_are_ignored() {
        let text = "fn f() {\n    // ignore this brace }\n    1\n}\n";
        let items = scan_items(text, Language::Rust);
        let f = find(&items, "fn f");
        assert_eq!((f.start_line, f.end_line), (1, 4));
    }

    #[test]
    fn finds_c_items_with_exact_ranges() {
        let items = scan_items(C_SAMPLE, Language::C);
        let sum = find(&items, "fn sum_even");
        assert_eq!((sum.start_line, sum.end_line), (3, 11));
        assert!(!sum.nested);
        let counter = find(&items, "struct counter");
        assert_eq!((counter.start_line, counter.end_line), (13, 15));
        let getter = find(&items, "fn counter_value");
        assert_eq!((getter.start_line, getter.end_line), (17, 19));
        // Control-flow headers inside the function body are not items.
        assert_eq!(items.len(), 3, "unexpected items: {items:?}");
    }

    #[test]
    fn finds_cpp_class_and_nested_method_with_exact_ranges() {
        let items = scan_items(CPP_SAMPLE, Language::Cpp);
        let sum = find(&items, "fn sum_even");
        assert_eq!((sum.start_line, sum.end_line), (3, 6));
        let class = find(&items, "class Counter");
        assert_eq!((class.start_line, class.end_line), (8, 16));
        assert!(!class.nested);
        let value = find(&items, "fn value");
        assert_eq!((value.start_line, value.end_line), (10, 12));
        assert!(value.nested);
        assert_eq!(items.len(), 3, "unexpected items: {items:?}");
    }

    #[test]
    fn c_prototypes_and_class_outside_cpp_are_not_items() {
        let text = "int f(int x);\n\nclass Counter {\n};\n";
        let items = scan_items(text, Language::C);
        assert!(
            items.is_empty(),
            "prototype/class must not be C items: {items:?}"
        );
    }

    #[test]
    fn rust_detection_is_unchanged_by_the_language_dispatch() {
        // The C sample under Rust rules finds only the `struct` header; the
        // Rust sample under Rust rules finds the same items as before.
        let items = scan_items(C_SAMPLE, Language::Rust);
        let keys: Vec<&str> = items.iter().map(|item| item.key.as_str()).collect();
        assert_eq!(keys, vec!["struct counter"]);
        let items = scan_items(SAMPLE, Language::Rust);
        let keys: Vec<&str> = items.iter().map(|item| item.key.as_str()).collect();
        assert_eq!(
            keys,
            vec!["fn alpha", "struct Counter", "impl Counter", "fn value"]
        );
    }
}
