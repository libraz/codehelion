//! Name stems: the part of a symbol name that template arguments, closure
//! numbering and parameter lists do not change.
//!
//! A stem runs up to the first parameterized path component, so a function
//! template groups by function, a class template's members by the class
//! template, and a closure by its enclosing function. Grouping is exact
//! equality of the stem string, an equivalence relation, not similarity.

use std::ops::Range;

use crate::ownership::{TRAILING_QUALIFIERS, function_name, head, judging_name, levels, normalize};

/// Separator between path components.
const PATH_SEPARATOR: &str = "::";
/// Stem spelling of a closure component.
const CLOSURE_STEM: &str = "{closure}";
/// Stem spelling of one erased template argument list.
const ERASED_ARGUMENTS: &str = "<>";

/// The stem of one symbol name and the instance spelling it was taken from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameStem {
    /// Grouping key: the path up to its first parameterized component, with
    /// template arguments written `<>` and closures `{closure}`; no parameter
    /// list, return type, or toolchain decoration.
    pub stem: String,
    /// The same prefix with the arguments kept (for a name with no
    /// parameterized component, the normalized name without its return type).
    pub instance: String,
    /// Whether a component was erased to form the stem.
    pub parameterized: bool,
}

/// Stem of a symbol named `name`, or `None` for a name without a function
/// name to group by.
///
/// `strip_platform_underscore` has the meaning it has for
/// [`owner_of`](crate::ownership::owner_of), and the name is normalized the
/// same way.
#[must_use]
pub fn name_stem(name: &str, strip_platform_underscore: bool) -> Option<NameStem> {
    let name = without_duplicate_suffix(judging_name(name, strip_platform_underscore));
    let (normalized, _) = normalize(name)?;
    let head_text = head(&normalized);
    let base = function_name(head_text);
    if !base.chars().any(is_identifier_char) {
        return None;
    }
    let mut stem = String::with_capacity(base.len());
    for (index, range) in components(base).into_iter().enumerate() {
        if index > 0 {
            stem.push_str(PATH_SEPARATOR);
        }
        let component = head(&base[range.clone()]);
        if let Some(erased) = erased(component) {
            stem.push_str(&erased);
            return Some(NameStem {
                stem,
                instance: base[..range.end].to_owned(),
                parameterized: true,
            });
        }
        stem.push_str(component);
    }
    let start = head_text.trim_end().len() - base.len();
    Some(NameStem {
        stem,
        instance: normalized[start..].to_owned(),
        parameterized: false,
    })
}

/// `name` without the `_<digits>` a name section appends to a duplicate,
/// which follows a parameter list, a trailing qualifier, or a clone annotation.
fn without_duplicate_suffix(name: &str) -> &str {
    let before_digits = name.trim_end_matches(|character: char| character.is_ascii_digit());
    if before_digits.len() == name.len() {
        return name;
    }
    let Some(rest) = before_digits.strip_suffix('_') else {
        return name;
    };
    let follows_signature = rest.ends_with(')')
        || rest.ends_with(']')
        || TRAILING_QUALIFIERS
            .iter()
            .any(|qualifier| rest.ends_with(qualifier));
    if follows_signature { rest } else { name }
}

/// Whether `character` can appear in an identifier.
const fn is_identifier_char(character: char) -> bool {
    character.is_ascii_alphanumeric()
        || matches!(character, '_' | '$' | '~')
        || !character.is_ascii()
}

/// Byte ranges of the components of `path`, split at each top-level `::`.
fn components(path: &str) -> Vec<Range<usize>> {
    let path_levels = levels(path);
    let mut ranges = Vec::new();
    let mut start = 0;
    for (at, _) in path.match_indices(PATH_SEPARATOR) {
        if path_levels[at] == Some(0) {
            ranges.push(start..at);
            start = at + PATH_SEPARATOR.len();
        }
    }
    ranges.push(start..path.len());
    ranges
}

/// Stem spelling of a component without its parameter list, when the
/// component is parameterized. A closure is judged before a wrapper, since
/// MSVC's `<lambda_1>` also has a wrapper's shape.
fn erased(component: &str) -> Option<String> {
    if is_closure(component) {
        return Some(CLOSURE_STEM.to_owned());
    }
    erase_arguments(component, usize::from(is_wrapper(component)))
}

/// Whether `component` is a toolchain's closure or lambda spelling.
fn is_closure(component: &str) -> bool {
    component == "{{closure}}"
        || component.strip_prefix("$_").is_some_and(is_number)
        || component
            .strip_prefix("{closure#")
            .and_then(|rest| rest.strip_suffix('}'))
            .is_some_and(is_number)
        || component
            .strip_prefix("{lambda(")
            .and_then(|rest| rest.strip_suffix('}'))
            .and_then(|rest| rest.rsplit_once(")#"))
            .is_some_and(|(_, number)| is_number(number))
        || component
            .strip_prefix("'lambda")
            .and_then(|rest| rest.strip_suffix('\''))
            .is_some_and(|number| number.bytes().all(|byte| byte.is_ascii_digit()))
        || component
            .strip_prefix("<lambda_")
            .and_then(|rest| rest.strip_suffix('>'))
            .is_some_and(|id| !id.is_empty() && id.bytes().all(|byte| byte.is_ascii_alphanumeric()))
}

/// Whether `text` is a non-empty run of decimal digits.
fn is_number(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit())
}

/// Whether `component` is one `<…>` wrapper: its opening `<` closes at its
/// last byte.
fn is_wrapper(component: &str) -> bool {
    let component_levels = levels(component);
    component.starts_with('<')
        && component.ends_with('>')
        && (1..component.len()).find(|&at| component_levels[at] == Some(0))
            == Some(component.len() - 1)
}

/// `component` with each `<…>` opened at `depth` written `<>`, or `None`
/// when no argument list opens there.
fn erase_arguments(component: &str, depth: usize) -> Option<String> {
    let bytes = component.as_bytes();
    let component_levels = levels(component);
    let mut erased = String::with_capacity(component.len());
    let mut copied = 0;
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] == b'<' && component_levels[at] == Some(depth) {
            erased.push_str(&component[copied..at]);
            erased.push_str(ERASED_ARGUMENTS);
            at = (at + 1..bytes.len())
                .find(|&close| component_levels[close] == Some(depth))
                .map_or(bytes.len(), |close| close + 1);
            copied = at;
        } else {
            at += 1;
        }
    }
    if copied == 0 {
        return None;
    }
    erased.push_str(&component[copied..]);
    Some(erased)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::{NameStem, name_stem};

    /// Expected `(stem, instance, parameterized)`, or `None` for no stem.
    type Expected = Option<(&'static str, &'static str, bool)>;

    /// `(name, strip_platform_underscore, expected)`.
    const ROWS: &[(&str, bool, Expected)] = &[
        (
            "int probe<f::$_2>(char const*, f::$_2)",
            false,
            Some(("probe<>", "probe<f::$_2>", true)),
        ),
        (
            "std::__2::deque<std::__2::basic_string<char, std::__2::char_traits<char>, std::__2::allocator<char>>, std::__2::allocator<std::__2::basic_string<char, std::__2::char_traits<char>, std::__2::allocator<char>>>>::__add_back_capacity()",
            false,
            Some((
                "std::__2::deque<>",
                "std::__2::deque<std::__2::basic_string<char, std::__2::char_traits<char>, std::__2::allocator<char>>, std::__2::allocator<std::__2::basic_string<char, std::__2::char_traits<char>, std::__2::allocator<char>>>>",
                true,
            )),
        ),
        (
            "void std::__2::__split_buffer<A*, B>::emplace_back<C>(C&&)",
            false,
            Some((
                "std::__2::__split_buffer<>",
                "std::__2::__split_buffer<A*, B>",
                true,
            )),
        ),
        (
            "f()::$_0::operator()(char) const",
            false,
            Some(("f::{closure}", "f()::$_0", true)),
        ),
        (
            "ns::g(int)::{lambda(int)#1}::operator()(int) const",
            false,
            Some(("ns::g::{closure}", "ns::g(int)::{lambda(int)#1}", true)),
        ),
        (
            "foo::bar::{{closure}}",
            false,
            Some(("foo::bar::{closure}", "foo::bar::{{closure}}", true)),
        ),
        (
            "foo::bar::{closure#0}",
            false,
            Some(("foo::bar::{closure}", "foo::bar::{closure#0}", true)),
        ),
        (
            "alloc::vec::Vec<u8>::push",
            false,
            Some(("alloc::vec::Vec<>", "alloc::vec::Vec<u8>", true)),
        ),
        (
            "<alloc::vec::Vec<u8> as core::fmt::Debug>::fmt",
            false,
            Some((
                "<alloc::vec::Vec<> as core::fmt::Debug>",
                "<alloc::vec::Vec<u8> as core::fmt::Debug>",
                true,
            )),
        ),
        (
            "<my::A as core::fmt::Debug>::fmt",
            false,
            Some((
                "<my::A as core::fmt::Debug>::fmt",
                "<my::A as core::fmt::Debug>::fmt",
                false,
            )),
        ),
        (
            "<my::Foo>::new",
            false,
            Some(("<my::Foo>::new", "<my::Foo>::new", false)),
        ),
        (
            "core::slice::<impl [T]>::sort",
            false,
            Some((
                "core::slice::<impl [T]>::sort",
                "core::slice::<impl [T]>::sort",
                false,
            )),
        ),
        (
            "<hashbrown::raw::RawTable<(usize, usize)>>::reserve_rehash",
            false,
            Some((
                "<hashbrown::raw::RawTable<>>",
                "<hashbrown::raw::RawTable<(usize, usize)>>",
                true,
            )),
        ),
        (
            "std::logic_error::~logic_error()_67",
            false,
            Some((
                "std::logic_error::~logic_error",
                "std::logic_error::~logic_error()",
                false,
            )),
        ),
        (
            "foo::get() const_3",
            false,
            Some(("foo::get", "foo::get()", false)),
        ),
        (
            "foo() [clone .cold]_3",
            false,
            Some(("foo", "foo()", false)),
        ),
        ("foo_2()", false, Some(("foo_2", "foo_2()", false))),
        ("x_1", false, Some(("x_1", "x_1", false))),
        ("foo_2", false, Some(("foo_2", "foo_2", false))),
        (
            "bool operator<(a const&, a const&)",
            false,
            Some(("operator<", "operator<(a const&, a const&)", false)),
        ),
        (
            "ns::X::operator<<(int)",
            false,
            Some(("ns::X::operator<<", "ns::X::operator<<(int)", false)),
        ),
        (
            "ns::Y<int>::operator()(int)",
            false,
            Some(("ns::Y<>", "ns::Y<int>", true)),
        ),
        (
            "my::Foo::bar()$byn$fpcast-emu$3",
            false,
            Some(("my::Foo::bar", "my::Foo::bar()", false)),
        ),
        (
            "foo(int) [clone .constprop.0]",
            false,
            Some(("foo", "foo(int)", false)),
        ),
        (
            "(anonymous namespace)::h<int>()",
            false,
            Some(("h<>", "h<int>", true)),
        ),
        (
            "f::<lambda_1>::operator()(int)",
            false,
            Some(("f::{closure}", "f::<lambda_1>", true)),
        ),
        (
            "<lambda_1>::operator()(int)",
            false,
            Some(("{closure}", "<lambda_1>", true)),
        ),
        ("_strtof", true, Some(("strtof", "strtof", false))),
        ("_strtof", false, Some(("_strtof", "_strtof", false))),
        ("strtof", false, Some(("strtof", "strtof", false))),
        ("", false, None),
        ("()", false, None),
        ("f", false, Some(("f", "f", false))),
        ("foo(int)", false, Some(("foo", "foo(int)", false))),
        (
            "foo(unsigned int)",
            false,
            Some(("foo", "foo(unsigned int)", false)),
        ),
    ];

    #[test]
    fn every_row_projects_to_its_stem() {
        for &(name, strip, expected) in ROWS {
            let expected = expected.map(|(stem, instance, parameterized)| NameStem {
                stem: stem.to_owned(),
                instance: instance.to_owned(),
                parameterized,
            });
            assert_eq!(name_stem(name, strip), expected, "{name:?} strip={strip}");
        }
    }

    #[test]
    fn overloads_share_a_stem_and_keep_their_instances() {
        let narrow = name_stem("foo(int)", false).unwrap();
        let wide = name_stem("foo(unsigned int)", false).unwrap();
        assert_eq!(narrow.stem, wide.stem);
        assert_ne!(narrow.instance, wide.instance);
    }
}
