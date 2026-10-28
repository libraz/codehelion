//! Display shortening of long symbol names.
//!
//! A template argument list that opens inside another bracket is written `…`,
//! which keeps the outermost qualification and the argument count readable
//! while dropping the nested instantiation text. The shortened form is for
//! display only; identity and grouping always use the full name.

use std::borrow::Cow;

use crate::ownership::levels;

/// What replaces the contents of an elided `<…>`.
const ELLIPSIS: &str = "…";

/// `name` with the contents of every `<…>` that opens inside another bracket
/// written `…`.
///
/// A `<` opens at depth one or more when a `(`, `[`, `{` or `<` encloses it. The
/// contents run to the `>` that returns to the depth the `<` opened at, or to
/// the end of the name when none does. Brackets at depth zero are kept whole,
/// and an operator spelling such as `operator<` is never read as a bracket.
/// The name is borrowed unchanged when nothing is elided.
///
/// # Examples
///
/// ```
/// use codehelion_artifact::short_name::short_name;
///
/// assert_eq!(
///     short_name("std::deque<std::basic_string<char>>::push_back(int&&)"),
///     "std::deque<std::basic_string<…>>::push_back(int&&)",
/// );
/// assert_eq!(short_name("strlen"), "strlen");
/// ```
#[must_use]
pub fn short_name(name: &str) -> Cow<'_, str> {
    let bytes = name.as_bytes();
    let name_levels = levels(name);
    let mut shortened = String::new();
    let mut copied = 0;
    let mut at = 0;
    while at < bytes.len() {
        let nested = bytes[at] == b'<' && name_levels[at].is_some_and(|depth| depth >= 1);
        if !nested {
            at += 1;
            continue;
        }
        shortened.push_str(&name[copied..=at]);
        shortened.push_str(ELLIPSIS);
        shortened.push('>');
        let close = (at + 1..bytes.len())
            .find(|&close| bytes[close] == b'>' && name_levels[close] == name_levels[at]);
        at = close.map_or(bytes.len(), |close| close + 1);
        copied = at;
    }
    if copied == 0 {
        return Cow::Borrowed(name);
    }
    shortened.push_str(&name[copied..]);
    Cow::Owned(shortened)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use std::borrow::Cow;
    use std::collections::HashMap;

    use super::short_name;

    /// `(input, expected)`; an expected value equal to the input must borrow.
    const ROWS: &[(&str, &str)] = &[
        ("", ""),
        ("strlen", "strlen"),
        (
            "std::__2::deque<int>::push_back(int&&)",
            "std::__2::deque<int>::push_back(int&&)",
        ),
        (
            "deque<basic_string<char>>::f()",
            "deque<basic_string<…>>::f()",
        ),
        ("f(std::vector<int>&)", "f(std::vector<…>&)"),
        ("a<b<c", "a<b<…>"),
        (
            "bool operator<(A<int> const&, B)",
            "bool operator<(A<…> const&, B)",
        ),
        (
            "ns::X::operator<<(A<int> const&)",
            "ns::X::operator<<(A<…> const&)",
        ),
        ("ns::X::operator->(A<int>)", "ns::X::operator->(A<…>)"),
        (
            "auto ns::X::operator<=>(A<int>)",
            "auto ns::X::operator<=>(A<…>)",
        ),
        (
            "core::ptr::drop_in_place<alloc::boxed::Box<dyn core::ops::function::FnOnce() -> i32>>",
            "core::ptr::drop_in_place<alloc::boxed::Box<…>>",
        ),
        (
            "<alloc::vec::Vec<u8> as core::fmt::Debug>::fmt",
            "<alloc::vec::Vec<…> as core::fmt::Debug>::fmt",
        ),
        ("probe<f::$_0>", "probe<f::$_0>"),
        (
            "ns::g(int)::{lambda(int)#1}::operator()(int) const",
            "ns::g(int)::{lambda(int)#1}::operator()(int) const",
        ),
        (
            "(anonymous namespace)::f<std::pair<int, int>>()",
            "(anonymous namespace)::f<std::pair<…>>()",
        ),
        ("a<b<c>>", "a<b<…>>"),
        ("ns::名前<型<x>>", "ns::名前<型<…>>"),
    ];

    #[test]
    fn every_boundary_row_shortens_as_written() {
        for &(input, expected) in ROWS {
            let actual = short_name(input);
            assert_eq!(actual, expected, "{input:?}");
            assert_eq!(
                matches!(actual, Cow::Borrowed(_)),
                input == expected,
                "{input:?} must borrow exactly when nothing is elided"
            );
        }
    }

    /// Every name of a real C++ WebAssembly module, in file order.
    const SAMPLE: &[&str] = &[
        "__wasm_call_ctors",
        "f",
        "int probe<f::$_0>(char const*, f::$_0)",
        "int probe<f::$_1>(char const*, f::$_1)",
        "int probe<f::$_2>(char const*, f::$_2)",
        "std::__2::deque<std::__2::basic_string<char, std::__2::char_traits<char>, std::__2::allocator<char>>, std::__2::allocator<std::__2::basic_string<char, std::__2::char_traits<char>, std::__2::allocator<char>>>>::__add_back_capacity()",
        "std::__2::basic_string<char, std::__2::char_traits<char>, std::__2::allocator<char>>::__throw_length_error[abi:nqe220108]()",
        "std::__2::__throw_length_error[abi:nqe220108](char const*)",
        "std::length_error::length_error[abi:nqe220108](char const*)",
        "std::__throw_bad_array_new_length[abi:nqe220108]()",
        "void std::__2::__split_buffer<std::__2::basic_string<char, std::__2::char_traits<char>, std::__2::allocator<char>>*, std::__2::allocator<std::__2::basic_string<char, std::__2::char_traits<char>, std::__2::allocator<char>>*>, std::__2::__split_buffer_pointer_layout>::emplace_back<std::__2::basic_string<char, std::__2::char_traits<char>, std::__2::allocator<char>>*&>(std::__2::basic_string<char, std::__2::char_traits<char>, std::__2::allocator<char>>*&)",
        "void std::__2::__split_buffer<std::__2::basic_string<char, std::__2::char_traits<char>, std::__2::allocator<char>>*, std::__2::allocator<std::__2::basic_string<char, std::__2::char_traits<char>, std::__2::allocator<char>>*>, std::__2::__split_buffer_pointer_layout>::emplace_back<std::__2::basic_string<char, std::__2::char_traits<char>, std::__2::allocator<char>>*>(std::__2::basic_string<char, std::__2::char_traits<char>, std::__2::allocator<char>>*&&)",
        "void std::__2::__split_buffer<std::__2::basic_string<char, std::__2::char_traits<char>, std::__2::allocator<char>>*, std::__2::allocator<std::__2::basic_string<char, std::__2::char_traits<char>, std::__2::allocator<char>>*>, std::__2::__split_buffer_pointer_layout>::emplace_front<std::__2::basic_string<char, std::__2::char_traits<char>, std::__2::allocator<char>>*&>(std::__2::basic_string<char, std::__2::char_traits<char>, std::__2::allocator<char>>*&)",
        "void std::__2::__split_buffer<std::__2::basic_string<char, std::__2::char_traits<char>, std::__2::allocator<char>>*, std::__2::allocator<std::__2::basic_string<char, std::__2::char_traits<char>, std::__2::allocator<char>>*>, std::__2::__split_buffer_pointer_layout>::emplace_front<std::__2::basic_string<char, std::__2::char_traits<char>, std::__2::allocator<char>>*>(std::__2::basic_string<char, std::__2::char_traits<char>, std::__2::allocator<char>>*&&)",
        "_initialize",
        "_abort_js",
        "emscripten_resize_heap",
        "__cxa_throw",
        "__errno_location",
        "abort",
        "emscripten_get_heap_size",
        "strcmp",
        "strlen",
        "emscripten_builtin_malloc",
        "prepend_alloc",
        "emscripten_builtin_free",
        "sbrk",
        "operator new(unsigned long)",
        "operator_new_impl(unsigned long)",
        "operator delete(void*)",
        "operator delete(void*, unsigned long)",
        "std::__throw_bad_alloc()",
        "std::__2::__libcpp_refstring::__libcpp_refstring(char const*)",
        "std::logic_error::logic_error(char const*)",
        "std::__2::basic_string<char, std::__2::char_traits<char>, std::__2::allocator<char>>::__allocate_long_buffer[abi:nqn220108](std::__2::allocator<char>&, unsigned long)",
        "std::__2::basic_string<char, std::__2::char_traits<char>, std::__2::allocator<char>>::__throw_length_error[abi:nqn220108]()",
        "std::__2::basic_string<char, std::__2::char_traits<char>, std::__2::allocator<char>>::__reset_internal_buffer[abi:nqn220108](std::__2::basic_string<char, std::__2::char_traits<char>, std::__2::allocator<char>>::__rep)",
        "std::__2::basic_string<char, std::__2::char_traits<char>, std::__2::allocator<char>>::append(char const*)",
        "std::__2::basic_string<char, std::__2::char_traits<char>, std::__2::allocator<char>>::append(char const*, unsigned long)",
        "std::__2::basic_string<char, std::__2::char_traits<char>, std::__2::allocator<char>>::__grow_by_and_replace(unsigned long, unsigned long, unsigned long, unsigned long, unsigned long, unsigned long, char const*)",
        "std::__2::basic_string<char, std::__2::char_traits<char>, std::__2::allocator<char>>::__get_amortized_growth_capacity[abi:nqn220108](unsigned long)",
        "__abort_message",
        "std::get_new_handler()",
        "__cxa_allocate_exception",
        "__cxxabiv1::__shim_type_info::~__shim_type_info()",
        "__cxxabiv1::__shim_type_info::noop1() const",
        "__cxxabiv1::__shim_type_info::noop2() const",
        "__cxxabiv1::__class_type_info::~__class_type_info()",
        "__cxxabiv1::__si_class_type_info::~__si_class_type_info()",
        "is_equal(std::type_info const*, std::type_info const*, bool)",
        "__cxxabiv1::__class_type_info::can_catch(__cxxabiv1::__shim_type_info const*, void*&) const",
        "__dynamic_cast",
        "__cxxabiv1::__class_type_info::process_found_base_class(__cxxabiv1::__dynamic_cast_info*, void*, int) const",
        "__cxxabiv1::__class_type_info::has_unambiguous_public_base(__cxxabiv1::__dynamic_cast_info*, void*, int) const",
        "__cxxabiv1::__si_class_type_info::has_unambiguous_public_base(__cxxabiv1::__dynamic_cast_info*, void*, int) const",
        "__cxxabiv1::__class_type_info::process_static_type_above_dst(__cxxabiv1::__dynamic_cast_info*, void const*, void const*, int) const",
        "__cxxabiv1::__si_class_type_info::search_below_dst(__cxxabiv1::__dynamic_cast_info*, void const*, int, bool) const",
        "__cxxabiv1::__class_type_info::search_below_dst(__cxxabiv1::__dynamic_cast_info*, void const*, int, bool) const",
        "__cxxabiv1::__si_class_type_info::search_above_dst(__cxxabiv1::__dynamic_cast_info*, void const*, void const*, int, bool) const",
        "__cxxabiv1::__class_type_info::search_above_dst(__cxxabiv1::__dynamic_cast_info*, void const*, void const*, int, bool) const",
        "std::exception::~exception()",
        "std::bad_array_new_length::bad_array_new_length()",
        "std::bad_array_new_length::~bad_array_new_length()",
        "std::bad_array_new_length::what() const",
        "std::logic_error::~logic_error()",
        "std::__2::__libcpp_refstring::~__libcpp_refstring()",
        "std::logic_error::~logic_error()",
        "std::logic_error::what() const",
        "std::length_error::~length_error()",
        "std::type_info::~type_info()",
        "_emscripten_stack_restore",
        "emscripten_stack_get_current",
        "setThrew",
    ];

    /// Names that occur more than once, counted by the number of surplus names.
    fn collisions<'a>(names: impl Iterator<Item = &'a str>) -> usize {
        let mut seen: HashMap<&str, usize> = HashMap::new();
        let mut total = 0;
        for name in names {
            let count = seen.entry(name).or_default();
            total += usize::from(*count > 0);
            *count += 1;
        }
        total
    }

    #[test]
    fn short_name_on_sample_names() {
        assert_eq!(SAMPLE.len(), 73);
        let shortened: Vec<Cow<'_, str>> = SAMPLE.iter().map(|name| short_name(name)).collect();
        let longest = shortened.iter().map(|name| name.chars().count()).max();
        assert_eq!(longest, Some(204));
        assert_eq!(
            collisions(shortened.iter().map(AsRef::as_ref)),
            collisions(SAMPLE.iter().copied()),
        );
    }
}
