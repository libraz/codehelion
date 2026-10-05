//! Owner labels for artifact symbols, derived from the demangled name alone.
//!
//! A symbol's key is the first element of its defining path: a Rust crate, a
//! C++ top-level namespace, or a fixed label for an unqualified name. The key
//! is toolchain code when it names the Rust sysroot or C++ `std`, a C17
//! Annex B function, a reserved identifier (C17 §7.1.3), or runtime support;
//! it is own only when the `[artifact] own` declaration lists it, and other
//! otherwise. Toolchain classification never depends on that declaration.
//!
//! A Rust `<Type as Trait>` impl is keyed by the orphan rule: when one side is
//! the standard library, the impl lives in the other side's crate.
//!
//! Brackets are counted for nesting depth, except an operator spelling written
//! directly after the `operator` keyword, which is opaque so that `operator<`
//! or `operator()` cannot unbalance the name.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::{ArtifactFormat, ArtifactIr};

mod toolchain;

/// Key of a symbol that has no name.
const UNNAMED_KEY: &str = "<unnamed>";
/// Key of an unqualified or function-local name outside the toolchain.
pub const GLOBAL_KEY: &str = "<global>";
/// Key of a Rust inherent impl on a non-path type such as `[u8]` or `str`.
const PRIMITIVE_IMPL_KEY: &str = "<primitive-impl>";
/// Key of the C++ standard library and its global allocation operators.
const STD_KEY: &str = "std";
/// Key of an unqualified C17 Annex B function.
const C_STD_KEY: &str = "c-std";
/// Key of an unqualified reserved identifier.
const RESERVED_KEY: &str = "reserved";
/// Key of an unqualified runtime support function.
const RUNTIME_KEY: &str = "runtime";

/// The `operator` keyword that introduces a C++ operator function name.
const OPERATOR: &str = "operator";
/// Operator spellings after `operator`, longest first so the first match is the longest.
const OPERATOR_SPELLINGS: &[&str] = &[
    "<<=", ">>=", "<=>", "->*", "<<", ">>", "<=", ">=", "->", "()", "[]", "==", "!=", "+=", "-=",
    "*=", "/=", "%=", "&=", "|=", "^=", "&&", "||", "++", "--", "<", ">", "+", "-", "*", "/", "%",
    "&", "|", "^", "~", "!", "=", ",",
];
/// Global allocation functions, which the C++ standard library defines.
const ALLOCATION_OPERATORS: &[&str] = &[
    "operator new",
    "operator delete",
    "operator new[]",
    "operator delete[]",
];
/// Program entry spellings: C17 §5.1.2.2.1 `main` and emscripten's renamings of it.
const MAIN_SPELLINGS: &[&str] = &["main", "__original_main", "__main_argc_argv"];
/// Prefix of compiler-generated static initializer functions.
const STATIC_INITIALIZER_PREFIX: &str = "_GLOBAL__";
/// Clone suffix that binaryen appends to a function name.
const BINARYEN_SUFFIX: &str = "$byn$";
/// Prefix of a compiler clone annotation such as ` [clone .cold]`.
const CLONE_ANNOTATION: &str = " [clone ";
/// Prefix of an Itanium ABI tag such as `[abi:cxx11]`.
const ABI_TAG: &str = "[abi:";
/// Trailing qualifiers that do not name the function, longest spelling first.
const TRAILING_QUALIFIERS: &[&str] = &[" const", " volatile", " &&", " &"];
/// Namespace spelling of a C++ unnamed namespace.
const ANONYMOUS_NAMESPACE: &str = "(anonymous namespace)::";
/// Pointer and reference forms stripped from the type side of a Rust impl.
const TYPE_PREFIXES: &[&str] = &["&mut ", "&", "*const ", "*mut ", "dyn "];

/// Who a symbol's code belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ownership {
    /// Code under a key the `[artifact] own` declaration lists.
    Own,
    /// Code a compiler toolchain ships: language and C standard libraries,
    /// reserved identifiers, and runtime support.
    Toolchain,
    /// Named code that is neither toolchain nor declared own.
    Other,
    /// Code without a name, which cannot be assigned an owner.
    Unnamed,
}

/// Which part of a toolchain a [`Ownership::Toolchain`] symbol comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolchainFamily {
    /// The Rust sysroot crates or the C++ standard library.
    LanguageStd,
    /// A C17 Annex B library function.
    CStd,
    /// An identifier C17 §7.1.3 reserves for the implementation.
    Reserved,
    /// Runtime support such as emscripten glue or the Rust panic runtime.
    Runtime,
}

/// The owner label of one symbol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymbolOwner {
    /// First element of the defining path, or a fixed label such as
    /// `<global>`, `<unnamed>`, `c-std`, `reserved`, or `runtime`.
    pub key: String,
    /// Class the key belongs to.
    pub ownership: Ownership,
    /// Toolchain part, present exactly when `ownership` is toolchain.
    pub family: Option<ToolchainFamily>,
}

/// Keys declared as own in `[artifact] own`, matched exactly.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OwnDeclaration(BTreeSet<String>);

impl OwnDeclaration {
    /// Whether no key is declared.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Whether `key` is declared, spelled exactly.
    #[must_use]
    pub fn contains(&self, key: &str) -> bool {
        self.0.contains(key)
    }
}

impl From<&[String]> for OwnDeclaration {
    fn from(keys: &[String]) -> Self {
        Self(keys.iter().cloned().collect())
    }
}

/// Owner label of a symbol named `name`.
///
/// `strip_platform_underscore` removes one leading `_` before judging, for a
/// format whose symbol table prefixes every C name with it. The display name
/// is never changed. Toolchain classification takes precedence over `own`.
#[must_use]
pub fn owner_of(
    name: Option<&str>,
    strip_platform_underscore: bool,
    own: &OwnDeclaration,
) -> SymbolOwner {
    let Some(name) = name else {
        return SymbolOwner {
            key: UNNAMED_KEY.to_owned(),
            ownership: Ownership::Unnamed,
            family: None,
        };
    };
    let name = judging_name(name, strip_platform_underscore);
    let normalized = normalize(name);
    let (key, family) = derive_key(function_name(head(&normalized)));
    let family = family.or_else(|| {
        if is_language_std_key(&key) {
            Some(ToolchainFamily::LanguageStd)
        } else if is_reserved_identifier(&key) {
            Some(ToolchainFamily::Reserved)
        } else {
            None
        }
    });
    let ownership = if family.is_some() {
        Ownership::Toolchain
    } else if own.contains(&key) {
        Ownership::Own
    } else {
        Ownership::Other
    };
    SymbolOwner {
        key,
        ownership,
        family,
    }
}

/// Whether judging `artifact`'s names removes one leading `_`, which only the
/// Mach-O symbol table adds to every C name.
#[must_use]
pub const fn strips_platform_underscore(artifact: &ArtifactIr) -> bool {
    matches!(artifact.format, ArtifactFormat::MachO)
}

/// Per-symbol platform-prefix lookup for one parsed artifact.
///
/// Ordinary artifacts have one format-wide answer. Archives retain one
/// interval per successfully parsed, non-thin Mach-O member, so symbols from
/// mixed-format archives are judged against the format that supplied them.
#[derive(Debug, Clone, Default)]
pub struct PlatformUnderscoreLookup {
    standalone_macho: bool,
    macho_member_ends: BTreeMap<u64, u64>,
}

impl PlatformUnderscoreLookup {
    /// Build a lookup from the parser-established format and archive members.
    #[must_use]
    pub fn new(artifact: &ArtifactIr) -> Self {
        if artifact.format != ArtifactFormat::Archive {
            return Self {
                standalone_macho: strips_platform_underscore(artifact),
                macho_member_ends: BTreeMap::new(),
            };
        }
        let mut macho_member_ends: BTreeMap<u64, u64> = BTreeMap::new();
        for member in &artifact.archive_members {
            let (Some(offset), Some(size)) = (member.offset, member.size) else {
                continue;
            };
            if member.thin
                || member.parse_error.is_some()
                || member.format != Some(ArtifactFormat::MachO)
            {
                continue;
            }
            let end = offset.saturating_add(size);
            macho_member_ends
                .entry(offset)
                .and_modify(|known| *known = (*known).max(end))
                .or_insert(end);
        }
        Self {
            standalone_macho: false,
            macho_member_ends,
        }
    }

    /// Whether the symbol at `symbol_offset` belongs to a Mach-O name space.
    #[must_use]
    pub fn for_offset(&self, symbol_offset: u64) -> bool {
        if self.standalone_macho {
            return true;
        }
        self.macho_member_ends
            .range(..=symbol_offset)
            .next_back()
            .is_some_and(|(_, end)| symbol_offset < *end)
    }
}

/// Name used for ownership and entry-spelling decisions.
///
/// A leading underscore is an ABI prefix only on an otherwise raw symbol
/// spelling. Demangled C++ and Rust names carry structure (`::`, argument
/// lists, angle brackets, or special-name braces), so removing their first
/// character would corrupt the defining path rather than remove an ABI
/// prefix.
pub(crate) fn judging_name(name: &str, strip_platform_underscore: bool) -> &str {
    if strip_platform_underscore
        && name.starts_with('_')
        && !name
            .bytes()
            .any(|byte| matches!(byte, b':' | b'(' | b')' | b'<' | b'>' | b'{' | b'}'))
    {
        name.strip_prefix('_').unwrap_or(name)
    } else {
        name
    }
}

/// Whether `name` is a program entry spelling: `main`, `__original_main`, or
/// `__main_argc_argv`.
#[must_use]
pub fn is_main_spelling(name: &str) -> bool {
    MAIN_SPELLINGS.contains(&name)
}

/// Whether `name` is a compiler-generated static initializer (`_GLOBAL__` prefix).
#[must_use]
pub fn is_static_initializer_spelling(name: &str) -> bool {
    name.starts_with(STATIC_INITIALIZER_PREFIX)
}

/// Judging form of a name: decorations removed, special-name braces opened,
/// and unnamed namespaces dropped.
fn normalize(name: &str) -> String {
    let mut current = strip_decorations(name);
    while let Some(inner) = special_name_target(&current) {
        current = strip_decorations(&inner);
    }
    drop_anonymous_namespaces(&current)
}

/// Remove a binaryen clone suffix, ABI tags, clone annotations, and trailing
/// cv- and ref-qualifiers.
fn strip_decorations(name: &str) -> String {
    let mut text = name
        .find(BINARYEN_SUFFIX)
        .map_or(name, |at| &name[..at])
        .to_owned();
    while let Some(start) = text.find(ABI_TAG) {
        let Some(length) = text[start..].find(']') else {
            break;
        };
        text.replace_range(start..=start + length, "");
    }
    loop {
        let trimmed = text.trim_end();
        let stripped = TRAILING_QUALIFIERS
            .iter()
            .find_map(|qualifier| trimmed.strip_suffix(qualifier))
            .or_else(|| {
                let start = trimmed.rfind(CLONE_ANNOTATION)?;
                (trimmed[start..].find(']')? == trimmed.len() - start - 1)
                    .then(|| &trimmed[..start])
            });
        match stripped {
            Some(rest) => text = rest.to_owned(),
            None => return trimmed.to_owned(),
        }
    }
}

/// For a name wholly wrapped in `{…}` (thunk, vtable, typeinfo), the name it
/// refers to: the last top-level argument of `name(args…)`, or the whole inner text.
fn special_name_target(name: &str) -> Option<String> {
    let inner = name.strip_prefix('{')?.strip_suffix('}')?;
    // The opening brace must close at the very end, not earlier.
    if levels(name)[1..name.len() - 1].contains(&Some(0)) {
        return None;
    }
    let inner_levels = levels(inner);
    let target = match trailing_group(inner, &inner_levels) {
        Some(open) if open > 0 => {
            let arguments = &inner[open + 1..inner.len() - 1];
            let argument_levels = levels(arguments);
            let last_comma = arguments
                .bytes()
                .enumerate()
                .filter(|&(at, byte)| byte == b',' && argument_levels[at] == Some(0))
                .map(|(at, _)| at)
                .next_back();
            last_comma.map_or(arguments, |at| &arguments[at + 1..])
        }
        _ => inner,
    };
    Some(target.trim().to_owned())
}

/// Remove every top-level `(anonymous namespace)::`.
fn drop_anonymous_namespaces(name: &str) -> String {
    let name_levels = levels(name);
    let mut result = String::with_capacity(name.len());
    let mut at = 0;
    while at < name.len() {
        if name_levels[at] == Some(0)
            && name.as_bytes()[at..].starts_with(ANONYMOUS_NAMESPACE.as_bytes())
        {
            at += ANONYMOUS_NAMESPACE.len();
            continue;
        }
        let Some(character) = name[at..].chars().next() else {
            break;
        };
        result.push(character);
        at += character.len_utf8();
    }
    result
}

/// The name without its trailing top-level argument list.
fn head(name: &str) -> &str {
    trailing_group(name, &levels(name)).map_or(name, |open| &name[..open])
}

/// The function name inside a head: from the token holding a top-level
/// `operator` keyword to the end, or else the last top-level token, which
/// drops a leading return type.
fn function_name(head: &str) -> &str {
    let head = head.trim_end();
    let head_levels = levels(head);
    let top_level_space =
        |at: usize| head.as_bytes()[at].is_ascii_whitespace() && head_levels[at] == Some(0);
    let end = (0..head.len())
        .find(|&at| head_levels[at] == Some(0) && is_operator_keyword(head, at))
        .unwrap_or(head.len());
    let start = (0..end)
        .rev()
        .find(|&at| top_level_space(at))
        .map_or(0, |at| at + 1);
    &head[start..]
}

/// Key of a function name, with the toolchain family when the name's shape
/// alone settles it.
fn derive_key(name: &str) -> (String, Option<ToolchainFamily>) {
    if name.starts_with('<') {
        return impl_key(name);
    }
    if let Some(first) = first_path_element(name) {
        // A function-local entity or one inside `main` belongs to no namespace.
        let key = if first.ends_with(')') || is_main_spelling(first) {
            GLOBAL_KEY
        } else {
            without_template_arguments(first)
        };
        return (key.to_owned(), None);
    }
    let (key, family) = if ALLOCATION_OPERATORS.contains(&name) {
        (STD_KEY, Some(ToolchainFamily::LanguageStd))
    } else if is_main_spelling(name) || is_static_initializer_spelling(name) {
        (GLOBAL_KEY, None)
    } else if toolchain::RUNTIME_NAMES.binary_search(&name).is_ok()
        || toolchain::RUNTIME_PREFIXES
            .iter()
            .any(|prefix| name.starts_with(prefix))
    {
        (RUNTIME_KEY, Some(ToolchainFamily::Runtime))
    } else if toolchain::C_STD_FUNCTIONS.binary_search(&name).is_ok() {
        (C_STD_KEY, Some(ToolchainFamily::CStd))
    } else if is_reserved_identifier(name) {
        (RESERVED_KEY, Some(ToolchainFamily::Reserved))
    } else {
        (GLOBAL_KEY, None)
    };
    (key.to_owned(), family)
}

/// Key of a Rust `<Type>` or `<Type as Trait>` impl item, chosen by the orphan
/// rule: a standard-library type implementing a foreign trait lives in the
/// trait's crate.
fn impl_key(name: &str) -> (String, Option<ToolchainFamily>) {
    let name_levels = levels(name);
    let close = (1..name.len())
        .find(|&at| name_levels[at] == Some(0))
        .unwrap_or(name.len());
    let inner = &name[1..close];
    let inner_levels = levels(inner);
    let split = inner
        .match_indices(" as ")
        .map(|(at, _)| at)
        .find(|&at| inner_levels[at] == Some(0));
    let (mut self_type, trait_path) = split.map_or((inner, None), |at| {
        (&inner[..at], Some(&inner[at + " as ".len()..]))
    });
    while let Some(rest) = TYPE_PREFIXES
        .iter()
        .find_map(|prefix| self_type.strip_prefix(prefix))
    {
        self_type = rest;
    }
    let type_key = self_type
        .chars()
        .next()
        .filter(|&first| first.is_alphanumeric() || first == '_')
        .and_then(|_| first_path_element(self_type));
    let trait_key = trait_path.map(|path| first_path_element(path).unwrap_or(path));
    let key = match (type_key, trait_key) {
        (Some(type_key), Some(trait_key))
            if is_sysroot_crate(type_key) && !is_sysroot_crate(trait_key) =>
        {
            trait_key
        }
        (Some(key), _) | (None, Some(key)) => key,
        (None, None) => {
            return (
                PRIMITIVE_IMPL_KEY.to_owned(),
                Some(ToolchainFamily::LanguageStd),
            );
        }
    };
    (key.to_owned(), None)
}

/// `element` without a trailing top-level `<…>`, so instantiations share one key.
fn without_template_arguments(element: &str) -> &str {
    let element_levels = levels(element);
    let Some(last) = element.len().checked_sub(1) else {
        return element;
    };
    if !element.ends_with('>') || element_levels[last] != Some(0) {
        return element;
    }
    (0..last)
        .rev()
        .find(|&at| element_levels[at] == Some(0))
        .filter(|&open| open > 0 && element.as_bytes()[open] == b'<')
        .map_or(element, |open| &element[..open])
}

/// Text before the first top-level `::`, when there is one.
fn first_path_element(path: &str) -> Option<&str> {
    let path_levels = levels(path);
    path.match_indices("::")
        .map(|(at, _)| at)
        .find(|&at| path_levels[at] == Some(0))
        .map(|at| &path[..at])
}

/// Byte offset of the `(` that opens a top-level argument list ending `name`.
fn trailing_group(name: &str, name_levels: &[Option<usize>]) -> Option<usize> {
    let last = name.len().checked_sub(1)?;
    if !name.ends_with(')') || name_levels[last] != Some(0) {
        return None;
    }
    let open = (0..last).rev().find(|&at| name_levels[at] == Some(0))?;
    (name.as_bytes()[open] == b'(').then_some(open)
}

/// Nesting depth of each byte, `None` inside an opaque operator spelling.
///
/// Scans bytes rather than `str` slices, since a byte offset may fall inside
/// a multibyte character.
///
/// An opening bracket sits at the depth outside it and a closing bracket at
/// the depth it returns to, so a matched pair shares one level. Depth never
/// goes below zero.
fn levels(name: &str) -> Vec<Option<usize>> {
    let bytes = name.as_bytes();
    let mut result = Vec::with_capacity(bytes.len());
    let mut depth = 0_usize;
    let mut opaque_until = 0;
    for (at, &byte) in bytes.iter().enumerate() {
        if at < opaque_until {
            result.push(None);
            continue;
        }
        if is_operator_keyword(name, at) {
            let spelling_start = at + OPERATOR.len();
            opaque_until = OPERATOR_SPELLINGS
                .iter()
                .find(|spelling| bytes[spelling_start..].starts_with(spelling.as_bytes()))
                .map_or(0, |spelling| spelling_start + spelling.len());
        }
        match byte {
            b'(' | b'[' | b'{' | b'<' => {
                result.push(Some(depth));
                depth += 1;
            }
            b')' | b']' | b'}' | b'>' => {
                depth = depth.saturating_sub(1);
                result.push(Some(depth));
            }
            _ => result.push(Some(depth)),
        }
    }
    result
}

/// Whether the `operator` keyword starts at `at`: preceded by the start, a
/// space, or `::`, and not followed by an identifier character.
fn is_operator_keyword(name: &str, at: usize) -> bool {
    let bytes = name.as_bytes();
    if !bytes[at..].starts_with(OPERATOR.as_bytes()) {
        return false;
    }
    let preceded =
        at == 0 || bytes[at - 1].is_ascii_whitespace() || (at >= 2 && &bytes[at - 2..at] == b"::");
    let followed = bytes
        .get(at + OPERATOR.len())
        .is_none_or(|&next| !(next.is_ascii_alphanumeric() || next == b'_' || next == b'$'));
    preceded && followed
}

/// Whether `key` names a Rust sysroot crate or the C++ standard library.
fn is_language_std_key(key: &str) -> bool {
    key == STD_KEY || is_sysroot_crate(key)
}

/// Whether `key` is a crate a Rust toolchain ships in its sysroot.
fn is_sysroot_crate(key: &str) -> bool {
    toolchain::RUST_SYSROOT_CRATES.binary_search(&key).is_ok()
}

/// Whether `name` is reserved by C17 §7.1.3: a leading `__`, or `_` followed
/// by an uppercase letter.
fn is_reserved_identifier(name: &str) -> bool {
    let bytes = name.as_bytes();
    bytes.first() == Some(&b'_')
        && bytes
            .get(1)
            .is_some_and(|&second| second == b'_' || second.is_ascii_uppercase())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::{OwnDeclaration, Ownership, SymbolOwner, ToolchainFamily, owner_of, toolchain};
    use crate::symbols::demangle;
    use crate::{ArtifactArchiveMember, ArtifactFingerprint, ArtifactFormat, ArtifactIr};

    /// Where a table row's name comes from.
    enum Input {
        /// A symbol without a name.
        Unnamed,
        /// A mangled name, run through the crate's demangler first.
        Mangled(&'static str),
        /// A spelling exactly as it would appear in the IR.
        Demangled(&'static str),
    }

    /// One row of the ownership table.
    struct Row {
        input: Input,
        strip: bool,
        own: &'static [&'static str],
        key: &'static str,
        ownership: Ownership,
        family: Option<ToolchainFamily>,
    }

    const fn row(
        input: Input,
        key: &'static str,
        ownership: Ownership,
        family: Option<ToolchainFamily>,
    ) -> Row {
        Row {
            input,
            strip: false,
            own: &[],
            key,
            ownership,
            family,
        }
    }

    const fn other(input: Input, key: &'static str) -> Row {
        row(input, key, Ownership::Other, None)
    }

    const fn language_std(input: Input, key: &'static str) -> Row {
        row(
            input,
            key,
            Ownership::Toolchain,
            Some(ToolchainFamily::LanguageStd),
        )
    }

    const fn toolchain(input: Input, key: &'static str, family: ToolchainFamily) -> Row {
        row(input, key, Ownership::Toolchain, Some(family))
    }

    #[allow(clippy::too_many_lines)]
    fn table() -> Vec<Row> {
        use Input::{Demangled, Mangled, Unnamed};
        use ToolchainFamily::{CStd, Reserved, Runtime};
        let mut rows = vec![
            row(Unnamed, "<unnamed>", Ownership::Unnamed, None),
            language_std(
                Mangled("_ZN4core3ptr13drop_in_place17h0123456789abcdefE"),
                "core",
            ),
            other(Demangled("my::parse::{closure#0}"), "my"),
            Row {
                own: &["my"],
                ..row(
                    Demangled("my::parse::{closure#0}"),
                    "my",
                    Ownership::Own,
                    None,
                )
            },
            other(
                Mangled("_RNvXCs4qZb0W2z9aP_2myNtB2_3FooNtNtCsaBcDeF_4core3fmt5Debug3fmt"),
                "my",
            ),
            other(Demangled("<&my::Foo as core::fmt::Debug>::fmt"), "my"),
            other(Demangled("<my::Foo>::new"), "my"),
            language_std(Demangled("<u8 as core::fmt::Display>::fmt"), "core"),
            other(Mangled("_RNvYINtNtC5alloc3vec3VechENtC2my5Trait1f"), "my"),
            other(Mangled("_RNvYDNtNtC4core3any3AnyEL_NtC2my5Trait1f"), "my"),
            language_std(
                Mangled("_RNvYINtNtC5alloc5boxed3BoxNtC2my3FooENtNtC4core3fmt5Debug3fmt"),
                "alloc",
            ),
            language_std(Mangled("_RNvMNtC4core5sliceSh4sort"), "<primitive-impl>"),
            language_std(Demangled("core::slice::<impl [T]>::sort"), "core"),
            language_std(
                Demangled("hashbrown::raw::RawTable<T>::reserve_rehash"),
                "hashbrown",
            ),
            language_std(
                Demangled("<hashbrown::raw::RawTable<(usize, usize)>>::reserve_rehash"),
                "hashbrown",
            ),
            language_std(
                Demangled("dlmalloc::dlmalloc::Dlmalloc<A>::malloc"),
                "dlmalloc",
            ),
            language_std(
                Mangled("_ZNSt3__26vectorIiNS_9allocatorIiEEE9push_backEOi"),
                "std",
            ),
            other(Mangled("_Z3fooIiEvi"), "<global>"),
            other(Demangled("void (*)(char) foo::bar<int>(int)"), "foo"),
            language_std(Mangled("_ZNSt3__13fooIiEEmv"), "std"),
            language_std(
                Mangled("_ZNSt3__1lsINS_11char_traitsIcEEEERNS_13basic_ostreamIcT_EES6_PKc"),
                "std",
            ),
            language_std(
                Mangled("_ZNSt3__1rsIcNS_11char_traitsIcEEEERNS_13basic_istreamIT_T0_EES7_RS4_"),
                "std",
            ),
            other(Mangled("_ZN2myltERKNS_1AES2_"), "my"),
            other(Mangled("_ZN3fooptEv"), "foo"),
            other(Mangled("_ZN3fooclEi"), "foo"),
            other(Mangled("_ZNK3foocvmEv"), "foo"),
            language_std(
                Mangled("_ZNKSt3__19basic_iosIcNS_11char_traitsIcEEEcvbEv"),
                "std",
            ),
            language_std(Mangled("_Znwm"), "std"),
            other(Mangled("_ZN12_GLOBAL__N_11fEv"), "<global>"),
            other(
                Demangled("void (anonymous namespace)::f<int>(int)"),
                "<global>",
            ),
            language_std(Demangled("std::(anonymous namespace)::g()"), "std"),
            language_std(
                Demangled(
                    "std::__2::basic_string<char, std::__2::char_traits<char>, \
                     std::__2::allocator<char> >::append(char const*) [clone .cold]",
                ),
                "std",
            ),
            language_std(
                Demangled(
                    "std::ios_base::failure[abi:cxx11]::failure(char const*, \
                     std::error_code const&)",
                ),
                "std",
            ),
            language_std(
                Mangled("_ZThn8_NSt3__114basic_iostreamIcNS_11char_traitsIcEEED1Ev"),
                "std",
            ),
            other(Mangled("_ZTVN2my6WidgetE"), "my"),
            other(Mangled("_ZZ4mainENK3$_0clEv"), "<global>"),
            other(Mangled("_ZZ5parsevENK3$_0clEv"), "<global>"),
            other(Mangled("_ZZN2my1fEvENKUlvE_clEv"), "my"),
            toolchain(
                Mangled("_ZN9__gnu_cxx27__verbose_terminate_handlerEv"),
                "__gnu_cxx",
                Reserved,
            ),
            toolchain(Demangled("strtof"), "c-std", CStd),
            toolchain(Demangled("__addtf3"), "reserved", Reserved),
            toolchain(Demangled("_Unwind_Resume"), "reserved", Reserved),
        ];
        for name in [
            "emscripten_memcpy_js",
            "_emscripten_stack_restore",
            "setThrew",
            "dlmalloc",
            "dynCall_vi",
            "iprintf",
            "vfiprintf",
            "rust_begin_unwind",
        ] {
            rows.push(toolchain(Demangled(name), "runtime", Runtime));
        }
        for name in [
            "main",
            "__original_main",
            "__main_argc_argv",
            "_GLOBAL__sub_I_a.cpp",
            "_GLOBAL__I_000100",
            "scanexp",
        ] {
            rows.push(other(Demangled(name), "<global>"));
        }
        rows.push(other(Demangled("my::f()$byn$fpcast-emu$3"), "my"));
        rows.push(other(Demangled("café::bär()"), "café"));
        rows.push(other(Demangled("bär"), "<global>"));
        rows.push(other(
            Demangled("crate_é::Foo::operator<(crate_é::Foo const&)"),
            "crate_é",
        ));
        rows.push(other(Demangled("ns<a, b<c>>::g()"), "ns"));
        rows.push(other(Demangled("Vec<int>::f()"), "Vec"));
        rows.push(Row {
            own: &["Vec"],
            ..row(Demangled("Vec<int>::f()"), "Vec", Ownership::Own, None)
        });
        rows.push(Row {
            strip: true,
            ..toolchain(Demangled("_strtof"), "c-std", CStd)
        });
        rows.push(other(Demangled("_strtof"), "<global>"));
        rows.push(Row {
            strip: true,
            ..toolchain(Demangled("__private::f()"), "__private", Reserved)
        });
        rows.push(Row {
            strip: true,
            ..toolchain(Demangled("__private()"), "reserved", Reserved)
        });
        rows.push(Row {
            strip: true,
            ..other(Demangled("_my::f()"), "_my")
        });

        rows.push(Row {
            own: &["<global>"],
            ..row(Demangled("parse"), "<global>", Ownership::Own, None)
        });
        rows.push(Row {
            own: &["std"],
            ..language_std(Demangled("std::foo()"), "std")
        });
        rows
    }

    #[test]
    fn binary_searched_name_lists_are_strictly_sorted() {
        for (list, names) in [
            ("RUST_SYSROOT_CRATES", toolchain::RUST_SYSROOT_CRATES),
            ("C_STD_FUNCTIONS", toolchain::C_STD_FUNCTIONS),
            ("RUNTIME_NAMES", toolchain::RUNTIME_NAMES),
        ] {
            for pair in names.windows(2) {
                assert!(
                    pair[0].as_bytes() < pair[1].as_bytes(),
                    "{list}: {:?} must sort before {:?}",
                    pair[0],
                    pair[1]
                );
            }
        }
    }

    #[test]
    fn owner_table_matches_every_rule() {
        let mut failures = Vec::new();
        for row in table() {
            let name = match row.input {
                Input::Unnamed => None,
                Input::Mangled(mangled) => Some(demangle(mangled)),
                Input::Demangled(spelling) => Some(spelling.to_owned()),
            };
            let declared: Vec<String> = row.own.iter().map(|&key| key.to_owned()).collect();
            let own = OwnDeclaration::from(declared.as_slice());
            let actual = owner_of(name.as_deref(), row.strip, &own);
            let expected = SymbolOwner {
                key: row.key.to_owned(),
                ownership: row.ownership,
                family: row.family,
            };
            if actual != expected {
                failures.push(format!("{name:?}: expected {expected:?}, got {actual:?}"));
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }

    #[test]
    fn platform_prefix_lookup_respects_many_member_boundaries() {
        let mut artifact = ArtifactIr::empty(ArtifactFormat::Archive, b"archive");
        for index in 0..128_u64 {
            let offset = 1_000 + index * 20;
            let failed = index == 2;
            let thin = index == 4;
            artifact.archive_members.push(ArtifactArchiveMember {
                name: format!("member{index}.o"),
                fingerprint: ArtifactFingerprint::from_content("member", &index.to_le_bytes()),
                offset: Some(offset),
                size: Some(10),
                format: Some(if index % 2 == 0 {
                    ArtifactFormat::MachO
                } else {
                    ArtifactFormat::PeCoff
                }),
                thin,
                parse_error: failed.then(|| "member parse failed".to_owned()),
            });
        }
        let lookup = super::PlatformUnderscoreLookup::new(&artifact);

        assert!(lookup.for_offset(1_000));
        assert!(lookup.for_offset(1_009));
        assert!(!lookup.for_offset(1_010));
        assert!(!lookup.for_offset(1_020));
        assert!(!lookup.for_offset(1_040));
        assert!(!lookup.for_offset(1_080));
        assert!(lookup.for_offset(1_120));
        assert!(lookup.for_offset(3_520));
        assert!(lookup.for_offset(3_529));
        assert!(!lookup.for_offset(3_530));
        assert!(!lookup.for_offset(3_549));
    }
}
