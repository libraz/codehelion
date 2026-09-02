//! Symbol-name canonicalization and template-spelling normalization.

pub(in crate::artifact) fn canonical_symbol_name(name: &str) -> Option<String> {
    let before_signature = name.trim().split('(').next()?.trim();
    let leaf = before_signature.rsplit("::").next()?.trim();
    let without_arguments = leaf.split('<').next()?.trim();
    (!without_arguments.is_empty()).then(|| without_arguments.to_owned())
}

pub(in crate::artifact) fn normalized_generic_instantiation_key(name: &str) -> Option<String> {
    let compact: String = name
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    (compact.contains('<') && compact.ends_with('>')).then(|| compact.replace("::<", "<"))
}

/// Normalize a C++ function-template display name for a source/artifact
/// comparison. Both inputs are compiler-produced: Clang's display name is
/// tagged by the helper, while the artifact backend has already demangled its
/// symbol. This deliberately rejects class templates and ordinary functions;
/// neither form has enough evidence to be a generic-origin correspondence.
pub(in crate::artifact) fn normalized_clang_template_display_name(name: &str) -> Option<String> {
    let tagged_source = name.starts_with("clang-display-v1:");
    let name = name
        .strip_prefix("clang-display-v1:")
        .unwrap_or(name)
        .trim();
    let open = name.find('(')?;
    let close = name.rfind(')')?;
    if close < open || (!name[..open].contains('<') && !tagged_source) {
        return None;
    }
    let before_parameters = name[..open].trim();
    let qualified = qualified_cpp_symbol_name(before_parameters);
    let mut normalized = String::with_capacity(name.len());
    let mut depth = 0_u32;
    for character in qualified.chars() {
        match character {
            '<' => depth = depth.saturating_add(1),
            '>' => depth = depth.saturating_sub(1),
            _ if depth == 0 => normalized.push(character),
            _ => {}
        }
    }
    normalized.push_str(name.get(open..=close)?);
    (!normalized.is_empty()).then_some(normalized)
}

/// Normalize a C++ class-template specialization that owns one demangled
/// member function. The source key is the fully qualified class display name;
/// the artifact key is the owner preceding the member name. The comparison is
/// exact after whitespace and integral-literal suffix normalization, so a
/// member of `Buffer<int, 8>` cannot be attributed to `Buffer<int, 4>`.
pub(in crate::artifact) fn normalized_clang_template_owner_name(name: &str) -> Option<String> {
    let tagged_source = name.starts_with("clang-display-v1:");
    let name = name
        .strip_prefix("clang-display-v1:")
        .unwrap_or(name)
        .trim();
    let owner = if tagged_source {
        (name.contains('<') && name.ends_with('>')).then_some(name)
    } else {
        let open = cpp_member_parameter_open(name)?;
        let before_parameters = name[..open].trim();
        let qualified = qualified_cpp_symbol_name(before_parameters);
        let (owner, _) = qualified.rsplit_once("::")?;
        (owner.contains('<') && owner.ends_with('>')).then_some(owner)
    }?;
    Some(normalize_cpp_template_owner(owner))
}

/// Locate the member-function parameter list outside template arguments.
///
/// A non-type template argument may itself contain a cast such as
/// `(unsigned long)4`, which is not the member-function parameter list.
pub(in crate::artifact) fn cpp_member_parameter_open(name: &str) -> Option<usize> {
    let mut template_depth = 0_u32;
    for (index, character) in name.char_indices() {
        match character {
            '<' => template_depth = template_depth.saturating_add(1),
            '>' => template_depth = template_depth.saturating_sub(1),
            '(' if template_depth == 0 => return Some(index),
            _ => {}
        }
    }
    None
}

/// Remove a C++ return type without mistaking whitespace inside `<...>` for
/// the separator before the qualified function name.
pub(in crate::artifact) fn qualified_cpp_symbol_name(spelling: &str) -> &str {
    let mut depth = 0_u32;
    let mut separator = None;
    for (index, character) in spelling.char_indices() {
        match character {
            '<' => depth = depth.saturating_add(1),
            '>' => depth = depth.saturating_sub(1),
            _ if depth == 0 && character.is_whitespace() => separator = Some(index),
            _ => {}
        }
    }
    separator.map_or(spelling, |index| spelling[index..].trim_start())
}

/// Remove formatting and the ABI's harmless decimal integer literal suffixes.
pub(in crate::artifact) fn normalize_cpp_template_owner(owner: &str) -> String {
    let compact: String = owner
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    // Demanglers may spell a non-type integral template argument with the
    // ABI's explicit type cast, e.g. `Buffer<int, (unsigned long)4>`.  This
    // function only receives the template owner (never parameter types), so
    // removing those integer casts leaves the specialization identity intact.
    let compact = [
        "(unsignedlonglong)",
        "(unsignedlong)",
        "(unsignedint)",
        "(longlong)",
        "(long)",
        "(int)",
    ]
    .into_iter()
    .fold(compact, |normalized, cast| normalized.replace(cast, ""));
    let characters: Vec<_> = compact.chars().collect();
    let mut normalized = String::with_capacity(compact.len());
    let mut index = 0;
    while index < characters.len() {
        if !characters[index].is_ascii_digit() {
            normalized.push(characters[index]);
            index += 1;
            continue;
        }
        let digits_start = index;
        while index < characters.len() && characters[index].is_ascii_digit() {
            index += 1;
        }
        normalized.extend(characters[digits_start..index].iter());
        let suffix_start = index;
        while index < characters.len() && matches!(characters[index], 'u' | 'U' | 'l' | 'L') {
            index += 1;
        }
        if suffix_start == index
            || index < characters.len() && !matches!(characters[index], ',' | '>' | ')')
        {
            normalized.extend(characters[suffix_start..index].iter());
        }
    }
    normalized
}

/// Restate a path so its components are separated by `/`.
///
/// The two sides of every comparison below are written by different programs:
/// debug information produced on Windows names a file with `\`, while the scan
/// records the path the way the project spells it. Whether a separator is a
/// separator is not a question either side's spelling gets to answer
/// differently.
pub(in crate::artifact) fn uniformly_separated(path: &str) -> String {
    path.replace('\\', "/")
}
