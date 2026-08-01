//! Shared symbol-name presentation helpers for artifact backends.

/// Render a Rust or C++ mangled symbol when its ABI is known, preserving an
/// unknown spelling exactly rather than inventing a name.
#[must_use]
pub fn demangle(name: &str) -> String {
    if let Ok(symbol) = rustc_demangle::try_demangle(name) {
        return format!("{symbol:#}");
    }
    cpp_demangle::Symbol::new(name.as_bytes())
        .ok()
        .and_then(|symbol| symbol.demangle().ok())
        .unwrap_or_else(|| name.to_owned())
}

#[cfg(test)]
mod tests {
    use super::demangle;

    #[test]
    fn known_abis_demangle_and_unknown_names_stay_exact() {
        assert_eq!(demangle("_Z3foov"), "foo()");
        assert!(demangle("_RNvCs4qZb0W2z9aP_3foo3bar").contains("foo"));
        assert_eq!(demangle("ordinary_symbol"), "ordinary_symbol");
    }
}
