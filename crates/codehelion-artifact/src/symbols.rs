//! Shared symbol-name presentation helpers for artifact backends.

/// Render a Rust or C++ mangled symbol when its ABI is known, preserving an
/// unknown spelling exactly rather than inventing a name.
#[must_use]
pub fn demangle(name: &str) -> String {
    // A `$byn$` clone suffix is not part of either mangling grammar; keep it verbatim.
    let (base, suffix) = name
        .find("$byn$")
        .map_or((name, ""), |at| name.split_at(at));
    if let Ok(symbol) = rustc_demangle::try_demangle(base) {
        return format!("{symbol:#}{suffix}");
    }
    // cpp_demangle also parses bare type codes ("y", "Ss"), so gate on the Itanium prefix.
    if (base.starts_with("_Z") || base.starts_with("__Z") || base.starts_with("___Z"))
        && let Some(demangled) = cpp_demangle::Symbol::new(base.as_bytes())
            .ok()
            .and_then(|symbol| symbol.demangle().ok())
    {
        return format!("{demangled}{suffix}");
    }
    name.to_owned()
}

#[cfg(test)]
mod tests {
    use super::demangle;

    #[test]
    fn known_abis_demangle_and_unknown_names_stay_exact() {
        assert_eq!(demangle("_Z3foov"), "foo()");
        assert_eq!(demangle("__Z3foov"), "foo()");
        assert!(demangle("_RNvCs4qZb0W2z9aP_3foo3bar").contains("foo"));
        assert_eq!(demangle("ordinary_symbol"), "ordinary_symbol");
    }

    #[test]
    fn bare_type_codes_stay_exact() {
        for name in ["y", "i", "Ss", "St", "_GLOBAL__I_a"] {
            assert_eq!(demangle(name), name);
        }
    }

    #[test]
    fn byn_suffix_is_kept_after_demangling() {
        assert_eq!(
            demangle("_ZN2my3Foo3barEv$byn$fpcast-emu$3"),
            "my::Foo::bar()$byn$fpcast-emu$3"
        );
        assert_eq!(demangle("plain$byn$x"), "plain$byn$x");
    }

    #[test]
    fn rust_legacy_and_v0_names_demangle() {
        assert_eq!(demangle("_ZN3foo3barE"), "foo::bar");
        assert_eq!(demangle("_ZN3foo3bar17h0123456789abcdefE"), "foo::bar");
        assert_eq!(demangle("_RNvCs4qZb0W2z9aP_3foo3bar"), "foo::bar");
    }
}
