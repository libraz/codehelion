//! A derive macro that writes a method nobody typed.
//!
//! Compiling the crate next door means running this program. A helper that
//! declines to run it sees `#[derive(Labelled)]` and an impl that does not
//! exist in any file; a helper that runs it sees the impl but has executed code
//! from the project it was asked to read. Which of the two happened has to be
//! visible in the result, which is what this fixture is for.

use proc_macro::TokenStream;

/// Derives a `label` method returning the type's own name.
#[proc_macro_derive(Labelled)]
pub fn labelled(input: TokenStream) -> TokenStream {
    let name = type_name(&input.to_string()).unwrap_or_else(|| "Unknown".to_string());
    format!(
        "impl {name} {{ \
             /// The type's name, written by the derive rather than by a person. \
             pub fn label(&self) -> &'static str {{ \"{name}\" }} \
         }}"
    )
    .parse()
    .unwrap_or_default()
}

/// The identifier that follows `struct` or `enum` in the derived item.
fn type_name(item: &str) -> Option<String> {
    let mut tokens = item.split_whitespace();
    while let Some(token) = tokens.next() {
        if token == "struct" || token == "enum" {
            let name: String = tokens
                .next()?
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            return (!name.is_empty()).then_some(name);
        }
    }
    None
}
