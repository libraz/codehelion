use std::collections::BTreeMap;

use clang::Type;
use codehelion_helper::ir::ResolvedType;

use crate::types::category;

use super::{Files, identity};

/// The types one analysis mentions, each recorded once.
///
/// # Why a type is recorded as the compiler resolved it
///
/// C and C++ let one type be written many ways. `Total`, `uint32_t` and
/// `unsigned int` can all name the same thing, and recording what was written
/// would file one type under three names — while recording the resolved form
/// files three spellings under one, which is what they are.
///
/// It also makes the answer say something the source text cannot. The same
/// header read by two translation units spells one type identically in both,
/// and a table of spellings would come back identical from two readings that
/// resolved it to different widths. What the compiler was asked for is what it
/// resolved; how it was written is in the file, where the syntactic side
/// already reads it.
#[derive(Default)]
pub(super) struct TypeTable {
    /// Position of each type, keyed by the resolved form.
    at: BTreeMap<String, u32>,
    resolved: Vec<ResolvedType>,
}

impl TypeTable {
    /// The index of `ty`, recording it if this is the first mention.
    pub(super) fn intern(&mut self, ty: Type<'_>, files: &mut Files<'_>) -> u32 {
        let canonical = ty.get_canonical_type();
        let display = canonical.get_display_name();
        if let Some(index) = self.at.get(&display) {
            return *index;
        }
        // Reserved before the arguments are interned: a template argument can
        // be the type being interned (`struct node { node* next; }`), and
        // recording the place first is what stops that from recursing.
        let index = u32::try_from(self.resolved.len()).unwrap_or(u32::MAX);
        self.at.insert(display.clone(), index);
        self.resolved.push(ResolvedType {
            display,
            category: category(ty),
            arguments: Vec::new(),
            definition: canonical
                .get_declaration()
                .map(|declaration| identity(declaration, files)),
        });
        let arguments = self.arguments(canonical, files);
        if let Some(recorded) = self.resolved.get_mut(index as usize) {
            recorded.arguments = arguments;
        }
        index
    }

    /// The types `ty` is built from: what it points at, what it holds, what it
    /// was instantiated with.
    fn arguments(&mut self, ty: Type<'_>, files: &mut Files<'_>) -> Vec<u32> {
        if let Some(pointee) = ty.get_pointee_type() {
            return vec![self.intern(pointee, files)];
        }
        if let Some(element) = ty.get_element_type() {
            return vec![self.intern(element, files)];
        }
        ty.get_template_argument_types()
            .unwrap_or_default()
            .into_iter()
            .flatten()
            .map(|argument| self.intern(argument, files))
            .collect()
    }

    pub(super) fn into_vec(self) -> Vec<ResolvedType> {
        self.resolved
    }
}
