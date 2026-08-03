//! Shared x86 instruction-shape normalization for native artifact backends.
//!
//! ELF, Mach-O, and PE/COFF all describe the same instruction stream once a
//! symbol's code bytes have been isolated. Keeping normalization here gives a
//! byte sequence one meaning across those container formats; backend-specific
//! implementations must not silently reuse a version label for different
//! encodings.

use iced_x86::{Decoder, DecoderOptions, OpKind};
use object::Architecture;

use crate::NormalizedInstructions;

/// Version of the x86 instruction-shape normalization representation.
pub const X86_NORMALIZATION_VERSION: &str = "x86-operand-shape-v1";

/// Whether this architecture has a supported normalized-instruction recipe.
#[must_use]
pub const fn supports_normalized_duplicates(architecture: Architecture) -> bool {
    matches!(architecture, Architecture::I386 | Architecture::X86_64)
}

/// Normalize an x86 instruction stream without retaining immediate values or
/// register choices.
///
/// `None` means either that the architecture is not x86 or the byte stream
/// does not decode into complete instructions. It is a fact about the bytes,
/// not a fallback to a lossy best-effort representation.
#[must_use]
pub fn normalize_x86(code: &[u8], architecture: Architecture) -> Option<NormalizedInstructions> {
    let bitness = match architecture {
        Architecture::I386 => 32,
        Architecture::X86_64 => 64,
        _ => return None,
    };
    let mut decoder = Decoder::with_ip(bitness, code, 0, DecoderOptions::NONE);
    let mut normalized = Vec::new();
    while decoder.can_decode() {
        let instruction = decoder.decode();
        if instruction.is_invalid() {
            return None;
        }
        normalized.extend((instruction.code() as u32).to_le_bytes());
        normalized.push(u8::try_from(instruction.op_count()).ok()?);
        for operand in 0..instruction.op_count() {
            let kind = instruction.op_kind(operand);
            normalized.push(kind as u8);
            if kind == OpKind::Memory {
                // Register choices and immediate displacements are not kept;
                // address width and scale preserve the operand's shape.
                normalized.push(instruction.memory_size() as u8);
                normalized.push(u8::try_from(instruction.memory_index_scale()).ok()?);
                normalized.push(u8::try_from(instruction.memory_displ_size()).ok()?);
            }
        }
    }
    Some(NormalizedInstructions {
        version: X86_NORMALIZATION_VERSION.to_owned(),
        bytes: normalized,
    })
}

/// Remove conventional trailing alignment bytes from an inferred x86 range.
///
/// Explicit symbol sizes are authoritative. This applies only when a native
/// format supplied no size and the next symbol or section boundary was used.
#[must_use]
pub fn trim_inferred_padding(code: &[u8], architecture: Architecture) -> &[u8] {
    if !matches!(architecture, Architecture::I386 | Architecture::X86_64) {
        return code;
    }
    let end = code
        .iter()
        .rposition(|byte| !matches!(byte, 0x00 | 0x90 | 0xcc))
        .map_or(0, |index| index + 1);
    &code[..end]
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn normalization_ignores_immediate_values_but_not_instruction_shape() {
        let first = normalize_x86(&[0xb8, 1, 0, 0, 0, 0xc3], Architecture::X86_64).unwrap();
        let second = normalize_x86(&[0xb8, 2, 0, 0, 0, 0xc3], Architecture::X86_64).unwrap();
        let call = normalize_x86(&[0xe8, 1, 0, 0, 0, 0xc3], Architecture::X86_64).unwrap();

        assert_eq!(first.version, X86_NORMALIZATION_VERSION);
        assert_eq!(first, second);
        assert_ne!(first, call);
        assert!(normalize_x86(&[0x0f], Architecture::X86_64).is_none());
        assert!(normalize_x86(&[0xc3], Architecture::Aarch64).is_none());
    }

    #[test]
    fn inferred_x86_ranges_drop_only_conventional_trailing_padding() {
        assert_eq!(
            trim_inferred_padding(&[0x90, 0xc3, 0x00, 0x90, 0xcc], Architecture::X86_64),
            &[0x90, 0xc3]
        );
        assert_eq!(
            trim_inferred_padding(&[0xc3, 0x00], Architecture::Aarch64),
            &[0xc3, 0x00]
        );
    }

    #[test]
    fn normalized_duplicate_capability_is_explicit_for_each_architecture() {
        assert!(supports_normalized_duplicates(Architecture::X86_64));
        assert!(!supports_normalized_duplicates(Architecture::Aarch64));
    }
}
