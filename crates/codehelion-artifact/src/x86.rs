//! Shared x86 instruction-shape normalization for native artifact backends.
//!
//! ELF, Mach-O, and PE/COFF all describe the same instruction stream once a
//! symbol's code bytes have been isolated. Keeping normalization here gives a
//! byte sequence one meaning across those container formats; backend-specific
//! implementations must not silently reuse a version label for different
//! encodings.

use iced_x86::{Decoder, DecoderOptions, Mnemonic, OpKind};
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

/// Remove conventional trailing alignment padding from an inferred x86 range.
///
/// The range is decoded forward and cut after its last instruction that is not
/// padding (`nop`, `int3`, or the `add [rax], al` a run of zero bytes decodes
/// to), so no byte of a real instruction is removed. A range whose
/// instruction boundaries cannot be established is returned whole, except for
/// a trailing run of padding bytes too short to be an instruction.
///
/// Explicit symbol sizes are authoritative. This applies only when a native
/// format supplied no size and the next symbol or section boundary was used.
#[must_use]
pub fn trim_inferred_padding(code: &[u8], architecture: Architecture) -> &[u8] {
    let bitness = match architecture {
        Architecture::I386 => 32,
        Architecture::X86_64 => 64,
        _ => return code,
    };
    let mut decoder = Decoder::with_ip(bitness, code, 0, DecoderOptions::NONE);
    let mut keep = 0;
    while decoder.can_decode() {
        let start = decoder.position();
        let instruction = decoder.decode();
        if instruction.is_invalid() {
            let undecoded = code.get(start..).unwrap_or_default();
            return if undecoded
                .iter()
                .all(|byte| matches!(byte, 0x00 | 0x90 | 0xcc))
            {
                code.get(..keep).unwrap_or(code)
            } else {
                code
            };
        }
        let end = decoder.position();
        let is_padding = matches!(instruction.mnemonic(), Mnemonic::Nop | Mnemonic::Int3)
            || code.get(start..end) == Some(&[0x00, 0x00]);
        if !is_padding {
            keep = end;
        }
    }
    code.get(..keep).unwrap_or(code)
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

    /// A function ending in `call rel32` or `ret imm16` whose operand bytes
    /// are zero and which is followed by padding.
    #[test]
    fn trailing_operand_bytes_are_not_taken_for_padding() {
        let call = [0xe8, 0x10, 0x01, 0x00, 0x00];
        let ret = [0xc2, 0x08, 0x00];
        for body in [&call[..], &ret[..]] {
            for padding in [
                &[0xcc, 0xcc, 0xcc][..],
                &[0x90][..],
                &[0x00, 0x00][..],
                &[][..],
            ] {
                let range = [body, padding].concat();
                let trimmed = trim_inferred_padding(&range, Architecture::X86_64);
                assert_eq!(trimmed, body, "padding {padding:x?}");
                assert!(normalize_x86(trimmed, Architecture::X86_64).is_some());
            }
        }
    }

    #[test]
    fn multi_byte_nops_and_an_odd_zero_tail_are_padding() {
        assert_eq!(
            trim_inferred_padding(
                &[0xc3, 0x0f, 0x1f, 0x44, 0x00, 0x00, 0x00],
                Architecture::X86_64
            ),
            &[0xc3]
        );
        assert_eq!(
            trim_inferred_padding(&[0xc3, 0x00, 0x00, 0x00], Architecture::X86_64),
            &[0xc3]
        );
    }

    #[test]
    fn a_range_that_does_not_decode_is_left_whole() {
        let truncated = [0xe8, 0x10, 0x01];
        assert_eq!(
            trim_inferred_padding(&truncated, Architecture::X86_64),
            &truncated
        );
    }

    #[test]
    fn normalized_duplicate_capability_is_explicit_for_each_architecture() {
        assert!(supports_normalized_duplicates(Architecture::X86_64));
        assert!(!supports_normalized_duplicates(Architecture::Aarch64));
    }
}
