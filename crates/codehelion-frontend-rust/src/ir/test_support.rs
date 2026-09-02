//! Helpers shared by the inline test modules of this frontend.

use codehelion_core::ir::{IrNode, Shape, StructuralFrontend, SyntaxIrFile};

use super::RustStructuralFrontend;

pub(super) fn parse(source: &str) -> SyntaxIrFile {
    RustStructuralFrontend.parse(source)
}

pub(super) fn shapes_of(children: &[IrNode]) -> Vec<Shape> {
    children.iter().map(|child| child.shape.clone()).collect()
}
