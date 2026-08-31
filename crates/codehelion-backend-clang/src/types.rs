//! Turning a type Clang resolved into the category two languages can share.
//!
//! The category is deliberately coarse, for the reason the protocol gives: two
//! languages do not agree on what a type *is*, and comparing spelled type names
//! compares vocabularies rather than programs. What survives translation is the
//! shape — whether a thing is a number, a sequence, a handle to something
//! elsewhere.
//!
//! # Why the category comes from the canonical type
//!
//! C and C++ let a program name the same type many ways. `Total`, `uint32_t`
//! and `unsigned int` can all be one type, and a helper that categorised what
//! was written would report three shapes for one. So the shape is read off the
//! canonical type, while the display name keeps what the code said — the first
//! is what two fragments are compared on, the second is what a person reads.
//!
//! # Why a handful of standard names are listed
//!
//! `std::string` is a class template, and reporting it as a record would be
//! true and useless: the point of the category is that a C++ `std::string` and
//! a Rust `String` are the same shape. The list is short and only applies to
//! types declared inside namespace `std`, so a project's own class called
//! `vector` is a record like any other class.

use clang::{Entity, EntityKind, Type, TypeKind};
use codehelion_helper::ir::TypeCategory;

/// The normalized category of `ty`.
pub(crate) fn category(ty: Type<'_>) -> TypeCategory {
    let canonical = ty.get_canonical_type();
    // A dependent type inside a template body is a type parameter until it is
    // substituted, and the declaration is the only place that says so: the kind
    // for both is `Unexposed`.
    if let Some(declaration) = canonical.get_declaration()
        && is_parameter(declaration)
    {
        return TypeCategory::Parameter;
    }
    match canonical.get_kind() {
        TypeKind::Void => TypeCategory::Nothing,
        TypeKind::Bool => TypeCategory::Boolean,
        TypeKind::CharS
        | TypeKind::CharU
        | TypeKind::SChar
        | TypeKind::UChar
        | TypeKind::WChar
        | TypeKind::Char16
        | TypeKind::Char32 => TypeCategory::Character,
        TypeKind::Short
        | TypeKind::UShort
        | TypeKind::Int
        | TypeKind::UInt
        | TypeKind::Long
        | TypeKind::ULong
        | TypeKind::LongLong
        | TypeKind::ULongLong
        | TypeKind::Int128
        | TypeKind::UInt128 => TypeCategory::Integer,
        TypeKind::Half
        | TypeKind::Float
        | TypeKind::Double
        | TypeKind::LongDouble
        | TypeKind::Float128
        | TypeKind::Complex => TypeCategory::Float,
        // A reference to a vector is a handle to a sequence, and what the code
        // holds is the handle — so pointers are decided before shapes.
        TypeKind::Pointer
        | TypeKind::BlockPointer
        | TypeKind::MemberPointer
        | TypeKind::LValueReference
        | TypeKind::RValueReference
        | TypeKind::ObjCObjectPointer
        | TypeKind::Nullptr => TypeCategory::Handle,
        TypeKind::ConstantArray
        | TypeKind::IncompleteArray
        | TypeKind::VariableArray
        | TypeKind::DependentSizedArray
        | TypeKind::Vector => TypeCategory::Sequence,
        TypeKind::FunctionPrototype | TypeKind::FunctionNoPrototype => TypeCategory::Callable,
        TypeKind::Enum => TypeCategory::Enumeration,
        TypeKind::Record => record(canonical),
        _ => TypeCategory::Unresolved,
    }
}

/// The shape of a class or struct.
fn record(canonical: Type<'_>) -> TypeCategory {
    canonical
        .get_declaration()
        .and_then(standard_shape)
        .unwrap_or(TypeCategory::Record)
}

/// The shape a standard-library type has in every language that has one.
///
/// `None` for anything declared outside `std`, however it is spelled: a class
/// called `vector` in somebody's own namespace is a record, and treating it as
/// a sequence because of its name would be reading the vocabulary again.
fn standard_shape(declaration: Entity<'_>) -> Option<TypeCategory> {
    if !in_standard_namespace(declaration) {
        return None;
    }
    Some(match declaration.get_name()?.as_str() {
        "basic_string" | "basic_string_view" | "string" | "string_view" | "filesystem" => {
            TypeCategory::Text
        }
        "vector" | "array" | "deque" | "list" | "forward_list" | "valarray" | "span"
        | "initializer_list" | "queue" | "stack" | "priority_queue" => TypeCategory::Sequence,
        "map" | "multimap" | "set" | "multiset" | "unordered_map" | "unordered_multimap"
        | "unordered_set" | "unordered_multiset" => TypeCategory::Mapping,
        "pair" | "tuple" => TypeCategory::Tuple,
        "unique_ptr" | "shared_ptr" | "weak_ptr" | "reference_wrapper" => TypeCategory::Handle,
        "function" => TypeCategory::Callable,
        // Named because the other side of a cross-language comparison has to
        // arrive at the same category. A function returning `std::optional<T>`
        // and one returning the optional of another language are the same
        // shape, and the construct layer already reads them as one; two
        // backends disagreeing here would lower the score of the clones that
        // agreement exists to find. A class template is what these are in C++,
        // so without this they would be records.
        "optional" | "expected" => TypeCategory::Enumeration,
        _ => return None,
    })
}

/// Whether `entity` is declared inside the standard library's namespace.
///
/// The walk allows for the inline versioning namespace an implementation puts
/// between `std` and everything in it: `std::__1::vector` is `std::vector`, and
/// a check that only looked at the immediate parent would miss every type in
/// the library that ships it.
pub(crate) fn in_standard_namespace(entity: Entity<'_>) -> bool {
    let mut parent = entity.get_semantic_parent();
    while let Some(current) = parent {
        if current.get_kind() == EntityKind::Namespace
            && current.get_name().as_deref() == Some("std")
        {
            return true;
        }
        parent = current.get_semantic_parent();
    }
    false
}

/// Whether a declaration is a type parameter rather than a type.
fn is_parameter(declaration: Entity<'_>) -> bool {
    matches!(
        declaration.get_kind(),
        EntityKind::TemplateTypeParameter | EntityKind::NonTypeTemplateParameter
    )
}

// The mapping is exercised against a real compiler rather than a mock one: it
// is a claim about what libclang reports for `std::vector<std::uint32_t>` and
// for a typedef to `uint64_t`, and only libclang can settle that. See
// `tests/analyzes_a_translation_unit.rs`.
