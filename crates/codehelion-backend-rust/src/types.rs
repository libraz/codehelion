//! Turning a resolved Rust type into the category two languages can share.
//!
//! The category is deliberately coarse, for the reason the protocol gives: two
//! languages do not agree on what a type *is*, and comparing spelled type names
//! compares vocabularies rather than programs. What survives translation is the
//! shape — whether a thing is a number, a sequence, a handle to something
//! elsewhere.
//!
//! Which is also why a handful of standard-library types are named here.
//! `String` is a struct, and reporting it as a record would be true and
//! useless: the point of the category is that a Rust `String` and a C++
//! `std::string` are the same shape. The list is short, and restricted to types
//! defined in the standard library, so that a project's own struct called
//! `Vec` is a record like any other struct.
//!
//! An unresolved type maps to [`TypeCategory::Unresolved`] rather than to a
//! guess. The compiler saying it does not know is information, and the engine
//! treats it as such: unresolved types carry no evidence at all, so a guess
//! here would not merely be wrong, it would be counted.

use codehelion_helper::ir::TypeCategory;
use ra_ap_hir::{Adt, HasCrate, Type};
use ra_ap_ide_db::RootDatabase;

/// The crates whose type names are the shared vocabulary rather than one
/// project's.
const STANDARD_LIBRARY: [&str; 3] = ["std", "alloc", "core"];

/// The normalized category of `ty`.
pub(crate) fn category(ty: &Type<'_>, db: &RootDatabase) -> TypeCategory {
    if ty.is_unknown() {
        return TypeCategory::Unresolved;
    }
    if ty.is_unit() {
        return TypeCategory::Nothing;
    }
    if ty.is_bool() {
        return TypeCategory::Boolean;
    }
    if ty.is_char() {
        return TypeCategory::Character;
    }
    if ty.is_str() {
        return TypeCategory::Text;
    }
    if ty.is_int_or_uint() {
        return TypeCategory::Integer;
    }
    if ty.is_float() {
        return TypeCategory::Float;
    }
    // Before the shapes below: a `&Vec<T>` is a handle to a sequence, and what
    // the code holds is the handle.
    if ty.is_reference() || ty.is_raw_ptr() {
        return TypeCategory::Handle;
    }
    if ty.is_slice() || ty.is_array() {
        return TypeCategory::Sequence;
    }
    if ty.is_tuple() {
        return TypeCategory::Tuple;
    }
    if ty.is_closure() || ty.is_fn() {
        return TypeCategory::Callable;
    }
    if ty.as_type_param(db).is_some() {
        return TypeCategory::Parameter;
    }
    if ty.as_dyn_trait().is_some() || ty.as_impl_traits(db).is_some() {
        return TypeCategory::Interface;
    }
    ty.as_adt()
        .map_or(TypeCategory::Unresolved, |adt| adt_category(adt, db))
}

fn adt_category(adt: Adt, db: &RootDatabase) -> TypeCategory {
    if let Some(shared) = standard_shape(adt, db) {
        return shared;
    }
    match adt {
        Adt::Struct(_) | Adt::Union(_) => TypeCategory::Record,
        Adt::Enum(_) => TypeCategory::Enumeration,
    }
}

/// The shape a standard-library type has in every language that has one.
///
/// `None` for anything the project defined itself, however it is spelled: a
/// struct called `Vec` in somebody's crate is a record, and treating it as a
/// sequence because of its name would be reading the vocabulary again.
fn standard_shape(adt: Adt, db: &RootDatabase) -> Option<TypeCategory> {
    let krate = adt.krate(db).display_name(db)?.to_string();
    if !STANDARD_LIBRARY.contains(&krate.as_str()) {
        return None;
    }
    let name = adt.name(db);
    Some(match name.as_str() {
        "String" | "OsString" | "PathBuf" | "Path" | "OsStr" | "CString" | "CStr" => {
            TypeCategory::Text
        }
        "Vec" | "VecDeque" | "BinaryHeap" | "LinkedList" => TypeCategory::Sequence,
        "HashMap" | "BTreeMap" | "HashSet" | "BTreeSet" => TypeCategory::Mapping,
        "Box" | "Rc" | "Arc" | "RefCell" | "Cell" | "Mutex" | "RwLock" => TypeCategory::Handle,
        _ => return None,
    })
}

// The mapping is exercised against a real compiler rather than a mock one: it
// is a claim about what rust-analyzer reports for `String` and `Vec<String>`,
// and only rust-analyzer can settle that. See `tests/analyzes_a_workspace.rs`.
