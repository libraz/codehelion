#pragma once

#include <cstdint>

// One body, written once, stamped out per field.
//
// Everything the invocations below produce is identical apart from the names
// substituted into it, and none of it can be deleted: there is one place it was
// written and three places it reads. A detector reading only the characters in
// this file sees three near-identical pairs of functions and reports repetition
// nobody can act on — which is why what is asked of the compiler is where each
// declaration was written, not only where it sits.
#define ACCESSOR(type, name)                    \
  type name##_;                                 \
  type name() const { return name##_; }         \
  void set_##name(type value) { name##_ = value; }

namespace settings {

/// The size of one frame, in whatever the accessors were stamped out over.
struct Frame {
  ACCESSOR(std::uint32_t, width)
  ACCESSOR(std::uint32_t, height)
  ACCESSOR(std::uint32_t, depth)
};

}  // namespace settings
