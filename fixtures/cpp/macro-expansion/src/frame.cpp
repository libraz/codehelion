#include "accessor.hpp"

namespace settings {

/// Written where it reads, so that the file holds both kinds of declaration and
/// a test can tell them apart rather than assume everything here came from the
/// macro.
std::uint32_t volume(const Frame& frame) {
  return frame.width() * frame.height() * frame.depth();
}

}  // namespace settings
