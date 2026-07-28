#pragma once

#include <cstdint>
#include <vector>

// The width of every accumulator declared below. Nothing in this file says
// what it is; the translation unit that includes the file does, and two
// translation units in this fixture say different things.
#ifndef ACCUM_WIDTH
#define ACCUM_WIDTH 32
#endif

namespace accumulate {

#if ACCUM_WIDTH == 64
using Total = std::uint64_t;
#else
using Total = std::uint32_t;
#endif

/// Sums the values, in whatever width this translation unit chose.
///
/// One definition, two meanings. The characters are identical in both
/// translation units and the resolved type is not, which is why a finding
/// anchored at a source location here is incomplete without the build
/// conditions that produced it.
inline Total sum(const std::vector<std::uint32_t>& values) {
  Total total = 0;
  for (std::uint32_t value : values) {
    total += static_cast<Total>(value);
  }
  return total;
}

/// The largest value, or zero for an empty input.
inline Total largest(const std::vector<std::uint32_t>& values) {
  Total best = 0;
  for (std::uint32_t value : values) {
    if (static_cast<Total>(value) > best) {
      best = static_cast<Total>(value);
    }
  }
  return best;
}

}  // namespace accumulate
