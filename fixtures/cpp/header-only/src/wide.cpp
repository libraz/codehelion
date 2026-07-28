// Compiled with -DACCUM_WIDTH=64, so the same header declares wider types.

#include "accumulate.hpp"

std::uint64_t wide_sum(const std::vector<std::uint32_t>& values) {
  return accumulate::sum(values);
}
