// Compiled without -DACCUM_WIDTH, so the header's default of 32 applies.

#include "accumulate.hpp"

std::uint32_t narrow_sum(const std::vector<std::uint32_t>& values) {
  return accumulate::sum(values);
}
