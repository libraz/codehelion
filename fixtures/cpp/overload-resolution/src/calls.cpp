#include "calls.hpp"

#include <cstdio>

namespace calls {

long exercise(Base& base, Derived& derived) {
  Mixer mixer{};
  auto pointer = &direct;
  return choose(1) + choose(1L) + mixer.mix(2) + mixer.mix(2L) + base.run(3) +
         derived.Base::run(4) + derived.run(5) + pointer(6) + CALL_DIRECT(7) +
         direct(9) + std::puts("codehelion");
}

}  // namespace calls
