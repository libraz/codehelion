#include "calls.hpp"

namespace calls {

long repeat_reading() { return stable_header_call() + selected_header_call(); }

}  // namespace calls
