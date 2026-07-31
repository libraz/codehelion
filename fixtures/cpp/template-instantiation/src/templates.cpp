#include "templates.hpp"

namespace templates {

int instantiate() {
  const int first = twice(2);
  const int repeated = twice(3);
  const long different = twice(4L);

  Buffer<int, 4> four{};
  Buffer<int, 8> eight{};
  Buffer<double, 4> floating{};
  BufferForComparison<int, 4> comparison{};

  Holder<int*> partial{};
  Holder<bool> explicit_specialization{};
  std::vector<int> external{};

  return ordinary(first + repeated + static_cast<int>(different)) + four.at(0) +
         eight.at(0) + static_cast<int>(floating.at(0)) + comparison.at(0) + *partial.value +
         static_cast<int>(explicit_specialization.explicit_body()) +
         static_cast<int>(external.size());
}

}  // namespace templates
