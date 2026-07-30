#pragma once

#include <cstddef>
#include <vector>

namespace templates {

template <typename T>
T twice(T value) {
  return value + value;
}

template <typename T, std::size_t N>
struct Buffer {
  T values[N];
};

inline Buffer<int, 16> shared_buffer{};

template <typename T>
struct Holder {
  T value;
};

template <typename T>
struct Holder<T*> {
  T* value;
};

template <>
struct Holder<bool> {
  bool value;
  bool explicit_body() const { return !value; }
};

inline int ordinary(int value) { return value + value; }

}  // namespace templates
