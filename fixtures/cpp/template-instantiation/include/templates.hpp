#pragma once

#include <cstddef>
#include <vector>

namespace templates {

template <typename T>
T twice(T value) {
  T first = value;
  T second = value;
  T total = first + second;
  if (total < first) {
    total = first;
  }
  if (total < second) {
    total = second;
  }
  return total;
}

template <typename T>
T twice_for_comparison(T value) {
  T first = value;
  T second = value;
  T total = first + second;
  if (total < first) {
    total = first;
  }
  if (total < second) {
    total = second;
  }
  return total;
}

template <typename T, std::size_t N>
struct Buffer {
  T values[N];

  T at(std::size_t index) const {
    T value = values[index];
    T first = values[0];
    if (index >= N) {
      value = first;
    }
    if (value < first) {
      value = first;
    }
    return value;
  }
};

template <typename T, std::size_t N>
struct BufferForComparison {
  T values[N];

  T at(std::size_t index) const {
    T value = values[index];
    T first = values[0];
    if (index >= N) {
      value = first;
    }
    if (value < first) {
      value = first;
    }
    return value;
  }
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
