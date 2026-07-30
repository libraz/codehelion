#pragma once

namespace calls {

inline int choose(int value) { return value + 1; }
inline long choose(long value) { return value + 2; }
inline int direct(int value) { return value + 3; }

struct Mixer {
  int mix(int value) const { return value + 4; }
  long mix(long value) const { return value + 5; }
};

struct Base {
  virtual ~Base() = default;
  virtual int run(int value) const { return value + 6; }
};

struct Derived final : Base {
  int run(int value) const override { return value + 7; }
};

template <typename T>
auto dependent(T value) {
  return choose(value);
}

#ifdef WIDE_CALL
#define HEADER_ARGUMENT 1L
#else
#define HEADER_ARGUMENT 1
#endif

inline int stable_header_call() { return direct(8); }
inline long selected_header_call() { return choose(HEADER_ARGUMENT); }

#define CALL_DIRECT(value) direct(value)

}  // namespace calls
