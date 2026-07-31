#include "calls.hpp"

#include <cstdio>
#include <algorithm>
#include <iterator>
#include <mutex>
#include <vector>

namespace calls {

long exercise(Base& base, Derived& derived) {
  Mixer mixer{};
  auto pointer = &direct;
  return choose(1) + choose(1L) + mixer.mix(2) + mixer.mix(2L) + base.run(3) +
         derived.Base::run(4) + derived.run(5) + pointer(6) + CALL_DIRECT(7) +
         direct(9) + std::puts("codehelion");
}

long standard_api_names() {
  std::vector<long> input{1};
  std::vector<long> output;
  auto first = input.begin();
  output.push_back(*first);
  return output.front();
}

long standard_api_names_again() {
  std::vector<long> input{2};
  std::vector<long> output;
  auto first = input.begin();
  output.push_back(*first);
  return output.front();
}

std::mutex guarded_mutex;

void hold_lock_once() {
  std::lock_guard<std::mutex> guard(guarded_mutex);
}

void hold_lock_again() {
  std::lock_guard<std::mutex> guard(guarded_mutex);
}

void hold_two_locks() {
  std::lock_guard<std::mutex> first(guarded_mutex);
  std::lock_guard<std::mutex> second(guarded_mutex);
}

void hold_nested_lock() {
  if (true) {
    std::lock_guard<std::mutex> guard(guarded_mutex);
  }
}

std::vector<long> doubled(std::vector<long> input) {
  std::vector<long> output;
  auto first = input.begin();
  std::transform(first, input.end(), std::back_inserter(output),
                 [](long value) { return value * 2; });
  return output;
}

std::vector<long> tripled(std::vector<long> input) {
  std::vector<long> output;
  auto first = input.begin();
  std::transform(first, input.end(), std::back_inserter(output),
                 [](long value) { return value * 3; });
  return output;
}

std::vector<long> positive(std::vector<long> input) {
  std::vector<long> output;
  auto first = input.begin();
  std::copy_if(first, input.end(), std::back_inserter(output),
               [](long value) { return value > 0; });
  return output;
}

std::vector<long> even(std::vector<long> input) {
  std::vector<long> output;
  auto first = input.begin();
  std::copy_if(first, input.end(), std::back_inserter(output),
               [](long value) { return value % 2 == 0; });
  return output;
}

}  // namespace calls
