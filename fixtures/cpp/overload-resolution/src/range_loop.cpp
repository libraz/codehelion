#include <vector>

std::vector<long> copied(std::vector<long> input) {
  std::vector<long> output;
  for (const auto& value : input) {
    output.push_back(value);
  }
  return output;
}

std::vector<long> copied_again(std::vector<long> input) {
  std::vector<long> output;
  for (const auto& value : input) {
    output.push_back(value);
  }
  return output;
}

std::vector<long> transformed(std::vector<long> input) {
  std::vector<long> output;
  for (const auto& value : input) {
    output.push_back(value + 1);
  }
  return output;
}

long summed(std::vector<long> input) {
  long total = 0;
  for (const auto& value : input) {
    total += value;
  }
  return total;
}

long summed_again(std::vector<long> input) {
  long total = 1;
  for (const auto& value : input) {
    total *= value;
  }
  return total;
}

long transformed_sum(std::vector<long> input) {
  long total = 0;
  for (const auto& value : input) {
    total += value + 1;
  }
  return total;
}
