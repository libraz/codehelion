#include <expected>

std::expected<unsigned long, int> direct(std::expected<unsigned long, int> value) {
  return value;
}

std::expected<unsigned long, int> transformed(std::expected<unsigned long, int> value) {
  return std::expected<unsigned long, int>(value.value_or(0) + 1);
}

bool present(std::expected<unsigned long, int> expected_value) {
  if (expected_value.has_value()) return true;
  return false;
}

bool present_with_flag(std::expected<unsigned long, int> expected_value, bool keep) {
  if (expected_value.has_value() && keep) return true;
  return false;
}
