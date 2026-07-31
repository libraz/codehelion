#include <string>

unsigned long long first(unsigned long long value) {
    const auto text = std::to_string(value);
    return std::stoull(text);
}

unsigned long long second(unsigned long long value) {
    const auto text = std::to_string(value);
    return std::stoull(text);
}

std::size_t formats_twice(unsigned long long value) {
    return (std::to_string(value) + std::to_string(value)).size();
}
