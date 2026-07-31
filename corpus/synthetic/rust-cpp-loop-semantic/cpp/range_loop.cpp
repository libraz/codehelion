#include <vector>

std::vector<unsigned long long> collect_direct(
    const std::vector<unsigned long long>& input) {
    std::vector<unsigned long long> output;
    for (unsigned long long value : input) {
        output.push_back(value);
    }
    return output;
}

unsigned long long sum_direct(const std::vector<unsigned long long>& input) {
    unsigned long long total = 0;
    for (unsigned long long value : input) {
        total += value;
    }
    return total;
}

std::vector<unsigned long long> collect_transformed(
    const std::vector<unsigned long long>& input) {
    std::vector<unsigned long long> output;
    for (unsigned long long value : input) {
        output.push_back(value + 1);
    }
    return output;
}

unsigned long long sum_transformed(const std::vector<unsigned long long>& input) {
    unsigned long long total = 0;
    for (unsigned long long value : input) {
        total += value + 1;
    }
    return total;
}
