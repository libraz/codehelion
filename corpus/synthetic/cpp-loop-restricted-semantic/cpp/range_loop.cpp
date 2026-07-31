#include <vector>

std::vector<long> collect_first(const std::vector<long>& input) {
    std::vector<long> output;
    for (long value : input) {
        output.push_back(value);
    }
    return output;
}

std::vector<long> collect_second(const std::vector<long>& input) {
    std::vector<long> output;
    for (long value : input) {
        output.push_back(value);
    }
    return output;
}

std::vector<long> collect_transformed(const std::vector<long>& input) {
    std::vector<long> output;
    for (long value : input) {
        output.push_back(value + 1);
    }
    return output;
}

long sum_first(const std::vector<long>& input) {
    long total = 0;
    for (long value : input) {
        total += value;
    }
    return total;
}

long product_second(const std::vector<long>& input) {
    long total = 1;
    for (long value : input) {
        total *= value;
    }
    return total;
}

long sum_transformed(const std::vector<long>& input) {
    long total = 0;
    for (long value : input) {
        total += value + 1;
    }
    return total;
}
