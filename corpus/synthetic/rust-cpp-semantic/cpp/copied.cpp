#include <algorithm>
#include <iterator>
#include <optional>
#include <vector>

long copied() {
    std::vector<long> input{1};
    std::vector<long> output;
    auto first = input.begin();
    output.push_back(*first);
    return output.front();
}

long defaulted(std::optional<long> value) {
    if (value.has_value()) {
        return *value;
    }
    return 0;
}

std::vector<long> transformed() {
    std::vector<long> input{2};
    std::vector<long> output;
    auto first = input.begin();
    std::transform(first, input.end(), std::back_inserter(output),
                   [](long value) { return value + 1; });
    return output;
}
