// Seed source for the synthetic evaluation corpus (C++).
// Hand-authored; the variant files derive from this one.

int sum_even(const int *values, int count) {
    int total = 0;
    for (int i = 0; i < count; i++) {
        if (values[i] % 2 == 0) {
            total += values[i];
        }
    }
    return total;
}

int max_run(const bool *flags, int count) {
    int best = 0;
    int current = 0;
    for (int i = 0; i < count; i++) {
        if (flags[i]) {
            current += 1;
            if (current > best) {
                best = current;
            }
        } else {
            current = 0;
        }
    }
    return best;
}

class Counter {
public:
    int value() const {
        return count_;
    }

private:
    int count_;
};
