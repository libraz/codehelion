// Seed source for the synthetic evaluation corpus (C).
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

int max_run(const int *flags, int count) {
    int best = 0;
    int current = 0;
    for (int i = 0; i < count; i++) {
        if (flags[i] != 0) {
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

struct counter {
    int count;
};

int counter_value(const struct counter *self) {
    return self->count;
}
