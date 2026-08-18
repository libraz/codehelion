// Seed source for the synthetic evaluation corpus (C++).
// Hand-authored; the variant files derive from this one.
//
// Every function here takes the same parameter list and returns the same type,
// so one signature covers the whole file. Only `sum_even` is duplicated: the
// rest are unrelated computations that happen to be reached the same way.

int sum_even(const int *values, int count) {
    int total = 0;
    for (int i = 0; i < count; i++) {
        if (values[i] % 2 == 0) {
            total += values[i];
        }
    }
    return total;
}

int first_zero_index(const int *values, int count) {
    int index = 0;
    while (index < count) {
        if (values[index] == 0) {
            return index;
        }
        index++;
    }
    return -1;
}

int range_span(const int *values, int count) {
    if (count <= 0) {
        return 0;
    }
    int low = values[0];
    int high = values[0];
    for (int i = 1; i < count; i++) {
        low = values[i] < low ? values[i] : low;
        high = values[i] > high ? values[i] : high;
    }
    return high - low;
}

int digit_rollover(const int *values, int count) {
    if (count <= 0) {
        return 0;
    }
    int carry = 0;
    int position = 0;
    do {
        carry = (carry + values[position]) / 10;
        position += 1;
    } while (position < count);
    return carry;
}

int nested_pair_hits(const int *values, int count) {
    int hits = 0;
    for (int i = 0; i < count; i++) {
        for (int j = i + 1; j < count; j++) {
            if (values[i] + values[j] == 0) {
                hits += 1;
            }
        }
    }
    return hits;
}

int switch_bucket(const int *values, int count) {
    int bucket = 0;
    for (int i = 0; i < count; i++) {
        switch (values[i] % 3) {
        case 0:
            bucket += 1;
            break;
        case 1:
            bucket += 2;
            break;
        default:
            bucket -= 1;
            break;
        }
    }
    return bucket;
}

int checksum_rotate(const int *values, int count) {
    unsigned int state = 2166136261u;
    for (int i = 0; i < count; i++) {
        state ^= static_cast<unsigned int>(values[i]);
        state = (state << 5) | (state >> 27);
    }
    return static_cast<int>(state & 0x7fffffff);
}

int trailing_zero_width(const int *values, int count) {
    int end = count;
    while (end > 0 && values[end - 1] == 0) {
        end -= 1;
    }
    if (end == count) {
        return 0;
    }
    return count - end;
}

int step_grade(const int *values, int count) {
    int grade = 0;
    for (int i = 1; i < count; i++) {
        int step = values[i] - values[i - 1];
        if (step > 4) {
            grade += 2;
        } else if (step > 0) {
            grade += 1;
        } else if (step < -4) {
            grade -= 2;
        }
    }
    return grade;
}
