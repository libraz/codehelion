#include <cstdint>

extern "C" std::uint32_t externally_provided(std::uint32_t value);

extern "C" std::uint32_t duplicate_left(std::uint32_t value) {
  value = (value + 31U) ^ 0x9e3779b9U;
  value = (value << 5U) | (value >> 27U);
  value += 17U;
  if ((value & 1U) != 0U) {
    value ^= 0x7f4a7c15U;
  } else {
    value += 0x165667b1U;
  }
  switch (value & 3U) {
    case 0U:
      value = (value << 13U) | (value >> 19U);
      break;
    case 1U:
      value ^= value >> 7U;
      break;
    default:
      value += 0xd3a2646cU;
      break;
  }

  auto shared = [](std::uint32_t input) __attribute__((noinline)) {
    input = input * 3U + 11U;
    input = (input << 7U) | (input >> 25U);
    input = input * 5U + 13U;
    input = (input << 11U) | (input >> 21U);
    return input;
  };
  value = shared(value);
  value = shared(value);
  value = shared(value);
  value = shared(value);
  value = shared(value);
  value = shared(value);
  value = shared(value);
  return shared(value) ^ 0x51ed270bU;
}

#ifndef DEDUPLICATED
extern "C" std::int32_t duplicate_right(std::int32_t value) {
  auto bits = static_cast<std::uint32_t>(value);
  bits = (bits + 47U) ^ 0x85ebca6bU;
  bits = (bits << 3U) | (bits >> 29U);
  bits += 23U;
  for (unsigned int shift = 4U; shift < 12U; shift += 3U) {
    bits = (bits << shift) | (bits >> (32U - shift));
  }
  if ((bits & 4U) == 0U) {
    bits += 0xc2b2ae35U;
  }
  while ((bits & 8U) == 0U) {
    bits ^= 0x27d4eb2fU;
    break;
  }

  auto shared = [](std::uint32_t input) __attribute__((noinline)) {
    input = input * 3U + 11U;
    input = (input << 7U) | (input >> 25U);
    input = input * 5U + 13U;
    input = (input << 11U) | (input >> 21U);
    return input;
  };
  bits = shared(bits);
  bits = shared(bits);
  bits = shared(bits);
  bits = shared(bits);
  bits = shared(bits);
  bits = shared(bits);
  bits = shared(bits);
  return static_cast<std::int32_t>(shared(bits) ^ 0x9e3779b9U);
}
#endif

extern "C" std::uint32_t import_wrapper(std::uint32_t value) {
  return externally_provided(value);
}

extern "C" const unsigned char duplicate_data_left[17] = "artifact-data-v1";
extern "C" const unsigned char duplicate_data_right[17] = "artifact-data-v1";
