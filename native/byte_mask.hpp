#pragma once
#include "common.hpp"
#include <algorithm>

namespace af {
// Byte-granular dependency state, operated on in word-sized pieces. No page
// rounding: one missing byte still makes an input incomplete.
struct ByteMask {
  std::array<uint64_t, PAGE / 64> words{};
  static uint64_t mask(unsigned offset, unsigned count) {
    return (UINT64_MAX >> (64 - count)) << offset;
  }
  bool operator[](size_t offset) const { return (words[offset / 64] >> (offset % 64)) & 1; }
  void set(size_t offset) { words[offset / 64] |= uint64_t(1) << (offset % 64); }
  bool any() const {
    for (auto word : words)
      if (word)
        return true;
    return false;
  }
  void mark(size_t offset, size_t count) {
    while (count) {
      auto n = std::min(count, 64 - offset % 64);
      words[offset / 64] |= mask(offset % 64, n);
      offset += n;
      count -= n;
    }
  }
  bool all(size_t offset, size_t count) const {
    while (count) {
      auto n = std::min(count, 64 - offset % 64);
      auto bits = mask(offset % 64, n);
      if ((words[offset / 64] & bits) != bits)
        return false;
      offset += n;
      count -= n;
    }
    return true;
  }
};
} // namespace af
