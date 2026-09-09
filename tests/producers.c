#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>
#define API __attribute__((visibility("default"), noinline))
API uint64_t expand(uint64_t *out, size_t n, uint64_t seed) {
  for (size_t i = 0; i < n; i++) {
    seed ^= seed << 13;
    seed ^= seed >> 7;
    seed ^= seed << 17;
    out[i] = seed;
  }
  return n;
}
API uint64_t lookup(uint64_t *out, size_t n, const uint64_t *seeds) {
  for (size_t i = 0; i < n; i++) {
    uint64_t x = seeds[i % 16] + i;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    out[i] = x;
  }
  return n;
}
API uint64_t partial(uint64_t *out, size_t n) {
  for (size_t i = 0; i < n / 2; i++)
    out[i] = i;
  return n / 2;
}
API uint64_t dependent(uint64_t *out, size_t n) {
  for (size_t i = 0; i < n; i++)
    out[i] ^= i;
  return n;
}
API uint64_t timed(uint64_t *out, size_t n) { return expand(out, n, (uint64_t)time(0)); }
API uint64_t timestamp(uint64_t *out, size_t n) {
  unsigned a, d;
  __asm__ volatile("rdtsc" : "=a"(a), "=d"(d));
  return expand(out, n, ((uint64_t)d << 32) | a);
}
API uint64_t sse(double *out, size_t n, const double *input) {
  for (size_t i = 0; i < n; i++)
    out[i] = input[i % 8] * 1.5 + (double)i;
  return n;
}
API uint64_t read_with_errno(const uint64_t *pointer) {
  errno = EDOM;
  volatile uint64_t value = *pointer;
  (void)value;
  return (uint64_t)errno;
}
