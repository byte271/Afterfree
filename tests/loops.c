#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <xmmintrin.h>

// Integer widths, flags across instructions, SIMD and floating state are
// checked by running this exact executable with and without Afterfree.
int main(int argc, char **argv) {
  if (argc != 4)
    return 2;
  size_t n = strtoul(argv[1], 0, 10);
  uint64_t seed = strtoull(argv[2], 0, 10);
  unsigned mode = strtoul(argv[3], 0, 10);
  if (!n || n > 262144 || mode > 4)
    return 2;
  uint64_t *data = malloc(n * 8);
  if (!data)
    return 3;
  for (size_t i = 0; i < n; i++) {
    seed ^= seed << 13;
    seed ^= seed >> 7;
    seed ^= seed << 17;
    data[i] = seed;
  }
  uint64_t sum = seed;
  if (mode == 0) {
    uint64_t accumulator = sum;
    for (size_t i = 0; i < n; i++) {
      uint64_t x = data[i];
      __asm__ volatile("bt $0, %1; adc %1, %0; ror $3, %0" : "+r"(accumulator) : "r"(x) : "cc");
    }
    sum = accumulator;
  } else if (mode == 1) {
    uint32_t a = (uint32_t)seed;
    for (size_t i = 0; i < n; i++) {
      a = (a << 7) | (a >> 25);
      a += (uint32_t)data[i];
    }
    sum = a;
  } else if (mode == 4) {
    volatile int *location = &errno;
    *location = 71;
    for (size_t i = 0; i < n; i++) {
      sum += *location;
      *location = (int)((data[i] ^ sum) & 0xffff);
    }
    sum ^= (uint64_t)*location;
  } else {
    unsigned saved = _mm_getcsr();
    _mm_setcsr((saved & ~0x6000U) | (mode == 2 ? 0x4000U : 0x2000U));
    double acc = 0.1;
    for (size_t i = 0; i < n; i++)
      acc = acc * 1.00000001 + (double)(data[i] & 0xffff);
    unsigned status = _mm_getcsr();
    _mm_setcsr(saved);
    if (fwrite(&acc, sizeof acc, 1, stdout) != 1 || fwrite(&status, sizeof status, 1, stdout) != 1)
      return 4;
  }
  if (fwrite(&sum, sizeof sum, 1, stdout) != 1 || fwrite(data, 8, n, stdout) != n)
    return 4;
  free(data);
  return 0;
}
