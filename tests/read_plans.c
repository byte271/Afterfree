#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

extern uint64_t expand(uint64_t *, size_t, uint64_t);

int main(int argc, char **argv) {
  if (argc != 2)
    return 2;
  unsigned mode = strtoul(argv[1], 0, 10);
  if (mode > 5)
    return 2;
  size_t n = 131072;
  uint64_t *p = malloc(n * 8), sum = 0;
  if (!p)
    return 3;
  expand(p, n, 42);
  volatile int *location = &errno;
  *location = 73;
  if (mode == 1) {
    for (size_t i = 0; i < n; i++) {
      sum ^= p[i] + i;
      if (i > 64 && (p[i] & 1))
        break;
    }
  } else if (mode == 2) {
    for (size_t i = n; i-- > 0;)
      sum ^= p[i] + i;
  } else if (mode == 3) {
    for (size_t i = 0; i < n; i += 2)
      sum ^= p[i] + i;
  } else if (mode == 4) {
    for (size_t i = 0; i < n; i++) {
      sum ^= p[i] + i;
      // Keep a changing bound visible in the actual original machine code.
      __asm__ volatile("sub $1, %0" : "+r"(n) : : "cc");
    }
  } else {
    if (mode == 5)
      n = 17;
    for (size_t i = 0; i < n; i++)
      sum ^= p[i] + i;
  }
  int saved = *location;
  free(p);
  printf("%016lx %d\n", sum, saved);
  return saved == 73 ? 0 : 4;
}
