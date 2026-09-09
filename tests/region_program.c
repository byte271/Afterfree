#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

__attribute__((noinline)) static uint64_t fill(uint8_t *output, size_t first, size_t length) {
  for (size_t i = first; i < first + length; i++)
    output[i] = (uint8_t)((i * 71) ^ (i >> 9));
  return length;
}
int main(int argc, char **argv) {
  if (argc != 2) return 2;
  unsigned mode = strtoul(argv[1], 0, 10);
  const size_t size = 1 << 20, length = 3 * size / 4;
  size_t first = mode == 0 ? 0 : mode == 1 ? size / 8 : size / 4;
  size_t produced = length - (mode == 3 ? 3 : 0);
  uint8_t *data = calloc(1, size);
  if (!data || mode > 3) return 3;
  if (fill(data, first, produced) != produced) return 4;
  // Cross-boundary reads and writes must preserve both the validated region
  // and ordinary live bytes in the same original allocation.
  data[0] = 19;
  data[size - 1] = 27;
  if (fwrite(data, 1, size, stdout) != size) return 5;
  free(data);
  return 0;
}
