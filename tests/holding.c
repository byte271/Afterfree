#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
extern uint64_t expand(uint64_t *, size_t, uint64_t);
int main(int argc, char **argv) {
  size_t count = argc > 1 ? strtoul(argv[1], 0, 10) : 4;
  size_t bytes = argc > 2 ? strtoul(argv[2], 0, 10) : 1048576;
  if (!count || count > 1024 || bytes < 8 || bytes % 8)
    return 2;
  uint64_t **buffers = malloc(count * sizeof(*buffers));
  if (!buffers)
    return 3;
  for (size_t i = 0; i < count; i++) {
    buffers[i] = malloc(bytes);
    if (!buffers[i])
      return 3;
    expand(buffers[i], bytes / 8, 42 + i);
  }
  uint64_t checksum = 0;
  for (size_t i = count; i-- > 0;) {
    for (size_t j = 0; j < bytes / 8; j++)
      checksum ^= buffers[i][j] + j;
    free(buffers[i]);
  }
  free(buffers);
  printf("%016lx\n", checksum);
  return 0;
}
