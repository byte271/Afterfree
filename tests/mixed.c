#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static uint64_t native_calls;
struct __attribute__((packed)) Unaligned {
  uint64_t value;
};
__attribute__((noinline)) static uint64_t produce(unsigned char *out, size_t size,
                                                  const uint64_t *input, int partial) {
  uint64_t call = ++native_calls;
  if (partial)
    size /= 2;
  out[0] = (unsigned char)(input[0] + call);
  size_t i = 1;
  for (; i + 8 <= size; i += 8)
    ((struct Unaligned *)(out + i))->value = input[(i / 8) % 16] + i + call;
  for (; i < size; i++)
    out[i] = (unsigned char)(input[i % 16] + i + call);
  return call;
}
int main(int argc, char **argv) {
  const size_t size = 65537;
  int mode = argc > 1 ? atoi(argv[1]) : 0;
  uint64_t values[64] = {0};
  unsigned char *outputs[6];
  for (int i = 0; i < 6; i++) {
    for (size_t j = 0; j < 64; j++)
      values[j] = (uint64_t)(i * 701 + j);
    outputs[i] = calloc(1, size);
    if (!outputs[i])
      return 2;
    const uint64_t *input = values + ((mode == 1 && i % 2) ? 32 : 0);
    if (produce(outputs[i], size, input, mode == 2 && i % 2) != (uint64_t)i + 1)
      return 3;
  }
  for (int i = 5; i >= 0; i--) {
    size_t offset = 0;
    while (offset < size) {
      ssize_t n = write(1, outputs[i] + offset, size - offset);
      if (n <= 0)
        return 4;
      offset += (size_t)n;
    }
    free(outputs[i]);
  }
  return native_calls == 6 ? 0 : 5;
}
