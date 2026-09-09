#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
int main(int argc, char **argv) {
  if (argc != 2)
    return 2;
  void *module = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
  if (!module)
    return 3;
  uint64_t (*expand)(uint64_t *, size_t, uint64_t) = dlsym(module, "expand");
  if (!expand)
    return 4;
  uint64_t *buffers[4];
  for (unsigned i = 0; i < 4; i++) {
    buffers[i] = malloc(65536);
    if (!buffers[i] || expand(buffers[i], 8192, i + 42) != 8192)
      return 5;
  }
  if (dlclose(module))
    return 6;
  for (unsigned i = 0; i < 4; i++) {
    if (write(1, buffers[i], 65536) != 65536)
      return 7;
    free(buffers[i]);
  }
  return 0;
}
