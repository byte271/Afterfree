#define _POSIX_C_SOURCE 200112L
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/uio.h>
#include <unistd.h>
extern uint64_t expand(uint64_t *, size_t, uint64_t);
int main(void) {
  int zero = open("/dev/zero", O_RDONLY);
  if (zero < 0)
    return 7;
  volatile uintptr_t invalid = 1;
  if (readv(zero, (const struct iovec *)invalid, 1) != -1 || errno != EFAULT)
    return 8;
  if (readv(-1, (const struct iovec *)invalid, 1) != -1 || errno != EBADF)
    return 9;
  void *p = (void *)(uintptr_t)1;
  errno = EDOM;
  if (posix_memalign(&p, 3, 65536) != EINVAL || p != (void *)(uintptr_t)1 || errno != EDOM)
    return 1;
  for (size_t alignment = 8; alignment <= 8192; alignment *= 2) {
    for (int api = 0; api < 2; api++) {
      if (api)
        p = aligned_alloc(alignment, 65536);
      else if (posix_memalign(&p, alignment, 65536))
        return 2;
      if (!p || (uintptr_t)p % alignment || expand(p, 8192, alignment) != 8192)
        return 3;
      struct iovec input[] = {{(char *)p + 8, 2}, {(char *)p + 4095, 2}};
      if (readv(zero, input, 2) != 4)
        return 10;
      struct iovec output[] = {
          {p, 4093}, {(void *)(uintptr_t)1, 0}, {(char *)p + 4093, 65536 - 4093}};
      if (writev(1, output, 3) != 65536)
        return 4;
      free(p);
    }
  }
  close(zero);
  // Exceed the runtime's managed-slot budget without consuming 256 MiB of RSS.
  unsigned char *buffers[4100];
  for (unsigned i = 0; i < 4100; i++) {
    buffers[i] = calloc(1, 65536);
    if (!buffers[i] || buffers[i][65535])
      return 5;
    buffers[i][0] = (unsigned char)i;
  }
  for (unsigned i = 0; i < 4100; i++) {
    if (buffers[i][0] != (unsigned char)i)
      return 6;
    free(buffers[i]);
  }
  return 0;
}
