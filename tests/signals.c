#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/resource.h>
extern uint64_t expand(uint64_t *, size_t, uint64_t);
int main(int argc, char **argv) {
  struct rlimit core = {0, 0};
  setrlimit(RLIMIT_CORE, &core);
  uint64_t *buffer = malloc(65536);
  if (!buffer || expand(buffer, 8192, 42) != 8192)
    return 2;
  if (argc > 1 && argv[1][0] == '2') {
    volatile uintptr_t invalid = 1;
    *(volatile int *)invalid = 1;
    return 3;
  }
  if (argc > 1 && argv[1][0] == '1')
    signal(SIGSEGV, SIG_IGN);
  else {
    struct sigaction action = {0};
    action.sa_handler = SIG_IGN;
    sigaction(SIGSEGV, &action, 0);
  }
  volatile uint64_t value = buffer[0];
  (void)value;
  free(buffer);
  return 0;
}
