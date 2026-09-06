/* Start the measured child from a small native image. Merely exec'ing the
 * target can retain the Python parent's pre-exec RSS high-water mark. */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char **argv) {
  if (argc < 3)
    return 2;
  int fd = atoi(argv[1]);
  if (fd < 3)
    return 2;
  pid_t child = fork();
  if (child < 0)
    return 2;
  if (child > 0) {
    int status;
    struct rusage usage;
    pid_t result;
    do {
      result = wait4(child, &status, 0, &usage);
    } while (result < 0 && errno == EINTR);
    if (result < 0)
      return 2;
    if (dprintf(fd, "%llu %d\n", (unsigned long long)usage.ru_maxrss * 1024, status) < 0)
      return 2;
    close(fd);
    return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
  }
  char pid[64];
  ssize_t n = readlink("/proc/self", pid, sizeof(pid) - 1);
  if (n <= 0)
    return 2;
  pid[n++] = '\n';
  for (ssize_t off = 0; off < n;) {
    ssize_t k = write(fd, pid + off, n - off);
    if (k < 0 && errno == EINTR)
      continue;
    if (k <= 0)
      return 2;
    off += k;
  }
  close(fd);
  const char *preload = getenv("AF_MEASURE_LD_PRELOAD");
  if (preload) {
    if (setenv("LD_PRELOAD", preload, 1))
      return 2;
    unsetenv("AF_MEASURE_LD_PRELOAD");
  }
  execvp(argv[2], argv + 2);
  perror("afterfree measurement launcher");
  return 127;
}
