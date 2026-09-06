#pragma once
#include "common.hpp"
#include <cstdlib>
#include <fcntl.h>
#include <linux/memfd.h>
#include <sys/mman.h>
#include <sys/stat.h>

namespace af {
// One bounded replay window. The app has a read-only mapping; the worker
// publishes it before replying and cannot reuse it until the next request.
// Both mappings count toward aggregate RSS. No file or spill path is used.
class SharedArena {
  int descriptor = -1;

public:
  static constexpr size_t maximum = 256 * PAGE;
  size_t capacity = 64 * PAGE;
  uint8_t *data = nullptr;
  ~SharedArena() { reset(); }
  void reset() {
    if (data)
      munmap(data, capacity);
    if (descriptor >= 0)
      close(descriptor);
    data = nullptr;
    descriptor = -1;
  }
  bool create() {
    // Diagnostic range is bounded; the receiver trusts only the sealed size.
    if (const char *option = std::getenv("AF_WINDOW_KIB")) {
      char *end;
      auto value = std::strtoul(option, &end, 10);
      if (!*option || *end || value < 64 || value > maximum / 1024 || value % 4)
        return false;
      capacity = value * 1024;
    }
    descriptor = syscall(SYS_memfd_create, "afterfree-window", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (descriptor < 0)
      return false;
    if (ftruncate(descriptor, capacity) ||
        fcntl(descriptor, F_ADD_SEALS, F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL) < 0) {
      reset();
      return false;
    }
    return map(PROT_READ);
  }
  bool map(int protection) {
    void *p = mmap(nullptr, capacity, protection, MAP_SHARED, descriptor, 0);
    if (p == MAP_FAILED) {
      reset();
      return false;
    }
    data = static_cast<uint8_t *>(p);
    madvise(data, capacity, MADV_DONTDUMP);
    return true;
  }
  bool send(int channel) {
    char byte = 0;
    iovec io{&byte, 1};
    alignas(cmsghdr) char control[CMSG_SPACE(sizeof(int))]{};
    msghdr message{};
    message.msg_iov = &io;
    message.msg_iovlen = 1;
    message.msg_control = control;
    message.msg_controllen = sizeof control;
    auto *c = CMSG_FIRSTHDR(&message);
    c->cmsg_level = SOL_SOCKET;
    c->cmsg_type = SCM_RIGHTS;
    c->cmsg_len = CMSG_LEN(sizeof(int));
    std::memcpy(CMSG_DATA(c), &descriptor, sizeof descriptor);
    ssize_t result;
    do {
      result = sendmsg(channel, &message, MSG_NOSIGNAL);
    } while (result < 0 && errno == EINTR);
    close(descriptor);
    descriptor = -1;
    return result == 1;
  }
  bool receive(int channel) {
    char byte;
    iovec io{&byte, 1};
    alignas(cmsghdr) char control[CMSG_SPACE(sizeof(int))]{};
    msghdr message{};
    message.msg_iov = &io;
    message.msg_iovlen = 1;
    message.msg_control = control;
    message.msg_controllen = sizeof control;
    ssize_t n;
    do {
      n = recvmsg(channel, &message, MSG_CMSG_CLOEXEC);
    } while (n < 0 && errno == EINTR);
    auto *c = CMSG_FIRSTHDR(&message);
    if (n != 1 || !c || c->cmsg_level != SOL_SOCKET || c->cmsg_type != SCM_RIGHTS ||
        c->cmsg_len != CMSG_LEN(sizeof(int)))
      return false;
    std::memcpy(&descriptor, CMSG_DATA(c), sizeof descriptor);
    struct stat info {};
    int seals = fcntl(descriptor, F_GET_SEALS);
    if ((message.msg_flags & (MSG_CTRUNC | MSG_TRUNC)) || fstat(descriptor, &info) ||
        info.st_size < 16 * int64_t(PAGE) || info.st_size > int64_t(maximum) ||
        info.st_size % PAGE || seals < 0 ||
        (seals & (F_SEAL_GROW | F_SEAL_SHRINK)) != (F_SEAL_GROW | F_SEAL_SHRINK)) {
      reset();
      return false;
    }
    capacity = info.st_size;
    if (!map(PROT_READ | PROT_WRITE))
      return false;
    close(descriptor);
    descriptor = -1;
    return true;
  }
};
} // namespace af
