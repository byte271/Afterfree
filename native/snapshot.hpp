#pragma once
#include "common.hpp"
#include <cstdio>
#include <memory>
#include <sys/uio.h>

namespace af {
// Safe speculative reads under the single-thread, stable-mappings contract.
class SnapshotReader {
public:
  bool fallback = false;
  std::vector<std::pair<uint64_t, uint64_t>> readable;
  bool copy(uint64_t address, void *out, size_t size) {
    if (!size || address > UINT64_MAX - size)
      return false;
    if (!fallback) {
      iovec local{out, size}, remote{reinterpret_cast<void *>(address), size};
      auto n = syscall(SYS_process_vm_readv, getpid(), &local, 1, &remote, 1, 0);
      if (n == static_cast<ssize_t>(size))
        return true;
      if (n >= 0 || (errno != ENOSYS && errno != EPERM))
        return false;
      // Some supported containers omit process_vm_readv. In the documented
      // single-thread/no-asynchronous-mapping-mutation contract, a current
      // readable-map check makes a local copy safe. Never read PROT_NONE.
      fallback = true;
      FILE *f = std::fopen("/proc/self/maps", "r");
      if (!f)
        return false;
      auto close_file = [](FILE *stream) { std::fclose(stream); };
      std::unique_ptr<FILE, decltype(close_file)> file(f, close_file);
      char line[8192], permissions[8];
      unsigned long low, high;
      while (std::fgets(line, sizeof line, f))
        if (std::sscanf(line, "%lx-%lx %7s", &low, &high, permissions) == 3 &&
            permissions[0] == 'r')
          readable.emplace_back(low, high);
    }
    uint64_t cursor = address;
    for (auto range : readable) {
      if (range.first > cursor)
        return false;
      if (range.second <= cursor)
        continue;
      cursor = std::min(address + size, range.second);
      if (cursor == address + size) {
        std::memcpy(out, reinterpret_cast<const void *>(address), size);
        return true;
      }
    }
    return false;
  }
};
} // namespace af
