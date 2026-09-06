#pragma once
#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#include <vector>

namespace af {
struct ErrnoScope {
  int saved = errno;
  ~ErrnoScope() { errno = saved; }
};
constexpr uint64_t PAGE = 4096, MAX_BLOB = 64ULL << 20, MAX_BUFFER = 256ULL << 20;
constexpr uint64_t MAGIC = 0x314552464146ULL;
inline uint64_t monotonic_ns() {
  timespec t{};
  clock_gettime(CLOCK_MONOTONIC, &t);
  return uint64_t(t.tv_sec) * 1000000000 + t.tv_nsec;
}
struct Timer {
  uint64_t &total, start;
  uint64_t *active;
  explicit Timer(uint64_t &value, uint64_t *live = nullptr)
      : total(value), start(monotonic_ns()), active(live) {
    if (active)
      *active = start;
  }
  ~Timer() {
    total += monotonic_ns() - start;
    if (active)
      *active = 0;
  }
};
inline uint64_t base(uint64_t p) { return p & ~(PAGE - 1); }
inline uint64_t rounded(uint64_t n) { return (n + PAGE - 1) & ~(PAGE - 1); }
struct Header {
  uint64_t magic = MAGIC, version = 1, entry = 0, stop = 0, output = 0, length = 0;
  uint64_t result = 0, steps = 0, input_bytes = 0, fs_base = 0, gs_base = 0;
  uint64_t regs[18]{};
  uint8_t xmm[16][16]{};
  uint32_t mxcsr = 0, page_count = 0, code_count = 0, input_count = 0;
  uint8_t digest[32]{};
};
struct Instruction {
  uint64_t address = 0;
  uint8_t size = 0;
  uint8_t bytes[15]{};
};
struct Segment {
  uint64_t address = 0;
  std::vector<uint8_t> bytes;
};
struct Recipe {
  Header h;
  std::vector<uint64_t> pages;
  std::vector<Instruction> code;
  std::vector<Segment> inputs;
};
inline bool read_snapshot(const Recipe &recipe, uint64_t address, void *out, size_t size) {
  if (address > UINT64_MAX - size)
    return false;
  auto *destination = static_cast<uint8_t *>(out);
  while (size) {
    const Segment *found = nullptr;
    for (auto &input : recipe.inputs)
      if (address >= input.address && address - input.address < input.bytes.size()) {
        found = &input;
        break;
      }
    if (!found)
      return false;
    size_t offset = address - found->address;
    size_t count = std::min(size, found->bytes.size() - offset);
    std::memcpy(destination, found->bytes.data() + offset, count);
    destination += count;
    address += count;
    size -= count;
  }
  return true;
}
inline bool rip_jump_slot(const Instruction &instruction, uint64_t &slot) {
  if (instruction.size != 6 || instruction.bytes[0] != 0xff || instruction.bytes[1] != 0x25)
    return false;
  int32_t displacement;
  std::memcpy(&displacement, instruction.bytes + 2, sizeof displacement);
  slot = instruction.address + instruction.size + displacement;
  return slot <= UINT64_MAX - 8;
}
enum Command : uint64_t {
  PUT = 1,
  RESTORE = 2,
  DROP = 3,
  QUIT = 4,
  PING = 5,
  POLICY_PROBE = 6,
  REGISTER = 7,
  RESTORE_RANGE = 8,
  PEAK_RSS = 9,
  PROFILE = 10,
  RESTORE_SHARED = 11,
  REGISTER_STREAM = 12,
  STREAM_ACK = 13
};
struct Registration {
  uint64_t backend = 0, page_bytes = 0, retained_bytes = 0;
};
struct Request {
  uint64_t command = 0, id = 0, size = 0;
};
struct Response {
  uint64_t status = 0, size = 0;
  char message[240]{};
};
inline bool read_all(int fd, void *p, size_t n) {
  auto *b = static_cast<uint8_t *>(p);
  while (n) {
    ssize_t k = syscall(SYS_read, fd, b, n);
    if (k < 0 && errno == EINTR)
      continue;
    if (k <= 0)
      return false;
    b += k;
    n -= k;
  }
  return true;
}
inline bool write_all(int fd, const void *p, size_t n) {
  auto *b = static_cast<const uint8_t *>(p);
  while (n) {
    ssize_t k = syscall(SYS_sendto, fd, b, n, MSG_NOSIGNAL, nullptr, 0);
    if (k < 0 && errno == EINTR)
      continue;
    if (k <= 0)
      return false;
    b += k;
    n -= k;
  }
  return true;
}
template <class T> inline void append(std::vector<uint8_t> &v, const T &x) {
  auto *p = reinterpret_cast<const uint8_t *>(&x);
  v.insert(v.end(), p, p + sizeof x);
}
inline std::vector<uint8_t> encode(Recipe &r) {
  r.h.page_count = r.pages.size();
  r.h.code_count = r.code.size();
  r.h.input_count = r.inputs.size();
  std::vector<uint8_t> v;
  append(v, r.h);
  for (auto p : r.pages)
    append(v, p);
  for (auto &c : r.code)
    append(v, c);
  for (auto &s : r.inputs) {
    append(v, s.address);
    uint64_t n = s.bytes.size();
    append(v, n);
    v.insert(v.end(), s.bytes.begin(), s.bytes.end());
  }
  if (v.size() > MAX_BLOB)
    throw std::runtime_error("recipe exceeds 64 MiB limit");
  return v;
}
struct Reader {
  const std::vector<uint8_t> &v;
  size_t offset = 0;
  template <class T> T take() {
    if (sizeof(T) > v.size() - offset)
      throw std::runtime_error("truncated recipe");
    T x;
    std::memcpy(&x, v.data() + offset, sizeof x);
    offset += sizeof x;
    return x;
  }
  std::vector<uint8_t> bytes(uint64_t n) {
    if (n > v.size() - offset)
      throw std::runtime_error("truncated input");
    std::vector<uint8_t> x(v.begin() + offset, v.begin() + offset + n);
    offset += n;
    return x;
  }
};
inline Recipe decode(const std::vector<uint8_t> &blob) {
  Reader v{blob};
  Recipe r;
  r.h = v.take<Header>();
  const auto &h = r.h;
  if (h.magic != MAGIC || h.version != 1 || !h.length || h.length > MAX_BUFFER || h.output % PAGE ||
      h.output > UINT64_MAX - rounded(h.length) || h.page_count > 262144 ||
      h.code_count > 1000000 || h.input_count > 1000000 || h.steps > 500000000 ||
      (h.mxcsr & ~uint32_t(0xffff)))
    throw std::runtime_error("invalid recipe header");
  for (uint32_t i = 0; i < h.page_count; i++) {
    auto p = v.take<uint64_t>();
    if (p % PAGE || p > UINT64_MAX - PAGE)
      throw std::runtime_error("invalid page");
    r.pages.push_back(p);
  }
  for (uint32_t i = 0; i < h.code_count; i++) {
    auto c = v.take<Instruction>();
    if (!c.size || c.size > 15 || c.address > UINT64_MAX - c.size)
      throw std::runtime_error("invalid instruction");
    r.code.push_back(c);
  }
  uint64_t total = 0;
  for (uint32_t i = 0; i < h.input_count; i++) {
    auto p = v.take<uint64_t>();
    auto n = v.take<uint64_t>();
    if (!n || n > MAX_BLOB || p > UINT64_MAX - n)
      throw std::runtime_error("invalid input range");
    total += n;
    r.inputs.push_back({p, v.bytes(n)});
  }
  if (v.offset != blob.size() || total != h.input_bytes)
    throw std::runtime_error("recipe length mismatch");
  std::sort(r.pages.begin(), r.pages.end());
  if (std::adjacent_find(r.pages.begin(), r.pages.end()) != r.pages.end())
    throw std::runtime_error("duplicate recipe page");
  std::sort(r.code.begin(), r.code.end(), [](auto &a, auto &b) { return a.address < b.address; });
  for (size_t i = 1; i < r.code.size(); i++)
    if (r.code[i].address < r.code[i - 1].address + r.code[i - 1].size)
      throw std::runtime_error("overlapping recipe instructions");
  std::sort(r.inputs.begin(), r.inputs.end(),
            [](auto &a, auto &b) { return a.address < b.address; });
  for (size_t i = 1; i < r.inputs.size(); i++)
    if (r.inputs[i].address < r.inputs[i - 1].address + r.inputs[i - 1].bytes.size())
      throw std::runtime_error("overlapping recipe inputs");
  for (auto &input : r.inputs) {
    auto it = std::lower_bound(r.code.begin(), r.code.end(), input.address,
                               [](auto &c, uint64_t p) { return c.address + c.size <= p; });
    for (; it != r.code.end() && it->address < input.address + input.bytes.size(); ++it) {
      auto first = std::max(input.address, it->address);
      auto last = std::min(input.address + input.bytes.size(), it->address + it->size);
      if (std::memcmp(input.bytes.data() + first - input.address, it->bytes + first - it->address,
                      last - first))
        throw std::runtime_error("input conflicts with recipe code");
    }
  }
  return r;
}
} // namespace af
