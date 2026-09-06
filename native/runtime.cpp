#include "afterfree.h"
#include "recorder.hpp"
#include "transport.hpp"
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <dirent.h>
#include <fcntl.h>
#include <malloc.h>
#include <openssl/sha.h>
#include <signal.h>
#include <spawn.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <ucontext.h>

extern char **environ;
namespace {
using namespace af;
enum State : uint64_t { RESIDENT = 0, SEALED = 1, EVICTED = 2, PINNED = 3 };
struct Buffer {
  void *data = nullptr;
  size_t mapped = 0, recipe_offset = 0, recipe_length = 0;
  uint64_t id = 0;
  af_stats stats{};
  std::atomic<uint64_t> state{RESIDENT}, fault_count{0}, restore_time{0};
  std::unique_ptr<std::atomic<uint8_t>[]> pages;
  std::atomic<uint64_t> resident_pages{0}, reconstructed{0}, full_restores{0};
  size_t last_fault_end = SIZE_MAX, readahead = 1;
  bool recipe_live = false;
  void clear() {
    data = nullptr;
    mapped = recipe_offset = recipe_length = 0;
    id = 0;
    stats = {};
    state.store(RESIDENT);
    fault_count.store(0);
    restore_time.store(0);
    pages.reset();
    resident_pages.store(0);
    reconstructed.store(0);
    full_restores.store(0);
    last_fault_end = SIZE_MAX;
    readahead = 1;
    recipe_live = false;
  }
};
constexpr size_t MAX_SLOTS = 4096;
Buffer buffers[MAX_SLOTS];
// One ordered index serves exact ownership lookups, faults and range prefaults.
// It owns no allocations and remains safe to read from the pager handler.
Buffer *allocation_index[MAX_SLOTS];
size_t allocation_count = 0;
size_t after_address(uintptr_t address) {
  size_t low = 0, high = allocation_count;
  while (low < high) {
    size_t mid = low + (high - low) / 2;
    if (reinterpret_cast<uintptr_t>(allocation_index[mid]->data) <= address)
      low = mid + 1;
    else
      high = mid;
  }
  return low;
}
void index_insert(Buffer &buffer) {
  size_t pos = after_address(reinterpret_cast<uintptr_t>(buffer.data));
  std::memmove(allocation_index + pos + 1, allocation_index + pos,
               (allocation_count - pos) * sizeof(Buffer *));
  allocation_index[pos] = &buffer;
  allocation_count++;
}
void index_remove(void *pointer) {
  size_t pos = after_address(reinterpret_cast<uintptr_t>(pointer));
  if (!pos || allocation_index[pos - 1]->data != pointer)
    std::abort();
  pos--;
  std::memmove(allocation_index + pos, allocation_index + pos + 1,
               (allocation_count - pos - 1) * sizeof(Buffer *));
  allocation_count--;
}
Buffer *containing(uintptr_t address) {
  size_t pos = after_address(address);
  if (!pos)
    return nullptr;
  Buffer *buffer = allocation_index[pos - 1];
  return address - reinterpret_cast<uintptr_t>(buffer->data) < buffer->mapped ? buffer : nullptr;
}
uint64_t nextid = 1;
uint64_t resident_target = 0, automatic_evictions = 0;
std::atomic<uint64_t> restore_operations{0}, restored_bytes{0};
std::atomic<uint64_t> resident_managed{0}, peak_over_target{0};
void observe_target() {
  auto resident = resident_managed.load();
  uint64_t excess = resident_target && resident > resident_target ? resident - resident_target : 0;
  auto previous = peak_over_target.load();
  while (excess > previous && !peak_over_target.compare_exchange_weak(previous, excess)) {
  }
}
int channel = -1;
SharedArena shared_arena;
pid_t worker = -1, owner = -1;
pid_t owner_thread = -1;
std::atomic<bool> channel_broken{false};
int worker_procfs = -1;
char error[512]{};
struct sigaction previous {};
stack_t old_stack{};
void *signal_stack = nullptr;
volatile sig_atomic_t handling_fault = 0;
static_assert(std::atomic<uint64_t>::is_always_lock_free, "requires lock-free word stores");
static_assert(std::atomic<uint8_t>::is_always_lock_free, "requires lock-free page states");
int fail(const std::string &s) {
  std::snprintf(error, sizeof error, "%s", s.c_str());
  return -1;
}
uint64_t now() {
  timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return uint64_t(ts.tv_sec) * 1000000000 + ts.tv_nsec;
}
bool single_thread() {
  DIR *d = opendir("/proc/self/task");
  if (!d)
    return false;
  int n = 0;
  while (auto *e = readdir(d))
    if (e->d_name[0] != '.')
      n++;
  closedir(d);
  return n == 1;
}
Buffer *find(void *p) {
  auto *buffer = containing(reinterpret_cast<uintptr_t>(p));
  return buffer && buffer->data == p ? buffer : nullptr;
}
bool usable() {
  if (channel < 0) {
    fail("Afterfree is not initialized");
    return false;
  }
  if (getpid() != owner) {
    fail("Afterfree cannot be used after fork");
    return false;
  }
  if (!single_thread()) {
    fail("Afterfree requires one application thread");
    return false;
  }
  if (syscall(SYS_gettid) != owner_thread) {
    fail("Afterfree belongs to a different application thread");
    return false;
  }
  return true;
}
bool request(uint64_t command, uint64_t id, Response &r, uint64_t size = 0) {
  if (channel_broken.load())
    return false;
  Request q{command, id, size};
  bool ok = write_all(channel, &q, sizeof q) && read_all(channel, &r, sizeof r);
  if (!ok) {
    channel_broken.store(true);
    syscall(SYS_shutdown, channel, SHUT_RDWR);
  }
  return ok;
}
[[noreturn]] void pager_failure() {
  const char msg[] = "afterfree: fatal reconstruction failure; refusing to "
                     "expose unverified bytes\n";
  ssize_t ignored = ::write(STDERR_FILENO, msg, sizeof(msg) - 1);
  (void)ignored;
  _exit(190);
}
bool restore_span(Buffer &b, size_t first, size_t last) {
  uint64_t start = now();
  uint64_t offset = first * PAGE;
  uint64_t length = std::min(uint64_t(last * PAGE), b.recipe_offset + b.recipe_length) - offset;
  bool sliced = b.stats.page_bytes != 0;
  if (!sliced) {
    offset = b.recipe_offset;
    first = offset / PAGE;
    last = (offset + rounded(b.recipe_length)) / PAGE;
    length = b.recipe_length;
  }
  Response r;
  bool shared = sliced && shared_arena.data && length <= shared_arena.capacity;
  if (!request(shared   ? RESTORE_SHARED
               : sliced ? RESTORE_RANGE
                        : RESTORE,
               b.id, r, sliced ? ((offset - b.recipe_offset) << 32) | length : 0) ||
      r.status || r.size != length)
    return false;
  auto *destination = static_cast<uint8_t *>(b.data) + offset;
  size_t mapped = (last - first) * PAGE;
  if (mprotect(destination, mapped, PROT_READ | PROT_WRITE))
    return false;
  if (shared)
    std::memcpy(destination, shared_arena.data, length);
  else if (!read_all(channel, destination, length))
    return false;
  if (mprotect(destination, mapped, PROT_READ))
    return false;
  for (size_t i = first; i < last; i++)
    b.pages[i].store(1);
  auto resident = b.resident_pages.fetch_add(last - first) + last - first;
  if (resident == b.mapped / PAGE) {
    if (b.state != PINNED)
      b.state = SEALED;
    b.full_restores.fetch_add(1);
  }
  resident_managed.fetch_add(mapped);
  observe_target();
  b.restore_time.fetch_add(now() - start);
  b.reconstructed.fetch_add(length);
  restore_operations.fetch_add(1);
  restored_bytes.fetch_add(length);
  return true;
}
bool materialize(Buffer &b, size_t first, size_t last, bool writing) {
  const size_t window_pages = shared_arena.data ? shared_arena.capacity / PAGE : 16;
  for (size_t page = first; page < last;) {
    if (b.pages[page].load()) {
      page++;
      continue;
    }
    size_t end = page + 1;
    while (end < last && end - page < window_pages && !b.pages[end].load())
      end++;
    if (!restore_span(b, page, end))
      return false;
    page = end;
  }
  if (writing && first < last) {
    if (mprotect(static_cast<uint8_t *>(b.data) + first * PAGE, (last - first) * PAGE,
                 PROT_READ | PROT_WRITE))
      return false;
    for (size_t page = first; page < last; page++)
      b.pages[page].store(3);
    if (b.state != RESIDENT && first < (b.recipe_offset + rounded(b.recipe_length)) / PAGE &&
        last > b.recipe_offset / PAGE)
      b.state = PINNED;
  }
  if (b.state == PINNED && b.resident_pages.load() == b.mapped / PAGE && b.recipe_live) {
    Response response;
    if (request(DROP, b.id, response) && !response.status) {
      b.recipe_live = false;
      b.stats.retained_bytes = b.mapped / PAGE;
    }
  }
  return true;
}
uint64_t managed_resident() { return resident_managed.load(); }
int collect(uint64_t incoming, void *protected_output) {
  if (!resident_target)
    return 0;
  uint64_t resident = managed_resident();
  while (resident + incoming > resident_target) {
    Buffer *best = nullptr;
    uint64_t best_benefit = 0, best_cost = 1;
    for (auto &b : buffers) {
      // Restore once, then keep that generation resident. Ordinary reads need
      // no added traps, and automatic reclamation cannot cause repeated replay.
      if (!b.data || b.data == protected_output || b.state != SEALED || b.stats.evictions ||
          b.fault_count.load())
        continue;
      uint64_t reclaimable = rounded(b.recipe_length);
      uint64_t benefit =
          reclaimable > b.stats.retained_bytes ? reclaimable - b.stats.retained_bytes : 0;
      if (!benefit)
        continue;
      uint64_t cost = std::max(uint64_t(1), b.stats.validation_ns);
      if (!best || __uint128_t(benefit) * best_cost > __uint128_t(best_benefit) * cost ||
          (__uint128_t(benefit) * best_cost == __uint128_t(best_benefit) * cost &&
           b.id < best->id)) {
        best = &b;
        best_benefit = benefit;
        best_cost = cost;
      }
    }
    if (!best)
      break; // An unmet soft target is reported; never hide it with thrashing.
    if (af_evict(best->data))
      return -1;
    automatic_evictions++;
    resident -= rounded(best->recipe_length);
  }
  return 0;
}
void fault(int signal, siginfo_t *info, void *context) {
  struct Scope {
    Scope() { handling_fault = 1; }
    ~Scope() { handling_fault = 0; }
  } scope;
  int saved_errno = errno;
  auto addr = reinterpret_cast<uintptr_t>(info->si_addr);
  if (auto *buffer = containing(addr)) {
    auto &b = *buffer;
    auto start = reinterpret_cast<uintptr_t>(b.data);
    auto *ctx = static_cast<ucontext_t *>(context);
    bool writing = (ctx->uc_mcontext.gregs[REG_ERR] & 2) != 0;
    if (getpid() != owner || syscall(SYS_gettid) != owner_thread)
      pager_failure();
    size_t page = (addr - start) / PAGE;
    if (!b.pages[page].load() || (writing && b.pages[page].load() == 1)) {
      b.fault_count.fetch_add(1);
      size_t end = page + 1;
      if (!writing && b.stats.page_bytes) {
        b.readahead = page == b.last_fault_end ? std::min(size_t(16), b.readahead * 2) : 1;
        while (end < b.mapped / PAGE && end - page < b.readahead && !b.pages[end].load())
          end++;
        b.last_fault_end = end;
      }
      if (!materialize(b, page, end, writing))
        pager_failure();
      errno = saved_errno;
      return;
    }
  }
  sigaction(SIGSEGV, &previous, nullptr);
  raise(signal);
}
} // namespace
extern "C" {
int af_handling_fault() { return handling_fault; }
const char *af_error() { return error; }
int af_worker_pid() { return worker; }
int af_worker_procfs_pid() { return worker_procfs; }
int af_get_worker_profile(af_worker_profile *profile) {
  if (!profile || !usable())
    return -1;
  Response response;
  if (!request(PROFILE, 0, response) || response.status || response.size != sizeof(*profile) ||
      !read_all(channel, profile, sizeof(*profile)))
    return fail("worker profile unavailable");
  return 0;
}
uint64_t af_worker_peak_rss() {
  if (!usable())
    return 0;
  Response response;
  if (!request(PEAK_RSS, 0, response) || response.status)
    return 0;
  response.message[sizeof response.message - 1] = 0;
  return std::strtoull(response.message, nullptr, 10);
}
int af_init(const char *path) {
  if (channel >= 0)
    return fail("only one Afterfree runtime is supported per process");
  if (!path || !single_thread())
    return fail("initialization requires a worker path and one application thread");
  if (sysconf(_SC_PAGESIZE) != 4096)
    return fail("4096-byte pages required");
  if (sigaction(SIGSEGV, nullptr, &previous) || previous.sa_handler != SIG_DFL)
    return fail("an existing SIGSEGV handler is incompatible");
  int sockets[2];
  if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets))
    return fail("socketpair failed");
  timeval timeout{35, 0};
  setsockopt(sockets[0], SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout);
  setsockopt(sockets[0], SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof timeout);
  posix_spawn_file_actions_t actions;
  posix_spawn_file_actions_init(&actions);
  // The worker receives only a communication socket, never a copy of app
  // memory.
  constexpr int targetfd = 198;
  posix_spawn_file_actions_adddup2(&actions, sockets[1], targetfd);
  if (sockets[0] != targetfd)
    posix_spawn_file_actions_addclose(&actions, sockets[0]);
  if (sockets[1] != targetfd)
    posix_spawn_file_actions_addclose(&actions, sockets[1]);
  char fdarg[] = "198";
  bool shared = !getenv("AF_DISABLE_SHARED") && shared_arena.create();
  char sharedarg[] = "shared";
  char *argv[] = {const_cast<char *>(path), fdarg, shared ? sharedarg : nullptr, nullptr};
  std::vector<char *> child_env;
  for (char **p = environ; *p; p++)
    if (std::strncmp(*p, "LD_PRELOAD=", 11) && std::strncmp(*p, "LD_AUDIT=", 9))
      child_env.push_back(*p);
  child_env.push_back(nullptr);
  int rc = posix_spawn(&worker, path, &actions, nullptr, argv, child_env.data());
  posix_spawn_file_actions_destroy(&actions);
  close(sockets[1]);
  if (rc) {
    shared_arena.reset();
    close(sockets[0]);
    worker = -1;
    return fail(std::string("worker spawn failed: ") + std::strerror(rc));
  }
  channel = sockets[0];
  owner = getpid();
  owner_thread = syscall(SYS_gettid);
  channel_broken.store(false);
  resident_target = automatic_evictions = 0;
  restore_operations.store(0);
  restored_bytes.store(0);
  resident_managed.store(0);
  peak_over_target.store(0);
  Response r;
  if (shared && !shared_arena.send(channel)) {
    af_shutdown();
    return fail("shared replay window handoff failed");
  }
  if (!request(PING, 0, r) || r.status) {
    af_shutdown();
    return fail("worker handshake failed");
  }
  worker_procfs = std::atoi(r.message);
  signal_stack =
      mmap(nullptr, 64 * 1024, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (signal_stack == MAP_FAILED) {
    signal_stack = nullptr;
    af_shutdown();
    return fail("signal stack allocation failed");
  }
  stack_t stack{};
  stack.ss_sp = signal_stack;
  stack.ss_size = 64 * 1024;
  if (sigaltstack(&stack, &old_stack)) {
    af_shutdown();
    return fail("sigaltstack failed");
  }
  struct sigaction sa {};
  sa.sa_sigaction = fault;
  sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
  sigfillset(&sa.sa_mask);
  if (sigaction(SIGSEGV, &sa, nullptr)) {
    af_shutdown();
    return fail("SIGSEGV installation failed");
  }
  return 0;
}
void *af_alloc(size_t size) {
  if (!usable())
    return nullptr;
  if (!size || size > MAX_BUFFER) {
    fail("buffer size must be 1 byte through 256 MiB");
    return nullptr;
  }
  Buffer *slot = nullptr;
  for (auto &b : buffers)
    if (!b.data) {
      slot = &b;
      break;
    }
  if (!slot) {
    fail("4096 buffer limit reached");
    return nullptr;
  }
  if (collect(rounded(size), nullptr))
    return nullptr;
  void *p =
      mmap(nullptr, rounded(size), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (p == MAP_FAILED) {
    fail("mmap failed");
    return nullptr;
  }
  // Prevent accidental process core dumps from turning the no-spill path into a
  // dump.
  madvise(p, rounded(size), MADV_DONTDUMP);
  slot->clear();
  slot->pages.reset(new (std::nothrow) std::atomic<uint8_t>[rounded(size) / PAGE]);
  if (!slot->pages) {
    munmap(p, rounded(size));
    fail("page metadata allocation failed");
    return nullptr;
  }
  for (size_t i = 0; i < rounded(size) / PAGE; i++)
    slot->pages[i].store(3);
  slot->resident_pages.store(rounded(size) / PAGE);
  slot->data = p;
  slot->mapped = rounded(size);
  slot->recipe_length = size;
  slot->id = nextid++;
  slot->stats.length = size;
  index_insert(*slot);
  resident_managed.fetch_add(slot->mapped);
  observe_target();
  return p;
}
int af_capture(void *output, void *function, const uint64_t *args, size_t nargs, uint64_t *result) {
  if (!usable())
    return -1;
  auto *b = find(output);
  if (!b || !function || nargs > 6 || (!args && nargs))
    return fail("invalid capture arguments");
  if (b->state != RESIDENT)
    return fail("capture requires a fresh resident buffer");
  uint64_t start = now();
  std::vector<uint8_t> blob;
  try {
    Recorder recorder(reinterpret_cast<uint64_t>(output), b->stats.length);
    {
      QBDI::VM vm;
      uint8_t *stack = nullptr;
      if (!QBDI::allocateVirtualStack(vm.getGPRState(), 1 << 20, &stack))
        throw std::runtime_error("capture stack allocation failed");
      std::unique_ptr<uint8_t, void (*)(void *)> stack_owner(stack, QBDI::alignedFree);
      if (!instrument_module(vm, reinterpret_cast<uint64_t>(function)))
        throw std::runtime_error("cannot find native function module");
      instrument_memory_routines(vm);
      recorder.install(vm, reinterpret_cast<uint64_t>(function));
      QBDI::rword ret = 0;
      bool ok = vm.callA(&ret, reinterpret_cast<uint64_t>(function), nargs, args);
      if (result)
        *result = ret;
      b->stats.instructions = recorder.steps;
      b->stats.input_bytes = recorder.live_bytes;
      if (!ok)
        throw std::runtime_error("native function did not execute");
      recorder.finish(ret);
    }
    b->stats.instructions = recorder.steps;
    b->stats.input_bytes = recorder.live_bytes;
    if (!SHA256(static_cast<const uint8_t *>(output), b->stats.length, recorder.recipe.h.digest))
      throw std::runtime_error("output digest calculation failed");
    blob = encode(recorder.recipe);
    b->stats.recipe_bytes = blob.size();
    if (blob.size() >= b->stats.length)
      throw std::runtime_error("recipe is not smaller than output");
  } catch (const std::exception &e) {
    b->stats.capture_ns = now() - start;
    malloc_trim(0);
    return fail(e.what());
  }
  b->stats.capture_ns = now() - start;
  int rc = af_submit(output, blob.data(), blob.size(), b->stats.capture_ns);
  std::vector<uint8_t>().swap(blob);
  malloc_trim(0);
  return rc;
}
static int submit(void *output, const uint8_t *data, size_t size, uint64_t capture_ns,
                  bool region) {
  if (!usable())
    return -1;
  auto *b = find(output);
  if (!b || b->state != RESIDENT || !data || size < sizeof(Header) || size > MAX_BLOB)
    return fail("invalid recipe submission");
  Header h;
  std::memcpy(&h, data, sizeof h);
  auto address = reinterpret_cast<uint64_t>(output);
  if ((!region && (h.output != address || h.length != b->stats.length)) || h.output < address ||
      h.output - address > b->stats.length || !h.length ||
      h.length > b->stats.length - (h.output - address) || (h.output - address) % PAGE ||
      (h.length % PAGE && h.output + h.length != address + b->stats.length))
    return fail("recipe does not match allocation");
  auto *original = reinterpret_cast<uint8_t *>(h.output);
  if (size >= h.length)
    return fail("recipe is not smaller than output");
  b->stats.capture_ns = capture_ns;
  b->stats.input_bytes = h.input_bytes;
  b->stats.instructions = h.steps;
  b->stats.recipe_bytes = size;
  uint64_t start = now();
  bool streaming = shared_arena.data && !getenv("AF_DISABLE_STREAMING");
  Request q{streaming ? REGISTER_STREAM : REGISTER, b->id, size};
  Response r;
  if (channel_broken.load() || !write_all(channel, &q, sizeof q) ||
      !write_all(channel, data, size) || !read_all(channel, &r, sizeof r)) {
    channel_broken.store(true);
    syscall(SYS_shutdown, channel, SHUT_RDWR);
    return fail("validation worker disconnected");
  }
  bool equal = true;
  if (streaming) {
    size_t offset = 0;
    for (;;) {
      if (r.status == 2 && !r.size) {
        offset = 0;
        equal = true;
      } else if (r.status)
        return fail(std::string("validation rejected: ") + r.message);
      else if (!r.size) {
        if (offset != h.length)
          equal = false;
        break;
      } else {
        if (r.size > shared_arena.capacity || offset > h.length || r.size > h.length - offset) {
          channel_broken.store(true);
          syscall(SYS_shutdown, channel, SHUT_RDWR);
          return fail("invalid validation window length");
        }
        if (std::memcmp(shared_arena.data, original + offset, r.size))
          equal = false;
        offset += r.size;
        Request ack{STREAM_ACK, b->id, offset};
        if (!write_all(channel, &ack, sizeof ack)) {
          channel_broken.store(true);
          syscall(SYS_shutdown, channel, SHUT_RDWR);
          return fail("validation window acknowledgement failed");
        }
      }
      if (!read_all(channel, &r, sizeof r)) {
        channel_broken.store(true);
        syscall(SYS_shutdown, channel, SHUT_RDWR);
        return fail("validation stream interrupted");
      }
    }
  } else if (r.status)
    return fail(std::string("validation rejected: ") + r.message);
  if (!streaming && r.size != h.length) {
    channel_broken.store(true);
    syscall(SYS_shutdown, channel, SHUT_RDWR);
    return fail("invalid validation response length");
  }
  Registration registration;
  if (!read_all(channel, &registration, sizeof registration) || registration.backend > 1 ||
      (registration.page_bytes && registration.page_bytes != PAGE) ||
      (registration.page_bytes && !registration.backend)) {
    channel_broken.store(true);
    syscall(SYS_shutdown, channel, SHUT_RDWR);
    return fail("invalid registration response");
  }
  uint8_t chunk[65536];
  for (size_t off = 0; !streaming && off < r.size;) {
    size_t n = std::min(sizeof chunk, size_t(r.size - off));
    if (!read_all(channel, chunk, n)) {
      channel_broken.store(true);
      syscall(SYS_shutdown, channel, SHUT_RDWR);
      return fail("validation stream interrupted");
    }
    if (std::memcmp(chunk, original + off, n))
      equal = false;
    off += n;
  }
  b->stats.validation_ns = now() - start;
  if (!equal) {
    request(DROP, b->id, r);
    return fail("byte-for-byte validation failed");
  }
  b->stats.retained_bytes = registration.retained_bytes + b->mapped / PAGE;
  b->stats.page_bytes = registration.page_bytes;
  b->stats.backend = registration.backend;
  if (b->stats.retained_bytes >= rounded(h.length)) {
    request(DROP, b->id, r);
    return fail("retained reconstruction metadata exceeds reclaimable memory");
  }
  if (mprotect(original, rounded(h.length), PROT_READ)) {
    request(DROP, b->id, r);
    return fail("cannot protect validated output");
  }
  b->recipe_offset = h.output - address;
  b->recipe_length = h.length;
  b->state = SEALED;
  b->recipe_live = true;
  for (size_t i = b->recipe_offset / PAGE; i < (b->recipe_offset + rounded(h.length)) / PAGE; i++)
    b->pages[i].store(1);
  return 0;
}
int af_submit(void *output, const uint8_t *data, size_t size, uint64_t capture_ns) {
  return submit(output, data, size, capture_ns, false);
}
int af_submit_region(void *output, const uint8_t *data, size_t size, uint64_t capture_ns) {
  return submit(output, data, size, capture_ns, true);
}
size_t af_size(void *output) {
  auto *b = find(output);
  return b ? b->stats.length : 0;
}
static int prepare(const void *address, size_t size, bool writing) {
  ErrnoScope errno_scope;
  if (!size)
    return 0;
  uint64_t first = reinterpret_cast<uint64_t>(address);
  if (first > UINT64_MAX - size)
    return -1;
  size_t pos = after_address(first);
  if (pos && first - reinterpret_cast<uintptr_t>(allocation_index[pos - 1]->data) <
                 allocation_index[pos - 1]->mapped)
    pos--;
  for (; pos < allocation_count; pos++) {
    auto &b = *allocation_index[pos];
    uint64_t start = reinterpret_cast<uint64_t>(b.data);
    if (first + size <= start)
      break;
    if (getpid() != owner || syscall(SYS_gettid) != owner_thread)
      pager_failure();
    size_t begin = (std::max(first, start) - start) / PAGE;
    size_t end = rounded(std::min(first + size, start + b.mapped) - start) / PAGE;
    if (!materialize(b, begin, end, writing))
      pager_failure();
  }
  return 0;
}
int af_prepare_read(const void *address, size_t size) { return prepare(address, size, false); }
int af_prepare_write(void *address, size_t size) { return prepare(address, size, true); }

int af_evict(void *output) {
  if (!usable())
    return -1;
  auto *b = find(output);
  if (!b)
    return fail("unknown buffer");
  size_t first = b->recipe_offset / PAGE;
  size_t last = first + rounded(b->recipe_length) / PAGE;
  auto *region = static_cast<uint8_t *>(output) + b->recipe_offset;
  size_t removed = 0;
  for (size_t i = first; i < last; i++)
    removed += b->pages[i].load() != 0;
  if (b->state == EVICTED && !removed)
    return 0;
  if (b->state != SEALED && b->state != EVICTED)
    return fail(b->state == PINNED ? "buffer was modified; its recipe is retired"
                                   : "buffer has no validated recipe");
  if (mprotect(region, rounded(b->recipe_length), PROT_NONE))
    return fail("mprotect failed");
  if (madvise(region, rounded(b->recipe_length), MADV_DONTNEED)) {
    for (size_t i = first; i < last; i++)
      if (mprotect(static_cast<uint8_t *>(output) + i * PAGE, PAGE,
                   b->pages[i].load() ? PROT_READ : PROT_NONE))
        pager_failure();
    return fail("MADV_DONTNEED failed");
  }
  b->state = EVICTED;
  resident_managed.fetch_sub(removed * PAGE);
  b->resident_pages.fetch_sub(removed);
  for (size_t i = first; i < last; i++)
    b->pages[i].store(0);
  b->last_fault_end = SIZE_MAX;
  b->readahead = 1;
  b->stats.evictions++;
  return 0;
}
int af_set_resident_target(uint64_t bytes) {
  if (!usable())
    return -1;
  if (bytes > MAX_BUFFER * MAX_SLOTS)
    return fail("managed resident target exceeds supported address space");
  resident_target = bytes;
  peak_over_target.store(0);
  observe_target();
  return 0;
}
int af_manage(void *newly_sealed) {
  if (!usable())
    return -1;
  if (!resident_target) {
    int result = af_evict(newly_sealed);
    if (!result)
      automatic_evictions++;
    return result;
  }
  return collect(0, newly_sealed);
}
int af_get_residency_stats(af_residency_stats *stats) {
  if (!stats)
    return fail("missing residency statistics destination");
  *stats = {};
  stats->target = resident_target;
  stats->resident_bytes = managed_resident();
  for (const auto &b : buffers)
    if (b.data && b.state == SEALED && !b.stats.evictions && !b.fault_count.load())
      stats->reclaimable_bytes += rounded(b.recipe_length);
  if (resident_target && stats->resident_bytes > resident_target)
    stats->over_target_bytes = stats->resident_bytes - resident_target;
  stats->automatic_evictions = automatic_evictions;
  stats->restore_operations = restore_operations.load();
  stats->restored_bytes = restored_bytes.load();
  stats->peak_over_target_bytes = peak_over_target.load();
  return 0;
}
int af_materialize(void *output) {
  if (!usable())
    return -1;
  auto *b = find(output);
  if (!b)
    return fail("unknown buffer");
  if (!materialize(*b, 0, b->mapped / PAGE, false))
    pager_failure();
  return 0;
}
int af_get_stats(void *output, af_stats *stats) {
  auto *b = find(output);
  if (!b || !stats)
    return fail("unknown buffer");
  *stats = b->stats;
  stats->state = b->state.load();
  stats->faults = b->fault_count.load();
  stats->restore_ns = b->restore_time.load();
  stats->reconstructed_bytes = b->reconstructed.load();
  stats->full_restores = b->full_restores.load();
  return 0;
}
int af_resident_pages(void *output) {
  auto *b = find(output);
  if (!b)
    return fail("unknown buffer");
  std::vector<unsigned char> pages(b->mapped / PAGE);
  if (mincore(output, b->mapped, pages.data()))
    return fail("mincore failed");
  int n = 0;
  for (auto p : pages)
    n += (p & 1);
  return n;
}
int af_free(void *output) {
  if (!usable())
    return -1;
  auto *b = find(output);
  if (!b)
    return fail("unknown buffer");
  if (b->recipe_live) {
    Response r;
    request(DROP, b->id,
            r); // Local deallocation remains safe after worker death.
  }
  if (munmap(output, b->mapped))
    return fail("munmap failed");
  resident_managed.fetch_sub(b->resident_pages.load() * PAGE);
  index_remove(output);
  b->clear();
  return 0;
}
int af_shutdown() {
  if (channel < 0)
    return 0;
  if (owner != getpid())
    return fail("cannot shut down an inherited runtime");
  for (auto &b : buffers)
    if (b.data)
      return fail("close every buffer before shutting down Afterfree");
  Request q{QUIT, 0, 0};
  write_all(channel, &q, sizeof q);
  close(channel);
  channel = -1;
  shared_arena.reset();
  if (worker > 0) {
    int status;
    while (waitpid(worker, &status, 0) < 0 && errno == EINTR) {
    }
  }
  worker = -1;
  worker_procfs = -1;
  if (signal_stack) {
    sigaction(SIGSEGV, &previous, nullptr);
    sigaltstack(&old_stack, nullptr);
    munmap(signal_stack, 64 * 1024);
    signal_stack = nullptr;
  }
  return 0;
}
}
