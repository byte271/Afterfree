#include "afterfree.h"
#include "native_loop.hpp"
#include "recorder.hpp"
#include "template.hpp"
#include <QBDIPreload.h>
#include <cerrno>
#include <fcntl.h>
#include <limits.h>
#include <malloc.h>
#include <memory>
#include <openssl/sha.h>
#include <pthread.h>
#include <signal.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

extern "C" void *__libc_malloc(size_t);
extern "C" void *__libc_calloc(size_t, size_t);
extern "C" void *__libc_realloc(void *, size_t);
extern "C" void __libc_free(void *);
namespace {
bool active = false, busy = false, reported = false, modules_changed = false;
int report_fd = 2;
uint64_t threshold = 65536, pending_return = 0, capture_start = 0, attempts = 0, accepted = 0,
         rejected = 0;
uint64_t recipes_bytes = 0, produced_bytes = 0, faults = 0, evictions = 0;
uint64_t capture_ns_total = 0, validation_ns_total = 0, restore_ns_total = 0;
uint64_t discovery_callbacks = 0, capture_callbacks = 0;
bool template_reuse = false, templates_enabled = true;
uint64_t template_attempts = 0, template_hits = 0, template_misses = 0;
uint64_t native_recipes = 0, page_recipes = 0, retained_bytes_total = 0;
uint64_t fully_restored_buffers = 0, native_dispatches = 0, retry_skips = 0;
uint64_t caller_pc = 0;
bool native_dispatch = false;
uint64_t discovery_run_ns = 0, detailed_run_ns = 0, producer_run_ns = 0;
uint64_t finish_ns = 0, vm_setup_ns = 0, execution_start = 0;
uint64_t discovery_live = 0, detailed_live = 0, producer_live = 0, finish_live = 0, setup_live = 0;
bool native_loops_enabled = true;
uint64_t native_read_plans = 0, native_read_plan_bytes = 0;
uint64_t native_loop_runs = 0, native_loop_bytes = 0, native_loop_peak = 0;
std::map<uint64_t, std::unique_ptr<af::NativeLoop>> native_loops;
af::NativeLoop *retire_loop = nullptr;
std::vector<std::pair<uint64_t, uint64_t>> dispatch_ranges;
struct Retry {
  uint64_t entry = 0, size = 0;
  unsigned failures = 0, remaining = 0;
};
Retry retries[256];
Retry &retry(uint64_t entry, uint64_t size) {
  auto &r = retries[((entry >> 4) ^ size ^ (size >> 12)) % 256];
  if (r.entry != entry || r.size != size)
    r = {entry, size, 0, 0};
  return r;
}
void account(void *p) {
  af_stats stats{};
  if (!af_get_stats(p, &stats)) {
    faults += stats.faults;
    evictions += stats.evictions;
    restore_ns_total += stats.restore_ns;
    fully_restored_buffers += stats.full_restores;
  }
}
af::TemplateCache templates;
std::unique_ptr<af::Recorder> capture;
struct Guard {
  bool old;
  Guard() : old(busy) { busy = true; }
  ~Guard() { busy = old; }
};
uint64_t now() {
  timespec t;
  clock_gettime(CLOCK_MONOTONIC, &t);
  return uint64_t(t.tv_sec) * 1000000000 + t.tv_nsec;
}
void line(const char *event, const char *reason, uint64_t size = 0, uint64_t recipe = 0) {
  // Reasons are runtime-generated tokens; escape quotes/backslashes regardless.
  char escaped[512]{};
  size_t n = 0;
  for (auto *p = reason; *p && n + 2 < sizeof escaped; p++) {
    if (*p == '"' || *p == '\\')
      escaped[n++] = '\\';
    if (static_cast<unsigned char>(*p) >= 32)
      escaped[n++] = *p;
  }
  char text[1024];
  int len = snprintf(text, sizeof text,
                     "{\"event\":\"%s\",\"reason\":\"%s\",\"output_bytes\":%lu,"
                     "\"recipe_bytes\":%lu}\n",
                     event, escaped, size, recipe);
  if (len > 0) {
    ssize_t ignored = syscall(SYS_write, report_fd, text, std::min(size_t(len), sizeof text - 1));
    (void)ignored;
  }
}
void prepare_vectors(const iovec *vectors, int count, bool writing) {
  if (count <= 0 || count > IOV_MAX)
    return;
  af::ErrnoScope errno_scope;
  if (af_prepare_read(vectors, count * sizeof(iovec)))
    return;
  iovec copy[IOV_MAX];
  af::SnapshotReader reader;
  // Leave invalid vectors to the kernel so its error precedence is preserved.
  if (!reader.copy(reinterpret_cast<uint64_t>(vectors), copy, count * sizeof(iovec)))
    return;
  for (int i = 0; i < count; i++) {
    int result = writing ? af_prepare_write(copy[i].iov_base, copy[i].iov_len)
                         : af_prepare_read(copy[i].iov_base, copy[i].iov_len);
    if (result)
      return;
  }
}
void finish(QBDI::GPRState *g) {
  af::Timer timer(finish_ns, &finish_live);
  auto output = reinterpret_cast<void *>(capture->recipe.h.output);
  uint64_t size = capture->recipe.h.length;
  try {
    if (af_size(output) != size)
      throw std::runtime_error("allocation changed during producer");
    if (template_reuse) {
      if (!capture->rejection.empty())
        throw std::runtime_error(capture->rejection);
      capture->recipe.h.result = g->rax;
    } else {
      capture->finish(g->rax, true);
    }
    size = capture->recipe.h.length;
    if (!SHA256(reinterpret_cast<const uint8_t *>(capture->recipe.h.output), size,
                capture->recipe.h.digest))
      throw std::runtime_error("output digest calculation failed");
    auto blob = af::encode(capture->recipe);
    if (af_submit_region(output, blob.data(), blob.size(), now() - capture_start))
      throw std::runtime_error(af_error());
    af_stats measured{};
    if (!af_get_stats(output, &measured)) {
      capture_ns_total += measured.capture_ns;
      validation_ns_total += measured.validation_ns;
    }
    native_recipes += measured.backend == 1;
    page_recipes += measured.page_bytes != 0;
    retained_bytes_total += measured.retained_bytes;
    if (af_manage(output))
      throw std::runtime_error(af_error());
    accepted++;
    retry(capture->entry_target, size) = {capture->entry_target, size, 0, 0};
    if (template_reuse)
      template_hits++;
    else if (templates_enabled && size == af_size(output)) {
      try {
        templates.put(capture->recipe, measured.backend == 1);
      } catch (const std::exception &) {
        // Optional caching cannot revoke an already committed, exact recipe.
      }
    }
    recipes_bytes += blob.size();
    produced_bytes += size;
    af_stats final_stats{};
    af_get_stats(output, &final_stats);
    line("sealed",
         final_stats.state == 2 ? "exact replay validated; pages discarded"
                                : "exact replay validated; retained by residency policy",
         size, blob.size());
  } catch (const std::exception &e) {
    if (template_reuse) {
      template_misses++;
      templates.erase(capture->recipe.h.entry);
    }
    auto &r = retry(capture->entry_target, size);
    r.failures = std::min(r.failures + 1, 6U);
    r.remaining = (1U << r.failures) - 1;
    rejected++;
    line("rejected", e.what(), size);
  }
  capture.reset();
  template_reuse = false;
  native_dispatch = false;
  dispatch_ranges.clear();
  malloc_trim(0);
}
std::vector<std::pair<uint64_t, uint64_t>> instrumented;
uint64_t capture_rsp = 0;
QBDI::VMAction unsupported(QBDI::VMInstanceRef, QBDI::GPRState *, QBDI::FPRState *, void *) {
  line("fatal", "EVEX/AVX-512 execution is unsupported; select compatible CPU routines");
  _Exit(194);
}
QBDI::VMAction enter_candidate(QBDI::VMInstanceRef vm, QBDI::GPRState *g, QBDI::FPRState *f,
                               void *) {
  af::ErrnoScope errno_scope;
  Guard guard;
  discovery_callbacks++;
  if (capture)
    return QBDI::CONTINUE;
  if (modules_changed)
    return QBDI::STOP;
  auto *a = vm->getInstAnalysis(QBDI::ANALYSIS_INSTRUCTION);
  uint64_t ret = a->address + a->instSize;
  if (*reinterpret_cast<const uint64_t *>(g->rsp) != ret)
    return QBDI::CONTINUE;
  bool inside = false;
  for (auto range : instrumented)
    if (g->rip >= range.first && g->rip < range.second)
      inside = true;
  if (!inside)
    return QBDI::CONTINUE;
  uint64_t args[] = {g->rdi, g->rsi, g->rdx, g->rcx, g->r8, g->r9};
  for (auto arg : args) {
    void *p = reinterpret_cast<void *>(arg);
    size_t size = af_size(p);
    af_stats stats{};
    if (!size || af_get_stats(p, &stats) || stats.state != 0)
      continue;
    auto &backoff = retry(g->rip, size);
    if (backoff.remaining) {
      backoff.remaining--;
      retry_skips++;
      continue;
    }
    capture = std::make_unique<af::Recorder>(arg, size);
    capture->entry_target = g->rip;
    capture->stop_on_rejection = true;
    caller_pc = a->address;
    capture->busy_flag = &busy;
    capture_start = now();
    capture_rsp = g->rsp;
    pending_return = ret;
    attempts++;
    if (templates_enabled)
      if (auto *model = templates.get(g->rip)) {
        template_attempts++;
        try {
          template_reuse = model->instantiate(*capture, g, f);
          native_dispatch = template_reuse && model->native_dispatch && a->instSize == 5 &&
                            *reinterpret_cast<const uint8_t *>(caller_pc) == 0xe8;
        } catch (const std::exception &) {
          template_reuse = false;
        }
      }
    return QBDI::STOP;
  }
  return QBDI::CONTINUE;
}
std::vector<QBDI::InstrRuleDataCBK> discovery_rule(QBDI::VMInstanceRef, const QBDI::InstAnalysis *a,
                                                   void *) {
  af::ErrnoScope errno_scope;
  Guard guard;
  if (*reinterpret_cast<const uint8_t *>(a->address) == 0x62)
    return {{QBDI::PREINST, unsupported, nullptr}};
  if (a->isCall)
    return {{QBDI::POSTINST, enter_candidate, nullptr}};
  if (native_loops_enabled && a->isBranch && !a->isCall && native_loops.size() < 128) {
    auto found = native_loops.find(a->address);
    if (found == native_loops.end()) {
      ZydisDecoder decoder;
      ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
      ZydisDecodedInstruction instruction{};
      ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT]{};
      if (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, reinterpret_cast<const void *>(a->address),
                                              a->instSize, &instruction, operands)) &&
          instruction.meta.category == ZYDIS_CATEGORY_COND_BR &&
          operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE && operands[0].imm.is_relative &&
          operands[0].imm.value.s < 0 && operands[0].imm.value.s >= -256) {
        auto &loop = native_loops[a->address];
        try {
          loop =
              std::make_unique<af::NativeLoop>(a->address + a->instSize + operands[0].imm.value.s,
                                               a->address, a->address + a->instSize);
          native_loop_bytes += loop->retained();
          native_loop_peak = std::max(native_loop_peak, native_loop_bytes);
        } catch (const std::exception &) {
        }
        found = native_loops.find(a->address);
      }
    }
    if (found != native_loops.end() && found->second && !found->second->disabled)
      return {{QBDI::PREINST,
               [](QBDI::VMInstanceRef vm, QBDI::GPRState *g, QBDI::FPRState *f, void *data) {
                 // This rule belongs only to the discovery VM. Template execution and
                 // already-rejected producers also execute original code here; the
                 // detailed recorder always uses its own VM without this rule.
                 af::ErrnoScope errno_scope;
                 Guard guard;
                 auto *loop = static_cast<af::NativeLoop *>(data);
                 if (!loop->continues(g->eflags)) {
                   loop->disabled = true;
                   retire_loop = loop;
                   return QBDI::STOP;
                 }
                 // Pay code revalidation and native dispatch only for a sustained loop.
                 // Short trips retain the normal VM path and never hide program work.
                 if (++loop->streak < 32)
                   return QBDI::CONTINUE;
                 loop->streak = 0;
                 auto guest_errno = vm->getErrno();
                 if (!loop->run(g, f, guest_errno))
                   return QBDI::CONTINUE;
                 vm->setErrno(guest_errno);
                 native_loop_runs++;
                 native_read_plans += loop->read_bytes != 0;
                 native_read_plan_bytes += loop->read_bytes;
                 if (loop->execution_ns < loop->guard_ns) {
                   loop->disabled = true;
                   retire_loop = loop;
                   return QBDI::STOP;
                 }
                 return QBDI::BREAK_TO_VM;
               },
               found->second.get()}};
  }
  return {};
}
void run_discovery(QBDI::VM &vm, uint64_t start, uint64_t stop) {
  for (;;) {
    vm.run(start, stop);
    if (!retire_loop)
      return;
    Guard guard;
    auto state = *vm.getGPRState();
    auto floating = *vm.getFPRState();
    auto saved_errno = vm.getErrno();
    auto [first, last] = retire_loop->range();
    native_loop_bytes -= retire_loop->retained();
    retire_loop->retire();
    native_loop_bytes += retire_loop->retained();
    retire_loop = nullptr;
    // Rebuild the loop without its callback only after leaving the VM.
    vm.clearCache(first, last);
    vm.setGPRState(&state);
    vm.setFPRState(&floating);
    vm.setErrno(saved_errno);
    start = state.rip;
  }
}
std::vector<QBDI::InstrRuleDataCBK> isa_guard(QBDI::VMInstanceRef, const QBDI::InstAnalysis *a,
                                              void *) {
  if (*reinterpret_cast<const uint8_t *>(a->address) == 0x62)
    return {{QBDI::PREINST, unsupported, nullptr}};
  return {};
}
void instrument(QBDI::VM &vm) {
  if (!instrumented.empty()) {
    for (auto range : instrumented)
      vm.addInstrumentedRange(range.first, range.second);
    return;
  }
  FILE *f = fopen("/proc/self/maps", "r");
  if (!f)
    return;
  char buf[8192];
  while (fgets(buf, sizeof buf, f)) {
    unsigned long lo, hi;
    char perm[8];
    int used = 0;
    if (sscanf(buf, "%lx-%lx %7s %*s %*s %*s %n", &lo, &hi, perm, &used) < 3 || perm[2] != 'x')
      continue;
    const char *name = buf + used;
    bool skip = false;
    for (const char *s : {"libc.so", "libm.so", "libpthread", "libstdc++", "libgcc_s", "ld-linux",
                          "libQBDI", "libafterfree.so", "libafterfree-preload", "libunicorn",
                          "libcrypto", "[vdso]", "[vsyscall]"})
      if (strstr(name, s))
        skip = true;
    if (!skip && *name == '/')
      instrumented.emplace_back(lo, hi);
  }
  fclose(f);
  for (auto range : af::memory_routine_extents())
    instrumented.push_back(range);
  for (auto range : instrumented)
    vm.addInstrumentedRange(range.first, range.second);
}
void prepare_dispatch() {
  dispatch_ranges.clear();
  if (!native_dispatch)
    return;
  struct Mapping {
    uint64_t low, high;
    std::string name;
  };
  std::vector<Mapping> maps;
  FILE *file = fopen("/proc/self/maps", "r");
  if (!file)
    return;
  char line[8192], permissions[8], name[4096];
  unsigned long low, high;
  std::string caller_module;
  while (fgets(line, sizeof line, file)) {
    if (sscanf(line, "%lx-%lx %7s %*s %*s %*s %4095[^\n]", &low, &high, permissions, name) != 4 ||
        permissions[2] != 'x' || name[0] != '/')
      continue;
    maps.push_back({low, high, name});
    if (caller_pc >= low && caller_pc < high)
      caller_module = name;
  }
  fclose(file);
  if (caller_module.empty())
    return;
  std::set<std::string> selected;
  for (auto &mapping : maps)
    if (mapping.name != caller_module &&
        std::find(instrumented.begin(), instrumented.end(),
                  std::make_pair(mapping.low, mapping.high)) != instrumented.end())
      for (auto &instruction : capture->recipe.code)
        if (instruction.address >= mapping.low && instruction.address < mapping.high)
          selected.insert(mapping.name);
  for (auto &mapping : maps)
    if (selected.count(mapping.name))
      dispatch_ranges.emplace_back(mapping.low, mapping.high);
}
} // namespace
extern "C" {
QBDIPRELOAD_INIT;
int sigaction(int number, const struct sigaction *action, struct sigaction *previous) {
  using Fn = int (*)(int, const struct sigaction *, struct sigaction *);
  static auto original = reinterpret_cast<Fn>(dlsym(RTLD_NEXT, "sigaction"));
  if (active && !busy && number == SIGSEGV && action && !af_handling_fault()) {
    line("fatal", "application replacement of the SIGSEGV pager is unsupported");
    _Exit(196);
  }
  return original(number, action, previous);
}
using SignalHandler = void (*)(int);
SignalHandler signal(int number, SignalHandler handler) {
  using Fn = SignalHandler (*)(int, SignalHandler);
  static auto original = reinterpret_cast<Fn>(dlsym(RTLD_NEXT, "signal"));
  if (active && !busy && number == SIGSEGV && !af_handling_fault()) {
    line("fatal", "application replacement of the SIGSEGV pager is unsupported");
    _Exit(196);
  }
  return original(number, handler);
}
void *malloc(size_t size) {
  if (!active || busy || size < threshold || size > af::MAX_BUFFER)
    return __libc_malloc(size);
  Guard guard;
  void *p = af_alloc(size);
  return p ? p : __libc_malloc(size);
}
void *calloc(size_t n, size_t size) {
  if (size && n > SIZE_MAX / size) {
    errno = ENOMEM;
    return nullptr;
  }
  size_t bytes = n * size;
  if (!active || busy || bytes < threshold || bytes > af::MAX_BUFFER)
    return __libc_calloc(n, size);
  Guard guard;
  void *p = af_alloc(bytes);
  return p ? p : __libc_calloc(n, size);
}
int posix_memalign(void **out, size_t alignment, size_t size) {
  using Fn = int (*)(void **, size_t, size_t);
  static auto original = reinterpret_cast<Fn>(dlsym(RTLD_NEXT, "posix_memalign"));
  if (!active || busy || size < threshold || size > af::MAX_BUFFER || alignment < sizeof(void *) ||
      alignment > af::PAGE || (alignment & (alignment - 1)))
    return original(out, alignment, size);
  af::ErrnoScope errno_scope;
  Guard guard;
  if (void *p = af_alloc(size)) {
    *out = p;
    return 0;
  }
  return original(out, alignment, size);
}
void *aligned_alloc(size_t alignment, size_t size) {
  using Fn = void *(*)(size_t, size_t);
  static auto original = reinterpret_cast<Fn>(dlsym(RTLD_NEXT, "aligned_alloc"));
  if (!active || busy || size < threshold || size > af::MAX_BUFFER || !alignment ||
      alignment > af::PAGE || (alignment & (alignment - 1)))
    return original(alignment, size);
  Guard guard;
  void *p = af_alloc(size);
  return p ? p : original(alignment, size);
}
void free(void *p) {
  af::ErrnoScope errno_scope;
  if (!p)
    return;
  if (!active || !af_size(p)) {
    __libc_free(p);
    return;
  }
  Guard guard;
  account(p);
  if (capture && capture->recipe.h.output == reinterpret_cast<uint64_t>(p))
    capture->reject("allocation freed during producer");
  if (af_free(p)) {
    line("fatal", af_error());
    _Exit(191);
  }
}
void *realloc(void *p, size_t size) {
  if (!active || !p || !af_size(p))
    return __libc_realloc(p, size);
  if (!size) {
    free(p);
    return nullptr;
  }
  Guard guard;
  size_t old = af_size(p);
  void *result = size >= threshold && size <= af::MAX_BUFFER ? af_alloc(size) : __libc_malloc(size);
  if (!result)
    result = __libc_malloc(size);
  if (!result) {
    errno = ENOMEM;
    return nullptr;
  }
  if (af_prepare_read(p, std::min(old, size))) {
    if (af_size(result))
      af_free(result);
    else
      __libc_free(result);
    errno = EFAULT;
    return nullptr;
  }
  memcpy(result, p, std::min(old, size));
  account(p);
  if (capture && capture->recipe.h.output == reinterpret_cast<uint64_t>(p))
    capture->reject("allocation resized during producer");
  if (af_free(p)) {
    line("fatal", af_error());
    _Exit(191);
  }
  return result;
}
void *dlopen(const char *path, int flags) {
  using Fn = void *(*)(const char *, int);
  static auto original = reinterpret_cast<Fn>(dlsym(RTLD_NEXT, "dlopen"));
  void *result = original(path, flags);
  if (active && !busy && result)
    modules_changed = true;
  return result;
}
int dlclose(void *handle) {
  using Fn = int (*)(void *);
  static auto original = reinterpret_cast<Fn>(dlsym(RTLD_NEXT, "dlclose"));
  int result = original(handle);
  if (active && !busy && !result)
    modules_changed = true;
  return result;
}
size_t malloc_usable_size(void *p) {
  if (active) {
    Guard guard;
    auto size = af_size(p);
    if (size)
      return size;
  }
  using Fn = size_t (*)(void *);
  static auto original = reinterpret_cast<Fn>(dlsym(RTLD_NEXT, "malloc_usable_size"));
  return original ? original(p) : 0;
}
ssize_t write(int fd, const void *p, size_t n) {
  if (active && !busy) {
    Guard guard;
    if (af_prepare_read(p, n)) {
      errno = EFAULT;
      return -1;
    }
  }
  return syscall(SYS_write, fd, p, n);
}
ssize_t pwrite(int fd, const void *p, size_t n, off_t offset) {
  if (active && !busy) {
    Guard guard;
    if (af_prepare_read(p, n)) {
      errno = EFAULT;
      return -1;
    }
  }
  return syscall(SYS_pwrite64, fd, p, n, offset);
}
ssize_t writev(int fd, const iovec *v, int n) {
  if (active && !busy) {
    Guard guard;
    prepare_vectors(v, n, false);
  }
  return syscall(SYS_writev, fd, v, n);
}
ssize_t read(int fd, void *p, size_t n) {
  if (active && !busy) {
    Guard guard;
    if (af_prepare_write(p, n)) {
      errno = EFAULT;
      return -1;
    }
  }
  return syscall(SYS_read, fd, p, n);
}
ssize_t pread(int fd, void *p, size_t n, off_t offset) {
  if (active && !busy) {
    Guard guard;
    if (af_prepare_write(p, n)) {
      errno = EFAULT;
      return -1;
    }
  }
  return syscall(SYS_pread64, fd, p, n, offset);
}
ssize_t readv(int fd, const iovec *v, int n) {
  if (active && !busy) {
    Guard guard;
    prepare_vectors(v, n, true);
  }
  return syscall(SYS_readv, fd, v, n);
}
size_t fwrite(const void *p, size_t size, size_t n, FILE *stream) {
  using Fn = size_t (*)(const void *, size_t, size_t, FILE *);
  static auto original = reinterpret_cast<Fn>(dlsym(RTLD_NEXT, "fwrite"));
  if (size && n > SIZE_MAX / size) {
    errno = EOVERFLOW;
    return 0;
  }
  if (active && !busy) {
    Guard guard;
    if (af_prepare_read(p, size * n)) {
      errno = EFAULT;
      return 0;
    }
  }
  return original(p, size, n, stream);
}
size_t fread(void *p, size_t size, size_t n, FILE *stream) {
  using Fn = size_t (*)(void *, size_t, size_t, FILE *);
  static auto original = reinterpret_cast<Fn>(dlsym(RTLD_NEXT, "fread"));
  if (size && n > SIZE_MAX / size) {
    errno = EOVERFLOW;
    return 0;
  }
  if (active && !busy) {
    Guard guard;
    if (af_prepare_write(p, size * n)) {
      errno = EFAULT;
      return 0;
    }
  }
  return original(p, size, n, stream);
}
int pthread_create(pthread_t *thread, const pthread_attr_t *attrs, void *(*start)(void *),
                   void *arg) {
  if (active && !busy) {
    Guard guard;
    line("fatal", "thread creation is unsupported");
    _Exit(193);
  }
  using Fn = int (*)(pthread_t *, const pthread_attr_t *, void *(*)(void *), void *);
  static auto original = reinterpret_cast<Fn>(dlsym(RTLD_NEXT, "pthread_create"));
  return original(thread, attrs, start, arg);
}
int qbdipreload_on_start(void *) { return QBDIPRELOAD_NOT_HANDLED; }
int qbdipreload_on_premain(void *, void *) { return QBDIPRELOAD_NOT_HANDLED; }
int qbdipreload_on_main(int, char **) {
  Guard guard;
  templates_enabled = getenv("AF_DISABLE_TEMPLATES") == nullptr;
  native_loops_enabled = getenv("AF_DISABLE_NATIVE_LOOPS") == nullptr;
  const char *worker = getenv("AF_WORKER");
  const char *report = getenv("AF_REPORT");
  if (report) {
    report_fd = open(report, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (report_fd < 0)
      _Exit(192);
  }
  if (!worker || af_init(worker)) {
    line("fatal", af_error());
    _Exit(192);
  }
  if (const char *target = getenv("AF_RESIDENT_TARGET")) {
    char *end = nullptr;
    errno = 0;
    auto bytes = strtoull(target, &end, 10);
    if (errno || !*target || *target == '-' || !end || *end || !bytes ||
        af_set_resident_target(bytes)) {
      line("fatal", "invalid managed resident target");
      _Exit(192);
    }
  }
  char procfs[64]{};
  auto len = readlink("/proc/self", procfs, sizeof procfs - 1);
  if (len > 0) {
    char event[192];
    int size = snprintf(event, sizeof event,
                        "{\"event\":\"process\",\"procfs_pid\":%s,\"worker_procfs_pid\":%d}\n",
                        procfs, af_worker_procfs_pid());
    ssize_t ignored = syscall(SYS_write, report_fd, event, size);
    (void)ignored;
  }
  active = true;
  return QBDIPRELOAD_NOT_HANDLED;
}
int qbdipreload_on_run(QBDI::VMInstanceRef vm, QBDI::rword start, QBDI::rword stop) {
  execution_start = now();
  {
    af::Timer timer(vm_setup_ns, &setup_live);
    Guard guard;
    instrument(*vm);
    vm->addInstrRule(discovery_rule, QBDI::ANALYSIS_INSTRUCTION, nullptr);
  }
  uint64_t pc = start;
  for (;;) {
    {
      af::Timer timer(discovery_run_ns, &discovery_live);
      run_discovery(*vm, pc, stop);
    }
    if (!capture) {
      if (!modules_changed) {
        if (vm->getGPRState()->rip != stop) {
          line("fatal", "execution stopped before the program return boundary");
          _Exit(195);
        }
        break;
      }
      Guard guard;
      pc = vm->getGPRState()->rip;
      vm->removeAllInstrumentedRanges();
      vm->clearAllCache();
      native_loops.clear();
      native_loop_bytes = 0;
      instrumented.clear();
      instrument(*vm);
      modules_changed = false;
      continue;
    }
    QBDI::GPRState result;
    QBDI::FPRState floating;
    uint32_t result_errno = 0;
    if (template_reuse) {
      {
        Guard guard;
        prepare_dispatch();
        if (!dispatch_ranges.empty()) {
          // Re-execute only a direct CALL, whose sole architectural effect was
          // pushing this same return address. No producer instruction ran yet.
          // Whole producer modules are excluded; QBDI's documented broker
          // returns to the fully instrumented caller. Never split a function.
          for (auto range : dispatch_ranges)
            vm->removeInstrumentedRange(range.first, range.second);
          vm->getGPRState()->rip = caller_pc;
          vm->getGPRState()->rsp += 8;
          native_dispatches++;
        }
      }
      {
        af::Timer timer(producer_run_ns, &producer_live);
        run_discovery(*vm, vm->getGPRState()->rip, pending_return);
      }
      result = *vm->getGPRState();
      floating = *vm->getFPRState();
      result_errno = vm->getErrno();
      {
        Guard guard;
        for (auto range : dispatch_ranges)
          vm->addInstrumentedRange(range.first, range.second);
      }
    } else {
      std::unique_ptr<QBDI::VM> detailed;
      {
        Guard guard;
        af::Timer timer(vm_setup_ns, &setup_live);
        detailed = std::make_unique<QBDI::VM>();
        detailed->setGPRState(vm->getGPRState());
        detailed->setFPRState(vm->getFPRState());
        detailed->setErrno(vm->getErrno());
        instrument(*detailed);
        capture->install(*detailed, vm->getGPRState()->rip);
        detailed->addInstrRule(isa_guard, QBDI::ANALYSIS_INSTRUCTION, nullptr);
      }
      {
        af::Timer timer(detailed_run_ns, &detailed_live);
        detailed->run(vm->getGPRState()->rip, pending_return);
      }
      // STOP only occurs at BASIC_BLOCK_ENTRY, before that block executes.
      // Resume the original call once, with discovery instrumentation only.
      if (!capture->rejection.empty() && detailed->getGPRState()->rip != pending_return) {
        vm->setGPRState(detailed->getGPRState());
        vm->setFPRState(detailed->getFPRState());
        vm->setErrno(detailed->getErrno());
        {
          af::Timer timer(producer_run_ns, &producer_live);
          run_discovery(*vm, vm->getGPRState()->rip, pending_return);
        }
        detailed->setGPRState(vm->getGPRState());
        detailed->setFPRState(vm->getFPRState());
        detailed->setErrno(vm->getErrno());
      }
      {
        Guard guard;
        result = *detailed->getGPRState();
        floating = *detailed->getFPRState();
        result_errno = detailed->getErrno();
        detailed.reset();
      }
    }
    {
      Guard guard;
      if (result.rip != pending_return || result.rsp != capture_rsp + 8) {
        line("fatal", "producer did not return to its original call boundary");
        _Exit(195);
      }
      capture_callbacks +=
          capture->block_callbacks + capture->read_callbacks + capture->write_callbacks;
      finish(&result);
      vm->setGPRState(&result);
      vm->setFPRState(&floating);
      vm->setErrno(result_errno);
      pc = result.rip;
      pending_return = 0;
    }
  }
  return QBDIPRELOAD_NO_ERROR;
}
int qbdipreload_on_exit(int status) {
  Guard guard;
  if (active && !reported) {
    reported = true;
    af_worker_profile profile{};
    bool profiled = af_get_worker_profile(&profile) == 0;
    rusage usage{};
    getrusage(RUSAGE_SELF, &usage);
    char timing[2048];
    uint64_t sample = now();
    auto phase = [&](uint64_t total, uint64_t live) { return total + (live ? sample - live : 0); };
    int timing_size = snprintf(
        timing, sizeof timing,
        "{\"event\":\"profile\",\"execution_ns\":%lu,\"discovery_run_ns\":%lu,"
        "\"detailed_run_ns\":%lu,\"producer_run_ns\":%lu,\"finish_ns\":%lu,\"vm_setup_ns\":%lu,"
        "\"worker_profile_available\":%s,\"worker_decode_ns\":%lu,\"worker_compile_ns\":%lu,"
        "\"worker_validate_ns\":%lu,\"worker_restore_ns\":%lu,\"worker_send_ns\":%lu,"
        "\"worker_arena_ns\":%lu,\"worker_trim_ns\":%lu,\"worker_requests\":%lu,"
        "\"worker_user_ns\":%lu,\"worker_system_ns\":%lu,\"app_user_ns\":%lu,\"app_system_ns\":%lu,"
        "\"worker_jit_ns\":%lu,\"worker_digest_ns\":%lu,"
        "\"native_read_plans\":%lu,\"native_read_plan_bytes\":%lu,"
        "\"native_loop_runs\":%lu,\"native_loop_peak_bytes\":%lu}\n",
        sample - execution_start, phase(discovery_run_ns, discovery_live),
        phase(detailed_run_ns, detailed_live), phase(producer_run_ns, producer_live),
        phase(finish_ns, finish_live), phase(vm_setup_ns, setup_live), profiled ? "true" : "false",
        profile.decode_ns, profile.compile_ns, profile.validate_ns, profile.restore_ns,
        profile.send_ns, profile.arena_ns, profile.trim_ns, profile.requests, profile.user_ns,
        profile.system_ns,
        uint64_t(usage.ru_utime.tv_sec) * 1000000000 + usage.ru_utime.tv_usec * 1000,
        uint64_t(usage.ru_stime.tv_sec) * 1000000000 + usage.ru_stime.tv_usec * 1000,
        profile.jit_ns, profile.digest_ns, native_read_plans, native_read_plan_bytes,
        native_loop_runs, native_loop_peak);
    ssize_t timing_ignored = syscall(SYS_write, report_fd, timing, timing_size);
    (void)timing_ignored;
    af_residency_stats policy{};
    af_get_residency_stats(&policy);
    char buf[4096];
    int n =
        snprintf(buf, sizeof buf,
                 "{\"event\":\"summary\",\"exit_status\":%d,\"attempts\":%"
                 "lu,\"accepted\":%lu,\"rejected\":%lu,\"output_bytes\":%"
                 "lu,\"recipe_bytes\":%lu,\"freed_buffer_faults\":%lu,"
                 "\"freed_buffer_evictions\":%lu,\"capture_ns\":%lu,"
                 "\"validation_ns\":%lu,\"restore_ns\":%lu,"
                 "\"discovery_callbacks\":%lu,\"capture_callbacks\":%lu,"
                 "\"template_attempts\":%lu,\"template_hits\":%lu,"
                 "\"template_validation_misses\":%lu,\"template_bytes_peak\":%zu,"
                 "\"managed_resident_target\":%lu,\"automatic_evictions\":%lu,"
                 "\"restore_operations\":%lu,\"restored_bytes\":%lu,"
                 "\"managed_over_target_bytes_at_exit\":%lu,"
                 "\"managed_peak_over_target_bytes\":%lu,"
                 "\"native_recipes\":%lu,\"page_recipes\":%lu,\"retained_bytes_total\":%lu,"
                 "\"fully_restored_buffers\":%lu,\"native_dispatches\":%lu,\"retry_skips\":%lu,"
                 "\"worker_kernel_peak_rss_bytes\":%lu}\n",
                 status, attempts, accepted, rejected, produced_bytes, recipes_bytes, faults,
                 evictions, capture_ns_total, validation_ns_total, restore_ns_total,
                 discovery_callbacks, capture_callbacks, template_attempts, template_hits,
                 template_misses, templates.peak_bytes, policy.target, policy.automatic_evictions,
                 policy.restore_operations, policy.restored_bytes, policy.over_target_bytes,
                 policy.peak_over_target_bytes, native_recipes, page_recipes, retained_bytes_total,
                 fully_restored_buffers, native_dispatches, retry_skips, af_worker_peak_rss());
    ssize_t ignored = syscall(SYS_write, report_fd, buf, n);
    (void)ignored;
  }
  return QBDIPRELOAD_NO_ERROR;
}
}
