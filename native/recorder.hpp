#pragma once
#include "byte_mask.hpp"
#include "common.hpp"
#include "native_loop.hpp"
#include "unwind.hpp"
#include <QBDI.h>
#include <asm/prctl.h>
#include <dlfcn.h>
#include <map>
#include <memory>
#include <set>
#include <sys/syscall.h>
#include <unordered_map>

namespace af {

struct ObservedPage {
  ByteMask written, input;
  std::unique_ptr<std::array<uint8_t, PAGE>> data;
};
class Recorder {
public:
  struct Plan {
    Recorder *owner = nullptr;
    Instruction instruction;
    uint64_t segment = 0;
    std::string rejection;
  };
  struct BusyScope {
    bool *flag;
    bool previous;
    explicit BusyScope(bool *flag) : flag(flag), previous(flag && *flag) {
      if (flag)
        *flag = true;
    }
    ~BusyScope() {
      if (flag)
        *flag = previous;
    }
  };
  Recipe recipe;
  std::string rejection;
  std::map<uint64_t, ObservedPage> pages;
  std::map<uint64_t, Instruction> code;
  uint64_t live_bytes = 0, steps = 0;
  bool began = false, stop_on_rejection = false;
  uint64_t output_frontier = 0, last_store_end = 0;
  uint64_t cached_base = UINT64_MAX;
  ObservedPage *cached = nullptr;
  bool *busy_flag = nullptr;
  uint64_t entry_target = 0;
  std::map<uint64_t, Plan> plans;
  std::map<std::pair<uint64_t, uint64_t>, uint64_t> block_counts;
  uint64_t block_callbacks = 0, read_callbacks = 0, write_callbacks = 0;
  uint64_t native_loop_runs = 0;
  struct InlineLoop {
    Recorder *owner;
    std::unique_ptr<NativeLoop> code;
  };
  std::map<uint64_t, InlineLoop> loops;
  Recorder(uint64_t output, uint64_t size) {
    recipe.h.output = output;
    output_frontier = output;
    recipe.h.length = size;
    if (syscall(SYS_arch_prctl, ARCH_GET_FS, &recipe.h.fs_base) ||
        syscall(SYS_arch_prctl, ARCH_GET_GS, &recipe.h.gs_base))
      reject("cannot capture TLS segment bases");
  }
  void reject(const std::string &why) {
    if (rejection.empty())
      rejection = why;
  }
  ObservedPage &page(uint64_t addr) {
    auto p = base(addr);
    if (p == cached_base)
      return *cached;
    if (pages.size() > 262144)
      throw std::runtime_error("capture page limit exceeded");
    cached_base = p;
    cached = &pages[p];
    return *cached;
  }
  void read(uint64_t addr, size_t n) {
    if (addr < PAGE || n > PAGE * 16 || addr > UINT64_MAX - n) {
      reject("unresolved or unbounded memory read");
      return;
    }
    while (n) {
      auto &p = page(addr);
      auto off = addr % PAGE;
      auto count = std::min(n, 64 - off % 64);
      auto bits = ByteMask::mask(off % 64, count);
      auto needed = bits & ~(p.written.words[off / 64] | p.input.words[off / 64]);
      auto low = std::max(addr, recipe.h.output), high = std::min(addr + count, output_frontier);
      if (low < high)
        needed &= ~ByteMask::mask(low % 64, high - low);
      if (needed) {
        live_bytes += __builtin_popcountll(needed);
        if (live_bytes > MAX_BLOB / 2) {
          reject("live inputs exceed 32 MiB");
          return;
        }
        if (!p.data)
          p.data = std::make_unique<std::array<uint8_t, PAGE>>();
        p.input.words[off / 64] |= needed;
        while (needed) {
          auto bit = __builtin_ctzll(needed);
          size_t index = (off / 64) * 64 + bit;
          (*p.data)[index] = *reinterpret_cast<const uint8_t *>(base(addr) + index);
          needed &= needed - 1;
        }
      }
      addr += count;
      n -= count;
    }
  }
  void write(uint64_t addr, size_t n) {
    if (n > PAGE * 16 || addr > UINT64_MAX - n) {
      reject("unbounded memory write");
      return;
    }
    last_store_end = addr + n;
    if (addr >= recipe.h.output && addr <= output_frontier &&
        addr + n <= recipe.h.output + recipe.h.length) {
      output_frontier = std::max(output_frontier, addr + n);
      return;
    }
    while (n) {
      auto count = std::min(n, PAGE - addr % PAGE);
      page(addr).written.mark(addr % PAGE, count);
      addr += count;
      n -= count;
    }
  }
  uint64_t segment_base(const QBDI::InstAnalysis &a) const {
    for (unsigned i = 0; i < a.numOperands; i++) {
      const auto &o = a.operands[i];
      if (o.type != QBDI::OPERAND_SEG || !o.regName)
        continue;
      if (std::strcmp(o.regName, "FS") == 0)
        return recipe.h.fs_base;
      if (std::strcmp(o.regName, "GS") == 0)
        return recipe.h.gs_base;
    }
    return 0;
  }
  static bool safe_instruction(const QBDI::InstAnalysis &a) {
    // Deliberately bounded to scalar integer, SSE/SSE2 data/arithmetic and
    // ordinary control flow. TLS reads use captured segment bases. No AVX,
    // x87, REP, privileged or time/random operations.
    const std::string m = a.mnemonic;
    static const char *allowed[] = {
        "MOV",   "LEA",   "ADD",    "SUB",   "IMUL",   "MUL",    "IDIV",   "DIV",   "AND",
        "OR",    "XOR",   "NOT",    "NEG",   "SHL",    "SHR",    "SAR",    "SAL",   "ROL",
        "ROR",   "SHLD",  "SHRD",   "CMP",   "TEST",   "INC",    "DEC",    "JMP",   "JCC",
        "CALL",  "RET",   "PUSH",   "POP",   "LEAVE",  "CMOV",   "SET",    "NOP",   "NOOP",
        "ENDBR", "CDQ",   "CQO",    "CWDE",  "CDQE",   "CBW",    "CWD",    "BSF",   "BSR",
        "BSWAP", "BT",    "BTS",    "BTR",   "BTC",    "ADC",    "SBB",    "CLC",   "STC",
        "CMC",   "PXOR",  "PAND",   "POR",   "PADD",   "PSUB",   "PMUL",   "PSLL",  "PSRL",
        "PSRA",  "PSHU",  "PUNPCK", "PACK",  "PCMPEQ", "PCMPGT", "UCOMIS", "COMIS", "CVT",
        "SQRT",  "MINSD", "MAXSD",  "MINSS", "MAXSS",  "UNPCK",  "SHUF",   "XORPS", "XORPD",
        "ANDPS", "ANDPD", "ORPS",   "ORPD"};
    bool allowed_prefix = false;
    for (auto p : allowed)
      if (m.rfind(p, 0) == 0) {
        allowed_prefix = true;
        break;
      }
    if (!allowed_prefix)
      return false;
    if (m.rfind("MOVS", 0) == 0 && m.rfind("MOVSX", 0) != 0 && m.rfind("MOVSD", 0) != 0 &&
        m.rfind("MOVSS", 0) != 0)
      return false;
    if (m.find("REP") != std::string::npos || m.find("LOCK") != std::string::npos || m == "MOVSD" ||
        m == "MOVSB" || m == "MOVSW" || m == "MOVSQ")
      return false;
    for (unsigned i = 0; i < a.numOperands; i++) {
      const auto &o = a.operands[i];

      if (o.type == QBDI::OPERAND_SEG && o.regName && *o.regName &&
          o.regAccess != QBDI::REGISTER_READ)
        return false;
      if (o.type == QBDI::OPERAND_SEG && o.regName &&
          (!std::strcmp(o.regName, "FS") || !std::strcmp(o.regName, "GS")) &&
          (a.isCall || a.isReturn || m.rfind("PUSH", 0) == 0 || m.rfind("POP", 0) == 0))
        return false;
      if (o.type == QBDI::OPERAND_FPR && o.regName && !std::strcmp(o.regName, "MXCSR") &&
          o.regAccess == QBDI::REGISTER_READ)
        continue;
      if (o.type == QBDI::OPERAND_FPR &&
          (o.size > 16 || (o.regName && std::strncmp(o.regName, "XMM", 3) != 0)))
        return false;
    }
    return true;
  }
  static QBDI::VMAction transfer(QBDI::VMInstanceRef, const QBDI::VMState *, QBDI::GPRState *,
                                 QBDI::FPRState *, void *ctx) {
    ErrnoScope errno_scope;
    static_cast<Recorder *>(ctx)->reject("call left the instrumented module");
    return QBDI::CONTINUE;
  }
  void begin(QBDI::GPRState *g, QBDI::FPRState *f) {
    if (began)
      return;
    began = true;
    auto &h = recipe.h;
    std::memcpy(h.regs, g, sizeof h.regs);
    std::memcpy(h.xmm, f->xmm0, sizeof h.xmm);
    h.mxcsr = f->mxcsr;
    h.entry = g->rip;
    h.stop = *reinterpret_cast<uint64_t *>(g->rsp);
  }
  static std::vector<QBDI::InstrRuleDataCBK> rule(QBDI::VMInstanceRef, const QBDI::InstAnalysis *a,
                                                  void *ctx) {
    auto &r = *static_cast<Recorder *>(ctx);
    ErrnoScope errno_scope;
    BusyScope busy(r.busy_flag);
    if (r.plans.size() >= 1000000) {
      r.reject("instruction metadata limit exceeded");
      return {};
    }
    auto &p = r.plans[a->address];
    p.owner = &r;
    p.instruction.address = a->address;
    p.instruction.size = a->instSize;
    std::memcpy(p.instruction.bytes, reinterpret_cast<void *>(a->address), a->instSize);
    p.segment = r.segment_base(*a);
    if (!safe_instruction(*a))
      p.rejection = std::string("unsupported instruction: ") + a->mnemonic;
    std::vector<QBDI::InstrRuleDataCBK> callbacks;
    if (a->address == r.entry_target)
      callbacks.emplace_back(QBDI::PREINST, initialize, &r, QBDI::PRIORITY_DEFAULT + 1);
    if (a->mayLoad)
      callbacks.emplace_back(QBDI::PREINST, read_access, &p);
    if (a->mayStore)
      callbacks.emplace_back(QBDI::POSTINST, write_access, &p);
    if (!getenv("AF_DISABLE_NATIVE_CAPTURE") && a->isBranch && loops_available(r, a)) {
      auto &loop = r.loops.at(a->address);
      if (loop.code)
        callbacks.emplace_back(QBDI::PREINST, inline_loop, &loop);
    }
    return callbacks;
  }
  static bool loops_available(Recorder &r, const QBDI::InstAnalysis *a) {
    if (r.loops.count(a->address))
      return true;
    if (r.loops.size() >= 128)
      return false;
    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
    ZydisDecodedInstruction d{};
    ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT]{};
    if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, reinterpret_cast<const void *>(a->address),
                                             a->instSize, &d, ops)) ||
        d.meta.category != ZYDIS_CATEGORY_COND_BR || ops[0].type != ZYDIS_OPERAND_TYPE_IMMEDIATE ||
        !ops[0].imm.is_relative || ops[0].imm.value.s >= 0 || ops[0].imm.value.s < -256)
      return false;
    auto &loop = r.loops[a->address];
    loop.owner = &r;
    try {
      loop.code = std::make_unique<NativeLoop>(a->address + a->instSize + ops[0].imm.value.s,
                                               a->address, a->address + a->instSize, true);
    } catch (const std::exception &) {
    }
    return true;
  }
  static QBDI::VMAction inline_loop(QBDI::VMInstanceRef vm, QBDI::GPRState *g, QBDI::FPRState *f,
                                    void *ctx) {
    auto &loop = *static_cast<InlineLoop *>(ctx);
    auto &r = *loop.owner;
    ErrnoScope errno_scope;
    BusyScope busy(r.busy_flag);
    if (!r.rejection.empty() || !loop.code)
      return QBDI::CONTINUE;
    auto first = loop.code->writes_output() ? r.last_store_end : r.output_frontier;
    if (first < r.recipe.h.output || first > r.recipe.h.output + r.recipe.h.length)
      return QBDI::CONTINUE;
    NativeLoop::Trace trace{first, r.recipe.h.output + r.recipe.h.length};
    auto guest_errno = vm->getErrno();
    if (!loop.code->run(g, f, guest_errno, &trace)) {
      loop.code.reset();
      return QBDI::CONTINUE;
    }
    vm->setErrno(guest_errno);
    r.native_loop_runs++;
    if (!trace.valid || trace.instructions > 500000000 - std::min(r.steps, uint64_t(500000000)))
      r.reject("inline capture exceeded exact coverage or instruction bounds");
    else {
      r.steps += trace.instructions;
      try {
        for (auto address = first; address < trace.frontier;) {
          auto length = std::min(uint64_t(65536), trace.frontier - address);
          r.write(address, length);
          address += length;
        }
      } catch (const std::exception &) {
        r.reject("inline capture metadata allocation failed");
      }
    }
    return QBDI::BREAK_TO_VM;
  }
  static QBDI::VMAction initialize(QBDI::VMInstanceRef, QBDI::GPRState *g, QBDI::FPRState *f,
                                   void *ctx) {
    auto &r = *static_cast<Recorder *>(ctx);
    ErrnoScope errno_scope;
    BusyScope busy(r.busy_flag);
    r.begin(g, f);
    return QBDI::CONTINUE;
  }
  static QBDI::VMAction block(QBDI::VMInstanceRef, const QBDI::VMState *state, QBDI::GPRState *,
                              QBDI::FPRState *, void *ctx) {
    auto &r = *static_cast<Recorder *>(ctx);
    ErrnoScope errno_scope;
    BusyScope busy(r.busy_flag);
    r.block_callbacks++;
    try {
      auto key = std::make_pair(state->basicBlockStart, state->basicBlockEnd);
      auto cached = r.block_counts.find(key);
      if (cached == r.block_counts.end()) {
        uint64_t count = 0;
        for (auto it = r.plans.lower_bound(key.first);
             it != r.plans.end() && it->first < key.second; ++it) {
          auto &p = it->second;
          count++;
          if (!p.rejection.empty())
            r.reject(p.rejection);
          r.code.emplace(p.instruction.address, p.instruction);
        }
        if (!count)
          r.reject("block has no instruction metadata");
        cached = r.block_counts.emplace(key, count).first;
      }
      r.steps += cached->second;
      if (r.steps > 500000000)
        r.reject("500 million instruction capture limit");
    } catch (const std::exception &e) {
      r.reject(e.what());
    }
    return r.stop_on_rejection && !r.rejection.empty() ? QBDI::STOP : QBDI::CONTINUE;
  }
  static QBDI::VMAction read_access(QBDI::VMInstanceRef vm, QBDI::GPRState *, QBDI::FPRState *,
                                    void *ctx) {
    auto &p = *static_cast<Plan *>(ctx);
    auto &r = *p.owner;
    ErrnoScope errno_scope;
    BusyScope busy(r.busy_flag);
    r.read_callbacks++;
    if (!r.rejection.empty())
      return QBDI::CONTINUE;
    try {
      for (const auto &m : vm->getInstMemoryAccess()) {
        if (!(m.type & QBDI::MEMORY_READ))
          continue;
        if (m.flags & (QBDI::MEMORY_UNKNOWN_SIZE | QBDI::MEMORY_MINIMUM_SIZE)) {
          r.reject("unknown memory read size");
          break;
        }
        r.read(m.accessAddress + p.segment, m.size);
      }
    } catch (const std::exception &e) {
      r.reject(e.what());
    }
    return QBDI::CONTINUE;
  }
  static QBDI::VMAction write_access(QBDI::VMInstanceRef vm, QBDI::GPRState *, QBDI::FPRState *,
                                     void *ctx) {
    auto &p = *static_cast<Plan *>(ctx);
    auto &r = *p.owner;
    ErrnoScope errno_scope;
    BusyScope busy(r.busy_flag);
    r.write_callbacks++;
    if (!r.rejection.empty())
      return QBDI::CONTINUE;
    try {
      for (const auto &m : vm->getInstMemoryAccess()) {
        if (!(m.type & QBDI::MEMORY_WRITE))
          continue;
        if (m.flags & (QBDI::MEMORY_UNKNOWN_SIZE | QBDI::MEMORY_MINIMUM_SIZE)) {
          r.reject("unknown memory write size");
          break;
        }
        r.write(m.accessAddress + p.segment, m.size);
      }
    } catch (const std::exception &e) {
      r.reject(e.what());
    }
    return QBDI::CONTINUE;
  }
  void install(QBDI::VM &vm, uint64_t entry) {
    entry_target = entry;
    vm.setOptions(vm.getOptions() | QBDI::OPT_DISABLE_MEMORYACCESS_VALUE);
    vm.recordMemoryAccess(QBDI::MEMORY_READ_WRITE);
    vm.addInstrRule(rule, QBDI::ANALYSIS_INSTRUCTION | QBDI::ANALYSIS_OPERANDS, this);
    vm.addVMEventCB(QBDI::BASIC_BLOCK_ENTRY, block, this);
    vm.addVMEventCB(QBDI::EXEC_TRANSFER_CALL, transfer, this);
  }
  void finish(uint64_t result, bool allow_region = false) {
    if (!rejection.empty())
      throw std::runtime_error(rejection);
    if (!began)
      throw std::runtime_error("no native instructions captured");
    auto &h = recipe.h;
    if (allow_region && !std::getenv("AF_DISABLE_REGIONS")) {
      auto original_output = h.output;
      auto covered = [&](uint64_t at, uint64_t count) {
        if (at + count <= output_frontier)
          return true;
        auto found = pages.find(base(at));
        auto begin = output_frontier > at ? output_frontier - at : 0;
        return found != pages.end() && found->second.written.all(begin, count - begin);
      };
      bool complete = true;
      uint64_t run = 0, best_start = 0, best_length = 0;
      for (uint64_t offset = 0; offset < h.length; offset += PAGE) {
        auto length = std::min(PAGE, h.length - offset);
        if (!covered(h.output + offset, length)) {
          complete = false;
          run = 0;
        } else if (length == PAGE) {
          run += PAGE;
          if (run > best_length) {
            best_length = run;
            best_start = offset + PAGE - run;
          }
        }
      }
      if (!complete && best_length >= std::max(uint64_t(65536), rounded(h.length / 2))) {
        h.output += best_start;
        h.length = best_length;
        // Frontier-only writes outside the chosen region become explicit
        // scratch writes in the original recipe. Never lose their dependencies.
        for (uint64_t at = original_output; at < output_frontier; at += PAGE)
          if (at < h.output || at >= h.output + h.length)
            page(at).written.mark(0, std::min(PAGE, output_frontier - at));
        output_frontier = std::max(h.output, std::min(output_frontier, h.output + h.length));
      }
    }
    h.result = result;
    h.steps = steps;
    h.input_bytes = live_bytes;
    if (output_frontier != h.output + h.length)
      for (uint64_t i = 0; i < h.length; i += PAGE) {
        auto &coverage = page(h.output + i).written;
        if (output_frontier > h.output + i)
          coverage.mark(0, std::min(PAGE, output_frontier - h.output - i));
        if (!coverage.all(0, std::min(PAGE, h.length - i)))
          throw std::runtime_error("output was not fully produced by this call");
      }
    for (auto &[addr, c] : code) {
      for (unsigned i = 0; i < c.size; i++)
        if (page(c.address + i).written.any())
          throw std::runtime_error("self-modifying code is ineligible");
      recipe.code.push_back(c);
    }
    uint64_t scratch_pages = 0;
    for (auto &[address, p] : pages)
      if (address < h.output || address >= h.output + rounded(h.length))
        scratch_pages++;
    if (scratch_pages * PAGE > h.length / 4 + (4ULL << 20))
      throw std::runtime_error("replay scratch exceeds the group budget");
    for (auto &[addr, p] : pages) {
      if (addr < h.output || addr >= h.output + rounded(h.length))
        recipe.pages.push_back(addr);
      for (size_t i = 0; i < PAGE;) {
        if (!p.input[i]) {
          i++;
          continue;
        }
        size_t start = i;
        while (i < PAGE && p.input[i])
          i++;
        Segment s;
        s.address = addr + start;
        s.bytes.assign(p.data->begin() + start, p.data->begin() + i);
        recipe.inputs.push_back(std::move(s));
      }
    }
  }
};
// /proc/self works in restricted PID namespaces where /proc/<getpid> may not.
inline bool instrument_module(QBDI::VM &vm, uint64_t function) {
  FILE *f = std::fopen("/proc/self/maps", "r");
  if (!f)
    return false;
  struct Mapping {
    uint64_t lo, hi;
    std::string name;
    bool executable;
  };
  std::vector<Mapping> maps;
  char line[8192];
  std::string wanted;
  while (std::fgets(line, sizeof line, f)) {
    unsigned long lo, hi, offset, inode;
    char perms[8], dev[32], name[4096]{};
    int n = std::sscanf(line, "%lx-%lx %7s %lx %31s %lu %4095[^\n]", &lo, &hi, perms, &offset, dev,
                        &inode, name);
    if (n < 6)
      continue;
    std::string path = name;
    maps.push_back({lo, hi, path, perms[2] == 'x'});
    if (function >= lo && function < hi)
      wanted = path;
  }
  std::fclose(f);
  if (wanted.empty())
    return false;
  for (auto &m : maps)
    if (m.name == wanted && m.executable)
      vm.addInstrumentedRange(m.lo, m.hi);
  return true;
}
inline void instrument_memory_routines(QBDI::VM &vm) {
  for (auto range : memory_routine_extents())
    vm.addInstrumentedRange(range.first, range.second);
}
} // namespace af
