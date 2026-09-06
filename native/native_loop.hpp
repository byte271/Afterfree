#pragma once
#include "affine.hpp"
#include "afterfree.h"
#include "snapshot.hpp"
#include <QBDI.h>
#include <memory>
#include <set>
#include <sys/mman.h>

namespace af {
// A bounded native island executes original instructions and real effects once.
// Discovery can prepare proved read spans; recorder mode proves affine output stores
// and retains inline coverage checks plus exact executed-instruction counts.
// Only a straight-line, stack-free body with one conditional backedge qualifies.
// No call, syscall, indirect transfer, RIP-relative access, or extra ISA state
// can cross this boundary. Unsupported loops remain under ordinary QBDI.
class NativeLoop {
  struct State {
    uint64_t regs[18];
    uint8_t xmm[16][16];
    uint32_t mxcsr, host_mxcsr;
    uint64_t iterations = 0, frontier = 0, limit = 0, invalid = 0;
  };
  std::vector<uint8_t> original;
  uint64_t begin, end;
  void *code = nullptr;
  size_t mapped = 0;
  int condition = -1;
  bool tracing = false;
  size_t instruction_count = 0;
  ZydisRegister output_base = ZYDIS_REGISTER_NONE, output_index = ZYDIS_REGISTER_NONE;
  uint64_t output_prefix = 0;
  unsigned output_scale = 0;
  bool output_store = false;
  x86::AffineAccess read_plan;
  ZydisRegister read_counter = ZYDIS_REGISTER_NONE, read_bound = ZYDIS_REGISTER_NONE;
  uint64_t read_increment = 0;
  static uint64_t value(const QBDI::GPRState *g, ZydisRegister r) {
    for (int i = 0; i < 16; i++)
      if (x86::gp(x86::physical[i]) == r)
        return reinterpret_cast<const uint64_t *>(g)[i];
    return 0;
  }
  void prepare_reads(const QBDI::GPRState *g) {
    ErrnoScope errno_scope;
    read_bytes = 0;
    if (!read_increment || std::getenv("AF_DISABLE_READ_PLANS"))
      return;
    auto current = value(g, read_counter), bound = value(g, read_bound);
    if (bound <= current || (bound - current) % read_increment)
      return;
    auto iterations = (bound - current) / read_increment;
    if (iterations > MAX_BUFFER / read_plan.width)
      return;
    auto size = iterations * read_plan.width;
    auto first =
        value(g, read_plan.base) + value(g, read_plan.index) * read_plan.scale + read_plan.prefix;
    if (first > UINT64_MAX - size)
      return;
    if (af_prepare_read(reinterpret_cast<const void *>(first), size))
      return;
    read_bytes = size;
  }

public:
  struct Trace {
    uint64_t frontier, limit, instructions = 0;
    bool valid = true;
  };
  bool writes_output() const { return output_store; }
  unsigned streak = 0;
  bool disabled = false;
  uint64_t guard_ns = 0, execution_ns = 0, read_bytes = 0;
  std::pair<uint64_t, uint64_t> range() const { return {begin, end}; }
  void retire() {
    disabled = true;
    if (code)
      munmap(code, mapped);
    code = nullptr;
    mapped = 0;
    original.clear();
    original.shrink_to_fit();
  }
  NativeLoop(uint64_t head, uint64_t branch, uint64_t after, bool trace = false)
      : begin(head), end(after), tracing(trace) {
    using namespace x86;
    if (branch < head || after - head > 256 || after <= branch)
      throw std::runtime_error("loop extent unsupported");
    original.resize(after - head);
    bool immutable = false;
    if (FILE *maps = std::fopen("/proc/self/maps", "r")) {
      char line[8192], permissions[8];
      unsigned long low, high;
      while (std::fgets(line, sizeof line, maps))
        if (std::sscanf(line, "%lx-%lx %7s", &low, &high, permissions) == 3 && low <= head &&
            high >= after && permissions[0] == 'r' && permissions[1] != 'w' &&
            permissions[2] == 'x') {
          immutable = true;
          break;
        }
      std::fclose(maps);
    }
    if (!immutable)
      throw std::runtime_error("loop code is not immutable executable memory");
    SnapshotReader reader;
    if (!reader.copy(head, original.data(), original.size()))
      throw std::runtime_error("loop code unavailable");
    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
    std::set<int> used, vectors;
    std::set<ZydisRegister> written;
    ZydisRegister compared = ZYDIS_REGISTER_NONE, bound = ZYDIS_REGISTER_NONE;
    size_t body_size = branch - head;
    for (size_t off = 0; off < original.size();) {
      ZydisDecodedInstruction d{};
      ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT]{};
      if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, original.data() + off,
                                               original.size() - off, &d, ops)) ||
          d.encoding != ZYDIS_INSTRUCTION_ENCODING_LEGACY ||
          (d.attributes & (ZYDIS_ATTRIB_HAS_LOCK | ZYDIS_ATTRIB_HAS_REP | ZYDIS_ATTRIB_HAS_REPE |
                           ZYDIS_ATTRIB_HAS_REPNE)))
        throw std::runtime_error("unsupported loop instruction");
      if (off == body_size) {
        if (off + d.length != original.size() || d.meta.category != ZYDIS_CATEGORY_COND_BR ||
            ops[0].type != ZYDIS_OPERAND_TYPE_IMMEDIATE || !ops[0].imm.is_relative ||
            after + ops[0].imm.value.s != head ||
            !((d.opcode >= 0x70 && d.opcode <= 0x7f) || (d.opcode >= 0x80 && d.opcode <= 0x8f)))
          throw std::runtime_error("loop backedge unsupported");
        condition = d.opcode & 15;
      } else if (off + d.length > body_size ||
                 (!permitted(d.mnemonic) && d.mnemonic != ZYDIS_MNEMONIC_BT))
        throw std::runtime_error("loop has a control or state boundary");
      if (off + d.length == body_size && d.mnemonic == ZYDIS_MNEMONIC_CMP &&
          ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER && ops[0].size == 64 &&
          ops[1].type == ZYDIS_OPERAND_TYPE_REGISTER && ops[1].size == 64) {
        compared = ops[0].reg.value;
        bound = ops[1].reg.value;
      }
      instruction_count++;
      for (unsigned i = 0; i < d.operand_count; i++) {
        auto use = [&](ZydisRegister r) {
          if (r == ZYDIS_REGISTER_RIP && off == body_size)
            return;
          if (r == ZYDIS_REGISTER_NONE || r == ZYDIS_REGISTER_RFLAGS ||
              r == ZYDIS_REGISTER_EFLAGS || r == ZYDIS_REGISTER_MXCSR)
            return;
          auto largest = ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, r);
          if (largest >= ZYDIS_REGISTER_RAX && largest <= ZYDIS_REGISTER_R15 &&
              largest != ZYDIS_REGISTER_RSP)
            used.insert(largest - ZYDIS_REGISTER_RAX);
          else if (r >= ZYDIS_REGISTER_XMM0 && r <= ZYDIS_REGISTER_XMM15)
            vectors.insert(r - ZYDIS_REGISTER_XMM0);
          else
            throw std::runtime_error("loop uses unsupported register state");
        };
        if (ops[i].type == ZYDIS_OPERAND_TYPE_REGISTER) {
          use(ops[i].reg.value);
          if (ops[i].actions & ZYDIS_OPERAND_ACTION_MASK_WRITE)
            written.insert(
                ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, ops[i].reg.value));
        }
        if (ops[i].type == ZYDIS_OPERAND_TYPE_MEMORY && d.mnemonic != ZYDIS_MNEMONIC_NOP) {
          if (tracing && d.mnemonic != ZYDIS_MNEMONIC_LEA &&
              (ops[i].actions != ZYDIS_OPERAND_ACTION_WRITE || !ops[i].size || ops[i].size > 128 ||
               ops[i].size % 8 || ops[i].mem.segment == ZYDIS_REGISTER_FS ||
               ops[i].mem.segment == ZYDIS_REGISTER_GS))
            throw std::runtime_error("inline capture requires pure output stores");
          use(ops[i].mem.base);
          use(ops[i].mem.index);
          if (i >= d.operand_count_visible || d.address_width != 64)
            throw std::runtime_error("loop has implicit memory effects");
        }
      }
      off += d.length;
    }
    if (tracing) {
      auto proof = AffineAccess::prove(original.data(), body_size);
      output_store = proof.width != 0;
      output_base = proof.base;
      output_index = proof.index;
      output_scale = proof.scale;
      output_prefix = proof.prefix;
    }
    // Equality comparisons are symmetric; compilers choose either operand order.
    if (condition == 5 && written.count(bound) && !written.count(compared))
      std::swap(compared, bound);
    if (!tracing && (condition == 2 || condition == 5) && bound != ZYDIS_REGISTER_NONE &&
        !written.count(bound)) {
      try {
        auto proof = AffineAccess::prove(original.data(), body_size, ZYDIS_OPERAND_ACTION_READ);
        uint64_t delta = 0;
        if (compared == proof.base && !proof.index_delta)
          delta = proof.base_delta;
        else if (compared == proof.index && !proof.base_delta)
          delta = proof.index_delta;
        if (proof.width && delta && delta <= proof.width) {
          read_plan = proof;
          read_increment = delta;
          read_counter = compared;
          read_bound = bound;
        }
      } catch (const std::exception &) {
      }
    }
    if (condition < 0)
      throw std::runtime_error("loop has no backedge");
    ZydisRegister context = ZYDIS_REGISTER_NONE;
    for (int p : {15, 14, 13, 12, 11, 10, 9, 8, 3, 5, 6, 7, 2, 1, 0})
      if (!used.count(p)) {
        context = gp(p);
        break;
      }
    if (context == ZYDIS_REGISTER_NONE)
      throw std::runtime_error("loop has no context register");
    ZydisRegister scratch = ZYDIS_REGISTER_NONE, counter = ZYDIS_REGISTER_NONE;
    if (tracing) {
      used.insert(context - ZYDIS_REGISTER_RAX);
      for (int p : {15, 14, 13, 12, 11, 10, 9, 8, 3, 5, 6, 7, 2, 1, 0})
        if (!used.count(p)) {
          if (scratch == ZYDIS_REGISTER_NONE)
            scratch = gp(p);
          else {
            counter = gp(p);
            break;
          }
        }
      used.erase(context - ZYDIS_REGISTER_RAX);
      if (counter == ZYDIS_REGISTER_NONE)
        throw std::runtime_error("inline capture lacks instrumentation registers");
    }
    Emitter e;
    auto field = [&](size_t offset, unsigned size = 8) { return mem(context, offset, size); };
    e.landing();
    e.bytes.push_back(0x9c);
    for (int p : {3, 5, 12, 13, 14, 15})
      e.op(ZYDIS_MNEMONIC_PUSH, {reg(gp(p))});
    e.op(ZYDIS_MNEMONIC_MOV, {reg(context), reg(ZYDIS_REGISTER_RDI)});
    e.op(ZYDIS_MNEMONIC_STMXCSR, {field(offsetof(State, host_mxcsr), 4)});
    e.op(ZYDIS_MNEMONIC_LDMXCSR, {field(offsetof(State, mxcsr), 4)});
    for (int i = 0; i < 16; i++)
      if (used.count(physical[i]))
        e.op(ZYDIS_MNEMONIC_MOV, {reg(gp(physical[i])), field(i * 8)});
    for (int i : vectors)
      e.op(ZYDIS_MNEMONIC_MOVDQU, {reg(xmm(i)), field(offsetof(State, xmm) + 16 * i, 16)});
    if (tracing)
      e.op(ZYDIS_MNEMONIC_MOV, {reg(counter), imm(0)});
    e.op(ZYDIS_MNEMONIC_PUSH, {field(17 * 8)});
    e.bytes.push_back(0x9d);
    // The callback is at the original branch, after its first body execution.
    auto skip = e.jump(condition ^ 1);
    auto body = e.bytes.size();
    if (!tracing)
      e.bytes.insert(e.bytes.end(), original.begin(), original.begin() + body_size);
    else {
      e.op(ZYDIS_MNEMONIC_LEA, {reg(counter), mem(counter, 1)});
      for (size_t off = 0; off < body_size;) {
        ZydisDecodedInstruction d{};
        ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT]{};
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, original.data() + off,
                                                 original.size() - off, &d, ops)))
          throw std::runtime_error("inline capture decode diverged");
        for (unsigned i = 0; i < d.operand_count_visible; i++)
          if (ops[i].type == ZYDIS_OPERAND_TYPE_MEMORY && d.mnemonic != ZYDIS_MNEMONIC_LEA &&
              d.mnemonic != ZYDIS_MNEMONIC_NOP) {
            auto operand = mem(ops[i].mem.base, ops[i].mem.disp.value);
            operand.mem.index = ops[i].mem.index;
            operand.mem.scale = ops[i].mem.scale;
            e.bytes.push_back(0x9c);
            e.op(ZYDIS_MNEMONIC_LEA, {reg(scratch), operand});
            e.op(ZYDIS_MNEMONIC_CMP, {reg(scratch), field(offsetof(State, frontier))});
            auto mismatch = e.jump(5);
            e.op(ZYDIS_MNEMONIC_ADD, {reg(scratch), imm(ops[i].size / 8)});
            auto overflow = e.jump(2);
            e.op(ZYDIS_MNEMONIC_CMP, {reg(scratch), field(offsetof(State, limit))});
            auto outside = e.jump(7);
            e.op(ZYDIS_MNEMONIC_MOV, {field(offsetof(State, frontier)), reg(scratch)});
            auto valid = e.jump();
            for (auto at : {mismatch, overflow, outside})
              e.patch(at, e.bytes.size());
            e.op(ZYDIS_MNEMONIC_MOV, {field(offsetof(State, invalid)), imm(1)});
            e.patch(valid, e.bytes.size());
            e.bytes.push_back(0x9d);
          }
        e.bytes.insert(e.bytes.end(), original.begin() + off, original.begin() + off + d.length);
        off += d.length;
      }
    }
    auto repeat = e.jump(condition);
    e.patch(repeat, body);
    e.patch(skip, e.bytes.size());
    e.bytes.push_back(0x9c);
    e.op(ZYDIS_MNEMONIC_POP, {field(17 * 8)});
    if (tracing)
      e.op(ZYDIS_MNEMONIC_MOV, {field(offsetof(State, iterations)), reg(counter)});
    for (int i = 0; i < 16; i++)
      if (used.count(physical[i]))
        e.op(ZYDIS_MNEMONIC_MOV, {field(i * 8), reg(gp(physical[i]))});
    for (int i : vectors)
      e.op(ZYDIS_MNEMONIC_MOVDQU, {field(offsetof(State, xmm) + 16 * i, 16), reg(xmm(i))});
    e.op(ZYDIS_MNEMONIC_STMXCSR, {field(offsetof(State, mxcsr), 4)});
    e.op(ZYDIS_MNEMONIC_LDMXCSR, {field(offsetof(State, host_mxcsr), 4)});
    for (int p : {15, 14, 13, 12, 5, 3})
      e.op(ZYDIS_MNEMONIC_POP, {reg(gp(p))});
    e.bytes.insert(e.bytes.end(), {0x9d, 0xc3});
    mapped = rounded(e.bytes.size());
    code = mmap(nullptr, mapped, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (code == MAP_FAILED) {
      code = nullptr;
      throw std::bad_alloc();
    }
    std::memcpy(code, e.bytes.data(), e.bytes.size());
    if (mprotect(code, mapped, PROT_READ | PROT_EXEC)) {
      munmap(code, mapped);
      code = nullptr;
      throw std::runtime_error("cannot seal native loop");
    }
  }
  ~NativeLoop() {
    if (code)
      munmap(code, mapped);
  }
  NativeLoop(const NativeLoop &) = delete;
  size_t retained() const { return sizeof(*this) + original.capacity() + mapped; }
  bool continues(uint64_t flags) const {
    bool carry = flags & 1, parity = flags & 4, zero = flags & 64, sign = flags & 128,
         overflow = flags & 2048;
    bool values[] = {overflow,
                     carry,
                     zero,
                     carry || zero,
                     sign,
                     parity,
                     sign != overflow,
                     zero || (sign != overflow)};
    return values[condition / 2] != bool(condition & 1);
  }
  bool run(QBDI::GPRState *g, QBDI::FPRState *f, uint32_t &guest_errno, Trace *trace = nullptr) {
    if (tracing != bool(trace))
      return false;
    if (trace && output_store) {
      if (value(g, output_base) + value(g, output_index) * output_scale + output_prefix !=
          trace->frontier)
        return false;
    }
    uint64_t started = monotonic_ns();
    int host_errno = errno;
    uint8_t current[256];
    ErrnoScope errno_scope;
    try {
      SnapshotReader reader;
      if ((g->eflags & ((1ULL << 8) | (1ULL << 14) | (1ULL << 18))) ||
          (f->mxcsr & 0x1f80) != 0x1f80 || !reader.copy(begin, current, original.size()) ||
          std::memcmp(current, original.data(), original.size()))
        return false;
    } catch (const std::exception &) {
      return false;
    }
    State state{};
    std::memcpy(state.regs, g, sizeof state.regs);
    std::memcpy(state.xmm, f->xmm0, sizeof state.xmm);
    state.mxcsr = f->mxcsr;
    if (trace) {
      state.frontier = trace->frontier;
      state.limit = trace->limit;
    }
    errno = guest_errno;
    uint64_t executing = monotonic_ns();
    guard_ns = executing - started;
    if (!tracing)
      prepare_reads(g);
    reinterpret_cast<void (*)(State *)>(code)(&state);
    execution_ns = monotonic_ns() - executing;
    guest_errno = errno;
    errno = host_errno;
    std::memcpy(g, state.regs, sizeof state.regs);
    g->rip = end;
    std::memcpy(f->xmm0, state.xmm, sizeof state.xmm);
    f->mxcsr = state.mxcsr;
    if (trace) {
      trace->frontier = state.frontier;
      trace->valid = !state.invalid && state.iterations <= 500000000 / instruction_count;
      trace->instructions = trace->valid ? state.iterations * instruction_count : 0;
    }
    return true;
  }
};
} // namespace af
