#pragma once
#include "afterfree.h"
#include "common.hpp"
#include "x86.hpp"
#include <cstddef>
#include <cstdlib>
#include <map>
#include <memory>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <set>
#include <sys/mman.h>

namespace af {
using namespace x86;
// A checked compiler, not a jump into captured guest code. Loads address only
// immutable snapshots. Stores extend a bounded output frontier. All branches
// stay within a closed, decoded CFG and consume the captured instruction budget.
class NativeReplay {
  struct State {
    uint64_t regs[18]{};
    uint8_t xmm[16][16]{};
    uint32_t mxcsr = 0, host_mxcsr = 0;
    uint64_t entry = 0, cursor = 0, end = 0, limit = 0, delta = 0;
    uint64_t remaining = 0, next_page = 0, next_frame = 0, trigger = 0;
    uint64_t collecting = 0, validating = 0, error = 0;
  };
  struct Decoded {
    Instruction source;
    ZydisDecodedInstruction inst{};
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT]{};
    uint64_t target = 0;
    int memory = -1, condition = -1;
    bool branch = false, returns = false;
    uint32_t flags_in = 0;
  };
  const Recipe &recipe;
  af_worker_profile &profile;
  std::map<uint64_t, Decoded> instructions;
  std::set<uint64_t> block_starts;
  std::vector<int> gprs, vectors;
  std::vector<std::pair<size_t, ZydisRegister>> hot_fields;
  ZydisRegister context_reg = ZYDIS_REGISTER_NONE, scratch_reg = ZYDIS_REGISTER_NONE;
  std::vector<uint64_t> constants;
  std::vector<uint8_t> frames;
  std::vector<std::array<uint8_t, 32>> digests;
  uint8_t *executable = nullptr;
  size_t executable_bytes = 0, frame_size = 0;
  uint64_t entry_offset = 0;
  bool pages = false;
  ZydisEncoderOperand field(size_t offset, unsigned size = 8) const {
    if (size == 8)
      for (auto [position, r] : hot_fields)
        if (position == offset)
          return reg(r);
    return mem(context_reg, offset, size);
  }
  ZydisEncoderOperand constant(uint64_t value) {
    auto offset = sizeof(State) + constants.size() * sizeof(uint64_t);
    constants.push_back(value);
    return field(offset);
  }
  void decode() {
    if (recipe.code.size() > 4096 || recipe.inputs.size() > 128 ||
        (recipe.h.mxcsr & 0x1f80) != 0x1f80 ||
        (recipe.h.regs[17] & ((1ULL << 8) | (1ULL << 14) | (1ULL << 18))))
      throw std::runtime_error("native replay subset exceeded");
    uint64_t returned;
    if (!read_snapshot(recipe, recipe.h.regs[15], &returned, sizeof returned))
      throw std::runtime_error("native return reads a missing input byte");
    if (returned != recipe.h.stop)
      throw std::runtime_error("native return address diverged");
    ZydisDecoder decoder;
    if (!ZYAN_SUCCESS(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64)))
      throw std::runtime_error("native decoder initialization failed");
    std::set<int> used_gp, used_xmm;
    auto use = [&](ZydisRegister r) {
      if (r == ZYDIS_REGISTER_NONE || r == ZYDIS_REGISTER_RIP || r == ZYDIS_REGISTER_RFLAGS ||
          r == ZYDIS_REGISTER_EFLAGS || r == ZYDIS_REGISTER_MXCSR)
        return;
      auto largest = ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, r);
      if (largest >= ZYDIS_REGISTER_RAX && largest <= ZYDIS_REGISTER_R15) {
        if (largest == ZYDIS_REGISTER_RSP || (r >= ZYDIS_REGISTER_AH && r <= ZYDIS_REGISTER_BH))
          throw std::runtime_error("native replay requires a stack-free body");
        used_gp.insert(largest - ZYDIS_REGISTER_RAX);
      } else if (r >= ZYDIS_REGISTER_XMM0 && r <= ZYDIS_REGISTER_XMM15)
        used_xmm.insert(r - ZYDIS_REGISTER_XMM0);
      else
        throw std::runtime_error("unsupported native register state");
    };
    for (auto &code : recipe.code) {
      Decoded d;
      d.source = code;
      if (code.address < recipe.h.output + rounded(recipe.h.length) &&
          code.address + code.size > recipe.h.output)
        throw std::runtime_error("output overlaps native code");
      if (!ZYAN_SUCCESS(
              ZydisDecoderDecodeFull(&decoder, code.bytes, code.size, &d.inst, d.operands)) ||
          d.inst.length != code.size || d.inst.encoding != ZYDIS_INSTRUCTION_ENCODING_LEGACY ||
          (d.inst.attributes & (ZYDIS_ATTRIB_HAS_LOCK | ZYDIS_ATTRIB_HAS_REP |
                                ZYDIS_ATTRIB_HAS_REPE | ZYDIS_ATTRIB_HAS_REPNE)))
        throw std::runtime_error("unsupported native instruction encoding");
      d.returns = d.inst.mnemonic == ZYDIS_MNEMONIC_RET && code.size == 1 && code.bytes[0] == 0xc3;
      d.branch =
          d.inst.meta.category == ZYDIS_CATEGORY_COND_BR || d.inst.mnemonic == ZYDIS_MNEMONIC_JMP;
      if (d.branch) {
        uint64_t slot;
        if (d.inst.mnemonic == ZYDIS_MNEMONIC_JMP && rip_jump_slot(code, slot)) {
          if (slot < recipe.h.output + rounded(recipe.h.length) && slot + 8 > recipe.h.output)
            throw std::runtime_error("native control flow depends on mutable output");
          for (auto &other : recipe.code)
            if (slot < other.address + other.size && slot + 8 > other.address)
              throw std::runtime_error("native control input overlaps code");
          if (!read_snapshot(recipe, slot, &d.target, 8))
            throw std::runtime_error("native jump reads a missing input byte");
        } else {
          if (d.inst.operand_count_visible != 1 ||
              d.operands[0].type != ZYDIS_OPERAND_TYPE_IMMEDIATE || !d.operands[0].imm.is_relative)
            throw std::runtime_error("native replay requires bounded control flow");
          d.target = code.address + code.size + d.operands[0].imm.value.s;
        }
        if (d.inst.meta.category == ZYDIS_CATEGORY_COND_BR) {
          if ((d.inst.opcode >= 0x70 && d.inst.opcode <= 0x7f) ||
              (d.inst.opcode >= 0x80 && d.inst.opcode <= 0x8f))
            d.condition = d.inst.opcode & 15;
          else
            throw std::runtime_error("unsupported native branch condition");
        }
        block_starts.insert(d.target);
        block_starts.insert(code.address + code.size);
      } else if (!d.returns && !permitted(d.inst.mnemonic))
        throw std::runtime_error("instruction outside native replay subset");
      if (!d.returns && d.inst.mnemonic != ZYDIS_MNEMONIC_NOP) {
        for (unsigned i = 0; i < d.inst.operand_count; i++) {
          auto &o = d.operands[i];
          if (o.type == ZYDIS_OPERAND_TYPE_REGISTER)
            use(o.reg.value);
          if (o.type == ZYDIS_OPERAND_TYPE_MEMORY) {
            if (i >= d.inst.operand_count_visible || d.memory != -1 || d.inst.address_width != 64 ||
                !o.size || o.size > 128 || o.size % 8)
              throw std::runtime_error("unsupported native memory operand");
            d.memory = i;
            use(o.mem.base);
            use(o.mem.index);
            if ((o.mem.segment == ZYDIS_REGISTER_FS || o.mem.segment == ZYDIS_REGISTER_GS) &&
                (o.mem.base != ZYDIS_REGISTER_NONE || o.mem.index != ZYDIS_REGISTER_NONE))
              throw std::runtime_error("unsupported native TLS addressing");
            if (d.inst.mnemonic != ZYDIS_MNEMONIC_LEA && o.actions != ZYDIS_OPERAND_ACTION_READ &&
                o.actions != ZYDIS_OPERAND_ACTION_WRITE)
              throw std::runtime_error("native replay requires pure loads or stores");
          }
        }
      }
      instructions.emplace(code.address, d);
    }
    block_starts.insert(recipe.h.entry);
    if (!instructions.count(recipe.h.entry))
      throw std::runtime_error("native entry was not observed");
    for (auto &[pc, d] : instructions) {
      if (d.branch && !instructions.count(d.target))
        throw std::runtime_error("native branch target was not observed");
      if (!d.returns && (!d.branch || d.condition >= 0) && !instructions.count(pc + d.source.size))
        throw std::runtime_error("native control-flow graph is incomplete");
    }
    // Save flags only when they can be observed before an unconditional write.
    // Zero-count shifts/rotates preserve flags; undefined writes never kill.
    bool changed;
    do {
      changed = false;
      for (auto it = instructions.rbegin(); it != instructions.rend(); ++it) {
        auto &[pc, d] = *it;
        uint32_t live = 0;
        if (d.branch)
          live |= instructions.at(d.target).flags_in;
        if (!d.returns && (!d.branch || d.condition >= 0))
          live |= instructions.at(pc + d.source.size).flags_in;
        auto *flags = d.inst.cpu_flags;
        uint32_t killed = flags ? flags->modified | flags->set_0 | flags->set_1 : 0;
        switch (d.inst.mnemonic) {
        case ZYDIS_MNEMONIC_SHL:
        case ZYDIS_MNEMONIC_SHR:
        case ZYDIS_MNEMONIC_SAR:
        case ZYDIS_MNEMONIC_ROL:
        case ZYDIS_MNEMONIC_ROR:
          killed = 0;
          break;
        default:
          break;
        }
        uint32_t needed = (flags ? flags->tested : 0) | (live & ~killed);
        if (needed != d.flags_in) {
          d.flags_in = needed;
          changed = true;
        }
      }
    } while (changed);
    used_gp.insert(0); // Integer return value must be checked even if unchanged.
    for (int p : {15, 14, 13, 12, 11, 10, 9, 8, 3, 5, 6, 7, 2, 1})
      if (!used_gp.count(p)) {
        if (context_reg == ZYDIS_REGISTER_NONE)
          context_reg = gp(p);
        else {
          scratch_reg = gp(p);
          break;
        }
      }
    if (scratch_reg == ZYDIS_REGISTER_NONE)
      throw std::runtime_error("no scratch registers for checked native replay");
    // Keep guard state in otherwise-unused guest registers. This removes
    // loop-carried loads/stores without removing any memory or budget check.
    if (!std::getenv("AF_DISABLE_REGISTER_CACHE")) {
      auto reserved = used_gp;
      reserved.insert(context_reg - ZYDIS_REGISTER_RAX);
      reserved.insert(scratch_reg - ZYDIS_REGISTER_RAX);
      for (size_t field : {offsetof(State, cursor), offsetof(State, remaining),
                           offsetof(State, limit), offsetof(State, delta), offsetof(State, trigger),
                           offsetof(State, next_page), offsetof(State, end)}) {
        for (int p : {15, 14, 13, 12, 11, 10, 9, 8, 3, 5, 6, 7, 2, 1})
          if (!reserved.count(p)) {
            hot_fields.emplace_back(field, gp(p));
            reserved.insert(p);
            break;
          }
      }
    }
    for (int i = 0; i < 16; i++)
      if (used_gp.count(physical[i]))
        gprs.push_back(i);
    vectors.assign(used_xmm.begin(), used_xmm.end());
    frame_size = 40 + gprs.size() * 8 + vectors.size() * 16;
    frames.resize(rounded(recipe.h.length) / PAGE * frame_size);
  }
  void address(Emitter &e, const Decoded &d) {
    auto &m = d.operands[d.memory].mem;
    if (m.base == ZYDIS_REGISTER_RIP)
      e.op(ZYDIS_MNEMONIC_MOV,
           {reg(scratch_reg), imm(d.source.address + d.source.size + m.disp.value)});
    else if (d.inst.mnemonic != ZYDIS_MNEMONIC_LEA &&
             (m.segment == ZYDIS_REGISTER_FS || m.segment == ZYDIS_REGISTER_GS))
      e.op(ZYDIS_MNEMONIC_MOV,
           {reg(scratch_reg),
            imm((m.segment == ZYDIS_REGISTER_FS ? recipe.h.fs_base : recipe.h.gs_base) +
                m.disp.value)});
    else {
      auto value = mem(m.base, m.disp.value);
      value.mem.index = m.index;
      value.mem.scale = m.scale;
      e.op(ZYDIS_MNEMONIC_LEA, {reg(scratch_reg), value});
    }
  }
  void compile() {
    bool fast_boundary = !std::getenv("AF_DISABLE_FAST_BOUNDARY");
    Emitter e;
    std::map<uint64_t, size_t> labels;
    std::vector<std::pair<size_t, uint64_t>> branches;
    std::vector<size_t> failures[2], success[2], frame_addresses;
    std::vector<uint64_t> frame_targets;
    std::vector<std::pair<size_t, uint64_t>> resume_addresses;
    auto F = [&](size_t o, unsigned n = 8) { return field(o, n); };
    e.landing();
    e.bytes.push_back(0x9c);
    for (int p : {3, 5, 12, 13, 14, 15})
      e.op(ZYDIS_MNEMONIC_PUSH, {reg(gp(p))});
    e.op(ZYDIS_MNEMONIC_MOV, {reg(context_reg), reg(ZYDIS_REGISTER_RDI)});
    for (auto [offset, r] : hot_fields)
      e.op(ZYDIS_MNEMONIC_MOV, {reg(r), mem(context_reg, offset)});
    e.op(ZYDIS_MNEMONIC_STMXCSR, {F(offsetof(State, host_mxcsr), 4)});
    e.op(ZYDIS_MNEMONIC_LDMXCSR, {F(offsetof(State, mxcsr), 4)});
    for (int i : gprs)
      e.op(ZYDIS_MNEMONIC_MOV, {reg(gp(physical[i])), F(offsetof(State, regs) + i * 8)});
    for (int i : vectors)
      e.op(ZYDIS_MNEMONIC_MOVDQU, {reg(xmm(i)), F(offsetof(State, xmm) + i * 16, 16)});
    e.op(ZYDIS_MNEMONIC_PUSH, {F(offsetof(State, regs) + 17 * 8)});
    e.bytes.push_back(0x9d);
    e.op(ZYDIS_MNEMONIC_JMP, {F(offsetof(State, entry))});
    for (auto &[pc, d] : instructions) {
      labels[pc] = e.bytes.size();
      if (block_starts.count(pc)) {
        e.landing();
        bool preserving = d.flags_in != 0;
        if (preserving)
          e.bytes.push_back(0x9c);
        size_t hot = 0;
        if (fast_boundary) {
          e.op(ZYDIS_MNEMONIC_MOV, {reg(scratch_reg), F(offsetof(State, cursor))});
          e.op(ZYDIS_MNEMONIC_CMP, {reg(scratch_reg), F(offsetof(State, trigger))});
          hot = e.jump(2);
        }
        e.op(ZYDIS_MNEMONIC_CMP, {F(offsetof(State, validating)), imm(0)});
        auto validation = e.jump(5);
        e.op(ZYDIS_MNEMONIC_MOV, {reg(scratch_reg), F(offsetof(State, cursor))});
        e.op(ZYDIS_MNEMONIC_CMP, {reg(scratch_reg), F(offsetof(State, limit))});
        auto not_limit = e.jump(5);
        // Persist the exact boundary state when yielding a validation window.
        // These stores run once per window, never on ordinary loop iterations.
        auto resume = constant(0);
        resume_addresses.emplace_back(constants.size() - 1, pc);
        e.op(ZYDIS_MNEMONIC_MOV, {reg(scratch_reg), resume});
        e.op(ZYDIS_MNEMONIC_MOV, {F(offsetof(State, entry)), reg(scratch_reg)});
        for (int i : gprs)
          e.op(ZYDIS_MNEMONIC_MOV, {F(offsetof(State, regs) + i * 8), reg(gp(physical[i]))});
        for (int i : vectors)
          e.op(ZYDIS_MNEMONIC_MOVDQU, {F(offsetof(State, xmm) + i * 16, 16), reg(xmm(i))});
        if (preserving) {
          e.op(ZYDIS_MNEMONIC_MOV, {reg(scratch_reg), mem(ZYDIS_REGISTER_RSP, 0)});
          e.op(ZYDIS_MNEMONIC_MOV, {F(offsetof(State, regs) + 17 * 8), reg(scratch_reg)});
        }
        e.op(ZYDIS_MNEMONIC_STMXCSR, {F(offsetof(State, mxcsr), 4)});
        success[preserving].push_back(e.jump());
        e.patch(not_limit, e.bytes.size());
        e.patch(validation, e.bytes.size());
        e.op(ZYDIS_MNEMONIC_CMP, {F(offsetof(State, collecting)), imm(0)});
        auto no_collect = e.jump(4);
        e.op(ZYDIS_MNEMONIC_MOV, {reg(scratch_reg), F(offsetof(State, cursor))});
        e.op(ZYDIS_MNEMONIC_CMP, {reg(scratch_reg), F(offsetof(State, end))});
        auto at_end = e.jump(4);
        e.op(ZYDIS_MNEMONIC_CMP, {reg(scratch_reg), F(offsetof(State, next_page))});
        auto before_page = e.jump(2), at_page = e.jump(4);
        e.op(ZYDIS_MNEMONIC_MOV, {F(offsetof(State, collecting)), imm(0)});
        auto no_boundary = e.jump();
        e.patch(at_page, e.bytes.size());
        e.op(ZYDIS_MNEMONIC_MOV, {reg(scratch_reg), F(offsetof(State, next_frame))});
        size_t offset = 40;
        for (int i : gprs) {
          e.op(ZYDIS_MNEMONIC_MOV, {mem(scratch_reg, offset), reg(gp(physical[i]))});
          offset += 8;
        }
        for (int i : vectors) {
          e.op(ZYDIS_MNEMONIC_MOVDQU, {mem(scratch_reg, offset, 16), reg(xmm(i))});
          offset += 16;
        }
        e.op(ZYDIS_MNEMONIC_PUSH, {reg(ZYDIS_REGISTER_RAX)});
        e.bytes.insert(e.bytes.end(), {0x48, 0xb8}); // fixed-width movabs patched below
        frame_addresses.push_back(e.bytes.size());
        frame_targets.push_back(pc);
        e.bytes.resize(e.bytes.size() + 8);
        e.op(ZYDIS_MNEMONIC_MOV, {mem(scratch_reg, 0), reg(ZYDIS_REGISTER_RAX)});
        for (auto pair : {std::pair<size_t, size_t>{8, offsetof(State, cursor)},
                          {16, offsetof(State, remaining)}}) {
          e.op(ZYDIS_MNEMONIC_MOV, {reg(ZYDIS_REGISTER_RAX), F(pair.second)});
          e.op(ZYDIS_MNEMONIC_MOV, {mem(scratch_reg, pair.first), reg(ZYDIS_REGISTER_RAX)});
        }
        e.op(ZYDIS_MNEMONIC_MOV,
             {reg(ZYDIS_REGISTER_RAX),
              preserving ? mem(ZYDIS_REGISTER_RSP, 8) : F(offsetof(State, regs) + 17 * 8)});
        e.op(ZYDIS_MNEMONIC_MOV, {mem(scratch_reg, 24), reg(ZYDIS_REGISTER_RAX)});
        e.op(ZYDIS_MNEMONIC_STMXCSR, {mem(scratch_reg, 32, 4)});
        e.op(ZYDIS_MNEMONIC_POP, {reg(ZYDIS_REGISTER_RAX)});
        e.op(ZYDIS_MNEMONIC_ADD, {F(offsetof(State, next_frame)), imm(frame_size)});
        e.op(ZYDIS_MNEMONIC_ADD, {F(offsetof(State, next_page)), imm(PAGE)});
        for (auto at : {no_collect, at_end, before_page, no_boundary})
          e.patch(at, e.bytes.size());
        if (fast_boundary) {
          e.op(ZYDIS_MNEMONIC_MOV, {reg(scratch_reg), F(offsetof(State, limit))});
          e.op(ZYDIS_MNEMONIC_CMP, {F(offsetof(State, collecting)), imm(0)});
          auto no_page = e.jump(4);
          e.op(ZYDIS_MNEMONIC_CMP, {reg(scratch_reg), F(offsetof(State, next_page))});
          auto limit_first = e.jump(6);
          e.op(ZYDIS_MNEMONIC_MOV, {reg(scratch_reg), F(offsetof(State, next_page))});
          e.patch(no_page, e.bytes.size());
          e.patch(limit_first, e.bytes.size());
          e.op(ZYDIS_MNEMONIC_MOV, {F(offsetof(State, trigger)), reg(scratch_reg)});
          e.patch(hot, e.bytes.size());
        }
        uint64_t count = 0, next = pc;
        for (;;) {
          auto found = instructions.find(next);
          if (found == instructions.end())
            break;
          count++;
          if (found->second.branch || found->second.returns)
            break;
          next += found->second.source.size;
          if (block_starts.count(next))
            break;
        }
        e.op(ZYDIS_MNEMONIC_SUB, {F(offsetof(State, remaining)), imm(count)});
        failures[preserving].push_back(e.jump(2));
        if (preserving)
          e.bytes.push_back(0x9d);
      }
      if (d.returns) {
        e.op(ZYDIS_MNEMONIC_MOV, {reg(scratch_reg), F(offsetof(State, cursor))});
        e.op(ZYDIS_MNEMONIC_CMP, {reg(scratch_reg), F(offsetof(State, end))});
        failures[0].push_back(e.jump(5));
        e.op(ZYDIS_MNEMONIC_CMP, {F(offsetof(State, remaining)), imm(0)});
        failures[0].push_back(e.jump(5));
        e.op(ZYDIS_MNEMONIC_CMP, {reg(ZYDIS_REGISTER_RAX), constant(recipe.h.result)});
        failures[0].push_back(e.jump(5));
        success[0].push_back(e.jump());
      } else if (d.branch)
        branches.emplace_back(e.jump(d.condition), d.target);
      else {
        ZydisEncoderRequest request{};
        if (!ZYAN_SUCCESS(ZydisEncoderDecodedInstructionToEncoderRequest(
                &d.inst, d.operands, d.inst.operand_count_visible, &request)))
          throw std::runtime_error("native instruction conversion failed");
        if (d.memory != -1) {
          auto &o = d.operands[d.memory];
          bool preserving = d.flags_in && d.inst.mnemonic != ZYDIS_MNEMONIC_LEA;
          if (preserving)
            e.bytes.push_back(0x9c);
          address(e, d);
          // Snapshot segments need not preserve the guest's host alignment.
          // Check virtual alignment, then use the equivalent unaligned move.
          if (d.inst.mnemonic == ZYDIS_MNEMONIC_MOVDQA ||
              d.inst.mnemonic == ZYDIS_MNEMONIC_MOVAPS ||
              d.inst.mnemonic == ZYDIS_MNEMONIC_MOVAPD) {
            e.op(ZYDIS_MNEMONIC_TEST, {reg(scratch_reg), imm(15)});
            failures[preserving].push_back(e.jump(5));
            request.mnemonic = d.inst.mnemonic == ZYDIS_MNEMONIC_MOVDQA   ? ZYDIS_MNEMONIC_MOVDQU
                               : d.inst.mnemonic == ZYDIS_MNEMONIC_MOVAPS ? ZYDIS_MNEMONIC_MOVUPS
                                                                          : ZYDIS_MNEMONIC_MOVUPD;
          }
          if (d.inst.mnemonic != ZYDIS_MNEMONIC_LEA) {
            if (o.actions == ZYDIS_OPERAND_ACTION_WRITE) {
              e.op(ZYDIS_MNEMONIC_CMP, {reg(scratch_reg), F(offsetof(State, cursor))});
              failures[preserving].push_back(e.jump(5));
              e.op(ZYDIS_MNEMONIC_ADD, {reg(scratch_reg), imm(o.size / 8)});
              failures[preserving].push_back(e.jump(2));
              e.op(ZYDIS_MNEMONIC_CMP, {reg(scratch_reg), F(offsetof(State, limit))});
              failures[preserving].push_back(e.jump(7));
              e.op(ZYDIS_MNEMONIC_MOV, {F(offsetof(State, cursor)), reg(scratch_reg)});
              e.op(ZYDIS_MNEMONIC_SUB, {reg(scratch_reg), imm(o.size / 8)});
              e.op(ZYDIS_MNEMONIC_ADD, {reg(scratch_reg), F(offsetof(State, delta))});
            } else {
              std::vector<size_t> reads;
              for (auto &input : recipe.inputs) {
                if (input.bytes.size() < o.size / 8 ||
                    (input.address < recipe.h.output + rounded(recipe.h.length) &&
                     input.address + input.bytes.size() > recipe.h.output))
                  continue;
                e.op(ZYDIS_MNEMONIC_CMP, {reg(scratch_reg), constant(input.address)});
                auto below = e.jump(2);
                e.op(ZYDIS_MNEMONIC_CMP,
                     {reg(scratch_reg), constant(input.address + input.bytes.size() - o.size / 8)});
                auto above = e.jump(7);
                e.op(ZYDIS_MNEMONIC_ADD,
                     {reg(scratch_reg),
                      constant(reinterpret_cast<uint64_t>(input.bytes.data()) - input.address)});
                reads.push_back(e.jump());
                e.patch(below, e.bytes.size());
                e.patch(above, e.bytes.size());
              }
              failures[preserving].push_back(e.jump());
              for (auto at : reads)
                e.patch(at, e.bytes.size());
            }
          }
          if (preserving)
            e.bytes.push_back(0x9d);
          auto &m = request.operands[d.memory].mem;
          m.base = scratch_reg;
          m.index = ZYDIS_REGISTER_NONE;
          m.scale = 0;
          m.displacement = 0;
          request.prefixes &= ~(ZYDIS_ATTRIB_HAS_SEGMENT_FS | ZYDIS_ATTRIB_HAS_SEGMENT_GS |
                                ZYDIS_ATTRIB_HAS_SEGMENT_CS | ZYDIS_ATTRIB_HAS_SEGMENT_DS |
                                ZYDIS_ATTRIB_HAS_SEGMENT_ES | ZYDIS_ATTRIB_HAS_SEGMENT_SS);
        }
        e.emit(request);
      }
    }
    for (auto at : failures[1])
      e.patch(at, e.bytes.size());
    e.bytes.push_back(0x9d);
    auto failed_with_flags = e.jump();
    for (auto at : failures[0])
      e.patch(at, e.bytes.size());
    e.patch(failed_with_flags, e.bytes.size());
    e.op(ZYDIS_MNEMONIC_MOV, {F(offsetof(State, error)), imm(1)});
    auto failed = e.jump();
    for (auto at : success[1])
      e.patch(at, e.bytes.size());
    e.bytes.push_back(0x9d);
    for (auto at : success[0])
      e.patch(at, e.bytes.size());
    e.patch(failed, e.bytes.size());
    for (auto [offset, r] : hot_fields)
      e.op(ZYDIS_MNEMONIC_MOV, {mem(context_reg, offset), reg(r)});
    e.op(ZYDIS_MNEMONIC_LDMXCSR, {F(offsetof(State, host_mxcsr), 4)});
    for (int p : {15, 14, 13, 12, 5, 3})
      e.op(ZYDIS_MNEMONIC_POP, {reg(gp(p))});
    e.bytes.insert(e.bytes.end(), {0x9d, 0xc3});
    for (auto [at, target] : branches)
      e.patch(at, labels.at(target));
    if (e.bytes.size() > (4ULL << 20))
      throw std::runtime_error("native code budget exceeded");
    executable_bytes = rounded(e.bytes.size());
    executable = static_cast<uint8_t *>(mmap(nullptr, executable_bytes, PROT_READ | PROT_WRITE,
                                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    if (executable == MAP_FAILED) {
      executable = nullptr;
      throw std::bad_alloc();
    }
    for (size_t i = 0; i < frame_addresses.size(); i++) {
      uint64_t address = reinterpret_cast<uint64_t>(executable + labels.at(frame_targets[i]));
      std::memcpy(e.bytes.data() + frame_addresses[i], &address, 8);
    }
    for (auto [index, pc] : resume_addresses)
      constants[index] = reinterpret_cast<uint64_t>(executable + labels.at(pc));
    std::memcpy(executable, e.bytes.data(), e.bytes.size());
    if (mprotect(executable, executable_bytes, PROT_READ | PROT_EXEC))
      throw std::runtime_error("cannot seal native replay code");
    entry_offset = labels.at(recipe.h.entry);
    instructions.clear();
    block_starts.clear();
  }
  void save_initial(State &s) {
    auto *p = frames.data();
    std::memcpy(p, &s.entry, 8);
    std::memcpy(p + 8, &s.cursor, 8);
    std::memcpy(p + 16, &s.remaining, 8);
    std::memcpy(p + 24, &s.regs[17], 8);
    std::memcpy(p + 32, &s.mxcsr, 4);
    size_t at = 40;
    for (int i : gprs) {
      std::memcpy(p + at, &s.regs[i], 8);
      at += 8;
    }
    for (int i : vectors) {
      std::memcpy(p + at, s.xmm[i], 16);
      at += 16;
    }
  }
  State &initial(std::vector<uint64_t> &storage) {
    storage.resize((sizeof(State) + constants.size() * 8 + 7) / 8);
    auto &s = *new (storage.data()) State{};
    std::memcpy(reinterpret_cast<uint8_t *>(&s) + sizeof s, constants.data(), constants.size() * 8);
    std::memcpy(s.regs, recipe.h.regs, sizeof s.regs);
    std::memcpy(s.xmm, recipe.h.xmm, sizeof s.xmm);
    s.mxcsr = recipe.h.mxcsr;
    s.entry = reinterpret_cast<uint64_t>(executable + entry_offset);
    s.remaining = recipe.h.steps;
    s.cursor = recipe.h.output;
    s.end = recipe.h.output + recipe.h.length;
    return s;
  }
  void collect(State &s) {
    s.collecting = 1;
    s.next_page = recipe.h.output + PAGE;
    s.next_frame = reinterpret_cast<uint64_t>(frames.data() + frame_size);
    save_initial(s);
  }
  void finish_collection(State &s) {
    pages = s.collecting && s.next_page >= s.end;
    if (!pages) {
      frames.clear();
      frames.shrink_to_fit();
      digests.clear();
      digests.shrink_to_fit();
    }
  }

public:
  explicit NativeReplay(const Recipe &r, af_worker_profile &p) : recipe(r), profile(p) {
    try {
      decode();
      compile();
    } catch (...) {
      if (executable)
        munmap(executable, executable_bytes);
      throw;
    }
  }
  ~NativeReplay() {
    if (executable)
      munmap(executable, executable_bytes);
  }
  NativeReplay(const NativeReplay &) = delete;
  bool pageable() const { return pages; }
  size_t retained_bytes() const {
    return sizeof(*this) + executable_bytes + frames.capacity() + constants.capacity() * 8 +
           digests.capacity() * 32 + gprs.capacity() * sizeof(int) +
           vectors.capacity() * sizeof(int) + hot_fields.capacity() * sizeof(hot_fields[0]);
  }
  template <class Sink> void validate_stream(uint8_t *window, size_t capacity, Sink sink) {
    if (!capacity || capacity % PAGE)
      throw std::runtime_error("invalid validation window");
    std::vector<uint64_t> storage;
    auto &s = initial(storage);
    collect(s);
    digests.resize(rounded(recipe.h.length) / PAGE);
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> digest(EVP_MD_CTX_new(),
                                                                   EVP_MD_CTX_free);
    if (!digest || !EVP_DigestInit_ex(digest.get(), EVP_sha256(), nullptr))
      throw std::runtime_error("cannot initialize validation digest");
    for (uint64_t offset = 0; offset < recipe.h.length;) {
      auto size = std::min(uint64_t(capacity), recipe.h.length - offset);
      s.limit = recipe.h.output + offset + size;
      s.delta = reinterpret_cast<uint64_t>(window) - s.cursor;
      // The final window must execute the return and exact instruction count.
      s.validating = s.limit == s.end;
      s.trigger = s.collecting ? std::min(s.limit, s.next_page) : s.limit;
      {
        Timer timer(profile.jit_ns);
        reinterpret_cast<void (*)(State *)>(executable)(&s);
      }
      if (s.error || s.cursor != s.limit)
        throw std::runtime_error("native validation cannot yield at the requested boundary");
      {
        Timer digest_timer(profile.digest_ns);
        if (!EVP_DigestUpdate(digest.get(), window, size))
          throw std::runtime_error("validation digest update failed");
        for (uint64_t at = 0; at < size; at += PAGE)
          if (!SHA256(window + at, std::min(PAGE, size - at), digests[(offset + at) / PAGE].data()))
            throw std::runtime_error("native page digest failed");
      }
      sink(window, size);
      offset += size;
    }
    uint8_t actual[32];
    unsigned length = 0;
    if (!EVP_DigestFinal_ex(digest.get(), actual, &length) || length != 32 ||
        std::memcmp(actual, recipe.h.digest, 32))
      throw std::runtime_error("native replay digest mismatch");
    finish_collection(s);
  }
  void run(uint8_t *output, uint64_t offset, uint64_t length, bool validate = false) {
    if (!length || offset > recipe.h.length || length > recipe.h.length - offset ||
        (offset && (!pages || offset % PAGE)) || (!validate && length != recipe.h.length && !pages))
      throw std::runtime_error("invalid native reconstruction range");
    std::vector<uint64_t> storage;
    auto &s = initial(storage);
    s.cursor = recipe.h.output + offset;
    s.end = recipe.h.output + recipe.h.length;
    s.limit = s.cursor + length;
    s.delta = reinterpret_cast<uint64_t>(output) - s.cursor;
    s.validating = validate || (offset == 0 && length == recipe.h.length);
    if (validate) {
      collect(s);
    } else if (offset) {
      const auto *p = frames.data() + offset / PAGE * frame_size;
      std::memcpy(&s.entry, p, 8);
      std::memcpy(&s.cursor, p + 8, 8);
      std::memcpy(&s.remaining, p + 16, 8);
      std::memcpy(&s.regs[17], p + 24, 8);
      std::memcpy(&s.mxcsr, p + 32, 4);
      size_t at = 40;
      for (int i : gprs) {
        std::memcpy(&s.regs[i], p + at, 8);
        at += 8;
      }
      for (int i : vectors) {
        std::memcpy(s.xmm[i], p + at, 16);
        at += 16;
      }
      if (s.cursor != recipe.h.output + offset ||
          s.entry < reinterpret_cast<uint64_t>(executable) ||
          s.entry >= reinterpret_cast<uint64_t>(executable) + executable_bytes)
        throw std::runtime_error("invalid native checkpoint");
    }
    s.trigger = s.collecting ? std::min(s.limit, s.next_page) : s.limit;
    {
      Timer timer(profile.jit_ns);
      reinterpret_cast<void (*)(State *)>(executable)(&s);
    }
    Timer digest_timer(profile.digest_ns);
    if (s.error || s.cursor != s.limit)
      throw std::runtime_error("checked native execution rejected memory or control flow");
    if (validate || (offset == 0 && length == recipe.h.length)) {
      uint8_t digest[32];
      if (!SHA256(output, length, digest) || std::memcmp(digest, recipe.h.digest, 32))
        throw std::runtime_error("native replay digest mismatch");
    }
    if (validate) {
      finish_collection(s);
      if (pages) {
        digests.resize(rounded(length) / PAGE);
        for (uint64_t at = 0; at < length; at += PAGE)
          if (!SHA256(output + at, std::min(PAGE, length - at), digests[at / PAGE].data()))
            throw std::runtime_error("native page digest failed");
      }
    } else if (pages) {
      for (uint64_t at = 0; at < length; at += PAGE) {
        uint8_t digest[32];
        if (!SHA256(output + at, std::min(PAGE, length - at), digest) ||
            std::memcmp(digest, digests[(offset + at) / PAGE].data(), 32))
          throw std::runtime_error("native page digest mismatch");
      }
    }
  }
};
} // namespace af
