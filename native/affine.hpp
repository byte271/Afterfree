#pragma once
#include "x86.hpp"

namespace af::x86 {
// A proof over decoded instructions, independent of workload names or values.
// Each iteration has at most one pure access of the requested kind. Its
// address changes by exactly its width under 64-bit modular arithmetic. Other
// memory effects or unproved address mutations retain the checked path.
struct AffineAccess {
  ZydisRegister base = ZYDIS_REGISTER_NONE, index = ZYDIS_REGISTER_NONE;
  unsigned scale = 0, width = 0, count = 0;
  uint64_t prefix = 0, base_delta = 0, index_delta = 0;
  static AffineAccess prove(const uint8_t *bytes, size_t size,
                            ZydisOperandActions action = ZYDIS_OPERAND_ACTION_WRITE) {
    struct Operation {
      ZydisDecodedInstruction d{};
      ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT]{};
    };
    AffineAccess result;
    std::vector<Operation> body;
    size_t access_at = 0;
    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
    for (size_t off = 0; off < size;) {
      Operation op;
      if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, bytes + off, size - off, &op.d, op.ops)) ||
          op.d.encoding != ZYDIS_INSTRUCTION_ENCODING_LEGACY ||
          op.d.meta.category == ZYDIS_CATEGORY_COND_BR ||
          op.d.meta.category == ZYDIS_CATEGORY_UNCOND_BR ||
          op.d.meta.category == ZYDIS_CATEGORY_CALL || op.d.meta.category == ZYDIS_CATEGORY_RET)
        throw std::runtime_error("affine proof requires a straight-line body");
      for (unsigned i = 0; i < op.d.operand_count; i++)
        if (op.ops[i].type == ZYDIS_OPERAND_TYPE_MEMORY && op.d.mnemonic != ZYDIS_MNEMONIC_NOP) {
          auto &o = op.ops[i];
          if (o.mem.base == ZYDIS_REGISTER_RIP || op.d.address_width != 64)
            throw std::runtime_error("affine proof needs ordinary 64-bit addresses");
          if (op.d.mnemonic == ZYDIS_MNEMONIC_LEA)
            continue;
          if (result.width || i >= op.d.operand_count_visible || o.actions != action || !o.size ||
              o.size > 128 || o.size % 8 || o.mem.segment == ZYDIS_REGISTER_FS ||
              o.mem.segment == ZYDIS_REGISTER_GS)
            throw std::runtime_error("affine proof requires one pure memory access");
          result.base = o.mem.base;
          result.index = o.mem.index;
          result.scale = o.mem.scale;
          result.width = o.size / 8;
          result.prefix = o.mem.disp.value;
          access_at = body.size();
        }
      off += op.d.length;
      body.push_back(op);
    }
    result.count = body.size();
    if (!result.width)
      return result;
    uint64_t total = 0;
    for (size_t n = 0; n < body.size(); n++) {
      auto &op = body[n];
      for (unsigned i = 0; i < op.d.operand_count; i++) {
        auto &o = op.ops[i];
        if (o.type != ZYDIS_OPERAND_TYPE_REGISTER || !(o.actions & ZYDIS_OPERAND_ACTION_MASK_WRITE))
          continue;
        auto largest = ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, o.reg.value);
        if (largest != result.base && largest != result.index)
          continue;
        if (o.reg.value != largest || i != 0)
          throw std::runtime_error("affine proof rejects partial address writes");
        uint64_t delta;
        if ((op.d.mnemonic == ZYDIS_MNEMONIC_ADD || op.d.mnemonic == ZYDIS_MNEMONIC_SUB) &&
            op.ops[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
          delta = op.ops[1].imm.value.u;
          if (op.d.mnemonic == ZYDIS_MNEMONIC_SUB)
            delta = uint64_t(0) - delta;
        } else if (op.d.mnemonic == ZYDIS_MNEMONIC_INC || op.d.mnemonic == ZYDIS_MNEMONIC_DEC)
          delta = op.d.mnemonic == ZYDIS_MNEMONIC_INC ? 1 : UINT64_MAX;
        else if (op.d.mnemonic == ZYDIS_MNEMONIC_LEA && op.d.address_width == 64 &&
                 op.ops[1].mem.base == largest && op.ops[1].mem.index == ZYDIS_REGISTER_NONE)
          delta = op.ops[1].mem.disp.value;
        else
          throw std::runtime_error("affine proof rejects data-dependent address changes");
        if (largest == result.base)
          result.base_delta += delta;
        if (largest == result.index)
          result.index_delta += delta;
        auto change = delta * ((largest == result.base ? 1 : 0) +
                               (largest == result.index ? result.scale : 0));
        total += change;
        if (n < access_at)
          result.prefix += change;
      }
    }
    if (total != result.width)
      throw std::runtime_error("affine proof rejects non-contiguous accesses");
    return result;
  }
};
} // namespace af::x86
