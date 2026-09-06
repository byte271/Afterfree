#pragma once
#include "common.hpp"
#include <Zydis.h>

namespace af::x86 {
struct Emitter {
  std::vector<uint8_t> bytes;
  void emit(ZydisEncoderRequest request) {
    uint8_t data[15];
    ZyanUSize size = sizeof data;
    if (!ZYAN_SUCCESS(ZydisEncoderEncodeInstruction(&request, data, &size)))
      throw std::runtime_error("native instruction encoding failed");
    bytes.insert(bytes.end(), data, data + size);
  }
  void op(ZydisMnemonic mnemonic, std::initializer_list<ZydisEncoderOperand> operands) {
    ZydisEncoderRequest request{};
    request.machine_mode = ZYDIS_MACHINE_MODE_LONG_64;
    request.allowed_encodings = ZYDIS_ENCODABLE_ENCODING_LEGACY;
    request.mnemonic = mnemonic;
    request.operand_count = operands.size();
    std::copy(operands.begin(), operands.end(), request.operands);
    emit(request);
  }
  void landing() { bytes.insert(bytes.end(), {0xf3, 0x0f, 0x1e, 0xfa}); }
  size_t jump(int condition = -1) {
    if (condition < 0)
      bytes.push_back(0xe9);
    else {
      bytes.push_back(0x0f);
      bytes.push_back(0x80 + condition);
    }
    size_t result = bytes.size();
    bytes.resize(result + 4);
    return result;
  }
  void patch(size_t at, size_t target) {
    int64_t distance = int64_t(target) - int64_t(at + 4);
    if (distance < INT32_MIN || distance > INT32_MAX)
      throw std::runtime_error("native branch exceeds displacement range");
    int32_t value = distance;
    std::memcpy(bytes.data() + at, &value, sizeof value);
  }
};
inline ZydisEncoderOperand reg(ZydisRegister value) {
  ZydisEncoderOperand r{};
  r.type = ZYDIS_OPERAND_TYPE_REGISTER;
  r.reg.value = value;
  return r;
}
inline ZydisEncoderOperand imm(uint64_t value) {
  ZydisEncoderOperand r{};
  r.type = ZYDIS_OPERAND_TYPE_IMMEDIATE;
  r.imm.u = value;
  return r;
}
inline ZydisEncoderOperand mem(ZydisRegister base_reg, int64_t offset, unsigned size = 8) {
  ZydisEncoderOperand r{};
  r.type = ZYDIS_OPERAND_TYPE_MEMORY;
  r.mem.base = base_reg;
  r.mem.displacement = offset;
  r.mem.size = size;
  return r;
}
// QBDI's saved-register order, translated to x86 register numbers.
static constexpr int physical[16] = {0, 3, 1, 2, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 5, 4};
inline ZydisRegister gp(int index) { return ZydisRegister(ZYDIS_REGISTER_RAX + index); }
inline ZydisRegister xmm(int index) { return ZydisRegister(ZYDIS_REGISTER_XMM0 + index); }
inline bool permitted(ZydisMnemonic mnemonic) {
  switch (mnemonic) {
  case ZYDIS_MNEMONIC_MOV:
  case ZYDIS_MNEMONIC_MOVZX:
  case ZYDIS_MNEMONIC_MOVSX:
  case ZYDIS_MNEMONIC_MOVSXD:
  case ZYDIS_MNEMONIC_LEA:
  case ZYDIS_MNEMONIC_ADD:
  case ZYDIS_MNEMONIC_SUB:
  case ZYDIS_MNEMONIC_IMUL:
  case ZYDIS_MNEMONIC_AND:
  case ZYDIS_MNEMONIC_OR:
  case ZYDIS_MNEMONIC_XOR:
  case ZYDIS_MNEMONIC_NOT:
  case ZYDIS_MNEMONIC_NEG:
  case ZYDIS_MNEMONIC_SHL:
  case ZYDIS_MNEMONIC_SHR:
  case ZYDIS_MNEMONIC_SAR:
  case ZYDIS_MNEMONIC_ROL:
  case ZYDIS_MNEMONIC_ROR:
  case ZYDIS_MNEMONIC_CMP:
  case ZYDIS_MNEMONIC_TEST:
  case ZYDIS_MNEMONIC_INC:
  case ZYDIS_MNEMONIC_DEC:
  case ZYDIS_MNEMONIC_ADC:
  case ZYDIS_MNEMONIC_SBB:
  case ZYDIS_MNEMONIC_CLC:
  case ZYDIS_MNEMONIC_STC:
  case ZYDIS_MNEMONIC_CMC:
  case ZYDIS_MNEMONIC_NOP:
  case ZYDIS_MNEMONIC_ENDBR64:
  case ZYDIS_MNEMONIC_MOVD:
  case ZYDIS_MNEMONIC_MOVQ:
  case ZYDIS_MNEMONIC_MOVDQA:
  case ZYDIS_MNEMONIC_MOVDQU:
  case ZYDIS_MNEMONIC_MOVAPS:
  case ZYDIS_MNEMONIC_MOVUPS:
  case ZYDIS_MNEMONIC_MOVAPD:
  case ZYDIS_MNEMONIC_MOVUPD:
  case ZYDIS_MNEMONIC_MOVSD:
  case ZYDIS_MNEMONIC_MOVSS:
  case ZYDIS_MNEMONIC_PXOR:
  case ZYDIS_MNEMONIC_PAND:
  case ZYDIS_MNEMONIC_POR:
  case ZYDIS_MNEMONIC_PADDQ:
  case ZYDIS_MNEMONIC_PADDD:
  case ZYDIS_MNEMONIC_PADDW:
  case ZYDIS_MNEMONIC_PADDB:
  case ZYDIS_MNEMONIC_PSUBQ:
  case ZYDIS_MNEMONIC_PSUBD:
  case ZYDIS_MNEMONIC_PSUBW:
  case ZYDIS_MNEMONIC_PSUBB:
  case ZYDIS_MNEMONIC_PSLLQ:
  case ZYDIS_MNEMONIC_PSRLQ:
  case ZYDIS_MNEMONIC_PSLLD:
  case ZYDIS_MNEMONIC_PSRLD:
  case ZYDIS_MNEMONIC_PSHUFD:
  case ZYDIS_MNEMONIC_XORPS:
  case ZYDIS_MNEMONIC_XORPD:
  case ZYDIS_MNEMONIC_ADDSD:
  case ZYDIS_MNEMONIC_ADDSS:
  case ZYDIS_MNEMONIC_ADDPD:
  case ZYDIS_MNEMONIC_ADDPS:
  case ZYDIS_MNEMONIC_SUBSD:
  case ZYDIS_MNEMONIC_SUBSS:
  case ZYDIS_MNEMONIC_MULSD:
  case ZYDIS_MNEMONIC_MULSS:
  case ZYDIS_MNEMONIC_MULPD:
  case ZYDIS_MNEMONIC_MULPS:
  case ZYDIS_MNEMONIC_CVTSI2SD:
  case ZYDIS_MNEMONIC_CVTSI2SS:
    return true;
  default:
    return false;
  }
}
} // namespace af::x86
