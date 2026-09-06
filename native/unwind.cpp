#include "unwind.hpp"
#include "snapshot.hpp"
#include <Zydis.h>
#include <dlfcn.h>
#include <optional>
#include <set>

namespace af {
// GNU unwinder ABI, available with the supported glibc/GCC runtime. An FDE
// gives a function fragment extent even for stripped IFUNC implementations.
// Unsupported CIE encodings simply leave the routine outside instrumentation.
static std::optional<std::pair<uint64_t, uint64_t>> function_extent(uint64_t address) {
  struct Bases {
    void *text, *data, *function;
  };
  using Find = const uint8_t *(*)(const void *, Bases *);
  static auto find = reinterpret_cast<Find>(dlsym(RTLD_DEFAULT, "_Unwind_Find_FDE"));
  if (!find)
    return {};
  Bases bases{};
  const auto *fde = find(reinterpret_cast<const void *>(address), &bases);
  if (!fde)
    return {};
  auto word = [](const uint8_t *p) {
    uint32_t value;
    std::memcpy(&value, p, 4);
    return value;
  };
  auto size = word(fde), distance = word(fde + 4);
  if (size < 12 || size > 4096 || !distance || distance > reinterpret_cast<uint64_t>(fde + 4))
    return {};
  const auto *cie = fde + 4 - distance;
  auto cie_size = word(cie);
  if (cie_size < 12 || cie_size > 4096 || word(cie + 4) != 0)
    return {};
  const auto *cursor = cie + 8, *end = cie + 4 + cie_size;
  uint8_t version = *cursor++;
  if ((version != 1 && version != 3) || end - cursor < 3 || cursor[0] != 'z' || cursor[1] != 'R' ||
      cursor[2] != 0)
    return {};
  cursor += 3;
  auto leb = [&]() {
    for (unsigned i = 0; cursor < end && i < 10; i++)
      if (!(*cursor++ & 0x80))
        return true;
    return false;
  };
  if (!leb() || !leb())
    return {}; // Code and data alignment factors.
  if (version == 1) {
    if (cursor == end)
      return {};
    cursor++;
  } else if (!leb())
    return {};
  // zR contains exactly one augmentation byte, the pointer encoding.
  if (end - cursor < 2 || *cursor++ != 1)
    return {};
  uint8_t encoding = *cursor;
  uint64_t low, length;
  if (encoding == 0x1b) { // DW_EH_PE_pcrel | DW_EH_PE_sdata4
    int32_t displacement, extent;
    std::memcpy(&displacement, fde + 8, 4);
    std::memcpy(&extent, fde + 12, 4);
    if (extent <= 0)
      return {};
    low = reinterpret_cast<uint64_t>(fde + 8) + displacement;
    length = extent;
  } else if (encoding == 0 && size >= 20) {
    std::memcpy(&low, fde + 8, 8);
    std::memcpy(&length, fde + 16, 8);
  } else
    return {};
  if (!length || length > (1ULL << 20) || low > UINT64_MAX - length ||
      low != reinterpret_cast<uint64_t>(bases.function) || address < low || address >= low + length)
    return {};
  return std::make_pair(low, low + length);
}
// Complete the control-flow closure: assembly routines can have several FDEs.
static std::vector<std::pair<uint64_t, uint64_t>> routine_extents(uint64_t entry) {
  SnapshotReader reader;
  ZydisDecoder decoder;
  if (!ZYAN_SUCCESS(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64)))
    return {};
  std::vector<uint64_t> pending{entry};
  std::set<uint64_t> visited;
  std::set<std::pair<uint64_t, uint64_t>> ranges;
  while (!pending.empty()) {
    uint64_t pc = pending.back();
    pending.pop_back();
    while (!visited.count(pc)) {
      if (visited.size() >= 32768 || ranges.size() >= 1024)
        return {};
      auto range = function_extent(pc);
      if (!range)
        return {};
      ranges.insert(*range);
      visited.insert(pc);
      uint8_t bytes[15];
      if (!reader.copy(pc, bytes, sizeof bytes))
        return {};
      ZydisDecodedInstruction instruction;
      ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
      if (!ZYAN_SUCCESS(
              ZydisDecoderDecodeFull(&decoder, bytes, sizeof bytes, &instruction, operands)) ||
          !instruction.length || pc > UINT64_MAX - instruction.length)
        return {};
      uint64_t next = pc + instruction.length;
      if (instruction.meta.category == ZYDIS_CATEGORY_RET)
        break;
      if (instruction.meta.category == ZYDIS_CATEGORY_CALL ||
          instruction.meta.category == ZYDIS_CATEGORY_SYSCALL ||
          instruction.meta.category == ZYDIS_CATEGORY_SYSRET ||
          instruction.meta.category == ZYDIS_CATEGORY_INTERRUPT)
        return {};
      bool branch = instruction.meta.category == ZYDIS_CATEGORY_COND_BR ||
                    instruction.meta.category == ZYDIS_CATEGORY_UNCOND_BR;
      if (branch) {
        if (instruction.operand_count_visible != 1 ||
            operands[0].type != ZYDIS_OPERAND_TYPE_IMMEDIATE || !operands[0].imm.is_relative)
          return {};
        pending.push_back(next + operands[0].imm.value.s);
        if (instruction.meta.category == ZYDIS_CATEGORY_UNCOND_BR)
          break;
      }
      pc = next;
    }
  }
  return {ranges.begin(), ranges.end()};
}
std::vector<std::pair<uint64_t, uint64_t>> memory_routine_extents() {
  static const auto ranges = [] {
    std::vector<std::pair<uint64_t, uint64_t>> result;
    for (const char *name : {"memcpy", "memmove", "memset"}) {
      auto address = reinterpret_cast<uint64_t>(dlsym(RTLD_DEFAULT, name));
      auto found = routine_extents(address);
      result.insert(result.end(), found.begin(), found.end());
    }
    std::sort(result.begin(), result.end());
    result.erase(std::unique(result.begin(), result.end()), result.end());
    return result;
  }();
  return ranges;
}
} // namespace af
