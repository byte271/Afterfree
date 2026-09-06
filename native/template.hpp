#pragma once
#include "recorder.hpp"
#include "snapshot.hpp"

namespace af {
// A template keeps code, input locations and guarded control-flow bindings.
// It is speculative: a current invocation must pass full independent validation.
struct RecipeTemplate {
  Header original;
  bool native_dispatch = false;
  std::vector<std::pair<uint64_t, uint64_t>> jump_bindings;
  std::vector<uint64_t> pages;
  std::vector<Instruction> code;
  std::vector<std::pair<uint64_t, size_t>> inputs;
  uint64_t stack_low = 0, stack_high = 0, used = 0;
  size_t bytes() const {
    return sizeof(*this) + pages.capacity() * sizeof(uint64_t) +
           code.capacity() * sizeof(Instruction) + inputs.capacity() * sizeof(inputs[0]) +
           jump_bindings.capacity() * sizeof(jump_bindings[0]);
  }
  explicit RecipeTemplate(const Recipe &recipe, bool checked_native)
      : original(recipe.h), native_dispatch(checked_native), pages(recipe.pages),
        code(recipe.code) {
    for (const auto &instruction : recipe.code) {
      uint64_t slot, target;
      if (rip_jump_slot(instruction, slot) && read_snapshot(recipe, slot, &target, 8))
        jump_bindings.emplace_back(slot, target);
    }
    for (const auto &input : recipe.inputs)
      inputs.emplace_back(input.address, input.bytes.size());
    FILE *f = std::fopen("/proc/self/maps", "r");
    if (!f)
      return;
    char line[8192];
    while (std::fgets(line, sizeof line, f)) {
      unsigned long low, high;
      if (std::sscanf(line, "%lx-%lx", &low, &high) == 2 && original.regs[15] >= low &&
          original.regs[15] < high) {
        stack_low = low;
        stack_high = high;
        break;
      }
    }
    std::fclose(f);
  }
  bool instantiate(Recorder &record, QBDI::GPRState *g, QBDI::FPRState *f) const {
    if (record.recipe.h.length != original.length || !stack_low)
      return false;
    auto output = record.recipe.h.output;
    SnapshotReader reader;
    auto relocate = [&](uint64_t p) -> uint64_t {
      if (p >= original.output && p < original.output + rounded(original.length))
        return output + (p - original.output);
      if (p >= stack_low && p < stack_high)
        return p - original.regs[15] + g->rsp;
      return p;
    };
    for (const auto &instruction : code) {
      uint8_t current[15];
      if (!reader.copy(instruction.address, current, instruction.size) ||
          std::memcmp(current, instruction.bytes, instruction.size))
        return false;
    }
    for (auto [slot, expected] : jump_bindings) {
      uint64_t actual;
      if (!reader.copy(slot, &actual, sizeof actual) || actual != expected)
        return false;
    }
    Recipe recipe;
    recipe.h = original;
    recipe.h.output = output;
    recipe.h.entry = g->rip;
    recipe.h.fs_base = record.recipe.h.fs_base;
    recipe.h.gs_base = record.recipe.h.gs_base;
    recipe.h.mxcsr = f->mxcsr;
    std::memcpy(recipe.h.regs, g, sizeof recipe.h.regs);
    std::memcpy(recipe.h.xmm, f->xmm0, sizeof recipe.h.xmm);
    if (!reader.copy(g->rsp, &recipe.h.stop, sizeof recipe.h.stop))
      return false;
    recipe.code = code;
    std::set<uint64_t> relocated;
    for (auto p : pages) {
      auto first = relocate(p), last = relocate(p + PAGE - 1);
      if (last < first || last - first != PAGE - 1)
        return false;
      relocated.insert(base(first));
      relocated.insert(base(last));
    }
    recipe.pages.assign(relocated.begin(), relocated.end());
    for (auto [p, size] : inputs) {
      auto address = relocate(p);
      Segment input{address, std::vector<uint8_t>(size)};
      if (!reader.copy(address, input.bytes.data(), size))
        return false;
      recipe.inputs.push_back(std::move(input));
    }
    record.recipe = std::move(recipe);
    record.steps = original.steps;
    record.live_bytes = original.input_bytes;
    record.began = true;
    return true;
  }
};
class TemplateCache {
  static constexpr size_t LIMIT = 8ULL << 20;
  std::map<uint64_t, RecipeTemplate> entries;
  uint64_t clock = 0;
  size_t retained = 0;

public:
  size_t peak_bytes = 0;
  RecipeTemplate *get(uint64_t entry) {
    auto it = entries.find(entry);
    if (it == entries.end())
      return nullptr;
    it->second.used = ++clock;
    return &it->second;
  }
  void erase(uint64_t entry) {
    auto it = entries.find(entry);
    if (it != entries.end()) {
      retained -= it->second.bytes();
      entries.erase(it);
    }
  }
  void put(const Recipe &recipe, bool checked_native = false) {
    RecipeTemplate value(recipe, checked_native);
    size_t size = value.bytes();
    if (size > LIMIT)
      return;
    erase(recipe.h.entry);
    while (!entries.empty() && (retained + size > LIMIT || entries.size() >= 64)) {
      auto oldest = entries.begin();
      for (auto it = entries.begin(); it != entries.end(); ++it)
        if (it->second.used < oldest->second.used)
          oldest = it;
      erase(oldest->first);
    }
    value.used = ++clock;
    entries.emplace(recipe.h.entry, std::move(value));
    retained += size;
    peak_bytes = std::max(peak_bytes, retained);
  }
};
} // namespace af
