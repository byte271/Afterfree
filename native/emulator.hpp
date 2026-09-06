#pragma once
#include "byte_mask.hpp"
#include "common.hpp"
#include <algorithm>
#include <map>
#include <openssl/sha.h>
#include <set>
#include <sys/mman.h>
#include <unicorn/unicorn.h>
#include <unordered_map>

namespace af {
static void check(uc_err e) {
  if (e != UC_ERR_OK)
    throw std::runtime_error(uc_strerror(e));
}
struct Replay {
  uc_engine *uc = nullptr;
  uint8_t *output = nullptr;
  uint64_t length = 0, mapped = 0, steps = 0;
  std::unordered_map<uint64_t, ByteMask> initialized;
  std::unordered_map<uint64_t, Instruction> code;
  struct Block {
    uint32_t size;
    uint64_t instructions;
  };
  std::unordered_map<uint64_t, Block> blocks;
  uint64_t expected_steps = 0;
  uint64_t output_address = 0;
  std::vector<ByteMask> output_written;
  std::string error;
  bool checking = false;
  ~Replay() {
    if (uc)
      uc_close(uc);
    if (output && output != MAP_FAILED)
      munmap(output, mapped);
  }
  void fail(const char *why) {
    if (error.empty())
      error = why;
    uc_emu_stop(uc);
  }
  static void instruction(uc_engine *, uint64_t addr, uint32_t size, void *ctx) {
    auto &r = *static_cast<Replay *>(ctx);
    auto block = r.blocks.find(addr);
    if (block == r.blocks.end()) {
      if (!size || size > 65536 || addr > UINT64_MAX - size) {
        r.fail("invalid replay block");
        return;
      }
      uint64_t count = 0, pc = addr;
      while (pc < addr + size) {
        auto it = r.code.find(pc);
        if (it == r.code.end() || it->second.size > addr + size - pc) {
          r.fail("replay reached unobserved code");
          return;
        }
        uint8_t current[15];
        const auto &c = it->second;
        if (uc_mem_read(r.uc, pc, current, c.size) != UC_ERR_OK ||
            std::memcmp(current, c.bytes, c.size)) {
          r.fail("replay code changed");
          return;
        }
        pc += c.size;
        count++;
      }
      block = r.blocks.emplace(addr, Block{size, count}).first;
    }
    // Executable pages are immutable RX mappings. A verified block therefore
    // needs no repeated byte comparisons, but every execution is counted.
    if (block->second.size != size) {
      r.fail("replay block changed");
      return;
    }
    r.steps += block->second.instructions;
    if (r.steps > r.expected_steps)
      r.fail("replay instruction bound exceeded");
  }
  static void memory(uc_engine *, uc_mem_type type, uint64_t addr, int size, int64_t, void *ctx) {
    auto &r = *static_cast<Replay *>(ctx);
    if (!r.checking || size <= 0)
      return;
    if (addr > UINT64_MAX - size) {
      r.fail("replay address overflow");
      return;
    }
    while (size) {
      auto it = r.initialized.find(base(addr));
      if (it == r.initialized.end()) {
        r.fail("replay touched an unobserved page");
        return;
      }
      auto off = addr % PAGE;
      auto count = std::min(uint64_t(size), PAGE - off);
      if (type == UC_MEM_READ && !it->second.all(off, count)) {
        r.fail("replay read a missing input byte");
        return;
      }
      if (type == UC_MEM_WRITE)
        it->second.mark(off, count);
      if (type == UC_MEM_WRITE && addr >= r.output_address && addr < r.output_address + r.length)
        r.output_written[(addr - r.output_address) / PAGE].mark(
            off, std::min(count, r.output_address + r.length - addr));
      addr += count;
      size -= count;
    }
  }
  void run(const Recipe &r, bool strict = true) {
    const auto &h = r.h;
    expected_steps = h.steps;
    output_address = h.output;
    length = h.length;
    mapped = rounded(length);
    if (strict)
      output_written.resize(mapped / PAGE);
    output = static_cast<uint8_t *>(
        mmap(nullptr, mapped, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    if (output == MAP_FAILED)
      throw std::runtime_error("worker output allocation failed");
    check(uc_open(UC_ARCH_X86, UC_MODE_64, &uc));
    // QEMU's CPU model is fixed so replay cannot consult the host CPU feature
    // set.
    check(uc_ctl_set_cpu_model(uc, UC_CPU_X86_HASWELL));
    check(uc_mem_map_ptr(uc, h.output, mapped, UC_PROT_READ | UC_PROT_WRITE, output));
    std::set<uint64_t> all(r.pages.begin(), r.pages.end());
    if (all.size() != r.pages.size())
      throw std::runtime_error("duplicate recipe page");
    for (uint64_t p = h.output; p < h.output + mapped; p += PAGE)
      all.insert(p);
    for (auto &c : r.code) {
      all.insert(base(c.address));
      all.insert(base(c.address + c.size - 1));
      if (!code.emplace(c.address, c).second)
        throw std::runtime_error("duplicate instruction");
    }
    if (all.size() * PAGE > mapped + h.length / 4 + (4ULL << 20))
      throw std::runtime_error("replay scratch exceeds the group budget");
    for (auto p : all) {
      if (strict)
        initialized.emplace(p, ByteMask{});
      if (p < h.output || p >= h.output + mapped)
        check(uc_mem_map(uc, p, PAGE, UC_PROT_READ | UC_PROT_WRITE));
    }
    for (auto &s : r.inputs) {
      check(uc_mem_write(uc, s.address, s.bytes.data(), s.bytes.size()));
      for (size_t i = 0; strict && i < s.bytes.size(); i++) {
        auto it = initialized.find(base(s.address + i));
        if (it == initialized.end())
          throw std::runtime_error("input outside mapped pages");
        it->second.set((s.address + i) % PAGE);
      }
    }
    for (auto &c : r.code) {
      if (c.address < h.output + mapped && c.address + c.size > h.output)
        throw std::runtime_error("output overlaps code");
      check(uc_mem_write(uc, c.address, c.bytes, c.size));
      for (unsigned i = 0; strict && i < c.size; i++)
        initialized.at(base(c.address + i)).set((c.address + i) % PAGE);
    }
    std::set<uint64_t> executable_pages;
    for (auto &c : r.code) {
      executable_pages.insert(base(c.address));
      executable_pages.insert(base(c.address + c.size - 1));
    }
    for (auto p : executable_pages)
      check(uc_mem_protect(uc, p, PAGE, UC_PROT_READ | UC_PROT_EXEC));
    int regs[] = {UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX,   UC_X86_REG_RDX, UC_X86_REG_RSI,
                  UC_X86_REG_RDI, UC_X86_REG_R8,  UC_X86_REG_R9,    UC_X86_REG_R10, UC_X86_REG_R11,
                  UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14,   UC_X86_REG_R15, UC_X86_REG_RBP,
                  UC_X86_REG_RSP, UC_X86_REG_RIP, UC_X86_REG_EFLAGS};
    for (size_t i = 0; i < 18; i++)
      check(uc_reg_write(uc, regs[i], &h.regs[i]));
    for (int i = 0; i < 16; i++)
      check(uc_reg_write(uc, UC_X86_REG_XMM0 + i, h.xmm[i]));
    check(uc_reg_write(uc, UC_X86_REG_MXCSR, &h.mxcsr));
    check(uc_reg_write(uc, UC_X86_REG_FS_BASE, &h.fs_base));
    check(uc_reg_write(uc, UC_X86_REG_GS_BASE, &h.gs_base));
    uc_hook hc, hm;
    if (strict)
      check(uc_hook_add(uc, &hc, UC_HOOK_BLOCK, reinterpret_cast<void *>(instruction), this, 1, 0));
    if (strict)
      check(uc_hook_add(uc, &hm, UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE,
                        reinterpret_cast<void *>(memory), this, 1, 0));
    checking = true;
    auto e = uc_emu_start(uc, h.entry, h.stop, 30000000, 0);
    checking = false;
    if (!error.empty())
      throw std::runtime_error(error);
    check(e);
    uint64_t rip = 0, rax = 0;
    check(uc_reg_read(uc, UC_X86_REG_RIP, &rip));
    check(uc_reg_read(uc, UC_X86_REG_RAX, &rax));
    if (rip != h.stop || rax != h.result || (strict && steps != h.steps))
      throw std::runtime_error("replay control flow or return value diverged");
    for (uint64_t offset = 0; strict && offset < length; offset += PAGE)
      if (!output_written[offset / PAGE].all(0, std::min(PAGE, length - offset)))
        throw std::runtime_error("replay did not produce every output byte");
    uint8_t digest[32];
    if (!SHA256(output, length, digest))
      throw std::runtime_error("replay digest calculation failed");
    if (std::memcmp(digest, h.digest, 32))
      throw std::runtime_error("replay output digest mismatch");
  }
};
} // namespace af
