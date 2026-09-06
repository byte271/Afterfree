// Small exec-only frontend. No interpreter or manager remains in the job.
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <elf.h>
#include <filesystem>
#include <fstream>
#include <limits.h>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

namespace fs = std::filesystem;
static constexpr const char *sse2 =
    "glibc.cpu.hwcaps=-AVX512VL,-AVX512BW,-AVX512F,-AVX2,-AVX,-ERMS,-FSRM";
static void environment(const char *name, const std::string &value) {
  if (setenv(name, value.c_str(), 1))
    throw std::runtime_error("cannot set execution environment");
}
static fs::path resolve(const char *command) {
  if (std::strchr(command, '/'))
    return command;
  const char *path = getenv("PATH");
  std::string search = path ? path : "/bin:/usr/bin";
  for (size_t begin = 0;;) {
    auto end = search.find(':', begin);
    auto directory = search.substr(begin, end == std::string::npos ? end : end - begin);
    auto candidate = fs::path(directory.empty() ? "." : directory) / command;
    struct stat info {};
    if (!stat(candidate.c_str(), &info) && S_ISREG(info.st_mode) &&
        !access(candidate.c_str(), X_OK))
      return candidate;
    if (end == std::string::npos)
      break;
    begin = end + 1;
  }
  throw std::runtime_error("executable not found");
}
int main(int argc, char **argv) {
  try {
    fs::path report = "afterfree.jsonl";
    bool restricted = false;
    std::string resident;
    int command = 1;
    for (; command < argc; command++) {
      std::string option = argv[command];
      if (option == "--") {
        command++;
        break;
      }
      if (option == "--help") {
        puts("Afterfree v0.1.0\nUsage: afterfree-run [--sse2] [--report PATH] [--resident-mib N] "
             "-- PROGRAM [ARGS...]");
        return 0;
      }
      if (option == "--sse2") {
        restricted = true;
        continue;
      }
      if (option != "--report" && option != "--resident-mib") {
        if (!option.empty() && option[0] == '-')
          throw std::runtime_error("unknown launcher option");
        break;
      }
      if (++command == argc)
        throw std::runtime_error("missing option value");
      if (option == "--report")
        report = argv[command];
      else {
        char *end;
        errno = 0;
        auto value = std::strtoull(argv[command], &end, 10);
        if (errno || !*argv[command] || *end || value < 1 || value > 1048576)
          throw std::runtime_error("managed resident target must be 1–1048576 MiB");
        resident = std::to_string(value * 1048576);
      }
    }
    if (command == argc)
      throw std::runtime_error("provide an executable after --");
    if (const char *preload = getenv("LD_PRELOAD"); preload && *preload)
      throw std::runtime_error(
          "run requires an empty LD_PRELOAD; combining interposers is unsupported");
    if (restricted) {
      const char *existing = getenv("GLIBC_TUNABLES");
      if (existing && *existing && std::strcmp(existing, sse2))
        throw std::runtime_error("--sse2 conflicts with existing GLIBC_TUNABLES");
      environment("GLIBC_TUNABLES", sse2);
    }
    auto executable = resolve(argv[command]);
    struct stat info {};
    if (stat(executable.c_str(), &info) || !S_ISREG(info.st_mode) ||
        access(executable.c_str(), X_OK))
      throw std::runtime_error("executable not found or not executable");
    if (info.st_mode & 06000)
      throw std::runtime_error("setuid/setgid executables are unsupported");
    std::ifstream input(executable, std::ios::binary);
    Elf64_Ehdr header{};
    if (!input.read(reinterpret_cast<char *>(&header), sizeof header) ||
        std::memcmp(header.e_ident, "\177ELF\2\1", 6) || header.e_machine != EM_X86_64 ||
        header.e_phentsize != sizeof(Elf64_Phdr) || !header.e_phnum || header.e_phnum > 4096)
      throw std::runtime_error("run requires a dynamically linked x86-64 ELF executable");
    if (header.e_phoff > uint64_t(info.st_size) ||
        uint64_t(header.e_phnum) * sizeof(Elf64_Phdr) > uint64_t(info.st_size) - header.e_phoff)
      throw std::runtime_error("invalid ELF program header");
    input.seekg(header.e_phoff);
    bool dynamic = false;
    for (unsigned i = 0; i < header.e_phnum; i++) {
      Elf64_Phdr segment{};
      if (!input.read(reinterpret_cast<char *>(&segment), sizeof segment))
        throw std::runtime_error("truncated ELF program header");
      dynamic |= segment.p_type == PT_INTERP;
    }
    input.close();
    if (!dynamic)
      throw std::runtime_error("statically linked executables are unsupported");
    char self[PATH_MAX];
    auto size = readlink("/proc/self/exe", self, sizeof self);
    if (size <= 0 || size == sizeof self)
      throw std::runtime_error("cannot locate native runtime");
    auto native = fs::path(std::string(self, size)).parent_path();
    if (!fs::exists(native / "libafterfree-preload.so") || !fs::exists(native / "afterfree-worker"))
      throw std::runtime_error("run python tools/build.py first");
    report = fs::absolute(report);
    fs::create_directories(report.parent_path());
    if (unlink(report.c_str()) && errno != ENOENT)
      throw std::runtime_error("cannot replace execution report");
    environment("LD_PRELOAD", native / "libafterfree-preload.so");
    environment("LD_BIND_NOW", "1");
    environment("AF_WORKER", native / "afterfree-worker");
    environment("AF_REPORT", report);
    if (!resident.empty())
      environment("AF_RESIDENT_TARGET", resident);
    fprintf(stderr, "Afterfree report: %s\n", report.c_str());
    execv(executable.c_str(), argv + command);
    throw std::runtime_error(std::string("exec failed: ") + std::strerror(errno));
  } catch (const std::exception &e) {
    fprintf(stderr, "afterfree: %s\n", e.what());
    return 2;
  }
}
