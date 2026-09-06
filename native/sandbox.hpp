#pragma once
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/sched.h>
#include <linux/seccomp.h>
#include <stdexcept>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <vector>

namespace af {
inline void restrict_worker(int channel) {
  std::vector<sock_filter> f;
  auto stmt = [&](uint16_t op, uint32_t k) { f.push_back(BPF_STMT(op, k)); };
  auto jump = [&](uint16_t op, uint32_t k, uint8_t yes, uint8_t no) {
    f.push_back(BPF_JUMP(op, k, yes, no));
  };
  constexpr uint32_t denied = SECCOMP_RET_ERRNO | EPERM;
  stmt(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, arch));
  jump(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0);
  stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);
  stmt(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, nr));
  for (int nr : {SYS_read, SYS_write, SYS_sendto}) {
    jump(BPF_JMP | BPF_JEQ | BPF_K, nr, 0, 4);
    stmt(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, args[0]));
    jump(BPF_JMP | BPF_JEQ | BPF_K, static_cast<uint32_t>(channel), 0, 1);
    stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
    stmt(BPF_RET | BPF_K, denied);
  }
  // Unicorn's timeout helper is a thread. Process-creating clones are denied.
  jump(BPF_JMP | BPF_JEQ | BPF_K, SYS_clone, 0, 5);
  stmt(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, args[0]));
  jump(BPF_JMP | BPF_JSET | BPF_K, CLONE_THREAD, 0, 2);
  jump(BPF_JMP | BPF_JSET | BPF_K, CLONE_VM, 0, 1);
  stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
  stmt(BPF_RET | BPF_K, denied);
#ifdef SYS_clone3
  // glibc falls back to clone when clone3 is unavailable.
  jump(BPF_JMP | BPF_JEQ | BPF_K, SYS_clone3, 0, 1);
  stmt(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | ENOSYS);
#endif
  for (int nr : {SYS_close,
                 SYS_mmap,
                 SYS_mprotect,
                 SYS_munmap,
                 SYS_mremap,
                 SYS_madvise,
                 SYS_brk,
                 SYS_clock_gettime,
                 SYS_clock_nanosleep,
                 SYS_nanosleep,
                 SYS_futex,
                 SYS_rt_sigaction,
                 SYS_rt_sigprocmask,
                 SYS_rt_sigreturn,
                 SYS_sigaltstack,
                 SYS_getpid,
                 SYS_gettid,
                 SYS_getrusage,
                 SYS_getuid,
                 SYS_geteuid,
                 SYS_set_robust_list,
                 SYS_rseq,
                 SYS_arch_prctl,
                 SYS_sched_yield,
                 SYS_sched_getaffinity,
                 SYS_getrandom,
                 SYS_exit,
                 SYS_exit_group,
                 SYS_restart_syscall,
                 SYS_membarrier,
                 SYS_uname,
                 SYS_readlink}) {
    jump(BPF_JMP | BPF_JEQ | BPF_K, nr, 0, 1);
    stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
  }
  // No socket creation, networking, file opens/writes, exec, ptrace, or file
  // mutation syscalls are admitted. Unknown syscalls fail closed with EPERM.
  stmt(BPF_RET | BPF_K, denied);
  sock_fprog program{static_cast<unsigned short>(f.size()), f.data()};
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) ||
      prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program))
    throw std::runtime_error("cannot install replay worker seccomp policy");
}
} // namespace af
