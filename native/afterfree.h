#pragma once
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
/* Linux x86-64, one application thread, integer/pointer SysV ABI arguments. */
typedef struct af_stats {
  uint64_t length, recipe_bytes, input_bytes, instructions, faults, evictions;
  uint64_t capture_ns, validation_ns, restore_ns, state;
  uint64_t retained_bytes, page_bytes, backend, reconstructed_bytes, full_restores;
} af_stats;
typedef struct af_residency_stats {
  uint64_t target, resident_bytes, reclaimable_bytes, over_target_bytes;
  uint64_t automatic_evictions, restore_operations, restored_bytes, peak_over_target_bytes;
} af_residency_stats;
typedef struct af_worker_profile {
  uint64_t decode_ns, compile_ns, validate_ns, restore_ns;
  uint64_t send_ns, arena_ns, trim_ns, requests, user_ns, system_ns;
  uint64_t jit_ns, digest_ns;
} af_worker_profile;
const char *af_error(void);
int af_init(const char *worker_path);
void *af_alloc(size_t size);
int af_capture(void *output, void *function, const uint64_t *args, size_t nargs, uint64_t *result);
/* Internal boundary used by the transparent executable recorder. */
int af_submit(void *output, const uint8_t *recipe, size_t size, uint64_t capture_ns);
/* Validated page-aligned subregion; allocation ownership remains unchanged. */
int af_submit_region(void *output, const uint8_t *recipe, size_t size, uint64_t capture_ns);
size_t af_size(void *output);
int af_prepare_read(const void *address, size_t size);
int af_prepare_write(void *address, size_t size);
int af_worker_procfs_pid(void);
/* Internal interposer guard: propagation of an unrelated fault must retain
 * the application's original signal behavior. */
int af_handling_fault(void);
int af_evict(void *output);
/* Soft managed-buffer target, not a process RSS or cgroup limit. Zero selects
 * eager eviction for af_manage(); explicit af_evict() remains unchanged. */
int af_set_resident_target(uint64_t bytes);
int af_manage(void *newly_sealed);
int af_get_residency_stats(af_residency_stats *stats);
int af_materialize(void *output);
int af_get_stats(void *output, af_stats *stats);
int af_resident_pages(void *output);
int af_worker_pid(void);
uint64_t af_worker_peak_rss(void);
int af_get_worker_profile(af_worker_profile *profile);
int af_free(void *output);
int af_shutdown(void);
#ifdef __cplusplus
}
#endif
