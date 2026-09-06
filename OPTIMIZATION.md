# Afterfree v0.1.0 — architecture and measured outcome

**The hard goals remain unmet.** The final paired 64 MiB run is 0.573 s versus
0.936 s for the frozen preceding release: 1.63× faster. It is still 8.26× native.
No unchanged real application demonstrates net RSS savings. This is a research
build, not a production-ready memory-saving release.

The historical 0.481 s is not a valid same-session baseline: this host became
slower and variable. Before any edits, the frozen binary measured about 0.811 s.
All final trials, outliers, failed probes, and hashes are retained. The separate
ablation's faster complete-configuration median (0.445 s) does not replace the
paired comparison's 0.573 s headline.

## What the profile actually shows

Whole-buffer instruction tracing was no longer the only large cost. Inline
capture reduces the accepted 4 MiB producer from 1,048,581 callbacks to **7**;
in the final ablation its detailed phase is 8.45 ms versus 80.77 ms with QBDI
capture. Every executed instruction and output write remains accounted for.

Worker digest work now dominates generated execution: medians of **177.65 ms
hashing versus 44.78 ms compiled execution** in the complete ablation. Digest
work includes full-output and page SHA-256 checks. The worker also waits for
transactional validation acknowledgements. These clocks are inclusive wall
measurements, not hardware counters, and must not be added to overlapping
parent phases. CPU counters and all raw events are included in the reports.

Demand faults and small requests impose another cost. Proved read plans reduce
this job from **1,088 to 272** reconstruction requests. The original consumer
still reads every byte; reconstruction remains exactly 64 MiB. The complete
ablation is 0.445 s versus 0.651 s with read plans disabled. No timing claim uses
an output-only shortcut or an incompletely reconstructed job.

## Architectural decisions

| Mechanism | Decision and correctness boundary |
|---|---|
| Inline native capture | Retained. A shared instruction proof permits one contiguous pure store per straight-line iteration. Inline guards record exact frontier and instruction counts. Other producers retain QBDI observation. |
| Proved read plans | Retained. A read-only loop must have one contiguous load, an affine 64-bit counter, an invariant bound, and an exact unsigned/equality termination test. Only its proved future span is prepared. Data-dependent exits, reverse/gapped scans, changing bounds, and short reads stay on the demand path. |
| Fused replay boundary | Retained. A cached next boundary combines window and checkpoint checks. Original memory, instruction-budget, return-state and digest checks remain. |
| Affine replay loop fast path | Removed. It passed tests and actually executed, but added code and proof obligations without a reliable advantage over the simpler checked compiler. Its source and measurements are frozen separately. |
| Region admission | Retained. One sufficiently large fully written page-aligned region may be validated and discarded inside an otherwise resident allocation. Untouched prefix/suffix bytes remain owned by the original allocation. Writes outside the region do not invalidate it; overlapping writes pin it. |
| Bounded shared window | 256 KiB default. A 64/256/1024 KiB comparison retained every byte check. The 1 MiB option reduced handoffs but charged about 1.5 MiB more aggregate RSS than 256 KiB, so it is not the default. Isolated reads still restore 4 KiB. |
| Native exec frontend | Retained. `afterfree/_native/afterfree-run` performs ELF/environment/report checks and execs the unchanged target. Python `afterfree run` delegates to the same implementation; duplicated Python launch validation was removed. |
| Reusable OpenSSL digest context | Tested, not retained. Small isolated gains did not resolve the dominant digest throughput cost. |
| Eight-page SIMD SHA-256 | Rejected. All 100 eight-page differential batches matched OpenSSL, but timing was no better. No custom cryptographic code remains in the runtime. |

The new proof helper is shared by capture and read planning. Exception guards
prevent code-read failures from crossing the VM callback; snapshot map-reading
now closes its descriptor on allocation failure. Region accounting, outside
writes, boundaries, partial tails, and reconstruction workspace have dedicated
regression coverage. Build jobs remain in one staged list; all compiler warnings
are errors. These changes add capability and tests, so the source tree is not
smaller overall. Removing tests or guards to meet a line-count target would be
misleading.

## Fixed final comparison

Seconds and estimated MiB; RSS columns are native / frozen Afterfree / current
Afterfree. Three fresh-process trials per row, alternating version order, the
same frozen executable and producer library, same glibc CPU settings, and eager
eviction. Both frontends' complete lifetimes count: the old release uses Python,
and the current release uses its public native launcher.

| Workload | Native s | Frozen s | Current s | Current/native | RSS MiB: native / frozen / current |
|---|---:|---:|---:|---:|---:|
| 4x1MiB | 0.0089 | 0.1442 | 0.0586 | 6.61× | 4.38 / 22.30 / 20.54 |
| 16x4MiB | 0.0694 | 0.9357 | 0.5730 | 8.26× | 64.50 / 24.69 / 25.40 |
| 4x8MiB | 0.0388 | 0.6386 | 0.2571 | 6.63× | 32.38 / 27.80 / 28.15 |

All 18 transformed runs pass exact complete stdout hash/length, required recipe
admissions/evictions, full restoration counts, exact reconstructed-byte volume,
worker accounting, and zero swap. The 64 MiB synthetic RSS is **25.40 MiB**, up
from the frozen build's 24.69 MiB; this memory cost is not hidden. It is about
39.4% of native's 64.50 MiB. Small jobs still lose memory.

[Paired runs](docs/evidence/range-final-comparison.json),
[controlled ablation](docs/evidence/range-final-ablation.json),
[window comparison](docs/evidence/range-window-ablation.json),
[rejected hash experiments with reproducible source](docs/evidence/range-hash-hypotheses.json).

## Unchanged real native applications

Every case below is retained. Seconds and estimated MiB are native / Afterfree.
Failed executions have no usable-performance or memory-saving interpretation.

| Program and frozen input | Seconds | RSS MiB | Output |
|---|---:|---:|---|
| upstream: repeated | 0.005 / 0.192 | 0.95 / 25.66 | exact |
| upstream: sparse | 0.004 / 0.304 | 0.95 / 25.61 | exact |
| upstream: random | 0.010 / 0.257 | 0.92 / 19.62 | exact |
| gzip: repeated | 0.074 / 0.171 | 0.62 / 19.08 | exact |
| gzip: sparse | 0.011 / 0.186 | 0.62 / 19.23 | exact |
| gzip: random | 0.010 / 0.401 | 0.88 / 19.07 | exact |
| zstd: qbdi.tar.gz-level3 | 0.048 / 5.086 | 4.25 / 32.02 | exact |
| zstd: zydis-amalgamated.tar.gz-level19 | 0.099 / 2.838 | 82.29 / 107.62 | exact |
| ffmpeg: color-small | 0.056 / 0.606 | 30.64 / unavailable | refused, exit 193 |
| ffmpeg: color-large | 0.090 / 0.823 | 53.24 / unavailable | refused, exit 193 |
| ffmpeg: pattern-large | 0.144 / 1.099 | 107.23 / unavailable | refused, exit 193 |
| imagemagick: gradient-2048 | 0.257 / 0.080 | 37.71 / unavailable | refused, exit 196 |
| imagemagick: gradient-4096 | 0.935 / 0.086 | 133.81 / unavailable | refused, exit 196 |

LZ4, gzip, and Zstandard accept no useful recipes in these probes. Eight complete
outputs match exactly, but every successful real application uses more total
RSS. The large Zstandard case is particularly informative: native uses about
82 MiB, yet Afterfree still adds memory instead of reclaiming enough of it.
FFmpeg remains outside the single-thread contract even with matching
`-threads 1`, filter-thread limits, and `-cpucount 1`. ImageMagick replaces the
SIGSEGV handler. Their refusals are compatibility failures, not speedups.

[Rejection counts](docs/evidence/range-rejection-summary.json) show that incomplete
production is only one obstacle. The level-3 Zstandard run has 100 rejected calls
leaving instrumented modules, 54 AVX-load rejections, 21 prefetch rejections,
20 TZCNT rejections, and 14 incomplete-output rejections. Broadening region
admission did not admit these calls. The runtime is not assuming memory remains
correct across unobserved calls or unsupported register state.

There are structural reasons synthetic savings fail to transfer. Candidate
selection still starts from tracked buffers in argument registers. Real programs
frequently expose descriptors, incrementally update outputs, retain large input
dependencies, or mutate tables immediately after producing them. A useful
recipe must cover a cold interval long enough to repay tracing, validation and
fixed runtime memory. The synthetic job deliberately tests complete producers
followed by a delayed consumption phase; the real probes need not have that
lifetime shape. Moreover, region admission still occurs after the original call
finishes. It cannot lower a peak reached during that call's initial production.

## Accounting, limits and next decision

The sampler counts the application, known worker, and every visible descendant
once per sample. A new regression test proves that a child allocation is counted.
It uses procfs parent links because this host exposes empty task/children files.
Runtime libraries, metadata, checkpoints, templates, replay code, dependencies,
shared pages charged in both processes, and workspace are included in RSS.
The common external measurement supervisor/sampler is excluded from both jobs.

The larger of sampled aggregate RSS and the sum of app/worker kernel peaks is
still an **estimate**, not a guaranteed upper bound. Samples can miss short-lived
or reparented descendants and exact peaks; unavailable samples are flagged.
A read-only cgroup filesystem prevents the hard whole-job memory gate here.
All final comparisons have no configured swap devices before/after execution
and zero sampled swap. No spill-to-disk or remote helper exists.

A path to the real-application goal needs production/lifetime discovery beyond
whole calls and direct pointer arguments, plus suitable native ISA/thread/signal
coverage. Incremental page admission would require independently validated
continuations and ownership for multiple regions within an allocation; that
backend has **not** been implemented. Faster hashing or more aggressive eviction
cannot repair missing recipes or an initial-production peak. No claim is made
that these changes meet the requested 3× or 75%-RSS targets.

Prior reports remain in docs/history; intermediate range profiles and rejected
prototypes remain labelled in docs/evidence and docs/baselines. Reproduction and
correctness evidence are in [VALIDATION.md](VALIDATION.md).
