# Afterfree v0.1.0 validation

**150 tests pass, with no skips. The 3× synthetic-runtime and real-application
75%-RSS gates do not pass.** Supported outputs remain exact; isolated sparse
reads reconstruct 4 KiB. This is a research preview with explicit compatibility
limits, not a proof of correctness for arbitrary native programs.

## Correctness and cleanup

The preceding 101 cases remain. Added coverage includes region admission at
allocation prefixes, middles, suffixes and short final pages; exact unchanged
bytes around a discarded region; inside/outside writes; invalid region bounds;
transparent partial producers; exact instruction budgets and checkpoint state;
three negotiated transport sizes; multi-window transactions and sparse replay;
native launcher errors; child-process RSS; and six differential consumer cases.

Read-plan tests include early data-dependent exits, reverse and gapped reads,
a changing loop bound, a complete scan, and a 17-element scan. Original stdout
and errno match with read plans enabled and disabled. The two short consumers
restore exactly one page. The compiler keeps its checked path and full SHA-256
validation. A larger window never authorizes missing bytes, an incorrect ACK,
a wrong step count, or an unvalidated recipe.

[Current test run](docs/evidence/range-checked-tests.xml) and
[separate fresh-build tests](docs/evidence/range-fresh-tests.xml) identify every
case. Intermediate failures were corrected before delivery; the original tests
were not removed or relaxed. The rejected affine replay implementation and SIMD
hash prototype are absent from the current runtime.

## Performance and real applications

[Final paired measurements](docs/evidence/range-final-comparison.json) preserve
the frozen previous executable/library and original three workloads, alternating
runtime order across three trials. All 18 transformed jobs validate full stdout,
admission/eviction counts, full restoration, exact reconstructed-byte volume,
worker memory and zero swap. The 64 MiB median is 0.573 s, 1.63× faster than the
fresh frozen-release median of 0.936 s, but still 8.26× native. It uses an estimated
25.40 MiB aggregate RSS. Host variability prevents a direct comparison against
the prior session's historical 0.481 s.

[Final ablation](docs/evidence/range-final-ablation.json) runs four mechanisms on
the same frozen 64 MiB target with every gate intact. Builds/tests did not run
concurrently with the final comparisons. Inclusive phase times are not additive.
[Replay latency evidence](docs/evidence/range-final-replay.json) reports sparse
4 KiB volumes and complete reads separately.

All three LZ4, three gzip and two Zstandard outputs match. None saves total RSS.
Three FFmpeg and two ImageMagick jobs are refused under the existing thread and
signal contracts. All failures remain visible. [OPTIMIZATION.md](OPTIMIZATION.md)
includes every case, negative hypotheses, memory costs and remaining limits.
The FFmpeg sources are generated video inputs to an unchanged native program;
they are not a claim about a representative media corpus.

## Memory and environment

RSS includes runtime libraries, snapshots, page metadata, recipes, caches,
compiled code, both mappings of the shared window, all observed descendants and
reconstruction memory. The complete exec frontend counts. The measurement-only
supervisor and sampler are excluded equally from both jobs.

Summed kernel app/worker peaks and procfs samples are estimates: counters may be
approximate, peaks need not coincide, exited processes can have unavailable
samples, and short-lived descendants may escape sampling. These are not hard
whole-job limits. [Doctor](docs/evidence/range-environment.json) reports no
configured swap, working discard/restoration, unavailable userfaultfd, and no
writable delegated cgroup. The existing cgroup gate was not weakened or replaced
by the soft managed-buffer target. No hardware-counter profiling is claimed.

## Reproduce

Build and install as in README.md, then:

```sh
pytest -q
python tools/replay_bench.py --output replay.json
python tools/validate_upstream.py --output upstream.json
python tools/validate_gzip.py --output gzip.json
python tools/validate_zstd.py --output zstd.json
python tools/validate_ffmpeg.py --output ffmpeg.json
python tools/validate_imagemagick.py --output imagemagick.json
python -m zipfile -e docs/baselines/before-range-0.1.0.zip ../baseline
python ../baseline/afterfree/tools/build.py
python tools/compare.py --baseline-root ../baseline/afterfree --output comparison.json --trials 3
python tools/ablate.py --baseline-root ../baseline/afterfree --output ablation.json --trials 3
python tools/ablate.py --windows --baseline-root ../baseline/afterfree --output windows.json --trials 3
```

FFmpeg/ImageMagick validation intentionally returns failure on this host. Real
application scripts record binary hashes and matching options. Zstandard uses
unchanged checksum-pinned upstream release archives. LZ4 builds unchanged pinned
source with its documented single-thread build option. Full program stdout is
hashed and counted even when its stored preview is truncated.

The current public exec frontend is `afterfree/_native/afterfree-run`; Python
`afterfree run` delegates to it. Comparisons count the public frontend available
in each release. The frozen preceding release still has its Python frontend.

A source-only extraction into another directory, a new Python environment,
and a complete independent native rebuild are documented in
[fresh installation evidence](docs/evidence/range-fresh-install.json). Every
packaged source member has a SHA-256 manifest entry. Dependency downloads remain
pinned; no SDKs, generated native binaries, caches, or active temporary interposer
are shipped. The frozen failed prototype is only a reproducibility artifact.
A second physical machine and the original hard-budget launch gates remain
unvalidated.
