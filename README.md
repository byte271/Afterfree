# Afterfree v0.1.0

**Keep the pointer. Reconstruct the bytes.**

Afterfree learns how native code produces a buffer, freezes its necessary inputs,
and validates an independent reconstruction against every original byte. It can
then discard physical pages while preserving the application's pointers.

This is a research preview. The current architecture adds inline native capture,
proved read batching, and page-aligned region admission to checked replay and
4 KiB checkpoints. The final paired 64 MiB synthetic median is **0.573 s,
8.26× native**, versus 0.936 s for the freshly measured frozen preceding release.
Estimated total RSS is **25.40 MiB**. **No tested unchanged real application saves
net RSS; the requested runtime and real-memory gates remain unmet.** See
[OPTIMIZATION.md](OPTIMIZATION.md) for all trials, costs and rejected designs.

## Build and run

Tested on Ubuntu 24.04, Linux x86-64, Python 3.12, and 4 KiB pages:

```sh
sudo apt-get install build-essential libssl-dev python3-venv liblz4-1
python3 -m venv .venv
. .venv/bin/activate
python tools/build.py
python -m pip install -e '.[test]'
afterfree doctor
afterfree demo --buffers 16 --mib 4 --output demo.json
```

The build verifies pinned QBDI 0.12.0, Unicorn 2.1.4, and Zydis 4.1.0 downloads.
The archive contains source, evidence, and the frozen comparison source, without
downloaded SDKs or binaries. See [baseline reproduction](docs/baselines/README.md).
`doctor` performs actual capture, physical discard, and exact restoration.

```sh
afterfree/_native/afterfree-run --sse2 --report run.jsonl -- ./program arguments
```

The native launcher avoids Python startup. `afterfree run` remains available and
delegates to the same launcher, with its interpreter startup included.

The command discovers producer calls in an existing executable. No application
reconstruction function is supplied. Qualifying allocations come from `malloc`,
`calloc`, `realloc`, `posix_memalign`, and `aligned_alloc`; supported alignment is
at most 4 KiB. Other alignments and exhausted tracking slots use the original
allocator. Rejected recipes leave the application's original output resident.

`--sse2` selects compatible glibc routines. Comparison baselines must use the
same setting, defined in `afterfree/cli.py`. It does not rewrite instructions
already compiled into an application. EVEX/AVX-512 execution is unsupported.

## What page replay changes

A supported sequential producer gets compact register checkpoints at 4 KiB
boundaries. A sparse read restores one page. Sequential faults grow read-ahead
from one page to a maximum of 16 pages. Explicit reads and supported I/O restore
only overlapping cold pages, in windows of at most 256 KiB by default. A proved
read-only loop can prepare its exact future read span in these bounded batches;
unproved and data-dependent scans keep the demand path.

A write restores the touched pages and permanently pins the generation. Remaining
cold pages still use the immutable recipe; dirty pages are preserved. The recipe
is released once all pages are resident. Non-pageable producers retain a bounded
whole-buffer replay fallback. Streamable native admission compares every byte
through a 256 KiB worker window; strict fallback can still need full-output scratch.
An automatic producer may instead admit one fully written page-aligned region
inside an allocation, leaving untouched bytes resident. The original call must
still finish before admission; this cannot eliminate its initial production peak.

The report exposes inclusive phase profiles, native/page recipe counts, restored bytes, restore operations,
completed buffer restorations, retained metadata, and worker peak RSS. Raw page
fault count is not a count of fully restored buffers.

The default eviction policy remains eager for reproducible mechanism benchmarks.
The optional `--resident-mib N` policy ranks older buffers by retained bytes saved
per measured validation cost and automatically evicts each generation at most
once. Its target counts managed mappings; **it is not a total RSS limit**.

## Explicit native-call API

```python
import ctypes as C
from afterfree import Runtime

library = C.CDLL("./producer.so")
with Runtime() as runtime:
    buffer = runtime.alloc(4 * 1024 * 1024)
    # uint64_t produce(void *out, size_t bytes, uint64_t seed)
    result = runtime.capture(library.produce, buffer, buffer.size, 42, output=buffer)
    if result.eligible:
        buffer.evict()
        assert buffer.resident_bytes == 0
        first_byte = C.c_ubyte.from_address(buffer.address).value
    else:
        print(result.reason)
```

The C API is in `native/afterfree.h`. There is one runtime per process. Pointers
must remain on the owning application thread and cannot outlive their buffer.
A failed reconstruction terminates execution instead of exposing unverified data.

## Supported boundary

- Dynamically linked glibc ELF64, one application thread, six integer/pointer
  SysV ABI argument registers, and tracked buffers from 64 KiB to 256 MiB.
- Bounded scalar/SSE/SSE2 capture. The native compiler accepts a narrower,
  stack-free subset with immutable loads and sequential output stores.
- Ordinary pointer reads/writes, supported scalar and vector libc I/O, and
  `fread`/`fwrite`. Late-loaded producer modules can be captured and later unloaded.
- No application threads, arbitrary fork use, signal-handler replacement,
  exceptions or longjmp across tracing boundaries, self-modifying code, GPU,
  direct pointer-bearing syscalls, asynchronous I/O, or general custom allocators.

The replay worker starts from a clean executable image and cannot open files,
create network sockets, or issue writes outside its protocol socket. Its only application-shared
reconstruction mapping is the bounded 256 KiB default window, read-only in the application. Recipes remain
resident; Afterfree has no swap or disk-spill path. System swap must also be
disabled for a zero-swap experiment.

## Evidence and design

```sh
pytest -q
python tools/validate_upstream.py --output upstream.json
python tools/validate_gzip.py --output gzip.json
python tools/validate_zstd.py --output zstd.json
python tools/validate_imagemagick.py --output imagemagick.json
python tools/replay_bench.py --output replay.json
```

The Zstandard and ImageMagick probes additionally require the distribution
`zstd` and `imagemagick` packages. ImageMagick is explicitly refused on the tested
host; its probe intentionally reports failure.

The demo and replay benchmark are synthetic mechanism tests. Upstream application
probes are labeled separately and compare complete outputs. RSS includes the
application and worker, including code, metadata, inputs, and reconstruction.
Samples and kernel counters are estimates. A delegated cgroup is required for a
hard aggregate-memory gate; `tools/cgroup_bench.py` provides that runner.

[Specification and unchanged release gates](spec.md) ·
[Architecture and invariants](docs/architecture.md) ·
[Optimization results](OPTIMIZATION.md) · [Validation](VALIDATION.md) ·
[Dependencies](docs/dependencies.md)
