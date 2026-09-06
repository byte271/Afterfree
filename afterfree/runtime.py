from __future__ import annotations

import ctypes as C
import os
import platform
from dataclasses import dataclass
from pathlib import Path


class AfterfreeError(RuntimeError):
    pass


class _Stats(C.Structure):
    _fields_ = [
        (n, C.c_uint64)
        for n in (
            "length",
            "recipe_bytes",
            "input_bytes",
            "instructions",
            "faults",
            "evictions",
            "capture_ns",
            "validation_ns",
            "restore_ns",
            "state",
            "retained_bytes",
            "page_bytes",
            "backend",
            "reconstructed_bytes",
            "full_restores",
        )
    ]


class _ResidencyStats(C.Structure):
    _fields_ = [
        (n, C.c_uint64)
        for n in (
            "target",
            "resident_bytes",
            "reclaimable_bytes",
            "over_target_bytes",
            "automatic_evictions",
            "restore_operations",
            "restored_bytes",
            "peak_over_target_bytes",
        )
    ]


@dataclass(frozen=True)
class Capture:
    value: int
    eligible: bool
    reason: str | None
    stats: dict

    @property
    def executed(self):
        """Whether the native call ran; preflight failures execute nothing."""
        return self.stats["instructions"] > 0


def _library():
    root = Path(__file__).resolve().parent / "_native"
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise AfterfreeError("Afterfree requires Linux x86-64")
    try:
        # Keep the GIL: application concurrency is explicitly unsupported.
        lib = C.PyDLL(str(root / "libafterfree.so"))
    except OSError as e:
        raise AfterfreeError(
            "Native runtime is missing; run python tools/build.py"
        ) from e
    definitions = {
        "af_error": ([], C.c_char_p),
        "af_init": ([C.c_char_p], C.c_int),
        "af_alloc": ([C.c_size_t], C.c_void_p),
        "af_capture": (
            [
                C.c_void_p,
                C.c_void_p,
                C.POINTER(C.c_uint64),
                C.c_size_t,
                C.POINTER(C.c_uint64),
            ],
            C.c_int,
        ),
        "af_evict": ([C.c_void_p], C.c_int),
        "af_set_resident_target": ([C.c_uint64], C.c_int),
        "af_manage": ([C.c_void_p], C.c_int),
        "af_get_residency_stats": ([C.POINTER(_ResidencyStats)], C.c_int),
        "af_materialize": ([C.c_void_p], C.c_int),
        "af_prepare_read": ([C.c_void_p, C.c_size_t], C.c_int),
        "af_prepare_write": ([C.c_void_p, C.c_size_t], C.c_int),
        "af_get_stats": ([C.c_void_p, C.POINTER(_Stats)], C.c_int),
        "af_resident_pages": ([C.c_void_p], C.c_int),
        "af_worker_pid": ([], C.c_int),
        "af_worker_procfs_pid": ([], C.c_int),
        "af_free": ([C.c_void_p], C.c_int),
        "af_shutdown": ([], C.c_int),
    }
    for name, (args, ret) in definitions.items():
        f = getattr(lib, name)
        f.argtypes, f.restype = args, ret
    return lib, root / "afterfree-worker"


class Runtime:
    """One single-threaded native recorder and one independently spawned worker.

    Calls use the x86-64 SysV ABI with at most six integer/pointer arguments.
    The original native function executes once. Rejected calls leave their
    output resident and usable. Reconstruction never invokes a Python callback.
    """

    def __init__(self, *, resident_target_bytes: int | None = None):
        if resident_target_bytes is not None and (
            not isinstance(resident_target_bytes, int)
            or not 1 <= resident_target_bytes <= 1 << 40
        ):
            raise ValueError("managed resident target must be 1 byte through 1 TiB")
        self._lib, worker = _library()
        self._closed = True
        self._buffers: list[Buffer] = []
        self._check(self._lib.af_init(os.fsencode(worker)))
        self._closed = False
        if resident_target_bytes is not None:
            self._check(self._lib.af_set_resident_target(resident_target_bytes))

    @property
    def residency(self):
        """Managed mapping accounting, not total process RSS or a hard limit."""
        if self._closed:
            raise AfterfreeError("runtime is closed")
        stats = _ResidencyStats()
        self._check(self._lib.af_get_residency_stats(C.byref(stats)))
        return {name: getattr(stats, name) for name, _ in stats._fields_}

    def _check(self, rc):
        if rc < 0:
            raise AfterfreeError(self._lib.af_error().decode("utf-8", "replace"))
        return rc

    @property
    def worker_pid(self):
        return self._lib.af_worker_pid()

    @property
    def worker_procfs_pid(self):
        """PID as exposed by procfs, which can differ in a sandbox PID namespace."""
        return self._lib.af_worker_procfs_pid()

    def alloc(self, size: int) -> Buffer:
        if self._closed:
            raise AfterfreeError("runtime is closed")
        if not isinstance(size, int) or not 0 < size <= 256 * 1024 * 1024:
            raise ValueError("size must be 1 byte through 256 MiB")
        ptr = self._lib.af_alloc(size)
        if not ptr:
            self._check(-1)
        buffer = Buffer(self, ptr, size)
        self._buffers.append(buffer)
        return buffer

    def capture(self, function, *args: int | Buffer, output: Buffer) -> Capture:
        if self._closed or output._runtime is not self:
            raise AfterfreeError("output must belong to this active runtime")
        output._assert_open()
        if output.stats["state"] != "resident":
            raise AfterfreeError("capture requires a fresh resident buffer")
        if len(args) > 6:
            raise ValueError("at most six integer/pointer ABI arguments are supported")
        values = [a.address if isinstance(a, Buffer) else int(a) for a in args]
        if any(v < -(1 << 63) or v >= 1 << 64 for v in values):
            raise ValueError("argument does not fit a 64-bit ABI register")
        words = (C.c_uint64 * len(values))(*values)
        fn = C.cast(function, C.c_void_p).value
        if not fn:
            raise ValueError("a native function is required")
        value = C.c_uint64()
        rc = self._lib.af_capture(
            output.address, fn, words, len(values), C.byref(value)
        )
        reason = self._lib.af_error().decode("utf-8", "replace") if rc < 0 else None
        return Capture(value.value, rc == 0, reason, output.stats)

    def close(self):
        if not self._closed:
            for buffer in list(self._buffers):
                buffer.close()
            self._check(self._lib.af_shutdown())
            self._closed = True

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


class Buffer:
    """An owned mapping whose address survives eviction and reconstruction.

    Raw pointers must not outlive this object or be passed to another thread.
    Any native write permanently pins the current generation.
    """

    def __init__(self, runtime, address, size):
        self._runtime, self._address, self.size = runtime, address, size
        self._closed = False

    def _assert_open(self):
        if self._closed:
            raise AfterfreeError("buffer is closed")

    @property
    def address(self):
        self._assert_open()
        return self._address

    @property
    def stats(self):
        raw = _Stats()
        self._runtime._check(
            self._runtime._lib.af_get_stats(self.address, C.byref(raw))
        )
        result = {n: getattr(raw, n) for n, _ in raw._fields_}
        result["state"] = ("resident", "sealed", "evicted", "pinned", "unused")[
            raw.state
        ]
        return result

    @property
    def resident_bytes(self):
        return 4096 * self._runtime._check(
            self._runtime._lib.af_resident_pages(self.address)
        )

    def evict(self):
        self._runtime._check(self._runtime._lib.af_evict(self.address))

    def materialize(self):
        self._runtime._check(self._runtime._lib.af_materialize(self.address))

    def read(self, offset=0, size=None) -> bytes:
        size = self.size - offset if size is None else size
        if offset < 0 or size < 0 or offset + size > self.size:
            raise ValueError("read is outside buffer")
        self._runtime._check(
            self._runtime._lib.af_prepare_read(self.address + offset, size)
        )
        return C.string_at(self.address + offset, size)

    def write(self, data: bytes, offset=0):
        if offset < 0 or offset + len(data) > self.size:
            raise ValueError("write is outside buffer")
        self._runtime._check(
            self._runtime._lib.af_prepare_write(self.address + offset, len(data))
        )
        C.memmove(self.address + offset, data, len(data))

    def close(self):
        if not self._closed:
            self._runtime._check(self._runtime._lib.af_free(self.address))
            self._closed = True
            self._runtime._buffers.remove(self)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
