import ctypes as C
import ctypes.util
import hashlib
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import errno

import pytest

from afterfree import AfterfreeError, Runtime
from afterfree.measure import memory

ROOT = Path(__file__).resolve().parents[1]
LIBRARY = ROOT / "afterfree/_native/libafterfree-fixtures.so"


@pytest.fixture
def native():
    return C.CDLL(str(LIBRARY))


def expected_expansion(n, seed):
    result = bytearray()
    for _ in range(n):
        seed ^= (seed << 13) & ((1 << 64) - 1)
        seed ^= seed >> 7
        seed ^= (seed << 17) & ((1 << 64) - 1)
        result += seed.to_bytes(8, "little")
    return bytes(result)


@pytest.mark.parametrize(
    "n,seed", [(8192, 42), (32768, 0xFFFFFFFFFFFFFFFF), (16384, 9)]
)
def test_native_exact_discard_and_repeated_restore(native, n, seed):
    reference = expected_expansion(n, seed)
    with Runtime() as runtime:
        buffer = runtime.alloc(n * 8)
        result = runtime.capture(native.expand, buffer, n, seed, output=buffer)
        assert result.eligible, result.reason
        assert result.value == n
        assert buffer.read() == reference
        address = buffer.address
        assert result.stats["recipe_bytes"] < buffer.size // 8
        for _ in range(3):
            buffer.evict()
            assert buffer.resident_bytes == 0
            assert C.c_uint64.from_address(address + 128).value == int.from_bytes(
                reference[128:136], "little"
            )
            assert buffer.read() == reference
            assert buffer.address == address
        assert buffer.stats["faults"] == 3
        assert buffer.stats["evictions"] == 3


def test_live_inputs_are_immutable_snapshots(native):
    with Runtime() as runtime:
        values = (C.c_uint64 * 16)(*range(16))
        buffer = runtime.alloc(128 * 1024)
        cap = runtime.capture(
            native.lookup, buffer, buffer.size // 8, C.addressof(values), output=buffer
        )
        assert cap.eligible, cap.reason
        expected = buffer.read()
        for i in range(16):
            values[i] = 0xAABBCCDDEE
        del values
        buffer.evict()
        assert buffer.read() == expected


@pytest.mark.parametrize("evicted", [False, True])
def test_alias_write_pins_and_prevents_stale_replay(native, evicted):
    with Runtime() as runtime:
        buffer = runtime.alloc(65536)
        assert runtime.capture(native.expand, buffer, 8192, 42, output=buffer).eligible
        original = buffer.read()
        if evicted:
            buffer.evict()
        alias = C.c_uint64.from_address(buffer.address + 88)
        alias.value = 0xDEADBEEF
        expected = original[:88] + (0xDEADBEEF).to_bytes(8, "little") + original[96:]
        assert buffer.stats["state"] == "pinned"
        assert buffer.read() == expected
        with pytest.raises(AfterfreeError, match="modified"):
            buffer.evict()


@pytest.mark.parametrize(
    "function,reason",
    [
        ("partial", "not fully produced"),
        ("dependent", "not smaller"),
        ("timed", "instrumented module"),
        ("timestamp", "RDTSC"),
    ],
)
def test_ineligible_calls_keep_original_results_resident(native, function, reason):
    with Runtime() as runtime:
        buffer = runtime.alloc(65536)
        result = runtime.capture(
            getattr(native, function), buffer, buffer.size // 8, output=buffer
        )
        assert not result.eligible
        assert reason in result.reason
        assert buffer.stats["state"] == "resident"
        assert buffer.resident_bytes > 0
        with pytest.raises(AfterfreeError, match="no validated"):
            buffer.evict()


def test_scalar_sse_state_and_floating_output(native):
    with Runtime() as runtime:
        inputs = (C.c_double * 8)(0.25, -2, 3, 1e10, 0, 8, -9.5, 11)
        buffer = runtime.alloc(65536)
        result = runtime.capture(
            native.sse, buffer, buffer.size // 8, C.addressof(inputs), output=buffer
        )
        assert result.eligible, result.reason
        output = C.string_at(buffer.address, buffer.size)
        buffer.evict()
        assert buffer.read() == output
        values = (C.c_double * (buffer.size // 8)).from_address(buffer.address)
        for i in range(0, len(values), 113):
            assert values[i] == inputs[i % 8] * 1.5 + i


def test_allocation_generation_and_free_without_restore(native):
    with Runtime() as runtime:
        for seed in range(12):
            buffer = runtime.alloc(65536)
            assert runtime.capture(
                native.expand, buffer, 8192, seed + 1, output=buffer
            ).eligible
            buffer.evict()
            buffer.close()
            with pytest.raises(AfterfreeError, match="closed"):
                buffer.read()


def test_input_bounds_and_lifecycle(native):
    with Runtime() as runtime:
        with pytest.raises(ValueError):
            runtime.alloc(-1)
        buffer = runtime.alloc(65536)
        with pytest.raises(ValueError):
            buffer.read(65535, 2)
        with pytest.raises(ValueError):
            buffer.write(b"ab", 65535)
        with pytest.raises(ValueError):
            runtime.capture(native.expand, *range(7), output=buffer)
        with pytest.raises(AfterfreeError, match="one Afterfree"):
            Runtime()
    with pytest.raises(AfterfreeError, match="closed"):
        runtime.alloc(1)


def test_new_thread_rejected_before_capture(native):
    event = threading.Event()
    with Runtime() as runtime:
        thread = threading.Thread(target=event.wait)
        thread.start()
        try:
            with pytest.raises(AfterfreeError, match="one application thread"):
                runtime.alloc(65536)
        finally:
            event.set()
            thread.join()


def child_script(body, timeout=30):
    return subprocess.run(
        [sys.executable, "-c", body],
        cwd=ROOT,
        text=True,
        capture_output=True,
        timeout=timeout,
    )


def test_worker_death_after_eviction_is_fail_stop():
    code = f"""
import ctypes as C,os,signal
from afterfree import Runtime
r=Runtime();b=r.alloc(65536);l=C.CDLL({str(LIBRARY)!r})
assert r.capture(l.expand,b,8192,42,output=b).eligible
b.evict();os.kill(r.worker_pid,signal.SIGKILL)
b.read()
print('UNSAFE CONTINUATION')
"""
    result = child_script(code)
    assert result.returncode == 190
    assert "refusing to expose unverified bytes" in result.stderr
    assert "UNSAFE CONTINUATION" not in result.stdout


def test_worker_death_before_eviction_allows_cleanup(native):
    with Runtime() as runtime:
        buffer = runtime.alloc(65536)
        assert runtime.capture(native.expand, buffer, 8192, 42, output=buffer).eligible
        os.kill(runtime.worker_pid, signal.SIGKILL)
        buffer.close()


def test_fault_preserves_application_errno(native):
    native.read_with_errno.argtypes = [C.c_void_p]
    native.read_with_errno.restype = C.c_uint64
    with Runtime() as runtime:
        buffer = runtime.alloc(65536)
        assert runtime.capture(native.expand, buffer, 8192, 42, output=buffer).eligible
        buffer.evict()
        assert native.read_with_errno(buffer.address) == errno.EDOM


def test_existing_crash_handler_is_explicitly_rejected():
    result = child_script(
        """
import faulthandler
from afterfree import Runtime,AfterfreeError
faulthandler.enable()
try:
 Runtime()
except AfterfreeError as e:
 assert 'SIGSEGV handler is incompatible' in str(e)
else:
 raise AssertionError('incompatible handler was replaced')
"""
    )
    assert result.returncode == 0, result.stderr


def test_cross_thread_fault_is_fail_stop():
    result = child_script(
        f"""
import ctypes as C,threading
from afterfree import Runtime
r=Runtime();b=r.alloc(65536);l=C.CDLL({str(LIBRARY)!r})
assert r.capture(l.expand,b,8192,42,output=b).eligible
b.evict()
t=threading.Thread(target=b.read);t.start();t.join()
print('UNSAFE CONTINUATION')
"""
    )
    assert result.returncode == 190
    assert "UNSAFE CONTINUATION" not in result.stdout


def test_nondumpable_worker_is_included_in_memory_accounting():
    with Runtime() as runtime:
        usage = memory(runtime.worker_procfs_pid)
        assert usage["rss"] >= 4096
        assert usage["source"] in ("smaps_rollup", "status.VmRSS")
        if usage["source"] == "status.VmRSS":
            assert usage["pss"] is None


def test_fork_does_not_share_pager_protocol():
    code = f"""
import ctypes as C,os
from afterfree import Runtime
with Runtime() as r:
 b=r.alloc(65536);l=C.CDLL({str(LIBRARY)!r})
 assert r.capture(l.expand,b,8192,42,output=b).eligible
 b.evict();pid=os.fork()
 if pid==0:
  b.read();os._exit(0)
 _,status=os.waitpid(pid,0)
 assert os.waitstatus_to_exitcode(status)==190
 assert len(b.read())==65536
"""
    result = child_script(code)
    assert result.returncode == 0, result.stderr


def test_upstream_lz4_native_code_replay():
    code = """
import ctypes as C,ctypes.util
from afterfree import Runtime
library=C.CDLL(ctypes.util.find_library('lz4'))
library.LZ4_compress_default.argtypes=[C.c_void_p,C.c_void_p,C.c_int,C.c_int]
data=(b'upstream LZ4 native recipe '*60000)[:1048576]
source=C.create_string_buffer(data);packed=C.create_string_buffer(len(data)+65536)
n=library.LZ4_compress_default(source,packed,len(data),len(packed))
assert n>0
with Runtime() as runtime:
 buffer=runtime.alloc(len(data))
 result=runtime.capture(library.LZ4_decompress_safe,C.addressof(packed),buffer,n,buffer.size,output=buffer)
 assert result.eligible,result.reason
 C.memset(C.addressof(packed),0,n)
 buffer.evict();assert buffer.resident_bytes==0
 assert buffer.read()==data
"""
    env = os.environ.copy()
    env["GLIBC_TUNABLES"] = (
        "glibc.cpu.hwcaps=-AVX512VL,-AVX512BW,-AVX512F,-AVX2,-AVX,-ERMS,-FSRM"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr


def test_allocation_index_survives_full_capacity_holes_and_reuse():
    with Runtime() as runtime:
        buffers = [runtime.alloc(8 + i % 7) for i in range(4096)]
        with pytest.raises(AfterfreeError, match="4096 buffer limit"):
            runtime.alloc(8)
        for i in range(1, 4096, 2):
            buffers[i].close()
        for i in range(0, 4096, 2):
            assert buffers[i].stats["length"] == 8 + i % 7
        replacements = [runtime.alloc(17 + i % 11) for i in range(2048)]
        assert len({b.address for b in buffers[::2] + replacements}) == 4096
        for i, buffer in enumerate(replacements):
            assert buffer.stats["length"] == 17 + i % 11
        for buffer in buffers[::2] + replacements:
            buffer.close()
        assert runtime.residency["resident_bytes"] == 0


def test_pressure_policy_reports_overshoot_instead_of_repeated_replay(native):
    size = 65536
    with Runtime(resident_target_bytes=2 * size) as runtime:
        buffers = []
        for seed in range(4):
            b = runtime.alloc(size)
            assert runtime.capture(
                native.expand, b, size // 8, seed + 42, output=b
            ).eligible
            buffers.append(b)
        assert runtime.residency["automatic_evictions"] == 2
        assert sum(b.stats["state"] == "evicted" for b in buffers) == 2
        for seed, b in enumerate(buffers):
            assert b.read() == expected_expansion(size // 8, seed + 42)
        replayed = [b for b in buffers if b.stats["evictions"]]
        assert len(replayed) == 2
        extra = runtime.alloc(size)
        assert extra.size == size
        assert all(
            b.stats["evictions"] == 1 and b.stats["state"] == "sealed" for b in replayed
        )
        stats = runtime.residency
        assert stats["over_target_bytes"] > 0
        assert stats["peak_over_target_bytes"] >= stats["over_target_bytes"]
        assert stats["restore_operations"] == 2 and stats["restored_bytes"] == 2 * size


def test_worker_socket_survives_launch_fd_collision():
    code = """
import os
from afterfree import Runtime
source = os.open('/dev/null', os.O_RDONLY)
for fd in range(3, 198):
    os.dup2(source, fd)
with Runtime() as runtime:
    assert runtime.worker_pid > 0
    buffer = runtime.alloc(65536)
    buffer.write(b'checked')
    assert buffer.read(0, 7) == b'checked'
"""
    result = subprocess.run(
        [sys.executable, "-c", code], cwd=ROOT, capture_output=True, timeout=30
    )
    assert result.returncode == 0, result.stderr
