"""Region admission must preserve the complete allocation and unchanged bytes."""

import ctypes as C
import hashlib
import struct

import pytest

from afterfree import AfterfreeError, Runtime
from test_worker import Header


def zero_recipe(address, length):
    h = Header()
    h.magic, h.version = 0x314552464146, 1
    h.entry, h.stop, h.output, h.length = 0x100000, 0x100100, address, length
    h.result, h.steps, h.mxcsr = 0, 4 * length + 4, 0x1F80
    h.regs[15], h.regs[16], h.regs[17] = 0x400800, h.entry, 2
    code = [
        b"\x31\xc0",
        b"\x48\xbf" + struct.pack("<Q", address),
        b"\x48\xb9" + struct.pack("<Q", length),
        b"\x88\x07",
        b"\x48\xff\xc7",
        b"\x48\xff\xc9",
        b"\x75\xf6",
        b"\xc3",
    ]
    h.page_count, h.code_count, h.input_count, h.input_bytes = 2, len(code), 1, 8
    h.digest[:] = hashlib.sha256(bytes(length)).digest()
    blob = bytes(h) + struct.pack("<QQ", 0x100000, 0x400000)
    pc = h.entry
    for instruction in code:
        blob += struct.pack("<QB15s", pc, len(instruction), instruction)
        pc += len(instruction)
    return blob + struct.pack("<QQQ", 0x400800, 8, h.stop)


def submit(runtime, buffer, offset, length, *, whole=False):
    blob = zero_recipe(buffer.address + offset, length)
    fn = runtime._lib.af_submit if whole else runtime._lib.af_submit_region
    fn.argtypes = [C.c_void_p, C.c_char_p, C.c_size_t, C.c_uint64]
    fn.restype = C.c_int
    return fn(buffer.address, blob, len(blob), 0)


@pytest.mark.parametrize(
    "offset,length,size",
    [
        (0, 32768, 65536),
        (16384, 32768, 65536),
        (32768, 32768, 65536),
        (4096, 61441, 65537),
    ],
)
def test_region_discard_is_sparse_and_preserves_every_other_byte(offset, length, size):
    with Runtime() as runtime:
        buffer = runtime.alloc(size)
        expected = bytearray(b"\xa5" * size)
        expected[offset : offset + length] = bytes(length)
        buffer.write(bytes(expected))
        assert submit(runtime, buffer, offset, length) == 0
        assert buffer.size == size
        resident = buffer.resident_bytes
        buffer.evict()
        assert buffer.resident_bytes == resident - ((length + 4095) // 4096) * 4096
        before = buffer.stats["reconstructed_bytes"]
        assert C.c_ubyte.from_address(buffer.address + offset).value == 0
        assert buffer.stats["reconstructed_bytes"] - before == 4096
        buffer.evict()
        assert buffer.read() == bytes(expected)
        assert buffer.stats["reconstructed_bytes"] == 4096 + length
        assert runtime.residency["resident_bytes"] == ((size + 4095) // 4096) * 4096


def test_region_external_write_does_not_retire_valid_recipe():
    with Runtime() as runtime:
        buffer = runtime.alloc(65536)
        buffer.write(bytes(65536))
        assert submit(runtime, buffer, 16384, 32768) == 0
        buffer.evict()
        buffer.write(b"keep", 0)
        buffer.write(b"tail", 65532)
        assert buffer.stats["state"] == "evicted"
        assert buffer.read(16380, 8) == bytes(8)
        buffer.evict()
        assert buffer.read() == b"keep" + bytes(65528) + b"tail"


def test_region_internal_write_pins_and_preserves_cold_remainder():
    with Runtime() as runtime:
        buffer = runtime.alloc(65536)
        buffer.write(bytes(65536))
        assert submit(runtime, buffer, 16384, 32768) == 0
        buffer.evict()
        buffer.write(b"changed", 20477)
        assert buffer.stats["state"] == "pinned"
        assert buffer.read() == bytes(20477) + b"changed" + bytes(65536 - 20484)
        with pytest.raises(AfterfreeError, match="modified"):
            buffer.evict()


@pytest.mark.parametrize(
    "offset,length", [(1, 32768), (16384, 32767), (65536, 4096), (32768, 65536)]
)
def test_invalid_region_cannot_authorize_discard(offset, length):
    with Runtime() as runtime:
        buffer = runtime.alloc(65536)
        buffer.write(bytes(65536))
        assert submit(runtime, buffer, offset, length) == -1
        assert buffer.stats["state"] == "resident"
        assert buffer.read() == bytes(65536)


def test_whole_allocation_api_still_rejects_partial_recipe():
    with Runtime() as runtime:
        buffer = runtime.alloc(65536)
        buffer.write(bytes(65536))
        assert submit(runtime, buffer, 0, 32768, whole=True) == -1
        assert buffer.stats["state"] == "resident"


@pytest.mark.parametrize("mode", range(4))
def test_unchanged_program_automatically_admits_only_written_region(tmp_path, mode):
    import json
    import os
    from pathlib import Path
    import subprocess
    import sys

    root = Path(__file__).resolve().parents[1]
    command = [str(root / "afterfree/_native/afterfree-region-fixture"), str(mode)]
    native = subprocess.run(command, capture_output=True, timeout=30)
    log = tmp_path / "region.jsonl"
    launch = [
        sys.executable,
        "-m",
        "afterfree",
        "run",
        "--sse2",
        "--report",
        str(log),
        "--",
        *command,
    ]
    after = subprocess.run(launch, capture_output=True, timeout=30)
    assert native.returncode == after.returncode == 0, after.stderr
    assert native.stdout == after.stdout and len(after.stdout) == 1 << 20
    summary = next(
        e
        for e in map(json.loads, log.read_text().splitlines())
        if e["event"] == "summary"
    )
    assert summary["accepted"] >= 1
    assert 0 < summary["restored_bytes"] < 1 << 20
    disabled = subprocess.run(
        launch,
        capture_output=True,
        env=dict(os.environ, AF_DISABLE_REGIONS="1"),
        timeout=30,
    )
    assert disabled.returncode == 0 and disabled.stdout == native.stdout
