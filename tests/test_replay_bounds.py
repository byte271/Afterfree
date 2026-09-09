"""Execute adversarial loops through the worker, including its checked fallback."""

import ctypes as C
import hashlib
import struct

import pytest

from test_worker import Header, receive, submit, worker  # noqa: F401


def loop_recipe(*, partial=False, indexed=False, stride=1, length=73728):
    h = Header()
    h.magic, h.version = 0x314552464146, 1
    h.entry, h.stop, h.output, h.length = 0x100000, 0x100200, 0x300000, length
    h.result, h.mxcsr = 0, 0x1F80
    h.regs[15], h.regs[16], h.regs[17] = 0x400800, h.entry, 2
    setup = [b"\x31\xc0", b"\x48\xbf" + struct.pack("<Q", h.output)]
    if indexed:
        setup += [b"\x31\xc9", b"\x48\xbe" + struct.pack("<Q", length)]
        body = [b"\x88\x04\x0f", b"\x48\xff\xc1", b"\x48\x39\xf1"]
    else:
        setup += [b"\x48\xb9" + struct.pack("<Q", length)]
        body = [
            b"\x88\x07",
            (b"" if partial else b"\x48") + b"\x83\xc7" + bytes([stride]),
            b"\x48\xff\xc9",
        ]
    body += [b"\x75" + struct.pack("b", -sum(map(len, body)) - 2)]
    code = setup + body + [b"\xc3"]
    h.steps = len(setup) + len(body) * length + 1
    h.page_count, h.code_count, h.input_count, h.input_bytes = 2, len(code), 1, 8
    h.digest[:] = hashlib.sha256(bytes(length)).digest()
    blob = bytes(h) + struct.pack("<QQ", 0x100000, 0x400000)
    pc = h.entry
    for instruction in code:
        blob += struct.pack("<QB15s", pc, len(instruction), instruction)
        pc += len(instruction)
    return blob + struct.pack("<QQQ", 0x400800, 8, h.stop)


@pytest.mark.parametrize(
    "partial,indexed", [(False, False), (True, False), (False, True)]
)
def test_address_updates_preserve_every_checkpoint(worker, partial, indexed):
    blob = loop_recipe(partial=partial, indexed=indexed)
    worker.sendall(struct.pack("<QQQ", 7, 1, len(blob)) + blob)
    status, size, message = struct.unpack("<QQ240s", receive(worker, 256))
    assert status == 0, message
    backend, page, _ = struct.unpack("<QQQ", receive(worker, 24))
    assert backend == 1 and page == 4096
    assert receive(worker, size) == bytes(73728)
    for offset in [65536, 4096, 32768, 0]:
        worker.sendall(struct.pack("<QQQ", 8, 1, offset << 32 | 4096))
        status, size, message = struct.unpack("<QQ240s", receive(worker, 256))
        assert status == 0 and size == 4096, message
        assert receive(worker, size) == bytes(4096)
    worker.sendall(struct.pack("<QQQ", 10, 0, 0))
    status, size, _ = struct.unpack("<QQ240s", receive(worker, 256))
    assert status == 0 and size == 12 * 8
    counters = struct.unpack("<12Q", receive(worker, size))
    assert counters[-2] > 0 and counters[-1] > 0


@pytest.mark.parametrize("difference", [-1, 1, -32768, 32768])
def test_checkpoint_budget_rejects_wrong_exact_step_count(worker, difference):
    blob = loop_recipe()
    h = Header.from_buffer_copy(blob)
    h.steps += difference
    status, _, message = submit(worker, bytes(h) + blob[C.sizeof(h) :])
    assert status == 1, message


def test_noncontiguous_store_cannot_escape_output(worker):
    status, _, message = submit(worker, loop_recipe(stride=2))
    assert status == 1, message
