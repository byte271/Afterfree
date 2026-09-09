"""Adversarial protocol tests exercise missing inputs and exact validation."""

import ctypes as C
import hashlib
from pathlib import Path
import socket
import struct
import subprocess
import array
import fcntl
import mmap
import os

import pytest

WORKER = Path(__file__).resolve().parents[1] / "afterfree/_native/afterfree-worker"


class Header(C.Structure):
    _fields_ = [
        (n, C.c_uint64)
        for n in (
            "magic",
            "version",
            "entry",
            "stop",
            "output",
            "length",
            "result",
            "steps",
            "input_bytes",
            "fs_base",
            "gs_base",
        )
    ]
    _fields_ += [("regs", C.c_uint64 * 18), ("xmm", C.c_uint8 * 256)]
    _fields_ += [
        (n, C.c_uint32) for n in ("mxcsr", "page_count", "code_count", "input_count")
    ]
    _fields_ += [("digest", C.c_uint8 * 32)]


def recipe(*, missing=False, mismatch=False, offset=0, missing_byte=None, steps=3):
    h = Header()
    h.magic, h.version = 0x314552464146, 1
    h.entry, h.stop, h.output, h.length = 0x100000, 0x100100, 0x300000, 8
    h.result, h.steps, h.mxcsr = 9, steps, 0x1F80
    h.regs[15], h.regs[16], h.regs[17] = 0x400800, h.entry, 2
    address = 0x200000 + offset
    instructions = [
        (h.entry, b"\x48\xa1" + struct.pack("<Q", address)),
        (h.entry + 10, b"\x48\xa3" + struct.pack("<Q", h.output)),
        (h.entry + 20, b"\xc3"),
    ]
    inputs = [(0x400800, struct.pack("<Q", h.stop))]
    if not missing:
        value = struct.pack("<Q", 9)
        if missing_byte is None:
            inputs.append((address, value))
        else:
            inputs.extend(
                (address + i, value[i : i + 1]) for i in range(8) if i != missing_byte
            )
    h.input_bytes = sum(len(b) for _, b in inputs)
    pages = sorted(
        {0x100000, 0x300000, 0x400000, address & ~4095, (address + 7) & ~4095}
    )
    h.page_count, h.code_count, h.input_count = (
        len(pages),
        len(instructions),
        len(inputs),
    )
    h.digest[:] = hashlib.sha256(struct.pack("<Q", 8 if mismatch else 9)).digest()
    blob = bytes(h) + struct.pack("<" + "Q" * len(pages), *pages)
    for address, instruction in instructions:
        blob += struct.pack("<QB15s", address, len(instruction), instruction)
    for address, data in inputs:
        blob += struct.pack("<QQ", address, len(data)) + data
    return blob


def receive(sock, n):
    data = b""
    while len(data) < n:
        part = sock.recv(n - len(data))
        assert part, "worker disconnected"
        data += part
    return data


@pytest.fixture
def worker():
    client, server = socket.socketpair()
    client.settimeout(10)
    process = subprocess.Popen(
        [str(WORKER), str(server.fileno())], pass_fds=(server.fileno(),)
    )
    server.close()
    try:
        yield client
    finally:
        client.close()
        process.wait(timeout=10)


@pytest.fixture(params=[65536, 262144, 1048576])
def shared_worker(request):
    capacity = request.param
    fd = os.memfd_create("afterfree-test-window", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    os.ftruncate(fd, capacity)
    fcntl.fcntl(fd, 1033, 1 | 2 | 4)
    arena = mmap.mmap(fd, capacity, flags=mmap.MAP_SHARED, prot=mmap.PROT_READ)
    client, server = socket.socketpair()
    client.settimeout(10)
    process = subprocess.Popen(
        [str(WORKER), str(server.fileno()), "shared"], pass_fds=(server.fileno(),)
    )
    server.close()
    client.sendmsg(
        [b"\0"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [fd]))]
    )
    os.close(fd)
    try:
        yield client, arena
    finally:
        client.close()
        arena.close()
        process.wait(timeout=10)


def test_stream_commit_and_shared_replay_require_exact_acknowledgement(shared_worker):
    client, arena = shared_worker
    blob = recipe()
    client.sendall(struct.pack("<QQQ", 12, 81, len(blob)) + blob)
    status, length, _ = struct.unpack("<QQ240s", receive(client, 256))
    assert status == 0 and length == 8 and arena[:8] == struct.pack("<Q", 9)
    client.sendall(struct.pack("<QQQ", 13, 81, 8))
    status, length, _ = struct.unpack("<QQ240s", receive(client, 256))
    assert status == length == 0
    backend, page, retained = struct.unpack("<QQQ", receive(client, 24))
    assert backend == 1 and page == 4096 and retained > 0
    client.sendall(struct.pack("<QQQ", 11, 81, 8))
    status, length, _ = struct.unpack("<QQ240s", receive(client, 256))
    assert status == 0 and length == 8 and arena[:8] == struct.pack("<Q", 9)
    client.sendall(struct.pack("<QQQ", 11, 81, 65537))
    status, _, _ = struct.unpack("<QQ240s", receive(client, 256))
    assert status == 1


def test_bad_stream_acknowledgement_does_not_commit_recipe(shared_worker):
    client, arena = shared_worker
    blob = recipe()
    client.sendall(struct.pack("<QQQ", 12, 93, len(blob)) + blob)
    status, length, _ = struct.unpack("<QQ240s", receive(client, 256))
    assert status == 0 and length == 8
    client.sendall(struct.pack("<QQQ", 13, 93, 7))
    status, _, message = struct.unpack("<QQ240s", receive(client, 256))
    assert status == 1 and b"acknowledgement" in message
    client.sendall(struct.pack("<QQQ", 2, 93, 0))
    status, _, message = struct.unpack("<QQ240s", receive(client, 256))
    assert status == 1 and b"not found" in message


def test_stream_uses_negotiated_window_and_preserves_sparse_restore(shared_worker):
    from test_replay_bounds import loop_recipe

    client, arena = shared_worker
    total = len(arena) * 2 + 17
    blob = loop_recipe(length=total)
    client.sendall(struct.pack("<QQQ", 12, 45, len(blob)) + blob)
    offset = 0
    while offset < total:
        status, length, message = struct.unpack("<QQ240s", receive(client, 256))
        assert status == 0 and length == min(len(arena), total - offset), message
        assert arena[:length] == bytes(length)
        offset += length
        client.sendall(struct.pack("<QQQ", 13, 45, offset))
    status, length, message = struct.unpack("<QQ240s", receive(client, 256))
    assert status == length == 0, message
    backend, page, _ = struct.unpack("<QQQ", receive(client, 24))
    assert backend == 1 and page == 4096
    client.sendall(struct.pack("<QQQ", 11, 45, (65536 << 32) | 4096))
    status, length, message = struct.unpack("<QQ240s", receive(client, 256))
    assert status == 0 and length == 4096 and arena[:length] == bytes(length), message


@pytest.mark.parametrize("invalid", ["missing", "mismatch"])
def test_stream_failure_keeps_worker_usable(shared_worker, invalid):
    client, _ = shared_worker
    blob = recipe(**{invalid: True})
    client.sendall(struct.pack("<QQQ", 12, 71, len(blob)) + blob)
    while True:
        status, length, _ = struct.unpack("<QQ240s", receive(client, 256))
        if status:
            break
        assert length == 8
        client.sendall(struct.pack("<QQQ", 13, 71, 8))
    assert status == 1
    client.sendall(struct.pack("<QQQ", 5, 0, 0))
    assert struct.unpack("<QQ240s", receive(client, 256))[0] == 0


def submit(worker, blob):
    worker.sendall(struct.pack("<QQQ", 1, 1, len(blob)) + blob)
    status, size, message = struct.unpack("<QQ240s", receive(worker, 256))
    return status, size, message.split(b"\0")[0].decode()


def test_missing_live_input_is_rejected(worker):
    status, _, message = submit(worker, recipe(missing=True))
    assert status == 1
    assert "missing input byte" in message


def test_digest_mismatch_is_rejected(worker):
    status, _, message = submit(worker, recipe(mismatch=True))
    assert status == 1
    assert "digest mismatch" in message


def test_strict_validation_then_fast_replay_still_checks_exact_output(worker):
    status, size, message = submit(worker, recipe())
    assert status == 0, message
    assert receive(worker, size) == struct.pack("<Q", 9)
    for _ in range(3):
        worker.sendall(struct.pack("<QQQ", 2, 1, 0))
        status, size, message = struct.unpack("<QQ240s", receive(worker, 256))
        assert status == 0, message
        assert receive(worker, size) == struct.pack("<Q", 9)


def test_truncated_recipe_is_rejected_without_killing_worker(worker):
    blob = recipe()[:-1]
    status, _, message = submit(worker, blob)
    assert status == 1
    assert "truncated" in message
    status, size, message = submit(worker, recipe())
    assert status == 0, message
    assert len(receive(worker, size)) == 8


def test_worker_cannot_open_files_or_create_network_sockets(worker):
    worker.sendall(struct.pack("<QQQ", 6, 0, 0))
    status, size, message = struct.unpack("<QQ240s", receive(worker, 256))
    assert status == 0, message
    assert size == 0


@pytest.mark.parametrize("offset", [1, 57, 63, 64, 4091, 4095, 4096])
def test_missing_zero_byte_at_word_and_page_boundaries_is_rejected(worker, offset):
    status, _, message = submit(worker, recipe(offset=offset, missing_byte=7))
    assert status == 1 and "missing input byte" in message
    status, size, message = submit(worker, recipe(offset=offset))
    assert status == 0, message
    assert receive(worker, size) == struct.pack("<Q", 9)


@pytest.mark.parametrize("steps", [2, 4])
def test_block_validation_preserves_exact_instruction_count(worker, steps):
    status, _, message = submit(worker, recipe(steps=steps))
    assert status == 1
    assert "instruction bound" in message or "control flow" in message


def test_correct_digest_does_not_authorize_unwritten_output(worker):
    blob = recipe()
    header = Header.from_buffer_copy(blob)
    header.length = 16
    header.digest[:] = hashlib.sha256(struct.pack("<QQ", 9, 0)).digest()
    status, _, message = submit(worker, bytes(header) + blob[C.sizeof(Header) :])
    assert status == 1 and "every output byte" in message


def test_conflicting_or_duplicate_input_segments_rejected(worker):
    blob = recipe()
    h = Header.from_buffer_copy(blob)
    h.input_count += 1
    h.input_bytes += 8
    for value in [9, 10]:
        status, _, message = submit(
            worker,
            bytes(h)
            + blob[C.sizeof(Header) :]
            + struct.pack("<QQQ", 0x200000, 8, value),
        )
        assert status == 1 and "overlapping recipe inputs" in message


def test_reserved_mxcsr_bits_rejected_without_worker_death(worker):
    blob = recipe()
    h = Header.from_buffer_copy(blob)
    h.mxcsr |= 1 << 16
    status, _, _ = submit(worker, bytes(h) + blob[C.sizeof(Header) :])
    assert status == 1
    status, size, message = submit(worker, blob)
    assert status == 0, message
    assert receive(worker, size) == struct.pack("<Q", 9)


def test_page_protocol_bounds_and_final_short_page(worker):
    blob = recipe()
    worker.sendall(struct.pack("<QQQ", 7, 1, len(blob)) + blob)
    status, size, message = struct.unpack("<QQ240s", receive(worker, 256))
    assert status == 0, message
    backend, page_bytes, retained = struct.unpack("<QQQ", receive(worker, 24))
    assert backend == 1 and page_bytes == 4096 and retained > 0
    assert receive(worker, size) == struct.pack("<Q", 9)
    for offset, length in [
        (1, 7),
        (0, 0),
        (0, 9),
        (4096, 8),
        (0, 4),
        (2**32 - 4096, 4096),
    ]:
        worker.sendall(struct.pack("<QQQ", 8, 1, offset << 32 | length))
        status, size, _ = struct.unpack("<QQ240s", receive(worker, 256))
        assert status == 1 and size == 0
    worker.sendall(struct.pack("<QQQ", 8, 1, 8))
    status, size, message = struct.unpack("<QQ240s", receive(worker, 256))
    assert status == 0, message
    assert receive(worker, size) == struct.pack("<Q", 9)
