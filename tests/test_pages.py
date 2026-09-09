"""Page replay invariants checked through ordinary pointers and independent bytes."""

import ctypes as C
from pathlib import Path
import pytest
from afterfree import Runtime, AfterfreeError

PAGE = 4096
MASK = 2**64 - 1
LIB = Path(__file__).resolve().parents[1] / "afterfree/_native/libafterfree-fixtures.so"


def capture(runtime, size=2**20):
    buffer = runtime.alloc(size)
    result = runtime.capture(
        C.CDLL(str(LIB)).expand, buffer, size // 8, 42, output=buffer
    )
    assert result.eligible, result.reason
    assert result.stats["backend"] == 1 and result.stats["page_bytes"] == PAGE
    return buffer, buffer.read()


def test_sparse_pages_and_partial_reeviction():
    with Runtime() as runtime:
        buffer, expected = capture(runtime)
        buffer.evict()
        for count, page in enumerate([0, 127, 31, 255], 1):
            assert (
                C.c_ubyte.from_address(buffer.address + page * PAGE).value
                == expected[page * PAGE]
            )
            assert buffer.resident_bytes == count * PAGE
            assert buffer.stats["reconstructed_bytes"] == count * PAGE
        buffer.evict()
        assert buffer.resident_bytes == runtime.residency["resident_bytes"] == 0
        assert buffer.read(31 * PAGE, 1) == expected[31 * PAGE : 31 * PAGE + 1]
        assert buffer.resident_bytes == PAGE
        assert buffer.stats["reconstructed_bytes"] == 5 * PAGE
        assert buffer.read() == expected
        assert buffer.stats["full_restores"] == 1


def test_sequential_readahead_is_bounded_and_never_repeats():
    with Runtime() as runtime:
        buffer, expected = capture(runtime)
        buffer.evict()
        previous = 0
        for page in range(buffer.size // PAGE):
            assert (
                C.c_ubyte.from_address(buffer.address + page * PAGE).value
                == expected[page * PAGE]
            )
            reconstructed = buffer.stats["reconstructed_bytes"]
            assert 0 <= reconstructed - previous <= 16 * PAGE
            assert reconstructed == buffer.resident_bytes
            previous = reconstructed
        assert previous == buffer.size
        assert buffer.stats["full_restores"] == 1
        assert buffer.read() == expected


@pytest.mark.parametrize("api", [False, True])
def test_cross_page_write_only_restores_touched_pages_then_retires(api):
    with Runtime() as runtime:
        buffer, expected = capture(runtime)
        buffer.evict()
        offset, value = 7 * PAGE - 3, 0x0102030405060708
        if api:
            buffer.write(value.to_bytes(8, "little"), offset)
        else:
            C.c_uint64.from_address(buffer.address + offset).value = value
        assert buffer.resident_bytes == 2 * PAGE
        assert buffer.stats["state"] == "pinned"
        assert buffer.stats["reconstructed_bytes"] == 2 * PAGE
        with pytest.raises(AfterfreeError, match="modified"):
            buffer.evict()
        expected = (
            expected[:offset] + value.to_bytes(8, "little") + expected[offset + 8 :]
        )
        assert buffer.read() == expected
        assert buffer.stats["reconstructed_bytes"] == buffer.size
        assert buffer.stats["retained_bytes"] == (buffer.size + PAGE - 1) // PAGE


def test_partial_final_page_and_unaligned_cross_page_load():
    with Runtime() as runtime:
        buffer, expected = capture(runtime, 65536 + 24)
        buffer.evict()
        assert buffer.read(65536, 24) == expected[65536:]
        assert buffer.stats["reconstructed_bytes"] == 24
        assert buffer.resident_bytes == PAGE
        offset = 4 * PAGE - 3
        assert C.c_uint64.from_address(buffer.address + offset).value == int.from_bytes(
            expected[offset : offset + 8], "little"
        )
        assert buffer.read() == expected
        assert buffer.stats["reconstructed_bytes"] == buffer.size
        assert buffer.stats["full_restores"] == 1


@pytest.mark.parametrize("seed", [0, MASK, MASK - 1])
@pytest.mark.parametrize("shift", [0, 64, 1])
def test_checkpoint_flags_zero_count_shift_and_carry(seed, shift):
    lib = C.CDLL(str(LIB))
    n = 8192
    x, carry = seed, 1
    expected = bytearray()
    for _ in range(n):
        total = x + carry
        x, carry = total & MASK, total >> 64
        expected.extend(x.to_bytes(8, "little"))
        if shift & 63:
            carry = 0
    original = (C.c_uint64 * n)()
    lib.flag_chain.argtypes = [C.c_void_p, C.c_size_t, C.c_uint64, C.c_uint64]
    lib.flag_chain(original, n, seed, shift)
    assert bytes(original) == expected
    with Runtime() as runtime:
        buffer = runtime.alloc(n * 8)
        cap = runtime.capture(lib.flag_chain, buffer, n, seed, shift, output=buffer)
        assert cap.eligible, cap.reason
        assert cap.stats["backend"] == 1 and cap.stats["page_bytes"] == PAGE
        buffer.evict()
        for page in [15, 7, 0, 9]:
            assert (
                buffer.read(page * PAGE, PAGE)
                == expected[page * PAGE : (page + 1) * PAGE]
            )
        assert buffer.read() == expected


def test_aligned_simd_load_from_unaligned_snapshot_segment():
    storage = (C.c_ubyte * 80)(*range(80))
    pointer = (C.addressof(storage) + 15) & ~15
    expected = C.string_at(pointer + 16, 16) * 4096
    with Runtime() as runtime:
        buffer = runtime.alloc(len(expected))
        cap = runtime.capture(
            C.CDLL(str(LIB)).aligned_copy, buffer, 4096, pointer, output=buffer
        )
        assert cap.eligible, cap.reason
        assert cap.stats["backend"] == 1 and cap.stats["page_bytes"] == PAGE
        C.memset(pointer, 0, 32)
        buffer.evict()
        for page in [15, 7, 0, 9]:
            assert (
                buffer.read(page * PAGE, PAGE)
                == expected[page * PAGE : (page + 1) * PAGE]
            )
        assert buffer.read() == expected


@pytest.mark.parametrize("seed,shift", [(0, 0), (MASK, 0), (MASK - 1, 64), (MASK, 1)])
def test_stream_validation_preserves_state_across_windows(seed, shift):
    n = 32769  # Four windows and a final eight-byte tail.
    lib = C.CDLL(str(LIB))
    lib.flag_chain.argtypes = [C.c_void_p, C.c_size_t, C.c_uint64, C.c_uint64]
    reference = (C.c_uint64 * n)()
    lib.flag_chain(reference, n, seed, shift)
    with Runtime() as runtime:
        buffer = runtime.alloc(n * 8)
        result = runtime.capture(lib.flag_chain, buffer, n, seed, shift, output=buffer)
        assert result.eligible and result.stats["page_bytes"] == PAGE, result.reason
        assert buffer.read() == bytes(reference)
        buffer.evict()
        for offset in [65536, 3 * 65536, n * 8 - 8, 0]:
            assert buffer.read(offset, 8) == bytes(reference)[offset : offset + 8]
        assert buffer.read() == bytes(reference)


def test_range_prefault_index_survives_holes_and_reused_addresses():
    with Runtime() as runtime:
        entries = [capture(runtime, 65536) for _ in range(5)]
        entries.sort(key=lambda item: item[0].address)
        entries[2][0].close()
        live = entries[:2] + entries[3:]
        for buffer, _ in live:
            buffer.evict()
        low = live[0][0].address
        high = live[-1][0].address + live[-1][0].size
        assert runtime._lib.af_prepare_read(low, high - low) == 0
        for buffer, expected in live:
            assert buffer.resident_bytes == buffer.size
            assert buffer.read() == expected
        for _ in range(8):
            buffer = runtime.alloc(65536)
            buffer.write(b"replacement")
            assert buffer.read(0, 11) == b"replacement"
            buffer.close()
