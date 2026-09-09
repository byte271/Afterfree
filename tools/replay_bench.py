#!/usr/bin/env python3
"""Separate learning, strict validation, and later fault costs for one buffer."""
import argparse
import ctypes as C
import hashlib
import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from afterfree import Runtime


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    size = 4 * 1024 * 1024
    native = C.CDLL(str(ROOT / "afterfree/_native/libafterfree-fixtures.so"))
    native.expand.argtypes = [C.c_void_p, C.c_size_t, C.c_uint64]
    native.expand.restype = C.c_uint64
    reference = C.create_string_buffer(size)
    baseline = []
    for _ in range(3):
        start = time.perf_counter_ns()
        native.expand(reference, size // 8, 42)
        baseline.append(time.perf_counter_ns() - start)
    expected = hashlib.sha256(reference).hexdigest()
    with Runtime() as runtime:
        buffer = runtime.alloc(size)
        cap = runtime.capture(native.expand, buffer, size // 8, 42, output=buffer)
        if not cap.eligible:
            raise RuntimeError(cap.reason)
        faults, volumes, full_times = [], [], []
        for _ in range(3):
            buffer.evict()
            assert buffer.resident_bytes == 0
            previous = buffer.stats["restore_ns"]
            previous_bytes = buffer.stats["reconstructed_bytes"]
            C.c_ubyte.from_address(buffer.address).value
            faults.append(buffer.stats["restore_ns"] - previous)
            volumes.append(buffer.stats["reconstructed_bytes"] - previous_bytes)
            before_full = buffer.stats["restore_ns"]
            assert hashlib.sha256(buffer.read()).hexdigest() == expected
            full_times.append(buffer.stats["restore_ns"] - before_full)
        result = {
            "schema": "afterfree.replay.v1",
            "kind": "synthetic latency measurement",
            "bytes": size,
            "native_call_ns": baseline,
            "capture_ns": cap.stats["capture_ns"],
            "strict_validation_ns": cap.stats["validation_ns"],
            "fault_restore_ns": faults,
            "recipe_bytes": cap.stats["recipe_bytes"],
            "input_bytes": cap.stats["input_bytes"],
            "sha256": expected,
            "trigger_read_bytes": 1,
            "reconstructed_bytes_per_fault": volumes,
            "remaining_restore_ns": full_times,
            "backend": cap.stats["backend"],
            "page_bytes": cap.stats["page_bytes"],
            "retained_bytes": cap.stats["retained_bytes"],
            "restore_operations": runtime.residency["restore_operations"],
            "restored_bytes": runtime.residency["restored_bytes"],
            "all_outputs_exact": True,
            "note": "All learning and validation reported. Each sparse fault restores one page; full reads then consume every remaining byte. Immutable checkpoints retain address and instruction guards plus page digests. This measures latency, not aggregate memory.",
        }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
