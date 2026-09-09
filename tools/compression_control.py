#!/usr/bin/env python3
"""Check ordinary compression against one independently generated demo buffer."""
import argparse
import ctypes as C
import hashlib
import json
from pathlib import Path
import zlib

ROOT = Path(__file__).resolve().parents[1]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    library = C.CDLL(str(ROOT / "afterfree/_native/libafterfree-fixtures.so"))
    library.expand.argtypes = [C.c_void_p, C.c_size_t, C.c_uint64]
    library.expand.restype = C.c_uint64
    size = 4 * 1024 * 1024
    output = C.create_string_buffer(size)
    assert library.expand(output, size // 8, 42) == size // 8
    data = output.raw
    compressed = zlib.compress(data, level=9)
    result = {
        "workload": "xorshift native expansion fixture",
        "seed": 42,
        "output_bytes": size,
        "output_sha256": hashlib.sha256(data).hexdigest(),
        "zlib_version": zlib.ZLIB_VERSION,
        "zlib_level": 9,
        "compressed_bytes": len(compressed),
        "compression_ratio": len(compressed) / size,
        "note": "This synthetic control does not establish useful memory savings on an upstream application.",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
