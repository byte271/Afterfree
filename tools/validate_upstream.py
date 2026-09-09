#!/usr/bin/env python3
"""Freeze three inputs and compare an unchanged upstream LZ4 CLI byte-for-byte."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import random
import subprocess
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from afterfree.cli import SSE2, events, run_command
from afterfree.measure import measure
from build import download

LZ4 = {
    "url": "https://github.com/lz4/lz4/archive/refs/tags/v1.10.0.tar.gz",
    "sha256": "537512904744b35e232912055ccf8ec66d768639ff3abe5788d90d792ec5f48b",
}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    cache = ROOT / ".cache/upstream"
    cache.mkdir(parents=True, exist_ok=True)
    download(LZ4, cache / "lz4.tar.gz")
    with tarfile.open(cache / "lz4.tar.gz") as archive:
        archive.extractall(cache, filter="data")
    source = cache / "lz4-1.10.0/programs"
    build = subprocess.run(
        ["make", "-j2", "HAVE_MULTITHREAD=0", "lz4"],
        cwd=source,
        text=True,
        capture_output=True,
    )
    if build.returncode:
        raise RuntimeError(build.stderr)
    executable = source / "lz4"
    workloads = {
        "repeated": (b"Afterfree observes original native code.\n" * 30000)[:1048576],
        "sparse": b"\0" * 458752 + bytes(range(256)) * 512 + b"\0" * 458752,
        "random": random.Random(701).randbytes(1048576),
    }
    report = {
        "schema": "afterfree.upstream.v1",
        "upstream": "LZ4 CLI 1.10.0",
        "source": LZ4,
        "build_mode": "HAVE_MULTITHREAD=0; unchanged source",
        "binary_sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
        "glibc_tunables_both_runs": SSE2,
        "workloads": [],
        "hard_aggregate_limit_tested": False,
    }
    baseline_env = os.environ.copy()
    if baseline_env.get("LD_PRELOAD"):
        raise RuntimeError("validation requires an empty LD_PRELOAD")
    baseline_env["GLIBC_TUNABLES"] = SSE2
    for name, data in workloads.items():
        original, compressed = cache / f"{name}.bin", cache / f"{name}.lz4"
        output, log = cache / f"{name}.out", cache / f"{name}.jsonl"
        original.write_bytes(data)
        subprocess.run(
            [str(executable), "-q", "-f", "-B4", str(original), str(compressed)],
            env=baseline_env,
            check=True,
        )
        command = [str(executable), "-q", "-d", "-f", str(compressed), str(output)]
        output.unlink(missing_ok=True)
        baseline = measure(command, env=baseline_env)
        baseline_bytes = output.read_bytes() if output.exists() else b""
        launch = run_command(command, log)
        output.unlink(missing_ok=True)
        transformed = measure(launch, event_path=log)
        transformed_bytes = output.read_bytes() if output.exists() else b""
        row = {
            "name": name,
            "input_bytes": len(data),
            "compressed_bytes": compressed.stat().st_size,
            "input_sha256": hashlib.sha256(data).hexdigest(),
            "compressed_sha256": hashlib.sha256(compressed.read_bytes()).hexdigest(),
            "baseline": baseline,
            "afterfree": transformed,
            "events": events(log),
            "same_output": baseline["exit_code"] == transformed["exit_code"] == 0
            and baseline_bytes == transformed_bytes == data,
            "baseline_output_bytes": len(baseline_bytes),
            "afterfree_output_bytes": len(transformed_bytes),
            "baseline_output_sha256": hashlib.sha256(baseline_bytes).hexdigest(),
            "afterfree_output_sha256": hashlib.sha256(transformed_bytes).hexdigest(),
        }
        report["workloads"].append(row)
        print(f"{name}: {'PASS' if row['same_output'] else 'FAIL'}", flush=True)
    report["all_outputs_exact"] = all(row["same_output"] for row in report["workloads"])
    report["launch_gate_passed"] = False
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    return 0 if report["all_outputs_exact"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
