#!/usr/bin/env python3
"""Probe the installed, unchanged Zstandard CLI on checksum-pinned upstream data."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from afterfree.cli import SSE2, events, run_command
from afterfree.measure import measure
from build import QBDI, ZYDIS, download


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    binary = shutil.which("zstd")
    if not binary:
        parser.error("the distribution zstd executable is required")
    cache = ROOT / ".cache"
    download(QBDI, cache / "qbdi.tar.gz")
    download(ZYDIS, cache / "zydis-amalgamated.tar.gz")
    env = {
        k: v
        for k, v in os.environ.items()
        if not k.startswith("AF_") and k not in {"LD_PRELOAD", "LD_AUDIT"}
    }
    env["GLIBC_TUNABLES"] = SSE2
    report = {
        "schema": "afterfree.zstd.v1",
        "upstream": subprocess.check_output([binary, "--version"], text=True),
        "binary_sha256": hashlib.sha256(Path(binary).read_bytes()).hexdigest(),
        "inputs": {"qbdi.tar.gz": QBDI, "zydis-amalgamated.tar.gz": ZYDIS},
        "note": "Unchanged installed native executable; unchanged upstream release archives supplied on stdin. Identical single-thread options and CPU environment. Failed and timed-out runs remain failures.",
        "workloads": [],
    }
    for name, level in [("qbdi.tar.gz", 3), ("zydis-amalgamated.tar.gz", 19)]:
        source = cache / name
        command = [binary, "-q", "--single-thread", "--no-asyncio", f"-{level}", "-c"]
        log = cache / f"zstd-{level}.jsonl"
        baseline = measure(command, env=env, stdin_path=source, timeout=60)
        launch = run_command(command, log)
        after = measure(launch, env=env, event_path=log, stdin_path=source, timeout=60)
        exact = (
            baseline["exit_code"] == after["exit_code"] == 0
            and baseline["stdout_sha256"] == after["stdout_sha256"]
            and baseline["stdout_bytes"] == after["stdout_bytes"]
        )
        for result in (baseline, after):
            result.pop("stdout", None)
        report["workloads"].append(
            {
                "name": f"{name}-level{level}",
                "baseline": baseline,
                "afterfree": after,
                "same_output": exact,
                "events": events(log),
            }
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n")
        print(name, level, "PASS" if exact else "FAIL", flush=True)
    report["all_outputs_exact"] = all(row["same_output"] for row in report["workloads"])
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    return 0 if report["all_outputs_exact"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
