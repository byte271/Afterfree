#!/usr/bin/env python3
"""Verify three frozen inputs with the installed, unmodified GNU gzip binary.

This is a compatibility probe. It does not claim a constrained-memory win.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import random
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from afterfree.cli import SSE2, events, run_command
from afterfree.measure import measure


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    executable = shutil.which("gzip")
    if not executable:
        parser.error("GNU gzip is required")
    env = {
        k: v
        for k, v in os.environ.items()
        if not k.startswith("AF_") and k not in {"LD_PRELOAD", "LD_AUDIT"}
    }
    env["GLIBC_TUNABLES"] = SSE2
    version = subprocess.check_output(
        [executable, "--version"], env=env, text=True
    ).splitlines()[0]
    cache = ROOT / ".cache/gzip"
    cache.mkdir(parents=True, exist_ok=True)
    workloads = {
        "repeated": (b"Afterfree observes original native code.\n" * 30000)[:1048576],
        "sparse": b"\0" * 458752 + bytes(range(256)) * 512 + b"\0" * 458752,
        "random": random.Random(701).randbytes(1048576),
    }
    report = {
        "schema": "afterfree.gzip.v1",
        "upstream": version,
        "binary_sha256": hashlib.sha256(Path(executable).read_bytes()).hexdigest(),
        "provenance": "installed distribution executable; neither source nor binary modified in this work",
        "glibc_tunables_all_runs": SSE2,
        "workloads": [],
        "hard_limit_tested": False,
        "launch_gate_passed": False,
    }
    for name, data in workloads.items():
        source, compressed, log = (
            cache / f"{name}.bin",
            cache / f"{name}.gz",
            cache / f"{name}.jsonl",
        )
        source.write_bytes(data)
        with compressed.open("wb") as stream:
            subprocess.run(
                [executable, "-n", "-c", str(source)],
                env=env,
                stdout=stream,
                check=True,
            )
        command = [executable, "-d", "-c", str(compressed)]
        baseline = measure(command, env=env)
        launch = run_command(command, log)
        after = measure(launch, env=env, event_path=log)
        expected = hashlib.sha256(data).hexdigest()
        exact = (
            baseline["exit_code"] == after["exit_code"] == 0
            and baseline["stdout_bytes"] == after["stdout_bytes"] == len(data)
            and baseline["stdout_sha256"] == after["stdout_sha256"] == expected
        )
        for result in (baseline, after):
            result.pop("stdout", None)
            result["stdout_preview_omitted"] = (
                "binary output; full SHA-256 and byte count retained"
            )
        row = {
            "name": name,
            "input_bytes": len(data),
            "input_sha256": expected,
            "compressed_bytes": compressed.stat().st_size,
            "compressed_sha256": hashlib.sha256(compressed.read_bytes()).hexdigest(),
            "baseline": baseline,
            "afterfree": after,
            "events": events(log),
            "same_output": exact,
        }
        report["workloads"].append(row)
        print(f"{name}: {'PASS' if exact else 'FAIL'}", flush=True)
    report["all_outputs_exact"] = all(row["same_output"] for row in report["workloads"])
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    return 0 if report["all_outputs_exact"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
