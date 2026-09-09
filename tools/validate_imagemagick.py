#!/usr/bin/env python3
"""Compare complete output of installed ImageMagick, including failed probes."""
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    binary = shutil.which("convert")
    if not binary:
        parser.error("ImageMagick convert is required")
    env = {
        k: v
        for k, v in os.environ.items()
        if not k.startswith("AF_") and k not in {"LD_PRELOAD", "LD_AUDIT"}
    }
    env.update(GLIBC_TUNABLES=SSE2, MAGICK_THREAD_LIMIT="1", OMP_NUM_THREADS="1")
    report = {
        "schema": "afterfree.imagemagick.v1",
        "upstream": subprocess.check_output([binary, "-version"], text=True),
        "binary_sha256": hashlib.sha256(Path(binary).read_bytes()).hexdigest(),
        "provenance": "installed distribution executable; neither source nor binary modified",
        "matching_environment": {
            key: env[key]
            for key in ["GLIBC_TUNABLES", "MAGICK_THREAD_LIMIT", "OMP_NUM_THREADS"]
        },
        "hard_limit_tested": False,
        "launch_gate_passed": False,
        "workloads": [],
    }
    cache = ROOT / ".cache/imagemagick"
    cache.mkdir(exist_ok=True)
    for side in [2048, 4096]:
        log = cache / f"gradient-{side}.jsonl"
        command = [
            binary,
            "-limit",
            "thread",
            "1",
            "-size",
            f"{side}x{side}",
            "gradient:",
            "-depth",
            "8",
            "RGB:-",
        ]
        baseline = measure(command, env=env, timeout=60)
        launch = run_command(command, log)
        after = measure(launch, env=env, event_path=log, timeout=60)
        same = (
            baseline["exit_code"] == after["exit_code"] == 0
            and baseline["stdout_bytes"] == after["stdout_bytes"] == side * side * 3
            and baseline["stdout_sha256"] == after["stdout_sha256"]
        )
        for result in (baseline, after):
            result.pop("stdout", None)
        try:
            data = events(log)
        except Exception as error:
            data = [{"event": "report_error", "reason": str(error)}]
        report["workloads"].append(
            {
                "name": f"gradient-{side}",
                "baseline": baseline,
                "afterfree": after,
                "same_output": same,
                "events": data,
            }
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n")
        print(f"{side}: {'PASS' if same else 'FAIL'}", flush=True)
    report["all_outputs_exact"] = all(row["same_output"] for row in report["workloads"])
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    return 0 if report["all_outputs_exact"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
