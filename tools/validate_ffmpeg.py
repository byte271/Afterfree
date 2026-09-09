#!/usr/bin/env python3
"""Frozen unchanged FFmpeg reverse-video probes; publish all outcomes."""
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
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    binary = shutil.which("ffmpeg")
    if not binary:
        p.error("the installed FFmpeg executable is required")
    env = {
        k: v
        for k, v in os.environ.items()
        if not k.startswith("AF_") and k not in {"LD_PRELOAD", "LD_AUDIT"}
    }
    env["GLIBC_TUNABLES"] = SSE2
    report = {
        "schema": "afterfree.ffmpeg.v1",
        "upstream": subprocess.check_output([binary, "-version"], text=True),
        "binary_sha256": hashlib.sha256(Path(binary).read_bytes()).hexdigest(),
        "note": "Unchanged distribution executable. Frozen generated-video inputs exercise a real reverse filter; these are application probes, not a substitute for externally sourced media. Identical CPU flags, a declared one-CPU execution setting, thread options, frame counts and output format. Every result is retained.",
        "workloads": [],
        "launch_gate_passed": False,
    }
    cache = ROOT / ".cache/ffmpeg"
    cache.mkdir(parents=True, exist_ok=True)
    for name, source, side in [
        ("color-small", "color=c=navy:s=512x512:r=1", 512),
        ("color-large", "color=c=navy:s=2048x2048:r=1", 2048),
        ("pattern-large", "testsrc2=s=2048x2048:r=1", 2048),
    ]:
        command = [
            binary,
            "-hide_banner",
            "-loglevel",
            "error",
            "-nostdin",
            "-cpuflags",
            "0",
            "-cpucount",
            "1",
            "-threads",
            "1",
            "-filter_threads",
            "1",
            "-filter_complex_threads",
            "1",
            "-f",
            "lavfi",
            "-i",
            source,
            "-frames:v",
            "8",
            "-vf",
            "trim=end_frame=8,reverse",
            "-threads",
            "1",
            "-pix_fmt",
            "yuv420p",
            "-f",
            "rawvideo",
            "pipe:1",
        ]
        log = cache / (name + ".jsonl")
        native = measure(command, env=env, timeout=60)
        launch = run_command(command, log)
        after = measure(launch, env=env, event_path=log, timeout=60)
        exact = (
            native["exit_code"] == after["exit_code"] == 0
            and native["stdout_bytes"]
            == after["stdout_bytes"]
            == side * side * 3 // 2 * 8
            and native["stdout_sha256"] == after["stdout_sha256"]
        )
        for result in (native, after):
            result.pop("stdout", None)
        report["workloads"].append(
            {
                "name": name,
                "source": source,
                "baseline": native,
                "afterfree": after,
                "events": events(log) if log.exists() else [],
                "same_output": exact,
            }
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n")
        print(name, "PASS" if exact else "FAIL", after["exit_code"], flush=True)
    report["all_outputs_exact"] = all(w["same_output"] for w in report["workloads"])
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    return 0 if report["all_outputs_exact"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
