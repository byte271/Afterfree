#!/usr/bin/env python3
"""Run one command in an already delegated cgroup v2, with swap disabled."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time
import uuid


def counters(path):
    return {
        line.split()[0]: int(line.split()[1]) for line in path.read_text().splitlines()
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--parent", type=Path, required=True)
    p.add_argument("--mib", type=int, required=True)
    p.add_argument("--timeout", type=float, default=180)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("command", nargs=argparse.REMAINDER)
    args = p.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command or args.mib < 1 or args.timeout <= 0:
        p.error("a command, positive MiB limit, and positive timeout are required")
    result = {
        "schema": "afterfree.cgroup.v1",
        "command": command,
        "memory_limit_bytes": args.mib * 2**20,
        "swap_limit_bytes": 0,
    }
    group = args.parent / ("afterfree-" + uuid.uuid4().hex[:12])
    process = None
    try:
        group.mkdir()
        required = [
            "memory.max",
            "memory.swap.max",
            "memory.peak",
            "memory.events",
            "cgroup.procs",
            "cgroup.kill",
        ]
        if any(not (group / name).exists() for name in required):
            raise OSError("delegated cgroup lacks required memory or process controls")
        (group / "memory.max").write_text(str(args.mib * 2**20))
        (group / "memory.swap.max").write_text("0")
        if int((group / "memory.swap.max").read_text()) != 0:
            raise OSError("could not disable cgroup swap")
        before = counters(group / "memory.events")

        def attach():
            os.setsid()
            (group / "cgroup.procs").write_text(str(os.getpid()))

        start = time.monotonic()
        with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
            process = subprocess.Popen(
                command, stdout=output, stderr=errors, preexec_fn=attach
            )
            try:
                process.wait(timeout=args.timeout)
                result["timed_out"] = False
            except subprocess.TimeoutExpired:
                (group / "cgroup.kill").write_text("1")
                process.wait(timeout=10)
                result["timed_out"] = True
            result.update(
                status="measured",
                exit_code=process.returncode,
                wall_seconds=time.monotonic() - start,
                aggregate_peak_bytes=int((group / "memory.peak").read_text()),
            )
            after = counters(group / "memory.events")
            result["memory_events_delta"] = {
                k: v - before.get(k, 0) for k, v in after.items()
            }
            output.seek(0)
            digest = hashlib.sha256()
            for chunk in iter(lambda: output.read(1024 * 1024), b""):
                digest.update(chunk)
            result["stdout_sha256"] = digest.hexdigest()
            errors.seek(0)
            result["stderr"] = errors.read(65536).decode("utf-8", "replace")
    except (OSError, subprocess.SubprocessError) as e:
        result.update(status="unavailable", reason=str(e), hard_limit_tested=False)
    finally:
        if group.exists():
            try:
                if (group / "cgroup.kill").exists():
                    (group / "cgroup.kill").write_text("1")
                if process is not None and process.poll() is None:
                    process.wait(timeout=10)
                group.rmdir()
            except (OSError, subprocess.SubprocessError) as e:
                result["cleanup_error"] = str(e)
    if result.get("status") == "measured":
        result["hard_limit_tested"] = True
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    return 0 if result["status"] == "measured" and result["exit_code"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
