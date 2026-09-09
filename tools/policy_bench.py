#!/usr/bin/env python3
"""Compare eager and soft residency policies on one unchanged executable.

This is a separate policy experiment. The published old/new cold comparison
keeps eager eviction fixed. Soft targets never establish a total RSS limit.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from afterfree.cli import SSE2, events
from afterfree.measure import measure
from compare import ENTRY


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture-root", type=Path, default=ROOT)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    fixture = args.fixture_root.resolve() / "afterfree/_native/afterfree-fixture"
    command = [str(fixture), "16", str(4 * 2**20)]
    env = {
        k: v
        for k, v in os.environ.items()
        if not k.startswith("AF_") and k not in {"LD_PRELOAD", "LD_AUDIT"}
    }
    env["GLIBC_TUNABLES"] = SSE2
    baseline = measure(command, env=env)
    report = {
        "schema": "afterfree.policy.v1",
        "trials": 1,
        "command": command,
        "target_sha256": hashlib.sha256(fixture.read_bytes()).hexdigest(),
        "target_library_sha256": hashlib.sha256(
            fixture.with_name("libafterfree-fixtures.so").read_bytes()
        ).hexdigest(),
        "glibc_tunables_all_runs": SSE2,
        "baseline": baseline,
        "runs": [],
        "note": "Soft target counts managed mappings, not total RSS. Peak overshoot and all worker RSS remain reported. Eager cold-comparison results are separate.",
        "hard_limit_tested": False,
        "launch_gate_passed": False,
    }
    with tempfile.TemporaryDirectory(prefix="afterfree-policy-") as temp:
        for label, target in [
            ("eager", 0),
            ("soft-8MiB", 8),
            ("soft-1MiB", 1),
            ("soft-64MiB", 64),
        ]:
            log = Path(temp) / (label + ".jsonl")
            launch = [
                sys.executable,
                "-c",
                ENTRY,
                str(ROOT),
                "run",
                "--sse2",
                "--report",
                str(log),
            ]
            if target:
                launch += ["--resident-mib", str(target)]
            result = measure(launch + ["--", *command], env=env, event_path=log)
            observed = events(log)
            summary = next(
                (e for e in reversed(observed) if e["event"] == "summary"), {}
            )
            checks = {
                "successful_exit": result["exit_code"] == baseline["exit_code"] == 0,
                "exact_output": result["stdout_sha256"] == baseline["stdout_sha256"]
                and result["stdout_bytes"] == baseline["stdout_bytes"],
                "all_recipes_accepted": summary.get("accepted") == 16
                and summary.get("rejected") == 0,
                "worker_memory_counted": result["worker_observed"]
                and result["aggregate_rss_available"],
                "bounded_automatic_restore_volume": summary.get("restored_bytes", 2**64)
                <= 64 * 2**20,
            }
            report["runs"].append(
                {
                    "policy": label,
                    "result": result,
                    "events": observed,
                    "summary": summary,
                    "checks": checks,
                }
            )
            print(
                f"{label}: {result['wall_seconds']:.3f} s, {'PASS' if all(checks.values()) else 'FAIL'}",
                flush=True,
            )
    report["all_checks_passed"] = all(
        all(row["checks"].values()) for row in report["runs"]
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    return 0 if report["all_checks_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
