#!/usr/bin/env python3
"""Paired fresh-process measurements against a separately built frozen version.

Every version runs the same target executable and target library. Eager
eviction remains fixed, and every synthetic buffer must be restored. No
diagnostic mode or policy adjustment can silently improve the score.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import statistics
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from afterfree.cli import SSE2, events, run_command
from afterfree.measure import measure

ENTRY = "import sys;sys.path.insert(0,sys.argv.pop(1));from afterfree.cli import main;raise SystemExit(main())"
WORKLOADS = [("4x1MiB", 4, 1), ("16x4MiB", 16, 4), ("4x8MiB", 4, 8)]


def run_version(root, command, log, env):
    launch = [
        sys.executable,
        "-c",
        ENTRY,
        str(root),
        "run",
        "--sse2",
        "--report",
        str(log),
        "--",
        *command,
    ]
    if (root / "afterfree/_native/afterfree-run").exists():
        launch = run_command(command, log, root=root)
    result = measure(launch, env=env, event_path=log)
    result["events"] = events(log)
    result["summary"] = next(
        (e for e in reversed(result["events"]) if e["event"] == "summary"), {}
    )
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--baseline-root", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--trials", type=int, default=3)
    args = p.parse_args()
    if not 1 <= args.trials <= 10:
        p.error("trials must be 1–10")
    old = args.baseline_root.resolve()
    fixture = old / "afterfree/_native/afterfree-fixture"
    target_library = fixture.with_name("libafterfree-fixtures.so")
    report = {
        "schema": "afterfree.comparison.v1",
        "trials": args.trials,
        "kind": "frozen synthetic mechanism workloads; not an upstream acceptance gate",
        "target_sha256": hashlib.sha256(fixture.read_bytes()).hexdigest(),
        "target_library_sha256": hashlib.sha256(
            target_library.read_bytes()
        ).hexdigest(),
        "old_runtime_sha256": hashlib.sha256(
            (old / "afterfree/_native/libafterfree.so").read_bytes()
        ).hexdigest(),
        "new_runtime_sha256": hashlib.sha256(
            (ROOT / "afterfree/_native/libafterfree.so").read_bytes()
        ).hexdigest(),
        "glibc_tunables_all_runs": SSE2,
        "eviction_policy": "eager for both versions",
        "frontend": "Public native exec launcher when available; frozen older root uses its Python frontend. Complete frontend lifetime is counted. Commands identify each path.",
        "cold_definition": "fresh process, all capture/validation included; no preloaded profiles; OS caches not flushed",
        "memory_note": "Application plus worker sampled RSS, including all runtime metadata. Samples can miss peaks. Kernel application peak is also reported; no hard aggregate gate is claimed.",
        "hard_limit_tested": False,
        "workloads": [],
    }
    env = {
        k: v
        for k, v in os.environ.items()
        if not k.startswith("AF_") and k not in {"LD_PRELOAD", "LD_AUDIT"}
    }
    env["GLIBC_TUNABLES"] = SSE2
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="afterfree-compare-") as temp:
        for name, count, mib in WORKLOADS:
            command = [str(fixture), str(count), str(mib * 2**20)]
            workload = {"name": name, "command": command, "runs": []}
            report["workloads"].append(workload)
            for trial in range(args.trials):
                row = {
                    "trial": trial + 1,
                    "baseline": measure(command, env=env),
                    "checks": {},
                }
                order = [("old", old), ("new", ROOT)]
                if trial % 2:
                    order.reverse()
                row["version_order"] = [label for label, _ in order]
                for label, root in order:
                    log = Path(temp) / f"{name}-{trial}-{label}.jsonl"
                    row[label] = run_version(root, command, log, env)
                    result, summary = row[label], row[label]["summary"]
                    checks = {
                        "successful_exit": result["exit_code"]
                        == row["baseline"]["exit_code"]
                        == 0,
                        "exact_output": result["stdout_sha256"]
                        == row["baseline"]["stdout_sha256"]
                        and result["stdout_bytes"] == row["baseline"]["stdout_bytes"],
                        "all_recipes_accepted": summary.get("accepted") == count
                        and summary.get("rejected") == 0,
                        "all_buffers_evicted": summary.get("freed_buffer_evictions")
                        == count,
                        "all_buffers_restored": (
                            summary.get("fully_restored_buffers") == count
                            if "fully_restored_buffers" in summary
                            else summary.get("freed_buffer_faults") == count
                        ),
                        "exact_reconstruction_volume": summary.get("restored_bytes")
                        == count * mib * 2**20,
                        "zero_swap": result["zero_swap_verified"]
                        and row["baseline"]["zero_swap_verified"],
                        "same_eager_policy": summary.get("managed_resident_target", 0)
                        == 0,
                        "worker_memory_counted": result["worker_observed"]
                        and result["aggregate_rss_available"],
                    }
                    row["checks"][label] = checks
                    verdict = "PASS" if all(checks.values()) else "FAIL"
                    print(
                        f"{name} trial {trial+1} {label}: {result['wall_seconds']:.3f} s, {verdict}",
                        flush=True,
                    )
                workload["runs"].append(row)
                args.output.write_text(json.dumps(report, indent=2) + "\n")
            medians = {
                label: statistics.median(
                    row[label]["wall_seconds"] for row in workload["runs"]
                )
                for label in ("baseline", "old", "new")
            }
            workload["median_seconds"] = medians
            workload["new_speedup_vs_old"] = medians["old"] / medians["new"]
            workload["new_slowdown_vs_native"] = medians["new"] / medians["baseline"]
            workload["all_outputs_exact"] = all(
                row["checks"][label]["exact_output"]
                for row in workload["runs"]
                for label in ("old", "new")
            )
    report["all_outputs_exact"] = all(
        w["all_outputs_exact"] for w in report["workloads"]
    )
    report["all_checks_passed"] = all(
        all(checks.values())
        for w in report["workloads"]
        for row in w["runs"]
        for checks in row["checks"].values()
    )
    report["launch_gate_passed"] = False
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(f"Saved {args.output}")
    return 0 if report["all_checks_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
