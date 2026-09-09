#!/usr/bin/env python3
"""Measure competing mechanisms with the same frozen 64 MiB job and exact gates."""
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
from afterfree.cli import SSE2
from afterfree.measure import measure
from compare import run_version

VARIANTS = {
    "checked_boundaries": ["FAST_BOUNDARY"],
    "complete": [],
    "qbdi_capture": ["NATIVE_CAPTURE"],
    "demand_faults": ["READ_PLANS"],
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--trials", type=int, default=3)
    parser.add_argument(
        "--windows", action="store_true", help="compare bounded validation windows"
    )
    args = parser.parse_args()
    variants = {
        label: {"AF_DISABLE_" + name: "1" for name in names}
        for label, names in VARIANTS.items()
    }
    if args.windows:
        variants = {
            str(kib) + "KiB": {"AF_WINDOW_KIB": str(kib)} for kib in [64, 256, 1024]
        }
    if not 1 <= args.trials <= 10:
        parser.error("trials must be 1 through 10")
    target = args.baseline_root.resolve() / "afterfree/_native/afterfree-fixture"
    command = [str(target), "16", "4194304"]
    env = {
        k: v
        for k, v in os.environ.items()
        if not k.startswith("AF_") and k not in {"LD_PRELOAD", "LD_AUDIT"}
    }
    env["GLIBC_TUNABLES"] = SSE2
    report = {
        "schema": "afterfree.ablation.v1",
        "command": command,
        "target_sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
        "target_library_sha256": hashlib.sha256(
            target.with_name("libafterfree-fixtures.so").read_bytes()
        ).hexdigest(),
        "variants_environment": variants,
        "note": "Same current source, fixed eager eviction and complete original work; only listed mechanisms vary. No concurrent test or build jobs.",
        "runs": [],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="afterfree-ablation-") as temp:
        for trial in range(args.trials):
            native = measure(command, env=env)
            labels = list(variants)
            labels = labels[trial % len(labels) :] + labels[: trial % len(labels)]
            row = {"native": native, "order": labels, "variants": {}}
            for label in labels:
                settings = dict(env)
                settings.update(variants[label])
                result = run_version(
                    ROOT, command, Path(temp) / f"{trial}-{label}.jsonl", settings
                )
                summary = result["summary"]
                checks = {
                    "output": native["exit_code"] == result["exit_code"] == 0
                    and native["stdout_sha256"] == result["stdout_sha256"]
                    and native["stdout_bytes"] == result["stdout_bytes"],
                    "accepted": summary.get("accepted") == 16
                    and summary.get("rejected") == 0,
                    "evicted": summary.get("freed_buffer_evictions") == 16,
                    "complete_restoration": summary.get("fully_restored_buffers") == 16
                    and summary.get("restored_bytes") == 64 * 2**20,
                    "all_runtime_memory": result["worker_observed"]
                    and result["aggregate_rss_available"],
                    "zero_swap": result["zero_swap_verified"]
                    and native["zero_swap_verified"],
                }
                row["variants"][label] = {"result": result, "checks": checks}
                print(
                    f"{trial+1} {label}: {result['wall_seconds']:.3f} s, {'PASS' if all(checks.values()) else 'FAIL'}",
                    flush=True,
                )
            report["runs"].append(row)
            args.output.write_text(json.dumps(report, indent=2) + "\n")
    report["medians"] = {
        label: {
            "seconds": statistics.median(
                row["variants"][label]["result"]["wall_seconds"]
                for row in report["runs"]
            ),
            "rss_estimate_bytes": statistics.median(
                row["variants"][label]["result"]["aggregate_peak_rss_estimate_bytes"]
                for row in report["runs"]
            ),
        }
        for label in variants
    }
    report["all_checks_passed"] = all(
        all(value["checks"].values())
        for row in report["runs"]
        for value in row["variants"].values()
    )
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    return 0 if report["all_checks_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
