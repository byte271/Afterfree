from __future__ import annotations

import argparse
import ctypes as C
import json
import os
from pathlib import Path
import platform
import sys
import tempfile

from . import __version__
from .runtime import Runtime, AfterfreeError
from .measure import measure

NATIVE = Path(__file__).resolve().parent / "_native"
SSE2 = "glibc.cpu.hwcaps=-AVX512VL,-AVX512BW,-AVX512F,-AVX2,-AVX,-ERMS,-FSRM"


def run_command(command, report, *, root=None, sse2=True):
    native = Path(root) / "afterfree/_native" if root else NATIVE
    return [
        str(native / "afterfree-run"),
        *(["--sse2"] if sse2 else []),
        "--report",
        str(report),
        "--",
        *command,
    ]


def events(path):
    try:
        return [
            json.loads(line) for line in path.read_text().splitlines() if line.strip()
        ]
    except (OSError, ValueError) as e:
        raise AfterfreeError(f"cannot read complete execution report: {e}") from e


def doctor(args):
    info = {
        "version": __version__,
        "platform": platform.platform(),
        "architecture": platform.machine(),
        "page_size": os.sysconf("SC_PAGE_SIZE"),
        "procfs_pid_matches": str(os.getpid()) == os.readlink("/proc/self"),
        "cgroup_delegated": os.access("/sys/fs/cgroup", os.W_OK),
        "swap_devices": [],
    }
    try:
        info["swap_devices"] = Path("/proc/swaps").read_text().splitlines()[1:]
    except OSError:
        info["swap_devices"] = None
    libc = C.CDLL(None, use_errno=True)
    if platform.machine() == "x86_64":
        fd = libc.syscall(323, os.O_CLOEXEC | 1)  # userfaultfd, UFFD_USER_MODE_ONLY
        info["userfaultfd"] = fd >= 0
        if fd >= 0:
            os.close(fd)
        else:
            info["userfaultfd_errno"] = C.get_errno()
    try:
        with Runtime() as runtime:
            library = C.CDLL(str(NATIVE / "libafterfree-fixtures.so"))
            buffer = runtime.alloc(65536)
            cap = runtime.capture(
                library.expand, buffer, buffer.size // 8, 42, output=buffer
            )
            if not cap.eligible:
                raise AfterfreeError(cap.reason)
            expected = buffer.read()
            buffer.evict()
            discarded = buffer.resident_bytes == 0
            identical = buffer.read() == expected
            info.update(
                native_capture=True,
                physical_discard=discarded,
                transparent_restore=identical,
                recipe_bytes=cap.stats["recipe_bytes"],
                pager="mprotect + independent replay worker",
            )
            info["usable"] = discarded and identical
    except (AfterfreeError, OSError) as e:
        info.update(usable=False, error=str(e))
    if args.json:
        print(json.dumps(info, indent=2))
    else:
        print(f"Afterfree {__version__}: {'ready' if info['usable'] else 'not ready'}")
        if info["usable"]:
            print(
                f"Native capture, physical discard, and exact restoration passed ({info['recipe_bytes']:,}-byte recipe)."
            )
            print(
                f"Hard cgroup benchmark: {'available' if info['cgroup_delegated'] else 'requires a delegated Linux cgroup' }."
            )
        else:
            print(info.get("error", "native self-check failed"))
    return 0 if info["usable"] else 1


def run(args):
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        raise AfterfreeError("provide an executable after --")
    if not (NATIVE / "libafterfree-preload.so").exists():
        raise AfterfreeError("run python tools/build.py first")
    launcher = NATIVE / "afterfree-run"
    options = [str(launcher), "--report", str(args.report)]
    if args.sse2:
        options.append("--sse2")
    if args.resident_mib is not None:
        options.extend(["--resident-mib", str(args.resident_mib)])
    os.execv(launcher, [*options, "--", *command])
    return 1


def demo(args):
    command = [
        str(NATIVE / "afterfree-fixture"),
        str(args.buffers),
        str(args.mib * 1024 * 1024),
    ]
    if not Path(command[0]).exists():
        raise AfterfreeError("run python tools/build.py first")
    with tempfile.TemporaryDirectory(prefix="afterfree-demo-") as temp:
        log = Path(temp) / "events.jsonl"
        baseline_env = os.environ.copy()
        baseline_env["GLIBC_TUNABLES"] = SSE2
        baseline = measure(command, env=baseline_env, timeout=args.timeout)
        launch = run_command(command, log)
        transformed = measure(launch, event_path=log, timeout=args.timeout)
        data = events(log)
    report = {
        "schema": "afterfree.demo.v1",
        "kind": "synthetic mechanism workload",
        "buffers": args.buffers,
        "bytes_per_buffer": args.mib * 1024 * 1024,
        "baseline": baseline,
        "afterfree": transformed,
        "events": data,
        "same_output": baseline["exit_code"] == transformed["exit_code"] == 0
        and baseline["stdout_sha256"] == transformed["stdout_sha256"]
        and baseline["stdout_bytes"] == transformed["stdout_bytes"],
        "hard_limit_tested": False,
        "measurement_note": "RSS totals sample the application and replay worker every 10 ms; they can miss peaks. The non-dumpable worker uses status.VmRSS when smaps is unavailable; unavailable aggregate PSS is null. RSS counts shared pages in each process. This is not a cgroup gate result.",
    }
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n")
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        summary = next((e for e in data if e.get("event") == "summary"), {})
        print(f"Exact output: {'PASS' if report['same_output'] else 'FAIL'}")
        print(
            f"Learned {summary.get('accepted', 0)} recipes for {summary.get('output_bytes', 0) / 2**20:.1f} MiB; recipes total {summary.get('recipe_bytes', 0):,} bytes."
        )
        for name, value in (("Baseline", baseline), ("Afterfree", transformed)):
            peak = value["aggregate_peak_rss_estimate_bytes"]
            label = (
                f"{peak / 2**20:.1f} MiB observed RSS peak"
                if peak is not None
                else "aggregate memory unavailable"
            )
            print(f"{name}: {label}, {value['wall_seconds']:.3f} s.")
        print(
            "Includes recorder and replay worker overhead. Synthetic workload; no hard memory limit tested."
        )
        if args.output:
            print(f"Full measurements: {args.output}")
    return 0 if report["same_output"] else 1


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="afterfree",
        description="Learn native computation and reconstruct discarded output pages.",
    )
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="action", required=True)
    p = sub.add_parser("doctor", help="check the host and run exact reconstruction")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=doctor)
    p = sub.add_parser(
        "run",
        help="automatically discover producers in a single-threaded ELF executable",
    )
    p.add_argument("--report", type=Path, default=Path("afterfree-report.jsonl"))
    p.add_argument(
        "--sse2",
        action="store_true",
        help="select glibc SSE2 memory routines; use identical settings for the baseline",
    )
    p.add_argument(
        "--resident-mib",
        type=int,
        help="soft target for managed buffers; not a total RSS limit",
    )
    p.add_argument("command", nargs=argparse.REMAINDER)
    p.set_defaults(func=run)
    p = sub.add_parser(
        "demo", help="compare the same synthetic executable with and without Afterfree"
    )
    p.add_argument("--buffers", type=int, default=16)
    p.add_argument("--mib", type=int, default=4)
    p.add_argument("--timeout", type=float, default=120)
    p.add_argument("--output", type=Path)
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=demo)
    args = parser.parse_args(argv)
    if args.action == "demo" and not (
        1 <= args.buffers <= 1024 and 1 <= args.mib <= 256 and args.timeout > 0
    ):
        parser.error(
            "demo requires 1–1024 buffers, 1–256 MiB per buffer, and a positive timeout"
        )
    try:
        return args.func(args)
    except (AfterfreeError, OSError) as e:
        print(f"afterfree: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
