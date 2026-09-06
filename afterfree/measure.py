"""Process measurements. Sampled RSS is never described as a hard memory limit."""

from __future__ import annotations
import json
import hashlib
import os
from pathlib import Path
import signal
import select
import subprocess
import tempfile
import time
from contextlib import nullcontext


def memory(pid: int) -> dict:
    try:
        values = {}
        for line in Path(f"/proc/{pid}/smaps_rollup").read_text().splitlines()[1:]:
            key, _, value = line.partition(":")
            if value.strip():
                values[key] = int(value.split()[0]) * 1024
        return {
            "rss": values["Rss"],
            "pss": values["Pss"],
            "swap": values.get("Swap"),
            "source": "smaps_rollup",
        }
    except (OSError, KeyError, ValueError):
        # A non-dumpable replay worker hides smaps from an unprivileged parent.
        # VmRSS remains readable. Missing PSS must never be reported as zero.
        try:
            status = Path(f"/proc/{pid}/status").read_text()
            fields = {
                line.split(":", 1)[0]: line.split(":", 1)[1]
                for line in status.splitlines()
                if ":" in line
            }
            if "VmRSS" in fields:
                return {
                    "rss": int(fields["VmRSS"].split()[0]) * 1024,
                    "pss": None,
                    "swap": (
                        int(fields["VmSwap"].split()[0]) * 1024
                        if "VmSwap" in fields
                        else None
                    ),
                    "source": "status.VmRSS",
                }
            if "State:\tZ" in status:
                return {"rss": 0, "pss": 0, "swap": 0, "source": "exited"}
        except (OSError, ValueError):
            pass
        return {"rss": 0, "pss": None, "swap": None, "source": "unavailable"}


def descendants(pid):
    """Walk procfs parent links; task/children is empty on some containers."""
    parents = {}
    complete = True
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            # comm can contain spaces and parentheses; subsequent fields cannot.
            fields = (entry / "stat").read_text().rsplit(")", 1)[1].split()
            parents.setdefault(int(fields[1]), []).append(int(entry.name))
        except FileNotFoundError:
            pass
        except (OSError, ValueError, IndexError):
            complete = False
    found, pending = set(), [pid]
    while pending:
        for child in parents.get(pending.pop(), []):
            if child != pid and child not in found:
                found.add(child)
                pending.append(child)
    return found, complete


def swap_devices():
    try:
        return Path("/proc/swaps").read_text().splitlines()[1:]
    except OSError:
        return None


def measure(
    command: list[str],
    *,
    env=None,
    event_path: Path | None = None,
    timeout=120,
    interval=0.01,
    stdin_path: Path | None = None,
) -> dict:
    """Measure an executable, visible descendants, and its known replay worker.

    procfs PIDs are reported before exec because some containers mount procfs
    from a different PID namespace. A native supervisor forks after exec and
    reports the child's wait4 peak, excluding the Python parent's inherited
    high-water mark. Samples and RSS counters can miss exact peaks; cgroup memory.peak is the gate.
    """
    if event_path is not None:
        event_path.unlink(missing_ok=True)
    launcher = Path(__file__).resolve().parent / "_native/afterfree-measure-launch"
    child_env = dict(os.environ if env is None else env)
    if child_env.get("LD_PRELOAD"):
        child_env["AF_MEASURE_LD_PRELOAD"] = child_env.pop("LD_PRELOAD")
    swap_before = swap_devices()
    peak_swap = 0
    swap_samples = 0
    start = time.monotonic()
    peak_rss = peak_pss = 0
    samples = 0
    timed_out = False
    worker_pid = None
    worker_samples = 0
    pss_complete = True
    worker_memory_sources = {}
    descendant_pids = set()
    descendant_scan_complete = True
    memory_samples_complete = True
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr, (
        Path(stdin_path).open("rb") if stdin_path is not None else nullcontext(None)
    ) as stdin:
        metadata_read, metadata_write = os.pipe()
        try:
            process = subprocess.Popen(
                [str(launcher), str(metadata_write), *command],
                env=child_env,
                stdout=stdout,
                stderr=stderr,
                stdin=stdin,
                pass_fds=(metadata_write,),
                start_new_session=True,
            )
        except BaseException:
            os.close(metadata_read)
            os.close(metadata_write)
            raise
        os.close(metadata_write)
        metadata = os.fdopen(metadata_read, "rb")
        try:
            procfs_pid = int(metadata.readline().strip())
        except BaseException:
            metadata.close()
            process.wait()
            raise
        try:
            exit_fd = os.pidfd_open(process.pid)
        except (AttributeError, OSError):
            exit_fd = None
        try:
            while True:
                if event_path is not None and worker_pid is None:
                    try:
                        for line in event_path.read_text().splitlines():
                            try:
                                event = json.loads(line)
                                if event.get("event") == "process":
                                    worker_pid = int(event["worker_procfs_pid"])
                            except (ValueError, KeyError):
                                continue
                    except OSError:
                        pass
                usage = memory(procfs_pid)
                children, complete = descendants(procfs_pid)
                descendant_scan_complete &= complete
                descendant_pids.update(children)
                if worker_pid:
                    children.add(worker_pid)
                memory_samples_complete &= usage["source"] != "unavailable"
                for child in children:
                    child_usage = memory(child)
                    if child == worker_pid:
                        worker_samples += child_usage["rss"] > 0
                        source = child_usage["source"]
                        worker_memory_sources[source] = (
                            worker_memory_sources.get(source, 0) + 1
                        )
                    # Exiting between discovery and reading is unavoidable;
                    # record unavailable samples instead of calling them zero.
                    memory_samples_complete &= child_usage["source"] != "unavailable"
                    usage["rss"] += child_usage["rss"]
                    for key in ["swap", "pss"]:
                        usage[key] = (
                            usage[key] + child_usage[key]
                            if usage[key] is not None and child_usage[key] is not None
                            else None
                        )
                if usage["swap"] is not None:
                    swap_samples += 1
                    peak_swap = max(peak_swap, usage["swap"])
                peak_rss = max(peak_rss, usage["rss"])
                if usage["pss"] is not None:
                    peak_pss = max(peak_pss, usage["pss"])
                else:
                    pss_complete = False
                samples += 1
                pid, status, rusage = os.wait4(process.pid, os.WNOHANG)
                if pid:
                    process.returncode = os.waitstatus_to_exitcode(status)
                    break
                if time.monotonic() - start > timeout:
                    timed_out = True
                    os.killpg(process.pid, signal.SIGKILL)
                    _, status, rusage = os.wait4(process.pid, 0)
                    process.returncode = os.waitstatus_to_exitcode(status)
                    break
                if exit_fd is None:
                    time.sleep(interval)
                else:
                    select.select([exit_fd], [], [], interval)
        except BaseException:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            metadata.close()
            raise
        finally:
            if exit_fd is not None:
                os.close(exit_fd)
        elapsed = time.monotonic() - start
        try:
            child_usage = metadata.readline().split()
        finally:
            metadata.close()
        child_peak = None
        if len(child_usage) == 2:
            child_peak, child_status = map(int, child_usage)
            exit_code = os.waitstatus_to_exitcode(child_status)
        else:
            exit_code = process.returncode
        stdout.seek(0)
        stderr.seek(0)
        digest = hashlib.sha256()
        preview = bytearray()
        output_bytes = 0
        for chunk in iter(lambda: stdout.read(1024 * 1024), b""):
            digest.update(chunk)
            output_bytes += len(chunk)
            if len(preview) < 65536:
                preview.extend(chunk[: 65536 - len(preview)])
        worker_peak = None
        if event_path is not None:
            try:
                for line in event_path.read_text().splitlines():
                    try:
                        event = json.loads(line)
                        if event.get("event") == "summary":
                            worker_peak = (
                                event.get("worker_kernel_peak_rss_bytes") or None
                            )
                    except ValueError:
                        continue
            except OSError:
                pass
        swap_after = swap_devices()
        return {
            "command": command,
            "exit_code": exit_code,
            "timed_out": timed_out,
            "wall_seconds": elapsed,
            "sampled_aggregate_peak_rss_bytes": (
                peak_rss if event_path is None or worker_samples > 0 else None
            ),
            "sampled_aggregate_peak_pss_bytes": peak_pss if pss_complete else None,
            "root_kernel_peak_rss_bytes": child_peak,
            "worker_kernel_peak_rss_bytes": worker_peak,
            "aggregate_peak_rss_estimate_bytes": (
                max(peak_rss, child_peak + worker_peak)
                if child_peak is not None and worker_peak is not None
                else max(peak_rss, child_peak or 0) if event_path is None else None
            ),
            "aggregate_estimate_method": "max of sampled aggregate RSS and sum of per-process kernel peaks; kernel counters can be approximate, peaks need not coincide",
            "sampled_aggregate_peak_swap_bytes": peak_swap if swap_samples else None,
            "swap_devices_before": swap_before,
            "swap_devices_after": swap_after,
            "zero_swap_verified": swap_before == []
            and swap_after == []
            and peak_swap == 0,
            "zero_swap_method": "no configured swap devices before or after run, plus process samples; no concurrent swapon assumed",
            "root_peak_method": "native supervisor wait4 after fresh-image fork",
            "samples": samples,
            "sample_interval_seconds": interval,
            "worker_observed": worker_samples > 0,
            "descendant_procfs_pids_observed": sorted(descendant_pids),
            "descendant_scan_complete": descendant_scan_complete,
            "all_memory_samples_available": memory_samples_complete,
            "process_scope_note": "Application, known worker, and visible descendants sampled once each. Short-lived or reparented processes can escape sampling; only a delegated cgroup provides a hard whole-job gate.",
            "worker_samples": worker_samples,
            "worker_memory_sources": worker_memory_sources,
            "aggregate_rss_available": event_path is None or worker_samples > 0,
            "exit_wait_method": "pidfd" if exit_fd is not None else "timed polling",
            "stdout": preview.decode("utf-8", "replace"),
            "stdout_sha256": digest.hexdigest(),
            "stdout_bytes": output_bytes,
            "stdout_truncated": output_bytes > len(preview),
            "stderr": stderr.read().decode("utf-8", "replace"),
            "hard_aggregate_limit": False,
        }
