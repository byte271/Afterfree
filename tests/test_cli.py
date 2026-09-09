import json
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import pytest

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "afterfree/_native/afterfree-fixture"


def test_automatic_discovery_same_existing_executable(tmp_path):
    command = [str(FIXTURE), "4", "262144"]
    env = os.environ.copy()
    env["GLIBC_TUNABLES"] = (
        "glibc.cpu.hwcaps=-AVX512VL,-AVX512BW,-AVX512F,-AVX2,-AVX,-ERMS,-FSRM"
    )
    baseline = subprocess.run(command, capture_output=True, env=env, timeout=30)
    log = tmp_path / "run.jsonl"
    transformed = subprocess.run(
        [
            sys.executable,
            "-m",
            "afterfree",
            "run",
            "--sse2",
            "--report",
            str(log),
            "--",
            *command,
        ],
        cwd=ROOT,
        capture_output=True,
        timeout=30,
    )
    assert baseline.returncode == transformed.returncode == 0, transformed.stderr
    assert baseline.stdout == transformed.stdout
    events = [json.loads(line) for line in log.read_text().splitlines()]
    summary = events[-1]
    assert summary["accepted"] == 4
    assert summary["rejected"] == 0
    assert summary["freed_buffer_faults"] >= 4
    assert summary["fully_restored_buffers"] == 4
    assert summary["restored_bytes"] == 4 * 262144
    assert summary["native_recipes"] == summary["page_recipes"] == 4
    assert summary["native_dispatches"] == 3
    assert summary["freed_buffer_evictions"] == 4


def test_doctor():
    result = subprocess.run(
        [sys.executable, "-m", "afterfree", "doctor", "--json"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    info = json.loads(result.stdout)
    assert info["usable"] and info["physical_discard"] and info["transparent_restore"]


def test_measurement_excludes_parent_heap_and_preserves_child_status():
    from afterfree.measure import measure

    parent_heap = bytearray(32 * 1024 * 1024)
    assert parent_heap[-1] == 0
    result = measure(["/bin/sh", "-c", "exit 7"])
    assert result["exit_code"] == 7
    assert result["root_kernel_peak_rss_bytes"] is not None
    assert result["root_kernel_peak_rss_bytes"] < len(parent_heap) // 2


@pytest.mark.parametrize("mode", [0, 1, 2])
def test_template_fresh_inputs_side_effects_and_changed_paths(tmp_path, mode):
    command = [str(FIXTURE.with_name("afterfree-edge-fixture")), str(mode)]
    baseline = subprocess.run(command, capture_output=True, timeout=30)
    log = tmp_path / "events.jsonl"
    after = subprocess.run(
        [
            sys.executable,
            "-m",
            "afterfree",
            "run",
            "--sse2",
            "--report",
            str(log),
            "--",
            *command,
        ],
        cwd=ROOT,
        capture_output=True,
        timeout=30,
    )
    assert baseline.returncode == after.returncode == 0, after.stderr
    assert len(after.stdout) == 6 * 65537
    assert baseline.stdout == after.stdout
    events = [json.loads(line) for line in log.read_text().splitlines()]
    summary = events[-1]
    if mode == 0:
        assert summary["accepted"] == 6 and summary["template_hits"] == 5
    else:
        assert summary["template_validation_misses"] >= 1
        assert summary["rejected"] >= 1


def test_low_pressure_retains_verified_buffers(tmp_path):
    command = [str(FIXTURE.with_name("afterfree-edge-fixture")), "0"]
    baseline = subprocess.run(command, capture_output=True, timeout=30)
    log = tmp_path / "policy.jsonl"
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "afterfree",
            "run",
            "--sse2",
            "--resident-mib",
            "1",
            "--report",
            str(log),
            "--",
            *command,
        ],
        cwd=ROOT,
        capture_output=True,
        timeout=30,
    )
    assert result.returncode == baseline.returncode == 0
    assert result.stdout == baseline.stdout
    summary = json.loads(log.read_text().splitlines()[-1])
    assert summary["accepted"] == 6 and summary["automatic_evictions"] == 0
    assert summary["restored_bytes"] == 0
    assert summary["managed_resident_target"] == 2**20


def test_measurement_hashes_full_binary_output():
    from afterfree.measure import measure

    results = []
    for value in (255, 254):
        result = measure(
            [
                sys.executable,
                "-c",
                f"import sys;sys.stdout.buffer.write(bytes([{value}])*70000)",
            ]
        )
        assert result["stdout_bytes"] == 70000 and result["stdout_truncated"]
        assert (
            result["stdout_sha256"]
            == hashlib.sha256(bytes([value]) * 70000).hexdigest()
        )
        results.append(result)
    assert results[0]["stdout"] == results[1]["stdout"]
    assert results[0]["stdout_sha256"] != results[1]["stdout_sha256"]


def test_measurement_preserves_complete_stdin_without_an_extra_process(tmp_path):
    from afterfree.measure import measure

    data = bytes(range(256)) * 513
    path = tmp_path / "input.bin"
    path.write_bytes(data)
    result = measure(["/bin/cat"], stdin_path=path)
    assert result["exit_code"] == 0
    assert result["stdout_bytes"] == len(data)
    assert result["stdout_sha256"] == hashlib.sha256(data).hexdigest()


def test_late_loaded_module_can_be_unloaded_before_reconstruction(tmp_path):
    command = [
        str(FIXTURE.with_name("afterfree-dynamic-fixture")),
        str(FIXTURE.with_name("libafterfree-fixtures.so")),
    ]
    baseline = subprocess.run(command, capture_output=True, timeout=30)
    log = tmp_path / "dynamic.jsonl"
    after = subprocess.run(
        [
            sys.executable,
            "-m",
            "afterfree",
            "run",
            "--sse2",
            "--report",
            str(log),
            "--",
            *command,
        ],
        cwd=ROOT,
        capture_output=True,
        timeout=30,
    )
    assert baseline.returncode == after.returncode == 0, after.stderr
    assert len(after.stdout) == 4 * 65536 and after.stdout == baseline.stdout
    summary = json.loads(log.read_text().splitlines()[-1])
    assert (
        summary["accepted"] == summary["native_recipes"] == summary["page_recipes"] == 4
    )
    assert summary["fully_restored_buffers"] == 4
    assert summary["restored_bytes"] == len(after.stdout)


def test_aligned_allocations_and_managed_capacity_fallback(tmp_path):
    command = [str(FIXTURE.with_name("afterfree-allocator-fixture"))]
    baseline = subprocess.run(command, capture_output=True, timeout=30)
    log = tmp_path / "allocators.jsonl"
    after = subprocess.run(
        [
            sys.executable,
            "-m",
            "afterfree",
            "run",
            "--sse2",
            "--report",
            str(log),
            "--",
            *command,
        ],
        cwd=ROOT,
        capture_output=True,
        timeout=30,
    )
    assert baseline.returncode == after.returncode == 0, after.stderr
    assert len(after.stdout) == 22 * 65536 and after.stdout == baseline.stdout
    summary = json.loads(log.read_text().splitlines()[-1])
    assert summary["accepted"] == summary["fully_restored_buffers"] == 20
    assert summary["restored_bytes"] == 20 * 65536


@pytest.mark.parametrize("api", ["0", "1"])
def test_pager_replacement_is_refused_before_reclaimed_access(tmp_path, api):
    command = [str(FIXTURE.with_name("afterfree-signal-fixture")), api]
    baseline = subprocess.run(command, capture_output=True, timeout=30)
    assert baseline.returncode == 0
    log = tmp_path / "signals.jsonl"
    after = subprocess.run(
        [
            sys.executable,
            "-m",
            "afterfree",
            "run",
            "--sse2",
            "--report",
            str(log),
            "--",
            *command,
        ],
        cwd=ROOT,
        capture_output=True,
        timeout=30,
    )
    assert after.returncode == 196, after.stderr
    data = [json.loads(line) for line in log.read_text().splitlines()]
    assert any(event["event"] == "sealed" for event in data)
    assert data[-1]["event"] == "fatal" and "SIGSEGV pager" in data[-1]["reason"]


def test_unrelated_native_crash_is_not_misreported_as_pager_replacement(tmp_path):
    command = [str(FIXTURE.with_name("afterfree-signal-fixture")), "2"]
    baseline = subprocess.run(command, capture_output=True, timeout=30)
    log = tmp_path / "native-crash.jsonl"
    after = subprocess.run(
        [
            sys.executable,
            "-m",
            "afterfree",
            "run",
            "--sse2",
            "--report",
            str(log),
            "--",
            *command,
        ],
        cwd=ROOT,
        capture_output=True,
        timeout=30,
    )
    assert baseline.returncode == after.returncode == -11
    assert "replacement" not in log.read_text()
