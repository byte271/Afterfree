import os
from pathlib import Path
import subprocess
import sys

import pytest

from afterfree.measure import measure

NATIVE = Path(__file__).resolve().parents[1] / "afterfree/_native"


@pytest.mark.parametrize(
    "options",
    [
        [],
        ["--resident-mib", "0"],
        ["--resident-mib", "-1"],
        ["--resident-mib", "18446744073709551616"],
        ["--report"],
        ["--unknown"],
    ],
)
def test_native_launcher_rejects_invalid_invocations(options):
    result = subprocess.run(
        [str(NATIVE / "afterfree-run"), *options], capture_output=True
    )
    assert result.returncode == 2 and b"afterfree:" in result.stderr


def test_invalid_elf_cannot_remove_existing_report(tmp_path):
    target, report = tmp_path / "program", tmp_path / "report"
    target.write_bytes(b"\x7fELF\x02\x01" + bytes(90))
    target.chmod(0o700)
    report.write_text("keep")
    result = subprocess.run(
        [str(NATIVE / "afterfree-run"), "--report", str(report), "--", str(target)],
        capture_output=True,
    )
    assert result.returncode == 2 and report.read_text() == "keep"


def test_report_directory_is_preserved(tmp_path):
    result = subprocess.run(
        [str(NATIVE / "afterfree-run"), "--report", str(tmp_path), "--", "/bin/true"],
        capture_output=True,
    )
    assert result.returncode == 2 and tmp_path.is_dir()


def test_descendant_memory_is_included():
    child = "import time; data=bytearray(32*1024*1024); time.sleep(0.25)"
    parent = "import subprocess,sys; subprocess.run([sys.executable, '-c', sys.argv[1]], check=True)"
    result = measure([sys.executable, "-c", parent, child])
    assert result["exit_code"] == 0
    assert result["descendant_scan_complete"]
    assert result["descendant_procfs_pids_observed"]
    assert result["sampled_aggregate_peak_rss_bytes"] >= 40 * 1024 * 1024
