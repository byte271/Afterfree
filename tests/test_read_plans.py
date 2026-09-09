import json
import os
from pathlib import Path
import subprocess

import pytest

from afterfree.cli import run_command

NATIVE = Path(__file__).resolve().parents[1] / "afterfree/_native"


@pytest.mark.parametrize("mode", range(6))
def test_only_proved_consumers_batch_reads(tmp_path, mode):
    command = [str(NATIVE / "afterfree-read-fixture"), str(mode)]
    baseline = subprocess.run(command, capture_output=True, timeout=20)
    assert baseline.returncode == 0
    for disabled in [False, True]:
        log = tmp_path / f"{disabled}.jsonl"
        env = dict(os.environ)
        if disabled:
            env["AF_DISABLE_READ_PLANS"] = "1"
        result = subprocess.run(
            run_command(command, log), env=env, capture_output=True, timeout=20
        )
        assert (
            result.returncode == 0 and result.stdout == baseline.stdout
        ), result.stderr
        events = list(map(json.loads, log.read_text().splitlines()))
        profile = next(e for e in events if e["event"] == "profile")
        summary = events[-1]
        assert summary["accepted"] == 1
        assert summary["freed_buffer_evictions"] == 1
        assert (profile["native_read_plans"] > 0) == (mode == 0 and not disabled)
        if mode in [1, 5]:
            assert summary["restored_bytes"] == 4096
            assert summary["fully_restored_buffers"] == 0
        elif mode in [0, 2, 3]:
            assert summary["restored_bytes"] == 1048576
