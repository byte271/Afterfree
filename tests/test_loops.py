import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / "afterfree/_native/afterfree-loop-fixture"


@pytest.mark.parametrize("mode", range(5))
@pytest.mark.parametrize("n,seed", [(1, 0), (2, 2**64 - 1), (513, 42), (32771, 73591)])
def test_native_loop_matches_original_bytes_flags_and_fp_state(tmp_path, mode, n, seed):
    command = [str(BINARY), str(n), str(seed), str(mode)]
    baseline = subprocess.run(command, capture_output=True, timeout=20)
    log = tmp_path / "loop.jsonl"
    launch = [
        sys.executable,
        "-m",
        "afterfree",
        "run",
        "--sse2",
        "--report",
        str(log),
        "--",
        *command,
    ]
    after = subprocess.run(launch, capture_output=True, timeout=20)
    assert after.returncode == baseline.returncode == 0, after.stderr
    assert after.stdout == baseline.stdout
    profile = next(
        e
        for e in map(json.loads, log.read_text().splitlines())
        if e["event"] == "profile"
    )
    if n >= 513:
        assert profile["native_loop_runs"] >= 2
    # A separate disabled run checks the original discovery engine as well.
    env = dict(os.environ, AF_DISABLE_NATIVE_LOOPS="1")
    disabled = subprocess.run(launch, capture_output=True, env=env, timeout=20)
    assert disabled.returncode == 0 and disabled.stdout == baseline.stdout
