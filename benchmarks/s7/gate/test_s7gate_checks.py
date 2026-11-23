# Copyright 2026 Cisco Systems, Inc. and its affiliates
# Licensed under the Apache License, Version 2.0 (the "License");
# SPDX-License-Identifier: Apache-2.0
"""Run the scorer self-checks that came with the deployed s7gate.py (rel-1-0-10 GAP-1581: one scorer, its checks in pytest).

Each check_s7gate_*.py drives s7gate.py in a temporary HOME with synthetic cases and exits 0 only when every check passes.
"""

import os
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
CHECKS = sorted(p.name for p in HERE.glob("check_s7gate_*.py"))


def test_every_check_is_found():
    assert CHECKS == [
        "check_s7gate_completeness.py",
        "check_s7gate_judgecost.py",
        "check_s7gate_prompt_timing.py",
        "check_s7gate_runstamp.py",
    ]


@pytest.mark.parametrize("name", CHECKS)
def test_check_passes(name):
    r = subprocess.run(
        [sys.executable, "-I", str(HERE / name), str(HERE / "s7gate.py")],
        env=dict(os.environ),
        capture_output=True,
        text=True,
        timeout=600,
    )
    out = r.stdout + r.stderr
    assert r.returncode == 0, out[-4000:]
    assert "PASS" in out, out[-4000:]
    assert "FAIL" not in out.replace("FAILS", ""), out[-4000:]
