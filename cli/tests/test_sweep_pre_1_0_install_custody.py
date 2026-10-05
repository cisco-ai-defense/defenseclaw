# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""scripts/sweep-pre-1.0-install-custody.py: `make all` removes 0.x custody folders (GAP-0053)."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "sweep-pre-1.0-install-custody.py"


def test_make_all_sweeps_pre_1_0_custody_but_keeps_the_live_one(tmp_path: Path) -> None:
    home, temp = tmp_path / "home", tmp_path / "tmp"
    legacy_tmp = temp / ".defenseclaw-install-custody-501-abc" / "retired-x"
    legacy_home = home / ".defenseclaw-install-custody" / "retired-y"
    live = home / ".local" / "bin" / ".defenseclaw-install-custody" / "retired-z"
    unrelated = temp / "keep-me"
    for path in (legacy_tmp, legacy_home, live, unrelated):
        path.mkdir(parents=True)
    env = {**os.environ, "HOME": str(home), "USERPROFILE": str(home), "DEFENSECLAW_HOME": str(home / ".defenseclaw")}

    result = subprocess.run(
        [sys.executable, str(SCRIPT), str(temp)], capture_output=True, text=True, env=env, timeout=60, check=False
    )

    assert result.returncode == 0, result.stderr
    assert "Removed 2 folder(s)" in result.stdout
    assert not legacy_tmp.parent.exists() and not legacy_home.parent.exists()
    assert live.exists() and unrelated.exists()
    again = subprocess.run(
        [sys.executable, str(SCRIPT), str(temp)], capture_output=True, text=True, env=env, timeout=60, check=False
    )
    assert again.returncode == 0 and again.stdout == ""
