# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""GAP-2580: usage errors name "defenseclaw", also when the TUI runs the module."""

from __future__ import annotations

import os
import subprocess
import sys


def test_module_run_usage_error_names_the_defenseclaw_command(tmp_path):
    # The TUI executor runs (sys.executable, "-m", "defenseclaw.main", ...).
    env = {**os.environ, "HOME": str(tmp_path), "USERPROFILE": str(tmp_path)}
    result = subprocess.run(
        [sys.executable, "-m", "defenseclaw.main", "--no-such-option"],
        capture_output=True,
        text=True,
        env=env,
        timeout=120,
        check=False,
    )
    assert result.returncode == 2
    assert "Usage: defenseclaw [OPTIONS]" in result.stderr
    assert "Try \x27defenseclaw " in result.stderr
    assert "defenseclaw.main" not in result.stderr
