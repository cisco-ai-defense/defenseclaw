# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""The #1174 upgrade-handoff help row must stop before release staging."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest


def test_issue_1174_upgrade_handoff_help_does_not_stage(tmp_path: Path) -> None:
    # The 0.8.x handoff is a POSIX shell entry point; Windows upgrades use Setup.
    if os.name == "nt":
        pytest.skip("POSIX upgrade handoff does not run on Windows")
    script = Path(__file__).resolve().parents[2] / "scripts" / "defenseclaw-upgrade.sh"
    marker = tmp_path / "network-command-ran"
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name in ("curl", "cosign"):
        fake = bin_dir / name
        fake.write_text(f"#!/bin/sh\ntouch '{marker}'\nexit 73\n", encoding="utf-8")
        fake.chmod(0o755)
    env = dict(os.environ)
    env["PATH"] = str(bin_dir) + os.pathsep + env.get("PATH", "")
    result = subprocess.run(
        ["bash", str(script), "--help"],
        capture_output=True, text=True, check=False, env=env, timeout=5,
    )
    assert result.returncode == 0, result.stderr
    assert "Usage: bash defenseclaw-upgrade.sh" in result.stdout
    assert "--help, -h" in result.stdout
    assert not marker.exists(), "help started the release staging path"
