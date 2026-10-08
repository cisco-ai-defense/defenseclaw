# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Regression for the enterprise upgrade release lookup gate."""

import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_release_lookup_failure_fails_upgrade_lane(tmp_path: Path) -> None:
    gh = tmp_path / "gh"
    gh.write_text("#!/bin/sh\nexit 1\n")
    gh.chmod(0o755)
    env = {**os.environ, "PATH": f"{tmp_path}:{os.environ['PATH']}", "GITHUB_REPOSITORY": "example/repo"}
    result = subprocess.run(
        ["bash", str(ROOT / "scripts/fetch-previous-enterprise-package.sh"),
         "--asset", "linux-amd64.deb", "--dir", str(tmp_path / "packages")],
        env=env, capture_output=True, text=True, check=False,
    )
    assert result.returncode != 0
    assert "could not look up" in result.stderr
