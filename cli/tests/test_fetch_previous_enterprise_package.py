# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Regression for the enterprise upgrade release lookup gate."""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _bash() -> str | None:
    """The bash the upgrade lanes run the script with (shell: bash).

    On Windows that is the bash of Git for Windows. A bare "bash" there
    starts System32\\bash.exe, the WSL launcher, because CreateProcess
    searches System32 before PATH; without a distribution it only prints
    how to install one (UTF-16, on stdout) and exits 1.
    """
    if os.name != "nt":
        return shutil.which("bash")
    git = shutil.which("git")
    for parent in Path(git).resolve().parents if git else ():
        if (candidate := parent / "bin" / "bash.exe").is_file():
            return str(candidate)
    return None


BASH = _bash()


@pytest.mark.skipif(BASH is None, reason="needs bash (the Git for Windows bash on Windows)")
def test_release_lookup_failure_fails_upgrade_lane(tmp_path: Path) -> None:
    gh = tmp_path / "gh"
    gh.write_bytes(b"#!/bin/sh\nexit 1\n")
    gh.chmod(0o755)
    path = os.pathsep.join([str(tmp_path), os.environ.get("PATH", "")])
    env = {**os.environ, "PATH": path, "GITHUB_REPOSITORY": "example/repo"}
    result = subprocess.run(
        [BASH, str(ROOT / "scripts/fetch-previous-enterprise-package.sh"),
         "--asset", "linux-amd64.deb", "--dir", str(tmp_path / "packages")],
        env=env, capture_output=True, text=True, check=False, timeout=60,
    )
    assert result.returncode != 0
    assert "could not look up" in result.stderr
