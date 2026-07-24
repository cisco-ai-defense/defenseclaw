# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
PROTOCOL_SCRIPT = ROOT / "scripts" / "test-upgrade-protocol-release.sh"


def _bash() -> str:
    forced = os.environ.get("DEFENSECLAW_TEST_BASH")
    if forced:
        return forced
    return shutil.which("bash") or "bash"


@pytest.mark.skipif(os.name == "nt", reason="POSIX release harness")
def test_protocol_exit_trap_stops_sandbox_gateway_before_removing_workdir(
    tmp_path: Path,
) -> None:
    workdir = tmp_path / "protocol-workdir"
    smoke_home = workdir / "staged-0.7.2"
    gateway = smoke_home / ".local" / "bin" / "defenseclaw-gateway"
    marker = tmp_path / "gateway-stopped"
    gateway.parent.mkdir(parents=True)
    gateway.write_text(
        """#!/usr/bin/env bash
set -euo pipefail
[[ "${1:-}" == "stop" ]]
: > "${UPGRADE_PROTOCOL_STOP_MARKER:?}"
""",
        encoding="utf-8",
    )
    gateway.chmod(0o700)

    command = f"""
set -euo pipefail
source {shlex.quote(str(PROTOCOL_SCRIPT))}
WORKDIR={shlex.quote(str(workdir))}
SMOKE_HOME={shlex.quote(str(smoke_home))}
KEEP_WORKDIR=0
SERVER_PID=
trap protocol_cleanup EXIT
exit 23
"""
    environment = os.environ.copy()
    environment["UPGRADE_PROTOCOL_STOP_MARKER"] = str(marker)
    result = subprocess.run(
        [_bash(), "-c", command],
        cwd=ROOT,
        env=environment,
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 23, result.stderr
    assert marker.is_file(), result.stderr
    assert not workdir.exists()
