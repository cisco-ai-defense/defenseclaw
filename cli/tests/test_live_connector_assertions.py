# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

import json
import os
import shutil
import sqlite3
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
ASSERTIONS = ROOT / "scripts" / "live-connector-e2e" / "lib" / "assert.sh"
BASH = shutil.which("bash")

pytestmark = pytest.mark.skipif(os.name == "nt" or BASH is None, reason="POSIX bash is required")


def _audit_db(path: Path) -> None:
    with sqlite3.connect(path) as connection:
        connection.execute(
            """CREATE TABLE audit_events (
                action TEXT,
                event_name TEXT,
                enforced INTEGER,
                structured_json TEXT
            )"""
        )


def _insert(
    path: Path,
    payload: dict[str, object],
    *,
    action: str = "hook_decision",
    event_name: str = "hook_decision",
    enforced: int | None = 1,
) -> None:
    with sqlite3.connect(path) as connection:
        connection.execute(
            "INSERT INTO audit_events VALUES (?, ?, ?, ?)",
            (action, event_name, enforced, json.dumps(payload)),
        )


def _run(database: Path) -> subprocess.CompletedProcess[str]:
    command = [
        BASH or "bash",
        "-c",
        'source "$1"; DC_AUDIT_DB="$2"; dc_assert_verdict_block 0',
        "bash",
        ASSERTIONS,
        database,
    ]
    return subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


def test_block_verdict_accepts_canonical_guardrail_fields(tmp_path: Path) -> None:
    database = tmp_path / "audit.db"
    _audit_db(database)
    _insert(
        database,
        {
            "defenseclaw.guardrail.effective_action": "block",
            "defenseclaw.guardrail.raw_action": "block",
            "defenseclaw.guardrail.mode": "enforce",
        },
    )

    result = _run(database)

    assert result.returncode == 0, result.stderr


def test_block_verdict_accepts_canonical_scan_verdict(tmp_path: Path) -> None:
    database = tmp_path / "audit.db"
    _audit_db(database)
    _insert(
        database,
        {"defenseclaw.scan.verdict": "block"},
        action="scan",
        event_name="scan.completed",
        enforced=None,
    )

    result = _run(database)

    assert result.returncode == 0, result.stderr


def test_raw_block_does_not_override_effective_allow(tmp_path: Path) -> None:
    database = tmp_path / "audit.db"
    _audit_db(database)
    _insert(
        database,
        {
            "defenseclaw.guardrail.effective_action": "allow",
            "defenseclaw.guardrail.raw_action": "block",
            "defenseclaw.guardrail.mode": "observe",
        },
        enforced=0,
    )

    result = _run(database)

    assert result.returncode == 1
