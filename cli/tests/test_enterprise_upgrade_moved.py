# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Check that a recorded move preserves the administrator's value."""

import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_moved_key_with_changed_value_fails(tmp_path: Path) -> None:
    before = tmp_path / "before.yaml"
    after = tmp_path / "after.yaml"
    record = tmp_path / "migration-v9.json"
    before.write_text("config_version: 8\nupdate_check: false\n")
    after.write_text("config_version: 9\nupdate:\n  check: true\n")
    record.write_text(json.dumps({
        "from_version": 8, "to_version": 9,
        "source_sha256": hashlib.sha256(before.read_bytes()).hexdigest(),
        "moved": [{"from": "update_check", "to": "update.check"}],
        "conflicts": [],
    }))
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts/check_enterprise_upgrade_config.py"),
         "--before", str(before), "--after", str(after), "--record", str(record)],
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 1
    assert "update_check moved to update.check, but changed from False to True" in result.stderr
