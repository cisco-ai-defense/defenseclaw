# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""A v9 to v9 enterprise upgrade has no migration record."""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_v9_upgrade_preserves_values_without_migration_record(tmp_path: Path) -> None:
    before = tmp_path / "before.yaml"
    after = tmp_path / "after.yaml"
    before.write_text("config_version: 9\nupdate:\n  check: false\n")
    after.write_text(before.read_text())
    command = [
        sys.executable, str(ROOT / "scripts/check_enterprise_upgrade_config.py"),
        "--before", str(before), "--after", str(after),
    ]
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr

    after.write_text("config_version: 9\nupdate:\n  check: true\n")
    changed = subprocess.run(command, capture_output=True, text=True, check=False)
    assert changed.returncode == 1
    assert "update.check changed" in changed.stderr
