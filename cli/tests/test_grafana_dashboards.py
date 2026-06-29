"""Durable contract checks for the bundled Grafana dashboard catalog."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_grafana_dashboard_catalog_contract() -> None:
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts/check_grafana_dashboards.py")],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stdout + result.stderr
