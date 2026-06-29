"""Durable contract checks for the bundled Grafana dashboard catalog."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _load_audit_module() -> ModuleType:
    path = ROOT / "scripts/check_grafana_dashboards.py"
    spec = importlib.util.spec_from_file_location("check_grafana_dashboards", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


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


def test_grafana_dashboard_catalog_requires_generated_mirror() -> None:
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/check_grafana_dashboards.py"),
            "--require-packaged",
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_source_audit_allows_missing_generated_mirror(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    audit = _load_audit_module()
    monkeypatch.setattr(audit, "PACKAGED_DIR", tmp_path / "missing")

    _dashboards, source_errors = audit.static_audit()
    _dashboards, ci_errors = audit.static_audit(require_packaged=True)

    assert not any("packaged Grafana dashboard directory is missing" in error for error in source_errors)
    assert any("packaged Grafana dashboard directory is missing" in error for error in ci_errors)
