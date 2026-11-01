# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""p0-round GAP-1095: a failed Windows deferred uninstall is visible."""

from __future__ import annotations

import json
import os
from pathlib import Path

from click.testing import CliRunner
from defenseclaw import platform_support
from defenseclaw.uninstall_result import failed_deferred_uninstall


def _result(folder: Path, name: str, payload: dict, mtime: float) -> Path:
    path = folder / f"defenseclaw-uninstall-result-{name}.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    os.utime(path, (mtime, mtime))
    return path


def test_the_newest_failed_result_after_the_install_is_reported(tmp_path: Path) -> None:
    _result(tmp_path, "old", {"status": "succeeded"}, 1000)
    path = _result(tmp_path, "new", {"status": "failed", "detail": "could not remove .defenseclaw: audit.db-shm is in use"}, 2000)
    assert failed_deferred_uninstall(str(tmp_path), since=1500) == (
        "could not remove .defenseclaw: audit.db-shm is in use",
        str(path),
    )


def test_a_result_older_than_the_install_or_not_failed_is_not_reported(tmp_path: Path) -> None:
    _result(tmp_path, "a", {"status": "failed", "detail": "x"}, 1000)
    assert failed_deferred_uninstall(str(tmp_path), since=1500) is None
    _result(tmp_path, "b", {"status": "succeeded"}, 2000)
    assert failed_deferred_uninstall(str(tmp_path), since=1500) is None
    (tmp_path / "defenseclaw-uninstall-result-c.json").write_text("{not json", encoding="utf-8")
    os.utime(tmp_path / "defenseclaw-uninstall-result-c.json", (3000, 3000))
    assert failed_deferred_uninstall(str(tmp_path), since=1500) is None


def test_any_command_on_windows_names_the_failed_uninstall(tmp_path: Path, monkeypatch) -> None:
    from defenseclaw import main as main_mod

    _result(tmp_path, "z", {"status": "failed", "detail": "could not remove .defenseclaw: audit.db-shm is in use"}, 4_000_000_000)
    monkeypatch.setattr(platform_support, "host_os", lambda: "windows")
    monkeypatch.setattr("tempfile.gettempdir", lambda: str(tmp_path))
    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path / "home"))
    result = CliRunner().invoke(main_mod.cli, ["version"])
    combined = result.output + (result.stderr if result.stderr_bytes is not None else "")
    assert "did not finish, so DefenseClaw is still installed" in combined
    assert "audit.db-shm is in use" in combined
    assert "run the same `defenseclaw uninstall` command again" in combined
