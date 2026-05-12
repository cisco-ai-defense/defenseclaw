"""Snapshot create + restore (dry-run) round-trip."""

from __future__ import annotations

import os
from pathlib import Path

from dctest.config import get_settings, reset_settings_for_tests
from dctest.services import run_store
from dctest.services.snapshot import create_snapshot, list_snapshots, restore_snapshot


def _seed_run(runs_root: Path) -> str:
    run_id = "snap-it"
    run_store.ensure_run_layout(runs_root, run_id)
    (runs_root / run_id / "run.json").write_text("{}", encoding="utf-8")
    return run_id


def test_create_then_restore_dry_run(monkeypatch, tmp_path, isolated_runs_root):
    target = tmp_path / "fake-home"
    target.mkdir()
    sample = target / "sample.cfg"
    sample.write_text("hello", encoding="utf-8")
    # Point dctest at the temp directory only and confine restore allowlist.
    monkeypatch.setenv("HOME", str(target))
    reset_settings_for_tests()
    settings = get_settings()
    settings.snapshot_paths = [str(sample)]

    run_id = _seed_run(settings.runs_root)
    tgz = create_snapshot(run_id, "test-label")
    assert tgz.exists()
    listed = list_snapshots(run_id)
    assert any(p.name == tgz.name for p in listed)
    sample.unlink()
    paths = restore_snapshot(run_id, "test-label", dry_run=True)
    assert paths
    # File still gone (dry-run).
    assert not sample.exists()


def test_restore_refuses_unsafe_destination(tmp_path, isolated_runs_root, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "home").mkdir()
    reset_settings_for_tests()
    settings = get_settings()
    settings.snapshot_paths = [str(tmp_path / "home" / "sample.cfg")]
    (tmp_path / "home" / "sample.cfg").write_text("ok", encoding="utf-8")
    run_id = _seed_run(settings.runs_root)
    tgz = create_snapshot(run_id, "uns-1")
    assert tgz.exists()
    # Manipulate $HOME so destination falls outside allowlist.
    monkeypatch.setenv("HOME", str(tmp_path / "elsewhere"))
    reset_settings_for_tests()
    # Restore now resolves "HOME/..." to a path NOT in the allowlist;
    # since we are not dry-run, this should raise.
    import pytest

    from dctest.exceptions import SnapshotError

    with pytest.raises(SnapshotError):
        restore_snapshot(run_id, "uns-1")
