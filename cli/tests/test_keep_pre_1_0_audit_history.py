# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""scripts/keep-pre-1.0-audit-history.py: `make all` keeps a 0.x audit history (GAP-1469)."""

from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "keep-pre-1.0-audit-history.py"


def _audit_db(home: Path, version: int, rows: int) -> None:
    home.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(home / "audit.db")
    conn.execute("CREATE TABLE schema_version (version INTEGER PRIMARY KEY, applied_at DATETIME NOT NULL)")
    conn.executemany("INSERT INTO schema_version VALUES (?, '2026-01-01')", [(v,) for v in range(1, version + 1)])
    conn.execute("CREATE TABLE audit_events (id TEXT PRIMARY KEY)")
    conn.execute("CREATE TABLE scan_results (id TEXT PRIMARY KEY)")
    conn.executemany("INSERT INTO audit_events VALUES (?)", [(f"e{i}",) for i in range(rows)])
    conn.commit()
    conn.close()


def _run(home: Path, *args: str) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "DEFENSECLAW_HOME": str(home)}
    cmd = [sys.executable, str(SCRIPT), *args]
    return subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=60, check=False)


def test_a_0_x_history_is_copied_once_before_make_all_installs_1_0(tmp_path: Path) -> None:
    home = tmp_path / ".defenseclaw"
    _audit_db(home, 29, 3)

    first = _run(home)

    assert first.returncode == 0, first.stderr
    kept = list((home / "backups").glob("audit-history-*.db"))
    assert len(kept) == 1
    assert sqlite3.connect(kept[0]).execute("SELECT COUNT(*) FROM audit_events").fetchone()[0] == 3
    assert "the 3 audit events, scan results and findings" in first.stdout
    assert f"Kept a copy in {kept[0]}." in first.stdout
    if os.name != "nt":
        assert kept[0].stat().st_mode & 0o777 == 0o600
    again = _run(home)
    assert again.returncode == 0 and "A copy from an earlier run is in" in again.stdout
    assert len(list((home / "backups").glob("audit-history-*.db"))) == 1


def test_a_1_x_or_empty_history_needs_no_copy(tmp_path: Path) -> None:
    for name, version, rows in (("current", 33, 5), ("empty", 29, 0)):
        home = tmp_path / name
        _audit_db(home, version, rows)
        result = _run(home)
        assert result.returncode == 0 and result.stdout == "", result.stdout + result.stderr
        assert not (home / "backups").exists()
    assert _run(tmp_path / "missing").returncode == 0


def test_pending_says_whether_the_next_gateway_start_purges_a_history(tmp_path: Path) -> None:
    for name, version, rows, want in (("old", 29, 3, 0), ("current", 33, 5, 1), ("empty", 29, 0, 1)):
        home = tmp_path / name
        _audit_db(home, version, rows)
        result = _run(home, "--pending")
        assert (result.returncode, result.stdout) == (want, ""), name + result.stderr
        assert not (home / "backups").exists()
    assert _run(tmp_path / "missing", "--pending").returncode == 1


def test_make_all_says_so_before_its_quiet_gateway_start_upgrades_the_audit_db() -> None:
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    recipe = makefile[makefile.index("\nsource-restart-gateway:") : makefile.index("\npath:")]
    assert "keep-pre-1.0-audit-history.py --pending" in recipe
    assert "Upgrading the audit database before the gateway starts (one time" in recipe
    start = recipe.index('$(EXE)" start >/dev/null')
    restart = recipe.index('$(EXE)" restart >/dev/null')
    assert recipe.index("upgrade_note;") < start < recipe.rindex("upgrade_note;") < restart


def test_make_all_keeps_it_before_installing() -> None:
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    recipe = makefile[makefile.index("\nall: ") : makefile.index("\npath: ")]
    assert recipe.index("keep-pre-1.0-audit-history.py") < recipe.index("_source-dev-install")


def test_a_history_is_kept_when_sqlite_cannot_open_it_read_only(tmp_path: Path, monkeypatch) -> None:
    # GAP-1792: Apple's /usr/bin/python3 cannot open a stopped gateway's WAL
    # database with mode=ro; the keep step must still copy the history.
    import importlib.util

    spec = importlib.util.spec_from_file_location("keep_history", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    home = tmp_path / ".defenseclaw"
    _audit_db(home, 29, 3)
    real_connect = sqlite3.connect

    def connect(database, *args, **kwargs):
        if "mode=ro" in str(database):
            raise sqlite3.OperationalError("unable to open database file")
        return real_connect(database, *args, **kwargs)

    monkeypatch.setattr(module.sqlite3, "connect", connect)
    monkeypatch.setenv("DEFENSECLAW_HOME", str(home))

    assert module.main() == 0
    kept = list((home / "backups").glob("audit-history-*.db"))
    assert len(kept) == 1
    assert real_connect(kept[0]).execute("SELECT COUNT(*) FROM audit_events").fetchone()[0] == 3


def test_an_unreadable_database_stops_make_all(tmp_path: Path) -> None:
    home = tmp_path / ".defenseclaw"
    home.mkdir()
    (home / "audit.db").write_bytes(b"not a database" * 100)

    result = _run(home)

    assert result.returncode == 1
    assert "Could not read" in result.stderr and "Nothing was changed" in result.stderr
