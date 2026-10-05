#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Keep a copy of a 0.x audit history before `make all` installs 1.0 over it.

The first time a 1.0 gateway opens an audit database written by 0.x, audit
migration 33 (a privacy cutover) deletes the audit events, scan results and
findings 0.x recorded. The release installers keep the old install, database
included, in ~/.defenseclaw/previous. A source install has no such copy, so
this keeps one in ~/.defenseclaw/backups and says so (GAP-1469).

Exit 0 when there is nothing to keep or the copy was made; exit 1 when the
database cannot be read or a copy is needed but could not be made, so
`make all` stops before anything changed.

With --pending it changes nothing and prints nothing: exit 0 when the next
gateway start still has that one-time purge to do, else 1. `make all` starts
the gateway quietly, so it says first that this start can take minutes
(GAP-2027).
"""

from __future__ import annotations

import os
import shutil
import sqlite3
import sys
import time
from pathlib import Path

# The schema version of internal/audit/store.go's
# "privacy: purge pre-cutover audit evidence" migration.
PURGE_MIGRATION = 33
HISTORY_TABLES = ("audit_events", "scan_results", "scan_findings", "findings")


def data_dir() -> Path:
    home = os.environ.get("DEFENSECLAW_HOME")
    return Path(home) if home else Path.home() / ".defenseclaw"


def open_db(db: Path) -> sqlite3.Connection:
    """Open db without changing it.

    Apple's /usr/bin/python3 (SQLite 3.43) cannot open a WAL database
    read-only once a stopped gateway has removed its -shm file, so fall back to
    a normal connection, which only adds the -wal/-shm files SQLite removes
    again on close (GAP-1792).
    """
    conn = None
    try:
        conn = sqlite3.connect(f"{db.as_uri()}?mode=ro", uri=True)
        conn.execute("SELECT 1 FROM sqlite_master LIMIT 1").fetchall()
        return conn
    except sqlite3.OperationalError:
        if conn is not None:
            conn.close()
    return sqlite3.connect(f"{db.as_uri()}?mode=rw", uri=True)


def rows_to_purge(db: Path) -> int:
    """Rows the purge would delete, or 0 when this database is already 1.x."""
    conn = open_db(db)
    try:
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
        if "schema_version" not in tables:
            return 0
        version = conn.execute("SELECT COALESCE(MAX(version), 0) FROM schema_version").fetchone()[0]
        if version == 0 or version >= PURGE_MIGRATION:
            return 0
        return sum(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] for table in HISTORY_TABLES if table in tables)
    finally:
        conn.close()


def main(argv: list[str] | None = None) -> int:
    home = data_dir().resolve()
    db = home / "audit.db"
    if argv == ["--pending"]:
        try:
            return 0 if db.is_file() and rows_to_purge(db) else 1
        except sqlite3.Error:
            return 1
    if not db.is_file():
        return 0
    try:
        rows = rows_to_purge(db)
    except sqlite3.Error as exc:
        # The 1.0 gateway would delete a 0.x history unseen, so stop here.
        print(f"  x Could not read {db} to check for a 0.x audit history ({exc}).", file=sys.stderr)
        print("    Nothing was changed.", file=sys.stderr)
        print(f"    Stop any gateway using it, or move {db} somewhere safe, then run make all again.", file=sys.stderr)
        return 1
    if rows == 0:
        return 0
    backups = home / "backups"
    earlier = sorted(backups.glob("audit-history-*.db")) if backups.is_dir() else []
    print(f"  ! DefenseClaw 1.0 starts a new audit history: the {rows:,} audit events, scan results and findings in {db}")
    print("    are deleted when the 1.0 gateway first opens it.")
    if earlier:
        print(f"    A copy from an earlier run is in {earlier[-1]}")
        return 0
    size = sum(path.stat().st_size for path in home.glob("audit.db*") if path.is_file())
    if shutil.disk_usage(home).free < size + 100 * 1024 * 1024:
        print(f"  x Not enough free disk space next to {db} for a copy ({size // (1024 * 1024):,} MB).", file=sys.stderr)
        print(f"    Free some space or move {db} somewhere safe, then run make all again; nothing was changed.", file=sys.stderr)
        return 1
    backups.mkdir(mode=0o700, exist_ok=True)
    kept = backups / f"audit-history-{time.strftime('%Y%m%dT%H%M%S')}.db"
    print(f"    Copying it to {kept} ({size // (1024 * 1024):,} MB; a large database takes a few minutes) ...", flush=True)
    partial = kept.with_name(kept.name + ".partial")
    source = open_db(db)
    try:
        # Copy under another name, so an interrupted copy is never taken for one.
        partial.unlink(missing_ok=True)
        os.close(os.open(partial, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
        target = sqlite3.connect(partial)
        try:
            # A fresh copy needs no journal; the source stays untouched.
            target.execute("PRAGMA journal_mode = OFF")
            target.execute("PRAGMA synchronous = OFF")
            source.backup(target)
        finally:
            target.close()
        os.replace(partial, kept)
    except (OSError, sqlite3.Error) as exc:
        partial.unlink(missing_ok=True)
        print(f"  x Could not copy {db} to {kept} ({exc}); nothing was changed.", file=sys.stderr)
        return 1
    finally:
        source.close()
    print(f"    Kept a copy in {kept}.")
    print(f"    Remove it once you no longer need the old history: rm '{kept}'")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
