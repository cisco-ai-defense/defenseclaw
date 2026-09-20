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

from __future__ import annotations

import json
import os
import shutil
import sqlite3
import stat
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
RESOLVER = ROOT / "scripts" / "upgrade.sh"
PROTOCOL_RESOLVER = ROOT / "scripts" / "test-upgrade-protocol-release.sh"

pytestmark = pytest.mark.skipif(
    os.name == "nt",
    reason="release-owned resolver field recovery is POSIX-only",
)


def _recovery_interpreters() -> tuple[str, ...]:
    active_bin = os.path.dirname(os.path.abspath(sys.executable))
    ambient_path = os.pathsep.join(
        entry
        for entry in os.environ.get("PATH", "").split(os.pathsep)
        if os.path.abspath(entry or os.curdir) != active_bin
    )
    candidates = [
        sys.executable,
        shutil.which("python3", path=ambient_path),
    ]
    selected: list[str] = []
    identities: set[str] = set()
    for candidate in candidates:
        if candidate is None:
            continue
        identity = os.path.realpath(candidate)
        if identity in identities:
            continue
        identities.add(identity)
        selected.append(candidate)
    return tuple(selected)


RECOVERY_INTERPRETERS = _recovery_interpreters()


def _embedded_python(after: str, *, before: str) -> str:
    source = RESOLVER.read_text(encoding="utf-8")
    start = source.find(after)
    assert start >= 0, f"missing resolver section anchor {after!r}"
    boundary = source.find(before, start + len(after))
    assert boundary >= 0, f"missing resolver section boundary {before!r}"
    heredoc = source.find("<<'PY'", start, boundary)
    assert heredoc >= 0, f"missing embedded Python opener within resolver section {after!r}"
    body = source.find("\n", heredoc, boundary)
    assert body >= 0, f"missing embedded Python body after resolver anchor {after!r}"
    body += 1
    end = source.find("\nPY\n", body, boundary)
    assert end >= 0, f"missing embedded Python terminator after resolver anchor {after!r}"
    return source[body:end] + "\n"


def _private_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(0o700)
    return path


def _write_private(path: Path, payload: bytes) -> None:
    path.write_bytes(payload)
    path.chmod(0o600)


def _run_quarantine(
    program: str,
    *,
    interpreter: str = sys.executable,
    data_dir: Path,
    backup_dir: Path,
    audit_db: Path,
    backup_root: Path,
    preflight_identity: str,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            interpreter,
            "-I",
            "-B",
            "-",
            str(data_dir),
            str(backup_dir),
            str(audit_db),
            str(backup_root),
            preflight_identity,
        ],
        input=program,
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )


def _run_live_probe(
    program: str,
    *,
    data_dir: Path,
    audit_db: Path,
    backup_root: Path,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            "-I",
            "-B",
            "-",
            str(data_dir),
            str(audit_db),
            str(backup_root),
        ],
        input=program,
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )


def _without_modern_sqlite_error_metadata(
    program: str,
    *,
    connection_statement: str,
    message: str,
) -> str:
    """Force the compatibility path used by Python 3.10 and older."""
    assert program.count("import sqlite3\n") == 1
    assert program.count(connection_statement) == 1
    compatibility_setup = """import sqlite3
for _sqlite_name in ("SQLITE_CORRUPT", "SQLITE_NOTADB"):
    if hasattr(sqlite3, _sqlite_name):
        delattr(sqlite3, _sqlite_name)
"""
    program = program.replace("import sqlite3\n", compatibility_setup, 1)
    return program.replace(
        connection_statement,
        f'raise sqlite3.DatabaseError("{message}")',
        1,
    )


def _identity(path: Path) -> dict[str, int]:
    info = path.lstat()
    return {
        "device": info.st_dev,
        "inode": info.st_ino,
        "size": info.st_size,
        "mtime_ns": info.st_mtime_ns,
    }


def _protocol_corrupt_audit_fixture_program() -> str:
    source = PROTOCOL_RESOLVER.read_text(encoding="utf-8")
    command_anchor = "python3 - \"${audit_db}\" <<'PY'"
    assert source.count(command_anchor) == 1, "ambiguous corrupt-audit fixture command anchor"
    command = source.index(command_anchor)
    case_anchor = "corrupt-audit-same-version)"
    assert source.count(case_anchor, 0, command) == 1, "ambiguous corrupt-audit fixture case anchor"
    case_start = source.rindex(case_anchor, 0, command)
    case_end = source.index("\n            ;;\n", command)
    body_anchor = "\nfrom pathlib import Path\n"
    assert source.count(body_anchor, command, case_end) == 1, "ambiguous corrupt-audit fixture body anchor"
    body = source.index(body_anchor, command, case_end) + 1
    end_anchor = "\nPY\n"
    assert source.count(end_anchor, body, case_end) == 1, "ambiguous corrupt-audit fixture terminator"
    end = source.index(end_anchor, body, case_end)
    assert case_start < command < body < end < case_end
    return source[body:end] + "\n"


def test_protocol_corrupt_fixture_removes_safe_sqlite_sidecars(tmp_path: Path) -> None:
    audit_db = tmp_path / "audit.db"
    _write_private(audit_db, b"healthy source database\n")
    sidecars = [Path(f"{audit_db}{suffix}") for suffix in ("-wal", "-shm", "-journal")]
    for sidecar in sidecars:
        _write_private(sidecar, f"{sidecar.name} stale bytes\n".encode())

    completed = subprocess.run(
        [sys.executable, "-I", "-B", "-", str(audit_db)],
        input=_protocol_corrupt_audit_fixture_program(),
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )

    assert completed.returncode == 0, completed.stderr
    assert audit_db.read_bytes() == b"DefenseClaw corrupt audit fixture\n"
    assert all(not os.path.lexists(sidecar) for sidecar in sidecars)


@pytest.mark.parametrize("unsafe_kind", ("symlink", "directory", "hardlink"))
def test_protocol_corrupt_fixture_refuses_unsafe_sqlite_sidecar(
    tmp_path: Path,
    unsafe_kind: str,
) -> None:
    audit_db = tmp_path / "audit.db"
    original = b"healthy source database\n"
    _write_private(audit_db, original)
    sidecar = Path(f"{audit_db}-wal")
    if unsafe_kind == "symlink":
        sidecar.symlink_to(audit_db)
    elif unsafe_kind == "directory":
        sidecar.mkdir()
    else:
        hardlink_source = tmp_path / "attacker-owned-alias"
        _write_private(hardlink_source, b"aliased sidecar bytes\n")
        os.link(hardlink_source, sidecar)

    completed = subprocess.run(
        [sys.executable, "-I", "-B", "-", str(audit_db)],
        input=_protocol_corrupt_audit_fixture_program(),
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )

    assert completed.returncode != 0
    assert "field-recovery audit sidecar is unsafe" in completed.stderr
    assert audit_db.read_bytes() == original
    assert os.path.lexists(sidecar)


def test_protocol_corrupt_fixture_preflights_all_sidecars_before_cleanup(tmp_path: Path) -> None:
    audit_db = tmp_path / "audit.db"
    original = b"healthy source database\n"
    _write_private(audit_db, original)
    safe_wal = Path(f"{audit_db}-wal")
    unsafe_shm = Path(f"{audit_db}-shm")
    _write_private(safe_wal, b"safe WAL bytes\n")
    unsafe_shm.symlink_to(audit_db)

    completed = subprocess.run(
        [sys.executable, "-I", "-B", "-", str(audit_db)],
        input=_protocol_corrupt_audit_fixture_program(),
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )

    assert completed.returncode != 0
    assert "field-recovery audit sidecar is unsafe" in completed.stderr
    assert audit_db.read_bytes() == original
    assert safe_wal.read_bytes() == b"safe WAL bytes\n"
    assert unsafe_shm.is_symlink()


@pytest.mark.parametrize("mode", (0o644, 0o640), ids=lambda value: f"{value:04o}")
def test_live_probe_accepts_owner_owned_legacy_readable_database(
    tmp_path: Path,
    mode: int,
) -> None:
    program = _embedded_python(
        "audit_db_probe=",
        before="\nIFS=$'\\t' read -r audit_db_state",
    )
    data_dir = _private_dir(tmp_path / "data")
    audit_parent = _private_dir(data_dir / "state")
    backup_root = _private_dir(tmp_path / "controller" / "backups")
    audit_db = audit_parent / "audit.db"
    with sqlite3.connect(audit_db) as connection:
        connection.execute("CREATE TABLE legacy_mode_fixture (value TEXT NOT NULL)")
        connection.execute("INSERT INTO legacy_mode_fixture VALUES ('preserved')")
    audit_db.chmod(mode)
    info = audit_db.lstat()

    completed = _run_live_probe(
        program,
        data_dir=data_dir,
        audit_db=audit_db,
        backup_root=backup_root,
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == f"healthy\t{info.st_dev}:{info.st_ino}"
    assert stat.S_IMODE(audit_db.stat().st_mode) == mode


@pytest.mark.parametrize("mode", (0o620, 0o602), ids=lambda value: f"{value:04o}")
def test_live_probe_rejects_group_or_world_writable_database(
    tmp_path: Path,
    mode: int,
) -> None:
    program = _embedded_python(
        "audit_db_probe=",
        before="\nIFS=$'\\t' read -r audit_db_state",
    )
    data_dir = _private_dir(tmp_path / "data")
    audit_parent = _private_dir(data_dir / "state")
    backup_root = _private_dir(tmp_path / "controller" / "backups")
    audit_db = audit_parent / "audit.db"
    with sqlite3.connect(audit_db) as connection:
        connection.execute("CREATE TABLE unsafe_mode_fixture (value TEXT NOT NULL)")
    audit_db.chmod(mode)

    completed = _run_live_probe(
        program,
        data_dir=data_dir,
        audit_db=audit_db,
        backup_root=backup_root,
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "invalid"
    assert stat.S_IMODE(audit_db.stat().st_mode) == mode


@pytest.mark.parametrize(
    ("mode", "expected"),
    (
        (0o644, "wal-pending"),
        (0o640, "wal-pending"),
        (0o620, "invalid"),
        (0o602, "invalid"),
    ),
    ids=lambda value: f"{value:04o}" if isinstance(value, int) else value,
)
def test_live_probe_applies_legacy_permission_rule_to_wal(
    tmp_path: Path,
    mode: int,
    expected: str,
) -> None:
    program = _embedded_python(
        "audit_db_probe=",
        before="\nIFS=$'\\t' read -r audit_db_state",
    )
    data_dir = _private_dir(tmp_path / "data")
    audit_parent = _private_dir(data_dir / "state")
    backup_root = _private_dir(tmp_path / "controller" / "backups")
    audit_db = audit_parent / "audit.db"
    with sqlite3.connect(audit_db) as connection:
        connection.execute("CREATE TABLE wal_mode_fixture (value TEXT NOT NULL)")
    audit_db.chmod(0o600)
    wal = Path(f"{audit_db}-wal")
    wal.write_bytes(b"legacy WAL permission fixture\n")
    wal.chmod(mode)
    info = audit_db.lstat()

    completed = _run_live_probe(
        program,
        data_dir=data_dir,
        audit_db=audit_db,
        backup_root=backup_root,
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == f"{expected}\t{info.st_dev}:{info.st_ino}"
    assert stat.S_IMODE(wal.stat().st_mode) == mode


@pytest.mark.parametrize("mode", (0o644, 0o640), ids=lambda value: f"{value:04o}")
def test_legacy_readable_corrupt_set_becomes_private_recovery_custody(
    tmp_path: Path,
    mode: int,
) -> None:
    program = _embedded_python(
        "quarantine_corrupt_audit_store() {",
        before="\n}\n\nassert_gateway_quiesced() {",
    )
    data_dir = _private_dir(tmp_path / "data")
    audit_parent = _private_dir(data_dir / "state")
    backup_root = _private_dir(tmp_path / "controller" / "backups")
    backup_dir = _private_dir(backup_root / "upgrade-test")
    audit_db = audit_parent / "custom.sqlite"
    sources = {
        "audit.db": audit_db,
        "audit.db-wal": Path(f"{audit_db}-wal"),
        "audit.db-shm": Path(f"{audit_db}-shm"),
    }
    for name, path in sources.items():
        path.write_bytes(f"{name} legacy readable bytes\n".encode())
        path.chmod(mode)
    info = audit_db.lstat()

    completed = _run_quarantine(
        program,
        data_dir=data_dir,
        backup_dir=backup_dir,
        audit_db=audit_db,
        backup_root=backup_root,
        preflight_identity=f"{info.st_dev}:{info.st_ino}",
    )

    assert completed.returncode == 0, completed.stderr
    custody = backup_dir / "audit-corrupt"
    assert completed.stdout.strip() == str(custody)
    assert stat.S_IMODE(custody.stat().st_mode) == 0o700
    for name, source in sources.items():
        retained = custody / name
        assert retained.read_bytes() == f"{name} legacy readable bytes\n".encode()
        assert stat.S_IMODE(retained.stat().st_mode) == 0o600
        assert not source.exists()


@pytest.mark.parametrize(
    ("component", "mode"),
    (
        ("audit.db", 0o620),
        ("audit.db", 0o602),
        ("audit.db-wal", 0o620),
        ("audit.db-wal", 0o602),
    ),
    ids=lambda value: f"{value:04o}" if isinstance(value, int) else value,
)
def test_quiesced_recovery_rejects_group_or_world_writable_sqlite_file(
    tmp_path: Path,
    component: str,
    mode: int,
) -> None:
    program = _embedded_python(
        "quarantine_corrupt_audit_store() {",
        before="\n}\n\nassert_gateway_quiesced() {",
    )
    data_dir = _private_dir(tmp_path / "data")
    audit_parent = _private_dir(data_dir / "state")
    backup_root = _private_dir(tmp_path / "controller" / "backups")
    backup_dir = _private_dir(backup_root / "upgrade-test")
    audit_db = audit_parent / "custom.sqlite"
    sources = {
        "audit.db": audit_db,
        "audit.db-wal": Path(f"{audit_db}-wal"),
    }
    for path in sources.values():
        _write_private(path, b"unsafe recovery mode fixture\n")
    sources[component].chmod(mode)
    info = audit_db.lstat()

    completed = _run_quarantine(
        program,
        data_dir=data_dir,
        backup_dir=backup_dir,
        audit_db=audit_db,
        backup_root=backup_root,
        preflight_identity=f"{info.st_dev}:{info.st_ino}",
    )

    assert completed.returncode != 0
    assert "unsafe audit recovery input" in completed.stderr
    assert not (backup_dir / "audit-corrupt").exists()
    assert all(path.exists() for path in sources.values())


@pytest.mark.parametrize(
    "interpreter",
    RECOVERY_INTERPRETERS,
    ids=lambda value: f"python-{Path(value).resolve().name}",
)
def test_corrupt_custom_audit_store_moves_exact_bytes_to_private_custody(
    tmp_path: Path,
    interpreter: str,
) -> None:
    program = _embedded_python(
        "quarantine_corrupt_audit_store() {",
        before="\n}\n\nassert_gateway_quiesced() {",
    )
    data_dir = _private_dir(tmp_path / "data")
    audit_parent = _private_dir(data_dir / "state")
    backup_root = _private_dir(tmp_path / "controller" / "backups")
    backup_dir = _private_dir(backup_root / "upgrade-test")
    audit_db = audit_parent / "custom.sqlite"
    payloads = {
        audit_db: b"not a sqlite database\n",
        Path(f"{audit_db}-wal"): b"wal custody\n",
        Path(f"{audit_db}-shm"): b"shm custody\n",
    }
    for path, payload in payloads.items():
        _write_private(path, payload)
    info = audit_db.lstat()

    completed = _run_quarantine(
        program,
        interpreter=interpreter,
        data_dir=data_dir,
        backup_dir=backup_dir,
        audit_db=audit_db,
        backup_root=backup_root,
        preflight_identity=f"{info.st_dev}:{info.st_ino}",
    )

    assert completed.returncode == 0, completed.stderr
    custody = backup_dir / "audit-corrupt"
    assert completed.stdout.strip() == str(custody)
    assert (custody / "audit.db").read_bytes() == payloads[audit_db]
    assert (custody / "audit.db-wal").read_bytes() == payloads[Path(f"{audit_db}-wal")]
    assert (custody / "audit.db-shm").read_bytes() == payloads[Path(f"{audit_db}-shm")]
    assert stat.S_IMODE(custody.stat().st_mode) == 0o700
    assert not audit_db.exists()
    assert not (data_dir / ".audit-recovery.json").exists()


@pytest.mark.parametrize(
    "interpreter",
    RECOVERY_INTERPRETERS,
    ids=lambda value: f"python-{Path(value).resolve().name}",
)
def test_wal_probe_without_source_shm_is_readable_and_non_mutating(
    tmp_path: Path,
    interpreter: str,
) -> None:
    program = _embedded_python(
        "quarantine_corrupt_audit_store() {",
        before="\n}\n\nassert_gateway_quiesced() {",
    )
    data_dir = _private_dir(tmp_path / "data")
    audit_parent = _private_dir(data_dir / "state")
    backup_root = _private_dir(tmp_path / "controller" / "backups")
    backup_dir = _private_dir(backup_root / "upgrade-test")
    audit_db = audit_parent / "custom.sqlite"
    producer = tmp_path / "producer.sqlite"

    with sqlite3.connect(producer) as connection:
        assert connection.execute("PRAGMA journal_mode=WAL").fetchone() == ("wal",)
        connection.execute("PRAGMA wal_autocheckpoint=0")
        connection.execute("CREATE TABLE events (value TEXT NOT NULL)")
        connection.commit()
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        connection.execute("INSERT INTO events VALUES ('from-wal')")
        connection.commit()
        _write_private(audit_db, producer.read_bytes())
        _write_private(Path(f"{audit_db}-wal"), Path(f"{producer}-wal").read_bytes())

    before = {
        audit_db: audit_db.read_bytes(),
        Path(f"{audit_db}-wal"): Path(f"{audit_db}-wal").read_bytes(),
    }
    info = audit_db.lstat()
    completed = _run_quarantine(
        program,
        interpreter=interpreter,
        data_dir=data_dir,
        backup_dir=backup_dir,
        audit_db=audit_db,
        backup_root=backup_root,
        preflight_identity=f"{info.st_dev}:{info.st_ino}",
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "__healthy__"
    assert {path: path.read_bytes() for path in before} == before
    assert not Path(f"{audit_db}-shm").exists()
    assert not (backup_dir / "audit-corrupt").exists()


def test_quiesced_probe_classifies_legacy_corruption_message(tmp_path: Path) -> None:
    program = _embedded_python(
        "quarantine_corrupt_audit_store() {",
        before="\n}\n\nassert_gateway_quiesced() {",
    )
    program = _without_modern_sqlite_error_metadata(
        program,
        connection_statement=("connection = sqlite3.connect(probe_db.as_uri() + query, uri=True, timeout=1.0)"),
        message="file is not a database",
    )
    data_dir = _private_dir(tmp_path / "data")
    audit_parent = _private_dir(data_dir / "state")
    backup_root = _private_dir(tmp_path / "controller" / "backups")
    backup_dir = _private_dir(backup_root / "upgrade-test")
    audit_db = audit_parent / "custom.sqlite"
    payload = b"legacy Python corrupt database\n"
    _write_private(audit_db, payload)
    info = audit_db.lstat()

    completed = _run_quarantine(
        program,
        data_dir=data_dir,
        backup_dir=backup_dir,
        audit_db=audit_db,
        backup_root=backup_root,
        preflight_identity=f"{info.st_dev}:{info.st_ino}",
    )

    assert completed.returncode == 0, completed.stderr
    custody = backup_dir / "audit-corrupt"
    assert completed.stdout.strip() == str(custody)
    assert (custody / "audit.db").read_bytes() == payload


def test_quiesced_probe_keeps_unclassified_legacy_failure_uncertain(tmp_path: Path) -> None:
    program = _embedded_python(
        "quarantine_corrupt_audit_store() {",
        before="\n}\n\nassert_gateway_quiesced() {",
    )
    program = _without_modern_sqlite_error_metadata(
        program,
        connection_statement=("connection = sqlite3.connect(probe_db.as_uri() + query, uri=True, timeout=1.0)"),
        message="database is locked",
    )
    data_dir = _private_dir(tmp_path / "data")
    audit_parent = _private_dir(data_dir / "state")
    backup_root = _private_dir(tmp_path / "controller" / "backups")
    backup_dir = _private_dir(backup_root / "upgrade-test")
    audit_db = audit_parent / "custom.sqlite"
    payload = b"do not move uncertain database bytes\n"
    _write_private(audit_db, payload)
    info = audit_db.lstat()

    completed = _run_quarantine(
        program,
        data_dir=data_dir,
        backup_dir=backup_dir,
        audit_db=audit_db,
        backup_root=backup_root,
        preflight_identity=f"{info.st_dev}:{info.st_ino}",
    )

    assert completed.returncode != 0
    assert "SQLite probe result: uncertain" in completed.stderr
    assert audit_db.read_bytes() == payload
    assert not (backup_dir / "audit-corrupt").exists()


@pytest.mark.parametrize(
    ("message", "expected_state"),
    (
        ("file is not a database", "suspected-corrupt"),
        ("interrupted", "unchecked"),
        ("database is locked", "unavailable"),
    ),
)
def test_live_probe_classifies_legacy_sqlite_failures_conservatively(
    tmp_path: Path,
    message: str,
    expected_state: str,
) -> None:
    program = _embedded_python(
        "audit_db_probe=",
        before="\nIFS=$'\\t' read -r audit_db_state",
    )
    program = _without_modern_sqlite_error_metadata(
        program,
        connection_statement=(
            'connection = sqlite3.connect(path.as_uri() + "?mode=ro&immutable=1", uri=True, timeout=1.0)'
        ),
        message=message,
    )
    data_dir = _private_dir(tmp_path / "data")
    audit_parent = _private_dir(data_dir / "state")
    backup_root = _private_dir(tmp_path / "controller" / "backups")
    audit_db = audit_parent / "audit.db"
    _write_private(audit_db, b"legacy SQLite failure fixture\n")
    info = audit_db.lstat()

    completed = subprocess.run(
        [
            sys.executable,
            "-I",
            "-B",
            "-",
            str(data_dir),
            str(audit_db),
            str(backup_root),
        ],
        input=program,
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )

    assert completed.returncode == 0, completed.stderr
    if expected_state == "suspected-corrupt":
        assert completed.stdout.strip() == (f"suspected-corrupt\t{info.st_dev}:{info.st_ino}")
    else:
        assert completed.stdout.strip() == expected_state


def test_live_probe_does_not_call_a_wal_backed_database_corrupt(tmp_path: Path) -> None:
    program = _embedded_python(
        "audit_db_probe=",
        before="\nIFS=$'\\t' read -r audit_db_state",
    )
    program = _without_modern_sqlite_error_metadata(
        program,
        connection_statement=(
            'connection = sqlite3.connect(path.as_uri() + "?mode=ro&immutable=1", uri=True, timeout=1.0)'
        ),
        message="file is not a database",
    )
    data_dir = _private_dir(tmp_path / "data")
    audit_parent = _private_dir(data_dir / "state")
    backup_root = _private_dir(tmp_path / "controller" / "backups")
    audit_db = audit_parent / "audit.db"
    _write_private(audit_db, b"database bytes requiring its WAL\n")
    _write_private(Path(f"{audit_db}-wal"), b"safe pending WAL bytes\n")
    info = audit_db.lstat()

    completed = _run_live_probe(
        program,
        data_dir=data_dir,
        audit_db=audit_db,
        backup_root=backup_root,
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == f"wal-pending\t{info.st_dev}:{info.st_ino}"


@pytest.mark.parametrize(
    ("recover", "expected_recovery"),
    ((False, 0), (True, 1)),
)
def test_live_corruption_is_only_a_post_stop_recovery_candidate(
    tmp_path: Path,
    recover: bool,
    expected_recovery: int,
) -> None:
    source = RESOLVER.read_text(encoding="utf-8")
    start = source.index("IFS=$'\\t' read -r audit_db_state AUDIT_DB_PREFLIGHT_IDENTITY")
    end = source.index("\nesac", start) + len("\nesac")
    decision = source[start:end]
    harness = tmp_path / "suspected-corruption-decision.sh"
    harness.write_text(
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        "audit_db_probe=$'suspected-corrupt\\t11:22'\n"
        f"RECOVER_CORRUPT_AUDIT={int(recover)}\n"
        "AUDIT_DB_RECOVERY_NEEDED=0\n"
        "AUDIT_DB_RECOVERY_USE_DATA_ROOT=0\n"
        "AUDIT_DB_RECOVERY_BACKUP_ROOT=''\n"
        "DATA_DIR=/fixture\n"
        "warn() { :; }\n"
        "die() { printf 'unexpected hard failure\\n' >&2; exit 73; }\n"
        + decision
        + "\n"
        + 'printf "%s\\t%s\\n" "$AUDIT_DB_RECOVERY_NEEDED" '
        + '"$AUDIT_DB_PREFLIGHT_IDENTITY"\n',
        encoding="utf-8",
    )

    completed = subprocess.run(
        ["/bin/bash", str(harness)],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == f"{expected_recovery}\t11:22"


@pytest.mark.parametrize("audit_state", ("invalid", "unexpected-state"))
@pytest.mark.parametrize("recover", (False, True))
def test_invalid_live_audit_state_fails_before_post_stop_recovery(
    tmp_path: Path,
    audit_state: str,
    recover: bool,
) -> None:
    source = RESOLVER.read_text(encoding="utf-8")
    start = source.index("IFS=$'\\t' read -r audit_db_state AUDIT_DB_PREFLIGHT_IDENTITY")
    end = source.index("\nesac", start) + len("\nesac")
    decision = source[start:end]
    harness = tmp_path / "invalid-audit-decision.sh"
    harness.write_text(
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        f"audit_db_probe={audit_state!r}\n"
        f"RECOVER_CORRUPT_AUDIT={int(recover)}\n"
        "AUDIT_DB_RECOVERY_NEEDED=0\n"
        "AUDIT_DB_RECOVERY_USE_DATA_ROOT=0\n"
        "AUDIT_DB_RECOVERY_BACKUP_ROOT=''\n"
        "DATA_DIR=/fixture\n"
        "warn() { :; }\n"
        'die() { printf \'recovery=%s\\t%s\\n\' "$AUDIT_DB_RECOVERY_NEEDED" "$*" >&2; exit 73; }\n'
        + decision
        + "\n"
        + "printf 'decision unexpectedly continued\\n'\n",
        encoding="utf-8",
    )

    completed = subprocess.run(
        ["/bin/bash", str(harness)],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )

    # "invalid" means the path itself is unsafe/unreadable, not merely that
    # the live integrity result was inconclusive. Neither ordinary upgrade nor
    # recovery opt-in may carry that unauthenticated path past the service stop.
    assert completed.returncode == 73
    assert completed.stdout == ""
    assert completed.stderr.startswith("recovery=0\t")
    assert "unsafe or unreadable" in completed.stderr


def test_legacy_readiness_child_closes_advisory_lock_descriptor() -> None:
    source = RESOLVER.read_text(encoding="utf-8")
    start = source.index("legacy_gateway_status_ready() {")
    heredoc = source.index("<<'PY'", start)
    invocation = source[start:heredoc]

    assert '"defenseclaw-legacy-readiness-v1" "${RELEASE_VERSION}" 9>&-' in invocation


def test_recovery_refusal_restarts_source_with_resolved_openclaw_home() -> None:
    source = RESOLVER.read_text(encoding="utf-8")
    start = source.index("if ! quarantine_corrupt_audit_store; then")
    end = source.index("\nfi", start) + len("\nfi")
    restart = source[start:end]

    assert 'DEFENSECLAW_HOME="${DATA_DIR}" DEFENSECLAW_CONFIG="${CONFIG_PATH}"' in restart
    assert 'OPENCLAW_HOME="${OPENCLAW_HOME}"' in restart
    assert '"${INSTALL_DIR}/defenseclaw-gateway" start' in restart


def test_audit_probe_rejects_non_mapping_recovery_marker_without_crashing(tmp_path: Path) -> None:
    program = _embedded_python(
        "audit_db_probe=",
        before="\nIFS=$'\\t' read -r audit_db_state",
    )
    data_dir = _private_dir(tmp_path / "data")
    audit_parent = _private_dir(data_dir / "state")
    backup_root = _private_dir(tmp_path / "controller" / "backups")
    audit_db = audit_parent / "audit.db"
    _write_private(data_dir / ".audit-recovery.json", b"[]\n")

    completed = subprocess.run(
        [
            sys.executable,
            "-I",
            "-B",
            "-",
            str(data_dir),
            str(audit_db),
            str(backup_root),
        ],
        input=program,
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "invalid-marker"


def test_audit_custody_resumes_cross_controller_from_recorded_identities(tmp_path: Path) -> None:
    program = _embedded_python(
        "quarantine_corrupt_audit_store() {",
        before="\n}\n\nassert_gateway_quiesced() {",
    )
    data_dir = _private_dir(tmp_path / "data")
    audit_parent = _private_dir(data_dir / "state")
    controller_backup_root = _private_dir(tmp_path / "controller" / "backups")
    new_backup_dir = _private_dir(controller_backup_root / "upgrade-shell-retry")
    cli_backup_root = _private_dir(data_dir / "backups")
    cli_backup_dir = _private_dir(cli_backup_root / "upgrade-cli-attempt")
    custody = _private_dir(cli_backup_dir / "audit-corrupt")
    audit_db = audit_parent / "custom.sqlite"
    sources = {
        "audit.db": audit_db,
        "audit.db-wal": Path(f"{audit_db}-wal"),
        "audit.db-shm": Path(f"{audit_db}-shm"),
    }
    for name, path in sources.items():
        _write_private(path, f"{name} exact bytes\n".encode())
    identities = {name: _identity(path) for name, path in sources.items()}
    os.rename(sources["audit.db-wal"], custody / "audit.db-wal")
    marker = data_dir / ".audit-recovery.json"
    marker.write_text(
        json.dumps(
            {
                "schema": 2,
                "source": str(audit_db),
                "custody": str(custody),
                "files": [
                    "audit.db-wal",
                    "audit.db-shm",
                    "audit.db-journal",
                    "audit.db",
                ],
                "identities": identities,
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    marker.chmod(0o600)

    completed = _run_quarantine(
        program,
        data_dir=data_dir,
        backup_dir=new_backup_dir,
        audit_db=audit_db,
        backup_root=controller_backup_root,
        preflight_identity="",
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == str(custody)
    for name, record in identities.items():
        retained = custody / name
        assert _identity(retained) == record
        assert not sources[name].exists()
    assert not marker.exists()


def test_audit_recovery_marker_refuses_custody_outside_backup_roots(tmp_path: Path) -> None:
    program = _embedded_python(
        "quarantine_corrupt_audit_store() {",
        before="\n}\n\nassert_gateway_quiesced() {",
    )
    data_dir = _private_dir(tmp_path / "data")
    audit_parent = _private_dir(data_dir / "state")
    backup_root = _private_dir(tmp_path / "controller" / "backups")
    backup_dir = _private_dir(backup_root / "upgrade-shell-retry")
    escaped_attempt = _private_dir(tmp_path / "escaped" / "upgrade-attacker")
    escaped_custody = _private_dir(escaped_attempt / "audit-corrupt")
    audit_db = audit_parent / "custom.sqlite"
    original = b"original corrupt database bytes\n"
    _write_private(audit_db, original)
    marker = data_dir / ".audit-recovery.json"
    marker.write_text(
        json.dumps(
            {
                "schema": 2,
                "source": str(audit_db),
                "custody": str(escaped_custody),
                "files": [
                    "audit.db-wal",
                    "audit.db-shm",
                    "audit.db-journal",
                    "audit.db",
                ],
                "identities": {"audit.db": _identity(audit_db)},
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    marker.chmod(0o600)

    completed = _run_quarantine(
        program,
        data_dir=data_dir,
        backup_dir=backup_dir,
        audit_db=audit_db,
        backup_root=backup_root,
        preflight_identity="",
    )

    assert completed.returncode != 0
    assert "audit recovery custody escapes the backup root" in completed.stderr
    assert audit_db.read_bytes() == original
    assert not list(escaped_custody.iterdir())
    assert marker.exists()
