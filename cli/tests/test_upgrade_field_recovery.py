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
import stat
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
RESOLVER = ROOT / "scripts" / "upgrade.sh"

pytestmark = pytest.mark.skipif(
    os.name == "nt",
    reason="release-owned resolver field recovery is POSIX-only",
)


def _embedded_python(after: str) -> str:
    source = RESOLVER.read_text(encoding="utf-8")
    start = source.index(after)
    heredoc = source.index("<<'PY'", start)
    body = source.index("\n", heredoc) + 1
    end = source.index("\nPY\n", body)
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
    data_dir: Path,
    backup_dir: Path,
    audit_db: Path,
    backup_root: Path,
    preflight_identity: str,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
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


def _identity(path: Path) -> dict[str, int]:
    info = path.lstat()
    return {
        "device": info.st_dev,
        "inode": info.st_ino,
        "size": info.st_size,
        "mtime_ns": info.st_mtime_ns,
    }


def test_corrupt_custom_audit_store_moves_exact_bytes_to_private_custody(tmp_path: Path) -> None:
    program = _embedded_python("quarantine_corrupt_audit_store() {")
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
    assert (custody / "audit.db-shm").is_file()
    assert stat.S_IMODE(custody.stat().st_mode) == 0o700
    assert not audit_db.exists()
    assert not (data_dir / ".audit-recovery.json").exists()


def test_audit_custody_resumes_cross_controller_from_recorded_identities(tmp_path: Path) -> None:
    program = _embedded_python("quarantine_corrupt_audit_store() {")
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


def test_missing_hard_cut_cursor_replays_real_migration_not_bootstrap(tmp_path: Path) -> None:
    program = _embedded_python("repair_hard_cut_migration_cursor() {")
    data_dir = _private_dir(tmp_path / "data")
    config = data_dir / "config.yaml"
    config.write_text(
        f"config_version: 8\ndata_dir: {data_dir}\nobservability: {{}}\n",
        encoding="utf-8",
    )
    config.chmod(0o600)
    cursor = data_dir / ".migration_state.json"
    applied = ["0.3.0", "0.4.0", "0.5.0", "0.7.0", "0.8.0"]
    cursor.write_text(
        json.dumps(
            {
                "schema": 1,
                "package_version": "0.8.6",
                "applied": applied,
                "applied_at": {version: "bootstrap" for version in applied},
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    cursor.chmod(0o600)
    openclaw_home = _private_dir(tmp_path / "openclaw")
    environment = os.environ.copy()
    environment.update(
        {
            "DEFENSECLAW_HOME": str(data_dir),
            "DEFENSECLAW_CONFIG": str(config),
        }
    )

    completed = subprocess.run(
        [
            sys.executable,
            "-I",
            "-B",
            "-",
            str(data_dir),
            str(config),
            str(openclaw_home),
            "0.8.6",
            "0",
        ],
        input=program,
        text=True,
        capture_output=True,
        env=environment,
        check=False,
        timeout=30,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    repaired = json.loads(cursor.read_text(encoding="utf-8"))
    assert "0.8.5" in repaired["applied"]
    assert repaired["applied_at"]["0.8.5"] != "bootstrap"


def test_absent_cursor_reconstructs_only_pre_hard_cut_then_runs_real_migration(
    tmp_path: Path,
) -> None:
    program = _embedded_python("repair_hard_cut_migration_cursor() {")
    data_dir = _private_dir(tmp_path / "data")
    config = data_dir / "config.yaml"
    config.write_text(
        f"config_version: 8\ndata_dir: {data_dir}\nobservability: {{}}\n",
        encoding="utf-8",
    )
    config.chmod(0o600)
    openclaw_home = _private_dir(tmp_path / "openclaw")
    completed = subprocess.run(
        [
            sys.executable,
            "-I",
            "-B",
            "-",
            str(data_dir),
            str(config),
            str(openclaw_home),
            "0.8.6",
            "1",
        ],
        input=program,
        text=True,
        capture_output=True,
        env={
            **os.environ,
            "DEFENSECLAW_HOME": str(data_dir),
            "DEFENSECLAW_CONFIG": str(config),
        },
        check=False,
        timeout=30,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    repaired = json.loads((data_dir / ".migration_state.json").read_text(encoding="utf-8"))
    assert repaired["applied"] == ["0.3.0", "0.4.0", "0.5.0", "0.7.0", "0.8.0", "0.8.5"]
    assert repaired["applied_at"]["0.8.5"] != "bootstrap"
