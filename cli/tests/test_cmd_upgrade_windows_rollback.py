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

import hashlib
import os
import struct
from pathlib import Path

import pytest
from defenseclaw import bundle_refresh, windows_acl
from defenseclaw.commands import cmd_upgrade
from defenseclaw.windows_acl import WindowsFileSecurity

ORIGINAL = WindowsFileSecurity(owner=b"original-owner", dacl=b"original-dacl", dacl_protected=False)
PRIVATE = WindowsFileSecurity(owner=b"private-owner", dacl=b"private-dacl", dacl_protected=True)
DRIFTED = WindowsFileSecurity(owner=b"attacker-owner", dacl=b"drifted-dacl", dacl_protected=False)
INHERITABLE_PRIVATE = WindowsFileSecurity(
    owner=b"private-owner",
    dacl=b"inheritable-private-dacl",
    dacl_protected=True,
)
_HIGH_LABEL_SID = b"\x01\x01" + (16).to_bytes(6, "big") + (0x3000).to_bytes(4, "little")
_HIGH_LABEL_ACE = struct.pack("<BBHI", 0x11, 0, 8 + len(_HIGH_LABEL_SID), 0x00000003) + _HIGH_LABEL_SID
HIGH_MANDATORY_LABEL = struct.pack("<BBHHH", 2, 0, 8 + len(_HIGH_LABEL_ACE), 1, 0) + _HIGH_LABEL_ACE
LABELED = WindowsFileSecurity(
    owner=b"labeled-owner",
    dacl=b"labeled-dacl",
    dacl_protected=True,
    mandatory_label=HIGH_MANDATORY_LABEL,
    sacl_protected=True,
)


class _FakeWindowsFiles:
    def __init__(self) -> None:
        self.security: dict[str, WindowsFileSecurity] = {}
        self.drift_once: str | None = None

    @staticmethod
    def _key(path: str | os.PathLike[str]) -> str:
        return os.path.abspath(os.fspath(path))

    def write_new_file(self, path: str, payload: bytes, security: WindowsFileSecurity) -> None:
        key = self._key(path)
        with open(key, "xb") as stream:
            stream.write(payload)
        self.security[key] = security.staging_copy()

    def apply_path(self, path: str, security: WindowsFileSecurity, **_kwargs: object) -> None:
        self.security[self._key(path)] = security

    def capture_path(self, path: str, **_kwargs: object) -> WindowsFileSecurity:
        key = self._key(path)
        if key == self.drift_once:
            self.drift_once = None
            return DRIFTED
        return self.security[key]

    def move_file_no_replace(self, source: str, target: str) -> None:
        source_key = self._key(source)
        target_key = self._key(target)
        if os.path.lexists(target_key):
            raise OSError("target exists")
        os.rename(source_key, target_key)
        self.security[target_key] = self.security.pop(source_key)


def _patch_windows_files(monkeypatch: pytest.MonkeyPatch, fake: _FakeWindowsFiles) -> None:
    monkeypatch.setattr(windows_acl, "write_new_file", fake.write_new_file)
    monkeypatch.setattr(windows_acl, "apply_path", fake.apply_path)
    monkeypatch.setattr(windows_acl, "capture_path", fake.capture_path)
    monkeypatch.setattr(windows_acl, "move_file_no_replace", fake.move_file_no_replace)


def test_windows_hard_cut_security_round_trips_label_and_accepts_legacy(tmp_path: Path) -> None:
    snapshot = cmd_upgrade._RollbackFileSnapshot(
        active_path=str(tmp_path / "config.yaml"),
        backup_path=str(tmp_path / "config.source"),
        existed=True,
        sha256="0" * 64,
        mode=0o600,
        windows_security=LABELED,
    )

    encoded = cmd_upgrade._snapshot_to_recovery_json(snapshot)
    decoded = cmd_upgrade._snapshot_from_recovery_json(encoded)

    security_raw = encoded["windows_security"]
    assert isinstance(security_raw, dict)
    assert security_raw["mandatory_label"] is not None
    assert security_raw["sacl_protected"] is True
    assert decoded.windows_security == LABELED

    legacy = dict(encoded)
    legacy_security = dict(security_raw)
    legacy_security.pop("mandatory_label")
    legacy_security.pop("sacl_protected")
    legacy["windows_security"] = legacy_security
    legacy_decoded = cmd_upgrade._snapshot_from_recovery_json(legacy)
    assert legacy_decoded.windows_security == WindowsFileSecurity(
        LABELED.owner,
        LABELED.dacl,
        LABELED.dacl_protected,
    )

    partial = dict(encoded)
    partial_security = dict(security_raw)
    partial_security.pop("sacl_protected")
    partial["windows_security"] = partial_security
    with pytest.raises(OSError, match="Windows security is invalid"):
        cmd_upgrade._snapshot_from_recovery_json(partial)


def test_windows_bundle_security_round_trips_mandatory_label() -> None:
    encoded = bundle_refresh._serialize_windows_security(LABELED)

    decoded = cmd_upgrade._parse_bundle_windows_security(
        {"managed/member.yaml": encoded},
        {"managed/member.yaml"},
    )

    assert decoded == {"managed/member.yaml": LABELED}


@pytest.mark.parametrize("name", ["config.yaml", ".env", ".migration_state.json"])
def test_windows_hard_cut_rollback_restores_exact_bytes_owner_and_dacl(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    name: str,
) -> None:
    fake = _FakeWindowsFiles()
    _patch_windows_files(monkeypatch, fake)
    active = tmp_path / name
    backup = tmp_path / f"{name}.source"
    active.write_bytes(b"failed-target-state")
    backup.write_bytes(b"exact-source-state")
    fake.security[str(active)] = DRIFTED
    snapshot = cmd_upgrade._RollbackFileSnapshot(
        active_path=str(active),
        backup_path=str(backup),
        existed=True,
        sha256=hashlib.sha256(b"exact-source-state").hexdigest(),
        mode=None,
        windows_security=ORIGINAL,
    )

    cmd_upgrade._restore_windows_rollback_file(snapshot)

    assert active.read_bytes() == b"exact-source-state"
    assert fake.capture_path(str(active)) == ORIGINAL
    assert not list(tmp_path.glob(f".{name}.hard-cut-*"))


def test_windows_hard_cut_rollback_recovers_from_post_publish_dacl_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _FakeWindowsFiles()
    _patch_windows_files(monkeypatch, fake)
    active = tmp_path / "config.yaml"
    backup = tmp_path / "config.source"
    active.write_bytes(b"failed-target-state")
    backup.write_bytes(b"exact-source-state")
    fake.security[str(active)] = DRIFTED
    fake.drift_once = str(active)
    snapshot = cmd_upgrade._RollbackFileSnapshot(
        active_path=str(active),
        backup_path=str(backup),
        existed=True,
        sha256=hashlib.sha256(b"exact-source-state").hexdigest(),
        mode=None,
        windows_security=ORIGINAL,
    )

    cmd_upgrade._restore_windows_rollback_file(snapshot)

    assert active.read_bytes() == b"exact-source-state"
    assert fake.capture_path(str(active)) == ORIGINAL
    assert not list(tmp_path.glob(".config.yaml.hard-cut-*"))


def test_windows_capture_uses_exact_handle_and_private_backup_before_return(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    active = tmp_path / ".env"
    backup = tmp_path / "environment.source"
    active.write_bytes(b"SECRET=source\n")
    captured_descriptors: list[int] = []
    backup_security: dict[str, WindowsFileSecurity] = {}
    timestamp_skew_observed = False

    class _WindowsOsProxy:
        name = "nt"

        def lstat(self, path: str | os.PathLike[str]):
            nonlocal timestamp_skew_observed
            info = os.lstat(path)
            if os.path.abspath(path) != os.path.abspath(active):
                return info
            timestamp_skew_observed = True

            class _TimestampSkewedStat:
                st_mtime_ns = info.st_mtime_ns + 1
                st_ctime_ns = info.st_ctime_ns + 1

                def __getattr__(self, name: str):
                    return getattr(info, name)

            return _TimestampSkewedStat()

        def __getattr__(self, name: str):
            return getattr(os, name)

    def capture_fd(descriptor: int) -> WindowsFileSecurity:
        captured_descriptors.append(descriptor)
        position = os.lseek(descriptor, 0, os.SEEK_CUR)
        os.lseek(descriptor, 0, os.SEEK_SET)
        assert os.read(descriptor, 6) == b"SECRET"
        os.lseek(descriptor, position, os.SEEK_SET)
        return ORIGINAL

    def write_new_file(path: str, payload: bytes, security: WindowsFileSecurity) -> None:
        Path(path).write_bytes(payload)
        backup_security[path] = security.staging_copy()

    monkeypatch.setattr(cmd_upgrade, "os", _WindowsOsProxy())
    monkeypatch.setattr(windows_acl, "capture_fd", capture_fd)
    monkeypatch.setattr(windows_acl, "private_security_for_directory", lambda _path: PRIVATE)
    monkeypatch.setattr(windows_acl, "write_new_file", write_new_file)

    snapshot = cmd_upgrade._capture_rollback_file(str(active), str(backup), required=True)

    assert timestamp_skew_observed
    assert captured_descriptors
    assert snapshot.windows_security == ORIGINAL
    assert snapshot.sha256 == hashlib.sha256(b"SECRET=source\n").hexdigest()
    assert backup.read_bytes() == b"SECRET=source\n"
    assert backup_security[str(backup)] == PRIVATE


def test_windows_upgrade_backup_directories_get_inheritable_private_dacl_before_use(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "backups"
    root.mkdir()
    applied: dict[str, WindowsFileSecurity] = {}
    inheritance_requests: list[bool] = []

    def private_security(_path: str, *, inherit_children: bool = False) -> WindowsFileSecurity:
        inheritance_requests.append(inherit_children)
        return INHERITABLE_PRIVATE

    def apply_path(path: str, security: WindowsFileSecurity, **_kwargs: object) -> None:
        applied[os.path.abspath(path)] = security

    def capture_path(path: str, **_kwargs: object) -> WindowsFileSecurity:
        return applied[os.path.abspath(path)]

    monkeypatch.setattr(windows_acl, "private_security_for_directory", private_security)
    monkeypatch.setattr(windows_acl, "apply_path", apply_path)
    monkeypatch.setattr(windows_acl, "capture_path", capture_path)

    created = cmd_upgrade._create_private_windows_backup_directory(str(root), "20260710T120000")

    assert Path(created).is_dir()
    assert inheritance_requests == [True]
    assert applied[str(root)] == INHERITABLE_PRIVATE
    assert applied[created] == INHERITABLE_PRIVATE


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows owner/DACL APIs")
def test_native_windows_hard_cut_rollback_restores_exact_owner_and_dacl(tmp_path: Path) -> None:
    active = tmp_path / "config.yaml"
    backup = tmp_path / "config.source"
    active.write_bytes(b"config_version: 7\n")
    backup.write_bytes(b"config_version: 7\n")
    private = windows_acl.private_security_for_directory(str(tmp_path))
    windows_acl.apply_path(str(active), private)
    original = windows_acl.capture_path(str(active))

    active.write_bytes(b"config_version: 8\n")
    snapshot = cmd_upgrade._RollbackFileSnapshot(
        active_path=str(active),
        backup_path=str(backup),
        existed=True,
        sha256=hashlib.sha256(b"config_version: 7\n").hexdigest(),
        mode=None,
        windows_security=original,
    )

    cmd_upgrade._restore_windows_rollback_file(snapshot)

    assert active.read_bytes() == b"config_version: 7\n"
    assert windows_acl.capture_path(str(active)) == original
    assert not list(tmp_path.glob(".config.yaml.hard-cut-*"))
