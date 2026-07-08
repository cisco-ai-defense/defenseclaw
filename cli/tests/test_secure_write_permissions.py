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

"""Cross-platform regressions for secure atomic-write permissions."""

from __future__ import annotations

import os
import subprocess
import tempfile
from types import SimpleNamespace

import pytest
import yaml
from defenseclaw import config as config_module
from defenseclaw import file_permissions, migrations
from defenseclaw.commands import cmd_setup_observability as setup_writer
from defenseclaw.observability import writer as observability_writer
from defenseclaw.webhooks import writer as webhook_writer

from tests.permissions import assert_owner_only_file, grant_everyone, set_known_windows_directory_acl

_ATOMIC_WRITERS = [
    (
        "config",
        file_permissions,
        lambda path: config_module.write_config_yaml_secure(
            os.fspath(path),
            {"data_dir": os.fspath(path.parent)},
        ),
    ),
    (
        "webhooks",
        file_permissions,
        lambda path: webhook_writer._write_yaml(
            os.fspath(path),
            {"webhooks": [{"name": "secure-write"}]},
        ),
    ),
    (
        "setup-observability",
        setup_writer,
        lambda path: setup_writer._write_atomically(
            os.fspath(path),
            {"data_dir": os.fspath(path.parent)},
        ),
    ),
]


def _assert_staging_cleanup(record: dict[str, object]) -> None:
    fd = record["fd"]
    path = record["path"]
    assert isinstance(fd, int)
    assert isinstance(path, str)

    try:
        os.fstat(fd)
    except OSError:
        descriptor_open = False
    else:
        descriptor_open = True

    staging_exists = os.path.exists(path)
    if descriptor_open:
        os.close(fd)
    if staging_exists:
        os.unlink(path)

    assert descriptor_open is False
    assert staging_exists is False


@pytest.mark.parametrize(("_name", "module", "write"), _ATOMIC_WRITERS)
@pytest.mark.parametrize("failure_stage", ["permission", "serialize", "replace"])
def test_atomic_writers_close_and_remove_staging_file_on_failure(
    monkeypatch,
    tmp_path,
    _name,
    module,
    write,
    failure_stage,
):
    record: dict[str, object] = {}
    real_mkstemp = tempfile.mkstemp

    def recording_mkstemp(*args, **kwargs):
        fd, path = real_mkstemp(*args, **kwargs)
        record.update(fd=fd, path=path)
        return fd, path

    monkeypatch.setattr(tempfile, "mkstemp", recording_mkstemp)

    def fail(*_args, **_kwargs):
        raise OSError(f"injected {failure_stage} failure")

    if failure_stage == "permission":
        monkeypatch.setattr(module, "set_file_mode", fail)
    elif failure_stage == "serialize":
        monkeypatch.setattr(yaml, "safe_dump", fail)
    else:
        monkeypatch.setattr(os, "replace", fail)

    target = tmp_path / f"{_name}.yaml"
    target.write_text("ORIGINAL\n", encoding="utf-8")
    with pytest.raises(OSError, match=f"injected {failure_stage} failure"):
        write(target)

    _assert_staging_cleanup(record)
    assert target.read_text(encoding="utf-8") == "ORIGINAL\n"


def test_migration_writer_closes_and_removes_staging_file_when_permissions_fail(
    monkeypatch,
    tmp_path,
):
    record: dict[str, object] = {}
    real_mkstemp = tempfile.mkstemp

    def recording_mkstemp(*args, **kwargs):
        fd, path = real_mkstemp(*args, **kwargs)
        record.update(fd=fd, path=path)
        return fd, path

    monkeypatch.setattr(tempfile, "mkstemp", recording_mkstemp)
    monkeypatch.setattr(
        migrations,
        "set_file_mode",
        lambda *_args: (_ for _ in ()).throw(OSError("injected permission failure")),
    )

    target = tmp_path / "migration-secret.yaml"
    assert migrations._atomic_write_text(os.fspath(target), "secret\n", mode=0o600) is False
    _assert_staging_cleanup(record)


def test_dotenv_writer_closes_descriptor_when_permissions_fail(monkeypatch, tmp_path):
    record: dict[str, int] = {}
    real_open = os.open

    def recording_open(*args, **kwargs):
        fd = real_open(*args, **kwargs)
        record["fd"] = fd
        return fd

    monkeypatch.setattr(os, "open", recording_open)
    monkeypatch.setattr(
        observability_writer,
        "set_file_mode",
        lambda *_args: (_ for _ in ()).throw(OSError("injected permission failure")),
    )

    with pytest.raises(OSError, match="injected permission failure"):
        observability_writer._write_dotenv(os.fspath(tmp_path / ".env"), {"TOKEN": "secret"})

    fd = record["fd"]
    try:
        os.fstat(fd)
    except OSError:
        descriptor_open = False
    else:
        descriptor_open = True
        os.close(fd)
    assert descriptor_open is False


@pytest.mark.parametrize("failure_stage", ["permission", "replace"])
def test_dotenv_writer_preserves_target_and_removes_staging_on_failure(
    monkeypatch,
    tmp_path,
    failure_stage,
):
    record: dict[str, object] = {}
    real_mkstemp = tempfile.mkstemp

    def recording_mkstemp(*args, **kwargs):
        fd, path = real_mkstemp(*args, **kwargs)
        record.update(fd=fd, path=path)
        return fd, path

    def fail(*_args, **_kwargs):
        raise OSError(f"injected {failure_stage} failure")

    monkeypatch.setattr(tempfile, "mkstemp", recording_mkstemp)
    if failure_stage == "permission":
        monkeypatch.setattr(observability_writer, "set_file_mode", fail)
    else:
        monkeypatch.setattr(os, "replace", fail)

    target = tmp_path / ".env"
    target.write_text("ORIGINAL=value\n", encoding="utf-8")

    with pytest.raises(OSError, match=f"injected {failure_stage} failure"):
        observability_writer._write_dotenv(os.fspath(target), {"TOKEN": "secret"})

    _assert_staging_cleanup(record)
    assert target.read_text(encoding="utf-8") == "ORIGINAL=value\n"


def test_posix_file_mode_still_uses_descriptor_api(monkeypatch):
    calls: list[tuple[int, int]] = []
    fake_os = SimpleNamespace(
        name="posix",
        fchmod=lambda fd, mode: calls.append((fd, mode)),
        chmod=lambda *_args: pytest.fail("path chmod must not replace POSIX fchmod"),
    )
    monkeypatch.setattr(file_permissions, "os", fake_os)

    file_permissions.set_file_mode(17, "/tmp/secret", 0o600)

    assert calls == [(17, 0o600)]


def test_private_atomic_write_can_preserve_operator_selected_parent(tmp_path):
    parent = tmp_path / "operator-selected"
    parent.mkdir(mode=0o755)
    if os.name == "nt":
        set_known_windows_directory_acl(parent, everyone_write=False)
        before = file_permissions._windows_acl_snapshot(os.fspath(parent))
    else:
        before = parent.stat().st_mode & 0o777

    target = parent / "private-export.json"
    file_permissions.atomic_write_private_bytes(target, b"synthetic fixture", protect_parent=False)

    after = (
        file_permissions._windows_acl_snapshot(os.fspath(parent))
        if os.name == "nt"
        else parent.stat().st_mode & 0o777
    )
    assert after == before
    assert_owner_only_file(target)


def test_private_atomic_write_rejects_unsafe_unmanaged_parent(tmp_path):
    parent = tmp_path / "unsafe-operator-parent"
    parent.mkdir()
    if os.name == "nt":
        set_known_windows_directory_acl(parent, everyone_write=True)
    else:
        parent.chmod(0o777)
    target = parent / "must-not-exist.json"

    with pytest.raises(OSError, match="unsafe"):
        file_permissions.atomic_write_private_bytes(target, b"synthetic fixture", protect_parent=False)

    assert not target.exists()


def test_shared_atomic_writer_requests_owner_only_mode_for_new_directory(
    monkeypatch,
    tmp_path,
):
    calls: list[tuple[str, int, bool]] = []
    real_makedirs = os.makedirs

    def recording_makedirs(path, mode=0o777, exist_ok=False):
        calls.append((os.fspath(path), mode, exist_ok))
        return real_makedirs(path, mode=mode, exist_ok=exist_ok)

    monkeypatch.setattr(file_permissions.os, "makedirs", recording_makedirs)
    target = tmp_path / "private" / "config.yaml"

    config_module.write_config_yaml_secure(
        os.fspath(target),
        {"data_dir": os.fspath(target.parent)},
    )

    assert calls == [(os.fspath(target.parent), 0o700, True)]


@pytest.mark.skipif(os.name != "nt", reason="validates native Windows DACLs")
@pytest.mark.allow_subprocess
@pytest.mark.parametrize(
    ("name", "write"),
    [
        ("config", _ATOMIC_WRITERS[0][2]),
        ("webhooks", _ATOMIC_WRITERS[1][2]),
        ("setup-observability", _ATOMIC_WRITERS[2][2]),
        (
            "migrations",
            lambda path: migrations._atomic_write_text(
                os.fspath(path),
                "secret\n",
                mode=0o600,
            ),
        ),
        (
            "observability-dotenv",
            lambda path: observability_writer._write_dotenv(
                os.fspath(path),
                {"TOKEN": "secret"},
            ),
        ),
    ],
)
def test_secret_writers_replace_inherited_windows_access(tmp_path, name, write):
    broad_dir = tmp_path / name
    broad_dir.mkdir()
    grant_everyone(broad_dir, "(RX)")
    target = broad_dir / "secret.yaml"

    result = write(target)

    if name == "migrations":
        assert result is True
    assert target.is_file()
    assert_owner_only_file(target)


@pytest.mark.skipif(os.name != "nt", reason="validates native Windows DACL preservation")
@pytest.mark.allow_subprocess
def test_private_atomic_rewrite_preserves_stricter_existing_windows_dacl(tmp_path):
    target = tmp_path / "stricter ACL 雪.json"
    target.write_text("old", encoding="utf-8")
    subprocess.run(
        [
            "icacls",
            os.fspath(target),
            "/inheritance:r",
            "/grant:r",
            "*S-1-3-4:F",
            "*S-1-5-18:R",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    before = file_permissions._windows_acl_snapshot(os.fspath(target))

    file_permissions.atomic_write_private_bytes(target, b"rewritten")

    after = file_permissions._windows_acl_snapshot(os.fspath(target))
    assert after == before
    assert target.read_bytes() == b"rewritten"


@pytest.mark.skipif(os.name != "nt", reason="validates native Windows junction refusal")
@pytest.mark.allow_subprocess
def test_private_atomic_write_refuses_windows_junction_escape(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    junction = tmp_path / "junction"
    result = subprocess.run(
        ["cmd.exe", "/d", "/c", "mklink", "/J", os.fspath(junction), os.fspath(outside)],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        pytest.skip(f"junction creation unavailable: {result.stderr or result.stdout}")
    try:
        with pytest.raises(file_permissions.UnsafePathError, match="reparse point"):
            file_permissions.atomic_write_private_bytes(junction / "escape.json", b"fixture")
        assert list(outside.iterdir()) == []
    finally:
        os.rmdir(junction)


@pytest.mark.skipif(os.name != "nt", reason="validates native Windows deny ACE handling")
@pytest.mark.allow_subprocess
def test_private_atomic_rewrite_does_not_preserve_system_deny_ace(tmp_path):
    target = tmp_path / "denied-system.json"
    target.write_text("old", encoding="utf-8")
    subprocess.run(
        [
            "icacls",
            os.fspath(target),
            "/inheritance:r",
            "/grant:r",
            "*S-1-3-4:F",
            "*S-1-5-18:R",
            "/deny",
            "*S-1-5-18:F",
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    file_permissions.atomic_write_private_bytes(target, b"rewritten")

    assert file_permissions._windows_acl_has_required_access(target)
    _owner, _null, entries = file_permissions._windows_acl_snapshot(os.fspath(target))
    assert not any(mode == 3 and sid == "S-1-5-18" for _mask, mode, _inheritance, sid in entries)


@pytest.mark.skipif(os.name != "nt", reason="validates native Windows ownership policy")
def test_private_directory_refuses_foreign_owner_without_acl_rewrite(monkeypatch):
    monkeypatch.setattr(
        file_permissions,
        "_windows_acl_snapshot",
        lambda _path: ("S-1-5-21-foreign", False, []),
    )
    monkeypatch.setattr(file_permissions, "_windows_current_user_sid", lambda: "S-1-5-21-current")
    monkeypatch.setattr(
        file_permissions,
        "_set_windows_owner_only_acl",
        lambda _path: pytest.fail("foreign-owned directory DACL must not be rewritten"),
    )

    with pytest.raises(OSError, match="foreign-owned"):
        file_permissions._protect_private_directory("synthetic")


@pytest.mark.skipif(os.name != "nt", reason="validates native Windows directory-swap lock")
def test_private_atomic_write_holds_parent_against_directory_swap(tmp_path):
    parent = tmp_path / "managed"
    parent.mkdir()
    moved = tmp_path / "moved"
    swap_refused = False

    def write(fd: int) -> None:
        nonlocal swap_refused
        try:
            os.replace(parent, moved)
        except OSError:
            swap_refused = True
        os.write(fd, b"synthetic fixture")

    target = parent / "state.json"
    file_permissions.atomic_write_private(target, write)

    assert swap_refused is True
    assert target.read_bytes() == b"synthetic fixture"
    assert not moved.exists()
