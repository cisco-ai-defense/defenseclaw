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

from tests.permissions import (
    assert_owner_only_directory,
    assert_owner_only_file,
    grant_everyone,
    set_known_windows_directory_acl,
)

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


@pytest.fixture(autouse=True)
def _private_windows_tmp_path(tmp_path):
    if os.name == "nt":
        set_known_windows_directory_acl(tmp_path)


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


def test_protect_private_file_rejects_path_replacement(monkeypatch, tmp_path):
    target = tmp_path / "target"
    replacement = tmp_path / "replacement"
    target.write_bytes(b"original")
    replacement.write_bytes(b"replacement")
    real_open = os.open

    def replace_before_open(path, flags, *args, **kwargs):
        os.replace(replacement, target)
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", replace_before_open)

    with pytest.raises(file_permissions.UnsafePathError, match="changed while opening"):
        file_permissions.protect_private_file(target)


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
        if module is file_permissions:
            monkeypatch.setattr(file_permissions, "replace_file_durable", fail)
        elif module is setup_writer:
            monkeypatch.setattr(setup_writer, "replace_file_durable", fail)
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
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("injected permission failure")),
    )

    target = tmp_path / "migration-secret.yaml"
    assert migrations._atomic_write_text(os.fspath(target), "secret\n", mode=0o600) is False
    _assert_staging_cleanup(record)


def test_durable_replace_commits_complete_sibling_file(tmp_path):
    target = tmp_path / "state.json"
    staging = tmp_path / ".state.json.new"
    target.write_bytes(b"old")
    staging.write_bytes(b"new-complete-payload")

    file_permissions.replace_file_durable(staging, target)

    assert target.read_bytes() == b"new-complete-payload"
    assert not staging.exists()


def test_durable_delete_removes_live_name_and_tombstone(tmp_path):
    target = tmp_path / "legacy-runtime.json"
    target.write_bytes(b"legacy")

    file_permissions.delete_file_durable(target)

    assert not target.exists()
    assert list(tmp_path.glob(".legacy-runtime.json.deleted.*")) == []


@pytest.mark.skipif(os.name != "nt", reason="write-through delete tombstones are Windows-specific")
def test_windows_durable_delete_reports_retained_tombstone(monkeypatch, tmp_path):
    target = tmp_path / "legacy-runtime.json"
    target.write_bytes(b"legacy")
    real_unlink = os.unlink

    def reject_tombstone(path):
        if ".deleted." in os.path.basename(os.fspath(path)):
            raise PermissionError("injected tombstone retention")
        return real_unlink(path)

    monkeypatch.setattr(file_permissions.os, "unlink", reject_tombstone)
    with pytest.raises(OSError, match="removed live path but could not delete durable tombstone") as caught:
        file_permissions.delete_file_durable(target)

    retained = list(tmp_path.glob(".legacy-runtime.json.deleted.*"))
    assert not target.exists()
    assert len(retained) == 1
    assert os.fspath(retained[0]) in str(caught.value)


@pytest.mark.skipif(os.name != "nt", reason="native long-path contract is Windows-specific")
def test_windows_durable_replace_supports_path_beyond_max_path(tmp_path):
    parent = tmp_path
    for index in range(18):
        parent /= f"durable-segment-{index:02d}"
    parent.mkdir(parents=True)
    target = parent / "state.json"
    staging = parent / ".state.json.new"
    assert len(os.fspath(target)) > 260
    target.write_bytes(b"old")
    staging.write_bytes(b"new")

    file_permissions.replace_file_durable(staging, target)

    assert target.read_bytes() == b"new"
    assert not staging.exists()


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
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("injected permission failure")),
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
        file_permissions._windows_acl_snapshot(os.fspath(parent)) if os.name == "nt" else parent.stat().st_mode & 0o777
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


def test_config_lock_secures_parent_before_creating_lock(monkeypatch, tmp_path):
    parent = tmp_path / "elevated-profile" / ".defenseclaw"
    config_path = parent / "config.yaml"
    secured: list[str] = []

    def secure_directory(path):
        secured.append(os.path.abspath(os.fspath(path)))
        os.makedirs(path, exist_ok=True)

    monkeypatch.setattr(config_module, "make_private_directory", secure_directory)

    with config_module.locked_config_yaml(os.fspath(config_path)):
        assert (parent / "config.yaml.lock").is_file()

    assert secured == [os.path.abspath(os.fspath(parent))]


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
    set_known_windows_directory_acl(broad_dir)
    grant_everyone(broad_dir, "(RX)")
    target = broad_dir / "secret.yaml"

    result = write(target)

    if name == "migrations":
        assert result is True
    assert target.is_file()
    assert_owner_only_file(target)


@pytest.mark.skipif(os.name != "nt", reason="validates native Windows directory read/traverse ACLs")
@pytest.mark.allow_subprocess
def test_owner_only_directory_assertion_rejects_untrusted_read_access(tmp_path):
    directory = tmp_path / "readable-directory"
    directory.mkdir()
    set_known_windows_directory_acl(directory)
    grant_everyone(directory, "RX")

    with pytest.raises(AssertionError, match="untrusted SID"):
        assert_owner_only_directory(directory)


@pytest.mark.skipif(os.name != "nt", reason="validates native Windows DACL preservation")
@pytest.mark.allow_subprocess
def test_private_atomic_rewrite_preserves_stricter_existing_windows_dacl(tmp_path):
    target = tmp_path / "stricter ACL 雪.json"
    target.write_text("old", encoding="utf-8")
    file_permissions._set_windows_current_user_owner(os.fspath(target))
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


@pytest.mark.skipif(os.name != "nt", reason="validates protected Windows DACL copying")
@pytest.mark.allow_subprocess
def test_copy_windows_dacl_protects_destination_from_parent_inheritance(tmp_path):
    source = tmp_path / "source.json"
    source.write_text("source", encoding="utf-8")
    file_permissions._set_windows_owner_only_acl(os.fspath(source), set_owner=True)

    broad_dir = tmp_path / "broad-parent"
    broad_dir.mkdir()
    set_known_windows_directory_acl(broad_dir)
    grant_everyone(broad_dir)
    destination = broad_dir / "destination.json"
    destination.write_text("destination", encoding="utf-8")
    file_permissions._set_windows_current_user_owner(os.fspath(destination))
    assert file_permissions._windows_dacl_is_protected(destination) is False

    file_permissions.copy_windows_dacl(os.fspath(source), os.fspath(destination))

    assert file_permissions._windows_dacl_is_protected(destination)
    assert file_permissions._windows_acl_has_required_access(destination)


def test_windows_post_replace_verification_repairs_target(monkeypatch, tmp_path):
    target = tmp_path / "repair.json"
    target.write_bytes(b"sensitive")
    problems = iter(["untrusted write grant", None])
    repaired: list[str] = []

    monkeypatch.setattr(file_permissions, "windows_acl_write_error", lambda _path: next(problems))
    monkeypatch.setattr(file_permissions, "_windows_acl_has_required_access", lambda _path: True)
    monkeypatch.setattr(file_permissions, "_set_windows_owner_only_acl", repaired.append)

    file_permissions._verify_or_repair_windows_private_target(os.fspath(target))

    assert repaired == [os.fspath(target)]
    assert target.read_bytes() == b"sensitive"


def test_windows_post_replace_verification_removes_unrepairable_target(monkeypatch, tmp_path):
    target = tmp_path / "unsafe.json"
    target.write_bytes(b"sensitive")

    monkeypatch.setattr(
        file_permissions,
        "windows_acl_write_error",
        lambda _path: "untrusted read grant",
    )
    monkeypatch.setattr(
        file_permissions,
        "_set_windows_owner_only_acl",
        lambda _path: (_ for _ in ()).throw(OSError("access denied")),
    )

    with pytest.raises(OSError, match="repair failed: access denied"):
        file_permissions._verify_or_repair_windows_private_target(os.fspath(target))

    assert not target.exists()


def test_windows_post_replace_inspection_error_removes_target(monkeypatch, tmp_path):
    target = tmp_path / "unverifiable.json"
    target.write_bytes(b"sensitive")

    monkeypatch.setattr(
        file_permissions,
        "windows_acl_write_error",
        lambda _path: (_ for _ in ()).throw(OSError("inspection denied")),
    )
    monkeypatch.setattr(
        file_permissions,
        "_set_windows_owner_only_acl",
        lambda _path: (_ for _ in ()).throw(OSError("repair denied")),
    )

    with pytest.raises(OSError, match="ACL inspection failed: inspection denied"):
        file_permissions._verify_or_repair_windows_private_target(os.fspath(target))

    assert not target.exists()


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


def test_private_directory_creation_descriptor_names_current_owner(monkeypatch):
    owner = "S-1-5-21-1000-1001-1002-1003"
    monkeypatch.setattr(file_permissions, "_windows_current_user_sid", lambda: owner)

    descriptor = file_permissions._windows_private_directory_sddl()

    assert descriptor.startswith(f"O:{owner}D:P")
    assert "(A;OICI;FA;;;OW)" in descriptor
    assert "(A;OICI;FA;;;SY)" in descriptor


@pytest.mark.skipif(os.name != "nt", reason="validates native Windows directory inheritance")
def test_private_directory_keeps_existing_managed_venv_accessible(tmp_path):
    private_home = tmp_path / "private-home"
    managed_venv = private_home / ".venv"
    managed_venv.mkdir(parents=True)
    existing = managed_venv / "existing.txt"
    existing.write_text("before", encoding="utf-8")
    set_known_windows_directory_acl(private_home)

    file_permissions.make_private_directory(private_home)

    assert existing.read_text(encoding="utf-8") == "before"
    created = managed_venv / "created-after-hardening.txt"
    created.write_text("after", encoding="utf-8")
    assert created.read_text(encoding="utf-8") == "after"
    assert file_permissions.windows_acl_write_error(private_home) is None


@pytest.mark.skipif(os.name != "nt", reason="validates native Windows directory-swap lock")
def test_private_atomic_write_holds_parent_against_directory_swap(tmp_path):
    parent = tmp_path / "managed"
    parent.mkdir()
    if os.name == "nt":
        set_known_windows_directory_acl(parent)
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
