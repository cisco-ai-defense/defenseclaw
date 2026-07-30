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
import shutil
import subprocess
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
import yaml
from defenseclaw import config as config_module
from defenseclaw import file_permissions, migrations
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


def test_open_regular_file_no_follow_requests_binary_mode(monkeypatch, tmp_path):
    target = tmp_path / "target"
    target.write_bytes(b"line one\r\nline two\r\n")
    real_open = os.open
    native_binary_flag = getattr(os, "O_BINARY", 0)
    binary_flag = native_binary_flag or 0x8000
    observed_flags: list[int] = []

    monkeypatch.setattr(file_permissions.os, "O_BINARY", binary_flag, raising=False)

    def record_open(path, flags, *args, **kwargs):
        observed_flags.append(flags)
        native_flags = flags if native_binary_flag else flags & ~binary_flag
        return real_open(path, native_flags, *args, **kwargs)

    monkeypatch.setattr(file_permissions.os, "open", record_open)

    descriptor = file_permissions.open_regular_file_no_follow(target)
    try:
        assert os.read(descriptor, 1024) == b"line one\r\nline two\r\n"
    finally:
        os.close(descriptor)

    assert observed_flags[0] & binary_flag


def test_read_regular_file_no_follow_rejects_same_object_overwrite(monkeypatch, tmp_path):
    if os.name == "nt":
        pytest.skip("Windows denies retained writers with a native share-mode lease")
    target = tmp_path / "mutable"
    target.write_bytes(b"a" * (128 * 1024))
    mutator = target.open("r+b", buffering=0)
    real_read = os.read
    mutated = False

    def read_then_mutate(fd, size):
        nonlocal mutated
        chunk = real_read(fd, size)
        if not mutated:
            mutated = True
            mutator.seek(0)
            mutator.write(b"b" * (128 * 1024))
            mutator.flush()
            os.fsync(mutator.fileno())
        return chunk

    monkeypatch.setattr(file_permissions.os, "read", read_then_mutate)
    try:
        with pytest.raises(file_permissions.UnsafePathError, match="changed while reading"):
            file_permissions.read_regular_file_no_follow(target, max_bytes=128 * 1024)
    finally:
        mutator.close()


@pytest.mark.skipif(os.name != "nt", reason="native Windows share-mode regression")
def test_read_regular_file_no_follow_rejects_retained_windows_writer(tmp_path):
    target = tmp_path / "mutable"
    original = b"same-length-original"
    replacement = b"same-length-mutated!"
    assert len(original) == len(replacement)
    target.write_bytes(original)

    writer = target.open("r+b", buffering=0)
    try:
        writer.write(replacement)
        writer.flush()
        os.fsync(writer.fileno())
        with pytest.raises(OSError):
            file_permissions.read_regular_file_no_follow(target, max_bytes=1024)
    finally:
        writer.close()

    assert file_permissions.read_regular_file_no_follow(target, max_bytes=1024) == replacement


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
        monkeypatch.setattr(file_permissions, "replace_file_durable", fail)

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
    target = parent / "state.json"
    staging = parent / ".state.json.new"
    assert len(os.fspath(target)) > 260
    # The validator itself may not be long-path-aware at the process manifest
    # level. Use the explicit Win32 namespace to create and inspect the
    # fixture; replace_file_durable must provide that same support internally.
    extended_parent = Path(file_permissions._windows_extended_path(parent))
    extended_target = Path(file_permissions._windows_extended_path(target))
    extended_staging = Path(file_permissions._windows_extended_path(staging))
    extended_root = Path(
        file_permissions._windows_extended_path(tmp_path / "durable-segment-00")
    )
    try:
        extended_parent.mkdir(parents=True)
        extended_target.write_bytes(b"old")
        extended_staging.write_bytes(b"new")

        file_permissions.replace_file_durable(staging, target)

        assert extended_target.read_bytes() == b"new"
        assert not extended_staging.exists()
    finally:
        if extended_root.exists():
            shutil.rmtree(extended_root)


def test_posix_file_mode_still_uses_descriptor_api(monkeypatch):
    calls: list[tuple[int, int]] = []
    fake_os = SimpleNamespace(
        name="posix",
        fchmod=lambda fd, mode: calls.append((fd, mode)),
        chmod=lambda *_args: pytest.fail("path chmod must not replace POSIX fchmod"),
    )
    monkeypatch.setattr(file_permissions, "os", fake_os)
    monkeypatch.setattr(file_permissions.sys, "platform", "linux")

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
        (
            "migrations",
            lambda path: migrations._atomic_write_text(
                os.fspath(path),
                "secret\n",
                mode=0o600,
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

    monkeypatch.setattr(
        file_permissions,
        "windows_acl_confidentiality_error",
        lambda _path: next(problems),
    )
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
        "windows_acl_confidentiality_error",
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
        "windows_acl_confidentiality_error",
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


def test_windows_confidentiality_rejects_read_only_untrusted_sid(monkeypatch):
    current_sid = "S-1-5-21-current"
    fake_os = SimpleNamespace(name="nt", fspath=os.fspath)
    entries = [
        (0x80000000, 1, 0, "S-1-5-32-545"),  # BUILTIN\Users: GENERIC_READ
    ]
    monkeypatch.setattr(file_permissions, "os", fake_os)
    monkeypatch.setattr(
        file_permissions,
        "_windows_acl_snapshot",
        lambda _path: (current_sid, False, entries),
    )
    monkeypatch.setattr(file_permissions, "_windows_current_user_sid", lambda: current_sid)

    # The existing integrity-only validator accepts this ACL; the
    # confidentiality validator must not.
    assert file_permissions.windows_acl_write_error("synthetic.env") is None
    problem = file_permissions.windows_acl_confidentiality_error("synthetic.env")

    assert problem == "ACL grants read access to untrusted SID S-1-5-32-545"


@pytest.mark.parametrize(
    "owner_sid",
    [
        "S-1-5-18",
        "S-1-5-32-544",
        "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
    ],
)
def test_windows_custody_accepts_system_owners(monkeypatch, owner_sid):
    current_sid = "S-1-5-21-current"
    fake_os = SimpleNamespace(name="nt", fspath=os.fspath)
    entries = [
        (0x10000000, 1, 0, owner_sid),
        (0x10000000, 1, 0, "S-1-5-18"),
        (0x10000000, 1, 0, "S-1-5-32-544"),
    ]
    monkeypatch.setattr(file_permissions, "os", fake_os)
    monkeypatch.setattr(
        file_permissions,
        "_windows_acl_snapshot",
        lambda _path: (owner_sid, False, entries),
    )
    monkeypatch.setattr(file_permissions, "_windows_current_user_sid", lambda: current_sid)

    assert (
        file_permissions.windows_acl_custody_write_error(
            "synthetic-system-path",
            allow_current_user=False,
        )
        is None
    )


def test_windows_custody_distinguishes_user_and_system_paths(monkeypatch):
    current_sid = "S-1-5-21-current"
    fake_os = SimpleNamespace(name="nt", fspath=os.fspath)
    entries = [(0x10000000, 1, 0, current_sid)]
    monkeypatch.setattr(file_permissions, "os", fake_os)
    monkeypatch.setattr(
        file_permissions,
        "_windows_acl_snapshot",
        lambda _path: (current_sid, False, entries),
    )
    monkeypatch.setattr(file_permissions, "_windows_current_user_sid", lambda: current_sid)

    assert (
        file_permissions.windows_acl_custody_write_error(
            "synthetic-user-path",
            allow_current_user=True,
        )
        is None
    )
    problem = file_permissions.windows_acl_custody_write_error(
        "synthetic-system-path",
        allow_current_user=False,
    )
    assert problem == f"owner SID {current_sid} is not a trusted custody principal"


def test_windows_runtime_custody_accepts_trusted_system_writers(monkeypatch):
    current_sid = "S-1-5-21-current"
    fake_os = SimpleNamespace(name="nt", fspath=os.fspath)
    entries = [
        (0x10000000, 1, 0, current_sid),
        (0x10000000, 1, 0, "S-1-5-18"),
        (0x10000000, 1, 0, "S-1-5-32-544"),
        (
            0x10000000,
            1,
            0,
            "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
        ),
    ]
    monkeypatch.setattr(file_permissions, "os", fake_os)
    monkeypatch.setattr(
        file_permissions,
        "_windows_acl_snapshot",
        lambda _path: (current_sid, False, entries),
    )
    monkeypatch.setattr(file_permissions, "_windows_current_user_sid", lambda: current_sid)

    assert (
        file_permissions.windows_acl_write_error("synthetic-private-secret")
        == "ACL grants write access to untrusted SID S-1-5-32-544"
    )
    assert (
        file_permissions.windows_acl_custody_write_error(
            "synthetic-runtime-state",
            allow_current_user=True,
            require_current_user_owner=True,
        )
        is None
    )


def test_windows_runtime_custody_requires_current_user_owner(monkeypatch):
    current_sid = "S-1-5-21-current"
    system_sid = "S-1-5-18"
    fake_os = SimpleNamespace(name="nt", fspath=os.fspath)
    monkeypatch.setattr(file_permissions, "os", fake_os)
    monkeypatch.setattr(
        file_permissions,
        "_windows_acl_snapshot",
        lambda _path: (system_sid, False, [(0x10000000, 1, 0, system_sid)]),
    )
    monkeypatch.setattr(file_permissions, "_windows_current_user_sid", lambda: current_sid)

    problem = file_permissions.windows_acl_custody_write_error(
        "synthetic-runtime-state",
        allow_current_user=True,
        require_current_user_owner=True,
    )

    assert problem == f"owner SID {system_sid} is not the current user"


def test_windows_runtime_custody_rejects_untrusted_writer(monkeypatch):
    current_sid = "S-1-5-21-current"
    untrusted_sid = "S-1-5-32-545"
    fake_os = SimpleNamespace(name="nt", fspath=os.fspath)
    monkeypatch.setattr(file_permissions, "os", fake_os)
    monkeypatch.setattr(
        file_permissions,
        "_windows_acl_snapshot",
        lambda _path: (current_sid, False, [(0x10000000, 1, 0, untrusted_sid)]),
    )
    monkeypatch.setattr(file_permissions, "_windows_current_user_sid", lambda: current_sid)

    problem = file_permissions.windows_acl_custody_write_error(
        "synthetic-runtime-state",
        allow_current_user=True,
        require_current_user_owner=True,
    )

    assert problem == f"ACL grants write access to untrusted SID {untrusted_sid}"


@pytest.mark.parametrize(
    ("validator", "kwargs"),
    [
        (file_permissions.windows_acl_write_error, {}),
        (
            file_permissions.windows_acl_custody_write_error,
            {"allow_current_user": True},
        ),
        (
            file_permissions.windows_acl_custody_write_error,
            {
                "allow_current_user": True,
                "require_current_user_owner": True,
            },
        ),
        (file_permissions.windows_acl_confidentiality_error, {}),
    ],
)
def test_windows_user_acl_validators_reject_unresolved_current_sid(
    monkeypatch,
    validator,
    kwargs,
):
    fake_os = SimpleNamespace(name="nt", fspath=os.fspath)
    monkeypatch.setattr(file_permissions, "os", fake_os)
    monkeypatch.setattr(
        file_permissions,
        "_windows_acl_snapshot",
        lambda _path: ("", False, [(0x10000000, 1, 0, "")]),
    )
    monkeypatch.setattr(file_permissions, "_windows_current_user_sid", lambda: "")

    assert validator("synthetic-user-path", **kwargs) == "current user SID could not be resolved"


def test_windows_system_custody_does_not_require_current_sid(monkeypatch):
    system_sid = "S-1-5-18"
    fake_os = SimpleNamespace(name="nt", fspath=os.fspath)
    monkeypatch.setattr(file_permissions, "os", fake_os)
    monkeypatch.setattr(
        file_permissions,
        "_windows_acl_snapshot",
        lambda _path: (system_sid, False, [(0x10000000, 1, 0, system_sid)]),
    )
    current_sid = Mock(side_effect=AssertionError("system custody must not query the current SID"))
    monkeypatch.setattr(file_permissions, "_windows_current_user_sid", current_sid)

    assert (
        file_permissions.windows_acl_custody_write_error(
            "synthetic-system-path",
            allow_current_user=False,
        )
        is None
    )
    current_sid.assert_not_called()


@pytest.mark.parametrize(
    ("validator", "kwargs"),
    [
        (file_permissions.windows_acl_write_error, {}),
        (
            file_permissions.windows_acl_custody_write_error,
            {"allow_current_user": True},
        ),
        (
            file_permissions.windows_acl_custody_write_error,
            {
                "allow_current_user": True,
                "require_current_user_owner": True,
            },
        ),
        (file_permissions.windows_acl_confidentiality_error, {}),
    ],
)
def test_windows_user_acl_validators_reject_sid_resolution_error(
    monkeypatch,
    validator,
    kwargs,
):
    current_sid = "S-1-5-21-current"
    fake_os = SimpleNamespace(name="nt", fspath=os.fspath)
    monkeypatch.setattr(file_permissions, "os", fake_os)
    monkeypatch.setattr(
        file_permissions,
        "_windows_acl_snapshot",
        lambda _path: (current_sid, False, [(0x10000000, 1, 0, current_sid)]),
    )
    monkeypatch.setattr(
        file_permissions,
        "_windows_current_user_sid",
        Mock(side_effect=OSError("token lookup failed")),
    )

    assert validator("synthetic-user-path", **kwargs) == "current user SID could not be resolved"


def test_windows_required_access_rejects_sid_resolution_error(monkeypatch):
    current_sid = "S-1-5-21-current"
    fake_os = SimpleNamespace(name="nt", fspath=os.fspath)
    monkeypatch.setattr(file_permissions, "os", fake_os)
    monkeypatch.setattr(
        file_permissions,
        "_windows_acl_snapshot",
        lambda _path: (current_sid, False, [(0x10000000, 1, 0, current_sid)]),
    )
    monkeypatch.setattr(
        file_permissions,
        "_windows_current_user_sid",
        Mock(side_effect=OSError("token lookup failed")),
    )

    assert file_permissions._windows_acl_has_required_access("synthetic-user-path") is False


def test_windows_confidentiality_accepts_owner_and_system_only(monkeypatch):
    current_sid = "S-1-5-21-current"
    fake_os = SimpleNamespace(name="nt", fspath=os.fspath)
    entries = [
        (0x10000000, 1, 0, current_sid),
        (0x10000000, 1, 0, "S-1-5-18"),
        (0x10000000, 1, 0, "S-1-3-4"),
    ]
    monkeypatch.setattr(file_permissions, "os", fake_os)
    monkeypatch.setattr(
        file_permissions,
        "_windows_acl_snapshot",
        lambda _path: (current_sid, False, entries),
    )
    monkeypatch.setattr(file_permissions, "_windows_current_user_sid", lambda: current_sid)
    monkeypatch.setattr(file_permissions, "_windows_acl_has_required_access", lambda _path: True)

    assert file_permissions.windows_acl_confidentiality_error("synthetic.env") is None


def test_windows_confidentiality_ignores_inherit_only_grant(monkeypatch):
    current_sid = "S-1-5-21-current"
    fake_os = SimpleNamespace(name="nt", fspath=os.fspath)
    entries = [
        (0x10000000, 1, 0, current_sid),
        (0x10000000, 1, 0, "S-1-5-18"),
        (0x80000000, 1, 0x08, "S-1-1-0"),
    ]
    monkeypatch.setattr(file_permissions, "os", fake_os)
    monkeypatch.setattr(
        file_permissions,
        "_windows_acl_snapshot",
        lambda _path: (current_sid, False, entries),
    )
    monkeypatch.setattr(file_permissions, "_windows_current_user_sid", lambda: current_sid)
    monkeypatch.setattr(file_permissions, "_windows_acl_has_required_access", lambda _path: True)

    assert file_permissions.windows_acl_confidentiality_error("synthetic.env") is None


def test_windows_confidentiality_reports_uninspectable_acl(monkeypatch):
    fake_os = SimpleNamespace(name="nt", fspath=os.fspath)
    monkeypatch.setattr(file_permissions, "os", fake_os)
    monkeypatch.setattr(
        file_permissions,
        "_windows_acl_snapshot",
        lambda _path: (_ for _ in ()).throw(OSError("access denied")),
    )

    problem = file_permissions.windows_acl_confidentiality_error("synthetic.env")

    assert problem == "cannot read Windows ACL (access denied)"


@pytest.mark.skipif(os.name != "nt", reason="validates native Windows read-only DACL grants")
@pytest.mark.allow_subprocess
def test_windows_confidentiality_rejects_native_everyone_read_grant(tmp_path):
    target = tmp_path / "readable-secret.env"
    target.write_text("SECRET=synthetic\n", encoding="utf-8")
    file_permissions._set_windows_owner_only_acl(os.fspath(target), set_owner=True)
    assert file_permissions.windows_acl_confidentiality_error(target) is None

    grant_everyone(target, "R")

    assert file_permissions.windows_acl_write_error(target) is None
    problem = file_permissions.windows_acl_confidentiality_error(target)
    assert problem == "ACL grants read access to untrusted SID S-1-1-0"


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
