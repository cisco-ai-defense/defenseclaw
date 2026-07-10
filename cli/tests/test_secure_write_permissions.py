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
from defenseclaw import config as config_module
from defenseclaw import file_permissions, migrations

from tests.permissions import assert_owner_only_file

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
def test_migration_writer_replaces_inherited_windows_access(tmp_path):
    broad_dir = tmp_path / "migrations"
    broad_dir.mkdir()
    subprocess.run(
        ["icacls", os.fspath(broad_dir), "/grant", "*S-1-1-0:(OI)(CI)(RX)"],
        check=True,
        capture_output=True,
        text=True,
    )
    target = broad_dir / "secret.yaml"

    result = migrations._atomic_write_text(
        os.fspath(target),
        "secret\n",
        mode=0o600,
    )

    assert result is True
    assert target.is_file()
    assert_owner_only_file(target)
