# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Windows downgrades retain the current controller's recovery checks."""

from __future__ import annotations

import hashlib
import os
import types
from pathlib import Path

import pytest
from defenseclaw import upgrade_shim


@pytest.fixture
def routing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    home = tmp_path / "home"
    home.mkdir()
    staging = tmp_path / "staging"
    staging.mkdir()
    monkeypatch.setenv("DEFENSECLAW_HOME", str(home))
    monkeypatch.delenv(upgrade_shim.LOCAL_DIR_ENV, raising=False)
    monkeypatch.setattr("defenseclaw.__version__", "1.0.2")
    # Keep platform selection local to this module, including on POSIX hosts.
    shim_os = types.SimpleNamespace(**vars(os))
    shim_os.name = "nt"
    monkeypatch.setattr(upgrade_shim, "os", shim_os)
    monkeypatch.setattr(upgrade_shim.tempfile, "tempdir", str(staging))
    monkeypatch.setattr(upgrade_shim, "release_source", lambda: upgrade_shim.DEFAULT_REPO)
    monkeypatch.setattr(upgrade_shim, "managed_deployment", lambda: None)
    monkeypatch.setattr(
        upgrade_shim, "_fetch_installer", lambda *_args: pytest.fail("older installer fetched directly")
    )
    launches: list[tuple[str, list[str], bytes]] = []

    def launch(path: str, args: list[str], workdir: str) -> int:
        assert os.path.dirname(path) == workdir
        launches.append((path, args, Path(path).read_bytes()))
        return 0

    monkeypatch.setattr(upgrade_shim, "_run_installer", launch)
    return home, launches


def _saved(home: Path, version: str = "1.0.2") -> Path:
    saved = home / "installer" / "install.ps1"
    saved.parent.mkdir(parents=True)
    saved.write_bytes(f'$DcVersion = "{version}"\n# current recovery controller\n'.encode())
    _record(home, saved)
    return saved


def _record(home: Path, saved: Path) -> None:
    # The digest the install records with the installer it saves (GAP-1067).
    record = home / "receipts" / "installer.sha256"
    record.parent.mkdir(parents=True, exist_ok=True)
    record.write_bytes(f"{hashlib.sha256(saved.read_bytes()).hexdigest()}  install.ps1\n".encode())


@pytest.mark.parametrize("local", [False, True])
@pytest.mark.parametrize("yes", [False, True])
def test_windows_downgrade_runs_a_copy_of_current_installer(routing, monkeypatch, tmp_path, local, yes):
    home, launches = routing
    saved = _saved(home)
    release = str(tmp_path / "older-assets")
    if local:
        monkeypatch.setenv(upgrade_shim.LOCAL_DIR_ENV, release)

    assert upgrade_shim._upgrade("1.0.1", yes=yes) == 0

    path, args, body = launches[0]
    assert path != str(saved)
    assert body == saved.read_bytes()
    assert args == (["--yes"] if yes else []) + ["--version", "1.0.1"] + (["--local", release] if local else [])
    assert [upgrade_shim._powershell_flag(arg) for arg in args] == (
        (["-Yes"] if yes else []) + ["-Version", "1.0.1"] + (["-Local", release] if local else [])
    )


@pytest.mark.parametrize("kind", ["missing", "directory", "wrong-version", "unstamped", "changed", "unrecorded"])
def test_windows_downgrade_refuses_without_current_controller(routing, kind):
    home, launches = routing
    if kind == "directory":
        (home / "installer" / "install.ps1").mkdir(parents=True)
    elif kind == "wrong-version":
        _saved(home, "1.0.1")
    elif kind == "unstamped":
        saved = _saved(home)
        saved.write_bytes(b"# unknown controller\n")
        _record(home, saved)
    elif kind == "changed":
        # GAP-1067: a controller changed after the install saved it.
        saved = _saved(home)
        saved.write_bytes(saved.read_bytes() + b"# r28sa note\n")
    elif kind == "unrecorded":
        _saved(home)
        (home / "receipts" / "installer.sha256").unlink()

    with pytest.raises(upgrade_shim.ShimError, match="Repair DefenseClaw 1.0.2"):
        upgrade_shim._upgrade("1.0.1", yes=True)

    assert launches == []


@pytest.mark.parametrize("entry", ["leaf", "parent"])
@pytest.mark.parametrize("command", ["upgrade", "rollback"])
def test_windows_saved_controller_refuses_reparse_paths(routing, monkeypatch, entry, command):
    home, launches = routing
    saved = _saved(home)
    reparse = saved if entry == "leaf" else saved.parent
    original = upgrade_shim.os.lstat

    def lstat(path):
        info = original(path)
        if os.path.normcase(str(path)) == os.path.normcase(str(reparse)):
            return types.SimpleNamespace(st_mode=info.st_mode, st_file_attributes=0x400)
        return info

    monkeypatch.setattr(upgrade_shim.os, "lstat", lstat)
    with pytest.raises(upgrade_shim.ShimError, match="[Rr]epair"):
        if command == "upgrade":
            upgrade_shim._upgrade("1.0.1", yes=True)
        else:
            upgrade_shim._rollback(yes=True)
    assert launches == []


def test_windows_downgrade_rejects_controller_replaced_during_copy(routing, monkeypatch):
    home, launches = routing
    _saved(home)
    original = upgrade_shim.os.fstat

    def fstat(fd):
        info = original(fd)
        fields = ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")
        values = {field: getattr(info, field) for field in fields}
        values["st_ino"] += 1
        return types.SimpleNamespace(**values)

    monkeypatch.setattr(upgrade_shim.os, "fstat", fstat)
    with pytest.raises(upgrade_shim.ShimError, match="changed while being copied"):
        upgrade_shim._upgrade("1.0.1", yes=True)
    assert launches == []


@pytest.mark.parametrize(("platform", "target"), [("nt", "1.0.2"), ("nt", "1.0.3"), ("posix", "1.0.1")])
def test_other_upgrade_routes_keep_fetching_the_requested_installer(routing, monkeypatch, platform, target):
    _home, launches = routing
    monkeypatch.setattr(upgrade_shim.os, "name", platform)
    fetched: list[str] = []

    def fetch(_repo, version, _local, workdir):
        fetched.append(version)
        installer = os.path.join(workdir, upgrade_shim._installer_name())
        Path(installer).write_bytes(b"verified target installer")
        return installer

    monkeypatch.setattr(upgrade_shim, "_fetch_installer", fetch)
    assert upgrade_shim._upgrade(target, yes=True) == 0
    assert fetched == [target]
    assert launches[0][1:] == (["--yes"], b"verified target installer")


@pytest.mark.parametrize("version", ["1.0.2", "1.1.0"])
def test_windows_rollback_fallback_still_rolls_forward(routing, version):
    home, launches = routing
    previous = home / "previous"
    saved = _saved(previous, version)
    (previous / "VERSION").write_text(version, encoding="utf-8")

    assert upgrade_shim._rollback(yes=True) == 0
    assert launches[0][0] != str(saved)
    assert launches[0][1:] == (["--rollback", "--yes"], saved.read_bytes())


@pytest.mark.parametrize("version", [None, "unknown", "1.0.1"])
def test_windows_rollback_fallback_refuses_older_or_unknown_controller(routing, version):
    home, launches = routing
    previous = home / "previous"
    _saved(previous, "1.0.1")
    if version is not None:
        (previous / "VERSION").write_text(version, encoding="utf-8")

    with pytest.raises(upgrade_shim.ShimError, match="Repair the current DefenseClaw install"):
        upgrade_shim._rollback(yes=True)
    assert launches == []


@pytest.mark.parametrize("current", [False, True])
def test_windows_rollback_refuses_a_stale_controller_stamp(routing, current):
    home, launches = routing
    if current:
        _saved(home, "1.0.1")
    else:
        _saved(home / "previous", "1.0.1")
        (home / "previous" / "VERSION").write_text("1.1.0", encoding="utf-8")

    with pytest.raises(upgrade_shim.ShimError, match="Repair the current DefenseClaw install"):
        upgrade_shim._rollback(yes=True)
    assert launches == []


@pytest.mark.parametrize("command", ["upgrade", "rollback"])
@pytest.mark.parametrize("extra_byte", [False, True])
def test_windows_saved_controller_read_is_bounded(routing, command, extra_byte):
    home, launches = routing
    saved = _saved(home)
    body = saved.read_bytes()
    saved.write_bytes(body + b"#" * (4 * 1024 * 1024 + int(extra_byte) - len(body)))
    _record(home, saved)

    def invoke():
        return upgrade_shim._upgrade("1.0.1", yes=True) if command == "upgrade" else upgrade_shim._rollback(yes=True)

    if extra_byte:
        with pytest.raises(upgrade_shim.ShimError, match="size limit"):
            invoke()
        assert launches == []
    else:
        assert invoke() == 0
        assert len(launches[0][2]) == 4 * 1024 * 1024


@pytest.mark.parametrize("size", [128, 129])
def test_windows_rollback_fallback_version_read_is_bounded(routing, size):
    home, launches = routing
    previous = home / "previous"
    _saved(previous, "1.1.0")
    (previous / "VERSION").write_bytes(b"1.1.0" + b" " * (size - len("1.1.0")))

    if size > 128:
        with pytest.raises(upgrade_shim.ShimError, match="Repair the current DefenseClaw install"):
            upgrade_shim._rollback(yes=True)
        assert launches == []
    else:
        assert upgrade_shim._rollback(yes=True) == 0
        assert launches[0][1] == ["--rollback", "--yes"]
