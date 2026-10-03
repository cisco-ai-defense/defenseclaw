# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""What ``defenseclaw uninstall`` removes by default and with --all --binaries.

The default removes only the hooks and registrations and keeps
~/.defenseclaw and the binaries; ``--all --binaries`` removes everything:
the data directory, the binaries, the launcher links, the installer's uv
and bookkeeping, the local observability stack and (on Windows) the user
Path entry the installer added.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from click.testing import CliRunner

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.commands import cmd_uninstall, windows_native_uninstall  # noqa: E402

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="POSIX per-user install layout")


def _per_user_install(home: Path) -> tuple[Path, Path]:
    """Lay out what install.sh leaves: the data dir, binaries and links."""
    data_dir = home / ".defenseclaw"
    venv_bin = data_dir / ".venv" / "bin"
    venv_bin.mkdir(parents=True)
    for name in ("defenseclaw", "skill-scanner", "mcp-scanner"):
        (venv_bin / name).write_text("#!/bin/sh\n", encoding="utf-8")
    (data_dir / "audit.db").write_bytes(b"")
    (data_dir / "hooks").mkdir()
    (data_dir / "hooks" / "claude-code-hook.sh").write_text("#!/bin/bash\n", encoding="utf-8")
    (data_dir / "foreign-hooks-backup").mkdir()
    stack = data_dir / "observability-stack"
    stack.mkdir()
    (stack / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")

    bin_dir = home / ".local" / "bin"
    bin_dir.mkdir(parents=True)
    (bin_dir / "defenseclaw-gateway").write_text("gateway", encoding="utf-8")
    (bin_dir / "defenseclaw-acp").write_text("acp", encoding="utf-8")
    for name in ("defenseclaw", "skill-scanner", "mcp-scanner"):
        (bin_dir / name).symlink_to(venv_bin / name)
    (bin_dir / "uv").write_bytes(b"uv")
    (bin_dir / "uvx").write_bytes(b"uvx")
    (bin_dir / "defenseclaw-uv.sha256").write_text(
        f"{hashlib.sha256(b'uv').hexdigest()}  uv\n{hashlib.sha256(b'uvx').hexdigest()}  uvx\n",
        encoding="utf-8",
    )
    (bin_dir / ".defenseclaw-source-root").write_text("/src", encoding="utf-8")
    (bin_dir / ".defenseclaw-install-custody").mkdir()
    # The account's own tool stays either way.
    (bin_dir / "rg").write_text("ripgrep", encoding="utf-8")
    return data_dir, bin_dir


@pytest.fixture
def per_user_install(tmp_path: Path):
    home = tmp_path.resolve() / "home"
    data_dir, bin_dir = _per_user_install(home)
    with (
        patch.dict(os.environ, {"HOME": str(home)}),
        patch.object(cmd_uninstall.config_module, "default_data_path", return_value=data_dir),
        patch.object(windows_native_uninstall, "prepare_native_windows_uninstall", return_value=None),
        # Never touch the shared /tmp of the test host.
        patch.object(cmd_uninstall, "_legacy_custody_parents", return_value=[]),
        patch.object(cmd_uninstall, "_remove_empty_plugin_cache"),
        patch.object(cmd_uninstall, "_stop_gateway"),
        patch.object(cmd_uninstall, "_local_observability_teardown") as observability,
    ):
        yield SimpleNamespace(home=home, data_dir=data_dir, bin_dir=bin_dir, observability=observability)


def _entries(path: Path) -> list[str]:
    return sorted(os.listdir(path))


@posix_only
def test_default_uninstall_keeps_data_and_binaries(per_user_install) -> None:
    before_data = _entries(per_user_install.data_dir)
    before_bin = _entries(per_user_install.bin_dir)

    result = CliRunner().invoke(cmd_uninstall.uninstall_cmd, ["--yes"])

    assert result.exit_code == 0, result.output
    assert _entries(per_user_install.data_dir) == before_data
    assert _entries(per_user_install.bin_dir) == before_bin
    per_user_install.observability.assert_not_called()


@posix_only
def test_all_binaries_removes_everything_and_leaves_no_dangling_link(per_user_install) -> None:
    result = CliRunner().invoke(cmd_uninstall.uninstall_cmd, ["--all", "--binaries", "--yes"])

    assert result.exit_code == 0, result.output
    # ~/.defenseclaw goes whole: hook scripts, foreign-hooks-backup, venv.
    assert not per_user_install.data_dir.exists()
    # The binaries, launcher links, installer uv and bookkeeping go; the
    # account's own tool stays, and no link is left dangling.
    assert _entries(per_user_install.bin_dir) == ["rg"]
    for name in _entries(per_user_install.bin_dir):
        assert (per_user_install.bin_dir / name).exists()
    # The local observability stack goes before its Compose files do.
    per_user_install.observability.assert_called_once_with(str(per_user_install.data_dir))


@posix_only
def test_all_without_binaries_removes_data_and_dangling_links_only(per_user_install) -> None:
    result = CliRunner().invoke(cmd_uninstall.uninstall_cmd, ["--all", "--yes"])

    assert result.exit_code == 0, result.output
    assert not per_user_install.data_dir.exists()
    # The links into the data dir go with it; the binaries stay for --binaries.
    left = _entries(per_user_install.bin_dir)
    assert "defenseclaw" not in left and "skill-scanner" not in left
    assert {"defenseclaw-gateway", "defenseclaw-acp", "uv", "rg"} <= set(left)


@posix_only
def test_dry_run_names_observability_and_the_kept_mac_app(per_user_install, tmp_path: Path) -> None:
    app = tmp_path / "Applications" / "DefenseClawMac.app"
    app.mkdir(parents=True)
    with patch.object(cmd_uninstall, "_installed_mac_app", return_value=str(app)):
        result = CliRunner().invoke(cmd_uninstall.uninstall_cmd, ["--all", "--binaries", "--dry-run"])

    assert result.exit_code == 0, result.output
    assert "local observability" in result.output
    assert "DefenseClawMac.app" in result.output and "Login Items" in result.output
    assert per_user_install.data_dir.exists()


def test_local_observability_teardown_resets_only_a_present_stack(tmp_path: Path) -> None:
    from defenseclaw.observability import local_stack

    stack = tmp_path / "observability-stack"
    stack.mkdir()
    (stack / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")

    class Runner:
        def __init__(self, output: str, returncode: int = 0) -> None:
            self.output, self.returncode, self.calls = output, returncode, []

        def run(self, argv, *, timeout, env=None):
            self.calls.append(list(argv))
            return SimpleNamespace(returncode=self.returncode, stdout=self.output, stderr="daemon down")

    def controller(runner):
        resets = []
        fake = SimpleNamespace(
            docker_path="/usr/bin/docker",
            runner=runner,
            environment={},
            reset=lambda *, confirmed: resets.append(confirmed),
        )
        return fake, resets

    for output, want_reset in (("abc123\n", [True]), ("", [])):
        fake, resets = controller(Runner(output))
        with (
            patch.object(cmd_uninstall.shutil, "which", return_value="/usr/bin/docker"),
            patch.object(local_stack, "LocalStackController", return_value=fake),
        ):
            cmd_uninstall._local_observability_teardown(str(tmp_path))
        assert resets == want_reset
        assert all(f"label=com.docker.compose.project={local_stack.COMPOSE_PROJECT}" in c for c in fake.runner.calls)

    # Docker cannot answer: the stack stays, with the command that removes it.
    fake, resets = controller(Runner("", returncode=1))
    with (
        patch.object(cmd_uninstall.shutil, "which", return_value="/usr/bin/docker"),
        patch.object(local_stack, "LocalStackController", return_value=fake),
        patch.object(cmd_uninstall.ux, "warn") as warn,
    ):
        cmd_uninstall._local_observability_teardown(str(tmp_path))
    assert resets == []
    assert "docker compose -p defenseclaw-observability down --volumes" in warn.call_args.args[0]

    # No Docker, or no stack: nothing runs.
    with patch.object(local_stack, "LocalStackController") as built:
        with patch.object(cmd_uninstall.shutil, "which", return_value=None):
            cmd_uninstall._local_observability_teardown(str(tmp_path))
        cmd_uninstall._local_observability_teardown(str(tmp_path / "missing"))
    built.assert_not_called()


def test_windows_path_entry_goes_and_the_rest_keep_their_text() -> None:
    profile = r"C:\Users\kévin"
    directory = profile + r"\.local\bin"

    def expand(value: str) -> str:
        return value.replace("%USERPROFILE%", profile)

    raw = r"%USERPROFILE%\AppData\Local\Microsoft\WindowsApps;" + directory + r"\;C:\Tools;;"
    assert cmd_uninstall._path_without_entry(raw, directory, expand) == (
        r"%USERPROFILE%\AppData\Local\Microsoft\WindowsApps;C:\Tools;;"
    )
    assert cmd_uninstall._path_without_entry(r'"%USERPROFILE%\.LOCAL\bin";C:\Tools', directory, expand) == r"C:\Tools"
    assert cmd_uninstall._path_without_entry(r"C:\Tools", directory, expand) == r"C:\Tools"


def test_windows_install_root_empties_only_without_other_files(tmp_path: Path) -> None:
    root = tmp_path / "bin"
    root.mkdir()
    (root / "defenseclaw.cmd").write_text("shim", encoding="utf-8")
    (root / ".defenseclaw-source-root").write_text("x", encoding="utf-8")
    plan = cmd_uninstall.UninstallPlan(
        platform_name="win32",
        install_root=str(root),
        binary_targets=(str(root / "defenseclaw.cmd"),),
        remove_binaries=True,
    )
    assert cmd_uninstall._install_root_empties(plan)
    (root / "other-tool.exe").write_text("tool", encoding="utf-8")
    assert not cmd_uninstall._install_root_empties(plan)
    assert cmd_uninstall._install_root_empties(
        cmd_uninstall.UninstallPlan(install_root=str(tmp_path / "missing"), remove_binaries=True)
    )


def test_windows_binary_removal_drops_the_emptied_folder_and_its_path_entry(tmp_path: Path) -> None:
    profile = tmp_path.resolve() / "profile"
    root = profile / ".local" / "bin"
    root.mkdir(parents=True)
    managed_venv = profile / ".defenseclaw" / ".venv"
    shim = root / "defenseclaw.cmd"
    shim.write_text(f'@echo off\n"{managed_venv / "Scripts" / "defenseclaw.exe"}" %*\n', encoding="utf-8")
    (root / "defenseclaw-gateway.exe").write_bytes(b"MZ")
    plan = cmd_uninstall.UninstallPlan(
        platform_name="win32",
        install_root=str(root),
        gateway_path=str(root / "defenseclaw-gateway.exe"),
        binary_targets=(str(shim), str(root / "defenseclaw-gateway.exe")),
        remove_binaries=True,
        managed_venv=str(managed_venv),
    )
    with (
        patch.object(cmd_uninstall.shutil, "which", return_value=None),
        patch.object(cmd_uninstall, "_legacy_custody_parents", return_value=[]),
        patch.object(cmd_uninstall, "_remove_user_path_entry") as path_entry,
    ):
        cmd_uninstall._remove_binaries(plan)
    assert not root.exists()
    path_entry.assert_called_once_with(plan)


def test_native_windows_setup_keeps_binaries_flag(tmp_path: Path) -> None:
    request = SimpleNamespace(setup_path=str(tmp_path / "Setup.exe"), platform_name="win32")
    outcome = windows_native_uninstall.NativeWindowsUninstallOutcome(0)
    for argv, cleaned in ((["--all", "--binaries", "--yes"], True), (["--all", "--yes"], False)):
        with (
            patch.object(windows_native_uninstall, "prepare_native_windows_uninstall", return_value=request),
            patch.object(windows_native_uninstall, "execute_native_windows_uninstall", return_value=outcome),
            patch.object(cmd_uninstall, "_remove_script_install_after_native_setup") as after,
            patch.object(cmd_uninstall, "_build_plan") as generic_plan,
        ):
            result = CliRunner().invoke(cmd_uninstall.uninstall_cmd, argv)
        assert result.exit_code == 0, result.output
        generic_plan.assert_not_called()
        if cleaned:
            after.assert_called_once_with("win32")
            assert "%USERPROFILE%\\.local\\bin" in result.output
        else:
            after.assert_not_called()


@posix_only
def test_all_binaries_removes_the_installer_uv_cache_and_python(per_user_install) -> None:
    home, data_dir = per_user_install.home, per_user_install.data_dir
    cache = home / ".cache" / "uv"
    (cache / "archive-v0").mkdir(parents=True)
    (cache / "archive-v0" / "wheel").write_bytes(b"w")
    python_root = home / ".local" / "share" / "uv" / "python"
    base = python_root / "cpython-3.12.0-linux-x86_64-gnu"
    (base / "bin").mkdir(parents=True)
    (base / "bin" / "python3").write_bytes(b"py")
    (python_root / ".lock").write_bytes(b"")
    (data_dir / ".venv" / "pyvenv.cfg").write_text(f"home = {base / 'bin'}\n", encoding="utf-8")
    env = {"PATH": str(per_user_install.bin_dir), "XDG_CACHE_HOME": "", "XDG_DATA_HOME": ""}
    with patch.dict(os.environ, env):
        os.environ.pop("UV_CACHE_DIR", None)
        os.environ.pop("UV_PYTHON_INSTALL_DIR", None)
        result = CliRunner().invoke(cmd_uninstall.uninstall_cmd, ["--all", "--binaries", "--yes"])

    assert result.exit_code == 0, result.output
    assert not cache.exists() and not (home / ".cache").exists()
    assert not (home / ".local" / "share").exists()
    assert _entries(per_user_install.bin_dir) == ["rg"]


@posix_only
def test_uv_python_with_other_pythons_stays(per_user_install) -> None:
    python_root = per_user_install.home / ".local" / "share" / "uv" / "python"
    base = python_root / "cpython-3.12.0"
    (base / "bin").mkdir(parents=True)
    (python_root / "cpython-3.13.0").mkdir()  # the account's own uv Python
    (per_user_install.data_dir / ".venv" / "pyvenv.cfg").write_text(f"home = {base / 'bin'}\n", encoding="utf-8")
    with patch.dict(os.environ, {"PATH": str(per_user_install.bin_dir)}):
        os.environ.pop("UV_PYTHON_INSTALL_DIR", None)
        leftovers = cmd_uninstall._installer_uv_leftovers(
            str(per_user_install.bin_dir), (str(per_user_install.bin_dir / "uv"),), str(per_user_install.data_dir), "linux"
        )
    assert str(python_root) not in leftovers


@posix_only
def test_uv_cache_stays_when_the_installer_kept_uv_in_the_data_dir(per_user_install) -> None:
    # GAP-1125: the current installer keeps uv's cache in data_dir/.uv, so
    # ~/.cache/uv is the account's own.
    cache = per_user_install.home / ".cache" / "uv"
    cache.mkdir(parents=True)
    (per_user_install.data_dir / ".uv" / "cache").mkdir(parents=True)
    with patch.dict(os.environ, {"PATH": str(per_user_install.bin_dir), "XDG_CACHE_HOME": ""}):
        os.environ.pop("UV_CACHE_DIR", None)
        leftovers = cmd_uninstall._installer_uv_leftovers(
            str(per_user_install.bin_dir), (str(per_user_install.bin_dir / "uv"),), str(per_user_install.data_dir), "linux"
        )
    assert leftovers == ()


@posix_only
def test_all_binaries_removes_old_uv_cache_entries_and_hook_scratch(per_user_install, tmp_path: Path) -> None:
    # GAP-1411: a 0.8.x installer's uv left DefenseClaw in the account's own
    # uv cache, and hooks that were killed left their scratch HOMEs in TMPDIR.
    home, bin_dir = per_user_install.home, per_user_install.bin_dir
    (per_user_install.data_dir / ".uv" / "cache").mkdir(parents=True)
    cache = home / ".cache" / "uv"
    (cache / "archive-v0" / "a1" / "defenseclaw-0.8.10.dist-info").mkdir(parents=True)
    log = tmp_path / "uv-args"
    (bin_dir / "uv").write_text(f'#!/bin/sh\necho "$UV_CACHE_DIR $*" > {log}\n', encoding="utf-8")
    (bin_dir / "uv").chmod(0o755)
    scratch_root = tmp_path / "tmp"
    scratch = scratch_root / "defenseclaw-hook.Ab12Cd34"
    (scratch / "sub").mkdir(parents=True)
    (scratch_root / "defenseclaw-hook-notes").mkdir()
    with (
        patch.dict(os.environ, {"PATH": str(bin_dir), "XDG_CACHE_HOME": ""}),
        patch.object(cmd_uninstall, "_hook_temp_roots", return_value=(str(scratch_root),)),
    ):
        os.environ.pop("UV_CACHE_DIR", None)
        result = CliRunner().invoke(cmd_uninstall.uninstall_cmd, ["--all", "--binaries", "--yes"])

    assert result.exit_code == 0, result.output
    assert "uv cache clean defenseclaw" in result.output
    assert log.read_text(encoding="utf-8").split() == [str(cache), "cache", "clean", "defenseclaw"]
    assert _entries(scratch_root) == ["defenseclaw-hook-notes"]


@posix_only
def test_all_binaries_removes_an_emptied_local_bin(per_user_install) -> None:
    (per_user_install.bin_dir / "rg").unlink()

    result = CliRunner().invoke(cmd_uninstall.uninstall_cmd, ["--all", "--binaries", "--yes"])

    assert result.exit_code == 0, result.output
    assert not (per_user_install.home / ".local").exists()


def test_remove_created_dirs_keeps_folders_with_content(tmp_path: Path) -> None:
    home = tmp_path.resolve()
    data_dir = home / ".defenseclaw"
    data_dir.mkdir()
    empty = home / ".copilot" / "hooks"
    empty.mkdir(parents=True)
    used = home / ".config" / "opencode" / "plugins"
    used.mkdir(parents=True)
    (used / "mine.js").write_text("x", encoding="utf-8")
    record = data_dir / cmd_uninstall._CREATED_DIRS_RECORD
    record.write_text(json.dumps({"dirs": [str(empty), str(empty.parent), str(used), "/etc/elsewhere"]}), encoding="utf-8")

    with patch.dict(os.environ, {"HOME": str(home), "USERPROFILE": str(home)}):
        cmd_uninstall._remove_created_dirs(str(data_dir))

    assert not (home / ".copilot").exists()
    assert used.is_dir()
    assert json.loads(record.read_text(encoding="utf-8"))["dirs"] == sorted([str(used), "/etc/elsewhere"])


def test_reset_keeps_the_installer_uv() -> None:
    assert ".uv" in cmd_uninstall._RESET_PRESERVED_ENTRIES


@posix_only
def test_all_binaries_removes_uv_editable_builds_of_defenseclaw(per_user_install) -> None:
    # GAP-1873: `uv cache clean defenseclaw` leaves the editable build a
    # `make all` made; uninstall removes it and keeps other projects' entries.
    home, bin_dir = per_user_install.home, per_user_install.bin_dir
    (per_user_install.data_dir / ".uv" / "cache").mkdir(parents=True)
    cache = home / ".cache" / "uv"
    editable = cache / "sdists-v9" / "editable" / "fd4b0bc0ea720841"
    (editable / "PMWiJyLN").mkdir(parents=True)
    (editable / "PMWiJyLN" / "defenseclaw-0.8.10-0.editable-py3-none-any.whl").write_bytes(b"whl")
    (editable / "revision.rev").write_bytes(b"")
    archive = cache / "archive-v0" / "SAh7Zu"
    (archive / "defenseclaw-0.8.10.dist-info").mkdir(parents=True)
    (archive / "__editable__.defenseclaw-0.8.10.pth").write_text("/gone/cli\n", encoding="utf-8")
    other = cache / "archive-v0" / "Other1" / "click-8.1.7.dist-info"
    other.mkdir(parents=True)
    (bin_dir / "uv").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    (bin_dir / "uv").chmod(0o755)
    with (
        patch.dict(os.environ, {"PATH": str(bin_dir), "XDG_CACHE_HOME": ""}),
        patch.object(cmd_uninstall, "_hook_temp_roots", return_value=()),
    ):
        os.environ.pop("UV_CACHE_DIR", None)
        result = CliRunner().invoke(cmd_uninstall.uninstall_cmd, ["--all", "--binaries", "--yes"])

    assert result.exit_code == 0, result.output
    assert not editable.exists()
    assert not archive.exists()
    assert other.is_dir()
    assert "removed DefenseClaw's entries from uv's cache" in result.output
