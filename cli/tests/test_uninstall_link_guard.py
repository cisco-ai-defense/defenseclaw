# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""No uninstall phase follows a link on a per-user Windows path.

A junction or symlink at a per-user folder, or at any folder above it, keeps
that folder: it is named with the step that is safe (remove only the link, or
ask an administrator), and nothing is read or removed through it. Each removal
site is checked here with a link on the way to its path; Linux and macOS keep
their behaviour.
"""

from __future__ import annotations

import contextlib
import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import click
import pytest
from click.testing import CliRunner

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw import link_guard  # noqa: E402
from defenseclaw.commands import cmd_uninstall, legacy_setup_install  # noqa: E402

from tests.test_legacy_setup_link_steps import _digest, _link  # noqa: E402
from tests.test_uninstall_legacy_setup_install import _junction, windows_only  # noqa: E402


def _dangling(link: Path, scratch: Path) -> str:
    """Make a directory link at *link* whose target is gone; return its kind."""
    target = scratch / "gone"
    target.mkdir()
    kind = _link(link, target)
    target.rmdir()
    return kind


@pytest.fixture
def profile(tmp_path: Path):
    """tmp/profile/AppData/Local is the LocalAppData; tmp/elsewhere is where a link can point."""
    base = tmp_path.resolve()
    local = base / "profile" / "AppData" / "Local"
    local.mkdir(parents=True)
    (base / "elsewhere").mkdir()
    with patch.object(legacy_setup_install, "local_app_data", return_value=str(local)):
        yield SimpleNamespace(base=base, home=base / "profile", local=local, elsewhere=base / "elsewhere")


def _named(problem: str, step: str, link: Path, kind: str) -> None:
    assert f"{link} is a {kind}" in problem
    assert f'cmd /c rmdir "{link}"' in step
    assert "removes only the link" in step
    assert "ask an administrator to" in step
    assert "yourself" not in step


# --- the shared helper -------------------------------------------------------------------------------------------


def test_the_step_for_other_folders_does_not_send_the_user_to_apps_and_features(profile) -> None:
    kind = _link(profile.local / "DefenseClaw", profile.elsewhere)
    other = link_guard.link_problem(str(profile.local / "DefenseClaw" / "HookRuntime"))
    setup = link_guard.link_problem(str(profile.local / "DefenseClaw" / "HookRuntime"), setup=True)
    assert other is not None and setup is not None
    _named(other, other.step, profile.local / "DefenseClaw", kind)
    assert "Apps & Features" not in other.step and "Apps & Features" in setup.step
    assert other.step.endswith(f"ask an administrator to check {profile.local / 'DefenseClaw'}.")
    # The folder itself is left out when only the way to it matters.
    assert link_guard.link_problem(str(profile.local / "DefenseClaw"), include_self=False) is None


def test_a_dangling_link_is_its_own_reason(profile) -> None:
    link = profile.local / "Programs"
    kind = _dangling(link, profile.elsewhere)
    problem = link_guard.dangling_link_problem(str(link / "DefenseClaw"))
    assert problem is not None
    assert f"{link} is a {kind} whose target cannot be found" in problem
    assert f'cmd /c rmdir "{link}"' in problem.step
    assert "nothing is behind it" not in problem.step and "nothing is behind it" not in problem
    assert "not connected" in problem.step and "connect it" in problem.step
    assert "Apps & Features" not in problem.step


def test_a_live_link_or_an_unreadable_target_is_not_dangling(profile) -> None:
    link = profile.local / "Programs"
    _link(link, profile.elsewhere)
    assert link_guard.dangling_link_problem(str(link / "DefenseClaw")) is None
    with patch.object(link_guard.os, "stat", side_effect=PermissionError("denied")):
        assert link_guard.dangling_link_problem(str(link / "DefenseClaw")) is None


# --- DefenseClaw Setup 0.8.x: a dangling link at the Setup folder -------------------------------------------------


@pytest.mark.parametrize("where", ["Programs", "Programs/DefenseClaw"])
def test_a_dangling_link_at_the_setup_folder_or_above_it_is_named(profile, where: str) -> None:
    link = profile.local.joinpath(*where.split("/"))
    link.parent.mkdir(exist_ok=True)
    kind = _dangling(link, profile.elsewhere)
    with (
        patch.object(legacy_setup_install, "_setup_registered", return_value=True),
        patch.object(
            legacy_setup_install, "_read_state", side_effect=AssertionError("nothing is read through a link")
        ),
    ):
        found = legacy_setup_install.find("win32")
    assert found is not None
    assert found.root == os.path.join(profile.local, "Programs", "DefenseClaw")
    # A link above the Setup folder is named here because Setup left its entries; at the folder it always is.
    _named(found.problem, found.problem_step, link, kind)
    assert "whose target cannot be found" in found.problem
    done, problems = legacy_setup_install.remove(found, edit_user_path=lambda _path: False)
    assert done == [] and [p.step for p in problems] == [found.problem_step]


def test_the_uninstall_prints_the_dangling_link_step(profile) -> None:
    from tests.test_uninstall_legacy_setup_install import _uninstall

    link = profile.local / "Programs"
    link.mkdir()
    link = link / "DefenseClaw"
    kind = _dangling(link, profile.elsewhere)
    found = legacy_setup_install.find("win32")
    assert found is not None
    problems = cmd_uninstall._remove_legacy_setup_install(found)
    result = cmd_uninstall.ExecutionResult(
        (
            cmd_uninstall.ExecutionPhaseResult(
                cmd_uninstall._LEGACY_SETUP_PHASE, "failed", "; ".join(problems), tuple(p.step for p in problems)
            ),
        )
    )
    code, output = _uninstall(found, result)
    assert code == 1
    assert f"- {link} is a {kind} whose target cannot be found (a deleted folder, or a drive or share" in output
    assert f'`cmd /c rmdir "{link}"`' in output


def test_a_link_to_a_folder_without_a_setup_install_is_nothing_to_find(profile) -> None:
    _link(profile.local / "Programs", profile.elsewhere)
    assert legacy_setup_install.find("win32") is None
    assert legacy_setup_install.find("linux") is None


# --- %LOCALAPPDATA%\DefenseClaw: the Setup leftovers ----------------------------------------------------------------


def _leftovers(base: Path) -> Path:
    """A DefenseClaw folder of Setup leftovers under *base*."""
    folder = base / "DefenseClaw"
    (folder / "HookRuntime").mkdir(parents=True)
    (folder / "HookRuntime" / "defenseclaw-hook.exe").write_bytes(b"MZ")
    (folder / "InstallerState").mkdir()
    (folder / "InstallerState" / "log.txt").write_text("decoy", encoding="utf-8")
    return folder


def _kept_behind(paths: tuple[str, ...], link: Path, kind: str, before: str, target: Path) -> None:
    kept = cmd_uninstall._remove_setup_leftovers(paths)
    assert len(kept) == len(paths)
    for problem in kept:
        assert problem.startswith("could not remove ")
        _named(problem, problem.step, link, kind)
    assert os.path.lexists(link)
    assert _digest(target) == before


def test_a_link_at_the_data_folder_keeps_the_setup_leftovers(profile) -> None:
    decoy = _leftovers(profile.elsewhere)
    link = profile.local / "DefenseClaw"
    kind = _link(link, decoy)
    before = _digest(decoy)
    with patch.object(legacy_setup_install, "local_app_data", return_value=str(profile.local)):
        leftovers = cmd_uninstall._windows_setup_leftovers("win32")
    assert set(leftovers) == {str(link / "HookRuntime"), str(link / "InstallerState")}
    _kept_behind(leftovers, link, kind, before, decoy)


def test_a_link_at_a_folder_above_keeps_the_setup_leftovers(profile) -> None:
    real_appdata = profile.elsewhere / "RealAppData"
    decoy = _leftovers(real_appdata / "Local")
    before = _digest(real_appdata)
    appdata = profile.home / "AppData"
    profile.local.rmdir()
    appdata.rmdir()
    kind = _link(appdata, real_appdata)
    leftovers = (str(profile.local / "DefenseClaw" / "HookRuntime"), str(profile.local / "DefenseClaw" / "InstallerState"))
    _kept_behind(leftovers, appdata, kind, before, real_appdata)
    assert decoy.is_dir()


def test_a_link_at_a_leftover_is_removed_without_being_followed(profile) -> None:
    folder = profile.local / "DefenseClaw"
    folder.mkdir()
    decoy = profile.elsewhere / "HookRuntime"
    decoy.mkdir()
    (decoy / "keep.txt").write_text("keep", encoding="utf-8")
    _link(folder / "HookRuntime", decoy)
    before = _digest(decoy)
    assert cmd_uninstall._remove_setup_leftovers((str(folder / "HookRuntime"),)) == []
    assert not os.path.lexists(folder / "HookRuntime")
    assert _digest(decoy) == before


def test_real_leftovers_go_and_the_folder_above_goes_when_empty(profile) -> None:
    folder = _leftovers(profile.local)
    paths = (str(folder / "HookRuntime"), str(folder / "InstallerState"))
    assert cmd_uninstall._remove_setup_leftovers(paths) == []
    assert not folder.exists()


def test_the_phase_fails_with_the_link_step_and_the_command_exits_one(profile, capsys) -> None:
    from tests.test_uninstall_legacy_setup_install import _uninstall

    decoy = _leftovers(profile.elsewhere)
    link = profile.local / "DefenseClaw"
    kind = _link(link, decoy)
    before = _digest(decoy)
    plan = cmd_uninstall.UninstallPlan(
        platform_name="win32",
        remove_binaries=True,
        setup_leftovers=(str(link / "HookRuntime"), str(link / "InstallerState")),
    )
    with patch.object(cmd_uninstall, "_validate_plan"):
        result = cmd_uninstall._execute_plan(plan)
    phase = next(p for p in result.phases if p.name == cmd_uninstall._SETUP_LEFTOVERS_PHASE)
    assert phase.status == "failed"
    assert phase.next_steps and f'cmd /c rmdir "{link}"' in phase.next_steps[0]
    assert len(phase.next_steps) == 1
    assert _digest(decoy) == before and os.path.lexists(link)
    code, output = _uninstall(None, result)
    assert code == 1
    assert "The folders DefenseClaw Setup left were not removed completely" in output
    assert f"- {link} is a {kind}." in output


def test_the_plan_says_which_leftovers_stay(profile, capsys) -> None:
    decoy = _leftovers(profile.elsewhere)
    link = profile.local / "DefenseClaw"
    kind = _link(link, decoy)
    plan = cmd_uninstall.UninstallPlan(
        platform_name="win32", remove_binaries=True, setup_leftovers=(str(link / "HookRuntime"),)
    )
    cmd_uninstall._render_plan(plan, dry_run=True)
    output = " ".join(capsys.readouterr().out.split())
    assert f"{link / 'HookRuntime'} (stays: {link} is a {kind}" in output


# --- the data folder, the install folder and the launchers -------------------------------------------------------


def _data_folder(base: Path) -> Path:
    data = base / ".defenseclaw"
    data.mkdir(parents=True)
    (data / "config.yaml").write_text("claw: {}\n", encoding="utf-8")
    (data / "audit.db").write_bytes(b"db")
    return data


def _win_plan(data_dir: Path, **fields) -> cmd_uninstall.UninstallPlan:
    return cmd_uninstall.UninstallPlan(
        platform_name="win32", data_dir=str(data_dir), remove_data_dir=True, **fields
    )


@pytest.mark.parametrize("make", ["at", "above"])
def test_a_link_at_or_above_the_data_folder_is_named_and_nothing_is_removed(profile, make: str) -> None:
    real = _data_folder(profile.elsewhere / "real")
    if make == "at":
        link = profile.home / ".defenseclaw"
        kind = _link(link, real)
        data_dir = link
    else:
        link = profile.home / "linked"
        kind = _link(link, real.parent)
        data_dir = link / ".defenseclaw"
    before = _digest(real.parent)
    with patch.object(cmd_uninstall, "_open_tui_refusal", return_value=""):
        with pytest.raises(click.ClickException) as refused:
            cmd_uninstall._validate_plan(_win_plan(data_dir))
    message = refused.value.message
    assert message.startswith("refusing data path: ") and f"{link} is a {kind}" in message
    assert f'cmd /c rmdir "{link}"' in message and "yourself" not in message
    with pytest.raises(click.ClickException) as direct:
        cmd_uninstall._remove_data_dir(str(data_dir), platform_name="win32")
    assert f"{link} is a {kind}" in direct.value.message
    assert _digest(real.parent) == before and os.path.lexists(link)


def test_linux_and_macos_keep_their_behaviour_for_a_link_above_the_data_folder(profile) -> None:
    real = _data_folder(profile.elsewhere / "real")
    link = profile.home / "linked"
    _link(link, real.parent)
    with patch.object(cmd_uninstall, "_open_tui_refusal", return_value=""):
        cmd_uninstall._validate_plan(
            cmd_uninstall.UninstallPlan(
                platform_name="linux", data_dir=str(link / ".defenseclaw"), remove_data_dir=True
            )
        )
    cmd_uninstall._remove_data_dir(str(link / ".defenseclaw"), platform_name="linux")
    assert not real.exists()


def test_a_link_above_the_install_folder_is_named_and_the_launchers_stay(profile) -> None:
    real_bin = profile.elsewhere / "real" / "bin"
    real_bin.mkdir(parents=True)
    launcher = real_bin / "defenseclaw.cmd"
    launcher.write_text("shim", encoding="utf-8")
    link = profile.home / ".local"
    kind = _link(link, real_bin.parent)
    install_root = link / "bin"
    before = _digest(real_bin.parent)
    plan = cmd_uninstall.UninstallPlan(
        platform_name="win32",
        install_root=str(install_root),
        gateway_path=str(install_root / "defenseclaw-gateway.exe"),
        binary_targets=(str(install_root / "defenseclaw.cmd"),),
        data_bound_launchers=(str(install_root / "defenseclaw.cmd"),),
        remove_binaries=True,
    )
    with pytest.raises(click.ClickException) as refused:
        cmd_uninstall._validate_plan(plan)
    assert refused.value.message.startswith("refusing binary install root: ")
    assert f"{link} is a {kind}" in refused.value.message
    with pytest.raises(click.ClickException) as launchers:
        cmd_uninstall._remove_data_bound_launchers(plan)
    assert f"{link} is a {kind}" in launchers.value.message
    assert _digest(real_bin.parent) == before


def test_a_link_above_the_openclaw_home_is_named(profile) -> None:
    real = profile.elsewhere / "oc" / ".openclaw"
    real.mkdir(parents=True)
    link = profile.home / "linked"
    kind = _link(link, real.parent)
    plan = cmd_uninstall.UninstallPlan(
        platform_name="win32", openclaw_home=str(link / ".openclaw"), remove_plugin=True
    )
    with pytest.raises(click.ClickException) as refused:
        cmd_uninstall._validate_plan(plan)
    assert f"{link} is a {kind}" in refused.value.message


# --- the connector backups ---------------------------------------------------------------------------------------


def test_connector_backups_are_not_moved_through_a_link(profile) -> None:
    data = _data_folder(profile.home)
    backup = data / "connector_backups" / "openhands"
    backup.mkdir(parents=True)
    (backup / "config.json").write_text("mine", encoding="utf-8")
    kept_root = Path(str(data) + "-removed-connector-backups")
    kind = _link(kept_root, profile.elsewhere)
    before = _digest(profile.elsewhere)
    with pytest.raises(click.ClickException) as refused:
        cmd_uninstall._move_removed_connector_backups_out(str(data), "win32")
    message = refused.value.message
    assert f"{kept_root} is a {kind}" in message and "No data or binaries were removed" in message
    assert f'cmd /c rmdir "{kept_root}"' in message
    assert (backup / "config.json").read_text(encoding="utf-8") == "mine"
    assert _digest(profile.elsewhere) == before


def test_connector_backups_move_as_before_without_a_link(profile) -> None:
    data = _data_folder(profile.home)
    backup = data / "connector_backups" / "openhands"
    backup.mkdir(parents=True)
    (backup / "config.json").write_text("mine", encoding="utf-8")
    moved = cmd_uninstall._move_removed_connector_backups_out(str(data), "win32")
    assert list(moved) == [str(backup)] and Path(moved[str(backup)], "config.json").is_file()


def test_the_mcp_config_backups_behind_a_link_stay(profile, capsys) -> None:
    from defenseclaw.connector_paths import _managed_mcp_backup_path

    real = profile.elsewhere / "codex"
    real.mkdir()
    (real / "config.toml").write_text("[mcp_servers]\n", encoding="utf-8")
    link = profile.home / ".codex"
    kind = _link(link, real)
    config = link / "config.toml"
    backup = Path(_managed_mcp_backup_path(str(config)))
    backup.write_text("copy", encoding="utf-8")
    data = profile.home / ".defenseclaw"
    (data / "connector_backups" / "mcp").mkdir(parents=True)
    (data / "connector_backups" / "mcp" / "registry.json").write_text(
        json.dumps({"a": {"path": str(config), "backup": str(backup)}}), encoding="utf-8"
    )
    before = _digest(real)
    cmd_uninstall._remove_mcp_writer_backups(str(data), "win32")
    out = " ".join(capsys.readouterr().out.split())
    assert f"kept {backup}" in out and f"{link} is a {kind}" in out and f'cmd /c rmdir "{link}"' in out
    assert _digest(real) == before and backup.is_file()
    # The registered copy is removed where nothing links the way to it (the Linux/macOS behaviour).
    cmd_uninstall._remove_mcp_writer_backups(str(data), "linux")
    assert not backup.exists()


def test_the_unregistered_mcp_config_backups_behind_a_link_stay(profile, capsys) -> None:
    from defenseclaw.connector_paths import _managed_mcp_backup_path

    real = profile.elsewhere / "codex"
    real.mkdir()
    link = profile.home / ".codex"
    kind = _link(link, real)
    config = str(link / "config.toml")
    backup = Path(_managed_mcp_backup_path(config))
    backup.write_text("copy", encoding="utf-8")
    before = _digest(real)
    with (
        patch("defenseclaw.connector_paths.KNOWN_CONNECTORS", ("codex",)),
        patch("defenseclaw.connector_paths.mcp_source_locations", return_value=[config]),
    ):
        cmd_uninstall._remove_unregistered_mcp_writer_backups("win32")
        out = " ".join(capsys.readouterr().out.split())
        assert f"kept {backup}" in out and f"{link} is a {kind}" in out
        assert _digest(real) == before
        cmd_uninstall._remove_unregistered_mcp_writer_backups("linux")
    assert not backup.exists()


def test_the_orphan_copilot_plugin_behind_a_link_stays(profile, capsys) -> None:
    real = profile.elsewhere / "copilot"
    plugin = real / "installed-plugins" / "defenseclaw" / "defenseclaw"
    (plugin / "hooks").mkdir(parents=True)
    (plugin / "plugin.json").write_text(json.dumps(cmd_uninstall._COPILOT_PLUGIN_MANIFEST), encoding="utf-8")
    command = (
        "'/opt/dc/defenseclaw-hook' hook --connector copilot --enterprise-managed --event 'PreToolUse' "
        "--hook-surface vscode-local"
    )
    (plugin / "hooks" / "hooks.json").write_text(
        json.dumps({"hooks": {"PreToolUse": [{"type": "command", "command": command, "timeout": 30}]}}),
        encoding="utf-8",
    )
    link = profile.home / ".copilot"
    kind = _link(link, real)
    before = _digest(real)
    with (
        patch.dict(os.environ, {"HOME": str(profile.home), "USERPROFILE": str(profile.home)}),
        patch("defenseclaw.upgrade_shim.managed_deployment", return_value=None),
    ):
        cmd_uninstall._remove_orphan_copilot_plugin("win32")
        out = " ".join(capsys.readouterr().out.split())
        assert f"{link} is a {kind}" in out and "kept " in out
        assert _digest(real) == before
        cmd_uninstall._remove_orphan_copilot_plugin("linux")
    assert _digest(real) != before


# --- uv, Sigstore and uv's cache ---------------------------------------------------------------------------------


def test_uv_and_sigstore_folders_behind_a_link_stay(profile, capsys) -> None:
    real = profile.elsewhere / "uv"
    (real / "cache").mkdir(parents=True)
    (real / "cache" / "entry").write_text("x", encoding="utf-8")
    link = profile.local / "uv"
    kind = _link(link, real)
    before = _digest(real)
    cmd_uninstall._remove_leftover_dirs((str(link / "cache"),), platform_name="win32")
    out = " ".join(capsys.readouterr().out.split())
    assert f"kept {link / 'cache'}" in out and f"{link} is a {kind}" in out
    assert _digest(real) == before
    cmd_uninstall._remove_leftover_dirs((str(link / "cache"),), platform_name="linux")
    assert not (real / "cache").exists()


def test_uv_cache_entries_behind_a_link_are_not_cleaned(profile, capsys) -> None:
    real = profile.elsewhere / "uv"
    (real / "cache").mkdir(parents=True)
    link = profile.local / "uv"
    kind = _link(link, real)
    plan = cmd_uninstall.UninstallPlan(
        platform_name="win32", install_root=str(profile.home / ".local" / "bin"), uv_cache_entries=str(link / "cache")
    )
    with patch.object(cmd_uninstall.subprocess, "run", side_effect=AssertionError("uv is not run")):
        cmd_uninstall._clean_uv_cache_entries(plan)
    out = " ".join(capsys.readouterr().out.split())
    assert f"{link} is a {kind}" in out and f'cmd /c rmdir "{link}"' in out


# --- real junctions ----------------------------------------------------------------------------------------------


@windows_only
def test_real_junction_at_the_data_folder_keeps_the_setup_leftovers(profile) -> None:
    decoy = _leftovers(profile.elsewhere)
    link = profile.local / "DefenseClaw"
    _junction(link, decoy)
    before = _digest(decoy)
    leftovers = (str(link / "HookRuntime"), str(link / "InstallerState"))
    _kept_behind(leftovers, link, "junction", before, decoy)


@windows_only
def test_real_dangling_junction_at_the_setup_folder_is_named(profile) -> None:
    (profile.local / "Programs").mkdir()
    link = profile.local / "Programs" / "DefenseClaw"
    target = profile.elsewhere / "gone"
    target.mkdir()
    _junction(link, target)
    target.rmdir()
    found = legacy_setup_install.find("win32")
    assert found is not None
    _named(found.problem, found.problem_step, link, "junction")
    assert "whose target cannot be found" in found.problem
    # The printed step removes only the link.
    subprocess.run(["cmd.exe", "/d", "/c", "rmdir", str(link)], check=True, capture_output=True)
    assert not os.path.lexists(link) and legacy_setup_install.find("win32") is None


@windows_only
def test_real_junction_above_the_data_folder_is_refused(profile) -> None:
    real = _data_folder(profile.elsewhere / "real")
    link = profile.home / "linked"
    _junction(link, real.parent)
    before = _digest(real.parent)
    with pytest.raises(click.ClickException) as refused:
        cmd_uninstall._remove_data_dir(str(link / ".defenseclaw"), platform_name="win32")
    assert f"{link} is a junction" in refused.value.message
    assert _digest(real.parent) == before


def test_the_uninstall_command_is_unchanged_without_a_link(profile) -> None:
    """The ordinary Setup leftovers still go through `uninstall --dry-run`'s plan (no stays note)."""
    folder = _leftovers(profile.local)
    plan = cmd_uninstall.UninstallPlan(
        platform_name="win32", setup_leftovers=(str(folder / "HookRuntime"),), remove_binaries=True
    )
    with (
        patch.object(cmd_uninstall, "_build_plan", return_value=plan),
        patch.object(cmd_uninstall, "_with_listed_sandboxes", side_effect=lambda p, _s: p),
    ):
        outcome = CliRunner().invoke(cmd_uninstall.uninstall_cmd, ["--dry-run"])
    assert "left by DefenseClaw Setup" in outcome.output and "stays:" not in outcome.output


# --- S1: a dangling link high in the chain of a profile that never had Setup 0.8.x -----------------------------------


def test_a_dangling_link_above_the_setup_folder_is_not_named_without_setup_evidence(profile) -> None:
    link = profile.local / "Programs"
    _dangling(link, profile.elsewhere)
    with patch.object(legacy_setup_install, "_setup_registered", return_value=False):
        assert legacy_setup_install.find("win32") is None


def test_a_dangling_link_above_the_setup_folder_is_named_when_setup_left_its_entries(profile) -> None:
    link = profile.local / "Programs"
    kind = _dangling(link, profile.elsewhere)
    with patch.object(legacy_setup_install, "_setup_registered", return_value=True):
        found = legacy_setup_install.find("win32")
    assert found is not None and f"{link} is a {kind} whose target cannot be found" in found.problem
    # Setup hook launcher state is evidence too.
    state = profile.local / "DefenseClaw" / "HookRuntime" / "hook-runtime-state.json"
    state.parent.mkdir(parents=True)
    state.write_text("{}", encoding="utf-8")
    with patch.object(legacy_setup_install, "_setup_registered", return_value=False):
        found = legacy_setup_install.find("win32")
    assert found is not None and "whose target cannot be found" in found.problem


def test_a_dangling_link_at_the_setup_folder_is_named_without_other_evidence(profile) -> None:
    (profile.local / "Programs").mkdir()
    link = profile.local / "Programs" / "DefenseClaw"
    kind = _dangling(link, profile.elsewhere)
    with patch.object(legacy_setup_install, "_setup_registered", return_value=False):
        found = legacy_setup_install.find("win32")
    assert found is not None and f"{link} is a {kind} whose target cannot be found" in found.problem


def test_the_dangling_text_does_not_say_nothing_is_behind_the_link(profile) -> None:
    link = profile.local / "Programs"
    _dangling(link, profile.elsewhere)
    problem = link_guard.dangling_link_problem(str(link / "DefenseClaw"))
    assert problem is not None
    assert "nothing is behind" not in problem and "nothing is behind" not in problem.step
    assert "a drive or share that is not connected" in problem.step
    # Only the link at the path itself, when asked.
    assert link_guard.dangling_link_problem(str(link / "DefenseClaw"), above=False) is None


def test_setup_registered_reads_the_uninstall_entry_and_the_sign_in_start(profile) -> None:
    root = str(profile.local / "Programs" / "DefenseClaw")
    cache = str(profile.local / "DefenseClaw" / "InstallerCache")
    class Key:
        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

    def run_entries(_key, index):
        values = [("other", "C:\\Other\\app.exe"), ("DefenseClaw", f"\"{root}{os.sep}defenseclaw.exe\" start")]
        if index >= len(values):
            raise OSError("no more")
        return (*values[index], 1)

    registry = SimpleNamespace(
        HKEY_CURRENT_USER=1,
        KEY_QUERY_VALUE=1,
        OpenKey=lambda *_args, **_kw: Key(),
        QueryValueEx=lambda *_args: (root, 1),
        EnumValue=run_entries,
        ExpandEnvironmentStrings=lambda value: value,
    )
    with patch.dict(sys.modules, {"winreg": registry}):
        assert legacy_setup_install._setup_registered(root, cache) is True
        registry.QueryValueEx = lambda *_args: (str(profile.elsewhere), 1)
        assert legacy_setup_install._setup_registered(root, cache) is True  # the Run value
        registry.EnumValue = lambda _key, _index: (_ for _ in ()).throw(OSError("none"))
        assert legacy_setup_install._setup_registered(root, cache) is False


def test_another_kind_of_reparse_point_is_not_sent_to_rmdir(profile) -> None:
    link = profile.local / "Programs"
    link.mkdir()
    with patch.object(link_guard, "links_on_path", return_value=[(str(link), "link")]):
        problem = link_guard.link_problem(str(link / "DefenseClaw"))
    assert problem is not None and "rmdir" not in problem.step
    assert "Ask an administrator to check" in problem.step
    assert f"{link} is a link" in problem
    _dangling(profile.local / "gone", profile.elsewhere)
    with patch.object(link_guard, "links_on_path", return_value=[(str(profile.local / "gone"), "link")]):
        dangling = link_guard.dangling_link_problem(str(profile.local / "gone"))
    assert dangling is not None and "rmdir" not in dangling.step and "Ask an administrator" in dangling.step


# --- S2: uv editable cache entries -------------------------------------------------------------------------------


def _uv_cache(base: Path) -> Path:
    cache = base / "cache"
    entry = cache / "archive-v0" / "abc123"
    (entry / "defenseclaw-1.0.0.dist-info").mkdir(parents=True)
    (entry / "defenseclaw.pth").write_text("src", encoding="utf-8")
    return cache


def _uv_plan(profile, cache: Path):
    bin_dir = profile.home / ".local" / "bin"
    bin_dir.mkdir(parents=True)
    uv = bin_dir / "uv.exe"
    uv.write_text("uv", encoding="utf-8")
    uv.chmod(0o755)
    return cmd_uninstall.UninstallPlan(platform_name="win32", install_root=str(bin_dir), uv_cache_entries=str(cache))


def test_uv_editable_entries_behind_a_linked_archive_folder_stay(profile, capsys) -> None:
    real = _uv_cache(profile.elsewhere)
    cache = profile.local / "uv-cache"
    cache.mkdir()
    link = cache / "archive-v0"
    kind = _link(link, real / "archive-v0")
    before = _digest(real)
    plan = _uv_plan(profile, cache)
    with patch.object(cmd_uninstall.subprocess, "run", return_value=SimpleNamespace(returncode=0)):
        cmd_uninstall._clean_uv_cache_entries(plan)
    out = " ".join(capsys.readouterr().out.split())
    assert f"{link} is a {kind}" in out and "removed DefenseClaw" not in out
    assert _digest(real) == before


def test_uv_editable_entries_that_are_links_are_not_candidates(profile) -> None:
    real = _uv_cache(profile.elsewhere)
    cache = profile.local / "uv-cache"
    (cache / "archive-v0").mkdir(parents=True)
    _link(cache / "archive-v0" / "abc123", real / "archive-v0" / "abc123")
    assert cmd_uninstall._uv_editable_leftovers(str(cache)) == []


def test_uv_editable_entries_without_a_link_are_removed_as_before(profile, capsys) -> None:
    cache = _uv_cache(profile.local / "uvbase")
    plan = _uv_plan(profile, cache)
    with patch.object(cmd_uninstall.subprocess, "run", return_value=SimpleNamespace(returncode=0)):
        cmd_uninstall._clean_uv_cache_entries(plan)
    assert not (cache / "archive-v0" / "abc123").exists()
    assert "removed DefenseClaw" in capsys.readouterr().out


# --- S3: a relative path is still looked at ----------------------------------------------------------------------


def test_a_relative_openclaw_path_is_checked_as_the_absolute_path_it_names(profile, monkeypatch) -> None:
    lnk = profile.base / "lnk"
    kind = _link(lnk, profile.elsewhere)
    monkeypatch.chdir(profile.base)
    with pytest.raises(click.ClickException) as refused:
        cmd_uninstall._validate_windows_ancestor_chain(os.path.join("lnk", "openclaw.json"), "OpenClaw config")
    assert f"{lnk} is a {kind}" in refused.value.message
    cmd_uninstall._validate_windows_ancestor_chain(os.path.join("elsewhere", "openclaw.json"), "OpenClaw config")
    plan = cmd_uninstall.UninstallPlan(
        platform_name="win32", revert_openclaw=True, openclaw_config_file=os.path.join("lnk", "openclaw.json")
    )
    with pytest.raises(click.ClickException) as plan_refused:
        cmd_uninstall._validate_plan(plan)
    assert f"{lnk} is a {kind}" in plan_refused.value.message


# --- S4: the launchers are looked at again before each unlink -----------------------------------------------------


def test_a_link_made_between_two_launchers_stops_the_rest(profile) -> None:
    bin_dir = profile.home / ".local" / "bin"
    bin_dir.mkdir(parents=True)
    first, second = bin_dir / "defenseclaw.cmd", bin_dir / "defenseclaw-scanner.cmd"
    for launcher in (first, second):
        launcher.write_text("shim", encoding="utf-8")
    plan = cmd_uninstall.UninstallPlan(
        platform_name="win32",
        install_root=str(bin_dir),
        binary_targets=(str(first), str(second)),
        data_bound_launchers=(str(first), str(second)),
    )
    calls: list[str] = []
    moved = profile.home / ".local" / "bin.real"

    def swap(path: str, _data: str, _platform: str) -> bool:
        calls.append(path)
        if len(calls) == 2:  # the install folder becomes a link before the second launcher is looked at
            bin_dir.rename(moved)
            _link(bin_dir, moved)
        return True

    with patch.object(cmd_uninstall, "_is_data_bound_launcher", side_effect=swap):
        with pytest.raises(OSError) as stopped:
            cmd_uninstall._remove_data_bound_launchers(plan)
    assert "is a " in str(stopped.value) and "does not read or remove a folder through a link" in str(stopped.value)
    assert not (moved / "defenseclaw.cmd").exists() and (moved / "defenseclaw-scanner.cmd").exists()


# --- hardening: the real path must be the path written ---------------------------------------------------------------


def test_a_path_that_resolves_elsewhere_is_refused_with_the_link_step(profile) -> None:
    folder = profile.local / "uv"
    folder.mkdir()
    with patch.object(link_guard, "_windows", return_value=True), patch.object(link_guard, "_long_name", lambda p: p):
        with (
            patch.object(link_guard.os.path, "realpath", side_effect=lambda p: str(p).upper()),
            patch.object(link_guard.os.path, "normcase", str.lower),
        ):
            assert link_guard.link_problem(str(folder)) is None  # case alone does not count
        with patch.object(link_guard.os.path, "realpath", return_value=str(profile.elsewhere / "uv")):
            problem = link_guard.link_problem(str(folder))
            above = link_guard.link_problem(str(folder), include_self=False)
        # The folder itself may be a link that goes as a link: only the folder above is compared then.
        with patch.object(link_guard.os.path, "realpath", return_value=str(profile.local)):
            assert link_guard.link_problem(str(folder), include_self=False) is None
    assert problem is not None and "resolves to" in problem and "Ask an administrator to check" in problem.step
    assert above is not None
    # Off Windows the look is not made. Say so: on a Windows runner the real platform check is True.
    with (
        patch.object(link_guard, "_windows", return_value=False),
        patch.object(link_guard.os.path, "realpath", return_value="/nowhere"),
    ):
        assert link_guard.link_problem(str(folder)) is None


def test_the_data_folder_removal_refuses_a_path_that_resolves_elsewhere(profile) -> None:
    data = _data_folder(profile.home)
    with patch.object(link_guard, "_windows", return_value=True), patch.object(link_guard, "_long_name", lambda p: p):
        with patch.object(link_guard.os.path, "realpath", return_value=str(profile.elsewhere / ".defenseclaw")):
            with pytest.raises(click.ClickException) as refused:
                cmd_uninstall._remove_data_dir(str(data), platform_name="win32")
    assert "resolves to" in refused.value.message and (data / "audit.db").exists()

# --- hardening round 4: a short name with a missing tail, a mapped network drive, a subst drive ---------------------


@contextlib.contextmanager
def _nt(*, exists=(), real=None, denied=()):
    """link_guard seen on Windows with ntpath: *exists* are the paths that exist, *real* maps a path to its real path.

    *denied* are paths whose lstat is refused (access denied): they are there, but cannot be read.
    """
    import ntpath

    def key(p: str) -> str:
        return ntpath.normcase(p).rstrip("\\")

    there, refused = {key(e) for e in exists}, {key(d) for d in denied}

    def lstat(p: str):
        if key(p) in refused:
            raise PermissionError(13, "access denied", p)
        if key(p) not in there:
            raise FileNotFoundError(2, "no such file", p)
        return SimpleNamespace(st_mode=0o040000)

    names = {name: getattr(ntpath, name) for name in dir(ntpath) if not name.startswith("__")}
    names["realpath"] = real or (lambda p: p)
    fake = SimpleNamespace(path=SimpleNamespace(**names), name="nt", lstat=lstat)
    # The component look (lstat on every folder) is not what these tests are about: no link is on the way.
    with patch.object(link_guard, "os", fake), patch.object(link_guard, "links_on_path", return_value=[]):
        yield


def test_a_short_name_with_a_missing_tail_is_the_same_place() -> None:
    # GetLongPathName fails for a path that does not exist; realpath expands the part that does.
    short = r"C:\revprobe\LONGFO~1\sub\missing\x.json"
    real = lambda p: p.replace("LONGFO~1", "LongFolderName")  # noqa: E731
    exists = [r"C:\revprobe\LONGFO~1\sub", r"C:\revprobe\LONGFO~1", r"C:\revprobe", "C:\\"]
    long_of = lambda p: p.replace("LONGFO~1", "LongFolderName")  # noqa: E731
    with patch.object(link_guard, "_windows", return_value=True), patch.object(link_guard, "_long_name", long_of):
        with _nt(exists=exists, real=real):
            assert link_guard.link_problem(short) is None
            assert link_guard.link_problem(short, include_self=False) is None
            assert link_guard.link_problem(short.upper()) is None
        # The existing part still has to be where it is written.
        with _nt(exists=exists, real=lambda p: p.replace("LONGFO~1", "Elsewhere")):
            problem = link_guard.link_problem(short)
    assert problem is not None and "a link" in problem and r"C:\revprobe\Elsewhere\sub\missing\x.json" in problem


def test_a_mapped_network_drive_is_its_unc_target_and_a_later_link_still_counts() -> None:
    home = r"H:\users\vn\.defenseclaw"
    exists = [r"H:\users\vn", r"H:\users", "H:\\"]
    unc = lambda p: p.replace("H:", r"\\srv\share")  # noqa: E731
    with patch.object(link_guard, "_windows", return_value=True), patch.object(link_guard, "_long_name", lambda p: p):
        with patch.object(link_guard, "_drive_kind", return_value=("network", r"\\srv\share")):
            with _nt(exists=exists, real=unc):
                assert link_guard.link_problem(home) is None
                assert link_guard.link_problem(r"H:\users\vn", include_self=False) is None
            # A DFS root: the share name WNetGetConnection gives is not what realpath says, but the root is.
            dfs = lambda p: p.replace("H:", r"\\dfs\ns\home")  # noqa: E731
            with _nt(exists=exists, real=dfs):
                assert link_guard.link_problem(home) is None
            # A link made under the mapped drive after the look still resolves elsewhere.
            moved = lambda p: p.replace(r"H:\users", r"\\srv\share\other") if p.startswith(r"H:\users") else unc(p)  # noqa: E731
            with _nt(exists=exists, real=moved):
                problem = link_guard.link_problem(home)
    assert problem is not None and "reached through a link" in problem and "subst" not in problem


def test_a_subst_drive_is_refused_and_named() -> None:
    with patch.object(link_guard, "_windows", return_value=True), patch.object(link_guard, "_long_name", lambda p: p):
        with patch.object(link_guard, "_drive_kind", return_value=("subst", "")):
            with _nt(exists=[r"X:\data", "X:\\"], real=lambda p: p.replace("X:", r"C:\real")):
                problem = link_guard.link_problem(r"X:\data\.defenseclaw")
                # Even a realpath that does not follow the substitution is refused.
            with _nt(exists=[r"X:\data", "X:\\"]):
                same = link_guard.link_problem(r"X:\data\.defenseclaw")
    for found in (problem, same):
        assert found is not None and "a substituted drive (subst)" in found and "a link" not in found
        assert "subst X: /d" in found.step and "ask an administrator" in found.step
    assert r"C:\real\data\.defenseclaw" in problem


def test_a_component_that_cannot_be_read_is_compared_not_skipped() -> None:
    # os.path.lexists turns "access denied" into "missing"; the part is then left out of the real-path check.
    written = r"C:\u\denied\child\x.json"
    exists = [r"C:\u\denied", r"C:\u", "C:\\"]
    denied = [r"C:\u\denied\child"]
    with patch.object(link_guard, "_windows", return_value=True), patch.object(link_guard, "_long_name", lambda p: p):
        with _nt(exists=exists, denied=denied, real=lambda p: p.replace("child", "other")):
            problem = link_guard.link_problem(written)
        with _nt(exists=exists, denied=denied):
            same = link_guard.link_problem(written)
    assert problem is not None and "a link" in problem and r"C:\u\denied\other\x.json" in problem
    assert same is None


def _boom(error: BaseException):
    def raiser(*_args, **_kwargs):
        raise error

    return raiser


@pytest.mark.parametrize(
    ("what", "error"),
    [
        ("realpath", OSError(1920, "The file cannot be accessed by the system")),
        ("realpath", ValueError("embedded null character")),
        ("realpath", RuntimeError("Symlink loop")),
        ("_long_name", OSError(5, "access denied")),
        ("_drive_kind", OSError(5, "access denied")),
    ],
)
@pytest.mark.parametrize("include_self", [True, False])
def test_a_real_path_that_cannot_be_determined_is_refused_and_named(what: str, error, include_self: bool) -> None:
    path = r"Z:\users\vn\.defenseclaw"
    exists = [r"Z:\users\vn", r"Z:\users", "Z:\\"]
    helpers = {"_long_name": lambda p: p, "_drive_kind": lambda d: ("network", r"\\srv\share")}
    if what != "realpath":
        helpers[what] = _boom(error)
    with patch.object(link_guard, "_windows", return_value=True):
        with _nt(exists=exists, real=_boom(error) if what == "realpath" else None):
            with patch.multiple(link_guard, **helpers):
                problem = link_guard.link_problem(path, include_self=include_self)
                elsewhere = link_guard.resolves_elsewhere(path, include_self=include_self)
    assert problem is not None, "a path whose real location is unknown must be refused, not accepted"
    assert f"its real location cannot be determined ({type(error).__name__})" in problem
    assert path in problem and "Ask an administrator" in problem.step
    assert "rmdir" not in problem.step and "subst" not in problem.step
    assert elsewhere, "resolves_elsewhere must be non-empty so that no caller removes the path"


def test_a_path_that_cannot_be_checked_never_raises_from_the_component_look() -> None:
    path = "C:\\users\\vn\\.defenseclaw"
    with patch.object(link_guard, "_windows", return_value=True):
        with patch.object(link_guard, "links_on_path", side_effect=ValueError("embedded null character")):
            problem = link_guard.link_problem(path)
            dangling = link_guard.dangling_link_problem(path)
    assert problem is not None and "its real location cannot be determined (ValueError)" in problem
    assert "Ask an administrator" in problem.step
    assert dangling is None, "the dangling-link note is only a note; link_problem is the gate"


def test_a_target_that_cannot_be_read_is_not_a_traceback_for_the_dangling_note(tmp_path: Path) -> None:
    target = tmp_path / "t"
    target.mkdir()
    link = tmp_path / "l"
    with contextlib.suppress(OSError):
        link.symlink_to(target, target_is_directory=True)
    if not link.is_symlink():
        pytest.skip("cannot make a symlink here")
    with patch.object(link_guard.os, "stat", side_effect=ValueError("embedded null character")):
        assert link_guard.dangling_link_problem(str(link / "x")) is None


def _fake_ctypes(device: str, *, wnet: int, remote: str = ""):
    """A ctypes stand-in whose QueryDosDevice says *device* and whose WNetGetConnection returns *wnet*."""

    class Buffer:
        value = ""

        def __len__(self) -> int:
            return 1024

    def query(_drive, buffer, _size):
        buffer.value = device
        return 1

    def wnet_connection(_drive, buffer, _size):
        buffer.value = remote
        return wnet

    return SimpleNamespace(
        create_unicode_buffer=lambda _n: Buffer(),
        c_ulong=lambda n: n,
        byref=lambda x: x,
        windll=SimpleNamespace(
            kernel32=SimpleNamespace(QueryDosDeviceW=query), mpr=SimpleNamespace(WNetGetConnectionW=wnet_connection)
        ),
    )


@pytest.mark.parametrize(
    ("device", "wnet", "expected"),
    [
        (r"\Device\LanmanRedirector\;Z:0\srv\share", 0, ("network", r"\\srv\share")),
        (r"\Device\LanmanRedirector\;Z:0\srv\share", 1222, ("network", "")),
        (r"\Device\Mup\srv\share", 1222, ("network", "")),
        (r"\??\UNC\srv\share", 0, ("network", r"\\srv\share")),
        # A raw \??\UNC\ target the network provider does not know is a substitution, not a mapped drive.
        (r"\??\UNC\srv\share", 1222, ("subst", "")),
        (r"\??\C:\Users", 1222, ("subst", "")),
    ],
)
def test_the_drive_kind_trusts_a_share_only_when_the_network_provider_knows_it(device, wnet, expected) -> None:
    ctypes_stub = _fake_ctypes(device, wnet=wnet, remote=r"\\srv\share")
    with patch.object(link_guard, "_windows", return_value=True), patch.dict(sys.modules, {"ctypes": ctypes_stub}):
        assert link_guard._drive_kind("Z:") == expected


def _free_letter() -> str:
    return next(letter for letter in "ZYXWVUTSR" if not os.path.exists(f"{letter}:\\"))


@windows_only
def test_real_short_names_are_the_same_place_with_and_without_a_missing_tail(tmp_path: Path) -> None:
    import ctypes

    folder = tmp_path.resolve() / "A Long Folder Name For Short Names" / "sub"
    folder.mkdir(parents=True)
    size = ctypes.windll.kernel32.GetShortPathNameW(str(folder), None, 0)
    short = ""
    if size:
        buffer = ctypes.create_unicode_buffer(size)
        ctypes.windll.kernel32.GetShortPathNameW(str(folder), buffer, size)
        short = buffer.value
    if not short or os.path.normcase(short) == os.path.normcase(str(folder)):
        pytest.skip("8.3 short names are disabled on this volume, so there is no short name to compare")
    assert "~" in short
    assert link_guard.link_problem(short) is None
    assert link_guard.link_problem(short.upper()) is None
    assert link_guard.link_problem(os.path.join(short, "missing", "x.json")) is None
    assert link_guard.link_problem(os.path.join(short, "missing"), include_self=False) is None
    # A link made at the missing part afterwards is still refused.
    elsewhere = tmp_path.resolve() / "elsewhere"
    elsewhere.mkdir()
    _link(folder / "linked", elsewhere)
    found = link_guard.link_problem(os.path.join(short, "linked", "x.json"))
    assert found is not None and "is a " in found


@windows_only
def test_a_real_subst_drive_is_refused_and_a_mapped_admin_share_is_not(tmp_path: Path) -> None:
    base = tmp_path.resolve()
    (base / "data").mkdir()
    letter = _free_letter()
    if subprocess.run(["subst", f"{letter}:", str(base)], capture_output=True, timeout=30).returncode != 0:
        pytest.skip("subst is not available here")
    try:
        found = link_guard.link_problem(f"{letter}:\\data\\.defenseclaw")
        assert found is not None and "a substituted drive (subst)" in found and f"subst {letter}: /d" in found.step
    finally:
        subprocess.run(["subst", f"{letter}:", "/d"], capture_output=True, timeout=30)
    drive, rest = os.path.splitdrive(str(base))
    if len(drive) != 2:
        pytest.skip("the test folder is not on a lettered drive")
    letter = _free_letter()
    share = rf"\\localhost\{drive[0]}$"
    mapped = subprocess.run(["net", "use", f"{letter}:", share], capture_output=True, timeout=60)
    if mapped.returncode != 0:
        pytest.skip(f"cannot map {share} here (net use rc {mapped.returncode})")
    try:
        assert link_guard.link_problem(f"{letter}:{rest}\\data\\.defenseclaw") is None
        assert link_guard.link_problem(f"{letter}:{rest}\\data") is None
    finally:
        subprocess.run(["net", "use", f"{letter}:", "/delete", "/y"], capture_output=True, timeout=60)


@windows_only
def test_a_real_junction_under_a_mapped_network_drive_stays_refused_and_named(tmp_path: Path) -> None:
    base = tmp_path.resolve()
    (base / "data").mkdir()
    (base / "elsewhere").mkdir()
    drive, rest = os.path.splitdrive(str(base))
    if len(drive) != 2:
        pytest.skip("the test folder is not on a lettered drive")
    letter = _free_letter()
    share = rf"\\localhost\{drive[0]}$"
    mapped = subprocess.run(["net", "use", f"{letter}:", share], capture_output=True, timeout=60)
    if mapped.returncode != 0:
        pytest.skip(f"cannot map {share} here (net use rc {mapped.returncode}: administrator rights are needed)")
    try:
        home = f"{letter}:{rest}\\data"
        assert link_guard.link_problem(home + "\\.defenseclaw") is None, "the clean mapped path is accepted"
        junction = f"{home}\\linked"
        made = subprocess.run(
            ["cmd.exe", "/d", "/c", "mklink", "/J", junction, str(base / "elsewhere")],
            capture_output=True,
            text=True,
            check=False,
        )
        if made.returncode != 0:  # the share refuses a junction made through it: make the same one on the server side
            _junction(base / "data" / "linked", base / "elsewhere")
        for written in (junction, junction + "\\.defenseclaw", junction + "\\missing\\x.json"):
            found = link_guard.link_problem(written)
            assert found is not None, written
            assert "is a junction" in found and os.path.normcase(junction) in os.path.normcase(found), found
            assert "rmdir" in found.step
        # The clean sibling under the same mapped drive is still accepted.
        assert link_guard.link_problem(home + "\\.defenseclaw") is None
    finally:
        subprocess.run(["net", "use", f"{letter}:", "/delete", "/y"], capture_output=True, timeout=60)
