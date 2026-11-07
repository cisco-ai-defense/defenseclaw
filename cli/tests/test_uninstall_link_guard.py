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
    assert f"{link} is a {kind} whose target is missing" in problem
    assert f'cmd /c rmdir "{link}"' in problem.step and "nothing is behind it" in problem.step
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
    with patch.object(
        legacy_setup_install, "_read_state", side_effect=AssertionError("nothing is read through a link")
    ):
        found = legacy_setup_install.find("win32")
    assert found is not None
    assert found.root == os.path.join(profile.local, "Programs", "DefenseClaw")
    _named(found.problem, found.problem_step, link, kind)
    assert "whose target is missing" in found.problem
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
    assert f"- {link} is a {kind} whose target is missing, so nothing is behind it." in output
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
    assert "whose target is missing" in found.problem
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
