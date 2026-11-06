# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""`defenseclaw uninstall` removes a DefenseClaw Setup 0.8.x install left beside it.

install.ps1 leaves a 0.8.x Setup install alone when its data is in another
folder (DEFENSECLAW_HOME). Uninstall used to hand off to that Setup and
refused outright, because the 0.8.x Setups were unsigned (cowork-1-0-8
GAP-0088 review L5). Now it removes the install itself, without running any
of its programs, and keeps its data folder.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.commands import cmd_uninstall, legacy_setup_install  # noqa: E402


def _install(local: Path, *, version: str = "0.8.10", data_root: str = "", **fields) -> Path:
    root = local / "Programs" / "DefenseClaw"
    (root / "installer").mkdir(parents=True)
    (root / "bin").mkdir()
    (root / "bin" / "defenseclaw-gateway.exe").write_bytes(b"MZ")
    state = {
        "schema_version": 1,
        "version": version,
        "install_kind": "native-windows-exe",
        "install_scope": "user",
        "install_root": str(root),
        "data_root": data_root,
        "unsigned_local_artifact": True,
        **fields,
    }
    (root / "installer" / "install-state.json").write_text(json.dumps(state), encoding="utf-8")
    cache = local / "DefenseClaw" / "InstallerCache"
    cache.mkdir(parents=True)
    (cache / "DefenseClawSetup-x64.exe").write_bytes(b"MZ")
    return root


@pytest.fixture
def local(tmp_path: Path):
    local = tmp_path.resolve() / "LocalAppData"
    local.mkdir()
    with (
        patch.object(legacy_setup_install, "local_app_data", return_value=str(local)),
        patch.object(legacy_setup_install, "_ownership_problem", return_value=""),
    ):
        yield local


def test_nothing_is_found_off_windows_or_without_a_setup_install(local: Path) -> None:
    assert legacy_setup_install.find("linux") is None
    assert legacy_setup_install.find("win32") is None
    _install(local)
    assert legacy_setup_install.find("darwin") is None


def test_a_released_0_8_setup_install_is_found(local: Path, tmp_path: Path) -> None:
    root = _install(local, data_root=str(tmp_path / "profile" / ".defenseclaw"))
    found = legacy_setup_install.find("win32")
    assert found is not None
    assert found.problem == ""
    assert found.root == str(root)
    assert found.version == "0.8.10"
    assert found.cache == str(local / "DefenseClaw" / "InstallerCache")


def test_only_released_0_x_setups_are_taken(local: Path) -> None:
    # A per-user Setup newer than 0.8.x was never released.
    _install(local, version="1.0.9")
    assert legacy_setup_install.find("win32") is None


def test_an_install_that_is_not_the_users_own_stays(local: Path) -> None:
    _install(local, install_root="C:\\Other\\DefenseClaw")
    found = legacy_setup_install.find("win32")
    assert found is not None
    assert "another program folder" in found.problem
    done, problems = legacy_setup_install.remove(found, edit_user_path=lambda _path: False)
    assert done == []
    assert problems and "another program folder" in problems[0]
    assert (local / "Programs" / "DefenseClaw").is_dir()


def test_another_owner_leaves_the_install_in_place(tmp_path: Path) -> None:
    local = tmp_path.resolve() / "LocalAppData"
    _install(local)
    with (
        patch.object(legacy_setup_install, "local_app_data", return_value=str(local)),
        patch.object(
            legacy_setup_install,
            "_ownership_problem",
            return_value="its program folder belongs to another account (S-1-5-32-544)",
        ),
    ):
        found = legacy_setup_install.find("win32")
    assert found is not None and "another account" in found.problem


def test_a_running_install_is_never_removed_from_under_this_command(local: Path) -> None:
    root = _install(local)
    with patch.object(legacy_setup_install.sys, "executable", str(root / "runtime" / "python" / "python.exe")):
        found = legacy_setup_install.find("win32")
    assert found is not None and found.problem == "this command runs from that install"


def test_unreadable_state_is_reported_not_guessed(local: Path) -> None:
    root = _install(local)
    (root / "installer" / "install-state.json").write_text("{not json", encoding="utf-8")
    found = legacy_setup_install.find("win32")
    assert found is not None and "not valid JSON" in found.problem


def _hook_state(local: Path, hook: Path) -> Path:
    state = local / "DefenseClaw" / "HookRuntime" / "hook-runtime-state.json"
    state.parent.mkdir(parents=True, exist_ok=True)
    state.write_text(json.dumps({"schema_version": 2, "status": "active", "hook_path": str(hook)}), encoding="utf-8")
    return state


def test_remove_takes_every_part_and_never_runs_a_program(local: Path) -> None:
    root = _install(local)
    hook_state = _hook_state(local, root / "bin" / "defenseclaw-hook.exe")
    found = legacy_setup_install.find("win32")
    assert found is not None
    paths: list[str] = []
    with (
        patch.object(legacy_setup_install, "_stop_processes_under", return_value=2) as stop,
        patch.object(legacy_setup_install, "_remove_run_values", return_value=["DefenseClaw"]) as run_values,
        patch.object(legacy_setup_install, "_remove_uninstall_entry", return_value=True) as entry,
        patch("subprocess.run", side_effect=AssertionError("no program of the old install runs")),
        patch("subprocess.Popen", side_effect=AssertionError("no program of the old install runs")),
    ):
        done, problems = legacy_setup_install.remove(found, edit_user_path=lambda path: paths.append(path) or True)
    assert problems == []
    stop.assert_called_once_with(str(root))
    run_values.assert_called_once_with(str(root), found.cache)
    entry.assert_called_once_with(str(root))
    assert paths == [str(root / "bin")]
    assert not root.exists()
    assert not Path(found.cache).exists()
    # The launcher state that ran the old hook is gone, so the launcher does nothing.
    assert not hook_state.exists()
    text = "\n".join(done)
    assert "stopped 2" in text and "sign-in start" in text and "Apps & Features" in text


def test_the_launcher_state_install_ps1_published_is_not_the_old_installs(local: Path) -> None:
    _install(local)
    delegated = local / "DefenseClaw" / "HookRuntime" / "delegated" / ("0" * 32) / "defenseclaw-hook.exe"
    hook_state = _hook_state(local, delegated)
    assert not legacy_setup_install._turn_hook_launcher_off(str(hook_state), str(local / "Programs" / "DefenseClaw"))
    assert hook_state.exists()


def test_a_step_that_fails_leaves_the_others_done(local: Path) -> None:
    root = _install(local)
    found = legacy_setup_install.find("win32")
    assert found is not None
    with (
        patch.object(legacy_setup_install, "_stop_processes_under", side_effect=OSError("access is denied")),
        patch.object(legacy_setup_install, "_remove_run_values", return_value=[]),
        patch.object(legacy_setup_install, "_remove_uninstall_entry", return_value=False),
    ):
        done, problems = legacy_setup_install.remove(found, edit_user_path=lambda _path: False)
    assert problems == [f"could not stop the programs running from {root}: access is denied"]
    assert not root.exists()
    assert f"removed {root}" in done


def test_plan_lines_keep_the_old_data_folder(local: Path, tmp_path: Path) -> None:
    old_data = tmp_path / "profile" / ".defenseclaw"
    old_data.mkdir(parents=True)
    _install(local, data_root=str(old_data))
    found = legacy_setup_install.find("win32")
    assert found is not None
    lines = legacy_setup_install.plan_lines(found, str(tmp_path / "other-home"))
    assert lines[0].startswith("DefenseClaw Setup 0.8.10 at ")
    assert any(f"kept: its data folder {old_data}" in line for line in lines)
    # Its data folder is this install's: nothing extra to say.
    assert len(legacy_setup_install.plan_lines(found, str(old_data))) == 1


def test_setup_leftovers_go_once_the_old_install_is_removed(local: Path) -> None:
    root = _install(local)
    _hook_state(local, root / "bin" / "defenseclaw-hook.exe")
    (local / "DefenseClaw" / "InstallerState").mkdir()
    with patch.object(cmd_uninstall.legacy_setup_install, "local_app_data", return_value=str(local)):
        # The install still owns them.
        assert cmd_uninstall._windows_setup_leftovers("win32") == ()
        found = legacy_setup_install.find("win32")
        assert found is not None
        leftovers = cmd_uninstall._windows_setup_leftovers("win32", found)
    assert set(leftovers) == {
        str(local / "DefenseClaw" / "HookRuntime"),
        str(local / "DefenseClaw" / "InstallerState"),
    }


def test_an_install_that_stays_keeps_its_leftovers(local: Path) -> None:
    _install(local, install_root="C:\\Other\\DefenseClaw")
    (local / "DefenseClaw" / "InstallerState").mkdir()
    with patch.object(cmd_uninstall.legacy_setup_install, "local_app_data", return_value=str(local)):
        found = legacy_setup_install.find("win32")
        assert found is not None and found.problem
        assert cmd_uninstall._windows_setup_leftovers("win32", found) == ()


def _uninstall(found, result) -> tuple[int, str]:
    plan = cmd_uninstall.UninstallPlan(platform_name="win32", legacy_setup=found)
    with (
        patch.object(cmd_uninstall, "_build_plan", return_value=plan) as build,
        patch.object(cmd_uninstall, "_execute_plan", return_value=result),
        patch.object(cmd_uninstall, "_configured_gateway_ports", return_value=frozenset()),
        patch.object(cmd_uninstall, "_remove_marked_native_otel_left"),
        patch.object(cmd_uninstall, "_render_kept_and_next_steps"),
    ):
        outcome = CliRunner().invoke(cmd_uninstall.uninstall_cmd, ["--yes"])
    assert build.call_args.kwargs["legacy_setup"] is True
    return outcome.exit_code, " ".join(outcome.output.split())


def test_uninstall_shows_the_old_install_in_the_plan_and_exits_zero_when_it_went(local: Path) -> None:
    _install(local)
    found = legacy_setup_install.find("win32")
    result = cmd_uninstall.ExecutionResult(
        (cmd_uninstall.ExecutionPhaseResult("DefenseClaw Setup 0.8.x removal", "succeeded"),)
    )
    code, output = _uninstall(found, result)
    assert code == 0, output
    assert "DefenseClaw Setup: DefenseClaw Setup 0.8.10 at" in output
    assert "not removed completely" not in output


def test_uninstall_exits_one_and_says_what_stayed(local: Path) -> None:
    _install(local)
    found = legacy_setup_install.find("win32")
    result = cmd_uninstall.ExecutionResult(
        (cmd_uninstall.ExecutionPhaseResult("DefenseClaw Setup 0.8.x removal", "failed", "could not remove X: in use"),)
    )
    code, output = _uninstall(found, result)
    assert code == 1
    assert "DefenseClaw Setup 0.8.x was not removed completely: could not remove X: in use" in output


def test_reset_never_looks_for_the_old_install() -> None:
    with (
        patch.object(cmd_uninstall, "_build_plan", return_value=cmd_uninstall.UninstallPlan()) as build,
        patch.object(cmd_uninstall, "_execute_plan"),
    ):
        CliRunner().invoke(cmd_uninstall.reset_cmd, ["--yes"])
    assert "legacy_setup" not in build.call_args.kwargs


def test_execute_plan_removes_the_old_install_after_teardown_and_before_leftovers(local: Path) -> None:
    root = _install(local)
    found = legacy_setup_install.find("win32")
    order: list[str] = []
    plan = cmd_uninstall.UninstallPlan(platform_name="win32", legacy_setup=found, remove_binaries=True)

    def remove(install, *, edit_user_path):
        order.append("legacy")
        return [f"removed {install.root}"], []

    with (
        patch.object(cmd_uninstall, "_validate_plan"),
        patch.object(cmd_uninstall.legacy_setup_install, "remove", side_effect=remove),
        patch.object(
            cmd_uninstall, "_windows_setup_leftovers", side_effect=lambda *_a: order.append("leftovers") or ("x",)
        ),
        patch.object(
            cmd_uninstall, "_remove_setup_leftovers", side_effect=lambda paths: order.append(f"remove {paths}")
        ),
        patch.object(cmd_uninstall, "_print_removed_connector_leftovers"),
        patch.object(cmd_uninstall, "_remove_binaries"),
        patch.object(cmd_uninstall, "_render_execution_result"),
    ):
        result = cmd_uninstall._execute_plan(plan)
    assert order[:3] == ["legacy", "leftovers", "remove ('x',)"]
    phase = next(p for p in result.phases if p.name == "DefenseClaw Setup 0.8.x removal")
    assert phase.status == "succeeded"
    assert root.exists()  # remove() was stubbed
