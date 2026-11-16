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

import contextlib
import json
import os
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw import link_guard  # noqa: E402
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


# The scoping rules, checked against real Windows state: a real registry key,
# a real junction, a real owner and real processes. Only the hive path is the
# test's own, so no test touches the account's real Run or Uninstall entries.

windows_only = pytest.mark.skipif(sys.platform != "win32", reason="real Windows registry, ACL and process checks")

_LOCAL = "c:\\users\\u\\appdata\\local\\"
_PREFIXES = (_LOCAL + "programs\\defenseclaw\\", _LOCAL + "defenseclaw\\installercache\\")


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        ('"' + _PREFIXES[0] + 'bin\\defenseclaw-startup.exe" --sign-in', True),
        (_PREFIXES[0] + "bin\\defenseclaw-startup.exe", True),
        ('  "' + _PREFIXES[1] + 'defenseclawsetup-x64.exe" /resume', True),
        # Another program that only passes the folder as an argument is not this install's.
        ('"c:\\windows\\system32\\cmd.exe" /c dir "' + _PREFIXES[0] + 'bin"', False),
        ("c:\\tools\\sync.exe " + _PREFIXES[0], False),
        # A sibling folder whose name only starts the same way.
        ('"' + _LOCAL + 'programs\\defenseclawother\\bin\\x.exe"', False),
        ("", False),
    ],
)
def test_a_run_value_is_the_installs_only_when_its_program_starts_in_the_folder(command: str, expected: bool) -> None:
    assert legacy_setup_install._starts_in(command, _PREFIXES) is expected


@pytest.fixture
def hkcu_key(monkeypatch):
    """A fresh HKCU key for one test; the module's Run and Uninstall paths point under it."""
    import winreg

    base = rf"Software\DefenseClawTest\{uuid.uuid4().hex}"
    monkeypatch.setattr(legacy_setup_install, "_RUN_KEY", base + r"\Run")
    monkeypatch.setattr(legacy_setup_install, "_UNINSTALL_KEY", base + r"\Uninstall\DefenseClaw")
    yield base
    with contextlib.suppress(FileNotFoundError):
        legacy_setup_install._delete_key_tree(winreg.HKEY_CURRENT_USER, base)
    with contextlib.suppress(OSError):
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, r"Software\DefenseClawTest")


def _values(path: str) -> dict[str, str]:
    import winreg

    found: dict[str, str] = {}
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path) as key:
        index = 0
        while True:
            try:
                name, value, _kind = winreg.EnumValue(key, index)
            except OSError:
                return found
            found[name] = value
            index += 1


@windows_only
def test_real_run_key_loses_only_the_values_that_start_in_the_install(hkcu_key: str, tmp_path: Path) -> None:
    import winreg

    root = tmp_path / "Programs" / "DefenseClaw"
    cache = tmp_path / "DefenseClaw" / "InstallerCache"
    values = {
        "DefenseClaw": f'"{root}\\bin\\defenseclaw-startup.exe" --sign-in',
        "DefenseClawSetupResume": f"{cache}\\DefenseClawSetup-x64.exe /resume",
        "Unrelated": r'"C:\Windows\System32\notepad.exe"',
        "PassesTheFolder": f'"C:\\Windows\\System32\\cmd.exe" /c dir "{root}\\bin"',
        "Sibling": f'"{root}Other\\bin\\x.exe"',
        "NotAString": b"\x00",
    }
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, legacy_setup_install._RUN_KEY) as key:
        for name, value in values.items():
            kind = winreg.REG_BINARY if isinstance(value, bytes) else winreg.REG_SZ
            winreg.SetValueEx(key, name, 0, kind, value)
    removed = legacy_setup_install._remove_run_values(str(root), str(cache))
    assert sorted(removed) == ["DefenseClaw", "DefenseClawSetupResume"]
    assert sorted(_values(legacy_setup_install._RUN_KEY)) == ["NotAString", "PassesTheFolder", "Sibling", "Unrelated"]


@windows_only
def test_real_uninstall_entry_of_another_location_stays(hkcu_key: str, tmp_path: Path) -> None:
    import winreg

    root = tmp_path / "Programs" / "DefenseClaw"
    path = legacy_setup_install._UNINSTALL_KEY
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, path) as key:
        winreg.SetValueEx(key, "InstallLocation", 0, winreg.REG_SZ, str(tmp_path / "Programs" / "DefenseClawOther"))
    winreg.CreateKey(winreg.HKEY_CURRENT_USER, path + r"\Child").Close()
    assert legacy_setup_install._remove_uninstall_entry(str(root)) is False
    assert _values(path)["InstallLocation"].endswith("DefenseClawOther")
    # The same folder, spelled with another case and a trailing separator, is this install.
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_SET_VALUE) as key:
        winreg.SetValueEx(key, "InstallLocation", 0, winreg.REG_SZ, str(root).upper() + "\\")
    assert legacy_setup_install._remove_uninstall_entry(str(root)) is True
    with pytest.raises(FileNotFoundError):
        winreg.OpenKey(winreg.HKEY_CURRENT_USER, path).Close()


def _junction(link: Path, target: Path) -> None:
    result = subprocess.run(
        ["cmd.exe", "/d", "/c", "mklink", "/J", str(link), str(target)], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.fixture
def real_local(tmp_path: Path):
    """A LocalAppData whose ownership checks run for real."""
    local = tmp_path.resolve() / "LocalAppData"
    local.mkdir()
    with patch.object(legacy_setup_install, "local_app_data", return_value=str(local)):
        yield local


def _set_owner(path: Path, sid: str) -> None:
    result = subprocess.run(["icacls", str(path), "/setowner", "*" + sid], capture_output=True, text=True, check=False)
    if result.returncode != 0:
        pytest.skip(f"setting the owner of {path} to {sid} failed: {result.stdout.strip()}")


@windows_only
def test_real_own_program_folder_passes_the_owner_check(real_local: Path) -> None:
    from defenseclaw.file_permissions import _windows_current_user_sid

    root = _install(real_local)
    # The 0.8.x Setup ran as the user, so its folder is the user's. Under an
    # elevated token new folders belong to Administrators instead; give this
    # one the owner a Setup install has.
    _set_owner(root, _windows_current_user_sid())
    assert legacy_setup_install._ownership_problem(str(root)) == ""
    found = legacy_setup_install.find("win32")
    assert found is not None and found.problem == ""


@windows_only
def test_real_program_folder_that_is_a_junction_is_refused(real_local: Path, tmp_path: Path) -> None:
    elsewhere = tmp_path / "elsewhere"
    root = _install(elsewhere)
    (real_local / "Programs").mkdir()
    _junction(real_local / "Programs" / "DefenseClaw", root)
    problem = legacy_setup_install._ownership_problem(str(real_local / "Programs" / "DefenseClaw"))
    assert f"{real_local / 'Programs' / 'DefenseClaw'} is a junction" in problem
    assert f'cmd /c rmdir "{real_local / "Programs" / "DefenseClaw"}"' in problem.step


@windows_only
def test_real_program_folder_below_a_junction_is_refused(real_local: Path, tmp_path: Path) -> None:
    elsewhere = tmp_path / "elsewhere"
    _install(elsewhere)
    _junction(real_local / "Programs", elsewhere / "Programs")
    # install-state.json names the real folder, so point it at the linked path the
    # Known Folder gives; only the link above the folder is left to refuse it.
    state_path = real_local / "Programs" / "DefenseClaw" / "installer" / "install-state.json"
    state = json.loads(state_path.read_text(encoding="utf-8"))
    state["install_root"] = str(real_local / "Programs" / "DefenseClaw")
    state_path.write_text(json.dumps(state), encoding="utf-8")
    linked = real_local / "Programs" / "DefenseClaw"
    problem = legacy_setup_install._ownership_problem(str(linked))
    assert f"{real_local / 'Programs'} is a junction" in problem
    assert f'cmd /c rmdir "{real_local / "Programs"}"' in problem.step
    # find() stops even earlier: the install state is never read through a link.
    found = legacy_setup_install.find("win32")
    assert found is not None
    assert f"{real_local / 'Programs'} is a junction" in found.problem
    assert "yourself" not in found.problem_step
    done, problems = legacy_setup_install.remove(found, edit_user_path=lambda _path: True)
    assert done == [] and problems
    assert (elsewhere / "Programs" / "DefenseClaw" / "bin" / "defenseclaw-gateway.exe").is_file()


@windows_only
def test_real_program_folder_owned_by_another_account_is_refused(real_local: Path) -> None:
    from defenseclaw.file_permissions import _windows_current_user_sid

    root = _install(real_local)
    system = "S-1-5-18"
    _set_owner(root, system)

    assert _windows_current_user_sid() != system
    found = legacy_setup_install.find("win32")
    assert found is not None
    # Windows names the account as well as the SID (NT AUTHORITY\SYSTEM, S-1-5-18).
    assert found.problem.startswith("its program folder belongs to another account (")
    assert f"{system})" in found.problem.split(";")[0]
    assert "delete the folder yourself" in found.problem
    done, problems = legacy_setup_install.remove(found, edit_user_path=lambda _path: True)
    assert done == [] and problems
    assert (root / "bin" / "defenseclaw-gateway.exe").is_file()


@windows_only
def test_real_program_folder_owned_by_administrators_is_removed(real_local: Path) -> None:
    from defenseclaw.file_permissions import _windows_current_user_sid

    root = _install(real_local)
    administrators = "S-1-5-32-544"
    # What an elevated install, Windows Server or a UAC-off account leaves.
    _set_owner(root, administrators)

    assert _windows_current_user_sid() != administrators
    found = legacy_setup_install.find("win32")
    assert found is not None and found.problem == ""
    done, problems = legacy_setup_install.remove(found, edit_user_path=lambda _path: True)
    assert not problems and any(str(root) in line for line in done)
    assert not root.exists()


@pytest.mark.parametrize(
    ("owner", "refused"),
    (
        ("S-1-5-21-1-2-3-1001", False),  # this account
        ("S-1-5-32-544", False),  # Administrators: an elevated install
        ("S-1-5-18", True),  # SYSTEM
        ("S-1-5-21-1-2-3-1002", True),  # another user
        ("", True),
    ),
)
def test_the_owner_check_accepts_this_account_and_administrators_only(monkeypatch, owner: str, refused: bool) -> None:
    from defenseclaw import file_permissions
    from defenseclaw.commands import windows_uninstall_helper

    monkeypatch.setattr(link_guard, "is_reparse", lambda _path: False)
    monkeypatch.setattr(windows_uninstall_helper, "_validate_root", lambda _root, _label: None)
    monkeypatch.setattr(file_permissions, "_windows_acl_snapshot", lambda _path: (owner, False, []))
    monkeypatch.setattr(file_permissions, "_windows_current_user_sid", lambda: "S-1-5-21-1-2-3-1001")
    problem = legacy_setup_install._ownership_problem(r"C:\Users\u\AppData\Local\Programs\DefenseClaw")
    assert bool(problem) is refused
    if refused:
        assert "belongs to another account" in problem and "delete the folder yourself" in problem


@windows_only
def test_real_processes_stop_only_when_their_program_is_inside_the_folder(tmp_path: Path) -> None:
    ping = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "PING.EXE"
    root = tmp_path / "Programs" / "DefenseClaw"
    sibling = tmp_path / "Programs" / "DefenseClawOther"
    images = []
    for folder in (root / "bin", sibling / "bin"):
        folder.mkdir(parents=True)
        images.append(folder / "ping.exe")
        shutil.copyfile(ping, images[-1])
    images.append(ping)
    started = [
        subprocess.Popen(
            [str(image), "-n", "120", "127.0.0.1"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        for image in images
    ]
    try:
        time.sleep(0.5)
        assert all(process.poll() is None for process in started)
        assert legacy_setup_install._stop_processes_under(str(root)) == 1
        assert started[0].wait(timeout=15) == 1
        # The sibling folder and the system copy keep running.
        assert started[1].poll() is None and started[2].poll() is None
    finally:
        for process in started:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=15)


# --- GAP-0098: the closing advice follows why each part stayed -------------------------------------------


def _real_ownership(tmp_path: Path, owner: str, current: str = "S-1-5-21-1-2-3-1001"):
    local = tmp_path.resolve() / "LocalAppData"
    local.mkdir()
    _install(local)
    with (
        patch.object(legacy_setup_install, "local_app_data", return_value=str(local)),
        patch("defenseclaw.file_permissions._windows_acl_snapshot", return_value=(owner, False, [])),
        patch("defenseclaw.file_permissions._windows_current_user_sid", return_value=current),
    ):
        return legacy_setup_install.find("win32")


def test_a_folder_of_another_account_stays_with_a_step_for_an_administrator(tmp_path: Path) -> None:
    found = _real_ownership(tmp_path, "S-1-5-18")
    assert found is not None
    # Windows names the account too (NT AUTHORITY\SYSTEM, S-1-5-18); elsewhere the SID stands alone.
    assert "belongs to another account (" in found.problem and "S-1-5-18)" in found.problem
    assert found.problem_step.startswith("Ask an administrator, or the account that owns it (")
    assert "S-1-5-18), to remove " in found.problem_step
    assert found.root in found.problem_step
    assert "close" not in found.problem_step.lower()
    _done, problems = legacy_setup_install.remove(found, edit_user_path=lambda _path: False)
    assert [p.step for p in problems] == [found.problem_step]


def test_a_state_naming_another_folder_is_told_to_use_apps_and_features(local: Path) -> None:
    _install(local, install_root="C:\\Other\\DefenseClaw")
    found = legacy_setup_install.find("win32")
    assert found is not None and "Apps & Features" in found.problem_step


def test_a_command_run_from_the_old_install_is_told_to_use_another_defenseclaw(local: Path) -> None:
    root = _install(local)
    with patch.object(legacy_setup_install.sys, "executable", str(root / "runtime" / "python" / "python.exe")):
        found = legacy_setup_install.find("win32")
    assert found is not None
    assert "outside" in found.problem_step and "where.exe defenseclaw" in found.problem_step


def _winerror(code: int) -> OSError:
    error = OSError(code, "x")
    error.winerror = code
    return error


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        (32, "Close the program that holds "),
        (33, "Close the program that holds "),
        (5, "Your account cannot remove "),
        (1, "Remove "),
    ],
)
def test_a_path_that_cannot_be_removed_gets_the_step_for_its_reason(code: int, expected: str) -> None:
    step = legacy_setup_install._path_step(_winerror(code), "C:\\x")
    assert step.startswith(expected) and "C:\\x" in step


def test_several_reasons_give_one_step_each(local: Path) -> None:
    root = _install(local)
    found = legacy_setup_install.find("win32")
    assert found is not None
    cache = local / "DefenseClaw" / "InstallerCache"

    def remove_tree(path: str) -> bool:
        raise _winerror(32 if path == str(root) else 5)

    with (
        patch.object(legacy_setup_install, "_stop_processes_under", side_effect=OSError("could not stop PID 7")),
        patch.object(legacy_setup_install, "_remove_run_values", return_value=[]),
        patch.object(legacy_setup_install, "_remove_uninstall_entry", return_value=False),
        patch.object(legacy_setup_install, "_remove_tree", side_effect=remove_tree),
    ):
        _done, problems = legacy_setup_install.remove(found, edit_user_path=lambda _path: False)
    steps = [p.step for p in problems]
    assert len(steps) == 3
    assert steps[0].startswith("End the DefenseClaw programs running from ")
    assert steps[1] == f"Close the program that holds {root}, then run the command again."
    assert steps[2].startswith(f"Your account cannot remove {cache}")


def test_the_closing_lines_follow_the_stay_reason_not_a_generic_program_hint(local: Path) -> None:
    _install(local)
    found = legacy_setup_install.find("win32")
    steps = ("Ask an administrator, or the account that owns it (S-1-5-18), to remove C:\\x.",)
    result = cmd_uninstall.ExecutionResult(
        (cmd_uninstall.ExecutionPhaseResult("DefenseClaw Setup 0.8.x removal", "failed", "C:\\x: belongs", steps),)
    )
    code, output = _uninstall(found, result)
    assert code == 1
    assert "- Ask an administrator, or the account that owns it (S-1-5-18), to remove C:\\x." in output
    assert "close a program" not in output.lower()


def test_each_distinct_reason_prints_one_line(local: Path) -> None:
    _install(local)
    found = legacy_setup_install.find("win32")
    steps = ("Close the program that holds C:\\a, then run the command again.", "Ask an administrator to remove C:\\b.")
    result = cmd_uninstall.ExecutionResult(
        (cmd_uninstall.ExecutionPhaseResult("DefenseClaw Setup 0.8.x removal", "failed", "two things", steps),)
    )
    _code, output = _uninstall(found, result)
    assert output.count("- Close the program that holds C:\\a") == 1
    assert output.count("- Ask an administrator to remove C:\\b.") == 1


def test_a_failure_without_steps_says_nothing_about_programs(local: Path) -> None:
    _install(local)
    found = legacy_setup_install.find("win32")
    result = cmd_uninstall.ExecutionResult(
        (cmd_uninstall.ExecutionPhaseResult("DefenseClaw Setup 0.8.x removal", "failed", "could not remove X: in use"),)
    )
    _code, output = _uninstall(found, result)
    assert "Fix what is named above, then run the command again." in output
    assert "close a program" not in output.lower()


def test_execute_plan_carries_one_step_per_distinct_reason(local: Path) -> None:
    _install(local)
    found = legacy_setup_install.find("win32")
    plan = cmd_uninstall.UninstallPlan(platform_name="win32", legacy_setup=found)
    problems = [
        legacy_setup_install.Problem("a", "step one"),
        legacy_setup_install.Problem("b", "step one"),
        legacy_setup_install.Problem("c", "step two"),
    ]
    with (
        patch.object(cmd_uninstall, "_validate_plan"),
        patch.object(cmd_uninstall, "_remove_legacy_setup_install", return_value=problems),
        patch.object(cmd_uninstall, "_print_removed_connector_leftovers"),
        patch.object(cmd_uninstall, "_render_execution_result"),
    ):
        result = cmd_uninstall._execute_plan(plan)
    phase = next(p for p in result.phases if p.name == "DefenseClaw Setup 0.8.x removal")
    assert phase.status == "failed" and phase.detail == "a; b; c"
    assert phase.next_steps == ("step one", "step two")


def test_the_step_names_the_file_the_error_names() -> None:
    error = _winerror(32)
    error.filename = "C:\\x\\bin\\held.dll"
    step = legacy_setup_install._path_step(error, "C:\\x")
    assert step == "Close the program that holds C:\\x\\bin\\held.dll, then run the command again."
