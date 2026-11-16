# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""A link above or at the 0.8.x Setup folder: `defenseclaw uninstall` names the link and removes nothing through it.

The install state is read without following links, so a link at the user's
Programs folder, at the Setup folder or at a folder between them used to end
in the generic "delete the folder yourself" step. Following that advice
through a profile-level link would delete what the link points to.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw import link_guard  # noqa: E402
from defenseclaw.commands import cmd_uninstall, legacy_setup_install  # noqa: E402

from tests.test_uninstall_legacy_setup_install import _install, _uninstall, _winerror  # noqa: E402


def _link(link: Path, target: Path) -> str:
    """Make a directory link at *link*; return its kind ("symlink" or "junction")."""
    try:
        link.symlink_to(target, target_is_directory=True)
        return "symlink"
    except OSError:
        pass
    if sys.platform == "win32":
        result = subprocess.run(
            ["cmd.exe", "/d", "/c", "mklink", "/J", str(link), str(target)], capture_output=True, text=True, check=False
        )
        if result.returncode == 0:
            return "junction"
    pytest.skip("this account cannot create links")


def _digest(folder: Path) -> str:
    """One hash over every file name and content under *folder*, read without following links."""
    h = hashlib.sha256()
    for path in sorted(folder.rglob("*")):
        h.update(str(path.relative_to(folder)).encode())
        if path.is_file() and not path.is_symlink():
            h.update(path.read_bytes())
    return h.hexdigest()


@pytest.fixture
def profile(tmp_path: Path):
    """tmp/profile/AppData/Local is the LocalAppData; tmp/elsewhere is where a link can point."""
    base = tmp_path.resolve()
    local = base / "profile" / "AppData" / "Local"
    local.mkdir(parents=True)
    (base / "elsewhere").mkdir()
    with (
        patch.object(legacy_setup_install, "local_app_data", return_value=str(local)),
        patch.object(legacy_setup_install, "_ownership_problem", return_value=""),
        patch.object(
            legacy_setup_install, "_read_state", side_effect=AssertionError("the state is never read through a link")
        ),
    ):
        yield SimpleNamespace(local=local, elsewhere=base / "elsewhere", appdata=local.parent)


def _programs_link(profile) -> tuple[Path, Path, str]:
    target = _install(profile.elsewhere)
    link = profile.local / "Programs"
    return link, target, _link(link, profile.elsewhere / "Programs")


def _setup_folder_link(profile) -> tuple[Path, Path, str]:
    target = _install(profile.elsewhere)
    (profile.local / "Programs").mkdir()
    link = profile.local / "Programs" / "DefenseClaw"
    return link, target, _link(link, target)


def _intermediate_link(profile) -> tuple[Path, Path, str]:
    # AppData is the link: LocalAppData and the Setup folder are reached through it.
    real_appdata = profile.elsewhere / "RealAppData"
    target = _install(real_appdata / "Local")
    link = profile.appdata
    profile.local.rmdir()
    link.rmdir()
    return link, target, _link(link, real_appdata)


@pytest.mark.parametrize("make", [_programs_link, _setup_folder_link, _intermediate_link])
def test_a_link_on_the_way_to_the_setup_folder_is_named_with_the_safe_step(profile, make) -> None:
    link, target, kind = make(profile)
    before = _digest(target.parent.parent)
    found = legacy_setup_install.find("win32")
    assert found is not None
    root = os.path.join(profile.local, "Programs", "DefenseClaw")
    assert found.root == root
    assert f"{link} is a {kind}" in found.problem
    step = found.problem_step
    assert f'cmd /c rmdir "{link}"' in step
    assert "removes only the link, not what it points to" in step
    assert "ask an administrator to" in step
    # Not the generic step, and no folder is advised for deletion.
    assert "yourself" not in step
    assert f"delete {root}" not in step and f"remove {root}" not in step
    assert "Apps & Features" in step
    # Nothing is removed through the link, by any phase.
    with (
        patch.object(legacy_setup_install, "_stop_processes_under", return_value=0),
        patch.object(legacy_setup_install, "_remove_run_values", return_value=[]),
        patch.object(legacy_setup_install, "_remove_uninstall_entry", return_value=False),
    ):
        done, problems = legacy_setup_install.remove(found, edit_user_path=lambda _path: False)
    assert done == []
    assert [p.step for p in problems] == [step]
    assert _digest(target.parent.parent) == before


@pytest.mark.parametrize("make", [_programs_link, _setup_folder_link, _intermediate_link])
def test_the_uninstall_prints_the_named_link_step_last(profile, make) -> None:
    link, _target, kind = make(profile)
    found = legacy_setup_install.find("win32")
    assert found is not None
    problems = cmd_uninstall._remove_legacy_setup_install(found)
    steps = tuple(p.step for p in problems)
    result = cmd_uninstall.ExecutionResult(
        (cmd_uninstall.ExecutionPhaseResult(cmd_uninstall._LEGACY_SETUP_PHASE, "failed", "; ".join(problems), steps),)
    )
    code, output = _uninstall(found, result)
    assert code == 1
    assert f"- {link} is a {kind}." in output
    assert f'`cmd /c rmdir "{link}"`' in output
    assert "yourself" not in output.split("was not removed completely", 1)[1]
    assert "Fix what is named above" not in output


def test_with_two_links_the_one_nearest_the_folder_comes_first(profile) -> None:
    target = _install(profile.elsewhere)
    before = _digest(target)
    outer = profile.local / "Programs"
    kind = _link(outer, profile.elsewhere / "Programs")
    # A link inside the first target, at the Setup folder.
    moved = profile.elsewhere / "Moved"
    (profile.elsewhere / "Programs" / "DefenseClaw").rename(moved)
    inner_kind = _link(profile.elsewhere / "Programs" / "DefenseClaw", moved)
    found = legacy_setup_install.find("win32")
    assert found is not None
    inner = outer / "DefenseClaw"
    assert found.problem.startswith(f"{inner} is a {inner_kind}")
    assert f"{outer} ({kind})" in found.problem
    assert f'cmd /c rmdir "{inner}"' in found.problem_step
    assert _digest(moved) == before


def test_no_link_keeps_the_ordinary_steps(profile) -> None:
    root = _install(profile.local)
    assert link_guard.link_problem(str(root)) is None
    with patch.object(legacy_setup_install, "_read_state", side_effect=OSError("it is not valid JSON")):
        found = legacy_setup_install.find("win32")
    assert found is not None and found.problem == "it is not valid JSON"
    assert found.problem_step.startswith("Uninstall DefenseClaw Setup from Apps & Features, or delete ")


def test_a_link_made_after_the_first_look_is_still_named(profile) -> None:
    _install(profile.local)
    link = profile.local / "Programs"

    def read_state(_path: str):
        # The folder is real at the first look; the link appears before the state is opened.
        link.rename(profile.elsewhere / "Programs")
        _link(link, profile.elsewhere / "Programs")
        raise OSError("refusing sensitive write through reparse point")

    with patch.object(legacy_setup_install, "_read_state", side_effect=read_state):
        found = legacy_setup_install.find("win32")
    assert found is not None
    assert f"{link} is a " in found.problem and "yourself" not in found.problem_step


@pytest.mark.parametrize("winerror", [1, 5, 32])
def test_a_removal_error_behind_a_link_gives_the_link_step(profile, winerror: int) -> None:
    target = _install(profile.elsewhere)
    link = profile.local / "Programs"
    kind = _link(link, profile.elsewhere / "Programs")
    step = legacy_setup_install._path_step(_winerror(winerror), str(link / "DefenseClaw"))
    assert step.startswith(f"{link} is a {kind}.")
    assert "yourself" not in step and "Close the program" not in step
    assert target.exists()


def test_the_cache_and_the_launcher_state_behind_a_link_are_not_touched(profile) -> None:
    """The program folder is real; the folder above the cache is a link to a real cache."""
    root = _install(profile.local)
    real_cache_parent = profile.elsewhere / "DefenseClaw"
    (profile.local / "DefenseClaw").rename(real_cache_parent)
    hook_state = real_cache_parent / "HookRuntime" / "hook-runtime-state.json"
    hook_state.parent.mkdir(parents=True)
    hook_state.write_text(
        json.dumps({"schema_version": 2, "status": "active", "hook_path": str(root / "bin" / "h.exe")}),
        encoding="utf-8",
    )
    link = profile.local / "DefenseClaw"
    kind = _link(link, real_cache_parent)
    before = _digest(real_cache_parent)
    install = legacy_setup_install.LegacySetupInstall(
        str(root),
        "0.8.10",
        "",
        str(link / "InstallerCache"),
        str(link / "HookRuntime" / "hook-runtime-state.json"),
    )
    with (
        patch.object(legacy_setup_install, "_stop_processes_under", return_value=0),
        patch.object(legacy_setup_install, "_remove_run_values", return_value=[]),
        patch.object(legacy_setup_install, "_remove_uninstall_entry", return_value=False),
    ):
        done, problems = legacy_setup_install.remove(install, edit_user_path=lambda _path: False)
    assert _digest(real_cache_parent) == before
    assert not root.exists()
    assert f"removed {root}" in done
    assert len(problems) == 2
    assert all(p.startswith("could not") and f"{link} is a {kind}" in p for p in problems)
    assert {p.step for p in problems} == {problems[0].step}
    assert f'cmd /c rmdir "{link}"' in problems[0].step


@pytest.mark.parametrize(
    ("mode", "tag", "expected"),
    [
        (0o040000, 0xA0000003, "junction"),
        (0o120000, 0xA000000C, "symlink"),
        (0o120000, 0, "symlink"),
        (0o040000, 0x9000601A, "link"),
        (0o040000, 0, "link"),
    ],
)
def test_the_kind_of_link_comes_from_the_reparse_tag(mode: int, tag: int, expected: str) -> None:
    assert link_guard.link_kind(SimpleNamespace(st_mode=mode, st_reparse_tag=tag)) == expected
