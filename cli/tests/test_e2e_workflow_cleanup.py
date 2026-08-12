# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Contracts for isolated source installs in persistent-runner E2E jobs."""

from __future__ import annotations

import os
import runpy
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "e2e.yml"
SOURCE_INSTALL_HELPER = ROOT / "scripts" / "e2e-source-install.py"
SOURCE_INSTALL_PREFLIGHT = ROOT / "scripts" / "source-install-preflight.sh"
RUNNER_CLEANUP = ROOT / "scripts" / "runner-cleanup.sh"
WORKFLOW = yaml.safe_load(WORKFLOW_PATH.read_text(encoding="utf-8"))
SOURCE_INSTALL_API = runpy.run_path(os.fspath(SOURCE_INSTALL_HELPER))
OWNER_MARKER = SOURCE_INSTALL_API["_OWNER_MARKER"]
STAGING_SUFFIX = SOURCE_INSTALL_API["_STAGING_SUFFIX"]
TOMBSTONE_SUFFIX = SOURCE_INSTALL_API["_TOMBSTONE_SUFFIX"]
POSIX_SHELL_ONLY = pytest.mark.skipif(
    os.name == "nt",
    reason="runner-cleanup.sh requires a native POSIX shell",
)


def _transaction_paths(root: Path) -> tuple[Path, Path]:
    return SOURCE_INSTALL_API["_transaction_paths"](root)


def _step(job: str, name: str) -> dict[str, object]:
    steps = WORKFLOW["jobs"][job]["steps"]
    matches = [step for step in steps if step.get("name") == name]
    assert len(matches) == 1, f"expected one {name!r} step in {job!r}"
    return matches[0]


def _step_script(job: str, name: str) -> str:
    script = _step(job, name).get("run")
    assert isinstance(script, str), f"expected {job}/{name} to be a run step"
    return script


def _substring_offsets(text: str, needle: str) -> list[int]:
    offsets: list[int] = []
    cursor = 0
    while (offset := text.find(needle, cursor)) >= 0:
        offsets.append(offset)
        cursor = offset + len(needle)
    return offsets


def _helper_env(runner_workspace: Path, persistent_home: Path, *, path: str | None = None) -> dict[str, str]:
    environment = os.environ.copy()
    environment.update(
        {
            "HOME": os.fspath(persistent_home),
            "USERPROFILE": os.fspath(persistent_home),
            "RUNNER_WORKSPACE": os.fspath(runner_workspace),
        }
    )
    if path is not None:
        environment["PATH"] = path
    return environment


def _run_helper(
    command: str,
    root: Path,
    *,
    runner_workspace: Path,
    persistent_home: Path,
    path: str | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, os.fspath(SOURCE_INSTALL_HELPER), command, os.fspath(root)],
        check=check,
        capture_output=True,
        text=True,
        env=_helper_env(runner_workspace, persistent_home, path=path),
    )


def test_persistent_e2e_jobs_are_serialized_through_cleanup() -> None:
    """Full-live must wait for core's always-run post-cleanup step."""

    workflow_text = WORKFLOW_PATH.read_text(encoding="utf-8")
    trigger_block = workflow_text.split("concurrency:", 1)[0]
    assert "schedule:" in trigger_block
    assert "workflow_dispatch:" not in trigger_block
    assert "pull_request:" not in trigger_block
    assert WORKFLOW["concurrency"]["cancel-in-progress"] is False
    full_live = WORKFLOW["jobs"]["full-live"]
    assert full_live["needs"] == "core"
    assert "always()" in full_live["if"]
    for job in ("core", "full-live"):
        assert _step(job, "Post-run cleanup")["if"] == "always()"


def test_persistent_e2e_jobs_use_distinct_persistent_install_homes() -> None:
    install_names: dict[str, str] = {}
    for job in ("core", "full-live"):
        environment = WORKFLOW["jobs"][job]["env"]
        install_name = environment["E2E_INSTALL_NAME"]
        expected = f"defenseclaw-e2e-slot-{job}"
        select_home = _step_script(job, "Select isolated DefenseClaw home")
        assert install_name == expected
        assert "/" not in install_name
        assert 'E2E_INSTALL_HOME="${RUNNER_WORKSPACE}/${E2E_INSTALL_NAME}"' in select_home
        assert 'E2E_INSTALL_HOME="${RUNNER_TEMP}/${E2E_INSTALL_NAME}"' not in select_home
        assert "RUNNER_TEMP is emptied by the Actions runner before each job" in select_home
        assert 'echo "DEFENSECLAW_HOME=${E2E_INSTALL_HOME}/.defenseclaw"' in select_home
        assert (
            'echo "DEFENSECLAW_CUSTOM_PROVIDERS_PATH=${E2E_INSTALL_HOME}/.defenseclaw/'
            'custom-providers.json"' in select_home
        )
        assert "OPENCLAW_HOME" not in select_home
        install_names[job] = install_name
    assert install_names["core"] != install_names["full-live"]


def test_persistent_e2e_checkouts_do_not_persist_job_credentials() -> None:
    for job in ("core", "full-live"):
        checkouts = [
            step
            for step in WORKFLOW["jobs"][job]["steps"]
            if isinstance(step.get("uses"), str) and step["uses"].startswith("actions/checkout@")
        ]
        assert len(checkouts) == 1
        options = checkouts[0].get("with")
        assert isinstance(options, dict)
        assert options.get("persist-credentials") is False


def test_persistent_e2e_jobs_use_the_source_install_helper_once() -> None:
    prepare = 'python3 scripts/e2e-source-install.py prepare "${E2E_INSTALL_HOME}"'
    cleanup = 'python3 scripts/e2e-source-install.py cleanup "${E2E_INSTALL_HOME}"'
    path = 'python3 scripts/e2e-source-install.py path "${E2E_INSTALL_HOME}"'
    authorization = 'python3 scripts/e2e-source-install.py authorize-cleanup "${E2E_INSTALL_HOME}"'
    for job in ("core", "full-live"):
        clean = _step_script(job, "Clean DefenseClaw")
        assert clean.count(prepare) == 1
        assert clean.count(authorization) == 1
        first_cleanup = clean.index("bash scripts/runner-cleanup.sh")
        assert clean.index(authorization) < first_cleanup < clean.index(prepare)
        assert all(
            clean.index(authorization) < offset
            for offset in _substring_offsets(clean, "bash scripts/runner-cleanup.sh")
        )
        assert _step_script(job, "Post-run cleanup").count(cleanup) == 1
        install = _step_script(job, "Install DefenseClaw")
        assert install.count(path) == 1
        assert 'USER_HOME="${E2E_INSTALL_HOME}"' in install
        assert 'OC_EXT_DIR="$HOME/.openclaw/extensions/defenseclaw"' in install
        assert 'echo "${E2E_INSTALL_HOME}/.local/bin" >> "$GITHUB_PATH"' in _step_script(job, "Activate venv")
        for test_step in ("Unit tests", "TypeScript plugin tests", "Rego policy tests"):
            assert 'USER_HOME="${E2E_INSTALL_HOME}"' in _step_script(job, test_step)


def test_opa_is_installed_into_the_isolated_job_bin() -> None:
    for job in ("core", "full-live"):
        install_opa = _step_script(job, "Install OPA")
        assert 'install -d -m 0755 "${E2E_INSTALL_HOME}/.local/bin"' in install_opa
        assert 'install -m 0755 /tmp/opa "${E2E_INSTALL_HOME}/.local/bin/opa"' in install_opa
        assert "$HOME/.local/bin/opa" not in install_opa


def test_workflow_preserves_the_account_level_source_install() -> None:
    forbidden = (
        "~/.defenseclaw",
        "$HOME/.defenseclaw",
        "${HOME}/.defenseclaw",
        "~/.local/bin/defenseclaw",
        "$HOME/.local/bin/defenseclaw",
        "${HOME}/.local/bin/defenseclaw",
        "~/.local/bin/defenseclaw-gateway",
        "$HOME/.local/bin/defenseclaw-gateway",
        "${HOME}/.local/bin/defenseclaw-gateway",
        "~/.local/bin/.defenseclaw-source-root",
        "$HOME/.local/bin/.defenseclaw-source-root",
        "${HOME}/.local/bin/.defenseclaw-source-root",
    )
    workflow_text = WORKFLOW_PATH.read_text(encoding="utf-8")
    for target in forbidden:
        assert target not in workflow_text


def test_selected_state_reaches_runtime_and_failure_cleanup() -> None:
    full_stack = (ROOT / "scripts" / "test-e2e-full-stack.sh").read_text(encoding="utf-8")
    refs = [line for line in full_stack.splitlines() if "$HOME/.defenseclaw" in line or "~/.defenseclaw" in line]
    assert refs == ['DC_HOME="${DEFENSECLAW_HOME:-$HOME/.defenseclaw}"']
    cleanup_script = (ROOT / "scripts" / "runner-cleanup.sh").read_text(encoding="utf-8")
    assert 'DC_STATE_HOME="${DEFENSECLAW_HOME:-$HOME/.defenseclaw}"' in cleanup_script
    assert 'OC_STATE_HOME="$HOME/.openclaw"' in cleanup_script
    service = _step_script("full-live", "Prepare OpenClaw Anthropic model + auth")
    assert '  "DEFENSECLAW_HOME",' in service
    assert '  "DEFENSECLAW_CUSTOM_PROVIDERS_PATH",' in service
    assert '  "HOME",' not in service
    assert '  "OPENCLAW_HOME",' not in service

    for job in ("core", "full-live"):
        post = _step_script(job, "Post-run cleanup")
        authorization = 'python3 scripts/e2e-source-install.py authorize-cleanup "${E2E_INSTALL_HOME}"'
        assert post.index(authorization) < post.index("bash scripts/runner-cleanup.sh")
        assert post.index("bash scripts/runner-cleanup.sh") < post.index(
            'python3 scripts/e2e-source-install.py cleanup "${E2E_INSTALL_HOME}"'
        )


@POSIX_SHELL_ONLY
@pytest.mark.parametrize("unsafe_kind", ["relative", "root", "broad", "symlink-root"])
def test_runner_cleanup_rejects_unsafe_defenseclaw_home(tmp_path: Path, unsafe_kind: str) -> None:
    persistent_home = tmp_path / "persistent-home"
    persistent_home.mkdir()
    if unsafe_kind == "relative":
        unsafe_home = "relative/state"
        expected = "DEFENSECLAW_HOME must be absolute"
    elif unsafe_kind == "root":
        unsafe_home = "/"
        expected = "DEFENSECLAW_HOME must not resolve to /"
    elif unsafe_kind == "broad":
        unsafe_home = os.fspath(tmp_path / "broad-home")
        expected = "explicit DEFENSECLAW_HOME must name a .defenseclaw state directory"
    else:
        link = tmp_path / "root-link"
        try:
            link.symlink_to("/", target_is_directory=True)
        except (NotImplementedError, OSError) as exc:
            pytest.skip(f"directory symlinks are unavailable: {exc}")
        unsafe_home = os.fspath(link)
        expected = "DEFENSECLAW_HOME must not be a symlink"

    environment = os.environ.copy()
    environment.update(
        {
            "HOME": os.fspath(persistent_home),
            "DEFENSECLAW_HOME": unsafe_home,
            "RUNNER_CLEANUP_STATE_ONLY": "1",
        }
    )
    result = subprocess.run(
        ["bash", os.fspath(RUNNER_CLEANUP)],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )
    assert result.returncode == 2
    assert expected in result.stderr


@POSIX_SHELL_ONLY
def test_runner_cleanup_preserves_the_legacy_default_state_path(tmp_path: Path) -> None:
    persistent_home = tmp_path / "persistent-home"
    default_state = persistent_home / ".defenseclaw"
    default_state.mkdir(parents=True)
    environment = os.environ.copy()
    environment.update(
        {
            "HOME": os.fspath(persistent_home),
            "RUNNER_CLEANUP_REPAIR_PERMISSIONS_ONLY": "1",
        }
    )
    environment.pop("DEFENSECLAW_HOME", None)

    result = subprocess.run(
        ["bash", os.fspath(RUNNER_CLEANUP)],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )

    assert result.returncode == 0, result.stdout + result.stderr


@POSIX_SHELL_ONLY
def test_runner_cleanup_does_not_follow_a_state_symlink(tmp_path: Path) -> None:
    persistent_home = tmp_path / "persistent-home"
    isolated_home = tmp_path / "isolated-home"
    victim = tmp_path / "victim"
    sentinel = victim / "quarantine" / "skills" / "e2e-must-survive"
    persistent_home.mkdir()
    sentinel.mkdir(parents=True)
    try:
        isolated_home.symlink_to(victim, target_is_directory=True)
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"directory symlinks are unavailable: {exc}")

    environment = os.environ.copy()
    environment.update(
        {
            "HOME": os.fspath(persistent_home),
            "DEFENSECLAW_HOME": os.fspath(isolated_home),
            "RUNNER_CLEANUP_STATE_ONLY": "1",
        }
    )
    result = subprocess.run(
        ["bash", os.fspath(RUNNER_CLEANUP)],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )
    assert result.returncode == 2
    assert "DEFENSECLAW_HOME must not be a symlink" in result.stderr
    assert sentinel.is_dir()


@POSIX_SHELL_ONLY
@pytest.mark.parametrize(
    "cleanup_flag",
    ["RUNNER_CLEANUP_STATE_ONLY", "RUNNER_CLEANUP_PERMISSIONS_ONLY"],
)
def test_runner_cleanup_does_not_follow_a_state_symlink_ancestor(tmp_path: Path, cleanup_flag: str) -> None:
    persistent_home = tmp_path / "persistent-home"
    linked_parent = tmp_path / "linked-parent"
    victim_parent = tmp_path / "victim-parent"
    victim_state = victim_parent / ".defenseclaw"
    sentinel = victim_state / "quarantine" / "skills" / "e2e-must-survive"
    persistent_home.mkdir()
    sentinel.mkdir(parents=True)
    try:
        linked_parent.symlink_to(victim_parent, target_is_directory=True)
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"directory symlinks are unavailable: {exc}")

    environment = os.environ.copy()
    environment.update(
        {
            "HOME": os.fspath(persistent_home),
            "DEFENSECLAW_HOME": os.fspath(linked_parent / ".defenseclaw"),
            cleanup_flag: "1",
        }
    )
    result = subprocess.run(
        ["bash", os.fspath(RUNNER_CLEANUP)],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )

    assert result.returncode == 2
    assert "DEFENSECLAW_HOME must not contain a symlink" in result.stderr
    assert sentinel.is_dir()


@POSIX_SHELL_ONLY
@pytest.mark.parametrize(
    ("cleanup_flag", "cleanup_value"),
    [
        ("RUNNER_CLEANUP_STATE_ONLY", "1"),
        ("RUNNER_CLEANUP_PERMISSIONS_ONLY", "1"),
    ],
)
@pytest.mark.parametrize(
    ("link_parts", "sentinel_parts"),
    [
        (("quarantine",), ("skills", "e2e-must-survive")),
        (("quarantine", "skills"), ("e2e-must-survive",)),
        (("quarantine", "plugins"), ("e2e-must-survive",)),
    ],
)
def test_runner_cleanup_does_not_follow_a_quarantine_symlink(
    tmp_path: Path,
    cleanup_flag: str,
    cleanup_value: str,
    link_parts: tuple[str, ...],
    sentinel_parts: tuple[str, ...],
) -> None:
    persistent_home = tmp_path / "persistent-home"
    isolated_state = tmp_path / "isolated" / ".defenseclaw"
    victim = tmp_path / "victim"
    link = isolated_state.joinpath(*link_parts)
    sentinel = victim.joinpath(*sentinel_parts)
    persistent_home.mkdir()
    isolated_state.mkdir(parents=True)
    link.parent.mkdir(parents=True, exist_ok=True)
    sentinel.mkdir(parents=True)
    try:
        link.symlink_to(victim, target_is_directory=True)
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"directory symlinks are unavailable: {exc}")

    environment = os.environ.copy()
    environment.update(
        {
            "HOME": os.fspath(persistent_home),
            "DEFENSECLAW_HOME": os.fspath(isolated_state),
            cleanup_flag: cleanup_value,
        }
    )

    result = subprocess.run(
        ["bash", os.fspath(RUNNER_CLEANUP)],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )

    assert result.returncode == 2
    assert "DefenseClaw cleanup path must not be a symlink" in result.stderr
    assert sentinel.is_dir()


@POSIX_SHELL_ONLY
def test_runner_cleanup_accepts_a_safe_isolated_state_root(tmp_path: Path) -> None:
    persistent_home = tmp_path / "persistent-home"
    isolated_state = tmp_path / "isolated" / ".defenseclaw"
    persistent_home.mkdir()
    isolated_state.mkdir(parents=True)
    environment = os.environ.copy()
    environment.update(
        {
            "HOME": os.fspath(persistent_home),
            "DEFENSECLAW_HOME": os.fspath(isolated_state),
            "RUNNER_CLEANUP_REPAIR_PERMISSIONS_ONLY": "1",
        }
    )
    result = subprocess.run(
        ["bash", os.fspath(RUNNER_CLEANUP)],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_runner_cleanup_pins_the_state_tree_during_privileged_repair() -> None:
    cleanup = RUNNER_CLEANUP.read_text(encoding="utf-8")

    assert "sudo -n chown -R" not in cleanup
    assert "sudo -n chmod -R" not in cleanup
    assert "sudo -n setfacl -R" not in cleanup
    assert "descriptor = os.open(os.path.sep, directory_flags)" in cleanup
    assert "child = os.open(component, directory_flags, dir_fd=descriptor)" in cleanup
    assert "| os.O_NOFOLLOW" in cleanup
    assert "os.listdir(descriptor)" in cleanup
    assert "os.stat(name, dir_fd=descriptor, follow_symlinks=False)" in cleanup
    assert "os.fchown(descriptor, uid, gid)" in cleanup
    assert "os.fchmod(descriptor" in cleanup
    assert "state directory changed during repair" in cleanup
    assert "Avoid every pathname-based privileged mutation" in cleanup
    assert "state repair refuses multiply-linked files" in cleanup
    assert "directory_mode &= ~(stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX)" in cleanup
    assert "mode &= ~(stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX)" in cleanup


def test_source_install_helper_lifecycle_preserves_persistent_home(tmp_path: Path) -> None:
    runner_workspace = tmp_path / "runner-workspace"
    persistent_home = tmp_path / "persistent-home"
    persistent_bin = persistent_home / ".local" / "bin"
    persistent_state = persistent_home / ".defenseclaw" / "config.yaml"
    unrelated_bin = tmp_path / "unrelated-bin"
    runner_workspace.mkdir()
    persistent_bin.mkdir(parents=True)
    persistent_state.parent.mkdir()
    unrelated_bin.mkdir()
    persistent_state.write_text("persistent: true\n", encoding="utf-8")
    for name in ("defenseclaw", "defenseclaw-gateway", ".defenseclaw-source-root"):
        (persistent_bin / name).write_text("persistent\n", encoding="utf-8")

    root = runner_workspace / "defenseclaw-e2e-slot-core"
    _run_helper("prepare", root, runner_workspace=runner_workspace, persistent_home=persistent_home)
    _run_helper("verify", root, runner_workspace=runner_workspace, persistent_home=persistent_home)
    assert (root / OWNER_MARKER).read_text(encoding="utf-8") == f"{root.name}\n"

    isolated_bin = root / ".local" / "bin"
    isolated_bin.mkdir(parents=True)
    selected = (
        _run_helper(
            "path",
            root,
            runner_workspace=runner_workspace,
            persistent_home=persistent_home,
            path=os.pathsep.join((os.fspath(persistent_bin), os.fspath(unrelated_bin), os.fspath(isolated_bin))),
        )
        .stdout.strip()
        .split(os.pathsep)
    )
    assert selected == [os.fspath(isolated_bin), os.fspath(unrelated_bin)]

    if os.name != "nt":
        workflow_path = _run_helper(
            "path",
            root,
            runner_workspace=runner_workspace,
            persistent_home=persistent_home,
            path=os.pathsep.join((os.fspath(persistent_bin), os.defpath)),
        ).stdout.strip()
        preflight_env = _helper_env(runner_workspace, persistent_home, path=workflow_path)
        preflight_env["DEFENSECLAW_HOME"] = os.fspath(root / ".defenseclaw")
        preflight = subprocess.run(
            [
                "bash",
                os.fspath(SOURCE_INSTALL_PREFLIGHT),
                "check",
                os.fspath(ROOT),
                os.fspath(isolated_bin),
                ".venv/bin",
                "defenseclaw",
                "defenseclaw-gateway",
            ],
            check=False,
            capture_output=True,
            text=True,
            env=preflight_env,
        )
        assert preflight.returncode == 0, preflight.stdout + preflight.stderr

    (root / ".defenseclaw").mkdir()
    _run_helper("cleanup", root, runner_workspace=runner_workspace, persistent_home=persistent_home)
    assert not root.exists()
    assert persistent_state.read_text(encoding="utf-8") == "persistent: true\n"
    for name in ("defenseclaw", "defenseclaw-gateway", ".defenseclaw-source-root"):
        assert (persistent_bin / name).read_text(encoding="utf-8") == "persistent\n"


def test_source_install_helper_rejects_the_ephemeral_runner_temp(tmp_path: Path) -> None:
    runner_workspace = tmp_path / "runner-workspace"
    runner_temp = tmp_path / "runner-temp"
    persistent_home = tmp_path / "persistent-home"
    runner_workspace.mkdir()
    runner_temp.mkdir()
    persistent_home.mkdir()
    environment = _helper_env(runner_workspace, persistent_home)
    environment["RUNNER_TEMP"] = os.fspath(runner_temp)
    result = subprocess.run(
        [
            sys.executable,
            os.fspath(SOURCE_INSTALL_HELPER),
            "prepare",
            os.fspath(runner_temp / "defenseclaw-e2e-slot-core"),
        ],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )

    assert result.returncode != 0
    assert "install home must be a direct child of RUNNER_WORKSPACE" in result.stderr
    assert not (runner_temp / "defenseclaw-e2e-slot-core").exists()


@POSIX_SHELL_ONLY
def test_isolated_path_preserves_only_required_account_build_tools(tmp_path: Path) -> None:
    runner_workspace = tmp_path / "runner-workspace"
    persistent_home = tmp_path / "persistent-home"
    persistent_bin = persistent_home / ".local" / "bin"
    unrelated_bin = tmp_path / "unrelated-bin"
    runner_workspace.mkdir()
    persistent_bin.mkdir(parents=True)
    unrelated_bin.mkdir()

    for name in ("uv", "npm", "go", "node", "opa", "defenseclaw"):
        executable = persistent_bin / name
        executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        executable.chmod(0o700)

    root = runner_workspace / "defenseclaw-e2e-slot-core"
    _run_helper("prepare", root, runner_workspace=runner_workspace, persistent_home=persistent_home)
    selected = Path(
        _run_helper(
            "path",
            root,
            runner_workspace=runner_workspace,
            persistent_home=persistent_home,
            path=os.pathsep.join((os.fspath(persistent_bin), os.fspath(unrelated_bin))),
        )
        .stdout.strip()
        .split(os.pathsep)[1]
    )

    assert selected.name == ".e2e-build-tools"
    assert not selected.is_symlink()
    assert {entry.name for entry in selected.iterdir()} == {"go", "node", "npm", "uv"}
    for name in ("go", "node", "npm", "uv"):
        assert (selected / name).is_symlink()
        assert (selected / name).resolve(strict=True) == (persistent_bin / name).resolve(strict=True)
    assert not (selected / "opa").exists()
    assert not (selected / "defenseclaw").exists()


@POSIX_SHELL_ONLY
def test_isolated_path_refreshes_the_bounded_build_tool_shims(tmp_path: Path) -> None:
    runner_workspace = tmp_path / "runner-workspace"
    persistent_home = tmp_path / "persistent-home"
    persistent_bin = persistent_home / ".local" / "bin"
    unrelated_bin = tmp_path / "unrelated-bin"
    runner_workspace.mkdir()
    persistent_bin.mkdir(parents=True)
    unrelated_bin.mkdir()

    uv = persistent_bin / "uv"
    uv.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    uv.chmod(0o700)
    root = runner_workspace / "defenseclaw-e2e-slot-core"
    _run_helper("prepare", root, runner_workspace=runner_workspace, persistent_home=persistent_home)
    selected = (
        _run_helper(
            "path",
            root,
            runner_workspace=runner_workspace,
            persistent_home=persistent_home,
            path=os.pathsep.join((os.fspath(persistent_bin), os.fspath(unrelated_bin))),
        )
        .stdout.strip()
        .split(os.pathsep)
    )
    shim_dir = Path(selected[1])
    assert {entry.name for entry in shim_dir.iterdir()} == {"uv"}

    uv.unlink()
    npm = persistent_bin / "npm"
    npm.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    npm.chmod(0o700)
    refreshed = (
        _run_helper(
            "path",
            root,
            runner_workspace=runner_workspace,
            persistent_home=persistent_home,
            path=os.pathsep.join((os.fspath(persistent_bin), os.fspath(unrelated_bin))),
        )
        .stdout.strip()
        .split(os.pathsep)
    )
    assert refreshed[1] == os.fspath(shim_dir)
    assert {entry.name for entry in shim_dir.iterdir()} == {"npm"}


def test_stable_slot_retry_replaces_only_owned_crash_state(tmp_path: Path) -> None:
    runner_workspace = tmp_path / "runner-workspace"
    persistent_home = tmp_path / "persistent-home"
    root = runner_workspace / "defenseclaw-e2e-slot-core"
    runner_workspace.mkdir()
    persistent_home.mkdir()

    _run_helper("prepare", root, runner_workspace=runner_workspace, persistent_home=persistent_home)
    stale = root / ".defenseclaw" / "root-owned-from-crash"
    stale.parent.mkdir()
    stale.write_text("stale\n", encoding="utf-8")

    _run_helper("authorize-cleanup", root, runner_workspace=runner_workspace, persistent_home=persistent_home)
    _run_helper("prepare", root, runner_workspace=runner_workspace, persistent_home=persistent_home)
    assert not stale.exists()
    assert (root / OWNER_MARKER).read_text(encoding="utf-8") == f"{root.name}\n"


def test_transaction_fixture_names_match_helper_constants() -> None:
    # These names are a persisted crash-recovery contract across workflow runs.
    assert OWNER_MARKER == ".defenseclaw-e2e-owner"
    assert STAGING_SUFFIX == ".staging"
    assert TOMBSTONE_SUFFIX == ".tombstone"


def test_owned_tree_removal_reports_an_e2e_refusal(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    helper = SOURCE_INSTALL_API
    root = tmp_path / "defenseclaw-e2e-slot-core"
    _, tombstone = _transaction_paths(root)
    child = tombstone / "unremovable"
    tombstone.mkdir()
    child.mkdir()
    (tombstone / OWNER_MARKER).write_text(f"{root.name}\n", encoding="utf-8")

    def refuse_removal(_path: Path) -> None:
        raise PermissionError("injected removal failure")

    monkeypatch.setattr(helper["shutil"], "rmtree", refuse_removal)
    with pytest.raises(
        SystemExit,
        match="e2e source install refused: could not remove owned E2E transaction contents",
    ):
        helper["_remove_owned_tree"](tombstone, root)

    assert child.is_dir()
    assert (tombstone / OWNER_MARKER).is_file()


def test_prepare_resumes_a_marked_prepublication_stage(tmp_path: Path) -> None:
    runner_workspace = tmp_path / "runner-workspace"
    persistent_home = tmp_path / "persistent-home"
    root = runner_workspace / "defenseclaw-e2e-slot-core"
    staging, _ = _transaction_paths(root)
    runner_workspace.mkdir()
    persistent_home.mkdir()
    staging.mkdir(mode=0o700)
    (staging / OWNER_MARKER).write_text(f"{root.name}\n", encoding="utf-8")

    _run_helper("prepare", root, runner_workspace=runner_workspace, persistent_home=persistent_home)

    assert root.is_dir()
    assert not staging.exists()
    assert {entry.name for entry in root.iterdir()} == {OWNER_MARKER}


def test_prepare_recovers_a_marked_midretirement_tombstone(tmp_path: Path) -> None:
    runner_workspace = tmp_path / "runner-workspace"
    persistent_home = tmp_path / "persistent-home"
    root = runner_workspace / "defenseclaw-e2e-slot-full-live"
    _, tombstone = _transaction_paths(root)
    runner_workspace.mkdir()
    persistent_home.mkdir()
    _run_helper("prepare", root, runner_workspace=runner_workspace, persistent_home=persistent_home)
    stale = root / ".defenseclaw" / "partial-retirement"
    stale.parent.mkdir()
    stale.write_text("stale\n", encoding="utf-8")
    root.rename(tombstone)

    _run_helper(
        "authorize-cleanup",
        root,
        runner_workspace=runner_workspace,
        persistent_home=persistent_home,
    )
    assert root.is_dir()
    assert not tombstone.exists()
    _run_helper("prepare", root, runner_workspace=runner_workspace, persistent_home=persistent_home)

    assert root.is_dir()
    assert not tombstone.exists()
    assert not stale.exists()
    assert {entry.name for entry in root.iterdir()} == {OWNER_MARKER}


@pytest.mark.parametrize("transaction_index", [0, 1])
@pytest.mark.parametrize("command", ["prepare", "authorize-cleanup", "cleanup"])
def test_helper_preserves_an_unmarked_transaction_path(
    tmp_path: Path,
    transaction_index: int,
    command: str,
) -> None:
    runner_workspace = tmp_path / "runner-workspace"
    persistent_home = tmp_path / "persistent-home"
    root = runner_workspace / "defenseclaw-e2e-slot-core"
    transaction = _transaction_paths(root)[transaction_index]
    runner_workspace.mkdir()
    persistent_home.mkdir()
    transaction.mkdir()
    sentinel = transaction / "keep.txt"
    sentinel.write_text("keep\n", encoding="utf-8")

    result = _run_helper(
        command,
        root,
        runner_workspace=runner_workspace,
        persistent_home=persistent_home,
        check=False,
    )

    assert result.returncode != 0
    assert "has no E2E ownership marker" in result.stderr
    assert sentinel.read_text(encoding="utf-8") == "keep\n"


def test_cleanup_resumes_marked_staging_and_tombstone_state(tmp_path: Path) -> None:
    runner_workspace = tmp_path / "runner-workspace"
    persistent_home = tmp_path / "persistent-home"
    root = runner_workspace / "defenseclaw-e2e-slot-core"
    staging, tombstone = _transaction_paths(root)
    runner_workspace.mkdir()
    persistent_home.mkdir()

    for transaction in (staging, tombstone):
        transaction.mkdir(mode=0o700)
        (transaction / OWNER_MARKER).write_text(f"{root.name}\n", encoding="utf-8")
    (tombstone / "partial-state").write_text("stale\n", encoding="utf-8")

    _run_helper(
        "authorize-cleanup",
        root,
        runner_workspace=runner_workspace,
        persistent_home=persistent_home,
    )
    _run_helper("cleanup", root, runner_workspace=runner_workspace, persistent_home=persistent_home)

    assert not root.exists()
    assert not staging.exists()
    assert not tombstone.exists()


@pytest.mark.parametrize("command", ["prepare", "authorize-cleanup", "cleanup"])
def test_helper_rejects_ambiguous_canonical_and_tombstone_state(tmp_path: Path, command: str) -> None:
    runner_workspace = tmp_path / "runner-workspace"
    persistent_home = tmp_path / "persistent-home"
    root = runner_workspace / "defenseclaw-e2e-slot-core"
    _, tombstone = _transaction_paths(root)
    runner_workspace.mkdir()
    persistent_home.mkdir()

    for transaction in (root, tombstone):
        transaction.mkdir(mode=0o700)
        (transaction / OWNER_MARKER).write_text(f"{root.name}\n", encoding="utf-8")
    root_sentinel = root / "keep-root.txt"
    retired_sentinel = tombstone / "keep-retired.txt"
    root_sentinel.write_text("root\n", encoding="utf-8")
    retired_sentinel.write_text("retired\n", encoding="utf-8")

    result = _run_helper(
        command,
        root,
        runner_workspace=runner_workspace,
        persistent_home=persistent_home,
        check=False,
    )

    assert result.returncode != 0
    assert "canonical and retired install homes both exist" in result.stderr
    assert root_sentinel.read_text(encoding="utf-8") == "root\n"
    assert retired_sentinel.read_text(encoding="utf-8") == "retired\n"


@pytest.mark.parametrize("command", ["prepare", "verify", "authorize-cleanup", "cleanup"])
def test_helper_rejects_an_unmarked_existing_root(tmp_path: Path, command: str) -> None:
    runner_workspace = tmp_path / "runner-workspace"
    persistent_home = tmp_path / "persistent-home"
    root = runner_workspace / "defenseclaw-e2e-slot-full-live"
    root.mkdir(parents=True)
    persistent_home.mkdir()
    sentinel = root / "keep.txt"
    sentinel.write_text("keep\n", encoding="utf-8")
    result = _run_helper(
        command,
        root,
        runner_workspace=runner_workspace,
        persistent_home=persistent_home,
        check=False,
    )
    assert result.returncode != 0
    assert "has no E2E ownership marker" in result.stderr
    assert sentinel.read_text(encoding="utf-8") == "keep\n"


def test_cleanup_authorization_accepts_absence_but_rejects_unowned_state(tmp_path: Path) -> None:
    runner_workspace = tmp_path / "runner-workspace"
    persistent_home = tmp_path / "persistent-home"
    root = runner_workspace / "defenseclaw-e2e-slot-core"
    runner_workspace.mkdir()
    persistent_home.mkdir()

    absent = _run_helper(
        "authorize-cleanup",
        root,
        runner_workspace=runner_workspace,
        persistent_home=persistent_home,
        check=False,
    )
    assert absent.returncode == 0

    root.mkdir()
    sentinel = root / "keep.txt"
    sentinel.write_text("keep\n", encoding="utf-8")
    unowned = _run_helper(
        "authorize-cleanup",
        root,
        runner_workspace=runner_workspace,
        persistent_home=persistent_home,
        check=False,
    )
    assert unowned.returncode != 0
    assert "has no E2E ownership marker" in unowned.stderr
    assert sentinel.read_text(encoding="utf-8") == "keep\n"


@pytest.mark.parametrize("command", ["prepare", "verify", "authorize-cleanup", "cleanup"])
def test_helper_rejects_a_symlink_root(tmp_path: Path, command: str) -> None:
    runner_workspace = tmp_path / "runner-workspace"
    persistent_home = tmp_path / "persistent-home"
    target = tmp_path / "target"
    root = runner_workspace / "defenseclaw-e2e-slot-core"
    runner_workspace.mkdir()
    persistent_home.mkdir()
    target.mkdir()
    sentinel = target / "keep.txt"
    sentinel.write_text("keep\n", encoding="utf-8")
    (target / OWNER_MARKER).write_text(f"{root.name}\n", encoding="utf-8")
    try:
        root.symlink_to(target, target_is_directory=True)
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"directory symlinks are unavailable: {exc}")
    result = _run_helper(
        command,
        root,
        runner_workspace=runner_workspace,
        persistent_home=persistent_home,
        check=False,
    )
    assert result.returncode != 0
    assert "install home is not a real directory" in result.stderr
    assert root.is_symlink()
    assert sentinel.read_text(encoding="utf-8") == "keep\n"
