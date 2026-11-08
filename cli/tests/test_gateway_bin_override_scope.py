# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""State-changing flows ignore DEFENSECLAW_GATEWAY_BIN (cowork GAP-0099/0100)."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw import bootstrap, fail_mode, gateway_path  # noqa: E402
from defenseclaw.commands import cmd_init, cmd_uninstall, legacy_setup_install  # noqa: E402

posix_only = pytest.mark.skipif(os.name == "nt", reason="POSIX layout")


def _file(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"x")
    path.chmod(0o755)
    return path


@pytest.fixture
def two_gateways(tmp_path: Path):
    """A real gateway in the own layout and a planted one named by the environment."""
    real = _file(tmp_path / "home" / ".local" / "bin" / "defenseclaw-gateway")
    planted = _file(tmp_path / "elsewhere" / "defenseclaw-gateway")
    with (
        patch.object(gateway_path, "_launcher_sibling_gateway", return_value=str(real)),
        patch.dict(os.environ, {"DEFENSECLAW_GATEWAY_BIN": str(planted), "HOME": str(tmp_path / "home")}),
    ):
        yield real, planted


# ---- S-b: the uninstall plan, its stop step and its delete step use the real gateway of the install


@posix_only
def test_the_uninstall_plan_and_its_steps_ignore_the_environment_override(two_gateways, tmp_path: Path) -> None:
    real, planted = two_gateways
    data = tmp_path / "home" / ".defenseclaw"
    data.mkdir(parents=True)
    with patch.object(cmd_uninstall.config_module, "default_data_path", return_value=str(data)):
        plan = cmd_uninstall._build_plan(
            wipe_data=False, binaries=True, revert_openclaw=False, remove_plugin=False, platform_name="linux"
        )
    assert plan.gateway_path == str(real)

    done = subprocess.CompletedProcess([], 0, "", "")
    with (
        patch.object(cmd_uninstall.subprocess, "run", return_value=done) as run,
        patch.object(cmd_uninstall, "_capture_managed_processes", return_value=[]),
        patch.object(cmd_uninstall, "_wait_managed_processes"),
    ):
        cmd_uninstall._stop_gateway(plan)
    assert run.call_args_list, "the stop step ran nothing"
    assert all(call.args[0][0] == str(real) for call in run.call_args_list)

    cmd_uninstall._remove_binaries(plan)
    assert not real.exists(), "the delete step left the gateway of the install"
    assert planted.exists(), "the delete step removed the file the environment named"


@posix_only
def test_the_no_plan_fallbacks_ignore_the_environment_override(two_gateways) -> None:
    real, _planted = two_gateways
    done = subprocess.CompletedProcess([], 0, "connector", "")
    with patch.object(cmd_uninstall.subprocess, "run", return_value=done) as run:
        cmd_uninstall._gateway_supports_connector_teardown()
        cmd_uninstall._gateway_connector_is_unknown("codex")
        cmd_uninstall._run_gateway_connector_teardown("codex")
    assert len(run.call_args_list) >= 3
    assert all(call.args[0][0] == str(real) for call in run.call_args_list)
    with (
        patch.object(cmd_uninstall.subprocess, "run", return_value=done) as run,
        patch.object(cmd_uninstall, "_capture_managed_processes", return_value=[]),
        patch.object(cmd_uninstall, "_wait_managed_processes"),
    ):
        cmd_uninstall._stop_gateway()
    assert run.call_args_list
    assert all(call.args[0][0] == str(real) for call in run.call_args_list)


# ---- S-c: hook registration, sidecar start and init do not run a binary the environment names


@posix_only
def test_connector_reconcile_runs_the_install_gateway_not_the_environment_one(two_gateways, tmp_path: Path) -> None:
    real, _planted = two_gateways
    cfg = MagicMock(data_dir=str(tmp_path / "data"))
    failed = subprocess.CompletedProcess([], 1, "", "reconcile refused")
    with patch.object(fail_mode.subprocess, "run", return_value=failed) as run:
        with pytest.raises(OSError, match="reconcile refused"):
            fail_mode.reconcile_connector_registration(cfg, "codex")
    assert run.call_args.args[0][0] == str(real)


@posix_only
def test_the_sidecar_start_runs_the_install_gateway_not_the_environment_one(two_gateways, tmp_path: Path) -> None:
    real, _planted = two_gateways
    cfg = MagicMock(data_dir=str(tmp_path / "data"))
    started = subprocess.CompletedProcess([], 0, "", "")
    with (
        patch.object(bootstrap, "_pid_file_running", return_value=False),
        patch.object(bootstrap.subprocess, "run", return_value=started) as run,
    ):
        step = bootstrap._start_gateway_structured(cfg)
    assert step.status == "pass"
    assert run.call_args.args[0][0] == str(real)


@posix_only
def test_init_looks_up_the_install_gateway_not_the_environment_one(two_gateways) -> None:
    real, _planted = two_gateways
    out = subprocess.CompletedProcess([], 0, "defenseclaw-gateway 1.0.9\n", "")
    with patch.object(cmd_init.subprocess, "run", return_value=out) as run:
        assert cmd_init._get_gateway_version() == "1.0.9"
        cmd_init._restart_gateway_quiet()
    assert [call.args[0][0] for call in run.call_args_list] == [str(real), str(real)]


# ---- L-b: an override that names no file is reported as such


def test_readiness_says_when_the_override_names_a_missing_file(tmp_path: Path) -> None:
    from defenseclaw.config import default_config

    missing = tmp_path / "nowhere" / "defenseclaw-gateway"
    options = bootstrap.FirstRunOptions(connector="none")
    with (
        patch.dict(os.environ, {"DEFENSECLAW_GATEWAY_BIN": str(missing)}),
        patch.object(bootstrap, "_scanner_availability", return_value=[]),
    ):
        steps = bootstrap.targeted_readiness(default_config(), options)
    step = next(s for s in steps if s.name == "Gateway binary")
    assert step.status == "warn"
    assert step.detail.startswith("set by DEFENSECLAW_GATEWAY_BIN, not found")


def test_readiness_passes_when_the_override_names_a_real_file(tmp_path: Path) -> None:
    from defenseclaw.config import default_config

    present = _file(tmp_path / "defenseclaw-gateway")
    options = bootstrap.FirstRunOptions(connector="none")
    with (
        patch.dict(os.environ, {"DEFENSECLAW_GATEWAY_BIN": str(present)}),
        patch.object(bootstrap, "_scanner_availability", return_value=[]),
    ):
        steps = bootstrap.targeted_readiness(default_config(), options)
    step = next(s for s in steps if s.name == "Gateway binary")
    assert (step.status, step.detail) == ("pass", f"found at {present}")


# ---- L-a: the problem line strips control characters from the install root


def test_the_problem_line_strips_control_characters_from_the_install_root(tmp_path: Path) -> None:
    from tests.test_uninstall_legacy_setup_install import _install

    local = tmp_path.resolve() / "LocalAppData"
    local.mkdir()
    _install(local, install_root="C:\\Other\\Docs\x07\x1b[31m")
    with (
        patch.object(legacy_setup_install, "local_app_data", return_value=str(local)),
        patch.object(legacy_setup_install, "_ownership_problem", return_value=""),
    ):
        found = legacy_setup_install.find("win32")
    assert found is not None
    assert "C:\\Other\\Docs" in found.problem
    assert "\x07" not in found.problem and "\x1b" not in found.problem
