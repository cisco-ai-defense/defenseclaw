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

"""Upgrade-command wiring for the P7-WP03 local bundle transaction."""

from __future__ import annotations

import json
import os
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import Mock, patch

from click.testing import CliRunner
from defenseclaw.commands.cmd_upgrade import (
    _LocalBundleUpgradeInvocationError,
    _run_installed_local_observability_bundle_upgrade,
    _start_and_verify_services,
    upgrade,
)
from defenseclaw.config import Config
from defenseclaw.context import AppContext


def test_absent_install_skips_target_interpreter(tmp_path: Path) -> None:
    with patch("defenseclaw.commands.cmd_upgrade.subprocess.run") as run:
        result = _run_installed_local_observability_bundle_upgrade(
            str(tmp_path / "data"),
            str(tmp_path / "backup"),
            "8.0.0",
            os_name="darwin",
        )
    assert result == {"installed": False}
    run.assert_not_called()


def test_target_interpreter_returns_validated_refresh_result(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    (data_dir / "observability-stack").mkdir(parents=True)
    home = tmp_path / "home"
    python = home / ".defenseclaw/.venv/bin/python"
    python.parent.mkdir(parents=True)
    python.write_text("python\n", encoding="utf-8")

    def child(args, **_kwargs):
        result_path = args[-1]
        Path(result_path).write_text(
            json.dumps(
                {
                    "ok": True,
                    "result": {
                        "installed": True,
                        "refreshed": True,
                        "restart_required": False,
                        "changed_paths": ["docker-compose.yml"],
                    },
                }
            ),
            encoding="utf-8",
        )
        return Mock(returncode=0, stdout="", stderr="")

    with (
        patch.dict(os.environ, {"DEFENSECLAW_HOME": str(home / ".defenseclaw")}),
        patch("defenseclaw.commands.cmd_upgrade.subprocess.run", side_effect=child) as run,
    ):
        result = _run_installed_local_observability_bundle_upgrade(
            str(data_dir),
            str(tmp_path / "backup"),
            "8.0.0",
            os_name="darwin",
        )

    assert result["installed"] is True
    assert result["changed_paths"] == ["docker-compose.yml"]
    command = run.call_args.args[0]
    assert command[0] == str(python)
    assert command[4] == "refresh"
    assert command[5] == str(data_dir)
    assert command[6] == str(tmp_path / "backup")
    assert command[7] == "8.0.0"


def test_local_stack_restart_occurs_only_when_preupgrade_stack_was_running() -> None:
    app = AppContext()
    app.cfg = Config(data_dir="/tmp/defenseclaw-test")
    data_dir = app.cfg.data_dir
    with (
        patch("defenseclaw.commands.cmd_upgrade._run_silent", return_value=True),
        patch("defenseclaw.commands.cmd_upgrade._poll_health"),
        patch(
            "defenseclaw.commands.cmd_upgrade._run_installed_local_observability_bundle_restart",
            return_value={"installed": True, "restarted": True, "degraded_errors": []},
        ) as restart,
    ):
        _start_and_verify_services(
            app,
            5,
            data_dir=data_dir,
            local_bundle_upgrade={"installed": True, "restart_required": False},
            os_name="darwin",
        )
        restart.assert_not_called()
        _start_and_verify_services(
            app,
            5,
            data_dir=data_dir,
            local_bundle_upgrade={"installed": True, "restart_required": True},
            os_name="darwin",
        )
    restart.assert_called_once_with(
        "/tmp/defenseclaw-test",
        health_timeout=5,
        os_name="darwin",
    )


def test_bundle_refresh_failure_prevents_all_target_restarts(tmp_path: Path) -> None:
    runner = CliRunner()
    app = AppContext()
    app.cfg = Config(data_dir=str(tmp_path / "data"))
    app.cfg.claw.home_dir = str(tmp_path / "openclaw")
    (Path(app.cfg.data_dir) / "observability-stack").mkdir(parents=True)
    backup = str(tmp_path / "backup")
    rollback_plan = Mock(
        active_gateway_path="defenseclaw-gateway",
        backup_dir=backup,
    )

    with ExitStack() as stack:
        stack.enter_context(patch("defenseclaw.__version__", "9.9.8"))
        stack.enter_context(
            patch(
                "defenseclaw.commands.cmd_upgrade._detect_platform",
                return_value=("darwin", "arm64"),
            )
        )
        stack.enter_context(
            patch("defenseclaw.commands.cmd_upgrade._preflight_installed_source_coherence")
        )
        stack.enter_context(
            patch(
                "defenseclaw.commands.cmd_upgrade._download_release_provenance",
                return_value=Mock(),
            )
        )
        stack.enter_context(
            patch("defenseclaw.commands.cmd_upgrade._require_hard_cut_manifest_contract")
        )
        stack.enter_context(
            patch("defenseclaw.commands.cmd_upgrade._enforce_upgrade_source_contract")
        )
        stack.enter_context(
            patch(
                "defenseclaw.commands.cmd_upgrade._manifest_release_artifact_names",
                return_value=(
                    "defenseclaw_9.9.9_darwin_arm64.tar.gz",
                    "defenseclaw-9.9.9-py3-none-any.whl",
                ),
            )
        )
        stack.enter_context(
            patch("defenseclaw.commands.cmd_upgrade._is_bridge_to_hard_cut_phase", return_value=True)
        )
        stack.enter_context(
            patch("defenseclaw.commands.cmd_upgrade._require_release_owned_hard_cut_handoff")
        )
        stack.enter_context(
            patch(
                "defenseclaw.commands.cmd_upgrade._acquire_bridge_rollback_artifacts",
                return_value=str(tmp_path / "bridge-artifacts"),
            )
        )
        stack.enter_context(
            patch(
                "defenseclaw.commands.cmd_upgrade._validate_staged_bridge_artifact_set",
                return_value=({}, "/tmp/bridge.dcwheel", "/tmp/bridge.dcgateway"),
            )
        )
        stack.enter_context(
            patch("defenseclaw.commands.cmd_upgrade._require_bridge_checksums_provenance")
        )
        stack.enter_context(
            patch(
                "defenseclaw.commands.cmd_upgrade._materialize_bridge_source_wheel_for_preflight",
                return_value="/tmp/bridge.whl",
            )
        )
        stack.enter_context(
            patch(
                "defenseclaw.commands.cmd_upgrade._prepare_hard_cut_rollback_plan",
                return_value=rollback_plan,
            )
        )
        stack.enter_context(
            patch(
                "defenseclaw.commands.cmd_upgrade._write_hard_cut_recovery_journal",
                return_value=tmp_path / "phase-two-active.json",
            )
        )
        stack.enter_context(
            patch("defenseclaw.commands.cmd_upgrade._hold_phase_two_lease_for_command_lifetime")
        )
        stack.enter_context(
            patch("defenseclaw.commands.cmd_upgrade._mark_hard_cut_bundle_mutation_intent")
        )
        stack.enter_context(
            patch("defenseclaw.commands.cmd_upgrade._assert_gateway_quiesced")
        )
        stack.enter_context(
            patch("defenseclaw.commands.cmd_upgrade._execute_hard_cut_rollback", return_value=True)
        )
        stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._preflight_check"))
        stack.enter_context(
            patch(
                "defenseclaw.commands.cmd_upgrade._download_checksums",
                return_value={
                    "defenseclaw_9.9.9_darwin_arm64.tar.gz": "0" * 64,
                    "defenseclaw-9.9.9-py3-none-any.whl": "0" * 64,
                    "upgrade-manifest.json": "0" * 64,
                },
            )
        )
        stack.enter_context(
            patch(
                "defenseclaw.commands.cmd_upgrade._download_upgrade_manifest",
                return_value={
                    "min_upgrade_protocol": 2,
                    "migration_failure_policy": "fail",
                    "required_cli_migrations": ["0.8.5"],
                    "minimum_source_version": "9.9.8",
                    "required_bridge_version": "9.9.9",
                    "auto_bridge_from": [],
                },
            )
        )
        stack.enter_context(
            patch(
                "defenseclaw.commands.cmd_upgrade._download_gateway",
                return_value=("/tmp/gateway", "gateway.tar.gz"),
            )
        )
        stack.enter_context(
            patch(
                "defenseclaw.commands.cmd_upgrade._download_wheel",
                return_value=("/tmp/cli.whl", "cli.whl"),
            )
        )
        stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._preflight_wheel_install"))
        stack.enter_context(
            patch(
                "defenseclaw.commands.cmd_upgrade._install_gateway",
                return_value="/tmp/installed-gateway",
            )
        )
        stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._install_wheel"))
        stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._verify_installed_gateway_version"))
        stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._run_installed_migrations", return_value=0))
        stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._assert_required_cli_migrations"))
        stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._create_backup", return_value=backup))
        stack.enter_context(
            patch(
                "defenseclaw.commands.cmd_upgrade._run_installed_local_observability_bundle_upgrade",
                side_effect=_LocalBundleUpgradeInvocationError("activation_failed", "activate"),
            )
        )
        run_silent = stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._run_silent", return_value=True))
        poll_health = stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._poll_health"))
        restart = stack.enter_context(
            patch("defenseclaw.commands.cmd_upgrade._run_installed_local_observability_bundle_restart")
        )
        stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._check_post_upgrade_drift"))
        result = runner.invoke(upgrade, ["--yes", "--version", "9.9.9"], obj=app)

    assert result.exit_code == 1, result.output
    assert "Local observability bundle refresh failed; target services remain stopped" in result.output
    assert "failure=activation_failed phase=activate" in result.output
    assert "Upgrade Complete" not in result.output
    assert run_silent.call_count == 1
    assert run_silent.call_args.args[0] == ["defenseclaw-gateway", "stop"]
    poll_health.assert_not_called()
    restart.assert_not_called()


def test_restart_failure_is_degraded_after_gateway_health() -> None:
    app = AppContext()
    app.cfg = Config(data_dir="/tmp/defenseclaw-test")
    events: list[str] = []

    def run_silent(command, *_args, **_kwargs):
        events.append("gateway-start" if command[0] == "defenseclaw-gateway" else "openclaw")
        return True

    with (
        patch("defenseclaw.commands.cmd_upgrade._run_silent", side_effect=run_silent),
        patch(
            "defenseclaw.commands.cmd_upgrade._poll_health",
            side_effect=lambda *_args, **_kwargs: events.append("gateway-health"),
        ),
        patch(
            "defenseclaw.commands.cmd_upgrade._run_installed_local_observability_bundle_restart",
            side_effect=_LocalBundleUpgradeInvocationError("stack_restart_failed", "restart"),
        ),
    ):
        _start_and_verify_services(
            app,
            5,
            data_dir=app.cfg.data_dir,
            local_bundle_upgrade={"installed": True, "restart_required": True},
            os_name="darwin",
        )

    assert events == ["gateway-start", "openclaw", "gateway-health"]
