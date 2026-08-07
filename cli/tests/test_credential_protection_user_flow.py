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

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from click.testing import CliRunner
from defenseclaw.commands.cmd_setup import setup
from defenseclaw.context import AppContext


def _setup_app(tmp_path: Path, *, enabled: bool) -> tuple[AppContext, Path, list[bool]]:
    app = AppContext()
    config_file = tmp_path / "config.yaml"
    saved: list[bool] = []
    credential = SimpleNamespace(enabled=enabled)

    def save() -> None:
        saved.append(bool(credential.enabled))
        config_file.write_text(
            f"credential_protection:\n  enabled: {str(credential.enabled).lower()}\n",
            encoding="utf-8",
        )

    app.cfg = SimpleNamespace(
        data_dir=str(tmp_path),
        credential_protection=credential,
        save=save,
    )
    return app, config_file, saved


def test_setup_group_enable_fails_and_rolls_back_when_gateway_restart_fails(tmp_path):
    app, config_file, saved = _setup_app(tmp_path, enabled=False)
    installed = [
        {
            "connector": "codex",
            "mcp_registration": "installed",
            "changed": True,
            "proxy_prompt_tokenization": "not_in_direct_upstream_path",
        }
    ]

    with (
        patch(
            "defenseclaw.commands.cmd_setup._config_yaml_path_from_ctx",
            return_value=str(config_file),
        ),
        patch("defenseclaw.commands.cmd_setup._is_pid_alive", return_value=True),
        patch(
            "defenseclaw.commands.cmd_setup._restart_defense_gateway",
            side_effect=[False, True],
        ) as restart,
        patch(
            "defenseclaw.commands.cmd_setup._quiesce_unverified_defense_gateway",
            return_value=True,
        ) as quiesce,
        patch(
            "defenseclaw.commands.cmd_credential_protection.setup_broker_for_runtime",
            return_value={"ready": True, "version": "0.2.0"},
        ),
        patch(
            "defenseclaw.commands.cmd_credential_protection.reconcile_mcp_connectors",
            return_value=installed,
        ),
        patch(
            "defenseclaw.commands.cmd_credential_protection.rollback_mcp_reconciliation",
            return_value=True,
        ) as rollback,
    ):
        result = CliRunner().invoke(
            setup,
            ["credential-protection", "--yes"],
            obj=app,
        )

    assert result.exit_code == 1, result.output
    assert "could not restart the running gateway" in result.output
    assert "rolled back to disabled" in result.output
    assert app.cfg.credential_protection.enabled is False
    assert saved == [True, False]
    rollback.assert_called_once_with(app.cfg, installed)
    assert restart.call_count == 2
    quiesce.assert_called_once_with(str(tmp_path))


def test_setup_group_disable_fails_and_restores_state_when_gateway_restart_fails(tmp_path):
    app, config_file, saved = _setup_app(tmp_path, enabled=True)
    removed = [
        {
            "connector": "codex",
            "mcp_registration": "removed",
            "changed": True,
            "proxy_prompt_tokenization": "not_in_direct_upstream_path",
        }
    ]

    with (
        patch(
            "defenseclaw.commands.cmd_setup._config_yaml_path_from_ctx",
            return_value=str(config_file),
        ),
        patch("defenseclaw.commands.cmd_setup._is_pid_alive", return_value=True),
        patch(
            "defenseclaw.commands.cmd_setup._restart_defense_gateway",
            side_effect=[False, True],
        ) as restart,
        patch(
            "defenseclaw.commands.cmd_setup._quiesce_unverified_defense_gateway",
            return_value=True,
        ) as quiesce,
        patch(
            "defenseclaw.commands.cmd_credential_protection.remove_managed_mcp_connectors",
            return_value=removed,
        ),
        patch(
            "defenseclaw.commands.cmd_credential_protection.rollback_mcp_removal",
            return_value=True,
        ) as rollback,
    ):
        result = CliRunner().invoke(
            setup,
            ["credential-protection", "--disable", "--yes"],
            obj=app,
        )

    assert result.exit_code == 1, result.output
    assert "could not restart the running gateway" in result.output
    assert "rolled back to enabled" in result.output
    assert app.cfg.credential_protection.enabled is True
    assert saved == [False, True]
    rollback.assert_called_once_with(app.cfg, removed)
    assert restart.call_count == 2
    quiesce.assert_called_once_with(str(tmp_path))


def test_setup_group_leaves_gateway_stopped_when_restored_restart_is_unhealthy(tmp_path):
    app, config_file, saved = _setup_app(tmp_path, enabled=False)
    installed = [
        {
            "connector": "codex",
            "mcp_registration": "installed",
            "changed": True,
            "proxy_prompt_tokenization": "not_in_direct_upstream_path",
        }
    ]

    with (
        patch(
            "defenseclaw.commands.cmd_setup._config_yaml_path_from_ctx",
            return_value=str(config_file),
        ),
        patch("defenseclaw.commands.cmd_setup._is_pid_alive", return_value=True),
        patch(
            "defenseclaw.commands.cmd_setup._restart_defense_gateway",
            side_effect=[False, False],
        ) as restart,
        patch(
            "defenseclaw.commands.cmd_setup._quiesce_unverified_defense_gateway",
            return_value=True,
        ) as quiesce,
        patch(
            "defenseclaw.commands.cmd_credential_protection.setup_broker_for_runtime",
            return_value={"ready": True, "version": "0.2.0"},
        ),
        patch(
            "defenseclaw.commands.cmd_credential_protection.reconcile_mcp_connectors",
            return_value=installed,
        ),
        patch(
            "defenseclaw.commands.cmd_credential_protection.rollback_mcp_reconciliation",
            return_value=True,
        ),
    ):
        result = CliRunner().invoke(
            setup,
            ["credential-protection", "--yes"],
            obj=app,
        )

    assert result.exit_code == 1, result.output
    assert "gateway remains stopped" in result.output
    assert app.cfg.credential_protection.enabled is False
    assert saved == [True, False]
    assert restart.call_count == 2
    assert quiesce.call_count == 2
