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

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest
from click.testing import CliRunner
from defenseclaw.bootstrap import FirstRunOptions, targeted_readiness
from defenseclaw.commands import cmd_doctor
from defenseclaw.commands.cmd_config import ValidationResult
from defenseclaw.config import default_config
from defenseclaw.main import cli, doctor, status


@pytest.mark.parametrize(
    "arguments",
    (
        ["doctor"],
        ["doctor", "--fix", "--dry-run"],
    ),
)
def test_doctor_dispatch_never_initializes_audit_store(arguments: list[str]) -> None:
    """Doctor must observe, rather than create, authoritative audit state."""

    cfg = SimpleNamespace(audit_db="/does/not/exist/audit.db")
    callback = Mock(return_value=None)
    with (
        patch("defenseclaw.config.load", return_value=cfg) as load,
        patch("defenseclaw.db.Store") as store,
        patch.object(doctor, "callback", callback),
    ):
        result = CliRunner().invoke(cli, arguments)

    assert result.exit_code == 0, result.output
    load.assert_called_once_with()
    store.assert_not_called()
    callback.assert_called_once()


def test_doctor_renders_raw_validation_when_runtime_config_load_fails() -> None:
    validation = ValidationResult()
    validation.path = "/isolated/.defenseclaw/config.yaml"
    validation.exists = True
    validation.errors.append("guardrail.port: must be between 1 and 65535")

    with (
        patch(
            "defenseclaw.config.load",
            side_effect=TypeError("gateway must be a mapping"),
        ),
        patch(
            "defenseclaw.commands.cmd_config.validate_config",
            return_value=validation,
        ) as validate,
        patch("defenseclaw.db.Store") as store,
        patch.object(cmd_doctor, "_json_mode", False),
    ):
        result = CliRunner().invoke(
            cli,
            ["doctor", "--fix", "--dry-run", "--json-output"],
        )

    assert result.exit_code == 1, result.output
    payload = json.loads(result.output)
    assert payload["failed"] >= 2
    checks = payload["checks"]
    assert any(item["label"] == "Config validation" and "guardrail.port" in item["detail"] for item in checks)
    load_failure = next(item for item in checks if item["label"] == "Config load")
    assert load_failure["status"] == "fail"
    assert "no startup mutation or automatic repair was attempted" in load_failure["detail"]
    assert "defenseclaw config validate" in load_failure["detail"]
    validate.assert_called_once_with()
    store.assert_not_called()


def test_doctor_config_load_failure_replaces_stale_green_cache(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cache = tmp_path / "doctor_cache.json"
    cache.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "outcome": "healthy",
                "exit_code": 0,
                "summary": {"passed": 1, "failed": 0, "warned": 0, "skipped": 0},
                "repair_summary": {
                    "planned": 0,
                    "applied": 0,
                    "failed": 0,
                    "blocked": 0,
                    "manual": 0,
                    "noop": 0,
                    "declined": 0,
                    "requires_confirmation": 0,
                },
                "checks": [],
                "repairs": [],
            }
        ),
        encoding="utf-8",
    )
    validation = ValidationResult()
    validation.path = str(tmp_path / "config.yaml")
    validation.exists = True
    validation.errors.append("gateway.api_port: expected an integer")
    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path))

    with (
        patch(
            "defenseclaw.config.load",
            side_effect=TypeError("gateway must be a mapping"),
        ),
        patch(
            "defenseclaw.commands.cmd_config.validate_config",
            return_value=validation,
        ),
    ):
        result = CliRunner().invoke(cli, ["doctor", "--json"])

    assert result.exit_code == 1, result.output
    saved = json.loads(cache.read_text(encoding="utf-8"))
    assert saved["schema_version"] == 2
    assert saved["outcome"] == "failed"
    assert saved["exit_code"] == 1
    assert saved["failed"] >= 2


def test_non_doctor_command_keeps_store_initialization() -> None:
    """The Doctor exemption must not weaken ordinary command startup."""

    cfg = SimpleNamespace(
        audit_db="/isolated/audit.db",
        _source_config_version=8,
    )
    validation = ValidationResult()
    callback = Mock(return_value=None)
    logger = Mock()
    with (
        patch("defenseclaw.config.require_v8_config"),
        patch("defenseclaw.config.load", return_value=cfg),
        patch(
            "defenseclaw.commands.cmd_config.validate_config",
            return_value=validation,
        ),
        patch("defenseclaw.db.Store") as store,
        patch("defenseclaw.logger.Logger.from_config", return_value=logger),
        patch.object(status, "callback", callback),
    ):
        result = CliRunner().invoke(cli, ["status"])

    assert result.exit_code == 0, result.output
    store.assert_called_once_with(cfg.audit_db)
    store.return_value.init.assert_called_once_with()
    callback.assert_called_once()


def test_invalid_config_guidance_does_not_claim_doctor_can_repair_it() -> None:
    cfg = SimpleNamespace(
        audit_db="/isolated/audit.db",
        _source_config_version=8,
    )
    validation = ValidationResult()
    validation.errors.append("gateway.api_port: expected an integer")
    with (
        patch("defenseclaw.config.require_v8_config"),
        patch("defenseclaw.config.load", return_value=cfg),
        patch(
            "defenseclaw.commands.cmd_config.validate_config",
            return_value=validation,
        ),
        patch("defenseclaw.db.Store") as store,
    ):
        result = CliRunner().invoke(cli, ["status"])

    assert result.exit_code == 1, result.output
    assert "defenseclaw config validate" in result.output
    assert "doctor --fix" not in result.output
    store.assert_not_called()


def test_bootstrap_missing_authoritative_state_points_to_init(tmp_path) -> None:
    cfg = default_config()
    cfg.data_dir = str(tmp_path)
    cfg.audit_db = str(tmp_path / "audit.db")
    cfg.gateway.device_key_file = str(tmp_path / "device.key")

    steps = targeted_readiness(
        cfg,
        FirstRunOptions(connector="none", start_gateway=False),
    )
    by_name = {step.name: step for step in steps}

    assert by_name["Audit database"].status == "fail"
    assert by_name["Audit database"].next_command == (
        "defenseclaw doctor --fix --fix-id doctor.state.audit-db.initialize"
    )
    assert by_name["Device key"].status == "fail"
    assert by_name["Device key"].next_command == (
        "defenseclaw doctor --fix --fix-id doctor.identity.device-key.initialize"
    )
