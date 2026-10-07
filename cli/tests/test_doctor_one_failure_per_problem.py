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

"""Doctor wording: one failure per config problem, next steps that help."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from defenseclaw.commands.cmd_doctor import (
    _check_config,
    _check_observability,
    _DoctorResult,
    _opencode_runtime_remediation,
    _warnings_label,
)
from defenseclaw.config_inspect import ConfigInspectError
from defenseclaw.doctor_preflight import inspect_doctor_config_load_failure


def test_config_validation_next_step_is_not_config_validate(tmp_path: Path) -> None:
    # GAP-1662: 'config validate' would print the same line again.
    (tmp_path / "config.yaml").write_text("config_version: 8\nguardrail:\n  mode: enforce-everything\n")
    refusal = ConfigInspectError(
        "invalid",
        field_path="$.guardrail.mode",
        reason='[config_schema_invalid] value not allowed; expected one of ["observe","action"]',
    )
    r = _DoctorResult()
    with patch("defenseclaw.config_inspect.inspect_v8_config", side_effect=refusal):
        _check_config(SimpleNamespace(data_dir=str(tmp_path)), r)
    row = r.checks[0]
    assert row["status"] == "fail"
    assert "guardrail.mode" in row["detail"]
    assert "config validate" not in row["remediation"]
    assert "correct config.yaml" in row["remediation"]


def test_missing_key_next_step_is_keys_set_not_editing_config(tmp_path: Path) -> None:
    # GAP-1915: the file is fine; the key it names has no value.
    (tmp_path / "config.yaml").write_text(
        "config_version: 8\nobservability:\n  destinations:\n    - name: galileo\n"
        "      headers:\n        Galileo-API-Key: {env: GALILEO_API_KEY}\n"
    )
    refusal = ConfigInspectError(
        "invalid",
        field_path='$.observability.destinations[0].headers["Galileo-API-Key"]',
        reason="[secret_reference_unresolved] required environment-backed secret is unavailable",
    )
    r = _DoctorResult()
    with patch("defenseclaw.config_inspect.inspect_v8_config", side_effect=refusal):
        _check_config(SimpleNamespace(data_dir=str(tmp_path)), r)
    row = r.checks[0]
    assert row["status"] == "fail"
    assert "Until it is set, setup commands refuse to run" in row["detail"]
    assert "setup commands check the whole file" not in row["detail"]
    assert row["remediation"].startswith("run `defenseclaw keys set GALILEO_API_KEY`")
    assert "correct config.yaml" not in row["remediation"]


def test_health_summary_says_one_warning() -> None:
    # GAP-1913.
    assert _warnings_label(1) == "1 warning"
    assert _warnings_label(5) == "5 warnings"


def test_observability_plan_skips_after_config_validation_failed(tmp_path: Path) -> None:
    # GAP-1662: the guardrail error is not repeated as an observability failure.
    (tmp_path / "config.yaml").write_text("config_version: 8\nobservability:\n  destinations: wrong\n")
    r = _DoctorResult()
    r.record("fail", "Config validation", "line 2: ...", check_id="doctor.config.validation")
    _check_observability(SimpleNamespace(data_dir=str(tmp_path)), r)
    row = next(c for c in r.checks if c["label"] == "Observability plan")
    assert row["status"] == "skip"
    assert "Config validation row" in row["detail"]
    assert r.failed == 1


def test_opencode_remediation_names_the_gateway_when_it_is_down() -> None:
    # GAP-1712.
    down = _opencode_runtime_remediation("warn", "runtime load not checked: the gateway is not running")
    assert "defenseclaw-gateway start" in down
    assert "OpenCode" not in down
    assert "start OpenCode" in _opencode_runtime_remediation("warn", "runtime load unverified: x")
    assert _opencode_runtime_remediation("pass", "loaded") == ""


def test_config_load_row_skips_when_validation_names_the_problem() -> None:
    # GAP-1692: an empty config.yaml gets one FAIL and one repair, no class name.
    validation = SimpleNamespace(
        path="/home/u/.defenseclaw/config.yaml",
        exists=True,
        parse_error="",
        errors=["/home/u/.defenseclaw/config.yaml is empty; remove the empty file and run defenseclaw init."],
        warnings=[],
        ok=False,
    )
    with patch("defenseclaw.commands.cmd_config.validate_config", return_value=validation):
        diag = inspect_doctor_config_load_failure(RuntimeError("ConfigVersionError: no config_version"))
    load = next(c for c in diag.checks if c.label == "Config load")
    assert load.status == "skip"
    assert "ConfigVersionError" not in load.detail
    assert [c.status for c in diag.checks].count("fail") == 1
    assert "upgrade" not in diag.remediation
    assert "Fix the config problem above" in diag.remediation
