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

"""Doctor rows that warn or fail name a next step (final-cert UX batch)."""

from __future__ import annotations

import io
import json
import os
from contextlib import redirect_stdout
from unittest import mock

from defenseclaw.commands import cmd_doctor
from defenseclaw.commands.cmd_doctor import _DoctorResult
from defenseclaw.config_inspect import ConfigInspectError
from defenseclaw.observability.custody_status import (
    ConnectorCustodyReport,
    ConnectorCustodyStatus,
    summarize_native_delivery,
)


def _render(fn) -> str:
    out = io.StringIO()
    with (
        mock.patch.object(cmd_doctor, "_json_mode", False),
        mock.patch.object(cmd_doctor.ux, "_color_enabled", return_value=False),
        redirect_stdout(out),
    ):
        fn()
    return out.getvalue()


def test_warn_and_fail_rows_print_their_remediation() -> None:
    r = _DoctorResult()
    text = _render(
        lambda: (
            cmd_doctor._emit("warn", "Audit database size", "big", r=r, remediation="stop; VACUUM; start"),
            cmd_doctor._emit("pass", "Fine", "ok", r=r, remediation="never shown"),
            cmd_doctor._emit("fail", "Inline", "run: fix-it", r=r, remediation="fix-it"),
        )
    )
    assert "Next step: stop; VACUUM; start" in text
    assert "never shown" not in text
    # Already spelled out in the detail: no second line.
    assert "Next step: fix-it" not in text
    assert r.checks[0]["remediation"] == "stop; VACUUM; start"


def test_human_size_never_reads_zero_for_a_non_empty_file() -> None:
    assert cmd_doctor._human_size(909312) == "888 KiB"
    assert cmd_doctor._human_size(512) == "512 bytes"
    assert cmd_doctor._human_size(3 * 1024 * 1024) == "3.0 MiB"
    assert cmd_doctor._human_size(2094 * 1024 * 1024) == "2094 MiB"


def test_claude_code_without_hooks_names_setup(tmp_path) -> None:
    settings = tmp_path / "settings.json"
    settings.write_text(json.dumps({"hooks": {}}), encoding="utf-8")
    r = _DoctorResult()
    cmd_doctor._check_claudecode_hooks(mock.MagicMock(), r, platform_name="posix", config_path=str(settings))
    assert r.checks[-1]["status"] == "fail"
    assert "defenseclaw setup claude-code --yes" in r.checks[-1]["remediation"]


def test_passive_doctor_does_not_fail_an_idle_hermes(tmp_path) -> None:
    hook = tmp_path / "config.yaml"
    hook.write_text("hooks:\n  - command: /x/hooks/hermes-hook.sh\n", encoding="utf-8")
    cfg = mock.MagicMock()
    cfg.data_dir = str(tmp_path)
    with mock.patch.object(cmd_doctor, "_hook_health_paths_from_lock", return_value=[str(hook)]):
        passive = _DoctorResult(passive=True)
        cmd_doctor._check_hook_health(cfg, "hermes", passive)
    row = passive.checks[-1]
    assert row["status"] == "warn"
    # Setup readiness still reads it as pending reload.
    assert "running hermes" in row["detail"].casefold() and "live=false" in row["detail"]
    assert "without --passive" in row["remediation"]


def test_codex_plugin_cache_missing_is_not_a_warning() -> None:
    cfg = mock.MagicMock()
    cfg.skill_dirs.return_value = []
    cfg.plugin_dirs.return_value = [os.path.join(os.sep, "nonexistent", "plugins", "cache")]
    cfg.mcp_servers.return_value = []
    cfg.guardrail.effective_mode.return_value = "observe"
    cfg.guardrail.effective_hook_fail_mode.return_value = "closed"
    cfg.guardrail.effective_rule_pack_dir.return_value = ""
    cfg.data_dir = ""
    r = _DoctorResult()
    cmd_doctor._check_connector_inventory(cfg, "codex", r)
    row = next(c for c in r.checks if c["label"] == "Plugin paths")
    assert row["status"] == "skip"
    assert "nothing to do" in row["detail"]


def test_loopback_endpoints_are_recognized() -> None:
    assert cmd_doctor._endpoint_is_loopback("127.0.0.1:14317")
    assert cmd_doctor._endpoint_is_loopback("http://localhost:4318/v1/traces")
    assert cmd_doctor._endpoint_is_loopback("[::1]:4317")
    assert not cmd_doctor._endpoint_is_loopback("10.0.0.5:4317")
    assert not cmd_doctor._endpoint_is_loopback("collector.example.com:4317")
    assert not cmd_doctor._endpoint_is_loopback("")


def test_fix_preflight_names_the_invalid_field(tmp_path) -> None:
    (tmp_path / "config.yaml").write_text("guardrail:\n  mode: enforce-everything\n", encoding="utf-8")
    cfg = mock.MagicMock()
    cfg.data_dir = str(tmp_path)
    error = ConfigInspectError(
        "candidate field=$.guardrail.mode; reason=...",
        field_path="$.guardrail.mode",
        reason='expected one of ["observe","action"]; '
        "inspect the canonical v8 schema or generated reference and correct this field",
    )
    with mock.patch("defenseclaw.config_inspect.inspect_v8_config", side_effect=error):
        decision = cmd_doctor._plan_canonical_config_preflight(cfg)
    assert decision.state == "blocked"
    assert "$.guardrail.mode is invalid" in decision.detail
    assert '["observe","action"]' in decision.detail
    assert "defenseclaw doctor --fix" in decision.detail
    assert "generated reference" not in decision.detail


def test_partial_drop_only_names_signals_and_next_step() -> None:
    report = ConnectorCustodyReport(
        state="available",
        reason="",
        observation_window_hours=24,
        instances=(
            ConnectorCustodyStatus(
                connector_instance_id="019b0000-0000-7000-8000-000000000001",
                connector="claudecode",
                custody="defenseclaw",
                profile_version="claudecode-v1",
                default=True,
                managed_config_state="verified",
                managed_config_files=1,
                normalized_batches=18,
                drop_only_batches=13,
                drop_only_signals=("metrics",),
            ),
        ),
    )
    (row,) = summarize_native_delivery(report).connectors
    assert "dropped signals: metrics" in row.detail
    r = _DoctorResult()
    cmd_doctor._check_connector_export_custody(report, r)
    check = r.checks[-1]
    assert check["status"] == "warn"
    assert "defenseclaw setup claude-code" in check["remediation"]
