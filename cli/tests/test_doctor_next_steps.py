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


def _custody_report(**overrides) -> ConnectorCustodyReport:
    fields = dict(
        connector_instance_id="019b0000-0000-7000-8000-000000000001",
        connector="claudecode",
        custody="defenseclaw",
        profile_version="claudecode-v1",
        default=True,
        managed_config_state="verified",
        managed_config_files=1,
        normalized_batches=11,
        drop_only_batches=8,
        drop_only_signals=("logs", "metrics"),
    )
    fields.update(overrides)
    return ConnectorCustodyReport(
        state="available",
        reason="",
        observation_window_hours=24,
        instances=(ConnectorCustodyStatus(**fields),),
    )


def test_unmapped_only_drops_are_healthy_delivery() -> None:
    # GAP-1090 / GAP-0052: a healthy agent sends record types DefenseClaw
    # does not map; those batches are skipped by design, not lost.
    report = _custody_report(drop_only_reasons=("unsupported_identity",))
    (row,) = summarize_native_delivery(report).connectors
    assert row.state == "accepted"
    assert "does not map, skipped by design" in row.detail
    r = _DoctorResult()
    cmd_doctor._check_connector_export_custody(report, r)
    assert r.checks[-1]["status"] == "pass"
    assert "partial drop-only" not in r.checks[-1]["detail"]


def test_real_drop_reasons_still_warn_with_the_reason() -> None:
    report = _custody_report(drop_only_reasons=("invalid_record", "unsupported_identity"))
    (row,) = summarize_native_delivery(report).connectors
    assert row.state == "partial_drop_only"
    assert "reason: invalid record, unsupported identity" in row.detail
    r = _DoctorResult()
    cmd_doctor._check_connector_export_custody(report, r)
    assert r.checks[-1]["status"] == "warn"
    assert "defenseclaw setup claude-code" in r.checks[-1]["remediation"]


def test_untracked_exporter_and_unattributed_credentials_read_plainly() -> None:
    report = _custody_report(managed_config_state="untracked", drop_only_batches=0)
    report = ConnectorCustodyReport(
        state="available",
        reason="",
        observation_window_hours=24,
        instances=report.instances,
        unattributed_authentication_failures=4,
    )
    r = _DoctorResult()
    cmd_doctor._check_connector_export_custody(report, r)
    rows = {c["label"]: c for c in r.checks}
    assert "drift is not checked" in rows["Connector OTLP: claudecode"]["detail"]
    assert "managed-exporter=untracked" not in rows["Connector OTLP: claudecode"]["detail"]
    credentials = rows["Native OTLP credentials"]
    assert credentials["status"] == "warn"
    assert "defenseclaw setup <connector>" in credentials["remediation"]


def test_drop_reason_class_is_read_from_the_drop_record() -> None:
    from defenseclaw.observability.custody_status import _telemetry_facts

    body = {
        "defenseclaw.telemetry.record_count": 3,
        "defenseclaw.telemetry.signal": "logs",
        "defenseclaw.telemetry.rejection_reason_class": "unsupported_identity",
    }
    assert _telemetry_facts(json.dumps({"body": body}))["reason"] == "unsupported_identity"


def test_destination_rows_name_a_next_step() -> None:
    from types import SimpleNamespace

    destination = SimpleNamespace(name="fdvlan", endpoint="10.0.1.40:14399")
    failing = SimpleNamespace(state="failing", circuit_state="closed")
    text = cmd_doctor._destination_remediation(destination, failing)
    assert "defenseclaw observability destination test fdvlan" in text
    assert "10.0.1.40:14399" in text
    starting = SimpleNamespace(state="initializing", circuit_state="")
    assert "run 'defenseclaw doctor' again" in cmd_doctor._destination_remediation(destination, starting)
    assert "defenseclaw-gateway start" in cmd_doctor._destination_remediation(destination, None)
    # The open-circuit detail already spells out the repair.
    assert cmd_doctor._destination_remediation(destination, SimpleNamespace(state="failing", circuit_state="open")) == ""


def test_header_corrupt_audit_db_names_gateway_restart(tmp_path) -> None:
    from defenseclaw.doctor_recovery import AuditDBHealthStatus

    health = mock.MagicMock(status=AuditDBHealthStatus.INVALID, reason_code="audit-db-integrity-unavailable")
    cfg = mock.MagicMock(audit_db=str(tmp_path / "audit.db"), data_dir=str(tmp_path))
    r = _DoctorResult()
    with mock.patch("defenseclaw.doctor_recovery.inspect_audit_db", return_value=health):
        cmd_doctor._check_audit_db_store(cfg, r)
    assert r.checks[-1]["status"] == "fail"
    assert "defenseclaw-gateway restart" in r.checks[-1]["remediation"]


def _bedrock_judge_cfg(tmp_path, auth_mode: str):
    from defenseclaw.config import (
        BedrockKeyConfig,
        Config,
        GatewayConfig,
        GuardrailConfig,
        LLMConfig,
        OpenShellConfig,
    )

    cfg = Config(
        data_dir=str(tmp_path),
        audit_db=str(tmp_path / "audit.db"),
        quarantine_dir=str(tmp_path / "q"),
        plugin_dir=str(tmp_path / "p"),
        policy_dir=str(tmp_path / "pol"),
        guardrail=GuardrailConfig(enabled=True, mode="action", connector="claudecode"),
        gateway=GatewayConfig(),
        openshell=OpenShellConfig(),
    )
    cfg.claw.mode = "claudecode"
    cfg.llm = LLMConfig(api_key_env="DEFENSECLAW_LLM_KEY")
    cfg.guardrail.judge.enabled = True
    cfg.guardrail.judge.llm = LLMConfig(
        provider="bedrock",
        model="us.anthropic.claude-haiku-4-5-20251001-v1:0",
        bedrock=BedrockKeyConfig(region="us-east-1", auth_mode=auth_mode),
    )
    return cfg


def test_bedrock_instance_role_judge_needs_no_api_key(tmp_path, monkeypatch) -> None:
    # GAP-1242 / GAP-1289: instance_role authenticates with AWS credentials.
    monkeypatch.delenv("DEFENSECLAW_LLM_KEY", raising=False)
    r = _DoctorResult()
    cmd_doctor._check_llm_api_key(_bedrock_judge_cfg(tmp_path, "instance_role"), r)
    assert r.checks[-1]["status"] == "skip"
    assert "auth_mode=instance_role" in r.checks[-1]["detail"]


def test_bedrock_api_key_judge_without_key_fails_with_next_step(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("DEFENSECLAW_LLM_KEY", raising=False)
    r = _DoctorResult()
    cmd_doctor._check_llm_api_key(_bedrock_judge_cfg(tmp_path, "api_key"), r)
    assert r.checks[-1]["status"] == "fail"
    assert "defenseclaw setup llm" in r.checks[-1]["remediation"]


def test_setup_llm_summary_says_why_no_key_is_needed() -> None:
    from defenseclaw.commands.cmd_setup import _llm_key_state
    from defenseclaw.config import BedrockKeyConfig, LLMConfig

    keyless = LLMConfig(provider="bedrock", bedrock=BedrockKeyConfig(auth_mode="instance_role"))
    assert _llm_key_state(keyless, "") == "(not needed: bedrock auth_mode=instance_role uses AWS credentials)"
    assert _llm_key_state(LLMConfig(provider="bedrock"), "") == "(not set)"


def test_retention_days_is_read_from_config_yaml(tmp_path, monkeypatch) -> None:
    # GAP-1329: the CLI model has no observability.local, so doctor reads the
    # value the gateway honors from config.yaml.
    from types import SimpleNamespace

    monkeypatch.delenv("DEFENSECLAW_CONFIG", raising=False)
    cfg = SimpleNamespace(data_dir=str(tmp_path), observability=SimpleNamespace(connectors={}))
    assert cmd_doctor._configured_local_retention_days(cfg) == 7
    (tmp_path / "config.yaml").write_text("observability:\n  local:\n    retention_days: 0\n", encoding="utf-8")
    assert cmd_doctor._configured_local_retention_days(cfg) == 0
    (tmp_path / "config.yaml").write_text("observability:\n  local:\n    retention_days: 30\n", encoding="utf-8")
    assert cmd_doctor._configured_local_retention_days(cfg) == 30


def test_windows_hermes_idle_is_healthy_not_pending_reload() -> None:
    # GAP-1298: with no Hermes process for the account there is nothing to reload.
    from defenseclaw.doctor_hooks import WindowsHookCheck

    listing = '"pwsh.exe","4100","RDP-Tcp#0","2","90,000 K"\n"defenseclaw-gateway.exe","4200","RDP-Tcp#0","2","40,000 K"\n'
    assert cmd_doctor._hermes_host_running_windows(listing) is False
    assert cmd_doctor._hermes_host_running_windows(listing + '"hermes.exe","4300","RDP-Tcp#0","2","9 K"\n') is True
    assert cmd_doctor._hermes_host_running_windows(listing + '"python.exe","4400","RDP-Tcp#0","2","9 K"\n') is None
    assert cmd_doctor._hermes_host_running_windows("INFO: No tasks are running.\n") is None

    pending = WindowsHookCheck(
        "pending-reload",
        "on-disk Windows-native executable registration is valid; hook_entries=23; running Hermes "
        "CLI/TUI/gateway/desktop/service hosts are unverified and must be reloaded or restarted; live=false",
    )
    with mock.patch.object(cmd_doctor, "_hermes_host_running", return_value=False):
        idle = cmd_doctor._hermes_idle_native_check(pending, _DoctorResult())
        assert idle.healthy and "no Hermes host is running" in idle.detail and "live=false" not in idle.detail
        assert cmd_doctor._hermes_idle_native_check(pending, _DoctorResult(passive=True)) is pending
    with mock.patch.object(cmd_doctor, "_hermes_host_running", return_value=True):
        assert cmd_doctor._hermes_idle_native_check(pending, _DoctorResult()) is pending


def test_hook_only_doctor_rows_skip_fleet_and_windows_wording_and_flag_bad_mode() -> None:
    # GAP-1363
    cfg = mock.MagicMock()
    cfg.active_connectors.return_value = ["claudecode", "codex"]
    assert cmd_doctor._fleet_uplink_unused(cfg) is True
    cfg.active_connectors.return_value = ["codex", "openclaw"]
    assert cmd_doctor._fleet_uplink_unused(cfg) is False

    repair, detail = cmd_doctor._watchdog_repair_posture(cfg, platform_name="linux")
    assert repair is False and "windows" not in detail.lower()

    cfg.skill_dirs.return_value = []
    cfg.plugin_dirs.return_value = []
    cfg.mcp_servers.return_value = []
    cfg.guardrail.effective_mode.return_value = "enforce-everything"
    cfg.guardrail.effective_hook_fail_mode.return_value = "open"
    cfg.guardrail.effective_rule_pack_dir.return_value = ""
    cfg.data_dir = ""
    r = _DoctorResult()
    cmd_doctor._check_connector_inventory(cfg, "claudecode", r)
    row = next(c for c in r.checks if c["label"] == "Mode")
    assert row["status"] == "fail" and "expected observe or action" in row["detail"]


def test_judge_only_llm_is_probed_by_llm_reachable(tmp_path, monkeypatch) -> None:
    # GAP-1365: `setup llm --role judge` leaves the unified model empty.
    monkeypatch.delenv("DEFENSECLAW_LLM_MODEL", raising=False)
    cfg = _bedrock_judge_cfg(tmp_path, "api_key")
    r = _DoctorResult()
    with mock.patch("defenseclaw.llm.ping", return_value=(True, "ok (1 token)")) as ping:
        cmd_doctor._check_llm_reachable(cfg, r)
    assert ping.call_args[0][0].model == "us.anthropic.claude-haiku-4-5-20251001-v1:0"
    assert r.checks[-1]["status"] == "pass" and r.checks[-1]["detail"].startswith("judge LLM: ")


def test_disk_full_audit_writes_read_plainly(tmp_path) -> None:
    # GAP-1308: a full disk is a FAIL with a next step, and the telemetry
    # error names the cause instead of internal tokens.
    details = {
        "event_history_failure": "sqlite_write_failed",
        "event_history_last_sqlite_class": "full",
        "event_history_last_sqlite_primary_code": 13,
    }
    assert "disk holding the audit database is full" in cmd_doctor._telemetry_error_reason(details)
    assert cmd_doctor._telemetry_error_reason({"event_history_failure": ""}) == ""

    from types import SimpleNamespace

    from defenseclaw.doctor_recovery import AuditDBHealthStatus

    health = mock.MagicMock(
        status=AuditDBHealthStatus.VALID, file_bytes=1024, freelist_bytes=0, oldest_retention_unix_nano=None
    )
    cfg = SimpleNamespace(audit_db=str(tmp_path / "audit.db"), data_dir=str(tmp_path), observability=None)
    r = _DoctorResult()
    with (
        mock.patch("defenseclaw.doctor_recovery.inspect_audit_db", return_value=health),
        mock.patch.object(cmd_doctor.shutil, "disk_usage", return_value=SimpleNamespace(free=0)),
    ):
        cmd_doctor._check_audit_db_store(cfg, r)
    row = next(c for c in r.checks if c["label"] == "Audit storage capacity")
    assert row["status"] == "fail" and "is full" in row["detail"]
    assert "free space" in row["remediation"]
