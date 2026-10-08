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

import dataclasses
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
    # GAP-0100: --fix --dry-run is passive but still lists processes, so it
    # reports an idle Hermes as the plain doctor does.
    with mock.patch.object(cmd_doctor, "_hook_health_paths_from_lock", return_value=[str(hook)]), \
            mock.patch.object(cmd_doctor, "_hermes_host_running", return_value=False):
        dry_run = _DoctorResult(mode="plan", passive=True, list_processes=True)
        cmd_doctor._check_hook_health(cfg, "hermes", dry_run)
    assert dry_run.checks[-1]["status"] == "pass"


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


def test_all_unmapped_window_is_not_a_bypass_failure() -> None:
    # GAP-1664: every batch unmapped right after setup (no model call succeeded yet).
    report = _custody_report(
        custody="external", normalized_batches=18, drop_only_batches=18, drop_only_reasons=("unsupported_identity",)
    )
    (row,) = summarize_native_delivery(report).connectors
    assert row.state == "unmapped_only"
    assert "no mapped native records yet (18/18" in row.detail
    r = _DoctorResult()
    cmd_doctor._check_connector_export_custody(report, r)
    check = r.checks[-1]
    assert check["status"] == "warn"
    assert "bypasses DefenseClaw" not in check["detail"]
    assert "reaches this gateway" in check["detail"]
    assert "setup" not in check["remediation"]


def test_real_drop_reasons_still_warn_with_the_reason() -> None:
    report = _custody_report(drop_only_reasons=("invalid_record", "unsupported_identity"))
    (row,) = summarize_native_delivery(report).connectors
    assert row.state == "partial_drop_only"
    assert "reason: invalid record, unsupported identity" in row.detail
    r = _DoctorResult()
    cmd_doctor._check_connector_export_custody(report, r)
    assert r.checks[-1]["status"] == "warn"
    assert "defenseclaw setup claude-code" in r.checks[-1]["remediation"]


def test_removed_connectors_get_no_otlp_rows_or_setup_advice() -> None:
    # GAP-1931: OpenClaw-only after removing the hook connectors.
    def status(connector: str, **overrides) -> ConnectorCustodyStatus:
        base = _custody_report().instances[0]
        return dataclasses.replace(base, connector=connector, profile_version=f"{connector}-v1", **overrides)

    report = ConnectorCustodyReport(
        state="available",
        reason="",
        observation_window_hours=24,
        instances=(
            status("claudecode", drop_only_reasons=("invalid_record",)),
            status("openclaw", drop_only_batches=0),
            status("openhands", custody="external"),
        ),
    )
    r = _DoctorResult()
    cfg = mock.Mock(spec=["policy_connectors"])
    cfg.policy_connectors.return_value = ["openclaw"]
    cmd_doctor._check_connector_export_custody(report, r, configured=cmd_doctor._otlp_configured_connectors(cfg))
    rows = {c["label"]: c for c in r.checks}
    assert set(rows) == {"Connector OTLP: openclaw", "Connector OTLP: not configured"}
    assert rows["Connector OTLP: openclaw"]["status"] == "pass"
    removed = rows["Connector OTLP: not configured"]
    assert removed["status"] == "skip" and "claudecode, openhands" in removed["detail"]
    assert not any("setup" in c.get("remediation", "") for c in r.checks)


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


def test_hook_binary_from_another_release_is_named() -> None:
    # GAP-1415: an older defenseclaw-hook.exe beside a newer gateway read as healthy hooks.
    import subprocess

    def ran(stdout: str, rc: int = 0) -> subprocess.CompletedProcess:
        return subprocess.CompletedProcess(["hook"], rc, stdout=stdout, stderr="")

    hook = r"C:\Users\u\.local\bin\defenseclaw-hook.exe"
    with mock.patch.object(cmd_doctor.subprocess, "run", return_value=ran('{"version":"1.0.0"}')):
        tag, detail, remediation = cmd_doctor._hook_binary_release_check(hook, "1.0.1")
    assert (tag, detail) == ("warn", f"{hook} is 1.0.0; this CLI is 1.0.1")
    assert "install.ps1" in remediation
    with mock.patch.object(cmd_doctor.subprocess, "run", return_value=ran('{"version":"1.0.1"}')):
        assert cmd_doctor._hook_binary_release_check(hook, "1.0.1")[0] == "pass"
    with mock.patch.object(cmd_doctor.subprocess, "run", return_value=ran("", rc=2)):
        assert cmd_doctor._hook_binary_release_check(hook, "1.0.1")[:2] == ("warn", f"{hook} did not report its release")


def test_windows_hermes_idle_is_healthy_not_pending_reload() -> None:
    # GAP-1298: with no Hermes process for the account there is nothing to reload.
    from defenseclaw.doctor_hooks import WindowsHookCheck

    listing = '"pwsh.exe","4100","RDP-Tcp#0","2","90,000 K"\n"defenseclaw-gateway.exe","4200","RDP-Tcp#0","2","40,000 K"\n'
    assert cmd_doctor._hermes_host_running_windows(listing) is False
    assert cmd_doctor._hermes_host_running_windows(listing + '"hermes.exe","4300","RDP-Tcp#0","2","9 K"\n') is True
    # An interpreter is judged by its command line (GAP-1605); unreadable is unknown.
    with mock.patch.object(cmd_doctor, "_windows_process_command_lines", return_value=None):
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
    # GAP-2190: an unknown listing (slow host right after an upgrade) is retried once.
    with mock.patch.object(cmd_doctor, "_hermes_host_running", side_effect=[None, False]):
        assert cmd_doctor._hermes_idle_native_check(pending, _DoctorResult()).healthy


def test_slow_codex_policy_probe_is_retried_then_a_warning(tmp_path) -> None:
    # GAP-2190: a Codex app-server that does not answer in time is slow, not policy-blocked.
    from defenseclaw import doctor_hooks
    from defenseclaw.doctor_hooks import CODEX_PROBE_TIMEOUT_STATE, WindowsHookCheck, _InspectionError

    config = str(tmp_path / "config.toml")
    slow = _InspectionError(CODEX_PROBE_TIMEOUT_STATE, "timed out waiting for Codex policy response 1")
    with mock.patch.object(doctor_hooks, "_codex_effective_policy_inspector", side_effect=[slow, (False, "src")]) as m:
        doctor_hooks._validate_codex_effective_hook_policy(str(tmp_path), config)
    assert m.call_count == 2
    with mock.patch.object(doctor_hooks, "_codex_effective_policy_inspector", side_effect=[slow, slow]):
        try:
            doctor_hooks._validate_codex_effective_hook_policy(str(tmp_path), config)
        except _InspectionError as exc:
            assert exc.state == CODEX_PROBE_TIMEOUT_STATE
        else:
            raise AssertionError("a second timeout must still be reported")

    r = _DoctorResult()
    check = WindowsHookCheck(CODEX_PROBE_TIMEOUT_STATE, "Codex app-server did not answer the policy probe")
    with mock.patch.object(cmd_doctor, "_windows_native_hook_check", return_value=check):
        _render(lambda: cmd_doctor._check_windows_native_hooks(mock.MagicMock(), "codex", "Codex hooks", r))
    assert (r.passed, r.warned, r.failed) == (0, 1, 0), r.checks
    assert "rerun defenseclaw doctor" in r.checks[0]["remediation"]


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


def test_omnigent_without_a_server_record_reads_plainly(tmp_path, monkeypatch) -> None:
    # GAP-1067: no internal path hash as the main text.
    monkeypatch.setenv("OMNIGENT_DATA_DIR", str(tmp_path))
    pid, detail = cmd_doctor._omnigent_local_server_pid()
    assert pid == 0 and detail == "OmniGent server has not started yet (no server record)"


def test_windows_hermes_check_reads_python_command_lines() -> None:
    # GAP-1605: DefenseClaw's own TUI is a python.exe; only a Hermes command line is a host.
    listing = '"pwsh.exe","4100"\n"python.exe","4400"\n"uv.exe","4500"\n'
    tui = {"4400": r'"C:\u\python.exe" "C:\u\Scripts\defenseclaw.exe" tui', "4500": "uv.exe tool run x"}
    argv = lambda line: tuple(part.strip('"') for part in line.split()) if line else None  # noqa: E731
    with (
        mock.patch.object(cmd_doctor, "_windows_process_command_lines", return_value=tui),
        mock.patch.object(cmd_doctor, "_windows_command_line_argv", side_effect=argv),
    ):
        assert cmd_doctor._hermes_host_running_windows(listing) is False
    host = dict(tui, **{"4400": r'"C:\u\python.exe" "C:\u\Scripts\hermes.exe" chat'})
    with (
        mock.patch.object(cmd_doctor, "_windows_process_command_lines", return_value=host),
        mock.patch.object(cmd_doctor, "_windows_command_line_argv", side_effect=argv),
    ):
        assert cmd_doctor._hermes_host_running_windows(listing) is True
    for lines in ({"4400": "", "4500": "uv.exe x"}, None):  # unreadable command line, no listing
        with (
            mock.patch.object(cmd_doctor, "_windows_process_command_lines", return_value=lines),
            mock.patch.object(cmd_doctor, "_windows_command_line_argv", side_effect=argv),
        ):
            assert cmd_doctor._hermes_host_running_windows(listing) is None


def test_windows_command_lines_prefer_the_native_reader() -> None:
    # GAP-1605: WMI answers "Access denied" for a standard user over SSH; the
    # native reader does not, so WMI runs only for what it could not read.
    native = ({"4400": "python.exe -m defenseclaw.main tui"}, {"4600"}, {"4700"})
    with (
        mock.patch.object(cmd_doctor, "_windows_native_command_lines", return_value=native),
        mock.patch.object(cmd_doctor, "_windows_cim_command_lines", return_value=None) as cim,
        mock.patch("shutil.which", return_value="pwsh"),
    ):
        assert cmd_doctor._windows_process_command_lines(["4400", "4600", "4700"]) == {
            "4400": "python.exe -m defenseclaw.main tui",
            "4600": None,
        }
        cim.assert_not_called()
        lines = cmd_doctor._windows_process_command_lines(["4400", "4800"])
        assert lines == {"4400": "python.exe -m defenseclaw.main tui", "4600": None, "4800": ""}


def test_windows_hermes_check_skips_other_accounts_in_an_all_accounts_listing() -> None:
    # Get-Process without -IncludeUserName lists every account: a process this
    # account may not open is another account's, not a Hermes host of ours.
    listing = '"python.exe","4400"\n"hermes.exe","4500"\n'
    denied = {"4400": None, "4500": None}
    with mock.patch.object(cmd_doctor, "_windows_process_command_lines", return_value=denied):
        assert cmd_doctor._hermes_host_running_windows("#all-accounts\n" + listing) is False
        assert cmd_doctor._hermes_host_running_windows(listing) is True
    with mock.patch.object(cmd_doctor, "_windows_process_command_lines", return_value={"4400": None}):
        assert cmd_doctor._hermes_host_running_windows('"python.exe","4400"\n') is None
    with mock.patch.object(cmd_doctor, "_windows_process_command_lines", return_value={"4400": None, "4500": ""}):
        assert cmd_doctor._hermes_host_running_windows("#all-accounts\n" + listing) is True


def test_windows_hermes_check_falls_back_to_get_process(monkeypatch) -> None:
    # GAP-1298: tasklist prints "ERROR: Access denied" for a standard user over SSH.
    import subprocess

    monkeypatch.setenv("USERNAME", "dcw-fc3")
    denied = subprocess.CompletedProcess(["tasklist"], 1, stdout="", stderr="ERROR: Access denied")
    with (
        mock.patch.object(cmd_doctor.subprocess, "run", return_value=denied),
        mock.patch.object(cmd_doctor, "_windows_process_listing_powershell", return_value='"pwsh","4100"\n'),
    ):
        assert cmd_doctor._hermes_host_running_windows() is False
    with (
        mock.patch.object(cmd_doctor.subprocess, "run", return_value=denied),
        mock.patch.object(cmd_doctor, "_windows_process_listing_powershell", return_value=None),
    ):
        assert cmd_doctor._hermes_host_running_windows() is None


def test_llm_ping_sends_the_bedrock_region_and_plain_errors() -> None:
    # GAP-1365: a Bedrock API key is bound to its region; GAP-1489: no LiteLLM banner or prefixes.
    import litellm
    from defenseclaw import llm as llm_mod
    from defenseclaw.config import BedrockKeyConfig, LLMConfig

    cfg = LLMConfig(
        provider="bedrock",
        model="us.anthropic.claude-haiku-4-5-20251001-v1:0",
        api_key="bedrock-api-key-x",
        bedrock=BedrockKeyConfig(region="us-east-1"),
    )
    err = RuntimeError(
        'litellm.BadRequestError: BedrockException - {"message":"The provided model identifier is invalid."}'
    )
    with mock.patch("litellm.completion", side_effect=err) as completion:
        ok, msg = llm_mod.ping(cfg)
    assert completion.call_args.kwargs["aws_region_name"] == "us-east-1"
    assert litellm.suppress_debug_info is True
    # GAP-1673: the provider and the problem in user terms, no internal class name.
    assert not ok and msg == "Bedrock rejected the request: The provided model identifier is invalid."


def test_unverified_version_hint_names_action_mode() -> None:
    # GAP-1372: plain `setup hermes` prompts with observe as the default.
    from types import SimpleNamespace

    from defenseclaw import doctor_health

    finding = doctor_health.ConnectorHealthFinding(
        connector="hermes",
        status=doctor_health.HealthStatus.UNTESTED,
        reason_code="connector-version-not-observed",
        summary="hermes is installed, but its version was not observed",
        remediations=doctor_health._untested_connector_remediations("hermes"),
    )
    report = SimpleNamespace(components=(), connectors=(finding,))
    r = _DoctorResult()
    with (
        mock.patch("defenseclaw.doctor_health.read_cached_discovery", return_value=None),
        mock.patch("defenseclaw.doctor_health.build_health_report", return_value=report),
        mock.patch.object(cmd_doctor, "_doctor_component_evidence", return_value=()),
        mock.patch.object(cmd_doctor, "_connector_enabled", return_value=True),
    ):
        cmd_doctor._check_component_connector_compatibility(SimpleNamespace(data_dir=""), ["hermes"], r)
    row = next(c for c in r.checks if c["label"] == "Connector compatibility: hermes")
    assert "'defenseclaw setup hermes --mode action'" in row["remediation"]


def test_agent_installed_after_discovery_names_the_refresh() -> None:
    # GAP-0052: Claude Code installed after init read as missing until a
    # refresh, and the next step said to install it.
    from types import SimpleNamespace

    from defenseclaw import doctor_health

    finding = doctor_health.ConnectorHealthFinding(
        connector="claudecode",
        status=doctor_health.HealthStatus.UNAVAILABLE,
        reason_code="connector-agent-unavailable",
        summary="claudecode is active but its agent installation is unavailable",
        remediations=doctor_health._unavailable_connector_remediations("claudecode"),
    )
    report = SimpleNamespace(components=(), connectors=(finding,))
    r = _DoctorResult()
    with (
        mock.patch("defenseclaw.doctor_health.read_cached_discovery", return_value=None),
        mock.patch("defenseclaw.doctor_health.build_health_report", return_value=report),
        mock.patch.object(cmd_doctor, "_doctor_component_evidence", return_value=()),
        mock.patch.object(cmd_doctor, "_connector_enabled", return_value=True),
        mock.patch("defenseclaw.inventory.agent_discovery.shutil.which", return_value="/opt/bin/claude"),
    ):
        cmd_doctor._check_component_connector_compatibility(SimpleNamespace(data_dir=""), ["claudecode"], r)
    row = next(c for c in r.checks if c["label"] == "Connector compatibility: claudecode")
    assert row["status"] == "warn"
    assert "is installed now, after the last agent discovery" in row["detail"]
    assert row["remediation"].startswith("defenseclaw agent discover --refresh")


def test_init_next_steps_drop_a_plain_setup_covered_by_mode_action() -> None:
    # GAP-1372: init printed "setup hermes --mode action" and then a plain "setup hermes".
    from types import SimpleNamespace

    from defenseclaw.bootstrap import _next_commands

    steps = [
        SimpleNamespace(next_command="defenseclaw setup hermes --mode action"),
        SimpleNamespace(next_command="defenseclaw setup hermes"),
    ]
    commands = _next_commands(steps, [], SimpleNamespace(data_dir=""), "observe")
    assert commands == ["defenseclaw setup hermes --mode action", "defenseclaw doctor"]


def test_stopped_gateway_is_one_failure_on_windows(tmp_path) -> None:
    # GAP-1389: rows that inspect the running gateway are skipped, not failed.
    from types import SimpleNamespace

    from defenseclaw.doctor_gateway import PIDRecord, WatchdogOwnershipEvidence

    r = _DoctorResult()
    r.gateway_down = "stopped"
    cfg = SimpleNamespace(data_dir=str(tmp_path), gateway=SimpleNamespace(watchdog=SimpleNamespace(enabled=True)))
    with mock.patch.object(cmd_doctor, "_configured_gateway_data_dir", return_value=str(tmp_path)):
        cmd_doctor._check_windows_gateway_diagnostics(cfg, r, evidence=object(), platform_name="win32")
    evidence = SimpleNamespace(
        watchdog_pid_record=lambda _p: PIDRecord("missing"),
        watchdog_ownership=lambda *_a: WatchdogOwnershipEvidence("unlocked", source="stable"),
    )
    cmd_doctor._check_windows_watchdog_diagnostics(cfg, r, evidence=evidence, platform_name="win32")
    assert r.failed == 0
    rows = {c["label"]: c for c in r.checks}
    assert rows["Gateway token drift"]["detail"] == cmd_doctor._NEEDS_RUNNING_GATEWAY
    assert rows["Watchdog runtime"]["status"] == "skip"
    assert "defenseclaw-gateway start" in rows["Watchdog runtime"]["detail"]


def test_fix_starts_the_gateway_before_the_watchdog() -> None:
    # GAP-1401: a watchdog started first recorded "down" and failed the run.
    from types import SimpleNamespace

    from defenseclaw.doctor_gateway import WatchdogStateEvidence

    ids = [spec.repair_id for spec in cmd_doctor._doctor_repair_specs()]
    assert ids.index("doctor.gateway.service.reconcile") < ids.index("doctor.gateway.watchdog.reconcile")

    r = _DoctorResult(mode="repair")
    r.repairs.append({"repair_id": "doctor.gateway.service.reconcile", "state": "applied"})
    state = WatchdogStateEvidence("ok", state="down")
    with mock.patch.object(cmd_doctor, "_inspect_windows_watchdog_runtime", return_value=("running", "ok", state)):
        cmd_doctor._check_windows_watchdog_diagnostics(
            SimpleNamespace(data_dir="", gateway=SimpleNamespace(watchdog=SimpleNamespace(enabled=True))),
            r,
            evidence=object(),
            platform_name="win32",
        )
    row = r.checks[-1]
    assert row["label"] == "Watchdog last-known state" and row["status"] == "warn"


def test_proxy_connector_without_a_guardrail_model_needs_no_llm_key(tmp_path, monkeypatch) -> None:
    # GAP-1453: OpenClaw passes the agent's own provider credentials through.
    from defenseclaw import credentials

    monkeypatch.delenv("DEFENSECLAW_LLM_KEY", raising=False)
    monkeypatch.delenv("DEFENSECLAW_LLM_MODEL", raising=False)
    cfg = _bedrock_judge_cfg(tmp_path, "api_key")
    cfg.guardrail.connector = "openclaw"
    cfg.claw.mode = "openclaw"
    cfg.guardrail.judge.enabled = False
    r = _DoctorResult()
    cmd_doctor._check_llm_api_key(cfg, r)
    assert r.checks[-1]["status"] == "skip" and "no guardrail LLM model" in r.checks[-1]["detail"]
    assert not credentials._any_llm_component_uses_default_key(cfg)


def test_text_rows_show_commands_in_quotes_not_backticks() -> None:
    # GAP-1526: text doctor printed markdown backticks literally.
    r = _DoctorResult()
    text = _render(
        lambda: cmd_doctor._emit(
            "fail", "Row", "run `defenseclaw doctor --fix`", r=r, remediation="then `defenseclaw-gateway start`"
        )
    )
    assert "run 'defenseclaw doctor --fix'" in text
    assert "Next step: then 'defenseclaw-gateway start'" in text
    assert "`" not in text
    assert r.checks[0]["detail"] == "run `defenseclaw doctor --fix`"


def test_stopped_gateway_row_carries_its_next_step(tmp_path) -> None:
    # GAP-1526: the Sidecar API FAIL row had an empty remediation in --json-output.
    from types import SimpleNamespace

    from defenseclaw.config import GatewayConfig

    cfg = SimpleNamespace(data_dir=str(tmp_path), gateway=GatewayConfig(api_bind="127.0.0.1", api_port=18_970))
    r = _DoctorResult()
    with mock.patch.object(cmd_doctor, "_http_probe", return_value=(0, "Connection refused")):
        text = _render(lambda: cmd_doctor._check_sidecar(cfg, r))
    row = r.checks[-1]
    assert row["status"] == "fail" and "defenseclaw-gateway start" in row["remediation"]
    assert "`" not in text and text.count("defenseclaw-gateway start") == 1


def test_drifted_exporter_warn_names_setup_in_remediation() -> None:
    # GAP-1526: the Connector OTLP drift WARN row had an empty remediation.
    report = _custody_report(managed_config_state="drifted", drop_only_batches=0, drop_only_signals=())
    # GAP-0076: the text row printed no Next step line (the remedy sat in the detail).
    r = _DoctorResult()
    text = _render(lambda: cmd_doctor._check_connector_export_custody(report, r))
    check = r.checks[-1]
    assert check["status"] == "warn"
    assert check["remediation"] == "run 'defenseclaw setup claude-code' to re-apply"
    assert "Next step: run 'defenseclaw setup claude-code' to re-apply" in text
    assert text.count("defenseclaw setup claude-code") == 1


def test_rows_that_name_a_command_in_their_detail_carry_it_as_remediation() -> None:
    # GAP-1526: Gateway authentication / Gateway token env / Hook contract rows
    # named their command only in the detail, so --json-output had no next step.
    r = _DoctorResult()
    text = _render(
        lambda: (
            cmd_doctor._emit(
                "fail",
                "Gateway authentication",
                "no gateway token is configured — run `defenseclaw doctor --fix` to generate and persist one",
                r=r,
            ),
            cmd_doctor._emit("pass", "Sidecar API", "127.0.0.1:18970 `x`", r=r),
            cmd_doctor._emit("warn", "Plain", "nothing to run", r=r),
        )
    )
    assert r.checks[0]["remediation"] == "run `defenseclaw doctor --fix` to generate and persist one"
    assert [c["remediation"] for c in r.checks[1:]] == ["", ""]
    assert text.count("defenseclaw doctor --fix") == 1 and "Next step" not in text


def test_port_held_by_another_account_row_carries_its_next_step(tmp_path) -> None:
    # GAP-1526: the foreign holder answers /health, and the FAIL row had no remediation.
    from types import SimpleNamespace

    from defenseclaw.config import GatewayConfig

    cfg = SimpleNamespace(data_dir=str(tmp_path), gateway=GatewayConfig(api_bind="127.0.0.1", api_port=19_020))
    trust = SimpleNamespace(trusted=False, detail="the gateway is not running (PID file is missing)")
    r = _DoctorResult()
    with (
        mock.patch.object(cmd_doctor, "_http_probe", return_value=(200, "{}")),
        mock.patch.object(cmd_doctor, "_trusted_gateway_listener", return_value=trust),
        mock.patch.object(cmd_doctor, "_gateway_port_holder", return_value="uid 1032 (dcr-other)"),
        mock.patch.object(cmd_doctor, "_free_api_port_hint", return_value=19_040),
    ):
        text = _render(lambda: cmd_doctor._check_sidecar(cfg, r))
    row = r.checks[-1]
    assert row["status"] == "fail" and r.gateway_down == "foreign"
    assert "--api-port 19040" in row["remediation"] and "defenseclaw-gateway start" in row["remediation"]
    assert text.count("defenseclaw setup gateway") == 1 and "`" not in text


def test_pre_first_start_token_and_codex_hook_rows_are_pending(tmp_path) -> None:
    # GAP-1975: right after `init --no-start-gateway` the token and the Codex
    # hook script do not exist yet; both appear on the first gateway start.
    from types import SimpleNamespace

    cfg = SimpleNamespace(data_dir=str(tmp_path), gateway=SimpleNamespace(token_env=""))
    r = _DoctorResult()
    r.gateway_down = "stopped"
    with (
        mock.patch.object(cmd_doctor, "_daemon_effective_gateway_token", return_value=("", "", "")),
        mock.patch.object(cmd_doctor, "_custom_gateway_token_env", return_value=""),
    ):
        text = _render(
            lambda: (
                cmd_doctor._check_gateway_auth(cfg, r),
                cmd_doctor._check_codex_hooks(cfg, r, platform_name="linux"),
            )
        )
    assert [c["status"] for c in r.checks] == ["skip", "skip"]
    assert text.count("'defenseclaw-gateway start'") == 2
    assert "doctor --fix" not in text

    running = _DoctorResult()
    cmd_doctor._check_codex_hooks(cfg, running, platform_name="linux")
    assert running.checks[-1]["status"] == "fail"
    assert running.checks[-1]["remediation"] == "re-register the hooks: defenseclaw setup codex --yes"


def test_unattributed_otlp_credentials_name_window_and_age() -> None:
    # GAP-2294: the count covers a rolling window; old attempts clear on
    # their own, so setup is only suggested while attempts are recent.
    from datetime import datetime, timezone

    now = datetime(2026, 10, 3, 6, 22, tzinfo=timezone.utc)

    def row(last: str) -> dict:
        report = ConnectorCustodyReport(
            state="available",
            reason="",
            observation_window_hours=24,
            unattributed_authentication_failures=9,
            last_unattributed_authentication_failure=last,
        )
        r = _DoctorResult()
        cmd_doctor._emit_unattributed_otlp_credentials(report, r, now=now)
        (check,) = r.checks
        assert check["label"] == "Native OTLP credentials" and check["status"] == "warn"
        return check

    old = row("2026-10-02T06:44:41Z")
    assert "9 rejected OTLP attempts in the last 24 h, last 23 h ago" in old["detail"]
    assert "clears on its own at 2026-10-03T06:44:41Z" in old["remediation"]
    assert "defenseclaw setup" not in old["remediation"]

    recent = row("2026-10-03T06:10:00Z")
    assert "last 12 min ago" in recent["detail"]
    assert "defenseclaw setup <connector>" in recent["remediation"]

    # GAP-2335: a few seconds old reads naturally, not "last 0 min ago".
    fresh = row("2026-10-03T06:21:55Z")
    assert "last under a minute ago" in fresh["detail"]
    assert "0 min" not in fresh["detail"]
