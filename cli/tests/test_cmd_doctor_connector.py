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

"""S6.5 — per-connector doctor checks.

These tests pin the new per-connector inventory and scan-coverage
sections that S6.5 added to ``defenseclaw doctor``. The checks are
deliberately narrow: they exercise the helpers in isolation rather
than the whole 1000-line doctor flow, so we can lock the contract
without smoke-testing every probe.

Coverage:

* ``_active_connector`` resolves the connector name in the same
  shape ``cfg.active_connector()`` exposes — including the
  legacy-config fallback when the method isn't present.
* ``_check_connector_inventory`` emits PASS for known connectors,
  WARN for unknown connectors, and surfaces the per-connector
  skill / plugin / MCP path lists.
* ``_check_scan_coverage`` mirrors the bullet list from
  ``_scan_ui.categories_for`` so the doctor and the scanner
  preambles agree on what each scanner checks.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw import doctor_gateway
from defenseclaw.commands.cmd_doctor import (
    _CURSOR_NATIVE_HOOK_TIMEOUT_SECONDS,
    _CURSOR_WINDOWS_RUNTIME_PROBE_ATTEMPTS,
    _CURSOR_WINDOWS_RUNTIME_PROBE_TIMEOUT_SECONDS,
    _CURSOR_WINDOWS_RUNTIME_TREE_REAP_SECONDS,
    _active_connector,
    _check_amp_native_policy_surfaces,
    _check_codex_hooks,
    _check_codex_otel_alignment,
    _check_connector_hooks,
    _check_connector_inventory,
    _check_cursor_configured_runtime,
    _check_hook_contract_lock,
    _check_hook_health,
    _check_omnigent_policy_health,
    _check_plugin_registry_required,
    _check_scan_coverage,
    _check_windsurf_hooks,
    _connector_enabled,
    _doctor_active_connectors,
    _doctor_label_suffix,
    _DoctorResult,
    _fix_plugin_registry_required,
    _hook_health_paths_from_lock,
    _omnigent_custody_read,
    _omnigent_live_config_evidence,
    _omnigent_local_server_pid,
    _omnigent_managed_artifact_drift,
    _omnigent_runtime_readiness,
    _omnigent_setup_repair_command,
    _opencode_load_heartbeat_status,
    _plugin_registry_required_offenders,
    _probe_cursor_windows_runtime,
    _run_cursor_windows_runtime_process,
    _windows_native_hook_check,
)
from defenseclaw.doctor_hooks import WindowsHookCheck
from defenseclaw.file_permissions import (
    UNSAFE_PATH_CHANGED,
    UNSAFE_PATH_SYMLINK_OR_REPARSE,
    UnsafePathError,
)


class TestCodexOtelAlignment(unittest.TestCase):
    def _cfg(self, environment: str = "windows") -> MagicMock:
        cfg = MagicMock()
        cfg.environment = environment
        cfg.gateway.api_port = 18970
        cfg.gateway.resolved_token.return_value = "test-gateway-token"
        return cfg

    def _write_codex_config(self, home: str, body: str) -> None:
        Path(home, "config.toml").write_text(body, encoding="utf-8")

    def test_configured_and_live_environment_agree(self) -> None:
        payload = {
            "runtime": {"environment": "windows"},
            "health": {"telemetry": {"state": "running"}},
        }
        with tempfile.TemporaryDirectory() as home, patch.dict(
            os.environ,
            {"CODEX_HOME": home},
            clear=False,
        ), patch(
            "defenseclaw.commands.cmd_doctor._http_probe",
            return_value=(200, json.dumps(payload)),
        ):
            self._write_codex_config(home, '[otel]\nenvironment = "windows"\n')
            result = _DoctorResult()
            _check_codex_otel_alignment(self._cfg(), result)

        self.assertEqual([check["status"] for check in result.checks], ["pass", "pass"])
        self.assertIn("'windows'", result.checks[0]["detail"])
        self.assertIn("running", result.checks[1]["detail"])

    def test_missing_codex_environment_exposes_dev_default(self) -> None:
        payload = {
            "runtime": {"environment": "windows"},
            "health": {"telemetry": {"state": "running"}},
        }
        with tempfile.TemporaryDirectory() as home, patch.dict(
            os.environ,
            {"CODEX_HOME": home},
            clear=False,
        ), patch(
            "defenseclaw.commands.cmd_doctor._http_probe",
            return_value=(200, json.dumps(payload)),
        ):
            self._write_codex_config(home, "[otel]\nlog_user_prompt = true\n")
            result = _DoctorResult()
            _check_codex_otel_alignment(self._cfg(), result)

        self.assertEqual(result.checks[0]["status"], "fail")
        self.assertIn("Codex would use 'dev'", result.checks[0]["detail"])
        self.assertEqual(result.checks[1]["status"], "pass")

    def test_stale_runtime_environment_fails_authenticated_status(self) -> None:
        payload = {
            "runtime": {"environment": "dev"},
            "health": {"telemetry": {"state": "running"}},
        }
        with tempfile.TemporaryDirectory() as home, patch.dict(
            os.environ,
            {"CODEX_HOME": home},
            clear=False,
        ), patch(
            "defenseclaw.commands.cmd_doctor._http_probe",
            return_value=(200, json.dumps(payload)),
        ):
            self._write_codex_config(home, '[otel]\nenvironment = "windows"\n')
            result = _DoctorResult()
            _check_codex_otel_alignment(self._cfg(), result)

        self.assertEqual(result.checks[0]["status"], "pass")
        self.assertEqual(result.checks[1]["status"], "fail")
        self.assertIn("live runtime reports 'dev'", result.checks[1]["detail"])

    def test_stopped_runtime_telemetry_fails_even_when_environment_matches(self) -> None:
        payload = {
            "runtime": {"environment": "windows"},
            "health": {"telemetry": {"state": "stopped"}},
        }
        with tempfile.TemporaryDirectory() as home, patch.dict(
            os.environ,
            {"CODEX_HOME": home},
            clear=False,
        ), patch(
            "defenseclaw.commands.cmd_doctor._http_probe",
            return_value=(200, json.dumps(payload)),
        ):
            self._write_codex_config(home, '[otel]\nenvironment = "windows"\n')
            result = _DoctorResult()
            _check_codex_otel_alignment(self._cfg(), result)

        self.assertEqual(result.checks[0]["status"], "pass")
        self.assertEqual(result.checks[1]["status"], "fail")
        self.assertIn("telemetry state is 'stopped'", result.checks[1]["detail"])


from defenseclaw.rulepack_validation import (
    RulePackValidationBridgeError,
    RulePackValidationIssue,
    RulePackValidationResult,
    safe_display_path,
)


class TestActiveConnectorResolver(unittest.TestCase):
    """``_active_connector`` is the single source of truth used by every
    per-connector doctor branch (inventory, fix_gateway_token,
    fix_pristine_backup). A regression here cascades through all of
    them, so the helper has its own tests.
    """

    def test_active_connector_uses_method_when_available(self) -> None:
        cfg = MagicMock()
        cfg.active_connector.return_value = "Codex"
        self.assertEqual(_active_connector(cfg), "codex")

    def test_active_connector_falls_back_to_guardrail_field(self) -> None:
        cfg = MagicMock(spec=["guardrail"])  # no active_connector method
        cfg.guardrail = MagicMock()
        cfg.guardrail.connector = "claudecode"
        self.assertEqual(_active_connector(cfg), "claudecode")

    def test_active_connector_defaults_to_openclaw_when_unset(self) -> None:
        cfg = MagicMock(spec=["guardrail"])
        cfg.guardrail = MagicMock()
        cfg.guardrail.connector = ""
        self.assertEqual(_active_connector(cfg), "openclaw")

    def test_active_connector_lowercases_method_result(self) -> None:
        """ZeptoClaw, OpenClaw, etc. — display casing varies, but the
        downstream connector switches all use lowercase.
        """
        cfg = MagicMock()
        cfg.active_connector.return_value = "ZeptoClaw"
        self.assertEqual(_active_connector(cfg), "zeptoclaw")

    def test_active_connector_swallows_method_exception(self) -> None:
        """A broken ``active_connector()`` must not abort the doctor —
        fall back to the legacy field.
        """
        cfg = MagicMock()
        cfg.active_connector.side_effect = RuntimeError("bad config")
        cfg.guardrail = MagicMock()
        cfg.guardrail.connector = "openclaw"
        self.assertEqual(_active_connector(cfg), "openclaw")


class TestCheckConnectorInventory(unittest.TestCase):
    """The new "── Connector ──" section surfaces the active connector
    plus the directories it points at."""

    def _cfg(self, *, skill_dirs: list[str], plugin_dirs: list[str], servers: list) -> MagicMock:
        cfg = MagicMock()
        cfg.skill_dirs.return_value = skill_dirs
        cfg.plugin_dirs.return_value = plugin_dirs
        cfg.mcp_servers.return_value = servers
        # Inventory now also surfaces effective mode + rule pack — keep
        # these returning plain strings so the isolated helper test doesn't
        # trip over MagicMock auto-attributes in os.path.isdir.
        cfg.guardrail.effective_mode.return_value = "observe"
        cfg.guardrail.effective_hook_fail_mode.return_value = "closed"
        cfg.guardrail.effective_rule_pack_dir.return_value = ""
        cfg.data_dir = ""
        return cfg

    def test_known_connector_passes(self) -> None:
        cfg = self._cfg(skill_dirs=[], plugin_dirs=[], servers=[])
        r = _DoctorResult()
        _check_connector_inventory(cfg, "openclaw", r)
        # First check is the connector label itself — rendered identically
        # whether one or many connectors are active.
        first = r.checks[0]
        self.assertEqual(first["status"], "pass")
        self.assertEqual(first["label"], "Connector")
        self.assertEqual(first["detail"], "OpenClaw")

    def test_unknown_connector_warns(self) -> None:
        cfg = self._cfg(skill_dirs=[], plugin_dirs=[], servers=[])
        r = _DoctorResult()
        _check_connector_inventory(cfg, "totallymadeupclaw", r)
        first = r.checks[0]
        self.assertEqual(first["status"], "warn")
        self.assertEqual(first["label"], "Connector")
        self.assertIn("unknown connector", first["detail"])

    def test_skill_paths_pass_when_directory_exists(self) -> None:
        # Use the cwd as a guaranteed-real directory.
        cfg = self._cfg(
            skill_dirs=[os.getcwd()],
            plugin_dirs=[],
            servers=[],
        )
        r = _DoctorResult()
        _check_connector_inventory(cfg, "openclaw", r)
        skill_check = next(c for c in r.checks if c["label"] == "Skill paths")
        self.assertEqual(skill_check["status"], "pass")
        self.assertIn("1/1 present", skill_check["detail"])

    def test_skill_paths_warn_when_no_directory_exists(self) -> None:
        cfg = self._cfg(
            skill_dirs=["/nonexistent/path/for/test"],
            plugin_dirs=[],
            servers=[],
        )
        r = _DoctorResult()
        _check_connector_inventory(cfg, "codex", r)
        skill_check = next(c for c in r.checks if c["label"] == "Skill paths")
        self.assertEqual(skill_check["status"], "warn")
        self.assertIn("0/1 present", skill_check["detail"])

    def test_skill_paths_skip_when_empty_list(self) -> None:
        cfg = self._cfg(skill_dirs=[], plugin_dirs=[], servers=[])
        r = _DoctorResult()
        _check_connector_inventory(cfg, "claudecode", r)
        skill_check = next(c for c in r.checks if c["label"] == "Skill paths")
        self.assertEqual(skill_check["status"], "skip")

    def test_mcp_server_summary_truncates_after_five(self) -> None:
        servers = [MagicMock(name=f"srv-{i}") for i in range(7)]
        for i, s in enumerate(servers):
            s.name = f"srv-{i}"
        cfg = self._cfg(skill_dirs=[], plugin_dirs=[], servers=servers)
        r = _DoctorResult()
        _check_connector_inventory(cfg, "openclaw", r)
        mcp_check = next(c for c in r.checks if c["label"] == "MCP servers")
        self.assertEqual(mcp_check["status"], "pass")
        self.assertIn("7 configured", mcp_check["detail"])
        self.assertIn("(+2 more)", mcp_check["detail"])

    def test_windsurf_missing_optional_mcp_is_not_hook_failure(self) -> None:
        cfg = self._cfg(skill_dirs=[], plugin_dirs=[], servers=[])
        r = _DoctorResult()

        _check_connector_inventory(cfg, "windsurf", r)

        mcp_check = next(c for c in r.checks if c["label"] == "MCP servers")
        self.assertEqual(mcp_check["status"], "skip")
        self.assertIn("optional legacy Cascade mcp_config.json", mcp_check["detail"])
        self.assertIn("does not own or repair hook activation", mcp_check["detail"])

    def test_paths_swallow_exception_as_warn(self) -> None:
        cfg = MagicMock()
        cfg.skill_dirs.side_effect = RuntimeError("kaboom")
        cfg.plugin_dirs.return_value = []
        cfg.mcp_servers.return_value = []
        cfg.guardrail.effective_mode.return_value = "observe"
        cfg.guardrail.effective_rule_pack_dir.return_value = ""

        r = _DoctorResult()
        _check_connector_inventory(cfg, "openclaw", r)

        skill_check = next(c for c in r.checks if c["label"] == "Skill paths")
        self.assertEqual(skill_check["status"], "warn")
        self.assertIn("kaboom", skill_check["detail"])


class TestConnectorInventoryUniformLabel(unittest.TestCase):
    """Every active connector's inventory block renders identically — there
    is no separate single- vs multi-connector layout. The header is always
    "Connector" and the caller tags each block with a "[<connector>]" suffix
    via ``_doctor_label_suffix`` so the blocks stay attributable.
    """

    def _cfg(self) -> MagicMock:
        cfg = MagicMock()
        cfg.skill_dirs.return_value = []
        cfg.plugin_dirs.return_value = []
        cfg.mcp_servers.return_value = []
        cfg.guardrail.effective_mode.return_value = "observe"
        cfg.guardrail.effective_hook_fail_mode.return_value = "closed"
        cfg.guardrail.effective_rule_pack_dir.return_value = ""
        cfg.data_dir = ""
        return cfg

    def test_header_label_is_always_connector(self) -> None:
        r = _DoctorResult()
        _check_connector_inventory(self._cfg(), "codex", r)
        self.assertEqual(r.checks[0]["label"], "Connector")

    def test_label_suffix_tags_rows(self) -> None:
        r = _DoctorResult()
        with _doctor_label_suffix("[codex]"):
            _check_connector_inventory(self._cfg(), "codex", r)
        self.assertTrue(r.checks[0]["label"].endswith("[codex]"))
        self.assertEqual(r.checks[0]["label"], "Connector [codex]")

    def test_inventory_emits_mode_and_rule_pack(self) -> None:
        cfg = self._cfg()
        cfg.guardrail.effective_mode.return_value = "action"
        r = _DoctorResult()
        _check_connector_inventory(cfg, "codex", r)
        labels = {c["label"]: c for c in r.checks}
        self.assertIn("Mode", labels)
        self.assertEqual(
            labels["Mode"]["detail"],
            "action; fail-mode=closed; provenance=config",
        )
        self.assertIn("Rule pack", labels)

    @patch(
        "defenseclaw.fail_mode.connector_fail_mode_report",
        return_value={"effective": "open", "provenance": "process-env"},
    )
    def test_inventory_mode_row_reports_runtime_provenance_without_new_statistic(self, _report) -> None:
        cfg = self._cfg()
        cfg.guardrail.effective_mode.return_value = "action"
        r = _DoctorResult()

        _check_connector_inventory(cfg, "codex", r)

        mode_rows = [c for c in r.checks if c["label"] == "Mode"]
        self.assertEqual(len(mode_rows), 1)
        self.assertEqual(
            mode_rows[0]["detail"],
            "action; fail-mode=open; provenance=process-env",
        )
        self.assertFalse(any(c["label"] == "Fail mode" for c in r.checks))


class TestCheckConnectorHooks(unittest.TestCase):
    """``_check_connector_hooks`` dispatches the Services hook/health check
    matching the connector, and combines with ``_doctor_label_suffix`` to
    attribute each connector's row on multi-connector installs.
    """

    def test_codex_emits_codex_hooks_row(self) -> None:
        cfg = MagicMock()
        cfg.data_dir = "/nonexistent/data/dir"
        r = _DoctorResult()
        _check_connector_hooks(cfg, "codex", r)
        self.assertTrue(r.checks)
        self.assertEqual(r.checks[-1]["label"], "Codex hooks")

    def test_codex_row_tagged_with_suffix(self) -> None:
        cfg = MagicMock()
        cfg.data_dir = "/nonexistent/data/dir"
        r = _DoctorResult()
        with _doctor_label_suffix("[codex]"):
            _check_connector_hooks(cfg, "codex", r)
        self.assertEqual(r.checks[-1]["label"], "Codex hooks [codex]")

    def _cursor_runtime_case(self, tmp: str, *, mode: str, fail_closed: bool, legacy_native: bool = False):
        runtime_dir = os.path.join(tmp, "DefenseClaw Hooks")
        os.makedirs(runtime_dir, exist_ok=True)
        if legacy_native:
            runtime = os.path.join(runtime_dir, "defenseclaw-hook.exe")
            with open(runtime, "wb") as fh:
                fh.write(b"MZ")
            command = f'"{runtime}" hook --connector cursor'
        else:
            runtime = os.path.join(runtime_dir, "cursor-hook.ps1")
            with open(runtime, "w", encoding="utf-8") as fh:
                fh.write(
                    "# defenseclaw-managed-hook v8\n"
                    f"$failClosed = ${str(fail_closed).lower()}\n"
                    "$startInfo = New-Object System.Diagnostics.ProcessStartInfo\n"
                    "$startInfo.RedirectStandardOutput = $true\n"
                    "$process.WaitForExit()\n"
                    "# defenseclaw-hook.exe hook --connector cursor --input-file $payloadPath\n"
                )
            command = "& '" + runtime.replace("'", "''") + "'"
        hooks_path = os.path.join(tmp, "hooks.json")
        with open(hooks_path, "w", encoding="utf-8") as fh:
            events = (
                "sessionStart",
                "sessionEnd",
                "preToolUse",
                "postToolUse",
                "postToolUseFailure",
                "subagentStart",
                "subagentStop",
                "beforeShellExecution",
                "beforeMCPExecution",
                "afterShellExecution",
                "afterMCPExecution",
                "beforeReadFile",
                "beforeTabFileRead",
                "afterFileEdit",
                "afterTabFileEdit",
                "beforeSubmitPrompt",
                "afterAgentResponse",
                "afterAgentThought",
                "stop",
                "preCompact",
                "workspaceOpen",
            )
            json.dump(
                {
                    "version": 1,
                    "hooks": {
                        event: [
                            {
                                "type": "command",
                                "command": command,
                                "timeout": 30,
                                "failClosed": fail_closed,
                            }
                        ]
                        for event in events
                    },
                },
                fh,
            )
        cfg = MagicMock()
        cfg.guardrail.effective_mode.return_value = mode
        cfg.guardrail.effective_hook_fail_mode.return_value = "closed" if fail_closed else "open"
        return cfg, hooks_path, runtime

    def _write_cursor_lock(self, tmp: str, hooks_path: str, runtime: str) -> None:
        with open(os.path.join(tmp, "hook_contract_lock.json"), "w", encoding="utf-8") as fh:
            json.dump(
                {
                    "connectors": {
                        "cursor": {
                            "locations": {
                                "hook_config_paths": [hooks_path],
                                "hook_script_paths": [runtime],
                            }
                        }
                    }
                },
                fh,
            )

    def _locked_cursor_case(self, tmp: str):
        cfg, hooks_path, runtime = self._cursor_runtime_case(
            tmp,
            mode="observe",
            fail_closed=False,
        )
        cfg.data_dir = tmp
        with open(hooks_path, encoding="utf-8") as fh:
            document = json.load(fh)
        return cfg, hooks_path, runtime, document

    def _run_locked_cursor_doctor(self, tmp: str, cfg, hooks_path: str, runtime: str, document):
        with open(hooks_path, "w", encoding="utf-8") as fh:
            json.dump(document, fh)
        self._write_cursor_lock(tmp, hooks_path, runtime)
        r = _DoctorResult()
        _check_cursor_configured_runtime(
            cfg,
            hooks_path,
            "Cursor hooks",
            r,
            platform_name="nt",
            probe_runtime=False,
        )
        with open(hooks_path, encoding="utf-8") as fh:
            after = json.load(fh)
        return r.checks[-1], after

    def test_cursor_doctor_validates_configured_windows_adapter(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cfg, hooks_path, runtime = self._cursor_runtime_case(
                tmp,
                mode="observe",
                fail_closed=False,
            )
            r = _DoctorResult()
            _check_cursor_configured_runtime(
                cfg,
                hooks_path,
                "Cursor hooks",
                r,
                platform_name="nt",
                probe_runtime=False,
            )

        self.assertEqual(r.checks[-1]["status"], "pass")
        self.assertIn(runtime, r.checks[-1]["detail"])
        self.assertIn("mode=observe", r.checks[-1]["detail"])
        self.assertIn("failClosed=false", r.checks[-1]["detail"])
        self.assertIn("enforcement=observe-only", r.checks[-1]["detail"])
        self.assertIn("higher-priority conflict detection=unavailable (none inferred)", r.checks[-1]["detail"])
        self.assertNotIn("inspect-tool.sh", r.checks[-1]["detail"])

    def test_cursor_doctor_ignores_high_cardinality_foreign_same_basename_entries(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cfg, hooks_path, runtime, document = self._locked_cursor_case(tmp)
            for event, entries in document["hooks"].items():
                foreign = [
                    {
                        "type": "command",
                        "command": "& '"
                        + os.path.join(tmp, "foreign", event, f"{index:02d}", "cursor-hook.ps1").replace(
                            "'", "''"
                        )
                        + "'",
                    }
                    for index in range(22)
                ]
                document["hooks"][event] = [*foreign, *entries]
            check, after = self._run_locked_cursor_doctor(tmp, cfg, hooks_path, runtime, document)

        self.assertEqual(check["status"], "pass")
        self.assertIn("entries=21", check["detail"])
        self.assertEqual(json.dumps(after, sort_keys=True), json.dumps(document, sort_keys=True))

    def test_cursor_doctor_still_rejects_duplicate_exact_locked_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cfg, hooks_path, runtime, document = self._locked_cursor_case(tmp)
            document["hooks"]["preToolUse"].append(dict(document["hooks"]["preToolUse"][0]))
            check, _after = self._run_locked_cursor_doctor(tmp, cfg, hooks_path, runtime, document)

        self.assertEqual(check["status"], "fail")
        self.assertIn("duplicated: preToolUse", check["detail"])

    def test_cursor_doctor_foreign_same_basename_cannot_replace_locked_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cfg, hooks_path, runtime, document = self._locked_cursor_case(tmp)
            foreign = os.path.join(tmp, "foreign", "cursor-hook.ps1")
            document["hooks"]["preToolUse"][0]["command"] = "& '" + foreign.replace("'", "''") + "'"
            check, _after = self._run_locked_cursor_doctor(tmp, cfg, hooks_path, runtime, document)

        self.assertEqual(check["status"], "fail")
        self.assertIn("incomplete: preToolUse", check["detail"])

    def test_cursor_doctor_preserves_tampered_command_as_foreign(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cfg, hooks_path, runtime, document = self._locked_cursor_case(tmp)
            tampered = dict(document["hooks"]["preToolUse"][0])
            tampered["command"] += " -OperatorChanged"
            document["hooks"]["preToolUse"].insert(0, tampered)
            check, after = self._run_locked_cursor_doctor(tmp, cfg, hooks_path, runtime, document)

        self.assertEqual(check["status"], "pass")
        self.assertIn("entries=21", check["detail"])
        self.assertEqual(after["hooks"]["preToolUse"][0], tampered)

    @patch("defenseclaw.commands.cmd_doctor._probe_cursor_windows_runtime")
    def test_cursor_doctor_is_passive_by_default(self, probe_mock) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cfg, hooks_path, _runtime = self._cursor_runtime_case(
                tmp,
                mode="observe",
                fail_closed=False,
            )
            r = _DoctorResult()
            _check_cursor_configured_runtime(
                cfg,
                hooks_path,
                "Cursor hooks",
                r,
                platform_name="nt",
            )

        probe_mock.assert_not_called()
        self.assertEqual(r.checks[-1]["status"], "pass")
        self.assertNotIn("live round trip", r.checks[-1]["detail"])

    def test_cursor_doctor_rejects_legacy_direct_windows_launcher(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cfg, hooks_path, _runtime = self._cursor_runtime_case(
                tmp,
                mode="observe",
                fail_closed=False,
                legacy_native=True,
            )
            r = _DoctorResult()
            _check_cursor_configured_runtime(
                cfg,
                hooks_path,
                "Cursor hooks",
                r,
                platform_name="nt",
                probe_runtime=False,
            )

        self.assertEqual(r.checks[-1]["status"], "fail")
        self.assertIn("PowerShell input adapter", r.checks[-1]["detail"])

    def test_cursor_doctor_rejects_fail_closed_observe_hook(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cfg, hooks_path, _runtime = self._cursor_runtime_case(
                tmp,
                mode="observe",
                fail_closed=True,
            )
            cfg.guardrail.effective_hook_fail_mode.return_value = "open"
            r = _DoctorResult()
            _check_cursor_configured_runtime(
                cfg,
                hooks_path,
                "Cursor hooks",
                r,
                platform_name="nt",
                probe_runtime=False,
            )

        self.assertEqual(r.checks[-1]["status"], "fail")
        self.assertIn("failClosed=false", r.checks[-1]["detail"])

    def test_cursor_doctor_accepts_fail_closed_action_hook(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cfg, hooks_path, _runtime = self._cursor_runtime_case(
                tmp,
                mode="action",
                fail_closed=True,
            )
            r = _DoctorResult()
            _check_cursor_configured_runtime(
                cfg,
                hooks_path,
                "Cursor hooks",
                r,
                platform_name="nt",
                probe_runtime=False,
            )

        self.assertEqual(r.checks[-1]["status"], "pass")
        self.assertIn("mode=action", r.checks[-1]["detail"])
        self.assertIn("failClosed=true", r.checks[-1]["detail"])
        self.assertIn("enforcement=user-hook native deny", r.checks[-1]["detail"])
        self.assertIn("human-approval=unsupported", r.checks[-1]["detail"])

    def test_cursor_doctor_rejects_millisecond_timeout(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cfg, hooks_path, _runtime = self._cursor_runtime_case(
                tmp,
                mode="observe",
                fail_closed=False,
            )
            with open(hooks_path, encoding="utf-8") as fh:
                hooks = json.load(fh)
            hooks["hooks"]["preToolUse"][0]["timeout"] = 30000
            with open(hooks_path, "w", encoding="utf-8") as fh:
                json.dump(hooks, fh)
            r = _DoctorResult()
            _check_cursor_configured_runtime(
                cfg,
                hooks_path,
                "Cursor hooks",
                r,
                platform_name="nt",
                probe_runtime=False,
            )

        self.assertEqual(r.checks[-1]["status"], "fail")
        self.assertIn("timeout=30 seconds", r.checks[-1]["detail"])

    @patch("defenseclaw.commands.cmd_doctor._http_probe")
    @patch(
        "defenseclaw.commands.cmd_doctor._windows_system_powershell",
        return_value=(
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            r"C:\Windows",
        ),
    )
    @patch("defenseclaw.commands.cmd_doctor._run_cursor_windows_runtime_process")
    def test_cursor_windows_runtime_probe_accepts_event_native_json_and_counter_advance(
        self,
        run_mock,
        _powershell_mock,
        http_probe_mock,
    ) -> None:
        before = json.dumps({"connectors": [{"name": "cursor", "requests": 4, "errors": 0}]})
        after = json.dumps(
            {
                "connectors": [
                    {
                        "name": "cursor",
                        "requests": 5,
                        "errors": 0,
                        "last_activity_at": "2026-07-01T22:46:47Z",
                    }
                ]
            }
        )
        http_probe_mock.side_effect = [(200, before), (200, after)]
        run_mock.return_value = subprocess.CompletedProcess(
            args=["powershell.exe"],
            returncode=0,
            stdout=b"{}",
            stderr=b"",
        )
        cfg = MagicMock()
        cfg.gateway.api_port = 18970

        ok, detail = _probe_cursor_windows_runtime(cfg, r"C:\DefenseClaw\cursor-hook.ps1")

        self.assertTrue(ok)
        self.assertIn("requests 4->5", detail)
        argv = run_mock.call_args.args[0]
        self.assertEqual(
            argv[:4],
            [
                r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-EncodedCommand",
            ],
        )
        self.assertEqual(run_mock.call_args.kwargs["env"]["SystemRoot"], r"C:\Windows")
        self.assertEqual(run_mock.call_args.kwargs["env"]["WINDIR"], r"C:\Windows")
        self.assertEqual(
            run_mock.call_args.kwargs["timeout"],
            _CURSOR_WINDOWS_RUNTIME_PROBE_TIMEOUT_SECONDS,
        )
        self.assertEqual(_CURSOR_NATIVE_HOOK_TIMEOUT_SECONDS, 30.0)
        self.assertEqual(_CURSOR_WINDOWS_RUNTIME_PROBE_TIMEOUT_SECONDS, 50.0)
        self.assertGreater(
            run_mock.call_args.kwargs["timeout"],
            _CURSOR_NATIVE_HOOK_TIMEOUT_SECONDS,
        )

    @patch("defenseclaw.commands.cmd_doctor._http_probe")
    @patch(
        "defenseclaw.commands.cmd_doctor._windows_system_powershell",
        return_value=(
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            r"C:\Windows",
        ),
    )
    @patch("defenseclaw.commands.cmd_doctor._run_cursor_windows_runtime_process")
    def test_cursor_windows_runtime_probe_retries_only_after_contained_timeout(
        self,
        run_mock,
        _powershell_mock,
        http_probe_mock,
    ) -> None:
        health = json.dumps({"connectors": [{"name": "cursor", "requests": 4, "errors": 0}]})
        after = json.dumps({"connectors": [{"name": "cursor", "requests": 5, "errors": 0}]})
        http_probe_mock.side_effect = [(200, health), (200, health), (200, after)]
        run_mock.side_effect = [
            subprocess.TimeoutExpired(
                cmd=["powershell.exe"],
                timeout=_CURSOR_WINDOWS_RUNTIME_PROBE_TIMEOUT_SECONDS,
            ),
            subprocess.CompletedProcess(
                args=["powershell.exe"],
                returncode=0,
                stdout=b"{}",
                stderr=b"",
            ),
        ]
        cfg = MagicMock()
        cfg.gateway.api_port = 18970

        ok, detail = _probe_cursor_windows_runtime(cfg, r"C:\DefenseClaw\cursor-hook.ps1")

        self.assertTrue(ok)
        self.assertIn("requests 4->5", detail)
        self.assertEqual(run_mock.call_count, 2)
        self.assertEqual(http_probe_mock.call_count, 3)
        self.assertEqual(
            run_mock.call_args.kwargs["timeout"],
            _CURSOR_WINDOWS_RUNTIME_PROBE_TIMEOUT_SECONDS,
        )

    @patch("defenseclaw.commands.cmd_doctor._http_probe")
    @patch(
        "defenseclaw.commands.cmd_doctor._windows_system_powershell",
        return_value=(
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            r"C:\Windows",
        ),
    )
    @patch("defenseclaw.commands.cmd_doctor._run_cursor_windows_runtime_process")
    def test_cursor_windows_runtime_probe_fails_after_strict_bounded_attempts(
        self,
        run_mock,
        _powershell_mock,
        http_probe_mock,
    ) -> None:
        health = json.dumps({"connectors": [{"name": "cursor", "requests": 4, "errors": 0}]})
        http_probe_mock.return_value = (200, health)
        run_mock.side_effect = subprocess.TimeoutExpired(
            cmd=["powershell.exe"],
            timeout=_CURSOR_WINDOWS_RUNTIME_PROBE_TIMEOUT_SECONDS,
        )
        cfg = MagicMock()
        cfg.gateway.api_port = 18970

        ok, detail = _probe_cursor_windows_runtime(cfg, r"C:\DefenseClaw\cursor-hook.ps1")

        self.assertFalse(ok)
        self.assertEqual(detail, "Cursor runtime probe timed out")
        self.assertEqual(run_mock.call_count, _CURSOR_WINDOWS_RUNTIME_PROBE_ATTEMPTS)
        self.assertEqual(http_probe_mock.call_count, _CURSOR_WINDOWS_RUNTIME_PROBE_ATTEMPTS)

    @patch("defenseclaw.commands.cmd_doctor._http_probe")
    @patch(
        "defenseclaw.commands.cmd_doctor._windows_system_powershell",
        return_value=(
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            r"C:\Windows",
        ),
    )
    @patch("defenseclaw.commands.cmd_doctor._run_cursor_windows_runtime_process")
    def test_cursor_windows_runtime_probe_never_retries_incomplete_tree_cleanup(
        self,
        run_mock,
        _powershell_mock,
        http_probe_mock,
    ) -> None:
        health = json.dumps({"connectors": [{"name": "cursor", "requests": 4, "errors": 0}]})
        http_probe_mock.return_value = (200, health)
        run_mock.side_effect = OSError("timed-out Cursor runtime probe tree did not terminate")
        cfg = MagicMock()
        cfg.gateway.api_port = 18970

        ok, detail = _probe_cursor_windows_runtime(cfg, r"C:\DefenseClaw\cursor-hook.ps1")

        self.assertFalse(ok)
        self.assertIn("tree did not terminate", detail)
        self.assertEqual(run_mock.call_count, 1)
        self.assertEqual(http_probe_mock.call_count, 1)

    @unittest.skipUnless(os.name == "nt", "Windows Job Object probe containment")
    @patch("defenseclaw.tui.windows_process.WindowsJob")
    @patch("defenseclaw.commands.cmd_doctor.subprocess.Popen")
    def test_cursor_windows_runtime_timeout_reaps_tree_before_returning(
        self,
        popen_mock,
        job_type_mock,
    ) -> None:
        process = popen_mock.return_value
        process.pid = 4242
        events = []
        communication_started = threading.Event()

        def wait(*, timeout):
            self.assertTrue(communication_started.wait(timeout=2))
            events.append(("wait", timeout))
            raise subprocess.TimeoutExpired(["powershell.exe"], timeout)

        def communicate():
            events.append(("communicate", None))
            communication_started.set()
            return b"", b""

        process.wait.side_effect = wait
        process.communicate.side_effect = communicate
        job = job_type_mock.return_value

        def terminate_sync(*, timeout):
            events.append(("terminate", timeout))
            return True

        job.terminate_sync.side_effect = terminate_sync

        with self.assertRaises(subprocess.TimeoutExpired):
            _run_cursor_windows_runtime_process(
                ["powershell.exe"],
                env={},
                timeout=_CURSOR_WINDOWS_RUNTIME_PROBE_TIMEOUT_SECONDS,
            )

        self.assertEqual(
            events,
            [
                ("communicate", None),
                ("wait", _CURSOR_WINDOWS_RUNTIME_PROBE_TIMEOUT_SECONDS),
                ("terminate", _CURSOR_WINDOWS_RUNTIME_TREE_REAP_SECONDS),
            ],
        )
        job_type_mock.assert_called_once_with(4242, allow_breakaway=False)
        job.close.assert_called_once_with()
        process.kill.assert_not_called()
        creationflags = popen_mock.call_args.kwargs["creationflags"]
        self.assertTrue(creationflags & getattr(subprocess, "CREATE_SUSPENDED", 0x00000004))

    @unittest.skipUnless(os.name == "nt", "Windows Job Object probe containment")
    @patch("defenseclaw.tui.windows_process.WindowsJob")
    @patch("defenseclaw.commands.cmd_doctor.subprocess.Popen")
    def test_cursor_windows_runtime_completed_root_reaps_pipe_holding_descendant(
        self,
        popen_mock,
        job_type_mock,
    ) -> None:
        process = popen_mock.return_value
        process.pid = 4242
        process.returncode = 0
        descendant_reaped = threading.Event()

        def communicate():
            if not descendant_reaped.wait(timeout=2):
                raise AssertionError("probe output was read before descendant cleanup")
            return b"{}", b""

        process.communicate.side_effect = communicate
        job = job_type_mock.return_value

        def terminate_sync(*, timeout):
            self.assertEqual(timeout, _CURSOR_WINDOWS_RUNTIME_TREE_REAP_SECONDS)
            descendant_reaped.set()
            return True

        job.terminate_sync.side_effect = terminate_sync

        result = _run_cursor_windows_runtime_process(
            ["powershell.exe"],
            env={},
            timeout=_CURSOR_WINDOWS_RUNTIME_PROBE_TIMEOUT_SECONDS,
        )

        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"{}")
        process.wait.assert_called_once_with(timeout=_CURSOR_WINDOWS_RUNTIME_PROBE_TIMEOUT_SECONDS)
        job.terminate_sync.assert_called_once_with(timeout=_CURSOR_WINDOWS_RUNTIME_TREE_REAP_SECONDS)
        job.close.assert_called_once_with()

    @patch("defenseclaw.commands.cmd_doctor._http_probe")
    @patch(
        "defenseclaw.commands.cmd_doctor._windows_system_powershell",
        return_value=(
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            r"C:\Windows",
        ),
    )
    @patch("defenseclaw.commands.cmd_doctor._run_cursor_windows_runtime_process")
    def test_cursor_windows_runtime_probe_rejects_generic_continue_output(
        self,
        run_mock,
        _powershell_mock,
        http_probe_mock,
    ) -> None:
        health = json.dumps(
            {"connectors": [{"name": "cursor", "requests": 4, "errors": 0}]}
        )
        http_probe_mock.return_value = (200, health)
        run_mock.return_value = subprocess.CompletedProcess(
            args=["powershell.exe"],
            returncode=0,
            stdout=b'{"continue":true}',
            stderr=b"",
        )
        cfg = MagicMock()
        cfg.gateway.api_port = 18970

        ok, detail = _probe_cursor_windows_runtime(cfg, r"C:\DefenseClaw\cursor-hook.ps1")

        self.assertFalse(ok)
        self.assertIn("invalid sessionStart fields: continue", detail)
        self.assertEqual(run_mock.call_count, 1)
        self.assertEqual(http_probe_mock.call_count, 1)

    @patch("defenseclaw.commands.cmd_doctor._http_probe")
    @patch(
        "defenseclaw.commands.cmd_doctor._windows_system_powershell",
        return_value=(
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            r"C:\Windows",
        ),
    )
    @patch("defenseclaw.commands.cmd_doctor._run_cursor_windows_runtime_process")
    def test_cursor_windows_runtime_probe_rejects_fail_open_without_delivery(
        self,
        run_mock,
        _powershell_mock,
        http_probe_mock,
    ) -> None:
        health = json.dumps({"connectors": [{"name": "cursor", "requests": 4, "errors": 0}]})
        http_probe_mock.side_effect = [(200, health), (200, health)]
        run_mock.return_value = subprocess.CompletedProcess(
            args=["powershell.exe"],
            returncode=0,
            stdout=b"{}",
            stderr=b"",
        )
        cfg = MagicMock()
        cfg.gateway.api_port = 18970

        ok, detail = _probe_cursor_windows_runtime(cfg, r"C:\DefenseClaw\cursor-hook.ps1")

        self.assertFalse(ok)
        self.assertIn("did not advance", detail)
        self.assertEqual(run_mock.call_count, 1)
        self.assertEqual(http_probe_mock.call_count, 2)

    def test_unknown_connector_is_noop(self) -> None:
        r = _DoctorResult()
        _check_connector_hooks(MagicMock(), "totallymadeupclaw", r)
        self.assertEqual(r.checks, [])


class TestCheckHookContractLock(unittest.TestCase):
    """Doctor surfaces the deterministic hook contract selected at setup."""

    def _cfg(self, data_dir: str) -> MagicMock:
        cfg = MagicMock()
        cfg.data_dir = data_dir
        return cfg

    def test_proxy_connector_skips(self) -> None:
        r = _DoctorResult()
        _check_hook_contract_lock(self._cfg("/tmp/unused"), "openclaw", r)
        check = r.checks[-1]
        self.assertEqual(check["status"], "skip")
        self.assertEqual(check["label"], "Hook contract")

    def test_active_windsurf_without_lock_fails_with_setup_owner(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            r = _DoctorResult()
            _check_hook_contract_lock(
                self._cfg(tmp),
                "windsurf",
                r,
                platform_name="linux",
            )

        check = r.checks[-1]
        self.assertEqual(check["status"], "fail")
        self.assertIn("no hook_contract_lock.json", check["detail"])
        self.assertIn("setup windsurf", check["detail"])

    def test_active_opencode_without_lock_fails_with_setup_owner(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            r = _DoctorResult()
            _check_hook_contract_lock(
                self._cfg(tmp),
                "opencode",
                r,
                platform_name="nt",
            )

        check = r.checks[-1]
        self.assertEqual(check["status"], "fail")
        self.assertIn("no hook_contract_lock.json", check["detail"])
        self.assertIn("setup opencode", check["detail"])

    def test_known_contract_passes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            runtime_path = os.path.join(tmp, "hooks", "inspect-tool.sh")
            with open(os.path.join(tmp, "hook_contract_lock.json"), "w", encoding="utf-8") as fh:
                json.dump(
                    {
                        "connectors": {
                            "codex": {
                                "contract_id": "codex-hooks-v1",
                                "compatibility_status": "known",
                                "raw_agent_version": "0.30.0",
                                "normalized_agent_version": "0.30.0",
                                "hook_script_version": "codex-hook.sh:1",
                                "locations": {
                                    "workspace_dir": "/tmp/repo",
                                    "hook_config_paths": ["/home/test/.codex/config.toml"],
                                    "hook_script_paths": [runtime_path],
                                },
                            }
                        }
                    },
                    fh,
                )
            for platform_name in ("linux", "darwin"):
                with self.subTest(platform_name=platform_name):
                    r = _DoctorResult()
                    _check_hook_contract_lock(
                        self._cfg(tmp),
                        "codex",
                        r,
                        platform_name=platform_name,
                    )
                    check = r.checks[-1]
                    self.assertEqual(check["status"], "pass")
                    self.assertIn("codex-hooks-v1", check["detail"])
                    self.assertIn("0.30.0", check["detail"])
                    self.assertIn("workspace=/tmp/repo", check["detail"])
                    self.assertIn("hook_path=/home/test/.codex/config.toml", check["detail"])
                    self.assertIn(f"runtime_path={runtime_path}", check["detail"])

    def test_posix_missing_runtime_help_is_unchanged(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cfg = self._cfg(tmp)
            for platform_name in ("linux", "darwin"):
                with self.subTest(platform_name=platform_name):
                    r = _DoctorResult()
                    _check_codex_hooks(cfg, r, platform_name=platform_name)
                    hook_script = os.path.join(tmp, "hooks", "codex-hook.sh")
                    self.assertEqual(
                        r.checks[-1]["detail"],
                        f"hook script not found at {hook_script}",
                    )

    def test_windows_contract_does_not_mislabel_portable_shell_assets(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            adapter = os.path.join(tmp, "hooks", "cursor-hook.ps1")
            with open(os.path.join(tmp, "hook_contract_lock.json"), "w", encoding="utf-8") as fh:
                json.dump(
                    {
                        "connectors": {
                            "cursor": {
                                "connector": "cursor",
                                "contract_id": "cursor-hooks-v1",
                                "compatibility_status": "known",
                                "hook_script_version": "v8",
                                "hook_fail_mode": "open",
                                "locations": {
                                    "hook_config_paths": [os.path.join(tmp, "hooks.json")],
                                    "hook_script_paths": [
                                        os.path.join(tmp, "hooks", "inspect-tool.sh"),
                                        os.path.join(tmp, "hooks", "cursor-hook.sh"),
                                        adapter,
                                    ],
                                },
                            }
                        }
                    },
                    fh,
                )

            r = _DoctorResult()
            _check_hook_contract_lock(
                self._cfg(tmp),
                "cursor",
                r,
                platform_name="nt",
            )
            detail = r.checks[-1]["detail"]
            self.assertEqual(r.checks[-1]["status"], "pass")
            self.assertIn(f"runtime_path={adapter}", detail)
            self.assertNotRegex(detail.lower(), r"inspect-tool\.sh|cursor-hook\.sh")

    def test_cursor_desktop_version_does_not_drift_agent_cli_contract(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "hook_contract_lock.json"), "w", encoding="utf-8") as fh:
                json.dump(
                    {
                        "connectors": {
                            "cursor": {
                                "connector": "cursor",
                                "contract_id": "cursor-hooks-v1",
                                "compatibility_status": "known",
                                "raw_agent_version": "2026.07.23-e383d2b",
                                "hook_script_version": "v8",
                                "hook_fail_mode": "open",
                            }
                        }
                    },
                    fh,
                )
            with open(os.path.join(tmp, "agent_discovery.json"), "w", encoding="utf-8") as fh:
                json.dump(
                    {
                        "agents": {
                            "cursor": {
                                "version": "3.14.7",
                                "binary_path": os.path.join(tmp, "Cursor.exe"),
                            }
                        }
                    },
                    fh,
                )

            r = _DoctorResult()
            _check_hook_contract_lock(self._cfg(tmp), "cursor", r, platform_name="linux")

            check = r.checks[-1]
            self.assertEqual(check["status"], "pass")
            self.assertIn("agent_cli=2026.07.23-e383d2b", check["detail"])
            self.assertIn("desktop=3.14.7 (separate; not Agent CLI contract evidence)", check["detail"])

    def test_discovered_version_drift_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "hook_contract_lock.json"), "w", encoding="utf-8") as fh:
                json.dump(
                    {
                        "connectors": {
                            "claudecode": {
                                "contract_id": "claudecode-hooks-v1",
                                "compatibility_status": "known",
                                "raw_agent_version": "1.2.3",
                            }
                        }
                    },
                    fh,
                )
            with open(os.path.join(tmp, "agent_discovery.json"), "w", encoding="utf-8") as fh:
                json.dump({"agents": {"claudecode": {"version": "1.2.4"}}}, fh)

            r = _DoctorResult()
            _check_hook_contract_lock(
                self._cfg(tmp),
                "claudecode",
                r,
                platform_name="linux",
            )
            check = r.checks[-1]
            self.assertEqual(check["status"], "fail")
            self.assertIn("drift", check["detail"])


class TestWindsurfDoctorContract(unittest.TestCase):
    def test_services_explicitly_reports_restricted_mode_and_noncertification(self) -> None:
        cfg = MagicMock()
        cfg.data_dir = tempfile.gettempdir()
        r = _DoctorResult()

        _check_windsurf_hooks(cfg, r, platform_name="linux")

        restricted = next(c for c in r.checks if c["label"] == "Cascade Restricted Mode")
        self.assertEqual(restricted["status"], "warn")
        self.assertIn("disables all Cascade hooks", restricted["detail"])
        self.assertIn("zero counters are not activation or certification", restricted["detail"])

    @patch("defenseclaw.commands.cmd_doctor.validate_windows_hook_registration")
    def test_lockless_windows_check_uses_bound_hooks_not_optional_mcp(
        self,
        validator,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bound = os.path.join(tmp, "windsurf-profile")
            expected = os.path.join(bound, ".codeium", "windsurf", "hooks.json")
            validator.return_value = WindowsHookCheck("healthy", "ok", "", "", "")
            cfg = MagicMock()
            cfg.data_dir = os.path.join(tmp, "data")
            with patch.dict(
                os.environ,
                {
                    "WINDSURF_USER_HOME": bound,
                    "WINDSURF_HOOK_CONFIG_PATH": expected,
                },
            ):
                _windows_native_hook_check(
                    cfg,
                    "windsurf",
                    install_root=os.path.join(tmp, "install"),
                    search_path="",
                    pathext=".EXE",
                )

        self.assertEqual(validator.call_args.kwargs["config_path"], expected)
        self.assertNotIn("mcp_config.json", validator.call_args.kwargs["config_path"])


class TestCheckScanCoverage(unittest.TestCase):
    """``_check_scan_coverage`` advertises what each scanner will check.

    The categories are owned by ``_scan_ui.categories_for``; this test
    just locks the round-trip from doctor through to that helper, so a
    drift between doctor and the scan preamble shows up in CI.
    """

    def test_all_components_emit_a_pass_check(self) -> None:
        from defenseclaw.commands import _scan_ui

        r = _DoctorResult()
        _check_scan_coverage(MagicMock(), r)

        labels_seen = {c["label"] for c in r.checks if c["status"] == "pass"}
        # One Scanner-coverage row per supported component.
        for component in _scan_ui.supported_components():
            sing = _scan_ui._COMPONENT_LABELS[component][0]  # type: ignore[attr-defined]
            self.assertIn(f"Scanner coverage ({sing})", labels_seen)

    def test_categories_match_scan_ui_source_of_truth(self) -> None:
        from defenseclaw.commands import _scan_ui

        r = _DoctorResult()
        _check_scan_coverage(MagicMock(), r)

        # Plugin row should literally contain every plugin category from
        # _scan_ui — locking the contract that doctor and the scanner
        # preamble can never disagree on what's being checked.
        plugin_row = next(c for c in r.checks if c["label"] == "Scanner coverage (plugin)")
        for cat in _scan_ui.categories_for("plugin"):
            self.assertIn(cat, plugin_row["detail"])


class TestConnectorInventoryRulePack(unittest.TestCase):
    """The inventory block authoritatively validates each effective rule pack.

    D9: when no explicit ``rule_pack_dir`` is set, the gateway resolves the
    built-in default to ``<data_dir>/policies/guardrail/default``. Doctor must
    send that effective path to the Go helper, not infer validity from whether
    the directory happens to contain files.
    """

    def _cfg(self, *, rule_pack_dir="", data_dir="/tmp/dc-doctor-test-datadir"):
        cfg = MagicMock()
        cfg.skill_dirs.return_value = []
        cfg.plugin_dirs.return_value = []
        cfg.mcp_servers.return_value = []
        cfg.data_dir = data_dir
        cfg.guardrail.effective_mode.return_value = "observe"
        cfg.guardrail.effective_rule_pack_dir.return_value = rule_pack_dir
        # Keep the N3 Detection row deterministic (real strings, not mocks).
        cfg.guardrail.detection_strategy = "regex_judge"
        cfg.guardrail.judge.enabled = False
        cfg.guardrail.judge.hook_connectors = []
        return cfg

    @staticmethod
    def _valid(**overrides: int | str) -> RulePackValidationResult:
        summary: dict[str, int | str] = {
            "judge_count": 2,
            "judge_category_count": 2,
            "rule_file_count": 4,
            "rule_count": 12,
            "enabled_rule_count": 11,
            "local_pattern_count": 6,
            "suppression_count": 3,
            "sensitive_tool_count": 5,
            "digest": "a" * 64,
        }
        summary.update(overrides)
        return RulePackValidationResult(
            wire_version=1,
            kind="validation",
            valid=True,
            summary=summary,
        )

    @staticmethod
    def _invalid() -> RulePackValidationResult:
        return RulePackValidationResult(
            wire_version=1,
            kind="validation_error",
            valid=False,
            error=RulePackValidationIssue(
                path="$",
                code="pack_not_found",
                reason="rule-pack directory does not exist",
            ),
        )

    @patch(
        "defenseclaw.commands.cmd_doctor.rulepack_validation.validate_rule_pack",
    )
    def test_rule_pack_invalid_fails(self, validate):
        validate.return_value = self._invalid()
        r = _DoctorResult()
        _check_connector_inventory(self._cfg(rule_pack_dir="/nonexistent/rule/pack/dir"), "cursor", r)
        rp = next(c for c in r.checks if c["label"] == "Rule pack")
        self.assertEqual(rp["status"], "fail")
        self.assertIn("pack_not_found", rp["detail"])
        self.assertIn("/nonexistent/rule/pack/dir", rp["detail"])
        validate.assert_called_once_with("/nonexistent/rule/pack/dir")

    @patch(
        "defenseclaw.commands.cmd_doctor.rulepack_validation.validate_rule_pack",
    )
    def test_rule_pack_helper_valid_passes(self, validate):
        validate.return_value = self._valid()
        r = _DoctorResult()
        _check_connector_inventory(self._cfg(rule_pack_dir=os.getcwd()), "cursor", r)
        rp = next(c for c in r.checks if c["label"] == "Rule pack")
        self.assertEqual(rp["status"], "pass")
        self.assertIn("11/12 rules enabled", rp["detail"])
        validate.assert_called_once_with(os.getcwd())

    @patch(
        "defenseclaw.commands.cmd_doctor.rulepack_validation.validate_rule_pack",
    )
    def test_valid_partial_pack_with_no_direct_rules_warns(self, validate):
        validate.return_value = self._valid(
            rule_file_count=0,
            rule_count=0,
            enabled_rule_count=0,
        )
        r = _DoctorResult()
        _check_connector_inventory(self._cfg(rule_pack_dir="/tmp/pack"), "cursor", r)
        rp = next(c for c in r.checks if c["label"] == "Rule pack")
        self.assertEqual(rp["status"], "warn")
        self.assertIn("0/0 rules enabled", rp["detail"])
        self.assertIn("compiled default categories retained", rp["detail"])

    @patch(
        "defenseclaw.commands.cmd_doctor.rulepack_validation.validate_rule_pack",
    )
    def test_valid_pack_with_all_rules_disabled_warns_without_default_hint(
        self, validate,
    ):
        validate.return_value = self._valid(rule_count=5, enabled_rule_count=0)
        r = _DoctorResult()
        _check_connector_inventory(self._cfg(rule_pack_dir="/tmp/pack"), "cursor", r)
        rp = next(c for c in r.checks if c["label"] == "Rule pack")
        self.assertEqual(rp["status"], "warn")
        self.assertIn("0/5 rules enabled", rp["detail"])
        self.assertNotIn("compiled default categories retained", rp["detail"])

    @patch(
        "defenseclaw.commands.cmd_doctor.rulepack_validation.validate_rule_pack",
    )
    def test_empty_digest_is_omitted_from_valid_pack_detail(self, validate):
        validate.return_value = self._valid(digest="")
        r = _DoctorResult()
        _check_connector_inventory(self._cfg(rule_pack_dir="/tmp/pack"), "cursor", r)
        rp = next(c for c in r.checks if c["label"] == "Rule pack")
        self.assertEqual(rp["status"], "pass")
        self.assertNotIn("digest=", rp["detail"])

    @patch(
        "defenseclaw.commands.cmd_doctor.rulepack_validation.validate_rule_pack",
    )
    def test_unset_rule_pack_validates_resolved_default(self, validate):
        validate.return_value = self._invalid()
        with tempfile.TemporaryDirectory() as data_dir:
            r = _DoctorResult()
            _check_connector_inventory(self._cfg(rule_pack_dir="", data_dir=data_dir), "codex", r)
            rp = next(c for c in r.checks if c["label"] == "Rule pack")
            self.assertEqual(rp["status"], "fail")
            self.assertIn("built-in default", rp["detail"])
            default_dir = os.path.join(data_dir, "policies", "guardrail", "default")
            self.assertIn(safe_display_path(default_dir), rp["detail"])
            validate.assert_called_once_with(default_dir)

    @patch(
        "defenseclaw.commands.cmd_doctor.rulepack_validation.validate_rule_pack",
        side_effect=RulePackValidationBridgeError(
            "rule-pack validation helper protocol is incompatible; run defenseclaw upgrade",
            code="protocol_error",
        ),
    )
    def test_incompatible_helper_warns_and_never_passes(self, _validate):
        r = _DoctorResult()
        _check_connector_inventory(self._cfg(rule_pack_dir="/tmp/pack"), "codex", r)
        rp = next(c for c in r.checks if c["label"] == "Rule pack")
        self.assertEqual(rp["status"], "warn")
        self.assertIn("validation unavailable", rp["detail"])

    @patch(
        "defenseclaw.commands.cmd_doctor.rulepack_validation.validate_rule_pack",
        side_effect=RulePackValidationBridgeError(
            "defenseclaw-gateway is required for authoritative rule-pack validation; "
            "run defenseclaw upgrade",
            code="gateway_unavailable",
        ),
    )
    def test_missing_helper_warns_and_never_passes(self, _validate):
        r = _DoctorResult()
        _check_connector_inventory(self._cfg(rule_pack_dir="/tmp/pack"), "codex", r)
        rp = next(c for c in r.checks if c["label"] == "Rule pack")
        self.assertEqual(rp["status"], "warn")
        self.assertNotEqual(rp["status"], "pass")
        self.assertIn("defenseclaw-gateway is required", rp["detail"])

    @patch(
        "defenseclaw.commands.cmd_doctor.rulepack_validation.validate_rule_pack",
        return_value={"valid": True, "secret": "DO-NOT-ECHO"},
    )
    def test_wrong_validator_outcome_type_warns_safely(self, _validate):
        r = _DoctorResult()
        _check_connector_inventory(self._cfg(rule_pack_dir="/tmp/pack"), "codex", r)
        rp = next(c for c in r.checks if c["label"] == "Rule pack")
        self.assertEqual(rp["status"], "warn")
        self.assertIn("internal response mismatch", rp["detail"])
        self.assertNotIn("DO-NOT-ECHO", rp["detail"])

    @patch(
        "defenseclaw.commands.cmd_doctor.rulepack_validation.validate_rule_pack",
        return_value=RulePackValidationResult(
            wire_version=1,
            kind="validation_error",
            valid=False,
        ),
    )
    def test_invalid_outcome_missing_error_warns(self, _validate):
        r = _DoctorResult()
        _check_connector_inventory(self._cfg(rule_pack_dir="/tmp/pack"), "codex", r)
        rp = next(c for c in r.checks if c["label"] == "Rule pack")
        self.assertEqual(rp["status"], "warn")
        self.assertIn("missing diagnostic", rp["detail"])

    @patch(
        "defenseclaw.commands.cmd_doctor.rulepack_validation.validate_rule_pack",
    )
    def test_shared_pack_is_validated_once_with_connector_attribution(self, validate):
        validate.return_value = self._valid()
        r = _DoctorResult()
        cache: dict[str, object] = {}
        cfg = self._cfg(rule_pack_dir="/tmp/shared")
        for connector in ("codex", "cursor"):
            with _doctor_label_suffix(f"[{connector}]"):
                _check_connector_inventory(
                    cfg,
                    connector,
                    r,
                    rule_pack_validation_cache=cache,
                )

        validate.assert_called_once_with("/tmp/shared")
        rows = [c for c in r.checks if c["label"].startswith("Rule pack")]
        self.assertEqual(
            [row["label"] for row in rows],
            ["Rule pack [codex]", "Rule pack [cursor]"],
        )
        self.assertTrue(all(row["status"] == "pass" for row in rows))

    @patch(
        "defenseclaw.commands.cmd_doctor.rulepack_validation.validate_rule_pack",
        side_effect=RuntimeError("sensitive validator value"),
    )
    def test_unexpected_validator_failure_warns_safely_and_is_cached(self, validate):
        r = _DoctorResult()
        cache: dict[str, object] = {}
        cfg = self._cfg(rule_pack_dir="/tmp/shared")
        for connector in ("codex", "cursor"):
            with _doctor_label_suffix(f"[{connector}]"):
                _check_connector_inventory(
                    cfg,
                    connector,
                    r,
                    rule_pack_validation_cache=cache,
                )

        validate.assert_called_once_with("/tmp/shared")
        rows = [c for c in r.checks if c["label"].startswith("Rule pack")]
        self.assertTrue(all(row["status"] == "warn" for row in rows))
        details = "\n".join(row["detail"] for row in rows)
        self.assertIn("unexpected validator failure", details)
        self.assertIn("RuntimeError", details)
        self.assertNotIn("sensitive validator value", details)


class TestDoctorActiveConnectors(unittest.TestCase):
    """``_doctor_active_connectors`` is the phantom-openclaw gate (D3): it must
    honor ``active_connectors()``'s empty signal instead of flooring to the
    singular ``openclaw`` path default the way doctor's old inventory/Services
    loops did.
    """

    def test_uses_active_connectors_when_present(self) -> None:
        cfg = MagicMock()
        cfg.active_connectors.return_value = ["Hermes", "codex"]
        self.assertEqual(_doctor_active_connectors(cfg), ["hermes", "codex"])

    def test_empty_active_connectors_returns_empty_not_phantom(self) -> None:
        """The D3 core: a configured-then-removed install reports ``[]`` and
        doctor must NOT fabricate ``["openclaw"]``."""
        cfg = MagicMock()
        cfg.active_connectors.return_value = []
        self.assertEqual(_doctor_active_connectors(cfg), [])

    def test_dedupes_and_lowercases_in_order(self) -> None:
        cfg = MagicMock()
        cfg.active_connectors.return_value = ["Codex", "codex", "Hermes"]
        self.assertEqual(_doctor_active_connectors(cfg), ["codex", "hermes"])

    def test_falls_back_to_primary_for_legacy_config(self) -> None:
        """A config predating ``active_connectors()`` falls back to the
        singular primary so legacy single-connector installs are unaffected."""
        cfg = MagicMock(spec=["guardrail"])  # no active_connectors/active_connector
        cfg.guardrail = MagicMock()
        cfg.guardrail.connector = "codex"
        self.assertEqual(_doctor_active_connectors(cfg), ["codex"])

    def test_swallows_active_connectors_exception(self) -> None:
        cfg = MagicMock()
        cfg.active_connectors.side_effect = RuntimeError("boom")
        cfg.active_connector.return_value = "openclaw"
        self.assertEqual(_doctor_active_connectors(cfg), ["openclaw"])


class TestCheckHookHealth(unittest.TestCase):
    """D4: generic hook-health rows for connectors that previously had no
    Services check (hermes/cursor/windsurf/geminicli/opencode). The check
    prefers the gateway's recorded ``hook_contract_lock.json`` paths and is
    format-agnostic (YAML for hermes, flat ``.js`` for opencode).
    """

    def setUp(self) -> None:
        # D:-rooted Windows CI workspaces commonly inherit an Authenticated
        # Users write ACE above TemporaryDirectory. Existing connector tests
        # isolate content behavior; custody-specific cases below override this
        # seam explicitly with safe, denied, unavailable, and Darwin verdicts.
        custody = patch(
            "defenseclaw.commands.cmd_doctor._pid_record_integrity_error",
            return_value=("ok", ""),
        )
        custody.start()
        self.addCleanup(custody.stop)
        private_custody = patch(
            "defenseclaw.commands.cmd_doctor.windows_acl_confidentiality_error",
            return_value=None,
        )
        private_custody.start()
        self.addCleanup(private_custody.stop)

    def _cfg(self, data_dir: str, connector: str, paths: list[str]) -> MagicMock:
        cfg = MagicMock()
        cfg.data_dir = data_dir
        cfg.gateway.api_port = 18970
        cfg.gateway.api_bind = "127.0.0.1"
        cfg.gateway.token_env = ""
        cfg.gateway.resolved_token.return_value = "opencode-runtime-fixture-token"
        with open(os.path.join(data_dir, "hook_contract_lock.json"), "w", encoding="utf-8") as fh:
            json.dump(
                {"connectors": {connector: {"locations": {"hook_config_paths": paths}}}},
                fh,
            )
        return cfg

    def _opencode_status(self, data_dir: str, row: dict, *, runtime_pid: object = 4242) -> str:
        now = datetime.now(timezone.utc)
        health = {
            "started_at": (now - timedelta(hours=1)).isoformat(),
            "connectors": [row],
        }
        return json.dumps(
            {
                "runtime": {"pid": runtime_pid, "data_dir": data_dir},
                "health": health,
            }
        )

    def _write_omnigent_backup(self, data_dir: str, logical: str, path: str) -> None:
        backup_dir = os.path.join(data_dir, "connector_backups", "omnigent")
        os.makedirs(backup_dir, exist_ok=True)
        with open(path, "rb") as fh:
            digest = hashlib.sha256(fh.read()).hexdigest()
        backup_path = os.path.join(backup_dir, f"{logical}.json")
        with open(backup_path, "w", encoding="utf-8") as fh:
            json.dump(
                {
                    "version": 1,
                    "connector": "omnigent",
                    "logical_name": logical,
                    "path": path,
                    "post_sha256": digest,
                },
                fh,
            )
        os.chmod(backup_path, 0o600)

    def test_lock_path_with_marker_requires_hermes_reload(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            hook = os.path.join(tmp, "config.yaml")
            with open(hook, "w", encoding="utf-8") as fh:
                fh.write("hooks:\n  - command: /x/hooks/hermes-hook.sh\n")
            r = _DoctorResult()
            _check_hook_health(self._cfg(tmp, "hermes", [hook]), "hermes", r)
        self.assertEqual(r.checks[-1]["status"], "fail")
        self.assertEqual(r.checks[-1]["label"], "Hermes hooks (fail-open)")
        self.assertIn(hook, r.checks[-1]["detail"])
        self.assertIn("live=false", r.checks[-1]["detail"])

    def test_lock_path_without_marker_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            hook = os.path.join(tmp, "config.yaml")
            with open(hook, "w", encoding="utf-8") as fh:
                fh.write("hooks: []\n")
            r = _DoctorResult()
            _check_hook_health(self._cfg(tmp, "hermes", [hook]), "hermes", r)
        self.assertEqual(r.checks[-1]["status"], "fail")
        self.assertIn("does not reference", r.checks[-1]["detail"])

    def test_missing_hook_file_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            r = _DoctorResult()
            _check_hook_health(
                self._cfg(tmp, "hermes", [os.path.join(tmp, "nope.yaml")]),
                "hermes",
                r,
            )
        self.assertEqual(r.checks[-1]["status"], "fail")
        self.assertIn("not found", r.checks[-1]["detail"])

    @patch("defenseclaw.commands.cmd_doctor._check_cursor_configured_runtime")
    def test_passive_cursor_health_disables_runtime_probe(self, configured_runtime) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            hook = os.path.join(tmp, "hooks.json")
            with open(hook, "w", encoding="utf-8") as fh:
                fh.write('{"hooks": [], "owner": "defenseclaw"}\n')
            r = _DoctorResult(passive=True)

            _check_hook_health(self._cfg(tmp, "cursor", [hook]), "cursor", r)

        configured_runtime.assert_called_once()
        self.assertIs(configured_runtime.call_args.kwargs["probe_runtime"], False)

    def test_opencode_flat_js_plugin_passes(self) -> None:
        """opencode's hook is a flat ``.js`` file (not JSON) keyed on the
        bare ``defenseclaw`` marker — the format-agnostic check must accept it."""
        with tempfile.TemporaryDirectory() as tmp:
            hook = os.path.join(tmp, "defenseclaw.js")
            with open(hook, "w", encoding="utf-8") as fh:
                fh.write("export const plugin = () => fetch('http://127.0.0.1:4000');  // defenseclaw bridge\n")
            body = Path(hook).read_bytes()
            backup = Path(tmp) / "connector_backups" / "opencode" / "config.json"
            backup.parent.mkdir(parents=True)
            backup.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "connector": "opencode",
                        "logical_name": "config",
                        "path": hook,
                        "post_sha256": hashlib.sha256(body).hexdigest(),
                    }
                ),
                encoding="utf-8",
            )
            r = _DoctorResult()
            cfg = self._cfg(tmp, "opencode", [hook])
            status = self._opencode_status(
                tmp,
                {
                    "name": "opencode",
                    "state": "running",
                    "source": "manual",
                    "load_heartbeat_at": datetime.now(timezone.utc).isoformat(),
                },
            )
            with (
                patch(
                    "defenseclaw.commands.cmd_doctor._trusted_gateway_listener",
                    return_value=MagicMock(trusted=True, pid=4242, detail=""),
                ),
                patch(
                    "defenseclaw.commands.cmd_doctor._http_probe",
                    return_value=(200, status),
                ),
            ):
                _check_hook_health(cfg, "opencode", r)
        self.assertEqual(r.checks[-1]["status"], "pass")
        self.assertEqual(r.checks[-1]["label"], "OpenCode hooks")
        self.assertIn("does not revalidate the Windows DACL", r.checks[-1]["detail"])
        self.assertIn("not tamper-proof", r.checks[-1]["detail"])
        self.assertIn("authenticated load heartbeat is fresh", r.checks[-1]["detail"])

    def test_opencode_missing_load_heartbeat_is_unverified_without_guessing_pure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            hook = Path(tmp) / "defenseclaw.js"
            body = b"// defenseclaw managed plugin\n"
            hook.write_bytes(body)
            backup = Path(tmp) / "connector_backups" / "opencode" / "config.json"
            backup.parent.mkdir(parents=True)
            backup.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "connector": "opencode",
                        "logical_name": "config",
                        "path": str(hook),
                        "post_sha256": hashlib.sha256(body).hexdigest(),
                    }
                ),
                encoding="utf-8",
            )
            r = _DoctorResult()
            cfg = self._cfg(tmp, "opencode", [str(hook)])
            status = self._opencode_status(
                tmp,
                {
                    "name": "opencode",
                    "state": "running",
                    "source": "manual",
                    "requests": 0,
                },
            )
            with (
                patch(
                    "defenseclaw.commands.cmd_doctor._trusted_gateway_listener",
                    return_value=MagicMock(trusted=True, pid=4242, detail=""),
                ),
                patch(
                    "defenseclaw.commands.cmd_doctor._http_probe",
                    return_value=(200, status),
                ),
            ):
                _check_hook_health(cfg, "opencode", r)

        self.assertEqual(r.checks[-1]["status"], "warn")
        self.assertIn("no authenticated load heartbeat", r.checks[-1]["detail"])
        self.assertNotIn("--pure", r.checks[-1]["detail"])

    def test_opencode_runtime_status_rejects_stale_and_malformed_heartbeat(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cfg = self._cfg(tmp, "opencode", [])
            for heartbeat, reason in (
                ((datetime.now(timezone.utc) - timedelta(minutes=16)).isoformat(), "stale"),
                ("not-a-timestamp", "malformed"),
            ):
                status = self._opencode_status(
                    tmp,
                    {
                        "name": "opencode",
                        "state": "running",
                        "source": "manual",
                        "load_heartbeat_at": heartbeat,
                    },
                )
                with (
                    self.subTest(heartbeat=heartbeat),
                    patch(
                        "defenseclaw.commands.cmd_doctor._trusted_gateway_listener",
                        return_value=MagicMock(trusted=True, pid=4242, detail=""),
                    ),
                    patch(
                        "defenseclaw.commands.cmd_doctor._http_probe",
                        return_value=(200, status),
                    ),
                ):
                    outcome, detail = _opencode_load_heartbeat_status(cfg)

                self.assertEqual(outcome, "warn")
                self.assertIn(reason, detail)
                self.assertNotIn("pure", detail.lower())

    def test_opencode_runtime_status_keeps_stopped_distinct_and_gateway_unavailable_unverified(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cfg = self._cfg(tmp, "opencode", [])
            stopped_status = self._opencode_status(
                tmp,
                {"name": "opencode", "state": "stopped"},
            )
            with (
                patch(
                    "defenseclaw.commands.cmd_doctor._trusted_gateway_listener",
                    return_value=MagicMock(trusted=True, pid=4242, detail=""),
                ),
                patch(
                    "defenseclaw.commands.cmd_doctor._http_probe",
                    return_value=(200, stopped_status),
                ),
            ):
                outcome, detail = _opencode_load_heartbeat_status(cfg)

            self.assertEqual(outcome, "warn")
            self.assertIn("reports stopped", detail)
            self.assertNotIn("pure", detail.lower())
            self.assertNotIn("drift", detail.lower())

            with (
                patch(
                    "defenseclaw.commands.cmd_doctor._trusted_gateway_listener",
                    return_value=MagicMock(trusted=True, pid=4242, detail=""),
                ),
                patch(
                    "defenseclaw.commands.cmd_doctor._http_probe",
                    return_value=(0, ""),
                ),
            ):
                outcome, detail = _opencode_load_heartbeat_status(cfg)

            self.assertEqual(outcome, "warn")
            self.assertIn("gateway is unreachable", detail)

    def test_opencode_runtime_requires_real_registration_source(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cfg = self._cfg(tmp, "opencode", [])
            for source, expected in (
                ("manual", "pass"),
                ("automatic", "pass"),
                ("", "warn"),
                ("discovered", "warn"),
                ("MANUAL", "warn"),
                ("Automatic", "warn"),
                (" manual", "warn"),
                ("automatic ", "warn"),
                (7, "warn"),
            ):
                status = self._opencode_status(
                    tmp,
                    {
                        "name": "opencode",
                        "state": "running",
                        "source": source,
                        "load_heartbeat_at": datetime.now(timezone.utc).isoformat(),
                    },
                )
                with (
                    self.subTest(source=source),
                    patch(
                        "defenseclaw.commands.cmd_doctor._trusted_gateway_listener",
                        return_value=MagicMock(trusted=True, pid=4242, detail=""),
                    ),
                    patch(
                        "defenseclaw.commands.cmd_doctor._http_probe",
                        return_value=(200, status),
                    ),
                ):
                    outcome, detail = _opencode_load_heartbeat_status(cfg)

                self.assertEqual(outcome, expected)
                if expected == "warn":
                    self.assertIn("manual or automatic OpenCode registration", detail)

    def test_opencode_runtime_rejects_unbound_authenticated_runtime_pid(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cfg = self._cfg(tmp, "opencode", [])
            row = {
                "name": "opencode",
                "state": "running",
                "source": "manual",
                "load_heartbeat_at": datetime.now(timezone.utc).isoformat(),
            }
            for runtime_pid in (
                4242.9,
                4242.0,
                True,
                None,
                {},
                [],
                "not-a-pid",
                0,
                -1,
                "4242",
                "004242",
                "+4242",
                " 4242 ",
                4241,
                9999,
            ):
                status = self._opencode_status(tmp, row, runtime_pid=runtime_pid)
                with (
                    self.subTest(runtime_pid=runtime_pid),
                    patch(
                        "defenseclaw.commands.cmd_doctor._trusted_gateway_listener",
                        return_value=MagicMock(trusted=True, pid=4242, detail=""),
                    ),
                    patch(
                        "defenseclaw.commands.cmd_doctor._http_probe",
                        return_value=(200, status),
                    ),
                ):
                    outcome, detail = _opencode_load_heartbeat_status(cfg)

                self.assertEqual(outcome, "warn")
                self.assertIn("runtime", detail.lower())

    def test_opencode_tamper_fails_digest_check(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            hook = Path(tmp) / "defenseclaw.js"
            original = b"// defenseclaw managed plugin\n"
            hook.write_bytes(original)
            backup = Path(tmp) / "connector_backups" / "opencode" / "config.json"
            backup.parent.mkdir(parents=True)
            backup.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "connector": "opencode",
                        "logical_name": "config",
                        "path": str(hook),
                        "post_sha256": hashlib.sha256(original).hexdigest(),
                    }
                ),
                encoding="utf-8",
            )
            hook.write_text("// defenseclaw operator edit\n", encoding="utf-8")
            r = _DoctorResult()
            _check_hook_health(self._cfg(tmp, "opencode", [str(hook)]), "opencode", r)
        self.assertEqual(r.checks[-1]["status"], "fail")
        self.assertIn("drift detected", r.checks[-1]["detail"])

    def test_opencode_lockless_fallback_honors_custom_config_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config_home = Path(tmp) / "custom-opencode"
            hook = config_home / "plugins" / "defenseclaw.js"
            hook.parent.mkdir(parents=True)
            body = b"// defenseclaw managed plugin\n"
            hook.write_bytes(body)
            data_dir = Path(tmp) / "data"
            backup = data_dir / "connector_backups" / "opencode" / "config.json"
            backup.parent.mkdir(parents=True)
            backup.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "connector": "opencode",
                        "logical_name": "config",
                        "path": str(hook),
                        "post_sha256": hashlib.sha256(body).hexdigest(),
                    }
                ),
                encoding="utf-8",
            )
            cfg = MagicMock()
            cfg.data_dir = str(data_dir)
            cfg.gateway.api_port = 18970
            cfg.gateway.api_bind = "127.0.0.1"
            cfg.gateway.token_env = ""
            cfg.gateway.resolved_token.return_value = "opencode-runtime-fixture-token"
            r = _DoctorResult()
            status = self._opencode_status(
                str(data_dir),
                {
                    "name": "opencode",
                    "state": "running",
                    "source": "manual",
                    "load_heartbeat_at": datetime.now(timezone.utc).isoformat(),
                },
            )
            with (
                patch.dict(os.environ, {"OPENCODE_CONFIG_DIR": str(config_home)}),
                patch(
                    "defenseclaw.commands.cmd_doctor._trusted_gateway_listener",
                    return_value=MagicMock(trusted=True, pid=4242, detail=""),
                ),
                patch(
                    "defenseclaw.commands.cmd_doctor._http_probe",
                    return_value=(200, status),
                ),
            ):
                _check_hook_health(cfg, "opencode", r)

        self.assertEqual(r.checks[-1]["status"], "pass")
        self.assertIn(str(hook), r.checks[-1]["detail"])

    def test_amp_warns_for_other_direct_plugins_without_following_links(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            amp_home = os.path.join(tmp, "system", "amp")
            system_plugins = os.path.join(amp_home, "plugins")
            project_plugins = os.path.join(tmp, "workspace", ".amp", "plugins")
            os.makedirs(system_plugins)
            os.makedirs(project_plugins)
            first_party = os.path.join(system_plugins, "defenseclaw.ts")
            system_third_party = os.path.join(system_plugins, "telemetry.ts")
            project_third_party = os.path.join(project_plugins, "custom-agent.ts")
            for path in (first_party, system_third_party, project_third_party):
                with open(path, "w", encoding="utf-8") as handle:
                    handle.write("throw new Error('doctor must not execute TypeScript')\n")
            linked = os.path.join(project_plugins, "linked.ts")
            try:
                os.symlink(system_third_party, linked)
            except OSError:
                linked = ""

            cfg = MagicMock()
            cfg.plugin_dirs.return_value = [project_plugins, system_plugins]
            cfg.connector_workspace_dir.return_value = os.path.join(tmp, "workspace")
            with (
                patch(
                    "defenseclaw.commands.cmd_doctor.amp_config_home",
                    return_value=amp_home,
                ),
                patch(
                    "defenseclaw.commands.cmd_doctor.amp_managed_settings_path",
                    return_value="",
                ),
                patch(
                    "defenseclaw.commands.cmd_doctor.connector_policy_settings",
                    return_value={},
                ),
                patch(
                    "defenseclaw.commands.cmd_doctor.rule_paths",
                    return_value=[],
                ),
            ):
                r = _DoctorResult()
                _check_amp_native_policy_surfaces(cfg, r)

        warnings = [
            check
            for check in r.checks
            if check["label"] == "Amp plugin initialization"
        ]
        self.assertEqual(len(warnings), 1)
        detail = warnings[0]["detail"]
        self.assertEqual(warnings[0]["status"], "warn")
        self.assertIn(system_third_party, detail)
        self.assertIn(project_third_party, detail)
        self.assertNotIn(first_party, detail)
        if linked:
            self.assertNotIn(linked, detail)
        self.assertIn("outside DefenseClaw's tool.call interception", detail)
        self.assertIn("handler order is undefined", detail)
        self.assertIn("does not sandbox Amp plugin initialization", detail)

    def test_unknown_connector_is_noop(self) -> None:
        r = _DoctorResult()
        _check_hook_health(MagicMock(), "totallymadeupclaw", r)
        self.assertEqual(r.checks, [])

    def test_omnigent_custody_reader_accepts_safe_chain_and_same_object(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            evidence = os.path.join(tmp, "evidence.json")
            Path(evidence).write_bytes(b'{"safe":true}')
            with patch(
                "defenseclaw.commands.cmd_doctor._pid_record_integrity_error",
                return_value=("ok", ""),
            ) as custody:
                status, body, detail = _omnigent_custody_read(
                    evidence,
                    role="omnigent-test-evidence",
                    max_bytes=64,
                    root=tmp,
                )
            current_stat = os.stat(evidence)

        self.assertEqual((status, body, detail), ("ok", b'{"safe":true}', ""))
        inspected_path, inspected_stat = custody.call_args.args
        self.assertEqual(inspected_path, evidence)
        self.assertTrue(os.path.samestat(inspected_stat, current_stat))

    def test_omnigent_custody_reader_refuses_unsafe_windows_ancestor(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            evidence = os.path.join(tmp, "private-evidence.json")
            Path(evidence).write_bytes(b"{}")
            with patch(
                "defenseclaw.commands.cmd_doctor._pid_record_integrity_error",
                return_value=(
                    "denied",
                    "PID file ancestor directory has unsafe ACLs (ACL grants write access to untrusted SID S-1-5-11)",
                ),
            ):
                status, body, detail = _omnigent_custody_read(
                    evidence,
                    role="omnigent-lock",
                    max_bytes=64,
                    root=tmp,
                )

        self.assertEqual(status, "unsafe")
        self.assertIsNone(body)
        self.assertIn("custody is unsafe", detail)
        self.assertIn("path-sha256=", detail)
        self.assertNotIn("private-evidence", detail)
        self.assertNotIn("S-1-5-11", detail)

    def test_omnigent_windows_acl_query_error_is_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            evidence = os.path.join(tmp, "private-query-error.json")
            Path(evidence).write_bytes(b"must not be returned")
            with (
                patch("defenseclaw.commands.cmd_doctor.os.name", "nt"),
                patch(
                    "defenseclaw.commands.cmd_doctor._pid_record_integrity_error",
                    side_effect=doctor_gateway._pid_record_integrity_error,
                ),
                patch(
                    "defenseclaw.file_permissions._windows_acl_snapshot",
                    side_effect=OSError("synthetic ACL query failure"),
                ),
            ):
                status, body, detail = _omnigent_custody_read(
                    evidence,
                    role="omnigent-windows-record",
                    max_bytes=64,
                )

        self.assertEqual(status, "unavailable")
        self.assertIsNone(body)
        self.assertIn("path-sha256=", detail)
        self.assertNotIn("private-query-error", detail)
        self.assertNotIn("synthetic ACL query failure", detail)

    def test_omnigent_windows_unresolved_current_sid_is_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            evidence = os.path.join(tmp, "private-sid-error.json")
            Path(evidence).write_bytes(b"must not be returned")
            with (
                patch("defenseclaw.commands.cmd_doctor.os.name", "nt"),
                patch(
                    "defenseclaw.commands.cmd_doctor._pid_record_integrity_error",
                    side_effect=doctor_gateway._pid_record_integrity_error,
                ),
                patch(
                    "defenseclaw.file_permissions._windows_acl_snapshot",
                    return_value=("S-1-5-21-current", False, []),
                ),
                patch(
                    "defenseclaw.file_permissions._windows_current_user_sid",
                    return_value="",
                ),
            ):
                status, body, detail = _omnigent_custody_read(
                    evidence,
                    role="omnigent-windows-record",
                    max_bytes=64,
                )

        self.assertEqual(status, "unavailable")
        self.assertIsNone(body)
        self.assertIn("path-sha256=", detail)
        self.assertNotIn("private-sid-error", detail)
        self.assertNotIn("SID", detail)

    def test_omnigent_windows_wrapped_acl_inspection_failures_are_unavailable(self) -> None:
        problems = (
            "PID file ancestor directory has unsafe ACLs (cannot read Windows ACL (synthetic ancestor query failure))",
            "PID file ancestor directory has unsafe ACLs (current user SID could not be resolved)",
        )
        with tempfile.TemporaryDirectory() as tmp:
            evidence = os.path.join(tmp, "private-ancestor-error.json")
            Path(evidence).write_bytes(b"must not be returned")
            for problem in problems:
                with (
                    self.subTest(problem=problem),
                    patch("defenseclaw.commands.cmd_doctor.os.name", "nt"),
                    patch(
                        "defenseclaw.commands.cmd_doctor._pid_record_integrity_error",
                        return_value=("denied", problem),
                    ),
                ):
                    status, body, detail = _omnigent_custody_read(
                        evidence,
                        role="omnigent-windows-record",
                        max_bytes=64,
                    )

                self.assertEqual(status, "unavailable")
                self.assertIsNone(body)
                self.assertIn("path-sha256=", detail)
                self.assertNotIn("private-ancestor-error", detail)
                self.assertNotIn("SID", detail)
                self.assertNotIn("synthetic ancestor", detail)

    def test_omnigent_custody_reader_keeps_unavailable_ancestor_distinct(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            evidence = os.path.join(tmp, "evidence.json")
            Path(evidence).write_bytes(b"{}")
            with patch(
                "defenseclaw.commands.cmd_doctor._pid_record_integrity_error",
                return_value=("unavailable", "synthetic UID-mapped ancestor"),
            ):
                status, body, detail = _omnigent_custody_read(
                    evidence,
                    role="omnigent-posix-evidence",
                    max_bytes=64,
                    root=tmp,
                )

        self.assertEqual(status, "unavailable")
        self.assertIsNone(body)
        self.assertIn("custody is unavailable", detail)
        self.assertNotIn("malformed", detail)

    def test_omnigent_backup_requires_private_windows_acl_but_artifact_is_integrity_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            data_dir = os.path.join(tmp, "data")
            os.makedirs(data_dir)
            module = os.path.join(data_dir, "defenseclaw_omnigent_policy.py")
            Path(module).write_bytes(b"POLICY_REGISTRY = []\ndefenseclaw_policy = None\n")
            self._write_omnigent_backup(data_dir, "module", module)
            backup_path = os.path.join(data_dir, "connector_backups", "omnigent", "module.json")
            record = json.loads(Path(backup_path).read_text(encoding="utf-8"))
            record["pristine_bytes"] = "private backup fixture bytes"
            Path(backup_path).write_text(json.dumps(record), encoding="utf-8")
            os.chmod(backup_path, 0o600)
            read_only_ace = "ACL grants read access to untrusted SID S-1-5-11"
            windows_os = MagicMock(wraps=os)
            windows_os.name = "nt"

            with (
                patch("defenseclaw.commands.cmd_doctor.os", windows_os),
                patch(
                    "defenseclaw.commands.cmd_doctor.windows_acl_confidentiality_error",
                    return_value=read_only_ace,
                ) as private_acl,
            ):
                backup_detail = _omnigent_managed_artifact_drift(
                    MagicMock(data_dir=data_dir),
                    "module",
                    module,
                )
                artifact_status, artifact_body, artifact_detail = _omnigent_custody_read(
                    module,
                    role="managed-module-artifact",
                    max_bytes=1024,
                    root=data_dir,
                )

        self.assertIn("private custody is unsafe", backup_detail)
        self.assertIn("path-sha256=", backup_detail)
        self.assertNotIn("module.json", backup_detail)
        self.assertEqual(artifact_status, "ok")
        self.assertEqual(artifact_body, b"POLICY_REGISTRY = []\ndefenseclaw_policy = None\n")
        self.assertEqual(artifact_detail, "")
        private_acl.assert_called_once_with(backup_path)

    def test_omnigent_darwin_acl_clean_write_grant_and_inspection_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            evidence = os.path.join(tmp, "private-darwin-evidence.json")
            Path(evidence).write_bytes(b"safe")
            cases = (
                (("ok", ""), "ok", b"safe"),
                (("denied", "extended ACL grants additional write access"), "unsafe", None),
                (("denied", "extended ACL could not be inspected"), "unavailable", None),
                (
                    (
                        "denied",
                        "PID file ancestor directory has unsafe ACLs (extended ACL could not be interpreted)",
                    ),
                    "unavailable",
                    None,
                ),
            )
            for custody_result, expected_status, expected_body in cases:
                with (
                    self.subTest(custody_result=custody_result),
                    patch("defenseclaw.commands.cmd_doctor.sys.platform", "darwin"),
                    patch(
                        "defenseclaw.commands.cmd_doctor._pid_record_integrity_error",
                        return_value=custody_result,
                    ),
                ):
                    status, body, detail = _omnigent_custody_read(
                        evidence,
                        role="omnigent-darwin-record",
                        max_bytes=64,
                    )

                self.assertEqual(status, expected_status)
                self.assertEqual(body, expected_body)
                if expected_status != "ok":
                    self.assertIn(f"custody is {expected_status}", detail)
                    self.assertNotIn("private-darwin", detail)

    def test_omnigent_custody_reader_rejects_darwin_acl_on_leaf_and_ancestor(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            evidence = os.path.join(tmp, "evidence.json")
            Path(evidence).write_bytes(b"safe")
            actual_info = os.lstat(evidence)
            leaf_info = SimpleNamespace(
                st_mode=stat.S_IFREG | 0o600,
                st_uid=getattr(actual_info, "st_uid", 0),
            )
            directory_info = SimpleNamespace(
                st_mode=stat.S_IFDIR | 0o700,
                st_uid=leaf_info.st_uid,
            )

            def fake_lstat(path, *args, **kwargs):
                del args, kwargs
                return (
                    leaf_info
                    if os.path.normcase(os.path.abspath(path)) == os.path.normcase(evidence)
                    else directory_info
                )

            for unsafe_index in (0, 1):
                checked: list[str] = []

                def acl_problem(path):
                    checked.append(os.fspath(path))
                    return "extended ACL grants write access" if len(checked) - 1 == unsafe_index else None

                with (
                    self.subTest(unsafe_index=unsafe_index),
                    patch(
                        "defenseclaw.commands.cmd_doctor._pid_record_integrity_error",
                        side_effect=doctor_gateway._pid_record_integrity_error,
                    ),
                    patch.object(doctor_gateway.os, "name", "posix"),
                    patch.object(doctor_gateway.sys, "platform", "darwin"),
                    patch.object(doctor_gateway.os, "lstat", side_effect=fake_lstat),
                    patch("defenseclaw.file_permissions.darwin_acl_write_error", side_effect=acl_problem),
                ):
                    status, body, detail = _omnigent_custody_read(
                        evidence,
                        role="omnigent-darwin-evidence",
                        max_bytes=64,
                    )

                self.assertEqual(status, "unsafe")
                self.assertIsNone(body)
                self.assertIn("custody is unsafe", detail)
                self.assertEqual(len(checked), unsafe_index + 1)

    def test_omnigent_custody_reader_rejects_reparse_race_oversize_and_escape(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = os.path.join(tmp, "trusted")
            os.makedirs(root)
            evidence = os.path.join(root, "private-evidence.json")
            Path(evidence).write_bytes(b"12345")
            outside = os.path.join(tmp, "private-outside.json")
            Path(outside).write_bytes(b"{}")

            with patch("defenseclaw.commands.cmd_doctor.is_link_or_reparse", return_value=True):
                leaf_reparse, _, _ = _omnigent_custody_read(
                    evidence,
                    role="omnigent-evidence",
                    max_bytes=64,
                    root=root,
                )
            with (
                patch(
                    "defenseclaw.commands.cmd_doctor._pid_record_integrity_error",
                    return_value=("ok", ""),
                ),
                patch(
                    "defenseclaw.commands.cmd_doctor.read_regular_file_no_follow",
                    side_effect=UnsafePathError(
                        "synthetic ancestor reparse",
                        code=UNSAFE_PATH_SYMLINK_OR_REPARSE,
                    ),
                ),
            ):
                ancestor_reparse, _, ancestor_detail = _omnigent_custody_read(
                    evidence,
                    role="omnigent-evidence",
                    max_bytes=64,
                    root=root,
                )
            with patch(
                "defenseclaw.commands.cmd_doctor._pid_record_integrity_error",
                return_value=("ok", ""),
            ):
                oversized, _, oversized_detail = _omnigent_custody_read(
                    evidence,
                    role="omnigent-evidence",
                    max_bytes=4,
                    root=root,
                )
                with patch(
                    "defenseclaw.commands.cmd_doctor.read_regular_file_no_follow",
                    side_effect=UnsafePathError(
                        "synthetic read-time replacement",
                        code=UNSAFE_PATH_CHANGED,
                    ),
                ):
                    replaced, _, replaced_detail = _omnigent_custody_read(
                        evidence,
                        role="omnigent-evidence",
                        max_bytes=64,
                        root=root,
                    )
            escaped, _, escaped_detail = _omnigent_custody_read(
                outside,
                role="omnigent-evidence",
                max_bytes=64,
                root=root,
            )

        self.assertEqual(
            (leaf_reparse, ancestor_reparse, oversized, replaced, escaped),
            ("unsafe", "unsafe", "invalid", "unavailable", "unsafe"),
        )
        self.assertIn("stable regular file", ancestor_detail)
        self.assertIn("byte limit", oversized_detail)
        self.assertIn("changed while", replaced_detail)
        self.assertIn("trusted root", escaped_detail)
        for detail in (ancestor_detail, oversized_detail, replaced_detail, escaped_detail):
            self.assertNotIn("private-", detail)

    def test_omnigent_local_server_pid_uses_custody_reader(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "local_server.pid").write_text("4242\n18970\n", encoding="utf-8")
            with (
                patch.dict(os.environ, {"OMNIGENT_DATA_DIR": tmp}),
                patch("defenseclaw.process_liveness.pid_alive", return_value=True),
            ):
                pid, detail = _omnigent_local_server_pid()

        self.assertEqual(pid, 4242)
        self.assertIn("port=18970", detail)

    def test_omnigent_unsafe_lock_does_not_fall_back(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cfg = self._cfg(tmp, "omnigent", [])
            with patch(
                "defenseclaw.commands.cmd_doctor._pid_record_integrity_error",
                return_value=("denied", "synthetic unsafe lock DACL"),
            ):
                r = _DoctorResult()
                _check_omnigent_policy_health(cfg, r)

        self.assertEqual(r.checks[-1]["status"], "fail")
        self.assertIn("omnigent-lock[path-sha256=", r.checks[-1]["detail"])
        self.assertIn("custody is unsafe", r.checks[-1]["detail"])

    def test_omnigent_target_escapes_are_redacted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            data_dir = os.path.join(tmp, "data")
            os.makedirs(data_dir)
            outside = os.path.join(tmp, "private-outside-module.py")
            Path(outside).write_text("POLICY_REGISTRY = []\ndefenseclaw_policy = None\n", encoding="utf-8")
            self._write_omnigent_backup(data_dir, "module", outside)
            detail = _omnigent_managed_artifact_drift(MagicMock(data_dir=data_dir), "module", outside)

        self.assertIn("escapes DefenseClaw data custody", detail)
        self.assertIn("path-sha256=", detail)
        self.assertNotIn("private-outside-module", detail)

    def test_omnigent_pth_import_escape_is_redacted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = os.path.join(tmp, "config.yaml")
            module = os.path.join(tmp, "defenseclaw_omnigent_policy.py")
            pth = os.path.join(tmp, "defenseclaw_omnigent.pth")
            Path(config).write_text(
                "policy_modules: [defenseclaw_omnigent_policy]\npolicies: {defenseclaw_guardrail: {}}\n",
                encoding="utf-8",
            )
            Path(module).write_text("POLICY_REGISTRY = []\ndefenseclaw_policy = None\n", encoding="utf-8")
            Path(pth).write_text(os.path.join(tmp, "private-import-target") + "\n", encoding="utf-8")
            for logical, path in (("config", config), ("module", module), ("pth", pth)):
                self._write_omnigent_backup(tmp, logical, path)
            cfg = self._cfg(tmp, "omnigent", [config])
            Path(tmp, "hook_contract_lock.json").write_text(
                json.dumps(
                    {
                        "connectors": {
                            "omnigent": {
                                "locations": {
                                    "hook_config_paths": [config],
                                    "hook_script_paths": [module, pth],
                                }
                            }
                        }
                    }
                ),
                encoding="utf-8",
            )
            r = _DoctorResult()

            _check_omnigent_policy_health(cfg, r)

        self.assertEqual(r.checks[-1]["status"], "fail")
        self.assertIn("points outside the managed module", r.checks[-1]["detail"])
        self.assertNotIn("private-import-target", r.checks[-1]["detail"])

    def test_non_omnigent_lock_reader_is_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            hook = os.path.join(tmp, "config.yaml")
            Path(hook).write_text("hooks: []\n", encoding="utf-8")
            cfg = self._cfg(tmp, "hermes", [hook])
            with patch(
                "defenseclaw.commands.cmd_doctor._omnigent_lock_locations",
                side_effect=AssertionError("OmniGent reader must stay connector-scoped"),
            ):
                paths = _hook_health_paths_from_lock(cfg, "hermes")

        self.assertEqual(paths, [hook])

    def test_omnigent_requires_config_module_and_import_shim(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = os.path.join(tmp, "config.yaml")
            module = os.path.join(tmp, "defenseclaw_omnigent_policy.py")
            pth = os.path.join(tmp, "defenseclaw_omnigent.pth")
            with open(config, "w", encoding="utf-8") as fh:
                fh.write("policy_modules: [defenseclaw_omnigent_policy]\npolicies: {defenseclaw_guardrail: {}}\n")
            with open(module, "w", encoding="utf-8") as fh:
                fh.write("def defenseclaw_policy(event): return {'result': 'ALLOW'}\nPOLICY_REGISTRY = []\n")
            with open(pth, "w", encoding="utf-8") as fh:
                fh.write(tmp + "\n")
            for logical, path in (("config", config), ("module", module), ("pth", pth)):
                self._write_omnigent_backup(tmp, logical, path)
            cfg = MagicMock()
            cfg.data_dir = tmp
            with open(os.path.join(tmp, "hook_contract_lock.json"), "w", encoding="utf-8") as fh:
                json.dump(
                    {
                        "connectors": {
                            "omnigent": {
                                "locations": {
                                    "hook_config_paths": [config],
                                    "hook_script_paths": [module, pth],
                                }
                            }
                        }
                    },
                    fh,
                )
            r = _DoctorResult()
            with patch(
                "defenseclaw.commands.cmd_doctor._omnigent_live_config_evidence",
                return_value=("pass", f"live effective config verified through --config={config}"),
            ):
                _check_omnigent_policy_health(cfg, r)
        self.assertEqual(r.checks[-1]["status"], "pass")

    def test_omnigent_repair_command_preserves_action_closed_hilt_posture(self) -> None:
        cfg = MagicMock()
        cfg.guardrail.effective_mode.return_value = "action"
        cfg.guardrail.effective_hook_fail_mode.return_value = "closed"
        cfg.guardrail.effective_hilt.return_value = MagicMock(enabled=True, min_severity="LOW")

        command = _omnigent_setup_repair_command(cfg)

        self.assertEqual(
            command,
            "defenseclaw setup omnigent --mode action --fail-mode closed "
            "--human-approval --hilt-min-severity LOW --yes --restart",
        )

    def test_omnigent_repair_command_preserves_observe_open_without_hilt(self) -> None:
        cfg = MagicMock()
        cfg.guardrail.effective_mode.return_value = "observe"
        cfg.guardrail.effective_hook_fail_mode.return_value = "open"
        cfg.guardrail.effective_hilt.return_value = MagicMock(enabled=False, min_severity="HIGH")

        command = _omnigent_setup_repair_command(cfg)

        self.assertEqual(
            command,
            "defenseclaw setup omnigent --mode observe --fail-mode open "
            "--no-human-approval --yes --restart",
        )

    def test_omnigent_repair_command_does_not_weaken_unresolved_posture(self) -> None:
        cfg = MagicMock()
        cfg.guardrail.effective_mode.return_value = "malformed"
        cfg.guardrail.effective_hook_fail_mode.side_effect = ValueError("invalid fail mode")
        cfg.guardrail.effective_hilt.side_effect = ValueError("invalid HILT")

        command = _omnigent_setup_repair_command(cfg)

        self.assertEqual(
            command,
            "defenseclaw setup omnigent --mode action --fail-mode closed --yes --restart",
        )

    def test_omnigent_drift_remediation_uses_posture_preserving_command(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            artifact = os.path.join(tmp, "config.yaml")
            with open(artifact, "w", encoding="utf-8") as fh:
                fh.write("original\n")
            self._write_omnigent_backup(tmp, "config", artifact)
            with open(artifact, "w", encoding="utf-8") as fh:
                fh.write("drifted\n")

            cfg = MagicMock()
            cfg.data_dir = tmp
            cfg.guardrail.effective_mode.return_value = "action"
            cfg.guardrail.effective_hook_fail_mode.return_value = "closed"
            cfg.guardrail.effective_hilt.return_value = MagicMock(enabled=True, min_severity="HIGH")

            detail = _omnigent_managed_artifact_drift(cfg, "config", artifact)

        self.assertIn(
            "`defenseclaw setup omnigent --mode action --fail-mode closed "
            "--human-approval --hilt-min-severity HIGH --yes --restart`",
            detail,
        )
        self.assertIn("without changing enforcement posture", detail)

    def test_omnigent_missing_import_shim_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = os.path.join(tmp, "config.yaml")
            module = os.path.join(tmp, "defenseclaw_omnigent_policy.py")
            with open(config, "w", encoding="utf-8") as fh:
                fh.write("policy_modules: [defenseclaw_omnigent_policy]\npolicies: {defenseclaw_guardrail: {}}\n")
            with open(module, "w", encoding="utf-8") as fh:
                fh.write("defenseclaw_policy = None\nPOLICY_REGISTRY = []\n")
            cfg = MagicMock()
            cfg.data_dir = tmp
            with open(os.path.join(tmp, "hook_contract_lock.json"), "w", encoding="utf-8") as fh:
                json.dump(
                    {
                        "connectors": {
                            "omnigent": {
                                "locations": {
                                    "hook_config_paths": [config],
                                    "hook_script_paths": [module],
                                }
                            }
                        }
                    },
                    fh,
                )
            r = _DoctorResult()
            _check_omnigent_policy_health(cfg, r)
        self.assertEqual(r.checks[-1]["status"], "fail")
        self.assertIn(".pth", r.checks[-1]["detail"])

    def test_omnigent_missing_policy_entry_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = os.path.join(tmp, "config.yaml")
            module = os.path.join(tmp, "defenseclaw_omnigent_policy.py")
            pth = os.path.join(tmp, "defenseclaw_omnigent.pth")
            with open(config, "w", encoding="utf-8") as fh:
                fh.write("policy_modules: [defenseclaw_omnigent_policy]\n")
            with open(module, "w", encoding="utf-8") as fh:
                fh.write("defenseclaw_policy = None\nPOLICY_REGISTRY = []\n")
            with open(pth, "w", encoding="utf-8") as fh:
                fh.write(tmp + "\n")
            cfg = MagicMock()
            cfg.data_dir = tmp
            with open(os.path.join(tmp, "hook_contract_lock.json"), "w", encoding="utf-8") as fh:
                json.dump(
                    {
                        "connectors": {
                            "omnigent": {
                                "locations": {
                                    "hook_config_paths": [config],
                                    "hook_script_paths": [module, pth],
                                }
                            }
                        }
                    },
                    fh,
                )
            with patch.dict(os.environ, {"OMNIGENT_CONFIG_HOME": tmp}):
                r = _DoctorResult()
                _check_omnigent_policy_health(cfg, r)

        self.assertEqual(r.checks[-1]["status"], "fail")
        self.assertIn("policy registration", r.checks[-1]["detail"])

    def test_omnigent_uses_managed_backups_when_lock_is_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config_home = os.path.join(tmp, "omnigent-config")
            os.makedirs(config_home)
            config = os.path.join(config_home, "config.yaml")
            module_dir = os.path.join(tmp, "hooks")
            os.makedirs(module_dir)
            module = os.path.join(module_dir, "defenseclaw_omnigent_policy.py")
            site_packages = os.path.join(tmp, "site-packages")
            os.makedirs(site_packages)
            pth = os.path.join(site_packages, "defenseclaw_omnigent.pth")
            with open(config, "w", encoding="utf-8") as fh:
                fh.write("policy_modules: [defenseclaw_omnigent_policy]\npolicies: {defenseclaw_guardrail: {}}\n")
            with open(module, "w", encoding="utf-8") as fh:
                fh.write("defenseclaw_policy = None\nPOLICY_REGISTRY = []\n")
            with open(pth, "w", encoding="utf-8") as fh:
                fh.write(module_dir + "\n")
            backup_dir = os.path.join(tmp, "connector_backups", "omnigent")
            os.makedirs(backup_dir)
            for logical, path in (("config", config), ("module", module), ("pth", pth)):
                self._write_omnigent_backup(tmp, logical, path)
            cfg = MagicMock()
            cfg.data_dir = tmp
            with patch.dict(os.environ, {"OMNIGENT_CONFIG_HOME": config_home}):
                r = _DoctorResult()
                with patch(
                    "defenseclaw.commands.cmd_doctor._omnigent_live_config_evidence",
                    return_value=("pass", f"live effective config verified through --config={config}"),
                ):
                    _check_omnigent_policy_health(cfg, r)

        self.assertEqual(r.checks[-1]["status"], "pass")

    def test_omnigent_valid_artifacts_without_live_server_warn(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = os.path.join(tmp, "config.yaml")
            module = os.path.join(tmp, "defenseclaw_omnigent_policy.py")
            pth = os.path.join(tmp, "defenseclaw_omnigent.pth")
            with open(config, "w", encoding="utf-8") as fh:
                fh.write("policy_modules: [defenseclaw_omnigent_policy]\npolicies: {defenseclaw_guardrail: {}}\n")
            with open(module, "w", encoding="utf-8") as fh:
                fh.write("defenseclaw_policy = None\nPOLICY_REGISTRY = []\n")
            with open(pth, "w", encoding="utf-8") as fh:
                fh.write(tmp + "\n")
            for logical, path in (("config", config), ("module", module), ("pth", pth)):
                self._write_omnigent_backup(tmp, logical, path)
            cfg = MagicMock()
            cfg.data_dir = tmp
            with open(os.path.join(tmp, "hook_contract_lock.json"), "w", encoding="utf-8") as fh:
                json.dump({"connectors": {"omnigent": {"locations": {
                    "hook_config_paths": [config],
                    "hook_script_paths": [module, pth],
                }}}}, fh)
            r = _DoctorResult()
            with patch(
                "defenseclaw.commands.cmd_doctor._omnigent_local_server_pid",
                return_value=(0, "no recorded server"),
            ):
                _check_omnigent_policy_health(cfg, r)

        self.assertEqual(r.checks[-1]["status"], "warn")
        self.assertIn("unverified", r.checks[-1]["detail"])

    def test_omnigent_live_config_evidence_matches_explicit_argument(self) -> None:
        config = os.path.abspath("managed-omnigent-config.yaml")
        with (
            patch(
                "defenseclaw.commands.cmd_doctor._omnigent_local_server_pid",
                return_value=(4242, "recorded live OmniGent server"),
            ),
            patch(
                "defenseclaw.commands.cmd_doctor._omnigent_process_argv",
                return_value=("omnigent.exe", "server", "--config", config),
            ),
        ):
            status, detail = _omnigent_live_config_evidence(config)

        self.assertEqual(status, "warn")
        self.assertIn("--config", detail)
        self.assertIn("loaded policy generation/module/config identity", detail)
        self.assertIn("action/fail-closed enforcement is unverified", detail)

    def test_omnigent_live_config_evidence_fails_on_mismatch(self) -> None:
        managed = os.path.abspath("managed-omnigent-config.yaml")
        other = os.path.abspath("other-omnigent-config.yaml")
        with (
            patch(
                "defenseclaw.commands.cmd_doctor._omnigent_local_server_pid",
                return_value=(4242, "recorded live OmniGent server"),
            ),
            patch(
                "defenseclaw.commands.cmd_doctor._omnigent_process_argv",
                return_value=("omnigent.exe", "server", "--config", other),
            ),
        ):
            status, detail = _omnigent_live_config_evidence(managed)

        self.assertEqual(status, "fail")
        self.assertIn("not managed", detail)

    def test_omnigent_live_config_evidence_expands_user_path(self) -> None:
        managed = os.path.join(os.path.expanduser("~"), "managed-omnigent-config.yaml")
        with (
            patch(
                "defenseclaw.commands.cmd_doctor._omnigent_local_server_pid",
                return_value=(4242, "recorded live OmniGent server"),
            ),
            patch(
                "defenseclaw.commands.cmd_doctor._omnigent_process_argv",
                return_value=("omnigent.exe", "server", "--config", "~/managed-omnigent-config.yaml"),
            ),
        ):
            status, detail = _omnigent_live_config_evidence(managed)

        self.assertEqual(status, "warn")
        self.assertIn("--config", detail)
        self.assertIn("pending reload/restart", detail)

    def test_omnigent_live_config_evidence_warns_without_source(self) -> None:
        managed = os.path.abspath("managed-omnigent-config.yaml")
        with (
            patch(
                "defenseclaw.commands.cmd_doctor._omnigent_local_server_pid",
                return_value=(4242, "recorded live OmniGent server"),
            ),
            patch(
                "defenseclaw.commands.cmd_doctor._omnigent_process_argv",
                return_value=("omnigent.exe", "server", "--host", "127.0.0.1"),
            ),
            patch("defenseclaw.commands.cmd_doctor._read_process_env_var", return_value=""),
        ):
            status, detail = _omnigent_live_config_evidence(managed)

        self.assertEqual(status, "warn")
        self.assertIn("empty/default configuration", detail)

    def test_omnigent_live_config_evidence_warns_when_command_line_is_unreadable(self) -> None:
        managed = os.path.abspath("managed-omnigent-config.yaml")
        with (
            patch(
                "defenseclaw.commands.cmd_doctor._omnigent_local_server_pid",
                return_value=(4242, "recorded live OmniGent server"),
            ),
            patch(
                "defenseclaw.commands.cmd_doctor._omnigent_process_argv",
                return_value=None,
            ),
        ):
            status, detail = _omnigent_live_config_evidence(managed)

        self.assertEqual(status, "warn")
        self.assertIn("command line is unreadable", detail)
        self.assertIn("effective policy config is unverified", detail)

    def test_omnigent_runtime_readiness_preserves_stale_record_warning(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = os.path.join(tmp, "config.yaml")
            with open(config, "w", encoding="utf-8") as fh:
                fh.write("policies: {}\n")
            cfg = MagicMock()
            with (
                patch(
                    "defenseclaw.commands.cmd_doctor._omnigent_lock_locations",
                    return_value=({"hook_config_paths": [config]}, ""),
                ),
                patch(
                    "defenseclaw.commands.cmd_doctor._omnigent_local_server_pid",
                    return_value=(0, "OmniGent server record is stale: synthetic-local_server.pid"),
                ),
            ):
                status, detail = _omnigent_runtime_readiness(cfg)

        self.assertEqual(status, "warn")
        self.assertIn("server record is stale", detail)
        self.assertIn("effective policy config is unverified", detail)

    def test_omnigent_live_config_evidence_accepts_process_environment(self) -> None:
        managed = os.path.abspath("managed-omnigent-config.yaml")
        with (
            patch(
                "defenseclaw.commands.cmd_doctor._omnigent_local_server_pid",
                return_value=(4242, "recorded live OmniGent server"),
            ),
            patch(
                "defenseclaw.commands.cmd_doctor._omnigent_process_argv",
                return_value=("python", "-m", "omnigent", "server"),
            ),
            patch("defenseclaw.commands.cmd_doctor.sys.platform", "linux"),
            patch("defenseclaw.commands.cmd_doctor._read_process_env_var", return_value=managed),
        ):
            status, detail = _omnigent_live_config_evidence(managed)

        self.assertEqual(status, "warn")
        self.assertIn("OMNIGENT_CONFIG", detail)
        self.assertIn("loaded policy generation/module/config identity", detail)

    def test_omnigent_live_config_evidence_warns_for_relative_source(self) -> None:
        managed = os.path.abspath("managed-omnigent-config.yaml")
        with (
            patch(
                "defenseclaw.commands.cmd_doctor._omnigent_local_server_pid",
                return_value=(4242, "recorded live OmniGent server"),
            ),
            patch(
                "defenseclaw.commands.cmd_doctor._omnigent_process_argv",
                return_value=("omnigent.exe", "server", "--config", "relative-config.yaml"),
            ),
        ):
            status, detail = _omnigent_live_config_evidence(managed)

        self.assertEqual(status, "warn")
        self.assertIn("working directory", detail)

    def test_omnigent_policy_module_tamper_fails_digest_check(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = os.path.join(tmp, "config.yaml")
            module = os.path.join(tmp, "defenseclaw_omnigent_policy.py")
            pth = os.path.join(tmp, "defenseclaw_omnigent.pth")
            with open(config, "w", encoding="utf-8") as fh:
                fh.write("policy_modules: [defenseclaw_omnigent_policy]\npolicies: {defenseclaw_guardrail: {}}\n")
            with open(module, "w", encoding="utf-8") as fh:
                fh.write("def defenseclaw_policy(event): return {'result': 'ALLOW'}\nPOLICY_REGISTRY = []\n")
            with open(pth, "w", encoding="utf-8") as fh:
                fh.write(tmp + "\n")
            for logical, path in (("config", config), ("module", module), ("pth", pth)):
                self._write_omnigent_backup(tmp, logical, path)
            with open(module, "a", encoding="utf-8") as fh:
                fh.write("# tampered\n")
            cfg = MagicMock()
            cfg.data_dir = tmp
            with open(os.path.join(tmp, "hook_contract_lock.json"), "w", encoding="utf-8") as fh:
                json.dump(
                    {"connectors": {"omnigent": {"locations": {
                        "hook_config_paths": [config],
                        "hook_script_paths": [module, pth],
                    }}}},
                    fh,
                )
            r = _DoctorResult()
            _check_omnigent_policy_health(cfg, r)

        self.assertEqual(r.checks[-1]["status"], "fail")
        self.assertIn("module drift detected", r.checks[-1]["detail"])

    def test_omnigent_malformed_utf8_metadata_fails_cleanly(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "config.yaml"), "w", encoding="utf-8") as fh:
                fh.write("policy_modules: [defenseclaw_omnigent_policy]\npolicies: {defenseclaw_guardrail: {}}\n")
            with open(os.path.join(tmp, "hook_contract_lock.json"), "wb") as fh:
                fh.write(b"\xff\xfe\x00")
            backup_dir = os.path.join(tmp, "connector_backups", "omnigent")
            os.makedirs(backup_dir)
            with open(os.path.join(backup_dir, "module.json"), "wb") as fh:
                fh.write(b"\xff\xfe\x00")
            cfg = MagicMock()
            cfg.data_dir = tmp
            with patch.dict(os.environ, {"OMNIGENT_CONFIG_HOME": tmp}):
                r = _DoctorResult()
                _check_omnigent_policy_health(cfg, r)

        self.assertEqual(r.checks[-1]["status"], "fail")
        self.assertIn("policy module and .pth", r.checks[-1]["detail"])

    def test_omnigent_malformed_utf8_import_shim_fails_cleanly(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = os.path.join(tmp, "config.yaml")
            module = os.path.join(tmp, "defenseclaw_omnigent_policy.py")
            pth = os.path.join(tmp, "defenseclaw_omnigent.pth")
            with open(config, "w", encoding="utf-8") as fh:
                fh.write("policy_modules: [defenseclaw_omnigent_policy]\npolicies: {defenseclaw_guardrail: {}}\n")
            with open(module, "w", encoding="utf-8") as fh:
                fh.write("defenseclaw_policy = None\nPOLICY_REGISTRY = []\n")
            with open(pth, "wb") as fh:
                fh.write(b"\xff\xfe\x00")
            cfg = MagicMock()
            cfg.data_dir = tmp
            with open(os.path.join(tmp, "hook_contract_lock.json"), "w", encoding="utf-8") as fh:
                json.dump(
                    {
                        "connectors": {
                            "omnigent": {
                                "locations": {
                                    "hook_config_paths": [config],
                                    "hook_script_paths": [module, pth],
                                }
                            }
                        }
                    },
                    fh,
                )
            r = _DoctorResult()
            _check_omnigent_policy_health(cfg, r)

        self.assertEqual(r.checks[-1]["status"], "fail")
        self.assertIn(".pth import shim", r.checks[-1]["detail"])

    def test_dispatch_routes_omnigent_policy_health(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cfg = MagicMock()
            cfg.data_dir = tmp
            with patch.dict(os.environ, {"OMNIGENT_CONFIG_HOME": tmp}):
                r = _DoctorResult()
                _check_connector_hooks(cfg, "omnigent", r)

        self.assertTrue(r.checks)
        self.assertEqual(r.checks[-1]["label"], "OmniGent policy")

    def test_dispatch_routes_all_five_connectors(self) -> None:
        """``_check_connector_hooks`` must dispatch each generic connector
        unhandled connectors to the generic hook-health row."""
        for connector, label in (
            ("hermes", "Hermes hooks (fail-open)"),
            ("cursor", "Cursor hooks"),
            ("windsurf", "Legacy Cascade hooks"),
            ("geminicli", "Gemini CLI hooks"),
            ("opencode", "OpenCode hooks"),
        ):
            with tempfile.TemporaryDirectory() as tmp:
                cfg = self._cfg(tmp, connector, [os.path.join(tmp, "missing")])
                r = _DoctorResult()
                _check_connector_hooks(cfg, connector, r)
            self.assertTrue(r.checks, msg=connector)
            self.assertIn(label, {check["label"] for check in r.checks}, msg=connector)


class TestConnectorEnabled(unittest.TestCase):
    """N1 — doctor must not render an operator-disabled connector as active.

    ``active_connectors()`` returns every key in ``guardrail.connectors``
    regardless of its ``enabled`` flag, so doctor's inventory/Services loops
    gate on :func:`_connector_enabled` (which mirrors ``cmd_status._is_enabled``
    over ``GuardrailConfig.effective_enabled``).
    """

    def _cfg_with(self, connectors):
        from defenseclaw import config

        cfg = config.default_config()
        cfg.guardrail.connectors = connectors
        return cfg

    def test_explicit_disabled_returns_false(self):
        from defenseclaw.config import PerConnectorGuardrailConfig

        cfg = self._cfg_with(
            {
                "codex": PerConnectorGuardrailConfig(enabled=False),
                "hermes": PerConnectorGuardrailConfig(enabled=True),
                "cursor": PerConnectorGuardrailConfig(),  # unset → inherit → True
            }
        )
        self.assertFalse(_connector_enabled(cfg, "codex"))
        self.assertTrue(_connector_enabled(cfg, "hermes"))
        self.assertTrue(_connector_enabled(cfg, "cursor"))

    def test_premise_active_connectors_still_lists_disabled(self):
        # The bug N1 fixes: active_connectors() does NOT drop a disabled
        # connector, so doctor would otherwise inventory it as active.
        from defenseclaw.config import PerConnectorGuardrailConfig

        cfg = self._cfg_with(
            {
                "codex": PerConnectorGuardrailConfig(enabled=False),
                "hermes": PerConnectorGuardrailConfig(enabled=True),
            }
        )
        self.assertIn("codex", cfg.active_connectors())
        self.assertIn("codex", _doctor_active_connectors(cfg))

    def test_missing_guardrail_defaults_true(self):
        cfg = MagicMock()
        cfg.guardrail = None
        self.assertTrue(_connector_enabled(cfg, "codex"))


class TestDetectionStrategyRow(unittest.TestCase):
    """N3 — read-only per-connector detection-strategy / judge-gating row."""

    def _cfg(self, *, strategy="regex_judge", judge_enabled=False, hook_connectors=None):
        cfg = MagicMock()
        cfg.skill_dirs.return_value = []
        cfg.plugin_dirs.return_value = []
        cfg.mcp_servers.return_value = []
        cfg.data_dir = ""  # keep the rule-pack row a benign skip
        cfg.guardrail.effective_mode.return_value = "observe"
        cfg.guardrail.effective_rule_pack_dir.return_value = ""
        cfg.guardrail.detection_strategy = strategy
        cfg.guardrail.judge.enabled = judge_enabled
        cfg.guardrail.judge.hook_connectors = hook_connectors or []
        return cfg

    def _detection_row(self, cfg, connector):
        r = _DoctorResult()
        _check_connector_inventory(cfg, connector, r)
        return next(c for c in r.checks if c["label"] == "Detection")

    def test_strategy_surfaced(self):
        row = self._detection_row(self._cfg(strategy="judge_first"), "codex")
        self.assertIn("strategy=judge_first", row["detail"])

    def test_judge_disabled_noted(self):
        row = self._detection_row(self._cfg(judge_enabled=False), "codex")
        self.assertIn("judge disabled", row["detail"])

    def test_hook_connector_not_gated(self):
        # judge enabled but this hook connector is NOT in hook_connectors →
        # surfaces root #4: the judge won't actually fire for it.
        row = self._detection_row(self._cfg(judge_enabled=True, hook_connectors=["hermes"]), "codex")
        self.assertIn("NOT gated", row["detail"])

    def test_hook_connector_gated_explicit(self):
        row = self._detection_row(self._cfg(judge_enabled=True, hook_connectors=["codex"]), "codex")
        self.assertIn("judge active (hook lane)", row["detail"])

    def test_hook_connector_gated_wildcard(self):
        row = self._detection_row(self._cfg(judge_enabled=True, hook_connectors=["*"]), "codex")
        self.assertIn("judge active (hook lane)", row["detail"])

    def test_proxy_connector_uses_proxy_lane(self):
        # openclaw is a proxy connector: the judge runs in the proxy lane
        # whenever it's enabled, regardless of hook_connectors.
        row = self._detection_row(self._cfg(judge_enabled=True, hook_connectors=[]), "openclaw")
        self.assertIn("judge active (proxy lane)", row["detail"])


class TestPluginRegistryRequiredCheck(unittest.TestCase):
    """OTHER-5 (doctor half) — surface + clear a dead-end
    ``asset_policy.plugin.registry_required=true``."""

    def _cfg(self, *, enabled=True, global_required=False, connector_required=None):
        from defenseclaw import config
        from defenseclaw.config import (
            PerConnectorAssetPolicy,
            PerConnectorAssetTypePolicy,
        )

        cfg = config.default_config()
        cfg.asset_policy.enabled = enabled
        cfg.asset_policy.plugin.registry_required = global_required
        if connector_required is not None:
            cfg.asset_policy.connectors = {
                "codex": PerConnectorAssetPolicy(
                    plugin=PerConnectorAssetTypePolicy(registry_required=connector_required)
                )
            }
        return cfg

    def test_clean_config_passes(self):
        r = _DoctorResult()
        _check_plugin_registry_required(self._cfg(global_required=False), r)
        row = next(c for c in r.checks if c["label"] == "Plugin registry policy")
        self.assertEqual(row["status"], "pass")

    def test_global_required_warns(self):
        r = _DoctorResult()
        _check_plugin_registry_required(self._cfg(enabled=True, global_required=True), r)
        row = next(c for c in r.checks if c["label"] == "Plugin registry policy")
        self.assertEqual(row["status"], "warn")
        self.assertIn("global", row["detail"])
        self.assertIn("blocks ALL plugins", row["detail"])

    def test_per_connector_required_warns(self):
        r = _DoctorResult()
        _check_plugin_registry_required(self._cfg(global_required=False, connector_required=True), r)
        row = next(c for c in r.checks if c["label"] == "Plugin registry policy")
        self.assertEqual(row["status"], "warn")
        self.assertIn("connector:codex", row["detail"])

    def test_disabled_enforcement_softer_wording(self):
        r = _DoctorResult()
        _check_plugin_registry_required(self._cfg(enabled=False, global_required=True), r)
        row = next(c for c in r.checks if c["label"] == "Plugin registry policy")
        self.assertEqual(row["status"], "warn")
        self.assertIn("once asset-policy enforcement is enabled", row["detail"])

    def test_offenders_lists_global_and_connector(self):
        cfg = self._cfg(global_required=True, connector_required=True)
        offenders = _plugin_registry_required_offenders(cfg)
        self.assertIn("global", offenders)
        self.assertIn("connector:codex", offenders)

    def test_per_connector_none_is_not_an_offender(self):
        # None = inherit; only an explicit True is a dead-end offender.
        cfg = self._cfg(global_required=False, connector_required=None)
        self.assertEqual(_plugin_registry_required_offenders(cfg), [])


class TestPluginRegistryRequiredFixer(unittest.TestCase):
    """OTHER-5 — ``doctor --fix`` clears the dead-end flag."""

    def _cfg(self, *, global_required=False, connector_required=None):
        from defenseclaw import config
        from defenseclaw.config import (
            PerConnectorAssetPolicy,
            PerConnectorAssetTypePolicy,
        )

        cfg = config.default_config()
        cfg.asset_policy.enabled = True
        cfg.asset_policy.plugin.registry_required = global_required
        if connector_required is not None:
            cfg.asset_policy.connectors = {
                "codex": PerConnectorAssetPolicy(
                    plugin=PerConnectorAssetTypePolicy(registry_required=connector_required)
                )
            }
        cfg.save = MagicMock()
        return cfg

    def test_nothing_set_skips(self):
        cfg = self._cfg(global_required=False)
        tag, _ = _fix_plugin_registry_required(cfg, assume_yes=True)
        self.assertEqual(tag, "skip")
        cfg.save.assert_not_called()

    def test_clears_global(self):
        cfg = self._cfg(global_required=True)
        with patch("defenseclaw.commands.cmd_doctor._doctor_config_present", return_value=True):
            tag, detail = _fix_plugin_registry_required(cfg, assume_yes=True)
        self.assertEqual(tag, "pass")
        self.assertFalse(cfg.asset_policy.plugin.registry_required)
        cfg.save.assert_called_once()
        self.assertIn("global", detail)

    def test_clears_per_connector_to_none(self):
        cfg = self._cfg(global_required=False, connector_required=True)
        with patch("defenseclaw.commands.cmd_doctor._doctor_config_present", return_value=True):
            tag, _ = _fix_plugin_registry_required(cfg, assume_yes=True)
        self.assertEqual(tag, "pass")
        # Tri-state field reset to None (inherit), not False.
        self.assertIsNone(cfg.asset_policy.connectors["codex"].plugin.registry_required)
        cfg.save.assert_called_once()

    def test_declined_does_not_save(self):
        cfg = self._cfg(global_required=True)
        with patch("defenseclaw.commands.cmd_doctor.click.confirm", return_value=False):
            tag, _ = _fix_plugin_registry_required(cfg, assume_yes=False)
        self.assertEqual(tag, "skip")
        cfg.save.assert_not_called()
        # Flag is untouched on decline.
        self.assertTrue(cfg.asset_policy.plugin.registry_required)

    def test_missing_config_refuses_to_create_it(self):
        cfg = self._cfg(global_required=True)
        with patch("defenseclaw.commands.cmd_doctor._doctor_config_present", return_value=False):
            tag, detail = _fix_plugin_registry_required(cfg, assume_yes=True)
        self.assertEqual(tag, "skip")
        self.assertIn("config.yaml is missing", detail)
        self.assertTrue(cfg.asset_policy.plugin.registry_required)
        cfg.save.assert_not_called()


if __name__ == "__main__":
    unittest.main()
