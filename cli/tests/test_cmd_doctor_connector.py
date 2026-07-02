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

import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.commands.cmd_doctor import (
    _active_connector,
    _check_connector_hooks,
    _check_connector_inventory,
    _check_cursor_configured_runtime,
    _check_hook_contract_lock,
    _check_hook_health,
    _check_omnigent_policy_health,
    _check_plugin_registry_required,
    _check_scan_coverage,
    _connector_enabled,
    _doctor_active_connectors,
    _doctor_label_suffix,
    _DoctorResult,
    _fix_plugin_registry_required,
    _plugin_registry_required_offenders,
    _probe_cursor_windows_runtime,
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
        cfg.guardrail.effective_rule_pack_dir.return_value = ""
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
        cfg.guardrail.effective_rule_pack_dir.return_value = ""
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
        self.assertEqual(labels["Mode"]["detail"], "action")
        self.assertIn("Rule pack", labels)


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
        data_dir = os.path.join(tmp, "data")
        os.makedirs(data_dir, exist_ok=True)
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
                    "$startInfo = New-Object System.Diagnostics.ProcessStartInfo\n"
                    "$startInfo.RedirectStandardOutput = $true\n"
                    "$process.WaitForExit()\n"
                    "# defenseclaw-hook.exe hook --connector cursor --input-file $payloadPath\n"
                )
            command = "& '" + runtime.replace("'", "''") + "'"
        hooks_path = os.path.join(tmp, "hooks.json")
        with open(hooks_path, "w", encoding="utf-8") as fh:
            json.dump(
                {
                    "version": 1,
                    "hooks": {
                        "beforeSubmitPrompt": [
                            {
                                "command": command,
                                "failClosed": fail_closed,
                            }
                        ]
                    },
                },
                fh,
            )
        cfg = MagicMock()
        cfg.data_dir = data_dir
        cfg.guardrail.effective_mode.return_value = mode
        cfg.guardrail.effective_hook_fail_mode.return_value = "closed" if fail_closed else "open"
        with open(os.path.join(data_dir, "hook_contract_lock.json"), "w", encoding="utf-8") as fh:
            json.dump(
                {
                    "connectors": {
                        "cursor": {
                            "locations": {
                                "hook_script_paths": [runtime],
                                "hook_config_paths": [hooks_path],
                            }
                        }
                    }
                },
                fh,
            )
        return cfg, hooks_path, runtime

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
        self.assertNotIn("inspect-tool.sh", r.checks[-1]["detail"])

    def test_cursor_doctor_rejects_unmanaged_windows_adapter(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cfg, hooks_path, runtime = self._cursor_runtime_case(
                tmp,
                mode="observe",
                fail_closed=False,
            )
            managed_runtime = os.path.join(tmp, "data", "hooks", "cursor-hook.ps1")
            os.makedirs(os.path.dirname(managed_runtime), exist_ok=True)
            with open(managed_runtime, "w", encoding="utf-8") as fh:
                fh.write("# managed adapter placeholder\n")
            with open(os.path.join(cfg.data_dir, "hook_contract_lock.json"), "w", encoding="utf-8") as fh:
                json.dump(
                    {
                        "connectors": {
                            "cursor": {
                                "locations": {
                                    "hook_script_paths": [managed_runtime],
                                    "hook_config_paths": [hooks_path],
                                }
                            }
                        }
                    },
                    fh,
                )
            r = _DoctorResult()
            with patch("defenseclaw.commands.cmd_doctor._probe_cursor_windows_runtime") as probe:
                _check_cursor_configured_runtime(
                    cfg,
                    hooks_path,
                    "Cursor hooks",
                    r,
                    platform_name="nt",
                    probe_runtime=True,
                )

        self.assertEqual(r.checks[-1]["status"], "fail")
        self.assertIn("outside the managed DefenseClaw hook path", r.checks[-1]["detail"])
        self.assertIn(runtime, r.checks[-1]["detail"])
        probe.assert_not_called()

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
        self.assertIn("expected false", r.checks[-1]["detail"])

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

    @patch("defenseclaw.commands.cmd_doctor._http_probe")
    @patch("defenseclaw.commands.cmd_doctor.subprocess.run")
    def test_cursor_windows_runtime_probe_requires_json_and_counter_advance(
        self,
        run_mock,
        http_probe_mock,
    ) -> None:
        before = json.dumps(
            {"connectors": [{"name": "cursor", "requests": 4, "errors": 0}]}
        )
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
            stdout=b'{"continue":true}',
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
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand"],
        )
        self.assertFalse(run_mock.call_args.kwargs.get("shell", False))

    @patch("defenseclaw.commands.cmd_doctor._http_probe")
    @patch("defenseclaw.commands.cmd_doctor.subprocess.run")
    def test_cursor_windows_runtime_probe_rejects_fail_open_without_delivery(
        self,
        run_mock,
        http_probe_mock,
    ) -> None:
        health = json.dumps(
            {"connectors": [{"name": "cursor", "requests": 4, "errors": 0}]}
        )
        http_probe_mock.side_effect = [(200, health), (200, health)]
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
        self.assertIn("did not advance", detail)

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

    def test_known_contract_passes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
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
                                },
                            }
                        }
                    },
                    fh,
                )

            r = _DoctorResult()
            _check_hook_contract_lock(self._cfg(tmp), "codex", r)
            check = r.checks[-1]
            self.assertEqual(check["status"], "pass")
            self.assertIn("codex-hooks-v1", check["detail"])
            self.assertIn("0.30.0", check["detail"])
            self.assertIn("workspace=/tmp/repo", check["detail"])
            self.assertIn("hook_path=/home/test/.codex/config.toml", check["detail"])

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
            _check_hook_contract_lock(self._cfg(tmp), "claudecode", r)
            check = r.checks[-1]
            self.assertEqual(check["status"], "fail")
            self.assertIn("drift", check["detail"])


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
        plugin_row = next(
            c for c in r.checks if c["label"] == "Scanner coverage (plugin)"
        )
        for cat in _scan_ui.categories_for("plugin"):
            self.assertIn(cat, plugin_row["detail"])


class TestConnectorInventoryRulePack(unittest.TestCase):
    """The inventory block surfaces each connector's effective rule pack,
    warning when the resolved directory is missing/empty on disk.

    D9: when no explicit ``rule_pack_dir`` is set, the gateway resolves the
    built-in default to ``<data_dir>/policies/guardrail/default`` and loads
    packs from there — doctor must validate THAT path, not emit a benign skip.
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

    def test_rule_pack_dir_missing_warns(self):
        r = _DoctorResult()
        _check_connector_inventory(self._cfg(rule_pack_dir="/nonexistent/rule/pack/dir"), "cursor", r)
        rp = next(c for c in r.checks if c["label"] == "Rule pack")
        self.assertEqual(rp["status"], "warn")
        self.assertIn("/nonexistent/rule/pack/dir", rp["detail"])

    def test_rule_pack_dir_present_passes(self):
        r = _DoctorResult()
        _check_connector_inventory(self._cfg(rule_pack_dir=os.getcwd()), "cursor", r)
        rp = next(c for c in r.checks if c["label"] == "Rule pack")
        self.assertEqual(rp["status"], "pass")

    def test_rule_pack_dir_empty_validates_resolved_default_missing(self):
        # D9: empty rule_pack_dir → resolve <data_dir>/policies/guardrail/default;
        # when it's absent, WARN (enforcement would run with no rule packs)
        # rather than the old benign skip.
        with tempfile.TemporaryDirectory() as data_dir:
            r = _DoctorResult()
            _check_connector_inventory(self._cfg(rule_pack_dir="", data_dir=data_dir), "codex", r)
            rp = next(c for c in r.checks if c["label"] == "Rule pack")
            self.assertEqual(rp["status"], "warn")
            self.assertIn("built-in default", rp["detail"])
            self.assertIn(
                os.path.join(data_dir, "policies", "guardrail", "default"),
                rp["detail"],
            )

    def test_rule_pack_dir_empty_validates_resolved_default_empty(self):
        # D9: the default dir exists but is empty → still a degradation (zero
        # rule packs loaded), so WARN.
        with tempfile.TemporaryDirectory() as data_dir:
            os.makedirs(os.path.join(data_dir, "policies", "guardrail", "default"))
            r = _DoctorResult()
            _check_connector_inventory(self._cfg(rule_pack_dir="", data_dir=data_dir), "codex", r)
            rp = next(c for c in r.checks if c["label"] == "Rule pack")
            self.assertEqual(rp["status"], "warn")
            self.assertIn("empty", rp["detail"])

    def test_rule_pack_dir_empty_validates_resolved_default_present(self):
        # D9: the resolved default dir exists and is seeded → PASS.
        with tempfile.TemporaryDirectory() as data_dir:
            default_dir = os.path.join(data_dir, "policies", "guardrail", "default")
            os.makedirs(default_dir)
            with open(os.path.join(default_dir, "injection.yaml"), "w") as fh:
                fh.write("rules: []\n")
            r = _DoctorResult()
            _check_connector_inventory(self._cfg(rule_pack_dir="", data_dir=data_dir), "codex", r)
            rp = next(c for c in r.checks if c["label"] == "Rule pack")
            self.assertEqual(rp["status"], "pass")
            self.assertIn("built-in default", rp["detail"])


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

    def _cfg(self, data_dir: str, connector: str, paths: list[str]) -> MagicMock:
        cfg = MagicMock()
        cfg.data_dir = data_dir
        with open(os.path.join(data_dir, "hook_contract_lock.json"), "w", encoding="utf-8") as fh:
            json.dump(
                {"connectors": {connector: {"locations": {"hook_config_paths": paths}}}},
                fh,
            )
        return cfg

    def test_lock_path_with_marker_passes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            hook = os.path.join(tmp, "config.yaml")
            with open(hook, "w", encoding="utf-8") as fh:
                fh.write("hooks:\n  - command: /x/hooks/hermes-hook.sh\n")
            r = _DoctorResult()
            _check_hook_health(self._cfg(tmp, "hermes", [hook]), "hermes", r)
        self.assertEqual(r.checks[-1]["status"], "pass")
        self.assertEqual(r.checks[-1]["label"], "Hermes hooks")
        self.assertIn(hook, r.checks[-1]["detail"])

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
                self._cfg(tmp, "hermes", [os.path.join(tmp, "nope.yaml")]), "hermes", r,
            )
        self.assertEqual(r.checks[-1]["status"], "fail")
        self.assertIn("not found", r.checks[-1]["detail"])

    def test_opencode_flat_js_plugin_passes(self) -> None:
        """opencode's hook is a flat ``.js`` file (not JSON) keyed on the
        bare ``defenseclaw`` marker — the format-agnostic check must accept it."""
        with tempfile.TemporaryDirectory() as tmp:
            hook = os.path.join(tmp, "defenseclaw.js")
            with open(hook, "w", encoding="utf-8") as fh:
                fh.write("export const plugin = () => fetch('http://127.0.0.1:4000');  // defenseclaw bridge\n")
            r = _DoctorResult()
            _check_hook_health(self._cfg(tmp, "opencode", [hook]), "opencode", r)
        self.assertEqual(r.checks[-1]["status"], "pass")
        self.assertEqual(r.checks[-1]["label"], "OpenCode hooks")

    def test_unknown_connector_is_noop(self) -> None:
        r = _DoctorResult()
        _check_hook_health(MagicMock(), "totallymadeupclaw", r)
        self.assertEqual(r.checks, [])

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
        self.assertEqual(r.checks[-1]["status"], "pass")

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
                    {"connectors": {"omnigent": {"locations": {
                        "hook_config_paths": [config],
                        "hook_script_paths": [module],
                    }}}},
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
                    {"connectors": {"omnigent": {"locations": {
                        "hook_config_paths": [config],
                        "hook_script_paths": [module, pth],
                    }}}},
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
            for logical, path in (("module", module), ("pth", pth)):
                with open(os.path.join(backup_dir, f"{logical}.json"), "w", encoding="utf-8") as fh:
                    json.dump(
                        {"connector": "omnigent", "logical_name": logical, "path": path},
                        fh,
                    )
            cfg = MagicMock()
            cfg.data_dir = tmp
            with patch.dict(os.environ, {"OMNIGENT_CONFIG_HOME": config_home}):
                r = _DoctorResult()
                _check_omnigent_policy_health(cfg, r)

        self.assertEqual(r.checks[-1]["status"], "pass")

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
                    {"connectors": {"omnigent": {"locations": {
                        "hook_config_paths": [config],
                        "hook_script_paths": [module, pth],
                    }}}},
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
            ("hermes", "Hermes hooks"),
            ("cursor", "Cursor hooks"),
            ("windsurf", "Windsurf hooks"),
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
        row = self._detection_row(
            self._cfg(judge_enabled=True, hook_connectors=["hermes"]), "codex"
        )
        self.assertIn("NOT gated", row["detail"])

    def test_hook_connector_gated_explicit(self):
        row = self._detection_row(
            self._cfg(judge_enabled=True, hook_connectors=["codex"]), "codex"
        )
        self.assertIn("judge active (hook lane)", row["detail"])

    def test_hook_connector_gated_wildcard(self):
        row = self._detection_row(
            self._cfg(judge_enabled=True, hook_connectors=["*"]), "codex"
        )
        self.assertIn("judge active (hook lane)", row["detail"])

    def test_proxy_connector_uses_proxy_lane(self):
        # openclaw is a proxy connector: the judge runs in the proxy lane
        # whenever it's enabled, regardless of hook_connectors.
        row = self._detection_row(
            self._cfg(judge_enabled=True, hook_connectors=[]), "openclaw"
        )
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
        _check_plugin_registry_required(
            self._cfg(global_required=False, connector_required=True), r
        )
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
        tag, detail = _fix_plugin_registry_required(cfg, assume_yes=True)
        self.assertEqual(tag, "pass")
        self.assertFalse(cfg.asset_policy.plugin.registry_required)
        cfg.save.assert_called_once()
        self.assertIn("global", detail)

    def test_clears_per_connector_to_none(self):
        cfg = self._cfg(global_required=False, connector_required=True)
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


if __name__ == "__main__":
    unittest.main()
