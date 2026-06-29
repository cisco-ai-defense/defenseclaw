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

import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.commands.cmd_doctor import (
    _ANTHROPIC_DEFAULT_PROBE_MODEL,
    _anthropic_probe_model,
    _bedrock_region,
    _check_antigravity_hooks,
    _check_cisco_ai_defense,
    _check_connector_residue,
    _check_copilot_hooks,
    _check_custom_provider_overlay,
    _check_guardrail_proxy,
    _check_hilt_support,
    _check_llm_api_key,
    _check_openhands_hooks,
    _check_sidecar,
    _DoctorResult,
    _probe_splunk_hec,
    _verify_bedrock,
)
from defenseclaw.config import (
    CiscoAIDefenseConfig,
    Config,
    GatewayConfig,
    GuardrailConfig,
    LLMConfig,
    OpenShellConfig,
    PerConnectorGuardrailConfig,
)


class DoctorMultiConnectorInventoryTests(unittest.TestCase):
    """D6: the connector inventory check scopes paths per connector."""

    @patch("defenseclaw.commands.cmd_doctor._workspace_dir", return_value="")
    def test_inventory_scopes_dirs_to_connector(self, _mock_ws):
        from defenseclaw.commands.cmd_doctor import (
            _check_connector_inventory,
            _DoctorResult,
        )

        seen: dict[str, list] = {"skill": [], "plugin": [], "mcp": []}
        cfg = SimpleNamespace(
            skill_dirs=lambda connector=None: (seen["skill"].append(connector) or []),
            plugin_dirs=lambda connector=None: (seen["plugin"].append(connector) or []),
            mcp_servers=lambda connector=None: (seen["mcp"].append(connector) or []),
        )
        r = _DoctorResult()

        _check_connector_inventory(cfg, "codex", r)

        self.assertEqual(seen["skill"], ["codex"])
        self.assertEqual(seen["plugin"], ["codex"])
        self.assertEqual(seen["mcp"], ["codex"])


class DoctorGuardrailTests(unittest.TestCase):
    @patch("defenseclaw.commands.cmd_doctor._http_probe", return_value=(200, "ok"))
    def test_empty_guardrail_model_is_warning_not_failure(self, _mock_probe):
        cfg = Config(
            data_dir="/tmp/defenseclaw",
            audit_db="/tmp/defenseclaw/audit.db",
            quarantine_dir="/tmp/defenseclaw/quarantine",
            plugin_dir="/tmp/defenseclaw/plugins",
            policy_dir="/tmp/defenseclaw/policies",
            guardrail=GuardrailConfig(enabled=True, model="", port=4000),
            gateway=GatewayConfig(),
            openshell=OpenShellConfig(),
        )
        result = _DoctorResult()

        _check_guardrail_proxy(cfg, result)

        self.assertEqual(result.failed, 0)
        self.assertEqual(result.warned, 1)
        self.assertEqual(result.passed, 1)
        warn_checks = [c for c in result.checks if c["status"] == "warn"]
        self.assertTrue(any("fetch-interceptor" in c["detail"] for c in warn_checks))

    @patch("defenseclaw.commands.cmd_doctor._http_probe")
    def test_sidecar_check_surfaces_disabled_summary(self, mock_probe):
        """When the sidecar publishes details.summary on a disabled
        subsystem (today: gateway standalone-mode short-circuit in
        runGatewayLoop), doctor must include that summary in its
        skip-row detail. The pre-fix generic message
        "disabled (reported by sidecar)" gave operators no way to
        tell apart "intentionally disabled" (codex+loopback) from
        "broken but the sidecar quietly gave up", which is what
        made the codex+standalone reconnect-spam regression so
        hard to diagnose.
        """
        import json as _json

        health_body = _json.dumps(
            {
                "gateway": {
                    "state": "disabled",
                    "details": {
                        "summary": "no OpenClaw fleet configured (standalone mode)",
                        "connector": "codex",
                        "host": "127.0.0.1",
                        "port": 18789,
                        "hint": "set gateway.host to a real OpenClaw upstream and restart",
                    },
                },
                "watcher": {"state": "running"},
                "guardrail": {"state": "running", "details": {"mode": "observe"}},
                "api": {"state": "running"},
            }
        )
        mock_probe.return_value = (200, health_body)

        cfg = Config(
            data_dir="/tmp/defenseclaw",
            audit_db="/tmp/defenseclaw/audit.db",
            quarantine_dir="/tmp/defenseclaw/quarantine",
            plugin_dir="/tmp/defenseclaw/plugins",
            policy_dir="/tmp/defenseclaw/policies",
            guardrail=GuardrailConfig(connector="codex"),
            gateway=GatewayConfig(),
            openshell=OpenShellConfig(),
        )
        cfg.claw.mode = "codex"
        result = _DoctorResult()

        _check_sidecar(cfg, result)

        gateway_rows = [c for c in result.checks if c.get("label", "").strip().endswith("gateway")]
        self.assertEqual(
            len(gateway_rows),
            1,
            f"expected exactly one gateway row, got {gateway_rows!r}",
        )
        row = gateway_rows[0]
        # Skip (not warn) — gateway has no on/off config knob, so
        # _subsystem_expected_enabled returns None and we fall to
        # the "skip" branch; the post-fix change appends the summary.
        self.assertEqual(row["status"], "skip")
        self.assertIn(
            "no OpenClaw fleet configured (standalone mode)",
            row["detail"],
            f"summary should be surfaced in detail; got: {row['detail']!r}",
        )

    @patch("defenseclaw.commands.cmd_doctor._http_probe")
    def test_sidecar_check_falls_back_to_generic_message_without_summary(self, mock_probe):
        """An older sidecar build (or a different subsystem with no
        publishable summary) must still produce the generic "disabled
        (reported by sidecar)" message — the post-fix code only adds
        the summary when one is present and is otherwise unchanged.
        """
        import json as _json

        health_body = _json.dumps(
            {
                "gateway": {"state": "disabled"},  # no details
                "watcher": {"state": "running"},
                "guardrail": {"state": "running"},
                "api": {"state": "running"},
            }
        )
        mock_probe.return_value = (200, health_body)

        cfg = Config(
            data_dir="/tmp/defenseclaw",
            audit_db="/tmp/defenseclaw/audit.db",
            quarantine_dir="/tmp/defenseclaw/quarantine",
            plugin_dir="/tmp/defenseclaw/plugins",
            policy_dir="/tmp/defenseclaw/policies",
            guardrail=GuardrailConfig(connector="codex"),
            gateway=GatewayConfig(),
            openshell=OpenShellConfig(),
        )
        cfg.claw.mode = "codex"
        result = _DoctorResult()
        _check_sidecar(cfg, result)
        gateway_rows = [c for c in result.checks if c.get("label", "").strip().endswith("gateway")]
        self.assertEqual(len(gateway_rows), 1)
        self.assertEqual(gateway_rows[0]["status"], "skip")
        self.assertEqual(
            gateway_rows[0]["detail"],
            "disabled (reported by sidecar)",
        )

    @patch("defenseclaw.commands.cmd_doctor._http_probe")
    def test_codex_observability_mode_skips_proxy_port_probe(self, mock_probe):
        cfg = Config(
            data_dir="/tmp/defenseclaw",
            audit_db="/tmp/defenseclaw/audit.db",
            quarantine_dir="/tmp/defenseclaw/quarantine",
            plugin_dir="/tmp/defenseclaw/plugins",
            policy_dir="/tmp/defenseclaw/policies",
            guardrail=GuardrailConfig(
                enabled=True,
                model="",
                port=4000,
                connector="codex",
            ),
            gateway=GatewayConfig(),
            openshell=OpenShellConfig(),
        )
        cfg.claw.mode = "codex"
        result = _DoctorResult()

        _check_guardrail_proxy(cfg, result)

        mock_probe.assert_not_called()
        self.assertEqual(result.failed, 0)
        self.assertEqual(result.warned, 0)
        self.assertEqual(result.passed, 1)
        self.assertIn("intentionally closed", result.checks[0]["detail"])

    @patch("defenseclaw.commands.cmd_doctor._http_probe")
    def test_hook_only_connector_skips_proxy_port_probe(self, mock_probe):
        cfg = Config(
            data_dir="/tmp/defenseclaw",
            audit_db="/tmp/defenseclaw/audit.db",
            quarantine_dir="/tmp/defenseclaw/quarantine",
            plugin_dir="/tmp/defenseclaw/plugins",
            policy_dir="/tmp/defenseclaw/policies",
            guardrail=GuardrailConfig(
                enabled=True,
                model="",
                port=4000,
                connector="geminicli",
            ),
            gateway=GatewayConfig(),
            openshell=OpenShellConfig(),
        )
        cfg.claw.mode = "geminicli"
        result = _DoctorResult()

        _check_guardrail_proxy(cfg, result)

        mock_probe.assert_not_called()
        self.assertEqual(result.failed, 0)
        self.assertEqual(result.warned, 0)
        self.assertEqual(result.passed, 1)
        # `_check_guardrail_proxy` now reports the mode alongside the
        # connector so an operator reading `doctor` can immediately
        # see whether the closed proxy port reflects an observe-mode
        # configuration (no enforcement) or an action-mode one
        # (enforcement runs through PreToolUse deny). The default
        # GuardrailConfig in this fixture leaves ``gc.mode`` at the
        # canonical ``"observe"`` default, so we expect the observe
        # variant of the message here.
        self.assertIn("hook-driven for geminicli", result.checks[0]["detail"])
        self.assertIn("mode=observe", result.checks[0]["detail"])
        self.assertIn("proxy port intentionally closed", result.checks[0]["detail"])

    @patch("defenseclaw.commands.cmd_doctor._http_probe")
    def test_hook_only_connector_in_action_mode_reports_pretooluse_enforcement(self, mock_probe):
        """Hook-enforced connector in action mode: the closed-port
        detail must surface ``mode=action via PreToolUse deny`` so an
        operator running `doctor` sees that enforcement IS happening
        — the proxy is closed *because* the hook bus has taken over,
        not because enforcement is off.

        Regression: an earlier wording said ``observability-only`` for
        every hook-enforced connector regardless of mode, which made
        action-mode Codex / Claude Code installations look passive.
        """
        from defenseclaw.commands.cmd_doctor import _check_guardrail_proxy

        cfg = Config(
            data_dir="/tmp/defenseclaw",
            audit_db="/tmp/defenseclaw/audit.db",
            quarantine_dir="/tmp/defenseclaw/quarantine",
            plugin_dir="/tmp/defenseclaw/plugins",
            policy_dir="/tmp/defenseclaw/policies",
            guardrail=GuardrailConfig(
                enabled=True,
                mode="action",
                model="",
                port=4000,
                connector="codex",
            ),
            gateway=GatewayConfig(),
            openshell=OpenShellConfig(),
        )
        cfg.claw.mode = "codex"
        result = _DoctorResult()

        _check_guardrail_proxy(cfg, result)

        # Action mode on a hook-enforced connector must NEVER probe
        # the proxy port — the listener doesn't bind in this topology.
        mock_probe.assert_not_called()
        self.assertEqual(result.failed, 0)
        self.assertEqual(result.warned, 0)
        self.assertEqual(result.passed, 1)
        detail = result.checks[0]["detail"]
        self.assertIn("hook-enforced for codex", detail)
        self.assertIn("mode=action via PreToolUse deny", detail)
        self.assertIn("proxy port intentionally closed", detail)

    @patch("defenseclaw.commands.cmd_doctor._http_probe")
    def test_omnigent_action_reports_policy_enforcement_without_proxy_probe(self, mock_probe):
        from defenseclaw.commands.cmd_doctor import _check_guardrail_proxy

        cfg = Config(
            data_dir="/tmp/defenseclaw",
            audit_db="/tmp/defenseclaw/audit.db",
            quarantine_dir="/tmp/defenseclaw/quarantine",
            plugin_dir="/tmp/defenseclaw/plugins",
            policy_dir="/tmp/defenseclaw/policies",
            guardrail=GuardrailConfig(
                enabled=True,
                mode="action",
                port=4000,
                connector="omnigent",
            ),
            gateway=GatewayConfig(),
            openshell=OpenShellConfig(),
        )
        cfg.claw.mode = "omnigent"
        result = _DoctorResult()

        _check_guardrail_proxy(cfg, result)

        mock_probe.assert_not_called()
        self.assertEqual(len(result.checks), 1, result.checks)
        self.assertEqual(result.checks[0]["status"], "pass")
        self.assertEqual(result.failed, 0, result.checks)
        self.assertEqual(result.warned, 0, result.checks)
        self.assertEqual(result.passed, 1, result.checks)
        detail = result.checks[0]["detail"]
        self.assertIn("policy-enforced for omnigent", detail)
        self.assertIn("mode=action via ALLOW/ASK/DENY", detail)

    def test_omnigent_without_judge_skips_llm_key_requirement(self):
        from defenseclaw.commands.cmd_doctor import _check_llm_api_key

        cfg = Config(
            data_dir="/tmp/defenseclaw",
            audit_db="/tmp/defenseclaw/audit.db",
            quarantine_dir="/tmp/defenseclaw/quarantine",
            plugin_dir="/tmp/defenseclaw/plugins",
            policy_dir="/tmp/defenseclaw/policies",
            guardrail=GuardrailConfig(
                enabled=True,
                mode="action",
                connector="omnigent",
            ),
            gateway=GatewayConfig(),
            openshell=OpenShellConfig(),
        )
        cfg.claw.mode = "omnigent"
        result = _DoctorResult()

        _check_llm_api_key(cfg, result)

        self.assertEqual(len(result.checks), 1, result.checks)
        self.assertEqual(result.failed, 0, result.checks)
        self.assertEqual(result.warned, 0, result.checks)
        self.assertEqual(result.checks[0]["status"], "skip")
        self.assertIn("not required by hook/policy enforcement", result.checks[0]["detail"])

    def test_hilt_disabled_is_pass(self):
        cfg = Config(
            data_dir="/tmp/defenseclaw",
            audit_db="/tmp/defenseclaw/audit.db",
            quarantine_dir="/tmp/defenseclaw/quarantine",
            plugin_dir="/tmp/defenseclaw/plugins",
            policy_dir="/tmp/defenseclaw/policies",
            guardrail=GuardrailConfig(enabled=True, mode="action", connector="openclaw"),
            gateway=GatewayConfig(),
            openshell=OpenShellConfig(),
        )
        result = _DoctorResult()
        _check_hilt_support(cfg, "openclaw", result)
        self.assertEqual(result.passed, 1)
        self.assertEqual(result.warned, 0)

    def test_hilt_codex_partial_support_warns(self):
        cfg = Config(
            data_dir="/tmp/defenseclaw",
            audit_db="/tmp/defenseclaw/audit.db",
            quarantine_dir="/tmp/defenseclaw/quarantine",
            plugin_dir="/tmp/defenseclaw/plugins",
            policy_dir="/tmp/defenseclaw/policies",
            guardrail=GuardrailConfig(enabled=True, mode="action", connector="codex"),
            gateway=GatewayConfig(),
            openshell=OpenShellConfig(),
        )
        cfg.guardrail.hilt.enabled = True
        result = _DoctorResult()
        _check_hilt_support(cfg, "codex", result)
        self.assertEqual(result.failed, 0)
        self.assertEqual(result.warned, 1)
        self.assertIn("no native ask surface", result.checks[0]["detail"])

    def test_hilt_observe_warning_names_connector_mode(self):
        cfg = Config(
            data_dir="/tmp/defenseclaw",
            audit_db="/tmp/defenseclaw/audit.db",
            quarantine_dir="/tmp/defenseclaw/quarantine",
            plugin_dir="/tmp/defenseclaw/plugins",
            policy_dir="/tmp/defenseclaw/policies",
            guardrail=GuardrailConfig(enabled=True, mode="observe", connector="hermes"),
            gateway=GatewayConfig(),
            openshell=OpenShellConfig(),
        )
        cfg.guardrail.hilt.enabled = True

        result = _DoctorResult()
        _check_hilt_support(cfg, "hermes", result)

        self.assertEqual(result.warned, 1)
        self.assertIn("hermes mode is observe", result.checks[0]["detail"])
        self.assertNotIn("guardrail.mode", result.checks[0]["detail"])

    def test_hilt_new_connector_support_matrix(self):
        cfg = Config(
            data_dir="/tmp/defenseclaw",
            audit_db="/tmp/defenseclaw/audit.db",
            quarantine_dir="/tmp/defenseclaw/quarantine",
            plugin_dir="/tmp/defenseclaw/plugins",
            policy_dir="/tmp/defenseclaw/policies",
            guardrail=GuardrailConfig(enabled=True, mode="action", connector="copilot"),
            gateway=GatewayConfig(),
            openshell=OpenShellConfig(),
        )
        cfg.guardrail.hilt.enabled = True

        result = _DoctorResult()
        _check_hilt_support(cfg, "copilot", result)
        self.assertEqual(result.passed, 1)
        self.assertIn("preToolUse ask supported", result.checks[0]["detail"])

        result = _DoctorResult()
        _check_hilt_support(cfg, "cursor", result)
        self.assertEqual(result.warned, 1)
        self.assertIn("documented ask-capable", result.checks[0]["detail"])

        result = _DoctorResult()
        _check_hilt_support(cfg, "geminicli", result)
        self.assertEqual(result.warned, 1)
        self.assertIn("no native human approval surface", result.checks[0]["detail"])

        result = _DoctorResult()
        _check_hilt_support(cfg, "openhands", result)
        self.assertEqual(result.warned, 1)
        self.assertIn("no native human approval surface", result.checks[0]["detail"])

        # Antigravity is the one hook-only connector with a native ask
        # surface that overrides --dangerously-skip-permissions, so it
        # should pass HILT (not warn like the rest of the hook-only crowd).
        result = _DoctorResult()
        _check_hilt_support(cfg, "antigravity", result)
        self.assertEqual(result.passed, 1, result.checks)
        self.assertEqual(result.warned, 0, result.checks)
        self.assertIn("PreToolUse ask", result.checks[0]["detail"])
        self.assertIn("dangerously-skip-permissions", result.checks[0]["detail"])


class DoctorHookReachabilityTests(unittest.TestCase):
    def _cfg(self, tmp: str, connector: str) -> Config:
        return Config(
            data_dir=os.path.join(tmp, ".defenseclaw"),
            audit_db=os.path.join(tmp, ".defenseclaw", "audit.db"),
            quarantine_dir=os.path.join(tmp, ".defenseclaw", "quarantine"),
            plugin_dir=os.path.join(tmp, ".defenseclaw", "plugins"),
            policy_dir=os.path.join(tmp, ".defenseclaw", "policies"),
            guardrail=GuardrailConfig(enabled=True, mode="action", connector=connector),
            gateway=GatewayConfig(),
            openshell=OpenShellConfig(),
        )

    def test_openhands_hooks_accept_sdk_home_fallback(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = os.path.join(tmp, "home")
            workspace = os.path.join(tmp, "repo")
            hook_path = os.path.join(home, ".openhands", "hooks.json")
            os.makedirs(os.path.dirname(hook_path), exist_ok=True)
            os.makedirs(workspace, exist_ok=True)
            with open(hook_path, "w", encoding="utf-8") as fh:
                json.dump(
                    {
                        "pre_tool_use": [
                            {
                                "matcher": "*",
                                "hooks": [
                                    {
                                        "type": "command",
                                        "command": os.path.join(tmp, ".defenseclaw", "hooks", "openhands-hook.sh"),
                                    }
                                ],
                            }
                        ]
                    },
                    fh,
                )
            cfg = self._cfg(tmp, "openhands")
            cfg.claw.workspace_dir = workspace
            with patch.dict(os.environ, {"HOME": home}, clear=False):
                result = _DoctorResult()
                _check_openhands_hooks(cfg, result)
            self.assertEqual(result.failed, 0, result.checks)
            self.assertEqual(result.passed, 1)
            self.assertIn("reachable", result.checks[0]["detail"])

    # ------------------------------------------------------------------
    # Antigravity (`agy`) hook reachability
    #
    # `_check_antigravity_hooks` enforces four facts:
    #
    #   1. Missing global file → fail.
    #   2. File exists but does not reference antigravity-hook.sh → fail.
    #   3. File exists and references the script → pass.
    #   4. Pass + duplicate registration in the legacy
    #      ~/.gemini/hooks.json or workspace .antigravitycli/hooks.json
    #      → emit a warn alongside the pass, because agy merges every
    #      discovered hooks file and would fire each registered hook
    #      once per discovery (silent double-billing).
    # ------------------------------------------------------------------

    def _antigravity_hooks_payload(self, hook_script_path: str) -> dict:
        # Returns the Claude-Code-compatible nested schema agy
        # v1.0.x evaluates at runtime, with all five Antigravity
        # 2.0 lifecycle events (PreInvocation, PreToolUse,
        # PostToolUse, PostInvocation, Stop) registered under
        # separate DefenseClaw-owned outer keys. Matches what
        # `defenseclaw setup antigravity` writes after the Hooks
        # v2 contract bump. See patchAntigravityHooks in
        # internal/gateway/connector/hook_only.go for the
        # empirical evidence behind the nested shape and the
        # rationale for registering all five events even when
        # only PreToolUse is empirically verified to fire on agy
        # v1.0.1.
        events = [
            "PreInvocation",
            "PreToolUse",
            "PostToolUse",
            "PostInvocation",
            "Stop",
        ]
        cfg: dict = {}
        for event in events:
            cfg[f"defenseclaw-antigravity-{event.lower()}"] = {
                event: [
                    {
                        "matcher": "*",
                        "hooks": [
                            {
                                "type": "command",
                                "command": hook_script_path,
                            }
                        ],
                    }
                ]
            }
        return cfg

    def test_antigravity_hooks_missing_global_file_fails(self):
        # When the canonical ~/.gemini/config/hooks.json is
        # missing, doctor must surface a FAIL pointing at the
        # canonical path so operators run the right setup
        # command.
        with tempfile.TemporaryDirectory() as tmp:
            home = os.path.join(tmp, "home")
            os.makedirs(home, exist_ok=True)
            cfg = self._cfg(tmp, "antigravity")
            with patch.dict(os.environ, {"HOME": home}, clear=False):
                result = _DoctorResult()
                _check_antigravity_hooks(cfg, result)
            self.assertEqual(result.passed, 0, result.checks)
            self.assertEqual(result.failed, 1)
            detail = result.checks[0]["detail"]
            self.assertIn(".gemini/config/hooks.json", detail)
            # Sanity: should NOT point at the legacy
            # antigravity-cli/ path now that we've pivoted.
            self.assertNotIn("antigravity-cli", detail)

    def test_antigravity_hooks_file_without_script_reference_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = os.path.join(tmp, "home")
            hook_path = os.path.join(home, ".gemini", "config", "hooks.json")
            os.makedirs(os.path.dirname(hook_path), exist_ok=True)
            with open(hook_path, "w", encoding="utf-8") as fh:
                json.dump(
                    {
                        "some-other-hook": {
                            "PreToolUse": [
                                {
                                    "matcher": "*",
                                    "hooks": [
                                        {"type": "command", "command": "/bin/true"}
                                    ],
                                }
                            ]
                        }
                    },
                    fh,
                )
            cfg = self._cfg(tmp, "antigravity")
            with patch.dict(os.environ, {"HOME": home}, clear=False):
                result = _DoctorResult()
                _check_antigravity_hooks(cfg, result)
            self.assertEqual(result.passed, 0, result.checks)
            self.assertEqual(result.failed, 1)
            self.assertIn("does not reference", result.checks[0]["detail"])

    def test_antigravity_hooks_global_only_passes(self):
        # Canonical happy path: the new ~/.gemini/config/hooks.json
        # exists with the nested schema and the legacy
        # antigravity-cli/ path is absent. Doctor should report
        # exactly one PASS, zero WARNs, zero FAILs.
        with tempfile.TemporaryDirectory() as tmp:
            home = os.path.join(tmp, "home")
            hook_path = os.path.join(home, ".gemini", "config", "hooks.json")
            os.makedirs(os.path.dirname(hook_path), exist_ok=True)
            script_path = os.path.join(tmp, ".defenseclaw", "hooks", "antigravity-hook.sh")
            with open(hook_path, "w", encoding="utf-8") as fh:
                json.dump(self._antigravity_hooks_payload(script_path), fh)
            cfg = self._cfg(tmp, "antigravity")
            with patch.dict(os.environ, {"HOME": home}, clear=False):
                result = _DoctorResult()
                _check_antigravity_hooks(cfg, result)
            self.assertEqual(result.failed, 0, result.checks)
            self.assertEqual(result.passed, 1)
            self.assertEqual(result.warned, 0, result.checks)
            self.assertIn("reachable", result.checks[0]["detail"])

    def test_antigravity_hooks_warn_on_legacy_path_residue(self):
        # Pre-v0.5.0 install left a stale defenseclaw-managed
        # entry at ~/.gemini/antigravity-cli/hooks.json. agy
        # ignores that path at runtime, so it doesn't break the
        # integration, but doctor must surface a WARN explaining
        # the situation. The canonical path still exists and is
        # valid, so PASS=1 and WARN=1.
        with tempfile.TemporaryDirectory() as tmp:
            home = os.path.join(tmp, "home")
            canonical = os.path.join(home, ".gemini", "config", "hooks.json")
            legacy = os.path.join(home, ".gemini", "antigravity-cli", "hooks.json")
            os.makedirs(os.path.dirname(canonical), exist_ok=True)
            os.makedirs(os.path.dirname(legacy), exist_ok=True)
            script_path = os.path.join(tmp, ".defenseclaw", "hooks", "antigravity-hook.sh")
            payload = self._antigravity_hooks_payload(script_path)
            for path in (canonical, legacy):
                with open(path, "w", encoding="utf-8") as fh:
                    json.dump(payload, fh)
            cfg = self._cfg(tmp, "antigravity")
            with patch.dict(os.environ, {"HOME": home}, clear=False):
                result = _DoctorResult()
                _check_antigravity_hooks(cfg, result)
            self.assertEqual(result.failed, 0, result.checks)
            self.assertEqual(result.passed, 1)
            self.assertEqual(result.warned, 1, result.checks)
            warn_check = next(c for c in result.checks if c["status"] == "warn")
            self.assertIn("pre-v0.5.0", warn_check["detail"])
            self.assertIn(legacy, warn_check["detail"])

    def test_antigravity_hooks_warn_on_duplicate_registration(self):
        # ~/.gemini/hooks.json (the legacy global hooks file agy
        # also reads) carries a duplicate DefenseClaw entry —
        # agy will fire DefenseClaw twice per tool call. Doctor
        # must surface a WARN distinct from the legacy-residue
        # warn above.
        with tempfile.TemporaryDirectory() as tmp:
            home = os.path.join(tmp, "home")
            canonical = os.path.join(home, ".gemini", "config", "hooks.json")
            legacy_global = os.path.join(home, ".gemini", "hooks.json")
            os.makedirs(os.path.dirname(canonical), exist_ok=True)
            script_path = os.path.join(tmp, ".defenseclaw", "hooks", "antigravity-hook.sh")
            payload = self._antigravity_hooks_payload(script_path)
            for path in (canonical, legacy_global):
                with open(path, "w", encoding="utf-8") as fh:
                    json.dump(payload, fh)
            cfg = self._cfg(tmp, "antigravity")
            with patch.dict(os.environ, {"HOME": home}, clear=False):
                result = _DoctorResult()
                _check_antigravity_hooks(cfg, result)
            self.assertEqual(result.failed, 0, result.checks)
            self.assertEqual(result.passed, 1)
            self.assertEqual(result.warned, 1, result.checks)
            warn_check = next(c for c in result.checks if c["status"] == "warn")
            self.assertIn("duplicate firings", warn_check["detail"])
            self.assertIn(legacy_global, warn_check["detail"])

    def test_copilot_hooks_fail_when_workspace_is_data_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = self._cfg(tmp, "copilot")
            cfg.claw.workspace_dir = cfg.data_dir
            result = _DoctorResult()
            _check_copilot_hooks(cfg, result)
            self.assertEqual(result.failed, 1, result.checks)
            self.assertIn("inside DefenseClaw data dir", result.checks[0]["detail"])

    def test_copilot_hooks_verify_workspace_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = os.path.join(tmp, "repo")
            hook_path = os.path.join(workspace, ".github", "hooks", "defenseclaw.json")
            os.makedirs(os.path.dirname(hook_path), exist_ok=True)
            with open(hook_path, "w", encoding="utf-8") as fh:
                json.dump(
                    {
                        "version": 1,
                        "hooks": {
                            "PreToolUse": [
                                {
                                    "type": "command",
                                    "bash": os.path.join(tmp, ".defenseclaw", "hooks", "copilot-hook.sh"),
                                }
                            ]
                        },
                    },
                    fh,
                )
            cfg = self._cfg(tmp, "copilot")
            cfg.claw.workspace_dir = workspace
            result = _DoctorResult()
            _check_copilot_hooks(cfg, result)
            self.assertEqual(result.failed, 0, result.checks)
            self.assertEqual(result.passed, 1)


class DoctorLLMKeyProviderRoutingTests(unittest.TestCase):
    """Regression: provider routing must be prefix-based, not substring-based.

    A Bedrock inference profile id such as
    "amazon-bedrock/us.anthropic.claude-haiku-4-5-20251001-v1:0" contains the
    substring "anthropic" but is NOT an Anthropic endpoint. The doctor must
    not ship a BIFROST_API_KEY / ABSK bearer to api.anthropic.com based on a
    substring match — doing so makes the whole "LLM API key" check fail with
    a spurious 401 even when the deployment is perfectly healthy.
    """

    def _make_cfg(self, *, model: str, api_key_env: str) -> Config:
        return Config(
            data_dir="/tmp/defenseclaw",
            audit_db="/tmp/defenseclaw/audit.db",
            quarantine_dir="/tmp/defenseclaw/quarantine",
            plugin_dir="/tmp/defenseclaw/plugins",
            policy_dir="/tmp/defenseclaw/policies",
            guardrail=GuardrailConfig(
                enabled=True,
                model=model,
                port=4000,
                api_key_env=api_key_env,
            ),
            gateway=GatewayConfig(),
            openshell=OpenShellConfig(),
        )

    @patch.dict(os.environ, {"BIFROST_API_KEY": "ABSKtest-not-an-anthropic-key"}, clear=False)
    @patch("defenseclaw.commands.cmd_doctor._resolve_api_key", return_value="ABSKtest-not-an-anthropic-key")
    @patch("defenseclaw.commands.cmd_doctor._verify_bedrock")
    @patch("defenseclaw.commands.cmd_doctor._verify_anthropic")
    @patch("defenseclaw.commands.cmd_doctor._verify_openai")
    def test_bedrock_inference_profile_routes_to_bedrock(
        self,
        mock_openai,
        mock_anthropic,
        mock_bedrock,
        _mock_resolve,
    ):
        cfg = self._make_cfg(
            model="amazon-bedrock/us.anthropic.claude-haiku-4-5-20251001-v1:0",
            api_key_env="BIFROST_API_KEY",
        )
        r = _DoctorResult()

        _check_llm_api_key(cfg, r)

        mock_bedrock.assert_called_once()
        mock_anthropic.assert_not_called()
        mock_openai.assert_not_called()

    @patch.dict(os.environ, {"DEFENSECLAW_LLM_KEY": "ABSKtoken=="}, clear=False)
    @patch("defenseclaw.commands.cmd_doctor._resolve_api_key", return_value="ABSKtoken==")
    @patch("defenseclaw.commands.cmd_doctor._verify_bedrock")
    def test_explicit_bedrock_provider_routes_even_with_bare_model(
        self,
        mock_bedrock,
        _mock_resolve,
    ):
        cfg = self._make_cfg(
            model="us.anthropic.claude-haiku-4-5-20251001-v1:0",
            api_key_env="DEFENSECLAW_LLM_KEY",
        )
        cfg.llm = LLMConfig(
            provider="bedrock",
            model="us.anthropic.claude-haiku-4-5-20251001-v1:0",
            api_key_env="DEFENSECLAW_LLM_KEY",
        )
        r = _DoctorResult()

        _check_llm_api_key(cfg, r)

        mock_bedrock.assert_called_once()

    @patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-ant-test"}, clear=False)
    @patch("defenseclaw.commands.cmd_doctor._resolve_api_key", return_value="sk-ant-test")
    @patch("defenseclaw.commands.cmd_doctor._verify_anthropic")
    def test_anthropic_prefix_routes_to_anthropic_verify(
        self,
        mock_anthropic,
        _mock_resolve,
    ):
        cfg = self._make_cfg(
            model="anthropic/claude-sonnet-4-5-20250514",
            api_key_env="ANTHROPIC_API_KEY",
        )
        r = _DoctorResult()

        _check_llm_api_key(cfg, r)

        mock_anthropic.assert_called_once()

    @patch.dict(os.environ, {"OPENAI_API_KEY": "sk-test"}, clear=False)
    @patch("defenseclaw.commands.cmd_doctor._resolve_api_key", return_value="sk-test")
    @patch("defenseclaw.commands.cmd_doctor._verify_openai")
    def test_openai_prefix_routes_to_openai_verify(
        self,
        mock_openai,
        _mock_resolve,
    ):
        cfg = self._make_cfg(model="openai/gpt-4o", api_key_env="OPENAI_API_KEY")
        r = _DoctorResult()

        _check_llm_api_key(cfg, r)

        mock_openai.assert_called_once()

    @patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-ant-test"}, clear=False)
    @patch("defenseclaw.commands.cmd_doctor._resolve_api_key", return_value="sk-ant-test")
    @patch("defenseclaw.commands.cmd_doctor._verify_anthropic")
    @patch("defenseclaw.commands.cmd_doctor._verify_openai")
    def test_env_name_fallback_only_when_model_has_no_prefix(
        self,
        mock_openai,
        mock_anthropic,
        _mock_resolve,
    ):
        # Empty model string — env-name fallback kicks in and routes to
        # Anthropic. Previously an env_name prefix of "ANTHROPIC_" would
        # *always* match even when model had a contradicting prefix;
        # that ambiguous routing is the bug M7 fixes.
        cfg = self._make_cfg(model="", api_key_env="ANTHROPIC_API_KEY")
        r = _DoctorResult()

        _check_llm_api_key(cfg, r)

        mock_anthropic.assert_called_once()
        mock_openai.assert_not_called()

    @patch.dict(os.environ, {"ANTHROPIC_API_KEY": "ABSK-bedrock-in-anthropic-slot"}, clear=False)
    @patch("defenseclaw.commands.cmd_doctor._resolve_api_key", return_value="ABSK-bedrock-in-anthropic-slot")
    @patch("defenseclaw.commands.cmd_doctor._verify_anthropic")
    @patch("defenseclaw.commands.cmd_doctor._verify_openai")
    def test_model_prefix_wins_over_env_name(
        self,
        mock_openai,
        mock_anthropic,
        _mock_resolve,
    ):
        # Operator accidentally stored a Bedrock bearer token in a variable
        # called ANTHROPIC_API_KEY. The model says amazon-bedrock/... so
        # we must NOT probe api.anthropic.com with that key.
        cfg = self._make_cfg(
            model="amazon-bedrock/us.anthropic.claude-haiku-4-5",
            api_key_env="ANTHROPIC_API_KEY",
        )
        r = _DoctorResult()

        _check_llm_api_key(cfg, r)

        mock_anthropic.assert_not_called()
        mock_openai.assert_not_called()


class AnthropicProbeModelTests(unittest.TestCase):
    """Tests for the hardcoded-probe-model fix (M6)."""

    def test_prefers_configured_anthropic_model(self):
        got = _anthropic_probe_model("anthropic/claude-opus-4-20250805")
        self.assertEqual(got, "claude-opus-4-20250805")

    def test_env_override(self):
        with patch.dict(os.environ, {"DEFENSECLAW_ANTHROPIC_PROBE_MODEL": "claude-3-opus-20240229"}, clear=False):
            got = _anthropic_probe_model("")
        self.assertEqual(got, "claude-3-opus-20240229")

    def test_default_when_no_configured_model(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("DEFENSECLAW_ANTHROPIC_PROBE_MODEL", None)
            got = _anthropic_probe_model("")
        self.assertEqual(got, _ANTHROPIC_DEFAULT_PROBE_MODEL)


class DoctorObservabilityLabelTests(unittest.TestCase):
    @patch(
        "defenseclaw.commands.cmd_doctor._resolve_audit_sink_endpoint_and_token",
        return_value=("https://splunk.example.com:8088/services/collector/event", "hec-token"),
    )
    @patch("defenseclaw.commands.cmd_doctor._http_probe", return_value=(200, "ok"))
    def test_splunk_enterprise_probe_label(self, _mock_probe, _mock_resolve):
        cfg = SimpleNamespace(data_dir="/tmp/defenseclaw")
        dest = SimpleNamespace(
            name="splunk-enterprise-splunk-example-com",
            kind="splunk_hec",
            preset_id="splunk-enterprise",
            endpoint="https://splunk.example.com:8088/services/collector/event",
        )
        result = _DoctorResult()

        _probe_splunk_hec(cfg, dest, result)

        self.assertEqual(result.passed, 1)
        self.assertEqual(
            result.checks[0]["label"],
            "splunk-enterprise-splunk-example-com (Splunk Enterprise (HEC))",
        )


class DoctorCacheWriteTests(unittest.TestCase):
    """P3-#21: `_write_doctor_cache` must emit a JSON file that the
    Go TUI can parse into a ``DoctorCache`` via
    ``internal/tui/doctor_cache.go``. Keep these assertions in
    lockstep with ``TestDoctorCache_PythonCompatibleTimestamp`` on
    the Go side.
    """

    def _run_write(self, tmpdir, result):
        from defenseclaw.commands.cmd_doctor import (
            DOCTOR_CACHE_FILENAME,
            _write_doctor_cache,
        )

        cfg = Config(
            data_dir=tmpdir,
            audit_db=os.path.join(tmpdir, "audit.db"),
            quarantine_dir=os.path.join(tmpdir, "quarantine"),
            plugin_dir=os.path.join(tmpdir, "plugins"),
            policy_dir=os.path.join(tmpdir, "policies"),
            guardrail=GuardrailConfig(),
            gateway=GatewayConfig(),
            openshell=OpenShellConfig(),
        )
        _write_doctor_cache(cfg, result)
        return os.path.join(tmpdir, DOCTOR_CACHE_FILENAME)

    def test_writes_cache_with_counts_and_checks(self):
        import json
        import tempfile

        r = _DoctorResult()
        r.passed = 3
        r.failed = 1
        r.warned = 2
        r.skipped = 0
        r.checks = [
            {"status": "pass", "label": "Config", "detail": "/etc/dc"},
            {"status": "fail", "label": "Sidecar", "detail": "unreachable"},
            {"status": "warn", "label": "Guardrail", "detail": "model empty"},
        ]
        with tempfile.TemporaryDirectory() as tmp:
            path = self._run_write(tmp, r)
            self.assertTrue(os.path.isfile(path), path)
            with open(path) as fh:
                payload = json.load(fh)
        self.assertEqual(payload["passed"], 3)
        self.assertEqual(payload["failed"], 1)
        self.assertEqual(payload["warned"], 2)
        self.assertEqual(payload["skipped"], 0)
        self.assertEqual(len(payload["checks"]), 3)
        # captured_at must be an ISO-8601 with Z suffix so Go's
        # time.Time parser accepts it.
        self.assertIn("captured_at", payload)
        self.assertTrue(payload["captured_at"].endswith("Z"), payload["captured_at"])

    def test_skips_write_when_no_data_dir(self):
        from defenseclaw.commands.cmd_doctor import _write_doctor_cache

        # A cfg with data_dir="" must not raise and must not touch
        # the filesystem — we silently no-op so nothing is logged
        # to stderr for the common "--help" / embedded-runner case.
        cfg = Config(
            data_dir="",
            audit_db="",
            quarantine_dir="",
            plugin_dir="",
            policy_dir="",
            guardrail=GuardrailConfig(),
            gateway=GatewayConfig(),
            openshell=OpenShellConfig(),
        )
        _write_doctor_cache(cfg, _DoctorResult())

    def test_atomic_replace(self):
        # Two back-to-back writes must leave exactly one cache file
        # — no `.tmp` residue — so the TUI never sees a half-written
        # JSON document.
        import tempfile

        r1 = _DoctorResult()
        r1.passed = 1
        r2 = _DoctorResult()
        r2.failed = 7
        with tempfile.TemporaryDirectory() as tmp:
            self._run_write(tmp, r1)
            self._run_write(tmp, r2)
            files = sorted(os.listdir(tmp))
        self.assertEqual(files, ["doctor_cache.json"], files)

    def test_concurrent_writes_do_not_corrupt_cache(self):
        # Regression: earlier revisions used a fixed ".tmp" suffix for
        # the staging file, so two concurrent doctor runs raced on the
        # same path and one could either crash or rename a partial
        # file over the other's finished cache. We now mint a unique
        # tempfile per write via tempfile.NamedTemporaryFile, which
        # this test locks in.
        import json
        import tempfile
        import threading

        with tempfile.TemporaryDirectory() as tmp:

            def write_one(i):
                r = _DoctorResult()
                r.passed = i
                self._run_write(tmp, r)

            threads = [threading.Thread(target=write_one, args=(i,)) for i in range(1, 9)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

            cache_path = os.path.join(tmp, "doctor_cache.json")
            # Exactly one canonical cache file, no orphaned tempfiles.
            entries = sorted(os.listdir(tmp))
            self.assertEqual(entries, ["doctor_cache.json"], entries)
            # And the survivor is syntactically valid JSON — the key
            # property the Go loader depends on.
            with open(cache_path) as fh:
                payload = json.load(fh)
            self.assertIn("passed", payload)
            self.assertIn("captured_at", payload)


class DoctorJsonOutputTests(unittest.TestCase):
    """Test --json-output flag on doctor."""

    def test_doctor_result_to_dict(self):
        r = _DoctorResult()
        r.passed = 2
        r.warned = 1
        r.failed = 0
        r.checks.append({"status": "pass", "label": "Config", "detail": "found"})
        r.checks.append({"status": "pass", "label": "Audit DB", "detail": "ok"})
        r.checks.append({"status": "warn", "label": "Scanner", "detail": "not found"})

        d = r.to_dict()
        self.assertEqual(d["passed"], 2)
        self.assertEqual(d["warned"], 1)
        self.assertEqual(d["failed"], 0)
        self.assertEqual(len(d["checks"]), 3)
        self.assertEqual(d["checks"][0]["label"], "Config")

    def test_llm_reachability_suppresses_probe_stdout_when_json_mode(self):
        from defenseclaw.commands import cmd_doctor

        cfg = SimpleNamespace(
            guardrail=SimpleNamespace(enabled=True),
            resolve_llm=lambda _scope: SimpleNamespace(model="openai/test"),
        )
        result = _DoctorResult()

        def noisy_ping(_llm, *, timeout):
            del timeout
            print("Give Feedback / Get Help: https://github.com/BerriAI/litellm/issues/new")
            return (False, "auth: LiteLLM probe failed")

        stdout = io.StringIO()
        previous = cmd_doctor._json_mode
        cmd_doctor._json_mode = True
        try:
            with (
                patch("defenseclaw.llm.ping", side_effect=noisy_ping),
                contextlib.redirect_stdout(stdout),
            ):
                cmd_doctor._check_llm_reachable(cfg, result)
        finally:
            cmd_doctor._json_mode = previous

        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(result.warned, 1)
        self.assertEqual(result.checks[0]["label"], "LLM reachable")
        self.assertIn("LiteLLM probe failed", result.checks[0]["detail"])


class VerifyBedrockTests(unittest.TestCase):
    """Regression tests for :func:`_verify_bedrock` (M3).

    Before the Bedrock verifier existed, ``_check_llm_api_key`` emitted
    a generic ``pass`` with "cannot verify provider" for any Bedrock
    config. That gave operators false confidence — a revoked ABSK
    token looked healthy until a scan actually called LiteLLM. These
    tests lock in the three shape branches and the HTTP response
    matrix so a future refactor can't regress to the silent pass.
    """

    def test_sigv4_key_emits_warning(self):
        # AWS long-term credentials start with AKIA (or ASIA for STS).
        # We intentionally don't probe them — verifying SigV4 means
        # pulling in botocore just for doctor, which we avoid.
        r = _DoctorResult()
        _verify_bedrock("AKIAEXAMPLEACCESSKEY", r)
        self.assertEqual(r.warned, 1, r.checks)
        self.assertEqual(r.failed, 0)
        self.assertIn("sts get-caller-identity", r.checks[0]["detail"])

    def test_sts_session_key_emits_warning(self):
        # ASIA prefixes are STS session credentials — same SigV4 flow.
        r = _DoctorResult()
        _verify_bedrock("ASIAEXAMPLETEMPKEY", r)
        self.assertEqual(r.warned, 1, r.checks)

    def test_unrecognized_shape_passes_with_note(self):
        # If the operator is running a custom gateway that accepts
        # some other token format, we shouldn't block — just note
        # the shape isn't one we can probe.
        r = _DoctorResult()
        _verify_bedrock("custom-gateway-token-xyz", r)
        self.assertEqual(r.passed, 1, r.checks)
        self.assertIn("shape not recognized", r.checks[0]["detail"])

    @patch("defenseclaw.commands.cmd_doctor._http_probe", return_value=(200, "{}"))
    def test_absk_200_is_pass(self, mock_probe):
        r = _DoctorResult()
        _verify_bedrock("ABSKexamplebearertoken==", r)
        self.assertEqual(r.passed, 1, r.checks)
        # Make sure we're hitting the Bedrock endpoint with a Bearer
        # header, not SigV4.
        args, kwargs = mock_probe.call_args
        url = args[0] if args else kwargs["url"]
        self.assertIn("bedrock.", url)
        self.assertIn("amazonaws.com/foundation-models", url)
        self.assertEqual(kwargs["headers"]["Authorization"], "Bearer ABSKexamplebearertoken==")

    @patch("defenseclaw.commands.cmd_doctor._http_probe", return_value=(401, ""))
    def test_absk_401_is_fail(self, _mock_probe):
        r = _DoctorResult()
        _verify_bedrock("ABSKrevokedtoken==", r)
        self.assertEqual(r.failed, 1, r.checks)

    @patch("defenseclaw.commands.cmd_doctor._http_probe", return_value=(403, "access denied"))
    def test_absk_403_is_warn_not_fail(self, _mock_probe):
        # 403 from Bedrock = authenticated but lacks ListFoundationModels.
        # Many production IAM policies grant only InvokeModel — we must
        # not fail the doctor run in that case because scans will work.
        r = _DoctorResult()
        _verify_bedrock("ABSKvalidtokenbutscoped==", r)
        self.assertEqual(r.warned, 1, r.checks)
        self.assertEqual(r.failed, 0)
        self.assertIn("InvokeModel", r.checks[0]["detail"])

    @patch("defenseclaw.commands.cmd_doctor._http_probe", return_value=(0, "DNS failure"))
    def test_network_failure_is_warn(self, _mock_probe):
        # Offline airgapped environments shouldn't fail the whole
        # doctor check — emit a warn so the operator knows connectivity
        # is the issue, not the key.
        r = _DoctorResult()
        _verify_bedrock("ABSKoffline==", r)
        self.assertEqual(r.warned, 1, r.checks)

    def test_region_override_from_environment(self):
        # Operator pinned a GovCloud region via AWS_REGION; the probe
        # URL must honor it instead of defaulting to us-east-1.
        with patch.dict(os.environ, {"AWS_REGION": "us-gov-west-1"}, clear=False):
            self.assertEqual(_bedrock_region(), "us-gov-west-1")

    def test_region_defaults_to_us_east_1(self):
        # Strip all the AWS region env vars we might inherit from the
        # developer shell so the default kicks in deterministically.
        env_copy = {k: v for k, v in os.environ.items() if not k.startswith("AWS_")}
        with patch.dict(os.environ, env_copy, clear=True):
            self.assertEqual(_bedrock_region(), "us-east-1")


class BedrockRoutingTests(unittest.TestCase):
    """Check ``_check_llm_api_key`` routes Bedrock configs to
    :func:`_verify_bedrock` (M3 hook)."""

    def _make_cfg(self, *, model: str, api_key_env: str) -> Config:
        return Config(
            data_dir="/tmp/defenseclaw",
            audit_db="/tmp/defenseclaw/audit.db",
            quarantine_dir="/tmp/defenseclaw/quarantine",
            plugin_dir="/tmp/defenseclaw/plugins",
            policy_dir="/tmp/defenseclaw/policies",
            guardrail=GuardrailConfig(
                enabled=True,
                model=model,
                port=4000,
                api_key_env=api_key_env,
            ),
            gateway=GatewayConfig(),
            openshell=OpenShellConfig(),
        )

    @patch.dict(os.environ, {"AWS_BEARER_TOKEN_BEDROCK": "ABSKtoken=="}, clear=False)
    @patch("defenseclaw.commands.cmd_doctor._resolve_api_key", return_value="ABSKtoken==")
    @patch("defenseclaw.commands.cmd_doctor._verify_bedrock")
    @patch("defenseclaw.commands.cmd_doctor._verify_anthropic")
    @patch("defenseclaw.commands.cmd_doctor._verify_openai")
    def test_bedrock_prefix_routes_to_bedrock_verify(
        self,
        mock_openai,
        mock_anthropic,
        mock_bedrock,
        _mock_resolve,
    ):
        cfg = self._make_cfg(
            model="bedrock/us.anthropic.claude-3-5-haiku-20241022-v1:0",
            api_key_env="AWS_BEARER_TOKEN_BEDROCK",
        )
        r = _DoctorResult()
        _check_llm_api_key(cfg, r)
        mock_bedrock.assert_called_once()
        mock_anthropic.assert_not_called()
        mock_openai.assert_not_called()

    @patch.dict(os.environ, {"AWS_BEARER_TOKEN_BEDROCK": "ABSKtoken=="}, clear=False)
    @patch("defenseclaw.commands.cmd_doctor._resolve_api_key", return_value="ABSKtoken==")
    @patch("defenseclaw.commands.cmd_doctor._verify_bedrock")
    def test_env_name_fallback_routes_when_model_empty(
        self,
        mock_bedrock,
        _mock_resolve,
    ):
        # Model empty + api_key_env=AWS_BEARER_TOKEN_BEDROCK: the
        # env-name fallback should still route to the bedrock verifier.
        cfg = self._make_cfg(model="", api_key_env="AWS_BEARER_TOKEN_BEDROCK")
        r = _DoctorResult()
        _check_llm_api_key(cfg, r)
        mock_bedrock.assert_called_once()


class CiscoAIDefenseProbeTests(unittest.TestCase):
    """The AI Defense probe surfaces an actionable hint on auth
    failures because all three regional deployments (us / eu /
    preview) reply with the same opaque ``401 invalid api key``
    body. Without the endpoint hint, an operator who pasted a key
    issued for a different region sees a generic "authentication
    failed" and assumes the key is bad — re-issuing wastes a key
    rotation cycle. The hint preserves the failure verdict (real
    auth problems still fail loudly) but adds the URL we'll send
    the key to and a remediation pointer to ``defenseclaw setup``.
    """

    def _make_cfg(self, *, endpoint: str = "https://us.api.inspect.aidefense.security.cisco.com") -> Config:
        return Config(
            data_dir="/tmp/defenseclaw",
            audit_db="/tmp/defenseclaw/audit.db",
            quarantine_dir="/tmp/defenseclaw/quarantine",
            plugin_dir="/tmp/defenseclaw/plugins",
            policy_dir="/tmp/defenseclaw/policies",
            guardrail=GuardrailConfig(enabled=True, scanner_mode="remote"),
            gateway=GatewayConfig(),
            openshell=OpenShellConfig(),
            cisco_ai_defense=CiscoAIDefenseConfig(
                endpoint=endpoint, api_key_env="CISCO_AI_DEFENSE_API_KEY",
            ),
        )

    @patch("defenseclaw.commands.cmd_doctor.click.echo")
    @patch("defenseclaw.commands.cmd_doctor._http_probe", return_value=(401, "invalid api key"))
    @patch("defenseclaw.commands.cmd_doctor._resolve_api_key", return_value="fake-key")
    def test_401_emits_endpoint_and_setup_hint(
        self, _mock_resolve, _mock_probe, mock_echo,
    ):
        cfg = self._make_cfg(endpoint="https://eu.api.inspect.aidefense.security.cisco.com")
        r = _DoctorResult()
        _check_cisco_ai_defense(cfg, r)
        self.assertEqual(r.failed, 1, r.checks)
        # Hints go through click.echo (not _emit) so they don't
        # count toward the tally. Walk the captured calls and
        # assert the operator-visible text appears.
        printed = "\n".join(
            call.args[0] if call.args else "" for call in mock_echo.call_args_list
        )
        self.assertIn(
            "endpoint: https://eu.api.inspect.aidefense.security.cisco.com",
            printed,
        )
        self.assertIn("defenseclaw setup", printed)

    @patch("defenseclaw.commands.cmd_doctor.click.echo")
    @patch("defenseclaw.commands.cmd_doctor._http_probe", return_value=(403, "forbidden"))
    @patch("defenseclaw.commands.cmd_doctor._resolve_api_key", return_value="fake-key")
    def test_403_also_emits_region_hint(
        self, _mock_resolve, _mock_probe, mock_echo,
    ):
        # 403 is the same UX failure mode (authenticated but not
        # authorized for the route) — same hint applies.
        cfg = self._make_cfg()
        r = _DoctorResult()
        _check_cisco_ai_defense(cfg, r)
        self.assertEqual(r.failed, 1, r.checks)
        printed = "\n".join(
            call.args[0] if call.args else "" for call in mock_echo.call_args_list
        )
        self.assertIn("defenseclaw setup", printed)

    @patch("defenseclaw.commands.cmd_doctor._http_probe", return_value=(200, "ok"))
    @patch("defenseclaw.commands.cmd_doctor._resolve_api_key", return_value="fake-key")
    def test_200_is_pass_with_no_hint_noise(self, _mock_resolve, _mock_probe):
        cfg = self._make_cfg()
        r = _DoctorResult()
        _check_cisco_ai_defense(cfg, r)
        self.assertEqual(r.passed, 1, r.checks)
        # The pass path uses the existing single-row format; no
        # extra hints should fire so we don't train operators to
        # ignore them on the happy path.
        details = " ".join(c["detail"] for c in r.checks)
        self.assertNotIn("↪", details)

    @patch("defenseclaw.commands.cmd_doctor.click.echo")
    @patch("defenseclaw.commands.cmd_doctor._http_probe", return_value=(0, "DNS failure"))
    @patch("defenseclaw.commands.cmd_doctor._resolve_api_key", return_value="fake-key")
    def test_unreachable_warns_and_shows_endpoint(
        self, _mock_resolve, _mock_probe, mock_echo,
    ):
        cfg = self._make_cfg(endpoint="https://preview.api.inspect.aidefense.aiteam.cisco.com")
        r = _DoctorResult()
        _check_cisco_ai_defense(cfg, r)
        self.assertEqual(r.warned, 1, r.checks)
        printed = "\n".join(
            call.args[0] if call.args else "" for call in mock_echo.call_args_list
        )
        self.assertIn("preview.api.inspect.aidefense.aiteam.cisco.com", printed)


class DoctorGeneratedHookFreshnessTests(unittest.TestCase):
    def _make_cfg(self, data_dir: str) -> Config:
        return Config(
            data_dir=data_dir,
            audit_db=os.path.join(data_dir, "audit.db"),
            quarantine_dir=os.path.join(data_dir, "quarantine"),
            plugin_dir=os.path.join(data_dir, "plugins"),
            policy_dir=os.path.join(data_dir, "policies"),
            llm=LLMConfig(),
            guardrail=GuardrailConfig(connector="codex"),
            gateway=GatewayConfig(),
            openshell=OpenShellConfig(),
        )

    def _write_hook(self, data_dir: str, filename: str, text: str) -> None:
        hook_dir = os.path.join(data_dir, "hooks")
        os.makedirs(hook_dir, exist_ok=True)
        with open(os.path.join(hook_dir, filename), "w", encoding="utf-8") as fh:
            fh.write(text)

    def test_stale_generated_hook_reasons_detect_old_codex_scripts(self):
        from defenseclaw.commands import cmd_doctor

        with tempfile.TemporaryDirectory() as tmp:
            cfg = self._make_cfg(tmp)
            self._write_hook(tmp, "codex-hook.sh", "fail_response() { echo \"$1\"; }\n")
            self._write_hook(tmp, "_hardening.sh", "defenseclaw_read_stdin_capped() { cat; }\n")

            reasons = cmd_doctor._stale_generated_hook_reasons(cfg, "codex")

        self.assertTrue(any("codex-hook.sh missing" in reason for reason in reasons), reasons)
        self.assertTrue(any("_hardening.sh missing" in reason for reason in reasons), reasons)

    def test_codex_hook_check_warns_when_generated_script_is_stale(self):
        from defenseclaw.commands import cmd_doctor

        with tempfile.TemporaryDirectory() as tmp:
            cfg = self._make_cfg(tmp)
            self._write_hook(tmp, "codex-hook.sh", "fail_response() { echo \"$1\"; }\n")
            self._write_hook(tmp, "_hardening.sh", "defenseclaw_read_stdin_capped() { cat; }\n")
            result = _DoctorResult()

            cmd_doctor._check_codex_hooks(cfg, result)

        freshness = [c for c in result.checks if c["label"] == "Codex hooks freshness"]
        self.assertEqual(len(freshness), 1, result.checks)
        self.assertEqual(freshness[0]["status"], "warn")
        self.assertIn("defenseclaw setup codex --yes --restart", freshness[0]["detail"])
        # Warning is advisory only — it must NOT promise `doctor --fix` will
        # repair it (the fixer was intentionally removed; the real remedy is
        # rerunning setup so hooks are regenerated and re-registered).
        self.assertNotIn("doctor --fix", freshness[0]["detail"])

    def test_claude_freshness_checks_registered_hook_path(self):
        from defenseclaw.commands import cmd_doctor

        with tempfile.TemporaryDirectory() as tmp:
            cfg = self._make_cfg(os.path.join(tmp, "current-dc-home"))
            home = os.path.join(tmp, "home")
            settings_dir = os.path.join(home, ".claude")
            os.makedirs(settings_dir, exist_ok=True)
            old_hook_dir = os.path.join(tmp, "old-dc-home", "hooks")
            os.makedirs(old_hook_dir, exist_ok=True)
            old_hook = os.path.join(old_hook_dir, "claude-code-hook.sh")
            with open(old_hook, "w", encoding="utf-8") as fh:
                fh.write("fail_response() { echo \"$1\"; }\n")
            with open(os.path.join(old_hook_dir, "_hardening.sh"), "w", encoding="utf-8") as fh:
                fh.write("defenseclaw_read_stdin_capped() { cat; }\n")
            with open(os.path.join(settings_dir, "settings.json"), "w", encoding="utf-8") as fh:
                json.dump(
                    {
                        "hooks": {
                            "PreToolUse": [
                                {
                                    "hooks": [
                                        {
                                            "type": "command",
                                            "command": old_hook,
                                        }
                                    ]
                                }
                            ]
                        }
                    },
                    fh,
                )
            result = _DoctorResult()

            with patch.object(
                cmd_doctor.os.path,
                "expanduser",
                side_effect=lambda p: p.replace("~", home, 1) if p.startswith("~") else p,
            ):
                cmd_doctor._check_claudecode_hooks(cfg, result)

        freshness = [c for c in result.checks if c["label"] == "Claude Code hooks freshness"]
        self.assertEqual(len(freshness), 1, result.checks)
        self.assertEqual(freshness[0]["status"], "warn")
        self.assertIn(old_hook, freshness[0]["detail"])
        self.assertIn("expected", freshness[0]["detail"])
        self.assertIn("defenseclaw setup claude-code --yes --restart", freshness[0]["detail"])
        self.assertNotIn("defenseclaw-gateway restart", freshness[0]["detail"])


class DoctorGatewayHomeMismatchTests(unittest.TestCase):
    """`_check_gateway_home_mismatch` warns when a gateway from a different
    DEFENSECLAW_HOME (e.g. a leftover /tmp sandbox) is holding the API port —
    the exact failure that makes every hook 401 while each half looks healthy.
    """

    def _make_cfg(self, data_dir: str) -> Config:
        return Config(
            data_dir=data_dir,
            audit_db=os.path.join(data_dir, "audit.db"),
            quarantine_dir=os.path.join(data_dir, "quarantine"),
            plugin_dir=os.path.join(data_dir, "plugins"),
            policy_dir=os.path.join(data_dir, "policies"),
            llm=LLMConfig(),
            guardrail=GuardrailConfig(connector="codex"),
            gateway=GatewayConfig(),
            openshell=OpenShellConfig(),
        )

    def test_warns_when_foreign_home_holds_the_port(self):
        from defenseclaw.commands import cmd_doctor

        with tempfile.TemporaryDirectory() as tmp:
            cfg = self._make_cfg(tmp)  # this config = the real home
            result = _DoctorResult()
            with (
                patch.object(cmd_doctor, "_http_probe", return_value=(200, "{}")),
                # This home's tracked gateway is NOT alive (no/stale pid file).
                patch.object(cmd_doctor, "_read_pid_from_file", return_value=0),
                # A foreign gateway is the actual listener...
                patch.object(cmd_doctor, "_gateway_listener_pid", return_value=4321),
                # ...rooted at a /tmp sandbox home.
                patch.object(
                    cmd_doctor,
                    "_read_process_env_var",
                    return_value="/tmp/defenseclaw-pr365-sandbox",
                ),
            ):
                cmd_doctor._check_gateway_home_mismatch(cfg, result)

        rows = [c for c in result.checks if c["label"] == "Gateway home"]
        self.assertEqual(len(rows), 1, result.checks)
        self.assertEqual(rows[0]["status"], "warn")
        self.assertIn("/tmp/defenseclaw-pr365-sandbox", rows[0]["detail"])
        self.assertIn("unset DEFENSECLAW_HOME", rows[0]["detail"])

    def test_passes_when_this_homes_gateway_is_alive(self):
        from defenseclaw.commands import cmd_doctor

        with tempfile.TemporaryDirectory() as tmp:
            cfg = self._make_cfg(tmp)
            result = _DoctorResult()
            with (
                patch.object(cmd_doctor, "_http_probe", return_value=(200, "{}")),
                patch.object(cmd_doctor, "_read_pid_from_file", return_value=999),
            ):
                cmd_doctor._check_gateway_home_mismatch(cfg, result)

        rows = [c for c in result.checks if c["label"] == "Gateway home"]
        self.assertEqual(len(rows), 1, result.checks)
        self.assertEqual(rows[0]["status"], "pass")

    def test_silent_when_listener_home_cannot_be_identified(self):
        from defenseclaw.commands import cmd_doctor

        with tempfile.TemporaryDirectory() as tmp:
            cfg = self._make_cfg(tmp)
            result = _DoctorResult()
            with (
                patch.object(cmd_doctor, "_http_probe", return_value=(200, "{}")),
                patch.object(cmd_doctor, "_read_pid_from_file", return_value=0),
                patch.object(cmd_doctor, "_gateway_listener_pid", return_value=4321),
                # Can't read the listener's env (perms / no var) -> "can't tell".
                patch.object(cmd_doctor, "_read_process_env_var", return_value=None),
            ):
                cmd_doctor._check_gateway_home_mismatch(cfg, result)

        # No mismatch row emitted — indeterminacy must not nag.
        rows = [c for c in result.checks if c["label"] == "Gateway home"]
        self.assertEqual(rows, [], result.checks)

    def test_passes_when_listener_home_matches_this_config(self):
        from defenseclaw.commands import cmd_doctor

        with tempfile.TemporaryDirectory() as tmp:
            cfg = self._make_cfg(tmp)
            result = _DoctorResult()
            with (
                patch.object(cmd_doctor, "_http_probe", return_value=(200, "{}")),
                # Stale pid file, but the live listener is THIS home's gateway.
                patch.object(cmd_doctor, "_read_pid_from_file", return_value=0),
                patch.object(cmd_doctor, "_gateway_listener_pid", return_value=4321),
                patch.object(cmd_doctor, "_read_process_env_var", return_value=tmp),
            ):
                cmd_doctor._check_gateway_home_mismatch(cfg, result)

        rows = [c for c in result.checks if c["label"] == "Gateway home"]
        self.assertEqual(len(rows), 1, result.checks)
        self.assertEqual(rows[0]["status"], "pass")

    def test_silent_when_api_not_reachable(self):
        from defenseclaw.commands import cmd_doctor

        with tempfile.TemporaryDirectory() as tmp:
            cfg = self._make_cfg(tmp)
            result = _DoctorResult()
            with patch.object(cmd_doctor, "_http_probe", return_value=(0, "")):
                cmd_doctor._check_gateway_home_mismatch(cfg, result)

        rows = [c for c in result.checks if c["label"] == "Gateway home"]
        self.assertEqual(rows, [], result.checks)


class DoctorFixDryRunTests(unittest.TestCase):
    """``doctor --fix --dry-run`` previews fixers without mutating disk.

    Used by the TUI's readiness check (see
    ``cli/defenseclaw/tui/services/setup_state.py::build_readiness_checks``)
    so the operator sees what *would* be repaired before approving
    a real ``--fix --yes`` run.
    """

    def _make_cfg(self):
        return Config(
            data_dir="/tmp/defenseclaw-dryrun",
            audit_db="/tmp/defenseclaw-dryrun/audit.db",
            quarantine_dir="/tmp/defenseclaw-dryrun/quarantine",
            plugin_dir="/tmp/defenseclaw-dryrun/plugins",
            policy_dir="/tmp/defenseclaw-dryrun/policies",
            llm=LLMConfig(),
            guardrail=GuardrailConfig(),
            gateway=GatewayConfig(),
            openshell=OpenShellConfig(),
        )

    def test_dry_run_skips_each_fixer_and_does_not_call_underlying_fns(self):
        from defenseclaw.commands import cmd_doctor

        cfg = self._make_cfg()
        result = _DoctorResult()
        # Patch the individual fixer functions to flag any invocation.
        with (
            patch.object(cmd_doctor, "_fix_stale_pid") as fix_pid,
            patch.object(cmd_doctor, "_fix_gateway_token") as fix_token,
            patch.object(cmd_doctor, "_fix_gateway_token_env") as fix_token_env,
            patch.object(cmd_doctor, "_fix_gateway_token_drift") as fix_drift,
            patch.object(cmd_doctor, "_fix_dotenv_perms") as fix_dotenv,
            patch.object(cmd_doctor, "_fix_pristine_backup") as fix_pristine,
            patch.object(cmd_doctor, "_fix_plugin_registry_required") as fix_plugin_reg,
            patch.object(cmd_doctor, "_fix_connector_residue") as fix_residue,
        ):
            cmd_doctor._run_fixers(
                cfg, result, assume_yes=True, json_out=True, dry_run=True,
            )

            fix_pid.assert_not_called()
            fix_token.assert_not_called()
            fix_token_env.assert_not_called()
            fix_drift.assert_not_called()
            fix_dotenv.assert_not_called()
            fix_pristine.assert_not_called()
            # OTHER-5: the plugin-registry dead-end fixer is wired into --fix
            # but, like the rest, must not run under --dry-run.
            fix_plugin_reg.assert_not_called()
            # D7: the connector-teardown fixer was removed from --fix entirely,
            # so it is never invoked even though it remains importable.
            fix_residue.assert_not_called()

        # Each remaining fixer should have produced a "skip" record so the TUI
        # can list every step the real run would touch. The teardown fixer was
        # removed (D7); the plugin-registry dead-end fixer was added (OTHER-5).
        # Stale generated hooks are detected as a warning only — there is no
        # auto-fixer for them, so they do not appear here.
        fix_records = [c for c in result.checks if c["label"].startswith("fix:")]
        self.assertEqual(len(fix_records), 7)
        for record in fix_records:
            self.assertEqual(record["status"], "skip")
            self.assertIn("dry-run", record["detail"])
        # Doctor must NEVER offer connector teardown from --fix (D7).
        self.assertNotIn(
            "fix: connector residue",
            [c["label"] for c in fix_records],
        )

    def test_real_fix_invokes_each_fixer_when_dry_run_false(self):
        from defenseclaw.commands import cmd_doctor

        cfg = self._make_cfg()
        result = _DoctorResult()
        with (
            patch.object(cmd_doctor, "_fix_stale_pid", return_value=("pass", "ok")),
            patch.object(cmd_doctor, "_fix_gateway_token", return_value=("pass", "ok")),
            patch.object(cmd_doctor, "_fix_gateway_token_env", return_value=("pass", "ok")),
            patch.object(cmd_doctor, "_fix_gateway_token_drift", return_value=("pass", "ok")),
            patch.object(cmd_doctor, "_fix_dotenv_perms", return_value=("pass", "ok")),
            patch.object(cmd_doctor, "_fix_pristine_backup", return_value=("pass", "ok")),
            patch.object(cmd_doctor, "_fix_plugin_registry_required", return_value=("pass", "ok")),
            # _fix_connector_residue is intentionally NOT wired into --fix (D7);
            # patch it so a regression that re-adds it would surface as an extra row.
            patch.object(cmd_doctor, "_fix_connector_residue", return_value=("pass", "ok")) as fix_residue,
        ):
            cmd_doctor._run_fixers(
                cfg, result, assume_yes=True, json_out=True, dry_run=False,
            )

        fix_records = [c for c in result.checks if c["label"].startswith("fix:")]
        # Seven fixers run: the connector-teardown fixer was removed (D7) and
        # the plugin-registry dead-end fixer was added (OTHER-5). Stale
        # generated hooks are warning-only (no auto-fixer), so they are not
        # counted here.
        self.assertEqual(len(fix_records), 7)
        for record in fix_records:
            self.assertEqual(record["status"], "pass")
        fix_residue.assert_not_called()
        self.assertNotIn(
            "fix: connector residue",
            [c["label"] for c in fix_records],
        )

    def test_dry_run_flag_is_exposed_on_click_command(self):
        from defenseclaw.commands.cmd_doctor import doctor

        opts = {p.name: p for p in doctor.params}
        self.assertIn("dry_run", opts)
        self.assertTrue(opts["dry_run"].is_flag)

    def test_dry_run_banner_discloses_restart_and_no_teardown(self):
        from defenseclaw.commands import cmd_doctor

        banner = cmd_doctor._auto_fix_hint(True)
        self.assertIn("nothing on disk changes", banner)
        self.assertIn("may restart the gateway sidecar", banner)
        self.assertIn("doctor never runs connector teardown", banner)


class CustomProviderOverlayChecksTests(unittest.TestCase):
    """Cover ``_check_custom_provider_overlay`` warnings — specifically the
    base_url/domains coverage check that prevents the resolver from
    silently dropping the overlay when no domain entry matches the inbound
    request URL.
    """

    def _make_cfg(self, data_dir: str) -> Config:
        return Config(
            data_dir=data_dir,
            audit_db=os.path.join(data_dir, "audit.db"),
            quarantine_dir=os.path.join(data_dir, "quarantine"),
            plugin_dir=os.path.join(data_dir, "plugins"),
            policy_dir=os.path.join(data_dir, "policies"),
            guardrail=GuardrailConfig(),
            gateway=GatewayConfig(),
            openshell=OpenShellConfig(),
        )

    def _write_overlay(self, data_dir: str, body: str) -> None:
        path = os.path.join(data_dir, "custom-providers.json")
        with open(path, "w", encoding="utf-8") as f:
            f.write(body)

    def test_base_url_host_missing_from_domains_emits_warn(self):
        import tempfile

        with tempfile.TemporaryDirectory() as data_dir:
            self._write_overlay(data_dir, """{
                "providers": [{
                    "name": "acme-internal",
                    "base_url": "https://llm.acme.internal:8443",
                    "base_provider_type": "openai"
                }]
            }""")
            r = _DoctorResult()
            _check_custom_provider_overlay(self._make_cfg(data_dir), r)
            warn_checks = [c for c in r.checks if c["status"] == "warn"]
            self.assertTrue(
                any("not covered by domains" in c["detail"] for c in warn_checks),
                f"expected domains-coverage warn; got {r.checks}",
            )

    def test_base_url_host_covered_by_domains_does_not_warn(self):
        import tempfile

        with tempfile.TemporaryDirectory() as data_dir:
            self._write_overlay(data_dir, """{
                "providers": [{
                    "name": "acme-internal",
                    "domains": ["llm.acme.internal"],
                    "base_url": "https://llm.acme.internal:8443",
                    "base_provider_type": "openai"
                }]
            }""")
            r = _DoctorResult()
            _check_custom_provider_overlay(self._make_cfg(data_dir), r)
            warn_checks = [
                c for c in r.checks
                if c["status"] == "warn" and "not covered by domains" in c["detail"]
            ]
            self.assertEqual(
                warn_checks, [],
                "domains-coverage warn should not fire when host is listed",
            )

    def test_subdomain_coverage_does_not_warn(self):
        # domains entry "acme.internal" should cover a base_url host of
        # "llm.acme.internal" via the suffix rule. This mirrors how the
        # Go gateway's matchProviderDomain treats the domain entry as a
        # substring match anchored at host or subdomain boundaries.
        import tempfile

        with tempfile.TemporaryDirectory() as data_dir:
            self._write_overlay(data_dir, """{
                "providers": [{
                    "name": "acme-internal",
                    "domains": ["acme.internal"],
                    "base_url": "https://llm.acme.internal:8443",
                    "base_provider_type": "openai"
                }]
            }""")
            r = _DoctorResult()
            _check_custom_provider_overlay(self._make_cfg(data_dir), r)
            warn_checks = [
                c for c in r.checks
                if c["status"] == "warn" and "not covered by domains" in c["detail"]
            ]
            self.assertEqual(warn_checks, [], r.checks)

    def test_entry_without_base_url_skips_domain_check(self):
        # When the overlay extends a built-in (env_keys only) without
        # declaring base_url, there is nothing for inferProviderFromURL
        # to match against and the check has no opinion.
        import tempfile

        with tempfile.TemporaryDirectory() as data_dir:
            self._write_overlay(data_dir, """{
                "providers": [{
                    "name": "openai",
                    "env_keys": ["MY_OPENAI_KEY"]
                }]
            }""")
            r = _DoctorResult()
            _check_custom_provider_overlay(self._make_cfg(data_dir), r)
            warn_checks = [
                c for c in r.checks
                if c["status"] == "warn" and "not covered by domains" in c["detail"]
            ]
            self.assertEqual(warn_checks, [], r.checks)


class DoctorHttpProbeRedirectTests(unittest.TestCase):
    """F-0441: _http_probe must NOT follow HTTP redirects.

    Several doctor probes attach credential-bearing headers (Cisco AI-Defense
    ``X-Cisco-AI-Defense-API-Key``, Splunk HEC ``Authorization: Splunk ...``,
    LLM API keys). Python's default opener transparently replays those headers
    to a 30x redirect target, so a hostile/misconfigured endpoint could harvest
    the secret simply by returning a redirect. _http_probe must refuse the
    redirect and surface it as an unreachable (status 0) result, never
    re-issuing the request to the redirect target.
    """

    def setUp(self):
        import http.server
        import threading

        # Records every path + header set the server received, so a test can
        # prove the auth header was NOT replayed to the redirect target.
        self.requests: list[dict] = []
        recorder = self.requests

        class _Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):  # silence test output
                pass

            def _record_and_route(self):
                recorder.append({
                    "path": self.path,
                    "headers": {k.lower(): v for k, v in self.headers.items()},
                })
                if self.path == "/redirect":
                    # 302 to a different path that, if followed, would receive
                    # the replayed credential header.
                    self.send_response(302)
                    self.send_header("Location", "/leaked")
                    self.end_headers()
                else:
                    body = b"reached"
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)

            def do_GET(self):
                self._record_and_route()

            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0) or 0)
                if length:
                    self.rfile.read(length)
                self._record_and_route()

        self.server = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def _url(self, path: str) -> str:
        return f"http://127.0.0.1:{self.port}{path}"

    def test_redirect_is_not_followed(self):
        from defenseclaw.commands.cmd_doctor import _http_probe

        status, body = _http_probe(self._url("/redirect"), timeout=5.0)

        # Refused redirect surfaces as an unreachable probe (status 0), the
        # shape every caller already treats as "could not complete".
        self.assertEqual(status, 0, (status, body))
        # The redirect target must never have been contacted.
        paths = [r["path"] for r in self.requests]
        self.assertIn("/redirect", paths)
        self.assertNotIn("/leaked", paths)

    def test_auth_header_not_replayed_to_redirect_target(self):
        from defenseclaw.commands.cmd_doctor import _http_probe

        secret = "super-secret-splunk-token"
        status, _ = _http_probe(
            self._url("/redirect"),
            method="POST",
            headers={
                "Authorization": f"Splunk {secret}",
                "X-Cisco-AI-Defense-API-Key": secret,
                "Content-Type": "application/json",
            },
            body=b"{}",
            timeout=5.0,
        )
        self.assertEqual(status, 0)

        # Only the initial /redirect request should have been made.
        leaked = [r for r in self.requests if r["path"] == "/leaked"]
        self.assertEqual(leaked, [], "auth header was replayed to redirect target")
        # And the secret must not appear in any request sent to /leaked
        # (defense-in-depth: ensure no second hop carried the header at all).
        for r in self.requests:
            if r["path"] == "/leaked":
                self.fail("redirect target received a request carrying credentials")

    def test_no_redirect_normal_request_still_succeeds(self):
        from defenseclaw.commands.cmd_doctor import _http_probe

        status, body = _http_probe(self._url("/ok"), timeout=5.0)
        self.assertEqual(status, 200, (status, body))
        self.assertIn("reached", body)


class GuardrailProxyMultiConnectorTests(unittest.TestCase):
    """D6: whether the proxy port is 'intentionally closed' is decided over the
    FULL active set. A proxy peer (openclaw/zeptoclaw) that binds port 4000
    forces the real liveliness probe even when the primary is hook-enforced.
    """

    def _cfg(self, connectors, mode="observe"):
        cfg = MagicMock()
        cfg.active_connectors.return_value = connectors
        cfg.guardrail = SimpleNamespace(mode=mode)
        return cfg

    def test_all_hook_enforced_reports_closed(self):
        from defenseclaw.commands.cmd_doctor import (
            _guardrail_proxy_intentionally_closed,
        )

        detail = _guardrail_proxy_intentionally_closed(self._cfg(["hermes", "codex"]))
        self.assertIn("proxy port intentionally closed", detail)
        self.assertIn("codex", detail)
        self.assertIn("hermes", detail)

    def test_mixed_hook_connector_modes_are_rendered_per_connector(self):
        from defenseclaw.commands.cmd_doctor import (
            _guardrail_proxy_intentionally_closed,
        )

        cfg = self._cfg(["codex", "hermes"], mode="observe")
        cfg.guardrail.connectors = {
            "codex": PerConnectorGuardrailConfig(mode="action"),
            "hermes": PerConnectorGuardrailConfig(mode="observe"),
        }
        cfg.guardrail.effective_mode = lambda name: (
            cfg.guardrail.connectors[name].mode or cfg.guardrail.mode
        )

        detail = _guardrail_proxy_intentionally_closed(cfg)

        self.assertIn("codex (mode=action via PreToolUse deny)", detail)
        self.assertIn("hermes (mode=observe)", detail)
        self.assertNotIn("codex, hermes (mode=observe)", detail)
        self.assertIn("proxy port intentionally closed", detail)

    def test_multi_hook_action_mode_reports_action_once_when_uniform(self):
        from defenseclaw.commands.cmd_doctor import (
            _guardrail_proxy_intentionally_closed,
        )

        detail = _guardrail_proxy_intentionally_closed(
            self._cfg(["codex", "hermes"], mode="action")
        )

        self.assertIn("hook-enforced for codex, hermes", detail)
        self.assertIn("mode=action via PreToolUse deny", detail)
        self.assertIn("proxy port intentionally closed", detail)

    def test_multi_hook_action_mode_preserves_omnigent_policy_semantics(self):
        from defenseclaw.commands.cmd_doctor import (
            _guardrail_proxy_intentionally_closed,
        )

        detail = _guardrail_proxy_intentionally_closed(
            self._cfg(["codex", "omnigent"], mode="action")
        )

        self.assertIn("codex (mode=action via PreToolUse deny)", detail)
        self.assertIn("omnigent (mode=action via ALLOW/ASK/DENY)", detail)
        self.assertIn("proxy port intentionally closed", detail)

    def test_proxy_peer_forces_real_probe(self):
        """hermes (hook) + openclaw (proxy): openclaw needs port 4000, so the
        helper returns '' and _check_guardrail_proxy runs the real probe — the
        exact case the singular-primary scoping masked."""
        from defenseclaw.commands.cmd_doctor import (
            _guardrail_proxy_intentionally_closed,
        )

        self.assertEqual(
            _guardrail_proxy_intentionally_closed(self._cfg(["hermes", "openclaw"])),
            "",
        )

    def test_zeptoclaw_peer_forces_real_probe(self):
        from defenseclaw.commands.cmd_doctor import (
            _guardrail_proxy_intentionally_closed,
        )

        self.assertEqual(
            _guardrail_proxy_intentionally_closed(self._cfg(["codex", "zeptoclaw"])),
            "",
        )

    def test_empty_active_set_runs_probe(self):
        from defenseclaw.commands.cmd_doctor import (
            _guardrail_proxy_intentionally_closed,
        )

        self.assertEqual(_guardrail_proxy_intentionally_closed(self._cfg([])), "")

    def test_single_connector_message_unchanged(self):
        from defenseclaw.commands.cmd_doctor import (
            _guardrail_proxy_intentionally_closed,
        )

        detail = _guardrail_proxy_intentionally_closed(self._cfg(["geminicli"]))
        self.assertIn("hook-driven for geminicli", detail)
        self.assertIn("mode=observe", detail)
        self.assertIn("proxy port intentionally closed", detail)


class DoctorFixHelpTextTests(unittest.TestCase):
    """D8: ``--fix`` help + docstring must disclose the gateway-sidecar restart
    blast radius and must no longer advertise connector teardown."""

    def test_fix_help_mentions_restart_and_dry_run(self):
        from defenseclaw.commands.cmd_doctor import doctor

        opts = {p.name: p for p in doctor.params}
        help_text = " ".join((opts["do_fix"].help or "").split()).lower()
        self.assertIn("restart", help_text)
        self.assertIn("--dry-run", help_text)

    def test_fix_docstring_discloses_restart_and_drops_teardown(self):
        from defenseclaw.commands.cmd_doctor import doctor

        doc = " ".join((doctor.help or "").split()).lower()
        self.assertIn("restart the gateway sidecar", doc)
        self.assertIn("no longer tears connectors down", doc)

    def test_connector_residue_warning_points_to_gateway_teardown_directly(self):
        with tempfile.TemporaryDirectory() as tmp:
            open(os.path.join(tmp, "codex_backup.json"), "w").close()
            cfg = SimpleNamespace(
                data_dir=tmp,
                claw=SimpleNamespace(config_file=""),
                active_connectors=lambda: ["hermes"],
            )
            result = _DoctorResult()

            _check_connector_residue(cfg, "hermes", result)

        warn = next(c for c in result.checks if c["label"] == "Connector residue")
        self.assertEqual(warn["status"], "warn")
        self.assertIn(
            "defenseclaw-gateway connector teardown --connector <name>",
            warn["detail"],
        )
        self.assertNotIn("doctor --fix", warn["detail"])


if __name__ == "__main__":
    unittest.main()
