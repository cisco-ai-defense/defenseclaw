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
import hashlib
import io
import json
import os
import sys
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from tests.environment import isolated_home_env

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
    _check_hook_health,
    _check_llm_api_key,
    _check_openhands_hooks,
    _check_proxy_interception,
    _check_scanners,
    _check_security_overrides,
    _check_sidecar,
    _DoctorResult,
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


class DoctorPolicyStateTests(unittest.TestCase):
    """The Policy row: the generation and digest the gateway applied, FAIL
    when it is stale against config.yaml or rejected the last change, WARN
    for a hand edit the writer did not record."""

    def test_policy_row(self):
        from defenseclaw.commands import cmd_doctor

        applied = "sha256:" + "a" * 64
        cases = [
            ({}, applied, "pass"),
            ({}, "sha256:" + "b" * 64, "fail"),
            ({"last_reload_error": "rule pack digest mismatch"}, applied, "fail"),
            ({"config_generation": 2, "config_generation_recorded": False}, applied, "warn"),
        ]
        for extra, local, want in cases:
            policy = {"effective_digest": applied, "generation": 3, "config_generation": 2,
                      "config_generation_recorded": True, **extra}
            result = _DoctorResult()
            with patch.object(cmd_doctor, "_local_policy_digest", return_value={"effective_digest": local}):
                cmd_doctor._check_policy_state(SimpleNamespace(), result, live_health={"policy": policy})
            self.assertEqual(result.checks[0]["status"], want, (extra, local, result.checks[0]))
            if want == "fail" and not extra:
                self.assertIn("defenseclaw-gateway restart", result.checks[0]["detail"])

        old = (
            "[config_schema_invalid] $.bogus_wp: configuration violates the additionalProperties constraint; "
            "inspect the canonical v8 schema or generated reference and correct this field"
        )
        policy = {"effective_digest": applied, "generation": 3, "last_reload_error": old}
        result = _DoctorResult()
        cmd_doctor._check_policy_state(SimpleNamespace(), result, live_health={"policy": policy})
        self.assertNotIn("canonical v8", result.checks[0]["detail"])
        self.assertNotIn("[config_schema_invalid]", result.checks[0]["detail"])
        self.assertNotIn("$.bogus_wp", result.checks[0]["detail"])
        self.assertIn("bogus_wp", result.checks[0]["detail"])

        # A "~/" policy_dir the gateway cannot open: the next step names the absolute path (GAP-1033).
        policy = {"effective_digest": applied, "generation": 3,
                  "last_reload_error": "opa: policy: read rego directory: open ~/team-policies: no such file"}
        result = _DoctorResult()
        cmd_doctor._check_policy_state(SimpleNamespace(policy_dir="~/team-policies"), result,
                                       live_health={"policy": policy})
        self.assertIn(os.path.join(os.path.expanduser("~"), "team-policies"), result.checks[0]["remediation"])

        # A generation applied without its Rego modules is a warning, not a rejected change (GAP-1033).
        policy = {"effective_digest": applied, "generation": 3, "config_generation": 2,
                  "config_generation_recorded": True, "opa_unavailable": "policy: admission.rego reads data.config",
                  "last_reload_error": "opa: policy: admission.rego reads data.config"}
        result = _DoctorResult()
        with patch.object(cmd_doctor, "_local_policy_digest", return_value={"effective_digest": applied}):
            cmd_doctor._check_policy_state(SimpleNamespace(policy_dir="/srv/team-policies"), result,
                                           live_health={"policy": policy})
        self.assertEqual([c["status"] for c in result.checks], ["warn", "pass"], result.checks)

        # A digest the gateway holds back for a restart-only key is a pending
        # restart (warn), not a stale gateway (fail) (GAP-0072).
        policy = {"effective_digest": applied, "generation": 3, "config_generation": 2,
                  "config_generation_recorded": True, "pending_restart": ["guardrail.connectors"]}
        result = _DoctorResult()
        with patch.object(cmd_doctor, "_local_policy_digest", return_value={"effective_digest": "sha256:" + "b" * 64}):
            cmd_doctor._check_policy_state(SimpleNamespace(), result, live_health={"policy": policy})
        self.assertEqual(result.checks[0]["status"], "warn")
        self.assertIn("guardrail.connectors", result.checks[0]["detail"])

        # With the gateway stopped, a hand edit is still found from
        # config.generation.json next to config.yaml (GAP-0305).
        from defenseclaw import config_writer

        with tempfile.TemporaryDirectory() as data_dir, patch.dict(os.environ, {"DEFENSECLAW_CONFIG": ""}):
            config = os.path.join(data_dir, "config.yaml")
            # Bytes, not text mode: Windows would write CRLF and the recorded
            # digest of the LF bytes would not match the file.
            with open(config, "wb") as f:
                f.write(b"config_version: 9\n")
            config_writer.record_generation(config, hashlib.sha256(b"config_version: 9\n").hexdigest(), "cli:t", "")
            for edited, want in ((False, "skip"), (True, "warn")):
                if edited:
                    with open(config, "ab") as f:
                        f.write(b"# hand edit\n")
                result = _DoctorResult()
                cmd_doctor._check_policy_state(SimpleNamespace(data_dir=data_dir), result, live_health=None)
                self.assertEqual(result.checks[0]["status"], want, result.checks[0])

    def test_invalid_config_does_not_claim_gateway_stopped(self):
        from defenseclaw.commands import cmd_doctor

        result = _DoctorResult()
        result.checks.append({"check_id": "doctor.config.validation", "status": "fail"})
        with patch.object(cmd_doctor, "_emit_policy_without_gateway") as emit:
            cmd_doctor._check_policy_state(SimpleNamespace(), result, live_health=None)
        self.assertIn("live state was not checked", emit.call_args.args[3])
        self.assertNotIn("gateway is not running", emit.call_args.args[3])


class DoctorRetiredPolicyDataTests(unittest.TestCase):
    def test_only_data_json_is_retired(self):
        from defenseclaw.commands import cmd_doctor
        from defenseclaw.config import Config

        with tempfile.TemporaryDirectory() as policy_dir:
            os.makedirs(os.path.join(policy_dir, "rego"))
            for name in ("data.json", "data-sandbox.json", "firewall.rego", "audit.rego"):
                with open(os.path.join(policy_dir, "rego", name), "w", encoding="utf-8") as f:
                    f.write("{}")
            result = _DoctorResult()
            cfg = Config(policy_dir=policy_dir, data_dir="")
            cfg._source_config_version = 9
            cmd_doctor._check_policy_evidence_files(cfg, result)
        detail = result.checks[0]["detail"]
        self.assertIn("data.json", detail)
        for leftover in ("data-sandbox.json", "firewall.rego", "audit.rego"):
            self.assertNotIn(leftover, detail)


class DoctorVirusTotalTests(unittest.TestCase):
    """GAP-1936: the VirusTotal row agrees with the credential row."""

    def _cfg(self, use_virustotal: bool, key_env: str = ""):
        from defenseclaw.config import SkillScannerAnalyzers, SkillScannerConfig, SkillScannerVirusTotal

        sc = SkillScannerConfig(
            analyzers=SkillScannerAnalyzers(virustotal=SkillScannerVirusTotal(enabled=use_virustotal, api_key_env=key_env))
        )
        return SimpleNamespace(scanners=SimpleNamespace(skill_scanner=sc))

    def test_disabled_is_skipped(self):
        from defenseclaw.commands.cmd_doctor import _check_virustotal

        result = _DoctorResult()
        with patch.dict(os.environ, {}, clear=True):
            _check_virustotal(self._cfg(False), result)
        self.assertEqual(result.checks[0]["status"], "skip")
        self.assertEqual(result.checks[0]["detail"], "not enabled")

    def test_enabled_without_key_warns_with_next_step(self):
        from defenseclaw.commands.cmd_doctor import _check_virustotal

        result = _DoctorResult()
        with patch.dict(os.environ, {}, clear=True):
            _check_virustotal(self._cfg(True), result)
        check = result.checks[0]
        self.assertEqual(check["status"], "warn")
        self.assertIn("enabled, but VIRUSTOTAL_API_KEY is not set", check["detail"])
        self.assertIn("defenseclaw keys set VIRUSTOTAL_API_KEY", check["remediation"])

    @patch("defenseclaw.commands.cmd_doctor._http_probe", return_value=(200, "ok"))
    def test_default_env_name_key_is_probed(self, probe):
        from defenseclaw.commands.cmd_doctor import _check_virustotal

        result = _DoctorResult()
        with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "dummy"}, clear=True):
            _check_virustotal(self._cfg(True), result)
        self.assertEqual(result.checks[0]["status"], "pass")
        self.assertEqual(probe.call_args.kwargs["headers"], {"x-apikey": "dummy"})


class DoctorSecurityOverrideTests(unittest.TestCase):
    def test_private_upstream_config_entries_are_visible(self):
        cfg = SimpleNamespace(guardrail=SimpleNamespace(allow_private_upstreams=["10.50.2.100", "172.16.0.5"]))
        result = _DoctorResult()

        with patch.dict(os.environ, {}, clear=True):
            _check_security_overrides(cfg, result)

        self.assertEqual(result.warned, 1)
        check = result.checks[0]
        self.assertEqual(check["label"], "Private upstream allowlist")
        self.assertIn("10.50.2.100", check["detail"])
        self.assertIn("172.16.0.5", check["detail"])
        self.assertIn("config.yaml", check["detail"])

    def test_private_upstream_env_and_config_entries_are_merged(self):
        cfg = SimpleNamespace(guardrail=SimpleNamespace(allow_private_upstreams=["10.50.2.100"]))
        result = _DoctorResult()

        with patch.dict(
            os.environ,
            {"DEFENSECLAW_ALLOW_PRIVATE_UPSTREAMS": "10.50.2.100,192.168.1.20"},
            clear=True,
        ):
            _check_security_overrides(cfg, result)

        self.assertEqual(result.warned, 1)
        detail = result.checks[0]["detail"]
        self.assertEqual(detail.count("10.50.2.100"), 1)
        self.assertIn("192.168.1.20", detail)
        self.assertIn("config.yaml", detail)
        self.assertIn("environment", detail)


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
            skill_dirs=lambda connector=None: seen["skill"].append(connector) or [],
            plugin_dirs=lambda connector=None: seen["plugin"].append(connector) or [],
            mcp_servers=lambda connector=None, **_: seen["mcp"].append(connector) or [],
        )
        r = _DoctorResult()

        _check_connector_inventory(cfg, "codex", r)

        self.assertEqual(seen["skill"], ["codex"])
        self.assertEqual(seen["plugin"], ["codex"])
        self.assertEqual(seen["mcp"], ["codex"])


class DoctorHermesPathTests(unittest.TestCase):
    def test_hook_health_uses_resolved_hermes_config_without_lock(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_path = os.path.join(tmp, "LocalAppData", "hermes", "config.yaml")
            os.makedirs(os.path.dirname(config_path), exist_ok=True)
            with open(config_path, "w", encoding="utf-8") as fh:
                fh.write('command: "defenseclaw-gateway.exe hook --connector hermes"\n')

            result = _DoctorResult()
            cfg = SimpleNamespace(data_dir=os.path.join(tmp, "defenseclaw"))
            with patch(
                "defenseclaw.commands.cmd_doctor.hermes_config_path",
                return_value=config_path,
            ), patch("defenseclaw.commands.cmd_doctor._hermes_host_running", return_value=True):
                _check_hook_health(cfg, "hermes", result)

            self.assertEqual(result.passed, 0, result.checks)
            self.assertEqual(result.failed, 1, result.checks)
            self.assertIn(config_path, result.checks[0]["detail"])
            self.assertIn("live=false", result.checks[0]["detail"])

class DoctorGuardrailTests(unittest.TestCase):
    @patch("defenseclaw.commands.cmd_doctor._http_probe", return_value=(200, "ok"))
    def test_empty_guardrail_model_is_not_a_warning(self, _mock_probe):
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

        # Fetch-interceptor routing is how OpenClaw works (GAP-2233):
        # an empty guardrail.model is not something to warn about.
        self.assertEqual(result.failed, 0)
        self.assertEqual(result.warned, 0)
        self.assertEqual(result.passed, 1)
        self.assertNotIn("guardrail.model", " ".join(c["detail"] for c in result.checks))

    def test_proxy_interception_fails_when_self_test_misses(self):
        cfg = Config(
            data_dir="/tmp/defenseclaw",
            audit_db="/tmp/defenseclaw/audit.db",
            quarantine_dir="/tmp/defenseclaw/quarantine",
            plugin_dir="/tmp/defenseclaw/plugins",
            policy_dir="/tmp/defenseclaw/policies",
            guardrail=GuardrailConfig(enabled=True, model="openai/gpt-4", port=4000, connector="openclaw"),
            gateway=GatewayConfig(),
            openshell=OpenShellConfig(),
        )
        result = _DoctorResult()
        _check_proxy_interception(cfg, result, live_health={"interception": {"verified": False}})
        self.assertEqual(result.failed, 1, result.checks)
        self.assertIn("not being intercepted", result.checks[0]["detail"])

    def test_proxy_interception_waits_for_first_report_after_restart(self):
        # GAP-2487: right after a sidecar restart the plugin has not reported
        # yet; it does within a minute, so this is not a FAIL.
        cfg = Config(
            data_dir="/tmp/defenseclaw",
            audit_db="/tmp/defenseclaw/audit.db",
            quarantine_dir="/tmp/defenseclaw/quarantine",
            plugin_dir="/tmp/defenseclaw/plugins",
            policy_dir="/tmp/defenseclaw/policies",
            guardrail=GuardrailConfig(enabled=True, model="openai/gpt-4", port=4000, connector="openclaw"),
            gateway=GatewayConfig(),
            openshell=OpenShellConfig(),
        )
        result = _DoctorResult()
        _check_proxy_interception(cfg, result, live_health={"uptime_ms": 2000})
        self.assertEqual(result.failed, 0, result.checks)
        self.assertEqual(result.warned, 1, result.checks)
        self.assertIn("waiting for the OpenClaw plugin", result.checks[0]["detail"])

        result = _DoctorResult()
        _check_proxy_interception(cfg, result, live_health={"uptime_ms": 600000})
        self.assertEqual(result.failed, 1, result.checks)
        self.assertIn("has not reported", result.checks[0]["detail"])

    def test_proxy_interception_points_at_an_unreachable_openclaw_gateway(self):
        # GAP-2506: the plugin cannot report while the OpenClaw gateway is
        # down, so "rerun doctor in a minute" never helped.
        cfg = Config(
            data_dir="/tmp/defenseclaw",
            audit_db="/tmp/defenseclaw/audit.db",
            quarantine_dir="/tmp/defenseclaw/quarantine",
            plugin_dir="/tmp/defenseclaw/plugins",
            policy_dir="/tmp/defenseclaw/policies",
            guardrail=GuardrailConfig(enabled=True, model="openai/gpt-4", port=4000, connector="openclaw"),
            gateway=GatewayConfig(),
            openshell=OpenShellConfig(),
        )
        result = _DoctorResult()
        result.record("fail", "OpenClaw gateway", "not reachable at 127.0.0.1:20497")
        _check_proxy_interception(cfg, result, live_health={"uptime_ms": 2000})
        self.assertEqual(result.warned, 0, result.checks)
        self.assertEqual(result.failed, 2, result.checks)
        row = result.checks[-1]
        self.assertIn("OpenClaw gateway is not reachable", row["detail"])
        self.assertIn("start or fix the OpenClaw gateway first", row["remediation"])

    def test_proxy_interception_passes_when_self_test_verified(self):
        cfg = Config(
            data_dir="/tmp/defenseclaw",
            audit_db="/tmp/defenseclaw/audit.db",
            quarantine_dir="/tmp/defenseclaw/quarantine",
            plugin_dir="/tmp/defenseclaw/plugins",
            policy_dir="/tmp/defenseclaw/policies",
            guardrail=GuardrailConfig(enabled=True, model="openai/gpt-4", port=4000, connector="openclaw"),
            gateway=GatewayConfig(),
            openshell=OpenShellConfig(),
        )
        result = _DoctorResult()
        _check_proxy_interception(
            cfg,
            result,
            live_health={
                "interception": {
                    "verified": True,
                    "last_verified_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "last_agent_traffic_at": "2026-09-04T12:00:00Z",
                }
            },
        )
        self.assertEqual(result.failed, 0, result.checks)
        self.assertEqual(result.passed, 1, result.checks)
        self.assertIn("self-test", result.checks[0]["detail"])
        self.assertIn("agent traffic", result.checks[0]["detail"])

    def test_proxy_interception_fails_when_a_model_call_missed_the_proxy(self):
        # GAP-0190: a passing self-test is not proof that real model calls take the proxy.
        # GAP-0836: each call needs a hop of its own, so a proxied call does not
        # vouch for a later call that took no hop.
        cfg = Config(
            data_dir="/tmp/defenseclaw",
            audit_db="/tmp/defenseclaw/audit.db",
            quarantine_dir="/tmp/defenseclaw/quarantine",
            plugin_dir="/tmp/defenseclaw/plugins",
            policy_dir="/tmp/defenseclaw/policies",
            guardrail=GuardrailConfig(enabled=True, model="openai/gpt-4", port=4000, connector="openclaw"),
            gateway=GatewayConfig(),
            openshell=OpenShellConfig(),
        )
        now = datetime.now(timezone.utc)

        def stamp(minutes_ago: int) -> str:
            return (now - timedelta(minutes=minutes_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")

        for calls, proxied, last_missed, last_proxied, want in (
            (2, 1, stamp(0), stamp(4), "fail"),
            (2, 2, None, stamp(0), "pass"),
            (3, 2, stamp(4), stamp(0), "warn"),
        ):
            info = {"verified": True, "last_verified_at": stamp(0), "last_agent_traffic_at": stamp(4),
                    "agent_model_calls": calls, "agent_model_calls_proxied": proxied,
                    "last_proxied_model_call_at": last_proxied}
            if last_missed:
                info["last_unproxied_model_call_at"] = last_missed
            result = _DoctorResult()
            _check_proxy_interception(cfg, result, live_health={"interception": info})
            self.assertEqual(result.checks[0]["status"], want, result.checks)
            if want != "pass":
                self.assertIn("did not go through the guardrail proxy", result.checks[0]["detail"])

    def test_proxy_interception_fails_when_self_test_is_stale(self):
        cfg = Config(
            data_dir="/tmp/defenseclaw",
            audit_db="/tmp/defenseclaw/audit.db",
            quarantine_dir="/tmp/defenseclaw/quarantine",
            plugin_dir="/tmp/defenseclaw/plugins",
            policy_dir="/tmp/defenseclaw/policies",
            guardrail=GuardrailConfig(enabled=True, model="openai/gpt-4", port=4000, connector="openclaw"),
            gateway=GatewayConfig(),
            openshell=OpenShellConfig(),
        )
        result = _DoctorResult()
        stale = (datetime.now(timezone.utc) - timedelta(minutes=4)).strftime("%Y-%m-%dT%H:%M:%SZ")
        _check_proxy_interception(
            cfg,
            result,
            live_health={"interception": {"verified": True, "last_verified_at": stale}},
        )
        self.assertEqual(result.failed, 1, result.checks)
        self.assertIn("stale", result.checks[0]["detail"])

    def test_proxy_interception_skips_zeptoclaw_only(self):
        cfg = Config(
            data_dir="/tmp/defenseclaw",
            audit_db="/tmp/defenseclaw/audit.db",
            quarantine_dir="/tmp/defenseclaw/quarantine",
            plugin_dir="/tmp/defenseclaw/plugins",
            policy_dir="/tmp/defenseclaw/policies",
            guardrail=GuardrailConfig(enabled=True, port=4000, connector="zeptoclaw"),
            gateway=GatewayConfig(),
            openshell=OpenShellConfig(),
        )
        result = _DoctorResult()
        _check_proxy_interception(cfg, result, live_health={"interception": {"verified": False}})
        self.assertEqual(result.checks, [])

    def test_proxy_interception_skips_hook_connectors(self):
        cfg = Config(
            data_dir="/tmp/defenseclaw",
            audit_db="/tmp/defenseclaw/audit.db",
            quarantine_dir="/tmp/defenseclaw/quarantine",
            plugin_dir="/tmp/defenseclaw/plugins",
            policy_dir="/tmp/defenseclaw/policies",
            guardrail=GuardrailConfig(enabled=True, port=4000, connector="codex"),
            gateway=GatewayConfig(),
            openshell=OpenShellConfig(),
        )
        result = _DoctorResult()
        _check_proxy_interception(cfg, result, live_health={"interception": {"verified": False}})
        self.assertEqual(result.checks, [])

    def test_proxy_interception_fails_when_document_absent(self):
        cfg = Config(
            data_dir="/tmp/defenseclaw",
            audit_db="/tmp/defenseclaw/audit.db",
            quarantine_dir="/tmp/defenseclaw/quarantine",
            plugin_dir="/tmp/defenseclaw/plugins",
            policy_dir="/tmp/defenseclaw/policies",
            guardrail=GuardrailConfig(enabled=True, model="openai/gpt-4", port=4000, connector="openclaw"),
            gateway=GatewayConfig(),
            openshell=OpenShellConfig(),
        )
        result = _DoctorResult()
        _check_proxy_interception(cfg, result, live_health={"guardrail": {"state": "running"}})
        self.assertEqual(result.failed, 1, result.checks)
        self.assertEqual(result.warned, 0, result.checks)
        self.assertEqual(result.to_dict()["exit_code"], 1)
        self.assertIn("has not reported an interceptor self-test", result.checks[0]["detail"])

    def test_disabled_openclaw_is_skipped_by_the_interception_check(self):
        cfg = Config(
            data_dir="/tmp/defenseclaw",
            audit_db="/tmp/defenseclaw/audit.db",
            quarantine_dir="/tmp/defenseclaw/quarantine",
            plugin_dir="/tmp/defenseclaw/plugins",
            policy_dir="/tmp/defenseclaw/policies",
            guardrail=GuardrailConfig(
                enabled=True,
                model="openai/gpt-4",
                port=4000,
                connector="openclaw",
                connectors={"openclaw": PerConnectorGuardrailConfig(enabled=False)},
            ),
            gateway=GatewayConfig(),
            openshell=OpenShellConfig(),
        )
        interception = _DoctorResult()
        _check_proxy_interception(
            cfg,
            interception,
            live_health={"interception": {"verified": False}},
        )
        self.assertEqual(interception.checks, [])

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
        # GAP-1363: a hook-only roster never uses the OpenClaw fleet uplink,
        # so the row says so instead of repeating the fleet summary.
        self.assertEqual(row["detail"], "disabled — not used: the configured connectors run through hooks")

    @patch("defenseclaw.commands.cmd_doctor._http_probe")
    def test_sidecar_guardrail_row_shows_the_hook_policy_mode(self, mock_probe):
        """A hook connector in action mode reported the data path as
        mode=observability; the row must show the policy mode instead."""
        import json as _json

        details = {
            "connector": "claudecode",
            "mode": "observability",
            "policy_mode": "action",
            "enforcement_enabled": True,
            "enforcement_surface": "agent_lifecycle_hooks",
            "proxy_port": "closed",
        }
        mock_probe.return_value = (
            200,
            _json.dumps(
                {
                    "gateway": {"state": "running"},
                    "watcher": {"state": "running"},
                    "guardrail": {"state": "running", "details": details},
                    "api": {"state": "running"},
                }
            ),
        )
        cfg = Config(
            data_dir="/tmp/defenseclaw",
            audit_db="/tmp/defenseclaw/audit.db",
            quarantine_dir="/tmp/defenseclaw/quarantine",
            plugin_dir="/tmp/defenseclaw/plugins",
            policy_dir="/tmp/defenseclaw/policies",
            guardrail=GuardrailConfig(enabled=True, connector="claudecode"),
            gateway=GatewayConfig(),
            openshell=OpenShellConfig(),
        )
        cfg.claw.mode = "claudecode"
        result = _DoctorResult()

        _check_sidecar(cfg, result)

        rows = [c for c in result.checks if c.get("label", "").strip().endswith("guardrail")]
        self.assertEqual([row["detail"] for row in rows], ["running (mode=action, hook-enforced)"])

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
            "disabled — not used: the configured connectors run through hooks",
        )

    @patch("defenseclaw.commands.cmd_doctor._http_probe")
    def test_sidecar_check_treats_v8_telemetry_as_mandatory(self, mock_probe):
        mock_probe.return_value = (
            200,
            json.dumps(
                {
                    "gateway": {"state": "running"},
                    "telemetry": {"state": "disabled"},
                }
            ),
        )
        cfg = Config(
            data_dir="/tmp/defenseclaw",
            audit_db="/tmp/defenseclaw/audit.db",
            quarantine_dir="/tmp/defenseclaw/quarantine",
            plugin_dir="/tmp/defenseclaw/plugins",
            policy_dir="/tmp/defenseclaw/policies",
            gateway=GatewayConfig(),
            openshell=OpenShellConfig(),
        )
        cfg._source_config_version = 8
        result = _DoctorResult()

        _check_sidecar(cfg, result)

        telemetry = [row for row in result.checks if row.get("label", "").strip().endswith("telemetry")]
        self.assertEqual(len(telemetry), 1)
        self.assertEqual(telemetry[0]["status"], "warn")
        self.assertIn("sidecar is stale", telemetry[0]["detail"])

    @staticmethod
    def _sidecar_alignment_cfg(
        *,
        fleet_mode: str = "disabled",
        watcher_enabled: bool = False,
    ) -> Config:
        gateway = GatewayConfig(
            host="127.0.0.1",
            fleet_mode=fleet_mode,
        )
        gateway.watcher.enabled = watcher_enabled
        cfg = Config(
            data_dir="/tmp/defenseclaw",
            audit_db="/tmp/defenseclaw/audit.db",
            quarantine_dir="/tmp/defenseclaw/quarantine",
            plugin_dir="/tmp/defenseclaw/plugins",
            policy_dir="/tmp/defenseclaw/policies",
            guardrail=GuardrailConfig(enabled=False, connector="codex"),
            gateway=gateway,
            openshell=OpenShellConfig(),
        )
        cfg.claw.mode = "codex"
        cfg._source_config_version = 8
        return cfg

    @staticmethod
    def _complete_sidecar_health() -> dict[str, dict[str, object]]:
        return {
            "gateway": {"state": "disabled"},
            "watcher": {"state": "disabled"},
            "guardrail": {"state": "disabled"},
            "api": {"state": "running"},
            "telemetry": {"state": "running"},
            "sandbox": {"state": "disabled"},
        }

    def _run_sidecar_health(
        self,
        cfg: Config,
        health: object,
    ) -> _DoctorResult:
        result = _DoctorResult()
        with patch(
            "defenseclaw.commands.cmd_doctor._http_probe",
            return_value=(200, json.dumps(health)),
        ):
            _check_sidecar(cfg, result)
        return result

    @staticmethod
    def _sidecar_row(result: _DoctorResult, subsystem: str) -> dict[str, str]:
        return next(row for row in result.checks if row.get("label", "").strip().endswith(subsystem))

    def test_sidecar_check_fails_when_required_api_entry_is_missing(self):
        health = self._complete_sidecar_health()
        del health["api"]

        result = self._run_sidecar_health(
            self._sidecar_alignment_cfg(),
            health,
        )

        api = self._sidecar_row(result, "api")
        self.assertEqual(api["status"], "fail")
        self.assertIn("absent from health response", api["detail"])

    def test_sidecar_check_says_gateway_is_stopped_once(self):
        from defenseclaw.commands import cmd_doctor

        cfg = self._sidecar_alignment_cfg()
        result = _DoctorResult()
        with patch.object(cmd_doctor, "_http_probe", return_value=(0, "<urlopen error [Errno 111] Connection refused>")):
            self.assertIsNone(_check_sidecar(cfg, result))
        with patch.object(cmd_doctor, "_daemon_effective_gateway_token", return_value=("t", "", "")):
            self.assertTrue(cmd_doctor._check_gateway_auth(cfg, result))
        self.assertEqual(len(result.checks), 1, result.checks)
        self.assertIn("the gateway is not running", result.checks[0]["detail"])
        self.assertIn("defenseclaw-gateway start", result.checks[0]["detail"])

    def test_sidecar_check_names_foreign_holder_without_its_health_rows(self):
        from defenseclaw.commands import cmd_doctor

        with (
            patch.object(
                cmd_doctor,
                "_trusted_gateway_listener",
                return_value=cmd_doctor._GatewayTrust("missing", "managed gateway PID file is missing"),
            ),
            patch.object(cmd_doctor, "_gateway_port_holder", return_value="PID 4242 (defenseclaw-gateway)"),
        ):
            result = self._run_sidecar_health(self._sidecar_alignment_cfg(), self._complete_sidecar_health())
        self.assertEqual(len(result.checks), 1, result.checks)
        self.assertEqual(result.checks[0]["status"], "fail")
        self.assertIn("held by PID 4242 (defenseclaw-gateway), not by this account's gateway", result.checks[0]["detail"])
        self.assertEqual(result.gateway_down, "foreign")

        # A holder that is not a gateway at all answers /health with an error.
        result = _DoctorResult()
        with (
            patch.object(cmd_doctor, "_http_probe", return_value=(404, "not found")),
            patch.object(cmd_doctor, "_foreign_gateway_port_holder", return_value="PID 4343 (python3)"),
        ):
            _check_sidecar(self._sidecar_alignment_cfg(), result)
        self.assertIn("held by PID 4343 (python3), not by this account's gateway", result.checks[0]["detail"])
        self.assertEqual(result.gateway_down, "foreign")

    def test_foreign_port_fix_does_not_ask_to_stop_another_accounts_process(self):
        # GAP-1706: the same command form as defenseclaw-gateway status/start,
        # and another account's process is not this account's to stop.
        from defenseclaw.commands import cmd_doctor

        cfg = self._sidecar_alignment_cfg()
        with patch.object(cmd_doctor, "_free_api_port_hint", return_value="18980"):
            other = cmd_doctor._foreign_gateway_port_detail(
                cfg, "PID 12964 (defenseclaw-gateway.exe, probably another account's DefenseClaw gateway)"
            )
            own = cmd_doctor._foreign_gateway_port_detail(cfg, "PID 4343 (python3)")
        self.assertIn("That process belongs to another account, so move", other)
        self.assertNotIn("Stop that process", other)
        self.assertIn("Stop that process, or move", own)
        for text in (other, own):
            # Word for word the text defenseclaw-gateway status and start print.
            self.assertIn(
                "move this account's gateway to a free port with: defenseclaw setup gateway --api-port 18980 "
                "--non-interactive, then run: defenseclaw-gateway start",
                text,
            )

        # GAP-1706: on Windows a standard user cannot read an elevated
        # holder's account; Windows refusing to open it means another account.
        from defenseclaw import process_liveness

        for denied in (True, False):
            with (
                patch.object(cmd_doctor.sys, "platform", "win32"),
                patch.object(process_liveness, "process_access_denied", return_value=denied),
                patch.object(cmd_doctor, "_free_api_port_hint", return_value="18980"),
            ):
                text = cmd_doctor._foreign_gateway_port_remediation(cfg, holder="PID 3792 (pwsh.exe)")
            self.assertEqual(text.startswith("That process belongs to another account"), denied, text)

    def test_refused_token_send_is_not_a_transport_failure(self):
        from defenseclaw.commands import cmd_doctor

        detail = cmd_doctor._token_probe_failure(0, "listener is not verified" + cmd_doctor._GATEWAY_TOKEN_REFUSED)
        self.assertEqual(detail, "the token was not sent: listener is not verified")

    def test_sidecar_check_accepts_intentionally_disabled_fleet_gateway(self):
        for scenario, fleet_mode in (
            ("codex loopback standalone", ""),
            ("explicit fleet disable", "disabled"),
        ):
            with self.subTest(scenario=scenario):
                result = self._run_sidecar_health(
                    self._sidecar_alignment_cfg(fleet_mode=fleet_mode),
                    self._complete_sidecar_health(),
                )

                gateway = self._sidecar_row(result, "gateway")
                self.assertEqual(gateway["status"], "skip")
                self.assertIn("disabled", gateway["detail"])

    def test_sidecar_check_aligns_disabled_watcher_with_config(self):
        for runtime_state, expected_status in (
            ("disabled", "skip"),
            ("running", "warn"),
        ):
            with self.subTest(runtime_state=runtime_state):
                health = self._complete_sidecar_health()
                health["watcher"] = {"state": runtime_state}
                result = self._run_sidecar_health(
                    self._sidecar_alignment_cfg(watcher_enabled=False),
                    health,
                )

                watcher = self._sidecar_row(result, "watcher")
                self.assertEqual(watcher["status"], expected_status)
                if runtime_state == "running":
                    self.assertIn("sidecar is stale", watcher["detail"])

    def test_sidecar_check_reports_malformed_nested_health_without_crashing(self):
        cases = (
            (
                "subsystem entry",
                "gateway",
                [],
                "malformed health entry",
            ),
            (
                "state",
                "watcher",
                {"state": ["running"]},
                "malformed health state",
            ),
            (
                "details",
                "gateway",
                {"state": "disabled", "details": ["unexpected"]},
                "malformed health details",
            ),
        )
        for scenario, subsystem, malformed, expected_detail in cases:
            with self.subTest(scenario=scenario):
                health = self._complete_sidecar_health()
                health[subsystem] = malformed

                result = self._run_sidecar_health(
                    self._sidecar_alignment_cfg(),
                    health,
                )

                row = self._sidecar_row(result, subsystem)
                self.assertEqual(row["status"], "fail")
                self.assertIn(expected_detail, row["detail"])

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
                connector="cursor",
            ),
            gateway=GatewayConfig(),
            openshell=OpenShellConfig(),
        )
        cfg.claw.mode = "cursor"
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
        self.assertIn("hook-driven for cursor", result.checks[0]["detail"])
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
    def test_omnigent_action_reports_configured_unverified_policy_without_proxy_probe(self, mock_probe):
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
        self.assertIn("policy path configured for omnigent", detail)
        self.assertIn("mode=action via ALLOW/ASK/DENY", detail)
        self.assertIn("live policy generation unverified", detail)

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

    def test_hilt_uses_resolved_identity_profile_for_connector(self):
        from defenseclaw.config import GuardrailProfile

        cfg = Config(
            data_dir="/tmp/defenseclaw",
            audit_db="/tmp/defenseclaw/audit.db",
            quarantine_dir="/tmp/defenseclaw/quarantine",
            plugin_dir="/tmp/defenseclaw/plugins",
            policy_dir="/tmp/defenseclaw/policies",
            guardrail=GuardrailConfig(enabled=True, mode="action", connector="claudecode"),
            gateway=GatewayConfig(),
            openshell=OpenShellConfig(),
        )
        cfg.guardrail.hilt.enabled = True
        cfg.guardrail.profiles = {"read_only": GuardrailProfile(mode="observe")}
        cfg.guardrail.default_profile = "read_only"
        result = _DoctorResult()
        with patch(
            "defenseclaw.gateway.current_user_guardrail_profile",
            return_value={
                "profile": "read_only",
                "effective": {"mode": "observe", "hilt": {"enabled": True, "min_severity": "HIGH"}},
            },
        ) as resolve:
            _check_hilt_support(cfg, "claudecode", result)
        resolve.assert_called_once_with(cfg, connector="claudecode")
        self.assertEqual(result.warned, 1, result.checks)
        self.assertEqual(result.passed, 0, result.checks)
        self.assertIn("mode is observe", result.checks[0]["detail"])

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

    def test_hilt_observe_warnings_collapse_into_one_row(self):
        from defenseclaw.commands.cmd_doctor import _emit_hilt_observe_summary

        cfg = Config(
            data_dir="/tmp/defenseclaw",
            audit_db="/tmp/defenseclaw/audit.db",
            quarantine_dir="/tmp/defenseclaw/quarantine",
            plugin_dir="/tmp/defenseclaw/plugins",
            policy_dir="/tmp/defenseclaw/policies",
            guardrail=GuardrailConfig(enabled=True, mode="observe", connector="codex"),
            gateway=GatewayConfig(),
            openshell=OpenShellConfig(),
        )
        cfg.guardrail.hilt.enabled = True
        result = _DoctorResult()
        observe_only: list[tuple[str, str]] = []
        for connector in ("amp", "codex", "cursor"):
            _check_hilt_support(cfg, connector, result, observe_only=observe_only)
        _emit_hilt_observe_summary(observe_only, result, tagged=True)

        [row] = result.checks
        self.assertEqual((row["status"], row["label"]), ("warn", "Human approval"))
        self.assertIn("amp, codex, cursor", row["detail"])
        self.assertIn("defenseclaw guardrail hilt off", row["remediation"])

    def test_llm_reachable_is_skipped_when_nothing_uses_the_llm(self):
        from defenseclaw.commands.cmd_doctor import _check_llm_reachable

        cfg = Config(
            data_dir="/tmp/defenseclaw",
            audit_db="/tmp/defenseclaw/audit.db",
            quarantine_dir="/tmp/defenseclaw/quarantine",
            plugin_dir="/tmp/defenseclaw/plugins",
            policy_dir="/tmp/defenseclaw/policies",
            guardrail=GuardrailConfig(enabled=True, mode="action", connector="omnigent"),
            gateway=GatewayConfig(),
            openshell=OpenShellConfig(),
        )
        cfg.claw.mode = "omnigent"
        cfg.llm.model = "ollama/qwen2.5:0.5b"
        result = _DoctorResult()
        with patch("defenseclaw.llm.ping", side_effect=AssertionError("probed an unused LLM")):
            _check_llm_reachable(cfg, result)

        self.assertEqual(result.checks[0]["status"], "skip")
        self.assertIn("not used", result.checks[0]["detail"])

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
        self.assertIn(
            "native human approval is not implemented",
            result.checks[0]["detail"],
        )

        result = _DoctorResult()
        _check_hilt_support(cfg, "openhands", result)
        self.assertEqual(result.warned, 1)
        self.assertIn("no native human approval surface", result.checks[0]["detail"])

        result = _DoctorResult()
        _check_hilt_support(cfg, "opencode", result)
        self.assertEqual(result.warned, 1)
        self.assertIn("publishes permission.ask", result.checks[0]["detail"])
        self.assertIn("intentionally does not implement", result.checks[0]["detail"])

        # Antigravity documents native ask only at PreToolUse. No override of
        # permission-bypass flags is claimed without persisted client evidence.
        result = _DoctorResult()
        _check_hilt_support(cfg, "antigravity", result)
        self.assertEqual(result.passed, 1, result.checks)
        self.assertEqual(result.warned, 0, result.checks)
        self.assertIn("PreToolUse ask", result.checks[0]["detail"])
        self.assertIn("no override", result.checks[0]["detail"])

    def test_hilt_omnigent_preserves_native_degraded_pre_action_ask_scope(self):
        cfg = Config(
            data_dir="/tmp/defenseclaw",
            audit_db="/tmp/defenseclaw/audit.db",
            quarantine_dir="/tmp/defenseclaw/quarantine",
            plugin_dir="/tmp/defenseclaw/plugins",
            policy_dir="/tmp/defenseclaw/policies",
            guardrail=GuardrailConfig(enabled=True, mode="action", connector="omnigent"),
            gateway=GatewayConfig(),
            openshell=OpenShellConfig(),
        )
        cfg.guardrail.hilt.enabled = True

        result = _DoctorResult()
        _check_hilt_support(cfg, "omnigent", result)

        self.assertEqual(result.passed, 1, result.checks)
        self.assertEqual(result.warned, 0, result.checks)
        self.assertIn("native-degraded support", result.checks[0]["detail"])
        self.assertIn("request, tool_call, and llm_request", result.checks[0]["detail"])


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
            with patch.dict(os.environ, isolated_home_env(home), clear=False):
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
    #   4. Pass + duplicate registration in the documented workspace
    #      .agents/hooks.json → emit a warn alongside the pass.
    # ------------------------------------------------------------------

    def _antigravity_hooks_payload(self, hook_script_path: str) -> dict:
        # Returns Google's documented mixed matcher/direct lifecycle schema.
        events = [
            "PreInvocation",
            "PreToolUse",
            "PostToolUse",
            "PostInvocation",
            "Stop",
        ]
        cfg: dict = {}
        for event in events:
            handler = {"type": "command", "command": hook_script_path, "timeout": 30}
            entries = (
                [{"matcher": "*", "hooks": [handler]}]
                if event in {"PreToolUse", "PostToolUse"}
                else [handler]
            )
            cfg[f"defenseclaw-antigravity-{event.lower()}"] = {event: entries}
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
            with patch.dict(os.environ, isolated_home_env(home), clear=False):
                result = _DoctorResult()
                _check_antigravity_hooks(cfg, result, platform_name="posix")
            self.assertEqual(result.passed, 0, result.checks)
            self.assertEqual(result.failed, 1)
            detail = result.checks[0]["detail"]
            self.assertIn(os.path.join(".gemini", "config", "hooks.json"), detail)
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
                                    "hooks": [{"type": "command", "command": "/bin/true"}],
                                }
                            ]
                        }
                    },
                    fh,
                )
            cfg = self._cfg(tmp, "antigravity")
            with patch.dict(os.environ, isolated_home_env(home), clear=False):
                result = _DoctorResult()
                _check_antigravity_hooks(cfg, result, platform_name="posix")
            self.assertEqual(result.passed, 0, result.checks)
            self.assertEqual(result.failed, 1)
            self.assertIn("does not reference", result.checks[0]["detail"])

    def test_antigravity_hooks_global_only_passes(self):
        # The documented global hooks file exists with the mixed schema.
        # Doctor should report exactly one PASS, zero WARNs, zero FAILs.
        with tempfile.TemporaryDirectory() as tmp:
            home = os.path.join(tmp, "home")
            hook_path = os.path.join(home, ".gemini", "config", "hooks.json")
            os.makedirs(os.path.dirname(hook_path), exist_ok=True)
            script_path = os.path.join(tmp, ".defenseclaw", "hooks", "antigravity-hook.sh")
            with open(hook_path, "w", encoding="utf-8") as fh:
                json.dump(self._antigravity_hooks_payload(script_path), fh)
            cfg = self._cfg(tmp, "antigravity")
            with patch.dict(os.environ, isolated_home_env(home), clear=False):
                result = _DoctorResult()
                _check_antigravity_hooks(cfg, result, platform_name="posix")
            self.assertEqual(result.failed, 0, result.checks)
            self.assertEqual(result.passed, 1)
            self.assertEqual(result.warned, 0, result.checks)
            self.assertIn("reachable", result.checks[0]["detail"])

    def test_antigravity_hooks_ignore_undocumented_legacy_path_residue(self):
        # Undocumented residue is ignored; only the documented global hook
        # file is authoritative for this check.
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
            with patch.dict(os.environ, isolated_home_env(home), clear=False):
                result = _DoctorResult()
                _check_antigravity_hooks(cfg, result, platform_name="posix")
            self.assertEqual(result.failed, 0, result.checks)
            self.assertEqual(result.passed, 1)
            self.assertEqual(result.warned, 0, result.checks)

    def test_antigravity_hooks_warn_on_duplicate_registration(self):
        # The documented workspace .agents/hooks.json carries a duplicate
        # DefenseClaw entry, so Doctor warns about double evaluation.
        with tempfile.TemporaryDirectory() as tmp:
            home = os.path.join(tmp, "home")
            canonical = os.path.join(home, ".gemini", "config", "hooks.json")
            workspace = os.path.join(tmp, "workspace")
            legacy_global = os.path.join(workspace, ".agents", "hooks.json")
            os.makedirs(os.path.dirname(canonical), exist_ok=True)
            os.makedirs(os.path.dirname(legacy_global), exist_ok=True)
            script_path = os.path.join(tmp, ".defenseclaw", "hooks", "antigravity-hook.sh")
            payload = self._antigravity_hooks_payload(script_path)
            for path in (canonical, legacy_global):
                with open(path, "w", encoding="utf-8") as fh:
                    json.dump(payload, fh)
            cfg = self._cfg(tmp, "antigravity")
            cfg.claw.workspace_dir = workspace
            with patch.dict(os.environ, isolated_home_env(home), clear=False):
                result = _DoctorResult()
                _check_antigravity_hooks(cfg, result, platform_name="posix")
            self.assertEqual(result.failed, 0, result.checks)
            self.assertEqual(result.passed, 1)
            self.assertEqual(result.warned, 1, result.checks)
            warn_check = next(c for c in result.checks if c["status"] == "warn")
            self.assertIn("fire twice", warn_check["detail"])
            self.assertIn(legacy_global, warn_check["detail"])

    def test_antigravity_windows_hooks_warn_on_workspace_duplicate(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = os.path.join(tmp, "workspace")
            workspace_hooks = os.path.join(workspace, ".agents", "hooks.json")
            os.makedirs(os.path.dirname(workspace_hooks), exist_ok=True)
            script_path = os.path.join(tmp, ".defenseclaw", "hooks", "defenseclaw-hook.exe")
            with open(workspace_hooks, "w", encoding="utf-8") as fh:
                json.dump(self._antigravity_hooks_payload(script_path), fh)
            cfg = self._cfg(tmp, "antigravity")
            cfg.claw.workspace_dir = workspace
            result = _DoctorResult()

            def healthy_native(_cfg, _connector, _label, native_result, **_kwargs):
                native_result.passed += 1
                native_result.checks.append(
                    {"status": "pass", "label": "Antigravity hooks", "detail": "healthy native matrix"}
                )

            with patch(
                "defenseclaw.commands.cmd_doctor._check_windows_native_hooks",
                side_effect=healthy_native,
            ) as native_check:
                _check_antigravity_hooks(cfg, result, platform_name="nt")

            native_check.assert_called_once()
            self.assertEqual(result.failed, 0, result.checks)
            self.assertEqual(result.passed, 1, result.checks)
            self.assertEqual(result.warned, 1, result.checks)
            warning = next(check for check in result.checks if check["status"] == "warn")
            self.assertIn(workspace_hooks, warning["detail"])
            self.assertIn("fire twice", warning["detail"])

    def test_copilot_hooks_fail_when_workspace_is_data_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = self._cfg(tmp, "copilot")
            cfg.claw.workspace_dir = cfg.data_dir
            result = _DoctorResult()
            _check_copilot_hooks(cfg, result, platform_name="posix")
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
            _check_copilot_hooks(cfg, result, platform_name="posix")
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

    @patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-ant-test"}, clear=False)
    @patch("defenseclaw.commands.cmd_doctor._resolve_api_key", return_value="sk-ant-test")
    @patch("defenseclaw.commands.cmd_doctor._verify_anthropic")
    def test_passive_anthropic_check_never_invokes_model(
        self,
        mock_anthropic,
        _mock_resolve,
    ):
        cfg = self._make_cfg(
            model="anthropic/claude-sonnet-4-5-20250514",
            api_key_env="ANTHROPIC_API_KEY",
        )
        r = _DoctorResult(passive=True)

        _check_llm_api_key(cfg, r)

        mock_anthropic.assert_not_called()
        self.assertEqual(r.checks[-1]["status"], "skip")
        self.assertIn("passive mode", r.checks[-1]["detail"])

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


class DoctorCacheWriteTests(unittest.TestCase):
    """`_write_doctor_cache` must emit an atomic Textual-TUI snapshot."""

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
        # captured_at is an unambiguous RFC3339 UTC value.
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

    def test_planned_repair_prevents_false_healthy_outcome(self):
        from defenseclaw.doctor_engine import RepairRecord

        r = _DoctorResult(mode="plan", passive=True)
        r.record_repair(
            RepairRecord(
                repair_id="doctor.example",
                label="Example",
                state="applicable",
                risk="safe",
                detail="would repair",
            )
        )

        result = r.to_dict()
        self.assertEqual(result["outcome"], "warning")
        self.assertEqual(result["exit_code"], 0)

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

    def test_failed_llm_probe_names_configured_endpoint_without_credentials(self):
        from defenseclaw.commands import cmd_doctor

        cfg = SimpleNamespace(
            guardrail=SimpleNamespace(enabled=True),
            resolve_llm=lambda _scope: SimpleNamespace(
                model="bedrock/model",
                base_url="https://user:secret@example.invalid:9443/v1?token=hidden",
            ),
        )
        result = _DoctorResult()
        with patch("defenseclaw.llm.ping", return_value=(False, "connection refused")):
            cmd_doctor._check_llm_reachable(cfg, result)
        detail = result.checks[0]["detail"]
        self.assertIn("https://example.invalid:9443/v1", detail)
        self.assertNotIn("secret", detail)
        self.assertNotIn("hidden", detail)


def test_failed_llm_probe_with_malformed_url_still_emits_row():
    from defenseclaw.commands import cmd_doctor

    cfg = SimpleNamespace(
        guardrail=SimpleNamespace(enabled=True),
        resolve_llm=lambda _scope: SimpleNamespace(model="openai/test", base_url="http://[invalid"),
    )
    result = _DoctorResult()
    with patch("defenseclaw.llm.ping", return_value=(False, "connection refused")):
        cmd_doctor._check_llm_reachable(cfg, result)
    assert result.checks[0]["label"] == "LLM reachable"
    assert result.checks[0]["status"] != "pass"
    assert "connection refused" in result.checks[0]["detail"]
    assert "http://[invalid" not in result.checks[0]["detail"]



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

    def test_unrecognized_shape_warns_with_next_step(self):
        # GAP-2195: Bedrock rejects keys without a known prefix, so an
        # unknown shape is a WARN with a next step, never a green check.
        r = _DoctorResult()
        _verify_bedrock("dccert-fake-invalid-key", r)
        self.assertEqual((r.passed, r.warned, r.failed), (0, 1, 0), r.checks)
        self.assertIn("does not look like a Bedrock API key", r.checks[0]["detail"])
        self.assertIn("keys set DEFENSECLAW_LLM_KEY", r.checks[0].get("remediation", ""))

    @patch("defenseclaw.commands.cmd_doctor._http_probe", return_value=(200, "{}"))
    def test_short_term_bedrock_api_key_is_probed(self, mock_probe):
        # GAP-1365: short-term keys from the AWS token generator.
        r = _DoctorResult()
        _verify_bedrock("bedrock-api-key-" + "A" * 40, r)
        mock_probe.assert_called_once()
        self.assertEqual(r.passed, 1, r.checks)

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
                endpoint=endpoint,
                api_key_env="CISCO_AI_DEFENSE_API_KEY",
            ),
        )

    @patch("defenseclaw.commands.cmd_doctor.click.echo")
    @patch("defenseclaw.commands.cmd_doctor._http_probe", return_value=(401, "invalid api key"))
    @patch("defenseclaw.commands.cmd_doctor._resolve_api_key", return_value="fake-key")
    def test_401_emits_endpoint_and_setup_hint(
        self,
        _mock_resolve,
        _mock_probe,
        mock_echo,
    ):
        cfg = self._make_cfg(endpoint="https://eu.api.inspect.aidefense.security.cisco.com")
        r = _DoctorResult()
        _check_cisco_ai_defense(cfg, r)
        self.assertEqual(r.failed, 1, r.checks)
        # Hints go through click.echo (not _emit) so they don't
        # count toward the tally. Walk the captured calls and
        # assert the operator-visible text appears.
        printed = "\n".join(call.args[0] if call.args else "" for call in mock_echo.call_args_list)
        self.assertIn(
            "endpoint: https://eu.api.inspect.aidefense.security.cisco.com",
            printed,
        )
        self.assertIn("defenseclaw setup", printed)

    @patch("defenseclaw.commands.cmd_doctor.click.echo")
    @patch("defenseclaw.commands.cmd_doctor._http_probe", return_value=(403, "forbidden"))
    @patch("defenseclaw.commands.cmd_doctor._resolve_api_key", return_value="fake-key")
    def test_403_also_emits_region_hint(
        self,
        _mock_resolve,
        _mock_probe,
        mock_echo,
    ):
        # 403 is the same UX failure mode (authenticated but not
        # authorized for the route) — same hint applies.
        cfg = self._make_cfg()
        r = _DoctorResult()
        _check_cisco_ai_defense(cfg, r)
        self.assertEqual(r.failed, 1, r.checks)
        printed = "\n".join(call.args[0] if call.args else "" for call in mock_echo.call_args_list)
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
        self,
        _mock_resolve,
        _mock_probe,
        mock_echo,
    ):
        cfg = self._make_cfg(endpoint="https://preview.api.inspect.aidefense.aiteam.cisco.com")
        r = _DoctorResult()
        _check_cisco_ai_defense(cfg, r)
        self.assertEqual(r.warned, 1, r.checks)
        printed = "\n".join(call.args[0] if call.args else "" for call in mock_echo.call_args_list)
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
            self._write_hook(tmp, "codex-hook.sh", 'fail_response() { echo "$1"; }\n')
            self._write_hook(tmp, "_hardening.sh", "defenseclaw_read_stdin_capped() { cat; }\n")

            reasons = cmd_doctor._stale_generated_hook_reasons(cfg, "codex")

        self.assertTrue(any("codex-hook.sh missing" in reason for reason in reasons), reasons)
        self.assertTrue(any("_hardening.sh missing" in reason for reason in reasons), reasons)

    def test_stale_generated_hook_reasons_report_a_baked_fail_mode_config_changed(self):
        # A writer change to guardrail.hook_fail_mode leaves the script with
        # the old baked mode; its derived-from header says which.
        from defenseclaw.commands import cmd_doctor

        with tempfile.TemporaryDirectory() as tmp:
            cfg = self._make_cfg(tmp)
            cfg.guardrail.mode, cfg.guardrail.hook_fail_mode = "action", "closed"
            self._write_hook(
                tmp, "codex-hook.sh",
                "#!/bin/bash\n# defenseclaw-managed-hook v7\n# defenseclaw-derived: sha256=00 fail_mode=open\n"
                "defenseclaw_response_failure_reason\n",
            )
            reasons = cmd_doctor._stale_generated_hook_reasons(cfg, "codex")

        self.assertTrue(any("bakes hook fail mode open" in reason for reason in reasons), reasons)

    def test_codex_hook_check_warns_when_generated_script_is_stale(self):
        from defenseclaw.commands import cmd_doctor

        with tempfile.TemporaryDirectory() as tmp:
            cfg = self._make_cfg(tmp)
            self._write_hook(tmp, "codex-hook.sh", 'fail_response() { echo "$1"; }\n')
            self._write_hook(tmp, "_hardening.sh", "defenseclaw_read_stdin_capped() { cat; }\n")
            result = _DoctorResult()

            cmd_doctor._check_codex_hooks(cfg, result, platform_name="posix")

        freshness = [c for c in result.checks if c["label"] == "Codex hooks freshness"]
        self.assertEqual(len(freshness), 1, result.checks)
        self.assertEqual(freshness[0]["status"], "warn")
        self.assertIn("defenseclaw setup codex --yes --restart", freshness[0]["detail"])
        # Warning is advisory only — it must NOT promise `doctor --fix` will
        # repair it (the fixer was intentionally removed; the real remedy is
        # rerunning setup so hooks are regenerated and re-registered).
        self.assertNotIn("doctor --fix", freshness[0]["detail"])

    @unittest.skipIf(os.name == "nt", "POSIX hook paths in a TOML basic string")
    def test_codex_hook_check_warns_about_another_installs_hooks(self):
        # GAP-1529: a config.toml copied from another account kept that
        # install's DefenseClaw hook entries next to ours; doctor said PASS.
        from defenseclaw.commands import cmd_doctor

        with tempfile.TemporaryDirectory() as tmp:
            own_home = os.path.join(tmp, "home", ".defenseclaw")
            cfg = self._make_cfg(own_home)
            self._write_hook(own_home, "codex-hook.sh", "#!/bin/sh\n# defenseclaw-managed-hook v6\n")
            other_live = os.path.join(tmp, "other", ".dc", "hooks", "codex-hook.sh")
            os.makedirs(os.path.dirname(other_live))
            with open(other_live, "w", encoding="utf-8") as fh:
                fh.write("#!/bin/sh\n# defenseclaw-managed-hook v6\n")
            other_gone = os.path.join(tmp, "gone", ".defenseclaw", "hooks", "codex-hook.sh")
            third_party = os.path.join(tmp, "vendor", "hooks", "codex-hook.sh")
            os.makedirs(os.path.dirname(third_party))
            with open(third_party, "w", encoding="utf-8") as fh:
                fh.write("#!/bin/sh\necho vendor\n")
            own = os.path.join(own_home, "hooks", "codex-hook.sh")
            config_toml = os.path.join(tmp, "codex", "config.toml")
            os.makedirs(os.path.dirname(config_toml))
            lines = []
            for script in (own, other_live, other_gone, third_party):
                lines += [
                    "[[hooks.PreToolUse]]",
                    "[[hooks.PreToolUse.hooks]]",
                    'type = "command"',
                    f'command = "{script} --event PreToolUse --hook-contract codex-hooks-v4"',
                    "timeout = 30",
                ]
            with open(config_toml, "w", encoding="utf-8") as fh:
                fh.write("\n".join(lines) + "\n")
            result = _DoctorResult()

            cmd_doctor._check_codex_hooks(cfg, result, platform_name="posix", config_path=config_toml)
            clean = _DoctorResult()
            with open(config_toml, "w", encoding="utf-8") as fh:
                fh.write("\n".join(lines[:5]) + "\n")
            cmd_doctor._check_codex_hooks(cfg, clean, platform_name="posix", config_path=config_toml)

        rows = [c for c in result.checks if c["label"] == "Codex hooks of another install"]
        self.assertEqual([c["status"] for c in rows], ["warn"], result.checks)
        runs, fails = rows[0]["detail"].split("; ")
        self.assertIn(other_live, runs)
        self.assertIn("runs two hook chains", runs)
        # GAP-1854: a deleted script fails on every event; it is no second chain.
        self.assertIn(other_gone, fails)
        self.assertIn("fail on every Codex event", fails)
        self.assertNotIn(third_party, rows[0]["detail"])
        self.assertNotIn(own + ",", rows[0]["detail"])
        self.assertEqual([c for c in clean.checks if c["label"] == "Codex hooks of another install"], [])

    @unittest.skipIf(os.name == "nt", "POSIX hook paths in a TOML basic string")
    def test_codex_hook_check_warns_when_notify_is_not_defenseclaw(self):
        # GAP-1248: a renamed notify program left Codex launching a missing
        # program on every turn while doctor said the hooks were healthy.
        from defenseclaw.commands import cmd_doctor

        with tempfile.TemporaryDirectory() as tmp:
            home = os.path.join(tmp, ".defenseclaw")
            cfg = self._make_cfg(home)
            self._write_hook(home, "codex-hook.sh", "#!/bin/sh\n# defenseclaw-managed-hook v6\n")
            bridge = os.path.join(home, "notify-bridge.sh")
            with open(bridge, "w", encoding="utf-8") as fh:
                fh.write("#!/bin/bash\n")
            own = os.path.join(home, "hooks", "codex-hook.sh")
            config_toml = os.path.join(tmp, "codex", "config.toml")
            os.makedirs(os.path.dirname(config_toml))
            hooks = (
                "[[hooks.PreToolUse]]\n[[hooks.PreToolUse.hooks]]\n"
                f'type = "command"\ncommand = "{own} --event PreToolUse"\n'
            )

            def notify_rows(notify: str) -> list[dict]:
                with open(config_toml, "w", encoding="utf-8") as fh:
                    fh.write(notify + hooks)
                result = _DoctorResult()
                cmd_doctor._check_codex_hooks(cfg, result, platform_name="posix", config_path=config_toml)
                return [c for c in result.checks if c["label"] == "Codex notify"]

            renamed = notify_rows(f'notify = ["bash", "{bridge[:-3]}-TAMPERED.sh"]\n')
            healthy = notify_rows(f'notify = ["bash", "{bridge}"]\n')

        self.assertEqual([c["status"] for c in renamed], ["warn"], renamed)
        self.assertIn("-TAMPERED.sh", renamed[0]["detail"])
        self.assertEqual(healthy, [])

    def test_unreadable_foreign_codex_hook_script_counts_as_broken(self):
        # GAP-1854: another account's unreadable home raised PermissionError
        # and the foreign entry was ignored.
        from unittest import mock

        from defenseclaw.commands import cmd_doctor

        path = "/Users/other/.defenseclaw/hooks/codex-hook.sh"
        with mock.patch("builtins.open", side_effect=PermissionError(13, "denied")):
            self.assertEqual(cmd_doctor._defenseclaw_hook_script_kind(path), "broken")
            self.assertEqual(cmd_doctor._defenseclaw_hook_script_kind("/opt/vendor/hooks/codex-hook.sh"), "")

    def test_codex_hook_check_fails_on_the_teardown_placeholder(self):
        # GAP-1312: after uninstall the script is the disabled placeholder
        # (disabledHookTombstone in Go) and config.toml no longer runs it.
        from defenseclaw.commands import cmd_doctor

        with tempfile.TemporaryDirectory() as tmp:
            cfg = self._make_cfg(tmp)
            self._write_hook(
                tmp,
                "codex-hook.sh",
                "#!/bin/sh\n# defenseclaw-managed-hook v0 (disabled tombstone)\n"
                "# Codex connector was torn down. Existing host processes may\nexit 0\n",
            )
            result = _DoctorResult()

            cmd_doctor._check_codex_hooks(cfg, result, platform_name="posix")

        rows = [c for c in result.checks if c["label"].startswith("Codex hooks")]
        self.assertEqual([c["status"] for c in rows], ["fail"], rows)
        self.assertIn("torn down", rows[0]["detail"])

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
                fh.write('fail_response() { echo "$1"; }\n')
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

            cmd_doctor._check_claudecode_hooks(
                cfg,
                result,
                platform_name="posix",
                config_path=os.path.join(settings_dir, "settings.json"),
            )

        freshness = [c for c in result.checks if c["label"] == "Claude Code hooks freshness"]
        self.assertEqual(len(freshness), 1, result.checks)
        self.assertEqual(freshness[0]["status"], "warn")
        self.assertIn(old_hook, freshness[0]["detail"])
        self.assertIn("expected", freshness[0]["detail"])
        self.assertIn("defenseclaw setup claude-code --yes --restart", freshness[0]["detail"])
        self.assertNotIn("defenseclaw-gateway restart", freshness[0]["detail"])


class DoctorGatewayHomeMismatchTests(unittest.TestCase):
    """Gateway-home diagnostics use the same strong trust chain as auth."""

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
                patch.object(
                    cmd_doctor,
                    "_trusted_gateway_listener",
                    return_value=cmd_doctor._GatewayTrust(
                        "foreign_home",
                        "managed PID record belongs to a different canonical data home",
                        4321,
                    ),
                ),
            ):
                cmd_doctor._check_gateway_home_mismatch(cfg, result)

        rows = [c for c in result.checks if c["label"] == "Gateway home"]
        self.assertEqual(len(rows), 1, result.checks)
        self.assertEqual(rows[0]["status"], "fail")
        self.assertIn("different canonical data home", rows[0]["detail"])
        self.assertNotIn("/tmp/defenseclaw-pr365-sandbox", rows[0]["detail"])

    def test_passes_when_this_homes_gateway_is_alive(self):
        from defenseclaw.commands import cmd_doctor

        with tempfile.TemporaryDirectory() as tmp:
            cfg = self._make_cfg(tmp)
            result = _DoctorResult()
            with (
                patch.object(cmd_doctor, "_http_probe", return_value=(200, "{}")),
                patch.object(
                    cmd_doctor,
                    "_trusted_gateway_listener",
                    return_value=cmd_doctor._GatewayTrust(
                        "trusted",
                        "verified",
                        999,
                        home_bound=True,
                    ),
                ),
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
                patch.object(
                    cmd_doctor,
                    "_trusted_gateway_listener",
                    return_value=cmd_doctor._GatewayTrust(
                        "missing",
                        "managed gateway PID file is missing",
                    ),
                ),
            ):
                cmd_doctor._check_gateway_home_mismatch(cfg, result)

        rows = [c for c in result.checks if c["label"] == "Gateway home"]
        self.assertEqual(len(rows), 1, result.checks)
        self.assertEqual(rows[0]["status"], "skip")
        self.assertIn("not inferred", rows[0]["detail"])

    def test_passes_when_listener_home_matches_this_config(self):
        from defenseclaw.commands import cmd_doctor

        with tempfile.TemporaryDirectory() as tmp:
            cfg = self._make_cfg(tmp)
            result = _DoctorResult()
            with (
                patch.object(cmd_doctor, "_http_probe", return_value=(200, "{}")),
                patch.object(
                    cmd_doctor,
                    "_trusted_gateway_listener",
                    return_value=cmd_doctor._GatewayTrust(
                        "trusted",
                        "verified",
                        4321,
                        home_bound=True,
                    ),
                ),
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
        cfg = Config(
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
        cfg.acp = None  # no ACP binding, so the ACP guard repair stays a noop
        return cfg

    def test_dry_run_calls_only_read_only_planners(self):
        from defenseclaw.commands import cmd_doctor

        cfg = self._make_cfg()
        result = _DoctorResult()
        planner_result = ("plan", "would repair the applicable state")
        healthy_prerequisite = cmd_doctor.RepairDecision("noop", "already healthy")
        watchdog_plan = cmd_doctor.RepairDecision(
            "applicable",
            "would start the enabled stopped watchdog",
        )
        with (
            patch.object(cmd_doctor.sys, "platform", "win32"),
            patch.object(
                cmd_doctor,
                "_plan_canonical_config_preflight",
                return_value=healthy_prerequisite,
            ),
            patch.object(
                cmd_doctor,
                "_plan_audit_db_recovery",
                return_value=healthy_prerequisite,
            ),
            patch.object(
                cmd_doctor,
                "_plan_device_key_recovery",
                return_value=healthy_prerequisite,
            ),
            patch.object(
                cmd_doctor,
                "_plan_connector_compatibility_review",
                return_value=healthy_prerequisite,
            ),
            patch.object(
                cmd_doctor,
                "_plan_connector_compatibility_gate",
                return_value=healthy_prerequisite,
            ),
            patch.object(
                cmd_doctor,
                "_plan_component_compatibility_review",
                return_value=healthy_prerequisite,
            ),
            patch.object(
                cmd_doctor,
                "_plan_component_compatibility_gate",
                return_value=healthy_prerequisite,
            ),
            patch.object(
                cmd_doctor,
                "_plan_watchdog_runtime",
                return_value=watchdog_plan,
            ) as plan_watchdog,
            patch.object(cmd_doctor, "_fix_stale_pid", return_value=planner_result) as fix_pid,
            patch.object(cmd_doctor, "_fix_gateway_token", return_value=planner_result) as fix_token,
            patch.object(cmd_doctor, "_fix_gateway_token_env", return_value=planner_result) as fix_token_env,
            patch.object(cmd_doctor, "_fix_gateway_token_drift", return_value=planner_result) as fix_drift,
            patch.object(cmd_doctor, "_fix_gateway_service", return_value=planner_result) as fix_service,
            patch.object(cmd_doctor, "_fix_watchdog_runtime") as fix_watchdog,
            patch.object(cmd_doctor, "_fix_dotenv_perms", return_value=planner_result) as fix_dotenv,
            patch.object(cmd_doctor, "_fix_pristine_backup", return_value=planner_result) as fix_pristine,
            patch.object(
                cmd_doctor,
                "_fix_plugin_registry_required",
                return_value=planner_result,
            ) as fix_plugin_reg,
            patch.object(cmd_doctor, "_fix_connector_residue") as fix_residue,
        ):
            cmd_doctor._run_fixers(
                cfg,
                result,
                assume_yes=True,
                json_out=True,
                dry_run=True,
            )

            for planner in (
                fix_pid,
                fix_token,
                fix_token_env,
                fix_drift,
                fix_service,
                fix_dotenv,
                fix_pristine,
                fix_plugin_reg,
            ):
                planner.assert_called_once()
                self.assertTrue(planner.call_args.kwargs["plan_only"])
            plan_watchdog.assert_called_once_with(cfg)
            fix_watchdog.assert_not_called()
            # D7: the connector-teardown fixer was removed from --fix entirely,
            # so it is never invoked even though it remains importable.
            fix_residue.assert_not_called()

        # Repairs have their own typed collection and do not contaminate
        # post-repair health counts. The policy-changing repair is visible but
        # explicitly requires selection on the real run.
        self.assertEqual(result.checks, [])
        self.assertEqual(len(result.repairs), 23)
        self.assertEqual(
            {record["state"] for record in result.repairs},
            {"applicable", "noop", "requires_confirmation"},
        )
        self.assertEqual(result.repair_summary.planned, 8)
        self.assertEqual(result.repair_summary.requires_confirmation, 1)
        self.assertEqual(result.repair_summary.noop, 14)
        # Doctor must NEVER offer connector teardown from --fix (D7).
        self.assertNotIn(
            "connector residue",
            [record["label"] for record in result.repairs],
        )

    def test_real_fix_invokes_each_fixer_when_dry_run_false(self):
        from defenseclaw.commands import cmd_doctor

        cfg = self._make_cfg()
        result = _DoctorResult()

        def planned_then_applied(*_args, **kwargs):
            return ("plan", "would repair") if kwargs.get("plan_only") else ("pass", "ok")

        healthy_prerequisite = cmd_doctor.RepairDecision("noop", "already healthy")
        watchdog_plan = cmd_doctor.RepairDecision(
            "applicable",
            "would start the enabled stopped watchdog",
        )
        with (
            patch.object(cmd_doctor.sys, "platform", "win32"),
            patch.object(
                cmd_doctor,
                "_plan_canonical_config_preflight",
                return_value=healthy_prerequisite,
            ),
            patch.object(
                cmd_doctor,
                "_plan_audit_db_recovery",
                return_value=healthy_prerequisite,
            ),
            patch.object(
                cmd_doctor,
                "_plan_device_key_recovery",
                return_value=healthy_prerequisite,
            ),
            patch.object(
                cmd_doctor,
                "_plan_connector_compatibility_review",
                return_value=healthy_prerequisite,
            ),
            patch.object(
                cmd_doctor,
                "_plan_connector_compatibility_gate",
                return_value=healthy_prerequisite,
            ),
            patch.object(
                cmd_doctor,
                "_plan_component_compatibility_review",
                return_value=healthy_prerequisite,
            ),
            patch.object(
                cmd_doctor,
                "_plan_component_compatibility_gate",
                return_value=healthy_prerequisite,
            ),
            patch.object(
                cmd_doctor,
                "_plan_watchdog_runtime",
                return_value=watchdog_plan,
            ),
            patch.object(cmd_doctor, "_fix_stale_pid", side_effect=planned_then_applied),
            patch.object(cmd_doctor, "_fix_gateway_token", side_effect=planned_then_applied),
            patch.object(cmd_doctor, "_fix_gateway_token_env", side_effect=planned_then_applied),
            patch.object(cmd_doctor, "_fix_gateway_token_drift", side_effect=planned_then_applied),
            patch.object(cmd_doctor, "_fix_gateway_service", side_effect=planned_then_applied),
            patch.object(cmd_doctor, "_fix_watchdog_runtime", return_value=("pass", "ok")),
            patch.object(cmd_doctor, "_fix_dotenv_perms", side_effect=planned_then_applied),
            patch.object(cmd_doctor, "_gateway_dotenv_safety_problem", return_value=""),
            patch.object(cmd_doctor, "_fix_pristine_backup", side_effect=planned_then_applied),
            patch.object(
                cmd_doctor,
                "_fix_plugin_registry_required",
                side_effect=planned_then_applied,
            ) as fix_plugin_reg,
            # _fix_connector_residue is intentionally NOT wired into --fix (D7);
            # patch it so a regression that re-adds it would surface as an extra row.
            patch.object(cmd_doctor, "_fix_connector_residue", return_value=("pass", "ok")) as fix_residue,
        ):
            cmd_doctor._run_fixers(
                cfg,
                result,
                assume_yes=True,
                json_out=True,
                dry_run=False,
            )

        self.assertEqual(result.checks, [])
        self.assertEqual(len(result.repairs), 23)
        self.assertEqual(result.repair_summary.applied, 8)
        self.assertEqual(result.repair_summary.manual, 1)
        self.assertEqual(result.repair_summary.noop, 14)
        self.assertEqual(fix_plugin_reg.call_count, 1)
        self.assertTrue(fix_plugin_reg.call_args.kwargs["plan_only"])
        fix_residue.assert_not_called()
        self.assertNotIn(
            "connector residue",
            [record["label"] for record in result.repairs],
        )

    def test_dry_run_flag_is_exposed_on_click_command(self):
        from defenseclaw.commands.cmd_doctor import doctor

        opts = {p.name: p for p in doctor.params}
        self.assertIn("dry_run", opts)
        self.assertTrue(opts["dry_run"].is_flag)
        self.assertTrue(opts["passive"].is_flag)
        self.assertTrue(opts["fix_ids"].multiple)

    def test_dry_run_banner_discloses_restart_and_no_teardown(self):
        from defenseclaw.commands import cmd_doctor

        banner = cmd_doctor._auto_fix_hint(True)
        self.assertIn("nothing on disk changes", banner)
        self.assertIn("start an enabled stopped watchdog", banner)
        self.assertIn("may start or restart the gateway sidecar", banner)
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
            self._write_overlay(
                data_dir,
                """{
                "providers": [{
                    "name": "acme-internal",
                    "base_url": "https://llm.acme.internal:8443",
                    "base_provider_type": "openai"
                }]
            }""",
            )
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
            self._write_overlay(
                data_dir,
                """{
                "providers": [{
                    "name": "acme-internal",
                    "domains": ["llm.acme.internal"],
                    "base_url": "https://llm.acme.internal:8443",
                    "base_provider_type": "openai"
                }]
            }""",
            )
            r = _DoctorResult()
            _check_custom_provider_overlay(self._make_cfg(data_dir), r)
            warn_checks = [c for c in r.checks if c["status"] == "warn" and "not covered by domains" in c["detail"]]
            self.assertEqual(
                warn_checks,
                [],
                "domains-coverage warn should not fire when host is listed",
            )

    def test_subdomain_coverage_does_not_warn(self):
        # domains entry "acme.internal" should cover a base_url host of
        # "llm.acme.internal" via the suffix rule. This mirrors how the
        # Go gateway's matchProviderDomain treats the domain entry as a
        # substring match anchored at host or subdomain boundaries.
        import tempfile

        with tempfile.TemporaryDirectory() as data_dir:
            self._write_overlay(
                data_dir,
                """{
                "providers": [{
                    "name": "acme-internal",
                    "domains": ["acme.internal"],
                    "base_url": "https://llm.acme.internal:8443",
                    "base_provider_type": "openai"
                }]
            }""",
            )
            r = _DoctorResult()
            _check_custom_provider_overlay(self._make_cfg(data_dir), r)
            warn_checks = [c for c in r.checks if c["status"] == "warn" and "not covered by domains" in c["detail"]]
            self.assertEqual(warn_checks, [], r.checks)

    def test_entry_without_base_url_skips_domain_check(self):
        # When the overlay extends a built-in (env_keys only) without
        # declaring base_url, there is nothing for inferProviderFromURL
        # to match against and the check has no opinion.
        import tempfile

        with tempfile.TemporaryDirectory() as data_dir:
            self._write_overlay(
                data_dir,
                """{
                "providers": [{
                    "name": "openai",
                    "env_keys": ["MY_OPENAI_KEY"]
                }]
            }""",
            )
            r = _DoctorResult()
            _check_custom_provider_overlay(self._make_cfg(data_dir), r)
            warn_checks = [c for c in r.checks if c["status"] == "warn" and "not covered by domains" in c["detail"]]
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

        # The in-process server stands in for this account's gateway, so it
        # is not reported as a foreign process holding the port.
        holder = patch("defenseclaw.commands.cmd_doctor._gateway_port_holder", return_value="")
        holder.start()
        self.addCleanup(holder.stop)

        # Records every path + header set the server received, so a test can
        # prove the auth header was NOT replayed to the redirect target.
        self.requests: list[dict] = []
        recorder = self.requests
        self.health_body = json.dumps(
            {
                "gateway": {
                    "state": "running",
                    "details": {"inventory": "x" * 2200},
                },
                "watcher": {"state": "running"},
                "guardrail": {"state": "running"},
                "api": {"state": "running"},
                "connectors": [
                    {"name": "codex", "state": "running"},
                    {"name": "claudecode", "state": "running"},
                ],
            }
        ).encode("utf-8")
        health_body = self.health_body

        class _Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):  # silence test output
                pass

            def _record_and_route(self):
                recorder.append(
                    {
                        "path": self.path,
                        "headers": {k.lower(): v for k, v in self.headers.items()},
                    }
                )
                if self.path == "/redirect":
                    # 302 to a different path that, if followed, would receive
                    # the replayed credential header.
                    self.send_response(302)
                    self.send_header("Location", "/leaked")
                    self.end_headers()
                elif self.path == "/trickle":
                    self.send_response(200)
                    self.send_header("Content-Length", "20")
                    self.end_headers()
                    for _ in range(20):
                        self.wfile.write(b"x")
                        self.wfile.flush()
                        time.sleep(0.1)
                else:
                    body = health_body if self.path == "/health" else b"reached"
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

    def test_probe_timeout_is_a_total_wall_clock_deadline(self):
        from defenseclaw.commands.cmd_doctor import _http_probe

        started = time.monotonic()
        status, body = _http_probe(self._url("/trickle"), timeout=0.12)
        elapsed = time.monotonic() - started

        self.assertEqual(status, 0)
        self.assertIn("total deadline", body)
        self.assertLess(elapsed, 1.0)

    def test_published_probe_result_does_not_wait_for_worker_teardown(self):
        import queue
        import threading

        from defenseclaw.commands import cmd_doctor

        real_queue = queue.Queue
        result_published = threading.Event()
        release_teardown = threading.Event()

        class _TeardownGatedQueue(real_queue):
            def put_nowait(self, item):
                super().put_nowait(item)
                result_published.set()
                release_teardown.wait(timeout=5)

        try:
            with (
                patch.object(cmd_doctor.queue, "Queue", _TeardownGatedQueue),
                patch.object(cmd_doctor, "_http_probe_once", return_value=(200, "reached")),
            ):
                status, body = cmd_doctor._http_probe(self._url("/unused"), timeout=1.0)

            self.assertTrue(result_published.is_set())
            self.assertEqual((status, body), (200, "reached"))
        finally:
            release_teardown.set()

    def test_sidecar_health_parses_complete_large_multi_connector_document(self):
        self.assertGreater(len(self.health_body), 2_000)
        cfg = SimpleNamespace(
            openshell=None,
            gateway=SimpleNamespace(api_port=self.port),
        )
        result = _DoctorResult()

        _check_sidecar(cfg, result)

        self.assertFalse(
            any(c["label"] == "Sidecar health JSON" for c in result.checks),
            result.checks,
        )
        subsystem_rows = {
            c["label"].strip().removeprefix("└─ "): c["status"] for c in result.checks if "└─" in c["label"]
        }
        self.assertEqual(subsystem_rows["gateway"], "pass")
        self.assertEqual(subsystem_rows["watcher"], "pass")
        self.assertEqual(subsystem_rows["guardrail"], "pass")
        self.assertEqual(subsystem_rows["api"], "pass")

    def test_structured_probe_rejects_response_over_its_byte_bound(self):
        from defenseclaw.commands.cmd_doctor import _http_probe

        status, body = _http_probe(
            self._url("/health"),
            timeout=5.0,
            response_limit=128,
            allow_truncation=False,
        )

        self.assertEqual(status, 200)
        self.assertEqual(body, "response exceeds 128-byte limit")

    @patch(
        "defenseclaw.commands.cmd_doctor._http_probe",
        return_value=(200, "response exceeds 1048576-byte limit"),
    )
    def test_sidecar_health_surfaces_oversized_document_reason(self, _probe):
        cfg = SimpleNamespace(
            openshell=None,
            gateway=SimpleNamespace(api_port=self.port),
        )
        result = _DoctorResult()

        _check_sidecar(cfg, result)

        row = next(c for c in result.checks if c["label"] == "Sidecar health JSON")
        self.assertEqual(row["status"], "warn")
        self.assertEqual(row["detail"], "response exceeds 1048576-byte limit")


class GuardrailProxyMultiConnectorTests(unittest.TestCase):
    """D6: whether the proxy port is 'intentionally closed' is decided over the
    FULL active set. A proxy peer (openclaw/zeptoclaw) that binds port 4000
    forces the real /health probe even when the primary is hook-enforced.
    """

    def _cfg(self, connectors, mode="observe"):
        cfg = MagicMock()
        cfg.active_connectors.return_value = connectors
        cfg.guardrail = SimpleNamespace(mode=mode)
        return cfg

    @patch("defenseclaw.commands.cmd_doctor._http_probe")
    def test_no_active_connector_skips_proxy_probe(self, mock_probe):
        # GAP-2291: after the last connector is removed nothing needs the
        # proxy, so doctor must not FAIL (and exit 1) on a closed port.
        from defenseclaw.commands.cmd_doctor import _check_guardrail_proxy

        cfg = self._cfg([])
        cfg.guardrail = SimpleNamespace(enabled=True, mode="observe", port=4000)
        result = _DoctorResult()

        _check_guardrail_proxy(cfg, result)

        mock_probe.assert_not_called()
        self.assertEqual(result.failed, 0)
        self.assertEqual(result.checks[0]["status"], "skip")
        self.assertIn("no active connector", result.checks[0]["detail"])

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
        cfg.guardrail.effective_mode = lambda name: cfg.guardrail.connectors[name].mode or cfg.guardrail.mode

        detail = _guardrail_proxy_intentionally_closed(cfg)

        self.assertIn("codex (mode=action via PreToolUse deny)", detail)
        self.assertIn("hermes (mode=observe)", detail)
        self.assertNotIn("codex, hermes (mode=observe)", detail)
        self.assertIn("proxy port intentionally closed", detail)

    def test_multi_hook_action_mode_reports_action_once_when_uniform(self):
        from defenseclaw.commands.cmd_doctor import (
            _guardrail_proxy_intentionally_closed,
        )

        detail = _guardrail_proxy_intentionally_closed(self._cfg(["codex", "hermes"], mode="action"))

        self.assertIn("hook-enforced for codex, hermes", detail)
        self.assertIn("mode=action via PreToolUse deny", detail)
        self.assertIn("proxy port intentionally closed", detail)

    def test_multi_hook_action_mode_preserves_omnigent_policy_semantics(self):
        from defenseclaw.commands.cmd_doctor import (
            _guardrail_proxy_intentionally_closed,
        )

        detail = _guardrail_proxy_intentionally_closed(self._cfg(["codex", "omnigent"], mode="action"))

        self.assertTrue(detail.startswith("configured for"), detail)
        self.assertIn("codex (mode=action via PreToolUse deny)", detail)
        self.assertIn(
            "omnigent (native-degraded; mode=action via ALLOW/ASK/DENY; live policy generation unverified)",
            detail,
        )
        self.assertIn("proxy port intentionally closed", detail)

    def test_single_omnigent_status_preserves_native_degraded_posture(self):
        from defenseclaw.commands.cmd_doctor import (
            _guardrail_proxy_intentionally_closed,
        )

        detail = _guardrail_proxy_intentionally_closed(
            self._cfg(["omnigent"], mode="action")
        )

        self.assertIn("native-degraded", detail)
        self.assertIn("mode=action via ALLOW/ASK/DENY", detail)
        self.assertIn("live policy generation unverified", detail)
        self.assertNotIn("policy-enforced", detail)
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

        detail = _guardrail_proxy_intentionally_closed(self._cfg(["cursor"]))
        self.assertIn("hook-driven for cursor", detail)
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

    def test_json_output_has_short_alias(self):
        from defenseclaw.commands.cmd_doctor import doctor

        json_option = next(param for param in doctor.params if param.name == "json_out")
        self.assertIn("--json-output", json_option.opts)
        self.assertIn("--json", json_option.opts)

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


class TestLegacySandboxDoctor(unittest.TestCase):
    """The removed openshell-sandbox mode is reported with its cleanup command."""

    def _cfg(self, data_dir: str, *, legacy: bool) -> Config:
        cfg = Config(
            data_dir=data_dir,
            audit_db=os.path.join(data_dir, "audit.db"),
            gateway=GatewayConfig(host="127.0.0.1"),
            openshell=OpenShellConfig(mode="standalone" if legacy else ""),
        )
        cfg._source_config_version = 8
        return cfg

    def test_legacy_install_warns_with_cleanup_remediation(self):
        from defenseclaw.commands.cmd_doctor import _check_legacy_sandbox

        with tempfile.TemporaryDirectory() as data_dir:
            result = _DoctorResult()
            _check_legacy_sandbox(self._cfg(data_dir, legacy=True), result)
        self.assertEqual(result.warned, 1, result.checks)
        row = result.checks[0]
        self.assertEqual(row["check_id"], "doctor.sandbox.legacy-install")
        self.assertIn("openshell.mode=standalone", row["detail"])
        self.assertIn("defenseclaw sandbox legacy-cleanup", row["remediation"])

    def test_leftover_data_dir_artifacts_are_evidence_too(self):
        from defenseclaw.commands.cmd_doctor import _check_legacy_sandbox

        with tempfile.TemporaryDirectory() as data_dir:
            with open(os.path.join(data_dir, "openclaw-ownership-backup.json"), "w") as fh:
                fh.write("{}")
            result = _DoctorResult()
            _check_legacy_sandbox(self._cfg(data_dir, legacy=False), result)
        self.assertEqual(result.warned, 1, result.checks)
        self.assertIn("openclaw-ownership-backup.json", result.checks[0]["detail"])

    def test_host_mode_install_emits_nothing(self):
        from defenseclaw.commands.cmd_doctor import _check_legacy_sandbox

        with tempfile.TemporaryDirectory() as data_dir:
            result = _DoctorResult()
            _check_legacy_sandbox(self._cfg(data_dir, legacy=False), result)
        self.assertEqual(result.checks, [])

    def test_degraded_legacy_sandbox_health_warns_instead_of_failing(self):
        health = {
            "gateway": {"state": "disabled"},
            "watcher": {"state": "disabled"},
            "guardrail": {"state": "disabled"},
            "api": {"state": "running"},
            "telemetry": {"state": "running"},
            "sandbox": {
                "state": "degraded",
                "last_error": "legacy standalone install detected — run `defenseclaw sandbox legacy-cleanup`",
            },
        }
        with tempfile.TemporaryDirectory() as data_dir:
            cfg = self._cfg(data_dir, legacy=True)
            result = _DoctorResult()
            with patch(
                "defenseclaw.commands.cmd_doctor._http_probe",
                return_value=(200, json.dumps(health)),
            ):
                _check_sidecar(cfg, result)
        sandbox = next(row for row in result.checks if row.get("label", "").strip().endswith("sandbox"))
        self.assertEqual(sandbox["status"], "warn")
        self.assertIn("legacy-cleanup", sandbox["detail"])

    def test_failing_optional_destination_warns_on_running_telemetry(self):
        # A jsonl destination the gateway cannot reach yet runs deferred: warn,
        # do not pass or fail (GAP-1265).
        health = {
            "gateway": {"state": "disabled"},
            "watcher": {"state": "disabled"},
            "guardrail": {"state": "disabled"},
            "api": {"state": "running"},
            "telemetry": {
                "state": "running",
                "details": {
                    "optional_destination_state": "degraded",
                    "optional_destination_failure_summary": "rv13:degraded:file_write_failed",
                },
            },
        }
        with tempfile.TemporaryDirectory() as data_dir:
            result = _DoctorResult()
            with patch(
                "defenseclaw.commands.cmd_doctor._http_probe",
                return_value=(200, json.dumps(health)),
            ):
                _check_sidecar(self._cfg(data_dir, legacy=False), result)
        telemetry = next(row for row in result.checks if row.get("label", "").strip().endswith("telemetry"))
        self.assertEqual(telemetry["status"], "warn", telemetry)
        self.assertIn("rv13:degraded:file_write_failed", telemetry["detail"])

    def test_openshell_sandbox_running_is_not_a_stale_sidecar(self):
        # openshell.enabled makes the gateway run the sandbox subsystem; its
        # "running" must not read as a stale sidecar or drive restarts.
        from defenseclaw.commands.cmd_doctor import _gateway_service_health_assessment

        health = {
            "gateway": {"state": "disabled"},
            "watcher": {"state": "disabled"},
            "guardrail": {"state": "disabled"},
            "api": {"state": "running"},
            "telemetry": {"state": "running"},
            "sandbox": {"state": "running", "details": {"ingress": "127.0.0.1:18971", "egress": "127.0.0.1:18972"}},
        }
        with tempfile.TemporaryDirectory() as data_dir:
            cfg = self._cfg(data_dir, legacy=False)
            cfg.openshell.enabled = True
            result = _DoctorResult()
            with (
                patch("defenseclaw.commands.cmd_doctor.sys.platform", "linux"),
                patch(
                    "defenseclaw.commands.cmd_doctor._http_probe",
                    return_value=(200, json.dumps(health)),
                ),
            ):
                _check_sidecar(cfg, result)
                _status, detail = _gateway_service_health_assessment(cfg, health)
        sandbox = next(row for row in result.checks if row.get("label", "").strip().endswith("sandbox"))
        self.assertEqual(sandbox["status"], "pass", sandbox)
        # Other subsystems of this fixture may drift; the sandbox does not.
        self.assertNotIn("sandbox", detail)

        # Sandboxes enabled but reported disabled is a stale sidecar, except
        # where the gateway turns them off on purpose.
        stale = dict(health, sandbox={"state": "disabled"})
        with tempfile.TemporaryDirectory() as data_dir:
            cfg = self._cfg(data_dir, legacy=False)
            cfg.openshell.enabled = True
            with patch("defenseclaw.commands.cmd_doctor.sys.platform", "linux"):
                status, detail = _gateway_service_health_assessment(cfg, stale)
            self.assertEqual(status, "repairable", detail)
            self.assertIn("sandbox is enabled in config but reports disabled", detail)
            with patch("defenseclaw.commands.cmd_doctor.sys.platform", "win32"):
                status, detail = _gateway_service_health_assessment(cfg, stale)
            self.assertNotIn("sandbox", detail)

    def test_degraded_legacy_sandbox_does_not_block_gateway_repairs(self):
        from defenseclaw.commands.cmd_doctor import _gateway_service_health_assessment

        with tempfile.TemporaryDirectory() as data_dir:
            cfg = self._cfg(data_dir, legacy=True)
            health = {
                "api": {"state": "running"},
                "gateway": {"state": "disabled"},
                "watcher": {"state": "disabled"},
                "telemetry": {"state": "running"},
                "guardrail": {"state": "disabled"},
                "sandbox": {"state": "degraded"},
            }
            status, detail = _gateway_service_health_assessment(cfg, health)
        self.assertNotEqual(status, "operational", detail)
        self.assertNotIn("sandbox", detail)


@unittest.skipIf(os.name == "nt", "the POSIX repair command")
class DoctorScannerRepairHintTests(unittest.TestCase):
    """A failed skill-scanner check names the command that repairs it (manual test R2-44)."""

    _CFG = SimpleNamespace(
        scanners=SimpleNamespace(
            skill_scanner=SimpleNamespace(binary="/opt/dc/.venv/bin/skill-scanner"),
            mcp_scanner=SimpleNamespace(binary="mcp-scanner"),
        )
    )

    def _run(self, side_effect):
        result = _DoctorResult()
        with (
            patch("defenseclaw.commands.cmd_doctor.resolve_scanner_binary", side_effect=lambda b: b),
            patch("defenseclaw.commands.cmd_doctor.subprocess.run", side_effect=side_effect),
        ):
            _check_scanners(self._CFG, result)
        return result.checks[0]

    def test_timeout_warns_to_retry_then_names_the_resolver(self):
        import subprocess as sp

        check = self._run(sp.TimeoutExpired(cmd="skill-scanner", timeout=30))
        self.assertEqual(check["status"], "warn")
        self.assertIn("did not answer --version within 30 s", check["detail"])
        self.assertIn("run `defenseclaw doctor` again", check["detail"])
        self.assertIn("`bash defenseclaw-upgrade.sh --yes`", check["detail"])
        self.assertIn("/docs/get-started/upgrade/", check["detail"])
        self.assertNotIn("repair path", check["detail"])

    def test_unstartable_launcher_names_the_resolver(self):
        check = self._run(OSError("exec format error"))
        self.assertEqual(check["status"], "fail")
        self.assertIn("could not start: exec format error; repair the launcher with the release upgrade resolver",
                      check["detail"])


if __name__ == "__main__":
    unittest.main()


def test_a_stopped_local_observability_stack_is_not_a_failure():
    from defenseclaw.commands import cmd_doctor

    local = SimpleNamespace(name="local-observability", preset="")
    remote = SimpleNamespace(name="splunk", preset="")
    remote_local_preset = SimpleNamespace(name="local-observability", preset="local-otlp", endpoint="stack-host:4317")
    live = SimpleNamespace(circuit_state="open", last_failure_class="network")
    with patch.object(cmd_doctor.socket, "create_connection", side_effect=ConnectionRefusedError):
        assert cmd_doctor._local_observability_stack_stopped(local, live, "fail")
        assert not cmd_doctor._local_observability_stack_stopped(remote, live, "fail")
        assert not cmd_doctor._local_observability_stack_stopped(remote_local_preset, live, "fail")
        assert cmd_doctor._local_observability_stack_stopped(
            remote_local_preset, live, "fail", secure_client=True
        )
    with patch.object(cmd_doctor.socket, "create_connection", return_value=contextlib.nullcontext()):
        # The stack is up, so its collector failing is a real failure.
        assert not cmd_doctor._local_observability_stack_stopped(local, live, "fail")


def test_a_signature_pack_that_fails_its_pin_is_a_doctor_warning(tmp_path):
    """GAP-0177: the refusal is a WARN naming the pack and both digests, not a gateway.log line."""
    from defenseclaw.commands import cmd_doctor

    pack = tmp_path / "pack.json"
    pack.write_text(json.dumps({"version": 1, "signatures": [{
        "id": "pinned-ai", "name": "Pinned", "vendor": "Example", "category": "ai_cli", "confidence": 0.7}]}))
    pinned = "sha256:" + "0" * 64
    discovery = SimpleNamespace(
        enabled=True, signature_packs=[str(pack)], signature_pack_digests={str(pack): pinned},
        allow_workspace_signatures=False, scan_roots=[],
    )
    cfg = SimpleNamespace(ai_discovery=discovery, data_dir=str(tmp_path))
    result = _DoctorResult()
    cmd_doctor._check_signature_packs(cfg, result)
    [check] = result.checks
    assert check["status"] == "warn" and check["reason_code"] == "signature-pack-refused"
    assert str(pack.resolve()) in check["detail"] and pinned in check["detail"]

    discovery.signature_pack_digests = {}
    result = _DoctorResult()
    cmd_doctor._check_signature_packs(cfg, result)
    assert [c["status"] for c in result.checks] == ["pass"]

    # GAP-0220: a configured pack whose file is gone is not "0 loaded" PASS.
    pack.unlink()
    result = _DoctorResult()
    cmd_doctor._check_signature_packs(cfg, result)
    [check] = result.checks
    assert check["status"] == "warn" and f"{pack}: file not found" in check["detail"]



def test_secure_client_config_check_keeps_v8_record(tmp_path):
    from defenseclaw.commands import cmd_doctor

    config = tmp_path / "config.yaml"
    config.write_text("config_version: 8\n", encoding="utf-8")
    cfg = SimpleNamespace(data_dir=os.fspath(tmp_path))
    result = _DoctorResult()
    with (
        patch("defenseclaw.commands.cmd_status._enterprise_profile", return_value="secure_client"),
        patch("defenseclaw.config_inspect.inspect_v8_config", return_value=SimpleNamespace(valid=True)),
    ):
        cmd_doctor._check_config(cfg, result)
    row = result.checks[-1]
    assert row["check_id"] == "doctor.config.canonical-v8"
    assert row["detail"] == f"{config}; canonical schema v8 valid"

    policy_result = _DoctorResult()
    with patch("defenseclaw.commands.cmd_status._enterprise_profile", return_value="secure_client"):
        cmd_doctor._check_policy_state(
            SimpleNamespace(deployment_mode="managed_enterprise"),
            policy_result,
            live_health={"policy": {"effective_digest": "sha256:" + "a" * 64}},
        )
    assert policy_result.checks == []




def test_policy_digest_probe_unavailable_does_not_pass():
    from defenseclaw.commands import cmd_doctor

    result = _DoctorResult()
    with (
        patch("defenseclaw.commands.cmd_status._enterprise_profile", return_value=""),
        patch.object(cmd_doctor, "_local_policy_digest", return_value=None),
    ):
        cmd_doctor._check_policy_state(
            SimpleNamespace(), result,
            live_health={"policy": {"effective_digest": "sha256:" + "a" * 64, "generation": 3}},
        )
    row = result.checks[-1]
    assert row["status"] == "warn"
    assert "comparison" in row["detail"]
