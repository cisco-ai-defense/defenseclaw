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

import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.commands.cmd_doctor import (
    _ANTHROPIC_DEFAULT_PROBE_MODEL,
    _anthropic_probe_model,
    _check_guardrail_proxy,
    _check_llm_api_key,
    _DoctorResult,
)
from defenseclaw.config import Config, GatewayConfig, GuardrailConfig, OpenShellConfig


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
    @patch("defenseclaw.commands.cmd_doctor._resolve_api_key",
           return_value="ABSKtest-not-an-anthropic-key")
    @patch("defenseclaw.commands.cmd_doctor._verify_anthropic")
    @patch("defenseclaw.commands.cmd_doctor._verify_openai")
    def test_bedrock_inference_profile_does_not_route_to_anthropic(
        self, mock_openai, mock_anthropic, _mock_resolve,
    ):
        cfg = self._make_cfg(
            model="amazon-bedrock/us.anthropic.claude-haiku-4-5-20251001-v1:0",
            api_key_env="BIFROST_API_KEY",
        )
        r = _DoctorResult()

        _check_llm_api_key(cfg, r)

        mock_anthropic.assert_not_called()
        mock_openai.assert_not_called()
        self.assertEqual(r.failed, 0, r.checks)
        self.assertEqual(r.passed, 1)
        self.assertTrue(
            any("cannot verify provider" in (c.get("detail") or "") for c in r.checks),
            r.checks,
        )

    @patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-ant-test"}, clear=False)
    @patch("defenseclaw.commands.cmd_doctor._resolve_api_key", return_value="sk-ant-test")
    @patch("defenseclaw.commands.cmd_doctor._verify_anthropic")
    def test_anthropic_prefix_routes_to_anthropic_verify(
        self, mock_anthropic, _mock_resolve,
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
        self, mock_openai, _mock_resolve,
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
        self, mock_openai, mock_anthropic, _mock_resolve,
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
    @patch("defenseclaw.commands.cmd_doctor._resolve_api_key",
           return_value="ABSK-bedrock-in-anthropic-slot")
    @patch("defenseclaw.commands.cmd_doctor._verify_anthropic")
    @patch("defenseclaw.commands.cmd_doctor._verify_openai")
    def test_model_prefix_wins_over_env_name(
        self, mock_openai, mock_anthropic, _mock_resolve,
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
        with patch.dict(os.environ,
                        {"DEFENSECLAW_ANTHROPIC_PROBE_MODEL": "claude-3-opus-20240229"},
                        clear=False):
            got = _anthropic_probe_model("")
        self.assertEqual(got, "claude-3-opus-20240229")

    def test_default_when_no_configured_model(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("DEFENSECLAW_ANTHROPIC_PROBE_MODEL", None)
            got = _anthropic_probe_model("")
        self.assertEqual(got, _ANTHROPIC_DEFAULT_PROBE_MODEL)


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


if __name__ == "__main__":
    unittest.main()
