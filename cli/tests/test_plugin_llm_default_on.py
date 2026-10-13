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

"""P-F: the plugin LLM lane is default-ON when a usable model is configured.

``PluginScannerWrapper.scan(use_llm=...)`` is tri-state:
  * None  → auto: enable the LLM analyzer iff a model and auth resolve.
  * True  → request it; loud-degrade (stderr) when unavailable.
  * False → force off (``--no-llm``).
"""

import io
import os
import sys
import unittest
from contextlib import redirect_stderr
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.config import LLMConfig
from defenseclaw.scanner.plugin import PluginScannerWrapper


class _StubResult:
    findings: list = []


class PluginLLMDefaultOnTests(unittest.TestCase):
    def _run(self, llm, use_llm):
        captured: dict = {}
        stderr = io.StringIO()

        def fake_scan_plugin(target, options):
            captured["options"] = options
            return _StubResult()

        with patch.dict(os.environ, {"DEFENSECLAW_LLM_KEY": ""}), \
                patch("defenseclaw.scanner.plugin.scan_plugin", fake_scan_plugin), \
                redirect_stderr(stderr):
            PluginScannerWrapper(llm=llm).scan("/tmp/x", use_llm=use_llm)
        captured["stderr"] = stderr.getvalue()
        return captured

    def test_auto_enables_when_model_configured(self):
        llm = LLMConfig(model="claude-3-5-haiku", provider="anthropic", api_key="k")
        cap = self._run(llm, None)
        self.assertTrue((cap["options"].llm_override or {}).get("enabled"))

    def test_auto_off_when_no_model(self):
        cap = self._run(LLMConfig(), None)
        self.assertFalse((cap["options"].llm_override or {}).get("enabled"))
        # auto-off is the expected state, not a degrade — no warning.
        self.assertEqual(cap["stderr"], "")

    def test_auto_with_cloud_model_but_no_key_warns_and_runs_static(self):
        llm = LLMConfig(model="claude-3-5-haiku", provider="anthropic")
        cap = self._run(llm, None)
        self.assertFalse((cap["options"].llm_override or {}).get("enabled"))
        self.assertIn("LLM analyzer skipped", cap["stderr"])
        self.assertIn("continuing with local analyzers", cap["stderr"])

    def test_explicit_on_with_cloud_model_but_no_key_degrades_loudly(self):
        llm = LLMConfig(model="claude-3-5-haiku", provider="anthropic")
        cap = self._run(llm, True)
        self.assertFalse((cap["options"].llm_override or {}).get("enabled"))
        self.assertIn("running static", cap["stderr"])
        self.assertIn("DEFENSECLAW_LLM_KEY is not configured", cap["stderr"])

    def test_explicit_off_disables_even_with_model(self):
        llm = LLMConfig(model="claude-3-5-haiku", provider="anthropic", api_key="k")
        cap = self._run(llm, False)
        self.assertFalse((cap["options"].llm_override or {}).get("enabled"))

    def test_explicit_on_without_model_degrades_loudly(self):
        cap = self._run(LLMConfig(), True)
        # static lane still ran (no crash), LLM not enabled, and a loud warning.
        self.assertFalse((cap["options"].llm_override or {}).get("enabled"))
        self.assertIn("no model", cap["stderr"].lower())


if __name__ == "__main__":
    unittest.main()


class WindowsRuntimePluginScanJudgeTests(unittest.TestCase):
    """GAP-1408: the standalone Windows runtime ran plugin scans rules-only."""

    def _run(self, env):
        import contextlib
        import re

        root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        with open(os.path.join(root, "cmd", "defenseclaw-scanners", "main.go"), encoding="utf-8") as stream:
            script = re.search(r"pluginScanScript = `(.*?)`", stream.read(), re.S).group(1)
        captured: dict = {}

        class _Result:
            def to_dict(self):
                return {"scanner": "plugin-scanner", "target": "/p", "findings": []}

        def fake_scan_plugin(target, options):
            captured["override"] = options.llm_override
            return _Result()

        clean = {k: "" for k in ("DEFENSECLAW_LLM_KEY", "DEFENSECLAW_SCANNER_LLM_API_KEY")}
        with patch.dict(os.environ, {**clean, **env}), \
                patch("defenseclaw.scanner.plugin_scanner.scan_plugin", fake_scan_plugin), \
                patch("defenseclaw.scanner.rulepack.overlay_findings", return_value=[]), \
                patch("defenseclaw.config.load", return_value=None), \
                patch.object(sys, "argv", ["plugin-scan", "/p"]), \
                contextlib.redirect_stdout(io.StringIO()):
            exec(compile(script, "pluginScanScript", "exec"), {"__name__": "__main__"})
        return captured

    def test_runtime_runs_the_configured_judge(self):
        cap = self._run({"DEFENSECLAW_SCANNER_LLM_MODEL": "openai/gpt-4o-mini",
                         "DEFENSECLAW_SCANNER_LLM_API_KEY": "k"})
        self.assertEqual(cap["override"]["model"], "openai/gpt-4o-mini")
        self.assertTrue(cap["override"]["enabled"])

    def test_runtime_judge_without_its_key_stops_the_scan(self):
        with self.assertRaises(SystemExit) as stop:
            self._run({"DEFENSECLAW_SCANNER_LLM_MODEL": "openai/gpt-4o-mini"})
        self.assertIn("openai/gpt-4o-mini", str(stop.exception.code))

    def test_windows_bedrock_judge_without_a_key_stops_the_scan(self):
        """GAP-1444: a key-less Bedrock judge (api_key mode) only warned on Windows; GAP-1460: iam_credentials."""
        from defenseclaw.config import BedrockKeyConfig, LLMConfig
        from defenseclaw.scanner import _llm_env

        model = "bedrock/us.anthropic.claude-haiku-4-5-20251001-v1:0"
        with patch.object(_llm_env, "_bedrock_needs_credential_source", return_value=True), \
                patch.object(_llm_env, "_aws_credential_chain_found", return_value=False), \
                patch.dict(os.environ, {"AWS_BEARER_TOKEN_BEDROCK": "", "DEFENSECLAW_LLM_KEY": ""}):
            with self.assertRaises(SystemExit) as stop:
                self._run({"DEFENSECLAW_SCANNER_LLM_MODEL": model})
            self.assertIn(model, str(stop.exception.code))
            keyed = self._run({"DEFENSECLAW_SCANNER_LLM_MODEL": model, "DEFENSECLAW_SCANNER_LLM_API_KEY": "k"})
            self.assertTrue(keyed["override"]["enabled"])
            # GAP-1460: iam_credentials signs with the keys in the variables
            # llm.bedrock names; the runtime gets them with the auth mode.
            iam = LLMConfig(model=model, bedrock=BedrockKeyConfig(
                auth_mode="iam_credentials", access_key_env="CORP_BEDROCK_AK", secret_key_env="CORP_BEDROCK_SK"))
            self.assertFalse(_llm_env.llm_analyzer_ready(iam))
            with patch.dict(os.environ, {"CORP_BEDROCK_AK": "ak", "CORP_BEDROCK_SK": "sk"}):
                self.assertTrue(_llm_env.llm_analyzer_ready(iam))
            runtime = self._run({"DEFENSECLAW_SCANNER_LLM_MODEL": model, "AWS_ACCESS_KEY_ID": "ak",
                                 "AWS_SECRET_ACCESS_KEY": "sk", "DEFENSECLAW_SCANNER_LLM_BEDROCK_AUTH_MODE": "iam_credentials"})
            self.assertTrue(runtime["override"]["enabled"])
        with patch.object(_llm_env, "_bedrock_needs_credential_source", return_value=False):
            self.assertTrue(_llm_env.llm_analyzer_ready(LLMConfig(model=model)))
