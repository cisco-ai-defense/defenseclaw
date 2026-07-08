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
