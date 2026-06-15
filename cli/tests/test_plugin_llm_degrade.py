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

"""Root-4 / P-F regression tests: the plugin LLM lane degrades gracefully.

``call_llm`` *raises* (``SubprocessExitError``) when the LLM bridge
subprocess exits non-zero — the usual outcome when the provider/backend
is unreachable. Before this fix the exception propagated out of the
analyzer loop and aborted the whole plugin scan, discarding the
pattern-based findings already collected. The lane must instead
skip-and-continue: surface the failure as a finding and let the scan
complete.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.scanner.plugin_scanner import llm_analyzer, scan_plugin  # noqa: E402
from defenseclaw.scanner.plugin_scanner.analyzer import ScanContext, SourceFile  # noqa: E402
from defenseclaw.scanner.plugin_scanner.llm_client import SubprocessExitError  # noqa: E402
from defenseclaw.scanner.plugin_scanner.types import PluginManifest, PluginScanOptions  # noqa: E402


def _raise_subprocess_exit(*_a, **_kw):
    raise SubprocessExitError(1, "litellm: provider unreachable (connection refused)")


def _raise_generic(*_a, **_kw):
    raise RuntimeError("unexpected bridge failure")


class LLMAnalyzerDegradeTests(unittest.TestCase):
    """``LLMAnalyzer.analyze`` converts a raised call_llm into a finding."""

    def setUp(self):
        self._orig = llm_analyzer.call_llm

    def tearDown(self):
        llm_analyzer.call_llm = self._orig

    def _analyze(self):
        ctx = ScanContext(
            plugin_dir="/tmp/x",
            manifest=PluginManifest(name="p", source="package.json"),
            source_files=[
                SourceFile(
                    path="/tmp/x/index.js",
                    rel_path="index.js",
                    content="console.log('hi')",
                    lines=[],
                    code_lines=[],
                    in_test_path=False,
                )
            ],
        )
        analyzer = llm_analyzer.LLMAnalyzer({"model": "test-model"})
        return analyzer.analyze(ctx)

    def test_subprocess_exit_becomes_scan_error_finding(self):
        llm_analyzer.call_llm = _raise_subprocess_exit
        findings = self._analyze()  # must not raise
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "LLM-SCAN-ERROR")
        self.assertEqual(findings[0].severity, "MEDIUM")

    def test_generic_exception_also_degrades(self):
        llm_analyzer.call_llm = _raise_generic
        findings = self._analyze()  # must not raise
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "LLM-SCAN-ERROR")


class RunMetaLLMDegradeTests(unittest.TestCase):
    """``run_meta_llm`` returns the empty contract instead of raising."""

    def setUp(self):
        self._orig = llm_analyzer.call_llm

    def tearDown(self):
        llm_analyzer.call_llm = self._orig

    def test_raised_call_llm_returns_empty_contract(self):
        llm_analyzer.call_llm = _raise_subprocess_exit
        ctx = ScanContext(plugin_dir="/tmp/x", manifest=None)
        ctx.previous_findings = []

        result = llm_analyzer.run_meta_llm({"model": "test-model"}, ctx)  # must not raise

        self.assertEqual(result["new_findings"], [])
        self.assertEqual(result["false_positive_advisories"], [])
        # No source files were supplied → the no-source warning is still
        # surfaced even though the LLM call itself failed.
        self.assertIsNotNone(result["no_source_files_warning"])


class ScanPluginNoAbortTests(unittest.TestCase):
    """End-to-end: a provider-down LLM lane must not abort the scan."""

    def setUp(self):
        self._orig = llm_analyzer.call_llm
        llm_analyzer.call_llm = _raise_subprocess_exit

    def tearDown(self):
        llm_analyzer.call_llm = self._orig

    def test_scan_completes_and_surfaces_llm_error(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "package.json"), "w", encoding="utf-8") as fh:
                json.dump({"name": "demo-plugin", "version": "1.0.0"}, fh)
            with open(os.path.join(d, "index.js"), "w", encoding="utf-8") as fh:
                fh.write("module.exports = () => console.log('hello')\n")

            # Manually enable the LLM lane (the default-on *enable* lives
            # in scanner/plugin.py — out of this lane); here we exercise
            # the degrade path the orchestrator must survive.
            options = PluginScanOptions(
                llm_override={"enabled": True, "model": "test-model"}
            )
            result = scan_plugin(d, options)  # must not raise

        rule_ids = [getattr(f, "rule_id", None) for f in result.findings]
        self.assertIn(
            "LLM-SCAN-ERROR", rule_ids,
            "the LLM failure must be surfaced as a finding, not swallowed or raised",
        )


if __name__ == "__main__":
    unittest.main()
