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

"""Root-4 / M6 regression tests for the MCP scanner's unified LLM lane.

Two halves of the same fix:

* **Model-driven analyzer selection.** The ``"auto"`` sentinel runs YARA
  always and adds the LLM analyzer only when a model is actually
  configured — so the lane is default-on without firing (and failing)
  LLM calls on installs with no model. Explicit ``analyzers: yara``
  stays a local-only escape hatch.
* **Graceful degrade.** An unreachable *LLM backend* during a local scan
  must not be conflated with an unreachable *MCP server*: the YARA lane
  ran, so the scan completes with a skip notice instead of a fatal
  "failed to connect to local server".
"""

from __future__ import annotations

import io
import logging
import os
import sys
import unittest
from enum import Enum
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.config import LLMConfig, MCPScannerConfig, MCPServerEntry  # noqa: E402
from defenseclaw.scanner.mcp import (  # noqa: E402
    MCPScannerWrapper,
    _is_llm_backend_error,
)


class _FakeAnalyzerEnum(Enum):
    """Stand-in for the SDK ``AnalyzerEnum`` (not installed in CI).

    Members expose ``.value`` exactly like the real enum, which is all
    ``_parse_analyzers`` consumes.
    """

    YARA = "yara"
    LLM = "llm"
    API = "api"


def _wrapper(
    analyzers: str,
    *,
    model: bool,
    credential: bool = True,
    provider: str = "openai",
) -> MCPScannerWrapper:
    llm = (
        LLMConfig(
            provider=provider,
            model=f"{provider}/test-model",
            api_key="test-key" if credential else "",
        )
        if model
        else LLMConfig()
    )
    return MCPScannerWrapper(MCPScannerConfig(analyzers=analyzers), llm=llm)


class AutoAnalyzerSelectionTests(unittest.TestCase):
    """``analyzers: auto`` is model-driven; explicit lists are verbatim."""

    def _values(self, result):
        self.assertIsNotNone(result, "expected a concrete analyzer list, got None")
        return [a.value for a in result]

    def test_auto_with_model_runs_yara_and_llm(self):
        s = _wrapper("auto", model=True)
        self.assertEqual(self._values(s._parse_analyzers(_FakeAnalyzerEnum)), ["yara", "llm"])

    def test_auto_without_model_is_yara_only(self):
        s = _wrapper("auto", model=False)
        self.assertEqual(self._values(s._parse_analyzers(_FakeAnalyzerEnum)), ["yara"])

    def test_auto_with_cloud_model_but_no_key_warns_and_runs_yara(self):
        s = _wrapper("auto", model=True, credential=False, provider="anthropic")
        captured = io.StringIO()
        with patch.dict(os.environ, {"DEFENSECLAW_LLM_KEY": ""}), patch("sys.stderr", captured):
            selected = s._parse_analyzers(_FakeAnalyzerEnum)
        self.assertEqual(self._values(selected), ["yara"])
        self.assertIn("LLM analyzer skipped", captured.getvalue())
        self.assertIn("continuing with local analyzers", captured.getvalue())

    def test_auto_with_local_model_needs_no_key(self):
        s = _wrapper("auto", model=True, credential=False, provider="ollama")
        self.assertEqual(self._values(s._parse_analyzers(_FakeAnalyzerEnum)), ["yara", "llm"])

    def test_auto_with_bedrock_model_uses_aws_credential_chain(self):
        s = _wrapper("auto", model=True, credential=False, provider="bedrock")
        self.assertEqual(self._values(s._parse_analyzers(_FakeAnalyzerEnum)), ["yara", "llm"])

    def test_auto_is_case_insensitive(self):
        s = _wrapper("AUTO", model=True)
        self.assertEqual(self._values(s._parse_analyzers(_FakeAnalyzerEnum)), ["yara", "llm"])

    def test_explicit_yara_is_escape_hatch_even_with_model(self):
        """An operator who pins ``analyzers: yara`` stays YARA-only."""
        s = _wrapper("yara", model=True)
        self.assertEqual(self._values(s._parse_analyzers(_FakeAnalyzerEnum)), ["yara"])

    def test_explicit_list_honoured_verbatim(self):
        s = _wrapper("yara,llm", model=False)
        self.assertEqual(self._values(s._parse_analyzers(_FakeAnalyzerEnum)), ["yara", "llm"])

    def test_empty_defers_to_sdk_all(self):
        """Empty keeps the legacy 'let the SDK run everything' meaning."""
        s = _wrapper("", model=True)
        self.assertIsNone(s._parse_analyzers(_FakeAnalyzerEnum))


class LLMBackendErrorClassifierTests(unittest.TestCase):

    def test_llm_analyzer_logger_is_llm(self):
        self.assertTrue(
            _is_llm_backend_error(
                "mcpscanner.core.analyzers.llm_analyzer", "boom", LLMConfig()
            )
        )

    def test_litellm_message_is_llm(self):
        self.assertTrue(
            _is_llm_backend_error(
                "mcpscanner.core.scanner",
                "litellm.APIConnectionError: connection refused",
                LLMConfig(),
            )
        )

    def test_configured_endpoint_host_is_llm(self):
        llm = LLMConfig(provider="ollama", model="llama3", base_url="http://127.0.0.1:11434")
        self.assertTrue(
            _is_llm_backend_error("x", "connection refused to 127.0.0.1:11434", llm)
        )

    def test_mcp_server_connection_error_is_not_llm(self):
        self.assertFalse(
            _is_llm_backend_error(
                "mcpscanner.core.scanner",
                "failed to connect to stdio server",
                LLMConfig(),
            )
        )


class _FakeScanner:
    """Drives ``_scan_local``: logs one ERROR then returns *results*."""

    def __init__(self, log_name: str, log_msg: str, results: list) -> None:
        self._log_name = log_name
        self._log_msg = log_msg
        self._results = results

    async def scan_mcp_config_file(self, **_kwargs):
        logging.getLogger(self._log_name).error(self._log_msg)
        return self._results


def _yara_result():
    tr = MagicMock()
    tr.tool_name = "some-tool"
    finding = MagicMock()
    tr.findings_by_analyzer = {"yara": [finding]}
    return tr


class ScanLocalGracefulDegradeTests(unittest.TestCase):
    """``_scan_local`` distinguishes LLM-backend from MCP-server failures."""

    def setUp(self):
        self.entry = MCPServerEntry(name="local-srv", command="npx", args=["x"])
        self.wrapper = _wrapper("auto", model=True)
        # These fakes exercise the legacy scanner config-file/log-degrade path,
        # which remains the macOS/Linux implementation. Native Windows uses
        # DefenseClaw's same-task stdio adapter and never calls this fake API.
        platform = patch("defenseclaw.scanner.mcp.os.name", "posix")
        platform.start()
        self.addCleanup(platform.stop)

    def _run(self, scanner):
        captured = io.StringIO()
        with patch("sys.stderr", captured):
            findings = self.wrapper._scan_local(scanner, self.entry, None)
        return findings, captured.getvalue()

    def test_llm_backend_down_degrades_keeps_yara(self):
        scanner = _FakeScanner(
            "mcpscanner.core.analyzers.llm_analyzer",
            "litellm.APIConnectionError: ollama unreachable at 11434",
            [_yara_result()],
        )
        findings, err = self._run(scanner)
        self.assertEqual(len(findings), 1, "YARA findings must survive an LLM-backend failure")
        self.assertIn("LLM skipped", err)
        self.assertIn("backend unreachable", err)

    def test_llm_backend_down_with_no_results_still_completes(self):
        """No YARA findings + only an LLM-backend error → no abort."""
        scanner = _FakeScanner(
            "mcpscanner.core.analyzers.llm_analyzer",
            "litellm connection error",
            [],
        )
        findings, err = self._run(scanner)
        self.assertEqual(findings, [])
        self.assertIn("LLM skipped", err)

    def test_mcp_server_connection_error_is_fatal(self):
        scanner = _FakeScanner(
            "mcpscanner.core.scanner",
            "failed to connect: connection refused spawning stdio server",
            [],
        )
        with self.assertRaises(RuntimeError) as cm:
            self.wrapper._scan_local(scanner, self.entry, None)
        self.assertIn("failed to connect to local server", str(cm.exception))

    def test_non_connection_error_with_no_results_raises(self):
        """A genuine non-LLM scan failure with no results still aborts."""
        scanner = _FakeScanner(
            "mcpscanner.core.scanner",
            "internal scanner error: bad manifest",
            [],
        )
        with self.assertRaises(RuntimeError) as cm:
            self.wrapper._scan_local(scanner, self.entry, None)
        self.assertIn("scan failed for local server", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
