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

"""The MCP LLM analyzer sends no temperature to GPT-5.6 Luna (GAP-0112).

MCP Scanner 4.8.7 forces temperature=1 for every GPT-5 model; LiteLLM's
drop_params keeps it and Bedrock refuses the field, so the analyzer failed
with BadRequestError. The real upstream analyzer builds the request here;
only LiteLLM's acompletion is replaced.
"""

import asyncio
import importlib
import io
import unittest
from unittest.mock import AsyncMock, patch

from defenseclaw.config import LLMConfig, MCPScannerConfig, MCPServerEntry
from defenseclaw.scanner import mcp as mcp_mod
from defenseclaw.scanner._llm_env import model_refuses_temperature
from defenseclaw.scanner.mcp import MCPScannerWrapper
from litellm.utils import get_optional_params
from mcpscanner.config.config import Config as MCPConfig
from mcpscanner.core.analyzers import llm_analyzer
from mcpscanner.utils import llm_request_params

_LUNA = "bedrock/us.openai.gpt-5.6-luna"
_HAIKU = "bedrock/us.anthropic.claude-haiku-4-5-20251001-v1:0"


def _request(model: str) -> dict:
    """The kwargs the upstream LLM analyzer hands to LiteLLM for *model*."""
    sent = AsyncMock(return_value=object())
    analyzer = llm_analyzer.LLMAnalyzer(
        MCPConfig(llm_provider_api_key="test-key", llm_model=model, aws_region_name="us-east-1"),
    )
    with patch.object(llm_analyzer, "acompletion", sent):
        asyncio.run(analyzer._make_llm_request([{"role": "user", "content": "x"}], "echo"))
    return sent.call_args.kwargs


class ScannerTemperatureTest(unittest.TestCase):
    def setUp(self):
        # Start from the upstream function, even if an earlier scan in this
        # process installed the shim.
        current = llm_request_params.apply_model_constraints
        self.addCleanup(setattr, llm_request_params, "apply_model_constraints", current)
        importlib.reload(llm_request_params)

    def test_upstream_temperature_survives_drop_params(self):
        # Why DefenseClaw must leave it out: LiteLLM passes the 1 to Bedrock.
        params = {"max_tokens": 100, "temperature": 0.1}
        llm_request_params.apply_model_constraints(_LUNA, params)
        self.assertEqual(params.get("temperature"), 1)
        optional = get_optional_params(
            model=_LUNA.split("/", 1)[1],
            custom_llm_provider="bedrock",
            temperature=1,
            drop_params=True,
        )
        self.assertIn("temperature", optional)

    def test_luna_request_has_no_temperature(self):
        mcp_mod._omit_refused_temperature()
        sent = _request(_LUNA)
        self.assertNotIn("temperature", sent)
        self.assertIn("max_completion_tokens", sent)
        self.assertTrue(sent["drop_params"])

    def test_haiku_request_keeps_its_temperature(self):
        mcp_mod._omit_refused_temperature()
        self.assertIn("temperature", _request(_HAIKU))

    def test_shim_is_installed_once(self):
        mcp_mod._omit_refused_temperature()
        first = llm_request_params.apply_model_constraints
        mcp_mod._omit_refused_temperature()
        self.assertIs(llm_request_params.apply_model_constraints, first)

    def test_scan_installs_it_before_the_sdk_runs(self):
        seen = []
        wrapper = MCPScannerWrapper(
            MCPScannerConfig(analyzers="yara,llm"),
            llm=LLMConfig(provider="bedrock", model=_LUNA, api_key="test-key"),
        )
        entry = MCPServerEntry(name="local-srv", command="npx", args=["x"])

        def scan_local(*_args, **_kwargs):
            seen.append(getattr(llm_request_params.apply_model_constraints, "_defenseclaw_omit_temperature", False))
            return []

        with (
            patch("defenseclaw.scanner.mcp.mcp_scan_refusal", return_value=None),
            patch.object(MCPScannerWrapper, "_scan_local", side_effect=scan_local),
        ):
            wrapper.scan("local-srv", entry)
        self.assertEqual(seen, [True])

    def test_rule_matches_the_gateway_judge(self):
        for model in (_LUNA, "us.openai.gpt-5.6-luna", "openai/gpt-5.5", "o3-mini", "azure/o1"):
            self.assertTrue(model_refuses_temperature(model), model)
        for model in (_HAIKU, "openai/gpt-4.1", "gpt-4o", "ollama/llama3", "", "bedrock/openai.gpt-oss-120b-1:0"):
            self.assertFalse(model_refuses_temperature(model), model)


class LLMSkipWarningCauseTest(unittest.TestCase):
    def _warn(self, detail: str) -> tuple[str, str]:
        wrapper = MCPScannerWrapper(MCPScannerConfig(), llm=LLMConfig(provider="bedrock", model=_LUNA))
        err = io.StringIO()
        with patch("sys.stderr", err):
            wrapper._warn_llm_skipped("http://127.0.0.1:1/mcp", detail)
        return err.getvalue(), wrapper._llm_skipped

    def test_bad_request_is_not_called_unreachable(self):
        err, note = self._warn("LLM API final error: BadRequestError")
        self.assertIn("warning: LLM skipped (the model refused the request; check llm.model)", err)
        self.assertNotIn("unreachable", err + note)
        self.assertIn("BadRequestError", note)

    def test_other_causes(self):
        for detail, cause in (
            ("LLM API final error: AuthenticationError", "refused the credentials"),
            ("LLM API final error: NotFoundError", "model was not found"),
            ("LLM API transient error, retries exhausted: RateLimitError", "rate limiting"),
            ("LLM API transient error, retries exhausted: APIConnectionError", "backend unreachable"),
            ("litellm connection error", "backend unreachable"),
        ):
            self.assertIn(cause, self._warn(detail)[0], detail)


if __name__ == "__main__":
    unittest.main()
