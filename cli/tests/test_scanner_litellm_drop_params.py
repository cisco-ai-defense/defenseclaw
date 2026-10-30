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

"""Scanner judges drop request parameters the model refuses (GAP-2612)."""

import unittest
from unittest.mock import patch

import litellm
from defenseclaw.config import LLMConfig, MCPScannerConfig, MCPServerEntry
from defenseclaw.scanner import _llm_env
from defenseclaw.scanner.mcp import MCPScannerWrapper
from litellm.exceptions import UnsupportedParamsError
from litellm.utils import get_optional_params

_LUNA = "us.openai.gpt-5.6-luna"


def _luna_params() -> dict:
    # mcp-scanner asks every judge for temperature 0.1.
    return get_optional_params(model=_LUNA, custom_llm_provider="bedrock", temperature=0.1)


class DropUnsupportedParamsTest(unittest.TestCase):
    def setUp(self):
        previous = litellm.drop_params
        self.addCleanup(setattr, litellm, "drop_params", previous)
        litellm.drop_params = False

    def test_luna_refuses_temperature_without_the_fix(self):
        with self.assertRaisesRegex(UnsupportedParamsError, "temperature"):
            _luna_params()

    def test_helper_drops_the_refused_temperature(self):
        _llm_env.drop_unsupported_litellm_params()
        self.assertTrue(litellm.drop_params)
        self.assertNotIn("temperature", _luna_params())

    def test_mcp_scan_turns_it_on_before_the_sdk_runs(self):
        seen = []
        wrapper = MCPScannerWrapper(
            MCPScannerConfig(analyzers="yara,llm"),
            llm=LLMConfig(provider="bedrock", model=f"bedrock/{_LUNA}", api_key="test-key"),
        )
        entry = MCPServerEntry(name="local-srv", command="npx", args=["x"])

        def scan_local(*_args, **_kwargs):
            seen.append(litellm.drop_params)
            return []

        # The launcher check reads PATH (npx.cmd on Windows); it is not under
        # test here, so admit the entry on every OS.
        with patch("defenseclaw.scanner.mcp.mcp_scan_refusal", return_value=None), \
                patch.object(MCPScannerWrapper, "_scan_local", side_effect=scan_local):
            wrapper.scan("local-srv", entry)
        self.assertEqual(seen, [True])


if __name__ == "__main__":
    unittest.main()
