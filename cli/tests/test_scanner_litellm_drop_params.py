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

import os
import unittest
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import litellm
from defenseclaw.config import LLMConfig, MCPScannerConfig, MCPServerEntry, SkillScannerConfig
from defenseclaw.models import ScanResult
from defenseclaw.scanner import _llm_env
from defenseclaw.scanner import skill as skill_mod
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


class SkillScanLiteLLMTest(unittest.TestCase):
    """A skill scan turns drop_params on only when a judge can call LiteLLM.

    Importing LiteLLM takes about 2 s; a static-only scan never calls it.
    """

    def _scan(self, scanner_cfg: SkillScannerConfig, llm: LLMConfig) -> list[dict[str, str]]:
        seen: list[dict[str, str]] = []

        def drop() -> None:
            seen.append({k: v for k, v in os.environ.items() if k.startswith("SKILL_SCANNER_")})

        def build(**_kwargs):
            # The SDK builds its analyzers after drop_params is set.
            seen.append({"built": "1"})
            return []

        sdk = MagicMock()
        sdk.SkillScanner.return_value.scan_skill.return_value = MagicMock(findings=[])
        result = ScanResult(scanner="skill-scanner", target="/tmp/skill", timestamp=datetime.now(timezone.utc))
        with patch.dict("sys.modules", {
            "skill_scanner": sdk,
            "skill_scanner.core": MagicMock(),
            "skill_scanner.core.analyzer_factory": MagicMock(build_analyzers=build),
            "skill_scanner.core.scan_policy": MagicMock(),
        }), patch.object(skill_mod, "drop_unsupported_litellm_params", side_effect=drop), \
                patch.object(skill_mod, "install_judge_compat", create=True), \
                patch.object(skill_mod.SkillScannerWrapper, "_convert", return_value=result), \
                patch.dict(os.environ, {"SKILL_SCANNER_LLM_MODEL": "inherited/model"}):
            skill_mod.SkillScannerWrapper(scanner_cfg, llm=llm).scan("/tmp/skill")
        return seen

    def test_judge_scan_drops_params_before_the_analyzers_are_built(self):
        seen = self._scan(
            SkillScannerConfig(use_llm=True),
            LLMConfig(provider="openai", model="openai/gpt-test", api_key="test-key"),
        )
        self.assertEqual(len(seen), 2)
        self.assertEqual(seen[0].get("SKILL_SCANNER_LLM_MODEL"), "openai/gpt-test")
        self.assertEqual(seen[1], {"built": "1"})

    def test_static_scan_does_not_import_litellm(self):
        # The shell's SKILL_SCANNER_LLM_MODEL is removed for the scan, as
        # before, so it does not count as a judge.
        seen = self._scan(SkillScannerConfig(use_llm=False), LLMConfig())
        self.assertEqual(seen, [{"built": "1"}])


if __name__ == "__main__":
    unittest.main()
