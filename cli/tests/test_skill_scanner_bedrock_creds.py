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

"""Skill scanner LLM lane with keyless Bedrock auth (GAP-2628)."""

import io
import os
import unittest
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from defenseclaw.config import BedrockKeyConfig, LLMConfig, SkillScannerConfig
from defenseclaw.models import Finding, ScanResult
from defenseclaw.scanner import skill as skill_mod

_ENV_KEYS = (
    "AWS_REGION",
    "AWS_BEARER_TOKEN_BEDROCK",
    "AWS_METADATA_SERVICE_NUM_ATTEMPTS",
    "SKILL_SCANNER_LLM_API_KEY",
    "SKILL_SCANNER_LLM_MODEL",
    "DEFENSECLAW_LLM_KEY",
)


def _instance_role_llm() -> LLMConfig:
    return LLMConfig(
        provider="bedrock",
        model="bedrock/us.anthropic.claude-haiku-4-5-20251001-v1:0",
        api_key_env="DEFENSECLAW_LLM_KEY",
        bedrock=BedrockKeyConfig(region="eu-west-1", auth_mode="instance_role"),
    )


class TestSkillScannerBedrockInstanceRole(unittest.TestCase):
    def setUp(self):
        self._env = patch.dict(os.environ, {}, clear=False)
        self._env.start()
        for key in _ENV_KEYS:
            os.environ.pop(key, None)
        skill_mod._warned_llm_skips.clear()

    def tearDown(self):
        self._env.stop()
        skill_mod._warned_llm_skips.clear()

    def _scan(self, creds_found: bool, scans: int = 1, findings=None):
        build_analyzers = MagicMock(return_value=[])
        sdk = MagicMock()
        sdk.SkillScanner.return_value.scan_skill.return_value = MagicMock(findings=[])
        result = ScanResult(
            scanner="skill-scanner",
            target="/tmp/skill",
            timestamp=datetime.now(timezone.utc),
            findings=findings or [],
        )
        stderr = io.StringIO()
        with patch.dict("sys.modules", {
            "skill_scanner": sdk,
            "skill_scanner.core": MagicMock(),
            "skill_scanner.core.analyzer_factory": MagicMock(build_analyzers=build_analyzers),
            "skill_scanner.core.scan_policy": MagicMock(),
        }), patch.object(
            skill_mod, "_aws_credentials_found", return_value=creds_found
        ), patch.object(
            skill_mod.SkillScannerWrapper, "_convert", return_value=result
        ), patch("sys.stderr", stderr):
            scanner = skill_mod.SkillScannerWrapper(
                SkillScannerConfig(use_llm=True), llm=_instance_role_llm()
            )
            for _ in range(scans):
                scanner.scan("/tmp/skill")
        return build_analyzers.call_args.kwargs, stderr.getvalue()

    def test_uses_credential_chain_and_configured_region(self):
        # The configured region wins over the shell, as in the gateway scanner env.
        os.environ["AWS_REGION"] = "ap-south-1"
        kwargs, err = self._scan(creds_found=True)
        self.assertTrue(kwargs.get("use_llm"))
        self.assertNotIn("llm_api_key", kwargs)
        self.assertEqual(os.environ.get("AWS_REGION"), "eu-west-1")
        self.assertEqual(os.environ.get("AWS_METADATA_SERVICE_NUM_ATTEMPTS"), "3")
        self.assertEqual(err, "")

    def test_missing_credentials_skip_llm_with_one_clear_warning(self):
        kwargs, err = self._scan(creds_found=False, scans=3)
        self.assertNotIn("use_llm", kwargs)
        self.assertEqual(err.count("LLM analyzer skipped"), 1)
        self.assertIn("no AWS credentials found for Bedrock (auth_mode=instance_role)", err)
        self.assertNotIn("DEFENSECLAW_LLM_KEY", err)


    def test_judge_that_did_not_answer_fails_the_scan(self):
        # GAP-0376: the outage came back as an INFO finding and exit 0.
        outage = Finding(
            id="llm_analysis_failed_x", severity="INFO", title="LLM analysis failed",
            description="The LLM analyzer encountered an error: APIConnectionError", rule_id="LLM_ANALYSIS_FAILED",
        )
        with self.assertRaisesRegex(skill_mod.JudgeUnavailableError, "the LLM judge did not run"):
            self._scan(creds_found=True, findings=[outage])


if __name__ == "__main__":
    unittest.main()
