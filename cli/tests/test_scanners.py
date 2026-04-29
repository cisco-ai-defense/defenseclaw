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

"""Tests for defenseclaw.scanner — MCP and skill scanner wrappers."""

import json
import os
import tempfile
import unittest
from datetime import timedelta
from unittest.mock import MagicMock, patch

import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


class TestMCPScannerWrapper(unittest.TestCase):
    def test_name(self):
        from defenseclaw.config import MCPScannerConfig
        from defenseclaw.scanner.mcp import MCPScannerWrapper
        s = MCPScannerWrapper(MCPScannerConfig())
        self.assertEqual(s.name(), "mcp-scanner")

    def test_config_fields_used_directly(self):
        """Common config values are accessible via wrapper."""
        from defenseclaw.config import MCPScannerConfig, InspectLLMConfig, CiscoAIDefenseConfig
        from defenseclaw.scanner.mcp import MCPScannerWrapper

        llm = InspectLLMConfig(
            api_key="cfg-llm-key",
            model="gpt-4o",
            base_url="https://llm.example.com",
        )
        aid = CiscoAIDefenseConfig(
            api_key="cfg-api-key",
            endpoint="https://scanner.example.com",
        )
        s = MCPScannerWrapper(MCPScannerConfig(), llm, aid)
        self.assertEqual(s.cisco_ai_defense.api_key, "cfg-api-key")
        self.assertEqual(s.cisco_ai_defense.endpoint, "https://scanner.example.com")
        self.assertEqual(s.inspect_llm.api_key, "cfg-llm-key")
        self.assertEqual(s.inspect_llm.model, "gpt-4o")
        self.assertEqual(s.inspect_llm.base_url, "https://llm.example.com")

    def test_convert_empty_findings(self):
        from defenseclaw.config import MCPScannerConfig
        from defenseclaw.scanner.mcp import MCPScannerWrapper

        s = MCPScannerWrapper(MCPScannerConfig())
        result = s._convert([], "http://localhost:3000", 1.5)

        self.assertEqual(result.scanner, "mcp-scanner")
        self.assertEqual(result.target, "http://localhost:3000")
        self.assertTrue(result.is_clean())
        self.assertAlmostEqual(result.duration.total_seconds(), 1.5, places=1)

    def test_convert_with_findings(self):
        from defenseclaw.config import MCPScannerConfig
        from defenseclaw.scanner.mcp import MCPScannerWrapper

        s = MCPScannerWrapper(MCPScannerConfig())

        finding = MagicMock()
        finding.severity = "HIGH"
        finding.summary = "Prompt injection detected"
        finding.threat_category = MagicMock()
        finding.threat_category.name = "PROMPT_INJECTION"
        finding.analyzer = "yara"
        finding.details = {"evidence": "suspicious pattern found"}
        finding.mcp_taxonomy = {"aisubtech_name": "Instruction Manipulation", "description": "Detailed desc"}
        finding._entity_name = "dangerous-tool"
        finding._entity_type = "tool"

        result = s._convert([finding], "http://localhost:3000", 0.5)
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].severity, "HIGH")
        self.assertEqual(result.findings[0].title, "Prompt injection detected")
        self.assertEqual(result.findings[0].location, "tool:dangerous-tool")
        self.assertIn("PROMPT_INJECTION", result.findings[0].tags)
        self.assertIn("mcp-scanner/yara", result.findings[0].scanner)

    def test_scan_raises_system_exit_on_import_error(self):
        from defenseclaw.config import MCPScannerConfig
        from defenseclaw.scanner.mcp import MCPScannerWrapper
        import builtins

        s = MCPScannerWrapper(MCPScannerConfig())
        real_import = builtins.__import__
        def fake_import(name, *args, **kwargs):
            if name == "mcpscanner" or name.startswith("mcpscanner."):
                raise ImportError(f"mocked: no module named {name}")
            return real_import(name, *args, **kwargs)

        with patch.object(builtins, "__import__", side_effect=fake_import):
            with self.assertRaises(SystemExit):
                s.scan("http://localhost:3000")

    @patch("defenseclaw.scanner.mcp.MCPScannerWrapper._convert")
    @patch("defenseclaw.scanner.mcp.asyncio.run")
    def test_scan_with_mocked_sdk(self, mock_asyncio_run, mock_convert):
        from defenseclaw.config import MCPScannerConfig
        from defenseclaw.scanner.mcp import MCPScannerWrapper
        from defenseclaw.models import ScanResult
        from datetime import datetime, timezone

        mock_tool_result = MagicMock()
        mock_tool_result.tool_name = "test-tool"
        mock_tool_result.findings_by_analyzer = {}
        mock_tool_result.findings = []
        mock_asyncio_run.return_value = [mock_tool_result]

        mock_convert.return_value = ScanResult(
            scanner="mcp-scanner",
            target="http://localhost:3000",
            timestamp=datetime.now(timezone.utc),
            findings=[],
        )

        with patch.dict("sys.modules", {
            "mcpscanner": MagicMock(),
            "mcpscanner.core": MagicMock(),
            "mcpscanner.core.models": MagicMock(),
        }):
            scanner = MCPScannerWrapper(MCPScannerConfig())
            result = scanner.scan("http://localhost:3000")

        self.assertTrue(result.is_clean())
        self.assertEqual(result.scanner, "mcp-scanner")

    def test_analyzer_parsing(self):
        from defenseclaw.config import MCPScannerConfig

        cfg = MCPScannerConfig(analyzers="yara,api,llm")
        self.assertEqual(cfg.analyzers, "yara,api,llm")

        parsed = [a.strip() for a in cfg.analyzers.split(",")]
        self.assertEqual(parsed, ["yara", "api", "llm"])

    @patch("defenseclaw.scanner.mcp.MCPScannerWrapper._convert")
    @patch("defenseclaw.scanner.mcp.asyncio.run")
    def test_invalid_analyzer_names_warn_on_stderr(self, mock_asyncio_run, mock_convert):
        """Typos in analyzer names must produce a warning, not silently drop."""
        from defenseclaw.config import MCPScannerConfig
        from defenseclaw.scanner.mcp import MCPScannerWrapper
        from defenseclaw.models import ScanResult
        from datetime import datetime, timezone
        from io import StringIO

        mock_asyncio_run.return_value = []
        mock_convert.return_value = ScanResult(
            scanner="mcp-scanner",
            target="http://localhost:3000",
            timestamp=datetime.now(timezone.utc),
            findings=[],
        )

        captured = StringIO()
        with patch.dict("sys.modules", {
            "mcpscanner": MagicMock(),
            "mcpscanner.core": MagicMock(),
            "mcpscanner.core.models": MagicMock(),
        }):
            cfg = MCPScannerConfig(analyzers="yara,aip")
            scanner = MCPScannerWrapper(cfg)
            with patch("sys.stderr", captured):
                scanner.scan("http://localhost:3000")

        output = captured.getvalue()
        self.assertIn("aip", output, "invalid analyzer name should appear in warning")
        self.assertIn("warning", output.lower())

    @patch("defenseclaw.scanner.mcp.MCPScannerWrapper._convert")
    @patch("defenseclaw.scanner.mcp.asyncio.run")
    def test_all_invalid_analyzers_falls_back_to_none(self, mock_asyncio_run, mock_convert):
        """When every analyzer name is invalid, fall back to all analyzers (None)."""
        from defenseclaw.config import MCPScannerConfig
        from defenseclaw.scanner.mcp import MCPScannerWrapper
        from defenseclaw.models import ScanResult
        from datetime import datetime, timezone
        from io import StringIO

        mock_asyncio_run.return_value = []
        mock_convert.return_value = ScanResult(
            scanner="mcp-scanner",
            target="http://localhost:3000",
            timestamp=datetime.now(timezone.utc),
            findings=[],
        )

        captured = StringIO()
        with patch.dict("sys.modules", {
            "mcpscanner": MagicMock(),
            "mcpscanner.core": MagicMock(),
            "mcpscanner.core.models": MagicMock(),
        }):
            cfg = MCPScannerConfig(analyzers="bogus,typo")
            scanner = MCPScannerWrapper(cfg)
            with patch("sys.stderr", captured):
                scanner.scan("http://localhost:3000")

        output = captured.getvalue()
        self.assertIn("falling back to all analyzers", output)

        call_args = mock_asyncio_run.call_args
        coro = call_args[0][0]
        coro.close()

    @patch("defenseclaw.scanner.mcp.MCPScannerWrapper._convert")
    @patch("defenseclaw.scanner.mcp.asyncio.run")
    def test_scan_instructions_iterates_over_results(self, mock_asyncio_run, mock_convert):
        """Regression: instruction results must be iterated like tools/prompts/resources."""
        from defenseclaw.config import MCPScannerConfig
        from defenseclaw.scanner.mcp import MCPScannerWrapper
        from defenseclaw.models import ScanResult
        from datetime import datetime, timezone

        finding = MagicMock()
        finding.severity = "HIGH"
        finding.summary = "Instruction injection"

        instr_result = MagicMock()
        instr_result.findings_by_analyzer = {"yara": [finding]}

        tool_result = MagicMock()
        tool_result.tool_name = "test-tool"
        tool_result.findings_by_analyzer = {}

        mock_asyncio_run.side_effect = [
            [tool_result],
            [instr_result],
        ]

        mock_convert.return_value = ScanResult(
            scanner="mcp-scanner",
            target="http://localhost:3000",
            timestamp=datetime.now(timezone.utc),
            findings=[],
        )

        with patch.dict("sys.modules", {
            "mcpscanner": MagicMock(),
            "mcpscanner.core": MagicMock(),
            "mcpscanner.core.models": MagicMock(),
        }):
            cfg = MCPScannerConfig(scan_instructions=True)
            scanner = MCPScannerWrapper(cfg)
            scanner.scan("http://localhost:3000")

        convert_args = mock_convert.call_args[0]
        sdk_findings = convert_args[0]
        self.assertGreaterEqual(len(sdk_findings), 1, "instruction findings must not be dropped")
        instruction_findings = [f for f in sdk_findings if getattr(f, "_entity_type", "") == "instructions"]
        self.assertEqual(len(instruction_findings), 1)
        self.assertEqual(instruction_findings[0]._entity_name, "server-instructions")


class TestExtractFindings(unittest.TestCase):
    """Tests for _extract_findings covering all storage formats."""

    def test_findings_by_analyzer_dict_with_lists(self):
        from defenseclaw.scanner.mcp import _extract_findings

        f1, f2 = MagicMock(), MagicMock()
        result = MagicMock()
        result.findings_by_analyzer = {"yara": [f1], "api": [f2]}

        extracted = _extract_findings(result)
        self.assertEqual(len(extracted), 2)
        self.assertIn(f1, extracted)
        self.assertIn(f2, extracted)

    def test_findings_by_analyzer_dict_with_objects(self):
        from defenseclaw.scanner.mcp import _extract_findings

        f1 = MagicMock()
        analyzer_result = MagicMock()
        analyzer_result.findings = [f1]

        result = MagicMock()
        result.findings_by_analyzer = {"yara": analyzer_result}

        del result.findings

        extracted = _extract_findings(result)
        self.assertEqual(len(extracted), 1)
        self.assertIn(f1, extracted)

    def test_flat_findings_list(self):
        from defenseclaw.scanner.mcp import _extract_findings

        f1, f2 = MagicMock(), MagicMock()
        result = MagicMock(spec=[])
        result.findings_by_analyzer = None
        result.findings = [f1, f2]

        extracted = _extract_findings(result)
        self.assertEqual(len(extracted), 2)

    def test_findings_dict_fallback(self):
        from defenseclaw.scanner.mcp import _extract_findings

        f1 = MagicMock()
        result = MagicMock(spec=[])
        result.findings_by_analyzer = None
        result.findings = {"yara": [f1]}

        extracted = _extract_findings(result)
        self.assertEqual(len(extracted), 1)
        self.assertIn(f1, extracted)

    def test_no_findings_returns_empty(self):
        from defenseclaw.scanner.mcp import _extract_findings

        result = MagicMock(spec=[])
        result.findings_by_analyzer = None
        result.findings = None

        extracted = _extract_findings(result)
        self.assertEqual(extracted, [])


class TestSkillScannerWrapper(unittest.TestCase):
    def test_name(self):
        from defenseclaw.config import SkillScannerConfig
        from defenseclaw.scanner.skill import SkillScannerWrapper
        s = SkillScannerWrapper(SkillScannerConfig())
        self.assertEqual(s.name(), "skill-scanner")

    def test_inject_env_sets_vars(self):
        from defenseclaw.config import SkillScannerConfig, InspectLLMConfig
        from defenseclaw.scanner.skill import SkillScannerWrapper

        llm = InspectLLMConfig(api_key="test-key-value", model="gpt-4")
        s = SkillScannerWrapper(SkillScannerConfig(), llm)

        env_backup = {}
        for k in ["SKILL_SCANNER_LLM_API_KEY", "SKILL_SCANNER_LLM_MODEL"]:
            if k in os.environ:
                env_backup[k] = os.environ.pop(k)

        try:
            s._inject_env()
            self.assertEqual(os.environ.get("SKILL_SCANNER_LLM_API_KEY"), "test-key-value")
            self.assertEqual(os.environ.get("SKILL_SCANNER_LLM_MODEL"), "gpt-4")
        finally:
            for k in ["SKILL_SCANNER_LLM_API_KEY", "SKILL_SCANNER_LLM_MODEL"]:
                os.environ.pop(k, None)
            os.environ.update(env_backup)

    def test_inject_env_does_not_override_existing(self):
        from defenseclaw.config import SkillScannerConfig, InspectLLMConfig
        from defenseclaw.scanner.skill import SkillScannerWrapper

        llm = InspectLLMConfig(api_key="new-key")
        s = SkillScannerWrapper(SkillScannerConfig(), llm)

        os.environ["SKILL_SCANNER_LLM_API_KEY"] = "original-key"
        try:
            s._inject_env()
            self.assertEqual(os.environ["SKILL_SCANNER_LLM_API_KEY"], "original-key")
        finally:
            del os.environ["SKILL_SCANNER_LLM_API_KEY"]

    def test_convert_empty_result(self):
        from defenseclaw.config import SkillScannerConfig
        from defenseclaw.scanner.skill import SkillScannerWrapper

        s = SkillScannerWrapper(SkillScannerConfig())
        sdk_result = MagicMock()
        sdk_result.findings = []

        result = s._convert(sdk_result, "/tmp/skill", 1.5)
        self.assertEqual(result.scanner, "skill-scanner")
        self.assertEqual(result.target, "/tmp/skill")
        self.assertTrue(result.is_clean())
        self.assertAlmostEqual(result.duration.total_seconds(), 1.5, places=1)

    def test_convert_with_findings(self):
        from defenseclaw.config import SkillScannerConfig
        from defenseclaw.scanner.skill import SkillScannerWrapper

        s = SkillScannerWrapper(SkillScannerConfig())

        finding = MagicMock()
        finding.id = "rule-001"
        finding.severity = MagicMock()
        finding.severity.name = "HIGH"
        finding.title = "Dangerous pattern"
        finding.description = "Found exec call"
        finding.file_path = "main.py"
        finding.line_number = 42
        finding.category = MagicMock()
        finding.category.name = "injection"
        finding.remediation = "Remove exec"
        finding.analyzer = "static"
        finding.rule_id = "rule-001"

        sdk_result = MagicMock()
        sdk_result.findings = [finding]

        result = s._convert(sdk_result, "/tmp/skill", 0.5)
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].severity, "HIGH")
        self.assertEqual(result.findings[0].location, "main.py:42")
        self.assertIn("injection", result.findings[0].tags)

    def test_scan_raises_system_exit_on_import_error(self):
        from defenseclaw.config import SkillScannerConfig
        from defenseclaw.scanner.skill import SkillScannerWrapper
        import builtins

        s = SkillScannerWrapper(SkillScannerConfig())
        real_import = builtins.__import__
        def fake_import(name, *args, **kwargs):
            if name == "skill_scanner" or name.startswith("skill_scanner."):
                raise ImportError(f"mocked: no module named {name}")
            return real_import(name, *args, **kwargs)

        with patch.object(builtins, "__import__", side_effect=fake_import):
            with self.assertRaises(SystemExit):
                s.scan("/tmp/nonexistent")

    @patch("defenseclaw.scanner.skill.SkillScannerWrapper._convert")
    def test_scan_with_mocked_sdk(self, mock_convert):
        from defenseclaw.config import SkillScannerConfig
        from defenseclaw.scanner.skill import SkillScannerWrapper
        from defenseclaw.models import ScanResult
        from datetime import datetime, timezone

        mock_sdk_module = MagicMock()
        mock_scanner_instance = MagicMock()
        mock_sdk_module.SkillScanner.return_value = mock_scanner_instance
        mock_scanner_instance.scan_skill.return_value = MagicMock(findings=[])

        mock_convert.return_value = ScanResult(
            scanner="skill-scanner",
            target="/tmp/skill",
            timestamp=datetime.now(timezone.utc),
            findings=[],
        )

        with patch.dict("sys.modules", {
            "skill_scanner": mock_sdk_module,
            "skill_scanner.core": MagicMock(),
            "skill_scanner.core.analyzer_factory": MagicMock(),
            "skill_scanner.core.scan_policy": MagicMock(),
        }):
            scanner = SkillScannerWrapper(SkillScannerConfig())
            result = scanner.scan("/tmp/skill")

        self.assertTrue(result.is_clean())
        self.assertEqual(result.scanner, "skill-scanner")

    @patch("defenseclaw.scanner.skill.SkillScannerWrapper._convert")
    def test_scan_skips_llm_analyzer_for_unsupported_provider(self, mock_convert):
        from defenseclaw.config import LLMConfig, SkillScannerConfig
        from defenseclaw.scanner.skill import SkillScannerWrapper
        from defenseclaw.models import ScanResult
        from datetime import datetime, timezone

        mock_sdk_module = MagicMock()
        mock_scanner_instance = MagicMock()
        mock_sdk_module.SkillScanner.return_value = mock_scanner_instance
        mock_scanner_instance.scan_skill.return_value = MagicMock(findings=[])

        build_analyzers = MagicMock(return_value=[])
        mock_convert.return_value = ScanResult(
            scanner="skill-scanner",
            target="/tmp/skill",
            timestamp=datetime.now(timezone.utc),
            findings=[],
        )

        cfg = SkillScannerConfig(use_llm=True, use_behavioral=True)
        llm = LLMConfig(provider="bedrock", model="us.anthropic.claude-haiku")
        with patch.dict("sys.modules", {
            "skill_scanner": mock_sdk_module,
            "skill_scanner.core": MagicMock(),
            "skill_scanner.core.analyzer_factory": MagicMock(build_analyzers=build_analyzers),
            "skill_scanner.core.scan_policy": MagicMock(),
        }):
            scanner = SkillScannerWrapper(cfg, llm=llm)
            result = scanner.scan("/tmp/skill")

        self.assertTrue(result.is_clean())
        kwargs = build_analyzers.call_args.kwargs
        self.assertNotIn("use_llm", kwargs)
        self.assertNotIn("llm_provider", kwargs)
        self.assertTrue(kwargs["use_behavioral"])


class TestMCPScannerCommonConfigs(unittest.TestCase):
    """Tests for MCPScannerWrapper using shared InspectLLM and CiscoAIDefense configs."""

    def test_defaults_when_no_common_configs(self):
        from defenseclaw.config import MCPScannerConfig
        from defenseclaw.scanner.mcp import MCPScannerWrapper

        s = MCPScannerWrapper(MCPScannerConfig())
        self.assertEqual(s.inspect_llm.provider, "")
        self.assertEqual(s.inspect_llm.api_key, "")
        self.assertEqual(s.cisco_ai_defense.endpoint, "https://us.api.inspect.aidefense.security.cisco.com")

    def test_inject_env_sets_provider_key(self):
        """_inject_env sets the provider-specific env var (e.g. OPENAI_API_KEY)."""
        from defenseclaw.config import MCPScannerConfig, InspectLLMConfig, CiscoAIDefenseConfig
        from defenseclaw.scanner.mcp import MCPScannerWrapper

        llm = InspectLLMConfig(api_key="llm-key-123", provider="openai")
        aid = CiscoAIDefenseConfig(api_key="cisco-key-456", api_key_env="")
        s = MCPScannerWrapper(MCPScannerConfig(), llm, aid)

        os.environ.pop("OPENAI_API_KEY", None)

        try:
            s._inject_env()
            self.assertEqual(os.environ.get("OPENAI_API_KEY"), "llm-key-123")
        finally:
            os.environ.pop("OPENAI_API_KEY", None)

    def test_resolve_llm_base_url_from_provider(self):
        from defenseclaw.config import MCPScannerConfig, InspectLLMConfig
        from defenseclaw.scanner.mcp import MCPScannerWrapper

        llm = InspectLLMConfig(provider="openai")
        s = MCPScannerWrapper(MCPScannerConfig(), llm)
        self.assertEqual(s._resolve_llm_base_url(), "https://api.openai.com")

    def test_resolve_llm_base_url_explicit(self):
        from defenseclaw.config import MCPScannerConfig, InspectLLMConfig
        from defenseclaw.scanner.mcp import MCPScannerWrapper

        llm = InspectLLMConfig(provider="openai", base_url="https://custom.llm.api")
        s = MCPScannerWrapper(MCPScannerConfig(), llm)
        self.assertEqual(s._resolve_llm_base_url(), "https://custom.llm.api")

    def test_resolve_llm_base_url_unknown_provider(self):
        from defenseclaw.config import MCPScannerConfig, InspectLLMConfig
        from defenseclaw.scanner.mcp import MCPScannerWrapper

        llm = InspectLLMConfig(provider="bedrock")
        s = MCPScannerWrapper(MCPScannerConfig(), llm)
        self.assertEqual(s._resolve_llm_base_url(), "")


class TestSkillScannerCommonConfigs(unittest.TestCase):
    """Tests for SkillScannerWrapper using shared InspectLLM and CiscoAIDefense configs."""

    def test_defaults_when_no_common_configs(self):
        from defenseclaw.config import SkillScannerConfig
        from defenseclaw.scanner.skill import SkillScannerWrapper

        s = SkillScannerWrapper(SkillScannerConfig())
        self.assertEqual(s.inspect_llm.provider, "")
        self.assertEqual(s.cisco_ai_defense.api_key, "")

    def test_inject_env_uses_inspect_llm(self):
        from defenseclaw.config import SkillScannerConfig, InspectLLMConfig, CiscoAIDefenseConfig
        from defenseclaw.scanner.skill import SkillScannerWrapper

        llm = InspectLLMConfig(api_key="shared-llm-key", model="gpt-4o")
        aid = CiscoAIDefenseConfig(api_key="shared-aid-key", api_key_env="")
        s = SkillScannerWrapper(SkillScannerConfig(), llm, aid)

        for k in ["SKILL_SCANNER_LLM_API_KEY", "SKILL_SCANNER_LLM_MODEL", "AI_DEFENSE_API_KEY"]:
            os.environ.pop(k, None)

        try:
            s._inject_env()
            self.assertEqual(os.environ.get("SKILL_SCANNER_LLM_API_KEY"), "shared-llm-key")
            self.assertEqual(os.environ.get("SKILL_SCANNER_LLM_MODEL"), "gpt-4o")
            self.assertEqual(os.environ.get("AI_DEFENSE_API_KEY"), "shared-aid-key")
        finally:
            for k in ["SKILL_SCANNER_LLM_API_KEY", "SKILL_SCANNER_LLM_MODEL", "AI_DEFENSE_API_KEY"]:
                os.environ.pop(k, None)

    def test_inject_env_cisco_resolved_from_env_var(self):
        from defenseclaw.config import SkillScannerConfig, CiscoAIDefenseConfig
        from defenseclaw.scanner.skill import SkillScannerWrapper

        aid = CiscoAIDefenseConfig(api_key="direct", api_key_env="TEST_CISCO_RESOLVE_XYZ")
        os.environ["TEST_CISCO_RESOLVE_XYZ"] = "env-resolved"
        os.environ.pop("AI_DEFENSE_API_KEY", None)

        try:
            s = SkillScannerWrapper(SkillScannerConfig(), cisco_ai_defense=aid)
            s._inject_env()
            self.assertEqual(os.environ.get("AI_DEFENSE_API_KEY"), "env-resolved")
        finally:
            os.environ.pop("TEST_CISCO_RESOLVE_XYZ", None)
            os.environ.pop("AI_DEFENSE_API_KEY", None)

    def test_inject_env_virustotal_still_from_scanner_config(self):
        from defenseclaw.config import SkillScannerConfig
        from defenseclaw.scanner.skill import SkillScannerWrapper

        cfg = SkillScannerConfig(virustotal_api_key="vt-key-abc")
        s = SkillScannerWrapper(cfg)

        os.environ.pop("VIRUSTOTAL_API_KEY", None)
        try:
            s._inject_env()
            self.assertEqual(os.environ.get("VIRUSTOTAL_API_KEY"), "vt-key-abc")
        finally:
            os.environ.pop("VIRUSTOTAL_API_KEY", None)


if __name__ == "__main__":
    unittest.main()
