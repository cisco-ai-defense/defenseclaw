"""Tests for defenseclaw.scanner — AIBOM, MCP, and skill scanner wrappers."""

import json
import os
import tempfile
import unittest
from datetime import timedelta
from unittest.mock import MagicMock, patch

import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


class TestAIBOMScannerWrapper(unittest.TestCase):
    def test_name(self):
        from defenseclaw.scanner.aibom import AIBOMScannerWrapper
        s = AIBOMScannerWrapper()
        self.assertEqual(s.name(), "aibom")

    @patch("defenseclaw.scanner.aibom.subprocess.run")
    def test_scan_success_with_json_output(self, mock_run):
        from defenseclaw.scanner.aibom import AIBOMScannerWrapper

        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        s = AIBOMScannerWrapper("cisco-aibom")

        with patch("defenseclaw.scanner.aibom.Path.read_text") as mock_read:
            mock_read.return_value = json.dumps({"components": ["model-a"]})
            with patch("defenseclaw.scanner.aibom.Path.unlink"):
                result = s.scan("/tmp/project")

        self.assertEqual(result.scanner, "aibom")
        self.assertEqual(result.target, "/tmp/project")
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].id, "aibom-inventory")

    @patch("defenseclaw.scanner.aibom.subprocess.run", side_effect=FileNotFoundError)
    def test_scan_binary_not_found(self, _mock):
        from defenseclaw.scanner.aibom import AIBOMScannerWrapper

        s = AIBOMScannerWrapper("nonexistent-binary")
        with self.assertRaises(SystemExit) as ctx:
            s.scan("/tmp/project")
        self.assertEqual(ctx.exception.code, 1)

    @patch("defenseclaw.scanner.aibom.subprocess.run")
    def test_scan_invalid_json_output(self, mock_run):
        from defenseclaw.scanner.aibom import AIBOMScannerWrapper

        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        s = AIBOMScannerWrapper()

        with patch("defenseclaw.scanner.aibom.Path.read_text") as mock_read:
            mock_read.return_value = "not-json"
            with patch("defenseclaw.scanner.aibom.Path.unlink"):
                result = s.scan("/tmp/project")

        self.assertEqual(len(result.findings), 0)


class TestMCPScannerWrapper(unittest.TestCase):
    def test_name(self):
        from defenseclaw.scanner.mcp import MCPScannerWrapper
        s = MCPScannerWrapper()
        self.assertEqual(s.name(), "mcp-scanner")

    @patch("defenseclaw.scanner.mcp.subprocess.run")
    def test_scan_clean_result(self, mock_run):
        from defenseclaw.scanner.mcp import MCPScannerWrapper

        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        s = MCPScannerWrapper()
        result = s.scan("http://localhost:3000")

        self.assertEqual(result.scanner, "mcp-scanner")
        self.assertEqual(result.target, "http://localhost:3000")
        self.assertTrue(result.is_clean())

    @patch("defenseclaw.scanner.mcp.subprocess.run")
    def test_scan_with_findings(self, mock_run):
        from defenseclaw.scanner.mcp import MCPScannerWrapper

        findings_json = json.dumps({
            "findings": [
                {"id": "mcp-001", "severity": "HIGH", "title": "Insecure transport"},
                {"id": "mcp-002", "severity": "LOW", "title": "No auth"},
            ]
        })
        mock_run.return_value = MagicMock(returncode=0, stdout=findings_json, stderr="")

        s = MCPScannerWrapper()
        result = s.scan("http://localhost:3000")

        self.assertEqual(len(result.findings), 2)
        self.assertEqual(result.max_severity(), "HIGH")
        self.assertEqual(result.findings[0].scanner, "mcp-scanner")

    @patch("defenseclaw.scanner.mcp.subprocess.run", side_effect=FileNotFoundError)
    def test_scan_binary_not_found(self, _mock):
        from defenseclaw.scanner.mcp import MCPScannerWrapper

        s = MCPScannerWrapper("nonexistent")
        with self.assertRaises(SystemExit) as ctx:
            s.scan("http://localhost:3000")
        self.assertEqual(ctx.exception.code, 1)

    @patch("defenseclaw.scanner.mcp.subprocess.run")
    def test_scan_invalid_json(self, mock_run):
        from defenseclaw.scanner.mcp import MCPScannerWrapper

        mock_run.return_value = MagicMock(returncode=1, stdout="ERROR: something", stderr="")
        s = MCPScannerWrapper()
        result = s.scan("http://localhost:3000")

        self.assertTrue(result.is_clean())


class TestSkillScannerWrapper(unittest.TestCase):
    def test_name(self):
        from defenseclaw.config import SkillScannerConfig
        from defenseclaw.scanner.skill import SkillScannerWrapper
        s = SkillScannerWrapper(SkillScannerConfig())
        self.assertEqual(s.name(), "skill-scanner")

    def test_inject_env_sets_vars(self):
        from defenseclaw.config import SkillScannerConfig
        from defenseclaw.scanner.skill import SkillScannerWrapper

        cfg = SkillScannerConfig(llm_api_key="test-key-value", llm_model="gpt-4")
        s = SkillScannerWrapper(cfg)

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
        from defenseclaw.config import SkillScannerConfig
        from defenseclaw.scanner.skill import SkillScannerWrapper

        cfg = SkillScannerConfig(llm_api_key="new-key")
        s = SkillScannerWrapper(cfg)

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

        s = SkillScannerWrapper(SkillScannerConfig())
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


if __name__ == "__main__":
    unittest.main()
