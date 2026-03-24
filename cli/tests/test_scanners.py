"""Tests for scanner wrappers — MCPScannerWrapper, AIBOMScannerWrapper, SkillScannerWrapper."""

import json
import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.scanner.mcp import MCPScannerWrapper
from defenseclaw.scanner.aibom import AIBOMScannerWrapper
from defenseclaw.config import SkillScannerConfig


class TestMCPScannerWrapper(unittest.TestCase):
    def test_name(self):
        scanner = MCPScannerWrapper("mcp-scanner")
        self.assertEqual(scanner.name(), "mcp-scanner")

    @patch("defenseclaw.scanner.mcp.subprocess.run")
    def test_scan_clean_result(self, mock_run):
        mock_run.return_value = MagicMock(
            stdout=json.dumps({"findings": []}),
            stderr="",
            returncode=0,
        )
        scanner = MCPScannerWrapper("mcp-scanner")
        result = scanner.scan("http://localhost:3000")

        self.assertEqual(result.scanner, "mcp-scanner")
        self.assertEqual(result.target, "http://localhost:3000")
        self.assertTrue(result.is_clean())
        mock_run.assert_called_once()

    @patch("defenseclaw.scanner.mcp.subprocess.run")
    def test_scan_with_findings(self, mock_run):
        mock_run.return_value = MagicMock(
            stdout=json.dumps({
                "findings": [
                    {
                        "id": "f1",
                        "severity": "HIGH",
                        "title": "Insecure endpoint",
                        "description": "No auth on sensitive endpoint",
                    },
                    {
                        "id": "f2",
                        "severity": "MEDIUM",
                        "title": "Missing rate limiting",
                    },
                ]
            }),
            stderr="",
            returncode=0,
        )
        scanner = MCPScannerWrapper("mcp-scanner")
        result = scanner.scan("http://localhost:3000")

        self.assertFalse(result.is_clean())
        self.assertEqual(len(result.findings), 2)
        self.assertEqual(result.max_severity(), "HIGH")
        self.assertEqual(result.findings[0].title, "Insecure endpoint")
        self.assertEqual(result.findings[1].severity, "MEDIUM")

    @patch("defenseclaw.scanner.mcp.subprocess.run", side_effect=FileNotFoundError)
    def test_scan_binary_not_found(self, _mock):
        scanner = MCPScannerWrapper("mcp-scanner")
        with self.assertRaises(SystemExit) as ctx:
            scanner.scan("http://localhost:3000")
        self.assertEqual(ctx.exception.code, 1)

    @patch("defenseclaw.scanner.mcp.subprocess.run")
    def test_scan_empty_stdout(self, mock_run):
        mock_run.return_value = MagicMock(stdout="", stderr="", returncode=0)
        scanner = MCPScannerWrapper("mcp-scanner")
        result = scanner.scan("http://localhost:3000")
        self.assertTrue(result.is_clean())

    @patch("defenseclaw.scanner.mcp.subprocess.run")
    def test_scan_malformed_json(self, mock_run):
        mock_run.return_value = MagicMock(stdout="not json", stderr="", returncode=0)
        scanner = MCPScannerWrapper("mcp-scanner")
        result = scanner.scan("http://localhost:3000")
        self.assertTrue(result.is_clean())


class TestAIBOMScannerWrapper(unittest.TestCase):
    def test_name(self):
        scanner = AIBOMScannerWrapper("cisco-aibom")
        self.assertEqual(scanner.name(), "aibom")

    @patch("defenseclaw.scanner.aibom.subprocess.run")
    def test_scan_success(self, mock_run):
        mock_run.return_value = MagicMock(stdout="", stderr="", returncode=0)

        def fake_run(cmd, **kwargs):
            output_file = cmd[cmd.index("--output-file") + 1]
            with open(output_file, "w") as f:
                json.dump({"components": [{"name": "torch", "version": "2.1"}]}, f)
            return MagicMock(stdout="", stderr="", returncode=0)

        mock_run.side_effect = fake_run
        scanner = AIBOMScannerWrapper("cisco-aibom")
        result = scanner.scan("/tmp/project")

        self.assertEqual(result.scanner, "aibom")
        self.assertEqual(result.target, "/tmp/project")
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].id, "aibom-inventory")
        self.assertEqual(result.findings[0].severity, "INFO")

    @patch("defenseclaw.scanner.aibom.subprocess.run", side_effect=FileNotFoundError)
    def test_scan_binary_not_found(self, _mock):
        scanner = AIBOMScannerWrapper("cisco-aibom")
        with self.assertRaises(SystemExit) as ctx:
            scanner.scan("/tmp/project")
        self.assertEqual(ctx.exception.code, 1)


class TestSkillScannerWrapper(unittest.TestCase):
    def test_name(self):
        from defenseclaw.scanner.skill import SkillScannerWrapper
        scanner = SkillScannerWrapper(SkillScannerConfig())
        self.assertEqual(scanner.name(), "skill-scanner")

    def test_scan_raises_on_missing_sdk(self):
        from defenseclaw.scanner.skill import SkillScannerWrapper
        scanner = SkillScannerWrapper(SkillScannerConfig())

        with patch.dict("sys.modules", {"skill_scanner": None}):
            with self.assertRaises(SystemExit):
                scanner.scan("/tmp/skill")

    @patch("defenseclaw.scanner.skill.SkillScannerWrapper._convert")
    def test_scan_with_mocked_sdk(self, mock_convert):
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

    def test_inject_env_sets_keys(self):
        from defenseclaw.scanner.skill import SkillScannerWrapper
        cfg = SkillScannerConfig(llm_api_key="test-key-123", llm_model="gpt-4")
        scanner = SkillScannerWrapper(cfg)

        env_backup = os.environ.copy()
        try:
            os.environ.pop("SKILL_SCANNER_LLM_API_KEY", None)
            os.environ.pop("SKILL_SCANNER_LLM_MODEL", None)
            scanner._inject_env()
            self.assertEqual(os.environ.get("SKILL_SCANNER_LLM_API_KEY"), "test-key-123")
            self.assertEqual(os.environ.get("SKILL_SCANNER_LLM_MODEL"), "gpt-4")
        finally:
            os.environ.clear()
            os.environ.update(env_backup)

    def test_inject_env_does_not_overwrite_existing(self):
        from defenseclaw.scanner.skill import SkillScannerWrapper
        cfg = SkillScannerConfig(llm_api_key="new-key")
        scanner = SkillScannerWrapper(cfg)

        env_backup = os.environ.copy()
        try:
            os.environ["SKILL_SCANNER_LLM_API_KEY"] = "existing-key"
            scanner._inject_env()
            self.assertEqual(os.environ["SKILL_SCANNER_LLM_API_KEY"], "existing-key")
        finally:
            os.environ.clear()
            os.environ.update(env_backup)


if __name__ == "__main__":
    unittest.main()
