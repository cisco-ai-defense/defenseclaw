"""Tests for defenseclaw.gateway — OrchestratorClient HTTP methods."""

import os
import unittest
from unittest.mock import MagicMock, patch

import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.gateway import OrchestratorClient


class TestOrchestratorClientInit(unittest.TestCase):
    def test_defaults(self):
        client = OrchestratorClient()
        self.assertEqual(client.base_url, "http://127.0.0.1:18790")
        self.assertEqual(client.timeout, 5)

    def test_custom_params(self):
        client = OrchestratorClient(host="10.0.0.1", port=9999, timeout=15)
        self.assertEqual(client.base_url, "http://10.0.0.1:9999")
        self.assertEqual(client.timeout, 15)


class TestOrchestratorClientHealth(unittest.TestCase):
    @patch("defenseclaw.gateway.requests.get")
    def test_health_success(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"status": "ok"}
        mock_get.return_value = mock_resp

        client = OrchestratorClient()
        result = client.health()

        mock_get.assert_called_once_with("http://127.0.0.1:18790/health", timeout=5)
        mock_resp.raise_for_status.assert_called_once()
        self.assertEqual(result, {"status": "ok"})


class TestOrchestratorClientStatus(unittest.TestCase):
    @patch("defenseclaw.gateway.requests.get")
    def test_status_success(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"uptime_ms": 5000}
        mock_get.return_value = mock_resp

        client = OrchestratorClient()
        result = client.status()

        mock_get.assert_called_once_with("http://127.0.0.1:18790/status", timeout=5)
        self.assertEqual(result["uptime_ms"], 5000)


class TestOrchestratorClientSkillOps(unittest.TestCase):
    @patch("defenseclaw.gateway.requests.post")
    def test_disable_skill(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"ok": True}
        mock_post.return_value = mock_resp

        client = OrchestratorClient()
        result = client.disable_skill("bad-skill")

        mock_post.assert_called_once_with(
            "http://127.0.0.1:18790/skill/disable",
            json={"skillKey": "bad-skill"},
            timeout=5,
        )
        self.assertTrue(result["ok"])

    @patch("defenseclaw.gateway.requests.post")
    def test_enable_skill(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"ok": True}
        mock_post.return_value = mock_resp

        client = OrchestratorClient()
        result = client.enable_skill("good-skill")

        mock_post.assert_called_once_with(
            "http://127.0.0.1:18790/skill/enable",
            json={"skillKey": "good-skill"},
            timeout=5,
        )
        self.assertTrue(result["ok"])


class TestOrchestratorClientPatchConfig(unittest.TestCase):
    @patch("defenseclaw.gateway.requests.post")
    def test_patch_config(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"patched": True}
        mock_post.return_value = mock_resp

        client = OrchestratorClient()
        result = client.patch_config("watch.auto_block", True)

        mock_post.assert_called_once_with(
            "http://127.0.0.1:18790/config/patch",
            json={"path": "watch.auto_block", "value": True},
            timeout=5,
        )
        self.assertTrue(result["patched"])


class TestOrchestratorClientIsRunning(unittest.TestCase):
    @patch("defenseclaw.gateway.requests.get")
    def test_is_running_true(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"status": "ok"}
        mock_get.return_value = mock_resp

        client = OrchestratorClient()
        self.assertTrue(client.is_running())

    @patch("defenseclaw.gateway.requests.get")
    def test_is_running_connection_error(self, mock_get):
        import requests
        mock_get.side_effect = requests.ConnectionError("refused")

        client = OrchestratorClient()
        self.assertFalse(client.is_running())

    @patch("defenseclaw.gateway.requests.get")
    def test_is_running_timeout(self, mock_get):
        import requests
        mock_get.side_effect = requests.Timeout("timed out")

        client = OrchestratorClient()
        self.assertFalse(client.is_running())


if __name__ == "__main__":
    unittest.main()
