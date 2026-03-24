"""Tests for OrchestratorClient — gateway HTTP client with mocked requests."""

import os
import unittest
from unittest.mock import MagicMock, patch

import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import requests
from defenseclaw.gateway import OrchestratorClient


class TestOrchestratorClient(unittest.TestCase):
    def setUp(self):
        self.client = OrchestratorClient(host="127.0.0.1", port=18790, timeout=2)

    @patch("defenseclaw.gateway.requests.get")
    def test_health(self, mock_get):
        mock_get.return_value = MagicMock(
            status_code=200,
            json=MagicMock(return_value={"status": "healthy", "uptime_ms": 5000}),
        )
        result = self.client.health()
        self.assertEqual(result["status"], "healthy")
        mock_get.assert_called_once_with("http://127.0.0.1:18790/health", timeout=2)

    @patch("defenseclaw.gateway.requests.get")
    def test_status(self, mock_get):
        mock_get.return_value = MagicMock(
            status_code=200,
            json=MagicMock(return_value={"gateway": {"state": "connected"}}),
        )
        result = self.client.status()
        self.assertEqual(result["gateway"]["state"], "connected")

    @patch("defenseclaw.gateway.requests.get")
    def test_is_running_true(self, mock_get):
        mock_get.return_value = MagicMock(status_code=200, json=MagicMock(return_value={}))
        self.assertTrue(self.client.is_running())

    @patch("defenseclaw.gateway.requests.get", side_effect=requests.ConnectionError)
    def test_is_running_false_on_connection_error(self, _mock):
        self.assertFalse(self.client.is_running())

    @patch("defenseclaw.gateway.requests.get", side_effect=requests.Timeout)
    def test_is_running_false_on_timeout(self, _mock):
        self.assertFalse(self.client.is_running())

    @patch("defenseclaw.gateway.requests.post")
    def test_disable_skill(self, mock_post):
        mock_post.return_value = MagicMock(
            status_code=200,
            json=MagicMock(return_value={"ok": True}),
        )
        result = self.client.disable_skill("bad-skill")
        self.assertTrue(result["ok"])
        mock_post.assert_called_once_with(
            "http://127.0.0.1:18790/skill/disable",
            json={"skillKey": "bad-skill"},
            timeout=2,
        )

    @patch("defenseclaw.gateway.requests.post")
    def test_enable_skill(self, mock_post):
        mock_post.return_value = MagicMock(
            status_code=200,
            json=MagicMock(return_value={"ok": True}),
        )
        result = self.client.enable_skill("my-skill")
        self.assertTrue(result["ok"])
        mock_post.assert_called_once_with(
            "http://127.0.0.1:18790/skill/enable",
            json={"skillKey": "my-skill"},
            timeout=2,
        )

    @patch("defenseclaw.gateway.requests.post")
    def test_patch_config(self, mock_post):
        mock_post.return_value = MagicMock(
            status_code=200,
            json=MagicMock(return_value={"ok": True}),
        )
        result = self.client.patch_config("gateway.auto_approve_safe", True)
        self.assertTrue(result["ok"])

    def test_base_url_construction(self):
        c = OrchestratorClient(host="10.0.0.1", port=9999)
        self.assertEqual(c.base_url, "http://10.0.0.1:9999")

    def test_default_params(self):
        c = OrchestratorClient()
        self.assertEqual(c.base_url, "http://127.0.0.1:18790")
        self.assertEqual(c.timeout, 5)


if __name__ == "__main__":
    unittest.main()
