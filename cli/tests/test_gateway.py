"""Tests for defenseclaw.gateway — OrchestratorClient HTTP methods."""

import os
import sys
import unittest
from unittest.mock import MagicMock

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

    def test_session_has_csrf_header(self):
        client = OrchestratorClient()
        self.assertEqual(
            client._session.headers["X-DefenseClaw-Client"], "python-cli"
        )


def _make_client() -> tuple[OrchestratorClient, MagicMock]:
    """Create a client with a mocked session for testing."""
    client = OrchestratorClient()
    mock_session = MagicMock()
    client._session = mock_session
    return client, mock_session


class TestOrchestratorClientHealth(unittest.TestCase):
    def test_health_success(self):
        client, session = _make_client()
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"status": "ok"}
        session.get.return_value = mock_resp

        result = client.health()

        session.get.assert_called_once_with("http://127.0.0.1:18790/health", timeout=5)
        mock_resp.raise_for_status.assert_called_once()
        self.assertEqual(result, {"status": "ok"})


class TestOrchestratorClientStatus(unittest.TestCase):
    def test_status_success(self):
        client, session = _make_client()
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"uptime_ms": 5000}
        session.get.return_value = mock_resp

        result = client.status()

        session.get.assert_called_once_with("http://127.0.0.1:18790/status", timeout=5)
        self.assertEqual(result["uptime_ms"], 5000)


class TestOrchestratorClientSkillOps(unittest.TestCase):
    def test_disable_skill(self):
        client, session = _make_client()
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"ok": True}
        session.post.return_value = mock_resp

        result = client.disable_skill("bad-skill")

        session.post.assert_called_once_with(
            "http://127.0.0.1:18790/skill/disable",
            json={"skillKey": "bad-skill"},
            timeout=5,
        )
        self.assertTrue(result["ok"])

    def test_enable_skill(self):
        client, session = _make_client()
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"ok": True}
        session.post.return_value = mock_resp

        result = client.enable_skill("good-skill")

        session.post.assert_called_once_with(
            "http://127.0.0.1:18790/skill/enable",
            json={"skillKey": "good-skill"},
            timeout=5,
        )
        self.assertTrue(result["ok"])


class TestOrchestratorClientPatchConfig(unittest.TestCase):
    def test_patch_config(self):
        client, session = _make_client()
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"patched": True}
        session.post.return_value = mock_resp

        result = client.patch_config("watch.auto_block", True)

        session.post.assert_called_once_with(
            "http://127.0.0.1:18790/config/patch",
            json={"path": "watch.auto_block", "value": True},
            timeout=5,
        )
        self.assertTrue(result["patched"])


class TestOrchestratorClientScanSkill(unittest.TestCase):
    def test_scan_skill(self):
        client, session = _make_client()
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"scanner": "skill-scanner", "findings": []}
        session.post.return_value = mock_resp

        result = client.scan_skill("/path/to/skill", name="my-skill")

        session.post.assert_called_once_with(
            "http://127.0.0.1:18790/v1/skill/scan",
            json={"target": "/path/to/skill", "name": "my-skill"},
            timeout=120,
        )
        self.assertEqual(result["scanner"], "skill-scanner")


class TestOrchestratorClientIsRunning(unittest.TestCase):
    def test_is_running_true(self):
        client, session = _make_client()
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"status": "ok"}
        session.get.return_value = mock_resp

        self.assertTrue(client.is_running())

    def test_is_running_connection_error(self):
        import requests
        client, session = _make_client()
        session.get.side_effect = requests.ConnectionError("refused")

        self.assertFalse(client.is_running())

    def test_is_running_timeout(self):
        import requests
        client, session = _make_client()
        session.get.side_effect = requests.Timeout("timed out")

        self.assertFalse(client.is_running())


class TestGatewayCSRFHeaderLiveServer(unittest.TestCase):
    """Verify OrchestratorClient sends X-DefenseClaw-Client using a real HTTP server (no mocks)."""

    def test_post_sends_csrf_header(self):
        import http.server
        import threading

        captured = [None]

        class CaptureHandler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                captured[0] = self.headers
                length = int(self.headers.get("Content-Length", 0))
                self.rfile.read(length)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"ok":true}')

            def log_message(self, *args):
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), CaptureHandler)
        port = server.server_address[1]
        thread = threading.Thread(target=server.handle_request, daemon=True)
        thread.start()

        try:
            client = OrchestratorClient(host="127.0.0.1", port=port)
            client.disable_skill("test-skill")
            thread.join(timeout=5)

            self.assertIsNotNone(captured[0])
            self.assertEqual(captured[0].get("X-DefenseClaw-Client"), "python-cli")
        finally:
            server.server_close()

    def test_get_sends_csrf_header(self):
        import http.server
        import threading

        captured = [None]

        class CaptureHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                captured[0] = self.headers
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"status":"ok"}')

            def log_message(self, *args):
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), CaptureHandler)
        port = server.server_address[1]
        thread = threading.Thread(target=server.handle_request, daemon=True)
        thread.start()

        try:
            client = OrchestratorClient(host="127.0.0.1", port=port)
            client.health()
            thread.join(timeout=5)

            self.assertIsNotNone(captured[0])
            self.assertEqual(captured[0].get("X-DefenseClaw-Client"), "python-cli")
        finally:
            server.server_close()

    def test_scan_skill_sends_csrf_header(self):
        import http.server
        import threading

        captured = [None]

        class CaptureHandler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                captured[0] = self.headers
                length = int(self.headers.get("Content-Length", 0))
                self.rfile.read(length)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"scanner":"skill-scanner","findings":[]}')

            def log_message(self, *args):
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), CaptureHandler)
        port = server.server_address[1]
        thread = threading.Thread(target=server.handle_request, daemon=True)
        thread.start()

        try:
            client = OrchestratorClient(host="127.0.0.1", port=port)
            client.scan_skill("/path/to/skill", name="my-skill")
            thread.join(timeout=5)

            self.assertIsNotNone(captured[0])
            self.assertEqual(captured[0].get("X-DefenseClaw-Client"), "python-cli")
        finally:
            server.server_close()


if __name__ == "__main__":
    unittest.main()
