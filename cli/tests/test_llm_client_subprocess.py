# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Tests for plugin_scanner llm_client subprocess handling."""

import json
import os
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


class TestLLMClientSubprocess(unittest.TestCase):
    def test_subprocess_nonzero_raises(self):
        from defenseclaw.scanner.plugin_scanner.llm_client import (
            LLMConfig,
            LLMMessage,
            SubprocessExitError,
            call_llm,
        )

        cfg = LLMConfig(model="gpt-4", python_binary=sys.executable)
        with patch("defenseclaw.scanner.plugin_scanner.llm_client.subprocess.run") as run:
            run.return_value = subprocess.CompletedProcess(
                [sys.executable, "-m", "defenseclaw.llm"],
                returncode=2,
                stdout="",
                stderr="boom",
            )
            with self.assertRaises(SubprocessExitError) as ctx:
                call_llm(cfg, [LLMMessage(role="user", content="hi")])
            self.assertEqual(ctx.exception.returncode, 2)
            self.assertIn("SUBPROCESS_EXIT", str(ctx.exception))

    def test_default_interpreter_is_the_running_one(self):
        # GAP-1579: a bare "python3" from PATH lacks the defenseclaw package
        # on a per-user install; the bridge must run in DefenseClaw's own venv.
        from defenseclaw.scanner.plugin_scanner.llm_client import (
            LLMMessage,
            call_llm,
        )
        from defenseclaw.scanner.plugin_scanner.policy import LLMPolicy

        cfg = {"model": "m", "python_binary": LLMPolicy().python_binary or None}
        with patch("defenseclaw.scanner.plugin_scanner.llm_client.subprocess.run") as run:
            run.return_value = subprocess.CompletedProcess([], 0, stdout='{"content": "ok"}', stderr="")
            call_llm(cfg, [LLMMessage(role="user", content="hi")])
        self.assertEqual(run.call_args.args[0][0], os.path.abspath(sys.executable))


if __name__ == "__main__":
    unittest.main()



def test_gap2105_a_failing_provider_is_retried_and_its_error_reaches_the_scanner(tmp_path) -> None:
    """A real bridge subprocess against a loopback provider that always
    answers HTTP 500: LiteLLM retries it (num_retries needs tenacity), stdout
    stays one JSON document, and the plugin scanner's client reports the
    provider's own error, not a JSON parse error (GAP-2105)."""
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    from defenseclaw.scanner.plugin_scanner.llm_client import call_llm as client_call

    hits: list[str] = []

    class Fail(BaseHTTPRequestHandler):
        def log_message(self, *_a):
            pass

        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length") or 0))
            hits.append(self.path)
            body = b'{"error":{"message":"r105 stub overload","type":"server_error"}}'
            self.send_response(500)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = HTTPServer(("127.0.0.1", 0), Fail)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        env_home = tmp_path / "home"
        env_home.mkdir()
        old = {k: os.environ.get(k) for k in ("HOME", "DEFENSECLAW_HOME")}
        os.environ["HOME"] = str(env_home)
        os.environ["DEFENSECLAW_HOME"] = str(env_home / ".defenseclaw")
        try:
            response = client_call(
                {"model": "openai/stub-judge", "api_key": "stub-not-a-key",
                 "api_base": f"http://127.0.0.1:{server.server_port}/v1", "max_tokens": 5},
                [{"role": "user", "content": "hi"}],
            )
        finally:
            for k, v in old.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v
        assert response.error, response
        assert "r105 stub overload" in response.error, response.error
        assert "Expecting value" not in response.error, response.error

        # The configured llm.max_retries reaches LiteLLM as num_retries (the
        # bridge merges it from the config); the OpenAI SDK tries a call 3
        # times, LiteLLM's own retries add more.
        hits.clear()
        request = json.dumps({
            "model": "openai/stub-judge", "api_key": "stub-not-a-key", "max_retries": 2,
            "api_base": f"http://127.0.0.1:{server.server_port}/v1", "max_tokens": 5,
            "messages": [{"role": "user", "content": "hi"}],
        })
        proc = subprocess.run([sys.executable, "-m", "defenseclaw.llm"], input=request,
                              capture_output=True, text=True, timeout=120, env={**os.environ, "HOME": str(env_home)})
        answer = json.loads(proc.stdout)
        assert "tenacity" not in answer["error"] and "r105 stub overload" in answer["error"], answer
        assert len(hits) > 3, hits
    finally:
        server.shutdown()
