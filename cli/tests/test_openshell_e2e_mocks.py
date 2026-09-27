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

"""The OpenShell E2E mock LLM servers (test/e2e/openshell) never log credentials."""

import argparse
import importlib.util
import json
import tempfile
import threading
import unittest
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

_MOCKS = Path(__file__).resolve().parents[2] / "test" / "e2e" / "openshell"
# Harmless stand-ins for the credentials a harness sends.
_SECRETS = ("dc-test-bearer-value", "dc-test-api-key-value", "dc-test-cookie-value")


def _load(name):
    spec = importlib.util.spec_from_file_location(f"openshell_e2e_{name}", _MOCKS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TestMockHeaderRedaction(unittest.TestCase):
    def test_redact_headers(self):
        for name in ("mock_anthropic", "mock_openai"):
            with self.subTest(mock=name):
                mock = _load(name)
                got = mock.redact_headers(
                    {
                        "Authorization": "Bearer " + _SECRETS[0],
                        "x-api-key": _SECRETS[1],
                        "Proxy-Authorization": "Basic " + _SECRETS[2],
                        "X-Upstream-Token": "openshell:resolve:env:v1_DEFENSECLAW_SANDBOX_TOKEN",
                        "Cookie": "session=" + _SECRETS[2],
                        "anthropic-version": "2023-06-01",
                        "Content-Type": "application/json",
                    }
                )
                self.assertEqual(
                    got,
                    {
                        "Authorization": "Bearer [redacted]",
                        "x-api-key": "[redacted]",
                        "Proxy-Authorization": "Basic [redacted]",
                        "X-Upstream-Token": "[redacted placeholder]",
                        "Cookie": "[redacted]",
                        "anthropic-version": "2023-06-01",
                        "Content-Type": "application/json",
                    },
                )

    def test_request_log_has_no_credentials(self):
        for name in ("mock_anthropic", "mock_openai"):
            with self.subTest(mock=name), tempfile.TemporaryDirectory() as tmp:
                mock = _load(name)
                log = Path(tmp) / "requests.jsonl"
                mock.ARGS = argparse.Namespace(script=None, log=str(log), dump_dir=None, quiet=True)
                server = ThreadingHTTPServer(("127.0.0.1", 0), mock.Handler)
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                try:
                    request = urllib.request.Request(
                        f"http://127.0.0.1:{server.server_address[1]}/v1/models",
                        headers={"Authorization": "Bearer " + _SECRETS[0], "x-api-key": _SECRETS[1]},
                    )
                    # Talk to the mock directly even when a proxy is configured.
                    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                    with opener.open(request, timeout=10) as response:
                        self.assertEqual(response.status, 200)
                finally:
                    server.shutdown()
                    server.server_close()
                    thread.join(timeout=10)
                text = log.read_text(encoding="utf-8")
                for secret in _SECRETS:
                    self.assertNotIn(secret, text)
                headers = {k.lower(): v for k, v in json.loads(text.splitlines()[0])["headers"].items()}
                self.assertEqual(headers["authorization"], "Bearer [redacted]")
                self.assertEqual(headers["x-api-key"], "[redacted]")


if __name__ == "__main__":
    unittest.main()
