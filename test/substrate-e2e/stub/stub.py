#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""A stub agent for the Substrate kind E2E (test only).

It stands in for a coding agent: it answers /readyz, makes the outbound HTTPS request a test
asks for (/fetch?url=), and posts a hook event to the gateway the way an agent hook helper does
(POST /hook, forwarded to $STUB_HOOK_URL). It holds no credentials.
"""
import http.server
import json
import os
import socketserver
import urllib.error
import urllib.parse
import urllib.request

PORT = int(os.environ.get("STUB_PORT", "8080"))
HOOK_URL = os.environ.get("STUB_HOOK_URL", "")


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def _send(self, code, body, ctype="text/plain"):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/readyz":
            return self._send(200, "ok\n")
        if parsed.path == "/fetch":
            url = urllib.parse.parse_qs(parsed.query).get("url", [""])[0]
            try:
                with urllib.request.urlopen(url, timeout=25) as resp:
                    return self._send(200, str(resp.status))
            except urllib.error.HTTPError as err:
                return self._send(200, str(err.code))
            except Exception as err:  # denied egress surfaces as a connection error or a reset
                return self._send(200, "error " + type(err).__name__)
        return self._send(404, "no\n")

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length)
        if self.path == "/hook":
            if not HOOK_URL:
                return self._send(500, "STUB_HOOK_URL is not set\n")
            req = urllib.request.Request(HOOK_URL, data=body, method="POST", headers={"Content-Type": "application/json"})
            try:
                with urllib.request.urlopen(req, timeout=25) as resp:
                    return self._send(resp.status, resp.read(), "application/json")
            except urllib.error.HTTPError as err:
                return self._send(err.code, err.read(), "application/json")
            except Exception as err:
                return self._send(502, json.dumps({"error": type(err).__name__}), "application/json")
        return self._send(404, "no\n")


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


if __name__ == "__main__":
    Server(("0.0.0.0", PORT), Handler).serve_forever()
