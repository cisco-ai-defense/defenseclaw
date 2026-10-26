# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""The CLI suite does not depend on what listens on the API port (GAP-1336)."""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from defenseclaw.config import default_config
from defenseclaw.logger import CanonicalObservabilityUnavailableError, _GatewayConfigRecorder


class _Ambiguous(BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802 - stdlib handler API
        self.send_response(500)
        self.end_headers()

    def log_message(self, *_args) -> None:
        return


def test_an_audit_event_never_reaches_a_listener_on_the_api_port(tmp_path, monkeypatch) -> None:
    server = HTTPServer(("127.0.0.1", 0), _Ambiguous)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        cfg = default_config()
        cfg.data_dir = str(tmp_path)
        cfg.gateway.api_port = server.server_address[1]
        monkeypatch.setattr(type(cfg.gateway), "resolved_token", lambda _self: "test-token")
        with pytest.raises(CanonicalObservabilityUnavailableError):
            _GatewayConfigRecorder(cfg).emit_cli_observability({"kind": "action"})
    finally:
        server.shutdown()
        server.server_close()
