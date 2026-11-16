"""Setup reads gateway health only from the configured DefenseClaw process."""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from defenseclaw.commands import cmd_setup


def test_setup_health_refuses_an_unverified_listener_before_reading_decisions(tmp_path, monkeypatch) -> None:
    requests_seen: list[str] = []

    class Impostor(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            requests_seen.append(self.path)
            body = b'{"api":{"state":"running"},"started_at":"foreign-generation"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Impostor)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_port
        (tmp_path / "config.yaml").write_text(
            f"config_version: 8\ndata_dir: {tmp_path}\ngateway:\n  api_bind: 127.0.0.1\n  api_port: {port}\n"
        )
        (tmp_path / "gateway.pid").write_text("999999\n")
        monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path))

        assert cmd_setup._read_gateway_health(str(tmp_path)) is None
        prior = cmd_setup._gateway_runtime_generation_before_restart(str(tmp_path))
        assert prior.started_at is None
        assert not cmd_setup._wait_for_defense_gateway_api(str(tmp_path), timeout=0.1)
        assert requests_seen == [], "setup sent /health to an unverified listener"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
