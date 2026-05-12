"""dctest fixture: tiny HTTP server that appends every POST body to a JSONL file.

Used by `skills.observability.webhook.delivery` to assert that webhook
delivery actually reaches a sink. Listens on 127.0.0.1:9777 only.
"""

from __future__ import annotations

import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

LOG_PATH = Path(__file__).resolve().parent / "received.jsonl"
MAX_BODY_BYTES = 1 << 20  # 1 MiB cap, defense-in-depth
SERVER_TOKEN = "dctest-fixture"


class _Handler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        length_header = self.headers.get("Content-Length", "0")
        try:
            length = int(length_header)
        except ValueError:
            self.send_error(400, "bad Content-Length")
            return
        if length < 0 or length > MAX_BODY_BYTES:
            self.send_error(413, "payload too large")
            return
        body = self.rfile.read(length)
        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            payload = {"_raw": body.decode("utf-8", errors="replace")}
        record = {"path": self.path, "headers": dict(self.headers), "body": payload}
        with LOG_PATH.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, default=str) + "\n")
        self.send_response(202)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"ok":true}')

    def log_message(self, fmt: str, *args: object) -> None:  # noqa: D401
        # Silence stderr noise; the JSONL file is the source of truth.
        return


def main() -> int:
    addr = ("127.0.0.1", 9777)
    httpd = HTTPServer(addr, _Handler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
