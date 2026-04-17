#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Minimal Splunk HEC collector mock for CI.

The real Splunk HEC accepts POST /services/collector with one or more
newline-delimited JSON envelopes in the body and returns 200 OK. This
mock mirrors that contract just closely enough to satisfy DefenseClaw's
splunk_hec sink: it accepts any path, validates the Authorization
header prefix, and appends each HEC envelope (one per line) to a log
file the Phase 6 observability assertions script can grep.

Why Python stdlib instead of netcat?
  - netcat speaks TCP, not HTTP. The HEC sink sends real requests with
    Content-Length and an Authorization header; nc would return 0 bytes
    and the sink would mark the collector unhealthy.
  - Every CI runner has Python 3, no extra dependencies needed.
  - A ~60-line stdlib handler is auditable and deterministic; we don't
    pull in Flask/FastAPI just to log request bodies.

Usage (from a CI workflow):
    python3 test/e2e/splunk_hec_mock.py \\
        --port 8088 \\
        --log /tmp/splunk-mock.log &
    # ... run e2e ...
    grep 'defenseclaw:judge' /tmp/splunk-mock.log

The server exits on SIGTERM / SIGINT and fsyncs the log file between
writes so the assertions step can read it safely without a race.
"""

from __future__ import annotations

import argparse
import signal
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

# Tests occasionally send an envelope per request at batch_size=1 which
# produces tiny payloads; reject anything larger than 16 MiB as
# protection against a misconfigured sink flooding the runner disk.
MAX_BODY_BYTES = 16 * 1024 * 1024

# Lock serialising writes so concurrent POSTs from the sink cannot
# interleave bytes mid-line in the log file. ThreadingHTTPServer
# dispatches each request in its own goroutine-like thread.
_write_lock = threading.Lock()


class _Handler(BaseHTTPRequestHandler):
    # Class-level attributes populated by run(); the HTTP server does
    # not support per-handler constructor args.
    log_path: Path = Path("/tmp/splunk-mock.log")
    required_auth_prefix: str = "Splunk "

    def do_POST(self) -> None:  # noqa: N802 (BaseHTTPRequestHandler naming)
        length = int(self.headers.get("Content-Length", "0"))
        if length < 0 or length > MAX_BODY_BYTES:
            self.send_response(413)
            self.end_headers()
            return

        # Authorization must be "Splunk <token>" per HEC spec; we
        # don't validate the token itself (this is a mock).
        auth = self.headers.get("Authorization", "")
        if not auth.startswith(self.required_auth_prefix):
            self.send_response(401)
            self.end_headers()
            self.wfile.write(b'{"text":"missing/invalid HEC token","code":3}')
            return

        body = self.rfile.read(length) if length else b""
        # Append each body on its own line so the grep in
        # observability_assertions.sh stays simple. The HEC payload
        # itself is already newline-delimited JSON; we just record
        # the raw bytes verbatim so assertions can match on the exact
        # envelope the sink produced.
        with _write_lock:
            with self.log_path.open("ab") as f:
                if body and not body.endswith(b"\n"):
                    body = body + b"\n"
                f.write(body)
                f.flush()

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"text":"Success","code":0}')

    # Silence the default per-request stderr spam so CI logs stay clean.
    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        return


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--port", type=int, default=8088)
    parser.add_argument(
        "--log",
        type=Path,
        default=Path("/tmp/splunk-mock.log"),
        help="File to append received HEC envelopes to",
    )
    parser.add_argument(
        "--bind",
        default="127.0.0.1",
        help="Interface to bind (default 127.0.0.1 — do not expose "
        "publicly, this mock has no real auth)",
    )
    args = parser.parse_args()

    # Truncate the log at startup so each CI run gets a clean slate.
    args.log.parent.mkdir(parents=True, exist_ok=True)
    args.log.write_bytes(b"")

    _Handler.log_path = args.log
    server = ThreadingHTTPServer((args.bind, args.port), _Handler)

    def _shutdown(signum: int, frame: object) -> None:  # noqa: ARG001
        # server.shutdown() blocks until serve_forever() acknowledges
        # the request, but signal handlers run on the same thread that
        # is currently *inside* serve_forever(). Calling shutdown
        # directly would deadlock. Defer it to a worker thread so the
        # signal handler returns, serve_forever resumes its poll loop,
        # notices the shutdown flag, and exits cleanly.
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    print(
        f"[splunk-hec-mock] listening on {args.bind}:{args.port} "
        f"log={args.log}",
        flush=True,
    )
    server.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
