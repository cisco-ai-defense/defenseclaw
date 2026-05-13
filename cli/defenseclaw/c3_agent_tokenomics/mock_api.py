# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import argparse
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

from .cli import build_payload_from_files
from .galileo_config import galileo_config_from_env

TRUTHY = {"1", "true", "yes", "y", "on"}


def _bool_query(query: dict[str, list[str]], name: str, default: bool = False) -> bool:
    values = query.get(name)
    if not values:
        return default
    return str(values[-1]).strip().lower() in TRUTHY


def _first(query: dict[str, list[str]], name: str, default: str | None = None) -> str | None:
    values = query.get(name)
    if not values:
        return default
    return values[-1]


class C3TokenomicsHandler(BaseHTTPRequestHandler):
    """Tiny stdlib HTTP server for Cisco Cloud Control frontend wiring and Kubernetes demos."""

    o11y_fixture_path: str | None = None
    galileo_fixture_path: str | None = None
    realm: str | None = None
    allow_fixture_fallback: bool = True

    def _send_json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self) -> None:  # noqa: N802
        self._send_json(200, {"status": "ok"})

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)
        if path == "/healthz":
            self._send_json(
                200,
                {"status": "ok", "integrations": {"galileo": galileo_config_from_env().public_status()}},
            )
            return
        if path != "/v1/c3/agent-tokenomics/summary":
            self._send_json(404, {"error": "not found"})
            return

        try:
            include_galileo = _bool_query(query, "include_galileo", default=False)
            tenant_id = _first(query, "tenant_id", "c3-demo-tenant")
            workspace_id = _first(query, "workspace_id", "wayne-demo")
            payload = build_payload_from_files(
                o11y_input=self.o11y_fixture_path,
                galileo_input=self.galileo_fixture_path,
                tenant_id=tenant_id,
                workspace_id=workspace_id,
                include_galileo=include_galileo,
                realm=self.realm,
            )
            payload.setdefault("debug", {})["internal_only"] = True
            payload["debug"]["fixture_backed"] = True
            payload["debug"]["galileo"] = galileo_config_from_env().public_status()
            self._send_json(200, payload)
        except Exception as exc:  # pragma: no cover - defensive for stage demos
            if not self.allow_fixture_fallback:
                self._send_json(503, {"error": "tokenomics summary unavailable", "detail": str(exc)})
                return
            self._send_json(500, {"error": "tokenomics summary failed", "detail": str(exc)})


def configure_handler(
    o11y_fixture_path: str | None = None,
    galileo_fixture_path: str | None = None,
    realm: str | None = None,
    allow_fixture_fallback: bool | None = None,
) -> type[C3TokenomicsHandler]:
    C3TokenomicsHandler.o11y_fixture_path = o11y_fixture_path or os.environ.get("TOKENOMICS_DEMO_FIXTURE_PATH")
    C3TokenomicsHandler.galileo_fixture_path = galileo_fixture_path or os.environ.get(
        "GALILEO_RUNTIME_CONTROLS_FIXTURE_PATH"
    )
    C3TokenomicsHandler.realm = realm or os.environ.get("O11Y_REALM")
    if allow_fixture_fallback is None:
        allow_fixture_fallback = os.environ.get("TOKENOMICS_DEMO_ALLOW_FIXTURE_FALLBACK", "true").lower() in TRUTHY
    C3TokenomicsHandler.allow_fixture_fallback = allow_fixture_fallback
    return C3TokenomicsHandler


def make_server(host: str, port: int, **kwargs: Any) -> ThreadingHTTPServer:
    handler = configure_handler(**kwargs)
    return ThreadingHTTPServer((host, port), handler)


def main() -> int:
    parser = argparse.ArgumentParser(description="Serve the fixture-backed Cisco Cloud Control Agent Tokenomics API.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument("--input", default=None, help="O11y token metric rows JSON fixture")
    parser.add_argument("--galileo-input", default=None, help="Galileo runtime controls JSON fixture")
    parser.add_argument("--realm", default=None)
    args = parser.parse_args()

    server = make_server(
        args.host,
        args.port,
        o11y_fixture_path=args.input,
        galileo_fixture_path=args.galileo_input,
        realm=args.realm,
    )
    print(f"serving http://{args.host}:{args.port}")
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
