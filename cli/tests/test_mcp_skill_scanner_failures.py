# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for MCP and skill scanner failure handling (final cert b3)."""

from __future__ import annotations

import socket
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from defenseclaw.logger import Logger


class _Recorder:
    def __init__(self) -> None:
        self.payloads: list[dict] = []

    def emit_cli_observability(self, payload) -> None:
        self.payloads.append(dict(payload))

    def close(self) -> None:
        return


def test_default_resolver_keeps_getaddrinfo_order():
    """GAP-1311: a set shuffled the answers per process, so the pin
    sometimes chose an unreachable IPv6 address."""
    from defenseclaw.registries import ssrf

    answers = [
        "52.27.233.237", "32.185.46.209", "52.34.242.133",
        "2600:1f14:36ec:d01::51af", "2600:1f14:36ec:d02::6ba6", "2600:1f14:36ec:d00::bf7b",
    ]
    infos = []
    for ip in answers + answers[:2]:
        family = socket.AF_INET6 if ":" in ip else socket.AF_INET
        infos.append((family, socket.SOCK_STREAM, 6, "", (ip, 0)))
    with patch.object(ssrf.socket, "getaddrinfo", return_value=infos):
        assert ssrf._default_resolver("mcp.example.com") == answers
