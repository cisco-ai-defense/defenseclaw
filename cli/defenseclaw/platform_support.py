# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Per-OS connector support — the Python single source of truth.

DefenseClaw runs hook-only on Windows: agents invoke the native Go hook
entrypoint (``defenseclaw-gateway hook``) directly, and there is no Windows
guardrail-proxy lifecycle. The proxy/chat connectors (``openclaw`` and
``zeptoclaw``) therefore cannot run on Windows, so the TUI/CLI must not
offer or accept them there.

This module mirrors the Go ``connector.proxyConnectors`` set in
``internal/gateway/connector/platform_support.go``; a parity test pins the
two together so the lists cannot drift.

Filtering is a pure no-op on non-Windows hosts, so callers can apply it
unconditionally at presentation/validation points without changing
behavior on macOS or Linux.
"""

from __future__ import annotations

import sys
from collections.abc import Iterable

# Proxy/chat connectors that require the local guardrail proxy. These are
# the only connectors unsupported on Windows. Keep in sync with the Go
# ``proxyConnectors`` map.
WINDOWS_UNSUPPORTED_CONNECTORS: frozenset[str] = frozenset({"openclaw", "zeptoclaw"})


def host_os() -> str:
    """Return a Go-``GOOS``-style token for the current host.

    Normalizes ``sys.platform`` to ``"windows"`` / ``"darwin"`` / ``"linux"``
    so the same string compares cleanly against the Go side and against the
    ``os_name`` arguments below.
    """
    plat = sys.platform
    if plat.startswith("win"):
        return "windows"
    if plat == "darwin":
        return "darwin"
    if plat.startswith("linux"):
        return "linux"
    return plat


def is_proxy_connector(name: str) -> bool:
    """Report whether *name* is a proxy/chat connector."""
    return name in WINDOWS_UNSUPPORTED_CONNECTORS


def connector_supported_on_os(name: str, os_name: str | None = None) -> bool:
    """Report whether connector *name* can be offered/used on *os_name*.

    Every hook-based connector is supported on every OS; the proxy
    connectors are unsupported on Windows. *os_name* defaults to the host
    OS but is injectable so tests can assert behavior for any platform.
    """
    if os_name is None:
        os_name = host_os()
    if os_name == "windows" and name in WINDOWS_UNSUPPORTED_CONNECTORS:
        return False
    return True


def supported_connectors(
    names: Iterable[str], os_name: str | None = None
) -> list[str]:
    """Filter *names* down to those supported on *os_name*, preserving order."""
    if os_name is None:
        os_name = host_os()
    return [n for n in names if connector_supported_on_os(n, os_name)]
