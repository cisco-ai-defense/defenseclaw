# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Display-only helpers for observability destinations."""

from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit


def redact_endpoint_for_display(endpoint: str, *, hide_path: bool = False) -> str:
    """Return an endpoint safe for terminal/TUI display.

    Runtime callers retain the original value.  This representation removes
    URL userinfo, query parameters, and fragments.  Audit/webhook callers can
    also hide provider-specific path tokens with ``hide_path=True``.
    """

    value = str(endpoint or "").strip()
    if not value or value == "—":
        return value or "—"

    has_scheme = "://" in value
    candidate = value if has_scheme else f"//{value}"
    try:
        parsed = urlsplit(candidate)
        hostname = parsed.hostname
        if not hostname:
            return "<redacted-endpoint>"
        host = f"[{hostname}]" if ":" in hostname and not hostname.startswith("[") else hostname
        try:
            if parsed.port is not None:
                host = f"{host}:{parsed.port}"
        except ValueError:
            return "<redacted-endpoint>"
        path = parsed.path or ""
        if hide_path and path not in {"", "/"}:
            path = "/…"
        safe = urlunsplit((parsed.scheme if has_scheme else "", host, path, "", ""))
        return safe if has_scheme else safe.removeprefix("//")
    except (TypeError, ValueError):
        return "<redacted-endpoint>"
