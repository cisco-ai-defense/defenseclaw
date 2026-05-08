# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Smithery.ai manifest adapter — kind=smithery.

Maps the Smithery catalog API response into a vendor-neutral
:class:`Manifest`. The default endpoint is
``https://registry.smithery.ai/servers``; operators on a private
mirror can override the URL.

The adapter intentionally exposes a minimal subset of Smithery
metadata — the goal is to surface enough fields for the scanner to
run and for the operator to make an approve/reject decision in the
TUI, not to mirror Smithery's full schema.
"""

from __future__ import annotations

import json
from typing import Any

from defenseclaw.config import RegistrySource
from defenseclaw.registries.adapters._base import (
    IngestError,
    http_get,
)
from defenseclaw.registries.manifest import (
    COMMAND_RE,
    NAME_RE,
    Manifest,
    ManifestEntry,
)
from defenseclaw.registries.ssrf import Resolver, SSRFError, guard_url

DEFAULT_SMITHERY_URL = "https://registry.smithery.ai/servers"


def fetch_smithery(
    source: RegistrySource,
    *,
    allow_private: bool = False,
    resolver: Resolver | None = None,
) -> tuple[Manifest, bytes]:
    url = (source.url or "").strip() or DEFAULT_SMITHERY_URL
    raw = http_get(
        url,
        auth_env=source.auth_env,
        accept="application/json",
        allow_private=allow_private,
        resolver=resolver,
    )
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise IngestError(f"smithery response is not valid JSON: {exc}") from exc

    servers = _extract_servers(payload)
    entries: list[ManifestEntry] = []
    for server in servers:
        if not isinstance(server, dict):
            continue
        try:
            entry = _server_to_entry(
                server,
                allow_private=allow_private,
                resolver=resolver,
            )
        except IngestError:
            # Skip individual bad rows — a single malformed server
            # shouldn't break the whole sync. Operators can still see
            # what was rejected via the structured log.
            continue
        if entry is None:
            continue
        entries.append(entry)

    manifest = Manifest(
        schema_version=1,
        publisher="smithery",
        entries=entries,
    )
    return manifest, raw


def _extract_servers(payload: Any) -> list[dict[str, Any]]:
    """Return the server array from a Smithery response.

    Smithery uses a few historical envelope shapes; we accept the
    common ones and bail with a clear error otherwise so a future API
    change is easy to spot.
    """
    if isinstance(payload, list):
        return [s for s in payload if isinstance(s, dict)]
    if not isinstance(payload, dict):
        raise IngestError("smithery response was neither array nor object")
    for key in ("servers", "data", "items", "results"):
        value = payload.get(key)
        if isinstance(value, list):
            return [s for s in value if isinstance(s, dict)]
    raise IngestError(
        "smithery response is missing a servers array (looked for "
        "'servers', 'data', 'items', 'results')"
    )


def _server_to_entry(
    server: dict[str, Any],
    *,
    allow_private: bool = False,
    resolver: Resolver | None = None,
) -> ManifestEntry | None:
    name = str(
        server.get("qualifiedName")
        or server.get("name")
        or server.get("id")
        or "",
    )
    name = name.replace("/", "-").replace("@", "").strip()
    if not NAME_RE.match(name):
        return None

    deployment = server.get("deployment") or {}
    if not isinstance(deployment, dict):
        deployment = {}

    transport = str(deployment.get("transport") or server.get("transport") or "stdio")
    transport = transport.strip().lower()

    command = str(deployment.get("command") or "")
    if command and not COMMAND_RE.match(command):
        return None

    args_raw = deployment.get("args") or []
    if not isinstance(args_raw, list):
        args_raw = []
    args = [str(a) for a in args_raw[:64]]

    env_raw = deployment.get("env") or []
    if isinstance(env_raw, dict):
        env_raw = list(env_raw.keys())
    if not isinstance(env_raw, list):
        env_raw = []
    env_required = [str(e) for e in env_raw[:32] if isinstance(e, str)]

    url = str(deployment.get("url") or "")
    if transport == "stdio" and not command:
        return None
    if transport != "stdio":
        if not url:
            return None
        # Network-bound MCP transports go straight from the
        # registry into ``asset_policy.mcp.registry`` and are then
        # opened by the gateway connector. A malicious smithery
        # entry could publish ``url: http://internal.corp/admin``;
        # the scanner is unlikely to flag the URL itself, so we
        # gate it here:
        # * HTTPS-only — no plaintext MCP transports.
        # * SSRF guard — same allow-list and private-IP policy
        #   as the registry fetch path. ``allow_private`` is
        #   forwarded so an operator who explicitly opted in for
        #   the ingest also opts in for the published targets.
        if not url.startswith("https://"):
            return None
        try:
            guard_url(url, allow_private=allow_private, resolver=resolver)
        except SSRFError:
            return None

    return ManifestEntry(
        name=name,
        type="mcp",
        transport=transport if transport in (
            "stdio", "http", "sse", "streamable-http", "websocket",
        ) else "stdio",
        command=command,
        args=args,
        env_required=env_required,
        url=url,
        version=str(server.get("version") or ""),
        license=str(server.get("license") or ""),
        publisher=str(server.get("publisher") or "smithery"),
        description=str(server.get("description") or "")[:2048],
        homepage=str(server.get("homepage") or "")[:2048],
    )
