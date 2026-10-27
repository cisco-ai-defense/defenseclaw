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
    ManifestError,
    validate_entry,
)
from defenseclaw.registries.ssrf import Resolver, SSRFError, guard_url

DEFAULT_SMITHERY_URL = "https://registry.smithery.ai/servers"

# The catalog list gives a hosted (remote) server's name but not its URL;
# the server's own record does (deploymentUrl). At most this many records
# are fetched per sync, so a dry run stays a handful of requests.
MAX_SMITHERY_DETAIL_FETCHES = 25


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
    notes: list[str] = []
    detail_fetches = 0
    no_url = 0
    detail_failed = 0
    capped = 0
    unusable = 0
    for server in servers:
        if not isinstance(server, dict):
            continue
        if _remote_without_url(server):
            # GAP-1640: the current catalog lists hosted servers with
            # remote=true and no deployment; read the server's record.
            if detail_fetches >= MAX_SMITHERY_DETAIL_FETCHES:
                capped += 1
                continue
            detail_fetches += 1
            detail = _fetch_server_detail(
                url, server, auth_env=source.auth_env,
                allow_private=allow_private, resolver=resolver,
            )
            if detail is None:
                detail_failed += 1
                continue
            server = {**server, **detail}
            if _remote_without_url(server):
                no_url += 1
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
            unusable += 1
            continue
        if entry is None:
            unusable += 1
            continue
        entries.append(entry)

    if detail_failed:
        notes.append(f"{detail_failed} hosted server record(s) could not be fetched")
    if no_url:
        notes.append(f"{no_url} hosted server(s) have no deployment URL in their record")
    if capped:
        notes.append(
            f"{capped} more hosted server(s) were not read: at most "
            f"{MAX_SMITHERY_DETAIL_FETCHES} server records are fetched per sync"
        )
    if unusable:
        notes.append(
            f"{unusable} server(s) were skipped: no https URL or allowed stdio command, "
            "or a field the manifest does not accept"
        )
    manifest = Manifest(
        schema_version=1,
        publisher="smithery",
        entries=entries,
        notes=notes,
    )
    return manifest, raw


def _remote_without_url(server: dict[str, Any]) -> bool:
    """A hosted server row that names no URL to connect to."""
    if server.get("remote") is not True:
        return False
    deployment = server.get("deployment")
    if isinstance(deployment, dict) and (deployment.get("url") or deployment.get("command")):
        return False
    return not _deployment_url(server)


def _deployment_url(server: dict[str, Any]) -> str:
    """The hosted server's URL: ``deploymentUrl``, else its HTTP connection's."""
    url = server.get("deploymentUrl")
    if isinstance(url, str) and url:
        return url
    for connection in server.get("connections") or []:
        if isinstance(connection, dict) and connection.get("type") in ("http", "streamable-http"):
            candidate = connection.get("deploymentUrl")
            if isinstance(candidate, str) and candidate:
                return candidate
    return ""


def _fetch_server_detail(
    list_url: str,
    server: dict[str, Any],
    *,
    auth_env: str = "",
    allow_private: bool = False,
    resolver: Resolver | None = None,
) -> dict[str, Any] | None:
    """Fetch one server's record (``<list url>/<qualifiedName>``), or None."""
    from urllib.parse import quote, urlsplit, urlunsplit

    qualified = str(server.get("qualifiedName") or "").strip()
    if not qualified:
        return None
    parts = urlsplit(list_url)
    path = parts.path.rstrip("/") + "/" + quote(qualified, safe="@/")
    detail_url = urlunsplit((parts.scheme, parts.netloc, path, "", ""))
    try:
        raw = http_get(
            detail_url,
            auth_env=auth_env,
            accept="application/json",
            allow_private=allow_private,
            resolver=resolver,
        )
        detail = json.loads(raw)
    except (IngestError, SSRFError, json.JSONDecodeError, ValueError):
        return None
    if not isinstance(detail, dict):
        return None
    return {
        key: detail[key]
        for key in ("deploymentUrl", "connections", "remote")
        if key in detail
    }


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

    hosted_url = "" if deployment.get("url") or deployment.get("command") else _deployment_url(server)
    default_transport = "streamable-http" if hosted_url else "stdio"
    transport = str(deployment.get("transport") or server.get("transport") or default_transport)
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

    url = str(deployment.get("url") or hosted_url or "")
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

    # Route the synthesized entry through the shared manifest validator
    # rather than constructing a ManifestEntry directly. The hand-written
    # checks in validate_entry() enforce the env-var character class,
    # transport enum, and length caps that the per-row code below was
    # silently coercing (e.g. unknown transports → "stdio") instead of
    # rejecting. A single source of truth for entry validity keeps the
    # security guarantees uniform across every adapter.
    candidate: dict[str, Any] = {
        "name": name,
        "type": "mcp",
        "transport": transport,
        "command": command,
        "args": args,
        "env_required": env_required,
        "url": url,
        "version": str(server.get("version") or ""),
        "license": str(server.get("license") or ""),
        "publisher": str(server.get("publisher") or "smithery"),
        "description": str(server.get("description") or "")[:2048],
        "homepage": str(server.get("homepage") or "")[:2048],
    }
    try:
        return validate_entry(candidate)
    except ManifestError as exc:
        # Convert to IngestError so the per-row except handler in
        # fetch_smithery() drops just this entry and keeps syncing.
        raise IngestError(f"smithery entry {name!r}: {exc}") from exc
