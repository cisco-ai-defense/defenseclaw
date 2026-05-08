# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""ClawHub manifest adapter — kind=clawhub.

Reads the ``openclaw`` npm package metadata from
``https://registry.npmjs.org/openclaw/latest`` and synthesises a
:class:`Manifest` listing every plugin under ``package/plugins/`` as a
:class:`ManifestEntry` with ``source_url=clawhub://<name>``.

We do this server-side metadata read rather than streaming the whole
tarball at sync time so that ``registry sync clawhub`` is fast (one
HTTP call) and so the sync pipeline doesn't fight the existing
``defenseclaw plugin install clawhub://...`` flow that already knows
how to download the actual tarball at install time.
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
    NAME_RE,
    Manifest,
    ManifestEntry,
)
from defenseclaw.registries.ssrf import Resolver

DEFAULT_NPM_REGISTRY = "https://registry.npmjs.org"


def fetch_clawhub(
    source: RegistrySource,
    *,
    allow_private: bool = False,
    resolver: Resolver | None = None,
) -> tuple[Manifest, bytes]:
    """Synthesize a :class:`Manifest` from the openclaw npm package.

    The fetch goes through :func:`http_get` so the SSRF guard, response
    size cap, and redirect-rebound-against-the-allow-list checks apply
    to operator-overridden npm registries the same way they do to
    every other adapter — historically this adapter called
    :func:`requests.get` directly, which left a hole when ``--url``
    pointed at internal infra.
    """
    registry = (source.url or "").strip() or DEFAULT_NPM_REGISTRY
    if not registry.startswith(("http://", "https://")):
        raise IngestError(
            f"clawhub source URL must be http(s); got {registry!r}"
        )
    raw = http_get(
        f"{registry}/openclaw/latest",
        auth_env=source.auth_env,
        accept="application/json",
        allow_private=allow_private,
        resolver=resolver,
    )
    try:
        meta: dict[str, Any] = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise IngestError(f"npm metadata is not valid JSON: {exc}") from exc

    plugins = (
        meta.get("openclaw", {}).get("plugins")
        or meta.get("plugins")
        or {}
    )
    if not isinstance(plugins, dict):
        raise IngestError(
            "openclaw package metadata is missing the plugins map; "
            "either upgrade openclaw or use kind=http_yaml against "
            "your own catalog"
        )

    entries: list[ManifestEntry] = []
    for plugin_name, plugin_meta in sorted(plugins.items()):
        if not isinstance(plugin_name, str) or not NAME_RE.match(plugin_name):
            continue
        if not isinstance(plugin_meta, dict):
            plugin_meta = {}
        entries.append(ManifestEntry(
            name=plugin_name,
            type="skill",
            source_url=f"clawhub://{plugin_name}",
            version=str(plugin_meta.get("version", "") or ""),
            license=str(plugin_meta.get("license", "") or ""),
            publisher="clawhub",
            description=str(plugin_meta.get("description", "") or "")[:2048],
            homepage=str(plugin_meta.get("homepage", "") or "")[:2048],
        ))

    manifest = Manifest(
        schema_version=1,
        publisher="clawhub",
        generated_at=str(meta.get("time", {}).get("modified", "") or ""),
        entries=entries,
    )
    return manifest, raw
