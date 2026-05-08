# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Generic HTTPS manifest adapter — kind=http_yaml / http_json.

The fetch is identical regardless of declared content type; the parser
auto-detects YAML vs JSON. The ``http_yaml`` / ``http_json`` split in
the source kind is purely advisory (it lets the TUI render a friendlier
hint, and a future cron scheduler could pick different mime hints) —
the adapter doesn't care which one came in.
"""

from __future__ import annotations

from defenseclaw.config import RegistrySource
from defenseclaw.registries.adapters._base import (
    IngestError,
    http_get,
    normalize_url,
)
from defenseclaw.registries.manifest import Manifest, parse_manifest
from defenseclaw.registries.ssrf import Resolver


def fetch_http(
    source: RegistrySource,
    *,
    allow_private: bool = False,
    resolver: Resolver | None = None,
) -> tuple[Manifest, bytes]:
    url = normalize_url(source)
    if not url:
        raise IngestError(
            f"source {source.id!r} has no URL — set --url to register the catalog"
        )
    raw = http_get(
        url,
        auth_env=source.auth_env,
        allow_private=allow_private,
        resolver=resolver,
    )
    manifest = parse_manifest(raw)
    return manifest, raw
