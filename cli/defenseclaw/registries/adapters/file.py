# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Local-file manifest adapter — kind=file.

Reads ``source.url`` as a filesystem path. Useful for air-gapped
deployments, regression tests, and the TUI dry-run flow that lets an
operator preview a manifest before promoting it.
"""

from __future__ import annotations

from pathlib import Path

from defenseclaw.config import RegistrySource
from defenseclaw.registries.adapters._base import (
    MAX_MANIFEST_BYTES,
    IngestError,
    normalize_url,
)
from defenseclaw.registries.manifest import Manifest, parse_manifest


def fetch_file(source: RegistrySource) -> tuple[Manifest, bytes]:
    url = normalize_url(source)
    if not url:
        raise IngestError(f"source {source.id!r} has no path")
    if url.lower().startswith("file://"):
        url = url[len("file://"):]
    p = Path(url).expanduser()
    if not p.is_absolute():
        raise IngestError(
            f"source {source.id!r} path must be absolute (got {url!r})"
        )
    if not p.exists():
        raise IngestError(f"manifest file does not exist: {p}")
    if not p.is_file():
        raise IngestError(f"manifest path is not a regular file: {p}")
    try:
        size = p.stat().st_size
    except OSError as exc:
        raise IngestError(f"could not stat {p}: {exc}") from exc
    if size > MAX_MANIFEST_BYTES:
        raise IngestError(
            f"manifest file is {size} bytes (max {MAX_MANIFEST_BYTES})"
        )
    raw = p.read_bytes()
    manifest = parse_manifest(raw)
    return manifest, raw
