# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Source adapters — each one knows how to turn a :class:`RegistrySource`
into a parsed :class:`Manifest`.

The dispatch entry point is :func:`fetch_manifest`. Adapters live in
sibling modules so each source kind can be unit-tested in isolation
with a mocked HTTP client; this module is a thin façade over them.
"""

from __future__ import annotations

from defenseclaw.config import RegistrySource
from defenseclaw.registries.adapters._base import IngestError
from defenseclaw.registries.adapters.clawhub import fetch_clawhub
from defenseclaw.registries.adapters.file import fetch_file
from defenseclaw.registries.adapters.git import fetch_git
from defenseclaw.registries.adapters.http_manifest import fetch_http
from defenseclaw.registries.adapters.skills_sh import fetch_skills_sh
from defenseclaw.registries.adapters.smithery import fetch_smithery
from defenseclaw.registries.manifest import Manifest
from defenseclaw.registries.ssrf import Resolver


def fetch_manifest(
    source: RegistrySource,
    *,
    allow_private: bool = False,
    resolver: Resolver | None = None,
) -> tuple[Manifest, bytes]:
    """Resolve *source* to a parsed manifest + the raw fetched bytes.

    Returns ``(manifest, raw_bytes)`` so the caller can persist the
    fetched bytes verbatim alongside the parsed view (see
    :mod:`defenseclaw.registries.cache`). Raises
    :class:`IngestError` on any fetch / parse / SSRF failure.

    The optional ``resolver`` is plumbed through to every adapter so
    test suites can stub DNS without hitting the network. Production
    callers leave it None.
    """
    kind = source.kind
    if kind == "clawhub":
        return fetch_clawhub(
            source, allow_private=allow_private, resolver=resolver,
        )
    if kind == "smithery":
        return fetch_smithery(
            source, allow_private=allow_private, resolver=resolver,
        )
    if kind == "skills_sh":
        return fetch_skills_sh(
            source, allow_private=allow_private, resolver=resolver,
        )
    if kind in ("http_yaml", "http_json"):
        return fetch_http(
            source, allow_private=allow_private, resolver=resolver,
        )
    if kind == "git":
        return fetch_git(
            source, allow_private=allow_private, resolver=resolver,
        )
    if kind == "file":
        return fetch_file(source)
    raise IngestError(f"unknown registry kind: {kind!r}")


__all__ = [
    "IngestError",
    "fetch_manifest",
    "fetch_clawhub",
    "fetch_file",
    "fetch_git",
    "fetch_http",
    "fetch_skills_sh",
    "fetch_smithery",
]
