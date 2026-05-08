# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""skills.sh manifest adapter — kind=skills_sh.

Maps the skills.sh public catalog (`https://skills.sh/api/v1/`) into a
vendor-neutral :class:`Manifest`. skills.sh is the open agent skills
directory maintained by Vercel that aggregates GitHub-hosted skill
repos — every entry on the leaderboard ultimately resolves to a
``github.com/<owner>/<repo>`` install URL.

The adapter intentionally keeps the surface small:

* ``view=curated``   — calls ``/api/v1/skills/curated`` once.
                       Matches the "Official" tab on skills.sh; the
                       safest default for a high-trust environment
                       since these are publisher-vetted skills.
* ``view=all-time``  — paginated ``/api/v1/skills``, sorted by total
                       installs. Use when an operator wants to mirror
                       broad popular usage and let the scanner +
                       approve workflow filter.
* ``view=trending``  — same endpoint with ``view=trending`` for recent
                       growth.
* ``view=hot``       — same endpoint with ``view=hot`` (last hour vs
                       same hour yesterday).

URL format the operator passes to ``--url`` (all optional):

* Empty                                   → ``view=curated``
* ``curated`` / ``all-time`` / ``trending`` / ``hot`` → fetch that view
* ``https://skills.sh?view=trending&max=200`` → explicit override

Caps:

* ``max`` (default 200)  — hard cap on entries returned, applied
                           after pagination. We refuse anything over
                           :data:`MAX_SKILLS_RESULTS` so a runaway
                           query can't OOM the scanner subprocess.
* ``per_page`` (50)      — page size for listing endpoints. The API
                           supports up to 500 but smaller pages let
                           us bail early if the server starts
                           returning malformed rows.

isDuplicate entries are filtered out — skills.sh flags forks/copies
and we want one canonical row per skill.
"""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

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

DEFAULT_BASE_URL = "https://skills.sh"
"""Default skills.sh base URL.

Operators on a private mirror that re-serves the same JSON shape can
override via ``--url https://mirror.example.com``; the adapter only
calls ``GET /api/v1/skills*`` so any endpoint conforming to the
public skills.sh API works.
"""

DEFAULT_VIEW = "curated"
DEFAULT_PER_PAGE = 50
DEFAULT_MAX_RESULTS = 200

MAX_SKILLS_RESULTS = 2000
"""Hard upper bound on entries returned to the sync pipeline.

The API itself supports paging up to ``per_page=500`` and arbitrary
page counts, but the scanner runs one subprocess per skill at promote
time. 2k entries is already an aggressive ceiling; anything larger
should be sliced into multiple narrower sources (e.g. one per
publisher) so an operator's approve queue stays manageable.
"""

KNOWN_VIEWS = ("all-time", "trending", "hot", "curated")

# Tightly scoped slug pattern — skills.sh uses lowercase kebab-case for
# slugs and ``owner/repo`` for sources. We rebuild the manifest entry
# name from these and refuse anything that wouldn't survive
# :data:`NAME_RE`. The slash in source names becomes a dash in the
# manifest name so the value is safe for filesystem and audit-store
# use (matches the smithery adapter's normalisation).
_SOURCE_SAFE_RE = re.compile(r"[^a-zA-Z0-9._-]")


def fetch_skills_sh(
    source: RegistrySource,
    *,
    allow_private: bool = False,
    resolver: Resolver | None = None,
) -> tuple[Manifest, bytes]:
    """Fetch the configured skills.sh view and return a Manifest."""
    base_url, view, per_page, max_results = _parse_source_url(
        source.url or "",
    )

    if view == "curated":
        entries, raw = _fetch_curated(
            base_url, source, allow_private, resolver, max_results,
        )
    else:
        entries, raw = _fetch_paginated(
            base_url, view, per_page, max_results,
            source, allow_private, resolver,
        )

    manifest = Manifest(
        schema_version=1,
        publisher="skills.sh",
        entries=entries,
    )
    return manifest, raw


# ---------------------------------------------------------------------------
# URL parsing
# ---------------------------------------------------------------------------

def _parse_source_url(raw: str) -> tuple[str, str, int, int]:
    """Return (base_url, view, per_page, max_results) from *raw*.

    *raw* is the operator-supplied ``source.url`` and is intentionally
    permissive: empty / a bare view keyword / a full https URL with
    query params are all accepted, with caps enforced after parsing.
    """
    raw = (raw or "").strip()
    if not raw:
        return DEFAULT_BASE_URL, DEFAULT_VIEW, DEFAULT_PER_PAGE, DEFAULT_MAX_RESULTS
    if raw in KNOWN_VIEWS:
        return DEFAULT_BASE_URL, raw, DEFAULT_PER_PAGE, DEFAULT_MAX_RESULTS

    if not raw.startswith(("http://", "https://")):
        raise IngestError(
            "skills_sh source URL must be empty, one of "
            f"{KNOWN_VIEWS}, or a full https URL (got {raw!r})"
        )

    parsed = urlparse(raw)
    base = urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))
    qs = parse_qs(parsed.query)

    view = (qs.get("view", [DEFAULT_VIEW])[0] or DEFAULT_VIEW).lower()
    if view not in KNOWN_VIEWS:
        raise IngestError(
            f"skills_sh view must be one of {KNOWN_VIEWS} (got {view!r})"
        )

    per_page = _parse_pos_int(
        qs.get("per_page", [str(DEFAULT_PER_PAGE)])[0], "per_page",
        default=DEFAULT_PER_PAGE,
    )
    if per_page < 1 or per_page > 500:
        raise IngestError(
            f"skills_sh per_page must be 1..500 (got {per_page})"
        )

    max_results = _parse_pos_int(
        qs.get("max", [str(DEFAULT_MAX_RESULTS)])[0], "max",
        default=DEFAULT_MAX_RESULTS,
    )
    if max_results < 1 or max_results > MAX_SKILLS_RESULTS:
        raise IngestError(
            f"skills_sh max must be 1..{MAX_SKILLS_RESULTS} (got {max_results})"
        )

    return base, view, per_page, max_results


def _parse_pos_int(value: str, label: str, *, default: int) -> int:
    s = (value or "").strip()
    if not s:
        return default
    try:
        return int(s)
    except ValueError as exc:
        raise IngestError(f"skills_sh {label} must be an integer (got {value!r})") from exc


# ---------------------------------------------------------------------------
# Endpoint fetchers
# ---------------------------------------------------------------------------

def _fetch_curated(
    base_url: str,
    source: RegistrySource,
    allow_private: bool,
    resolver: Resolver | None,
    max_results: int,
) -> tuple[list[ManifestEntry], bytes]:
    url = f"{base_url}/api/v1/skills/curated"
    raw = http_get(
        url,
        auth_env=source.auth_env,
        accept="application/json",
        allow_private=allow_private,
        resolver=resolver,
    )
    payload = _decode_json(raw)
    owners = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(owners, list):
        raise IngestError(
            "skills.sh curated response missing 'data' array"
        )

    entries: list[ManifestEntry] = []
    seen: set[str] = set()
    for owner in owners:
        if not isinstance(owner, dict):
            continue
        skills = owner.get("skills")
        if not isinstance(skills, list):
            continue
        for skill in skills:
            entry = _skill_to_entry(skill)
            if entry is None or entry.name in seen:
                continue
            seen.add(entry.name)
            entries.append(entry)
            if len(entries) >= max_results:
                return entries, raw
    return entries, raw


def _fetch_paginated(
    base_url: str,
    view: str,
    per_page: int,
    max_results: int,
    source: RegistrySource,
    allow_private: bool,
    resolver: Resolver | None,
) -> tuple[list[ManifestEntry], bytes]:
    """Walk ``/api/v1/skills`` until *max_results* or pagination ends.

    The first page's raw bytes are kept as the canonical "raw manifest"
    for cache persistence — operators inspecting
    ``~/.defenseclaw/registries/<id>/manifest.json`` will see the
    server-shaped response, not our re-stitched view, which makes
    drift between API versions easier to spot.
    """
    entries: list[ManifestEntry] = []
    seen: set[str] = set()
    first_raw: bytes | None = None
    page = 0
    safety_pages = (max_results // max(per_page, 1)) + 2
    while len(entries) < max_results and page < safety_pages:
        params = urlencode({
            "view": view,
            "page": page,
            "per_page": min(per_page, max_results - len(entries)),
        })
        url = f"{base_url}/api/v1/skills?{params}"
        raw = http_get(
            url,
            auth_env=source.auth_env,
            accept="application/json",
            allow_private=allow_private,
            resolver=resolver,
        )
        if first_raw is None:
            first_raw = raw
        payload = _decode_json(raw)
        if not isinstance(payload, dict):
            raise IngestError("skills.sh response was not a JSON object")
        rows = payload.get("data")
        if not isinstance(rows, list):
            raise IngestError("skills.sh response missing 'data' array")
        if not rows:
            break
        for row in rows:
            entry = _skill_to_entry(row)
            if entry is None or entry.name in seen:
                continue
            seen.add(entry.name)
            entries.append(entry)
            if len(entries) >= max_results:
                break
        pagination = payload.get("pagination")
        if not isinstance(pagination, dict) or not pagination.get("hasMore"):
            break
        page += 1

    if first_raw is None:
        first_raw = b'{"data":[]}'
    return entries, first_raw


# ---------------------------------------------------------------------------
# Mapping
# ---------------------------------------------------------------------------

def _skill_to_entry(row: Any) -> ManifestEntry | None:
    """Convert a skills.sh ``V1Skill`` object into a :class:`ManifestEntry`.

    Returns None for malformed rows or known forks/copies — the
    sync pipeline already logs structured errors at a higher layer,
    so silently dropping a single bad row keeps the rest of the
    catalog usable.
    """
    if not isinstance(row, dict):
        return None
    if row.get("isDuplicate") is True:
        return None

    skill_id = str(row.get("id") or "").strip()
    slug = str(row.get("slug") or "").strip()
    skill_source = str(row.get("source") or "").strip()
    if not skill_id or not slug or not skill_source:
        return None

    # Manifest names must match NAME_RE — collapse "owner/repo/slug"
    # into "owner-repo-slug" with non-allowed chars replaced by dashes,
    # then truncate to the 128-char cap. Skills.sh slugs and sources
    # are already kebab-cased so this rarely changes anything; the
    # collapse defends against future schema additions that might
    # introduce other characters.
    name = _SOURCE_SAFE_RE.sub("-", skill_id.replace("/", "-"))
    name = name.strip("-").strip(".")[:128]
    if not name or not NAME_RE.match(name):
        return None

    install_url = str(row.get("installUrl") or "").strip()
    source_type = str(row.get("sourceType") or "github").strip().lower()

    # GitHub repos are by far the most common case. We pass the repo
    # URL through verbatim — the existing skill scanner treats
    # ``https://github.com/owner/repo`` as a tarball download
    # candidate via the registry-side install flow. Well-known
    # sources are passed through unchanged for a future
    # ``.well-known/skills`` scan path.
    #
    # HTTPS-only on purpose: skills.sh is a TLS-only public catalog
    # and accepting plain ``http://`` would let an on-path attacker
    # downgrade a skill download. The scanner happily fetches the
    # URL later, so this guard is the only place we can refuse the
    # install before it lands in cache.
    if not install_url.startswith("https://"):
        return None
    if source_type == "github" and "github.com" not in install_url:
        return None

    publisher = skill_source.split("/", 1)[0] if "/" in skill_source else skill_source
    description = str(row.get("name") or "")[:256]
    homepage = str(row.get("url") or "")
    if homepage and not homepage.startswith("https://"):
        homepage = ""

    return ManifestEntry(
        name=name,
        type="skill",
        source_url=install_url,
        publisher=publisher,
        description=description,
        homepage=homepage,
        tags=[source_type] if source_type else [],
    )


def _decode_json(raw: bytes) -> Any:
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise IngestError(f"skills.sh response is not valid JSON: {exc}") from exc
