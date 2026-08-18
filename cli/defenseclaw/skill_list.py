# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""Connector-agnostic skill enumeration.

Provides :func:`list_skills`, the canonical way to ask "what skills
are installed?" without caring which agent framework is active.

For OpenClaw the answer comes from the ``openclaw skills list
--json`` CLI (and falls back to walking ``Config.skill_dirs()``
when the binary isn't available). For Codex / Claude Code /
ZeptoClaw — none of which have a comparable JSON CLI — we walk
``Config.skill_dirs()`` directly. This mirrors the AIBOM filesystem
adapter in :mod:`defenseclaw.inventory.claw_inventory` (S4.3); the
two pieces share the same eligibility / description rules so the
``defenseclaw skill list`` and ``defenseclaw aibom scan`` outputs
agree on which skills exist.

Schema returned: a list of dicts, each with::

    {
        "name": "<skill id>",         # required
        "description": "<one-line>",  # may be ""
        "eligible": True/False,        # has SKILL.md / skill.json / README.md
        "disabled": False,             # filesystem walks always return False
        "source": "<directory path>", # where the skill lives
        "bundled": False,              # True for Codex .system child skills
        "path": "<full path>",        # absolute path to the skill dir
    }

OpenClaw rows additionally include the original ``openclaw skills
list`` payload (``emoji``, ``missing``, etc.).
"""

from __future__ import annotations

import json
import os
import subprocess
from typing import TYPE_CHECKING, Any

from defenseclaw.safety import is_symlink
from defenseclaw.skill_discovery import (
    discover_skill_directories,
    skill_dir_is_eligible,
)

if TYPE_CHECKING:
    from defenseclaw.config import Config


def list_skills(
    cfg: Config, *, prefer_cli: bool = True, connector: str | None = None
) -> list[dict[str, Any]]:
    """Return the connector-aware skill list.

    Parameters
    ----------
    cfg
        The :class:`defenseclaw.config.Config` carrying the active
        connector (via :meth:`Config.active_connector`).
    prefer_cli
        For ``openclaw`` only — when True (default) we shell out to
        ``openclaw skills list --json`` first and only walk the
        filesystem when the CLI isn't available. When False we always
        walk the filesystem; useful in tests and inside sandboxes
        that don't have an ``openclaw`` binary on $PATH.
    connector
        Multi-connector override (``skill list --connector <name>``).
        When supplied, that connector's directories are walked instead
        of the active connector's. Defaults to
        :meth:`Config.active_connector`.
    """
    resolved = connector or cfg.active_connector()
    if resolved == "openclaw" and prefer_cli:
        rows = _list_skills_via_openclaw_cli()
        if rows is not None:
            return rows
    return _list_skills_from_filesystem(cfg, connector=resolved)


# ---------------------------------------------------------------------------
# OpenClaw CLI adapter
# ---------------------------------------------------------------------------


def _list_skills_via_openclaw_cli() -> list[dict[str, Any]] | None:
    """Invoke ``openclaw skills list --json`` and parse the response.

    Returns ``None`` (so the caller falls back to the filesystem
    walk) when the binary is missing, exits non-zero, or emits
    non-JSON.
    """
    try:
        from defenseclaw.config import openclaw_bin, openclaw_cmd_prefix
        prefix = openclaw_cmd_prefix()
    except Exception:
        return None

    try:
        result = subprocess.run(
            [*prefix, openclaw_bin(), "skills", "list", "--json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None

    if result.returncode != 0:
        return None
    try:
        payload = json.loads(result.stdout or "{}")
    except json.JSONDecodeError:
        return None

    raw_skills = payload.get("skills") if isinstance(payload, dict) else None
    if not isinstance(raw_skills, list):
        return []

    # Normalize the OpenClaw payload into the shared schema.
    rows: list[dict[str, Any]] = []
    for s in raw_skills:
        if not isinstance(s, dict):
            continue
        name = s.get("name", "")
        if not name:
            continue
        rows.append({
            "name": name,
            "description": s.get("description", ""),
            "eligible": bool(s.get("eligible", True)),
            "disabled": bool(s.get("disabled", False)),
            "source": s.get("source", ""),
            "bundled": bool(s.get("bundled", False)),
            "path": s.get("path", ""),
            **{
                k: s[k] for k in ("emoji", "missing")
                if k in s
            },
        })
    return rows


# ---------------------------------------------------------------------------
# Filesystem adapter (Codex / Claude Code / ZeptoClaw / OpenClaw fallback)
# ---------------------------------------------------------------------------


def _list_skills_from_filesystem(
    cfg: Config, connector: str | None = None
) -> list[dict[str, Any]]:
    """Walk every directory in ``cfg.skill_dirs()`` and return one
    row per immediate subdirectory. Codex's reserved ``.system`` container is
    expanded into its marked child skills instead of being reported as one
    ineligible skill.

    Mirrors the rules used by
    :func:`defenseclaw.inventory.claw_inventory._enumerate_skills_filesystem`
    so ``skill list`` and ``aibom scan`` agree on which skills exist.

    ``connector`` selects which connector's directories to walk
    (multi-connector focus); defaults to the active connector.
    """
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for skill_dir in cfg.skill_dirs(connector):
        if not os.path.isdir(skill_dir):
            continue
        for discovered in discover_skill_directories(
            skill_dir, connector=connector or cfg.active_connector()
        ):
            entry = discovered.name
            if _is_openhands_installed_container(skill_dir, entry):
                continue
            full = discovered.path
            if entry in seen:
                continue
            seen.add(entry)
            row: dict[str, Any] = {
                "name": entry,
                "description": _read_skill_description(full),
                "eligible": _skill_dir_is_eligible(full),
                "disabled": False,
                "source": discovered.source,
                "bundled": discovered.bundled,
                "baseDir": full,
                "path": full,
            }
            rows.append(row)
    return rows


def _is_openhands_installed_container(skill_dir: str, entry: str) -> bool:
    return (
        entry == "installed"
        and os.path.basename(skill_dir) == "skills"
        and os.path.basename(os.path.dirname(skill_dir)) == ".openhands"
    )


def _skill_dir_is_eligible(path: str) -> bool:
    return skill_dir_is_eligible(path)


def _read_skill_description(path: str) -> str:
    """Return a short description from SKILL.md / README.md.

    Bounded to 2 KiB so we don't accidentally slurp a multi-MB README
    into the listing.
    """
    for marker in ("SKILL.md", "README.md"):
        marker_path = os.path.join(path, marker)
        # F-0281: ``os.path.isfile`` follows symlinks, so a malicious skill
        # dir could symlink SKILL.md/README.md to an arbitrary
        # operator-readable file (``~/.netrc``, ``/etc/shadow`` …) and leak
        # its first non-empty line into the skill listing. Skip the marker
        # if it is a symlink — we only describe files the skill author
        # actually authored inside the skill dir.
        if is_symlink(marker_path) or not os.path.isfile(marker_path):
            continue
        try:
            with open(marker_path, encoding="utf-8", errors="replace") as f:
                text = f.read(2048)
        except OSError:
            continue
        frontmatter_description = _frontmatter_description(text)
        if frontmatter_description:
            return frontmatter_description[:200]
        for line in text.splitlines():
            stripped = line.strip().lstrip("#").strip()
            if stripped:
                return stripped[:200]
    return ""


def _frontmatter_description(text: str) -> str:
    if not text.startswith("---"):
        return ""
    end = text.find("\n---", 3)
    if end < 0:
        return ""
    for line in text[3:end].splitlines():
        key, sep, value = line.partition(":")
        if sep and key.strip() == "description":
            return value.strip().strip("\"'")
    return ""
