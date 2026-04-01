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

"""Centralized resolution of bundled data and repo-relative resources.

Wheel install (production):
    <site-packages>/defenseclaw/_data/policies/
    <site-packages>/defenseclaw/_data/skills/codeguard/
    <site-packages>/defenseclaw/_data/splunk_local_bridge/

Editable install (dev):
    <repo>/policies/
    <repo>/skills/codeguard/
    <repo>/bundles/splunk_local_bridge/
    <repo>/extensions/defenseclaw/

Every resolver tries _data/ first (wheel), then repo-relative (dev).
"""

from __future__ import annotations

import os
from pathlib import Path

_PKG_DIR = Path(__file__).resolve().parent
_DATA_DIR = _PKG_DIR / "_data"
_REPO_ROOT = _PKG_DIR.parent.parent


def _first_existing(*candidates: Path) -> Path:
    """Return the first candidate directory that exists, or the first candidate."""
    for c in candidates:
        if c.is_dir():
            return c
    return candidates[0]


def bundled_policies_dir() -> Path:
    """YAML policy files (default.yaml, strict.yaml, etc.)."""
    return _first_existing(
        _DATA_DIR / "policies",
        _REPO_ROOT / "policies",
    )


def bundled_rego_dir() -> Path:
    """Rego modules and data.json for OPA."""
    return _first_existing(
        _DATA_DIR / "policies" / "rego",
        _REPO_ROOT / "policies" / "rego",
    )


def bundled_codeguard_dir() -> Path:
    """CodeGuard skill source (SKILL.md, skill.yaml, main.py)."""
    return _first_existing(
        _DATA_DIR / "skills" / "codeguard",
        _REPO_ROOT / "skills" / "codeguard",
    )


def bundled_splunk_bridge_dir() -> Path:
    """Vendored Splunk local bridge runtime."""
    return _first_existing(
        _DATA_DIR / "splunk_local_bridge",
        _REPO_ROOT / "bundles" / "splunk_local_bridge",
    )


def bundled_extensions_dir() -> Path:
    """Built OpenClaw plugin (package.json + dist/)."""
    dc_home = Path.home() / ".defenseclaw"
    return _first_existing(
        dc_home / "extensions" / "defenseclaw",
        _REPO_ROOT / "extensions" / "defenseclaw",
    )


def scripts_dir() -> str:
    """Return the paths to the scripts/ directory in the repository."""
    candidate = _REPO_ROOT / "scripts"
    return str(candidate) if candidate.is_dir() else str(_REPO_ROOT)


def splunk_bridge_bin(data_dir: str) -> str | None:
    """Locate the splunk-claw-bridge executable.

    Checks the user's seeded copy (~/.defenseclaw/splunk-bridge/) first,
    then the bundled source.
    """
    candidates = [
        os.path.join(data_dir, "splunk-bridge", "bin", "splunk-claw-bridge"),
        str(bundled_splunk_bridge_dir() / "bin" / "splunk-claw-bridge"),
    ]
    for c in candidates:
        if os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    return None
