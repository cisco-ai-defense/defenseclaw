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
    <site-packages>/defenseclaw/_data/local_observability_stack/

Editable install (dev):
    <repo>/policies/
    <repo>/skills/codeguard/
    <repo>/bundles/splunk_local_bridge/
    <repo>/bundles/local_observability_stack/
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


def bundled_local_observability_dir() -> Path:
    """Vendored local observability stack (OTel Collector + Prom + Loki + Tempo + Grafana).

    Ships the same compose-driven layout that historically lived under
    ``deploy/observability/``. The stack is seeded into the user's data
    directory by ``defenseclaw init`` so operators can customize
    dashboards / alert rules in place without editing the Python wheel.
    """
    return _first_existing(
        _DATA_DIR / "local_observability_stack",
        _REPO_ROOT / "bundles" / "local_observability_stack",
    )


def bundled_extensions_dir() -> Path:
    """Built OpenClaw plugin (package.json + dist/)."""
    dc_home = Path.home() / ".defenseclaw"
    return _first_existing(
        dc_home / "extensions" / "defenseclaw",
        _REPO_ROOT / "extensions" / "defenseclaw",
    )


def bundled_guardrail_profiles_dir() -> Path | None:
    """Guardrail rule-pack profile directory (default/strict/permissive)."""
    candidates = [
        _DATA_DIR / "policies" / "guardrail",
        _REPO_ROOT / "policies" / "guardrail",
    ]
    for c in candidates:
        if c.is_dir():
            return c
    return None


def bundled_openshell_policies_dir() -> Path | None:
    """OpenShell policy templates (default.rego, default-data.yaml, etc.)."""
    candidates = [
        _DATA_DIR / "policies" / "openshell",
        _REPO_ROOT / "policies" / "openshell",
    ]
    for c in candidates:
        if c.is_dir():
            return c
    return None


def bundled_install_openshell_script() -> Path | None:
    """Locate install-openshell-sandbox.sh (wheel _data/ or repo scripts/)."""
    candidates = [
        _DATA_DIR / "scripts" / "install-openshell-sandbox.sh",
        _REPO_ROOT / "scripts" / "install-openshell-sandbox.sh",
    ]
    for c in candidates:
        if c.is_file():
            return c
    return None


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


def local_observability_bridge_bin(data_dir: str) -> str | None:
    """Locate the openclaw-observability-bridge executable.

    Checks the user's seeded copy (~/.defenseclaw/observability-stack/)
    first, then the bundled source. The bridge is used by
    ``defenseclaw setup local-observability`` to drive a docker compose
    stack with Prometheus, Loki, Tempo, Grafana, and an OTel Collector
    on loopback.
    """
    candidates = [
        os.path.join(data_dir, "observability-stack", "bin", "openclaw-observability-bridge"),
        str(bundled_local_observability_dir() / "bin" / "openclaw-observability-bridge"),
    ]
    for c in candidates:
        if os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    return None
