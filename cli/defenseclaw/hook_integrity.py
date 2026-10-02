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

"""Drift checks for the generated per-user hook runtime files.

Setup seals each generated hook file's digest into ``hook_contract_lock.json``
and writes a connector-scoped ``.hook-<connector>.token`` that the script
reads. An edited script (an early ``exit 0``) silently disables enforcement,
and a missing token blocks every call; doctor and status report both
(GAP-1141, GAP-1138). Windows runs the native launcher instead, so these
Unix checks are skipped there.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

_LOCK_LIMIT = 4 * 1024 * 1024


def setup_command(connector: str) -> str:
    """The per-user repair command for *connector*."""

    return f"defenseclaw setup {'claude-code' if connector == 'claudecode' else connector}"


def hook_runtime_problems(cfg: Any, connector: str) -> list[str]:
    """Return short descriptions of drifted hook files for *connector*."""

    if os.name == "nt":
        return []
    data_dir = str(getattr(cfg, "data_dir", "") or "")
    lock_path = Path(data_dir, "hook_contract_lock.json")
    try:
        if not data_dir or lock_path.stat().st_size > _LOCK_LIMIT:
            return []
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []  # the Hook contract row reports a missing or unreadable lock
    connectors = lock.get("connectors") if isinstance(lock, dict) else None
    entry = connectors.get(connector) if isinstance(connectors, dict) else None
    if not isinstance(entry, dict):
        return []
    locations = entry.get("locations")
    raw_paths = locations.get("hook_script_paths") if isinstance(locations, dict) else None
    scripts = [Path(str(p)) for p in raw_paths if str(p or "").strip()] if isinstance(raw_paths, list) else []

    digests: dict[str, str] = {}
    # v2 locks keep the shared scripts' digests at the root; that copy wins.
    for source in (entry.get("hook_script_digests"), lock.get("shared_hook_script_digests")):
        if isinstance(source, dict):
            digests.update({str(name): str(value) for name, value in source.items()})

    from defenseclaw.fail_mode import _sha256_regular_file

    problems: list[str] = []
    for script in scripts:
        expected = digests.get(script.name)
        if expected and _sha256_regular_file(script) != expected:
            problems.append(
                f"hook script {script} changed since setup (an edit, or a copy from another build; "
                "it does not match hook_contract_lock.json)"
            )
            break

    token_name = f".hook-{connector}.token"
    for script in scripts:
        if script.suffix != ".sh":
            continue
        try:
            text = script.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if token_name not in text:
            continue
        token_path = script.parent / token_name
        # A connector-scoped script clears any inherited
        # DEFENSECLAW_GATEWAY_TOKEN and reads only this file, so the env var
        # (which doctor and status load from .env) never stands in for it.
        if not token_path.is_file():
            problems.append(f"hook token {token_path} is missing, so every hook call fails")
        break
    return problems


_CONFIG_LIMIT = 2 * 1024 * 1024


def _registration_text(text: str) -> str:
    """The part of an agent config file that can register DefenseClaw hooks.

    Setup also writes ``env`` entries that name DefenseClaw (the OTLP headers
    and resource attributes in ``~/.claude/settings.json``), so a whole-file
    match kept a settings file with no hooks looking registered (GAP-1230).
    For a JSON object only its ``hooks`` section counts; other formats are
    matched as a whole.
    """

    try:
        data = json.loads(text)
    except ValueError:
        return text.lower()
    if not isinstance(data, dict):
        return text.lower()
    if "hooks" in data:
        return json.dumps(data["hooks"]).lower()
    return json.dumps({key: value for key, value in data.items() if key != "env"}).lower()


def hook_registration_problems(cfg: Any, connector: str) -> list[str]:
    """Report hook config files that no longer mention DefenseClaw at all.

    Setup records the agent config files it registered hooks in
    (``locations.hook_config_paths``). When every one of them that exists has
    lost its DefenseClaw entries (for example the ``hooks`` key was deleted
    from ``~/.claude/settings.json``), the agent runs unguarded; status says
    so instead of showing the connector as normal (GAP-1230).
    """

    if os.name == "nt":
        return []
    data_dir = str(getattr(cfg, "data_dir", "") or "")
    lock_path = Path(data_dir, "hook_contract_lock.json")
    try:
        if not data_dir or lock_path.stat().st_size > _LOCK_LIMIT:
            return []
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    connectors = lock.get("connectors") if isinstance(lock, dict) else None
    entry = connectors.get(connector) if isinstance(connectors, dict) else None
    locations = entry.get("locations") if isinstance(entry, dict) else None
    raw_paths = locations.get("hook_config_paths") if isinstance(locations, dict) else None
    if not isinstance(raw_paths, list):
        return []
    existing: list[Path] = []
    for raw in raw_paths:
        path = Path(str(raw or ""))
        if not str(raw or "").strip():
            continue
        try:
            if not path.is_file() or path.stat().st_size > _CONFIG_LIMIT:
                continue
            if "defenseclaw" in _registration_text(path.read_text(encoding="utf-8", errors="replace")):
                return []
        except OSError:
            continue
        existing.append(path)
    if not existing:
        return []
    return [f"no DefenseClaw hooks are registered in {existing[0]}"]
