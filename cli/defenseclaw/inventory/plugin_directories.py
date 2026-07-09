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

"""Shared filtering and Codex-cache discovery for filesystem plugins."""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from typing import Any

import tomllib

from defenseclaw.inventory.plugin_identity import (
    AmbiguousPluginIdentityError,
    PluginIdentityError,
    canonical_plugin_id,
    filesystem_identity_key,
)
from defenseclaw.safety import is_symlink, is_within_roots

_CODEX_MANIFEST = ".codex-plugin/plugin.json"
_MAX_MANIFEST_BYTES = 1_048_576
_MAX_CONFIG_BYTES = 2_097_152


@dataclass(frozen=True)
class PluginDirectory:
    """One logical plugin and the concrete directory that should be scanned."""

    id: str
    path: str
    enabled: bool = True
    name: str = ""
    version: str = ""
    description: str = ""
    origin: str = ""
    manifest: str = ""
    registry: str = ""
    cached: bool = False


def _child_directories(root: str) -> list[tuple[str, str]]:
    """Return regular, non-symlink child directories in stable order."""
    try:
        entries = sorted(os.scandir(root), key=lambda entry: entry.name.casefold())
    except OSError:
        return []
    children: list[tuple[str, str]] = []
    for entry in entries:
        try:
            if entry.is_symlink() or not entry.is_dir(follow_symlinks=False):
                continue
        except OSError:
            continue
        children.append((entry.name, entry.path))
    return children


def _read_bounded_json(path: str) -> dict[str, Any] | None:
    if is_symlink(path) or not os.path.isfile(path):
        return None
    try:
        with open(path, encoding="utf-8") as handle:
            raw = handle.read(_MAX_MANIFEST_BYTES + 1)
    except OSError:
        return None
    if len(raw) > _MAX_MANIFEST_BYTES:
        return None
    try:
        payload = json.loads(raw)
    except (TypeError, ValueError):
        return None
    return payload if isinstance(payload, dict) else None


def _codex_config_path(cache_root: str) -> str:
    # <CODEX_HOME>/plugins/cache -> <CODEX_HOME>/config.toml
    return os.path.join(os.path.dirname(os.path.dirname(cache_root)), "config.toml")


def _codex_active_plugins(cache_root: str) -> dict[str, bool]:
    """Read only Codex's ``plugins`` activation table from config.toml."""
    path = _codex_config_path(cache_root)
    if is_symlink(path) or not os.path.isfile(path):
        return {}
    try:
        with open(path, "rb") as handle:
            raw = handle.read(_MAX_CONFIG_BYTES + 1)
    except OSError:
        return {}
    if len(raw) > _MAX_CONFIG_BYTES:
        return {}
    try:
        payload = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError):
        return {}
    plugins = payload.get("plugins", {})
    if not isinstance(plugins, dict):
        return {}
    active: dict[str, bool] = {}
    for key, value in plugins.items():
        if not isinstance(key, str) or not isinstance(value, dict):
            continue
        active[key.casefold()] = value.get("enabled") is True
    return active


def _natural_version_key(value: str) -> tuple[tuple[int, int | str], ...]:
    """Return a deterministic numeric-aware key for cached version folders."""
    parts: list[tuple[int, int | str]] = []
    for part in re.split(r"(\d+)", value or ""):
        if not part:
            continue
        parts.append((1, int(part)) if part.isdigit() else (0, part.casefold()))
    return tuple(parts)


def _is_codex_cache_root(root: str, connector: str) -> bool:
    if os.path.basename(os.path.normpath(root)).casefold() != "cache":
        return False
    normalized = (connector or "").casefold().replace("-", "")
    if normalized == "codex":
        return True
    parent = os.path.dirname(os.path.normpath(root))
    return (
        os.path.basename(parent).casefold() == "plugins"
        and os.path.basename(os.path.dirname(parent)).casefold() == ".codex"
    )


def _discover_codex_cache(cache_root: str) -> list[PluginDirectory]:
    """Discover exact ``registry/name/version`` Codex manifest roots."""
    active = _codex_active_plugins(cache_root)
    candidates: list[PluginDirectory] = []
    for registry, registry_path in _child_directories(cache_root):
        if registry.startswith("."):
            continue
        for logical_name, logical_path in _child_directories(registry_path):
            if logical_name.startswith("."):
                continue
            for folder_version, plugin_path in _child_directories(logical_path):
                if folder_version.startswith(".") or not is_within_roots(plugin_path, cache_root):
                    continue
                manifest_path = os.path.join(plugin_path, ".codex-plugin", "plugin.json")
                if not is_within_roots(manifest_path, plugin_path):
                    continue
                manifest = _read_bounded_json(manifest_path)
                if manifest is None:
                    continue
                plugin_id = str(manifest.get("name") or logical_name).strip()
                if not plugin_id:
                    continue
                version = str(manifest.get("version") or folder_version).strip()
                activation_keys = (
                    f"{plugin_id}@{registry}".casefold(),
                    f"{logical_name}@{registry}".casefold(),
                )
                enabled = any(active.get(key) is True for key in activation_keys)
                candidates.append(
                    PluginDirectory(
                        id=plugin_id,
                        name=plugin_id,
                        path=plugin_path,
                        enabled=enabled,
                        version=version,
                        description=str(manifest.get("description") or ""),
                        origin=registry,
                        manifest=_CODEX_MANIFEST,
                        registry=registry,
                        cached=True,
                    )
                )

    # One logical plugin row. An explicitly active registry wins over stale
    # copies; otherwise keep the newest cached version deterministically.
    selected: dict[str, PluginDirectory] = {}
    for candidate in candidates:
        key = candidate.id.casefold()
        current = selected.get(key)
        candidate_rank = (
            int(candidate.enabled),
            _natural_version_key(candidate.version),
            candidate.registry.casefold(),
        )
        current_rank = (
            (
                int(current.enabled),
                _natural_version_key(current.version),
                current.registry.casefold(),
            )
            if current is not None
            else None
        )
        if current_rank is None or candidate_rank > current_rank:
            selected[key] = candidate
    return sorted(selected.values(), key=lambda entry: entry.id.casefold())


def discover_plugin_directories(
    root: str,
    *,
    connector: str = "",
) -> list[PluginDirectory]:
    """Return real plugin roots, never registry/cache container directories."""
    if not os.path.isdir(root) or is_symlink(root):
        return []
    if _is_codex_cache_root(root, connector):
        return _discover_codex_cache(root)

    plugins: list[PluginDirectory] = []
    claimed: dict[str, str] = {}
    for entry, path in _child_directories(root):
        if entry == "cache" or entry.startswith("."):
            continue
        try:
            plugin_id, manifest = canonical_plugin_id(path)
        except PluginIdentityError as exc:
            if not str(exc).startswith(("invalid plugin manifest", "could not read plugin manifest")):
                raise
            plugin_id, manifest = entry, ""
        key = filesystem_identity_key(plugin_id, root)
        if key in claimed:
            raise AmbiguousPluginIdentityError(
                f"ambiguous plugin identity {plugin_id!r}: {claimed[key]}, {path}; "
                "remove or rename duplicate directories"
            )
        claimed[key] = path
        plugins.append(
            PluginDirectory(
                id=plugin_id,
                name=plugin_id,
                path=path,
                origin=root,
                manifest=manifest,
            )
        )
    return plugins


def plugin_directory_entries(
    root: str,
    *,
    connector: str = "",
) -> list[tuple[str, str]]:
    """Backward-compatible ``(id, path)`` view of plugin discovery."""
    return [(entry.id, entry.path) for entry in discover_plugin_directories(root, connector=connector)]
