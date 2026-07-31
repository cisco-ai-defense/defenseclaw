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

"""Shared connector-aware discovery for filesystem plugins."""

from __future__ import annotations

import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - exercised on Python 3.10
    import tomli as tomllib

from defenseclaw.file_permissions import (
    open_regular_file_no_follow,
    reject_reparse_path,
)
from defenseclaw.inventory.plugin_identity import (
    AmbiguousPluginIdentityError,
    PluginIdentityError,
    canonical_plugin_id,
    filesystem_identity_key,
    is_link_or_reparse,
    validate_plugin_id,
)
from defenseclaw.safety import is_symlink, is_within_roots

_CODEX_MANIFEST = ".codex-plugin/plugin.json"
_CLAUDE_MANIFEST = ".claude-plugin/plugin.json"
_MAX_MANIFEST_BYTES = 1_048_576
_MAX_CONFIG_BYTES = 2_097_152
_MAX_CLAUDE_CACHE_DEPTH = 4
_MAX_CODEX_DIRECTORY_SNAPSHOT_ATTEMPTS = 8
_CLAUDE_CACHE_SKIP_DIRS = frozenset(
    {"node_modules", ".git", ".hg", ".svn", "__pycache__"}
)


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
    activation_verified: bool = True
    logical_id: str = ""


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
    try:
        raw = _read_bounded_stable_file(path, max_bytes=_MAX_MANIFEST_BYTES)
        payload = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, TypeError, ValueError):
        return None
    return payload if isinstance(payload, dict) else None


def _read_bounded_stable_file(path: str, *, max_bytes: int) -> bytes:
    """Read one stable regular file without following a reparse path."""
    fd = open_regular_file_no_follow(path)
    try:
        before = os.fstat(fd)
        if before.st_size > max_bytes:
            raise OSError(f"file exceeds {max_bytes} byte inventory limit")
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining:
            chunk = os.read(fd, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if len(payload) > max_bytes:
            raise OSError(f"file exceeds {max_bytes} byte inventory limit")
        after = os.fstat(fd)
        before_identity = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        after_identity = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if before_identity != after_identity:
            raise OSError("file changed while it was being inventoried")
        reject_reparse_path(path)
        named = os.stat(path, follow_symlinks=False)
        if not os.path.samestat(before, named):
            raise OSError("file was replaced while it was being inventoried")
        return payload
    finally:
        os.close(fd)


def _stable_directory_info(path: str) -> os.stat_result:
    """Return one real directory's stable, named identity."""
    reject_reparse_path(path)
    before = os.stat(path, follow_symlinks=False)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    if (
        not stat.S_ISDIR(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or bool(getattr(before, "st_file_attributes", 0) & reparse_flag)
    ):
        raise OSError(f"directory is a symlink or reparse point: {path}")
    reject_reparse_path(path)
    after = os.stat(path, follow_symlinks=False)
    if _directory_identity(before) != _directory_identity(after):
        raise OSError(f"directory changed while it was being inventoried: {path}")
    return after


def _directory_identity(info: os.stat_result) -> tuple[int, int, int, int]:
    """Bind both directory object identity and observable content metadata."""
    return (
        info.st_dev,
        info.st_ino,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _directory_unchanged(path: str, expected: os.stat_result) -> bool:
    try:
        current = _stable_directory_info(path)
    except OSError:
        return False
    return _directory_identity(expected) == _directory_identity(current)


def _directory_entry_matches(
    enumerated: os.stat_result,
    named: os.stat_result,
) -> bool:
    """Compare an entry snapshot without requiring unavailable Windows IDs."""
    if not stat.S_ISDIR(enumerated.st_mode) or not stat.S_ISDIR(named.st_mode):
        return False
    if enumerated.st_dev or enumerated.st_ino:
        return (
            enumerated.st_dev,
            enumerated.st_ino,
            enumerated.st_mtime_ns,
            enumerated.st_ctime_ns,
        ) == (
            named.st_dev,
            named.st_ino,
            named.st_mtime_ns,
            named.st_ctime_ns,
        )
    # Windows DirEntry.stat() can expose 0/0 for dev/ino even though a named
    # os.stat() returns the real file ID. Its cached directory size and
    # timestamps can likewise differ from the named view. When the entry has
    # no usable identity, use it only for type/reparse filtering; the
    # twice-checked named snapshot still binds file ID, timestamps, type, and
    # no-reparse custody before and after traversal.
    return True


def _codex_child_directories(
    root: str,
) -> list[tuple[str, str, os.stat_result]]:
    """Return stable real child directories for Codex cache traversal."""
    for _attempt in range(_MAX_CODEX_DIRECTORY_SNAPSHOT_ATTEMPTS):
        try:
            before = _stable_directory_info(root)
            with os.scandir(root) as iterator:
                entries = sorted(iterator, key=lambda entry: entry.name.casefold())
            after = _stable_directory_info(root)
        except OSError:
            continue
        if _directory_identity(before) != _directory_identity(after):
            continue

        children: list[tuple[str, str, os.stat_result]] = []
        refresh_snapshot = False
        for entry in entries:
            try:
                entry_info = entry.stat(follow_symlinks=False)
                if (
                    entry.is_symlink()
                    or is_link_or_reparse(entry.path)
                    or not stat.S_ISDIR(entry_info.st_mode)
                ):
                    continue
                named = _stable_directory_info(entry.path)
                if not _directory_entry_matches(entry_info, named):
                    refresh_snapshot = True
                    break
            except OSError:
                continue
            children.append((entry.name, entry.path, named))
        if not refresh_snapshot:
            return children
    return []


def _codex_config_path(cache_root: str) -> str:
    # <CODEX_HOME>/plugins/cache -> <CODEX_HOME>/config.toml
    normalized = os.path.normpath(cache_root)
    return os.path.join(os.path.dirname(os.path.dirname(normalized)), "config.toml")


def _codex_active_plugins(cache_root: str) -> dict[str, bool]:
    """Read only Codex's ``plugins`` activation table from config.toml."""
    path = _codex_config_path(cache_root)
    try:
        raw = _read_bounded_stable_file(path, max_bytes=_MAX_CONFIG_BYTES)
    except OSError:
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
    plugins_root = os.path.dirname(os.path.normpath(cache_root))
    codex_home = os.path.dirname(plugins_root)
    try:
        # POSIX permits symlinked system ancestors, so reject_reparse_path()
        # only checks the leaf and its immediate parent there. Validate the
        # complete declared Codex cache chain explicitly without climbing
        # above the client-owned home.
        _stable_directory_info(codex_home)
        _stable_directory_info(plugins_root)
        cache_identity = _stable_directory_info(cache_root)
    except OSError:
        return []
    active = _codex_active_plugins(cache_root)
    candidates: list[PluginDirectory] = []
    for registry, registry_path, registry_identity in _codex_child_directories(
        cache_root
    ):
        if registry.startswith("."):
            continue
        for logical_name, logical_path, logical_identity in _codex_child_directories(
            registry_path
        ):
            if logical_name.startswith("."):
                continue
            for (
                folder_version,
                plugin_path,
                plugin_identity,
            ) in _codex_child_directories(logical_path):
                if folder_version.startswith(".") or not is_within_roots(
                    plugin_path,
                    cache_root,
                ):
                    continue
                manifest_path = os.path.join(
                    plugin_path,
                    ".codex-plugin",
                    "plugin.json",
                )
                if not is_within_roots(manifest_path, plugin_path):
                    continue
                manifest = _read_bounded_json(manifest_path)
                if manifest is None:
                    continue
                plugin_id = str(manifest.get("name") or logical_name).strip()
                if not plugin_id:
                    continue
                version = str(manifest.get("version") or folder_version).strip()
                try:
                    named_plugin = _stable_directory_info(plugin_path)
                except OSError:
                    return []
                if _directory_identity(plugin_identity) != _directory_identity(
                    named_plugin
                ):
                    return []
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
            if not _directory_unchanged(logical_path, logical_identity):
                return []
        if not _directory_unchanged(registry_path, registry_identity):
            return []

    if not _directory_unchanged(cache_root, cache_identity):
        return []

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


def _is_claude_root(root: str, connector: str, leaf: str) -> bool:
    normalized = (connector or "").casefold().replace("-", "")
    return normalized in {"claude", "claudecode"} and (
        os.path.basename(os.path.normpath(root)).casefold() == leaf
    )


def _claude_config_dir() -> str:
    configured = (os.environ.get("CLAUDE_CONFIG_DIR") or "").strip()
    if configured:
        return os.path.abspath(os.path.expanduser(configured))
    return os.path.join(os.path.abspath(os.path.expanduser("~")), ".claude")


def _read_claude_enabled_plugins(
    workspace_dir: str = "",
    *,
    managed_settings_paths: tuple[str, ...] | None = None,
) -> tuple[dict[str, bool], bool]:
    """Resolve user → project → local → managed ``enabledPlugins`` layers."""

    settings_paths = [os.path.join(_claude_config_dir(), "settings.json")]
    workspace = (workspace_dir or "").strip()
    if workspace:
        workspace = os.path.abspath(os.path.expanduser(workspace))
        settings_paths.extend(
            [
                os.path.join(workspace, ".claude", "settings.json"),
                os.path.join(workspace, ".claude", "settings.local.json"),
            ]
        )

    resolved: dict[str, bool] = {}
    for path in settings_paths:
        payload = _read_bounded_json(path)
        if payload is None:
            continue
        enabled = payload.get("enabledPlugins")
        if not isinstance(enabled, dict):
            continue
        for plugin_id, value in enabled.items():
            if isinstance(plugin_id, str) and isinstance(value, bool):
                resolved[plugin_id.casefold()] = value
    # Import lazily so the small inventory module does not pull Doctor's
    # Windows inspection dependencies into non-Claude discovery.
    from defenseclaw.doctor_hooks import inspect_claude_managed_enabled_plugins

    managed, managed_verified = inspect_claude_managed_enabled_plugins(
        settings_paths[0],
        managed_settings_paths=managed_settings_paths,
    )
    if managed_verified:
        # Managed settings are the highest-precedence scope and cannot be
        # overridden by local/project/user plugin preferences.
        resolved.update(managed)
    return resolved, managed_verified


def _claude_enabled(
    configured: dict[str, bool],
    keys: tuple[str, ...],
    manifest: dict[str, Any],
) -> bool:
    for key in keys:
        if key.casefold() in configured:
            return configured[key.casefold()]
    default_enabled = manifest.get("defaultEnabled")
    return default_enabled if isinstance(default_enabled, bool) else True


def _discover_claude_cache(
    cache_root: str,
    *,
    workspace_dir: str = "",
    managed_settings_paths: tuple[str, ...] | None = None,
) -> list[PluginDirectory]:
    """Discover exact cached Claude marketplace plugin versions.

    Anthropic documents
    ``~/.claude/plugins/cache/<marketplace>/<plugin>/<version>`` and makes the
    plugin manifest optional. Walk only that exact depth, never follow links,
    and treat each physical version directory as a distinct custody boundary.
    """

    configured, managed_verified = _read_claude_enabled_plugins(
        workspace_dir,
        managed_settings_paths=managed_settings_paths,
    )
    candidates: list[PluginDirectory] = []
    cache_abs = os.path.abspath(cache_root)
    for current, dirs, _files in os.walk(cache_abs, topdown=True, followlinks=False):
        relative = os.path.relpath(current, cache_abs)
        depth = 0 if relative == "." else len(Path(relative).parts)
        dirs[:] = [
            name
            for name in sorted(dirs, key=str.casefold)
            if not name.startswith(".")
            and name.casefold() not in _CLAUDE_CACHE_SKIP_DIRS
            and not is_symlink(os.path.join(current, name))
        ]
        if depth >= _MAX_CLAUDE_CACHE_DEPTH:
            dirs[:] = []
        if not is_within_roots(current, cache_abs):
            continue

        parts = Path(relative).parts
        # The documented cache layout is
        # <marketplace>/<plugin>/<version>. A manifest at the plugin root is
        # optional, so directory shape -- not manifest presence -- establishes
        # a cache artifact boundary.
        if len(parts) != 3:
            continue
        manifest_path = os.path.join(current, _CLAUDE_MANIFEST)
        manifest_present = os.path.isfile(manifest_path) and not is_symlink(manifest_path)
        manifest = _read_bounded_json(manifest_path) or {}
        logical_name = str(manifest.get("name") or parts[1]).strip()
        if not logical_name:
            continue
        registry = parts[0]
        storage_name = parts[1]
        scoped_ids = tuple(
            value
            for value in (
                f"{storage_name}@{registry}" if registry else storage_name,
                f"{logical_name}@{registry}" if registry else logical_name,
            )
            if value
        )
        folder_version = parts[2]
        version = str(manifest.get("version") or folder_version).strip()
        candidates.append(
            PluginDirectory(
                id=scoped_ids[0],
                name=logical_name,
                path=current,
                # Cache presence alone does not prove the installed/active
                # version: Claude retains orphaned versions for 14 days.
                # Activation is resolved after grouping below.
                enabled=False,
                version=version,
                description=str(manifest.get("description") or ""),
                origin=registry or cache_root,
                manifest=_CLAUDE_MANIFEST if manifest_present else "",
                registry=registry,
                cached=True,
                activation_verified=False,
                logical_id=scoped_ids[0],
            )
        )
        # A plugin root is the attribution boundary. Do not discover manifests
        # planted inside its dependency tree.
        dirs[:] = []

    grouped: dict[str, list[PluginDirectory]] = {}
    for candidate in candidates:
        grouped.setdefault(candidate.id.casefold(), []).append(candidate)

    selected: list[PluginDirectory] = []
    for key, versions in grouped.items():
        versions.sort(
            key=lambda candidate: (
                _natural_version_key(candidate.version),
                candidate.path.casefold(),
            )
        )
        configured_state = configured.get(key)
        # An explicit enabledPlugins entry plus exactly one cached version is
        # sufficient filesystem evidence. With multiple retained versions,
        # only `claude plugin list --json` can identify the active one, so the
        # cache row remains conservatively disabled/unverified.
        activation_verified = (
            managed_verified
            and len(versions) == 1
            and configured_state is not None
        )
        for candidate in versions:
            physical_id = candidate.id
            if len(versions) > 1:
                physical_id = f"{candidate.id}#{Path(candidate.path).name}"
            selected.append(
                PluginDirectory(
                    **{
                        **candidate.__dict__,
                        "id": physical_id,
                        "enabled": (
                            bool(configured_state)
                            if activation_verified
                            else False
                        ),
                        "activation_verified": activation_verified,
                    }
                )
            )
    return sorted(selected, key=lambda entry: entry.id.casefold())


def _discover_claude_skills_plugins(
    skills_root: str,
    *,
    workspace_dir: str = "",
    managed_settings_paths: tuple[str, ...] | None = None,
) -> list[PluginDirectory]:
    """Return only manifest-bearing immediate children of a skills directory."""

    configured, managed_verified = _read_claude_enabled_plugins(
        workspace_dir,
        managed_settings_paths=managed_settings_paths,
    )
    plugins: list[PluginDirectory] = []
    claimed: dict[str, str] = {}
    for storage_name, plugin_path in _child_directories(skills_root):
        manifest_path = os.path.join(plugin_path, _CLAUDE_MANIFEST)
        manifest = _read_bounded_json(manifest_path)
        if manifest is None:
            continue
        logical_name = str(manifest.get("name") or storage_name).strip()
        if not logical_name:
            continue
        plugin_id = f"{logical_name}@skills-dir"
        identity = filesystem_identity_key(plugin_id, skills_root)
        if identity in claimed:
            raise AmbiguousPluginIdentityError(
                f"ambiguous plugin identity {plugin_id!r}: "
                f"{claimed[identity]}, {plugin_path}; remove or rename duplicate directories"
            )
        claimed[identity] = plugin_path
        plugins.append(
            PluginDirectory(
                id=plugin_id,
                name=logical_name,
                path=plugin_path,
                enabled=(
                    _claude_enabled(configured, (plugin_id,), manifest)
                    if managed_verified
                    else False
                ),
                version=str(manifest.get("version") or ""),
                description=str(manifest.get("description") or ""),
                origin="skills-dir",
                manifest=_CLAUDE_MANIFEST,
                registry="skills-dir",
                activation_verified=managed_verified,
                logical_id=plugin_id,
            )
        )
    return plugins


def discover_plugin_directories(
    root: str,
    *,
    connector: str = "",
    workspace_dir: str = "",
    claude_managed_settings_paths: tuple[str, ...] | None = None,
) -> list[PluginDirectory]:
    """Return real plugin roots, never registry/cache container directories."""
    if _is_codex_cache_root(root, connector):
        return _discover_codex_cache(root)
    if _is_claude_root(root, connector, "cache"):
        return _discover_claude_cache(
            root,
            workspace_dir=workspace_dir,
            managed_settings_paths=claude_managed_settings_paths,
        )
    if _is_claude_root(root, connector, "skills"):
        return _discover_claude_skills_plugins(
            root,
            workspace_dir=workspace_dir,
            managed_settings_paths=claude_managed_settings_paths,
        )
    if not os.path.isdir(root) or is_symlink(root):
        return []

    plugins: list[PluginDirectory] = []
    claimed: dict[str, str] = {}
    for entry, path in _child_directories(root):
        if entry == "cache" or entry.startswith("."):
            continue
        try:
            plugin_id, manifest = canonical_plugin_id(path)
        except PluginIdentityError as exc:
            if not str(exc).startswith(
                ("invalid plugin manifest", "could not read plugin manifest")
            ):
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


def discover_exact_plugin_directory(
    path: str,
    *,
    origin: str = "",
) -> list[PluginDirectory]:
    """Return one marketplace-declared plugin root, if it is a safe directory."""
    try:
        root_identity = _stable_directory_info(path)
    except OSError:
        return []

    manifest_path = os.path.join(path, _CODEX_MANIFEST)
    payload = _read_bounded_json(manifest_path)
    plugin_id = validate_plugin_id(
        (payload or {}).get("id")
        or (payload or {}).get("name")
        or os.path.basename(os.path.normpath(path))
    )
    manifest = _CODEX_MANIFEST if payload is not None else ""
    try:
        named_root = _stable_directory_info(path)
    except OSError:
        return []
    if _directory_identity(root_identity) != _directory_identity(named_root):
        return []
    return [
        PluginDirectory(
            id=plugin_id,
            name=plugin_id,
            path=path,
            origin=origin or os.path.dirname(path),
            manifest=manifest,
        )
    ]


def plugin_directory_entries(
    root: str,
    *,
    connector: str = "",
    workspace_dir: str = "",
) -> list[tuple[str, str]]:
    """Backward-compatible ``(id, path)`` view of plugin discovery."""
    return [
        (entry.id, entry.path)
        for entry in discover_plugin_directories(
            root,
            connector=connector,
            workspace_dir=workspace_dir,
        )
    ]
