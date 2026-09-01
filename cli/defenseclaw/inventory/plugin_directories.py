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

"""Shared filtering and connector-registry discovery for filesystem plugins."""

from __future__ import annotations

import json
import os
import re
import stat
from dataclasses import dataclass
from enum import Enum
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - exercised on Python 3.10
    import tomli as tomllib

from defenseclaw.inventory.plugin_identity import (
    AmbiguousPluginIdentityError,
    PluginIdentityError,
    canonical_plugin_id,
    filesystem_identity_key,
    is_link_or_reparse,
    read_plugin_manifest,
    validate_plugin_id,
)
from defenseclaw.safety import is_symlink, is_within_roots

_CODEX_MANIFEST = ".codex-plugin/plugin.json"
_CLAUDE_INSTALLED_PLUGINS = "installed_plugins.json"
_MAX_MANIFEST_BYTES = 1_048_576
_MAX_CONFIG_BYTES = 2_097_152
_MAX_AMP_PLUGIN_BYTES = 2_097_152


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
    scope: str = ""
    project_path: str = ""
    registry_source: str = ""


@dataclass(frozen=True)
class _PluginInstallClaim:
    """One physical claimant for a connector plugin identity."""

    path: str
    registry_instance: tuple[str, str] | None


class PluginInstallClaims:
    """Reject conflicting plugin paths without collapsing registry scopes.

    Ordinary filesystem plugins have one connector-wide identity and remain
    fail-closed when two directories claim it. Claude Code v2 registry rows
    are authoritative per ``(scope, projectPath)`` instance, so the same
    logical plugin may legitimately have a user install plus one or more
    project installs. Two different paths for the *same* registry instance
    are still ambiguous and fail closed.
    """

    def __init__(self) -> None:
        self._claims: dict[str, list[_PluginInstallClaim]] = {}

    @staticmethod
    def _registry_instance(
        registry_source: str,
        scope: str,
        project_path: str,
    ) -> tuple[str, str] | None:
        if not registry_source:
            return None
        normalized_project = (
            os.path.normcase(os.path.normpath(project_path.strip()))
            if project_path.strip()
            else ""
        )
        return scope.strip().casefold(), normalized_project

    @staticmethod
    def _same_path(first: str, second: str) -> bool:
        try:
            return os.path.samefile(first, second)
        except OSError:
            return os.path.normcase(os.path.realpath(first)) == os.path.normcase(
                os.path.realpath(second)
            )

    def add(
        self,
        plugin_id: str,
        path: str,
        root: str,
        *,
        registry_source: str = "",
        scope: str = "",
        project_path: str = "",
    ) -> bool:
        """Claim one install, returning false only for an exact duplicate."""

        logical_key = filesystem_identity_key(plugin_id, root)
        registry_instance = self._registry_instance(
            registry_source,
            scope,
            project_path,
        )
        previous_claims = self._claims.setdefault(logical_key, [])
        for previous in previous_claims:
            # Distinct authoritative scope/project instances are both valid.
            # Any ordinary claimant, or the same authoritative instance, must
            # resolve to one physical path.
            conflicts = (
                previous.registry_instance is None
                or registry_instance is None
                or previous.registry_instance == registry_instance
            )
            if not conflicts:
                continue
            if self._same_path(previous.path, path):
                return False
            instance_detail = ""
            if registry_instance is not None:
                instance_detail = (
                    f" for scope={scope.strip() or '<unspecified>'!r}"
                    f", projectPath={project_path.strip() or '<none>'!r}"
                )
            scoped_registry_conflict = (
                previous.registry_instance is not None and registry_instance is not None
            )
            identity_kind = "Claude plugin" if scoped_registry_conflict else "plugin"
            remediation = (
                "remove the conflicting installation record"
                if scoped_registry_conflict
                else "remove or rename duplicate directories"
            )
            raise AmbiguousPluginIdentityError(
                f"ambiguous {identity_kind} identity {plugin_id!r}{instance_detail}: "
                f"{previous.path}, {path}; {remediation}"
            )
        previous_claims.append(
            _PluginInstallClaim(
                path=path,
                registry_instance=registry_instance,
            )
        )
        return True

    def add_directory(self, entry: PluginDirectory, root: str) -> bool:
        """Claim a discovered directory using its registry provenance."""

        return self.add(
            entry.id,
            entry.path,
            root,
            registry_source=entry.registry_source,
            scope=entry.scope,
            project_path=entry.project_path,
        )


class PluginRegistryState(str, Enum):
    """Machine-stable outcome of probing one connector plugin registry."""

    MISSING = "missing"
    UNSAFE_OR_UNREADABLE = "unsafe/unreadable"
    MALFORMED = "malformed"
    UNSUPPORTED = "unsupported"
    VALID = "valid"


@dataclass(frozen=True)
class PluginRegistryProbe:
    """Diagnostic for one exact connector registry source."""

    source_path: str
    state: PluginRegistryState
    entries: int = 0
    detail: str = ""

    @property
    def failed(self) -> bool:
        """Return whether an existing registry could not be safely consumed."""

        return self.state in {
            PluginRegistryState.UNSAFE_OR_UNREADABLE,
            PluginRegistryState.MALFORMED,
            PluginRegistryState.UNSUPPORTED,
        }

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-ready representation with stable field names."""

        result: dict[str, Any] = {
            "source": self.source_path,
            "state": self.state.value,
            "entries": self.entries,
        }
        if self.detail:
            result["detail"] = self.detail
        return result


# A command-scoped cache keeps one immutable projection of Claude's
# authoritative registry per root. Callers deliberately own the dictionary so
# results never leak across commands after the registry changes on disk.
PluginRegistryCache = dict[
    str,
    tuple[tuple[PluginDirectory, ...], PluginRegistryProbe],
]


def _claude_registry_cache_key(plugin_root: str) -> str:
    return os.path.normcase(os.path.abspath(os.path.normpath(plugin_root)))


def _discover_claude_registry_cached(
    plugin_root: str,
    registry_cache: PluginRegistryCache | None,
) -> tuple[list[PluginDirectory], PluginRegistryProbe]:
    if registry_cache is None:
        return _discover_claude_registry(plugin_root)

    key = _claude_registry_cache_key(plugin_root)
    cached = registry_cache.get(key)
    if cached is None:
        plugins, probe = _discover_claude_registry(plugin_root)
        cached = (tuple(plugins), probe)
        registry_cache[key] = cached
    plugins, probe = cached
    # Discovery appends ordinary sibling directories to this list, so each
    # caller receives a fresh list while the cached registry rows stay fixed.
    return list(plugins), probe


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


def _amp_plugin_files(root: str, connector: str) -> list[tuple[str, str]]:
    """Return bounded direct ``*.ts`` Amp plugins without following links."""

    if (connector or "").casefold().replace("-", "") != "amp":
        return []
    try:
        entries = sorted(os.scandir(root), key=lambda entry: entry.name.casefold())
    except OSError:
        return []
    plugins: list[tuple[str, str]] = []
    for entry in entries:
        if entry.name.startswith(".") or not entry.name.casefold().endswith(".ts"):
            continue
        try:
            if entry.is_symlink() or not entry.is_file(follow_symlinks=False):
                continue
            if entry.stat(follow_symlinks=False).st_size > _MAX_AMP_PLUGIN_BYTES:
                continue
        except OSError:
            continue
        if not is_within_roots(entry.path, root):
            continue
        plugin_id = entry.name[:-3].strip()
        if plugin_id:
            plugins.append((plugin_id, entry.path))
    return plugins


def read_amp_plugin_source(path: str) -> str:
    """Read one Amp plugin as bounded UTF-8 without following symlinks."""

    if is_symlink(path):
        return ""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError:
        return ""
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or opened.st_size > _MAX_AMP_PLUGIN_BYTES:
            return ""
        with os.fdopen(fd, "rb", closefd=False) as handle:
            raw = handle.read(_MAX_AMP_PLUGIN_BYTES + 1)
        if len(raw) > _MAX_AMP_PLUGIN_BYTES:
            return ""
    except OSError:
        return ""
    finally:
        os.close(fd)
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return ""


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


def _is_claude_plugin_root(root: str, connector: str) -> bool:
    """Return whether *root* is a Claude Code plugin registry directory."""

    normalized = (connector or "").casefold().replace("-", "")
    return (
        normalized == "claudecode"
        and os.path.basename(os.path.normpath(root)).casefold() == "plugins"
    )


def _read_claude_registry(
    plugin_root: str,
) -> tuple[dict[str, Any] | None, PluginRegistryProbe]:
    """Read and classify Claude Code's registry without following links."""

    path = os.path.join(plugin_root, _CLAUDE_INSTALLED_PLUGINS)
    try:
        before = os.lstat(path)
    except FileNotFoundError:
        return None, PluginRegistryProbe(
            source_path=path,
            state=PluginRegistryState.MISSING,
            detail="registry source does not exist",
        )
    except OSError:
        return None, PluginRegistryProbe(
            source_path=path,
            state=PluginRegistryState.UNSAFE_OR_UNREADABLE,
            detail="registry source metadata could not be read safely",
        )
    if is_link_or_reparse(plugin_root) or is_link_or_reparse(path):
        return None, PluginRegistryProbe(
            source_path=path,
            state=PluginRegistryState.UNSAFE_OR_UNREADABLE,
            detail="registry source traverses a link or reparse point",
        )
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError:
        return None, PluginRegistryProbe(
            source_path=path,
            state=PluginRegistryState.UNSAFE_OR_UNREADABLE,
            detail="registry source could not be opened safely",
        )
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or not stat.S_ISREG(opened.st_mode):
            return None, PluginRegistryProbe(
                source_path=path,
                state=PluginRegistryState.UNSAFE_OR_UNREADABLE,
                detail="registry source is not a regular file",
            )
        if not os.path.samestat(before, opened) or opened.st_size > _MAX_CONFIG_BYTES:
            detail = (
                "registry source changed while opening"
                if not os.path.samestat(before, opened)
                else f"registry source exceeds {_MAX_CONFIG_BYTES} bytes"
            )
            return None, PluginRegistryProbe(
                source_path=path,
                state=PluginRegistryState.UNSAFE_OR_UNREADABLE,
                detail=detail,
            )
        chunks: list[bytes] = []
        remaining = _MAX_CONFIG_BYTES + 1
        while remaining > 0:
            chunk = os.read(fd, min(65_536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
    except OSError:
        return None, PluginRegistryProbe(
            source_path=path,
            state=PluginRegistryState.UNSAFE_OR_UNREADABLE,
            detail="registry source could not be read safely",
        )
    finally:
        os.close(fd)
    if len(raw) > _MAX_CONFIG_BYTES:
        return None, PluginRegistryProbe(
            source_path=path,
            state=PluginRegistryState.UNSAFE_OR_UNREADABLE,
            detail=f"registry source exceeds {_MAX_CONFIG_BYTES} bytes",
        )
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None, PluginRegistryProbe(
            source_path=path,
            state=PluginRegistryState.MALFORMED,
            detail="registry source is not valid UTF-8 JSON",
        )
    if not isinstance(payload, dict):
        return None, PluginRegistryProbe(
            source_path=path,
            state=PluginRegistryState.MALFORMED,
            detail="registry root must be a JSON object",
        )
    if payload.get("version") != 2:
        return None, PluginRegistryProbe(
            source_path=path,
            state=PluginRegistryState.UNSUPPORTED,
            detail=f"unsupported registry version {payload.get('version')!r}; expected 2",
        )
    if not isinstance(payload.get("plugins"), dict):
        return None, PluginRegistryProbe(
            source_path=path,
            state=PluginRegistryState.MALFORMED,
            detail="registry field 'plugins' must be a JSON object",
        )
    return payload, PluginRegistryProbe(
        source_path=path,
        state=PluginRegistryState.VALID,
    )


def _path_is_within(path: str, root: str) -> bool:
    """Cross-platform, drive-aware real-path containment."""

    candidate = os.path.normcase(os.path.realpath(path))
    boundary = os.path.normcase(os.path.realpath(root))
    try:
        return os.path.normcase(os.path.commonpath((candidate, boundary))) == boundary
    except ValueError:
        # Different Windows drives have no common path.
        return False


def _path_has_linked_component(path: str, root: str) -> bool:
    """Return whether *path* traverses a link/reparse point below *root*."""

    candidate = os.path.abspath(path)
    boundary = os.path.abspath(root)
    try:
        common = os.path.normcase(os.path.commonpath((candidate, boundary)))
        if common != os.path.normcase(boundary):
            return True
    except ValueError:
        return True
    current = candidate
    while True:
        if is_link_or_reparse(current):
            return True
        if os.path.normcase(current) == os.path.normcase(boundary):
            return False
        parent = os.path.dirname(current)
        if parent == current:
            return True
        current = parent


def _claude_registry_identity(
    registry_key: str,
    plugin_path: str,
) -> tuple[str, str, dict[str, Any]]:
    """Resolve a cached Claude plugin's identity with a registry-key fallback."""

    registry_name, separator, _marketplace = registry_key.rpartition("@")
    fallback = registry_name if separator and registry_name else registry_key
    try:
        safe_fallback = validate_plugin_id(fallback)
    except PluginIdentityError:
        safe_fallback = ""
    try:
        manifest = read_plugin_manifest(plugin_path)
    except PluginIdentityError:
        # The authoritative install record remains a scan target even when a
        # malformed manifest cannot supply trusted display metadata.
        if not safe_fallback:
            raise
        return safe_fallback, "", {}
    if manifest is None:
        if not safe_fallback:
            raise PluginIdentityError("Claude plugin registry identity is not portable")
        return safe_fallback, "", {}
    payload, relative = manifest
    declared = payload.get("id") or payload.get("name") or fallback
    try:
        plugin_id = validate_plugin_id(declared)
    except PluginIdentityError:
        if not safe_fallback:
            raise
        plugin_id = safe_fallback
    return plugin_id, relative, payload


def _discover_claude_registry(
    plugin_root: str,
) -> tuple[list[PluginDirectory], PluginRegistryProbe]:
    """Read Claude Code's v2 install registry and return exact cache roots.

    ``installed_plugins.json`` maps ``plugin@marketplace`` identifiers to a
    list of scope-specific installation records. Each record's ``installPath``
    points below ``plugins/cache``; the cache is nested too deeply for the
    ordinary one-level directory discovery contract.
    """

    payload, probe = _read_claude_registry(plugin_root)
    if payload is None:
        return [], probe
    registry_path = probe.source_path
    plugins = payload["plugins"]

    cache_root = os.path.join(plugin_root, "cache")
    candidates: list[PluginDirectory] = []
    claimed = PluginInstallClaims()
    for registry_key in sorted(plugins, key=lambda value: str(value).casefold()):
        installs = plugins.get(registry_key)
        if not isinstance(registry_key, str) or not isinstance(installs, list):
            continue
        for install in installs:
            if not isinstance(install, dict):
                continue
            raw_path = install.get("installPath")
            if (
                not isinstance(raw_path, str)
                or not raw_path.strip()
                or not os.path.isabs(raw_path)
            ):
                continue
            plugin_path = os.path.abspath(raw_path)
            same_as_cache = os.path.normcase(
                os.path.realpath(plugin_path)
            ) == os.path.normcase(os.path.realpath(cache_root))
            if (
                same_as_cache
                or not _path_is_within(plugin_path, cache_root)
                or _path_has_linked_component(plugin_path, cache_root)
                or not os.path.isdir(plugin_path)
            ):
                continue
            try:
                plugin_id, manifest, manifest_payload = _claude_registry_identity(
                    registry_key,
                    plugin_path,
                )
            except PluginIdentityError:
                continue
            _plugin_name, separator, marketplace = registry_key.rpartition("@")
            raw_scope = install.get("scope")
            scope = raw_scope.strip() if isinstance(raw_scope, str) else ""
            raw_project_path = install.get("projectPath")
            project_path = (
                raw_project_path.strip()
                if isinstance(raw_project_path, str)
                else ""
            )
            if not claimed.add(
                plugin_id,
                plugin_path,
                plugin_root,
                registry_source=registry_path,
                scope=scope,
                project_path=project_path,
            ):
                continue

            origin_parts = [scope, project_path]
            origin_parts.append(marketplace if separator else "")
            candidates.append(
                PluginDirectory(
                    id=plugin_id,
                    name=str(manifest_payload.get("displayName") or plugin_id),
                    path=plugin_path,
                    enabled=True,
                    version=str(
                        manifest_payload.get("version")
                        or install.get("version")
                        or ""
                    ),
                    description=str(manifest_payload.get("description") or ""),
                    origin=(
                        ":".join(part for part in origin_parts if part)
                        or registry_path
                    ),
                    manifest=manifest,
                    registry=marketplace if separator else "",
                    cached=True,
                    scope=scope,
                    project_path=project_path,
                    registry_source=registry_path,
                )
            )
    candidates = sorted(
        candidates,
        key=lambda entry: (
            entry.id.casefold(),
            entry.scope.casefold(),
            os.path.normcase(os.path.normpath(entry.project_path)),
            os.path.normcase(entry.path),
        ),
    )
    return candidates, PluginRegistryProbe(
        source_path=probe.source_path,
        state=probe.state,
        entries=len(candidates),
        detail=probe.detail,
    )


def probe_claude_plugin_registry(
    plugin_root: str,
    *,
    connector: str = "claudecode",
    registry_cache: PluginRegistryCache | None = None,
) -> PluginRegistryProbe | None:
    """Return the typed Claude registry diagnostic for a configured root.

    Non-Claude roots have no ``installed_plugins.json`` contract and return
    ``None`` rather than manufacturing a missing-source warning.
    """

    if not _is_claude_plugin_root(plugin_root, connector):
        return None
    try:
        _plugins, probe = _discover_claude_registry_cached(
            plugin_root,
            registry_cache,
        )
    except PluginIdentityError as exc:
        return PluginRegistryProbe(
            source_path=os.path.join(plugin_root, _CLAUDE_INSTALLED_PLUGINS),
            state=PluginRegistryState.MALFORMED,
            detail=str(exc),
        )
    return probe


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
    registry_cache: PluginRegistryCache | None = None,
) -> list[PluginDirectory]:
    """Return real plugin roots, never registry/cache container directories."""
    if not os.path.isdir(root) or is_link_or_reparse(root):
        return []
    if _is_codex_cache_root(root, connector):
        return _discover_codex_cache(root)

    claude_root = _is_claude_plugin_root(root, connector)
    plugins = (
        _discover_claude_registry_cached(root, registry_cache)[0]
        if claude_root
        else []
    )
    claimed = PluginInstallClaims()
    for plugin in plugins:
        claimed.add_directory(plugin, root)
    for entry, path in _child_directories(root):
        if entry == "cache" or entry.startswith(".") or (claude_root and entry == "marketplaces"):
            continue
        try:
            plugin_id, manifest = canonical_plugin_id(path)
        except PluginIdentityError as exc:
            if not str(exc).startswith(("invalid plugin manifest", "could not read plugin manifest")):
                raise
            plugin_id, manifest = entry, ""
        if not claimed.add(plugin_id, path, root):
            continue
        plugins.append(
            PluginDirectory(
                id=plugin_id,
                name=plugin_id,
                path=path,
                origin=root,
                manifest=manifest,
            )
        )
    for plugin_id, path in _amp_plugin_files(root, connector):
        if not claimed.add(plugin_id, path, root):
            continue
        plugins.append(
            PluginDirectory(
                id=plugin_id,
                name=plugin_id,
                path=path,
                origin=root,
                # Amp's source file is the plugin artifact; there is no
                # separate manifest requirement for direct TypeScript plugins.
                manifest=os.path.basename(path),
            )
        )
    return sorted(plugins, key=lambda entry: entry.id.casefold())


def plugin_directory_entries(
    root: str,
    *,
    connector: str = "",
    registry_cache: PluginRegistryCache | None = None,
) -> list[tuple[str, str]]:
    """Backward-compatible ``(id, path)`` view of plugin discovery."""
    return [
        (entry.id, entry.path)
        for entry in discover_plugin_directories(
            root,
            connector=connector,
            registry_cache=registry_cache,
        )
    ]
