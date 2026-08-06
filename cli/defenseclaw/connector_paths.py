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

"""Connector-specific path discovery for DefenseClaw.

This module is the single Python-side source of truth for "where does
agent framework X keep its skills / plugins / MCP server registrations?"
It mirrors:

* ``internal/config/claw.go::SkillDirsForConnector``
* ``internal/config/claw.go::PluginDirsForConnector``
* ``internal/config/claw.go::ReadMCPServersForConnector``
* ``internal/gateway/connector/<name>.go::ComponentTargets``

Importing this module instead of reaching into private helpers in
:mod:`defenseclaw.config` lets other CLI commands (``cmd_doctor``,
``cmd_uninstall``, ``cmd_setup_sandbox``) walk the connector matrix
without circular imports through ``Config``.

Public surface
--------------

* :data:`KNOWN_CONNECTORS` — tuple of every name the dispatchers
  recognize. Adding a connector is a one-line change here plus
  a matching dispatch arm in each ``*_for_connector`` function below
  and a Go-side ``connector.NewDefaultRegistry`` registration.
* :func:`normalize` — canonicalize an operator-supplied connector name
  (trim, lowercase, default to ``"openclaw"``). Mirrors
  ``Config.activeConnector`` semantics in claw.go.
* :func:`is_known` — connector-name allow-list check.
* :func:`skill_dirs` / :func:`plugin_dirs` / :func:`agent_dirs` /
  :func:`rule_dirs` / :func:`mcp_servers` / :func:`claude_agent_dirs` —
  polymorphic dispatchers; pass a connector name and they return the
  paths or MCP entries for that connector.
"""

from __future__ import annotations

import base64
import copy
import errno
import hashlib
import importlib.util
import json
import ntpath
import os
import re
import stat
import subprocess
import sys
import uuid
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field, replace
from itertools import islice
from pathlib import Path
from typing import Any

try:  # Python 3.11+ ships ``tomllib`` in the stdlib.
    import tomllib
except ModuleNotFoundError:  # Python 3.10 fallback to the ``tomli`` backport.
    import tomli as tomllib

import yaml

from defenseclaw.file_permissions import (
    UnsafePathError,
    atomic_write_private_bytes,
    delete_file_durable,
    make_private_directory,
    open_regular_file_no_follow,
    reject_reparse_path,
)
from defenseclaw.safety import is_symlink

_MCP_CONFIG_MAX_BYTES = 2 * 1024 * 1024

# ---------------------------------------------------------------------------
# Public constants
# ---------------------------------------------------------------------------

KNOWN_CONNECTORS: tuple[str, ...] = (
    "openclaw",
    "codex",
    "claudecode",
    "zeptoclaw",
    "hermes",
    "cursor",
    "windsurf",
    "geminicli",
    "copilot",
    "openhands",
    "antigravity",
    "opencode",
    "amp",
    "omnigent",
)
"""Allow-list of recognized agent-framework connector names.

Anything outside this set is treated as "unknown — fall back to
OpenClaw". Keeping the list explicit (rather than discovering at
import time) means a typo in ``guardrail.connector`` surfaces in
:func:`is_known` and in setup-time validation, instead of silently
producing wrong paths.
"""

KNOWN_AGENT_KINDS: tuple[str, ...] = (
    *KNOWN_CONNECTORS,
    # Discovery-only agents. These have AI-signature entries in
    # ai_signatures.json (mirrored between Go and Python copies) but no
    # DefenseClaw enforcement path, so they do NOT appear in
    # KNOWN_CONNECTORS (which is the enforcement-connector allow-list).
    # They ARE first-class agents on the discovery/inventory side:
    # ``defenseclaw agent discover`` reports them, and the wire
    # payload's ``agent_kind`` gets populated for their signals via the
    # promotion table in internal/inventory/ai_catalog.go.
    #
    # Keep this list in sync with ``promotedAgentKinds`` in the Go
    # catalog — the connector slug values here (aider, continue, cline,
    # claudedesktop) must match the values in that map for dashboards
    # to join cleanly across the two sides.
    "aider",
    "continue",
    "cline",
    "claudedesktop",
)
"""All agent slugs the CLI's discovery / inventory paths know about.

Superset of :data:`KNOWN_CONNECTORS`: adds discovery-only agents that
have AI-signature entries but no DefenseClaw enforcement path.
Consumers that walk *installed* connectors keep using
:data:`KNOWN_CONNECTORS`; consumers that enumerate *known agents*
(inventory / agent_discovery) use this.
"""

HOOK_ONLY_CONNECTORS: frozenset[str] = frozenset(
    {
        "hermes",
        "cursor",
        "windsurf",
        "geminicli",
        "copilot",
        "openhands",
        "antigravity",
        "opencode",
        "amp",
        "omnigent",
    }
)
"""Connectors added through lifecycle hook surfaces.

Kept as a compatibility constant for older tests/importers. These connectors
now expose connector-specific MCP/skill/rule/plugin path discovery instead of
falling back to OpenClaw or returning hook-only empty paths.
"""


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class MCPServerEntry:
    """One MCP server registration as discovered from disk.

    The fields are a superset across every supported framework's
    on-disk schema (Claude Code's ``settings.json``, Codex's
    ``config.toml``, ZeptoClaw's ``config.json``, OpenClaw's
    ``openclaw.json``). Optional fields default to empty so callers
    can treat the struct uniformly.
    """

    name: str = ""
    command: str = ""
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    cwd: str = ""
    url: str = ""
    transport: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    auth_provider_type: str = ""
    oauth: dict[str, Any] = field(default_factory=dict)
    disabled: bool = False
    disabled_tools: list[str] = field(default_factory=list)
    source: str = ""
    source_scope: str = ""
    trust_required: bool = False


@dataclass(frozen=True)
class OpenCodeConfigLayer:
    """One locally representable OpenCode v1.18.10-v1.18.11 config layer."""

    source: str
    source_scope: str
    path: str = ""
    data: dict[str, Any] | None = None


@dataclass(frozen=True)
class OpenCodeUnverifiedConfigSource:
    """A higher/lower precedence source deliberately not read offline."""

    source: str
    source_scope: str
    reason: str


@dataclass(frozen=True)
class OpenCodeConfigResolution:
    """Precedence-ordered local layers plus explicitly unverified sources."""

    layers: tuple[OpenCodeConfigLayer, ...] = ()
    unverified: tuple[OpenCodeUnverifiedConfigSource, ...] = ()


@dataclass(frozen=True)
class ClaudeAutoMemoryResolution:
    """One offline resolution of Claude Code's project auto-memory path."""

    path: str = ""
    source: str = ""
    project_root: str = ""
    activation_verified: bool = False
    limitation: str = ""


@dataclass(frozen=True)
class CopilotSettingsResolution:
    """Effective local Copilot hook policy for one lifecycle binding."""

    disable_all_hooks: bool = False
    source: str = ""
    inspected: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()
    verified: bool = True
    # Enterprise/managed policy is intentionally owned by another connector
    # change and must never be inferred from local files.
    managed_policy_verified: bool = False


def infer_mcp_transport(
    transport: Any = "",
    *,
    url: Any = "",
    command: Any = "",
) -> str:
    """Return an MCP transport label without misclassifying URL entries.

    Older config files often omit ``transport``. A missing value on a remote
    URL-backed server must not display as ``stdio``; use ``http`` as the
    generic URL transport unless the config supplied a more specific value
    such as ``sse`` or ``streamable-http``.
    """
    explicit = str(transport or "").strip()
    if explicit:
        return explicit
    if str(url or "").strip():
        return "http"
    if str(command or "").strip():
        return "stdio"
    return "stdio"


# ---------------------------------------------------------------------------
# Connector-name normalization
# ---------------------------------------------------------------------------


def normalize(connector: str | None) -> str:
    """Return the canonical lowercase connector name.

    Empty / whitespace-only / None values default to ``"openclaw"`` for
    backward compatibility with pre-S1.x deployments. Matches the
    precedence rule in ``Config.activeConnector`` (Go).
    """
    if not connector:
        return "openclaw"
    name = connector.strip().lower()
    if name in {"open-hands", "open_hands"}:
        return "openhands"
    if name in {"claude-code", "claude_code"}:
        return "claudecode"
    if name in {"gemini-cli", "gemini_cli", "gemini"}:
        return "geminicli"
    return name or "openclaw"


def is_known(connector: str | None) -> bool:
    """Return True iff *connector* (after :func:`normalize`) is in
    :data:`KNOWN_CONNECTORS`."""
    return normalize(connector) in KNOWN_CONNECTORS


# ---------------------------------------------------------------------------
# Path expansion helper — kept private to avoid divergence from the
# Go-side ``expandPath`` (which only handles a leading ``~/`` prefix).
# ---------------------------------------------------------------------------


def _expand(path: str) -> str:
    if path.startswith("~/"):
        return str(Path.home() / path[2:])
    return path


def _dedup(paths: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for p in paths:
        if not p:
            continue
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out


def _workspace_dir(workspace_dir: str | None = None) -> str:
    raw = (workspace_dir or "").strip()
    if not raw:
        return ""
    raw = _expand(raw)
    return os.path.abspath(os.path.expanduser(raw))


def _workspace_path(workspace_dir: str | None, *parts: str) -> str:
    root = _workspace_dir(workspace_dir)
    if not root:
        return ""
    return os.path.join(root, *parts)


def _omnigent_config_home() -> str:
    config_home = (os.environ.get("OMNIGENT_CONFIG_HOME") or "").strip()
    if config_home:
        return os.path.abspath(_expand(config_home))
    return os.path.join(str(Path.home()), ".omnigent")


def _connector_env_home(variable: str, default_dir: str) -> str:
    """Resolve a connector-owned home using the variable its client honors."""

    configured = (os.environ.get(variable) or "").strip()
    if configured:
        return os.path.abspath(os.path.expanduser(_expand(configured)))
    return os.path.join(os.path.abspath(str(Path.home())), default_dir)


def claude_config_dir() -> str:
    """Return Claude Code's effective user configuration directory."""

    return _connector_env_home("CLAUDE_CONFIG_DIR", ".claude")


def claude_mcp_state_path() -> str:
    """Return Claude Code's user/local MCP state file.

    Claude Code keeps user-scoped MCP servers at ``~/.claude.json`` by
    default. When ``CLAUDE_CONFIG_DIR`` is set, Claude stores its state under
    that override instead of the default home locations.
    """

    configured = (os.environ.get("CLAUDE_CONFIG_DIR") or "").strip()
    if configured:
        return os.path.join(claude_config_dir(), ".claude.json")
    return os.path.join(os.path.abspath(str(Path.home())), ".claude.json")


def claude_settings_paths(workspace_dir: str | None = None) -> list[str]:
    """Return Claude Code settings files without mixing in MCP state.

    Structural callers keep user, project, then local order. Callers that need
    effective-precedence order can reverse the three entries to obtain
    local, project, then user.
    """

    return _dedup(
        [
            os.path.join(claude_config_dir(), "settings.json"),
            _workspace_path(workspace_dir, ".claude", "settings.json"),
            _workspace_path(workspace_dir, ".claude", "settings.local.json"),
        ]
    )


def claude_agent_dirs(workspace_dir: str | None = None) -> list[str]:
    """Return Claude agent roots in effective precedence order.

    Project roots are ordered from the launch directory through the nearest
    repository root, then the user root. Claude identifies definitions by
    frontmatter ``name`` and lets the closest project definition win.
    """

    return _dedup(
        [
            *_claudecode_project_agent_dirs(workspace_dir),
            os.path.join(claude_config_dir(), "agents"),
        ]
    )


def claude_auto_memory_resolution(
    workspace_dir: str | None,
    *,
    managed_settings_paths: list[str] | None = None,
) -> ClaudeAutoMemoryResolution:
    """Resolve Claude's documented auto-memory path without session guessing.

    File-based settings are read in user → project → local → managed override
    order so the last valid scalar wins. Session-only ``--settings``, remote
    managed settings, registry/MDM policies, and policy-helper output are not
    observable from a passive filesystem inventory, so the result is always
    labelled unverified and carries that limitation.
    """

    workspace = _workspace_dir(workspace_dir)
    if not workspace:
        return ClaudeAutoMemoryResolution(
            limitation=(
                "Claude auto-memory project identity is unresolved because no "
                "connector workspace/session CWD is available"
            ),
        )
    project_root, project_limitation = _claude_project_root(workspace)
    if not project_root:
        return ClaudeAutoMemoryResolution(limitation=project_limitation)

    sources = [
        os.path.join(claude_config_dir(), "settings.json"),
        os.path.join(project_root, ".claude", "settings.json"),
        os.path.join(project_root, ".claude", "settings.local.json"),
    ]
    managed = (
        list(managed_settings_paths)
        if managed_settings_paths is not None
        else _claude_file_managed_settings_paths()
    )
    sources.extend(managed)

    override = ""
    override_source = ""
    limitations = [project_limitation] if project_limitation else []
    for source in sources:
        document, error = _read_bounded_json_object_no_follow(source)
        if error:
            limitations.append(error)
            continue
        if document is None:
            continue
        if source in managed and document.get("policyHelper"):
            limitations.append(
                f"{source} configures policyHelper; dynamic managed settings "
                "cannot be resolved by passive inventory",
            )
        value = document.get("autoMemoryDirectory")
        if value is None:
            continue
        if not isinstance(value, str):
            limitations.append(
                f"{source} has non-string autoMemoryDirectory and cannot "
                "establish an effective memory path",
            )
            continue
        candidate = value.strip()
        if candidate.startswith("~/") or candidate.startswith("~\\"):
            candidate = os.path.join(str(Path.home()), candidate[2:])
        elif not os.path.isabs(candidate):
            limitations.append(
                f"{source} has non-absolute autoMemoryDirectory; Claude "
                "requires an absolute path or ~/ prefix",
            )
            continue
        override = os.path.abspath(candidate)
        override_source = source

    if override:
        path = override
        source = override_source
    else:
        project_key = _claude_project_storage_key(project_root)
        if not project_key:
            return ClaudeAutoMemoryResolution(
                project_root=project_root,
                limitation="Claude auto-memory project storage identity could not be derived",
            )
        path = os.path.join(
            claude_config_dir(),
            "projects",
            project_key,
            "memory",
        )
        source = "derived-project-default"

    limitations.append(
        "passive inventory cannot observe session --settings, remote managed "
        "settings, or native registry/MDM policy; confirm the active path with "
        "Claude Code /memory or /status",
    )
    return ClaudeAutoMemoryResolution(
        path=os.path.abspath(path),
        source=source,
        project_root=project_root,
        activation_verified=False,
        limitation="; ".join(item for item in limitations if item),
    )


def claude_auto_memory_files(
    workspace_dir: str | None,
    *,
    managed_settings_paths: list[str] | None = None,
) -> tuple[ClaudeAutoMemoryResolution, list[str]]:
    """Return bounded regular Markdown files under the resolved memory path."""

    resolution = claude_auto_memory_resolution(
        workspace_dir,
        managed_settings_paths=managed_settings_paths,
    )
    root = resolution.path
    if not root or not os.path.isdir(root) or is_symlink(root):
        return resolution, []
    files: list[str] = []
    visited = 0
    for current, dirs, names in os.walk(root, topdown=True, followlinks=False):
        dirs[:] = [
            name
            for name in sorted(dirs, key=str.casefold)
            if not is_symlink(os.path.join(current, name))
        ]
        visited += 1
        if visited > _CLAUDE_SKILL_DISCOVERY_DIR_LIMIT:
            dirs[:] = []
            break
        for name in sorted(names, key=str.casefold):
            path = os.path.join(current, name)
            if (
                name.lower().endswith(".md")
                and os.path.isfile(path)
                and not is_symlink(path)
            ):
                files.append(os.path.abspath(path))
    return resolution, _dedup(files)


def codex_home() -> str:
    """Return Codex's effective home directory."""

    return _connector_env_home("CODEX_HOME", ".codex")


def _read_bounded_stable_file(path: str, *, max_bytes: int) -> bytes:
    """Read one regular file without reparse traversal or replacement races."""
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


def _codex_project_root_markers() -> tuple[str, ...]:
    """Return the configured project-root markers, or Codex's default.

    ``project_root_markers = []`` intentionally makes the active directory the
    project root. A malformed or unreadable user config cannot safely alter
    discovery, so it falls back to the documented ``.git`` default.
    """
    path = os.path.join(codex_home(), "config.toml")
    try:
        payload = _read_bounded_stable_file(path, max_bytes=1024 * 1024)
        config = tomllib.loads(payload.decode("utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError):
        return (".git",)
    raw = config.get("project_root_markers")
    if not isinstance(raw, list):
        return (".git",)
    if not all(isinstance(marker, str) for marker in raw):
        return (".git",)
    return tuple(marker for marker in raw if marker)


def _codex_project_layer_dirs(workspace_dir: str | None) -> list[str]:
    """Return project config layers from the active directory toward its root.

    The result is highest-precedence first. When no configured root marker is
    found, Codex treats the active directory as the project root rather than
    scanning arbitrary filesystem ancestors.
    """
    active = _workspace_dir(workspace_dir)
    if not active:
        return []
    markers = _codex_project_root_markers()
    if not markers:
        return [active]

    current = active
    candidates: list[str] = []
    while True:
        candidates.append(current)
        if any(os.path.exists(os.path.join(current, marker)) for marker in markers):
            return candidates
        parent = os.path.dirname(current)
        if parent == current:
            return [active]
        current = parent


def _codex_project_config_paths(workspace_dir: str | None) -> list[str]:
    """Return project ``.codex/config.toml`` files, closest layer first."""
    return [
        os.path.join(layer, ".codex", "config.toml")
        for layer in _codex_project_layer_dirs(workspace_dir)
    ]


def _codex_project_root(workspace_dir: str | None) -> str:
    """Return the detected project root for an explicit active workspace."""
    layers = _codex_project_layer_dirs(workspace_dir)
    return layers[-1] if layers else ""


def _codex_marketplace_files(workspace_dir: str | None) -> list[tuple[str, str]]:
    """Return ``(marketplace.json, source-root)`` pairs in Codex precedence."""
    pairs: list[tuple[str, str]] = []
    project_root = _codex_project_root(workspace_dir)
    if project_root:
        pairs.extend(
            (
                (
                    os.path.join(project_root, ".agents", "plugins", "marketplace.json"),
                    project_root,
                ),
                (
                    os.path.join(project_root, ".claude-plugin", "marketplace.json"),
                    project_root,
                ),
            )
        )
    user_root = os.path.abspath(str(Path.home()))
    pairs.append(
        (
            os.path.join(user_root, ".agents", "plugins", "marketplace.json"),
            user_root,
        )
    )
    return pairs


def copilot_home() -> str:
    """Return the exact lifecycle-bound Copilot configuration directory."""

    configured = os.environ.get("COPILOT_HOME")
    if configured is not None:
        if (
            configured.strip() != configured
            or "\x00" in configured
            or "\r" in configured
            or "\n" in configured
            or not os.path.isabs(configured)
            or os.path.normpath(configured) != configured
        ):
            raise ValueError("COPILOT_HOME is not an absolute normalized path")
        return configured
    return os.path.join(os.path.abspath(str(Path.home())), ".copilot")


def copilot_settings_paths(workspace_dir: str | None = None) -> list[str]:
    """Return local settings layers from lowest to highest priority.

    ``config.json`` remains first solely for Copilot's documented legacy
    migration/merge behavior. It is internal application state and is not
    advertised by :func:`connector_config_files` as operator configuration.
    Native Copilot files win over compatible Claude files at the same scope.
    """

    paths = [
        os.path.join(copilot_home(), "config.json"),
        os.path.join(copilot_home(), "settings.json"),
    ]
    ancestors = _copilot_workspace_ancestors(_workspace_dir(workspace_dir))
    if ancestors:
        repository = ancestors[-1]
        paths.extend(
            [
                os.path.join(repository, ".claude", "settings.json"),
                os.path.join(repository, ".github", "copilot", "settings.json"),
                os.path.join(repository, ".claude", "settings.local.json"),
                os.path.join(repository, ".github", "copilot", "settings.local.json"),
            ]
        )
    return _dedup(paths)


def _load_bounded_json_or_jsonc(path: str) -> Any:
    payload = _read_bounded_stable_file(path, max_bytes=1024 * 1024)
    raw = payload.decode("utf-8-sig")
    try:
        return json.loads(_normalize_jsonc(raw))
    except json.JSONDecodeError as exc:
        raise ValueError("file is not valid JSON/JSONC") from exc


def _normalize_jsonc(raw: str) -> str:
    """Remove JSONC comments and trailing commas without touching strings."""

    uncommented: list[str] = []
    index = 0
    in_string = False
    escaped = False
    while index < len(raw):
        current = raw[index]
        if in_string:
            uncommented.append(current)
            if escaped:
                escaped = False
            elif current == "\\":
                escaped = True
            elif current == '"':
                in_string = False
            index += 1
            continue
        if current == '"':
            in_string = True
            uncommented.append(current)
            index += 1
            continue
        if current == "/" and index + 1 < len(raw) and raw[index + 1] == "/":
            index += 2
            while index < len(raw) and raw[index] not in "\r\n":
                index += 1
            continue
        if current == "/" and index + 1 < len(raw) and raw[index + 1] == "*":
            index += 2
            closed = False
            while index + 1 < len(raw):
                if raw[index] == "*" and raw[index + 1] == "/":
                    index += 2
                    closed = True
                    break
                if raw[index] in "\r\n":
                    uncommented.append(raw[index])
                index += 1
            if not closed:
                raise ValueError("file has an unterminated JSONC comment")
            continue
        uncommented.append(current)
        index += 1

    cleaned: list[str] = []
    in_string = False
    escaped = False
    for index, current in enumerate(uncommented):
        if in_string:
            cleaned.append(current)
            if escaped:
                escaped = False
            elif current == "\\":
                escaped = True
            elif current == '"':
                in_string = False
            continue
        if current == '"':
            in_string = True
            cleaned.append(current)
            continue
        if current == ",":
            lookahead = index + 1
            while lookahead < len(uncommented) and uncommented[lookahead].isspace():
                lookahead += 1
            if lookahead < len(uncommented) and uncommented[lookahead] in "}]":
                continue
        cleaned.append(current)
    return "".join(cleaned)


def copilot_settings_resolution(
    workspace_dir: str | None = None,
) -> CopilotSettingsResolution:
    """Resolve the documented local ``disableAllHooks`` settings cascade."""

    try:
        paths = copilot_settings_paths(workspace_dir)
    except ValueError as exc:
        return CopilotSettingsResolution(
            errors=(str(exc),),
            verified=False,
            managed_policy_verified=False,
        )
    disabled = False
    source = ""
    inspected: list[str] = []
    errors: list[str] = []
    for path in paths:
        try:
            document = _load_bounded_json_or_jsonc(path)
        except FileNotFoundError:
            continue
        except (OSError, UnicodeDecodeError, ValueError) as exc:
            errors.append(f"{path}: {exc}")
            continue
        inspected.append(path)
        if not isinstance(document, dict):
            errors.append(f"{path}: top-level settings value must be an object")
            continue
        if "disableAllHooks" not in document:
            continue
        value = document["disableAllHooks"]
        if type(value) is not bool:
            errors.append(f"{path}: disableAllHooks must be boolean")
            continue
        disabled = value
        source = path
    return CopilotSettingsResolution(
        disable_all_hooks=disabled,
        source=source,
        inspected=tuple(inspected),
        errors=tuple(errors),
        verified=not errors,
        managed_policy_verified=False,
    )


def windsurf_user_home() -> str:
    """Return DefenseClaw's exact Windsurf user-profile binding.

    Windsurf has no vendor configuration-home override. Native Setup records
    the Windows Profile Known Folder and the packaged launcher supplies that
    validated value through this DefenseClaw-only environment contract.
    Reject malformed bindings instead of falling back to an ambient profile.
    """

    configured = os.environ.get("WINDSURF_USER_HOME")
    if configured:
        if (
            configured.strip() != configured
            or "\x00" in configured
            or "\r" in configured
            or "\n" in configured
            or not os.path.isabs(configured)
            or os.path.normpath(configured) != configured
        ):
            raise ValueError("WINDSURF_USER_HOME is not an absolute normalized path")
        return configured
    if os.name == "nt" and os.environ.get("DEFENSECLAW_INSTALL_ROOT"):
        raise ValueError("packaged Windsurf profile binding is missing")
    return os.path.abspath(str(Path.home()))


def windsurf_config_home() -> str:
    """Return the bound user-level Windsurf configuration directory."""

    root = windsurf_user_home()
    candidate = os.path.normpath(os.path.join(root, ".codeium", "windsurf"))
    if os.path.commonpath((root, candidate)) != os.path.commonpath((root, root)):
        raise ValueError("Windsurf configuration path escapes its bound profile")
    return candidate


def windsurf_hook_config_path() -> str:
    """Return the exact bound user-level Cascade hooks file."""

    expected = os.path.join(windsurf_config_home(), "hooks.json")
    configured = os.environ.get("WINDSURF_HOOK_CONFIG_PATH")
    if configured:
        if (
            configured.strip() != configured
            or "\x00" in configured
            or "\r" in configured
            or "\n" in configured
            or not os.path.isabs(configured)
            or os.path.normpath(configured) != configured
            or os.path.normcase(configured) != os.path.normcase(expected)
        ):
            raise ValueError("WINDSURF_HOOK_CONFIG_PATH does not match the bound profile")
        return configured
    return expected


def amp_config_home() -> str:
    """Return Amp's documented system configuration directory."""

    return os.path.join(os.path.abspath(str(Path.home())), ".config", "amp")


def amp_policy_plugin_path() -> str:
    """Return the single global DefenseClaw policy-plugin path Amp loads."""

    return os.path.join(amp_config_home(), "plugins", "defenseclaw.ts")


def _resolve_amp_managed_settings_path(
    *,
    platform_name: str,
    platform_id: str,
    program_data: str,
) -> str:
    """Resolve Amp's platform-owned enterprise settings file."""

    if platform_name == "nt":
        root = (program_data or "").strip()
        if not root:
            return ""
        return ntpath.join(root, "ampcode", "managed-settings.json")
    if platform_id == "darwin":
        return "/Library/Application Support/ampcode/managed-settings.json"
    return "/etc/ampcode/managed-settings.json"


def amp_managed_settings_path() -> str:
    """Return Amp's current-platform enterprise managed-settings path."""

    return _resolve_amp_managed_settings_path(
        platform_name=os.name,
        platform_id=sys.platform,
        program_data=os.environ.get("ProgramData", "")
        or os.environ.get("PROGRAMDATA", ""),
    )


def amp_managed_agents_path() -> str:
    """Return Amp's current-platform system-wide ``AGENTS.md`` path."""

    settings_path = amp_managed_settings_path()
    if not settings_path:
        return ""
    path_module = ntpath if os.name == "nt" else os.path
    return path_module.join(path_module.dirname(settings_path), "AGENTS.md")


def _resolve_hermes_home(
    *,
    platform_name: str,
    user_home: str,
    local_app_data: str,
    override: str,
) -> str:
    """Resolve Hermes' effective home without mutating process state.

    Hermes gives ``HERMES_HOME`` highest precedence. Native Windows installs
    otherwise use ``%LOCALAPPDATA%\\hermes``; macOS, Linux, and WSL retain the
    historical ``~/.hermes`` default. Windows never falls back to the legacy
    profile home because it can contain an unrelated credential-bearing
    configuration.
    """
    configured = (override or "").strip()
    if configured:
        if platform_name == "nt" and (
            override != configured
            or "\x00" in configured
            or "\r" in configured
            or "\n" in configured
            or not ntpath.isabs(configured)
            or ntpath.normpath(configured) != configured
        ):
            raise ValueError("HERMES_HOME is not an absolute normalized Windows path")
        if platform_name == "nt":
            return ntpath.normpath(configured)
        return os.path.abspath(os.path.expanduser(configured))

    if platform_name == "nt":
        windows_root = (local_app_data or "").strip()
        if windows_root:
            if (
                local_app_data != windows_root
                or "\x00" in windows_root
                or "\r" in windows_root
                or "\n" in windows_root
                or not ntpath.isabs(windows_root)
                or ntpath.normpath(windows_root) != windows_root
            ):
                raise ValueError(
                    "current-user LocalAppData is not an absolute normalized path for Hermes"
                )
            return ntpath.join(windows_root, "hermes")
        raise ValueError("current-user LocalAppData is unavailable for Hermes")
    home = os.path.abspath(os.path.expanduser((user_home or "").strip()))
    return os.path.join(home, ".hermes")


def _windows_current_user_local_app_data() -> str:
    """Resolve LocalAppData for the current Windows token, not the environment."""

    if os.name != "nt":
        return ""
    import ctypes
    from ctypes import wintypes

    class GUID(ctypes.Structure):
        _fields_ = [
            ("Data1", wintypes.DWORD),
            ("Data2", wintypes.WORD),
            ("Data3", wintypes.WORD),
            ("Data4", ctypes.c_ubyte * 8),
        ]

    value = uuid.UUID("F1B32785-6FBA-4FCF-9D55-7B8E7F157091")
    guid = GUID.from_buffer_copy(value.bytes_le)
    path = ctypes.c_wchar_p()
    token = wintypes.HANDLE()
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    shell32 = ctypes.WinDLL("shell32", use_last_error=True)
    ole32 = ctypes.WinDLL("ole32", use_last_error=True)
    kernel32.GetCurrentProcess.argtypes = []
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    advapi32.OpenProcessToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    advapi32.OpenProcessToken.restype = wintypes.BOOL
    shell32.SHGetKnownFolderPath.argtypes = [
        ctypes.POINTER(GUID),
        wintypes.DWORD,
        wintypes.HANDLE,
        ctypes.POINTER(ctypes.c_wchar_p),
    ]
    shell32.SHGetKnownFolderPath.restype = ctypes.c_long
    ole32.CoTaskMemFree.argtypes = [ctypes.c_void_p]
    ole32.CoTaskMemFree.restype = None
    if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), 0x0008 | 0x0004, ctypes.byref(token)):
        return ""
    try:
        if shell32.SHGetKnownFolderPath(ctypes.byref(guid), 0, token, ctypes.byref(path)) != 0 or not path.value:
            return ""
        return os.path.abspath(path.value)
    finally:
        if path:
            ole32.CoTaskMemFree(ctypes.cast(path, ctypes.c_void_p))
        kernel32.CloseHandle(token)


def hermes_home() -> str:
    """Return the home directory used by the current Hermes installation."""
    return _resolve_hermes_home(
        platform_name=os.name,
        user_home=str(Path.home()),
        local_app_data=(
            _windows_current_user_local_app_data()
            if os.name == "nt"
            else os.environ.get("LOCALAPPDATA", "")
        ),
        override=os.environ.get("HERMES_HOME", ""),
    )


def hermes_config_path() -> str:
    """Return Hermes' effective user-level ``config.yaml`` path."""
    return os.path.join(hermes_home(), "config.yaml")


_HERMES_CONFIG_INSPECTION_LIMIT = 1 << 20
_HERMES_PROFILE_ENTRY_LIMIT = 256


def _bounded_scandir(path: str, limit: int) -> list[os.DirEntry[str]]:
    entries: list[os.DirEntry[str]] = []
    with os.scandir(path) as iterator:
        for entry in iterator:
            entries.append(entry)
            if len(entries) >= limit:
                break
    return entries


def _read_hermes_config_bounded(path: str | None = None) -> tuple[dict[str, Any], str]:
    """Read the selected Hermes config without following a final symlink."""

    target = path or hermes_config_path()
    try:
        info = os.lstat(target)
    except FileNotFoundError:
        return {}, ""
    except OSError as exc:
        return {}, f"cannot inspect {target}: {exc}"
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        return {}, f"{target} is not a regular non-symlink file"
    if info.st_size > _HERMES_CONFIG_INSPECTION_LIMIT:
        return {}, f"{target} exceeds the {_HERMES_CONFIG_INSPECTION_LIMIT}-byte inspection limit"
    try:
        descriptor = open_regular_file_no_follow(target)
        with os.fdopen(descriptor, encoding="utf-8") as handle:
            document = yaml.safe_load(handle) or {}
    except (OSError, yaml.YAMLError) as exc:
        return {}, f"cannot parse {target}: {exc}"
    if not isinstance(document, dict):
        return {}, f"{target} is not a YAML object"
    return document, ""


def _hermes_truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return isinstance(value, str) and value.strip().lower() in {"1", "true", "yes", "on"}


def hermes_profile_unsupported_reason(config_path: str | None = None) -> str:
    """Return why a selected Hermes home is outside the single-profile contract."""

    target = os.path.abspath(config_path or hermes_config_path())
    home = os.path.dirname(target)
    if os.path.basename(os.path.dirname(home)).casefold() == "profiles":
        return (
            "Hermes named profiles are unsupported by the single-HERMES_HOME "
            "connector; select the default profile and retry"
        )

    active_profile = os.path.join(home, "active_profile")
    try:
        info = os.lstat(active_profile)
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_size > 4096:
            return "Hermes active_profile cannot be safely inspected"
        descriptor = open_regular_file_no_follow(active_profile)
        with os.fdopen(descriptor, encoding="utf-8") as handle:
            profile = handle.read(4097).strip()
        if profile and profile.casefold() != "default":
            return (
                f"Hermes active named profile {profile!r} is unsupported by the "
                "single-HERMES_HOME connector"
            )
    except FileNotFoundError:
        pass
    except OSError as exc:
        return f"Hermes active_profile cannot be safely inspected: {exc}"

    profiles_dir = os.path.join(home, "profiles")
    try:
        entries = _bounded_scandir(profiles_dir, _HERMES_PROFILE_ENTRY_LIMIT + 1)
    except FileNotFoundError:
        entries = []
    except OSError as exc:
        return f"Hermes profiles directory cannot be safely inspected: {exc}"
    if len(entries) > _HERMES_PROFILE_ENTRY_LIMIT:
        return "Hermes profiles directory exceeds the bounded inspection limit"
    for entry in entries:
        try:
            if entry.is_dir(follow_symlinks=False):
                return (
                    f"Hermes named profile {entry.name!r} is unsupported by the "
                    "single-HERMES_HOME connector"
                )
        except OSError as exc:
            return f"Hermes profile entry cannot be safely inspected: {exc}"

    document, error = _read_hermes_config_bounded(target)
    if error:
        return f"Hermes profile topology is unverified: {error}"
    multiplex = document.get("multiplex_profiles")
    if multiplex is None and isinstance(document.get("gateway"), dict):
        multiplex = document["gateway"].get("multiplex_profiles")
    raw_override = os.environ.get("GATEWAY_MULTIPLEX_PROFILES")
    if raw_override is not None:
        token = raw_override.strip().lower()
        if token in {"1", "true", "yes", "on"}:
            multiplex = True
        elif token in {"0", "false", "no", "off"}:
            multiplex = False
    if _hermes_truthy(multiplex):
        return (
            "Hermes multiplex profiles are unsupported by the single-HERMES_HOME "
            "connector"
        )
    return ""


def omnigent_config_path() -> str:
    """Return OmniGent's effective user-level ``config.yaml`` path.

    OmniGent's hosted server entrypoints resolve an explicit
    ``OMNIGENT_CONFIG`` file before ``OMNIGENT_CONFIG_HOME/config.yaml`` and
    the ``~/.omnigent/config.yaml`` default. The CLI server still needs that
    selected path passed with ``--config``; Doctor verifies that separately
    from this setup-time resolver.
    """
    explicit = (os.environ.get("OMNIGENT_CONFIG") or "").strip()
    if explicit:
        return os.path.abspath(_expand(explicit))
    return os.path.join(_omnigent_config_home(), "config.yaml")


# ---------------------------------------------------------------------------
# Public dispatchers
# ---------------------------------------------------------------------------


def connector_home(
    connector: str | None,
    *,
    openclaw_home: str | None = None,
    workspace_dir: str | None = None,
) -> str:
    """Return the on-disk home directory for *connector*.

    Returned values are absolute, ``~/`` expanded paths so callers can
    show them in inventory views without further normalization. The
    OpenClaw branch defaults to ``~/.openclaw`` when *openclaw_home* is
    None / empty, matching :func:`_openclaw_skill_dirs`. For unknown
    connectors we return the empty string so the renderer falls back
    to whatever per-component path it already has — the worst-case is
    a missing label, never a wrong one.
    """
    name = normalize(connector)
    home = str(Path.home())
    if name == "claudecode":
        return claude_config_dir()
    if name == "codex":
        return codex_home()
    if name == "amp":
        return amp_config_home()
    if name == "zeptoclaw":
        return os.environ.get("ZEPTOCLAW_HOME") or os.path.join(home, ".zeptoclaw")
    if name == "geminicli":
        return os.path.join(home, ".gemini")
    if name == "copilot":
        return copilot_home()
    if name == "openhands":
        root = _workspace_dir(workspace_dir)
        if root:
            return os.path.join(root, ".openhands")
        return os.path.join(home, ".openhands")
    if name == "antigravity":
        # Google documents one global customization root at ~/.gemini/config
        # and publishes no config-home environment override. workspace_dir is
        # intentionally ignored because DefenseClaw does not patch the host's
        # separate <workspace>/.agents/hooks.json surface.
        return os.path.join(home, ".gemini", "config")
    if name == "cursor":
        return os.path.join(home, ".cursor")
    if name == "windsurf":
        return windsurf_config_home()
    if name == "hermes":
        return hermes_home()
    if name == "opencode":
        # opencode keeps its config under ~/.config/opencode/ (XDG-style).
        # Surfaced so inventory/doctor render a truthful home label rather
        # than an empty string or — worse — OpenClaw's path.
        return _opencode_config_dir() or os.path.join(home, ".config", "opencode")
    if name == "omnigent":
        return _omnigent_config_home()
    if name == "openclaw":
        if openclaw_home:
            return _expand(openclaw_home)
        return os.path.join(home, ".openclaw")
    return ""


def connector_config_files(
    connector: str | None,
    *,
    openclaw_config: str | None = None,
    openclaw_home: str | None = None,
    workspace_dir: str | None = None,
) -> list[str]:
    """Return the documented config file paths for *connector*.

    Lists the *expected* primary config files even when they don't
    exist on disk yet — callers (inventory, doctor) want to show the
    operator "this is where I'd look", not just "this exists right
    now". Order is most-canonical first; deduplicated. Returns an
    empty list for unknown connectors.
    """
    name = normalize(connector)
    home = str(Path.home())
    paths: list[str] = []
    if name == "claudecode":
        settings_paths = claude_settings_paths(workspace_dir)
        paths = [
            settings_paths[0],
            claude_mcp_state_path(),
            *settings_paths[1:],
            _workspace_path(workspace_dir, ".mcp.json"),
        ]
    elif name == "codex":
        paths = [
            os.path.join(codex_home(), "config.toml"),
            *_codex_project_config_paths(workspace_dir),
            *[
                marketplace_file
                for marketplace_file, _source_root in _codex_marketplace_files(workspace_dir)
            ],
        ]
    elif name == "amp":
        paths = [
            os.path.join(amp_config_home(), "settings.json"),
            os.path.join(amp_config_home(), "settings.jsonc"),
            _workspace_path(workspace_dir, ".amp", "settings.json"),
            _workspace_path(workspace_dir, ".amp", "settings.jsonc"),
            amp_managed_settings_path(),
            amp_policy_plugin_path(),
        ]
    elif name == "zeptoclaw":
        zepto_home = os.environ.get("ZEPTOCLAW_HOME") or os.path.join(home, ".zeptoclaw")
        paths = [
            os.path.join(zepto_home, "config.json"),
            _workspace_path(workspace_dir, ".mcp.json"),
        ]
    elif name == "geminicli":
        paths = [
            os.path.join(home, ".gemini", "settings.json"),
            _workspace_path(workspace_dir, ".gemini", "settings.json"),
        ]
    elif name == "copilot":
        copilot_root = copilot_home()
        paths = [
            *copilot_settings_paths(workspace_dir)[1:],
            os.path.join(copilot_root, "hooks", "defenseclaw.json"),
            _workspace_path(workspace_dir, ".github", "hooks", "defenseclaw.json"),
        ]
    elif name == "openhands":
        paths = [
            os.path.join(home, ".openhands", "hooks.json"),
            os.path.join(home, ".openhands", "mcp.json"),
            _workspace_path(workspace_dir, ".openhands", "hooks.json"),
        ]
    elif name == "antigravity":
        # Google's global Hooks and MCP contract is pinned to
        # ~/.gemini/config. Setup does not own workspace hooks.
        hooks_home = connector_home("antigravity")
        paths = [
            os.path.join(home, ".gemini", "config", "mcp_config.json"),
            _workspace_path(workspace_dir, ".agents", "mcp_config.json"),
            os.path.join(hooks_home, "hooks.json"),
        ]
    elif name == "opencode":
        # opencode auto-loads plugins from ~/.config/opencode/plugins/;
        # DefenseClaw installs a single bridge plugin there. There is no
        # command-hook config file to patch.
        paths = [
            os.path.join(connector_home("opencode"), "plugins", "defenseclaw.js"),
        ]
    elif name == "omnigent":
        paths = [omnigent_config_path()]
    elif name == "cursor":
        paths = [
            os.path.join(home, ".cursor", "mcp.json"),
            _workspace_path(workspace_dir, ".cursor", "mcp.json"),
        ]
    elif name == "windsurf":
        paths = list(_windsurf_mcp_paths())
    elif name == "hermes":
        # Hermes' real config file is YAML, not JSON. HERMES_HOME takes
        # precedence, native Windows defaults to %LOCALAPPDATA%\\hermes, and
        # macOS/Linux/WSL retain ~/.hermes. The optional workspace entry is a
        # read surface only; gateway hook setup writes the effective user file.
        paths = [
            hermes_config_path(),
            _workspace_path(workspace_dir, ".hermes", "config.yaml"),
        ]
    elif name == "openclaw":
        if openclaw_config:
            paths = [_expand(openclaw_config)]
        else:
            paths = [os.path.join(home, ".openclaw", "openclaw.json")]
    return _dedup(paths)


def rule_paths(
    connector: str | None,
    *,
    workspace_dir: str | None = None,
    target_path: str | None = None,
) -> list[str]:
    """Return connector-owned guidance and policy-bearing read surfaces.

    The initial public consumer is Amp inventory. These paths are strictly
    discovery-only: setup never writes user, workspace, or enterprise Amp
    guidance/checks. Unknown connectors return an empty list instead of
    borrowing another connector's policy files.
    """

    if normalize(connector) != "amp":
        return []
    home = os.path.abspath(str(Path.home()))
    workspace = _workspace_dir(workspace_dir)
    scoped_dirs = _amp_guidance_scope_dirs(workspace, target_path)
    guidance = [_amp_guidance_file_for_dir(path) for path in scoped_dirs]
    checks = [os.path.join(path, ".agents", "checks") for path in scoped_dirs]
    return _dedup(
        [
            *guidance,
            *checks,
            os.path.join(amp_config_home(), "checks"),
            os.path.join(home, ".config", "agents", "checks"),
            os.path.join(amp_config_home(), "AGENTS.md"),
            os.path.join(home, ".config", "AGENTS.md"),
            amp_managed_agents_path(),
        ]
    )


def _amp_guidance_file_for_dir(directory: str) -> str:
    """Select Amp's per-directory guidance filename with exact fallback."""

    candidates = ("AGENTS.md", "AGENT.md", "CLAUDE.md")
    for name in candidates:
        path = os.path.join(directory, name)
        if os.path.isfile(path):
            return path
    # Keep the documented primary as the expected discovery path even before
    # an operator creates it; connector path APIs intentionally report
    # expected locations as well as existing ones.
    return os.path.join(directory, "AGENTS.md")


def _amp_guidance_scope_dirs(workspace: str, target_path: str | None) -> list[str]:
    """Return deterministic parent and on-demand subtree guidance scopes.

    Parent traversal stops after ``$HOME`` when the workspace is below it.
    ``target_path`` models Amp reading a file: only directories on that
    subtree path are added, so inventory never scans unrelated repository
    subtrees or eagerly loads their guidance.
    """

    if not workspace:
        return []
    home = os.path.abspath(str(Path.home()))
    upward: list[str] = []
    current = workspace
    home_is_ancestor = False
    try:
        home_is_ancestor = os.path.commonpath((workspace, home)) == home
    except ValueError:
        pass
    while current:
        upward.append(current)
        if not home_is_ancestor:
            break
        if home_is_ancestor and os.path.normcase(current) == os.path.normcase(home):
            break
        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent

    # Present broad-to-specific, matching Amp's override intuition while
    # preserving exactly one guidance filename per directory.
    scopes = list(reversed(upward))
    raw_target = (target_path or "").strip()
    if not raw_target:
        return scopes
    expanded_target = os.path.expanduser(_expand(raw_target))
    target = (
        os.path.abspath(expanded_target)
        if os.path.isabs(expanded_target)
        else os.path.abspath(os.path.join(workspace, expanded_target))
    )
    target_dir = target if os.path.isdir(target) else os.path.dirname(target)
    try:
        if os.path.commonpath((workspace, target_dir)) != workspace:
            return scopes
    except ValueError:
        return scopes
    relative = os.path.relpath(target_dir, workspace)
    cursor = workspace
    for part in (() if relative == "." else Path(relative).parts):
        cursor = os.path.join(cursor, part)
        scopes.append(cursor)
    return _dedup(scopes)


_AMP_POLICY_SETTING_KEYS: tuple[str, ...] = (
    "amp.permissions",
    "amp.guardedFiles.allowlist",
    "amp.dangerouslyAllowAll",
    "amp.mcpPermissions",
)


def connector_policy_settings(
    connector: str | None,
    *,
    workspace_dir: str | None = None,
) -> dict[str, Any]:
    """Return effective connector-native policy settings for inventory.

    Amp enterprise settings are loaded last and therefore override workspace
    and user values. Returned values are deep-copied so read-only inventory
    callers cannot mutate parsed documents accidentally.
    """

    if normalize(connector) != "amp":
        return {}
    effective: dict[str, Any] = {}
    for document in _amp_settings_documents(workspace_dir):
        for key in _AMP_POLICY_SETTING_KEYS:
            value = _amp_setting_value(document, key)
            if value is not _MISSING:
                effective[key] = copy.deepcopy(value)
    return effective


def skill_dirs(
    connector: str | None,
    *,
    openclaw_home: str | None = None,
    openclaw_config: str | None = None,
    workspace_dir: str | None = None,
) -> list[str]:
    """Return the skill directory list for *connector*.

    Codex follows its current cross-client skill layout: ``.agents/skills``
    at every repository directory from the active workspace to the project
    root, then ``$HOME/.agents/skills`` and the Unix admin directory
    ``/etc/codex/skills``. For OpenClaw — and any unknown
    name — we walk ``openclaw.json`` to honor any ``skills.load.extraDirs``
    overrides, then add the home_dir/skills fallback.

    *openclaw_home* and *openclaw_config* are only consulted on the
    OpenClaw branch. Callers that pass ``None`` get the documented
    OpenClaw defaults (``~/.openclaw`` and
    ``~/.openclaw/openclaw.json``).
    """
    name = normalize(connector)
    if name == "claudecode":
        return _claudecode_skill_dirs(workspace_dir)
    if name == "codex":
        return _codex_skill_dirs(workspace_dir)
    if name == "amp":
        return _amp_skill_dirs(workspace_dir)
    if name == "zeptoclaw":
        return _zeptoclaw_skill_dirs(workspace_dir)
    if name == "hermes":
        return _hermes_skill_dirs()
    if name == "cursor":
        return _cursor_skill_dirs(workspace_dir)
    if name == "windsurf":
        return _windsurf_skill_dirs(workspace_dir)
    if name == "geminicli":
        return _gemini_skill_dirs(workspace_dir)
    if name == "copilot":
        return _copilot_skill_dirs(workspace_dir)
    if name == "openhands":
        return _openhands_skill_dirs(workspace_dir)
    if name == "antigravity":
        return _antigravity_skill_dirs(workspace_dir)
    if name == "opencode":
        return []
    if name == "omnigent":
        return []
    return _openclaw_skill_dirs(openclaw_home, openclaw_config)


def skill_write_dirs(
    connector: str | None,
    *,
    openclaw_home: str | None = None,
    openclaw_config: str | None = None,
    workspace_dir: str | None = None,
) -> list[str]:
    """Return connector-native install targets, not discovery precedence.

    Amp discovers several user, project, compatibility, configured, and
    plugin-bundled roots. Its default write scope is narrower: a pinned
    workspace uses ``.agents/skills`` and an unpinned install is explicitly
    user-global. Other connectors retain their historical first-discovery-root
    install behavior.
    """

    if normalize(connector) == "amp":
        workspace = _workspace_dir(workspace_dir)
        if workspace:
            return [os.path.join(workspace, ".agents", "skills")]
        return [os.path.join(str(Path.home()), ".config", "agents", "skills")]
    return skill_dirs(
        connector,
        openclaw_home=openclaw_home,
        openclaw_config=openclaw_config,
        workspace_dir=workspace_dir,
    )


def plugin_dirs(
    connector: str | None,
    *,
    openclaw_home: str | None = None,
    workspace_dir: str | None = None,
) -> list[str]:
    """Return the plugin (extension) directory list for *connector*.

    Uses each framework's documented plugin location:

    * Claude Code: ``~/.claude/plugins/cache`` plus manifest-bearing
                   user/project skills-directory plugins
    * Codex:       local paths declared by repo/user marketplace files plus
                   the installed ``$CODEX_HOME/plugins/cache`` hierarchy
    * ZeptoClaw:   ``~/.zeptoclaw/plugins`` (+ ``cache`` subdir)
    * OpenClaw:    ``<home_dir>/extensions``
    """
    name = normalize(connector)
    if name == "claudecode":
        return _claudecode_plugin_dirs(workspace_dir)
    if name == "codex":
        return _codex_plugin_dirs(workspace_dir)
    if name == "amp":
        return _amp_plugin_dirs(workspace_dir)
    if name == "zeptoclaw":
        return _zeptoclaw_plugin_dirs()
    if name == "hermes":
        return _hermes_plugin_dirs(workspace_dir)
    if name == "cursor":
        return []
    if name == "windsurf":
        return []
    if name == "geminicli":
        return _gemini_plugin_dirs(workspace_dir)
    if name == "copilot":
        return []
    if name == "openhands":
        return []
    if name == "antigravity":
        return _antigravity_plugin_dirs(workspace_dir)
    if name == "opencode":
        return []
    if name == "omnigent":
        return []
    return _openclaw_plugin_dirs(openclaw_home)


def plugin_inventory_dirs(
    connector: str | None,
    *,
    openclaw_home: str | None = None,
    workspace_dir: str | None = None,
) -> list[str]:
    """Return read-only plugin discovery roots for *connector*.

    Most connectors use the same roots for inventory and installation. Cursor
    is intentionally different: its documented local-plugin root is an
    applicable inventory surface, but DefenseClaw does not install, remove, or
    otherwise claim custody of Cursor plugins. Write paths must continue to use
    :func:`plugin_dirs`, which returns no Cursor target.
    """

    if normalize(connector) == "cursor":
        return [os.path.join(str(Path.home()), ".cursor", "plugins", "local")]
    return plugin_dirs(
        connector,
        openclaw_home=openclaw_home,
        workspace_dir=workspace_dir,
    )


def agent_dirs(
    connector: str | None,
    *,
    workspace_dir: str | None = None,
) -> list[str]:
    """Return documented custom-agent directories for *connector*.

    Codex custom agents are standalone TOML files. Candidate project layers
    have higher precedence than the user layer, and the nearest project layer
    wins when Codex trusts the project. This path inventory does not infer the
    client's private trust decision. Other connector agent layouts remain
    owned by their existing inventory adapters.
    """
    name = normalize(connector)
    if name == "codex":
        return _dedup(
            [
                *[
                    os.path.join(layer, ".codex", "agents")
                    for layer in _codex_project_layer_dirs(workspace_dir)
                ],
                os.path.join(codex_home(), "agents"),
            ]
        )
    if name == "cursor":
        home = str(Path.home())
        return _dedup(
            [
                _workspace_path(workspace_dir, ".cursor", "agents"),
                _workspace_path(workspace_dir, ".claude", "agents"),
                _workspace_path(workspace_dir, ".codex", "agents"),
                os.path.join(home, ".cursor", "agents"),
                os.path.join(home, ".claude", "agents"),
                os.path.join(home, ".codex", "agents"),
            ]
        )
    return []


def rule_dirs(
    connector: str | None,
    *,
    workspace_dir: str | None = None,
) -> list[str]:
    """Return documented command-rule directories for *connector*.

    Codex loads ``rules/*.rules`` beside every active config layer. Candidate
    project layers are returned closest-first for deterministic inventory and
    require project trust at runtime; unlike scalar configuration, rules
    combine and the most restrictive decision wins. The Unix system layer is
    omitted on native Windows.
    """
    name = normalize(connector)
    if name == "copilot":
        return copilot_instruction_paths(workspace_dir)
    if name == "cursor":
        return _dedup([_workspace_path(workspace_dir, ".cursor", "rules")])
    if name == "windsurf":
        paths = [os.path.join(windsurf_config_home(), "memories")]
        for layer in _windsurf_workspace_ancestors(workspace_dir):
            paths.extend(
                [
                    os.path.join(layer, ".devin", "rules"),
                    os.path.join(layer, ".windsurf", "rules"),
                ]
            )
        return _dedup(paths)
    if name != "codex":
        return []
    paths = [
        *[
            os.path.join(layer, ".codex", "rules")
            for layer in _codex_project_layer_dirs(workspace_dir)
        ],
        os.path.join(codex_home(), "rules"),
    ]
    if os.name != "nt":
        paths.append(os.path.join(os.sep, "etc", "codex", "rules"))
    return _dedup(paths)


def mcp_servers(
    connector: str | None,
    *,
    openclaw_config: str | None = None,
    workspace_dir: str | None = None,
    openclaw_bin_resolver: Any = None,
    openclaw_cmd_prefix: list[str] | None = None,
) -> list[MCPServerEntry]:
    """Return the MCP server registrations for *connector*.

    Reads each framework's canonical config:

    * Claude Code: local/user ``~/.claude.json`` plus explicit workspace
                   ``.mcp.json``, in local → project → user precedence
    * Codex:       project ``.codex/config.toml`` layers (closest first), then
                   user ``~/.codex/config.toml``
    * ZeptoClaw:   ``~/.zeptoclaw/config.json`` then explicit workspace ``.mcp.json``
    * Antigravity: ``~/.gemini/config/mcp_config.json`` then explicit workspace
                    ``.agents/mcp_config.json``
    * OpenClaw:    ``openclaw config get mcp.servers`` (preferred)
                    falling back to direct ``openclaw.json`` parse

    *openclaw_bin_resolver* and *openclaw_cmd_prefix* let callers
    inject test doubles or sandbox-mode prefixes (``sudo -u sandbox``);
    when omitted, lookups go through ``shutil.which`` and an empty
    prefix.
    """
    name = normalize(connector)
    if name == "claudecode":
        return _claudecode_mcp_servers(workspace_dir)
    if name == "codex":
        return _codex_mcp_servers(workspace_dir)
    if name == "amp":
        return _amp_mcp_servers(workspace_dir)
    if name == "zeptoclaw":
        return _zeptoclaw_mcp_servers(workspace_dir)
    if name == "hermes":
        return _hermes_mcp_servers()
    if name == "cursor":
        return _cursor_mcp_servers(workspace_dir)
    if name == "windsurf":
        return _windsurf_mcp_servers()
    if name == "geminicli":
        return _gemini_mcp_servers()
    if name == "copilot":
        return _copilot_mcp_servers(workspace_dir)
    if name == "openhands":
        return _openhands_mcp_servers()
    if name == "antigravity":
        return _antigravity_mcp_servers(workspace_dir)
    if name == "opencode":
        # opencode manages MCP servers in its own opencode.json (full
        # read/write parity with codex/claudecode — mcp.md M2/M5), under
        # a top-level ``mcp`` map rather than the ``mcpServers`` shape the
        # other connectors use. Read its config, never OpenClaw's.
        return _opencode_mcp_servers(workspace_dir)
    if name == "omnigent":
        return []
    return _openclaw_mcp_servers(
        openclaw_config,
        openclaw_bin_resolver=openclaw_bin_resolver,
        openclaw_cmd_prefix=openclaw_cmd_prefix,
    )


# ---------------------------------------------------------------------------
# Per-connector implementations
# ---------------------------------------------------------------------------


_CLAUDE_SKILL_DISCOVERY_DIR_LIMIT = 32768


def _claudecode_skill_dirs(workspace_dir: str | None = None) -> list[str]:
    # Claude resolves true skills before legacy commands. Personal skills have
    # higher precedence than project skills; command roots come only after all
    # skill roots so a same-name command never hides a skill.
    return _dedup(
        [
            os.path.join(claude_config_dir(), "skills"),
            *_claudecode_project_skill_dirs(workspace_dir),
            os.path.join(claude_config_dir(), "commands"),
            _workspace_path(workspace_dir, ".claude", "commands"),
        ]
    )


def _claudecode_project_skill_dirs(workspace_dir: str | None) -> list[str]:
    """Return Claude's launch-ancestor and lazy nested project skill roots."""

    raw = (workspace_dir or "").strip()
    if not raw:
        return []
    start = os.path.abspath(os.path.expanduser(raw))
    repository_root = _claudecode_repository_root(start)
    roots: list[str] = []
    current = start
    while True:
        roots.append(os.path.join(current, ".claude", "skills"))
        if (
            not repository_root
            or os.path.normcase(current) == os.path.normcase(repository_root)
        ):
            break
        parent = os.path.dirname(current)
        if os.path.normcase(parent) == os.path.normcase(current):
            break
        current = parent

    visited = 0
    if os.path.isdir(start) and not is_symlink(start):
        for current, dirs, _files in os.walk(
            start,
            topdown=True,
            followlinks=False,
        ):
            dirs[:] = [
                name
                for name in sorted(dirs, key=str.casefold)
                if name != ".git"
                and not is_symlink(os.path.join(current, name))
            ]
            visited += 1
            if visited > _CLAUDE_SKILL_DISCOVERY_DIR_LIMIT:
                dirs[:] = []
                break
            if (
                os.path.basename(current).casefold() == "skills"
                and os.path.basename(os.path.dirname(current)).casefold()
                == ".claude"
            ):
                roots.append(os.path.abspath(current))
    return _dedup(roots)


def _claudecode_project_agent_dirs(workspace_dir: str | None) -> list[str]:
    """Return closest-first project agent roots through the repository root."""

    raw = (workspace_dir or "").strip()
    if not raw:
        return []
    start = os.path.abspath(os.path.expanduser(raw))
    repository_root = _claudecode_repository_root(start)
    roots: list[str] = []
    current = start
    while True:
        roots.append(os.path.join(current, ".claude", "agents"))
        if (
            not repository_root
            or os.path.normcase(current) == os.path.normcase(repository_root)
        ):
            break
        parent = os.path.dirname(current)
        if os.path.normcase(parent) == os.path.normcase(current):
            break
        current = parent
    return _dedup(roots)


def _claudecode_repository_root(start: str) -> str:
    current = os.path.abspath(start)
    while True:
        marker = os.path.join(current, ".git")
        try:
            info = os.lstat(marker)
        except OSError:
            info = None
        if info is not None and (
            stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)
        ):
            return current
        parent = os.path.dirname(current)
        if os.path.normcase(parent) == os.path.normcase(current):
            return ""
        current = parent


def _claude_project_root(workspace: str) -> tuple[str, str]:
    """Resolve the shared main-checkout root without invoking Git."""

    root = _claudecode_repository_root(workspace)
    if not root:
        return workspace, (
            "workspace is outside a discoverable Git repository; Claude's "
            "documented outside-repository project-root identity is assumed "
            "to be the explicit connector workspace"
        )
    marker = os.path.join(root, ".git")
    try:
        marker_info = os.lstat(marker)
    except (OSError, ValueError, UnsafePathError) as exc:
        return root, f"cannot inspect Git project marker {marker}: {exc}"
    if stat.S_ISDIR(marker_info.st_mode):
        return root, ""
    if not stat.S_ISREG(marker_info.st_mode) or is_symlink(marker):
        return "", f"Git project marker {marker} is not a stable regular file"
    marker_text, error = _read_bounded_text_no_follow(marker, 8192)
    if error:
        return "", error
    prefix = "gitdir:"
    if not marker_text.lower().startswith(prefix):
        return "", f"Git project marker {marker} has an unsupported format"
    git_dir = marker_text[len(prefix) :].strip()
    if not os.path.isabs(git_dir):
        git_dir = os.path.abspath(os.path.join(root, git_dir))
    common_path = os.path.join(git_dir, "commondir")
    common_text, common_error = _read_bounded_text_no_follow(common_path, 8192)
    if common_error:
        return root, (
            f"linked-worktree project identity is unresolved: {common_error}"
        )
    common_dir = common_text.strip()
    if not common_dir:
        return root, (
            f"linked-worktree project identity is unresolved: {common_path} is empty"
        )
    if not os.path.isabs(common_dir):
        common_dir = os.path.abspath(os.path.join(git_dir, common_dir))
    if os.path.basename(common_dir).casefold() != ".git":
        return root, (
            "linked-worktree common Git directory does not identify a main "
            f"checkout root: {common_dir}"
        )
    return os.path.dirname(common_dir), ""


def _claude_project_storage_key(project_root: str) -> str:
    """Mirror Claude's on-disk project-key encoding for absolute paths."""

    return re.sub(r"[^A-Za-z0-9_-]", "-", os.path.abspath(project_root))


def _claude_file_managed_settings_paths() -> list[str]:
    if os.name == "nt":
        program_files = os.environ.get("ProgramFiles") or r"C:\Program Files"
        parent = os.path.join(program_files, "ClaudeCode")
    elif sys.platform == "darwin":
        parent = "/Library/Application Support/ClaudeCode"
    else:
        parent = "/etc/claude-code"
    paths = [os.path.join(parent, "managed-settings.json")]
    dropins = os.path.join(parent, "managed-settings.d")
    if os.path.isdir(dropins) and not is_symlink(dropins):
        try:
            names = sorted(os.listdir(dropins), key=str.casefold)
        except OSError:
            names = []
        for name in names[:256]:
            path = os.path.join(dropins, name)
            if (
                name.lower().endswith(".json")
                and not name.startswith(".")
                and os.path.isfile(path)
                and not is_symlink(path)
            ):
                paths.append(path)
    return paths


def _read_bounded_text_no_follow(path: str, limit: int) -> tuple[str, str]:
    try:
        descriptor = open_regular_file_no_follow(path)
        with os.fdopen(descriptor, "rb") as source:
            raw = source.read(limit + 1)
    except OSError as exc:
        return "", f"cannot read stable file {path}: {exc}"
    if len(raw) > limit:
        return "", f"stable file {path} exceeds the {limit}-byte inventory limit"
    try:
        return raw.decode("utf-8"), ""
    except UnicodeDecodeError as exc:
        return "", f"stable file {path} is not UTF-8: {exc}"


def _read_bounded_json_object_no_follow(
    path: str,
    limit: int = 1024 * 1024,
) -> tuple[dict[str, Any] | None, str]:
    if not os.path.exists(path):
        return None, ""
    text, error = _read_bounded_text_no_follow(path, limit)
    if error:
        return None, error
    try:
        document = json.loads(text)
    except json.JSONDecodeError as exc:
        return None, f"settings file {path} is invalid JSON: {exc}"
    if not isinstance(document, dict):
        return None, f"settings file {path} is not a JSON object"
    return document, ""


def _codex_skill_dirs(workspace_dir: str | None = None) -> list[str]:
    paths = [
        *[
            os.path.join(layer, ".agents", "skills")
            for layer in _codex_project_layer_dirs(workspace_dir)
        ],
        os.path.join(str(Path.home()), ".agents", "skills"),
    ]
    if os.name != "nt":
        paths.append(os.path.join(os.sep, "etc", "codex", "skills"))
    return _dedup(paths)


def _amp_settings_paths(workspace_dir: str | None = None) -> list[str]:
    """Return Amp settings candidates in user/workspace/managed layer order."""

    return _dedup(
        [
            os.path.join(amp_config_home(), "settings.json"),
            os.path.join(amp_config_home(), "settings.jsonc"),
            _workspace_path(workspace_dir, ".amp", "settings.json"),
            _workspace_path(workspace_dir, ".amp", "settings.jsonc"),
            amp_managed_settings_path(),
        ]
    )


def _amp_settings_documents(workspace_dir: str | None = None) -> list[dict[str, Any]]:
    """Load at most one settings document per Amp scope.

    Amp documents ``settings.json`` and ``settings.jsonc`` as alternative
    spellings. Prefer JSON when both exist rather than double-counting one
    scope, and preserve user-before-workspace order so callers can compute an
    effective workspace and administrator override deterministically.
    """

    candidates = (
        (
            os.path.join(amp_config_home(), "settings.json"),
            os.path.join(amp_config_home(), "settings.jsonc"),
        ),
        (
            _workspace_path(workspace_dir, ".amp", "settings.json"),
            _workspace_path(workspace_dir, ".amp", "settings.jsonc"),
        ),
        (amp_managed_settings_path(),),
    )
    documents: list[dict[str, Any]] = []
    for scope in candidates:
        selected = next(
            (path for path in scope if path and os.path.lexists(path)),
            None,
        )
        if not selected:
            continue
        document = _load_amp_settings_document(selected)
        if isinstance(document, dict):
            documents.append(document)
    return documents


_AMP_SETTINGS_MAX_BYTES = 2 * 1024 * 1024


def _load_amp_settings_document(path: str) -> Any:
    """Parse one bounded, stable, non-symlink Amp settings document."""

    try:
        before = os.lstat(path)
    except OSError:
        return None
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or before.st_size > _AMP_SETTINGS_MAX_BYTES
    ):
        return None

    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        opened_before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened_before.st_mode)
            or opened_before.st_size > _AMP_SETTINGS_MAX_BYTES
            or not os.path.samestat(before, opened_before)
        ):
            return None
        with os.fdopen(descriptor, "rb", closefd=True) as stream:
            descriptor = -1
            raw = stream.read(_AMP_SETTINGS_MAX_BYTES + 1)
            opened_after = os.fstat(stream.fileno())
    except (OSError, ValueError):
        return None
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass

    if (
        len(raw) > _AMP_SETTINGS_MAX_BYTES
        or not os.path.samestat(opened_before, opened_after)
        or (opened_before.st_size, opened_before.st_mtime_ns, opened_before.st_mode)
        != (opened_after.st_size, opened_after.st_mtime_ns, opened_after.st_mode)
    ):
        return None
    try:
        named_after = os.lstat(path)
    except OSError:
        return None
    if (
        stat.S_ISLNK(named_after.st_mode)
        or not stat.S_ISREG(named_after.st_mode)
        or not os.path.samestat(opened_after, named_after)
        or (before.st_size, before.st_mtime_ns, before.st_mode)
        != (named_after.st_size, named_after.st_mtime_ns, named_after.st_mode)
    ):
        return None
    try:
        return _parse_json_or_jsonc(raw.decode("utf-8"))
    except UnicodeDecodeError:
        return None


_MISSING = object()


def _amp_setting_value(document: dict[str, Any], dotted_key: str) -> Any:
    """Read one documented dotted Amp key with nested compatibility."""

    if dotted_key in document:
        return document[dotted_key]
    current: Any = document
    for part in dotted_key.split("."):
        if not isinstance(current, dict) or part not in current:
            return _MISSING
        current = current[part]
    return current


def _amp_skill_settings(workspace_dir: str | None = None) -> tuple[list[str], bool]:
    """Return configured extra skill paths and effective Claude compatibility."""

    configured: Any = _MISSING
    disable_setting: Any = _MISSING
    disable_claude = False
    for document in _amp_settings_documents(workspace_dir):
        candidate = _amp_setting_value(document, "amp.skills.path")
        if candidate is not _MISSING:
            configured = candidate
        candidate = _amp_setting_value(document, "amp.skills.disableClaudeCodeSkills")
        if candidate is not _MISSING:
            disable_setting = candidate

    if isinstance(configured, str):
        configured_paths = configured.split(os.pathsep)
    elif isinstance(configured, list):
        configured_paths = configured
    else:
        configured_paths = []
    extras: list[str] = []
    for raw in configured_paths:
        if not isinstance(raw, str) or not raw.strip():
            continue
        path = os.path.expanduser(_expand(raw.strip()))
        if not os.path.isabs(path):
            workspace = _workspace_dir(workspace_dir)
            if not workspace:
                # The daemon must never reinterpret an Amp-relative skill root
                # against its own process cwd. Relative roots are meaningful
                # only when an explicit connector workspace is pinned.
                continue
            path = os.path.join(workspace, path)
        extras.append(os.path.abspath(path))
    if isinstance(disable_setting, bool):
        disable_claude = disable_setting
    return _dedup(extras), disable_claude


def _amp_skill_dirs(workspace_dir: str | None = None) -> list[str]:
    """Return Amp's documented skill roots in its discovery precedence."""

    home = str(Path.home())
    custom, disable_claude = _amp_skill_settings(workspace_dir)
    paths = [
        os.path.join(home, ".config", "agents", "skills"),
        os.path.join(home, ".agents", "skills"),
        os.path.join(amp_config_home(), "skills"),
        _workspace_path(workspace_dir, ".agents", "skills"),
    ]
    if not disable_claude:
        paths.extend(
            [
                _workspace_path(workspace_dir, ".claude", "skills"),
                os.path.join(home, ".claude", "skills"),
            ]
        )
        paths.extend(_amp_claude_plugin_cache_skill_dirs(home))
    paths.extend(custom)
    paths.extend(_plugin_component_dirs(_amp_plugin_dirs(workspace_dir), "skills"))
    return _dedup(paths)


def _amp_claude_plugin_cache_skill_dirs(home: str) -> list[str]:
    """Expand bounded Claude plugin-cache entries into skill containers.

    Amp treats ``~/.claude/plugins/cache/`` as a Claude-compatible skill
    source unless ``amp.skills.disableClaudeCodeSkills`` is enabled.  Cache
    layouts include marketplace, plugin, and version components before the
    plugin's ``skills`` directory, so returning only the cache root would make
    DefenseClaw inventory misclassify those containers as skills.  Walk only
    four directory levels below the fixed user cache, never follow links, and
    cap the number of inspected entries.
    """

    root = os.path.join(home, ".claude", "plugins", "cache")
    if not os.path.isdir(root) or os.path.islink(root):
        return []

    max_depth = 4
    max_entries = 4096
    inspected = 0
    pending: list[tuple[str, int]] = [(root, 0)]
    skill_dirs: list[str] = []
    while pending and inspected < max_entries:
        directory, depth = pending.pop(0)
        entries = _bounded_amp_directory_entries(directory, max_entries - inspected)
        for entry in entries:
            inspected += 1
            try:
                if entry.is_symlink() or not entry.is_dir(follow_symlinks=False):
                    continue
            except OSError:
                continue
            child_depth = depth + 1
            if entry.name.casefold() == "skills":
                skill_dirs.append(entry.path)
                continue
            if child_depth < max_depth:
                pending.append((entry.path, child_depth))
    return _dedup(skill_dirs)


def _bounded_amp_directory_entries(directory: str, remaining: int) -> list[os.DirEntry[str]]:
    """Read and sort at most ``remaining`` entries from one Amp cache dir."""

    if remaining <= 0:
        return []
    try:
        with os.scandir(directory) as iterator:
            entries = list(islice(iterator, remaining))
    except OSError:
        return []
    entries.sort(key=lambda entry: entry.name.casefold())
    return entries


def _zeptoclaw_skill_dirs(workspace_dir: str | None = None) -> list[str]:
    zepto_home = os.environ.get("ZEPTOCLAW_HOME") or os.path.join(str(Path.home()), ".zeptoclaw")
    return _dedup(
        [
            os.path.join(zepto_home, "skills"),
            _workspace_path(workspace_dir, ".zeptoclaw", "skills"),
        ]
    )


def _hermes_skill_dirs() -> list[str]:
    home = hermes_home()
    paths = [os.path.join(home, "skills")]
    document, _error = _read_hermes_config_bounded()
    skills = document.get("skills") if isinstance(document, dict) else None
    raw_dirs = skills.get("external_dirs") if isinstance(skills, dict) else None
    if isinstance(raw_dirs, str):
        raw_dirs = [raw_dirs]
    if not isinstance(raw_dirs, list):
        return paths
    for raw in raw_dirs[:_HERMES_PROFILE_ENTRY_LIMIT]:
        if not isinstance(raw, str) or not raw.strip():
            continue
        expanded = os.path.expandvars(os.path.expanduser(raw.strip()))
        if not os.path.isabs(expanded):
            expanded = os.path.join(home, expanded)
        candidate = os.path.realpath(os.path.abspath(expanded))
        if os.path.isdir(candidate):
            paths.append(candidate)
    return _dedup(paths)


def _cursor_skill_dirs(workspace_dir: str | None = None) -> list[str]:
    home = str(Path.home())
    return _dedup(
        [
            *_cursor_project_skill_dirs(workspace_dir),
            os.path.join(home, ".cursor", "skills"),
            os.path.join(home, ".agents", "skills"),
            os.path.join(home, ".claude", "skills"),
            os.path.join(home, ".codex", "skills"),
        ]
    )


_CURSOR_DISCOVERY_DIR_LIMIT = 32768


def _cursor_project_skill_dirs(workspace_dir: str | None) -> list[str]:
    """Return documented Cursor project and lazy nested skill roots.

    Cursor recursively discovers SKILL.md within each root and additionally
    scopes nested .cursor/skills and .agents/skills roots to their subtree.
    Discovery is bounded and refuses symlink/reparse traversal.
    """

    workspace = _workspace_dir(workspace_dir)
    if not workspace:
        return []
    roots = [
        os.path.join(workspace, ".cursor", "skills"),
        os.path.join(workspace, ".agents", "skills"),
        os.path.join(workspace, ".claude", "skills"),
        os.path.join(workspace, ".codex", "skills"),
    ]
    if not _cursor_walkable_directory(workspace):
        return _dedup(roots)

    visited = 0
    for current, dirs, _files in os.walk(workspace, topdown=True, followlinks=False):
        safe_dirs: list[str] = []
        for name in sorted(dirs, key=str.casefold):
            if name == ".git":
                continue
            candidate = os.path.join(current, name)
            if _cursor_walkable_directory(candidate):
                safe_dirs.append(name)
        dirs[:] = safe_dirs
        visited += 1
        if visited > _CURSOR_DISCOVERY_DIR_LIMIT:
            dirs[:] = []
            break
        if (
            os.path.basename(current).casefold() == "skills"
            and os.path.basename(os.path.dirname(current)).casefold()
            in {".cursor", ".agents"}
        ):
            roots.append(os.path.abspath(current))
    return _dedup(roots)


def _cursor_walkable_directory(path: str) -> bool:
    try:
        reject_reparse_path(path)
        info = os.stat(path, follow_symlinks=False)
    except OSError:
        return False
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return (
        stat.S_ISDIR(info.st_mode)
        and not stat.S_ISLNK(info.st_mode)
        and not bool(getattr(info, "st_file_attributes", 0) & reparse_flag)
    )


def _windsurf_skill_dirs(workspace_dir: str | None = None) -> list[str]:
    home = windsurf_user_home()
    return _dedup(
        [
            os.path.join(home, ".codeium", "windsurf", "skills"),
            os.path.join(home, ".agents", "skills"),
            _workspace_path(workspace_dir, ".windsurf", "skills"),
            _workspace_path(workspace_dir, ".agents", "skills"),
        ]
    )


_WINDSURF_CUSTOMIZATION_DIR_LIMIT = 32768
_WINDSURF_CUSTOMIZATION_FILE_LIMIT = 65536


def _windsurf_workspace_ancestors(workspace_dir: str | None) -> list[str]:
    """Return the pinned workspace through its repository root, closest first."""

    start = _workspace_dir(workspace_dir)
    if not start:
        return []
    repository_root = _windsurf_repository_root(start)
    stop = repository_root or start
    layers: list[str] = []
    current = start
    while True:
        layers.append(current)
        if os.path.normcase(current) == os.path.normcase(stop):
            break
        parent = os.path.dirname(current)
        if os.path.normcase(parent) == os.path.normcase(current):
            break
        current = parent
    return _dedup(layers)


def _windsurf_repository_root(start: str) -> str:
    """Resolve a Git root without following linked/reparse marker ancestry."""

    current = os.path.abspath(start)
    while True:
        marker = os.path.join(current, ".git")
        try:
            reject_reparse_path(marker)
            info = os.stat(marker, follow_symlinks=False)
        except OSError:
            info = None
        if info is not None and (
            stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)
        ):
            return current
        parent = os.path.dirname(current)
        if os.path.normcase(parent) == os.path.normcase(current):
            return ""
        current = parent


def _windsurf_safe_directory(path: str) -> bool:
    try:
        reject_reparse_path(path)
        info = os.stat(path, follow_symlinks=False)
    except OSError:
        return False
    return stat.S_ISDIR(info.st_mode) and not is_symlink(path)


def _windsurf_safe_regular_file(path: str) -> bool:
    try:
        reject_reparse_path(path)
        info = os.stat(path, follow_symlinks=False)
    except OSError:
        return False
    return stat.S_ISREG(info.st_mode) and not is_symlink(path)


def _windsurf_walk_directories(root: str) -> list[str]:
    """Return a deterministic bounded workspace walk without following links."""

    if not root:
        return []
    root = os.path.abspath(root)
    if not _windsurf_safe_directory(root):
        return []
    pending = [root]
    walked: list[str] = []
    while pending and len(walked) < _WINDSURF_CUSTOMIZATION_DIR_LIMIT:
        current = pending.pop()
        if not _windsurf_safe_directory(current):
            continue
        walked.append(current)
        try:
            with os.scandir(current) as iterator:
                entries = sorted(iterator, key=lambda entry: entry.name.casefold())
        except OSError:
            continue
        children: list[str] = []
        for entry in entries:
            if entry.name.casefold() == ".git":
                continue
            candidate = entry.path
            try:
                info = entry.stat(follow_symlinks=False)
            except OSError:
                continue
            if (
                entry.is_symlink()
                or not stat.S_ISDIR(info.st_mode)
                or not _windsurf_safe_directory(candidate)
            ):
                continue
            try:
                if os.path.normcase(os.path.commonpath((root, candidate))) != os.path.normcase(root):
                    continue
            except ValueError:
                continue
            children.append(candidate)
        pending.extend(reversed(children))
    return walked


def windsurf_rule_files(workspace_dir: str | None = None) -> list[str]:
    """Discover non-enterprise Cascade rules with bounded no-follow semantics.

    This intentionally excludes system/ProgramData, managed dashboard, and MDM
    layers. It covers the documented user-global rule, preferred and legacy
    workspace rule directories, legacy ``.windsurfrules``, and case-insensitive
    ``AGENTS.md`` files in the workspace plus ancestors through the Git root.
    """

    files: list[str] = []

    def add(candidate: str) -> None:
        if len(files) >= _WINDSURF_CUSTOMIZATION_FILE_LIMIT:
            return
        absolute = os.path.abspath(candidate)
        if _windsurf_safe_regular_file(absolute):
            files.append(absolute)

    add(os.path.join(windsurf_config_home(), "memories", "global_rules.md"))
    ancestors = _windsurf_workspace_ancestors(workspace_dir)
    for layer in ancestors:
        if not _windsurf_safe_directory(layer):
            continue
        try:
            with os.scandir(layer) as iterator:
                entries = sorted(iterator, key=lambda entry: entry.name.casefold())
        except OSError:
            entries = []
        for entry in entries:
            folded = entry.name.casefold()
            if folded in {"agents.md", ".windsurfrules"}:
                add(entry.path)
        for rules_dir in (
            os.path.join(layer, ".devin", "rules"),
            os.path.join(layer, ".windsurf", "rules"),
        ):
            if not _windsurf_safe_directory(rules_dir):
                continue
            try:
                with os.scandir(rules_dir) as iterator:
                    rule_entries = sorted(iterator, key=lambda entry: entry.name.casefold())
            except OSError:
                continue
            for entry in rule_entries:
                if entry.name.casefold().endswith(".md"):
                    add(entry.path)

    workspace = _workspace_dir(workspace_dir)
    for current in _windsurf_walk_directories(workspace):
        try:
            with os.scandir(current) as iterator:
                entries = sorted(iterator, key=lambda entry: entry.name.casefold())
        except OSError:
            continue
        is_rule_dir = (
            os.path.basename(current).casefold() == "rules"
            and os.path.basename(os.path.dirname(current)).casefold()
            in {".devin", ".windsurf"}
        )
        for entry in entries:
            folded = entry.name.casefold()
            if folded == "agents.md" or (is_rule_dir and folded.endswith(".md")):
                add(entry.path)
    return _dedup(files)


def _opencode_config_dir() -> str:
    raw = os.environ.get("OPENCODE_CONFIG_DIR", "").strip()
    if raw:
        return os.path.abspath(os.path.expanduser(_expand(raw)))
    return ""


def _opencode_skill_dirs(workspace_dir: str | None = None) -> list[str]:
    home = str(Path.home())
    custom = _opencode_config_dir()
    return _dedup(
        [
            _workspace_path(workspace_dir, ".opencode", "skills"),
            _workspace_path(workspace_dir, ".claude", "skills"),
            _workspace_path(workspace_dir, ".agents", "skills"),
            os.path.join(home, ".config", "opencode", "skills"),
            os.path.join(home, ".claude", "skills"),
            os.path.join(home, ".agents", "skills"),
            os.path.join(custom, "skills") if custom else "",
        ]
    )


def _antigravity_skill_dirs(workspace_dir: str | None = None) -> list[str]:
    home = str(Path.home())
    plugin_skill_dirs = _plugin_component_dirs(
        _antigravity_plugin_dirs(workspace_dir),
        "skills",
    )
    return _dedup(
        [
            os.path.join(home, ".gemini", "config", "skills"),
            _workspace_path(workspace_dir, ".agents", "skills"),
            _workspace_path(workspace_dir, ".agent", "skills"),
            os.path.join(home, ".gemini", "antigravity-cli", "skills"),
            *plugin_skill_dirs,
        ]
    )


def _gemini_skill_dirs(workspace_dir: str | None = None) -> list[str]:
    return _dedup(
        [
            os.path.join(str(Path.home()), ".gemini", "skills"),
            _workspace_path(workspace_dir, ".gemini", "skills"),
            _workspace_path(workspace_dir, ".agents", "skills"),
        ]
    )


def _copilot_skill_dirs(workspace_dir: str | None = None) -> list[str]:
    workspace = _workspace_dir(workspace_dir)
    ancestors = _copilot_workspace_ancestors(workspace)
    project: list[str] = []
    if ancestors:
        # Current-project precedence is exact: GitHub, Agents, then Claude.
        project.extend(
            [
                os.path.join(ancestors[0], ".github", "skills"),
                os.path.join(ancestors[0], ".agents", "skills"),
                os.path.join(ancestors[0], ".claude", "skills"),
            ]
        )
        # The official inherited skill surface is parent .github/skills,
        # deepest first, through the Git root.
        project.extend(os.path.join(root, ".github", "skills") for root in ancestors[1:])
    commands = (
        [os.path.join(ancestors[0], ".claude", "commands")]
        if ancestors
        else []
    )
    return _dedup(
        [
            *project,
            os.path.join(copilot_home(), "skills"),
            os.path.join(str(Path.home()), ".agents", "skills"),
            *_copilot_custom_skill_dirs(workspace),
            # Alternative command skills lose every same-name collision to
            # the Agent Skill locations above.
            *commands,
        ]
    )


def copilot_agent_dirs(workspace_dir: str | None = None) -> list[str]:
    """Return every documented local Copilot custom-agent directory.

    Project agents are loaded at every ancestor from the pinned workspace to
    the Git root, deepest first, with ``.github`` taking precedence over
    ``.claude`` at each level. Plugin-contributed agents are deliberately not
    expanded from an undocumented on-disk cache; callers inventory the plugin
    itself through Copilot's official read-only command instead.
    """

    project: list[str] = []
    for root in _copilot_workspace_ancestors(_workspace_dir(workspace_dir)):
        project.extend(
            [
                os.path.join(root, ".github", "agents"),
                os.path.join(root, ".claude", "agents"),
            ]
        )
    return _dedup([*project, os.path.join(copilot_home(), "agents")])


def copilot_mcp_config_files(workspace_dir: str | None = None) -> list[str]:
    """Return documented local Copilot MCP files in effective priority order."""

    project: list[str] = []
    for root in _copilot_workspace_ancestors(_workspace_dir(workspace_dir)):
        project.extend(
            [
                os.path.join(root, ".mcp.json"),
                os.path.join(root, ".github", "mcp.json"),
            ]
        )
    return _dedup([*project, os.path.join(copilot_home(), "mcp-config.json")])


def copilot_instruction_paths(workspace_dir: str | None = None) -> list[str]:
    """Return documented local instruction files/roots for passive scanning."""

    paths = [
        os.path.join(copilot_home(), "copilot-instructions.md"),
        os.path.join(copilot_home(), "instructions"),
    ]
    workspace = _workspace_dir(workspace_dir)
    ancestors = _copilot_workspace_ancestors(workspace)
    for root in reversed(ancestors):
        paths.extend(
            [
                os.path.join(root, ".github", "copilot-instructions.md"),
                os.path.join(root, "AGENTS.md"),
                os.path.join(root, "CLAUDE.md"),
                os.path.join(root, ".claude", "CLAUDE.md"),
                os.path.join(root, "GEMINI.md"),
            ]
        )
    if ancestors:
        paths.extend(
            [
                os.path.join(ancestors[-1], ".github", "instructions"),
                os.path.join(ancestors[0], ".github", "instructions"),
                # Nested general instruction files can become applicable when
                # Copilot works on an active file below the pinned workspace.
                ancestors[-1],
            ]
        )
    for raw in os.environ.get("COPILOT_CUSTOM_INSTRUCTIONS_DIRS", "").split(","):
        candidate = os.path.expanduser(_expand(raw.strip()))
        if not candidate:
            continue
        if not os.path.isabs(candidate):
            if not workspace:
                continue
            candidate = os.path.join(workspace, candidate)
        candidate = os.path.abspath(candidate)
        paths.extend([os.path.join(candidate, "AGENTS.md"), candidate])
    return _dedup(paths)


def _copilot_workspace_ancestors(workspace_dir: str) -> list[str]:
    if not workspace_dir:
        return []
    current = os.path.abspath(workspace_dir)
    candidates: list[str] = []
    while True:
        candidates.append(current)
        if os.path.exists(os.path.join(current, ".git")):
            return candidates
        parent = os.path.dirname(current)
        if parent == current:
            # A pinned non-repository workspace has only its immediate
            # project surface; never scan unrelated filesystem ancestors.
            return candidates[:1]
        current = parent


def _copilot_custom_skill_dirs(workspace_dir: str) -> list[str]:
    out: list[str] = []
    for raw in os.environ.get("COPILOT_SKILLS_DIRS", "").split(","):
        candidate = os.path.expanduser(_expand(raw.strip()))
        if not candidate:
            continue
        if not os.path.isabs(candidate):
            if not workspace_dir:
                # Relative custom paths are meaningful only in Copilot's
                # launch workspace. Do not reinterpret them against the
                # long-lived DefenseClaw daemon directory.
                continue
            candidate = os.path.join(workspace_dir, candidate)
        out.append(os.path.abspath(candidate))
    return _dedup(out)


def _openhands_skill_dirs(workspace_dir: str | None = None) -> list[str]:
    home = str(Path.home())
    return _dedup(
        [
            _workspace_path(workspace_dir, ".agents", "skills"),
            _workspace_path(workspace_dir, ".openhands", "skills"),
            _workspace_path(workspace_dir, ".openhands", "microagents"),
            os.path.join(home, ".agents", "skills"),
            os.path.join(home, ".openhands", "skills"),
            os.path.join(home, ".openhands", "microagents"),
            os.path.join(home, ".openhands", "skills", "installed"),
            os.path.join(home, ".openhands", "cache", "skills", "public-skills", "skills"),
        ]
    )


def _openclaw_skill_dirs(
    openclaw_home: str | None,
    openclaw_config: str | None,
) -> list[str]:
    home = _expand(openclaw_home or "~/.openclaw")
    config_file = _expand(openclaw_config or "~/.openclaw/openclaw.json")
    workspace = os.path.join(home, "workspace")
    dirs: list[str] = []
    oc = _read_openclaw_json(config_file)
    if oc:
        ws = oc.get("agents", {}).get("defaults", {}).get("workspace", "")
        if ws:
            workspace = _expand(ws)
        dirs.append(os.path.join(workspace, "skills"))
        for d in oc.get("skills", {}).get("load", {}).get("extraDirs", []) or []:
            dirs.append(_expand(d))
    else:
        dirs.append(os.path.join(workspace, "skills"))
    dirs.append(os.path.join(home, "skills"))
    return _dedup(dirs)


def _claudecode_plugin_dirs(workspace_dir: str | None = None) -> list[str]:
    user_skills = os.path.join(claude_config_dir(), "skills")
    plugin_parent = os.path.abspath(
        os.path.expanduser(
            (os.environ.get("CLAUDE_CODE_PLUGIN_CACHE_DIR") or "").strip()
            or os.path.join(claude_config_dir(), "plugins")
        )
    )
    return _dedup(
        [
            os.path.join(plugin_parent, "cache"),
            user_skills,
            *_claudecode_project_skill_dirs(workspace_dir),
        ]
    )


def _codex_plugin_dirs(workspace_dir: str | None = None) -> list[str]:
    """Return documented local and installed Codex plugin roots.

    Marketplace ``source.path`` values are resolved relative to the marketplace
    root and must remain inside it. Git, URL, and npm entries do not expose a
    stable local source path; installed copies of those entries are still
    discovered through the canonical cache.
    """
    cache = os.path.join(codex_home(), "plugins", "cache")
    paths = codex_marketplace_plugin_dirs(workspace_dir)
    paths.append(cache)
    return _dedup(paths)


def codex_marketplace_plugin_dirs(workspace_dir: str | None = None) -> list[str]:
    """Return exact local plugin roots declared by Codex marketplaces."""
    paths: list[str] = []
    for marketplace_file, source_root in _codex_marketplace_files(workspace_dir):
        paths.extend(_read_codex_local_marketplace_paths(marketplace_file, source_root))
    return _dedup(paths)


def _read_codex_local_marketplace_paths(path: str, source_root: str) -> list[str]:
    """Safely resolve local ``source.path`` entries from one marketplace."""
    try:
        payload = _read_bounded_stable_file(path, max_bytes=1024 * 1024)
    except OSError:
        return []
    try:
        document = json.loads(payload)
    except (UnicodeDecodeError, ValueError):
        return []
    if not isinstance(document, dict) or not isinstance(document.get("plugins"), list):
        return []

    root = os.path.abspath(source_root)
    try:
        reject_reparse_path(root)
    except OSError:
        return []
    resolved: list[str] = []
    for plugin in document["plugins"]:
        if not isinstance(plugin, dict):
            continue
        source = plugin.get("source")
        relative = ""
        if isinstance(source, str):
            relative = source
        elif isinstance(source, dict) and source.get("source") == "local":
            relative = source.get("path") if isinstance(source.get("path"), str) else ""
        if not relative.startswith("./"):
            continue
        candidate = os.path.abspath(os.path.join(root, relative[2:]))
        try:
            if os.path.commonpath([root, candidate]) != root:
                continue
            reject_reparse_path(candidate)
        except (OSError, ValueError):
            continue
        resolved.append(candidate)
    return _dedup(resolved)


def _amp_plugin_dirs(workspace_dir: str | None = None) -> list[str]:
    return _dedup(
        [
            _workspace_path(workspace_dir, ".amp", "plugins"),
            os.path.join(amp_config_home(), "plugins"),
        ]
    )


def _zeptoclaw_plugin_dirs() -> list[str]:
    zepto_home = os.environ.get("ZEPTOCLAW_HOME") or os.path.join(str(Path.home()), ".zeptoclaw")
    base = os.path.join(zepto_home, "plugins")
    return _dedup(
        [
            base,
            os.path.join(base, "cache"),
        ]
    )


def _hermes_plugin_dirs(workspace_dir: str | None = None) -> list[str]:
    _ = workspace_dir  # project plugins are process-CWD/env conditional and unverified.
    home = hermes_home()
    paths = [
        os.path.join(home, "plugins"),
        # Official native installers place the tagged checkout (and therefore
        # its bundled plugin tree) beside the data files under HERMES_HOME.
        os.path.join(home, "hermes-agent", "plugins"),
    ]
    bundled_override = (os.environ.get("HERMES_BUNDLED_PLUGINS") or "").strip()
    if bundled_override:
        paths.append(os.path.abspath(os.path.expanduser(bundled_override)))
    else:
        try:
            spec = importlib.util.find_spec("hermes_cli")
        except (ImportError, AttributeError, ValueError):
            spec = None
        if spec is not None and spec.origin:
            paths.append(os.path.join(os.path.dirname(os.path.dirname(spec.origin)), "plugins"))
    return _dedup(paths)


def _opencode_plugin_dirs(workspace_dir: str | None = None) -> list[str]:
    home = str(Path.home())
    custom = _opencode_config_dir()
    return _dedup(
        [
            _workspace_path(workspace_dir, ".opencode", "plugins"),
            os.path.join(home, ".config", "opencode", "plugins"),
            os.path.join(custom, "plugins") if custom else "",
        ]
    )


def _antigravity_plugin_dirs(workspace_dir: str | None = None) -> list[str]:
    home = str(Path.home())
    return _dedup(
        [
            _workspace_path(workspace_dir, ".agents", "plugins"),
            _workspace_path(workspace_dir, "_agents", "plugins"),
            os.path.join(home, ".gemini", "config", "plugins"),
            os.path.join(home, ".gemini", "antigravity-cli", "plugins"),
        ]
    )


def _plugin_component_dirs(plugin_dirs: list[str], component: str) -> list[str]:
    out: list[str] = []
    for plugin_dir in plugin_dirs:
        if not os.path.isdir(plugin_dir):
            continue
        try:
            entries = sorted(os.listdir(plugin_dir))
        except OSError:
            continue
        for entry in entries:
            plugin_root = os.path.join(plugin_dir, entry)
            if not os.path.isdir(plugin_root):
                continue
            component_dir = os.path.join(plugin_root, component)
            if os.path.isdir(component_dir):
                out.append(component_dir)
    return _dedup(out)


def _gemini_plugin_dirs(workspace_dir: str | None = None) -> list[str]:
    home = str(Path.home())
    return _dedup(
        [
            os.path.join(home, ".gemini", "extensions"),
            _workspace_path(workspace_dir, ".gemini", "extensions"),
        ]
    )


def _openclaw_plugin_dirs(openclaw_home: str | None) -> list[str]:
    home = _expand(openclaw_home or "~/.openclaw")
    return [os.path.join(home, "extensions")]


# --- MCP readers -----------------------------------------------------------


def _claudecode_mcp_servers(workspace_dir: str | None = None) -> list[MCPServerEntry]:
    entries: list[MCPServerEntry] = []
    # Claude's documented precedence is local, project, then user. Local and
    # user entries share one state document, so parse it once and select only
    # the local entry whose project key resolves to the explicitly pinned
    # workspace. Never infer a project from DefenseClaw's daemon cwd.
    local_entries, user_entries = _read_claude_mcp_state(
        claude_mcp_state_path(),
        workspace_dir=workspace_dir,
    )
    entries.extend(local_entries)
    project_mcp = _workspace_path(workspace_dir, ".mcp.json")
    if project_mcp:
        entries.extend(_read_dotmcp_json(project_mcp))
    entries.extend(user_entries)
    return _dedup_mcp_entries(entries)


def _read_claude_mcp_state(
    path: str,
    *,
    workspace_dir: str | None = None,
) -> tuple[list[MCPServerEntry], list[MCPServerEntry]]:
    """Return Claude Code ``(local, user)`` MCP entries from one state file.

    Local entries live at ``projects[<absolute workspace>].mcpServers`` and
    user entries at top-level ``mcpServers``. Project keys are compared using
    the host filesystem's native normalization rules (including case folding
    on Windows). An unpinned workspace intentionally yields no local entries.
    """

    try:
        with open(path) as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return [], []
    if not isinstance(data, dict):
        return [], []

    local_entries: list[MCPServerEntry] = []
    workspace = _workspace_dir(workspace_dir)
    projects = data.get("projects")
    if workspace and isinstance(projects, dict):
        normalized_workspace = os.path.normcase(os.path.normpath(workspace))
        for project_key, project_state in projects.items():
            if not isinstance(project_key, str) or not isinstance(project_state, dict):
                continue
            normalized_key = os.path.normcase(
                os.path.normpath(
                    os.path.abspath(os.path.expanduser(_expand(project_key)))
                )
            )
            if normalized_key != normalized_workspace:
                continue
            local_entries = _parse_mcp_servers_value(project_state.get("mcpServers"))
            break

    user_entries = _parse_mcp_servers_value(data.get("mcpServers"))
    return local_entries, user_entries


def _codex_mcp_servers(workspace_dir: str | None = None) -> list[MCPServerEntry]:
    """Return the merged Codex MCP server list.

    Codex stores both user and project MCP registries in ``config.toml``
    under ``[mcp_servers]`` tables. Project layers are ordered from project
    root through the current working directory, and the closest layer wins.
    This read-only inventory accepts an explicit workspace as the active
    directory, walks its candidate project layers closest-first, then falls
    back to the user registry. Codex activates those project layers only for a
    trusted project; DefenseClaw reports that requirement but does not infer
    the client's private trust decision from filesystem presence.
    """
    entries: list[MCPServerEntry] = []
    for project_config in _codex_project_config_paths(workspace_dir):
        entries.extend(
            _read_codex_config_toml(
                project_config,
                source_scope="project",
                trust_required=True,
            )
        )
    entries.extend(
        _read_codex_config_toml(
            os.path.join(codex_home(), "config.toml"),
            source_scope="user",
        )
    )
    return _dedup_mcp_entries(entries)


def _amp_mcp_servers(workspace_dir: str | None = None) -> list[MCPServerEntry]:
    """Return Amp MCP registrations using its documented precedence."""

    entries: list[MCPServerEntry] = []
    documents = _amp_settings_documents(workspace_dir)
    for document in reversed(documents):
        servers = _amp_setting_value(document, "amp.mcpServers")
        if servers is _MISSING:
            servers = document.get("mcpServers")
        entries.extend(_parse_mcp_servers_value(servers))

    for root in _amp_skill_dirs(workspace_dir):
        for path in _amp_skill_mcp_paths(root):
            entries.extend(_read_dotmcp_json(path))
    return _dedup_mcp_entries(entries)


def _amp_skill_mcp_paths(root: str) -> list[str]:
    """Return direct skill-bundled ``mcp.json`` files below *root*."""

    paths: list[str] = []
    root_manifest = os.path.join(root, "mcp.json")
    if os.path.isfile(root_manifest):
        paths.append(root_manifest)
    try:
        children = sorted(os.scandir(root), key=lambda item: item.name.casefold())
    except OSError:
        return paths
    for child in children:
        try:
            if child.is_dir(follow_symlinks=False):
                manifest = os.path.join(child.path, "mcp.json")
                if os.path.isfile(manifest):
                    paths.append(manifest)
        except OSError:
            continue
    return _dedup(paths)


def _read_codex_config_toml(
    path: str,
    *,
    source_scope: str = "",
    trust_required: bool = False,
) -> list[MCPServerEntry]:
    """Parse the ``[mcp_servers]`` table out of Codex's config.toml.

    Codex's documented schema (developers.openai.com/codex/config) is::

        [mcp_servers.<name>]
        command = "..."
        args = ["..."]
        env = { KEY = "value" }

    Values may also use a flat ``[mcp_servers]`` mapping where each
    entry is itself a table — both shapes are accepted. Failures
    (missing file, malformed TOML, missing block) return ``[]`` so
    callers can continue inventorying lower-precedence layers.

    Implementation note: we use the stdlib :mod:`tomllib` (Python
    3.11+), falling back to the ``tomli`` backport on Python 3.10
    (see the module-level import); no exec-based parser is used.
    """
    try:
        payload = _read_bounded_stable_file(path, max_bytes=1024 * 1024)
        data = tomllib.loads(payload.decode("utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError):
        return []
    servers = data.get("mcp_servers")
    if not isinstance(servers, dict):
        return []
    out: list[MCPServerEntry] = []
    for name, cfg in servers.items():
        if not isinstance(cfg, dict):
            continue
        out.append(
            MCPServerEntry(
                name=name,
                command=str(cfg.get("command", "") or ""),
                args=list(cfg.get("args", []) or []),
                env={str(k): str(v) for k, v in (cfg.get("env", {}) or {}).items()},
                url=str(cfg.get("url", "") or ""),
                transport=str(cfg.get("transport", "") or ""),
                source=path,
                source_scope=source_scope,
                trust_required=trust_required,
            )
        )
    return out


def _zeptoclaw_mcp_servers(workspace_dir: str | None = None) -> list[MCPServerEntry]:
    zepto_home = os.environ.get("ZEPTOCLAW_HOME") or os.path.join(str(Path.home()), ".zeptoclaw")
    entries: list[MCPServerEntry] = []
    entries.extend(_read_zepto_config(os.path.join(zepto_home, "config.json")))
    project_mcp = _workspace_path(workspace_dir, ".mcp.json")
    if project_mcp:
        entries.extend(_read_dotmcp_json(project_mcp))
    return _dedup_mcp_entries(entries)


def _openclaw_mcp_servers(
    openclaw_config: str | None,
    *,
    openclaw_bin_resolver: Any = None,
    openclaw_cmd_prefix: list[str] | None = None,
) -> list[MCPServerEntry]:
    cli_entries = _read_mcp_servers_via_openclaw_cli(
        openclaw_bin_resolver=openclaw_bin_resolver,
        openclaw_cmd_prefix=openclaw_cmd_prefix,
    )
    if cli_entries is not None:
        return cli_entries
    return _read_mcp_servers_from_openclaw_json(
        _expand(openclaw_config or "~/.openclaw/openclaw.json"),
    )


def _hermes_mcp_servers() -> list[MCPServerEntry]:
    return _read_yaml_mcp_servers(
        hermes_config_path(),
        key_paths=(("mcp", "servers"), ("mcpServers",)),
    )


def _cursor_mcp_servers(workspace_dir: str | None = None) -> list[MCPServerEntry]:
    home = str(Path.home())
    entries: list[MCPServerEntry] = []
    project_mcp = _workspace_path(workspace_dir, ".cursor", "mcp.json")
    if project_mcp:
        entries.extend(_read_dotmcp_json(project_mcp, source_scope="project"))
    entries.extend(
        _read_dotmcp_json(
            os.path.join(home, ".cursor", "mcp.json"),
            source_scope="user",
        )
    )
    # Cursor documents both scopes but not a same-name winner, and extension
    # APIs may register dynamic servers without either file. Preserve every
    # local candidate instead of silently selecting the first one.
    return entries


def _windsurf_mcp_servers() -> list[MCPServerEntry]:
    entries: list[MCPServerEntry] = []
    for path in _windsurf_mcp_paths():
        entries.extend(_read_dotmcp_json(path))
    return _dedup_mcp_entries(entries)


def _gemini_mcp_servers() -> list[MCPServerEntry]:
    return _read_mcp_settings_block(
        os.path.join(str(Path.home()), ".gemini", "settings.json"),
        keys=("mcpServers",),
    )


def _copilot_mcp_servers(workspace_dir: str | None = None) -> list[MCPServerEntry]:
    entries: list[MCPServerEntry] = []
    # Copilot loads both workspace forms at every ancestor through the Git
    # root. Deeper entries are visited first so name deduplication below
    # preserves the documented higher-priority registration.
    for path in copilot_mcp_config_files(workspace_dir):
        entries.extend(_read_dotmcp_json(path))
    return _dedup_mcp_entries(entries)


def _openhands_mcp_servers() -> list[MCPServerEntry]:
    return _read_dotmcp_json(os.path.join(str(Path.home()), ".openhands", "mcp.json"))


def _antigravity_global_mcp_path() -> str:
    return os.path.join(str(Path.home()), ".gemini", "config", "mcp_config.json")


def _antigravity_workspace_mcp_path(workspace_dir: str | None) -> str:
    return _workspace_path(workspace_dir, ".agents", "mcp_config.json")


def _antigravity_mcp_servers(workspace_dir: str | None = None) -> list[MCPServerEntry]:
    """Return Antigravity MCP registrations from native mcp_config.json files.

    The contract pins the global path to ``~/.gemini/config/mcp_config.json``.
    When an explicit workspace is supplied, Antigravity also reads
    ``<workspace>/.agents/mcp_config.json``. Both files use a top-level
    ``mcpServers`` object and remote entries may spell the URL as either the
    canonical ``serverUrl`` or compatibility alias ``url``.
    """
    entries: list[MCPServerEntry] = []
    entries.extend(_read_antigravity_mcp_config(_antigravity_global_mcp_path()))
    workspace_mcp = _antigravity_workspace_mcp_path(workspace_dir)
    if workspace_mcp:
        entries.extend(_read_antigravity_mcp_config(workspace_mcp))
    return _dedup_mcp_entries(entries)


def _read_antigravity_mcp_config(path: str) -> list[MCPServerEntry]:
    return _read_mcp_settings_block(path, keys=("mcpServers",))


def _opencode_env_path(value: str, workspace_dir: str | None) -> str:
    """Resolve an OpenCode env path without borrowing the daemon's cwd."""
    value = os.path.expanduser(value.strip())
    if not value:
        return ""
    if os.path.isabs(value):
        return os.path.abspath(value)
    root = _workspace_dir(workspace_dir)
    return os.path.abspath(os.path.join(root, value)) if root else ""


def _opencode_layer(path: str, scope: str) -> OpenCodeConfigLayer:
    data = _load_json_or_jsonc(path)
    return OpenCodeConfigLayer(
        source=os.path.abspath(path),
        source_scope=scope,
        path=os.path.abspath(path),
        data=data if isinstance(data, dict) else None,
    )


def _resolve_opencode_config(workspace_dir: str | None = None) -> OpenCodeConfigResolution:
    """Resolve non-enterprise OpenCode v1.18.10-v1.18.11 config precedence.

    Remote authenticated ``.well-known`` config and Windows ProgramData
    managed config cannot be established safely by an offline connector read;
    they are returned as typed, unverified sources and are never fetched or
    opened here. Relative env paths require an explicit workspace so this
    process never substitutes its own cwd for the OpenCode client's cwd.
    """
    home = str(Path.home())
    root = _workspace_dir(workspace_dir)
    candidates: list[tuple[str, str]] = [
        (os.path.join(home, ".config", "opencode", "config.json"), "global"),
        (os.path.join(home, ".config", "opencode", "opencode.json"), "global"),
        (os.path.join(home, ".config", "opencode", "opencode.jsonc"), "global"),
    ]
    unverified = [
        OpenCodeUnverifiedConfigSource(
            source="authenticated .well-known/opencode",
            source_scope="remote",
            reason="requires OpenCode's authenticated runtime fetch",
        ),
    ]

    explicit_raw = os.environ.get("OPENCODE_CONFIG", "")
    if explicit_raw:
        explicit = _opencode_env_path(explicit_raw, workspace_dir)
        if explicit:
            candidates.append((explicit, "custom-file"))
        else:
            unverified.append(
                OpenCodeUnverifiedConfigSource(
                    source="OPENCODE_CONFIG",
                    source_scope="custom-file",
                    reason="relative path has no explicit workspace",
                ),
            )
    if root:
        candidates.extend(
            [
                (os.path.join(root, "opencode.json"), "project"),
                (os.path.join(root, "opencode.jsonc"), "project"),
                (os.path.join(root, ".opencode", "opencode.json"), "project-directory"),
                (os.path.join(root, ".opencode", "opencode.jsonc"), "project-directory"),
            ],
        )
    candidates.extend(
        [
            (os.path.join(home, ".opencode", "opencode.json"), "home-directory"),
            (os.path.join(home, ".opencode", "opencode.jsonc"), "home-directory"),
        ],
    )
    custom_raw = os.environ.get("OPENCODE_CONFIG_DIR", "")
    if custom_raw:
        custom = _opencode_env_path(custom_raw, workspace_dir)
        if custom:
            candidates.extend(
                [
                    (os.path.join(custom, "opencode.json"), "custom-directory"),
                    (os.path.join(custom, "opencode.jsonc"), "custom-directory"),
                ],
            )
        else:
            unverified.append(
                OpenCodeUnverifiedConfigSource(
                    source="OPENCODE_CONFIG_DIR",
                    source_scope="custom-directory",
                    reason="relative path has no explicit workspace",
                ),
            )

    layers: list[OpenCodeConfigLayer] = []
    seen: set[str] = set()
    for path, scope in candidates:
        key = os.path.normcase(os.path.abspath(path))
        if key in seen:
            continue
        seen.add(key)
        layers.append(_opencode_layer(path, scope))

    content = os.environ.get("OPENCODE_CONFIG_CONTENT", "")
    if content:
        parsed = _load_json_or_jsonc_content(content)
        layers.append(
            OpenCodeConfigLayer(
                source="OPENCODE_CONFIG_CONTENT",
                source_scope="inline",
                data=parsed if isinstance(parsed, dict) else None,
            ),
        )

    unverified.append(
        OpenCodeUnverifiedConfigSource(
            source="Windows ProgramData managed config",
            source_scope="managed-enterprise",
            reason="excluded from this non-enterprise connector; effective precedence is unverified",
        ),
    )
    return OpenCodeConfigResolution(tuple(layers), tuple(unverified))


def _opencode_config_paths(workspace_dir: str | None) -> list[str]:
    """Return locally representable file layers in v1.18.10 merge order."""
    return [layer.path for layer in _resolve_opencode_config(workspace_dir).layers if layer.path]


def _opencode_mcp_servers(workspace_dir: str | None = None) -> list[MCPServerEntry]:
    """Return opencode's MCP server registrations.

    opencode stores MCP servers under a top-level ``mcp`` map in its
    JSON/JSONC config — a different schema from the ``mcpServers`` shape
    every other connector uses. Global servers are read first, then the
    pinned project, user ``~/.opencode`` component, and active custom-directory
    files layer on top, matching how opencode itself loads them at runtime.
    """
    order: list[str] = []
    entries: dict[str, dict[str, Any]] = {}
    provenance: dict[str, tuple[str, str]] = {}
    for layer in _resolve_opencode_config(workspace_dir).layers:
        data = layer.data
        servers = data.get("mcp") if isinstance(data, dict) else None
        if not isinstance(servers, dict):
            continue
        for name_raw, cfg in servers.items():
            if not isinstance(cfg, dict):
                continue
            name = str(name_raw)
            if name not in entries:
                order.append(name)
            # OpenCode deep-merges config objects. Merge the raw entry before
            # projecting it into MCPServerEntry so a higher-precedence
            # enabled-only override preserves the lower command/url.
            entries[name] = _merge_opencode_mcp_config(entries.get(name, {}), cfg)
            provenance[name] = (layer.source, layer.source_scope)
    return [
        _opencode_entry_to_mcp(name, entries[name], *provenance[name])
        for name in order
    ]


def _read_opencode_mcp_block(path: str) -> dict[str, dict[str, Any]]:
    """Parse opencode's top-level ``mcp`` map without losing partial overrides.

    Tolerates JSONC (``//`` and ``/* */`` comments) via the optional
    ``json5`` backport — mirroring the OpenClaw reader — so a
    hand-authored ``opencode.jsonc`` still parses. A missing file,
    unparseable content, or missing ``mcp`` block all yield ``{}``.
    """
    data = _load_json_or_jsonc(path)
    if not isinstance(data, dict):
        return {}
    servers = data.get("mcp")
    if not isinstance(servers, dict):
        return {}
    out: dict[str, dict[str, Any]] = {}
    for name, cfg in servers.items():
        if not isinstance(cfg, dict):
            continue
        out[str(name)] = cfg
    return out


def _merge_opencode_mcp_config(
    base: dict[str, Any],
    override: dict[str, Any],
) -> dict[str, Any]:
    """Deep-merge one OpenCode MCP config layer over another."""
    merged = dict(base)
    for key, value in override.items():
        previous = merged.get(key)
        if isinstance(previous, dict) and isinstance(value, dict):
            merged[key] = _merge_opencode_mcp_config(previous, value)
        else:
            merged[key] = value
    return merged


def _opencode_entry_to_mcp(
    name: str,
    cfg: dict[str, Any],
    source: str = "",
    source_scope: str = "",
) -> MCPServerEntry:
    """Map one opencode ``mcp`` entry to the connector-neutral schema.

    opencode local servers carry ``command`` as a single argv array
    (command + args fused) plus an ``environment`` map; remote servers
    carry ``url``. We split the argv back into command/args and surface
    ``type`` as the transport so callers can tell local from remote.
    """
    kind = str(cfg.get("type", "") or "").strip().lower()
    url = str(cfg.get("url", "") or "")
    command_list = cfg.get("command")
    disabled = cfg.get("enabled", True) is False
    if kind == "remote" or (not kind and url and not command_list):
        raw_headers = cfg.get("headers")
        headers = (
            {str(k): str(v) for k, v in raw_headers.items()}
            if isinstance(raw_headers, dict)
            else {}
        )
        return MCPServerEntry(
            name=name,
            url=url,
            transport="remote",
            headers=headers,
            disabled=disabled,
            source=source,
            source_scope=source_scope,
        )
    command = ""
    args: list[str] = []
    if isinstance(command_list, list) and command_list:
        command = str(command_list[0] or "")
        args = [str(a) for a in command_list[1:]]
    elif isinstance(command_list, str):
        command = command_list
    raw_env = cfg.get("environment")
    env = (
        {str(k): str(v) for k, v in raw_env.items()}
        if isinstance(raw_env, dict)
        else {}
    )
    return MCPServerEntry(
        name=name,
        command=command,
        args=args,
        env=env,
        transport="local",
        disabled=disabled,
        source=source,
        source_scope=source_scope,
    )


def _load_json_or_jsonc_content(raw: str) -> Any:
    """Parse JSON/JSONC text without ever logging the potentially secret text."""
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        try:
            import json5  # type: ignore[import-untyped]

            return json5.loads(raw)
        except Exception:
            return None


def _load_json_or_jsonc(path: str) -> Any:
    """Read *path* as JSON, falling back to JSON5 for JSONC comments.

    Returns the parsed value, or ``None`` when the file is missing or
    parses as neither JSON nor JSON5 (e.g. ``json5`` not installed and
    the file carries comments). Callers treat ``None`` as "no data".
    """
    try:
        with open(path) as f:
            raw = f.read()
    except OSError:
        return None
    return _load_json_or_jsonc_content(raw)


def _parse_json_or_jsonc(raw: str) -> Any:
    """Parse already-read JSON/JSONC text without changing read policy."""

    parsed = _load_json_or_jsonc_content(raw)
    if parsed is not None:
        return parsed
    try:
        return json.loads(_strip_jsonc(raw))
    except json.JSONDecodeError:
        return None


def _strip_jsonc(raw: str) -> str:
    """Remove JSONC comments and trailing commas without touching strings."""

    out: list[str] = []
    index = 0
    in_string = False
    escaped = False
    while index < len(raw):
        char = raw[index]
        if in_string:
            out.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            index += 1
            continue
        if char == '"':
            in_string = True
            out.append(char)
            index += 1
            continue
        if char == "/" and index + 1 < len(raw):
            next_char = raw[index + 1]
            if next_char == "/":
                index += 2
                while index < len(raw) and raw[index] not in "\r\n":
                    index += 1
                continue
            if next_char == "*":
                index += 2
                while index + 1 < len(raw) and raw[index : index + 2] != "*/":
                    if raw[index] in "\r\n":
                        out.append(raw[index])
                    index += 1
                index = min(index + 2, len(raw))
                continue
        if char == "," and _next_jsonc_significant_char(raw, index + 1) in ("}", "]"):
            index += 1
            continue
        out.append(char)
        index += 1
    return "".join(out)


def _next_jsonc_significant_char(raw: str, index: int) -> str:
    """Return the next non-whitespace, non-comment JSONC character."""

    while index < len(raw):
        char = raw[index]
        if char.isspace():
            index += 1
            continue
        if char == "/" and index + 1 < len(raw):
            next_char = raw[index + 1]
            if next_char == "/":
                index += 2
                while index < len(raw) and raw[index] not in "\r\n":
                    index += 1
                continue
            if next_char == "*":
                end = raw.find("*/", index + 2)
                if end < 0:
                    return ""
                index = end + 2
                continue
        return char
    return ""


# --- Low-level file/CLI helpers --------------------------------------------


def _read_openclaw_json(config_file: str) -> dict[str, Any] | None:
    try:
        with open(_expand(config_file)) as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return None


def _read_mcp_settings_block(
    path: str,
    *,
    keys: tuple[str, ...],
) -> list[MCPServerEntry]:
    """Read an MCP servers block out of a JSON settings file.

    *keys* is a tuple of the dotted lookup path inside the JSON
    document — e.g. ``("mcpServers",)`` for Claude Code's
    settings.json or ``("mcp", "servers")`` for ZeptoClaw's
    config.json. Returns an empty list when the file is missing,
    invalid JSON, or the block isn't a mapping.
    """
    try:
        with open(path) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return []
    if not isinstance(data, dict):
        return []
    cursor: Any = data
    for k in keys:
        if not isinstance(cursor, dict):
            return []
        cursor = cursor.get(k)
        if cursor is None:
            return []
    return _parse_mcp_servers_value(cursor)


def _read_yaml_mcp_servers(
    path: str,
    *,
    key_paths: tuple[tuple[str, ...], ...],
) -> list[MCPServerEntry]:
    try:
        with open(path, "rb") as f:
            raw = f.read(_MCP_CONFIG_MAX_BYTES + 1)
        if len(raw) > _MCP_CONFIG_MAX_BYTES:
            return []
        data = yaml.safe_load(raw.decode("utf-8-sig", errors="strict")) or {}
    except (OSError, UnicodeDecodeError, yaml.YAMLError):
        return []
    if not isinstance(data, dict):
        return []
    entries: list[MCPServerEntry] = []
    for keys in key_paths:
        cursor: Any = data
        for k in keys:
            if not isinstance(cursor, dict):
                cursor = None
                break
            cursor = cursor.get(k)
        if cursor is not None:
            entries.extend(_parse_mcp_servers_value(cursor))
    return _dedup_mcp_entries(entries)


def _read_dotmcp_json(
    path: str,
    *,
    source_scope: str = "",
) -> list[MCPServerEntry]:
    """Parse a project-local ``.mcp.json``.

    The file may either wrap the servers under ``mcpServers`` (Claude
    Code / Codex SDK convention) or be a top-level mapping of name →
    server. Both are accepted.
    """
    try:
        with open(path) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return []
    if not isinstance(data, dict):
        return []
    inner = data.get("mcpServers")
    if isinstance(inner, dict):
        entries = _parse_mcp_servers_dict(inner)
    else:
        entries = _parse_mcp_servers_dict(data)
    if source_scope:
        return [
            replace(entry, source=path, source_scope=source_scope)
            for entry in entries
        ]
    return entries


def _read_zepto_config(path: str) -> list[MCPServerEntry]:
    return _read_mcp_settings_block(path, keys=("mcp", "servers"))


def _windsurf_mcp_paths(home: str | None = None) -> list[str]:
    home = home or windsurf_user_home()
    return [
        os.path.join(home, ".codeium", "windsurf", "mcp_config.json"),
    ]


def _read_mcp_servers_via_openclaw_cli(
    *,
    openclaw_bin_resolver: Any = None,
    openclaw_cmd_prefix: list[str] | None = None,
) -> list[MCPServerEntry] | None:
    """Run ``openclaw config get mcp.servers`` and parse the JSON.

    Returns ``None`` (not ``[]``) on any failure so callers can fall
    back to direct ``openclaw.json`` parsing. Honors *openclaw_cmd_prefix*
    so sandbox-mode setups can prepend ``sudo -u sandbox``.
    """
    if openclaw_bin_resolver is None:
        import shutil

        bin_path = shutil.which("openclaw") or "openclaw"
    else:
        bin_path = openclaw_bin_resolver()
    prefix = list(openclaw_cmd_prefix or [])
    try:
        result = subprocess.run(
            [*prefix, bin_path, "config", "get", "mcp.servers"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            return None
        return _parse_mcp_servers_text(result.stdout)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None


def _read_mcp_servers_from_openclaw_json(path: str) -> list[MCPServerEntry]:
    try:
        with open(path) as f:
            raw = f.read()
    except OSError:
        return []
    data: dict[str, Any] | None = None
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        try:
            import json5  # type: ignore[import-untyped]

            data = json5.loads(raw)
        except Exception:
            return []
    if not isinstance(data, dict):
        return []
    servers = data.get("mcp", {}).get("servers")
    if not isinstance(servers, dict):
        return []
    return _parse_mcp_servers_dict(servers)


def _parse_mcp_servers_text(text: str) -> list[MCPServerEntry]:
    text = text.strip()
    if not text:
        return []
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return []
    return _parse_mcp_servers_value(parsed)


def _parse_mcp_servers_value(servers: Any) -> list[MCPServerEntry]:
    if isinstance(servers, dict):
        return _parse_mcp_servers_dict(servers)
    if isinstance(servers, list):
        return _parse_mcp_servers_list(servers)
    return []


def _parse_mcp_servers_dict(servers: dict[str, Any]) -> list[MCPServerEntry]:
    out: list[MCPServerEntry] = []
    for name, cfg in servers.items():
        if not isinstance(cfg, dict):
            continue
        disabled = cfg.get("disabled", False)
        out.append(
            MCPServerEntry(
                name=name,
                command=cfg.get("command", "") or "",
                args=list(cfg.get("args", []) or []),
                env=dict(cfg.get("env", {}) or {}),
                cwd=cfg.get("cwd", "") or "",
                url=cfg.get("serverUrl", "") or cfg.get("url", "") or "",
                transport=infer_mcp_transport(
                    cfg.get("transport", ""),
                    url=cfg.get("serverUrl", "") or cfg.get("url", "") or "",
                    command=cfg.get("command", "") or "",
                ),
                headers=dict(cfg.get("headers", {}) or {}),
                auth_provider_type=cfg.get("authProviderType", "") or "",
                oauth=dict(cfg.get("oauth", {}) or {}),
                disabled=disabled if isinstance(disabled, bool) else False,
                disabled_tools=list(cfg.get("disabledTools", []) or []),
            )
        )
    return out


def _parse_mcp_servers_list(servers: list[Any]) -> list[MCPServerEntry]:
    out: list[MCPServerEntry] = []
    for cfg in servers:
        if not isinstance(cfg, dict):
            continue
        name = str(cfg.get("name", "") or "")
        if not name:
            continue
        disabled = cfg.get("disabled", False)
        out.append(
            MCPServerEntry(
                name=name,
                command=cfg.get("command", "") or "",
                args=list(cfg.get("args", []) or []),
                env=dict(cfg.get("env", {}) or {}),
                cwd=cfg.get("cwd", "") or "",
                url=cfg.get("serverUrl", "") or cfg.get("url", "") or "",
                transport=infer_mcp_transport(
                    cfg.get("transport", ""),
                    url=cfg.get("serverUrl", "") or cfg.get("url", "") or "",
                    command=cfg.get("command", "") or "",
                ),
                headers=dict(cfg.get("headers", {}) or {}),
                auth_provider_type=cfg.get("authProviderType", "") or "",
                oauth=dict(cfg.get("oauth", {}) or {}),
                disabled=disabled if isinstance(disabled, bool) else False,
                disabled_tools=list(cfg.get("disabledTools", []) or []),
            )
        )
    return out


def _dedup_mcp_entries(entries: list[MCPServerEntry]) -> list[MCPServerEntry]:
    seen: set[str] = set()
    out: list[MCPServerEntry] = []
    for e in entries:
        if e.name in seen:
            continue
        seen.add(e.name)
        out.append(e)
    return out


# ---------------------------------------------------------------------------
# MCP server WRITES — connector-specific set / unset adapters (S4.2)
# ---------------------------------------------------------------------------


class MCPWriteUnsupportedError(RuntimeError):
    """Raised when MCP set/unset is requested for a connector that
    doesn't expose a programmatic write surface.

    Today this fires for ZeptoClaw — its config.json is owned by the
    ZeptoClaw TUI and rewriting it from outside the application can
    race with on-disk autosave. Operators should add the server inside
    the ZeptoClaw UI and re-run ``defenseclaw mcp scan`` to pick it
    up via the read path.
    """


def set_mcp_server(
    connector: str | None,
    name: str,
    entry: dict[str, Any],
    *,
    workspace_dir: str | None = None,
    openclaw_config_setter: Any = None,
) -> None:
    """Add or update an MCP server in the active connector's registry.

    *entry* is a dict shaped per the connector's on-disk schema —
    typically containing ``command``, ``args``, ``url``, ``env``,
    ``transport`` keys (extra keys are preserved verbatim so newer
    schemas pass through unchanged).

    Per-connector write surfaces:

    * OpenClaw     — delegated to ``openclaw config set
                     mcp.servers.<name> <json>`` via
                     *openclaw_config_setter* (callable taking
                     ``(path, json_value_str)``). Caller injects this
                     so we can keep subprocess access out of this
                     module.
    * Claude Code  — ``$HOME/.claude.json[mcpServers][name]`` (or the
                     equivalent file under ``CLAUDE_CONFIG_DIR``)
                     via :func:`_atomic_json_merge`.
    * Codex        — ``~/.codex/config.toml[mcp_servers][name]``
                     by default, or ``<workspace>/.codex/config.toml`` when
                     *workspace_dir* is explicit.
    * opencode     — global ``~/.config/opencode/opencode.json[mcp][name]``
                     by default, or ``<workspace>/opencode.json`` when
                     *workspace_dir* is explicit, mapping the entry into
                     opencode's ``mcp`` schema.
    * Antigravity  — global ``~/.gemini/config/mcp_config.json[mcpServers][name]``
                     by default, or ``<workspace>/.agents/mcp_config.json``
                     when *workspace_dir* is explicit. Remote generic ``url``
                     entries are written canonically as ``serverUrl``.
    * ZeptoClaw    — :class:`MCPWriteUnsupportedError`.
    * Hook-backed  — connector-owned JSON/YAML config when documented
                     (for example OpenHands writes ``~/.openhands/mcp.json``).
    """
    name_n = normalize(connector)
    if name_n == "openclaw":
        if openclaw_config_setter is None:
            raise RuntimeError(
                "openclaw_config_setter not provided — set_mcp_server "
                "for openclaw requires the caller to inject the "
                "openclaw config-set shim",
            )
        openclaw_config_setter(f"mcp.servers.{name}", json.dumps(entry))
        return
    if name_n == "claudecode":
        path = claude_mcp_state_path()
        try:
            _set_claudecode_mcp_server(path, name, entry)
        except UnsafePathError as exc:
            raise ValueError(str(exc)) from exc
        return
    if name_n == "codex":
        workspace = _workspace_dir(workspace_dir)
        path = (
            os.path.join(workspace, ".codex", "config.toml")
            if workspace
            else _codex_config_toml_path()
        )
        _set_codex_mcp_server_at_path(path, name, entry)
        return
    if name_n == "amp":
        raise MCPWriteUnsupportedError(
            "amp MCP discovery is read-only in DefenseClaw. Add or update the "
            "server with `amp mcp add`, then re-run `defenseclaw mcp scan`.",
        )
    if name_n == "hermes":
        _atomic_yaml_merge(hermes_config_path(), ("mcp", "servers", name), entry)
        return
    if name_n == "cursor":
        workspace = _workspace_dir(workspace_dir)
        path = (
            os.path.join(workspace, ".cursor", "mcp.json")
            if workspace
            else os.path.join(str(Path.home()), ".cursor", "mcp.json")
        )
        _atomic_json_merge(path, ("mcpServers", name), entry)
        return
    if name_n == "windsurf":
        path = _windsurf_existing_mcp_write_path()
        if not path:
            raise MCPWriteUnsupportedError(
                "windsurf MCP writes are disabled until an existing documented "
                "Windsurf MCP config file is present; DefenseClaw will not "
                "create guessed Windsurf config paths.",
            )
        _atomic_json_merge(path, ("mcpServers", name), entry)
        return
    if name_n == "geminicli":
        path = os.path.join(str(Path.home()), ".gemini", "settings.json")
        _atomic_json_merge(path, ("mcpServers", name), entry)
        return
    if name_n == "copilot":
        workspace = _workspace_dir(workspace_dir)
        path = (
            os.path.join(workspace, ".github", "mcp.json")
            if workspace
            else os.path.join(copilot_home(), "mcp-config.json")
        )
        _atomic_json_merge(path, ("mcpServers", name), entry)
        return
    if name_n == "openhands":
        path = os.path.join(str(Path.home()), ".openhands", "mcp.json")
        _atomic_json_merge(path, ("mcpServers", name), entry)
        return
    if name_n == "antigravity":
        _set_antigravity_mcp_server(name, entry, workspace_dir=workspace_dir)
        return
    if name_n == "opencode":
        _set_opencode_mcp_server(name, entry, workspace_dir=workspace_dir)
        return
    if name_n == "omnigent":
        raise MCPWriteUnsupportedError(
            "omnigent MCP configuration is unsupported and unverified by the "
            "DefenseClaw connector; only the custom policy bridge is installed.",
        )
    if name_n == "zeptoclaw":
        raise MCPWriteUnsupportedError(
            "zeptoclaw does not expose a programmatic MCP write surface. "
            "Add the server inside the ZeptoClaw UI and re-run "
            "`defenseclaw mcp scan` to discover it via the read path.",
        )
    # Anything else — treat as an unknown framework. Refuse rather than
    # silently writing to the OpenClaw config.
    raise MCPWriteUnsupportedError(
        f"set_mcp_server: unknown connector {connector!r}; expected one of {KNOWN_CONNECTORS}",
    )


def unset_mcp_server(
    connector: str | None,
    name: str,
    *,
    workspace_dir: str | None = None,
    openclaw_config_unsetter: Any = None,
) -> None:
    """Remove an MCP server from the active connector's registry.

    Mirrors :func:`set_mcp_server` and uses the connector's native JSON or TOML
    format; OpenClaw delegates to the injected
    *openclaw_config_unsetter*; ZeptoClaw raises
    :class:`MCPWriteUnsupportedError`.
    """
    name_n = normalize(connector)
    if name_n == "openclaw":
        if openclaw_config_unsetter is None:
            raise RuntimeError(
                "openclaw_config_unsetter not provided — unset_mcp_server "
                "for openclaw requires the caller to inject the "
                "openclaw config-unset shim",
            )
        openclaw_config_unsetter(f"mcp.servers.{name}")
        return
    if name_n == "claudecode":
        path = claude_mcp_state_path()
        try:
            _unset_claudecode_mcp_server(path, name)
        except UnsafePathError as exc:
            raise ValueError(str(exc)) from exc
        return
    if name_n == "codex":
        workspace = _workspace_dir(workspace_dir)
        path = (
            os.path.join(workspace, ".codex", "config.toml")
            if workspace
            else _codex_config_toml_path()
        )
        _unset_codex_mcp_server_at_path(path, name)
        return
    if name_n == "amp":
        raise MCPWriteUnsupportedError(
            "amp MCP discovery is read-only in DefenseClaw. Remove the server "
            "with Amp's MCP command, then re-run `defenseclaw mcp scan`.",
        )
    if name_n == "hermes":
        _atomic_yaml_delete(hermes_config_path(), ("mcp", "servers", name))
        return
    if name_n == "cursor":
        workspace = _workspace_dir(workspace_dir)
        path = (
            os.path.join(workspace, ".cursor", "mcp.json")
            if workspace
            else os.path.join(str(Path.home()), ".cursor", "mcp.json")
        )
        _atomic_json_delete(path, ("mcpServers", name))
        return
    if name_n == "windsurf":
        path = _windsurf_existing_mcp_write_path()
        if not path:
            raise MCPWriteUnsupportedError(
                "windsurf MCP writes are disabled until an existing documented Windsurf MCP config file is present.",
            )
        _atomic_json_delete(path, ("mcpServers", name))
        return
    if name_n == "geminicli":
        path = os.path.join(str(Path.home()), ".gemini", "settings.json")
        _atomic_json_delete(path, ("mcpServers", name))
        return
    if name_n == "copilot":
        workspace = _workspace_dir(workspace_dir)
        path = (
            os.path.join(workspace, ".github", "mcp.json")
            if workspace
            else os.path.join(copilot_home(), "mcp-config.json")
        )
        _atomic_json_delete(path, ("mcpServers", name))
        return
    if name_n == "openhands":
        path = os.path.join(str(Path.home()), ".openhands", "mcp.json")
        _atomic_json_delete(path, ("mcpServers", name))
        return
    if name_n == "antigravity":
        _unset_antigravity_mcp_server(name, workspace_dir=workspace_dir)
        return
    if name_n == "opencode":
        _unset_opencode_mcp_server(name, workspace_dir=workspace_dir)
        return
    if name_n == "omnigent":
        raise MCPWriteUnsupportedError(
            "omnigent MCP configuration is unsupported and unverified by the "
            "DefenseClaw connector; only the custom policy bridge is installed.",
        )
    if name_n == "zeptoclaw":
        raise MCPWriteUnsupportedError(
            "zeptoclaw does not expose a programmatic MCP write surface. Remove the server inside the ZeptoClaw UI.",
        )
    raise MCPWriteUnsupportedError(
        f"unset_mcp_server: unknown connector {connector!r}; expected one of {KNOWN_CONNECTORS}",
    )


# ---------------------------------------------------------------------------
# Codex TOML MCP writer
# ---------------------------------------------------------------------------


def _codex_config_toml_path() -> str:
    return os.path.join(codex_home(), "config.toml")


def _toml_string(value: Any) -> str:
    return json.dumps(str(value))


def _toml_array(values: Any) -> str:
    if not isinstance(values, list):
        return "[]"
    return "[" + ", ".join(_toml_string(v) for v in values) + "]"


def _codex_mcp_block(name: str, entry: dict[str, Any]) -> str:
    """Render one Codex ``[mcp_servers]`` table.

    This intentionally writes only the table DefenseClaw owns. The
    surrounding config text is preserved by replacing that table in
    place and appending it when absent.
    """
    table = f"mcp_servers.{_toml_string(name)}"
    lines = [f"[{table}]"]
    for key in ("command", "url", "transport"):
        value = entry.get(key)
        if value:
            lines.append(f"{key} = {_toml_string(value)}")
    if entry.get("args") is not None:
        lines.append(f"args = {_toml_array(entry.get('args'))}")
    env = entry.get("env")
    if isinstance(env, dict) and env:
        lines.append("")
        lines.append(f"[{table}.env]")
        for key in sorted(env):
            lines.append(f"{_toml_string(key)} = {_toml_string(env[key])}")
    return "\n".join(lines).rstrip() + "\n"


def _codex_mcp_section_names(name: str) -> set[str]:
    quoted = f"mcp_servers.{_toml_string(name)}"
    names = {quoted, f"{quoted}.env"}
    if all(ch.isalnum() or ch in {"_", "-"} for ch in name):
        bare = f"mcp_servers.{name}"
        names.update({bare, f"{bare}.env"})
    return names


def _strip_codex_mcp_block(text: str, name: str) -> str:
    section_names = _codex_mcp_section_names(name)
    out: list[str] = []
    skipping = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            section_name = stripped.strip("[]").strip()
            skipping = section_name in section_names
        if not skipping:
            out.append(line)
    return "\n".join(out).rstrip() + ("\n" if out else "")


def _set_codex_mcp_server_at_path(path: str, name: str, entry: dict[str, Any]) -> None:
    try:
        with open(path, encoding="utf-8") as f:
            text = f.read()
    except FileNotFoundError:
        text = ""
    if text.strip():
        try:
            tomllib.loads(text)
        except tomllib.TOMLDecodeError as exc:
            raise ValueError(f"refusing to modify malformed Codex config.toml: {exc}") from exc
    updated = _strip_codex_mcp_block(text, name)
    if updated and not updated.endswith("\n\n"):
        updated = updated.rstrip() + "\n\n"
    updated += _codex_mcp_block(name, entry)
    _capture_managed_mcp_backup(path)
    _atomic_write_text(path, updated)


def _unset_codex_mcp_server_at_path(path: str, name: str) -> bool:
    try:
        with open(path, encoding="utf-8") as f:
            text = f.read()
    except FileNotFoundError:
        return False
    updated = _strip_codex_mcp_block(text, name)
    if updated == text:
        return False
    _capture_managed_mcp_backup(path)
    _atomic_write_text(path, updated)
    return True


# ---------------------------------------------------------------------------
# Antigravity JSON MCP writer
# ---------------------------------------------------------------------------


def _antigravity_mcp_write_path(workspace_dir: str | None) -> str:
    workspace = _workspace_dir(workspace_dir)
    if workspace:
        return os.path.join(workspace, ".agents", "mcp_config.json")
    return _antigravity_global_mcp_path()


def _read_antigravity_doc_for_write(path: str) -> dict[str, Any]:
    """Read an Antigravity MCP config for read-modify-write.

    Missing or empty files start from ``{}``. Existing non-empty files must be
    JSON objects so DefenseClaw can preserve unknown top-level and per-server
    fields instead of clobbering hand-authored Antigravity settings.
    """
    try:
        with open(path, encoding="utf-8") as f:
            raw = f.read()
    except FileNotFoundError:
        return {}
    if not raw.strip():
        return {}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"refusing to write Antigravity MCP config {path}: existing file "
            "is not valid JSON; fix it by hand so DefenseClaw does not "
            "clobber unrelated configuration.",
        ) from exc
    if isinstance(data, dict):
        return data
    raise ValueError(
        f"refusing to write Antigravity MCP config {path}: existing file is "
        "not a JSON object; fix it by hand so DefenseClaw does not clobber "
        "unrelated configuration.",
    )


def _antigravity_mcp_entry_from_generic(
    entry: dict[str, Any],
    *,
    existing: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Map a generic MCP entry dict into Antigravity's native schema.

    ``defenseclaw mcp set`` passes remote URLs as ``url``; Antigravity accepts
    that spelling for reads but DefenseClaw writes the canonical ``serverUrl``.
    Known native fields are overlaid onto the existing server object while
    unrelated keys are kept so future Antigravity fields survive updates.
    """
    out: dict[str, Any] = dict(existing or {})
    handled = {
        "command",
        "args",
        "env",
        "cwd",
        "disabled",
        "disabledTools",
        "serverUrl",
        "url",
        "httpUrl",
        "headers",
        "authProviderType",
        "oauth",
        "transport",
    }
    for key in ("command", "cwd", "authProviderType", "transport"):
        if key in entry:
            value = entry.get(key)
            if value is None:
                out.pop(key, None)
            else:
                out[key] = str(value)
    for key in ("args", "disabledTools"):
        if key in entry:
            value = entry.get(key)
            if value is None:
                out.pop(key, None)
            else:
                out[key] = [str(v) for v in (value or [])]
    for key in ("env", "headers"):
        if key in entry:
            value = entry.get(key)
            if value is None:
                out.pop(key, None)
            elif isinstance(value, dict):
                out[key] = {str(k): str(v) for k, v in value.items()}
    if "oauth" in entry:
        value = entry.get("oauth")
        if value is None:
            out.pop("oauth", None)
        elif isinstance(value, dict):
            out["oauth"] = value
    if "disabled" in entry:
        value = entry.get("disabled")
        if value is None:
            out.pop("disabled", None)
        elif isinstance(value, bool):
            out["disabled"] = value

    remote_url = (
        entry.get("serverUrl")
        or entry.get("url")
        or entry.get("httpUrl")
        or out.get("serverUrl")
        or out.get("url")
        or out.get("httpUrl")
    )
    if remote_url:
        out["serverUrl"] = str(remote_url)
        # `url` is read-compatible but not DefenseClaw's canonical write
        # spelling; `httpUrl` is legacy migration input only.
        out.pop("url", None)
        out.pop("httpUrl", None)

    for key, value in entry.items():
        if key not in handled:
            out[key] = value
    return out


def _set_antigravity_mcp_server(
    name: str,
    entry: dict[str, Any],
    *,
    workspace_dir: str | None = None,
) -> None:
    path = _antigravity_mcp_write_path(workspace_dir)
    _reject_symlink_config(path)
    parent = os.path.dirname(path)
    if parent and not os.path.exists(parent):
        os.makedirs(parent, mode=0o700, exist_ok=True)
    data = _read_antigravity_doc_for_write(path)
    servers = data.get("mcpServers")
    if not isinstance(servers, dict):
        servers = {}
    existing = servers.get(name)
    servers[name] = _antigravity_mcp_entry_from_generic(
        entry,
        existing=existing if isinstance(existing, dict) else None,
    )
    data["mcpServers"] = servers
    _capture_managed_mcp_backup(path)
    _atomic_write_json(path, data)


def _unset_antigravity_mcp_server(
    name: str,
    *,
    workspace_dir: str | None = None,
) -> bool:
    path = _antigravity_mcp_write_path(workspace_dir)
    if not os.path.lexists(path):
        return False
    _reject_symlink_config(path)
    try:
        with open(path, encoding="utf-8") as f:
            loaded = json.load(f)
    except (OSError, json.JSONDecodeError):
        return False
    if not isinstance(loaded, dict):
        return False
    servers = loaded.get("mcpServers")
    if not isinstance(servers, dict) or name not in servers:
        return False
    del servers[name]
    loaded["mcpServers"] = servers
    _capture_managed_mcp_backup(path)
    _atomic_write_json(path, loaded)
    return True


# ---------------------------------------------------------------------------
# opencode JSON MCP writer
# ---------------------------------------------------------------------------
#
# opencode keeps MCP servers under a top-level ``mcp`` map keyed by name,
# where each entry is ``{type: local, command: [...], environment: {...},
# enabled: bool}`` or ``{type: remote, url: ..., enabled: bool}`` — a
# different shape from the ``mcpServers`` schema the other JSON connectors
# use. Writes target the highest writable local component layer: an active
# ``OPENCODE_CONFIG_DIR``, the user ``~/.opencode`` component, an existing
# project ``.opencode`` component, an explicitly pinned project root,
# ``OPENCODE_CONFIG``, or the documented global
# ``~/.config/opencode/opencode.json``.
#
# Write policy is plain JSON (documented, mcp.md M5 open decision): every
# unrelated key is round-tripped by value, but JSONC comments are NOT
# preserved. To avoid clobbering a config we cannot understand, the
# writer fails closed (MCPWriteUnsupportedError) when an existing
# non-empty file parses as neither JSON nor JSON5, rather than
# overwriting it with just the ``mcp`` block.


def _opencode_write_path(workspace_dir: str | None) -> str:
    root = _workspace_dir(workspace_dir)
    custom_raw = os.environ.get("OPENCODE_CONFIG_DIR", "")
    explicit_raw = os.environ.get("OPENCODE_CONFIG", "")
    custom = _opencode_env_path(custom_raw, workspace_dir)
    explicit = _opencode_env_path(explicit_raw, workspace_dir)
    for variable, raw, resolved in (
        ("OPENCODE_CONFIG_DIR", custom_raw, custom),
        ("OPENCODE_CONFIG", explicit_raw, explicit),
    ):
        if raw.strip() and not resolved:
            raise MCPWriteUnsupportedError(
                f"refusing to write OpenCode MCP config because relative {variable} "
                "requires an explicitly pinned workspace",
            )
    home_component = os.path.join(str(Path.home()), ".opencode")
    if custom:
        config_root = custom
    elif os.path.isdir(home_component):
        config_root = home_component
    elif root:
        project_component = os.path.join(root, ".opencode")
        if os.path.isdir(project_component):
            config_root = project_component
        else:
            config_root = root
    elif explicit:
        return explicit
    else:
        config_root = os.path.join(str(Path.home()), ".config", "opencode")
    # OpenCode loads .jsonc after .json in component directories. Update the
    # existing higher-precedence document when present so a same-name entry in
    # it cannot silently override a newly written lower-precedence JSON file.
    jsonc = os.path.join(config_root, "opencode.jsonc")
    if os.path.lexists(jsonc):
        return jsonc
    return os.path.join(config_root, "opencode.json")


def _opencode_mcp_entry_from_generic(entry: dict[str, Any]) -> dict[str, Any]:
    """Map a connector-neutral MCP entry dict to opencode's ``mcp`` schema.

    A ``url`` (with no command, or an explicit ``transport: remote``)
    becomes an opencode ``remote`` server; otherwise it is a ``local``
    server whose ``command``/``args`` are fused into opencode's single
    ``command`` argv array and whose ``env`` becomes ``environment``.
    """
    url = str(entry.get("url", "") or "")
    transport = str(entry.get("transport", "") or "").strip().lower()
    command = entry.get("command")
    if url and (transport == "remote" or not command):
        remote: dict[str, Any] = {"type": "remote", "url": url, "enabled": True}
        headers = entry.get("headers")
        if isinstance(headers, dict) and headers:
            remote["headers"] = {str(k): str(v) for k, v in headers.items()}
        return remote
    argv: list[str] = []
    if isinstance(command, list):
        argv = [str(c) for c in command]
    elif command:
        argv = [str(command)]
    argv += [str(a) for a in (entry.get("args", []) or [])]
    local: dict[str, Any] = {"type": "local", "command": argv, "enabled": True}
    env = entry.get("env")
    if isinstance(env, dict) and env:
        local["environment"] = {str(k): str(v) for k, v in env.items()}
    return local


def _read_opencode_doc_for_write(path: str) -> dict[str, Any]:
    """Read an existing opencode config for read-modify-write.

    Returns ``{}`` for a missing or empty file. Raises
    :class:`MCPWriteUnsupportedError` when a non-empty file parses as
    neither JSON nor JSON5 (or is not a JSON object), so a malformed or
    unexpectedly-shaped config is never silently overwritten.
    """
    try:
        with open(path) as f:
            raw = f.read()
    except FileNotFoundError:
        return {}
    if not raw.strip():
        return {}
    data = _load_json_or_jsonc(path)
    if isinstance(data, dict):
        return data
    raise MCPWriteUnsupportedError(
        f"refusing to write opencode MCP config {path}: existing file is not "
        "parseable as a JSON/JSON5 object; edit it by hand or remove it first "
        "so DefenseClaw does not clobber unrelated configuration.",
    )


def _set_opencode_mcp_server(
    name: str,
    entry: dict[str, Any],
    *,
    workspace_dir: str | None = None,
) -> None:
    if os.environ.get("OPENCODE_CONFIG_CONTENT", ""):
        raise MCPWriteUnsupportedError(
            "refusing to write OpenCode MCP config while OPENCODE_CONFIG_CONTENT "
            "is active because the inline higher-precedence layer cannot be "
            "updated or restored atomically",
        )
    path = _opencode_write_path(workspace_dir)
    _reject_symlink_config(path)
    data = _read_opencode_doc_for_write(path)
    mcp = data.get("mcp")
    if not isinstance(mcp, dict):
        mcp = {}
    mcp[name] = _opencode_mcp_entry_from_generic(entry)
    data["mcp"] = mcp
    parent = os.path.dirname(path)
    if parent and not os.path.exists(parent):
        os.makedirs(parent, mode=0o700, exist_ok=True)
    _capture_managed_mcp_backup(path)
    _atomic_write_json(path, data)


def _unset_opencode_mcp_server(
    name: str,
    *,
    workspace_dir: str | None = None,
) -> bool:
    if os.environ.get("OPENCODE_CONFIG_CONTENT", ""):
        raise MCPWriteUnsupportedError(
            "refusing to remove OpenCode MCP config while OPENCODE_CONFIG_CONTENT "
            "is active because an inline declaration could remain effective",
        )
    # Resolve the highest writable target even though unset mutates every
    # active file layer. This fails closed when a relative env path cannot be
    # made authoritative without a pinned workspace.
    _opencode_write_path(workspace_dir)
    updates: list[tuple[str, dict[str, Any]]] = []
    # OpenCode merges every active layer. Removing only the winning custom or
    # project declaration would let a same-name lower layer silently resurface,
    # so validate first and then remove the name from every active config file.
    for path in _opencode_config_paths(workspace_dir):
        if not os.path.lexists(path):
            continue
        _reject_symlink_config(path)
        data = _read_opencode_doc_for_write(path)
        mcp = data.get("mcp")
        if not isinstance(mcp, dict) or name not in mcp:
            continue
        del mcp[name]
        data["mcp"] = mcp
        updates.append((path, data))
    for path, data in updates:
        _capture_managed_mcp_backup(path)
        _atomic_write_json(path, data)
    return bool(updates)


# ---------------------------------------------------------------------------
# Atomic JSON read-modify-write helpers
# ---------------------------------------------------------------------------
#
# These mirror the Go-side atomicWriteFile pattern in
# internal/gateway/connector/codex.go: write to a tempfile in the same
# directory, fsync, then os.replace. Permissions are forced to 0o600
# because the targets (~/.claude.json, ./.mcp.json) frequently
# carry credentials in the env: block.


_CLAUDE_MCP_OWNERSHIP_SCHEMA = 3
_CLAUDE_MUTATION_GUARD: ContextVar[dict[str, Any] | None] = ContextVar(
    "claude_mcp_mutation_guard",
    default=None,
)


def _read_regular_bytes_if_present(path: str) -> bytes | None:
    """Read one optional sensitive file without following redirected paths."""
    if not os.path.lexists(path):
        reject_reparse_path(path)
        return None
    _reject_symlink_config(path)
    reject_reparse_path(path)
    fd = open_regular_file_no_follow(path)
    with os.fdopen(fd, "rb") as source:
        return source.read()


def _parse_claude_settings(path: str, raw: bytes | None) -> dict[str, Any]:
    """Accept only an absent, empty, or strict UTF-8 JSON object."""
    if raw is None or not raw.strip():
        return {}
    try:
        loaded = json.loads(
            raw.decode("utf-8"),
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError(f"non-finite JSON constant: {value}"),
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise MCPWriteUnsupportedError(
            f"refusing to write Claude MCP settings {path}: existing file must "
            "be a valid UTF-8 JSON object (an empty or whitespace-only file is allowed)",
        ) from exc
    if not isinstance(loaded, dict):
        raise MCPWriteUnsupportedError(
            f"refusing to write Claude MCP settings {path}: existing file must "
            "be a JSON object (an empty or whitespace-only file is allowed)",
        )
    if "mcpServers" in loaded and not isinstance(loaded["mcpServers"], dict):
        raise MCPWriteUnsupportedError(
            f"refusing to write Claude MCP settings {path}: existing mcpServers property must be a JSON object",
        )
    return loaded


def _render_json_bytes(data: dict[str, Any]) -> bytes:
    try:
        rendered = json.dumps(data, indent=2, sort_keys=True, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise MCPWriteUnsupportedError("refusing Claude MCP mutation: JSON value is not finite") from exc
    return (rendered + "\n").encode("utf-8")


def _bytes_to_b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _bytes_from_b64(value: Any) -> bytes | None:
    if not isinstance(value, str):
        return None
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except (ValueError, UnicodeEncodeError):
        return None


def _optional_bytes_to_b64(value: bytes | None) -> str | None:
    return _bytes_to_b64(value) if value is not None else None


def _required_bytes_from_b64(value: Any, *, label: str) -> bytes:
    decoded = _bytes_from_b64(value)
    if decoded is None:
        raise MCPWriteUnsupportedError(f"Claude MCP ownership metadata has invalid {label}")
    return decoded


def _optional_bytes_from_b64(value: Any, *, label: str) -> bytes | None:
    if value is None:
        return None
    return _required_bytes_from_b64(value, label=label)


def _validate_claude_released_names(value: Any, *, label: str) -> set[str]:
    if (
        not isinstance(value, list)
        or any(not isinstance(name, str) or not name for name in value)
        or value != sorted(set(value))
    ):
        raise MCPWriteUnsupportedError(f"Claude MCP ownership metadata has invalid {label}")
    return set(value)


def _claude_mcp_ownership_path(path: str) -> str:
    target = os.path.abspath(path)
    # Keep native Windows staging paths below MAX_PATH even under long profile
    # roots. The envelope still binds and validates the complete target path.
    target_key = _registry_key(target)[:40]
    return os.path.join(
        _registry_dir(),
        f"c-{target_key}.json",
    )


def _claude_windows_private_file_security(path: str, destination: str | None = None):
    """Return the validated owner-only file DACL of this target's lock."""
    from defenseclaw import windows_acl
    from defenseclaw.file_permissions import windows_acl_write_error

    lock_path = _claude_mcp_ownership_path(path) + ".lock"
    reject_reparse_path(lock_path)
    problem = windows_acl_write_error(lock_path)
    if problem is not None:
        raise MCPWriteUnsupportedError(
            f"refusing Claude MCP mutation: ownership lock is not private: {problem}",
        )
    security = windows_acl.capture_path(lock_path)
    parent = os.path.dirname(os.path.abspath(destination or path)) or os.curdir
    if windows_acl.capture_path(parent, directory=True).owner != security.owner:
        raise MCPWriteUnsupportedError(
            f"refusing Claude MCP mutation: settings parent has an unexpected owner: {parent}",
        )
    return security


def _validate_claude_private_file(path: str, *, label: str, snapshot: Any = None) -> None:
    """Require existing secret-bearing coordination files to be owner-private."""
    if not os.path.lexists(path):
        return
    reject_reparse_path(path)
    info = os.lstat(path)
    if not stat.S_ISREG(info.st_mode):
        raise MCPWriteUnsupportedError(
            f"refusing Claude MCP mutation: {label} is not a regular file: {path}",
        )
    if os.name == "nt":
        from defenseclaw import windows_acl
        from defenseclaw.file_permissions import windows_acl_write_error

        problem = windows_acl_write_error(path)
        if problem is not None:
            raise MCPWriteUnsupportedError(
                f"refusing Claude MCP mutation: {label} is not private: {problem}",
            )
        captured = windows_acl.capture_path(path)
        if snapshot is not None and captured != snapshot.windows_security:
            raise MCPWriteUnsupportedError(
                f"refusing Claude MCP mutation: {label} security changed while validating: {path}",
            )
        return
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise MCPWriteUnsupportedError(
            f"refusing Claude MCP mutation: {label} must have owner-only permissions: {path}",
        )
    getuid = getattr(os, "getuid", None)
    if getuid is not None and info.st_uid != getuid():
        raise MCPWriteUnsupportedError(
            f"refusing Claude MCP mutation: {label} has an unexpected owner: {path}",
        )
    if snapshot is not None and (
        info.st_dev != snapshot.device or info.st_ino != snapshot.inode or stat.S_IMODE(info.st_mode) != snapshot.mode
    ):
        raise MCPWriteUnsupportedError(
            f"refusing Claude MCP mutation: {label} changed while validating: {path}",
        )


def _new_claude_mcp_state(
    raw: bytes | None,
    data: dict[str, Any],
) -> dict[str, Any]:
    container_present = "mcpServers" in data
    return {
        "file_preexisting": raw is not None,
        "preimage_b64": _optional_bytes_to_b64(raw),
        "postimage_b64": "",
        "postimage_identity": None,
        "exact_restore": True,
        "container_preexisting": container_present,
        "container_preimage": data.get("mcpServers") if container_present else None,
        "managed": {},
    }


def _windows_security_sha256(security: Any) -> str | None:
    if security is None:
        return None
    digest = hashlib.sha256()
    for value in (
        security.owner,
        security.dacl,
        security.mandatory_label or b"",
        b"1" if security.dacl_protected else b"0",
        b"1" if security.sacl_protected else b"0",
    ):
        digest.update(len(value).to_bytes(8, "big"))
        digest.update(value)
    return digest.hexdigest()


def _claude_postimage_identity_from_snapshot(snapshot: Any) -> dict[str, Any]:
    # Windows ownership and authorization are represented by the native file
    # ID, parent ID, and security descriptor.  The CRT mode/uid/gid projection
    # can be normalized after a staged file is published (notably when an
    # inheriting DACL is restored), so persisting those projection values
    # would make two snapshots of the same proven file object disagree.  Keep
    # the native security digest exact; only the non-authoritative CRT fields
    # are normalized away on Windows.
    windows_native = os.name == "nt"
    return {
        "device": snapshot.device,
        "inode": snapshot.inode,
        "parent_device": snapshot.parent_device,
        "parent_inode": snapshot.parent_inode,
        "mode": None if windows_native else snapshot.mode,
        "uid": None if windows_native else snapshot.uid,
        "gid": None if windows_native else snapshot.gid,
        "windows_security_sha256": _windows_security_sha256(snapshot.windows_security),
    }


def _capture_claude_postimage_identity(path: str) -> dict[str, Any]:
    from defenseclaw.observability import v8_activation

    snapshot = v8_activation._snapshot_regular_file(path, required=True)
    return _claude_postimage_identity_from_snapshot(snapshot)


def _validate_claude_postimage_identity(value: Any, *, label: str) -> dict[str, Any]:
    required = {
        "device",
        "inode",
        "parent_device",
        "parent_inode",
        "mode",
        "uid",
        "gid",
        "windows_security_sha256",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise MCPWriteUnsupportedError(f"Claude MCP ownership metadata has invalid {label}")
    for key in required - {"windows_security_sha256"}:
        if value[key] is not None and (not isinstance(value[key], int) or isinstance(value[key], bool)):
            raise MCPWriteUnsupportedError(f"Claude MCP ownership metadata has invalid {label}.{key}")
    security_digest = value["windows_security_sha256"]
    if security_digest is not None and (
        not isinstance(security_digest, str)
        or len(security_digest) != 64
        or any(character not in "0123456789abcdef" for character in security_digest)
    ):
        raise MCPWriteUnsupportedError(
            f"Claude MCP ownership metadata has invalid {label}.windows_security_sha256",
        )
    return value


def _claude_postimage_identity_matches(path: str, state: dict[str, Any]) -> bool:
    from defenseclaw.observability import v8_activation

    expected = state.get("postimage_identity")
    if not isinstance(expected, dict):
        return False
    try:
        return _capture_claude_postimage_identity(path) == expected
    except (OSError, ValueError, v8_activation.V8ActivationError):
        return False


def _validate_claude_mcp_state(
    value: Any,
    *,
    label: str,
    pending: bool = False,
) -> dict[str, Any] | None:
    if value is None:
        return None
    required = {
        "file_preexisting",
        "preimage_b64",
        "postimage_b64",
        "postimage_identity",
        "exact_restore",
        "container_preexisting",
        "container_preimage",
        "managed",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise MCPWriteUnsupportedError(f"Claude MCP ownership metadata has invalid {label}")
    for key in ("file_preexisting", "exact_restore", "container_preexisting"):
        if not isinstance(value[key], bool):
            raise MCPWriteUnsupportedError(f"Claude MCP ownership metadata has invalid {label}.{key}")
    preimage = value["preimage_b64"]
    if value["file_preexisting"]:
        preimage_raw = _required_bytes_from_b64(preimage, label=f"{label}.preimage_b64")
        preimage_data = _parse_claude_settings(label, preimage_raw)
    elif preimage is not None:
        raise MCPWriteUnsupportedError(f"Claude MCP ownership metadata has invalid {label}.preimage_b64")
    else:
        preimage_data = {}
    if not value["file_preexisting"] and value["container_preexisting"]:
        raise MCPWriteUnsupportedError(f"Claude MCP ownership metadata has invalid {label}.container_preexisting")
    container_present = "mcpServers" in preimage_data
    if value["container_preexisting"] != container_present or (
        container_present and not _json_values_match(value["container_preimage"], preimage_data["mcpServers"])
    ):
        raise MCPWriteUnsupportedError(f"Claude MCP ownership metadata has invalid {label}.container_preimage")
    if not container_present and value["container_preimage"] is not None:
        raise MCPWriteUnsupportedError(f"Claude MCP ownership metadata has invalid {label}.container_preimage")

    postimage_raw = _required_bytes_from_b64(value["postimage_b64"], label=f"{label}.postimage_b64")
    postimage_data = _parse_claude_settings(label, postimage_raw)
    identity = value["postimage_identity"]
    if identity is None:
        if not pending:
            raise MCPWriteUnsupportedError(f"Claude MCP ownership metadata has invalid {label}.postimage_identity")
    else:
        _validate_claude_postimage_identity(identity, label=f"{label}.postimage_identity")

    managed = value["managed"]
    if not isinstance(managed, dict) or not managed:
        raise MCPWriteUnsupportedError(f"Claude MCP ownership metadata has invalid {label}.managed")
    postimage_servers = postimage_data.get("mcpServers")
    if not isinstance(postimage_servers, dict):
        raise MCPWriteUnsupportedError(f"Claude MCP ownership metadata has invalid {label}.postimage_b64")
    for server_name, record in managed.items():
        record_keys = {"owned", "prior_present", "prior"}
        if (
            not isinstance(server_name, str)
            or not server_name
            or not isinstance(record, dict)
            or set(record) != record_keys
        ):
            raise MCPWriteUnsupportedError(f"Claude MCP ownership metadata has invalid {label}.managed")
        if not isinstance(record["owned"], dict):
            raise MCPWriteUnsupportedError(
                f"Claude MCP ownership metadata has invalid {label}.managed.{server_name}.owned",
            )
        if not isinstance(record["prior_present"], bool):
            raise MCPWriteUnsupportedError(
                f"Claude MCP ownership metadata has invalid {label}.managed.{server_name}.prior_present",
            )
        if not record["prior_present"] and record["prior"] is not None:
            raise MCPWriteUnsupportedError(
                f"Claude MCP ownership metadata has invalid {label}.managed.{server_name}.prior",
            )
        if server_name not in postimage_servers or not _json_values_match(
            postimage_servers[server_name],
            record["owned"],
        ):
            raise MCPWriteUnsupportedError(
                f"Claude MCP ownership metadata has invalid {label}.postimage_b64",
            )
    return value


def _load_claude_mcp_envelope(path: str) -> dict[str, Any] | None:
    metadata_path = _claude_mcp_ownership_path(path)
    _validate_claude_private_file(metadata_path, label="ownership metadata")
    raw = _read_regular_bytes_if_present(metadata_path)
    if raw is None:
        return None
    try:
        envelope = json.loads(
            raw.decode("utf-8"),
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError(f"non-finite JSON constant: {value}"),
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise MCPWriteUnsupportedError(
            f"refusing Claude MCP mutation: ownership metadata {metadata_path} is corrupt",
        ) from exc
    if not isinstance(envelope, dict) or set(envelope) != {
        "schema",
        "path",
        "committed",
        "pending",
        "released",
    }:
        raise MCPWriteUnsupportedError(
            f"refusing Claude MCP mutation: ownership metadata {metadata_path} is corrupt",
        )
    if envelope.get("schema") != _CLAUDE_MCP_OWNERSHIP_SCHEMA:
        raise MCPWriteUnsupportedError(
            f"refusing Claude MCP mutation: ownership metadata {metadata_path} has an unsupported schema",
        )
    recorded_path = envelope.get("path")
    if not isinstance(recorded_path, str) or os.path.normcase(os.path.abspath(recorded_path)) != os.path.normcase(
        os.path.abspath(path)
    ):
        raise MCPWriteUnsupportedError(
            f"refusing Claude MCP mutation: ownership metadata {metadata_path} targets another file",
        )
    envelope["committed"] = _validate_claude_mcp_state(
        envelope.get("committed"),
        label="committed",
    )
    released = _validate_claude_released_names(
        envelope.get("released"),
        label="released",
    )
    pending_transaction = envelope["pending"]
    if pending_transaction is not None:
        if not isinstance(pending_transaction, dict) or set(pending_transaction) != {
            "old_config_b64",
            "new_config_b64",
            "next_state",
            "next_released",
        }:
            raise MCPWriteUnsupportedError("Claude MCP ownership metadata has invalid pending transaction")
        next_released = _validate_claude_released_names(
            pending_transaction["next_released"],
            label="pending.next_released",
        )
        if len(released ^ next_released) > 1:
            raise MCPWriteUnsupportedError(
                "Claude MCP ownership metadata has inconsistent pending released names",
            )
        old_config = _optional_bytes_from_b64(
            pending_transaction["old_config_b64"],
            label="pending.old_config_b64",
        )
        new_config = _optional_bytes_from_b64(
            pending_transaction["new_config_b64"],
            label="pending.new_config_b64",
        )
        old_data = _parse_claude_settings("pending.old_config_b64", old_config) if old_config is not None else {}
        if new_config is not None:
            _parse_claude_settings("pending.new_config_b64", new_config)
        next_state = _validate_claude_mcp_state(
            pending_transaction["next_state"],
            label="pending.next_state",
            pending=True,
        )
        pending_transaction["next_state"] = next_state
        committed = envelope["committed"]
        newly_released = next_released - released
        newly_managed = released - next_released
        if newly_released and (
            committed is None
            or not newly_released.issubset(committed["managed"])
            or (next_state is not None and bool(newly_released & set(next_state["managed"])))
        ):
            raise MCPWriteUnsupportedError(
                "Claude MCP ownership metadata has inconsistent pending released names",
            )
        if newly_managed and (next_state is None or not newly_managed.issubset(next_state["managed"])):
            raise MCPWriteUnsupportedError(
                "Claude MCP ownership metadata has inconsistent pending released names",
            )
        if committed is None and next_state is None and (old_config is None or new_config is None):
            raise MCPWriteUnsupportedError(
                "Claude MCP ownership metadata has incomplete unowned pending config",
            )
        if committed is None and next_state is None and old_config == new_config:
            raise MCPWriteUnsupportedError(
                "Claude MCP ownership metadata has an invalid unowned no-op transaction",
            )
        if committed is not None and old_config != _required_bytes_from_b64(
            committed["postimage_b64"],
            label="committed.postimage_b64",
        ):
            raise MCPWriteUnsupportedError("Claude MCP ownership metadata has inconsistent pending old config")
        if committed is not None and old_config is None:
            raise MCPWriteUnsupportedError("Claude MCP ownership metadata has inconsistent pending old config")
        if next_state is not None and (
            new_config is None
            or new_config
            != _required_bytes_from_b64(
                next_state["postimage_b64"],
                label="pending.next_state.postimage_b64",
            )
        ):
            raise MCPWriteUnsupportedError("Claude MCP ownership metadata has inconsistent pending new config")
        if next_state is not None and committed is None:
            next_preimage = _optional_bytes_from_b64(
                next_state["preimage_b64"],
                label="pending.next_state.preimage_b64",
            )
            if next_preimage != old_config or next_state["file_preexisting"] != (old_config is not None):
                raise MCPWriteUnsupportedError(
                    "Claude MCP ownership metadata has inconsistent pending episode preimage",
                )
            if not next_state["exact_restore"]:
                raise MCPWriteUnsupportedError(
                    "Claude MCP ownership metadata has inconsistent initial exact-restore state",
                )
        if next_state is not None and committed is not None:
            immutable_fields = (
                "file_preexisting",
                "preimage_b64",
                "exact_restore",
                "container_preexisting",
                "container_preimage",
            )
            if any(not _json_values_match(next_state[field], committed[field]) for field in immutable_fields):
                raise MCPWriteUnsupportedError(
                    "Claude MCP ownership metadata changes immutable pending episode fields",
                )
            for server_name in committed["managed"].keys() & next_state["managed"].keys():
                committed_record = committed["managed"][server_name]
                next_record = next_state["managed"][server_name]
                if committed_record["prior_present"] != next_record["prior_present"] or not _json_values_match(
                    committed_record["prior"],
                    next_record["prior"],
                ):
                    raise MCPWriteUnsupportedError(
                        "Claude MCP ownership metadata changes immutable managed prior state",
                    )
        if next_state is not None:
            committed_names = set(committed["managed"]) if committed is not None else set()
            added_names = set(next_state["managed"]) - committed_names
            if len(added_names) > 1:
                raise MCPWriteUnsupportedError(
                    "Claude MCP ownership metadata adds multiple managed servers in one transaction",
                )
            old_servers = old_data.get("mcpServers", {})
            for server_name in added_names:
                record = next_state["managed"][server_name]
                prior_present = server_name in old_servers
                prior_matches = not prior_present or _json_values_match(
                    record["prior"],
                    old_servers[server_name],
                )
                if record["prior_present"] != prior_present or not prior_matches:
                    raise MCPWriteUnsupportedError(
                        "Claude MCP ownership metadata has inconsistent managed prior state",
                    )
    return envelope


def _claude_mcp_envelope(
    path: str,
    *,
    committed: dict[str, Any] | None,
    pending: dict[str, Any] | None,
    released: set[str],
) -> dict[str, Any]:
    return {
        "schema": _CLAUDE_MCP_OWNERSHIP_SCHEMA,
        "path": os.path.abspath(path),
        "committed": committed,
        "pending": pending,
        "released": sorted(released),
    }


def _write_claude_private_metadata(
    path: str,
    payload: bytes,
    *,
    owner_path: str,
    expected_snapshot: Any = None,
) -> None:
    """CAS-publish private metadata below the already-held ancestor chain."""
    from defenseclaw.observability import v8_activation

    _assert_claude_mutation_guard()
    snapshot = v8_activation._snapshot_regular_file(path, required=False)
    if snapshot.existed:
        _validate_claude_private_file(
            path,
            label="ownership metadata",
            snapshot=snapshot,
        )
    guard = _CLAUDE_MUTATION_GUARD.get()
    is_ownership = guard is not None and os.path.normcase(os.path.abspath(path)) == os.path.normcase(
        guard["ownership_path"]
    )
    expected = guard["ownership_snapshot"] if is_ownership else expected_snapshot
    if expected is not None and not v8_activation._same_snapshot_identity(snapshot, expected):
        raise MCPWriteUnsupportedError(
            f"refusing Claude MCP mutation: private metadata changed before publication: {path}",
        )
    metadata = None
    if os.name == "nt" and not snapshot.existed:
        metadata = replace(
            snapshot,
            mode=0o600,
            windows_security=_claude_windows_private_file_security(owner_path, path),
        )
    try:
        published = _atomic_replace_claude_with_proof(
            snapshot,
            payload,
            default_mode=0o600,
            metadata=metadata,
        )
        _assert_claude_mutation_guard()
        observed = v8_activation._snapshot_regular_file(path, required=True)
        if observed.payload != payload or not v8_activation._same_snapshot_identity(
            observed,
            published,
        ):
            raise MCPWriteUnsupportedError(
                f"refusing Claude MCP mutation: private metadata was replaced after publication: {path}",
            )
        if is_ownership:
            guard["ownership_snapshot"] = published
    except MCPWriteUnsupportedError:
        raise
    except (OSError, v8_activation.V8ActivationError) as exc:
        raise MCPWriteUnsupportedError(
            f"refusing Claude MCP mutation: private metadata publication failed: {exc}",
        ) from exc


def _save_claude_mcp_envelope(path: str, envelope: dict[str, Any]) -> None:
    _write_claude_private_metadata(
        _claude_mcp_ownership_path(path),
        _render_json_bytes(envelope),
        owner_path=path,
    )


def _delete_private_regular_file(path: str, *, expected_snapshot: Any = None) -> bool:
    _assert_claude_mutation_guard()
    if not os.path.lexists(path):
        if expected_snapshot is not None and expected_snapshot.existed:
            raise MCPWriteUnsupportedError(
                f"refusing Claude MCP mutation: private metadata disappeared before deletion: {path}",
            )
        return False
    reject_reparse_path(path)
    if expected_snapshot is not None:
        from defenseclaw.observability import v8_activation

        current = v8_activation._snapshot_regular_file(path, required=True)
        if not v8_activation._same_snapshot_identity(current, expected_snapshot):
            raise MCPWriteUnsupportedError(
                f"refusing Claude MCP mutation: private metadata changed before deletion: {path}",
            )
        if os.name != "nt":
            parent = os.path.dirname(os.path.abspath(path)) or os.curdir
            parent_descriptor = v8_activation._open_pinned_parent(expected_snapshot)
            try:
                _assert_claude_mutation_guard()
                v8_activation._restore_absent_posix_target(
                    expected_snapshot,
                    parent_descriptor=parent_descriptor,
                    parent=parent,
                )
            finally:
                os.close(parent_descriptor)
            return True
        from defenseclaw import windows_acl

        descriptor = windows_acl.open_regular_mutation_fd(path)
        try:
            opened = v8_activation._snapshot_claimed_windows_file(path, descriptor)
            if not v8_activation._same_snapshot_identity(opened, expected_snapshot):
                raise MCPWriteUnsupportedError(
                    f"refusing Claude MCP mutation: private metadata changed while opening: {path}",
                )
            _assert_claude_mutation_guard()
            windows_acl.delete_regular_fd(descriptor)
        finally:
            os.close(descriptor)
        return True
    if os.name == "nt":
        from defenseclaw.windows_acl import delete_regular_file_by_handle

        return delete_regular_file_by_handle(path, missing_ok=True)
    delete_file_durable(path)
    return True


def _clear_claude_mcp_ownership(path: str) -> None:
    metadata_path = _claude_mcp_ownership_path(path)
    guard = _CLAUDE_MUTATION_GUARD.get()
    if guard is None or os.path.normcase(os.path.abspath(metadata_path)) != os.path.normcase(guard["ownership_path"]):
        raise MCPWriteUnsupportedError(
            "refusing Claude MCP mutation: ownership metadata clear is outside its lock",
        )
    expected = guard["ownership_snapshot"]
    _delete_private_regular_file(metadata_path, expected_snapshot=expected)
    from defenseclaw.observability import v8_activation

    guard["ownership_snapshot"] = v8_activation._snapshot_regular_file(
        metadata_path,
        required=False,
    )


def _directory_identity(path: str) -> tuple[int, int]:
    reject_reparse_path(path)
    info = os.stat(path, follow_symlinks=False)
    if not stat.S_ISDIR(info.st_mode):
        raise MCPWriteUnsupportedError(
            f"refusing Claude MCP mutation: settings parent is not a directory: {path}",
        )
    return info.st_dev, info.st_ino


def _directory_chain_identities(path: str) -> tuple[tuple[str, int, int], ...]:
    target = os.path.abspath(path)
    reject_reparse_path(target)
    current = target if os.path.isdir(target) else os.path.dirname(target) or os.curdir
    identities: list[tuple[str, int, int]] = []
    while True:
        info = os.stat(current, follow_symlinks=False)
        if not stat.S_ISDIR(info.st_mode):
            raise MCPWriteUnsupportedError(
                f"refusing Claude MCP mutation: ancestor is not a directory: {current}",
            )
        identities.append((os.path.normcase(os.path.abspath(current)), info.st_dev, info.st_ino))
        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent
    return tuple(reversed(identities))


def _prepare_claude_settings_parent(path: str) -> tuple[str, tuple[int, int]]:
    parent = os.path.abspath(os.path.dirname(path) or os.curdir)
    try:
        if os.path.lexists(parent):
            identity = _directory_identity(parent)
        else:
            from defenseclaw.file_permissions import _make_private_directories

            reject_reparse_path(parent)
            _make_private_directories(parent)
            identity = _directory_identity(parent)
            # Apply the public policy validation after the creation identity
            # is bound; any swap at this boundary is detected below.
            make_private_directory(parent)
            if _directory_identity(parent) != identity:
                raise MCPWriteUnsupportedError(
                    f"refusing Claude MCP mutation: settings parent changed during preparation: {parent}",
                )
    except OSError as exc:
        raise MCPWriteUnsupportedError(
            f"refusing Claude MCP mutation: settings parent changed during preparation: {parent}",
        ) from exc
    return parent, identity


def _claude_lock_identity(path: str) -> tuple[int, int, int]:
    info = os.lstat(path)
    if not stat.S_ISREG(info.st_mode):
        raise MCPWriteUnsupportedError(
            f"refusing Claude MCP mutation: lock is not a regular file: {path}",
        )
    return info.st_dev, info.st_ino, stat.S_IMODE(info.st_mode)


def _assert_claude_bound_lock(lock: dict[str, Any]) -> None:
    try:
        reject_reparse_path(lock["path"])
        if _claude_lock_identity(lock["path"]) != lock["identity"]:
            raise MCPWriteUnsupportedError(
                f"refusing Claude MCP mutation: lock changed while held: {lock['path']}",
            )
        _validate_claude_private_file(lock["path"], label=lock["label"])
    except OSError as exc:
        raise MCPWriteUnsupportedError(
            f"refusing Claude MCP mutation: lock changed while held: {lock['path']}",
        ) from exc


def _assert_claude_mutation_guard() -> None:
    guard = _CLAUDE_MUTATION_GUARD.get()
    if guard is None:
        return
    try:
        reject_reparse_path(guard["config_path"])
        if _directory_chain_identities(guard["config_path"]) != guard["config_chain"]:
            raise MCPWriteUnsupportedError(
                "refusing Claude MCP mutation: settings ancestor changed while locked",
            )
        if _directory_identity(guard["config_parent"]) != guard["config_parent_identity"]:
            raise MCPWriteUnsupportedError(
                f"refusing Claude MCP mutation: settings parent changed while locked: {guard['config_parent']}",
            )
        if _directory_identity(guard["metadata_dir"]) != guard["metadata_dir_identity"]:
            raise MCPWriteUnsupportedError(
                f"refusing Claude MCP mutation: metadata directory changed while locked: {guard['metadata_dir']}",
            )
        if _directory_chain_identities(guard["metadata_dir"]) != guard["metadata_chain"]:
            raise MCPWriteUnsupportedError(
                "refusing Claude MCP mutation: metadata ancestor changed while locked",
            )
    except OSError as exc:
        raise MCPWriteUnsupportedError(
            "refusing Claude MCP mutation: protected path changed while locked",
        ) from exc
    for lock in guard["bound_locks"]:
        _assert_claude_bound_lock(lock)


@contextmanager
def _locked_claude_file_update(path: str, *, label: str):
    """Hold and identity-bind one private sibling sentinel lock."""
    from defenseclaw import file_lock

    directory = os.path.dirname(path) or os.curdir
    make_private_directory(directory)
    lock_path = os.path.abspath(path + ".lock")
    if not os.path.lexists(lock_path):
        atomic_write_private_bytes(lock_path, b"")
    _validate_claude_private_file(lock_path, label=label)
    flags = os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(lock_path, flags)
    try:
        lock_file = os.fdopen(fd, "r+")
    except BaseException:
        os.close(fd)
        raise
    bound = None
    guard = None
    try:
        file_lock._lock_file_exclusive(lock_file, timeout_seconds=None)
        opened = os.fstat(lock_file.fileno())
        identity = _claude_lock_identity(lock_path)
        if identity[:2] != (opened.st_dev, opened.st_ino):
            raise MCPWriteUnsupportedError(
                f"refusing Claude MCP mutation: lock changed during acquisition: {lock_path}",
            )
        bound = {"path": lock_path, "identity": identity, "label": label}
        _assert_claude_bound_lock(bound)
        guard = _CLAUDE_MUTATION_GUARD.get()
        if guard is not None:
            guard["bound_locks"].append(bound)
        yield bound
        _assert_claude_bound_lock(bound)
    finally:
        if guard is not None and bound is not None and guard["bound_locks"][-1:] == [bound]:
            guard["bound_locks"].pop()
        file_lock._unlock_file(lock_file)
        lock_file.close()


@contextmanager
def _locked_claude_mcp_mutation(path: str):
    """Serialize DefenseClaw writers; native publication pins each parent."""
    config_parent, config_parent_identity = _prepare_claude_settings_parent(path)
    metadata_dir = _registry_dir()
    make_private_directory(metadata_dir)
    metadata_path = _claude_mcp_ownership_path(path)
    lock_path = metadata_path + ".lock"
    if not os.path.lexists(lock_path):
        atomic_write_private_bytes(lock_path, b"")
    _validate_claude_private_file(lock_path, label="ownership lock")
    with _locked_claude_file_update(
        metadata_path,
        label="ownership lock",
    ) as ownership_lock:
        from defenseclaw.observability import v8_activation

        if os.path.lexists(metadata_path):
            _validate_claude_private_file(metadata_path, label="ownership metadata")

        guard = {
            "config_path": os.path.abspath(path),
            "config_parent": config_parent,
            "config_parent_identity": config_parent_identity,
            "config_chain": _directory_chain_identities(path),
            "metadata_dir": os.path.abspath(metadata_dir),
            "metadata_dir_identity": _directory_identity(metadata_dir),
            "metadata_chain": _directory_chain_identities(metadata_dir),
            "bound_locks": [ownership_lock],
            "ownership_path": os.path.abspath(metadata_path),
            "ownership_snapshot": v8_activation._snapshot_regular_file(
                metadata_path,
                required=False,
            ),
        }
        token = _CLAUDE_MUTATION_GUARD.set(guard)
        try:
            yield
        finally:
            _CLAUDE_MUTATION_GUARD.reset(token)


def _json_values_match(left: Any, right: Any) -> bool:
    """Compare JSON values without Python's True-equals-one coercion."""
    try:
        return json.dumps(left, sort_keys=True, separators=(",", ":")) == json.dumps(
            right,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError):
        return False


def _reconcile_claude_managed_servers(
    state: dict[str, Any],
    data: dict[str, Any],
) -> bool:
    """Release ownership of server entries an operator has changed or removed."""
    managed = state["managed"]
    servers = data.get("mcpServers")
    released = False
    for server_name, record in list(managed.items()):
        if (
            not isinstance(servers, dict)
            or server_name not in servers
            or not _json_values_match(servers[server_name], record["owned"])
        ):
            del managed[server_name]
            released = True
    return released


def _load_claude_legacy_registry() -> tuple[dict[str, Any], Any]:
    from defenseclaw.observability import v8_activation

    path = _registry_path()
    snapshot = v8_activation._snapshot_regular_file(path, required=False)
    if not snapshot.existed:
        return {}, snapshot
    try:
        state = json.loads(snapshot.payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MCPWriteUnsupportedError(
            f"refusing Claude MCP mutation: legacy backup registry is corrupt: {path}",
        ) from exc
    if not isinstance(state, dict):
        raise MCPWriteUnsupportedError(
            f"refusing Claude MCP mutation: legacy backup registry is corrupt: {path}",
        )
    return state, snapshot


def _retire_claude_legacy_backup(path: str) -> None:
    """Make the old one-shot backup unable to restore after this episode."""
    abs_target = os.path.abspath(path)
    backup = os.path.abspath(_managed_mcp_backup_path(path))
    registry_path = _registry_path()
    # Lock order is always target ownership first, shared legacy registry
    # second. The snapshot CAS also protects against older unlocked writers.
    with _locked_claude_file_update(registry_path, label="legacy registry lock"):
        from defenseclaw.observability import v8_activation

        registry, registry_snapshot = _load_claude_legacy_registry()
        keys = _registry_matching_keys(registry, abs_target)
        for key in keys:
            entry = registry[key]
            if not isinstance(entry, dict):
                raise MCPWriteUnsupportedError(
                    f"refusing Claude MCP mutation: legacy backup registry for {path} is corrupt",
                )
            recorded_path = entry.get("path")
            recorded_backup = entry.get("backup")
            if (
                not isinstance(recorded_path, str)
                or not _registry_paths_match(recorded_path, abs_target)
                or not isinstance(recorded_backup, str)
                or (_registry_entry_is_retired(entry) and recorded_backup != "")
                or (not _registry_entry_is_retired(entry) and not _registry_paths_match(recorded_backup, backup))
            ):
                raise MCPWriteUnsupportedError(
                    f"refusing Claude MCP mutation: legacy backup registry for {path} points to an unexpected path",
                )
        for key in keys:
            registry.pop(key, None)
        registry[_registry_key(abs_target)] = _registry_retirement_record(abs_target)
        # Publish the durable suppression marker first. A crash from this
        # point onward can leave an inert backup, but restore will never
        # consume it as an unregistered legacy sibling.
        _write_claude_private_metadata(
            registry_path,
            _render_json_bytes(registry),
            owner_path=path,
            expected_snapshot=registry_snapshot,
        )
        backup_snapshot = v8_activation._snapshot_regular_file(
            backup,
            required=False,
        )
        _delete_private_regular_file(
            backup,
            expected_snapshot=backup_snapshot,
        )


def _finish_claude_mcp_episode(
    path: str,
    state: dict[str, Any] | None,
    released: set[str],
) -> dict[str, Any] | None:
    released = set(released)
    if state is None:
        # Pending metadata remains until both legacy restore surfaces are gone.
        _retire_claude_legacy_backup(path)
        if released:
            _save_claude_mcp_envelope(
                path,
                _claude_mcp_envelope(
                    path,
                    committed=None,
                    pending=None,
                    released=released,
                ),
            )
        else:
            _clear_claude_mcp_ownership(path)
        return None
    postimage = _required_bytes_from_b64(
        state["postimage_b64"],
        label="committed.postimage_b64",
    )
    from defenseclaw.observability import v8_activation

    snapshot = v8_activation._snapshot_regular_file(path, required=True)
    if snapshot.payload != postimage:
        raise MCPWriteUnsupportedError(
            "refusing Claude MCP mutation: settings no longer match the committed postimage",
        )
    observed_identity = _claude_postimage_identity_from_snapshot(snapshot)
    expected_identity = state.get("postimage_identity")
    # A state without the exact identity of the candidate DefenseClaw
    # published is ambiguous after a crash. Likewise, matching bytes on a
    # replacement inode belong to the external writer. In either case retain
    # the settings bytes but release all ownership instead of rebinding them.
    if not isinstance(expected_identity, dict) or observed_identity != expected_identity:
        released.update(state["managed"])
        _finish_claude_mcp_episode(path, None, released)
        return None
    _save_claude_mcp_envelope(
        path,
        _claude_mcp_envelope(
            path,
            committed=state,
            pending=None,
            released=released,
        ),
    )
    return copy.deepcopy(state)


def _recover_claude_mcp_transaction(
    path: str,
    envelope: dict[str, Any] | None,
) -> tuple[dict[str, Any] | None, set[str]]:
    if envelope is None:
        return None, set()
    committed = envelope["committed"]
    released = set(envelope["released"])
    pending = envelope.get("pending")
    if pending is None:
        if committed is None:
            _finish_claude_mcp_episode(path, None, released)
        return copy.deepcopy(committed), released

    old_config = _optional_bytes_from_b64(
        pending.get("old_config_b64"),
        label="pending.old_config_b64",
    )
    new_config = _optional_bytes_from_b64(
        pending.get("new_config_b64"),
        label="pending.new_config_b64",
    )
    next_state = pending["next_state"]
    next_released = set(pending["next_released"])
    current = _read_regular_bytes_if_present(path)
    if current == old_config and current == new_config:
        committed_matches = committed is not None and _claude_postimage_identity_matches(
            path,
            committed,
        )
        next_matches = next_state is not None and _claude_postimage_identity_matches(
            path,
            next_state,
        )
        if committed_matches != next_matches:
            selected = next_state if next_matches else committed
            selected_released = next_released if next_matches else released
            recovered = _finish_claude_mcp_episode(
                path,
                copy.deepcopy(selected),
                selected_released,
            )
            if selected is not None and recovered is None:
                raise MCPWriteUnsupportedError(
                    "refusing Claude MCP mutation: equal-byte pending ownership no longer matches the settings file",
                )
            return recovered, selected_released
        ambiguous_released = released | next_released
        if committed is not None:
            ambiguous_released.update(committed["managed"])
        if next_state is not None:
            ambiguous_released.update(next_state["managed"])
        _finish_claude_mcp_episode(path, None, ambiguous_released)
        raise MCPWriteUnsupportedError(
            "refusing Claude MCP mutation: equal-byte pending ownership is identity-ambiguous",
        )
    if current == old_config:
        recovered = _finish_claude_mcp_episode(
            path,
            copy.deepcopy(committed),
            released,
        )
        if committed is not None and recovered is None:
            raise MCPWriteUnsupportedError(
                "refusing Claude MCP mutation: pending ownership no longer matches the settings file",
            )
        return recovered, released
    if current == new_config:
        recovered = _finish_claude_mcp_episode(
            path,
            copy.deepcopy(next_state),
            next_released,
        )
        if next_state is not None and recovered is None:
            raise MCPWriteUnsupportedError(
                "refusing Claude MCP mutation: pending ownership no longer matches the settings file",
            )
        return recovered, next_released

    data = _parse_claude_settings(path, current)
    # Ambiguous bytes can never acquire next-only ownership. At most, retain
    # ownership that was already committed before the interrupted operation.
    chosen = copy.deepcopy(committed)
    chosen_released = set(released)
    if chosen is not None:
        chosen["exact_restore"] = False
        previously_managed = set(chosen["managed"])
        if not _claude_postimage_identity_matches(path, chosen):
            chosen_released.update(previously_managed)
            chosen = None
        elif _reconcile_claude_managed_servers(chosen, data):
            chosen_released.update(previously_managed - set(chosen["managed"]))
            chosen["exact_restore"] = False
    retained_names = set(chosen["managed"]) if chosen is not None else set()
    if next_state is not None:
        chosen_released.update(set(next_state["managed"]) - retained_names)
    if chosen is not None:
        if not chosen["managed"]:
            chosen = None
        else:
            if current is None:
                raise MCPWriteUnsupportedError("Claude MCP recovery lost its managed settings file")
            chosen["postimage_b64"] = _bytes_to_b64(current)
    return (
        _finish_claude_mcp_episode(path, chosen, chosen_released),
        chosen_released,
    )


def _cleanup_claude_posix_committed_entry(
    parent_descriptor: int,
    parent: str,
    displaced: Any,
    *,
    target_path: str,
    retained_path: str,
) -> None:
    from defenseclaw.observability import v8_activation

    try:
        v8_activation._restore_absent_posix_target(
            displaced,
            parent_descriptor=parent_descriptor,
            parent=parent,
        )
    except FileNotFoundError:
        return
    except BaseException:
        raise v8_activation.V8ActivationRollbackError(
            "rollback_incomplete",
            "post_commit_cleanup",
            target_path=target_path,
            backup_directory=retained_path,
        ) from None


def _publish_claude_posix_checked(
    expected: Any,
    candidate: Any,
    *,
    parent_descriptor: int,
    candidate_name: str,
) -> None:
    """Publish with exact-inode cleanup of every displaced entry."""
    from defenseclaw.observability import v8_activation

    parent = os.path.dirname(expected.path) or "."
    target_name = os.path.basename(expected.path)
    retained_path = os.path.join(parent, candidate_name)
    if not expected.existed:
        try:
            os.link(
                candidate_name,
                target_name,
                src_dir_fd=parent_descriptor,
                dst_dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        except OSError:
            raise v8_activation.V8ActivationError(
                "source_changed",
                "locked_publish_check",
                target_path=expected.path,
            ) from None
        try:
            v8_activation._assert_pinned_parent_public(expected, parent_descriptor)
            _assert_claude_mutation_guard()
            os.fsync(parent_descriptor)
        except BaseException:
            raise v8_activation.V8ActivationRollbackError(
                "rollback_incomplete",
                "publication_commit",
                target_path=expected.path,
                backup_directory=retained_path,
            ) from None
        _cleanup_claude_posix_committed_entry(
            parent_descriptor,
            parent,
            candidate,
            target_path=expected.path,
            retained_path=retained_path,
        )
        return

    current = v8_activation._snapshot_regular_file_at(
        parent_descriptor,
        parent,
        target_name,
        required=True,
    )
    if not v8_activation._same_snapshot_identity(current, expected):
        raise v8_activation.V8ActivationError(
            "source_changed",
            "locked_publish_check",
            target_path=expected.path,
        )
    v8_activation._exchange_entries(
        parent_descriptor,
        candidate_name,
        target_name,
        expected.path,
    )
    try:
        displaced = v8_activation._snapshot_regular_file_at(
            parent_descriptor,
            parent,
            candidate_name,
            required=True,
        )
        published = v8_activation._snapshot_regular_file_at(
            parent_descriptor,
            parent,
            target_name,
            required=True,
        )
    except BaseException:
        raise v8_activation.V8ActivationRollbackError(
            "rollback_incomplete",
            "locked_publish_check",
            target_path=expected.path,
            backup_directory=retained_path,
        ) from None
    if not v8_activation._same_snapshot_identity(
        displaced,
        expected,
    ) or not v8_activation._same_snapshot_identity(published, candidate):
        try:
            restored = v8_activation._restore_displaced_exchange(
                parent_descriptor,
                parent,
                candidate_name,
                target_name,
                candidate,
                displaced,
                expected.path,
            )
        except BaseException:
            restored = False
        if not restored:
            raise v8_activation.V8ActivationRollbackError(
                "rollback_incomplete",
                "locked_publish_check",
                target_path=expected.path,
                backup_directory=retained_path,
            )
        raise v8_activation.V8ActivationError(
            "source_changed",
            "locked_publish_check",
            target_path=expected.path,
        )
    try:
        v8_activation._assert_pinned_parent_public(expected, parent_descriptor)
        _assert_claude_mutation_guard()
    except BaseException:
        try:
            restored = v8_activation._restore_displaced_exchange(
                parent_descriptor,
                parent,
                candidate_name,
                target_name,
                candidate,
                displaced,
                expected.path,
            )
        except BaseException:
            restored = False
        if not restored:
            raise v8_activation.V8ActivationRollbackError(
                "rollback_incomplete",
                "locked_publish_check",
                target_path=expected.path,
                backup_directory=retained_path,
            ) from None
        raise
    try:
        os.fsync(parent_descriptor)
    except BaseException:
        raise v8_activation.V8ActivationRollbackError(
            "rollback_incomplete",
            "publication_commit",
            target_path=expected.path,
            backup_directory=retained_path,
        ) from None
    _cleanup_claude_posix_committed_entry(
        parent_descriptor,
        parent,
        displaced,
        target_path=expected.path,
        retained_path=retained_path,
    )


def _atomic_replace_claude_posix_with_proof(
    snapshot: Any,
    payload: bytes,
    *,
    default_mode: int,
    metadata: Any = None,
    before_publish: Any = None,
) -> Any:
    """Publish the exact staged POSIX inode and return its proven snapshot.

    This intentionally mirrors ``v8_activation._atomic_replace`` while
    retaining the staged snapshot that the pinned-parent CAS publishes.  A
    later path lookup cannot establish provenance because another writer may
    atomically install identical bytes between publication and that lookup.
    """
    from defenseclaw.observability import v8_activation

    metadata_source = snapshot if metadata is None else metadata
    if metadata_source.darwin_acl is not None or metadata_source.flags not in (None, 0):
        raise OSError(
            errno.ENOTSUP,
            "Claude MCP settings metadata cannot be represented by the POSIX publisher",
        )
    parent = os.path.dirname(snapshot.path) or "."
    parent_descriptor = v8_activation._open_pinned_parent(snapshot)
    descriptor, temporary_name = v8_activation._create_staged_file(
        parent_descriptor,
        os.path.basename(snapshot.path),
        "candidate",
    )
    candidate = None
    try:
        v8_activation._assert_descriptor_acl_representable(descriptor, snapshot.path)
        mode = metadata_source.mode if metadata_source.mode is not None else default_mode
        v8_activation._apply_descriptor_metadata(
            descriptor,
            mode,
            metadata_source.uid,
            metadata_source.gid,
            xattrs=metadata_source.xattrs,
        )
        handle = os.fdopen(descriptor, "wb")
        descriptor = -1
        with handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
            v8_activation._remove_unexpected_xattrs(
                handle.fileno(),
                frozenset(name for name, _value in metadata_source.xattrs),
            )
            os.fsync(handle.fileno())
        candidate = v8_activation._snapshot_regular_file_at(
            parent_descriptor,
            parent,
            temporary_name,
            required=True,
        )
        v8_activation._assert_staged_metadata(candidate, metadata_source, mode)
        published = replace(candidate, path=snapshot.path)
        if before_publish is not None:
            before_publish(published)
        _assert_claude_mutation_guard()
        reject_reparse_path(snapshot.path)
        try:
            _publish_claude_posix_checked(
                snapshot,
                candidate,
                parent_descriptor=parent_descriptor,
                candidate_name=temporary_name,
            )
        except v8_activation.V8ActivationRollbackError:
            # The retained name may now be authoritative recovery evidence.
            temporary_name = ""
            raise
        temporary_name = ""
        return published
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary_name and candidate is not None:
            try:
                v8_activation._restore_absent_posix_target(
                    candidate,
                    parent_descriptor=parent_descriptor,
                    parent=parent,
                )
            except FileNotFoundError:
                pass
        os.close(parent_descriptor)


def _atomic_replace_claude_windows_with_proof(
    snapshot: Any,
    payload: bytes,
    *,
    metadata: Any = None,
    before_publish: Any = None,
) -> Any:
    """Publish and return the exact Windows file object proven by v8."""
    from defenseclaw import windows_acl
    from defenseclaw.observability import v8_activation

    metadata_source = snapshot if metadata is None else metadata
    security = metadata_source.windows_security
    if security is None:
        raise OSError(errno.ENOTSUP, "Windows security metadata is unavailable")
    parent = os.path.dirname(snapshot.path) or "."
    # Keep native transient names compact.  The Win32 APIs below deliberately
    # operate on the already-validated parent and some supported Windows hosts
    # still enforce MAX_PATH for direct CreateFileW calls.  Repeating a long
    # ownership-metadata basename here can otherwise make CREATE_NEW report
    # ERROR_PATH_NOT_FOUND even though the private parent exists.  The random
    # transaction identifier retains the same create-if-absent collision
    # protection without weakening the bound-parent or reparse checks.
    transaction_id = uuid.uuid4().hex
    temporary_path = os.path.join(
        parent,
        f".dc-v8-c-{transaction_id}.tmp",
    )
    backup_path = os.path.join(
        parent,
        f".dc-v8-r-{transaction_id}.tmp",
    )
    discard_path = os.path.join(
        parent,
        f".dc-v8-d-{transaction_id}.tmp",
    )
    preserve_transients = False
    staged = None
    displaced = None
    try:
        staged_security = windows_acl.write_new_file(temporary_path, payload, security) or security.staging_copy()
        staged = v8_activation._snapshot_regular_file(temporary_path, required=True)
        v8_activation._assert_windows_staged_snapshot(staged, payload, staged_security)
        verification_staged = staged
        expected_security = security if snapshot.existed else staged_security
        expected = v8_activation._ExpectedFileState(
            existed=True,
            sha256=v8_activation._sha256(payload),
            mode=None,
            uid=None,
            gid=None,
            xattrs=(),
            allow_platform_xattrs=not snapshot.existed,
            windows_security=expected_security,
        )
        published = replace(
            staged,
            path=snapshot.path,
            windows_security=expected_security,
        )
        if before_publish is not None:
            before_publish(published)
        _assert_claude_mutation_guard()
        reject_reparse_path(snapshot.path)
        v8_activation._assert_snapshot_current(snapshot, "locked_publish_check")

        if snapshot.existed:
            preserve_transients = True
            original_descriptor = -1
            staged_descriptor = -1
            original_displaced = False
            try:
                # A path check followed by ReplaceFileW still permits an
                # uncooperative writer to change the target in the final
                # check-to-call gap.  Claim both exact files, verify those
                # claims after the complete-chain guard, and rename the
                # claimed descriptors.  The current parent lease cannot wrap
                # child renames because it intentionally denies delete
                # sharing; a future pinned-parent primitive must close the
                # remaining ancestor check-to-call gap.  The target claim
                # nevertheless denies writes and replacement until its exact
                # inode has been displaced.
                _assert_claude_mutation_guard()
                reject_reparse_path(snapshot.path)
                original_descriptor = v8_activation._claim_windows_file(
                    snapshot.path,
                    missing_ok=False,
                )
                claimed_original = v8_activation._snapshot_claimed_windows_file(
                    snapshot.path,
                    original_descriptor,
                )
                if not v8_activation._same_snapshot_identity(
                    claimed_original,
                    snapshot,
                ):
                    raise v8_activation.V8ActivationError(
                        "source_changed",
                        "locked_publish_check",
                        target_path=snapshot.path,
                    )
                staged_descriptor = windows_acl.open_regular_security_mutation_fd(
                    temporary_path,
                )
                claimed_staged = v8_activation._snapshot_claimed_windows_file(
                    temporary_path,
                    staged_descriptor,
                )
                if not v8_activation._same_snapshot_identity(claimed_staged, staged):
                    raise v8_activation.V8ActivationError(
                        "source_changed",
                        "locked_publish_check",
                        target_path=snapshot.path,
                    )
                _assert_claude_mutation_guard()
                reject_reparse_path(snapshot.path)
                windows_acl.move_regular_fd_no_replace(
                    original_descriptor,
                    backup_path,
                )
                original_displaced = True
                v8_activation._fsync_directory(parent)
                try:
                    windows_acl.move_regular_fd_no_replace(
                        staged_descriptor,
                        snapshot.path,
                    )
                    v8_activation._fsync_directory(parent)
                    verification_staged = v8_activation._snapshot_claimed_windows_file(
                        snapshot.path,
                        staged_descriptor,
                    )
                    verification_expected = replace(
                        expected,
                        windows_security=verification_staged.windows_security,
                    )
                    if (
                        not v8_activation._same_windows_publication_identity(
                            verification_staged,
                            staged,
                        )
                        or not v8_activation._same_windows_publication_metadata(
                            verification_staged,
                            staged,
                        )
                        or not v8_activation._matches_expected_state(
                            verification_staged,
                            verification_expected,
                        )
                        or verification_staged.windows_security != staged.windows_security
                    ):
                        raise v8_activation.V8ActivationError(
                            "source_changed",
                            "windows_publish_verification",
                            target_path=snapshot.path,
                        )
                    if verification_staged.windows_security != expected.windows_security:
                        assert expected.windows_security is not None
                        windows_acl.apply_fd(
                            staged_descriptor,
                            expected.windows_security,
                        )
                    verification_staged = v8_activation._snapshot_claimed_windows_file(
                        snapshot.path,
                        staged_descriptor,
                    )
                    if (
                        not v8_activation._same_windows_publication_identity(
                            verification_staged,
                            staged,
                        )
                        or not v8_activation._same_windows_publication_metadata(
                            verification_staged,
                            staged,
                        )
                        or not v8_activation._matches_expected_state(
                            verification_staged,
                            expected,
                        )
                    ):
                        raise v8_activation.V8ActivationError(
                            "source_changed",
                            "windows_publish_verification",
                            target_path=snapshot.path,
                        )
                    windows_acl.flush_fd(staged_descriptor)
                    verification_staged = v8_activation._snapshot_claimed_windows_file(
                        snapshot.path,
                        staged_descriptor,
                    )
                    if (
                        not v8_activation._same_windows_publication_identity(
                            verification_staged,
                            staged,
                        )
                        or not v8_activation._same_windows_publication_metadata(
                            verification_staged,
                            staged,
                        )
                        or not v8_activation._matches_expected_state(
                            verification_staged,
                            expected,
                        )
                    ):
                        raise v8_activation.V8ActivationError(
                            "source_changed",
                            "windows_publish_verification",
                            target_path=snapshot.path,
                        )
                except BaseException as publish_exc:
                    # The original is still claimed by this descriptor.
                    # Restore only by moving that exact inode into the
                    # known-absent target name; never reconstruct bytes.
                    try:
                        try:
                            published_candidate = v8_activation._snapshot_claimed_windows_file(
                                snapshot.path,
                                staged_descriptor,
                            )
                        except v8_activation.V8ActivationError:
                            published_candidate = None
                        if published_candidate is not None:
                            if not v8_activation._same_windows_publication_identity(
                                published_candidate,
                                claimed_staged,
                            ):
                                raise v8_activation.V8ActivationError(
                                    "source_changed",
                                    "windows_handle_publish",
                                    target_path=snapshot.path,
                                )
                            windows_acl.delete_regular_fd(staged_descriptor)
                            os.close(staged_descriptor)
                            staged_descriptor = -1
                            v8_activation._fsync_directory(parent)
                        windows_acl.move_regular_fd_no_replace(
                            original_descriptor,
                            snapshot.path,
                        )
                        original_displaced = False
                        v8_activation._fsync_directory(parent)
                    except BaseException:
                        raise v8_activation._windows_rollback_incomplete(
                            "windows_handle_publish",
                            snapshot.path,
                            backup_path,
                            temporary_path,
                            snapshot.path,
                        ) from publish_exc
                    preserve_transients = False
                    raise
            except v8_activation.V8ActivationRollbackError:
                raise
            except BaseException as exc:
                if original_displaced:
                    raise v8_activation._windows_rollback_incomplete(
                        "windows_handle_publish",
                        snapshot.path,
                        backup_path,
                        temporary_path,
                        snapshot.path,
                    ) from exc
                preserve_transients = False
                raise
            finally:
                if staged_descriptor >= 0:
                    os.close(staged_descriptor)
                if original_descriptor >= 0:
                    os.close(original_descriptor)
        else:
            preserve_transients = True
            try:
                windows_acl.move_file_no_replace(temporary_path, snapshot.path)
            except windows_acl.WindowsAclError:
                # If the staged source name still exists, the move did not
                # publish that inode. Any target now present belongs to an
                # external writer and must not be compared by content or
                # deleted. Only an ambiguously completed move (source gone)
                # is eligible for exact staged-identity rollback.
                if not os.path.lexists(temporary_path):
                    descriptor = v8_activation._claim_windows_file(
                        snapshot.path,
                        missing_ok=True,
                    )
                    if descriptor >= 0:
                        try:
                            live = v8_activation._snapshot_claimed_windows_file(
                                snapshot.path,
                                descriptor,
                            )
                            if (
                                v8_activation._same_windows_publication_identity(
                                    live,
                                    staged,
                                )
                                and v8_activation._same_windows_publication_metadata(
                                    live,
                                    staged,
                                )
                                and v8_activation._matches_expected_state(live, expected)
                            ):
                                windows_acl.delete_regular_fd(descriptor)
                                v8_activation._fsync_directory(parent)
                        finally:
                            os.close(descriptor)
                preserve_transients = False
                raise

        if snapshot.existed:
            displaced = v8_activation._snapshot_regular_file(backup_path, required=True)
            if not v8_activation._same_snapshot_identity(displaced, snapshot):
                raise v8_activation._windows_rollback_incomplete(
                    "locked_publish_check",
                    snapshot.path,
                    backup_path,
                    discard_path,
                    temporary_path,
                    snapshot.path,
                ) from None

        try:
            v8_activation._repair_and_verify_windows_publication(
                snapshot.path,
                verification_staged,
                expected,
            )
        except v8_activation._WindowsPublicationVerificationError:
            raise v8_activation._windows_rollback_incomplete(
                "windows_publish_verification",
                snapshot.path,
                snapshot.path,
                backup_path if snapshot.existed else "",
            ) from None
        except BaseException as exc:
            raise v8_activation._windows_rollback_incomplete(
                "windows_publish_verification",
                snapshot.path,
                backup_path if snapshot.existed else snapshot.path,
                temporary_path,
                discard_path,
            ) from exc

        if os.path.lexists(backup_path):
            if displaced is None:
                raise v8_activation._windows_rollback_incomplete(
                    "windows_backup_cleanup",
                    snapshot.path,
                    backup_path,
                )
            _delete_private_regular_file(
                backup_path,
                expected_snapshot=displaced,
            )
        preserve_transients = False
        v8_activation._fsync_directory(parent)
        return published
    finally:
        if not preserve_transients:
            for transient, expected_snapshot in (
                (temporary_path, staged),
                (backup_path, displaced),
            ):
                if os.path.lexists(transient) and expected_snapshot is not None:
                    _delete_private_regular_file(
                        transient,
                        expected_snapshot=expected_snapshot,
                    )


def _atomic_replace_claude_with_proof(
    snapshot: Any,
    payload: bytes,
    *,
    default_mode: int,
    metadata: Any = None,
    before_publish: Any = None,
) -> Any:
    if os.name == "nt":
        return _atomic_replace_claude_windows_with_proof(
            snapshot,
            payload,
            metadata=metadata,
            before_publish=before_publish,
        )
    return _atomic_replace_claude_posix_with_proof(
        snapshot,
        payload,
        default_mode=default_mode,
        metadata=metadata,
        before_publish=before_publish,
    )


def _publish_claude_config_if_unchanged(
    path: str,
    expected: bytes | None,
    replacement: bytes | None,
    *,
    candidate_prepared: Any = None,
    candidate_verified: Any = None,
) -> dict[str, Any] | None:
    """Publish through the identity-bound observability CAS primitive."""
    # Import lazily: connector discovery must remain cheap and independent of
    # the observability migration stack until a Claude settings write occurs.
    from defenseclaw.observability import v8_activation

    _assert_claude_mutation_guard()
    parent = os.path.dirname(os.path.abspath(path)) or os.curdir
    guard = _CLAUDE_MUTATION_GUARD.get()
    if guard is not None and (
        os.path.normcase(os.path.abspath(path)) == os.path.normcase(guard["config_path"])
        and _directory_identity(parent) != guard["config_parent_identity"]
    ):
        raise MCPWriteUnsupportedError(
            f"refusing Claude MCP mutation: settings parent changed before publication: {parent}",
        )
    if os.path.lexists(parent):
        reject_reparse_path(parent)
        if not os.path.isdir(parent):
            raise MCPWriteUnsupportedError(
                f"refusing Claude MCP mutation: settings parent is not a directory: {parent}",
            )
    else:
        make_private_directory(parent)

    try:
        snapshot = v8_activation._snapshot_regular_file(path, required=False)
        if snapshot.existed != (expected is not None) or (snapshot.existed and snapshot.payload != expected):
            raise MCPWriteUnsupportedError(
                f"refusing Claude MCP mutation: settings changed concurrently before publication: {path}",
            )

        published = None
        if replacement is None:
            if not snapshot.existed:
                return
            _delete_private_regular_file(
                path,
                expected_snapshot=snapshot,
            )
        else:
            metadata = None
            if os.name == "nt" and not snapshot.existed:
                metadata = replace(
                    snapshot,
                    mode=0o600,
                    windows_security=_claude_windows_private_file_security(path),
                )

            def bind_candidate(candidate):
                if candidate_prepared is not None:
                    candidate_prepared(
                        _claude_postimage_identity_from_snapshot(candidate),
                    )

            published = _atomic_replace_claude_with_proof(
                snapshot,
                replacement,
                default_mode=0o600,
                metadata=metadata,
                before_publish=bind_candidate,
            )

        observed = v8_activation._snapshot_regular_file(path, required=False)
        if observed.existed != (replacement is not None) or (observed.existed and observed.payload != replacement):
            raise MCPWriteUnsupportedError(
                f"Claude MCP settings changed concurrently during publication: {path}",
            )
        if replacement is not None and snapshot.existed and observed.windows_security != snapshot.windows_security:
            raise MCPWriteUnsupportedError(
                f"Claude MCP settings security changed during publication: {path}",
            )
        if replacement is None:
            return None
        if published is None or not v8_activation._same_snapshot_identity(observed, published):
            raise MCPWriteUnsupportedError(
                f"Claude MCP settings were replaced after publication: {path}",
            )
        # Rebind only after proving the public path still names the exact
        # staged file object with the expected bytes and security.  The
        # pre-publication journal remains the crash-safe fallback until this
        # callback durably records the observed public identity.
        observed_identity = _claude_postimage_identity_from_snapshot(observed)
        if candidate_verified is not None:
            candidate_verified(observed_identity)
        return observed_identity
    except MCPWriteUnsupportedError:
        raise
    except (OSError, v8_activation.V8ActivationError) as exc:
        raise MCPWriteUnsupportedError(
            f"refusing Claude MCP mutation: identity-bound settings publication failed: {exc}",
        ) from exc


def _finalize_claude_mcp_transaction(
    path: str,
    next_state: dict[str, Any] | None,
    next_released: set[str],
) -> None:
    committed = _finish_claude_mcp_episode(path, next_state, next_released)
    if next_state is not None and committed is None:
        raise MCPWriteUnsupportedError(
            "refusing Claude MCP mutation: published ownership no longer matches the settings file",
        )


def _apply_claude_mcp_transaction(
    path: str,
    *,
    expected: bytes | None,
    replacement: bytes | None,
    committed: dict[str, Any] | None,
    next_state: dict[str, Any] | None,
    released: set[str],
    next_released: set[str],
) -> None:
    pending = {
        "old_config_b64": _optional_bytes_to_b64(expected),
        "new_config_b64": _optional_bytes_to_b64(replacement),
        "next_state": copy.deepcopy(next_state),
        "next_released": sorted(next_released),
    }
    _save_claude_mcp_envelope(
        path,
        _claude_mcp_envelope(
            path,
            committed=copy.deepcopy(committed),
            pending=pending,
            released=released,
        ),
    )
    finalized_state = copy.deepcopy(next_state)
    verified_identity_persisted = False

    def persist_candidate_identity(candidate_identity):
        if finalized_state is None:
            raise MCPWriteUnsupportedError(
                "refusing Claude MCP mutation: candidate identity has no managed state",
            )
        finalized_state["postimage_identity"] = candidate_identity
        pending["next_state"] = copy.deepcopy(finalized_state)
        # Bind the staged candidate before it becomes public. Therefore either
        # crash boundary leaves a recoverable journal: old bytes select the
        # committed state, while new bytes must also match this exact inode.
        _save_claude_mcp_envelope(
            path,
            _claude_mcp_envelope(
                path,
                committed=copy.deepcopy(committed),
                pending=pending,
                released=released,
            ),
        )

    def persist_verified_identity(verified_identity):
        nonlocal verified_identity_persisted
        if finalized_state is None:
            raise MCPWriteUnsupportedError(
                "refusing Claude MCP mutation: verified identity has no managed state",
            )
        finalized_state["postimage_identity"] = verified_identity
        pending["next_state"] = copy.deepcopy(finalized_state)
        # This callback runs only after the publisher proves that the live
        # path still names the exact staged candidate.  A crash before this
        # write therefore retains the fail-closed pre-publication identity;
        # a crash afterward can recover from the observed public identity.
        _save_claude_mcp_envelope(
            path,
            _claude_mcp_envelope(
                path,
                committed=copy.deepcopy(committed),
                pending=pending,
                released=released,
            ),
        )
        verified_identity_persisted = True

    published_identity = _publish_claude_config_if_unchanged(
        path,
        expected,
        replacement,
        candidate_prepared=(persist_candidate_identity if finalized_state is not None else None),
        candidate_verified=(persist_verified_identity if finalized_state is not None else None),
    )
    if finalized_state is not None and (published_identity is None or not verified_identity_persisted):
        raise MCPWriteUnsupportedError(
            "refusing Claude MCP mutation: verified publication identity is unavailable",
        )
    _finalize_claude_mcp_transaction(path, finalized_state, next_released)


def _commit_claude_state_without_config(
    path: str,
    state: dict[str, Any] | None,
    raw: bytes | None,
    released: set[str],
) -> None:
    if state is None or not state["managed"]:
        _finish_claude_mcp_episode(path, None, released)
        return
    if raw is None:
        raise MCPWriteUnsupportedError("Claude MCP ownership state has no settings file")
    state["postimage_b64"] = _bytes_to_b64(raw)
    _finish_claude_mcp_episode(path, state, released)


def _set_claudecode_mcp_server(
    path: str,
    name: str,
    entry: dict[str, Any],
) -> None:
    with _locked_claude_mcp_mutation(path):
        state, released = _recover_claude_mcp_transaction(
            path,
            _load_claude_mcp_envelope(path),
        )
        raw = _read_regular_bytes_if_present(path)
        data = _parse_claude_settings(path, raw)

        if state is not None:
            postimage = _required_bytes_from_b64(
                state["postimage_b64"],
                label="committed.postimage_b64",
            )
            identity_matches = _claude_postimage_identity_matches(path, state)
            if raw != postimage or not identity_matches:
                state["exact_restore"] = False
            if not identity_matches:
                released.update(state["managed"])
                state["managed"].clear()
            else:
                previously_managed = set(state["managed"])
                if _reconcile_claude_managed_servers(state, data):
                    released.update(previously_managed - set(state["managed"]))
                    state["exact_restore"] = False
            if not state["managed"]:
                _finish_claude_mcp_episode(path, None, released)
                state = None
            elif raw is not None:
                state["postimage_b64"] = _bytes_to_b64(raw)

        if state is None:
            _retire_claude_legacy_backup(path)
            working = _new_claude_mcp_state(raw, data)
            committed = None
        else:
            working = state
            committed = copy.deepcopy(state)

        servers = data.get("mcpServers")
        if not isinstance(servers, dict):
            servers = {}
        next_state = copy.deepcopy(working)
        record = next_state["managed"].get(name)
        if not isinstance(record, dict):
            prior_present = name in servers
            record = {
                "prior_present": prior_present,
                "prior": servers.get(name) if prior_present else None,
                "owned": entry,
            }
            next_state["managed"][name] = record
        else:
            record["owned"] = entry
        servers[name] = entry
        data["mcpServers"] = servers

        replacement = _render_json_bytes(data)
        next_state["postimage_b64"] = _bytes_to_b64(replacement)
        next_state["postimage_identity"] = None
        next_released = set(released)
        next_released.discard(name)
        _apply_claude_mcp_transaction(
            path,
            expected=raw,
            replacement=replacement,
            committed=committed,
            next_state=next_state,
            released=released,
            next_released=next_released,
        )


def _restore_claude_server_prior(
    data: dict[str, Any],
    name: str,
    record: dict[str, Any],
) -> bool:
    servers = data.get("mcpServers")
    if not isinstance(servers, dict) or name not in servers or not _json_values_match(servers[name], record["owned"]):
        return False
    if record["prior_present"]:
        servers[name] = record.get("prior")
    else:
        del servers[name]
    data["mcpServers"] = servers
    return True


def _cleanup_claude_owned_container(data: dict[str, Any], state: dict[str, Any]) -> None:
    servers = data.get("mcpServers")
    if not isinstance(servers, dict) or servers:
        return
    if not state["container_preexisting"]:
        data.pop("mcpServers", None)
        return
    original = state.get("container_preimage")
    if not isinstance(original, dict):
        data["mcpServers"] = original


def _unset_claude_without_state(
    path: str,
    name: str,
    raw: bytes | None,
    data: dict[str, Any],
    released: set[str],
) -> bool:
    servers = data.get("mcpServers")
    if not isinstance(servers, dict) or name not in servers:
        return False
    _retire_claude_legacy_backup(path)
    del servers[name]
    data["mcpServers"] = servers
    _apply_claude_mcp_transaction(
        path,
        expected=raw,
        replacement=_render_json_bytes(data),
        committed=None,
        next_state=None,
        released=released,
        next_released=released,
    )
    return True


def _unset_claudecode_mcp_server(path: str, name: str) -> bool:
    with _locked_claude_mcp_mutation(path):
        state, released = _recover_claude_mcp_transaction(
            path,
            _load_claude_mcp_envelope(path),
        )
        raw = _read_regular_bytes_if_present(path)
        data = _parse_claude_settings(path, raw)
        if name in released:
            return False
        if state is None:
            return _unset_claude_without_state(path, name, raw, data, released)

        postimage = _required_bytes_from_b64(
            state["postimage_b64"],
            label="committed.postimage_b64",
        )
        identity_matches = _claude_postimage_identity_matches(path, state)
        bytes_match = raw == postimage and identity_matches
        if not bytes_match:
            state["exact_restore"] = False
        target_was_owned = name in state["managed"]
        if not identity_matches:
            released.update(state["managed"])
            state["managed"].clear()
        else:
            previously_managed = set(state["managed"])
            if _reconcile_claude_managed_servers(state, data):
                released.update(previously_managed - set(state["managed"]))
                state["exact_restore"] = False

        if not state["managed"]:
            _finish_claude_mcp_episode(path, None, released)
            if target_was_owned or name in released:
                return False
            return _unset_claude_without_state(path, name, raw, data, released)

        if raw is None:
            raise MCPWriteUnsupportedError("Claude MCP ownership state has no settings file")
        state["postimage_b64"] = _bytes_to_b64(raw)
        committed = copy.deepcopy(state)
        record = state["managed"].get(name)
        if record is not None and bytes_match and state["exact_restore"] and len(state["managed"]) == 1:
            next_released = set(released)
            if record["prior_present"]:
                next_released.add(name)
            replacement = (
                _required_bytes_from_b64(
                    state["preimage_b64"],
                    label="committed.preimage_b64",
                )
                if state["file_preexisting"]
                else None
            )
            _apply_claude_mcp_transaction(
                path,
                expected=raw,
                replacement=replacement,
                committed=committed,
                next_state=None,
                released=released,
                next_released=next_released,
            )
            return True

        next_state = copy.deepcopy(state)
        next_released = set(released)
        changed = False
        record = next_state["managed"].get(name)
        if record is not None:
            changed = _restore_claude_server_prior(data, name, record)
            if changed and record["prior_present"]:
                next_released.add(name)
            del next_state["managed"][name]
        elif not target_was_owned:
            servers = data.get("mcpServers")
            if isinstance(servers, dict) and name in servers:
                del servers[name]
                data["mcpServers"] = servers
                committed["exact_restore"] = False
                next_state["exact_restore"] = False
                changed = True

        if not changed:
            _commit_claude_state_without_config(path, next_state, raw, released)
            return False

        if not next_state["managed"]:
            _cleanup_claude_owned_container(data, next_state)
            final_state = None
        else:
            final_state = next_state
        replacement = _render_json_bytes(data)
        if final_state is not None:
            final_state["postimage_b64"] = _bytes_to_b64(replacement)
            final_state["postimage_identity"] = None
        _apply_claude_mcp_transaction(
            path,
            expected=raw,
            replacement=replacement,
            committed=committed,
            next_state=final_state,
            released=released,
            next_released=next_released,
        )
        return True


def _reject_symlink_config(path: str) -> None:
    """Refuse to read/merge through a symlinked connector config path.

    Workspace-scoped MCP configs (Codex ``.codex/config.toml``, Cursor
    ``.cursor/mcp.json``, Copilot ``.github/mcp.json``) live in an
    operator-chosen CWD. A malicious repository can pre-place that path
    as a symlink to a private file readable by the operator (``~/.netrc``,
    ``~/.aws/credentials``, etc.). A plain ``open(path)`` follows the
    link, so the merge reads the private target and the subsequent
    atomic rewrite leaks its contents into a repository-visible file.
    Fail closed before any read so the secret never crosses the
    workspace boundary (F-0041).
    """
    if os.path.islink(path):
        try:
            target = os.readlink(path)
        except OSError:
            target = "<unreadable>"
        raise ValueError(
            f"refusing to write MCP config {path}: path is a symlink -> "
            f"{target!r} (following it could disclose the link target)",
        )


def _atomic_json_merge(
    path: str,
    keys: tuple[str, ...],
    value: dict[str, Any],
) -> None:
    """Read *path* (or start from {}), set ``data[keys[0]][keys[1]]...
    = value``, then atomically replace *path* with the new content.

    Creates parent directory if missing. Permissions are forced to
    0o600 on every write — these files commonly contain API keys
    in the ``env`` block.
    """
    _reject_symlink_config(path)
    parent = os.path.dirname(path)
    if parent and not os.path.exists(parent):
        os.makedirs(parent, mode=0o700, exist_ok=True)
    _capture_managed_mcp_backup(path)
    data: dict[str, Any]
    try:
        with open(path) as f:
            loaded = json.load(f)
        data = loaded if isinstance(loaded, dict) else {}
    except (FileNotFoundError, json.JSONDecodeError):
        data = {}
    cursor = data
    for k in keys[:-1]:
        node = cursor.get(k)
        if not isinstance(node, dict):
            node = {}
            cursor[k] = node
        cursor = node
    cursor[keys[-1]] = value
    _atomic_write_json(path, data)


def _atomic_json_delete(
    path: str,
    keys: tuple[str, ...],
) -> bool:
    """Delete ``data[keys[0]][keys[1]]...`` from *path* and atomically
    rewrite. Returns True iff the key existed and was removed.

    Missing files / missing keys are no-ops returning False.
    """
    try:
        with open(path) as f:
            loaded = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return False
    if not isinstance(loaded, dict):
        return False
    cursor: Any = loaded
    for k in keys[:-1]:
        if not isinstance(cursor, dict) or k not in cursor:
            return False
        cursor = cursor[k]
    if not isinstance(cursor, dict) or keys[-1] not in cursor:
        return False
    del cursor[keys[-1]]
    _capture_managed_mcp_backup(path)
    _atomic_write_json(path, loaded)
    return True


def _atomic_yaml_merge(
    path: str,
    keys: tuple[str, ...],
    value: dict[str, Any],
) -> None:
    _reject_symlink_config(path)
    parent = os.path.dirname(path)
    if parent and not os.path.exists(parent):
        os.makedirs(parent, mode=0o700, exist_ok=True)
    _capture_managed_mcp_backup(path)
    try:
        with open(path) as f:
            loaded = yaml.safe_load(f) or {}
        data = loaded if isinstance(loaded, dict) else {}
    except (FileNotFoundError, yaml.YAMLError):
        data = {}
    cursor = data
    for k in keys[:-1]:
        node = cursor.get(k)
        if not isinstance(node, dict):
            node = {}
            cursor[k] = node
        cursor = node
    cursor[keys[-1]] = value
    _atomic_write_yaml(path, data)


def _atomic_yaml_delete(
    path: str,
    keys: tuple[str, ...],
) -> bool:
    try:
        with open(path) as f:
            loaded = yaml.safe_load(f) or {}
    except (FileNotFoundError, yaml.YAMLError):
        return False
    if not isinstance(loaded, dict):
        return False
    cursor: Any = loaded
    for k in keys[:-1]:
        if not isinstance(cursor, dict) or k not in cursor:
            return False
        cursor = cursor[k]
    if not isinstance(cursor, dict) or keys[-1] not in cursor:
        return False
    del cursor[keys[-1]]
    _capture_managed_mcp_backup(path)
    _atomic_write_yaml(path, loaded)
    return True


def restore_managed_mcp_backup(path: str) -> bool:
    """Restore the one-shot DefenseClaw backup for *path* if present.

    Looks first for the registry-recorded backup under
    ``$DEFENSECLAW_HOME/connector_backups/mcp/`` (which records the
    absolute target path so workspace-scoped restores survive a
    ``cd``); falls back to the legacy sibling ``.bak`` file for
    backwards compatibility with existing installs.
    """
    abs_path = os.path.abspath(path)
    ownership_path = _claude_mcp_ownership_path(abs_path)
    with _locked_claude_mcp_mutation(abs_path):
        if os.path.lexists(ownership_path):
            raise MCPWriteUnsupportedError(
                "refusing legacy MCP backup restore while an ownership-aware "
                f"Claude MCP transaction is active for {path}",
            )
        registry_path = _registry_path()
        with _locked_claude_file_update(registry_path, label="legacy registry lock"):
            registry, registry_snapshot = _load_claude_legacy_registry()
            keys = _registry_matching_keys(registry, abs_path)
            retired_keys = [key for key in keys if _registry_entry_is_retired(registry[key])]
            if retired_keys:
                if len(retired_keys) != len(keys):
                    raise MCPWriteUnsupportedError(
                        f"refusing legacy MCP backup restore: registry aliases for {path} disagree",
                    )
                for key in retired_keys:
                    entry = registry[key]
                    if (
                        not isinstance(entry.get("path"), str)
                        or not _registry_paths_match(entry["path"], abs_path)
                        or entry.get("backup") != ""
                    ):
                        raise MCPWriteUnsupportedError(
                            f"refusing legacy MCP backup restore: retirement marker for {path} is corrupt",
                        )
                return False
            registry_backup: str | None = None
            for key in keys:
                entry = registry[key]
                if not isinstance(entry, dict):
                    raise MCPWriteUnsupportedError(
                        f"refusing legacy MCP backup restore: registry entry for {path} is corrupt",
                    )
                recorded_path = entry.get("path")
                recorded_backup = entry.get("backup")
                if not isinstance(recorded_path, str) or not _registry_paths_match(recorded_path, abs_path):
                    raise MCPWriteUnsupportedError(
                        f"refusing legacy MCP backup restore: registry entry for {path} targets another file",
                    )
                if not isinstance(recorded_backup, str):
                    raise MCPWriteUnsupportedError(
                        f"refusing legacy MCP backup restore: registry backup for {path} is corrupt",
                    )
                candidate = os.path.abspath(recorded_backup)
                if registry_backup is not None and not _registry_paths_match(candidate, registry_backup):
                    raise MCPWriteUnsupportedError(
                        f"refusing legacy MCP backup restore: registry aliases for {path} disagree",
                    )
                registry_backup = candidate
            if registry_backup is not None and os.path.lexists(registry_backup):
                _reject_symlink_config(registry_backup)
                reject_reparse_path(registry_backup)
                if os.path.lexists(ownership_path):
                    raise MCPWriteUnsupportedError(
                        "refusing legacy MCP backup restore while an ownership-aware "
                        f"Claude MCP transaction is active for {path}",
                    )
                for key in keys:
                    registry.pop(key, None)
                registry[_registry_key(abs_path)] = _registry_retirement_record(abs_path)
                _write_claude_private_metadata(
                    registry_path,
                    _render_json_bytes(registry),
                    owner_path=abs_path,
                    expected_snapshot=registry_snapshot,
                )
                os.replace(registry_backup, abs_path)
                return True

            backup = os.path.abspath(_managed_mcp_backup_path(abs_path))
            if not os.path.lexists(backup):
                return False
            _reject_symlink_config(backup)
            reject_reparse_path(backup)
            if os.path.lexists(ownership_path):
                raise MCPWriteUnsupportedError(
                    "refusing legacy MCP backup restore while an ownership-aware "
                    f"Claude MCP transaction is active for {path}",
                )
            registry[_registry_key(abs_path)] = _registry_retirement_record(abs_path)
            _write_claude_private_metadata(
                registry_path,
                _render_json_bytes(registry),
                owner_path=abs_path,
                expected_snapshot=registry_snapshot,
            )
            os.replace(backup, abs_path)
            return True


def _capture_managed_mcp_backup(path: str) -> None:
    # workspace-scoped MCP configs (Codex .codex/config.toml,
    # Cursor .cursor/mcp.json, Copilot .github/mcp.json) live in a
    # CWD chosen by the operator. A malicious repository can pre-place
    # those config paths as symlinks to private files readable by the
    # operator (e.g. ~/.ssh/id_rsa, ~/.netrc, ~/.aws/credentials).
    # `os.path.isfile` and `shutil.copy2` BOTH follow symlinks, so the
    # private link target was being copied into a workspace-visible
    # `.defenseclaw-<name>.bak` sibling and registered for restore.
    #
    # We refuse to back up via a symlink: if the path is a symlink we
    # skip backup entirely (callers tolerate "no backup" — restore
    # only runs when a backup is present), and we use os.lstat /
    # follow_symlinks=False to keep the fix robust on mixed Linux/macOS.
    try:
        st = os.lstat(path)
    except (FileNotFoundError, OSError):
        return
    if stat.S_ISLNK(st.st_mode):
        # Hard fail-closed: refuse to follow the symlink, and log so the
        # operator sees why no .bak was written.
        try:
            target = os.readlink(path)
        except OSError:
            target = "<unreadable>"
        sys.stderr.write(f"[defenseclaw] refusing to back up MCP config: {path} is a symlink -> {target!r}\n")
        return
    if not stat.S_ISREG(st.st_mode):
        return
    backup = _managed_mcp_backup_path(path)
    abs_target = os.path.abspath(path)
    registry_path = _registry_path()
    with _locked_claude_mcp_mutation(abs_target):
        with _locked_claude_file_update(registry_path, label="legacy registry lock"):
            registry, _registry_snapshot = _load_claude_legacy_registry()
            matching = _registry_matching_keys(registry, abs_target)
            retired = [key for key in matching if _registry_entry_is_retired(registry[key])]
            if retired and len(retired) != len(matching):
                raise MCPWriteUnsupportedError(
                    f"refusing MCP backup capture: registry aliases for {path} disagree",
                )
            if os.path.lexists(backup):
                if retired:
                    # Never adopt a sibling that appeared after retirement.
                    # A fresh capture may clear the tombstone only after it
                    # creates and proves a new backup itself.
                    return
                _reject_symlink_config(backup)
                reject_reparse_path(backup)
                _registry_register_locked(abs_target, backup)
                return
            # Hold the target lock and shared legacy lock across backup
            # creation and registry publication so retirement cannot be
            # followed by a stale backup reappearing from an older episode.
            from defenseclaw.observability import v8_activation

            backup_snapshot = v8_activation._snapshot_regular_file(
                backup,
                required=False,
            )
            fd = open_regular_file_no_follow(path)
            with os.fdopen(fd, "rb") as source:
                _write_claude_private_metadata(
                    backup,
                    source.read(),
                    owner_path=abs_target,
                    expected_snapshot=backup_snapshot,
                )
            _registry_register_locked(abs_target, backup)


def _managed_mcp_backup_path(path: str) -> str:
    parent = os.path.dirname(path) or "."
    basename = os.path.basename(path).lstrip(".") or "config"
    return os.path.join(parent, f".defenseclaw-{basename}.bak")


# ---------------------------------------------------------------------------
# MCP backup registry — workspace-cwd-independent restore (S5.2 / C-2)
# ---------------------------------------------------------------------------
#
# The historical ``.defenseclaw-<name>.bak`` sibling-file scheme works
# fine for user-scope configs (``~/.claude.json``) because the
# absolute path is stable. It breaks for explicitly pinned workspace configs
# (for example Copilot's ``<workspace>/.github/mcp.json``) because the .bak
# is anchored to the target directory; restoring after a ``cd`` used to lose
# track of the original file.
#
# The registry below is a single JSON file under
# ``$DEFENSECLAW_HOME/connector_backups/mcp/registry.json`` that maps
# the SHA-256 of the absolute target path -> {"path": <abs target>,
# "backup": <abs sibling .bak>, "ts": <utc>}. ``restore_by_id`` and
# ``restore_managed_mcp_backup`` look here first, ensuring restore is
# anchored to the original target regardless of cwd.


def _registry_dir() -> str:
    """Return the absolute MCP backup registry directory.

    Created lazily with mode 0o700 because the registry leaks the
    file paths of every config DefenseClaw has touched.
    """
    home = os.environ.get("DEFENSECLAW_HOME", "").strip()
    if not home:
        home = str(Path.home() / ".defenseclaw")
    return os.path.join(home, "connector_backups", "mcp")


def _registry_path() -> str:
    return os.path.join(_registry_dir(), "registry.json")


def _registry_load() -> dict[str, dict[str, str]]:
    path = _registry_path()
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}
    if not isinstance(data, dict):
        return {}
    out: dict[str, dict[str, str]] = {}
    for k, v in data.items():
        if isinstance(k, str) and isinstance(v, dict):
            out[k] = {kk: str(vv) for kk, vv in v.items() if isinstance(kk, str)}
    return out


def _registry_save(state: dict[str, dict[str, str]]) -> None:
    path = _registry_path()
    payload = json.dumps(state, indent=2, sort_keys=True) + "\n"
    atomic_write_private_bytes(path, payload.encode("utf-8"))


def _registry_key(abs_target: str) -> str:
    """Stable identifier for *abs_target* used as the registry key.

    SHA-256 of the absolute path. We use a hash (not the path itself)
    because some operators consider the on-disk filename of a workspace
    as sensitive; the original is still recorded in the value as
    ``path`` so legitimate restore flows can echo it back to the user.
    """
    import hashlib

    return hashlib.sha256(_registry_normalized_path(abs_target).encode("utf-8")).hexdigest()


def _registry_normalized_path(path: str) -> str:
    absolute = os.path.abspath(path)
    if os.name == "nt":
        return ntpath.normcase(ntpath.abspath(absolute))
    return absolute


def _registry_paths_match(left: str, right: str) -> bool:
    return _registry_normalized_path(left) == _registry_normalized_path(right)


def _registry_matching_keys(state: dict[str, Any], abs_target: str) -> list[str]:
    """Return primary and legacy raw-path hashes for one target identity."""
    primary = _registry_key(abs_target)
    matching: list[str] = []
    if primary in state:
        matching.append(primary)
    for key, entry in state.items():
        if key in matching or not isinstance(entry, dict):
            continue
        recorded = entry.get("path")
        if isinstance(recorded, str) and _registry_paths_match(recorded, abs_target):
            matching.append(key)
    return matching


def _registry_entry_is_retired(entry: Any) -> bool:
    return isinstance(entry, dict) and entry.get("retired") is True


def _registry_retirement_record(abs_target: str) -> dict[str, Any]:
    import datetime as _dt

    return {
        "path": os.path.abspath(abs_target),
        "backup": "",
        "retired": True,
        "ts": _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


def _registry_register_locked(abs_target: str, backup: str) -> None:
    import datetime as _dt

    state, snapshot = _load_claude_legacy_registry()
    for alias in _registry_matching_keys(state, abs_target):
        state.pop(alias, None)
    state[_registry_key(abs_target)] = {
        "path": abs_target,
        "backup": os.path.abspath(backup),
        "ts": _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    _write_claude_private_metadata(
        _registry_path(),
        _render_json_bytes(state),
        owner_path=abs_target,
        expected_snapshot=snapshot,
    )


def _registry_register(abs_target: str, backup: str) -> None:
    with _locked_claude_mcp_mutation(abs_target):
        with _locked_claude_file_update(_registry_path(), label="legacy registry lock"):
            _registry_register_locked(abs_target, backup)


def _registry_clear(abs_target: str) -> None:
    with _locked_claude_mcp_mutation(abs_target):
        with _locked_claude_file_update(_registry_path(), label="legacy registry lock"):
            state, snapshot = _load_claude_legacy_registry()
            keys = _registry_matching_keys(state, abs_target)
            if not keys:
                return
            for key in keys:
                state.pop(key, None)
            _write_claude_private_metadata(
                _registry_path(),
                _render_json_bytes(state),
                owner_path=abs_target,
                expected_snapshot=snapshot,
            )


def _registry_backup_for(abs_target: str) -> str | None:
    with _locked_claude_file_update(_registry_path(), label="legacy registry lock"):
        state, _snapshot = _load_claude_legacy_registry()
        keys = _registry_matching_keys(state, abs_target)
        if not keys:
            return None
        entry = state[keys[0]]
        if not isinstance(entry, dict):
            return None
        if _registry_entry_is_retired(entry):
            return None
        backup = entry.get("backup", "")
        return backup if isinstance(backup, str) and backup else None


def lookup_managed_mcp_backup(path: str) -> str | None:
    """Return the absolute backup path for *path* if recorded.

    Public lookup helper for tests and for tooling that needs to surface
    the recorded backup location without performing a restore.
    """
    return _registry_backup_for(os.path.abspath(path))


def _atomic_write_yaml(path: str, data: dict[str, Any]) -> None:
    payload = yaml.safe_dump(data, default_flow_style=False, sort_keys=False)
    atomic_write_private_bytes(path, payload.encode("utf-8"))


def _atomic_write_text(path: str, text: str) -> None:
    """Atomically write UTF-8 text with private permissions."""
    atomic_write_private_bytes(path, text.encode("utf-8"))


def _windsurf_existing_mcp_write_path() -> str | None:
    for path in _windsurf_mcp_paths():
        if os.path.isfile(path):
            return path
    return None


def _atomic_write_json(path: str, data: dict[str, Any]) -> None:
    """Write *data* to *path* atomically with 0o600 permissions.

    Uses tempfile in the same directory + ``os.replace`` so a crash
    never leaves a half-written file. Mirrors the Go gateway's
    atomicWriteFile contract for connector config patches.
    """
    payload = json.dumps(data, indent=2, sort_keys=True) + "\n"
    atomic_write_private_bytes(path, payload.encode("utf-8"))
