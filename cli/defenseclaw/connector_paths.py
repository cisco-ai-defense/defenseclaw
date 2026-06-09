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
* :func:`skill_dirs` / :func:`plugin_dirs` / :func:`mcp_servers` —
  polymorphic dispatchers; pass a connector name and they return the
  paths or MCP entries for that connector.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

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
)
"""Allow-list of recognized agent-framework connector names.

Anything outside this set is treated as "unknown — fall back to
OpenClaw". Keeping the list explicit (rather than discovering at
import time) means a typo in ``guardrail.connector`` surfaces in
:func:`is_known` and in setup-time validation, instead of silently
producing wrong paths.
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
    ``.mcp.json``, ZeptoClaw's ``config.json``, OpenClaw's
    ``openclaw.json``). Optional fields default to empty so callers
    can treat the struct uniformly.
    """

    name: str = ""
    command: str = ""
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    url: str = ""
    transport: str = ""


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
        return os.path.join(home, ".claude")
    if name == "codex":
        return os.path.join(home, ".codex")
    if name == "zeptoclaw":
        return os.environ.get("ZEPTOCLAW_HOME") or os.path.join(home, ".zeptoclaw")
    if name == "geminicli":
        return os.path.join(home, ".gemini")
    if name == "copilot":
        return os.path.join(home, ".copilot")
    if name == "openhands":
        root = _workspace_dir(workspace_dir)
        if root:
            return os.path.join(root, ".openhands")
        return os.path.join(home, ".openhands")
    if name == "antigravity":
        # Antigravity (`agy`) is global-only by design: agy v1.0.x
        # merges every discovered hooks.json (global, project,
        # legacy ~/.gemini/hooks.json), so DefenseClaw deliberately
        # does NOT honor workspace_dir — multiple writes cause
        # duplicate firings.
        #
        # NOTE: agy *advertises* ~/.gemini/antigravity-cli/ in its
        # --help output, but empirically it reads PreToolUse hooks
        # only from ~/.gemini/config/hooks.json (see
        # internal/gateway/connector/hook_only.go ::
        # antigravityHooksPath for the smoke-test evidence). We
        # report the marketing-facing dir here as the "connector
        # home" because it's the agy-owned directory operators
        # know about; the actual hooks file path comes back via
        # connector_config_files() below, which points at the
        # path agy actually evaluates.
        return os.path.join(home, ".gemini", "antigravity-cli")
    if name == "cursor":
        return os.path.join(home, ".cursor")
    if name == "windsurf":
        return os.path.join(home, ".codeium", "windsurf")
    if name == "hermes":
        return os.path.join(home, ".hermes")
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
        paths = [
            os.path.join(home, ".claude", "settings.json"),
            _workspace_path(workspace_dir, ".claude", "settings.json"),
        ]
    elif name == "codex":
        paths = [
            os.path.join(home, ".codex", "config.toml"),
            _workspace_path(workspace_dir, ".mcp.json"),
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
        paths = [
            os.path.join(home, ".copilot", "config.json"),
            os.path.join(home, ".copilot", "hooks", "defenseclaw.json"),
            _workspace_path(workspace_dir, ".github", "copilot.json"),
            _workspace_path(workspace_dir, ".github", "hooks", "defenseclaw.json"),
        ]
    elif name == "openhands":
        paths = [
            os.path.join(home, ".openhands", "hooks.json"),
            os.path.join(home, ".openhands", "mcp.json"),
            _workspace_path(workspace_dir, ".openhands", "hooks.json"),
        ]
    elif name == "antigravity":
        # Global only — agy merges hooks files from all discovered
        # locations, so listing the workspace path here would
        # mislead operators into thinking DefenseClaw might patch it.
        #
        # The canonical path is ~/.gemini/config/hooks.json — that
        # is the only path agy v1.0.x actually evaluates at
        # runtime, even though `agy --help` still advertises
        # ~/.gemini/antigravity-cli/ as the install location. The
        # legacy path is also listed (best-effort) so doctor /
        # inventory can surface stale defenseclaw-managed entries
        # left behind from pre-v0.5.0 installs that wrote to the
        # wrong file.
        paths = [
            os.path.join(home, ".gemini", "config", "hooks.json"),
            os.path.join(home, ".gemini", "antigravity-cli", "hooks.json"),
        ]
    elif name == "opencode":
        # opencode auto-loads plugins from ~/.config/opencode/plugins/;
        # DefenseClaw installs a single bridge plugin there. There is no
        # command-hook config file to patch.
        paths = [
            os.path.join(home, ".config", "opencode", "plugins", "defenseclaw.js"),
        ]
    elif name == "cursor":
        paths = [
            os.path.join(home, ".cursor", "mcp.json"),
            _workspace_path(workspace_dir, ".cursor", "mcp.json"),
        ]
    elif name == "windsurf":
        paths = list(_windsurf_mcp_paths(home))
    elif name == "hermes":
        paths = [
            os.path.join(home, ".hermes", "config.json"),
            _workspace_path(workspace_dir, ".hermes", "config.json"),
        ]
    elif name == "openclaw":
        if openclaw_config:
            paths = [_expand(openclaw_config)]
        else:
            paths = [os.path.join(home, ".openclaw", "openclaw.json")]
    return _dedup(paths)


def skill_dirs(
    connector: str | None,
    *,
    openclaw_home: str | None = None,
    openclaw_config: str | None = None,
    workspace_dir: str | None = None,
) -> list[str]:
    """Return the skill directory list for *connector*.

    For Claude Code / Codex / ZeptoClaw the layout is fixed
    (``$HOME/.<framework>/skills`` plus the project-local
    ``./.<framework>/skills``). For OpenClaw — and any unknown
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
    if name == "zeptoclaw":
        return _zeptoclaw_skill_dirs(workspace_dir)
    if name == "hermes":
        return _hermes_skill_dirs()
    if name == "cursor":
        return _cursor_skill_dirs(workspace_dir)
    if name == "windsurf":
        return _windsurf_skill_dirs()
    if name == "geminicli":
        return _gemini_skill_dirs(workspace_dir)
    if name == "copilot":
        return _copilot_skill_dirs(workspace_dir)
    if name == "openhands":
        return _openhands_skill_dirs(workspace_dir)
    if name == "antigravity":
        # Antigravity v1 publishes only the hooks surface; no
        # documented skills install/discovery path yet.
        return []
    return _openclaw_skill_dirs(openclaw_home, openclaw_config)


def plugin_dirs(
    connector: str | None,
    *,
    openclaw_home: str | None = None,
    workspace_dir: str | None = None,
) -> list[str]:
    """Return the plugin (extension) directory list for *connector*.

    Uses each framework's documented plugin location:

    * Claude Code: ``~/.claude/plugins`` and ``./.claude/plugins``
    * Codex:       ``~/.codex/plugins`` (+ ``cache`` subdir)
    * ZeptoClaw:   ``~/.zeptoclaw/plugins`` (+ ``cache`` subdir)
    * OpenClaw:    ``<home_dir>/extensions``
    """
    name = normalize(connector)
    if name == "claudecode":
        return _claudecode_plugin_dirs(workspace_dir)
    if name == "codex":
        return _codex_plugin_dirs()
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
        return []
    return _openclaw_plugin_dirs(openclaw_home)


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

    * Claude Code: ``~/.claude/settings.json`` then explicit workspace ``.mcp.json``
    * Codex:       ``~/.codex/config.toml`` then explicit workspace ``.mcp.json``
    * ZeptoClaw:   ``~/.zeptoclaw/config.json`` then explicit workspace ``.mcp.json``
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
        # Antigravity does not expose a documented MCP install
        # surface; nothing to discover.
        return []
    return _openclaw_mcp_servers(
        openclaw_config,
        openclaw_bin_resolver=openclaw_bin_resolver,
        openclaw_cmd_prefix=openclaw_cmd_prefix,
    )


# ---------------------------------------------------------------------------
# Per-connector implementations
# ---------------------------------------------------------------------------


def _claudecode_skill_dirs(workspace_dir: str | None = None) -> list[str]:
    home = str(Path.home())
    return _dedup(
        [
            os.path.join(home, ".claude", "skills"),
            _workspace_path(workspace_dir, ".claude", "skills"),
        ]
    )


def _codex_skill_dirs(workspace_dir: str | None = None) -> list[str]:
    home = str(Path.home())
    return _dedup(
        [
            os.path.join(home, ".codex", "skills"),
            _workspace_path(workspace_dir, ".codex", "skills"),
        ]
    )


def _zeptoclaw_skill_dirs(workspace_dir: str | None = None) -> list[str]:
    zepto_home = os.environ.get("ZEPTOCLAW_HOME") or os.path.join(str(Path.home()), ".zeptoclaw")
    return _dedup(
        [
            os.path.join(zepto_home, "skills"),
            _workspace_path(workspace_dir, ".zeptoclaw", "skills"),
        ]
    )


def _hermes_skill_dirs() -> list[str]:
    return [os.path.join(str(Path.home()), ".hermes", "skills")]


def _cursor_skill_dirs(workspace_dir: str | None = None) -> list[str]:
    home = str(Path.home())
    return _dedup(
        [
            os.path.join(home, ".cursor", "skills"),
            os.path.join(home, ".agents", "skills"),
            _workspace_path(workspace_dir, ".cursor", "skills"),
            _workspace_path(workspace_dir, ".agents", "skills"),
        ]
    )


def _windsurf_skill_dirs() -> list[str]:
    return []


def _gemini_skill_dirs(workspace_dir: str | None = None) -> list[str]:
    return _dedup(
        [
            os.path.join(str(Path.home()), ".gemini", "skills"),
            _workspace_path(workspace_dir, ".gemini", "skills"),
            _workspace_path(workspace_dir, ".agents", "skills"),
        ]
    )


def _copilot_skill_dirs(workspace_dir: str | None = None) -> list[str]:
    home = str(Path.home())
    return _dedup(
        [
            os.path.join(home, ".copilot", "skills"),
            _workspace_path(workspace_dir, ".github", "skills"),
            _workspace_path(workspace_dir, ".agents", "skills"),
        ]
    )


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
    home = str(Path.home())
    return _dedup(
        [
            os.path.join(home, ".claude", "plugins"),
            _workspace_path(workspace_dir, ".claude", "plugins"),
        ]
    )


def _codex_plugin_dirs() -> list[str]:
    home = str(Path.home())
    base = os.path.join(home, ".codex", "plugins")
    return _dedup(
        [
            base,
            os.path.join(base, "cache"),
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
    home = str(Path.home())
    return _dedup(
        [
            os.path.join(home, ".hermes", "plugins"),
            _workspace_path(workspace_dir, ".hermes", "plugins"),
        ]
    )


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
    home = str(Path.home())
    entries: list[MCPServerEntry] = []
    entries.extend(
        _read_mcp_settings_block(
            os.path.join(home, ".claude", "settings.json"),
            keys=("mcpServers",),
        )
    )
    project_mcp = _workspace_path(workspace_dir, ".mcp.json")
    if project_mcp:
        entries.extend(_read_dotmcp_json(project_mcp))
    return _dedup_mcp_entries(entries)


def _codex_mcp_servers(workspace_dir: str | None = None) -> list[MCPServerEntry]:
    """Return the merged Codex MCP server list.

    Codex stores its global MCP server registry in
    ``~/.codex/config.toml`` under the ``[mcp_servers]`` table, and
    *additionally* honors a project-local ``./.mcp.json`` (a
    convention shared with Claude Code SDK). Pre-S5.x we only read
    ``./.mcp.json``, which silently dropped every globally-registered
    server from ``defenseclaw mcp list`` for Codex users — the
    gateway's connector watch path read config.toml fine, but the
    CLI/TUI saw an empty registry.

    We read the global registry first (config.toml) and let the
    project-local file override matching names, mirroring how Codex
    itself layers them at runtime.
    """
    home = str(Path.home())
    entries: list[MCPServerEntry] = []
    entries.extend(_read_codex_config_toml(os.path.join(home, ".codex", "config.toml")))
    project_mcp = _workspace_path(workspace_dir, ".mcp.json")
    if project_mcp:
        entries.extend(_read_dotmcp_json(project_mcp))
    return _dedup_mcp_entries(entries)


def _read_codex_config_toml(path: str) -> list[MCPServerEntry]:
    """Parse the ``[mcp_servers]`` table out of Codex's config.toml.

    Codex's documented schema (developers.openai.com/codex/config) is::

        [mcp_servers.<name>]
        command = "..."
        args = ["..."]
        env = { KEY = "value" }

    Values may also use a flat ``[mcp_servers]`` mapping where each
    entry is itself a table — both shapes are accepted. Failures
    (missing file, malformed TOML, missing block) return ``[]`` so
    callers can soft-fall back to ``./.mcp.json``.

    Implementation note: we use the stdlib :mod:`tomllib` (Python
    3.11+) which is already a project requirement; no third-party
    parser is added.
    """
    try:
        import tomllib  # Python 3.11+ stdlib — safe parser, no exec.
    except ImportError:
        # Defensive: cli/defenseclaw targets 3.12 in pyproject.toml,
        # so this branch is unreachable in supported deployments.
        # We still soft-fail rather than raising because the caller
        # treats this as best-effort discovery.
        return []
    try:
        with open(path, "rb") as f:
            data = tomllib.load(f)
    except (OSError, tomllib.TOMLDecodeError):
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
        os.path.join(str(Path.home()), ".hermes", "config.yaml"),
        key_paths=(("mcp", "servers"), ("mcpServers",)),
    )


def _cursor_mcp_servers(workspace_dir: str | None = None) -> list[MCPServerEntry]:
    home = str(Path.home())
    entries: list[MCPServerEntry] = []
    entries.extend(_read_dotmcp_json(os.path.join(home, ".cursor", "mcp.json")))
    project_mcp = _workspace_path(workspace_dir, ".cursor", "mcp.json")
    if project_mcp:
        entries.extend(_read_dotmcp_json(project_mcp))
    return _dedup_mcp_entries(entries)


def _windsurf_mcp_servers() -> list[MCPServerEntry]:
    home = str(Path.home())
    entries: list[MCPServerEntry] = []
    for path in _windsurf_mcp_paths(home):
        entries.extend(_read_dotmcp_json(path))
    return _dedup_mcp_entries(entries)


def _gemini_mcp_servers() -> list[MCPServerEntry]:
    return _read_mcp_settings_block(
        os.path.join(str(Path.home()), ".gemini", "settings.json"),
        keys=("mcpServers",),
    )


def _copilot_mcp_servers(workspace_dir: str | None = None) -> list[MCPServerEntry]:
    home = str(Path.home())
    entries: list[MCPServerEntry] = []
    entries.extend(_read_dotmcp_json(os.path.join(home, ".copilot", "mcp-config.json")))
    github_mcp = _workspace_path(workspace_dir, ".github", "mcp.json")
    if github_mcp:
        entries.extend(_read_dotmcp_json(github_mcp))
    project_mcp = _workspace_path(workspace_dir, ".mcp.json")
    if project_mcp:
        entries.extend(_read_dotmcp_json(project_mcp))
    return _dedup_mcp_entries(entries)


def _openhands_mcp_servers() -> list[MCPServerEntry]:
    return _read_dotmcp_json(os.path.join(str(Path.home()), ".openhands", "mcp.json"))


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
        with open(path) as f:
            data = yaml.safe_load(f) or {}
    except (OSError, yaml.YAMLError):
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


def _read_dotmcp_json(path: str) -> list[MCPServerEntry]:
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
        return _parse_mcp_servers_dict(inner)
    return _parse_mcp_servers_dict(data)


def _read_zepto_config(path: str) -> list[MCPServerEntry]:
    return _read_mcp_settings_block(path, keys=("mcp", "servers"))


def _windsurf_mcp_paths(home: str | None = None) -> list[str]:
    home = home or str(Path.home())
    return [
        os.path.join(home, ".codeium", "windsurf", "mcp_config.json"),
        os.path.join(home, ".codeium", "windsurf", "mcp.json"),
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
        out.append(
            MCPServerEntry(
                name=name,
                command=cfg.get("command", "") or "",
                args=list(cfg.get("args", []) or []),
                env=dict(cfg.get("env", {}) or {}),
                url=cfg.get("url", "") or "",
                transport=cfg.get("transport", "") or "",
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
        out.append(
            MCPServerEntry(
                name=name,
                command=cfg.get("command", "") or "",
                args=list(cfg.get("args", []) or []),
                env=dict(cfg.get("env", {}) or {}),
                url=cfg.get("url", "") or "",
                transport=cfg.get("transport", "") or "",
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
    * Claude Code  — ``$HOME/.claude/settings.json[mcpServers][name]``
                     via :func:`_atomic_json_merge`.
    * Codex        — ``~/.codex/config.toml[mcp_servers][name]``
                     by default, or ``<workspace>/.mcp.json`` when
                     *workspace_dir* is explicit.
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
        path = os.path.join(str(Path.home()), ".claude", "settings.json")
        _atomic_json_merge(path, ("mcpServers", name), entry)
        return
    if name_n == "codex":
        workspace = _workspace_dir(workspace_dir)
        if workspace:
            _atomic_json_merge(os.path.join(workspace, ".mcp.json"), ("mcpServers", name), entry)
        else:
            _set_codex_global_mcp_server(name, entry)
        return
    if name_n == "hermes":
        path = os.path.join(str(Path.home()), ".hermes", "config.yaml")
        _atomic_yaml_merge(path, ("mcp", "servers", name), entry)
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
            else os.path.join(str(Path.home()), ".copilot", "mcp-config.json")
        )
        _atomic_json_merge(path, ("mcpServers", name), entry)
        return
    if name_n == "openhands":
        path = os.path.join(str(Path.home()), ".openhands", "mcp.json")
        _atomic_json_merge(path, ("mcpServers", name), entry)
        return
    if name_n == "antigravity":
        raise MCPWriteUnsupportedError(
            "antigravity does not publish a documented MCP install "
            "surface in agy v1.0.0. DefenseClaw will pick this up via "
            "a contract bump once Google ships an MCP install path.",
        )
    if name_n == "opencode":
        raise MCPWriteUnsupportedError(
            "opencode MCP servers live in opencode.json, which DefenseClaw "
            "does not manage in v1; the opencode connector governs tool "
            "execution via its bridge plugin only.",
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

    Mirrors :func:`set_mcp_server` and uses :func:`_atomic_json_delete`
    on Claude Code / Codex; OpenClaw delegates to the injected
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
        path = os.path.join(str(Path.home()), ".claude", "settings.json")
        _atomic_json_delete(path, ("mcpServers", name))
        return
    if name_n == "codex":
        workspace = _workspace_dir(workspace_dir)
        if workspace:
            _atomic_json_delete(os.path.join(workspace, ".mcp.json"), ("mcpServers", name))
        else:
            _unset_codex_global_mcp_server(name)
        return
    if name_n == "hermes":
        path = os.path.join(str(Path.home()), ".hermes", "config.yaml")
        _atomic_yaml_delete(path, ("mcp", "servers", name))
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
            else os.path.join(str(Path.home()), ".copilot", "mcp-config.json")
        )
        _atomic_json_delete(path, ("mcpServers", name))
        return
    if name_n == "openhands":
        path = os.path.join(str(Path.home()), ".openhands", "mcp.json")
        _atomic_json_delete(path, ("mcpServers", name))
        return
    if name_n == "antigravity":
        raise MCPWriteUnsupportedError(
            "antigravity does not publish a documented MCP install "
            "surface in agy v1.0.0; nothing to remove.",
        )
    if name_n == "opencode":
        raise MCPWriteUnsupportedError(
            "opencode MCP servers live in opencode.json, which DefenseClaw "
            "does not manage in v1; the opencode connector governs tool "
            "execution via its bridge plugin only.",
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
    return os.path.join(str(Path.home()), ".codex", "config.toml")


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


def _set_codex_global_mcp_server(name: str, entry: dict[str, Any]) -> None:
    path = _codex_config_toml_path()
    try:
        with open(path, encoding="utf-8") as f:
            text = f.read()
    except FileNotFoundError:
        text = ""
    updated = _strip_codex_mcp_block(text, name)
    if updated and not updated.endswith("\n\n"):
        updated = updated.rstrip() + "\n\n"
    updated += _codex_mcp_block(name, entry)
    _capture_managed_mcp_backup(path)
    _atomic_write_text(path, updated)


def _unset_codex_global_mcp_server(name: str) -> bool:
    path = _codex_config_toml_path()
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
# Atomic JSON read-modify-write helpers
# ---------------------------------------------------------------------------
#
# These mirror the Go-side atomicWriteFile pattern in
# internal/gateway/connector/codex.go: write to a tempfile in the same
# directory, fsync, then os.replace. Permissions are forced to 0o600
# because the targets (~/.claude/settings.json, ./.mcp.json) frequently
# carry credentials in the env: block.


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
    registry_backup = _registry_backup_for(abs_path)
    if registry_backup is not None and os.path.isfile(registry_backup):
        os.replace(registry_backup, abs_path)
        _registry_clear(abs_path)
        return True
    backup = _managed_mcp_backup_path(path)
    if not os.path.isfile(backup):
        return False
    os.replace(backup, path)
    return True


def _capture_managed_mcp_backup(path: str) -> None:
    # workspace-scoped MCP configs (Codex .mcp.json,
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
        sys.stderr.write(
            f"[defenseclaw] refusing to back up MCP config: {path} is a symlink "
            f"-> {target!r}\n"
        )
        return
    if not stat.S_ISREG(st.st_mode):
        return
    backup = _managed_mcp_backup_path(path)
    if os.path.exists(backup):
        # Sibling backup already present — the registry entry may be
        # stale; refresh it so a later restore_by_id() resolves to the
        # right absolute path even when called from a different cwd.
        _registry_register(os.path.abspath(path), backup)
        return
    # follow_symlinks=False is defense-in-depth: even if a symlink slips
    # past the lstat above (e.g. TOCTOU), copy2 will not follow it.
    shutil.copy2(path, backup, follow_symlinks=False)
    os.chmod(backup, 0o600)
    _registry_register(os.path.abspath(path), backup)


def _managed_mcp_backup_path(path: str) -> str:
    parent = os.path.dirname(path) or "."
    basename = os.path.basename(path).lstrip(".") or "config"
    return os.path.join(parent, f".defenseclaw-{basename}.bak")


# ---------------------------------------------------------------------------
# MCP backup registry — workspace-cwd-independent restore (S5.2 / C-2)
# ---------------------------------------------------------------------------
#
# The historical ``.defenseclaw-<name>.bak`` sibling-file scheme works
# fine for user-scope configs (``~/.claude/settings.json``) because the
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
    parent = os.path.dirname(path)
    os.makedirs(parent, mode=0o700, exist_ok=True)
    try:
        os.chmod(parent, 0o700)
    except OSError:
        pass
    import tempfile

    fd, tmp = tempfile.mkstemp(prefix=".dc-mcp-registry-", dir=parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2, sort_keys=True)
            f.write("\n")
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _registry_key(abs_target: str) -> str:
    """Stable identifier for *abs_target* used as the registry key.

    SHA-256 of the absolute path. We use a hash (not the path itself)
    because some operators consider the on-disk filename of a workspace
    as sensitive; the original is still recorded in the value as
    ``path`` so legitimate restore flows can echo it back to the user.
    """
    import hashlib

    return hashlib.sha256(abs_target.encode("utf-8")).hexdigest()


def _registry_register(abs_target: str, backup: str) -> None:
    import datetime as _dt

    state = _registry_load()
    state[_registry_key(abs_target)] = {
        "path": abs_target,
        "backup": os.path.abspath(backup),
        "ts": _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    try:
        _registry_save(state)
    except OSError:
        # Best-effort: registry write failure must not block setup.
        # The legacy sibling backup is still in place for restore.
        pass


def _registry_clear(abs_target: str) -> None:
    state = _registry_load()
    if state.pop(_registry_key(abs_target), None) is None:
        return
    try:
        _registry_save(state)
    except OSError:
        pass


def _registry_backup_for(abs_target: str) -> str | None:
    entry = _registry_load().get(_registry_key(abs_target))
    if not entry:
        return None
    backup = entry.get("backup", "")
    return backup or None


def lookup_managed_mcp_backup(path: str) -> str | None:
    """Return the absolute backup path for *path* if recorded.

    Public lookup helper for tests and for tooling that needs to surface
    the recorded backup location without performing a restore.
    """
    return _registry_backup_for(os.path.abspath(path))


def _atomic_write_yaml(path: str, data: dict[str, Any]) -> None:
    import tempfile

    parent = os.path.dirname(path) or "."
    os.makedirs(parent, mode=0o700, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".defenseclaw-", suffix=".tmp", dir=parent)
    try:
        with os.fdopen(fd, "w") as f:
            yaml.safe_dump(data, f, default_flow_style=False, sort_keys=False)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    finally:
        try:
            if os.path.exists(tmp):
                os.unlink(tmp)
        except OSError:
            pass


def _atomic_write_text(path: str, text: str) -> None:
    """Atomically write UTF-8 text with private permissions."""
    import tempfile

    parent = os.path.dirname(path) or "."
    os.makedirs(parent, mode=0o700, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".dc-mcp-", dir=parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


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
    import tempfile

    parent = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(prefix=".dc-mcp-", dir=parent)
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=2, sort_keys=True)
            f.write("\n")
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
