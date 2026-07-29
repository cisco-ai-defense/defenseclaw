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

"""Cached local agent discovery for first-run connector selection."""

from __future__ import annotations

import glob
import json
import os
import shutil
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from io import StringIO
from pathlib import Path
from typing import NamedTuple

import yaml

from defenseclaw.inventory._semver import pick_highest_supported

# `grp` is POSIX-only. We import it lazily-but-at-module-load so the
# group-ownership check below can run without an inline import,
# while still keeping Windows hosts importable.
try:  # pragma: no cover - Windows path
    import grp as _grp
except ImportError:  # pragma: no cover - non-POSIX
    _grp = None  # type: ignore[assignment]

from defenseclaw.config import config_path_for_data_dir, default_data_path
from defenseclaw.connector_paths import (
    KNOWN_AGENT_KINDS,
    KNOWN_CONNECTORS,
    _expand,
    omnigent_config_path,
)

# Sentinel error returned by ``_version_for_binary`` when a connector
# binary resolves outside the trusted install prefixes. Callers (e.g.
# ``cmd_setup``) key off this exact value to decide whether to offer the
# "trust this directory" remediation, so it lives here as a shared
# constant rather than being duplicated as a string literal on both
# sides — if the wording ever changes, the consumer can't silently drift.
UNTRUSTED_PREFIX_ERROR = "binary path is not in a trusted install prefix"

CACHE_SCHEMA_VERSION = 1
CACHE_TTL_SECONDS = 86_400
CACHE_FILENAME = "agent_discovery.json"
VERSION_TIMEOUT_SECONDS = 2.0

# Canonical install prefixes that we trust enough to exec
# `<binary> --version` against. Anything outside this allow-list is
# refused — even when ``shutil.which`` returns it — because a user PATH
# entry pointing to /tmp, the current directory, or some other
# attacker-writable location could otherwise have us run a hostile
# binary as part of a passive discovery scan.
#
# The default list is restricted to system-managed prefixes that
# require root / package-manager privilege to write. User-writable tool
# directories (~/.local/bin, ~/.cargo/bin, ~/.nvm, ~/.asdf, ~/.pyenv,
# ~/.pipx, ~/Library/Application Support, /Applications) are deliberately
# excluded: a local agent process running as the operator can write to
# those dirs, plant `codex` (or any other discovery target), and a
# default-trusted prefix would let the passive scan exec it. Operators
# with bespoke install layouts extend the allow-list at runtime via the
# ``DEFENSECLAW_TRUSTED_BIN_PREFIXES`` env var (``os.pathsep``-separated).
_TRUSTED_BIN_PREFIXES_DEFAULT: tuple[str, ...] = (
    "/usr/bin",
    "/usr/local/bin",
    "/usr/sbin",
    "/usr/local/sbin",
    "/bin",
    "/sbin",
    "/opt/homebrew/bin",
    "/opt/homebrew/sbin",
    "/opt/homebrew/Cellar",
    "/opt/homebrew/Caskroom",
    "/opt/homebrew/lib/node_modules",
    "/usr/local/Cellar",
    "/usr/local/lib/node_modules",
    "/opt/local/bin",
    "/opt/local/sbin",
    # User-writable tool dirs (~/.local/bin, ~/.codex/packages,
    # ~/.opencode/bin, ~/.cargo/bin, ~/.nvm, ~/.asdf, ~/.pyenv, ~/.pipx,
    # ~/Library/Application Support, /Applications, …) are intentionally
    # NOT trusted by default — a local agent running as the operator can
    # plant a binary there (e.g. `codex` or `opencode`) and the passive
    # scan would exec it. Operators who install discovery targets under a
    # user-owned tool root (modern Codex CLI lives in
    # ~/.codex/packages/standalone/...; opencode lives in ~/.opencode/bin)
    # must opt in explicitly via DEFENSECLAW_TRUSTED_BIN_PREFIXES
    # (``os.pathsep``-separated); the per-file/parent permission checks in
    # _is_trusted_binary_path still apply on top of any extension.
)

DISCOVERY_PRECEDENCE: tuple[str, ...] = (
    "codex",
    "claudecode",
    "openclaw",
    "zeptoclaw",
    "hermes",
    "cursor",
    "windsurf",
    "geminicli",
    "copilot",
    "openhands",
    "antigravity",
    "opencode",
    "omnigent",
)


@dataclass
class AgentSignal:
    name: str
    installed: bool
    config_path: str
    binary_path: str
    version: str
    error: str
    # ``source`` records WHERE the reported ``version`` came from — the
    # native-installer symlink, an NVM node_modules root, the ChatGPT.app
    # bundle, etc. Populated only by the three item-level collectors
    # (claudecode / codex / cursor) added for the multi-install
    # discovery fix; other connectors leave it empty and legacy JSON
    # caches without the field deserialize with the empty default. Kept
    # optional so callers that ignore the field (older TUI renderers)
    # keep working.
    source: str = ""


@dataclass
class AgentDiscovery:
    scanned_at: str
    agents: dict[str, AgentSignal]
    cache_hit: bool


class _AgentSpec(NamedTuple):
    config_candidates: tuple[str, ...]
    binary_name: str
    version_args: tuple[str, ...]


_SPECS: dict[str, _AgentSpec] = {
    "codex": _AgentSpec(("~/.codex/config.toml",), "codex", ("--version",)),
    "claudecode": _AgentSpec(("~/.claude/settings.json", "~/.claude"), "claude", ("--version",)),
    "openclaw": _AgentSpec(("~/.openclaw/openclaw.json",), "openclaw", ("--version",)),
    "zeptoclaw": _AgentSpec(("~/.zeptoclaw/config.json",), "zeptoclaw", ("--version",)),
    "hermes": _AgentSpec(("~/.hermes/config.yaml",), "hermes", ("--version",)),
    "cursor": _AgentSpec(("~/.cursor/hooks.json", "~/.cursor/mcp.json"), "cursor", ("--version",)),
    "windsurf": _AgentSpec(
        (
            "~/.codeium/windsurf/hooks.json",
            "~/.codeium/windsurf/mcp_config.json",
            "~/.codeium/windsurf/mcp.json",
        ),
        "windsurf",
        ("--version",),
    ),
    "geminicli": _AgentSpec(("~/.gemini/settings.json",), "gemini", ("--version",)),
    "copilot": _AgentSpec(
        (
            "~/.copilot/mcp-config.json",
            ".github/hooks/defenseclaw.json",
            ".github/mcp.json",
            ".mcp.json",
        ),
        "copilot",
        ("version",),
    ),
    "openhands": _AgentSpec(
        (".openhands/hooks.json", ".openhands", "~/.openhands/mcp.json"), "openhands", ("--version",)
    ),
    "antigravity": _AgentSpec(
        # agy v1.0.x reads PreToolUse hooks from ~/.gemini/config/
        # hooks.json (the canonical runtime path). The legacy
        # ~/.gemini/antigravity-cli/ directory is still listed
        # because `agy --help` advertises it and pre-v0.5.0
        # installs put files there — discovery should pick up
        # either signal.
        (
            "~/.gemini/config/hooks.json",
            "~/.gemini/antigravity-cli/hooks.json",
            "~/.gemini/antigravity-cli",
        ),
        "agy",
        ("--version",),
    ),
    "opencode": _AgentSpec(
        # opencode auto-loads plugins from ~/.config/opencode/plugins/;
        # DefenseClaw installs its bridge there. opencode.json / the
        # .opencode project dir are also signals the agent is present.
        (
            "~/.config/opencode/plugins/defenseclaw.js",
            "~/.config/opencode/opencode.json",
            "~/.config/opencode",
            ".opencode",
        ),
        "opencode",
        ("--version",),
    ),
    "omnigent": _AgentSpec(
        ("~/.omnigent/config.yaml", "~/.omnigent"),
        "omnigent",
        ("--version",),
    ),
    # Discovery-only agents (not in KNOWN_CONNECTORS). Config
    # candidates mirror the corresponding entries in
    # internal/inventory/ai_signatures.json so `agent discover` picks
    # up the same install signals the sidecar does.
    "aider": _AgentSpec(
        ("~/.aider.conf.yml", "~/.aider", ".aider.conf.yml"),
        "aider",
        ("--version",),
    ),
    "continue": _AgentSpec(
        (
            "~/.continue/config.json",
            "~/.continue/config.yaml",
            "~/.continue",
            ".continue/config.json",
        ),
        "continue",
        ("--version",),
    ),
    "cline": _AgentSpec(
        # Cline / Roo Code lives inside the VS Code / Cursor extension
        # storage tree; probe the extension-installed marker rather
        # than expecting a top-level binary. `binary_name=""` disables
        # the exec-based liveness probe for signals that are purely
        # extension-installed — the config-file probe is enough.
        # Paths mirror the `cline` entry in ai_signatures.json so
        # discovery does not false-positive on every editor user.
        (
            "~/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev",
            "~/Library/Application Support/Code/User/globalStorage/rooveterinaryinc.roo-cline",
        ),
        "",
        (),
    ),
    "claudedesktop": _AgentSpec(
        (
            "~/Library/Application Support/Claude/claude_desktop_config.json",
            "~/.config/Claude/claude_desktop_config.json",
            "~/AppData/Roaming/Claude/claude_desktop_config.json",
        ),
        "",
        (),
    ),
}


# Minimum-supported agent versions for the hook-contract gate. Values
# mirror ``min_inclusive`` in
# cli/defenseclaw/inventory/hook_contracts.json and the
# ``MinAgentVersion`` constants in
# internal/gateway/connector/hook_contract.go. When updating any of the
# three copies, update all three — the test
# ``test_min_versions_match_hook_contracts_json`` catches drift on CI.
_MIN_SUPPORTED_VERSIONS: dict[str, str] = {
    "claudecode": "2.1.144",
    "codex": "0.124.0",
    "cursor": "1.7.0",
}


def _read_pkg_version(path: str) -> str:
    """Return the top-level ``.version`` string from a package.json.

    Metadata-only: parses JSON, returns "" for any error (missing file,
    unreadable file, malformed JSON, missing field, non-string value).
    Never exec's the binary the package.json describes. Mirrors the
    ``_read_json_version`` helper in packaging/macos/lib/installer_lib.sh
    so the two discovery paths stay behavior-equivalent.
    """
    try:
        with open(path, encoding="utf-8") as f:
            payload = json.load(f)
    except (OSError, ValueError):
        return ""
    if not isinstance(payload, dict):
        return ""
    value = payload.get("version", "")
    return value if isinstance(value, str) else ""


def _collect_node_manager_pkg_versions(
    home: str, npm_scope: str, pkg: str
) -> list[tuple[str, str]]:
    """Enumerate (source_path, version) tuples across Node version managers.

    Node version managers (NVM, Volta, fnm, asdf) install npm globals
    under a per-node-version root, so an operator running two Node
    versions has two copies of the same ``@scope/pkg``. Discovery must
    enumerate every root and let ``pick_highest_supported`` sort out the
    winner — QA regression: previously not probed at all.

    Read-only glob cost: one readdir per manager root. Cheap even on
    developer boxes with a dozen node versions.
    """
    rel = f"{npm_scope}/{pkg}/package.json"
    roots = (
        f"{home}/.nvm/versions/node/*/lib/node_modules/{rel}",
        f"{home}/.local/share/fnm/node-versions/*/installation/lib/node_modules/{rel}",
        f"{home}/.asdf/installs/nodejs/*/.npm/lib/node_modules/{rel}",
        f"{home}/.volta/tools/image/packages/{npm_scope}/{pkg}/*/package.json",
    )
    out: list[tuple[str, str]] = []
    for pattern in roots:
        for candidate in sorted(glob.glob(pattern)):
            version = _read_pkg_version(candidate)
            if version:
                out.append((candidate, version))
    return out


def _native_claudecode_version_from_dir(base: str) -> list[tuple[str, str]]:
    """Read Claude Code's native-installer layout under ``base``.

    Matches ``_native_claudecode_version_from_dir`` in
    packaging/macos/lib/installer_lib.sh. Layout:
        base/
          current           -> symlink to versions/<X.Y.Z>
          versions/<X.Y.Z>/ actual install root
    The active ``current`` pointer wins over the highest ``versions/*``
    entry so a user who ran ``claude version rollback`` gets the same
    version the sidecar reports. Returns ``("", "")`` when base is
    missing or nothing looks like a semver.
    """
    if not base or not os.path.isdir(base):
        return []
    current = os.path.join(base, "current")
    if os.path.islink(current) and os.path.exists(current):
        target = os.readlink(current)
        candidate = os.path.basename(target)
        # Same regex tolerance as installer_lib.sh: accept anything
        # that starts X.Y.Z, allow the usual prerelease / build tails.
        # `current` is the authoritative user choice (survives
        # `claude version rollback`), so it wins over the versions/*
        # scan and short-circuits enumeration.
        if candidate and candidate[0].isdigit():
            return [(f"{base}/current -> {candidate}", candidate)]
    versions_dir = os.path.join(base, "versions")
    out: list[tuple[str, str]] = []
    if os.path.isdir(versions_dir):
        # No `current` pointer: return one tuple per candidate rather
        # than pre-picking with a local sort key. The naive digit-prefix
        # sort here would put "3.0.0-alpha" ahead of the stable "2.1.144"
        # and starve pick_highest_supported (the authoritative
        # comparator that understands prerelease tails) of the stable
        # entry.
        for name in os.listdir(versions_dir):
            if name and name[0].isdigit():
                out.append((f"{versions_dir}/{name}", name))
    return out


def _collect_claudecode_versions(home: str) -> list[tuple[str, str]]:
    """Return (source_path, version) for every claudecode install found.

    Enumerates all five distribution channels:
      1. Anthropic native installer (per-user).
      2. System-wide native install (/opt/claude, /usr/local/share/claude).
      3. npm-global (user, system, Homebrew).
      4. Node version managers (NVM, Volta, fnm, asdf).
      5. VS Code / Cursor editor extensions.
    Metadata-only — no binary is exec'd.
    """
    out: list[tuple[str, str]] = []
    for base in (
        os.path.join(home, ".local", "share", "claude"),
        "/opt/claude",
        "/usr/local/share/claude",
    ):
        out.extend(_native_claudecode_version_from_dir(base))
    for pkg in (
        f"{home}/.npm-global/lib/node_modules/@anthropic-ai/claude-code/package.json",
        "/usr/local/lib/node_modules/@anthropic-ai/claude-code/package.json",
        "/opt/homebrew/lib/node_modules/@anthropic-ai/claude-code/package.json",
    ):
        version = _read_pkg_version(pkg)
        if version:
            out.append((pkg, version))
    for pattern in (
        f"{home}/.cursor/extensions/anthropic.claude-code-*/package.json",
        f"{home}/.vscode/extensions/anthropic.claude-code-*/package.json",
    ):
        for candidate in sorted(glob.glob(pattern)):
            version = _read_pkg_version(candidate)
            if version:
                out.append((candidate, version))
    out.extend(_collect_node_manager_pkg_versions(home, "@anthropic-ai", "claude-code"))
    return out


def _collect_codex_versions(home: str) -> list[tuple[str, str]]:
    """Return (source_path, version) for every codex install found.

    Metadata-only: ChatGPT.app bundle carries no ``package.json`` today,
    so we skip the exec path entirely (the shell installer keeps a
    bundle-exec probe because it runs at install time as root and can
    afford ``sudo -u`` drop-privs; the Python discovery pass has no
    such lifecycle guarantee). Homebrew Caskroom, npm-global, and node
    version managers all expose enumerable metadata files.
    """
    out: list[tuple[str, str]] = []
    for caskroom in ("/opt/homebrew/Caskroom/codex", "/usr/local/Caskroom/codex"):
        if not os.path.isdir(caskroom):
            continue
        try:
            entries = sorted(os.listdir(caskroom))
        except OSError:
            continue
        for name in entries:
            if not name or not name[0].isdigit():
                continue
            out.append((os.path.join(caskroom, name), name))
    for pkg in (
        f"{home}/.npm-global/lib/node_modules/@openai/codex/package.json",
        "/usr/local/lib/node_modules/@openai/codex/package.json",
        "/opt/homebrew/lib/node_modules/@openai/codex/package.json",
    ):
        version = _read_pkg_version(pkg)
        if version:
            out.append((pkg, version))
    out.extend(_collect_node_manager_pkg_versions(home, "@openai", "codex"))
    return out


def _collect_cursor_versions(home: str) -> list[tuple[str, str]]:
    """Return (source_path, version) for every Cursor.app install found.

    Cursor.app is a signed macOS bundle with two version sources that
    can drift out of sync across a release:
      - ``Info.plist`` -> ``CFBundleShortVersionString`` (marketing).
      - ``Contents/Resources/app/package.json`` -> ``.version`` (npm
        layout the bundled agent actually reports).
    Enumerating both lets the highest-supported policy pick whichever
    one meets the hook contract's minimum.
    """
    del home  # Cursor lives under /Applications; home is unused today.
    out: list[tuple[str, str]] = []
    plist = "/Applications/Cursor.app/Contents/Info.plist"
    if os.path.isfile(plist):
        try:
            proc = subprocess.run(
                ["/usr/libexec/PlistBuddy", "-c", "Print :CFBundleShortVersionString", plist],
                capture_output=True,
                text=True,
                timeout=VERSION_TIMEOUT_SECONDS,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            proc = None
        if proc is not None and proc.returncode == 0:
            version = (proc.stdout or "").strip()
            if version:
                out.append((plist, version))
    pkg = "/Applications/Cursor.app/Contents/Resources/app/package.json"
    version = _read_pkg_version(pkg)
    if version:
        out.append((pkg, version))
    return out


# _SCAN_METADATA_ONLY maps connector name -> collector function. When a
# connector has an entry here, ``_scan_agent`` uses the metadata-only
# discovery path instead of shutil.which + subprocess.run. This is the
# fix for QA regressions #1 (Anthropic native installer fails the
# trust-prefix gate) and #2 (Homebrew wins first-hit over supported
# NVM). Every other connector keeps the legacy ``--version`` exec path.
_SCAN_METADATA_ONLY = {
    "claudecode": _collect_claudecode_versions,
    "codex": _collect_codex_versions,
    "cursor": _collect_cursor_versions,
}


def discover_agents(
    *,
    use_cache: bool = True,
    refresh: bool = False,
    data_dir: str | os.PathLike[str] | None = None,
) -> AgentDiscovery:
    """Return cached or freshly scanned local agent install signals."""
    if use_cache and not refresh:
        cached = _read_cache(data_dir=data_dir)
        if cached is not None:
            return cached

    scanned_at = _format_rfc3339(_now_utc())
    require_trusted, _prefixes = _ai_discovery_trust_config(data_dir)
    # Resolve the operator-configured home_dirs list once and pass it
    # down. Empty means "use the current user's $HOME" — that keeps the
    # single-tenant default identical to the pre-home_dirs behaviour.
    home_dirs = _ai_discovery_home_dirs(data_dir)
    with ThreadPoolExecutor(max_workers=4) as pool:
        signals = list(
            pool.map(
                lambda name: _scan_agent(
                    name,
                    data_dir=data_dir,
                    require_trusted_binary_paths=require_trusted,
                    home_dirs=home_dirs,
                ),
                KNOWN_AGENT_KINDS,
            )
        )
    agents = {signal.name: signal for signal in signals}
    discovery = AgentDiscovery(scanned_at=scanned_at, agents=agents, cache_hit=False)
    _write_cache(discovery, data_dir=data_dir)
    return discovery


def first_installed(disc: AgentDiscovery, fallback: str = "codex") -> str:
    """Return the preferred installed connector, or *fallback* when none match."""
    fallback = _normalize_connector(fallback) or "codex"
    preferred = disc.agents.get(fallback)
    if preferred and preferred.installed:
        return fallback

    for name in DISCOVERY_PRECEDENCE:
        signal = disc.agents.get(name)
        if signal and signal.installed:
            return name

    return fallback if fallback in KNOWN_CONNECTORS else "codex"


def render_discovery_table(disc: AgentDiscovery) -> str:
    """Render discovery as a Rich table string suitable for click.echo."""
    try:
        from rich.console import Console
        from rich.table import Table
    except Exception:
        return _render_plain_table(disc)

    stream = StringIO()
    console = Console(file=stream, force_terminal=False, color_system=None, width=120)
    title = "Agent discovery (cached)" if disc.cache_hit else "Agent discovery"
    table = Table(title=title)
    table.add_column("Connector")
    table.add_column("Installed")
    table.add_column("Config")
    table.add_column("Binary")
    table.add_column("Version / Error")

    for name in _ordered_connector_names(disc):
        signal = disc.agents[name]
        detail = signal.version or signal.error
        table.add_row(
            signal.name,
            "yes" if signal.installed else "no",
            _display_path(signal.config_path),
            _display_path(signal.binary_path),
            detail,
        )

    console.print(table)
    return stream.getvalue()


def _scan_agent(
    name: str,
    *,
    data_dir: str | os.PathLike[str] | None = None,
    require_trusted_binary_paths: bool = False,
    home_dirs: tuple[str, ...] = (),
) -> AgentSignal:
    spec = _SPECS.get(name, _AgentSpec((), "", ("--version",)))
    config_candidates = spec.config_candidates
    if name == "omnigent":
        config_path = omnigent_config_path()
        config_candidates = (config_path, os.path.dirname(config_path))
    config_path = _first_existing_path(config_candidates)

    collector = _SCAN_METADATA_ONLY.get(name)
    if collector is not None:
        # Metadata-only path for the three connectors with multi-channel
        # installs (claudecode, codex, cursor). Enumerates every visible
        # install and picks the highest that meets the hook contract's
        # MinAgentVersion — see _MIN_SUPPORTED_VERSIONS above and QA
        # regressions #1 / #2 in the PR description.
        #
        # home_dirs (from ai_discovery.home_dirs in config.yaml) lets
        # multi-tenant hosts enumerate every operator's installs from a
        # single sidecar; empty falls back to the current process's
        # $HOME so single-tenant behavior is unchanged. Duplicate
        # (source, version) pairs are naturally deduped inside
        # pick_highest_supported by the highest-wins policy.
        homes = home_dirs if home_dirs else (os.path.expanduser("~"),)
        candidates: list[tuple[str, str]] = []
        for h in homes:
            candidates.extend(collector(h))
        min_version = _MIN_SUPPORTED_VERSIONS.get(name, "")
        picked = pick_highest_supported(candidates, min_version)
        if picked is not None:
            source, version = picked
            installed = True
            return AgentSignal(
                name=name,
                installed=installed,
                config_path=config_path,
                # binary_path stays empty in the metadata path — we
                # deliberately dodged shutil.which to avoid the
                # untrusted-prefix rejection. Downstream renderers
                # already treat binary_path as best-effort.
                binary_path="",
                version=version,
                error="",
                source=source,
            )
        # No enumerable installs found. Fall through to the legacy
        # config-file-presence branch below so an operator with a bare
        # `~/.claude` directory still shows installed=True.
        return AgentSignal(
            name=name,
            installed=bool(config_path),
            config_path=config_path,
            binary_path="",
            version="",
            error="",
            source="",
        )

    binary_path = _which(spec.binary_name) if spec.binary_name else ""
    version = ""
    error = ""
    version_ok = False

    if binary_path:
        version, error = _version_for_binary(
            binary_path,
            spec.version_args,
            require_trusted_binary_paths=require_trusted_binary_paths,
            data_dir=data_dir,
        )
        version_ok = bool(version) and not error

    installed = bool(config_path) or (bool(binary_path) and version_ok)
    return AgentSignal(
        name=name,
        installed=installed,
        config_path=config_path,
        binary_path=binary_path,
        version=version,
        error=error,
    )


def _ai_discovery_trust_config(
    data_dir: str | os.PathLike[str] | None = None,
) -> tuple[bool, tuple[str, ...]]:
    """Return ``(require_trusted_paths, config_prefixes)`` from config.yaml."""
    path = config_path_for_data_dir(data_dir)
    try:
        with open(path, encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}
    except (OSError, yaml.YAMLError):
        # See _ai_discovery_home_dirs for the same fallback rationale.
        raw = {}
    if not isinstance(raw, dict):
        return False, ()
    block = raw.get("ai_discovery")
    if not isinstance(block, dict):
        return False, ()
    prefixes = tuple(str(v).strip() for v in (block.get("trusted_binary_prefixes", []) or []) if str(v).strip())
    return bool(block.get("require_trusted_binary_paths", False)), prefixes


def _ai_discovery_home_dirs(
    data_dir: str | os.PathLike[str] | None = None,
) -> tuple[str, ...]:
    """Return the operator-configured ``ai_discovery.home_dirs`` list.

    Empty when the field is absent — callers should fall back to
    ``[os.path.expanduser("~")]`` in that case. Multi-tenant hosts
    (shared build boxes, notebook servers with per-user home dirs) set
    this so a single sidecar can enumerate every operator's installs
    without needing one process per user.

    Kept read-only: config.yaml is the authoritative source (rendered
    by install.sh from operator flags), so the discovery pass doesn't
    mutate it here.
    """
    path = config_path_for_data_dir(data_dir)
    try:
        with open(path, encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}
    except (OSError, yaml.YAMLError):
        # OSError: config.yaml unreadable / absent. YAMLError: file
        # exists but its contents are malformed (mid-write, hand-edit
        # that broke indentation, etc.). Either way, fall back to the
        # empty tuple — the caller then uses the single-tenant $HOME
        # default. Silently degrading to that fallback is preferable
        # to raising here: config-parse failures already surface
        # through the primary Load() path in the sidecar boot, so
        # this side-channel accessor shouldn't gate discovery.
        return ()
    if not isinstance(raw, dict):
        return ()
    block = raw.get("ai_discovery")
    if not isinstance(block, dict):
        return ()
    dirs = block.get("home_dirs", []) or []
    if not isinstance(dirs, list):
        return ()
    # Expand and canonicalise each entry; drop empties + duplicates
    # while preserving encounter order.
    seen: set[str] = set()
    out: list[str] = []
    for entry in dirs:
        raw_dir = str(entry).strip()
        if not raw_dir:
            continue
        expanded = os.path.expanduser(raw_dir)
        if expanded in seen:
            continue
        seen.add(expanded)
        out.append(expanded)
    return tuple(out)


def _trusted_bin_prefixes(
    data_dir: str | os.PathLike[str] | None = None,
) -> tuple[str, ...]:
    """Return the allow-list of canonical install prefixes.

    The defaults cover platform-package, Homebrew, MacPorts, and common
    user-scoped tooling (cargo, npm, pyenv, asdf, pipx, etc.). Operators
    can extend the list at runtime via ``DEFENSECLAW_TRUSTED_BIN_PREFIXES``
    (``os.pathsep``-separated). Each entry is tilde-expanded and absolutised
    before comparison.
    """
    extras: list[str] = []
    _require, config_prefixes = _ai_discovery_trust_config(data_dir)
    extras.extend(config_prefixes)
    raw = os.environ.get("DEFENSECLAW_TRUSTED_BIN_PREFIXES", "")
    # Split on os.pathsep (':' POSIX, ';' Windows) so a Windows
    # drive-qualified path like 'C:\\Tools' survives unmangled.
    for piece in raw.split(os.pathsep):
        piece = piece.strip()
        if piece:
            extras.append(piece)
    return tuple(_expand_bin_prefixes((*_TRUSTED_BIN_PREFIXES_DEFAULT, *extras)))


def _expand_bin_prefixes(prefixes: tuple[str, ...]) -> list[str]:
    expanded: list[str] = []
    for prefix in prefixes:
        try:
            # Binary admission compares against the binary's realpath, so
            # trusted prefixes must use the same canonical form. This matters
            # on macOS where /tmp and /var are symlinks into /private: an
            # operator-approved /tmp/tool/bin prefix otherwise never matches
            # the resolved /private/tmp/tool/bin/binary path.
            absolute = os.path.realpath(os.path.abspath(_expand(prefix)))
        except Exception:
            continue
        # Refuse degenerate prefixes that would defeat the allow-list:
        # `/` matches every absolute path, and `""` would normalize to
        # the current working directory which an attacker can pivot via
        # `cd`. The allow-list must name a real installation root.
        normalized = absolute.rstrip(os.sep)
        if normalized in ("", os.sep.rstrip(os.sep)):
            continue
        # Require at least one path component below the filesystem
        # root — `/usr` is fine, `/` is not.
        if absolute.count(os.sep) < 1 or normalized == "":
            continue
        expanded.append(absolute)
    return expanded


def _default_trusted_bin_prefixes() -> frozenset[str]:
    """The absolutised built-in (non-operator-supplied) trusted prefixes.

    These are the prefixes we trust *by default*, without an operator
    opting in via ``DEFENSECLAW_TRUSTED_BIN_PREFIXES``. They get a stricter
    ownership requirement (see ``_is_trusted_binary_path``).
    """
    return frozenset(_expand_bin_prefixes(_TRUSTED_BIN_PREFIXES_DEFAULT))


def _bin_chain_is_system_owned(resolved: str, prefix: str) -> bool:
    """F-0421: require root ownership along the resolved→prefix chain.

    For a *default* trusted prefix (e.g. ``/opt/homebrew/bin``) we refuse to
    exec a binary when the binary itself, or any parent directory up to and
    including the prefix, is owner-writable while owned by a NON-root user.
    Such a path is swappable by that (non-root) owner — including
    operator-level malware running as that user — before the passive
    version probe execs it. Genuine system-managed prefixes are root-owned,
    so they pass; a user-owned Homebrew/MacPorts tree does not (operators
    who deliberately trust a user-owned root must opt in via
    ``DEFENSECLAW_TRUSTED_BIN_PREFIXES``, which routes around this check).
    """
    prefix_norm = prefix.rstrip(os.sep)
    current = resolved
    seen: set[str] = set()
    while current and current not in seen:
        seen.add(current)
        try:
            st = os.stat(current)
        except OSError:
            return False
        # Owner-writable while owned by a non-root user → swappable by a
        # non-root principal. (World/group-writable is already rejected by
        # the per-node checks in the caller.)
        if (st.st_mode & 0o200) and st.st_uid != 0:
            return False
        if current.rstrip(os.sep) == prefix_norm:
            break
        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent
    return True


def _trusted_prefix_dir_mode_error(st: os.stat_result) -> str | None:
    """Return a human-readable refusal when a directory mode is unsafe to trust.

    Mirrors the parent-directory permission checks in ``_is_trusted_binary_path``
    so ``trusted-paths add`` cannot succeed on directories discovery would still
    reject for version probing.
    """
    if st.st_mode & 0o002:
        return "directory is world-writable"
    if st.st_mode & 0o020:
        grp_name = ""
        if _grp is not None:
            try:
                grp_name = _grp.getgrgid(st.st_gid).gr_name
            except (KeyError, OSError):
                grp_name = ""
        if grp_name not in ("root", "wheel", "admin"):
            return "directory is group-writable"
    return None


def validate_trusted_prefix(path: str) -> tuple[str, str | None]:
    """Validate a candidate trusted-bin-prefix directory.

    Returns ``(resolved_abspath, error)`` where ``error`` is ``None`` when the
    directory is a safe place to trust, or a short human-readable reason
    otherwise. Shared by the ``setup trusted-paths`` CLI (and any other
    caller) so the security rules can never drift from the discovery gate.

    Rules:
      * a *non-absolute* input is rejected — the resolved location would
        otherwise depend on the caller's working directory;
      * existing paths are canonicalised with ``realpath`` so symlink aliases
        match the discovery gate;
      * a *world-writable* or unsafe *group-writable* directory is rejected —
        anyone on the host (or anyone sharing the group) could drop a malicious
        binary into it, the exact threat the allow-list defends against;
      * a path that exists but is not a directory is rejected;
      * a path that does not yet exist is allowed (the caller may warn) — it
        is not itself unsafe to trust.
    """
    raw = (path or "").strip()
    if not raw:
        return "", "path is empty"
    expanded = _expand(raw)
    if not os.path.isabs(expanded):
        return os.path.abspath(expanded), "path is not absolute"
    try:
        resolved = os.path.realpath(expanded)
    except OSError:
        resolved = os.path.abspath(expanded)
    try:
        st = os.stat(resolved)
    except FileNotFoundError:
        return resolved, None
    except OSError as exc:  # pragma: no cover - rare stat failure
        return resolved, f"cannot stat path ({exc})"
    if not os.path.isdir(resolved):
        return resolved, "path is not a directory"
    mode_err = _trusted_prefix_dir_mode_error(st)
    if mode_err:
        return resolved, mode_err
    return resolved, None


def _is_trusted_binary_path(
    binary_path: str,
    data_dir: str | os.PathLike[str] | None = None,
) -> bool:
    """M-4: refuse to exec a binary that lives outside the allow-list.

    The check follows symlinks (``os.path.realpath``) so an attacker
    can't drop a symlink into a trusted prefix that points at a hostile
    target outside it. We also reject world-writable parent directories
    — a binary in ``/usr/local/bin`` is only trustworthy if root or the
    operator owns the directory.
    """
    if not binary_path:
        return False
    try:
        resolved = os.path.realpath(binary_path)
    except (OSError, ValueError):
        return False
    if not os.path.isabs(resolved):
        return False
    if not os.path.isfile(resolved):
        return False
    if not os.access(resolved, os.X_OK):
        return False
    parent = os.path.dirname(resolved)
    try:
        parent_st = os.stat(parent)
    except OSError:
        return False
    # World-writable parent → an attacker who can write to that dir
    # could swap the binary at any time. Treat as untrusted.
    if parent_st.st_mode & 0o002:
        return False
    # also reject group-writable parents unless the
    # group is the system root group. A non-root user that shares a
    # group with the parent dir can swap the binary.
    if parent_st.st_mode & 0o020:
        grp_name = ""
        if _grp is not None:
            try:
                grp_name = _grp.getgrgid(parent_st.st_gid).gr_name
            except (KeyError, OSError):
                grp_name = ""
        if grp_name not in ("root", "wheel", "admin"):
            return False
    # refuse a binary whose own file is writable by
    # anyone other than the trusted system owner. The user-writable
    # ~/.local/bin/* case is the canonical exploit path; even if an
    # operator extends DEFENSECLAW_TRUSTED_BIN_PREFIXES to include it,
    # we still refuse the individual file when its mode bits expose
    # group/world write.
    try:
        bin_st = os.stat(resolved)
    except OSError:
        return False
    if bin_st.st_mode & 0o022:
        return False
    prefixes = _trusted_bin_prefixes(data_dir)
    default_prefixes = _default_trusted_bin_prefixes()
    for prefix in prefixes:
        # Both the resolved binary and the candidate need to share a
        # path-component boundary; suffix-string match would let
        # /usr/binEvil sneak past /usr/bin.
        if resolved == prefix or resolved.startswith(prefix.rstrip(os.sep) + os.sep):
            # F-0421: built-in default prefixes additionally require the
            # resolved binary and its parent chain (up to the prefix) to be
            # root-owned. A user-owned, owner-writable binary under a
            # default "system" prefix (the classic /opt/homebrew/bin case)
            # is swappable by a non-root principal, so we refuse to exec it
            # during passive discovery. Operator opt-in prefixes
            # (DEFENSECLAW_TRUSTED_BIN_PREFIXES) keep the looser checks.
            if prefix in default_prefixes and not _bin_chain_is_system_owned(resolved, prefix):
                # A user-owned Homebrew tree can fail the default-prefix
                # ownership gate while a narrower operator opt-in prefix
                # (DEFENSECLAW_TRUSTED_BIN_PREFIXES) still matches — keep
                # scanning instead of rejecting early.
                continue
            return True
    return False


def _version_for_binary(
    binary_path: str,
    version_args: tuple[str, ...],
    *,
    require_trusted_binary_paths: bool = True,
    data_dir: str | os.PathLike[str] | None = None,
) -> tuple[str, str]:
    # M-4: the value of ``binary_path`` is sourced from
    # ``shutil.which(binary_name)`` which honours $PATH — an attacker
    # who can prepend a hostile directory to PATH can otherwise have us
    # exec their binary as part of a passive discovery scan. Refuse
    # anything outside the canonical install prefixes.
    if require_trusted_binary_paths and not _is_trusted_binary_path(binary_path, data_dir=data_dir):
        return "", UNTRUSTED_PREFIX_ERROR
    binary_name = os.path.basename(binary_path).lower()
    env = None
    timeout = VERSION_TIMEOUT_SECONDS
    if binary_name in {"hermes", "openhands"}:
        timeout = 8.0
    if binary_name == "openhands":
        env = {**os.environ, "OPENHANDS_SUPPRESS_BANNER": "1"}

    try:
        result = subprocess.run(
            [binary_path, *(version_args or ("--version",))],
            shell=False,
            timeout=timeout,
            capture_output=True,
            text=True,
            env=env,
        )
    except subprocess.TimeoutExpired:
        return "", "version probe timed out"
    except Exception as exc:
        return "", f"version probe failed: {exc}"

    stdout = (result.stdout or "").strip()
    if result.returncode != 0:
        detail = (result.stderr or stdout or "").strip()
        if detail:
            return "", f"version probe exited {result.returncode}: {detail}"
        return "", f"version probe exited {result.returncode}"
    if not stdout:
        return "", "version probe returned empty stdout"
    return _version_line_for_binary(binary_path, stdout), ""


def _version_line_for_binary(binary_path: str, stdout: str) -> str:
    lines = [line.strip() for line in stdout.splitlines() if line.strip()]
    if not lines:
        return ""
    binary_name = os.path.basename(binary_path).lower()
    if binary_name == "openhands":
        for line in reversed(lines):
            if "openhands cli" in line.lower():
                return line
    return lines[0]


def _first_existing_path(candidates: tuple[str, ...]) -> str:
    for candidate in candidates:
        path = os.path.abspath(_expand(candidate))
        if os.path.isfile(path) or os.path.isdir(path):
            return path
    return ""


def _which(binary_name: str) -> str:
    if not binary_name:
        return ""
    path = shutil.which(binary_name)
    if not path:
        return ""
    return os.path.abspath(path)


def _read_cache(*, data_dir: str | os.PathLike[str] | None = None) -> AgentDiscovery | None:
    path = _cache_path(data_dir=data_dir)
    try:
        with open(path, encoding="utf-8") as fh:
            payload = json.load(fh)
    except Exception:
        return None

    if payload.get("version") != CACHE_SCHEMA_VERSION:
        return None
    if int(payload.get("ttl_seconds", 0) or 0) != CACHE_TTL_SECONDS:
        return None

    scanned_at = str(payload.get("scanned_at") or "")
    scanned_dt = _parse_rfc3339(scanned_at)
    if scanned_dt is None:
        return None
    if _now_utc() - scanned_dt > timedelta(seconds=CACHE_TTL_SECONDS):
        return None

    raw_agents = payload.get("agents")
    if not isinstance(raw_agents, dict):
        return None

    agents: dict[str, AgentSignal] = {}
    try:
        # Legacy caches predate the discovery-only agent expansion
        # (KNOWN_AGENT_KINDS vs KNOWN_CONNECTORS). A missing entry for a
        # freshly-added agent is a normal upgrade case, not a corrupt
        # cache — treat it as "not installed" so we don't invalidate the
        # entire cache on first read after upgrade. A missing entry for
        # an *enforcement* connector (KNOWN_CONNECTORS) is still a
        # corruption signal and rejects the cache.
        for name in KNOWN_AGENT_KINDS:
            if name not in raw_agents:
                # Discovery-only kinds may legitimately be missing from a
                # pre-KNOWN_AGENT_KINDS cache written by an older CLI.
                # Synthesize a "not installed" default so we don't force
                # a rescan for every upgraded host on first read after
                # bump. Absence for an enforcement connector is still a
                # corruption signal — reject the cache and let the caller
                # re-scan.
                if name in KNOWN_CONNECTORS:
                    return None
                agents[name] = AgentSignal(
                    name=name,
                    installed=False,
                    config_path="",
                    binary_path="",
                    version="",
                    error="",
                )
                continue
            raw = raw_agents[name]
            if not isinstance(raw, dict):
                # Entry exists but isn't a dict — that's real corruption
                # (a scalar / null where a nested object was expected),
                # not the legacy-cache-missing-a-new-kind case above.
                # Reject the whole cache and rescan.
                return None
            agents[name] = AgentSignal(
                name=str(raw.get("name") or name),
                installed=bool(raw.get("installed")),
                config_path=str(raw.get("config_path") or ""),
                binary_path=str(raw.get("binary_path") or ""),
                version=str(raw.get("version") or ""),
                error=str(raw.get("error") or ""),
                # ``source`` was added when the multi-install discovery
                # path landed; legacy caches don't carry it, hence the
                # empty default. Not a corruption signal — just an
                # older cache.
                source=str(raw.get("source") or ""),
            )
    except Exception:
        return None

    return AgentDiscovery(scanned_at=scanned_at, agents=agents, cache_hit=True)


def _write_cache(
    disc: AgentDiscovery,
    *,
    data_dir: str | os.PathLike[str] | None = None,
) -> None:
    target_dir = Path(data_dir) if data_dir else default_data_path()
    path = _cache_path(data_dir=target_dir)
    tmp_path = ""
    try:
        os.makedirs(target_dir, mode=0o700, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(
            prefix=".agent_discovery.",
            suffix=".tmp",
            dir=target_dir,
        )
        payload = {
            "version": CACHE_SCHEMA_VERSION,
            "scanned_at": disc.scanned_at,
            "ttl_seconds": CACHE_TTL_SECONDS,
            "agents": {name: asdict(signal) for name, signal in disc.agents.items()},
        }
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, sort_keys=True)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, path)
        tmp_path = ""
    except Exception:
        pass
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


def _cache_path(*, data_dir: str | os.PathLike[str] | None = None) -> Path:
    return (Path(data_dir) if data_dir else default_data_path()) / CACHE_FILENAME


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _format_rfc3339(ts: datetime) -> str:
    return ts.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _parse_rfc3339(value: str) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return None


def _normalize_connector(value: str | None) -> str:
    if not value:
        return ""
    name = value.strip().lower()
    if name in {"claude-code", "claude_code", "claude"}:
        return "claudecode"
    if name in {"open-hands", "open_hands"}:
        return "openhands"
    return name


def _ordered_connector_names(disc: AgentDiscovery) -> list[str]:
    names: list[str] = []
    for name in DISCOVERY_PRECEDENCE:
        if name in disc.agents:
            names.append(name)
    for name in KNOWN_AGENT_KINDS:
        if name in disc.agents and name not in names:
            names.append(name)
    return names


def _display_path(path: str) -> str:
    return path or "-"


def _render_plain_table(disc: AgentDiscovery) -> str:
    lines = ["Agent discovery (cached)" if disc.cache_hit else "Agent discovery"]
    lines.append("connector | installed | config | binary | version/error")
    for name in _ordered_connector_names(disc):
        signal = disc.agents[name]
        lines.append(
            " | ".join(
                [
                    signal.name,
                    "yes" if signal.installed else "no",
                    _display_path(signal.config_path),
                    _display_path(signal.binary_path),
                    signal.version or signal.error,
                ]
            )
        )
    return "\n".join(lines) + "\n"
