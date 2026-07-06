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

import json
import locale
import ntpath
import os
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from io import StringIO
from pathlib import Path
from typing import Any, NamedTuple

import yaml

# `grp` is POSIX-only. We import it lazily-but-at-module-load so the
# group-ownership check below can run without an inline import,
# while still keeping Windows hosts importable.
try:  # pragma: no cover - Windows path
    import grp as _grp
except ImportError:  # pragma: no cover - non-POSIX
    _grp = None  # type: ignore[assignment]

from defenseclaw.config import config_path_for_data_dir, default_data_path
from defenseclaw.connector_paths import (
    KNOWN_CONNECTORS,
    _expand,
    hermes_config_path,
    omnigent_config_path,
)
from defenseclaw.file_permissions import atomic_write_private_bytes

# Sentinel error returned by ``_version_for_binary`` when a connector
# binary resolves outside the trusted install prefixes. Callers (e.g.
# ``cmd_setup``) key off this exact value to decide whether to offer the
# "trust this directory" remediation, so it lives here as a shared
# constant rather than being duplicated as a string literal on both
# sides — if the wording ever changes, the consumer can't silently drift.
UNTRUSTED_PREFIX_ERROR = "binary path is not in a trusted install prefix"

# Version 3 separates a connector's on-disk configuration from a verified
# application installation.  Version 2 caches treated either signal as
# ``installed``, which produced false positives for observe-only connectors.
CACHE_SCHEMA_VERSION = 3
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
_TRUSTED_BIN_PREFIXES_DEFAULT_POSIX: tuple[str, ...] = (
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


def _windows_default_trusted_bin_prefixes() -> tuple[str, ...]:
    """Return narrow, documented Windows CLI installation roots.

    Do not trust ``%LOCALAPPDATA%`` or ``%APPDATA%`` wholesale: either root can
    contain unrelated executables.  These candidates are limited to the
    connector and package-manager bin directories used by supported Windows
    installers.  Admission still requires the real ACL checks below.
    """
    local_app_data = os.environ.get("LOCALAPPDATA", "")
    roaming_app_data = os.environ.get("APPDATA", "")
    home = os.path.expanduser("~")
    program_roots = tuple(
        path
        for path in (
            os.environ.get("ProgramFiles", ""),
            os.environ.get("ProgramFiles(x86)", ""),
        )
        if path
    )

    candidates: list[str] = []
    if local_app_data:
        candidates.extend(
            (
                os.path.join(local_app_data, "Programs", "OpenAI", "Codex", "bin"),
                # Codex Desktop installs its bundled native MCP executables
                # below this product-specific runtime root.  Never trust all
                # of LOCALAPPDATA; executable admission still validates the
                # full owner/DACL chain through this narrow prefix.
                os.path.join(local_app_data, "OpenAI", "Codex", "runtimes"),
                os.path.join(
                    local_app_data,
                    "hermes",
                    "hermes-agent",
                    "venv",
                    "Scripts",
                ),
                os.path.join(local_app_data, "agy", "bin"),
                os.path.join(local_app_data, "Programs", "antigravity"),
                os.path.join(local_app_data, "Programs", "cursor", "resources", "app", "bin"),
                os.path.join(local_app_data, "Programs", "Windsurf", "bin"),
                os.path.join(local_app_data, "Microsoft", "WinGet", "Links"),
                os.path.join(local_app_data, "pnpm"),
            )
        )
    if roaming_app_data:
        candidates.append(os.path.join(roaming_app_data, "npm"))
    if home:
        candidates.extend(
            (
                os.path.join(home, ".local", "bin"),
                os.path.join(home, ".opencode", "bin"),
                os.path.join(home, "scoop", "shims"),
            )
        )
    for root in program_roots:
        candidates.extend(
            (
                os.path.join(root, "OpenAI", "Codex", "bin"),
                os.path.join(root, "cursor", "resources", "app", "bin"),
                os.path.join(root, "Windsurf", "bin"),
            )
        )
    return tuple(candidates)


_TRUSTED_BIN_PREFIXES_DEFAULT: tuple[str, ...] = (
    _windows_default_trusted_bin_prefixes()
    if os.name == "nt"
    else _TRUSTED_BIN_PREFIXES_DEFAULT_POSIX
)


def _builtin_trusted_bin_prefixes() -> tuple[str, ...]:
    """Resolve identity-dependent Windows defaults at point of use."""
    if os.name == "nt":
        return _windows_default_trusted_bin_prefixes()
    return _TRUSTED_BIN_PREFIXES_DEFAULT_POSIX


_WINDOWS_EXECUTABLE_EXTENSIONS = frozenset({".com", ".exe", ".bat", ".cmd"})

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
    configured: bool = False
    active: bool = False
    mode: str = ""


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
    "claudecode": _AgentSpec(
        (
            "~/.claude/settings.json",
            "~/.claude.json",
            ".claude/settings.json",
            ".claude/settings.local.json",
        ),
        "claude",
        ("--version",),
    ),
    "openclaw": _AgentSpec(("~/.openclaw/openclaw.json",), "openclaw", ("--version",)),
    "zeptoclaw": _AgentSpec(("~/.zeptoclaw/config.json",), "zeptoclaw", ("--version",)),
    # Hermes' path is resolved dynamically in _scan_agent so HERMES_HOME and
    # the native Windows %LOCALAPPDATA% default are honored.
    "hermes": _AgentSpec((), "hermes", ("--version",)),
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
        (
            ".openhands/hooks.json",
            "~/.openhands/hooks.json",
            "~/.openhands/mcp.json",
            "~/.openhands/settings.json",
            "~/.openhands/agent_settings.json",
            "~/.openhands/cli_config.json",
        ),
        "openhands",
        ("--version",),
    ),
    "antigravity": _AgentSpec(
        # agy v1.0.x reads PreToolUse hooks from ~/.gemini/config/
        # hooks.json (the canonical runtime path). The legacy
        # ~/.gemini/antigravity-cli/hooks.json file remains a legacy
        # signal, but the parent directory alone is not installation
        # evidence: other tools can create empty plugin/skill folders.
        (
            "~/.gemini/config/hooks.json",
            "~/.gemini/antigravity-cli/hooks.json",
        ),
        "agy",
        ("--version",),
    ),
    "opencode": _AgentSpec(
        # opencode auto-loads plugins from ~/.config/opencode/plugins/;
        # DefenseClaw installs its bridge there. opencode.json / the
        # documented JSON/JSONC files are also signals the agent is present.
        # Bare config directories are deliberately not evidence.
        (
            "~/.config/opencode/plugins/defenseclaw.js",
            "~/.config/opencode/opencode.json",
            "~/.config/opencode/opencode.jsonc",
            "~/.config/opencode/tui.json",
            "~/.config/opencode/tui.jsonc",
            "opencode.json",
            "opencode.jsonc",
            ".opencode/plugins/defenseclaw.js",
        ),
        "opencode",
        ("--version",),
    ),
    "omnigent": _AgentSpec(
        ("~/.omnigent/config.yaml",),
        "omnigent",
        ("--version",),
    ),
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
    with ThreadPoolExecutor(max_workers=4) as pool:
        signals = list(
            pool.map(
                lambda name: _scan_agent(
                    name,
                    data_dir=data_dir,
                    require_trusted_binary_paths=require_trusted,
                ),
                KNOWN_CONNECTORS,
            )
        )
    agents = {signal.name: signal for signal in signals}
    discovery = AgentDiscovery(scanned_at=scanned_at, agents=agents, cache_hit=False)
    # Cache persistence is deliberately best-effort: the freshly computed
    # discovery result is authoritative and must still be returned when the
    # optional acceleration cache cannot be protected or written.
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


def apply_config_state(disc: AgentDiscovery, cfg: Any) -> AgentDiscovery:
    """Add DefenseClaw's active connector state to discovery signals.

    Application discovery and DefenseClaw configuration are intentionally
    separate sources of truth.  The filesystem scan determines whether an
    application is installed and whether a meaningful connector config file
    exists; ``config.yaml`` determines which connectors the operator selected
    and their effective observe/action modes.
    """
    try:
        active = {
            _normalize_connector(str(name))
            for name in cfg.active_connectors()
            if str(name).strip()
        }
    except (AttributeError, TypeError):
        active = set()

    guardrail = getattr(cfg, "guardrail", None)
    for name, signal in disc.agents.items():
        normalized = _normalize_connector(name)
        signal.active = normalized in active
        signal.mode = ""
        if not signal.active or guardrail is None:
            continue
        try:
            mode = guardrail.effective_mode(normalized)
        except (AttributeError, TypeError):
            mode = getattr(guardrail, "mode", "")
        normalized_mode = str(mode or "observe").strip().lower()
        signal.mode = normalized_mode if normalized_mode in {"observe", "action"} else "observe"
    return disc


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
    table.add_column("Configured")
    table.add_column("Active / Mode")
    table.add_column("Config")
    table.add_column("Binary")
    table.add_column("Version / Error")

    for name in _ordered_connector_names(disc):
        signal = disc.agents[name]
        detail = signal.version or signal.error
        table.add_row(
            signal.name,
            "yes" if signal.installed else "no",
            "yes" if signal.configured else "no",
            signal.mode if signal.active else "no",
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
) -> AgentSignal:
    spec = _SPECS.get(name, _AgentSpec((), "", ("--version",)))
    config_candidates = spec.config_candidates
    if name == "hermes":
        config_candidates = (hermes_config_path(),)
    elif name == "omnigent":
        config_path = omnigent_config_path()
        config_candidates = (config_path,)
    config_path = _first_existing_file(config_candidates)
    binary_path = _binary_path_for_agent(name, spec)
    version = ""
    error = ""
    version_ok = False

    if binary_path:
        version, error = _version_for_agent_binary(
            name,
            binary_path,
            spec.version_args,
            require_trusted_binary_paths=require_trusted_binary_paths,
            data_dir=data_dir,
        )
        version_ok = bool(version) and not error

    installed = bool(binary_path) and version_ok
    return AgentSignal(
        name=name,
        installed=installed,
        config_path=config_path,
        binary_path=binary_path,
        version=version,
        error=error,
        configured=bool(config_path),
    )


def _ai_discovery_trust_config(
    data_dir: str | os.PathLike[str] | None = None,
) -> tuple[bool, tuple[str, ...]]:
    """Return ``(require_trusted_paths, config_prefixes)`` from config.yaml."""
    path = config_path_for_data_dir(data_dir)
    try:
        with open(path, encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}
    except OSError:
        raw = {}
    if not isinstance(raw, dict):
        return False, ()
    block = raw.get("ai_discovery")
    if not isinstance(block, dict):
        return False, ()
    prefixes = tuple(str(v).strip() for v in (block.get("trusted_binary_prefixes", []) or []) if str(v).strip())
    return bool(block.get("require_trusted_binary_paths", False)), prefixes


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
    return tuple(_expand_bin_prefixes((*_builtin_trusted_bin_prefixes(), *extras)))


def _path_key(path: str) -> str:
    """Return the platform comparison key for an already-absolute path."""
    return os.path.normcase(os.path.normpath(path))


def _is_filesystem_root(path: str) -> bool:
    anchor = Path(path).anchor
    return bool(anchor) and _path_key(path) == _path_key(anchor)


def _path_is_within(path: str, prefix: str) -> bool:
    """Compare canonical paths with component and Windows case semantics."""
    path_key = _path_key(path)
    prefix_key = _path_key(prefix)
    try:
        return os.path.commonpath((path_key, prefix_key)) == prefix_key
    except ValueError:
        # Different Windows drives (or a malformed path) have no common path.
        return False


def _expand_bin_prefixes(prefixes: tuple[str, ...]) -> list[str]:
    expanded: list[str] = []
    seen: set[str] = set()
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
        if _is_filesystem_root(absolute):
            continue
        key = _path_key(absolute)
        if not key or key in seen:
            continue
        seen.add(key)
        expanded.append(absolute)
    return expanded


def _default_trusted_bin_prefixes() -> frozenset[str]:
    """The absolutised built-in (non-operator-supplied) trusted prefixes.

    These are the prefixes we trust *by default*, without an operator
    opting in via ``DEFENSECLAW_TRUSTED_BIN_PREFIXES``. They get a stricter
    ownership requirement (see ``_is_trusted_binary_path``).
    """
    return frozenset(_expand_bin_prefixes(_builtin_trusted_bin_prefixes()))


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


def _windows_acl_snapshot(path: str) -> tuple[str, bool, list[tuple[int, int, int, str]]]:
    """Return ``(owner_sid, null_dacl, access_entries)`` for *path*.

    ``os.stat().st_mode`` on Windows is synthesized from DOS attributes and
    cannot answer who may replace an executable.  Read the owner and DACL from
    the Win32 security descriptor instead.  The ctypes declarations stay
    local so importing this module remains safe on Unix.
    """
    if os.name != "nt":  # pragma: no cover - guarded by Windows callers
        raise OSError("Windows ACLs are unavailable on this platform")

    import ctypes  # noqa: PLC0415
    from ctypes import wintypes  # noqa: PLC0415

    class _TrusteeW(ctypes.Structure):
        pass

    _TrusteeW._fields_ = [
        ("pMultipleTrustee", ctypes.POINTER(_TrusteeW)),
        ("MultipleTrusteeOperation", wintypes.DWORD),
        ("TrusteeForm", wintypes.DWORD),
        ("TrusteeType", wintypes.DWORD),
        # For TRUSTEE_IS_SID this is a PSID, not a string pointer.
        ("ptstrName", ctypes.c_void_p),
    ]

    class _ExplicitAccessW(ctypes.Structure):
        _fields_ = [
            ("grfAccessPermissions", wintypes.DWORD),
            ("grfAccessMode", wintypes.DWORD),
            ("grfInheritance", wintypes.DWORD),
            ("Trustee", _TrusteeW),
        ]

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    get_security = advapi32.GetNamedSecurityInfoW
    get_security.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
    ]
    get_security.restype = wintypes.DWORD

    get_entries = advapi32.GetExplicitEntriesFromAclW
    get_entries.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.ULONG),
        ctypes.POINTER(ctypes.POINTER(_ExplicitAccessW)),
    ]
    get_entries.restype = wintypes.DWORD

    sid_to_string = advapi32.ConvertSidToStringSidW
    sid_to_string.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    sid_to_string.restype = wintypes.BOOL

    local_free = kernel32.LocalFree
    local_free.argtypes = [ctypes.c_void_p]
    local_free.restype = ctypes.c_void_p

    def _sid_string(sid: int | None) -> str:
        if not sid:
            return ""
        value = wintypes.LPWSTR()
        if not sid_to_string(ctypes.c_void_p(sid), ctypes.byref(value)):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            return value.value or ""
        finally:
            local_free(ctypes.cast(value, ctypes.c_void_p))

    owner = ctypes.c_void_p()
    dacl = ctypes.c_void_p()
    descriptor = ctypes.c_void_p()
    # SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION
    result = get_security(
        path,
        1,
        0x00000001 | 0x00000004,
        ctypes.byref(owner),
        None,
        ctypes.byref(dacl),
        None,
        ctypes.byref(descriptor),
    )
    if result:
        raise OSError(result, ctypes.FormatError(result), path)

    entries_ptr = ctypes.POINTER(_ExplicitAccessW)()
    try:
        owner_sid = _sid_string(owner.value)
        if not dacl.value:
            return owner_sid, True, []

        count = wintypes.ULONG()
        result = get_entries(dacl, ctypes.byref(count), ctypes.byref(entries_ptr))
        if result:
            raise OSError(result, ctypes.FormatError(result), path)

        entries: list[tuple[int, int, int, str]] = []
        for index in range(count.value):
            entry = entries_ptr[index]
            # GetExplicitEntriesFromAcl normally returns SID trustees.  An
            # unknown form with write rights is retained as an empty identity
            # and rejected conservatively by the caller.
            sid = (
                _sid_string(entry.Trustee.ptstrName)
                if entry.Trustee.TrusteeForm == 0
                else ""
            )
            entries.append(
                (
                    int(entry.grfAccessPermissions),
                    int(entry.grfAccessMode),
                    int(entry.grfInheritance),
                    sid,
                )
            )
        return owner_sid, False, entries
    finally:
        if entries_ptr:
            local_free(ctypes.cast(entries_ptr, ctypes.c_void_p))
        if descriptor.value:
            local_free(descriptor)


def _windows_acl_write_error(path: str) -> str | None:
    """Return a refusal when an untrusted Windows principal may write *path*."""
    try:
        owner_sid, null_dacl, entries = _windows_acl_snapshot(path)
    except OSError as exc:
        return f"cannot read Windows ACL ({exc})"

    if null_dacl:
        return "ACL grants write access to untrusted principal Everyone (null DACL)"

    # The object owner plus the two privileged Windows control principals may
    # retain write/full-control.  Other principals may read and execute, but
    # must not be able to replace the binary or change its DACL/owner.
    trusted_controllers = {
        "S-1-3-4",  # OWNER RIGHTS (the descriptor's owner only)
        "S-1-5-18",  # LocalSystem
        "S-1-5-32-544",  # BUILTIN\Administrators
    }
    if owner_sid:
        trusted_controllers.add(owner_sid)
    write_mask = (
        0x00000002  # FILE_WRITE_DATA / FILE_ADD_FILE
        | 0x00000004  # FILE_APPEND_DATA / FILE_ADD_SUBDIRECTORY
        | 0x00000010  # FILE_WRITE_EA
        | 0x00000040  # FILE_DELETE_CHILD
        | 0x00000100  # FILE_WRITE_ATTRIBUTES
        | 0x00010000  # DELETE
        | 0x00040000  # WRITE_DAC
        | 0x00080000  # WRITE_OWNER
        | 0x10000000  # GENERIC_ALL
        | 0x40000000  # GENERIC_WRITE
    )
    sid_labels = {
        "": "unknown trustee",
        "S-1-1-0": "Everyone",
        "S-1-3-0": "CREATOR OWNER",
        "S-1-5-11": "Authenticated Users",
        "S-1-5-32-545": "BUILTIN\\Users",
    }
    for permissions, access_mode, inheritance, sid in entries:
        # GRANT_ACCESS and SET_ACCESS are the allow modes emitted by
        # GetExplicitEntriesFromAcl.  Deny/audit entries do not grant writes.
        if access_mode not in (1, 2) or not (permissions & write_mask):
            continue
        if sid in trusted_controllers:
            continue
        # CREATOR OWNER on an inherit-only ACE becomes the already-trusted
        # owner of a newly created child; it grants nothing on this directory.
        if sid == "S-1-3-0" and inheritance & 0x08:  # INHERIT_ONLY_ACE
            continue
        principal = sid_labels.get(sid, sid)
        return f"ACL grants write access to untrusted principal {principal}"
    return None


def _windows_acl_chain_is_safe(resolved: str, prefix: str) -> bool:
    """Check the executable and every ancestor through its trusted prefix."""
    current = resolved
    prefix_key = _path_key(prefix)
    seen: set[str] = set()
    while current:
        key = _path_key(current)
        if key in seen:
            return False
        seen.add(key)
        if _windows_acl_write_error(current) is not None:
            return False
        if key == prefix_key:
            return True
        parent = os.path.dirname(current)
        if parent == current:
            return False
        current = parent
    return False


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
    mode_err = (
        _windows_acl_write_error(resolved)
        if os.name == "nt"
        else _trusted_prefix_dir_mode_error(st)
    )
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
    if os.name == "nt":
        if os.path.splitext(resolved)[1].lower() not in _WINDOWS_EXECUTABLE_EXTENSIONS:
            return False
    else:
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
        if _path_is_within(resolved, prefix):
            if os.name == "nt":
                if not _windows_acl_chain_is_safe(resolved, prefix):
                    continue
                return True
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


def _binary_command_name(binary_path: str) -> str:
    """Normalize a CLI basename, stripping Windows executable wrappers."""
    name = ntpath.basename(binary_path).lower()
    stem, extension = os.path.splitext(name)
    return stem if extension in _WINDOWS_EXECUTABLE_EXTENSIONS else name


def _decode_version_probe_output(output: bytes | str | None) -> str:
    """Decode CLI output without relying on the Windows ANSI code page.

    Modern CLIs commonly write UTF-8 to redirected stdout even when Python's
    preferred Windows text encoding is a legacy code page.  Decode UTF-8 first
    so multibyte punctuation remains intact, then preserve compatibility with
    older native tools by falling back to the host's preferred encoding.
    """

    if output is None:
        return ""
    if isinstance(output, str):
        # Test doubles and callers that already decoded the stream remain
        # supported; production probes request bytes below.
        return output

    encodings = ("utf-8-sig", locale.getpreferredencoding(False) or "utf-8")
    attempted: set[str] = set()
    for encoding in encodings:
        key = encoding.casefold().replace("_", "-")
        if key in attempted:
            continue
        attempted.add(key)
        try:
            return output.decode(encoding)
        except (LookupError, UnicodeDecodeError):
            continue
    return output.decode("utf-8", errors="replace")


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
    binary_name = _binary_command_name(binary_path)
    env = None
    timeout = VERSION_TIMEOUT_SECONDS
    if binary_name in {"claude", "hermes", "openhands"}:
        timeout = 8.0
    if binary_name == "openhands":
        env = {**os.environ, "OPENHANDS_SUPPRESS_BANNER": "1"}

    try:
        result = subprocess.run(
            [binary_path, *(version_args or ("--version",))],
            shell=False,
            timeout=timeout,
            capture_output=True,
            text=False,
            env=env,
        )
    except subprocess.TimeoutExpired:
        return "", "version probe timed out"
    except Exception as exc:
        return "", f"version probe failed: {exc}"

    stdout = _decode_version_probe_output(result.stdout).strip()
    stderr = _decode_version_probe_output(result.stderr).strip()
    if result.returncode != 0:
        detail = stderr or stdout
        if detail:
            return "", f"version probe exited {result.returncode}: {detail}"
        return "", f"version probe exited {result.returncode}"
    if not stdout:
        return "", "version probe returned empty stdout"
    return _version_line_for_binary(binary_path, stdout), ""


def _version_for_agent_binary(
    name: str,
    binary_path: str,
    version_args: tuple[str, ...],
    *,
    require_trusted_binary_paths: bool = True,
    data_dir: str | os.PathLike[str] | None = None,
) -> tuple[str, str]:
    """Probe a CLI, or read metadata for a GUI that must not be launched."""

    if name == "antigravity" and _binary_command_name(binary_path) == "antigravity":
        return _windows_file_version_for_binary(
            binary_path,
            require_trusted_binary_paths=require_trusted_binary_paths,
            data_dir=data_dir,
        )
    return _version_for_binary(
        binary_path,
        version_args,
        require_trusted_binary_paths=require_trusted_binary_paths,
        data_dir=data_dir,
    )


def _windows_file_version_for_binary(
    binary_path: str,
    *,
    require_trusted_binary_paths: bool = True,
    data_dir: str | os.PathLike[str] | None = None,
) -> tuple[str, str]:
    """Read trusted Windows executable version metadata without launching it."""

    if require_trusted_binary_paths and not _is_trusted_binary_path(binary_path, data_dir=data_dir):
        return "", UNTRUSTED_PREFIX_ERROR
    if os.name != "nt":
        return "", "Windows file-version metadata is unavailable on this host"

    try:
        import ctypes
        from ctypes import wintypes

        class _VSFixedFileInfo(ctypes.Structure):
            _fields_ = [
                ("signature", wintypes.DWORD),
                ("struct_version", wintypes.DWORD),
                ("file_version_ms", wintypes.DWORD),
                ("file_version_ls", wintypes.DWORD),
                ("product_version_ms", wintypes.DWORD),
                ("product_version_ls", wintypes.DWORD),
                ("file_flags_mask", wintypes.DWORD),
                ("file_flags", wintypes.DWORD),
                ("file_os", wintypes.DWORD),
                ("file_type", wintypes.DWORD),
                ("file_subtype", wintypes.DWORD),
                ("file_date_ms", wintypes.DWORD),
                ("file_date_ls", wintypes.DWORD),
            ]

        version_dll = ctypes.WinDLL("version", use_last_error=True)
        get_size = version_dll.GetFileVersionInfoSizeW
        get_size.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(wintypes.DWORD)]
        get_size.restype = wintypes.DWORD
        get_info = version_dll.GetFileVersionInfoW
        get_info.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID]
        get_info.restype = wintypes.BOOL
        query_value = version_dll.VerQueryValueW
        query_value.argtypes = [
            wintypes.LPCVOID,
            wintypes.LPCWSTR,
            ctypes.POINTER(wintypes.LPVOID),
            ctypes.POINTER(wintypes.UINT),
        ]
        query_value.restype = wintypes.BOOL

        ignored = wintypes.DWORD()
        size = int(get_size(binary_path, ctypes.byref(ignored)))
        if size <= 0:
            return "", "version metadata is unavailable"
        payload = ctypes.create_string_buffer(size)
        if not get_info(binary_path, 0, size, payload):
            return "", "version metadata could not be read"

        value = wintypes.LPVOID()
        value_size = wintypes.UINT()
        if not query_value(payload, "\\", ctypes.byref(value), ctypes.byref(value_size)):
            return "", "version metadata has no fixed version block"
        if value_size.value < ctypes.sizeof(_VSFixedFileInfo):
            return "", "version metadata fixed block is truncated"

        info = ctypes.cast(value, ctypes.POINTER(_VSFixedFileInfo)).contents
        if info.signature != 0xFEEF04BD:
            return "", "version metadata fixed block is invalid"
        parts = [
            info.file_version_ms >> 16,
            info.file_version_ms & 0xFFFF,
            info.file_version_ls >> 16,
            info.file_version_ls & 0xFFFF,
        ]
        while len(parts) > 3 and parts[-1] == 0:
            parts.pop()
        return ".".join(str(part) for part in parts), ""
    except (AttributeError, OSError, TypeError, ValueError) as exc:
        return "", f"version metadata probe failed: {exc}"


def _version_line_for_binary(binary_path: str, stdout: str) -> str:
    lines = [line.strip() for line in stdout.splitlines() if line.strip()]
    if not lines:
        return ""
    binary_name = _binary_command_name(binary_path)
    if binary_name == "openhands":
        for line in reversed(lines):
            if "openhands cli" in line.lower():
                return line
    return lines[0]


def _first_existing_file(candidates: tuple[str, ...]) -> str:
    """Return the first real config file; parent directories are not evidence."""

    for candidate in candidates:
        path = os.path.abspath(_expand(candidate))
        if os.path.isfile(path):
            return path
    return ""


def _which(binary_name: str) -> str:
    if not binary_name:
        return ""
    path = shutil.which(binary_name)
    if not path:
        return ""
    return os.path.abspath(path)


def _binary_path_for_agent(name: str, spec: _AgentSpec) -> str:
    """Resolve PATH first, then narrow documented connector locations."""

    if not spec.binary_name:
        return ""
    path = _which(spec.binary_name)
    if path or not _is_windows_host():
        return path

    for candidate in _windows_binary_candidates(name, spec.binary_name):
        if os.path.isfile(candidate):
            return os.path.abspath(candidate)

    if name != "antigravity":
        return ""

    local_app_data = os.environ.get("LOCALAPPDATA", "")
    if not local_app_data:
        return ""
    for candidate in (
        os.path.join(local_app_data, "agy", "bin", "agy.exe"),
        os.path.join(local_app_data, "Programs", "antigravity", "Antigravity.exe"),
    ):
        if os.path.isfile(candidate):
            return os.path.abspath(candidate)
    return ""


def _is_windows_host() -> bool:
    """Return whether native Windows lookup rules apply.

    Kept behind a helper so cross-platform tests can exercise documented
    Windows install locations without mutating ``os.name`` process-wide.
    """
    return os.name == "nt"


def _windows_binary_candidates(connector: str, binary_name: str) -> tuple[str, ...]:
    """Return exact-name candidates under this connector's Windows bin roots."""

    if not binary_name:
        return ()
    suffix = os.path.splitext(binary_name)[1]
    names = [binary_name] if suffix else [binary_name + ext for ext in (".exe", ".cmd", ".bat", ".com")]
    local_app_data = os.environ.get("LOCALAPPDATA", "")
    roaming_app_data = os.environ.get("APPDATA", "")
    home = os.path.expanduser("~")
    program_roots = [
        root
        for root in (os.environ.get("ProgramFiles", ""), os.environ.get("ProgramFiles(x86)", ""))
        if root
    ]

    prefixes: list[str] = []
    if local_app_data:
        prefixes.extend(
            (
                os.path.join(local_app_data, "Microsoft", "WinGet", "Links"),
                os.path.join(local_app_data, "pnpm"),
            )
        )
    if roaming_app_data:
        prefixes.append(os.path.join(roaming_app_data, "npm"))
    if home:
        prefixes.extend((os.path.join(home, ".local", "bin"), os.path.join(home, "scoop", "shims")))

    if connector == "codex" and local_app_data:
        prefixes.insert(0, os.path.join(local_app_data, "Programs", "OpenAI", "Codex", "bin"))
    elif connector == "hermes" and local_app_data:
        prefixes.insert(
            0,
            os.path.join(
                local_app_data,
                "hermes",
                "hermes-agent",
                "venv",
                "Scripts",
            ),
        )
    elif connector == "cursor" and local_app_data:
        prefixes.insert(0, os.path.join(local_app_data, "Programs", "cursor", "resources", "app", "bin"))
    elif connector == "windsurf" and local_app_data:
        prefixes.insert(0, os.path.join(local_app_data, "Programs", "Windsurf", "bin"))
    elif connector == "antigravity" and local_app_data:
        prefixes.insert(0, os.path.join(local_app_data, "agy", "bin"))
    elif connector == "opencode" and home:
        prefixes.insert(0, os.path.join(home, ".opencode", "bin"))

    for root in program_roots:
        if connector == "codex":
            prefixes.append(os.path.join(root, "OpenAI", "Codex", "bin"))
        elif connector == "cursor":
            prefixes.append(os.path.join(root, "cursor", "resources", "app", "bin"))
        elif connector == "windsurf":
            prefixes.append(os.path.join(root, "Windsurf", "bin"))

    candidates: list[str] = []
    for prefix in prefixes:
        for name in names:
            candidates.append(os.path.join(prefix, name))
    return tuple(candidates)


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
        for name in KNOWN_CONNECTORS:
            raw = raw_agents.get(name)
            if not isinstance(raw, dict):
                return None
            agents[name] = AgentSignal(
                name=str(raw.get("name") or name),
                installed=bool(raw.get("installed")),
                config_path=str(raw.get("config_path") or ""),
                binary_path=str(raw.get("binary_path") or ""),
                version=str(raw.get("version") or ""),
                error=str(raw.get("error") or ""),
                configured=bool(raw.get("configured")),
            )
    except Exception:
        return None

    return AgentDiscovery(scanned_at=scanned_at, agents=agents, cache_hit=True)


def _write_cache(
    disc: AgentDiscovery,
    *,
    data_dir: str | os.PathLike[str] | None = None,
) -> bool:
    target_dir = Path(data_dir) if data_dir else default_data_path()
    path = _cache_path(data_dir=target_dir)
    try:
        payload = {
            "version": CACHE_SCHEMA_VERSION,
            "scanned_at": disc.scanned_at,
            "ttl_seconds": CACHE_TTL_SECONDS,
            "agents": {name: asdict(signal) for name, signal in disc.agents.items()},
        }
        body = json.dumps(payload, indent=2, sort_keys=True) + "\n"
        atomic_write_private_bytes(path, body.encode("utf-8"))
        return True
    except (OSError, TypeError, ValueError):
        return False


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
    for name in KNOWN_CONNECTORS:
        if name in disc.agents and name not in names:
            names.append(name)
    return names


def _display_path(path: str) -> str:
    return path or "-"


def _render_plain_table(disc: AgentDiscovery) -> str:
    lines = ["Agent discovery (cached)" if disc.cache_hit else "Agent discovery"]
    lines.append(
        "connector | installed | configured | active/mode | config | binary | version/error"
    )
    for name in _ordered_connector_names(disc):
        signal = disc.agents[name]
        lines.append(
            " | ".join(
                [
                    signal.name,
                    "yes" if signal.installed else "no",
                    "yes" if signal.configured else "no",
                    signal.mode if signal.active else "no",
                    _display_path(signal.config_path),
                    _display_path(signal.binary_path),
                    signal.version or signal.error,
                ]
            )
        )
    return "\n".join(lines) + "\n"
