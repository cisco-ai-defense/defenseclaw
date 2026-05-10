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

# `grp` is POSIX-only. We import it lazily-but-at-module-load so the
# group-ownership check below can run without an inline import,
# while still keeping Windows hosts importable.
try:  # pragma: no cover - Windows path
    import grp as _grp
except ImportError:  # pragma: no cover - non-POSIX
    _grp = None  # type: ignore[assignment]

from defenseclaw.config import default_data_path
from defenseclaw.connector_paths import KNOWN_CONNECTORS, _expand

CACHE_SCHEMA_VERSION = 1
CACHE_TTL_SECONDS = 86_400
CACHE_FILENAME = "agent_discovery.json"
VERSION_TIMEOUT_SECONDS = 2.0

# M-4: canonical install prefixes that we trust enough to exec
# `<binary> --version` against. Anything outside this allow-list is
# refused — even when ``shutil.which`` returns it — because a user PATH
# entry pointing to /tmp, the current directory, or some other
# attacker-writable location could otherwise have us run a hostile
# binary as part of a passive discovery scan. Operators with bespoke
# install layouts can extend the allow-list at runtime via the
# ``DEFENSECLAW_TRUSTED_BIN_PREFIXES`` env var (colon-separated).
# the default trusted-prefix list previously included
# normal user-writable tool directories (~/.local/bin, ~/.cargo/bin,
# ~/.nvm, ~/.asdf, ~/.pyenv, ~/.pipx, ~/Library/Application Support,
# /Applications) and the only post-resolution check rejected
# *world-writable* parents. A local agent process that can write to
# the operator's tool dir could plant `codex` (or any other discovery
# target) and DefenseClaw's passive scan would exec it. We restrict
# the default list to system-managed prefixes that require root /
# package-manager privilege to write. Operators with bespoke install
# layouts can extend the list at runtime via
# ``DEFENSECLAW_TRUSTED_BIN_PREFIXES`` (colon-separated).
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
    "/opt/homebrew/lib/node_modules",
    "/usr/local/Cellar",
    "/usr/local/lib/node_modules",
    "/opt/local/bin",
    "/opt/local/sbin",
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
)


@dataclass
class AgentSignal:
    name: str
    installed: bool
    config_path: str
    binary_path: str
    version: str
    error: str


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
    with ThreadPoolExecutor(max_workers=4) as pool:
        signals = list(pool.map(_scan_agent, KNOWN_CONNECTORS))
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


def _scan_agent(name: str) -> AgentSignal:
    spec = _SPECS.get(name, _AgentSpec((), "", ("--version",)))
    config_path = _first_existing_path(spec.config_candidates)
    binary_path = _which(spec.binary_name) if spec.binary_name else ""
    version = ""
    error = ""
    version_ok = False

    if binary_path:
        version, error = _version_for_binary(binary_path, spec.version_args)
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


def _trusted_bin_prefixes() -> tuple[str, ...]:
    """Return the allow-list of canonical install prefixes.

    The defaults cover platform-package, Homebrew, MacPorts, and common
    user-scoped tooling (cargo, npm, pyenv, asdf, pipx, etc.). Operators
    can extend the list at runtime via ``DEFENSECLAW_TRUSTED_BIN_PREFIXES``
    (colon-separated). Each entry is tilde-expanded and absolutised
    before comparison.
    """
    extras: list[str] = []
    raw = os.environ.get("DEFENSECLAW_TRUSTED_BIN_PREFIXES", "")
    for piece in raw.split(":"):
        piece = piece.strip()
        if piece:
            extras.append(piece)
    expanded: list[str] = []
    for prefix in (*_TRUSTED_BIN_PREFIXES_DEFAULT, *extras):
        try:
            absolute = os.path.abspath(_expand(prefix))
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
    return tuple(expanded)


def _is_trusted_binary_path(binary_path: str) -> bool:
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
    prefixes = _trusted_bin_prefixes()
    for prefix in prefixes:
        # Both the resolved binary and the candidate need to share a
        # path-component boundary; suffix-string match would let
        # /usr/binEvil sneak past /usr/bin.
        if resolved == prefix:
            return True
        if resolved.startswith(prefix.rstrip(os.sep) + os.sep):
            return True
    return False


def _version_for_binary(binary_path: str, version_args: tuple[str, ...]) -> tuple[str, str]:
    # M-4: the value of ``binary_path`` is sourced from
    # ``shutil.which(binary_name)`` which honours $PATH — an attacker
    # who can prepend a hostile directory to PATH can otherwise have us
    # exec their binary as part of a passive discovery scan. Refuse
    # anything outside the canonical install prefixes.
    if not _is_trusted_binary_path(binary_path):
        return "", "binary path is not in a trusted install prefix"
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
    for name in KNOWN_CONNECTORS:
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
