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

from defenseclaw.config import default_data_path
from defenseclaw.connector_paths import KNOWN_CONNECTORS, _expand

CACHE_SCHEMA_VERSION = 1
CACHE_TTL_SECONDS = 86_400
CACHE_FILENAME = "agent_discovery.json"
VERSION_TIMEOUT_SECONDS = 2.0

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


_SPECS: dict[str, _AgentSpec] = {
    "codex": _AgentSpec(("~/.codex/config.toml",), "codex"),
    "claudecode": _AgentSpec(("~/.claude/settings.json", "~/.claude"), "claude"),
    "openclaw": _AgentSpec(("~/.openclaw/openclaw.json",), "openclaw"),
    "zeptoclaw": _AgentSpec(("~/.zeptoclaw/config.json",), "zeptoclaw"),
    "hermes": _AgentSpec(("~/.hermes/config.yaml",), ""),
    "cursor": _AgentSpec(("~/.cursor/hooks.json", "~/.cursor/mcp.json"), ""),
    "windsurf": _AgentSpec(
        (
            "~/.codeium/windsurf/hooks.json",
            "~/.codeium/windsurf/mcp_config.json",
            "~/.codeium/windsurf/mcp.json",
        ),
        "",
    ),
    "geminicli": _AgentSpec(("~/.gemini/settings.json",), ""),
    "copilot": _AgentSpec(
        (
            "~/.copilot/mcp-config.json",
            ".github/hooks/defenseclaw.json",
            ".github/mcp.json",
            ".mcp.json",
        ),
        "",
    ),
}


def discover_agents(*, use_cache: bool = True, refresh: bool = False) -> AgentDiscovery:
    """Return cached or freshly scanned local agent install signals."""
    if use_cache and not refresh:
        cached = _read_cache()
        if cached is not None:
            return cached

    scanned_at = _format_rfc3339(_now_utc())
    with ThreadPoolExecutor(max_workers=4) as pool:
        signals = list(pool.map(_scan_agent, KNOWN_CONNECTORS))
    agents = {signal.name: signal for signal in signals}
    discovery = AgentDiscovery(scanned_at=scanned_at, agents=agents, cache_hit=False)
    _write_cache(discovery)
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
    spec = _SPECS.get(name, _AgentSpec((), ""))
    config_path = _first_existing_path(spec.config_candidates)
    binary_path = _which(spec.binary_name) if spec.binary_name else ""
    version = ""
    error = ""
    version_ok = False

    if binary_path:
        version, error = _version_for_binary(binary_path)
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


def _version_for_binary(binary_path: str) -> tuple[str, str]:
    try:
        result = subprocess.run(
            [binary_path, "--version"],
            shell=False,
            timeout=VERSION_TIMEOUT_SECONDS,
            capture_output=True,
            text=True,
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
    return stdout.splitlines()[0].strip(), ""


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


def _read_cache() -> AgentDiscovery | None:
    path = _cache_path()
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


def _write_cache(disc: AgentDiscovery) -> None:
    data_dir = default_data_path()
    path = _cache_path()
    tmp_path = ""
    try:
        os.makedirs(data_dir, mode=0o700, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(prefix=".agent_discovery.", suffix=".tmp", dir=data_dir)
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


def _cache_path() -> Path:
    return default_data_path() / CACHE_FILENAME


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
            " | ".join([
                signal.name,
                "yes" if signal.installed else "no",
                _display_path(signal.config_path),
                _display_path(signal.binary_path),
                signal.version or signal.error,
            ])
        )
    return "\n".join(lines) + "\n"
