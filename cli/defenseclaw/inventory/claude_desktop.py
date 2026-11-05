# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Claude Desktop on this account: its data folders, the Claude Code engine
builds it keeps there, and the Claude Desktop block of an AI discovery signal.

``CLAUDE_DESKTOP_ROOTS`` is the Python copy of the Go table
``internal/claudedesktop/roots.json`` (tests pin it). ``setup cowork`` and the
Cowork row ask it whether Claude Desktop is here; agent discovery asks it for
the engine builds (``claude_desktop_engines``), which count as a Claude Code
installation for an account that has Claude Desktop and no ``claude`` CLI
(cowork-1-0-8 GAP-0036).

``ClaudeDesktopInfo`` mirrors ``ClaudeDesktopInfo`` in
``internal/inventory/ai_discovery_claude_desktop.go``. The gateway sends it as
``claude_desktop`` on the ``claude_desktop`` signal of each user's Claude
Desktop data folder; ``defenseclaw agent usage --detail`` and the TUI render it
with :meth:`ClaudeDesktopInfo.summary`.
"""

from __future__ import annotations

import glob
import os
import re
import stat
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

# Claude Desktop's per-user data folders, one per deployment and install:
# (deployment, base, path below base). "1p" is signed in to Claude, "3p" is
# third-party inference (Bedrock, Vertex AI, Foundry), which keeps its own
# folder (Claude-3p). The source is the Go table
# internal/claudedesktop/roots.json; tests/test_cowork_setup.py pins this
# copy to it.
CLAUDE_DESKTOP_ROOTS: dict[str, tuple[tuple[str, str, str], ...]] = {
    "darwin": (
        ("1p", "home", "Library/Application Support/Claude"),
        ("3p", "home", "Library/Application Support/Claude-3p"),
    ),
    "linux": (
        ("1p", "config", "Claude"),
        ("3p", "config", "Claude-3p"),
    ),
    "windows": (
        ("1p", "appdata", "Claude"),
        ("1p", "localappdata", "Claude-Data/claude_*"),
        ("1p", "localappdata", "Packages/Claude_*/LocalCache/Roaming/Claude"),
        ("3p", "localappdata", "Claude-3p"),
        ("3p", "localappdata", "Packages/Claude_*/LocalCache/Local/Claude-3p"),
    ),
}

#: The paths one root with a "*" expands to (Go claudedesktop.MaxGlobMatches).
GLOB_MAX = 4

#: The folder under a data folder that holds the engine builds,
#: <data>/claude-code/<version>/... (Go claudedesktop.EngineFolder).
ENGINE_FOLDER = "claude-code"

#: Version folders read per engine folder, newest first (Go
#: unixDesktopEngineCandidatesMax).
ENGINE_VERSIONS_MAX = 4

#: Build folders searched in one version folder (Go
#: unixDesktopEngineBundlesMax, linuxEngineBuildsMax).
ENGINE_BUILDS_MAX = 4

# Entries read from one engine or version folder (Go unixVersionDirsMax).
_ENTRIES_MAX = 4096

# A version folder is dotted numbers ("2.1.317"); anything else in the
# engine folder (claude-code-vm is a sibling, not a child) is not a build.
_VERSION_FOLDER = re.compile(r"^[0-9]{1,9}(?:\.[0-9]{1,9}){1,3}$")

# The engine executable below a build folder, per OS (measured layouts:
# macOS <v>/<build>/claude.app, Windows <v>/<build>/claude.exe; Linux
# <v>/claude or <v>/<build>/claude, Go claudedesktop.LinuxEngineExecutable).
_ENGINE_EXECUTABLE = {
    "darwin": ("claude.app", "Contents", "MacOS", "claude"),
    "windows": ("claude.exe",),
    "linux": ("claude",),
}


def desktop_platform() -> str:
    """This host as a key of ``CLAUDE_DESKTOP_ROOTS``."""
    if sys.platform == "darwin":
        return "darwin"
    if os.name == "nt":
        return "windows"
    return "linux"


def _xdg_config_home(home: str) -> str:
    """$XDG_CONFIG_HOME when absolute, else ~/.config.

    The XDG Base Directory specification says a relative value is invalid
    and must be ignored; the Go side (claudedesktop.FoldersFromEnv) does the
    same.
    """
    value = os.environ.get("XDG_CONFIG_HOME", "").strip()
    return value if os.path.isabs(value) else os.path.join(home, ".config")


def _data_dirs(platform: str) -> list[tuple[str, str]]:
    """(deployment, folder) of every data folder of this account, table order."""
    home = os.path.expanduser("~")
    bases = {
        "home": home,
        "config": _xdg_config_home(home),
        "appdata": os.environ.get("APPDATA", ""),
        "localappdata": os.environ.get("LOCALAPPDATA", ""),
    }
    dirs: list[tuple[str, str]] = []
    for deployment, base, rel in CLAUDE_DESKTOP_ROOTS.get(platform, ()):
        root = bases.get(base, "")
        if not root or not os.path.isabs(root):
            continue
        path = os.path.join(root, *rel.split("/"))
        for found in sorted(glob.glob(path))[:GLOB_MAX] if "*" in rel else [path]:
            dirs.append((deployment, found))
    return dirs


def claude_desktop_data_dirs(platform: str | None = None) -> list[str]:
    """This account's Claude Desktop data folders (a "*" only where one exists)."""
    return [path for _deployment, path in _data_dirs(platform or desktop_platform())]


@dataclass(frozen=True)
class EngineBuild:
    """One Claude Code engine build Claude Desktop keeps for this account."""

    #: The engine executable.
    path: str
    #: The name of its version folder ("2.1.317").
    version: str
    #: "1p" or "3p", from the data folder it is in.
    deployment: str


def _version_key(name: str) -> tuple[int, ...]:
    return tuple(int(part) for part in name.split("."))


def _list_dir(path: str, limit: int) -> list[os.DirEntry[str]]:
    """At most ``limit`` entries of a real folder (not a link); [] otherwise."""
    try:
        if not stat.S_ISDIR(os.lstat(path).st_mode):
            return []
        entries: list[os.DirEntry[str]] = []
        with os.scandir(path) as it:
            for entry in it:
                if len(entries) >= limit:
                    break
                entries.append(entry)
        return entries
    except OSError:
        return []


def _real_executable(path: str, platform: str) -> bool:
    """A regular file that is not a link (nor a Windows reparse point), with an
    execute bit outside Windows. Reads the mode only."""
    try:
        info = os.lstat(path)
    except OSError:
        return False
    if not stat.S_ISREG(info.st_mode):
        return False
    if getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400):
        return False
    return platform == "windows" or bool(info.st_mode & 0o111)


def _version_folder_engines(platform: str, version_dir: str) -> list[str]:
    """The engine executables of one version folder: the folder itself first,
    then its build folders in name order (at most ENGINE_BUILDS_MAX), as the
    Go side checks them."""
    relative = _ENGINE_EXECUTABLE.get(platform)
    if relative is None:
        return []
    builds = sorted(entry.name for entry in _list_dir(version_dir, 64) if entry.is_dir(follow_symlinks=False))
    found: list[str] = []
    for folder in (version_dir, *(os.path.join(version_dir, name) for name in builds[:ENGINE_BUILDS_MAX])):
        if platform == "darwin":
            bundle = os.path.join(folder, relative[0])
            try:
                if not stat.S_ISDIR(os.lstat(bundle).st_mode):
                    continue
            except OSError:
                continue
        candidate = os.path.join(folder, *relative)
        if _real_executable(candidate, platform):
            found.append(candidate)
    return found


def claude_desktop_engines(platform: str | None = None) -> list[EngineBuild]:
    """Every Claude Code engine build in this account's Claude Desktop data
    folders (every root of the table: 1p, 3p, the Windows MSIX folders),
    newest version first; for one version, the later folder of the table
    (3p after 1p).

    It reads folder names and file modes only and runs nothing. A build
    found here is not identified by its folder (the folder is the user's
    own): the caller cross-checks its version (agent discovery: Info.plist on
    macOS, the file version on Windows, then ``--version``).
    """
    platform = platform or desktop_platform()
    ranked: list[tuple[tuple[tuple[int, ...], int, int], EngineBuild]] = []
    for folder_index, (deployment, data_dir) in enumerate(_data_dirs(platform)):
        engine_dir = os.path.join(data_dir, ENGINE_FOLDER)
        versions = sorted(
            (
                entry.name
                for entry in _list_dir(engine_dir, _ENTRIES_MAX)
                if _VERSION_FOLDER.match(entry.name) and entry.is_dir(follow_symlinks=False)
            ),
            key=_version_key,
            reverse=True,
        )[:ENGINE_VERSIONS_MAX]
        for version in versions:
            paths = _version_folder_engines(platform, os.path.join(engine_dir, version))
            for build_index, path in enumerate(paths):
                # -build_index: within one version folder, the Go check order.
                rank = (_version_key(version), folder_index, -build_index)
                ranked.append((rank, EngineBuild(path=path, version=version, deployment=deployment)))
    # For one version the later data folder of the table comes first, as the
    # gateway picks it (enterprisehooks.ClaudeDesktopEngineVersion): 3p
    # folders follow the 1p ones, and an account that has both (measured on
    # the Cowork Mac) was set up for third-party inference after it used
    # Claude, so Claude Desktop runs the 3p folder's engine.
    return [build for _rank, build in sorted(ranked, key=lambda item: item[0], reverse=True)]


_UNITS = ("B", "KiB", "MiB", "GiB", "TiB")


def format_bytes(size: int) -> str:
    """``12.2 GiB``-style size; whole bytes below 1 KiB."""
    value = float(max(size, 0))
    unit = 0
    while value >= 1024 and unit < len(_UNITS) - 1:
        value /= 1024
        unit += 1
    return f"{int(value)} B" if unit == 0 else f"{value:.1f} {_UNITS[unit]}"


_DEPLOYMENTS = {"1p": "Claude account", "3p": "third-party inference"}


@dataclass(frozen=True)
class ClaudeDesktopInfo:
    installed: bool = False
    installed_source: str = ""
    version: str = ""
    # None is "unknown": the gateway never guesses true.
    cowork_enabled: bool | None = None
    cowork_enabled_source: str = ""
    engine_version: str = ""
    vm_bundle_present: bool = False
    vm_bundle_bytes: int = 0
    cowork_plugins: tuple[str, ...] = ()
    # "1p" (signed in to Claude) or "3p" (third-party inference: Bedrock,
    # Vertex AI, Foundry); each has its own data folder.
    deployment: str = ""

    @classmethod
    def from_mapping(cls, raw: Any) -> ClaudeDesktopInfo | None:
        if not isinstance(raw, Mapping) or not raw:
            return None
        enabled = raw.get("cowork_enabled")
        plugins = raw.get("cowork_plugins")
        deployment = raw.get("deployment")
        try:
            size = int(raw.get("vm_bundle_bytes") or 0)
        except (TypeError, ValueError, OverflowError):
            size = 0
        return cls(
            installed=raw.get("installed") is True,
            installed_source=str(raw.get("installed_source") or ""),
            version=str(raw.get("version") or ""),
            cowork_enabled=enabled if isinstance(enabled, bool) else None,
            cowork_enabled_source=str(raw.get("cowork_enabled_source") or ""),
            engine_version=str(raw.get("engine_version") or ""),
            vm_bundle_present=raw.get("vm_bundle_present") is True,
            vm_bundle_bytes=max(size, 0),
            cowork_plugins=tuple(str(p) for p in plugins if p) if isinstance(plugins, (list, tuple)) else (),
            deployment=deployment if isinstance(deployment, str) and deployment in _DEPLOYMENTS else "",
        )

    def summary(self) -> str:
        """One line: app, engine, Cowork, VM bundle, plugins."""
        if self.installed:
            app = f"app {self.version}" if self.version else "app installed"
        else:
            app = "app not found"
        parts = [app]
        if self.deployment:
            parts.append(_DEPLOYMENTS[self.deployment])
        if self.engine_version:
            parts.append(f"engine {self.engine_version}")
        if self.cowork_enabled is None:
            parts.append("cowork unknown")
        else:
            state = "on" if self.cowork_enabled else "off"
            source = f" ({self.cowork_enabled_source})" if self.cowork_enabled_source else ""
            parts.append(f"cowork {state}{source}")
        if self.vm_bundle_present:
            size = f" {format_bytes(self.vm_bundle_bytes)}" if self.vm_bundle_bytes else ""
            parts.append(f"vm bundle{size}")
        else:
            parts.append("no vm bundle")
        if self.cowork_plugins:
            parts.append("plugins " + ", ".join(self.cowork_plugins))
        return "; ".join(parts)
