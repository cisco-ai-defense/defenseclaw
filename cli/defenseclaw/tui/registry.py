"""Textual TUI command registry.

The command palette is a compatibility surface, not a new CLI. The
Python backend starts from the Go TUI registry port and keeps exact
TUI-name to argv mappings so existing operator muscle memory and docs
continue to work while panels migrate.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from defenseclaw.platform_support import (
    connector_supported_on_os,
    local_observability_stack_supported,
)
from defenseclaw.tui.registry_data import GO_PARITY_REGISTRY

CliBinary = Literal["defenseclaw", "defenseclaw-gateway"]

_SETUP_CONNECTOR_ALIASES: dict[str, str] = {
    "openclaw": "openclaw",
    "zeptoclaw": "zeptoclaw",
    "codex": "codex",
    "claude-code": "claudecode",
    "hermes": "hermes",
    "cursor": "cursor",
    "devin": "devin",
    "copilot": "copilot",
    "openhands": "openhands",
    "antigravity": "antigravity",
    "opencode": "opencode",
    "amp": "amp",
    "omnigent": "omnigent",
}


@dataclass(frozen=True)
class CmdEntry:
    tui_name: str
    cli_binary: CliBinary
    cli_args: tuple[str, ...]
    description: str
    category: str
    needs_arg: bool = False
    arg_hint: str = ""


def build_registry(os_name: str | None = None) -> tuple[CmdEntry, ...]:
    """Return the Go-compatible TUI command registry for this platform."""

    def available(cli_args: tuple[str, ...]) -> bool:
        if not (
            local_observability_stack_supported(os_name) or tuple(cli_args[:2]) != ("setup", "local-observability")
        ):
            return False
        if len(cli_args) < 2 or cli_args[0] != "setup":
            return True
        connector = _SETUP_CONNECTOR_ALIASES.get(cli_args[1])
        return connector is None or connector_supported_on_os(connector, os_name)

    return tuple(
        CmdEntry(
            tui_name=tui_name,
            cli_binary=cli_binary,
            cli_args=cli_args,
            description=description,
            category=category,
            needs_arg=needs_arg,
            arg_hint=arg_hint,
        )
        for tui_name, cli_binary, cli_args, description, category, needs_arg, arg_hint in GO_PARITY_REGISTRY
        if available(cli_args)
    )


def match_command(text: str, registry: tuple[CmdEntry, ...] | None = None) -> tuple[CmdEntry | None, str]:
    """Match a TUI alias using the Go TUI longest-prefix rule."""

    query = text.strip()
    if not query:
        return None, ""

    entries = registry or build_registry()
    best: CmdEntry | None = None
    best_extra = ""
    for entry in entries:
        name = entry.tui_name
        if not query.startswith(name):
            continue
        extra = query[len(name):].strip()
        if best is None or len(name) > len(best.tui_name):
            best = entry
            best_extra = extra
    return best, best_extra


def match_cli_args(
    binary: CliBinary,
    args: tuple[str, ...],
    registry: tuple[CmdEntry, ...] | None = None,
) -> CmdEntry | None:
    """Match raw CLI argv to the longest compatible registry entry."""

    entries = registry or build_registry()
    best: CmdEntry | None = None
    for entry in entries:
        if entry.cli_binary != binary:
            continue
        if len(args) < len(entry.cli_args):
            continue
        if args[: len(entry.cli_args)] != entry.cli_args:
            continue
        if best is None or len(entry.cli_args) > len(best.cli_args):
            best = entry
    return best
