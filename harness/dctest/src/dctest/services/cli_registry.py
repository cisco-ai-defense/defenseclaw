"""Build a structured registry of supported CLI subcommands and flags.

Recursively runs ``--help`` on the ``defenseclaw`` (Python click) and
``defenseclaw-gateway`` (Go cobra) binaries and parses the output into a
tree of ``CliNode`` records. The result is persisted as JSON so the
linter and other consumers don't re-shell ``--help`` hundreds of times.

Two parser flavors are supported:

* Click — "Usage: <prog> [OPTIONS] COMMAND [ARGS]...". Sections include
  ``Commands:`` (subcommands) and ``Options:`` (flags). Click never emits
  positional argument lists outside of the Usage line.
* Cobra — "Usage: <prog> [flags]" / "[command]". Sections include
  ``Available Commands:`` (subcommands) and ``Flags:`` / ``Global Flags:``.

The parser is intentionally lenient: any line under a recognized section
header that starts with ``--`` (or a short ``-x``) is treated as a flag,
and any indented line under ``Commands:`` / ``Available Commands:`` whose
first non-whitespace token is a bare alphanumeric word is treated as a
subcommand. Unknown sections are skipped.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from dctest.config import get_settings

_FLAG_LINE = re.compile(r"^\s{2,}(-{1,2}[A-Za-z0-9][\w\-]*)")
_SUBCMD_LINE = re.compile(r"^\s{2,}([a-z][a-z0-9\-]*)\s+\S")
_SECTION_COMMANDS = re.compile(r"^(?:Commands|Available Commands):\s*$", re.IGNORECASE)
_SECTION_OPTIONS = re.compile(
    r"^(?:Options|Flags|Global Flags):\s*$",
    re.IGNORECASE,
)


class CliNode(BaseModel):
    """A node in the CLI surface tree.

    ``name`` is the leaf name relative to its parent (e.g. ``"scan"`` under
    ``defenseclaw skill``). Flags are stored as a set of strings including
    the leading ``-``/``--`` (e.g. ``"--json"``, ``"-h"``).
    """

    name: str
    subcommands: dict[str, CliNode] = Field(default_factory=dict)
    flags: set[str] = Field(default_factory=set)
    positionals: list[str] = Field(default_factory=list)

    def has_subcommand(self, name: str) -> bool:
        return name in self.subcommands

    def has_flag(self, name: str) -> bool:
        return name in self.flags


CliNode.model_rebuild()


def _parse_help(text: str) -> tuple[set[str], list[str], list[str]]:
    """Extract (flags, subcommands, positionals) from one ``--help`` body."""
    flags: set[str] = set()
    subs: list[str] = []
    positionals: list[str] = []

    section: str | None = None
    for raw_line in text.splitlines():
        if _SECTION_COMMANDS.match(raw_line):
            section = "commands"
            continue
        if _SECTION_OPTIONS.match(raw_line):
            section = "options"
            continue
        # A non-indented header that doesn't match resets the section.
        if raw_line and not raw_line.startswith((" ", "\t")):
            if raw_line.lower().startswith("usage:"):
                # Cheap positional extraction from the Usage line itself.
                # We don't care about the leading binary name.
                tokens = raw_line.split()
                for tok in tokens[1:]:
                    if tok.isupper() and len(tok) > 1 and tok.isalpha():
                        positionals.append(tok)
            section = None
            continue

        if section == "options":
            m = _FLAG_LINE.match(raw_line)
            if m:
                flag = m.group(1)
                flags.add(flag)
                # Some help output crowds two flags on one line:
                #   "-h, --help   Show this message and exit."
                comma_pair = re.match(
                    r"^\s{2,}(-[A-Za-z]),\s+(--[A-Za-z0-9][\w\-]*)",
                    raw_line,
                )
                if comma_pair:
                    flags.add(comma_pair.group(1))
                    flags.add(comma_pair.group(2))
        elif section == "commands":
            m = _SUBCMD_LINE.match(raw_line)
            if m:
                subs.append(m.group(1))

    # De-dup positionals while preserving order.
    seen: set[str] = set()
    deduped_positionals = []
    for p in positionals:
        if p in seen:
            continue
        seen.add(p)
        deduped_positionals.append(p)
    return flags, subs, deduped_positionals


def _shell_help(argv: list[str], *, timeout: float = 8.0) -> str:
    """Run ``argv --help`` and return its combined stdout/stderr."""
    try:
        proc = subprocess.run(
            argv + ["--help"],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return ""
    # Click writes help to stdout; cobra writes to stdout when invoked with
    # ``--help`` (only an unknown-command error goes to stderr). Join both
    # for resilience.
    return (proc.stdout or "") + "\n" + (proc.stderr or "")


def _build_subtree(argv: list[str], *, name: str, depth: int = 0, max_depth: int = 4) -> CliNode:
    """Recursively build a CliNode for ``argv``.

    ``argv`` is the command prefix to invoke (e.g. ``["defenseclaw","skill"]``).
    """
    node = CliNode(name=name)
    if depth > max_depth:
        return node
    body = _shell_help(argv)
    if not body:
        return node
    flags, subs, positionals = _parse_help(body)
    node.flags = flags
    node.positionals = positionals
    for sub in subs:
        # The literal "help" subcommand on cobra binaries doesn't have flags
        # of its own that matter for case linting, and recursing into it can
        # produce noisy duplicates of the parent help.
        if sub == "help":
            continue
        node.subcommands[sub] = _build_subtree(
            argv + [sub], name=sub, depth=depth + 1, max_depth=max_depth
        )
    return node


def build_registry(*, binaries: list[str] | None = None) -> dict[str, CliNode]:
    """Build a fresh registry by shelling out to each binary on PATH.

    Returns a mapping of top-level binary name -> CliNode tree. Binaries
    that aren't on PATH are silently skipped (the registry just doesn't
    contain them) — the linter treats "binary unknown" as a soft warning.
    """
    settings = get_settings()
    targets = binaries or [settings.defenseclaw_bin, settings.defenseclaw_gateway_bin]
    out: dict[str, CliNode] = {}
    for bin_name in targets:
        if shutil.which(bin_name) is None:
            continue
        out[bin_name] = _build_subtree([bin_name], name=bin_name)
    return out


def save_registry(registry: dict[str, CliNode], path: Path) -> None:
    """Persist a registry to JSON at ``path``."""
    path.parent.mkdir(parents=True, exist_ok=True)
    payload: dict[str, Any] = {name: _node_to_dict(node) for name, node in registry.items()}
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def load_registry(path: Path) -> dict[str, CliNode]:
    """Load a registry previously written by :func:`save_registry`."""
    if not path.exists():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    return {name: _node_from_dict(name, body) for name, body in data.items()}


def _node_to_dict(node: CliNode) -> dict[str, Any]:
    return {
        "name": node.name,
        "flags": sorted(node.flags),
        "positionals": list(node.positionals),
        "subcommands": {
            name: _node_to_dict(child) for name, child in sorted(node.subcommands.items())
        },
    }


def _node_from_dict(name: str, body: dict[str, Any]) -> CliNode:
    return CliNode(
        name=body.get("name", name),
        flags=set(body.get("flags", [])),
        positionals=list(body.get("positionals", [])),
        subcommands={
            sub_name: _node_from_dict(sub_name, sub_body)
            for sub_name, sub_body in body.get("subcommands", {}).items()
        },
    )
