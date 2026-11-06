# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""No doc tells an administrator to type a bare DefenseClaw command on managed Windows.

Setup puts no DefenseClaw command on ``PATH`` on a managed Windows computer, so
``defenseclaw.exe enterprise windows status`` typed as written is not
recognised. A doc names the installed CLI by its full path instead:

    & 'C:\\Program Files\\Cisco\\DefenseClaw\\bin\\defenseclaw.exe' enterprise windows status

from an elevated PowerShell prompt (in ``cmd.exe``, the path in double quotes).

This test reads every ``.mdx`` page under ``docs-site/content`` and every
``.md`` file under ``docs``, takes each fenced code line and each inline code
span, and fails on a command that starts with the bare name:

* ``defenseclaw.exe`` or ``defenseclaw-gateway.exe`` followed by any argument.
  The name alone, and ``defenseclaw.exe enterprise windows`` alone (the command
  family, named as a reference), are not commands to run.
* ``defenseclaw`` or ``defenseclaw-gateway`` followed by ``enterprise windows
  <verb>``: that family exists only on managed Windows.

The full-path form (``& '...'``, ``& $Cli``, ``"..." status``) does not start
with the bare name, so it passes. A per-user Windows page puts the CLI on
``PATH`` and may type it bare; those pages go in ``PER_USER_PAGES`` with the
reason.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SITE = ROOT / "docs-site/content"
DOCS = ROOT / "docs"

# Pages where a bare command is right because the CLI is on PATH there: the
# per-user Windows install puts %USERPROFILE%\.local\bin on PATH. Each entry is
# a path relative to the repository root and a reason. An entry that no longer
# matches a command fails the test, so the list cannot go stale.
PER_USER_PAGES: dict[str, str] = {}

_FENCE = re.compile(r"^(\s*)(`{3,}|~{3,})\s*([^\s`]*)")
_SPAN = re.compile(r"(?<!`)`([^`]+)`(?!`)")
_PROMPT = re.compile(r"^(?:\$ |PS> |PS [^>]*> |> )")
_BARE = re.compile(r"^(defenseclaw|defenseclaw-gateway)(\.exe)?(?:\s+(.*))?$", re.DOTALL)


def _doc_files() -> list[Path]:
    return sorted([*SITE.rglob("*.mdx"), *DOCS.rglob("*.md")])


def _units(text: str):
    """Yield ``(line number, text)`` for each code line and inline span."""
    fence: str | None = None
    prose: list[tuple[int, str]] = []
    for number, line in enumerate(text.splitlines(), 1):
        match = _FENCE.match(line)
        if fence is None and match:
            fence = match.group(2)[0]
            continue
        if fence is not None:
            if match and match.group(2)[0] == fence and not match.group(3):
                fence = None
                continue
            yield number, line.strip()
            continue
        prose.append((number, line))
    # Inline spans may wrap across lines inside a paragraph.
    joined = "\n".join(line for _, line in prose)
    starts = [0]
    for _, line in prose:
        starts.append(starts[-1] + len(line) + 1)
    for found in _SPAN.finditer(joined):
        index = max(i for i, offset in enumerate(starts[:-1]) if offset <= found.start())
        yield prose[index][0], " ".join(found.group(1).split())


def _bare_command(unit: str) -> str | None:
    """Why ``unit`` is a bare managed-Windows command, or ``None``."""
    unit = _PROMPT.sub("", unit.strip())
    match = _BARE.match(unit)
    if not match:
        return None
    name, exe, args = match.group(1), match.group(2), (match.group(3) or "").strip()
    if exe:
        if args and args != "enterprise windows":
            return f"bare {name}{exe} with arguments"
        return None
    if re.match(r"enterprise windows [a-z]", args):
        return f"bare {name} enterprise windows <verb>"
    return None


def _findings() -> list[tuple[str, int, str, str]]:
    found = []
    for path in _doc_files():
        rel = path.relative_to(ROOT).as_posix()
        for number, unit in _units(path.read_text(encoding="utf-8")):
            why = _bare_command(unit)
            if why:
                found.append((rel, number, why, unit))
    return found


def test_no_bare_managed_windows_command_in_the_docs() -> None:
    hits = [hit for hit in _findings() if hit[0] not in PER_USER_PAGES]
    assert not hits, (
        "A managed Windows computer has no DefenseClaw command on PATH. Write the full path from an elevated "
        "PowerShell prompt, `& 'C:\\Program Files\\Cisco\\DefenseClaw\\bin\\defenseclaw.exe' ...` "
        "(in cmd.exe, the path in double quotes), or add a per-user page to PER_USER_PAGES:\n"
        + "\n".join(f"  {rel}:{number}: {why}: {unit[:110]}" for rel, number, why, unit in hits)
    )


def test_per_user_allowlist_has_no_stale_entries() -> None:
    used = {hit[0] for hit in _findings()}
    stale = sorted(set(PER_USER_PAGES) - used)
    assert not stale, f"PER_USER_PAGES entries with no bare command left, remove them: {stale}"


@pytest.mark.parametrize(
    "unit, expected",
    [
        ("defenseclaw.exe enterprise windows status --json", True),
        ("defenseclaw.exe --version", True),
        ("defenseclaw-gateway.exe rulepack validate --dir X", True),
        ("defenseclaw enterprise windows status", True),
        ("PS> defenseclaw.exe status", True),
        ("defenseclaw.exe", False),
        ("defenseclaw.exe enterprise windows", False),
        ("& 'C:\\Program Files\\Cisco\\DefenseClaw\\bin\\defenseclaw.exe' status", False),
        ('"C:\\Program Files\\Cisco\\DefenseClaw\\bin\\defenseclaw.exe" status', False),
        ("& $Cli enterprise windows status", False),
        ("defenseclaw status", False),
        ("defenseclaw-gateway enterprise linux status", False),
    ],
)
def test_the_matcher(unit: str, expected: bool) -> None:
    assert (_bare_command(unit) is not None) is expected
