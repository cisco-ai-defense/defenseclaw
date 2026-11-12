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
* In a fence titled for an elevated or Administrator prompt, any bare
  ``defenseclaw`` or ``defenseclaw-gateway`` (with or without ``.exe``) on a
  line that is not a comment: such a block is for a managed computer.

Windows is case-insensitive and PowerShell joins whitespace, so the match
ignores case and runs of whitespace, and finds the bare name anywhere in a
unit (``$r = defenseclaw.exe ...``, ``cmd /c defenseclaw.exe ...``,
``Start-Process defenseclaw.exe``), after a prompt (``PS>``, ``C:\\>``) too.
A name after a path separator, a quote or a ``$`` is not bare, so the
full-path forms (``& '...'``, ``& $Cli``, ``"..." status``) pass. A per-user
Windows page puts the CLI on ``PATH`` and may type it bare; those pages go in
``PER_USER_PAGES`` with the reason (g072 review 2 M2).
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

_FENCE = re.compile(r"^(\s*)(`{3,}|~{3,})\s*([^\s`]*)(.*)$")
_SPAN = re.compile(r"(?<!`)`([^`]+)`(?!`)")
# A shell prompt: POSIX, PowerShell (PS>, PS C:\x>) and cmd.exe (C:\>, C:\Users\x>).
_PROMPT = re.compile(r"^(?:\$ |PS> |PS [^>]*> |> |[A-Za-z]:\\[^>]*> ?)")
# The bare name anywhere: not after a path separator, a word character, a dot,
# a quote, a $ or a dash, and not followed by more of a name.
_BARE = re.compile(r"(?<![\\/\w.'\"$-])(defenseclaw-gateway|defenseclaw)(\.exe)?(?![\w-])(.*)$", re.IGNORECASE)
# The end of one command's arguments.
_SEPARATOR = re.compile(r"\s*(?:\||;|&&|\)|$)")
# The bare name where a shell runs it: first, after = ( | ; & or &&, or as
# the program of cmd /c or Start-Process. Elsewhere it is an argument
# (Get-Service DefenseClaw*, -LogName DefenseClaw).
_BARE_RUN = re.compile(
    r"(?:^|[=(|;&]\s*|\b(?:cmd(?:\.exe)?\s+/c|Start-Process(?:\s+-FilePath)?)\s+)"
    r"(defenseclaw-gateway|defenseclaw)(\.exe)?(?![\w-])",
    re.IGNORECASE,
)
_ELEVATED_TITLE = re.compile(r"""title\s*=\s*["'][^"']*\b(?:elevated|administrator|admin\b)""", re.IGNORECASE)
# A quote that opens a token holding the bare name ("defenseclaw.exe" status,
# & 'defenseclaw.exe' status, Invoke-Expression 'defenseclaw.exe status'):
# quoting the name does not put it on PATH (g072 review 3 S1). A quoted full
# path keeps its quote, because the name follows a backslash there.
_OPENING_QUOTE = re.compile(
    r"""(^|[\s&=(|;,])['"](?=(?:defenseclaw-gateway|defenseclaw)(?:\.exe)?(?![\w-]))""", re.IGNORECASE
)
# The same quote where the elevated rule runs the name: after the call
# operator, -FilePath, or first (cmd.exe). After = it is a string value
# ($Task = 'DefenseClaw Setup as SYSTEM').
_RUN_QUOTE = re.compile(
    r"""(^|&\s*|-FilePath\s+)['"](?=(?:defenseclaw-gateway|defenseclaw)(?:\.exe)?(?![\w-]))""", re.IGNORECASE
)


def _doc_files() -> list[Path]:
    return sorted([*SITE.rglob("*.mdx"), *DOCS.rglob("*.md")])


def _units(text: str):
    """Yield ``(line number, text, elevated)`` for each code line and inline span.

    ``elevated`` is true for a line of a fence titled for an elevated or
    Administrator prompt. Whitespace runs are one space.
    """
    fence: str | None = None
    elevated = False
    prose: list[tuple[int, str]] = []
    for number, line in enumerate(text.splitlines(), 1):
        match = _FENCE.match(line)
        if fence is None and match:
            fence = match.group(2)[0]
            elevated = bool(_ELEVATED_TITLE.search(match.group(4)))
            continue
        if fence is not None:
            if match and match.group(2)[0] == fence and not match.group(3) and not match.group(4).strip():
                fence = None
                continue
            yield number, " ".join(line.split()), elevated
            continue
        prose.append((number, line))
    # Inline spans may wrap across lines inside a paragraph.
    joined = "\n".join(line for _, line in prose)
    starts = [0]
    for _, line in prose:
        starts.append(starts[-1] + len(line) + 1)
    for found in _SPAN.finditer(joined):
        index = max(i for i, offset in enumerate(starts[:-1]) if offset <= found.start())
        yield prose[index][0], " ".join(found.group(1).split()), False


def _bare_command(unit: str, elevated: bool = False) -> str | None:
    """Why ``unit`` is a bare managed-Windows command, or ``None``."""
    unit = _PROMPT.sub("", " ".join(unit.split()))
    if elevated and not unit.startswith(("#", "REM ", "rem ", "::")):
        match = _BARE_RUN.search(_RUN_QUOTE.sub(r"\1", unit))
        if match:
            return f"bare {match.group(1)}{match.group(2) or ''} in an elevated prompt block"
    for match in _BARE.finditer(_OPENING_QUOTE.sub(r"\1", unit)):
        name, exe = match.group(1), match.group(2)
        # The quote that closes a quoted name is not an argument.
        args = _SEPARATOR.split(match.group(3).lstrip("'\""), maxsplit=1)[0].strip()
        if exe:
            if args and args.lower() != "enterprise windows":
                return f"bare {name}{exe} with arguments"
        elif re.match(r"enterprise windows [a-z]", args, re.IGNORECASE):
            return f"bare {name} enterprise windows <verb>"
    return None


def _findings() -> list[tuple[str, int, str, str]]:
    found = []
    for path in _doc_files():
        rel = path.relative_to(ROOT).as_posix()
        for number, unit, elevated in _units(path.read_text(encoding="utf-8")):
            why = _bare_command(unit, elevated)
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


# A sentence that calls the bare `defenseclaw` the managed Windows administrator's command: the
# command there is defenseclaw.exe, by its full path (cowork-1-0-8 GAP-0081).
_BARE_ADMIN_COMMAND = re.compile(
    r"\b(?:native |managed )?windows\b[^.\n]{0,60}`defenseclaw`\s+is\s+the\s+administrator", re.IGNORECASE
)


def test_no_page_calls_the_bare_name_the_windows_administrators_command() -> None:
    hits = [
        f"{path.relative_to(ROOT).as_posix()}:{number}"
        for path in _doc_files()
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
        if _BARE_ADMIN_COMMAND.search(line)
    ]
    assert not hits, f"name `defenseclaw.exe` as the Windows administrator's command, not `defenseclaw`: {hits}"


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
        # g072 review 2 M2: the near variants.
        ("C:\\> defenseclaw.exe enterprise windows status", True),
        ("C:\\Users\\dcadmin> defenseclaw.exe status", True),
        ("$r = defenseclaw.exe enterprise windows status --json | ConvertFrom-Json", True),
        ("cmd /c defenseclaw.exe status", True),
        ("Start-Process defenseclaw.exe -ArgumentList status", True),
        ("Start-Process defenseclaw.exe", False),
        ("DefenseClaw.exe status", True),
        ("DEFENSECLAW-GATEWAY.EXE rulepack validate --dir X", True),
        ("defenseclaw  enterprise  windows status", True),
        ("defenseclaw\tenterprise windows status", True),
        ("DefenseClaw Enterprise Windows Status", True),
        ("(defenseclaw.exe status)", True),
        ("Get-Service DefenseClawSensorHelper, DefenseClawGateway", False),
        ("& 'C:\\Program Files\\Cisco\\DefenseClaw\\bin\\defenseclaw.exe' enterprise windows status --json", False),
        ('C:\\> "C:\\Program Files\\Cisco\\DefenseClaw\\bin\\defenseclaw.exe" status', False),
        ("defenseclaw-hook.exe --version", False),
        ("defenseclaw.exe | Out-Null", False),
        # g072 review 3 S1: a quote that opens the name does not make it a path.
        ('& "defenseclaw.exe" enterprise windows status', True),
        ("& 'defenseclaw.exe' status", True),
        ('"defenseclaw.exe" status', True),
        ("Start-Process -FilePath 'defenseclaw.exe' -ArgumentList status", True),
        ("Invoke-Expression 'defenseclaw.exe status'", True),
        ("& 'defenseclaw-gateway.exe' rulepack validate --dir X", True),
        ('Get-Command "defenseclaw.exe"', False),
        ("& 'C:\\Program Files\\Cisco\\DefenseClaw\\bin\\defenseclaw.exe' status", False),
        ("'C:\\Program Files\\Cisco\\DefenseClaw\\bin\\defenseclaw.exe' status", False),
    ],
)
def test_the_matcher(unit: str, expected: bool) -> None:
    assert (_bare_command(unit) is not None) is expected


@pytest.mark.parametrize(
    "unit, expected",
    [
        # Any bare command in a block for an elevated or Administrator prompt,
        # with or without .exe: such a block is for a managed computer.
        ("defenseclaw agent discovery runtime selftest", True),
        ("defenseclaw agent discovery runtime permissions", True),
        ("PS> defenseclaw status", True),
        ("defenseclaw-gateway status", True),
        ("defenseclaw", True),
        ("$x = defenseclaw status", True),
        ("& 'C:\\Program Files\\Cisco\\DefenseClaw\\bin\\defenseclaw.exe' enterprise windows status --json", False),
        ("Get-Service DefenseClawSensorHelper, DefenseClawGateway", False),
        ("# defenseclaw is not on PATH here", False),
        ("& defenseclaw status", True),
        ("cmd /c defenseclaw status", True),
        ("Start-Process -FilePath defenseclaw -ArgumentList status", True),
        ("Get-Service DefenseClaw* | Format-Table Name, Status, StartType", False),
        ("Get-WinEvent -LogName DefenseClaw -MaxEvents 3", False),
        ("& 'defenseclaw' status", True),
        ('"defenseclaw" doctor', True),
        ("$Task = 'DefenseClaw Setup as SYSTEM'", False),
    ],
)
def test_the_matcher_in_an_elevated_block(unit: str, expected: bool) -> None:
    assert (_bare_command(unit, elevated=True) is not None) is expected
    if expected and "enterprise windows" not in unit and ".exe" not in unit:
        assert _bare_command(unit) is None, "outside an elevated block a per-user command may be bare"


def test_units_read_the_fence_title_and_join_whitespace() -> None:
    page = "\n".join(
        [
            '```powershell title="Elevated PowerShell prompt"',
            "defenseclaw   agent discovery runtime selftest",
            "```",
            '```powershell title="Per-user PowerShell"',
            "defenseclaw status",
            "```",
            "~~~bash title='Administrator prompt'",
            "defenseclaw-gateway status",
            "~~~",
            '```ps1 title="Admin PowerShell"',
            "defenseclaw doctor",
            "```",
            '```ps1 title="Badminton club"',
            "defenseclaw doctor",
            "```",
        ]
    )
    units = [(unit, elevated) for _, unit, elevated in _units(page)]
    assert units == [
        ("defenseclaw agent discovery runtime selftest", True),
        ("defenseclaw status", False),
        ("defenseclaw-gateway status", True),
        ("defenseclaw doctor", True),
        ("defenseclaw doctor", False),
    ]
    # The block a review found: a per-user command under an elevated title.
    hits = [_bare_command(unit, elevated) for unit, elevated in units]
    assert [hit is not None for hit in hits] == [True, False, True, True, False]
