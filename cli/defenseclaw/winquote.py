# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""PowerShell single-quoted literals: the Python copy of the Go quoting rule.

PowerShell reads the apostrophe and the typographic single quotes U+2018 to
U+201B alike, so each one is doubled inside a single-quoted literal. Quoted
with only the apostrophe doubled, a path like ``C:\\Users\\O\u2019Brien``
ends its literal at the typographic quote and the command does not parse
(g072 review 2 S3). Since 1.0.9 the Go hook builders and hints render with
internal/managed PowerShellLiteral; this module renders and reads the same
text, so doctor, the fail-mode freshness guard and every printed command
agree with them byte for byte (g072 review 3 M2, M3). The golden file
testdata/powershell_quotes/windows_hook_commands.json, written by the Go
connector tests, holds the Go renders the Python tests read back, and
tests/test_powershell_quoting_source.py fails a quote doubled by hand.
"""

from __future__ import annotations

import os
import shlex

# The characters PowerShell takes as a single quote.
SINGLE_QUOTES = "'\u2018\u2019\u201a\u201b"


def powershell_literal_body(value: str) -> str:
    """*value* escaped for the inside of a single-quoted literal (managed.PowerShellLiteralBody)."""
    return "".join(char * 2 if char in SINGLE_QUOTES else char for char in value)


def powershell_literal(value: str) -> str:
    """*value* as one inert single-quoted PowerShell string (managed.PowerShellLiteral)."""
    return "'" + powershell_literal_body(value) + "'"


def powershell_literal_value(body: str) -> str:
    """The value of *body*, the inside of a single-quoted literal (managed.PowerShellLiteralValue).

    Each doubled quote is one. A quote that is not doubled is kept, so the
    render of releases before 1.0.9 (a lone typographic quote) reads as the
    same path: it stays DefenseClaw's own, and the readers report it stale
    with powershell_literal_is_current. PowerShell's tokenizer reads any two
    quotes in a row as one; reading only identical pairs is enough because
    every reader then requires the value to be DefenseClaw's own path or
    exact command, which no other pairing decodes to.
    """
    value: list[str] = []
    index = 0
    while index < len(body):
        char = body[index]
        value.append(char)
        if char in SINGLE_QUOTES and index + 1 < len(body) and body[index + 1] == char:
            index += 1
        index += 1
    return "".join(value)


def powershell_literal_is_current(body: str) -> bool:
    """Whether *body* is this release's render of its value.

    False for a lone quote, such as the typographic quote releases before
    1.0.9 left undoubled: PowerShell ends the literal there.
    """
    return powershell_literal_body(powershell_literal_value(body)) == body


def powershell_literal_before_typographic_quotes(text: str) -> str:
    """*text*, holding literals from powershell_literal, as releases before 1.0.9 rendered it.

    They doubled only the apostrophe, so each doubled typographic quote is
    one again (managed.PowerShellLiteralBeforeTypographicQuotes).
    """
    for quote in SINGLE_QUOTES[1:]:
        text = text.replace(quote * 2, quote)
    return text


# Stands for a doubled apostrophe while shlex splits (a private-use character).
_DOUBLED_APOSTROPHE = "\ue000"


def split_windows_words(command: str) -> list[str]:
    """``shlex.split(command, posix=False)``, but a single-quoted literal keeps its doubled apostrophes.

    Non-POSIX shlex ends a quoted word at the first closing quote, so
    ``'C:\\Users\\O''Brien\\x.exe'``, the render of a profile with an
    apostrophe, split into two words and the readers did not know their own
    hook (g072 review 3 M3). The words keep their quotes, as shlex's do. It
    raises ValueError as shlex does.
    """
    if _DOUBLED_APOSTROPHE in command:
        raise ValueError("command holds a reserved character")
    protected: list[str] = []
    quote = ""
    word_start = True  # shlex opens a quoted word only where a word starts
    index = 0
    while index < len(command):
        char = command[index]
        if quote == "'" and char == "'" and command[index + 1 : index + 2] == "'":
            protected.append(_DOUBLED_APOSTROPHE)
            index += 2
            continue
        if quote:
            if char == quote:
                quote, word_start = "", True
        elif char in " \t\r\n":
            word_start = True
        elif char in "'\"" and word_start:
            quote = char
        else:
            word_start = False
        protected.append(char)
        index += 1
    return [word.replace(_DOUBLED_APOSTROPHE, "''") for word in shlex.split("".join(protected), posix=False)]


def powershell_argument(arg: str) -> str:
    """*arg* as PowerShell passes it to a native command (managed powerShellArgument).

    Unchanged when it is a plain word (a subcommand, a flag, a connector
    name) or a <placeholder> the reader replaces, a literal otherwise.
    """
    if len(arg) > 2 and arg[0] == "<" and arg[-1] == ">" and not any(char in _NOT_IN_PLACEHOLDER for char in arg[1:-1]):
        return arg
    if arg == "":
        return "''"
    if all(char in _PLAIN_CHARACTERS for char in arg):
        return arg
    return powershell_literal(arg)


# The characters a <placeholder> may not hold.
_NOT_IN_PLACEHOLDER = "<>\"`$" + SINGLE_QUOTES

# The characters a bare argument may hold (managed powerShellPlainRune): ASCII
# letters and digits and - _ . : / = +, none of which PowerShell reads as syntax.
_PLAIN_CHARACTERS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.:/=+"
)


def powershell_command_line(executable: str, *args: str) -> str:
    """The PowerShell line that runs *executable* with *args* (managed.WindowsCommandLine).

    The executable is a literal after the call operator; plain words stay
    bare. The line runs only in PowerShell, so the text around it says so
    (run_instruction).
    """
    return " ".join(["&", powershell_literal(executable), *(powershell_argument(arg) for arg in args)])


def run_instruction(command: str, *, windows: bool | None = None) -> str:
    """The words that ask the user to run *command*: "in PowerShell, run" on Windows, else "run".

    A Windows command DefenseClaw prints is a PowerShell line (a call
    operator, quoted literals), which cmd.exe does not run (REVIEW-1 M4).
    """
    if windows is None:
        windows = os.name == "nt"
    return f"in PowerShell, run {command}" if windows else f"run {command}"
