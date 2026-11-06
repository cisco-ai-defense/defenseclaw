# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Every PowerShell literal and call-operator line the Python CLI renders comes from winquote.

The twin of the Go source check (internal/managed
windows_admin_cli_source_test.go). A literal quoted by hand doubled only the
apostrophe and missed U+2018 to U+201B, and a call-operator line built by
hand named no shell (g072 review 3 M2): cmd_acp printed
``run & '...'`` with an O\u2019Brien data dir that did not parse.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

_PACKAGE = Path(__file__).resolve().parents[1] / "defenseclaw"

# Files and reasons the rules do not apply to. A stale entry fails.
_ALLOWED = {
    # The one renderer and reader.
    "winquote.py": "the PowerShell quoting rule itself",
    # YAML single-quoted scalars double the apostrophe; YAML has no typographic quote rule.
    "observability/v8_yaml.py": "YAML, not PowerShell",
}
# (file, function) pairs whose "&" is not a PowerShell line DefenseClaw renders.
_ALLOWED_FUNCTIONS = {
    # The cmd.exe launcher-guard words a reader compares hook tokens against.
    ("hook_integrity.py", "claude_launcher_guard_view"): "a reader's cmd.exe word list",
    # RFC 3986 sub-delims.
    ("observability/hash_v1.py", "<module>"): "a URL character class, not a command",
    # Go's json.Marshal escape table.
    ("commands/cmd_acp.py", "<module>"): "a JSON escape, not a command",
    # A POSIX background job inside an ssh command line.
    ("commands/cmd_edge_install.py", "_start_remote_daemon"): "POSIX shell, not PowerShell",
    # cmd.exe's command separator.
    ("commands/windows_uninstall_helper.py", "_remove_after_exit"): "cmd.exe, not PowerShell",
    # Rebuilds the published 1.0.0-1.0.8 Copilot scripts around the launcher
    # literal it matched, to compare them (a reader).
    ("commands/cmd_uninstall.py", "_orphan_copilot_handler_owned"): "a reader of published scripts",
}
# winquote's renderers: a formatted value from one of them is a literal or a line it made.
_RENDERERS = {"powershell_literal", "powershell_command_line", "powershell_argument"}
# Calls whose string arguments a reader compares with, not text it renders.
_READER_CALLS = {"startswith", "endswith", "find", "index", "count", "partition", "rpartition", "removeprefix"}

# A call operator before a quote, a formatted value, or the end of a literal
# that a concatenation continues: "& '", f"& {x}", "& " + x, "&'" and "&\t'".
_CALL_OPERATOR = re.compile(r"(?:^|[^&>\w])&(?:[ \t]*['\u2018-\u201b]|[ \t]*\x00|[ \t]+$)")
# A quote doubled by hand: x * 2 if x in "'..."
_DOUBLED_BY_HAND = re.compile(r"\*\s*2\s+if\s+\w+\s+in\s+(?:[rbuf]*[\"']{1,3}'|SINGLE_QUOTES)")
_REGEX_CALLS = {"compile", "fullmatch", "match", "search", "finditer", "findall", "sub", "subn", "split"}


def _text(node: ast.AST) -> str | None:
    """A string literal's text: a formatted value as NUL, or as "L" when winquote rendered it."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        return "".join(_part(part) for part in node.values)
    return None


def _part(part: ast.AST) -> str:
    if isinstance(part, ast.Constant) and isinstance(part.value, str):
        return part.value
    value = part.value if isinstance(part, ast.FormattedValue) else None
    if isinstance(value, ast.Call) and isinstance(value.func, ast.Name) and value.func.id in _RENDERERS:
        return "L"
    return "\x00"


def _is_reader_use(node: ast.AST, parent: ast.AST | None) -> bool:
    """A literal compared with, a docstring, or an argument of startswith and the like."""
    if isinstance(parent, (ast.Compare, ast.Expr)):
        return True
    return (
        isinstance(parent, ast.Call)
        and isinstance(parent.func, ast.Attribute)
        and parent.func.attr in _READER_CALLS
        and node in parent.args
    )


def _function(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> str:
    """The name of the module-level function holding *node*, or "<module>"."""
    name = "<module>"
    while node in parents:
        node = parents[node]
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            name = node.name
    return name


def _is_regex_call(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "re"
        and node.func.attr in _REGEX_CALLS
    )


def _is_quote_replace(node: ast.AST) -> bool:
    """x.replace("'", "''") or x.replace("''", "'")."""
    if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "replace"):
        return False
    values = [arg.value for arg in node.args if isinstance(arg, ast.Constant)]
    return values in (["'", "''"], ["''", "'"])


def _is_join_or_sequence(parent: ast.AST | None) -> bool:
    if isinstance(parent, (ast.List, ast.Tuple, ast.Set)):
        return True
    return (
        isinstance(parent, ast.Call)
        and isinstance(parent.func, ast.Attribute)
        and parent.func.attr == "join"
    )


def problems(source: str, name: str = "<probe>", used: set[tuple[str, str]] | None = None) -> list[str]:
    """The hand-built PowerShell quoting in *source*, as "line: reason"."""
    tree = ast.parse(source)
    parents: dict[ast.AST, ast.AST] = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[child] = node
    found: list[str] = []
    for node in ast.walk(tree):
        if _is_quote_replace(node):
            found.append(f"{node.lineno}: a PowerShell quote doubled by hand (use winquote)")
        text = _text(node)
        parent = parents.get(node)
        if text is None or isinstance(parent, (ast.JoinedStr, ast.FormattedValue)) or _is_reader_use(node, parent):
            continue
        ancestor, regex = parents.get(node), False
        while ancestor is not None:
            if _is_regex_call(ancestor):
                regex = True  # a reader's pattern, not a rendered command
                break
            ancestor = parents.get(ancestor)
        if regex:
            continue
        problem = ""
        if _CALL_OPERATOR.search(text):
            problem = "a PowerShell call-operator line built by hand (use winquote)"
        elif text.strip() == "&" and _is_join_or_sequence(parent):
            problem = "a call operator joined into a command by hand (use winquote)"
        if problem:
            key = (name, _function(node, parents))
            if key in _ALLOWED_FUNCTIONS:
                if used is not None:
                    used.add(key)
            else:
                found.append(f"{node.lineno}: {problem}")
    for number, line in enumerate(source.splitlines(), 1):
        if _DOUBLED_BY_HAND.search(line):
            found.append(f"{number}: a PowerShell quote doubled by hand (use winquote)")
    return found


def test_the_python_cli_renders_powershell_through_winquote() -> None:
    failures = []
    seen = set()
    used: set[tuple[str, str]] = set()
    for path in sorted(_PACKAGE.rglob("*.py")):
        name = path.relative_to(_PACKAGE).as_posix()
        if name in _ALLOWED:
            seen.add(name)
            continue
        failures += [f"{name}:{problem}" for problem in problems(path.read_text(encoding="utf-8"), name, used)]
    assert not failures, "\n".join(failures)
    assert seen == set(_ALLOWED), f"stale allowlist entries: {set(_ALLOWED) - seen}"
    assert used == set(_ALLOWED_FUNCTIONS), f"stale allowlist entries: {set(_ALLOWED_FUNCTIONS) - used}"


@pytest.mark.parametrize(
    "source",
    [
        "x = \"& '\" + path + \"' status\"",
        "x = '& ' + powershell_literal(path)",
        "x = f\"& '{path}' status\"",
        "x = f\"& {literal} status\"",
        "x = f\"run & {literal}\"",
        "x = \"&'\" + path",
        "x = \"&\\t'\" + path",
        "x = \"&  '\" + path",
        "x = \"& \\u2018\" + path",
        "x = \" \".join([\"&\", path, \"status\"])",
        "x = \" \".join((\"& \", path))",
        "x = \"'\" + value.replace(\"'\", \"''\") + \"'\"",
        "x = body.replace(\"''\", \"'\")",
        "x = \"\".join(ch * 2 if ch in \"'\\u2019\" else ch for ch in value)",
        "x = \"; \".join([a, f\"if (x) {{ & {binary} hook }}\"])",
    ],
)
def test_the_check_catches_hand_built_quoting(source: str) -> None:
    assert problems(source), source


@pytest.mark.parametrize(
    "source",
    [
        "ok = parts[0] == \"&\"",
        "ok = value.startswith(\"&\")",
        "x = re.fullmatch(r\"& '((?:[^']|'')+)' hook\", script)",
        "x = re.compile(\"^& '\" + name + \"'$\")",
        "x = \"set X=1&& \" + command",
        "x = \"echo hi 1>&2\"",
        "x = powershell_command_line(exe, \"status\")",
        "x = f\"Get-Content -LiteralPath {powershell_literal(path)} -Raw\"",
        "x = {\"a\"} & {\"b\"}",
        "x = f\"& {powershell_literal(path)} -Event {powershell_literal(event)}\"",
        "def f():\n    \"\"\"Reads a ``& '...'`` command.\"\"\"",
        "ok = lowered.startswith(\"& \")",
    ],
)
def test_the_check_passes_its_benign_twins(source: str) -> None:
    assert not problems(source), source
