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
# that a concatenation continues: "& '", f"& {x}", "& " + x, "&'" and "&\t'";
# since g072 review 4 M2 also a %-format or str.format field ("& %s",
# "& {}", "& {0!r}"), and a no-break space, which PowerShell reads as a
# blank. A scriptblock ("& { $input | ... }") is not a format field.
# Since g072 review 5 S1 a %-format mapping key ("& %(p)s") and %a count too.
#
# Documented limits, which no source in the package uses (g072 review 5 N1;
# the Go rule in windows_admin_cli_source_test.go keeps the same kind of list):
# "&{} x".format(v) and "&{0}" with no blank (the twin of Go's &%s); a nested
# format spec ("& {0:{1}}"); a quote doubled with a new value that is not a
# literal (v.replace("'", "'" * 2), v.replace("'", Q + Q)); re.sub with a group
# backreference (re.sub(r"(')", r"\1\1", v)); string.Template("& $p"); and a
# "run" + winquote join that goes through a variable or a .format() call
# instead of a + chain or an f-string.
_CALL_OPERATOR = re.compile(
    r"(?:^|[^&>\w])&(?:[ \t\u00a0]*['\u2018-\u201b]|[ \t\u00a0]*\x00"
    r"|[ \t\u00a0]+(?:%(?:\([^)]*\))?[-+# 0-9.*]*[sqra]|\{[\w.\[\]]*(?:![rsa])?(?::[^{}\s]*)?\}|$))"
)
# A quote doubled by hand: x * 2 if x in "'...", or x + x if x == "'".
_DOUBLED_BY_HAND = re.compile(r"(?:\*\s*2|\b(\w+)\s*\+\s*\1)\s+if\s+\w+\s+(?:in|==)\s+(?:[rbuf]*[\"']{1,3}['\u2018-\u201b]|SINGLE_QUOTES)")
# A run instruction built by hand around a winquote render ("L") or a call
# operator that does not say the shell: cmd.exe does not run a PowerShell line
# (use winquote.run_instruction, which says "in PowerShell, run").
_RUN_WITHOUT_SHELL = re.compile(r"(?i)\brun:?\s+[`'\"]?(?:L\b|&\s)")
# PowerShell's single quotes, as winquote.SINGLE_QUOTES.
_QUOTES = "'\u2018\u2019\u201a\u201b"
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


def _is_renderer_call(node: ast.AST) -> bool:
    func = node.func if isinstance(node, ast.Call) else None
    name = func.id if isinstance(func, ast.Name) else func.attr if isinstance(func, ast.Attribute) else ""
    return name in _RENDERERS


def _is_top_concat(node: ast.AST, parent: ast.AST | None) -> bool:
    """The outermost node of a "a" + "b" + ... chain."""
    return (
        isinstance(node, ast.BinOp)
        and isinstance(node.op, ast.Add)
        and not (isinstance(parent, ast.BinOp) and isinstance(parent.op, ast.Add))
    )


def _concat_text(node: ast.AST) -> str:
    """The text of a + chain: literals as written, a winquote render as "L", any other value as NUL.

    A "Run " + powershell_command_line(...) join says what an f-string does
    (g072 review 5 S1), so the run-instruction rule reads both.
    """
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _concat_text(node.left) + _concat_text(node.right)
    if _is_renderer_call(node):
        return "L"
    return _text(node) or "\x00"


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


def _ancestors(node: ast.AST, parents: dict[ast.AST, ast.AST]):
    while node in parents:
        node = parents[node]
        yield node


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


def _constant(node: ast.AST) -> str | None:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _quote_of(pattern: str | None) -> str | None:
    """The PowerShell quote *pattern* is: the quote itself, or a regex class holding one."""
    if pattern is None:
        return None
    if len(pattern) == 1 and pattern in _QUOTES:
        return pattern
    if pattern.startswith("[") and pattern.endswith("]"):
        held = [quote for quote in _QUOTES if quote in pattern]
        return held[0] if held else None
    return None


def _doubles(new: str | None, quote: str) -> bool:
    return new in (quote * 2, "''", "\\g<0>\\g<0>", "\\0\\0")


def _is_quote_replace(node: ast.AST) -> bool:
    """A PowerShell quote doubled, or a doubled one read back, by hand (g072 review 4 M2).

    x.replace(q, q + q) and back, re.sub(q or a class holding q, q + q or
    "\\g<0>\\g<0>", x), x.translate({ord(q): q + q}) or maketrans, and
    "''".join(x.split("'")).
    """
    if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
        return False
    attr = node.func.attr
    args = [_constant(arg) for arg in node.args]
    if attr == "replace" and len(args) >= 2:
        old, new = args[0], args[1]
        if (quote := _quote_of(old)) is not None and _doubles(new, quote):
            return True
        return new is not None and len(new) == 1 and new in _QUOTES and old in (new * 2, "''")
    if attr == "sub" and isinstance(node.func.value, ast.Name) and node.func.value.id == "re" and len(args) >= 2:
        quote = _quote_of(args[0])
        return quote is not None and _doubles(args[1], quote)
    if attr in {"translate", "maketrans"}:
        for arg in node.args:
            if isinstance(arg, ast.Dict):
                for value in arg.values:
                    text = _constant(value)
                    if text is not None and len(text) == 2 and text[0] == text[1] and text[0] in _QUOTES:
                        return True
        # The two-string maketrans form maps one character to one, so it cannot double.
        return False
    if attr == "join" and (joiner := _constant(node.func.value)) is not None:
        if len(joiner) == 2 and joiner[0] == joiner[1] and joiner[0] in _QUOTES and node.args:
            split = node.args[0]
            return (
                isinstance(split, ast.Call)
                and isinstance(split.func, ast.Attribute)
                and split.func.attr == "split"
                and bool(split.args)
                and _constant(split.args[0]) == joiner[0]
            )
    return False


def _is_join_or_sequence(node: ast.AST, parent: ast.AST | None) -> bool:
    """A lone "&" joined into a command: a sequence, a join, a str.format argument
    (g072 review 4 M2), or a + operand whose sibling starts with a blank or a quote."""
    if isinstance(parent, (ast.List, ast.Tuple, ast.Set)):
        return True
    if isinstance(parent, ast.Call) and isinstance(parent.func, ast.Attribute):
        return parent.func.attr == "join" or (parent.func.attr == "format" and node in parent.args)
    if isinstance(parent, ast.BinOp) and isinstance(parent.op, ast.Add):
        sibling = parent.right if parent.left is node else parent.left
        while isinstance(sibling, ast.BinOp) and isinstance(sibling.op, ast.Add):
            sibling = sibling.left if parent.left is node else sibling.right
        text = _text(sibling)
        return text is None or text[:1] in (" ", "\t", "\u00a0") or (text[:1] != "" and text[0] in _QUOTES)
    return False


def _in_run_instruction(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> bool:
    while node in parents:
        node = parents[node]
        if isinstance(node, ast.Call):
            func = node.func
            name = func.id if isinstance(func, ast.Name) else func.attr if isinstance(func, ast.Attribute) else ""
            if name == "run_instruction":
                return True
    return False


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
        parent = parents.get(node)
        if _is_top_concat(node, parent) and not _is_reader_use(node, parent):
            joined = _concat_text(node)
            if (
                _RUN_WITHOUT_SHELL.search(joined)
                and "powershell" not in joined.lower()
                and not _in_run_instruction(node, parents)
                and not any(_is_regex_call(up) for up in _ancestors(node, parents))
            ):
                key = (name, _function(node, parents))
                if key in _ALLOWED_FUNCTIONS:
                    if used is not None:
                        used.add(key)
                else:
                    found.append(
                        f"{node.lineno}: a PowerShell line in a run instruction that does not say PowerShell"
                        " (use winquote.run_instruction)"
                    )
        text = _text(node)
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
        elif text.strip() == "&" and _is_join_or_sequence(node, parent):
            problem = "a call operator joined into a command by hand (use winquote)"
        elif (
            _RUN_WITHOUT_SHELL.search(text)
            and "powershell" not in text.lower()
            and not _in_run_instruction(node, parents)
        ):
            problem = "a PowerShell line in a run instruction that does not say PowerShell (use winquote.run_instruction)"
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
        # g072 review 4 M2.
        "x = \"& %s status\" % lit",
        "x = \"& {} status\".format(lit)",
        "x = \"&\" + \" \" + lit",
        "x = \"{} {}\".format(\"&\", lit)",
        "x = re.sub(\"'\", \"''\", v)",
        "x = v.replace(\"\u2019\", \"\u2019\u2019\")",
        "x = \"''\".join(v.split(\"'\"))",
        "x = v.translate({ord(\"'\"): \"''\"})",
        "x = \"\".join(c + c if c in \"'\" else c for c in v)",
        "x = \"&\\u00a0'\" + v",
        "x = f\"run {powershell_command_line(exe, 'status')}\"",
        # g072 review 5 S1.
        "x = \"& %(p)s status\" % {\"p\": lit}",
        "x = \"& %a status\" % lit",
        "x = \"Run \" + powershell_command_line(a)",
        "x = \"run: \" + powershell_command_line(a)",
        "x = \"Run \" + winquote.powershell_command_line(a) + \" now\"",
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
        "x = f\"in PowerShell, run {powershell_command_line(exe, 'status')}\"",
        "x = run_instruction(f\"{powershell_command_line(exe, 'status')}\")",
        "x = f\"Get-Content -Raw | & {{ $input | & {powershell_literal(path)} }}\"",
        "x = value.replace(\"'\", \"\\\\'\")",
        # g072 review 5 S1.
        "x = \"In PowerShell, run \" + powershell_command_line(a)",
        "x = run_instruction(\"\" + powershell_command_line(a))",
        "x = \"Run \" + name",
        "x = \"%d%% done\" % n",
    ],
)
def test_the_check_passes_its_benign_twins(source: str) -> None:
    assert not problems(source), source
