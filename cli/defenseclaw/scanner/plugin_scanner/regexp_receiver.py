# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Tell RegExp.prototype.exec from command execution for the SRC-EXEC rule.

``exec(`` names two unrelated calls in JavaScript: ``child_process.exec`` runs
a shell command, and ``RegExp.prototype.exec`` matches a pattern. The rule
matches the word, so every package that matches text with ``/re/.exec(text)``
was reported as running commands. A call is a pattern match only when its
receiver is provably a regular expression in this file:

* a regular expression literal, bare or in parentheses: ``/re/g.exec(t)``,
  ``(/re/).exec(t)``;
* a construction: ``new RegExp(...)`` or ``RegExp(...)``;
* a name whose single binding is one of those (``const NAME = /re/``, with or without a ``: RegExp`` type) and
  whose every other use is the object of a property access (``NAME.exec(``,
  ``NAME.lastIndex = 0``) or an argument of a logging call. A name that is
  rebound, passed to any other function, returned, indexed or shadowed by a
  parameter is not proven and keeps the finding.

Nothing is proven in a plugin that can change what a regular expression
reaches. The guard reads every JavaScript and TypeScript file of the plugin,
not the one with the call, and works from the routes that lead to the built-in
object, not from spellings of the word ``exec``: the name ``RegExp`` may only be
called, tested with ``instanceof`` or (in TypeScript) used as a type; a
prototype is never read from an object, passed on, replaced or given a computed
member; properties are never defined through reflection, proxies or the global
object by computed name. A plugin that does any of this keeps the finding, as it
did before this module. An unrelated string or key that happens to read
'exec' does not change the proof.

A bare ``exec(``, ``cp.exec(``, ``obj.pattern.exec(`` or any receiver this
module cannot prove stays reported.
"""

from __future__ import annotations

import re

_LITERAL_RECEIVER = re.compile(
    r"(?:^|[(,=:\[!&|?{};+\-*%<>~^]|\b(?:return|typeof|await|yield|case|void|in|of|else|do))"
    r"\s*/(?![/*])(?:[^/\\\n\[]|\\.|\[(?:[^\]\\\n]|\\.)*\])+/[dgimsuvy]*$"
)
_REGEXP_CONSTRUCTION = re.compile(r"(?<![\w$.])(?:new\s+)?RegExp$")
# A parenthesis after one of these groups an expression; after anything else
# that ends a value it is a call, whose result is not proven.
_GROUPING_KEYWORD = re.compile(r"\b(?:return|typeof|await|yield|case|void|in|of|else|do)$")
_BINDING = re.compile(
    r"(?<![\w$.])(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::\s*RegExp\s*)?="
    r"\s*(?:/(?![/*])|(?:new\s+)?RegExp\s*\()"
)
_EXEC_CALL = re.compile(r"\bexec\s*\(")
_NAME_AT_END = re.compile(r"(?<![\w$.])([A-Za-z_$][\w$]*)$")
_LOG_CALL_BEFORE = re.compile(
    r"(?<![\w$])(?:console|[\w$]*[Ll]og(?:ger)?)\s*\.\s*"
    r"(?:log|debug|info|warn|error|trace|dir|verbose|silly)\s*\([^()]*$"
)
_QUOTE = r"[\x27\"`]"
# Anything that can change what a regular expression call reaches.
_EXEC_CHANGED = re.compile(
    r"\b(?:defineProperty|defineProperties|setPrototypeOf|getPrototypeOf|__proto__"
    r"|__defineGetter__|__defineSetter__|Proxy)\b"
    r"|\bReflect\s*\.\s*(?:set|defineProperty|setPrototypeOf)\b"
    r"|\.\s*exec\s*=(?!=)"
    rf"|\[\s*{_QUOTE}exec{_QUOTE}\s*\]\s*=(?!=)"
    r"|\bprototype\s*\["
    r"|\bprototype\b\s*(?:[,;)\]}>]|=(?!=)|$)"
    r"|\bconstructor\b[^;\n]*\bprototype\b"
    r"|\b(?:globalThis|global|window)\s*\["
    r"|\b(?:function|class)\s+RegExp\b|\b(?:const|let|var)\s+RegExp\b",
    re.MULTILINE,
)
_REGEXP_NAME = re.compile(r"(?<![\w$])RegExp(?![\w$])")
_TYPESCRIPT = (".ts", ".tsx", ".cts", ".mts")
_LITERAL_WINDOW = 2000


def regexp_may_be_changed(path: str, lines: list[str]) -> bool:
    """True when the file can change what a regular expression call reaches.

    Judged over every file of the plugin before any call is proven, so a
    change made by one file voids the proof in all of them.
    """

    text = "\n".join(lines)
    if _EXEC_CHANGED.search(text) is not None:
        return True
    typescript = path.casefold().endswith(_TYPESCRIPT)
    for line in lines:
        for name in _REGEXP_NAME.finditer(line):
            if not _regexp_name_is_plain(line[:name.start()].rstrip(), line[name.end():].lstrip(), typescript):
                return True
    return False


def _regexp_name_is_plain(before: str, after: str, typescript: bool) -> bool:
    """The name is called, tested with instanceof, or (TypeScript) a type."""

    if after.startswith("("):
        return not re.search(r"\b(?:function|class)\s*\*?$", before)
    if re.search(r"(?<![\w$.])instanceof$", before):
        return True
    if not typescript:
        return False
    return before.endswith((":", "<", "|", "&")) or (before.endswith(",") and after.startswith(">"))


class RegexpReceivers:
    """Judge ``exec(`` calls of one source file; bindings are read on first use.

    The caller has already checked the whole plugin with
    ``regexp_may_be_changed``.
    """

    def __init__(self, lines: list[str]) -> None:
        self._text = "\n".join(lines)
        self._names: frozenset[str] | None = None

    def only_pattern_matches(self, line: str) -> bool:
        """True when every ``exec(`` call on the line is a RegExp match."""

        calls = list(_EXEC_CALL.finditer(line))
        if not calls:
            return False
        return all(self._is_pattern_match(line, call.start()) for call in calls)

    def _is_pattern_match(self, line: str, start: int) -> bool:
        receiver = line[:start].rstrip()
        if not receiver.endswith("."):
            return False
        receiver = receiver[:-1].rstrip()
        if receiver.endswith("?"):
            receiver = receiver[:-1].rstrip()
        return self._is_regexp(receiver)

    def _is_regexp(self, receiver: str) -> bool:
        if _LITERAL_RECEIVER.search(receiver[-_LITERAL_WINDOW:]):
            return True
        if receiver.endswith(")"):
            opening = _opening_of_last_parenthesis(receiver)
            if opening is None:
                return False
            head = receiver[:opening].rstrip()
            if _REGEXP_CONSTRUCTION.search(head):
                return True
            if re.search(r"[\w$)\]]$", head) and not _GROUPING_KEYWORD.search(head):
                return False
            return self._is_regexp(receiver[opening + 1:-1].strip())
        name = _NAME_AT_END.search(receiver)
        return name is not None and name.group(1) in self._regexp_names()

    def _regexp_names(self) -> frozenset[str]:
        if self._names is None:
            self._names = frozenset(
                binding.group(1) for binding in _BINDING.finditer(self._text)
                if _used_only_as_object(self._text, binding)
            )
        return self._names


def _opening_of_last_parenthesis(text: str) -> int | None:
    """Index of the parenthesis that the final ")" of the text closes."""

    stack: list[int] = []
    quote = ""
    index = 0
    while index < len(text):
        char = text[index]
        if quote:
            if char == "\\":
                index += 1
            elif char == quote:
                quote = ""
        elif char in "\x27\"`":
            quote = char
        elif char == "(":
            stack.append(index)
        elif char == ")":
            if not stack:
                return None
            opening = stack.pop()
            if index == len(text) - 1:
                return opening
        index += 1
    return None


def _used_only_as_object(text: str, binding: re.Match[str]) -> bool:
    """Every other use of the bound name is a property access or a log argument."""

    name = re.escape(binding.group(1))
    for use in re.finditer(rf"(?<![\w$.]){name}(?![\w$])", text):
        if use.start() == binding.start(1):
            continue
        if re.match(r"\s*\??\.", text[use.end():use.end() + 8]):
            continue
        line_start = text.rfind("\n", 0, use.start()) + 1
        if _LOG_CALL_BEFORE.search(text[line_start:use.start()]):
            continue
        return False
    return True
