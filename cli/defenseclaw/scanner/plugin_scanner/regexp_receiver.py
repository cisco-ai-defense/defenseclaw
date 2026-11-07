# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Tell RegExp.prototype.exec from command execution for the SRC-EXEC rule.

``exec(`` names two unrelated calls in JavaScript: ``child_process.exec`` runs
a shell command, and ``RegExp.prototype.exec`` matches a pattern. The rule
matches the word, so every package that matches text with ``/re/.exec(text)``
was reported as running commands. A call is a pattern match only when its
receiver is provably a regular expression in this file:

* a regular expression literal, as in ``/re/g.exec(text)``;
* a name whose single binding is ``const NAME = /re/`` or
  ``const NAME = new RegExp(...)`` and which is used nowhere else except as the
  object of a property access (``NAME.exec(``, ``NAME.lastIndex = 0``). A name
  that is rebound, passed to a function, returned, or shadowed by a parameter
  is not proven and keeps the finding.

A bare ``exec(``, ``cp.exec(``, ``obj.pattern.exec(`` or any receiver this
module cannot prove stays reported.
"""

from __future__ import annotations

import re

# Characters before a regular expression literal: an operator or opening
# bracket, or a keyword that ends an expression position.
_LITERAL_RECEIVER = re.compile(
    r"(?:^|[(,=:\[!&|?{};+\-*%<>~^]|\b(?:return|typeof|await|yield|case|void|in|of|else|do))"
    r"\s*/(?![/*])(?:[^/\\\n\[]|\\.|\[(?:[^\]\\\n]|\\.)*\])+/[dgimsuvy]*$"
)
_BINDING = re.compile(
    r"(?<![\w$.])(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:/(?![/*])|new\s+RegExp\s*\()"
)
_EXEC_CALL = re.compile(r"\bexec\s*\(")
_NAME_AT_END = re.compile(r"(?<![\w$.])([A-Za-z_$][\w$]*)$")
_LITERAL_WINDOW = 2000


class RegexpReceivers:
    """Judge ``exec(`` calls of one source file; bindings are read on first use."""

    def __init__(self, lines: list[str]) -> None:
        self._lines = lines
        self._names: frozenset[str] | None = None

    def only_pattern_matches(self, line: str) -> bool:
        """True when every ``exec(`` call on the line is a RegExp match."""

        calls = list(_EXEC_CALL.finditer(line))
        return bool(calls) and all(self._is_pattern_match(line, call.start()) for call in calls)

    def _is_pattern_match(self, line: str, start: int) -> bool:
        receiver = line[:start].rstrip()
        if not receiver.endswith("."):
            return False
        receiver = receiver[:-1].rstrip()
        if receiver.endswith("?"):
            receiver = receiver[:-1].rstrip()
        if _LITERAL_RECEIVER.search(receiver[-_LITERAL_WINDOW:]):
            return True
        name = _NAME_AT_END.search(receiver)
        return name is not None and name.group(1) in self._regexp_names()

    def _regexp_names(self) -> frozenset[str]:
        if self._names is None:
            text = "\n".join(self._lines)
            self._names = frozenset(
                binding.group(1) for binding in _BINDING.finditer(text)
                if _used_only_as_object(text, binding)
            )
        return self._names


def _used_only_as_object(text: str, binding: re.Match[str]) -> bool:
    """Every other use of the bound name is the object of a property access."""

    name = re.escape(binding.group(1))
    for use in re.finditer(rf"(?<![\w$.]){name}(?![\w$])", text):
        if use.start() == binding.start(1):
            continue
        if not re.match(r"\s*\??\.", text[use.end():use.end() + 8]):
            return False
    return True
