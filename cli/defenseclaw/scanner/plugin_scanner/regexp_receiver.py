# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Tell RegExp.prototype.exec from command execution for the SRC-EXEC rule.

``exec(`` names two unrelated calls in JavaScript: ``child_process.exec`` runs
a shell command, and ``RegExp.prototype.exec`` matches a pattern. The rule
matches the word, so every package that matches text with ``/re/.exec(text)``
was reported as running commands.

Every judgement here is made on a *code view* of the source (``code_view``):
comments are gone, string and template text is empty, and a regular expression
literal is one marker. A word in a comment or in a string is therefore never a
binding, a call or a mutation, and a comment between two tokens cannot hide a
declaration. A few exact strings that name a property (``"exec"``,
``"constructor"``, ``"prototype"`` and the reflection names) are kept so that a
computed member (``obj["prototype"]``) is still seen.

A call is a pattern match only when its receiver is provably a regular
expression:

* a regular expression literal, bare or in parentheses: ``/re/g.exec(t)``,
  ``(/re/).exec(t)``, ``(a, /re/).exec(t)``;
* a construction: ``new RegExp(...)`` or ``RegExp(...)``;
* a name whose single binding is one of those (``const NAME = /re/``, with or
  without a ``: RegExp`` type) and whose every other use is the object of a
  property access (``NAME.exec(``, ``NAME.lastIndex = 0``) or an argument of a
  logging call. A name that is rebound, passed to any other function, returned,
  indexed or shadowed is not proven and keeps the finding.

Nothing is proven in a plugin that can change what the built-in regular
expression reaches. The guard reads every JavaScript and TypeScript file of the
plugin and follows the routes *to* the built-in object, not spellings of one
property:

* the name ``RegExp`` may only be called (and never declared as a function,
  class, variable or parameter), tested with ``instanceof`` or, in TypeScript,
  used as a type; quoted as an object key or handed to a reflection call it is
  a route too. A method of an object or class that happens to be called
  ``RegExp`` binds nothing: it matters only through the routes above (the
  global object, ``with``);
* ``exec`` is only ever called: reading, assigning, destructuring or indexing
  it is not;
* the global object (``globalThis``, ``global``, ``window``) is only read
  through a plain member or a plain string index, never passed, assigned,
  returned or aliased, because a copy can be written to by a computed name;
  ``eval(`` and ``Function(`` can reach it from a string, and a ``with``
  statement can rebind any name;
* taking a prototype (``getPrototypeOf``, ``__proto__``) or reading a
  constructor in a plugin that names a prototype reaches the built-in only when
  a regular expression can be handed to it, so it voids the proof when some file
  lets a pattern escape (passes it to a call other than a string method that
  only reads it, returns it, stores it). A bundler's ``defineProperty`` and
  ``getPrototypeOf`` helpers over module objects are therefore not a finding.

An unrelated string, comment or class prototype changes nothing.

A bare ``exec(``, ``cp.exec(``, ``obj.pattern.exec(`` or any receiver this
module cannot prove stays reported.
"""

from __future__ import annotations

import re
from typing import NamedTuple

_REGEX_BODY = "\ue000"
# A "/" after one of these characters starts a regular expression literal. "}",
# ")" and "]" are left out: they can end an operand, and a literal wrongly read
# as division only exposes its text to the guard (a false block), while the
# reverse would hide code. The exceptions are the ")" that closes the head of
# an if, while, for or with statement (what follows is a statement, never a
# division) and the "}" that ends a statement block.
_REGEX_AFTER = frozenset("(,=:[!&|?{;+-*%<>~^")
_REGEX_AFTER_WORD = frozenset({
    "return", "typeof", "await", "yield", "case", "void", "in", "of", "else", "do",
    "delete", "instanceof", "new", "throw",
})
_EXPRESSION_KEYWORDS = frozenset({
    "return", "typeof", "await", "yield", "case", "void", "in", "of", "delete", "instanceof", "new", "throw",
})
# Strings that name a property are kept in the code view.
_KEPT_STRINGS = frozenset({"exec", "constructor", "prototype", "__proto__", "RegExp", "getPrototypeOf"})
_SPECIAL = re.compile(r"[\"'`/{}()]")
_WORD_AT_END = re.compile(r"[A-Za-z_$][\w$]*$")
_FLAGS = re.compile(r"[A-Za-z]*")
_CONTROL_HEAD = re.compile(r"(?<![\w$.])(?:if|while|for(?:\s+await)?|with)\s*$")


def code_view(text: str) -> str:
    """The source with comments, string text and literal bodies removed.

    The view has the same number of lines as the source, so line ``n`` of the
    view is line ``n`` of the file.
    """

    out: list[str] = []
    tail = ""
    length = len(text)
    index = 0
    templates: list[int] = []
    braces: list[bool] = []
    parens: list[bool] = []
    block_ended = False
    control_ended = False

    def emit(piece: str) -> None:
        nonlocal tail, block_ended, control_ended
        out.append(piece)
        tail = (tail + piece)[-40:]
        if piece.strip():
            block_ended = False
            control_ended = False

    def template_text(start: int) -> int:
        """Skip template text from ``start``; return where code resumes."""

        position = start
        while position < length:
            char = text[position]
            if char == "\\":
                position += 2
            elif char == "`":
                emit("\n" * text.count("\n", start, position) + "`")
                return position + 1
            elif char == "$" and text.startswith("{", position + 1):
                emit("\n" * text.count("\n", start, position) + "${")
                templates.append(0)
                return position + 2
            else:
                position += 1
        emit("\n" * text.count("\n", start, length))
        return length

    while index < length:
        found = _SPECIAL.search(text, index)
        if found is None:
            emit(text[index:])
            break
        at = found.start()
        if at > index:
            emit(text[index:at])
        char = text[at]
        index = at + 1
        if char == "{":
            if templates:
                templates[-1] += 1
            braces.append(_opens_object(tail))
            emit("{")
        elif char == "}":
            if templates and templates[-1] == 0:
                templates.pop()
                emit("}")
                index = template_text(index)
            else:
                if templates:
                    templates[-1] -= 1
                literal = braces.pop() if braces else False
                emit("}")
                block_ended = not literal
        elif char == "(":
            parens.append(_CONTROL_HEAD.search(tail) is not None)
            emit("(")
        elif char == ")":
            control = parens.pop() if parens else False
            emit(")")
            control_ended = control
        elif char == "`":
            emit("`")
            index = template_text(index)
        elif char in "\"'":
            end, closed = _string_end(text, at)
            body = text[at + 1:end - 1] if closed else text[at + 1:end]
            emit(char + (body if body in _KEPT_STRINGS else "") + "\n" * body.count("\n") + char)
            index = end
        elif text.startswith("//", at):
            newline = text.find("\n", at)
            index = length if newline < 0 else newline
            emit(" ")
        elif text.startswith("/*", at):
            close = text.find("*/", at + 2)
            end = length if close < 0 else close + 2
            emit(" " + "\n" * text.count("\n", at, end))
            index = end
        else:
            end = _regex_end(text, at) if block_ended or control_ended or _regex_allowed(tail) else None
            if end is None:
                emit("/")
            else:
                flags = _FLAGS.match(text, end + 1)
                index = flags.end()
                # After the end of a block the slash is a literal only if that
                # block was a statement; the text stays visible in case it was not.
                exposed = text[at + 1:end] if block_ended else ""
                emit(f"{exposed}/{_REGEX_BODY}/{flags.group()}")
    return "".join(out)


def _opens_object(tail: str) -> bool:
    """A "{" after this text opens an object literal, not a block."""

    significant = tail.rstrip()
    if not significant or significant.endswith("=>"):
        return False
    if significant[-1] in "(,=[?:!&|+-*%<>~^.":
        return True
    word = _WORD_AT_END.search(significant)
    return word is not None and word.group() in _EXPRESSION_KEYWORDS


def _regex_allowed(tail: str) -> bool:
    significant = tail.rstrip()
    if not significant:
        return True
    last = significant[-1]
    if last in "+-":
        return significant[-2:-1] != last
    if last in _REGEX_AFTER:
        return True
    word = _WORD_AT_END.search(significant)
    return word is not None and word.group() in _REGEX_AFTER_WORD


def _string_end(text: str, start: int) -> tuple[int, bool]:
    """Index after the closing quote, and whether there was one."""

    quote = text[start]
    position = start + 1
    while position < len(text):
        char = text[position]
        if char == "\\":
            position += 2
        elif char == quote:
            return position + 1, True
        elif char == "\n":
            return position, False
        else:
            position += 1
    return len(text), False


def _regex_end(text: str, start: int) -> int | None:
    """Index of the closing slash of a literal that starts at ``start``."""

    position = start + 1
    in_class = False
    while position < len(text):
        char = text[position]
        if char == "\n":
            return None
        if char == "\\":
            position += 2
            continue
        if in_class:
            in_class = char != "]"
        elif char == "[":
            in_class = True
        elif char == "/":
            return position
        position += 1
    return None


_LITERAL = re.compile(rf"/{_REGEX_BODY}/[A-Za-z]*")
_LITERAL_AT_END = re.compile(rf"/{_REGEX_BODY}/[A-Za-z]*$")
_CONSTRUCTION = re.compile(r"(?:new\s+)?RegExp")
_REGEXP_CONSTRUCTION_AT_END = re.compile(r"(?<![\w$.])(?:new\s+)?RegExp$")
# A parenthesis after one of these groups an expression; after anything else
# that ends a value it is a call, whose result is not proven.
_GROUPING_KEYWORD = re.compile(r"\b(?:return|typeof|await|yield|case|void|in|of|else|do)$")
_BINDING = re.compile(
    rf"(?<![\w$.])(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::\s*RegExp\s*)?=\s*(?:/{_REGEX_BODY}/[A-Za-z]*|(?P<call>(?:new\s+)?RegExp\s*)(?=\())"
)
_EXEC_CALL = re.compile(r"\bexec\s*\(")
_NAME_AT_END = re.compile(r"(?<![\w$.])([A-Za-z_$][\w$]*)$")
_LOG_CALL_BEFORE = re.compile(
    r"(?<![\w$])(?:console|[\w$]*[Ll]og(?:ger)?)\s*\.\s*"
    r"(?:log|debug|info|warn|error|trace|dir|verbose|silly)\s*\([^()]*$"
)
_NOT_AFTER_INITIALIZER = frozenset(".([?+-*/%&|^<>=!`")
_QUOTE = r"[\x27\"`]"
_NOT_QUOTED = r"(?<![\w$\x27\"`])"
# Anything that can change what the built-in regular expression is or does.
_CHANGES_THE_BUILTIN = re.compile(
    # exec is only ever called; reading, assigning or destructuring it is not.
    r"\.\s*exec\b(?!\s*(?:\(|\?\.\())"
    rf"|\[\s*{_QUOTE}(?:exec|RegExp){_QUOTE}\s*\]"
    # the name RegExp as a quoted object key or method name, or handed to a
    # reflection call (defineProperty(global, "RegExp", ...), __defineGetter__("RegExp", ...))
    rf"|(?:[{{,*]|\b(?:async|get|set|static))\s*{_QUOTE}RegExp{_QUOTE}\s*[:(]"
    rf"|\(\s*{_QUOTE}RegExp{_QUOTE}\s*,|,\s*{_QUOTE}RegExp{_QUOTE}\s*,"
    # a with statement can rebind any name
    r"|(?<![\w$.])with\s*\(",
)
_GLOBAL_NAMES = ("globalThis", "global", "window")
# Uses of the global object that give nobody a copy of it.
_GLOBAL_READ_AFTER = re.compile(
    rf"\s*(?:\??\.\s*[A-Za-z_$#]|(?:\?\.\s*)?\[\s*{_QUOTE}\s*{_QUOTE}\s*\]|[!=]==?|=>?)"
)
_GLOBAL_NOT_A_VALUE_BEFORE = re.compile(
    r"(?<![\w$.])(?:typeof|in|var|let|const|function|class|import|declare)\s*$|[!=]==?\s*$|!\s*$"
)
# "name = <names, operators and members>": the right side hands the global object to a name.
_ALIAS_INITIALIZER = re.compile(r"(?<![\w$.])([A-Za-z_$][\w$]*)\s*=(?![=>])([\w$\s?:|&!=<>.\x27\"`]*)$")
_DESTRUCTURED_FROM = re.compile(r"(?:const|let|var)\s*\{[^{}\[\]]*\}\s*=$")
# Strings that run code can reach the global object by a name nobody wrote.
_STRING_TO_CODE = re.compile(r"(?<![\w$.])(?:eval(?![\w$])|(?:new\s+)?Function\s*\()")
# Ways to take the prototype of a value: harmless unless a regular expression
# can be handed to them (see _regex_escapes).
_PROTOTYPE_OF = re.compile(
    rf"{_NOT_QUOTED}getPrototypeOf\b|\[\s*{_QUOTE}(?:getPrototypeOf|__proto__){_QUOTE}\s*\]"
    rf"|{_NOT_QUOTED}__proto__\b(?!\s*:\s*null\b)"
)
_CONSTRUCTOR_READ = re.compile(
    r"\.\s*constructor\b(?!\s*\.\s*name\b)"
    rf"|\[\s*{_QUOTE}constructor{_QUOTE}\s*\]"
    r"|(?<![\w$.\x27\"`])constructor\s*[:,}]"
)
_PROTOTYPE_NAMED = re.compile(r"\bprototype\b")
_REGEXP_NAME = re.compile(r"(?<![\w$\x27\"`])RegExp(?![\w$])")
_REGEXP_VALUE = re.compile(
    rf"/{_REGEX_BODY}/[A-Za-z]*|(?<![\w$.])(?:new\s+)?RegExp\s*\("
)
# Calls that read a regular expression they are given and keep nothing of it.
_PATTERN_CONSUMER = re.compile(r"\.\s*(?:replace|replaceAll|match|matchAll|split|search|test)\s*$")
_TYPESCRIPT = (".ts", ".tsx", ".cts", ".mts")
_WINDOW = 4000


class FileFacts(NamedTuple):
    """What one file does that matters to the pattern-match proof."""

    changes: bool
    reaches_prototype: bool
    names_the_type: bool
    names_a_prototype: bool
    view: str


def file_facts(path: str, view: str) -> FileFacts:
    """Judge one file's ``code_view``; see ``regexp_may_be_changed`` for the plugin."""

    typescript = path.casefold().endswith(_TYPESCRIPT)
    uses = [
        _regexp_name_use(view, name.start(), name.end(), typescript)
        for name in _REGEXP_NAME.finditer(view)
    ]
    changes = (
        _CHANGES_THE_BUILTIN.search(view) is not None
        or _STRING_TO_CODE.search(view) is not None
        or _global_object_escapes(view)
        or None in uses
    )
    reaches = _PROTOTYPE_OF.search(view) is not None or (
        _CONSTRUCTOR_READ.search(view) is not None and _PROTOTYPE_NAMED.search(view) is not None
    )
    typed = "type" in uses
    return FileFacts(changes, reaches, typed, _PROTOTYPE_NAMED.search(view) is not None, view)


def _global_object_escapes(view: str) -> bool:
    """The global object is used as a value the proof cannot follow.

    A copy of it can be written to under a name computed at run time. A name
    that is assigned the global object (``root = typeof window !== "" ? window :
    global``) is followed the same way, so it may only be read through a member.
    Reading a member or a plain string index, comparing it, ``typeof``, ``in``, naming a
    variable, a key or a parameter ``global``, and destructuring it are not
    uses of the value; neither is a use inside the scope of a variable of the
    same name that holds something else.
    """

    names = set(_GLOBAL_NAMES)
    for _ in range(8):
        pattern = re.compile(r"(?<![\w$.])(?:" + "|".join(map(re.escape, sorted(names))) + r")(?![\w$])")
        grown = False
        for use in pattern.finditer(view):
            if _global_use_is_harmless(view, use, pattern):
                continue
            alias = _alias_of(view, use)
            if alias is None:
                return True
            if alias not in names:
                names.add(alias)
                grown = True
        if not grown:
            return False
    return True


def _global_use_is_harmless(view: str, use: re.Match[str], pattern: re.Pattern[str]) -> bool:
    before = view[max(0, use.start() - 40):use.start()].rstrip()
    after = view[use.end():use.end() + 80]
    if _GLOBAL_READ_AFTER.match(after) or _GLOBAL_NOT_A_VALUE_BEFORE.search(before):
        return True
    if before.endswith(("{", ",")) and after.lstrip().startswith(":"):
        return True
    if _DESTRUCTURED_FROM.search(view[max(0, use.start() - 120):use.start()].rstrip()):
        return True
    if before.endswith(("(", ",")) and _parameter_list_end(view, use.start()) is not None:
        return True
    return _shadowed(view, use.group(), use.start(), pattern)


def _alias_of(view: str, use: re.Match[str]) -> str | None:
    """The name that ``use`` is assigned to, when the statement is ``name = <expression of names>``."""

    head = view[max(0, use.start() - 200):use.start()]
    head = head[max(head.rfind(";"), head.rfind("{"), head.rfind("}")) + 1:]
    found = _ALIAS_INITIALIZER.search(head)
    if found is None or "=" in re.sub(r"[!=]==?", "", found.group(2)):
        return None
    return found.group(1)


def _parameter_list_end(view: str, position: int) -> int | None:
    """Index of the ")" closing the parameter list around ``position`` (a body or an arrow follows), if it is one."""

    depth = 0
    for index in range(position - 1, max(-1, position - _WINDOW), -1):
        char = view[index]
        if char == ")":
            depth += 1
        elif char == "(":
            if depth:
                depth -= 1
                continue
            close = _closing_parenthesis(view, index)
            if close is not None and view[close + 1:close + 61].lstrip().startswith(("{", "=>", ":")):
                return close
            return None
    return None


def _matching_brace(view: str, opening: int) -> int:
    depth = 0
    for index in range(opening, len(view)):
        if view[index] == "{":
            depth += 1
        elif view[index] == "}":
            depth -= 1
            if depth == 0:
                return index
    return len(view)


def _enclosing_block_end(view: str, position: int) -> int:
    depth = 0
    for index in range(position - 1, -1, -1):
        if view[index] == "}":
            depth += 1
        elif view[index] == "{":
            if depth == 0:
                return _matching_brace(view, index)
            depth -= 1
    return len(view)


def _body_end(view: str, close: int) -> int:
    """End of the function whose parameter list closes at ``close``."""

    rest = view[close + 1:close + 61]
    body = close + 1 + (len(rest) - len(rest.lstrip()))
    if view.startswith("=>", body):
        body += 2
        while body < len(view) and view[body].isspace():
            body += 1
    elif view.startswith(":", body):
        brace = view.find("{", body)
        body = brace if 0 <= brace <= body + 80 else body
    if view.startswith("{", body):
        return _matching_brace(view, body)
    stop = [at for at in (view.find(";", body), view.find("\n", body)) if at >= 0]
    return min(stop) if stop else len(view)


def _shadowed(view: str, name: str, position: int, pattern: re.Pattern[str]) -> bool:
    """``name`` at ``position`` is a variable or parameter of that name, not the global object."""

    word = re.escape(name)
    for declared in re.finditer(rf"(?<![\w$.])(?:const|let|var)\s+{word}(?![\w$])", view[:position]):
        initializer = re.split(r"[;\n]", view[declared.end():declared.end() + 200], maxsplit=1)[0]
        if pattern.search(initializer):
            continue
        if position < _enclosing_block_end(view, declared.start()):
            return True
    for parameter in re.finditer(rf"[(,]\s*{word}(?![\w$])", view[:position]):
        close = _parameter_list_end(view, parameter.end())
        if close is not None and close < position < _body_end(view, close):
            return True
    return False


def regexp_may_be_changed(facts: list[FileFacts]) -> bool:
    """True when the plugin can change what a regular expression call reaches.

    Judged over every file of the plugin before any call is proven, so a change
    made by one file voids the proof in all of them. Taking a prototype or a
    constructor changes nothing by itself: it matters only when a regular
    expression can reach it, so it voids the proof when some file lets one
    escape (and, in the file that takes it, the escape need not be in the same
    file: the plugin shares values between its files).
    """

    if any(fact.changes for fact in facts):
        return True
    # A TypeScript type position and a ternary branch read the same: in a plugin
    # that also names a prototype, a mention of the type may be a value.
    if any(fact.names_the_type for fact in facts) and any(fact.names_a_prototype for fact in facts):
        return True
    return any(fact.reaches_prototype for fact in facts) and any(_regex_escapes(fact.view) for fact in facts)


def _regex_escapes(view: str) -> bool:
    """A regular expression is handed to code the proof cannot see.

    A literal or construction is contained when it is the object of a member
    access (other than ``constructor`` or ``__proto__``), the pattern argument
    of a string method that only reads it, or the single initializer of a name
    whose every use is a property access or a log argument. Anything else (an
    argument of another call, a returned or stored value, a name that is
    passed on) lets it reach any helper in the plugin.
    """

    receivers = RegexpReceivers(view)
    names = receivers.contained_names()
    for found in _REGEXP_VALUE.finditer(view):
        end = found.end()
        if found.group().endswith("("):
            close = _closing_parenthesis(view, end - 1)
            if close is None:
                return True
            end = close + 1
        else:
            end = found.end()
        before = view[max(0, found.start() - 80):found.start()].rstrip()
        after = view[end:end + 40].lstrip()
        member = re.match(r"\??\.\s*([A-Za-z_$][\w$]*)", after)
        if member is not None and member.group(1) not in ("constructor", "__proto__"):
            continue
        opener = before[:-1].rstrip() if before.endswith("(") else None
        if opener is not None:
            grouping = not re.search(r"[\w$)\]]$", opener) or _GROUPING_KEYWORD.search(opener) is not None
            if grouping and re.match(r"\)\s*\??\.\s*(?!constructor\b|__proto__\b)[A-Za-z_$]", after):
                continue
            if _PATTERN_CONSUMER.search(opener) and after.startswith((",", ")")):
                continue
        initializer = re.search(r"(?<![\w$.])(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::\s*RegExp\s*)?=$", before)
        if initializer is not None and initializer.group(1) in names:
            continue
        return True
    return False


def _regexp_name_use(view: str, start: int, end: int, typescript: bool) -> str | None:
    """How the name is used: "value" (called, not declared; tested with
    instanceof), "type" (TypeScript type position) or None (anything else)."""

    before = view[max(0, start - 80):start].rstrip()
    after = end
    while after < len(view) and view[after].isspace():
        after += 1
    if view.startswith("(", after):
        if re.search(r"\b(?:function|class)\s*\*?$", before):
            return None
        # RegExp(...) { is a method declaration. It binds nothing: only a route
        # to the global object or a with statement could make it the callee.
        return "value" if _closing_parenthesis(view, after) is not None else None
    if re.search(r"(?<![\w$.])instanceof$", before):
        return "value"
    if typescript and (
        before.endswith((":", "<", "|", "&")) or (before.endswith(",") and view.startswith(">", after))
    ):
        return "type"
    return None


def _closing_parenthesis(text: str, opening: int) -> int | None:
    depth = 0
    for position in range(opening, min(len(text), opening + _WINDOW)):
        char = text[position]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return position
    return None


def _opening_parenthesis(text: str, closing: int) -> int | None:
    """Index of the parenthesis that the ")" at ``closing`` closes."""

    depth = 0
    for position in range(closing, max(-1, closing - _WINDOW), -1):
        char = text[position]
        if char == ")":
            depth += 1
        elif char == "(":
            depth -= 1
            if depth == 0:
                return position
    return None


class RegexpReceivers:
    """Judge ``exec(`` calls of one source file; bindings are read on first use.

    The caller has already checked the whole plugin with
    ``regexp_may_be_changed``.
    """

    def __init__(self, view: str) -> None:
        self._view = view
        self._starts = [0]
        self._starts.extend(match.end() for match in re.finditer("\n", view))
        self._names: frozenset[str] | None = None

    def only_pattern_matches(self, line_index: int) -> bool:
        """True when every ``exec(`` call on the line is a RegExp match."""

        if line_index >= len(self._starts):
            return False
        begin = self._starts[line_index]
        finish = self._starts[line_index + 1] if line_index + 1 < len(self._starts) else len(self._view)
        calls = list(_EXEC_CALL.finditer(self._view, begin, finish))
        return bool(calls) and all(self._is_pattern_match(call.start()) for call in calls)

    def _is_pattern_match(self, start: int) -> bool:
        receiver = self._view[max(0, start - _WINDOW):start].rstrip()
        if not receiver.endswith("."):
            return False
        receiver = receiver[:-1].rstrip()
        if receiver.endswith("?"):
            receiver = receiver[:-1].rstrip()
        return self._is_regexp(receiver)

    def _is_regexp(self, receiver: str) -> bool:
        """The last operand of ``receiver`` (it ends right before ``.exec``) is a regular expression."""

        if _LITERAL_AT_END.search(receiver):
            return True
        if receiver.endswith(")"):
            opening = _opening_parenthesis(receiver, len(receiver) - 1)
            if opening is None:
                return False
            head = receiver[:opening].rstrip()
            if _REGEXP_CONSTRUCTION_AT_END.search(head):
                return True
            if re.search(r"[\w$)\]]$", head) and not _GROUPING_KEYWORD.search(head):
                return False
            return self._is_whole(receiver[opening + 1:-1])
        name = _NAME_AT_END.search(receiver)
        return name is not None and name.group(1) in self.regexp_names()

    def _is_whole(self, expression: str) -> bool:
        """The value of the whole expression is a regular expression."""

        expression = expression.strip()
        comma = _last_top_level_comma(expression)
        if comma is not None:
            return self._is_whole(expression[comma + 1:])
        if _LITERAL.fullmatch(expression):
            return True
        if expression.endswith(")"):
            opening = _opening_parenthesis(expression, len(expression) - 1)
            if opening is None:
                return False
            head = expression[:opening].strip()
            if _CONSTRUCTION.fullmatch(head):
                return True
            return head == "" and self._is_whole(expression[opening + 1:-1])
        return re.fullmatch(r"[A-Za-z_$][\w$]*", expression) is not None and expression in self.regexp_names()

    def contained_names(self) -> frozenset[str]:
        """Names bound to a regular expression that is only read, never passed on."""

        return frozenset(
            binding.group(1) for binding in _BINDING.finditer(self._view)
            if _initializer_ends(self._view, binding) and _used_only_as_object(self._view, binding, consumers=True)
        )

    def regexp_names(self) -> frozenset[str]:
        if self._names is None:
            self._names = frozenset(
                binding.group(1) for binding in _BINDING.finditer(self._view)
                if _initializer_ends(self._view, binding) and _used_only_as_object(self._view, binding)
            )
        return self._names


def _last_top_level_comma(expression: str) -> int | None:
    depth = 0
    found = None
    for position, char in enumerate(expression):
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
        elif char == "," and depth == 0:
            found = position
    return found


def _initializer_ends(view: str, binding: re.Match[str]) -> bool:
    """The initializer is exactly the literal or construction (no ``|| other``, no member)."""

    position = binding.end()
    if binding.group("call") is not None:
        close = _closing_parenthesis(view, position)
        if close is None:
            return False
        position = close + 1
    while position < len(view) and view[position] in " \t\r":
        position += 1
    if position >= len(view) or view[position] in ";,})":
        return True
    if view[position] != "\n":
        return False
    while position < len(view) and view[position].isspace():
        position += 1
    return position >= len(view) or view[position] not in _NOT_AFTER_INITIALIZER


def _used_only_as_object(view: str, binding: re.Match[str], consumers: bool = False) -> bool:
    """Every other use of the bound name is a property access or a log argument.

    With ``consumers`` the pattern argument of a string method that only reads
    it (``text.replace(NAME, ...)``) is a use too.
    """

    name = re.escape(binding.group(1))
    for use in re.finditer(rf"(?<![\w$.]){name}(?![\w$])", view):
        if use.start() == binding.start(1):
            continue
        if re.match(r"\s*\??\.(?!\s*(?:constructor|__proto__)\b)", view[use.end():use.end() + 24]):
            continue
        line_start = view.rfind("\n", 0, use.start()) + 1
        if _LOG_CALL_BEFORE.search(view[line_start:use.start()]):
            continue
        opener = view[max(0, use.start() - 80):use.start()].rstrip()
        if (
            consumers
            and opener.endswith("(")
            and _PATTERN_CONSUMER.search(opener[:-1].rstrip())
            and view[use.end():use.end() + 8].lstrip().startswith((",", ")"))
        ):
            continue
        return False
    return True
