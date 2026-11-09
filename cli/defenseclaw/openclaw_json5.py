# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""The one reader DefenseClaw uses for ``openclaw.json``.

OpenClaw reads ``openclaw.json`` as JSON5 (comments, unquoted keys, single
quotes, trailing commas, hexadecimal numbers), and so does the gateway sidecar
(``internal/jsonc.JSON5ToJSON``). A DefenseClaw command that read the file with
``json.load`` called a file OpenClaw runs on "not JSON" (GAP-0846). Every
Python reader of ``openclaw.json`` goes through ``loads`` or ``load_file`` here,
and the rules below match the Go converter, so the CLI and the sidecar cannot
disagree about what the file says.

``rewrite`` is a normalizer, not a validator: input that is not JSON5 stays
invalid (an unterminated string, container or block comment, a bare ``-``, a
malformed hexadecimal number) and ``loads`` raises ``OpenClawConfigSyntaxError``
with the line and column in the original text.
"""

from __future__ import annotations

import bisect
import json
import re
import unicodedata
from typing import Any

# The JSON5 rewrite (the slow path, a Python loop per character) is skipped for text
# larger than this; openclaw.json is a few KiB. Strict JSON is parsed at any size, as
# before JSON5 support, and as the gateway sidecar does.
MAX_JSON5_CHARS = 4 * 1024 * 1024

_HEX = frozenset("0123456789abcdefABCDEF")
_DIGITS = frozenset("0123456789")
_ASCII_SPACE = " \t\n\r\v\f"
_ZWNJ_ZWJ = ("\u200c", "\u200d")


class OpenClawConfigSyntaxError(ValueError):
    """openclaw.json is neither JSON nor JSON5. ``line`` and ``column`` are 1-based."""

    def __init__(self, message: str, line: int, column: int) -> None:
        super().__init__(f"{message} (line {line}, column {column})")
        self.reason = message
        self.line = line
        self.column = column


def _is_ident_rune(ch: str, first: bool) -> bool:
    if ch == "_" or ch == "$" or "a" <= ch <= "z" or "A" <= ch <= "Z":
        return True
    if ord(ch) < 0x80:
        return (not first) and ch in _DIGITS
    category = unicodedata.category(ch)
    if category.startswith("L") or category == "Nl":
        return True
    return (not first) and (category in ("Mn", "Mc", "Nd", "Pc") or ch in _ZWNJ_ZWJ)


def _is_ident_start_char(ch: str) -> bool:
    return ch == "_" or ch == "$" or "a" <= ch <= "z" or "A" <= ch <= "Z" or ord(ch) >= 0x80


def _is_space(ch: str) -> bool:
    """A non-ASCII JSON5 whitespace or line terminator."""
    return ch in ("\ufeff", "\u2028", "\u2029") or unicodedata.category(ch) == "Zs"


def _unicode_escape(code: int) -> str:
    return f"\\u{code:04x}"


class _Rewriter:
    def __init__(self, text: str) -> None:
        self.s = text
        self.parts: list[str] = []
        self.out_len = 0
        self.out_marks: list[int] = []  # output offset at the start of each part
        self.src_marks: list[int] = []  # source offset of each part

    def emit(self, text: str, src: int) -> None:
        if not text:
            return
        self.out_marks.append(self.out_len)
        self.src_marks.append(src)
        self.parts.append(text)
        self.out_len += len(text)

    def source_offset(self, out_pos: int) -> int:
        if not self.out_marks:
            return 0
        index = max(bisect.bisect_right(self.out_marks, out_pos) - 1, 0)
        return min(self.src_marks[index] + (out_pos - self.out_marks[index]), len(self.s))

    # -- main loop ---------------------------------------------------------

    def run(self) -> str:
        s = self.s
        i = 1 if s.startswith("\ufeff") else 0
        n = len(s)
        while i < n:
            ch = s[i]
            if ch == '"' or ch == "'":
                i = self.string(i)
            elif ch == "/" and i + 1 < n and s[i + 1] in "/*":
                nxt, closed = self.skip_comment(i)
                if not closed:
                    # An unterminated block comment is not JSON5: keep the rest
                    # as it is so the strict parse fails here.
                    self.emit(s[i:], i)
                    return "".join(self.parts)
                self.emit(" ", i)
                i = nxt
            elif ch in "+-." or ch in _DIGITS:
                text, nxt = self.number(i)
                if nxt == i:
                    self.emit(ch, i)
                    nxt = i + 1
                else:
                    self.emit(text, i)
                i = nxt
            elif ch in "\v\f":
                self.emit(" ", i)
                i += 1
            elif ord(ch) < 0x80 and ch != "\\" and not _is_ident_start_char(ch):
                self.emit(ch, i)
                i += 1
            else:
                end = self.scan_identifier(i)
                if end > i:
                    self.emit(self.word(i, end), i)
                    i = end
                else:
                    self.emit(" " if (ord(ch) >= 0x80 and _is_space(ch)) else ch, i)
                    i += 1
        return "".join(self.parts)

    # -- pieces ------------------------------------------------------------

    def skip_comment(self, start: int) -> tuple[int, bool]:
        """Index after the comment at ``start`` and whether it is well formed."""
        s = self.s
        i = start + 2
        if s[start + 1] == "*":
            end = s.find("*/", i)
            if end < 0:
                return len(s), False
            return end + 2, True
        while i < len(s) and s[i] not in "\n\r\u2028\u2029":
            i += 1
        return i, True

    def scan_identifier(self, start: int) -> int:
        s = self.s
        i = start
        n = len(s)
        while i < n:
            if s[i] == "\\":
                if i + 6 > n or s[i + 1] != "u" or not all(c in _HEX for c in s[i + 2 : i + 6]):
                    break
                ch, size = chr(int(s[i + 2 : i + 6], 16)), 6
            else:
                ch, size = s[i], 1
            if not _is_ident_rune(ch, i == start):
                break
            i += size
        return i

    def word(self, start: int, end: int) -> str:
        """An identifier or word: a key is quoted, Infinity and NaN become null."""
        s = self.s
        n = len(s)
        k = end
        while k < n:
            if s[k] == "/" and k + 1 < n and s[k + 1] in "/*":
                nxt, closed = self.skip_comment(k)
                if not closed:
                    break
                k = nxt
                continue
            if s[k] in _ASCII_SPACE or (ord(s[k]) >= 0x80 and _is_space(s[k])):
                k += 1
                continue
            break
        word = s[start:end]
        if k < n and s[k] == ":":
            return '"' + word + '"'
        if word in ("Infinity", "NaN"):
            return "null"
        return word

    def number(self, start: int) -> tuple[str, int]:
        """The JSON number for the JSON5 number at ``start``, or ("", start)."""
        s = self.s
        n = len(s)
        i = start
        sign = ""
        if s[i] in "+-":
            if s[i] == "-":
                sign = "-"
            i += 1
        for word in ("Infinity", "NaN"):
            if s.startswith(word, i):
                end = i + len(word)
                if end < n and _is_ident_rune(s[end], False):
                    return "", start
                return "null", end
        if i + 2 < n and s[i] == "0" and s[i + 1] in "xX":
            end = i + 2
            while end < n and s[end] in _HEX:
                end += 1
            if end == i + 2:
                return "", start
            try:
                return sign + str(int(s[i + 2 : end], 16)), end
            except ValueError:  # beyond the interpreter digit limit
                return "", start
        end = i
        while end < n and s[end] in _DIGITS:
            end += 1
        whole = s[i:end]
        frac = ""
        dot = False
        if end < n and s[end] == ".":
            dot = True
            frac_start = end + 1
            end = frac_start
            while end < n and s[end] in _DIGITS:
                end += 1
            frac = s[frac_start:end]
        if not whole and not frac:
            return "", start
        text = sign + (whole or "0")
        if dot:
            text += "." + (frac or "0")
        if end < n and s[end] in "eE":
            exp = end + 1
            if exp < n and s[exp] in "+-":
                exp += 1
            digits = exp
            while digits < n and s[digits] in _DIGITS:
                digits += 1
            if digits > exp:
                text += s[end:digits]
                end = digits
        return text, end

    def string(self, start: int) -> int:
        """Emit the string at ``start`` as a double-quoted JSON string."""
        s = self.s
        n = len(s)
        quote = s[start]
        self.emit('"', start)
        i = start + 1
        while i < n:
            ch = s[i]
            if ch == quote:
                self.emit('"', i)
                return i + 1
            if ch == "\\" and i + 1 < n:
                i = self.escape(i)
            elif ch == '"':
                self.emit('\\"', i)
                i += 1
            elif ord(ch) < 0x20 and ch not in "\n\r":
                self.emit(_unicode_escape(ord(ch)), i)
                i += 1
            else:
                self.emit(ch, i)
                i += 1
        # Unterminated: the strict parse rejects what was read.
        return i

    def escape(self, at: int) -> int:
        """Rewrite the escape at ``at`` (a backslash); return the index after it."""
        s = self.s
        n = len(s)
        nxt = s[at + 1]
        i = at + 2
        if nxt == "\n":
            return i
        if nxt == "\r":
            return i + 1 if i < n and s[i] == "\n" else i
        if nxt in "bfnrtu\\/\"":
            self.emit("\\" + nxt, at)
            return i
        if nxt == "'":
            self.emit("'", at)
            return i
        if nxt == "v":
            self.emit(_unicode_escape(0x0B), at)
            return i
        if nxt == "x" and i + 1 < n and s[i] in _HEX and s[i + 1] in _HEX:
            self.emit("\\u00" + s[i : i + 2], at)
            return i + 2
        if nxt == "0" and not (i < n and s[i] in _DIGITS):
            self.emit(_unicode_escape(0), at)
            return i
        if ord(nxt) >= 0x80:
            # A backslash before a multi-byte character stands for the
            # character; U+2028 and U+2029 are line continuations.
            return at + 2 if nxt in ("\u2028", "\u2029") else at + 1
        if nxt == "x" or nxt in _DIGITS or ord(nxt) < 0x20:
            # Not valid JSON5: keep the backslash so the strict parse fails.
            self.emit("\\" + nxt, at)
            return i
        self.emit(nxt, at)
        return i


def _strip_trailing_commas(text: str) -> tuple[str, list[int]]:
    """Drop commas before a closing bracket; return the text and each kept char's old offset."""
    out: list[str] = []
    origin: list[int] = []
    in_string = False
    escaped = False
    n = len(text)
    for i, ch in enumerate(text):
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
        elif ch == '"':
            in_string = True
        elif ch == ",":
            j = i + 1
            while j < n and text[j] in " \t\n\r":
                j += 1
            if j < n and text[j] in "}]":
                continue
        out.append(ch)
        origin.append(i)
    return "".join(out), origin


# JSON5 line terminators: LF, CR, CRLF (one terminator), U+2028 and U+2029, nothing else.
_LINE_END = re.compile("\r\n|[\n\r\u2028\u2029]")


def _line_column(text: str, offset: int) -> tuple[int, int]:
    offset = max(0, min(offset, len(text)))
    line, start = 1, 0
    for end in _LINE_END.finditer(text):
        if end.end() > offset:
            break
        line += 1
        start = end.end()
    return line, offset - start + 1


def loads(text: str) -> Any:
    """Parse JSON or JSON5 text; raise ``OpenClawConfigSyntaxError`` when it is neither."""
    try:
        return json.loads(text)
    except json.JSONDecodeError as strict:
        strict_error = strict
    except RecursionError as exc:
        raise OpenClawConfigSyntaxError("nested too deeply", 1, 1) from exc
    if len(text) > MAX_JSON5_CHARS:
        raise OpenClawConfigSyntaxError(
            f"{strict_error.msg}; file is too large to read as JSON5",
            *_line_column(text, strict_error.pos),
        ) from None
    rewriter = _Rewriter(text)
    rewritten, origin = _strip_trailing_commas(rewriter.run())
    try:
        return json.loads(rewritten)
    except json.JSONDecodeError as exc:
        if not origin:
            line, column = _line_column(text, 0)
        else:
            pos = origin[min(exc.pos, len(origin) - 1)]
            line, column = _line_column(text, rewriter.source_offset(pos))
        reason = exc.msg or strict_error.msg
        raise OpenClawConfigSyntaxError(reason, line, column) from None
    except RecursionError as exc:
        raise OpenClawConfigSyntaxError("nested too deeply", 1, 1) from exc


def load_file(path: str) -> Any:
    """Read and parse a JSON/JSON5 file. ``OSError``/``UnicodeError`` pass through."""
    with open(path, "rb") as handle:
        raw = handle.read()
    return loads(raw.decode("utf-8"))
