# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""Small terminal renderer shared by first-run commands.

The renderer intentionally keeps presentation out of the bootstrap
backend. It honors non-TTY/NO_COLOR output, gives operators concise step
lines, and still produces plain text that is friendly to CI logs.

In addition to the :class:`CLIRenderer` (used by the structured
first-run pipeline), this module exports a handful of small *free
functions* — :func:`section`, :func:`subhead`, :func:`ok`,
:func:`warn`, :func:`err`, :func:`hint`, :func:`kv`, :func:`bold`,
:func:`dim`, and :func:`accent` — so ad-hoc setup wizards (e.g.
``defenseclaw setup guardrail``) can colorize their output without
instantiating a renderer per call site. They share the same TTY +
``NO_COLOR`` detection rule as :class:`CLIRenderer`, but the gate is
recomputed on every call so a test that monkey-patches
``sys.stdout`` or ``os.environ`` behaves predictably.
"""

from __future__ import annotations

import atexit
import os
import re
import sys
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

import click


def tui_unavailable_message(*, stdin: object | None = None, stdout: object | None = None) -> str:
    """Explain the failed terminal prerequisite with a platform-specific remedy."""

    if not _stream_is_tty(sys.stdin if stdin is None else stdin) or not _stream_is_tty(
        sys.stdout if stdout is None else stdout
    ):
        return (
            "The interactive dashboard needs a terminal on stdin and stdout. "
            "Run 'defenseclaw tui' directly in a terminal, without a pipe or redirect."
        )
    if os.environ.get("TERM", "").strip().lower() == "dumb":
        return (
            "The interactive dashboard cannot run with TERM=dumb. "
            "Open a terminal with TERM=xterm-256color and run 'defenseclaw tui' again."
        )
    if sys.platform == "win32":
        return (
            "The interactive dashboard needs a UTF-8 capable terminal. "
            "Open Windows Terminal or PowerShell 7 and run 'defenseclaw tui' again."
        )
    terminal = "Terminal.app or iTerm2" if sys.platform == "darwin" else "a UTF-8 terminal or tmux"
    return f"The interactive dashboard needs UTF-8 output. Open {terminal} and run 'defenseclaw tui' again."

# ``main()`` snapshots this before it reconfigures Python's streams to UTF-8.
# Without the snapshot, a legacy cp1252/OEM stream would look capable after the
# reconfigure even though its terminal host still cannot render these glyphs.
_configured_unicode_output: bool | None = None
# stderr gets its own snapshot: '2> file' with stdout on a terminal must still
# write stable ASCII into the file (GAP-2564).
_configured_unicode_error_output: bool | None = None

_UNICODE_PROBE = "✓✗⚠─═└—↪"
_ASCII_PRESENTATION_TRANSLATION = str.maketrans(
    {
        "✓": "OK",
        "✔": "OK",
        "✗": "X",
        "✘": "X",
        "⚠": "!",
        "─": "-",
        "━": "-",
        "═": "=",
        "│": "|",
        "┃": "|",
        "║": "|",
        "┏": "+",
        "┓": "+",
        "┗": "+",
        "┛": "+",
        "┳": "+",
        "┻": "+",
        "┡": "+",
        "┩": "+",
        "╇": "+",
        "┌": "+",
        "┐": "+",
        "└": "\\",
        "┘": "+",
        "├": "+",
        "┤": "+",
        "┬": "+",
        "┴": "+",
        "┼": "+",
        "╭": "+",
        "╮": "+",
        "╯": "+",
        "╰": "+",
        "—": "-",
        "–": "-",
        "→": "->",
        "←": "<-",
        "↪": "->",
        "↳": "->",
        "⇒": "=>",
        "ℹ": "i",
        "≤": "<=",
        "≥": ">=",
        "…": "...",
        "•": "*",
        "·": "-",
        "●": "*",
        "○": "o",
    }
)


# Table rows are cut at these; a border line holds only these and spaces.
_TABLE_VERTICALS = "│┃║"
_TABLE_ROW_SPLIT = re.compile(f"([{_TABLE_VERTICALS}])")
_TABLE_BORDER_CHARS = frozenset("─━═┌┐└┘├┤┬┴┼┏┓┗┛┳┻┡┩╇╭╮╯╰ ")


def _fit_ascii_cell(cell: str, width: int) -> str:
    """Shrink a translated table cell back to its rendered width."""

    body = cell.rstrip(" ")
    if len(body) <= width:
        # The cell's right padding absorbs the extra characters.
        return body + " " * (width - len(body))
    right_pad = 1 if cell.endswith(" ") else 0
    room = max(width - right_pad, 0)
    if body.endswith("...") and room >= 3:
        body = body[: room - 3].rstrip(" ") + "..."
    else:
        body = body[:room]
    return body + " " * (width - len(body))


def _ascii_presentation_line(line: str) -> str:
    """Translate one line; table cells and borders keep their widths."""

    stripped = line.strip()
    if stripped and set(stripped) <= _TABLE_BORDER_CHARS:
        # A tree branch "└─ x" stays "\- x"; a table's bottom-left corner is "+".
        return line.replace("└", "+").translate(_ASCII_PRESENTATION_TRANSLATION)
    if not any(ch in line for ch in _TABLE_VERTICALS):
        return line.translate(_ASCII_PRESENTATION_TRANSLATION)
    out = []
    for part in _TABLE_ROW_SPLIT.split(line):
        new = part.translate(_ASCII_PRESENTATION_TRANSLATION)
        if len(new) > len(part) and part not in _TABLE_VERTICALS:
            new = _fit_ascii_cell(new, len(part))
        out.append(new)
    return "".join(out)


def ascii_presentation_text(text: str) -> str:
    """Downgrade presentation glyphs to ASCII, keeping table columns aligned."""

    if not any(ch in text for ch in _TABLE_VERTICALS) and "└" not in text:
        return text.translate(_ASCII_PRESENTATION_TRANSLATION)
    return "".join(_ascii_presentation_line(line) for line in text.splitlines(keepends=True))


def _stream_is_tty(stream: object) -> bool:
    try:
        return bool(stream.isatty())  # type: ignore[attr-defined]
    except (AttributeError, OSError, ValueError):
        return False


def _stream_supports_unicode(stream: object) -> bool:
    """Return whether an interactive stream can encode CLI presentation glyphs."""

    if not _stream_is_tty(stream):
        # Redirected output is deliberately stable ASCII even when the target
        # file happens to use UTF-8. Machine-readable JSON bypasses this layer.
        return False
    try:
        encoding = getattr(stream, "encoding", None)
    except (AttributeError, OSError, ValueError):
        return False
    if not isinstance(encoding, str) or not encoding:
        return False
    try:
        _UNICODE_PROBE.encode(encoding)
    except (LookupError, UnicodeEncodeError):
        return False
    return True


def configure_console_output(stream: object | None = None, err_stream: object | None = None) -> bool:
    """Snapshot whether human CLI output may use rich Unicode presentation.

    ``TERM=dumb`` is the explicit native-launch fallback. Otherwise the stream
    must be an interactive stream whose original encoding supports the complete
    presentation-glyph set. stdout and stderr are snapshotted separately; an
    explicit *stream* without *err_stream* leaves stderr alone. Call this before any
    UTF-8 stream reconfiguration. Returns the stdout policy.
    """

    global _configured_unicode_output, _configured_unicode_error_output
    dumb = os.environ.get("TERM", "").strip().lower() == "dumb"
    target = sys.stdout if stream is None else stream
    _configured_unicode_output = not dumb and _stream_supports_unicode(target)
    if err_stream is not None or stream is None:
        err_target = sys.stderr if err_stream is None else err_stream
        _configured_unicode_error_output = not dumb and _stream_supports_unicode(err_target)
    return _configured_unicode_output


def unicode_output_enabled(*, err: bool = False) -> bool:
    """Return the policy snapshot, preserving rich output before configuration.

    The default keeps direct library/Click-test use backward-compatible. The
    shipped entrypoint always calls :func:`configure_console_output` first.
    ``err=True`` asks about stderr, which follows stdout until it has its
    own snapshot.
    """

    if os.environ.get("TERM", "").strip().lower() == "dumb":
        return False
    snapshot = _configured_unicode_output
    if err and _configured_unicode_error_output is not None:
        snapshot = _configured_unicode_error_output
    if snapshot is None:
        return True
    return snapshot


def console_text(text: str, *, err: bool = False) -> str:
    """Downgrade presentation glyphs while preserving ordinary Unicode text."""

    if unicode_output_enabled(err=err):
        return text
    return ascii_presentation_text(text)


def _console_output_code_page() -> int:
    """Return the attached Windows console's output code page, or 0."""

    try:
        import ctypes

        return int(ctypes.windll.kernel32.GetConsoleOutputCP())  # type: ignore[attr-defined]
    except (AttributeError, OSError, ValueError):
        return 0


class _ASCIIPresentationStream:
    """Text stream proxy that writes presentation glyphs as ASCII.

    Rich sizes table columns before the glyphs are swapped, so a table row is
    held until its newline arrives and its cells are then fitted back to their
    widths (GAP-1757). Rich's Windows renderer writes a row piece by piece.
    """

    def __init__(self, stream: Any) -> None:
        self._stream = stream
        self._pending = ""
        atexit.register(self._drain)

    def write(self, text: Any) -> int:
        if not isinstance(text, str):
            return self._stream.write(text)
        data = self._pending + text
        self._pending = ""
        head, newline, tail = data.rpartition("\n")
        if tail and any(ch in tail for ch in _TABLE_VERTICALS):
            self._pending = tail
            data = head + newline
        if data:
            self._stream.write(ascii_presentation_text(data))
        return len(text)

    def _drain(self) -> None:
        if self._pending:
            pending, self._pending = self._pending, ""
            try:
                self._stream.write(ascii_presentation_text(pending))
                self._stream.flush()
            except (OSError, ValueError):
                pass

    def writelines(self, lines: Any) -> None:
        for line in lines:
            self.write(line)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._stream, name)


def ascii_safe_redirected_stream(stream: Any) -> Any:
    """Wrap a Windows stream that is piped through a legacy-code-page console.

    PowerShell decodes a native command's piped output (``defenseclaw ... |
    Out-Host``) with the console code page, so the UTF-8 bytes of a glyph such
    as ``✓`` come out as mojibake. Output written straight through ``click.echo``
    skips :func:`console_text`, so the downgrade happens at the stream. JSON
    output is unaffected: it escapes these characters.
    """

    if sys.platform != "win32" or stream is None or _stream_is_tty(stream):
        return stream
    if _console_output_code_page() in (0, 65001):
        return stream
    return _ASCIIPresentationStream(stream)


def table_cell_text(text: str) -> str:
    """A Rich table cell as the output stream will print it.

    Behind :func:`ascii_safe_redirected_stream` a glyph turns into wider
    ASCII ("✓" -> "OK") after Rich sized the column, which can eat the
    cell's right padding (GAP-1972). Swapping first sizes the column right.
    """

    if isinstance(sys.stdout, _ASCIIPresentationStream):
        return ascii_presentation_text(text)
    return text


def echo(message: object | None = None, **kwargs: object) -> None:
    """Call :func:`click.echo` with presentation-safe human output."""

    if isinstance(message, str):
        message = console_text(message, err=bool(kwargs.get("err")))
    click.echo(message, **kwargs)


def secho(message: object | None = None, **kwargs: object) -> None:
    """Call :func:`click.secho` with presentation-safe human output."""

    if isinstance(message, str):
        message = console_text(message, err=bool(kwargs.get("err")))
    click.secho(message, **kwargs)


def terminal_supports_tui(*, stdin: object | None = None, stdout: object | None = None) -> bool:
    """Return whether both streams and the rendering policy can host Textual."""

    input_stream = sys.stdin if stdin is None else stdin
    output_stream = sys.stdout if stdout is None else stdout
    return unicode_output_enabled() and _stream_is_tty(input_stream) and _stream_is_tty(output_stream)


@dataclass
class CLIRenderer:
    """Minimal status renderer for CLI setup flows."""

    color: bool | None = None
    quiet: bool = False

    def __post_init__(self) -> None:
        if self.color is None:
            self.color = unicode_output_enabled() and sys.stdout.isatty() and "NO_COLOR" not in os.environ

    def echo(self, text: str = "", *, err: bool = False) -> None:
        if self.quiet:
            return
        echo(text, err=err)

    def title(self, text: str, subtitle: str = "") -> None:
        if self.quiet:
            return
        self.echo()
        self.echo(self._style(f"  {text}", fg="cyan", bold=True))
        if subtitle:
            self.echo(self._style(f"  {subtitle}", fg="bright_black"))
        self.echo("  " + self._style("─" * 56, fg="bright_black"))

    def section(self, text: str) -> None:
        if self.quiet:
            return
        self.echo()
        self.echo(self._style(f"  {text}", fg="bright_black", bold=True))

    def step(self, status: str, label: str, detail: str = "") -> None:
        if self.quiet:
            return
        icon = {
            "pass": "✓",
            "warn": "!",
            "fail": "x",
            "skip": "-",
        }.get(status, "-")
        fg = {
            "pass": "green",
            "warn": "yellow",
            "fail": "red",
            "skip": "bright_black",
        }.get(status, "white")
        line = f"  {self._style(icon, fg=fg, bold=True)} {label}"
        if detail:
            line += self._style(f"  {detail}", fg="bright_black")
        self.echo(line)

    def _style(self, text: str, **kwargs) -> str:
        text = console_text(text)
        if not self.color:
            return text
        return click.style(text, **kwargs)


# ---------------------------------------------------------------------------
# Module-level free helpers used by ad-hoc setup wizards
# ---------------------------------------------------------------------------
#
# Design contract (shared by every helper below):
#
#   * Each helper reads :func:`_color_enabled` per call so tests that
#     monkey-patch ``sys.stdout`` or ``NO_COLOR`` see the new state
#     immediately. Caching the gate on import would freeze the
#     decision to whatever the first call observed — that bit a
#     past iteration of this module so the live evaluation is
#     deliberate.
#   * Honors the de-facto cross-tool conventions:
#       - ``NO_COLOR`` env var (any value) disables colors.
#         See https://no-color.org for the cross-vendor spec.
#       - Non-TTY stdout disables colors.
#       - ``CLICOLOR_FORCE`` / ``FORCE_COLOR`` can opt back into color only
#         when the snapshotted rendering policy is Unicode-capable.
#   * Returns plain strings (no side-effects) so callers can compose
#     them inside ``f"…"`` and ``click.echo``. A separate helper
#     (:func:`section`) emits two lines for headings; that one prints
#     directly because the divider is ALWAYS bound to the heading.
#
# These helpers exist BECAUSE :class:`CLIRenderer` is overkill for
# wizard flows that already do their own ``click.echo`` layout. They
# are intentionally additive: existing call sites that use
# :class:`CLIRenderer` keep working unchanged.


def _color_enabled() -> bool:
    """Return ``True`` when colorized output is appropriate.

    Recomputed on every call so monkey-patched stdout / env vars in
    tests take effect immediately. Order:

      1. ASCII-safe / ``TERM=dumb`` rendering → False. ANSI controls are not
         safe to inject into the final legacy fallback.
      2. ``CLICOLOR_FORCE`` / ``FORCE_COLOR`` truthy → True (force
         colors even when not a TTY; the standard "yes I really
         want colors in my piped log" escape hatch).
      3. ``NO_COLOR`` set (any value) → False. Per
         https://no-color.org any presence — including empty — means
         "no color".
      4. ``sys.stdout.isatty()`` → use that.
    """
    if not unicode_output_enabled():
        return False
    if os.environ.get("CLICOLOR_FORCE", "").strip() or os.environ.get("FORCE_COLOR", "").strip():
        return True
    if "NO_COLOR" in os.environ:
        return False
    try:
        return bool(sys.stdout.isatty())
    except (AttributeError, ValueError):
        # ``sys.stdout`` may have been swapped for a non-stream
        # object in tests or under unusual reentrancy; degrade to
        # "no color" rather than crashing.
        return False


def _style(text: str, **kwargs: object) -> str:
    """Wrap :func:`click.style` with the color gate.

    Centralized so every helper picks up policy changes (NO_COLOR,
    forced color, TTY downgrade) from a single check.
    """
    text = console_text(text)
    if not _color_enabled():
        return text
    return click.style(text, **kwargs)


def bold(text: str) -> str:
    """Bold the text (no color change)."""
    return _style(text, bold=True)


def dim(text: str) -> str:
    """Dim text — typically for explanatory copy below a heading."""
    return _style(text, fg="bright_black")


def accent(text: str) -> str:
    """Cyan accent for inline emphasis on key concepts."""
    return _style(text, fg="cyan")


def hint(text: str) -> str:
    """Dim hint text — same color as :func:`dim` but spelled out
    for caller intent (``hint('...')`` reads better than ``dim``
    when the line is a parenthetical aside)."""
    return _style(text, fg="bright_black")


def section(title: str, *, indent: str = "  ", divider_char: str = "─") -> None:
    """Print a bold cyan heading with a colored divider underneath.

    Two lines are emitted — heading and divider — and a leading
    blank line precedes the heading so back-to-back sections don't
    visually run together. Divider length matches ``len(title)`` so
    the underline tracks the heading width.

    Use for wizard-level section breaks (``LLM Guardrail Setup``,
    ``Hook fail mode``, ``Human Approval``, etc.). For inline
    emphasis use :func:`accent` instead.
    """
    echo()
    echo(f"{indent}{_style(title, fg='cyan', bold=True)}")
    echo(f"{indent}{_style(divider_char * len(title), fg='cyan')}")


def banner(
    title: str,
    *,
    indent: str = "  ",
    width: int = 54,
    divider_char: str = "─",
    leading_blank: bool = True,
) -> None:
    """Print a full-width ``── Title ─────…──`` banner.

    Used by long-form flows (``defenseclaw init``,
    ``defenseclaw upgrade``, ``defenseclaw uninstall``) where the
    section dividers are tall and wide so the operator can locate
    them when scrolling back through a 200-line transcript.

    The banner format is ``── <title> ───…───`` extending to ``width``
    columns; we intentionally keep the layout legacy-compatible
    when colors are off so existing tests that grep for
    ``"── Environment ──"`` keep matching unchanged. Color-on
    bolds the title and dims the dashes so the title pops without
    making the dashes shouty.
    """
    if leading_blank:
        echo()
    label = f" {title} "
    side = max(2, (width - len(label)) // 2)
    left = divider_char * side
    right = divider_char * (width - side - len(label))
    if _color_enabled():
        echo(
            f"{indent}{_style(left, fg='bright_black')}"
            f" {_style(title, fg='cyan', bold=True)} "
            f"{_style(right, fg='bright_black')}"
        )
    else:
        # Plain mode keeps the legacy "── Title ──────...──"
        # format exactly so any test or screen scraper that
        # grep-substrings on ``"── Environment ──"`` keeps
        # matching.
        echo(f"{indent}{left}{label}{right}")
    echo()


def subhead(text: str, *, indent: str = "  ") -> None:
    """Print a single dim subhead/explanatory line.

    Mirrors :meth:`CLIRenderer.section` color — bright_black so it
    visually recedes below the cyan heading without disappearing.
    """
    echo(f"{indent}{dim(text)}")


def ok(text: str, *, indent: str = "  ", marker: str = "✓") -> None:
    """Print a green success line: ``  ✓ {text}``."""
    echo(f"{indent}{_style(marker, fg='green', bold=True)} {text}")


def warn(text: str, *, indent: str = "  ", marker: str = "⚠") -> None:
    """Print a yellow warning line: ``  ⚠ {text}``.

    Use for non-fatal advisories (e.g., "Configuration not saved";
    "redaction is OFF in shared deployments"). Reserve :func:`err`
    for genuinely failed operations.
    """
    echo(f"{indent}{_style(marker, fg='yellow', bold=True)} {_style(text, fg='yellow')}")


def err(text: str, *, indent: str = "  ", marker: str = "✗") -> None:
    """Print a red error line: ``  ✗ {text}``.

    Output goes to stdout (not stderr) because Click's ``echo``
    convention in this codebase is to mix all wizard output on the
    same channel for screen-reader and copy-paste predictability.
    Callers that genuinely need stderr should use
    :func:`click.echo` with ``err=True`` directly.
    """
    echo(f"{indent}{_style(marker, fg='red', bold=True)} {_style(text, fg='red')}")


def not_found_message(
    kind: str,
    name: str,
    available: Iterable[object],
    list_command: str,
    *,
    empty: str = "",
    empty_hint: str = "",
    limit: int = 12,
) -> str:
    """One wording for an unknown name on show/enable/... commands (GAP-1818, GAP-1928).

    ``kind 'name' not found. Available: a, b. Run `<list_command>` for details.``
    Callers add the ``Error:`` prefix (``click.ClickException`` does) and exit 1.
    ``empty_hint`` replaces the list-command hint when nothing is configured,
    since pointing at a list that is known to be empty is no help (GAP-2392).
    """
    names = sorted({str(item) for item in available if item is not None and str(item)})
    text = f"{kind} '{name}' not found."
    if names:
        shown = ", ".join(names[:limit])
        if len(names) > limit:
            shown += f" and {len(names) - limit} more"
        text += f" Available: {shown}."
    else:
        text += " " + (empty or f"No {kind}s are configured.")
        if empty_hint:
            return f"{text} {empty_hint}"
    return f"{text} Run `{list_command}` for details."


def kv(
    key: str,
    value: object,
    *,
    indent: str = "    ",
    key_width: int = 30,
) -> None:
    """Print a colored key/value row used in wizard summaries.

    The key is rendered dim+bold and right-padded so the colon
    column lines up across rows. ``key_width`` is the total
    column width (including the trailing ``":"``) — matches the
    pre-existing ``f"{key + ':':<30s} {val}"`` format that the
    guardrail summary uses, so this helper is a drop-in upgrade
    that does not shift the layout.

    The value is rendered in the default foreground so it pops
    out against the dim key. Empty / falsy values render as a
    dim em-dash so the row still occupies its column instead of
    looking truncated.
    """
    text_value = "" if value is None else str(value)
    rendered_value = dim("—") if not text_value else text_value
    label = (key + ":").ljust(key_width)
    echo(f"{indent}{_style(label, fg='bright_black', bold=True)} {rendered_value}")
