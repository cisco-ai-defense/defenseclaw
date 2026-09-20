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

"""Shared key-driven checkbox prompts for terminal setup flows."""

from __future__ import annotations

import os
from collections.abc import Callable, Iterator
from contextlib import contextmanager

import click

from defenseclaw import ux


def stdout_is_tty() -> bool:
    """Return whether Click's stdout stream is attached to a terminal."""

    try:
        return click.get_text_stream("stdout").isatty()
    except Exception:
        return False


def _has_ansi_terminal_hint() -> bool:
    """Recognize Windows pseudoterminals whose wrapped stdout is not a TTY."""

    if os.name != "nt":
        return False
    if os.environ.get("WT_SESSION") or os.environ.get("ANSICON"):
        return True
    if os.environ.get("ConEmuANSI", "").upper() == "ON":
        return True
    if os.environ.get("TERM_PROGRAM"):
        return True
    term = os.environ.get("TERM", "").strip().lower()
    return bool(term and term != "dumb")


def supports_terminal_redraw() -> bool:
    """Return whether the terminal can redraw the checkbox list in place.

    Click installs Colorama on Windows. Colorama translates the cursor-up and
    erase-line controls used below into native console calls when VT processing
    is unavailable, so a Windows TTY does not need a successful VT-mode probe
    to retain the same moving-cursor picker used on macOS and Linux.
    """

    if stdout_is_tty():
        return True
    return _has_ansi_terminal_hint()


def checkbox_key_name(ch: str) -> str:
    """Normalize Windows, ANSI, and vi-style checkbox navigation keys."""

    if ch in ("\r", "\n"):
        return "enter"
    if ch in (" ", "\t"):
        return "toggle"
    if ch in ("\x1b[A", "\x00H", "\xe0H", "k", "K"):
        return "up"
    if ch in ("\x1b[B", "\x00P", "\xe0P", "j", "J"):
        return "down"
    if ch == "a":
        return "all"
    if ch == "n":
        return "none"
    return ""


def render_checkbox_menu(
    options: list[str],
    selected: set[str],
    cursor: int,
    *,
    redraw: bool,
) -> None:
    """Render the full checkbox list, optionally replacing prior ANSI rows."""

    if redraw:
        # CSI A (cursor up) is understood both by VT terminals and Colorama's
        # native Windows-console adapter. CSI F was not translated by Colorama,
        # which caused the menu to fall back or stack in legacy Windows hosts.
        click.echo(f"\x1b[{len(options)}A\r", nl=False, color=True)
    for idx, name in enumerate(options):
        if redraw:
            click.echo("\r\x1b[2K", nl=False, color=True)
        pointer = ">" if idx == cursor else " "
        mark = "x" if name in selected else " "
        click.echo(f"  {pointer} [{mark}] {name}")


def _render_static_menu(options: list[str], selected: set[str]) -> None:
    """Print a non-ANSI menu exactly once."""

    for name in options:
        mark = "x" if name in selected else " "
        click.echo(f"    [{mark}] {name}")


def _render_non_redraw_status(
    options: list[str],
    selected: set[str],
    cursor: int,
    previous_width: int,
) -> int:
    """Update one carriage-return status line without ANSI cursor controls."""

    name = options[cursor]
    mark = "x" if name in selected else " "
    status = (
        f"  Current {cursor + 1}/{len(options)}: [{mark}] {name}"
        f" | selected {len(selected)}"
    )
    click.echo("\r" + status.ljust(previous_width), nl=False)
    return len(status)


def _line_prompt_termios(termios_mod: object, attributes: list[object]) -> list[object] | None:
    """Return a copy of *attributes* with cooked line-editing flags enabled.

    Snapshot restore alone is not enough: if a prior ``getchar`` leak already
    disabled echo before the picker started, replaying that snapshot leaves
    the next ``click.prompt`` swallowing keystrokes. Force the flags the
    following line prompt needs regardless of how raw the snapshot was.
    """

    if not isinstance(attributes, list) or len(attributes) < 4:
        return None
    iflag, lflag = attributes[0], attributes[3]
    if not isinstance(iflag, int) or not isinstance(lflag, int):
        return None
    restored = list(attributes)
    restored[0] = iflag | int(getattr(termios_mod, "ICRNL"))
    restored[3] = lflag | int(
        getattr(termios_mod, "ECHO")
        | getattr(termios_mod, "ICANON")
        | getattr(termios_mod, "ISIG")
        | getattr(termios_mod, "IEXTEN")
    )
    return restored


def restore_line_prompt_mode() -> None:
    """Force cooked echo on the current stdin TTY.

    Safe in a fresh process that inherited raw mode from an earlier
    checkbox picker in the same terminal (``make all`` runs ``init``
    then ``setup llm`` on one TTY). No-op on Windows, non-TTYs, and
    when termios is unavailable.
    """

    if os.name == "nt":
        return
    try:
        import termios

        stdin = click.get_text_stream("stdin")
        fd = stdin.fileno()
        if not os.isatty(fd):
            return
        attributes = termios.tcgetattr(fd)
        cooked = _line_prompt_termios(termios, attributes)
        if cooked is None:
            return
        termios.tcsetattr(fd, termios.TCSANOW, cooked)
    except (AttributeError, ImportError, OSError, ValueError):
        return


@contextmanager
def _preserve_terminal_input_mode() -> Iterator[None]:
    """Restore the POSIX TTY mode after Click's raw key reader exits.

    ``click.getchar`` temporarily switches the terminal to raw mode for every
    checkbox keystroke. Some pseudoterminals can fail to restore one of the
    input flags on that raw-to-cooked transition, most visibly ``ICRNL`` and
    ``ECHO``. The next line-oriented prompt then either echoes Enter as
    ``^M`` or accepts keystrokes without showing them. Snapshotting the mode
    around the complete picker gives us a second restore at the boundary
    back to ordinary Click prompts, and cooked echo/ICANON/ICRNL are forced
    on even when that snapshot was already raw.

    Windows does not expose ``termios`` and already uses Click's console input
    implementation, so the guard intentionally becomes a no-op there.
    """

    snapshot: tuple[object, int, list[object]] | None = None
    if os.name != "nt":
        try:
            import termios

            stdin = click.get_text_stream("stdin")
            fd = stdin.fileno()
            if os.isatty(fd):
                snapshot = (termios, fd, termios.tcgetattr(fd))
        except (AttributeError, ImportError, OSError, ValueError):
            # The picker still works with Click's own fallback when stdin is
            # wrapped or /dev/tty is unavailable; there is simply no mode we
            # can preserve independently in that case.
            snapshot = None

    try:
        yield
    finally:
        if snapshot is not None:
            termios, fd, attributes = snapshot
            try:
                termios.tcsetattr(fd, termios.TCSANOW, attributes)
            except (AttributeError, OSError, ValueError):
                # Do not mask the user's selection (or a Ctrl-C) merely
                # because a terminal disappeared while the prompt was open.
                pass
        restore_line_prompt_mode()


def prompt_checkbox_selection(
    options: list[str],
    *,
    default_selected: list[str],
    title: str,
    empty_ok: bool,
    redraw: bool | None = None,
    getchar: Callable[[], str] | None = None,
) -> list[str]:
    """Select options with keys in both VT and non-VT interactive terminals.

    VT-capable terminals redraw the full menu in place. Other interactive
    terminals print the menu once and update only a carriage-return status
    line. Both modes keep the same Up/Down, j/k, Space, and Enter interaction;
    lack of ANSI support never changes the selector into a line prompt.
    """

    if not options:
        return []

    selected = {name for name in default_selected if name in options}
    cursor = 0
    ux.subhead(title)
    ux.subhead(
        "  Up/Down or j/k moves, Space toggles, a selects all, "
        "n clears, Enter continues."
    )

    if redraw is None:
        redraw = supports_terminal_redraw()
    read_key = getchar or click.getchar

    rendered = False
    status_width = 0
    if not redraw:
        _render_static_menu(options, selected)
        status_width = _render_non_redraw_status(
            options,
            selected,
            cursor,
            status_width,
        )

    with _preserve_terminal_input_mode():
        while True:
            if redraw:
                render_checkbox_menu(options, selected, cursor, redraw=rendered)
                rendered = True

            key = checkbox_key_name(read_key())
            if key == "enter":
                if selected or empty_ok:
                    if not redraw:
                        click.echo()
                    return [name for name in options if name in selected]
                if not redraw:
                    click.echo()
                ux.warn("Select at least one connector.", indent="  ")
            elif key == "toggle":
                name = options[cursor]
                if name in selected:
                    selected.remove(name)
                else:
                    selected.add(name)
            elif key == "up":
                cursor = (cursor - 1) % len(options)
            elif key == "down":
                cursor = (cursor + 1) % len(options)
            elif key == "all":
                selected = set(options)
            elif key == "none":
                selected.clear()

            if not redraw:
                status_width = _render_non_redraw_status(
                    options,
                    selected,
                    cursor,
                    status_width,
                )
