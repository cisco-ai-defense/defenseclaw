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

import os
import sys
from dataclasses import dataclass

import click


@dataclass
class CLIRenderer:
    """Minimal status renderer for CLI setup flows."""

    color: bool | None = None
    quiet: bool = False

    def __post_init__(self) -> None:
        if self.color is None:
            self.color = sys.stdout.isatty() and "NO_COLOR" not in os.environ

    def echo(self, text: str = "", *, err: bool = False) -> None:
        if self.quiet:
            return
        click.echo(text, err=err)

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
#       - ``CLICOLOR_FORCE`` / ``FORCE_COLOR`` env vars override
#         non-TTY downgrade so CI pipelines that scrape logs with a
#         color-aware viewer can opt back in.
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

      1. ``CLICOLOR_FORCE`` / ``FORCE_COLOR`` truthy → True (force
         colors even when not a TTY; the standard "yes I really
         want colors in my piped log" escape hatch).
      2. ``NO_COLOR`` set (any value) → False. Per
         https://no-color.org any presence — including empty — means
         "no color".
      3. ``sys.stdout.isatty()`` → use that.
    """
    if os.environ.get("CLICOLOR_FORCE", "").strip() or os.environ.get(
        "FORCE_COLOR", ""
    ).strip():
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
    click.echo()
    click.echo(f"{indent}{_style(title, fg='cyan', bold=True)}")
    click.echo(f"{indent}{_style(divider_char * len(title), fg='cyan')}")


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
        click.echo()
    label = f" {title} "
    side = max(2, (width - len(label)) // 2)
    left = divider_char * side
    right = divider_char * (width - side - len(label))
    if _color_enabled():
        click.echo(
            f"{indent}{_style(left, fg='bright_black')}"
            f" {_style(title, fg='cyan', bold=True)} "
            f"{_style(right, fg='bright_black')}"
        )
    else:
        # Plain mode keeps the legacy "── Title ──────...──"
        # format exactly so any test or screen scraper that
        # grep-substrings on ``"── Environment ──"`` keeps
        # matching.
        click.echo(f"{indent}{left}{label}{right}")
    click.echo()


def subhead(text: str, *, indent: str = "  ") -> None:
    """Print a single dim subhead/explanatory line.

    Mirrors :meth:`CLIRenderer.section` color — bright_black so it
    visually recedes below the cyan heading without disappearing.
    """
    click.echo(f"{indent}{dim(text)}")


def ok(text: str, *, indent: str = "  ", marker: str = "✓") -> None:
    """Print a green success line: ``  ✓ {text}``."""
    click.echo(f"{indent}{_style(marker, fg='green', bold=True)} {text}")


def warn(text: str, *, indent: str = "  ", marker: str = "⚠") -> None:
    """Print a yellow warning line: ``  ⚠ {text}``.

    Use for non-fatal advisories (e.g., "Configuration not saved";
    "redaction is OFF in shared deployments"). Reserve :func:`err`
    for genuinely failed operations.
    """
    click.echo(f"{indent}{_style(marker, fg='yellow', bold=True)} {_style(text, fg='yellow')}")


def err(text: str, *, indent: str = "  ", marker: str = "✗") -> None:
    """Print a red error line: ``  ✗ {text}``.

    Output goes to stdout (not stderr) because Click's ``echo``
    convention in this codebase is to mix all wizard output on the
    same channel for screen-reader and copy-paste predictability.
    Callers that genuinely need stderr should use
    :func:`click.echo` with ``err=True`` directly.
    """
    click.echo(f"{indent}{_style(marker, fg='red', bold=True)} {_style(text, fg='red')}")


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
    click.echo(
        f"{indent}{_style(label, fg='bright_black', bold=True)} {rendered_value}"
    )
