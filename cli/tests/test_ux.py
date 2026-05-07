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

"""Unit tests for the module-level color helpers in defenseclaw.ux.

The wizards in defenseclaw.commands.cmd_setup rely on these helpers
to colorize their output WITHOUT having to instantiate a CLIRenderer
per call site. Their per-call TTY/NO_COLOR gate is what makes them
safe in tests; this module locks the gate's behavior in.
"""

from __future__ import annotations

import io
import os
import unittest
from contextlib import redirect_stdout
from unittest import mock

from defenseclaw import ux


# ANSI escape sequence introducer. Used as a cheap "is this string
# colorized?" check — any helper that emits an ANSI control will
# include this byte.
_ESC = "\x1b"


class _NonTTYStdout(io.StringIO):
    """StringIO that explicitly reports as NOT a TTY.

    ``io.StringIO`` returns ``False`` from ``isatty()`` by default
    in CPython, but spelling it out documents the test contract
    (we are simulating a piped/redirected stdout) and protects
    against future Python releases that might change that default.
    """

    def isatty(self) -> bool:
        return False


class _TTYStdout(io.StringIO):
    """StringIO that lies about being a TTY.

    Used to validate the color-emitting branch without spinning up
    a pty. The helpers we test only care about the ``isatty()``
    return value, not about real terminal capabilities.
    """

    def isatty(self) -> bool:
        return True


# ---------------------------------------------------------------------------
# _color_enabled — the central gate that every helper consults
# ---------------------------------------------------------------------------


class TestColorEnabled(unittest.TestCase):
    def test_force_color_overrides_non_tty(self):
        """``FORCE_COLOR`` MUST enable colors even when stdout is
        a pipe — that is the standard ``yes I want colors in my CI
        log`` escape hatch and is widely supported by other tools."""
        with (
            mock.patch.object(ux.sys, "stdout", _NonTTYStdout()),
            mock.patch.dict(os.environ, {"FORCE_COLOR": "1"}, clear=False),
        ):
            os.environ.pop("NO_COLOR", None)
            self.assertTrue(ux._color_enabled())

    def test_clicolor_force_overrides_non_tty(self):
        """``CLICOLOR_FORCE`` is the older sibling of ``FORCE_COLOR``;
        we honor both because tooling adopts them inconsistently."""
        with (
            mock.patch.object(ux.sys, "stdout", _NonTTYStdout()),
            mock.patch.dict(os.environ, {"CLICOLOR_FORCE": "1"}, clear=False),
        ):
            os.environ.pop("NO_COLOR", None)
            os.environ.pop("FORCE_COLOR", None)
            self.assertTrue(ux._color_enabled())

    def test_no_color_disables_even_on_tty(self):
        """``NO_COLOR`` is the no-color.org spec: any presence of the
        env var (even empty string) disables colors regardless of
        TTY status. Critical for screen-reader and dumb-terminal
        users who set ``NO_COLOR=1`` once and expect every CLI to
        respect it."""
        with (
            mock.patch.object(ux.sys, "stdout", _TTYStdout()),
            mock.patch.dict(os.environ, {"NO_COLOR": ""}, clear=False),
        ):
            os.environ.pop("FORCE_COLOR", None)
            os.environ.pop("CLICOLOR_FORCE", None)
            self.assertFalse(ux._color_enabled())

    def test_force_color_beats_no_color(self):
        """Both env vars set: ``FORCE_COLOR`` wins because it's a
        more explicit "I really want colors" signal than the more
        passive ``NO_COLOR``. Tested explicitly because some CIs
        export both unintentionally."""
        with (
            mock.patch.object(ux.sys, "stdout", _NonTTYStdout()),
            mock.patch.dict(
                os.environ, {"FORCE_COLOR": "1", "NO_COLOR": "1"}, clear=False,
            ),
        ):
            self.assertTrue(ux._color_enabled())

    def test_tty_true_no_env_means_colors_on(self):
        with (
            mock.patch.object(ux.sys, "stdout", _TTYStdout()),
            mock.patch.dict(os.environ, {}, clear=False),
        ):
            os.environ.pop("FORCE_COLOR", None)
            os.environ.pop("CLICOLOR_FORCE", None)
            os.environ.pop("NO_COLOR", None)
            self.assertTrue(ux._color_enabled())

    def test_non_tty_no_env_means_colors_off(self):
        with (
            mock.patch.object(ux.sys, "stdout", _NonTTYStdout()),
            mock.patch.dict(os.environ, {}, clear=False),
        ):
            os.environ.pop("FORCE_COLOR", None)
            os.environ.pop("CLICOLOR_FORCE", None)
            os.environ.pop("NO_COLOR", None)
            self.assertFalse(ux._color_enabled())

    def test_stdout_without_isatty_treats_as_non_tty(self):
        """Defensive: a custom stdout substitute that lacks
        ``isatty`` (or raises) MUST NOT crash _color_enabled. We
        treat the unknown case as "no color" because emitting ANSI
        codes into a stream that can't render them is the worse
        failure mode."""

        class NoIsTTY:
            # Intentionally no isatty method.
            def write(self, _): pass

        with (
            mock.patch.object(ux.sys, "stdout", NoIsTTY()),
            mock.patch.dict(os.environ, {}, clear=False),
        ):
            os.environ.pop("FORCE_COLOR", None)
            os.environ.pop("CLICOLOR_FORCE", None)
            os.environ.pop("NO_COLOR", None)
            # Should not raise.
            self.assertFalse(ux._color_enabled())


# ---------------------------------------------------------------------------
# Inline string helpers (bold / dim / accent / hint)
# ---------------------------------------------------------------------------


class TestInlineHelpersStripWhenColorOff(unittest.TestCase):
    """When color is OFF, helpers are pure pass-through (no ANSI).

    This contract matters for log scraping and snapshot tests that
    pattern-match against literal substrings like
    ``Config saved to ~/.defenseclaw/config.yaml`` — adding a stray
    escape would break every existing assertion.
    """

    def setUp(self):
        # Force NO_COLOR so every helper takes the pass-through path.
        self._patcher = mock.patch.dict(os.environ, {"NO_COLOR": "1"}, clear=False)
        self._patcher.start()
        # Belt-and-suspenders: if FORCE_COLOR somehow sneaks in,
        # NO_COLOR loses by helper contract — but pop it just in
        # case the test runner's parent shell sets it.
        os.environ.pop("FORCE_COLOR", None)
        os.environ.pop("CLICOLOR_FORCE", None)

    def tearDown(self):
        self._patcher.stop()

    def test_bold_passthrough(self):
        self.assertEqual(ux.bold("hello"), "hello")
        self.assertNotIn(_ESC, ux.bold("hello"))

    def test_dim_passthrough(self):
        self.assertEqual(ux.dim("hello"), "hello")
        self.assertNotIn(_ESC, ux.dim("hello"))

    def test_accent_passthrough(self):
        self.assertEqual(ux.accent("hello"), "hello")

    def test_hint_passthrough(self):
        self.assertEqual(ux.hint("hello"), "hello")


class TestInlineHelpersAddColorWhenForced(unittest.TestCase):
    """When color is FORCED on, helpers wrap the input in ANSI."""

    def setUp(self):
        self._patcher = mock.patch.dict(
            os.environ, {"FORCE_COLOR": "1"}, clear=False,
        )
        self._patcher.start()
        os.environ.pop("NO_COLOR", None)

    def tearDown(self):
        self._patcher.stop()

    def test_bold_emits_escape(self):
        out = ux.bold("hello")
        self.assertIn(_ESC, out)
        self.assertIn("hello", out)

    def test_dim_emits_escape(self):
        out = ux.dim("hello")
        self.assertIn(_ESC, out)

    def test_accent_emits_escape(self):
        out = ux.accent("hello")
        self.assertIn(_ESC, out)

    def test_helpers_do_not_corrupt_payload(self):
        """The helpers must wrap, never truncate or duplicate, the
        caller's text. Regression: an early draft used ``%`` formatting
        which silently swallowed ``%`` characters from input."""
        src = "text-with-100% special % characters & symbols"
        for helper in (ux.bold, ux.dim, ux.accent, ux.hint):
            with self.subTest(helper=helper.__name__):
                self.assertIn(src, helper(src))


# ---------------------------------------------------------------------------
# Block helpers — section / subhead / ok / warn / err / kv
# ---------------------------------------------------------------------------


class TestBlockHelpersFormat(unittest.TestCase):
    """Block helpers print to stdout. We capture and assert on the
    rendered shape — divider length, indentation, marker glyphs."""

    def setUp(self):
        self._patcher = mock.patch.dict(os.environ, {"NO_COLOR": "1"}, clear=False)
        self._patcher.start()
        os.environ.pop("FORCE_COLOR", None)
        os.environ.pop("CLICOLOR_FORCE", None)

    def tearDown(self):
        self._patcher.stop()

    def test_section_emits_divider_matching_title_width(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            ux.section("Hook fail mode")
        out = buf.getvalue()
        # Three lines of output: leading blank line, title, divider.
        # The blank line precedes the heading so back-to-back sections
        # don't visually run together.
        lines = out.splitlines()
        self.assertEqual(len(lines), 3, f"expected 3 lines, got {lines!r}")
        self.assertEqual(lines[0], "")
        self.assertIn("Hook fail mode", lines[1])
        # The divider's character count must equal the title length
        # so the underline tracks the title width — this catches
        # regressions where someone hardcodes a fixed-width divider.
        self.assertEqual(lines[2].strip("─ "), "")
        self.assertEqual(lines[2].count("─"), len("Hook fail mode"))

    def test_section_supports_custom_divider(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            ux.section("Warnings", divider_char="=")
        self.assertIn("=" * len("Warnings"), buf.getvalue())

    def test_subhead_indents_two_spaces(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            ux.subhead("dim explanation")
        self.assertEqual(buf.getvalue(), "  dim explanation\n")

    def test_ok_prepends_check_marker(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            ux.ok("Config saved")
        self.assertIn("✓ Config saved", buf.getvalue())

    def test_warn_prepends_warning_marker(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            ux.warn("Sidecar restart failed")
        self.assertIn("⚠ Sidecar restart failed", buf.getvalue())

    def test_err_prepends_x_marker(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            ux.err("Failed to save config: permission denied")
        self.assertIn("✗ Failed to save config: permission denied", buf.getvalue())

    def test_kv_aligns_keys_to_default_width(self):
        """Default ``key_width=30`` matches the legacy
        ``f"{key + ':':<30s} {val}"`` format used in the guardrail
        summary — this test pins the layout so a future kv tweak
        doesn't shift every wizard row by one column."""
        buf = io.StringIO()
        with redirect_stdout(buf):
            ux.kv("guardrail.connector", "OpenClaw (openclaw)")
        line = buf.getvalue()
        # 4-space indent + 30-char padded key + 1 space + value.
        self.assertTrue(line.startswith("    "))
        self.assertIn("guardrail.connector:", line)
        self.assertIn("OpenClaw (openclaw)", line)
        # Verify the separator: at least one space between the key
        # column (30 chars) and the value.
        leading, _, rest = line.partition(":")
        self.assertEqual(rest.lstrip(" ").startswith("OpenClaw"), True)
        # Bonus: padding length is at least key_width minus key
        # length, so different keys still line up.
        self.assertGreaterEqual(len(leading), len("guardrail.connector"))

    def test_kv_renders_empty_value_as_dash(self):
        """An empty / None value renders as a dim em-dash so the
        column still lines up. Operators reading the summary care
        more about "what's missing" than they do about a blank gap
        — the dash makes missing fields LOUD."""
        buf = io.StringIO()
        with redirect_stdout(buf):
            ux.kv("guardrail.api_key_env", "")
            ux.kv("guardrail.model", None)
        out = buf.getvalue()
        # Two rows, both with em-dashes.
        self.assertEqual(out.count("—"), 2)
        self.assertNotIn(" None", out)
        self.assertNotIn("guardrail.api_key_env: \n", out)

    def test_kv_renders_non_string_value(self):
        """``ux.kv`` accepts ``object`` values per its annotation;
        a numeric port should stringify cleanly without coercion
        boilerplate at every call site."""
        buf = io.StringIO()
        with redirect_stdout(buf):
            ux.kv("guardrail.port", 4000)
            ux.kv("guardrail.enabled", True)
        out = buf.getvalue()
        self.assertIn("4000", out)
        self.assertIn("True", out)


if __name__ == "__main__":
    unittest.main()
