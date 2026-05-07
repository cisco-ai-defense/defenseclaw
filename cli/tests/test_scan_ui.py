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

"""Tests for the shared scan-UI helpers (S6.1).

These tests lock the shape of the contract that
``cmd_plugin scan`` / ``cmd_skill scan`` / ``cmd_mcp scan`` will
plug into in S6.2 / S6.3 / S6.4. The schema of
:func:`render_json_payload` in particular is the public CLI
contract — automation parses it — so any drift here is a breaking
change.
"""

from __future__ import annotations

import json
import unittest

from click.testing import CliRunner

from defenseclaw.commands import _scan_ui


class TestScanContextNormalization(unittest.TestCase):
    """ScanContext smooths over user-input quirks before any helper sees it."""

    def test_lowercases_connector(self):
        ctx = _scan_ui.ScanContext.for_plugin(connector="OpenClaw", paths=[])
        self.assertEqual(ctx.connector, "openclaw")

    def test_strips_whitespace(self):
        ctx = _scan_ui.ScanContext.for_plugin(connector="  Codex  ", paths=[])
        self.assertEqual(ctx.connector, "codex")

    def test_empty_connector_defaults_to_openclaw(self):
        ctx = _scan_ui.ScanContext.for_plugin(connector="", paths=[])
        self.assertEqual(ctx.connector, "openclaw")

    def test_whitespace_connector_defaults_to_openclaw(self):
        ctx = _scan_ui.ScanContext.for_plugin(connector="   ", paths=[])
        self.assertEqual(ctx.connector, "openclaw")

    def test_default_categories_per_component(self):
        for ctor, comp in (
            (_scan_ui.ScanContext.for_plugin, _scan_ui.COMPONENT_PLUGIN),
            (_scan_ui.ScanContext.for_skill, _scan_ui.COMPONENT_SKILL),
            (_scan_ui.ScanContext.for_mcp, _scan_ui.COMPONENT_MCP),
        ):
            ctx = ctor(connector="openclaw", paths=[])
            self.assertEqual(ctx.component, comp)
            self.assertGreater(len(ctx.categories), 0)
            for entry in ctx.categories:
                self.assertIsInstance(entry, str)
                self.assertGreater(len(entry), 0)


class TestRenderPreamble(unittest.TestCase):
    def _capture(self, cb):
        runner = CliRunner()
        # Use Click's runner just to capture stdout from `click.echo`.
        result = runner.invoke(_make_cli(cb))
        return result.stdout

    def test_emits_count_label_and_connector(self):
        ctx = _scan_ui.ScanContext.for_plugin(
            connector="codex",
            paths=["/home/me/.codex/extensions"],
        )
        out = self._capture(lambda: _scan_ui.render_preamble(ctx, 3))
        self.assertIn("Scanning 3 plugins on codex for:", out)

    def test_singular_when_one(self):
        ctx = _scan_ui.ScanContext.for_skill(connector="claudecode", paths=[])
        out = self._capture(lambda: _scan_ui.render_preamble(ctx, 1))
        self.assertIn("Scanning 1 skill on claudecode for:", out)

    def test_lists_each_category(self):
        ctx = _scan_ui.ScanContext.for_mcp(connector="openclaw", paths=[])
        out = self._capture(lambda: _scan_ui.render_preamble(ctx, 2))
        for cat in ctx.categories:
            self.assertIn(cat, out)

    def test_no_output_in_json_mode(self):
        ctx = _scan_ui.ScanContext.for_plugin(
            connector="codex",
            paths=["/x"],
            as_json=True,
        )
        out = self._capture(lambda: _scan_ui.render_preamble(ctx, 5))
        self.assertEqual(out, "")

    def test_single_source_label(self):
        ctx = _scan_ui.ScanContext.for_plugin(
            connector="codex",
            paths=["/home/me/.codex/extensions"],
        )
        out = self._capture(lambda: _scan_ui.render_preamble(ctx, 1))
        self.assertIn("Source: /home/me/.codex/extensions", out)

    def test_multiple_sources_label(self):
        ctx = _scan_ui.ScanContext.for_plugin(
            connector="openclaw",
            paths=["/a", "/b"],
        )
        out = self._capture(lambda: _scan_ui.render_preamble(ctx, 2))
        self.assertIn("Sources:", out)
        self.assertIn("/a", out)
        self.assertIn("/b", out)


class TestRenderPerTargetStatus(unittest.TestCase):
    def _capture(self, cb):
        runner = CliRunner()
        result = runner.invoke(_make_cli(cb))
        return result.stdout

    def test_clean_glyph(self):
        ctx = _scan_ui.ScanContext.for_plugin(connector="codex", paths=[])
        out = self._capture(
            lambda: _scan_ui.render_per_target_status(
                ctx, target="alpha", verdict=_scan_ui.VERDICT_CLEAN
            )
        )
        self.assertIn("[ok] alpha", out)

    def test_blocked_glyph_with_findings_plural(self):
        ctx = _scan_ui.ScanContext.for_plugin(connector="codex", paths=[])
        out = self._capture(
            lambda: _scan_ui.render_per_target_status(
                ctx, target="evil",
                verdict=_scan_ui.VERDICT_BLOCKED, findings=3,
            )
        )
        self.assertIn("[BLOCKED] evil (3 findings)", out)

    def test_blocked_with_one_finding_singular(self):
        ctx = _scan_ui.ScanContext.for_plugin(connector="codex", paths=[])
        out = self._capture(
            lambda: _scan_ui.render_per_target_status(
                ctx, target="x", verdict=_scan_ui.VERDICT_BLOCKED, findings=1,
            )
        )
        self.assertIn("(1 finding)", out)
        self.assertNotIn("findings", out)

    def test_detail_appended(self):
        ctx = _scan_ui.ScanContext.for_plugin(connector="codex", paths=[])
        out = self._capture(
            lambda: _scan_ui.render_per_target_status(
                ctx, target="x",
                verdict=_scan_ui.VERDICT_ERROR,
                detail="manifest unreadable",
            )
        )
        self.assertIn("manifest unreadable", out)

    def test_no_output_in_json_mode(self):
        ctx = _scan_ui.ScanContext.for_plugin(
            connector="codex", paths=[], as_json=True,
        )
        out = self._capture(
            lambda: _scan_ui.render_per_target_status(
                ctx, target="x", verdict=_scan_ui.VERDICT_CLEAN,
            )
        )
        self.assertEqual(out, "")


class TestRenderSummary(unittest.TestCase):
    def _capture(self, cb):
        runner = CliRunner()
        result = runner.invoke(_make_cli(cb))
        return result.stdout

    def test_basic_counts(self):
        ctx = _scan_ui.ScanContext.for_plugin(connector="codex", paths=[])
        out = self._capture(
            lambda: _scan_ui.render_summary(
                ctx, clean=2, blocked=1, errored=0, total=3,
            )
        )
        self.assertIn("Summary: 3 plugins scanned", out)
        self.assertIn("clean=2", out)
        self.assertIn("blocked=1", out)

    def test_errored_only_shown_when_nonzero(self):
        ctx = _scan_ui.ScanContext.for_plugin(connector="codex", paths=[])
        out = self._capture(
            lambda: _scan_ui.render_summary(
                ctx, clean=2, blocked=0, errored=0, total=2,
            )
        )
        self.assertNotIn("errored=", out)

    def test_errored_shown_when_positive(self):
        ctx = _scan_ui.ScanContext.for_plugin(connector="codex", paths=[])
        out = self._capture(
            lambda: _scan_ui.render_summary(
                ctx, clean=1, blocked=0, errored=1, total=2,
            )
        )
        self.assertIn("errored=1", out)

    def test_singular_when_one(self):
        ctx = _scan_ui.ScanContext.for_mcp(connector="openclaw", paths=[])
        out = self._capture(
            lambda: _scan_ui.render_summary(
                ctx, clean=1, blocked=0, errored=0, total=1,
            )
        )
        self.assertIn("Summary: 1 MCP server scanned", out)

    def test_no_output_in_json_mode(self):
        ctx = _scan_ui.ScanContext.for_plugin(
            connector="codex", paths=[], as_json=True,
        )
        out = self._capture(
            lambda: _scan_ui.render_summary(
                ctx, clean=1, blocked=0, errored=0, total=1,
            )
        )
        self.assertEqual(out, "")

    def test_duration_appended(self):
        ctx = _scan_ui.ScanContext.for_plugin(connector="codex", paths=[])
        out = self._capture(
            lambda: _scan_ui.render_summary(
                ctx, clean=1, blocked=0, errored=0, total=1, duration_ms=42,
            )
        )
        self.assertIn("in 42ms", out)


class TestRenderJsonPayload(unittest.TestCase):
    """The JSON shape is the public CLI contract."""

    def _build(self, **kw):
        ctx = _scan_ui.ScanContext.for_plugin(
            connector="codex",
            paths=["/x"],
            as_json=True,
        )
        return json.loads(_scan_ui.render_json_payload(ctx, **kw))

    def test_top_level_keys(self):
        payload = self._build(
            results=[],
            clean=0, blocked=0, errored=0,
        )
        self.assertEqual(payload["version"], 1)
        self.assertEqual(payload["component"], "plugin")
        self.assertEqual(payload["connector"], "codex")
        self.assertEqual(payload["paths"], ["/x"])
        self.assertIn("scanned_at", payload)
        self.assertGreater(len(payload["categories"]), 0)

    def test_summary_block(self):
        payload = self._build(
            results=[{"id": "a"}, {"id": "b"}, {"id": "c"}],
            clean=2, blocked=1, errored=0,
        )
        self.assertEqual(payload["summary"]["total"], 3)
        self.assertEqual(payload["summary"]["clean"], 2)
        self.assertEqual(payload["summary"]["blocked"], 1)
        self.assertEqual(payload["summary"]["errored"], 0)

    def test_duration_in_summary_when_passed(self):
        payload = self._build(
            results=[],
            clean=0, blocked=0, errored=0,
            duration_ms=128,
        )
        self.assertEqual(payload["summary"]["duration_ms"], 128)

    def test_duration_omitted_when_unset(self):
        payload = self._build(
            results=[],
            clean=0, blocked=0, errored=0,
        )
        self.assertNotIn("duration_ms", payload["summary"])

    def test_extras_attached_without_clobbering(self):
        payload = self._build(
            results=[],
            clean=0, blocked=0, errored=0,
            extra={"checked_for_signatures": True, "version": 999},
        )
        # ``checked_for_signatures`` is passed through, but the
        # caller-supplied ``version=999`` must NOT overwrite the
        # locked top-level ``version=1``.
        self.assertTrue(payload["checked_for_signatures"])
        self.assertEqual(payload["version"], 1)

    def test_results_are_passed_through_unchanged(self):
        rows = [{"id": "alpha", "verdict": "clean"}, {"id": "beta", "verdict": "blocked"}]
        payload = self._build(
            results=rows,
            clean=1, blocked=1, errored=0,
        )
        self.assertEqual(payload["results"], rows)


class TestSchemaIntrospection(unittest.TestCase):
    def test_supported_components(self):
        self.assertEqual(
            _scan_ui.supported_components(),
            ("plugin", "skill", "mcp"),
        )

    def test_categories_for_known_component(self):
        cats = _scan_ui.categories_for("plugin")
        self.assertGreater(len(cats), 0)

    def test_categories_for_unknown_component(self):
        self.assertEqual(_scan_ui.categories_for("widget"), ())


def _make_cli(cb):
    """Build a tiny click command that invokes *cb* — used to capture
    output from the render helpers without spinning up a full CLI app."""
    import click as _click

    @_click.command()
    def _cmd():
        cb()

    return _cmd


if __name__ == "__main__":
    unittest.main()
