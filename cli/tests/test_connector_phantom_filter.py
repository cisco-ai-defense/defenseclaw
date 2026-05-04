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

"""Connector-aware phantom-row filtering for ``skill list`` / ``mcp list``
/ ``plugin list``.

The shared audit DB ``actions`` and ``scan_results`` tables are
connector-untagged. Historically ``defenseclaw skill list`` (and the
sibling MCP / Plugin commands) merged those rows back into the listing
as ``source: "enforcement"`` or ``source: "scan-history"`` phantom
entries — which surfaced OpenClaw-owned skills inside the Codex /
Claude Code / ZeptoClaw views and confused the TUI Skills tab.

These tests pin the new contract: phantom rows are only injected when
``cfg.active_connector() == "openclaw"``.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from click.testing import CliRunner

from defenseclaw.commands.cmd_mcp import mcp as mcp_cli
from defenseclaw.commands.cmd_plugin import plugin as plugin_cli
from defenseclaw.commands.cmd_skill import skill as skill_cli
from defenseclaw.models import ActionState
from tests.helpers import cleanup_app, make_app_context


def _seed_skill_action(app, *, name: str) -> None:
    app.store.set_action(
        target_type="skill",
        target_name=name,
        source_path="",
        state=ActionState(install="block"),
        reason="seeded by test",
    )


def _seed_mcp_action(app, *, name: str) -> None:
    app.store.set_action(
        target_type="mcp",
        target_name=name,
        source_path="",
        state=ActionState(install="block"),
        reason="seeded by test",
    )


def _seed_plugin_scan(app, *, plugin_id: str) -> None:
    """Insert a faux scan_results row whose target = plugin id so the
    plugin command's scan-history phantom branch fires.
    """
    import uuid
    from datetime import datetime, timezone
    app.store.db.execute(
        """INSERT INTO scan_results
              (id, scanner, target, timestamp, duration_ms,
               finding_count, max_severity, raw_json, run_id)
           VALUES (?, ?, ?, ?, 0, 0, 'CLEAN', '{}', '')""",
        (
            str(uuid.uuid4()),
            "plugin-scanner",
            plugin_id,
            datetime.now(timezone.utc).isoformat(),
        ),
    )
    app.store.db.commit()


class _ConnectorFilterTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self.app, self.tmp_dir, self.db_path = make_app_context()
        self.runner = CliRunner()
        self._orig_columns = os.environ.get("COLUMNS")
        os.environ["COLUMNS"] = "200"
        # Force the active connector by pinning ``claw.mode`` only —
        # leaves ``guardrail.connector`` at its "openclaw" default so
        # tests don't accidentally cover the post-``setup mode``
        # transition path. ``Config.active_connector()`` consults
        # ``guardrail.connector`` first, so set both for symmetry.
        self._orig_home = os.environ.get("HOME")
        # Use a fresh temp HOME so ``~/.codex/skills`` /
        # ``~/.openclaw`` lookups don't see real user files.
        self._fake_home = tempfile.mkdtemp(prefix="dclaw-test-home-")
        os.environ["HOME"] = self._fake_home

    def tearDown(self) -> None:
        cleanup_app(self.app, self.db_path, self.tmp_dir)
        if self._orig_home is None:
            os.environ.pop("HOME", None)
        else:
            os.environ["HOME"] = self._orig_home
        if self._orig_columns is None:
            os.environ.pop("COLUMNS", None)
        else:
            os.environ["COLUMNS"] = self._orig_columns
        try:
            import shutil
            shutil.rmtree(self._fake_home)
        except OSError:
            pass

    def _set_connector(self, connector: str) -> None:
        self.app.cfg.guardrail.connector = connector
        self.app.cfg.claw.mode = connector


# ---------------------------------------------------------------------------
# Skills
# ---------------------------------------------------------------------------


class TestSkillListPhantomFiltering(_ConnectorFilterTestBase):
    def test_codex_mode_hides_openclaw_audit_phantom(self) -> None:
        """A ``skill block`` recorded against ``openclaw-only-skill`` must
        not leak into the Codex skill list — that was the user-reported
        bug ("non codex skills with enforcement actions in the skills
        tab").
        """
        self._set_connector("codex")
        _seed_skill_action(self.app, name="openclaw-only-skill")

        result = self.runner.invoke(
            skill_cli, ["list", "--json"],
            obj=self.app, catch_exceptions=False,
        )

        self.assertEqual(result.exit_code, 0, result.output)
        # Empty connector skill_dirs => no real skills + no phantoms.
        self.assertEqual(json.loads(result.output), [])

    def test_claudecode_mode_hides_openclaw_audit_phantom(self) -> None:
        self._set_connector("claudecode")
        _seed_skill_action(self.app, name="some-blocked-skill")

        result = self.runner.invoke(
            skill_cli, ["list", "--json"],
            obj=self.app, catch_exceptions=False,
        )

        self.assertEqual(result.exit_code, 0, result.output)
        names = [s["name"] for s in json.loads(result.output)]
        self.assertNotIn("some-blocked-skill", names)

    def test_zeptoclaw_mode_hides_openclaw_audit_phantom(self) -> None:
        self._set_connector("zeptoclaw")
        _seed_skill_action(self.app, name="legacy-blocked")

        result = self.runner.invoke(
            skill_cli, ["list", "--json"],
            obj=self.app, catch_exceptions=False,
        )

        self.assertEqual(result.exit_code, 0, result.output)
        names = [s["name"] for s in json.loads(result.output)]
        self.assertNotIn("legacy-blocked", names)

    def test_openclaw_mode_still_shows_audit_phantom(self) -> None:
        """Regression guard: OpenClaw mode must keep surfacing audit-DB
        phantoms so operators can still see "previously blocked but
        now removed" skills via ``skill list``.
        """
        self._set_connector("openclaw")
        _seed_skill_action(self.app, name="ghost-skill")

        result = self.runner.invoke(
            skill_cli, ["list", "--json"],
            obj=self.app, catch_exceptions=False,
        )

        self.assertEqual(result.exit_code, 0, result.output)
        names = [s["name"] for s in json.loads(result.output)]
        self.assertIn("ghost-skill", names)
        ghost = next(s for s in json.loads(result.output) if s["name"] == "ghost-skill")
        self.assertEqual(ghost.get("source"), "enforcement")

    def test_codex_mode_with_no_skills_or_actions_emits_friendly_message(self) -> None:
        self._set_connector("codex")
        result = self.runner.invoke(
            skill_cli, ["list"],
            obj=self.app, catch_exceptions=False,
        )
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("connector='codex'", result.output)
        self.assertIn("No skills found", result.output)


# ---------------------------------------------------------------------------
# MCP
# ---------------------------------------------------------------------------


class TestMcpListPhantomFiltering(_ConnectorFilterTestBase):
    def test_codex_mode_hides_orphan_action_row_in_table(self) -> None:
        """The ``mcp list`` table view used to append an
        ``[enforcement only]`` row for any actions-DB entry not present
        in the active connector's MCP config. Hiding it on non-OpenClaw
        connectors prevents OpenClaw-era MCP blocks from appearing in
        the Codex / Claude Code / ZeptoClaw view.
        """
        self._set_connector("codex")
        _seed_mcp_action(self.app, name="legacy-openclaw-mcp")

        result = self.runner.invoke(
            mcp_cli, ["list"],
            obj=self.app, catch_exceptions=False,
        )

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertNotIn("legacy-openclaw-mcp", result.output)
        self.assertNotIn("removed from config", result.output)

    def test_openclaw_mode_still_shows_orphan_action_row_in_table(self) -> None:
        from unittest.mock import patch

        from defenseclaw.config import MCPServerEntry

        self._set_connector("openclaw")
        _seed_mcp_action(self.app, name="legacy-mcp")

        # ``mcp list`` early-returns when ``servers`` is empty, so we
        # need at least one configured server to exercise the
        # orphan-row append branch. Returning a single in-memory
        # entry is the smallest fixture that lets the table be
        # built — the orphan row for ``legacy-mcp`` is then expected
        # to follow.
        live_server = MCPServerEntry(name="present-mcp", transport="stdio", command="echo")
        with patch.object(self.app.cfg, "mcp_servers", return_value=[live_server]):
            result = self.runner.invoke(
                mcp_cli, ["list"],
                obj=self.app, catch_exceptions=False,
            )

        self.assertEqual(result.exit_code, 0, result.output)
        # The orphan name only ever lands in the table via the
        # "enforcement only" branch — there is no other code path
        # that could surface it, so its presence in the rendered
        # table is sufficient to prove the regression guard. (Rich
        # wraps the "removed from config" marker text across cell
        # boundaries on narrow terminals, so we don't assert on
        # that string verbatim.)
        self.assertIn("legacy-mcp", result.output)


# ---------------------------------------------------------------------------
# Plugins
# ---------------------------------------------------------------------------


class TestPluginListPhantomFiltering(_ConnectorFilterTestBase):
    def test_codex_mode_hides_scan_history_phantom(self) -> None:
        self._set_connector("codex")
        _seed_plugin_scan(self.app, plugin_id="ghost-openclaw-plugin")

        result = self.runner.invoke(
            plugin_cli, ["list", "--json"],
            obj=self.app, catch_exceptions=False,
        )

        self.assertEqual(result.exit_code, 0, result.output)
        # Output may be a friendly "No plugins found" message rather
        # than JSON — either way, the OpenClaw scan-history id must
        # not appear.
        self.assertNotIn("ghost-openclaw-plugin", result.output)

    def test_openclaw_mode_still_shows_scan_history_phantom(self) -> None:
        self._set_connector("openclaw")
        _seed_plugin_scan(self.app, plugin_id="ghost-plugin")

        result = self.runner.invoke(
            plugin_cli, ["list", "--json"],
            obj=self.app, catch_exceptions=False,
        )

        self.assertEqual(result.exit_code, 0, result.output)
        # OpenClaw mode keeps the scan-history phantom.
        self.assertIn("ghost-plugin", result.output)
        # And tags it with the documented source.
        try:
            payload = json.loads(result.output)
        except json.JSONDecodeError:
            self.fail(
                f"OpenClaw plugin list should emit JSON when scan_map is "
                f"non-empty, got: {result.output!r}",
            )
        ids = [p["id"] for p in payload]
        self.assertIn("ghost-plugin", ids)
        ghost = next(p for p in payload if p["id"] == "ghost-plugin")
        self.assertEqual(ghost.get("source"), "scan-history")


if __name__ == "__main__":
    unittest.main()
