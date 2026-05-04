# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Plan E2 / item 2 — Claude Code config parity tests.

Mirrors test_guardrail.py's OpenClaw flow but for Claude Code's
``~/.claude/settings.json``: shape parsing, ``hooks`` block round-trip,
``mcpServers`` enumeration, and connector_paths dispatcher coverage.
We do NOT shell out to a real ``claude-code`` binary; every test is
filesystem-shape-only.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw import connector_paths
from tests.connector_fixtures import make_claudecode_settings


class _IsolatedHome:
    """tmpdir HOME that connector_paths.Path.home() picks up."""

    def __init__(self) -> None:
        self._tmp: tempfile.TemporaryDirectory | None = None
        self._prev_home: str | None = None
        self.home: str = ""

    def __enter__(self) -> str:
        self._tmp = tempfile.TemporaryDirectory(prefix="dc-cc-")
        self.home = self._tmp.name
        self._prev_home = os.environ.get("HOME")
        os.environ["HOME"] = self.home
        return self.home

    def __exit__(self, *exc):
        if self._prev_home is None:
            os.environ.pop("HOME", None)
        else:
            os.environ["HOME"] = self._prev_home
        if self._tmp is not None:
            self._tmp.cleanup()


class MakeClaudeCodeSettingsShapeTests(unittest.TestCase):
    def test_default_seeds_empty_hooks_and_mcp(self):
        with _IsolatedHome() as home:
            path = make_claudecode_settings(home)
            self.assertTrue(path.endswith(".claude/settings.json"))
            with open(path) as fh:
                doc = json.load(fh)
            self.assertEqual(doc["hooks"], [])
            self.assertEqual(doc["mcpServers"], {})

    def test_custom_hooks_round_trip(self):
        with _IsolatedHome() as home:
            hooks = [
                {"event": "PreToolUse", "matcher": "Bash", "command": "/bin/inspect.sh"},
            ]
            mcps = {
                "playwright": {"command": "npx", "args": ["@playwright/mcp"]},
            }
            path = make_claudecode_settings(home, hooks=hooks, mcp_servers=mcps)
            with open(path) as fh:
                doc = json.load(fh)
            self.assertEqual(doc["hooks"], hooks)
            self.assertIn("playwright", doc["mcpServers"])
            self.assertEqual(doc["mcpServers"]["playwright"]["command"], "npx")


class ClaudeCodeMCPReaderTests(unittest.TestCase):
    """``connector_paths.mcp_servers('claudecode')`` reads
    ``~/.claude/settings.json`` ``mcpServers`` and merges in
    ``./.mcp.json`` (when present).
    """

    def test_reads_mcp_from_settings_json(self):
        with _IsolatedHome() as home:
            make_claudecode_settings(
                home,
                mcp_servers={
                    "playwright": {"command": "npx", "args": ["@playwright/mcp"]},
                    "filesystem": {"command": "uvx", "args": ["mcp-server-filesystem"]},
                },
            )
            entries = connector_paths.mcp_servers("claudecode")
            names = sorted(e.name for e in entries)
            self.assertIn("playwright", names)
            self.assertIn("filesystem", names)
            playwright = next(e for e in entries if e.name == "playwright")
            self.assertEqual(playwright.command, "npx")
            self.assertEqual(playwright.args, ["@playwright/mcp"])

    def test_missing_settings_returns_empty(self):
        with _IsolatedHome():
            self.assertEqual(connector_paths.mcp_servers("claudecode"), [])


class ClaudeCodeSkillAndPluginDirsTests(unittest.TestCase):
    def test_skill_dirs_includes_home_and_cwd(self):
        with _IsolatedHome() as home:
            dirs = connector_paths.skill_dirs("claudecode")
            self.assertIn(os.path.join(home, ".claude", "skills"), dirs)
            self.assertIn(os.path.join(os.getcwd(), ".claude", "skills"), dirs)

    def test_plugin_dirs_includes_home_and_cwd(self):
        with _IsolatedHome() as home:
            dirs = connector_paths.plugin_dirs("claudecode")
            self.assertIn(os.path.join(home, ".claude", "plugins"), dirs)
            self.assertIn(os.path.join(os.getcwd(), ".claude", "plugins"), dirs)


class ClaudeCodeHooksRoundTripTests(unittest.TestCase):
    """The ``hooks`` block in ``settings.json`` is what DefenseClaw
    edits during ``setup guardrail``. The Go-side ``patchClaudeCodeHooks``
    path keys off our hookDir-prefix sentinel; this Python test mirrors
    the same expectation: writing a synthetic patched-state and
    confirming the reverse-mapping (clear our hooks, leave foreign
    hooks alone) works on the JSON shape only.
    """

    def test_partial_restore_preserves_foreign_hooks(self):
        with _IsolatedHome() as home:
            foreign = {"event": "PreToolUse", "matcher": "Bash", "command": "/usr/local/bin/audit.sh"}
            ours = {"event": "PreToolUse", "matcher": "Bash", "command": "/home/u/.defenseclaw/hooks/claude-code-hook.sh"}
            path = make_claudecode_settings(home, hooks=[foreign, ours])

            with open(path) as fh:
                doc = json.load(fh)

            kept = [h for h in doc["hooks"] if ".defenseclaw/hooks/" not in h["command"]]
            self.assertEqual(kept, [foreign])

            doc["hooks"] = kept
            with open(path, "w") as fh:
                json.dump(doc, fh)

            with open(path) as fh:
                final = json.load(fh)
            self.assertEqual(final["hooks"], [foreign])


if __name__ == "__main__":
    unittest.main()
