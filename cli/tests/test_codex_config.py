# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Plan E2 / item 3 — Codex config parity tests.

Mirrors test_guardrail.py's OpenClaw flow but for Codex's
``~/.codex/config.toml`` + ``./.mcp.json``: TOML shape parsing,
``[hooks]`` block round-trip (S2.2 forward-compat write),
``mcpServers`` enumeration via ``./.mcp.json``, and connector_paths
dispatcher coverage.

Codex deliberately has the *narrowest* on-disk surface of the four
connectors — TOML for general settings, project-local ``.mcp.json``
for MCP. The ``[hooks]`` block is forward-compat only (plan C3 WONTFIX:
codex doesn't honor it today). Tests here document the shape so any
future refactor that drops the write must update both this file
and ``codex.go::Setup``.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw import connector_paths
from tests.connector_fixtures import make_codex_config


class _IsolatedHomeAndCwd:
    """Context manager: isolated HOME and CWD for codex tests.

    Codex's ``mcp_servers`` reader uses ``./.mcp.json`` from the
    current working directory (project-local convention), so we
    chdir into a tmp project root for the duration of the test.
    """

    def __init__(self) -> None:
        self._tmp_home: tempfile.TemporaryDirectory | None = None
        self._tmp_cwd: tempfile.TemporaryDirectory | None = None
        self._prev_home: str | None = None
        self._prev_cwd: str | None = None
        self.home: str = ""
        self.cwd: str = ""

    def __enter__(self):
        self._tmp_home = tempfile.TemporaryDirectory(prefix="dc-codex-home-")
        self._tmp_cwd = tempfile.TemporaryDirectory(prefix="dc-codex-cwd-")
        self.home = self._tmp_home.name
        self.cwd = self._tmp_cwd.name
        self._prev_home = os.environ.get("HOME")
        os.environ["HOME"] = self.home
        self._prev_cwd = os.getcwd()
        os.chdir(self.cwd)
        return self

    def __exit__(self, *exc):
        if self._prev_home is None:
            os.environ.pop("HOME", None)
        else:
            os.environ["HOME"] = self._prev_home
        if self._prev_cwd is not None:
            os.chdir(self._prev_cwd)
        if self._tmp_home is not None:
            self._tmp_home.cleanup()
        if self._tmp_cwd is not None:
            self._tmp_cwd.cleanup()


class MakeCodexConfigShapeTests(unittest.TestCase):
    def test_default_writes_model_provider(self):
        with _IsolatedHomeAndCwd() as iso:
            path = make_codex_config(iso.home)
            self.assertTrue(path.endswith(".codex/config.toml"))
            with open(path) as fh:
                body = fh.read()
            self.assertIn('model_provider = "openai"', body)

    def test_with_hooks_block(self):
        with _IsolatedHomeAndCwd() as iso:
            block = '\n[hooks]\nbefore_tool = "/usr/local/bin/dc-hook.sh"'
            path = make_codex_config(iso.home, hooks_block=block)
            with open(path) as fh:
                body = fh.read()
            self.assertIn("[hooks]", body)
            self.assertIn("before_tool", body)


class CodexMCPReaderTests(unittest.TestCase):
    """``connector_paths.mcp_servers('codex')`` reads ONLY from
    ``./.mcp.json`` — Codex doesn't have a settings-style MCP block.
    """

    def test_reads_dotmcp_json_in_cwd(self):
        with _IsolatedHomeAndCwd() as iso:
            mcp_path = os.path.join(iso.cwd, ".mcp.json")
            with open(mcp_path, "w") as fh:
                json.dump(
                    {
                        "mcpServers": {
                            "codex-stdio": {"command": "node", "args": ["mcp.js"]},
                        }
                    },
                    fh,
                )
            entries = connector_paths.mcp_servers("codex")
            self.assertEqual(len(entries), 1)
            self.assertEqual(entries[0].name, "codex-stdio")
            self.assertEqual(entries[0].command, "node")
            self.assertEqual(entries[0].args, ["mcp.js"])

    def test_no_mcp_file_returns_empty(self):
        with _IsolatedHomeAndCwd():
            self.assertEqual(connector_paths.mcp_servers("codex"), [])


class CodexSkillAndPluginDirsTests(unittest.TestCase):
    def test_skill_dirs_includes_home_and_cwd(self):
        with _IsolatedHomeAndCwd() as iso:
            dirs = connector_paths.skill_dirs("codex")
            self.assertIn(os.path.join(iso.home, ".codex", "skills"), dirs)
            cwd_skills = os.path.join(os.getcwd(), ".codex", "skills")
            self.assertIn(cwd_skills, dirs)

    def test_plugin_dirs_includes_home_and_cache(self):
        with _IsolatedHomeAndCwd() as iso:
            dirs = connector_paths.plugin_dirs("codex")
            base = os.path.join(iso.home, ".codex", "plugins")
            self.assertIn(base, dirs)
            self.assertIn(os.path.join(base, "cache"), dirs)


class CodexHooksRoundTripTests(unittest.TestCase):
    """Plan S2.2 / C3: the ``[hooks]`` block in config.toml is a
    forward-compat placeholder — codex doesn't honor it today, but
    when it grows external-script hook support, the wiring is on disk.
    Test the shape so a future refactor that drops the write must
    update both this file and codex.go::Setup.
    """

    def test_codex_config_with_hooks_section_reparses(self):
        with _IsolatedHomeAndCwd() as iso:
            block = '\n[hooks]\nbefore_tool = "/home/u/.defenseclaw/hooks/codex-hook.sh"'
            make_codex_config(iso.home, hooks_block=block)
            cfg_path = os.path.join(iso.home, ".codex", "config.toml")
            with open(cfg_path) as fh:
                body = fh.read()
            self.assertIn("[hooks]", body)
            self.assertIn("codex-hook.sh", body)


if __name__ == "__main__":
    unittest.main()
