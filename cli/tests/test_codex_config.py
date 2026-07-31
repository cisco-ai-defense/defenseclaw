# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Codex configuration and official asset-layout parity tests.

Codex reads user configuration from ``$CODEX_HOME/config.toml`` and trusted
project layers from ``.codex/config.toml``. MCP servers use
``[mcp_servers.<name>]`` tables in those TOML files; Codex does not use
Claude Code's project ``.mcp.json`` convention. Skills use project and
personal ``.agents/skills`` directories independently of ``CODEX_HOME``.
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw import connector_paths

from tests.connector_fixtures import make_codex_config
from tests.environment import isolated_home_env


class _IsolatedHomeAndCwd:
    """Context manager: isolated HOME and CWD for codex tests.

    The current working directory is isolated for tests that pass an
    explicit workspace_dir and need a project-local ``.codex/config.toml``.
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
        self._env = patch.dict(os.environ, isolated_home_env(self.home), clear=False)
        self._env.start()
        self._prev_cwd = os.getcwd()
        os.chdir(self.cwd)
        return self

    def __exit__(self, *exc):
        self._env.stop()
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
            self.assertEqual(Path(path).parts[-2:], (".codex", "config.toml"))
            with open(path) as fh:
                body = fh.read()
            self.assertIn('model_provider = "openai"', body)

class CodexMCPReaderTests(unittest.TestCase):
    """``connector_paths.mcp_servers('codex')`` defaults to
    ``$CODEX_HOME/config.toml`` and reads project ``.codex/config.toml``
    layers only for an explicit workspace.
    """

    def test_reads_project_config_toml_when_workspace_explicit(self):
        with _IsolatedHomeAndCwd() as iso:
            mcp_path = Path(iso.cwd) / ".codex" / "config.toml"
            mcp_path.parent.mkdir()
            mcp_path.write_text(
                '[mcp_servers.codex-stdio]\ncommand = "node"\nargs = ["mcp.js"]\n'
            )
            entries = connector_paths.mcp_servers("codex", workspace_dir=iso.cwd)
            self.assertEqual(len(entries), 1)
            self.assertEqual(entries[0].name, "codex-stdio")
            self.assertEqual(entries[0].command, "node")
            self.assertEqual(entries[0].args, ["mcp.js"])

    def test_no_mcp_file_returns_empty(self):
        with _IsolatedHomeAndCwd():
            self.assertEqual(connector_paths.mcp_servers("codex"), [])


class CodexSkillAndPluginDirsTests(unittest.TestCase):
    def test_skill_dirs_default_to_home(self):
        with _IsolatedHomeAndCwd() as iso:
            dirs = connector_paths.skill_dirs("codex")
            self.assertIn(os.path.join(iso.home, ".agents", "skills"), dirs)
            if os.name != "nt":
                self.assertIn("/etc/codex/skills", dirs)
            cwd_skills = os.path.join(os.getcwd(), ".agents", "skills")
            self.assertNotIn(cwd_skills, dirs)

    def test_skill_dirs_include_workspace_when_explicit(self):
        with _IsolatedHomeAndCwd() as iso:
            dirs = connector_paths.skill_dirs("codex", workspace_dir=iso.cwd)
            self.assertIn(os.path.join(iso.home, ".agents", "skills"), dirs)
            cwd_skills = os.path.join(iso.cwd, ".agents", "skills")
            self.assertIn(cwd_skills, dirs)

    def test_plugin_dirs_includes_installed_cache_only(self):
        with _IsolatedHomeAndCwd() as iso:
            dirs = connector_paths.plugin_dirs("codex")
            base = os.path.join(iso.home, ".codex", "plugins")
            self.assertNotIn(base, dirs)
            self.assertIn(os.path.join(base, "cache"), dirs)


class CodexFixtureRoundTripTests(unittest.TestCase):
    """Keep the synthetic TOML fixture's optional appendix parseable.

    Runtime hook schema and event behavior are covered by the versioned
    contract tests; this fixture test does not certify a native hook shape.
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
