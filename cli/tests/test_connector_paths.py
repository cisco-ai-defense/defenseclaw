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

"""Tests for defenseclaw.connector_paths.

Pin the connector dispatch contract end-to-end so adding a fifth
framework remains a one-file change. Each test exercises a single
public function and asserts the per-connector branch returns the
documented paths.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from defenseclaw import connector_paths
from defenseclaw.connector_paths import MCPServerEntry


# ---------------------------------------------------------------------------
# normalize / is_known
# ---------------------------------------------------------------------------

class TestNormalize:
    @pytest.mark.parametrize("inp,expected", [
        (None, "openclaw"),
        ("", "openclaw"),
        ("   ", "openclaw"),
        ("openclaw", "openclaw"),
        ("OpenClaw", "openclaw"),
        ("  CODEX  ", "codex"),
        ("Claudecode", "claudecode"),
        ("zeptoclaw", "zeptoclaw"),
        ("future-connector", "future-connector"),
    ])
    def test_normalizes(self, inp, expected):
        assert connector_paths.normalize(inp) == expected


class TestIsKnown:
    def test_known_lowercase(self):
        for name in ("openclaw", "codex", "claudecode", "zeptoclaw"):
            assert connector_paths.is_known(name)

    def test_known_mixed_case(self):
        assert connector_paths.is_known("OpenClaw")
        assert connector_paths.is_known("Codex")

    def test_unknown(self):
        assert not connector_paths.is_known("future-frame")
        assert not connector_paths.is_known("openclaaaaw")

    def test_none_falls_back_to_openclaw_and_is_known(self):
        # Per normalize() contract — None resolves to "openclaw"
        assert connector_paths.is_known(None)


# ---------------------------------------------------------------------------
# skill_dirs
# ---------------------------------------------------------------------------

class TestSkillDirs:
    def test_claudecode(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        dirs = connector_paths.skill_dirs("claudecode")
        home = str(Path.home())
        assert os.path.join(home, ".claude", "skills") in dirs
        assert os.path.join(str(tmp_path), ".claude", "skills") in dirs

    def test_codex(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        dirs = connector_paths.skill_dirs("codex")
        home = str(Path.home())
        assert os.path.join(home, ".codex", "skills") in dirs

    def test_zeptoclaw(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        dirs = connector_paths.skill_dirs("zeptoclaw")
        home = str(Path.home())
        assert os.path.join(home, ".zeptoclaw", "skills") in dirs

    def test_openclaw_default_paths(self, tmp_path):
        dirs = connector_paths.skill_dirs(
            "openclaw",
            openclaw_home=str(tmp_path),
            openclaw_config=str(tmp_path / "openclaw.json"),
        )
        # workspace/skills is the documented OpenClaw default even
        # when openclaw.json is missing.
        assert os.path.join(str(tmp_path), "workspace", "skills") in dirs
        assert os.path.join(str(tmp_path), "skills") in dirs

    def test_openclaw_honors_extra_dirs(self, tmp_path):
        cfg_path = tmp_path / "openclaw.json"
        cfg_path.write_text(json.dumps({
            "agents": {"defaults": {"workspace": str(tmp_path / "ws")}},
            "skills": {"load": {"extraDirs": [str(tmp_path / "extra1")]}},
        }))
        dirs = connector_paths.skill_dirs(
            "openclaw",
            openclaw_home=str(tmp_path),
            openclaw_config=str(cfg_path),
        )
        assert os.path.join(str(tmp_path / "ws"), "skills") in dirs
        assert str(tmp_path / "extra1") in dirs
        assert os.path.join(str(tmp_path), "skills") in dirs

    def test_unknown_connector_falls_back_to_openclaw(self, tmp_path):
        dirs = connector_paths.skill_dirs(
            "totally-unknown",
            openclaw_home=str(tmp_path),
            openclaw_config=str(tmp_path / "openclaw.json"),
        )
        # Must not be empty and must include the OpenClaw home_dir/skills
        # so "guardrail.connector got typo'd" doesn't silently swallow
        # all skill discovery.
        assert os.path.join(str(tmp_path), "skills") in dirs


# ---------------------------------------------------------------------------
# plugin_dirs
# ---------------------------------------------------------------------------

class TestPluginDirs:
    def test_claudecode(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        dirs = connector_paths.plugin_dirs("claudecode")
        home = str(Path.home())
        assert os.path.join(home, ".claude", "plugins") in dirs

    def test_codex(self):
        dirs = connector_paths.plugin_dirs("codex")
        home = str(Path.home())
        # Codex plugins live at ~/.codex/plugins (with cache subdir)
        assert os.path.join(home, ".codex", "plugins") in dirs

    def test_zeptoclaw(self):
        dirs = connector_paths.plugin_dirs("zeptoclaw")
        home = str(Path.home())
        assert os.path.join(home, ".zeptoclaw", "plugins") in dirs

    def test_openclaw(self, tmp_path):
        dirs = connector_paths.plugin_dirs(
            "openclaw", openclaw_home=str(tmp_path),
        )
        assert dirs == [os.path.join(str(tmp_path), "extensions")]

    def test_no_overlap_between_connectors(self, tmp_path, monkeypatch):
        """Switching connectors must change the path set — pins the
        contract that each framework owns its own filesystem footprint."""
        monkeypatch.chdir(tmp_path)
        codex = set(connector_paths.plugin_dirs("codex"))
        claudecode = set(connector_paths.plugin_dirs("claudecode"))
        zepto = set(connector_paths.plugin_dirs("zeptoclaw"))
        assert codex.isdisjoint(claudecode)
        assert codex.isdisjoint(zepto)
        assert claudecode.isdisjoint(zepto)


# ---------------------------------------------------------------------------
# mcp_servers
# ---------------------------------------------------------------------------

class TestMCPServers:
    def _write_mcp_json(self, dirpath: Path, servers: dict) -> Path:
        path = dirpath / ".mcp.json"
        path.write_text(json.dumps({"mcpServers": servers}))
        return path

    def test_codex_reads_dotmcp(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        # Isolate $HOME so the test doesn't accidentally pick up a
        # real ~/.codex/config.toml on the developer's machine.
        fake_home = tmp_path / "home"
        fake_home.mkdir()
        monkeypatch.setenv("HOME", str(fake_home))
        self._write_mcp_json(tmp_path, {
            "github": {"command": "gh", "args": ["mcp"]},
        })
        entries = connector_paths.mcp_servers("codex")
        assert [e.name for e in entries] == ["github"]
        assert entries[0].command == "gh"
        assert entries[0].args == ["mcp"]

    def test_codex_no_dotmcp_returns_empty(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        fake_home = tmp_path / "home"
        fake_home.mkdir()
        monkeypatch.setenv("HOME", str(fake_home))
        assert connector_paths.mcp_servers("codex") == []

    def test_codex_reads_global_config_toml(self, tmp_path, monkeypatch):
        """Bug fix regression: pre-S5.x ``defenseclaw mcp list`` only
        consulted ``./.mcp.json`` for Codex, dropping every server
        registered globally in ``~/.codex/config.toml``. We now read
        both."""
        fake_home = tmp_path / "home"
        codex_dir = fake_home / ".codex"
        codex_dir.mkdir(parents=True)
        (codex_dir / "config.toml").write_text(
            "[mcp_servers.global-fs]\n"
            'command = "node"\n'
            'args = ["/opt/fs.js"]\n'
            "\n"
            "[mcp_servers.global-fs.env]\n"
            'TOKEN = "redacted"\n'
        )
        monkeypatch.setenv("HOME", str(fake_home))
        cwd = tmp_path / "project"
        cwd.mkdir()
        monkeypatch.chdir(cwd)

        entries = connector_paths.mcp_servers("codex")
        assert [e.name for e in entries] == ["global-fs"]
        assert entries[0].command == "node"
        assert entries[0].args == ["/opt/fs.js"]
        assert entries[0].env == {"TOKEN": "redacted"}

    def test_codex_merges_global_toml_and_local_dotmcp(
        self, tmp_path, monkeypatch,
    ):
        fake_home = tmp_path / "home"
        codex_dir = fake_home / ".codex"
        codex_dir.mkdir(parents=True)
        (codex_dir / "config.toml").write_text(
            "[mcp_servers.global-fs]\n"
            'command = "node"\n'
        )
        monkeypatch.setenv("HOME", str(fake_home))

        cwd = tmp_path / "project"
        cwd.mkdir()
        self._write_mcp_json(cwd, {
            "local-search": {"command": "search-mcp"},
        })
        monkeypatch.chdir(cwd)

        entries = connector_paths.mcp_servers("codex")
        names = sorted(e.name for e in entries)
        assert names == ["global-fs", "local-search"]

    def test_codex_malformed_config_toml_falls_back_to_dotmcp(
        self, tmp_path, monkeypatch,
    ):
        fake_home = tmp_path / "home"
        codex_dir = fake_home / ".codex"
        codex_dir.mkdir(parents=True)
        (codex_dir / "config.toml").write_text("[mcp_servers.fs\nbroken")
        monkeypatch.setenv("HOME", str(fake_home))

        cwd = tmp_path / "project"
        cwd.mkdir()
        self._write_mcp_json(cwd, {
            "local-search": {"command": "search-mcp"},
        })
        monkeypatch.chdir(cwd)

        # Malformed TOML must NOT raise — we soft-fall-back to the
        # project-local file. This keeps `defenseclaw mcp list`
        # usable when an operator hand-edits config.toml and breaks
        # it; the next save will fix it without us crashing.
        entries = connector_paths.mcp_servers("codex")
        assert [e.name for e in entries] == ["local-search"]

    def test_claudecode_merges_settings_and_dotmcp(
        self, tmp_path, monkeypatch,
    ):
        # Override $HOME so we can write a fake .claude/settings.json
        fake_home = tmp_path / "home"
        fake_home.mkdir()
        (fake_home / ".claude").mkdir()
        (fake_home / ".claude" / "settings.json").write_text(json.dumps({
            "mcpServers": {
                "from-settings": {"command": "x"},
            },
        }))
        monkeypatch.setenv("HOME", str(fake_home))

        cwd = tmp_path / "project"
        cwd.mkdir()
        self._write_mcp_json(cwd, {
            "from-mcp-json": {"command": "y"},
        })
        monkeypatch.chdir(cwd)

        entries = connector_paths.mcp_servers("claudecode")
        names = [e.name for e in entries]
        assert "from-settings" in names
        assert "from-mcp-json" in names

    def test_zeptoclaw_reads_config_json(self, tmp_path, monkeypatch):
        fake_home = tmp_path / "home"
        (fake_home / ".zeptoclaw").mkdir(parents=True)
        (fake_home / ".zeptoclaw" / "config.json").write_text(json.dumps({
            "mcp": {"servers": {
                "zepto-srv": {"command": "z", "transport": "stdio"},
            }},
        }))
        monkeypatch.setenv("HOME", str(fake_home))
        monkeypatch.chdir(tmp_path)

        entries = connector_paths.mcp_servers("zeptoclaw")
        names = [e.name for e in entries]
        assert "zepto-srv" in names
        srv = next(e for e in entries if e.name == "zepto-srv")
        assert srv.transport == "stdio"

    def test_zeptoclaw_dedups_when_dotmcp_repeats_name(
        self, tmp_path, monkeypatch,
    ):
        fake_home = tmp_path / "home"
        (fake_home / ".zeptoclaw").mkdir(parents=True)
        (fake_home / ".zeptoclaw" / "config.json").write_text(json.dumps({
            "mcp": {"servers": {
                "shared": {"command": "from-config"},
            }},
        }))
        monkeypatch.setenv("HOME", str(fake_home))
        cwd = tmp_path / "p"
        cwd.mkdir()
        self._write_mcp_json(cwd, {"shared": {"command": "from-mcp"}})
        monkeypatch.chdir(cwd)

        entries = connector_paths.mcp_servers("zeptoclaw")
        # First-write-wins → config.json beats .mcp.json on dedup.
        assert len(entries) == 1
        assert entries[0].command == "from-config"

    def test_openclaw_reads_openclaw_json_when_cli_unavailable(
        self, tmp_path, monkeypatch,
    ):
        oc_path = tmp_path / "openclaw.json"
        oc_path.write_text(json.dumps({
            "mcp": {"servers": {
                "oc-srv": {"command": "openclaw-mcp"},
            }},
        }))

        # Force the CLI helper to return None (=> fallback to file).
        monkeypatch.setattr(
            connector_paths,
            "_read_mcp_servers_via_openclaw_cli",
            lambda **_kw: None,
        )

        entries = connector_paths.mcp_servers(
            "openclaw", openclaw_config=str(oc_path),
        )
        assert [e.name for e in entries] == ["oc-srv"]


# ---------------------------------------------------------------------------
# Round-trip via Config.skill_dirs / plugin_dirs / mcp_servers
# ---------------------------------------------------------------------------

class TestConfigDispatch:
    def test_config_skill_dirs_uses_active_connector(self):
        from defenseclaw import config

        cfg = config.default_config()
        cfg.guardrail.connector = "codex"
        dirs = cfg.skill_dirs()
        home = str(Path.home())
        assert os.path.join(home, ".codex", "skills") in dirs

    def test_config_plugin_dirs_uses_active_connector(self):
        from defenseclaw import config

        cfg = config.default_config()
        cfg.guardrail.connector = "claudecode"
        dirs = cfg.plugin_dirs()
        home = str(Path.home())
        assert os.path.join(home, ".claude", "plugins") in dirs

    def test_config_active_connector_precedence(self):
        from defenseclaw import config

        cfg = config.default_config()
        cfg.guardrail.connector = "  codex  "
        cfg.claw.mode = "openclaw"
        assert cfg.active_connector() == "codex"

        cfg.guardrail.connector = ""
        cfg.claw.mode = "ZeptoClaw"
        assert cfg.active_connector() == "zeptoclaw"

        cfg.guardrail.connector = ""
        cfg.claw.mode = ""
        assert cfg.active_connector() == "openclaw"


# ---------------------------------------------------------------------------
# Re-export contract — MCPServerEntry must remain importable from
# defenseclaw.config so downstream callers (cmd_mcp, tests) don't break.
# ---------------------------------------------------------------------------

class TestMCPServerEntryReExport:
    def test_importable_from_config(self):
        from defenseclaw.config import MCPServerEntry as MCPFromConfig
        assert MCPFromConfig is MCPServerEntry
