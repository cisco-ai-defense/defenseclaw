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
    @pytest.mark.parametrize(
        "inp,expected",
        [
            (None, "openclaw"),
            ("", "openclaw"),
            ("   ", "openclaw"),
            ("openclaw", "openclaw"),
            ("OpenClaw", "openclaw"),
            ("  CODEX  ", "codex"),
            ("Claudecode", "claudecode"),
            ("zeptoclaw", "zeptoclaw"),
            ("future-connector", "future-connector"),
        ],
    )
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
        assert os.path.join(str(tmp_path), ".claude", "skills") not in dirs
        workspace_dirs = connector_paths.skill_dirs("claudecode", workspace_dir=str(tmp_path))
        assert os.path.join(str(tmp_path), ".claude", "skills") in workspace_dirs

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

    def test_new_connector_skill_dirs_are_connector_specific(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("HOME", str(tmp_path / "home"))
        monkeypatch.setenv("HERMES_HOME", str(tmp_path / "home" / ".hermes"))
        monkeypatch.setenv("OPENCODE_CONFIG_DIR", str(tmp_path / "opencode-custom"))
        assert connector_paths.skill_dirs("hermes") == [
            os.path.join(str(tmp_path / "home"), ".hermes", "skills"),
        ]
        assert os.path.join(str(tmp_path / "home"), ".cursor", "skills") in connector_paths.skill_dirs("cursor")
        assert os.path.join(str(tmp_path), ".cursor", "skills") in connector_paths.skill_dirs(
            "cursor",
            workspace_dir=str(tmp_path),
        )
        assert connector_paths.skill_dirs("windsurf") == []
        antigravity = connector_paths.skill_dirs("antigravity", workspace_dir=str(tmp_path))
        assert os.path.join(str(tmp_path), ".agents", "skills") in antigravity
        assert os.path.join(str(tmp_path), "_agents", "skills") in antigravity
        assert os.path.join(str(tmp_path / "home"), ".gemini", "antigravity-cli", "skills") in antigravity
        assert os.path.join(str(tmp_path / "home"), ".gemini", "skills") in antigravity
        assert os.path.join(str(tmp_path / "home"), ".agents", "skills") in antigravity
        opencode = connector_paths.skill_dirs("opencode", workspace_dir=str(tmp_path))
        assert os.path.join(str(tmp_path), ".opencode", "skills") in opencode
        assert os.path.join(str(tmp_path), ".claude", "skills") in opencode
        assert os.path.join(str(tmp_path), ".agents", "skills") in opencode
        assert os.path.join(str(tmp_path / "home"), ".config", "opencode", "skills") in opencode
        assert os.path.join(str(tmp_path / "home"), ".claude", "skills") in opencode
        assert os.path.join(str(tmp_path / "home"), ".agents", "skills") in opencode
        assert os.path.join(str(tmp_path), "opencode-custom", "skills") in opencode
        assert os.path.join(str(tmp_path / "home"), ".gemini", "skills") in connector_paths.skill_dirs("geminicli")
        assert os.path.join(str(tmp_path), ".gemini", "skills") in connector_paths.skill_dirs(
            "geminicli",
            workspace_dir=str(tmp_path),
        )
        assert os.path.join(str(tmp_path / "home"), ".copilot", "skills") in connector_paths.skill_dirs("copilot")
        assert os.path.join(str(tmp_path), ".github", "skills") in connector_paths.skill_dirs(
            "copilot",
            workspace_dir=str(tmp_path),
        )
        openhands = connector_paths.skill_dirs("openhands")
        assert os.path.join(str(tmp_path / "home"), ".agents", "skills") in openhands
        assert os.path.join(str(tmp_path / "home"), ".openhands", "skills") in openhands
        assert os.path.join(str(tmp_path / "home"), ".openhands", "microagents") in openhands
        assert os.path.join(str(tmp_path / "home"), ".openhands", "skills", "installed") in openhands
        assert (
            os.path.join(str(tmp_path / "home"), ".openhands", "cache", "skills", "public-skills", "skills")
            in openhands
        )

    def test_openhands_skill_dirs_honor_workspace_override(self, tmp_path, monkeypatch):
        outside = tmp_path / "outside"
        workspace = tmp_path / "repo"
        outside.mkdir()
        workspace.mkdir()
        monkeypatch.chdir(outside)

        openhands = connector_paths.skill_dirs("openhands", workspace_dir=str(workspace))

        assert os.path.join(str(workspace), ".agents", "skills") in openhands
        assert os.path.join(str(workspace), ".openhands", "skills") in openhands
        assert os.path.join(str(workspace), ".openhands", "microagents") in openhands
        assert all(str(outside) not in path for path in openhands)

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
        cfg_path.write_text(
            json.dumps(
                {
                    "agents": {"defaults": {"workspace": str(tmp_path / "ws")}},
                    "skills": {"load": {"extraDirs": [str(tmp_path / "extra1")]}},
                }
            )
        )
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
            "openclaw",
            openclaw_home=str(tmp_path),
        )
        assert dirs == [os.path.join(str(tmp_path), "extensions")]

    def test_new_connector_plugin_dirs(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("HOME", str(tmp_path / "home"))
        monkeypatch.setenv("HERMES_HOME", str(tmp_path / "home" / ".hermes"))
        monkeypatch.setenv("OPENCODE_CONFIG_DIR", str(tmp_path / "opencode-custom"))
        assert os.path.join(str(tmp_path / "home"), ".hermes", "plugins") in connector_paths.plugin_dirs("hermes")
        assert connector_paths.plugin_dirs("cursor") == []
        assert connector_paths.plugin_dirs("windsurf") == []
        assert os.path.join(str(tmp_path / "home"), ".gemini", "extensions") in connector_paths.plugin_dirs("geminicli")
        assert os.path.join(str(tmp_path), ".gemini", "extensions") in connector_paths.plugin_dirs(
            "geminicli",
            workspace_dir=str(tmp_path),
        )
        assert connector_paths.plugin_dirs("copilot") == []
        assert connector_paths.plugin_dirs("openhands") == []
        antigravity = connector_paths.plugin_dirs("antigravity", workspace_dir=str(tmp_path))
        assert os.path.join(str(tmp_path), ".agents", "plugins") in antigravity
        assert os.path.join(str(tmp_path), "_agents", "plugins") in antigravity
        assert os.path.join(str(tmp_path / "home"), ".gemini", "config", "plugins") in antigravity
        assert os.path.join(str(tmp_path / "home"), ".gemini", "antigravity-cli", "plugins") in antigravity
        opencode = connector_paths.plugin_dirs("opencode", workspace_dir=str(tmp_path))
        assert os.path.join(str(tmp_path), ".opencode", "plugins") in opencode
        assert os.path.join(str(tmp_path / "home"), ".config", "opencode", "plugins") in opencode
        assert os.path.join(str(tmp_path), "opencode-custom", "plugins") in opencode

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
        self._write_mcp_json(
            tmp_path,
            {
                "github": {"command": "gh", "args": ["mcp"]},
            },
        )
        entries = connector_paths.mcp_servers("codex", workspace_dir=str(tmp_path))
        assert [e.name for e in entries] == ["github"]
        assert entries[0].command == "gh"
        assert entries[0].args == ["mcp"]

    def test_codex_no_dotmcp_returns_empty(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        fake_home = tmp_path / "home"
        fake_home.mkdir()
        monkeypatch.setenv("HOME", str(fake_home))
        assert connector_paths.mcp_servers("codex") == []
        assert connector_paths.mcp_servers("codex", workspace_dir=str(tmp_path)) == []

    def test_new_connector_mcp_readers(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        fake_home = tmp_path / "home"
        fake_home.mkdir()
        monkeypatch.setenv("HOME", str(fake_home))
        monkeypatch.setenv("HERMES_HOME", str(fake_home / ".hermes"))

        hermes = fake_home / ".hermes" / "config.yaml"
        hermes.parent.mkdir(parents=True)
        hermes.write_text("mcp:\n  servers:\n    h:\n      command: hermes-mcp\n")
        assert connector_paths.mcp_servers("hermes")[0].command == "hermes-mcp"

        cursor = tmp_path / ".cursor" / "mcp.json"
        cursor.parent.mkdir(parents=True)
        cursor.write_text(json.dumps({"mcpServers": {"c": {"command": "cursor-mcp"}}}))
        assert connector_paths.mcp_servers("cursor", workspace_dir=str(tmp_path))[0].command == "cursor-mcp"

        gemini = fake_home / ".gemini" / "settings.json"
        gemini.parent.mkdir(parents=True)
        gemini.write_text(json.dumps({"mcpServers": {"g": {"command": "gemini-mcp"}}}))
        assert connector_paths.mcp_servers("geminicli")[0].command == "gemini-mcp"

        copilot = tmp_path / ".github" / "mcp.json"
        copilot.parent.mkdir(parents=True)
        copilot.write_text(json.dumps({"mcpServers": {"p": {"command": "copilot-mcp"}}}))
        assert connector_paths.mcp_servers("copilot", workspace_dir=str(tmp_path))[0].command == "copilot-mcp"

        openhands = fake_home / ".openhands" / "mcp.json"
        openhands.parent.mkdir(parents=True)
        openhands.write_text(json.dumps({"mcpServers": {"o": {"command": "openhands-mcp"}}}))
        assert connector_paths.mcp_servers("openhands")[0].command == "openhands-mcp"

    def test_antigravity_reads_global_and_workspace_mcp_config(
        self,
        tmp_path,
        monkeypatch,
    ):
        fake_home = tmp_path / "home"
        fake_home.mkdir()
        monkeypatch.setenv("HOME", str(fake_home))
        workspace = tmp_path / "project"
        workspace.mkdir()

        global_mcp = fake_home / ".gemini" / "config" / "mcp_config.json"
        global_mcp.parent.mkdir(parents=True)
        global_mcp.write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "local": {
                            "command": "/opt/defenseclaw/bin/defenseclaw",
                            "args": ["mcp", "serve"],
                            "env": {"AGY_PROFILE": "default"},
                            "cwd": "/workspace/project",
                            "disabled": True,
                            "disabledTools": ["unsafe_tool"],
                        },
                        "remote": {
                            "serverUrl": "https://mcp.example.com/mcp/",
                            "headers": {"Authorization": "Bearer ${AGY_MCP_TOKEN}"},
                            "authProviderType": "oauth",
                            "oauth": {"issuer": "https://accounts.example.com"},
                        },
                    }
                }
            )
        )
        workspace_mcp = workspace / ".agents" / "mcp_config.json"
        workspace_mcp.parent.mkdir()
        workspace_mcp.write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "workspace-remote": {"url": "https://workspace.example.com/mcp"},
                    }
                }
            )
        )

        entries = connector_paths.mcp_servers("antigravity", workspace_dir=str(workspace))
        names = [e.name for e in entries]
        assert names == ["local", "remote", "workspace-remote"]
        local = entries[0]
        assert local.command == "/opt/defenseclaw/bin/defenseclaw"
        assert local.args == ["mcp", "serve"]
        assert local.env == {"AGY_PROFILE": "default"}
        assert local.cwd == "/workspace/project"
        assert local.disabled is True
        assert local.disabled_tools == ["unsafe_tool"]
        remote = entries[1]
        assert remote.url == "https://mcp.example.com/mcp/"
        assert remote.headers == {"Authorization": "Bearer ${AGY_MCP_TOKEN}"}
        assert remote.auth_provider_type == "oauth"
        assert remote.oauth == {"issuer": "https://accounts.example.com"}
        assert entries[2].url == "https://workspace.example.com/mcp"

    def test_antigravity_ignores_workspace_mcp_without_explicit_workspace(
        self,
        tmp_path,
        monkeypatch,
    ):
        fake_home = tmp_path / "home"
        fake_home.mkdir()
        monkeypatch.setenv("HOME", str(fake_home))
        workspace = tmp_path / "project"
        workspace.mkdir()
        workspace_mcp = workspace / ".agents" / "mcp_config.json"
        workspace_mcp.parent.mkdir()
        workspace_mcp.write_text(
            json.dumps(
                {
                    "mcpServers": {"workspace": {"command": "workspace-mcp"}},
                }
            )
        )

        assert connector_paths.mcp_servers("antigravity") == []

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

        entries = connector_paths.mcp_servers("codex", workspace_dir=str(cwd))
        assert [e.name for e in entries] == ["global-fs"]
        assert entries[0].command == "node"
        assert entries[0].args == ["/opt/fs.js"]
        assert entries[0].env == {"TOKEN": "redacted"}

    def test_codex_merges_global_toml_and_local_dotmcp(
        self,
        tmp_path,
        monkeypatch,
    ):
        fake_home = tmp_path / "home"
        codex_dir = fake_home / ".codex"
        codex_dir.mkdir(parents=True)
        (codex_dir / "config.toml").write_text('[mcp_servers.global-fs]\ncommand = "node"\n')
        monkeypatch.setenv("HOME", str(fake_home))

        cwd = tmp_path / "project"
        cwd.mkdir()
        self._write_mcp_json(
            cwd,
            {
                "local-search": {"command": "search-mcp"},
            },
        )
        monkeypatch.chdir(cwd)

        entries = connector_paths.mcp_servers("codex", workspace_dir=str(cwd))
        names = sorted(e.name for e in entries)
        assert names == ["global-fs", "local-search"]

    def test_codex_malformed_config_toml_falls_back_to_dotmcp(
        self,
        tmp_path,
        monkeypatch,
    ):
        fake_home = tmp_path / "home"
        codex_dir = fake_home / ".codex"
        codex_dir.mkdir(parents=True)
        (codex_dir / "config.toml").write_text("[mcp_servers.fs\nbroken")
        monkeypatch.setenv("HOME", str(fake_home))

        cwd = tmp_path / "project"
        cwd.mkdir()
        self._write_mcp_json(
            cwd,
            {
                "local-search": {"command": "search-mcp"},
            },
        )
        monkeypatch.chdir(cwd)

        # Malformed TOML must NOT raise — we soft-fall-back to the
        # project-local file. This keeps `defenseclaw mcp list`
        # usable when an operator hand-edits config.toml and breaks
        # it; the next save will fix it without us crashing.
        entries = connector_paths.mcp_servers("codex", workspace_dir=str(cwd))
        assert [e.name for e in entries] == ["local-search"]

    def test_claudecode_merges_settings_and_dotmcp(
        self,
        tmp_path,
        monkeypatch,
    ):
        # Override $HOME so we can write a fake .claude/settings.json
        fake_home = tmp_path / "home"
        fake_home.mkdir()
        (fake_home / ".claude").mkdir()
        (fake_home / ".claude" / "settings.json").write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "from-settings": {"command": "x"},
                    },
                }
            )
        )
        monkeypatch.setenv("HOME", str(fake_home))

        cwd = tmp_path / "project"
        cwd.mkdir()
        self._write_mcp_json(
            cwd,
            {
                "from-mcp-json": {"command": "y"},
            },
        )
        monkeypatch.chdir(cwd)

        entries = connector_paths.mcp_servers("claudecode", workspace_dir=str(cwd))
        names = [e.name for e in entries]
        assert "from-settings" in names
        assert "from-mcp-json" in names

    def test_zeptoclaw_reads_config_json(self, tmp_path, monkeypatch):
        fake_home = tmp_path / "home"
        (fake_home / ".zeptoclaw").mkdir(parents=True)
        (fake_home / ".zeptoclaw" / "config.json").write_text(
            json.dumps(
                {
                    "mcp": {
                        "servers": {
                            "zepto-srv": {"command": "z", "transport": "stdio"},
                        }
                    },
                }
            )
        )
        monkeypatch.setenv("HOME", str(fake_home))
        monkeypatch.chdir(tmp_path)

        entries = connector_paths.mcp_servers("zeptoclaw")
        names = [e.name for e in entries]
        assert "zepto-srv" in names
        srv = next(e for e in entries if e.name == "zepto-srv")
        assert srv.transport == "stdio"

    def test_zeptoclaw_dedups_when_dotmcp_repeats_name(
        self,
        tmp_path,
        monkeypatch,
    ):
        fake_home = tmp_path / "home"
        (fake_home / ".zeptoclaw").mkdir(parents=True)
        (fake_home / ".zeptoclaw" / "config.json").write_text(
            json.dumps(
                {
                    "mcp": {
                        "servers": {
                            "shared": {"command": "from-config"},
                        }
                    },
                }
            )
        )
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
        self,
        tmp_path,
        monkeypatch,
    ):
        oc_path = tmp_path / "openclaw.json"
        oc_path.write_text(
            json.dumps(
                {
                    "mcp": {
                        "servers": {
                            "oc-srv": {"command": "openclaw-mcp"},
                        }
                    },
                }
            )
        )

        # Force the CLI helper to return None (=> fallback to file).
        monkeypatch.setattr(
            connector_paths,
            "_read_mcp_servers_via_openclaw_cli",
            lambda **_kw: None,
        )

        entries = connector_paths.mcp_servers(
            "openclaw",
            openclaw_config=str(oc_path),
        )
        assert [e.name for e in entries] == ["oc-srv"]


# ---------------------------------------------------------------------------
# opencode MCP reader — reads opencode.json's `mcp` map, never OpenClaw
# ---------------------------------------------------------------------------


class TestOpenCodeMCPReader:
    def _write_global(self, home: Path, servers: dict) -> Path:
        path = home / ".config" / "opencode" / "opencode.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"mcp": servers}))
        return path

    def test_reads_local_server_splits_command_argv(self, tmp_path, monkeypatch):
        home = tmp_path / "home"
        home.mkdir()
        monkeypatch.setenv("HOME", str(home))
        self._write_global(
            home,
            {
                "fs": {
                    "type": "local",
                    "command": ["npx", "-y", "fs-mcp"],
                    "environment": {"TOKEN": "secret"},
                    "enabled": True,
                },
            },
        )
        entries = connector_paths.mcp_servers("opencode")
        assert [e.name for e in entries] == ["fs"]
        assert entries[0].command == "npx"
        assert entries[0].args == ["-y", "fs-mcp"]
        assert entries[0].env == {"TOKEN": "secret"}
        assert entries[0].transport == "local"

    def test_reads_remote_server(self, tmp_path, monkeypatch):
        home = tmp_path / "home"
        home.mkdir()
        monkeypatch.setenv("HOME", str(home))
        self._write_global(
            home,
            {"api": {"type": "remote", "url": "https://example.com/mcp", "enabled": True}},
        )
        entries = connector_paths.mcp_servers("opencode")
        assert [e.name for e in entries] == ["api"]
        assert entries[0].url == "https://example.com/mcp"
        assert entries[0].transport == "remote"
        assert entries[0].command == ""

    def test_never_reads_openclaw_config(self, tmp_path, monkeypatch):
        """The Root-1 leak: opencode must read its own config, never
        ~/.openclaw/openclaw.json — even when openclaw has servers and
        opencode has none."""
        home = tmp_path / "home"
        home.mkdir()
        monkeypatch.setenv("HOME", str(home))
        # Populate OpenClaw's config with a server that must NOT leak.
        oc = home / ".openclaw"
        oc.mkdir()
        (oc / "openclaw.json").write_text(json.dumps({"mcp": {"servers": {"leaked": {"command": "do-not-show"}}}}))
        # No opencode.json present → opencode sees nothing.
        assert connector_paths.mcp_servers("opencode") == []
        # Now add an opencode server; only it shows, never "leaked".
        self._write_global(home, {"mine": {"type": "local", "command": ["mine"]}})
        names = [e.name for e in connector_paths.mcp_servers("opencode")]
        assert names == ["mine"]
        assert "leaked" not in names

    def test_project_file_layers_with_explicit_workspace(self, tmp_path, monkeypatch):
        home = tmp_path / "home"
        home.mkdir()
        monkeypatch.setenv("HOME", str(home))
        self._write_global(home, {"g": {"type": "local", "command": ["g-cmd"]}})
        workspace = tmp_path / "ws"
        workspace.mkdir()
        (workspace / "opencode.json").write_text(json.dumps({"mcp": {"p": {"type": "local", "command": ["p-cmd"]}}}))
        # Without workspace: only the global server.
        assert [e.name for e in connector_paths.mcp_servers("opencode")] == ["g"]
        # With an explicit workspace: both global and project servers.
        names = {e.name for e in connector_paths.mcp_servers("opencode", workspace_dir=str(workspace))}
        assert names == {"g", "p"}

    def test_no_config_returns_empty(self, tmp_path, monkeypatch):
        home = tmp_path / "home"
        home.mkdir()
        monkeypatch.setenv("HOME", str(home))
        assert connector_paths.mcp_servers("opencode") == []


# ---------------------------------------------------------------------------
# connector_home — opencode/antigravity resolve to their own dirs
# ---------------------------------------------------------------------------


class TestConnectorHome:
    @pytest.mark.parametrize(
        ("connector", "variable", "directory", "config_name"),
        [
            ("codex", "CODEX_HOME", "custom-codex", "config.toml"),
            ("claudecode", "CLAUDE_CONFIG_DIR", "custom-claude", "settings.json"),
        ],
    )
    def test_codex_and_claude_honor_client_home_overrides(
        self,
        connector,
        variable,
        directory,
        config_name,
        monkeypatch,
        tmp_path,
    ):
        configured = tmp_path / directory
        monkeypatch.setenv(variable, str(configured))

        assert connector_paths.connector_home(connector) == str(configured)
        assert connector_paths.connector_config_files(connector)[0] == str(configured / config_name)

    @pytest.mark.parametrize(
        ("connector", "variable", "directory"),
        [
            ("codex", "CODEX_HOME", "relative-codex"),
            ("claudecode", "CLAUDE_CONFIG_DIR", "relative-claude"),
        ],
    )
    def test_client_home_overrides_are_resolved_absolutely(self, connector, variable, directory, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv(variable, directory)

        assert connector_paths.connector_home(connector) == str(tmp_path / directory)

    def test_opencode_home_is_xdg_config(self, monkeypatch, tmp_path):
        monkeypatch.setenv("HOME", str(tmp_path))
        assert connector_paths.connector_home("opencode") == os.path.join(str(tmp_path), ".config", "opencode")

    def test_antigravity_home(self, monkeypatch, tmp_path):
        monkeypatch.setenv("HOME", str(tmp_path))
        assert connector_paths.connector_home("antigravity") == os.path.join(
            str(tmp_path), ".gemini", "antigravity-cli"
        )

    def test_opencode_home_is_not_openclaw(self, monkeypatch, tmp_path):
        monkeypatch.setenv("HOME", str(tmp_path))
        home = connector_paths.connector_home("opencode")
        assert ".openclaw" not in home


class TestHermesPathResolution:
    def test_hermes_home_override_has_highest_precedence(self, monkeypatch, tmp_path):
        configured = tmp_path / "custom-hermes"
        monkeypatch.setenv("HERMES_HOME", str(configured))
        monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "local-app-data"))

        assert connector_paths.hermes_home() == str(configured)
        assert connector_paths.hermes_config_path() == str(configured / "config.yaml")

    def test_windows_defaults_to_local_app_data(self, tmp_path):
        home = tmp_path / "home"
        local_app_data = tmp_path / "local-app-data"

        resolved = connector_paths._resolve_hermes_home(
            platform_name="nt",
            user_home=str(home),
            local_app_data=str(local_app_data),
            override="",
        )

        assert resolved == str(local_app_data / "hermes")

    def test_non_windows_preserves_dot_hermes_default(self, tmp_path):
        home = tmp_path / "home"

        resolved = connector_paths._resolve_hermes_home(
            platform_name="posix",
            user_home=str(home),
            local_app_data=str(tmp_path / "ignored"),
            override="",
        )

        assert resolved == str(home / ".hermes")

    def test_windows_without_local_app_data_falls_back_to_user_home(self, tmp_path):
        home = tmp_path / "home"

        resolved = connector_paths._resolve_hermes_home(
            platform_name="nt",
            user_home=str(home),
            local_app_data="",
            override="",
        )

        assert resolved == str(home / ".hermes")

    def test_legacy_config_path_is_read_only_migration_candidate(self, monkeypatch, tmp_path):
        home = tmp_path / "home"
        monkeypatch.setattr("defenseclaw.connector_paths.Path.home", lambda: home)

        assert connector_paths.hermes_legacy_config_path() == str(home / ".hermes" / "config.yaml")


# ---------------------------------------------------------------------------
# Round-trip via Config.skill_dirs / plugin_dirs / mcp_servers
# ---------------------------------------------------------------------------


class TestConnectorConfigFiles:
    """N2 — ``connector_config_files`` must point at the file the connector
    actually writes, not a phantom path."""

    def test_hermes_lists_yaml_not_json(self, tmp_path, monkeypatch):
        fake_home = tmp_path / "home"
        fake_home.mkdir()
        hermes_home = fake_home / "effective-hermes"
        monkeypatch.setenv("HERMES_HOME", str(hermes_home))

        files = connector_paths.connector_config_files("hermes")
        assert str(hermes_home / "config.yaml") in files
        assert not any(p.endswith(os.path.join(".hermes", "config.json")) for p in files)

    def test_hermes_workspace_path_is_yaml(self, tmp_path, monkeypatch):
        fake_home = tmp_path / "home"
        fake_home.mkdir()
        monkeypatch.setattr("defenseclaw.connector_paths.Path.home", lambda: fake_home)
        monkeypatch.setenv("HERMES_HOME", str(fake_home / ".hermes"))

        files = connector_paths.connector_config_files("hermes", workspace_dir=str(tmp_path))
        assert os.path.join(str(tmp_path), ".hermes", "config.yaml") in files
        assert not any(p.endswith("config.json") for p in files)

    def test_antigravity_lists_mcp_config_paths(self, tmp_path, monkeypatch):
        fake_home = tmp_path / "home"
        fake_home.mkdir()
        monkeypatch.setattr("defenseclaw.connector_paths.Path.home", lambda: fake_home)

        files = connector_paths.connector_config_files(
            "antigravity",
            workspace_dir=str(tmp_path),
        )
        assert os.path.join(str(fake_home), ".gemini", "config", "mcp_config.json") in files
        assert os.path.join(str(tmp_path), ".agents", "mcp_config.json") in files

    def test_omnigent_honors_config_home(self, tmp_path, monkeypatch):
        config_home = tmp_path / "isolated-omnigent"
        monkeypatch.setenv("OMNIGENT_CONFIG_HOME", str(config_home))

        assert connector_paths.omnigent_config_path() == str(config_home / "config.yaml")
        assert connector_paths.connector_home("omnigent") == str(config_home)
        assert connector_paths.connector_config_files("omnigent") == [str(config_home / "config.yaml")]

    def test_omnigent_relative_config_home_is_resolved_consistently(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("OMNIGENT_CONFIG_HOME", "relative-omnigent")
        config_home = tmp_path / "relative-omnigent"

        assert connector_paths.omnigent_config_path() == str(config_home / "config.yaml")
        assert connector_paths.connector_home("omnigent") == str(config_home)

    @pytest.mark.parametrize(
        ("connector", "variable", "directory", "file_name"),
        [
            ("codex", "CODEX_HOME", "codex-home", "config.toml"),
            ("claudecode", "CLAUDE_CONFIG_DIR", "claude-home", "settings.json"),
        ],
    )
    def test_config_reads_and_writes_use_effective_client_home(
        self,
        connector,
        variable,
        directory,
        file_name,
        tmp_path,
        monkeypatch,
    ):
        effective_home = tmp_path / directory
        monkeypatch.setenv(variable, str(effective_home))
        config_path = effective_home / file_name
        config_path.parent.mkdir(parents=True)
        if connector == "claudecode":
            config_path.write_text(
                json.dumps({"mcpServers": {"existing": {"command": "one"}}}),
                encoding="utf-8",
            )
        else:
            config_path.write_text(
                '[mcp_servers.existing]\ncommand = "one"\n',
                encoding="utf-8",
            )

        assert {entry.name for entry in connector_paths.mcp_servers(connector)} == {"existing"}
        connector_paths.set_mcp_server(connector, "added", {"command": "two"})
        assert "added" in config_path.read_text(encoding="utf-8")
        connector_paths.unset_mcp_server(connector, "added")
        assert "added" not in config_path.read_text(encoding="utf-8")


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
