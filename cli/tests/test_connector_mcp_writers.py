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

"""Tests for the connector-aware MCP set/unset writers (S4.2).

Pins three contracts:

1. The dispatch matrix — OpenClaw delegates to its CLI shim,
   Claude Code patches ~/.claude/settings.json, Codex patches
   ~/.codex/config.toml by default, ZeptoClaw refuses with a clear error.
2. Atomicity + 0o600 perms on the JSON-rewriting branches.
3. Round-trip — what we set is what we read back via mcp_servers().
"""

from __future__ import annotations

import json
import os
import stat

import pytest
from defenseclaw import connector_paths
from defenseclaw.connector_paths import (
    KNOWN_CONNECTORS,
    MCPWriteUnsupportedError,
    lookup_managed_mcp_backup,
    restore_managed_mcp_backup,
    set_mcp_server,
    unset_mcp_server,
)

# ---------------------------------------------------------------------------
# OpenClaw — delegation to injected setter/unsetter
# ---------------------------------------------------------------------------

class TestOpenClawDelegation:
    def test_set_calls_setter_with_dotted_path_and_json(self):
        calls: list[tuple[str, str]] = []

        def fake_setter(path: str, value: str) -> None:
            calls.append((path, value))

        set_mcp_server(
            "openclaw", "demo",
            {"command": "uvx", "args": ["demo-mcp"]},
            openclaw_config_setter=fake_setter,
        )
        assert calls == [
            ("mcp.servers.demo",
             json.dumps({"command": "uvx", "args": ["demo-mcp"]})),
        ]

    def test_unset_calls_unsetter_with_dotted_path(self):
        calls: list[str] = []

        def fake_unsetter(path: str) -> None:
            calls.append(path)

        unset_mcp_server(
            "openclaw", "demo",
            openclaw_config_unsetter=fake_unsetter,
        )
        assert calls == ["mcp.servers.demo"]

    def test_set_without_setter_raises(self):
        with pytest.raises(RuntimeError, match="openclaw_config_setter"):
            set_mcp_server("openclaw", "demo", {"command": "x"})

    def test_unset_without_unsetter_raises(self):
        with pytest.raises(RuntimeError, match="openclaw_config_unsetter"):
            unset_mcp_server("openclaw", "demo")


# ---------------------------------------------------------------------------
# ZeptoClaw — programmatic writes are explicitly unsupported
# ---------------------------------------------------------------------------

class TestZeptoClawUnsupported:
    def test_set_raises(self):
        with pytest.raises(MCPWriteUnsupportedError, match="zeptoclaw"):
            set_mcp_server("zeptoclaw", "demo", {"command": "x"})

    def test_unset_raises(self):
        with pytest.raises(MCPWriteUnsupportedError, match="zeptoclaw"):
            unset_mcp_server("zeptoclaw", "demo")

    def test_unknown_connector_raises_unsupported(self):
        with pytest.raises(MCPWriteUnsupportedError, match="unknown connector"):
            set_mcp_server("future-frame", "demo", {"command": "x"})


# ---------------------------------------------------------------------------
# Claude Code — patches ~/.claude/settings.json
# ---------------------------------------------------------------------------

class TestClaudeCodeWrites:
    def test_set_creates_settings_when_absent(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        set_mcp_server("claudecode", "demo", {"command": "uvx"})

        settings = tmp_path / ".claude" / "settings.json"
        assert settings.is_file()
        data = json.loads(settings.read_text())
        assert data["mcpServers"]["demo"] == {"command": "uvx"}

    def test_set_preserves_unrelated_keys(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        settings = tmp_path / ".claude" / "settings.json"
        settings.parent.mkdir(parents=True)
        settings.write_text(json.dumps({
            "mcpServers": {"existing": {"command": "old"}},
            "theme": "dark",
            "permissions": {"allow": ["edit"]},
        }))

        set_mcp_server(
            "claudecode", "demo",
            {"command": "uvx", "args": ["demo-mcp"]},
        )

        data = json.loads(settings.read_text())
        assert data["theme"] == "dark"
        assert data["permissions"] == {"allow": ["edit"]}
        assert data["mcpServers"]["existing"] == {"command": "old"}
        assert data["mcpServers"]["demo"]["command"] == "uvx"

    def test_set_uses_0o600_permissions(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        set_mcp_server(
            "claudecode", "demo",
            {"command": "uvx", "env": {"API_KEY": "secret"}},
        )
        settings = tmp_path / ".claude" / "settings.json"
        mode = stat.S_IMODE(settings.stat().st_mode)
        assert mode == 0o600, (
            f"settings.json mode = {oct(mode)}, want 0o600 — file may "
            "contain API keys in env: blocks and must be owner-only"
        )

    def test_unset_removes_key(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        settings = tmp_path / ".claude" / "settings.json"
        settings.parent.mkdir(parents=True)
        settings.write_text(json.dumps({
            "mcpServers": {
                "demo": {"command": "uvx"},
                "keep": {"command": "stay"},
            },
        }))

        unset_mcp_server("claudecode", "demo")

        data = json.loads(settings.read_text())
        assert "demo" not in data["mcpServers"]
        assert data["mcpServers"]["keep"] == {"command": "stay"}

    def test_unset_missing_is_noop(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        # No file present.
        unset_mcp_server("claudecode", "demo")  # must not raise


# ---------------------------------------------------------------------------
# Codex — patches ~/.codex/config.toml by default
# ---------------------------------------------------------------------------

class TestCodexWrites:
    def test_set_creates_global_config_toml(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        set_mcp_server("codex", "demo", {"command": "uvx", "args": ["d"]})

        path = tmp_path / ".codex" / "config.toml"
        assert path.is_file()
        entries = connector_paths.mcp_servers("codex")
        assert [e.name for e in entries] == ["demo"]
        assert entries[0].command == "uvx"
        assert entries[0].args == ["d"]

    def test_set_uses_0o600(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        set_mcp_server("codex", "demo", {"command": "uvx"})
        path = tmp_path / ".codex" / "config.toml"
        mode = stat.S_IMODE(path.stat().st_mode)
        assert mode == 0o600

    def test_unset_removes_key(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        path = tmp_path / ".codex" / "config.toml"
        path.parent.mkdir()
        path.write_text(
            '[mcp_servers.demo]\ncommand = "x"\n\n'
            '[mcp_servers.keep]\ncommand = "y"\n'
        )
        unset_mcp_server("codex", "demo")
        entries = connector_paths.mcp_servers("codex")
        assert [e.name for e in entries] == ["keep"]
        assert entries[0].command == "y"

    def test_set_captures_restorable_backup(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        path = tmp_path / ".codex" / "config.toml"
        path.parent.mkdir()
        path.write_text('[mcp_servers.old]\ncommand = "old"\n')

        set_mcp_server("codex", "demo", {"command": "uvx"})
        assert (tmp_path / ".codex" / ".defenseclaw-config.toml.bak").is_file()
        assert restore_managed_mcp_backup(str(path))

        entries = connector_paths.mcp_servers("codex")
        assert [e.name for e in entries] == ["old"]
        assert entries[0].command == "old"

    def test_set_records_absolute_target_in_registry(self, tmp_path, monkeypatch):
        """C-2: workspace MCP backup must persist the absolute target path.

        Without this, ``restore_managed_mcp_backup`` could not be
        called from a different cwd (Copilot, Codex, Cursor all use
        workspace-scoped paths), and a ``cd`` between setup and
        teardown would silently lose the original config.
        """
        # DEFENSECLAW_HOME isolates the registry for this test run.
        monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path / "dchome"))
        workspace = tmp_path / "ws"
        workspace.mkdir()
        monkeypatch.chdir(workspace)
        path = workspace / ".mcp.json"
        path.write_text(json.dumps({"mcpServers": {"old": {"command": "old"}}}))

        set_mcp_server("codex", "demo", {"command": "uvx"}, workspace_dir=str(workspace))

        recorded = lookup_managed_mcp_backup(str(path))
        assert recorded is not None
        assert os.path.isabs(recorded), recorded
        # The registry directory itself must be 0o700 because it
        # leaks every config path DefenseClaw has ever touched.
        registry_dir = tmp_path / "dchome" / "connector_backups" / "mcp"
        assert registry_dir.is_dir()
        mode = stat.S_IMODE(registry_dir.stat().st_mode)
        assert mode == 0o700, f"registry dir mode {oct(mode)} != 0o700"

        # Restore from a totally different cwd — proves the fix.
        far_away = tmp_path / "elsewhere"
        far_away.mkdir()
        monkeypatch.chdir(far_away)
        assert restore_managed_mcp_backup(str(path)) is True
        data = json.loads(path.read_text())
        assert "demo" not in data["mcpServers"]
        assert data["mcpServers"]["old"]["command"] == "old"


# ---------------------------------------------------------------------------
# Antigravity — patches ~/.gemini/config/mcp_config.json by default
# ---------------------------------------------------------------------------

class TestAntigravityWrites:
    def _global(self, home) -> os.PathLike:
        return home / ".gemini" / "config" / "mcp_config.json"

    def test_set_remote_uses_server_url_and_preserves_unknowns(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        path = self._global(tmp_path)
        path.parent.mkdir(parents=True)
        path.write_text(json.dumps({
            "theme": "dark",
            "mcpServers": {
                "demo": {
                    "url": "https://old.example/mcp",
                    "x-antigravity": {"keep": True},
                },
                "keep": {"command": "stay"},
            },
        }))

        set_mcp_server(
            "antigravity",
            "demo",
            {
                "url": "https://new.example/mcp",
                "transport": "sse",
                "headers": {"Authorization": "Bearer ${AGY_MCP_TOKEN}"},
                "authProviderType": "oauth",
                "oauth": {"issuer": "https://accounts.example.com"},
                "futureField": {"enabled": True},
            },
        )

        data = json.loads(path.read_text())
        assert data["theme"] == "dark"
        assert data["mcpServers"]["keep"] == {"command": "stay"}
        demo = data["mcpServers"]["demo"]
        assert demo["serverUrl"] == "https://new.example/mcp"
        assert "url" not in demo
        assert "httpUrl" not in demo
        assert demo["transport"] == "sse"
        assert demo["headers"] == {"Authorization": "Bearer ${AGY_MCP_TOKEN}"}
        assert demo["authProviderType"] == "oauth"
        assert demo["oauth"] == {"issuer": "https://accounts.example.com"}
        assert demo["x-antigravity"] == {"keep": True}
        assert demo["futureField"] == {"enabled": True}
        entries = connector_paths.mcp_servers("antigravity")
        assert entries[0].transport == "sse"

    def test_set_local_supports_native_fields(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        set_mcp_server(
            "antigravity",
            "local",
            {
                "command": "/opt/defenseclaw/bin/defenseclaw",
                "args": ["mcp", "serve"],
                "env": {"AGY_PROFILE": "default"},
                "cwd": "/workspace/project",
                "disabled": True,
                "disabledTools": ["unsafe_tool"],
            },
        )

        data = json.loads(self._global(tmp_path).read_text())
        assert data["mcpServers"]["local"] == {
            "command": "/opt/defenseclaw/bin/defenseclaw",
            "args": ["mcp", "serve"],
            "env": {"AGY_PROFILE": "default"},
            "cwd": "/workspace/project",
            "disabled": True,
            "disabledTools": ["unsafe_tool"],
        }

    def test_workspace_writes_agents_mcp_config(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path / "home"))
        workspace = tmp_path / "ws"
        workspace.mkdir()

        set_mcp_server(
            "antigravity",
            "demo",
            {"command": "npx", "args": ["demo-mcp"]},
            workspace_dir=str(workspace),
        )

        project_config = workspace / ".agents" / "mcp_config.json"
        assert project_config.is_file()
        assert not self._global(tmp_path / "home").exists()
        entries = connector_paths.mcp_servers("antigravity", workspace_dir=str(workspace))
        assert [e.name for e in entries] == ["demo"]
        assert entries[0].command == "npx"
        assert entries[0].args == ["demo-mcp"]

    def test_set_uses_0o600(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        set_mcp_server(
            "antigravity",
            "demo",
            {"command": "x", "env": {"API_KEY": "secret"}},
        )
        mode = stat.S_IMODE(self._global(tmp_path).stat().st_mode)
        assert mode == 0o600

    def test_unset_removes_entry_preserves_others(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        path = self._global(tmp_path)
        path.parent.mkdir(parents=True)
        path.write_text(json.dumps({
            "mcpServers": {
                "demo": {"command": "x"},
                "keep": {"serverUrl": "https://keep.example/mcp"},
            },
        }))

        unset_mcp_server("antigravity", "demo")

        data = json.loads(path.read_text())
        assert "demo" not in data["mcpServers"]
        assert data["mcpServers"]["keep"] == {"serverUrl": "https://keep.example/mcp"}

    def test_round_trip_set_read_unset(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        set_mcp_server("antigravity", "demo", {"url": "https://x.example/mcp"})
        entries = connector_paths.mcp_servers("antigravity")
        assert [e.name for e in entries] == ["demo"]
        assert entries[0].url == "https://x.example/mcp"
        assert entries[0].transport == "http"

        unset_mcp_server("antigravity", "demo")
        assert connector_paths.mcp_servers("antigravity") == []


# ---------------------------------------------------------------------------
# Round-trip: set → mcp_servers() → unset → mcp_servers()
# ---------------------------------------------------------------------------

class TestRoundTrip:
    def test_codex_set_then_read_then_unset(self, tmp_path, monkeypatch):
        # Isolate HOME so the real user's ``~/.codex/config.toml``
        # (which may register global MCP servers like ``playwright``)
        # doesn't bleed into ``mcp_servers("codex")`` — the codex
        # reader merges the global TOML table with the project-local
        # ``./.mcp.json`` we're about to write, and without HOME
        # pinned to ``tmp_path`` this assertion is non-deterministic
        # across dev machines.
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.chdir(tmp_path)

        set_mcp_server(
            "codex", "demo",
            {"command": "uvx", "args": ["demo-mcp"]},
        )
        entries = connector_paths.mcp_servers("codex")
        assert [e.name for e in entries] == ["demo"]
        assert entries[0].command == "uvx"
        assert entries[0].args == ["demo-mcp"]

        unset_mcp_server("codex", "demo")
        entries = connector_paths.mcp_servers("codex")
        assert entries == []

    def test_claudecode_set_then_read_then_unset(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.chdir(tmp_path)

        set_mcp_server("claudecode", "ccd", {"command": "ccd-mcp"})
        entries = connector_paths.mcp_servers("claudecode")
        assert "ccd" in [e.name for e in entries]

        unset_mcp_server("claudecode", "ccd")
        entries = connector_paths.mcp_servers("claudecode")
        assert "ccd" not in [e.name for e in entries]


# ---------------------------------------------------------------------------
# Atomicity — partially-broken existing file gets reset to {} not crashed
# ---------------------------------------------------------------------------

class TestAtomicity:
    def test_set_recovers_from_corrupt_json(self, tmp_path, monkeypatch):
        path = tmp_path / ".mcp.json"
        path.write_text("{ this is not valid json")

        set_mcp_server("codex", "demo", {"command": "uvx"}, workspace_dir=str(tmp_path))

        data = json.loads(path.read_text())
        assert data["mcpServers"]["demo"]["command"] == "uvx"

    def test_set_does_not_leave_tempfile_on_success(
        self, tmp_path, monkeypatch,
    ):
        monkeypatch.setenv("HOME", str(tmp_path))
        set_mcp_server("codex", "demo", {"command": "uvx"})
        # No leftover .dc-mcp- temp files
        codex_dir = tmp_path / ".codex"
        leftovers = [
            p for p in os.listdir(codex_dir) if p.startswith(".dc-mcp-")
        ]
        assert leftovers == []


# ---------------------------------------------------------------------------
# All known connectors are covered (no silent fallthrough)
# ---------------------------------------------------------------------------

class TestCoverage:
    def test_every_known_connector_has_explicit_set_behavior(self, tmp_path):
        """Loop over KNOWN_CONNECTORS and assert each branch is reached.
        Catches the "added a connector but forgot to teach the
        writer" bug class.
        """
        for name in KNOWN_CONNECTORS:
            if name == "openclaw":
                # Requires injected setter — assert it raises without one.
                with pytest.raises(RuntimeError):
                    set_mcp_server(name, "x", {"command": "y"})
            elif name in {"zeptoclaw", "omnigent"}:
                with pytest.raises(MCPWriteUnsupportedError):
                    set_mcp_server(name, "x", {"command": "y"})
            elif name == "windsurf":
                with pytest.MonkeyPatch.context() as m:
                    m.setenv("HOME", str(tmp_path / "isolated-home"))
                    with pytest.raises(MCPWriteUnsupportedError):
                        set_mcp_server(name, "x", {"command": "y"})
            elif name == "antigravity":
                # Antigravity now has a documented native MCP write path:
                # ~/.gemini/config/mcp_config.json.
                with pytest.MonkeyPatch.context() as m:
                    m.setenv("HOME", str(tmp_path / "agy-home"))
                    set_mcp_server(name, "x", {"command": "y"})
                    assert (
                        tmp_path / "agy-home" / ".gemini" / "config" / "mcp_config.json"
                    ).is_file()
            elif name == "opencode":
                # opencode now has full MCP write parity (mcp.md M2/M5):
                # set writes the global ~/.config/opencode/opencode.json.
                with pytest.MonkeyPatch.context() as m:
                    m.setenv("HOME", str(tmp_path / "oc-home"))
                    set_mcp_server(name, "x", {"command": "y"})
                    assert (
                        tmp_path / "oc-home" / ".config" / "opencode" / "opencode.json"
                    ).is_file()
            else:
                # All other connectors have a documented MCP write path.
                # Use chdir + isolated HOME so the test doesn't trash
                # the developer's real config files.
                with pytest.MonkeyPatch.context() as m:
                    m.chdir(tmp_path)
                    m.setenv("HOME", str(tmp_path))
                    set_mcp_server(name, "x", {"command": "y"})


# ---------------------------------------------------------------------------
# opencode — full read+write parity (mcp.md M2/M5). Writes the global
# ~/.config/opencode/opencode.json (project file under explicit workspace),
# mapping into opencode's `mcp` schema (type/command-argv/environment).
# ---------------------------------------------------------------------------

class TestOpenCodeWrites:
    def _global(self, home) -> os.PathLike:
        return home / ".config" / "opencode" / "opencode.json"

    def test_set_creates_global_with_opencode_schema(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        set_mcp_server(
            "opencode", "demo",
            {"command": "npx", "args": ["-y", "demo-mcp"], "env": {"K": "v"}},
        )
        path = self._global(tmp_path)
        assert path.is_file()
        data = json.loads(path.read_text())
        # opencode's bespoke schema: top-level `mcp`, fused command argv,
        # `environment` (not `env`), explicit type + enabled.
        assert data["mcp"]["demo"] == {
            "type": "local",
            "command": ["npx", "-y", "demo-mcp"],
            "enabled": True,
            "environment": {"K": "v"},
        }

    def test_set_remote_server(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        set_mcp_server("opencode", "api", {"url": "https://x.example/mcp"})
        data = json.loads(self._global(tmp_path).read_text())
        assert data["mcp"]["api"] == {
            "type": "remote",
            "url": "https://x.example/mcp",
            "enabled": True,
        }

    def test_set_preserves_unrelated_keys(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        path = self._global(tmp_path)
        path.parent.mkdir(parents=True)
        path.write_text(json.dumps({
            "$schema": "https://opencode.ai/config.json",
            "theme": "tokyonight",
            "mcp": {"existing": {"type": "local", "command": ["keep"]}},
        }))
        set_mcp_server("opencode", "demo", {"command": "npx"})
        data = json.loads(path.read_text())
        assert data["$schema"] == "https://opencode.ai/config.json"
        assert data["theme"] == "tokyonight"
        assert data["mcp"]["existing"] == {"type": "local", "command": ["keep"]}
        assert data["mcp"]["demo"]["command"] == ["npx"]

    def test_set_uses_0o600(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        set_mcp_server("opencode", "demo", {"command": "x", "env": {"API_KEY": "s"}})
        mode = stat.S_IMODE(self._global(tmp_path).stat().st_mode)
        assert mode == 0o600, f"opencode.json mode {oct(mode)} != 0o600"

    def test_unset_removes_entry_preserves_others(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        path = self._global(tmp_path)
        path.parent.mkdir(parents=True)
        path.write_text(json.dumps({
            "mcp": {
                "demo": {"type": "local", "command": ["x"]},
                "keep": {"type": "local", "command": ["y"]},
            },
        }))
        unset_mcp_server("opencode", "demo")
        data = json.loads(path.read_text())
        assert "demo" not in data["mcp"]
        assert data["mcp"]["keep"] == {"type": "local", "command": ["y"]}

    def test_unset_missing_is_noop(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        unset_mcp_server("opencode", "demo")  # no file — must not raise

    def test_round_trip_set_read_unset(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        set_mcp_server("opencode", "demo", {"command": "npx", "args": ["demo-mcp"]})
        entries = connector_paths.mcp_servers("opencode")
        assert [e.name for e in entries] == ["demo"]
        assert entries[0].command == "npx"
        assert entries[0].args == ["demo-mcp"]

        unset_mcp_server("opencode", "demo")
        assert connector_paths.mcp_servers("opencode") == []

    def test_workspace_writes_project_file(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path / "home"))
        workspace = tmp_path / "ws"
        workspace.mkdir()
        set_mcp_server(
            "opencode", "demo", {"command": "npx"}, workspace_dir=str(workspace),
        )
        # Project file written; global left untouched.
        assert (workspace / "opencode.json").is_file()
        assert not self._global(tmp_path / "home").exists()
        names = {
            e.name
            for e in connector_paths.mcp_servers("opencode", workspace_dir=str(workspace))
        }
        assert names == {"demo"}

    def test_set_fails_closed_on_unparseable_existing(self, tmp_path, monkeypatch):
        """A config we can't safely parse must NOT be clobbered — the
        writer raises instead of overwriting unrelated content."""
        monkeypatch.setenv("HOME", str(tmp_path))
        path = self._global(tmp_path)
        path.parent.mkdir(parents=True)
        # Valid JSON but not an object (top-level array) → unexpected shape.
        original = json.dumps([1, 2, 3])
        path.write_text(original)
        with pytest.raises(MCPWriteUnsupportedError):
            set_mcp_server("opencode", "demo", {"command": "x"})
        # File left exactly as it was.
        assert path.read_text() == original
