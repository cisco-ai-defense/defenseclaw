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
   ./.mcp.json, ZeptoClaw refuses with a clear error.
2. Atomicity + 0o600 perms on the JSON-rewriting branches.
3. Round-trip — what we set is what we read back via mcp_servers().
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from defenseclaw import connector_paths
from defenseclaw.connector_paths import (
    KNOWN_CONNECTORS,
    MCPWriteUnsupportedError,
    set_mcp_server,
    restore_managed_mcp_backup,
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
# Codex — patches ./.mcp.json
# ---------------------------------------------------------------------------

class TestCodexWrites:
    def test_set_creates_mcp_json(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        set_mcp_server("codex", "demo", {"command": "uvx", "args": ["d"]})

        path = tmp_path / ".mcp.json"
        assert path.is_file()
        data = json.loads(path.read_text())
        assert data["mcpServers"]["demo"]["command"] == "uvx"

    def test_set_uses_0o600(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        set_mcp_server("codex", "demo", {"command": "uvx"})
        path = tmp_path / ".mcp.json"
        mode = stat.S_IMODE(path.stat().st_mode)
        assert mode == 0o600

    def test_unset_removes_key(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        path = tmp_path / ".mcp.json"
        path.write_text(json.dumps({"mcpServers": {
            "demo": {"command": "x"},
            "keep": {"command": "y"},
        }}))
        unset_mcp_server("codex", "demo")
        data = json.loads(path.read_text())
        assert "demo" not in data["mcpServers"]
        assert "keep" in data["mcpServers"]

    def test_set_captures_restorable_backup(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        path = tmp_path / ".mcp.json"
        path.write_text(json.dumps({"mcpServers": {"old": {"command": "old"}}}))

        set_mcp_server("codex", "demo", {"command": "uvx"})
        assert (tmp_path / ".defenseclaw-mcp.json.bak").is_file()
        assert restore_managed_mcp_backup(str(path))

        data = json.loads(path.read_text())
        assert "demo" not in data["mcpServers"]
        assert data["mcpServers"]["old"]["command"] == "old"


# ---------------------------------------------------------------------------
# Round-trip: set → mcp_servers() → unset → mcp_servers()
# ---------------------------------------------------------------------------

class TestRoundTrip:
    def test_codex_set_then_read_then_unset(self, tmp_path, monkeypatch):
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
        monkeypatch.chdir(tmp_path)
        path = tmp_path / ".mcp.json"
        path.write_text("{ this is not valid json")

        set_mcp_server("codex", "demo", {"command": "uvx"})

        data = json.loads(path.read_text())
        assert data["mcpServers"]["demo"]["command"] == "uvx"

    def test_set_does_not_leave_tempfile_on_success(
        self, tmp_path, monkeypatch,
    ):
        monkeypatch.chdir(tmp_path)
        set_mcp_server("codex", "demo", {"command": "uvx"})
        # No leftover .dc-mcp- temp files
        leftovers = [
            p for p in os.listdir(tmp_path) if p.startswith(".dc-mcp-")
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
            elif name == "zeptoclaw":
                with pytest.raises(MCPWriteUnsupportedError):
                    set_mcp_server(name, "x", {"command": "y"})
            elif name == "windsurf":
                with pytest.MonkeyPatch.context() as m:
                    m.setenv("HOME", str(tmp_path / "isolated-home"))
                    with pytest.raises(MCPWriteUnsupportedError):
                        set_mcp_server(name, "x", {"command": "y"})
            else:
                # All other connectors have a documented MCP write path.
                # Use chdir + isolated HOME so the test doesn't trash
                # the developer's real config files.
                with pytest.MonkeyPatch.context() as m:
                    m.chdir(tmp_path)
                    m.setenv("HOME", str(tmp_path))
                    set_mcp_server(name, "x", {"command": "y"})
