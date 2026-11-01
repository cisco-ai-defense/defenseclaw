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

"""MCP set/unset config writers and shared skill-dir quarantine scope.

GAP-1837 (Claude ``type``), GAP-1812 (unset restores the original bytes),
GAP-1846 (unset wording), GAP-1838 (disk full), GAP-1259 (shared skill dir).
"""

from __future__ import annotations

import errno
import json
import os
import unittest
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner
from defenseclaw import connector_paths, main
from defenseclaw.commands.cmd_mcp import mcp
from defenseclaw.commands.cmd_skill import skill
from defenseclaw.config import MCPServerEntry
from defenseclaw.connector_paths import set_mcp_server, unset_mcp_server
from defenseclaw.enforce.policy import PolicyEngine

from tests.helpers import cleanup_app, make_app_context


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path / "dc-home"))
    monkeypatch.delenv("CLAUDE_CONFIG_DIR", raising=False)
    monkeypatch.delenv("OPENCODE_CONFIG", raising=False)
    monkeypatch.delenv("OPENCODE_CONFIG_CONTENT", raising=False)
    return tmp_path


def test_claude_url_entry_gets_a_type_claude_code_loads(home):
    # GAP-1837: Claude Code skips {"url": ...} without "type".
    set_mcp_server("claudecode", "deepwiki", {"url": "https://mcp.example.invalid/mcp"})
    set_mcp_server("claudecode", "events", {"url": "https://e.example.invalid/sse", "transport": "sse"})
    set_mcp_server("claudecode", "local", {"command": "uvx", "args": ["demo"]})
    servers = json.loads((home / ".claude.json").read_text(encoding="utf-8"))["mcpServers"]
    assert servers["deepwiki"] == {"type": "http", "url": "https://mcp.example.invalid/mcp"}
    assert servers["events"] == {"type": "sse", "url": "https://e.example.invalid/sse"}
    assert servers["local"] == {"command": "uvx", "args": ["demo"]}
    listed = {s.name: s.transport for s in connector_paths.mcp_servers("claudecode")}
    assert listed["deepwiki"] == "http" and listed["events"] == "sse"


def test_opencode_set_then_unset_restores_the_original_bytes(home):
    # GAP-1812: no new "mcp": {} and no re-serialised keys after the unset.
    path = home / ".config" / "opencode" / "opencode.json"
    path.parent.mkdir(parents=True)
    original = b'{\n    "theme": "tokyonight",\n    "$schema": "https://opencode.ai/config.json"\n}\n'
    path.write_bytes(original)

    set_mcp_server("opencode", "probe", {"url": "https://example.invalid/mcp"})
    assert "probe" in json.loads(path.read_text(encoding="utf-8"))["mcp"]
    unset_mcp_server("opencode", "probe")
    assert path.read_bytes() == original


def test_cursor_set_then_unset_restores_the_original_bytes(home):
    path = home / ".cursor" / "mcp.json"
    path.parent.mkdir(parents=True)
    original = b'{"editor": {"fontSize": 14}}\n'
    path.write_bytes(original)
    set_mcp_server("cursor", "probe", {"url": "https://example.invalid/mcp"})
    unset_mcp_server("cursor", "probe")
    assert path.read_bytes() == original


def test_claude_unset_reports_the_users_entry_was_put_back(home):
    # GAP-1846 (b): DefenseClaw replaced the user's own entry; unset puts it back.
    own = {"type": "http", "url": "https://mcp.example.invalid/mcp"}
    (home / ".claude.json").write_text(json.dumps({"mcpServers": {"own": own}}), encoding="utf-8")
    set_mcp_server("claudecode", "own", {"url": "https://other.example.invalid/mcp"})
    assert unset_mcp_server("claudecode", "own") == connector_paths.MCP_PRIOR_RESTORED
    assert json.loads((home / ".claude.json").read_text(encoding="utf-8"))["mcpServers"]["own"] == own


def test_disk_full_write_names_the_file_and_main_prints_one_line(home, monkeypatch, capsys):
    # GAP-1838: a full disk ended in a raw traceback with no file name.
    set_mcp_server("hermes", "deepwiki", {"url": "https://mcp.example.invalid/mcp"})
    config = connector_paths.hermes_config_path()

    real_write = connector_paths.atomic_write_private_bytes

    def _full(path, data, **kwargs):
        if os.fspath(path) != config:
            return real_write(path, data, **kwargs)
        raise OSError(errno.ENOSPC, "No space left on device")

    monkeypatch.setattr(connector_paths, "atomic_write_private_bytes", _full)
    with pytest.raises(OSError) as raised:
        unset_mcp_server("hermes", "deepwiki")
    assert raised.value.errno == errno.ENOSPC and raised.value.filename == config

    # main() snapshots console state into module globals and the environment;
    # keep that out of later tests.
    for name in ("_keep_console_width_when_piped", "_force_utf8_io"):
        monkeypatch.setattr(main, name, lambda: None)
    monkeypatch.setattr(main.ux, "configure_console_output", lambda *_a: None)
    monkeypatch.setattr(main, "_try_launch_tui", lambda: False)
    monkeypatch.setattr(main, "cli", MagicMock(side_effect=raised.value))
    with pytest.raises(SystemExit) as exited:
        main.main()
    assert exited.value.code == 1
    err = capsys.readouterr().err
    assert f"the disk is full, so DefenseClaw could not write {config}" in err
    assert "Traceback" not in err


class TestMCPUnsetWording(unittest.TestCase):
    def setUp(self):
        self.app, self.tmp_dir, self.db_path = make_app_context()
        self.app.cfg.active_connectors = lambda: ["claudecode", "codex"]  # type: ignore[method-assign]
        self.app.cfg.mcp_servers = MagicMock(  # type: ignore[method-assign]
            return_value=[MCPServerEntry(name="ctx7", url="http://x", transport="http")]
        )

    def tearDown(self):
        cleanup_app(self.app, self.db_path, self.tmp_dir)

    def invoke(self, args):
        return CliRunner().invoke(mcp, args, obj=self.app, catch_exceptions=False)

    @patch("defenseclaw.commands.cmd_mcp._unset_mcp_via_connector")
    def test_partial_unset_names_the_connectors_and_ends_with_an_error(self, mock_unset):
        # GAP-1846 (a)
        def _kept(cfg, name, connector=None):
            if connector == "claudecode":
                raise connector_paths.MCPServerNotRemovedError("left in place")

        mock_unset.side_effect = _kept
        result = self.invoke(["unset", "ctx7"])
        self.assertEqual(result.exit_code, 1)
        self.assertIn("[mcp] Removed 'ctx7' from codex", result.output)
        self.assertIn("Error: MCP server 'ctx7' was not removed from: claudecode.", result.output)

    @patch("defenseclaw.commands.cmd_mcp._unset_mcp_via_connector")
    def test_restored_user_entry_is_not_called_removed(self, mock_unset):
        # GAP-1846 (b)
        mock_unset.return_value = connector_paths.MCP_PRIOR_RESTORED
        result = self.invoke(["unset", "ctx7", "--connector", "claudecode"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertNotIn("[mcp] Removed", result.output)
        self.assertIn("Restored your previous ctx7 entry on claudecode", result.output)


class TestSharedSkillDirScope(unittest.TestCase):
    # GAP-1259: Claude Code and Amp share ~/.claude/skills; the watcher files
    # the quarantine under its own connector (amp) plus a global block.
    def setUp(self):
        self.app, self.tmp_dir, self.db_path = make_app_context()
        self.shared = os.path.join(self.tmp_dir, "claude-skills")
        self.original = os.path.join(self.shared, "review")
        os.makedirs(self.original)
        with open(os.path.join(self.original, "SKILL.md"), "w", encoding="utf-8") as handle:
            handle.write("test fixture\n")
        self.app.cfg.active_connector = lambda: "amp"  # type: ignore[method-assign]
        self.app.cfg.active_connectors = lambda: ["amp", "claudecode"]  # type: ignore[method-assign]
        self.app.cfg.skill_dirs = lambda connector=None: [self.shared]  # type: ignore[method-assign]

    def tearDown(self):
        cleanup_app(self.app, self.db_path, self.tmp_dir)

    def invoke(self, args):
        return CliRunner().invoke(skill, args, obj=self.app, catch_exceptions=False)

    def test_claudecode_scoped_unblock_and_restore_act_on_the_amp_quarantine(self):
        quarantined = self.invoke(["quarantine", "review", "--connector", "amp"])
        self.assertEqual(quarantined.exit_code, 0, quarantined.output)
        PolicyEngine(self.app.store, self.app.cfg).block("skill", "review", "watcher enforcement")

        unblocked = self.invoke(["unblock", "review", "--connector", "claudecode"])
        self.assertEqual(unblocked.exit_code, 0, unblocked.output)
        self.assertNotIn("already unblocked", unblocked.output)
        self.assertIn("a global decision", unblocked.output)
        self.assertIn("defenseclaw skill unblock review", unblocked.output)

        restored = self.invoke(["restore", "review", "--connector", "claudecode"])
        self.assertEqual(restored.exit_code, 0, restored.output)
        self.assertTrue(os.path.isfile(os.path.join(self.original, "SKILL.md")))


class TestSharedSkillDirGlobalWatcherBlock(TestSharedSkillDirScope):
    # GAP-1259 r4: the watcher's decision is global, and its quarantine record
    # is filed under amp. Scoped unblock named only "a global decision", and
    # bare unblock reported "cleared (connector=amp)" for a claudecode skill.
    def _watcher_state(self):
        quarantined = self.invoke(["quarantine", "review", "--connector", "amp"])
        self.assertEqual(quarantined.exit_code, 0, quarantined.output)
        pe = PolicyEngine(self.app.store, self.app.cfg)
        pe.remove_action_for_connector("skill", "review", "amp")
        pe.block("skill", "review", "watcher enforcement")
        return pe

    def test_scoped_unblock_names_the_peer_that_holds_the_quarantine(self):
        self._watcher_state()
        unblocked = self.invoke(["unblock", "review", "--connector", "claudecode"])
        self.assertEqual(unblocked.exit_code, 0, unblocked.output)
        self.assertIn("a global decision", unblocked.output)
        self.assertIn("quarantined under connector=amp", unblocked.output)

    def test_bare_unblock_reports_the_global_clear_not_the_quarantine_owner(self):
        pe = self._watcher_state()
        unblocked = self.invoke(["unblock", "review"])
        self.assertEqual(unblocked.exit_code, 0, unblocked.output)
        self.assertIn("Unblocked 'review' (every connector).", unblocked.output)
        self.assertNotIn("connector=amp", unblocked.output)
        self.assertFalse(pe.is_blocked("skill", "review"))


class TestClaudeProfileSymlinkRefusal(unittest.TestCase):
    # GAP-1390: a Claude profile whose .claude.json is a symlink is refused for
    # a sensitive write. The refusal is one plain line that names the file, and
    # the success lines name the profile that was written.
    def setUp(self):
        self.app, self.tmp_dir, self.db_path = make_app_context()
        self.profile = os.path.join(self.tmp_dir, "alt-profile")
        os.makedirs(self.profile)
        self.env = patch.dict(
            os.environ,
            {"HOME": self.tmp_dir, "USERPROFILE": self.tmp_dir, "CLAUDE_CONFIG_DIR": self.profile},
        )
        self.env.start()
        self.app.cfg.active_connectors = lambda: ["claudecode"]  # type: ignore[method-assign]
        self.app.cfg.mcp_servers = MagicMock(  # type: ignore[method-assign]
            return_value=[MCPServerEntry(name="demo", url="https://x.invalid/mcp", transport="http")]
        )

    def tearDown(self):
        self.env.stop()
        cleanup_app(self.app, self.db_path, self.tmp_dir)

    def invoke(self, args):
        return CliRunner().invoke(mcp, args, obj=self.app, catch_exceptions=False)

    def _link_state_file(self) -> str:
        real = os.path.join(self.tmp_dir, "operator-state.json")
        with open(real, "w", encoding="utf-8") as handle:
            handle.write("{}")
        link = os.path.join(self.profile, ".claude.json")
        try:
            os.symlink(real, link)
        except OSError:
            self.skipTest("symlink creation is unavailable")
        return link

    def _assert_one_plain_line(self, result, link):
        self.assertEqual(result.exit_code, 1, result.output)
        lines = [line for line in result.output.splitlines() if line.strip()]
        self.assertEqual(len(lines), 1, result.output)
        self.assertIn("refusing sensitive write through symlink", lines[0])
        self.assertIn(link, lines[0])
        self.assertNotIn("Traceback", result.output)

    def test_unset_refusal_is_one_line_naming_the_file(self):
        link = self._link_state_file()
        self._assert_one_plain_line(self.invoke(["unset", "demo", "--connector", "claudecode"]), link)

    def test_set_refusal_is_one_line_naming_the_file(self):
        link = self._link_state_file()
        result = self.invoke(["set", "demo2", "--url", "https://x.invalid/mcp", "--skip-scan", "--connector", "claudecode"])
        self._assert_one_plain_line(result, link)

    def test_success_lines_name_the_profile(self):
        with patch("defenseclaw.commands.cmd_mcp._set_mcp_via_connector"), patch(
            "defenseclaw.commands.cmd_mcp._unset_mcp_via_connector", return_value=None
        ):
            args = ["--url", "https://x.invalid/mcp", "--skip-scan", "--connector", "claudecode"]
            added = self.invoke(["set", "demo2", *args])
            removed = self.invoke(["unset", "demo", "--connector", "claudecode"])
            self.assertIn(f"[mcp] Added 'demo2' (claudecode, profile {self.profile}).", added.output)
            self.assertIn(f"[mcp] Removed 'demo' (claudecode, profile {self.profile}).", removed.output)
            with patch.dict(os.environ):
                os.environ.pop("CLAUDE_CONFIG_DIR")
                default = self.invoke(["set", "demo3", *args])
            self.assertIn("[mcp] Added 'demo3' (claudecode, default profile).", default.output)


@pytest.mark.parametrize("wrapped", [False, True])
def test_main_prints_a_symlink_refusal_from_any_command_as_one_line(monkeypatch, capsys, wrapped):
    # GAP-1390: skill, plugin and mcp writers share the sensitive-write check;
    # none of them may end in a traceback. Some re-raise the refusal as a ValueError.
    from defenseclaw.file_permissions import UnsafePathError

    refusal = UnsafePathError("refusing sensitive write through symlink: /x/.claude.json")
    raised: Exception = refusal
    if wrapped:
        raised = ValueError(str(refusal))
        raised.__cause__ = refusal
    for name in ("_keep_console_width_when_piped", "_force_utf8_io"):
        monkeypatch.setattr(main, name, lambda: None)
    monkeypatch.setattr(main.ux, "configure_console_output", lambda *_a: None)
    monkeypatch.setattr(main, "_try_launch_tui", lambda: False)
    monkeypatch.setattr(main, "cli", MagicMock(side_effect=raised))
    with pytest.raises(SystemExit) as exited:
        main.main()
    assert exited.value.code == 1
    err = capsys.readouterr().err
    assert err.strip() == "Error: refusing sensitive write through symlink: /x/.claude.json"


def test_an_unrelated_value_error_still_reaches_the_traceback(monkeypatch):
    for name in ("_keep_console_width_when_piped", "_force_utf8_io"):
        monkeypatch.setattr(main, name, lambda: None)
    monkeypatch.setattr(main.ux, "configure_console_output", lambda *_a: None)
    monkeypatch.setattr(main, "_try_launch_tui", lambda: False)
    monkeypatch.setattr(main, "cli", MagicMock(side_effect=ValueError("a real bug")))
    with pytest.raises(ValueError, match="a real bug"):
        main.main()
