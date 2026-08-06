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
import ntpath
import os
import sys
from pathlib import Path

import pytest
import yaml
from defenseclaw import connector_paths
from defenseclaw.connector_paths import MCPServerEntry


def _pin_claude_home(monkeypatch, home: Path) -> None:
    """Bind both platform home selectors, then disable Claude's override."""

    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.delenv("CLAUDE_CONFIG_DIR", raising=False)


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
            ("claude-code", "claudecode"),
            ("claude_code", "claudecode"),
            ("gemini-cli", "geminicli"),
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


def test_windsurf_paths_use_explicit_profile_binding_not_ambient_home(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bound = tmp_path / "bound-profile"
    ambient = tmp_path / "ambient-profile"
    monkeypatch.setenv("WINDSURF_USER_HOME", str(bound))
    monkeypatch.setattr(Path, "home", lambda: ambient)

    assert connector_paths.connector_home("windsurf") == str(
        bound / ".codeium" / "windsurf"
    )
    assert connector_paths.windsurf_hook_config_path() == str(
        bound / ".codeium" / "windsurf" / "hooks.json"
    )
    assert connector_paths.connector_config_files("windsurf") == [
        str(bound / ".codeium" / "windsurf" / "mcp_config.json"),
    ]


def test_windsurf_profile_binding_rejects_non_normalized_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(
        "WINDSURF_USER_HOME",
        str(tmp_path / "profile" / ".." / "redirected"),
    )

    with pytest.raises(ValueError, match="absolute normalized"):
        connector_paths.windsurf_hook_config_path()


def test_windsurf_hook_binding_must_match_bound_profile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bound = tmp_path / "bound-profile"
    monkeypatch.setenv("WINDSURF_USER_HOME", str(bound))
    monkeypatch.setenv(
        "WINDSURF_HOOK_CONFIG_PATH",
        str(tmp_path / "ambient-profile" / ".codeium" / "windsurf" / "hooks.json"),
    )

    with pytest.raises(ValueError, match="does not match"):
        connector_paths.windsurf_hook_config_path()


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

    def test_claudecode_includes_launch_ancestors_and_lazy_nested_skill_roots(
        self,
        tmp_path,
        monkeypatch,
    ):
        repository = tmp_path / "repo"
        launch = repository / "apps" / "web"
        nested = launch / "packages" / "ui" / ".claude" / "skills"
        (repository / ".git").mkdir(parents=True)
        nested.mkdir(parents=True)
        monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(tmp_path / "claude-home"))

        dirs = connector_paths.skill_dirs(
            "claudecode",
            workspace_dir=str(launch),
        )

        for expected in (
            launch / ".claude" / "skills",
            repository / "apps" / ".claude" / "skills",
            repository / ".claude" / "skills",
            nested,
        ):
            assert str(expected) in dirs

        user_skills = os.path.join(str(tmp_path / "claude-home"), "skills")
        user_commands = os.path.join(str(tmp_path / "claude-home"), "commands")
        assert dirs.index(user_skills) < dirs.index(str(repository / ".claude" / "skills"))
        assert dirs.index(str(repository / ".claude" / "skills")) < dirs.index(user_commands)

    def test_codex(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        dirs = connector_paths.skill_dirs("codex")
        home = str(Path.home())
        assert os.path.join(home, ".agents", "skills") in dirs
        assert os.path.join(home, ".codex", "skills") not in dirs

    def test_codex_scans_skill_layers_from_active_dir_to_repo_root(self, tmp_path, monkeypatch):
        fake_home = tmp_path / "home"
        fake_home.mkdir()
        monkeypatch.setenv("HOME", str(fake_home))
        repo = tmp_path / "repo"
        active = repo / "services" / "api"
        active.mkdir(parents=True)
        (repo / ".git").mkdir()

        dirs = connector_paths.skill_dirs("codex", workspace_dir=str(active))

        assert dirs[:3] == [
            str(active / ".agents" / "skills"),
            str(active.parent / ".agents" / "skills"),
            str(repo / ".agents" / "skills"),
        ]
        assert str(fake_home / ".agents" / "skills") in dirs


class TestClaudeAgentDirs:
    def test_closest_first_launch_ancestors_then_user(self, tmp_path, monkeypatch):
        repository = tmp_path / "repo"
        launch = repository / "apps" / "web"
        (repository / ".git").mkdir(parents=True)
        launch.mkdir(parents=True)
        config_dir = tmp_path / "claude-home"
        monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(config_dir))

        assert connector_paths.claude_agent_dirs(str(launch)) == [
            str(launch / ".claude" / "agents"),
            str(repository / "apps" / ".claude" / "agents"),
            str(repository / ".claude" / "agents"),
            str(config_dir / "agents"),
        ]


class TestClaudeAutoMemory:
    def test_default_uses_shared_linked_worktree_project_root(self, tmp_path, monkeypatch):
        main = tmp_path / "main"
        git_dir = main / ".git"
        worktree = tmp_path / "worktree"
        worktree_git = git_dir / "worktrees" / "feature"
        worktree.mkdir(parents=True)
        worktree_git.mkdir(parents=True)
        (worktree / ".git").write_text(
            f"gitdir: {worktree_git}\n",
            encoding="utf-8",
        )
        (worktree_git / "commondir").write_text("../..\n", encoding="utf-8")
        config_dir = tmp_path / "claude-home"
        monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(config_dir))

        resolution = connector_paths.claude_auto_memory_resolution(
            str(worktree),
            managed_settings_paths=[],
        )

        assert resolution.project_root == str(main)
        assert resolution.path == os.path.join(
            str(config_dir),
            "projects",
            connector_paths._claude_project_storage_key(str(main)),
            "memory",
        )
        assert resolution.source == "derived-project-default"
        assert resolution.activation_verified is False
        assert "--settings" in resolution.limitation

    def test_file_settings_precedence_and_tilde_override(self, tmp_path, monkeypatch):
        project = tmp_path / "project"
        (project / ".git").mkdir(parents=True)
        config_dir = tmp_path / "claude-home"
        managed = tmp_path / "managed-settings.json"
        monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(config_dir))
        for path, value in (
            (config_dir / "settings.json", str(tmp_path / "user-memory")),
            (project / ".claude" / "settings.json", str(tmp_path / "project-memory")),
            (project / ".claude" / "settings.local.json", str(tmp_path / "local-memory")),
            (managed, "~/managed-memory"),
        ):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                json.dumps({"autoMemoryDirectory": value}),
                encoding="utf-8",
            )

        resolution = connector_paths.claude_auto_memory_resolution(
            str(project),
            managed_settings_paths=[str(managed)],
        )

        assert resolution.path == os.path.join(str(Path.home()), "managed-memory")
        assert resolution.source == str(managed)

    def test_memory_files_are_bounded_to_regular_markdown(self, tmp_path, monkeypatch):
        project = tmp_path / "project"
        (project / ".git").mkdir(parents=True)
        memory = tmp_path / "memory"
        (memory / "topics").mkdir(parents=True)
        (memory / "MEMORY.md").write_text("index\n", encoding="utf-8")
        (memory / "topics" / "debugging.md").write_text("topic\n", encoding="utf-8")
        (memory / "ignored.txt").write_text("ignored\n", encoding="utf-8")
        config_dir = tmp_path / "claude-home"
        config_dir.mkdir()
        (config_dir / "settings.json").write_text(
            json.dumps({"autoMemoryDirectory": str(memory)}),
            encoding="utf-8",
        )
        monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(config_dir))

        resolution, files = connector_paths.claude_auto_memory_files(
            str(project),
            managed_settings_paths=[],
        )

        assert resolution.path == str(memory)
        assert files == [
            str(memory / "MEMORY.md"),
            str(memory / "topics" / "debugging.md"),
        ]

    def test_amp_honors_documented_precedence_and_custom_settings(self, tmp_path, monkeypatch):
        fake_home = tmp_path / "home"
        workspace = tmp_path / "repo"
        settings_dir = workspace / ".amp"
        settings_dir.mkdir(parents=True)
        (fake_home / ".config" / "amp").mkdir(parents=True)
        monkeypatch.setenv("HOME", str(fake_home))
        custom_one = tmp_path / "team-skills"
        custom_two = tmp_path / "shared-skills"
        custom_path = f"{custom_one}{os.pathsep}{custom_two}"
        (settings_dir / "settings.jsonc").write_text(
            "{\n"
            '  // Amp settings use dotted keys.\n'
            f'  "amp.skills.path": {json.dumps(custom_path)},\n'
            '  "amp.skills.disableClaudeCodeSkills": true\n'
            "}\n"
        )

        dirs = connector_paths.skill_dirs("amp", workspace_dir=str(workspace))

        assert dirs[:4] == [
            str(fake_home / ".config" / "agents" / "skills"),
            str(fake_home / ".agents" / "skills"),
            str(fake_home / ".config" / "amp" / "skills"),
            str(workspace / ".agents" / "skills"),
        ]
        assert str(custom_one) in dirs
        assert str(custom_two) in dirs
        assert str(workspace / ".claude" / "skills") not in dirs
        assert str(fake_home / ".claude" / "skills") not in dirs

    def test_amp_claude_plugin_cache_skills_follow_disable_setting(self, tmp_path, monkeypatch):
        fake_home = tmp_path / "home"
        workspace = tmp_path / "repo"
        settings_dir = workspace / ".amp"
        cached_skills = (
            fake_home
            / ".claude"
            / "plugins"
            / "cache"
            / "marketplace"
            / "review-plugin"
            / "1.2.3"
            / "skills"
        )
        cached_skills.mkdir(parents=True)
        settings_dir.mkdir(parents=True)
        monkeypatch.setenv("HOME", str(fake_home))

        enabled = connector_paths.skill_dirs("amp", workspace_dir=str(workspace))
        assert str(cached_skills) in enabled

        (settings_dir / "settings.json").write_text(
            json.dumps({"amp.skills.disableClaudeCodeSkills": True}),
        )
        disabled = connector_paths.skill_dirs("amp", workspace_dir=str(workspace))
        assert str(cached_skills) not in disabled
        assert str(workspace / ".claude" / "skills") not in disabled
        assert str(fake_home / ".claude" / "skills") not in disabled

    def test_amp_settings_reader_rejects_symlink(self, tmp_path):
        target = tmp_path / "target.json"
        target.write_text(json.dumps({"amp.skills.disableClaudeCodeSkills": True}))
        link = tmp_path / "settings-link.json"
        try:
            link.symlink_to(target)
        except OSError as exc:
            pytest.skip(f"symlink unavailable: {exc}")
        assert connector_paths._load_amp_settings_document(str(link)) is None

    def test_amp_settings_reader_rejects_oversize(self, tmp_path):
        oversized = tmp_path / "oversized.json"
        oversized.write_bytes(b" " * (connector_paths._AMP_SETTINGS_MAX_BYTES + 1))
        assert connector_paths._load_amp_settings_document(str(oversized)) is None

    def test_amp_cache_directory_reader_enforces_requested_entry_cap(self, tmp_path):
        for name in ("zeta", "alpha", "middle", "omega"):
            (tmp_path / name).mkdir()

        entries = connector_paths._bounded_amp_directory_entries(str(tmp_path), 2)

        assert len(entries) == 2
        assert [entry.name.casefold() for entry in entries] == sorted(
            entry.name.casefold() for entry in entries
        )

    def test_amp_relative_custom_skill_requires_explicit_workspace(self, tmp_path, monkeypatch):
        fake_home = tmp_path / "home"
        settings = fake_home / ".config" / "amp" / "settings.json"
        settings.parent.mkdir(parents=True)
        settings.write_text(json.dumps({"amp.skills.path": "relative-skills"}))
        monkeypatch.setenv("HOME", str(fake_home))
        monkeypatch.chdir(tmp_path)

        assert str(tmp_path / "relative-skills") not in connector_paths.skill_dirs("amp")
        assert str(tmp_path / "repo" / "relative-skills") in connector_paths.skill_dirs(
            "amp",
            workspace_dir=str(tmp_path / "repo"),
        )

    def test_amp_skill_write_scope_is_workspace_when_pinned_else_global(self, tmp_path, monkeypatch):
        fake_home = tmp_path / "home"
        workspace = tmp_path / "repo"
        monkeypatch.setenv("HOME", str(fake_home))
        monkeypatch.setenv("USERPROFILE", str(fake_home))

        assert connector_paths.skill_write_dirs("amp") == [
            str(fake_home / ".config" / "agents" / "skills")
        ]
        assert connector_paths.skill_write_dirs(
            "amp",
            workspace_dir=str(workspace),
        ) == [str(workspace / ".agents" / "skills")]

    def test_amp_settings_json_wins_same_scope_then_jsonc_falls_back(self, tmp_path, monkeypatch):
        fake_home = tmp_path / "home"
        config = fake_home / ".config" / "amp"
        config.mkdir(parents=True)
        json_skills = tmp_path / "json-skills"
        jsonc_skills = tmp_path / "jsonc-skills"
        monkeypatch.setenv("HOME", str(fake_home))
        monkeypatch.setenv("USERPROFILE", str(fake_home))
        json_path = config / "settings.json"
        jsonc_path = config / "settings.jsonc"
        json_path.write_text(
            json.dumps(
                {
                    "amp.skills.path": str(json_skills),
                    "amp.skills.disableClaudeCodeSkills": True,
                }
            )
        )
        jsonc_path.write_text(
            "{\n"
            f'  "amp.skills.path": {json.dumps(str(jsonc_skills))},\n'
            '  "amp.skills.disableClaudeCodeSkills": false\n'
            "}\n"
        )

        dirs = connector_paths.skill_dirs("amp")
        assert str(json_skills) in dirs
        assert str(jsonc_skills) not in dirs
        assert str(fake_home / ".claude" / "skills") not in dirs

        json_path.unlink()
        dirs = connector_paths.skill_dirs("amp")
        assert str(jsonc_skills) in dirs
        assert str(json_skills) not in dirs
        assert str(fake_home / ".claude" / "skills") in dirs

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
        monkeypatch.setenv("WINDSURF_USER_HOME", str(tmp_path / "windsurf-profile"))
        assert connector_paths.skill_dirs("hermes") == [
            os.path.join(str(tmp_path / "home"), ".hermes", "skills"),
        ]
        assert os.path.join(str(tmp_path / "home"), ".cursor", "skills") in connector_paths.skill_dirs("cursor")
        assert os.path.join(str(tmp_path), ".cursor", "skills") in connector_paths.skill_dirs(
            "cursor",
            workspace_dir=str(tmp_path),
        )
        for family in (".cursor", ".agents", ".claude", ".codex"):
            assert os.path.join(str(tmp_path / "home"), family, "skills") in connector_paths.skill_dirs(
                "cursor",
                workspace_dir=str(tmp_path),
            )
            assert os.path.join(str(tmp_path), family, "skills") in connector_paths.skill_dirs(
                "cursor",
                workspace_dir=str(tmp_path),
            )
        assert connector_paths.skill_dirs("windsurf") == [
            os.path.join(
                str(tmp_path / "windsurf-profile"),
                ".codeium",
                "windsurf",
                "skills",
            ),
            os.path.join(str(tmp_path / "windsurf-profile"), ".agents", "skills"),
        ]
        assert connector_paths.skill_dirs("windsurf", workspace_dir=str(tmp_path)) == [
            os.path.join(
                str(tmp_path / "windsurf-profile"),
                ".codeium",
                "windsurf",
                "skills",
            ),
            os.path.join(str(tmp_path / "windsurf-profile"), ".agents", "skills"),
            os.path.join(str(tmp_path), ".windsurf", "skills"),
            os.path.join(str(tmp_path), ".agents", "skills"),
        ]
        antigravity = connector_paths.skill_dirs("antigravity", workspace_dir=str(tmp_path))
        assert os.path.join(str(tmp_path / "home"), ".gemini", "config", "skills") in antigravity
        assert os.path.join(str(tmp_path), ".agents", "skills") in antigravity
        assert os.path.join(str(tmp_path), ".agent", "skills") in antigravity
        assert os.path.join(str(tmp_path / "home"), ".gemini", "antigravity-cli", "skills") in antigravity
        assert os.path.join(str(tmp_path / "home"), ".gemini", "skills") not in antigravity
        assert os.path.join(str(tmp_path / "home"), ".agents", "skills") not in antigravity
        assert connector_paths.skill_dirs("opencode", workspace_dir=str(tmp_path)) == []
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

    def test_cursor_skill_dirs_include_nested_documented_roots_without_aliases(self, tmp_path, monkeypatch):
        home = tmp_path / "home"
        workspace = tmp_path / "repo"
        nested = workspace / "apps" / "web" / ".agents" / "skills"
        nested.mkdir(parents=True)
        rejected = workspace / "linked" / ".cursor" / "skills"
        rejected.mkdir(parents=True)
        monkeypatch.setenv("HOME", str(home))
        monkeypatch.setattr(
            connector_paths,
            "_cursor_walkable_directory",
            lambda path: os.path.normcase(os.path.abspath(path))
            != os.path.normcase(os.path.abspath(str(workspace / "linked"))),
        )

        roots = connector_paths.skill_dirs("cursor", workspace_dir=str(workspace))

        assert str(nested) in roots
        assert str(rejected) not in roots
        openhands = connector_paths.skill_dirs("openhands")
        assert os.path.join(str(tmp_path / "home"), ".agents", "skills") in openhands
        assert os.path.join(str(tmp_path / "home"), ".openhands", "skills") in openhands
        assert os.path.join(str(tmp_path / "home"), ".openhands", "microagents") in openhands
        assert os.path.join(str(tmp_path / "home"), ".openhands", "skills", "installed") in openhands
        assert (
            os.path.join(str(tmp_path / "home"), ".openhands", "cache", "skills", "public-skills", "skills")
            in openhands
        )

    def test_hermes_skill_dirs_include_existing_external_dirs(self, tmp_path, monkeypatch):
        hermes_home = tmp_path / "hermes"
        external = tmp_path / "shared-skills"
        relative = hermes_home / "relative-skills"
        external.mkdir()
        relative.mkdir(parents=True)
        hermes_home.mkdir(exist_ok=True)
        (hermes_home / "config.yaml").write_text(
            yaml.safe_dump(
                {
                    "skills": {
                        "external_dirs": [str(external), "relative-skills", str(tmp_path / "missing")]
                    }
                }
            ),
            encoding="utf-8",
        )
        monkeypatch.setenv("HERMES_HOME", str(hermes_home))

        assert connector_paths.skill_dirs("hermes") == [
            str(hermes_home / "skills"),
            str(external),
            str(relative),
        ]

    @pytest.mark.parametrize(
        ("fixture", "needle"),
        [
            ("named_home", "named profiles"),
            ("profile_directory", "named profile"),
            ("active_profile", "active named profile"),
            ("multiplex_config", "multiplex profiles"),
            ("multiplex_env", "multiplex profiles"),
        ],
    )
    def test_hermes_profile_topology_is_rejected(self, fixture, needle, tmp_path, monkeypatch):
        home = tmp_path / "hermes"
        home.mkdir()
        config = home / "config.yaml"
        if fixture == "named_home":
            config = home / "profiles" / "coder" / "config.yaml"
        elif fixture == "profile_directory":
            (home / "profiles" / "coder").mkdir(parents=True)
        elif fixture == "active_profile":
            (home / "active_profile").write_text("coder\n", encoding="utf-8")
        elif fixture == "multiplex_config":
            config.write_text("gateway:\n  multiplex_profiles: true\n", encoding="utf-8")
        elif fixture == "multiplex_env":
            monkeypatch.setenv("GATEWAY_MULTIPLEX_PROFILES", "on")
        monkeypatch.setenv("HERMES_HOME", str(config.parent))

        reason = connector_paths.hermes_profile_unsupported_reason(str(config))

        assert needle in reason

    def test_copilot_skill_and_agent_dirs_follow_official_precedence(self, tmp_path, monkeypatch):
        home = tmp_path / "home"
        copilot_home = home / "custom-copilot"
        repo = tmp_path / "repo"
        package = repo / "packages" / "service"
        package.mkdir(parents=True)
        (repo / ".git").mkdir()
        custom = tmp_path / "custom-skills"
        monkeypatch.setenv("HOME", str(home))
        monkeypatch.setenv("USERPROFILE", str(home))
        monkeypatch.setenv("COPILOT_HOME", str(copilot_home))
        monkeypatch.setenv("COPILOT_SKILLS_DIRS", f"{custom},relative-skills")

        skills = connector_paths.skill_dirs("copilot", workspace_dir=str(package))
        assert skills == [
            str(package / ".github" / "skills"),
            str(package / ".agents" / "skills"),
            str(package / ".claude" / "skills"),
            str(package.parent / ".github" / "skills"),
            str(repo / ".github" / "skills"),
            str(copilot_home / "skills"),
            str(home / ".agents" / "skills"),
            str(custom),
            str(package / "relative-skills"),
            str(package / ".claude" / "commands"),
        ]
        assert connector_paths.copilot_agent_dirs(str(package)) == [
            str(package / ".github" / "agents"),
            str(package / ".claude" / "agents"),
            str(package.parent / ".github" / "agents"),
            str(package.parent / ".claude" / "agents"),
            str(repo / ".github" / "agents"),
            str(repo / ".claude" / "agents"),
            str(copilot_home / "agents"),
        ]
        assert connector_paths.copilot_mcp_config_files(str(package)) == [
            str(package / ".mcp.json"),
            str(package / ".github" / "mcp.json"),
            str(package.parent / ".mcp.json"),
            str(package.parent / ".github" / "mcp.json"),
            str(repo / ".mcp.json"),
            str(repo / ".github" / "mcp.json"),
            str(copilot_home / "mcp-config.json"),
        ]

    def test_copilot_settings_cascade_uses_bound_home_and_repository_layers(
        self, tmp_path, monkeypatch
    ):
        home = tmp_path / "copilot-home"
        repo = tmp_path / "repo"
        workspace = repo / "package"
        workspace.mkdir(parents=True)
        (repo / ".git").mkdir()
        (home).mkdir()
        monkeypatch.setenv("COPILOT_HOME", str(home))
        (home / "config.json").write_text('{"disableAllHooks": true}')
        (home / "settings.json").write_text('{// operator\n"disableAllHooks": false,}')
        claude = repo / ".claude"
        claude.mkdir()
        (claude / "settings.json").write_text('{"disableAllHooks": false}')
        (claude / "settings.local.json").write_text('{"disableAllHooks": true}')
        native = repo / ".github" / "copilot"
        native.mkdir(parents=True)
        (native / "settings.json").write_text('{"disableAllHooks": true}')
        (native / "settings.local.json").write_text('{"disableAllHooks": false}')

        resolution = connector_paths.copilot_settings_resolution(str(workspace))

        assert resolution.verified is True
        assert resolution.disable_all_hooks is False
        assert resolution.source == str(native / "settings.local.json")
        assert resolution.managed_policy_verified is False
        assert resolution.inspected == tuple(
            connector_paths.copilot_settings_paths(str(workspace))
        )
        assert str(claude / "settings.json") in resolution.inspected
        assert str(claude / "settings.local.json") in resolution.inspected
        instruction_paths = connector_paths.rule_dirs(
            "copilot", workspace_dir=str(workspace)
        )
        assert str(home / "copilot-instructions.md") in instruction_paths
        assert str(repo / "AGENTS.md") in instruction_paths
        assert str(repo / ".github" / "instructions") in instruction_paths
        assert str(repo) in instruction_paths
        configs = connector_paths.connector_config_files(
            "copilot", workspace_dir=str(workspace)
        )
        assert str(home / "settings.json") in configs
        assert str(home / "config.json") not in configs
        assert str(workspace / ".github" / "copilot.json") not in configs

    @pytest.mark.parametrize("binding", [" relative-home ", ""])
    def test_copilot_home_rejects_non_exact_lifecycle_binding(self, monkeypatch, binding):
        monkeypatch.setenv("COPILOT_HOME", binding)

        with pytest.raises(ValueError, match="absolute normalized"):
            connector_paths.copilot_home()
        resolution = connector_paths.copilot_settings_resolution()
        assert resolution.verified is False
        assert resolution.errors == ("COPILOT_HOME is not an absolute normalized path",)

    def test_copilot_non_repository_workspace_does_not_scan_filesystem_ancestors(self, tmp_path):
        workspace = tmp_path / "not-a-repo" / "package"
        workspace.mkdir(parents=True)

        agents = connector_paths.copilot_agent_dirs(str(workspace))

        assert str(workspace / ".github" / "agents") in agents
        assert str(workspace.parent / ".github" / "agents") not in agents

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
        assert os.path.join(home, ".claude", "plugins", "cache") in dirs
        assert os.path.join(home, ".claude", "skills") in dirs
        assert os.path.join(str(tmp_path), ".claude", "plugins") not in dirs

    def test_claudecode_includes_only_official_workspace_skills_plugin_root(
        self,
        tmp_path,
    ):
        dirs = connector_paths.plugin_dirs(
            "claudecode",
            workspace_dir=str(tmp_path),
        )
        assert os.path.join(str(tmp_path), ".claude", "skills") in dirs
        assert os.path.join(str(tmp_path), ".claude", "plugins") not in dirs

    def test_claudecode_plugins_include_ancestor_and_nested_skills_roots(
        self,
        tmp_path,
    ):
        repository = tmp_path / "repo"
        launch = repository / "apps" / "web"
        nested = launch / "packages" / "ui" / ".claude" / "skills"
        (repository / ".git").mkdir(parents=True)
        nested.mkdir(parents=True)

        dirs = connector_paths.plugin_dirs(
            "claudecode",
            workspace_dir=str(launch),
        )

        assert str(repository / ".claude" / "skills") in dirs
        assert str(nested) in dirs

    def test_claudecode_honors_plugin_parent_override(self, tmp_path, monkeypatch):
        plugin_parent = tmp_path / "claude-plugin-parent"
        monkeypatch.setenv("CLAUDE_CODE_PLUGIN_CACHE_DIR", str(plugin_parent))

        dirs = connector_paths.plugin_dirs("claudecode")

        assert str(plugin_parent / "cache") in dirs
        assert os.path.join(str(Path.home()), ".claude", "plugins", "cache") not in dirs

    def test_codex(self):
        dirs = connector_paths.plugin_dirs("codex")
        home = str(Path.home())
        # Installed Codex plugins live only below the canonical cache.
        assert os.path.join(home, ".codex", "plugins", "cache") in dirs
        assert os.path.join(home, ".codex", "plugins") not in dirs

    def test_codex_resolves_local_marketplaces_without_inventing_repo_plugin_root(
        self,
        tmp_path,
        monkeypatch,
    ):
        fake_home = tmp_path / "home"
        fake_home.mkdir()
        custom_codex_home = tmp_path / "codex-state"
        monkeypatch.setattr("defenseclaw.connector_paths.Path.home", lambda: fake_home)
        monkeypatch.setenv("CODEX_HOME", str(custom_codex_home))

        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / ".git").mkdir()
        repo_plugin = repo / "packages" / "repo-plugin"
        repo_plugin.mkdir(parents=True)
        legacy_plugin = repo / "packages" / "legacy-plugin"
        legacy_plugin.mkdir(parents=True)
        personal_plugin = fake_home / "personal-plugins" / "personal-plugin"
        personal_plugin.mkdir(parents=True)

        repo_marketplace = repo / ".agents" / "plugins" / "marketplace.json"
        repo_marketplace.parent.mkdir(parents=True)
        repo_marketplace.write_text(
            json.dumps(
                {
                    "plugins": [
                        {"name": "repo", "source": {"source": "local", "path": "./packages/repo-plugin"}},
                        {"name": "remote", "source": {"source": "url", "url": "https://example.com/plugin.git"}},
                        {"name": "escape", "source": {"source": "local", "path": "./../outside"}},
                    ]
                }
            )
        )
        legacy_marketplace = repo / ".claude-plugin" / "marketplace.json"
        legacy_marketplace.parent.mkdir(parents=True)
        legacy_marketplace.write_text(
            json.dumps(
                {
                    "plugins": [
                        {
                            "name": "legacy",
                            "source": {
                                "source": "local",
                                "path": "./packages/legacy-plugin",
                            },
                        },
                    ]
                }
            )
        )
        personal_marketplace = fake_home / ".agents" / "plugins" / "marketplace.json"
        personal_marketplace.parent.mkdir(parents=True)
        personal_marketplace.write_text(
            json.dumps(
                {
                    "plugins": [
                        {"name": "personal", "source": "./personal-plugins/personal-plugin"},
                    ]
                }
            )
        )

        dirs = connector_paths.plugin_dirs("codex", workspace_dir=str(repo))

        assert dirs[:3] == [str(repo_plugin), str(legacy_plugin), str(personal_plugin)]
        assert str(custom_codex_home / "plugins" / "cache") in dirs
        assert str(custom_codex_home / "plugins") not in dirs
        assert str(repo / "plugins") not in dirs
        assert all("outside" not in path for path in dirs)

    def test_codex_marketplace_rejects_reparse_source_and_oversized_catalog(
        self,
        tmp_path,
        monkeypatch,
    ):
        fake_home = tmp_path / "home"
        fake_home.mkdir()
        monkeypatch.setattr("defenseclaw.connector_paths.Path.home", lambda: fake_home)
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / ".git").mkdir()
        plugin = repo / "packages" / "plugin"
        plugin.mkdir(parents=True)
        marketplace = repo / ".agents" / "plugins" / "marketplace.json"
        marketplace.parent.mkdir(parents=True)
        marketplace.write_text(
            json.dumps({"plugins": [{"name": "p", "source": "./packages/plugin"}]})
        )

        real_reject = connector_paths.reject_reparse_path

        def reject_candidate(path):
            if os.path.normcase(os.path.abspath(path)) == os.path.normcase(str(plugin)):
                raise OSError("mocked Windows reparse point")
            return real_reject(path)

        monkeypatch.setattr(connector_paths, "reject_reparse_path", reject_candidate)
        assert str(plugin) not in connector_paths.plugin_dirs(
            "codex",
            workspace_dir=str(repo),
        )

        monkeypatch.setattr(connector_paths, "reject_reparse_path", real_reject)
        marketplace.write_bytes(b" " * (1024 * 1024 + 1))
        assert str(plugin) not in connector_paths.plugin_dirs(
            "codex",
            workspace_dir=str(repo),
        )

    def test_codex_marketplace_rejects_catalog_replaced_during_read(
        self,
        tmp_path,
        monkeypatch,
    ):
        marketplace = tmp_path / "marketplace.json"
        marketplace.write_text('{"plugins":[]}')
        monkeypatch.setattr(
            connector_paths,
            "_read_bounded_stable_file",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(
                OSError("file was replaced while it was being inventoried")
            ),
        )

        assert connector_paths._read_codex_local_marketplace_paths(
            str(marketplace),
            str(tmp_path),
        ) == []

    def test_amp_project_and_system_plugin_dirs(self, tmp_path, monkeypatch):
        fake_home = tmp_path / "home"
        monkeypatch.setenv("HOME", str(fake_home))
        assert connector_paths.plugin_dirs("amp", workspace_dir=str(tmp_path)) == [
            str(tmp_path / ".amp" / "plugins"),
            str(fake_home / ".config" / "amp" / "plugins"),
        ]

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
        # Cursor local plugins are inventory-only. The write/install path API
        # intentionally remains empty so DefenseClaw cannot claim custody.
        assert connector_paths.plugin_dirs("cursor") == []
        assert connector_paths.plugin_inventory_dirs("cursor") == [
            os.path.join(str(tmp_path / "home"), ".cursor", "plugins", "local"),
        ]
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
        assert connector_paths.plugin_dirs("opencode", workspace_dir=str(tmp_path)) == []

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
# agent_dirs / rule_dirs
# ---------------------------------------------------------------------------


class TestCodexAssetDirs:
    def test_agent_and_rule_layers_follow_project_precedence(self, tmp_path, monkeypatch):
        fake_home = tmp_path / "home"
        fake_home.mkdir()
        monkeypatch.setenv("HOME", str(fake_home))
        repo = tmp_path / "repo"
        active = repo / "nested"
        active.mkdir(parents=True)
        (repo / ".git").mkdir()

        agents = connector_paths.agent_dirs("codex", workspace_dir=str(active))
        rules = connector_paths.rule_dirs("codex", workspace_dir=str(active))

        assert agents[:2] == [
            str(active / ".codex" / "agents"),
            str(repo / ".codex" / "agents"),
        ]
        assert agents[-1] == str(fake_home / ".codex" / "agents")
        assert rules[:2] == [
            str(active / ".codex" / "rules"),
            str(repo / ".codex" / "rules"),
        ]
        assert str(fake_home / ".codex" / "rules") in rules

    def test_custom_project_root_markers_bound_ancestor_scan(self, tmp_path, monkeypatch):
        fake_home = tmp_path / "home"
        codex_home = fake_home / ".codex"
        codex_home.mkdir(parents=True)
        (codex_home / "config.toml").write_text('project_root_markers = [".sl"]\n')
        monkeypatch.setenv("HOME", str(fake_home))
        repo = tmp_path / "repo"
        active = repo / "nested"
        active.mkdir(parents=True)
        (repo / ".sl").mkdir()

        dirs = connector_paths.agent_dirs("codex", workspace_dir=str(active))

        assert dirs[:2] == [
            str(active / ".codex" / "agents"),
            str(repo / ".codex" / "agents"),
        ]
        assert not any(str(tmp_path / ".codex" / "agents") == path for path in dirs)

    def test_unsafe_project_marker_config_falls_back_to_git(self, tmp_path, monkeypatch):
        fake_home = tmp_path / "home"
        codex_home = fake_home / ".codex"
        codex_home.mkdir(parents=True)
        (codex_home / "config.toml").write_text('project_root_markers = [".sl"]\n')
        monkeypatch.setenv("HOME", str(fake_home))
        repo = tmp_path / "repo"
        active = repo / "nested"
        active.mkdir(parents=True)
        (repo / ".git").mkdir()
        monkeypatch.setattr(
            connector_paths,
            "_read_bounded_stable_file",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(
                OSError("mocked Windows reparse point")
            ),
        )

        dirs = connector_paths.agent_dirs("codex", workspace_dir=str(active))

        assert dirs[:2] == [
            str(active / ".codex" / "agents"),
            str(repo / ".codex" / "agents"),
        ]


# ---------------------------------------------------------------------------
# mcp_servers
# ---------------------------------------------------------------------------


class TestMCPServers:
    def _write_mcp_json(self, dirpath: Path, servers: dict) -> Path:
        path = dirpath / ".mcp.json"
        path.write_text(json.dumps({"mcpServers": servers}))
        return path

    def _write_codex_config(self, directory: Path, servers: dict[str, dict]) -> Path:
        path = directory / ".codex" / "config.toml"
        path.parent.mkdir(parents=True, exist_ok=True)
        blocks = []
        for name, server in servers.items():
            blocks.append(f'[mcp_servers."{name}"]')
            if server.get("command"):
                blocks.append(f'command = "{server["command"]}"')
            if server.get("args") is not None:
                args = ", ".join(json.dumps(arg) for arg in server["args"])
                blocks.append(f"args = [{args}]")
            blocks.append("")
        path.write_text("\n".join(blocks))
        return path

    def test_codex_reads_project_config_toml(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        # Isolate $HOME so the test doesn't accidentally pick up a
        # real ~/.codex/config.toml on the developer's machine.
        fake_home = tmp_path / "home"
        fake_home.mkdir()
        monkeypatch.setenv("HOME", str(fake_home))
        self._write_codex_config(
            tmp_path,
            {
                "github": {"command": "gh", "args": ["mcp"]},
            },
        )
        entries = connector_paths.mcp_servers("codex", workspace_dir=str(tmp_path))
        assert [e.name for e in entries] == ["github"]
        assert entries[0].command == "gh"
        assert entries[0].args == ["mcp"]

    def test_codex_without_config_toml_returns_empty(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        fake_home = tmp_path / "home"
        fake_home.mkdir()
        monkeypatch.setenv("HOME", str(fake_home))
        assert connector_paths.mcp_servers("codex") == []
        assert connector_paths.mcp_servers("codex", workspace_dir=str(tmp_path)) == []

    def test_amp_reads_jsonc_workspace_user_and_skill_mcp_with_precedence(
        self,
        tmp_path,
        monkeypatch,
    ):
        fake_home = tmp_path / "home"
        workspace = tmp_path / "repo"
        user_config = fake_home / ".config" / "amp"
        workspace_config = workspace / ".amp"
        user_skill = fake_home / ".config" / "agents" / "skills" / "browser"
        managed_settings = tmp_path / "managed" / "managed-settings.json"
        user_config.mkdir(parents=True)
        workspace_config.mkdir(parents=True)
        user_skill.mkdir(parents=True)
        managed_settings.parent.mkdir(parents=True)
        monkeypatch.setenv("HOME", str(fake_home))
        monkeypatch.setattr(
            connector_paths,
            "amp_managed_settings_path",
            lambda: str(managed_settings),
        )
        (user_config / "settings.json").write_text(
            json.dumps(
                {
                    "amp.mcpServers": {
                        "shared": {"command": "from-user"},
                        "user-only": {"url": "https://user.example/mcp"},
                    }
                }
            )
        )
        (workspace_config / "settings.jsonc").write_text(
            "{\n"
            '  "amp.mcpServers": {\n'
            '    "shared": {"command": "from-workspace"}, // wins\n'
            '    "workspace-only": {"command": "workspace-mcp"}\n'
            "  }\n"
            "}\n"
        )
        managed_settings.write_text(
            json.dumps(
                {
                    "amp.mcpServers": {
                        "shared": {"command": "from-managed"},
                        "managed-only": {"command": "managed-mcp"},
                    }
                }
            )
        )
        (user_skill / "mcp.json").write_text(
            json.dumps(
                {
                    "shared": {"command": "from-skill"},
                    "skill-only": {"command": "skill-mcp"},
                }
            )
        )

        entries = connector_paths.mcp_servers("amp", workspace_dir=str(workspace))
        by_name = {entry.name: entry for entry in entries}

        assert list(by_name) == [
            "shared",
            "managed-only",
            "workspace-only",
            "user-only",
            "skill-only",
        ]
        assert by_name["shared"].command == "from-managed"
        assert by_name["user-only"].url == "https://user.example/mcp"

    def test_amp_jsonc_fallback_preserves_comma_bracket_text_in_quoted_mcp_values(
        self,
        tmp_path,
        monkeypatch,
    ):
        fake_home = tmp_path / "home"
        workspace = tmp_path / "repo"
        settings = workspace / ".amp" / "settings.jsonc"
        settings.parent.mkdir(parents=True)
        monkeypatch.setenv("HOME", str(fake_home))
        monkeypatch.setenv("USERPROFILE", str(fake_home))
        monkeypatch.setitem(sys.modules, "json5", None)
        monkeypatch.setattr(
            connector_paths,
            "amp_managed_settings_path",
            lambda: str(tmp_path / "missing-managed-settings.json"),
        )
        settings.write_text(
            "{\n"
            "  // Force the string-aware fallback parser.\n"
            '  "amp.mcpServers": {\n'
            '    "quoted": {\n'
            '      "command": "runner,}",\n'
            '      "args": ["literal,]"],\n'
            '      "env": {"PATTERN": "abc,}"},\n'
            "    },\n"
            '    "remote": {"url": "https://example.test/a,]"},\n'
            "  },\n"
            "}\n"
        )

        entries = connector_paths.mcp_servers("amp", workspace_dir=str(workspace))
        by_name = {entry.name: entry for entry in entries}

        assert by_name["quoted"].command == "runner,}"
        assert by_name["quoted"].args == ["literal,]"]
        assert by_name["quoted"].env == {"PATTERN": "abc,}"}
        assert by_name["remote"].url == "https://example.test/a,]"

    def test_amp_config_and_home_are_explicit_on_all_platforms(self, tmp_path, monkeypatch):
        fake_home = tmp_path / "profile"
        workspace = tmp_path / "repo"
        monkeypatch.setenv("HOME", str(fake_home))
        assert connector_paths.connector_home("amp") == str(fake_home / ".config" / "amp")
        assert connector_paths.connector_config_files("amp", workspace_dir=str(workspace)) == [
            str(fake_home / ".config" / "amp" / "settings.json"),
            str(fake_home / ".config" / "amp" / "settings.jsonc"),
            str(workspace / ".amp" / "settings.json"),
            str(workspace / ".amp" / "settings.jsonc"),
            connector_paths.amp_managed_settings_path(),
            str(fake_home / ".config" / "amp" / "plugins" / "defenseclaw.ts"),
        ]

    def test_amp_managed_settings_paths_are_platform_specific(self):
        assert connector_paths._resolve_amp_managed_settings_path(
            platform_name="posix",
            platform_id="darwin",
            program_data="",
        ) == "/Library/Application Support/ampcode/managed-settings.json"
        assert connector_paths._resolve_amp_managed_settings_path(
            platform_name="posix",
            platform_id="linux",
            program_data="",
        ) == "/etc/ampcode/managed-settings.json"
        assert connector_paths._resolve_amp_managed_settings_path(
            platform_name="nt",
            platform_id="win32",
            program_data=r"C:\ProgramData",
        ) == r"C:\ProgramData\ampcode\managed-settings.json"
        assert (
            connector_paths._resolve_amp_managed_settings_path(
                platform_name="nt",
                platform_id="win32",
                program_data="",
            )
            == ""
        )

    def test_amp_policy_settings_managed_override_and_rules_are_read_only_discovery(
        self,
        tmp_path,
        monkeypatch,
    ):
        fake_home = tmp_path / "home"
        workspace = fake_home / "src" / "repo"
        subtree = workspace / "service" / "api"
        managed_settings = tmp_path / "enterprise" / "managed-settings.json"
        (fake_home / ".config" / "amp").mkdir(parents=True)
        (workspace / ".amp").mkdir(parents=True)
        subtree.mkdir(parents=True)
        managed_settings.parent.mkdir()
        monkeypatch.setenv("HOME", str(fake_home))
        monkeypatch.setattr(
            connector_paths,
            "amp_managed_settings_path",
            lambda: str(managed_settings),
        )
        monkeypatch.setattr(
            connector_paths,
            "amp_managed_agents_path",
            lambda: str(managed_settings.parent / "AGENTS.md"),
        )
        (fake_home / ".config" / "amp" / "settings.json").write_text(
            json.dumps(
                {
                    "amp.permissions": [{"matches": {"tool": "Bash"}, "action": "ask"}],
                    "amp.dangerouslyAllowAll": True,
                }
            )
        )
        (workspace / ".amp" / "settings.json").write_text(
            json.dumps(
                {
                    "amp.guardedFiles.allowlist": ["README.md"],
                    "amp.dangerouslyAllowAll": True,
                }
            )
        )
        managed_settings.write_text(
            json.dumps(
                {
                    "amp.dangerouslyAllowAll": False,
                    "amp.mcpPermissions": [
                        {"matches": {"command": "*"}, "action": "reject"},
                    ],
                }
            )
        )
        (fake_home / "AGENT.md").write_text("home fallback")
        (workspace / "CLAUDE.md").write_text("workspace fallback")
        (subtree / "AGENTS.md").write_text("scoped")

        policy = connector_paths.connector_policy_settings(
            "amp",
            workspace_dir=str(workspace),
        )
        assert set(policy) == {
            "amp.permissions",
            "amp.guardedFiles.allowlist",
            "amp.dangerouslyAllowAll",
            "amp.mcpPermissions",
        }
        assert policy["amp.dangerouslyAllowAll"] is False

        paths = connector_paths.rule_paths(
            "amp",
            workspace_dir=str(workspace),
            target_path=os.path.join("service", "api", "handler.ts"),
        )
        assert str(fake_home / "AGENT.md") in paths
        assert str(workspace / "CLAUDE.md") in paths
        assert str(subtree / "AGENTS.md") in paths
        assert str(subtree / ".agents" / "checks") in paths
        assert str(managed_settings.parent / "AGENTS.md") in paths
        assert str(workspace / "AGENTS.md") not in paths

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

    def test_hermes_mcp_yaml_uses_bounded_utf8_decoding(self, tmp_path, monkeypatch):
        hermes_home = tmp_path / "hermes"
        hermes_home.mkdir()
        monkeypatch.setenv("HERMES_HOME", str(hermes_home))
        config = hermes_home / "config.yaml"
        config.write_bytes(
            "mcp:\n  servers:\n    display\u200f:\n      command: hermes-mcp\n".encode()
        )

        entries = connector_paths.mcp_servers("hermes")

        assert [(entry.name, entry.command) for entry in entries] == [
            ("display\u200f", "hermes-mcp")
        ]

        config.write_bytes(b"x" * (connector_paths._MCP_CONFIG_MAX_BYTES + 1))
        assert connector_paths.mcp_servers("hermes") == []

    def test_cursor_mcp_preserves_same_name_scope_candidates(self, tmp_path, monkeypatch):
        home = tmp_path / "home"
        workspace = tmp_path / "repo"
        monkeypatch.setenv("HOME", str(home))
        for path, command in (
            (workspace / ".cursor" / "mcp.json", "project-server"),
            (home / ".cursor" / "mcp.json", "user-server"),
        ):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps({"mcpServers": {"shared": {"command": command}}}))

        entries = connector_paths.mcp_servers("cursor", workspace_dir=str(workspace))

        assert [(entry.name, entry.command, entry.source_scope) for entry in entries] == [
            ("shared", "project-server", "project"),
            ("shared", "user-server", "user"),
        ]

    def test_cursor_agent_and_rule_roots_cover_compatibility_paths(self, tmp_path, monkeypatch):
        home = tmp_path / "home"
        workspace = tmp_path / "repo"
        monkeypatch.setenv("HOME", str(home))

        assert connector_paths.agent_dirs("cursor", workspace_dir=str(workspace)) == [
            str(workspace / ".cursor" / "agents"),
            str(workspace / ".claude" / "agents"),
            str(workspace / ".codex" / "agents"),
            str(home / ".cursor" / "agents"),
            str(home / ".claude" / "agents"),
            str(home / ".codex" / "agents"),
        ]
        assert connector_paths.rule_dirs("cursor", workspace_dir=str(workspace)) == [
            str(workspace / ".cursor" / "rules"),
        ]

    def test_windsurf_mcp_reads_only_persisted_bound_profile(
        self,
        tmp_path,
        monkeypatch,
    ):
        bound = tmp_path / "bound-profile"
        ambient = tmp_path / "ambient-profile"
        monkeypatch.setenv("WINDSURF_USER_HOME", str(bound))
        monkeypatch.setattr(Path, "home", lambda: ambient)

        for profile, name in ((bound, "bound"), (ambient, "ambient")):
            mcp = profile / ".codeium" / "windsurf" / "mcp_config.json"
            mcp.parent.mkdir(parents=True)
            mcp.write_text(
                json.dumps({"mcpServers": {name: {"command": f"{name}-mcp"}}}),
                encoding="utf-8",
            )
        guessed = bound / ".codeium" / "windsurf" / "mcp.json"
        guessed.write_text(
            json.dumps({"mcpServers": {"guessed": {"command": "guessed-mcp"}}}),
            encoding="utf-8",
        )

        entries = connector_paths.mcp_servers("windsurf")

        assert [(entry.name, entry.command) for entry in entries] == [
            ("bound", "bound-mcp")
        ]

    def test_windsurf_rule_discovery_covers_non_enterprise_cascade_sources(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        bound = tmp_path / "bound-profile"
        repo = tmp_path / "repo"
        workspace = repo / "packages" / "app"
        nested = workspace / "src" / "feature"
        (repo / ".git").mkdir(parents=True)
        nested.mkdir(parents=True)
        monkeypatch.setenv("WINDSURF_USER_HOME", str(bound))

        expected = [
            bound / ".codeium" / "windsurf" / "memories" / "global_rules.md",
            repo / "AGENTS.md",
            repo / ".devin" / "rules" / "preferred.md",
            workspace / ".windsurfrules",
            workspace / ".windsurf" / "rules" / "legacy.md",
            nested / "AgEnTs.Md",
            nested / ".devin" / "rules" / "nested.md",
        ]
        for path in expected:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("rule\n", encoding="utf-8")

        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "AGENTS.md").write_text("outside\n", encoding="utf-8")
        linked = workspace / "linked"
        try:
            linked.symlink_to(outside, target_is_directory=True)
        except OSError:
            linked = None

        discovered = connector_paths.windsurf_rule_files(str(workspace))

        assert set(discovered) == {str(path) for path in expected}
        if linked is not None:
            assert str(outside / "AGENTS.md") not in discovered
        assert all("ProgramData" not in path for path in discovered)

    def test_windsurf_rule_discovery_requires_an_explicit_workspace(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        bound = tmp_path / "bound-profile"
        ambient_workspace = tmp_path / "ambient-workspace"
        ambient_workspace.mkdir()
        (ambient_workspace / "AGENTS.md").write_text("ambient\n", encoding="utf-8")
        monkeypatch.setenv("WINDSURF_USER_HOME", str(bound))
        monkeypatch.chdir(ambient_workspace)

        assert connector_paths.windsurf_rule_files() == []

    def test_copilot_mcp_reads_ancestors_and_deduplicates_by_priority(
        self,
        tmp_path,
        monkeypatch,
    ):
        home = tmp_path / "home"
        copilot_home = home / "copilot"
        repo = tmp_path / "repo"
        package = repo / "packages" / "service"
        package.mkdir(parents=True)
        (repo / ".git").mkdir()
        monkeypatch.setenv("HOME", str(home))
        monkeypatch.setenv("USERPROFILE", str(home))
        monkeypatch.setenv("COPILOT_HOME", str(copilot_home))

        sources = (
            (
                package / ".mcp.json",
                {
                    "shared": {"command": "package"},
                    "package-only": {"command": "package-only"},
                },
            ),
            (
                repo / ".github" / "mcp.json",
                {
                    "shared": {"command": "repo"},
                    "repo-only": {"command": "repo-only"},
                },
            ),
            (
                copilot_home / "mcp-config.json",
                {
                    "shared": {"command": "user"},
                    "user-only": {"command": "user-only"},
                },
            ),
        )
        for path, servers in sources:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps({"mcpServers": servers}))

        entries = connector_paths.mcp_servers("copilot", workspace_dir=str(package))
        by_name = {entry.name: entry for entry in entries}

        assert set(by_name) == {"shared", "package-only", "repo-only", "user-only"}
        assert by_name["shared"].command == "package"

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

    def test_codex_merges_user_and_project_config_toml(
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
        self._write_codex_config(
            cwd,
            {
                "local-search": {"command": "search-mcp"},
            },
        )
        monkeypatch.chdir(cwd)

        entries = connector_paths.mcp_servers("codex", workspace_dir=str(cwd))
        names = sorted(e.name for e in entries)
        assert names == ["global-fs", "local-search"]

    def test_codex_malformed_user_config_does_not_hide_project_config(
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
        self._write_codex_config(
            cwd,
            {
                "local-search": {"command": "search-mcp"},
            },
        )
        monkeypatch.chdir(cwd)

        # Malformed user TOML must not hide a valid higher-precedence
        # project layer.
        entries = connector_paths.mcp_servers("codex", workspace_dir=str(cwd))
        assert [e.name for e in entries] == ["local-search"]

    def test_codex_unsafe_project_config_continues_to_user_layer(
        self,
        tmp_path,
        monkeypatch,
    ):
        fake_home = tmp_path / "home"
        codex_dir = fake_home / ".codex"
        codex_dir.mkdir(parents=True)
        user_config = codex_dir / "config.toml"
        user_config.write_text('[mcp_servers.user]\ncommand = "user-mcp"\n')
        monkeypatch.setenv("HOME", str(fake_home))
        project = tmp_path / "project"
        project.mkdir()
        project_config = self._write_codex_config(
            project,
            {"unsafe": {"command": "unsafe-mcp"}},
        )
        real_read = connector_paths._read_bounded_stable_file

        def reject_project(path, *, max_bytes):
            if os.path.normcase(os.path.abspath(path)) == os.path.normcase(str(project_config)):
                raise OSError("mocked Windows reparse/replacement race")
            return real_read(path, max_bytes=max_bytes)

        monkeypatch.setattr(connector_paths, "_read_bounded_stable_file", reject_project)

        entries = connector_paths.mcp_servers("codex", workspace_dir=str(project))

        assert [entry.name for entry in entries] == ["user"]

    def test_codex_project_mcp_layers_use_closest_first_precedence(
        self,
        tmp_path,
        monkeypatch,
    ):
        fake_home = tmp_path / "home"
        fake_home.mkdir()
        (fake_home / ".codex").mkdir()
        (fake_home / ".codex" / "config.toml").write_text(
            '[mcp_servers.shared]\ncommand = "user"\n'
        )
        monkeypatch.setenv("HOME", str(fake_home))

        repo = tmp_path / "repo"
        active = repo / "services" / "api"
        active.mkdir(parents=True)
        (repo / ".git").mkdir()
        self._write_codex_config(repo, {"shared": {"command": "root"}, "root-only": {"command": "root"}})
        self._write_codex_config(active, {"shared": {"command": "closest"}})

        entries = connector_paths.mcp_servers("codex", workspace_dir=str(active))

        assert [entry.name for entry in entries] == ["shared", "root-only"]
        assert entries[0].command == "closest"
        assert entries[0].source == str(active / ".codex" / "config.toml")
        assert entries[0].source_scope == "project"
        assert entries[0].trust_required is True

    def test_claudecode_merges_user_state_and_dotmcp_without_duplicates(
        self,
        tmp_path,
        monkeypatch,
    ):
        fake_home = tmp_path / "home"
        fake_home.mkdir()
        _pin_claude_home(monkeypatch, fake_home)
        (fake_home / ".claude.json").write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "shared": {"command": "user-command"},
                        "from-user-state": {"command": "x"},
                    },
                }
            )
        )

        cwd = tmp_path / "project"
        cwd.mkdir()
        self._write_mcp_json(
            cwd,
            {
                "shared": {"command": "project-command"},
                "from-mcp-json": {"command": "y"},
            },
        )
        monkeypatch.chdir(cwd)

        entries = connector_paths.mcp_servers("claudecode", workspace_dir=str(cwd))
        names = [entry.name for entry in entries]
        assert names == ["shared", "from-mcp-json", "from-user-state"]
        assert next(entry for entry in entries if entry.name == "shared").command == "project-command"

    def test_claudecode_local_project_user_precedence_and_workspace_attribution(
        self,
        tmp_path,
        monkeypatch,
    ):
        fake_home = tmp_path / "home"
        fake_home.mkdir()
        _pin_claude_home(monkeypatch, fake_home)
        workspace = tmp_path / "project" / ".." / "project"
        workspace.resolve().mkdir(parents=True)
        other_workspace = tmp_path / "other-project"
        other_workspace.mkdir()
        state_workspace_key = os.path.join(str(tmp_path), "project", ".")

        (fake_home / ".claude.json").write_text(
            json.dumps(
                {
                    "projects": {
                        state_workspace_key: {
                            "mcpServers": {
                                "shared": {"command": "local-command"},
                                "local-only": {"command": "local-only-command"},
                            }
                        },
                        str(other_workspace): {
                            "mcpServers": {
                                "other-local": {"command": "must-not-appear"},
                            }
                        },
                    },
                    "mcpServers": {
                        "shared": {"command": "user-command"},
                        "user-only": {"command": "user-only-command"},
                    },
                }
            )
        )
        self._write_mcp_json(
            workspace.resolve(),
            {
                "shared": {"command": "project-command"},
                "project-only": {"command": "project-only-command"},
            },
        )

        entries = connector_paths.mcp_servers(
            "claudecode",
            workspace_dir=str(workspace),
        )
        assert [entry.name for entry in entries] == [
            "shared",
            "local-only",
            "project-only",
            "user-only",
        ]
        assert entries[0].command == "local-command"
        assert all(entry.name != "other-local" for entry in entries)

    def test_claudecode_does_not_infer_local_scope_from_process_cwd(
        self,
        tmp_path,
        monkeypatch,
    ):
        fake_home = tmp_path / "home"
        fake_home.mkdir()
        _pin_claude_home(monkeypatch, fake_home)
        workspace = tmp_path / "project"
        workspace.mkdir()
        monkeypatch.chdir(workspace)
        (fake_home / ".claude.json").write_text(
            json.dumps(
                {
                    "projects": {
                        str(workspace): {
                            "mcpServers": {
                                "local-only": {"command": "must-not-appear"},
                            }
                        }
                    },
                    "mcpServers": {
                        "user-only": {"command": "user-command"},
                    },
                }
            )
        )

        entries = connector_paths.mcp_servers("claudecode")
        assert [entry.name for entry in entries] == ["user-only"]

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

    def test_custom_config_layers_last_and_overrides_same_name(self, tmp_path, monkeypatch):
        home = tmp_path / "home"
        home.mkdir()
        monkeypatch.setenv("HOME", str(home))
        self._write_global(
            home,
            {
                "shared": {"type": "local", "command": ["global-command"]},
                "global-only": {"type": "local", "command": ["global-only-command"]},
            },
        )
        workspace = tmp_path / "ws"
        workspace.mkdir()
        (workspace / "opencode.json").write_text(
            json.dumps({"mcp": {"shared": {"type": "local", "command": ["project-command"]}}})
        )
        custom = tmp_path / "custom-opencode"
        custom.mkdir()
        (custom / "opencode.jsonc").write_text(
            json.dumps({"mcp": {"shared": {"type": "local", "command": ["custom-command"]}}})
        )
        monkeypatch.setenv("OPENCODE_CONFIG_DIR", str(custom))

        entries = {
            entry.name: entry
            for entry in connector_paths.mcp_servers("opencode", workspace_dir=str(workspace))
        }

        assert set(entries) == {"shared", "global-only"}
        assert entries["shared"].command == "custom-command"

    def test_v11810_precedence_content_disabled_and_provenance(self, tmp_path, monkeypatch):
        home = tmp_path / "home"
        home.mkdir()
        monkeypatch.setenv("HOME", str(home))
        global_dir = home / ".config" / "opencode"
        global_dir.mkdir(parents=True)
        (global_dir / "config.json").write_text(
            json.dumps({"mcp": {"shared": {"type": "local", "command": ["global"]}}}),
        )
        explicit = tmp_path / "explicit.jsonc"
        explicit.write_text(
            '// exact OPENCODE_CONFIG layer\n{"mcp":{"shared":{"command":["explicit"]}}}',
        )
        monkeypatch.setenv("OPENCODE_CONFIG", str(explicit))
        workspace = tmp_path / "workspace"
        (workspace / ".opencode").mkdir(parents=True)
        (workspace / "opencode.json").write_text(
            json.dumps({"mcp": {"shared": {"command": ["project"]}}}),
        )
        (workspace / ".opencode" / "opencode.jsonc").write_text(
            json.dumps({"mcp": {"shared": {"command": ["project-directory"]}}}),
        )
        home_component = home / ".opencode"
        home_component.mkdir()
        (home_component / "opencode.json").write_text(
            json.dumps({"mcp": {"shared": {"command": ["home-directory"]}}}),
        )
        custom = tmp_path / "custom"
        custom.mkdir()
        (custom / "opencode.json").write_text(
            json.dumps({"mcp": {"shared": {"command": ["custom-directory"]}}}),
        )
        monkeypatch.setenv("OPENCODE_CONFIG_DIR", str(custom))
        monkeypatch.setenv(
            "OPENCODE_CONFIG_CONTENT",
            json.dumps({"mcp": {"shared": {"enabled": False}}}),
        )

        entries = connector_paths.mcp_servers("opencode", workspace_dir=str(workspace))

        assert len(entries) == 1
        assert entries[0].command == "custom-directory"
        assert entries[0].disabled is True
        assert entries[0].source == "OPENCODE_CONFIG_CONTENT"
        assert entries[0].source_scope == "inline"

        resolution = connector_paths._resolve_opencode_config(str(workspace))
        first_scope = {}
        for index, layer in enumerate(resolution.layers):
            first_scope.setdefault(layer.source_scope, index)
        assert first_scope["project-directory"] < first_scope["home-directory"]
        assert first_scope["home-directory"] < first_scope["custom-directory"]
        assert first_scope["custom-directory"] < first_scope["inline"]

    def test_resolver_types_remote_and_programdata_as_unverified(self, tmp_path, monkeypatch):
        home = tmp_path / "home"
        home.mkdir()
        monkeypatch.setenv("HOME", str(home))

        resolution = connector_paths._resolve_opencode_config()

        unverified = {(item.source_scope, item.source) for item in resolution.unverified}
        assert ("remote", "authenticated .well-known/opencode") in unverified
        assert ("managed-enterprise", "Windows ProgramData managed config") in unverified
        assert all("ProgramData" not in layer.path for layer in resolution.layers)

    def test_inline_content_refuses_non_authoritative_write(self, tmp_path, monkeypatch):
        home = tmp_path / "home"
        home.mkdir()
        monkeypatch.setenv("HOME", str(home))
        monkeypatch.setenv("OPENCODE_CONFIG_CONTENT", '{"mcp":{}}')

        with pytest.raises(connector_paths.MCPWriteUnsupportedError, match="inline"):
            connector_paths._set_opencode_mcp_server(
                "demo",
                {"command": "demo"},
            )

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
            ("copilot", "COPILOT_HOME", "custom-copilot", "settings.json"),
        ],
    )
    def test_clients_honor_client_home_overrides(
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

    def test_claude_mcp_state_honors_config_override(self, monkeypatch, tmp_path):
        configured = tmp_path / "custom-claude"
        monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(configured))

        assert connector_paths.claude_mcp_state_path() == str(configured / ".claude.json")
        assert str(configured / ".claude.json") in connector_paths.connector_config_files("claudecode")

    def test_claude_paths_default_to_platform_home_without_override(self, monkeypatch, tmp_path):
        home = tmp_path / "claude-home"
        _pin_claude_home(monkeypatch, home)

        assert connector_paths.claude_config_dir() == str(home / ".claude")
        assert connector_paths.claude_mcp_state_path() == str(home / ".claude.json")

    def test_claude_settings_paths_are_separate_and_scope_ordered(self, monkeypatch, tmp_path):
        home = tmp_path / "claude-home"
        workspace = tmp_path / "workspace"
        _pin_claude_home(monkeypatch, home)

        assert connector_paths.claude_settings_paths(str(workspace)) == [
            str(home / ".claude" / "settings.json"),
            str(workspace / ".claude" / "settings.json"),
            str(workspace / ".claude" / "settings.local.json"),
        ]

    def test_opencode_home_is_xdg_config(self, monkeypatch, tmp_path):
        monkeypatch.setenv("HOME", str(tmp_path))
        assert connector_paths.connector_home("opencode") == os.path.join(str(tmp_path), ".config", "opencode")

    def test_opencode_home_and_managed_plugin_honor_config_override(self, monkeypatch, tmp_path):
        configured = tmp_path / "custom-opencode"
        monkeypatch.setenv("OPENCODE_CONFIG_DIR", str(configured))

        assert connector_paths.connector_home("opencode") == str(configured)
        assert connector_paths.connector_config_files("opencode") == [str(configured / "plugins" / "defenseclaw.js")]

    def test_antigravity_home(self, monkeypatch, tmp_path):
        monkeypatch.setenv("HOME", str(tmp_path))
        assert connector_paths.connector_home("antigravity") == os.path.join(
            str(tmp_path), ".gemini", "config"
        )

    def test_antigravity_home_ignores_undocumented_config_overrides(self, monkeypatch, tmp_path):
        configured = tmp_path / "custom-antigravity"
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.setenv("ANTIGRAVITY_CONFIG_DIR", str(configured))
        monkeypatch.setenv("GEMINI_CONFIG_DIR", str(configured / "gemini"))

        official = tmp_path / ".gemini" / "config"
        assert connector_paths.connector_home("antigravity") == str(official)
        assert connector_paths.connector_config_files("antigravity") == [
            str(official / "mcp_config.json"),
            str(official / "hooks.json"),
        ]

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
        local_app_data = r"C:\Users\kevin\AppData\Local"

        resolved = connector_paths._resolve_hermes_home(
            platform_name="nt",
            user_home=str(home),
            local_app_data=local_app_data,
            override="",
        )

        assert resolved == ntpath.join(local_app_data, "hermes")

    def test_windows_explicit_absolute_hermes_home_remains_supported(self, tmp_path):
        configured = r"C:\Users\kevin\Hermes Current"

        resolved = connector_paths._resolve_hermes_home(
            platform_name="nt",
            user_home=str(tmp_path / "legacy-home"),
            local_app_data=r"C:\Users\kevin\AppData\Local",
            override=configured,
        )

        assert resolved == configured

    @pytest.mark.parametrize(
        "override,local_app_data,error",
        [
            ("relative-hermes", r"C:\Users\kevin\AppData\Local", "HERMES_HOME"),
            ("", "relative-local-app-data", "LocalAppData"),
        ],
    )
    def test_windows_rejects_relative_hermes_roots(
        self,
        tmp_path,
        override,
        local_app_data,
        error,
    ):
        with pytest.raises(ValueError, match=error):
            connector_paths._resolve_hermes_home(
                platform_name="nt",
                user_home=str(tmp_path / "legacy-home"),
                local_app_data=local_app_data,
                override=override,
            )

    def test_non_windows_preserves_dot_hermes_default(self, tmp_path):
        home = tmp_path / "home"

        resolved = connector_paths._resolve_hermes_home(
            platform_name="posix",
            user_home=str(home),
            local_app_data=str(tmp_path / "ignored"),
            override="",
        )

        assert resolved == str(home / ".hermes")

    def test_windows_without_token_local_app_data_never_falls_back_to_legacy_home(
        self,
        tmp_path,
        monkeypatch,
    ):
        home = tmp_path / "home"
        monkeypatch.setattr(
            connector_paths.os.path,
            "abspath",
            lambda _path: pytest.fail("Windows resolver consulted a cwd-derived path"),
        )

        with pytest.raises(ValueError, match="LocalAppData"):
            connector_paths._resolve_hermes_home(
                platform_name="nt",
                user_home=str(home),
                local_app_data="",
                override="",
            )

# ---------------------------------------------------------------------------
# Round-trip via Config.skill_dirs / plugin_dirs / mcp_servers
# ---------------------------------------------------------------------------


class TestConnectorConfigFiles:
    """N2 — ``connector_config_files`` must point at the file the connector
    actually writes, not a phantom path."""

    def test_codex_lists_every_project_config_layer_not_dotmcp(self, tmp_path, monkeypatch):
        fake_home = tmp_path / "home"
        fake_home.mkdir()
        monkeypatch.setenv("HOME", str(fake_home))
        repo = tmp_path / "repo"
        active = repo / "nested"
        active.mkdir(parents=True)
        (repo / ".git").mkdir()

        files = connector_paths.connector_config_files("codex", workspace_dir=str(active))

        assert files == [
            str(fake_home / ".codex" / "config.toml"),
            str(active / ".codex" / "config.toml"),
            str(repo / ".codex" / "config.toml"),
            str(repo / ".agents" / "plugins" / "marketplace.json"),
            str(repo / ".claude-plugin" / "marketplace.json"),
            str(fake_home / ".agents" / "plugins" / "marketplace.json"),
        ]
        assert not any(path.endswith(".mcp.json") for path in files)

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
        assert os.path.join(str(fake_home), ".gemini", "config", "hooks.json") in files
        assert not any("antigravity-cli" in path for path in files)

    def test_omnigent_honors_config_home(self, tmp_path, monkeypatch):
        config_home = tmp_path / "isolated-omnigent"
        monkeypatch.delenv("OMNIGENT_CONFIG", raising=False)
        monkeypatch.setenv("OMNIGENT_CONFIG_HOME", str(config_home))

        assert connector_paths.omnigent_config_path() == str(config_home / "config.yaml")
        assert connector_paths.connector_home("omnigent") == str(config_home)
        assert connector_paths.connector_config_files("omnigent") == [str(config_home / "config.yaml")]

    def test_omnigent_relative_config_home_is_resolved_consistently(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        monkeypatch.delenv("OMNIGENT_CONFIG", raising=False)
        monkeypatch.setenv("OMNIGENT_CONFIG_HOME", "relative-omnigent")
        config_home = tmp_path / "relative-omnigent"

        assert connector_paths.omnigent_config_path() == str(config_home / "config.yaml")
        assert connector_paths.connector_home("omnigent") == str(config_home)

    def test_omnigent_explicit_config_path_takes_precedence(self, tmp_path, monkeypatch):
        config_path = tmp_path / "explicit" / "server.yaml"
        monkeypatch.setenv("OMNIGENT_CONFIG", str(config_path))
        monkeypatch.setenv("OMNIGENT_CONFIG_HOME", str(tmp_path / "ignored-home"))

        assert connector_paths.omnigent_config_path() == str(config_path)
        assert connector_paths.connector_config_files("omnigent") == [str(config_path)]

    @pytest.mark.parametrize(
        ("connector", "variable", "directory", "file_name"),
        [
            ("codex", "CODEX_HOME", "codex-home", "config.toml"),
            ("claudecode", "CLAUDE_CONFIG_DIR", "claude-home", ".claude.json"),
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
        assert os.path.join(home, ".agents", "skills") in dirs

    def test_config_plugin_dirs_uses_active_connector(self):
        from defenseclaw import config

        cfg = config.default_config()
        cfg.guardrail.connector = "claudecode"
        dirs = cfg.plugin_dirs()
        home = str(Path.home())
        assert os.path.join(home, ".claude", "plugins", "cache") in dirs
        assert os.path.join(home, ".claude", "skills") in dirs

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
