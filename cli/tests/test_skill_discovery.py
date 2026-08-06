# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Security and compatibility tests for shared skill discovery."""

from __future__ import annotations

import os
from types import SimpleNamespace

import defenseclaw.skill_discovery as skill_discovery_module
import pytest
from defenseclaw.skill_discovery import discover_skill_directories

from tests.environment import requires_symlink_privilege


def test_copilot_markdown_commands_are_stable_alternative_skills(tmp_path, monkeypatch) -> None:
    commands = tmp_path / ".claude" / "commands"
    commands.mkdir(parents=True)
    (commands / "review.md").write_text("review safely", encoding="utf-8")
    (commands / "000-ignored.txt").write_text("not a command", encoding="utf-8")
    monkeypatch.setattr(skill_discovery_module, "_COPILOT_COMMAND_FILE_LIMIT", 1)

    discovered = discover_skill_directories(os.fspath(commands), connector="copilot")

    assert [(entry.name, entry.path) for entry in discovered] == [
        ("review", os.fspath(commands / "review.md"))
    ]


@requires_symlink_privilege
def test_copilot_markdown_commands_reject_linked_files(tmp_path) -> None:
    commands = tmp_path / ".claude" / "commands"
    commands.mkdir(parents=True)
    outside = tmp_path / "outside.md"
    outside.write_text("outside", encoding="utf-8")
    os.symlink(outside, commands / "linked.md")

    assert discover_skill_directories(os.fspath(commands), connector="copilot") == []


@requires_symlink_privilege
def test_codex_system_child_rejects_symlinked_marker(tmp_path) -> None:
    system_root = tmp_path / ".system"
    skill = system_root / "linked-marker"
    skill.mkdir(parents=True)
    real_marker = tmp_path / "outside.md"
    real_marker.write_text("# outside", encoding="utf-8")
    os.symlink(real_marker, skill / "SKILL.md")

    discovered = discover_skill_directories(os.fspath(tmp_path), connector="codex")

    assert "linked-marker" not in {entry.name for entry in discovered}


@requires_symlink_privilege
def test_skill_discovery_rejects_linked_root(tmp_path) -> None:
    actual_root = tmp_path / "actual-skills"
    skill = actual_root / "outside"
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_text("# outside", encoding="utf-8")
    linked_root = tmp_path / "linked-skills"
    linked_root.symlink_to(actual_root, target_is_directory=True)

    assert discover_skill_directories(
        os.fspath(linked_root),
        connector="codex",
    ) == []


@requires_symlink_privilege
def test_codex_system_container_rejects_linked_ancestry(tmp_path) -> None:
    outside_system = tmp_path / "outside-system"
    skill = outside_system / "outside"
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_text("# outside", encoding="utf-8")
    (tmp_path / ".system").symlink_to(
        outside_system,
        target_is_directory=True,
    )

    assert discover_skill_directories(
        os.fspath(tmp_path),
        connector="codex",
    ) == []


@requires_symlink_privilege
def test_skill_discovery_rejects_linked_child(tmp_path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "SKILL.md").write_text("# outside", encoding="utf-8")
    root = tmp_path / "skills"
    root.mkdir()
    (root / "linked").symlink_to(outside, target_is_directory=True)

    assert discover_skill_directories(
        os.fspath(root),
        connector="codex",
    ) == []


def test_codex_system_container_rejects_windows_reparse_attribute(
    tmp_path,
    monkeypatch,
) -> None:
    system_root = tmp_path / ".system"
    skill = system_root / "bundled"
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_text("# bundled", encoding="utf-8")
    real_stat = os.stat
    system_key = os.path.normcase(os.path.abspath(system_root))

    def stat_with_reparse(path, *args, **kwargs):
        info = real_stat(path, *args, **kwargs)
        if os.path.normcase(os.path.abspath(path)) != system_key:
            return info
        return SimpleNamespace(
            st_mode=info.st_mode,
            st_dev=info.st_dev,
            st_ino=info.st_ino,
            st_size=info.st_size,
            st_mtime_ns=info.st_mtime_ns,
            st_ctime_ns=info.st_ctime_ns,
            st_file_attributes=0x400,
        )

    monkeypatch.setattr(skill_discovery_module.os, "stat", stat_with_reparse)

    assert discover_skill_directories(
        os.fspath(tmp_path),
        connector="codex",
    ) == []


def test_codex_system_child_keeps_regular_marker(tmp_path) -> None:
    skill = tmp_path / ".system" / "legitimate"
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_text("# legitimate", encoding="utf-8")

    discovered = discover_skill_directories(os.fspath(tmp_path), connector="codex")

    assert [(entry.name, entry.path, entry.bundled) for entry in discovered] == [
        ("legitimate", os.fspath(skill), True),
    ]


def test_claude_skills_directory_plugin_is_not_a_plain_skill(tmp_path) -> None:
    plain = tmp_path / "plain"
    plain.mkdir()
    (plain / "SKILL.md").write_text("# plain", encoding="utf-8")
    plugin = tmp_path / "storage-name"
    manifest = plugin / ".claude-plugin" / "plugin.json"
    manifest.parent.mkdir(parents=True)
    manifest.write_text('{"name":"semantic-name"}', encoding="utf-8")
    (plugin / "SKILL.md").write_text("# plugin skill", encoding="utf-8")

    discovered = discover_skill_directories(
        os.fspath(tmp_path),
        connector="claudecode",
    )

    assert [(entry.name, entry.path) for entry in discovered] == [
        ("plain", os.fspath(plain)),
    ]


def test_claude_legacy_command_markdown_is_discovered_as_a_skill(tmp_path) -> None:
    commands = tmp_path / ".claude" / "commands"
    commands.mkdir(parents=True)
    command = commands / "deploy.md"
    command.write_text("# Deploy\n", encoding="utf-8")
    (commands / "ignored.txt").write_text("ignored\n", encoding="utf-8")

    entries = discover_skill_directories(
        str(commands),
        connector="claudecode",
    )

    assert [(entry.name, entry.path) for entry in entries] == [
        ("deploy", str(command))
    ]


def test_claudecode_follows_and_deduplicates_skill_directory_symlinks(
    tmp_path,
) -> None:
    root = tmp_path / "skills"
    target = tmp_path / "shared-skill"
    root.mkdir()
    target.mkdir()
    (target / "SKILL.md").write_text("# Shared\n", encoding="utf-8")
    try:
        (root / "first").symlink_to(target, target_is_directory=True)
        (root / "second").symlink_to(target, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"directory symlinks unavailable: {exc}")

    discovered = discover_skill_directories(str(root), connector="claudecode")

    assert len(discovered) == 1
    assert discovered[0].path == str(target)
