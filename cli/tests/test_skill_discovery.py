# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Security and compatibility tests for shared skill discovery."""

from __future__ import annotations

import os
from types import SimpleNamespace

import defenseclaw.skill_discovery as skill_discovery_module
import pytest
from defenseclaw.hermes_skills import directory_md5, is_bundled_skill_path
from defenseclaw.skill_discovery import discover_skill_directories

from tests.environment import requires_symlink_privilege


def _codex_skill_root(tmp_path, monkeypatch):
    codex_home = tmp_path / "codex-home"
    root = codex_home / "skills"
    root.mkdir(parents=True)
    monkeypatch.setenv("CODEX_HOME", os.fspath(codex_home))
    return root


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
def test_codex_system_child_rejects_symlinked_marker(tmp_path, monkeypatch) -> None:
    root = _codex_skill_root(tmp_path, monkeypatch)
    system_root = root / ".system"
    skill = system_root / "linked-marker"
    skill.mkdir(parents=True)
    real_marker = tmp_path / "outside.md"
    real_marker.write_text("# outside", encoding="utf-8")
    os.symlink(real_marker, skill / "SKILL.md")

    discovered = discover_skill_directories(os.fspath(root), connector="codex")

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
def test_codex_system_container_rejects_linked_ancestry(tmp_path, monkeypatch) -> None:
    root = _codex_skill_root(tmp_path, monkeypatch)
    outside_system = tmp_path / "outside-system"
    skill = outside_system / "outside"
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_text("# outside", encoding="utf-8")
    (root / ".system").symlink_to(
        outside_system,
        target_is_directory=True,
    )

    assert discover_skill_directories(
        os.fspath(root),
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
    root = _codex_skill_root(tmp_path, monkeypatch)
    system_root = root / ".system"
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
        os.fspath(root),
        connector="codex",
    ) == []


def test_codex_system_child_keeps_regular_marker(tmp_path, monkeypatch) -> None:
    root = _codex_skill_root(tmp_path, monkeypatch)
    skill = root / ".system" / "legitimate"
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_text("# legitimate", encoding="utf-8")

    discovered = discover_skill_directories(os.fspath(root), connector="codex")

    assert [(entry.name, entry.path, entry.bundled) for entry in discovered] == [
        ("legitimate", os.fspath(skill), True),
    ]


def test_codex_arbitrary_system_directory_is_not_bundled(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("CODEX_HOME", os.fspath(tmp_path / "real-codex-home"))
    root = tmp_path / "workspace-skills"
    skill = root / ".system" / "operator-skill"
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_text("# operator controlled", encoding="utf-8")

    discovered = discover_skill_directories(os.fspath(root), connector="codex")

    assert [(entry.name, entry.path, entry.bundled) for entry in discovered] == [
        ("operator-skill", os.fspath(skill), False),
    ]


def test_hermes_nested_manifest_provenance_distinguishes_vendor_and_user_skills(
    tmp_path,
    monkeypatch,
) -> None:
    hermes_home = tmp_path / "hermes-home"
    root = hermes_home / "skills"
    bundled = root / "productivity" / "vendor-docs"
    modified = root / "software-development" / "modified-vendor"
    forged = root / "productivity" / "manifest-only"
    user = root / "operator-skill"
    for path, name in (
        (bundled, "vendor-docs"),
        (modified, "modified-vendor"),
        (forged, "manifest-only"),
        (user, "operator-skill"),
    ):
        path.mkdir(parents=True)
        (path / "SKILL.md").write_text(
            f"---\nname: {name}\ndescription: test\n---\n",
            encoding="utf-8",
        )

    source_root = hermes_home / "hermes-agent" / "skills"
    for relative, name in (
        (bundled.relative_to(root), "vendor-docs"),
        (modified.relative_to(root), "modified-vendor"),
    ):
        source = source_root / relative
        source.mkdir(parents=True)
        (source / "SKILL.md").write_text(
            f"---\nname: {name}\ndescription: test\n---\n",
            encoding="utf-8",
        )

    bundled_hash = directory_md5(os.fspath(bundled))
    modified_hash = directory_md5(os.fspath(modified))
    forged_hash = directory_md5(os.fspath(forged))
    assert bundled_hash and modified_hash and forged_hash
    (root / ".bundled_manifest").write_text(
        f"vendor-docs:{bundled_hash}\n"
        f"modified-vendor:{modified_hash}\n"
        f"manifest-only:{forged_hash}\n",
        encoding="utf-8",
    )
    (modified / "SKILL.md").write_text(
        "---\nname: modified-vendor\n---\noperator changed this\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("HERMES_HOME", os.fspath(hermes_home))

    discovered = discover_skill_directories(os.fspath(root), connector="hermes")

    by_name = {entry.name: entry for entry in discovered}
    assert set(by_name) == {
        "manifest-only",
        "modified-vendor",
        "operator-skill",
        "vendor-docs",
    }
    assert by_name["vendor-docs"].path == os.fspath(bundled)
    assert by_name["vendor-docs"].bundled
    assert not by_name["modified-vendor"].bundled
    assert not by_name["manifest-only"].bundled
    assert not by_name["operator-skill"].bundled
    assert is_bundled_skill_path(os.fspath(bundled / "SKILL.md"))
    assert not is_bundled_skill_path(os.fspath(modified))
    assert not is_bundled_skill_path(os.fspath(forged))
    assert not is_bundled_skill_path(os.fspath(user))


def test_hermes_tree_hash_fails_open_when_content_exceeds_bounds(
    tmp_path,
    monkeypatch,
) -> None:
    import defenseclaw.hermes_skills as hermes_skills

    skill = tmp_path / "oversized"
    skill.mkdir()
    (skill / "SKILL.md").write_bytes(b"12345")

    monkeypatch.setattr(hermes_skills, "_SKILL_FILE_MAX_BYTES", 4)
    assert directory_md5(os.fspath(skill)) is None

    monkeypatch.setattr(hermes_skills, "_SKILL_FILE_MAX_BYTES", 10)
    monkeypatch.setattr(hermes_skills, "_SKILL_TREE_MAX_BYTES", 4)
    assert directory_md5(os.fspath(skill)) is None


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
