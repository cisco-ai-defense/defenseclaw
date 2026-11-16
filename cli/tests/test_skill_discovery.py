# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Security and compatibility tests for shared skill discovery."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from types import SimpleNamespace

import defenseclaw.skill_discovery as skill_discovery_module
import pytest
from defenseclaw.hermes_skills import _tree_sha256, is_bundled_skill_path
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


def test_hermes_nested_pinned_provenance_distinguishes_vendor_and_user_skills(
    tmp_path,
    monkeypatch,
) -> None:
    hermes_home = tmp_path / "hermes-home"
    root = hermes_home / "skills"
    bundled = root / "media" / "songsee"
    modified = root / "software-development" / "modified-vendor"
    forged = root / "productivity" / "manifest-only"
    user = root / "operator-skill"
    for path, name in (
        (modified, "modified-vendor"),
        (forged, "manifest-only"),
        (user, "operator-skill"),
    ):
        path.mkdir(parents=True)
        (path / "SKILL.md").write_text(
            f"---\nname: {name}\ndescription: test\n---\n",
            encoding="utf-8",
        )

    bundled.mkdir(parents=True)
    vendor_marker = (
        Path(__file__).resolve().parents[2]
        / "internal/hermesskills/testdata/vendor/media/songsee/SKILL.md"
    ).read_bytes()
    (bundled / "SKILL.md").write_bytes(vendor_marker)

    source_root = hermes_home / "hermes-agent" / "skills"
    for relative, name in (
        (modified.relative_to(root), "modified-vendor"),
    ):
        source = source_root / relative
        source.mkdir(parents=True)
        (source / "SKILL.md").write_text(
            f"---\nname: {name}\ndescription: test\n---\n",
            encoding="utf-8",
        )

    def manifest_hash(path: Path) -> str:
        return hashlib.md5(b"SKILL.md" + (path / "SKILL.md").read_bytes()).hexdigest()

    (root / ".bundled_manifest").write_text(
        f"modified-vendor:{manifest_hash(modified)}\n"
        f"manifest-only:{manifest_hash(forged)}\n",
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
        "songsee",
    }
    assert by_name["songsee"].path == os.fspath(bundled)
    assert by_name["songsee"].bundled
    assert not by_name["modified-vendor"].bundled
    assert not by_name["manifest-only"].bundled
    assert not by_name["operator-skill"].bundled
    assert is_bundled_skill_path(os.fspath(bundled / "SKILL.md"))
    assert not is_bundled_skill_path(os.fspath(modified))
    assert not is_bundled_skill_path(os.fspath(forged))
    assert not is_bundled_skill_path(os.fspath(user))
    (bundled / "SKILL.md").write_bytes(vendor_marker + b"\nlocal change\n")
    assert not is_bundled_skill_path(os.fspath(bundled))


def test_hermes_tree_hash_fails_open_when_content_exceeds_bounds(
    tmp_path,
    monkeypatch,
) -> None:
    import defenseclaw.hermes_skills as hermes_skills

    skill = tmp_path / "oversized"
    skill.mkdir()
    (skill / "SKILL.md").write_bytes(b"12345")

    monkeypatch.setattr(hermes_skills, "_SKILL_FILE_MAX_BYTES", 4)
    assert _tree_sha256(os.fspath(skill)) is None

    monkeypatch.setattr(hermes_skills, "_SKILL_FILE_MAX_BYTES", 10)
    monkeypatch.setattr(hermes_skills, "_SKILL_TREE_MAX_BYTES", 4)
    assert _tree_sha256(os.fspath(skill)) is None


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
    assert discovered[0].aliases == ("second",)


@requires_symlink_privilege
def test_claudecode_real_folder_names_the_skill_and_its_links_are_aliases(
    tmp_path,
) -> None:
    """A link that sorts first must not hide the folder it points at."""
    root = tmp_path / "skills"
    folder = root / "zeta-skill"
    folder.mkdir(parents=True)
    (folder / "SKILL.md").write_text("# Zeta\n", encoding="utf-8")
    (root / "alpha-link").symlink_to(folder, target_is_directory=True)

    discovered = discover_skill_directories(str(root), connector="claudecode")

    assert [(d.name, d.path, d.aliases) for d in discovered] == [
        ("zeta-skill", os.path.realpath(folder), ("alpha-link",))
    ]


def test_claudecode_commands_folder_keeps_precedence_over_same_stem_markdown(
    tmp_path,
) -> None:
    """The sorted walk order decides a folder/Markdown name collision."""
    root = tmp_path / ".claude" / "commands"
    folder = root / "ordinary"
    folder.mkdir(parents=True)
    (folder / "SKILL.md").write_text("# Ordinary\n", encoding="utf-8")
    (root / "ordinary.md").write_text("# legacy command\n", encoding="utf-8")

    discovered = discover_skill_directories(str(root), connector="claudecode")

    assert discovered[0].name == "ordinary"
    assert discovered[0].path == os.path.realpath(folder)


@requires_symlink_privilege
def test_claudecode_commands_folder_with_link_and_markdown_stays_one_folder_skill(
    tmp_path,
) -> None:
    root = tmp_path / ".claude" / "commands"
    folder = root / "ordinary"
    folder.mkdir(parents=True)
    (folder / "SKILL.md").write_text("# Ordinary\n", encoding="utf-8")
    (root / "ordinary.md").write_text("# legacy command\n", encoding="utf-8")
    (root / "z-link").symlink_to(folder, target_is_directory=True)

    discovered = discover_skill_directories(str(root), connector="claudecode")

    assert discovered[0].name == "ordinary"
    assert discovered[0].path == os.path.realpath(folder)
    assert discovered[0].aliases == ("z-link",)


@pytest.mark.parametrize("connector", ["claudecode", "amp"])
def test_claude_account_synced_skills_are_expanded(tmp_path, connector) -> None:
    """GAP-1243: ~/.claude/skills/synced/<account>/<skill> holds real skills."""
    root = tmp_path / ".claude" / "skills"
    own = root / "own"
    own.mkdir(parents=True)
    (own / "SKILL.md").write_text("# own", encoding="utf-8")
    account = root / "synced" / "7e6ed31d-account"
    for name in ("pdf", "docx"):
        (account / name).mkdir(parents=True)
        (account / name / "SKILL.md").write_text(f"# {name}", encoding="utf-8")
    (account / "unmarked").mkdir()
    (root / "synced" / "manifest.json").write_text("{}", encoding="utf-8")

    discovered = discover_skill_directories(os.fspath(root), connector=connector)

    assert [(entry.name, entry.path) for entry in discovered] == [
        ("own", os.fspath(own)),
        ("docx", os.fspath(account / "docx")),
        ("pdf", os.fspath(account / "pdf")),
    ]
