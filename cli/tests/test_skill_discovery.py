# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Security and compatibility tests for shared skill discovery."""

from __future__ import annotations

import os

import pytest
from defenseclaw.skill_discovery import discover_skill_directories


def test_codex_system_child_rejects_symlinked_marker(tmp_path) -> None:
    system_root = tmp_path / ".system"
    skill = system_root / "linked-marker"
    skill.mkdir(parents=True)
    real_marker = tmp_path / "outside.md"
    real_marker.write_text("# outside", encoding="utf-8")
    try:
        os.symlink(real_marker, skill / "SKILL.md")
    except OSError:
        pytest.skip("filesystem does not support symlinks")

    discovered = discover_skill_directories(os.fspath(tmp_path), connector="codex")

    assert "linked-marker" not in {entry.name for entry in discovered}


def test_codex_system_child_keeps_regular_marker(tmp_path) -> None:
    skill = tmp_path / ".system" / "legitimate"
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_text("# legitimate", encoding="utf-8")

    discovered = discover_skill_directories(os.fspath(tmp_path), connector="codex")

    assert [(entry.name, entry.path, entry.bundled) for entry in discovered] == [
        ("legitimate", os.fspath(skill), True),
    ]
