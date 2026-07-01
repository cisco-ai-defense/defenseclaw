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

"""Shared filesystem rules for connector skill discovery."""

from __future__ import annotations

import os
from dataclasses import dataclass

_SKILL_MARKERS = ("SKILL.md", "skill.json", "README.md")


@dataclass(frozen=True)
class SkillDirectory:
    """One discoverable skill directory beneath a connector skill root."""

    name: str
    path: str
    source: str
    bundled: bool = False


def skill_dir_is_eligible(path: str) -> bool:
    """Return whether *path* contains a recognized skill marker."""
    return any(os.path.isfile(os.path.join(path, marker)) for marker in _SKILL_MARKERS)


def discover_skill_directories(
    skill_root: str,
    *,
    connector: str,
) -> list[SkillDirectory]:
    """Return immediate skills, expanding connector-owned containers.

    Codex reserves ``.system`` as a container for bundled skills. Treating the
    container itself as a skill produces a false "missing SKILL.md" result, so
    enumerate only its marked child skill directories. Ordinary top-level
    skills are returned first so an operator-installed skill with the same
    name takes precedence over a bundled child.
    """
    try:
        entries = sorted(os.listdir(skill_root))
    except OSError:
        return []

    normalized_connector = (connector or "").strip().lower().replace("-", "")
    system_containers = {".system"} if normalized_connector == "codex" else set()

    regular: list[SkillDirectory] = []
    bundled: list[SkillDirectory] = []
    for entry in entries:
        full = os.path.join(skill_root, entry)
        if not os.path.isdir(full):
            continue
        if entry not in system_containers:
            regular.append(SkillDirectory(entry, full, skill_root))
            continue

        try:
            children = sorted(os.listdir(full))
        except OSError:
            continue
        for child in children:
            child_path = os.path.join(full, child)
            if not os.path.isdir(child_path) or not skill_dir_is_eligible(child_path):
                continue
            bundled.append(
                SkillDirectory(child, child_path, full, bundled=True)
            )
    return regular + bundled
