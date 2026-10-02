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

"""GAP-1908/GAP-1920: Codex vendor skills are discovery-only everywhere."""

from __future__ import annotations

import os

from defenseclaw.inventory.claw_inventory import _build_summary, enrich_with_policy
from defenseclaw.skill_discovery import discover_skill_directories


def test_cursor_marks_codex_system_skills_bundled(tmp_path, monkeypatch):
    codex = tmp_path / "codex"
    monkeypatch.setenv("CODEX_HOME", str(codex))
    root = codex / "skills"
    for rel in (".system/imagegen", "mine"):
        (root / rel).mkdir(parents=True)
        (root / rel / "SKILL.md").write_text("---\nname: x\ndescription: y\n---\n")

    rows = {d.name: d for d in discover_skill_directories(str(root), connector="cursor")}

    assert rows["imagegen"].bundled is True
    assert rows["imagegen"].source == os.path.join(str(root), ".system")
    assert rows["mine"].bundled is False
    assert rows["mine"].source == str(root)


def test_summary_eligible_excludes_discovery_only(tmp_path):
    from defenseclaw.db import Store

    store = Store(str(tmp_path / "audit.db"))
    store.init()
    skills = [
        {"id": f"vendor{i}", "eligible": True, "bundled": True, "path": str(tmp_path / f"v{i}")} for i in range(5)
    ] + [{"id": "mine", "eligible": True, "path": str(tmp_path / "mine")}]
    inv = {"connector": "codex", "skills": skills, "summary": _build_summary({"skills": skills, "plugins": []})}

    enrich_with_policy(inv, store)

    assert inv["summary"]["skills"] == {"count": 6, "eligible": 1}
    assert inv["summary"]["policy_skills"]["discovery-only"] == 5
