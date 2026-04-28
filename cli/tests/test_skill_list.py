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

"""Tests for the connector-agnostic ``skill_list.list_skills`` adapter (S4.4)."""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from defenseclaw import skill_list
from defenseclaw.config import ClawConfig, Config


def _make_cfg(tmp: str, connector: str = "openclaw") -> Config:
    ddir = os.path.join(tmp, ".defenseclaw")
    os.makedirs(ddir, exist_ok=True)
    cfg = Config(
        data_dir=ddir,
        audit_db=os.path.join(ddir, "audit.db"),
        quarantine_dir=os.path.join(tmp, "q"),
        plugin_dir=os.path.join(tmp, "p"),
        policy_dir=os.path.join(tmp, "pol"),
        claw=ClawConfig(
            mode="openclaw",
            home_dir=os.path.join(tmp, "oc"),
            config_file=os.path.join(tmp, "oc", "openclaw.json"),
        ),
    )
    cfg.active_connector = lambda c=connector: c  # type: ignore[method-assign]
    return cfg


def _seed_skill(root: str, name: str, *, marker: str = "SKILL.md", body: str = "# Skill\n") -> str:
    path = os.path.join(root, name)
    os.makedirs(path, exist_ok=True)
    with open(os.path.join(path, marker), "w", encoding="utf-8") as f:
        f.write(body)
    return path


class TestListSkillsForNonOpenClawConnector(unittest.TestCase):
    """Each non-OpenClaw connector must walk its skill_dirs() output."""

    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="dc-skill-list-")

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _patch_skill_dirs(self, dirs):
        return patch(
            "defenseclaw.config.Config.skill_dirs",
            return_value=list(dirs),
        )

    def test_codex_walks_disk_and_skips_subprocess(self):
        cfg = _make_cfg(self.tmp, "codex")
        skill_root = os.path.join(self.tmp, ".codex", "skills")
        os.makedirs(skill_root, exist_ok=True)
        _seed_skill(skill_root, "alpha")
        _seed_skill(skill_root, "beta", body="# Beta\n\nBeta does X.")

        with self._patch_skill_dirs([skill_root]), \
             patch("defenseclaw.skill_list.subprocess.run") as mock_run:
            rows = skill_list.list_skills(cfg)
            mock_run.assert_not_called()

        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["name"], "alpha")
        self.assertEqual(rows[1]["name"], "beta")
        self.assertEqual(rows[1]["description"], "Beta")
        for r in rows:
            self.assertTrue(r["eligible"])
            self.assertFalse(r["disabled"])
            self.assertFalse(r["bundled"])
            self.assertEqual(r["source"], skill_root)

    def test_claudecode_walks_disk(self):
        cfg = _make_cfg(self.tmp, "claudecode")
        skill_root = os.path.join(self.tmp, ".claude", "skills")
        os.makedirs(skill_root, exist_ok=True)
        _seed_skill(skill_root, "weather")
        with self._patch_skill_dirs([skill_root]):
            rows = skill_list.list_skills(cfg)
        self.assertEqual([r["name"] for r in rows], ["weather"])

    def test_zeptoclaw_walks_disk_with_skill_json(self):
        cfg = _make_cfg(self.tmp, "zeptoclaw")
        skill_root = os.path.join(self.tmp, ".zeptoclaw", "skills")
        os.makedirs(skill_root, exist_ok=True)
        _seed_skill(skill_root, "alpha", marker="skill.json", body="{}")
        with self._patch_skill_dirs([skill_root]):
            rows = skill_list.list_skills(cfg)
        self.assertEqual(rows[0]["name"], "alpha")
        self.assertTrue(rows[0]["eligible"])

    def test_directory_without_marker_is_ineligible(self):
        cfg = _make_cfg(self.tmp, "codex")
        skill_root = os.path.join(self.tmp, "skills")
        os.makedirs(os.path.join(skill_root, "marked"), exist_ok=True)
        with open(os.path.join(skill_root, "marked", "SKILL.md"), "w") as f:
            f.write("# X")
        os.makedirs(os.path.join(skill_root, "empty"), exist_ok=True)
        with self._patch_skill_dirs([skill_root]):
            rows = skill_list.list_skills(cfg)
        by_name = {r["name"]: r for r in rows}
        self.assertTrue(by_name["marked"]["eligible"])
        self.assertFalse(by_name["empty"]["eligible"])

    def test_dedup_across_skill_dirs(self):
        cfg = _make_cfg(self.tmp, "codex")
        a = os.path.join(self.tmp, "a")
        b = os.path.join(self.tmp, "b")
        os.makedirs(a, exist_ok=True)
        os.makedirs(b, exist_ok=True)
        _seed_skill(a, "shared")
        _seed_skill(b, "shared")
        with self._patch_skill_dirs([a, b]):
            rows = skill_list.list_skills(cfg)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["source"], a)

    def test_missing_skill_dir_is_skipped(self):
        cfg = _make_cfg(self.tmp, "codex")
        with self._patch_skill_dirs(["/nonexistent/path"]):
            rows = skill_list.list_skills(cfg)
        self.assertEqual(rows, [])


class TestListSkillsForOpenClaw(unittest.TestCase):
    """OpenClaw default keeps the subprocess-first behavior."""

    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="dc-skill-list-oc-")

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_uses_openclaw_cli_when_available(self):
        cfg = _make_cfg(self.tmp, "openclaw")
        payload = {
            "skills": [
                {
                    "name": "github",
                    "description": "GitHub integration",
                    "eligible": True,
                    "disabled": False,
                    "source": "openclaw-bundled",
                    "bundled": True,
                },
            ],
        }
        with patch("defenseclaw.skill_list.subprocess.run") as mock_run, \
             patch(
                 "defenseclaw.config.openclaw_cmd_prefix",
                 return_value=[],
             ), \
             patch(
                 "defenseclaw.config.openclaw_bin",
                 return_value="openclaw",
             ):
            mock_run.return_value = MagicMock(
                returncode=0, stdout=json.dumps(payload), stderr=""
            )
            rows = skill_list.list_skills(cfg)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["name"], "github")
        self.assertTrue(rows[0]["bundled"])

    def test_falls_back_to_filesystem_when_cli_missing(self):
        cfg = _make_cfg(self.tmp, "openclaw")
        skill_root = os.path.join(self.tmp, "fallback-skills")
        os.makedirs(skill_root, exist_ok=True)
        _seed_skill(skill_root, "fs-only")
        with patch(
            "defenseclaw.skill_list.subprocess.run",
            side_effect=FileNotFoundError,
        ), patch(
            "defenseclaw.config.Config.skill_dirs",
            return_value=[skill_root],
        ):
            rows = skill_list.list_skills(cfg)
        self.assertEqual(rows[0]["name"], "fs-only")

    def test_prefer_cli_false_skips_subprocess(self):
        cfg = _make_cfg(self.tmp, "openclaw")
        skill_root = os.path.join(self.tmp, "fs-only-skills")
        os.makedirs(skill_root, exist_ok=True)
        _seed_skill(skill_root, "alpha")
        with patch("defenseclaw.skill_list.subprocess.run") as mock_run, \
             patch(
                 "defenseclaw.config.Config.skill_dirs",
                 return_value=[skill_root],
             ):
            rows = skill_list.list_skills(cfg, prefer_cli=False)
            mock_run.assert_not_called()
        self.assertEqual(rows[0]["name"], "alpha")

    def test_returns_empty_when_cli_returns_non_dict(self):
        cfg = _make_cfg(self.tmp, "openclaw")
        with patch("defenseclaw.skill_list.subprocess.run") as mock_run, \
             patch(
                 "defenseclaw.config.openclaw_cmd_prefix",
                 return_value=[],
             ), \
             patch(
                 "defenseclaw.config.openclaw_bin",
                 return_value="openclaw",
             ):
            mock_run.return_value = MagicMock(
                returncode=0, stdout="[]", stderr=""
            )
            rows = skill_list.list_skills(cfg)
        # ``[]`` parses as a list, not a dict — so the parser treats
        # it as "no skills key" and returns []. Crucially we must NOT
        # crash and we must NOT fall back to the filesystem (the CLI
        # returned a successful response).
        self.assertEqual(rows, [])


if __name__ == "__main__":
    unittest.main()
