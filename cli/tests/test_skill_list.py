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
            self.assertEqual(r["baseDir"], os.path.join(skill_root, r["name"]))
            self.assertEqual(r["path"], os.path.join(skill_root, r["name"]))

    def test_codex_system_container_expands_bundled_child_skills(self):
        cfg = _make_cfg(self.tmp, "codex")
        skill_root = os.path.join(self.tmp, ".codex", "skills")
        system_root = os.path.join(skill_root, ".system")
        _seed_skill(system_root, "skill-creator", body="# System skill")
        os.makedirs(os.path.join(system_root, "not-a-skill"), exist_ok=True)
        _seed_skill(skill_root, "operator-skill", body="# Operator skill")

        with self._patch_skill_dirs([skill_root]):
            rows = skill_list.list_skills(cfg)

        by_name = {row["name"]: row for row in rows}
        self.assertNotIn(".system", by_name)
        self.assertNotIn("not-a-skill", by_name)
        self.assertEqual(set(by_name), {"operator-skill", "skill-creator"})
        self.assertTrue(by_name["skill-creator"]["bundled"])
        self.assertEqual(by_name["skill-creator"]["source"], system_root)
        self.assertTrue(by_name["skill-creator"]["eligible"])
        self.assertFalse(by_name["operator-skill"]["bundled"])

    def test_codex_operator_skill_precedes_same_named_system_skill(self):
        cfg = _make_cfg(self.tmp, "codex")
        skill_root = os.path.join(self.tmp, ".codex", "skills")
        _seed_skill(skill_root, "shared", body="# Operator copy")
        _seed_skill(os.path.join(skill_root, ".system"), "shared", body="# System copy")

        with self._patch_skill_dirs([skill_root]):
            rows = skill_list.list_skills(cfg)

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["description"], "Operator copy")
        self.assertFalse(rows[0]["bundled"])

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

    def test_description_uses_skill_frontmatter(self):
        cfg = _make_cfg(self.tmp, "openhands")
        skill_root = os.path.join(self.tmp, "skills")
        _seed_skill(
            skill_root,
            "frontmatter",
            body="---\nname: frontmatter\ndescription: Frontmatter description\n---\n\n# Fallback\n",
        )

        with self._patch_skill_dirs([skill_root]):
            rows = skill_list.list_skills(cfg)

        self.assertEqual(rows[0]["description"], "Frontmatter description")

    def test_openhands_installed_container_is_not_a_skill(self):
        cfg = _make_cfg(self.tmp, "openhands")
        openhands_skills = os.path.join(self.tmp, ".openhands", "skills")
        installed = os.path.join(openhands_skills, "installed")
        os.makedirs(installed, exist_ok=True)
        _seed_skill(installed, "real-installed")

        with self._patch_skill_dirs([openhands_skills, installed]):
            rows = skill_list.list_skills(cfg)

        self.assertEqual([r["name"] for r in rows], ["real-installed"])

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

    def test_f0281_symlinked_marker_does_not_leak_secret(self):
        """F-0281: a malicious skill dir whose SKILL.md is a symlink to an
        arbitrary operator-readable file must NOT leak that file's first
        line into the description. ``os.path.isfile`` follows symlinks; the
        reader must skip a symlinked marker (``is_symlink``)."""
        cfg = _make_cfg(self.tmp, "codex")
        skill_root = os.path.join(self.tmp, "skills")
        skill_dir = os.path.join(skill_root, "evil")
        os.makedirs(skill_dir, exist_ok=True)

        # The secret the attacker wants disclosed via the listing.
        secret = os.path.join(self.tmp, "secret.txt")
        with open(secret, "w", encoding="utf-8") as f:
            f.write("TOP-SECRET-CREDENTIAL\nmore\n")

        # SKILL.md is a symlink pointing at the secret.
        os.symlink(secret, os.path.join(skill_dir, "SKILL.md"))

        with self._patch_skill_dirs([skill_root]):
            rows = skill_list.list_skills(cfg)

        by_name = {r["name"]: r for r in rows}
        self.assertIn("evil", by_name)
        # The secret's first line must NOT appear in the description.
        self.assertNotIn("TOP-SECRET-CREDENTIAL", by_name["evil"]["description"])
        self.assertEqual(by_name["evil"]["description"], "")

    def test_f0281_real_marker_still_described(self):
        """F-0281 regression guard: a genuine (non-symlink) SKILL.md is
        still read for the description."""
        cfg = _make_cfg(self.tmp, "codex")
        skill_root = os.path.join(self.tmp, "skills")
        _seed_skill(skill_root, "good", body="# Good\n\nDoes good.")
        with self._patch_skill_dirs([skill_root]):
            rows = skill_list.list_skills(cfg)
        self.assertEqual(rows[0]["description"], "Good")


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


class TestListSkillsConnectorOverride(unittest.TestCase):
    """WU13: ``list_skills(cfg, connector=...)`` walks the requested
    connector's directories instead of the active one, so the TUI focus
    selector (``skill list --connector <name>``) shows the right catalog."""

    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="dc-skill-list-override-")

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_override_walks_requested_connector_dirs(self):
        cfg = _make_cfg(self.tmp, "codex")  # active connector = codex
        # Arbitrary dir names (skill_dirs is patched below); avoid real
        # dotted connector layouts so the sandbox doesn't block creation.
        codex_root = os.path.join(self.tmp, "codex_skills")
        cursor_root = os.path.join(self.tmp, "cursor_skills")
        os.makedirs(codex_root, exist_ok=True)
        os.makedirs(cursor_root, exist_ok=True)
        _seed_skill(codex_root, "codex-skill")
        _seed_skill(cursor_root, "cursor-skill")

        dirs_by_connector = {"codex": [codex_root], "cursor": [cursor_root]}

        def fake_skill_dirs(self_cfg, connector=None):
            return dirs_by_connector.get(connector or "codex", [codex_root])

        with patch(
            "defenseclaw.config.Config.skill_dirs",
            autospec=True,
            side_effect=fake_skill_dirs,
        ):
            # No override → active connector (codex).
            default_rows = skill_list.list_skills(cfg)
            # Override → cursor's directories.
            override_rows = skill_list.list_skills(cfg, connector="cursor")

        self.assertEqual([r["name"] for r in default_rows], ["codex-skill"])
        self.assertEqual([r["name"] for r in override_rows], ["cursor-skill"])


if __name__ == "__main__":
    unittest.main()
