"""Tests for SkillEnforcer — filesystem quarantine and restore operations."""

import os
import shutil
import tempfile
import unittest

import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.enforce.skill_enforcer import SkillEnforcer


class TestSkillEnforcer(unittest.TestCase):
    def setUp(self):
        self.quarantine_root = tempfile.mkdtemp(prefix="dclaw-quarantine-")
        self.skills_root = tempfile.mkdtemp(prefix="dclaw-skills-")
        self.enforcer = SkillEnforcer(self.quarantine_root)

    def tearDown(self):
        shutil.rmtree(self.quarantine_root, ignore_errors=True)
        shutil.rmtree(self.skills_root, ignore_errors=True)

    def _create_skill(self, name: str) -> str:
        skill_dir = os.path.join(self.skills_root, name)
        os.makedirs(skill_dir, exist_ok=True)
        with open(os.path.join(skill_dir, "main.py"), "w") as f:
            f.write("print('hello')\n")
        return skill_dir

    def test_quarantine_moves_directory(self):
        skill_path = self._create_skill("bad-skill")
        dest = self.enforcer.quarantine("bad-skill", skill_path)

        self.assertIsNotNone(dest)
        self.assertFalse(os.path.exists(skill_path))
        self.assertTrue(os.path.exists(dest))
        self.assertTrue(os.path.isfile(os.path.join(dest, "main.py")))

    def test_quarantine_returns_none_for_nonexistent(self):
        dest = self.enforcer.quarantine("ghost", "/nonexistent/path")
        self.assertIsNone(dest)

    def test_quarantine_overwrites_existing_quarantine(self):
        skill_path = self._create_skill("dup-skill")
        self.enforcer.quarantine("dup-skill", skill_path)

        skill_path2 = self._create_skill("dup-skill")
        with open(os.path.join(skill_path2, "extra.txt"), "w") as f:
            f.write("new content")
        dest = self.enforcer.quarantine("dup-skill", skill_path2)

        self.assertIsNotNone(dest)
        self.assertTrue(os.path.isfile(os.path.join(dest, "extra.txt")))

    def test_is_quarantined(self):
        self.assertFalse(self.enforcer.is_quarantined("my-skill"))
        skill_path = self._create_skill("my-skill")
        self.enforcer.quarantine("my-skill", skill_path)
        self.assertTrue(self.enforcer.is_quarantined("my-skill"))

    def test_restore_moves_back(self):
        skill_path = self._create_skill("restore-me")
        self.enforcer.quarantine("restore-me", skill_path)
        self.assertFalse(os.path.exists(skill_path))

        success = self.enforcer.restore("restore-me", skill_path)
        self.assertTrue(success)
        self.assertTrue(os.path.exists(skill_path))
        self.assertTrue(os.path.isfile(os.path.join(skill_path, "main.py")))
        self.assertFalse(self.enforcer.is_quarantined("restore-me"))

    def test_restore_nonexistent_returns_false(self):
        success = self.enforcer.restore("doesnt-exist", "/tmp/wherever")
        self.assertFalse(success)

    def test_full_quarantine_restore_cycle(self):
        skill_path = self._create_skill("cycle-skill")
        self.assertFalse(self.enforcer.is_quarantined("cycle-skill"))

        self.enforcer.quarantine("cycle-skill", skill_path)
        self.assertTrue(self.enforcer.is_quarantined("cycle-skill"))
        self.assertFalse(os.path.exists(skill_path))

        self.enforcer.restore("cycle-skill", skill_path)
        self.assertFalse(self.enforcer.is_quarantined("cycle-skill"))
        self.assertTrue(os.path.exists(skill_path))


if __name__ == "__main__":
    unittest.main()
