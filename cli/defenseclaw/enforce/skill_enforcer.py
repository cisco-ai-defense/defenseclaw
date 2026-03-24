"""SkillEnforcer — filesystem quarantine for skills.

Mirrors internal/enforce/skill_enforcer.go.
"""

from __future__ import annotations

import os
import shutil


class SkillEnforcer:
    def __init__(self, quarantine_dir: str) -> None:
        self.quarantine_dir = os.path.join(quarantine_dir, "skills")
        os.makedirs(self.quarantine_dir, exist_ok=True)

    def quarantine(self, skill_name: str, source_path: str) -> str | None:
        """Move skill directory to quarantine. Returns quarantine path or None."""
        if not os.path.exists(source_path):
            return None
        dest = os.path.join(self.quarantine_dir, skill_name)
        if os.path.exists(dest):
            shutil.rmtree(dest)
        shutil.move(source_path, dest)
        return dest

    def restore(self, skill_name: str, restore_path: str) -> bool:
        """Restore a quarantined skill to its original location."""
        src = os.path.join(self.quarantine_dir, skill_name)
        if not os.path.exists(src):
            return False
        os.makedirs(os.path.dirname(restore_path), exist_ok=True)
        shutil.move(src, restore_path)
        return True

    def is_quarantined(self, skill_name: str) -> bool:
        return os.path.exists(os.path.join(self.quarantine_dir, skill_name))
