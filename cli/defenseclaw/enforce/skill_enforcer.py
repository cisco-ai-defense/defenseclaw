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
        if os.path.islink(source_path):
            return None
        real_path = os.path.realpath(source_path)
        if not os.path.exists(real_path):
            return None
        dest = os.path.join(self.quarantine_dir, skill_name)
        if os.path.exists(dest):
            shutil.rmtree(dest)
        shutil.move(real_path, dest)
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
