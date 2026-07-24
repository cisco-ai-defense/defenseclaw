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

"""PluginEnforcer — filesystem quarantine for plugins.

Mirrors internal/enforce/plugin_enforcer.go.
"""

from __future__ import annotations

import os
import shutil

from defenseclaw.inventory.plugin_identity import (
    PluginIdentityError,
    canonical_plugin_id,
    filesystem_identity_key,
    is_link_or_reparse,
    validate_plugin_id,
)


class PluginEnforcer:
    def __init__(self, quarantine_dir: str) -> None:
        self.quarantine_dir = os.path.join(quarantine_dir, "plugins")
        os.makedirs(self.quarantine_dir, exist_ok=True)

    @staticmethod
    def _safe_segment(value: str) -> str | None:
        safe = os.path.basename(value)
        if not safe or safe != value or safe in (".", ".."):
            return None
        return safe

    def _quarantine_path(self, plugin_name: str, connector: str = "") -> str | None:
        safe_name = self._safe_segment(plugin_name)
        if safe_name is None:
            return None
        if connector:
            safe_connector = self._safe_segment(connector)
            if safe_connector is None:
                return None
            dest = os.path.join(self.quarantine_dir, safe_connector, safe_name)
        else:
            dest = os.path.join(self.quarantine_dir, safe_name)
        if not os.path.realpath(dest).startswith(os.path.realpath(self.quarantine_dir) + os.sep):
            return None
        return dest

    def quarantine(
        self,
        plugin_name: str,
        source_path: str,
        connector: str = "",
    ) -> str | None:
        """Move plugin directory to quarantine. Returns quarantine path or None."""
        if is_link_or_reparse(source_path):
            return None
        real_path = os.path.realpath(source_path)
        if not os.path.exists(real_path):
            return None
        try:
            source_id, _manifest = canonical_plugin_id(source_path)
            if filesystem_identity_key(source_id, os.path.dirname(source_path)) != filesystem_identity_key(
                validate_plugin_id(plugin_name), os.path.dirname(source_path)
            ):
                return None
        except PluginIdentityError:
            return None
        dest = self._quarantine_path(plugin_name, connector)
        if dest is None:
            return None
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        if os.path.lexists(dest):
            return None
        shutil.move(real_path, dest)
        return dest

    def restore(
        self,
        plugin_name: str,
        restore_path: str,
        allowed_roots: list[str] | None = None,
        connector: str = "",
    ) -> bool:
        """Restore a quarantined plugin to its original location."""
        src = self._quarantine_path(plugin_name, connector)
        if src is None:
            return False
        if is_link_or_reparse(src) or not os.path.exists(src):
            return False
        try:
            source_id, _manifest = canonical_plugin_id(src)
            if filesystem_identity_key(source_id, os.path.dirname(src)) != filesystem_identity_key(
                validate_plugin_id(plugin_name), os.path.dirname(src)
            ):
                return False
        except PluginIdentityError:
            return False
        real_dest = os.path.realpath(restore_path)
        if allowed_roots:
            if not any(
                real_dest == os.path.realpath(r) or real_dest.startswith(os.path.realpath(r) + os.sep)
                for r in allowed_roots
            ):
                return False
        if os.path.lexists(restore_path):
            return False
        os.makedirs(os.path.dirname(restore_path), exist_ok=True)
        shutil.move(src, restore_path)
        return True

    def is_quarantined(self, plugin_name: str, connector: str = "") -> bool:
        path = self._quarantine_path(plugin_name, connector)
        return bool(path and os.path.exists(path))
