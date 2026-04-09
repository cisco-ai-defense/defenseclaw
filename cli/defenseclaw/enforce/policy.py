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

"""PolicyEngine — thin facade over the audit Store for enforcement decisions.

Mirrors internal/enforce/policy.go exactly.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from defenseclaw.models import ActionEntry, ActionState

if TYPE_CHECKING:
    from defenseclaw.db import Store


class PolicyEngine:
    def __init__(self, store: Store | None) -> None:
        self.store = store

    def is_blocked(self, target_type: str, name: str) -> bool:
        if not self.store:
            return False
        return self.store.has_action(target_type, name, "install", "block")

    def is_allowed(self, target_type: str, name: str) -> bool:
        if not self.store:
            return False
        return self.store.has_action(target_type, name, "install", "allow")

    def is_quarantined(self, target_type: str, name: str) -> bool:
        if not self.store:
            return False
        return self.store.has_action(target_type, name, "file", "quarantine")

    def block(self, target_type: str, name: str, reason: str) -> None:
        if self.store:
            self.store.set_action_field(target_type, name, "install", "block", reason)

    def allow(self, target_type: str, name: str, reason: str) -> None:
        """Set install=allow and clear residual file/runtime enforcement.

        Mirrors internal/enforce/policy.go Allow() exactly: after allowing,
        quarantine and disable state are removed so the allow takes full
        effect.  Only a manual block() can override an allow entry.
        """
        if not self.store:
            return
        self.store.set_action_field(target_type, name, "install", "allow", reason)
        self.store.clear_action_field(target_type, name, "file")
        self.store.clear_action_field(target_type, name, "runtime")

    def unblock(self, target_type: str, name: str) -> None:
        if self.store:
            self.store.clear_action_field(target_type, name, "install")

    def quarantine(self, target_type: str, name: str, reason: str) -> None:
        if self.store:
            self.store.set_action_field(target_type, name, "file", "quarantine", reason)

    def clear_quarantine(self, target_type: str, name: str) -> None:
        if self.store:
            self.store.clear_action_field(target_type, name, "file")

    def disable(self, target_type: str, name: str, reason: str) -> None:
        if self.store:
            self.store.set_action_field(target_type, name, "runtime", "disable", reason)

    def enable(self, target_type: str, name: str) -> None:
        if self.store:
            self.store.clear_action_field(target_type, name, "runtime")

    def set_source_path(self, target_type: str, name: str, path: str) -> None:
        if self.store:
            self.store.set_source_path(target_type, name, path)

    def set_action(
        self, target_type: str, name: str, source_path: str,
        state: ActionState, reason: str,
    ) -> None:
        if self.store:
            self.store.set_action(target_type, name, source_path, state, reason)

    def get_action(self, target_type: str, name: str) -> ActionEntry | None:
        if not self.store:
            return None
        return self.store.get_action(target_type, name)

    def list_blocked(self) -> list[ActionEntry]:
        if not self.store:
            return []
        return self.store.list_by_action("install", "block")

    def list_allowed(self) -> list[ActionEntry]:
        if not self.store:
            return []
        return self.store.list_by_action("install", "allow")

    def list_all(self) -> list[ActionEntry]:
        if not self.store:
            return []
        return self.store.list_all_actions()

    def list_by_type(self, target_type: str) -> list[ActionEntry]:
        if not self.store:
            return []
        return self.store.list_actions_by_type(target_type)

    def remove_action(self, target_type: str, name: str) -> None:
        if self.store:
            self.store.remove_action(target_type, name)

    # ------------------------------------------------------------------
    # Tool-level helpers (target_type="tool", scoped naming supported)
    # ------------------------------------------------------------------

    def is_tool_blocked(self, tool_name: str, source: str = "") -> bool:
        """Return True if the tool is blocked (scoped check first, then global)."""
        if not self.store:
            return False
        if source:
            scoped = f"{source}/{tool_name}"
            if self.store.has_action("tool", scoped, "install", "block"):
                return True
        return self.store.has_action("tool", tool_name, "install", "block")

    def is_tool_allowed(self, tool_name: str, source: str = "") -> bool:
        """Return True if the tool is allowed (scoped check first, then global)."""
        if not self.store:
            return False
        if source:
            scoped = f"{source}/{tool_name}"
            if self.store.has_action("tool", scoped, "install", "allow"):
                return True
        return self.store.has_action("tool", tool_name, "install", "allow")

    def block_tool(self, tool_name: str, source: str, reason: str) -> None:
        """Block a tool, optionally scoped to a source."""
        if self.store:
            target = f"{source}/{tool_name}" if source else tool_name
            self.store.set_action_field("tool", target, "install", "block", reason)

    def allow_tool(self, tool_name: str, source: str, reason: str) -> None:
        """Allow a tool, optionally scoped to a source.

        Uses the same cleanup pattern as allow() for consistency.
        """
        if not self.store:
            return
        target = f"{source}/{tool_name}" if source else tool_name
        self.store.set_action_field("tool", target, "install", "allow", reason)
        self.store.clear_action_field("tool", target, "file")
        self.store.clear_action_field("tool", target, "runtime")

    def list_blocked_tools(self) -> list[ActionEntry]:
        """List all tool-level block entries."""
        if not self.store:
            return []
        return self.store.list_by_action_and_type("install", "block", "tool")

    def list_allowed_tools(self) -> list[ActionEntry]:
        """List all tool-level allow entries."""
        if not self.store:
            return []
        return self.store.list_by_action_and_type("install", "allow", "tool")
