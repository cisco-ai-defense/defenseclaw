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

    def set_source_path(
        self, target_type: str, name: str, path: str, connector: str = "",
    ) -> None:
        if self.store:
            self.store.set_source_path(target_type, name, path, connector)

    def set_action(
        self, target_type: str, name: str, source_path: str,
        state: ActionState, reason: str,
    ) -> None:
        if self.store:
            self.store.set_action(target_type, name, source_path, state, reason)

    def get_action(
        self, target_type: str, name: str, connector: str = "",
    ) -> ActionEntry | None:
        if not self.store:
            return None
        return self.store.get_action(target_type, name, connector)

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
    # Connector-scoped enforcement helpers (N2 — per-connector
    # mcp block/allow/unblock)
    #
    # The connector dimension lives in the audit store's per-connector
    # ``connector`` column (the f/dbmig SK-4 foundation), which is distinct
    # from the ``@<connector>/<tool>`` name-encoding the tool gate uses below.
    # A bare entry (connector="") is **GLOBAL** — it applies to every
    # connector; a non-empty connector **NARROWS** the entry to that peer.
    #
    # Reads resolve **most-specific-wins per action field**: if the connector
    # owns a row with the requested field set, that field is authoritative for
    # that connector; otherwise the global row falls through. This lets a
    # connector-scoped allow override a global block for that connector, while a
    # connector-scoped block still wins when both scoped/global allows exist.
    # Writes are exact-match on connector (the actions table is unique on
    # (target_type, target_name, connector)). Mirrors the ``*ForConnector``
    # methods in internal/enforce/policy.go.
    # ------------------------------------------------------------------

    def is_blocked_for_connector(
        self, target_type: str, name: str, connector: str = "",
    ) -> bool:
        """True if blocked for ``connector`` (connector-scoped entry, else global)."""
        if not self.store:
            return False
        if connector:
            scoped = self.store.get_action(target_type, name, connector)
            if scoped is not None and scoped.actions.install:
                return scoped.actions.install == "block"
        return self.store.has_action(target_type, name, "install", "block")

    def is_allowed_for_connector(
        self, target_type: str, name: str, connector: str = "",
    ) -> bool:
        """True if allowed for ``connector`` (connector-scoped entry, else global)."""
        if not self.store:
            return False
        if connector:
            scoped = self.store.get_action(target_type, name, connector)
            if scoped is not None and scoped.actions.install:
                return scoped.actions.install == "allow"
        return self.store.has_action(target_type, name, "install", "allow")

    def is_quarantined_for_connector(
        self, target_type: str, name: str, connector: str = "",
    ) -> bool:
        """True if quarantined for ``connector`` (connector-scoped entry, else global)."""
        if not self.store:
            return False
        if connector:
            scoped = self.store.get_action(target_type, name, connector)
            if scoped is not None and scoped.actions.file:
                return scoped.actions.file == "quarantine"
        return self.store.has_action(target_type, name, "file", "quarantine")

    def block_for_connector(
        self, target_type: str, name: str, connector: str, reason: str,
    ) -> None:
        """Block ``name`` for ``connector`` (exact-match; connector="" = global)."""
        if self.store:
            self.store.set_action_field(
                target_type, name, "install", "block", reason, connector,
            )

    def allow_for_connector(
        self, target_type: str, name: str, connector: str, reason: str,
    ) -> None:
        """Allow ``name`` for ``connector`` and clear residual file/runtime state.

        Exact-match on connector (connector="" = global). Mirrors :meth:`allow`.
        """
        if not self.store:
            return
        self.store.set_action_field(
            target_type, name, "install", "allow", reason, connector,
        )
        self.store.clear_action_field(target_type, name, "file", connector)
        self.store.clear_action_field(target_type, name, "runtime", connector)

    def unblock_for_connector(
        self, target_type: str, name: str, connector: str = "",
    ) -> None:
        """Clear the install action for ``connector`` (exact-match; ""=global)."""
        if self.store:
            self.store.clear_action_field(target_type, name, "install", connector)

    def quarantine_for_connector(
        self, target_type: str, name: str, connector: str, reason: str,
    ) -> None:
        """Quarantine ``name`` for ``connector`` (file dimension; exact-match;
        connector="" = global). Mirrors :meth:`quarantine`."""
        if self.store:
            self.store.set_action_field(
                target_type, name, "file", "quarantine", reason, connector,
            )

    def clear_quarantine_for_connector(
        self, target_type: str, name: str, connector: str = "",
    ) -> None:
        """Clear the file (quarantine) action for ``connector`` (exact-match;
        ""=global). Mirrors :meth:`clear_quarantine`."""
        if self.store:
            self.store.clear_action_field(target_type, name, "file", connector)

    def disable_for_connector(
        self, target_type: str, name: str, connector: str, reason: str,
    ) -> None:
        """Disable ``name`` at runtime for ``connector`` (runtime dimension;
        exact-match; connector="" = global). Mirrors :meth:`disable`."""
        if self.store:
            self.store.set_action_field(
                target_type, name, "runtime", "disable", reason, connector,
            )

    def enable_for_connector(
        self, target_type: str, name: str, connector: str = "",
    ) -> None:
        """Clear the runtime (disable) action for ``connector`` (exact-match;
        ""=global). Mirrors :meth:`enable`."""
        if self.store:
            self.store.clear_action_field(target_type, name, "runtime", connector)

    def remove_action_for_connector(
        self, target_type: str, name: str, connector: str = "",
    ) -> None:
        """Remove all enforcement for ``connector`` (exact-match; ""=global)."""
        if self.store:
            self.store.remove_action(target_type, name, connector)

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

    # ------------------------------------------------------------------
    # Connector-scoped tool helpers (target_type="tool", "@<connector>/<tool>")
    #
    # The ``@`` sigil keeps connector scoping distinct from the orthogonal
    # ``<source>/<tool>`` source scoping above. Runtime resolution order
    # (mirrored by the Go gateway lanes via the policy.go methods of the same
    # name) is, for request connector ``C`` and tool ``T``:
    #   block @C/T → block T → allow @C/T → allow T → scan
    # i.e. a global block still wins over a connector-scoped allow because
    # callers consult is_tool_blocked_for_connector before
    # is_tool_allowed_for_connector.
    # ------------------------------------------------------------------

    @staticmethod
    def _tool_connector_target(tool_name: str, connector: str) -> str:
        """Build the connector-scoped tool key ``@<connector>/<tool>``.

        Centralised here so the read gate and the write surface stay in
        lockstep on the encoding.
        """
        return f"@{connector}/{tool_name}" if connector else tool_name

    def is_tool_blocked_for_connector(self, tool_name: str, connector: str = "") -> bool:
        """Return True if the tool is blocked for ``connector`` (scoped then global)."""
        if not self.store:
            return False
        if connector:
            scoped = self._tool_connector_target(tool_name, connector)
            if self.store.has_action("tool", scoped, "install", "block"):
                return True
        return self.store.has_action("tool", tool_name, "install", "block")

    def is_tool_allowed_for_connector(self, tool_name: str, connector: str = "") -> bool:
        """Return True if the tool is allowed for ``connector`` (scoped then global).

        Callers must check :meth:`is_tool_blocked_for_connector` first so a
        global block wins over a connector-scoped allow.
        """
        if not self.store:
            return False
        if connector:
            scoped = self._tool_connector_target(tool_name, connector)
            if self.store.has_action("tool", scoped, "install", "allow"):
                return True
        return self.store.has_action("tool", tool_name, "install", "allow")

    def block_tool_for_connector(self, tool_name: str, connector: str, reason: str) -> None:
        """Block a tool, optionally scoped to a connector (``@<connector>/<tool>``)."""
        if self.store:
            target = self._tool_connector_target(tool_name, connector)
            self.store.set_action_field("tool", target, "install", "block", reason)

    def allow_tool_for_connector(self, tool_name: str, connector: str, reason: str) -> None:
        """Allow a tool, optionally scoped to a connector.

        Uses the same cleanup pattern as :meth:`allow_tool` for consistency.
        """
        if not self.store:
            return
        target = self._tool_connector_target(tool_name, connector)
        self.store.set_action_field("tool", target, "install", "allow", reason)
        self.store.clear_action_field("tool", target, "file")
        self.store.clear_action_field("tool", target, "runtime")
