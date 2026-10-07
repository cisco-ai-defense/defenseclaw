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

"""PolicyEngine — enforcement answers for skills, MCP servers, plugins and tools.

Operator block/allow decisions live in config.yaml ``asset_policy`` (the
``<type>.denied/allowed`` and ``tool`` lists): :meth:`block`, :meth:`allow`
and :meth:`unblock` change them through the single config writer, and the
``is_blocked*``/``is_allowed*`` reads come from the loaded config passed as
``cfg``. The audit.db ``actions`` table is the enforcement journal — scan
verdict blocks, quarantine, runtime disable — and is never read as policy.
Secure Client hosts keep operator rows in the table, unchanged.

Mirrors internal/enforce/policy.go.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from defenseclaw.enforce import asset_lists
from defenseclaw.models import ActionEntry, ActionState

if TYPE_CHECKING:
    from defenseclaw.db import Store


def _tool_policy_entries(tools: Any) -> list[ActionEntry]:
    """asset_policy.tool rules as ActionEntry rows. config.yaml stores no
    time for a rule, so ``updated_at`` is None (shown as "-"), never the
    time of the read."""
    out: list[ActionEntry] = []
    for decision, rules in (("block", getattr(tools, "denied", [])), ("allow", getattr(tools, "allowed", []))):
        for rule in rules or []:
            target = f"@{rule.connector}/{rule.name}" if rule.connector else rule.name
            out.append(ActionEntry(
                id=f"asset_policy:tool:{target}", target_type="tool", target_name=target,
                actions=ActionState(install=decision), reason=rule.reason, updated_at=None,
            ))
    return out


def tool_rule_entries(cfg: Any | None, store: Store | None) -> list[ActionEntry]:
    """The tool rules ``defenseclaw tool list`` shows, as config.yaml holds them now.

    For a long-running reader such as the TUI: the CLI it runs writes
    ``asset_policy.tool`` to config.yaml, so the config loaded at start would
    miss every later rule. Secure Client (and a reader with no config) keeps
    the audit.db rows.
    """
    if cfg is None or asset_lists.is_secure_client(cfg):
        return store.list_actions_by_type("tool") if store else []
    return _tool_policy_entries(asset_lists.tool_policy_on_disk(cfg))


class PolicyEngine:
    def __init__(self, store: Store | None, cfg: Any | None = None) -> None:
        self.store = store
        self.cfg = cfg

    def _legacy_rows(self) -> bool:
        return asset_lists.is_secure_client(self.cfg)

    def _asset_policy(self) -> Any | None:
        return getattr(self.cfg, "asset_policy", None)

    # ------------------------------------------------------------------
    # Operator block/allow (config.yaml asset_policy)
    #
    # A rule scoped to the connector decides before an unscoped one, so a
    # connector-scoped allow overrides a global block for that connector.
    # ------------------------------------------------------------------

    def is_blocked(self, target_type: str, name: str) -> bool:
        return self.is_blocked_for_connector(target_type, name, "")

    def is_allowed(self, target_type: str, name: str) -> bool:
        return self.is_allowed_for_connector(target_type, name, "")

    def is_blocked_for_connector(self, target_type: str, name: str, connector: str = "") -> bool:
        if self._legacy_rows():
            return self._journal_install_is(target_type, name, connector, "block")
        return self._operator_decision(target_type, name, connector) == asset_lists.LIST_DENY

    def is_allowed_for_connector(self, target_type: str, name: str, connector: str = "") -> bool:
        if self._legacy_rows():
            return self._journal_install_is(target_type, name, connector, "allow")
        return self._operator_decision(target_type, name, connector) == asset_lists.LIST_ALLOW

    def _operator_decision(self, target_type: str, name: str, connector: str) -> str:
        if target_type == "tool":
            return asset_lists.tool_decision(self._asset_policy(), name, connector)[0]
        return asset_lists.list_decision(self._asset_policy(), target_type, name, connector)[0]

    def block(self, target_type: str, name: str, reason: str) -> None:
        self.block_for_connector(target_type, name, "", reason)

    def block_for_connector(self, target_type: str, name: str, connector: str, reason: str) -> None:
        """Add an operator block (asset_policy.<type>.denied)."""
        if self._legacy_rows():
            if self.store:
                self.store.set_action_field(target_type, name, "install", "block", reason, connector)
            return
        asset_lists.write_operator_decision(
            self.cfg, op=asset_lists.OP_BLOCK, target_type=target_type, name=name,
            connector=connector, reason=reason,
        )

    def allow(
        self, target_type: str, name: str, reason: str, source_path: str = "", *, clear_journal: bool = True,
    ) -> None:
        self.allow_for_connector(target_type, name, "", reason, source_path, clear_journal=clear_journal)

    def allow_for_connector(
        self,
        target_type: str,
        name: str,
        connector: str,
        reason: str,
        source_path: str = "",
        *,
        clear_journal: bool = True,
    ) -> None:
        """Add an operator allow (asset_policy.<type>.allowed, pinned to
        ``source_path`` when given) and, with ``clear_journal``, clear the
        residual quarantine and runtime-disable journal state so the allow
        takes full effect."""
        if self._legacy_rows():
            if self.store:
                self.store.set_action_field(target_type, name, "install", "allow", reason, connector)
        else:
            asset_lists.write_operator_decision(
                self.cfg, op=asset_lists.OP_ALLOW, target_type=target_type, name=name,
                connector=connector, reason=reason, source_path=source_path,
            )
        if self.store and clear_journal:
            self.store.clear_action_field(target_type, name, "file", connector)
            self.store.clear_action_field(target_type, name, "runtime", connector)

    def unblock(self, target_type: str, name: str, connector: str = "") -> None:
        """Remove an operator block, and the journal's scan-verdict install
        block, so a later restore no longer keeps the asset blocked."""
        self._refuse_if_managed(target_type, name, asset_lists.OP_UNBLOCK)
        self._drop_operator_entries(target_type, name, connector, asset_lists.OP_UNBLOCK)
        if self.store:
            self.store.clear_action_field(target_type, name, "install", connector)

    def _refuse_if_managed(self, target_type: str, name: str, op: str) -> None:
        """A managed standalone device takes block/allow/unblock from the
        admin config only, so an unblock is refused before it touches the
        operator lists or the journal (whose runtime disables the gateway
        still enforces)."""
        if not self._legacy_rows():
            asset_lists.refuse_if_managed(self.cfg, target_type=target_type, op=op, name=name)

    def _drop_operator_entries(self, target_type: str, name: str, connector: str, op: str) -> None:
        if self._legacy_rows():
            return
        decisions = ("block",) if op == asset_lists.OP_UNBLOCK else ("block", "allow")
        if any(asset_lists.has_entry(self.cfg, self.store, target_type, name, connector, d) for d in decisions):
            asset_lists.write_operator_decision(
                self.cfg, op=op, target_type=target_type, name=name, connector=connector,
            )

    # Tool rules (asset_policy.tool) are presented as ActionEntry rows keyed
    # "@<connector>/<tool>" (scoped) or "<tool>" (unscoped), the shape the
    # tool commands render.

    def block_tool_for_connector(self, tool_name: str, connector: str, reason: str) -> None:
        self.block_for_connector("tool", tool_name, connector, reason)

    def allow_tool_for_connector(self, tool_name: str, connector: str, reason: str) -> None:
        self.allow_for_connector("tool", tool_name, connector, reason)

    def unblock_tool_for_connector(self, tool_name: str, connector: str = "") -> None:
        """Remove the tool's block or allow at exactly this connector scope."""
        self._refuse_if_managed("tool", tool_name, asset_lists.OP_CLEAR)
        if self._legacy_rows():
            if self.store:
                target = f"@{connector}/{tool_name}" if connector else tool_name
                self.store.clear_action_field("tool", target, "install")
            return
        self._drop_operator_entries("tool", tool_name, connector, asset_lists.OP_CLEAR)

    def list_blocked_tools(self) -> list[ActionEntry]:
        return [e for e in self._tool_entries() if e.actions.install == "block"]

    def list_allowed_tools(self) -> list[ActionEntry]:
        return [e for e in self._tool_entries() if e.actions.install == "allow"]

    def _tool_entries(self) -> list[ActionEntry]:
        if self._legacy_rows():
            return self.store.list_actions_by_type("tool") if self.store else []
        return _tool_policy_entries(getattr(self._asset_policy(), "tool", None))

    # ------------------------------------------------------------------
    # Enforcement journal (audit.db actions)
    #
    # A bare entry (connector="") is GLOBAL; a non-empty connector NARROWS
    # the entry to that peer. Reads resolve most-specific-wins per field.
    # ------------------------------------------------------------------

    def record_scan_block(self, target_type: str, name: str, connector: str, reason: str) -> None:
        """Journal a scan verdict's install block (never operator policy)."""
        if self.store:
            self.store.set_action_field(target_type, name, "install", "block", reason, connector)

    def _journal_install_is(self, target_type: str, name: str, connector: str, want: str) -> bool:
        if not self.store:
            return False
        if connector:
            scoped = self.store.get_action(target_type, name, connector)
            if scoped is not None and scoped.actions.install:
                return scoped.actions.install == want
        return self.store.has_action(target_type, name, "install", want)

    def is_quarantined(self, target_type: str, name: str) -> bool:
        return self.is_quarantined_for_connector(target_type, name, "")

    def is_quarantined_for_connector(self, target_type: str, name: str, connector: str = "") -> bool:
        if not self.store:
            return False
        if connector:
            scoped = self.store.get_action(target_type, name, connector)
            if scoped is not None and scoped.actions.file:
                return scoped.actions.file == "quarantine"
        return self.store.has_action(target_type, name, "file", "quarantine")

    def quarantine(self, target_type: str, name: str, reason: str) -> None:
        self.quarantine_for_connector(target_type, name, "", reason)

    def quarantine_for_connector(self, target_type: str, name: str, connector: str, reason: str) -> None:
        if self.store:
            self.store.set_action_field(target_type, name, "file", "quarantine", reason, connector)

    def clear_quarantine(self, target_type: str, name: str) -> None:
        self.clear_quarantine_for_connector(target_type, name, "")

    def clear_quarantine_for_connector(self, target_type: str, name: str, connector: str = "") -> None:
        if self.store:
            self.store.clear_action_field(target_type, name, "file", connector)

    def disable(self, target_type: str, name: str, reason: str) -> None:
        self.disable_for_connector(target_type, name, "", reason)

    def disable_for_connector(self, target_type: str, name: str, connector: str, reason: str) -> None:
        if self.store:
            self.store.set_action_field(target_type, name, "runtime", "disable", reason, connector)

    def enable(self, target_type: str, name: str) -> None:
        self.enable_for_connector(target_type, name, "")

    def enable_for_connector(self, target_type: str, name: str, connector: str = "") -> None:
        if self.store:
            self.store.clear_action_field(target_type, name, "runtime", connector)

    def set_source_path(self, target_type: str, name: str, path: str, connector: str = "") -> None:
        if self.store:
            self.store.set_source_path(target_type, name, path, connector)

    def get_action(self, target_type: str, name: str, connector: str = "") -> ActionEntry | None:
        if target_type == "tool" and not self._legacy_rows():
            return next((e for e in self._tool_entries() if e.target_name == name), None)
        if not self.store:
            return None
        return self.store.get_action(target_type, name, connector)

    def list_by_type(self, target_type: str) -> list[ActionEntry]:
        if target_type == "tool":
            return self._tool_entries()
        if not self.store:
            return []
        return self.store.list_actions_by_type(target_type)

    def remove_action(self, target_type: str, name: str) -> None:
        self.remove_action_for_connector(target_type, name, "")

    def remove_action_for_connector(self, target_type: str, name: str, connector: str = "") -> None:
        """Remove all enforcement state at exactly this scope: the operator
        block/allow entries and the journal row."""
        self._refuse_if_managed(target_type, name, asset_lists.OP_CLEAR)
        self._drop_operator_entries(target_type, name, connector, asset_lists.OP_CLEAR)
        if self.store:
            self.store.remove_action(target_type, name, connector)
