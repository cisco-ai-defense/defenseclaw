# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Pure Inventory state for the Textual TUI."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from typing import Any, Literal

from defenseclaw.tui.services import connector_filter as connector_filter_svc
from defenseclaw.tui.services.overview_state import friendly_connector_name

InventorySubTab = Literal[
    "summary", "skills", "plugins", "mcp", "agents", "tools", "models", "memory", "ide_plugins"
]
InventoryFilter = Literal["", "eligible", "warning", "blocked", "loaded", "disabled"]

INVENTORY_CATEGORIES: tuple[str, ...] = (
    "skills", "plugins", "mcp", "agents", "tools", "models", "memory", "ide_plugins"
)
FAST_SCAN_CATEGORIES: tuple[str, ...] = ("skills", "plugins", "mcp")
INVENTORY_SUBTABS: tuple[InventorySubTab, ...] = (
    "summary",
    "skills",
    "plugins",
    "mcp",
    "agents",
    "tools",
    "models",
    "memory",
    "ide_plugins",
)
INVENTORY_SUBTAB_LABELS: Mapping[InventorySubTab, str] = {
    "summary": "Summary",
    "skills": "Skills",
    "plugins": "Plugins",
    "mcp": "MCPs",
    "agents": "Agents",
    "tools": "Tools",
    "models": "Models",
    "memory": "Memory",
    "ide_plugins": "IDE plugins",
}

# IDE cell suffix for a plugin of a remote install; mirrors
# ``defenseclaw agent ide-plugins``.
IDE_REMOTE_LABELS: Mapping[str, str] = {
    "ssh_server": "ssh",
    "jetbrains_remote_dev": "remote dev",
}

# Enabled cell for an IDE plugin row; mirrors ``defenseclaw agent ide-plugins``.
IDE_PLUGIN_ENABLED_LABELS: Mapping[str, str] = {
    "enabled": "yes",
    "disabled": "no",
    "client_side_unknown": "client side",
    "unknown": "unknown",
}


@dataclass(frozen=True)
class InventoryCommandIntent:
    label: str
    args: tuple[str, ...]
    binary: str = "defenseclaw"
    category: str = "info"
    hint: str = ""

    @property
    def argv(self) -> tuple[str, ...]:
        return (self.binary, *self.args)


@dataclass(frozen=True)
class InventoryPanelAction:
    handled: bool
    intent: InventoryCommandIntent | None = None
    hint: str = ""
    detail_opened: bool = False
    detail_closed: bool = False


@dataclass(frozen=True)
class InventorySkill:
    id: str
    source: str = ""
    eligible: bool = False
    enabled: bool = False
    bundled: bool = False
    description: str = ""
    emoji: str = ""
    verdict: str = ""
    verdict_detail: str = ""
    scan_findings: int = 0
    scan_severity: str = ""
    scan_target: str = ""
    # 8.13 pass 2: connector this entity was inventoried from. Empty for
    # single-connector installs; set when the app merges ``aibom scan`` across
    # every active connector so the CONNECTOR column can attribute each row.
    connector: str = ""

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> InventorySkill:
        return cls(
            id=str(raw.get("id") or ""),
            source=str(raw.get("source") or ""),
            eligible=bool(raw.get("eligible")),
            enabled=bool(raw.get("enabled")),
            bundled=bool(raw.get("bundled")),
            description=str(raw.get("description") or ""),
            emoji=str(raw.get("emoji") or ""),
            verdict=str(raw.get("policy_verdict") or raw.get("verdict") or ""),
            verdict_detail=str(raw.get("policy_detail") or raw.get("verdict_detail") or ""),
            scan_findings=int(raw.get("scan_findings") or 0),
            scan_severity=str(raw.get("scan_severity") or ""),
            scan_target=str(raw.get("scan_target") or ""),
        )


@dataclass(frozen=True)
class InventoryPlugin:
    id: str
    name: str = ""
    version: str = ""
    origin: str = ""
    enabled: bool = False
    status: str = ""
    verdict: str = ""
    verdict_detail: str = ""
    scan_findings: int = 0
    scan_severity: str = ""
    scan_target: str = ""
    connector: str = ""
    user: str = ""

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> InventoryPlugin:
        return cls(
            id=str(raw.get("id") or ""),
            name=str(raw.get("name") or ""),
            version=str(raw.get("version") or ""),
            # GAP-1593: Hermes rows carry source_kind and enabled, not
            # origin and status; show them as 'plugin list' does.
            origin=str(raw.get("origin") or raw.get("source_kind") or ""),
            enabled=bool(raw.get("enabled")),
            status=str(
                raw.get("status")
                or (("enabled" if raw.get("enabled") else "disabled") if "enabled" in raw else "")
            ),
            verdict=str(raw.get("policy_verdict") or raw.get("verdict") or ""),
            verdict_detail=str(raw.get("policy_detail") or raw.get("verdict_detail") or ""),
            scan_findings=int(raw.get("scan_findings") or 0),
            scan_severity=str(raw.get("scan_severity") or ""),
            scan_target=str(raw.get("scan_target") or ""),
            user=_user_of(raw),
        )

    @property
    def display_name(self) -> str:
        return self.name or self.id


@dataclass(frozen=True)
class InventoryMCP:
    id: str
    source: str = ""
    transport: str = ""
    command: str = ""
    url: str = ""
    connector: str = ""
    user: str = ""

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> InventoryMCP:
        return cls(
            id=str(raw.get("id") or ""),
            source=str(raw.get("source") or ""),
            transport=str(raw.get("transport") or ""),
            command=str(raw.get("command") or ""),
            url=str(raw.get("url") or ""),
            user=_user_of(raw),
        )

    @property
    def command_or_url(self) -> str:
        return self.command or self.url


@dataclass(frozen=True)
class InventoryAgent:
    id: str
    model: str = ""
    workspace: str = ""
    default: bool = False
    source: str = ""
    bindings: Mapping[str, Any] | None = None
    max_concurrent: int = 0
    connector: str = ""
    user: str = ""
    # Set on rows from ``defenseclaw agent identities`` (stable agent ids).
    identity: bool = False
    first_seen: str = ""
    last_seen: str = ""
    sessions_seen: int = 0

    @classmethod
    def from_identity(cls, raw: Mapping[str, Any]) -> InventoryAgent:
        return cls(
            id=str(raw.get("agent_id") or ""),
            source="agent identity",
            connector=str(raw.get("connector") or ""),
            user=_user_of(raw),
            identity=True,
            first_seen=str(raw.get("first_seen") or ""),
            last_seen=str(raw.get("last_seen") or ""),
            sessions_seen=_safe_int(raw.get("sessions_seen")),
        )

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> InventoryAgent:
        bindings = raw.get("bindings")
        parsed_bindings: Mapping[str, Any] | None
        if isinstance(bindings, Mapping):
            parsed_bindings = bindings
        elif isinstance(bindings, str) and bindings not in {"", "null", "0"}:
            try:
                decoded = json.loads(bindings)
            except json.JSONDecodeError:
                decoded = None
            parsed_bindings = decoded if isinstance(decoded, Mapping) else None
        else:
            parsed_bindings = None
        return cls(
            id=str(raw.get("id") or ""),
            model=str(raw.get("model") or ""),
            workspace=str(raw.get("workspace") or ""),
            default=bool(raw.get("is_default") or raw.get("default")),
            source=str(raw.get("source") or ""),
            bindings=parsed_bindings,
            max_concurrent=int(raw.get("subagents_max_concurrent") or raw.get("max_concurrent") or 0),
            user=_user_of(raw),
        )


@dataclass(frozen=True)
class InventoryIDEPlugin:
    """One IDE extension or plugin from the gateway's IDE inventory."""

    plugin_id: str
    fingerprint: str = ""
    user: str = ""
    ide_family: str = ""
    ide_product: str = ""
    display_name: str = ""
    publisher: str = ""
    version: str = ""
    enabled: str = "unknown"
    enabled_source: str = ""
    scope: str = ""
    remote_kind: str = ""
    is_ai: bool = False
    ai_signature_id: str = ""
    installed_at: str = ""
    last_seen: str = ""

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> InventoryIDEPlugin:
        return cls(
            plugin_id=str(raw.get("plugin_id") or ""),
            fingerprint=str(raw.get("fingerprint") or ""),
            user=_user_of(raw),
            ide_family=str(raw.get("ide_family") or ""),
            ide_product=str(raw.get("ide_product") or ""),
            display_name=str(raw.get("display_name") or ""),
            publisher=str(raw.get("publisher") or ""),
            version=str(raw.get("version") or ""),
            enabled=str(raw.get("enabled") or "unknown"),
            enabled_source=str(raw.get("enabled_source") or ""),
            scope=str(raw.get("scope") or ""),
            remote_kind=str(raw.get("remote_kind") or ""),
            is_ai=bool(raw.get("is_ai")),
            ai_signature_id=str(raw.get("ai_signature_id") or ""),
            installed_at=str(raw.get("installed_at") or ""),
            last_seen=str(raw.get("last_seen") or ""),
        )

    @property
    def label(self) -> str:
        return self.plugin_id or self.display_name

    @property
    def enabled_label(self) -> str:
        return IDE_PLUGIN_ENABLED_LABELS.get(self.enabled, self.enabled)

    @property
    def location(self) -> str:
        if self.remote_kind:
            return IDE_REMOTE_LABELS.get(self.remote_kind, "remote")
        return "remote" if self.scope == "remote" else ""

    @property
    def ide_label(self) -> str:
        product = self.ide_product or self.ide_family
        return f"{product} ({self.location})" if self.location else product

    @property
    def key(self) -> str:
        return self.fingerprint or "|".join((self.user, self.ide_product, self.plugin_id, self.scope))


@dataclass(frozen=True)
class InventoryTool:
    id: str
    name: str = ""
    kind: str = ""
    source: str = ""
    description: str = ""
    connector: str = ""

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> InventoryTool:
        return cls(
            id=str(raw.get("id") or raw.get("name") or ""),
            name=str(raw.get("name") or ""),
            kind=str(raw.get("kind") or ""),
            source=str(raw.get("source") or ""),
            description=str(raw.get("description") or ""),
        )

    @property
    def display_name(self) -> str:
        return self.name or self.id


@dataclass(frozen=True)
class InventoryModelProvider:
    id: str
    source: str = ""
    default_model: str = ""
    fallbacks: tuple[str, ...] = ()
    allowed: tuple[str, ...] = ()
    config_path: str = ""
    status: str = ""
    connector: str = ""

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> InventoryModelProvider:
        return cls(
            id=str(raw.get("id") or ""),
            source=str(raw.get("source") or ""),
            default_model=str(raw.get("default_model") or ""),
            fallbacks=tuple(str(item) for item in raw.get("fallbacks") or ()),
            allowed=tuple(str(item) for item in raw.get("allowed") or ()),
            config_path=str(raw.get("config_path") or ""),
            status=str(raw.get("status") or ""),
        )


@dataclass(frozen=True)
class InventoryMemory:
    id: str
    backend: str = ""
    files: int = 0
    chunks: int = 0
    db_path: str = ""
    provider: str = ""
    sources: tuple[str, ...] = ()
    workspace: str = ""
    fts_available: bool = False
    vector_enabled: bool = False
    connector: str = ""

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> InventoryMemory:
        return cls(
            id=str(raw.get("id") or ""),
            backend=str(raw.get("backend") or ""),
            files=int(raw.get("files") or 0),
            chunks=int(raw.get("chunks") or 0),
            db_path=str(raw.get("db_path") or ""),
            provider=str(raw.get("provider") or ""),
            sources=tuple(str(item) for item in raw.get("sources") or ()),
            workspace=str(raw.get("workspace") or ""),
            fts_available=bool(raw.get("fts_available")),
            vector_enabled=bool(raw.get("vector_enabled")),
        )


@dataclass(frozen=True)
class InventorySummary:
    total_items: int = 0
    skills: Mapping[str, Any] = field(default_factory=dict)
    plugins: Mapping[str, Any] = field(default_factory=dict)
    mcp: Mapping[str, Any] = field(default_factory=dict)
    agents: Mapping[str, Any] = field(default_factory=dict)
    # Counted only: rule files ("Rules (Hermes 1)" in aibom) have no sub-tab
    # yet, but the Summary lists them so every aibom category shows (GAP-1546).
    rules: Mapping[str, Any] = field(default_factory=dict)
    tools: Mapping[str, Any] = field(default_factory=dict)
    models: Mapping[str, Any] = field(default_factory=dict)
    memory: Mapping[str, Any] = field(default_factory=dict)
    errors: Any = 0
    limitations: Any = 0
    policy_skills: Mapping[str, Any] = field(default_factory=dict)
    scan_skills: Mapping[str, Any] = field(default_factory=dict)
    policy_plugins: Mapping[str, Any] = field(default_factory=dict)
    scan_plugins: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any] | None) -> InventorySummary:
        if not raw:
            return cls()
        return cls(
            total_items=int(raw.get("total_items") or 0),
            skills=_mapping(raw.get("skills")),
            plugins=_mapping(raw.get("plugins")),
            mcp=_mapping(raw.get("mcp")),
            agents=_mapping(raw.get("agents")),
            rules=_mapping(raw.get("rules")),
            tools=_mapping(raw.get("tools")),
            models=_mapping(raw.get("model_providers")),
            memory=_mapping(raw.get("memory")),
            errors=raw.get("errors") or 0,
            limitations=raw.get("limitations") or 0,
            policy_skills=_mapping(raw.get("policy_skills")),
            scan_skills=_mapping(raw.get("scan_skills")),
            policy_plugins=_mapping(raw.get("policy_plugins")),
            scan_plugins=_mapping(raw.get("scan_plugins")),
        )


@dataclass(frozen=True)
class InventoryLimitation:
    connector: str = ""
    category: str = ""
    status: str = "unsupported"
    reason: str = ""

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> InventoryLimitation:
        return cls(
            connector=str(raw.get("connector") or ""),
            category=str(raw.get("category") or ""),
            status=str(raw.get("status") or "unsupported"),
            reason=str(raw.get("reason") or ""),
        )


@dataclass(frozen=True)
class InventorySnapshot:
    version: str = ""
    generated_at: str = ""
    openclaw_config: str = ""
    claw_home: str = ""
    claw_mode: str = ""
    connector: str = ""
    connector_home: str = ""
    connector_config_files: tuple[str, ...] = ()
    connector_skill_dirs: tuple[str, ...] = ()
    connector_plugin_dirs: tuple[str, ...] = ()
    connector_mcp_files: tuple[str, ...] = ()
    connector_rule_files: tuple[str, ...] = ()
    connector_policy_settings: Mapping[str, Any] = field(default_factory=dict)
    live: bool = False
    skills: tuple[InventorySkill, ...] = ()
    plugins: tuple[InventoryPlugin, ...] = ()
    mcps: tuple[InventoryMCP, ...] = ()
    agents: tuple[InventoryAgent, ...] = ()
    tools: tuple[InventoryTool, ...] = ()
    models: tuple[InventoryModelProvider, ...] = ()
    memory: tuple[InventoryMemory, ...] = ()
    errors: tuple[Any, ...] = ()
    limitations: tuple[InventoryLimitation, ...] = ()
    summary: InventorySummary = field(default_factory=InventorySummary)
    # IDE plugins come from the gateway, once per user, not per connector.
    # ``ide_collected`` is False when this scan did not ask for them.
    ide_plugins: tuple[InventoryIDEPlugin, ...] = ()
    ide_collected: bool = False
    ide_note: str = ""

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> InventorySnapshot:
        summary_raw = raw.get("summary")
        return cls(
            version=str(raw.get("version") or ""),
            generated_at=str(raw.get("generated_at") or ""),
            openclaw_config=str(raw.get("openclaw_config") or ""),
            claw_home=str(raw.get("claw_home") or ""),
            claw_mode=str(raw.get("claw_mode") or ""),
            connector=str(raw.get("connector") or ""),
            connector_home=str(raw.get("connector_home") or ""),
            connector_config_files=tuple(str(item) for item in raw.get("connector_config_files") or ()),
            connector_skill_dirs=tuple(str(item) for item in raw.get("connector_skill_dirs") or ()),
            connector_plugin_dirs=tuple(str(item) for item in raw.get("connector_plugin_dirs") or ()),
            connector_mcp_files=tuple(str(item) for item in raw.get("connector_mcp_files") or ()),
            connector_rule_files=tuple(str(item) for item in raw.get("connector_rule_files") or ()),
            connector_policy_settings=(
                raw.get("connector_policy_settings")
                if isinstance(raw.get("connector_policy_settings"), Mapping)
                else {}
            ),
            live=bool(raw.get("live")),
            skills=tuple(
                InventorySkill.from_mapping(item)
                for item in raw.get("skills") or ()
                if isinstance(item, Mapping)
            ),
            plugins=tuple(
                InventoryPlugin.from_mapping(item)
                for item in raw.get("plugins") or ()
                if isinstance(item, Mapping)
            ),
            mcps=tuple(
                InventoryMCP.from_mapping(item)
                for item in raw.get("mcp") or ()
                if isinstance(item, Mapping)
            ),
            agents=tuple(
                InventoryAgent.from_mapping(item)
                for item in raw.get("agents") or ()
                if isinstance(item, Mapping)
            ),
            tools=tuple(
                InventoryTool.from_mapping(item)
                for item in raw.get("tools") or ()
                if isinstance(item, Mapping)
            ),
            models=tuple(
                InventoryModelProvider.from_mapping(item)
                for item in raw.get("model_providers") or ()
                if isinstance(item, Mapping)
            ),
            memory=tuple(
                InventoryMemory.from_mapping(item)
                for item in raw.get("memory") or ()
                if isinstance(item, Mapping)
            ),
            errors=tuple(raw.get("errors") or ()),
            limitations=tuple(
                InventoryLimitation.from_mapping(item)
                for item in raw.get("limitations") or ()
                if isinstance(item, Mapping)
            ),
            summary=InventorySummary.from_mapping(summary_raw if isinstance(summary_raw, Mapping) else None),
            ide_plugins=tuple(
                InventoryIDEPlugin.from_mapping(item)
                for item in raw.get("ide_plugins") or ()
                if isinstance(item, Mapping)
            ),
            ide_collected="ide_plugins" in raw,
            ide_note=str(raw.get("ide_plugins_note") or ""),
        )

    @classmethod
    def from_json(cls, text: str) -> InventorySnapshot:
        try:
            raw = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError(f"parse inventory json: {exc}") from exc
        if raw == []:
            # aibom scan --json with no connector configured (GAP-2073).
            raw = {}
        if not isinstance(raw, Mapping):
            raise ValueError("parse inventory json: expected object")
        return cls.from_mapping(raw)


@dataclass(frozen=True)
class InventorySummaryState:
    connector_name: str
    source_label: str
    home_path: str
    config_path: str
    counts: Mapping[str, str]
    policy_skill_verdicts: Mapping[str, str]
    policy_plugin_verdicts: Mapping[str, str]
    version: str = ""
    generated_at: str = ""
    errors: str = "0"
    limitations: str = "0"
    scan_skill_coverage: Mapping[str, str] = field(default_factory=dict)
    scan_plugin_coverage: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class InventoryDetailInfo:
    title: str
    fields: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class InventorySubTabInfo:
    subtab: InventorySubTab
    label: str
    active: bool = False
    count: int | None = None

    @property
    def display_label(self) -> str:
        if self.count is None:
            return self.label
        return f"{self.label} ({self.count})"


@dataclass(frozen=True)
class InventoryScopeChip:
    category: str
    label: str
    active: bool = False


@dataclass(frozen=True)
class InventoryScopeState:
    label: str
    chips: tuple[InventoryScopeChip, ...]
    only_arg: str = ""
    hint: str = "(o toggles fast, r reloads)"


def _row_key(row: object) -> tuple[str, ...]:
    """Identity of an inventory row that survives a rescan."""

    if isinstance(row, InventoryIDEPlugin):
        return (row.key,)
    return tuple(str(getattr(row, name, "") or "") for name in ("id", "connector", "user", "identity"))


class InventoryPanelModel:
    """Go-compatible pure model for inventory scope, filters, cursor and detail."""

    def __init__(self, *, connector: str = "") -> None:
        self.active_sub: InventorySubTab = "summary"
        self.loading = False
        # E1: when the operator focuses a connector (TUI `m` in a
        # multi-connector install) the Inventory view passes
        # ``--connector <name>`` so it inventories THAT connector, not the
        # primary. Off by default ⇒ single-connector behaviour unchanged.
        self.connector_focus_enabled = False
        self.loaded = False
        self.inventory: InventorySnapshot | None = None
        self.cursor = 0
        self.message = ""
        self.detail_open = False
        self.filter: InventoryFilter = ""
        self.category_scope: tuple[str, ...] = ()
        self.connector = connector
        self.width = 0
        self.height = 0
        # 8.13 pass 2: when the app merges the inventory across every active
        # connector it sets ``show_connector_column = True`` and tags entities
        # with their connector. ``connector_filter`` ("" = All) then narrows the
        # merged rows in-memory, mirroring the catalog/signal panes.
        self.show_connector_column = False
        self.connector_filter = ""
        # Per-connector snapshots kept so the Summary sub-tab can show a
        # breakdown; ``inventory`` holds the merged view used by every tab.
        self.connector_snapshots: tuple[tuple[str, InventorySnapshot], ...] = ()
        # Stable agent ids from ``defenseclaw agent identities --json``; empty
        # when the command is unavailable or fails.
        self.agent_identities: tuple[InventoryAgent, ...] = ()

    def set_size(self, width: int, height: int) -> None:
        self.width = width
        self.height = height

    def set_connector(self, connector: str) -> None:
        self.connector = connector

    def set_connector_filter(self, connector: str) -> None:
        """Narrow the merged inventory to one connector ("" = All)."""

        connector = (connector or "").strip().lower()
        if connector == self.connector_filter:
            return
        self.connector_filter = connector
        self.cursor = 0
        self.detail_open = False

    def _connector_keep(self, entity: object) -> bool:
        if not self.connector_filter:
            return True
        return connector_filter_svc.filter_allows(
            self.connector_filter, str(getattr(entity, "connector", "") or "")
        )

    def set_active_subtab(self, subtab: InventorySubTab) -> None:
        if subtab not in INVENTORY_SUBTABS:
            return
        self.active_sub = subtab
        self.cursor = 0
        self.detail_open = False

    def move_subtab(self, delta: int) -> None:
        index = INVENTORY_SUBTABS.index(self.active_sub)
        next_index = max(0, min(index + delta, len(INVENTORY_SUBTABS) - 1))
        self.set_active_subtab(INVENTORY_SUBTABS[next_index])

    def set_active_subtab_index(self, index: int) -> None:
        if 0 <= index < len(INVENTORY_SUBTABS):
            self.set_active_subtab(INVENTORY_SUBTABS[index])

    def load_args(self) -> tuple[str, ...]:
        args = ["aibom", "scan", "--json"]
        if self.category_scope:
            args.extend(("--only", ",".join(self.category_scope)))
        # E1: follow the focused connector when one is selected.
        if self.connector_focus_enabled and self.connector:
            args.extend(("--connector", self.connector))
        return tuple(args)

    def load_intent(self) -> InventoryCommandIntent:
        return InventoryCommandIntent(
            label="aibom scan --json",
            args=self.load_args(),
            hint="Loading inventory...",
        )

    def load_intent_for(self, connector: str) -> InventoryCommandIntent:
        """``load_intent`` forced to a specific connector (merged loads).

        Temporarily pins the connector + focus so ``load_args`` appends
        ``--connector <name>``, then restores the prior state so single-
        connector behaviour is untouched.
        """

        saved_connector = self.connector
        saved_focus = self.connector_focus_enabled
        try:
            self.connector = connector
            self.connector_focus_enabled = bool(connector)
            return self.load_intent()
        finally:
            self.connector = saved_connector
            self.connector_focus_enabled = saved_focus

    def start_loading(self) -> InventoryCommandIntent:
        self.loading = True
        return self.load_intent()

    def set_category_scope(self, categories: Sequence[str] | None) -> None:
        if not categories:
            self.category_scope = ()
            return
        allowed = set(INVENTORY_CATEGORIES)
        filtered = tuple(category for category in categories if category in allowed)
        self.category_scope = filtered

    def toggle_category(self, category: str) -> None:
        if category not in INVENTORY_CATEGORIES:
            return
        scope = list(self.category_scope)
        if category in scope:
            scope.remove(category)
        else:
            scope.append(category)
        self.category_scope = tuple(scope)

    def toggle_fast_scan(self) -> None:
        if self.is_fast_scan():
            self.category_scope = ()
        else:
            self.category_scope = FAST_SCAN_CATEGORIES

    def is_fast_scan(self) -> bool:
        return set(self.category_scope) == set(FAST_SCAN_CATEGORIES) and len(self.category_scope) == len(
            FAST_SCAN_CATEGORIES
        )

    def scope_label(self) -> str:
        if not self.category_scope:
            return "Scope (all)"
        if self.is_fast_scan():
            return "Scope (fast)"
        return "Scope"

    def scope_state(self) -> InventoryScopeState:
        active = set(INVENTORY_CATEGORIES if not self.category_scope else self.category_scope)
        chips = tuple(
            InventoryScopeChip(category=category, label=f" {category} ", active=category in active)
            for category in INVENTORY_CATEGORIES
        )
        return InventoryScopeState(
            label=self.scope_label(),
            chips=chips,
            only_arg=",".join(self.category_scope),
        )

    def subtab_info(self) -> tuple[InventorySubTabInfo, ...]:
        counts = self._subtab_counts()
        return tuple(
            InventorySubTabInfo(
                subtab=subtab,
                label=INVENTORY_SUBTAB_LABELS[subtab],
                active=subtab == self.active_sub,
                count=counts.get(subtab),
            )
            for subtab in INVENTORY_SUBTABS
        )

    def apply_loaded(
        self,
        snapshot: InventorySnapshot | None = None,
        error: Exception | str | None = None,
    ) -> None:
        self.loading = False
        if error is not None:
            self.message = f"Error loading inventory: {error}"
            return
        selected = self._selected_key()
        self.inventory = snapshot
        self.loaded = snapshot is not None
        self.message = ""
        self._reselect(selected)

    def apply_json(self, text: str) -> None:
        self.apply_loaded(InventorySnapshot.from_json(text))

    def identities_intent(self) -> InventoryCommandIntent:
        return InventoryCommandIntent(
            label="agent identities --json",
            args=("agent", "identities", "--json"),
            hint="Loading agent identities...",
        )

    def apply_agent_identities(self, text: str | None) -> None:
        """Keep the agent identity rows; anything unreadable leaves none.

        Older installs have no ``agent identities`` command, so a missing or
        malformed answer is not an error the panel shows.
        """
        rows: tuple[InventoryAgent, ...] = ()
        if text:
            try:
                raw = json.loads(text)
            except (json.JSONDecodeError, ValueError):
                raw = None
            #  prints {enabled, identities}.
            identities = raw.get("identities") if isinstance(raw, Mapping) else None
            if isinstance(identities, list):
                rows = tuple(
                    InventoryAgent.from_identity(item)
                    for item in identities
                    if isinstance(item, Mapping) and item.get("agent_id")
                )
        selected = self._selected_key()
        self.agent_identities = rows
        self._reselect(selected)

    def apply_merged(self, results: Sequence[tuple[str, str | None]]) -> None:
        """Merge per-connector ``aibom scan`` payloads into one snapshot.

        ``results`` is ``[(connector, json_text_or_None)]``; a ``None`` payload
        means that connector's scan failed and is skipped. Each surviving
        snapshot has its entities tagged with the connector so the merged view
        can attribute every row, and the per-connector snapshots are retained
        for the Summary breakdown.
        """

        self.loading = False
        snapshots: list[tuple[str, InventorySnapshot]] = []
        for connector, text in results:
            if not text:
                continue
            try:
                snap = InventorySnapshot.from_json(text)
            except Exception:  # noqa: BLE001 - a bad payload skips one connector.
                continue
            snapshots.append((connector, self._tag_snapshot(snap, connector)))
        selected = self._selected_key()
        self.connector_snapshots = tuple(snapshots)
        if not snapshots:
            self.inventory = None
            self.loaded = False
            self._reselect(None)
            return
        self.inventory = self._merge_snapshots([snap for _connector, snap in snapshots])
        self.loaded = True
        self.message = ""
        self._reselect(selected)

    def _selected_key(self) -> tuple[str, ...] | None:
        rows = self._current_rows()
        return _row_key(rows[self.cursor]) if 0 <= self.cursor < len(rows) else None

    def _reselect(self, key: tuple[str, ...] | None) -> None:
        """Keep the selected row, and its open card, across a reload.

        The 60 s background refresh reloads the inventory with no user action;
        resetting the cursor and closing the card there lost the row the user
        was reading (GAP-0106). Only a row that is gone closes the card.
        """

        keys = [_row_key(row) for row in self._current_rows()]
        if key is not None and key in keys:
            self.cursor = keys.index(key)
            return
        self.set_cursor(self.cursor)
        self.detail_open = False

    @staticmethod
    def _tag_snapshot(snap: InventorySnapshot, connector: str) -> InventorySnapshot:
        return replace(
            snap,
            skills=tuple(replace(item, connector=connector) for item in snap.skills),
            plugins=tuple(replace(item, connector=connector) for item in snap.plugins),
            mcps=tuple(replace(item, connector=connector) for item in snap.mcps),
            agents=tuple(replace(item, connector=connector) for item in snap.agents),
            tools=tuple(replace(item, connector=connector) for item in snap.tools),
            models=tuple(replace(item, connector=connector) for item in snap.models),
            memory=tuple(replace(item, connector=connector) for item in snap.memory),
        )

    @staticmethod
    def _merge_snapshots(snaps: Sequence[InventorySnapshot]) -> InventorySnapshot:
        primary = snaps[0]
        skills = tuple(item for snap in snaps for item in snap.skills)
        plugins = tuple(item for snap in snaps for item in snap.plugins)
        mcps = tuple(item for snap in snaps for item in snap.mcps)
        agents = tuple(item for snap in snaps for item in snap.agents)
        tools = tuple(item for snap in snaps for item in snap.tools)
        models = tuple(item for snap in snaps for item in snap.models)
        memory = tuple(item for snap in snaps for item in snap.memory)
        # Every per-connector scan carries the same per-user IDE inventory.
        ide_seen: set[str] = set()
        ide_plugins: list[InventoryIDEPlugin] = []
        for snap in snaps:
            for item in snap.ide_plugins:
                if item.key not in ide_seen:
                    ide_seen.add(item.key)
                    ide_plugins.append(item)
        ide_collected = any(snap.ide_collected for snap in snaps)
        ide_note = next((snap.ide_note for snap in snaps if snap.ide_note), "") if not ide_plugins else ""
        total_errors = sum(len(snap.errors) for snap in snaps)
        limitations = tuple(item for snap in snaps for item in snap.limitations)
        rules = sum(_int_count(snap.summary.rules) for snap in snaps)
        total_items = (
            len(skills)
            + len(plugins)
            + len(mcps)
            + len(agents)
            + rules
            + len(tools)
            + len(models)
            + len(memory)
        )
        summary = InventorySummary(
            total_items=total_items,
            skills={"count": str(len(skills))},
            plugins={"count": str(len(plugins))},
            mcp={"count": str(len(mcps))},
            agents={"count": str(len(agents))},
            rules={"count": str(rules)},
            tools={"count": str(len(tools))},
            models={"count": str(len(models))},
            memory={"count": str(len(memory))},
            errors=str(total_errors),
            limitations=str(len(limitations)),
        )
        return replace(
            primary,
            connector="",
            skills=skills,
            plugins=plugins,
            mcps=mcps,
            agents=agents,
            tools=tools,
            models=models,
            memory=memory,
            errors=tuple(error for snap in snaps for error in snap.errors),
            limitations=limitations,
            summary=summary,
            ide_plugins=tuple(ide_plugins),
            ide_collected=ide_collected,
            ide_note=ide_note,
        )

    def scroll_by(self, delta: int) -> None:
        self.set_cursor(self.cursor + delta)

    def set_cursor(self, index: int) -> None:
        max_cursor = self.current_list_len() - 1
        if max_cursor < 0:
            self.cursor = 0
            return
        self.cursor = max(0, min(index, max_cursor))

    def cursor_at(self) -> int:
        return self.cursor

    def set_filter(self, value: InventoryFilter) -> None:
        self.filter = "" if self.filter == value else value
        self.cursor = 0
        self.detail_open = False

    def clear_filter(self) -> None:
        self.filter = ""
        self.cursor = 0

    def toggle_detail(self) -> None:
        if self.active_sub == "summary":
            return
        self.detail_open = not self.detail_open

    def current_list_len(self) -> int:
        return len(self._current_rows())

    def _current_rows(self) -> Sequence[object]:
        match self.active_sub:
            case "skills":
                return self.filtered_skills()
            case "plugins":
                return self.filtered_plugins()
            case "mcp":
                return self.filtered_mcps()
            case "agents":
                return self.filtered_agents()
            case "tools":
                return self.filtered_tools()
            case "models":
                return self.filtered_models()
            case "memory":
                return self.filtered_memory()
            case "ide_plugins":
                return self.filtered_ide_plugins()
            case _:
                return ()

    def filtered_skills(self) -> tuple[InventorySkill, ...]:
        if self.inventory is None:
            return ()
        skills = tuple(skill for skill in self.inventory.skills if self._connector_keep(skill))
        if not self.filter:
            return skills
        if self.filter == "eligible":
            return tuple(skill for skill in skills if skill.eligible)
        if self.filter == "warning":
            return tuple(skill for skill in skills if skill.verdict == "warning")
        if self.filter == "blocked":
            return tuple(skill for skill in skills if skill.verdict == "blocked")
        return skills

    def filtered_plugins(self) -> tuple[InventoryPlugin, ...]:
        if self.inventory is None:
            return ()
        plugins = tuple(plugin for plugin in self.inventory.plugins if self._connector_keep(plugin))
        if not self.filter:
            return plugins
        if self.filter == "loaded":
            return tuple(plugin for plugin in plugins if plugin.status == "loaded")
        if self.filter == "disabled":
            return tuple(plugin for plugin in plugins if plugin.status == "disabled")
        if self.filter == "blocked":
            return tuple(plugin for plugin in plugins if plugin.verdict == "blocked")
        return plugins

    def filtered_mcps(self) -> tuple[InventoryMCP, ...]:
        if self.inventory is None:
            return ()
        return tuple(mcp for mcp in self.inventory.mcps if self._connector_keep(mcp))

    def filtered_agents(self) -> tuple[InventoryAgent, ...]:
        if self.inventory is None:
            return ()
        agents = (*self.inventory.agents, *self.agent_identities)
        return tuple(agent for agent in agents if self._connector_keep(agent))

    def filtered_ide_plugins(self) -> tuple[InventoryIDEPlugin, ...]:
        # IDE plugins belong to a user, not a connector: the connector
        # filter does not narrow them.
        if self.inventory is None:
            return ()
        return self.inventory.ide_plugins

    @staticmethod
    def _multi_user(items: Sequence[object]) -> bool:
        users = {str(getattr(item, "user", "") or "") for item in items} - {""}
        return len(users) > 1

    def _show_user_column(self) -> bool:
        if self.inventory is None:
            return False
        match self.active_sub:
            case "plugins":
                return self._multi_user(self.inventory.plugins)
            case "mcp":
                return self._multi_user(self.inventory.mcps)
            case "agents":
                return self._multi_user((*self.inventory.agents, *self.agent_identities))
            case _:
                return False

    def filtered_tools(self) -> tuple[InventoryTool, ...]:
        if self.inventory is None:
            return ()
        return tuple(tool for tool in self.inventory.tools if self._connector_keep(tool))

    def filtered_models(self) -> tuple[InventoryModelProvider, ...]:
        if self.inventory is None:
            return ()
        return tuple(model for model in self.inventory.models if self._connector_keep(model))

    def filtered_memory(self) -> tuple[InventoryMemory, ...]:
        if self.inventory is None:
            return ()
        return tuple(mem for mem in self.inventory.memory if self._connector_keep(mem))

    def _summary_inventory(self) -> InventorySnapshot | None:
        """Snapshot backing the Summary sub-tab, honoring the connector filter.

        When the shared chip narrows to a single connector we surface *that*
        connector's own scan snapshot (its real Source/Home/Config + per-
        connector counts) instead of the merged roll-up — otherwise the
        Summary would keep showing the primary connector's attributes no
        matter which connector the operator selects. With no filter ("All")
        the merged snapshot is used so the totals span every connector.
        """

        if self.inventory is None:
            return None
        selected = (self.connector_filter or "").strip().lower()
        if selected:
            for connector, snap in self.connector_snapshots:
                if connector.strip().lower() == selected:
                    return snap
        return self.inventory

    def summary_state(self) -> InventorySummaryState | None:
        inv = self._summary_inventory()
        if inv is None:
            return None
        connector = inv.connector or inv.claw_mode or self.connector
        source_label = friendly_connector_name(connector)
        if connector and source_label.lower() != connector.lower():
            source_label = f"{source_label} ({connector})"
        counts = {
            "total_items": str(inv.summary.total_items),
            "skills": _map_val(inv.summary.skills, "count"),
            "plugins": _map_val(inv.summary.plugins, "count"),
            "mcp": _map_val(inv.summary.mcp, "count"),
            "agents": _map_val(inv.summary.agents, "count"),
            "rules": str(_int_count(inv.summary.rules)),
            "tools": _map_val(inv.summary.tools, "count"),
            "models": _map_val(inv.summary.models, "count"),
            "memory": _map_val(inv.summary.memory, "count"),
        }
        from defenseclaw.inventory.claw_inventory import aibom_display_config

        config_path = aibom_display_config({
            "connector": connector,
            "openclaw_config": inv.openclaw_config,
            "connector_config_files": list(inv.connector_config_files),
            "connector_mcp_files": list(inv.connector_mcp_files),
        }) or inv.openclaw_config
        return InventorySummaryState(
            connector_name=connector,
            source_label=source_label,
            home_path=inv.connector_home or inv.claw_home,
            config_path=config_path,
            counts=counts,
            policy_skill_verdicts=_string_map(inv.summary.policy_skills),
            policy_plugin_verdicts=_string_map(inv.summary.policy_plugins),
            version=inv.version,
            generated_at=inv.generated_at,
            errors=str(inv.summary.errors),
            limitations=str(inv.summary.limitations),
            scan_skill_coverage=_string_map(inv.summary.scan_skills),
            scan_plugin_coverage=_string_map(inv.summary.scan_plugins),
        )

    def summary_table_rows(self) -> tuple[tuple[str, str], ...]:
        summary = self.summary_state()
        if summary is None:
            return ()
        inv = self._summary_inventory()
        # Under "All" in a multi-connector install the merged snapshot's
        # Source/Home/Config belong to the primary connector only; name every
        # connector instead and leave the per-connector paths to the filter
        # (GAP-1156).
        merged_names = (
            [friendly_connector_name(name) for name, _snap in self.connector_snapshots]
            if not (self.connector_filter or "").strip() and len(self.connector_snapshots) > 1
            else []
        )
        if merged_names:
            origin: list[tuple[str, str]] = [
                ("Source", f"All {len(merged_names)} connectors: {', '.join(merged_names)}"),
                ("Home / Config", "per connector (press m to pick one)"),
            ]
        else:
            origin = [
                ("Source", summary.source_label),
                ("Home", summary.home_path),
                ("Config", summary.config_path),
            ]
        rows: list[tuple[str, str]] = [
            ("AIBOM version", summary.version),
            ("Generated", summary.generated_at),
            *origin,
            ("Total items", summary.counts["total_items"]),
            ("Skills", _count_with_suffix(summary.counts["skills"], "eligible", inv.summary.skills if inv else {})),
            (
                "Plugins",
                _plugin_count_summary(
                    summary.counts["plugins"],
                    inv.summary.plugins if inv else {},
                ),
            ),
            ("MCPs", summary.counts["mcp"]),
            ("Agents", summary.counts["agents"]),
            (
                "Rules",
                summary.counts["rules"]
                if summary.counts["rules"] == "0"
                else f"{summary.counts['rules']} (list them with: defenseclaw aibom scan)",
            ),
            ("Tools", summary.counts["tools"]),
            ("Models", summary.counts["models"]),
            ("Memory", summary.counts["memory"]),
        ]
        if inv is not None and inv.ide_collected:
            rows.append(("IDE plugins", _ide_count_summary(inv)))
        if summary.errors not in {"0", "", "<nil>", "None"}:
            rows.append(("Errors", summary.errors))
        if summary.limitations not in {"0", "", "<nil>", "None"}:
            rows.append(("Unsupported capabilities", f"{summary.limitations} (informational)"))
        if skill_verdicts := _verdict_summary(summary.policy_skill_verdicts):
            rows.append(("Skill policy verdicts", skill_verdicts))
        if plugin_verdicts := _verdict_summary(summary.policy_plugin_verdicts):
            rows.append(("Plugin policy verdicts", plugin_verdicts))
        if skill_scan := _scan_summary(summary.scan_skill_coverage):
            rows.append(("Skill scan coverage", skill_scan))
        if plugin_scan := _scan_summary(summary.scan_plugin_coverage):
            rows.append(("Plugin scan coverage", plugin_scan))
        return tuple((key, value) for key, value in rows if value)

    def detail_info(self) -> InventoryDetailInfo | None:
        info = self._detail_info()
        if info is None:
            return None
        # At 80x24 the card has room for two or three lines, and they repeated
        # the row above it (Enabled, AI, User) while Scope, Installed, Last
        # seen and Sessions stayed hidden (GAP-0098). Fields whose value the
        # row already shows go last; a cell cut to fit ("…") moves up.
        rows = self.data_table_rows()
        shown = set(rows[self.cursor]) if 0 <= self.cursor < len(rows) else set()
        return replace(info, fields=tuple(sorted(info.fields, key=lambda field: field[1] in shown)))

    def _detail_info(self) -> InventoryDetailInfo | None:
        if self.inventory is None:
            return None
        match self.active_sub:
            case "skills":
                rows = self.filtered_skills()
                if not 0 <= self.cursor < len(rows):
                    return None
                skill = rows[self.cursor]
                fields: list[tuple[str, str]] = [
                    ("Source", skill.source),
                    ("Eligible", str(skill.eligible).lower()),
                    ("Enabled", str(skill.enabled).lower()),
                    ("Bundled", str(skill.bundled).lower()),
                    ("Verdict", skill.verdict),
                    ("Detail", skill.verdict_detail),
                    ("Scan Findings", str(skill.scan_findings)),
                    ("Scan Severity", skill.scan_severity),
                    ("Scan Target", skill.scan_target),
                ]
                if skill.description:
                    fields.insert(0, ("Description", skill.description))
                return InventoryDetailInfo(f"SKILL: {skill.id}", tuple(fields))
            case "plugins":
                rows = self.filtered_plugins()
                if not 0 <= self.cursor < len(rows):
                    return None
                plugin = rows[self.cursor]
                return InventoryDetailInfo(
                    f"PLUGIN: {plugin.display_name}",
                    (
                        ("ID", plugin.id),
                        ("Version", plugin.version),
                        ("Origin", plugin.origin),
                        ("Status", plugin.status),
                        ("Enabled", str(plugin.enabled).lower()),
                        ("Verdict", plugin.verdict),
                        ("Detail", plugin.verdict_detail),
                        ("Scan Findings", str(plugin.scan_findings)),
                        ("Scan Severity", plugin.scan_severity),
                        ("Scan Target", plugin.scan_target),
                    ),
                )
            case "mcp":
                mcp_rows = self.filtered_mcps()
                if not 0 <= self.cursor < len(mcp_rows):
                    return None
                mcp = mcp_rows[self.cursor]
                return InventoryDetailInfo(
                    f"MCP: {mcp.id}",
                    (
                        ("Source", mcp.source),
                        ("Transport", mcp.transport),
                        ("Command", mcp.command),
                        ("URL", mcp.url),
                    ),
                )
            case "agents":
                agent_rows = self.filtered_agents()
                if not 0 <= self.cursor < len(agent_rows):
                    return None
                agent = agent_rows[self.cursor]
                if agent.identity:
                    return InventoryDetailInfo(
                        f"AGENT: {agent.id}",
                        (
                            ("User", agent.user),
                            ("Connector", agent.connector),
                            ("First seen", agent.first_seen),
                            ("Last seen", agent.last_seen),
                            ("Sessions", str(agent.sessions_seen)),
                        ),
                    )
                return InventoryDetailInfo(
                    f"AGENT: {agent.id}",
                    (
                        ("Model", agent.model),
                        ("Workspace", agent.workspace),
                        ("Default", str(agent.default).lower()),
                        ("Source", agent.source),
                        ("Max Concurrent", str(agent.max_concurrent)),
                    ),
                )
            case "tools":
                tool_rows = self.filtered_tools()
                if not 0 <= self.cursor < len(tool_rows):
                    return None
                tool = tool_rows[self.cursor]
                return InventoryDetailInfo(
                    f"TOOL: {tool.display_name}",
                    (
                        ("ID", tool.id),
                        ("Kind", tool.kind),
                        ("Source", tool.source),
                        ("Description", tool.description),
                    ),
                )
            case "models":
                model_rows = self.filtered_models()
                if not 0 <= self.cursor < len(model_rows):
                    return None
                provider = model_rows[self.cursor]
                fields = [
                    ("Source", provider.source),
                    ("Default Model", provider.default_model),
                    ("Status", provider.status),
                    ("Config", provider.config_path),
                ]
                if provider.fallbacks:
                    fields.append(("Fallbacks", ", ".join(provider.fallbacks)))
                if provider.allowed:
                    fields.append(("Allowed", ", ".join(provider.allowed)))
                return InventoryDetailInfo(f"MODEL: {provider.id}", tuple(fields))
            case "memory":
                memory_rows = self.filtered_memory()
                if not 0 <= self.cursor < len(memory_rows):
                    return None
                memory = memory_rows[self.cursor]
                fields = [
                    ("Backend", memory.backend),
                    ("Provider", memory.provider),
                    ("Workspace", memory.workspace),
                    ("DB Path", memory.db_path),
                    ("Files", str(memory.files)),
                    ("Chunks", str(memory.chunks)),
                    ("FTS Available", str(memory.fts_available).lower()),
                    ("Vector Enabled", str(memory.vector_enabled).lower()),
                ]
                if memory.sources:
                    fields.append(("Sources", ", ".join(memory.sources)))
                return InventoryDetailInfo(f"MEMORY: {memory.id}", tuple(fields))
            case "ide_plugins":
                ide_rows = self.filtered_ide_plugins()
                if not 0 <= self.cursor < len(ide_rows):
                    return None
                ide = ide_rows[self.cursor]
                fields = (
                    ("Enabled", ide.enabled_label),
                    ("AI", "yes" if ide.is_ai else "no"),
                    ("IDE", ide.ide_label),
                    ("Version", ide.version),
                    ("User", ide.user),
                    ("Name", ide.display_name),
                    ("Publisher", ide.publisher),
                    ("Enabled from", ide.enabled_source),
                    ("Scope", ide.scope),
                    ("AI signature", ide.ai_signature_id),
                    ("Installed", ide.installed_at),
                    ("Last seen", ide.last_seen),
                )
                return InventoryDetailInfo(
                    f"IDE PLUGIN: {ide.label}",
                    tuple((name, value) for name, value in fields if value),
                )
            case _:
                return None

    def data_table_columns(self) -> tuple[str, ...]:
        match self.active_sub:
            case "skills":
                base = ("ID", "Verdict", "Enabled", "Severity", "Findings", "Source")
            case "plugins":
                base = ("Name", "Version", "Origin", "Status", "Verdict", "Findings", "Severity")
            case "mcp":
                base = ("ID", "Source", "Transport", "Command/URL")
            case "agents":
                base = ("ID", "Source", "Model", "Workspace", "Default")
            case "tools":
                base = ("ID", "Name", "Kind", "Source")
            case "models":
                base = ("ID", "Source", "Default Model", "Status")
            case "memory":
                base = ("ID", "Backend", "Provider", "Files", "Chunks", "Workspace")
            case "ide_plugins":
                # Per user, never per connector: no Connector column.
                return self._ide_plugin_columns()
            case _:
                # The Summary sub-tab is a key/value list, not a per-connector
                # entity table, so it never carries a CONNECTOR column.
                return ("Metric", "Value")
        if self._show_user_column():
            base = ("User", *base)
        if self.show_connector_column:
            return ("Connector", *base)
        return base

    def _with_connector_cell(self, entity: object, cells: tuple[str, ...]) -> tuple[str, ...]:
        if self._show_user_column():
            cells = (str(getattr(entity, "user", "") or "—"), *cells)
        if not self.show_connector_column:
            return cells
        return (str(getattr(entity, "connector", "") or "—"), *cells)

    def data_table_rows(self) -> tuple[tuple[str, ...], ...]:
        if self.inventory is None:
            return ()
        match self.active_sub:
            case "skills":
                return tuple(
                    self._with_connector_cell(
                        skill,
                        (
                            skill.id,
                            skill.verdict,
                            "yes" if skill.enabled else "no",
                            skill.scan_severity,
                            str(skill.scan_findings),
                            skill.source,
                        ),
                    )
                    for skill in self.filtered_skills()
                )
            case "plugins":
                return tuple(
                    self._with_connector_cell(
                        plugin,
                        (
                            plugin.display_name,
                            plugin.version,
                            plugin.origin,
                            plugin.status,
                            plugin.verdict,
                            str(plugin.scan_findings),
                            plugin.scan_severity,
                        ),
                    )
                    for plugin in self.filtered_plugins()
                )
            case "mcp":
                return tuple(
                    self._with_connector_cell(mcp, (mcp.id, mcp.source, mcp.transport, mcp.command_or_url))
                    for mcp in self.filtered_mcps()
                )
            case "agents":
                return tuple(
                    self._with_connector_cell(
                        agent,
                        (
                            agent.id,
                            agent.source,
                            agent.model,
                            agent.workspace,
                            "" if agent.identity else ("yes" if agent.default else "no"),
                        ),
                    )
                    for agent in self.filtered_agents()
                )
            case "tools":
                return tuple(
                    self._with_connector_cell(
                        tool,
                        (tool.id, tool.display_name, tool.kind, tool.source),
                    )
                    for tool in self.filtered_tools()
                )
            case "models":
                return tuple(
                    self._with_connector_cell(
                        provider, (provider.id, provider.source, provider.default_model, provider.status)
                    )
                    for provider in self.filtered_models()
                )
            case "memory":
                return tuple(
                    self._with_connector_cell(
                        memory,
                        (
                            memory.id,
                            memory.backend,
                            memory.provider,
                            str(memory.files),
                            str(memory.chunks),
                            memory.workspace,
                        ),
                    )
                    for memory in self.filtered_memory()
                )
            case "ide_plugins":
                return self._ide_plugin_rows()
            case _:
                return self.summary_table_rows()

    def _ide_plugin_columns(self) -> tuple[str, ...]:
        columns = ("IDE", "Plugin", "Version", "Enabled", "AI")
        return ("User", *columns) if self._multi_user(self.filtered_ide_plugins()) else columns

    def _ide_plugin_rows(self) -> tuple[tuple[str, ...], ...]:
        plugins = self.filtered_ide_plugins()
        multi_user = self._multi_user(plugins)
        rows = tuple(
            (
                *((ide.user or "—",) if multi_user else ()),
                ide.ide_label,
                ide.label,
                ide.version,
                ide.enabled_label,
                "yes" if ide.is_ai else "",
            )
            for ide in plugins
        )
        # Enabled and AI stay whole; the wider text columns give way so the
        # table fits an 80-column terminal (GAP-0020, GAP-0050, GAP-0055).
        return _fit_cells(self._ide_plugin_columns(), rows, self.width or 80, keep=("Enabled", "AI"))

    def handle_key(self, key: str) -> InventoryPanelAction:
        # Digits 1-4 are filters only on the Skills and Plugins sub-tabs.
        # Everywhere else they fall through to the panel shortcuts, so "3"
        # opens Skills as the tab bar says (GAP-1156).
        if key in {"1", "2", "3", "4"} and self.active_sub not in {"skills", "plugins"}:
            return InventoryPanelAction(False)
        if key == "1":
            self.filter = ""
            self.cursor = 0
            self.detail_open = False
            return InventoryPanelAction(True, hint="Inventory filter: all. (Digits filter on this sub-tab; Ctrl+P switches panel.)")
        if key in {"2", "3", "4"}:
            if self.active_sub == "skills":
                filters: Mapping[str, InventoryFilter] = {
                    "2": "eligible",
                    "3": "warning",
                    "4": "blocked",
                }
            else:
                filters = {
                    "2": "loaded",
                    "3": "disabled",
                    "4": "blocked",
                }
            self.filter = filters[key]
            self.cursor = 0
            self.detail_open = False
            label = self.filter or "all"
            return InventoryPanelAction(
                True,
                hint=f"Inventory filter: {label} (1 shows all). Digits filter on this sub-tab; Ctrl+P switches panel.",
            )
        # Tab / Shift+Tab stay global (next / previous panel), as the help
        # says; h/l walk the sub-tabs (GAP-1641).
        if key in {"h", "left"}:
            before = self.active_sub
            self.move_subtab(-1)
            return InventoryPanelAction(True, hint="" if self.active_sub != before else "(first inventory sub-tab)")
        if key in {"l", "right"}:
            before = self.active_sub
            self.move_subtab(1)
            return InventoryPanelAction(True, hint="" if self.active_sub != before else "(last inventory sub-tab)")
        if key in {"j", "down"}:
            self.scroll_by(1)
            return InventoryPanelAction(True)
        if key in {"k", "up"}:
            self.scroll_by(-1)
            return InventoryPanelAction(True)
        if key == "esc" and self.detail_open:
            self.detail_open = False
            return InventoryPanelAction(True, detail_closed=True)
        if key == "enter":
            if self.active_sub == "summary" or self.current_list_len() == 0:
                return InventoryPanelAction(True, hint="(no inventory row selected)")
            self.detail_open = True
            return InventoryPanelAction(True, detail_opened=True)
        if key == "o":
            self.toggle_fast_scan()
            scope = ", ".join(self.category_scope) or "all categories"
            return InventoryPanelAction(True, hint=f"The next inventory scan (r) covers {scope}.")
        if key == "r":
            return InventoryPanelAction(True, self.load_intent())
        return InventoryPanelAction(False)

    def empty_state(self) -> str:
        if self.message:
            return self.message
        if self.loading:
            return f"Scanning inventory from {friendly_connector_name(self.connector)}..."
        if not self.loaded or self.inventory is None:
            return 'Press "r" to load inventory. Runs "defenseclaw aibom scan".'
        if self.active_sub == "ide_plugins" and self.current_list_len() == 0:
            inv = self.inventory
            if inv.ide_note:
                return f"IDE plugins: {inv.ide_note}."
            if not inv.ide_collected:
                return 'IDE plugins are not in this scan scope. Press "o" for all categories, then "r".'
            return "No IDE plugins found."
        if self.current_list_len() == 0 and self.active_sub != "summary":
            return "No items match the current filter." if self.filter else f"No {self.active_sub} found."
        return ""

    def _subtab_counts(self) -> Mapping[InventorySubTab, int]:
        if self.inventory is None:
            return {}
        # Badges reflect the connector filter (so they match the visible rows)
        # but not the verdict/status sub-filter, which only narrows the list.
        def _kept(items: Sequence[object]) -> int:
            return sum(1 for item in items if self._connector_keep(item))

        return {
            "skills": _kept(self.inventory.skills),
            "plugins": _kept(self.inventory.plugins),
            "mcp": _kept(self.inventory.mcps),
            "agents": _kept((*self.inventory.agents, *self.agent_identities)),
            "tools": _kept(self.inventory.tools),
            "models": _kept(self.inventory.models),
            "memory": _kept(self.inventory.memory),
            **({"ide_plugins": len(self.inventory.ide_plugins)} if self.inventory.ide_collected else {}),
        }


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _user_of(raw: Mapping[str, Any]) -> str:
    return str(raw.get("user") or raw.get("user_name") or raw.get("user_id") or "")


def _fit_cells(
    columns: Sequence[str],
    rows: tuple[tuple[str, ...], ...],
    width: int,
    keep: Sequence[str] = (),
) -> tuple[tuple[str, ...], ...]:
    """Clip cells so the table fits *width*; ``keep`` columns stay whole.

    The widest other column loses a character at a time (never below its
    header or 6), and a clipped cell ends in "…".
    """
    widths = [max([len(name), *(len(row[i]) for row in rows)]) for i, name in enumerate(columns)]
    # Panel margins, the scrollbar and one space of padding each side of a cell.
    budget = width - 8 - 2 * len(columns)
    shrinkable = [i for i, name in enumerate(columns) if name not in keep]
    while shrinkable and sum(widths) > budget:
        i = max(shrinkable, key=lambda j: widths[j])
        if widths[i] <= max(6, len(columns[i])):
            break
        widths[i] -= 1
    return tuple(
        tuple(cell if len(cell) <= widths[i] else cell[: widths[i] - 1] + "…" for i, cell in enumerate(row))
        for row in rows
    )


def _safe_int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _ide_count_summary(inv: InventorySnapshot) -> str:
    if inv.ide_note and not inv.ide_plugins:
        return inv.ide_note
    plugins = inv.ide_plugins
    ai = sum(1 for item in plugins if item.is_ai)
    disabled = sum(1 for item in plugins if item.enabled == "disabled")
    users = len({item.user for item in plugins} - {""})
    return f"{len(plugins)} ({ai} AI, {disabled} disabled, {users} user{'s' if users != 1 else ''})"


def _int_count(raw: Mapping[str, Any]) -> int:
    try:
        return int(raw.get("count") or 0)
    except (TypeError, ValueError):
        return 0


def _map_val(mapping: Mapping[str, Any], key: str) -> str:
    if key not in mapping:
        return "0"
    return str(mapping[key])


def _string_map(mapping: Mapping[str, Any]) -> Mapping[str, str]:
    return {str(key): str(value) for key, value in mapping.items()}


def _count_with_suffix(count: str, suffix_key: str, mapping: Mapping[str, Any]) -> str:
    suffix = _map_val(mapping, suffix_key)
    if suffix and suffix != "0":
        return f"{count} ({suffix} {suffix_key})"
    return count


def _plugin_count_summary(count: str, mapping: Mapping[str, Any]) -> str:
    loaded = _map_val(mapping, "loaded")
    disabled = _map_val(mapping, "disabled")
    if loaded != "0" or disabled != "0":
        return f"{count} ({loaded} loaded, {disabled} disabled)"
    return count


def _verdict_summary(mapping: Mapping[str, str]) -> str:
    parts: list[str] = []
    for key in ("blocked", "rejected", "allowed", "warning", "clean", "unscanned", "discovery-only"):
        value = mapping.get(key, "0")
        if value not in {"", "0"}:
            parts.append(f"{value} {key}")
    return "  ".join(parts)


def _scan_summary(mapping: Mapping[str, str]) -> str:
    if not mapping:
        return ""
    scanned = mapping.get("scanned", "0")
    unscanned = mapping.get("unscanned", "0")
    findings = mapping.get("total_findings", "0")
    if scanned == "0" and unscanned == "0" and findings == "0":
        return ""
    return f"{scanned} scanned  {unscanned} unscanned  {findings} findings"


__all__ = [
    "FAST_SCAN_CATEGORIES",
    "INVENTORY_CATEGORIES",
    "INVENTORY_SUBTAB_LABELS",
    "INVENTORY_SUBTABS",
    "InventoryAgent",
    "InventoryCommandIntent",
    "InventoryDetailInfo",
    "InventoryFilter",
    "InventoryMCP",
    "InventoryMemory",
    "InventoryLimitation",
    "InventoryModelProvider",
    "InventoryPanelAction",
    "InventoryPanelModel",
    "InventoryPlugin",
    "InventoryScopeChip",
    "InventoryScopeState",
    "InventorySkill",
    "InventorySnapshot",
    "InventorySubTab",
    "InventorySubTabInfo",
    "InventorySummary",
    "InventorySummaryState",
    "InventoryTool",
]
