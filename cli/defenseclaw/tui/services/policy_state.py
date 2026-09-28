# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Pure model for the Policies panel (key ``P``).

DefenseClaw has three independent policy layers, one sub-tab each:

1. the named security policy (``policy activate NAME``): the guardrail block
   and alert thresholds, install blocking, firewall default and approvals;
2. the guardrail rule pack, global or per connector (``guardrail use-pack``);
3. the sandbox policy pack (``sandbox pack list``), shown read-only.

No I/O happens here. The app reads :mod:`defenseclaw.policy_catalog` in a
thread and feeds the results in; the model answers what to render and which
action a key asked for. Mutations leave as command intents.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

POLICY_VIEWS: tuple[str, ...] = ("policies", "packs", "sandbox_packs")
VIEW_TITLES = {"policies": "Policies", "packs": "Rule packs", "sandbox_packs": "Sandbox packs"}
VIEW_KEYS = {"1": "policies", "2": "packs", "3": "sandbox_packs"}

# Under this many columns the tables drop what the detail shows.
WIDE_COLUMNS = 100

# Sandbox packs: the gateway's packs.DefaultPack.
DEFAULT_SANDBOX_PACK = "open"

# Rule-pack presets, strictest last (cmd_guardrail / policy_catalog.RULE_PACK_PRESETS).
PACK_STRICTNESS = {"permissive": 1, "default": 2, "strict": 3}

# policy_catalog threshold labels -> how much they block (lower = stricter).
# "none" blocks nothing, so it is the weakest.
_THRESHOLD_RANK = {"LOW+": 1, "MEDIUM+": 2, "HIGH+": 3, "CRITICAL": 4, "NONE": 5}


def threshold_rank(label: str) -> int | None:
    """How little a threshold label catches (1 = LOW+ … 5 = none); None if unknown."""
    return _THRESHOLD_RANK.get((label or "").strip().upper())


def fit(text: str, width: int) -> str:
    """``text`` cut to ``width`` characters with an ellipsis (0 keeps it whole)."""
    if width <= 0 or len(text) <= width:
        return text
    return text[: max(0, width - 1)].rstrip() + "…"


def _attr(obj: object, name: str, default: Any = "") -> Any:
    value = getattr(obj, name, default)
    return default if value is None else value


def _hilt_label(value: object) -> str:
    if value is True:
        return "on"
    if value is False:
        return "off"
    return "inherit"


# ---------------------------------------------------------------------------
# Intents
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PolicyCommandIntent:
    """A CLI command the app previews and runs."""

    label: str
    args: tuple[str, ...]
    binary: str = "defenseclaw"
    category: str = "policy"
    risk: str = "mutation"
    hint: str = ""

    @property
    def argv(self) -> tuple[str, ...]:
        return (self.binary, *self.args)


def activate_intent(name: str) -> PolicyCommandIntent:
    return PolicyCommandIntent(
        label=f"policy activate {name}",
        args=("policy", "activate", name),
        hint=f"Activate the {name} policy and reload the gateway.",
    )


def use_pack_intent(pack: str, connector: str = "") -> PolicyCommandIntent:
    args: tuple[str, ...] = ("guardrail", "use-pack", pack)
    if connector:
        args = (*args, "--connector", connector)
    scope = f" for {connector}" if connector else ""
    return PolicyCommandIntent(
        label=f"guardrail use-pack {pack}{scope}",
        args=args,
        hint=f"Switch the guardrail rule pack{scope or ' for every connector'} to {pack}.",
    )


# ---------------------------------------------------------------------------
# Comparing policies and packs
# ---------------------------------------------------------------------------


def policy_weakenings(old: object | None, new: object | None) -> tuple[str, ...]:
    """Ways ``new`` protects less than ``old`` (empty when it does not).

    A threshold that catches fewer severities, a firewall that goes from deny
    to allow by default, or human approval switched off.
    """
    if old is None or new is None:
        return ()
    reasons: list[str] = []
    for field, label in (
        ("block_at", "blocks"),
        ("alert_at", "alerts on"),
        ("install_block_at", "blocks installs of"),
    ):
        before, after = str(_attr(old, field)), str(_attr(new, field))
        old_rank, new_rank = threshold_rank(before), threshold_rank(after)
        if old_rank is not None and new_rank is not None and new_rank > old_rank:
            reasons.append(f"{label} {after} instead of {before}")
    if _attr(old, "firewall_default") == "deny" and _attr(new, "firewall_default") == "allow":
        reasons.append("the firewall allows by default instead of denying")
    if _attr(old, "hilt", None) is True and _attr(new, "hilt", None) is False:
        reasons.append("human approval is turned off")
    return tuple(reasons)


def policy_comparison(old: object | None, new: object) -> tuple[tuple[str, str, str], ...]:
    """``(label, active value, new value)`` rows for the picker preview."""

    def values(policy: object | None) -> dict[str, str]:
        if policy is None:
            return {}
        firewall = str(_attr(policy, "firewall_default")) or "unchanged"
        return {
            "Block at": str(_attr(policy, "block_at")) or "-",
            "Alert at": str(_attr(policy, "alert_at")) or "-",
            "Install block at": str(_attr(policy, "install_block_at")) or "-",
            "Firewall default": firewall,
            "Human approval": _hilt_label(_attr(policy, "hilt", None)),
        }

    before, after = values(old), values(new)
    return tuple((label, before.get(label, "-"), value) for label, value in after.items())


def policy_side_effects(new: object) -> tuple[str, ...]:
    """What activating ``new`` changes besides the thresholds."""
    effects: list[str] = []
    if _attr(new, "replaces_webhooks", False):
        effects.append("replaces your webhooks")
    if _attr(new, "sets_cisco", False):
        effects.append("changes Cisco AI Defense settings")
    overrides = int(_attr(new, "scanner_overrides", 0) or 0)
    if overrides:
        effects.append(f"{overrides} scanner override{'s' if overrides != 1 else ''}")
    return tuple(effects)


def pack_weakens(old_packs: tuple[str, ...] | list[str], new_pack: str) -> bool:
    """Whether switching any of ``old_packs`` to ``new_pack`` moves to a looser preset."""
    new_rank = PACK_STRICTNESS.get(new_pack)
    if new_rank is None:
        return False
    return any(PACK_STRICTNESS.get(old, 0) > new_rank for old in old_packs)


def policy_posture_text(active: object | None) -> str:
    """``strict · block MEDIUM+ · alert LOW+`` for the active policy ("" if unknown)."""
    if active is None:
        return ""
    name = str(_attr(active, "name")) or "?"
    return f"{name} · block {_attr(active, 'block_at') or '?'} · alert {_attr(active, 'alert_at') or '?'}"


# ---------------------------------------------------------------------------
# Rule-pack validation (``guardrail validate-pack PATH --json``)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PackValidation:
    """The validator's answer: ``valid``, ``invalid`` or ``unavailable``."""

    state: str
    message: str = ""
    rule_count: int = 0
    enabled_rule_count: int = 0
    rule_file_count: int = 0
    digest: str = ""

    @property
    def summary(self) -> str:
        if self.state == "valid":
            digest = f" · digest {self.digest[:12]}" if self.digest else ""
            return (
                f"valid: {self.enabled_rule_count}/{self.rule_count} rules enabled "
                f"across {self.rule_file_count} files{digest}"
            )
        if self.state == "invalid":
            return f"invalid: {self.message or 'the pack did not load'}"
        return f"validator unavailable: {self.message or 'defenseclaw-gateway could not check it'}"


def parse_validation(returncode: int, stdout: str) -> PackValidation:
    """Decode ``validate-pack --json`` (exit 0 valid, 1 invalid, 2 unavailable)."""
    try:
        payload = json.loads(stdout or "{}")
    except ValueError:
        payload = {}
    if not isinstance(payload, dict):
        payload = {}
    error = payload.get("error") if isinstance(payload.get("error"), dict) else {}
    reason = str(error.get("reason", "") or "").strip()
    where = str(error.get("path", "") or "").strip()
    if where and where != "$":
        reason = f"{reason} (at {where})" if reason else where
    if returncode == 2:
        return PackValidation("unavailable", reason)
    if returncode == 0 and payload.get("valid") is True:
        summary = payload.get("summary") if isinstance(payload.get("summary"), dict) else {}

        def count(key: str) -> int:
            try:
                return int(summary.get(key, 0) or 0)
            except (TypeError, ValueError):
                return 0

        return PackValidation(
            "valid",
            rule_count=count("rule_count"),
            enabled_rule_count=count("enabled_rule_count"),
            rule_file_count=count("rule_file_count"),
            digest=str(summary.get("digest", "") or ""),
        )
    return PackValidation("invalid", reason or f"exit {returncode}")


# ---------------------------------------------------------------------------
# Sandbox packs (``defenseclaw sandbox pack list -o json``)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SandboxPackRow:
    name: str
    builtin: bool = False
    source: str = ""
    description: str = ""
    profile: str = ""
    digest: str = ""
    error: str = ""


def decode_sandbox_packs(text: str) -> list[SandboxPackRow]:
    """Rows from ``{"packs": [...]}``; raises ValueError on malformed JSON."""
    payload = json.loads(text or "{}")
    items = payload.get("packs") if isinstance(payload, dict) else None
    if not isinstance(items, list):
        raise ValueError("sandbox pack list returned no packs array")
    rows: list[SandboxPackRow] = []
    for item in items:
        if not isinstance(item, dict) or not str(item.get("name", "") or "").strip():
            continue
        rows.append(
            SandboxPackRow(
                name=str(item.get("name")),
                builtin=bool(item.get("builtin")),
                source=str(item.get("source", "") or ""),
                description=str(item.get("description", "") or ""),
                profile=str(item.get("profile", "") or ""),
                digest=str(item.get("digest", "") or ""),
                error=str(item.get("error", "") or ""),
            )
        )
    return rows


# ---------------------------------------------------------------------------
# The panel
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PolicyPanelAction:
    """What a key asked for.

    ``kind``: ``none`` (not handled), ``render``, ``hint``, ``refresh``,
    ``load_sandbox_packs``, ``pick_policy`` (``policy`` = the highlighted
    one) or ``pick_pack`` (``connector`` = the highlighted scope, "" = global).
    """

    kind: str
    hint: str = ""
    policy: str = ""
    connector: str = ""
    intent: PolicyCommandIntent | None = None

    @property
    def handled(self) -> bool:
        return self.kind != "none"


def policies_keys_hint(view: str, *, sandbox_supported: bool = True) -> str:
    """The hint bar's keys for a Policies view (one line at 80 columns)."""
    views = "1/2/3 view" if sandbox_supported else "1/2 view"
    if view == "packs":
        return f"KEYS  {views} | Enter change pack | i details | r refresh"
    if view == "sandbox_packs":
        return f"KEYS  {views} | Enter details | r refresh | read-only: sandbox pack set"
    return f"KEYS  {views} | Enter activate a policy | i details | r refresh"


class PoliciesPanelModel:
    """State for the Policies panel."""

    def __init__(self, *, sandbox_supported: bool = True) -> None:
        self.sandbox_supported = sandbox_supported
        self.view = "policies"
        self.cursors = {view: 0 for view in POLICY_VIEWS}
        self.detail_open = False
        self.loaded = False
        self.loading = False
        self.error = ""
        self.policies: tuple[Any, ...] = ()
        self.global_pack: Any | None = None
        self.connector_packs: tuple[Any, ...] = ()
        self.packs: tuple[Any, ...] = ()
        self.pack_error = ""
        self.sandbox_loaded = False
        self.sandbox_error = ""
        self.sandbox_packs: tuple[SandboxPackRow, ...] = ()
        self.sandbox_active = DEFAULT_SANDBOX_PACK

    # ---- inputs -----------------------------------------------------------

    def set_config(self, config: object | None) -> None:
        openshell = getattr(config, "openshell", None)
        pack = str(getattr(openshell, "pack", "") or "").strip()
        self.sandbox_active = pack or DEFAULT_SANDBOX_PACK

    def apply_policies(self, policies: list[Any] | tuple[Any, ...]) -> None:
        self.policies = tuple(policies)
        self.loaded = True
        self.error = ""
        self._clamp()

    def apply_packs(
        self, global_pack: Any | None, connectors: list[Any] | tuple[Any, ...], packs: list[Any] | tuple[Any, ...]
    ) -> None:
        self.global_pack = global_pack
        self.connector_packs = tuple(connectors)
        self.packs = tuple(packs)
        self.pack_error = ""
        self._clamp()

    def apply_sandbox_packs(self, rows: list[SandboxPackRow] | tuple[SandboxPackRow, ...]) -> None:
        self.sandbox_packs = tuple(rows)
        self.sandbox_loaded = True
        self.sandbox_error = ""
        self._clamp()

    def apply_sandbox_json(self, text: str) -> None:
        try:
            self.apply_sandbox_packs(decode_sandbox_packs(text))
        except ValueError as exc:
            self.set_sandbox_error(str(exc))

    def set_error(self, message: str) -> None:
        """A failed read keeps the last good rows."""
        self.error = message
        self.loaded = True

    def set_pack_error(self, message: str) -> None:
        self.pack_error = message

    def set_sandbox_error(self, message: str) -> None:
        self.sandbox_error = message
        self.sandbox_loaded = True

    # ---- queries ----------------------------------------------------------

    def views(self) -> tuple[str, ...]:
        return POLICY_VIEWS if self.sandbox_supported else POLICY_VIEWS[:2]

    @property
    def cursor(self) -> int:
        return self.cursors[self.view]

    @cursor.setter
    def cursor(self, value: int) -> None:
        self.cursors[self.view] = value
        self._clamp()

    def active_policy(self) -> Any | None:
        return next((policy for policy in self.policies if getattr(policy, "active", False)), None)

    def policy_named(self, name: str) -> Any | None:
        return next((policy for policy in self.policies if getattr(policy, "name", "") == name), None)

    def pack_rows(self) -> tuple[Any, ...]:
        """The global row first, then one per active connector."""
        rows = (self.global_pack,) if self.global_pack is not None else ()
        return (*rows, *self.connector_packs)

    def override_connectors(self) -> tuple[str, ...]:
        """Connectors whose own pack a global switch would clear."""
        return tuple(row.connector for row in self.connector_packs if getattr(row, "source", "") == "override")

    def packs_for_scope(self, connector: str) -> tuple[str, ...]:
        """The pack names a switch at this scope replaces."""
        if connector:
            row = next((r for r in self.connector_packs if r.connector == connector), None)
            return (row.pack,) if row is not None else ()
        names = [self.global_pack.pack] if self.global_pack is not None else []
        names.extend(row.pack for row in self.connector_packs if getattr(row, "source", "") == "override")
        return tuple(names)

    def current_pack(self, connector: str) -> str:
        if connector:
            row = next((r for r in self.connector_packs if r.connector == connector), None)
            return row.pack if row is not None else ""
        return self.global_pack.pack if self.global_pack is not None else ""

    def row_count(self) -> int:
        if self.view == "packs":
            return len(self.pack_rows())
        if self.view == "sandbox_packs":
            return len(self.sandbox_packs)
        return len(self.policies)

    def selected_policy(self) -> Any | None:
        if self.view != "policies" or not self.policies:
            return None
        return self.policies[self.cursor]

    def selected_pack_row(self) -> Any | None:
        rows = self.pack_rows()
        if self.view != "packs" or not rows:
            return None
        return rows[self.cursor]

    def selected_sandbox_pack(self) -> SandboxPackRow | None:
        if self.view != "sandbox_packs" or not self.sandbox_packs:
            return None
        return self.sandbox_packs[self.cursor]

    # ---- keys -------------------------------------------------------------

    def set_view(self, view: str) -> None:
        if view not in self.views():
            return
        if view != self.view:
            self.detail_open = False
        self.view = view
        self._clamp()

    def handle_key(self, key: str) -> PolicyPanelAction:
        if key in VIEW_KEYS:
            view = VIEW_KEYS[key]
            if view not in self.views():
                return PolicyPanelAction("hint", hint="Sandbox packs are available on Linux and macOS only.")
            self.set_view(view)
            if view == "sandbox_packs" and not self.sandbox_loaded:
                return PolicyPanelAction("load_sandbox_packs")
            return PolicyPanelAction("render")
        if key in {"escape", "esc", "q"}:
            if self.detail_open:
                self.detail_open = False
                return PolicyPanelAction("render")
            return PolicyPanelAction("none")
        if key in {"down", "j"}:
            self.cursor = self.cursor + 1
            return PolicyPanelAction("render")
        if key in {"up", "k"}:
            self.cursor = self.cursor - 1
            return PolicyPanelAction("render")
        if key == "r":
            return PolicyPanelAction("refresh", hint="Refreshing policies...")
        if key == "i":
            if not self.row_count():
                return PolicyPanelAction("hint", hint="Nothing is selected.")
            self.detail_open = not self.detail_open
            return PolicyPanelAction("render")
        if key == "enter":
            if self.view == "policies":
                policy = self.selected_policy()
                if policy is None:
                    return PolicyPanelAction("hint", hint="No named policies were found.")
                return PolicyPanelAction("pick_policy", policy=policy.name)
            if self.view == "packs":
                row = self.selected_pack_row()
                connector = "" if row is None or row.connector == "global" else row.connector
                return PolicyPanelAction("pick_pack", connector=connector)
            if not self.row_count():
                return PolicyPanelAction("hint", hint="No sandbox packs are loaded.")
            self.detail_open = not self.detail_open
            return PolicyPanelAction("render")
        return PolicyPanelAction("none")

    def keys_hint(self, view: str | None = None) -> str:
        return policies_keys_hint(view or self.view, sandbox_supported=self.sandbox_supported)

    # ---- rendering --------------------------------------------------------

    def headline(self) -> str:
        """One plain line under the view tabs."""
        if self.loading and not self.loaded:
            return "Loading policies…"
        if self.view == "sandbox_packs":
            if self.sandbox_error:
                return f"Could not list sandbox packs: {self.sandbox_error}"
            if not self.sandbox_loaded:
                return "Loading sandbox packs…"
            return f"New sandboxes use the {self.sandbox_active} pack (openshell.pack); change it in Setup."
        if self.error:
            return f"Could not read policies: {self.error}"
        active = self.active_policy()
        policy = f"active policy {active.name}" if active is not None else "no policy activated yet"
        if self.view == "packs" and self.pack_error:
            return f"Could not read rule packs: {self.pack_error}"
        pack = self.global_pack.pack if self.global_pack is not None else "?"
        overrides = len(self.override_connectors())
        own = f" · {overrides} connector{'s' if overrides != 1 else ''} with their own" if overrides else ""
        return f"{policy} · rule pack {pack}{own}"

    def empty_state(self) -> str:
        if self.row_count():
            return ""
        if self.view == "packs":
            return "" if self.pack_error else "No rule packs found."
        if self.view == "sandbox_packs":
            return "" if not self.sandbox_loaded or self.sandbox_error else "No sandbox packs found."
        if self.loading or not self.loaded or self.error:
            return ""
        return "No named policies found. Create one with: defenseclaw policy create NAME"

    def data_table_columns(self, width: int = 0) -> tuple[str, ...]:
        wide = width >= WIDE_COLUMNS
        if self.view == "packs":
            return ("Scope", "Pack", "Source", "Folder") if wide else ("Scope", "Pack", "Source")
        if self.view == "sandbox_packs":
            if wide:
                return ("", "Pack", "Kind", "Profile", "Digest", "Description")
            return ("", "Pack", "Kind", "Profile", "Digest")
        if wide:
            return ("", "Policy", "Kind", "Block at", "Alert at", "Install block", "Firewall", "Description")
        return ("", "Policy", "Kind", "Block", "Alert", "Install block")

    def data_table_rows(self, width: int = 0) -> tuple[tuple[str, ...], ...]:
        wide = width >= WIDE_COLUMNS
        if self.view == "packs":
            rows = []
            for row in self.pack_rows():
                scope = "global" if row.connector == "global" else row.connector
                source = {"global": "uses global", "override": "own pack", "default": "built-in default"}.get(
                    row.source, row.source
                )
                if row.connector == "global":
                    source = "configured" if row.source == "global" else "built-in default"
                cells = (scope, row.pack or "-", source)
                rows.append((*cells, fit(row.path or "-", 48)) if wide else cells)
            return tuple(rows)
        if self.view == "sandbox_packs":
            rows = []
            for pack in self.sandbox_packs:
                marker = "●" if pack.name == self.sandbox_active else ""
                digest = "invalid" if pack.error else (pack.digest[:12] or "-")
                cells = (marker, pack.name, "built-in" if pack.builtin else "custom", pack.profile or "-", digest)
                rows.append((*cells, fit(pack.description or "-", 40)) if wide else cells)
            return tuple(rows)
        rows = []
        for policy in self.policies:
            cells = (
                "●" if policy.active else "",
                fit(policy.name, 24 if wide else 16),
                "built-in" if policy.builtin else "custom",
                policy.block_at or "-",
                policy.alert_at or "-",
                policy.install_block_at or "-",
            )
            if wide:
                cells = (*cells, policy.firewall_default or "-", fit(policy.description or "-", 40))
            rows.append(cells)
        return tuple(rows)

    def detail_text(self) -> str:
        """Plain ``label: value`` lines for the selected row ("" when closed)."""
        if not self.detail_open:
            return ""
        if self.view == "packs":
            row = self.selected_pack_row()
            if row is None:
                return ""
            lines = [
                f"Rule pack · {row.connector}",
                f"pack: {row.pack}",
                f"source: {row.source}",
                f"folder: {row.path}",
            ]
            pack = next((p for p in self.packs if getattr(p, "path", "") == row.path), None)
            if pack is not None:
                lines.append(f"kind: {pack.kind}")
                if pack.used_by:
                    lines.append(f"used by: {', '.join(pack.used_by)}")
            return "\n".join(lines)
        if self.view == "sandbox_packs":
            pack = self.selected_sandbox_pack()
            if pack is None:
                return ""
            lines = [
                f"Sandbox pack · {pack.name}",
                f"kind: {'built-in' if pack.builtin else 'custom'}",
                f"profile: {pack.profile or '-'}",
                f"source: {pack.source or '-'}",
                f"digest: {pack.digest or '-'}",
            ]
            if pack.description:
                lines.append(f"description: {pack.description}")
            if pack.error:
                lines.append(f"error: {pack.error}")
            return "\n".join(lines)
        policy = self.selected_policy()
        if policy is None:
            return ""
        lines = [
            f"Policy · {policy.name}{' (active)' if policy.active else ''}",
            f"description: {policy.description or '-'}",
            f"kind: {'built-in' if policy.builtin else 'custom'} · {policy.path}",
            f"guardrail: block {policy.block_at} · alert {policy.alert_at}",
            f"installs blocked at: {policy.install_block_at}",
            f"firewall default: {policy.firewall_default or 'unchanged'} · human approval: {_hilt_label(policy.hilt)}",
        ]
        effects = policy_side_effects(policy)
        if effects:
            lines.append("activating it: " + " · ".join(effects))
        return "\n".join(lines)

    # ---- internals --------------------------------------------------------

    def _clamp(self) -> None:
        count = self.row_count()
        value = self.cursors[self.view]
        self.cursors[self.view] = max(0, min(value, count - 1)) if count else 0


__all__ = [
    "DEFAULT_SANDBOX_PACK",
    "PACK_STRICTNESS",
    "POLICY_VIEWS",
    "VIEW_TITLES",
    "PackValidation",
    "PoliciesPanelModel",
    "PolicyCommandIntent",
    "PolicyPanelAction",
    "SandboxPackRow",
    "activate_intent",
    "decode_sandbox_packs",
    "fit",
    "pack_weakens",
    "parse_validation",
    "policies_keys_hint",
    "policy_comparison",
    "policy_posture_text",
    "policy_side_effects",
    "policy_weakenings",
    "threshold_rank",
    "use_pack_intent",
]
