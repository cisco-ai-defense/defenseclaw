# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Policies panel behaviour for the Textual TUI (key ``P``): the protection center.

:class:`PolicyPanelMixin` is mixed into ``DefenseClawTUI``. It owns the
panel's I/O: reading the policy catalog in-process through
:mod:`defenseclaw.policy_catalog` on a thread (named policies, rule packs,
scope postures, opt-in protection packs, rule families and tool chains),
listing sandbox packs (``defenseclaw sandbox pack list -o json``), validating
a rule pack (``guardrail validate-pack PATH --json``), and the change flows.
Each flow shows a consequence modal (red, with a second press, when
protection gets weaker) and then runs the command directly:

- ``m``: ``guardrail mode observe|action [--connector C]``
- ``b`` / ``a`` on Posture: pick a tool-call level →
  ``guardrail block-at|alert-at LEVEL|inherit [--connector C]``
- ``b`` / ``a`` on Policies: pick the policy's LLM-traffic level →
  ``policy edit guardrail --block-threshold N -p NAME`` (or ``--alert-threshold N``)
- ``h``: pick approval → ``guardrail hilt on --min-severity S|off [--connector C] --yes``
- ``p`` / Enter on a rule pack: ``guardrail use-pack PACK [--connector C]``
- Space on an opt-in pack: ``guardrail protection enable|disable NAME [--connector C]``
- Enter on a policy: ``policy activate NAME``

The pure state lives in :mod:`defenseclaw.tui.services.policy_state`.
"""

from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass, field
from typing import Any

from rich.console import RenderableType

from defenseclaw.platform_support import openshell_sandboxes_supported
from defenseclaw.tui.markup_safe import escape as rich_escape
from defenseclaw.tui.screens.consequence import (
    ConsequenceAction,
    ConsequenceModalModel,
    ConsequenceModalScreen,
)
from defenseclaw.tui.screens.policy_picker import PolicyPickerScreen
from defenseclaw.tui.screens.posture_picker import (
    LevelPickerScreen,
    approval_choices,
    threshold_choices,
    tool_level_choices,
)
from defenseclaw.tui.screens.rule_pack_picker import (
    PackOption,
    PackScope,
    RulePackChoice,
    RulePackPickerScreen,
)
from defenseclaw.tui.services.policy_state import (
    INHERIT,
    TOOL_ALERT_LEVELS,
    TOOL_BLOCK_LEVELS,
    VIEW_SHORT_TITLES,
    PackRule,
    PackValidation,
    PoliciesPanelModel,
    PolicyPanelAction,
    actions_weaken,
    activate_intent,
    fit,
    hilt_intent,
    hilt_weakens,
    level_intent,
    levels_setting,
    loosened_text,
    mode_intent,
    mode_weakens,
    pack_weakens,
    parse_validation,
    policy_side_effects,
    policy_weakenings,
    posture_summary,
    protection_claim,
    protection_intent,
    severity_actions,
    threshold_intent,
    threshold_weakens,
    use_pack_intent,
)
from defenseclaw.tui.theme import DEFAULT_TOKENS as TOKENS
from defenseclaw.tui.widgets.panel_split import ASIDE_MIN_WIDTH, NAV_MIN_WIDTH, NAV_WIDTH, Aside, NavItem

# #panel-aside's width beside the table (keep in sync with the app CSS).
_ASIDE_SHARE = 0.38
# Terminals with at least this many rows always show the detail; shorter
# ones (the app's "compact" detail pane) open it with i.
_TALL_ROWS = 30

# Buttons of the panel's control bar, mapped to the key they press. The
# views themselves are switched from the navigation list or with 1-7.
POLICY_BUTTON_KEYS: dict[str, str] = {
    "policies-mode": "m",
    "policies-block": "b",
    "policies-alert": "a",
    "policies-approval": "h",
    "policies-rule-pack": "p",
    "policies-toggle": "space",
    "policies-scope": "s",
    "policies-activate": "enter",
    "policies-change-pack": "enter",
    "policies-details": "i",
    "policies-refresh": "r",
}


@dataclass
class PolicyCatalogRead:
    """One in-process read of the policy catalog."""

    policies: list[Any] = field(default_factory=list)
    global_pack: Any | None = None
    connectors: list[Any] = field(default_factory=list)
    packs: list[Any] = field(default_factory=list)
    error: str = ""
    pack_error: str = ""
    postures: list[Any] = field(default_factory=list)
    protection: list[Any] = field(default_factory=list)
    pack_rules: dict[str, tuple[PackRule, ...]] = field(default_factory=dict)
    families: dict[str, list[Any]] = field(default_factory=dict)
    chains: list[Any] = field(default_factory=list)
    pack_bases: dict[str, str] = field(default_factory=dict)
    posture_error: str = ""


def _pack_rules(pack: Any) -> tuple[PackRule, ...]:
    """``id · severity · title`` of an opt-in pack's rules, when the catalog has them."""
    rules = getattr(pack, "rules", None)
    if rules:
        out = []
        for rule in rules:
            if isinstance(rule, dict):
                out.append(PackRule(str(rule.get("id", "")), str(rule.get("severity", "")), str(rule.get("title", ""))))
            else:
                out.append(
                    PackRule(
                        str(getattr(rule, "id", "")),
                        str(getattr(rule, "severity", "")),
                        str(getattr(rule, "title", "")),
                    )
                )
        return tuple(rule for rule in out if rule.id)
    return tuple(PackRule(str(rule_id)) for rule_id in getattr(pack, "rule_ids", ()) or ())


def read_policy_catalog(config: object | None) -> PolicyCatalogRead:
    """Blocking read of everything the panel shows (run it in a thread)."""
    from defenseclaw import policy_catalog

    read = PolicyCatalogRead()
    policy_dir = getattr(config, "policy_dir", None)
    try:
        read.policies = policy_catalog.list_named_policies(policy_dir)
    except Exception as exc:  # noqa: BLE001 - a bad policy dir is panel state
        read.error = str(exc) or type(exc).__name__
    try:
        read.global_pack = policy_catalog.global_pack(config)
        read.connectors = policy_catalog.effective_packs(config)
        read.packs = policy_catalog.discover_rule_packs(config)
    except Exception as exc:  # noqa: BLE001
        read.pack_error = str(exc) or type(exc).__name__
    # The protection catalog: each part on its own, so one bad file only
    # empties its own view.
    errors: list[str] = []
    try:
        scope_postures = getattr(policy_catalog, "scope_postures", None)
        read.postures = list(scope_postures(config)) if callable(scope_postures) else []
    except Exception as exc:  # noqa: BLE001
        errors.append(str(exc) or type(exc).__name__)
    try:
        protection_packs = getattr(policy_catalog, "protection_packs", None)
        read.protection = list(protection_packs()) if callable(protection_packs) else []
        read.pack_rules = {str(getattr(p, "name", "")): _pack_rules(p) for p in read.protection}
    except Exception as exc:  # noqa: BLE001
        errors.append(str(exc) or type(exc).__name__)
    try:
        tool_chains = getattr(policy_catalog, "tool_chains", None)
        read.chains = list(tool_chains()) if callable(tool_chains) else []
    except Exception as exc:  # noqa: BLE001
        errors.append(str(exc) or type(exc).__name__)
    read_manifest = getattr(policy_catalog, "read_protection_manifest", None)
    if callable(read_manifest):
        for path in dict.fromkeys(str(getattr(row, "pack_path", "") or "") for row in read.postures):
            try:
                manifest = read_manifest(path)
            except Exception:  # noqa: BLE001 - no manifest just means "not composed"
                manifest = None
            base = str(getattr(manifest, "base_name", "") or "") if manifest is not None else ""
            if manifest is not None:
                read.pack_bases[path] = base or os.path.basename(str(getattr(manifest, "base", "") or ""))
    rule_families = getattr(policy_catalog, "rule_families", None)
    if callable(rule_families):
        for path in dict.fromkeys(str(getattr(row, "pack_path", "") or "") for row in read.postures):
            try:
                read.families[path] = list(rule_families(path))
            except Exception as exc:  # noqa: BLE001
                errors.append(str(exc) or type(exc).__name__)
    read.posture_error = errors[0] if errors else ""
    return read


class PolicyPanelMixin:
    """The Policies panel's loading, rendering and change flows."""

    policy_model: PoliciesPanelModel

    # ---- lifecycle --------------------------------------------------------

    def _policy_init(self, model: PoliciesPanelModel | None) -> None:
        self._policy_model_injected = model is not None
        self.policy_model = model or PoliciesPanelModel(sandbox_supported=openshell_sandboxes_supported())
        self.policy_model.set_config(getattr(self, "config", None))
        self._policy_load_running = False
        # A load asked for while one runs (a config change mid-read): the
        # running read saw the old config, so one more load follows it.
        self._policy_load_pending = False
        self._policy_sandbox_running = False

    def _policy_mount(self) -> None:
        """Read the catalog once so Overview and the status strip name the active policy."""
        if self._policy_model_injected:
            self._policy_publish_active()
            return
        self._schedule_policy_load()

    def _schedule_policy_load(self, *, sandbox: bool = False) -> None:
        if getattr(self, "_app_shutting_down", False):
            return
        if sandbox and self.policy_model.sandbox_supported and not self._policy_sandbox_running:
            self._policy_sandbox_running = True
            self.run_worker(self._load_sandbox_packs(), exclusive=False, thread=False)  # type: ignore[attr-defined]
        if self._policy_model_injected:
            return
        if self._policy_load_running:
            self._policy_load_pending = True
            return
        self._policy_load_running = True
        self.policy_model.loading = True
        self.run_worker(self._load_policy_catalog(), exclusive=False, thread=False)  # type: ignore[attr-defined]

    async def _load_policy_catalog(self) -> None:
        try:
            read = await asyncio.to_thread(read_policy_catalog, getattr(self, "config", None))
        except Exception as exc:  # noqa: BLE001 - never a stack trace in the TUI
            read = PolicyCatalogRead(error=str(exc))
        finally:
            self._policy_load_running = False
        model = self.policy_model
        model.loading = False
        model.set_config(getattr(self, "config", None))
        if read.error:
            model.set_error(read.error)
        else:
            model.apply_policies(read.policies)
        if read.pack_error:
            model.set_pack_error(read.pack_error)
        else:
            model.apply_packs(read.global_pack, read.connectors, read.packs)
        model.apply_protection(
            read.postures,
            read.protection,
            pack_rules=read.pack_rules,
            families=read.families,
            chains=read.chains,
            pack_bases=read.pack_bases,
        )
        if read.posture_error:
            model.set_posture_error(read.posture_error)
        self._policy_publish_active()
        if getattr(self, "active_panel", "") in {"policies", "overview"} and not getattr(self, "help_open", False):
            self._render_chrome()  # type: ignore[attr-defined]
        if self._policy_load_pending:
            self._policy_load_pending = False
            self._schedule_policy_load()

    async def _load_sandbox_packs(self) -> None:
        from defenseclaw.tui import app as app_module

        model = self.policy_model
        try:
            returncode, stdout, stderr = await app_module._communicate_captured(
                "defenseclaw", ("sandbox", "pack", "list", "-o", "json")
            )
        except OSError as exc:
            model.set_sandbox_error(str(exc))
        else:
            if returncode != 0:
                message = stderr.decode(errors="replace").strip().splitlines()
                model.set_sandbox_error(message[-1] if message else f"exit {returncode}")
            else:
                model.apply_sandbox_json(stdout.decode(errors="replace"))
        finally:
            self._policy_sandbox_running = False
        if getattr(self, "active_panel", "") == "policies" and not getattr(self, "help_open", False):
            self._render_chrome()  # type: ignore[attr-defined]

    def _policy_publish_active(self) -> None:
        overview = getattr(self, "overview_model", None)
        setter = getattr(overview, "set_active_policy", None)
        if callable(setter):
            setter(self.policy_model.active_policy())

    # ---- rendering --------------------------------------------------------

    def _policy_width(self) -> int:
        size = getattr(self, "size", None)
        return int(getattr(size, "width", 0) or 120)

    def _policy_table_width(self) -> int:
        """Characters the table gets: the body minus the nav list and the aside.

        Mirrors the split's CSS (widgets/panel_split.py and the app): the body
        panel takes 6 columns, the nav list ``NAV_WIDTH`` + 1, an aside beside
        the table ``_ASIDE_SHARE`` + 1, and the table's own border 2 once the
        nav list is shown.
        """
        width = self._policy_width()
        body = max(20, width - 6)
        table = body
        if width >= NAV_MIN_WIDTH:
            table -= NAV_WIDTH + 1 + 2
        if width >= ASIDE_MIN_WIDTH:
            table -= round(body * _ASIDE_SHARE) + 1
        # A table taller than the screen draws a 2-column scrollbar.
        return max(20, table - 2)

    def _policy_nav_shown(self) -> bool:
        """Whether the navigation list replaces the one-line view switcher."""
        return self._policy_width() >= NAV_MIN_WIDTH

    def _policy_aside_shown(self) -> bool:
        """Whether the detail sits beside the table (instead of under it)."""
        return self._policy_width() >= ASIDE_MIN_WIDTH

    def _policy_detail_always(self) -> bool:
        """Whether the detail is always on screen: beside the table, or below it
        when the terminal has room; a short one opens it with ``i`` instead."""
        size = getattr(self, "size", None)
        height = int(getattr(size, "height", 0) or 0)
        return self._policy_aside_shown() or height >= _TALL_ROWS

    def _policy_panel_nav(self) -> tuple[NavItem, ...]:
        """``_panel_nav`` for Policies: the seven views, badges with counts."""
        return tuple(
            NavItem(view, title, badge, active) for view, title, badge, active in self.policy_model.nav_entries()
        )

    def _policy_panel_aside(self) -> RenderableType | None:
        """``_panel_aside`` for Policies: the highlighted row's detail.

        Beside the table from ``ASIDE_MIN_WIDTH`` columns, below it on a
        narrower terminal with at least ``_TALL_ROWS`` rows (the design
        sketch), and on a short one only once ``i`` (or Enter on a read-only
        row) opened it, so the table keeps its rows at 80x24.
        """
        model = self.policy_model
        if not self._policy_detail_always() and not model.detail_open:
            return None
        title, lines = model.aside()
        if not title:
            return None
        return Aside(title, "\n".join(rich_escape(line) for line in lines))

    def _select_policy_nav(self, key: str) -> bool:
        """A click on a nav item or switcher segment opens that view."""
        model = self.policy_model
        if key not in model.views() or key == model.view:
            return False
        action = model.select_view(key)
        if action.kind == "load_sandbox_packs":
            self._schedule_policy_load(sandbox=True)
        return True

    def _policies_body_text(self) -> str:
        """Up to three lines: header, view switcher (narrow), the view's status line."""
        model = self.policy_model
        width = max(40, self._policy_width() - 8)
        header = model.header(max(20, width - 10))
        color_dot = TOKENS.accent_green if model.active_policy() is not None else TOKENS.accent_amber
        if header.startswith("● "):
            head = f"[{color_dot}]●[/] [{TOKENS.text_secondary}]{rich_escape(header[2:])}[/]"
        else:
            head = f"[{TOKENS.text_secondary}]{rich_escape(header)}[/]"
        lines = [f"[bold {TOKENS.accent_cyan}]Policies[/]  {head}"]
        if not self._policy_nav_shown():
            short = tuple(
                NavItem(key_view, VIEW_SHORT_TITLES[key_view], active=active)
                for key_view, _title, _badge, active in model.nav_entries()
            )
            lines.append(self._body_nav_switcher(short, len(lines)))  # type: ignore[attr-defined]
        failed = (
            model.error
            or (model.view == "packs" and model.pack_error)
            or (model.view == "sandbox_packs" and model.sandbox_error)
            or (model.view in {"posture", "optin", "chains", "families"} and model.posture_error)
        )
        empty = model.empty_state()
        if empty:
            lines.append(f"[{TOKENS.text_secondary}]{rich_escape(fit(empty, width))}[/]")
        else:
            color = TOKENS.accent_amber if failed else TOKENS.text_secondary
            lines.append(f"[{color}]{rich_escape(fit(model.headline(width), width))}[/]")
        return "\n".join(lines)

    def _sync_policy_controls(self) -> None:
        model = self.policy_model
        view = model.view
        scope = model.selected_scope()
        pack = model.selected_protection()
        selectable = pack is not None and getattr(pack, "status", "") != "staged"
        # b / a: a scope's tool-call levels on Posture, the highlighted policy's
        # LLM-traffic levels on Policies.
        levels = (view == "posture" and scope is not None) or (
            view == "policies" and model.selected_policy() is not None
        )
        visible = {
            "policies-mode": view == "posture" and scope is not None,
            "policies-block": levels,
            "policies-alert": levels,
            "policies-approval": view == "posture" and scope is not None,
            "policies-rule-pack": view == "posture" and scope is not None and model.global_pack is not None,
            "policies-toggle": view == "optin" and selectable and scope is not None,
            "policies-scope": view in {"optin", "families"} and len(model.postures) > 1,
            "policies-activate": view == "policies" and model.selected_policy() is not None,
            "policies-change-pack": view == "packs" and model.global_pack is not None,
            # i and Enter open the details too; on a narrow Posture view the
            # five change buttons need the room.
            "policies-details": not self._policy_detail_always()
            and model.row_count() > 0
            and not (view == "posture" and not self._policy_nav_shown()),
            "policies-refresh": True,
        }
        for button_id, show in visible.items():
            self._set_button_visible(f"#{button_id}", show)  # type: ignore[attr-defined]
        if visible["policies-toggle"] and pack is not None:
            on = str(getattr(pack, "name", "")) in model.scope_protection()
            self._set_button_label("#policies-toggle", "Turn off" if on else "Turn on")

    def _set_button_label(self, selector: str, label: str) -> None:
        from textual.widgets import Button

        try:
            button = self.query_one(selector, Button)  # type: ignore[attr-defined]
        except Exception:  # noqa: BLE001 - button missing during teardown
            return
        if str(button.label) != label:
            button.label = label
            # A longer label ("Turn on" -> "Turn off") keeps the old width
            # unless the bar lays out again, and then shows only "Turn".
            button.refresh(layout=True)

    def _handle_policy_control(self, button_id: str) -> None:
        key = POLICY_BUTTON_KEYS.get(button_id)
        if key is None:
            return
        self._apply_policy_action(self.policy_model.handle_key(key))

    # ---- actions ----------------------------------------------------------

    def _apply_policy_action(self, action: PolicyPanelAction) -> bool:
        kind = action.kind
        if kind == "none":
            return False
        if action.hint:
            self._set_status(action.hint)  # type: ignore[attr-defined]
        flow = None
        if kind == "refresh":
            self._schedule_policy_load(sandbox=self.policy_model.sandbox_loaded)
        elif kind == "load_sandbox_packs":
            self._schedule_policy_load(sandbox=True)
        elif kind == "pick_policy":
            flow = self._policy_activate_flow(action.policy)
        elif kind == "pick_pack":
            flow = self._rule_pack_flow(action.connector)
        elif kind == "toggle_mode":
            flow = self._mode_flow(action.connector)
        elif kind in {"pick_block", "pick_alert"}:
            flow = self._level_flow("block" if kind == "pick_block" else "alert", action.connector)
        elif kind in {"pick_policy_block", "pick_policy_alert"}:
            flow = self._policy_threshold_flow("block" if kind == "pick_policy_block" else "alert", action.policy)
        elif kind == "pick_hilt":
            flow = self._hilt_flow(action.connector)
        elif kind == "toggle_protection":
            flow = self._protection_flow(action.connector, action.pack, action.enable)
        if flow is not None:
            self.run_worker(flow, exclusive=False, thread=False)  # type: ignore[attr-defined]
            return True
        self._render_chrome()  # type: ignore[attr-defined]
        return True

    async def _policy_activate_flow(self, selected: str) -> None:
        model = self.policy_model
        if not model.policies:
            self._set_status("No named policies were found.")  # type: ignore[attr-defined]
            return
        name = await self.push_screen_wait(PolicyPickerScreen(model.policies, selected=selected))  # type: ignore[attr-defined]
        if not name:
            self._set_status("Policy unchanged.")  # type: ignore[attr-defined]
            return
        chosen = model.policy_named(name)
        if chosen is None:
            return
        confirmed = await self.push_screen_wait(  # type: ignore[attr-defined]
            PolicyConsequenceScreen(policy_change_modal(model.active_policy(), chosen))
        )
        if confirmed is None:
            self._set_status("Policy unchanged.")  # type: ignore[attr-defined]
            return
        # The consequence modal already showed the exact command, so run it
        # now rather than asking a third time in the generic preview.
        await self._run_policy_intent(activate_intent(name))

    async def _validate_rule_pack(self, path: str) -> PackValidation:
        from defenseclaw.tui import app as app_module

        try:
            returncode, stdout, _stderr = await app_module._communicate_captured(
                "defenseclaw", ("guardrail", "validate-pack", path, "--json")
            )
        except OSError as exc:
            return PackValidation("unavailable", str(exc))
        return parse_validation(returncode, stdout.decode(errors="replace"))

    async def _rule_pack_flow(self, connector: str) -> None:
        model = self.policy_model
        if model.global_pack is None:
            self._set_status("The rule packs could not be read.")  # type: ignore[attr-defined]
            return
        scopes = [PackScope("", "Global (every connector)", model.current_pack(""))]
        scopes.extend(PackScope(row.connector, row.connector, row.pack) for row in model.connector_packs)
        options = [
            PackOption(pack.name, pack.name if pack.kind == "preset" else pack.path, pack.path, pack.kind == "preset")
            for pack in model.packs
        ]
        choice = await self.push_screen_wait(  # type: ignore[attr-defined]
            RulePackPickerScreen(scopes, options, validate=self._validate_rule_pack, selected_scope=connector)
        )
        if choice is None:
            self._set_status("Rule pack unchanged.")  # type: ignore[attr-defined]
            return
        confirmed = await self.push_screen_wait(  # type: ignore[attr-defined]
            PolicyConsequenceScreen(rule_pack_change_modal(model, choice))
        )
        if confirmed is None:
            self._set_status("Rule pack unchanged.")  # type: ignore[attr-defined]
            return
        await self._run_policy_intent(use_pack_intent(choice.pack, choice.connector))

    async def _mode_flow(self, connector: str) -> None:
        model = self.policy_model
        row = model.scope_row(connector)
        if row is None:
            self._set_status("That scope is no longer configured; press r to refresh.")  # type: ignore[attr-defined]
            return
        new = "observe" if getattr(row, "mode", "") == "action" else "action"
        confirmed = await self.push_screen_wait(  # type: ignore[attr-defined]
            PolicyConsequenceScreen(mode_change_modal(model, row, new))
        )
        if confirmed is None:
            self._set_status("Mode unchanged.")  # type: ignore[attr-defined]
            return
        await self._run_policy_intent(mode_intent(new, model.command_connector(row)))

    async def _level_flow(self, kind: str, connector: str) -> None:
        """``b`` / ``a`` on Posture: the scope's tool-call level → ``guardrail block-at|alert-at``."""
        model = self.policy_model
        row = model.scope_row(connector)
        what = "Block" if kind == "block" else "Alert"
        if row is None:
            self._set_status("That scope is no longer configured; press r to refresh.")  # type: ignore[attr-defined]
            return
        current = model.level_current(kind, row)
        levels = TOOL_BLOCK_LEVELS if kind == "block" else TOOL_ALERT_LEVELS
        weaker = [value for value in (*levels, INHERIT) if model.level_change(kind, row, value).weakened()]
        choices = tool_level_choices(kind, current, model.level_inherit_text(kind, row), weaker)
        previews = {choice.value: level_preview(model, kind, row, choice.value) for choice in choices}
        chosen = await self.push_screen_wait(  # type: ignore[attr-defined]
            LevelPickerScreen(
                f"{what} at: tool calls for {_level_scope_words(model, row)}",
                choices,
                subtitle="Tool calls in action mode. The policy's levels for LLM traffic through the guardrail "
                "proxy are separate (Policies view).",
                previews=previews,
            )
        )
        if not chosen or chosen == current:
            self._set_status(f"{what} level unchanged.")  # type: ignore[attr-defined]
            return
        confirmed = await self.push_screen_wait(  # type: ignore[attr-defined]
            PolicyConsequenceScreen(level_change_modal(model, row, kind, chosen))
        )
        if confirmed is None:
            self._set_status(f"{what} level unchanged.")  # type: ignore[attr-defined]
            return
        await self._run_policy_intent(level_intent(kind, chosen, model.command_connector(row)))

    async def _policy_threshold_flow(self, kind: str, name: str) -> None:
        """``b`` / ``a`` on Policies: the policy's LLM-traffic level → ``policy edit guardrail``."""
        model = self.policy_model
        policy = model.policy_named(name)
        what = "Block" if kind == "block" else "Alert"
        if policy is None:
            self._set_status("That policy is no longer listed; press r to refresh.")  # type: ignore[attr-defined]
            return
        current = str(getattr(policy, "block_at" if kind == "block" else "alert_at", "") or "")
        choices = threshold_choices(kind, current)
        previews = {choice.value: policy_threshold_preview(policy, kind, choice.value) for choice in choices}
        chosen = await self.push_screen_wait(  # type: ignore[attr-defined]
            LevelPickerScreen(
                f"{what} at: LLM traffic (guardrail proxy), {policy.name} policy",
                choices,
                subtitle="Tool calls take their levels from each scope instead (Posture view).",
                previews=previews,
            )
        )
        if not chosen or chosen == current.upper():
            self._set_status(f"{what} level unchanged.")  # type: ignore[attr-defined]
            return
        confirmed = await self.push_screen_wait(  # type: ignore[attr-defined]
            PolicyConsequenceScreen(policy_threshold_modal(kind, chosen, policy))
        )
        if confirmed is None:
            self._set_status(f"{what} level unchanged.")  # type: ignore[attr-defined]
            return
        await self._run_policy_intent(threshold_intent(kind, chosen, policy.name))

    async def _hilt_flow(self, connector: str) -> None:
        model = self.policy_model
        row = model.scope_row(connector)
        if row is None:
            self._set_status("That scope is no longer configured; press r to refresh.")  # type: ignore[attr-defined]
            return
        current = str(getattr(row, "hilt", "") or "off")
        choices = approval_choices(current)
        block, alert = model.scope_levels(row)
        previews = {
            choice.value: "At each severity: "
            + " · ".join(f"{sev} {action}" for sev, action in severity_actions(block, alert, choice.value))
            for choice in choices
        }
        chosen = await self.push_screen_wait(  # type: ignore[attr-defined]
            LevelPickerScreen(
                f"Human approval: {_scope_words(model, row)}",
                choices,
                subtitle="A held tool call waits for a person to approve it (action mode only).",
                previews=previews,
            )
        )
        if not chosen or chosen == (current if current == "off" else current.upper()):
            self._set_status("Approval unchanged.")  # type: ignore[attr-defined]
            return
        confirmed = await self.push_screen_wait(  # type: ignore[attr-defined]
            PolicyConsequenceScreen(hilt_change_modal(model, row, chosen))
        )
        if confirmed is None:
            self._set_status("Approval unchanged.")  # type: ignore[attr-defined]
            return
        await self._run_policy_intent(hilt_intent(chosen, model.command_connector(row)))

    async def _protection_flow(self, connector: str, name: str, enable: bool) -> None:
        model = self.policy_model
        row = model.scope_row(connector)
        pack = model.protection_pack(name)
        if row is None or pack is None:
            self._set_status("That pack or scope is no longer listed; press r to refresh.")  # type: ignore[attr-defined]
            return
        confirmed = await self.push_screen_wait(  # type: ignore[attr-defined]
            PolicyConsequenceScreen(protection_change_modal(model, row, pack, enable))
        )
        if confirmed is None:
            self._set_status("Opt-in packs unchanged.")  # type: ignore[attr-defined]
            return
        await self._run_policy_intent(protection_intent(name, enable=enable, connector=model.command_connector(row)))

    async def _run_policy_intent(self, intent: Any) -> None:
        await self._run_command(  # type: ignore[attr-defined]
            getattr(intent, "binary", "defenseclaw"), tuple(intent.args), display_name=intent.label
        )


class PolicyConsequenceScreen(ConsequenceModalScreen):
    """The consequence modal, narrowed so it fits an 80x24 terminal."""

    CSS = (
        ConsequenceModalScreen.CSS
        + """
    PolicyConsequenceScreen #consequence-dialog {
        width: 78;
        max-width: 100%;
        max-height: 100%;
        padding: 0 1;
    }
    PolicyConsequenceScreen #consequence-title,
    PolicyConsequenceScreen #consequence-summary {
        margin-bottom: 0;
    }
    """
    )


# ---- consequence modals (pure) --------------------------------------------


def _scope_words(model: PoliciesPanelModel, row: Any) -> str:
    """How a modal names a scope: ``codex``, or what the global row covers."""
    connector = model.connector_of(row)
    if connector:
        return connector
    return "the global default"


def _run_line(intent: Any, suffix: str = "") -> str:
    # Never shortened: the modal promises to run exactly this.
    return f"Runs: {' '.join(intent.argv)}{suffix}"


def _confirm(action_id: str, hotkey: str, label: str, weaker: bool) -> ConsequenceAction:
    return ConsequenceAction(
        action_id=action_id,
        hotkey=hotkey,
        label=rich_escape(label),
        description="Runs the command shown above.",
        variant="error" if weaker else "primary",
        danger=weaker,
    )


def _modal(
    title: str,
    summary: str,
    details: list[str],
    consequence: str,
    action: ConsequenceAction,
) -> ConsequenceModalModel:
    return ConsequenceModalModel(
        title=rich_escape(title),
        summary=rich_escape(summary),
        details=tuple(rich_escape(line) for line in details),
        consequence=rich_escape(consequence),
        actions=(action,),
        default_action_id=action.action_id,
        border_color=TOKENS.accent_red if action.danger else TOKENS.border_active,
    )


def policy_change_modal(active: Any | None, chosen: Any) -> ConsequenceModalModel:
    """What activating ``chosen`` changes; red with a second confirm when it protects less."""
    weaker = policy_weakenings(active, chosen)
    before = active.name if active is not None else "no policy"
    details = [
        f"block {active.block_at if active else '-'} → {chosen.block_at} · "
        f"alert {active.alert_at if active else '-'} → {chosen.alert_at} · "
        f"installs {active.install_block_at if active else '-'} → {chosen.install_block_at}",
    ]
    effects = policy_side_effects(chosen)
    if effects:
        details.append("Also: " + " · ".join(effects))
    details.append(f"Runs: defenseclaw policy activate {chosen.name}; the gateway reloads it.")
    consequence = ("This weakens protection: " + "; ".join(weaker) + ".") if weaker else ""
    return ConsequenceModalModel(
        title=f"Activate the {rich_escape(chosen.name)} policy?",
        summary=rich_escape(f"{before} → {chosen.name}"),
        details=tuple(rich_escape(line) for line in details),
        consequence=rich_escape(consequence),
        actions=(
            ConsequenceAction(
                action_id="activate",
                hotkey="a",
                label=f"Activate {rich_escape(chosen.name)}",
                description="Runs the command shown above.",
                variant="error" if weaker else "primary",
                danger=bool(weaker),
            ),
        ),
        default_action_id="activate",
        border_color=TOKENS.accent_red if weaker else TOKENS.border_active,
    )


def rule_pack_change_modal(model: PoliciesPanelModel, choice: RulePackChoice) -> ConsequenceModalModel:
    """What switching the rule pack changes, naming the overrides a global switch clears."""
    connector = choice.connector
    replaced = model.packs_for_scope(connector)
    weaker = pack_weakens(replaced, choice.name)
    details: list[str] = []
    if connector:
        details.append(f"{connector}: {model.current_pack(connector) or '-'} → {choice.name}")
        details.append("Other connectors keep their pack.")
    else:
        details.append(f"Global: {model.current_pack('') or '-'} → {choice.name}")
        cleared = model.override_connectors()
        if cleared:
            details.append("Clears the own pack of: " + ", ".join(cleared))
        else:
            details.append("Every connector uses the global pack.")
    # guardrail.block_at / alert_at win over the pack's own levels.
    levels, pack_levels = model.levels_with_pack(connector, choice.path or choice.pack)
    held = [
        f"{verb} at {now} (not the pack's {theirs})"
        for verb, source, now, theirs in (
            ("block", levels.block_source, levels.block_at, pack_levels.block_at),
            ("alert", levels.alert_source, levels.alert_at, pack_levels.alert_at),
        )
        if source != "pack" and now != theirs
    ]
    if held:
        details.append("Tool calls still " + " and ".join(held) + ", as set with block-at / alert-at.")
    details.append(f"Validation: {choice.validation.summary}")
    details.append(_run_line(use_pack_intent(choice.pack, connector)))
    consequence = ""
    if weaker:
        consequence = f"{choice.name} is a looser preset than {', '.join(sorted(set(replaced)))}."
    elif choice.validation.state == "unavailable":
        consequence = "The validator is unavailable; the preset is used without checking it."
    where = connector or "every connector"
    return _modal(
        f"Use the {choice.name} rule pack for {where}?",
        "A running gateway restarts to load the new pack.",
        details,
        consequence,
        _confirm("use", "u", f"Use {choice.name}", weaker),
    )


def mode_change_modal(model: PoliciesPanelModel, row: Any, new: str) -> ConsequenceModalModel:
    """Observe ↔ action for one scope; red when it stops blocking."""
    old = str(getattr(row, "mode", "") or "observe")
    weaker = mode_weakens(old, new)
    scope = str(getattr(row, "scope", "") or "global")
    block, alert = model.scope_levels(row)
    hilt = str(getattr(row, "hilt", "") or "off")
    intent = mode_intent(new, model.command_connector(row))
    details = [posture_summary(scope, new, block, alert, hilt)]
    connector = model.connector_of(row)
    if connector and not model.multi_connector:
        details.append("This install has one connector, so this sets the global mode.")
    elif connector:
        details.append("Only this connector changes; the others keep their mode. A running gateway restarts.")
    else:
        own = model.own_setting("mode")
        if own:
            details.append("Connectors with their own mode keep it: " + ", ".join(own) + ".")
        details.append("A running gateway restarts to apply it.")
    details.append(_run_line(intent))
    consequence = ""
    if weaker:
        consequence = (
            f"This weakens protection: {scope} stops blocking; findings are only logged, and its hooks "
            "fail open while the gateway is down unless their fail mode is set to closed."
        )
    title = f"Switch {connector} to {new} mode?" if connector else f"Set the global guardrail mode to {new}?"
    return _modal(title, f"{old} → {new}", details, consequence, _confirm("mode", "s", f"Switch to {new}", weaker))


def policy_threshold_preview(policy: Any, kind: str, level: str) -> str:
    """Picker preview for a policy's level: what LLM traffic gets at each severity."""
    block = str(getattr(policy, "block_at", "") or "CRITICAL")
    alert = str(getattr(policy, "alert_at", "") or "MEDIUM+")
    if kind == "block":
        block = level
    else:
        alert = level
    traffic = " · ".join(f"{sev} {action}" for sev, action in severity_actions(block, alert, "off"))
    return f"LLM traffic: {traffic}"


def policy_threshold_modal(kind: str, level: str, policy: Any) -> ConsequenceModalModel:
    """A named policy's block or alert level for LLM traffic through the guardrail proxy.

    Red with a second press when it catches fewer severities on the active
    policy; editing another one only saves it until it is activated.
    """
    name = str(getattr(policy, "name", "") or "active")
    active = bool(getattr(policy, "active", False))
    old = str(getattr(policy, "block_at" if kind == "block" else "alert_at", "") or "-")
    weaker = active and threshold_weakens(old, level)
    intent = threshold_intent(kind, level, name)
    what = "Block" if kind == "block" else "Alert"
    verb = "blocks" if kind == "block" else "alerts on"
    details = [
        "LLM traffic through the guardrail proxy only; tool calls keep each scope's levels (Posture view).",
    ]
    if not active:
        details.append(f"The {name} policy isn't active, so nothing changes until you activate it (Enter).")
    if getattr(policy, "builtin", False) and not getattr(policy, "edited", False):
        details.append(f"The built-in {name} policy is copied to your policy folder first.")
    details.append(_run_line(intent, "; the gateway reloads the policy." if active else ""))
    consequence = f"This weakens protection: the policy {verb} {level} instead of {old}." if weaker else ""
    return _modal(
        f"{what} LLM traffic at {level} in the {name} policy?",
        f"{old} → {level}",
        details,
        consequence,
        _confirm("threshold", "s", f"Set {what.lower()} at {level}", weaker),
    )


def _level_scope_words(model: PoliciesPanelModel, row: Any) -> str:
    """Who a tool-call level change reaches: ``codex``, or every connector."""
    connector = model.connector_of(row)
    if connector:
        return connector
    return "every connector" if model.multi_connector else "the global default"


def level_preview(model: PoliciesPanelModel, kind: str, row: Any, choice: str) -> str:
    """Picker preview for a tool-call level: the scope at each severity, and who else loosens."""
    change = model.level_change(kind, row, choice)
    effect = change.effect_for(str(getattr(row, "scope", "") or "global"))
    if effect is None:
        return ""
    hilt = str(getattr(row, "hilt", "") or "off")
    after = effect.after
    lines = [
        "At each severity: "
        + " · ".join(f"{sev} {action}" for sev, action in severity_actions(after.block_at, after.alert_at, hilt))
    ]
    others = loosened_text(e for e in change.weakened() if e.scope != effect.scope)
    if others:
        lines.append(f"Also {others}.")
    return "\n".join(lines)


def level_change_modal(model: PoliciesPanelModel, row: Any, kind: str, choice: str) -> ConsequenceModalModel:
    """A scope's tool-call block or alert level; red when any scope it reaches loosens.

    A global value replaces the level of every connector without its own,
    so a connector on a stricter pack can loosen even when the global
    default gets stricter: the modal names those.
    """
    change = model.level_change(kind, row, choice)
    scope = str(getattr(row, "scope", "") or "global")
    effect = change.effect_for(scope)
    before = effect.before if effect is not None else model.row_levels(row)
    after = effect.after if effect is not None else before
    old, _old_source = levels_setting(before, kind)
    new, new_source = levels_setting(after, kind)
    mode = str(getattr(row, "mode", "") or "observe")
    hilt = str(getattr(row, "hilt", "") or "off")
    intent = level_intent(kind, choice, change.connector)
    connector = model.connector_of(row)
    details = [posture_summary(scope, mode, after.block_at, after.alert_at, hilt)]
    if choice == INHERIT:
        follows = "the global level" if new_source == "global" else "its rule pack's level"
        details.append(f"Follows {follows} again.")
    elif old == new:
        others = "the global or rule pack level" if change.connector else "the rule pack's level"
        details.append(f"Stays at {new}, but no longer follows {others} if that changes.")
    if connector and not model.multi_connector:
        details.append("This install has one connector, so this sets the global level.")
    elif connector:
        details.append("Only this connector changes; a running gateway restarts to apply it.")
    elif model.multi_connector:
        details.append("Every connector without its own level follows it; a running gateway restarts to apply it.")
        if change.keep_own:
            details.append("Keep their own level: " + ", ".join(change.keep_own) + ".")
    else:
        details.append("A running gateway restarts to apply it.")
    if after.alert_clamped:
        details.append(f"Alerts start at {after.alert_at}: anything that blocks also alerts.")
    details.append(_run_line(intent))
    loosened = loosened_text(change.weakened())
    weaker = bool(loosened)
    consequence = f"This weakens protection: {loosened}." if weaker else ""
    what = "block" if kind == "block" else "alert"
    target = change.connector
    if choice == INHERIT:
        title = f"Clear {target}'s own {what} level?" if target else f"Clear the global {what} level?"
        label = "Use the inherited level"
    else:
        title = f"Set {target}'s {what} level to {choice}?" if target else f"Set the global {what} level to {choice}?"
        label = f"{what.capitalize()} at {choice}"
    return _modal(title, f"{what} level: {old} → {new}", details, consequence, _confirm("level", "s", label, weaker))


def hilt_change_modal(model: PoliciesPanelModel, row: Any, level: str) -> ConsequenceModalModel:
    """Human approval for one scope; red when it asks for fewer severities."""
    old = str(getattr(row, "hilt", "") or "off")
    weaker = hilt_weakens(old, level)
    scope = str(getattr(row, "scope", "") or "global")
    mode = str(getattr(row, "mode", "") or "observe")
    block, alert = model.scope_levels(row)
    connector = model.connector_of(row)
    intent = hilt_intent(level, model.command_connector(row))
    details = [posture_summary(scope, "action", block, alert, level)]
    if mode != "action":
        details.append(f"{scope} is in observe mode, so nothing waits for approval until it runs in action mode.")
    if connector and not model.multi_connector:
        details.append("This install has one connector, so this sets approval for every connector.")
    elif not connector and model.multi_connector:
        others = [str(getattr(r, "scope", "")) for r in model.postures if model.connector_of(r)]
        if others:
            details.append("Sets approval on every active connector: " + ", ".join(others) + ".")
    details.append(_run_line(intent, "; the gateway restarts to apply it."))
    consequence = ""
    if weaker:
        lost = actions_weaken(severity_actions(block, alert, old), severity_actions(block, alert, level))
        if lost:
            consequence = (
                f"This weakens protection: {', '.join(lost)} findings on {scope} are no longer held for a person."
            )
        else:
            consequence = f"This weakens protection: {scope} asks a person for fewer findings."
    title = "Turn off human approval" if level == "off" else f"Ask a human for {level}"
    return _modal(
        f"{title} on {_scope_words(model, row)}?",
        f"{old} → {level}",
        details,
        consequence,
        _confirm("hilt", "s", "Turn approval off" if level == "off" else f"Ask for {level}", weaker),
    )


def protection_change_modal(model: PoliciesPanelModel, row: Any, pack: Any, enable: bool) -> ConsequenceModalModel:
    """Turning an opt-in protection pack on or off for one scope."""
    name = str(getattr(pack, "name", ""))
    title = str(getattr(pack, "title", "") or name)
    covers = str(getattr(pack, "covers", "") or getattr(pack, "summary", "") or "")
    scope = str(getattr(row, "scope", "") or "global")
    connector = model.command_connector(row)
    where = connector or "the global pack"
    intent = protection_intent(name, enable=enable, connector=connector)
    details: list[str] = []
    if model.connector_of(row) and not connector:
        details.append("This install has one connector, so this changes the global pack.")
    consequence = ""
    weaker = not enable
    if enable:
        summary = protection_claim(name, scope)
        count = int(getattr(pack, "rule_count", 0) or 0)
        rules = f" ({count} rule{'s' if count != 1 else ''}; the details list them)" if count else ""
        details.append(f"It blocks: {covers}{rules}." if covers else "It adds the pack's blocking rules.")
        details.append(
            f"Adds it to {where}'s guardrail.rules.protections in config.yaml; the gateway layers it on "
            f"{str(getattr(row, 'pack', '') or 'the rule pack')} and applies it on its next reload."
        )
    else:
        summary = f"{scope} stops blocking what the pack covers."
        remaining = [p for p in model.scope_protection(row) if p != name]
        if not remaining:
            details.append(f"That is the last opt-in pack, so {where} goes back to its base pack.")
        details.append("The gateway applies the change on its next reload.")
        details.append(f"No longer blocked: {covers}." if covers else "Its rules stop applying.")
        consequence = f"This weakens protection: {title} is turned off for {scope}."
    details.append(_run_line(intent))
    verb = "Turn on" if enable else "Turn off"
    return _modal(
        f"{verb} {title} for {where}?",
        summary,
        details,
        consequence,
        _confirm("protection", "t", verb, weaker),
    )


__all__ = [
    "POLICY_BUTTON_KEYS",
    "PolicyCatalogRead",
    "PolicyPanelMixin",
    "hilt_change_modal",
    "level_change_modal",
    "level_preview",
    "mode_change_modal",
    "policy_change_modal",
    "policy_threshold_modal",
    "policy_threshold_preview",
    "protection_change_modal",
    "read_policy_catalog",
    "rule_pack_change_modal",
]
